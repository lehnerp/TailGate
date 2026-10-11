#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local web dashboard for Cisco ASA VPN incident analysis.

Everything stays on your machine: the server listens on 127.0.0.1 only, opens
the SQLite database read-only, and needs nothing beyond the Python standard
library.

Import a CSV and start (runs asa_parse.py + asa_analyze.py first):
    python3 asa_server.py --import export.csv --outdir out --geoip-mmdb GeoLite2-Country.mmdb

Start on an existing database:
    python3 asa_server.py out/events.db

Re-run the analysis with other thresholds, then start:
    python3 asa_server.py out/events.db --reanalyze --analyze-args "--bf-min 5 --trusted-ip 203.0.113.0/24"

Then open http://127.0.0.1:8765 (opened automatically unless --no-browser).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import ipaddress
import hmac
import json
import secrets
import os
import queue
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import traceback
import webbrowser
from collections import Counter, OrderedDict, defaultdict
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import pathname2url

HERE = os.path.dirname(os.path.abspath(__file__))
MB = 1024 * 1024
ANALYSIS_TABLES = {"sessions", "incidents", "incident_users", "incident_ips", "users", "ips", "links", "daily", "meta"}


class NotFound(Exception):
    pass


# ---------------------------------------------------------------- database

class Pool:
    """A few read-only SQLite connections shared by the request threads."""

    def __init__(self, path: str, size: int = 8):
        self.path = os.path.abspath(path)
        self.q: queue.Queue = queue.Queue()
        for _ in range(size):
            self.q.put(self._open())
        with self.cur() as c:
            self.event_cols = {r[1] for r in c.execute("PRAGMA table_info(events)")}
            self.session_cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)")}
            self.tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def _open(self) -> sqlite3.Connection:
        c = sqlite3.connect(f"file:{pathname2url(self.path)}?mode=ro", uri=True, check_same_thread=False)
        c.row_factory = sqlite3.Row
        for p in ("PRAGMA query_only=1", "PRAGMA mmap_size=1073741824", "PRAGMA cache_size=-262144",
                  "PRAGMA temp_store=MEMORY"):
            c.execute(p)
        return c

    @contextmanager
    def cur(self):
        c = self.q.get()
        try:
            yield c
        finally:
            self.q.put(c)


def rows(c, sql, args=()):
    return [dict(r) for r in c.execute(sql, args)]


def one(c, sql, args=()):
    r = c.execute(sql, args).fetchone()
    return dict(r) if r else None


def val(c, sql, args=()):
    r = c.execute(sql, args).fetchone()
    return r[0] if r else None


def chunked_in(c, sql_tpl: str, values: list, extra=(), size=800):
    """Run sql_tpl (containing {IN}) for chunks of values; return all rows."""
    out = []
    values = list(values)
    for i in range(0, len(values), size):
        part = values[i:i + size]
        out += rows(c, sql_tpl.replace("{IN}", ",".join("?" * len(part))), tuple(part) + tuple(extra))
    return out


# ---------------------------------------------------------------- params

def P(qs, k, d=""):
    v = qs.get(k)
    return v[0].strip() if v else d


def I(qs, k, d, lo=0, hi=10_000):
    try:
        return max(lo, min(hi, int(P(qs, k, str(d)))))
    except ValueError:
        return d


def is_full_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def ip_clause(col: str, value: str):
    """Exact match for a full IP, otherwise prefix match written as a range so the index is used."""
    if is_full_ip(value):
        return f"{col} = ?", [value]
    return f"({col} >= ? AND {col} < ?)", [value, value + "\uffff"]


def day_end(s: str) -> str:
    return s + " 23:59:59" if len(s) == 10 else s


# ---------------------------------------------------------------- row shapes

def user_obj(r):
    return dict(key=r["user_key"], n=r["name"], status=r["status"], risk=r["risk"], inc=r["incidents"],
                top=r["top_finding"], sess=r["sessions"], open=r["open_sessions"], secs=r["connected_s"],
                up=r["bytes_up"], down=r["bytes_down"], total=r["bytes_total"], ips=r["source_ips"],
                ccs=(r["countries"] or "").split(), fails=r["failed_logins"], first=r["first_seen"],
                last=r["last_seen"], groups=(r["vpn_groups"] or "").split(),
                int_hosts=r["int_hosts"] if "int_hosts" in r.keys() else 0,
                int_bytes=r["int_bytes"] if "int_bytes" in r.keys() else 0,
                clients=[x for x in ((r["clients"] if "clients" in r.keys() else "") or "").split(" | ") if x])


def ip_obj(r):
    return dict(ip=r["ip"], cc=r["cc"], country=r["country"], role=r["role"], risk=r["risk"], inc=r["incidents"],
                users=r["accounts_connected"], attacked=r["accounts_attacked"], fails=r["failed_logins"],
                sess=r["sessions"], up=r["bytes_up"], down=r["bytes_down"], total=r["bytes_total"],
                secs=r["connected_s"], first=r["first_seen"], last=r["last_seen"], trusted=r["trusted"])


def sess_obj(r):
    return dict(id=r["id"], u=r["user_key"], n=r["user"], ip=r["outside_ip"], country=r.get("country") or "",
                s=r["start"], e=r["end"], secs=r["duration_s"], up=r["bytes_up"], down=r["bytes_down"],
                inside=r["inside_ip"], open=r["end_estimated"], reason=r["reason"], g=r["vpn_group"], seq=r["seq"],
                client=r.get("client") or "", int_hosts=r.get("int_hosts") or 0, int_bytes=r.get("int_bytes") or 0,
                blocked=r.get("blocked") or 0)


# ---------------------------------------------------------------- time range

DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?$")
HM_RE = re.compile(r"^\d{2}:\d{2}$")


def norm_dt(s: str, end: bool) -> str:
    s = (s or "").strip()
    if not DT_RE.match(s):
        return ""
    s = s.replace("T", " ")
    if len(s) == 10:
        return s + (" 23:59:59" if end else " 00:00:00")
    if len(s) == 16:
        return s + (":59" if end else ":00")
    return s


class Rng:
    """Global time filter: from/to (date or date+time) and optional daily hours h1..h2 (may wrap midnight)."""

    def __init__(self, qs):
        self.frm = norm_dt(P(qs, "from"), False)
        self.to = norm_dt(P(qs, "to"), True)
        h1, h2 = P(qs, "h1")[:5], P(qs, "h2")[:5]
        ok = bool(HM_RE.match(h1) and HM_RE.match(h2) and h1 != h2)
        self.h1, self.h2 = (h1, h2) if ok else ("", "")

    @property
    def on(self) -> bool:
        return bool(self.frm or self.to or self.h1)

    def key(self):
        return (self.frm, self.to, self.h1, self.h2)

    def clause(self, col, end_col=None, hours=True):
        """SQL conditions for rows whose time `col` (or span col..end_col) falls in the range."""
        w, a = [], []
        if self.frm:
            w.append(f"{end_col or col} >= ?")
            a.append(self.frm)
        if self.to:
            w.append(f"{col} <= ?")
            a.append(self.to)
        if hours and self.h1:
            t = f"substr({col},12,5)"
            w.append(f"({t} >= ? AND {t} < ?)" if self.h1 < self.h2 else f"({t} >= ? OR {t} < ?)")
            a += [self.h1, self.h2]
        return w, a


def W(parts):
    return (" WHERE " + " AND ".join(parts)) if parts else ""


def AND(parts):
    return "".join(" AND " + p for p in parts)


_cache: OrderedDict = OrderedDict()
_cache_lock = threading.Lock()


def cached(key, fn):
    """Small LRU cache: ranged aggregates are computed once per time range, paging is then instant."""
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    v = fn()
    with _cache_lock:
        _cache[key] = v
        while len(_cache) > 16:
            _cache.popitem(last=False)
    return v


def _mn(*v):
    v = [x for x in v if x]
    return min(v) if v else None


def _mx(*v):
    v = [x for x in v if x]
    return max(v) if v else None


def ranged_users(c, rng):
    def build():
        w, a = rng.clause("start", "end")
        S = {r["user_key"]: r for r in rows(
            c, "SELECT user_key, COUNT(*) sess, SUM(duration_s) secs, SUM(bytes_up) up, SUM(bytes_down) down, "
               "COUNT(DISTINCT outside_ip) ips, SUM(end_estimated) open, MIN(start) first, MAX(end) last "
               f"FROM sessions{W(w)} GROUP BY user_key", a)}
        w2, a2 = rng.clause("ts")
        Fl = {r["k"]: r for r in rows(
            c, "SELECT lower(user) k, COUNT(*) fails, MIN(ts) first, MAX(ts) last FROM events "
               f"WHERE kind='INVALID_PW' AND user<>''{AND(w2)} GROUP BY k", a2)}
        out = []
        for b in chunked_in(c, "SELECT * FROM users WHERE user_key IN ({IN})", set(S) | set(Fl)):
            u = user_obj(b)
            s, f = S.get(u["key"]) or {}, Fl.get(u["key"]) or {}
            u.update(sess=s.get("sess") or 0, secs=s.get("secs") or 0, up=s.get("up") or 0,
                     down=s.get("down") or 0, ips=s.get("ips") or 0, open=s.get("open") or 0,
                     fails=f.get("fails") or 0, first=_mn(s.get("first"), f.get("first")),
                     last=_mx(s.get("last"), f.get("last")))
            u["total"] = u["up"] + u["down"]
            out.append(u)
        return out
    return cached(("users",) + rng.key(), build)


def ranged_ips(c, rng):
    def build():
        w, a = rng.clause("start", "end")
        S = {r["ip"]: r for r in rows(
            c, "SELECT outside_ip ip, COUNT(*) sess, SUM(bytes_up) up, SUM(bytes_down) down, SUM(duration_s) secs, "
               "COUNT(DISTINCT user_key) users, MIN(start) first, MAX(end) last "
               f"FROM sessions WHERE outside_ip<>''{AND(w)} GROUP BY outside_ip", a)}
        w2, a2 = rng.clause("ts")
        Fl = {r["ip"]: r for r in rows(
            c, "SELECT outside_ip ip, COUNT(*) fails, COUNT(DISTINCT lower(user)) attacked, MIN(ts) first, "
               f"MAX(ts) last FROM events WHERE kind='INVALID_PW' AND outside_ip<>''{AND(w2)} GROUP BY outside_ip",
            a2)}
        out = []
        for b in chunked_in(c, "SELECT * FROM ips WHERE ip IN ({IN})", set(S) | set(Fl)):
            x = ip_obj(b)
            s, f = S.get(x["ip"]) or {}, Fl.get(x["ip"]) or {}
            x.update(sess=s.get("sess") or 0, up=s.get("up") or 0, down=s.get("down") or 0,
                     secs=s.get("secs") or 0, users=s.get("users") or 0, fails=f.get("fails") or 0,
                     attacked=f.get("attacked") or 0, first=_mn(s.get("first"), f.get("first")),
                     last=_mx(s.get("last"), f.get("last")))
            x["total"] = x["up"] + x["down"]
            out.append(x)
        return out
    return cached(("ips",) + rng.key(), build)


def ranged_links(c, rng):
    def build():
        w, a = rng.clause("start", "end")
        L = {}
        for r in rows(c, "SELECT user_key u, outside_ip ip, COUNT(*) n, SUM(bytes_up) up, SUM(bytes_down) down, "
                         f"SUM(duration_s) secs FROM sessions WHERE outside_ip<>''{AND(w)} GROUP BY user_key, outside_ip",
                      a):
            L[(r["u"], r["ip"])] = dict(user_key=r["u"], ip=r["ip"], sessions=r["n"], failed_logins=0,
                                        bytes_up=r["up"] or 0, bytes_down=r["down"] or 0, connected_s=r["secs"] or 0)
        w2, a2 = rng.clause("ts")
        for r in rows(c, "SELECT lower(user) u, outside_ip ip, COUNT(*) n FROM events WHERE kind='INVALID_PW' "
                         f"AND outside_ip<>'' AND user<>''{AND(w2)} GROUP BY u, ip", a2):
            L.setdefault((r["u"], r["ip"]), dict(user_key=r["u"], ip=r["ip"], sessions=0, failed_logins=0, bytes_up=0,
                                                 bytes_down=0, connected_s=0))["failed_logins"] = r["n"]
        return L
    return cached(("links",) + rng.key(), build)


U_KEY = {"total": lambda u: (-u["total"], u["key"]), "up": lambda u: (-u["up"], u["key"]),
         "down": lambda u: (-u["down"], u["key"]), "secs": lambda u: (-u["secs"], u["key"]),
         "sess": lambda u: (-u["sess"], u["key"]), "risk": lambda u: (-u["risk"], -u["total"], u["key"]),
         "fails": lambda u: (-u["fails"], u["key"]), "n": lambda u: u["key"]}
I_KEY = {"risk": lambda x: (-x["risk"], -x["fails"], x["ip"]), "fails": lambda x: (-x["fails"], x["ip"]),
         "attacked": lambda x: (-x["attacked"], x["ip"]), "users": lambda x: (-x["users"], x["ip"]),
         "total": lambda x: (-x["total"], x["ip"]), "sess": lambda x: (-x["sess"], x["ip"])}


# ---------------------------------------------------------------- API

def api_meta(c, qs):
    return dict(
        meta=json.loads(val(c, "SELECT value FROM meta WHERE key='summary'") or "{}"),
        types=[r["type"] for r in rows(c, "SELECT type, COUNT(*) n FROM incidents GROUP BY type ORDER BY n DESC")],
        kinds=[r["kind"] for r in rows(c, "SELECT DISTINCT kind FROM events ORDER BY kind")],
    )


def api_summary(c, qs):
    rng = Rng(qs)
    iw, ia = rng.clause("start", "end", hours=False)
    comp_sub = ("SELECT id FROM incidents WHERE (severity='critical' OR type IN ('concurrent_sessions',"
                f"'impossible_travel')){AND(iw)}")
    atk_sub = f"SELECT id FROM incidents WHERE type IN ('brute_force','password_spray'){AND(iw)}"
    sev = {r["severity"]: r["n"] for r in rows(c, f"SELECT severity, COUNT(*) n FROM incidents{W(iw)} "
                                                  "GROUP BY severity", ia)}
    cw = "status='compromise'" + (f" AND user_key IN (SELECT user_key FROM incident_users WHERE incident_id IN "
                                  f"({comp_sub}))" if rng.on else "")
    aw = "role='attacker'" + (f" AND ip IN (SELECT ip FROM incident_ips WHERE incident_id IN ({atk_sub}))"
                              if rng.on else "")
    args = ia if rng.on else []
    if rng.on:
        w, a = rng.clause("start", "end")
        k = one(c, "SELECT COUNT(*) sessions, COALESCE(SUM(bytes_up),0) up, COALESCE(SUM(bytes_down),0) down, "
                   f"COALESCE(SUM(duration_s),0) secs, COUNT(DISTINCT user_key) connected FROM sessions{W(w)}", a)
        w2, a2 = rng.clause("ts")
        k["fails"] = val(c, f"SELECT COUNT(*) FROM events WHERE kind='INVALID_PW'{AND(w2)}", a2)
    else:
        m = json.loads(val(c, "SELECT value FROM meta WHERE key='summary'") or "{}")
        k = dict(sessions=m.get("sessions", 0), up=m.get("up", 0), down=m.get("down", 0), secs=m.get("secs", 0),
                 fails=m.get("fails", 0), connected=val(c, "SELECT COUNT(*) FROM users WHERE sessions>0"))
    if has("cases"):
        k["cases"] = val(c, f"SELECT COUNT(*) FROM cases{W(iw)}", ia)
    if has("login_reviews"):
        lw, la = rng.clause("ts")
        k["logins_review"] = val(c, f"SELECT COUNT(*) FROM login_reviews WHERE verdict IN ('likely','review'){AND(lw)}", la)
        k["logins_comp"] = val(c, f"SELECT COUNT(*) FROM login_reviews WHERE verdict='compromised'{AND(lw)}", la)
        k["cases_crit"] = val(c, f"SELECT COUNT(*) FROM cases WHERE severity='critical'{AND(iw)}", ia)
    if has("hosts"):
        if rng.on:
            k["hosts"] = len(ranged_hosts(c, rng))
        else:
            k["hosts"] = val(c, "SELECT COUNT(*) FROM hosts")
    return dict(
        kpi=k, sev=sev, ranged=rng.on,
        compromised=[user_obj(r) for r in rows(c, f"SELECT * FROM users WHERE {cw} "
                                                  "ORDER BY risk DESC, bytes_total DESC LIMIT 25", args)],
        comp_n=val(c, f"SELECT COUNT(*) FROM users WHERE {cw}", args),
        attackers=[ip_obj(r) for r in rows(c, f"SELECT * FROM ips WHERE {aw} "
                                              "ORDER BY accounts_attacked DESC, failed_logins DESC LIMIT 25", args)],
        atk_n=val(c, f"SELECT COUNT(*) FROM ips WHERE {aw}", args),
    )


def api_daily(c, qs):
    rng = Rng(qs)
    if not rng.on:
        return dict(unit="day", start="", end="",
                    rows=[dict(d=r["day"], up=r["bytes_up"], down=r["bytes_down"], sess=r["sessions"],
                               fails=r["failed_logins"], users=r["users"])
                          for r in rows(c, "SELECT * FROM daily ORDER BY day")])
    hourly = bool(rng.frm and rng.to and
                  dt.datetime.fromisoformat(rng.to) - dt.datetime.fromisoformat(rng.frm) <= dt.timedelta(days=4))
    L = 13 if hourly else 10
    m: dict = {}
    w, a = rng.clause("start")
    for r in rows(c, f"SELECT substr(start,1,{L}) d, COUNT(*) sess, SUM(bytes_up) up, SUM(bytes_down) down, "
                     f"COUNT(DISTINCT user_key) users FROM sessions{W(w)} GROUP BY d", a):
        m[r["d"]] = dict(d=r["d"], up=r["up"] or 0, down=r["down"] or 0, sess=r["sess"], users=r["users"], fails=0)
    w2, a2 = rng.clause("ts")
    for r in rows(c, f"SELECT substr(ts,1,{L}) d, COUNT(*) n FROM events WHERE kind='INVALID_PW'{AND(w2)} "
                     "GROUP BY d", a2):
        m.setdefault(r["d"], dict(d=r["d"], up=0, down=0, sess=0, users=0, fails=0))["fails"] = r["n"]
    return dict(unit="hour" if hourly else "day", start=rng.frm[:L], end=rng.to[:L],
                rows=sorted(m.values(), key=lambda x: x["d"]))


USER_SORT = {"total": "bytes_total DESC", "up": "bytes_up DESC", "down": "bytes_down DESC",
             "secs": "connected_s DESC", "sess": "sessions DESC", "risk": "risk DESC, bytes_total DESC",
             "fails": "failed_logins DESC", "n": "user_key ASC"}


def api_users(c, qs):
    rng = Rng(qs)
    q, st = P(qs, "q").lower(), P(qs, "status")
    lim, off = I(qs, "limit", 200, 1, 2000), I(qs, "offset", 0, 0, 10**9)
    if rng.on:
        lst = ranged_users(c, rng)
        if q:
            lst = [u for u in lst if q in u["key"]]
        lst = [u for u in lst if not u["sess"]] if st == "failonly" else \
              [u for u in lst if u["sess"] and (not st or u["status"] == st)]
        lst = sorted(lst, key=U_KEY.get(P(qs, "sort"), U_KEY["total"]))
        return dict(total=len(lst), max=max((max(u["up"], u["down"]) for u in lst), default=1) or 1,
                    rows=lst[off:off + lim])
    w, a = [], []
    if q:
        w.append("user_key LIKE ?")
        a.append(f"%{q}%")
    if st == "failonly":
        w.append("sessions=0")
    else:
        w.append("sessions>0")
        if st:
            w.append("status=?")
            a.append(st)
    order = USER_SORT.get(P(qs, "sort"), USER_SORT["total"])
    return dict(
        total=val(c, f"SELECT COUNT(*) FROM users{W(w)}", a),
        max=val(c, f"SELECT MAX(MAX(bytes_up, bytes_down)) FROM users{W(w)}", a) or 1,
        rows=[user_obj(r) for r in rows(c, f"SELECT * FROM users{W(w)} ORDER BY {order}, user_key "
                                           "LIMIT ? OFFSET ?", a + [lim, off])])


IP_SORT = {"risk": "risk DESC, failed_logins DESC", "fails": "failed_logins DESC",
           "attacked": "accounts_attacked DESC", "users": "accounts_connected DESC",
           "total": "bytes_total DESC", "sess": "sessions DESC"}


def api_ips(c, qs):
    rng = Rng(qs)
    q, role = P(qs, "q"), P(qs, "role")
    lim, off = I(qs, "limit", 200, 1, 2000), I(qs, "offset", 0, 0, 10**9)
    if rng.on:
        lst = ranged_ips(c, rng)
        if q:
            ql = q.lower()
            lst = [x for x in lst if x["ip"].startswith(q) or ql in (x["country"] or "").lower()
                   or (x["cc"] or "").upper() == q.upper()]
        if role:
            lst = [x for x in lst if x["role"] == role]
        lst = sorted(lst, key=I_KEY.get(P(qs, "sort"), I_KEY["risk"]))
        return dict(total=len(lst), rows=lst[off:off + lim])
    w, a = [], []
    if q:
        w.append("(ip LIKE ? OR country LIKE ? OR cc = ?)")
        a += [f"{q}%", f"%{q}%", q.upper()]
    if role:
        w.append("role=?")
        a.append(role)
    order = IP_SORT.get(P(qs, "sort"), IP_SORT["risk"])
    return dict(total=val(c, f"SELECT COUNT(*) FROM ips{W(w)}", a),
                rows=[ip_obj(r) for r in rows(c, f"SELECT * FROM ips{W(w)} ORDER BY {order}, ip LIMIT ? OFFSET ?",
                                              a + [lim, off])])


INC_SORT = {"sev": "sev_rank ASC, start DESC", "new": "start DESC", "old": "start ASC"}


def incidents_for(c, where, args, order, lim, off):
    items = rows(c, f"SELECT * FROM incidents{where} ORDER BY {order} LIMIT ? OFFSET ?", list(args) + [lim, off])
    ids = [x["id"] for x in items]
    us: dict = {}
    if ids:
        for r in chunked_in(c, "SELECT iu.incident_id, iu.user_key, u.name FROM incident_users iu "
                               "JOIN users u ON u.user_key=iu.user_key WHERE iu.incident_id IN ({IN})", ids):
            lst = us.setdefault(r["incident_id"], [])
            if len(lst) < 10:
                lst.append(dict(k=r["user_key"], n=r["name"]))
    return [dict(id=x["id"], sev=x["severity"], type=x["type"], title=x["title"], detail=x["detail"],
                 start=x["start"], end=x["end"], count=x["count"], n_users=x["n_users"],
                 users=us.get(x["id"], []), ips=(x["ips"] or "").split(), hosts=(x.get("hosts") or "").split(),
                 seqs=[int(s) for s in (x["evidence_seq"] or "").split() if s.isdigit()]) for x in items]


def api_incidents(c, qs):
    w, a = Rng(qs).clause("start", "end", hours=False)
    sev = P(qs, "sev")
    if sev:
        sv = [s for s in sev.split(",") if s in ("critical", "high", "medium", "low")]
        w.append(f"severity IN ({','.join('?' * len(sv))})" if sv else "0")
        a += sv
    if P(qs, "type"):
        w.append("type=?")
        a.append(P(qs, "type"))
    if P(qs, "user"):
        w.append("id IN (SELECT incident_id FROM incident_users WHERE user_key=?)")
        a.append(P(qs, "user"))
    if P(qs, "ip"):
        w.append("id IN (SELECT incident_id FROM incident_ips WHERE ip=?)")
        a.append(P(qs, "ip"))
    q = P(qs, "q")
    if q:
        w.append("(title LIKE ? OR detail LIKE ? OR users LIKE ? OR ips LIKE ?)")
        a += [f"%{q}%"] * 4
    lim, off = I(qs, "limit", 100, 1, 1000), I(qs, "offset", 0, 0, 10**9)
    return dict(total=val(c, f"SELECT COUNT(*) FROM incidents{W(w)}", a),
                rows=incidents_for(c, W(w), a, INC_SORT.get(P(qs, "sort"), INC_SORT["sev"]), lim, off))


SESS_SORT = {"new": "s.start DESC", "old": "s.start ASC", "up": "s.bytes_up DESC", "down": "s.bytes_down DESC",
             "total": "(s.bytes_up + s.bytes_down) DESC", "dur": "s.duration_s DESC"}


def sessions_filter(qs):
    w, a = Rng(qs).clause("s.start", "s.end")
    user = P(qs, "user").lower()
    if user:
        if P(qs, "exact") == "1":
            w.append("s.user_key=?")
            a.append(user)
        else:
            w.append("s.user_key LIKE ?")
            a.append(f"%{user}%")
    ip = P(qs, "ip")
    if ip:
        if is_full_ip(ip):
            w.append("s.outside_ip=?")
            a.append(ip)
        else:
            w.append("s.outside_ip LIKE ?")
            a.append(f"{ip}%")
    inside = P(qs, "inside")
    if inside:
        c_, a_ = ip_clause("s.inside_ip", inside)
        w.append(c_)
        a += a_
    try:
        mu = float(P(qs, "min_up") or 0)
        if mu > 0:
            w.append("s.bytes_up >= ?")
            a.append(int(mu * MB))
    except ValueError:
        pass
    return W(w), a, SESS_SORT.get(P(qs, "sort"), SESS_SORT["new"])


SESS_SELECT = "SELECT s.*, i.country FROM sessions s LEFT JOIN ips i ON i.ip = s.outside_ip"


def api_sessions(c, qs):
    where, a, order = sessions_filter(qs)
    lim, off = I(qs, "limit", 100, 1, 5000), I(qs, "offset", 0, 0, 10**9)
    return dict(total=val(c, f"SELECT COUNT(*) FROM sessions s{where}", a),
                rows=[sess_obj(r) for r in rows(c, f"{SESS_SELECT}{where} ORDER BY {order} LIMIT ? OFFSET ?",
                                                a + [lim, off])])


def daily_rows(c, where_s, args_s, where_f, args_f):
    m: dict = {}
    for r in rows(c, f"SELECT substr(start,1,10) d, SUM(bytes_up) up, SUM(bytes_down) down, COUNT(*) sess "
                     f"FROM sessions WHERE {where_s} GROUP BY d", args_s):
        m[r["d"]] = dict(d=r["d"], up=r["up"], down=r["down"], sess=r["sess"], fails=0)
    for r in rows(c, f"SELECT substr(ts,1,10) d, COUNT(*) n FROM events WHERE kind='INVALID_PW' AND {where_f} "
                     f"GROUP BY d", args_f):
        m.setdefault(r["d"], dict(d=r["d"], up=0, down=0, sess=0, fails=0))["fails"] = r["n"]
    return sorted(m.values(), key=lambda x: x["d"])


def with_params(qs, **kw):
    q2 = {k: v for k, v in qs.items() if k in ("from", "to", "h1", "h2")}
    q2.update({k: [v] for k, v in kw.items()})
    return q2


def api_user(c, qs):
    rng = Rng(qs)
    key = P(qs, "key").lower()
    r = one(c, "SELECT * FROM users WHERE user_key=?", (key,))
    if not r:
        raise NotFound(f"Account {key!r} not found")
    u = user_obj(r)
    if rng.on:
        ru = next((x for x in ranged_users(c, rng) if x["key"] == key), None)
        if ru:
            u = ru
        else:
            u.update(sess=0, secs=0, up=0, down=0, total=0, ips=0, open=0, fails=0, first=None, last=None)
        lk = [x for (uk, _), x in ranged_links(c, rng).items() if uk == key]
        geo = {x["ip"]: x for x in chunked_in(c, "SELECT ip, country, role FROM ips WHERE ip IN ({IN})",
                                               [x["ip"] for x in lk])}
        links = [dict(x, country=geo.get(x["ip"], {}).get("country"), role=geo.get(x["ip"], {}).get("role"))
                 for x in lk]
        links.sort(key=lambda x: (-(x["bytes_up"] + x["bytes_down"]), -x["failed_logins"]))
    else:
        links = rows(c, "SELECT l.*, i.country, i.role FROM links l LEFT JOIN ips i ON i.ip=l.ip WHERE l.user_key=? "
                        "ORDER BY (l.bytes_up+l.bytes_down) DESC, l.failed_logins DESC LIMIT 1000", (key,))
    sw, sa = rng.clause("start", "end")
    s0, s0a = rng.clause("start")
    fw, fa = rng.clause("ts")
    g_sess = [[x["outside_ip"], x["start"], x["end"], x["duration_s"], x["bytes_up"], x["bytes_down"],
               x["end_estimated"], x["inside_ip"]]
              for x in rows(c, "SELECT outside_ip,start,end,duration_s,bytes_up,bytes_down,end_estimated,inside_ip "
                               f"FROM sessions WHERE user_key=?{AND(sw)} ORDER BY start LIMIT 20000", [key] + sa)]
    g_fail = [[x["outside_ip"], x["ts"]] for x in rows(
        c, f"SELECT outside_ip, ts FROM events WHERE user=? COLLATE NOCASE AND kind='INVALID_PW'{AND(fw)} "
           "ORDER BY ts DESC LIMIT 5000", [key] + fa)]
    where, a, order = sessions_filter(with_params(qs, user=key, exact="1"))
    iw, ia = rng.clause("start", "end", hours=False)
    acc, clients = [], []
    if has("flows"):
        if rng.on:
            acc = rows(c, "SELECT dst_ip, dst_port, proto, COUNT(*) conns, SUM(blocked) blocked, SUM(bytes) bytes, "
                          f"MIN(start) first, MAX(ts) last FROM flows WHERE user_key=?{AND(s0)} "
                          "GROUP BY dst_ip, dst_port, proto ORDER BY bytes DESC, conns DESC LIMIT 300", [key] + s0a)
        else:
            acc = rows(c, "SELECT dst_ip, dst_port, proto, conns, blocked, bytes, first_seen first, last_seen last "
                          "FROM access WHERE user_key=? ORDER BY bytes DESC, conns DESC LIMIT 300", (key,))
    if "client" in POOL.session_cols:
        clients = rows(c, "SELECT client, COUNT(*) n, MIN(start) first, MAX(start) last FROM sessions "
                          f"WHERE user_key=? AND client<>''{AND(sw)} GROUP BY client ORDER BY first", [key] + sa)
    hosts_role = {r["ip"]: r["role"] for r in chunked_in(c, "SELECT ip, role FROM hosts WHERE ip IN ({IN})",
                                                        {x["dst_ip"] for x in acc})} if has("hosts") else {}
    return dict(
        access=[dict(x, role=hosts_role.get(x["dst_ip"], "")) for x in acc], clients=clients,
        logins=[lr_obj(r) for r in rows(c, "SELECT * FROM login_reviews WHERE user_key=? ORDER BY score DESC, ts DESC "
                                           "LIMIT 50", (key,))] if has("login_reviews") else [],
        linked=[dict(k=(r["u2"] if r["u1"] == key else r["u1"]), why=list(json.loads(r["reasons"]).values()))
                for r in rows(c, "SELECT * FROM account_links WHERE u1=? OR u2=?", (key, key))] if has("account_links") else [],
        user=u,
        incidents=incidents_for(c, " WHERE id IN (SELECT incident_id FROM incident_users WHERE user_key=?)" + AND(iw),
                                [key] + ia, INC_SORT["sev"], 200, 0),
        links=[dict(ip=x["ip"], country=x["country"] or "", role=x["role"] or "", sess=x["sessions"],
                    fails=x["failed_logins"], up=x["bytes_up"], down=x["bytes_down"], secs=x["connected_s"])
               for x in links[:1000]],
        gantt=dict(sess=g_sess, fails=g_fail),
        daily=daily_rows(c, "user_key=?" + AND(s0), [key] + s0a, "user=? COLLATE NOCASE" + AND(fw), [key] + fa),
        sessions=dict(total=val(c, f"SELECT COUNT(*) FROM sessions s{where}", a),
                      rows=[sess_obj(x) for x in rows(c, f"{SESS_SELECT}{where} ORDER BY {order} LIMIT 100", a)]),
    )


def api_ip(c, qs):
    rng = Rng(qs)
    ip = P(qs, "ip")
    r = one(c, "SELECT * FROM ips WHERE ip=?", (ip,))
    if not r:
        raise NotFound(f"IP {ip!r} not found")
    x = ip_obj(r)
    if rng.on:
        rx = next((y for y in ranged_ips(c, rng) if y["ip"] == ip), None)
        if rx:
            x = rx
        else:
            x.update(sess=0, up=0, down=0, total=0, secs=0, users=0, fails=0, attacked=0, first=None, last=None)
        lk = [v for (_, i), v in ranged_links(c, rng).items() if i == ip]
        nm = {v["user_key"]: v for v in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})",
                                                   [v["user_key"] for v in lk])}
        accts = [dict(v, name=nm.get(v["user_key"], {}).get("name", v["user_key"]),
                      status=nm.get(v["user_key"], {}).get("status", "normal")) for v in lk]
        accts.sort(key=lambda v: (-v["sessions"], -(v["bytes_up"] + v["bytes_down"]), -v["failed_logins"]))
        accts_total = len(accts)
    else:
        accts = rows(c, "SELECT l.*, u.name, u.status FROM links l JOIN users u ON u.user_key=l.user_key WHERE l.ip=? "
                        "ORDER BY l.sessions DESC, (l.bytes_up+l.bytes_down) DESC, l.failed_logins DESC LIMIT 1000",
                     (ip,))
        accts_total = val(c, "SELECT COUNT(*) FROM links WHERE ip=?", (ip,))
    accts = accts[:1000]
    sw, sa = rng.clause("start", "end")
    s0, s0a = rng.clause("start")
    fw, fa = rng.clause("ts")
    g_sess = [[s["user_key"], s["start"], s["end"], s["duration_s"], s["bytes_up"], s["bytes_down"],
               s["end_estimated"], s["inside_ip"]]
              for s in rows(c, "SELECT user_key,start,end,duration_s,bytes_up,bytes_down,end_estimated,inside_ip "
                               f"FROM sessions WHERE outside_ip=?{AND(sw)} ORDER BY start LIMIT 20000", [ip] + sa)]
    g_fail = [[(f["user"] or "").lower(), f["ts"]] for f in rows(
        c, f"SELECT user, ts FROM events WHERE outside_ip=? AND kind='INVALID_PW'{AND(fw)} ORDER BY ts DESC LIMIT 5000",
        [ip] + fa)]
    names = {a["user_key"]: dict(n=a["name"], status=a["status"]) for a in accts}
    missing = ({k for k, *_ in g_sess} | {k for k, _ in g_fail}) - set(names)
    if missing:
        for a in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})", missing):
            names[a["user_key"]] = dict(n=a["name"], status=a["status"])
    where, a, order = sessions_filter(with_params(qs, ip=ip))
    iw, ia = rng.clause("start", "end", hours=False)
    probes = None
    if has("conns"):
        probes = one(c, "SELECT COUNT(*) n, COUNT(DISTINCT p2) ports, COUNT(DISTINCT ip2) hosts, MIN(ts) first, "
                        f"MAX(ts) last FROM conns WHERE ip1=? AND action='deny'{AND(fw)}", [ip] + fa)
    admin = val(c, "SELECT COUNT(*) FROM events WHERE outside_ip=? AND kind IN ('MGMT_LOGIN_OK','MGMT_LOGIN_FAIL',"
                   f"'CONFIG_CMD'){AND(fw)}", [ip] + fa)
    return dict(
        probes=probes, admin=admin, related=related_ips(c, ip)[0], campaign=related_ips(c, ip)[1],
        logins=[lr_obj(r) for r in rows(c, "SELECT * FROM login_reviews WHERE ip=? ORDER BY score DESC, ts DESC "
                                           "LIMIT 50", (ip,))] if has("login_reviews") else [],
        ip=x,
        incidents=incidents_for(c, " WHERE id IN (SELECT incident_id FROM incident_ips WHERE ip=?)" + AND(iw),
                                [ip] + ia, INC_SORT["sev"], 200, 0),
        accounts=[dict(k=v["user_key"], n=v["name"], status=v["status"], sess=v["sessions"], fails=v["failed_logins"],
                       up=v["bytes_up"], down=v["bytes_down"], secs=v["connected_s"]) for v in accts],
        accounts_total=accts_total,
        names=names,
        gantt=dict(sess=g_sess, fails=g_fail),
        daily=daily_rows(c, "outside_ip=?" + AND(s0), [ip] + s0a, "outside_ip=?" + AND(fw), [ip] + fa),
        sessions=dict(total=val(c, f"SELECT COUNT(*) FROM sessions s{where}", a),
                      rows=[sess_obj(s) for s in rows(c, f"{SESS_SELECT}{where} ORDER BY {order} LIMIT 100", a)]),
    )


def events_filter(qs, cols):
    w, a = Rng(qs).clause("e.ts")
    user = P(qs, "user")
    if user:
        if P(qs, "exact") == "1":
            w.append("e.user = ? COLLATE NOCASE")
            a.append(user)
        else:
            w.append("e.user LIKE ?")
            a.append(f"%{user}%")
    ip = P(qs, "ip")
    if ip:
        if is_full_ip(ip):
            w.append("e.outside_ip=?")
            a.append(ip)
        else:
            w.append("e.outside_ip LIKE ?")
            a.append(f"{ip}%")
    inside = P(qs, "inside")
    if inside:
        c_, a_ = ip_clause("e.inside_ip", inside)
        w.append(c_)
        a += a_
    if P(qs, "kind"):
        w.append("e.kind=?")
        a.append(P(qs, "kind"))
    kinds = [k for k in P(qs, "kinds").split(",") if re.match(r"^[A-Z_]+$", k)]
    if kinds:
        w.append(f"e.kind IN ({','.join('?' * len(kinds))})")
        a += kinds
    if P(qs, "q"):
        w.append("e.raw LIKE ?")
        a.append(f"%{P(qs, 'q')}%")
    seqs = [s for s in P(qs, "seqs").replace(" ", ",").split(",") if s.strip().isdigit()][:1000]
    if seqs:
        w.append(f"e.seq IN ({','.join('?' * len(seqs))})")
        a += [int(s) for s in seqs]
    order = "e.ts ASC, e.seq ASC" if P(qs, "sort") == "asc" else "e.ts DESC, e.seq DESC"
    extra = ", e.year_source" if "year_source" in cols else ""
    extra += ", e.msg_id" if "msg_id" in cols else ""
    sql = (f"SELECT e.seq, e.ts, e.raw_ts, e.kind, e.user, e.vpn_group, e.outside_ip, e.inside_ip, e.country, "
           f"e.duration_s, e.bytes_xmt, e.bytes_rcv, e.reason, e.raw{extra} FROM events e{W(w)} ORDER BY {order}")
    return sql, a


def api_events(c, qs):
    sql, a = events_filter(qs, POOL.event_cols)
    lim, off = I(qs, "limit", 200, 1, 5000), I(qs, "offset", 0, 0, 10**9)
    got = rows(c, sql + " LIMIT ? OFFSET ?", a + [lim + 1, off])
    return dict(rows=got[:lim], has_more=len(got) > lim)


def api_graph(c, qs):
    rng = Rng(qs)
    scope, q, show_f = P(qs, "scope", "flag"), P(qs, "q").lower(), P(qs, "fails", "1") == "1"
    MAXN = I(qs, "max", 350, 20, 1500)
    found: dict = {}
    seeds_u, seeds_i = set(), set()

    if rng.on:
        L = ranged_links(c, rng)
        with_sess = {u for (u, _), r in L.items() if r["sessions"] > 0}
        E = {k: r for k, r in L.items() if r["sessions"] > 0 or (show_f and r["failed_logins"] > 0 and k[0] in with_sess)}
        RU = {u["key"]: u for u in ranged_users(c, rng)}
        RI = {x["ip"]: x for x in ranged_ips(c, rng)}
        uattr = lambda k: RU.get(k)
        iattr = lambda k: RI.get(k)
        if q:
            seeds_u = set(sorted((k for k in RU if q in k), key=lambda k: -RU[k]["risk"])[:25])
            seeds_i = set(sorted((k for k in RI if k.startswith(q)), key=lambda k: -RI[k]["risk"])[:25])
            U, IP = set(seeds_u), set(seeds_i)
            for _hop in range(2):
                for k, r in E.items():
                    if (k[0] in U or k[1] in IP) and len(found) < 8000:
                        found[k] = r
                U |= {k[0] for k in found}
                IP |= {k[1] for k in found}
        elif scope == "flag":
            fu = {r[0] for r in c.execute("SELECT user_key FROM users WHERE status!='normal' AND sessions>0")}
            fi = {r[0] for r in c.execute("SELECT ip FROM ips WHERE role!=''")}
            found = {k: r for k, r in E.items() if k[0] in fu or k[1] in fi}
        else:
            top = {u["key"] for u in sorted((u for u in RU.values() if u["sess"]),
                                            key=lambda u: (-u["risk"], -u["total"]))[:150]}
            found = {k: r for k, r in E.items() if k[0] in top}
    else:
        lf = "(l.sessions>0" + (" OR (l.failed_logins>0 AND u.sessions>0)" if show_f else "") + ")"
        base = ("SELECT l.user_key, l.ip, l.sessions, l.failed_logins, l.bytes_up, l.bytes_down, l.connected_s "
                f"FROM links l JOIN users u ON u.user_key=l.user_key WHERE {lf}")
        if q:
            seeds_u = {r["user_key"] for r in rows(c, "SELECT user_key FROM users WHERE user_key LIKE ? "
                                                      "ORDER BY risk DESC LIMIT 25", (f"%{q}%",))}
            seeds_i = {r["ip"] for r in rows(c, "SELECT ip FROM ips WHERE ip LIKE ? ORDER BY risk DESC LIMIT 25",
                                             (f"{q}%",))}
            U, IP = set(seeds_u), set(seeds_i)
            for _hop in range(2):
                new = []
                if U:
                    new += chunked_in(c, base + " AND l.user_key IN ({IN})", U)
                if IP:
                    new += chunked_in(c, base + " AND l.ip IN ({IN})", IP)
                for r in new[:8000]:
                    found[(r["user_key"], r["ip"])] = r
                U |= {r["user_key"] for r in found.values()}
                IP |= {r["ip"] for r in found.values()}
        elif scope == "flag":
            for r in rows(c, base + " AND (l.user_key IN (SELECT user_key FROM users WHERE status!='normal' AND "
                                    "sessions>0) OR l.ip IN (SELECT ip FROM ips WHERE role!='')) LIMIT 30000"):
                found[(r["user_key"], r["ip"])] = r
        else:
            for r in rows(c, base + " AND l.user_key IN (SELECT user_key FROM users WHERE sessions>0 "
                                    "ORDER BY risk DESC, bytes_total DESC LIMIT 150) LIMIT 30000"):
                found[(r["user_key"], r["ip"])] = r
        uk = {k for k, _ in found} | seeds_u
        ik = {i for _, i in found} | seeds_i
        UA = {r["user_key"]: user_obj(r) for r in chunked_in(c, "SELECT * FROM users WHERE user_key IN ({IN})", uk)}
        IA = {r["ip"]: ip_obj(r) for r in chunked_in(c, "SELECT * FROM ips WHERE ip IN ({IN})", ik)}
        uattr = lambda k: UA.get(k)
        iattr = lambda k: IA.get(k)

    cand = []
    for k in {k for k, _ in found} | seeds_u:
        a = uattr(k)
        if a:
            cand.append(("u", k, a["risk"] * 1e13 + a["total"]))
    for k in {i for _, i in found} | seeds_i:
        a = iattr(k)
        if a:
            cand.append(("i", k, a["risk"] * 1e13 + a["total"] + a["fails"]))
    cand.sort(key=lambda x: (-(x[1] in seeds_u or x[1] in seeds_i), -x[2]))
    capped = len(cand) > MAXN
    keep = cand[:MAXN]
    idx = {(t, k): n for n, (t, k, _) in enumerate(keep)}
    links, deg = [], [0] * len(keep)
    for (u, ip), r in found.items():
        a, b = idx.get(("u", u)), idx.get(("i", ip))
        if a is None or b is None:
            continue
        deg[a] += 1
        deg[b] += 1
        links.append(dict(a=a, b=b, sess=r["sessions"], fails=r["failed_logins"], up=r["bytes_up"],
                          down=r["bytes_down"], secs=r["connected_s"]))
    nodes = []
    for (t, k, _), d in zip(keep, deg):
        if t == "u":
            a = uattr(k)
            nodes.append(dict(type="u", key=k, n=a["n"], status=a["status"], risk=a["risk"], total=a["total"],
                              up=a["up"], down=a["down"], secs=a["secs"], sess=a["sess"], deg=d))
        else:
            a = iattr(k)
            nodes.append(dict(type="i", ip=k, country=a["country"] or "", role=a["role"] or "", users=a["users"],
                              attacked=a["attacked"], fails=a["fails"], total=a["total"], deg=d))
    keep_ix = [i for i, n in enumerate(nodes) if n["deg"] or n.get("key") in seeds_u or n.get("ip") in seeds_i]
    remap = {old: new for new, old in enumerate(keep_ix)}
    nodes = [nodes[i] for i in keep_ix]
    links = [dict(l, a=remap[l["a"]], b=remap[l["b"]]) for l in links if l["a"] in remap and l["b"] in remap]
    if P(qs, "hosts", "1") == "1" and has("flows"):
        uix = {n["key"]: i for i, n in enumerate(nodes) if n["type"] == "u"}
        if uix:
            if rng.on:
                w, a = rng.clause("start")
                hl = chunked_in(c, "SELECT user_key, dst_ip, COUNT(*) conns, SUM(bytes) bytes, SUM(blocked) blocked "
                                   f"FROM flows WHERE user_key IN ({{IN}}){AND(w)} GROUP BY user_key, dst_ip",
                                list(uix), a)
            else:
                hl = chunked_in(c, "SELECT user_key, dst_ip, SUM(conns) conns, SUM(bytes) bytes, SUM(blocked) blocked "
                                   "FROM access WHERE user_key IN ({IN}) GROUP BY user_key, dst_ip", list(uix))
            roles = {r["ip"]: r for r in chunked_in(c, "SELECT ip, role, users, bytes FROM hosts WHERE ip IN ({IN})",
                                                    {r["dst_ip"] for r in hl})}
            per_u: dict = defaultdict(list)
            for r in hl:
                per_u[r["user_key"]].append(r)
            hix: dict = {}
            for uk, lst in per_u.items():
                lst.sort(key=lambda r: (-(roles.get(r["dst_ip"], {}).get("role") == "target"), -(r["bytes"] or 0),
                                        -r["conns"]))
                for r in lst[:10]:
                    if r["dst_ip"] not in hix:
                        if len(hix) >= 200:
                            continue
                        rr = roles.get(r["dst_ip"], {})
                        hix[r["dst_ip"]] = len(nodes)
                        nodes.append(dict(type="h", ip=r["dst_ip"], role=rr.get("role") or "", users=rr.get("users") or 0,
                                          total=rr.get("bytes") or 0, deg=0))
                    links.append(dict(a=uix[uk], b=hix[r["dst_ip"]], kind="int", sess=0, fails=0, up=0,
                                      down=r["bytes"] or 0, secs=0, conns=r["conns"], blocked=r["blocked"] or 0))
                if len(lst) > 10:
                    nodes[uix[uk]]["more_hosts"] = len(lst) - 10
    return dict(nodes=nodes, links=links, capped=capped, q=q)


# ---------------------------------------------------------------- interconnection: hosts, cases, timeline

def has(table):
    return table in POOL.tables


def host_obj(r, base=None):
    b = base or {}
    ports = [p.split(":") for p in (r.get("ports") or b.get("ports") or "").split() if ":" in p]
    return dict(ip=r["ip"], users=r.get("users") or 0, conns=r.get("conns") or 0, blocked=r.get("blocked") or 0,
                bytes=r.get("bytes") or 0, secs=r.get("connected_s") or r.get("secs") or 0,
                ports=[[p, int(n)] for p, n in ports], first=r.get("first_seen") or r.get("first"),
                last=r.get("last_seen") or r.get("last"), risk=b.get("risk", r.get("risk")) or 0,
                inc=b.get("incidents", r.get("incidents")) or 0, role=b.get("role", r.get("role")) or "")


def ranged_hosts(c, rng):
    def build():
        w, a = rng.clause("start")
        agg = {r["ip"]: r for r in rows(
            c, "SELECT dst_ip ip, COUNT(DISTINCT user_key) users, COUNT(*) conns, SUM(blocked) blocked, "
               f"SUM(bytes) bytes, SUM(duration_s) secs, MIN(start) first, MAX(ts) last FROM flows{W(w)} GROUP BY dst_ip",
            a)}
        ports: dict = {}
        for r in rows(c, f"SELECT dst_ip, dst_port || '/' || proto p, COUNT(*) n FROM flows{W(w)} "
                         "GROUP BY dst_ip, p ORDER BY n DESC", a):
            lst = ports.setdefault(r["dst_ip"], [])
            if len(lst) < 12:
                lst.append(f"{r['p']}:{r['n']}")
        base = {r["ip"]: r for r in chunked_in(c, "SELECT ip, risk, incidents, role FROM hosts WHERE ip IN ({IN})", agg)}
        return [host_obj(dict(r, ports=" ".join(ports.get(ip, []))), base.get(ip)) for ip, r in agg.items()]
    return cached(("hosts",) + rng.key(), build)


H_KEY = {"bytes": lambda h: (-h["bytes"], h["ip"]), "conns": lambda h: (-h["conns"], h["ip"]),
         "users": lambda h: (-h["users"], h["ip"]), "blocked": lambda h: (-h["blocked"], h["ip"]),
         "risk": lambda h: (-h["risk"], -h["bytes"], h["ip"]), "last": lambda h: (h["last"] or "", h["ip"])}


def api_hosts(c, qs):
    if not has("hosts"):
        return dict(total=0, rows=[], missing=True)
    rng = Rng(qs)
    q, role = P(qs, "q"), P(qs, "role")
    lim, off = I(qs, "limit", 200, 1, 2000), I(qs, "offset", 0, 0, 10**9)
    lst = ranged_hosts(c, rng) if rng.on else [host_obj(r) for r in rows(c, "SELECT * FROM hosts")]
    if q:
        lst = [h for h in lst if h["ip"].startswith(q)]
    if role:
        lst = [h for h in lst if h["role"] == role]
    key = P(qs, "sort") or "bytes"
    lst = sorted(lst, key=H_KEY.get(key, H_KEY["bytes"]), reverse=(key == "last"))
    return dict(total=len(lst), rows=lst[off:off + lim])


def api_host(c, qs):
    rng = Rng(qs)
    ip = P(qs, "ip")
    if not has("hosts"):
        raise NotFound("No internal connection data in this database")
    r = one(c, "SELECT * FROM hosts WHERE ip=?", (ip,))
    if not r:
        raise NotFound(f"Internal host {ip!r} not found")
    h = host_obj(r)
    if rng.on:
        h = next((x for x in ranged_hosts(c, rng) if x["ip"] == ip), None) or dict(
            h, users=0, conns=0, blocked=0, bytes=0, secs=0, ports=[], first=None, last=None)
    w, a = rng.clause("start")
    accts = rows(c, "SELECT user_key, COUNT(*) conns, SUM(blocked) blocked, SUM(bytes) bytes, SUM(duration_s) secs, "
                    "MIN(start) first, MAX(ts) last, GROUP_CONCAT(DISTINCT dst_port) ports FROM flows "
                    f"WHERE dst_ip=?{AND(w)} GROUP BY user_key ORDER BY bytes DESC LIMIT 500", [ip] + a)
    nm = {x["user_key"]: x for x in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})",
                                               [x["user_key"] for x in accts])}
    ports = rows(c, "SELECT dst_port port, proto, COUNT(*) conns, SUM(bytes) bytes, SUM(blocked) blocked, "
                    f"COUNT(DISTINCT user_key) users FROM flows WHERE dst_ip=?{AND(w)} GROUP BY dst_port, proto "
                    "ORDER BY conns DESC LIMIT 100", [ip] + a)
    g = [[x["user_key"], x["start"], x["ts"], x["duration_s"], x["bytes"], x["blocked"], x["dst_port"]] for x in rows(
        c, f"SELECT user_key, start, ts, duration_s, bytes, blocked, dst_port FROM flows WHERE dst_ip=?{AND(w)} "
           "ORDER BY start LIMIT 20000", [ip] + a)]
    iw, ia = rng.clause("start", "end", hours=False)
    return dict(
        host=h,
        accounts=[dict(k=x["user_key"], n=nm.get(x["user_key"], {}).get("name", x["user_key"]),
                       status=nm.get(x["user_key"], {}).get("status", "normal"), conns=x["conns"],
                       blocked=x["blocked"] or 0, bytes=x["bytes"] or 0, secs=x["secs"] or 0, first=x["first"],
                       last=x["last"], ports=sorted({int(p) for p in (x["ports"] or "").split(",") if p.isdigit()}))
                  for x in accts],
        ports=ports,
        names={k: dict(n=v["name"], status=v["status"]) for k, v in nm.items()},
        gantt=g,
        incidents=incidents_for(c, " WHERE id IN (SELECT incident_id FROM incident_hosts WHERE host=?)" + AND(iw),
                                [ip] + ia, INC_SORT["sev"], 200, 0),
    )


def api_cases(c, qs):
    if not has("cases"):
        return dict(total=0, rows=[], missing=True)
    w, a = Rng(qs).clause("start", "end", hours=False)
    sev = [s for s in P(qs, "sev").split(",") if s in ("critical", "high", "medium", "low")]
    if P(qs, "sev"):
        w.append(f"severity IN ({','.join('?' * len(sev))})" if sev else "0")
        a += sev
    q = P(qs, "q")
    if q:
        w.append("(title LIKE ? OR who LIKE ? OR users LIKE ? OR ips LIKE ? OR hosts LIKE ?)")
        a += [f"%{q}%"] * 5
    if P(qs, "user"):
        w.append("id IN (SELECT ci.case_id FROM case_incidents ci JOIN incident_users iu ON iu.incident_id=ci.incident_id "
                 "WHERE iu.user_key=?)")
        a.append(P(qs, "user").lower())
    stmap = REVIEW.status_map()
    rv = P(qs, "review")
    if rv in REVIEW_STATUS:
        if rv == "new":
            done = [k for k, v in stmap.items() if v != "new"]
            if done:
                w.append(f"COALESCE(ckey,'') NOT IN ({','.join('?' * len(done))})")
                a += done
        else:
            ks = [k for k, v in stmap.items() if v == rv]
            w.append(f"ckey IN ({','.join('?' * len(ks))})" if ks else "0")
            a += ks
    lim, off = I(qs, "limit", 30, 1, 200), I(qs, "offset", 0, 0, 10**9)
    items = rows(c, f"SELECT * FROM cases{W(w)} ORDER BY sev_rank, score DESC, start DESC LIMIT ? OFFSET ?",
                 a + [lim, off])
    out = []
    for x in items:
        us = x["users"].split() if x["users"] else []
        nm = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})", us)}
        out.append(dict(review=stmap.get(x.get("ckey") or "", "new"), summary=x.get("summary") or "",
                        id=x["id"], sev=x["severity"], score=x["score"], title=x["title"], who=x["who"],
                        start=x["start"], end=x["end"], n=x["n_incidents"],
                        users=[dict(k=u, n=nm.get(u, {}).get("name", u), status=nm.get(u, {}).get("status", "")) for u in us],
                        ips=x["ips"].split() if x["ips"] else [], hosts=x["hosts"].split() if x["hosts"] else [],
                        incidents=incidents_for(c, " WHERE id IN (SELECT incident_id FROM case_incidents WHERE case_id=?)",
                                                [x["id"]], "start ASC, sev_rank ASC", 200, 0)))
    idx = "/cases/index.html" if CASE_DIR and os.path.exists(os.path.join(CASE_DIR, "index.html")) else ""
    return dict(total=val(c, f"SELECT COUNT(*) FROM cases{W(w)}", a), rows=out, index=idx)


def api_timeline(c, qs):
    """One chronological story for an account, a source IP or an internal host."""
    rng = Rng(qs)
    user, ip, host = P(qs, "user").lower(), P(qs, "ip"), P(qs, "host")
    sw, sa = rng.clause("start", "end")
    s0, s0a = rng.clause("start")
    fw, fa = rng.clause("ts")
    iw, ia = rng.clause("start", "end", hours=False)
    items: list = []
    names: dict = {}
    scols = POOL.session_cols

    def inc(where, args):
        for x in incidents_for(c, where + AND(iw), args + ia, "start ASC", 300, 0):
            items.append(dict(t=x["start"], cat="incident", sev=x["sev"], title=x["title"], detail=x["detail"],
                              seqs=x["seqs"][:30]))

    def sess(where, args, with_user):
        extra = ", client, int_hosts, int_bytes" if "client" in scols else ""
        for s in rows(c, f"SELECT user_key, user, outside_ip, start, end, duration_s, bytes_up, bytes_down, "
                         f"end_estimated{extra} FROM sessions WHERE {where}{AND(sw)} ORDER BY start LIMIT 400",
                      args + sa):
            items.append(dict(t=s["start"], cat="login", title="VPN session started", u=s["user_key"] if with_user else "",
                              n=s["user"], ip=s["outside_ip"], detail=s.get("client") or ""))
            ih = s.get("int_hosts") or 0
            items.append(dict(t=s["end"], cat="logout", u=s["user_key"] if with_user else "", n=s["user"],
                              title=("Session end (estimated)" if s["end_estimated"] else "VPN session ended"),
                              detail=f"{hd(s['duration_s'])}, uploaded {hb(s['bytes_up'])}, downloaded "
                                     f"{hb(s['bytes_down'])}" + (f", reached {ih} internal hosts" if ih else "")))

    def admin_events(where, args):
        for e in rows(c, f"SELECT ts, kind, user, outside_ip, reason FROM events WHERE {where} AND kind IN "
                         f"('LOCKOUT','MGMT_LOGIN_OK','MGMT_LOGIN_FAIL','CONFIG_CMD','PRIV_CHANGE','THREAT')"
                         f"{AND(fw)} ORDER BY ts LIMIT 400", args + fa):
            lbl = {"LOCKOUT": "Account locked out", "MGMT_LOGIN_OK": "Firewall admin login",
                   "MGMT_LOGIN_FAIL": "Failed firewall admin login", "CONFIG_CMD": "Firewall command",
                   "PRIV_CHANGE": "Admin privilege changed", "THREAT": "Threat detection"}[e["kind"]]
            items.append(dict(t=e["ts"], cat="admin" if e["kind"] != "THREAT" else "probe", title=lbl,
                              u=(e["user"] or "").lower(), n=e["user"] or "", ip=e["outside_ip"] or "",
                              detail=e["reason"] or ""))

    def flows(where, args, by):
        if not has("flows"):
            return
        grp = "dst_ip" if by == "user" else "user_key"   # an account's story lists hosts; a host's story lists accounts
        rs = rows(c, f"SELECT substr(start,1,13) h, {grp} k, COUNT(*) n, SUM(bytes) b, SUM(blocked) bl, "
                     f"GROUP_CONCAT(DISTINCT dst_port) ports, MIN(start) t FROM flows WHERE {where}{AND(s0)} "
                     f"GROUP BY h, k ORDER BY t LIMIT 3000", args + s0a)
        by_h: dict = {}
        for r in rs:
            by_h.setdefault(r["h"], []).append(r)
        for h, lst in by_h.items():
            lst.sort(key=lambda r: -(r["b"] or 0))
            blocked = sum(r["bl"] or 0 for r in lst)
            n = sum(r["n"] for r in lst)
            b = sum(r["b"] or 0 for r in lst)
            ports = sorted({int(p) for r in lst for p in (r["ports"] or "").split(",") if p.isdigit()})
            if by == "user":
                items.append(dict(t=lst[0]["t"] if len(lst) == 1 else min(r["t"] for r in lst), cat="access",
                                  title=f"Reached {len(lst)} internal host{'s' if len(lst) != 1 else ''}",
                                  hosts=[r["k"] for r in lst[:8]], more=max(0, len(lst) - 8), ports=ports[:12],
                                  detail=f"{n} connections, {hb(b)}" + (f", {blocked} blocked" if blocked else ""),
                                  blocked=blocked))
            else:
                for r in lst[:6]:
                    names.setdefault(r["k"], None)
                    items.append(dict(t=r["t"], cat="access", title="Accessed this host", u=r["k"],
                                      ports=sorted({int(p) for p in (r["ports"] or "").split(",") if p.isdigit()})[:12],
                                      detail=f"{r['n']} connections, {hb(r['b'] or 0)}"
                                             + (f", {r['bl']} blocked" if r["bl"] else ""), blocked=r["bl"] or 0))
                if len(lst) > 6:
                    items.append(dict(t=lst[0]["t"], cat="access", title=f"...and {len(lst) - 6} more accounts this hour"))

    if user:
        sess("user_key=?", [user], False)
        for r in rows(c, "SELECT substr(ts,1,16) m, outside_ip, COUNT(*) n, MIN(reason) reason, MIN(ts) t FROM events "
                         f"WHERE user=? COLLATE NOCASE AND kind='INVALID_PW'{AND(fw)} GROUP BY m, outside_ip "
                         "ORDER BY m LIMIT 500", [user] + fa):
            items.append(dict(t=r["t"], cat="fail", cnt=r["n"], ip=r["outside_ip"], detail=r["reason"] or ""))
        admin_events("user=? COLLATE NOCASE", [user])
        flows("user_key=?", [user], "user")
        inc(" WHERE id IN (SELECT incident_id FROM incident_users WHERE user_key=?)", [user])
    elif ip:
        sess("outside_ip=?", [ip], True)
        for r in rows(c, "SELECT substr(ts,1,16) m, COUNT(*) n, COUNT(DISTINCT lower(user)) nu, MIN(ts) t, "
                         f"GROUP_CONCAT(DISTINCT user) us FROM events WHERE outside_ip=? AND kind='INVALID_PW'{AND(fw)} "
                         "GROUP BY m ORDER BY m LIMIT 500", [ip] + fa):
            us = [x for x in (r["us"] or "").split(",") if x][:6]
            items.append(dict(t=r["t"], cat="fail", cnt=r["n"], accts=us, detail=""))
        if has("conns"):
            for r in rows(c, "SELECT substr(ts,1,15) m, COUNT(*) n, COUNT(DISTINCT p2) np, COUNT(DISTINCT ip2) nh, "
                             "MIN(ts) t, GROUP_CONCAT(DISTINCT p2) ports FROM conns WHERE ip1=? AND action='deny'"
                             f"{AND(fw)} GROUP BY m ORDER BY m LIMIT 300", [ip] + fa):
                items.append(dict(t=r["t"], cat="probe", title=f"{r['n']} blocked probe{'s' if r['n'] != 1 else ''}",
                                  detail=f"{r['np']} ports on {r['nh']} address{'es' if r['nh'] != 1 else ''}",
                                  ports=sorted({int(p) for p in (r["ports"] or "").split(",") if p.isdigit()})[:12]))
        admin_events("outside_ip=?", [ip])
        inc(" WHERE id IN (SELECT incident_id FROM incident_ips WHERE ip=?)", [ip])
    elif host:
        flows("dst_ip=?", [host], "host")
        inc(" WHERE id IN (SELECT incident_id FROM incident_hosts WHERE host=?)", [host])
    else:
        raise NotFound("Give user, ip or host")
    ukeys = {x["u"] for x in items if x.get("u")}
    for r in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})", ukeys):
        names[r["user_key"]] = dict(n=r["name"], status=r["status"])
    for x in items:
        if x.get("u") and x["u"] in names and names[x["u"]]:
            x["n"] = names[x["u"]]["n"]
    items.sort(key=lambda x: (x["t"] or "", 0 if x["cat"] == "incident" else 1))
    # merge runs of failed logins (same source, less than 5 minutes apart) into one line
    merged: list = []
    last_fail = None
    for x in items:
        if x["cat"] == "fail":
            if (last_fail is not None and last_fail.get("ip") == x.get("ip")
                    and (x["t"] or "") <= _plus_minutes(last_fail["_last"], 5)):
                last_fail["cnt"] += x["cnt"]
                last_fail["_last"] = x["t"]
                for a_ in x.get("accts", []):
                    if a_ not in last_fail["accts"]:
                        last_fail["accts"].append(a_)
                continue
            x["_last"] = x["t"]
            x.setdefault("accts", [])
            last_fail = x
        merged.append(x)
    for x in merged:
        if x["cat"] == "fail":
            span = _minutes_between(x["t"], x.pop("_last"))
            accts = x.pop("accts")
            x["title"] = (f"{x['cnt']} failed login{'s' if x['cnt'] != 1 else ''}"
                          + (f" against {len(accts)} account{'s' if len(accts) != 1 else ''}" if accts else "")
                          + (f" over {span} min" if span >= 1 else ""))
            if accts:
                x["detail"] = ", ".join(accts[:8]) + (" ..." if len(accts) > 8 else "")
    items = merged
    lim = 1500
    return dict(items=items[:lim], truncated=len(items) > lim)


def _plus_minutes(ts, m):
    try:
        return (dt.datetime.fromisoformat(ts) + dt.timedelta(minutes=m)).isoformat(sep=" ")
    except (TypeError, ValueError):
        return ts or ""


def _minutes_between(a, b):
    try:
        return round((dt.datetime.fromisoformat(b) - dt.datetime.fromisoformat(a)).total_seconds() / 60)
    except (TypeError, ValueError):
        return 0


def hb(n):
    x = float(n or 0)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if x < 1024:
            return f"{x:.2f} {u}" if u != "B" else f"{int(x)} B"
        x /= 1024
    return f"{x:.2f} PB"


def hd(sec):
    sec = int(sec or 0)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m"


# ---------------------------------------------------------------- case review (evidence walk-through)

REVIEW_STATUS = ("new", "investigating", "confirmed", "false_positive", "closed")


class ReviewStore:
    """Analyst decisions per case, kept in a small JSON file next to the DB (the DB itself stays read-only).
    Cases are keyed by a stable hash, so notes survive a re-analysis."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {}
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict):
                self.data = d
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[warn] could not read {path}: {e}", file=sys.stderr)

    def get(self, key):
        with self.lock:
            return dict(self.data.get(key) or {"status": "new", "notes": "", "actions_done": [], "steps_done": []})

    def status_map(self):
        with self.lock:
            return {k: v.get("status", "new") for k, v in self.data.items()}

    def update(self, key, patch):
        with self.lock:
            cur = dict(self.data.get(key) or {"status": "new", "notes": "", "actions_done": [], "steps_done": []})
            if "status" in patch and patch["status"] in REVIEW_STATUS:
                cur["status"] = patch["status"]
            if isinstance(patch.get("notes"), str):
                cur["notes"] = patch["notes"][:50000]
            if isinstance(patch.get("reviewer"), str):
                cur["reviewer"] = patch["reviewer"][:100]
            for f in ("actions_done", "steps_done"):
                if isinstance(patch.get(f), list):
                    cur[f] = [str(x)[:300] for x in patch[f]][:500]
            cur["updated"] = dt.datetime.now().isoformat(sep=" ", timespec="seconds")
            self.data[key] = cur
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)   # atomic, so a crash never leaves a half-written file
            return dict(cur)


REVIEW: "ReviewStore" = None  # type: ignore
TOKEN = ""
CASE_DIR = ""


def step_key(x):
    return f"{x['type']}|{x['start']}"


def api_case(c, qs):
    if not has("cases"):
        raise NotFound("No cases in this database")
    cid = I(qs, "id", 0, 0, 10**9)
    x = one(c, "SELECT * FROM cases WHERE id=?", (cid,))
    if not x:
        raise NotFound(f"Case {cid} not found")
    incs = incidents_for(c, " WHERE id IN (SELECT incident_id FROM case_incidents WHERE case_id=?)", [cid],
                         "start ASC, sev_rank ASC", 500, 0)
    ev: dict = {}
    if has("case_evidence"):
        for r in rows(c, "SELECT incident_id, seq, ts, source, kind, text, raw FROM case_evidence WHERE case_id=? "
                         "ORDER BY incident_id, ts, seq", (cid,)):
            ev.setdefault(r["incident_id"], []).append([r["seq"], r["ts"], r["source"], r["kind"], r["raw"] or r["text"]])
    for i in incs:
        i["key"] = step_key(i)
        i["evidence"] = ev.get(i["id"], [])
    sess = []
    if has("case_sessions"):
        sess = [sess_obj(r) for r in rows(c, f"{SESS_SELECT} WHERE s.id IN (SELECT session_id FROM case_sessions "
                                             "WHERE case_id=?) ORDER BY s.start", (cid,))]
    us = (x["users"] or "").split()
    ips = (x["ips"] or "").split()
    unm = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status, sessions, failed_logins, bytes_down "
                                                   "FROM users WHERE user_key IN ({IN})", us)}
    ipm = {r["ip"]: r for r in chunked_in(c, "SELECT ip, country, role, failed_logins, sessions FROM ips "
                                             "WHERE ip IN ({IN})", ips)}
    ckey = x.get("ckey") or f"case{cid}"
    report = x.get("report") or ""
    return dict(
        id=cid, key=ckey, sev=x["severity"], title=x["title"], who=x["who"], start=x["start"], end=x["end"],
        summary=x.get("summary") or "", actions=json.loads(x.get("actions") or "[]"),
        report=f"/cases/{report}" if report and CASE_DIR and os.path.exists(os.path.join(CASE_DIR, report)) else "",
        users=[dict(k=u, n=unm.get(u, {}).get("name", u), status=unm.get(u, {}).get("status", ""),
                    sess=unm.get(u, {}).get("sessions", 0), fails=unm.get(u, {}).get("failed_logins", 0),
                    down=unm.get(u, {}).get("bytes_down", 0)) for u in us],
        ips=[dict(ip=i, country=ipm.get(i, {}).get("country", ""), role=ipm.get(i, {}).get("role", ""),
                  fails=ipm.get(i, {}).get("failed_logins", 0), sess=ipm.get(i, {}).get("sessions", 0)) for i in ips],
        hosts=(x["hosts"] or "").split(), incidents=incs, sessions=sess, review=REVIEW.get(ckey), graph=case_graph(c, x))

def api_countries(c, qs):
    """Where VPN logins and failed logins come from, by country (respects the time filter)."""
    rng = Rng(qs)

    def build():
        sw, sa = rng.clause("start", "end")
        fw, fa = rng.clause("ts")
        out: dict = {}
        for r in rows(c, "SELECT i.cc, MAX(i.country) country, COUNT(*) sess, COUNT(DISTINCT s.user_key) users, "
                         "COUNT(DISTINCT s.outside_ip) ips, SUM(s.bytes_up) up, SUM(s.bytes_down) down, "
                         "SUM(s.duration_s) secs, MIN(s.start) first, MAX(s.start) last FROM sessions s "
                         f"JOIN ips i ON i.ip = s.outside_ip WHERE COALESCE(i.cc,'') <> ''{AND(sw)} GROUP BY i.cc", sa):
            out[r["cc"]] = dict(r, fails=0, fail_ips=0, attackers=0, targets=0)
        for r in rows(c, "SELECT i.cc, MAX(i.country) country, COUNT(*) fails, COUNT(DISTINCT e.outside_ip) fail_ips, "
                         "COUNT(DISTINCT lower(e.user)) targets FROM events e JOIN ips i ON i.ip = e.outside_ip "
                         f"WHERE e.kind='INVALID_PW' AND COALESCE(i.cc,'') <> ''{AND(fw)} GROUP BY i.cc", fa):
            x = out.setdefault(r["cc"], dict(cc=r["cc"], country=r["country"], sess=0, users=0, ips=0, up=0, down=0,
                                             secs=0, first=None, last=None, attackers=0))
            x.update(fails=r["fails"], fail_ips=r["fail_ips"], targets=r["targets"])
        for r in rows(c, "SELECT cc, COUNT(*) n FROM ips WHERE role='attacker' AND COALESCE(cc,'') <> '' GROUP BY cc"):
            if r["cc"] in out:
                out[r["cc"]]["attackers"] = r["n"]
        unknown = val(c, "SELECT COUNT(*) FROM sessions s LEFT JOIN ips i ON i.ip = s.outside_ip "
                         f"WHERE COALESCE(i.cc,'') = ''{AND(sw)}", sa)
        return dict(rows=sorted(out.values(), key=lambda x: (-(x["sess"] or 0), -(x["fails"] or 0))), unknown=unknown)

    meta = json.loads(val(c, "SELECT value FROM meta WHERE key='summary'") or "{}")
    d = cached(("countries",) + rng.key(), build)
    return dict(d, geo=bool(meta.get("geo")), home=meta.get("home_countries") or [])


def lr_obj(r):
    return dict(id=r["id"], ts=r["ts"], k=r["user_key"], n=r["user"], ip=r["ip"], country=r["country"] or "",
                score=r["score"], verdict=r["verdict"], reasons=json.loads(r["reasons"] or "[]"),
                ip_fails=r["ip_fails"], ip_accounts=r["ip_accounts"], user_fails=r["user_fails"],
                other_fails=r["other_ip_fails"], gap=r["gap_s"], known=r["known_ip"], first=r["first_fail"],
                seqs=[int(x) for x in (r["evidence_seq"] or "").split() if x.isdigit()], inc=r["incident_id"])


def api_logins(c, qs):
    """Every successful login that had failures before it, with its score and evidence."""
    if not has("login_reviews"):
        return dict(total=0, rows=[], counts={}, missing=True)
    w, a = Rng(qs).clause("ts")
    base_w, base_a = list(w), list(a)
    vs = [v for v in P(qs, "verdict").split(",") if v in ("compromised", "likely", "review", "benign")]
    if vs:
        w.append(f"verdict IN ({','.join('?' * len(vs))})")
        a += vs
    q = P(qs, "q")
    if q:
        w.append("(user LIKE ? OR ip LIKE ? OR country LIKE ?)")
        a += [f"%{q}%"] * 3
        base_w.append("(user LIKE ? OR ip LIKE ? OR country LIKE ?)")
        base_a += [f"%{q}%"] * 3
    if P(qs, "user"):
        w.append("user_key=?")
        a.append(P(qs, "user").lower())
    if P(qs, "ip"):
        w.append("ip=?")
        a.append(P(qs, "ip"))
    order = "ts DESC" if P(qs, "sort") == "time" else "score DESC, ts DESC"
    lim, off = I(qs, "limit", 100, 1, 1000), I(qs, "offset", 0, 0, 10**9)
    counts = {r["verdict"]: r["n"] for r in rows(c, f"SELECT verdict, COUNT(*) n FROM login_reviews{W(base_w)} "
                                                    "GROUP BY verdict", base_a)}
    return dict(total=val(c, f"SELECT COUNT(*) FROM login_reviews{W(w)}", a), counts=counts,
                rows=[lr_obj(r) for r in rows(c, f"SELECT * FROM login_reviews{W(w)} ORDER BY {order} LIMIT ? OFFSET ?",
                                              a + [lim, off])])


# ---------------------------------------------------------------- investigation matrices & charts

TACTICS = [("recon", "Reconnaissance", "TA0043"), ("cred", "Credential Access", "TA0006"),
           ("init", "Initial Access", "TA0001"), ("anom", "Login anomalies", ""),
           ("disc", "Discovery", "TA0007"), ("lat", "Lateral Movement", "TA0008"),
           ("evas", "Defense Evasion", "TA0005"), ("c2", "Command and Control", "TA0011"),
           ("exfil", "Exfiltration", "TA0010")]
TYPE_TACTIC = {"port_scan": "recon", "threat_detection": "recon",
               "brute_force": "cred", "password_spray": "cred", "account_lockout": "cred", "admin_brute_force": "cred",
               "compromise": "init", "attack_ip_login": "init", "login_from_scanner": "init",
               "suspicious_login": "init", "shared_new_ip": "init", "coordinated_attack": "cred",
               "admin_login_internet": "init",
               "concurrent_sessions": "anom", "impossible_travel": "anom", "new_country": "anom",
               "foreign_login": "anom", "new_client": "anom", "unusual_time": "anom", "shared_ip": "anom",
               "long_session": "anom",
               "internal_scan": "disc", "lateral_movement": "lat", "post_compromise": "lat",
               "logging_tampered": "evas", "config_change": "evas", "large_upload": "c2",
               "large_download": "exfil", "unusual_download": "exfil", "large_transfer": "exfil"}
SEV_W = {"critical": 40, "high": 15, "medium": 5, "low": 1}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def api_matrix(c, qs):
    rng = Rng(qs)
    mode = P(qs, "mode") or "attack"
    lim = I(qs, "limit", 40, 5, 200)
    q = P(qs, "q").lower()
    if mode == "access":
        return matrix_access(c, rng, lim, q)
    iw, ia = rng.clause("start", "end", hours=False)
    incs = {r["id"]: r for r in rows(c, f"SELECT id, type, severity, title, start, n_users FROM incidents{W(iw)}", ia)}
    ent: dict = {}

    def cell(key, x):
        tac = TYPE_TACTIC.get(x["type"])
        if not tac:
            return
        e = ent.setdefault(key, dict(cells={}, risk=0, n=0))
        cl = e["cells"].setdefault(tac, dict(n=0, sev="low", items=[]))
        cl["n"] += 1
        if SEV_RANK[x["severity"]] < SEV_RANK[cl["sev"]]:
            cl["sev"] = x["severity"]
        if len(cl["items"]) < 12:
            cl["items"].append([x["id"], x["title"], x["severity"], x["start"], x["type"]])
        e["risk"] += SEV_W[x["severity"]]
        e["n"] += 1

    ids = list(incs)
    kinds = set((P(qs, "kinds") or "u,i,h").split(","))
    if "u" in kinds:
        for r in chunked_in(c, "SELECT incident_id, user_key FROM incident_users WHERE incident_id IN ({IN})", ids):
            x = incs[r["incident_id"]]
            if (x["n_users"] or 0) <= 3:          # spray targets are shown on the attacking IP's row
                cell(("u", r["user_key"]), x)
    if "i" in kinds:
        for r in chunked_in(c, "SELECT incident_id, ip FROM incident_ips WHERE incident_id IN ({IN})", ids):
            cell(("i", r["ip"]), incs[r["incident_id"]])
    if "h" in kinds and has("incident_hosts"):
        for r in chunked_in(c, "SELECT incident_id, host FROM incident_hosts WHERE incident_id IN ({IN})", ids):
            cell(("h", r["host"]), incs[r["incident_id"]])
    if q:
        ent = {k: v for k, v in ent.items() if q in k[1].lower()}
    worst = lambda e: min(SEV_RANK[c_["sev"]] for c_ in e["cells"].values())
    top = sorted(ent.items(), key=lambda kv: (worst(kv[1]), -kv[1]["risk"], -kv[1]["n"], kv[0][1]))[:lim]
    uinfo = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})",
                                                  [k[1] for k, _ in top if k[0] == "u"])}
    iinfo = {r["ip"]: r for r in chunked_in(c, "SELECT ip, country, role FROM ips WHERE ip IN ({IN})",
                                            [k[1] for k, _ in top if k[0] == "i"])}
    out = []
    for (kind, key), e in top:
        if kind == "u":
            u = uinfo.get(key, {})
            out.append(dict(kind="u", key=key, label=u.get("name", key), sub=u.get("status", ""), **e))
        elif kind == "i":
            i = iinfo.get(key, {})
            out.append(dict(kind="i", key=key, label=key, sub=i.get("role", ""), country=i.get("country") or "", **e))
        else:
            out.append(dict(kind="h", key=key, label=key, sub="internal host", **e))
    return dict(mode="attack", columns=[dict(id=t, name=nm, ref=ref) for t, nm, ref in TACTICS], rows=out,
                total=len(ent))


def matrix_access(c, rng, lim, q):
    """Accounts x source IPs: sessions and failed logins in each cell."""
    if rng.on:
        L = {k: dict(sessions=r["sessions"], fails=r["failed_logins"]) for k, r in ranged_links(c, rng).items()}
    else:
        L = {(r["user_key"], r["ip"]): dict(sessions=r["sessions"], fails=r["failed_logins"])
             for r in rows(c, "SELECT user_key, ip, sessions, failed_logins FROM links")}
    users = {r["user_key"]: r for r in rows(c, "SELECT user_key, name, status, risk FROM users WHERE status <> 'normal'"
                                               " OR user_key IN (SELECT user_key FROM incident_users)")}
    ucand = list(users)
    if q:
        ucand = [u for u in ucand if q in u] or [u for (u, ip) in L if q in u or ip.startswith(q)]
    used = {}
    for (u, ip), v in L.items():
        if u in ucand or (q and ip.startswith(q)):
            used.setdefault(u, 0)
            used[u] += v["sessions"] + v["fails"]
    st_rank = {"compromise": 0, "review": 1, "targeted": 2, "watch": 3, "normal": 4}
    extra = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status, risk FROM users WHERE user_key IN ({IN})",
                                                  [u for u in used if u not in users])}
    users.update(extra)
    urows = sorted(used, key=lambda u: (st_rank.get(users.get(u, {}).get("status"), 5),
                                        -(users.get(u, {}).get("risk") or 0), -used[u]))[:lim]
    ipset: dict = {}
    for (u, ip), v in L.items():
        if u in urows:
            ipset[ip] = ipset.get(ip, 0) + v["sessions"] * 1 + v["fails"] * 3
    iinfo = {r["ip"]: r for r in chunked_in(c, "SELECT ip, country, role, risk FROM ips WHERE ip IN ({IN})", ipset)}
    r_rank = {"attacker": 0, "compromise": 1, "review": 2, "shared": 3, "": 4}
    icols = sorted(ipset, key=lambda ip: (r_rank.get(iinfo.get(ip, {}).get("role") or "", 4),
                                          -(iinfo.get(ip, {}).get("risk") or 0), -ipset[ip]))[:max(lim, 30)]
    return dict(mode="access",
                columns=[dict(id=ip, name=ip, country=iinfo.get(ip, {}).get("country") or "",
                              role=iinfo.get(ip, {}).get("role") or "") for ip in icols],
                rows=[dict(kind="u", key=u, label=users.get(u, {}).get("name", u), sub=users.get(u, {}).get("status", ""),
                           cells={ip: L[(u, ip)] for ip in icols if (u, ip) in L}) for u in urows],
                total=len(used))


def api_heatmap(c, qs):
    rng = Rng(qs)
    sw, sa = rng.clause("start")
    fw, fa = rng.clause("ts")
    def build():
        sess = rows(c, "SELECT CAST(strftime('%w', start) AS INTEGER) dow, CAST(substr(start, 12, 2) AS INTEGER) h, "
                       "COUNT(*) n, SUM(bytes_down) down, COUNT(DISTINCT user_key) users FROM sessions "
                       f"WHERE start IS NOT NULL{AND(sw)} GROUP BY dow, h", sa)
        fails = rows(c, "SELECT CAST(strftime('%w', ts) AS INTEGER) dow, CAST(substr(ts, 12, 2) AS INTEGER) h, "
                        "COUNT(*) n, COUNT(DISTINCT outside_ip) ips FROM events "
                        f"WHERE kind='INVALID_PW' AND ts IS NOT NULL{AND(fw)} GROUP BY dow, h", fa)
        return dict(sessions=[[r["dow"], r["h"], r["n"], r["users"]] for r in sess],
                    down=[[r["dow"], r["h"], r["down"] or 0, r["users"]] for r in sess],
                    fails=[[r["dow"], r["h"], r["n"], r["ips"]] for r in fails])
    return cached(("heat",) + rng.key(), build)


def api_inctrend(c, qs):
    rng = Rng(qs)
    unit = "hour" if P(qs, "unit") == "hour" else "day"
    n = 13 if unit == "hour" else 10
    iw, ia = rng.clause("start", "end", hours=False)
    out: dict = {}
    for r in rows(c, f"SELECT substr(start, 1, {n}) d, severity, COUNT(*) k FROM incidents{W(iw)} GROUP BY d, severity", ia):
        out.setdefault(r["d"], dict(d=r["d"], critical=0, high=0, medium=0, low=0))[r["severity"]] = r["k"]
    return dict(unit=unit, rows=sorted(out.values(), key=lambda x: x["d"]))


def case_graph(c, x):
    """Source IPs -> accounts -> internal hosts for one case, for the attack-flow drawing."""
    us = (x["users"] or "").split()
    ips = (x["ips"] or "").split()
    hosts = (x["hosts"] or "").split()[:60]
    try:
        a = (dt.datetime.fromisoformat(x["start"]) - dt.timedelta(days=1)).isoformat(sep=" ")
        b = (dt.datetime.fromisoformat(x["end"]) + dt.timedelta(days=1)).isoformat(sep=" ")
    except (TypeError, ValueError):
        a, b = "0000", "9999"
    nodes, idx, links = [], {}, []
    uinfo = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})", us)}
    iinfo = {r["ip"]: r for r in chunked_in(c, "SELECT ip, country, role FROM ips WHERE ip IN ({IN})", ips)}
    hinfo = {r["ip"]: r for r in chunked_in(c, "SELECT ip, role FROM hosts WHERE ip IN ({IN})", hosts)} if has("hosts") else {}
    for u in us:
        idx[("u", u)] = len(nodes)
        nodes.append(dict(type="u", key=u, n=uinfo.get(u, {}).get("name", u), status=uinfo.get(u, {}).get("status", "")))
    tried = {r["outside_ip"]: r["n"] for r in chunked_in(
        c, "SELECT outside_ip, COUNT(DISTINCT lower(user)) n FROM events WHERE kind='INVALID_PW' AND outside_ip IN ({IN}) "
           "AND ts BETWEEN ? AND ? GROUP BY outside_ip", ips, [a, b])}
    for ip in ips:
        idx[("i", ip)] = len(nodes)
        nodes.append(dict(type="i", ip=ip, country=iinfo.get(ip, {}).get("country") or "",
                          role=iinfo.get(ip, {}).get("role") or "", tried=tried.get(ip, 0)))
    for h in hosts:
        idx[("h", h)] = len(nodes)
        nodes.append(dict(type="h", ip=h, role=hinfo.get(h, {}).get("role") or ""))
    lk: dict = {}
    if us and ips:
        for r in chunked_in(c, "SELECT user_key, outside_ip, COUNT(*) n, SUM(bytes_up) up, SUM(bytes_down) down "
                               "FROM sessions WHERE user_key IN ({IN}) AND start BETWEEN ? AND ? GROUP BY user_key, "
                               "outside_ip", us, [a, b]):
            if ("i", r["outside_ip"]) in idx:
                lk[(r["user_key"], r["outside_ip"])] = dict(a=idx[("u", r["user_key"])], b=idx[("i", r["outside_ip"])],
                                                            kind="login", sess=r["n"], fails=0, up=r["up"] or 0,
                                                            down=r["down"] or 0)
        for r in chunked_in(c, "SELECT lower(user) u, outside_ip, COUNT(*) n FROM events WHERE kind='INVALID_PW' AND "
                               "lower(user) IN ({IN}) AND ts BETWEEN ? AND ? GROUP BY u, outside_ip", us, [a, b]):
            if ("i", r["outside_ip"]) in idx and ("u", r["u"]) in idx:
                l_ = lk.setdefault((r["u"], r["outside_ip"]), dict(a=idx[("u", r["u"])], b=idx[("i", r["outside_ip"])],
                                                                    kind="login", sess=0, fails=0, up=0, down=0))
                l_["fails"] = r["n"]
    links = list(lk.values())
    if us and hosts and has("flows"):
        for r in chunked_in(c, "SELECT user_key, dst_ip, COUNT(*) n, SUM(bytes) b, SUM(blocked) bl FROM flows "
                               "WHERE user_key IN ({IN}) AND start BETWEEN ? AND ? GROUP BY user_key, dst_ip", us, [a, b]):
            if ("h", r["dst_ip"]) in idx:
                links.append(dict(a=idx[("u", r["user_key"])], b=idx[("h", r["dst_ip"])], kind="int", conns=r["n"],
                                  down=r["b"] or 0, blocked=r["bl"] or 0, sess=0, fails=0, up=0))
    return dict(nodes=nodes, links=links)


# ---------------------------------------------------------------- hunting: search, compromised accounts, IP clusters

def api_search(c, qs):
    q = P(qs, "q").strip()
    if len(q) < 2:
        return dict(results=[])
    like, pre = f"%{q}%", f"{q}%"
    res = []
    st_ord = "CASE status WHEN 'compromise' THEN 0 WHEN 'review' THEN 1 WHEN 'targeted' THEN 2 WHEN 'watch' THEN 3 ELSE 4 END"
    for r in rows(c, f"SELECT user_key, name, status, risk, sessions, failed_logins FROM users WHERE user_key LIKE ? "
                     f"OR name LIKE ? ORDER BY {st_ord}, risk DESC, sessions DESC LIMIT 8", (like, like)):
        res.append(dict(type="u", k=r["user_key"], label=r["name"], status=r["status"],
                        sub=f"{r['sessions']} sessions, {r['failed_logins']} failed logins"))
    for r in rows(c, "SELECT ip, country, role, risk, sessions, failed_logins FROM ips WHERE ip LIKE ? OR country LIKE ? "
                     "ORDER BY risk DESC, sessions DESC LIMIT 8", (pre, like)):
        res.append(dict(type="i", k=r["ip"], label=r["ip"], status=r["role"] or "", country=r["country"] or "",
                        sub=f"{r['sessions']} sessions, {r['failed_logins']} failed logins"))
    if has("hosts"):
        for r in rows(c, "SELECT ip, role, users, conns FROM hosts WHERE ip LIKE ? ORDER BY risk DESC, conns DESC LIMIT 5", (pre,)):
            res.append(dict(type="h", k=r["ip"], label=r["ip"], status=r["role"] or "",
                            sub=f"internal host, {r['users']} accounts"))
    if has("cases"):
        for r in rows(c, "SELECT id, who, title, severity FROM cases WHERE who LIKE ? OR users LIKE ? OR ips LIKE ? "
                         "OR hosts LIKE ? ORDER BY sev_rank LIMIT 5", (like,) * 4):
            res.append(dict(type="case", k=r["id"], label=f"Case {r['id']}: {r['who']}", status=r["severity"],
                            sub=r["title"]))
    if has("campaigns"):
        for r in rows(c, "SELECT id, title, severity FROM campaigns WHERE ips LIKE ? OR success LIKE ? OR targets LIKE ? "
                         "ORDER BY sev_rank LIMIT 5", (like,) * 3):
            res.append(dict(type="camp", k=r["id"], label=f"IP cluster #{r['id']}", status=r["severity"], sub=r["title"]))
    return dict(results=res)


HUNT_CHIP = {"suspicious_login": "Looks like someone else (no failures)", "shared_new_ip": "New IP shared with other accounts",
             "compromise": "Got in after failed logins", "attack_ip_login": "Got in from attacking IP",
             "login_from_scanner": "Got in from scanning IP", "coordinated_attack": "Targeted by IP cluster",
             "internal_scan": "Scanned the network", "lateral_movement": "Lateral movement",
             "post_compromise": "Reached internal servers", "large_download": "Large download",
             "unusual_download": "Unusual download", "new_client": "New device", "foreign_login": "Login from abroad",
             "new_country": "New country", "impossible_travel": "Country change", "concurrent_sessions": "Two places at once",
             "unusual_time": "Odd hour", "account_lockout": "Locked out", "brute_force": "Brute forced",
             "admin_login_internet": "Firewall admin login", "logging_tampered": "Cleared logs",
             "config_change": "Changed firewall", "large_upload": "Large upload"}


def api_hunt(c, qs):
    rng = Rng(qs)
    iw, ia = rng.clause("start", "end", hours=False)
    lw, la = rng.clause("ts")
    sw, sa = rng.clause("start", "end")
    want = [x for x in (P(qs, "status") or "compromise,review").split(",") if x]
    q = P(qs, "q").lower()
    cand = {r["user_key"]: r for r in rows(
        c, f"SELECT * FROM users WHERE status IN ({','.join('?' * len(want))})", want)}
    if "review" in want and has("login_reviews"):        # anyone with a non-typo login verdict
        extra = [r["user_key"] for r in rows(c, f"SELECT DISTINCT user_key FROM login_reviews WHERE verdict <> 'benign'{AND(lw)}", la)]
        for r in chunked_in(c, "SELECT * FROM users WHERE user_key IN ({IN})", [u for u in extra if u not in cand]):
            cand[r["user_key"]] = r
    if q:
        cand = {k: v for k, v in cand.items() if q in k or q in (v["name"] or "").lower()}
    keys = list(cand)
    best: dict = {}
    if has("login_reviews"):
        for r in chunked_in(c, "SELECT * FROM login_reviews WHERE user_key IN ({IN}) AND verdict <> 'benign'"
                               f"{AND(lw)} ORDER BY score DESC", keys, la):
            best.setdefault(r["user_key"], lr_obj(r))
    incs: dict = defaultdict(list)
    for r in chunked_in(c, "SELECT iu.user_key, i.id, i.type, i.severity, i.title, i.start, i.hosts FROM incident_users iu "
                           "JOIN incidents i ON i.id = iu.incident_id WHERE iu.user_key IN ({IN}) AND i.n_users <= 20"
                           f"{AND([x.replace('start', 'i.start').replace('end', 'i.end') for x in iw])}", keys, ia):
        incs[r["user_key"]].append(r)
    bad_ips: dict = defaultdict(list)
    for r in chunked_in(c, "SELECT s.user_key, s.outside_ip, COUNT(*) n, SUM(s.bytes_down) down, MIN(s.start) first, "
                           "MAX(i.country) country FROM sessions s JOIN ips i ON i.ip = s.outside_ip "
                           "WHERE i.role IN ('attacker','compromise','review') AND s.user_key IN ({IN})"
                           f"{AND([x.replace('start', 's.start').replace('end', 's.end') for x in sw])} "
                           "GROUP BY s.user_key, s.outside_ip", keys, sa):
        bad_ips[r["user_key"]].append(dict(ip=r["outside_ip"], n=r["n"], down=r["down"] or 0, first=r["first"],
                                           country=r["country"] or ""))
    camps: dict = defaultdict(list)
    if has("campaigns"):
        for r in rows(c, "SELECT id, success, n_ips, severity FROM campaigns"):
            for u in (r["success"] or "").split():
                camps[u].append(dict(id=r["id"], n_ips=r["n_ips"]))
    cases: dict = defaultdict(set)
    if has("cases"):
        for r in chunked_in(c, "SELECT ci.case_id, iu.user_key FROM case_incidents ci JOIN incident_users iu "
                               "ON iu.incident_id = ci.incident_id JOIN incidents i ON i.id = ci.incident_id "
                               "WHERE i.n_users <= 3 AND iu.user_key IN ({IN})", keys):   # not as one of many spray targets
            cases[r["user_key"]].add(r["case_id"])
    links_u: dict = defaultdict(list)
    if has("account_links"):
        lrows = {(r["u1"], r["u2"]): r for col in ("u1", "u2")
                 for r in chunked_in(c, f"SELECT * FROM account_links WHERE {col} IN ({{IN}})", keys)}
        for r in lrows.values():
            for a_, b_ in ((r["u1"], r["u2"]), (r["u2"], r["u1"])):
                if a_ in cand or a_ in keys:
                    links_u[a_].append(dict(k=b_, why=list(json.loads(r["reasons"]).values())))
    lnames = {r["user_key"]: r["name"] for r in chunked_in(c, "SELECT user_key, name FROM users WHERE user_key IN ({IN})",
                                                         {x["k"] for v in links_u.values() for x in v})}
    out = []
    st_rank = {"compromise": 0, "review": 1, "targeted": 2, "watch": 3, "normal": 4}
    for k, u in cand.items():
        il = incs.get(k, [])
        chips, seen = [], set()
        for x in sorted(il, key=lambda x: SEV_RANK[x["severity"]]):
            lbl = HUNT_CHIP.get(x["type"])
            if lbl and lbl not in seen:
                seen.add(lbl)
                chips.append(dict(t=lbl, sev=x["severity"], tip=x["title"]))
        hosts = {h for x in il for h in (x["hosts"] or "").split()}
        if not il and k not in best and not bad_ips.get(k):
            continue
        out.append(dict(k=k, n=u["name"], status=u["status"], risk=u["risk"], sessions=u["sessions"],
                        fails=u["failed_logins"], last=u["last_seen"], countries=(u["countries"] or "").split(),
                        login=best.get(k), chips=chips[:10], bad_ips=sorted(bad_ips.get(k, []), key=lambda x: x["first"])[:6],
                        campaigns=camps.get(k, []), cases=sorted(cases.get(k, ())), hosts=len(hosts),
                        linked=[dict(x, n=lnames.get(x["k"], x["k"])) for x in links_u.get(k, [])][:8],
                        worst=min([SEV_RANK[x["severity"]] for x in il] or [4])))
    key = P(qs, "sort") or "score"
    if key == "recent":
        out.sort(key=lambda x: x["last"] or "", reverse=True)
    elif key == "risk":
        out.sort(key=lambda x: (-(x["risk"] or 0), x["n"]))
    else:
        out.sort(key=lambda x: (st_rank.get(x["status"], 5), -((x["login"] or {}).get("score") or 0), x["worst"],
                                -(x["risk"] or 0)))
    counts = Counter(x["status"] for x in out)
    return dict(rows=out[:I(qs, "limit", 300, 1, 2000)], total=len(out), counts=counts,
                campaigns=val(c, "SELECT COUNT(*) FROM campaigns") if has("campaigns") else 0)


def ip_account_graph(c, ips, accounts=None, limit_accounts=30):
    """Nodes/links for flowGraph: source IPs and the accounts they failed against or used."""
    if not ips:
        return dict(nodes=[], links=[])
    fails = chunked_in(c, "SELECT outside_ip ip, lower(user) u, COUNT(*) n FROM events WHERE kind='INVALID_PW' AND "
                          "outside_ip IN ({IN}) AND user <> '' GROUP BY ip, u", ips)
    sess = chunked_in(c, "SELECT outside_ip ip, user_key u, COUNT(*) n, SUM(bytes_up) up, SUM(bytes_down) down FROM sessions "
                         "WHERE outside_ip IN ({IN}) GROUP BY ip, u", ips)
    score: Counter = Counter()
    for r in fails:
        score[r["u"]] += r["n"]
    for r in sess:
        score[r["u"]] += 1000 * r["n"]
    keep = set(accounts or []) | {u for u, _ in score.most_common(limit_accounts)}
    uinfo = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status, risk FROM users WHERE user_key IN ({IN})", keep)}
    iinfo = {r["ip"]: r for r in chunked_in(c, "SELECT ip, country, role FROM ips WHERE ip IN ({IN})", ips)}
    nodes, idx = [], {}
    for ip in ips:
        idx[("i", ip)] = len(nodes)
        nodes.append(dict(type="i", ip=ip, country=iinfo.get(ip, {}).get("country") or "", role=iinfo.get(ip, {}).get("role") or ""))
    for u in keep:
        idx[("u", u)] = len(nodes)
        nodes.append(dict(type="u", key=u, n=uinfo.get(u, {}).get("name", u), status=uinfo.get(u, {}).get("status", ""),
                          risk=uinfo.get(u, {}).get("risk", 0)))
    lk: dict = {}
    for r in sess:
        if ("u", r["u"]) in idx:
            lk[(r["ip"], r["u"])] = dict(a=idx[("u", r["u"])], b=idx[("i", r["ip"])], kind="login", sess=r["n"], fails=0,
                                         up=r["up"] or 0, down=r["down"] or 0)
    for r in fails:
        if ("u", r["u"]) in idx:
            lk.setdefault((r["ip"], r["u"]), dict(a=idx[("u", r["u"])], b=idx[("i", r["ip"])], kind="login", sess=0,
                                                   fails=0, up=0, down=0))["fails"] = r["n"]
    return dict(nodes=nodes, links=list(lk.values()), more=max(0, len(score) - len(keep)))


LINK_TXT = {"targets": "Shared target accounts", "subnet": "Same network", "cofail": "Same account within 30 min",
            "handoff": "Failed here, logged in there", "rotation": "Same account from both within 48 h"}


def api_campaigns(c, qs):
    if not has("campaigns"):
        return dict(total=0, rows=[], missing=True)
    w, a = Rng(qs).clause("first", "last", hours=False)
    q = P(qs, "q")
    if q:
        w.append("(ips LIKE ? OR success LIKE ? OR targets LIKE ? OR countries LIKE ?)")
        a += [f"%{q}%"] * 4
    if P(qs, "id"):
        w.append("id=?")
        a.append(I(qs, "id", 0, 0, 10**9))
    lim = I(qs, "limit", 20, 1, 200)
    out = []
    for r in rows(c, f"SELECT * FROM campaigns{W(w)} ORDER BY sev_rank, n_success DESC, n_ips DESC LIMIT ?", a + [lim]):
        ips = r["ips"].split()
        succ = (r["success"] or "").split()
        iinfo = {x["ip"]: x for x in chunked_in(c, "SELECT ip, country, role, failed_logins, sessions FROM ips WHERE ip IN ({IN})", ips)}
        uinfo = {x["user_key"]: x for x in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})", succ)}
        rel = [dict(a=x["ip_a"], b=x["ip_b"], w=x["weight"], kinds=json.loads(x["kinds"] or "{}"))
               for x in rows(c, "SELECT * FROM ip_links WHERE campaign_id=? ORDER BY weight DESC LIMIT 200", (r["id"],))]
        out.append(dict(id=r["id"], sev=r["severity"], title=r["title"], first=r["first"], last=r["last"], fails=r["fails"],
                        n_targets=r["n_targets"], countries=[x for x in (r["countries"] or "").split(" | ") if x],
                        kinds={LINK_TXT.get(k, k): v for k, v in json.loads(r["kinds"] or "{}").items()},
                        ips=[dict(ip=ip, country=iinfo.get(ip, {}).get("country") or "", role=iinfo.get(ip, {}).get("role") or "",
                                  fails=iinfo.get(ip, {}).get("failed_logins", 0), sess=iinfo.get(ip, {}).get("sessions", 0))
                             for ip in ips],
                        success=[dict(k=u, n=uinfo.get(u, {}).get("name", u), status=uinfo.get(u, {}).get("status", "")) for u in succ],
                        relations=[dict(x, why=[f"{LINK_TXT.get(k, k)}: {v}" for k, v in x["kinds"].items()]) for x in rel],
                        graph=ip_account_graph(c, ips, succ), incident=r["incident_id"]))
    return dict(total=val(c, f"SELECT COUNT(*) FROM campaigns{W(w)}", a), rows=out)


def related_ips(c, ip):
    if not has("ip_links"):
        return [], None
    rel = rows(c, "SELECT * FROM ip_links WHERE ip_a=? OR ip_b=? ORDER BY weight DESC LIMIT 60", (ip, ip))
    others = [x["ip_b"] if x["ip_a"] == ip else x["ip_a"] for x in rel]
    info = {x["ip"]: x for x in chunked_in(c, "SELECT ip, country, role FROM ips WHERE ip IN ({IN})", others)}
    camp = val(c, "SELECT campaign_id FROM campaign_ips WHERE ip=?", (ip,))
    return [dict(ip=o, country=info.get(o, {}).get("country") or "", role=info.get(o, {}).get("role") or "", w=x["weight"],
                 why=[f"{LINK_TXT.get(k, k)}: {v}" for k, v in json.loads(x["kinds"] or "{}").items()],
                 campaign=x["campaign_id"]) for o, x in zip(others, rel)], camp


def api_venn(c, qs):
    """Sets for Venn / UpSet drawings.
    mode=ip:   one set per IP = the accounts it failed against or logged in as.
    mode=user: one set per account = the IPs it failed from or logged in from."""
    rng = Rng(qs)
    fw, fa = rng.clause("ts")
    sw, sa = rng.clause("start", "end")
    mode = "user" if P(qs, "mode") == "user" else "ip"
    keys = [k.strip() for k in re.split(r"[\s,;]+", P(qs, "items")) if k.strip()][:8]
    if mode == "user":
        keys = [k.lower() for k in keys]
    if len(keys) < 1:
        return dict(mode=mode, sets=[])
    sets = {k: {} for k in keys}

    def item(setk, itk):
        return sets[setk].setdefault(itk, dict(k=itk, fails=0, sess=0, ff=None, fl=None, sf=None, sl=None, down=0))
    if mode == "ip":
        for r in chunked_in(c, "SELECT outside_ip k, lower(user) it, COUNT(*) n, MIN(ts) a, MAX(ts) b FROM events "
                               "WHERE kind='INVALID_PW' AND user <> '' AND outside_ip IN ({IN})" + AND(fw) +
                               " GROUP BY k, it", keys, fa):
            x = item(r["k"], r["it"]); x.update(fails=r["n"], ff=r["a"], fl=r["b"])
        for r in chunked_in(c, "SELECT outside_ip k, user_key it, COUNT(*) n, MIN(start) a, MAX(start) b, "
                               "SUM(bytes_down) d FROM sessions WHERE outside_ip IN ({IN})" + AND(sw) +
                               " GROUP BY k, it", keys, sa):
            x = item(r["k"], r["it"]); x.update(sess=r["n"], sf=r["a"], sl=r["b"], down=r["d"] or 0)
        info = {r["ip"]: r for r in chunked_in(c, "SELECT ip, country, role FROM ips WHERE ip IN ({IN})", keys)}
        names = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})",
                                                       {i for v in sets.values() for i in v})}
        meta = lambda k: dict(label=k, sub=" ".join(x for x in (info.get(k, {}).get("country"), "") if x),
                              role=info.get(k, {}).get("role") or "")
        imeta = lambda i: dict(n=names.get(i, {}).get("name", i), status=names.get(i, {}).get("status", ""))
    else:
        for r in chunked_in(c, "SELECT lower(user) k, outside_ip it, COUNT(*) n, MIN(ts) a, MAX(ts) b FROM events "
                               "WHERE kind='INVALID_PW' AND lower(user) IN ({IN})" + AND(fw) + " GROUP BY k, it", keys, fa):
            x = item(r["k"], r["it"]); x.update(fails=r["n"], ff=r["a"], fl=r["b"])
        for r in chunked_in(c, "SELECT user_key k, outside_ip it, COUNT(*) n, MIN(start) a, MAX(start) b, "
                               "SUM(bytes_down) d FROM sessions WHERE user_key IN ({IN})" + AND(sw) +
                               " GROUP BY k, it", keys, sa):
            x = item(r["k"], r["it"]); x.update(sess=r["n"], sf=r["a"], sl=r["b"], down=r["d"] or 0)
        uinfo = {r["user_key"]: r for r in chunked_in(c, "SELECT user_key, name, status FROM users WHERE user_key IN ({IN})", keys)}
        iinfo = {r["ip"]: r for r in chunked_in(c, "SELECT ip, country, role FROM ips WHERE ip IN ({IN})",
                                                {i for v in sets.values() for i in v})}
        meta = lambda k: dict(label=uinfo.get(k, {}).get("name", k), sub="", role=uinfo.get(k, {}).get("status", ""))
        imeta = lambda i: dict(n=i, status=iinfo.get(i, {}).get("role") or "", country=iinfo.get(i, {}).get("country") or "")
    out = []
    for k in keys:
        its = [dict(v, **imeta(i)) for i, v in sets[k].items()]
        times = [t for v in its for t in (v["ff"], v["fl"], v["sf"], v["sl"]) if t]
        out.append(dict(k=k, **meta(k), items=sorted(its, key=lambda v: (-v["sess"], -v["fails"], v["k"])),
                        first=min(times) if times else None, last=max(times) if times else None))
    return dict(mode=mode, sets=out)


# ---------------------------------------------------------------- investigate: connections between chosen accounts / IPs

def resolve_items(c, raw):
    """'j.kral', '185.220.101.47', 'u:j.kral', 'i:1.2.3.4', 'h:192.168.10.5' -> node ids."""
    out, missing = [], []
    for it in raw:
        it = it.strip()
        if not it:
            continue
        if re.match(r"^[uih]:", it):
            k, v = it[0], it[2:].strip()
        else:
            try:
                ipaddress.ip_address(it)
                k, v = "i", it
            except ValueError:
                k, v = "u", it
        if k == "u":
            r = one(c, "SELECT user_key FROM users WHERE user_key=? OR lower(name)=?", (v.lower(), v.lower()))
            (out.append("u:" + r["user_key"]) if r else missing.append(it))
        elif k == "i":
            if one(c, "SELECT 1 FROM ips WHERE ip=?", (v,)):
                out.append("i:" + v)
            elif has("hosts") and one(c, "SELECT 1 FROM hosts WHERE ip=?", (v,)):
                out.append("h:" + v)
            else:
                missing.append(it)
        else:
            (out.append("h:" + v) if has("hosts") and one(c, "SELECT 1 FROM hosts WHERE ip=?", (v,)) else missing.append(it))
    return list(dict.fromkeys(out)), missing


def api_connect(c, qs):
    rng = Rng(qs)
    seeds, missing = resolve_items(c, re.split(r"[\s,;]+", P(qs, "items")))
    seeds = seeds[:12]
    hops = I(qs, "hops", 3, 1, 4)
    use_hosts = P(qs, "hosts") == "1" and has("access")
    through = P(qs, "through") == "1"
    hub_limit = I(qs, "hub", 40, 5, 1000)
    if len(seeds) < 2:
        return dict(seeds=seeds, missing=missing, nodes=[], edges=[], paths=[], connectors=[], pairs=[],
                    error="Add at least two accounts or IPs that exist in this log.")
    L_by_u: dict = defaultdict(list)
    L_by_i: dict = defaultdict(list)
    if rng.on:
        for (u, ip), r in ranged_links(c, rng).items():
            L_by_u[u].append(r)
            L_by_i[ip].append(r)
    nb_cache: dict = {}

    def neighbors(node):
        if node in nb_cache:
            return nb_cache[node]
        kind, key = node.split(":", 1)
        out = []
        if kind in ("u", "i"):
            lr = (L_by_u.get(key, []) if kind == "u" else L_by_i.get(key, [])) if rng.on else rows(
                c, f"SELECT * FROM links WHERE {'user_key' if kind == 'u' else 'ip'}=?", (key,))
            for r in lr:
                other = "i:" + r["ip"] if kind == "u" else "u:" + r["user_key"]
                out.append((other, dict(kind="login" if r["sessions"] else "fail", sess=r["sessions"],
                                        fails=r["failed_logins"], down=r["bytes_down"] or 0)))
        if kind == "u" and has("account_links"):
            for r in rows(c, "SELECT * FROM account_links WHERE u1=? OR u2=?", (key, key)):
                out.append(("u:" + (r["u2"] if r["u1"] == key else r["u1"]),
                            dict(kind="acct", why=list(json.loads(r["reasons"]).values()))))
        if kind == "i" and has("ip_links"):
            for r in rows(c, "SELECT * FROM ip_links WHERE (ip_a=? OR ip_b=?) AND weight >= 2", (key, key)):
                out.append(("i:" + (r["ip_b"] if r["ip_a"] == key else r["ip_a"]),
                            dict(kind="iplink", w=r["weight"],
                                 why=[f"{LINK_TXT.get(k, k)}: {v}" for k, v in json.loads(r["kinds"] or "{}").items()])))
        if use_hosts:
            if kind == "u":
                w, a = rng.clause("start")
                src = rows(c, f"SELECT dst_ip k, COUNT(*) n, SUM(bytes) b, SUM(blocked) bl FROM flows WHERE user_key=?{AND(w)} "
                              "GROUP BY dst_ip", [key] + a) if rng.on else rows(
                    c, "SELECT dst_ip k, SUM(conns) n, SUM(bytes) b, SUM(blocked) bl FROM access WHERE user_key=? GROUP BY dst_ip", (key,))
                out += [("h:" + r["k"], dict(kind="access", conns=r["n"], bytes=r["b"] or 0, blocked=r["bl"] or 0)) for r in src]
            elif kind == "h":
                src = rows(c, "SELECT user_key k, SUM(conns) n, SUM(bytes) b, SUM(blocked) bl FROM access WHERE dst_ip=? "
                              "GROUP BY user_key", (key,))
                out += [("u:" + r["k"], dict(kind="access", conns=r["n"], bytes=r["b"] or 0, blocked=r["bl"] or 0)) for r in src]
        nb_cache[node] = out
        return out

    hubs = set()

    def bfs(seed):
        dist, parent, frontier = {seed: 0}, {seed: None}, [seed]
        for d in range(hops):
            nxt = []
            for n in frontier:
                nb = neighbors(n)
                if n != seed and n not in seeds and len(nb) > hub_limit:
                    hubs.add(n)               # office NAT / file server: connects everyone, proves nothing
                    if not through:
                        continue
                for m, e in nb:
                    if m not in dist:
                        dist[m] = d + 1
                        parent[m] = (n, e)
                        nxt.append(m)
                if len(dist) > 6000:
                    break
            frontier = nxt
        return dist, parent
    B = {s: bfs(s) for s in seeds}

    def chain(seed, node):                    # nodes and edges from seed to node
        dist, parent = B[seed]
        ns, es = [node], []
        while parent[ns[-1]] is not None:
            p, e = parent[ns[-1]]
            es.append((p, ns[-1], e))
            ns.append(p)
        return ns[::-1], es[::-1]

    # node details for scoring and display
    def info_for(nodes):
        us = [n[2:] for n in nodes if n[0] == "u"]
        ip_ = [n[2:] for n in nodes if n[0] == "i"]
        hs = [n[2:] for n in nodes if n[0] == "h"]
        I_ = {}
        for r in chunked_in(c, "SELECT user_key, name, status, risk FROM users WHERE user_key IN ({IN})", us):
            I_["u:" + r["user_key"]] = dict(label=r["name"], status=r["status"], risk=r["risk"] or 0)
        camp = {r["ip"]: r["campaign_id"] for r in chunked_in(c, "SELECT ip, campaign_id FROM campaign_ips WHERE ip IN ({IN})", ip_)} \
            if has("campaign_ips") else {}
        for r in chunked_in(c, "SELECT ip, country, role, risk FROM ips WHERE ip IN ({IN})", ip_):
            I_["i:" + r["ip"]] = dict(label=r["ip"], country=r["country"] or "", status=r["role"] or "", risk=r["risk"] or 0,
                                      campaign=camp.get(r["ip"]))
        if hs and has("hosts"):
            for r in chunked_in(c, "SELECT ip, role, users FROM hosts WHERE ip IN ({IN})", hs):
                I_["h:" + r["ip"]] = dict(label=r["ip"], status=r["role"] or "", users=r["users"])
        return I_
    reached = set().union(*(set(B[s][0]) for s in seeds))
    INFO = info_for(reached)
    BAD = {"compromise": 3, "attacker": 3, "review": 2, "targeted": 1, "target": 1}

    def node_sus(n):
        return BAD.get(INFO.get(n, {}).get("status", ""), 0)

    def edge_sus(e):
        return {"fail": 1, "iplink": 2, "acct": 2}.get(e["kind"], 0)
    paths, pairs = [], []
    for i_, s in enumerate(seeds):
        for t in seeds[i_ + 1:]:
            ds, dt_ = B[s][0], B[t][0]
            meet = [m for m in ds if m in dt_ and ds[m] + dt_[m] <= hops]
            cand = []
            for m in meet:
                n1, e1 = chain(s, m)
                n2, e2 = chain(t, m)
                ns = n1 + n2[::-1][1:]
                if len(set(ns)) != len(ns):
                    continue
                es = e1 + [(b, a, e) for a, b, e in e2[::-1]]
                if any(n in hubs and n not in seeds for n in ns[1:-1]) and not through:
                    continue
                sus = sum(node_sus(n) for n in ns[1:-1]) + sum(edge_sus(e) for _, _, e in es)
                cand.append((len(es), -sus, ns, es))
            cand.sort(key=lambda x: (x[0], x[1]))
            seen_p, best = set(), []
            for ln, ms, ns, es in cand:
                key_ = tuple(ns)
                if key_ in seen_p:
                    continue
                seen_p.add(key_)
                best.append(dict(a=s, b=t, nodes=ns, edges=[dict(a=a, b=b, **e) for a, b, e in es], len=ln, sus=-ms))
                if len(best) >= 4:
                    break
            pairs.append(dict(a=s, b=t, dist=best[0]["len"] if best else None, n=len(best)))
            paths += best
    # connectors: entities reached from several seeds
    con = []
    for n in reached - set(seeds):
        ss = [s for s in seeds if n in B[s][0]]
        if len(ss) >= 2 and not (n in hubs and not through):
            con.append(dict(n=n, seeds=ss, dist=sum(B[s][0][n] for s in ss), sus=node_sus(n)))
    con.sort(key=lambda x: (-len(x["seeds"]), -x["sus"], x["dist"]))
    con = con[:25]
    # graph: paths + connectors with their chains to each seed
    nodes_g, edges_g = set(seeds), {}
    for p in paths:
        nodes_g.update(p["nodes"])
        for e in p["edges"]:
            edges_g[tuple(sorted((e["a"], e["b"]))) + (e["kind"],)] = e
    for x in con[:12]:
        for s in x["seeds"]:
            ns, es = chain(s, x["n"])
            nodes_g.update(ns)
            for a, b, e in es:
                edges_g[tuple(sorted((a, b))) + (e["kind"],)] = dict(a=a, b=b, **e)
    INFO.update(info_for([n for n in nodes_g if n not in INFO]))
    # dates for login / failure edges
    pairs_ui = [(e["a"], e["b"]) if e["a"][0] == "u" else (e["b"], e["a"]) for e in edges_g.values() if e["kind"] in ("login", "fail")]
    us = list({u[2:] for u, _ in pairs_ui})
    ips_ = list({i[2:] for _, i in pairs_ui})
    when: dict = {}
    if us and ips_:
        for r in chunked_in(c, "SELECT user_key u, outside_ip ip, MIN(start) a, MAX(start) b FROM sessions WHERE user_key IN ({IN})"
                               " GROUP BY u, ip", us):
            if r["ip"] in ips_:
                when.setdefault(("u:" + r["u"], "i:" + r["ip"]), {})["sess"] = (r["a"], r["b"])
        for r in chunked_in(c, "SELECT lower(user) u, outside_ip ip, MIN(ts) a, MAX(ts) b FROM events WHERE kind='INVALID_PW' "
                               "AND lower(user) IN ({IN}) GROUP BY u, ip", us):
            if r["ip"] in ips_:
                when.setdefault(("u:" + r["u"], "i:" + r["ip"]), {})["fail"] = (r["a"], r["b"])
    for e in list(edges_g.values()) + [e for p in paths for e in p["edges"]]:
        if e["kind"] in ("login", "fail"):
            k = (e["a"], e["b"]) if e["a"][0] == "u" else (e["b"], e["a"])
            e["when"] = when.get(k, {})
    nodes_out = [dict(id=n, type=n[0], key=n[2:], seed=n in seeds, hub=n in hubs, **INFO.get(n, dict(label=n[2:])))
                 for n in nodes_g]
    return dict(seeds=seeds, missing=missing, hops=hops, nodes=nodes_out, edges=list(edges_g.values()), paths=paths,
                pairs=pairs, connectors=[dict(x, **INFO.get(x["n"], {})) for x in con], hubs=sorted(hubs)[:30],
                info={s: INFO.get(s, {}) for s in seeds})


class InvStore(ReviewStore):
    """Saved investigations (name, items, options) in a JSON file next to the DB."""

    def __init__(self, path):
        super().__init__(path)

    def all(self):
        with self.lock:
            return [dict(v, id=k) for k, v in sorted(self.data.items(), key=lambda kv: kv[1].get("updated", ""), reverse=True)]

    def save(self, body):
        with self.lock:
            iid = str(body.get("id") or "") or secrets.token_hex(4)
            if not re.match(r"^[A-Za-z0-9]{1,40}$", iid):
                raise ValueError("bad id")
            self.data[iid] = dict(name=str(body.get("name") or "Investigation")[:120],
                                  items=[str(x)[:120] for x in (body.get("items") or [])][:50],
                                  hops=int(body.get("hops") or 3), hosts=bool(body.get("hosts")),
                                  notes=str(body.get("notes") or "")[:20000],
                                  updated=dt.datetime.now().isoformat(sep=" ", timespec="seconds"))
            self._write()
            return dict(self.data[iid], id=iid)

    def delete(self, iid):
        with self.lock:
            self.data.pop(str(iid), None)
            self._write()

    def _write(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)


INV: "InvStore" = None  # type: ignore


def api_investigations(c, qs):
    return dict(rows=INV.all())


API = {"/api/connect": api_connect, "/api/investigations": api_investigations, "/api/venn": api_venn, "/api/search": api_search, "/api/hunt": api_hunt, "/api/campaigns": api_campaigns,
       "/api/matrix": api_matrix, "/api/heatmap": api_heatmap, "/api/inctrend": api_inctrend,
       "/api/logins": api_logins, "/api/countries": api_countries, "/api/case": api_case, "/api/meta": api_meta, "/api/hosts": api_hosts, "/api/host": api_host, "/api/cases": api_cases,
       "/api/timeline": api_timeline, "/api/summary": api_summary, "/api/daily": api_daily, "/api/users": api_users, "/api/ips": api_ips,
       "/api/incidents": api_incidents, "/api/sessions": api_sessions, "/api/user": api_user, "/api/ip": api_ip,
       "/api/events": api_events, "/api/graph": api_graph}


# ---------------------------------------------------------------- HTTP

POOL: Pool = None  # type: ignore
PAGE = b""
ALLOWED_HOSTS: set = set()


class Handler(BaseHTTPRequestHandler):
    server_version = "ASA-Dashboard/1.0"
    verbose = False

    def log_message(self, fmt, *a):
        if self.verbose:
            super().log_message(fmt, *a)

    def _headers(self, code, ctype, length=None, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if length is not None:
            self.send_header("Content-Length", str(length))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, obj, code=200):
        b = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        self._headers(code, "application/json; charset=utf-8", len(b))
        self.wfile.write(b)

    def do_GET(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if "*" not in ALLOWED_HOSTS and host not in ALLOWED_HOSTS:  # blocks DNS-rebinding style access from other sites
            return self._json({"error": "host not allowed"}, 403)
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                self._headers(200, "text/html; charset=utf-8", len(PAGE), {
                    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
                    "img-src 'self' data:; connect-src 'self'"})
                self.wfile.write(PAGE)
            elif u.path in ("/api/export/sessions.csv", "/api/export/events.csv"):
                self._export(u.path, qs)
            elif u.path == "/api/export/case.csv":
                self._export_case(qs)
            elif u.path.startswith("/cases/"):
                self._case_file(u.path[len("/cases/"):])
            elif u.path in API:
                with POOL.cur() as c:
                    data = API[u.path](c, qs)
                self._json(data)
            else:
                self._json({"error": "not found"}, 404)
        except NotFound as e:
            self._json({"error": str(e)}, 404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            traceback.print_exc()
            try:
                self._json({"error": f"{type(e).__name__}: {e}"}, 500)
            except Exception:
                pass

    def _case_file(self, name):
        if not CASE_DIR or not re.match(r"^[A-Za-z0-9_.\-]+\.(html|csv)$", name) or ".." in name:
            return self._json({"error": "not found"}, 404)
        path = os.path.join(CASE_DIR, name)
        if not os.path.isfile(path):
            return self._json({"error": "not found"}, 404)
        with open(path, "rb") as f:
            b = f.read()
        ctype = "text/html; charset=utf-8" if name.endswith(".html") else "text/csv; charset=utf-8"
        extra = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}
        if name.endswith(".csv"):
            extra["Content-Disposition"] = f'attachment; filename="{name}"'
        self._headers(200, ctype, len(b), extra)
        self.wfile.write(b)

    def _export_case(self, qs):
        cid = I(qs, "id", 0, 0, 10**9)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["case", "step_time", "finding", "severity", "seq", "time", "source", "kind", "text", "raw_message"])
        with POOL.cur() as c:
            if not has("case_evidence"):
                raise NotFound("No case evidence in this database")
            for r in c.execute("SELECT e.case_id, i.start, i.title, i.severity, e.seq, e.ts, e.source, e.kind, e.text, "
                               "e.raw FROM case_evidence e JOIN incidents i ON i.id = e.incident_id WHERE e.case_id=? "
                               "ORDER BY i.start, e.ts, e.seq", (cid,)):
                w.writerow(list(r))
        b = buf.getvalue().encode("utf-8-sig")
        self._headers(200, "text/csv; charset=utf-8", len(b),
                      {"Content-Disposition": f'attachment; filename="case_{cid:03d}_evidence.csv"'})
        self.wfile.write(b)

    def do_POST(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if "*" not in ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
            return self._json({"error": "host not allowed"}, 403)
        # only the dashboard page knows the per-run token; other websites cannot send it (no CORS)
        if not TOKEN or not hmac.compare_digest(self.headers.get("X-ASA-Token") or "", TOKEN):
            return self._json({"error": "missing or wrong token - reload the page"}, 403)
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in ALLOWED_HOSTS and "*" not in ALLOWED_HOSTS:
            return self._json({"error": "origin not allowed"}, 403)
        path = urlparse(self.path).path
        if path not in ("/api/review", "/api/investigations"):
            return self._json({"error": "not found"}, 404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > 200_000:
                return self._json({"error": "bad request size"}, 400)
            body = json.loads(self.rfile.read(n).decode("utf-8"))
            if path == "/api/investigations":
                if body.get("action") == "delete":
                    INV.delete(body.get("id"))
                    return self._json(dict(rows=INV.all()))
                saved = INV.save(body)
                return self._json(dict(saved=saved, rows=INV.all()))
            key = str(body.get("key") or "")
            if not re.match(r"^[A-Za-z0-9]{1,40}$", key):
                return self._json({"error": "bad case key"}, 400)
            self._json(REVIEW.update(key, body))
        except (ValueError, UnicodeDecodeError):
            self._json({"error": "bad JSON"}, 400)
        except Exception as e:
            traceback.print_exc()
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def _export(self, path, qs):
        if path.endswith("sessions.csv"):
            where, a, order = sessions_filter(qs)
            sql, args = f"{SESS_SELECT}{where} ORDER BY {order}", a
            header = ["user", "outside_ip", "country", "inside_ip", "vpn_group", "start", "end", "duration_s",
                      "bytes_up", "bytes_down", "end_estimated", "reason", "seq"]
            conv = lambda r: [r["user"], r["outside_ip"], r["country"], r["inside_ip"], r["vpn_group"], r["start"],
                              r["end"], r["duration_s"], r["bytes_up"], r["bytes_down"], r["end_estimated"],
                              r["reason"], r["seq"]]
            name = "sessions_export.csv"
        else:
            sql, args = events_filter(qs, POOL.event_cols)
            header = None
            conv = None
            name = "events_export.csv"
        self._headers(200, "text/csv; charset=utf-8", None,
                      {"Content-Disposition": f'attachment; filename="{name}"', "Connection": "close"})
        buf = io.StringIO()
        w = csv.writer(buf)
        with POOL.cur() as c:
            cur = c.execute(sql, args)
            if header is None:
                header = [d[0] for d in cur.description]
                conv = lambda r: list(r)
            w.writerow(header)
            n = 0
            for r in cur:
                w.writerow(conv(r))
                n += 1
                if n % 2000 == 0:
                    self.wfile.write(buf.getvalue().encode("utf-8"))
                    buf.seek(0)
                    buf.truncate()
            self.wfile.write(buf.getvalue().encode("utf-8"))


# ---------------------------------------------------------------- startup

def run_step(script, argv):
    cmd = [sys.executable, os.path.join(HERE, script)] + argv
    print(f"\n$ {' '.join(shlex.quote(x) for x in cmd)}", flush=True)
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit(f"[error] {script} failed with exit code {r.returncode}")


def ensure_indexes(db):
    """Older databases lack inside-IP indexes; add them once (the server itself only reads)."""
    want = {"idx_s_inside": "CREATE INDEX IF NOT EXISTS idx_s_inside ON sessions(inside_ip, start)",
            "idx_ev_inside": "CREATE INDEX IF NOT EXISTS idx_ev_inside ON events(inside_ip, ts)",
            "idx_links_u": "CREATE INDEX IF NOT EXISTS idx_links_u ON links(user_key)",
            "idx_links_ip": "CREATE INDEX IF NOT EXISTS idx_links_ip ON links(ip)",
            "idx_al_u1": "CREATE INDEX IF NOT EXISTS idx_al_u1 ON account_links(u1)",
            "idx_al_u2": "CREATE INDEX IF NOT EXISTS idx_al_u2 ON account_links(u2)"}
    try:
        c = sqlite3.connect(db)
        have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        missing = [sql for name, sql in want.items() if name not in have]
        if missing:
            print("Adding lookup indexes (one time only)...", flush=True)
            for sql in missing:
                try:
                    c.execute(sql)
                except sqlite3.OperationalError:
                    pass        # table not present in an older database
            c.commit()
        c.close()
    except sqlite3.Error as e:
        print(f"[warn] could not add inside-IP indexes ({e}); inside-IP filters will be slower", file=sys.stderr)


def has_analysis(db) -> bool:
    c = sqlite3.connect(db)
    try:
        t = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not ANALYSIS_TABLES <= t:
            return False
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)")}
        return "user_key" in cols
    finally:
        c.close()


def main() -> int:
    global POOL, PAGE, ALLOWED_HOSTS, REVIEW, TOKEN, CASE_DIR, INV
    ap = argparse.ArgumentParser(description="Local web dashboard for ASA VPN incident analysis")
    ap.add_argument("db", nargs="?", default="", help="events.db (default OUTDIR/events.db)")
    ap.add_argument("--import", dest="csv", default="", help="Import this CSV first (runs asa_parse + asa_analyze)")
    ap.add_argument("--outdir", default="out", help="Output folder used with --import")
    ap.add_argument("--geoip", "--geoip-mmdb", dest="geoip_mmdb", default="",
                    help="Country database (GeoLite2-Country.mmdb or free DB-IP country CSV), used for import and analysis")
    ap.add_argument("--home-countries", default="", help="Countries where logins are expected, e.g. CZ,SK")
    ap.add_argument("--newest-year", default="", help="Passed to the parser")
    ap.add_argument("--parse-args", default="", help='Extra parser options, e.g. "--order file-reversed"')
    ap.add_argument("--analyze-args", default="", help='Extra analyzer options, e.g. "--bf-min 5"')
    ap.add_argument("--reanalyze", action="store_true", help="Re-run the analysis before starting")
    ap.add_argument("--host", default="127.0.0.1", help="Address to listen on (keep 127.0.0.1 for privacy)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    ap.add_argument("--no-web-fonts", action="store_true", help="Do not load fonts from Google")
    ap.add_argument("--verbose", action="store_true", help="Log every request")
    args = ap.parse_args()

    db = args.db or os.path.join(args.outdir, "events.db")
    if args.csv:
        pa = [args.csv, "--outdir", args.outdir, "--db", db]
        if args.geoip_mmdb:
            pa += ["--geoip-mmdb", args.geoip_mmdb]
        if args.newest_year:
            pa += ["--newest-year", args.newest_year]
        run_step("asa_parse.py", pa + shlex.split(args.parse_args))
    if not os.path.exists(db):
        sys.exit(f"[error] {db} not found. Import a CSV with --import export.csv")
    if args.csv or args.reanalyze or not has_analysis(db):
        extra = (["--geoip", args.geoip_mmdb] if args.geoip_mmdb else []) + \
                (["--home-countries", args.home_countries] if args.home_countries else [])
        run_step("asa_analyze.py", [db, "--outdir", os.path.dirname(db) or ".", "--no-html"] + extra
                 + shlex.split(args.analyze_args))

    ensure_indexes(db)
    POOL = Pool(db)
    fonts = "" if args.no_web_fonts else FONTS_LINK
    TOKEN = secrets.token_urlsafe(24)
    REVIEW = ReviewStore(os.path.join(os.path.dirname(os.path.abspath(db)), "case_review.json"))
    INV = InvStore(os.path.join(os.path.dirname(os.path.abspath(db)), "investigations.json"))
    with POOL.cur() as c:
        cd = val(c, "SELECT value FROM meta WHERE key='case_dir'") if "meta" in POOL.tables else ""
    cand = cd or os.path.join(os.path.dirname(os.path.abspath(db)), "cases")
    CASE_DIR = cand if os.path.isdir(cand) else ""
    PAGE = (PAGE_HTML.replace("<!--FONTS-->", fonts)
            .replace('<meta charset="utf-8">', f'<meta charset="utf-8">\n<meta name="asa-token" content="{TOKEN}">', 1)
            .encode("utf-8"))
    ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", args.host.lower()}
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("[warn] listening on a non-local address: anyone who can reach this port can read the logs.",
              file=sys.stderr)
        ALLOWED_HOSTS.add("*")

    Handler.verbose = args.verbose
    try:
        srv = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as e:
        sys.exit(f"[error] cannot listen on {args.host}:{args.port}: {e}. Try --port {args.port + 1}")
    srv.daemon_threads = True
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '') else args.host}:{args.port}/"
    print(f"\nDashboard running at {url}  (database: {db})\nPress Ctrl+C to stop.", flush=True)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


FONTS_LINK = ('<link rel="preconnect" href="https://fonts.googleapis.com">'
              '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
              '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500'
              '&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">')

PAGE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>VPN incident review</title>
<!--FONTS-->
<script>try{var t=localStorage.getItem('asa-theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>
<style>
:root{
  --bg:#F2F4F5;--surface:#FFFFFF;--ink:#1B2530;--muted:#5C6B79;--rule:#D6DDE2;--rule2:#B7C2CB;--hover:#E9EEF2;
  --up:#7A3E9D;--down:#1D857B;--crit:#C21E4B;--high:#C4580F;--med:#8F6F00;--low:#3F72A6;--sess:#6F8292;--focus:#2563C9;
  box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#151B22;--surface:#1C242D;--ink:#E4E9ED;--muted:#97A6B3;--rule:#2D3843;--rule2:#465563;--hover:#242E39;
  --up:#B584DB;--down:#4CC0B2;--crit:#FF5F86;--high:#FF9A52;--med:#E2C14F;--low:#7DB0E3;--sess:#8B9DAD;--focus:#7FAEFF;}}
:root[data-theme="dark"]{
  --bg:#151B22;--surface:#1C242D;--ink:#E4E9ED;--muted:#97A6B3;--rule:#2D3843;--rule2:#465563;--hover:#242E39;
  --up:#B584DB;--down:#4CC0B2;--crit:#FF5F86;--high:#FF9A52;--med:#E2C14F;--low:#7DB0E3;--sess:#8B9DAD;--focus:#7FAEFF;}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "IBM Plex Sans","Segoe UI",system-ui,-apple-system,sans-serif;font-variant-numeric:tabular-nums}
button{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.ip{font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;font-size:.92em}
.wrap{max-width:1240px;margin:0 auto;padding:0 20px}
.top{padding:26px 0 14px}
h1{font-size:1.7rem;line-height:1.2;font-weight:600;margin:0;letter-spacing:-.01em}
.period{color:var(--muted);margin:6px 0 0;max-width:75ch}
h2{font-size:1.05rem;font-weight:600;margin:0 0 10px}
h3{font-size:1rem;font-weight:600;margin:0}
.count{color:var(--muted);font-weight:400}
#attention{display:grid;grid-template-columns:1.2fr 1fr;gap:36px;padding:18px 0 22px;border-top:2px solid var(--ink)}
.alist{display:flex;flex-direction:column}
.aitem{appearance:none;background:none;border:0;border-bottom:1px solid var(--rule);display:grid;grid-template-columns:auto 1fr;gap:2px 10px;text-align:left;padding:8px 2px;cursor:pointer;align-items:baseline}
.aitem:hover{background:var(--hover)}
.aitem .why{grid-column:2;color:var(--muted);font-size:.86rem}
.aitem .dot{align-self:center}
.none{color:var(--muted);margin:0}
.more{appearance:none;background:none;border:0;color:var(--focus);cursor:pointer;padding:8px 2px;text-align:left}
.kpis{display:flex;flex-wrap:wrap;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);margin-bottom:0}
.kpi{padding:12px 28px 12px 0}
.kpi b{display:block;font-size:1.3rem;font-weight:600;line-height:1.25}
.kpi span{color:var(--muted);font-size:.84rem}
.kpi.up b{color:var(--up)} .kpi.down b{color:var(--down)} .kpi.crit b{color:var(--crit)}
nav.tabs{position:sticky;top:env(safe-area-inset-top,0px);z-index:6;background:var(--bg);display:flex;gap:2px;overflow-x:auto;border-bottom:1px solid var(--rule);margin:0 -20px;padding:0 20px}
nav.tabs button{appearance:none;background:none;border:0;border-bottom:2px solid transparent;padding:12px 14px 10px;color:var(--muted);cursor:pointer;white-space:nowrap}
nav.tabs button[aria-selected="true"]{color:var(--ink);border-bottom-color:var(--ink);font-weight:600}
main{padding:22px 0 60px}
.sec{margin:0 0 34px}
.sec-h{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.sec-h h2{margin:0}
.note{color:var(--muted);font-size:.86rem;margin:4px 0 0;max-width:80ch}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:.84rem;color:var(--muted)}
.sw{display:inline-block;width:10px;height:10px;margin-right:6px;vertical-align:-1px}
.chart{width:100%;overflow:hidden}
.chart svg{display:block}
svg text{font-family:inherit}
.ax{fill:var(--muted);font-size:11px}
.axl{stroke:var(--ink);stroke-width:1}
.grid{stroke:var(--rule);stroke-width:1}
rect.up{fill:var(--up)} rect.down{fill:var(--down)} rect.fail{fill:var(--crit)} rect.sess{fill:var(--sess)} rect.flag{fill:var(--crit)}
.hl{stroke:var(--ink);stroke-width:1;stroke-dasharray:2 2}
.two{display:grid;grid-template-columns:1.6fr 1fr;gap:36px}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 12px}
input[type=search],select{font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--rule2);border-radius:4px;padding:6px 10px;min-height:36px}
input[type=search]{min-width:min(260px,100%)}
label.chk{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:.9rem}
.chip{appearance:none;border:1px solid var(--rule2);background:var(--surface);border-radius:4px;padding:5px 10px;cursor:pointer;font-size:.88rem}
.chip[aria-pressed="false"]{opacity:.45}
.chip .sq{display:inline-block;width:8px;height:8px;margin-right:6px}
/* ledger */
.ledger{display:flex;flex-direction:column}
.lh,.lrow{display:grid;grid-template-columns:minmax(8rem,13rem) 1fr 1fr 5.5rem;align-items:center}
.ledger.wide .lh,.ledger.wide .lrow{grid-template-columns:minmax(8rem,13rem) 1fr 1fr 5.5rem 4.2rem 3.4rem 4.4rem}
.lh{font-size:.8rem;color:var(--muted);padding:0 0 6px;border-bottom:1px solid var(--rule2)}
.lh .c-up{text-align:right;padding-right:10px} .lh .c-down{padding-left:10px}
.lrow{appearance:none;background:none;border:0;border-bottom:1px solid var(--rule);text-align:left;padding:6px 0;cursor:pointer;width:100%}
.lrow:hover{background:var(--hover)}
.lname{display:flex;align-items:center;gap:8px;min-width:0;padding-right:10px}
.lname span.t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lup,.ldown{display:flex;align-items:center;min-height:22px;gap:8px}
.lup{flex-direction:row-reverse;border-right:2px solid var(--ink)}
.track{flex:1;display:flex;min-width:0}
.lup .track{justify-content:flex-end}
.bar{height:14px}
.bar.up{background:var(--up)} .bar.down{background:var(--down)}
.lv{font-size:.8rem;color:var(--muted);white-space:nowrap;width:4.9rem}
.lup .lv{text-align:left} .ldown .lv{text-align:right}
.ltime,.lx{text-align:right;font-size:.9rem;padding-right:2px}
.lx.bad{color:var(--crit)}
.dot{width:9px;height:9px;border-radius:50%;flex:none;display:inline-block;background:var(--rule2)}
.st-compromise{background:var(--crit)} .st-review{background:var(--high);box-shadow:0 0 0 2px var(--surface),0 0 0 3px var(--high)} .st-targeted{background:var(--high)} .st-watch{background:var(--med)}
.badge{display:inline-block;font-size:.78rem;line-height:1.4;padding:0 7px;border-radius:3px;border:1px solid currentColor;white-space:nowrap}
.c-crit,.c-critical,.c-compromise,.c-attacker{color:var(--crit)} .c-high,.c-targeted,.c-review,.c-likely{color:var(--high)} .c-compromised{color:var(--crit)} .c-benign{color:var(--muted)} .c-medium,.c-watch,.c-shared{color:var(--med)} .c-low{color:var(--low)} .c-normal{color:var(--muted)}
/* incidents */
.inc{border-left:3px solid var(--rule2);border-bottom:1px solid var(--rule);padding:10px 0 12px 14px}
.inc.critical{border-left-color:var(--crit)} .inc.high{border-left-color:var(--high)} .inc.medium{border-left-color:var(--med)} .inc.low{border-left-color:var(--low)}
.inc-h{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.inc p{margin:4px 0 6px;max-width:80ch}
.inc-m{display:flex;gap:6px 12px;flex-wrap:wrap;align-items:center;font-size:.86rem;color:var(--muted)}
.ref{appearance:none;background:none;border:0;padding:0;color:var(--focus);cursor:pointer;text-decoration:underline;text-decoration-color:var(--rule2);text-underline-offset:3px}
.inc details{font-size:.82rem;color:var(--muted);margin-top:4px}
.inc details summary{cursor:pointer}
/* tables */
.tw{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.88rem}
th{text-align:left;font-weight:500;color:var(--muted);border-bottom:1px solid var(--rule2);padding:6px 14px 6px 0;white-space:nowrap}
td{border-bottom:1px solid var(--rule);padding:6px 14px 6px 0;white-space:nowrap}
tr.click{cursor:pointer} tr.click:hover td{background:var(--hover)}
.num{text-align:right}
td.up{color:var(--up)} td.down{color:var(--down)}
/* graph */
.gwrap{position:relative}
#graph{width:100%;height:min(72vh,720px);display:block;border:1px solid var(--rule);background:var(--surface);touch-action:none;cursor:grab}
.gbtns{position:absolute;right:10px;top:10px;display:flex;flex-direction:column;gap:4px}
.gbtns button{width:34px;height:34px;border:1px solid var(--rule2);background:var(--surface);border-radius:4px;cursor:pointer;font-size:1.1rem}
.gl{stroke:var(--rule2);stroke-opacity:.9}
.gl.fail{stroke:var(--crit);stroke-dasharray:4 3;stroke-opacity:.7}
.gl.int{stroke:var(--up);stroke-opacity:.45;stroke-dasharray:1 3;stroke-linecap:round}
.gl.int.fail{stroke:var(--crit);stroke-opacity:.6}
.gn{cursor:pointer}
.gn circle,.gn rect{stroke:var(--surface);stroke-width:1.5}
.gn text{font-size:11px;fill:var(--ink);paint-order:stroke;stroke:var(--surface);stroke-width:3px;pointer-events:none}
.dim{opacity:.12}
.sel circle,.sel rect{stroke:var(--ink);stroke-width:2.5}
/* drawer */
.scrim{position:fixed;inset:0;background:rgba(10,15,20,.35);z-index:19}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(760px,100%);background:var(--surface);border-left:1px solid var(--rule2);z-index:20;overflow-y:auto;padding:calc(env(safe-area-inset-top,0px) + 18px) 24px calc(env(safe-area-inset-bottom,0px) + 30px);box-shadow:-18px 0 40px rgba(0,0,0,.18)}
@media (prefers-reduced-motion:no-preference){.drawer{animation:slide .18s ease-out}@keyframes slide{from{transform:translateX(24px);opacity:.4}}}
.dh{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:12px}
.dh h2{font-size:1.35rem;margin:0;word-break:break-all}
.close{appearance:none;border:1px solid var(--rule2);background:var(--surface);border-radius:4px;padding:6px 12px;cursor:pointer;flex:none}
.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:0;border-top:1px solid var(--rule);margin:10px 0 20px}
.fact{padding:9px 10px 9px 0;border-bottom:1px solid var(--rule)}
.fact b{display:block;font-weight:600}
.fact span{color:var(--muted);font-size:.8rem}
.fact.up b{color:var(--up)} .fact.down b{color:var(--down)} .fact.bad b{color:var(--crit)}
.drawer .sec{margin-bottom:26px}
#tip{position:fixed;z-index:40;pointer-events:none;background:var(--ink);color:var(--bg);font-size:.8rem;line-height:1.45;padding:7px 9px;border-radius:4px;max-width:300px;display:none}
#tip b{font-weight:600}
.empty{color:var(--muted);padding:14px 0}
@media (max-width:860px){.two{grid-template-columns:1fr}#attention{grid-template-columns:1fr;gap:18px}}
@media (max-width:640px){
  .wrap{padding:0 14px} nav.tabs{margin:0 -14px;padding:0 14px}
  h1{font-size:1.4rem}
  .kpi{padding:10px 18px 10px 0}.kpi b{font-size:1.1rem}
  .lh,.lrow,.ledger.wide .lh,.ledger.wide .lrow{grid-template-columns:1fr 1fr;grid-template-areas:"n t" "u d"}
  .lname{grid-area:n}.ltime{grid-area:t}.lup{grid-area:u}.ldown{grid-area:d}.lx,.lh .lx{display:none}
  .lh .c-name,.lh .c-time{display:none}
  .lrow{padding:8px 0}
  .lv{width:4.3rem}
  .drawer{padding-left:16px;padding-right:16px}
}
.errbar{background:var(--crit);color:#fff;padding:8px 12px;border-radius:4px;margin:0 0 12px}
.loading{color:var(--muted);padding:14px 0}
.row-actions{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}
.btn{appearance:none;border:1px solid var(--rule2);background:var(--surface);border-radius:4px;padding:6px 12px;cursor:pointer;font-size:.9rem;color:var(--ink);text-decoration:none;display:inline-flex;align-items:center;min-height:36px}
.btn:hover{background:var(--hover)}
input[type=date],input[type=number],input[type=text]{font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--rule2);border-radius:4px;padding:6px 10px;min-height:36px}
input[type=number]{width:8rem}
.fl{display:flex;flex-direction:column;gap:2px;font-size:.8rem;color:var(--muted)}
td.msg{white-space:normal;min-width:28rem;max-width:60rem;font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;font-size:.8rem;line-height:1.45}
.kind{font-size:.78rem;color:var(--muted)}
:root{color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark}}
:root[data-theme="dark"]{color-scheme:dark}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
.seg{display:inline-flex;border:1px solid var(--rule2);border-radius:4px;overflow:hidden;flex:none}
.seg button{appearance:none;border:0;border-right:1px solid var(--rule2);background:var(--surface);color:var(--muted);padding:6px 12px;cursor:pointer;font-size:.85rem;min-height:34px}
.seg button:last-child{border-right:0}
.seg button[aria-pressed="true"]{background:var(--ink);color:var(--bg)}
.timebar{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:flex-end;padding:14px 0 14px 0;border-bottom:1px solid var(--rule)}
.timebar.on{border-left:3px solid var(--focus);padding-left:12px;background:linear-gradient(90deg,var(--hover),transparent 60%)}
.timebar .note{flex-basis:100%;margin:0}
.timebar .note b{color:var(--ink);font-weight:600}
input[type=datetime-local],input[type=time]{font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--rule2);border-radius:4px;padding:6px 10px;min-height:36px}
.hours{display:flex;align-items:center;gap:6px}
.chart.zoomable .daily-ov{cursor:zoom-in}
.case{border-left:3px solid var(--rule2);border-bottom:1px solid var(--rule);padding:14px 0 16px 16px}
.case.critical{border-left-color:var(--crit)} .case.high{border-left-color:var(--high)} .case.medium{border-left-color:var(--med)}
.case h3{font-size:1.05rem;margin:4px 0 6px;line-height:1.35}
.case .chain{color:var(--muted);font-size:.9rem}
.ents{display:flex;flex-wrap:wrap;gap:4px 12px;font-size:.88rem;margin:6px 0 10px}
.ents b{font-weight:500;color:var(--muted)}
.tl{list-style:none;margin:0;padding:0;border-left:2px solid var(--rule);margin-left:4px}
.tl li{position:relative;padding:5px 0 7px 16px;font-size:.9rem}
.tl li::before{content:"";position:absolute;left:-6px;top:11px;width:10px;height:10px;border-radius:50%;background:var(--rule2);border:2px solid var(--surface)}
.tl li.c-incident.critical::before{background:var(--crit)} .tl li.c-incident.high::before{background:var(--high)}
.tl li.c-incident.medium::before{background:var(--med)} .tl li.c-incident.low::before{background:var(--low)}
.tl li.c-fail::before,.tl li.c-probe::before{background:var(--crit);border-radius:1px}
.tl li.c-login::before{background:var(--down)} .tl li.c-logout::before{background:var(--sess)}
.tl li.c-access::before{background:var(--up)} .tl li.c-admin::before{background:var(--high);border-radius:1px}
.tl .tm{color:var(--muted);font-size:.8rem;margin-right:8px;font-variant-numeric:tabular-nums}
.tl .dt{color:var(--muted);font-size:.84rem;display:block}
.tl .day{list-style:none;margin:10px 0 2px -2px;padding:0;font-weight:600;font-size:.84rem;color:var(--muted);background:var(--surface)}
.tl .day::before{display:none}
.tl li.c-incident .tt{font-weight:600}
.cmd-anti td{color:var(--crit)} .cmd-sens td.msg{color:var(--high)}
.portchip{display:inline-block;font-size:.76rem;border:1px solid var(--rule2);border-radius:3px;padding:0 5px;margin:1px 3px 1px 0;color:var(--muted)}
.portchip.adm{border-color:var(--high)}
.drawer.wide{width:min(1120px,100%)}
.lrow2{border-bottom:1px solid var(--rule);padding:10px 0}
.lhead{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center}
.lscore{display:inline-block;width:70px;height:7px;background:var(--rule);border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:4px}
.lscore i{display:block;height:100%;background:currentColor}
.reasons{list-style:none;padding:0;margin:6px 0;font-size:.9rem}.reasons li{padding:2px 0}
.reasons .pos{display:inline-block;min-width:34px;font-weight:600;color:var(--crit)}.reasons .neg{display:inline-block;min-width:34px;font-weight:600;color:var(--down)}
.trend .ax{font-size:10px;fill:var(--muted)} .trend .hit{cursor:zoom-in} .trend .hit:hover{fill:var(--ink);fill-opacity:.06}
.heat{display:grid;grid-template-columns:2.6rem repeat(24,minmax(10px,1fr));gap:2px;max-width:900px;font-size:.72rem}
.heat .hh{color:var(--muted);text-align:left} .heat .hd{color:var(--muted);align-self:center}
.heat .hc{height:18px;border-radius:2px;cursor:pointer} .heat .hc:hover{outline:2px solid var(--ink);outline-offset:-1px}
.mxw{max-height:72vh;overflow:auto}
.mxt{border-collapse:separate;border-spacing:2px;font-size:.86rem}
.mxt th{position:sticky;top:0;background:var(--surface);z-index:2;font-weight:500;color:var(--muted);vertical-align:bottom;padding:4px 6px;font-size:.8rem;line-height:1.2}
.mxt th .ref-id{display:block;font-size:.68rem;opacity:.7}
.mxt td.ent,.mxt th.ent{position:sticky;left:0;background:var(--surface);z-index:1;white-space:nowrap;padding-right:12px;text-align:left}
.mxt th.ent{z-index:3}
.mxt td.mx{min-width:44px;height:30px;text-align:center;border-radius:3px;background:var(--rule);font-weight:600;font-variant-numeric:tabular-nums}
.mxt td.mx.s-critical{background:color-mix(in srgb,var(--crit) 75%,transparent);color:#fff}
.mxt td.mx.s-high{background:color-mix(in srgb,var(--high) 55%,transparent)}
.mxt td.mx.s-medium{background:color-mix(in srgb,var(--med) 40%,transparent)}
.mxt td.mx.s-low{background:color-mix(in srgb,var(--low) 30%,transparent)}
.mxt td.mx[data-mx]{cursor:pointer} .mxt td.mx[data-mx]:hover,.mxt td.mx.sel{outline:2px solid var(--ink);outline-offset:-2px}
.mxt.acc td.mx{min-width:26px;height:24px;font-weight:500;font-size:.78rem;position:relative}
.mxt th.vert{height:118px;white-space:nowrap;padding:2px} .mxt th.vert span{writing-mode:vertical-rl;transform:rotate(180deg);display:inline-block;font-family:var(--mono,monospace);font-size:.74rem}
.mxt th.vert.c-attacker,.mxt th.vert.c-compromise{color:var(--crit)} .mxt th.vert.c-review{color:var(--high)}
.mxt .fdot{position:absolute;top:2px;right:2px;width:7px;height:7px;border-radius:50%;background:var(--crit);opacity:var(--f)}
.mk{display:inline-block;width:9px;height:9px;margin-right:6px;vertical-align:middle}
.mk.u{border-radius:50%;background:var(--sess)} .mk.i{transform:rotate(45deg) scale(.85);background:var(--rule2)} .mk.h{border:2px solid var(--up);border-radius:2px;width:7px;height:7px}
svg.flow .fhd{font-size:12px;font-weight:600;fill:var(--muted)}
svg.flow .fe{fill:none;stroke:var(--rule2);stroke-opacity:.7}
svg.flow .fe.ok{stroke:var(--sess)} svg.flow .fe.fail{stroke:var(--crit);stroke-dasharray:4 3;stroke-opacity:.75}
svg.flow .fe.int{stroke:var(--up);stroke-dasharray:1 3;stroke-linecap:round} svg.flow .fe.crit{stroke:var(--crit);stroke-opacity:.9}
svg.flow .fn{cursor:pointer} svg.flow .fn text{font-size:12px;fill:var(--ink);paint-order:stroke;stroke:var(--surface);stroke-width:3px}
svg.flow.focus .fe{stroke-opacity:.08} svg.flow.focus .fn{opacity:.25} svg.flow.focus .fe.on{stroke-opacity:1} svg.flow.focus .fn.on{opacity:1}
svg.flow .fe:hover{stroke-opacity:1}
.ttools{display:flex;justify-content:flex-end;margin:-4px 0 2px} .tbtn{font:inherit;font-size:.74rem;border:1px solid var(--rule2);background:none;color:var(--muted);border-radius:3px;padding:0 6px;cursor:pointer}
.tbtn:hover{color:var(--ink)}
th.sorth{cursor:pointer;user-select:none} th.sorth:hover{color:var(--ink)}
th.sorth[aria-sort=ascending]::after{content:" \25B2";font-size:.7em} th.sorth[aria-sort=descending]::after{content:" \25BC";font-size:.7em}
.tw.tall{max-height:70vh;overflow:auto} .tw.tall thead th{position:sticky;top:0;background:var(--surface);z-index:1}
button.kpi{background:none;border:0;font:inherit;color:inherit;text-align:left;cursor:pointer;border-radius:4px}
button.kpi:hover span{text-decoration:underline} button.kpi:focus-visible{outline:2px solid var(--ink)}
nav.tabs .hunt-tab{font-weight:600}
.gsearch{position:relative;flex:1;max-width:460px;margin:4px 16px 0 auto}
.gsearch input{width:100%;font:inherit;padding:8px 12px;border:1px solid var(--rule2);border-radius:6px;background:var(--surface);color:var(--ink)}
.gsearch input:focus{outline:2px solid var(--down);outline-offset:0}
.gs-res{position:absolute;top:100%;right:0;min-width:min(520px,92vw);z-index:30;background:var(--surface);border:1px solid var(--rule2);border-radius:6px;margin-top:4px;box-shadow:0 12px 30px rgba(0,0,0,.25);max-height:70vh;overflow:auto}
.gsr{display:grid;grid-template-columns:18px 1fr auto;grid-template-areas:"i l t" ". s s";gap:0 8px;width:100%;text-align:left;background:none;border:0;border-bottom:1px solid var(--rule);padding:7px 12px;font:inherit;color:inherit;cursor:pointer}
.gsr.on,.gsr:hover{background:var(--rule)} .gsr .mk{grid-area:i;align-self:center} .gsl{grid-area:l;font-weight:600} .gst{grid-area:t;font-size:.8rem} .gss{grid-area:s;font-size:.8rem;color:var(--muted)}
.mk.c{background:var(--high);border-radius:1px} .mk.k{background:var(--crit);border-radius:1px;transform:rotate(45deg) scale(.8)}
.hsum{display:flex;flex-wrap:wrap;gap:12px;margin:0 0 14px}
.hs{background:none;border:1px solid var(--rule2);border-radius:8px;padding:10px 16px;text-align:left;font:inherit;color:inherit;cursor:pointer;min-width:180px}
.hs b{display:block;font-size:1.6rem;line-height:1.1} .hs span{color:var(--muted);font-size:.86rem} .hs:hover{border-color:var(--ink)}
.hs.crit b{color:var(--crit)} .hs.warn b{color:var(--high)}
.hcard{display:grid;grid-template-columns:minmax(12rem,16rem) 1fr auto;gap:8px 18px;border:1px solid var(--rule);border-left:4px solid var(--rule2);border-radius:6px;padding:10px 14px;margin:0 0 8px}
.hcard.st-b-compromise{border-left-color:var(--crit)} .hcard.st-b-review{border-left-color:var(--high)}
.hc-name{display:flex;align-items:center;gap:6px;flex-wrap:wrap} .ref.big{font-size:1.05rem;font-weight:600}
.hc-score{margin-top:6px;font-size:.86rem} .hc-how{font-size:.92rem}
.hc-r{display:flex;flex-direction:column;gap:4px;align-items:flex-end}
.chips{display:flex;flex-wrap:wrap;gap:4px}
.chip{font:inherit;font-size:.76rem;border:1px solid var(--rule2);border-radius:10px;padding:1px 8px;background:none;color:var(--ink)}
.chip.s-critical{border-color:var(--crit);color:var(--crit)} .chip.s-high{border-color:var(--high);color:var(--high)} .chip.s-medium{border-color:var(--med)}
button.chip{cursor:pointer} button.chip:hover{background:var(--rule)}
@media (max-width:820px){.hcard{grid-template-columns:1fr}.hc-r{align-items:flex-start;flex-direction:row;flex-wrap:wrap}.gsearch{margin:8px 0;max-width:none}}
.venn-wrap{display:grid;grid-template-columns:minmax(280px,560px) minmax(220px,1fr);gap:12px 24px;align-items:start}
.venn-svg svg{width:100%;height:auto;display:block} .venn-svg svg.upset{width:auto;max-width:100%}
svg.venn .vn{font-size:18px;font-weight:700;fill:var(--ink);paint-order:stroke;stroke:var(--surface);stroke-width:3px}
svg.venn .vs{font-size:10.5px;fill:var(--muted)} svg.venn .vlab{font-size:12.5px;font-weight:600;font-family:var(--mono,monospace)}
svg.venn .vreg{cursor:pointer} svg.venn .vreg.on .vn{fill:var(--crit)} svg.venn .vreg.on .ubar{stroke:var(--ink);stroke-width:2}
svg.vtl{width:100%;max-width:900px;height:auto}
.vleg{display:flex;gap:8px;align-items:flex-start;margin:0 0 8px} .vleg>i{width:12px;height:12px;border-radius:50%;margin-top:4px;flex:none;opacity:.8}
.vdot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:middle}
.vtitle{font-size:.95rem;margin:14px 0 4px}
@media (max-width:820px){.venn-wrap{grid-template-columns:1fr}}
.ivchips{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px;min-height:28px;align-items:center}
.ivchip{display:inline-flex;align-items:center;gap:4px;border:1px solid var(--rule2);border-radius:14px;padding:2px 4px 2px 10px;font-size:.9rem}
.ivchip .x{border:0;background:none;color:var(--muted);font-size:1.05rem;cursor:pointer;padding:0 6px;line-height:1} .ivchip .x:hover{color:var(--crit)}
.btn.primary{background:var(--ink);color:var(--surface);border-color:var(--ink)}
.mxt.pairs td.mx{min-width:40px} .mxt.pairs th.vert{height:140px} .mxt.pairs td.d1{background:color-mix(in srgb,var(--crit) 70%,transparent);color:#fff;cursor:pointer}
.mxt.pairs td.d2{background:color-mix(in srgb,var(--high) 55%,transparent);cursor:pointer} .mxt.pairs td.d3{background:color-mix(in srgb,var(--med) 40%,transparent);cursor:pointer}
.mxt.pairs td.d4{background:color-mix(in srgb,var(--low) 30%,transparent);cursor:pointer} .mxt.pairs td.self{background:none} .mxt.pairs td.none{color:var(--muted);font-weight:400}
.pchain{display:flex;flex-wrap:wrap;align-items:center;gap:4px 0;padding:8px 0;border-bottom:1px solid var(--rule)}
.pnode{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border:1px solid var(--rule2);border-radius:6px;background:var(--surface)}
.pnode.seed{border:2px solid var(--ink)}
.pedge{display:inline-flex;flex-direction:column;align-items:center;padding:0 10px;font-size:.76rem;line-height:1.25;position:relative;min-width:90px}
.pedge::before{content:"";position:absolute;left:4px;right:4px;top:50%;border-top:2px solid var(--rule2);z-index:0}
.pedge>span{position:relative;z-index:1;background:var(--surface);padding:0 4px} .pek{font-weight:600} .pet{color:var(--muted)}
.pedge.k-fail::before{border-top:2px dashed var(--crit)} .pedge.k-fail .pek{color:var(--crit)} .pedge.k-login::before{border-color:var(--sess)}
.pedge.k-iplink::before{border-top:2px dashed var(--high)} .pedge.k-iplink .pek{color:var(--high)} .pedge.k-acct::before{border-color:var(--up)} .pedge.k-acct .pek{color:var(--up)}
.pedge.k-access::before{border-top:2px dotted var(--down)}
svg.conn .ce{stroke-width:2;stroke-opacity:.75} svg.conn .ce.k-fail{stroke:var(--crit);stroke-dasharray:5 3} svg.conn .ce.k-login{stroke:var(--sess)}
svg.conn .ce.k-login.crit{stroke:var(--crit);stroke-width:3} svg.conn .ce.k-iplink{stroke:var(--high);stroke-dasharray:6 3} svg.conn .ce.k-acct{stroke:var(--up);stroke-width:2.5}
svg.conn .ce.k-access{stroke:var(--down);stroke-dasharray:1 3;stroke-linecap:round}
svg.conn .cn{cursor:pointer} svg.conn .cn text{font-size:12px;fill:var(--ink);paint-order:stroke;stroke:var(--surface);stroke-width:3px}
svg.conn .cn.seed text{font-weight:700}
svg.conn.focus .ce{stroke-opacity:.08} svg.conn.focus .cn{opacity:.25} svg.conn.focus .ce.on{stroke-opacity:1} svg.conn.focus .cn.on{opacity:1}
.toast{position:fixed;left:50%;bottom:24px;transform:translate(-50%,20px);background:var(--ink);color:var(--surface);padding:8px 16px;border-radius:6px;opacity:0;transition:.2s;z-index:50;pointer-events:none}
.toast.on{opacity:1;transform:translate(-50%,0)}
.wmapbox{border:1px solid var(--rule);border-radius:8px;overflow:hidden;background:var(--surface)}
svg.wmap{display:block} svg.wmap .land circle{fill:var(--rule2);opacity:.9}
svg.wmap .arcs path{fill:none;stroke-opacity:.35;stroke-linecap:round} svg.wmap .arcs path.bad{stroke-opacity:.6;stroke-dasharray:6 4}
svg.wmap .wb{cursor:pointer} svg.wmap .wb:hover>circle:first-child{fill-opacity:.65}
svg.wmap .lbl text{font-size:11.5px;font-weight:600;fill:var(--ink);paint-order:stroke;stroke:var(--surface);stroke-width:3px;pointer-events:none}
.cbar{display:inline-block;height:9px;border-radius:2px;vertical-align:middle;margin-right:4px;opacity:.85}
.rv{display:inline-block;font-size:.76rem;font-weight:600;border-radius:3px;padding:1px 7px;border:1px solid var(--rule2);color:var(--muted)}
.rv.investigating{border-color:var(--med);color:var(--med)} .rv.confirmed{border-color:var(--crit);color:var(--crit)}
.rv.false_positive{border-color:var(--low);color:var(--low)} .rv.closed{background:var(--rule);color:var(--ink)}
.cr-bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:10px 0 4px}
.cr-sum{border:1px solid var(--rule2);border-radius:6px;padding:10px 14px;margin:10px 0;line-height:1.55}
.progress{height:6px;background:var(--rule);border-radius:3px;overflow:hidden;margin:6px 0 2px;max-width:420px}
.progress i{display:block;height:100%;background:var(--down)}
.acts{list-style:none;padding:0;margin:0}.acts li{padding:4px 0}.acts label{display:flex;gap:8px;align-items:flex-start;cursor:pointer}
.acts input:checked + span{color:var(--muted);text-decoration:line-through}
.step{border-left:3px solid var(--rule2);padding:4px 0 6px 14px;margin:16px 0}
.step.critical{border-left-color:var(--crit)} .step.high{border-left-color:var(--high)} .step.medium{border-left-color:var(--med)}
.step.done{opacity:.72} .step h3{font-size:1rem;margin:2px 0 4px}
.step .rvchk{float:right;font-size:.86rem;display:flex;gap:6px;align-items:center;cursor:pointer}
.ev{font-size:.8rem} .ev td.raw{font-family:var(--mono,ui-monospace,Consolas,monospace);word-break:break-all;white-space:normal}
.ev tr.blocked td{color:var(--crit)}
#cr-notes{width:100%;min-height:140px;font:inherit;padding:8px;border:1px solid var(--rule2);border-radius:4px;background:var(--surface);color:var(--ink)}
.saved{font-size:.82rem;color:var(--muted)}
@media print{body>*:not(#drawer){display:none!important}.drawer{position:static;width:auto!important;box-shadow:none;border:0;overflow:visible;padding:0}
  .no-print,.close{display:none!important}.step{break-inside:avoid-page}details{display:block}details>summary{display:none}
  body{overflow:visible!important}}
@media (max-width:640px){.topbar{flex-direction:column}.timebar label.fl{flex:1 1 45%}.timebar input{width:100%}}
</style>
</head>
<body>
<div class="wrap">
  <header class="top topbar">
    <div><h1 id="title">VPN incident review</h1>
    <p class="period" id="period">Loading…</p></div>
    <div class="gsearch"><input type="search" id="gs" placeholder="Search account, IP, host, country, case…  ( / )" aria-label="Search everything" autocomplete="off"><div id="gs-res" class="gs-res" hidden></div></div>
    <div class="seg" id="theme" role="group" aria-label="Colour theme"><button data-theme-set="auto">Auto</button><button data-theme-set="light">Light</button><button data-theme-set="dark">Dark</button></div>
  </header>
  <div id="err" class="errbar" hidden></div>
  <section id="attention" aria-label="Needs attention"></section>
  <div class="kpis" id="kpis"></div>
  <div class="timebar" id="timebar">
    <label class="fl">Time range<select id="r-preset"><option value="">Whole log</option><option value="24h">Last 24 hours of the log</option><option value="7d">Last 7 days of the log</option><option value="30d">Last 30 days of the log</option><option value="custom">Custom</option></select></label>
    <label class="fl">From<input type="datetime-local" id="r-from" step="60"></label>
    <label class="fl">To<input type="datetime-local" id="r-to" step="60"></label>
    <label class="fl">Only between (each day)<span class="hours"><input type="time" id="r-h1" aria-label="Daily start time"><span>and</span><input type="time" id="r-h2" aria-label="Daily end time"></span></label>
    <button class="btn" id="r-reset" hidden>Show whole log</button>
    <p class="note" id="r-note">Filters every tab. Tip: click a day in the chart to zoom into it hour by hour.</p>
  </div>
  <nav class="tabs" role="tablist">
    <button id="t-overview" role="tab" data-v="overview">Overview</button>
    <button id="t-hunt" role="tab" data-v="hunt" class="hunt-tab">Hunt</button>
    <button id="t-inv" role="tab" data-v="inv">Investigate</button>
    <button id="t-cases" role="tab" data-v="cases">Cases</button>
    <button id="t-incidents" role="tab" data-v="incidents">Incidents</button>
    <button id="t-logins" role="tab" data-v="logins">Logins</button>
    <button id="t-camps" role="tab" data-v="camps">IP clusters</button>
    <button id="t-matrix" role="tab" data-v="matrix">Matrix</button>
    <button id="t-users" role="tab" data-v="users">Accounts</button>
    <button id="t-ips" role="tab" data-v="ips">Source IPs</button>
    <button id="t-hosts" role="tab" data-v="hosts">Internal hosts</button>
    <button id="t-sessions" role="tab" data-v="sessions">Sessions</button>
    <button id="t-events" role="tab" data-v="events">Raw events</button>
    <button id="t-admin" role="tab" data-v="admin">Firewall admin</button>
    <button id="t-links" role="tab" data-v="links">Connections map</button>
  </nav>
  <main>
    <section id="v-overview" class="view">
      <div class="sec" hidden><div class="sec-h"><h2>IP clusters (attacking IPs working together)</h2><button class="more" data-go="camps">All IP clusters</button></div><div id="ov-camps" class="attn-list"></div></div>
      <div class="sec">
        <div class="sec-h"><h2 id="daily-h">Data moved per day</h2>
          <div class="legend"><span><i class="sw" style="background:var(--up)"></i>Uploaded by users</span><span><i class="sw" style="background:var(--down)"></i>Downloaded by users</span><span><i class="sw" style="background:var(--crit)"></i>Failed logins</span></div></div>
        <div class="chart" id="daily"><p class="loading">Loading…</p></div>
      </div>
      <div class="two">
        <div class="sec"><div class="sec-h"><h2>Who moved the most data</h2><button class="more" data-go="users">All accounts</button></div><div id="topdata"></div></div>
        <div class="sec"><div class="sec-h"><h2>Longest connected</h2></div><div id="toptime"></div></div>
      </div>
      <div class="two">
        <div class="sec"><div class="sec-h"><h2 id="inctrend-h">Incidents per day</h2>
          <div class="legend"><span><i class="sw" style="background:var(--crit)"></i>Critical</span><span><i class="sw" style="background:var(--high)"></i>High</span><span><i class="sw" style="background:var(--med)"></i>Medium</span><span><i class="sw" style="background:var(--low)"></i>Low</span></div></div>
          <div id="inctrend"><p class="loading">Loading…</p></div></div>
        <div class="sec"><div class="sec-h"><h2>When activity happens</h2>
          <select id="heat-m" aria-label="What the heatmap shows"><option value="sessions">VPN sessions</option><option value="fails">Failed logins</option><option value="down">Data downloaded</option></select></div>
          <div id="heat"><p class="loading">Loading…</p></div></div>
      </div>
      <div class="sec"><div class="sec-h"><h2>Where connections come from</h2>
          <div class="controls" style="margin:0"><select id="wm-view" aria-label="Map area"><option value="fit">Fit to data</option><option value="europe">Europe</option><option value="world">World</option></select>
          <select id="wm-metric" aria-label="Bubble size"><option value="sessions">VPN sessions</option><option value="fails">Failed logins</option><option value="users">Accounts</option><option value="down">Data downloaded</option></select>
          <label class="chk"><input type="checkbox" id="wm-arcs" checked> Lines to home</label></div></div>
        <div id="wmap" class="wmapbox"></div>
        <div class="legend" id="wm-legend" style="margin:4px 0 10px"><span><i class="sw" style="background:var(--down);border-radius:50%"></i>Home country</span><span><i class="sw" style="background:var(--high);border-radius:50%"></i>Abroad</span><span><i class="sw" style="background:var(--crit);border-radius:50%"></i>Has attacking IPs</span><span><i class="sw" style="background:var(--crit);transform:rotate(45deg) scale(.8)"></i>Attacking IPs from a home country</span><span><i class="sw" style="border:1.5px dashed var(--crit);border-radius:50%;background:transparent"></i>Failed logins (ring)</span></div>
        <div id="countries"></div></div>
    </section>

    <section id="v-hunt" class="view" hidden>
      <p class="note" style="margin:0 0 12px">Every account that was probably broken into or needs a look, worst first: how the attacker got in, the evidence, and the IP clusters involved.</p>
      <div id="hu-sum"></div>
      <div class="controls">
        <select id="hu-status" aria-label="Which accounts"><option value="compromise,review">Compromised and to review</option><option value="compromise">Compromised only</option><option value="review">To review only</option><option value="compromise,review,targeted,watch">Everything with findings</option></select>
        <input type="search" id="hu-q" placeholder="Account name" aria-label="Filter accounts">
        <select id="hu-sort" aria-label="Sort"><option value="score">Most certain first</option><option value="risk">Highest risk</option><option value="recent">Most recent</option></select>
      </div>
      <div id="hu-list"></div>
    </section>
    <section id="v-inv" class="view" hidden>
      <p class="note" style="margin:0 0 12px">Collect the accounts and IPs you suspect, then search how they are connected: failed and successful logins, linked IPs (same target list, hand-off, rotation, same network), linked accounts and, optionally, shared internal servers, up to 4 steps apart.</p>
      <div id="iv-chips" class="ivchips"></div>
      <div class="controls">
        <div class="gsearch" style="margin:0;max-width:420px"><input type="search" id="iv-in" placeholder="Add account or IP (several: separate with commas)" aria-label="Add account or IP" autocomplete="off"><div id="iv-sug" class="gs-res" hidden></div></div>
        <button class="btn" id="iv-add">Add</button>
        <label class="note" style="margin:0">Steps <select id="iv-hops" aria-label="Maximum steps"><option value="1">1 (direct only)</option><option value="2">2</option><option value="3" selected>3</option><option value="4">4</option></select></label>
        <label class="chk"><input type="checkbox" id="iv-hosts"> Through internal servers</label>
        <label class="chk"><input type="checkbox" id="iv-through"> Through busy addresses</label>
        <button class="btn primary" id="iv-run">Find connections</button><button class="btn" id="iv-clear">Clear</button>
      </div>
      <div class="controls">
        <input type="text" id="iv-name" placeholder="Name to save this investigation" aria-label="Investigation name">
        <button class="btn" id="iv-save">Save</button>
        <select id="iv-saved" aria-label="Saved investigations"><option value="">Saved investigations…</option></select>
        <button class="btn" id="iv-del">Delete</button>
      </div>
      <details><summary class="note" style="cursor:pointer">Notes for this investigation</summary><textarea id="iv-notes" rows="4" style="width:100%;font:inherit;padding:8px;border:1px solid var(--rule2);border-radius:4px;background:var(--surface);color:var(--ink)" placeholder="Saved together with the investigation"></textarea></details>
      <div id="iv-out"></div>
    </section>
    <section id="v-camps" class="view" hidden>
      <p class="note" style="margin:0 0 12px">IPs that work together: they tried the same accounts, failed against the same account within minutes, share a network, or one failed and another then logged in as that account. Blocking only one IP of a cluster is not enough.</p>
      <div class="sec" id="vn-sec"><div class="sec-h"><h2>Compare</h2></div>
        <p class="note" style="margin:0 0 8px">Venn diagram of what IPs share: enter 2 or 3 IPs (4-8 give an UpSet chart), or switch to accounts to see which IPs they share.</p>
        <div class="controls"><select id="vn-mode" aria-label="Compare"><option value="ip">IPs &rarr; accounts they touched</option><option value="user">Accounts &rarr; IPs they came from</option></select>
          <input type="search" id="vn-items" placeholder="e.g. 185.220.101.47, 5.188.206.14" aria-label="Items to compare" style="min-width:min(420px,100%)">
          <button class="btn" id="vn-go">Compare</button></div>
        <div id="vn-out"></div></div>
      <div class="controls"><input type="search" id="k-q" placeholder="IP, account or country" aria-label="Search IP clusters"></div>
      <p class="note" id="k-count"></p>
      <div id="k-list"></div>
    </section>
    <section id="v-cases" class="view" hidden>
      <p class="note" style="margin:0 0 12px">A case links incidents that share an account or IP and happened close together, so an attack reads as one story (e.g. port scan, password spray, login, internal scanning, data download).</p>
      <div class="controls"><input type="search" id="c-q" placeholder="Search account, IP, host or step" aria-label="Search cases">
        <select id="c-sev" aria-label="Severity"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select>
        <select id="c-review" aria-label="Review status"><option value="">Any review status</option><option value="new">Not started</option><option value="investigating">Investigating</option><option value="confirmed">Confirmed incident</option><option value="false_positive">False positive</option><option value="closed">Closed</option></select></div>
      <p class="note" id="c-count"></p>
      <div id="c-list"></div>
    </section>
    <section id="v-hosts" class="view" hidden>
      <p class="note" style="margin:0 0 12px">Internal servers reached through the VPN, worked out by matching each connection's source address to the VPN user who had it at that moment.</p>
      <div class="controls">
        <input type="search" id="h-q" placeholder="IP prefix, e.g. 192.168.10." aria-label="Search hosts">
        <select id="h-sort" aria-label="Sort hosts"><option value="bytes">Most data</option><option value="conns">Most connections</option><option value="users">Most accounts</option><option value="blocked">Most blocked attempts</option><option value="risk">Highest risk</option><option value="last">Most recent</option></select>
        <select id="h-role" aria-label="Filter"><option value="">All hosts</option><option value="target">Involved in high/critical incidents</option></select>
      </div>
      <p class="note" id="h-count"></p>
      <div class="tw" id="h-list"></div>
    </section>
    <section id="v-logins" class="view" hidden>
      <p class="note" style="margin:0 0 12px">Every successful VPN login that had failed attempts before it (from the same IP, or for the same account from other IPs) is scored 0-100.
        Points come from evidence such as password spraying from the IP, many wrong passwords, a new IP or country, and what the session did afterwards.
        Points are taken off when the IP is the user's normal address or a shared office address. Low scores are users mistyping their password.</p>
      <div class="controls">
        <input type="search" id="l-q" placeholder="Account, IP or country" aria-label="Search logins">
        <select id="l-verdict" aria-label="Verdict"><option value="compromised,likely,review">Compromised, likely and review</option><option value="compromised">Compromised</option><option value="likely">Likely compromised</option><option value="review">Needs review</option><option value="benign">Probably the user (typos)</option><option value="">All assessed logins</option></select>
        <select id="l-sort" aria-label="Sort"><option value="score">Highest score first</option><option value="time">Newest first</option></select>
      </div>
      <p class="note" id="l-count"></p>
      <div id="l-list"></div>
    </section>
    <section id="v-matrix" class="view" hidden>
      <div class="controls">
        <select id="m-mode" aria-label="Matrix"><option value="attack">Attack stages (MITRE ATT&amp;CK)</option><option value="access">Accounts &times; source IPs</option></select>
        <input type="search" id="m-q" placeholder="Filter account, IP or host" aria-label="Filter">
        <select id="m-lim" aria-label="Rows"><option value="25">25 rows</option><option value="40" selected>40 rows</option><option value="80">80 rows</option><option value="150">150 rows</option></select>
        <span id="m-kinds"><label class="chk"><input type="checkbox" id="m-ku" checked> Accounts</label><label class="chk"><input type="checkbox" id="m-ki" checked> Source IPs</label><label class="chk"><input type="checkbox" id="m-kh"> Internal hosts</label></span>
      </div>
      <p class="note" id="m-note"></p>
      <div id="m-grid"></div>
      <div id="m-detail"></div>
    </section>
    <section id="v-incidents" class="view" hidden>
      <div class="controls" id="sevchips"></div>
      <div class="controls">
        <input type="search" id="inc-q" placeholder="Search account, IP or text" aria-label="Search incidents">
        <select id="inc-type" aria-label="Incident type"></select>
        <select id="inc-sort" aria-label="Sort incidents"><option value="sev">Most severe first</option><option value="new">Newest first</option><option value="old">Oldest first</option></select>
      </div>
      <p class="note" id="inc-count"></p>
      <div id="inc-list"></div>
    </section>

    <section id="v-users" class="view" hidden>
      <div class="controls">
        <input type="search" id="u-q" placeholder="Search accounts" aria-label="Search accounts">
        <select id="u-sort" aria-label="Sort accounts">
          <option value="total">Most data</option><option value="up">Most uploaded</option><option value="down">Most downloaded</option>
          <option value="secs">Longest connected</option><option value="sess">Most sessions</option><option value="risk">Highest risk</option><option value="fails">Most failed logins</option><option value="n">Name</option></select>
        <select id="u-status" aria-label="Filter by status">
          <option value="">All VPN users</option><option value="compromise">Suspected compromise</option><option value="review">Needs review</option><option value="targeted">Targeted</option><option value="watch">Watch</option><option value="normal">No findings</option><option value="failonly">Failed-only names (no session)</option></select>
      </div>
      <p class="note" id="u-count"></p>
      <div id="u-list"></div>
    </section>

    <section id="v-ips" class="view" hidden>
      <div class="controls">
        <input type="search" id="i-q" placeholder="IP prefix or country" aria-label="Search IPs">
        <select id="i-sort" aria-label="Sort IPs"><option value="risk">Highest risk</option><option value="fails">Most failed logins</option><option value="attacked">Most accounts attacked</option><option value="users">Most accounts connected</option><option value="total">Most data</option><option value="sess">Most sessions</option></select>
        <select id="i-role" aria-label="Filter by role"><option value="">All IPs</option><option value="attacker">Attack sources</option><option value="compromise">Used in compromise</option><option value="review">Needs review</option><option value="shared">Shared by accounts</option></select>
      </div>
      <p class="note" id="i-count"></p>
      <div class="tw" id="i-list"></div>
    </section>

    <section id="v-sessions" class="view" hidden>
      <div class="controls">
        <label class="fl">Account<input type="search" id="s-user" placeholder="contains"></label>
        <label class="fl">Source IP<input type="search" id="s-ip" placeholder="full IP or prefix"></label>
        <label class="fl">Inside IP (VPN address)<input type="search" id="s-inside" placeholder="e.g. 10.20.1.5 or 10.20.1."></label>
        <label class="fl">Min. upload (MB)<input type="number" id="s-minup" min="0" step="10"></label>
        <label class="fl">Sort<select id="s-sort"><option value="new">Newest first</option><option value="old">Oldest first</option><option value="up">Largest upload</option><option value="down">Largest download</option><option value="total">Most data</option><option value="dur">Longest</option></select></label>
      </div>
      <div class="row-actions"><a class="btn" id="s-export" href="#">Export these sessions as CSV</a><button class="btn" id="s-clear">Clear filters</button></div>
      <p class="note" id="s-count"></p>
      <div class="tw" id="s-list"></div>
    </section>

    <section id="v-events" class="view" hidden>
      <div class="controls">
        <label class="fl">Account<input type="search" id="e-user" placeholder="contains"></label>
        <label class="fl">Source IP<input type="search" id="e-ip" placeholder="full IP or prefix"></label>
        <label class="fl">Inside IP (VPN address)<input type="search" id="e-inside" placeholder="e.g. 10.20.1.5 or 10.20.1."></label>
        <label class="fl">Event type<select id="e-kind"></select></label>
        <label class="fl">Message contains<input type="search" id="e-q"></label>
        <label class="fl">Seq numbers<input type="text" id="e-seqs" placeholder="e.g. 1201, 1202"></label>
        <label class="fl">Order<select id="e-sort"><option value="desc">Newest first</option><option value="asc">Oldest first</option></select></label>
      </div>
      <div class="row-actions"><a class="btn" id="e-export" href="#">Export these events as CSV</a><button class="btn" id="e-clear">Clear filters</button></div>
      <p class="note" id="e-count">Only events the parser recognised are stored (logins, sessions, pool assignments).</p>
      <div class="tw" id="e-list"></div>
    </section>

    <section id="v-admin" class="view" hidden>
      <p class="note" style="margin:0 0 12px">Logins to the firewall itself and the commands run on it. Commands that clear or disable logging are shown in red, security-relevant changes in orange.</p>
      <div class="controls">
        <select id="a-kind" aria-label="Type"><option value="">Everything</option><option value="MGMT_LOGIN_FAIL">Failed admin logins</option><option value="MGMT_LOGIN_OK">Successful admin logins</option><option value="CONFIG_CMD">Commands</option><option value="PRIV_CHANGE">Privilege changes</option></select>
        <input type="search" id="a-user" placeholder="Admin account" aria-label="Admin account">
        <input type="search" id="a-q" placeholder="Command or text contains" aria-label="Text">
        <select id="a-sort" aria-label="Order"><option value="desc">Newest first</option><option value="asc">Oldest first</option></select>
      </div>
      <p class="note" id="a-count"></p>
      <div class="tw" id="a-list"></div>
    </section>
    <section id="v-links" class="view" hidden>
      <div class="controls">
        <select id="g-mode" aria-label="Drawing"><option value="flow">Attack flow (IPs &rarr; accounts &rarr; hosts)</option><option value="network">Network (free layout)</option></select>
        <select id="g-scope" aria-label="What to show"><option value="flag">Accounts and IPs with findings</option><option value="all">Riskiest and busiest accounts</option></select>
        <input type="search" id="g-q" placeholder="Trace an account or IP" aria-label="Trace an account or IP">
        <label class="chk"><input type="checkbox" id="g-fails" checked> Failed-login links</label>
        <label class="chk"><input type="checkbox" id="g-hosts" checked> Internal servers reached</label>
      </div>
      <div class="legend" style="margin-bottom:8px">
        <span><i class="sw" style="border-radius:50%;background:var(--crit)"></i>Suspected compromise</span>
        <span><i class="sw" style="border-radius:50%;background:var(--high)"></i>Targeted</span>
        <span><i class="sw" style="border-radius:50%;background:var(--sess)"></i>Account</span>
        <span><i class="sw" style="transform:rotate(45deg);background:var(--crit)"></i>Attacking IP</span>
        <span><i class="sw" style="transform:rotate(45deg);background:var(--rule2)"></i>IP</span>
        <span><i class="sw" style="height:2px;background:var(--rule2)"></i>Connected (width = data)</span>
        <span><i class="sw" style="height:0;border-top:2px dashed var(--crit)"></i>Failed logins only</span>
        <span><i class="sw" style="background:transparent;border:2px solid var(--up)"></i>Internal server (line = VPN traffic)</span>
      </div>
      <div id="gflow" class="tw" hidden></div>
      <div class="gwrap"><svg id="graph" role="img" aria-label="Map of accounts and source IPs"></svg>
        <div class="gbtns"><button id="g-in" aria-label="Zoom in">+</button><button id="g-out" aria-label="Zoom out">&minus;</button><button id="g-fit" aria-label="Fit to screen">&#x2922;</button></div></div>
      <p class="note" id="g-note"></p>
    </section>
  </main>
</div>
<div class="scrim" id="scrim" hidden></div>
<aside class="drawer" id="drawer" hidden aria-modal="true" role="dialog"></aside>
<div id="tip" role="tooltip"></div>
<script>
(function(){
"use strict";
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtN = n => (n || 0).toLocaleString('en');
function fmtB(n){ if(n == null) return '–'; const u=['B','KB','MB','GB','TB','PB']; let i=0, x=n; while(x>=1024 && i<u.length-1){x/=1024;i++;} return (i ? x.toFixed(x<10?2:x<100?1:0) : x) + ' ' + u[i]; }
function fmtD(s){ if(s == null) return '–'; s=Math.round(s); const d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60); if(d) return d+' d '+h+' h'; if(h) return h+' h '+m+' m'; if(m) return m+' m'; return s+' s'; }
const T = s => s ? Date.parse(s.replace(' ','T')+'Z') : null;
const short = s => s ? s.slice(0,16) : '–';
const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const niceDate = s => { if(!s) return '–'; const [y,m,d] = s.slice(0,10).split('-'); return (+d)+' '+MON[+m-1]+' '+y; };
const WROLE = {target:'Involved in incidents'};
const STATUS = {compromise:'Suspected compromise', review:'Needs review', targeted:'Targeted', watch:'Watch', normal:'No findings'};
const ROLE = {attacker:'Attack source', compromise:'Used in compromise', review:'Needs review', shared:'Shared by accounts'};
const VERDICT = {compromised:'Compromised', likely:'Likely compromised', review:'Needs review', benign:'Probably the user'};
const SEV = {critical:'Critical', high:'High', medium:'Medium', low:'Low'};
const TYPE = {brute_force:'Brute force', password_spray:'Password spraying', compromise:'Login after failed attempts',
  attack_ip_login:'Login from attacking IP', concurrent_sessions:'Simultaneous sessions', impossible_travel:'Country change',
  new_country:'New country', shared_ip:'Shared IP', large_upload:'Large upload', large_transfer:'Large transfer', long_session:'Long session',
  large_download:'Large download', unusual_download:'Unusual download volume', unusual_time:'Unusual login time', new_client:'New VPN client',
  account_lockout:'Account lockout', internal_scan:'Internal scanning', lateral_movement:'Lateral movement', post_compromise:'Internal access after compromise',
  port_scan:'Port scan', login_from_scanner:'Login from scanning IP', threat_detection:'Threat detection', admin_brute_force:'Admin brute force',
  admin_login_internet:'Admin login from internet', logging_tampered:'Logging tampered', config_change:'Firewall config change',
  foreign_login:'Login from abroad', coordinated_attack:'Coordinated attack (IP cluster)', suspicious_login:'Suspicious login (no failures)',
  shared_new_ip:'Same new IP, several accounts'};
const PORTS = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',88:'Kerberos',110:'POP3',111:'RPCbind',135:'RPC',139:'NetBIOS',143:'IMAP',161:'SNMP',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',587:'SMTP',636:'LDAPS',993:'IMAPS',1433:'MSSQL',1521:'Oracle',2049:'NFS',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',5985:'WinRM',5986:'WinRM',8080:'HTTP-alt',8443:'HTTPS-alt',9100:'Printer'};
const ADMINP = new Set([22,23,88,111,135,139,161,389,445,636,1433,2049,3306,3389,5432,5900,5985,5986]);
const svcName = p => p == null ? '' : (PORTS[p] ? `${PORTS[p]} ${p}` : String(p));
const portChips = ps => (ps || []).map(p => `<span class="portchip ${ADMINP.has(+p) ? 'adm' : ''}">${esc(svcName(+p))}</span>`).join('');
const RE_ANTI = /\b(clear\s+logging|no\s+logging|logging\s+disable|clear\s+configure\s+logging|write\s+erase|clear\s+configure\s+all)\b/i;
const RE_SENS = /\b(username|password|passwd|access-list|access-group|aaa|tunnel-group|group-policy|crypto|webvpn|anyconnect|http\s+server|telnet|snmp-server|nat|route|shun|capture|copy|export)\b/i;
const KIND = {INVALID_PW:'Wrong password', AUTH_SUCCESS:'Login succeeded', GROUP_SET:'Group policy set', GROUP_RETRIEVED:'Group policy read',
  PARENT_STARTED:'Session started', POOL_ASSIGNED:'Pool address given', ASSIGNED:'Address assigned', DISCONNECTED:'Session ended', POOL_FREED:'Pool address freed',
  CLIENT_INFO:'VPN client', LOCKOUT:'Account locked', WEBVPN_START:'WebVPN started', WEBVPN_END:'WebVPN ended', MGMT_LOGIN_OK:'Admin login',
  MGMT_LOGIN_FAIL:'Admin login failed', CONFIG_CMD:'Firewall command', PRIV_CHANGE:'Privilege change', THREAT:'Threat detection', OTHER:'Other (not parsed)'};
const uRef = (k, n) => `<button class="ref" data-u="${esc(k)}">${esc(n)}</button>`;
const insideRef = ip => ip ? `<button class="ref ip" data-inside="${esc(ip)}" title="Show all sessions with this VPN address">${esc(ip)}</button>` : '–';
const hostRef = ip => ip ? `<button class="ref ip" data-host="${esc(ip)}" title="Internal host">${esc(ip)}</button>` : '–';
const ipRef = ip => ip ? `<button class="ref ip" data-ip="${esc(ip)}">${esc(ip)}</button>` : '–';
const TK = {};
const tick = k => (TK[k] = (TK[k] || 0) + 1);

/* ---------- API ---------- */
const errbar = $('#err');
function showErr(e){ errbar.hidden = false; errbar.textContent = 'Could not load data: ' + (e && e.message || e) + '. Check that asa_server.py is still running.'; }
function qstr(p){ const u = new URLSearchParams(); for(const [k,v] of Object.entries(p || {})) if(v !== '' && v != null && v !== false) u.set(k, v); return u.toString(); }
const RANGE = {from:'', to:'', h1:'', h2:''};
const rp = () => ({from: RANGE.from, to: RANGE.to, h1: RANGE.h1 && RANGE.h2 ? RANGE.h1 : '', h2: RANGE.h1 && RANGE.h2 ? RANGE.h2 : ''});
const rangeOn = () => !!(RANGE.from || RANGE.to || (RANGE.h1 && RANGE.h2));
const withRange = p => Object.assign({}, rp(), p || {});
async function api(path, p, noRange){
  let r;
  try { r = await fetch(path + '?' + qstr(noRange ? p : withRange(p))); } catch(e){ showErr(e); throw e; }
  if(!r.ok){ let m = r.statusText; try { m = (await r.json()).error || m; } catch(e){} const err = new Error(m); if(r.status !== 404) showErr(err); throw err; }
  errbar.hidden = true; return r.json();
}
const debounce = (f, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), ms || 300); }; };

/* ---------- tooltip ---------- */
const tip = $('#tip');
function showTip(h, x, y){ tip.innerHTML = h; tip.style.display = 'block'; const r = tip.getBoundingClientRect(); let L = x + 14, Tp = y + 14; if(L + r.width > innerWidth - 8) L = x - r.width - 14; if(Tp + r.height > innerHeight - 8) Tp = y - r.height - 14; tip.style.left = Math.max(6, L) + 'px'; tip.style.top = Math.max(6, Tp) + 'px'; }
function hideTip(){ tip.style.display = 'none'; }
document.addEventListener('pointermove', e => { const t = e.target.closest && e.target.closest('[data-tip]'); if(t) showTip(t.getAttribute('data-tip'), e.clientX, e.clientY); else if(!e.target.closest('.daily-ov')) hideTip(); });
document.addEventListener('scroll', hideTip, true);

/* ---------- header ---------- */
let META = null, SUM = null;
function renderHeader(){
  const M = META.meta;
  $('#period').textContent = `Covers ${niceDate(M.first)} to ${niceDate(M.last)}. ${fmtN(M.events)} parsed events from ${M.db}, analysed ${short(M.generated)}.` + (M.geo ? '' : ' Country checks are off because no country database was used (see Overview).');
  $('#inc-type').innerHTML = '<option value="">All types</option>' + META.types.map(t => `<option value="${esc(t)}">${esc(TYPE[t] || t)}</option>`).join('');
  $('#e-kind').innerHTML = '<option value="">All types</option>' + META.kinds.map(k => `<option value="${esc(k)}">${esc(KIND[k] || k)}</option>`).join('');
  const lo = (M.first || '').slice(0,16).replace(' ','T'), hi = (M.last || '').slice(0,16).replace(' ','T');
  ['r-from','r-to'].forEach(id => { $('#' + id).min = lo; $('#' + id).max = hi; });
}
async function loadSummary(){
  const t = tick('sum');
  try { const s = await api('/api/summary'); if(t !== TK.sum) return; SUM = s; renderAttention(); } catch(e){}
}
function renderAttention(){
  const S = SUM, rng = S.ranged;
  const list = (arr, total, fn, go, more) => arr.length ? `<div class="alist">${arr.slice(0,6).map(fn).join('')}${total > 6 ? `<button class="more" data-go="${go}" data-more="${more}">Show all ${fmtN(total)}</button>` : ''}</div>` : '';
  $('#attention').innerHTML =
    `<div><h2>Suspected compromised accounts <span class="count">${fmtN(S.comp_n)}</span></h2>` +
    (list(S.compromised, S.comp_n, u => `<button class="aitem" data-u="${esc(u.key)}"><i class="dot st-compromise"></i><span>${esc(u.n)}</span><span class="why">${esc(u.top)}</span></button>`, 'users', 'compromise') || `<p class="none">${rng ? 'No suspected compromise in the selected time.' : 'No account matches the compromise rules with the current thresholds.'}</p>`) + `</div>` +
    `<div><h2>Attacking IP addresses <span class="count">${fmtN(S.atk_n)}</span></h2>` +
    (list(S.attackers, S.atk_n, x => `<button class="aitem" data-ip="${esc(x.ip)}"><i class="dot st-compromise" style="border-radius:1px;transform:rotate(45deg)"></i><span class="ip">${esc(x.ip)}</span><span class="why">${fmtN(x.fails)} failed logins against ${fmtN(x.attacked)} account${x.attacked === 1 ? '' : 's'}${x.country ? ', ' + esc(x.country) : ''}${x.users ? `, <b>${x.users} successful</b>` : ''}</span></button>`, 'ips', 'attacker') || `<p class="none">${rng ? 'No attacking IP active in the selected time.' : 'No IP crossed the brute-force or spraying thresholds.'}</p>`) + `</div>`;
  const s = S.sev, K = S.kpi;
  $('#kpis').innerHTML = [
    ['', fmtN(K.sessions), 'VPN sessions'], ['', fmtN(K.connected), 'Accounts connected'],
    ['up', fmtB(K.up), 'Uploaded by users'], ['down', fmtB(K.down), 'Downloaded by users'], ['', fmtD(K.secs), 'Total connected time'],
    ['', fmtN(K.fails), 'Failed logins'], [s.critical ? 'crit' : '', (s.critical || 0) + ' / ' + (s.high || 0), 'Critical / high incidents']
  ].concat(K.cases != null ? [[K.cases_crit ? 'crit' : '', fmtN(K.cases), 'Cases (linked incidents)']] : [])
   .concat(K.hosts != null ? [['', fmtN(K.hosts), 'Internal hosts reached']] : [])
   .concat(K.logins_review != null ? [[K.logins_comp ? 'crit' : '', fmtN(K.logins_comp) + ' / ' + fmtN(K.logins_review), 'Logins compromised / to review']] : [])
   .map(k => `<button class="kpi ${k[0]}" data-go="${KGO[k[2]] || 'overview'}" title="Open ${esc(KGO[k[2]] || '')}"><b>${k[1]}</b><span>${k[2]}</span></button>`).join('');
}

const KGO = {'VPN sessions': 'sessions', 'Accounts connected': 'users', 'Uploaded by users': 'users', 'Downloaded by users': 'users',
  'Total connected time': 'sessions', 'Failed logins': 'logins', 'Critical / high incidents': 'incidents', 'Cases (linked incidents)': 'cases',
  'Internal hosts reached': 'hosts', 'Logins compromised / to review': 'logins'};
/* ---------- charts ---------- */
function fillBuckets(list, unit, a, b){
  const hour = unit === 'hour', step = hour ? 3600e3 : 86400e3;
  const toMs = k => hour ? Date.parse(k.replace(' ', 'T') + ':00:00Z') : Date.parse(k + 'T00:00:00Z');
  const key = ms => { const x = new Date(ms).toISOString(); return hour ? x.slice(0,10) + ' ' + x.slice(11,13) : x.slice(0,10); };
  if(!list.length && !(a && b)) return [];
  const m = new Map(list.map(d => [d.d, d])); const out = [];
  let t = toMs(a || list[0].d); const end = toMs(b || list[list.length-1].d);
  if(!isFinite(t) || !isFinite(end)) return list;
  for(let i = 0; t <= end && i < 20000; i++, t += step){ const k = key(t); out.push(Object.assign({d:k, up:0, down:0, sess:0, fails:0}, m.get(k) || {})); }
  out.unit = unit; return out;
}
const bucketLabel = d => d.d.length > 10 ? `${niceDate(d.d)}, ${d.d.slice(11,13)}:00 to ${String((+d.d.slice(11,13) + 1) % 24).padStart(2,'0')}:00` : niceDate(d.d);
function dailyChart(el, days, compact, onPick){
  el.innerHTML = '';
  if(!days.length || days.every(d => !d.up && !d.down && !d.fails && !d.sess)){ el.innerHTML = '<p class="empty">No activity in the selected time.</p>'; return; }
  const W = Math.max(el.clientWidth, 280), padL = W < 500 ? 56 : 62, half = compact ? 60 : 92, failH = compact ? 20 : 28, axisH = 20;
  const H = half * 2 + 10 + failH + axisH, n = days.length, bw = (W - padL) / n, mid = half;
  let mx = 1, mf = 1; for(const d of days){ mx = Math.max(mx, d.up, d.down); mf = Math.max(mf, d.fails); }
  const w = Math.min(Math.max(bw - (bw > 3 ? 1 : 0), 0.7), 28), off = (bw - w) / 2;
  let s = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Uploaded and downloaded data per day">`;
  s += `<line class="grid" x1="${padL}" x2="${W}" y1="1" y2="1"/><line class="grid" x1="${padL}" x2="${W}" y1="${half*2}" y2="${half*2}"/>`;
  s += `<text class="ax" x="${padL-6}" y="11" text-anchor="end">${fmtB(mx)}</text><text class="ax" x="${padL-6}" y="${mid-4}" text-anchor="end" style="fill:var(--up)">up</text>`;
  s += `<text class="ax" x="${padL-6}" y="${mid+13}" text-anchor="end" style="fill:var(--down)">down</text><text class="ax" x="${padL-6}" y="${half*2-2}" text-anchor="end">${fmtB(mx)}</text>`;
  let bars = ''; const f0 = half * 2 + 10;
  days.forEach((d, i) => { const x = padL + i * bw + off;
    if(d.up) { const h = Math.max(d.up / mx * half, 1); bars += `<rect class="up" x="${x.toFixed(2)}" y="${(mid-h).toFixed(2)}" width="${w.toFixed(2)}" height="${h.toFixed(2)}"/>`; }
    if(d.down){ const h = Math.max(d.down / mx * half, 1); bars += `<rect class="down" x="${x.toFixed(2)}" y="${mid}" width="${w.toFixed(2)}" height="${h.toFixed(2)}"/>`; }
    if(d.fails){ const h = Math.max(d.fails / mf * failH, 1.5); bars += `<rect class="fail" x="${x.toFixed(2)}" y="${(f0+failH-h).toFixed(2)}" width="${w.toFixed(2)}" height="${h.toFixed(2)}"/>`; } });
  s += `<g shape-rendering="crispEdges">${bars}</g><line class="axl" x1="${padL}" x2="${W}" y1="${mid}" y2="${mid}"/>`;
  s += `<text class="ax" x="${padL-6}" y="${f0+failH-2}" text-anchor="end" style="fill:var(--crit)">${fmtN(mf)}</text>`;
  let lastX = -1e9;
  const hourly = days.length && days[0].d.length > 10;
  days.forEach((d, i) => { const day = +d.d.slice(8,10), mon = +d.d.slice(5,7);
    if(hourly){ const h = +d.d.slice(11,13); if(i === 0 || h === 0 || h === 12){ const x = padL + i * bw; if(x - lastX > 70){ s += `<text class="ax" x="${x.toFixed(1)}" y="${H-5}">${h === 0 || i === 0 ? day + ' ' + MON[mon-1] + ' ' : ''}${String(h).padStart(2,'0')}:00</text>`; lastX = x; } } }
    else if(i === 0 || day === 1){ const x = padL + i * bw; if(x - lastX > 64){ s += `<text class="ax" x="${x.toFixed(1)}" y="${H-5}">${MON[mon-1]} ${d.d.slice(0,4)}</text>`; lastX = x; } } });
  s += `<line class="hl" x1="0" x2="0" y1="0" y2="${f0+failH}" style="display:none"/><rect class="daily-ov" x="${padL}" y="0" width="${W-padL}" height="${H}" fill="transparent"/></svg>`;
  el.innerHTML = s;
  const ov = el.querySelector('.daily-ov'), hl = el.querySelector('.hl');
  const move = e => { const r = ov.getBoundingClientRect(); const i = Math.min(n-1, Math.max(0, Math.floor((e.clientX - r.left) / r.width * n))); const d = days[i]; const x = padL + (i + 0.5) * bw;
    hl.setAttribute('x1', x); hl.setAttribute('x2', x); hl.style.display = '';
    showTip(`<b>${bucketLabel(d)}</b><br>Uploaded ${fmtB(d.up)}<br>Downloaded ${fmtB(d.down)}<br>${fmtN(d.sess)} sessions${d.users != null ? ', ' + fmtN(d.users) + ' accounts' : ''}<br>${fmtN(d.fails)} failed logins`, e.clientX, e.clientY); };
  ov.addEventListener('pointermove', move); ov.addEventListener('pointerdown', move);
  ov.addEventListener('pointerleave', () => { hl.style.display = 'none'; hideTip(); });
  el.classList.toggle('zoomable', !!onPick);
  if(onPick) ov.addEventListener('click', e => { const r = ov.getBoundingClientRect(); const i = Math.min(n-1, Math.max(0, Math.floor((e.clientX - r.left) / r.width * n))); hideTip(); onPick(days[i]); });
}
function gantt(el, items, fails, lanes){
  /* items: {lane,s,e,secs,up,down,open,inside}; fails: {lane,t}; lanes: Map lane -> {label, attr, flag} */
  el.innerHTML = '';
  if(!items.length && !fails.length){ el.innerHTML = '<p class="empty">No sessions.</p>'; return; }
  const W = Math.max(el.clientWidth, 280), lw = W < 480 ? 100 : 136, laneH = 22, MAXL = 14;
  const cnt = new Map(); for(const s of items) cnt.set(s.lane, (cnt.get(s.lane) || 0) + 3); for(const f of fails) cnt.set(f.lane, (cnt.get(f.lane) || 0) + 1);
  let ls = [...cnt.keys()].sort((a,b) => cnt.get(b) - cnt.get(a)); let other = false;
  if(ls.length > MAXL){ ls = ls.slice(0, MAXL - 1); other = true; }
  const li = new Map(ls.map((k, i) => [k, i])); const laneOf = k => li.has(k) ? li.get(k) : MAXL - 1; const nL = ls.length + (other ? 1 : 0);
  let t0 = Infinity, t1 = -Infinity; for(const s of items){ t0 = Math.min(t0, T(s.s)); t1 = Math.max(t1, T(s.e)); } for(const f of fails){ const t = T(f.t); t0 = Math.min(t0, t); t1 = Math.max(t1, t); }
  if(t1 - t0 < 3600e3){ t0 -= 1800e3; t1 += 1800e3; }
  const X = t => lw + (t - t0) / (t1 - t0) * (W - lw - 6), H = nL * laneH + 24;
  const info = k => lanes.get(k) || {label:k, attr:'', flag:false};
  let s = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Sessions over time">`;
  for(let i = 0; i < nL; i++){ const y = i * laneH; const k = i < ls.length ? ls[i] : null;
    s += `<line class="grid" x1="${lw}" x2="${W}" y1="${y + laneH}" y2="${y + laneH}"/>`;
    if(k != null){ const f = info(k); const lab = String(f.label); s += `<text class="ax ${f.mono ? 'ip' : ''}" x="0" y="${y + 15}" ${f.attr} style="cursor:pointer;${f.flag ? 'fill:var(--crit)' : ''}">${esc(lab.length > 18 ? lab.slice(0,17) + '…' : lab)}</text>`; }
    else s += `<text class="ax" x="0" y="${y + 15}">Others</text>`; }
  for(const x of items){ const i = laneOf(x.lane), xa = X(T(x.s)), w = Math.max(X(T(x.e)) - xa, 2); const f = info(x.lane);
    const tt = x.tip || `<b>${esc(f.label)}</b><br>${short(x.s)} to ${short(x.e)}${x.open ? ' (estimated)' : ''}<br>${fmtD(x.secs)} connected<br>Uploaded ${fmtB(x.up)}, downloaded ${fmtB(x.down)}${x.inside ? '<br>Inside IP ' + esc(x.inside) : ''}`;
    s += `<rect class="${f.flag ? 'flag' : 'sess'}" x="${xa.toFixed(1)}" y="${i * laneH + 4}" width="${w.toFixed(1)}" height="${laneH - 10}" ${x.open ? 'fill-opacity=".45"' : ''} data-tip="${esc(tt)}"/>`; }
  for(const f of fails){ const i = laneOf(f.lane), x = X(T(f.t)); s += `<rect class="fail" x="${(x - 1).toFixed(1)}" y="${i * laneH + laneH - 6}" width="2" height="5" opacity=".8" data-tip="${esc((f.tip || 'Failed login') + ' ' + short(f.t) + ': ' + esc(info(f.lane).label))}"/>`; }
  for(let k = 0; k <= 4; k++){ const t = t0 + (t1 - t0) * k / 4; const d = new Date(t).toISOString(); const x = X(t); s += `<text class="ax" x="${x.toFixed(1)}" y="${H - 4}" text-anchor="${k === 0 ? 'start' : k === 4 ? 'end' : 'middle'}">${t1 - t0 < 3 * 86400e3 ? d.slice(5,16).replace('T',' ') : d.slice(0,10)}</text>`; }
  el.innerHTML = s + '</svg>';
}

/* ---------- ledger ---------- */
function ledger(list, mx, wide){
  if(!list.length) return '<p class="empty">No accounts match.</p>';
  if(!mx){ mx = 1; for(const u of list) mx = Math.max(mx, u.up, u.down); }
  const pct = v => v ? Math.max(v / mx * 100, 0.6).toFixed(2) : 0;
  let h = `<div class="ledger ${wide ? 'wide' : ''}"><div class="lh"><span class="c-name">Account</span><span class="c-up">Uploaded</span><span class="c-down">Downloaded</span><span class="ltime c-time">Connected</span>` +
    (wide ? '<span class="lx">Sessions</span><span class="lx">IPs</span><span class="lx">Failed</span>' : '') + '</div>';
  for(const u of list){
    h += `<button class="lrow" data-u="${esc(u.key)}" data-tip="${esc(`<b>${esc(u.n)}</b><br>${STATUS[u.status]}${u.top ? ': ' + esc(u.top) : ''}<br>Uploaded ${fmtB(u.up)}, downloaded ${fmtB(u.down)}<br>Connected ${fmtD(u.secs)} in ${fmtN(u.sess)} sessions`)}">` +
      `<span class="lname"><i class="dot st-${u.status}"></i><span class="t">${esc(u.n)}</span></span>` +
      `<span class="lup"><span class="track"><span class="bar up" style="width:${pct(u.up)}%"></span></span><span class="lv">${fmtB(u.up)}</span></span>` +
      `<span class="ldown"><span class="track"><span class="bar down" style="width:${pct(u.down)}%"></span></span><span class="lv">${fmtB(u.down)}</span></span>` +
      `<span class="ltime">${fmtD(u.secs)}</span>` +
      (wide ? `<span class="lx">${fmtN(u.sess)}</span><span class="lx">${fmtN(u.ips)}</span><span class="lx ${u.fails ? 'bad' : ''}">${fmtN(u.fails)}</span>` : '') + '</button>';
  }
  return h + '</div>';
}
function timeBars(list){
  if(!list.length) return '<p class="empty">No sessions in the selected time.</p>';
  let mx = 1; for(const u of list) mx = Math.max(mx, u.secs);
  return `<div class="ledger">` + list.map(u => `<button class="lrow" style="grid-template-columns:minmax(7rem,11rem) 1fr 5.5rem;grid-template-areas:none" data-u="${esc(u.key)}"><span class="lname" style="grid-area:auto"><i class="dot st-${u.status}"></i><span class="t">${esc(u.n)}</span></span><span class="track"><span class="bar" style="background:var(--sess);width:${Math.max(u.secs/mx*100,0.6).toFixed(2)}%"></span></span><span class="ltime" style="grid-area:auto">${fmtD(u.secs)}</span></button>`).join('') + '</div>';
}

/* ---------- overview ---------- */
let dailyCache = null;
function drawDaily(){ const d = dailyCache; $('#daily-h').textContent = d.unit === 'hour' ? 'Data moved per hour' : 'Data moved per day'; dailyChart($('#daily'), fillBuckets(d.rows, d.unit, d.start, d.end), false, pickBucket); }
function pickBucket(d){
  if(d.d.length > 10){ const h = d.d.slice(11,13); setRange({from: d.d.slice(0,10) + 'T' + h + ':00', to: d.d.slice(0,10) + 'T' + h + ':59'}); }
  else setRange({from: d.d + 'T00:00', to: d.d + 'T23:59'});
}
async function renderOverview(){
  const t = tick('ov');
  try {
    const [d, a, b] = await Promise.all([dailyCache ? dailyCache : api('/api/daily'), api('/api/users', {sort:'total', limit:12}), api('/api/users', {sort:'secs', limit:12})]);
    if(t !== TK.ov) return;
    dailyCache = d; drawDaily();
    $('#topdata').innerHTML = ledger(a.rows); $('#toptime').innerHTML = timeBars(b.rows);
    drawIncTrend(); drawHeat(); renderOvCamps();
    renderCountries(await api('/api/countries'));
  } catch(e){}
}
function renderCountries(r){
  WM = r; $('#wmap').hidden = !r.geo; $('#wm-legend').hidden = !r.geo; $('#wm-view').closest('.controls').hidden = !r.geo; drawWorldMap();
  const el = $('#countries');
  if(!r.geo){ el.innerHTML = `<p class="note">Countries are not available because no country database was used. Re-run the analysis with
    <code>--analyze-args "--geoip dbip-country-lite.csv"</code> (free file from db-ip.com, no account needed) or a MaxMind GeoLite2-Country.mmdb.
    Add <code>--home-countries CZ</code> to flag VPN logins from anywhere else.</p>`; return; }
  if(!r.rows.length){ el.innerHTML = '<p class="empty">No connections with a known country in the selected time.</p>'; return; }
  const home = new Set(r.home), mx = Math.max(1, ...r.rows.map(x => x.sess)), mf = Math.max(1, ...r.rows.map(x => x.fails));
  el.innerHTML = (r.home.length ? `<p class="note">Expected countries: ${r.home.map(esc).join(', ')}. Others are highlighted.</p>` : '<p class="note">Tip: add <code>--home-countries CZ</code> to the analysis to highlight and flag logins from other countries.</p>') +
    `<div class="tw"><table><thead><tr><th>Country</th><th>VPN sessions</th><th class="num">Accounts</th><th class="num">Source IPs</th><th>Failed logins</th><th class="num">Attacking IPs</th><th class="num">Downloaded</th><th>Last session</th></tr></thead><tbody>` +
    r.rows.map(x => { const foreign = home.size && !home.has(x.cc);
      return `<tr class="click" data-country="${esc(x.country || x.cc)}"><td ${foreign ? 'style="color:var(--high);font-weight:600"' : ''}>${esc(x.country || x.cc)} <span class="note">${esc(x.cc)}</span></td>
        <td><span class="cbar" style="width:${Math.max(2, x.sess / mx * 120)}px;background:var(--down)"></span> ${fmtN(x.sess)}</td><td class="num">${fmtN(x.users)}</td><td class="num">${fmtN(x.ips)}</td>
        <td>${x.fails ? `<span class="cbar" style="width:${Math.max(2, x.fails / mf * 120)}px;background:var(--crit)"></span> ${fmtN(x.fails)}` : '–'}</td>
        <td class="num" ${x.attackers ? 'style="color:var(--crit)"' : ''}>${fmtN(x.attackers)}</td><td class="num">${fmtB(x.down)}</td><td>${short(x.last)}</td></tr>`; }).join('') +
    `</tbody></table></div>` + (r.unknown ? `<p class="note">${fmtN(r.unknown)} sessions from IPs without a known country (private or not in the database).</p>` : '');
}

/* ---------- incidents ---------- */
function incRow(x){
  const us = x.users.map(u => uRef(u.k, u.n)).join(', ') + (x.n_users > x.users.length ? ` and ${fmtN(x.n_users - x.users.length)} more` : '');
  const is = x.ips.slice(0, 6).map(ipRef).join(', ') + (x.ips.length > 6 ? ` and ${x.ips.length - 6} more` : '');
  return `<article class="inc ${x.sev}"><div class="inc-h"><span class="badge c-${x.sev}">${SEV[x.sev]}</span><h3>${esc(x.title)}</h3></div>` +
    `<p>${esc(x.detail)}</p><div class="inc-m"><span>${esc(TYPE[x.type] || x.type)}</span><span>${short(x.start)}${x.end && x.end.slice(0,16) !== x.start.slice(0,16) ? ' to ' + short(x.end) : ''}</span>` +
    (us ? `<span>Accounts: ${us}</span>` : '') + (is ? `<span>IPs: ${is}</span>` : '') +
    (x.hosts && x.hosts.length ? `<span>Internal hosts: ${x.hosts.slice(0, 6).map(hostRef).join(', ')}${x.hosts.length > 6 ? ` and ${x.hosts.length - 6} more` : ''}</span>` : '') +
    (x.seqs.length ? `<button class="ref" data-seqs="${x.seqs.join(',')}">Show ${x.seqs.length} raw event${x.seqs.length === 1 ? '' : 's'}</button>` : '') + '</div></article>';
}
const incS = {sev: new Set(['critical','high','medium','low']), rows: [], total: 0};
function incParams(){ return {sev: [...incS.sev].join(',') || 'none', type: $('#inc-type').value, q: $('#inc-q').value.trim(), sort: $('#inc-sort').value}; }
async function loadIncidents(append){
  const t = tick('inc');
  if(!append) $('#inc-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/incidents', Object.assign(incParams(), {limit: 100, offset: append ? incS.rows.length : 0}));
    if(t !== TK.inc) return;
    incS.rows = append ? incS.rows.concat(r.rows) : r.rows; incS.total = r.total;
    $('#sevchips').innerHTML = Object.keys(SEV).map(s => `<button class="chip" data-sev="${s}" aria-pressed="${incS.sev.has(s)}"><i class="sq" style="background:var(--${s === 'critical' ? 'crit' : s === 'medium' ? 'med' : s})"></i>${SEV[s]} ${fmtN((SUM && SUM.sev[s]) || 0)}</button>`).join('');
    $('#inc-count').textContent = `${fmtN(incS.total)} incidents match`;
    $('#inc-list').innerHTML = incS.rows.length ? incS.rows.map(incRow).join('') + (incS.total > incS.rows.length ? `<button class="more" data-more-list="inc">Show more (${fmtN(incS.total - incS.rows.length)} left)</button>` : '') : '<p class="empty">No incidents match these filters.</p>';
  } catch(e){}
}

/* ---------- accounts ---------- */
const uS = {rows: [], total: 0, max: 1};
async function loadUsers(append){
  const t = tick('u');
  if(!append) $('#u-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/users', {q: $('#u-q').value.trim(), sort: $('#u-sort').value, status: $('#u-status').value, limit: 200, offset: append ? uS.rows.length : 0});
    if(t !== TK.u) return;
    uS.rows = append ? uS.rows.concat(r.rows) : r.rows; uS.total = r.total; uS.max = r.max;
    $('#u-count').textContent = `${fmtN(uS.total)} accounts. Bars share one scale: uploaded grows left, downloaded grows right.`;
    $('#u-list').innerHTML = ledger(uS.rows, uS.max, true) + (uS.total > uS.rows.length ? `<button class="more" data-more-list="u">Show more (${fmtN(uS.total - uS.rows.length)} left)</button>` : '');
  } catch(e){}
}

/* ---------- IPs ---------- */
const iS = {rows: [], total: 0};
async function loadIps(append){
  const t = tick('i');
  if(!append) $('#i-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/ips', {q: $('#i-q').value.trim(), sort: $('#i-sort').value, role: $('#i-role').value, limit: 200, offset: append ? iS.rows.length : 0});
    if(t !== TK.i) return;
    iS.rows = append ? iS.rows.concat(r.rows) : r.rows; iS.total = r.total;
    $('#i-count').textContent = `${fmtN(iS.total)} source IPs`;
    $('#i-list').innerHTML = `<table><thead><tr><th>IP address</th><th>Country</th><th>Role</th><th class="num">Accounts connected</th><th class="num">Accounts attacked</th><th class="num">Failed logins</th><th class="num">Sessions</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th>Last seen</th></tr></thead><tbody>` +
      iS.rows.map(x => `<tr class="click" data-ip="${esc(x.ip)}"><td class="ip">${esc(x.ip)}</td><td>${esc(x.country || '–')}</td><td>${x.role ? `<span class="badge c-${x.role}">${ROLE[x.role]}</span>` : ''}</td><td class="num">${fmtN(x.users)}</td><td class="num">${fmtN(x.attacked)}</td><td class="num">${fmtN(x.fails)}</td><td class="num">${fmtN(x.sess)}</td><td class="num up">${fmtB(x.up)}</td><td class="num down">${fmtB(x.down)}</td><td>${short(x.last)}</td></tr>`).join('') +
      '</tbody></table>' + (iS.total > iS.rows.length ? `<button class="more" data-more-list="i">Show more (${fmtN(iS.total - iS.rows.length)} left)</button>` : '');
  } catch(e){}
}

/* ---------- sessions ---------- */
const clientShort = c => (c || '').replace(/^Cisco AnyConnect( Secure Mobility Client| VPN Agent)?( for)?\s*/i, '').replace(/\s+\d[\w.\-]*$/, '') || '–';
function sessTable(rows, hide){
  hide = hide || '';
  return `<table><thead><tr><th>Start</th><th>End</th><th class="num">Duration</th>${hide !== 'u' ? '<th>Account</th>' : ''}${hide !== 'ip' ? '<th>Source IP</th><th>Country</th>' : ''}<th>Inside IP</th><th>Client</th><th class="num">Internal</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th>Reason</th></tr></thead><tbody>` +
    rows.map(x => `<tr><td>${esc(x.s)}</td><td>${esc(x.e)}${x.open ? ' *' : ''}</td><td class="num">${fmtD(x.secs)}</td>${hide !== 'u' ? `<td>${uRef(x.u, x.n)}</td>` : ''}${hide !== 'ip' ? `<td>${ipRef(x.ip)}</td><td>${esc(x.country || '–')}</td>` : ''}<td>${insideRef(x.inside)}</td><td title="${esc(x.client)}">${esc(clientShort(x.client))}</td><td class="num">${x.int_hosts ? `${fmtN(x.int_hosts)} host${x.int_hosts === 1 ? '' : 's'}, ${fmtB(x.int_bytes)}${x.blocked ? `, <span style="color:var(--crit)">${fmtN(x.blocked)} blocked</span>` : ''}` : '–'}</td><td class="num up">${fmtB(x.up)}</td><td class="num down">${fmtB(x.down)}</td><td>${esc(x.reason)}</td></tr>`).join('') +
    '</tbody></table>' + (rows.some(x => x.open) ? '<p class="note">* No disconnect was logged, so the end is estimated from the next activity of the account.</p>' : '');
}
const sS = {rows: [], total: 0};
const sParams = () => ({user: $('#s-user').value.trim(), exact: sS.exact ? 1 : '', ip: $('#s-ip').value.trim(), inside: $('#s-inside').value.trim(), min_up: $('#s-minup').value, sort: $('#s-sort').value});
async function loadSessions(append){
  const t = tick('s'); const p = sParams();
  $('#s-export').href = '/api/export/sessions.csv?' + qstr(withRange(p));
  if(!append) $('#s-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/sessions', Object.assign({}, p, {limit: 200, offset: append ? sS.rows.length : 0}));
    if(t !== TK.s) return;
    sS.rows = append ? sS.rows.concat(r.rows) : r.rows; sS.total = r.total;
    let up = 0, down = 0, secs = 0; for(const x of sS.rows){ up += x.up; down += x.down; secs += x.secs; }
    $('#s-count').textContent = `${fmtN(sS.total)} session${sS.total === 1 ? '' : 's'} match${sS.total === 1 ? 'es' : ''}. Shown: ${fmtN(sS.rows.length)}, uploaded ${fmtB(up)}, downloaded ${fmtB(down)}, connected ${fmtD(secs)}.`;
    $('#s-list').innerHTML = sS.rows.length ? sessTable(sS.rows) + (sS.total > sS.rows.length ? `<button class="more" data-more-list="s">Show more (${fmtN(sS.total - sS.rows.length)} left)</button>` : '') : '<p class="empty">No sessions match these filters.</p>';
  } catch(e){}
}

/* ---------- raw events ---------- */
const eS = {rows: [], more: false};
const eParams = () => ({user: $('#e-user').value.trim(), exact: eS.exact ? 1 : '', ip: $('#e-ip').value.trim(), inside: $('#e-inside').value.trim(), kind: $('#e-kind').value, q: $('#e-q').value.trim(), seqs: $('#e-seqs').value.trim(), sort: $('#e-sort').value});
async function loadEvents(append){
  const t = tick('e'); const p = eParams();
  $('#e-export').href = '/api/export/events.csv?' + qstr(withRange(p));
  if(!append) $('#e-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/events', Object.assign({}, p, {limit: 200, offset: append ? eS.rows.length : 0}));
    if(t !== TK.e) return;
    eS.rows = append ? eS.rows.concat(r.rows) : r.rows; eS.more = r.has_more;
    $('#e-count').textContent = `${fmtN(eS.rows.length)}${eS.more ? '+' : ''} event${eS.rows.length === 1 && !eS.more ? '' : 's'}. Only events the parser recognised are stored (logins, sessions, address assignments).`;
    $('#e-list').innerHTML = eS.rows.length ? `<table><thead><tr><th>Seq</th><th>Time</th><th>Type</th><th>Account</th><th>Source IP</th><th>Inside IP</th><th>Country</th><th>Message</th></tr></thead><tbody>` +
      eS.rows.map(x => `<tr><td class="num">${esc(x.seq)}</td><td title="Original: ${esc(x.raw_ts)}${x.year_source ? ', year: ' + esc(x.year_source) : ''}">${esc(x.ts || x.raw_ts)}</td><td class="kind">${esc(KIND[x.kind] || x.kind)}</td><td>${x.user ? uRef(x.user.toLowerCase(), x.user) : '–'}</td><td>${ipRef(x.outside_ip)}</td><td>${insideRef(x.inside_ip)}</td><td>${esc(x.country && x.country !== 'Unknown' ? x.country : '–')}</td><td class="msg">${esc(x.raw)}</td></tr>`).join('') +
      '</tbody></table>' + (eS.more ? `<button class="more" data-more-list="e">Show more</button>` : '') : '<p class="empty">No events match these filters.</p>';
  } catch(e){}
}
function openEvents(f){
  ['user','ip','inside','kind','q','seqs'].forEach(k => $('#e-' + k).value = f[k] || '');
  eS.exact = !!f.exact; closeDrawer(); show('events'); window.scrollTo({top: $('nav.tabs').offsetTop - 4});
}
function openSessions(f){
  ['user','ip','inside','minup'].forEach(k => $('#s-' + k).value = f[k] || '');
  sS.exact = !!f.exact; closeDrawer(); show('sessions'); window.scrollTo({top: $('nav.tabs').offsetTop - 4});
}

/* ---------- connections map ---------- */
const G = {view: null, nodes: [], links: []};
function layout(nodes, links, W, H){
  const n = nodes.length; if(!n) return;
  const k = Math.sqrt(W * H / n) * 0.75, cx = W / 2, cy = H / 2;
  nodes.forEach((d, i) => { const a = i * 2.39996, r = Math.sqrt((i + 0.5) / n) * Math.min(W, H) * 0.45; d.x = cx + r * Math.cos(a); d.y = cy + r * Math.sin(a); });
  let temp = W / 8; const it = n > 250 ? 220 : 320; const dx = new Float64Array(n), dy = new Float64Array(n);
  for(let t = 0; t < it; t++){
    dx.fill(0); dy.fill(0);
    for(let i = 0; i < n; i++){ const a = nodes[i]; for(let j = i + 1; j < n; j++){ const b = nodes[j]; let x = a.x - b.x, y = a.y - b.y; let d2 = x*x + y*y; if(d2 < 0.01){ x = Math.random() - .5; y = Math.random() - .5; d2 = 0.5; } const f = k * k / d2; dx[i] += x * f; dy[i] += y * f; dx[j] -= x * f; dy[j] -= y * f; } }
    for(const l of links){ const a = nodes[l.a], b = nodes[l.b]; const x = a.x - b.x, y = a.y - b.y; const d = Math.sqrt(x*x + y*y) || 0.01; const f = d / k; dx[l.a] -= x * f; dy[l.a] -= y * f; dx[l.b] += x * f; dy[l.b] += y * f; }
    for(let i = 0; i < n; i++){ const a = nodes[i]; dx[i] += (cx - a.x) * 0.03; dy[i] += (cy - a.y) * 0.03; const d = Math.sqrt(dx[i]*dx[i] + dy[i]*dy[i]) || 1; const m = Math.min(d, temp); a.x += dx[i] / d * m; a.y += dy[i] / d * m; }
    temp = Math.max(temp * 0.985, 0.5);
  }
  let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9; for(const d of nodes){ x0 = Math.min(x0, d.x); y0 = Math.min(y0, d.y); x1 = Math.max(x1, d.x); y1 = Math.max(y1, d.y); }
  const aw = W - 170, ah = H - 50, sc = Math.min(aw / Math.max(x1 - x0, 1), ah / Math.max(y1 - y0, 1));
  const ox = 30 + (aw - (x1 - x0) * sc) / 2, oy = 25 + (ah - (y1 - y0) * sc) / 2;
  for(const d of nodes){ d.x = ox + (d.x - x0) * sc; d.y = oy + (d.y - y0) * sc; }
}
async function drawGraph(){
  const t = tick('g'); const svg = $('#graph');
  $('#g-note').textContent = 'Loading…';
  let gd; try { gd = await api('/api/graph', {scope: $('#g-scope').value, q: $('#g-q').value.trim(), fails: $('#g-fails').checked ? 1 : 0, hosts: $('#g-hosts').checked ? 1 : 0}); } catch(e){ return; }
  if(t !== TK.g) return;
  const flow = $('#g-mode').value === 'flow';
  $('#gflow').hidden = !flow; svg.closest('.gwrap').hidden = flow;
  if(flow){
    flowGraph($('#gflow'), gd, {cap: 90});
    $('#g-note').textContent = gd.nodes.length ? `${fmtN(gd.nodes.filter(n => n.type === 'i').length)} source IPs, ${fmtN(gd.nodes.filter(n => n.type === 'u').length)} accounts and ${fmtN(gd.nodes.filter(n => n.type === 'h').length)} internal hosts. Hover a node to follow its path; click to open details. Red lines join attack sources and compromised accounts; dashed lines are failed logins only; dotted lines are internal traffic.` : '';
    return;
  }
  const W = svg.clientWidth || 800, H = svg.clientHeight || 600;
  G.nodes = gd.nodes; G.links = gd.links;
  if(!gd.nodes.length){ svg.innerHTML = ''; $('#g-note').textContent = gd.q ? 'Nothing matches that account or IP.' : 'No accounts or IPs with findings. Switch the scope to see the busiest accounts.'; return; }
  layout(gd.nodes, gd.links, W, H);
  let mxB = 1; gd.links.forEach(l => mxB = Math.max(mxB, l.up + l.down));
  let mxU = 1; gd.nodes.forEach(n => { if(n.type === 'u') mxU = Math.max(mxU, n.total); });
  const showAll = gd.nodes.length <= 70;
  let s = '<g>';
  let mxI = 1; gd.links.forEach(l => { if(l.kind === 'int') mxI = Math.max(mxI, l.down); });
  for(const l of gd.links){ const a = gd.nodes[l.a], b = gd.nodes[l.b]; const intl = l.kind === 'int'; const failOnly = !intl && !l.sess;
    const w = intl ? 0.8 + Math.sqrt(l.down / mxI) * 4 : failOnly ? 1.2 : 1 + Math.sqrt((l.up + l.down) / mxB) * 6;
    const tt = intl ? `<b>${esc(a.n)}</b> reached <span class="ip">${esc(b.ip)}</span><br>${fmtN(l.conns)} connections, ${fmtB(l.down)}${l.blocked ? '<br>' + fmtN(l.blocked) + ' blocked' : ''}`
      : `<b>${esc(a.n)}</b> and <span class="ip">${esc(b.ip)}</span><br>${fmtN(l.sess)} sessions, ${fmtD(l.secs)} connected<br>Uploaded ${fmtB(l.up)}, downloaded ${fmtB(l.down)}${l.fails ? '<br>' + fmtN(l.fails) + ' failed logins' : ''}`;
    s += `<line class="gl ${failOnly ? 'fail' : ''}${intl ? ' int' : ''}${intl && l.blocked > l.conns / 2 ? ' fail' : ''}" data-a="${l.a}" data-b="${l.b}" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke-width="${w.toFixed(2)}" data-tip="${esc(tt)}"/>`; }
  gd.nodes.forEach((n, i) => {
    let shape, label, tt, fill, lab;
    if(n.type === 'u'){ const r = 5 + Math.sqrt(n.total / mxU) * 12;
      fill = n.status === 'compromise' ? 'var(--crit)' : n.status === 'targeted' || n.status === 'review' ? 'var(--high)' : n.status === 'watch' ? 'var(--med)' : 'var(--sess)';
      shape = `<circle r="${r.toFixed(1)}" fill="${fill}"/>`; label = n.n; n.r = r; lab = showAll || n.status !== 'normal';
      tt = `<b>${esc(n.n)}</b><br>${STATUS[n.status]}<br>Uploaded ${fmtB(n.up)}, downloaded ${fmtB(n.down)}<br>Connected ${fmtD(n.secs)}`;
    } else if(n.type === 'h'){
      shape = `<rect x="-6" y="-6" width="12" height="12" rx="2" fill="var(--surface)" stroke="${n.role ? 'var(--high)' : 'var(--up)'}" stroke-width="2.5"/>`; label = n.ip; n.r = 8; lab = showAll || !!n.role;
      tt = `<b class="ip">${esc(n.ip)}</b> internal host<br>${fmtN(n.users)} VPN accounts, ${fmtB(n.total)} in total${n.role ? '<br>Involved in incidents' : ''}`;
    } else { fill = n.role === 'attacker' || n.role === 'compromise' ? 'var(--crit)' : n.role === 'shared' ? 'var(--med)' : 'var(--rule2)';
      shape = `<rect x="-6" y="-6" width="12" height="12" transform="rotate(45)" fill="${fill}"/>`; label = n.ip; n.r = 8; lab = showAll || !!n.role;
      tt = `<b class="ip">${esc(n.ip)}</b>${n.country ? ' ' + esc(n.country) : ''}<br>${n.role ? ROLE[n.role] + '<br>' : ''}${fmtN(n.users)} accounts connected, ${fmtN(n.attacked)} attacked`; }
    s += `<g class="gn" data-n="${i}" transform="translate(${n.x.toFixed(1)},${n.y.toFixed(1)})" data-tip="${esc(tt)}">${shape}${lab ? `<text x="${(n.r + 4).toFixed(1)}" y="4" ${n.type === 'i' ? 'class="ip"' : ''}>${esc(label)}</text>` : ''}</g>`;
  });
  svg.innerHTML = s + '</g>'; setView({x:0, y:0, w:W, h:H});
  $('#g-note').textContent = `${fmtN(gd.nodes.filter(n => n.type === 'u').length)} accounts, ${fmtN(gd.nodes.filter(n => n.type === 'i').length)} source IPs and ${fmtN(gd.nodes.filter(n => n.type === 'h').length)} internal hosts shown (up to 10 busiest internal hosts per account).` + (gd.capped ? ' Limited to the riskiest and busiest; type an account or IP to trace it.' : '') + ' Tap a node to highlight its links and open details.';
}
function setView(v){ G.view = v; $('#graph').setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`); }
function zoom(f, cx, cy){ const v = G.view; if(!v) return; if(cx == null){ cx = v.x + v.w / 2; cy = v.y + v.h / 2; } setView({x: cx - (cx - v.x) * f, y: cy - (cy - v.y) * f, w: v.w * f, h: v.h * f}); }
function selectNode(i){
  const svg = $('#graph'); const nb = new Set(i == null ? [] : [i]); G.links.forEach(l => { if(l.a === i) nb.add(l.b); if(l.b === i) nb.add(l.a); });
  svg.querySelectorAll('.gn').forEach(g => { const k = +g.dataset.n; g.classList.toggle('dim', i != null && !nb.has(k)); g.classList.toggle('sel', k === i); });
  svg.querySelectorAll('.gl').forEach(l => l.classList.toggle('dim', i != null && +l.dataset.a !== i && +l.dataset.b !== i));
}
function initGraph(){
  const svg = $('#graph'); let drag = null;
  svg.addEventListener('pointerdown', e => { drag = {x:e.clientX, y:e.clientY, v:Object.assign({}, G.view), moved:false}; svg.setPointerCapture(e.pointerId); });
  svg.addEventListener('pointermove', e => { if(!drag || !G.view) return; const dx = e.clientX - drag.x, dy = e.clientY - drag.y; if(Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true; if(!drag.moved) return; const sc = drag.v.w / svg.clientWidth; setView({x: drag.v.x - dx * sc, y: drag.v.y - dy * sc, w: drag.v.w, h: drag.v.h}); hideTip(); });
  svg.addEventListener('pointerup', e => { const d = drag; drag = null; if(!d || d.moved) return;
    const el = document.elementFromPoint(e.clientX, e.clientY); const g = el && el.closest('.gn');
    if(g){ const i = +g.dataset.n; selectNode(i); const n = G.nodes[i]; if(n.type === 'u') openUser(n.key); else if(n.type === 'h') openHost(n.ip); else openIp(n.ip); } else selectNode(null); });
  svg.addEventListener('wheel', e => { if(!G.view) return; e.preventDefault(); const r = svg.getBoundingClientRect(); const cx = G.view.x + (e.clientX - r.left) / r.width * G.view.w, cy = G.view.y + (e.clientY - r.top) / r.height * G.view.h; zoom(e.deltaY > 0 ? 1.15 : 1 / 1.15, cx, cy); }, {passive:false});
  $('#g-in').onclick = () => zoom(1 / 1.3); $('#g-out').onclick = () => zoom(1.3); $('#g-fit').onclick = () => { const s = $('#graph'); setView({x:0, y:0, w:s.clientWidth, h:s.clientHeight}); };
  ['g-mode','g-scope','g-fails','g-hosts'].forEach(id => $('#'+id).addEventListener('change', drawGraph));
  $('#g-q').addEventListener('input', debounce(drawGraph, 350));
}
function traceOnMap(q){ closeDrawer(); $('#g-q').value = q; show('links'); window.scrollTo({top: $('nav.tabs').offsetTop - 4}); }


/* ---------- cases ---------- */
const cS = {rows: [], total: 0};
function caseCard(c){
  const ents = [];
  if(c.users.length) ents.push(`<span><b>Accounts</b> ${c.users.map(u => uRef(u.k, u.n)).join(', ')}</span>`);
  if(c.ips.length) ents.push(`<span><b>IPs</b> ${c.ips.slice(0, 8).map(ipRef).join(', ')}${c.ips.length > 8 ? ' ...' : ''}</span>`);
  if(c.hosts.length) ents.push(`<span><b>Internal hosts</b> ${c.hosts.slice(0, 8).map(hostRef).join(', ')}${c.hosts.length > 8 ? ` and ${c.hosts.length - 8} more` : ''}</span>`);
  let day = '';
  const tl = c.incidents.map(x => { const d = x.start.slice(0,10); const hdr = d !== day ? `<li class="day">${niceDate(d)}</li>` : ''; day = d;
    return hdr + `<li class="c-incident ${x.sev}"><span class="tm">${x.start.slice(11,16)}</span><span class="tt">${esc(x.title)}</span> <span class="badge c-${x.sev}">${SEV[x.sev]}</span><span class="dt">${esc(x.detail)}${x.seqs.length ? ` <button class="ref" data-seqs="${x.seqs.join(',')}">raw events</button>` : ''}</span></li>`; }).join('');
  return `<article class="case ${c.sev}"><div class="inc-h"><span class="badge c-${c.sev}">${SEV[c.sev]}</span><span class="rv ${c.review}">${RSTAT[c.review] || c.review}</span><span class="note" style="margin:0">Case ${c.id}, ${c.n} linked incidents, ${short(c.start)} to ${short(c.end)}</span></div>
    <h3>${esc(c.who)}</h3><div class="chain">${esc(c.title)}</div>${c.summary ? `<p style="margin:6px 0">${esc(c.summary)}</p>` : ''}
    <div class="row-actions" style="margin:6px 0"><button class="btn" data-case="${c.id}">Review case with evidence</button></div><div class="ents">${ents.join('')}</div>
    <details ${c.sev === 'critical' ? 'open' : ''}><summary class="note" style="cursor:pointer">Timeline of this case</summary><ul class="tl" style="margin-top:8px">${tl}</ul></details></article>`;
}
async function loadCases(append){
  const t = tick('c');
  if(!append) $('#c-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/cases', {q: $('#c-q').value.trim(), sev: $('#c-sev').value, review: $('#c-review').value, limit: 30, offset: append ? cS.rows.length : 0});
    if(t !== TK.c) return;
    cS.rows = append ? cS.rows.concat(r.rows) : r.rows; cS.total = r.total;
    $('#c-count').innerHTML = r.missing ? 'This database was analysed with an older version. Re-run the analysis (--reanalyze) to build cases.' : `${fmtN(cS.total)} case${cS.total === 1 ? '' : 's'}` + (r.index ? ` &middot; <a href="${r.index}" target="_blank" rel="noopener">Saved case reports</a>` : '');
    $('#c-list').innerHTML = cS.rows.length ? cS.rows.map(caseCard).join('') + (cS.total > cS.rows.length ? `<button class="more" data-more-list="c">Show more</button>` : '') : '<p class="empty">No linked incidents in the selected time.</p>';
  } catch(e){}
}

/* ---------- internal hosts ---------- */
const hS = {rows: [], total: 0};
async function loadHosts(append){
  const t = tick('h');
  if(!append) $('#h-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/hosts', {q: $('#h-q').value.trim(), sort: $('#h-sort').value, role: $('#h-role').value, limit: 200, offset: append ? hS.rows.length : 0});
    if(t !== TK.h) return;
    hS.rows = append ? hS.rows.concat(r.rows) : r.rows; hS.total = r.total;
    $('#h-count').textContent = r.missing ? 'No connection data: the log has no 302013/302014 messages, or the database needs --reanalyze.' : `${fmtN(hS.total)} internal hosts`;
    $('#h-list').innerHTML = hS.rows.length ? `<table><thead><tr><th>Host</th><th>Services used</th><th class="num">VPN accounts</th><th class="num">Connections</th><th class="num">Blocked</th><th class="num">Data</th><th>Last seen</th><th></th></tr></thead><tbody>` +
      hS.rows.map(h => `<tr class="click" data-host="${esc(h.ip)}"><td class="ip">${esc(h.ip)}</td><td>${portChips(h.ports.slice(0, 5).map(p => p[0].split('/')[0]))}</td><td class="num">${fmtN(h.users)}</td><td class="num">${fmtN(h.conns)}</td><td class="num" ${h.blocked ? 'style="color:var(--crit)"' : ''}>${fmtN(h.blocked)}</td><td class="num">${fmtB(h.bytes)}</td><td>${short(h.last)}</td><td>${h.role ? `<span class="badge c-high">${WROLE[h.role] || h.role}</span>` : ''}</td></tr>`).join('') +
      '</tbody></table>' + (hS.total > hS.rows.length ? `<button class="more" data-more-list="h">Show more</button>` : '') : '<p class="empty">No internal hosts in the selected time.</p>';
  } catch(e){}
}

/* ---------- firewall admin ---------- */
const aS = {rows: [], more: false};
async function loadAdmin(append){
  const t = tick('a');
  if(!append) $('#a-list').innerHTML = '<p class="loading">Loading…</p>';
  const k = $('#a-kind').value;
  try {
    const r = await api('/api/events', {kinds: k || 'MGMT_LOGIN_OK,MGMT_LOGIN_FAIL,CONFIG_CMD,PRIV_CHANGE', user: $('#a-user').value.trim(), q: $('#a-q').value.trim(), sort: $('#a-sort').value, limit: 200, offset: append ? aS.rows.length : 0});
    if(t !== TK.a) return;
    aS.rows = append ? aS.rows.concat(r.rows) : r.rows; aS.more = r.has_more;
    $('#a-count').textContent = `${fmtN(aS.rows.length)}${aS.more ? '+' : ''} firewall management event${aS.rows.length === 1 ? '' : 's'}`;
    $('#a-list').innerHTML = aS.rows.length ? `<table><thead><tr><th>Time</th><th>What</th><th>Admin account</th><th>From</th><th>Detail / command</th></tr></thead><tbody>` +
      aS.rows.map(x => { const d = x.reason || ''; const cls = x.kind === 'CONFIG_CMD' ? (RE_ANTI.test(d) ? 'cmd-anti' : RE_SENS.test(d) ? 'cmd-sens' : '') : (x.kind === 'MGMT_LOGIN_FAIL' ? 'cmd-sens' : '');
        return `<tr class="${cls}"><td>${esc(x.ts)}</td><td class="kind">${esc(KIND[x.kind] || x.kind)}</td><td>${x.user ? uRef(x.user.toLowerCase(), x.user) : '–'}</td><td>${ipRef(x.outside_ip)}</td><td class="msg">${esc(d)}</td></tr>`; }).join('') +
      '</tbody></table>' + (aS.more ? `<button class="more" data-more-list="a">Show more</button>` : '') : '<p class="empty">No firewall management events. The log may not contain 605004/605005, 611101/611102, 111008/111010 or 502103 messages.</p>';
  } catch(e){}
}

/* ---------- timeline (account / IP / host story) ---------- */
function tlItem(x){
  const refs = [];
  if(x.u && x.cat !== 'incident') refs.push(uRef(x.u, x.n || x.u));
  if(x.ip && x.cat !== 'incident') refs.push(ipRef(x.ip));
  if(x.hosts) refs.push(x.hosts.map(hostRef).join(', ') + (x.more ? ` and ${x.more} more` : ''));
  const ports = x.ports && x.ports.length ? ' ' + portChips(x.ports) : '';
  const badge = x.sev ? ` <span class="badge c-${x.sev}">${SEV[x.sev]}</span>` : '';
  const ev = x.seqs && x.seqs.length ? ` <button class="ref" data-seqs="${x.seqs.join(',')}">raw events</button>` : '';
  return `<li class="c-${x.cat} ${x.sev || ''}"><span class="tm">${esc((x.t || '').slice(11,16))}</span><span class="tt">${esc(x.title)}</span>${badge} ${refs.join(' ')}${ports}${x.detail ? `<span class="dt">${esc(x.detail)}${ev}</span>` : ev}</li>`;
}
async function loadTimeline(el, p){
  el.innerHTML = '<p class="loading">Loading timeline…</p>';
  try {
    const r = await api('/api/timeline', p);
    if(!r.items.length){ el.innerHTML = '<p class="empty">Nothing in the selected time.</p>'; return; }
    let day = '', h = '';
    for(const x of r.items){ const d = (x.t || '').slice(0,10); if(d !== day){ h += `<li class="day">${niceDate(d)}</li>`; day = d; } h += tlItem(x); }
    el.innerHTML = `<ul class="tl">${h}</ul>` + (r.truncated ? '<p class="note">Showing the first 1,500 entries; narrow the time range to see the rest.</p>' : '');
  } catch(e){ el.innerHTML = `<p class="empty">${esc(e.message)}</p>`; }
}
const tlSection = (id) => `<div class="sec"><h2>Timeline</h2><p class="note">Logins, failures, internal access, firewall changes and incidents in one chronological story.</p><div id="${id}"><button class="btn" data-load-tl>Show timeline</button></div></div>`;

/* ---------- internal host drawer ---------- */
async function openHost(ip){
  drawerOpen = () => openHost(ip);
  const t = tick('dr'); openDrawer(); $('#drawer').innerHTML = '<p class="loading">Loading host…</p>';
  let d; try { d = await api('/api/host', {ip}); } catch(e){ $('#drawer').innerHTML = `<div class="dh"><h2 class="ip">${esc(ip)}</h2><button class="close" data-close>Close</button></div><p class="empty">${esc(e.message)}</p>`; return; }
  if(t !== TK.dr) return;
  const h = d.host;
  const lanes = new Map(Object.entries(d.names).map(([k, v]) => [k, {label: v.n, attr: `data-u="${esc(k)}"`, flag: v.status === 'compromise'}]));
  const items = [], fails = [];
  for(const r of d.gantt){ const lab = (d.names[r[0]] || {}).n || r[0];
    if(r[5]) fails.push({lane: r[0], t: r[1], tip: `Blocked ${svcName(r[6])}`});
    else items.push({lane: r[0], s: r[1], e: r[2], tip: `<b>${esc(lab)}</b><br>${short(r[1])}, ${esc(svcName(r[6]))}<br>${fmtD(r[3])}, ${fmtB(r[4])}`}); }
  DS.rows = []; DS.total = 0; DS.filter = null;
  TL.params = {host: ip};
  drawerRender = () => {
    const dr = $('#drawer'); const st = dr.scrollTop;
    dr.innerHTML = `<div class="dh"><div><h2 class="ip">${esc(ip)}</h2><p class="note">Internal host ${h.role ? `<span class="badge c-high">${WROLE[h.role] || h.role}</span>` : ''}</p></div><button class="close" data-close>Close</button></div>` +
      `<div class="row-actions"><button class="btn" data-act="map" data-q="${esc(ip)}">Trace on map</button><button class="btn" data-inv-add="h:${esc(ip)}">Investigate</button></div>` + rangeBanner() +
      `<div class="facts">${fact(fmtN(h.users), 'VPN accounts')}${fact(fmtN(h.conns), 'Connections')}${fact(fmtN(h.blocked), 'Blocked attempts', h.blocked ? 'bad' : '')}${fact(fmtB(h.bytes), 'Data')}${fact(fmtD(h.secs), 'Connection time')}${fact(short(h.first), 'First seen')}${fact(short(h.last), 'Last seen')}</div>` +
      (d.incidents.length ? `<div class="sec"><h2>Findings <span class="count">${d.incidents.length}</span></h2>${d.incidents.map(incRow).join('')}</div>` : '') +
      `<div class="sec"><h2>Services used</h2><div class="tw"><table><thead><tr><th>Service</th><th class="num">Connections</th><th class="num">Accounts</th><th class="num">Blocked</th><th class="num">Data</th></tr></thead><tbody>` +
      d.ports.map(p => `<tr><td>${portChips([p.port])} <span class="note">${esc(p.proto)}</span></td><td class="num">${fmtN(p.conns)}</td><td class="num">${fmtN(p.users)}</td><td class="num">${fmtN(p.blocked)}</td><td class="num">${fmtB(p.bytes)}</td></tr>`).join('') + '</tbody></table></div></div>' +
      `<div class="sec"><h2>Who used it</h2><p class="note">Each bar is one connection; red marks suspected compromised accounts, ticks are blocked attempts.</p><div class="chart" id="d-gantt"></div></div>` +
      `<div class="sec"><h2>VPN accounts <span class="count">${fmtN(d.accounts.length)}</span></h2><div class="tw"><table><thead><tr><th>Account</th><th>Status</th><th>Services</th><th class="num">Connections</th><th class="num">Blocked</th><th class="num">Data</th><th>Last</th></tr></thead><tbody>` +
      d.accounts.map(a => `<tr class="click" data-u="${esc(a.k)}"><td>${esc(a.n)}</td><td><span class="badge c-${a.status}">${STATUS[a.status] || a.status}</span></td><td>${portChips(a.ports.slice(0, 5))}</td><td class="num">${fmtN(a.conns)}</td><td class="num">${fmtN(a.blocked)}</td><td class="num">${fmtB(a.bytes)}</td><td>${short(a.last)}</td></tr>`).join('') + '</tbody></table></div></div>' +
      tlSection('d-tl');
    gantt($('#d-gantt'), items, fails, lanes); restoreTimeline();
    dr.scrollTop = st;
  };
  $('#drawer').scrollTop = 0; drawerRender(); const c = $('#drawer .close'); c && c.focus({preventScroll:true});
}
const TL = {params: null, shown: false};
function restoreTimeline(){ const el = $('#d-tl'); if(el && TL.shown) loadTimeline(el, TL.params); }


/* ---------- login assessments ---------- */
const lS = {rows: [], total: 0};
const scoreBar = x => `<span class="lscore c-${x.verdict}" title="Confidence ${x.score}/100"><i style="width:${x.score}%"></i></span><b class="c-${x.verdict}">${x.score}</b>`;
function loginRow(x, hide){
  const reasons = x.reasons.map(r => `<li><span class="${r[0] > 0 ? 'pos' : 'neg'}">${r[0] > 0 ? '+' : ''}${r[0]}</span> ${esc(r[1])}</li>`).join('');
  return `<div class="lrow2"><div class="lhead">${scoreBar(x)} <span class="badge c-${x.verdict}">${VERDICT[x.verdict]}</span>
      <span>${hide !== 'u' ? uRef(x.k, x.n) : ''} ${hide !== 'ip' ? 'from ' + ipRef(x.ip) : ''}${x.country ? ' <span class="note">' + esc(x.country) + '</span>' : ''}</span>
      <span class="note" style="margin:0">${short(x.ts)}</span></div>
    <div class="note" style="margin:2px 0 0">${!x.ip_fails && !x.other_fails && !x.user_fails ? 'No failed logins before this one; judged on how unusual the login and session were.' : `Before the login: ${fmtN(x.ip_fails)} failure${x.ip_fails === 1 ? '' : 's'} from this IP against ${fmtN(x.ip_accounts)} account${x.ip_accounts === 1 ? '' : 's'} (${fmtN(x.user_fails)} for this account)${x.other_fails ? `, ${fmtN(x.other_fails)} for this account from other IPs` : ''}${x.gap ? `; last failure ${fmtD(x.gap)} before` : ''}.`}</div>
    <details><summary class="note" style="cursor:pointer">Why this score</summary><ul class="reasons">${reasons}</ul>
      <div class="row-actions">${x.seqs.length ? `<button class="btn" data-seqs="${x.seqs.join(',')}">Raw events</button>` : ''}<button class="btn" data-act="map" data-q="${esc(x.ip)}">Trace on map</button></div></details></div>`;
}
async function loadLogins(append){
  const t = tick('l');
  if(!append) $('#l-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/logins', {q: $('#l-q').value.trim(), verdict: $('#l-verdict').value, sort: $('#l-sort').value, limit: 100, offset: append ? lS.rows.length : 0});
    if(t !== TK.l) return;
    lS.rows = append ? lS.rows.concat(r.rows) : r.rows; lS.total = r.total;
    const c = r.counts || {};
    $('#l-count').innerHTML = r.missing ? 'Re-run the analysis (--reanalyze) to assess logins.' :
      `${fmtN(lS.total)} shown &middot; <span class="c-compromised">${fmtN(c.compromised || 0)} compromised</span>, <span class="c-likely">${fmtN(c.likely || 0)} likely</span>, <span class="c-review">${fmtN(c.review || 0)} to review</span>, ${fmtN(c.benign || 0)} probably the user`;
    $('#l-list').innerHTML = lS.rows.length ? lS.rows.map(x => loginRow(x)).join('') + (lS.total > lS.rows.length ? `<button class="more" data-more-list="l">Show more</button>` : '') : '<p class="empty">No logins after failures in the selected time.</p>';
  } catch(e){}
}

/* ---------- incidents over time (stacked by severity) ---------- */
const SEVC = {critical:'var(--crit)', high:'var(--high)', medium:'var(--med)', low:'var(--low)'};
let TREND = [];
async function drawIncTrend(){
  const el = $('#inctrend'); if(!el) return;
  const unit = dailyCache ? dailyCache.unit : 'day';
  let r; try { r = await api('/api/inctrend', {unit}); } catch(e){ return; }
  const rows = fillBuckets(r.rows, unit, dailyCache && dailyCache.start, dailyCache && dailyCache.end);
  TREND = rows;
  $('#inctrend-h').textContent = unit === 'hour' ? 'Incidents per hour' : 'Incidents per day';
  if(!rows.length || !rows.some(d => (d.critical||0)+(d.high||0)+(d.medium||0)+(d.low||0))){ el.innerHTML = '<p class="empty">No incidents in the selected time.</p>'; return; }
  const W = Math.max(320, el.clientWidth || 900), H = 140, pb = 20, n = rows.length, bw = W / n;
  let mx = 1; rows.forEach(d => mx = Math.max(mx, (d.critical||0)+(d.high||0)+(d.medium||0)+(d.low||0)));
  let s = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" class="trend" role="img" aria-label="Incidents over time">`;
  rows.forEach((d, i) => {
    let y = H - pb; const x = i * bw;
    const tot = (d.critical||0)+(d.high||0)+(d.medium||0)+(d.low||0);
    for(const k of ['low','medium','high','critical']){ const v = d[k] || 0; if(!v) continue; const h = v / mx * (H - pb - 8); y -= h;
      s += `<rect x="${(x + bw * .12).toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(1, bw * .76).toFixed(1)}" height="${h.toFixed(1)}" fill="${SEVC[k]}"/>`; }
    if(tot) s += `<rect class="hit" data-trend="${i}" x="${x.toFixed(1)}" y="0" width="${bw.toFixed(1)}" height="${H - pb}" fill="transparent" data-tip="${esc(`<b>${esc(bucketLabel(d))}</b><br>${d.critical||0} critical, ${d.high||0} high, ${d.medium||0} medium, ${d.low||0} low<br><span class='note'>Click to zoom in</span>`)}"/>`;
  });
  const every = Math.max(1, Math.ceil(n / 10));
  rows.forEach((d, i) => { if(i % every === 0) s += `<text x="${(i * bw + 2).toFixed(1)}" y="${H - 5}" class="ax">${esc(d.d.length > 10 ? d.d.slice(11,13) + ':00' : niceDate(d.d).replace(/ \d{4}$/, ''))}</text>`; });
  el.innerHTML = s + '</svg>';
}

/* ---------- weekday x hour heatmap ---------- */
let HEAT = null;
const DOWS = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
async function drawHeat(){ try { HEAT = await api('/api/heatmap'); renderHeat(); } catch(e){} }
function renderHeat(){
  const el = $('#heat'); if(!el || !HEAT) return;
  const m = $('#heat-m').value, data = HEAT[m] || [];
  const g = Array.from({length: 7}, () => Array(24).fill(null));
  let mx = 0; for(const [dow, h, v, x] of data){ const r = (dow + 6) % 7; g[r][h] = [v, x]; mx = Math.max(mx, v); }
  const col = m === 'fails' ? 'var(--crit)' : m === 'down' ? 'var(--down)' : 'var(--low)';
  const fmt = v => m === 'down' ? fmtB(v) : fmtN(v);
  const what = {sessions: 'sessions started', fails: 'failed logins', down: 'downloaded'}[m];
  let h = '<div class="heat"><span></span>' + Array.from({length: 24}, (_, i) => `<span class="hh">${i % 3 ? '' : String(i).padStart(2, '0')}</span>`).join('');
  g.forEach((row, r) => { h += `<span class="hd">${DOWS[r]}</span>` + row.map((c, hr) => { const v = c ? c[0] : 0; const pct = mx ? Math.round(Math.sqrt(v / mx) * 85) : 0;
    const extra = c ? (m === 'fails' ? `, from ${fmtN(c[1])} IPs` : `, ${fmtN(c[1])} accounts`) : '';
    return `<span class="hc" data-hh="${hr}" style="background:${v ? `color-mix(in srgb, ${col} ${pct + 8}%, transparent)` : 'var(--rule)'}" data-tip="${esc(`<b>${DOWS[r]} ${String(hr).padStart(2,'0')}:00-${String((hr + 1) % 24).padStart(2,'0')}:00</b><br>${fmt(v)} ${what}${extra}<br><span class='note'>Click to show only this hour of the day</span>`)}"></span>`; }).join(''); });
  el.innerHTML = h + '</div>' + (mx ? '' : '<p class="empty">Nothing in the selected time.</p>');
}

/* ---------- investigation matrix ---------- */
let MX = null;
const mxRef = r => r.kind === 'u' ? `<button class="ref" data-u="${esc(r.key)}">${esc(r.label)}</button>` : r.kind === 'i' ? ipRef(r.key) : hostRef(r.key);
const mxSub = r => r.kind === 'u' ? (r.sub ? `<span class="badge c-${r.sub}">${STATUS[r.sub] || r.sub}</span>` : '') : r.kind === 'i' ? `${r.country ? '<span class="note">' + esc(r.country) + '</span> ' : ''}${r.sub ? `<span class="badge c-${r.sub}">${ROLE[r.sub] || r.sub}</span>` : ''}` : '<span class="note">internal host</span>';
const KINDICON = {u: '<i class="mk u"></i>', i: '<i class="mk i"></i>', h: '<i class="mk h"></i>'};
async function loadMatrix(){
  const t = tick('mx'); const mode = $('#m-mode').value;
  $('#m-kinds').hidden = mode !== 'attack';
  $('#m-grid').innerHTML = '<p class="loading">Loading…</p>'; $('#m-detail').innerHTML = '';
  const kinds = ['u','i','h'].filter(k => $('#m-k' + k).checked).join(',');
  try { MX = await api('/api/matrix', {mode, q: $('#m-q').value.trim(), limit: $('#m-lim').value, kinds}); } catch(e){ return; }
  if(t !== TK.mx) return;
  if(!MX.rows.length){ $('#m-grid').innerHTML = '<p class="empty">Nothing to show in the selected time.</p>'; return; }
  if(MX.mode === 'attack'){
    const cols = MX.columns.filter(c => MX.rows.some(r => r.cells[c.id]));
    $('#m-note').textContent = `${fmtN(MX.rows.length)} of ${fmtN(MX.total)} accounts, IPs and hosts with findings, worst first. Columns follow the attack stages of MITRE ATT&CK; click a cell to see the findings.`;
    $('#m-grid').innerHTML = `<div class="tw mxw"><table class="mxt no-enh"><thead><tr><th class="ent">Account / IP / host</th>${cols.map(c => `<th title="${esc(c.ref)}">${esc(c.name)}${c.ref ? `<span class="ref-id">${c.ref}</span>` : ''}</th>`).join('')}<th class="num">Risk</th></tr></thead><tbody>` +
      MX.rows.map((r, ri) => `<tr><td class="ent">${KINDICON[r.kind]}${mxRef(r)} ${mxSub(r)}</td>` + cols.map(c => { const x = r.cells[c.id];
        return x ? `<td class="mx s-${x.sev}" data-mx="${ri}|${c.id}" data-tip="${esc(`<b>${esc(r.label)}</b>: ${esc(c.name)}<br>${x.n} finding${x.n === 1 ? '' : 's'}, worst ${SEV[x.sev]}`)}">${x.n}</td>` : '<td class="mx"></td>'; }).join('') + `<td class="num">${fmtN(r.risk)}</td></tr>`).join('') + '</tbody></table></div>';
  } else {
    $('#m-note').textContent = `Which accounts connected (number) or failed to log in (red mark) from which source IPs. Rows: accounts with findings, worst first. Columns: their source IPs, attack sources first.`;
    let mxs = 1; MX.rows.forEach(r => Object.values(r.cells).forEach(v => mxs = Math.max(mxs, v.sessions)));
    $('#m-grid').innerHTML = `<div class="tw mxw"><table class="mxt acc no-enh"><thead><tr><th class="ent">Account</th>${MX.columns.map(c => `<th class="vert ${c.role ? 'c-' + c.role : ''}" title="${esc(c.name + (c.country ? ' ' + c.country : '') + (c.role ? ', ' + (ROLE[c.role] || c.role) : ''))}"><span>${esc(c.name)}</span></th>`).join('')}</tr></thead><tbody>` +
      MX.rows.map((r, ri) => `<tr><td class="ent">${mxRef(r)} ${mxSub(r)}</td>` + MX.columns.map(c => { const v = r.cells[c.id]; if(!v) return '<td class="mx"></td>';
        const pct = v.sessions ? Math.round(Math.sqrt(v.sessions / mxs) * 70) + 10 : 0;
        return `<td class="mx acc${v.fails ? ' hasf' : ''}" data-mx="${ri}|${esc(c.id)}" style="${pct ? `background:color-mix(in srgb, var(--down) ${pct}%, transparent)` : ''}" data-tip="${esc(`<b>${esc(r.label)}</b> from <span class='ip'>${esc(c.name)}</span><br>${fmtN(v.sessions)} sessions, ${fmtN(v.fails)} failed logins`)}">${v.sessions || ''}${v.fails ? `<i class="fdot" style="--f:${Math.min(1, .35 + v.fails / 40)}"></i>` : ''}</td>`; }).join('') + '</tr>').join('') + '</tbody></table></div>';
  }
}
function matrixDetail(ri, col){
  const r = MX.rows[ri]; const el = $('#m-detail');
  if(MX.mode === 'attack'){ const x = r.cells[col], c = MX.columns.find(c => c.id === col);
    el.innerHTML = `<div class="sec"><h2>${esc(r.label)}: ${esc(c.name)} <span class="count">${x.n}</span></h2><ul class="tl">` +
      x.items.map(i => `<li class="c-incident ${i[2]}"><span class="tm">${esc(short(i[3]))}</span><span class="tt">${esc(i[1])}</span> <span class="badge c-${i[2]}">${SEV[i[2]]}</span> <span class="note">${esc(TYPE[i[4]] || i[4])}</span></li>`).join('') +
      `</ul>${x.n > x.items.length ? `<p class="note">${x.n - x.items.length} more in the Incidents tab.</p>` : ''}<div class="row-actions"><button class="btn" data-mx-open="${ri}">Open ${r.kind === 'u' ? 'account' : r.kind === 'i' ? 'IP' : 'host'} details</button><button class="btn" data-mx-inc="${esc(r.kind === 'u' ? r.label : r.key)}">Show in Incidents</button></div></div>`;
  } else { const v = r.cells[col]; const c = MX.columns.find(c => c.id === col);
    el.innerHTML = `<div class="sec"><h2>${esc(r.label)} from <span class="ip">${esc(c.name)}</span></h2><p>${fmtN(v.sessions)} VPN sessions and ${fmtN(v.fails)} failed logins${c.country ? ' &middot; ' + esc(c.country) : ''}${c.role ? ' &middot; ' + esc(ROLE[c.role] || c.role) : ''}.</p>
      <div class="row-actions"><button class="btn" data-u="${esc(r.key)}">Open account</button><button class="btn" data-ip="${esc(c.id)}">Open IP</button><button class="btn" data-act="sessions" data-user="${esc(r.key)}">Sessions of this account</button></div></div>`; }
  el.scrollIntoView({block: 'nearest', behavior: 'smooth'});
}

/* ---------- attack flow: source IPs -> accounts -> internal hosts ---------- */
function flowGraph(el, gd, opt){
  opt = opt || {};
  const N = gd.nodes, L = gd.links.filter(l => N[l.a] && N[l.b]);
  if(!N.length){ el.innerHTML = '<p class="empty">Nothing to draw.</p>'; return; }
  const cols = {i: [], u: [], h: []};
  N.forEach((n, i) => { if(cols[n.type]) cols[n.type].push(i); });
  const adj = N.map(() => []); L.forEach((l, k) => { adj[l.a].push(k); adj[l.b].push(k); });
  const stR = {compromise: 0, review: 1, targeted: 2, watch: 3, normal: 4};
  cols.u.sort((a, b) => (stR[N[a].status] ?? 5) - (stR[N[b].status] ?? 5) || (N[b].risk || 0) - (N[a].risk || 0) || (N[b].total || 0) - (N[a].total || 0));
  const cap = opt.cap || 70, hidden = {};
  for(const t of ['u','i','h']){ if(cols[t].length > cap){ hidden[t] = cols[t].length - cap; cols[t] = cols[t].slice(0, cap); } }
  const keep = new Set([...cols.i, ...cols.u, ...cols.h]);
  const pos = {}; cols.u.forEach((i, k) => pos[i] = k);
  const bary = i => { let s = 0, c = 0; for(const k of adj[i]){ const l = L[k]; const o = l.a === i ? l.b : l.a; if(pos[o] != null){ s += pos[o]; c++; } } return c ? s / c : 1e9; };
  cols.i.sort((a, b) => bary(a) - bary(b)); cols.h.sort((a, b) => bary(a) - bary(b));
  const present = ['i','u','h'].filter(t => cols[t].length);
  const W = Math.max(640, el.clientWidth || 900), rowH = 24, top = 40;
  const maxLen = Math.max(...present.map(t => cols[t].length));
  const H = top + maxLen * rowH + 14;
  const X = present.length === 3 ? {i: 240, u: W / 2 - 20, h: W - 200} : present.length === 2 ? {[present[0]]: 210, [present[1]]: W - 260} : {[present[0]]: W / 2};
  const P = {};
  for(const t of present){ const off = (maxLen - cols[t].length) * rowH / 2; cols[t].forEach((i, k) => P[i] = [X[t], top + off + k * rowH + rowH / 2]); }
  let mxD = 1, mxI = 1; L.forEach(l => { if(l.kind === 'int') mxI = Math.max(mxI, l.down || 0); else mxD = Math.max(mxD, (l.up || 0) + (l.down || 0)); });
  const bad = n => n && (n.status === 'compromise' || n.role === 'attacker' || n.role === 'compromise');
  let s = `<svg class="flow" viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Attack flow">`;
  const HD = {i: 'Source IPs', u: 'Accounts', h: 'Internal hosts'};
  for(const t of present) s += `<text class="fhd" x="${X[t]}" y="16" text-anchor="middle">${HD[t]}${hidden[t] ? ` (+${hidden[t]} not shown)` : ''}</text>`;
  L.forEach((l, k) => { if(!keep.has(l.a) || !keep.has(l.b)) return;
    const [x1, y1] = P[l.a], [x2, y2] = P[l.b]; const left = x1 < x2 ? [x1, y1, x2, y2] : [x2, y2, x1, y1];
    const mx = (left[0] + left[2]) / 2; const intl = l.kind === 'int'; const failOnly = !intl && !l.sess;
    const crit = intl ? l.blocked > (l.conns || 0) / 2 : (bad(N[l.a]) && bad(N[l.b]));
    const w = intl ? 0.8 + Math.sqrt((l.down || 0) / mxI) * 2.4 : failOnly ? 1.3 : 1.2 + Math.sqrt(((l.up || 0) + (l.down || 0)) / mxD) * 5;
    const a = N[l.a].type === 'u' ? N[l.a] : N[l.b], o = N[l.a].type === 'u' ? N[l.b] : N[l.a];
    const tt = intl ? `<b>${esc(a.n)}</b> reached <span class='ip'>${esc(o.ip)}</span><br>${fmtN(l.conns)} connections, ${fmtB(l.down)}${l.blocked ? '<br>' + fmtN(l.blocked) + ' blocked' : ''}`
      : `<span class='ip'>${esc(o.ip)}</span> &rarr; <b>${esc(a.n)}</b><br>${fmtN(l.sess)} sessions${l.fails ? ', ' + fmtN(l.fails) + ' failed logins' : ''}${l.sess ? '<br>Downloaded ' + fmtB(l.down) : ''}`;
    s += `<path class="fe ${intl ? 'int' : failOnly ? 'fail' : 'ok'}${crit ? ' crit' : ''}" data-k="${k}" d="M${left[0]},${left[1]} C${mx},${left[1]} ${mx},${left[3]} ${left[2]},${left[3]}" stroke-width="${w.toFixed(1)}" data-tip="${esc(tt)}"/>`; });
  for(const i of keep){ const n = N[i], [x, y] = P[i]; let shape, label, attr, tt, anchor = 'start', lx = 12;
    if(n.type === 'u'){ const f = n.status === 'compromise' ? 'var(--crit)' : n.status === 'review' || n.status === 'targeted' ? 'var(--high)' : n.status === 'watch' ? 'var(--med)' : 'var(--sess)';
      shape = `<circle r="7" fill="${f}"/>`; label = n.n; attr = `data-u="${esc(n.key)}"`;
      if(present.length === 3){ anchor = 'middle'; lx = 0; } tt = `<b>${esc(n.n)}</b><br>${esc(STATUS[n.status] || n.status || '')}`; }
    else if(n.type === 'i'){ const f = n.role === 'attacker' || n.role === 'compromise' ? 'var(--crit)' : n.role === 'review' ? 'var(--high)' : 'var(--rule2)';
      shape = `<rect x="-6" y="-6" width="12" height="12" transform="rotate(45)" fill="${f}"/>`; label = n.ip + (n.country ? ' ' + n.country : ''); attr = `data-ip="${esc(n.ip)}"`;
      anchor = present.length > 1 && present[0] === 'i' ? 'end' : 'start'; lx = anchor === 'end' ? -12 : 12;
      tt = `<b class='ip'>${esc(n.ip)}</b> ${esc(n.country || '')}<br>${esc(ROLE[n.role] || 'Source IP')}${n.tried ? `<br>tried ${fmtN(n.tried)} accounts` : ''}`; }
    else { shape = `<rect x="-6" y="-6" width="12" height="12" rx="2" fill="var(--surface)" stroke="${n.role ? 'var(--high)' : 'var(--up)'}" stroke-width="2.5"/>`; label = n.ip; attr = `data-host="${esc(n.ip)}"`; tt = `<b class='ip'>${esc(n.ip)}</b> internal host${n.role ? '<br>Involved in incidents' : ''}`; }
    s += `<g class="fn" data-n="${i}" ${attr} transform="translate(${x.toFixed(1)},${y.toFixed(1)})" data-tip="${esc(tt)}">${shape}<text x="${lx}" y="${anchor === 'middle' ? -10 : 4}" text-anchor="${anchor}">${esc(label)}</text></g>`; }
  el.innerHTML = s + '</svg>';
  const svg = el.querySelector('svg');
  const focus = i => {   // follow the path through the account in the middle
    const on = new Set([i]), eOn = new Set();
    const step = (from, wantType) => { for(const k of adj[from]){ const l = L[k]; const o = l.a === from ? l.b : l.a; if(!keep.has(o) || (wantType && N[o].type !== wantType)) continue; eOn.add(k); on.add(o); } };
    if(N[i].type === 'u') step(i);
    else { step(i, 'u'); for(const u of [...on]) if(N[u].type === 'u') step(u, N[i].type === 'i' ? 'h' : 'i'); }
    svg.classList.add('focus');
    svg.querySelectorAll('.fn').forEach(g => g.classList.toggle('on', on.has(+g.dataset.n)));
    svg.querySelectorAll('.fe').forEach(p => p.classList.toggle('on', eOn.has(+p.dataset.k)));
  };
  svg.addEventListener('pointerover', e => { const g = e.target.closest('.fn'); if(g) focus(+g.dataset.n); });
  svg.addEventListener('pointerleave', () => svg.classList.remove('focus'));
}

/* ---------- tables: click a header to sort, download as CSV ---------- */
function cellVal(t){
  t = (t || '').replace(/\s+/g, ' ').trim();
  if(!t || t === '–' || t === '-') return null;
  let m = t.match(/^([\d.,]+)\s*(B|KB|MB|GB|TB|PB)\b/);
  if(m) return parseFloat(m[1].replace(/,/g, '')) * Math.pow(1024, ['B','KB','MB','GB','TB','PB'].indexOf(m[2]));
  if(/^\d+\s*(d|h|m)\b/.test(t) && /^[\d\sdhm]+$/.test(t)){ let v = 0; t.replace(/(\d+)\s*(d|h|m)/g, (_, n, u) => { v += +n * {d: 86400, h: 3600, m: 60}[u]; }); return v; }
  if(/^\d{4}-\d\d-\d\d/.test(t)) return t;
  m = t.match(/^-?[\d,]+(\.\d+)?(?=\s|$|\/|%)/); if(m) return parseFloat(m[0].replace(/,/g, ''));
  return t.toLowerCase();
}
function enhanceTable(t){
  if(t.dataset.enh || t.classList.contains('no-enh') || t.closest('.no-enh') || !t.tHead || !t.tBodies[0]) return;
  t.dataset.enh = '1';
  const n = t.tBodies[0].rows.length; if(n < 2) return;
  Array.from(t.tHead.rows[0].cells).forEach((th, ci) => { if(!th.textContent.trim()) return; th.classList.add('sorth'); th.dataset.ci = ci; th.tabIndex = 0; th.title = 'Click to sort'; });
  if(n >= 3 && t.parentNode){ const tl = document.createElement('div'); tl.className = 'ttools no-print'; tl.innerHTML = `<button class="tbtn" data-tcsv title="Download this table as CSV">CSV</button>`; t.parentNode.insertBefore(tl, t); }
  if(n > 25 && t.parentNode && t.parentNode.classList.contains('tw')) t.parentNode.classList.add('tall');
}
function sortTable(th){
  const t = th.closest('table'), ci = +th.dataset.ci, tb = t.tBodies[0];
  const rows = Array.from(tb.rows), vals = rows.map(r => cellVal(r.cells[ci] ? r.cells[ci].innerText : ''));
  const numeric = vals.filter(v => typeof v === 'number').length >= vals.filter(v => v != null).length / 2;
  const cur = th.getAttribute('aria-sort'); const asc = cur ? cur === 'descending' : !numeric;
  t.tHead.querySelectorAll('th[aria-sort]').forEach(x => x.removeAttribute('aria-sort'));
  th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');
  const cmp = (a, b) => (typeof a === typeof b ? (a < b ? -1 : a > b ? 1 : 0) : typeof a === 'number' ? -1 : 1);
  rows.map((r, i) => i).sort((a, b) => { const x = vals[a], y = vals[b]; if(x == null || y == null) return (x == null) - (y == null); return cmp(x, y) * (asc ? 1 : -1) || a - b; })
    .forEach(i => tb.appendChild(rows[i]));
}
function tableCSV(t){ return Array.from(t.rows).map(r => Array.from(r.cells).map(c => '"' + c.innerText.replace(/\s+/g, ' ').trim().replace(/"/g, '""') + '"').join(',')).join('\r\n'); }
function downloadText(name, text){ const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['\ufeff' + text], {type: 'text/csv;charset=utf-8'})); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500); }
new MutationObserver(ms => { for(const m of ms) for(const nd of m.addedNodes){ if(nd.nodeType !== 1) continue; if(nd.tagName === 'TABLE') enhanceTable(nd); else if(nd.querySelectorAll) nd.querySelectorAll('table').forEach(enhanceTable); } })
  .observe(document.body, {childList: true, subtree: true});
document.addEventListener('click', e => {
  const th = e.target.closest('th.sorth'); if(th){ sortTable(th); return; }
  const cv = e.target.closest('[data-tcsv]'); if(cv){ const t = cv.parentNode.nextElementSibling; const sec = cv.closest('.sec, section, .drawer');
    const h = sec && (sec.tagName === 'SECTION' ? $('nav.tabs [aria-selected="true"]') || sec.querySelector('h2') : sec.querySelector('h2')); downloadText(((h ? h.textContent : 'table').replace(/[^\w]+/g, '_').replace(/^_|_$/g, '').toLowerCase() || 'table') + '.csv', tableCSV(t)); return; }
  const tr = e.target.closest('[data-trend]'); if(tr){ pickBucket(TREND[+tr.dataset.trend]); return; }
  const hc = e.target.closest('[data-hh]'); if(hc){ const h = +hc.dataset.hh, p2 = n => String(n).padStart(2, '0'); setRange({from: RANGE.from, to: RANGE.to, h1: `${p2(h)}:00`, h2: `${p2(h)}:59`}, $('#r-preset').value); return; }
  const mx = e.target.closest('[data-mx]'); if(mx){ const [ri, col] = mx.dataset.mx.split('|'); $$('.mxt td.sel').forEach(x => x.classList.remove('sel')); mx.classList.add('sel'); matrixDetail(+ri, col); return; }
  const mo = e.target.closest('[data-mx-open]'); if(mo){ const r = MX.rows[+mo.dataset.mxOpen]; if(r.kind === 'u') openUser(r.key); else if(r.kind === 'i') openIp(r.key); else openHost(r.key); return; }
  const mi = e.target.closest('[data-mx-inc]'); if(mi){ $('#inc-q').value = mi.dataset.mxInc; show('incidents'); window.scrollTo({top: $('nav.tabs').offsetTop - 4}); return; }
});
document.addEventListener('keydown', e => { if((e.key === 'Enter' || e.key === ' ') && e.target.matches && e.target.matches('th.sorth')){ e.preventDefault(); sortTable(e.target); } });

/* ---------- global search ---------- */
const GS = {items: [], sel: -1};
const gsIcon = {u: '<i class="mk u"></i>', i: '<i class="mk i"></i>', h: '<i class="mk h"></i>', case: '<i class="mk c"></i>', camp: '<i class="mk k"></i>'};
const gsType = {u: 'Account', i: 'Source IP', h: 'Internal host', case: 'Case', camp: 'IP cluster'};
const gsLabel = r => r.type === 'u' ? (STATUS[r.status] || '') : r.type === 'i' ? [r.country, ROLE[r.status]].filter(Boolean).join(', ') : r.type === 'case' || r.type === 'camp' ? SEV[r.status] || '' : (r.status ? 'Involved in incidents' : '');
const runSearch = debounce(async () => {
  const q = $('#gs').value.trim(); const box = $('#gs-res');
  if(q.length < 2){ box.hidden = true; return; }
  let r; try { r = await api('/api/search', {q}, true); } catch(e){ return; }
  if($('#gs').value.trim() !== q) return;
  GS.items = r.results; GS.sel = r.results.length ? 0 : -1;
  box.innerHTML = r.results.length ? r.results.map((x, i) => `<button class="gsr ${i === 0 ? 'on' : ''}" data-gs="${i}">${gsIcon[x.type]}<span class="gsl">${esc(x.label)}</span><span class="gst ${x.type === 'u' || x.type === 'i' ? 'c-' + x.status : 'c-' + x.status}">${esc(gsLabel(x))}</span><span class="gss">${esc(gsType[x.type])} &middot; ${esc(x.sub || '')}</span></button>`).join('')
    : '<p class="note" style="padding:8px 12px;margin:0">No account, IP, host or case matches.</p>';
  box.hidden = false;
}, 180);
function gsOpen(i){ const x = GS.items[i]; if(!x) return; $('#gs-res').hidden = true; $('#gs').blur();
  if(x.type === 'u') openUser(x.k); else if(x.type === 'i') openIp(x.k); else if(x.type === 'h') openHost(x.k);
  else if(x.type === 'case') openCase(x.k); else { show('camps'); $('#k-q').value = ''; loadCamps().then(() => { const el = $(`#camp-${x.k}`); if(el) el.scrollIntoView({block: 'start'}); }); } }
$('#gs').addEventListener('input', runSearch);
$('#gs').addEventListener('keydown', e => {
  const n = GS.items.length; if(!n) return;
  if(e.key === 'ArrowDown' || e.key === 'ArrowUp'){ e.preventDefault(); GS.sel = (GS.sel + (e.key === 'ArrowDown' ? 1 : n - 1)) % n; $$('#gs-res .gsr').forEach((b, i) => b.classList.toggle('on', i === GS.sel)); }
  else if(e.key === 'Enter'){ e.preventDefault(); gsOpen(Math.max(0, GS.sel)); }
  else if(e.key === 'Escape'){ $('#gs-res').hidden = true; }
});
document.addEventListener('keydown', e => { if(e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)){ e.preventDefault(); $('#gs').focus(); $('#gs').select(); } });
document.addEventListener('click', e => { const b = e.target.closest('[data-gs]'); if(b){ gsOpen(+b.dataset.gs); return; } if(!e.target.closest('.gsearch')) $('#gs-res').hidden = true; });

/* ---------- hunt: compromised and suspicious accounts ---------- */
const hu = {rows: []};
function huntCard(x){
  const L = x.login;
  const how = L ? `Got in from ${ipRef(L.ip)}${L.country ? ' <span class="note">' + esc(L.country) + '</span>' : ''} on ${esc(short(L.ts))}` +
      ` after ${fmtN(L.ip_fails + L.other_fails)} failed login${L.ip_fails + L.other_fails === 1 ? '' : 's'}` + (L.ip_accounts > 1 ? ` (that IP tried ${fmtN(L.ip_accounts)} accounts)` : '')
    : x.bad_ips.length ? `Connected from flagged IP${x.bad_ips.length > 1 ? 's' : ''} ${x.bad_ips.map(b => ipRef(b.ip)).join(', ')}` : '';
  const top = L ? L.reasons.filter(r => r[0] > 0).slice(0, 3).map(r => esc(r[1])).join('; ') : '';
  return `<article class="hcard st-b-${x.status}">
    <div class="hc-l"><div class="hc-name"><i class="dot st-${x.status}"></i><button class="ref big" data-u="${esc(x.k)}">${esc(x.n)}</button> <span class="badge c-${x.status}">${STATUS[x.status] || x.status}</span></div>
      ${L ? `<div class="hc-score">${scoreBar(L)} <span class="c-${L.verdict}">${VERDICT[L.verdict]}</span></div>` : ''}</div>
    <div class="hc-m">${how ? `<div class="hc-how">${how}</div>` : ''}${top ? `<div class="note" style="margin:2px 0 4px">${top}</div>` : ''}
      <div class="chips">${x.chips.map(c => `<span class="chip s-${c.sev}" data-tip="${esc(esc(c.tip))}">${esc(c.t)}</span>`).join('')}
      ${x.campaigns.map(c => `<button class="chip s-critical" data-camp="${c.id}" title="Open IP cluster">IP cluster #${c.id} (${c.n_ips} IPs)</button>`).join('')}
      ${x.hosts ? `<span class="chip">${fmtN(x.hosts)} internal hosts</span>` : ''}</div>
      ${x.linked && x.linked.length ? `<div class="note" style="margin:6px 0 0">Linked accounts: ${x.linked.map(l => `<button class="ref" data-u="${esc(l.k)}" data-tip="${esc(esc(l.why.join('; ')))}">${esc(l.n)}</button>`).join(', ')}</div>` : ''}</div>
    <div class="hc-r">${x.cases.slice(0, 2).map(id => `<button class="btn" data-case="${id}">Review case ${id}</button>`).join('')}
      <button class="btn" data-act="map" data-q="${esc(x.k)}">Map</button><button class="btn" data-inv-add="u:${esc(x.k)}">Investigate</button><span class="note" style="margin:0">Last seen ${short(x.last)}</span></div></article>`;
}
async function loadHunt(){
  const t = tick('hu'); $('#hu-list').innerHTML = '<p class="loading">Loading…</p>';
  try {
    const r = await api('/api/hunt', {status: $('#hu-status').value, q: $('#hu-q').value.trim(), sort: $('#hu-sort').value});
    if(t !== TK.hu) return;
    hu.rows = r.rows; const c = r.counts || {};
    $('#hu-sum').innerHTML = `<div class="hsum"><button class="hs crit" data-hs="compromise"><b>${fmtN(c.compromise || 0)}</b><span>compromised accounts</span></button>
      <button class="hs warn" data-hs="review"><b>${fmtN(c.review || 0)}</b><span>accounts to review</span></button>
      <button class="hs" data-go="camps"><b>${fmtN(r.campaigns || 0)}</b><span>IP clusters (IPs working together)</span></button></div>`;
    $('#hu-list').innerHTML = r.rows.length ? r.rows.map(huntCard).join('') : '<p class="empty">No compromised or suspicious accounts in the selected time.</p>';
  } catch(e){}
}

/* ---------- IP clusters (campaigns) ---------- */
async function loadCamps(){
  const t = tick('k'); $('#k-list').innerHTML = '<p class="loading">Loading…</p>';
  let r; try { r = await api('/api/campaigns', {q: $('#k-q').value.trim(), limit: 50}); } catch(e){ return; }
  if(t !== TK.k) return;
  $('#k-count').textContent = r.missing ? 'Re-run the analysis (--reanalyze) to find IP clusters.' : `${fmtN(r.total)} IP cluster${r.total === 1 ? '' : 's'}`;
  if(!r.rows.length){ $('#k-list').innerHTML = '<p class="empty">No groups of linked attacking IPs in the selected time.</p>'; return; }
  $('#k-list').innerHTML = r.rows.map(x => `<article class="case ${x.sev}" id="camp-${x.id}">
      <div class="inc-h"><span class="badge c-${x.sev}">${SEV[x.sev]}</span><span class="note" style="margin:0">IP cluster #${x.id} &middot; ${short(x.first)} to ${short(x.last)} &middot; ${fmtN(x.fails)} failed logins against ${fmtN(x.n_targets)} accounts</span></div>
      <h3>${esc(x.title)}</h3>
      ${x.success.length ? `<p><b class="c-critical">Broken into:</b> ${x.success.map(u => uRef(u.k, u.n)).join(', ')}</p>` : ''}
      <div class="ents"><span><b>IPs</b> ${x.ips.map(i => `${ipRef(i.ip)}${i.country ? '<span class="note"> ' + esc(i.country) + '</span>' : ''}`).join(', ')}</span></div>
      <div class="chips" style="margin-bottom:8px">${Object.entries(x.kinds).map(([k, v]) => `<span class="chip">${esc(k)} &times;${v}</span>`).join('')}</div>
      <div class="tw" data-campgraph="${x.id}"></div>
      <details ${x.ips.length <= 8 ? 'open' : ''}><summary class="note" style="cursor:pointer">Which accounts each IP touched (${x.ips.length <= 3 ? 'Venn diagram' : 'UpSet chart'})</summary><div data-campvenn="${esc(x.ips.slice(0, 8).map(i => i.ip).join(','))}"></div></details>
      <details><summary class="note" style="cursor:pointer">Why these IPs are linked (${x.relations.length})</summary><div class="tw"><table><thead><tr><th>IP</th><th>IP</th><th class="num">Strength</th><th>Evidence</th></tr></thead><tbody>` +
      x.relations.map(l => `<tr><td>${ipRef(l.a)}</td><td>${ipRef(l.b)}</td><td class="num">${l.w}</td><td>${l.why.map(esc).join('<br>')}</td></tr>`).join('') + `</tbody></table></div></details></article>`).join('');
  r.rows.forEach(x => { const el = $(`[data-campgraph="${x.id}"]`); if(el && x.graph.nodes.length) flowGraph(el, x.graph, {cap: 40}); });
  $$('#k-list [data-campvenn]').forEach(el => vennLoad(el, el.dataset.campvenn.split(','), 'ip'));
}
document.addEventListener('click', e => {
  const k = e.target.closest('[data-camp]'); if(k){ const id = +k.dataset.camp; if(!$('#drawer').hidden) closeDrawer(); show('camps'); window.scrollTo({top: $('nav.tabs').offsetTop - 4}); loadCamps().then(() => { const el = $(`#camp-${id}`); if(el) el.scrollIntoView({block: 'start', behavior: 'smooth'}); }); return; }
  const hs = e.target.closest('[data-hs]'); if(hs){ $('#hu-status').value = hs.dataset.hs; loadHunt(); }
});
async function renderOvCamps(){
  const el = $('#ov-camps'); if(!el) return;
  let r; try { r = await api('/api/campaigns', {limit: 6}); } catch(e){ return; }
  el.closest('.sec').hidden = !r.rows.length;
  el.innerHTML = r.rows.map(x => `<button class="aitem" data-camp="${x.id}"><i class="dot st-compromise" style="border-radius:2px"></i><span>${esc(x.title)}</span><span class="why">${x.ips.slice(0, 4).map(i => esc(i.ip)).join(', ')}${x.ips.length > 4 ? ' ...' : ''}${x.success.length ? ' &middot; <b>in: ' + x.success.map(u => esc(u.n)).join(', ') + '</b>' : ''}</span></button>`).join('');
}

/* ---------- Venn (2-3 sets) / UpSet (4+ sets): which accounts each IP touched, and when ---------- */
const VCOL = ['var(--low)', 'var(--high)', 'var(--up)', 'var(--down)', 'var(--med)', 'var(--crit)', 'var(--sess)', 'var(--focus)'];
function lensArea(r1, r2, d){
  if(d >= r1 + r2) return 0;
  if(d <= Math.abs(r1 - r2)) return Math.PI * Math.min(r1, r2) ** 2;
  const a = r1 * r1 * Math.acos((d * d + r1 * r1 - r2 * r2) / (2 * d * r1)), b = r2 * r2 * Math.acos((d * d + r2 * r2 - r1 * r1) / (2 * d * r2));
  return a + b - 0.5 * Math.sqrt((-d + r1 + r2) * (d + r1 - r2) * (d - r1 + r2) * (d + r1 + r2));
}
function distFor(r1, r2, area){        // circle distance giving the wanted overlap area
  if(area <= 0) return r1 + r2 + 14;
  let lo = Math.abs(r1 - r2), hi = r1 + r2;
  if(area >= Math.PI * Math.min(r1, r2) ** 2 - 1e-6) return lo;
  for(let i = 0; i < 50; i++){ const m = (lo + hi) / 2; if(lensArea(r1, r2, m) > area) lo = m; else hi = m; }
  return (lo + hi) / 2;
}
const vSetName = (V, m) => { const ix = V.sets.map((_, i) => i).filter(i => m & (1 << i)); const nm = i => V.sets[i].label;
  if(ix.length === 1) return V.sets.length === 1 ? nm(ix[0]) : `Only ${nm(ix[0])}`;
  return ix.length === V.sets.length && ix.length > 2 ? `All ${ix.length}: ${ix.map(nm).join(' + ')}` : ix.map(nm).join(' + ') + (ix.length < V.sets.length ? ' only' : ''); };
async function vennLoad(el, items, mode, opt){
  el.innerHTML = '<p class="loading">Loading…</p>';
  let d; try { d = await api('/api/venn', {items: items.join(','), mode: mode || 'ip'}); } catch(e){ el.innerHTML = `<p class="empty">${esc(e.message)}</p>`; return; }
  vennRender(el, d, opt || {});
}
function vennRender(el, d, opt){
  const sets = d.sets.filter(s => s.items.length);
  if(sets.length < 2){ el.innerHTML = `<p class="empty">${sets.length ? 'Only one of these has any activity in the selected time.' : 'No activity for these in the selected time.'}</p>`; return; }
  const byKey = new Map();
  sets.forEach((s, i) => s.items.forEach(it => { let e = byKey.get(it.k); if(!e){ e = {k: it.k, n: it.n, status: it.status, country: it.country, mask: 0, per: {}}; byKey.set(it.k, e); } e.mask |= 1 << i; e.per[i] = it; }));
  const masks = new Map(); for(const e of byKey.values()){ if(!masks.has(e.mask)) masks.set(e.mask, []); masks.get(e.mask).push(e); }
  const V = {d, sets, byKey, masks, mode: d.mode, sel: null};
  el._venn = V;
  const what = d.mode === 'ip' ? 'accounts' : 'IPs';
  el.innerHTML = `<div class="venn-wrap"><div class="venn-svg"></div><div class="venn-side"></div></div>
    <div class="venn-time"></div><div class="venn-list"></div>`;
  (sets.length <= 3 ? drawVenn : drawUpset)(el, V);
  // legend / sizes
  el.querySelector('.venn-side').innerHTML = sets.map((s, i) => { const nIn = s.items.filter(x => x.sess).length;
    return `<div class="vleg"><i style="background:${VCOL[i]}"></i><div><b>${d.mode === 'ip' ? ipRef(s.k) : uRef(s.k, s.label)}</b> ${s.sub ? `<span class="note">${esc(s.sub)}</span>` : ''}${s.role ? ` <span class="badge c-${s.role}">${esc((d.mode === 'ip' ? ROLE : STATUS)[s.role] || s.role)}</span>` : ''}
      <div class="note" style="margin:0">${fmtN(s.items.length)} ${what}${d.mode === 'ip' ? `, logged in as ${fmtN(nIn)}` : `, logged in from ${fmtN(nIn)}`} &middot; ${short(s.first)} to ${short(s.last)}</div></div></div>`; }).join('') +
    `<p class="note">${d.mode === 'ip' ? 'Overlaps = accounts tried or used by several of these IPs.' : 'Overlaps = IPs used by several of these accounts.'} Click a region to list them.</p>`;
  vennTimeline(el, V);
  const best = [...masks.entries()].filter(([m]) => (m & (m - 1))).sort((a, b) => b[1].length - a[1].length)[0];
  vennSelect(el, best ? best[0] : [...masks.keys()][0]);
}
function drawVenn(el, V){
  const n = V.sets.length, W = 520, H = n === 2 ? 270 : 330, mx = Math.max(...V.sets.map(s => s.items.length));
  const R = n === 2 ? 105 : 95, r = V.sets.map(s => R * Math.sqrt(s.items.length / mx) + 18);
  const inter = (i, j) => [...V.byKey.values()].filter(e => (e.mask >> i & 1) && (e.mask >> j & 1)).length;
  const dist = (i, j) => distFor(r[i], r[j], Math.PI * Math.min(r[i], r[j]) ** 2 * inter(i, j) / Math.min(V.sets[i].items.length, V.sets[j].items.length) * .92);
  let P;
  if(n === 2){ const dd = dist(0, 1); P = [[0, 0], [dd, 0]]; }
  else { const a = dist(0, 1), b = dist(0, 2), c = dist(1, 2); const x = (b * b - c * c + a * a) / (2 * a); P = [[0, 0], [a, 0], [x, Math.sqrt(Math.max(0, b * b - x * x)) || Math.min(b, c) * .8]]; }
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  P.forEach(([x, y], i) => { x0 = Math.min(x0, x - r[i]); x1 = Math.max(x1, x + r[i]); y0 = Math.min(y0, y - r[i]); y1 = Math.max(y1, y + r[i]); });
  const k = Math.min((W - 30) / (x1 - x0), (H - 30) / (y1 - y0), 1.4);
  const C = P.map(([x, y], i) => [W / 2 + (x - (x0 + x1) / 2) * k, H / 2 + (y - (y0 + y1) / 2) * k, r[i] * k]);
  V.circles = C;
  const inside = (x, y) => C.reduce((m, [cx, cy, cr], i) => ((x - cx) ** 2 + (y - cy) ** 2 <= cr * cr ? m | (1 << i) : m), 0);
  V.maskAt = inside;
  const acc = new Map();          // region label positions = centroid of the region's pixels
  for(let y = 4; y < H; y += 3) for(let x = 4; x < W; x += 3){ const m = inside(x, y); if(m){ const a = acc.get(m) || [0, 0, 0]; a[0] += x; a[1] += y; a[2]++; acc.set(m, a); } }
  let s = `<svg viewBox="0 0 ${W} ${H}" class="venn" role="img" aria-label="Venn diagram">`;
  C.forEach(([cx, cy, cr], i) => s += `<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="${cr.toFixed(1)}" fill="${VCOL[i]}" fill-opacity=".16" stroke="${VCOL[i]}" stroke-width="2"/>`);
  for(const [m, list] of V.masks){ const a = acc.get(m); let x, y;
    if(a){ x = a[0] / a[2]; y = a[1] / a[2]; } else { const i = Math.log2(m & -m); x = C[i][0]; y = C[i][1] + 14; }
    const nIn = list.filter(e => Object.values(e.per).some(p => p.sess)).length, bad = list.filter(e => e.status === 'compromise' || e.status === 'attacker').length;
    s += `<g class="vreg" data-mask="${m}" transform="translate(${x.toFixed(1)},${y.toFixed(1)})"><text class="vn" text-anchor="middle" y="5">${list.length}</text>${nIn ? `<text class="vs" text-anchor="middle" y="20">${nIn} logged in</text>` : ''}${bad ? `<circle cx="${String(list.length).length * 5 + 6}" cy="-4" r="4" fill="var(--crit)"/>` : ''}</g>`; }
  C.forEach(([cx, cy, cr], i) => { const ang = [-2.3, -0.8, 1.6][i] || -1.5; let lx = cx + Math.cos(ang) * (cr + 10); const ly = Math.min(H - 4, Math.max(12, cy + Math.sin(ang) * (cr + 10)));
    const lw_ = V.sets[i].label.length * 7.6; let anc = Math.cos(ang) < -0.2 ? 'end' : Math.cos(ang) > 0.2 ? 'start' : 'middle';
    if(anc === 'start' && lx + lw_ > W - 2){ anc = 'end'; lx = W - 2; } if(anc === 'end' && lx - lw_ < 2){ anc = 'start'; lx = 2; }
    s += `<text class="vlab" x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anc}" fill="${VCOL[i]}">${esc(V.sets[i].label)}</text>`; });
  const box = el.querySelector('.venn-svg'); box.innerHTML = s + '</svg>';
  const svg = box.querySelector('svg');
  const toLocal = e => { const b = svg.getBoundingClientRect(); return [(e.clientX - b.left) * W / b.width, (e.clientY - b.top) * H / b.height]; };
  svg.addEventListener('click', e => { const g = e.target.closest('.vreg'); const m = g ? +g.dataset.mask : inside(...toLocal(e)); if(m && V.masks.has(m)) vennSelect(el, m); });
  svg.addEventListener('pointermove', e => { const m = inside(...toLocal(e)); const l = V.masks.get(m);
    if(m && l) showTip(`<b>${esc(vSetName(V, m))}</b><br>${l.length} ${V.mode === 'ip' ? 'account' : 'IP'}${l.length === 1 ? '' : 's'}<br><span class='note'>Click to list</span>`, e.clientX, e.clientY); else hideTip(); });
  svg.addEventListener('pointerleave', hideTip);
}
function drawUpset(el, V){
  const n = V.sets.length, cols = [...V.masks.entries()].sort((a, b) => b[1].length - a[1].length || popc(b[0]) - popc(a[0])).slice(0, 18);
  const lw = Math.max(150, 20 + 7.8 * Math.max(...V.sets.map(st => (st.label + ` (${st.items.length})`).length))), cw = 30, top = 120, rh = 22, W = lw + cols.length * cw + 20, H = top + n * rh + 12, mx = Math.max(...cols.map(c => c[1].length));
  let s = `<svg viewBox="0 0 ${W} ${H}" class="venn upset" role="img" aria-label="UpSet chart" style="max-width:${W}px">`;
  V.sets.forEach((st, i) => { s += `<text class="vlab" x="${lw - 10}" y="${top + i * rh + rh / 2 + 4}" text-anchor="end" fill="${VCOL[i]}">${esc(st.label)} (${st.items.length})</text>`;
    if(i % 2 === 0) s += `<rect x="${lw}" y="${top + i * rh}" width="${cols.length * cw}" height="${rh}" fill="var(--rule)" opacity=".35"/>`; });
  cols.forEach(([m, list], j) => { const x = lw + j * cw + cw / 2, h = (list.length / mx) * (top - 30);
    const nIn = list.filter(e => Object.values(e.per).some(p => p.sess)).length;
    s += `<g class="vreg" data-mask="${m}"><rect class="ubar" x="${x - 9}" y="${top - 8 - h}" width="18" height="${h}" fill="${nIn ? 'var(--crit)' : 'var(--sess)'}" data-tip="${esc(`<b>${esc(vSetName(V, m))}</b><br>${list.length} ${V.mode === 'ip' ? 'accounts' : 'IPs'}${nIn ? `, ${nIn} logged in` : ''}`)}"/>
      <text class="vs" x="${x}" y="${top - 12 - h}" text-anchor="middle">${list.length}</text>`;
    const on = V.sets.map((_, i) => m >> i & 1).map((b, i) => b ? i : -1).filter(i => i >= 0);
    if(on.length > 1) s += `<line x1="${x}" x2="${x}" y1="${top + on[0] * rh + rh / 2}" y2="${top + on[on.length - 1] * rh + rh / 2}" stroke="var(--ink)" stroke-width="2"/>`;
    V.sets.forEach((_, i) => s += `<circle cx="${x}" cy="${top + i * rh + rh / 2}" r="5.5" fill="${m >> i & 1 ? 'var(--ink)' : 'var(--rule2)'}" opacity="${m >> i & 1 ? 1 : .45}"/>`);
    s += `<rect x="${x - cw / 2}" y="0" width="${cw}" height="${H}" fill="transparent"/></g>`; });
  const box = el.querySelector('.venn-svg'); box.innerHTML = s + '</svg>';
  box.querySelector('svg').addEventListener('click', e => { const g = e.target.closest('.vreg'); if(g) vennSelect(el, +g.dataset.mask); });
}
const popc = m => { let c = 0; while(m){ c += m & 1; m >>= 1; } return c; };
function vennSelect(el, m){
  const V = el._venn; if(!V || !V.masks.has(m)) return; V.sel = m;
  el.querySelectorAll('.vreg').forEach(g => g.classList.toggle('on', +g.dataset.mask === m));
  const list = V.masks.get(m).slice().sort((a, b) => (b.status === 'compromise') - (a.status === 'compromise') || sum(b, 'sess') - sum(a, 'sess') || sum(b, 'fails') - sum(a, 'fails'));
  const ix = V.sets.map((_, i) => i).filter(i => m & (1 << i));
  const rowsH = list.map(e => {
    const ref = V.mode === 'ip' ? `<button class="ref" data-u="${esc(e.k)}">${esc(e.n || e.k)}</button>${e.status && e.status !== 'normal' ? ` <span class="badge c-${e.status}">${STATUS[e.status] || e.status}</span>` : ''}`
      : `${ipRef(e.k)}${e.country ? ' <span class="note">' + esc(e.country) + '</span>' : ''}${e.status ? ` <span class="badge c-${e.status}">${ROLE[e.status] || e.status}</span>` : ''}`;
    const cells = ix.map(i => { const p = e.per[i]; return `<td>${p.sess ? `<b class="c-critical">logged in ${p.sess}&times;</b> <span class="note">${esc(short(p.sf))}</span>` : ''}${p.sess && p.fails ? '<br>' : ''}${p.fails ? `<span>${p.fails} failed</span> <span class="note">${esc(short(p.ff))}${p.fl && p.fl !== p.ff ? ' – ' + esc(short(p.fl).slice(-5)) : ''}</span>` : ''}</td>`; }).join('');
    return `<tr><td>${ref}</td>${cells}</tr>`; }).join('');
  el.querySelector('.venn-list').innerHTML = `<h3 class="vtitle">${esc(vSetName(V, m))} <span class="count">${list.length}</span></h3>
    <div class="tw"><table><thead><tr><th>${V.mode === 'ip' ? 'Account' : 'IP'}</th>${ix.map(i => `<th><i class="vdot" style="background:${VCOL[i]}"></i>${esc(V.sets[i].label)}</th>`).join('')}</tr></thead><tbody>${rowsH}</tbody></table></div>`;
}
const sum = (e, f) => Object.values(e.per).reduce((a, p) => a + (p[f] || 0), 0);
function vennTimeline(el, V){
  const ts = []; V.sets.forEach(s => s.items.forEach(it => [it.ff, it.fl, it.sf, it.sl].forEach(t => t && ts.push(T(t)))));
  if(!ts.length) return;
  let a = Math.min(...ts), b = Math.max(...ts); if(b - a < 3600e3){ a -= 1800e3; b += 1800e3; }
  const W = 760, lw = Math.max(150, 20 + 7.8 * Math.max(...V.sets.map(st => st.label.length))), rh = 22, H = 26 + V.sets.length * rh, X = t => lw + (T(t) - a) / (b - a) * (W - lw - 14);
  let s = `<svg viewBox="0 0 ${W} ${H}" class="venn vtl" role="img" aria-label="When each one was active">`;
  const fmtT = ms => { const d = new Date(ms).toISOString(); return (b - a) < 3 * 86400e3 ? d.slice(5, 16).replace('T', ' ') : d.slice(0, 10); };
  for(let i = 0; i <= 4; i++){ const ms = a + (b - a) * i / 4, x = lw + (W - lw - 14) * i / 4; s += `<line x1="${x}" x2="${x}" y1="14" y2="${H}" stroke="var(--rule)"/><text class="vs" x="${x}" y="10" text-anchor="${i === 4 ? 'end' : 'middle'}">${fmtT(ms)}</text>`; }
  V.sets.forEach((st, i) => { const y = 22 + i * rh + rh / 2;
    s += `<text class="vlab" x="${lw - 10}" y="${y + 4}" text-anchor="end" fill="${VCOL[i]}">${esc(st.label)}</text>`;
    st.items.forEach(it => { const who = esc(it.n || it.k);
      if(it.ff) s += `<line x1="${X(it.ff).toFixed(1)}" x2="${Math.max(X(it.fl || it.ff) , X(it.ff) + 2).toFixed(1)}" y1="${y}" y2="${y}" stroke="var(--crit)" stroke-width="6" stroke-opacity=".55" data-tip="${esc(`<b>${who}</b><br>${it.fails} failed: ${esc(short(it.ff))} to ${esc(short(it.fl))}`)}"/>`;
      if(it.sf) s += `<circle cx="${X(it.sf).toFixed(1)}" cy="${y}" r="5" fill="var(--down)" stroke="var(--surface)" data-tip="${esc(`<b>${who}</b><br>logged in ${it.sess}&times;, first ${esc(short(it.sf))}`)}"/>`; }); });
  el.querySelector('.venn-time').innerHTML = `<h3 class="vtitle">When</h3><p class="note" style="margin:0 0 4px">Red bars: failed logins (first to last). Teal dots: successful logins. Hover for details.</p>` + s + '</svg>';
}

function runCompare(){ const items = $('#vn-items').value.split(/[\s,;]+/).filter(Boolean); if(items.length < 2){ $('#vn-out').innerHTML = '<p class="empty">Enter at least two.</p>'; return; } vennLoad($('#vn-out'), items, $('#vn-mode').value); }
$('#vn-go').addEventListener('click', runCompare);
$('#vn-items').addEventListener('keydown', e => { if(e.key === 'Enter') runCompare(); });
document.addEventListener('click', e => { const b = e.target.closest('[data-vn-open]'); if(!b) return;
  closeDrawer(); show('camps'); $('#vn-mode').value = b.dataset.vnMode; $('#vn-items').value = b.dataset.vnOpen; runCompare();
  setTimeout(() => $('#vn-sec').scrollIntoView({block: 'start', behavior: 'smooth'}), 50); });
/* ---------- investigate: connections between chosen accounts and IPs ---------- */
const IV = {items: [], data: null, saved: []};
try { IV.items = JSON.parse(localStorage.getItem('asa-iv') || '[]').filter(x => typeof x === 'string'); } catch(e){}
const ivType = id => id[0];
const ivLabel = id => id.slice(2);
function ivUpdate(){
  try { localStorage.setItem('asa-iv', JSON.stringify(IV.items)); } catch(e){}
  $('#iv-chips').innerHTML = IV.items.length ? IV.items.map((id, i) => `<span class="ivchip">${gsIcon[ivType(id)]}<button class="ref" ${ivType(id) === 'u' ? `data-u="${esc(id.slice(2))}"` : ivType(id) === 'i' ? `data-ip="${esc(id.slice(2))}"` : `data-host="${esc(id.slice(2))}"`}>${esc(ivLabel(id))}</button><button class="x" data-iv-del="${i}" aria-label="Remove ${esc(ivLabel(id))}">&times;</button></span>`).join('')
    : '<span class="note">Add accounts or IPs: type below, or use the "Investigate" button in any account or IP panel.</span>';
  $('#t-inv').textContent = IV.items.length ? `Investigate (${IV.items.length})` : 'Investigate';
}
function ivAdd(id, quiet){
  id = (id || '').trim(); if(!id) return;
  if(!/^[uih]:/.test(id)) id = (/^[0-9a-f.:]+$/i.test(id) && /[.:]/.test(id) ? 'i:' : 'u:') + id;
  if(!IV.items.includes(id)) IV.items.push(id);
  ivUpdate(); if(!quiet) toast(`Added ${ivLabel(id)} to the investigation (${IV.items.length})`);
}
function toast(msg){ let t = $('#toast'); if(!t){ t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; t.setAttribute('role', 'status'); document.body.appendChild(t); }
  t.textContent = msg; t.classList.add('on'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('on'), 2200); }
// suggestions while typing
const ivSuggest = debounce(async () => {
  const q = $('#iv-in').value.trim(), box = $('#iv-sug'); if(q.length < 2 || /[,;\s]/.test(q)){ box.hidden = true; return; }
  let r; try { r = await api('/api/search', {q}, true); } catch(e){ return; }
  const res = r.results.filter(x => x.type === 'u' || x.type === 'i' || x.type === 'h').slice(0, 10); IV.sug = res;
  box.innerHTML = res.map((x, i) => `<button class="gsr ${i === 0 ? 'on' : ''}" data-iv-sug="${i}">${gsIcon[x.type]}<span class="gsl">${esc(x.label)}</span><span class="gst c-${x.status}">${esc(gsLabel(x))}</span><span class="gss">${esc(gsType[x.type])} &middot; ${esc(x.sub || '')}</span></button>`).join('');
  box.hidden = !res.length;
}, 180);
function ivAddInput(){ const v = $('#iv-in').value.trim(); if(!v) return;
  const box = $('#iv-sug');
  if(!box.hidden && IV.sug && IV.sug.length && !/[,;\s]/.test(v)){ const x = IV.sug[0]; ivAdd(`${x.type}:${x.k}`, true); }
  else v.split(/[\s,;]+/).forEach(x => ivAdd(x, true));
  $('#iv-in').value = ''; box.hidden = true; }
$('#iv-in').addEventListener('input', ivSuggest);
$('#iv-in').addEventListener('keydown', e => { if(e.key === 'Enter'){ e.preventDefault(); ivAddInput(); } else if(e.key === 'Escape') $('#iv-sug').hidden = true; });
$('#iv-add').addEventListener('click', ivAddInput);
$('#iv-run').addEventListener('click', () => runConnect());
$('#iv-clear').addEventListener('click', () => { IV.items = []; ivUpdate(); $('#iv-out').innerHTML = ''; });

const EK = {login: 'Logged in', fail: 'Failed logins', iplink: 'Linked IPs', acct: 'Linked accounts', access: 'Internal access'};
function edgeText(e){
  const w = e.when || {};
  if(e.kind === 'login') return `${fmtN(e.sess)} session${e.sess === 1 ? '' : 's'}${e.fails ? `, ${fmtN(e.fails)} failed` : ''}${w.sess ? ' &middot; ' + esc(short(w.sess[0])) : ''}`;
  if(e.kind === 'fail') return `${fmtN(e.fails)} failed login${e.fails === 1 ? '' : 's'}${w.fail ? ' &middot; ' + esc(short(w.fail[0])) : ''}`;
  if(e.kind === 'access') return `${fmtN(e.conns)} internal connections, ${fmtB(e.bytes)}`;
  return esc((e.why || [])[0] || EK[e.kind]);
}
function nodeChip(d, id){ const n = d.nodes.find(x => x.id === id) || {id, type: id[0], label: id.slice(2)};
  const attr = n.type === 'u' ? `data-u="${esc(n.key || id.slice(2))}"` : n.type === 'i' ? `data-ip="${esc(n.key || id.slice(2))}"` : `data-host="${esc(n.key || id.slice(2))}"`;
  const st = n.status ? `<span class="badge c-${n.status}">${esc((n.type === 'u' ? STATUS : ROLE)[n.status] || (n.type === 'h' ? 'in incidents' : n.status))}</span>` : '';
  return `<span class="pnode ${n.seed ? 'seed' : ''}">${gsIcon[n.type]}<button class="ref" ${attr}>${esc(n.label || id.slice(2))}</button>${n.country ? ' <span class="note">' + esc(n.country) + '</span>' : ''} ${st}</span>`; }
async function runConnect(){
  if(IV.items.length < 2){ $('#iv-out').innerHTML = '<p class="empty">Add at least two accounts or IPs.</p>'; return; }
  const t = tick('iv'); $('#iv-out').innerHTML = '<p class="loading">Searching for connections…</p>';
  let d; try { d = await api('/api/connect', {items: IV.items.join(','), hops: $('#iv-hops').value, hosts: $('#iv-hosts').checked ? 1 : 0, through: $('#iv-through').checked ? 1 : 0}); } catch(e){ return; }
  if(t !== TK.iv) return;
  IV.data = d;
  if(d.error){ $('#iv-out').innerHTML = `<p class="empty">${esc(d.error)}</p>` + (d.missing.length ? `<p class="note">Not found in this log: ${d.missing.map(esc).join(', ')}</p>` : ''); return; }
  const lab = id => esc((d.info[id] || {}).label || id.slice(2));
  const conn = d.pairs.filter(p => p.dist != null).length;
  let h = (d.missing.length ? `<p class="note">Not found in this log: ${d.missing.map(esc).join(', ')}</p>` : '') +
    `<div class="hsum"><div class="hs ${conn ? 'crit' : ''}"><b>${conn} / ${d.pairs.length}</b><span>pairs connected within ${d.hops} step${d.hops === 1 ? '' : 's'}</span></div>
      <div class="hs"><b>${fmtN(d.connectors.length)}</b><span>connectors (tie 2+ of your items together)</span></div>
      ${d.hubs.length ? `<div class="hs"><b>${fmtN(d.hubs.length)}</b><span>busy addresses skipped (office/NAT, servers)</span></div>` : ''}</div>`;
  // pair grid
  h += `<div class="sec"><h2>Who connects to whom</h2><p class="note">Number of steps between each pair (1 = direct evidence). Click a cell to jump to the paths.</p><div class="tw"><table class="mxt no-enh pairs"><thead><tr><th class="ent"></th>${d.seeds.map(s => `<th class="vert"><span>${lab(s)}</span></th>`).join('')}</tr></thead><tbody>` +
    d.seeds.map(a => `<tr><td class="ent">${nodeChip(d, a)}</td>` + d.seeds.map(b => { if(a === b) return '<td class="mx self"></td>';
      const p = d.pairs.find(x => (x.a === a && x.b === b) || (x.a === b && x.b === a));
      return p && p.dist != null ? `<td class="mx d${p.dist}" data-ivpair="${esc(p.a + '|' + p.b)}" data-tip="${esc(`${lab(a)} &harr; ${lab(b)}: ${p.dist} step${p.dist === 1 ? '' : 's'}, ${p.n} path${p.n === 1 ? '' : 's'} shown`)}">${p.dist}</td>` : '<td class="mx none" title="No connection found within the step limit">–</td>'; }).join('') + '</tr>').join('') + '</tbody></table></div></div>';
  // graph
  h += `<div class="sec"><h2>Connection graph</h2><div class="legend" style="margin-bottom:6px"><span><i class="sw" style="height:0;border-top:2px dashed var(--crit)"></i>Failed logins</span><span><i class="sw" style="height:2px;background:var(--sess)"></i>Logged in</span><span><i class="sw" style="height:0;border-top:2px dashed var(--high)"></i>Linked IPs</span><span><i class="sw" style="height:2px;background:var(--up)"></i>Linked accounts</span><span><i class="sw" style="height:0;border-top:2px dotted var(--down)"></i>Internal access</span><span><i class="sw" style="border-radius:50%;border:2px solid var(--ink);background:transparent"></i>Your items</span></div><div id="iv-graph" class="tw"></div></div>`;
  // paths
  const byPair = {}; d.paths.forEach(p => (byPair[p.a + '|' + p.b] = byPair[p.a + '|' + p.b] || []).push(p));
  h += `<div class="sec"><h2>Paths</h2>` + (d.pairs.filter(p => p.dist != null).map(pr => `<div class="ppair" id="ivp-${esc((pr.a + '|' + pr.b).replace(/[^\w]/g, '_'))}"><h3 class="vtitle">${lab(pr.a)} &harr; ${lab(pr.b)} <span class="count">${pr.dist} step${pr.dist === 1 ? '' : 's'}</span></h3>` +
      (byPair[pr.a + '|' + pr.b] || []).map(p => { let s = '<div class="pchain">' + nodeChip(d, p.nodes[0]);
        p.edges.forEach((e, i) => { s += `<span class="pedge k-${e.kind}"><span class="pek">${EK[e.kind]}</span><span class="pet">${edgeText(e)}</span></span>` + nodeChip(d, p.nodes[i + 1]); });
        return s + '</div>'; }).join('') + '</div>').join('') || `<p class="empty">No connection between these within ${d.hops} steps. Try more steps, include internal hosts, or allow busy addresses.</p>`) + '</div>';
  // connectors
  if(d.connectors.length) h += `<div class="sec"><h2>Connectors</h2><p class="note">Accounts and IPs that tie several of your items together. Add them to widen the investigation.</p><div class="tw"><table><thead><tr><th>Entity</th><th>Connects</th><th class="num">Items</th><th></th></tr></thead><tbody>` +
    d.connectors.map(x => `<tr><td>${nodeChip(d, x.n)}</td><td>${x.seeds.map(lab).join(', ')}</td><td class="num">${x.seeds.length}</td><td><button class="btn" data-inv-add="${esc(x.n)}">Add</button></td></tr>`).join('') + '</tbody></table></div></div>';
  const types = new Set(d.seeds.map(s => s[0]));
  if(types.size === 1 && !types.has('h')) h += `<div class="row-actions"><button class="btn" data-vn-open="${esc(d.seeds.map(s => s.slice(2)).join(', '))}" data-vn-mode="${types.has('u') ? 'user' : 'ip'}">Compare these in a Venn diagram</button></div>`;
  $('#iv-out').innerHTML = h;
  connGraph($('#iv-graph'), d);
}
function connGraph(el, d){
  const N = d.nodes.map(n => Object.assign({}, n)), idx = new Map(N.map((n, i) => [n.id, i]));
  const L = d.edges.map(e => ({a: idx.get(e.a), b: idx.get(e.b), e})).filter(l => l.a != null && l.b != null);
  const W = Math.max(640, el.clientWidth || 900), H = Math.min(720, Math.max(380, 90 + N.length * 16));
  // lay out each separate group in its own area, side by side, so one isolated item cannot squash the rest
  const par = N.map((_, i) => i), fd = i => { while(par[i] !== i){ par[i] = par[par[i]]; i = par[i]; } return i; };
  L.forEach(l => { par[fd(l.a)] = fd(l.b); });
  const groups = new Map(); N.forEach((_, i) => { const r = fd(i); if(!groups.has(r)) groups.set(r, []); groups.get(r).push(i); });
  const gl = [...groups.values()].sort((a, b) => b.length - a.length);
  const wts = gl.map(g => Math.sqrt(g.length) + 1.2), tw = wts.reduce((a, b) => a + b, 0);
  let x0 = 0;
  gl.forEach((g, gi) => { const gw = Math.max(220, W * wts[gi] / tw), sub = g.map(i => N[i]), loc = new Map(g.map((i, k) => [i, k]));
    const subL = L.filter(l => loc.has(l.a) && loc.has(l.b)).map(l => ({a: loc.get(l.a), b: loc.get(l.b)}));
    if(sub.length === 1){ sub[0].x = x0 + gw / 2 - 30; sub[0].y = H / 2; } else layout(sub, subL, gw, H);
    if(sub.length > 1) sub.forEach(n => { n.x += x0; });
    x0 += gw; });
  if(x0 > W) N.forEach(n => { n.x = n.x * (W - 20) / x0; });
  const bad = n => n.status === 'compromise' || n.status === 'attacker';
  let s = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" class="conn" role="img" aria-label="Connection graph">`;
  L.forEach((l, k) => { const a = N[l.a], b = N[l.b], e = l.e; const crit = e.kind === 'login' && (bad(a) || bad(b)) && (a.type === 'i' || b.type === 'i') && (bad(a) && bad(b));
    s += `<line class="ce k-${e.kind}${crit ? ' crit' : ''}" data-k="${k}" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" data-tip="${esc(`<b>${esc(a.label)}</b> &ndash; <b>${esc(b.label)}</b><br>${EK[e.kind]}: ${edgeText(e)}`)}"/>`; });
  N.forEach((n, i) => { const r = n.seed ? 9 : 6;
    const f = n.type === 'h' ? 'var(--surface)' : bad(n) ? 'var(--crit)' : n.status === 'review' || n.status === 'targeted' ? 'var(--high)' : n.type === 'u' ? 'var(--sess)' : 'var(--rule2)';
    const shape = n.type === 'u' ? `<circle r="${r}" fill="${f}"/>` : n.type === 'i' ? `<rect x="${-r}" y="${-r}" width="${2 * r}" height="${2 * r}" transform="rotate(45)" fill="${f}"/>` : `<rect x="${-r}" y="${-r}" width="${2 * r}" height="${2 * r}" rx="2" fill="${f}" stroke="${n.status ? 'var(--high)' : 'var(--down)'}" stroke-width="2.5"/>`;
    const attr = n.type === 'u' ? `data-u="${esc(n.key)}"` : n.type === 'i' ? `data-ip="${esc(n.key)}"` : `data-host="${esc(n.key)}"`;
    s += `<g class="cn${n.seed ? ' seed' : ''}" data-n="${i}" ${attr} transform="translate(${n.x.toFixed(1)},${n.y.toFixed(1)})" data-tip="${esc(`<b>${esc(n.label)}</b>${n.country ? ' ' + esc(n.country) : ''}<br>${esc(((n.type === 'u' ? STATUS : ROLE)[n.status]) || '')}${n.seed ? '<br>One of your items' : ''}${n.hub ? '<br>Busy address' : ''}`)}">${n.seed ? `<circle r="${r + 5}" fill="none" stroke="var(--ink)" stroke-width="2"/>` : ''}${shape}<text x="${r + 6}" y="4">${esc(n.label)}</text></g>`; });
  el.innerHTML = s + '</svg>';
  const svg = el.querySelector('svg'), adj = N.map(() => []); L.forEach((l, k) => { adj[l.a].push([k, l.b]); adj[l.b].push([k, l.a]); });
  svg.addEventListener('pointerover', e => { const g = e.target.closest('.cn'); if(!g) return; const i = +g.dataset.n, on = new Set([i]), eo = new Set();
    adj[i].forEach(([k, o]) => { eo.add(k); on.add(o); });
    svg.classList.add('focus'); svg.querySelectorAll('.cn').forEach(x => x.classList.toggle('on', on.has(+x.dataset.n))); svg.querySelectorAll('.ce').forEach(x => x.classList.toggle('on', eo.has(+x.dataset.k))); });
  svg.addEventListener('pointerleave', () => svg.classList.remove('focus'));
}
// saved investigations
async function ivLoadSaved(){ try { const r = await api('/api/investigations', {}, true); IV.saved = r.rows; ivSavedUI(); } catch(e){} }
function ivSavedUI(){ $('#iv-saved').innerHTML = '<option value="">Saved investigations…</option>' + IV.saved.map(x => `<option value="${esc(x.id)}">${esc(x.name)} (${x.items.length}) &middot; ${esc((x.updated || '').slice(0, 16))}</option>`).join(''); }
async function ivPost(body){ const r = await fetch('/api/investigations', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-ASA-Token': TOKEN}, body: JSON.stringify(body)});
  const j = await r.json(); if(!r.ok) throw new Error(j.error || r.statusText); IV.saved = j.rows; ivSavedUI(); return j; }
$('#iv-save').addEventListener('click', async () => { if(!IV.items.length){ toast('Nothing to save yet'); return; }
  const name = $('#iv-name').value.trim() || `Investigation ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`;
  const cur = IV.saved.find(x => x.name === name);
  try { await ivPost({id: cur ? cur.id : '', name, items: IV.items, hops: +$('#iv-hops').value, hosts: $('#iv-hosts').checked, notes: $('#iv-notes').value}); toast(`Saved "${name}"`); } catch(e){ showErr(e); } });
$('#iv-saved').addEventListener('change', e => { const x = IV.saved.find(y => y.id === e.target.value); if(!x) return;
  IV.items = x.items.slice(); $('#iv-name').value = x.name; $('#iv-hops').value = String(x.hops || 3); $('#iv-hosts').checked = !!x.hosts; $('#iv-notes').value = x.notes || ''; ivUpdate(); runConnect(); });
$('#iv-del').addEventListener('click', async () => { const id = $('#iv-saved').value; if(!id){ toast('Choose a saved investigation first'); return; }
  try { await ivPost({action: 'delete', id}); toast('Deleted'); } catch(e){ showErr(e); } });
document.addEventListener('click', e => {
  const a = e.target.closest('[data-inv-add]'); if(a){ ivAdd(a.dataset.invAdd); return; }
  const dl = e.target.closest('[data-iv-del]'); if(dl){ IV.items.splice(+dl.dataset.ivDel, 1); ivUpdate(); return; }
  const sg = e.target.closest('[data-iv-sug]'); if(sg){ const x = IV.sug[+sg.dataset.ivSug]; ivAdd(`${x.type}:${x.k}`, true); $('#iv-in').value = ''; $('#iv-sug').hidden = true; $('#iv-in').focus(); return; }
  const pc = e.target.closest('[data-ivpair]'); if(pc){ const el = $('#ivp-' + pc.dataset.ivpair.replace(/[^\w]/g, '_')); if(el) el.scrollIntoView({block: 'start', behavior: 'smooth'}); return; }
  if(!e.target.closest('#iv-sug') && e.target.id !== 'iv-in' && $('#iv-sug')) $('#iv-sug').hidden = true;
});
ivUpdate();

/* Simplified hand-drawn outlines (stylised, not exact borders) and country positions from the tz database. */
const GEO = {"land":{"namerica":[[-168,66],[-162,70],[-156,71.3],[-141,69.6],[-128,70],[-115,68.5],[-105,68],[-95,72],[-85,69],[-82,64],[-90,63],[-94,59],[-92,57],[-85,55],[-82,52.5],[-79,54],[-77,60],[-72,62],[-65,60],[-61,56],[-56,52],[-60,47],[-64,45],[-70,43.5],[-70,41.5],[-74,40.5],[-76,37],[-75.5,35],[-78,33.8],[-81,31.5],[-80.2,27],[-80.4,25.2],[-81.5,25.8],[-82.8,28],[-84,30],[-89,30.2],[-90,29],[-94,29.6],[-97.2,27.5],[-97.5,24],[-97.5,21.5],[-96,19],[-94.5,18.2],[-91,18.6],[-90.5,21],[-87,21.5],[-88,16],[-84,15.8],[-83.2,10],[-79.5,9.5],[-77.3,8.5],[-78.5,7.5],[-80.5,7.5],[-85.5,10.5],[-87.5,13],[-91.5,14],[-94,16],[-97,15.8],[-101,17.3],[-105.5,20.5],[-105.7,22.5],[-108,25.5],[-111,28],[-112.8,31.3],[-114.7,30.2],[-112,25],[-110,23],[-110.3,24.2],[-112.5,27.2],[-114.6,30.5],[-117,32.5],[-118.5,34],[-120.6,34.6],[-122.4,37.5],[-124.2,40.5],[-124,46],[-124.7,48.4],[-123,49],[-127,50.5],[-130,54.5],[-134,58],[-139,59.8],[-146,60.6],[-151,59.5],[-154,57.5],[-158,56],[-163,54.8],[-157.5,58.5],[-162,59.5],[-165,60.8],[-164.5,63.2],[-161,64.5],[-166,65.5]],"greenland":[[-73,78],[-67,80.5],[-58,82],[-40,83.5],[-22,82.5],[-18,80],[-19,76],[-21,72],[-24,69.5],[-32,68],[-40,65],[-43,60],[-48,61],[-51,64],[-53,67],[-55,70.5],[-58,75.5],[-66,76.5]],"baffin":[[-61,67],[-63.5,66],[-68,62.5],[-73,62.4],[-78,64.5],[-73,68],[-79,71.5],[-89,73.6],[-80,73.7],[-73,72],[-68,70.5],[-62,67.5]],"victoria":[[-120,71.5],[-105,73],[-100,72],[-102,69],[-112,68.5],[-118,69.5]],"ellesmere":[[-90,77],[-82,76.3],[-78,78],[-70,80.5],[-62,82.4],[-80,83],[-92,81]],"samerica":[[-77.3,8.5],[-75.5,10.5],[-72,12],[-68,10.5],[-62,10.7],[-60,8.5],[-57,6],[-52,5],[-50,1],[-48,-1],[-44,-2.5],[-39,-3.5],[-35,-5.5],[-35,-9],[-38.5,-13],[-39,-17.5],[-40.5,-21.5],[-44,-23],[-48.5,-26],[-48.7,-28.5],[-52,-32],[-54.5,-34.5],[-57.5,-35],[-57,-38],[-62,-39],[-65,-41],[-64,-43],[-67.5,-46],[-66,-48],[-69,-51.5],[-68.5,-54.8],[-72,-53],[-74.5,-50],[-75.5,-46],[-73.5,-42],[-73.6,-37],[-71.5,-32],[-71.4,-28],[-70.3,-18.5],[-75,-15.5],[-77,-12],[-79.5,-8],[-81.2,-5],[-80,-1],[-80,1],[-78.8,1.6],[-77.5,4],[-77.4,7]],"cuba":[[-84.9,21.9],[-80,23],[-77,21.3],[-74.2,20.2],[-77.7,19.9],[-82,22.6]],"hispaniola":[[-74.4,18.4],[-72.8,19.9],[-69,19.8],[-68.4,18.6],[-71.2,17.6]],"eurasia":[[-8.9,37],[-9.5,39],[-8.8,42],[-9.3,43.2],[-7,43.6],[-1.5,43.4],[-1.2,46],[-4.5,47.8],[-1.8,48.7],[1.5,50.1],[3.5,51.4],[4.8,53],[8,53.6],[8.5,55],[8.1,56.8],[10.5,57.7],[11.2,58.9],[10,59],[8,58],[6,58.3],[5,60],[5,62],[8,63.5],[12,65.5],[14,67.5],[16.5,69],[19.5,70],[24,71],[28.5,71],[31,70],[36,69],[41,67.2],[44,66],[44.3,68.5],[46,68],[53,68.5],[58,69],[60,69.8],[66,69.5],[68,71.5],[73,72.5],[73,68],[78,72],[83,71],[87,74],[98,76],[104,77.7],[113,73.5],[126,73.5],[131,71],[140,72.5],[150,71.5],[160,70],[170,70],[180,69],[180,65.5],[177,64.5],[173,61],[166,60],[163,58],[163,56],[160.5,53],[156.5,51],[156,57],[160,61],[155,59.5],[150,59.5],[143,59],[138,55],[141.4,53],[141,48.5],[138,46],[135,43.2],[132,43],[129.7,41.3],[129.4,37],[127,34.7],[126.3,35],[126.6,37.7],[124.7,38],[125.5,39.8],[121.5,39],[122.2,40.5],[121.6,41],[118.2,39],[119.2,37.2],[122.5,37],[120,35],[121.3,32],[122,30],[119.6,25.6],[116.5,23],[113.5,22.2],[110.5,21],[109.7,21.5],[108,21.5],[106.5,20],[105.7,18.5],[107.4,16.5],[109.3,13],[109,11.6],[106.8,10.4],[104.8,8.6],[104.7,10.4],[103,11],[100.5,13.5],[99.2,10],[100.5,7],[103.3,4.5],[103.5,1.4],[101.3,2.9],[98.5,8],[98.3,9.5],[98.7,13.2],[97.6,16.5],[94.5,16.2],[94.2,19],[92.3,20.8],[91.8,22.3],[89,21.8],[86.9,20.8],[85,19.3],[82.3,17],[80.3,15.2],[80.1,13],[79.8,10.3],[77.5,8],[76.2,10],[74.7,13],[73.4,16],[72.8,19],[72.6,21.5],[70.5,20.8],[68.8,22.3],[66.7,25.3],[61.7,25.2],[57.3,25.8],[56.4,27.1],[54.5,26.7],[51.4,27.9],[50.1,30.2],[48.5,29.9],[47.8,29.4],[48.4,28.5],[50.2,26.2],[51.6,24.5],[54.1,24.2],[56.4,26.3],[56.6,24.5],[59.8,22.5],[57.8,19],[55,17],[52,15.6],[48,14],[45,12.8],[43.3,12.7],[42.6,16.5],[39.2,21.5],[38.4,23.5],[35.6,28],[34.9,29.5],[34.2,31.2],[34.9,32.8],[35.9,35],[36.1,36.6],[33,36.1],[30.6,36.6],[27.4,37.2],[26.3,38.3],[26.6,40.1],[26.1,40.6],[24,40.8],[22.6,40.3],[24.3,38.2],[23.2,36.4],[21.7,36.9],[21.1,38.3],[19.4,40.3],[19.4,41.9],[16,43.5],[13.7,45.1],[12.3,45.3],[12.4,44.2],[13.6,43.5],[16,41.4],[18.5,40.2],[17,40.5],[16.6,38.9],[15.7,37.9],[15.8,38.8],[15.6,40],[14,40.8],[12.3,41.7],[10.5,42.9],[10.2,44],[8.8,44.4],[7.5,43.8],[6.5,43.1],[4.6,43.4],[3.1,43],[3.2,41.9],[0.8,41],[-0.3,39.5],[0.2,38.7],[-0.7,37.6],[-2.1,36.7],[-4.4,36.7],[-5.6,36],[-6.5,36.9],[-7.4,37.2]],"africa":[[-17,21],[-16.5,24],[-13,27.7],[-9.8,30.5],[-9.3,32.6],[-6.5,34.2],[-5.9,35.8],[-2,35.1],[1,36.5],[3,36.8],[8.6,36.9],[10.3,37.2],[11,35.5],[10.2,34.3],[11.1,33.3],[15.2,32.3],[19.9,30.9],[20.1,32.2],[23,32.6],[25,31.8],[29,30.9],[32.3,31.3],[34.2,31.2],[34.5,28],[33.5,27.5],[35.5,24],[37.3,21],[38.5,17.8],[39.7,15.3],[43.3,12.5],[44.3,10.4],[51.2,11.8],[51,10.4],[48.9,5.9],[46,2],[42,-1],[40.2,-2.8],[39.3,-5],[38.8,-7.3],[40.5,-10.5],[40.5,-15.5],[35.3,-22],[35.5,-24],[32.9,-26],[32.6,-28.6],[30.5,-31],[27.5,-33.7],[22.5,-34],[20,-34.8],[18.4,-34.1],[18,-31],[16.5,-28.6],[15.2,-26.8],[14.4,-22.9],[11.8,-17.2],[13.5,-11.5],[12.3,-6.1],[11.8,-3.5],[9.4,0],[9.6,3.6],[8.5,4.5],[5.9,4.3],[4.5,6.3],[1.8,6.2],[-2,4.8],[-4,5.2],[-7.5,4.4],[-9.3,5.5],[-11.5,6.9],[-13.2,8.4],[-15,10.9],[-16.7,12.5],[-17.5,14.7],[-16.5,16.2],[-16.3,19.4]],"madagascar":[[49.3,-12],[50.5,-15.5],[49.6,-17.5],[48,-23.5],[47.1,-24.9],[45.2,-25.5],[43.7,-23],[43.3,-21.3],[44.4,-19],[44,-17],[46.4,-15.6],[48.6,-13.5]],"australia":[[113.6,-22],[114.2,-26.3],[115,-29.5],[115.7,-33.5],[117.9,-35.1],[123.5,-33.9],[126.1,-32.3],[131,-31.5],[134.2,-32.6],[135.9,-34.9],[137.8,-33],[138.5,-35.3],[140,-37.6],[143.5,-38.8],[146.3,-39.1],[150,-37.5],[151.3,-33.8],[153.1,-30.5],[153.5,-27],[150.8,-22.6],[146.3,-18.5],[145.3,-14.9],[142.5,-10.7],[141.6,-12.9],[141.5,-15.6],[140.6,-17.7],[137,-15.8],[135.6,-14.7],[136.9,-12.1],[132.6,-11.5],[130.1,-12.9],[129.2,-14.9],[126.3,-13.9],[124.4,-16.3],[122.2,-18.2],[119,-20],[116.7,-20.6]],"tasmania":[[144.6,-40.7],[148.3,-40.9],[147.9,-43.2],[146,-43.6],[144.7,-41.3]],"nz_n":[[172.7,-34.4],[174.5,-36.8],[176,-37.6],[178.5,-37.7],[177,-39.3],[176.9,-40.1],[174.9,-41.3],[173.8,-39.3],[174.6,-38.8]],"nz_s":[[172.7,-40.5],[174.3,-41.8],[172.8,-43.7],[171.2,-44.5],[169.3,-46.6],[166.5,-46],[168.3,-44],[171,-42.4]],"honshu":[[130.8,31.5],[131.9,33.3],[133,33.9],[135.2,33.6],[136.9,34.6],[138.8,34.6],[140.9,35.7],[141,38],[142,39.6],[141.5,41.4],[140,40.5],[139.8,38.3],[137.3,36.8],[136,35.8],[133.1,35.5],[131,34.3],[129.8,33.3]],"hokkaido":[[140,41.5],[141.4,42.6],[143.3,42],[145.5,43.3],[144.3,44.1],[141.9,45.5],[141.4,43.3]],"britain":[[-5.7,50.1],[-3,50.6],[1.3,51.1],[1.7,52.6],[0.2,53.5],[-0.1,54.5],[-1.6,55.6],[-2,57],[-1.8,57.6],[-4,57.7],[-3,58.6],[-5,58.6],[-6.2,57.4],[-5.6,56.3],[-6.2,55.6],[-4.9,55],[-3.3,54.8],[-3.4,53.4],[-4.6,53.3],[-4.2,52.3],[-5.3,51.7],[-3.3,51.4],[-4.5,51]],"ireland":[[-6,52.2],[-6,53.9],[-5.5,54.8],[-7.3,55.3],[-8.5,54.4],[-10.2,54.2],[-9.9,53.4],[-10.4,51.8],[-8.5,51.6],[-6.4,52.2]],"iceland":[[-22.7,63.9],[-20,63.5],[-16,64],[-13.5,65.1],[-14.6,66.3],[-18,66.2],[-22.4,66.4],[-24,65.5],[-21.7,64.4]],"srilanka":[[79.8,8.2],[80.3,9.8],[81.8,7.5],[81.2,6.2],[80.1,6]],"luzon":[[120.6,18.5],[122.3,18.4],[122,16],[124,13],[123,13],[120.6,14.3],[119.8,16.3]],"mindanao":[[122,7],[126.6,7.3],[126,9.2],[125.4,9.8],[123.6,8.6],[122,7.6]],"sumatra":[[95.3,5.6],[97.5,5.2],[100.3,2.5],[103.8,-1],[106,-3.2],[105.8,-5.8],[104.5,-5.9],[102.3,-4],[100.2,-1],[98.8,1.7]],"java":[[105.2,-6.8],[108.3,-6.2],[111,-6.4],[114.6,-7.7],[114.4,-8.7],[111,-8.3],[106.4,-7.4]],"borneo":[[109,1.5],[109.6,-1.3],[110.2,-2.9],[114.5,-4],[116.5,-3.2],[118,1],[119,5],[117,7],[115.5,5],[113.5,3.4],[111,1.8]],"sulawesi":[[119.4,-5.5],[119.6,-3.5],[120.3,0.6],[123,0.9],[124.9,1.6],[121.5,-0.9],[123.3,-1.3],[121.8,-1.9],[122.9,-4.8],[121,-4.5],[120.4,-2.8],[120.4,-5.5]],"newguinea":[[131,-1.4],[134,-0.8],[138,-1.6],[141,-2.6],[145,-4.5],[147.5,-6],[150.5,-10.5],[147,-10.1],[144,-7.8],[141,-9.1],[139,-8.1],[137.7,-5.2],[135,-4.4],[132.8,-4],[131.9,-2.6]],"taiwan":[[120.1,23],[121,25.2],[122,25],[121.4,22.7],[120.8,21.9]],"svalbard":[[11,78.5],[17,80.3],[27,80],[22,77.5],[16,76.6]],"novayazemlya":[[52,71.5],[56,73.5],[60,76.5],[68,77],[61,74.5],[55,71]],"sicily":[[12.4,37.8],[13.4,38.2],[15.6,38.3],[15.1,36.7],[14.3,37],[12.6,37.6]],"sardinia":[[8.4,39],[9.6,39.1],[9.8,41],[9.2,41.3],[8.2,40.9],[8.4,39.9]],"corsica":[[8.6,41.4],[9.4,41.4],[9.5,43],[8.6,42.4]],"crete":[[23.5,35.3],[26.3,35.1],[26.1,35.3],[24,35.6]],"cyprus":[[32.3,34.7],[34.6,35.7],[33.9,35.1],[32.9,34.6]],"sakhalin":[[142,46],[143.5,46.5],[143,49.5],[144.5,49],[143,53],[142.6,54.3],[142,51.5]]},"water":{"blacksea":[[27.7,42.5],[28.6,43.7],[29.7,45.2],[30.8,46.5],[33.6,46.1],[32.6,45.4],[33.5,44.5],[35.5,45],[36.5,45.3],[38,44.6],[39.7,43.6],[41.6,41.6],[40,41],[37,41.2],[35,42],[33,41.9],[31.2,41.1],[29.1,41.2],[28,41.7]],"azov":[[35,45.3],[35.4,46.3],[37,46.9],[39.3,47.2],[38.2,46.1],[37.5,45.4]],"caspian":[[47,44.8],[49,46.5],[51.5,47],[53,46.8],[53.2,45.2],[51.3,44.3],[52.8,42],[54,40.8],[53.9,38],[53.2,37.1],[51,36.7],[49.2,37.6],[48.9,38.6],[49.5,40.3],[48,42],[47.5,43.5]],"baltic":[[10.8,54.3],[12.5,54.5],[14.2,53.9],[18.5,54.6],[21,55.2],[21.1,56.9],[23.6,57.2],[24.3,58.4],[23.5,59.2],[25.5,59.6],[28,59.7],[30,59.9],[28.5,60.5],[25,60.2],[22.9,59.9],[21.4,60.7],[21.1,62.4],[21.6,63.4],[25.2,65],[24.6,65.7],[22.2,65.8],[21.3,64.6],[19.1,63.4],[17.7,62.5],[17.2,60.7],[18.9,59.8],[18.4,58.9],[16.6,57.5],[16.4,56.2],[14.3,55.5],[12.9,55.4],[12.5,56.3],[12,57.5],[11.2,58.6],[10.6,57.6],[10.5,56.4],[10.9,55.6],[10.3,55]],"whitesea":[[32.5,66.2],[34.8,64.5],[37,63.9],[39.8,64.6],[41.2,66.1],[40.4,66.6],[35.5,66.6],[33.3,66.7]],"aral":[[58.3,46.5],[61.2,46.6],[61.6,45],[59.8,43.8],[58.6,44.6]]}};
const CXY = {"AD":[1.52,42.5],"AE":[55.3,25.3],"AF":[69.2,34.52],"AG":[-61.8,17.05],"AI":[-63.07,18.2],"AL":[19.83,41.33],"AM":[44.5,40.18],"AO":[13.23,-8.8],"AQ":[0.0,-75.0],"AR":[-60.0,-33.5],"AS":[-170.7,-14.27],"AT":[16.33,48.22],"AU":[149.5,-33.0],"AW":[-69.97,12.5],"AX":[19.95,60.1],"AZ":[49.85,40.38],"BA":[18.42,43.87],"BB":[-59.62,13.1],"BD":[90.42,23.72],"BE":[4.33,50.83],"BF":[-1.52,12.37],"BG":[23.32,42.68],"BH":[50.58,26.38],"BI":[29.37,-3.38],"BJ":[2.62,6.48],"BL":[-62.85,17.88],"BM":[-64.77,32.28],"BN":[114.92,4.93],"BO":[-68.15,-16.5],"BQ":[-68.28,12.15],"BR":[-47.0,-18.0],"BS":[-77.35,25.08],"BT":[89.65,27.47],"BW":[25.92,-24.65],"BY":[27.57,53.9],"BZ":[-88.2,17.5],"CA":[-79.4,45.0],"CC":[96.92,-12.17],"CD":[20.0,-3.0],"CF":[18.58,4.37],"CG":[15.28,-4.27],"CH":[8.53,47.38],"CI":[-4.03,5.32],"CK":[-159.77,-21.23],"CL":[-70.6,-33.4],"CM":[9.7,4.05],"CN":[113.0,32.0],"CO":[-74.08,4.6],"CR":[-84.08,9.93],"CU":[-82.37,23.13],"CV":[-23.52,14.92],"CW":[-69.0,12.18],"CX":[105.72,-10.42],"CY":[33.37,35.17],"CZ":[14.43,50.08],"DE":[10.0,51.0],"DJ":[43.15,11.6],"DK":[12.58,55.67],"DM":[-61.4,15.3],"DO":[-69.9,18.47],"DZ":[3.05,36.78],"EC":[-78.5,-1.5],"EE":[24.75,59.42],"EG":[31.2,28.0],"EH":[-13.2,27.15],"ER":[38.88,15.33],"ES":[-3.7,40.4],"ET":[38.7,9.03],"FI":[25.5,62.0],"FJ":[178.42,-18.13],"FK":[-57.85,-51.7],"FM":[158.2,6.9],"FO":[-6.77,62.02],"FR":[2.5,46.6],"GA":[9.45,0.38],"GB":[-1.5,52.5],"GD":[-61.75,12.05],"GE":[44.82,41.72],"GF":[-52.33,4.93],"GG":[-2.54,49.45],"GH":[-0.22,5.55],"GI":[-5.35,36.13],"GL":[-45.0,66.0],"GM":[-16.65,13.47],"GN":[-13.72,9.52],"GP":[-61.53,16.23],"GQ":[8.78,3.75],"GR":[23.72,37.97],"GS":[-36.53,-54.27],"GT":[-90.52,14.63],"GU":[144.75,13.47],"GW":[-15.58,11.85],"GY":[-58.17,6.8],"HK":[114.15,22.28],"HN":[-87.22,14.1],"HR":[15.97,45.8],"HT":[-72.33,18.53],"HU":[19.08,47.5],"ID":[110.0,-6.5],"IE":[-6.25,53.33],"IL":[35.22,31.78],"IM":[-4.47,54.15],"IN":[77.2,23.0],"IO":[72.42,-7.33],"IQ":[44.42,33.35],"IR":[53.0,32.5],"IS":[-21.85,64.15],"IT":[12.5,42.5],"JE":[-2.11,49.18],"JM":[-76.79,17.97],"JO":[35.93,31.95],"JP":[138.5,36.0],"KE":[36.82,-1.28],"KG":[74.6,42.9],"KH":[104.92,11.55],"KI":[173.0,1.4],"KM":[43.27,-11.68],"KN":[-62.72,17.3],"KP":[125.75,39.02],"KR":[126.97,37.55],"KW":[47.98,29.33],"KY":[-81.38,19.3],"KZ":[71.4,49.5],"LA":[102.6,17.97],"LB":[35.5,33.88],"LC":[-61.0,14.02],"LI":[9.52,47.15],"LK":[79.85,6.93],"LR":[-10.78,6.3],"LS":[27.5,-29.47],"LT":[25.32,54.68],"LU":[6.15,49.6],"LV":[24.1,56.95],"LY":[13.18,32.9],"MA":[-7.58,33.65],"MC":[7.38,43.7],"MD":[28.83,47.0],"ME":[19.27,42.43],"MF":[-63.08,18.07],"MG":[47.52,-18.92],"MH":[171.2,7.15],"MK":[21.43,41.98],"ML":[-8.0,12.65],"MM":[96.17,16.78],"MN":[106.9,47.9],"MO":[113.54,22.2],"MP":[145.75,15.2],"MQ":[-61.08,14.6],"MR":[-15.95,18.1],"MS":[-62.22,16.72],"MT":[14.52,35.9],"MU":[57.5,-20.17],"MV":[73.5,4.17],"MW":[35.0,-15.78],"MX":[-99.1,20.5],"MY":[101.7,3.1],"MZ":[32.58,-25.97],"NA":[17.1,-22.57],"NC":[166.45,-22.27],"NE":[2.12,13.52],"NF":[167.97,-29.05],"NG":[7.5,9.0],"NI":[-86.28,12.15],"NL":[4.9,52.37],"NO":[9.5,60.5],"NP":[85.32,27.72],"NR":[166.92,-0.52],"NU":[-169.92,-19.02],"NZ":[174.8,-39.0],"OM":[58.58,23.6],"PA":[-79.53,8.97],"PE":[-77.05,-12.05],"PF":[-149.5,-17.6],"PG":[147.17,-9.5],"PH":[120.97,14.59],"PK":[67.05,24.87],"PL":[19.4,52.1],"PM":[-56.33,47.05],"PN":[-130.08,-25.07],"PR":[-66.11,18.47],"PS":[35.2,31.9],"PT":[-8.6,39.6],"PW":[134.48,7.33],"PY":[-57.67,-25.27],"QA":[51.53,25.28],"RE":[55.47,-20.87],"RO":[26.1,44.43],"RS":[20.5,44.83],"RU":[37.62,55.75],"UA":[31.0,49.5],"RW":[30.07,-1.95],"SA":[45.0,24.0],"SB":[160.2,-9.53],"SC":[55.47,-4.67],"SD":[32.53,15.6],"SE":[15.5,60.0],"SG":[103.85,1.28],"SH":[-5.7,-15.92],"SI":[14.52,46.05],"SJ":[16.0,78.0],"SK":[17.12,48.15],"SL":[-13.25,8.5],"SM":[12.47,43.92],"SN":[-17.43,14.67],"SO":[45.37,2.07],"SR":[-55.17,5.83],"SS":[31.62,4.85],"ST":[6.73,0.33],"SV":[-89.2,13.7],"SX":[-63.05,18.05],"SY":[36.3,33.5],"SZ":[31.1,-26.3],"TC":[-71.13,21.47],"TD":[15.05,12.12],"TF":[70.22,-49.35],"TG":[1.22,6.13],"TH":[100.52,13.75],"TJ":[68.8,38.58],"TK":[-171.23,-9.37],"TL":[125.58,-8.55],"TM":[58.38,37.95],"TN":[10.18,36.8],"TO":[-175.2,-21.13],"TR":[33.0,39.2],"TT":[-61.52,10.65],"TV":[179.22,-8.52],"TW":[121.5,25.05],"TZ":[39.28,-6.8],"UG":[32.42,0.32],"UM":[-162.0,6.0],"US":[-95.0,38.5],"UY":[-56.21,-34.91],"UZ":[66.8,39.67],"VA":[12.45,41.9],"VC":[-61.23,13.15],"VE":[-66.93,10.5],"VG":[-64.62,18.45],"VI":[-64.93,18.35],"VN":[106.0,16.0],"VU":[168.42,-17.67],"WF":[-176.17,-13.3],"WS":[-171.73,-13.83],"YE":[45.2,12.75],"YT":[45.23,-12.78],"ZA":[25.5,-29.0],"ZM":[28.28,-15.42],"ZW":[31.05,-17.83]};
/* ---------- world map (dotted land, Miller projection) ---------- */
const WMAP = {views: {world: {lon: [-170, 190], lat: [-56, 84], step: 1.8}, europe: {lon: [-25, 50], lat: [33, 71.5], step: 0.55}}, cache: {}};
function pip(x, y, poly){ let ins = false; for(let i = 0, j = poly.length - 1; i < poly.length; j = i++){ const xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];
  if(((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi)) ins = !ins; } return ins; }
const millerY = lat => 1.25 * Math.log(Math.tan(Math.PI / 4 + 0.4 * lat * Math.PI / 180));
function mapProj(v, W){ const x0 = v.lon[0], x1 = v.lon[1], y0 = millerY(v.lat[1]), y1 = millerY(v.lat[0]);
  const kx = W / (x1 - x0), H = W * (y0 - y1) / ((x1 - x0) * Math.PI / 180);
  return {W, H, x: lon => (lon - x0) * kx, y: lat => (y0 - millerY(lat)) / (y0 - y1) * H}; }
function landDots(name){
  if(WMAP.cache[name]) return WMAP.cache[name];
  const v = WMAP.views[name], polys = Object.values(GEO.land), holes = Object.values(GEO.water), out = [];
  const bb = p => { let a = 1e9, b = 1e9, c = -1e9, d = -1e9; for(const [x, y] of p){ a = Math.min(a, x); b = Math.min(b, y); c = Math.max(c, x); d = Math.max(d, y); } return [a, b, c, d]; };
  const pb = polys.map(bb), hb = holes.map(bb);
  for(let lat = v.lat[0] + v.step / 2; lat < v.lat[1]; lat += v.step) for(let lon = v.lon[0] + v.step / 2; lon < v.lon[1]; lon += v.step){
    const L = lon > 180 ? lon - 360 : lon;
    let on = false; for(let i = 0; i < polys.length && !on; i++){ const b = pb[i]; if(L >= b[0] && L <= b[2] && lat >= b[1] && lat <= b[3] && pip(L, lat, polys[i])) on = true; }
    if(on) for(let i = 0; i < holes.length; i++){ const b = hb[i]; if(L >= b[0] && L <= b[2] && lat >= b[1] && lat <= b[3] && pip(L, lat, holes[i])){ on = false; break; } }
    if(on) out.push([lon, lat]);
  }
  return (WMAP.cache[name] = out);
}
/* ---------- world map of logins ---------- */
let WM = null;   // last /api/countries result
function mapFitView(rows){
  const pts = rows.map(r => CXY[r.cc]).filter(Boolean);
  if(!pts.length) return WMAP.views.europe;
  let a = Math.min(...pts.map(p => p[0])), b = Math.max(...pts.map(p => p[0])), c = Math.min(...pts.map(p => p[1])), d = Math.max(...pts.map(p => p[1]));
  const padX = Math.max(8, (b - a) * .15), padY = Math.max(6, (d - c) * .2);
  a -= padX; b += padX; c -= padY; d += padY;
  if((b - a) < 40){ const m = (a + b) / 2; a = m - 20; b = m + 20; }
  if((d - c) < 22){ const m = (c + d) / 2; c = m - 11; d = m + 11; }
  a = Math.max(-170, a); b = Math.min(190, b); c = Math.max(-56, c); d = Math.min(83, d);
  return {lon: [a, b], lat: [c, d], step: Math.max(0.45, (b - a) / 140)};
}
function drawWorldMap(){
  const el = $('#wmap'); if(!el || !WM) return;
  const rows = WM.rows.filter(r => CXY[r.cc]);
  if(!WM.geo){ el.innerHTML = ''; return; }
  const vName = $('#wm-view').value, metric = $('#wm-metric').value;
  const v = vName === 'fit' ? mapFitView(rows) : WMAP.views[vName];
  const key = vName === 'fit' ? 'fit:' + v.lon.join(',') + ':' + v.lat.join(',') : vName;
  if(!WMAP.views[key]) WMAP.views[key] = v;
  const W = Math.max(600, Math.min(1400, el.clientWidth || 1000)), P = mapProj(v, W), H = P.H;
  const dots = landDots(key), dr = Math.max(1.4, Math.min(3.2, (P.x(v.lon[0] + v.step) - P.x(v.lon[0])) * .4));
  const home = new Set(WM.home || []), homeRow = rows.filter(r => home.has(r.cc)).sort((a, b) => b.sess - a.sess)[0] || rows.slice().sort((a, b) => b.sess - a.sess)[0];
  const val = r => metric === 'fails' ? r.fails : metric === 'users' ? r.users : metric === 'down' ? r.down : r.sess;
  const mx = Math.max(1, ...rows.map(val)), mf = Math.max(1, ...rows.map(r => r.fails));
  const rad = x => x ? 4 + Math.sqrt(x / mx) * (vName === 'world' ? 26 : 34) : 0;
  // home stays teal even when an attacker used a local IP; attacking IPs get their own red marker
  const col = r => home.has(r.cc) ? 'var(--down)' : r.attackers ? 'var(--crit)' : home.size ? 'var(--high)' : 'var(--low)';
  const inV = ([lon, lat]) => lon >= v.lon[0] && lon <= v.lon[1] && lat >= v.lat[0] && lat <= v.lat[1];
  let s = `<svg viewBox="0 0 ${W} ${H.toFixed(0)}" width="100%" class="wmap" role="img" aria-label="Map of where logins come from">`;
  s += `<g class="land">${dots.map(([lo, la]) => `<circle cx="${P.x(lo).toFixed(1)}" cy="${P.y(la).toFixed(1)}" r="${dr.toFixed(2)}"/>`).join('')}</g>`;
  // arcs: from each country to the home country
  if($('#wm-arcs').checked && homeRow){ const [hx, hy] = [P.x(CXY[homeRow.cc][0]), P.y(CXY[homeRow.cc][1])];
    s += '<g class="arcs">' + rows.filter(r => r !== homeRow && val(r)).sort((a, b) => val(a) - val(b)).map(r => { const [lo, la] = CXY[r.cc];
      const x = P.x(lo), y = P.y(la), mxp = (x + hx) / 2, myp = (y + hy) / 2 - Math.hypot(hx - x, hy - y) * .25;
      return `<path d="M${x.toFixed(1)},${y.toFixed(1)} Q${mxp.toFixed(1)},${myp.toFixed(1)} ${hx.toFixed(1)},${hy.toFixed(1)}" stroke="${col(r)}" stroke-width="${(1 + Math.sqrt(val(r) / mx) * 4).toFixed(1)}" class="${r.attackers ? 'bad' : ''}"/>`; }).join('') + '</g>'; }
  // bubbles, largest first so small ones stay clickable
  const vis = rows.filter(r => inV(CXY[r.cc]) && val(r)).sort((a, b) => val(b) - val(a));
  s += '<g class="bub">' + vis.map(r => { const [lo, la] = CXY[r.cc], x = P.x(lo), y = P.y(la), R = rad(val(r));
    const fr = metric === 'sessions' && r.fails ? 3 + Math.sqrt(r.fails / mf) * 12 : 0;
    const tip = `<b>${esc(r.country || r.cc)}</b> ${esc(r.cc)}${home.has(r.cc) ? ' (home)' : ''}<br>${fmtN(r.sess)} VPN sessions, ${fmtN(r.users)} accounts, ${fmtN(r.ips)} IPs<br>${fmtN(r.fails)} failed logins${r.attackers ? `<br><b>${fmtN(r.attackers)} attacking IP${r.attackers === 1 ? '' : 's'}</b>` : ''}<br>Downloaded ${fmtB(r.down)}<br><span class='note'>Click to list the IPs</span>`;
    return `<g class="wb" data-country="${esc(r.country || r.cc)}" data-tip="${esc(tip)}" transform="translate(${x.toFixed(1)},${y.toFixed(1)})">
      <circle r="${R.toFixed(1)}" fill="${col(r)}" fill-opacity=".38" stroke="${col(r)}" stroke-width="1.5"/>${fr ? `<circle r="${(R + fr).toFixed(1)}" fill="none" stroke="var(--crit)" stroke-width="1.6" stroke-dasharray="3 2" opacity=".85"/>` : ''}
      <circle r="2.2" fill="${col(r)}"/>${r.attackers && home.has(r.cc) ? `<rect x="${(R * .7 - 4).toFixed(1)}" y="${(-R * .7 - 4).toFixed(1)}" width="8" height="8" transform="rotate(45 ${(R * .7).toFixed(1)} ${(-R * .7).toFixed(1)})" fill="var(--crit)" stroke="var(--surface)"/>` : ''}</g>`; }).join('') + '</g>';
  // labels for the biggest ones
  s += '<g class="lbl">' + vis.slice(0, vName === 'world' ? 14 : 22).map(r => { const [lo, la] = CXY[r.cc], R = rad(val(r));
    return `<text x="${(P.x(lo) + R + 4).toFixed(1)}" y="${(P.y(la) + 4).toFixed(1)}">${esc(r.cc)} ${metric === 'down' ? fmtB(val(r)) : fmtN(val(r))}</text>`; }).join('') + '</g>';
  const off = rows.filter(r => val(r) && !inV(CXY[r.cc]));
  el.innerHTML = s + '</svg>' + (off.length ? `<p class="note">Outside this view: ${off.map(r => esc(r.country || r.cc)).join(', ')}. Switch to World.</p>` : '');
}

/* ---------- case review: go through a case step by step with its evidence ---------- */
const RSTAT = {new:'Not started', investigating:'Investigating', confirmed:'Confirmed incident', false_positive:'False positive', closed:'Closed'};
const TOKEN = (document.querySelector('meta[name="asa-token"]') || {}).content || '';
const CR = {d: null};
async function saveReview(patch){
  if(!CR.d) return;
  const el = $('#cr-saved'); if(el) el.textContent = 'Saving…';
  try {
    const r = await fetch('/api/review', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-ASA-Token': TOKEN}, body: JSON.stringify(Object.assign({key: CR.d.key}, patch))});
    const j = await r.json(); if(!r.ok) throw new Error(j.error || r.statusText);
    CR.d.review = j; if(el) el.textContent = 'Saved ' + (j.updated || '').slice(11, 16);
    crProgress(); const c = cS.rows.find(x => x.id === CR.d.id); if(c){ c.review = j.status; }
  } catch(e){ if(el) el.textContent = 'Not saved: ' + e.message; showErr(e); }
}
const saveNotes = debounce(() => saveReview({notes: $('#cr-notes').value}), 800);
function crProgress(){
  const d = CR.d, rv = d.review; if(!d) return;
  const sd = d.incidents.filter(x => rv.steps_done.includes(x.key)).length, ad = d.actions.filter(a => rv.actions_done.includes(a)).length;
  const tot = d.incidents.length + d.actions.length, pct = tot ? Math.round((sd + ad) / tot * 100) : 0;
  const el = $('#cr-prog'); if(el) el.innerHTML = `<div class="progress"><i style="width:${pct}%"></i></div><span class="note">${sd} of ${d.incidents.length} steps reviewed, ${ad} of ${d.actions.length} next steps done</span>`;
  $$('.step[data-step]').forEach(n => n.classList.toggle('done', rv.steps_done.includes(n.dataset.step)));
}
function evTable(ev){
  if(!ev.length) return '<p class="note">No individual log lines are stored for this finding (it is based on aggregated data shown above).</p>';
  const shown = ev.slice(0, 300);
  return `<details ${ev.length <= 12 ? 'open' : ''}><summary class="note" style="cursor:pointer">Evidence: ${fmtN(ev.length)} line${ev.length === 1 ? '' : 's'}</summary><div class="tw"><table class="ev"><thead><tr><th>Seq</th><th>Time</th><th>Kind</th><th>Log line / connection</th></tr></thead><tbody>` +
    shown.map(r => `<tr class="${r[3] === 'BLOCKED' || r[3] === 'DENY' ? 'blocked' : ''}"><td>${r[2] === 'log' && r[0] != null ? `<button class="ref" data-seqs="${r[0]}" title="Show in Raw events">${r[0]}</button>` : esc(r[0] == null ? '' : String(r[0]))}</td><td>${esc(r[1] || '')}</td><td class="kind">${esc(KIND[r[3]] || r[3])}</td><td class="raw">${esc(r[4] || '')}</td></tr>`).join('') +
    `</tbody></table></div>${ev.length > shown.length ? `<p class="note">${fmtN(ev.length - shown.length)} more lines in the evidence CSV.</p>` : ''}</details>`;
}
async function openCase(id){
  drawerOpen = () => openCase(id);
  const t = tick('dr'); openDrawer(); $('#drawer').classList.add('wide'); $('#drawer').innerHTML = '<p class="loading">Loading case…</p>';
  let d; try { d = await api('/api/case', {id}, true); } catch(e){ $('#drawer').innerHTML = `<div class="dh"><h2>Case ${id}</h2><button class="close" data-close>Close</button></div><p class="empty">${esc(e.message)}</p>`; return; }
  if(t !== TK.dr) return;
  CR.d = d; const rv = d.review;
  DS.rows = d.sessions; DS.total = d.sessions.length; DS.filter = null; DS.hide = '';
  drawerRender = () => {
    const dr = $('#drawer'); const st = dr.scrollTop;
    let day = '';
    const steps = d.incidents.map((x, i) => { const dd = x.start.slice(0, 10); const hdr = dd !== day ? `<h3 class="note" style="margin:22px 0 0">${niceDate(dd)}</h3>` : ''; day = dd;
      return hdr + `<div class="step ${x.sev}" data-step="${esc(x.key)}"><label class="rvchk no-print"><input type="checkbox" data-rv-step="${esc(x.key)}" ${rv.steps_done.includes(x.key) ? 'checked' : ''}> Reviewed</label>
        <div class="note" style="margin:0">Step ${i + 1} &middot; ${short(x.start)}${x.end && x.end !== x.start ? ' to ' + short(x.end) : ''}</div>
        <h3><span class="badge c-${x.sev}">${SEV[x.sev]}</span> ${esc(x.title)}</h3><p style="margin:4px 0 6px">${esc(x.detail)}</p>
        ${x.hosts && x.hosts.length ? `<p class="note">Internal hosts: ${x.hosts.slice(0, 12).map(hostRef).join(', ')}${x.hosts.length > 12 ? ` and ${x.hosts.length - 12} more` : ''}</p>` : ''}
        ${evTable(x.evidence)}</div>`; }).join('');
    dr.innerHTML = `<div class="dh"><div><h2>Case ${d.id}: ${esc(d.who)}</h2><p class="note">${esc(d.title)}</p></div><button class="close" data-close>Close</button></div>
      <div class="cr-bar"><span class="badge c-${d.sev}">${SEV[d.sev]}</span><span class="note" style="margin:0">${short(d.start)} to ${short(d.end)}</span>
        <label class="note" style="margin:0">Review status <select id="cr-status">${Object.entries(RSTAT).map(([k, v]) => `<option value="${k}" ${rv.status === k ? 'selected' : ''}>${v}</option>`).join('')}</select></label>
        <span class="saved" id="cr-saved">${rv.updated ? 'Last saved ' + esc(rv.updated) : ''}</span></div>
      <div id="cr-prog"></div>
      <div class="row-actions no-print"><a class="btn" href="/api/export/case.csv?id=${d.id}">Evidence CSV</a>${d.report ? `<a class="btn" href="${esc(d.report)}" target="_blank" rel="noopener">Saved report</a>` : ''}<button class="btn" data-print>Print / save as PDF</button></div>
      <div class="cr-sum"><b>Summary.</b> ${esc(d.summary)}</div>
      ${d.graph && d.graph.nodes.length ? `<div class="sec"><h2>Attack flow</h2><p class="note">Source IPs, the accounts they failed against or used, and the internal hosts those accounts reached around this case. Hover to follow a path; click to open details.</p><div id="cr-flow" class="tw"></div></div>` : ''}
      <div class="sec"><h2>Next steps</h2><ul class="acts">${d.actions.map((a, i) => `<li><label><input type="checkbox" data-rv-act="${i}" ${rv.actions_done.includes(a) ? 'checked' : ''}><span>${esc(a)}</span></label></li>`).join('')}</ul></div>
      <div class="sec"><h2>Who and what is involved</h2><div class="tw"><table><thead><tr><th>Account</th><th>Status</th><th class="num">Sessions</th><th class="num">Failed logins</th><th class="num">Downloaded</th></tr></thead><tbody>` +
        d.users.map(u => `<tr class="click" data-u="${esc(u.k)}"><td>${esc(u.n)}</td><td><span class="badge c-${u.status}">${STATUS[u.status] || u.status}</span></td><td class="num">${fmtN(u.sess)}</td><td class="num">${fmtN(u.fails)}</td><td class="num">${fmtB(u.down)}</td></tr>`).join('') +
      `</tbody></table></div>` + (d.ips.length ? `<div class="tw"><table><thead><tr><th>Source IP</th><th>Country</th><th>Role</th><th class="num">Failed logins</th><th class="num">Sessions</th></tr></thead><tbody>` +
        d.ips.map(i => `<tr class="click" data-ip="${esc(i.ip)}"><td class="ip">${esc(i.ip)}</td><td>${esc(i.country || '')}</td><td>${esc(ROLE[i.role] || i.role || '')}</td><td class="num">${fmtN(i.fails)}</td><td class="num">${fmtN(i.sess)}</td></tr>`).join('') + '</tbody></table></div>' : '') +
      (d.hosts.length ? `<p>Internal hosts: ${d.hosts.slice(0, 30).map(hostRef).join(', ')}${d.hosts.length > 30 ? ` and ${d.hosts.length - 30} more` : ''}</p>` : '') + `</div>` +
      (d.sessions.length ? `<div class="sec"><h2>Suspicious VPN sessions</h2><div class="tw">${sessTable(d.sessions, '')}</div></div>` : '') +
      `<div class="sec"><h2>Steps with evidence</h2><p class="note">Go through each step, open its evidence and tick it as reviewed. Seq is the sequence number in your original CSV export.</p>${steps}</div>
      <div class="sec"><h2>Investigation notes</h2><textarea id="cr-notes" placeholder="What you checked, who you contacted, conclusion…">${esc(rv.notes || '')}</textarea></div>`;
    crProgress(); if(d.graph && $('#cr-flow')) flowGraph($('#cr-flow'), d.graph, {cap: 60}); dr.scrollTop = st;
  };
  $('#drawer').scrollTop = 0; drawerRender(); const c = $('#drawer .close'); c && c.focus({preventScroll:true});
}
document.addEventListener('change', e => {
  if(!CR.d || !e.target.closest('#drawer')) return;
  const rv = CR.d.review, t = e.target;
  if(t.id === 'cr-status') saveReview({status: t.value});
  else if(t.dataset.rvStep){ const k = t.dataset.rvStep; rv.steps_done = t.checked ? [...new Set([...rv.steps_done, k])] : rv.steps_done.filter(x => x !== k); saveReview({steps_done: rv.steps_done}); }
  else if(t.dataset.rvAct != null){ const a = CR.d.actions[+t.dataset.rvAct]; rv.actions_done = t.checked ? [...new Set([...rv.actions_done, a])] : rv.actions_done.filter(x => x !== a); saveReview({actions_done: rv.actions_done}); }
});
document.addEventListener('input', e => { if(e.target.id === 'cr-notes' && CR.d){ CR.d.review.notes = e.target.value; $('#cr-saved').textContent = 'Typing…'; saveNotes(); } });

/* ---------- drawer ---------- */
let drawerRender = null, lastFocus = null, drawerOpen = null;
function rangeText(){
  if(!rangeOn()) return '';
  const f = s => s ? niceDate(s) + (s.length > 10 ? ' ' + s.slice(11,16) : '') : '';
  const hrs = RANGE.h1 && RANGE.h2 ? `${RANGE.h1} to ${RANGE.h2} each day` : '';
  const t = RANGE.from && RANGE.to ? `${f(RANGE.from)} to ${f(RANGE.to)}` : RANGE.from ? `from ${f(RANGE.from)}` : RANGE.to ? `until ${f(RANGE.to)}` : '';
  return t && hrs ? `${t}, only ${hrs}` : (t || hrs);
}
const rangeBanner = () => rangeOn() ? `<p class="note" style="margin:0 0 12px">Figures limited to <b>${esc(rangeText())}</b>.</p>` : '';
const DS = {rows: [], total: 0, filter: null, hide: ''};
const fact = (v, l, c) => `<div class="fact ${c || ''}"><b>${v}</b><span>${l}</span></div>`;
function openDrawer(){ const dr = $('#drawer'); dr.classList.remove('wide'); if(dr.hidden) CR.d = null; if(dr.hidden) lastFocus = document.activeElement; dr.hidden = false; $('#scrim').hidden = false; document.body.style.overflow = 'hidden'; }
function closeDrawer(){ const wasCase = !!CR.d; if(CR.d && $('#cr-notes')){ saveReview({notes: $('#cr-notes').value}).then(() => { if(wasCase && !$('#v-cases').hidden) loadCases(); }); } CR.d = null; $('#drawer').hidden = true; $('#scrim').hidden = true; document.body.style.overflow = ''; drawerRender = null; drawerOpen = null; hideTip(); if(lastFocus && lastFocus.focus) lastFocus.focus({preventScroll:true}); }
function drawerSessions(){ return DS.rows.length ? sessTable(DS.rows, DS.hide) + (DS.total > DS.rows.length ? `<button class="more" data-dmore>Show more (${fmtN(DS.total - DS.rows.length)} left)</button>` : '') : '<p class="empty">No sessions.</p>'; }
async function drawerMore(){ const r = await api('/api/sessions', Object.assign({}, DS.filter, {limit: 200, offset: DS.rows.length})); DS.rows = DS.rows.concat(r.rows); $('#d-sess').innerHTML = drawerSessions(); }
async function openUser(key){
  drawerOpen = () => openUser(key);
  const t = tick('dr'); openDrawer(); $('#drawer').innerHTML = '<p class="loading">Loading account…</p>';
  let d; try { d = await api('/api/user', {key}); } catch(e){ $('#drawer').innerHTML = `<div class="dh"><h2>${esc(key)}</h2><button class="close" data-close>Close</button></div><p class="empty">${esc(e.message)}</p>`; return; }
  if(t !== TK.dr) return;
  DS.rows = d.sessions.rows; DS.total = d.sessions.total; DS.filter = {user: key, exact: 1}; DS.hide = 'u';
  TL.params = {user: key}; TL.shown = false;
  const u = d.user;
  const flagged = new Set(d.links.filter(l => l.role === 'attacker' || l.role === 'compromise').map(l => l.ip));
  const lanes = new Map(d.links.map(l => [l.ip, {label: l.ip, attr: `data-ip="${esc(l.ip)}"`, flag: flagged.has(l.ip), mono: true}]));
  const items = d.gantt.sess.map(r => ({lane:r[0], s:r[1], e:r[2], secs:r[3], up:r[4], down:r[5], open:r[6], inside:r[7]}));
  const fails = d.gantt.fails.map(r => ({lane:r[0], t:r[1]}));
  drawerRender = () => {
    const dr = $('#drawer'); const st = dr.scrollTop;
    dr.innerHTML = `<div class="dh"><div><h2>${esc(u.n)}</h2><p class="note"><span class="badge c-${u.status}">${STATUS[u.status]}</span> Risk ${u.risk}/100${u.groups.length ? ', group ' + esc(u.groups.join(', ')) : ''}</p></div><button class="close" data-close>Close</button></div>` +
      `<div class="row-actions"><button class="btn" data-act="map" data-q="${esc(u.key)}">Trace on map</button><button class="btn" data-act="sessions" data-user="${esc(u.key)}">Open in Sessions</button><button class="btn" data-inv-add="u:${esc(u.key)}">Investigate</button><button class="btn" data-act="events" data-user="${esc(u.n)}">Raw events</button><a class="btn" href="/api/export/sessions.csv?${qstr(withRange({user: u.key, exact: 1}))}">Export sessions CSV</a></div>` + rangeBanner() +
      `<div class="facts">${fact(fmtB(u.up), 'Uploaded by user', 'up')}${fact(fmtB(u.down), 'Downloaded by user', 'down')}${fact(fmtD(u.secs), 'Connected time')}${fact(fmtN(u.sess), 'Sessions')}${fact(fmtN(u.ips), 'Source IPs')}${fact(u.ccs.length ? esc(u.ccs.join(', ')) : '–', 'Countries')}${fact(fmtN(u.fails), 'Failed logins', u.fails ? 'bad' : '')}${fact(short(u.first), 'First seen')}${fact(short(u.last), 'Last seen')}</div>` +
      (d.incidents.length ? `<div class="sec"><h2>Findings <span class="count">${d.incidents.length}</span></h2>${d.incidents.map(incRow).join('')}</div>` : '') +
      `<div class="sec"><h2>Sessions by source IP</h2><p class="note">Each bar is one session; red marks IPs that attacked or were used in a compromise, ticks are failed logins.</p><div class="chart" id="d-gantt"></div></div>` +
      `<div class="sec"><div class="sec-h"><h2>Data per day</h2><div class="legend"><span><i class="sw" style="background:var(--up)"></i>Uploaded</span><span><i class="sw" style="background:var(--down)"></i>Downloaded</span><span><i class="sw" style="background:var(--crit)"></i>Failed logins</span></div></div><div class="chart" id="d-daily"></div></div>` +
      `<div class="sec"><h2>Source IPs</h2><div class="tw"><table><thead><tr><th>IP address</th><th>Country</th><th class="num">Sessions</th><th class="num">Connected</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th class="num">Failed logins</th></tr></thead><tbody>` +
      d.links.map(e => `<tr class="click" data-ip="${esc(e.ip)}"><td class="ip" ${flagged.has(e.ip) ? 'style="color:var(--crit)"' : ''}>${esc(e.ip)}</td><td>${esc(e.country || '–')}</td><td class="num">${fmtN(e.sess)}</td><td class="num">${fmtD(e.secs)}</td><td class="num up">${fmtB(e.up)}</td><td class="num down">${fmtB(e.down)}</td><td class="num">${fmtN(e.fails)}</td></tr>`).join('') + '</tbody></table></div></div>' +
      (d.access && d.access.length ? `<div class="sec"><h2>Internal servers reached <span class="count">${fmtN(new Set(d.access.map(a => a.dst_ip)).size)}</span></h2><div class="tw"><table><thead><tr><th>Host</th><th>Service</th><th class="num">Connections</th><th class="num">Blocked</th><th class="num">Data</th><th>First</th><th>Last</th></tr></thead><tbody>` +
        d.access.slice(0, 150).map(a => `<tr class="click" data-host="${esc(a.dst_ip)}"><td class="ip" ${a.role ? 'style="color:var(--high)"' : ''}>${esc(a.dst_ip)}</td><td>${portChips([a.dst_port])}</td><td class="num">${fmtN(a.conns)}</td><td class="num" ${a.blocked ? 'style="color:var(--crit)"' : ''}>${fmtN(a.blocked)}</td><td class="num">${fmtB(a.bytes)}</td><td>${short(a.first)}</td><td>${short(a.last)}</td></tr>`).join('') +
        `</tbody></table>${d.access.length > 150 ? '<p class="note">Showing the 150 busiest; open Internal hosts for all.</p>' : ''}</div></div>` : '') +
      (d.clients && d.clients.length ? `<div class="sec"><h2>VPN clients used</h2><div class="tw"><table><thead><tr><th>Client</th><th class="num">Sessions</th><th>First</th><th>Last</th></tr></thead><tbody>` +
        d.clients.map(c => `<tr><td>${esc(c.client)}</td><td class="num">${fmtN(c.n)}</td><td>${short(c.first)}</td><td>${short(c.last)}</td></tr>`).join('') + '</tbody></table></div></div>' : '') +
      (d.linked && d.linked.length ? `<div class="sec"><h2>IPs shared with linked accounts</h2><div id="d-venn" data-items="${esc([key].concat(d.linked.slice(0, 2).map(l => l.k)).join(','))}" data-mode="user"></div></div>` : '') +
      (d.linked && d.linked.length ? `<div class="sec"><h2>Linked accounts <span class="count">${d.linked.length}</span></h2><p class="note">Accounts sharing attacker infrastructure with this one.</p><div class="tw"><table><thead><tr><th>Account</th><th>Why linked</th></tr></thead><tbody>` +
        d.linked.map(l => `<tr class="click" data-u="${esc(l.k)}"><td>${esc(l.k)}</td><td>${l.why.map(esc).join('<br>')}</td></tr>`).join('') + '</tbody></table></div></div>' : '') +
      (d.logins && d.logins.length ? `<div class="sec"><h2>Assessed logins <span class="count">${d.logins.length}</span></h2>${d.logins.slice(0, 10).map(x => loginRow(x, 'u')).join('')}</div>` : '') +
      tlSection('d-tl') +
      `<div class="sec"><h2>Sessions <span class="count">${fmtN(DS.total)}</span></h2><div class="tw" id="d-sess">${drawerSessions()}</div></div>`;
    gantt($('#d-gantt'), items, fails, lanes); dailyChart($('#d-daily'), fillBuckets(d.daily, 'day'), true); restoreTimeline();
    { const dv = $('#d-venn'); if(dv) vennLoad(dv, dv.dataset.items.split(','), dv.dataset.mode); }
    dr.scrollTop = st;
  };
  $('#drawer').scrollTop = 0; drawerRender(); const c = $('#drawer .close'); c && c.focus({preventScroll:true});
}
async function openIp(ip){
  drawerOpen = () => openIp(ip);
  const t = tick('dr'); openDrawer(); $('#drawer').innerHTML = '<p class="loading">Loading IP…</p>';
  let d; try { d = await api('/api/ip', {ip}); } catch(e){ $('#drawer').innerHTML = `<div class="dh"><h2 class="ip">${esc(ip)}</h2><button class="close" data-close>Close</button></div><p class="empty">${esc(e.message)}</p>`; return; }
  if(t !== TK.dr) return;
  DS.rows = d.sessions.rows; DS.total = d.sessions.total; DS.filter = {ip}; DS.hide = 'ip';
  TL.params = {ip}; TL.shown = false;
  const x = d.ip, pr = d.probes;
  const lanes = new Map(Object.entries(d.names).map(([k, v]) => [k, {label: v.n, attr: `data-u="${esc(k)}"`, flag: v.status === 'compromise'}]));
  const items = d.gantt.sess.map(r => ({lane:r[0], s:r[1], e:r[2], secs:r[3], up:r[4], down:r[5], open:r[6], inside:r[7]}));
  const fails = d.gantt.fails.map(r => ({lane:r[0], t:r[1]}));
  drawerRender = () => {
    const dr = $('#drawer'); const st = dr.scrollTop;
    dr.innerHTML = `<div class="dh"><div><h2 class="ip">${esc(ip)}</h2><p class="note">${esc(x.country || 'Country unknown')} ${x.role ? `<span class="badge c-${x.role}">${ROLE[x.role]}</span>` : ''}${x.trusted ? ' <span class="badge">Trusted</span>' : ''}</p></div><button class="close" data-close>Close</button></div>` +
      `<div class="row-actions"><button class="btn" data-act="map" data-q="${esc(ip)}">Trace on map</button><button class="btn" data-act="sessions" data-ip="${esc(ip)}">Open in Sessions</button><button class="btn" data-inv-add="i:${esc(ip)}">Investigate</button><button class="btn" data-act="events" data-ipq="${esc(ip)}">Raw events</button><a class="btn" href="/api/export/sessions.csv?${qstr(withRange({ip}))}">Export sessions CSV</a></div>` + rangeBanner() +
      `<div class="facts">${fact(fmtN(x.users), 'Accounts connected')}${fact(fmtN(x.attacked), 'Accounts attacked', x.attacked ? 'bad' : '')}${fact(fmtN(x.fails), 'Failed logins', x.fails ? 'bad' : '')}${fact(fmtN(x.sess), 'Sessions')}${fact(fmtB(x.up), 'Uploaded', 'up')}${fact(fmtB(x.down), 'Downloaded', 'down')}${fact(fmtD(x.secs), 'Connected time')}${fact(short(x.first), 'First seen')}${fact(short(x.last), 'Last seen')}${pr && pr.n ? fact(fmtN(pr.n), `Blocked probes (${fmtN(pr.ports)} ports)`, 'bad') : ''}${d.admin ? fact(fmtN(d.admin), 'Firewall admin events', 'bad') : ''}</div>` +
      (d.incidents.length ? `<div class="sec"><h2>Findings <span class="count">${d.incidents.length}</span></h2>${d.incidents.map(incRow).join('')}</div>` : '') +
      (d.related && d.related.length ? `<div class="sec"><h2>Shared accounts with related IPs</h2><div id="d-venn" data-items="${esc([ip].concat(d.related.slice(0, 2).map(r => r.ip)).join(','))}" data-mode="ip"></div>
        <div class="row-actions"><button class="btn" data-vn-open="${esc([ip].concat(d.related.slice(0, 3).map(r => r.ip)).join(', '))}" data-vn-mode="ip">Open in Compare</button></div></div>` : '') +
      (d.related && d.related.length ? `<div class="sec"><h2>Related IPs <span class="count">${d.related.length}</span></h2>${d.campaign ? `<p><button class="chip s-critical" data-camp="${d.campaign}">Part of IP cluster #${d.campaign}</button></p>` : ''}<div class="tw"><table><thead><tr><th>IP</th><th>Country</th><th>Role</th><th class="num">Strength</th><th>Why linked</th></tr></thead><tbody>` +
        d.related.map(r => `<tr class="click" data-ip="${esc(r.ip)}"><td class="ip">${esc(r.ip)}</td><td>${esc(r.country)}</td><td>${r.role ? `<span class="badge c-${r.role}">${ROLE[r.role] || r.role}</span>` : ''}</td><td class="num">${r.w}</td><td>${r.why.map(esc).join('<br>')}</td></tr>`).join('') + '</tbody></table></div></div>' : '') +
      (d.logins && d.logins.length ? `<div class="sec"><h2>Logins after failed attempts from this IP <span class="count">${d.logins.length}</span></h2>${d.logins.slice(0, 10).map(x => loginRow(x, 'ip')).join('')}</div>` : '') +
      tlSection('d-tl') +
      `<div class="sec"><h2>Activity by account</h2><p class="note">Each bar is one session from this IP; red marks suspected compromised accounts, ticks are failed logins.</p><div class="chart" id="d-gantt"></div></div>` +
      `<div class="sec"><div class="sec-h"><h2>Data per day</h2></div><div class="chart" id="d-daily"></div></div>` +
      `<div class="sec"><h2>Accounts linked to this IP <span class="count">${fmtN(d.accounts_total)}</span></h2><div class="tw"><table><thead><tr><th>Account</th><th>Status</th><th class="num">Sessions</th><th class="num">Connected</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th class="num">Failed logins</th></tr></thead><tbody>` +
      d.accounts.map(a => `<tr class="click" data-u="${esc(a.k)}"><td>${esc(a.n)}</td><td><span class="badge c-${a.status}">${STATUS[a.status]}</span></td><td class="num">${fmtN(a.sess)}</td><td class="num">${fmtD(a.secs)}</td><td class="num up">${fmtB(a.up)}</td><td class="num down">${fmtB(a.down)}</td><td class="num">${fmtN(a.fails)}</td></tr>`).join('') + `</tbody></table>${d.accounts_total > d.accounts.length ? `<p class="note">Showing ${fmtN(d.accounts.length)} of ${fmtN(d.accounts_total)}.</p>` : ''}</div></div>` +
      `<div class="sec"><h2>Sessions <span class="count">${fmtN(DS.total)}</span></h2><div class="tw" id="d-sess">${drawerSessions()}</div></div>`;
    gantt($('#d-gantt'), items, fails, lanes); dailyChart($('#d-daily'), fillBuckets(d.daily, 'day'), true); restoreTimeline();
    { const dv = $('#d-venn'); if(dv) vennLoad(dv, dv.dataset.items.split(','), dv.dataset.mode); }
    dr.scrollTop = st;
  };
  $('#drawer').scrollTop = 0; drawerRender(); const c = $('#drawer .close'); c && c.focus({preventScroll:true});
}

/* ---------- navigation ---------- */
const VIEWS = ['overview','hunt','inv','cases','incidents','logins','camps','matrix','users','ips','hosts','sessions','events','admin','links'];
const LOADERS = {overview: renderOverview, hunt: () => loadHunt(), inv: () => { ivLoadSaved(); if(IV.items.length >= 2 && !IV.data) runConnect(); }, camps: () => loadCamps(), cases: () => loadCases(), incidents: () => loadIncidents(), logins: () => loadLogins(), matrix: () => loadMatrix(), users: () => loadUsers(), ips: () => loadIps(), hosts: () => loadHosts(), sessions: () => loadSessions(), events: () => loadEvents(), admin: () => loadAdmin(), links: drawGraph};
let cur = 'overview';
function show(v){
  cur = v; VIEWS.forEach(x => { $('#v-' + x).hidden = x !== v; $('#t-' + x).setAttribute('aria-selected', String(x === v)); });
  LOADERS[v](); try { localStorage.setItem('asa-live-view', v); } catch(e){}
}
document.querySelector('nav.tabs').addEventListener('click', e => { const b = e.target.closest('[data-v]'); if(b) show(b.dataset.v); });
document.addEventListener('click', e => {
  if(e.target.closest('#graph')) return;
  if(e.target.closest('[data-close]')){ closeDrawer(); return; }
  const ins = e.target.closest('[data-inside]'); if(ins){ openSessions({inside: ins.dataset.inside}); return; }
  const cs = e.target.closest('[data-case]'); if(cs){ openCase(+cs.dataset.case); return; }
  const co = e.target.closest('[data-country]'); if(co){ $('#i-q').value = co.dataset.country; $('#i-role').value = ''; show('ips'); window.scrollTo({top: $('nav.tabs').offsetTop - 4}); return; }
  if(e.target.closest('[data-print]')){ $$('#drawer details').forEach(d => d.open = true); window.print(); return; }
  if(e.target.closest('[data-load-tl]')){ TL.shown = true; loadTimeline($('#d-tl'), TL.params); return; }
  const hs = e.target.closest('[data-host]'); if(hs){ openHost(hs.dataset.host); return; }
  const sq = e.target.closest('[data-seqs]'); if(sq){ openEvents({seqs: sq.dataset.seqs}); return; }
  if(e.target.closest('[data-dmore]')){ drawerMore(); return; }
  const act = e.target.closest('[data-act]');
  if(act){ const a = act.dataset.act;
    if(a === 'map') traceOnMap(act.dataset.q);
    else if(a === 'sessions') openSessions({user: act.dataset.user, ip: act.dataset.ip, exact: !!act.dataset.user});
    else if(a === 'events') openEvents({user: act.dataset.user, ip: act.dataset.ipq, exact: !!act.dataset.user});
    return; }
  const ml = e.target.closest('[data-more-list]'); if(ml){ ({inc: loadIncidents, u: loadUsers, i: loadIps, s: loadSessions, e: loadEvents, c: loadCases, h: loadHosts, a: loadAdmin, l: loadLogins})[ml.dataset.moreList](true); return; }
  const go = e.target.closest('[data-go]'); if(go){ if(go.dataset.more){ if(go.dataset.go === 'users') $('#u-status').value = go.dataset.more; else $('#i-role').value = go.dataset.more; } show(go.dataset.go); window.scrollTo({top: $('nav.tabs').offsetTop - 4}); return; }
  const u = e.target.closest('[data-u]'); if(u){ openUser(u.dataset.u); return; }
  const ip = e.target.closest('[data-ip]'); if(ip){ openIp(ip.dataset.ip); return; }
});
$('#sevchips').addEventListener('click', e => { const b = e.target.closest('[data-sev]'); if(!b) return; const s = b.dataset.sev; incS.sev.has(s) ? incS.sev.delete(s) : incS.sev.add(s); loadIncidents(); });
$('#scrim').addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => { if(e.key === 'Escape' && !$('#drawer').hidden) closeDrawer(); });
const bind = (ids, fn) => ids.forEach(id => { const el = $('#' + id); el.addEventListener(el.type === 'search' || el.type === 'text' || el.type === 'number' ? 'input' : 'change', debounce(() => fn(), el.type === 'search' || el.type === 'text' || el.type === 'number' ? 350 : 0)); });
bind(['inc-q','inc-type','inc-sort'], loadIncidents);
bind(['c-q','c-sev','c-review'], loadCases);
bind(['l-q','l-verdict','l-sort'], loadLogins);
['wm-view','wm-metric','wm-arcs'].forEach(id => $('#' + id).addEventListener('change', drawWorldMap));
bind(['hu-status','hu-q','hu-sort'], loadHunt);
bind(['k-q'], loadCamps);
bind(['m-mode','m-q','m-lim','m-ku','m-ki','m-kh'], loadMatrix);
$('#heat-m').addEventListener('change', renderHeat);
bind(['h-q','h-sort','h-role'], loadHosts);
bind(['a-kind','a-user','a-q','a-sort'], loadAdmin);
bind(['u-q','u-sort','u-status'], loadUsers);
bind(['i-q','i-sort','i-role'], loadIps);
$('#s-user').addEventListener('input', () => { sS.exact = false; });
bind(['s-user','s-ip','s-inside','s-minup','s-sort'], loadSessions);
$('#e-user').addEventListener('input', () => { eS.exact = false; });
bind(['e-user','e-ip','e-inside','e-kind','e-q','e-seqs','e-sort'], loadEvents);
$('#s-clear').onclick = () => { ['user','ip','inside','minup'].forEach(k => $('#s-' + k).value = ''); sS.exact = false; loadSessions(); };
$('#e-clear').onclick = () => { ['user','ip','inside','kind','q','seqs'].forEach(k => $('#e-' + k).value = ''); eS.exact = false; loadEvents(); };
let rt, lastW = innerWidth;
addEventListener('resize', () => { if(Math.abs(innerWidth - lastW) < 30) return; lastW = innerWidth; clearTimeout(rt); rt = setTimeout(() => { if(cur === 'overview' && dailyCache){ drawDaily(); drawWorldMap(); } if(cur === 'links') drawGraph(); if(drawerRender && !$('#drawer').hidden) drawerRender(); }, 200); });

/* ---------- theme ---------- */
function setTheme(t){
  if(t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t); else { document.documentElement.removeAttribute('data-theme'); t = 'auto'; }
  try { localStorage.setItem('asa-theme', t); } catch(e){}
  document.querySelectorAll('#theme [data-theme-set]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.themeSet === t)));
}
$('#theme').addEventListener('click', e => { const b = e.target.closest('[data-theme-set]'); if(b) setTheme(b.dataset.themeSet); });
setTheme((() => { try { return localStorage.getItem('asa-theme') || 'auto'; } catch(e){ return 'auto'; } })());

/* ---------- global time range ---------- */
const toInput = s => s ? s.slice(0,16).replace(' ', 'T') : '';
function syncRangeUI(){
  $('#r-from').value = RANGE.from; $('#r-to').value = RANGE.to; $('#r-h1').value = RANGE.h1; $('#r-h2').value = RANGE.h2;
  const on = rangeOn(); $('#timebar').classList.toggle('on', on); $('#r-reset').hidden = !on;
  $('#r-note').innerHTML = on ? `Showing <b>${esc(rangeText())}</b> in every tab. Account status and risk are still judged on the whole log.`
                              : 'Filters every tab. Tip: click a day in the chart to zoom into it hour by hour.';
  const h = qstr(rp()); history.replaceState(null, '', h ? '#' + h : location.pathname);
}
function setRange(r, preset){
  Object.assign(RANGE, {from: r.from || '', to: r.to || '', h1: r.h1 != null ? r.h1 : RANGE.h1, h2: r.h2 != null ? r.h2 : RANGE.h2});
  $('#r-preset').value = preset != null ? preset : (RANGE.from || RANGE.to ? 'custom' : '');
  applyRange();
}
function applyRange(){
  syncRangeUI();
  dailyCache = null; incS.rows = []; cS.rows = []; lS.rows = []; hS.rows = []; aS.rows = []; uS.rows = []; iS.rows = []; sS.rows = []; eS.rows = [];
  loadSummary().then(() => { LOADERS[cur](); });
  if(drawerOpen && !$('#drawer').hidden) drawerOpen();
}
$('#r-preset').addEventListener('change', e => {
  const v = e.target.value, last = META && META.meta.last;
  if(!v) return setRange({from:'', to:''}, '');
  if(v === 'custom'){ $('#r-from').focus(); return; }
  const end = T(last), back = {'24h': 1, '7d': 7, '30d': 30}[v] * 86400e3;
  setRange({from: new Date(end - back).toISOString().slice(0,16), to: toInput(last)}, v);
});
['r-from','r-to'].forEach(id => $('#' + id).addEventListener('change', () => setRange({from: $('#r-from').value, to: $('#r-to').value})));
['r-h1','r-h2'].forEach(id => $('#' + id).addEventListener('change', () => {
  const a = $('#r-h1').value, b = $('#r-h2').value;
  if((a && b) || (!a && !b)) setRange({from: RANGE.from, to: RANGE.to, h1: a, h2: b}, $('#r-preset').value);
}));
$('#r-reset').onclick = () => setRange({from:'', to:'', h1:'', h2:''}, '');
(function readHash(){
  const h = new URLSearchParams(location.hash.slice(1));
  RANGE.from = toInput(h.get('from') || ''); RANGE.to = toInput(h.get('to') || '');
  RANGE.h1 = (h.get('h1') || '').slice(0,5); RANGE.h2 = (h.get('h2') || '').slice(0,5);
  $('#r-preset').value = RANGE.from || RANGE.to ? 'custom' : '';
})();

initGraph();
api('/api/meta', null, true).then(async m => {
  META = m; if(m.meta.title) { $('#title').textContent = m.meta.title; document.title = m.meta.title; }
  renderHeader(); syncRangeUI(); await loadSummary();
  let start = 'overview'; try { const s = localStorage.getItem('asa-live-view'); if(VIEWS.includes(s)) start = s; } catch(e){}
  show(start);
}).catch(() => {});
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    raise SystemExit(main())
