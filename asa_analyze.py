#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Incident tracking and dashboard for Cisco ASA VPN logs.

Step 1 (dates):     python3 asa_parse.py export.csv --outdir out [--geoip-mmdb GeoLite2-Country.mmdb]
Step 2 (analysis):  python3 asa_analyze.py out/events.db --outdir out

What step 2 does
----------------
* Rebuilds VPN sessions per user (start, end, duration, source IP, inside IP,
  uploaded / downloaded bytes, disconnect reason).
* Detects incidents:
    brute_force          many wrong passwords for one account
    password_spray       one IP trying many accounts
    coordinated_attack   several IPs linked (same targets, same network, hand-off, rotation) = one campaign
    suspicious_login     login with NO failures that does not look like the owner (stolen password)
    shared_new_ip        one new address used by several accounts for the first time
    compromise           successful login right after an attack
    attack_ip_login      successful login from an IP that attacked other accounts
    concurrent_sessions  same account connected from two IPs at the same time
    impossible_travel    country changes faster than possible (needs GeoIP)
    foreign_login        session from outside --home-countries (needs GeoIP)
    new_country          account suddenly used from a new country (needs GeoIP)
    shared_ip            several accounts connected from one IP
    large_download       big download in one session (possible data exfiltration)
    unusual_download     a day's download far above the account's own normal
    large_upload         big upload in one session (tool staging / data pushed in)
    large_transfer       big total transfer in one session
    long_session         unusually long session
    unusual_time         login at an hour this account normally never uses
    new_client           new VPN client platform for this account (other device/OS)
    account_lockout      account locked after failed logins
    internal_scan        VPN session touching many internal hosts/ports (needs 302013/302014 logs)
    lateral_movement     VPN session reaching many hosts over admin protocols (SMB, RDP, SSH, WinRM...)
    post_compromise      internal servers reached during a suspicious session
    port_scan            external IP probing many ports/hosts (needs deny logs)
    login_from_scanner   successful VPN login from an IP that scanned the firewall
    threat_detection     ASA threat detection flagged / shunned an IP
    admin_brute_force    repeated failed logins to the firewall management
    admin_login_internet firewall management login from a public IP
    logging_tampered     logging disabled or cleared on the firewall
    config_change        sensitive firewall configuration commands
Related incidents (same account or IP, close in time) are linked into cases.
* Writes CSV files (sessions, users, IPs, links, incidents), adds `sessions`
  and `incidents` tables to the DB and creates a self-contained dashboard.html.

Byte direction: ASA "Bytes rcv" = received FROM the client = uploaded by the
user. "Bytes xmt" = sent TO the client = downloaded by the user.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
import sqlite3
import sys
import time
import re
from bisect import bisect_left, bisect_right, insort
from collections import Counter, defaultdict
from typing import Iterable, Optional, Tuple

SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
MB = 1024 * 1024

ADMIN_PORTS = {22: "SSH", 23: "Telnet", 88: "Kerberos", 111: "RPCbind", 135: "RPC", 139: "NetBIOS", 161: "SNMP",
               389: "LDAP", 445: "SMB", 636: "LDAPS", 1433: "MSSQL", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
               5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
PORT_NAMES = {**ADMIN_PORTS, **{21: "FTP", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                                  443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 1521: "Oracle",
                                  8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Printer"}}
RE_ANTI_FORENSIC = re.compile(r"\b(clear\s+logging|no\s+logging|logging\s+disable|clear\s+configure\s+logging|"
                              r"write\s+erase|clear\s+configure\s+all)\b", re.I)
RE_SENSITIVE_CMD = re.compile(r"\b(username|password|passwd|access-list|access-group|aaa|tunnel-group|group-policy|"
                              r"crypto|webvpn|anyconnect|http\s+server|http\s+\d|ssh\s+\d|telnet|snmp-server|nat|"
                              r"route|shun|capture|copy|export|packet-tracer)\b", re.I)
TYPE_LABEL = {
    "brute_force": "Brute force", "password_spray": "Password spraying", "compromise": "Login after failed attempts",
    "attack_ip_login": "Login from attacking IP", "concurrent_sessions": "Simultaneous sessions",
    "impossible_travel": "Country change", "new_country": "New country", "foreign_login": "Login from abroad", "shared_ip": "Shared IP",
    "large_download": "Large download", "unusual_download": "Unusual download volume", "large_upload": "Large upload",
    "large_transfer": "Large transfer", "long_session": "Long session", "unusual_time": "Unusual login time",
    "new_client": "New VPN client", "account_lockout": "Account lockout", "internal_scan": "Internal scanning",
    "lateral_movement": "Lateral movement", "post_compromise": "Internal access after compromise",
    "coordinated_attack": "Coordinated attack (IP cluster)", "suspicious_login": "Suspicious login (no failures)",
    "shared_new_ip": "Same new IP, several accounts", "port_scan": "Port scan", "login_from_scanner": "Login from scanning IP", "threat_detection": "Threat detection",
    "admin_brute_force": "Admin brute force", "admin_login_internet": "Admin login from internet",
    "logging_tampered": "Logging tampered", "config_change": "Firewall config change"}


COUNTRY_NAMES = dict(x.split(":", 1) for x in (
    "AD:Andorra|AE:United Arab Emirates|AF:Afghanistan|AG:Antigua and Barbuda|AI:Anguilla|AL:Albania|AM:Armenia|"
    "AO:Angola|AQ:Antarctica|AR:Argentina|AS:American Samoa|AT:Austria|AU:Australia|AW:Aruba|AX:Aland Islands|"
    "AZ:Azerbaijan|BA:Bosnia and Herzegovina|BB:Barbados|BD:Bangladesh|BE:Belgium|BF:Burkina Faso|BG:Bulgaria|"
    "BH:Bahrain|BI:Burundi|BJ:Benin|BL:Saint Barthelemy|BM:Bermuda|BN:Brunei|BO:Bolivia|BQ:Caribbean Netherlands|"
    "BR:Brazil|BS:Bahamas|BT:Bhutan|BW:Botswana|BY:Belarus|BZ:Belize|CA:Canada|CC:Cocos Islands|CD:DR Congo|"
    "CF:Central African Republic|CG:Congo|CH:Switzerland|CI:Ivory Coast|CK:Cook Islands|CL:Chile|CM:Cameroon|"
    "CN:China|CO:Colombia|CR:Costa Rica|CU:Cuba|CV:Cape Verde|CW:Curacao|CX:Christmas Island|CY:Cyprus|"
    "CZ:Czechia|DE:Germany|DJ:Djibouti|DK:Denmark|DM:Dominica|DO:Dominican Republic|DZ:Algeria|EC:Ecuador|"
    "EE:Estonia|EG:Egypt|EH:Western Sahara|ER:Eritrea|ES:Spain|ET:Ethiopia|EU:European Union|FI:Finland|FJ:Fiji|"
    "FK:Falkland Islands|FM:Micronesia|FO:Faroe Islands|FR:France|GA:Gabon|GB:United Kingdom|GD:Grenada|"
    "GE:Georgia|GF:French Guiana|GG:Guernsey|GH:Ghana|GI:Gibraltar|GL:Greenland|GM:Gambia|GN:Guinea|"
    "GP:Guadeloupe|GQ:Equatorial Guinea|GR:Greece|GT:Guatemala|GU:Guam|GW:Guinea-Bissau|GY:Guyana|HK:Hong Kong|"
    "HN:Honduras|HR:Croatia|HT:Haiti|HU:Hungary|ID:Indonesia|IE:Ireland|IL:Israel|IM:Isle of Man|IN:India|"
    "IO:British Indian Ocean Territory|IQ:Iraq|IR:Iran|IS:Iceland|IT:Italy|JE:Jersey|JM:Jamaica|JO:Jordan|"
    "JP:Japan|KE:Kenya|KG:Kyrgyzstan|KH:Cambodia|KI:Kiribati|KM:Comoros|KN:Saint Kitts and Nevis|KP:North Korea|"
    "KR:South Korea|KW:Kuwait|KY:Cayman Islands|KZ:Kazakhstan|LA:Laos|LB:Lebanon|LC:Saint Lucia|"
    "LI:Liechtenstein|LK:Sri Lanka|LR:Liberia|LS:Lesotho|LT:Lithuania|LU:Luxembourg|LV:Latvia|LY:Libya|"
    "MA:Morocco|MC:Monaco|MD:Moldova|ME:Montenegro|MF:Saint Martin|MG:Madagascar|MH:Marshall Islands|"
    "MK:North Macedonia|ML:Mali|MM:Myanmar|MN:Mongolia|MO:Macao|MP:Northern Mariana Islands|MQ:Martinique|"
    "MR:Mauritania|MS:Montserrat|MT:Malta|MU:Mauritius|MV:Maldives|MW:Malawi|MX:Mexico|MY:Malaysia|"
    "MZ:Mozambique|NA:Namibia|NC:New Caledonia|NE:Niger|NF:Norfolk Island|NG:Nigeria|NI:Nicaragua|"
    "NL:Netherlands|NO:Norway|NP:Nepal|NR:Nauru|NU:Niue|NZ:New Zealand|OM:Oman|PA:Panama|PE:Peru|"
    "PF:French Polynesia|PG:Papua New Guinea|PH:Philippines|PK:Pakistan|PL:Poland|PM:Saint Pierre and Miquelon|"
    "PR:Puerto Rico|PS:Palestine|PT:Portugal|PW:Palau|PY:Paraguay|QA:Qatar|RE:Reunion|RO:Romania|RS:Serbia|"
    "RU:Russia|RW:Rwanda|SA:Saudi Arabia|SB:Solomon Islands|SC:Seychelles|SD:Sudan|SE:Sweden|SG:Singapore|"
    "SH:Saint Helena|SI:Slovenia|SK:Slovakia|SL:Sierra Leone|SM:San Marino|SN:Senegal|SO:Somalia|SR:Suriname|"
    "SS:South Sudan|ST:Sao Tome and Principe|SV:El Salvador|SX:Sint Maarten|SY:Syria|SZ:Eswatini|"
    "TC:Turks and Caicos Islands|TD:Chad|TG:Togo|TH:Thailand|TJ:Tajikistan|TK:Tokelau|TL:Timor-Leste|"
    "TM:Turkmenistan|TN:Tunisia|TO:Tonga|TR:Turkey|TT:Trinidad and Tobago|TV:Tuvalu|TW:Taiwan|TZ:Tanzania|"
    "UA:Ukraine|UG:Uganda|US:United States|UY:Uruguay|UZ:Uzbekistan|VA:Vatican City|"
    "VC:Saint Vincent and the Grenadines|VE:Venezuela|VG:British Virgin Islands|VI:US Virgin Islands|VN:Vietnam|"
    "VU:Vanuatu|WF:Wallis and Futuna|WS:Samoa|XK:Kosovo|YE:Yemen|YT:Mayotte|ZA:South Africa|ZM:Zambia|ZW:Zimbabwe"
).split("|"))


class GeoIP:
    """IP -> (country code, country name).

    Accepts either
      * a MaxMind GeoLite2/GeoIP2 Country or City .mmdb file (needs `pip install geoip2` or `pip install maxminddb`), or
      * an IP-range CSV such as DB-IP "IP to Country Lite" (start_ip,end_ip,country_code; free, no account,
        https://db-ip.com/db/download/ip-to-country-lite) or IP2Location LITE DB1 (integer ranges) - stdlib only.
    """

    def __init__(self, path: Optional[str]):
        self.reader = None          # truthy when lookups are possible
        self.kind = ""
        self.cache: dict = {}
        self._mm = None
        self._ranges = {}           # version -> (starts, ends, codes, names)
        if not path:
            return
        if not os.path.exists(path):
            print(f"[warn] GeoIP disabled: {path} not found", file=sys.stderr)
            return
        try:
            low = path.lower()
            if low.endswith((".csv", ".csv.gz")):
                self._load_csv(path)
                self.kind = "csv"
            else:
                try:
                    import geoip2.database  # type: ignore
                    self._mm = ("geoip2", geoip2.database.Reader(path))
                except ImportError:
                    import maxminddb  # type: ignore
                    self._mm = ("maxminddb", maxminddb.open_database(path))
                self.kind = "mmdb"
            self.reader = True
        except ImportError:
            print("[warn] GeoIP disabled: reading .mmdb needs 'pip install geoip2' (or maxminddb). Alternatively use "
                  "the free DB-IP country CSV, which needs no extra package.", file=sys.stderr)
        except Exception as e:
            print(f"[warn] GeoIP disabled: {e}", file=sys.stderr)

    def _load_csv(self, path):
        import gzip
        op = gzip.open if path.lower().endswith(".gz") else open
        data: dict = {4: [], 6: []}
        with op(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
            for row in csv.reader(f):
                if len(row) < 3:
                    continue
                a, b, cc = row[0].strip(), row[1].strip(), row[2].strip().upper()
                if not cc or cc == "-" or len(cc) != 2:
                    continue
                try:
                    if a.isdigit():                      # IP2Location style integer ranges
                        lo, hi = int(a), int(b)
                        ver = 4 if hi <= 0xFFFFFFFF else 6
                    else:
                        la, lb = ipaddress.ip_address(a), ipaddress.ip_address(b)
                        lo, hi, ver = int(la), int(lb), la.version
                except ValueError:
                    continue                             # header line etc.
                name = row[3].strip() if len(row) > 3 and row[3].strip() and not row[3].strip().isdigit() else ""
                data[ver].append((lo, hi, cc, name))
        for ver, lst in data.items():
            lst.sort()
            self._ranges[ver] = ([x[0] for x in lst], [x[1] for x in lst], [x[2] for x in lst], [x[3] for x in lst])
        if not data[4] and not data[6]:
            raise ValueError(f"no IP ranges recognised in {path}")

    def lookup(self, ip: str) -> Tuple[str, str]:
        ip = (ip or "").strip()
        if not ip or not self.reader:
            return ("", "Unknown")
        hit = self.cache.get(ip)
        if hit:
            return hit
        cc, name = "", "Unknown"
        try:
            a = ipaddress.ip_address(ip)
            if not (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_unspecified
                    or a.is_link_local):
                if self.kind == "csv":
                    r = self._ranges.get(a.version)
                    if r:
                        n = int(a)
                        i = bisect_right(r[0], n) - 1
                        if i >= 0 and r[0][i] <= n <= r[1][i]:
                            cc = r[2][i]
                            name = r[3][i] or COUNTRY_NAMES.get(cc, cc)
                elif self._mm[0] == "geoip2":
                    try:
                        resp = self._mm[1].country(ip)
                    except Exception:
                        resp = self._mm[1].city(ip)     # City databases also work
                    cc = (resp.country.iso_code or resp.registered_country.iso_code or "").upper()
                    name = resp.country.name or COUNTRY_NAMES.get(cc, "Unknown")
                else:
                    rec = self._mm[1].get(ip) or {}
                    c_ = rec.get("country") or rec.get("registered_country") or {}
                    cc = (c_.get("iso_code") or "").upper()
                    name = (c_.get("names") or {}).get("en") or COUNTRY_NAMES.get(cc, "Unknown")
        except Exception:
            cc, name = "", "Unknown"
        if not cc:
            name = "Unknown"
        if len(self.cache) < 500_000:
            self.cache[ip] = (cc, name)
        return (cc, name)


def svc(p):
    return PORT_NAMES.get(p) or (str(p) if p else "?")


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_link_local)
    except ValueError:
        return False


def runs(keys: list) -> list:
    """Group sorted integer bucket keys into runs of consecutive values."""
    out: list = []
    for k in keys:
        if out and k - out[-1][-1] <= 1:
            out[-1].append(k)
        else:
            out.append([k])
    return out


def P(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s)


def F(t: Optional[dt.datetime]) -> Optional[str]:
    return t.replace(microsecond=0).isoformat(sep=" ") if t else None


def hb(n: Optional[float]) -> str:
    if n is None:
        return ""
    x = float(n)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if x < 1024:
            return f"{x:.2f} {u}"
        x /= 1024
    return f"{x:.2f} PB"


def hd(sec: Optional[float]) -> str:
    if sec is None:
        return ""
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def bursts(items: list, gap: dt.timedelta) -> Iterable[list]:
    """Split time-sorted tuples (time first) wherever the pause is longer than gap."""
    cur: list = []
    for it in items:
        if cur and it[0] - cur[-1][0] > gap:
            yield cur
            cur = []
        cur.append(it)
    if cur:
        yield cur


class Trusted:
    def __init__(self, cidrs: list[str]):
        self.nets = []
        for c in cidrs:
            try:
                self.nets.append(ipaddress.ip_network(c.strip(), strict=False))
            except ValueError:
                print(f"[warn] ignoring invalid --trusted-ip {c!r}", file=sys.stderr)

    def __contains__(self, ip: str) -> bool:
        if not self.nets or not ip:
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets)



# ------------------------------------------------------------------------------------------------
# Case packages: evidence, summary and next steps for every case, saved in the DB and as files
# ------------------------------------------------------------------------------------------------

CASE_ACTIONS = {
    "compromise": ["Confirm with {users} whether the login from {ips} was really them (check the confidence "
                   "score and evidence list).",
                   "Reset the password of {users} and end their active VPN sessions.",
                   "Require MFA for VPN logins if it is not enforced yet."],
    "attack_ip_login": ["Treat {users} as compromised: reset the password and end active VPN sessions.",
                        "Block {ips} on the firewall (ACL or shun).",
                        "Require MFA for VPN logins if it is not enforced yet."],
    "login_from_scanner": ["Treat {users} as compromised: reset the password and end active VPN sessions.",
                           "Block {ips} on the firewall (ACL or shun)."],
    "password_spray": ["Block {ips} on the firewall (ACL or shun).",
                       "Check whether any sprayed account logged in successfully later (see timeline).",
                       "Consider geo-blocking or rate-limiting the VPN portal."],
    "brute_force": ["Block {ips} if they are not the user's own addresses.",
                    "Ask {users} whether they had login trouble at that time."],
    "account_lockout": ["Check with {users} whether the lockout was caused by themselves."],
    "concurrent_sessions": ["Ask {users} which of the two connections was theirs; reset the password if one was not."],
    "impossible_travel": ["Verify where {users} really was; a proxy/VPN service can also explain it."],
    "new_country": ["Verify with {users} that they were travelling."],
    "foreign_login": ["Verify with {users} that they were abroad; if not, treat the account as compromised.",
                      "Consider allowing VPN logins only from the countries where staff work."],
    "new_client": ["Ask {users} whether they used a new device or operating system."],
    "unusual_time": ["Ask {users} whether they worked at that time."],
    "large_download": ["Check file-server / application audit logs for what {users} accessed from the VPN address "
                       "during the session.", "Decide whether the volume matches their job."],
    "unusual_download": ["Check file-server / application audit logs for what {users} accessed that day."],
    "large_upload": ["Check what was written to internal servers ({hosts}) during the session "
                     "(new executables, archives, scripts)."],
    "internal_scan": ["Check the scanned internal hosts for follow-up logins from the VPN address (Windows event "
                      "4624/4625, SSH logs).", "Look for scanner software on the device used by {users}."],
    "lateral_movement": ["Check {hosts} for remote logons (RDP/SMB/WinRM) from the VPN address and for new "
                         "services or scheduled tasks.", "Isolate affected hosts if intrusion is confirmed."],
    "post_compromise": ["Review {hosts} with EDR / event logs for activity during the suspicious session.",
                        "Preserve evidence (memory, disk) on hosts that show changes before cleaning them."],
    "port_scan": ["Block {ips} on the firewall (ACL or shun)."],
    "suspicious_login": ["Ask {users} whether they logged in from {ips}; if not, the password was stolen "
                         "(phishing, malware, reuse): reset it, end sessions and check the device."],
    "shared_new_ip": ["Check whether {users} know each other's connection; if not, treat all as compromised.",
                      "Block {ips} if no one recognises it."],
    "coordinated_attack": ["Block all IPs of the campaign ({ips}), not only the loudest one.",
                           "Reset passwords of {users} and check their sessions from these IPs."],
    "threat_detection": ["Block {ips} on the firewall (ACL or shun)."],
    "admin_brute_force": ["Restrict firewall management (ssh/http/asdm) to trusted admin networks.",
                          "Change firewall admin passwords."],
    "admin_login_internet": ["Treat the firewall admin account {users} as compromised: change its password.",
                             "Restrict firewall management to trusted admin networks.",
                             "Compare the running configuration with the last known-good backup."],
    "logging_tampered": ["Collect logs for this period from the syslog server; the firewall's own buffer may be "
                         "incomplete.", "Re-enable logging and find out who ran the command."],
    "config_change": ["Review each command and roll back unauthorised changes.",
                      "Compare the running configuration with the last known-good backup."],
    "shared_ip": [], "long_session": [], "large_transfer": ["Check what {users} transferred during the session."],
}


def _fmt_list(xs, n=4):
    xs = list(xs)
    return ", ".join(xs[:n]) + (f" and {len(xs) - n} more" if len(xs) > n else "") if xs else "the accounts involved"


def case_actions(case, incs, names):
    """Next steps per finding, naming that finding's own accounts, IPs and hosts."""
    out: list = []
    for x in sorted(incs, key=lambda x: (SEV_ORDER[x["sev"]], x["start"])):
        users = _fmt_list(names.get(u, u) for u in x["users"][:6]) if x["users"] and x["n_users"] <= 6 \
            else "the accounts involved"
        ips = _fmt_list(x["ips"]) if x["ips"] else "the source IPs"
        hosts = _fmt_list(x.get("hosts") or case["hosts"]) if (x.get("hosts") or case["hosts"]) \
            else "the internal servers involved"
        for a in CASE_ACTIONS.get(x["type"], []):
            a = a.format(users=users, ips=ips, hosts=hosts)
            if a not in out:
                out.append(a)
    out.append("Record the outcome (confirmed / false positive) and close the case.")
    return out


def case_summary(case, incs, names, sessions, user_status, ip_role):
    comp = [names.get(u, u) for u in case["users"] if user_status.get(u) == "compromise"]
    att = [i for i in case["ips"] if ip_role.get(i) == "attacker"]
    sids = {x["sid"] for x in incs if x.get("sid")}
    ss = [sessions[i - 1] for i in sorted(sids)]
    parts = [f"{len(incs)} linked findings between {case['start']:%d %b %Y %H:%M} and {case['end']:%d %b %Y %H:%M}."]
    if att:
        parts.append(f"Attacking IP{'s' if len(att) > 1 else ''}: {_fmt_list(att)}.")
    if comp:
        parts.append(f"Account{'s' if len(comp) > 1 else ''} probably compromised: {_fmt_list(comp)}.")
    if ss:
        down = sum(s["down"] for s in ss)
        up = sum(s["up"] for s in ss)
        hosts = sum(s["int_hosts"] for s in ss)
        parts.append(f"{len(ss)} suspicious VPN session{'s' if len(ss) > 1 else ''} downloaded {hb(down)}, "
                     f"uploaded {hb(up)}" + (f" and reached {hosts} internal host(s)." if hosts else "."))
    if any(x["type"] in ("logging_tampered", "admin_login_internet") for x in incs):
        parts.append("The firewall itself was accessed or its logging changed, so the log may be incomplete.")
    parts.append("Steps in order: " + " > ".join(dict.fromkeys(TYPE_LABEL.get(x["type"], x["type"])
                                                                for x in sorted(incs, key=lambda x: x["start"]))) + ".")
    return " ".join(parts)


def gather_evidence(conn, x, has_flows, has_conns, max_ev=150, max_conn=300):
    """Evidence rows for one incident: (seq, ts, source, kind, text, raw)."""
    out: list = []
    seqs = [q for q in x["seqs"] if q is not None][:max_ev]
    if seqs:
        qs = ",".join("?" * len(seqs))
        for seq, ts, kind, raw in conn.execute(
                f"SELECT seq, ts, kind, raw FROM events WHERE seq IN ({qs}) ORDER BY ts, seq", seqs):
            out.append((seq, ts, "log", kind, "", raw or ""))
    s, e = F(x["start"] - dt.timedelta(minutes=1)), F(x["end"] + dt.timedelta(minutes=1))
    if has_flows and x["users"] and x["type"] in ("internal_scan", "lateral_movement", "post_compromise",
                                                   "large_download", "unusual_download", "large_upload"):
        order = "bytes DESC" if "download" in x["type"] or x["type"] == "large_upload" else "start"
        lim = 60 if order == "bytes DESC" else max_conn
        users = x["users"][:3]
        where = "session_id=?" if x.get("sid") and x["type"] == "post_compromise" else \
                f"user_key IN ({','.join('?' * len(users))}) AND start BETWEEN ? AND ?"
        args = [x["sid"]] if where.startswith("session_id") else users + [s, e]
        for seq, st, ts, vpn, dst, port, proto, b, dur, blk in conn.execute(
                f"SELECT conn_seq, start, ts, vpn_ip, dst_ip, dst_port, proto, bytes, duration_s, blocked FROM flows "
                f"WHERE {where} ORDER BY {order} LIMIT {lim}", args):
            txt = (f"{proto or ''} {vpn} -> {dst}:{port} ({svc(port)})" +
                   (" BLOCKED by firewall" if blk else f", {hd(dur)}, {hb(b)}"))
            out.append((seq, st, "connection", "BLOCKED" if blk else "CONNECTION", txt, ""))
    if has_conns and x["type"] == "port_scan" and x["ips"]:
        for seq, ts, proto, ip1, p1, ip2, p2, reason in conn.execute(
                "SELECT seq, ts, proto, ip1, p1, ip2, p2, reason FROM conns WHERE ip1=? AND action='deny' AND ts "
                f"BETWEEN ? AND ? ORDER BY ts LIMIT {max_conn}", (x["ips"][0], s, e)):
            out.append((seq, ts, "connection", "DENY",
                        f"{proto} {ip1}:{p1 or ''} -> {ip2}:{p2 or ''} ({svc(p2)}) denied by {reason}", ""))
    if "download" in x["type"] or x["type"] == "large_upload":
        # log lines in time order, then the biggest transfers first (they explain the volume)
        logs = sorted((r for r in out if r[2] == "log"), key=lambda r: (r[1] or "", r[0] or 0))
        return logs + [r for r in out if r[2] != "log"]
    out.sort(key=lambda r: (r[1] or "", r[0] or 0))
    return out


REPORT_CSS = """
:root{--fg:#1d2126;--mu:#5d6670;--ln:#d9dde2;--bg:#fff;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#4b6b8a}
@media (prefers-color-scheme:dark){:root{--fg:#e4e7eb;--mu:#9aa3ad;--ln:#353b43;--bg:#15181c;--crit:#f2756a;--high:#f59e5b;--med:#e3b341;--low:#8fb0cf}}
*{box-sizing:border-box}body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg);margin:0}
main{max-width:1000px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:1.6rem;margin:.2rem 0}h2{font-size:1.1rem;margin:28px 0 8px;border-bottom:1px solid var(--ln);padding-bottom:4px}
h3{font-size:1rem;margin:0}.mu{color:var(--mu)}.b{display:inline-block;font-size:.75rem;font-weight:600;border:1px solid;border-radius:3px;padding:0 6px;margin-right:6px}
.b.critical{color:var(--crit)}.b.high{color:var(--high)}.b.medium{color:var(--med)}.b.low{color:var(--low)}
table{border-collapse:collapse;width:100%;font-size:.86rem;margin:6px 0}th,td{text-align:left;border-bottom:1px solid var(--ln);padding:4px 8px 4px 0;vertical-align:top}
th{color:var(--mu);font-weight:500}.raw{font-family:ui-monospace,Consolas,monospace;font-size:.8rem;word-break:break-all}
.step{border-left:3px solid var(--ln);padding:2px 0 2px 14px;margin:18px 0}.step.critical{border-color:var(--crit)}
.step.high{border-color:var(--high)}.step.medium{border-color:var(--med)}.chk{list-style:none;padding:0}.chk li::before{content:"\\2610  "}
.box{border:1px solid var(--ln);border-radius:6px;padding:10px 14px}.nav a{color:inherit}
@media print{main{max-width:none;padding:0}.step{break-inside:avoid-page}a{color:inherit;text-decoration:none}}
"""


def write_case_files(folder, packages, title):
    os.makedirs(folder, exist_ok=True)
    for f in os.listdir(folder):            # remove reports from an earlier run
        if re.match(r"^(case_\d+.*\.(html|csv)|index\.html)$", f):
            os.remove(os.path.join(folder, f))
    E = html.escape
    idx_rows = []
    for p in packages:
        c = p["case"]
        slug = re.sub(r"[^A-Za-z0-9.]+", "_", c["who"])[:40].strip("_") or "case"
        base = f"case_{c['id']:03d}_{slug}"
        p["files"] = (base + ".html", base + "_evidence.csv")
        with open(os.path.join(folder, base + "_evidence.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["case", "step", "step_time", "finding", "severity", "seq", "time", "source", "kind", "text",
                        "raw_message"])
            for x in p["incs"]:
                for ev in p["evidence"].get(x["id"], []):
                    w.writerow([c["id"], x["id"], F(x["start"]), x["title"], x["sev"], *ev])
        steps = []
        for x in p["incs"]:
            ev = p["evidence"].get(x["id"], [])
            rows_ = "".join(f"<tr><td>{E(str(r[0] or ''))}</td><td>{E(r[1] or '')}</td><td>{E(r[3])}</td>"
                            f"<td class=raw>{E(r[5] or r[4])}</td></tr>" for r in ev[:100])
            more = f"<p class=mu>{len(ev) - 100} more rows in the evidence CSV.</p>" if len(ev) > 100 else ""
            steps.append(
                f"<div class='step {x['sev']}'><div class=mu>{F(x['start'])}"
                f"{' to ' + F(x['end']) if x['end'] != x['start'] else ''}</div><h3><span class='b {x['sev']}'>"
                f"{x['sev'].upper()}</span>{E(x['title'])}</h3><p>{E(x['detail'])}</p>"
                + (f"<p class=mu>Internal hosts: {E(', '.join(x.get('hosts', [])[:20]))}</p>" if x.get("hosts") else "")
                + (f"<table><tr><th>Seq</th><th>Time</th><th>Kind</th><th>Log line / connection</th></tr>{rows_}</table>{more}"
                   if ev else "<p class=mu>No individual log lines stored for this finding.</p>") + "</div>")
        st_lbl = {"compromise": "Suspected compromise", "review": "Needs review", "targeted": "Targeted", "watch": "Watch", "normal": "No findings"}
        ents = "".join(f"<tr><td>{E(a['n'])}</td><td>{E(st_lbl.get(a['status'], a['status']))}</td><td>{a['sess']}</td><td>{a['fails']}</td>"
                       f"<td>{hb(a['down'])}</td></tr>" for a in p["accounts"])
        ipt = "".join(f"<tr><td>{E(i['ip'])}</td><td>{E(i['country'] or '')}</td><td>{E({'attacker': 'Attack source', 'compromise': 'Used in compromise', 'shared': 'Shared by accounts'}.get(i['role'], i['role'] or ''))}</td>"
                      f"<td>{i['fails']}</td><td>{i['sess']}</td></tr>" for i in p["ips"])
        sess = "".join(f"<tr><td>{E(s['n'])}</td><td>{E(s['ip'])}</td><td>{E(s['inside'])}</td><td>{F(s['s'])}</td>"
                       f"<td>{hd(s['secs'])}</td><td>{hb(s['up'])}</td><td>{hb(s['down'])}</td><td>{s['int_hosts']}</td>"
                       f"<td>{E(s['client'])}</td></tr>" for s in p["sessions"])
        page = f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Case {c['id']}: {E(c['who'])}</title><style>{REPORT_CSS}</style><main>
<p class='mu nav'><a href="index.html">All cases</a> &middot; {E(title)}</p>
<p><span class='b {c['sev']}'>{c['sev'].upper()}</span><span class=mu>Case {c['id']} &middot; {F(c['start'])} to {F(c['end'])}
 &middot; generated {F(dt.datetime.now())}</span></p><h1>{E(c['who'])}</h1><p class=mu>{E(c['title'])}</p>
<div class=box><b>Summary.</b> {E(p['summary'])}</div>
<h2>Next steps</h2><ul class=chk>{''.join(f'<li>{E(a)}</li>' for a in p['actions'])}</ul>
<h2>Accounts</h2>{'<table><tr><th>Account</th><th>Status</th><th>Sessions</th><th>Failed logins</th><th>Downloaded</th></tr>' + ents + '</table>' if ents else '<p class=mu>None</p>'}
<h2>Source IPs</h2>{'<table><tr><th>IP</th><th>Country</th><th>Role</th><th>Failed logins</th><th>Sessions</th></tr>' + ipt + '</table>' if ipt else '<p class=mu>None</p>'}
{('<h2>Internal hosts</h2><p>' + E(', '.join(c['hosts'][:200])) + '</p>') if c['hosts'] else ''}
{('<h2>Suspicious sessions</h2><table><tr><th>Account</th><th>From</th><th>Inside IP</th><th>Start</th><th>Duration</th><th>Uploaded</th><th>Downloaded</th><th>Internal hosts</th><th>Client</th></tr>' + sess + '</table>') if sess else ''}
<h2>Timeline with evidence</h2><p class=mu>"Seq" is the sequence number from the original CSV export, so every line can be found in the source log.
Full evidence: <a href="{E(base)}_evidence.csv">{E(base)}_evidence.csv</a></p>
{''.join(steps)}
<h2>Review</h2><table><tr><th style="width:30%">Outcome</th><td>&#9744; Confirmed incident &nbsp; &#9744; False positive &nbsp; &#9744; Needs more data</td></tr>
<tr><th>Reviewed by / date</th><td>&nbsp;</td></tr><tr><th>Notes</th><td style="height:120px">&nbsp;</td></tr></table>
</main></html>"""
        with open(os.path.join(folder, base + ".html"), "w", encoding="utf-8") as f:
            f.write(page)
        idx_rows.append(f"<tr><td><span class='b {c['sev']}'>{c['sev'].upper()}</span></td><td><a href='{E(base)}.html'>"
                        f"Case {c['id']}: {E(c['who'])}</a><div class=mu>{E(c['title'])}</div></td><td>{F(c['start'])}</td>"
                        f"<td>{len(p['incs'])}</td><td><a href='{E(base)}_evidence.csv'>CSV</a></td></tr>")
    with open(os.path.join(folder, "index.html"), "w", encoding="utf-8") as f:
        f.write(f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Cases: {E(title)}</title><style>{REPORT_CSS}</style><main><h1>Cases to review</h1><p class=mu>{E(title)} &middot; generated {F(dt.datetime.now())}.
Each case links related findings and lists the log lines that prove them.</p>
<table><tr><th></th><th>Case</th><th>Start</th><th>Findings</th><th>Evidence</th></tr>{''.join(idx_rows) or '<tr><td colspan=5>No cases.</td></tr>'}</table></main></html>""")


def main() -> int:
    ap = argparse.ArgumentParser(description="Incident tracking + dashboard for ASA events.db")
    ap.add_argument("db", nargs="?", default="out/events.db", help="events.db created by asa_parse.py")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--title", default="VPN incident review")
    ap.add_argument("--trusted-ip", action="append", default=[],
                    help="IP or CIDR of your own egress/NAT (excluded from shared-IP and country checks)")

    d = ap.add_argument_group("detection thresholds")
    d.add_argument("--bf-min", type=int, default=10, help="Failed logins for one account to count as brute force")
    d.add_argument("--bf-pause-min", type=float, default=15, help="A pause longer than this ends a brute-force burst")
    d.add_argument("--spray-min-users", type=int, default=5, help="Accounts one IP must try to count as spraying")
    d.add_argument("--spray-pause-min", type=float, default=60, help="A pause longer than this ends a spray burst")
    d.add_argument("--comp-min-fails", type=int, default=5, help="Failures before a success that flag a compromise")
    d.add_argument("--comp-window-min", type=float, default=60,
                   help="How far back failures for the same account (from any IP) are counted")
    d.add_argument("--login-window-hours", type=float, default=24,
                   help="How far back failures from the same IP are counted before a successful login")
    d.add_argument("--nofail-compromise-score", type=int, default=80,
                   help="Logins without failed attempts: score for 'compromised' (default 80, stricter than 70)")
    d.add_argument("--nofail-likely-score", type=int, default=55, help="... for 'likely compromised' (default 55)")
    d.add_argument("--nofail-review-score", type=int, default=40, help="... for 'needs review' (default 40)")
    d.add_argument("--concurrent-min-minutes", type=float, default=10,
                   help="Minimum overlap of two sessions from different IPs to report (default 10)")
    d.add_argument("--campaign-min-fails", type=int, default=3,
                   help="Failed logins an IP needs before it can be linked to other IPs (default 3)")
    d.add_argument("--campaign-min-weight", type=int, default=2,
                   help="Evidence needed to link two IPs into one campaign (default 2)")
    d.add_argument("--login-compromise-score", type=int, default=70, help="Score for 'compromised' (default 70)")
    d.add_argument("--login-likely-score", type=int, default=45, help="Score for 'likely compromised' (default 45)")
    d.add_argument("--login-review-score", type=int, default=25,
                   help="Score for 'needs review' (default 25); lower scores count as a user typo")
    d.add_argument("--travel-hours", type=float, default=4, help="Country change within this time is flagged")
    d.add_argument("--geoip", default="",
                   help="Country database (GeoLite2-Country.mmdb or free DB-IP country CSV). Adds countries "
                        "without re-importing the log.")
    d.add_argument("--home-countries", default="",
                   help="Country codes where VPN logins are expected, e.g. CZ,SK. Logins from elsewhere are flagged.")
    d.add_argument("--new-country-baseline", type=int, default=5, help="Sessions needed before a new country is unusual")
    d.add_argument("--shared-ip-min-users", type=int, default=2, help="Accounts from one IP to flag it as shared")
    d.add_argument("--exfil-download-mb", type=float, default=2048,
                   help="Download in one session flagged as possible exfiltration (default 2048)")
    d.add_argument("--large-upload-mb", type=float, default=1024, help="Upload in one session flagged (default 1024)")
    d.add_argument("--spike-factor", type=float, default=5, help="Daily download this many times the usual = unusual")
    d.add_argument("--spike-min-mb", type=float, default=1024, help="...and at least this much (default 1024)")
    d.add_argument("--work-hours", default="07-20", help="Normal working hours for unusual-time checks (default 07-20)")
    d.add_argument("--time-baseline", type=int, default=20, help="Sessions needed before unusual time is judged")
    d.add_argument("--scan-hosts", type=int, default=30, help="Internal hosts in 10 min counted as scanning")
    d.add_argument("--scan-ports", type=int, default=50, help="Ports on one host in 10 min counted as scanning")
    d.add_argument("--lateral-hosts", type=int, default=8, help="Hosts over admin protocols in 1 h = lateral movement")
    d.add_argument("--port-scan-min", type=int, default=20, help="Denied ports/hosts in 10 min from one IP = port scan")
    d.add_argument("--admin-bf-min", type=int, default=5, help="Failed firewall admin logins counted as brute force")
    d.add_argument("--case-window-hours", type=float, default=48, help="Incidents this close are linked into a case")
    d.add_argument("--large-transfer-mb", type=float, default=5120, help="Total transfer in one session flagged")
    d.add_argument("--long-session-hours", type=float, default=12, help="Session length flagged as long")

    o = ap.add_argument_group("dashboard")
    o.add_argument("--dashboard", default="", help="Output HTML path (default OUTDIR/dashboard.html)")
    o.add_argument("--max-dashboard-sessions", type=int, default=200_000)
    o.add_argument("--max-fail-points-per-user", type=int, default=300)
    o.add_argument("--no-case-files", action="store_true",
                   help="Do not write the case reports (OUTDIR/cases/*.html + evidence CSV)")
    o.add_argument("--no-html", action="store_true",
                   help="Skip the static dashboard.html (use asa_server.py for the live dashboard)")
    o.add_argument("--no-web-fonts", action="store_true", help="Do not load fonts from Google (fully offline file)")
    args = ap.parse_args()

    t_start = time.perf_counter()
    if not os.path.exists(args.db):
        print(f"[error] DB not found: {args.db} (run asa_parse.py first)", file=sys.stderr)
        return 2
    os.makedirs(args.outdir, exist_ok=True)
    trusted = Trusted(args.trusted_ip)

    conn = sqlite3.connect(args.db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    if "ts" not in cols:
        print("[error] events table missing - run asa_parse.py first", file=sys.stderr)
        return 2

    # ------------------------------------------------------------------ load
    names: dict[str, str] = {}

    def ukey(u: str) -> str:
        u = (u or "").strip()
        if not u:
            return ""
        k = u.lower()
        names.setdefault(k, u)
        return k

    geo: dict[str, tuple[str, str]] = {}
    fails: list[tuple] = []                       # (t, user, ip, seq, reason)
    starts: dict[tuple, list] = defaultdict(list)  # (user, ip) -> [(t, seq, group, inside)]
    discs: list[tuple] = []
    user_times: dict[str, list] = defaultdict(list)
    seen_ips: set = set()
    clients: list[tuple] = []   # (t, user, ip, client string, seq)
    lockouts: list[tuple] = []
    mgmt: list[tuple] = []      # firewall management: (t, kind, user, ip, detail, seq)
    threats: list[tuple] = []
    n_events = 0
    first_t = last_t = None

    q = conn.execute(
        "SELECT seq, ts, kind, user, vpn_group, outside_ip, inside_ip, cc, country, "
        "duration_s, bytes_xmt, bytes_rcv, reason FROM events WHERE ts IS NOT NULL AND kind <> 'OTHER' "
        "ORDER BY ts, seq")
    for seq, ts, kind, user, grp, oip, iip, cc, country, dur, bx, br, reason in q:
        t = P(ts)
        n_events += 1
        first_t = first_t or t
        last_t = t
        u = ukey(user)
        ip = (oip or "").strip()
        if ip:
            seen_ips.add(ip)
        if ip and country and country != "Unknown":
            geo[ip] = (cc or "", country)
        if u:
            user_times[u].append(t)
        if kind == "INVALID_PW":
            fails.append((t, u, ip, seq, reason or ""))
        elif kind in ("PARENT_STARTED", "ASSIGNED") and u:
            starts[(u, ip)].append((t, seq, grp or "", (iip or "").strip() if kind == "ASSIGNED" else ""))
        elif kind == "DISCONNECTED" and u:
            discs.append((t, u, ip, grp or "", dur, bx, br, reason or "", seq))
        elif kind == "CLIENT_INFO" and u:
            clients.append((t, u, ip, reason or "", seq))
        elif kind == "LOCKOUT" and u:
            lockouts.append((t, u, reason or "", seq))
        elif kind in ("MGMT_LOGIN_OK", "MGMT_LOGIN_FAIL", "CONFIG_CMD", "PRIV_CHANGE"):
            mgmt.append((t, kind, u, ip, reason or "", seq))
        elif kind == "THREAT":
            threats.append((t, ip, reason or "", seq))

    if not n_events:
        print("[error] no events with timestamps in DB", file=sys.stderr)
        return 1
    log_end = last_t

    G = GeoIP(args.geoip) if args.geoip else None
    if G and G.reader:
        found = 0
        for ip in seen_ips:
            cc_, nm_ = G.lookup(ip)
            if cc_:
                geo[ip] = (cc_, nm_)
                found += 1
        conn.executemany("UPDATE events SET cc=?, country=? WHERE outside_ip=?",
                         ((cc_, nm_, ip) for ip, (cc_, nm_) in geo.items()))
        conn.commit()
        print(f"  - Countries found for {found:,} of {len(seen_ips):,} source IPs ({G.kind} database)",
              file=sys.stderr)
    home = {x.strip().upper() for x in args.home_countries.split(",") if x.strip()}

    def geo_of(ip):
        if ip not in geo and G and G.reader:
            cc_, nm_ = G.lookup(ip)
            if cc_:
                geo[ip] = (cc_, nm_)
        return geo.get(ip, ("", ""))

    # ------------------------------------------------------------- sessions
    sessions: list[dict] = []
    start_times = {k: [x[0] for x in v] for k, v in starts.items()}
    used = {k: [False] * len(v) for k, v in starts.items()}

    for t, u, ip, grp, dur, bx, br, reason, seq in discs:
        dur = int(dur or 0)
        s = t - dt.timedelta(seconds=dur)
        inside = ""
        k = (u, ip)
        if k in starts:
            lo = bisect_left(start_times[k], s - dt.timedelta(seconds=120))
            hi = bisect_right(start_times[k], t)
            for i in range(lo, hi):
                used[k][i] = True
                inside = starts[k][i][3] or inside
                grp = grp or starts[k][i][2]
        sessions.append(dict(u=u, ip=ip, s=s, e=t, secs=dur, up=int(br or 0), down=int(bx or 0),
                             inside=inside, g=grp, reason=reason, open=False, seq=seq))

    for k, lst in starts.items():
        u, ip = k
        cluster: list = []
        pending_clusters = []
        for i, item in enumerate(lst):
            if used[k][i]:
                continue
            if cluster and item[0] - cluster[-1][0] > dt.timedelta(minutes=5):
                pending_clusters.append(cluster)
                cluster = []
            cluster.append(item)
        if cluster:
            pending_clusters.append(cluster)
        for c in pending_clusters:
            s = c[0][0]
            ut = user_times[u]
            j = bisect_right(ut, c[-1][0])
            e = ut[j] if j < len(ut) else log_end
            inside = next((x[3] for x in c if x[3]), "")
            sessions.append(dict(u=u, ip=ip, s=s, e=e, secs=int((e - s).total_seconds()), up=0, down=0,
                                 inside=inside, g=c[0][2], reason="No disconnect logged (end estimated)",
                                 open=True, seq=c[0][1]))

    sessions.sort(key=lambda x: (x["s"], x["seq"]))
    s_by_user: dict[str, list] = defaultdict(list)
    for s in sessions:
        s_by_user[s["u"]].append(s)
    s_by_ip: dict[str, list] = defaultdict(list)
    for s in sessions:
        if s["ip"]:
            s_by_ip[s["ip"]].append(s)
    for i, s in enumerate(sessions, 1):
        s.update(id=i, client="", int_conns=0, int_bytes=0, blocked=0)
    sess_hosts: dict[int, Counter] = defaultdict(Counter)   # session id -> internal host -> connections
    sess_ports: dict[int, set] = defaultdict(set)

    # AnyConnect client string (722055) -> session
    cl_by_user: dict[str, list] = defaultdict(list)
    for c_ in clients:
        cl_by_user[c_[1]].append(c_)
    for u, ss in s_by_user.items():
        cl = cl_by_user.get(u)
        if not cl:
            continue
        ct = [x[0] for x in cl]
        for s in ss:
            lo = bisect_left(ct, s["s"] - dt.timedelta(seconds=120))
            hi = bisect_right(ct, min(s["e"], s["s"] + dt.timedelta(minutes=10)))
            for i in range(lo, hi):
                if not cl[i][2] or cl[i][2] == s["ip"]:
                    s["client"] = cl[i][3]
                    break

    # internal connections (302013-302016 + denies) -> the VPN user holding that inside IP at that moment
    by_inside: dict[str, list] = defaultdict(list)
    for s in sessions:
        if s["inside"]:
            by_inside[s["inside"]].append(s)
    ins_starts = {k: [x["s"] for x in v] for k, v in by_inside.items()}
    slack = dt.timedelta(seconds=90)

    def owner(ip, t):
        lst = by_inside.get(ip)
        if not lst:
            return None
        i = bisect_right(ins_starts[ip], t + slack) - 1
        for j in range(i, max(i - 4, -1), -1):
            if lst[j]["s"] - slack <= t <= lst[j]["e"] + slack:
                return lst[j]
        return None

    conn.executescript("""
        DROP TABLE IF EXISTS flows;
        CREATE TABLE flows(user_key TEXT, session_id INTEGER, start TEXT, ts TEXT, vpn_ip TEXT, dst_ip TEXT,
            dst_port INTEGER, proto TEXT, bytes INTEGER, duration_s INTEGER, blocked INTEGER, conn_seq INTEGER);
    """)
    uflows: dict[str, list] = defaultdict(list)      # user -> (start, dst, port, blocked, bytes, session)
    access: dict[tuple, list] = {}                     # (user, dst, port, proto) -> [conns, blocked, bytes, secs, first, last]
    ext_denies: list[tuple] = []                       # (t, src, dst, port, seq) not tied to a VPN user
    n_conn_rows = n_attr = 0
    has_conns = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='conns'").fetchone()
    if has_conns:
        has_td = conn.execute("SELECT 1 FROM conns WHERE action='teardown' LIMIT 1").fetchone()
        acts = "('teardown','deny')" if has_td else "('built','deny')"
        fbatch: list = []
        for ts, action, proto, ip1, p1, ip2, p2, ident, cdur, cbytes, seq in conn.execute(
                "SELECT ts, action, proto, ip1, p1, ip2, p2, ident, duration_s, bytes, seq FROM conns "
                f"WHERE ts IS NOT NULL AND action IN {acts} ORDER BY ts"):
            n_conn_rows += 1
            t = P(ts)
            cdur = int(cdur or 0)
            st = t - dt.timedelta(seconds=cdur) if action == "teardown" else t
            s = None
            if ip1 in by_inside:
                s = owner(ip1, st)
                vpn, dst, dport = ip1, ip2, p2
            if s is None and ip2 in by_inside:
                s = owner(ip2, st)
                if s:
                    vpn, dst, dport = ip2, ip1, p1
            u = s["u"] if s else None
            if u is None and ident and ident.lower() in names:
                u = ident.lower()
                vpn, dst, dport = (ip2, ip1, p1) if ip2 in by_inside and ip1 not in by_inside else (ip1, ip2, p2)
            if u is None:
                if action == "deny":
                    ext_denies.append((t, ip1, ip2, p2, seq))
                continue
            n_attr += 1
            blocked = action == "deny"
            b = int(cbytes or 0)
            fbatch.append((u, s["id"] if s else None, F(st), ts, vpn, dst, dport, proto, b, cdur, int(blocked), seq))
            if len(fbatch) >= 20000:
                conn.executemany("INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", fbatch)
                fbatch.clear()
            a = access.get((u, dst, dport, proto))
            if a is None:
                a = access[(u, dst, dport, proto)] = [0, 0, 0, 0, st, t]
            a[0] += 1
            a[1] += int(blocked)
            a[2] += b
            a[3] += cdur
            a[5] = t
            uflows[u].append((st, dst, dport, blocked, b, s))
            if s:
                s["int_conns"] += 1
                s["int_bytes"] += b
                s["blocked"] += int(blocked)
                sess_hosts[s["id"]][dst] += 1
                if dport:
                    sess_ports[s["id"]].add(dport)
        if fbatch:
            conn.executemany("INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", fbatch)
        conn.executescript("""
            CREATE INDEX idx_f_user ON flows(user_key, start);
            CREATE INDEX idx_f_dst ON flows(dst_ip, start);
            CREATE INDEX idx_f_sess ON flows(session_id);
            CREATE INDEX idx_f_start ON flows(start);
        """)
        conn.commit()
    for s in sessions:
        s["int_hosts"] = len(sess_hosts.get(s["id"], ()))

    # ------------------------------------------------------------ incidents
    incidents: list[dict] = []

    def add(typ, sev, title, detail, start, end, users=(), ips=(), seqs=(), count=None, hosts=(), sid=None):
        users = sorted(set(u for u in users if u))
        ips = sorted(set(i for i in ips if i))
        incidents.append(dict(type=typ, sev=sev, title=title, detail=detail, start=start, end=end,
                              users=users, ips=ips, seqs=[q for q in seqs if q is not None][:60], count=count,
                              n_users=len(users), hosts=list(dict.fromkeys(hosts))[:100], sid=sid))

    fails_by_user: dict[str, list] = defaultdict(list)
    fails_by_ip: dict[str, list] = defaultdict(list)
    for f in fails:
        if f[1]:
            fails_by_user[f[1]].append(f)
        if f[2]:
            fails_by_ip[f[2]].append(f)

    # ---------------- noise model: what is normal for each account ----------------
    # Many false positives come from ordinary users: dynamic home IPs that change within the same provider,
    # mobile-carrier NAT addresses shared by many people, users mistyping and then getting in.
    if not home and geo:                         # no --home-countries: infer them from where people connect
        cc_cnt = Counter(geo_of(s["ip"])[0] for s in sessions if geo_of(s["ip"])[0])
        tot_cc = sum(cc_cnt.values())
        home = {cc_ for cc_, k in cc_cnt.most_common(3) if tot_cc and k / tot_cc >= 0.05}
        if home:
            print(f"  - Home countries inferred from the log: {', '.join(sorted(home))} "
                  f"(set --home-countries to override)", file=sys.stderr)

    def net_of(ip):
        """Provider-sized network (IPv4 /16, IPv6 /32): dynamic addresses of one ISP usually stay inside it."""
        try:
            a_ = ipaddress.ip_address(ip)
            return str(ipaddress.ip_network(f"{ip}/{16 if a_.version == 4 else 32}", strict=False))
        except ValueError:
            return ip
    reg_days: dict = defaultdict(set)
    net_days: dict = defaultdict(set)
    u_cc: dict = defaultdict(Counter)
    sess_start_ui: dict = defaultdict(list)
    for s in sessions:
        reg_days[(s["u"], s["ip"])].add(s["s"].date())
        net_days[(s["u"], net_of(s["ip"]))].add(s["s"].date())
        sess_start_ui[(s["u"], s["ip"])].append(s["s"])
        if geo_of(s["ip"])[0]:
            u_cc[s["u"]][geo_of(s["ip"])[0]] += 1
    for v_ in sess_start_ui.values():
        v_.sort()
    # An address the account first reached only after a run of failures from it was earned by guessing:
    # it never counts as the account's own address, even if the attacker comes back on other days.
    f_ui: dict = defaultdict(list)
    for f in fails:
        if f[1]:
            f_ui[(f[1], f[2])].append(f[0])
    tainted = set()
    for k, starts_ in sess_start_ui.items():
        ft_ = f_ui.get(k)
        if ft_:
            first = starts_[0]
            if sum(1 for t_ in ft_ if first - dt.timedelta(hours=24) <= t_ <= first) >= args.comp_min_fails:
                tainted.add(k)
    regular = {k for k, d_ in reg_days.items() if len(d_) >= 2 and k not in tainted}   # the account's own addresses

    def resolved(f):
        """A failed login followed by a successful one from the same IP within 30 minutes: a typo."""
        lst = sess_start_ui.get((f[1], f[2]))
        if not lst:
            return False
        i = bisect_left(lst, f[0])
        return i < len(lst) and lst[i] - f[0] <= dt.timedelta(minutes=30)
    regular_fail = {f[3] for f in fails if f[1] and (f[1], f[2]) in regular}
    typo_fail = {f[3] for f in fails if f[1] and f[3] not in regular_fail and resolved(f)}
    noise_fail = regular_fail | typo_fail
    afails_by_ip = {ip: [x for x in lst if x[3] not in noise_fail] for ip, lst in fails_by_ip.items()}
    print(f"  - Failed logins judged as ordinary user typos: {len(noise_fail):,} of {len(fails):,}", file=sys.stderr)

    attack_ips: set[str] = set()   # sprayed several accounts
    brute_ips: set[str] = set()    # brute forced one account

    bf_gap = dt.timedelta(minutes=args.bf_pause_min)
    for u, lst in fails_by_user.items():
        lst = [x for x in lst if x[3] not in regular_fail]
        for b in bursts(lst, bf_gap):
            if len(b) < args.bf_min:
                continue
            ips = {x[2] for x in b}
            per_ip = Counter(x[2] for x in b)
            brute_ips.update(ip for ip, c in per_ip.items() if c >= args.bf_min)
            sev = "high" if len(ips) >= 3 or len(b) >= args.bf_min * 5 else "medium"
            mins = max(1, round((b[-1][0] - b[0][0]).total_seconds() / 60))
            add("brute_force", sev, f"{len(b)} wrong passwords for {names[u]}",
                f"{len(b)} failed logins in {mins} min from {len(ips)} IP address(es).",
                b[0][0], b[-1][0], [u], ips, [x[3] for x in b], len(b))

    sp_gap = dt.timedelta(minutes=args.spray_pause_min)
    for ip, lst in afails_by_ip.items():
        for b in bursts(lst, sp_gap):
            us = {x[1] for x in b if x[1]}
            if len(us) < args.spray_min_users:
                continue
            attack_ips.add(ip)
            real = [x for x in us if x in s_by_user]
            add("password_spray", "high", f"Password spraying from {ip}",
                f"{len(b)} failed logins against {len(us)} accounts"
                f" ({len(real)} of them are real VPN users with sessions).",
                b[0][0], b[-1][0], (real or list(us))[:300], [ip], [x[3] for x in b], len(b))

    # ---------------- connections between IPs -> campaigns ----------------
    # Two suspicious IPs are linked when they tried largely the same accounts, failed against the same account
    # within 30 minutes, sit in the same /24 (or /48) network, or when one IP failed for an account and another
    # IP then logged in as that account ("hand-off"). Linked IPs form campaigns.
    cmp_w = dt.timedelta(hours=args.login_window_hours)
    # a user mistyping at home is not an attack: ignore failures from an account's own regular address
    sus_ips = {ip for ip, lst in afails_by_ip.items() if ip and ip not in trusted and len(lst) >= args.campaign_min_fails}
    tgt = {ip: {x[1] for x in afails_by_ip[ip] if x[1]} for ip in sus_ips}
    ip_links: dict = {}

    def link(a, b, kind, w, detail):
        if not a or not b or a == b:
            return
        k = (a, b) if a < b else (b, a)
        e = ip_links.setdefault(k, dict(kinds={}, w=0))
        if kind not in e["kinds"]:
            e["kinds"][kind] = detail
            e["w"] += w
        elif kind in ("cofail", "handoff") and detail not in e["kinds"][kind] and len(e["kinds"][kind]) < 200:
            e["kinds"][kind] += "; " + detail       # several accounts: keep listing them
            e["w"] += 1 if kind == "cofail" else 2

    # a) shared targets (skip names that half the internet tries, e.g. 'admin')
    u_ips: dict = defaultdict(set)
    for ip in sus_ips:
        for u in tgt[ip]:
            u_ips[u].add(ip)
    common: Counter = Counter()
    for u, ips_ in u_ips.items():
        if 2 <= len(ips_) <= 50:
            L_ = sorted(ips_)
            for i in range(len(L_)):
                for j in range(i + 1, len(L_)):
                    common[(L_[i], L_[j])] += 1
    for (a, b), n_ in common.items():
        ja = n_ / max(1, len(tgt[a] | tgt[b]))
        contain = n_ / max(1, min(len(tgt[a]), len(tgt[b])))      # one list inside the other = reused target list
        if n_ >= 5 and contain >= 0.8:
            small, big = (a, b) if len(tgt[a]) <= len(tgt[b]) else (b, a)
            link(a, b, "targets", 3, f"{contain * 100:.0f}% of the {len(tgt[small])} accounts {small} tried were also "
                                     f"tried by {big} (same target list)")
        elif n_ >= 3 and ja >= 0.3:
            link(a, b, "targets", 3 if ja >= 0.6 else 2, f"tried {n_} of the same accounts ({ja * 100:.0f}% overlap)")
    # b) same network
    by_net: dict = defaultdict(list)
    for ip in sus_ips:
        try:
            a_ = ipaddress.ip_address(ip)
            by_net[str(ipaddress.ip_network(f"{ip}/{24 if a_.version == 4 else 48}", strict=False))].append(ip)
        except ValueError:
            pass
    for net, L_ in by_net.items():
        if 2 <= len(L_) <= 256:
            L_.sort()
            for ip in L_[1:]:
                link(L_[0], ip, "subnet", 1, f"same network {net}")   # needs a second signal to form a campaign
    # c) failed against the same account within 30 minutes
    for u, lst in fails_by_user.items():
        lst_ = [x for x in lst if x[2] in sus_ips and x[3] not in noise_fail]
        j = 0
        for i, x in enumerate(lst_):
            while lst_[j][0] < x[0] - dt.timedelta(minutes=30):
                j += 1
            for y in lst_[max(j, i - 30):i]:
                if y[2] != x[2]:
                    link(y[2], x[2], "cofail", 1, names.get(u, u))
    # d) hand-off: failures from one IP, then a successful login as that account from another IP
    handoff: dict = {}            # session id -> set of IPs that failed for the account first
    for u, ss in s_by_user.items():
        fl = fails_by_user.get(u)
        if not fl:
            continue
        ft = [x[0] for x in fl]
        days_by_ip: dict = defaultdict(set)
        for s in ss:
            if s["ip"] not in trusted and len(days_by_ip[s["ip"]]) < 2:   # not the user's normal address
                lo, hi = bisect_left(ft, s["s"] - cmp_w), bisect_right(ft, s["s"])
                fips = {fl[i][2] for i in range(lo, hi) if fl[i][2] and fl[i][2] != s["ip"] and (u, fl[i][2]) not in regular}
                fips = {ip for ip in fips if ip in sus_ips or sum(1 for i in range(lo, hi) if fl[i][2] == ip) >= 2}
                if fips:
                    handoff[s["id"]] = fips
                    for a in fips:
                        link(a, s["ip"], "handoff", 4, f"{names[u]} at {F(s['s'])[:16]}")
            days_by_ip[s["ip"]].add(s["s"].date())
    # e) rotation: one account logs in from several NEW networks within 48 h and at least one of those IPs attacked
    #    before -> the attacker's addresses belong together.  f) one new address used by several accounts.
    rot_w = dt.timedelta(hours=48)
    attackish = sus_ips | attack_ips | brute_ips
    first_use: dict = defaultdict(list)            # ip -> [(t, user, session)] where it was new for that user
    for u, ss in s_by_user.items():
        seen_ip_u: set = set()
        seen_net_u: dict = defaultdict(set)
        recent_new: list = []                       # (t, ip) of logins from networks new to this account
        for s in ss:
            ip, net = s["ip"], net_of(s["ip"])
            if ip not in trusted:
                if ip not in seen_ip_u:
                    first_use[ip].append((s["s"], u, s))
                if not seen_net_u.get(net):
                    recent_new = [(t_, i_) for t_, i_ in recent_new if s["s"] - t_ <= rot_w]
                    for t_, i_ in recent_new:
                        if i_ != ip and (i_ in attackish or ip in attackish):
                            link(i_, ip, "rotation", 2, f"{names[u]} logged in from both within 48 h")
                    recent_new.append((s["s"], ip))
            seen_ip_u.add(ip)
            seen_net_u[net].add(s["s"].date())
    shared_new: dict = {}                          # ip -> [(t, u, s)] first-time uses by different accounts
    for ip, uses in first_use.items():
        if len({u for _, u, _ in uses}) < 2 or any((u, ip) in regular for u in {x[1] for x in uses}):
            continue                                # an office / home address someone uses regularly
        cc_ = geo_of(ip)[0]
        strong = ip in attackish or (home and cc_ and cc_ not in home)
        uses = sorted(uses, key=lambda x: x[0])
        grp = [x for i_, x in enumerate(uses) if any(y[1] != x[1] and abs((y[0] - x[0]).total_seconds())
                                                    <= (7 * 86400 if strong else 7200) for y in uses)]
        if len({x[1] for x in grp}) >= 2:
            shared_new[ip] = grp
    acct_links: dict = defaultdict(dict)           # (u1, u2) -> {reason: detail}

    def alink(a, b, why, detail):
        if a and b and a != b:
            acct_links[tuple(sorted((a, b)))].setdefault(why, detail)
    for ip, grp in shared_new.items():
        us_ = sorted({x[1] for x in grp})
        strong = ip in attackish or (home and geo_of(ip)[0] and geo_of(ip)[0] not in home)
        for i_ in range(len(us_)):
            for j_ in range(i_ + 1, len(us_)):
                alink(us_[i_], us_[j_], "same new IP", f"both used {ip} for the first time")
        add("shared_new_ip", "high" if strong else "medium",
            f"{len(us_)} accounts first used the same new IP {ip}",
            f"{', '.join(names[u] for u in us_[:8])} each connected from {ip}"
            f"{' (' + geo_of(ip)[1] + ')' if geo_of(ip)[0] else ''} for the first time, "
            f"{'within 7 days' if strong else 'within 2 hours'}, and no account uses it regularly. One attacker "
            f"using several stolen passwords looks like this.", grp[0][0], grp[-1][0], us_[:20], [ip],
            [x[2]["seq"] for x in grp][:40])

    # clusters
    parent_ip = {}

    def fip(a):
        parent_ip.setdefault(a, a)
        while parent_ip[a] != a:
            parent_ip[a] = parent_ip[parent_ip[a]]
            a = parent_ip[a]
        return a
    for (a, b), e in ip_links.items():
        if e["w"] >= args.campaign_min_weight:
            parent_ip[fip(a)] = fip(b)
    comps_ip: dict = defaultdict(set)
    for (a, b), e in ip_links.items():
        if e["w"] >= args.campaign_min_weight:
            comps_ip[fip(a)].update((a, b))
    campaigns: list = []
    ip_campaign: dict = {}
    for members in comps_ip.values():
        if len(members) < 2:
            continue
        mem = sorted(members)
        c_fails = [x for ip in mem for x in afails_by_ip.get(ip, [])]
        c_fails.sort()
        targets = {x[1] for x in c_fails if x[1]}
        # accounts that got in from a campaign IP after the campaign failed against them
        success: dict = {}
        for ip in mem:
            for s in s_by_ip.get(ip, []):
                tried = [x for x in c_fails if x[1] == s["u"] and s["s"] - cmp_w <= x[0] <= s["s"]]
                own = len({d_ for d_ in reg_days.get((s["u"], ip), ()) if d_ < s["s"].date()}) >= 2
                if (tried and not own) or (s["id"] in handoff and handoff[s["id"]] & members):
                    success.setdefault(s["u"], []).append(s)
        kinds_c: Counter = Counter()
        for (a, b), e in ip_links.items():
            if a in members and b in members:
                kinds_c.update(e["kinds"].keys())
        cid = len(campaigns) + 1
        for ip in mem:
            ip_campaign[ip] = cid
        countries = sorted({geo_of(ip)[1] for ip in mem if geo_of(ip)[0]})
        campaigns.append(dict(id=cid, ips=mem, targets=targets, success=success, fails=len(c_fails),
                              first=c_fails[0][0] if c_fails else min(s["s"] for v in success.values() for s in v),
                              last=max([x[0] for x in c_fails[-1:]] + [s["s"] for v in success.values() for s in v]),
                              kinds=kinds_c, countries=countries, seqs=[x[3] for x in c_fails[:40]]))
    KIND_TXT = {"targets": "shared target accounts", "subnet": "same network", "cofail": "same account within 30 min",
                "handoff": "failed here, logged in there", "rotation": "same account from both within 48 h"}
    for cp in campaigns:
        sev = "critical" if cp["success"] else "high" if len(cp["ips"]) >= 3 or len(cp["targets"]) >= 10 else "medium"
        cp["sev"] = sev
        got = sorted(names.get(u, u) for u in cp["success"])
        cp["title"] = (f"Coordinated attack from {len(cp['ips'])} IPs" +
                       (f": {len(got)} account(s) broken into" if got else f" against {len(cp['targets'])} account(s)"))
        add("coordinated_attack", sev, cp["title"],
            f"IPs {', '.join(cp['ips'][:8])}{' ...' if len(cp['ips']) > 8 else ''}"
            f"{' (' + ', '.join(cp['countries']) + ')' if cp['countries'] else ''} are linked by "
            f"{', '.join(KIND_TXT[k] for k in cp['kinds'])}. {cp['fails']} failed logins against "
            f"{len(cp['targets'])} account(s)." + (f" Successful logins afterwards: {', '.join(got)}." if got else ""),
            cp["first"], cp["last"], list(cp["success"])[:20], cp["ips"][:100], cp["seqs"], cp["fails"])
        cp["inc"] = incidents[-1]

    # ---------------- logins after failures: evidence-based scoring ----------------
    # Every successful VPN login that had failed attempts before it (from the same IP or for the same account)
    # is scored. Points for attacker-like evidence, minus points for "this is just the user mistyping".
    # The score is finished at the end of the analysis, when post-login behaviour is known.
    compromised: set[str] = set()
    cw = dt.timedelta(minutes=args.comp_window_min)
    ipw = dt.timedelta(hours=args.login_window_hours)
    ip_ft = {ip: [x[0] for x in lst] for ip, lst in fails_by_ip.items()}
    u_ft = {u: [x[0] for x in lst] for u, lst in fails_by_user.items()}
    lock_t: dict = defaultdict(list)
    for t, u, why, seq in lockouts:
        lock_t[u].append(t)
    # an IP is "normal" for an account when it was used successfully on 2+ earlier days
    u_ip_days: dict = defaultdict(lambda: defaultdict(set))
    for s in sessions:
        u_ip_days[s["u"]][s["ip"]].add(s["s"].date())
    ip_regulars: dict = defaultdict(int)          # accounts that use the IP regularly (office / home NAT)
    for u, d_ in u_ip_days.items():
        for ip, days in d_.items():
            if len(days) >= 3:
                ip_regulars[ip] += 1
    login_reviews: list = []
    succ_after_fail_by_ip: dict = defaultdict(set)   # accounts that got in from this IP after its failures

    for u, ss in s_by_user.items():
        last_rep = None
        prior_ips: Counter = Counter()
        prior_days: dict = defaultdict(set)
        prior_nets: dict = defaultdict(set)
        for s in ss:
            t, ip = s["s"], s["ip"]
            if ip in trusted:
                prior_ips[ip] += 1
                prior_days[ip].add(t.date())
                prior_nets[net_of(ip)].add(t.date())
                continue
            # failures from this IP in the lookback window
            ifl = fails_by_ip.get(ip, [])
            lo, hi = (bisect_left(ip_ft[ip], t - ipw), bisect_right(ip_ft[ip], t)) if ifl else (0, 0)
            ip_win = ifl[lo:hi]
            ip_accts = {x[1] for x in ip_win if x[1] and (x[1] == u or x[3] not in noise_fail)}
            ip_fails_u = [x for x in ip_win if x[1] == u]
            masked = sum(1 for x in ip_win if x[3] not in noise_fail and (not x[1] or "not found" in (x[4] or "").lower()))
            # failures for this account from other IPs shortly before
            ufl = fails_by_user.get(u, [])
            ulo, uhi = (bisect_left(u_ft[u], t - cw), bisect_right(u_ft[u], t)) if ufl else (0, 0)
            other_ip_fails = [x for x in ufl[ulo:uhi] if x[2] != ip]
            ho = handoff.get(s["id"], set())
            if not ip_win and len(other_ip_fails) < args.comp_min_fails and not ho:
                prior_ips[ip] += 1
                prior_days[ip].add(t.date())
                prior_nets[net_of(ip)].add(t.date())
                continue
            if last_rep and t - last_rep < cw and not ip_accts - {u}:
                prior_ips[ip] += 1
                prior_days[ip].add(t.date())
                prior_nets[net_of(ip)].add(t.date())
                continue
            last_rep = t
            pts: list = []
            n_other = len(ip_accts - {u})
            if n_other + 1 >= args.spray_min_users:
                pts.append((50, f"{ip} failed against {n_other + 1} accounts before this login (password spraying)"))
            elif n_other >= 2:
                pts.append((25, f"{ip} also failed against {n_other} other account(s)"))
            nf = len(ip_fails_u)
            if nf >= args.bf_min:
                pts.append((35, f"{nf} wrong passwords for this account from the same IP first (brute force)"))
            elif nf >= args.comp_min_fails:
                pts.append((20, f"{nf} wrong passwords for this account from the same IP first"))
            elif nf:
                pts.append((5, f"{nf} wrong password(s) for this account from the same IP first"))
            if len(other_ip_fails) >= args.comp_min_fails:
                pts.append((15, f"{len(other_ip_fails)} failures for this account from {len({x[2] for x in other_ip_fails})} "
                                f"other IP(s) within {int(args.comp_window_min)} min (distributed guessing)"))
            if masked >= 3:
                pts.append((10, f"{masked} attempts from the IP used unknown or hidden user names"))
            if ho:
                same_c = {a for a in ho if ip_campaign.get(a) and ip_campaign.get(a) == ip_campaign.get(ip)}
                if same_c:
                    pts.append((35, f"failed first from {', '.join(sorted(same_c)[:4])} (same attack campaign), then "
                                    f"got in from this IP: a password found by one IP was used from another"))
                elif not other_ip_fails or len(other_ip_fails) < args.comp_min_fails:
                    pts.append((15, f"failed first from other IP(s) {', '.join(sorted(ho)[:4])}, then got in from this IP"))
            if ip_campaign.get(ip) and not ho:
                pts.append((15, f"{ip} belongs to attack campaign #{ip_campaign[ip]}"))
            if any(t - ipw <= lt <= t for lt in lock_t.get(u, [])):
                pts.append((10, "the account was locked out shortly before"))
            known = len(prior_days.get(ip, ())) >= 2 and (u, ip) not in tainted
            if known:
                pts.append((-30, f"{ip} is a normal address for this account (used on {len(prior_days[ip])} earlier days)"))
            elif len(prior_nets.get(net_of(ip), ())) >= 2 and (u, ip) not in tainted:
                pts.append((-15, f"{ip} is in {net_of(ip)}, a provider network this account uses regularly "
                                 f"(dynamic address)"))
            elif sum(prior_ips.values()) >= 3 and ip not in prior_ips:
                pts.append((15, f"first time this account connected from {ip} and its network"))
            cc_ip = geo_of(ip)[0]
            if cc_ip and u_cc.get(u) and cc_ip == u_cc[u].most_common(1)[0][0] and n_other + 1 < args.spray_min_users \
                    and ip not in sus_ips:
                pts.append((-10, f"from {geo_of(ip)[1]}, the country this account normally connects from"))
            if ip_regulars.get(ip, 0) >= 3 and not n_other + 1 >= args.spray_min_users:
                pts.append((-15, f"{ip} is shared by {ip_regulars[ip]} accounts as their regular address (office/NAT)"))
            gap = (t - max([x[0] for x in ip_fails_u + other_ip_fails] or [t])).total_seconds()
            ho_fails = [x for x in fails_by_user.get(u, []) if x[2] in ho and t - cmp_w <= x[0] <= t]
            ev = [x[3] for x in (ip_win[-40:] + other_ip_fails[-20:] + ho_fails[-20:])] + [s["seq"]]
            lr = dict(t=t, u=u, ip=ip, s=s, pts=pts, ip_fails=len(ip_win), ip_accts=len(ip_accts), user_fails=nf,
                      other_fails=len(other_ip_fails), gap=int(gap), seqs=ev, known=known,
                      start=min([x[0] for x in ip_win + other_ip_fails + ho_fails] or [t]),
                      campaign=ip_campaign.get(ip), handoff=sorted(ho))
            login_reviews.append(lr)
            if ip_win:
                succ_after_fail_by_ip[ip].add(u)
            prior_ips[ip] += 1
            prior_days[ip].add(t.date())
            prior_nets[net_of(ip)].add(t.date())
    # several different accounts got in from the same failing IP -> stronger
    for lr in login_reviews:
        others = succ_after_fail_by_ip.get(lr["ip"], set()) - {lr["u"]}
        if others and lr["ip_fails"]:
            lr["pts"].append((20, f"{len(others)} other account(s) also logged in from {lr['ip']} after its failures: "
                                  f"{', '.join(sorted(names[x] for x in others)[:5])}"))
    for lr in login_reviews:     # provisional: compromise if the login evidence alone is strong
        if sum(p for p, _ in lr["pts"]) >= 70:
            compromised.add(lr["u"])

    for u, ss in s_by_user.items():
        closed = [s for s in ss if not s["open"]]
        active: list = []
        seen = set()
        for s in closed:
            active = [a for a in active if a["e"] > s["s"] + dt.timedelta(seconds=60)]
            for a in active:
                if a["ip"] != s["ip"] and a["ip"] and s["ip"]:
                    key = (frozenset((a["ip"], s["ip"])), s["s"].date())
                    if key in seen:
                        continue
                    seen.add(key)
                    overlap = min(a["e"], s["e"]) - s["s"]
                    if net_of(a["ip"]) == net_of(s["ip"]) or overlap < dt.timedelta(minutes=args.concurrent_min_minutes):
                        continue          # reconnect after an address change within the same provider
                    ca, cb = geo_of(a["ip"])[0], geo_of(s["ip"])[0]
                    flagged_pair = bool({a["ip"], s["ip"]} & (attack_ips | brute_ips | set(ip_campaign)))
                    both_regular = (u, a["ip"]) in regular and (u, s["ip"]) in regular
                    foreign_c = bool(home) and ((ca and ca not in home) or (cb and cb not in home))
                    if flagged_pair or foreign_c or (ca and cb and ca != cb and not (ca in home and cb in home)):
                        sev_c, why_c = "high", "One account used by two parties is a strong sign of shared or stolen credentials."
                    elif both_regular:
                        sev_c, why_c = "low", "Both addresses are regular for this account: probably two devices (e.g. office and home)."
                    else:
                        sev_c, why_c = "medium", "Same country and no attack evidence: possibly two devices (laptop and phone)."
                    add("concurrent_sessions", sev_c, f"{names[u]} connected from two IPs at once",
                        f"Sessions from {a['ip']} and {s['ip']} overlapped for {hd(overlap.total_seconds())}. {why_c}",
                        s["s"], min(a["e"], s["e"]), [u], [a["ip"], s["ip"]], [a["seq"], s["seq"]], sid=s["id"])
            active.append(s)

    travel = dt.timedelta(hours=args.travel_hours)
    foreign_seen: set = set()
    if geo:
        for u, ss in s_by_user.items():
            prev = None
            seen_cc: Counter = Counter()
            for s in ss:
                if s["ip"] in trusted:
                    continue
                cc, cname = geo.get(s["ip"], ("", ""))
                if not cc:
                    continue
                if prev and prev[1] != cc and not (home and prev[1] in home and cc in home):
                    gap = s["s"] - prev[0]["e"]
                    if gap < travel:
                        when = ("while still connected" if gap.total_seconds() <= 0
                                else f"within {hd(gap.total_seconds())}")
                        add("impossible_travel", "high", f"{names[u]} changed country {when}",
                            f"{prev[2]} ({prev[0]['ip']}) then {cname} ({s['ip']}). Too fast to travel; "
                            f"could be a VPN/proxy or a second person using the account.",
                            prev[0]["e"], s["s"], [u], [prev[0]["ip"], s["ip"]], [prev[0]["seq"], s["seq"]])
                is_new = cc not in seen_cc and sum(seen_cc.values()) >= args.new_country_baseline
                foreign = bool(home) and cc not in home
                if is_new and not foreign and cc not in home:
                    add("new_country", "medium", f"{names[u]} connected from {cname} for the first time",
                        f"After {sum(seen_cc.values())} sessions from {', '.join(sorted(seen_cc))}, "
                        f"a session came from {cname} ({s['ip']}).",
                        s["s"], s["e"], [u], [s["ip"]], [s["seq"]])
                if foreign and (u, cc, s["s"].date()) not in foreign_seen:
                    foreign_seen.add((u, cc, s["s"].date()))
                    add("foreign_login", "high" if (u in compromised or is_new) else "medium",
                        f"{names[u]} connected from {cname}" + (" for the first time" if is_new else ""),
                        f"Session from {s['ip']} ({cname}); VPN logins are expected only from "
                        f"{', '.join(sorted(home))}."
                        + (f" Earlier sessions came from {', '.join(sorted(seen_cc))}." if is_new else ""),
                        s["s"], s["e"], [u], [s["ip"]], [s["seq"]], sid=s.get("id"))
                seen_cc[cc] += 1
                prev = (s, cc, cname)

    ip_users: dict[str, set] = defaultdict(set)
    for s in sessions:
        if s["ip"]:
            ip_users[s["ip"]].add(s["u"])
    shared_ips = set()
    for ip, us in ip_users.items():
        if len(us) >= args.shared_ip_min_users and ip not in attack_ips and ip not in trusted:
            shared_ips.add(ip)
            ss = s_by_ip[ip]
            add("shared_ip", "medium" if len(us) >= 3 else "low",
                f"{len(us)} accounts connected from {ip}",
                f"Accounts: {', '.join(names[x] for x in sorted(us)[:12])}{' and more' if len(us) > 12 else ''}. "
                f"Normal for a shared office/home NAT, suspicious otherwise.",
                ss[0]["s"], ss[-1]["e"], us, [ip], [x["seq"] for x in ss[:60]], len(ss))

    # ---------------- data volume (download = data leaving the company through the VPN) ----------------
    for s in sessions:
        u = s["u"]
        top_hosts = [h for h, _ in sess_hosts.get(s["id"], Counter()).most_common(10)]
        where = f" Internal servers used most: {', '.join(top_hosts[:3])}." if top_hosts else ""
        if s["down"] >= args.exfil_download_mb * MB:
            add("large_download", "high", f"{names[u]} downloaded {hb(s['down'])} in one session",
                f"From {s['ip']} over {hd(s['secs'])}. Pulling this much data out through the VPN can mean data "
                f"exfiltration.{where}", s["s"], s["e"], [u], [s["ip"]], [s["seq"]], hosts=top_hosts, sid=s["id"])
        if s["up"] >= args.large_upload_mb * MB:
            add("large_upload", "medium", f"{names[u]} uploaded {hb(s['up'])} in one session",
                f"From {s['ip']} over {hd(s['secs'])}. Large uploads into the network can be tool staging, "
                f"ransomware preparation or legitimate backups.{where}", s["s"], s["e"], [u], [s["ip"]], [s["seq"]],
                hosts=top_hosts, sid=s["id"])
        if (s["down"] < args.exfil_download_mb * MB and s["up"] < args.large_upload_mb * MB
                and s["up"] + s["down"] >= args.large_transfer_mb * MB):
            add("large_transfer", "medium", f"{names[u]} moved {hb(s['up'] + s['down'])} in one session",
                f"Uploaded {hb(s['up'])}, downloaded {hb(s['down'])} from {s['ip']} over {hd(s['secs'])}.{where}",
                s["s"], s["e"], [u], [s["ip"]], [s["seq"]], hosts=top_hosts, sid=s["id"])
        if not s["open"] and s["secs"] >= args.long_session_hours * 3600:
            add("long_session", "low", f"{names[u]} stayed connected for {hd(s['secs'])}",
                f"Session from {s['ip']}; uploaded {hb(s['up'])}, downloaded {hb(s['down'])}.",
                s["s"], s["e"], [u], [s["ip"]], [s["seq"]])

    # ---------------- unusual daily download compared with the account's own history ----------------
    for u, ss in s_by_user.items():
        daily_dl: Counter = Counter()
        dsess: dict = defaultdict(list)
        for s in ss:
            daily_dl[s["s"].date()] += s["down"]
            dsess[s["s"].date()].append(s)
        prior: list = []
        for d in sorted(daily_dl):
            v = daily_dl[d]
            if len(prior) >= 5:
                m_ = len(prior) // 2
                med = prior[m_] if len(prior) % 2 else (prior[m_ - 1] + prior[m_]) / 2
                if v >= args.spike_min_mb * MB and v >= args.spike_factor * max(med, 1):
                    lst = dsess[d]
                    hc: Counter = Counter()
                    for s in lst:
                        hc.update(sess_hosts.get(s["id"], Counter()))
                    sev_d = "high" if v >= 2 * args.spike_factor * max(med, 1) else "medium"
                    add("unusual_download", sev_d, f"{names[u]} downloaded {hb(v)} on {d:%d %b %Y}",
                        f"About {v / max(med, 1):.0f}x this account's usual day ({hb(med)} median over {len(prior)} "
                        f"active days) from {', '.join(sorted({s['ip'] for s in lst}))}. Possible data theft."
                        + (f" Internal servers used most: {', '.join(h for h, _ in hc.most_common(3))}." if hc else ""),
                        max(lst, key=lambda s: s["down"])["s"], max(s["e"] for s in lst), [u], {s["ip"] for s in lst},
                        [s["seq"] for s in lst], hosts=[h for h, _ in hc.most_common(10)])
            insort(prior, v)

    # ---------------- unusual login time for this account ----------------
    try:
        ws, we = (int(x) for x in args.work_hours.split("-"))
    except ValueError:
        ws, we = 7, 20
    for u, ss in s_by_user.items():
        n_ = len(ss)
        if n_ < args.time_baseline:
            continue
        hours = Counter(s["s"].hour for s in ss)
        wk = sum(1 for s in ss if s["s"].weekday() >= 5)
        seen_days = set()
        for s in ss:
            h = s["s"].hour
            share = (hours[(h - 1) % 24] + hours[h] + hours[(h + 1) % 24] - 1) / (n_ - 1)
            odd_hour = share < 0.02 and not (ws <= h < we)
            odd_day = s["s"].weekday() >= 5 and (wk - 1) / (n_ - 1) < 0.03
            if (odd_hour or odd_day) and s["s"].date() not in seen_days:
                seen_days.add(s["s"].date())
                why = []
                if odd_hour:
                    why.append(f"only {share * 100:.1f}% of this account's {n_} sessions start around {h:02d}:00")
                if odd_day:
                    why.append("this account almost never connects at weekends")
                add("unusual_time", "medium", f"{names[u]} connected at an unusual time ({s['s']:%a %H:%M})",
                    f"Session from {s['ip']}: {' and '.join(why)}.", s["s"], s["e"], [u], [s["ip"]], [s["seq"]],
                    sid=s["id"])

    # ---------------- new VPN client platform (other device / OS) ----------------
    def client_family(c):
        """Device type from the client string (Windows, macOS, Linux, iOS, Android...). Product renames such as
        AnyConnect -> Cisco Secure Client and version upgrades are deliberately ignored."""
        cl = (c or "").lower()
        for k_, v_ in (("windows", "Windows"), ("mac os", "macOS"), ("macos", "macOS"), ("darwin", "macOS"),
                       ("android", "Android"), ("iphone", "iOS"), ("ipad", "iOS"), (" ios", "iOS"),
                       ("chrome", "ChromeOS"), ("linux", "Linux")):
            if k_ in cl:
                return v_
        return re.sub(r"\s+", " ", re.sub(r"\d[\w.\-]*", "", c or "")).strip(" -,")
    for u, ss in s_by_user.items():
        seen_c: Counter = Counter()
        seen_ip: set = set()
        for s in ss:
            if s["client"]:
                fam = client_family(s["client"])
                if fam and fam not in seen_c and sum(seen_c.values()) >= 3:
                    new_ip = s["ip"] not in seen_ip
                    add("new_client", "high" if new_ip else "medium", f"{names[u]} used a new VPN client: {fam}",
                        f"Earlier sessions used: {', '.join(seen_c)}. Full client: {s['client']}."
                        + (" The source IP was also new for this account." if new_ip else ""),
                        s["s"], s["e"], [u], [s["ip"]], [s["seq"]], sid=s["id"])
                seen_c[fam] += 1
            seen_ip.add(s["ip"])

    seen_l = set()
    for t, u, why, seq in lockouts:
        k = (u, t.replace(minute=0, second=0, microsecond=0))
        if k not in seen_l:
            seen_l.add(k)
            add("account_lockout", "medium", f"{names[u]} was locked out", f"The firewall locked the account ({why}).",
                t, t, [u], [], [seq])

    # ---------------- perimeter: port scans and threat detection ----------------
    recon_ips: set = set()
    by_src: dict = defaultdict(list)
    for t, src, dst, port, seq in ext_denies:
        if src and src not in trusted and is_public(src):
            by_src[src].append((t, dst, port, seq))
    for src, lst in by_src.items():
        bk: dict = defaultdict(lambda: [set(), set(), None, None, []])
        for t, dst, port, seq in lst:
            x = bk[int(t.timestamp() // 600)]
            x[0].add(dst)
            x[1].add(port)
            x[2] = x[2] or t
            x[3] = t
            x[4].append(seq)
        for g in runs(sorted(k for k, x in bk.items() if len(x[1]) >= args.port_scan_min
                                                          or len(x[0]) >= args.port_scan_min)):
            hs = set().union(*(bk[k][0] for k in g))
            ps = set().union(*(bk[k][1] for k in g)) - {None}
            sq = [q for k in g for q in bk[k][4]]
            recon_ips.add(src)
            mins = max(1, round((bk[g[-1]][3] - bk[g[0]][2]).total_seconds() / 60))
            add("port_scan", "medium", f"Port scan from {src}",
                f"{len(sq)} blocked probes to {len(ps)} ports on {len(hs)} addresses within {mins} min"
                f" (e.g. {', '.join(svc(p) for p in sorted(ps)[:8])}).",
                bk[g[0]][2], bk[g[-1]][3], [], [src], sq, len(sq), hosts=sorted(h for h in hs if not is_public(h))[:30])
    th: dict = defaultdict(list)
    for t, ip, why, seq in threats:
        if ip:
            th[(ip, t.date())].append((t, why, seq))
    for (ip, d), lst in th.items():
        recon_ips.add(ip)
        add("threat_detection", "medium", f"Firewall threat detection flagged {ip}",
            f"{len(lst)} alert(s): {', '.join(sorted({w for _, w, _ in lst}))}.",
            lst[0][0], lst[-1][0], [], [ip], [x[2] for x in lst], len(lst))
    for ip in recon_ips - attack_ips:      # spraying IPs are already reported as attack_ip_login
        for s in s_by_ip.get(ip, []):
            add("login_from_scanner", "critical", f"{names[s['u']]} logged in from a scanning IP",
                f"{ip} probed the firewall and then opened a VPN session as {names[s['u']]} "
                f"({hd(s['secs'])}, downloaded {hb(s['down'])}).", s["s"], s["e"], [s["u"]], [ip], [s["seq"]],
                sid=s["id"])
            compromised.add(s["u"])

    # ---------------- inside the network: scanning and lateral movement from VPN sessions ----------------
    for u, fl in uflows.items():
        fl.sort(key=lambda x: x[0])
        b10: dict = defaultdict(lambda: [set(), defaultdict(set), None, None, 0, set()])
        b60: dict = defaultdict(lambda: [set(), None, None, Counter(), set()])
        for st, dst, dport, blocked, b, s in fl:
            x = b10[int(st.timestamp() // 600)]
            x[0].add(dst)
            x[1][dst].add(dport)
            x[2] = x[2] or st
            x[3] = st
            x[4] += int(blocked)
            if s:
                x[5].add(s["ip"])
            if dport in ADMIN_PORTS:
                y = b60[int(st.timestamp() // 3600)]
                y[0].add(dst)
                y[1] = y[1] or st
                y[2] = st
                y[3][ADMIN_PORTS[dport]] += 1
                if s:
                    y[4].add(s["ip"])
        sev = "critical" if u in compromised else "high"
        for g in runs(sorted(k for k, x in b10.items() if len(x[0]) >= args.scan_hosts
                                                           or max(len(v) for v in x[1].values()) >= args.scan_ports)):
            hs = set().union(*(b10[k][0] for k in g))
            maxp = max(len(v) for k in g for v in b10[k][1].values())
            blk = sum(b10[k][4] for k in g)
            mins = max(1, round((b10[g[-1]][3] - b10[g[0]][2]).total_seconds() / 60))
            add("internal_scan", sev, f"{names[u]} scanned the internal network",
                f"{len(hs)} internal hosts and up to {maxp} ports on one host were contacted within {mins} min "
                f"({blk} attempts blocked). This is typical of discovery tools after a break-in.",
                b10[g[0]][2], b10[g[-1]][3], [u], set().union(*(b10[k][5] for k in g)), [], len(hs),
                hosts=sorted(hs)[:50])
        for g in runs(sorted(k for k, y in b60.items() if len(y[0]) >= args.lateral_hosts)):
            hs = set().union(*(b60[k][0] for k in g))
            protos: Counter = Counter()
            for k in g:
                protos.update(b60[k][3])
            add("lateral_movement", sev, f"{names[u]} reached {len(hs)} hosts over admin protocols",
                f"Connections via {', '.join(f'{p} ({c})' for p, c in protos.most_common(5))} to {len(hs)} internal "
                f"hosts. Remote-admin fan-out like this is how attackers move between machines.",
                b60[g[0]][1], b60[g[-1]][2], [u], set().union(*(b60[k][4] for k in g)), [], len(hs),
                hosts=sorted(hs)[:50])

    # ---------------- firewall management plane ----------------
    mf: dict = defaultdict(list)
    for t, kind, u, ip, detail, seq in mgmt:
        if kind == "MGMT_LOGIN_FAIL":
            mf[ip or ""].append((t, u, seq))
    admin_attack: set = set()
    for ip, lst in mf.items():
        for b in bursts(lst, dt.timedelta(minutes=15)):
            if len(b) >= args.admin_bf_min:
                if ip:
                    admin_attack.add(ip)
                tried = sorted({names.get(x[1], x[1]) for x in b if x[1]})
                add("admin_brute_force", "high", f"Brute force on firewall management{' from ' + ip if ip else ''}",
                    f"{len(b)} failed admin logins. Names tried: {', '.join(tried[:8]) or 'unknown'}.",
                    b[0][0], b[-1][0], [x[1] for x in b], [ip] if ip else [], [x[2] for x in b], len(b))
    for t, kind, u, ip, detail, seq in mgmt:
        if kind == "MGMT_LOGIN_OK" and ip and ip not in trusted:
            bad = ip in admin_attack or ip in attack_ips or ip in brute_ips or ip in recon_ips
            if bad or is_public(ip):
                add("admin_login_internet", "critical" if bad else "high",
                    f"Firewall admin login by {names.get(u, u) or 'unknown'} from {ip}",
                    ("This IP attacked the firewall or VPN before. " if bad else
                     "Management access from a public IP is unusual. ") + f"({detail})", t, t, [u], [ip], [seq])
    seen_cmd: set = set()
    sens: dict = defaultdict(list)
    for t, kind, u, ip, detail, seq in mgmt:
        if kind != "CONFIG_CMD":
            continue
        k = (u, detail, t.replace(second=0, microsecond=0))
        if k in seen_cmd:          # 111008 and 111010 report the same command
            continue
        seen_cmd.add(k)
        if RE_ANTI_FORENSIC.search(detail):
            add("logging_tampered", "critical", f"Logging was disabled or cleared by {names.get(u, u) or 'unknown'}",
                f"Command: '{detail}'{' from ' + ip if ip else ''}. Attackers do this to hide their tracks; check "
                f"what happened just before.", t, t, [u], [ip] if ip else [], [seq])
        elif RE_SENSITIVE_CMD.search(detail):
            sens[(u, t.replace(minute=0, second=0, microsecond=0))].append((t, detail, ip, seq))
    for (u, hr), lst in sens.items():
        cmds = [x[1] for x in lst]
        add("config_change", "medium", f"{len(lst)} sensitive firewall change(s) by {names.get(u, u) or 'unknown'}",
            "Commands: " + "; ".join(cmds[:8]) + (" ..." if len(cmds) > 8 else ""), lst[0][0], lst[-1][0], [u],
            {x[2] for x in lst if x[2]}, [x[3] for x in lst], len(lst))

    # ---------------- what did suspicious sessions touch inside? ----------------
    post_done: set = set()
    for x in list(incidents):
        sid = x.get("sid")
        hc = sess_hosts.get(sid) if sid else None
        if not hc or x["type"] not in ("compromise", "attack_ip_login", "login_from_scanner", "new_client",
                                       "concurrent_sessions", "unusual_time"):
            continue
        s = sessions[sid - 1]
        x["detail"] += (f" During this session the account reached {len(hc)} internal host(s): "
                        f"{', '.join(h for h, _ in hc.most_common(5))}.")
        x["hosts"] = [h for h, _ in hc.most_common(50)]
        if x["type"] == "login_from_scanner" and sid not in post_done:
            post_done.add(sid)
            ports = sorted(sess_ports.get(sid, ()))
            add("post_compromise", "critical", f"Suspicious session of {names[s['u']]} reached {len(hc)} internal host(s)",
                f"After the suspicious login from {s['ip']}: {s['int_conns']} internal connections "
                f"(services: {', '.join(svc(p) for p in ports[:10])}), {hb(s['int_bytes'])} moved, "
                f"{s['blocked']} blocked. Check these servers for signs of intrusion.",
                s["s"], s["e"], [s["u"]], [s["ip"]], [s["seq"]], len(hc), hosts=x["hosts"], sid=sid)

    # ---------------- finish login scoring with what happened afterwards ----------------
    LOGIN_AFTER = {"new_client": (15, "a new VPN client/device was used in this session"),
                   "foreign_login": (15, "the session came from an unexpected country"),
                   "new_country": (15, "first session from this country for the account"),
                   "impossible_travel": (15, "country changed too fast around this login"),
                   "concurrent_sessions": (15, "the account was connected from two places at once (different country or flagged IP)"),
                   "unusual_time": (10, "login at an hour this account normally never uses"),
                   "internal_scan": (30, "the session scanned the internal network"),
                   "lateral_movement": (30, "the session reached many hosts over admin protocols"),
                   "large_download": (15, "the session downloaded an unusually large amount of data"),
                   "unusual_download": (15, "unusually high download volume that day"),
                   "large_upload": (10, "large upload into the network")}
    by_sid: dict = defaultdict(list)
    by_user_inc: dict = defaultdict(list)
    for x in incidents:
        if x.get("sid"):
            by_sid[x["sid"]].append(x)
        if x["n_users"] <= 3:
            for u in x["users"]:
                by_user_inc[u].append(x)
    for lr in login_reviews:
        s = lr["s"]
        seen_t: set = set()
        # incidents of this session, or of this account that started while the session was running
        rel = by_sid.get(s["id"], []) + [x for x in by_user_inc.get(lr["u"], [])
                                         if s["s"] - dt.timedelta(minutes=5) <= x["start"] <= s["e"]
                                         or (x["type"] == "unusual_download" and x["start"].date() == s["s"].date())]
        for x in rel:
            if x["type"] in LOGIN_AFTER and x["type"] not in seen_t and not (x["type"] == "concurrent_sessions" and x["sev"] != "high"):
                seen_t.add(x["type"])
                lr["pts"].append(LOGIN_AFTER[x["type"]])
        if lr["ip"] in recon_ips:
            lr["pts"].append((20, f"{lr['ip']} also port-scanned the firewall or triggered threat detection"))
        if lr["ip"] in admin_attack:
            lr["pts"].append((20, f"{lr['ip']} also attacked the firewall's admin login"))
        score = max(0, min(100, sum(p for p, _ in lr["pts"])))
        lr["score"] = score
        lr["verdict"] = ("compromised" if score >= args.login_compromise_score else
                         "likely" if score >= args.login_likely_score else
                         "review" if score >= args.login_review_score else "benign")
    # ---------------- logins WITHOUT failed attempts that do not look like the account owner ----------------
    # A phished or stolen password gives no failed logins at all, so these are scored on anomalies alone.
    reviewed_sids = {lr["s"]["id"] for lr in login_reviews}
    fam_cnt = Counter(client_family(s["client"]) for s in sessions if s["client"])
    fam_tot = sum(fam_cnt.values()) or 1
    shared_sid = {x[2]["id"]: ip for ip, grp in shared_new.items() for x in grp}
    flagged_ips = attack_ips | brute_ips | set(ip_campaign) | recon_ips | admin_attack
    NF_AFTER = {"internal_scan": 30, "lateral_movement": 30, "large_download": 15, "unusual_download": 15,
                "unusual_time": 10, "large_upload": 10}
    n_nofail = 0
    comp_pairs = {(lr["u"], lr["ip"]) for lr in login_reviews if lr["verdict"] in ("compromised", "likely")}
    for u, ss in s_by_user.items():
        p_ips: Counter = Counter()
        p_nets: dict = defaultdict(set)
        p_cc: Counter = Counter()
        p_fam: Counter = Counter()
        for s in ss:
            ip, net = s["ip"], net_of(s["ip"])
            cc_ = geo_of(ip)[0]
            fam = client_family(s["client"]) if s["client"] else ""
            if s["id"] not in reviewed_sids and ip not in trusted and sum(p_ips.values()) >= 5:
                pts: list = []
                new_net = not p_nets.get(net)
                if ip in flagged_ips:
                    pts.append((30, f"{ip} is a known attacking IP"))
                if ip not in p_ips and new_net:
                    pts.append((15, f"first time from {ip} and its network {net}"))
                if home and cc_ and cc_ not in home:
                    pts.append((15, f"connected from {geo_of(ip)[1]}, outside the usual countries"))
                if cc_ and p_cc and cc_ not in p_cc and cc_ not in home:
                    pts.append((10, f"first session from {geo_of(ip)[1]} for this account"))
                if (u, ip) in comp_pairs:
                    pts.append((40, f"an earlier login of this account from {ip} was judged compromised: the attacker came back"))
                if fam and p_fam and fam not in p_fam:
                    rare = fam_cnt[fam] / fam_tot < 0.03
                    pts.append((20 if rare else 10, f"new device type: {fam}" + (" (rare in this company)" if rare else "")))
                if s["id"] in shared_sid:
                    pts.append((25, f"{ip} was also used for the first time by another account around then"))
                if ip in ip_campaign:
                    pts.append((15, f"{ip} belongs to IP cluster #{ip_campaign[ip]}"))
                seen_t: set = set()
                for x in by_sid.get(s["id"], []) + [x for x in by_user_inc.get(u, [])
                                                     if s["s"] - dt.timedelta(minutes=5) <= x["start"] <= s["e"]]:
                    if x["type"] in NF_AFTER and x["type"] not in seen_t:
                        seen_t.add(x["type"])
                        pts.append((NF_AFTER[x["type"]], LOGIN_AFTER[x["type"]][1]))
                    elif x["type"] == "concurrent_sessions" and x["sev"] == "high" and "conc" not in seen_t:
                        seen_t.add("conc")
                        pts.append((15, "connected from two places at once (different country or flagged IP)"))
                if sum(1 for p_ in pts if p_[0] > 0) >= 2 or (u, ip) in comp_pairs:
                    if not new_net and ip not in flagged_ips and (u, ip) not in tainted:
                        pts.append((-15, f"{net} is a provider network this account has used before"))
                    if cc_ and u_cc.get(u) and cc_ == u_cc[u].most_common(1)[0][0] and ip not in flagged_ips:
                        pts.append((-10, f"from {geo_of(ip)[1]}, the country this account normally connects from"))
                    score = max(0, min(100, sum(p_ for p_, _ in pts)))
                    verdict = ("compromised" if score >= args.nofail_compromise_score else
                               "likely" if score >= args.nofail_likely_score else
                               "review" if score >= args.nofail_review_score else "")
                    if verdict:
                        n_nofail += 1
                        login_reviews.append(dict(
                            t=s["s"], u=u, ip=ip, s=s, score=score, verdict=verdict, nofail=True,
                            pts=[(0, "no failed logins before this one: if it was not the user, the password was "
                                     "stolen elsewhere (phishing, malware, password reuse)")] + pts,
                            ip_fails=0, ip_accts=0, user_fails=0, other_fails=0, gap=0, seqs=[s["seq"]], known=False,
                            start=s["s"], campaign=ip_campaign.get(ip), handoff=[]))
            p_ips[ip] += 1
            p_nets[net].add(s["s"].date())
            if cc_:
                p_cc[cc_] += 1
            if fam:
                p_fam[fam] += 1

    # incidents: one per assessed login that is not just a typo
    VERDICT_SEV = {"compromised": "critical", "likely": "high", "review": "medium"}
    VERDICT_TXT = {"compromised": "compromised", "likely": "likely compromised", "review": "needs review",
                   "benign": "probably the user"}
    for lr in login_reviews:
        if lr["verdict"] == "benign":
            continue
        s, u, ip = lr["s"], lr["u"], lr["ip"]
        spray = lr["ip_accts"] >= 3
        why = "; ".join(f"{t_} ({'+' if p > 0 else ''}{p})" for p, t_ in sorted(lr["pts"], key=lambda z: -abs(z[0])))
        typ = "suspicious_login" if lr.get("nofail") else "attack_ip_login" if spray else "compromise"
        title = (f"{names[u]} logged in from {ip} with no failed attempts, but it does not look like them"
                 if lr.get("nofail") else
                 f"{names[u]} logged in from {ip} after password spraying" if spray else
                 f"{names[u]} logged in after {lr['user_fails'] + lr['other_fails']} failed attempts")
        x = dict(type=typ, sev=VERDICT_SEV[lr["verdict"]], title=f"{title} ({VERDICT_TXT[lr['verdict']]})",
                 detail=f"Confidence {lr['score']}/100. Evidence: {why}. Session: {hd(s['secs'])}, uploaded "
                        f"{hb(s['up'])}, downloaded {hb(s['down'])}.",
                 start=lr["start"], end=s["s"], users=[u], ips=[ip], seqs=lr["seqs"][:60],
                 count=lr["ip_fails"] + lr["other_fails"], n_users=1, hosts=[], sid=s["id"])
        hc = sess_hosts.get(s["id"])
        if hc:
            x["detail"] += (f" During this session the account reached {len(hc)} internal host(s): "
                            f"{', '.join(h for h, _ in hc.most_common(5))}.")
            x["hosts"] = [h for h, _ in hc.most_common(50)]
        incidents.append(x)
        lr["inc"] = x
        if lr["verdict"] in ("compromised", "likely") and hc and s["id"] not in post_done:
            post_done.add(s["id"])
            ports = sorted(sess_ports.get(s["id"], ()))
            add("post_compromise", "critical" if lr["verdict"] == "compromised" else "high",
                f"Suspicious session of {names[u]} reached {len(hc)} internal host(s)",
                f"After the suspicious login from {ip}: {s['int_conns']} internal connections "
                f"(services: {', '.join(svc(p) for p in ports[:10])}), {hb(s['int_bytes'])} moved, "
                f"{s['blocked']} blocked. Check these servers for signs of intrusion.",
                s["s"], s["e"], [u], [ip], [s["seq"]], len(hc), hosts=x["hosts"], sid=s["id"])
    # final account marking: "compromised" only when the evidence is strong enough
    compromised = ({lr["u"] for lr in login_reviews if lr["verdict"] == "compromised"} |
                   {u for x in incidents if x["type"] == "login_from_scanner" for u in x["users"]})
    review_users = {lr["u"] for lr in login_reviews if lr["verdict"] in ("likely", "review")} - compromised
    # linked accounts: same IP cluster got in, same attacking IP used, same new IP first used
    for cp in campaigns:
        su_ = sorted(cp["success"])
        for i_ in range(len(su_)):
            for j_ in range(i_ + 1, len(su_)):
                alink(su_[i_], su_[j_], "same IP cluster", f"both broken into by IP cluster #{cp['id']}")
    for ip in flagged_ips:
        us_ = sorted({s["u"] for s in s_by_ip.get(ip, [])})
        if 2 <= len(us_) <= 10:
            for i_ in range(len(us_)):
                for j_ in range(i_ + 1, len(us_)):
                    alink(us_[i_], us_[j_], "same attacking IP", f"both logged in from attacking IP {ip}")
    compromise_ips = {lr["ip"] for lr in login_reviews if lr["verdict"] in ("compromised", "likely")}
    review_ips = {lr["ip"] for lr in login_reviews if lr["verdict"] == "review"}

    incidents.sort(key=lambda x: (SEV_ORDER[x["sev"]], -(x["start"].timestamp())))
    for i, x in enumerate(incidents, 1):
        x["id"] = i

    # ---------------- cases: incidents sharing an account or IP, close in time ----------------
    case_w = dt.timedelta(hours=args.case_window_hours)
    elig = [x for x in incidents if x["type"] not in ("shared_ip", "long_session") and x["sev"] != "low"]
    parent = {x["id"]: x["id"] for x in elig}

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    by_key: dict = defaultdict(list)
    for x in elig:
        keys = [("ip", i) for i in x["ips"] if i not in trusted]
        if x["n_users"] <= 3:                       # a spray listing 300 targets must not glue everything together
            keys += [("u", u) for u in x["users"]]
        for k in keys:
            by_key[k].append(x)
    for lst in by_key.values():
        lst.sort(key=lambda x: x["start"])
        root, end = None, None
        for x in lst:
            if end is not None and x["start"] - end <= case_w:
                parent[find(x["id"])] = find(root)
                end = max(end, x["end"])
            else:
                root, end = x["id"], x["end"]
    comps: dict = defaultdict(list)
    for x in elig:
        comps[find(x["id"])].append(x)
    cases: list = []
    for lst in comps.values():
        sevs = {x["sev"] for x in lst}
        if len(lst) < 2 and "critical" not in sevs:
            continue
        lst.sort(key=lambda x: x["start"])
        chain: list = []
        for x in lst:
            lbl = TYPE_LABEL.get(x["type"], x["type"])
            if lbl not in chain:
                chain.append(lbl)
        c_users = sorted({u for x in lst if x["n_users"] <= 3 for u in x["users"]})
        c_ips = sorted({i for x in lst for i in x["ips"]})
        cases.append(dict(sev=min(sevs, key=SEV_ORDER.get), score=sum(SEV_WEIGHT[x["sev"]] for x in lst),
                          title=" > ".join(chain[:7]) + (" > ..." if len(chain) > 7 else ""),
                          who=", ".join(names.get(u, u) for u in c_users[:3]) or ", ".join(c_ips[:2]),
                          start=lst[0]["start"], end=max(x["end"] for x in lst), users=c_users, ips=c_ips,
                          hosts=sorted({h for x in lst for h in x.get("hosts", [])}), incs=[x["id"] for x in lst]))
    cases.sort(key=lambda c: (SEV_ORDER[c["sev"]], -c["score"], -c["start"].timestamp()))
    inc_by_id = {x["id"]: x for x in incidents}
    for i, c_ in enumerate(cases, 1):
        c_["id"] = i
        f0 = inc_by_id[c_["incs"][0]]
        c_["key"] = hashlib.sha1(f"{f0['type']}|{F(f0['start'])}|{' '.join(f0['users'])}|{' '.join(f0['ips'])}"
                                 .encode()).hexdigest()[:12]

    # ------------------------------------------------------------ summaries
    inc_by_user: dict[str, list] = defaultdict(list)
    inc_by_ip: dict[str, list] = defaultdict(list)
    for x in incidents:
        for u in x["users"]:
            inc_by_user[u].append(x)
        for ip in x["ips"]:
            inc_by_ip[ip].append(x)

    all_users = set(names)
    edges: dict[tuple, dict] = defaultdict(lambda: dict(sess=0, fails=0, up=0, down=0, secs=0))
    for s in sessions:
        e = edges[(s["u"], s["ip"])]
        e["sess"] += 1
        e["up"] += s["up"]
        e["down"] += s["down"]
        e["secs"] += s["secs"]
    for f in fails:
        if f[1]:
            edges[(f[1], f[2])]["fails"] += 1

    mgmt_users = {m[2] for m in mgmt if m[2]}
    u_hosts: dict = defaultdict(set)
    u_ibytes: Counter = Counter()
    for (u, dst, port, proto), a in access.items():
        u_hosts[u].add(dst)
        u_ibytes[u] += a[2]
    users_out = []
    for u in sorted(all_users):
        ss = s_by_user.get(u, [])
        inc = inc_by_user.get(u, [])
        types = {x["type"] for x in inc}
        sevs = {x["sev"] for x in inc}
        risk = min(100, sum(SEV_WEIGHT[x["sev"]] for x in inc))
        if u in compromised or "critical" in sevs or types & {"internal_scan", "lateral_movement"}:
            status = "compromise"
        elif u in review_users or types & {"impossible_travel"} or \
                any(x["type"] in ("concurrent_sessions", "new_client") and x["sev"] == "high" for x in inc) or \
                any(x["type"] in ("compromise", "attack_ip_login") for x in inc):
            status = "review"
            status = "review"
        elif types & {"brute_force", "compromise", "password_spray", "account_lockout", "admin_brute_force"} and \
                (ss or u in mgmt_users):
            status = "targeted"
        elif inc and ss:
            status = "watch"
        else:
            status = "normal"
        top = min(inc, key=lambda x: SEV_ORDER[x["sev"]])["title"] if inc else ""
        ips = {s["ip"] for s in ss if s["ip"]}
        fl = fails_by_user.get(u, [])
        times = [s["s"] for s in ss] + [f[0] for f in fl]
        users_out.append(dict(
            key=u, n=names[u], sess=len(ss), open=sum(1 for s in ss if s["open"]),
            secs=sum(s["secs"] for s in ss), up=sum(s["up"] for s in ss), down=sum(s["down"] for s in ss),
            ips=len(ips), ccs=sorted({geo[i][0] for i in ips if i in geo and geo[i][0]}),
            fails=len(fl), first=F(min(times)) if times else None,
            last=F(max([s["e"] for s in ss] + [f[0] for f in fl])) if times else None,
            groups=sorted({s["g"] for s in ss if s["g"]}), risk=risk, status=status, top=top,
            inc=len(inc), int_hosts=len(u_hosts.get(u, ())), int_bytes=u_ibytes.get(u, 0),
            clients=sorted({client_family(s["client"]) for s in ss if s["client"]})))
    uidx = {x["key"]: i for i, x in enumerate(users_out)}

    all_ips = set(ip_users) | set(fails_by_ip) | recon_ips | admin_attack | {m[3] for m in mgmt if m[3]} | \
              {i for x in incidents for i in x["ips"]}
    ips_out = []
    for ip in sorted(all_ips):
        ss = s_by_ip.get(ip, [])
        fl = fails_by_ip.get(ip, [])
        inc = inc_by_ip.get(ip, [])
        if ip in attack_ips or ip in brute_ips or ip in recon_ips or ip in admin_attack or ip in ip_campaign:
            role = "attacker"
        elif ip in compromise_ips or any(x["sev"] == "critical" for x in inc):
            role = "compromise"
        elif ip in review_ips:
            role = "review"
        elif ip in shared_ips:
            role = "shared"
        else:
            role = ""
        times = [s["s"] for s in ss] + [f[0] for f in fl]
        ips_out.append(dict(
            ip=ip, cc=geo_of(ip)[0], country=geo_of(ip)[1],
            users=len(ip_users.get(ip, ())), attacked=len({f[1] for f in fl if f[1]}), fails=len(fl),
            sess=len(ss), up=sum(s["up"] for s in ss), down=sum(s["down"] for s in ss),
            secs=sum(s["secs"] for s in ss), first=F(min(times)) if times else None,
            last=F(max(times)) if times else None, role=role,
            risk=min(100, sum(SEV_WEIGHT[x["sev"]] for x in inc)), inc=len(inc),
            trusted=ip in trusted))

    inc_by_host: dict = defaultdict(list)
    for x in incidents:
        for h in x.get("hosts", []):
            inc_by_host[h].append(x)
    hagg: dict = {}
    for (u, dst, port, proto), a in access.items():
        h = hagg.get(dst)
        if h is None:
            h = hagg[dst] = dict(users=set(), conns=0, blocked=0, bytes=0, secs=0, ports=Counter(), first=a[4], last=a[5])
        h["users"].add(u)
        h["conns"] += a[0]
        h["blocked"] += a[1]
        h["bytes"] += a[2]
        h["secs"] += a[3]
        h["ports"][f"{port}/{proto}"] += a[0]
        h["first"] = min(h["first"], a[4])
        h["last"] = max(h["last"], a[5])
    hosts_out = []
    for dst, h in hagg.items():
        inc = inc_by_host.get(dst, [])
        hosts_out.append(dict(ip=dst, users=len(h["users"]), conns=h["conns"], blocked=h["blocked"], bytes=h["bytes"],
                              secs=h["secs"], ports=" ".join(f"{k}:{v}" for k, v in h["ports"].most_common(12)),
                              first=F(h["first"]), last=F(h["last"]),
                              risk=min(100, sum(SEV_WEIGHT[x["sev"]] for x in inc)), inc=len(inc),
                              role="target" if any(x["sev"] in ("critical", "high") for x in inc) else ""))

    # daily series (continuous so gaps are visible)
    day_up: Counter = Counter()
    day_down: Counter = Counter()
    day_sess: Counter = Counter()
    day_fail: Counter = Counter()
    day_users: dict = defaultdict(set)
    for s in sessions:
        d0 = s["s"].date().isoformat()
        day_up[d0] += s["up"]
        day_down[d0] += s["down"]
        day_sess[d0] += 1
        day_users[d0].add(s["u"])
    for f in fails:
        day_fail[f[0].date().isoformat()] += 1
    daily = []
    dcur = first_t.date()
    while dcur <= last_t.date():
        k = dcur.isoformat()
        daily.append(dict(d=k, up=day_up[k], down=day_down[k], sess=day_sess[k], fails=day_fail[k],
                          users=len(day_users[k])))
        dcur += dt.timedelta(days=1)

    # ------------------------------------------------------------ write CSV
    def wcsv(name, header, rows):
        p = os.path.join(args.outdir, name)
        with open(p, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        return p

    written = [
        wcsv("sessions.csv",
             ["user", "outside_ip", "country", "inside_ip", "vpn_group", "start", "end", "duration_s", "duration",
              "uploaded_bytes", "uploaded", "downloaded_bytes", "downloaded", "total", "end_estimated",
              "disconnect_reason", "seq"],
             ([names[s["u"]], s["ip"], geo.get(s["ip"], ("", ""))[1], s["inside"], s["g"], F(s["s"]), F(s["e"]),
               s["secs"], hd(s["secs"]), s["up"], hb(s["up"]), s["down"], hb(s["down"]), hb(s["up"] + s["down"]),
               int(s["open"]), s["reason"], s["seq"]] for s in sessions)),
        wcsv("users_summary.csv",
             ["user", "status", "risk", "incidents", "top_finding", "sessions", "connected_s", "connected",
              "uploaded_bytes", "uploaded", "downloaded_bytes", "downloaded", "total", "source_ips", "countries",
              "failed_logins", "first_seen", "last_seen", "vpn_groups"],
             ([x["n"], x["status"], x["risk"], x["inc"], x["top"], x["sess"], x["secs"], hd(x["secs"]), x["up"],
               hb(x["up"]), x["down"], hb(x["down"]), hb(x["up"] + x["down"]), x["ips"], " ".join(x["ccs"]),
               x["fails"], x["first"], x["last"], " ".join(x["groups"])]
              for x in sorted(users_out, key=lambda x: (-x["risk"], -(x["up"] + x["down"]))))),
        wcsv("ips_summary.csv",
             ["ip", "role", "risk", "cc", "country", "accounts_connected", "accounts_attacked", "failed_logins",
              "sessions", "uploaded", "downloaded", "connected", "first_seen", "last_seen", "trusted"],
             ([x["ip"], x["role"], x["risk"], x["cc"], x["country"], x["users"], x["attacked"], x["fails"],
               x["sess"], hb(x["up"]), hb(x["down"]), hd(x["secs"]), x["first"], x["last"], int(x["trusted"])]
              for x in sorted(ips_out, key=lambda x: (-x["risk"], -x["fails"])))),
        wcsv("user_ip_links.csv",
             ["user", "ip", "country", "sessions", "failed_logins", "uploaded", "downloaded", "connected"],
             ([names[u], ip, geo.get(ip, ("", ""))[1], e["sess"], e["fails"], hb(e["up"]), hb(e["down"]),
               hd(e["secs"])] for (u, ip), e in sorted(edges.items()))),
        wcsv("incidents.csv",
             ["id", "severity", "type", "title", "detail", "start", "end", "users", "ips", "count", "evidence_seq"],
             ([x["id"], x["sev"], x["type"], x["title"], x["detail"], F(x["start"]), F(x["end"]),
               " ".join(names[u] for u in x["users"]), " ".join(x["ips"]), x["count"],
               " ".join(map(str, x["seqs"]))] for x in incidents)),
    ]

    meta_summary = dict(title=args.title, generated=F(dt.datetime.now()), db=os.path.basename(args.db),
                        first=F(first_t), last=F(last_t), events=n_events, geo=bool(geo),
                        home_countries=sorted(home),
                        sessions=len(sessions), open=sum(1 for s in sessions if s["open"]), fails=len(fails),
                        up=sum(s["up"] for s in sessions), down=sum(s["down"] for s in sessions),
                        secs=sum(s["secs"] for s in sessions), conn_rows=n_conn_rows,
                        login_verdicts=dict(Counter(lr["verdict"] for lr in login_reviews)), campaigns=len(campaigns), conn_attributed=n_attr,
                        internal_hosts=len(hosts_out), cases=len(cases), mgmt_events=len(mgmt),
                        thresholds={k: v for k, v in vars(args).items() if k[:3] in
                                    ("bf_", "spr", "com", "tra", "new", "sha", "exf", "lar", "lon", "spi",
                                     "wor", "tim", "sca", "lat", "por", "adm", "cas")})

    # ---- analysis tables in the DB (used by asa_server.py) ----
    conn.executescript("""
        DROP TABLE IF EXISTS sessions; DROP TABLE IF EXISTS incidents; DROP TABLE IF EXISTS incident_users;
        DROP TABLE IF EXISTS incident_ips; DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS ips;
        DROP TABLE IF EXISTS links; DROP TABLE IF EXISTS daily; DROP TABLE IF EXISTS meta;
        CREATE TABLE sessions(id INTEGER PRIMARY KEY, user_key TEXT, user TEXT, outside_ip TEXT, inside_ip TEXT,
            vpn_group TEXT, start TEXT, end TEXT, duration_s INTEGER, bytes_up INTEGER, bytes_down INTEGER,
            end_estimated INTEGER, reason TEXT, seq INTEGER, client TEXT, int_hosts INTEGER, int_conns INTEGER,
            int_bytes INTEGER, blocked INTEGER);
        CREATE TABLE incidents(id INTEGER PRIMARY KEY, severity TEXT, sev_rank INTEGER, type TEXT, title TEXT,
            detail TEXT, start TEXT, end TEXT, users TEXT, ips TEXT, count INTEGER, evidence_seq TEXT, n_users INTEGER,
            hosts TEXT);
        DROP TABLE IF EXISTS incident_hosts; CREATE TABLE incident_hosts(incident_id INTEGER, host TEXT);
        DROP TABLE IF EXISTS login_reviews; CREATE TABLE login_reviews(id INTEGER PRIMARY KEY, ts TEXT, user_key TEXT,
            user TEXT, ip TEXT, country TEXT, score INTEGER, verdict TEXT, reasons TEXT, ip_fails INTEGER,
            ip_accounts INTEGER, user_fails INTEGER, other_ip_fails INTEGER, gap_s INTEGER, known_ip INTEGER,
            session_id INTEGER, incident_id INTEGER, first_fail TEXT, evidence_seq TEXT, campaign_id INTEGER,
            handoff_ips TEXT);
        DROP TABLE IF EXISTS ip_links; CREATE TABLE ip_links(ip_a TEXT, ip_b TEXT, weight INTEGER, kinds TEXT,
            campaign_id INTEGER);
        DROP TABLE IF EXISTS campaigns; CREATE TABLE campaigns(id INTEGER PRIMARY KEY, severity TEXT, sev_rank INTEGER,
            title TEXT, ips TEXT, n_ips INTEGER, countries TEXT, targets TEXT, n_targets INTEGER, success TEXT,
            n_success INTEGER, fails INTEGER, first TEXT, last TEXT, kinds TEXT, incident_id INTEGER);
        DROP TABLE IF EXISTS campaign_ips; CREATE TABLE campaign_ips(campaign_id INTEGER, ip TEXT);
        DROP TABLE IF EXISTS account_links; CREATE TABLE account_links(u1 TEXT, u2 TEXT, reasons TEXT);
        DROP TABLE IF EXISTS access; CREATE TABLE access(user_key TEXT, dst_ip TEXT, dst_port INTEGER, proto TEXT,
            conns INTEGER, blocked INTEGER, bytes INTEGER, connected_s INTEGER, first_seen TEXT, last_seen TEXT);
        DROP TABLE IF EXISTS hosts; CREATE TABLE hosts(ip TEXT PRIMARY KEY, users INTEGER, conns INTEGER,
            blocked INTEGER, bytes INTEGER, connected_s INTEGER, ports TEXT, first_seen TEXT, last_seen TEXT,
            risk INTEGER, incidents INTEGER, role TEXT);
        DROP TABLE IF EXISTS cases; CREATE TABLE cases(id INTEGER PRIMARY KEY, severity TEXT, sev_rank INTEGER,
            score INTEGER, title TEXT, who TEXT, start TEXT, end TEXT, users TEXT, ips TEXT, hosts TEXT,
            n_incidents INTEGER, ckey TEXT, summary TEXT, actions TEXT, report TEXT);
        DROP TABLE IF EXISTS case_evidence; CREATE TABLE case_evidence(case_id INTEGER, incident_id INTEGER, seq INTEGER,
            ts TEXT, source TEXT, kind TEXT, text TEXT, raw TEXT);
        DROP TABLE IF EXISTS case_sessions; CREATE TABLE case_sessions(case_id INTEGER, session_id INTEGER);
        DROP TABLE IF EXISTS case_incidents; CREATE TABLE case_incidents(case_id INTEGER, incident_id INTEGER);
        CREATE TABLE incident_users(incident_id INTEGER, user_key TEXT);
        CREATE TABLE incident_ips(incident_id INTEGER, ip TEXT);
        CREATE TABLE users(user_key TEXT PRIMARY KEY, name TEXT, status TEXT, risk INTEGER, incidents INTEGER,
            top_finding TEXT, sessions INTEGER, open_sessions INTEGER, connected_s INTEGER, bytes_up INTEGER,
            bytes_down INTEGER, bytes_total INTEGER, source_ips INTEGER, countries TEXT, failed_logins INTEGER,
            first_seen TEXT, last_seen TEXT, vpn_groups TEXT, int_hosts INTEGER, int_bytes INTEGER, clients TEXT);
        CREATE TABLE ips(ip TEXT PRIMARY KEY, cc TEXT, country TEXT, role TEXT, risk INTEGER, incidents INTEGER,
            accounts_connected INTEGER, accounts_attacked INTEGER, failed_logins INTEGER, sessions INTEGER,
            bytes_up INTEGER, bytes_down INTEGER, bytes_total INTEGER, connected_s INTEGER,
            first_seen TEXT, last_seen TEXT, trusted INTEGER);
        CREATE TABLE links(user_key TEXT, ip TEXT, sessions INTEGER, failed_logins INTEGER, bytes_up INTEGER,
            bytes_down INTEGER, connected_s INTEGER);
        CREATE TABLE daily(day TEXT PRIMARY KEY, sessions INTEGER, failed_logins INTEGER, bytes_up INTEGER,
            bytes_down INTEGER, users INTEGER);
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
    """)
    conn.executemany("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((s["id"], s["u"], names[s["u"]], s["ip"], s["inside"], s["g"], F(s["s"]), F(s["e"]), s["secs"],
                       s["up"], s["down"], int(s["open"]), s["reason"], s["seq"], s["client"], s["int_hosts"],
                       s["int_conns"], s["int_bytes"], s["blocked"]) for s in sessions))
    conn.executemany("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((x["id"], x["sev"], SEV_ORDER[x["sev"]], x["type"], x["title"], x["detail"], F(x["start"]),
                       F(x["end"]), " ".join(names.get(u, u) for u in x["users"]), " ".join(x["ips"]), x["count"],
                       " ".join(map(str, x["seqs"])), x["n_users"], " ".join(x.get("hosts", []))) for x in incidents))
    conn.executemany("INSERT INTO ip_links VALUES (?,?,?,?,?)",
                     ((a, b, e["w"], json.dumps(e["kinds"]), ip_campaign.get(a) if ip_campaign.get(a) == ip_campaign.get(b)
                       else None) for (a, b), e in ip_links.items() if e["w"] >= 1))
    conn.executemany("INSERT INTO campaigns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((cp["id"], cp["sev"], SEV_ORDER[cp["sev"]], cp["title"], " ".join(cp["ips"]), len(cp["ips"]),
                       " | ".join(cp["countries"]), " ".join(sorted(cp["targets"]))[:20000], len(cp["targets"]),
                       " ".join(sorted(cp["success"])), len(cp["success"]), cp["fails"], F(cp["first"]), F(cp["last"]),
                       json.dumps(dict(cp["kinds"])), cp["inc"].get("id")) for cp in campaigns))
    conn.executemany("INSERT INTO account_links VALUES (?,?,?)",
                     ((a, b, json.dumps(r_)) for (a, b), r_ in acct_links.items()))
    conn.executemany("INSERT INTO campaign_ips VALUES (?,?)", ((cp["id"], ip) for cp in campaigns for ip in cp["ips"]))
    conn.executemany("INSERT INTO login_reviews VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((F(lr["t"]), lr["u"], names[lr["u"]], lr["ip"], geo_of(lr["ip"])[1], lr["score"], lr["verdict"],
                       json.dumps(sorted(lr["pts"], key=lambda z: -abs(z[0]))), lr["ip_fails"], lr["ip_accts"],
                       lr["user_fails"], lr["other_fails"], lr["gap"], int(lr["known"]), lr["s"]["id"],
                       (lr.get("inc") or {}).get("id"), F(lr["start"]), " ".join(map(str, lr["seqs"][:80])),
                       lr.get("campaign"), " ".join(lr.get("handoff") or []))
                      for lr in sorted(login_reviews, key=lambda z: (-z["score"], z["t"]))))
    conn.executemany("INSERT INTO incident_hosts VALUES (?,?)",
                     ((x["id"], h) for x in incidents for h in x.get("hosts", [])))
    conn.executemany("INSERT INTO access VALUES (?,?,?,?,?,?,?,?,?,?)",
                     ((u, dst, port, proto, a[0], a[1], a[2], a[3], F(a[4]), F(a[5]))
                      for (u, dst, port, proto), a in access.items()))
    conn.executemany("INSERT INTO hosts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((h["ip"], h["users"], h["conns"], h["blocked"], h["bytes"], h["secs"], h["ports"], h["first"],
                       h["last"], h["risk"], h["inc"], h["role"]) for h in hosts_out))
    # ---- case packages: summary, next steps, evidence ----
    user_status = {x["key"]: x["status"] for x in users_out}
    ip_role = {x["ip"]: x["role"] for x in ips_out}
    u_by_key = {x["key"]: x for x in users_out}
    ip_by = {x["ip"]: x for x in ips_out}
    tables_now = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    packages = []
    ev_rows = []
    for c_ in cases:
        incs = sorted((inc_by_id[i] for i in c_["incs"]), key=lambda x: (x["start"], SEV_ORDER[x["sev"]]))
        evidence = {x["id"]: gather_evidence(conn, x, "flows" in tables_now, "conns" in tables_now) for x in incs}
        for iid, lst in evidence.items():
            ev_rows += [(c_["id"], iid, *r) for r in lst]
        sids = sorted({x["sid"] for x in incs if x.get("sid")})
        pk = dict(case=c_, incs=incs, evidence=evidence,
                  summary=case_summary(c_, incs, names, sessions, user_status, ip_role),
                  actions=case_actions(c_, incs, names), sids=sids,
                  sessions=[dict(sessions[i - 1], n=names[sessions[i - 1]["u"]]) for i in sids],
                  accounts=[dict(n=names.get(u, u), status=user_status.get(u, ""), sess=u_by_key.get(u, {}).get("sess", 0),
                                 fails=u_by_key.get(u, {}).get("fails", 0), down=u_by_key.get(u, {}).get("down", 0))
                            for u in c_["users"]],
                  ips=[dict(ip=i, country=(ip_by.get(i) or {}).get("country", ""), role=ip_role.get(i, ""),
                            fails=(ip_by.get(i) or {}).get("fails", 0), sess=(ip_by.get(i) or {}).get("sess", 0))
                       for i in c_["ips"]])
        packages.append(pk)
    case_dir = os.path.join(args.outdir, "cases")
    if packages and not args.no_case_files:
        write_case_files(case_dir, packages, args.title)
    conn.executemany("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((c_["id"], c_["sev"], SEV_ORDER[c_["sev"]], c_["score"], c_["title"], c_["who"], F(c_["start"]),
                       F(c_["end"]), " ".join(c_["users"]), " ".join(c_["ips"]), " ".join(c_["hosts"]),
                       len(c_["incs"]), c_["key"], pk["summary"], json.dumps(pk["actions"]),
                       pk.get("files", ("",))[0]) for c_, pk in zip(cases, packages)))
    conn.executemany("INSERT INTO case_evidence VALUES (?,?,?,?,?,?,?,?)", ev_rows)
    conn.executemany("INSERT INTO case_sessions VALUES (?,?)", ((pk["case"]["id"], i) for pk in packages for i in pk["sids"]))
    conn.execute("INSERT INTO meta VALUES ('case_dir', ?)",
                 (os.path.abspath(case_dir) if packages and not args.no_case_files else "",))
    conn.executemany("INSERT INTO case_incidents VALUES (?,?)", ((c_["id"], i) for c_ in cases for i in c_["incs"]))
    conn.executemany("INSERT INTO incident_users VALUES (?,?)", ((x["id"], u) for x in incidents for u in x["users"]))
    conn.executemany("INSERT INTO incident_ips VALUES (?,?)", ((x["id"], ip) for x in incidents for ip in x["ips"]))
    conn.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((x["key"], x["n"], x["status"], x["risk"], x["inc"], x["top"], x["sess"], x["open"], x["secs"],
                       x["up"], x["down"], x["up"] + x["down"], x["ips"], " ".join(x["ccs"]), x["fails"],
                       x["first"], x["last"], " ".join(x["groups"]), x["int_hosts"], x["int_bytes"],
                       " | ".join(x["clients"])) for x in users_out))
    conn.executemany("INSERT INTO ips VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     ((x["ip"], x["cc"], x["country"], x["role"], x["risk"], x["inc"], x["users"], x["attacked"],
                       x["fails"], x["sess"], x["up"], x["down"], x["up"] + x["down"], x["secs"], x["first"],
                       x["last"], int(x["trusted"])) for x in ips_out))
    conn.executemany("INSERT INTO links VALUES (?,?,?,?,?,?,?)",
                     ((u, ip, e["sess"], e["fails"], e["up"], e["down"], e["secs"])
                      for (u, ip), e in edges.items() if ip))
    conn.executemany("INSERT INTO daily VALUES (?,?,?,?,?,?)",
                     ((d["d"], d["sess"], d["fails"], d["up"], d["down"], d["users"]) for d in daily))
    conn.execute("INSERT INTO meta VALUES ('summary', ?)", (json.dumps(meta_summary),))
    conn.executescript("""
        CREATE INDEX idx_s_user ON sessions(user_key, start);
        CREATE INDEX idx_s_ip ON sessions(outside_ip, start);
        CREATE INDEX idx_s_start ON sessions(start);
        CREATE INDEX idx_s_up ON sessions(bytes_up);
        CREATE INDEX idx_iu_user ON incident_users(user_key);
        CREATE INDEX idx_iu_inc ON incident_users(incident_id);
        CREATE INDEX idx_ii_ip ON incident_ips(ip);
        CREATE INDEX idx_inc_order ON incidents(sev_rank, start);
        CREATE INDEX idx_l_user ON links(user_key);
        CREATE INDEX idx_l_ip ON links(ip);
        CREATE INDEX idx_u_status ON users(status, risk);
        CREATE INDEX idx_u_total ON users(bytes_total);
        CREATE INDEX idx_ip_role ON ips(role);
        CREATE INDEX idx_ih_host ON incident_hosts(host);
        CREATE INDEX idx_lr_user ON login_reviews(user_key);
        CREATE INDEX idx_il_a ON ip_links(ip_a);
        CREATE INDEX idx_il_b ON ip_links(ip_b);
        CREATE INDEX idx_ci_ip ON campaign_ips(ip);
        CREATE INDEX idx_lr_ip ON login_reviews(ip);
        CREATE INDEX idx_lr_ts ON login_reviews(ts);
        CREATE INDEX idx_ih_inc ON incident_hosts(incident_id);
        CREATE INDEX idx_a_user ON access(user_key);
        CREATE INDEX idx_a_dst ON access(dst_ip);
        CREATE INDEX idx_ci_case ON case_incidents(case_id);
        CREATE INDEX idx_ci_inc ON case_incidents(incident_id);
        CREATE INDEX idx_ce_case ON case_evidence(case_id, incident_id);
        CREATE INDEX idx_cs_case ON case_sessions(case_id);
        CREATE INDEX IF NOT EXISTS idx_ev_user_nc ON events(user COLLATE NOCASE, ts);
        CREATE INDEX IF NOT EXISTS idx_ev_kind_ts ON events(kind, ts);
        CREATE INDEX IF NOT EXISTS idx_ev_seq ON events(seq);
        CREATE INDEX IF NOT EXISTS idx_ev_inside ON events(inside_ip, ts);
        CREATE INDEX idx_s_inside ON sessions(inside_ip, start);
        CREATE INDEX IF NOT EXISTS idx_ev_ts ON events(ts, seq);
        ANALYZE;
    """)
    conn.commit()
    conn.close()

    # ------------------------------------------------------------ static dashboard (optional)
    dash_path = ""
    if not args.no_html:
        dash_sessions = sessions
        if len(sessions) > args.max_dashboard_sessions:
            flagged = {u for u in inc_by_user}
            keep = [s for s in sessions if s["u"] in flagged]
            rest = sorted((s for s in sessions if s["u"] not in flagged), key=lambda s: -(s["up"] + s["down"]))
            dash_sessions = sorted(keep + rest[:max(0, args.max_dashboard_sessions - len(keep))],
                                   key=lambda s: s["s"])
        fail_pts = []
        for u, lst in fails_by_user.items():
            for f in lst[-args.max_fail_points_per_user:]:
                fail_pts.append([uidx[u], f[2], F(f[0])])
        data = dict(
            meta=dict(meta_summary, shown_sessions=len(dash_sessions)),
            users=[{k: v for k, v in x.items() if k != "key"} for x in users_out],
            ips=ips_out,
            sessions=[[uidx[s["u"]], s["ip"], F(s["s"]), F(s["e"]), s["secs"], s["up"], s["down"], s["inside"],
                       1 if s["open"] else 0, s["reason"], s["g"]] for s in dash_sessions],
            fails=fail_pts,
            edges=[[uidx[u], ip, e["sess"], e["fails"], e["up"], e["down"], e["secs"]]
                   for (u, ip), e in edges.items() if ip],
            incidents=[dict(id=x["id"], type=x["type"], sev=x["sev"], title=x["title"], detail=x["detail"],
                            start=F(x["start"]), end=F(x["end"]), users=[uidx[u] for u in x["users"]],
                            ips=x["ips"], count=x["count"], seqs=x["seqs"]) for x in incidents],
            daily=daily,
        )
        payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")
        fonts = "" if args.no_web_fonts else FONTS_LINK
        page = (TEMPLATE.replace("<!--FONTS-->", fonts)
                .replace("__TITLE__", html.escape(args.title))
                .replace("__DATA__", payload))
        dash_path = args.dashboard or os.path.join(args.outdir, "dashboard.html")
        with open(dash_path, "w", encoding="utf-8") as f:
            f.write(page)

    sev_count = Counter(x["sev"] for x in incidents)
    print("Done.")
    print(f"  - Analysis tables written to {args.db}")
    if dash_path:
        print(f"  - Static dashboard: {dash_path}")
    for p in written:
        print(f"  - {p}")
    print(f"  - Sessions: {len(sessions)} ({meta_summary['open']} without disconnect)")
    print(f"  - Incidents: {len(incidents)}  " +
          "  ".join(f"{k}={sev_count.get(k, 0)}" for k in SEV_ORDER))
    print(f"  - Connection records: {n_conn_rows:,}, tied to VPN users: {n_attr:,}; internal hosts reached: "
          f"{len(hosts_out):,}")
    print(f"  - Logins without failures that look like someone else: {n_nofail}; accounts first using the same new "
          f"IP: {len(shared_new)} IP(s); linked account pairs: {len(acct_links)}")
    print(f"  - Attack campaigns (linked IPs): {len(campaigns)}")
    for cp in sorted(campaigns, key=lambda c_: SEV_ORDER[c_["sev"]])[:5]:
        print(f"      [{cp['sev']}] {', '.join(cp['ips'][:5])}{' ...' if len(cp['ips']) > 5 else ''}: "
              f"{len(cp['targets'])} targets, in: {', '.join(sorted(names.get(u, u) for u in cp['success'])) or '-'}")
    vc = Counter(lr["verdict"] for lr in login_reviews)
    print(f"  - Logins after failures assessed: {len(login_reviews)}  compromised={vc['compromised']} "
          f"likely={vc['likely']} review={vc['review']} typo/benign={vc['benign']}")
    for lr in sorted(login_reviews, key=lambda z: -z["score"])[:6]:
        if lr["verdict"] != "benign":
            print(f"      {lr['score']:>3}/100 {lr['verdict']:<11} {names[lr['u']]} from {lr['ip']} at {F(lr['t'])}")
    print(f"  - Cases (linked incidents): {len(cases)}"
          + (f", reports in {os.path.join(args.outdir, 'cases')}{os.sep}index.html" if cases and not args.no_case_files else ""))
    for c_ in cases[:5]:
        print(f"      [{c_['sev']}] {c_['who']}: {c_['title']}")
    print(f"  - Suspected compromised accounts: {', '.join(names[u] for u in sorted(compromised)) or 'none'}")
    print(f"  - Attacking IPs: {len(attack_ips | brute_ips)}")
    if not geo:
        print("  - Country checks skipped (add --geoip GeoLite2-Country.mmdb or the DB-IP country CSV)")
    print(f"  - Processing time: {time.perf_counter() - t_start:.2f} s")
    return 0


FONTS_LINK = ('<link rel="preconnect" href="https://fonts.googleapis.com">'
              '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
              '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500'
              '&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">')

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>__TITLE__</title>
<!--FONTS-->
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
.st-compromise{background:var(--crit)} .st-targeted{background:var(--high)} .st-watch{background:var(--med)}
.badge{display:inline-block;font-size:.78rem;line-height:1.4;padding:0 7px;border-radius:3px;border:1px solid currentColor;white-space:nowrap}
.c-crit,.c-critical,.c-compromise,.c-attacker{color:var(--crit)} .c-high,.c-targeted{color:var(--high)} .c-medium,.c-watch,.c-shared{color:var(--med)} .c-low{color:var(--low)} .c-normal{color:var(--muted)}
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
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1 id="title">__TITLE__</h1>
    <p class="period" id="period"></p>
  </header>
  <section id="attention" aria-label="Needs attention"></section>
  <div class="kpis" id="kpis"></div>
  <nav class="tabs" role="tablist">
    <button id="t-overview" role="tab" data-v="overview">Overview</button>
    <button id="t-incidents" role="tab" data-v="incidents">Incidents</button>
    <button id="t-users" role="tab" data-v="users">Accounts</button>
    <button id="t-ips" role="tab" data-v="ips">Source IPs</button>
    <button id="t-links" role="tab" data-v="links">Connections map</button>
  </nav>
  <main>
    <section id="v-overview" class="view">
      <div class="sec">
        <div class="sec-h"><h2>Data moved per day</h2>
          <div class="legend"><span><i class="sw" style="background:var(--up)"></i>Uploaded by users</span><span><i class="sw" style="background:var(--down)"></i>Downloaded by users</span><span><i class="sw" style="background:var(--crit)"></i>Failed logins</span></div></div>
        <div class="chart" id="daily"></div>
      </div>
      <div class="two">
        <div class="sec"><div class="sec-h"><h2>Who moved the most data</h2><button class="more" data-go="users">All accounts</button></div><div id="topdata"></div></div>
        <div class="sec"><div class="sec-h"><h2>Longest connected</h2></div><div id="toptime"></div></div>
      </div>
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
          <option value="">All VPN users</option><option value="compromise">Suspected compromise</option><option value="targeted">Targeted</option><option value="watch">Watch</option><option value="normal">No findings</option><option value="failonly">Failed-only names (no session)</option></select>
      </div>
      <p class="note" id="u-count"></p>
      <div id="u-list"></div>
    </section>
    <section id="v-ips" class="view" hidden>
      <div class="controls">
        <input type="search" id="i-q" placeholder="Search IP or country" aria-label="Search IPs">
        <select id="i-sort" aria-label="Sort IPs"><option value="risk">Highest risk</option><option value="fails">Most failed logins</option><option value="attacked">Most accounts attacked</option><option value="users">Most accounts connected</option><option value="total">Most data</option><option value="sess">Most sessions</option></select>
        <select id="i-role" aria-label="Filter by role"><option value="">All IPs</option><option value="attacker">Attack sources</option><option value="compromise">Used in compromise</option><option value="shared">Shared by accounts</option></select>
      </div>
      <p class="note" id="i-count"></p>
      <div class="tw" id="i-list"></div>
    </section>
    <section id="v-links" class="view" hidden>
      <div class="controls">
        <select id="g-scope" aria-label="What to show"><option value="flag">Accounts and IPs with findings</option><option value="all">Everything (largest first)</option></select>
        <input type="search" id="g-q" placeholder="Trace an account or IP" aria-label="Trace an account or IP">
        <label class="chk"><input type="checkbox" id="g-fails" checked> Failed-login links</label>
      </div>
      <div class="legend" style="margin-bottom:8px">
        <span><i class="sw" style="border-radius:50%;background:var(--crit)"></i>Suspected compromise</span>
        <span><i class="sw" style="border-radius:50%;background:var(--high)"></i>Targeted</span>
        <span><i class="sw" style="border-radius:50%;background:var(--sess)"></i>Account</span>
        <span><i class="sw" style="transform:rotate(45deg);background:var(--crit)"></i>Attacking IP</span>
        <span><i class="sw" style="transform:rotate(45deg);background:var(--rule2)"></i>IP</span>
        <span><i class="sw" style="height:2px;background:var(--rule2)"></i>Connected (width = data)</span>
        <span><i class="sw" style="height:0;border-top:2px dashed var(--crit)"></i>Failed logins only</span>
      </div>
      <div class="gwrap"><svg id="graph" role="img" aria-label="Map of accounts and source IPs"></svg>
        <div class="gbtns"><button id="g-in" aria-label="Zoom in">+</button><button id="g-out" aria-label="Zoom out">&minus;</button><button id="g-fit" aria-label="Fit to screen">&#x2922;</button></div></div>
      <p class="note" id="g-note"></p>
    </section>
  </main>
</div>
<div class="scrim" id="scrim" hidden></div>
<aside class="drawer" id="drawer" hidden aria-modal="true" role="dialog"></aside>
<div id="tip" role="tooltip"></div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
"use strict";
const D = JSON.parse(document.getElementById('data').textContent);
const $ = (s, r) => (r || document).querySelector(s);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtN = n => (n || 0).toLocaleString('en');
function fmtB(n){ if(n == null) return '–'; const u=['B','KB','MB','GB','TB','PB']; let i=0, x=n; while(x>=1024 && i<u.length-1){x/=1024;i++;} return (i ? x.toFixed(x<10?2:x<100?1:0) : x) + ' ' + u[i]; }
function fmtD(s){ if(s == null) return '–'; s=Math.round(s); const d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60); if(d) return d+' d '+h+' h'; if(h) return h+' h '+m+' m'; if(m) return m+' m'; return s+' s'; }
const T = s => s ? Date.parse(s.replace(' ','T')+'Z') : null;
const short = s => s ? s.slice(0,16) : '–';
const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const niceDate = s => { if(!s) return '–'; const [y,m,d] = s.slice(0,10).split('-'); return (+d)+' '+MON[+m-1]+' '+y; };
const STATUS = {compromise:'Suspected compromise', targeted:'Targeted', watch:'Watch', normal:'No findings'};
const ROLE = {attacker:'Attack source', compromise:'Used in compromise', shared:'Shared by accounts'};
const SEV = {critical:'Critical', high:'High', medium:'Medium', low:'Low'};
const SEVO = {critical:0, high:1, medium:2, low:3};
const TYPE = {brute_force:'Brute force', password_spray:'Password spraying', compromise:'Login after failed attempts',
  attack_ip_login:'Login from attacking IP', concurrent_sessions:'Simultaneous sessions', impossible_travel:'Country change',
  new_country:'New country', shared_ip:'Shared IP', large_upload:'Large upload', large_transfer:'Large transfer', long_session:'Long session'};

const users = D.users; users.forEach((u,i) => { u.i = i; u.total = u.up + u.down; u.lc = u.n.toLowerCase(); });
const ips = D.ips; const ipMap = new Map(ips.map(x => [x.ip, x])); ips.forEach(x => x.total = x.up + x.down);
const sessions = D.sessions.map(r => ({u:r[0], ip:r[1], s:r[2], e:r[3], secs:r[4], up:r[5], down:r[6], inside:r[7], open:r[8], reason:r[9], g:r[10]}));
const fails = D.fails.map(r => ({u:r[0], ip:r[1], t:r[2]}));
const edges = D.edges.map(r => ({u:r[0], ip:r[1], sess:r[2], fails:r[3], up:r[4], down:r[5], secs:r[6]}));
const incidents = D.incidents;
function group(a, f){ const m = new Map(); for(const x of a){ const k=f(x); if(!m.has(k)) m.set(k, []); m.get(k).push(x); } return m; }
const sByU = group(sessions, s => s.u), sByIp = group(sessions, s => s.ip), fByU = group(fails, f => f.u), fByIp = group(fails, f => f.ip);
const eByU = group(edges, e => e.u), eByIp = group(edges, e => e.ip);
const incByU = new Map(), incByIp = new Map();
for(const x of incidents){ for(const u of x.users){ if(!incByU.has(u)) incByU.set(u, []); incByU.get(u).push(x); } for(const ip of x.ips){ if(!incByIp.has(ip)) incByIp.set(ip, []); incByIp.get(ip).push(x); } }
const flaggedIp = ip => { const x = ipMap.get(ip); return !!(x && (x.role === 'attacker' || x.role === 'compromise')); };
const uRef = i => `<button class="ref" data-u="${i}">${esc(users[i].n)}</button>`;
const ipRef = ip => `<button class="ref ip" data-ip="${esc(ip)}">${esc(ip)}</button>`;

/* ---------- tooltip ---------- */
const tip = $('#tip');
function showTip(h, x, y){ tip.innerHTML = h; tip.style.display = 'block'; const r = tip.getBoundingClientRect(); let L = x + 14, Tp = y + 14; if(L + r.width > innerWidth - 8) L = x - r.width - 14; if(Tp + r.height > innerHeight - 8) Tp = y - r.height - 14; tip.style.left = Math.max(6, L) + 'px'; tip.style.top = Math.max(6, Tp) + 'px'; }
function hideTip(){ tip.style.display = 'none'; }
document.addEventListener('pointermove', e => { const t = e.target.closest && e.target.closest('[data-tip]'); if(t) showTip(t.getAttribute('data-tip'), e.clientX, e.clientY); else if(!e.target.closest('.daily-ov')) hideTip(); });
document.addEventListener('scroll', hideTip, true);

/* ---------- header ---------- */
const M = D.meta;
$('#period').textContent = `Covers ${niceDate(M.first)} to ${niceDate(M.last)}. ${fmtN(M.events)} parsed events from ${M.db}, generated ${short(M.generated)}.` + (M.geo ? '' : ' Country checks are off because no GeoIP database was used.');
function renderAttention(){
  const comp = users.filter(u => u.status === 'compromise').sort((a,b) => b.risk - a.risk);
  const atk = ips.filter(x => x.role === 'attacker').sort((a,b) => b.attacked - a.attacked || b.fails - a.fails);
  const list = (arr, fn, go, more) => arr.length ? `<div class="alist">${arr.slice(0,6).map(fn).join('')}${arr.length > 6 ? `<button class="more" data-go="${go}" data-more="${more}">Show all ${arr.length}</button>` : ''}</div>` : '';
  $('#attention').innerHTML =
    `<div><h2>Suspected compromised accounts <span class="count">${comp.length}</span></h2>` +
    (list(comp, u => `<button class="aitem" data-u="${u.i}"><i class="dot st-compromise"></i><span>${esc(u.n)}</span><span class="why">${esc(u.top)}</span></button>`, 'users', 'compromise') || '<p class="none">No account matches the compromise rules with the current thresholds.</p>') + `</div>` +
    `<div><h2>Attacking IP addresses <span class="count">${atk.length}</span></h2>` +
    (list(atk, x => `<button class="aitem" data-ip="${esc(x.ip)}"><i class="dot st-compromise" style="border-radius:1px;transform:rotate(45deg)"></i><span class="ip">${esc(x.ip)}</span><span class="why">${fmtN(x.fails)} failed logins against ${fmtN(x.attacked)} account${x.attacked === 1 ? '' : 's'}${x.country ? ', ' + esc(x.country) : ''}${x.users ? `, <b>${x.users} successful</b>` : ''}</span></button>`, 'ips', 'attacker') || '<p class="none">No IP crossed the brute-force or spraying thresholds.</p>') + `</div>`;
  const nI = s => incidents.filter(x => x.sev === s).length;
  $('#kpis').innerHTML = [
    ['', fmtN(M.sessions), 'VPN sessions'], ['', fmtN(users.filter(u => u.sess).length), 'Accounts connected'],
    ['up', fmtB(M.up), 'Uploaded by users'], ['down', fmtB(M.down), 'Downloaded by users'], ['', fmtD(M.secs), 'Total connected time'],
    ['', fmtN(M.fails), 'Failed logins'], [nI('critical') ? 'crit' : '', nI('critical') + ' / ' + nI('high'), 'Critical / high incidents']
  ].map(k => `<div class="kpi ${k[0]}"><b>${k[1]}</b><span>${k[2]}</span></div>`).join('');
}

/* ---------- daily chart ---------- */
function fillDays(map, d0, d1){ const out = []; let t = Date.parse(d0 + 'T00:00:00Z'); const end = Date.parse(d1 + 'T00:00:00Z'); while(t <= end){ const k = new Date(t).toISOString().slice(0,10); out.push(Object.assign({d:k, up:0, down:0, sess:0, fails:0}, map.get(k) || {})); t += 86400000; } return out; }
function dailyChart(el, days, compact){
  el.innerHTML = '';
  if(!days.length){ el.innerHTML = '<p class="empty">No activity in this period.</p>'; return; }
  const W = Math.max(el.clientWidth, 280), padL = W < 500 ? 56 : 62, half = compact ? 60 : 92, failH = compact ? 20 : 28, axisH = 20;
  const H = half * 2 + 10 + failH + axisH, n = days.length, bw = (W - padL) / n, mid = half;
  let mx = 1, mf = 1; for(const d of days){ mx = Math.max(mx, d.up, d.down); mf = Math.max(mf, d.fails); }
  const w = Math.min(Math.max(bw - (bw > 3 ? 1 : 0), 0.7), 28), off = (bw - w) / 2;
  let s = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Uploaded and downloaded data per day">`;
  s += `<line class="grid" x1="${padL}" x2="${W}" y1="1" y2="1"/><line class="grid" x1="${padL}" x2="${W}" y1="${half*2}" y2="${half*2}"/>`;
  s += `<text class="ax" x="${padL-6}" y="11" text-anchor="end">${fmtB(mx)}</text><text class="ax" x="${padL-6}" y="${mid-4}" text-anchor="end" style="fill:var(--up)">up</text>`;
  s += `<text class="ax" x="${padL-6}" y="${mid+13}" text-anchor="end" style="fill:var(--down)">down</text><text class="ax" x="${padL-6}" y="${half*2-2}" text-anchor="end">${fmtB(mx)}</text>`;
  let bars = '';
  const f0 = half * 2 + 10;
  days.forEach((d, i) => {
    const x = padL + i * bw + off;
    if(d.up) { const h = Math.max(d.up / mx * half, 1); bars += `<rect class="up" x="${x.toFixed(2)}" y="${(mid-h).toFixed(2)}" width="${w.toFixed(2)}" height="${h.toFixed(2)}"/>`; }
    if(d.down){ const h = Math.max(d.down / mx * half, 1); bars += `<rect class="down" x="${x.toFixed(2)}" y="${mid}" width="${w.toFixed(2)}" height="${h.toFixed(2)}"/>`; }
    if(d.fails){ const h = Math.max(d.fails / mf * failH, 1.5); bars += `<rect class="fail" x="${x.toFixed(2)}" y="${(f0+failH-h).toFixed(2)}" width="${w.toFixed(2)}" height="${h.toFixed(2)}"/>`; }
  });
  s += `<g shape-rendering="crispEdges">${bars}</g><line class="axl" x1="${padL}" x2="${W}" y1="${mid}" y2="${mid}"/>`;
  s += `<text class="ax" x="${padL-6}" y="${f0+failH-2}" text-anchor="end" style="fill:var(--crit)">${fmtN(mf)}</text>`;
  let lastX = -1e9;
  days.forEach((d, i) => {
    const day = +d.d.slice(8,10), mon = +d.d.slice(5,7);
    if(i === 0 || day === 1){ const x = padL + i * bw; if(x - lastX > 64){ s += `<text class="ax" x="${x.toFixed(1)}" y="${H-5}">${MON[mon-1]} ${d.d.slice(0,4)}</text>`; lastX = x; } }
  });
  s += `<line class="hl" id="hl" x1="0" x2="0" y1="0" y2="${f0+failH}" style="display:none"/>`;
  s += `<rect class="daily-ov" x="${padL}" y="0" width="${W-padL}" height="${H}" fill="transparent"/></svg>`;
  el.innerHTML = s;
  const ov = el.querySelector('.daily-ov'), hl = el.querySelector('#hl');
  const move = e => { const r = ov.getBoundingClientRect(); const i = Math.min(n-1, Math.max(0, Math.floor((e.clientX - r.left) / r.width * n))); const d = days[i]; const x = padL + (i + 0.5) * bw;
    hl.setAttribute('x1', x); hl.setAttribute('x2', x); hl.style.display = '';
    showTip(`<b>${niceDate(d.d)}</b><br>Uploaded ${fmtB(d.up)}<br>Downloaded ${fmtB(d.down)}<br>${fmtN(d.sess)} sessions${d.users != null ? ', ' + fmtN(d.users) + ' accounts' : ''}<br>${fmtN(d.fails)} failed logins`, e.clientX, e.clientY); };
  ov.addEventListener('pointermove', move); ov.addEventListener('pointerdown', move);
  ov.addEventListener('pointerleave', () => { hl.style.display = 'none'; hideTip(); });
}

/* ---------- ledger ---------- */
function ledger(list, opts){
  opts = opts || {};
  if(!list.length) return '<p class="empty">No accounts match.</p>';
  let mx = 1; for(const u of list) mx = Math.max(mx, u.up, u.down);
  const pct = v => v ? Math.max(v / mx * 100, 0.6).toFixed(2) : 0;
  const wide = !!opts.wide;
  let h = `<div class="ledger ${wide ? 'wide' : ''}"><div class="lh"><span class="c-name">Account</span><span class="c-up">Uploaded</span><span class="c-down">Downloaded</span><span class="ltime c-time">Connected</span>` +
    (wide ? '<span class="lx">Sessions</span><span class="lx">IPs</span><span class="lx">Failed</span>' : '') + '</div>';
  for(const u of list){
    h += `<button class="lrow" data-u="${u.i}" data-tip="${esc(`<b>${esc(u.n)}</b><br>${STATUS[u.status]}${u.top ? ': ' + esc(u.top) : ''}<br>Uploaded ${fmtB(u.up)}, downloaded ${fmtB(u.down)}<br>Connected ${fmtD(u.secs)} in ${fmtN(u.sess)} sessions`)}">` +
      `<span class="lname"><i class="dot st-${u.status}"></i><span class="t">${esc(u.n)}</span></span>` +
      `<span class="lup"><span class="track"><span class="bar up" style="width:${pct(u.up)}%"></span></span><span class="lv">${fmtB(u.up)}</span></span>` +
      `<span class="ldown"><span class="track"><span class="bar down" style="width:${pct(u.down)}%"></span></span><span class="lv">${fmtB(u.down)}</span></span>` +
      `<span class="ltime">${fmtD(u.secs)}</span>` +
      (wide ? `<span class="lx">${fmtN(u.sess)}</span><span class="lx">${fmtN(u.ips)}</span><span class="lx ${u.fails ? 'bad' : ''}">${fmtN(u.fails)}</span>` : '') + '</button>';
  }
  return h + '</div>';
}
function timeBars(list){
  let mx = 1; for(const u of list) mx = Math.max(mx, u.secs);
  return `<div class="ledger">` + list.map(u => `<button class="lrow" style="grid-template-columns:minmax(7rem,11rem) 1fr 5.5rem;grid-template-areas:none" data-u="${u.i}"><span class="lname" style="grid-area:auto"><i class="dot st-${u.status}"></i><span class="t">${esc(u.n)}</span></span><span class="track"><span class="bar" style="background:var(--sess);width:${Math.max(u.secs/mx*100,0.6).toFixed(2)}%"></span></span><span class="ltime" style="grid-area:auto">${fmtD(u.secs)}</span></button>`).join('') + '</div>';
}
function renderOverview(){
  const dm = new Map(D.daily.map(d => [d.d, d]));
  dailyChart($('#daily'), D.daily);
  const act = users.filter(u => u.sess);
  $('#topdata').innerHTML = ledger(act.slice().sort((a,b) => b.total - a.total).slice(0, 12));
  $('#toptime').innerHTML = timeBars(act.slice().sort((a,b) => b.secs - a.secs).slice(0, 12));
}

/* ---------- incidents ---------- */
const incState = {sev: new Set(['critical','high','medium','low'])};
function incRow(x){
  const us = x.users.slice(0, 8).map(uRef).join(', ') + (x.users.length > 8 ? ` and ${x.users.length - 8} more` : '');
  const is = x.ips.slice(0, 6).map(ipRef).join(', ') + (x.ips.length > 6 ? ` and ${x.ips.length - 6} more` : '');
  return `<article class="inc ${x.sev}"><div class="inc-h"><span class="badge c-${x.sev}">${SEV[x.sev]}</span><h3>${esc(x.title)}</h3></div>` +
    `<p>${esc(x.detail)}</p><div class="inc-m"><span>${esc(TYPE[x.type] || x.type)}</span><span>${short(x.start)}${x.end && x.end.slice(0,16) !== x.start.slice(0,16) ? ' to ' + short(x.end) : ''}</span>` +
    (us ? `<span>Accounts: ${us}</span>` : '') + (is ? `<span>IPs: ${is}</span>` : '') + '</div>' +
    (x.seqs && x.seqs.length ? `<details><summary>Evidence (event seq numbers)</summary>${x.seqs.map(esc).join(', ')}</details>` : '') + '</article>';
}
let incLimit = 150;
function renderIncidents(){
  const counts = {}; for(const x of incidents) counts[x.sev] = (counts[x.sev] || 0) + 1;
  $('#sevchips').innerHTML = Object.keys(SEV).map(s => `<button class="chip" data-sev="${s}" aria-pressed="${incState.sev.has(s)}"><i class="sq" style="background:var(--${s === 'critical' ? 'crit' : s === 'medium' ? 'med' : s})"></i>${SEV[s]} ${counts[s] || 0}</button>`).join('');
  const q = $('#inc-q').value.trim().toLowerCase(), ty = $('#inc-type').value, so = $('#inc-sort').value;
  let list = incidents.filter(x => incState.sev.has(x.sev) && (!ty || x.type === ty) &&
    (!q || (x.title + ' ' + x.detail + ' ' + x.ips.join(' ') + ' ' + x.users.map(i => users[i].n).join(' ')).toLowerCase().includes(q)));
  if(so === 'new') list.sort((a,b) => b.start.localeCompare(a.start)); else if(so === 'old') list.sort((a,b) => a.start.localeCompare(b.start)); else list.sort((a,b) => SEVO[a.sev] - SEVO[b.sev] || b.start.localeCompare(a.start));
  $('#inc-count').textContent = `${fmtN(list.length)} of ${fmtN(incidents.length)} incidents`;
  $('#inc-list').innerHTML = list.length ? list.slice(0, incLimit).map(incRow).join('') + (list.length > incLimit ? `<button class="more" id="inc-more">Show ${Math.min(150, list.length - incLimit)} more</button>` : '') : '<p class="empty">No incidents match these filters.</p>';
}
function initIncidentControls(){
  const types = [...new Set(incidents.map(x => x.type))];
  $('#inc-type').innerHTML = '<option value="">All types</option>' + types.map(t => `<option value="${t}">${esc(TYPE[t] || t)}</option>`).join('');
  $('#sevchips').addEventListener('click', e => { const b = e.target.closest('[data-sev]'); if(!b) return; const s = b.dataset.sev; incState.sev.has(s) ? incState.sev.delete(s) : incState.sev.add(s); incLimit = 150; renderIncidents(); });
  ['inc-q','inc-type','inc-sort'].forEach(id => $('#'+id).addEventListener('input', () => { incLimit = 150; renderIncidents(); }));
  $('#inc-list').addEventListener('click', e => { if(e.target.id === 'inc-more'){ incLimit += 150; renderIncidents(); } });
}

/* ---------- accounts ---------- */
let uLimit = 200;
function renderUsers(){
  const q = $('#u-q').value.trim().toLowerCase(), so = $('#u-sort').value, st = $('#u-status').value;
  let list = users.filter(u => (st === 'failonly' ? !u.sess : u.sess && (!st || u.status === st)) && (!q || u.lc.includes(q)));
  const key = so === 'n' ? null : so;
  list.sort(key ? (a,b) => b[key] - a[key] || a.lc.localeCompare(b.lc) : (a,b) => a.lc.localeCompare(b.lc));
  $('#u-count').textContent = `${fmtN(list.length)} accounts. Bars share one scale: uploaded grows left, downloaded grows right.`;
  $('#u-list').innerHTML = ledger(list.slice(0, uLimit), {wide:true}) + (list.length > uLimit ? `<button class="more" id="u-more">Show ${Math.min(200, list.length - uLimit)} more</button>` : '');
}

/* ---------- IPs ---------- */
let iLimit = 200;
function renderIps(){
  const q = $('#i-q').value.trim().toLowerCase(), so = $('#i-sort').value, ro = $('#i-role').value;
  let list = ips.filter(x => (!ro || x.role === ro) && (!q || (x.ip + ' ' + x.country + ' ' + x.cc).toLowerCase().includes(q)));
  list.sort((a,b) => b[so] - a[so] || b.fails - a.fails);
  $('#i-count').textContent = `${fmtN(list.length)} source IPs`;
  $('#i-list').innerHTML = `<table><thead><tr><th>IP address</th><th>Country</th><th>Role</th><th class="num">Accounts connected</th><th class="num">Accounts attacked</th><th class="num">Failed logins</th><th class="num">Sessions</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th>Last seen</th></tr></thead><tbody>` +
    list.slice(0, iLimit).map(x => `<tr class="click" data-ip="${esc(x.ip)}"><td class="ip">${esc(x.ip)}</td><td>${esc(x.country || '–')}</td><td>${x.role ? `<span class="badge c-${x.role}">${ROLE[x.role]}</span>` : ''}</td><td class="num">${fmtN(x.users)}</td><td class="num">${fmtN(x.attacked)}</td><td class="num">${fmtN(x.fails)}</td><td class="num">${fmtN(x.sess)}</td><td class="num up">${fmtB(x.up)}</td><td class="num down">${fmtB(x.down)}</td><td>${short(x.last)}</td></tr>`).join('') +
    '</tbody></table>' + (list.length > iLimit ? `<button class="more" id="i-more">Show ${Math.min(200, list.length - iLimit)} more</button>` : '');
}

/* ---------- connections map ---------- */
const G = {view:null, nodes:[], links:[], sel:null};
function graphData(){
  const scope = $('#g-scope').value, showF = $('#g-fails').checked, q = $('#g-q').value.trim().toLowerCase();
  const ok = e => (e.sess > 0 || (showF && e.fails > 0 && users[e.u].sess > 0));
  const E = edges.filter(ok);
  const uKey = i => 'u' + i, iKey = ip => 'i' + ip;
  let keep = new Set();
  if(q){
    const seeds = new Set();
    users.forEach(u => { if(u.lc.includes(q)) seeds.add(uKey(u.i)); });
    ips.forEach(x => { if(x.ip.startsWith(q)) seeds.add(iKey(x.ip)); });
    keep = new Set(seeds);
    for(let hop = 0; hop < 2; hop++){ const add = []; for(const e of E){ const a = uKey(e.u), b = iKey(e.ip); if(keep.has(a) && !keep.has(b)) add.push(b); if(keep.has(b) && !keep.has(a)) add.push(a); } add.forEach(k => keep.add(k)); }
  } else if(scope === 'flag'){
    users.forEach(u => { if(u.sess && u.status !== 'normal') keep.add(uKey(u.i)); });
    ips.forEach(x => { if(x.role) keep.add(iKey(x.ip)); });
    const add = []; for(const e of E){ const a = uKey(e.u), b = iKey(e.ip); if(keep.has(a) || keep.has(b)){ add.push(a, b); } } add.forEach(k => keep.add(k));
  } else {
    E.forEach(e => { keep.add(uKey(e.u)); keep.add(iKey(e.ip)); });
  }
  const weight = k => k[0] === 'u' ? (users[+k.slice(1)].risk * 1e13 + users[+k.slice(1)].total) : ((ipMap.get(k.slice(1)) || {risk:0}).risk * 1e13 + ((ipMap.get(k.slice(1)) || {}).total || 0));
  const MAX = 350; let capped = false;
  if(keep.size > MAX){ keep = new Set([...keep].sort((a,b) => weight(b) - weight(a)).slice(0, MAX)); capped = true; }
  const nodes = [...keep].map(k => k[0] === 'u' ? {k, type:'u', u:users[+k.slice(1)]} : {k, type:'i', x0:ipMap.get(k.slice(1)) || {ip:k.slice(1), role:'', total:0}});
  const idx = new Map(nodes.map((n, i) => [n.k, i]));
  const links = []; for(const e of E){ const a = idx.get(uKey(e.u)), b = idx.get(iKey(e.ip)); if(a != null && b != null) links.push({a, b, e}); }
  const deg = new Array(nodes.length).fill(0); links.forEach(l => { deg[l.a]++; deg[l.b]++; });
  const final = nodes.filter((n, i) => deg[i] > 0 || (q && ((n.type === 'u' && n.u.lc.includes(q)) || (n.type === 'i' && n.x0.ip.startsWith(q)))));
  const idx2 = new Map(final.map((n, i) => [n.k, i]));
  const links2 = links.map(l => ({a: idx2.get(nodes[l.a].k), b: idx2.get(nodes[l.b].k), e: l.e})).filter(l => l.a != null && l.b != null);
  return {nodes: final, links: links2, capped, q};
}
function layout(nodes, links, W, H){
  const n = nodes.length; if(!n) return;
  const k = Math.sqrt(W * H / n) * 0.75, cx = W / 2, cy = H / 2;
  nodes.forEach((d, i) => { const a = i * 2.39996, r = Math.sqrt((i + 0.5) / n) * Math.min(W, H) * 0.45; d.x = cx + r * Math.cos(a); d.y = cy + r * Math.sin(a); });
  let temp = W / 8; const it = n > 250 ? 220 : 320;
  const dx = new Float64Array(n), dy = new Float64Array(n);
  for(let t = 0; t < it; t++){
    dx.fill(0); dy.fill(0);
    for(let i = 0; i < n; i++){ const a = nodes[i]; for(let j = i + 1; j < n; j++){ const b = nodes[j]; let x = a.x - b.x, y = a.y - b.y; let d2 = x*x + y*y; if(d2 < 0.01){ x = Math.random() - .5; y = Math.random() - .5; d2 = 0.5; } const f = k * k / d2; dx[i] += x * f; dy[i] += y * f; dx[j] -= x * f; dy[j] -= y * f; } }
    for(const l of links){ const a = nodes[l.a], b = nodes[l.b]; const x = a.x - b.x, y = a.y - b.y; const d = Math.sqrt(x*x + y*y) || 0.01; const f = d / k; dx[l.a] -= x * f; dy[l.a] -= y * f; dx[l.b] += x * f; dy[l.b] += y * f; }
    for(let i = 0; i < n; i++){ const a = nodes[i]; dx[i] += (cx - a.x) * 0.03; dy[i] += (cy - a.y) * 0.03; const d = Math.sqrt(dx[i]*dx[i] + dy[i]*dy[i]) || 1; const m = Math.min(d, temp); a.x += dx[i] / d * m; a.y += dy[i] / d * m; }
    temp *= 0.985; if(temp < 0.5) temp = 0.5;
  }
}
function drawGraph(){
  const svg = $('#graph'); const W = svg.clientWidth || 800, H = svg.clientHeight || 600;
  const gd = graphData(); G.nodes = gd.nodes; G.links = gd.links; G.sel = null;
  if(!gd.nodes.length){ svg.innerHTML = ''; $('#g-note').textContent = gd.q ? 'Nothing matches that account or IP.' : 'No accounts or IPs with findings. Switch to "Everything" to see all connections.'; return; }
  layout(gd.nodes, gd.links, W, H);
  { let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9; for(const n of gd.nodes){ x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y); }
    const aw = W - 170, ah = H - 50, sc = Math.min(aw / Math.max(x1 - x0, 1), ah / Math.max(y1 - y0, 1));
    const ox = 30 + (aw - (x1 - x0) * sc) / 2, oy = 25 + (ah - (y1 - y0) * sc) / 2;
    for(const n of gd.nodes){ n.x = ox + (n.x - x0) * sc; n.y = oy + (n.y - y0) * sc; } }
  let mxB = 1; gd.links.forEach(l => mxB = Math.max(mxB, l.e.up + l.e.down));
  let mxU = 1; gd.nodes.forEach(n => { if(n.type === 'u') mxU = Math.max(mxU, n.u.total); });
  const showAll = gd.nodes.length <= 70;
  let s = '<g id="gv">';
  for(const l of gd.links){ const a = gd.nodes[l.a], b = gd.nodes[l.b]; const e = l.e; const failOnly = !e.sess;
    const w = failOnly ? 1.2 : 1 + Math.sqrt((e.up + e.down) / mxB) * 6;
    const t = `<b>${esc(users[e.u].n)}</b> and <span class="ip">${esc(e.ip)}</span><br>${fmtN(e.sess)} sessions, ${fmtD(e.secs)} connected<br>Uploaded ${fmtB(e.up)}, downloaded ${fmtB(e.down)}${e.fails ? '<br>' + fmtN(e.fails) + ' failed logins' : ''}`;
    s += `<line class="gl ${failOnly ? 'fail' : ''}" data-a="${l.a}" data-b="${l.b}" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke-width="${w.toFixed(2)}" data-tip="${esc(t)}"/>`; }
  gd.nodes.forEach((n, i) => {
    let shape, label, t, fill;
    if(n.type === 'u'){ const u = n.u; const r = 5 + Math.sqrt(u.total / mxU) * 12;
      fill = u.status === 'compromise' ? 'var(--crit)' : u.status === 'targeted' ? 'var(--high)' : u.status === 'watch' ? 'var(--med)' : 'var(--sess)';
      shape = `<circle r="${r.toFixed(1)}" fill="${fill}"/>`; label = u.n; n.r = r;
      t = `<b>${esc(u.n)}</b><br>${STATUS[u.status]}<br>Uploaded ${fmtB(u.up)}, downloaded ${fmtB(u.down)}<br>Connected ${fmtD(u.secs)}`;
    } else { const x = n.x0; fill = x.role === 'attacker' || x.role === 'compromise' ? 'var(--crit)' : x.role === 'shared' ? 'var(--med)' : 'var(--rule2)';
      shape = `<rect x="-6" y="-6" width="12" height="12" transform="rotate(45)" fill="${fill}"/>`; label = x.ip; n.r = 8;
      t = `<b class="ip">${esc(x.ip)}</b>${x.country ? ' ' + esc(x.country) : ''}<br>${x.role ? ROLE[x.role] + '<br>' : ''}${fmtN(x.users || 0)} accounts connected, ${fmtN(x.attacked || 0)} attacked`; }
    const lab = showAll || (n.type === 'u' ? n.u.status !== 'normal' : !!n.x0.role);
    s += `<g class="gn" data-n="${i}" transform="translate(${n.x.toFixed(1)},${n.y.toFixed(1)})" data-tip="${esc(t)}">${shape}${lab ? `<text x="${(n.r + 4).toFixed(1)}" y="4" ${n.type === 'i' ? 'class="ip"' : ''}>${esc(label)}</text>` : ''}</g>`;
  });
  svg.innerHTML = s + '</g>';
  fitGraph();
  $('#g-note').textContent = `${fmtN(gd.nodes.filter(n => n.type === 'u').length)} accounts and ${fmtN(gd.nodes.filter(n => n.type === 'i').length)} IPs shown.` + (gd.capped ? ' Limited to the 350 riskiest and busiest; search to trace a specific account or IP.' : '') + ' Tap a node to highlight its links and open details.';
}
function setView(v){ G.view = v; $('#graph').setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`); }
function fitGraph(){ if(!G.nodes.length) return; let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9; for(const n of G.nodes){ x0 = Math.min(x0, n.x - 20); y0 = Math.min(y0, n.y - 20); x1 = Math.max(x1, n.x + 110); y1 = Math.max(y1, n.y + 20); }
  const svg = $('#graph'), W = svg.clientWidth || 800, H = svg.clientHeight || 600; let w = x1 - x0, h = y1 - y0; const ar = W / H;
  if(w / h > ar){ const nh = w / ar; y0 -= (nh - h) / 2; h = nh; } else { const nw = h * ar; x0 -= (nw - w) / 2; w = nw; } setView({x:x0, y:y0, w, h}); }
function zoom(f, cx, cy){ const v = G.view; if(!v) return; if(cx == null){ cx = v.x + v.w / 2; cy = v.y + v.h / 2; } setView({x: cx - (cx - v.x) * f, y: cy - (cy - v.y) * f, w: v.w * f, h: v.h * f}); }
function selectNode(i){
  G.sel = i; const svg = $('#graph');
  const nb = new Set(i == null ? [] : [i]); G.links.forEach(l => { if(l.a === i) nb.add(l.b); if(l.b === i) nb.add(l.a); });
  svg.querySelectorAll('.gn').forEach(g => { const k = +g.dataset.n; g.classList.toggle('dim', i != null && !nb.has(k)); g.classList.toggle('sel', k === i); });
  svg.querySelectorAll('.gl').forEach(l => l.classList.toggle('dim', i != null && +l.dataset.a !== i && +l.dataset.b !== i));
}
function initGraph(){
  const svg = $('#graph'); let drag = null;
  svg.addEventListener('pointerdown', e => { drag = {x:e.clientX, y:e.clientY, v:Object.assign({}, G.view), moved:false}; svg.setPointerCapture(e.pointerId); svg.style.cursor = 'grabbing'; });
  svg.addEventListener('pointermove', e => { if(!drag || !G.view) return; const dx = e.clientX - drag.x, dy = e.clientY - drag.y; if(Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true; if(!drag.moved) return; const sc = drag.v.w / svg.clientWidth; setView({x: drag.v.x - dx * sc, y: drag.v.y - dy * sc, w: drag.v.w, h: drag.v.h}); hideTip(); });
  svg.addEventListener('pointerup', e => { svg.style.cursor = ''; const d = drag; drag = null; if(!d || d.moved) return;
    const el = document.elementFromPoint(e.clientX, e.clientY); const g = el && el.closest('.gn');
    if(g){ const i = +g.dataset.n; selectNode(i); const n = G.nodes[i]; if(n.type === 'u') openUser(n.u.i); else openIp(n.x0.ip); } else selectNode(null); });
  svg.addEventListener('wheel', e => { if(!G.view) return; e.preventDefault(); const r = svg.getBoundingClientRect(); const cx = G.view.x + (e.clientX - r.left) / r.width * G.view.w, cy = G.view.y + (e.clientY - r.top) / r.height * G.view.h; zoom(e.deltaY > 0 ? 1.15 : 1 / 1.15, cx, cy); }, {passive:false});
  $('#g-in').onclick = () => zoom(1 / 1.3); $('#g-out').onclick = () => zoom(1.3); $('#g-fit').onclick = fitGraph;
  let tm; ['g-scope','g-fails'].forEach(id => $('#'+id).addEventListener('change', drawGraph));
  $('#g-q').addEventListener('input', () => { clearTimeout(tm); tm = setTimeout(drawGraph, 300); });
}

/* ---------- drawer ---------- */
let lastDrawer = null, lastFocus = null;
function gantt(el, ss, fl){
  el.innerHTML = '';
  if(!ss.length && !fl.length){ el.innerHTML = '<p class="empty">No sessions.</p>'; return; }
  const W = Math.max(el.clientWidth, 280), lw = W < 480 ? 100 : 136, laneH = 22, MAXL = 14;
  const cnt = new Map(); for(const s of ss) cnt.set(s.ip, (cnt.get(s.ip) || 0) + 3); for(const f of fl) cnt.set(f.ip, (cnt.get(f.ip) || 0) + 1);
  let lanes = [...cnt.keys()].sort((a,b) => cnt.get(b) - cnt.get(a)); let other = false;
  if(lanes.length > MAXL){ lanes = lanes.slice(0, MAXL - 1); other = true; }
  const li = new Map(lanes.map((ip, i) => [ip, i])); const laneOf = ip => li.has(ip) ? li.get(ip) : MAXL - 1; const nL = lanes.length + (other ? 1 : 0);
  let t0 = Infinity, t1 = -Infinity; for(const s of ss){ t0 = Math.min(t0, T(s.s)); t1 = Math.max(t1, T(s.e)); } for(const f of fl){ const t = T(f.t); t0 = Math.min(t0, t); t1 = Math.max(t1, t); }
  if(t1 - t0 < 3600e3){ t0 -= 1800e3; t1 += 1800e3; }
  const X = t => lw + (t - t0) / (t1 - t0) * (W - lw - 6), H = nL * laneH + 24;
  let s = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Sessions over time by source IP">`;
  for(let i = 0; i < nL; i++){ const y = i * laneH; const ip = i < lanes.length ? lanes[i] : null;
    s += `<line class="grid" x1="${lw}" x2="${W}" y1="${y + laneH}" y2="${y + laneH}"/>`;
    s += ip ? `<text class="ax ip" x="0" y="${y + 15}" data-ip="${esc(ip)}" style="cursor:pointer;${flaggedIp(ip) ? 'fill:var(--crit)' : ''}">${esc(ip.length > 18 ? ip.slice(0,17) + '…' : ip)}</text>` : `<text class="ax" x="0" y="${y + 15}">Other IPs</text>`; }
  for(const x of ss){ const i = laneOf(x.ip), xa = X(T(x.s)), w = Math.max(X(T(x.e)) - xa, 2);
    const tt = `<b class="ip">${esc(x.ip)}</b><br>${short(x.s)} to ${short(x.e)}${x.open ? ' (estimated)' : ''}<br>${fmtD(x.secs)} connected<br>Uploaded ${fmtB(x.up)}, downloaded ${fmtB(x.down)}${x.inside ? '<br>Inside IP ' + esc(x.inside) : ''}`;
    s += `<rect class="${flaggedIp(x.ip) ? 'flag' : 'sess'}" x="${xa.toFixed(1)}" y="${i * laneH + 4}" width="${w.toFixed(1)}" height="${laneH - 10}" ${x.open ? 'fill-opacity=".45"' : ''} data-tip="${esc(tt)}"/>`; }
  for(const f of fl){ const i = laneOf(f.ip), x = X(T(f.t)); s += `<rect class="fail" x="${(x - 1).toFixed(1)}" y="${i * laneH + laneH - 6}" width="2" height="5" opacity=".8" data-tip="${esc('Failed login ' + short(f.t) + ' from <span class=ip>' + esc(f.ip) + '</span>')}"/>`; }
  for(let k = 0; k <= 4; k++){ const t = t0 + (t1 - t0) * k / 4; const d = new Date(t).toISOString(); const x = X(t); s += `<text class="ax" x="${x.toFixed(1)}" y="${H - 4}" text-anchor="${k === 0 ? 'start' : k === 4 ? 'end' : 'middle'}">${t1 - t0 < 3 * 86400e3 ? d.slice(5,16).replace('T',' ') : d.slice(0,10)}</text>`; }
  el.innerHTML = s + '</svg>';
}
function sessTable(ss, id){
  const rows = ss.slice().sort((a,b) => b.s.localeCompare(a.s));
  const lim = +(document.getElementById(id) && document.getElementById(id).dataset.lim) || 100;
  return `<div class="tw" id="${id}" data-lim="${lim}"><table><thead><tr><th>Start</th><th>End</th><th class="num">Duration</th><th>Account / IP</th><th>Country</th><th>Inside IP</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th>Reason</th></tr></thead><tbody>` +
    rows.slice(0, lim).map(x => { const ipx = ipMap.get(x.ip) || {}; return `<tr><td>${esc(x.s)}</td><td>${esc(x.e)}${x.open ? ' *' : ''}</td><td class="num">${fmtD(x.secs)}</td><td>${id === 'ust' ? ipRef(x.ip) : uRef(x.u)}</td><td>${esc(ipx.country || '–')}</td><td class="ip">${esc(x.inside || '–')}</td><td class="num up">${fmtB(x.up)}</td><td class="num down">${fmtB(x.down)}</td><td>${esc(x.reason)}</td></tr>`; }).join('') +
    `</tbody></table>${rows.length > lim ? `<button class="more" data-more-rows="${id}">Show all ${fmtN(rows.length)} sessions</button>` : ''}${rows.some(x => x.open) ? '<p class="note">* No disconnect was logged, so the end is estimated from the next activity of the account.</p>' : ''}</div>`;
}
const fact = (v, l, c) => `<div class="fact ${c || ''}"><b>${v}</b><span>${l}</span></div>`;
function openDrawer(html, after){
  const dr = $('#drawer'); if(dr.hidden) lastFocus = document.activeElement;
  dr.innerHTML = html; dr.hidden = false; $('#scrim').hidden = false; document.body.style.overflow = 'hidden'; dr.scrollTop = 0;
  requestAnimationFrame(() => { after && after(); const c = dr.querySelector('.close'); c && c.focus({preventScroll:true}); });
}
function closeDrawer(){ $('#drawer').hidden = true; $('#scrim').hidden = true; document.body.style.overflow = ''; lastDrawer = null; hideTip(); if(lastFocus && lastFocus.focus) lastFocus.focus({preventScroll:true}); }
function openUser(i){
  const u = users[i]; lastDrawer = () => openUser(i);
  const ss = sByU.get(i) || [], fl = fByU.get(i) || [], inc = (incByU.get(i) || []).slice().sort((a,b) => SEVO[a.sev] - SEVO[b.sev]);
  const es = (eByU.get(i) || []).slice().sort((a,b) => (b.up + b.down) - (a.up + a.down) || b.fails - a.fails);
  const h = `<div class="dh"><div><h2>${esc(u.n)}</h2><p class="note"><span class="badge c-${u.status}">${STATUS[u.status]}</span> Risk ${u.risk}/100${u.groups.length ? ', group ' + esc(u.groups.join(', ')) : ''}</p></div><button class="close" data-close>Close</button></div>` +
    `<div class="facts">${fact(fmtB(u.up), 'Uploaded by user', 'up')}${fact(fmtB(u.down), 'Downloaded by user', 'down')}${fact(fmtD(u.secs), 'Connected time')}${fact(fmtN(u.sess), 'Sessions')}${fact(fmtN(u.ips), 'Source IPs')}${fact(u.ccs.length ? esc(u.ccs.join(', ')) : '–', 'Countries')}${fact(fmtN(u.fails), 'Failed logins', u.fails ? 'bad' : '')}${fact(short(u.first), 'First seen')}${fact(short(u.last), 'Last seen')}</div>` +
    (inc.length ? `<div class="sec"><h2>Findings <span class="count">${inc.length}</span></h2>${inc.map(incRow).join('')}</div>` : '') +
    `<div class="sec"><h2>Sessions by source IP</h2><p class="note">Each bar is one session; red marks IPs that attacked or were used in a compromise, ticks are failed logins.</p><div class="chart" id="d-gantt"></div></div>` +
    `<div class="sec"><div class="sec-h"><h2>Data per day</h2><div class="legend"><span><i class="sw" style="background:var(--up)"></i>Uploaded</span><span><i class="sw" style="background:var(--down)"></i>Downloaded</span><span><i class="sw" style="background:var(--crit)"></i>Failed logins</span></div></div><div class="chart" id="d-daily"></div></div>` +
    `<div class="sec"><h2>Source IPs</h2><div class="tw"><table><thead><tr><th>IP address</th><th>Country</th><th class="num">Sessions</th><th class="num">Connected</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th class="num">Failed logins</th></tr></thead><tbody>` +
    es.map(e => { const x = ipMap.get(e.ip) || {}; return `<tr class="click" data-ip="${esc(e.ip)}"><td class="ip" ${flaggedIp(e.ip) ? 'style="color:var(--crit)"' : ''}>${esc(e.ip)}</td><td>${esc(x.country || '–')}</td><td class="num">${fmtN(e.sess)}</td><td class="num">${fmtD(e.secs)}</td><td class="num up">${fmtB(e.up)}</td><td class="num down">${fmtB(e.down)}</td><td class="num">${fmtN(e.fails)}</td></tr>`; }).join('') + '</tbody></table></div></div>' +
    `<div class="sec"><h2>Sessions <span class="count">${fmtN(ss.length)}</span></h2>${ss.length ? sessTable(ss, 'ust') : '<p class="empty">This name never connected; it only appears in failed logins.</p>'}</div>`;
  openDrawer(h, () => {
    gantt($('#d-gantt'), ss, fl);
    const m = new Map(); const add = (d, k, v) => { if(!m.has(d)) m.set(d, {up:0, down:0, sess:0, fails:0}); m.get(d)[k] += v; };
    ss.forEach(x => { const d = x.s.slice(0,10); add(d, 'up', x.up); add(d, 'down', x.down); add(d, 'sess', 1); }); fl.forEach(f => add(f.t.slice(0,10), 'fails', 1));
    const ks = [...m.keys()].sort(); dailyChart($('#d-daily'), ks.length ? fillDays(m, ks[0], ks[ks.length - 1]) : [], true);
  });
}
function openIp(ip){
  const x = ipMap.get(ip); if(!x) return; lastDrawer = () => openIp(ip);
  const ss = sByIp.get(ip) || [], fl = fByIp.get(ip) || [], inc = (incByIp.get(ip) || []).slice().sort((a,b) => SEVO[a.sev] - SEVO[b.sev]);
  const es = (eByIp.get(ip) || []).slice().sort((a,b) => b.sess - a.sess || (b.up + b.down) - (a.up + a.down) || b.fails - a.fails);
  const h = `<div class="dh"><div><h2 class="ip">${esc(ip)}</h2><p class="note">${esc(x.country || 'Country unknown')} ${x.role ? `<span class="badge c-${x.role}">${ROLE[x.role]}</span>` : ''}${x.trusted ? ' <span class="badge">Trusted</span>' : ''}</p></div><button class="close" data-close>Close</button></div>` +
    `<div class="facts">${fact(fmtN(x.users), 'Accounts connected')}${fact(fmtN(x.attacked), 'Accounts attacked', x.attacked ? 'bad' : '')}${fact(fmtN(x.fails), 'Failed logins', x.fails ? 'bad' : '')}${fact(fmtN(x.sess), 'Sessions')}${fact(fmtB(x.up), 'Uploaded', 'up')}${fact(fmtB(x.down), 'Downloaded', 'down')}${fact(fmtD(x.secs), 'Connected time')}${fact(short(x.first), 'First seen')}${fact(short(x.last), 'Last seen')}</div>` +
    (inc.length ? `<div class="sec"><h2>Findings <span class="count">${inc.length}</span></h2>${inc.slice(0, 40).map(incRow).join('')}</div>` : '') +
    `<div class="sec"><h2>Accounts linked to this IP</h2><div class="tw"><table><thead><tr><th>Account</th><th>Status</th><th class="num">Sessions</th><th class="num">Connected</th><th class="num">Uploaded</th><th class="num">Downloaded</th><th class="num">Failed logins</th></tr></thead><tbody>` +
    es.slice(0, 500).map(e => { const u = users[e.u]; return `<tr class="click" data-u="${e.u}"><td>${esc(u.n)}</td><td><span class="badge c-${u.status}">${STATUS[u.status]}</span></td><td class="num">${fmtN(e.sess)}</td><td class="num">${fmtD(e.secs)}</td><td class="num up">${fmtB(e.up)}</td><td class="num down">${fmtB(e.down)}</td><td class="num">${fmtN(e.fails)}</td></tr>`; }).join('') + `</tbody></table>${es.length > 500 ? `<p class="note">Showing 500 of ${fmtN(es.length)} accounts.</p>` : ''}</div></div>` +
    `<div class="sec"><h2>Sessions <span class="count">${fmtN(ss.length)}</span></h2>${ss.length ? sessTable(ss, 'ist') : '<p class="empty">No successful session from this IP.</p>'}</div>`;
  openDrawer(h);
}

/* ---------- navigation ---------- */
const VIEWS = ['overview','incidents','users','ips','links'];
let cur = 'overview';
function show(v){
  cur = v; VIEWS.forEach(x => { $('#v-' + x).hidden = x !== v; $('#t-' + x).setAttribute('aria-selected', String(x === v)); });
  if(v === 'overview') renderOverview(); else if(v === 'incidents') renderIncidents(); else if(v === 'users') renderUsers(); else if(v === 'ips') renderIps(); else if(v === 'links') drawGraph();
  try { localStorage.setItem('asa-view', v); } catch(e){}
}
document.querySelector('nav.tabs').addEventListener('click', e => { const b = e.target.closest('[data-v]'); if(b) show(b.dataset.v); });
document.addEventListener('click', e => {
  if(e.target.closest('#graph')) return;
  const c = e.target.closest('[data-close]'); if(c){ closeDrawer(); return; }
  const mr = e.target.closest('[data-more-rows]'); if(mr){ document.getElementById(mr.dataset.moreRows).dataset.lim = 1e9; const st = $('#drawer').scrollTop; lastDrawer && lastDrawer(); requestAnimationFrame(() => { $('#drawer').scrollTop = st; }); return; }
  const go = e.target.closest('[data-go]'); if(go){ if(go.dataset.more){ if(go.dataset.go === 'users') $('#u-status').value = go.dataset.more; else $('#i-role').value = go.dataset.more; } show(go.dataset.go); window.scrollTo({top: $('nav.tabs').offsetTop - 4}); return; }
  if(e.target.id === 'u-more'){ uLimit += 200; renderUsers(); return; }
  if(e.target.id === 'i-more'){ iLimit += 200; renderIps(); return; }
  const u = e.target.closest('[data-u]'); if(u){ openUser(+u.dataset.u); return; }
  const ip = e.target.closest('[data-ip]'); if(ip){ openIp(ip.dataset.ip); return; }
});
$('#scrim').addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => { if(e.key === 'Escape' && !$('#drawer').hidden) closeDrawer(); });
['u-q','u-sort','u-status'].forEach(id => $('#'+id).addEventListener('input', () => { uLimit = 200; renderUsers(); }));
['i-q','i-sort','i-role'].forEach(id => $('#'+id).addEventListener('input', () => { iLimit = 200; renderIps(); }));
let rt; let lastW = innerWidth;
addEventListener('resize', () => { if(Math.abs(innerWidth - lastW) < 30) return; lastW = innerWidth; clearTimeout(rt); rt = setTimeout(() => { if(cur === 'overview') renderOverview(); if(cur === 'links') drawGraph(); if(lastDrawer && !$('#drawer').hidden){ const st = $('#drawer').scrollTop; lastDrawer(); $('#drawer').scrollTop = st; } }, 200); });

renderAttention(); initIncidentControls(); initGraph();
let start = 'overview'; try { const s = localStorage.getItem('asa-view'); if(VIEWS.includes(s)) start = s; } catch(e){}
show(start);
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    raise SystemExit(main())
