# PyASA-Analys: Cisco ASA VPN log forensics

A self-contained Python toolkit for investigating Cisco ASA / Firepower (FTD) VPN logs exported as CSV. It rebuilds the missing years in syslog timestamps, finds compromised accounts and attacking IPs, links related findings into cases and IP clusters, and serves an interactive investigation dashboard on your own computer.

- **Standard library only.** No pip installs are needed for the core toolkit.
- **Local and private.** The dashboard runs on `127.0.0.1` and makes no outbound requests (fonts can be turned off too with `--no-web-fonts`).
- **Fast.** About 760,000 log rows import in under a minute and analyse in about 12 seconds on an ordinary laptop.

> **Use it on logs you are authorised to analyse.** The output contains usernames, IP addresses and session details. Treat the generated `out/` folder as sensitive.

---

## Contents

- [Quick start](#quick-start)
- [Files](#files)
- [Input format](#input-format)
- [What it detects](#what-it-detects)
- [How compromise is judged](#how-compromise-is-judged)
- [The dashboard](#the-dashboard)
- [Country lookup (GeoIP)](#country-lookup-geoip)
- [Command reference](#command-reference)
- [Tuning and false positives](#tuning-and-false-positives)
- [Output files](#output-files)
- [Logging requirements on the ASA](#logging-requirements-on-the-asa)
- [Limitations](#limitations)

---

## Quick start

Requires **Python 3.9 or newer** (tested on 3.13).

```bash
# 1. Import, analyse and open the dashboard in one step
python3 asa_server.py --import export.csv --outdir out --newest-year 2025

# 2. Same, with countries and your home country
python3 asa_server.py --import export.csv --outdir out \
    --geoip dbip-country-lite.csv.gz --home-countries CZ

# 3. Later: open an existing analysis without re-importing
python3 asa_server.py out/events.db --port 9090

# 4. Re-run only the analysis (e.g. new thresholds or a country database)
python3 asa_server.py out/events.db --reanalyze \
    --geoip dbip-country-lite.csv.gz --home-countries CZ,SK \
    --analyze-args "--trusted-ip 10.0.0.0/8 --work-hours 06-22"
```

The browser opens at `http://127.0.0.1:8765/` by default. Use `--port` to change it, and `--no-browser` to start without opening a browser.

---

## Files

| File | Purpose |
|---|---|
| `asa_parse.py` | Reads the CSV export, rebuilds timestamp years, recognises ASA message types and writes a SQLite database (`events.db`) plus per-year CSVs. |
| `asa_analyze.py` | Builds sessions, ties internal connections to VPN users, runs all detections, scores logins, links IPs into clusters and incidents into cases, and writes summary tables, CSVs and case reports. |
| `asa_server.py` | Local web server with the interactive dashboard. Can also run the two steps above (`--import`, `--reanalyze`). |

The scripts can also be run separately:

```bash
python3 asa_parse.py export.csv --outdir out --newest-year 2025
python3 asa_analyze.py out/events.db --outdir out --geoip dbip-country-lite.csv.gz
python3 asa_server.py out/events.db
```

---

## Input format

A CSV export with, by default, three columns:

```
seq,message,timestamp
1234567,"%ASA-6-113005: AAA user authentication Rejected : reason = Invalid password : ...","Nov 24 13:07:49"
```

| Column | Default | Option |
|---|---|---|
| Sequence number | column 0 | `--seq-col` |
| ASA message | column 1 | `--message-col` |
| Timestamp (`Mon DD HH:MM:SS`, or ISO) | last column | `--timestamp-col` |

### Rebuilding the year

Syslog timestamps such as `Nov 24 13:07:49` have no year. The parser walks the log from newest to oldest and counts New Year rollovers.

- Tell it the year of the **newest** entry with `--newest-year 2025`, or more precisely with `--newest-date 2025-04-30`.
- Rows are put in time order by sequence number. If your export has no reliable sequence, use `--order file` (oldest first) or `--order file-reversed` (newest first).
- Single out-of-order rows do not trigger a false year change; jumps are checked against the following rows.
- ISO timestamps are used directly, and `--year-anchor SEQ:YEAR` forces a year from a given sequence number on.
- Gaps longer than about a year cannot be detected from the timestamps alone. They are reported in `year_inference_report.csv`.

---

## What it detects

**Logins and credentials**

| Finding | Meaning |
|---|---|
| Brute force | Many wrong passwords for one account |
| Password spraying | One IP trying many accounts |
| Login after failed attempts | A successful login that followed failures (scored, see below) |
| Login from attacking IP | An account logged in from an IP that sprayed or scanned |
| Suspicious login (no failures) | A login with no failures that does not look like the owner (stolen or phished password) |
| Same new IP, several accounts | One new address used for the first time by several accounts |
| Coordinated attack (IP cluster) | Several IPs working together (see [IP clusters](#ip-clusters)) |
| Account lockout | The firewall locked an account |

**Login anomalies**

| Finding | Meaning |
|---|---|
| Simultaneous sessions | One account connected from two places at once |
| Country change / new country / login from abroad | Needs a country database |
| New VPN client | A new device type (Windows, macOS, Linux, iOS, Android…) |
| Unusual login time | An hour or day this account practically never uses |
| Shared IP, long session | Informational |

**Inside the network** (needs connection logging, see [below](#logging-requirements-on-the-asa))

| Finding | Meaning |
|---|---|
| Internal scanning | A VPN session touching many hosts or ports within minutes |
| Lateral movement | A session reaching many hosts over SMB, RDP, SSH, WinRM, etc. |
| Internal access after compromise | Which servers a suspicious session touched |
| Large / unusual download | Possible data exfiltration (data leaving through the VPN) |
| Large upload | Possible tool staging or ransomware preparation |

**Perimeter and firewall**

| Finding | Meaning |
|---|---|
| Port scan, threat detection | An external IP probing the firewall |
| Admin brute force, admin login from internet | Attacks on the firewall's own management login |
| Logging tampered | `clear logging`, `no logging` and similar (critical) |
| Firewall config change | Sensitive commands such as access lists, users, AAA, crypto |

Findings are mapped to **MITRE ATT&CK** tactics in the dashboard's Matrix view.

---

## How compromise is judged

### Login scoring

Every successful login preceded by failed attempts is scored **0–100**. Every reason, with its points, is shown in the dashboard under "Why this score".

| Evidence | Points |
|---|---|
| The IP was password spraying (5+ accounts) | +50 |
| Failed first from a partner IP in the same campaign, then got in here | +35 |
| Many wrong passwords for this account from this IP | up to +35 |
| The session scanned the network or moved laterally | +30 |
| The IP also failed against 2–4 other accounts | +25 |
| Other accounts also got in from the same failing IP | +20 |
| The IP also port-scanned or attacked the firewall's admin login | +20 |
| First time from this IP and its network; new device; foreign country; large download | +15 each |
| Lockout shortly before; unusual hour; hidden user names tried | +10 each |
| The IP is the account's normal address (used on 2+ days) | −30 |
| The IP is in a provider network this account uses regularly (dynamic address) | −15 |
| Shared office/NAT address used regularly by 3+ accounts | −15 |
| From the account's usual country | −10 |

| Score | Verdict | Account / IP marked |
|---|---|---|
| 70+ | Compromised | Suspected compromise / Used in compromise |
| 45–69 | Likely compromised | Needs review |
| 25–44 | Needs review | Needs review |
| below 25 | Probably the user mistyping | no alert |

Logins **without** any failed attempts use stricter thresholds (80 / 55 / 40) and need at least two pieces of evidence.

### Avoiding false positives

The analyser models what is normal for each account before judging:

- A failure followed by a successful login from the same IP within 30 minutes is a **typo**, and so is a failure from the account's own regular address. Typos are ignored for spraying, brute force and IP clustering.
- Dynamic home addresses within the same provider network (/16) are treated as familiar.
- Colleagues mistyping behind a shared office or mobile-carrier (CGNAT) address do not count as spraying.
- Reconnects within the same network, and two regular addresses at once (laptop and phone), are not reported as high-severity simultaneous sessions.
- Moving between your own home countries (e.g. CZ ↔ SK) is not a country change.
- Client version upgrades and the AnyConnect → Cisco Secure Client rename are not a "new device".
- An address an attacker first reached after a run of failures never becomes the account's "regular" address, even if they come back on other days.

### IP clusters

Two suspicious IPs are linked when they:

- tried largely the **same accounts**, or one IP's target list is contained in the other's (**same target list**, even weeks apart),
- failed against the **same account within 30 minutes** (distributed guessing),
- **handed off** an account: one IP failed for it and another then logged in as it,
- were both used by the same account from **new networks within 48 hours**, one of them attacking (**rotation**),
- sit in the **same /24 network** (only together with another signal).

Linked IPs form a cluster with its countries, targeted accounts and the accounts broken into.

### Cases

Incidents that share an account or IP within 48 hours (`--case-window-hours`) are linked into **cases**: one attack told as a story, e.g. *port scan → password spray → login from the attacking IP → RDP to 12 servers → large download*.

---

## The dashboard

| Tab | What it is for |
|---|---|
| **Overview** | KPIs (clickable), compromised accounts and attacking IPs, IP clusters, data per account, incidents per day, weekday × hour heatmap, **world map** of where logins come from, and the countries table |
| **Hunt** | Every compromised or suspicious account, most certain first: how the attacker got in, the evidence, linked accounts, cases |
| **Investigate** | Add accounts and IPs and search how they are connected, up to 4 steps apart; save investigations |
| **Cases** | Linked incidents with a step-by-step review: evidence lines, attack-flow graph, next-steps checklist, status, notes, printable report |
| **Incidents** | All findings with filters |
| **Logins** | Every assessed login with its score and reasons |
| **IP clusters** | IPs working together, with Venn / UpSet diagrams of shared accounts and a timeline |
| **Matrix** | MITRE ATT&CK stages per account/IP, and an accounts × source IPs grid |
| **Accounts, Source IPs, Internal hosts, Sessions** | Sortable tables with detail panels |
| **Raw events** | Search every stored log line by text, message type, account, IP or sequence number |
| **Firewall admin** | Logins to the firewall and the commands run on it |
| **Connections map** | Attack flow (source IPs → accounts → internal hosts) or a free network layout |

Common features:

- **Search** everything from the header box (press `/`).
- **Global time filter** (date range and hours of the day) that applies to every tab and is kept in the URL.
- **Detail panels** for every account, IP and internal host, each with a merged **timeline**.
- **Compare** 2–3 IPs or accounts in a Venn diagram (4–8 give an UpSet chart).
- **Every table** sorts by clicking a header and downloads as CSV.
- **Light, dark and auto** themes.

Case reviews and saved investigations are stored next to the database in `case_review.json` and `investigations.json`, and survive a re-analysis. Writing them requires a token that only the dashboard page receives, so other websites open in your browser cannot change them.

---

## Country lookup (GeoIP)

Countries are optional but enable the country checks, the map and "login from abroad". Two kinds of database are supported:

| Database | Extra package | Notes |
|---|---|---|
| **DB-IP "IP to Country Lite"** CSV (`.csv` or `.csv.gz`) | none | Free, no account: <https://db-ip.com/db/download/ip-to-country-lite> |
| **MaxMind GeoLite2-Country** or DB-IP MMDB (`.mmdb`) | `pip install geoip2` (or `maxminddb`) | Unpack `.mmdb.gz` files first |

```bash
python3 asa_server.py out/events.db --reanalyze --geoip dbip-country-lite.csv.gz --home-countries CZ
```

If `--home-countries` is not given, home countries are inferred from where most sessions come from. Countries are based on the source IP: a user on a commercial VPN or proxy shows that service's country.

---

## Command reference

### `asa_server.py`

| Option | Meaning |
|---|---|
| `DB` (positional) | Existing `events.db` to open |
| `--import CSV` | Import this CSV first (runs the parser and analyser) |
| `--outdir DIR` | Output folder for `--import` |
| `--newest-year YEAR` | Year of the newest log entry, passed to the parser |
| `--geoip FILE`, `--home-countries CC,CC` | Passed to the parser and analyser |
| `--parse-args "..."`, `--analyze-args "..."` | Extra options for the parser / analyser |
| `--reanalyze` | Re-run the analysis before starting |
| `--host`, `--port` | Listen address (keep `127.0.0.1`) and port (default 8765) |
| `--no-browser`, `--no-web-fonts`, `--verbose` | Convenience options |

### `asa_parse.py` (main options)

| Option | Default | Meaning |
|---|---|---|
| `--newest-year` / `--newest-date` | 2025 | Year or date of the newest entry |
| `--order seq\|file\|file-reversed` | `seq` | How rows are put in time order |
| `--year-anchor SEQ:YEAR` | | Force a year from a sequence number on (repeatable) |
| `--conns teardown\|all\|none` | `teardown` | Which connection messages to store |
| `--skip-ids` | NAT/ICMP noise | Message IDs never stored (`''` keeps everything) |
| `--skip-unknown` | off | Do not store unrecognised messages |
| `--delimiter`, `--seq-col`, `--message-col`, `--timestamp-col` | | CSV layout |

At the end of an import the parser prints the most frequent message IDs and whether each was understood, kept or skipped. The full list is in the `msg_ids` table.

### `asa_analyze.py` (main options)

| Option | Default | Meaning |
|---|---|---|
| `--trusted-ip CIDR` | | Never flag these sources (repeatable), e.g. your admin network |
| `--home-countries` | inferred | Countries where VPN logins are expected |
| `--bf-min` | 10 | Failed logins for one account = brute force |
| `--spray-min-users` | 5 | Accounts one IP must try = spraying |
| `--comp-min-fails`, `--comp-window-min` | 5, 60 | Failures before a login, and how far back |
| `--login-compromise-score` / `-likely-` / `-review-` | 70 / 45 / 25 | Login verdict thresholds |
| `--nofail-compromise-score` / `-likely-` / `-review-` | 80 / 55 / 40 | Thresholds for logins without failures |
| `--campaign-min-fails`, `--campaign-min-weight` | 3, 2 | Evidence needed to link IPs into a cluster |
| `--concurrent-min-minutes` | 10 | Minimum overlap of simultaneous sessions |
| `--travel-hours` | 4 | Country change faster than this is suspicious |
| `--work-hours` | `07-20` | Normal hours for unusual-time checks |
| `--exfil-download-mb` | 2048 | Download per session flagged as possible exfiltration |
| `--large-upload-mb` | 1024 | Upload per session flagged |
| `--spike-factor`, `--spike-min-mb` | 5, 1024 | Daily download vs the account's own median |
| `--scan-hosts`, `--scan-ports` | 30, 50 | Internal hosts / ports in 10 minutes = scanning |
| `--lateral-hosts` | 8 | Hosts over admin protocols in 1 hour = lateral movement |
| `--port-scan-min` | 20 | Denied ports/hosts in 10 minutes = port scan |
| `--admin-bf-min` | 5 | Failed firewall admin logins = brute force |
| `--case-window-hours` | 48 | Incidents this close are linked into a case |
| `--long-session-hours` | 12 | Long session (informational) |
| `--no-case-files`, `--no-html` | | Skip the case reports / static dashboard |

Run any script with `--help` for the complete list.

---

## Tuning and false positives

1. Start with `--trusted-ip` for your own admin and office networks, and `--home-countries` for the countries your staff work from.
2. Open **Logins** and filter to "Needs review". Each entry lists the reasons with their points, which shows exactly which rule is too eager.
3. Raise the relevant threshold through `--analyze-args` and re-run with `--reanalyze`. Your case reviews and saved investigations are kept.

---

## Output files

In the output folder (`out/` by default):

| File | Content |
|---|---|
| `events.db` | SQLite database with all events, connections and analysis tables |
| `events_YYYY.csv` | Recognised events per year |
| `year_inference_report.csv` | Year changes, gaps and corrected out-of-order rows |
| `sessions.csv`, `users_summary.csv`, `ips_summary.csv`, `user_ip_links.csv`, `incidents.csv` | Analysis results |
| `cases/index.html`, `cases/case_NNN_*.html`, `cases/case_NNN_*_evidence.csv` | Printable case reports with every evidence line (sequence numbers refer to the original export) |
| `case_review.json`, `investigations.json` | Your review notes and saved investigations |

---

## Logging requirements on the ASA

| Feature | Message IDs | Level |
|---|---|---|
| VPN logins and sessions | 113004/113005/113015, 113019, 113039, 722051, 722055, 737016/737026 | 6 (informational) |
| Lockouts, WebVPN | 113006, 716001/716002/716039 | 6 |
| Internal access, scans, lateral movement, exfiltration targets | 302013–302016 | 6 |
| Firewall denies, port scans | 106001, 106023, 106100, 710003 | 2–6 |
| Threat detection | 733100–733102 | 4 |
| Firewall admin activity | 605004/605005, 611101/611102, 111008/111010, 502103 | 5–6 |

Without the 302013–302016 connection messages the toolkit still analyses logins, but the Internal hosts tab and the inside-the-network detections stay empty.

---

## Limitations

- **Year reconstruction** relies on a continuous log; gaps over about a year cannot be detected from timestamps alone.
- **Countries** are per country, not per city, and reflect the source IP (VPN services and proxies show their own country). There is no hosting-provider (ASN) data yet.
- **The world map** uses simplified, hand-drawn outlines so that it works fully offline. It is stylised, not an exact border map.
- **Scores are evidence, not proof.** A "compromised" verdict means the log strongly suggests it; confirm with the user and with endpoint and server logs before acting.
- The static `dashboard.html` written by the analyser is a lightweight snapshot. All interactive features are in `asa_server.py`.
