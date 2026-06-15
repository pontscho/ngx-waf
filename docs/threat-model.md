# Edge Threat Model & Honeypot Analysis

**Status:** living document · **Audience:** module authors + edge operators
**Data source:** `ngxlogs/access.log` + `error.log` — the real production logs of
this edge (`203.0.113.10`, `example.com`), **1,651,507 HTTP requests over
~3 years 10 months** (2022-08-22 → 2026-06-13), captured **before** the WAF was
ever enforcing. Every number below is measured directly from that corpus.

> **Why this matters.** The WAF's rule set is not guessed — it is *fitted to
> this edge's actual attack surface*. This document records what the edge
> really sees, how we derive rules from it, and the test program that keeps the
> rules honest as traffic evolves. It is the empirical backing for
> [`modules/ngx_http_waf/lists/scanners.list`](../modules/ngx_http_waf/lists/scanners.list)
> and for the geo/reputation tuning.

---

## 1. The corpus at a glance

| Metric | Value |
|---|---|
| Total requests | 1,651,507 |
| Distinct source IPs | 79,192 |
| Span | 2022-08-22 → 2026-06-13 (~3y 10m) |
| Nature | **pre-WAF** — the legacy backend / catch-all answered everything |

**This is a pure internet-scan profile.** The host is a small edge with no
organic user base for any of the probed resources; effectively all non-trivial
traffic is automated reconnaissance and exploitation attempts. That makes the
log an unusually clean *honeypot corpus*: almost every hostile-shaped request
really is hostile.

### 1.1 Traffic is rising fast

| Year | Requests |
|---|---:|
| 2022 | 35,487 *(from Aug)* |
| 2023 | 181,819 |
| 2024 | 234,955 |
| 2025 | 574,737 |
| 2026 | 624,507 *(through 13 Jun — already past all of 2025)* |

Roughly **doubling year over year** (2024→2025 +145%). Whatever rules we ship
must assume scan volume keeps climbing.

---

## 2. Response-status picture (what the legacy backend already did)

| Group | Count | Share | Note |
|---|---:|---:|---|
| 2xx | 172,059 | 10.4% | mostly the internal health-check IPs (§5.1) |
| 3xx | 626,648 | 37.9% | **301 = 626,209** — a blanket http→https / canonical redirect |
| **404** | 602,024 | **36.5%** | the backend already 404'd nearly every scan |
| **400** | 138,857 | 8.4% | **parser-rejected** — malformed / non-HTTP (§4) |
| 5xx | 106,397 | 6.4% | almost all **502**: proxied paths whose upstream was down |
| 403 | 3,268 | 0.2% | |
| 499 | 252 | 0.02% | client-closed connections (see note) |
| other 4xx | 1,659 | 0.1% | |

Two operational facts fall out of this:

- **The backend was already absorbing scans as 404** (36.5%). The WAF's job is
  not to invent rejection — it is to reject *earlier and cheaper* (at
  `PREACCESS`, before proxying), to hide the fingerprint, and to feed reputation.
- **nginx logs a dropped connection as `499`, not `444`.** The `444` action in
  `scanners.list` closes the connection; in the access log that surfaces as
  status `499` with `0` bytes. There is no literal `444` status. (Only 252
  total here — the legacy backend rarely closed connections.)

---

## 3. Attack-class volumes

Case-insensitive match on the **decoded URL path** (query stripped). Classes
overlap (one path can match several — e.g. `/wp-login.php` is both `php` and
`wordpress`), so these are per-class totals, not a partition.

| Class | Requests | Representative top paths |
|---|---:|---|
| **php** | 364,455 | `/index.php`, `/wp-login.php`, `/vendor/phpunit/.../eval-stdin.php`, `/info.php`, `/xmlrpc.php` |
| **secret_vcs** | 161,302 | `/.env` (20,683), `/.git/config` (8,192), `/api/.env`, `/backend/.env`, `/admin/.env` |
| **wordpress** | 139,228 | `/wp-login.php`, `/xmlrpc.php`, `/wordpress`, `/wp-content/plugins/hellopress/wp_filemanager.php` |
| **router_iot** | 22,060 | `/cgi-bin/luci/;stok=/locale` (7,087), `/boaform/admin/formLogin`, `/cgi-bin/.%2e/.%2e/.../bin/sh`, `/SDK/webLanguage` |
| **legacy_ext** | 15,290 | `/owa/auth/logon.aspx`, `/dispatch.asp`, `/cgi-bin/authLogin.cgi`, `/login.jsp` |
| **phpadmin** | 13,462 | `/phpMyAdmin/scripts/setup.php`, `/phpmyadmin/index.php`, `/phpMyAdmin-5.2.0/index.php` |
| **backup** | 10,837 | `/.env.bak` (1,120), `/backup`, `/wp-config.php.bak`, `*/eval-stdin.php` under `/backup/` |
| **appliance** | 10,082 | `/actuator/gateway/routes` (2,411), `/geoserver/web/` (2,286), `/actuator/health`, `/solr/admin/info/system` |
| **webmail** | 4,217 | `/owa/auth/logon.aspx`, `/autodiscover/autodiscover.json`, `/ecp/.../exporttool/...application` |

**Reading it:** PHP/CMS probing dominates by an order of magnitude (`php` 364k +
`wordpress` 139k), with **credential / secret harvesting** a close and
fast-growing second (`secret_vcs` 161k — the `/.env` and `/.git/config` floods
are attempts to lift cloud keys and repo contents). Router/IoT RCE and
Java/appliance probes (Spring Actuator, GeoServer, Solr) are the second tier.
This ordering is what `scanners.list` is weighted toward.

### 3.1 What we do **not** yet catalogue

1,022,767 requests matched **none** of the classes above. The bulk is
legitimate-shaped noise — `/` (594,032), `/app.css` (57,694), `/app.json`
(57,661), `/favicon.ico`, `/robots.txt`, `/sitemap.xml` — i.e. **not hostile**,
and correctly left alone. But the long tail hides probe families our taxonomy
does not name yet (candidates for new `scanners.list` entries):

| Count | Path | Probe |
|---:|---|---|
| 2,805 | `/nice%20ports%2C/Tri%6Eity.txt%2ebak` | nmap `http-*` fingerprint |
| 2,794 | `mstshash=Administr` | RDP probe mis-delivered to the web port (§4) |
| 1,970 | `/dns-query` | DoH endpoint probe |
| 2,129 | `/hello.world` | scanner liveness ping |
| 1,480 | `/_profiler/phpinfo` | Symfony debug-profiler probe |

(`/_profiler`, DoH `/dns-query`, the nmap `Trinity` fingerprint, and the
`/hello.world` liveness ping are now all covered — added in the 2026-06-15
gap-loop, see §6 A.)

---

## 4. Non-HTTP / protocol junk (the 400 bucket)

**138,857 requests (8.4%) were rejected by nginx's request-line parser with
status 400** — before any module phase ran. Of the malformed-method subset
(96,510), **99.97% got 400**; only 31 were syntactically valid HTTP with a
merely-unusual method token (`RAW`, `LINK`, random 4-letter, `SSTP_DUPLEX_POST`).

What this junk actually is — **non-HTTP traffic hitting the HTTP/S port**, the
method token itself being binary or another protocol's banner:

| Volume | Payload | Protocol |
|---:|---|---|
| ~2,800 | `\x03\x00\x00/*\xE0...Cookie: mstshash=` | RDP handshake |
| ~2,600 | `PRI * HTTP/2.0` | HTTP/2 cleartext preface |
| ~55,752 | `\x16\x03...` | **raw TLS ClientHello** sent to a plaintext listener |
| 1,638 | `SSH-2.0-Go` | SSH client banner |
| 1,376 | `MGLNDD_203.0.113.10_443` | masscan / Shodan banner-probe |
| 1,157 | `\x05\x01\x00` | SOCKS5 greeting |
| — | SMB negotiate, WebLogic `t3`, Java `JRMI`, DNS `version.bind`, Gh0st/njRAT/Stratum beacons | misc L4 / malware |

**Architectural consequence (decided):** this vector is **not reachable from the
WAF's HTTP phases** — nginx kills it at the request-line parser, so it never
reaches `POST_READ`/`PREACCESS`. It is already "handled" (400 + connection torn
down, backend never sees it). It surfaces only in `error.log`
(`client sent invalid method` 61,964; `invalid request` 15,584;
`invalid version` 47 — ~77.5k events) and at L4. We deliberately do **not** build
an HTTP-layer classifier for it: an `error_page 400` / log-phase counter would
be a hack for no operational gain, and an L4 first-byte sniffer is a separate,
larger capability we are not pursuing now. *Documented as a known,
parser-handled class — no WAF action required.*

---

## 5. Source & User-Agent intelligence

### 5.1 Sources

79,192 distinct IPs, but heavily clustered. **Exclude the internal
`10.0.0.0/24`** (`10.0.0.2`+`.6` = 120,438 requests, 118,796 of them 200)
— that is local health-check / monitoring traffic, not a threat, and it also
accounts for much of the early TLS-on-plaintext 400 noise.

The largest **external** aggressors (prime prefix-block candidates):

| /24 prefix | Requests | Note |
|---|---:|---|
| `185.177.72.0/24` | 66,515 | single hostile /24, **5+ IPs in the global top 25** |
| `78.153.140.0/24` | 34,827 | persistent offender |
| `195.178.110.0/24` | 22,992 | |
| `204.76.203.0/24` | 22,196 | |
| `45.148.10.0/24` | 18,867 | |

A handful of /24s drive a disproportionate share — **prefix-level blocking is
high-yield here** (`waf_blocklist <cidr>`), and is the empirical basis for the
geo/ASN tuning in §6 (D).

### 5.2 User-Agents

- **30.81% (508,839) send no User-Agent at all** — the single biggest UA bucket.
  This is why `waf_bot_block` treats empty UA as hostile (→ 404).
- **Honest self-declaring scanners** are a large, identifiable population:
  `zgrab` (~19k), `masscan`/`ivre-masscan`, `l9explore`+`libredtail` (LeakIX,
  ~46k combined), `CensysInspect` (10k), Palo Alto `Expanse` (~9k),
  `Go-http-client` (~50k), `python-requests`/`httpx`, `fasthttp`,
  `Custom-AsyncHttpClient`, `Nmap Scripting Engine`, `Shodan-Pull`. These map
  cleanly to `scanner-ua.list` / `bot.list` and to `$waf_type`.
- **Spoofed-browser automation** is the blind spot: a dozen near-identical
  high-volume `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...537.36` strings and
  one `Mozilla/5.0 (Macintosh ... 10_15_7)` at 96,904 — far too uniform for
  organic users on a 404-everything host. **No `sqlmap`/`nikto`/`nuclei`/`wpscan`
  UA ever appears**: offensive tools ran with these fake browser UAs. UA-based
  classification cannot catch them — path signatures and reputation must.

---

## 6. Methodology — data-driven rule tuning

The rule set is maintained as a **repeatable gap-analysis loop** against this
corpus, not by intuition. The four work-streams (A–D): **A, B, and C are done** (B is detailed in
`docs/honeypot-B-plan.md`); D is planned.

### A — Gap-analysis → `scanners.list` growth (DONE)

The procedure (reproducible, read-only, libc tools only — **no libloc**):

1. Extract decoded request paths from the corpus (`"$request"` field, second
   token, query stripped).
2. Compute current coverage: which paths the *present* `scanners.list` would
   match (compile the same anchored alternation regex the module uses and run
   it over the path list).
3. The **complement** (hostile-shaped paths the list misses) is the gap. Rank
   it by volume; the high-frequency misses become new patterns.
4. Re-measure; commit the list with the before/after numbers.

This loop already raised path coverage from **18.1% → 24.8%** (+~110k requests)
in commit `d2b557a`, adding nested-dotfile, anywhere-`phpunit`, `/_profiler`,
`/SDK/webLanguage`, and `/wordpress` patterns.

The **2026-06-15 iteration** closed the largest remaining gaps surfaced by the
B replay (validated FP-clean by the B detect gate before enforcing):

| class | before | after | driver |
|---|---:|---:|---|
| php | 41.6% | **99.2%** | generic `\.php(/\|$)` catch-all (this edge serves no PHP; +~127k probe paths) |
| wordpress | 89.0% | **99.5%** | `wlwmanifest.xml` (nested `*/wp-includes/...`) |
| phpadmin | 15.0% | **98.5%** | subsumed by the generic `.php` rule |

Also added: nmap `Trinity` fingerprint, `/hello.world` liveness ping (and its
`php://input` RCE variant), Fortinet `/remote/login`, Cisco `/+cscoe+/`, the
shellshock `/bin/sh` traversal tail, and a `php://input` **args** signature
(444), plus a credential / config / infra-API leak cluster (`aws/credentials`,
`secrets.json`, `appsettings.json`, `*.env`, Docker `/containers/json`, Apache
`/server-status`, Druid) that lifted the `uncatalogued` class 14.1% → 21.6%.
**Action note:** the generic `.php` rule lands in the 404 bucket, and the
lookup checks 404 before 403/444 (`waf_match.c` `scanner_lookup`), so ~46
phpmyadmin/pma paths that end in `.php` now return **404 instead of 403** — they
stay blocked, just blended into the backdrop 404s (the §2 "hide the fingerprint"
goal). The phpmyadmin/pma *directory* probes keep their 403.

A **second 2026-06-15 iteration** extended the config/secret surface from the B
uncovered export. The edge serves no config/IaC formats, so blanket extension
rules (`\.ya?ml$`, `\.properties$`, `\.tfstate`/`\.tfvars`) are FP-clean here (the
B gate confirmed zero baseline hits); distinctive `.json`/dotfile secret stores
(`credentials.json`, `composer.json`/`.lock`, `.npmrc`/`.netrc`/`.htpasswd`,
`.kube`/`.docker/config.json`, Rails `config/credentials`, `appsettings.<env>.json`)
are enumerated instead (a blanket `.json` rule would hit the `/app.json` baseline).
Also added: Symfony web-profiler `/debug/default/view`, the `.phpN` and IIS
`.php::$DATA` source-leak tail on the generic `.php` rule, and a cluster of
distinctive appliance/VPN/RCE fingerprints (Citrix `WPnBr.dll`, Telerik
`WebResource.axd`, GPON `GponForm`, Cisco `/+CSCOL+/`, SAP `metadatauploader`,
D-Link `getuser`, Pulse `/dana-{na,cached}/`, F5 `/mgmt/tm/util/bash`, SonicWall
`/api/sonicos/`, MobileIron `/mifs/`, ColdFusion `/CFIDE/`, Sitecore). This lifted
the `uncatalogued` class 21.6% → **35.3%** (and `appliance` to **100%**). The bare
dictionary tail (`/login`, `/home`, `/admin`, `/test`, …) was deliberately
**excluded** — those can be legitimate navigation and the B gate sees only the
baseline corpus, not production traffic. All new path patterns are 404 (blend-in),
so the re-freeze grew only the 404 bucket (403/444 byte-identical).

> **Coverage caveat.** "24.8% of requests" is not "24.8% of attacks" — the
> denominator includes the ~36% legitimate noise (`/`, `app.css`, `app.json`).
> Coverage of the *hostile* subset is far higher; treat the headline % as a
> trend signal, not an absolute.

### B — Detect-mode FP/TP replay (done)

Validate a policy *before* enforcing it. Replay the corpus against the sandbox
WAF in `waf detect;` mode and read the `would_block[reason]` counters:

- **FP set** — the legitimate baseline (`/`, `/app.css`, `/app.json`,
  `/favicon.ico`, `/robots.txt`, `/sitemap.xml`): **must produce zero**
  `would_block`. Any hit is a false positive to fix before enforcing.
- **TP set** — the attack classes (§3): each should land in the expected
  `would_block[reason]` bucket.
- **Output:** an FP rate on the legit set and a TP rate on the hostile set, per
  rule change — the safety gate for flipping `detect → enforce`.

### C — Real-attack replay regression fixture (DONE)

The detect-mode coverage from B is distilled into a **frozen, committed**
fixture and asserted in **enforce** mode, so a future list edit that silently
stops matching `/.env` or `/wp-login.php` — or changes its action
(404↔403↔444) — fails the harness. Partner decision: the fixture is the FULL
covered set (every vector the WAF blocks today), not top-N.

The procedure (reproducible, core-perl + nginx only — **no docker**):

1. **Freeze** (`tests/corpus/freeze-regression-fixture.pl`, run once against a
   live regression-nginx): a two-pass probe per dimension. The *detect* vhost
   yields the authoritative `X-WAF-Reason`; a vector is frozen iff its reason
   != `none`. The *enforce* vhost then yields the real HTTP status. Frozen
   verdict = `{expected_reason: detect, expected_status: enforce}`. Outputs the
   committed `regression-vectors.jsonl` (path/args, keyed by uri) and
   `regression-headers.jsonl` (ua/referer/cookie/fakebot, keyed by value).
2. **Assert** (`tests/run-regression-tests.sh`, modelled on `run-stat-tests.sh`):
   an FP gate (benign baseline must not block) plus an enforce replay of the
   committed fixture, joining each result to its frozen verdict and asserting
   the `(reason,status)` tuple per vector. A 444 (`NGX_HTTP_CLOSE`, observed as
   a byte-0 connection close — no `X-WAF-Reason` reaches the wire) is asserted
   status-only; its reason stands frozen from generation time.

The harness uses a dedicated config (`tests/waf-regression-test.conf`, ports
283xx) with detect+enforce vhost pairs and **exactly one matcher per vhost**
(PREACCESS is first-match-wins, so dimensions stay isolated); no `proxy_pass`,
no `waf_trusted_proxy`, no rate/geo — the only verdict is the matcher under
test. `replay-client.pl` gained an `--enforce` mode (a fresh `Connection: close`
socket per request, so a byte-0 EOF is an unambiguous 444).

Current frozen fixture: **40,614** path/args vectors + **160** header vectors
(`expected_status` ∈ {404: 40,573, 403: 146, 444: 55}); the enforce replay runs
in ~25 s and asserts 100% frozen-match. (Re-frozen 2026-06-15 across two §6 A
gap-loop iterations — a fixture re-freeze is mandatory whenever a list edit
intentionally changes coverage or an action bucket.) It complements the existing 6 unit +
131 integration tests with **live-fire** samples.

### D — ASN / geo tuning from attacker IPs (planned)

Feed the top external sources (§5.1, **excluding** `10.0.0.0/24`) through the
module's **own** geo reader — the embedded nanolibloc adaptation in
`waf_geo.c`, or the standalone `reference/loctest.c` oracle — to resolve
CC + ASN (**never libloc / the `location` CLI**; Decisions, no-libloc). Then:

- Persistent hostile /24s (`185.177.72`, `78.153.140`, ...) → `waf_blocklist`
  candidates (prefix block is the most precise lever here).
- Dominant attacker ASNs → `waf_asn_block` candidates.
- Dominant attacker countries → `waf_geo_block` candidates (coarse — country
  block also drops legitimate traffic from that country, so prefer prefix/ASN
  for surgical cases).

---

## 7. Limitations & caveats

- **Pre-WAF corpus.** The WAF never enforced during capture; every `.php` 200
  (incl. the historic `/xleet-shell.php` hit) reflects the *old* backend /
  catch-all, **not** a WAF bypass. The `/xleet-shell.php` 200 may indicate a
  past compromise of the legacy infra — an infrastructure question, not a WAF
  one.
- **Signature, not content.** `scanners.list` matches paths; it cannot catch a
  random-named webshell (`/xleet-shell.php` is caught only by the `\.php`
  extension rule, not by name).
- **Spoofed-browser blind spot** (§5.2): UA classification misses offensive
  tools hiding behind fake browser strings — covered only by path signatures
  and IP reputation.
- **Internal traffic** (`10.0.0.0/24`) must be excluded from any
  attacker-derived tuning, or it pollutes the geo/ASN and volume stats.
- **Numbers age.** Traffic doubles yearly (§1.1); re-run the gap-analysis (A)
  periodically — this document's figures are a 2026-06 snapshot.
