# External Threat-Intel Sources for Header-Attack Fixtures

**Status:** living catalogue · **Audience:** WAF rule authors + fixture builders
**Provenance:** deep-research sweep 2026-06-15 (5 angles, 23 sources fetched, 108
claims extracted, 25 adversarially verified 3-0, 0 refuted). This file is the
source catalogue for the honeypot program's **header dimension**
([`docs/threat-model.md`](threat-model.md) §6, work-streams B and C).

> **Why this exists.** Our corpus (`ngxlogs/access.log`) is the empirical basis
> for *path*-signature tuning, but the nginx combined log only records
> `User-Agent` and `Referer` — it has **no Cookie, Host, X-Forwarded-For, or
> other request headers**. The header attack surface is at least as rich as path
> traversal, so the header-attack fixture must be sourced from external,
> maintained, machine-readable threat-intel — catalogued here.

---

## 0. How this maps to the WAF

The module already matches on:
`User-Agent` (`scanner-ua.list` / `bot.list`), `Referer` signatures, `Cookie`
signatures, query-arg signatures, and CIDR-based **fake-bot** verification.

Two classes of source follow:
- **§1 — feeds existing matchers** (UA / fake-bot / referer): direct TP fixture.
- **§2 — covers current GAPS** (Host, X-Forwarded-For/forwarding, CRLF, cache
  poisoning, smuggling): these first serve **gap-discovery** — replaying them in
  `detect` mode shows today's ~0% coverage and yields new rule candidates for the
  §6/A gap-analysis loop.

---

## 1. Sources that feed EXISTING matchers (UA / fake-bot / referer)

| Source | Harvestable artifact | Format / licence | Size | Feeds | Caveat |
|---|---|---|---|---|---|
| **SecLists** `Fuzzing/User-Agents/UserAgents.fuzz.txt` | scanner + spoof + harvester UAs | plain-text, 1/line, MIT | ~2,454 (large) | `scanner-ua.list`, `bot.list`, fake-bot fixture | uncurated: HTML-entity junk lines + stale entries → sanitize |
| **OWASP CRS** `rules/scanners-user-agents.data` (+ `REQUEST-913-SCANNER-DETECTION.conf`) | curated scanner-UA substrings (nikto, sqlmap, arachni, Hydra…) | `@pmFromFile`, 1 substring/line, Apache-2.0 | curated | `scanner-ua.list` (**identical shape**) | strip `#` comment lines |
| **monperrus/crawler-user-agents** `crawler-user-agents.json` | legit-crawler regex `pattern` + `instances` | JSON, MIT | curated | **fake-bot reference** (pair with CIDR check) | catalogues *legitimate* crawlers — not a blocklist |
| **JayBizzle/Crawler-Detect** `raw/Crawlers.txt` (+ `.json`, `.php`) | crawler-UA regexes (`^Nuclei`, `Acunetix`, `ApacheBench`…) | regex/line, MIT, **v1.4.0 2026-06-11** (very active) | thousands | regex UA matcher | matches UA *and* `From:`; includes legit bots |
| **mitchellkrogza/nginx-ultimate-bad-bot-blocker** `_generator_lists/` | `bad-user-agents.list` (~690), `fake-googlebots.list` (~218), `bad-referrers.list` (~7,100) | plain-text for nginx `map`/`geo`, active (PRs → Nov 2025) | large | UA sig + **Referer sig** + fake-Googlebot | counts drift — re-pull live; magnitudes approximate |
| **omrilotan/isbot** | `list` (string[]) / `getPattern()`; README names 5 upstream UA feeds | TS/Node, Unlicense | curated | UA matcher seed + upstream index | good+bad bots broadly, not scanner-specific |

---

## 2. Sources for the GAP areas (Host / XFF / CRLF / cache / smuggling)

| Source | Harvestable artifact | What it gives | Critical limit |
|---|---|---|---|
| **OWASP CRS** `rules/REQUEST-921-PROTOCOL-ATTACK.conf` | **921140** `@rx [\n\r]` on `REQUEST_HEADERS_NAMES\|REQUEST_HEADERS` (phase 1, CRITICAL) — a **true header-level CRLF matcher**; **921160** header-name watchlist (host, forwarded-, via, x-forwarded-*, originating-IP, cookie/set-cookie); **921110** smuggling heuristic | the one directly reusable header matcher (921140) + the header-name list | 921160 / 921110 actually inspect **ARGS/body**, not transport headers; 921110 is a *signature*, not CL.TE/TE.CL parsing |
| **Nuclei templates** `helpers/payloads/request-headers.txt` | ~110 forwarding/IP header **names**: X-Forwarded-For, X-Real-IP, True-Client-IP, CF-Connecting-IP, X-Originating-IP… | the forwarding-header name set | names only — not bypass *values* |
| **FuzzDB** `attack/http-protocol/{crlf-injection,http-header-cache-poison}.txt` | CRLF + cache-poison payloads (e.g. `%0d%0aContent-Type:%20text/html;charset=UTF-7%0d%0a`) | line-oriented header payloads | mature/low-activity; header-thin, body-biased |
| **PortSwigger research** (J. Kettle): *Practical Web Cache Poisoning*, *Web Cache Entanglement*, *Gotta Cache 'em All* | unkeyed-header payloads: `X-Forwarded-Host: a.\"><script>…`, `X-Forwarded-Scheme`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, Origin; "fat GET" | concrete cache-poison payloads + the unkeyed-header taxonomy | prose, not a downloadable wordlist — extract by hand |
| **PortSwigger** Host-header / request-smuggling labs + MDN `X-Forwarded-For` | Host-injection (reset-poisoning, routing SSRF), TE.CL/CL.TE lab payloads | taxonomy + reference payloads | smuggling is a parser-layer concern (see §3) |

---

## 3. Three load-bearing truths

1. **Request smuggling is NOT a regex-WAF job.** CRS 921110 only matches a
   smuggling-*shaped string* in ARGS/body; genuine CL.TE/TE.CL/TE.TE frame
   desync is resolved at the reverse-proxy/parser layer. Treat smuggling like the
   §4 parser-junk class: **document as out-of-scope** for the HTTP-phase WAF; the
   CRS rules feed a "smuggling-shaped" fixture, not real desync detection.
2. **Fake-bot lives or dies on the CIDR check.** Sending a `Googlebot` UA is
   *benign*; the attack is sending it from a **non-Google IP**. UA lists are only
   half the fake-bot fixture — the other half is the source IP.
3. **The UA lists are noisy.** They mix legitimate crawlers, stale entries, and a
   few junk lines, and do **not** pre-classify fake-bot-reference vs
   malicious-scanner. Self-categorize + sanitize before feeding the matchers.

---

## 4. Open data gaps (no ready machine-readable source found)

- **Cookie injection / SQLi-in-cookie payloads** as a header fixture — FuzzDB SQLi
  lists and CRS cookie rules exist but were not confirmed cookie-header-targeted.
  (We already have a synthetic Cookie fixture; extend it from FuzzDB SQLi.)
- **X-Forwarded-For / X-Real-IP ACL-bypass VALUES** (`127.0.0.1`, internal CIDRs,
  multi-value XFF chains) — Nuclei supplies header *names*, not bypass values.
  Assemble a small values fixture by hand.
- **Transfer-Encoding / Content-Type / Accept obfuscation** — no dedicated list
  beyond the CRS 921110 method-shape heuristic.

---

## 5. Shortlist — best sources to build the header fixture from

1. **OWASP CRS** `scanners-user-agents.data` — drop-in scanner-UA substrings (`scanner-ua.list` shape).
2. **SecLists** `UserAgents.fuzz.txt` — broad UA corpus for scanner + fake-bot (sanitize).
3. **monperrus/crawler-user-agents.json** — fake-bot reference regexes (pair with CIDR).
4. **nginx-ultimate-bad-bot-blocker** `_generator_lists/` — UA + **bad-referrers** + fake-googlebots.
5. **OWASP CRS** `REQUEST-921-PROTOCOL-ATTACK.conf` (921140) — the one true header-level CRLF matcher + header-name watchlist.
6. **Nuclei** `helpers/payloads/request-headers.txt` — forwarding/IP header name set (XFF gap).
7. **FuzzDB** `attack/http-protocol/` — CRLF + cache-poison payloads.
8. **PortSwigger** cache-poisoning research — unkeyed-header payloads (hand-extract).

---

## 6. Source URLs

- SecLists: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/User-Agents
- OWASP CRS: https://github.com/coreruleset/coreruleset/tree/main/rules
- FuzzDB: https://github.com/fuzzdb-project/fuzzdb
- Nuclei templates: https://github.com/projectdiscovery/nuclei-templates
- monperrus/crawler-user-agents: https://github.com/monperrus/crawler-user-agents
- JayBizzle/Crawler-Detect: https://github.com/JayBizzle/Crawler-Detect
- nginx-ultimate-bad-bot-blocker: https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker
- omrilotan/isbot: https://github.com/omrilotan/isbot
- PayloadsAllTheThings (CRLF): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection
- PortSwigger: https://portswigger.net/research/practical-web-cache-poisoning · https://portswigger.net/research/web-cache-entanglement · https://portswigger.net/web-security/host-header/exploiting
