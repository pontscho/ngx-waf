# Work-stream B — Detect-mode FP/TP Replay (implementation plan)

**Status:** plan, inspector-reviewed (plan-inspector: APPROVE-WITH-CHANGES;
security-officer: REVISE — all findings folded in below) · **Scope:** threat-model
[§6 B](threat-model.md). **Depends on:** step 0 (`replay-vectors.jsonl`, DONE),
`docs/threat-intel-sources.md` (header fixtures).

> **Path convention (inspector H1):** the test tree is
> `modules/ngx_http_waf/tests/`, lists are `modules/ngx_http_waf/lists/`, the
> corpus is `modules/ngx_http_waf/tests/corpus/`. All paths below use these.

---

## 1. Goal & framing

Replay the real corpus against the sandbox WAF in **`detect` mode** and read the
`http_would_block[reason]` counters, to produce two things per rule state:

1. **FP gate** — the legit baseline set (`/`, `/app.*`, static, favicon/robots/
   sitemap) MUST produce **zero** `would_block` across **every** reason. Any hit
   is a false positive to fix before `detect → enforce`.
2. **Coverage (TP) measure** — per §3 class, what fraction of its volume lands in
   the expected `would_block[reason]` bucket, **plus the uncovered remainder**.

**Key correction (drove the design):** the §3 taxonomy classes are NOT the same
as `scanners.list` coverage. Example: the `php` class (`/index.php`, ~364k) has
**no** generic `\.php` rule in `scanners.list`, so most of it will NOT trip
`would_block`. So B is **not** a binary pass/fail — it is a **coverage meter**:
per-class hit-rate + an **uncovered-hostile list** that feeds the §6/A
gap-analysis loop (the same loop that took path coverage 18.1% → 24.8%).

### In scope
- A reusable **replay harness** (modelled on `modules/ngx_http_waf/tests/run-stat-tests.sh`).
- A dimension-clean sandbox config for replay.
- Path/args replay from `replay-vectors.jsonl` (all vectors — partner: "mind").
- Header replay (UA / Referer / Cookie) from fixtures built off `docs/threat-intel-sources.md`.
- FP gate, per-class coverage report, uncovered-hostile export.

### Out of scope (documented, not built)
- **Enforce-mode** flipping (B only measures; the flip is an operator action).
- **Request smuggling** (parser-layer, not a regex-WAF job — see threat-intel §3).
- **Host / XFF / CRLF / cache** *enforcement* — B only quantifies the current
  ~0% coverage as gap-discovery; new rules are a later work-stream.
- The committed bounded fixture — that is **work-stream C**.

---

## 2. The phase-order problem and the dimension-clean vhosts

`would_block` records the **first** blocking phase. PREACCESS order (verified,
`ngx_http_waf_module.c`): reputation (857) → method (891) → rate (927) → **UA-bot
(967) → fake-bot (996) → scanner-path (1018) → args (1063) → cookie (1082) →
referer (1100)**; each hit `return`s immediately (first-match-wins). Consequences:

- UA-bot (967) precedes scanner-path (1018): with `waf_bot_block on`, the ~30%
  empty-UA traffic lands in `would_block[empty_ua]`, masking the path signal.
- scanner-path (1018) precedes args (1063) precedes cookie (1082) precedes
  referer (1100): an earlier dimension masks a later one.

**Design:** one **dimension-isolated** detect vhost per matcher, only that matcher
enabled, **`waf_bot_block off` on every non-UA vhost**, and the client sends a
**benign UA** on every non-UA dimension (inspector M2). New self-contained config
`modules/ngx_http_waf/tests/waf-replay-test.conf` (do NOT overload
`waf-stat-test.conf`):

| vhost (port) | mode | enabled matcher | bot_block | fed by |
|---|---|---|---|---|
| `replay-path` (28182) | `detect` | `waf_scanner_list` only | off | `.jsonl` method+uri |
| `replay-args` (28183) | `detect` | `waf_args_list` only | off | `.jsonl` uri with query |
| `replay-cookie` (28187) | `detect` | `waf_cookie_list` only | off | synthetic cookie fixture |
| `replay-ua` (28184) | `detect` | scanner_ua/bot/ai/crawler lists | **on** | UA fixture, path `/` |
| `replay-referer` (28185) | `detect` | `waf_referer_list` only | off | Referer fixture, path `/` |
| `replay-fakebot` (28186) | `detect` | `waf_verified_bot` + crawler list | off | crawler UA from non-verified IP |
| `status` (28190) | `waf off` | `waf_status` | — | counter readout |

All locations are **static-file-backed** so a *declined* request reaches CONTENT
(200) — the proven pattern from the existing `detect.test` vhost
(`waf-stat-test.conf:125`) + `run-stat-tests.sh:155-174`.

**Security invariants baked into the conf (security-officer S1/S5):**
- **No `proxy_pass` in any replay HTTP vhost** — static-file backing only, so a
  replayed request can never be relayed off-box.
- All listeners bind **`127.0.0.1`** only (incl. `status`).
- **No `waf_trusted_proxy`** — XFF is not honoured, so the canonical client IP
  stays the loopback peer (the fake-bot dimension depends on this).

---

## 3. The replay client (all ~85k+ vectors)

**Primary, security-preferred client = a raw-socket perl client** (not curl).
Rationale (security-officer S2/S3 + fidelity): a raw client writes bytes to a
socket with **zero shell and zero curl-config-DSL grammar in the loop**, which
eliminates both injection surfaces at once, and is *also* required for `\xNN`
byte fidelity and `--path-as-is` semantics. (curl `--parallel --config` is a
fallback ONLY if it escapes the config DSL with a real writer and never
interpolates a fixture byte through a shell — see S2.)

**Connection-target invariant (security-officer S1):** the client ALWAYS opens
the TCP socket to `127.0.0.1:<dimension-port>`, chosen by the harness, **never**
derived from the vector. An absolute-form (`GET http://host/…`) or `CONNECT`
request-line in the corpus is **skip-and-counted**, not sent (the extractor's URI
regex permits absolute-form, `extract-replay-vectors.pl` URI token = `\S+`; the
WAF matches `r->uri`, so authority-form adds no coverage).

**Other critical client details:**
- **Path on the wire is sent as-is** (raw socket writes the request-line
  verbatim); `%2e`/`%0d%0a` stay percent-encoded — the *server* decodes (the WAF
  matches decoded `r->uri`). Percent-encoded CRLF in the path is in-scope & safe.
- **`\xNN` re-encoding + CRLF framing invariant (security-officer S3):** re-expand
  `\xNN` only **inside the single header value being placed**; write each header
  as exactly one `Name: value\r\n` unit so a value's bytes can never frame the
  *next* header. If a re-expanded UA/Referer/Cookie value contains a literal
  CR/LF, either send it raw into that one value (highest-fidelity TP) or
  **skip-and-count** — never let it inject sibling headers (which would pollute
  dimension isolation).
- **No fixture/corpus byte is ever passed as a shell word or interpolated into a
  command line** (security-officer S2) — belongs next to the "purity is the only
  file writer" rule in §7.
- The dedup `count` is irrelevant for *sending* (one send per unique vector);
  keep it only to weight the coverage report by volume.

---

## 4. Header fixtures (the dimension with no corpus data)

Build from `docs/threat-intel-sources.md`, staged under
`modules/ngx_http_waf/tests/corpus/fixtures/` (gitignored derivatives):

- **UA fixture:** raw UAs from the corpus regenerated **without** `--collapse-ua`
  (the collapse was a path-cardinality measure only), MERGED with OWASP CRS
  `scanners-user-agents.data` + SecLists `UserAgents.fuzz.txt` (**sanitized** —
  the SecLists feed is uncurated/parser-breaking). Sent to `replay-ua` on path
  `/` → `http_would_block_scanner_ua` / `_empty_ua`.
- **Referer fixture:** raw referers from the corpus + nginx-ultimate-bad-bot-
  blocker `bad-referrers.list`. Sent to `replay-referer` → `_referer`.
- **Cookie fixture:** synthetic (no corpus data) — the existing synthetic cookie
  fixture extended with FuzzDB SQLi payloads. Sent to `replay-cookie` → `_cookie`.
- **Fake-bot:** Googlebot/Bingbot strings (monperrus/crawler-user-agents) sent
  from the loopback peer (NOT in the verified CIDR) → `_fake_bot`. (Threat-intel
  truth #2: the string is benign; the wrong source IP is the attack.)

**Extractor change (small):** add `--ua-vectors` / `--referer-vectors` output
modes to `extract-replay-vectors.pl` (top hostile UA / referer with volume), so
the header fixture is reproducible from the same one-pass tool. The output stays
**IP-free** (carry forward the extractor's existing discipline: no `remote_addr`
in any emitted artifact — security-officer S4).

---

## 5. Reason mapping (the TP assertion table)

Plain keys verified against `waf_status.c:224,241`. Reason labels are
`waf_reason_str[]` (`ngx_http_waf_module.c:59-76`).

| dimension / source | expected counter (plain key) | notes |
|---|---|---|
| scanner-path hit | `http_would_block_scanner_path` | **aggregate only in detect** — see below |
| args signature | `http_would_block_args` | |
| cookie signature | `http_would_block_cookie` | synthetic fixture |
| referer signature | `http_would_block_referer` | |
| scanner / hostile UA | `http_would_block_scanner_ua` | |
| empty UA | `http_would_block_empty_ua` | |
| fake bot | `http_would_block_fake_bot` | crawler UA from unverified IP |

**Inspector C1 correction:** `http_scanner_path_{404,403,444}` action buckets do
NOT increment in detect mode — the detect branch returns before the action
`switch` (`ngx_http_waf_module.c:1021-1046`). Action-split is **enforce-only**;
detect gives the single aggregate `http_would_block_scanner_path`. The plan does
NOT rely on action buckets.

Full reason-label set (for the FP gate, §6): `scanner_ua, empty_ua, scanner_path,
asn, method, args, cookie, referer, fake_bot, rate_limit, blocklist, geo,
geo_whitelist, flag, allowlist`.

**Counter read + reset (inspector C2):** counters do NOT zero on `nginx -s
reload` (the shm struct is re-used verbatim, `ngx_http_waf_module.c:2244-2248`).
The ONLY reset mechanism is **delta snapshots** — `getcnt` before, replay, `getcnt`
after, assert on the delta (exactly `run-stat-tests.sh:40-46` `assert_delta`).
There is no reload-reset path.

---

## 6. Outputs

1. **FP report** — baseline set replayed on `replay-path`/`replay-args`; assert
   every `http_would_block_*` **delta == 0 across ALL reason labels** (not just
   the 7 cited — inspector M1), to catch a baseline tripping e.g. `method` or
   `rate_limit`. Non-zero → list the offending baseline paths.
2. **Coverage report** — per §3 class: volume, would_block hits, coverage%,
   weighted by `count`. (Expectation: secret_vcs/wordpress high; php low because
   no generic `\.php` rule — that low number IS the finding.)
3. **Uncovered-hostile export** — hostile vectors that triggered NO would_block,
   ranked by volume → the next `scanners.list` candidates (§6/A loop input).
4. Exit non-zero if the FP gate fails (CI-friendly); coverage is reported, not
   asserted as pass/fail (trend signal, like the §6/A headline %).

**Data handling (security-officer S4):** the FP/coverage reports and the
uncovered-hostile export are **corpus derivatives → gitignored**, never committed,
and contain **no `remote_addr`**. Only the harness script + `waf-replay-test.conf`
are committable.

---

## 7. Build/run rules

- Sandbox nginx already built with the WAF `.so` (no `.c` change in B). If the
  module must be rebuilt: cmake `--build --target waf_module`, mind the OpenSSL
  rebuild trap (touch `ssl.h` after reconfigure).
- `purity` is the only file writer; `ngxlogs/` stays read-only; docker forbidden.
- **No fixture/corpus byte ever reaches a shell word or a command line**
  (security-officer S2).
- `modules/ngx_http_waf/tests/corpus/` derivatives (incl. B's reports + fixtures)
  stay gitignored; the harness script + replay conf ARE committable.

---

## 8. Step order

1. Extend `extract-replay-vectors.pl` with `--ua-vectors` / `--referer-vectors`
   (IP-free); regenerate the raw-UA vector set (no `--collapse-ua`).
2. Pull + **sanitize** the external fixtures (CRS scanners-ua, SecLists UA,
   bad-referrers) into `modules/ngx_http_waf/tests/corpus/fixtures/`.
3. Write `modules/ngx_http_waf/tests/waf-replay-test.conf` (dimension-clean
   vhosts; no proxy_pass; loopback-only; no trusted_proxy).
4. Write the **raw-socket perl replay client** + harness
   `modules/ngx_http_waf/tests/run-replay-tests.sh` (delta snapshots; absolute-
   form skip+count; CRLF framing invariant).
5. Run; produce FP report + coverage report + uncovered export (all gitignored).
6. Hand the uncovered list to the §6/A loop (informs C's bounded fixture).

---

## 9. Risks / open questions (post-review)

- **Cardinality:** raw-UA path set ~207k. The raw-socket client must handle it
  with keep-alive; if wall-clock is bad, weight-sample by `count` and report the
  cut.
- **`\xNN` vectors:** quantify how many vectors need byte re-encoding; the
  raw-socket client (§3) handles them with fidelity and the CRLF framing
  invariant.
- **RESOLVED (C1):** action-split is enforce-only; detect = aggregate.
- **RESOLVED (C2):** reload does not reset; use delta snapshots only.
- **Fixture licences:** CRS Apache-2.0, SecLists MIT, crawler-user-agents MIT,
  bad-bot-blocker — verify before C commits any derived fixture.
