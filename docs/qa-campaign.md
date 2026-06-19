# heavybag WAF — QA Campaign Ledger

> Master ledger for the systematic QA hardening campaign of the `ngx_http_heavybag` module.
> Goal: a thoroughly-tested edge firewall. This document is the cross-session memory of the campaign.
>
> **Naming:** `heavybag` = product identity (C symbols/files/.so/metrics/logs). `waf` = nginx config surface (directives, `$waf_*` vars, `X-WAF-*` headers, zone names).

## Campaign parameters (locked 2026-06-17)

- **Depth:** exhaustive Workflow fan-out — 1 reviewer/subunit + adversarial multi-vote verify + loop-until-dry edge hunt.
- **Policy:** *discovery only* this round. This ledger is the deliverable. Test-matrix expansion and source fixes are SEPARATE, partner-initiated rounds.
- **Commits:** partner commits on main and pushes himself. The campaign never commits source.

## Severity legend

| Sev | Meaning |
|---|---|
| **critical** | Memory-corruption / RCE / crash trivially reachable by attacker input, OR a full security bypass of the firewall. |
| **high** | Reachable crash/DoS, exploitable bypass under specific config, shared-memory race with real impact. |
| **medium** | Correctness bug with security relevance under edge conditions; robustness gap. |
| **low** | Defensive-coding gap, narrow edge case, hard to trigger. |
| **info** | Observation / maintainability / test-coverage note, no direct security impact. |

## Subunit inventory & unit-test coverage (recon, 2026-06-17)

### Shared analysis libs (unit-testable in isolation)
| Subunit | Lines | Unit test | Risk |
|---|---|---|---|
| `heavybag_ua_parse.c` | 769 | yes | medium |
| `heavybag_match.c` | 596 | **none** | high |
| `heavybag_geo.c` | 497 | **none** | high (nanolibloc layout) |
| `heavybag_rate.c` | 500 | **none** | high (shared mem) |
| `heavybag_ja4.c` | 424 | yes | medium |
| `heavybag_reputation.c` | 344 | **none** | high (shared mem) |
| `heavybag_spoof.c` | 315 | **none** | medium (UA↔JA4, r->ctx mine) |

### nginx integration glue (runtime-bound)
| Subunit | Lines | Unit test | Risk |
|---|---|---|---|
| `ngx_http_heavybag_module.c` | 2922 | **none** | critical (the giant) |
| `heavybag_status.c` | 796 | **none** | medium |
| `heavybag_stream.c` | 617 | **none** | high (L4) |
| `heavybag_authhttp.c` | 321 | **none** | medium |

**Headline gap:** 9 of 11 translation units have no unit tests — including the two highest-risk classes (geo memory-layout, shared-memory concurrency in rate/reputation/status).

## Known landmines (from prior work)

- nginx clears `r->ctx` on internal redirect → per-connection data used across HTTP phases must come from SSL ex-data, NOT request ctx.
- nanolibloc `location.db` network-leaf entry is 12 bytes; flags (anycast etc.) at byte offset 8 (not 2).
- nginx pool lifetime: `r->pool` freed at request end, `c->pool` at connection end; cross-request state needs the shared-memory slab.

---

# Findings ledger

_Status: WF-1 (per-subunit review) in progress. Findings populated on completion._

## Per-subunit findings (WF-1)

**WF-1 complete (2026-06-17):** 13 reviewers + 26 adversarial verifiers (39 agents, 2.68M tokens). **Result: no critical, no high.** The core decision logic is genuinely well-written and defensive; the majority of findings are documented design intent or false positives. 30 primary findings (1 medium, 7 low, 22 info) + 1 build-portability defect that a verifier surfaced (the reviewer missed it).

### Actionable — fix-round candidates

| ID | Sev | Subunit | Issue | Disposition |
|---|---|---|---|---|
| `ja4-01` | **medium** | ja4.c:229-234,257-269 | Empty cipher/extension list is SHA-hashed (→ `e3b0c44298fc`) instead of the FoxIO-canonical literal `000000000000`. A blocklist/allowlist keyed on canonical JA4 silently misses only-GREASE / empty-extension hellos (attacker controls own ClientHello); canonical `ja4.list` entries for empty-list hellos never fire. | **FIX.** When the list feeding a JA4 field is empty, emit the literal `000000000000` (per FoxIO: JA4_c when n==0 && ns==0). Unit-testable. |
| `module-cfg-v01` | low (build) | module.c:39 vs 2861-2862,2905,2921 | `ngx_http_heavybag_next_reason_filter` declared inside `#if (NGX_HTTP_SSL)` but referenced unconditionally → `--without-http_ssl_module` build fails (undeclared identifier). Build-time only. | **FIX.** Move the declaration out of the SSL guard (or guard the uses). |
| `rate-01` | low | rate.c:221 | `added = elapsed*rate_num_fp/period_ms` has no in-function `period_ms==0` guard. Not reachable from the HTTP config path (rule_add only sets 1000/60000/3600000), but `rate_check` is an exported opaque API documented for HTTP/STREAM/mail heads → SIGFPE if a future/zeroed caller passes 0. **DISPUTED** (confirm=FP-not-triggerable, refute=real-defensive-gap). | Hardening: add `if (period_ms == 0) return NGX_OK;` alongside the fail-open guards. |
| `status-01` | low | status.c:497-500 | JSON `server_name` escaped with `ngx_escape_json` (up to 6× expansion) but only a 1-byte free-space guard; safe TODAY solely because the buffer over-reserves ~18× per vhost. `server_name` is admin-controlled, not request-controlled. **DISPUTED.** | Hardening: size via `ngx_escape_json(NULL,...)` and clamp to a local destination bound. |
| `module-phase-01` | low | module.c:991-1016 | `rate_check()` decrements the shared bucket BEFORE detect-mode is evaluated → `waf detect` still mutates token-bucket state; a later flip to enforce (or a parallel head on the same zone) sees depleted buckets. No security bypass. | Gate `rate_check` (or read-only peek) when mode==DETECT, or document it. |

### Policy decision for partner

- `match-01` (low, decode policy): `sig_lookup_decoded()` percent-decodes **once**, so `%2527union` reaches the matcher as `%27union` and evades a pattern targeting the once-decoded literal quote. The matcher itself is faultless (length-bounded, no NUL-truncation bypass — verified). **Decision:** is multi-encoding in scope? If yes → iterate decode to a fixed point; if no → document the single-pass contract.

### Confirmed design-intent / fail-open (no code change; document loudly)

- `reputation-02` — unknown IP (absent from location.db) fails OPEN in block mode (NGX_DECLINED). Stricter posture = use whitelist (`allow_cc`) mode.
- `reputation-03` — ASN deny fails open when `res.asn==0` (no AS in the geo leaf).
- `match-02` — alternation is unanchored + caseless by design; relies on author-supplied anchors.
- `rate-02` — a full 32-slot probe window evicts the oldest-seen IP and resets it to a full burst; IP-rotation can un-throttle a victim (fail-open for the victim, not attacker-quota escalation). Documented "saturating attacker evicts itself" trade-off.
- `module-phase-04` — allowlist short-circuits ONLY the reputation stage; allowlisted IPs still flow through method/rate/UA/fake-bot/scanner-path/signature.
- `stream-02` — stream rate limit silently fail-opens if `http{}` never registered the `waf_rate` zone; no `nginx -t` diagnostic (observability gap → candidate for an init-time WARN).
- `module-phase-02/03`, `stream-03` — counter accounting quirks: double-count across internal-redirect hops; detect-mode would-blocks omitted from `requests_total == allowed + sum(blocked)`. → routed to WF-2 observability subsystem.

### Full triage table (all 30 findings + 1 missed)

| Subunit | ID | Sev | Category | Title | Consensus |
|---|---|---|---|---|---|
| match | match-01 | low | input-validation | Single-pass percent-decode → double-encoding gap | likely-real |
| match | match-02 | info | nginx-idiom | Alternation unanchored/caseless by design | likely-real |
| match | match-03 | info | integer | off_t→size_t file size cast (config-time) | false-positive |
| geo | geo-01 | low | robustness | IPv4 root index not bounds-checked at assign (re-validated) | false-positive |
| rate | rate-01 | low | robustness | No period_ms==0 div-by-zero guard (exported API) | disputed |
| rate | rate-02 | low | decision-bypass | Eviction resets actively-throttled IP's bucket | likely-real |
| rate | rate-03 | info | decision-falseblock | New bucket denies 1st req iff now32==0 (1ms/49d) | likely-real |
| reputation | reputation-01 | low | robustness | res not zero-init before geo_lookup (geo sets found first) | false-positive |
| reputation | reputation-02 | info | decision-bypass | Unknown IP fails open in block mode (intent) | likely-real |
| reputation | reputation-03 | info | decision-bypass | ASN deny fails open when asn==0 (intent) | likely-real |
| reputation | reputation-04 | info | config | flag 'anon' alias exact-length match correct | likely-real |
| reputation | reputation-05 | info | integer | cc16 packing integer-safe/byte-consistent | likely-real |
| spoof | spoof-01 | info | info | Subunit is HTTP spoofing, not JA4-vs-UA detection | likely-real |
| spoof | spoof-02 | info | nginx-idiom | ctx-on-redirect N/A (single-pass header→body) | likely-real |
| spoof | spoof-03 | info | memory-safety | Error-page buffer math correct, snprintf-bounded | likely-real |
| spoof | spoof-04 | info | decision-falseblock | Error-page detection predicate correctly narrow | likely-real |
| ua_parse | ua_parse-01 | info | info | ua_version borrowed slice; lifetime correct | disputed |
| ja4 | ja4-01 | **medium** | decision-bypass | Empty list hashed, not literal 000000000000 | likely-real |
| ja4 | ja4-02 | info | integer | JA4_a count loops use int before clamp (unreachable) | disputed |
| stream | stream-01 | info | info | No JA4/ssl_preread/ex-data surface in this TU | likely-real |
| stream | stream-02 | info | info | Stream rate fail-opens if http omits waf_rate_zone | likely-real |
| stream | stream-03 | info | control-flow | Detect-mode rate-check runs on would-block peer | likely-real |
| status | status-01 | low | robustness | JSON server_name unbounded ngx_escape_json | disputed |
| authhttp | authhttp-01 | info | decision-bypass | Trust gate fail-open/safe intentional; no bypass | likely-real |
| module-cfg | module-cfg-01 | info | info | Reason header filter installed globally (gated) | disputed |
| module-cfg | module-cfg-02 | info | info | stat_init_zone size not re-guarded for overflow | disputed |
| module-phase | module-phase-01 | low | robustness | Detect mode still consumes a rate-limit token | likely-real |
| module-phase | module-phase-02 | info | robustness | Counters double-count across internal-redirect hops | likely-real |
| module-phase | module-phase-03 | info | info | Detect would-block omitted from allow accounting | likely-real |
| module-phase | module-phase-04 | info | info | Allowlist short-circuits only reputation stage | likely-real |
| module-vars | module-vars-01 | info | info | Decoded URI logged to error log (log hygiene) | likely-real |
| module-vars | module-vars-02 | info | robustness | Static tables indexed by ctx enum, no local bound | likely-real |
| module-cfg | module-cfg-v01 | low (build) | portability | Reason-filter symbol under #if NGX_HTTP_SSL, used unconditionally | missed-by-reviewer, confirmed |

**Cleared as false positives:** `match-03`, `geo-01`, `reputation-01` (both verifiers concur — not exploitable).

## Subsystem cross-cutting findings (WF-2)

**WF-2 complete (2026-06-17):** 5 subsystem architects + 10 adversarial verifiers (15 agents, 1.47M tokens). **Result: 2 high, 6 medium, 12 low, 6 info — but NO attacker-triggerable BYPASS and NO remote crash.** Both high-severity items are operator-/build-triggered startup failures. The JA4 flow correctly reads from SSL ex-data (the r->ctx landmine is avoided); shared-memory hot paths and reload re-attach are verified correct.

### Key reframing established by WF-2

- **The JA4-vs-UA spoof verdict (`ctx->is_spoofed`) is OBSERVABILITY-ONLY — it never gates a block** (`lifecycle-03`/`ja4flow-01`). No reason enum entry exists for a spoof verdict; it only feeds a counter and `$waf_ua_is_spoofed`. **This bounds `ja4-01` (WF-1) to a metrics-accuracy issue** — the empty-list hash never changes an allow/deny decision because the lookup result is never enforced. → Decision for partner: should JA4-vs-UA spoofing actually *block* (behind a `waf_spoof_block` directive)? Right now the headline TLS-fingerprint feature has zero enforcement effect.

### Actionable — fix-round candidates

| ID | Sev | Where | Issue | Disposition |
|---|---|---|---|---|
| `sharedmem-01` | **high** | stream.c:396-404 ↔ module.c:2664-2699 | Stream-only config: stream postconfig `ngx_shared_memory_add("waf_status", 0, ...)` pushes a size-0 stub; HTTP postconfig (which sets the real size) never runs → nginx zero-size guard → **fatal startup abort** for a documented-valid config shape. | **FIX.** Resolve `waf_status` by walking `cycle->shared_memory` (set pointer only if HTTP head registered it; tolerate NULL) — mirror the existing `waf_rate` pattern. |
| `config-01` | **high** | module.c:29-40 (decl) vs 2861-2862/2904-2905/2921 (use) | `ngx_http_heavybag_next_reason_filter` declared under `#if (NGX_HTTP_SSL)` but installed/dereferenced unconditionally → `--without-http_ssl_module` fails to compile/link the **entire .so** (incl. the SSL-independent STREAM head). (= WF-1 `module-cfg-v01`, elevated.) | **FIX.** Move the pointer declaration OUT of the `#if (NGX_HTTP_SSL)` block; only the JA4 ex-data index needs the SSL guard. |
| `lifecycle-01` | medium | reputation.c:45-53 ↔ module.c:905-1202 | `waf_allowlist` CIDR hit returns NGX_DECLINED+reason=ALLOWLIST, short-circuiting ONLY reputation; allowlisted IPs still hit method/rate/UA/fake-bot/scanner/signature → a trusted CIDR can still get 404/403/444/429. Refute notes the code matches its own doc string ("bypass the reputation checks") and is consistent with the mail-auth head. | **DECISION:** full-pipeline bypass on ALLOWLIST, or fix the docs to say reputation-exemption-only. (See also missed `lifecycle-v01`: allowlisted IP has no geo → lands in the default NULL-cc rate bucket; NAT'd trusted clients can 429 each other.) |
| `sharedmem-02` | medium | stream.c:416-446 ↔ module.c:1961-2013 | If `stream{}` is lexically before `http{}`, the stream head's postconfig walk for `waf_rate` finds nothing → zone NULL → `rate_check(NULL)` fail-opens for every stream connection, silently. | **FIX.** Resolve the zone lazily at worker-init/first-request, or enforce/document http{}-before-stream{}; at minimum WARN. |
| `sharedmem-03` / `config-02` | medium | stream.c:611-617 vs module.c:2030-2033 | Asymmetric validation: HTTP `set_rate_limit` rejects a missing zone at `nginx -t`; the stream setter does not → combined with the fail-open, a stream operator configures rate-limiting that never runs, zero feedback. | **FIX.** Mirror the HTTP guard — stream postconfig emits `nginx -t` error/EMERG when rate_rules exist but the zone resolved NULL. |
| `observability-01` | medium | module.c:869-901 vs 1204-1224 vs 684-716 | `requests_total == allowed + sum(blocked)` is FALSE in detect mode: a detect would-block is in `requests_total` + `would_block` but neither allowed nor blocked. | **FIX/DOC.** Either bump `http_allowed` in detect (would_block becomes a pure overlay) or document `requests_total == allowed + sum(blocked) + sum(would_block)`. |
| `observability-02` | medium | module.c:869-871, 894-901, 1208-1221 | Internal redirects (error_page/try_files/X-Accel/rewrite-last) keep r==r->main and re-run PREACCESS; the only guard is `r != r->main` (subrequests). One request over N hops counts N× across volume, UA share, per-country, and the ratio denominator. | **FIX.** Count once-per-client-request via `r->internal` / a `ctx->counted` flag (the security decision may still re-run). Root cause shared with WF-1 `module-phase-02`. |

### Low / info (catalog for the fix + test rounds)

- `config-03` (low) — `scanner_re[404/403/444]` inherit per-action-slot guarded only by `==NULL`, ignoring the `scanner_list` sentinel → a child loading a 404-only list silently enforces the parent's 403/444 buckets (over-block / policy-leak). Fix: gate on `scanner_list.data == NULL` like the sig_re rows.
- `ja4flow-03` (low) — empty cipher/ext hashed not canonical zeros → missed `is_spoofed` metric only (bounded by observability-only enforcement).
- `ja4flow-04` (low) — TLS session resumption (abbreviated handshake) yields no JA4 → spoof metric undercounts resumed connections (known blind spot).
- `sharedmem-04` (low) — detect `would_block` shm counters double-count on internal redirects (same root as observability-02).
- `observability-03` (low) — reputation/method/rate blocks omit UA-distribution counting → `sum(http_ua[*]) != requests_total`, gate-dependent gap.
- `observability-04` (low) — stream detect would-blocks fold into `allowed`; HTTP folds into neither → two reconciliation models for the same conceptual counter.
- `observability-05` (low) — status snapshot freezes only the fixed struct section; per-vhost arrays read live → cross-section sums can be torn under load. (Confirm corrected: the `cc[]` array IS inside the struct, so it's snapshot-consistent; only per-vhost tearing stands.)
- `observability-06` (low) — Prometheus emits flag blocks under `heavybag_http_blocked_total` twice (reason="flag" and reason="flag",flag=...) → `sum()` double-counts. Fix: distinct metric name.
- `lifecycle-02` (low), `lifecycle-05` (info), `ja4flow-02/05/06` (info/clean), `sharedmem-05` (clean), `config-04` (FP) — see triage table.

### Full triage table (WF-2, 26 findings)

| Subsystem | ID | Sev | Category | Title | Consensus |
|---|---|---|---|---|---|
| lifecycle | lifecycle-01 | medium | decision-falseblock | Allowlist exempts only reputation, later stages still block | likely-real |
| lifecycle | lifecycle-02 | low | observability | Detect mode drops would-block from per-country stats | likely-real |
| lifecycle | lifecycle-03 | info | decision-falseblock | JA4-vs-UA spoof verdict computed but never blocks | likely-real |
| lifecycle | lifecycle-04 | low | state-lifetime | Lazy $waf_country/$waf_asn stale geo cache across redirect | false-positive |
| lifecycle | lifecycle-05 | info | robustness | Single-decode uniform; double-encoding gap is system-wide | likely-real |
| ja4flow | ja4flow-01 | info | observability | Spoof verdict observability-only, never a block gate | likely-real |
| ja4flow | ja4flow-02 | info | state-lifetime | JA4 correctly read from SSL ex-data, not request ctx | likely-real (clean) |
| ja4flow | ja4flow-03 | low | observability | Empty cipher/ext hash → missed spoof metric only | likely-real |
| ja4flow | ja4flow-04 | low | state-lifetime | TLS resumption → no JA4, spoof silently degrades | likely-real |
| ja4flow | ja4flow-05 | low | config | h3/QUIC JA4 coverage unverified | false-positive |
| ja4flow | ja4flow-06 | info | control-flow | Build sort and runtime bsearch comparators match | likely-real (clean) |
| sharedmem | sharedmem-01 | **high** | config | Stream-only → size-0 waf_status zone → fatal abort | likely-real |
| sharedmem | sharedmem-02 | medium | config | stream{} before http{} → waf_rate unresolved → fail-open | likely-real |
| sharedmem | sharedmem-03 | medium | config | Stream rate limit lacks zone guard → silent fail-open | likely-real |
| sharedmem | sharedmem-04 | low | observability | Detect would_block shm counters double-count on redirects | likely-real |
| sharedmem | sharedmem-05 | info | concurrency | Rate zone reload re-attach coherence correct | likely-real (clean) |
| config | config-01 | **high** | config | SSL-guarded reason-filter used unconditionally → non-SSL build fails .so | likely-real |
| config | config-02 | medium | config | waf_stream_rate_limit no zone validation → silent fail-open | likely-real |
| config | config-03 | low | config | scanner_re inherits per-slot → parent buckets leak to child | likely-real |
| config | config-04 | low | config | JA4 wrapper re-installed each reload (ex-index process-lifetime) | false-positive |
| observability | observability-01 | medium | observability | requests_total==allowed+blocked FALSE in detect mode | likely-real |
| observability | observability-02 | medium | observability | Internal redirects multiply-count one request | likely-real |
| observability | observability-03 | low | observability | reputation/method/rate blocks omit UA-distribution | likely-real |
| observability | observability-04 | low | observability | Stream detect would-blocks fold into allowed (differs from HTTP) | likely-real |
| observability | observability-05 | low | observability | Torn snapshot: globals frozen, per-vhost live | likely-real |
| observability | observability-06 | low | observability | Prometheus flag_blocked double-counts | likely-real |

**Cleared as false positives:** `lifecycle-04`, `ja4flow-05`, `config-04`.

**Notable verifier-surfaced items (missed by reviewer):** `lifecycle-v01` (allowlisted IP → default NULL-cc rate bucket; NAT'd trusted clients 429 each other) and the `observability-v01(refute)` note that `stat_http_block` has a `default: break;` arm where an unexpected block_code bumps `http_blocked[reason]` but no `http_resp_*` — latent `sum(blocked)==sum(resp)` break.

## Edge-case findings (WF-3)

**WF-3 complete (2026-06-17):** 7 adversarial finders + completeness critic + dual-lens verify (12 agents, ~1M tokens). **156 concrete attack vectors probed; only 3 flagged as gaps.** The module is byte-level and protocol-level robust to a striking degree: allocation-free length-bounded UA scan, every TLS wire-walk clamps declared lengths to the getter length, trie walk is `size_t`-bounded before every deref, lock-free rate bucket is unsigned-wrap-correct with bounded CAS loops, per-request `pcalloc` ctx + connection-scoped JA4 ex-data + `r==r->main` gating. **142 vectors are `test_worthy` — this is the regression-test backlog for the next round.**

### Gaps found

| ID | Sev | Consensus | Issue | Disposition |
|---|---|---|---|---|
| `config-build-001` | **high** (build) | REAL-GAP (both verifiers) | `--without-stream` build FAILS: `config:34` unconditionally compiles `heavybag_stream.c`, which `#include <ngx_stream.h>` and uses `NGX_STREAM_MODULE` / `ngx_stream_session_t` / `NGX_STREAM_FORBIDDEN` with NO `#if (NGX_STREAM)` guard → whole `.so` fails to build. Sibling to `config-01` (non-SSL build). | **FIX.** Wrap `heavybag_stream.c` body in `#if (NGX_STREAM)` (and/or gate it in `config`). |
| `rate-divzero-period0` | medium | DISPUTED (latent) | = WF-1 `rate-01`, re-confirmed: `rate_check` exported API has no `period_ms==0` guard → SIGFPE. Unreachable from config (rule_add only sets 1000/60000/3600000) but a real defensive gap on the documented multi-head API. | Hardening: `if (period_ms == 0) return NGX_OK;` |
| `rate-burst0-failclosed` | low | DISPUTED (latent) | NEW: `rate_check` with `burst_fp==0` (raw API) → every request denied forever (fail-CLOSED). Default-substitution is done in the config-time populator, so unreachable today, but the same exported-API class as above. | Hardening: substitute/guard `burst_fp==0` inside `rate_check`. |

**Net new from WF-3:** one HIGH build-portability defect (`--without-stream`), plus a second latent rate-API hardening item. No attacker-triggerable crash/OOB/bypass surfaced at the byte or protocol level.

### Completeness critic — areas NOT yet deeply fuzzed (optional follow-up)

The critic found **0 new gaps** but flagged edge classes no finder probed (candidate scope for a future round): (1) `heavybag_authhttp.c` SMTP path as a whole — attacker `Client-IP` driving the full reputation+geo+rate pipeline from the mail head; (2) the spoof body-filter swapping the WAF's OWN 403/404 block page into the synthetic Apache page (with request `Host` reflected into HTML); (3) `reputation.c` verdict branch precedence when one record satisfies flag_mask+block_asn+flag_cc+block_cc simultaneously, and the `country[0]==0` no-record sentinel colliding with a leaf CC high-byte 0x00; (4) `stat_cc_bump` open-addressed per-country table saturation + `cc16==0` sentinel; (5) status format parser fed a crafted `r->uri` last segment + per-vhost stat index fallback to slot 0 (cross-vhost attribution); (6) IPv6 scope/zone-id / V4MAPPED into geo via the authhttp sockaddr source.

### Test-matrix seed (142 `test_worthy` vectors — the regression backlog)

The full code-grounded vector catalog lives in the WF-3 output; counts per target and the highest-value vectors:

- **ua-fuzz (21):** empty UA; single-byte < every needle (underflow guard); UA==needle (last==0 boundary); token-at-buffer-end → zero-len version; enormous all-digit version (downstream overflow bait); multi-KB no-delimiter termination; embedded NUL mid-UA & in version charset; CR/LF/quote injection clamp; HeadlessChrome/OPR ordering precedence; `wv` webview no-version; HarmonyOS-before-Android; AppleWebKit-without-Safari empty version; overlong UTF-8 passthrough.
- **ja4-fuzz (20):** supported_versions/sigalgs/ALPN inner-length lying > body (clamp); odd trailing byte (dangling half-entry); ALPN zero-len proto → `00`; ALPN non-alnum → hex-escape; ALPN embedded NUL (length-driven); cipher odd byte count; >256 ciphers / >99 ext count clamps; empty cipher/ext canonicalization (`ja4-01`); duplicate ext types; all-GREASE cipher AND ext; ALPN exact-fit boundary.
- **match-redos (11):** bare trailing `%` dropped; `%2g` deletes 3 bytes (silent sig evasion); `%2`-at-EOF drops nibble; `%00` NUL breaks token (no truncation bypass); empty args/cookie short-circuit; **no PCRE2 match/depth limit + JIT off (latent quadratic foot-gun)**; greedy `.*` vs long URI (perf); caseless alternation on 8KB UA (perf); cookie matched WHOLE (no `;`/`=` pair-walk — premise correction); multi-Cookie ngx_list walk; all-`%` contraction invariant.
- **geo-edge (20):** AF_INET6 socklen-trust invariant; `::ffff:1.2.3.4` → IPv4 tree; `::1.2.3.4` compat → full v6 (NOT mapped); `::`/`0.0.0.0` root leaf; `::1` full-depth; all-ones right-path; `/0` default leaf; `/32` & `/128` host leaf at max depth; node/leaf index near UINT32_MAX non-wrap bound; AF_UNIX/unknown family clean no-match; NULL sockaddr/db; truncated DB < DATA_OFF rejected; block offset past EOF rejected; node-0 self-loop cannot hang; single-node boundary; all-zero file fail-closed; ND leaf at exact block boundary (off-by-one).
- **rate-boundary (16):** `period_ms==0` SIGFPE & `burst_fp==0` fail-closed (the 2 gaps — defensive-guard tests); exact burst boundary (Nth allow, N+1 deny); 49-day msec wrap mid-bucket; clock-backwards skew → refill; sub-ms refill rounds to 0; CAS livelock bound (CAS_MAX=16) fail-open; 32-slot window full (age==0 eviction); eviction-storm single-shot CAS; FNV key-equality gating (collision can't poison victim); FNV hash==0 → sentinel 1; min 1r/h & max rate/burst non-overflow; uint32 tok downcast safe; tiny-zone MIN_SLOTS backoff termination.
- **protocol-lifecycle (13):** keepalive blocked-A-then-clean-B fresh ctx; keepalive TLS JA4 stable A/B; H2/H3 multiplex shared JA4 + per-stream ctx; error_page redirect re-runs full decision (double-count/re-block); auth/SSI subrequest never re-scanned; Server-header override on subrequests harmless; plaintext listener JA4 no-op (no NULL deref); TLS resumption/0-RTT → CIDR-only degrade; redirect re-derives client_sa identically (XFF); spoof body-filter emits once; HTTP/1.1 pipelining judged independently; SMTP auth_http bypasses ctx/JA4; ctx first created by log-phase `$waf_*` var when PREACCESS skipped.
- **config-build (28):** **`--without-stream` build fails (the gap)**; geo_block-without-geo_db refused (both heads); empty/comments-only `.list` → NULL bucket; last line w/o trailing newline; CRLF stripped; 100KB single line no-OOM; duplicate directive rejection; rate_limit-without-zone refused (HTTP) vs stream silent fail-open; rate_zone size<8 pages rejected; rate/burst 0/negative/overflow guards; for_geo trailing-comma OK vs double-comma rejected; >1 default rate rule rejected; unknown verified_bot/flag_block class rejected; reload-storm shm reuse by layout signature; stream resolves waf_status/waf_rate size-0 by name+tag; ja4.list malformed line WARN-skip; unknown action → WARN+404 fallback; invalid regex / unreadable file aborts config (fail-closed); 3-level inheritance matrix; **inline-comment-after-action silently degrades to 404 (footgun)**; UA list whole-line-as-fragment.

> Two latent robustness notes worth promoting to the fix list: **match-redos** — `ngx_regex` PCRE2 has no explicit match/backtrack limit set and JIT is off, so a pathological operator-authored pattern + crafted subject is a latent quadratic foot-gun (not exploitable with the shipped lists, but worth a `pcre2_set_match_limit`); **config-build** — an inline comment after an action token silently degrades the rule to a 404 fallback (operator footgun).

---

# Consolidated synthesis (Discovery phase complete, 2026-06-17)

**3 workflows, ~66 agents, ~5.1M tokens.** Verdict: the heavybag WAF is a mature, defensive codebase. **Zero attacker-triggerable memory-corruption, crash, or security bypass** was found at the unit, subsystem, or byte/protocol level. The real issues cluster into four themes: (A) **build-portability** — the single `.so` fails to build in two *supported* configs; (B) **operator-config footguns** — silent fail-open on stream-rate misconfig; (C) **accounting honesty** — detect-mode & internal-redirect counter inconsistencies; (D) **one feature gap** — JA4-vs-UA spoofing is computed and counted but never enforces a block.

## Prioritized fix list (for the partner-initiated fix round)

**P0 — build (the `.so` does not build in supported configurations):**
- `config-01` / `module-cfg-v01` — move `ngx_http_heavybag_next_reason_filter` decl OUT of `#if (NGX_HTTP_SSL)` (fixes `--without-http_ssl_module`).
- `config-build-001` — wrap `heavybag_stream.c` body in `#if (NGX_STREAM)` (fixes `--without-stream`).

**P1 — correctness / silent security loss:**
- `sharedmem-01` (high) — stream-only config → size-0 `waf_status` zone → fatal startup abort. Resolve by walking `cycle->shared_memory` (mirror `waf_rate`).
- `sharedmem-02`/`-03`/`config-02` (medium) — stream rate silent fail-open: resolve zone lazily + `nginx -t` guard + init WARN.
- `lifecycle-01` (medium) — allowlist semantics: DECISION (full bypass vs reputation-only) + doc fix.
- `ja4-01` (medium) — empty list → canonical `000000000000` (impact gated on whether spoof is ever enforced — see Decisions).

**P2 — hardening / observability honesty:**
- `observability-01`/`-02`, `module-phase-01`/`-02`/`-03`, `lifecycle-02`, `sharedmem-04` — detect-mode + internal-redirect counter reconciliation; count-once-per-request.
- `rate-divzero-period0` / `rate-burst0-failclosed` — defensive guards on the exported `rate_check` API.
- `config-03` — `scanner_re` per-slot inherit → gate on `scanner_list` sentinel.
- `status-01` — bound the `ngx_escape_json` destination.
- `observability-06` — Prometheus `flag_blocked` under a distinct metric name.
- `match` (ReDoS foot-gun) — set `pcre2_set_match_limit` / depth limit (latent; not exploitable with shipped lists).
- `config-build` footgun — reject (not silently 404) an inline comment after an action token.

## Decisions needed from the partner

1. **JA4-vs-UA spoof enforcement** — should it BLOCK (new `waf_spoof_block` directive + a spoof reason) or stay observability-only? Right now the headline TLS-fingerprint feature has *zero* enforcement effect (`lifecycle-03`/`ja4flow-01`).
2. **Allowlist semantics** (`lifecycle-01`) — full-pipeline bypass on `waf_allowlist`, or reputation-exemption-only (fix docs)?
3. **Double-encoding** (`match-01`) — multi-encoding in scope (iterate decode to fixed point) or document the single-pass contract?
4. **Detect-mode accounting** (`observability-01`) — bump `allowed` in detect (would_block becomes a pure overlay) or expose+document the 3-term invariant `requests_total == allowed + sum(blocked) + sum(would_block)`?

## Test-matrix round (the 142-vector backlog)

- **ctest.h unit tests** for the 9 uncovered TUs (priority: match, geo, rate, reputation, spoof) seeded directly from the WF-3 per-category vectors above.
- **Regression tests** for the 2 rate gaps (defensive-guard) and the 2 build gaps (a build-matrix CI across http_ssl/stream/http_v2/http_v3/mail permutations).
- **Integration `.conf` scenarios** for the lifecycle/protocol vectors (keepalive reuse, internal-redirect re-entry, H2/H3 multiplex, detect-mode accounting reconciliation).
- **Optional deeper fuzz round** on the critic's un-probed areas: `authhttp` SMTP path, spoof self-block swap, reputation verdict precedence, `stat_cc` table saturation, status format parser + cross-vhost attribution.

## Fix round

Address P0→P2 by severity; re-verify each fix; re-run the relevant WF-1/WF-2 reviewer + the new regression test. Partner commits on main and pushes.

### Fix round 1 — COMPLETED 2026-06-17 (A+B+C+D + waf_spoof_block + allowlist scope)

Partner decisions taken (AskUserQuestion): allowlist → `waf_allowlist_scope` default `full`; double-encoding → single-pass contract documented (no double-decoding backend); accounting → detect allowed-bump (simple invariant).

| ID(s) | Theme | Fix | Verification |
|---|---|---|---|
| `config-01` / `module-cfg-v01` | A build | Moved `ngx_http_heavybag_next_reason_filter` decl OUT of `#if (NGX_HTTP_SSL)` (module.c); JA4 ssl-index stays guarded. | default build clean; **--without-http_ssl permutation build PASS** (reason-filter compiles, no undefined SSL symbol) |
| `config-build-001` | A build | Gated stream src + `ngx_stream_heavybag_module` registration in `config` on `[ "$STREAM" != NO ]`. **NOTE:** an initial `#if (NGX_STREAM)` body-guard was WRONG (nginx defines no such macro → dropped the stream module from the with-stream build, dlopen "undefined symbol"); removed. Gating is config-only. | smoke A (dlopen) PASS; **--without-stream permutation build PASS** (heavybag_stream.c excluded, no stream symbol) |
| `ja4ssl-build-001` **(NEW — MISSED by Discovery; surfaced by the --without-http_ssl permutation test)** | A build | `ngx_http_heavybag_ja4_compute()` + its static helper used `SSL_is_quic` (OpenSSL 3.2+ QUIC API) but lived only inside `#ifndef HEAVYBAG_JA4_UNIT_TEST`, NOT `#if (NGX_HTTP_SSL)` → `--without-http_ssl_module` failed (implicit decl of SSL_is_quic). Wrapped the whole SSL extractor in `#if (NGX_HTTP_SSL)` (heavybag_ja4.c ~313-445); the pure JA4 core (ja4_build) stays outside. | --without-http_ssl permutation PASS; default build + 43 tests re-verified PASS |
| `sharedmem-01` | B | Stream `waf_status` resolved by walking `cycle->shared_memory` (shared helper), never `ngx_shared_memory_add(...,0,...)` → no zero-size fatal abort in stream-only configs. Resolution moved to `init_module` (order-independent, runs under `nginx -t`). | smoke A/B PASS |
| `sharedmem-02/-03`, `config-02` | C | Zone resolution in `init_module` (block-order independent) + WARN when `waf_stream_rate_limit` set but `waf_rate` zone NULL. | smoke B WARN line confirmed |
| `observability-01` | D | Detect would-block now also bumps `http_allowed` (+vhost) → `requests_total == allowed + sum(blocked)` holds; would_block is a pure overlay. | unit/build |
| `observability-02`, `module-phase-02/03` | D | Count-once-per-client-request: `sh` left NULL on internal-redirect hops (`r->internal != 0`) so every direct counter bump is skipped; `finalize_decision` applies the same `r->internal` gate. Security DECISION still runs every hop. (ctx-cleared-on-redirect landmine: `r->internal`, not a ctx flag.) | build |
| `observability-04` | D | HTTP detect model aligned to the stream model (would_block overlay + counted-allowed) → the two heads now reconcile identically; no stream code change needed. | build |
| `lifecycle-03` / `ja4flow-01` + `ja4-01` | feature | New `waf_spoof_block on\|off` directive + `HEAVYBAG_REASON_SPOOF` (enum+string lockstep) + spoof block-stage in PREACCESS (after reputation, 403, detect-aware). `ja4-01`: empty cipher list → JA4_b `000000000000`; empty exts+sigalgs → JA4_c `000000000000` (FoxIO-canonical), now enforcement-relevant. | 43 unit tests PASS incl. 2 ja4 (1 updated + 1 new); parse smoke PASS |
| `lifecycle-01` (+ `lifecycle-v01`) | feature | `waf_allowlist_scope full\|reputation` (default `full`): a `waf_allowlist` hit short-circuits the ENTIRE pipeline (full) via goto+label; `reputation` keeps the old reputation-only exemption. Full default also keeps a geo-less trusted IP out of the default rate bucket. | parse smoke PASS (both scope values) |
| `match-01` | §6.B | Documented the single-pass percent-decode contract at `sig_lookup_decoded` (no decode-to-fixed-point loop; partner confirmed no double-decoding backend). | doc |

**Files touched:** `ngx_http_heavybag_module.c`, `heavybag_stream.c`, `heavybag_ja4.c`, `heavybag_rep.h`, `ngx_http_heavybag.h`, `config`, `tests/unit/test-ja4.c`.

**Verified (all 4 build dimensions + tests):**
- default (with ssl + stream): build clean under -Werror; 43/43 unit tests; `nginx -t` of the existing sandbox config + a new-directives config (incl. the stream-rate WARN line).
- `--without-stream`: `make modules` PASS, `heavybag_stream.c` excluded, no `ngx_stream_heavybag_module` reference (config-build-001 ✓).
- `--without-http_ssl_module`: `make modules` PASS (after the ja4ssl-build-001 fix), reason-filter compiles (config-01 ✓), no undefined SSL symbols.
- Re-verified default build + 43 tests + nginx -t green AFTER the heavybag_ja4.c SSL-guard edit.

**Not commit:** partner commits on main himself. Permutation scratch dirs `objs-nossl/` and `objs-nostream/` left under the nginx source tree (build/nginx_ext-prefix/src/nginx_ext) for inspection — removable.

**Out of scope (separate rounds):** the 142-vector regression test matrix; P2 hardening (rate-divzero/burst0 guards, scanner_re inherit gate, status JSON bound, Prometheus flag metric, PCRE2 match-limit, inline-comment footgun); `lifecycle-02` (detect would-block per-country) low item; the critic's un-probed deep-fuzz surfaces.

### Fix round 1 — RUNTIME re-verification (live nginx) — 2026-06-17

Beyond the build/unit verification above, the four Fix-round-1 *runtime* behaviors were exercised against a **live sandbox nginx** (freshly rebuilt + redeployed `.so`, mtime 10:35; OpenSSL did NOT rebuild) driving real HTTP/HTTPS requests and scraping the `waf_status` plain endpoint. **45/45 assertions PASS, 0 FAIL, 0 warn.** Harness lives under `.claude/tmp/reverify/` (confA-http.conf, confB-spoof.conf, driveA.sh, driveB.sh, test-ja4.list).

**HTTP scenarios (confA, 27/27)** — distinct servers on 28081-28085, status scraped on 28085 (`waf off`, self-checked to not self-count):

| Behavior | Setup | Observed |
|---|---|---|
| `lifecycle-01` allowlist **full** bypass | 127.0.0.1 allowlisted, scope `full`, GET /wp-login.php (a scanner path) | 200 served, `blocked_scanner_path Δ=0`, `allowed Δ=3`, `allowlist_hits Δ=3` — full scope skips the scanner stage |
| `lifecycle-01` allowlist **reputation** scope | same but scope `reputation` | /wp-login.php → 404 ×3 (`blocked_scanner_path Δ=3`); control /index.html → 200 — reputation scope does NOT skip later stages |
| `observability-02`/`module-phase-02/03` **count-once** | GET 3× nonexistent path → static 404 → `error_page` redirect to /index.html (internal redirect hop) | `http_requests_total Δ=3` (NOT 6) — the `r->internal` hop is not re-counted; `allowed Δ=3`, `sum(blocked) Δ=0` |
| `observability-01`/`-04` **detect overlay** | `waf detect`, GET 3× /wp-login.php | 200 served ×3, `would_block_scanner_path Δ=3`, `blocked_scanner_path Δ=0`, `http_allowed Δ=3` — detect would-block also bumps allowed |
| **GLOBAL invariant** | full workload (13 reqs) | `requests_total(Δ13) == allowed(Δ10) + sum(blocked)(Δ3)` ✓ |

**HTTPS spoof scenarios (confB, 18/18)** — JA4 over TLS. Discovery first read the local curl JA4 via `add_header X-JA4 $waf_ja4_hash` = `t13i3112h2_e8f1e7e78f70_ce5650b735ce` (TLS1.3) / `t12i2807h2_d943125447b4_dd0a478c1db3` (TLS1.2); the production `ja4.list` correctly leaves curl's **IP-SNI `t13i`** variant UNKNOWN (safe-degrade, no false positive). A controlled `test-ja4.list` maps those two fingerprints → `tool`, so a UA claiming Chrome/Firefox produces a genuine JA4-vs-UA family contradiction — the real code path (JA4 fetch → family lookup → expected-family → mismatch → `is_spoofed` → block-stage → counter) is exercised end-to-end; only the configured fingerprint-DB row is controlled.

| Behavior | Setup | Observed |
|---|---|---|
| `waf_spoof_block` **enforce** | `waf on` + `waf_spoof_block on`, UA=Chrome | **403** ×3, `X-Spoof: 1`, `http_blocked_spoof Δ=3` |
| spoof **no false positive** | same server, UA=curl (real tool, JA4=tool → families match) | `X-Spoof: 0`, **200** served, `blocked_spoof Δ=0` |
| spoof second positive | UA=Firefox (expected firefox) vs JA4 tool | **403** (family mismatch enforced) |
| `waf_spoof_block` **off** (observability-only) | `waf on` + `waf_spoof_block off`, UA=Chrome | `X-Spoof: 1` (still detected, `http_ua_spoofed` bumps) but **200** — not enforced; `blocked_spoof`/`would_block_spoof Δ=0` (stage gated off) |
| spoof in **detect** mode | `waf detect` + `waf_spoof_block on`, UA=Chrome | **200** ×2 (overlay), `would_block_spoof Δ=2`, `blocked_spoof Δ=0`, `http_allowed Δ=2` |

Runtime error log: only the 3 *expected* `open() ... nope-* failed` static-404 lines from the count-once redirect test; **no WAF errors, no crashes, no alloc failures**; clean worker exit (code 0). The runtime re-verification confirms the Fix-round-1 source is correct in a running server, not just at compile/unit level. (Harness untracked under `.claude/tmp/`; not part of the commit unless the partner wants it.)

### Fix round 2 — P2 hardening — COMPLETED 2026-06-17

The six P2 backlog items (all `low`/`latent`, **none attacker-triggerable** with the shipped lists): robustness on the exported APIs, honest observability, fail-closed config validation, bounding the regex engine. Partner decisions taken (AskUserQuestion): ReDoS → **module-local PCRE2 match context** (the real fix, not a refactor); inline-comment footgun → **support inline comments + hard error on a genuine typo**. All edits landed in **existing translation units** — no new `.c`, no nginx `./configure` rerun (module-only rebuild).

| ID(s) | Theme | Fix | Verification |
|---|---|---|---|
| `rate-divzero-period0` + `rate-burst0-failclosed` | exported-API robustness | Two early fail-open guards in `ngx_http_heavybag_rate_check` (heavybag_rate.c), before the CAS loop, beside the existing 3 (`hdr`/`key`/`nslots`): `period_ms==0 → return NGX_OK` (no SIGFPE on the div at the old line 221); `burst_fp==0 → return NGX_OK` + a **one-time `NGX_LOG_ALERT`** via `ngx_cycle->log` (a zeroed param is a caller bug — surface the otherwise-silent disabled limiter). Config-substituted callers never hit either (period ∈ {1000,60000,3600000}, burst defaults to rate); the guards protect the raw exported API. | default build clean -Werror; `rate_check called with burst_fp==0` string present in deployed `.so` |
| `config-03` | fail-closed inheritance | `merge_loc_conf` (ngx_http_heavybag_module.c): **deleted** the buggy per-slot `scanner_re[i]==NULL` inherit loop and **folded** the standalone `scanner_list` copy into ONE sentinel-gated block (`conf->scanner_list.data == NULL`) that copies all `HEAVYBAG_ACTION_MAX` buckets together — mirroring the `sig_re` row model. A child defining ANY scanner list now owns all three buckets (no parent 403/444 leak); a child with no list still fully inherits. | runtime B-#2: `/parent-only` (parent scope) → 403, `/probe` (child 404-only scope) → 404 **not 403** (no leak) |
| `config-build` (inline-comment footgun) | fail-closed config | `scanner_compile` (heavybag_match.c) action-token region: truncate at the first `#` then right-trim (new local `ae`) → `403 # note` parses as `403`; empty token (comment-only, e.g. `^/x # note`) keeps the default 404 bucket; a non-empty **unknown** token now `return NGX_ERROR` with `NGX_LOG_EMERG "unknown action \"%V\" in scanner list"` (was: WARN + silent 404). The regex pattern (before `pe`) is untouched, so a `#` inside a pattern is safe. **Inspector [H1]:** `scanner_compile` is shared by `waf_scanner_list` AND `waf_{args,cookie,referer}_list` → the fatal applies to all four list types (uniform fail-closed action parsing). | A1 inline-after-action loads (exit 0); A2 scanner typo `^/x bock` → config abort + EMERG; **A3 sig-list (`waf_args_list`) typo → config abort + EMERG** (shared path proven); runtime B-#3 `/secret`→403, `/danger`→444(000), `/note`→404 |
| `status-01` | defense-in-depth | JSON vhost loop (heavybag_status.c): pre-measure `need = ngx_escape_json(NULL, name->data, name->len)` and gate the write on `(size_t)(last-p) >= need` (new local `need`). The buffer is already over-reserved by `status_bufsize` (6×), so this never truncates in practice — pure bound on the admin-controlled `server_name` escape. | runtime B-#4: `/stat/json` valid RFC8259 (jq parse) with a `server_name` carrying `"`+`\`; the name round-trips escaped, no overrun, clean error.log |
| `observability-06` | honest metrics | Prometheus per-flag breakdown (heavybag_status.c) renamed `heavybag_http_blocked_total{reason="flag",flag=...}` → **`heavybag_http_blocked_flag_total{flag=...}`** (distinct metric name, dropped the redundant `reason="flag"` label) — mirroring the `country_total`/`country_blocked_total` distinct-name pattern. The reason loop's flag aggregate is unchanged. README example updated. **Inspector [M2]:** this is NOT a reconcilable sum — `http_blocked[FLAG]` bumps once per blocked *request*, `flag_blocked[]` once per matched flag *bit*, so the per-bit breakdown does not equal the aggregate by design; the rename only removes the `sum(heavybag_http_blocked_total)` double-count. | runtime B-#5: new metric present; **no** `blocked_total` line carries a `flag=` label → `sum(blocked_total)` no longer double-counts |
| `match` ReDoS | CPU-bounding | New `#if (NGX_PCRE2)` helper `ngx_http_heavybag_regex_exec` (heavybag_match.c) bypasses nginx's default-context `ngx_regex_exec` wrapper with a module-local `pcre2_match_context` carrying `pcre2_set_match_limit(100000)` + `pcre2_set_depth_limit(1000)` and a size-1 `pcre2_match_data`. On MATCHLIMIT/DEPTHLIMIT → negative → **no-match (fail-open, CPU-bounded)**. Both call sites (`scanner_lookup` :311, `ua_classify` :589) switched to the helper; sig lists ride `scanner_lookup` too, so they're covered. `#else` macro keeps PCRE1 working. **Inspector [L2]:** the two per-worker statics live for the process lifetime (reclaimed at exit, like nginx's own global `ngx_regex_match_data`) — deliberately NO `exit_process` handler added for two tiny objects (module.c exit-process slot stays NULL). | runtime B-#6: `(a+)+$` + 40×'a'+`X` → fail-open in **0.020s** (unbounded ≈ 2⁴⁰ steps = hang); positive all-'a' still → 403 (limit never clips a real match); regression: scanner-path 404, args-sig 403, UA sqlmap→`scanner` all still fire through the limited exec |

**Files touched:** `heavybag_rate.c`, `ngx_http_heavybag_module.c` (no exit_process hook added), `heavybag_match.c`, `heavybag_status.c`, `README.md` (Prometheus metric example).

**Build / unit:** SSL variant (the one the sandbox nginx loads) rebuilt clean under `-Werror` via `make -f objs/Makefile modules` (OpenSSL did NOT rebuild — ssl-touch-guard applied); 43/43 unit tests green (no unit test touches the changed paths). **Permutation:** the non-SSL `objs-nossl` variant ALSO compiled the changes clean — the `#if (NGX_PCRE2)` helper builds in both variants. (A full standalone `--without-http_ssl_module` configure tree was NOT stood up: every edit is gated on `NGX_PCRE2`, none on `NGX_HTTP_SSL`, so a dedicated SSL-less tree adds no coverage this round. Build-infra change deferred as out-of-scope.)

**Build landmine surfaced (worth recording):** the nginx source tree carries TWO objs variants — `objs/` (SSL, what `sandbox/sbin/nginx` is md5-identical to) and `objs-nossl/` (the top `Makefile`'s `modules` target delegates here). Deploying the wrong variant's `.so` to `sandbox/modules/` yields nginx `[emerg] module ... is not binary compatible`. Correct recipe for a module-only SSL rebuild: `make -f objs/Makefile modules` then copy `objs/ngx_http_heavybag_module.so` → `sandbox/modules/`. The plain `cmake --build --target heavybag_module` and the top-level `make modules` both build/refresh the *nossl* tree, not the SSL `.so` the sandbox runs.

**Runtime re-verification (live sandbox nginx, freshly rebuilt + redeployed SSL `.so` mtime 13:03, binary-compatible):** harness under `.claude/tmp/reverify2/` (runtime.conf + 3 nginx-`-t` smoke configs + 6 lists + run.sh). **24/24 assertions PASS, 0 FAIL, 0 warn** — Part A config smoke (3 nginx -t cases incl. the sig-list shared-path abort) + Part B live runtime (#2 inheritance, #3 inline action, #4 JSON escape, #5 Prometheus rename, #6 ReDoS limit + positive + regression). Error log clean (only benign fs-404 `open()` noise from non-existent test paths); no WAF errors, no crashes, clean worker exit.

**Not committed:** partner commits on main + pushes himself. Harness untracked under `.claude/tmp/reverify2/`.

**Out of scope (unchanged):** the 142-vector regression matrix (incl. dedicated rate/match unit harnesses) — the every-shipped-pattern ReDoS-positive sweep is that round's job; this round proved a representative positive set never clips. Deep-fuzz of the critic's un-probed surfaces (authhttp SMTP, spoof self-swap, reputation precedence, stat_cc saturation).

### Fix round 3 — lifecycle-02 (detect per-country accounting) — COMPLETED 2026-06-17

The last remaining `low`/observability backlog item. **No attacker impact** — pure metrics honesty.

| ID | Theme | Fix | Verification |
|---|---|---|---|
| `lifecycle-02` | observability | In HTTP DETECT mode a would-be-blocked request exited via `return NGX_DECLINED` from `ngx_http_heavybag_finalize_decision` BEFORE reaching any of the 11 per-stage `cc_bump(...,1)` call sites or the `allowed:` label's `cc_bump(...,0)` — so the per-country slot got **zero** credit for the request, even though (since the round-1 observability-01 fix) the global `http_allowed` WAS bumped. Fix: in the detect branch of `finalize_decision` (module.c ~760-771), inside the existing `if (sh != NULL && count)` count-once block, add `if (ctx->geo_done) cc_bump(sh, (cc16 from ctx->country), 0)` — `total++`, `blocked` unchanged. The geo result is read from `ctx` (set == `verdict.geo_valid` before the first finalize call), following the function's own "re-resolve from r, don't thread through callers" design (the comment at module.c:712 already states sh/idx are re-resolved this way). No signature change, no call-site churn. | build clean -Werror (SSL `.so` rebuilt via `make -f objs/Makefile modules`, OpenSSL not rebuilt, md5 build==deploy, `nginx -t` binary-compatible); **runtime 7/7 PASS** live nginx |

**Model decision:** a detect would-block is accounted as *allowed* (it proceeds), consistent with the round-1 observability-01/-04 fixes — so the per-country bump is `cc_bump(...,0)` (`total++` only), NOT `blocked++`. This matches the **already-correct STREAM head**, which has always called `cc_bump(sh, cc16, denied)` unconditionally with `denied==0` in detect (heavybag_stream.c:253,257,289-291). The HTTP head was the only one with the gap (its `cc_bump` is scattered across per-stage block paths that the detect early-return skipped); this fix brings HTTP into line with stream. The `would_block`-per-country alternative was rejected: it needs a new field in `ngx_http_heavybag_stat_cc_t` → shm-layout change (version-guard, open-addressed cc table) — disproportionate for a `low` item.

**Files touched:** `ngx_http_heavybag_module.c` (one 4-line block in `finalize_decision`).

**Runtime re-verification (live sandbox nginx, SSL `.so` mtime 13:26, binary-compatible):** harness under `.claude/tmp/reverify-lc02/` (lc02.conf + run.sh). Geo resolved via `waf_trusted_proxy 127.0.0.1/32` + spoofed `X-Forwarded-For` against the project's own `geodb/location.db` (oracle `reference/geolookup.c`: 185.177.72.1→FR, 1.1.1.1→AU, 8.8.8.8→US). **7/7 assertions PASS:**

| Scenario | Setup | Observed |
|---|---|---|
| **lifecycle-02 fix** — detect would-block bumps per-country total | `waf detect`, scanner `/.env` ×3, XFF=185.177.72.1 (FR) | `country FR total Δ=3`, `blocked Δ=0` — detect would-blocks now visible per-country |
| control — enforce block bumps total AND blocked | `waf on`, scanner `/.env` ×3, XFF=1.1.1.1 (AU) | `country AU total Δ=3`, `blocked Δ=3` — enforce path unchanged; cc table + geo resolution proven real |
| control — allowed request bumps total only | `waf on`, `/index.html` ×2, XFF=8.8.8.8 (US) | `country US total Δ=2`, `blocked Δ=0` — allowed: path correct |

Error log clean (no WAF errors, no crashes, no alloc failures, clean worker exit). Harness untracked under `.claude/tmp/`.

**Not committed:** partner commits on main + pushes himself.

---

## Test-matrix round (permanent regression net for the 142-vector backlog)

The Discovery campaign found **zero** attacker-triggerable corruption/crash/bypass but surfaced one structural gap: 9 of 11 TUs had no unit tests, and the three fix rounds were re-verified only ad-hoc. This round codifies the 142 code-grounded vectors as a permanent regression net, closing the untested-TU gap. Partner decision (2026-06-17): full 142, all three layers (unit / integration / build), multi-session, check-in between phases; partner commits source+tests on `main` and pushes.

Isolation pattern: each pure-core TU is `#include`d directly under a `-DHEAVYBAG_<TU>_UNIT_TEST` flag; an `#ifdef` shim block substitutes the nginx typedefs/macros **byte-for-byte** (`NGX_OK 0`/`NGX_ERROR -1`/`NGX_AGAIN -2`/`NGX_BUSY -3`/`NGX_DECLINED -5`), the nginx-coupled tail (config parsers, slab, mmap, filter chain) sits behind `#ifndef`. The real `-Werror` SSL `objs/` build (`make -f objs/Makefile modules`, md5 build==deploy, `nginx -t`) is the correctness contract — a divergent shim would make the net lie.

### Phase 1 — `rate.c` unit (16 vectors) — COMPLETED 2026-06-17

New `tests/unit/test-rate.c` (suite `rate`); guard additions to `heavybag_rate.h` (include-gate + `u_char`/`ngx_int_t`/`ngx_uint_t`/`ngx_atomic_t`/`ngx_atomic_uint_t`/`ngx_msec_t` shim, all 64-bit so the packed-state CAS + ~49-day msec wrap hit the production boundary) and `heavybag_rate.c` (runtime-symbol shim: `__sync` atomics, writable `ngx_current_msec`, no-op `ngx_log_error` + zeroed `ngx_cycle`; `rule_select`/`rule_add`/`init_zone` gated behind `#ifndef`). The table is a flat `calloc` `[hdr][slot×nslots]`; the private slot/hdr structs and the `static` FNV key fn are reachable because the test includes the `.c`.

| # | Vector | Assertion |
|---|---|---|
| V1 | `burst_fp==0` (round-2 guard) | fail-open `NGX_OK` + one-shot ALERT path exercised |
| V2 | `period_ms==0` (round-2 div-by-zero guard) | fail-open `NGX_OK`, no SIGFPE |
| V3 | NULL shm | fail-open `NGX_OK` |
| V4 | `nslots==0` | fail-open `NGX_OK` |
| V5 | unsupported family (AF_UNIX) | `key()==0` → fail-open `NGX_OK` |
| V6 | NULL sockaddr | `key(NULL)==0` → fail-open `NGX_OK` |
| V7 | exact burst boundary | Nth allow / (N+1)th deny `== NGX_BUSY` (-3) |
| V8 | sub-ms refill rounds to 0 | tokens unchanged AND stamp preserved (anti-drift) |
| V9 | 49-day uint32 msec wrap mid-bucket | wrap-safe elapsed → small refill, not 2^32 |
| V10 | clock skewed backwards | uint32 underflow → refill to burst, never stuck/UB |
| V11 | FNV key-equality gating | colliding probe does not mutate the victim's bucket |
| V12 | v4-mapped IPv6 == native IPv4 | identical key |
| V13 | native IPv6 /64 keying | same /64 → same key; different /64 → different key |
| V14 | FNV key never 0 (sentinel) | 200k-IP sweep, always nonzero |
| V15 | probe window full (32) | evict OLDEST, fresh full bucket, `rate_overflow==0` |
| V16 | max rate/burst (P6 bound) | non-overflowing 64-bit refill + lossless uint32 downcast at elapsed=0xffffffff |

**Honest out-of-unit-scope** (documented in test-rate.c header, NOT faked): CAS-starvation fail-open (multi-worker only; covered by the `CAS_MAX` bound + integration/stress); `waf_rate` zone `MIN_SLOTS` back-off (in `init_zone`, slab-coupled → config/integration layer); exact `hash==0` remap (2^-64, not brute-forceable → asserted as the always-nonzero invariant in V14).

**Verification:** `run-unit-tests.sh` exit 0 — rate 16/16, JA4 7/7, UA 36/36 (regressions clean). Real SSL `objs/` rebuild clean `-Werror` (zero warnings), md5 build==deploy `dd921b76ac212755da40cda71e2dd7f1`, `nginx -t` binary-compatible. No production logic changed (guards take the original branch in the no-`-D` build).

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 2 — `geo.c` unit (20 vectors) — COMPLETED 2026-06-17

The highest-risk class (libloc on-disk byte layout). MANDATED header-split applied to the shared `heavybag_geo.h` (included by 4 production TUs: geo.c, reputation.c, status.c, module.c), following the `heavybag_rate.h`/`heavybag_ja4.h` pattern:

- **`heavybag_geo.h`** restructured into three regions: (1) a type-provider block — `#ifndef HEAVYBAG_GEO_UNIT_TEST` → `#include "ngx_http_heavybag.h"`, `#else` → a tiny byte-mirroring shim (`u_char`/`ngx_int_t`/`ngx_uint_t`/`ngx_str_t` + `ngx_inline`, all derived from `<stddef.h>`/`<stdint.h>`); (2) the SHARED section — block-index + per-network-flag macros and the `geo_db_t`/`geo_result_t` structs (they reference only shimmable types, so the unit test can build a synthetic in-memory db); (3) the production-only prototypes (`geo_open`/`geo_lookup`, `ngx_conf_t`/`struct sockaddr` coupled) behind `#ifndef`. The on-disk layout constants are NEVER duplicated into the shim — a divergent copy would silently drift from the real layout the walk depends on.
- **`heavybag_geo.c`** gated: top includes (`<sys/mman.h>` + OpenSSL → `#ifndef`; `<netinet/in.h>` for sockaddr/IN6_IS_ADDR_V4MAPPED/AF_* → `#else`); the signing-key static, `geo_cleanup` (munmap), `geo_verify` (OpenSSL ECDSA-P521), and `geo_open` (ngx_conf_t/mmap) all behind `#ifndef HEAVYBAG_GEO_UNIT_TEST`. The `u32`/`u16` big-endian readers, the radix-trie `geo_walk` (static), and `geo_lookup` stay ungated — they ARE the production code under test (12-byte ND-leaf with **flags at offset 8**, the `(size_t)net*12+12 > block_len[ND]` bound, the `off+12 > ntlen` node bound), never re-declared.

New `tests/unit/test-geo.c` (suite `geo`) includes `heavybag_geo.c` directly under `-DHEAVYBAG_GEO_UNIT_TEST`; hand-built 12-byte tree nodes (`[bit0-child | bit1-child | net]`, `net & 0x80000000` = internal) and 12-byte leaves (`[cc | rsv | asn | flags | rsv]`) drive `geo_walk`/`geo_lookup`. Both are reachable because the test includes the `.c`.

| # | Vector | Assertion |
|---|---|---|
| V1 | v4 native leaf decode | country + ASN read from the matched leaf, found=1 |
| V2 | flags at ND offset 8 (libloc landmine) | flags from `[8,10)`; poison `0xDEAD`@`[2,4)` / `0xBEEF`@`[10,12)` NOT read; ASN intact |
| V3 | `::ffff:1.2.3.4` (v4-mapped) == native v4 | identical leaf via `ipv4root` (distinct subtree, genuinely walked) |
| V4 | `::1.2.3.4` (v4-COMPATIBLE, not mapped) | full 16-byte v6 walk from node 0, does NOT see the v4 tree's leaf |
| V5 | genuine AF_INET6 (`8000::`) | 16-byte path, bit0==1 right-child branch; `::` → no-match |
| V6 | all-zero `::` & `0.0.0.0` | root leaf matched at depth 0 |
| V7 | `/0` default | non-zero address falls back to the root leaf |
| V8 | longest-prefix | a deeper leaf supersedes the `/0` leaf; sibling stays default |
| V9 | internal sentinel node | `net & 0x80000000` not recorded as a leaf; sentinel-only path → no-match |
| V10 | `/32` host leaf max v4 depth | reached only after all 32 bits; flip last bit → no-match |
| V11 | `/128` host leaf max v6 depth | reached only after all 128 bits; flip last bit → no-match |
| V12 | ND-leaf bound off-by-one | last leaf (`end==block_len`) accepted; index one past rejected (found=0) |
| V13 | NT-node bound off-by-one | node at exact `block_len` walkable; child one node past → walk -1, no over-read |
| V14 | leaf index near UINT32_MAX | `net=0x7FFFFFFF` → `(size_t)net*12+12` rejects, no 32-bit multiply wrap |
| V15 | child index near UINT32_MAX | `nxt=0xFFFFFFFE` → `off+12 > ntlen` rejects in size_t, no wrap/over-read |
| V16 | self-referential child | node1 bit0-child → node1; bounded by addrlen (≤32 iters), terminates, no hang |
| V17 | single-node tree (`block_len[NT]==12`) | leaf-root matches; internal-only root → no-match; no boundary over-read |
| V18 | AF_UNIX / unknown family | clean no-match, no walk |
| V19 | NULL db & NULL sockaddr | clean no-match, no crash |
| V20 | MSB-first bit direction | bit0 = MSB of byte 0: `0.0.0.0`→left leaf, `128.0.0.0`→right leaf |

**Honest out-of-unit-scope** (documented in test-geo.c header, NOT faked): the config-time `geo_open`/`geo_verify` path is behind `#ifndef` and needs `ngx_conf_t` + mmap + an ECDSA-P521/SHA-512-signed `location.db` + OpenSSL — magic check, mandatory signature verify, `size < DATA_OFF` / `> MAX_SIZE` rejection, block `offset+len > EOF` rejection, the 96-level descent to the IPv4-mapped root, and all-zero-FILE fail-closed (magic mismatch). These are covered by the **Fix-round-3 LIVE nginx test** (real FR/AU/US ground-truth lookups against the project's signed `geodb/location.db`, oracle `reference/geolookup.c`) and the config-build layer; they cannot be unit tested without nginx+OpenSSL.

**Verification:** `run-unit-tests.sh` exit 0 — **geo 20/20**, rate 16/16, JA4 7/7, UA 36/36 (regressions clean). The header touches 4 production TUs → verified byte-transparent: SSL `objs/` rebuild clean `-Werror` (zero warnings, all 4 includer TUs compile silently), md5 build==deploy `c1ddfa3b4772403e8331f843034be16d`, `nginx -t` binary-compatible; the `objs-nossl` and `objs-nostream` permutation trees also compile `heavybag_geo.c` clean. The `.so` md5 changed from Phase 1's `dd921b76…` to `c1ddfa3b…` due only to `__LINE__`/debug-info shift from the added `#ifndef` lines — the production preprocessed token stream is unchanged (the guards take the nginx branch in the no-`-D` build). No production logic changed.

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 3 — `ua_parse` extend (21 vectors) — COMPLETED 2026-06-17

The descriptive UA parser core (`heavybag_ua_parse.c`, 769 lines) already had a 36-case happy-path + ordering + clamp suite. This phase adds the **WF-3 ua-fuzz backlog (21 vectors)** as a byte-level robustness net, driving the two security-critical primitives DIRECTLY — `heavybag_ua_find()` (the bounded, case-insensitive scan; never reads past `hay+hlen`) and `heavybag_ua_version()` (the `[0-9A-Za-z._-]` version slice; the CR/LF/quote/control-char clamp is the parser's one attacker-byte sink). Both are `static` and reachable because the test `#include`s the `.c` under `-DHEAVYBAG_UA_PARSE_UNIT_TEST`. **No production source touched, no header split needed** (the existing isolation harness already pulls in the nginx-free core); the deployed SSL `.so` is byte-identical (md5 unchanged).

Three suites added to `tests/unit/test_heavybag_ua_parse.c`:

| # | Suite / test | Vector | Assertion |
|---|---|---|---|
| V1 | `ua_find/needle_longer_than_hay_no_underflow` | `nlen>hlen` (and `hlen==0`) | NULL — the size_t underflow guard (`last=hlen-nlen` never computed) |
| V2 | `ua_find/exact_length_match_last_zero` | `nlen==hlen` | match returns `hay` at `last==0`; mismatch → NULL |
| V3 | `ua_find/empty_needle_is_null` | `nlen==0` | NULL short-circuit |
| V4 | `ua_find/match_at_final_position` | match at `i==last` | returns `hay+2` (inclusive upper bound) |
| V5 | `ua_find/nul_transparent_scan` | embedded NUL mid-hay | needle after the NUL still found (length-driven, not strstr) |
| V6 | `ua_find/case_insensitive_fold` | `CHROME` vs `chrome` | `|0x20` A–Z fold matches at `hay+3` |
| V7 | `ua_version/token_at_buffer_end_zero_len` | token at EOF (`s==end`) | vlen 0, vstart==`hay+hlen`, no byte beyond end read |
| V8 | `ua_version/nul_byte_terminates_version` | NUL in version charset | slice clamps before the NUL (`"8.5"`) |
| V9 | `ua_version/high_bit_byte_terminates_version` | `>=0x80` (UTF-8 lead) | clamps at the first 8-bit byte (`"8.5.0"`) — overlong-UTF-8 passthrough blocked |
| V10 | `ua_version/full_charset_accepted` | digits `.` `_` `-` lower upper | whole `"1.2.3-rc_4Z"` sliced verbatim |
| V11 | `ua_version/absent_token_null_slice` | token not present | vstart NULL + vlen 0 (poison overwritten) |
| V12 | `ua_version/enormous_all_digit_version` | 4 KB all-digit version | vlen 4096 — zero-copy slice, NO length clamp (downstream-overflow note: consumer must bound its own copy) |
| V13 | `ua_version/space_terminates_version` | common delimiter | slice clamps at the space (`"120"`) |
| V14 | `ua_edge/empty_ua_all_fields_unknown` | empty UA | browser/os/category/vendor ALL UNKNOWN + vlen 0 (every needle hits the `nlen>hlen` guard) |
| V15 | `ua_edge/single_byte_ua_all_unknown` | 1-byte UA `"M"` | all UNKNOWN (shorter than every needle, shortest is `wv`=2) |
| V16 | `ua_edge/multi_kb_no_delimiter` | 8 KB of `'a'`, no token | UNKNOWN; every needle scan runs to `i==last` across 8 KB, no over-read |
| V17 | `ua_edge/webview_wv_no_version` | `; wv) ... Chrome/` | CHROME via the dedicated `wv` branch, which yields **vlen 0** (no version slice) |
| V18 | `ua_edge/applewebkit_without_safari_empty_version` | AppleWebKit, no `Safari/` | SAFARI with empty version (HEAVYBAG_VER on absent token → len 0), vendor apple |
| V19 | `ua_edge/crios_over_safari` | iOS Chrome (`CriOS/`) | CHROME/google before the trailing `Safari/` (ordering precedence), version `120.0.6099.119` |
| V20 | `ua_edge/harmonyos_browser_vendor_precedence` | HarmonyOS + bare Chrome | os HARMONYOS but vendor GOOGLE — browser-switch precedes the os→huawei fallback |
| V21 | `ua_edge/embedded_nul_then_token_found` | `"ab\0Chrome/120..."` explicit len | CHROME + version found end-to-end past the NUL (no NUL-truncation smuggling) |

**Honest out-of-unit-scope** (documented in the test header, NOT faked): the nginx-facing wrappers `ngx_http_heavybag_ua_parse()` (request-ctx population, `ua_parsed` latch, threat-category override) and `ngx_http_heavybag_ua_spoof_eval()` (live JA4 fetch from SSL ex-data + verified-bot CIDR signal) sit behind `#ifndef HEAVYBAG_UA_PARSE_UNIT_TEST` — they need an `ngx_http_request_t` + a TLS connection. The `ja4_signal` contradiction boolean is already mirrored in the existing `spoof` suite; the live JA4 wire walk is Phase 6b. The CR/LF/quote clamp's downstream-sink protection (log_format / add_header) is an integration concern — the core only guarantees the slice TERMINATES at the first out-of-charset byte, which is exactly what V7–V13 assert.

**Verification:** `run-unit-tests.sh` exit 0 — **UA 57/57** (was 36; +21), rate 16/16, JA4 7/7, geo 20/20 (regressions clean). Test-file-only change: no production source edited, no module rebuild, deployed SSL `.so` md5 `c1ddfa3b4772403e8331f843034be16d` (unchanged from Phase 2, build==deploy). The unit harness compiles the UA core with `-Wall` clean (no extra libs).

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 4 — `ja4` core extend (17 vectors) — COMPLETED 2026-06-17

The pure JA4 core (`ngx_http_heavybag_ja4_build`, in `heavybag_ja4.c`) already had a 7-case suite (FoxIO canonical vector, GREASE filtering, ALPN hex fallback, no-ALPN/QUIC, the two `ja4-01` empty-list canonicalizations, cipher count clamp). This phase adds the **WF-3 ja4-fuzz backlog** as a byte-level robustness + canonical-semantics net, driving `ngx_http_heavybag_ja4_build()` directly (already isolated under `-DHEAVYBAG_JA4_UNIT_TEST`, includes `heavybag_ja4.c`, links `-lcrypto` for SHA256). **No header split** (the core is already nginx-free behind the existing guard) and **no production source touched** — test-file-only. Assertions are STRUCTURAL/RELATIVE (two builds compared, or fixed byte offsets in the 37-char JA4 string) so no hand-computed SHA256 literal is needed — mirroring the existing `grease_is_filtered` style.

JA4 string layout pinned by the offsets: `[0]` proto `t|q`, `[1..2]` version, `[3]` SNI `d|i`, `[4..5]` cipher count, `[6..7]` ext count, `[8..9]` ALPN, `[10]` `_`, `[11..22]` JA4_b (cipher hash), `[23]` `_`, `[24..35]` JA4_c (ext+sigalg hash).

| # | Test | Vector | Assertion |
|---|---|---|---|
| V1 | `ext_count_clamp_99` | 150 non-GREASE exts | ext count field (`[6..7]`) clamps to `"99"` (the `next>99` clamp), mirrors the cipher-side clamp |
| V2 | `max_elems_hash_clamp` | 257 vs 256 ascending ciphers | `HEAVYBAG_JA4_MAX_ELEMS` (256) keeps the first 256 in input order before sort → JA4_b byte-identical to the 256-prefix; no over-read |
| V3 | `cipher_order_independent` | shuffled cipher list | ciphers sorted before hashing → fingerprint order-invariant (fwd == rev) |
| V4 | `ext_order_independent` | shuffled ext list | exts sorted before hashing → JA4_c order-invariant |
| V5 | `sigalg_order_preserved` | reversed sigalgs | **the behavioral pin:** sigalgs kept in ORIGINAL order → JA4_c differs while JA4_a+`_`+JA4_b (`memcmp 23`) stay byte-identical |
| V6 | `duplicate_ext_types_kept` | `{0x0005}` vs `{0x0005,0x0005}` | no de-dup: count `01`→`02`, JA4_c differs |
| V7 | `duplicate_ciphers_kept` | `{0x1301}` vs `{0x1301,0x1301}` | no de-dup: count `01`→`02`, JA4_b differs |
| V8 | `all_grease_cipher_and_ext` | all-GREASE ciphers AND exts | counts `00`/`00`, SNI `i`, JA4_b and JA4_c both the canonical literal `000000000000` |
| V9 | `alpn_zero_len_is_00` | non-NULL ALPN ptr, `alpn_len==0` | field `"00"` (the `len==0` guard, not the NULL guard) |
| V10 | `alpn_leading_nul_hex_escaped` | ALPN `{0x00,'h'}` | leading NUL non-alnum → hex `"08"` (high nibble of `0x00`, low nibble of `'h'`) |
| V11 | `alpn_interior_nul_transparent` | ALPN `{'h',0x00,'2'}` | only first/last byte drive the field → `"h2"` (interior NUL transparent, length-driven) |
| V12 | `alpn_single_byte` | ALPN `{'x'}` len 1 | `alpn[0]==alpn[len-1]` → `"xx"` |
| V13 | `version_codes_legacy` | 0x0302 / 0x0301 / 0x0300 | TLS1.1 `"11"`, TLS1.0 `"10"`, SSL3.0 `"s3"` |
| V14 | `version_codes_dtls_and_unknown` | 0xfeff/0xfefd/0xfefc/0x9999 | DTLS `d1`/`d2`/`d3`, unrecognised → `"00"` fallback |
| V15 | `sni_presence_byte` | ext 0x0000 present vs absent | byte `[3]` `'d'` vs `'i'` |
| V16 | `sni_alpn_counted_excluded_from_hash` | `{SNI,ALPN,0x000d}` vs `{0x000d}` | SNI(0x0000)+ALPN(0x0010) COUNTED in `[6..7]` (`03` vs `01`) but EXCLUDED from JA4_c → hash identical |
| V17 | `null_out_returns_error` | `out==NULL` | returns `-1`, no write (the core's one hard error) |

**Honest out-of-unit-scope** (documented in the test header, NOT faked → Phase 6b wire-walk): the inner-length-lying-past-body clamps for `supported_versions`/`signature_algorithms`/ALPN, the odd-trailing-byte / dangling-half-entry drops, and the 2-byte-per-cipher wire parse all live in `ngx_http_heavybag_ja4_compute()` behind `#if (NGX_HTTP_SSL)` — they parse raw `SSL_client_hello_*` getters into the arrays this core consumes, and require a live `SSL*`. The pure core's contract (it trusts the parsed arrays + their counts and canonicalizes deterministically) is exactly what V1–V17 pin; the extractor's length-clamping is the Phase 6b SSL-harness job. `SSL_is_quic` likewise is extractor-only (the core takes `is_quic` as a parameter — covered by the existing `no_alpn_and_quic` case).

**Verification:** `run-unit-tests.sh` exit 0 — **JA4 24/24** (was 7; +17), rate 16/16, geo 20/20, UA 57/57 (regressions clean). Test-file-only change: no production source edited, no module rebuild, deployed SSL `.so` md5 `c1ddfa3b4772403e8331f843034be16d` (unchanged from Phase 2/3, build==deploy). Build+test via p:minion-builder.

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 5 — `match.c` unit (15 vectors, full config-shim) — COMPLETED 2026-06-18

The design-risk TU: `heavybag_match.c` (596 lines) is PCRE2-opaque and the config-time parser is heavily nginx-coupled (`ngx_conf_t` / `cf->pool` / `ngx_array_*` / file I/O / `ngx_regex_compile`). Partner decision (2026-06-18, AskUserQuestion): **Option A — full config-shim** (vs a narrow regex-only harness), the heaviest shim of the campaign but the strongest permanent net — it codifies the round-2 action-parse fatal + inline-comment fix AND the round-2 ReDoS match/depth-limit fix, both of which were until now only ad-hoc runtime-tested (the throwaway `.claude/tmp/reverify2/` harness).

**Key scope finding:** the WF-3 "match-redos" backlog (11 vectors) splits across TWO translation units. The **percent-decode** half (`%2g` 3-byte delete, `%00` NUL token-break, bare trailing `%`, all-`%` contraction), the **empty args/cookie short-circuit**, the **cookie WHOLE-match** (no `;`/`=` pair-walk) and the **multi-Cookie `ngx_list` walk** do NOT live in `heavybag_match.c` — they live in `ngx_http_heavybag_module.c` (`ngx_http_heavybag_sig_lookup_decoded` :856 + `ngx_unescape_uri` :873 + the cookie loop :914), which is `ngx_http_request_t`-bound → **integration (Phase 6)**, not a unit. Verified (inspector grep): `unescape|decode|[Cc]ookie` returns 0 matches in `match.c`. The `match.c`-resident half is what Phase 5 freezes.

**Isolation (MANDATED header-split, rate/geo pattern):** `heavybag_match.h` splits `#include "ngx_http_heavybag.h"` — `#ifndef HEAVYBAG_MATCH_UNIT_TEST` → the real module header; `#else` → a type shim (`u_char`/`ngx_int_t`/`ngx_uint_t`/`ngx_str_t`/`ngx_pool_t`(opaque)/`ngx_regex_t`(opaque, cast to `pcre2_code*` exactly as production does)/`ngx_conf_t`/`ngx_array_t`/`ngx_regex_compile_t` + the action enum 404=0/403=1/444=2). The nginx-glue prototypes (`ua_list_compile`/`verified_bot_compile`/`ua_classify`/`ja4_list_compile`) are gated behind `#ifndef`. `heavybag_match.c` carries the runtime shim in its `#else` (real PCRE2 via `#define PCRE2_CODE_UNIT_WIDTH 8` + `<pcre2.h>`, `NGX_*` macros, malloc arena, minimal `ngx_array_create`/`push`, `ngx_regex_compile`→`pcre2_compile` honouring `NGX_REGEX_CASELESS`→`PCRE2_CASELESS`, `ngx_conf_log_error`→an EMERG counter, an in-memory `read_file` serving `heavybag_ut_file`); `read_file` and the glue tail (`ua_list_compile`..`ua_classify`) sit behind `#ifndef`. The tested core (the `next_line` tokenizer, `compile_bucket`, `scanner_compile`, `scanner_lookup`, and the `#if (NGX_PCRE2)` bounded-exec helper `ngx_http_heavybag_regex_exec`) stays UNGATED — it IS the production code under test, reachable because `test-match.c` includes the `.c`. **REAL `-lpcre2-8` is linked** (not a mock): a mocked engine would make the ReDoS fail-open a tautology.

New `tests/unit/test-match.c` (suite `match`); runner stanza added with `-lpcre2-8` (`pcre2.h` at `/usr/include`, no extra flags).

| # | Test | Vector | Assertion |
|---|---|---|---|
| V1 | `next_line_crlf_stripped` | CRLF line ending | trailing `\r` stripped (`le[-1]=='\r'`); two lines then NGX_DONE |
| V2 | `next_line_whitespace_trimmed` | leading+trailing space/tab | both ends trimmed → `^/x` len 3 |
| V3 | `next_line_blank_and_comment_skipped` | blank + ws-only + full-line `#` | only the significant line yielded; NGX_DONE after |
| V4 | `next_line_last_line_no_newline` | last line, no trailing `\n` (`le==end`) | still yielded len 3, then NGX_DONE |
| V5 | `next_line_hash_only_at_start_is_comment` | mid-line `#` (`^/a#b`) | `#`-skip is first-char-only → whole line preserved (boundary vs scanner_compile's action-`#` strip) |
| V6 | `action_explicit_buckets` | `403`/`404`/`444` tokens | each lands in its bucket → FORBIDDEN/NOT_FOUND/CLOSE via the real enum→`heavybag_action_code[]` map |
| V7 | `action_inline_comment_after_action` | `^/x 403 # note` (round-2) | action region truncated at `#` + right-trimmed → 403, `emerg==0` (not a typo) |
| V8 | `action_comment_only_defaults_404` | `^/x # note` | empty action token → default 404, `emerg==0` |
| V9 | `action_unknown_is_fatal` | `^/x bock` (round-2) | `NGX_ERROR` + EMERG fired (fail-closed; never silent-degrade to 404) |
| V10 | `action_hash_inside_pattern_safe` | `^/a#b` (no whitespace) | whole token is the PATTERN → `#` part of the regex, default 404, `emerg==0`, matches `/a#b` |
| V11 | `empty_list_null_buckets_declined` | comments/blank only | every bucket NULL (`compile_bucket` `nelts==0`→NULL); `scanner_lookup` skips NULL → NGX_DECLINED |
| V12 | `bucket_precedence_404_before_444` | subject in BOTH 404 and 444 bucket | `scanner_lookup` walks action order → NOT_FOUND (404 i=0) wins, not CLOSE |
| V13 | `caseless_match` | `^/admin` vs `/ADMIN` | `NGX_REGEX_CASELESS`→`PCRE2_CASELESS` honoured by real `pcre2_compile` |
| V14 | `alternation_second_pattern_matches` | 2 patterns one bucket | `(?:^/aaa)\|(?:^/bbb)` join correct — both alternatives hit via real `pcre2_match` |
| V15 | `redos_failopen_bounded` | `(a+)+$` vs 40×`a`+`X` (round-2 fix) | real `ngx_http_heavybag_regex_exec` → `pcre2_match` with `match_limit=100000`/`depth_limit=1000` trips MATCHLIMIT → negative → no-match (security fail-open), terminates; positive control `aaaa`→FORBIDDEN proves the limit never clips a real match |

**Honest out-of-unit-scope** (documented in test-match.c header, NOT faked): the percent-decode / empty-short-circuit / cookie-WHOLE-match / multi-Cookie-walk vectors live in `module.c` (`sig_lookup_decoded` + `ngx_unescape_uri` + the cookie loop), `ngx_http_request_t`-bound → Phase 6 integration. The ReDoS *timing* proof (bounded 0.020s vs an unbounded ~2⁴⁰-step hang) is the runtime layer's (Fix-round-2 `.claude/tmp/reverify2/` measured it); the unit asserts the OUTCOME the limit guarantees (fail-open no-match + terminates + legit match still fires). The nginx-glue tail (`ua_list`/`ja4`/`verified_bot`/`ua_classify`) is `#ifndef`-gated (request/cidr/ja4-table coupled) — the ja4 fingerprint table already has its own suite.

**Verification:** `run-unit-tests.sh` exit 0 — **match 15/15** (new suite), JA4 24/24, UA 57/57, rate 16/16, geo 20/20 (regressions clean). The production header+`.c` got `#ifndef` isolation guards → verified byte-transparent: **inspector PASS** (p:minion-impl-inspector — git diff against HEAD is 100% additive, ZERO deletions/modified statements; the `#if (NGX_PCRE2)` ReDoS helper sits ABOVE every unit guard = shared production code, byte-identical between builds; 15/15 CORRECT, no tautology incl. the real-engine ReDoS vector, scope-honesty confirmed). SSL `objs/` rebuild clean `-Werror` (zero warnings, all 12 objs incl. `heavybag_match.o` + every includer TU compile silently, OpenSSL NOT rebuilt), md5 build==deploy `4098d087c1b1b88873d0d5ac2494ce67`, `nginx -t` binary-compatible. The `.so` md5 changed from Phase 2-4's `c1ddfa3b…` to `4098d087…` due only to DWARF `__LINE__`/debug-info shift from the added `#ifndef` lines — the production preprocessed token stream is unchanged (guards take the nginx branch in the no-`-D` build). Build+test+inspect via minions.

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 6 — protocol-lifecycle + decode/cookie integration + ja4 extractor unit (48 vectors) — COMPLETED 2026-06-18

The live-fire phase. Where Phases 1-5 froze the pure-core contracts as standalone unit tests, Phase 6 drives the request-lifecycle paths that only exist with a real `ngx_http_request_t` / TLS handshake, plus the ja4 *extractor* clamps that a live OpenSSL handshake cannot reach. Three sub-phases, two new permanent harnesses:

- **6a/6b — `tests/heavybag-protocol-test.conf` + `tests/run-protocol-tests.sh`** (new committed integration harness, honeypot-regression style: self-contained 285xx ports, zero-proxy_pass invariant asserted, 127.0.0.1-only, `waf_reason_header on`, `waf_status` scrape). **32/32 assertions PASS** against the live sandbox nginx.
- **6c — `tests/unit/test-ja4-extract.c`** (new committed unit, mocks the 5 `SSL_client_hello_*` getters + `SSL_is_quic` and drives `ngx_http_heavybag_ja4_compute` directly). **16/16 PASS**; unit suite now **148** (JA4 24 + **ja4x 16** + UA 57 + rate 16 + geo 20 + match 15).

Partner decisions (2026-06-18, AskUserQuestion): permanent committed `tests/` harness (not throwaway `.claude/tmp/reverify`); 6c as a unit-mock extractor (not a brittle live raw-socket TLS client, since the malformed-inner-length / odd-byte clamps abort the OpenSSL handshake before the JA4 is observable on the wire).

#### Part A — protocol-lifecycle (11 assertions, live nginx)

| # | Vector | Setup | Observed |
|---|---|---|---|
| A1 | keepalive fresh ctx (both orders) | one keepalive conn, blocked-then-clean + clean-then-blocked | `/wp-login.php`=404 then `/index.html`=200; `/index.html`=200 then `/phpmyadmin/`=403 — per-request verdict independent, no ctx poisoning across reuse |
| A2 | keepalive TLS JA4 stable | 2 requests, one TLS conn | identical `$waf_ja4_hash` (`t13i3112h1_…`) on both |
| A3 | H2 multiplex | `curl --http2`, two URLs one conn | shared connection JA4 (`t13i3112h2_…`) + per-stream verdict (200 / 404) |
| A4 | internal-redirect count-once | 404 → `error_page` → `/index.html` | `http_requests_total` +1 (NOT +2), `http_allowed` +1 — confirms the observability-02 fix (`r->internal` gate) as a permanent net |
| A5 | SSI subrequest never re-scanned | SSI page `#include`s a scanner path | direct hit `blocked_scanner_path` +1, SSI-include subrequest +0 — `r != r->main` bail proven live |
| A7 | plaintext JA4 no-op | non-TLS listener, `add_header X-JA4 [$waf_ja4_hash]` | `X-JA4: []` (empty) + 200, no NULL deref / crash |
| A8 | TLS resumption | `openssl s_client -sess_out`/`-sess_in` | full JA4 `t13i310900_…`, resumed JA4 `t13i311000_…` — **FINDING:** resumption does NOT degrade to no-JA4 (the client_hello callback fires on the resumption ClientHello too), it yields a DIFFERENT JA4 (the resumption hello carries extra PSK/early-data extensions → different ext count). No crash, no NULL deref. This refines the Discovery `ja4flow-04` assumption ("resumption → no JA4") to "resumption → a distinct JA4, computed safely". |
| A9 | XFF client IP honoured | `waf_trusted_proxy` + blocklisted XFF | blocklisted XFF=403 (reason=blocklist), benign XFF=200 — client IP derived from XFF across the request (the observable core of lifecycle-09 redirect client_sa re-derivation) |
| A10 | spoof body-filter emits once | controlled runtime ja4.list maps live JA4 → tool; UA=Chrome | enforce → 403 `X-Spoof:1`, body emitted once (Content-Length 275 == bytes received); control UA=curl (tool family) → 200 `X-Spoof:0` (no false positive) |
| A12 | mail auth_http (no ctx/JA4) | `waf_mail_auth` content handler, Client-IP header | blocklisted Client-IP → `Auth-Status: static blocklist`; benign → `Auth-Status: OK` — reputation runs over plain HTTP with no request ctx / no TLS / no JA4 |
| A13 | log-phase lazy ctx | `waf off` vhost, `$waf_*` in `log_format` | 200 + `type=regular spoof=0` logged, no crash — the var getters lazily resolve ctx at LOG phase when PREACCESS was skipped |

**Not exercised (honest out-of-scope, documented in the runner header):** H3/QUIC transport — the system curl (7.81) has no HTTP/3 client; the QUIC JA4 path shares `ngx_http_heavybag_ja4_compute` with the TLS path (A2/A3 + the 6c extractor unit cover the fingerprint logic), so only the transport is unverified, not the WAF logic. HTTP/1.1 pipelining was folded into the keepalive ctx-isolation assertion (A1) since curl will not emit a pipelined burst.

#### Part B — module.c percent-decode + Cookie ngx_list walk (14 assertions)

Controlled probe lists (`corpus/protocol-args.list`: `union`→403, `'union`→404; `corpus/protocol-cookie.list`: `sqlmap`→404, `^evilcookie$`→403) make each `ngx_unescape_uri(type=0)` + `ngx_http_heavybag_sig_lookup_decoded`/`_sig_cookie_lookup` edge map to an unambiguous verdict. All assertions match the **real** `ngx_unescape_uri` semantics (traced from the nginx source, `type=0`): `%2g` → all 3 bytes deleted; `%00` → a literal NUL byte emitted (no truncation); a bare trailing `%` → dropped; `%%%%` → contracts to `%%`.

| # | Vector | Verdict | Proves |
|---|---|---|---|
| B1 | `%75nion` → `union` | 403 | basic single decode |
| B2 | `uni%2gon` → `union` | 403 | `%2g` 3-byte delete bridges "uni"+"on" |
| B3a | `%27union` → `'union` | 404 | single decode produces the literal quote |
| B3b | `%2527union` → `%27union` | 403 (via `union`, NOT 404) | **single-pass contract**: the quote stays `%27`-encoded, so the `'union`(404) pattern never fires — only `union`(403) does |
| B4a | `un%00ion` → `un\0ion` | 200 | NUL breaks the token (no `union` match) |
| B4b | `safe%00union` → `safe\0union` | 403 | **NO truncation bypass**: bytes after the NUL are still scanned (length-driven), `union` matches |
| B5 | `union%` → `union` | 403 | bare trailing `%` dropped |
| B6 | `%%%%` → `%%` | 200 | all-`%` contraction, no crash |
| B7 | no query | 200 | empty-args short-circuit (`raw->len==0` → DECLINED, no decode alloc) |
| B8a | `Cookie: a=sqlmap` | 404 | whole-value substring match |
| B8b | `Cookie: a=evilcookie` vs `^evilcookie$` | 200 | **no `;`/`=` pair-walk**: the whole value (`a=evilcookie`) cannot satisfy the anchored pattern |
| B8c | `Cookie: evilcookie` | 403 | anchored whole-value match (control for B8b) |
| B9 | `Cookie: clean=1` + `Cookie: junk=sqlmap` | 404 | multi-Cookie `ngx_list` walk reaches the 2nd header |
| B10 | `Cookie;` (empty) | 200 | empty-cookie short-circuit |

+ 2 reason-attribution spot-checks (`X-WAF-Reason: args` / `cookie`) and an error-log scan (clean: no crash/alert/emerg/alloc-fail).

#### Part C — ja4 extractor unit-mock (16 vectors, `test-ja4-extract.c`)

Isolation: a byte-mirroring nginx type shim + mock `SSL_client_hello_*` getters, then `#include heavybag_ja4.c` under `-DHEAVYBAG_JA4_EXTRACT_UNIT_TEST`. That macro makes `heavybag_ja4.{h,c}` SKIP their `<ngx_config.h>`/`<ngx_core.h>`/`<openssl/ssl.h>` includes (the test supplies the types + getters) while still pulling in the real pure core (real `<openssl/evp.h>` for SHA256, `-lcrypto`) and the real extractor `ngx_http_heavybag_ja4_compute`. Two tiny `#ifndef HEAVYBAG_JA4_EXTRACT_UNIT_TEST` guards added to production (`.h` + `.c`) — production defines NEITHER test macro → byte-transparent. Assertions are STRUCTURAL (fixed byte offsets in the 36-char JA4 string, or two builds compared) — no hand-computed SHA literal.

| # | Test | Clamp / behaviour exercised |
|---|---|---|
| 1 | `cipher_two_byte_parse` | 2-byte BE cipher decode → count `02` |
| 2 | `cipher_odd_trailing_byte_dropped` | `i+1<len` drops the dangling half-cipher → count `01` |
| 3 | `cipher_count_over_max_clamps` | 300 ciphers → `n_cip` clamps to `HEAVYBAG_JA4_MAX_ELEMS`, count field `99`, no over-read |
| 4 | `supported_versions_inner_length_lie_clamped` | ext 0x002b `list=255` vs body 3 → `end=len` clamp, the one real version (TLS1.3) parsed |
| 5 | `supported_versions_short_body_falls_back` | too-short body → no full entry → legacy version |
| 6 | `sigalgs_inner_length_lie_clamped` | ext 0x000d `list=255` clamped → 1 sigalg still feeds JA4_c (differs from no-sigalgs build) |
| 7 | `sigalgs_odd_trailing_byte_dropped` | trailing odd byte dropped (`i+1<end`) → JA4_c equals the clean-list build |
| 8 | `alpn_exact_fit` | `3+list==len` → ALPN `h2` |
| 9 | `alpn_zero_len_is_00` | `list==0` guard → no ALPN → `00` |
| 10 | `alpn_lying_length_rejected` | `3+list>len` → ALPN rejected entirely → `00`, no over-read |
| 11 | `alpn_embedded_nul_length_driven` | proto `{h,NUL,2}` length 3 → field `h2` (first/last byte, length-driven, not strlen-cut at NUL) |
| 12 | `sni_presence_byte` | ext 0x0000 present → byte[3]=`d`; absent → `i` |
| 13 | `ext_count_field` | 4 ext ids → count `04` |
| 14 | `is_quic_proto_char` | `SSL_is_quic` → proto byte `q` vs `t` |
| 15 | `ext_ids_freed` | the allocating getter's buffer is `OPENSSL_free`d on success (CWE-401) |
| 16 | `null_out_is_error` | NULL `out` (with non-NULL ssl+pool) → `NGX_ERROR`, no write |

**Honest out-of-unit-scope:** the live H3/QUIC transport (no client); the `client_hello` callback + `SSL_CTX` wiring (in module.c, not this TU). The wire-level inner-length-lie / odd-byte vectors are unreachable through a live handshake (OpenSSL aborts before the JA4 is observable) — which is exactly why they are driven here through mocked getters.

**Verification:** `run-protocol-tests.sh` 32/32 + `run-unit-tests.sh` 148/148, both exit 0. The two production guard edits are byte-transparent: SSL `objs/` rebuild clean `-Werror` (zero warnings, OpenSSL NOT rebuilt), `nginx -t` binary-compatible; deployed `.so` md5 `4098d087…` → `03a216df17d1661854e8287045050eb8` (DWARF `__LINE__` shift only; production token stream unchanged — the protocol harness re-ran 32/32 against the rebuilt `.so`, behavioral byte-transparency confirmed). Build via p:minion-builder; integration + unit runs inline (runtime harness against the built `.so`, the reverify pattern). New committed files: `tests/heavybag-protocol-test.conf`, `tests/run-protocol-tests.sh`, `tests/corpus/protocol-args.list`, `tests/corpus/protocol-cookie.list`, `tests/unit/test-ja4-extract.c`; edited: `tests/unit/run-unit-tests.sh` (+1 stanza), `src/heavybag_ja4.{h,c}` (2 byte-transparent guards).

**Not committed:** partner commits source+tests on main + pushes himself.

### Phase 7 — config-build layer: nginx -t validation + build matrix + startup/reload (64 vectors) — COMPLETED 2026-06-19

The last backlog category. Where Phases 1-6 froze the pure-core contracts (unit) and the request-lifecycle paths (integration), Phase 7 closes the **config-build** dimension: the merge-time / parse-time fail-closed decisions that only exist with the real nginx config machinery, the build-portability surface across the supported `./configure` permutations, and the two runtime vectors that only manifest in a live master/worker cycle. Partner decision (2026-06-19, AskUserQuestion): **full permutation matrix** (not just the 3 shipped-fix trees) + **reload + stream-startup runtime** (not nginx -t + build only). **Three new committed harnesses, ZERO production source touched** (test-only phase — deployed SSL `.so` md5 `03a216df17d1661854e8287045050eb8` unchanged from Phase 6, build==deploy, byte-transparent by construction). No inspector required (mirrors the Phase 3 test-file-only precedent).

**Scope split established:** the WF-3 "config-build (28)" backlog has a LIST-PARSE half already frozen byte-for-byte by the Phase 5 `match.c` unit (next_line CRLF/no-newline/blank-skip, empty->NULL bucket, inline-comment, unknown-action EMERG). Phase 7 adds the two layers a unit cannot reach — `nginx -t` integration of those same decisions PLUS the merge/build/runtime-only vectors.

#### Part A — config-validation `nginx -t` net (`tests/run-config-tests.sh`, 34 assertions)

Each vector generates a minimal self-contained conf and runs `nginx -t`, asserting accept / reject-with-specific-diagnostic / accept+WARN. A reject for the WRONG reason (e.g. a missing stream handler) FAILS the assertion because the grep targets the exact `ngx_conf_log_error` string. `nginx -t` does not bind sockets, so the loopback ports never conflict and nothing egresses. **34/34 PASS.**

| Vector(s) | What it pins |
|---|---|
| V1-V4 | `waf_geo_block`/`waf_asn_block`/`waf_geo_whitelist` without `waf_geo_db` -> EMERG `require waf_geo_db` (HTTP **and** STREAM heads — both fail-closed) |
| V5 | geo policy WITH the valid signed `geodb/location.db` -> accept (real ECDSA-P521 verify in -t) |
| V6 vs V7 | the rate-zone asymmetry: HTTP `waf_rate_limit` with no zone -> **EMERG reject**; STREAM `waf_stream_rate_limit` with no zone -> **accepts + WARN** `stream rate limiting is DISABLED` (sharedmem-03/config-02, init_module WARN landing in the error_log during -t) |
| V8 | `waf_rate_zone size=4k` (< 8 pages) -> EMERG `too-small size`; V9 size=1m -> accept |
| V10-V15 | rate_rule_add guards: `rate=0` (invalid rate count), `r/d` (invalid rate unit), `1e12 r/s` (rate is too large), missing `rate=` (requires a rate=), `>1 default rule`, `burst=0` (invalid burst) |
| V16-V18 | `for_geo=CN,US` accept; **trailing comma `CN,` accepts** (skip-comma exits the loop, no empty token — matches the WF-3 "trailing-comma OK" seed); **double comma `CN,,US` rejects** (`two letters`) |
| V19-V22 | unknown `waf_verified_bot` class; unknown `waf_flag_block` token; duplicate `waf_scanner_list`; duplicate `waf_rate_zone` |
| V23-V28 | list-parse @ integration: ja4.list malformed line -> accept+WARN-skip; invalid regex -> abort; missing file -> abort (`open() ... failed`); unknown action -> EMERG (round-2); inline-comment-after-action -> accept (round-2); **100KB single line -> bounded `pcre2 too large` reject, no OOM/hang** (graceful fail-closed) |
| V29-V32 | `waf_mail_backend` hostname rejected (numeric IP only), out-of-range port rejected, valid IP+port accepted; corrupt/unsigned geo_db rejected (fail-closed verify) |
| V33 | kitchen-sink: every major directive in one valid config -> accept (proves the harness is not merely rejecting everything) |

#### Part B — build-portability matrix (`tests/run-build-matrix.sh`, 20 assertions)

Module-only rebuild (`make -f <tree>/Makefile modules` — no `./configure` rerun, no OpenSSL-rebuild trap) across the supported permutation trees + `nm -D` symbol assertions. Self-bootstraps a missing builddir tree via `./configure --builddir` + the ssl.h touch-guard; the 3 CORE trees are required. **20/20 PASS** — and crucially **NO new build defect surfaced** (unlike Fix-round-1 which caught `ja4ssl-build-001` via the permutation test). The three shipped build fixes hold across the whole matrix:

| Permutation | Result | Symbol assertion |
|---|---|---|
| `objs` (SSL+stream+v2+v3+mail, canonical) | build clean, 0 warn | http+stream modules both exported |
| `objs-nossl` (`--without-http_ssl_module`) | build clean, 0 warn | **0 undefined `SSL_*` symbols** (config-01 + ja4ssl-build-001 hold) |
| `objs-nostream` (`--without-stream`) | build clean, 0 warn | `ngx_stream_heavybag_module` **absent** (config-build-001 holds) |
| `objs-nov2` (`--without http_v2`) | build clean, 0 warn | both modules exported (no v2 coupling) |
| `objs-nov3` (`--without http_v3`) | build clean, 0 warn | both modules exported (no v3 coupling) |
| `objs-mail` (+mail; canonical already enables it) | build clean, 0 warn | both modules exported (zero mail interference; .so 8 bytes = alignment padding vs canonical) |
| `objs-nopcre` (`--without-pcre`) | **expected nginx configure ABORT** | n/a — nginx's built-in `http_rewrite` module hard-requires PCRE; a clean `requires the PCRE library` diagnostic at configure time, BEFORE any heavybag source is reached. Not a heavybag portability defect; asserted as the expected failure mode. |

#### Part C — startup/reload runtime net (`tests/run-runtime-tests.sh` + 2 confs, 10 assertions)

Live master/worker cycle (binds 127.0.0.1 286xx). **10/10 PASS.**

| # | Vector | Setup | Observed |
|---|---|---|---|
| C1 | **stream-only startup (sharedmem-01)** | HTTP-less config (`stream{}` only, `waf_stream on` + `waf_blocklist`, proxy to a closed loopback port) | passes `nginx -t`; master **starts clean** (no size-0 `waf_status` fatal abort); a loopback connection exercises the NULL-resolved stream stat path with no crash; error log clean |
| C2 | **reload-storm (shm reuse by layout signature)** | http{} `waf_rate_zone` + `waf_status` + scanner list, stream{} `waf_stream_rate_limit` sharing the same `waf_rate` zone; warm counters then 10× SIGHUP reload | all 10 reloads accepted; master pid **stable** across the storm + alive; counters **persisted + accumulated** `http_requests_total 8 -> 18` (== R0+10, shm reused not reset; a reallocated zone would read ~10 and fail the `>= R0+8` threshold); scanner rule still enforced post-reload (`/phpmyadmin/ -> 403`); error log clean (no `not binary compatible`, no emerg, no crash) |

**Verification:** all three harnesses green against the live sandbox nginx (`run-config-tests.sh` 34/34, `run-build-matrix.sh` 20/20, `run-runtime-tests.sh` 10/10 — 64 assertions total, all exit 0). Deployed SSL `.so` md5 `03a216df17d1661854e8287045050eb8` **unchanged from Phase 6** (no production source edited; build==deploy; `nginx -t` binary-compatible). New committed files: `tests/run-config-tests.sh`, `tests/run-build-matrix.sh`, `tests/run-runtime-tests.sh`, `tests/heavybag-runtime-streamonly.conf`, `tests/heavybag-runtime-reload.conf`. Generated corpus (`tests/corpus/.config-tmp/`) is scratch (gitignore-able). No edits to any `src/*.c`/`*.h` or `tests/unit/`.

**Out of scope (documented):** a fully no-PCRE deployment (would need `--without-http_rewrite_module` too — an unrealistic target with no location regex); the critic's un-probed deep-fuzz surfaces (authhttp SMTP path, spoof self-swap, reputation verdict precedence, stat_cc table saturation) remain a separate optional round.

**Not committed:** partner commits source+tests on main + pushes himself.

---

## Campaign status (2026-06-19)

**Discovery (WF-1/2/3) + 3 fix rounds + 7 test-matrix phases COMPLETE.** The full 142-vector backlog is now a permanent regression net across all three layers:

- **Unit** (`tests/unit/`, 148 cases): rate 16, geo 20, ua 57, ja4-core 24, ja4-extract 16, match 15.
- **Integration** (`tests/run-*.sh`): protocol-lifecycle + decode/cookie (32), config-validation `nginx -t` (34), startup/reload runtime (10).
- **Build** (`tests/run-build-matrix.sh`, 20): the full `./configure` permutation surface, 3 shipped build-fixes netted.

**Portable runner (2026-06-19):** all harnesses are registered as CTest tests via `cmake/Tests.cmake` (included from the top `CMakeLists.txt` after `enable_testing()`). The bash harness stays the source of truth; CTest is the portable launcher. After a normal build: `ctest --test-dir build` (or `cmake --build build --target check`); filter with `ctest -L unit|integration|build` / `ctest -R config`. nginx-bound tests share a `RESOURCE_LOCK heavybag_sandbox` (never run concurrently under `ctest -j`); a harness that exits 2 (sandbox not built) is reported SKIPPED via `SKIP_RETURN_CODE 2`. Registered (10): heavybag_{unit,build_matrix,config,protocol,stat,regression,runtime,replay,honeypot,oracle_build}. `heavybag_replay` asserts the false-positive gate (its main coverage sweep is capped via `ENV "LIMIT=200"`); `heavybag_honeypot` is the read-only ASN/geo analysis pipeline (label `analysis`) and SKIPs cleanly via `SKIP_RETURN_CODE 2` when the raw access log / geo db are absent on the host. `heavybag_oracle_build` (label `build`, `tests/run-oracle-build.sh`) is a build smoke that compiles the four `reference/*.c` developer oracles (geolookup/loctest/nanolibloc libc-only; locverify against the in-tree OpenSSL) so they cannot rot silently — it asserts no behaviour. With this, EVERY runnable script under `tests/` is wired into CTest; only the `tools/*` data/fixture regenerators (which mutate committed corpora) remain intentionally hand-run.

**Relocatable harnesses (2026-06-19):** every `run-*.sh` reads its repo root from `ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}`, and CTest injects `HEAVYBAG_ROOT=${CMAKE_SOURCE_DIR}` (the `ENVIRONMENT` test property), so a moved/renamed checkout works with no edits. The committed `.conf` files (which bake absolute paths nginx cannot env-substitute) are rendered through `sed s#<default-root>#$ROOT#` into `tests/corpus/.render/` before nginx loads them (a no-op on the default root); the runtime-generated confs already build from `$ROOT`/`$SBX` vars. Proven end-to-end: a `/tmp/hb-relocated -> repo` symlink + `HEAVYBAG_ROOT=/tmp/hb-relocated` ran config 34/34 + runtime 10/10 with the rendered conf carrying the relocated `load_module /tmp/hb-relocated/...` path.

Verdict unchanged from Discovery: **zero attacker-triggerable memory-corruption, crash, or security bypass.** Every issue the campaign found was build-portability, operator-config footgun, accounting honesty, or the one feature gap (JA4-vs-UA spoof enforcement) — all addressed in the three fix rounds and now permanently guarded by tests.
