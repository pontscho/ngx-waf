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
