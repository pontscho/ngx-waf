---
name: stress-campaign
type: analysis
status: stale
title: Stress & Load Campaign Ledger
description: Cross-session ledger of the reproducible stress/load campaign — scenarios, S3 counter invariants, and result tables.
sources:
  - modules/ngx_http_heavybag/tests/run-stress-tests.sh
  - modules/ngx_http_heavybag/tests/stress/stress-lib.sh
  - modules/ngx_http_heavybag/tools/gen-stress-corpus.pl
  - modules/ngx_http_heavybag/tests/live/live-slo-path.sh
  - modules/ngx_http_heavybag/tests/live/live-slo-local.sh
verified:
  commit: 7a935b0
  date: 2026-06-21
links:
  - stress-testing
  - overview
---
# heavybag WAF — Stress & Load Campaign Ledger

> Master ledger for the reproducible stress / load-testing campaign of the
> `ngx_http_heavybag` module. Goal: a documented, bit-reproducible measurement
> layer over the (already mature) correctness suite — throughput/latency cost,
> rate-limiter accuracy, lock-free correctness under genuine concurrency, CPU
> under burst, and long-run stability. This document is the cross-session memory
> of the campaign; the per-run numbers come from the `summary.json` artifacts.
>
> **Naming:** `heavybag` = product identity (C symbols / .so / metrics / logs).
> `waf` = nginx config surface (directives, `$waf_*` vars, `X-WAF-*` headers, zone names).

## Campaign parameters (locked 2026-06-21)

- **Focus (partner decision):** correctness-under-load + rate-precision + perf-overhead
  + stability/soak + **CPU under burst** + **latency distribution**.
- **Tools:** h2load (nghttp2) + wrk2 (Gil Tene's constant-arrival fork) combo.
- **Scope:** all three heads — HTTP (L7), stream (L4), mail (auth_http).
- **Reproducibility contract:** nginx-side knobs are BAKED in the stress conf; only
  load-side params are env-tunable, and every one is recorded into each run's
  `params.env` + `summary.json`. The absolute req/s is machine-specific — the
  reproducible metric is the **enforce-vs-`waf off` RATIO**. The machine header
  (CPU / kernel / cores / worker_processes) is stamped into every `summary.json`.
- **Ground truth:** the status-endpoint counter delta (`/waf/stat/plain`, the
  `getcnt()` source lifted to before/after JSON snapshots), never the load tool's
  own status tally.
- **Commits:** partner commits on main and pushes himself. Phased commits
  (infra+HTTP / stream+mail / CPU-burst / soak), atomic style.

## Tooling layout

| Path | Role |
|---|---|
| `tools/stress/versions.env` | pinned h2load/wrk2 versions + H3-capability expectation |
| `modules/ngx_http_heavybag/tools/gen-stress-corpus.pl` | deterministic `replay-vectors.jsonl` → `stress-urls.txt` (top-N, fixed benign cadence, no randomness) |
| `tests/corpus/stress-urls.txt` | **committed** deterministic URL corpus (the load contract) |
| `tests/stress/heavybag-stress-test.conf` | dedicated stress conf, 283xx port band, `worker_processes >=2` baked |
| `tests/stress/stress-lib.sh` | counter snapshot/delta/invariants, CPU/RSS sampling, HDR parsing, tool/capability probes |
| `tests/run-stress-tests.sh` | orchestrator (S1–S5, `--quick` smoke = ctest, `--soak` opt-in) |
| `docs/stress-campaign.md` | this ledger |
| `cmake/Tests.cmake` | `heavybag_stress` (smoke gate) + `heavybag_soak` (opt-in) |

## Scenario inventory

| ID | Name | Tool | Heads | Metric | Gate? |
|---|---|---|---|---|---|
| **S1** | perf-overhead | h2load (H1/H2/H3) | HTTP | enforce-vs-off req/s ratio + latency p50/p99/p999 + full distribution | no (measure) |
| **S2** | rate-precision | wrk2 `-R` sweep | HTTP | measured 429-share vs theoretical `max(0,R−limit)/R` + HDR latency | no (measure) |
| **S3** | correctness-under-load | h2load + curl | HTTP + stream + mail | **per-head counter invariants** | **YES** |
| **S4** | cpu-burst | h2load | HTTP | warmup→burst→cooldown CPU%/RSS timeseries + burst-window HDR | no (measure) |
| **S5** | soak (opt-in) | h2load | HTTP | RSS/fd trend + reload cycling + least-squares leak gate | YES (leak) |

### S3 invariants (the hard correctness gate)

Measured on the counter delta around a concurrent mixed-load window:

- **HTTP:**  `Δhttp_requests_total == Δhttp_allowed + Σ Δhttp_blocked[reason]`
- **STREAM:** `Δstream_connections_total == Δstream_allowed + Σ Δstream_denied[reason]`
- **MAIL:** no status counter → **wire-only** (Auth-Status OK/deny), allow+deny mix.
- **Side assertions:** `Δhttp_allowlist_hits ≤ Δhttp_allowed` (subset, NOT an addend);
  no counter delta goes negative (monotonic).
- **Excluded by construction:** the `would_block[*]` overlay (detect requests count
  as `allowed`), the `http_scanner_path_{403,404,444}` / `http_resp_*` / `http_flag_*`
  / `http_ua*` breakdowns (overlays, not addends), and all `waf off` traffic
  (moves no counter). The 16 reason slots are the only block/deny addends:
  `allowlist blocklist geo geo_whitelist flag scanner_ua empty_ua scanner_path
  asn method args cookie referer fake_bot rate_limit spoof`.

The sharpest surface: the HTTP head and the stream head (port 28391) draw rate
budget from the **same** `waf_rate` shm zone (`heavybag_stream.c:449-454`); loading
both concurrently with `worker_processes >= 2` is the real lock-free race the
`concurrent_same_key` TSan micro-bench only approximates.

## Reproducibility — concretely

- `gen-stress-corpus.pl` is deterministic (top-N by `count` DESC then `uri` ASC,
  fixed benign cadence, **no randomness**); `stress-urls.txt` is committed, so every
  host replays the identical load. Regenerate + verify byte-identity:
  `perl modules/ngx_http_heavybag/tools/gen-stress-corpus.pl` (idempotent).
- Pinned tool versions in `tools/stress/versions.env`; the harness WARNs on drift
  and records expected+found in `summary.json` (never fails on version).
- H3 is a capability, not a version: the harness probes `h2load --help` for the
  HTTP/3 flag and SKIPs the H3 dimension when absent (most distro builds are H1/H2).
- wrk2 must support `-R`; Debian's `wrk` (Will Glozer) does NOT → the harness treats
  it as absent and SKIPs S2 with an actionable message.

## How to run

> Full operational guide (install, params, reading results, troubleshooting):
> [`docs/stress-testing.md`](stress-testing.md).

```sh
# smoke (the ctest gate): ~10s/scenario, pass/fail = S3 invariants
bash modules/ngx_http_heavybag/tests/run-stress-tests.sh --quick
#   or: ctest --test-dir build -R heavybag_stress

# full reference run (fills the tables below)
bash modules/ngx_http_heavybag/tests/run-stress-tests.sh

# opt-in soak
HB_STRESS_SOAK_OPT_IN=1 HB_SOAK_DUR=3600 ctest --test-dir build -R heavybag_soak
```

Artifacts land under `tests/corpus/.stress/<scenario>-<timestamp>/` (gitignored):
`params.env`, raw tool output, `counter-delta.json`, `cpu-rss.csv`, `summary.json`.

---

# Results ledger

> Populated from the `summary.json` of each reference run. Record the machine
> header with every table so cross-host numbers stay comparable.

## Pipeline verification (2026-06-21, dev host, curl fallback)

The load tools (h2load, wrk2) were **not installed** on the build host, so the
pipeline was verified tool-independently: config render + `nginx -t`, corpus
determinism (byte-identical, md5 stable), SKIP-on-absent gating, and the **S3
counter invariants driven with a curl fallback** (`HB_STRESS_CURL_FALLBACK=1`)
under `worker_processes=2` concurrent multi-head load.

**S3 correctness gate — PASS:**

| Head | Invariant | Observed |
|---|---|---|
| HTTP | `Δrequests_total == Δallowed + ΣΔblocked` | `6012 == 2558 + 3454` ✓ |
| STREAM | `Δconnections_total == Δallowed + ΣΔdenied` | `2000 == 116 + 1884` ✓ |
| HTTP | `Δallowlist_hits ≤ Δallowed` | `0 ≤ 2558` ✓ |
| — | monotonic (no negative delta) | ✓ |
| MAIL | wire-only Auth-Status | deny=`static blocklist`, allow=`OK` ✓ |

This already demonstrates the lock-free counters and the shared-shm rate buckets
stay consistent under real cross-worker, cross-head contention — the core
correctness claim. The throughput/latency/CPU tables below await a reference run
on a host with h2load + wrk2 installed.

## S1 — perf overhead (enforce vs `waf off`)

_Pending reference run (needs h2load). Machine header: —_

| Proto | baseline req/s | enforce req/s | overhead ratio | p50 | p99 | p999 |
|---|---|---|---|---|---|---|
| H1 | | | | | | |
| H2 | | | | | | |
| H3 | | | | | | |

## S2 — rate precision

_Pending reference run (needs wrk2). Rate vhost limit = 100 r/s._

| R (req/s) | requests | blocked 429 | measured share | theoretical `max(0,R−100)/R` |
|---|---|---|---|---|
| 50 | | | | 0.000 |
| 100 | | | | 0.000 |
| 200 | | | | 0.500 |
| 500 | | | | 0.800 |

## S4 — CPU under burst

_Pending reference run (needs h2load). See `cpu-rss.csv` + `burst.hdr` per run._

| Phase | worker CPU% (sum) | RSS (KiB) | burst req/s | burst p99 / p999 |
|---|---|---|---|---|
| warmup | | | | |
| burst | | | | |
| cooldown | | | | |

## S5 — soak

_Pending opt-in run. Leak gate: RSS least-squares slope ≤ 64 KiB/s._

| Duration | reloads | RSS slope (KiB/s) | fd trend | verdict |
|---|---|---|---|---|
| | | | | |

---

# Live production run (2026-06-23, example.com edge)

Black-box load test of the **live** edge, distinct from the sandbox S1–S5 harness
above. Driven from a separate host with [`tests/live/live-slo-path.sh`](../modules/ngx_http_heavybag/tests/live/live-slo-path.sh)
(over-the-network, SSH CPU sampling) and [`tests/live/live-slo-local.sh`](../modules/ngx_http_heavybag/tests/live/live-slo-local.sh)
(on-box loopback). Tool: **vegeta** (open-loop constant arrival — true p99);
h2load used for the closed-loop concurrency peak.

**Machine / setup.** Target `example.com` → `203.0.113.10` (Apache-cloaked
heavybag, 6-core box, OpenSSL-QUIC build). Generator on a separate host, ~200
Mbit/s gen↔box path (box uplinks at 1 Gbit/s). Target request `GET /` → nginx
**404** (full WAF pipeline at `http{}` level, then static 404, **no upstream**),
body 274 B → bandwidth never binds (~91k req/s of 404s would fill the link).
Server CPU sampled mid-load with `mpstat -P ALL` / `pidstat -C nginx`.

**Deployed config at test time** (hardened vs the repo sample): `waf on`,
`waf_rate_limit rate=30r/s burst=50 for_geo=HU` + `rate=10r/s burst=15` default,
`waf_geo_whitelist HU LU`, `waf_allowlist 127.0.0.1/32` + `10.0.0.0/24`.
Capacity/latency legs ran with the two `waf_rate_limit` lines temporarily
commented (rate off) so throughput was not capped at 30 r/s; restored after.

## Rate limiter (real config, public path, HU egress)

vegeta constant arrival; the generator's public egress geolocates HU → 30 r/s rule.

| arrival | passed (404) | 429-share (measured) | theory `(R−30)/R` |
|---|---|---|---|
| 30 r/s | 30 r/s | 0 % | 0 % |
| 60 r/s | 30 r/s | 49.9 % | 50 % |
| 120 r/s | 30 r/s | 75.0 % | 75 % |

Steady pass-rate pins to exactly 30 r/s, `burst≈50` absorbs the spike, p99 < 15 ms
on both the pass and the 429 path even at 4× overload. Surgical.

## Capacity & WAF overhead (rate off, public path, vegeta sweep)

| target req/s | p50 | p99 | all-cpu (6c) | nginx CPU | p99≤25 ms |
|---|---|---|---|---|---|
| 800 | 2.7 ms | 16.8 ms | ~8 % | ~50 %/600 | ✅ (SLO knee) |
| 1 000 | 3.4 ms | 47 ms | 11 % | 58 %/600 | ❌ |
| 2 000 | 3.4 ms | 91 ms | 26 % | 131 %/600 | ❌ |
| 4 000 | 13.9 ms | 1.57 s | 47 % | 252 %/600 | ❌ |
| 6 000 | 29 ms | 2.42 s | 60 % | 313 %/600 | ❌ |
| 8 000 | 58 ms | 1.42 s | 77 % | 406 %/600 | ❌ |
| ~10–11k | — | — | ~100 % | CPU-saturated | — |

CPU-bound: six cores peg at ~10–11k req/s (absolute h2load closed-loop peak
~43k req/s deep in saturation). `waf off` vs `enforce` at equal rate differ by
only ~+20–40 % nginx CPU, widening to ~+1 core near 8k.

## True serving latency (loopback, path jitter removed)

`live-slo-local.sh` on the box vs `127.0.0.1` (taken **before** the
`waf_allowlist 127.0.0.1/32` was added — see findings; valid only ≤ ~2k req/s
before the co-located generator steals cores):

| | p50 | p99 |
|---|---|---|
| `waf off`, 1 000 r/s | 0.71 ms | 9.8 ms |
| `enforce`, 1 000 r/s | 0.73 ms | 7.2 ms |
| `enforce`, 2 000 r/s | 0.67 ms | 25.0 ms |

**Full WAF pipeline (geo + JA4 + UA-parse + list-match + rate bookkeeping) costs
~30 µs/request at the median** — lost in the ~0.7 ms TLS+nginx floor.

## Scanner block-path cost (public path, 25 r/s)

| UA | p50 | p99 | verdict |
|---|---|---|---|
| benign (Firefox) | 4.1 ms | 38.8 ms¹ | geo-pass → location 404 |
| scanner (sqlmap) | 3.7 ms | 5.4 ms | `bot_block` → 404 (`scanner_ua`) |

The scanner path is **as cheap or cheaper** than the pass path — `waf_bot_block`
short-circuits at `PREACCESS` before geo/scanner-path/location run. ¹benign p99 is
small-sample path jitter, not server cost.

## Findings

- **Operating point @ p99 ≤ 25 ms:** ~800 req/s over the path, ~2 000 req/s on
  loopback. Both ceilings are set by the **measurement path** (network jitter /
  co-located generator CPU), **not** by heavybag — p50/p95 stay ~3–5 ms past them.
- **Verdict: heavybag is effectively free.** Capacity is bound by the hardware
  (6 cores ≈ 10k req/s of 404 fast-path) and the network path; the WAF adds
  ~30 µs/req latency and a fraction of a core until near saturation.
- **Allowlist short-circuits the whole WAF.** `waf_allowlist 127.0.0.1/32` +
  `10.0.0.0/24` means loopback and the internal subnet (incl. the gen host)
  bypass **all** checks incl. rate limiting — matched on the connection peer.
  Consequence for testing: the **rate/WAF path is only exercisable from a
  non-allowlisted source** (the public path). Loopback runs measure the WAF only
  if the loopback IP is not allowlisted.
- **`rate_overflow` (zone saturation) is not reproducible from a single live
  vantage:** the 10 MB zone holds hundreds of thousands of slots, XFF-spoofing
  many client IPs needs a `waf_trusted_proxy` peer (only loopback qualifies, and
  loopback is allowlisted), and the public peer cannot spoof XFF. Saturation /
  fail-open behaviour belongs in the **sandbox harness with a deliberately tiny
  `waf_rate_zone`** (and the TSan rate-stress micro-bench), not the live edge.

> Caveats: black-box over a bandwidth-limited path (the p99 tail is the path's,
> not the server's); loopback CPU above ~2–4k req/s is confounded by the
> co-located generator; numbers are machine- and path-specific, not a portable
> benchmark.
