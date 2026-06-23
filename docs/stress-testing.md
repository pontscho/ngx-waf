---
name: stress-testing
type: runbook
status: stale
title: Stress & Load Testing Guide
description: Operational how-to for running the heavybag stress/load campaign (install, run, tune, troubleshoot).
sources:
  - modules/ngx_http_heavybag/tests/run-stress-tests.sh
  - modules/ngx_http_heavybag/tests/stress/stress-lib.sh
  - modules/ngx_http_heavybag/tests/stress/heavybag-stress-test.conf
  - modules/ngx_http_heavybag/tools/gen-stress-corpus.pl
verified:
  commit: 7a935b0
  date: 2026-06-21
links:
  - stress-campaign
  - overview
---
# heavybag WAF — Stress & Load Testing Guide

Operational how-to for running the heavybag stress campaign. For the campaign
rationale, scenario design, and the running results tables see the ledger:
[`docs/stress-campaign.md`](stress-campaign.md).

> **TL;DR**
> ```sh
> sudo apt-get install -y nghttp2-client          # h2load (H1/H2)
> #   + build wrk2 from source (see below) for S2
> cmake --build build -j                          # ensure sandbox nginx + deployed .so exist
> bash modules/ngx_http_heavybag/tests/run-stress-tests.sh --quick   # smoke + S3 gate
> bash modules/ngx_http_heavybag/tests/run-stress-tests.sh           # full reference run
> ```

---

## 1. What it measures

The correctness suite (ctest) proves *what* the WAF decides. The stress campaign
measures the *cost* of deciding and proves the lock-free counters and shared rate
buckets stay consistent under genuine concurrency. Five scenarios across all
three heads (HTTP L7, stream L4, mail auth_http):

| ID | Measures | Tool | Gate |
|---|---|---|---|
| **S1** | enforce-vs-`waf off` req/s ratio + latency p50/p99/p999 + full distribution | h2load (H1/H2/H3) | — |
| **S2** | rate-limiter accuracy: measured 429-share vs theoretical `max(0,R−limit)/R` | wrk2 `-R` | — |
| **S3** | **counter correctness under concurrent load** (the hard gate) | h2load + curl | **yes** |
| **S4** | CPU% / RSS under a warmup→burst→cooldown profile + burst-window latency | h2load | — |
| **S5** | long-run RSS/fd trend + reload cycling, leak regression (opt-in) | h2load | leak |

---

## 2. Prerequisites

### 2.1 The sandbox build

The harness loads the **deployed** module and starts the **sandbox** nginx. Both
must exist (a normal build produces them):

```sh
cmake --build build -j
# expects: sandbox/sbin/nginx  and  sandbox/modules/ngx_http_heavybag_module.so
```

If either is missing the harness exits 2 (→ CTest SKIPPED), so running it on an
unbuilt tree is harmless.

### 2.2 h2load (required for S1, S3, S4, S5)

Distro package (Ubuntu/Debian) — gives an **H1/H2** h2load, which is enough for
everything except the H3 dimension:

```sh
sudo apt-get install -y nghttp2-client      # provides /usr/bin/h2load
h2load --version                            # -> nghttp2/x.y.z
```

**HTTP/3 (optional, S1 H3 dimension only).** The distro h2load is built without
QUIC, so the H3 dimension SKIPs automatically. To enable it you must build
nghttp2 from source with `--enable-http3` against ngtcp2 + nghttp3 + a
QUIC-capable TLS (quictls / aws-lc / OpenSSL ≥ 3.5). This is involved and entirely
optional — H1/H2 cover the overhead story. The harness detects QUIC capability by
probing `h2load --help`, not the version string.

### 2.3 wrk2 (required for S2)

> ⚠️ **Ubuntu's `wrk` is NOT wrk2.** The `wrk` package ships Will Glozer's
> original wrk, which has **no `-R` constant-arrival-rate flag**. S2's whole point
> is coordinated-omission-free measurement, which needs Gil Tene's **wrk2** fork.
> The harness probes for `-R` and treats a non-`-R` `wrk` as absent → S2 SKIPs
> with a message. Install the real wrk2 from source (no distro package; no docker
> needed):

```sh
git clone https://github.com/giltene/wrk2 /tmp/wrk2
make -C /tmp/wrk2
sudo install -m755 /tmp/wrk2/wrk /usr/local/bin/wrk2   # name it wrk2 so it wins discovery
wrk2 --version 2>&1 | head -1
wrk2 --help 2>&1 | grep -- -R                          # must list -R, --rate
```

The harness looks for `wrk2` first, then `wrk`; installing the fork as `wrk2`
guarantees it is picked over any system `wrk`.

### 2.4 Already present

`pidstat` is not required (the harness samples `/proc/PID/stat` directly); `curl`
and `perl` (with `JSON::PP`) are assumed present, as the rest of the test suite
already needs them.

---

## 3. Running

All commands run from the repo root. `HEAVYBAG_ROOT` defaults to the checkout; set
it only if you relocated the tree.

### 3.1 Smoke (the ctest gate)

~10 s/scenario. The pass/fail is the **S3 counter invariant**; S1/S2 just run
through to prove the pipeline.

```sh
bash modules/ngx_http_heavybag/tests/run-stress-tests.sh --quick
#   or via CTest:
ctest --test-dir build -R heavybag_stress --output-on-failure
```

### 3.2 Full reference run

Runs S1 → S2 → S3 → S4 at full workload. This is the run that fills the ledger
tables.

```sh
bash modules/ngx_http_heavybag/tests/run-stress-tests.sh
```

### 3.3 Soak (opt-in, long)

A bare `ctest` SKIPs soak instantly; run it deliberately:

```sh
HB_STRESS_SOAK_OPT_IN=1 HB_SOAK_DUR=3600 \
  bash modules/ngx_http_heavybag/tests/run-stress-tests.sh --soak
#   or:
HB_STRESS_SOAK_OPT_IN=1 HB_SOAK_DUR=3600 ctest --test-dir build -R heavybag_soak
```

---

## 4. Tuning the load (env parameters)

Nginx-side knobs are **baked** in `tests/stress/heavybag-stress-test.conf` for
reproducibility; you tune only the load side via env. Every value is recorded
into each run's `params.env` and `summary.json`.

| Env | Default | Meaning |
|---|---|---|
| `HB_REQS` | 20000 | requests per h2load invocation (`--quick` forces 2000) |
| `HB_CONN` | 50 | concurrent connections / clients (`--quick` forces 20) |
| `HB_STREAMS` | 10 | h2load max concurrent streams per connection (`-m`) |
| `HB_THREADS` | 4 | wrk2 threads (S2) |
| `HB_DUR` | 20 | wrk2 duration seconds (S2); `--quick` forces 5 |
| `HB_RATE` | 2000 | top of the wrk2 arrival-rate sweep (S2) |
| `HB_WORKERS` | 2 | `worker_processes` override (the conf bakes ≥2; raise to host core count for perf) |
| `HB_SOAK_DUR` | 3600 | soak duration seconds (S5) |
| `HB_STRESS_SOAK_OPT_IN` | 0 | must be `1` to actually run soak |
| `HB_STRESS_CURL_FALLBACK` | 0 | **dev only**: drive load with curl when h2load is absent (see §7) |

Example — a heavier HTTP perf run pinned to 8 workers:

```sh
HB_WORKERS=8 HB_REQS=200000 HB_CONN=200 \
  bash modules/ngx_http_heavybag/tests/run-stress-tests.sh
```

---

## 5. Reading the results

Each scenario writes a timestamped directory under
`tests/corpus/.stress/<scenario>-<YYYYmmdd-HHMMSS>/` (gitignored):

| File | Contents |
|---|---|
| `params.env` | every load parameter for this run |
| `summary.json` | machine header (CPU/kernel/cores/workers) + tool versions + key metrics + `invariant_pass` |
| `counter-delta.json` | `/waf/stat/plain` before/after delta (the ground truth) |
| `*.out` | raw h2load / wrk2 stdout |
| `*.log` / `*.hdr` | h2load per-request latency log → parsed HDR percentile table (µs) |
| `cpu-rss.csv` | S4 CPU jiffies + RSS pages per worker, 1 Hz (header carries `CLK_TCK`/`PAGESIZE`) |
| `rss-fd-trend.csv` | S5 RSS/fd time series + the least-squares slope verdict |

**The reproducible metric is the ratio, not the absolute.** Absolute req/s is
machine-specific; compare the **`overhead_ratio`** (enforce ÷ baseline) in S1 and
the **measured-vs-theoretical share** in S2. Always cite the `summary.json`
machine header so cross-host numbers stay comparable.

### The S3 gate

PASS means, on the counter delta around the concurrent mixed-load window:

```
HTTP:   Δhttp_requests_total      == Δhttp_allowed   + Σ Δhttp_blocked[reason]
STREAM: Δstream_connections_total == Δstream_allowed + Σ Δstream_denied[reason]
MAIL:   Auth-Status shows deny for a blocklisted Client-IP and OK for an allowed one
        (wire-only — the mail head moves no status counter)
plus:   Δhttp_allowlist_hits ≤ Δhttp_allowed, and no counter delta is negative
```

Any mismatch is a real bug (a lost counter or a lock-free race), and the harness
exits 1. The `would_block[*]` overlay, the `http_resp_*` / `http_scanner_path_*`
/ `http_flag_*` / `http_ua*` breakdowns, and all `waf off` traffic are excluded
by construction.

---

## 6. Reproducibility

- **Corpus.** `tests/corpus/stress-urls.txt` is committed and generated
  deterministically (top-N by volume + fixed benign cadence, no randomness).
  Regenerate and confirm it is byte-identical:
  ```sh
  perl modules/ngx_http_heavybag/tools/gen-stress-corpus.pl
  git diff --stat modules/ngx_http_heavybag/tests/corpus/stress-urls.txt   # expect no change
  ```
  Knobs: `--top-n N` (default 100), `--benign-every K` (default 5).
- **Tool versions.** Pinned in `tools/stress/versions.env`. The harness WARNs on
  drift and records expected+found in `summary.json`; it never fails on version.
- **Config.** All nginx-side parameters are fixed in the stress conf; only the
  load-side env knobs vary, and they are all recorded per run.

---

## 7. Verifying the pipeline without the load tools (dev)

If h2load is not installed you can still exercise the full pipeline and the S3
invariants using a curl-driven fallback — useful for validating changes to the
harness itself:

```sh
HB_STRESS_CURL_FALLBACK=1 \
  bash modules/ngx_http_heavybag/tests/run-stress-tests.sh --quick
```

This drives load with curl instead of h2load (S1/S2/S4 numbers will be empty, but
S3 counter invariants + mail wire verdicts are fully checked). The `heavybag_stress`
ctest deliberately does **not** set this, so without h2load the ctest SKIPs rather
than silently using curl.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Whole run SKIPs (`h2load absent`) | install `nghttp2-client`, or use the curl fallback (§7) |
| S2 SKIPs (`wrk2 absent`) even though `wrk` is installed | that `wrk` has no `-R`; install Gil Tene's **wrk2** (§2.3) |
| S1 H3 dimension SKIPs | distro h2load lacks QUIC; build nghttp2 `--enable-http3` (§2.2) — optional |
| geo dimension SKIPs | `geodb/location.db` absent; it is a downloaded artifact, not committed |
| `nginx -t` warns about stream rate limiting disabled | `waf_rate_zone` not resolving in `http{}` — should not happen with the shipped conf; check you did not strip the zone in a render |
| Port already in use | a previous run's nginx is still up: `sandbox/sbin/nginx -p sandbox/ -c <rendered-conf> -s stop`, or `pkill -f nginx-stress` |
| S3 gate FAILS | a genuine counter/lock-free bug — inspect `counter-delta.json` and `invariants.txt` in the run dir; this is the campaign doing its job |

---

## 9. Recording a campaign run

After a reference run, copy the headline numbers from the per-scenario
`summary.json` files into the result tables in
[`docs/stress-campaign.md`](stress-campaign.md), together with the machine header
from any `summary.json`. The `.stress/` artifact dirs themselves are gitignored
— the ledger is the durable record.

---

## 10. Live-edge testing (a running deployment)

The S1–S5 harness above spins up its own sandbox nginx. To characterise a
**live** edge instead (real box, real network path), use the manual runners in
[`modules/ngx_http_heavybag/tests/live/`](../modules/ngx_http_heavybag/tests/live/)
— see that directory's `README.md`:

- **`live-slo-path.sh`** — vegeta constant-arrival SLO sweep from a gen host
  against a remote URL, sampling the target's CPU over SSH. Finds the max req/s
  where `p99 ≤ TARGET_MS`. The measured tail includes the network path.
- **`live-slo-local.sh`** — run on the box against `127.0.0.1` to remove path
  jitter and read the WAF's true latency; separates nginx CPU from the
  co-located generator's.

These are **not** CTest-wired (they need a target + SSH). The most recent live
results, methodology, and caveats — including why loopback/internal sources are
allowlist-bypassed and why `rate_overflow` is not reproducible from a single live
vantage — are in [`docs/stress-campaign.md`](stress-campaign.md) under *Live
production run*.
