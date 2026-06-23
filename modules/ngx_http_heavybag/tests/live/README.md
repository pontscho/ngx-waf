# Live-edge load runners (`tests/live/`)

Ad-hoc tooling for load-testing a **running** heavybag edge (a real deployment),
as opposed to the sandbox `run-stress-tests.sh` harness which spins up its own
nginx. Use these to characterise capacity / latency / WAF overhead against a live
box. They are **not** wired into CTest (they need a target host and SSH access)
and are intentionally manual.

Both use **vegeta** (open-loop constant arrival — the only common tool that
reports true latency percentiles) and sample server CPU with `mpstat`/`pidstat`.

## `live-slo-path.sh` — over-the-network SLO sweep

Generates load from the gen host against a remote target URL and samples the
target's CPU **over SSH** mid-load. Finds the max req/s where `p99 <= TARGET_MS`.

```sh
# defaults: target=https://example.com/  ssh=v  p99<=25ms
RATES="200 400 800 1000 2000 4000" TARGET_MS=25 LABEL=enforce \
  bash live-slo-path.sh

# point elsewhere
SSH_HOST=edge1 TARGET="https://example.com/" RATES="500 1000 2000" \
  bash live-slo-path.sh
```

Env knobs: `SSH_HOST` (SSH alias for CPU sampling), `TARGET`, `UA`, `RATES`,
`DUR`, `SETTLE`, `SAMP` (steady-state CPU sample seconds), `TARGET_MS`, `LABEL`.

Caveat: the measured p99 / SLO ceiling includes the **network path** — over a
jittery or bandwidth-limited link the tail is the path's, not the server's.
For the server's true latency, run the loopback variant on the box.

## `live-slo-local.sh` — on-box loopback sweep

Run **on the target box** (e.g. `ssh edge bash -s < live-slo-local.sh`). Hits
`127.0.0.1` (no path jitter) and separates nginx CPU from the co-located
generator's CPU.

```sh
# copy vegeta to the box first (static Go binary, no sudo):
scp ~/.local/bin/vegeta edge:/tmp/vegeta

ssh edge "RATES='500 1000 2000' DUR=15 LABEL=enforce-local bash -s" \
  < live-slo-local.sh
```

Env knobs: `RATES`, `DUR`, `SETTLE`, `SAMP`, `TARGET_MS`, `HOSTH` (Host header,
default `example.com`), `UA`, `LABEL`. Assumes `/tmp/vegeta` on the box.

**Two confounds to respect:**
- The generator runs on the same cores as nginx → valid only up to ~⅓ of the
  box's capacity before vegeta steals cores (watch `vegeta-cpu` in the output).
- If the loopback peer (`127.0.0.1`) or the box's own subnet is in
  `waf_allowlist`, loopback traffic is **fully bypassed** (no WAF, no rate
  limit) — you will measure the allowlist short-circuit, not the WAF. Test the
  WAF/rate path from a **non-allowlisted** source (i.e. the public path).

## What can / can't be measured live

| Goal | How |
|---|---|
| Capacity, WAF CPU overhead | `live-slo-path.sh`, rate disabled, `waf off` vs `enforce` legs |
| True serving latency (p50/p99) | `live-slo-local.sh` loopback, low rate |
| Rate-limiter precision (429-share) | `live-slo-path.sh` from a non-allowlisted source |
| `rate_overflow` zone saturation | **not** feasible from one source (needs huge IP cardinality or a tiny zone) → use the sandbox harness |

See [`docs/stress-testing.md`](../../../../docs/stress-testing.md) §10 and the
live-run results in [`docs/stress-campaign.md`](../../../../docs/stress-campaign.md).
