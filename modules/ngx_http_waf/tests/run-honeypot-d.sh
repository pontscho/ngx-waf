#!/usr/bin/env bash
# run-honeypot-d.sh — Honeypot work-stream D: offline ASN/geo tuning from
# attacker IPs (docs/threat-model.md §6.D). End-to-end, read-only on the log:
#
#   1. build the standalone geolookup reader (reference/geolookup.c, libc-only)
#   2. extract the per-IP volume feed from the raw access log
#      (extract-replay-vectors.pl --ip-volume)
#   3. join volume × geo and emit the candidate report + paste-ready directives
#      (honeypot-d-report.pl)
#
# Pure analysis -> candidates for the partner to review and apply by hand.
# Writes NO list the WAF loads, changes no module .c, restarts no prod nginx.
#
# The per-IP feed and the report are IP-bearing -> gitignored, never committed.
# The committed corpus feeds (replay-vectors.jsonl + summary) are NOT touched:
# the extractor's standard outputs go to a throwaway scratch --outdir, while the
# IP feed lands at a fixed corpus path via --ip-out.
#
# Usage:
#   [ACCESS_LOG=...] [GEODB=...] [GEOLOOKUP=...] bash run-honeypot-d.sh [-- <report-args>]
#
# Env overrides:
#   ACCESS_LOG  raw edge access log         (default ngxlogs/access.log)
#   GEODB       IPFire location.db          (default geodb/location.db)
#   GEOLOOKUP   geolookup binary build path (default /tmp/geolookup)
# Extra args after `--` are forwarded to honeypot-d-report.pl (e.g. thresholds).

set -u

ROOT=/mnt/nvme/imaginarium/openresty
CORPUS=$ROOT/modules/ngx_http_waf/tests/corpus
TOOLS=$ROOT/modules/ngx_http_waf/tools
SRC=$ROOT/reference/geolookup.c

ACCESS_LOG=${ACCESS_LOG:-$ROOT/ngxlogs/access.log}
GEODB=${GEODB:-$ROOT/geodb/location.db}
GEOLOOKUP=${GEOLOOKUP:-/tmp/geolookup}

IP_FEED=$CORPUS/replay-ip-volume.jsonl
REPORT=$CORPUS/honeypot-d-report.md

# forward anything after `--` to the report driver (threshold tuning)
REPORT_ARGS=()
if [ "$#" -gt 0 ] && [ "$1" = "--" ]; then
    shift
    REPORT_ARGS=("$@")
fi

echo "=== Honeypot D — ASN/geo tuning (offline analysis) ==="
echo "access log : $ACCESS_LOG"
echo "geo db     : $GEODB"
echo "geolookup  : $GEOLOOKUP"
echo

[ -r "$ACCESS_LOG" ] || { echo "FATAL: access log not readable: $ACCESS_LOG"; exit 2; }
[ -r "$GEODB" ]      || { echo "FATAL: geo db not readable: $GEODB"; exit 2; }

# ---------------------------------------------------------------------------
# 1. build geolookup (manual build, not part of the module build)
# ---------------------------------------------------------------------------
echo "--- build geolookup ---"
cc -O2 -Wall -Wextra -o "$GEOLOOKUP" "$SRC" \
    || { echo "FATAL: geolookup build failed"; exit 2; }
echo "built: $GEOLOOKUP"
echo

# ---------------------------------------------------------------------------
# 2. per-IP volume feed (standard feeds -> scratch; IP feed -> corpus)
# ---------------------------------------------------------------------------
echo "--- extract per-IP volume feed ---"
SCRATCH=$(mktemp -d /tmp/honeypot-d.XXXXXX)
trap 'rm -rf "$SCRATCH"' EXIT
perl "$TOOLS/extract-replay-vectors.pl" \
    --in "$ACCESS_LOG" \
    --outdir "$SCRATCH" \
    --ip-volume \
    --ip-out "$IP_FEED" \
    || { echo "FATAL: extractor failed"; exit 2; }
echo

# ---------------------------------------------------------------------------
# 3. join volume × geo, emit report + paste-ready candidates
# ---------------------------------------------------------------------------
echo "--- generate report ---"
perl "$TOOLS/honeypot-d-report.pl" \
    --ip-volume "$IP_FEED" \
    --geodb     "$GEODB" \
    --geolookup "$GEOLOOKUP" \
    --out       "$REPORT" \
    "${REPORT_ARGS[@]+"${REPORT_ARGS[@]}"}" \
    || { echo "FATAL: report generation failed"; exit 2; }

echo
echo "======================================================================"
echo "report : $REPORT"
echo "feed   : $IP_FEED  (IP-bearing, gitignored)"
echo "review the candidates, then apply the surgical levers to the prod conf"
echo "by hand (out of band) — D applies nothing."
echo "======================================================================"
