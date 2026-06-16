#!/usr/bin/env bash
# run-replay-tests.sh — WAF detect-mode replay harness
# Orchestrates nginx + replay-client.pl + report generation.
# Exit 0 iff FP gate passes; coverage is reported, never asserted.
#
# Usage:  [LIMIT=200] bash run-replay-tests.sh
#   LIMIT=0 (default) means unlimited (full sweep).

set -u

ROOT=/mnt/nvme/imaginarium/openresty
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
CONF=$ROOT/modules/ngx_http_heavybag/tests/heavybag-replay-test.conf
CORPUS=$ROOT/modules/ngx_http_heavybag/tests/corpus
export CORPUS
STAT=http://127.0.0.1:28190/waf/stat
LIMIT=${LIMIT:-0}

CLIENT="perl $ROOT/modules/ngx_http_heavybag/tests/replay-client.pl"

PORT_PATH=28182
PORT_ARGS=28183
PORT_UA=28184
PORT_REFERER=28185
PORT_FAKEBOT=28186
PORT_COOKIE=28187

# ---------------------------------------------------------------------------
# Cleanup / trap
# ---------------------------------------------------------------------------
cleanup() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
    local pid_file="$SBX/logs/nginx-replay.pid"
    if [ -f "$pid_file" ]; then
        kill "$(cat "$pid_file")" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helper: read a scalar counter from the plain format
# ---------------------------------------------------------------------------
getcnt() {
    curl -s "$STAT/plain" | awk -v k="$1" '$1==k{print $2; f=1} END{if(!f)print 0}'
}

# ---------------------------------------------------------------------------
# Config test + start
# ---------------------------------------------------------------------------
echo "=== WAF detect-mode replay harness ==="
echo "LIMIT=$LIMIT  (0 = unlimited)"
echo

"$NGINX" -p "$SBX/" -c "$CONF" -t || { echo "CONFIG TEST FAILED"; exit 2; }

# Stop any stale instance
"$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
local_pid="$SBX/logs/nginx-replay.pid"
[ -f "$local_pid" ] && kill "$(cat "$local_pid")" 2>/dev/null || true
sleep 1

"$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
sleep 1

# Verify nginx is up
curl -sf "$STAT/plain" >/dev/null || { echo "stat endpoint not reachable"; exit 2; }

# ---------------------------------------------------------------------------
# FP GATE
# ---------------------------------------------------------------------------
echo "--- FP gate ---"

# Snapshot ALL would_block counters before baseline
declare -A fp_before fp_after
WOULD_BLOCK_KEYS=(
    http_would_block_scanner_ua
    http_would_block_empty_ua
    http_would_block_scanner_path
    http_would_block_asn
    http_would_block_method
    http_would_block_args
    http_would_block_cookie
    http_would_block_referer
    http_would_block_fake_bot
    http_would_block_rate_limit
    http_would_block_blocklist
    http_would_block_geo
    http_would_block_geo_whitelist
    http_would_block_flag
    http_would_block_allowlist
)
for k in "${WOULD_BLOCK_KEYS[@]}"; do
    fp_before[$k]=$(getcnt "$k")
done

FP_TMP=$(mktemp /tmp/replay-fp-baseline.XXXXXX.jsonl)

# Run baseline on path port (28182) and args port (28183)
$CLIENT --kind baseline --port "$PORT_PATH" --out "$FP_TMP"
$CLIENT --kind baseline --port "$PORT_ARGS" --out /dev/null

# Snapshot after
for k in "${WOULD_BLOCK_KEYS[@]}"; do
    fp_after[$k]=$(getcnt "$k")
done

# Evaluate FP gate
fp_pass=1
fp_details=""

# Check every result line from baseline has reason "none"
while IFS= read -r line; do
    reason=$(echo "$line" | perl -MJSON::PP -e '
        my $d = JSON::PP->new->utf8->decode(do{local$/;<STDIN>});
        print $d->{reason}//"MISSING";
    ')
    key=$(echo "$line" | perl -MJSON::PP -e '
        my $d = JSON::PP->new->utf8->decode(do{local$/;<STDIN>});
        print $d->{key}//"?";
    ')
    if [ "$reason" != "none" ]; then
        fp_pass=0
        fp_details="${fp_details}  FP: baseline key='${key}' reason='${reason}'\n"
    fi
done < "$FP_TMP"

# Check all would_block deltas are 0
for k in "${WOULD_BLOCK_KEYS[@]}"; do
    delta=$(( fp_after[$k] - fp_before[$k] ))
    if [ "$delta" -ne 0 ]; then
        fp_pass=0
        fp_details="${fp_details}  FP: counter $k delta=$delta (want 0)\n"
    fi
done

rm -f "$FP_TMP"

# Write FP report
FP_REPORT="$CORPUS/replay-fp-report.txt"
if [ "$fp_pass" -eq 1 ]; then
    printf "FP gate: PASS\nAll baseline paths returned reason=none; all would_block counter deltas=0.\n" > "$FP_REPORT"
    echo "FP gate: PASS"
else
    {
        printf "FP gate: FAIL\n"
        printf "Offending entries:\n"
        printf "%b" "$fp_details"
    } > "$FP_REPORT"
    echo "FP gate: FAIL"
    printf "%b" "$fp_details"
fi

# ---------------------------------------------------------------------------
# MAIN REPLAY — always run regardless of FP gate
# ---------------------------------------------------------------------------
echo
echo "--- Main replay ---"

# Helper: run one replay dimension
# run_dim NAME KIND PORT IN_FILE OUT_FILE COUNTER_KEY [HEADER]
run_dim() {
    local name="$1"
    local kind="$2"
    local port="$3"
    local in_file="$4"
    local out_file="$5"
    local ckey="$6"
    local hdr="${7:-}"

    local before after delta
    before=$(getcnt "$ckey")

    local limit_arg=""
    [ "$LIMIT" -gt 0 ] && limit_arg="--limit $LIMIT"

    local header_arg=""
    [ -n "$hdr" ] && header_arg="--header $hdr"

    # shellcheck disable=SC2086
    $CLIENT \
        --kind  "$kind" \
        --port  "$port" \
        --in    "$in_file" \
        --out   "$out_file" \
        $limit_arg \
        $header_arg \
        2>/tmp/replay-stderr-${name}.txt

    after=$(getcnt "$ckey")
    delta=$(( after - before ))

    # Count result lines with reason != "none"
    local covered=0
    if [ -f "$out_file" ]; then
        covered=$(perl -MJSON::PP -e '
            my $j = JSON::PP->new->utf8;
            my $c = 0;
            while (<STDIN>) {
                chomp;
                next unless /\S/;
                my $d = eval { $j->decode($_) } or next;
                $c++ if defined $d->{reason} && $d->{reason} ne "none";
            }
            print $c;
        ' < "$out_file")
    fi

    local total=0
    if [ -f "$out_file" ]; then
        total=$(wc -l < "$out_file")
    fi

    echo "  $name: sent=$total covered(reason!=none)=$covered  counter_delta=$delta"
    if [ "$covered" -ne "$delta" ]; then
        echo "    NOTE: covered($covered) != counter_delta($delta) — possible cross-dimension hit"
    fi

    # store for summary
    eval "DIM_COVERED_${name}=$covered"
    eval "DIM_TOTAL_${name}=$total"
}

# path dimension (vs http_would_block_scanner_path)
run_dim "path"    path   "$PORT_PATH"    "$CORPUS/replay-vectors.jsonl"        "$CORPUS/replay-path-results.jsonl"    http_would_block_scanner_path

# args dimension (vs http_would_block_args)
run_dim "args"    path   "$PORT_ARGS"    "$CORPUS/replay-vectors.jsonl"        "$CORPUS/replay-args-results.jsonl"    http_would_block_args

# ua dimension (vs http_would_block_scanner_ua + http_would_block_empty_ua)
# We track scanner_ua as the primary key; empty_ua may also move
run_dim "ua"      header "$PORT_UA"      "$CORPUS/fixtures/ua.jsonl"           "$CORPUS/replay-ua-results.jsonl"      http_would_block_scanner_ua User-Agent

# referer dimension (vs http_would_block_referer)
run_dim "referer" header "$PORT_REFERER" "$CORPUS/fixtures/referer.jsonl"      "$CORPUS/replay-referer-results.jsonl" http_would_block_referer    Referer

# cookie dimension (vs http_would_block_cookie)
run_dim "cookie"  header "$PORT_COOKIE"  "$CORPUS/fixtures/cookie.jsonl"       "$CORPUS/replay-cookie-results.jsonl"  http_would_block_cookie     Cookie

# fakebot dimension (vs http_would_block_fake_bot)
run_dim "fakebot" header "$PORT_FAKEBOT" "$CORPUS/fixtures/fakebot.jsonl"      "$CORPUS/replay-fakebot-results.jsonl" http_would_block_fake_bot   User-Agent

# ---------------------------------------------------------------------------
# REPORTS
# ---------------------------------------------------------------------------
echo
echo "--- Generating reports ---"

# --- replay-coverage-report.txt ---
COV_REPORT="$CORPUS/replay-coverage-report.txt"

perl -MJSON::PP -e '
use strict;
use warnings;

my $json = JSON::PP->new->utf8;

# (a) Path-class coverage from replay-path-results.jsonl
my @CLASSES = qw(
    php wordpress secret_vcs router_iot legacy_ext phpadmin
    backup appliance webmail uncatalogued
);

my %vol;      # class -> sum of count
my %covered;  # class -> sum of count where reason != none

my $path_file = $ENV{CORPUS} . "/replay-path-results.jsonl";
if (open my $fh, "<", $path_file) {
    while (<$fh>) {
        chomp; next unless /\S/;
        my $d = eval { $json->decode($_) } or next;
        my $count   = $d->{count}  || 1;
        my $reason  = $d->{reason} // "none";
        my $classes = $d->{classes} || [];
        for my $cls (@$classes) {
            $vol{$cls}     += $count;
            $covered{$cls} += $count if $reason ne "none";
        }
    }
    close $fh;
}

print "=== Path-class coverage (from replay-path-results.jsonl) ===\n";
printf "%-20s %10s %10s %10s\n", "class", "volume", "covered", "coverage%";
printf "%-20s %10s %10s %10s\n", "-" x 20, "-" x 10, "-" x 10, "-" x 10;
for my $cls (@CLASSES) {
    my $v = $vol{$cls}     || 0;
    my $c = $covered{$cls} || 0;
    my $pct = $v > 0 ? sprintf("%.1f", 100.0 * $c / $v) : "N/A";
    printf "%-20s %10d %10d %10s\n", $cls, $v, $c, $pct;
}
print "\n";

# (b) Per header-dimension coverage
my @DIMS = (
    { name => "ua",      file => "replay-ua-results.jsonl"      },
    { name => "referer", file => "replay-referer-results.jsonl"  },
    { name => "cookie",  file => "replay-cookie-results.jsonl"   },
    { name => "fakebot", file => "replay-fakebot-results.jsonl"  },
);

print "=== Header-dimension coverage ===\n";
for my $dim (@DIMS) {
    my $file = $ENV{CORPUS} . "/" . $dim->{file};
    my (%src_total, %src_covered);
    my ($total, $cov) = (0, 0);
    if (open my $fh, "<", $file) {
        while (<$fh>) {
            chomp; next unless /\S/;
            my $d = eval { $json->decode($_) } or next;
            my $reason = $d->{reason} // "none";
            my $src    = $d->{src}    // "unknown";
            $total++;
            $src_total{$src}++;
            if ($reason ne "none") {
                $cov++;
                $src_covered{$src}++;
            }
        }
        close $fh;
    }
    my $pct = $total > 0 ? sprintf("%.1f", 100.0 * $cov / $total) : "N/A";
    printf "  %-10s total=%d covered=%d coverage=%s%%\n",
        $dim->{name}, $total, $cov, $pct;
    for my $src (sort keys %src_total) {
        my $st = $src_total{$src}  || 0;
        my $sc = $src_covered{$src}|| 0;
        my $sp = $st > 0 ? sprintf("%.1f", 100.0 * $sc / $st) : "N/A";
        printf "    src=%-20s total=%d covered=%d coverage=%s%%\n",
            $src, $st, $sc, $sp;
    }
}
' > "$COV_REPORT"

echo "  Wrote $COV_REPORT"

# --- replay-uncovered.jsonl ---
UNCOV="$CORPUS/replay-uncovered.jsonl"
perl -MJSON::PP -e '
use strict;
use warnings;
my $json = JSON::PP->new->utf8;
my @rows;
my $path_file = $ENV{CORPUS} . "/replay-path-results.jsonl";
if (open my $fh, "<", $path_file) {
    while (<$fh>) {
        chomp; next unless /\S/;
        my $d = eval { $json->decode($_) } or next;
        next if ($d->{reason} // "none") ne "none";
        push @rows, {
            count   => $d->{count}   // 1,
            uri     => $d->{key}     // "",
            classes => $d->{classes} || [],
        };
    }
    close $fh;
}
# sort by count desc
@rows = sort { $b->{count} <=> $a->{count} } @rows;
my $total = scalar @rows;
my $cap   = 2000;
if ($total > $cap) {
    warn "replay-uncovered: $total uncovered paths; capped to top $cap\n";
    @rows = @rows[0 .. $cap-1];
}
for my $r (@rows) {
    print $json->encode($r), "\n";
}
' > "$UNCOV" 2>&1

UNCOV_LINES=$(wc -l < "$UNCOV")
echo "  Wrote $UNCOV  ($UNCOV_LINES entries)"

# ---------------------------------------------------------------------------
# STDOUT SUMMARY
# ---------------------------------------------------------------------------
echo
echo "======================================================================"
echo "SUMMARY"
echo "======================================================================"
echo
echo "FP gate:   $(grep '^FP gate' "$FP_REPORT" | head -1)"
echo
echo "Per-dimension covered/total:"
for dim in path args ua referer cookie fakebot; do
    cov_var="DIM_COVERED_${dim}"
    tot_var="DIM_TOTAL_${dim}"
    cov="${!cov_var:-0}"
    tot="${!tot_var:-0}"
    pct="N/A"
    [ "$tot" -gt 0 ] && pct=$(perl -e "printf '%.1f', 100.0*$cov/$tot")
    printf "  %-10s %d / %d  (%.0s%s%%)\n" "$dim" "$cov" "$tot" "" "$pct"
done
echo
echo "Per-class coverage (path):"
# Extract from the report
grep -A 20 "Path-class coverage" "$COV_REPORT" | grep -v "^=" | grep -v "^-" | grep -v "^class" | grep '\S'
echo
echo "Reports written:"
echo "  $FP_REPORT"
echo "  $COV_REPORT"
echo "  $UNCOV"
echo "======================================================================"

# ---------------------------------------------------------------------------
# Exit
# ---------------------------------------------------------------------------
[ "$fp_pass" -eq 1 ]
