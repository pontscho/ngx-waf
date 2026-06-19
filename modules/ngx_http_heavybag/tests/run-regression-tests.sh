#!/usr/bin/env bash
#
# run-regression-tests.sh - WAF enforce-mode committed-fixture regression net
#
# Replays the FROZEN, committed fixture (corpus/regression-vectors.jsonl +
# regression-headers.jsonl) against the enforce vhosts and asserts that every
# vector still yields its frozen verdict (threat-model docs/threat-model.md §6 C;
# plan docs/honeypot-C-plan.md). This is the live-fire complement to the 6 unit
# + 131 stat-integration tests: if a future scanners.list / args.list / header
# list edit stops matching /.env or wp-login.php, or changes its action
# (404<->403<->444), THIS harness fails with the exact divergence.
#
# Unlike work-stream B (detect mode, would_block counters), C asserts the REAL
# HTTP status via replay-client --enforce: 404 / 403 / 444 (444 = NGX_HTTP_CLOSE,
# observed as a byte-0 connection close). For non-444 vectors the (reason,status)
# tuple is asserted (the enforce vhost emits X-WAF-Reason); for 444 the reason is
# unobservable on the wire so the assert is status-only and the reason stands
# frozen from generation time.
#
# Standalone entrypoint (like run-stat-tests.sh / run-replay-tests.sh); it does
# NOT modify run-stat-tests.sh. There is no CI; tests are run manually.
#
# Usage:  bash run-regression-tests.sh
# Exit 0 = FP gate passed AND every fixture vector frozen-matched.

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
TESTS=$ROOT/modules/ngx_http_heavybag/tests
CONF=$TESTS/heavybag-regression-test.conf
# portability: render the committed conf with the active ROOT so its baked absolute
# paths follow a relocated checkout (the sed is a no-op on the default root).
HB_RENDER_DIR=$ROOT/modules/ngx_http_heavybag/tests/corpus/.render
mkdir -p "$HB_RENDER_DIR"
hb_render() { local d="$HB_RENDER_DIR/$(basename "$1")"; sed "s#/mnt/nvme/imaginarium/openresty#$ROOT#g" "$1" > "$d"; printf '%s' "$d"; }
CONF=$(hb_render "$CONF")
CORPUS=$TESTS/corpus
CLIENT="perl $TESTS/replay-client.pl"
STAT=http://127.0.0.1:28300/waf/stat
VEC_FIXTURE=$CORPUS/regression-vectors.jsonl
HDR_FIXTURE=$CORPUS/regression-headers.jsonl
TMP=$CORPUS/.freeze-tmp           # gitignored scratch (shared with the freeze step)
mkdir -p "$TMP"

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

cleanup() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
    local pid_file="$SBX/logs/nginx-regression.pid"
    [ -f "$pid_file" ] && kill "$(cat "$pid_file")" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== WAF enforce-mode regression harness ==="
echo

# --- fixtures present? ------------------------------------------------------
[ -s "$VEC_FIXTURE" ] || { echo "missing/empty $VEC_FIXTURE (run freeze-regression-fixture.pl first)"; exit 2; }
[ -s "$HDR_FIXTURE" ] || { echo "missing/empty $HDR_FIXTURE (run freeze-regression-fixture.pl first)"; exit 2; }

# --- nginx -t + [security #4] zero-proxy_pass invariant ---------------------
"$NGINX" -p "$SBX/" -c "$CONF" -t || { echo "CONFIG TEST FAILED"; exit 2; }
# match the DIRECTIVE only (line-leading), never the word inside a comment.
np=$(grep -cE '^[[:space:]]*proxy_pass' "$CONF")
[ "$np" -eq 0 ] && ok "conf has zero proxy_pass directives (no off-box egress)" \
    || bad "conf has $np proxy_pass directive(s) -- egress risk"

# --- start ------------------------------------------------------------------
cleanup 2>/dev/null; sleep 1
"$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
sleep 1
curl -sf "$STAT/plain" >/dev/null || { echo "stat endpoint not reachable"; exit 2; }
ok "regression-nginx up (13 vhosts, stat reachable)"

# --- compare.pl: join a dim's fixture subset with its enforce result --------
# Reads @ARGV: <fixture-subset> <result> <dim> <joinkey>. Prints DIVERGE lines
# (first 20) to STDERR and a single machine line "STATS <total> <match>
# <mismatch>" to STDOUT. 444 vectors are asserted status-only; all others on the
# (reason,status) tuple. Catches BOTH regression shapes: "stopped matching"
# (got reason=none status=200) and "action changed" (expected 404 got 403).
cat > "$TMP/compare.pl" <<'PERL'
use strict; use warnings; use JSON::PP;
my ($subf, $resf, $dim, $key) = @ARGV;
my $j = JSON::PP->new->utf8;
my %exp;
open my $S, '<', $subf or die "compare: cannot read $subf: $!\n";
binmode $S;
while (<$S>) { next unless /\S/; my $d = eval { $j->decode($_) } or next;
    $exp{ $d->{$key} } = [ $d->{expected_reason} // 'none', ($d->{expected_status} // -1) + 0 ]; }
close $S;
my %got;
open my $R, '<', $resf or die "compare: cannot read $resf: $!\n";
binmode $R;
# replay-client names its join field literally 'key' (= uri / raw header value),
# whereas the fixture names it 'uri' / 'value' ($key). Read each from its own
# field so the join lines up.
while (<$R>) { next unless /\S/; my $d = eval { $j->decode($_) } or next;
    $got{ $d->{key} } = [ $d->{reason} // 'MISSING', ($d->{status} // -1) + 0 ]; }
close $R;
my ($total, $match, $mismatch, $shown) = (0, 0, 0, 0);
for my $k (sort keys %exp) {
    $total++;
    my ($er, $es) = @{ $exp{$k} };
    my $g = $got{$k};
    my ($gr, $gs) = $g ? @$g : ('<none>', '<no-result>');
    my $is_ok;
    if ($es == 444) { $is_ok = (defined $g && "$gs" eq '444'); }      # 444: status only
    else            { $is_ok = (defined $g && "$gs" eq "$es" && $gr eq $er); }
    if ($is_ok) { $match++; next; }
    $mismatch++;
    if ($shown < 20) { $shown++;
        printf STDERR "    DIVERGE [%s] key='%s' expected=(%s,%s) got=(%s,%s)\n",
            $dim, $k, $er, $es, $gr, $gs; }
}
print "STATS $total $match $mismatch\n";
PERL

# --- FP gate ----------------------------------------------------------------
# Benign baseline against the path ENFORCE vhost (28302): the WAF must DECLINE
# every benign path -> served static (reason=none, status 200 or static-404),
# never a WAF block (reason!=none or status 403/444). reason=none (X-WAF-Reason
# on the enforce vhost) is what distinguishes a static-404 from a WAF-404.
echo
echo "--- FP gate ---"
FP_OUT=$TMP/fp-baseline.out
$CLIENT --kind baseline --port 28302 --enforce --out "$FP_OUT" 2>/dev/null
fp_bad=$(perl -MJSON::PP -e '
    my $j = JSON::PP->new->utf8; my $bad = 0;
    while (<STDIN>) { next unless /\S/; my $d = eval { $j->decode($_) } or next;
        my $r = $d->{reason} // "MISSING"; my $s = ($d->{status} // -1) + 0;
        if ($r ne "none" || ($s != 200 && $s != 404)) { $bad++;
            print STDERR "    FP: key=".($d->{key}//"?")." reason=$r status=$s\n"; } }
    print $bad;' < "$FP_OUT")
if [ "${fp_bad:-1}" -eq 0 ]; then
    ok "FP gate: benign baseline not blocked (reason=none, status 200/404)"
else
    bad "FP gate: $fp_bad benign baseline vector(s) blocked"
fi

# --- enforce replay vs committed fixture ------------------------------------
echo
echo "--- Enforce replay vs committed fixture ---"

# run_dim_assert <dim> <kind> <enforce-port> <header|""> <fixture-file> <joinkey>
run_dim_assert() {
    local dim="$1" kind="$2" port="$3" header="$4" fixture="$5" joinkey="$6"
    local sub="$TMP/fixture-$dim.jsonl"
    local res="$TMP/result-$dim.jsonl"

    # extract this dimension's fixture lines (the fixture interleaves dims).
    perl -MJSON::PP -e '
        my $j = JSON::PP->new->utf8; my $want = shift;
        while (<STDIN>) { next unless /\S/; my $d = eval { $j->decode($_) } or next;
            print if ($d->{dim} // "") eq $want; }
    ' "$dim" < "$fixture" > "$sub"

    local n; n=$(wc -l < "$sub")
    if [ "$n" -eq 0 ]; then
        echo "  NOTE: $dim has 0 fixture vectors (nothing to assert)"
        return
    fi

    # replay in ENFORCE mode. replay-client reads method/uri/count/classes
    # (path) or value/count/src (header) and IGNORES the extra fixture fields
    # (dim/expected_*), so the committed fixture is a valid --in feed as-is.
    local hdr_arg=""
    [ -n "$header" ] && hdr_arg="--header $header"
    # shellcheck disable=SC2086
    $CLIENT --kind "$kind" --port "$port" --enforce --in "$sub" --out "$res" $hdr_arg 2>/dev/null

    # join + compare (divergences to STDERR, STATS line to STDOUT).
    local stats; stats=$(perl "$TMP/compare.pl" "$sub" "$res" "$dim" "$joinkey")
    local _tag total matched mismatched
    read -r _tag total matched mismatched <<<"$stats"
    if [ "${mismatched:-1}" -eq 0 ]; then
        ok "$dim: $matched/$total frozen-match"
    else
        bad "$dim: $mismatched/$total diverged (matched=$matched)"
    fi
}

#              dim      kind    port   header       fixture         joinkey
run_dim_assert path     path    28302  ""           "$VEC_FIXTURE"  uri
run_dim_assert args     path    28304  ""           "$VEC_FIXTURE"  uri
run_dim_assert ua       header  28306  User-Agent   "$HDR_FIXTURE"  value
run_dim_assert referer  header  28308  Referer      "$HDR_FIXTURE"  value
run_dim_assert cookie   header  28310  Cookie       "$HDR_FIXTURE"  value
run_dim_assert fakebot  header  28312  User-Agent   "$HDR_FIXTURE"  value

echo
echo "==================  RESULT: $pass passed, $fail failed  =================="
[ "$fail" -eq 0 ]
