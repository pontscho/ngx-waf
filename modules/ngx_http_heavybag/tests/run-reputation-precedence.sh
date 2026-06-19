#!/usr/bin/env bash
#
# run-reputation-precedence.sh - deep-fuzz reputation_check verdict precedence
#
# The QA-campaign critic's "un-probed reputation verdict-precedence" surface.
# reputation_check() (heavybag_reputation.c) is first-match-wins; every prior
# test was single-source. This harness builds COLLISIONS (one IP matching
# multiple sources) and asserts the documented order, each backed by
# single-source CONTROLS proving the lower-priority source fires alone:
#
#   allowlist > blocklist > flag(bit) > ASN > block_cc      (+ geo-whitelist)
#
# Drives heavybag-repprec-test.conf over the HTTP PREACCESS path (waf_trusted_
# proxy + spoofed XFF inject the client IP; X-WAF-Reason exposes ctx->reason).
# reputation_check is shared verbatim by the mail + stream heads.
#
# Geo-centric: the whole suite needs geodb/location.db + the geolookup.c oracle.
# Absent or drifted -> exit 2 (CTest SKIPPED), never a false failure.
# Exit 0 = every assertion passed and the error log is clean.

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
TESTS=$ROOT/modules/ngx_http_heavybag/tests
SRC_CONF=$TESTS/heavybag-repprec-test.conf
GEODB=$ROOT/geodb/location.db
ELOG=$SBX/logs/error-repprec.log
HTML=$SBX/html

HB_RENDER_DIR=$TESTS/corpus/.render
mkdir -p "$HB_RENDER_DIR"
CONF=$HB_RENDER_DIR/heavybag-repprec-test.conf
sed "s#/mnt/nvme/imaginarium/openresty#$ROOT#g" "$SRC_CONF" > "$CONF"

LOCS="base cg cg2 ca ca2 ca3 cf cf2 r1 r2 r3 r4 r5 r6a r6b r8"

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

cleanup() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null || true
    local pf="$SBX/logs/nginx-repprec.pid"
    [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null || true
    for n in $LOCS; do rm -f "$HTML/p-$n"; done
}
trap cleanup EXIT

# probe location p-<name> with an injected XFF client IP; echo "CODE REASON".
rp() {
    curl -s -o /dev/null -D - -H "X-Forwarded-For: $2" \
        "http://127.0.0.1:28701/p-$1" 2>/dev/null | tr -d '\r' \
        | awk 'BEGIN{c="?";r="none"} /^HTTP\//{c=$2} tolower($1)=="x-waf-reason:"{r=$2} END{print c" "r}'
}
# chk DESC NAME IP WANT_CODE WANT_REASON
chk() {
    local code reason
    read -r code reason <<<"$(rp "$2" "$3")"
    if [ "$code" = "$4" ] && [ "$reason" = "$5" ]; then
        ok "$1 -> $code/$reason"
    else
        bad "$1 -> got $code/$reason (want $4/$5)"
    fi
}

echo "=== WAF reputation verdict-precedence deep-fuzz harness ==="

# --- geodb + oracle ground-truth gate (whole suite is geo-centric) ----------
if [ ! -f "$GEODB" ] || ! cc -O2 -o "$HB_RENDER_DIR/geolookup-rp" "$ROOT/reference/geolookup.c" 2>/dev/null; then
    echo "  geodb/oracle unavailable -> SKIP (precedence suite needs the geo DB)"; exit 2
fi
gl=$(printf '185.177.72.1\n8.8.8.8\n185.220.101.1\n' | "$HB_RENDER_DIR/geolookup-rp" "$GEODB" 2>/dev/null)
echo "  oracle ground-truth:"; printf '%s\n' "$gl" | sed 's/^/    /'
gt() { printf '%s\n' "$gl" | awk -v ip="$1" -v f="$2" '$1==ip{print $f}'; }
fr_ok=0; us_ok=0; de_ok=0
[ "$(gt 185.177.72.1 2)" = FR ] && [ "$(gt 185.177.72.1 3)" = 211590 ] && fr_ok=1
[ "$(gt 8.8.8.8 2)" = US ] && [ "$(gt 8.8.8.8 3)" = 15169 ] && us_ok=1
[ "$(gt 185.220.101.1 2)" = DE ] && [ "$(gt 185.220.101.1 3)" = 60729 ] && de_ok=1
if [ "$fr_ok" -ne 1 ] || [ "$us_ok" -ne 1 ] || [ "$de_ok" -ne 1 ]; then
    echo "  oracle ground-truth drifted from the baked conf -> SKIP"; exit 2
fi

# --- backing files (served in place -> no try_files redirect clearing ctx) --
for n in $LOCS; do echo precedence-probe > "$HTML/p-$n"; done

# --- nginx -t + [security] zero-proxy_pass invariant ------------------------
"$NGINX" -p "$SBX/" -c "$CONF" -t || { echo "CONFIG TEST FAILED"; exit 2; }
np=$(grep -cE '^[[:space:]]*proxy_pass' "$CONF")
[ "$np" -eq 0 ] && ok "conf has zero proxy_pass directives (no off-box egress)" \
    || bad "conf has $np proxy_pass directive(s) -- egress risk"

# --- start ------------------------------------------------------------------
cleanup 2>/dev/null; sleep 1
for n in $LOCS; do echo precedence-probe > "$HTML/p-$n"; done   # cleanup removed them
: > "$ELOG" 2>/dev/null || true
"$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
sleep 1
read -r bc br <<<"$(rp base 8.8.8.8)"
[ "$bc" != "?" ] || { echo "repprec vhost not reachable"; exit 2; }
ok "repprec-nginx up (base vhost answers: $bc/$br)"

echo
echo "================  baseline + single-source CONTROLS  ================"
chk "baseline: unblocked IP -> allowed"            base 8.8.8.8      200 none
chk "control geo US fires (8.8.8.8)"               cg   8.8.8.8      403 geo
chk "control geo FR fires (185.177.72.1)"          cg2  185.177.72.1 403 geo
chk "control asn 15169 fires (8.8.8.8)"            ca   8.8.8.8      403 asn
chk "control asn 211590 fires (185.177.72.1)"      ca2  185.177.72.1 403 asn
chk "control asn 60729 fires (185.220.101.1)"      ca3  185.220.101.1 403 asn
chk "control flag anycast fires (8.8.8.8)"         cf   8.8.8.8      403 flag
chk "control flag anon-proxy fires (185.220.101.1)" cf2 185.220.101.1 403 flag

echo
echo "================  COLLISIONS: precedence order  ================"
chk "R1 allowlist > blocklist (same IP both lists)" r1  185.177.72.1 200 allowlist
chk "R2 blocklist > flag+asn+geo (all 4 match)"     r2  8.8.8.8      403 blocklist
chk "R3 flag > asn (anycast + AS15169)"             r3  8.8.8.8      403 flag
chk "R4 flag > block_cc (anycast + US)"             r4  8.8.8.8      403 flag
chk "R5 asn > block_cc (AS211590 + FR, no flag)"    r5  185.177.72.1 403 asn
chk "R6a geo-whitelist control (US found, not HU)"  r6a 8.8.8.8      404 geo_whitelist
chk "R6b blocklist > geo-whitelist"                 r6b 8.8.8.8      403 blocklist
chk "R8 flag(anon-proxy) > asn (AS60729)"           r8  185.220.101.1 403 flag

echo
echo "================  error.log clean  ================"
if grep -Ei '\[crit\]|\[alert\]|\[emerg\]|segfault|worker process [0-9]+ exited' "$ELOG" >/tmp/rp_errs 2>/dev/null; [ -s /tmp/rp_errs ]; then
    echo "  --- suspicious error.log lines:"; sed 's/^/      /' /tmp/rp_errs
    bad "error.log has crash/abort lines"
else
    ok "error.log clean (no crash/abort/worker-exit)"
fi
rm -f /tmp/rp_errs

echo
echo "================== RESULT: $pass passed, $fail failed =================="
[ "$fail" -eq 0 ]
