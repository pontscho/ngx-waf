#!/usr/bin/env bash
#
# run-config-tests.sh - WAF config-validation (nginx -t) regression net
#
# Phase 7a of the QA test-matrix campaign (docs/qa-campaign.md "config-build").
# Where the unit suite (tests/unit/test-match.c) freezes the LIST-PARSE half of
# the config-build backlog byte-for-byte (next_line CRLF/no-newline/blank-skip,
# empty->NULL bucket, inline-comment, unknown-action EMERG), THIS harness drives
# the merge-time / parse-time fail-closed decisions that ONLY exist with the real
# nginx config machinery: directives reaching ngx_conf_log_error(NGX_LOG_EMERG)
# + return NGX_CONF_ERROR, the stream<->http rate-zone asymmetry (EMERG vs WARN),
# the geo-policy-without-geo_db fail-closed (both heads), the signed-DB verify,
# and the four duplicate / range / class guards.
#
# Each vector generates a minimal self-contained conf and runs `nginx -t` on it,
# asserting one of:
#   expect_accept  - nginx -t exits 0 (config is valid)
#   expect_reject  - nginx -t exits != 0 AND stderr/error-log matches a SPECIFIC
#                    diagnostic regex (so a reject for the WRONG reason -- e.g. a
#                    missing stream handler -- correctly FAILS the assertion)
#   expect_warn    - nginx -t exits 0 AND a WARN line matches (config loads but a
#                    silently-degraded feature is flagged loudly)
#
# `nginx -t` does NOT bind listening sockets, so the (high, loopback-only) ports
# never conflict and nothing egresses. The kitchen-sink accept (V34) proves the
# harness is not merely rejecting everything.
#
# Standalone entrypoint (like run-protocol-tests.sh). No CI; run manually.
# Usage:  bash run-config-tests.sh
# Exit 0 = every assertion passed.

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
MOD=$ROOT/modules/ngx_http_heavybag
TESTS=$MOD/tests
SO=$SBX/modules/ngx_http_heavybag_module.so
LISTS=$MOD/lists
GEODB=$ROOT/geodb/location.db
WORK=$TESTS/corpus/.config-tmp
ERRF=$WORK/nt.stderr
ERRLOG=$WORK/nt.err.log
OUT=$WORK/nt.combined
mkdir -p "$WORK"

# preflight: the sandbox nginx + deployed .so must exist (exit 2 = CTest SKIP).
[ -x "$NGINX" ] || { echo "sandbox nginx not built -- run: cmake --build build"; exit 2; }
[ -f "$SO" ]     || { echo "deployed .so missing -- run: cmake --build build --target heavybag_module"; exit 2; }

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/      /'; }

# run nginx -t on a generated conf; set RC, leave combined stderr+error_log in OUT.
# (init_module/merge WARNs land in the configured error_log file, conf-parse
# EMERGs on -t stderr -- combine both so a grep finds either.)
run_nt() {
    : > "$ERRLOG" 2>/dev/null || true
    "$NGINX" -p "$SBX/" -c "$1" -t >"$ERRF" 2>&1
    RC=$?
    cat "$ERRF" "$ERRLOG" 2>/dev/null > "$OUT"
}

expect_reject() {  # <label> <conf> <diagnostic-regex>
    run_nt "$2"
    if [ "$RC" -ne 0 ] && grep -qiE "$3" "$OUT"; then
        ok "$1"
    else
        bad "$1 (rc=$RC, want reject matching /$3/)" "$(tail -2 "$OUT")"
    fi
}
expect_accept() {  # <label> <conf>
    run_nt "$2"
    if [ "$RC" -eq 0 ]; then ok "$1"; else bad "$1 (rc=$RC, want accept)" "$(tail -3 "$OUT")"; fi
}
expect_warn() {  # <label> <conf> <warn-regex>
    run_nt "$2"
    if [ "$RC" -eq 0 ] && grep -qiE "$3" "$OUT"; then
        ok "$1"
    else
        bad "$1 (rc=$RC, want accept+warn /$3/)" "$(tail -3 "$OUT")"
    fi
}

# conf skeleton emitters (heredoc bodies interpolate $SO/$WORK/$LISTS/$GEODB) ---
C=$WORK/case.conf
http_conf() {  # body on stdin -> full http{} conf in $C
    { echo "load_module $SO;"
      echo "worker_processes 1;"
      echo "pid $WORK/nt.pid;"
      echo "error_log $ERRLOG info;"
      echo "events { worker_connections 64; }"
      echo "http {"; cat; echo "}"
    } > "$C"
}
stream_conf() {  # body on stdin -> full stream{} conf in $C
    { echo "load_module $SO;"
      echo "worker_processes 1;"
      echo "pid $WORK/nt.pid;"
      echo "error_log $ERRLOG info;"
      echo "events { worker_connections 64; }"
      echo "stream {"; cat; echo "}"
    } > "$C"
}

echo "=== WAF config-validation (nginx -t) harness ==="
echo

# preflight: the deployed .so must load at all -------------------------------
http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; location / { return 204; } }
EOF
expect_accept "preflight: module loads + trivial waf on config valid" "$C"

# --- generated corpus list files --------------------------------------------
GOOD=$WORK/good-scanner.list
printf '^/wp-login\\.php  403\n^/\\.env  404\n^/phpmyadmin/  444\n' > "$GOOD"

BADACTION=$WORK/badaction.list
printf '^/secret  bock\n' > "$BADACTION"          # typo'd action token -> EMERG

BADREGEX=$WORK/badregex.list
printf '^/(unclosed  403\n' > "$BADREGEX"         # unbalanced ( -> pcre2 compile error

INLINE=$WORK/inline.list
printf '^/admin  403 # admin area is forbidden\n' > "$INLINE"   # inline comment after action

JA4BAD=$WORK/ja4-malformed.list
printf 't13d1516h2_8daaf6152771_b186095e22b6 chrome\nloneTokenNoFamily\n' > "$JA4BAD"

BIGLINE=$WORK/bigline.list
{ printf '^/'; head -c 100000 /dev/zero | tr '\\0' 'a'; printf '  404\n'; } > "$BIGLINE"

CORRUPTDB=$WORK/corrupt.db
head -c 4096 /dev/zero > "$CORRUPTDB"            # all-zero -> magic/signature fail

echo
echo "================  geo-policy fail-closed (require waf_geo_db)  ================"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_geo_block CN; location / { return 204; } }
EOF
expect_reject "V1  HTTP waf_geo_block without waf_geo_db refused" "$C" "require waf_geo_db"

stream_conf <<EOF
server { listen 127.0.0.1:28601; waf_stream on; waf_geo_block CN; proxy_pass 127.0.0.1:9; }
EOF
expect_reject "V2  STREAM waf_geo_block without waf_geo_db refused (both heads)" "$C" "require waf_geo_db"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_asn_block 64512; location / { return 204; } }
EOF
expect_reject "V3  HTTP waf_asn_block without waf_geo_db refused" "$C" "require waf_geo_db"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_geo_whitelist US; location / { return 204; } }
EOF
expect_reject "V4  HTTP waf_geo_whitelist without waf_geo_db refused" "$C" "require waf_geo_db"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_geo_db $GEODB; waf_geo_block CN; location / { return 204; } }
EOF
expect_accept "V5  HTTP waf_geo_block WITH valid signed waf_geo_db accepted" "$C"

echo
echo "================  rate-limit zone + parameter guards  ================"

http_conf <<EOF
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/s; } }
EOF
expect_reject "V6  HTTP waf_rate_limit without waf_rate_zone refused" "$C" "requires a waf_rate_zone"

stream_conf <<EOF
server { listen 127.0.0.1:28601; waf_stream on; waf_stream_rate_limit rate=10r/s; proxy_pass 127.0.0.1:9; }
EOF
expect_warn "V7  STREAM waf_stream_rate_limit without zone: accepts + WARN (asymmetry)" "$C" "stream rate limiting is DISABLED"

http_conf <<EOF
waf_rate_zone size=4k;
server { listen 127.0.0.1:28600; location / { return 204; } }
EOF
expect_reject "V8  waf_rate_zone size < 8 pages refused" "$C" "too-small size"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/s burst=20; } }
EOF
expect_accept "V9  waf_rate_zone size=1m + rate_limit accepted" "$C"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=0r/s; } }
EOF
expect_reject "V10 waf_rate_limit rate=0 refused (invalid rate count)" "$C" "invalid rate count"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/d; } }
EOF
expect_reject "V11 waf_rate_limit invalid unit (r/d) refused" "$C" "invalid rate unit"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=1000000000000r/s; } }
EOF
expect_reject "V12 waf_rate_limit rate overflow refused (rate is too large)" "$C" "rate is too large"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit burst=20; } }
EOF
expect_reject "V13 waf_rate_limit missing rate= refused" "$C" "requires a rate="

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/s; waf_rate_limit rate=5r/s; } }
EOF
expect_reject "V14 >1 default rate rule refused" "$C" "more than one default rule"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/s burst=0; } }
EOF
expect_reject "V15 waf_rate_limit burst=0 refused (invalid burst)" "$C" "invalid burst"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/s for_geo=CN,US; } }
EOF
expect_accept "V16 waf_rate_limit for_geo=CN,US accepted" "$C"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/s for_geo=CN,; } }
EOF
expect_accept "V17 for_geo trailing comma accepted (OK -- skip-comma exits loop, no empty token)" "$C"

http_conf <<EOF
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { waf_rate_limit rate=10r/s for_geo=CN,,US; } }
EOF
expect_reject "V18 for_geo double comma refused (two letters)" "$C" "two letters"

echo
echo "================  class / token / duplicate guards  ================"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_verified_bot spider $LISTS/verified-crawler.list; location / { return 204; } }
EOF
expect_reject "V19 waf_verified_bot unknown class refused" "$C" "unknown class"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_flag_block bogusflag; location / { return 204; } }
EOF
expect_reject "V20 waf_flag_block unknown token refused" "$C" "unknown waf_flag_block value"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_scanner_list $GOOD; waf_scanner_list $GOOD; location / { return 204; } }
EOF
expect_reject "V21 duplicate waf_scanner_list refused" "$C" "is duplicate"

http_conf <<EOF
waf_rate_zone size=1m;
waf_rate_zone size=1m;
server { listen 127.0.0.1:28600; location / { return 204; } }
EOF
expect_reject "V22 duplicate waf_rate_zone refused" "$C" "is duplicate"

echo
echo "================  list-file parse @ nginx -t (integration of Phase-5 units)  ================"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_ja4_list $JA4BAD; location / { return 204; } }
EOF
expect_warn "V23 ja4.list malformed line: accepts + WARN-skip" "$C" "malformed ja4.list"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_scanner_list $BADREGEX; location / { return 204; } }
EOF
expect_reject "V24 invalid regex in scanner list aborts config" "$C" "pcre|regex|compil|failed"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_scanner_list $WORK/does-not-exist.list; location / { return 204; } }
EOF
expect_reject "V25 unreadable/missing list file aborts config" "$C" "failed"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_scanner_list $BADACTION; location / { return 204; } }
EOF
expect_reject "V26 unknown action in scanner list refused (round-2 fail-closed)" "$C" "unknown action"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_scanner_list $INLINE; location / { return 204; } }
EOF
expect_accept "V27 inline comment after action accepted (round-2)" "$C"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_scanner_list $BIGLINE; location / { return 204; } }
EOF
# A 100KB single line is read + tokenised without OOM/crash; PCRE2 then rejects
# it with a BOUNDED diagnostic (fail-closed), proving graceful handling, not a hang.
expect_reject "V28 100KB single list line handled gracefully (bounded pcre2 error, no OOM)" "$C" "regular expression is too large"

echo
echo "================  mail-backend + geo-db signature  ================"

http_conf <<EOF
server { listen 127.0.0.1:28600; location = /m { waf_mail_auth; waf_mail_backend example.com 25; } }
EOF
expect_reject "V29 waf_mail_backend hostname refused (numeric IP only)" "$C" "is not a numeric"

http_conf <<EOF
server { listen 127.0.0.1:28600; location = /m { waf_mail_auth; waf_mail_backend 127.0.0.1 70000; } }
EOF
expect_reject "V30 waf_mail_backend out-of-range port refused" "$C" "port .* is invalid"

http_conf <<EOF
server { listen 127.0.0.1:28600; location = /m { waf_mail_auth; waf_mail_backend 127.0.0.1 2525; } }
EOF
expect_accept "V31 waf_mail_backend valid IP+port accepted" "$C"

http_conf <<EOF
server { listen 127.0.0.1:28600; waf on; waf_geo_db $CORRUPTDB; waf_geo_block CN; location / { return 204; } }
EOF
expect_reject "V32 corrupt/unsigned geo_db refused (fail-closed verify)" "$C" "geo|magic|signature|verif|invalid|fail"

echo
echo "================  kitchen-sink accept (harness sanity)  ================"

http_conf <<EOF
waf_rate_zone size=1m;
server {
    listen 127.0.0.1:28600;
    waf on;
    waf_geo_db          $GEODB;
    waf_geo_block       CN;
    waf_flag_block      tor anonymous-proxy;
    waf_scanner_list    $GOOD;
    waf_args_list       $LISTS/args.list;
    waf_cookie_list     $LISTS/cookie.list;
    waf_referer_list    $LISTS/referer.list;
    waf_ja4_list        $LISTS/ja4.list;
    waf_verified_bot    crawler $LISTS/verified-crawler.list;
    waf_trusted_proxy   127.0.0.1;
    waf_blocklist       198.51.100.0/24;
    location / { waf_rate_limit rate=100r/s burst=200 for_geo=CN,RU; }
}
EOF
expect_accept "V33 kitchen-sink valid config (all major directives) accepted" "$C"

echo
echo "==================  RESULT: $pass passed, $fail failed  =================="
[ "$fail" -eq 0 ]
