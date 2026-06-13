#!/usr/bin/env bash
#
# ngx_http_waf_module - waf_status integration test suite
#
# Drives the sandbox nginx (built with the WAF .so) with curl, asserting that
# each verdict class bumps exactly the right counter across all three status
# formats, that the STREAM + SMTP-auth paths work, that counters survive a
# reload, and that hostile bytes in a server_name are escaped (not injected).
#
# Usage:  bash run-stat-tests.sh
# Exit 0 = all assertions passed; non-zero = at least one failed.

set -u

ROOT=/mnt/nvme/imaginarium/openresty
SBX=$ROOT/sandbox
NGINX=$SBX/sbin/nginx
CONF=$ROOT/modules/ngx_http_waf/tests/waf-stat-test.conf
STAT=http://127.0.0.1:28090/waf/stat
A=http://127.0.0.1:28080

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

cleanup() {
    "$NGINX" -p "$SBX/" -c "$CONF" -s stop 2>/dev/null
    sleep 1
    [ -f "$SBX/logs/nginx-stat.pid" ] && kill "$(cat "$SBX/logs/nginx-stat.pid")" 2>/dev/null
}
trap cleanup EXIT

# --- start -----------------------------------------------------------------
"$NGINX" -p "$SBX/" -c "$CONF" -t || { echo "config test FAILED"; exit 2; }
cleanup 2>/dev/null; sleep 1
"$NGINX" -p "$SBX/" -c "$CONF" || { echo "nginx failed to start"; exit 2; }
sleep 1

# read a scalar counter from the plain format (lines: "key value")
getcnt() { curl -s "$STAT/plain" | awk -v k="$1" '$1==k{print $2; f=1} END{if(!f)print 0}'; }

# assert a counter incremented by exactly $4 around the preceding action
assert_delta() { # name before after want
    local d=$(( $3 - $2 ))
    if [ "$d" -eq "$4" ]; then ok "$1 (+$d)"; else bad "$1: want +$4 got +$d ($2 -> $3)"; fi
}

UA='Mozilla/5.0 (test)'

echo "== HTTP verdict classes =="

# allowed (use /index.html directly to avoid nginx internal index sub-request
# which would trigger the WAF handler twice, inflating the counter by 2)
b=$(getcnt http_allowed)
curl -s -o /dev/null -A "$UA" "$A/index.html"
a=$(getcnt http_allowed); assert_delta http_allowed "$b" "$a" 1

# scanner UA -> 404
b=$(getcnt http_blocked_scanner_ua)
code=$(curl -s -o /dev/null -w '%{http_code}' -A sqlmap "$A/")
[ "$code" = 404 ] && ok "scanner-UA returns 404" || bad "scanner-UA code=$code"
a=$(getcnt http_blocked_scanner_ua); assert_delta http_blocked_scanner_ua "$b" "$a" 1

# empty UA -> 404
b=$(getcnt http_blocked_empty_ua)
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'User-Agent;' "$A/")
[ "$code" = 404 ] && ok "empty-UA returns 404" || bad "empty-UA code=$code"
a=$(getcnt http_blocked_empty_ua); assert_delta http_blocked_empty_ua "$b" "$a" 1

# scanner path -> 404
b=$(getcnt http_blocked_scanner_path)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$A/.env")
[ "$code" = 404 ] && ok "scanner-path returns 404" || bad "scanner-path code=$code"
a=$(getcnt http_blocked_scanner_path); assert_delta http_blocked_scanner_path "$b" "$a" 1
b=$(getcnt http_scanner_path_404)
curl -s -o /dev/null -A "$UA" "$A/.git/config"
a=$(getcnt http_scanner_path_404); assert_delta http_scanner_path_404 "$b" "$a" 1

# static blocklist -> 403
b=$(getcnt http_blocked_blocklist)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$A/blocked")
[ "$code" = 403 ] && ok "blocklist returns 403" || bad "blocklist code=$code"
a=$(getcnt http_blocked_blocklist); assert_delta http_blocked_blocklist "$b" "$a" 1

# geo whitelist miss -> 404
b=$(getcnt http_blocked_geo_whitelist)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$A/geo-whitelist")
[ "$code" = 404 ] && ok "geo-whitelist returns 404" || bad "geo-whitelist code=$code"
a=$(getcnt http_blocked_geo_whitelist); assert_delta http_blocked_geo_whitelist "$b" "$a" 1

# response-code counter
b=$(getcnt http_resp_403)
curl -s -o /dev/null -A "$UA" "$A/blocked"
a=$(getcnt http_resp_403); assert_delta http_resp_403 "$b" "$a" 1

echo "== method filter (waf_method_allow / waf_method_deny -> 404) =="

# whitelist: GET/HEAD pass, PUT -> 404 + blocked_method++
b=$(getcnt http_blocked_method)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -X PUT "$A/method-allow")
[ "$code" = 404 ] && ok "method-allow PUT returns 404" || bad "method-allow PUT code=$code"
a=$(getcnt http_blocked_method); assert_delta http_blocked_method "$b" "$a" 1
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$A/method-allow")
[ "$code" = 200 ] && ok "method-allow GET passes (200)" || bad "method-allow GET code=$code"

# blacklist: DELETE (standard bit) -> 404 + blocked_method++
b=$(getcnt http_blocked_method)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -X DELETE "$A/method-deny")
[ "$code" = 404 ] && ok "method-deny DELETE returns 404" || bad "method-deny DELETE code=$code"
a=$(getcnt http_blocked_method); assert_delta http_blocked_method "$b" "$a" 1

# blacklist: non-standard TRACK (string-list match) -> 404 + blocked_method++
b=$(getcnt http_blocked_method)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -X TRACK "$A/method-deny")
[ "$code" = 404 ] && ok "method-deny TRACK (non-standard) returns 404" || bad "method-deny TRACK code=$code"
a=$(getcnt http_blocked_method); assert_delta http_blocked_method "$b" "$a" 1
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$A/method-deny")
[ "$code" = 200 ] && ok "method-deny GET passes (200)" || bad "method-deny GET code=$code"

echo "== detect mode (passes through, bumps would_block[]) =="
D=http://127.0.0.1:28082

# scanner path under detect -> 200 + http_would_block_scanner_path++
b=$(getcnt http_would_block_scanner_path)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$D/.env")
[ "$code" = 200 ] && ok "detect: scanner path passes (200)" || bad "detect scanner-path code=$code"
a=$(getcnt http_would_block_scanner_path); assert_delta http_would_block_scanner_path "$b" "$a" 1

# denied method under detect -> 200 (passed through) + http_would_block_method++
b=$(getcnt http_would_block_method)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$D/method-detect")
[ "$code" = 200 ] && ok "detect: denied method passes (200)" || bad "detect method code=$code"
a=$(getcnt http_would_block_method); assert_delta http_would_block_method "$b" "$a" 1

echo "== JA4 fingerprint (TCP-TLS) =="
# the client_hello wrapper computes JA4 at handshake; $waf_ja4_hash surfaces it
ja4=$(curl -sk -o /dev/null -D - "https://127.0.0.1:28443/ja4" \
      | awk -F': ' 'tolower($1)=="x-waf-ja4"{print $2}' | tr -d '\r')
if echo "$ja4" | grep -Eq '^t[0-9a-z]{9}_[0-9a-f]{12}_[0-9a-f]{12}$'; then
    ok "JA4 well-formed over TCP-TLS ($ja4)"
else
    bad "JA4 malformed or absent: '$ja4'"
fi

echo "== formats =="
ct=$(curl -s -o /dev/null -w '%{content_type}' "$STAT/plain")
echo "$ct" | grep -q 'text/plain' && ok "plain content-type" || bad "plain ct=$ct"
ct=$(curl -s -o /dev/null -w '%{content_type}' "$STAT/prometheus")
echo "$ct" | grep -q 'text/plain' && ok "prometheus content-type" || bad "prom ct=$ct"
ct=$(curl -s -o /dev/null -w '%{content_type}' "$STAT/json")
echo "$ct" | grep -q 'application/json' && ok "json content-type" || bad "json ct=$ct"

curl -s "$STAT/json" | jq -e . >/dev/null 2>&1 && ok "json parses (jq)" || bad "json does not parse"
curl -s "$STAT/prometheus" | grep -q '^waf_http_requests_total ' && ok "prometheus has metrics" || bad "prometheus missing metrics"

# unknown segment -> plain default
code=$(curl -s -o /dev/null -w '%{http_code}' "$STAT/bogus")
[ "$code" = 200 ] && ok "unknown segment serves (plain default)" || bad "unknown segment code=$code"

# method restriction
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$STAT/plain")
[ "$code" = 405 ] && ok "POST rejected (405)" || bad "POST code=$code"

# cross-format value consistency for one counter
pv=$(getcnt http_requests_total)
jv=$(curl -s "$STAT/json" | jq -r '.http.requests_total')
[ "$pv" = "$jv" ] && ok "http_requests_total plain==json ($pv)" || bad "plain=$pv json=$jv"

echo "== escaping (hostile server_name with \" and \\) =="
# prometheus: the quote and backslash must appear ESCAPED, never raw-breaking
curl -s "$STAT/prometheus" | grep -F 'evil\"name\\back' >/dev/null && ok "prometheus escapes server_name" || bad "prometheus did not escape server_name"
# json: jq must still parse AND decode the name back to the raw bytes
jname=$(curl -s "$STAT/json" | jq -r '.vhosts[].server' | grep -F 'evil"name\back')
[ -n "$jname" ] && ok "json escapes+roundtrips server_name" || bad "json server_name wrong: $jname"

echo "== no client IP / PII in any format =="
for f in plain json prometheus; do
    if curl -s "$STAT/$f" | grep -qF '127.0.0.1'; then bad "$f leaks 127.0.0.1"; else ok "$f has no client IP"; fi
done

echo "== STREAM =="
b=$(getcnt stream_denied_blocklist)
curl -s --max-time 2 -o /dev/null "http://127.0.0.1:29090/" 2>/dev/null
sleep 1
a=$(getcnt stream_denied_blocklist); assert_delta stream_denied_blocklist "$b" "$a" 1
b=$(getcnt stream_allowed)
curl -s --max-time 2 -o /dev/null -A "$UA" "http://127.0.0.1:29091/" 2>/dev/null
sleep 1
a=$(getcnt stream_allowed); assert_delta stream_allowed "$b" "$a" 1

# detect mode: would-deny peer is allowed through, stream_would_block[blocklist]++
b=$(getcnt stream_would_block_blocklist)
curl -s --max-time 2 -o /dev/null -A "$UA" "http://127.0.0.1:29092/" 2>/dev/null
sleep 1
a=$(getcnt stream_would_block_blocklist); assert_delta stream_would_block_blocklist "$b" "$a" 1

echo "== asn/method reasons + would_block exposed in all 3 formats =="
# new reasons render automatically in the WAF_REASON_MAX-driven blocked loops
curl -s "$STAT/plain" | grep -q '^http_blocked_asn '          && ok "plain: http_blocked_asn"          || bad "plain missing http_blocked_asn"
curl -s "$STAT/plain" | grep -q '^http_blocked_method '       && ok "plain: http_blocked_method"       || bad "plain missing http_blocked_method"
curl -s "$STAT/plain" | grep -q '^http_would_block_method '   && ok "plain: http_would_block_method"   || bad "plain missing http_would_block_method"
curl -s "$STAT/plain" | grep -q '^stream_would_block_blocklist ' && ok "plain: stream_would_block"     || bad "plain missing stream_would_block"
# json structure
curl -s "$STAT/json" | jq -e '.http.blocked.asn'            >/dev/null 2>&1 && ok "json: http.blocked.asn"          || bad "json missing http.blocked.asn"
curl -s "$STAT/json" | jq -e '.http.would_block.method'     >/dev/null 2>&1 && ok "json: http.would_block.method"   || bad "json missing http.would_block.method"
curl -s "$STAT/json" | jq -e '.stream.would_block.blocklist'>/dev/null 2>&1 && ok "json: stream.would_block"        || bad "json missing stream.would_block"
# json still parses with the new nested objects
curl -s "$STAT/json" | jq -e . >/dev/null 2>&1 && ok "json still parses with would_block objects" || bad "json broken by would_block objects"
# prometheus
curl -s "$STAT/prometheus" | grep -q 'waf_http_blocked_total{reason="asn"}'         && ok "prom: blocked asn"          || bad "prom missing blocked asn"
curl -s "$STAT/prometheus" | grep -q 'waf_http_would_block_total{reason="method"}'  && ok "prom: would_block method"   || bad "prom missing would_block method"
curl -s "$STAT/prometheus" | grep -q 'waf_stream_would_block_total{reason="blocklist"}' && ok "prom: stream would_block" || bad "prom missing stream would_block"

echo "== SMTP-auth (reputation_check out==NULL) =="
# blocked Client-IP (10/8) -> Auth-Status carries the deny reason, no crash
hdr=$(curl -s -D - -o /dev/null -H 'Client-IP: 10.1.2.3' http://127.0.0.1:28081/waf-mail-auth)
echo "$hdr" | grep -qi 'Auth-Status: static blocklist' && ok "mail-auth deny (out==NULL safe)" || bad "mail-auth deny header: $(echo "$hdr" | grep -i auth-status)"
# allowed Client-IP -> Auth-Status: OK
hdr=$(curl -s -D - -o /dev/null -H 'Client-IP: 8.8.8.8' http://127.0.0.1:28081/waf-mail-auth)
echo "$hdr" | grep -qi 'Auth-Status: OK' && ok "mail-auth allow (out==NULL safe)" || bad "mail-auth allow header: $(echo "$hdr" | grep -i auth-status)"

echo "== reload preserves counters =="
before=$(getcnt http_requests_total)
rl_before=$(getcnt last_reload)
sleep 1
"$NGINX" -p "$SBX/" -c "$CONF" -s reload
sleep 2
after=$(getcnt http_requests_total)
rl_after=$(getcnt last_reload)
if [ "$after" -ge "$before" ] && [ "$after" -gt 0 ]; then ok "counters preserved across reload ($before -> $after)"; else bad "counters lost on reload ($before -> $after)"; fi
if [ "$rl_after" -ge "$rl_before" ]; then ok "last_reload updated ($rl_before -> $rl_after)"; else bad "last_reload regressed ($rl_before -> $rl_after)"; fi

echo
echo "==================  RESULT: $pass passed, $fail failed  =================="
[ "$fail" -eq 0 ]
