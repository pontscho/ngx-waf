#!/usr/bin/env bash
#
# ngx_http_heavybag_module - waf_status integration test suite
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
CONF=$ROOT/modules/ngx_http_heavybag/tests/heavybag-stat-test.conf
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

echo "== request-field signatures (args / cookie / referer) =="
S=$A/sig

# args: %-decoded match (%27union -> 'union, 404 bucket) -> 404 + blocked_args++
b=$(getcnt http_blocked_args)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$S?q=%27union")
[ "$code" = 404 ] && ok "args decoded match returns 404" || bad "args match code=$code"
a=$(getcnt http_blocked_args); assert_delta http_blocked_args "$b" "$a" 1

# args: 403-bucket pattern (decoded "union select") -> 403
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$S?id=1%20union%20select%202")
[ "$code" = 403 ] && ok "args union-select returns 403" || bad "args 403 code=$code"

# args: no signature -> 200 (WAF declined, static file served)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$S?q=hello")
[ "$code" = 200 ] && ok "args non-match passes (200)" || bad "args non-match code=$code"

# cookie: match in a Cookie header value -> 404 + blocked_cookie++
b=$(getcnt http_blocked_cookie)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -H 'Cookie: sid=sqlmap' "$S")
[ "$code" = 404 ] && ok "cookie match returns 404" || bad "cookie match code=$code"
a=$(getcnt http_blocked_cookie); assert_delta http_blocked_cookie "$b" "$a" 1

# referer: match (404 bucket) -> 404 + blocked_referer++
b=$(getcnt http_blocked_referer)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -e 'http://evil.example/x' "$S")
[ "$code" = 404 ] && ok "referer match returns 404" || bad "referer match code=$code"
a=$(getcnt http_blocked_referer); assert_delta http_blocked_referer "$b" "$a" 1

# $waf_reason renders the new subject token in the access log
curl -s -o /dev/null -A "$UA" "$S?q=%27union"
sleep 1
tail -20 "$SBX/logs/access-stat.log" | grep -q 'reason=args' \
    && ok "\$waf_reason=args in access log" || bad "\$waf_reason args missing in log"

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

# args signature under detect -> 200 (passed through) + would_block_args++
b=$(getcnt http_would_block_args)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$D/sig-detect?q=%27union")
[ "$code" = 200 ] && ok "detect: args signature passes (200)" || bad "detect args code=$code"
a=$(getcnt http_would_block_args); assert_delta http_would_block_args "$b" "$a" 1

# X-WAF-Reason header (waf_reason_header on; detect vhost): the per-request
# verdict token is exposed on the response. A default-off vhost never emits it.
rh=$(curl -s -o /dev/null -D - -A "$UA" "$D/sig-detect?q=%27union" | awk 'tolower($1)=="x-waf-reason:"{print $2}' | tr -d '\r')
[ "$rh" = args ] && ok "reason-header: args token on detect response" || bad "reason-header: want args got '$rh'"
rh=$(curl -s -o /dev/null -D - -A "$UA" "$D/index.html" | awk 'tolower($1)=="x-waf-reason:"{print $2}' | tr -d '\r')
[ "$rh" = none ] && ok "reason-header: none token on clean detect response" || bad "reason-header: want none got '$rh'"
rh=$(curl -s -o /dev/null -D - -A "$UA" "$A/index.html" | grep -ci x-waf-reason)
[ "$rh" = 0 ] && ok "reason-header: absent when directive unset (default off)" || bad "reason-header: leaked on default-off vhost"

echo "== fake-bot (CIDR-verified crawler) =="
# "Googlebot" classifies as crawler; the canonical client IP is the loopback
# peer (no waf_trusted_proxy -> XFF ignored). The published range excludes
# loopback, so the claimed crawler is a fake bot unless its location's list
# includes 127.0.0.1.
CRAWLER='Googlebot/2.1 (+http://www.google.com/bot.html)'

# (b) crawler UA, loopback OUT of published range -> 403 + http_blocked_fake_bot++
b=$(getcnt http_blocked_fake_bot)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$CRAWLER" "$A/fakebot")
[ "$code" = 403 ] && ok "fake-bot out-of-range returns 403" || bad "fake-bot code=$code"
a=$(getcnt http_blocked_fake_bot); assert_delta http_blocked_fake_bot "$b" "$a" 1

# (a) crawler UA, loopback IN range -> verified, served (200), no block bump
b=$(getcnt http_blocked_fake_bot)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$CRAWLER" "$A/fakebot-ok")
[ "$code" = 200 ] && ok "fake-bot in-range passes (200)" || bad "fake-bot in-range code=$code"
a=$(getcnt http_blocked_fake_bot); assert_delta http_blocked_fake_bot "$b" "$a" 0

# (c) switch on but class unconfigured -> skipped (200)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$CRAWLER" "$A/fakebot-skip")
[ "$code" = 200 ] && ok "fake-bot unconfigured class skipped (200)" || bad "fake-bot skip code=$code"

# (d) list present but switch off -> not enforced (200)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$CRAWLER" "$A/fakebot-off")
[ "$code" = 200 ] && ok "fake-bot block off passes (200)" || bad "fake-bot off code=$code"

# (e) detect mode -> 200 (passed through) + http_would_block_fake_bot++
b=$(getcnt http_would_block_fake_bot)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$CRAWLER" "$D/fakebot-detect")
[ "$code" = 200 ] && ok "detect: fake-bot passes (200)" || bad "detect fake-bot code=$code"
a=$(getcnt http_would_block_fake_bot); assert_delta http_would_block_fake_bot "$b" "$a" 1

# $waf_reason renders the fake_bot token in the access log
curl -s -o /dev/null -A "$CRAWLER" "$A/fakebot"
sleep 1
tail -20 "$SBX/logs/access-stat.log" | grep -q 'reason=fake_bot' \
    && ok "\$waf_reason=fake_bot in access log" || bad "\$waf_reason fake_bot missing in log"

echo "== per-IP rate limit (token bucket) =="
# /rate has burst=3: the loopback peer gets 3 allowed (200) then 429. Refill at
# 5r/m is negligible on the ms test scale, so the cutoff is deterministic. This
# drains the SHARED loopback bucket, which the detect + stream rate tests below
# then rely on being empty.
b_blk=$(getcnt http_blocked_rate_limit)
b_429=$(getcnt http_resp_429)
n200=0; n429=0
for i in 1 2 3 4 5; do
    c=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$A/rate")
    [ "$c" = 200 ] && n200=$((n200+1))
    [ "$c" = 429 ] && n429=$((n429+1))
done
[ "$n200" = 3 ] && ok "rate: first 3 requests allowed (200)" || bad "rate: 200 count=$n200 (want 3)"
[ "$n429" = 2 ] && ok "rate: over-limit requests get 429"   || bad "rate: 429 count=$n429 (want 2)"
a=$(getcnt http_blocked_rate_limit); assert_delta http_blocked_rate_limit "$b_blk" "$a" 2
a=$(getcnt http_resp_429);          assert_delta http_resp_429          "$b_429" "$a" 2

# P5(c): with no waf_trusted_proxy, X-Forwarded-For must NOT change the rate key
# -> a spoofed XFF cannot earn a fresh bucket; the drained loopback bucket still
# rejects (the limit pins to the real peer, not the header).
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -H 'X-Forwarded-For: 1.2.3.4' "$A/rate")
[ "$code" = 429 ] && ok "rate: untrusted XFF does not bypass the per-IP limit" || bad "rate XFF bypass code=$code"

# $waf_reason renders the rate_limit token in the access log
sleep 1
tail -40 "$SBX/logs/access-stat.log" | grep -q 'reason=rate_limit' \
    && ok "\$waf_reason=rate_limit in access log" || bad "\$waf_reason rate_limit missing in log"

# detect mode: the shared loopback bucket is now drained, so /rate-detect sees
# over-limit -> passes through (200) and bumps would_block[rate_limit].
b=$(getcnt http_would_block_rate_limit)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$D/rate-detect")
[ "$code" = 200 ] && ok "detect: rate limit passes (200)" || bad "detect rate code=$code"
a=$(getcnt http_would_block_rate_limit); assert_delta http_would_block_rate_limit "$b" "$a" 1

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
curl -s "$STAT/prometheus" | grep -q '^heavybag_http_requests_total ' && ok "prometheus has metrics" || bad "prometheus missing metrics"

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

# rate limit at L4 (29093, burst=2). The loopback bucket is SHARED with the HTTP
# rate locations and was drained above, so over-budget connections are closed
# -> stream_denied[rate_limit] climbs. Assert >=1 (order-independent).
b=$(getcnt stream_denied_rate_limit)
for i in 1 2 3 4; do curl -s --max-time 2 -o /dev/null -A "$UA" "http://127.0.0.1:29093/" 2>/dev/null; done
sleep 1
a=$(getcnt stream_denied_rate_limit)
[ $((a - b)) -ge 1 ] && ok "stream rate limit denies over-budget connections (+$((a-b)))" || bad "stream rate: want >=1 got +$((a-b))"

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
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_blocked_total{reason="asn"}'         && ok "prom: blocked asn"          || bad "prom missing blocked asn"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_would_block_total{reason="method"}'  && ok "prom: would_block method"   || bad "prom missing would_block method"
curl -s "$STAT/prometheus" | grep -q 'heavybag_stream_would_block_total{reason="blocklist"}' && ok "prom: stream would_block" || bad "prom missing stream would_block"

echo "== args/cookie/referer reasons exposed in all 3 formats (auto-extend) =="
# the WAF_REASON_MAX bump must surface the three new reasons in every format
curl -s "$STAT/plain" | grep -q '^http_blocked_args '    && ok "plain: http_blocked_args"    || bad "plain missing http_blocked_args"
curl -s "$STAT/plain" | grep -q '^http_blocked_cookie '  && ok "plain: http_blocked_cookie"  || bad "plain missing http_blocked_cookie"
curl -s "$STAT/plain" | grep -q '^http_blocked_referer ' && ok "plain: http_blocked_referer" || bad "plain missing http_blocked_referer"
curl -s "$STAT/json" | jq -e '.http.blocked.args'    >/dev/null 2>&1 && ok "json: http.blocked.args"    || bad "json missing http.blocked.args"
curl -s "$STAT/json" | jq -e '.http.blocked.cookie'  >/dev/null 2>&1 && ok "json: http.blocked.cookie"  || bad "json missing http.blocked.cookie"
curl -s "$STAT/json" | jq -e '.http.blocked.referer' >/dev/null 2>&1 && ok "json: http.blocked.referer" || bad "json missing http.blocked.referer"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_blocked_total{reason="args"}'    && ok "prom: blocked args"    || bad "prom missing blocked args"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_blocked_total{reason="cookie"}'  && ok "prom: blocked cookie"  || bad "prom missing blocked cookie"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_blocked_total{reason="referer"}' && ok "prom: blocked referer" || bad "prom missing blocked referer"

echo "== fake_bot reason exposed in all 3 formats (auto-extend, no truncation) =="
curl -s "$STAT/plain" | grep -q '^http_blocked_fake_bot '     && ok "plain: http_blocked_fake_bot"     || bad "plain missing http_blocked_fake_bot"
curl -s "$STAT/plain" | grep -q '^http_would_block_fake_bot ' && ok "plain: http_would_block_fake_bot" || bad "plain missing http_would_block_fake_bot"
curl -s "$STAT/json" | jq -e '.http.blocked.fake_bot'     >/dev/null 2>&1 && ok "json: http.blocked.fake_bot"     || bad "json missing http.blocked.fake_bot"
curl -s "$STAT/json" | jq -e '.http.would_block.fake_bot' >/dev/null 2>&1 && ok "json: http.would_block.fake_bot" || bad "json missing http.would_block.fake_bot"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_blocked_total{reason="fake_bot"}'     && ok "prom: blocked fake_bot"     || bad "prom missing blocked fake_bot"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_would_block_total{reason="fake_bot"}' && ok "prom: would_block fake_bot" || bad "prom missing would_block fake_bot"
# truncation guard: the extra reason must not push the body past WAF_STAT_FIXED_LINES
curl -s "$STAT/json" | jq -e . >/dev/null 2>&1 && ok "json still parses with fake_bot (no truncation)" || bad "json truncated/broken by fake_bot"

echo "== rate_limit reason + http_resp_429 + rate_overflow in all 3 formats =="
curl -s "$STAT/plain" | grep -q '^http_blocked_rate_limit '     && ok "plain: http_blocked_rate_limit"     || bad "plain missing http_blocked_rate_limit"
curl -s "$STAT/plain" | grep -q '^http_would_block_rate_limit ' && ok "plain: http_would_block_rate_limit" || bad "plain missing http_would_block_rate_limit"
curl -s "$STAT/plain" | grep -q '^http_resp_429 '               && ok "plain: http_resp_429"               || bad "plain missing http_resp_429"
curl -s "$STAT/plain" | grep -q '^rate_overflow '              && ok "plain: rate_overflow"              || bad "plain missing rate_overflow"
curl -s "$STAT/plain" | grep -q '^stream_denied_rate_limit '    && ok "plain: stream_denied_rate_limit"    || bad "plain missing stream_denied_rate_limit"
curl -s "$STAT/json" | jq -e '.http.blocked.rate_limit'   >/dev/null 2>&1 && ok "json: http.blocked.rate_limit"  || bad "json missing http.blocked.rate_limit"
curl -s "$STAT/json" | jq -e '.http.responses."429"'      >/dev/null 2>&1 && ok "json: http.responses.429"       || bad "json missing http.responses.429"
curl -s "$STAT/json" | jq -e '.rate_overflow'            >/dev/null 2>&1 && ok "json: rate_overflow"            || bad "json missing rate_overflow"
curl -s "$STAT/json" | jq -e '.stream.denied.rate_limit'  >/dev/null 2>&1 && ok "json: stream.denied.rate_limit" || bad "json missing stream.denied.rate_limit"
curl -s "$STAT/json" | jq -e . >/dev/null 2>&1 && ok "json still parses with rate_limit/429/overflow" || bad "json broken by rate additions"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_blocked_total{reason="rate_limit"}' && ok "prom: blocked rate_limit" || bad "prom missing blocked rate_limit"
curl -s "$STAT/prometheus" | grep -q 'heavybag_http_responses_total{code="429"}'        && ok "prom: responses 429"     || bad "prom missing responses 429"
curl -s "$STAT/prometheus" | grep -q '^heavybag_rate_overflow_total '                   && ok "prom: rate_overflow"     || bad "prom missing rate_overflow"

echo "== SMTP-auth (reputation_check out==NULL) =="
# blocked Client-IP (10/8) -> Auth-Status carries the deny reason, no crash
hdr=$(curl -s -D - -o /dev/null -H 'Client-IP: 10.1.2.3' http://127.0.0.1:28081/waf-mail-auth)
echo "$hdr" | grep -qi 'Auth-Status: static blocklist' && ok "mail-auth deny (out==NULL safe)" || bad "mail-auth deny header: $(echo "$hdr" | grep -i auth-status)"
# allowed Client-IP -> Auth-Status: OK
hdr=$(curl -s -D - -o /dev/null -H 'Client-IP: 8.8.8.8' http://127.0.0.1:28081/waf-mail-auth)
echo "$hdr" | grep -qi 'Auth-Status: OK' && ok "mail-auth allow (out==NULL safe)" || bad "mail-auth allow header: $(echo "$hdr" | grep -i auth-status)"

# rate limit per Client-IP: 8.8.4.4 is reputation-allowed; burst=2 -> the 3rd
# request in a quick burst is rate-limited. Independent bucket from 8.8.8.8.
hdr=$(curl -s -D - -o /dev/null -H 'Client-IP: 8.8.4.4' http://127.0.0.1:28081/waf-mail-auth)
echo "$hdr" | grep -qi 'Auth-Status: OK' && ok "mail-auth rate req1 OK" || bad "mail rate req1: $(echo "$hdr" | grep -i auth-status)"
hdr=$(curl -s -D - -o /dev/null -H 'Client-IP: 8.8.4.4' http://127.0.0.1:28081/waf-mail-auth)
echo "$hdr" | grep -qi 'Auth-Status: OK' && ok "mail-auth rate req2 OK" || bad "mail rate req2: $(echo "$hdr" | grep -i auth-status)"
hdr=$(curl -s -D - -o /dev/null -H 'Client-IP: 8.8.4.4' http://127.0.0.1:28081/waf-mail-auth)
echo "$hdr" | grep -qi 'Auth-Status: rate limit' && ok "mail-auth 3rd request rate-limited" || bad "mail rate req3: $(echo "$hdr" | grep -i auth-status)"

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

echo "== geo DB signature verification (load-time, fail-closed) =="
# A tampered / truncated location.db must make nginx -t FAIL at config parse
# (geo_open -> verify -> NGX_CONF_ERROR). Each case uses its own minimal conf;
# we assert BOTH a non-zero exit AND the gate-specific message on stderr, so
# the rejection is pinned to the verify path, not an unrelated config error.
VTMP=$(mktemp -d)
DBSRC=$ROOT/geodb/location.db
DBSIZE=$(stat -c%s "$DBSRC")

mkconf() { # <db-path>
    cat > "$VTMP/v.conf" <<EOF
load_module $SBX/modules/ngx_http_heavybag_module.so;
worker_processes 1;
pid $VTMP/v.pid;
error_log $VTMP/v-error.log info;
events { worker_connections 64; }
http {
    waf_geo_db $1;
    server { listen 127.0.0.1:28099; server_name neg.test; }
}
EOF
}

# (1) tampered data region: flip one byte at an offset DERIVED from the real DB
#     size (size/2, clamped >= 4200) -- never a hard-coded offset a smaller
#     future DB could push past EOF, turning the flip into a silent no-op. The
#     signature blobs are zeroed pre-hash, so corrupting them would not change
#     the digest; we must corrupt the hashed data region.
cp "$DBSRC" "$VTMP/bad.db"
FLIP=$(( DBSIZE / 2 )); [ "$FLIP" -lt 4200 ] && FLIP=4200
if [ "$FLIP" -lt "$DBSIZE" ]; then
    python3 -c "f=open('$VTMP/bad.db','r+b'); o=$FLIP; f.seek(o); b=f.read(1); f.seek(o); f.write(bytes([b[0]^0xff])); f.close()"
    ok "verify setup: flipped data byte at $FLIP (db $DBSIZE bytes)"
else
    bad "verify setup: flip offset $FLIP not < db size $DBSIZE"
fi
mkconf "$VTMP/bad.db"
"$NGINX" -p "$SBX/" -c "$VTMP/v.conf" -t 2>"$VTMP/out-bad.log"
[ $? -ne 0 ] && ok "tampered DB: nginx -t fails" || bad "tampered DB: nginx -t unexpectedly OK"
grep -q 'signature verification failed' "$VTMP/out-bad.log" \
    && ok "tampered DB: verify-failure logged" || bad "tampered DB: verify message missing"

# (2) truncated to header-only (4200 bytes): the 4192-byte header is intact but
#     the data region is empty, so the signature (over the whole file) cannot
#     match -> verify fails (distinct from the too-small guard below).
head -c 4200 "$DBSRC" > "$VTMP/short.db"
mkconf "$VTMP/short.db"
"$NGINX" -p "$SBX/" -c "$VTMP/v.conf" -t 2>"$VTMP/out-short.log"
[ $? -ne 0 ] && ok "header-only DB: nginx -t fails" || bad "header-only DB: nginx -t unexpectedly OK"
grep -q 'signature verification failed' "$VTMP/out-short.log" \
    && ok "header-only DB: verify-failure logged" || bad "header-only DB: verify message missing"

# (3) truncated to 100 bytes: rejected by the pre-mmap size guard (< 4200),
#     before mmap/verify ever runs.
head -c 100 "$DBSRC" > "$VTMP/tiny.db"
mkconf "$VTMP/tiny.db"
"$NGINX" -p "$SBX/" -c "$VTMP/v.conf" -t 2>"$VTMP/out-tiny.log"
[ $? -ne 0 ] && ok "tiny DB: nginx -t fails" || bad "tiny DB: nginx -t unexpectedly OK"
grep -q 'too small' "$VTMP/out-tiny.log" \
    && ok "tiny DB: too-small rejection logged" || bad "tiny DB: too-small message missing"

# (4) sanity: the real DB is comfortably under the 512 MiB cap, so the cap can
#     never become a self-inflicted fail-closed DoS on an organically growing DB.
CAP=$(( 512 * 1024 * 1024 ))
[ "$DBSIZE" -lt "$CAP" ] && ok "real DB ($DBSIZE) under 512 MiB cap" || bad "real DB ($DBSIZE) exceeds cap ($CAP)"

rm -rf "$VTMP"

echo "== rate-limit config guard (P4/P5: waf_rate_limit requires waf_rate_zone) =="
# A waf_rate_limit with no waf_rate_zone declared must fail nginx -t at parse
# (the HTTP setter's ordering guard), not silently no-op.
RTMP=$(mktemp -d)
cat > "$RTMP/r.conf" <<EOF
load_module $SBX/modules/ngx_http_heavybag_module.so;
worker_processes 1;
pid $RTMP/r.pid;
error_log $RTMP/r-error.log info;
events { worker_connections 64; }
http {
    server {
        listen 127.0.0.1:28097;
        server_name rl.test;
        location = /x { waf_rate_limit rate=10r/s burst=10; }
    }
}
EOF
"$NGINX" -p "$SBX/" -c "$RTMP/r.conf" -t 2>"$RTMP/out.log"
[ $? -ne 0 ] && ok "waf_rate_limit without zone: nginx -t fails" || bad "waf_rate_limit without zone: unexpectedly OK"
grep -q 'requires a waf_rate_zone' "$RTMP/out.log" \
    && ok "waf_rate_limit without zone: guard message logged" || bad "waf_rate_limit zone guard message missing"
rm -rf "$RTMP"

echo
echo "==================  RESULT: $pass passed, $fail failed  =================="
[ "$fail" -eq 0 ]
