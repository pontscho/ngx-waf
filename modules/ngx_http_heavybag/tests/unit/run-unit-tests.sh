#!/usr/bin/env bash
#
# ngx_http_heavybag_module - pure-core unit tests (standalone, no nginx).
#
# Each test includes one module .c under a -D*_UNIT_TEST guard, pulling in only
# the nginx-free core (no nginx / SSL headers), and links just what that core
# needs. The full module build covers -Werror cleanliness; here we keep the
# flags minimal so the vendored ctest.h compiles cleanly.
#
#   test-ja4.c                -> JA4 core            (needs -lcrypto for SHA256)
#   test_heavybag_ua_parse.c  -> UA descriptive core (no extra libs)
#   test-rate.c               -> token-bucket core   (no extra libs)
#   test-geo.c                -> geo radix-trie core (no extra libs)
#   test-match.c              -> scanner/match core  (needs -lpcre2-8, real engine)
#
# Usage:  bash run-unit-tests.sh [suite[:test]]
# Exit 0 = all tests in all binaries passed.

set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../../src"
CC="${CC:-cc}"
TMP="${TMPDIR:-/tmp}"

# -Wno-attributes: the vendored ctest.h uses a no_sanitize attribute this gcc
# does not recognise; it is harmless test-harness noise, not our code.
COMMON="-I$SRC -O2 -Wall -Wno-attributes"

# Sanitizer flags for the memory-sensitive parsers (ja4 wire-walk + scanner).
# These TUs do bounds/pointer arithmetic over attacker-controlled lengths; -O2
# alone makes an OOB read/write on the small static globals silent. ASan+UBSan
# turn a single off-by-one into a hard, halting failure (CWE-125/787). Kept off
# the other binaries so the cheap pure-core suites stay fast.
# --param asan-globals=0 + -fno-sanitize=object-size,pointer-overflow: the
# vendored ctest.h registers tests as globals in a custom linker section and
# ENUMERATES them by walking pointer+/-1 across object boundaries reading a
# magic field (ctest.h ~584-597). That deliberate cross-object walk trips ASan's
# global redzones AND UBSan's object-size/pointer-overflow checks -- a harness
# false positive, NOT a heavybag bug (ctest.h tags the section no_sanitize but
# GCC ignores that attribute on variables). Disabling JUST global redzones +
# those two UBSan sub-checks silences the walk while keeping the detections that
# matter here: ASan STACK overflow (the extractor's ciphers/sigalgs/exts[256] +
# buf[37] locals) and HEAP overflow (the malloc'd odd-end sigalgs vector), plus
# all other UBSan checks (shift/signed-overflow/alignment/...).
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all --param asan-globals=0 -fno-sanitize=object-size,pointer-overflow"
# The unit shims deliberately leak (malloc-backed arena / JA4 result buffers are
# never freed -- the process is short-lived). That is by design, NOT a leak bug,
# so LeakSanitizer is disabled for the run; ASan/UBSan still catch OOB and UB.
SAN_RUN="ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"

rc=0

# ---- JA4 core -------------------------------------------------------------
BIN_JA4="$TMP/heavybag-test-ja4"
if "$CC" -DHEAVYBAG_JA4_UNIT_TEST $COMMON $SAN "$DIR/test-ja4.c" -lcrypto -o "$BIN_JA4"; then
    echo "== JA4 core (ASan+UBSan) =="
    env $SAN_RUN "$BIN_JA4" "$@" || rc=1
else
    echo "JA4 unit test COMPILE FAILED"; rc=1
fi

# ---- JA4 SSL extractor (mocked getters, real core) -----------------------
BIN_JA4X="$TMP/heavybag-test-ja4-extract"
if "$CC" -DHEAVYBAG_JA4_EXTRACT_UNIT_TEST $COMMON $SAN "$DIR/test-ja4-extract.c" -lcrypto -o "$BIN_JA4X"; then
    echo "== JA4 SSL extractor (ASan+UBSan) =="
    env $SAN_RUN "$BIN_JA4X" "$@" || rc=1
else
    echo "JA4 extractor unit test COMPILE FAILED"; rc=1
fi

# ---- UA descriptive parser core ------------------------------------------
BIN_UA="$TMP/heavybag-test-ua-parse"
if "$CC" -DHEAVYBAG_UA_PARSE_UNIT_TEST $COMMON "$DIR/test_heavybag_ua_parse.c" -o "$BIN_UA"; then
    echo "== UA parser core =="
    "$BIN_UA" "$@" || rc=1
else
    echo "UA parser unit test COMPILE FAILED"; rc=1
fi

# ---- rate-limit token-bucket core ----------------------------------------
BIN_RATE="$TMP/heavybag-test-rate"
if "$CC" -DHEAVYBAG_RATE_UNIT_TEST $COMMON "$DIR/test-rate.c" -o "$BIN_RATE"; then
    echo "== rate-limit core =="
    "$BIN_RATE" "$@" || rc=1
else
    echo "rate-limit unit test COMPILE FAILED"; rc=1
fi

# ---- geo radix-trie walk core --------------------------------------------
BIN_GEO="$TMP/heavybag-test-geo"
if "$CC" -DHEAVYBAG_GEO_UNIT_TEST $COMMON "$DIR/test-geo.c" -o "$BIN_GEO"; then
    echo "== geo trie core =="
    "$BIN_GEO" "$@" || rc=1
else
    echo "geo unit test COMPILE FAILED"; rc=1
fi

# ---- scanner/match core (real PCRE2 match/depth-limit fix) ---------------
BIN_MATCH="$TMP/heavybag-test-match"
if "$CC" -DHEAVYBAG_MATCH_UNIT_TEST $COMMON $SAN "$DIR/test-match.c" -lpcre2-8 -o "$BIN_MATCH"; then
    echo "== scanner/match core (ASan+UBSan) =="
    env $SAN_RUN "$BIN_MATCH" "$@" || rc=1
else
    echo "match unit test COMPILE FAILED"; rc=1
fi

# ---- per-country stat-table core (open-addressed cc[] + cc_overflow) -----
BIN_STATCC="$TMP/heavybag-test-stat-cc"
if "$CC" -DHEAVYBAG_STAT_CC_UNIT_TEST $COMMON "$DIR/test-stat-cc.c" -o "$BIN_STATCC"; then
    echo "== per-country stat-table core =="
    "$BIN_STATCC" "$@" || rc=1
else
    echo "stat-cc unit test COMPILE FAILED"; rc=1
fi

exit $rc
