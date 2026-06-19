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

# ---- coverage opt-in (HEAVYBAG_COVERAGE=1) -------------------------------
# Instruments every suite with gcov (--coverage) and drops to -O0 so the
# line/branch attribution is exact. Composes with ASan; NOT with TSan (that
# is its own pass). When unset, $COV is empty and this script is byte-
# identical to the plain run -- the heavybag_unit gate stays fast (-O2, no
# gcov, no cd).
#
# Footgun: each suite is ONE translation unit (test-X.c #includes the
# production src/heavybag_*.c), and a single-step compile+link names the
# notes/data files "<outbin>-<srcbase>.gcno/.gcda" in the COMPILE cwd. We cd
# into $TMP so they land deterministically, then gcov the stem after the run.
COV=""
if [ "${HEAVYBAG_COVERAGE:-0}" = "1" ]; then
    COV="--coverage -O0"
    cd "$TMP" || { echo "coverage: cannot cd to $TMP"; exit 1; }
fi

rc=0

# ---- JA4 core -------------------------------------------------------------
BIN_JA4="$TMP/heavybag-test-ja4"
if "$CC" -DHEAVYBAG_JA4_UNIT_TEST $COMMON $COV $SAN "$DIR/test-ja4.c" -lcrypto -o "$BIN_JA4"; then
    echo "== JA4 core (ASan+UBSan) =="
    env $SAN_RUN "$BIN_JA4" "$@" || rc=1
else
    echo "JA4 unit test COMPILE FAILED"; rc=1
fi

# ---- JA4 SSL extractor (mocked getters, real core) -----------------------
BIN_JA4X="$TMP/heavybag-test-ja4-extract"
if "$CC" -DHEAVYBAG_JA4_EXTRACT_UNIT_TEST $COMMON $COV $SAN "$DIR/test-ja4-extract.c" -lcrypto -o "$BIN_JA4X"; then
    echo "== JA4 SSL extractor (ASan+UBSan) =="
    env $SAN_RUN "$BIN_JA4X" "$@" || rc=1
else
    echo "JA4 extractor unit test COMPILE FAILED"; rc=1
fi

# ---- UA descriptive parser core ------------------------------------------
BIN_UA="$TMP/heavybag-test-ua-parse"
if "$CC" -DHEAVYBAG_UA_PARSE_UNIT_TEST $COMMON $COV "$DIR/test_heavybag_ua_parse.c" -o "$BIN_UA"; then
    echo "== UA parser core =="
    "$BIN_UA" "$@" || rc=1
else
    echo "UA parser unit test COMPILE FAILED"; rc=1
fi

# ---- rate-limit token-bucket core ----------------------------------------
BIN_RATE="$TMP/heavybag-test-rate"
if "$CC" -DHEAVYBAG_RATE_UNIT_TEST $COMMON $COV "$DIR/test-rate.c" -o "$BIN_RATE"; then
    echo "== rate-limit core =="
    "$BIN_RATE" "$@" || rc=1
else
    echo "rate-limit unit test COMPILE FAILED"; rc=1
fi

# ---- geo radix-trie walk core --------------------------------------------
BIN_GEO="$TMP/heavybag-test-geo"
if "$CC" -DHEAVYBAG_GEO_UNIT_TEST $COMMON $COV "$DIR/test-geo.c" -o "$BIN_GEO"; then
    echo "== geo trie core =="
    "$BIN_GEO" "$@" || rc=1
else
    echo "geo unit test COMPILE FAILED"; rc=1
fi

# ---- scanner/match core (real PCRE2 match/depth-limit fix) ---------------
BIN_MATCH="$TMP/heavybag-test-match"
if "$CC" -DHEAVYBAG_MATCH_UNIT_TEST $COMMON $COV $SAN "$DIR/test-match.c" -lpcre2-8 -o "$BIN_MATCH"; then
    echo "== scanner/match core (ASan+UBSan) =="
    env $SAN_RUN "$BIN_MATCH" "$@" || rc=1
else
    echo "match unit test COMPILE FAILED"; rc=1
fi

# ---- per-country stat-table core (open-addressed cc[] + cc_overflow) -----
BIN_STATCC="$TMP/heavybag-test-stat-cc"
if "$CC" -DHEAVYBAG_STAT_CC_UNIT_TEST $COMMON $COV "$DIR/test-stat-cc.c" -o "$BIN_STATCC"; then
    echo "== per-country stat-table core =="
    "$BIN_STATCC" "$@" || rc=1
else
    echo "stat-cc unit test COMPILE FAILED"; rc=1
fi

# ---- reputation verdict-precedence core (pure decision fn, mocked deps) ---
BIN_REP="$TMP/heavybag-test-reputation"
if "$CC" -DHEAVYBAG_REPUTATION_UNIT_TEST $COMMON $COV "$DIR/test-reputation.c" -o "$BIN_REP"; then
    echo "== reputation verdict core =="
    "$BIN_REP" "$@" || rc=1
else
    echo "reputation unit test COMPILE FAILED"; rc=1
fi

# ---- scanner/match PCRE1 #else-arm coverage (real pcre2 engine underneath) -
# Drives the legacy PCRE1 code path of ngx_http_heavybag_regex_exec -- dead in
# the normal match build, which hard-defines NGX_PCRE2. -DHEAVYBAG_MATCH_FORCE_
# PCRE1 leaves NGX_PCRE2 undefined so the #else arm + PCRE1 NOMATCH constant
# compile. ASan+UBSan like the main match suite; needs -lpcre2-8.
BIN_MATCHP1="$TMP/heavybag-test-match-pcre1"
if "$CC" -DHEAVYBAG_MATCH_UNIT_TEST -DHEAVYBAG_MATCH_FORCE_PCRE1 $COMMON $COV $SAN \
        "$DIR/test-match-pcre1.c" -lpcre2-8 -o "$BIN_MATCHP1"; then
    echo "== scanner/match PCRE1 arm (ASan+UBSan) =="
    env $SAN_RUN "$BIN_MATCHP1" "$@" || rc=1
else
    echo "match PCRE1 unit test COMPILE FAILED"; rc=1
fi

# ---- rate-limit CAS contention stress (TSan; opt-in HEAVYBAG_TSAN=1) ------
# Drives the lock-free CAS lose/retry path + bounded-retry starvation fail-open
# under REAL thread contention -- both unreachable single-threaded, so the
# plain heavybag_unit gate cannot cover them. TSan cannot combine with ASan and
# is slow (~4 s), hence opt-in and separate from the fast gate. -O2 only (no
# $COV: coverage composes with ASan, NOT TSan -- this is its own pass). The one
# DELIBERATE nginx lock-free-idiom race (optimistic plain read vs __sync CAS in
# ngx_http_heavybag_rate_check) is suppressed via tsan-rate.supp; every other
# race + any crash still fails the run.
if [ "${HEAVYBAG_TSAN:-0}" = "1" ]; then
    BIN_RATESTRESS="$TMP/heavybag-test-rate-stress"
    if "$CC" -DHEAVYBAG_RATE_UNIT_TEST $COMMON -fsanitize=thread \
            -fno-sanitize-recover=all "$DIR/test-rate-stress.c" -lpthread \
            -o "$BIN_RATESTRESS"; then
        echo "== rate-limit CAS contention stress (TSan) =="
        env TSAN_OPTIONS="suppressions=$DIR/tsan-rate.supp halt_on_error=1:abort_on_error=1" \
            "$BIN_RATESTRESS" "$@" || rc=1
    else
        echo "rate-stress (TSan) unit test COMPILE FAILED"; rc=1
    fi
fi

# ---- per-suite coverage report (gcov text; lcov HTML if available) -------
# Each suite is ONE translation unit: test-X.c #includes the production
# src/heavybag_*.c. gcov on the TU stem reports every contributing source;
# we print only the production files (src/heavybag*), skipping the harness.
if [ "${HEAVYBAG_COVERAGE:-0}" = "1" ]; then
    echo
    echo "================== COVERAGE (gcov -b) =================="
    cov_one() {  # $1 = output-binary basename (== gcno/gcda stem prefix), $2 = test src
        stem="$1-${2%.c}"
        if [ ! -f "$TMP/$stem.gcda" ]; then
            echo "  [$1] no .gcda (suite skipped or aborted -- no coverage)"; return
        fi
        # gcov lists the production file as its LAST File block, so the
        # trailing whole-TU summary would inherit p=1; reset on 'Creating'.
        gcov -b "$stem" 2>/dev/null | awk '
            /^File / { p = ($0 ~ /src\/heavybag/); if (p) print "  " $0; next }
            /^Creating / { p = 0; next }
            p && /^Lines executed:/    { print "      " $0 }
            p && /^Branches executed:/ { print "      " $0 }
        '
    }
    cov_one heavybag-test-ja4          test-ja4.c
    cov_one heavybag-test-ja4-extract  test-ja4-extract.c
    cov_one heavybag-test-ua-parse     test_heavybag_ua_parse.c
    cov_one heavybag-test-rate         test-rate.c
    cov_one heavybag-test-geo          test-geo.c
    cov_one heavybag-test-match        test-match.c
    cov_one heavybag-test-stat-cc      test-stat-cc.c
    cov_one heavybag-test-reputation   test-reputation.c
    cov_one heavybag-test-match-pcre1  test-match-pcre1.c

    if command -v lcov >/dev/null 2>&1 && command -v genhtml >/dev/null 2>&1; then
        lcov --quiet --capture --directory "$TMP" --output-file "$TMP/heavybag.info" 2>/dev/null
        if genhtml --quiet --output-directory "$TMP/coverage-html" "$TMP/heavybag.info" 2>/dev/null; then
            echo "  HTML report: $TMP/coverage-html/index.html"
        fi
    else
        echo "  (lcov/genhtml absent -> gcov text only; install lcov for an HTML report)"
    fi
    echo "========================================================"
fi

exit $rc
