#!/usr/bin/env bash
#
# ngx_http_waf_module - JA4 pure-core unit tests (standalone, no nginx).
#
# test-ja4.c includes ../../src/waf_ja4.c under -DWAF_JA4_UNIT_TEST, pulling in
# only the nginx-free JA4 core, and links OpenSSL's libcrypto for SHA256. The
# core's -Werror cleanliness is covered separately by the full module build;
# here we keep the flags minimal so the vendored ctest.h compiles cleanly.
#
# Usage:  bash run-unit-tests.sh [suite[:test]]
# Exit 0 = all tests passed.

set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../../src"
BIN="${TMPDIR:-/tmp}/waf-test-ja4"
CC="${CC:-cc}"

# -Wno-attributes: the vendored ctest.h uses a no_sanitize attribute this gcc
# does not recognise; it is harmless test-harness noise, not our code.
"$CC" -DWAF_JA4_UNIT_TEST -I"$SRC" -O2 -Wall -Wno-attributes \
    "$DIR/test-ja4.c" -lcrypto -o "$BIN" \
    || { echo "JA4 unit test COMPILE FAILED"; exit 1; }

"$BIN" "$@"
