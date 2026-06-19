#!/usr/bin/env bash
#
# run-oracle-build.sh - reference-oracle build smoke
#
# The reference/ programs are hand-compiled developer oracles (the geo/libloc
# on-disk-layout ground truth the QA campaign validated the production reader
# against). They are NOT pass/fail test harnesses, but they DO rot silently if a
# shared assumption drifts and nobody recompiles them. This smoke just proves
# each still BUILDS (compiles + links) -- it asserts no behaviour.
#
#   geolookup.c  loctest.c  nanolibloc.c   libc-only (cc, no extra libs)
#   locverify.c                            needs OpenSSL libcrypto -- linked
#                                          against the project's IN-TREE OpenSSL
#                                          (the same build nginx uses), not the
#                                          host's, so it is hermetic. If the
#                                          in-tree OpenSSL is not built yet the
#                                          locverify build is NOTE-skipped (the
#                                          three libc-only oracles still build).
#
# Standalone entrypoint. exit 0 = every attempted build succeeded; exit 2 = no
# C compiler (CTest SKIP). Built binaries go to a throwaway temp dir.
# Usage:  bash run-oracle-build.sh

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
REF=$ROOT/reference
OSSL=$ROOT/build/openssl_src-prefix/src/openssl_src/.openssl
CC=${CC:-cc}
TMP=$(mktemp -d /tmp/oracle-build.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/      /'; }

command -v "$CC" >/dev/null 2>&1 || { echo "no C compiler ($CC) -- skipping"; exit 2; }

echo "=== reference-oracle build smoke ==="
echo "cc: $CC"
echo

# libc-only oracles -- must build with -Wall -Wextra (no extra libs).
for o in geolookup loctest nanolibloc; do
    src=$REF/$o.c
    if [ ! -f "$src" ]; then bad "$o: source missing ($src)"; continue; fi
    if log=$("$CC" -O2 -Wall -Wextra -o "$TMP/$o" "$src" 2>&1); then
        ok "$o builds (libc-only)"
    else
        bad "$o failed to build" "$(printf '%s' "$log" | tail -4)"
    fi
done

# locverify -- OpenSSL EVP/PEM (ECDSA-P521 signature verify). Link against the
# project's in-tree OpenSSL when present; NOTE-skip otherwise.
if [ -f "$OSSL/include/openssl/evp.h" ] && [ -f "$OSSL/lib/libcrypto.a" ]; then
    if log=$("$CC" -O2 -Wall -o "$TMP/locverify" "$REF/locverify.c" \
                -I"$OSSL/include" -L"$OSSL/lib" -lcrypto 2>&1); then
        ok "locverify builds (in-tree OpenSSL)"
    else
        bad "locverify failed to build against in-tree OpenSSL" "$(printf '%s' "$log" | tail -4)"
    fi
else
    echo "  NOTE: locverify build skipped -- in-tree OpenSSL not built"
    echo "        ($OSSL/lib/libcrypto.a absent; run: cmake --build build)"
fi

echo
echo "==================  RESULT: $pass passed, $fail failed  =================="
[ "$fail" -eq 0 ]
