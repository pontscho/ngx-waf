#!/usr/bin/env bash
#
# run-build-matrix.sh - WAF build-portability regression net (full permutation)
#
# Phase 7b of the QA test-matrix campaign (docs/qa-campaign.md "config-build").
# The single .so carries TWO nginx modules (ngx_http_heavybag + ngx_stream_heavybag)
# and conditionally-compiled SSL/JA4 code. Three shipped build fixes must hold
# across the supported configure surface:
#   config-01        - reason-filter decl moved OUT of #if (NGX_HTTP_SSL)
#                      (--without-http_ssl_module must still build the .so)
#   config-build-001 - stream sources gated in `config` via [ "$STREAM" != NO ]
#                      (--without-stream must build, dropping ngx_stream_heavybag)
#   ja4ssl-build-001 - the JA4 SSL extractor (uses SSL_is_quic etc.) wrapped in
#                      #if (NGX_HTTP_SSL) (no undefined SSL_* in the nossl .so)
#
# This harness REBUILDS each permutation's dynamic module (module-only -- no
# nginx ./configure rerun, so NO OpenSSL-rebuild trap) and asserts:
#   - `make modules` exits 0 with ZERO warnings (the build is -Werror)
#   - the .so is produced
#   - ngx_http_heavybag_module is exported by EVERY variant
#   - ngx_stream_heavybag_module is exported EXCEPT in --without-stream
#   - the --without-http_ssl_module .so has ZERO undefined SSL_* symbols
#
# Permutations (builddir trees under the nginx source):
#   objs           default (SSL + stream + http_v2 + http_v3 + mail)  -- canonical
#   objs-nossl     --without-http_ssl_module (+ no stream_ssl_preread / mail_ssl / openssl)
#   objs-nostream  --without-stream
#   objs-nov2      --without http_v2
#   objs-nov3      --without http_v3
#   objs-mail      +mail (canonical already enables mail; cross-check for zero interference)
#   objs-nopcre    --without-pcre -- EXPECTED nginx configure ABORT (the built-in
#                  http_rewrite module hard-requires PCRE); a clean configure-time
#                  diagnostic, NOT a heavybag source defect. Asserted as such.
#
# Trees are created ONCE (CMake makes objs/; fix-round-1 + this campaign make the
# rest). On a fresh checkout where a non-core tree is missing, this script
# bootstraps it via ./configure --builddir + the OpenSSL ssl.h touch-guard. The
# three CORE trees (objs / objs-nossl / objs-nostream) are required; their absence
# is a hard failure (run the CMake build + fix-round permutations first).
#
# Usage:  bash run-build-matrix.sh
# Exit 0 = every buildable permutation built clean and all symbol assertions held.

set -u

ROOT=${HEAVYBAG_ROOT:-/mnt/nvme/imaginarium/openresty}
NSRC=$ROOT/build/nginx_ext-prefix/src/nginx_ext
NGINX=$ROOT/sandbox/sbin/nginx
TOUCH_GUARD=$ROOT/build/ssl-touch-guard.sh
MODDIR=$ROOT/modules/ngx_http_heavybag
SONAME=ngx_http_heavybag_module.so

pass=0; fail=0; skip=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }
skp()  { echo "  SKIP: $1"; skip=$((skip+1)); }

[ -d "$NSRC" ] || { echo "nginx source tree not found: $NSRC (run the CMake build first)"; exit 2; }

# canonical configure arguments, read live from the built binary (path-robust).
BASE_ARGS=$($NGINX -V 2>&1 | sed -n 's/^configure arguments: //p')
[ -n "$BASE_ARGS" ] || { echo "could not read configure arguments from $NGINX -V"; exit 2; }

# bootstrap a missing builddir tree: re-run ./configure with transformed args +
# --builddir, then touch the prebuilt OpenSSL ssl.h so make does NOT trigger a
# doomed full OpenSSL rebuild (the documented build trap).
bootstrap() {  # <builddir> <sed-transform-of-BASE_ARGS>
    local dir=$1 xform=$2 args
    args=$(printf '%s' "$BASE_ARGS" | sed "$xform")
    echo "    bootstrapping $dir via ./configure --builddir=$dir ..."
    ( cd "$NSRC" && ./configure $args --builddir="$dir" ) >"$NSRC/$dir.configure.log" 2>&1
    local rc=$?
    [ -x "$TOUCH_GUARD" ] && sh "$TOUCH_GUARD" >/dev/null 2>&1 || true
    return $rc
}

# build a tree's modules + assert. Args: label dir [bootstrap-xform]
build_tree() {
    local label=$1 dir=$2 xform=${3:-}
    if [ ! -f "$NSRC/$dir/Makefile" ]; then
        if [ -n "$xform" ]; then
            bootstrap "$dir" "$xform" || { bad "$label: bootstrap configure failed" "$(tail -3 "$NSRC/$dir.configure.log")"; return; }
        else
            bad "$label: core tree $dir/Makefile missing (run CMake / fix-round build first)"; return
        fi
    fi
    local log=$NSRC/$dir.modules.log
    ( cd "$NSRC" && make -f "$dir/Makefile" modules ) >"$log" 2>&1
    local rc=$?
    local warns; warns=$(grep -c 'warning:' "$log" 2>/dev/null); warns=${warns:-0}
    if [ "$rc" -ne 0 ]; then
        bad "$label: make modules failed (rc=$rc)" "$(tail -4 "$log")"; return
    fi
    if [ "$warns" -ne 0 ]; then
        bad "$label: built with $warns warning(s) (-Werror surface)" "$(grep 'warning:' "$log" | head -3)"; return
    fi
    [ -f "$NSRC/$dir/$SONAME" ] && ok "$label: make modules clean (0 warnings), .so produced" \
        || { bad "$label: .so not produced"; return; }
}

# symbol assertions on a tree's .so. Args: label dir want_stream(yes|no) nossl(yes|no)
sym_tree() {
    local label=$1 dir=$2 want_stream=$3 nossl=${4:-no}
    local so=$NSRC/$dir/$SONAME
    [ -f "$so" ] || { skp "$label symbols: no .so"; return; }
    nm -D "$so" 2>/dev/null | grep -q 'ngx_http_heavybag_module' \
        && ok "$label: exports ngx_http_heavybag_module" \
        || bad "$label: ngx_http_heavybag_module MISSING"
    if nm -D "$so" 2>/dev/null | grep -q 'ngx_stream_heavybag_module'; then
        [ "$want_stream" = yes ] && ok "$label: exports ngx_stream_heavybag_module" \
            || bad "$label: ngx_stream_heavybag_module present but should be ABSENT (--without-stream)"
    else
        [ "$want_stream" = no ] && ok "$label: ngx_stream_heavybag_module absent (correct, --without-stream)" \
            || bad "$label: ngx_stream_heavybag_module MISSING (should be present)"
    fi
    if [ "$nossl" = yes ]; then
        local n; n=$(nm -D "$so" 2>/dev/null | awk '$1=="U" && $2 ~ /^SSL_/ {c++} END{print c+0}')
        [ "$n" -eq 0 ] && ok "$label: ZERO undefined SSL_* symbols (ja4ssl-build-001 holds)" \
            || bad "$label: $n undefined SSL_* symbol(s) in a non-SSL build" "$(nm -D "$so" | awk '$1=="U" && $2 ~ /^SSL_/')"
    fi
}

echo "=== WAF build-portability matrix ==="
echo "canonical: $BASE_ARGS"
echo

echo "================  default (SSL + stream + v2 + v3 + mail)  ================"
build_tree "objs (canonical)"        objs
sym_tree   "objs (canonical)"        objs        yes  no

echo
echo "================  --without-http_ssl_module (config-01 + ja4ssl-build-001)  ================"
build_tree "objs-nossl"              objs-nossl
sym_tree   "objs-nossl"              objs-nossl  yes  yes

echo
echo "================  --without-stream (config-build-001)  ================"
build_tree "objs-nostream"           objs-nostream
sym_tree   "objs-nostream"           objs-nostream  no   no

echo
echo "================  --without http_v2 / http_v3 / +mail (no module coupling)  ================"
build_tree "objs-nov2"  objs-nov2  's/ --with-http_v2_module//'
sym_tree   "objs-nov2"  objs-nov2  yes  no
build_tree "objs-nov3"  objs-nov3  's/ --with-http_v3_module//'
sym_tree   "objs-nov3"  objs-nov3  yes  no
build_tree "objs-mail"  objs-mail  's/$/ /'
sym_tree   "objs-mail"  objs-mail  yes  no

echo
echo "================  --without-pcre (EXPECTED nginx configure abort)  ================"
# nginx's built-in http_rewrite module hard-requires PCRE, so ./configure aborts
# BEFORE any heavybag source is reached -- a clean human-readable diagnostic, not
# a heavybag portability defect. We assert exactly that failure mode.
NOPCRE_LOG=$NSRC/objs-nopcre.configure.log
if [ ! -f "$NSRC/objs-nopcre/Makefile" ]; then
    NOPCRE_ARGS=$(printf '%s' "$BASE_ARGS" | sed 's# --with-pcre=[^ ]*##; s/ --with-pcre-jit//')
    ( cd "$NSRC" && ./configure $NOPCRE_ARGS --without-pcre --builddir=objs-nopcre ) >"$NOPCRE_LOG" 2>&1
fi
if grep -qiE 'requires the PCRE library' "$NOPCRE_LOG" 2>/dev/null && [ ! -f "$NSRC/objs-nopcre/Makefile" ]; then
    ok "objs-nopcre: nginx configure aborts cleanly (http_rewrite requires PCRE) -- expected, not a heavybag defect"
else
    bad "objs-nopcre: expected a clean 'requires the PCRE library' configure abort" "$(tail -3 "$NOPCRE_LOG" 2>/dev/null)"
fi

echo
echo "==================  RESULT: $pass passed, $fail failed, $skip skipped  =================="
[ "$fail" -eq 0 ]
