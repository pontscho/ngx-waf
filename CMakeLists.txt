# ============================================================================
# CMake super-build for the nginx edge-firewall
#
#   cmake -B build -S .          # configure: declare the 3 ExternalProjects
#   cmake --build build -j       # fetch + build zlib-ng, fetch OpenSSL src,
#                                #   build nginx + WAF module, install -> sandbox/
#
# Produces (installed into the runnable sandbox/ tree):
#   sandbox/sbin/nginx                       (OpenSSL 3.5.7 + static zlib-ng)
#   sandbox/modules/ngx_http_waf_module.so   (the WAF dynamic module)
#
# Dependency chain:
#   zlibng_ext  --(static libz.a + zlib.h)----\
#   openssl_src --(download + extract only)---+--> nginx_ext  (builds OpenSSL +
#   pcre2_src   --(download + extract only)---/    PCRE2 in-tree, links zlib-ng)
# ============================================================================
cmake_minimum_required(VERSION 3.16)
project(nginx_edge_firewall NONE)

include(ExternalProject)
include(ProcessorCount)
include(${CMAKE_SOURCE_DIR}/cmake/Versions.cmake)

ProcessorCount(NPROC)
if(NPROC EQUAL 0)
  set(NPROC 1)
endif()

# --- stable paths ----------------------------------------------------------
set(SANDBOX_DIR   ${CMAKE_SOURCE_DIR}/sandbox        CACHE PATH "nginx install prefix = the runnable sandbox tree")
set(ZLIBNG_PREFIX ${CMAKE_BINARY_DIR}/zlibng         CACHE PATH "static zlib-ng install prefix")

# ============================================================================
# 1. zlib-ng — static, zlib-compatible drop-in (libz.a + zlib.h)
#    --zlib-compat : provides libz.a / zlib.h so nginx's -lz resolves here
#    --static      : no .so in the prefix -> the archive is the only candidate
# ============================================================================
ExternalProject_Add(zlibng_ext
  URL              ${ZLIBNG_URL}
  URL_HASH         SHA256=${ZLIBNG_SHA256}
  DOWNLOAD_NAME    zlib-ng-${PKG_ZLIBNG_VERSION}.tar.gz
  BUILD_IN_SOURCE  TRUE
  CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=${ZLIBNG_PREFIX} --zlib-compat --static
  BUILD_COMMAND    make -j${NPROC}
  INSTALL_COMMAND  make install
  BUILD_BYPRODUCTS ${ZLIBNG_PREFIX}/lib/libz.a)

# ============================================================================
# 2. OpenSSL — download + extract only; nginx builds it in-tree via
#    --with-openssl=<src> (the QUIC-proven path).
# ============================================================================
ExternalProject_Add(openssl_src
  URL               ${OPENSSL_URL}
  URL_HASH          SHA256=${OPENSSL_SHA256}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")
ExternalProject_Get_Property(openssl_src SOURCE_DIR)
set(OPENSSL_SRC_DIR ${SOURCE_DIR})

# ============================================================================
# 3. PCRE2 — download + extract only; nginx builds it in-tree via
#    --with-pcre=<src> (the same model as OpenSSL above). Pinned + SHA256-
#    verified so the regex engine the WAF's ngx_regex_* calls run on is
#    hermetic, not whatever PCRE the host happens to ship.
# ============================================================================
ExternalProject_Add(pcre2_src
  URL               ${PCRE2_URL}
  URL_HASH          SHA256=${PCRE2_SHA256}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")
ExternalProject_Get_Property(pcre2_src SOURCE_DIR)
set(PCRE2_SRC_DIR ${SOURCE_DIR})

# ============================================================================
# 4. nginx + WAF module
#    --prefix=${SANDBOX_DIR} : no-root `make install` at a stable repo path
#    -I/-L zlib-ng opts   : NOT --with-zlib (breaks on zlib-ng); the cc/ld
#                           opts make the gzip probe + final link pick libz.a
# ============================================================================
set(_SSL_HEADER "${OPENSSL_SRC_DIR}/.openssl/include/openssl/ssl.h")

# OpenSSL-rebuild-trap guard: if ssl.h already exists (incremental build),
# touch it before make so re-running ./configure doesn't trigger a doomed full
# OpenSSL rebuild. No-op on a clean first build (header not present yet).
set(_NGINX_BUILD_SH "test -f ${_SSL_HEADER} && touch ${_SSL_HEADER}; make -j${NPROC}")

ExternalProject_Add(nginx_ext
  DEPENDS          zlibng_ext openssl_src pcre2_src
  URL              ${NGINX_URL}
  URL_HASH         SHA256=${NGINX_SHA256}
  BUILD_IN_SOURCE  TRUE
  CONFIGURE_COMMAND <SOURCE_DIR>/configure
      --prefix=${SANDBOX_DIR} --build=E
      --with-stream --with-stream_realip_module --with-stream_ssl_preread_module
      --with-pcre=${PCRE2_SRC_DIR} --with-pcre-jit --with-http_stub_status_module
      --with-threads --with-file-aio
      --with-http_ssl_module --with-http_v2_module --with-http_v3_module
      --with-http_realip_module --with-http_addition_module
      --with-mail --with-mail_ssl_module
      --with-openssl=${OPENSSL_SRC_DIR}
      --with-cc-opt=-I${ZLIBNG_PREFIX}/include
      --with-ld-opt=-L${ZLIBNG_PREFIX}/lib
      --add-dynamic-module=${CMAKE_SOURCE_DIR}/modules/ngx_http_waf
  BUILD_COMMAND    sh -c "${_NGINX_BUILD_SH}"
  INSTALL_COMMAND  make install
  BUILD_BYPRODUCTS ${SANDBOX_DIR}/sbin/nginx
                   ${SANDBOX_DIR}/modules/ngx_http_waf_module.so)
ExternalProject_Get_Property(nginx_ext SOURCE_DIR)
set(NGINX_SRC_DIR ${SOURCE_DIR})

# ============================================================================
# Convenience target — fast WAF-module iteration
#   cmake --build build --target waf_module
# Re-runs only `make modules` in the already-built nginx tree and copies the
# fresh .so into sandbox/. NOTE: a rebuilt .so needs a full nginx stop+start —
# `nginx -s reload` does NOT reload module code.
# ============================================================================
add_custom_target(waf_module
  COMMAND sh -c "test -f ${_SSL_HEADER} && touch ${_SSL_HEADER}; make -C ${NGINX_SRC_DIR} modules"
  COMMAND ${CMAKE_COMMAND} -E copy
          ${NGINX_SRC_DIR}/objs/ngx_http_waf_module.so
          ${SANDBOX_DIR}/modules/ngx_http_waf_module.so
  COMMENT "Rebuilding ngx_http_waf_module.so and copying into sandbox/modules/")
