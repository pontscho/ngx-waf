# Versions.cmake — version pins, download URLs and SHA256 hashes for the
# super-build. Kept separate from CMakeLists.txt so bumping a dependency is a
# one-file change. Override any PKG_* on the command line with -D.

set(PKG_OPENSSL_VERSION 3.5.7  CACHE STRING "OpenSSL version")
set(PKG_NGINX_VERSION   1.30.2 CACHE STRING "nginx version")
set(PKG_ZLIBNG_VERSION  2.3.3  CACHE STRING "zlib-ng version")

# --- download URLs ---------------------------------------------------------
set(ZLIBNG_URL  "https://github.com/zlib-ng/zlib-ng/archive/refs/tags/${PKG_ZLIBNG_VERSION}.tar.gz")
set(NGINX_URL   "https://nginx.org/download/nginx-${PKG_NGINX_VERSION}.tar.gz")
set(OPENSSL_URL "https://github.com/openssl/openssl/releases/download/openssl-${PKG_OPENSSL_VERSION}/openssl-${PKG_OPENSSL_VERSION}.tar.gz")

# --- pinned SHA256 hashes --------------------------------------------------
# openssl/nginx computed locally from the in-repo tarballs; zlib-ng fetched
# from its published 2.3.3 release tarball.
set(ZLIBNG_SHA256  "f9c65aa9c852eb8255b636fd9f07ce1c406f061ec19a2e7d508b318ca0c907d1")
set(NGINX_SHA256   "7df3090907fca3cc0e456d6dc00ceb230da74ea88026ceff0affc29dbbd9ac4c")
set(OPENSSL_SHA256 "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8")
