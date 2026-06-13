# ngx_http_waf_module — an nginx edge firewall

A lean, fast **edge firewall** for vanilla nginx, built as a dynamic C module
plus the stock `ngx_mail` proxy, sharing a single IP-reputation core. It is
*not* a heavy WAF — it is a slim edge filter: scanner/bot path blocking,
Apache fingerprint spoofing, libloc-based geo/reputation filtering, and
SMTP protection driven by the same reputation engine.

It replaces a legacy `nginx-firewall.conf` (~130 location-based scanner
rules riddled with over-broad prefixes, unanchored substring matches, and
dead rules) with compiled, anchored, hot-reloadable rules.


## Goals & design constraints

- **Edge filtering, not deep inspection.** Block known scanner/bot paths,
  reject bad IP reputation early, and hide the server fingerprint.
- **HTTP/3 (QUIC) + 0-RTT** via native OpenSSL QUIC — this is why OpenSSL
  3.5.x is bundled (the host OpenSSL 3.0.2 is too old for native QUIC).
- **No shared writable state.** Deliberately *out of scope*: custom
  rate-limiting (stock `limit_req`/`limit_conn` suffice), Hyperscan (PCRE2
  with JIT is enough for ~130 rules), a MaxMind/libloc library dependency
  (the geo reader is an embedded nanolibloc adaptation, libc-only), request
  body inspection, dynamic auto-ban, and TLS fingerprint spoofing.
  **Consequence:** there is no slab, no rbtree, no shared memory. The geo
  database is read-only (shared across workers via fork copy-on-write),
  every list/pattern is resolved at configuration time, and workers are
  stateless with respect to each other.
- **One reputation engine, two heads.** The HTTP `PREACCESS` handler and
  the SMTP `auth_http` endpoint call the *same*
  `ngx_http_waf_reputation_check()`.


## Repository layout

```
.
├── CMakeLists.txt               super-build: fetch + build OpenSSL/zlib-ng/nginx
├── cmake/Versions.cmake         pinned PKG_* versions, URLs, SHA256 hashes
├── dist/                        build output (nginx binary + module) — generated
├── modules/ngx_http_waf/        the dynamic module
│   ├── config                   nginx addon build descriptor
│   ├── scanners.list            scanner path patterns (hot-reloadable)
│   └── src/
│       ├── ngx_http_waf_module.c  module glue: directives, phases, merge
│       ├── ngx_http_waf.h         shared types / loc_conf
│       ├── waf_match.{c,h}         scanner regex buckets + bot heuristics
│       ├── waf_spoof.{c,h}         Apache Server header + error-page spoof
│       ├── waf_geo.{c,h}           libloc location.db mmap reader
│       ├── waf_reputation.{c,h}    shared reputation core + config helpers
│       └── waf_authhttp.{c,h}      ngx_mail auth_http content handler
├── geodb/
│   ├── location.db              IPFire libloc database (uncompressed)
├── reference/                   nanolibloc.c (basis), loctest.c (geo oracle)
├── sandbox/                     runnable test environment
│   ├── nginx.conf               full HTTP + mail example config
│   ├── certs/                   self-signed test cert/key
│   ├── html/                    test documents
│   └── logs/
```


## Building

The toolchain is a **CMake super-build**. From a clean checkout it downloads
version-pinned sources (OpenSSL, zlib-ng, nginx), builds them, and produces
the nginx binary + WAF module under `dist/` — no vendored trees, no manual
`./configure` dance.

### Prerequisites

- CMake ≥ 3.16, a C toolchain (gcc/clang), `make`, and network access
  (sources are fetched at build time).
- PCRE2 dev headers (linked dynamically) and the usual nginx build deps.
- Everything else is fetched and built by CMake:
  - **OpenSSL 3.5.7** — built from source and statically linked, because
    native QUIC needs OpenSSL ≥ 3.5 (the host's 3.0.2 is too old). nginx
    builds it in-tree via `--with-openssl=<src>`.
  - **zlib-ng 2.3.3** — built statically (`--zlib-compat --static`) and
    linked in place of the system dynamic zlib.
  - **nginx 1.30.2** — configured with the full flag set and the WAF module
    as a dynamic add-on.

Versions/URLs/hashes are pinned in [`cmake/Versions.cmake`](cmake/Versions.cmake);
bump a `PKG_*` there (or pass `-DPKG_*_VERSION=…`) to change a dependency.

### One-shot build

```sh
cmake -B build -S .
cmake --build build -j
```

This produces, at stable repo-relative paths:

- `dist/sbin/nginx` — the binary (OpenSSL 3.5.7 + static zlib-ng)
- `dist/modules/ngx_http_waf_module.so` — the WAF dynamic module

> **Note — clean-build stamp race.** On a *fresh* checkout the very long
> in-tree OpenSSL compile can make the first `cmake --build` step report a
> spurious non-zero exit before CMake writes its stamp. If that happens, just
> run `cmake --build build -j` **again** — the second pass finds the build
> done and proceeds to `make install`. Incremental builds are unaffected.

### Fast module iteration

Day-to-day module edits should not re-run the whole chain. After the first
full build, rebuild just the `.so` and refresh `dist/` with:

```sh
cmake --build build --target waf_module
```

It runs `make modules` in the already-built nginx tree and copies the fresh
`ngx_http_waf_module.so` into `dist/modules/`.

### Verifying the build

```sh
dist/sbin/nginx -V                 # OpenSSL 3.5.7, --with-http_v3_module, --with-mail
ldd dist/sbin/nginx                # no libz.so -> zlib-ng is static
strings dist/sbin/nginx | grep -i zlib-ng
```

### ⚠️ Gotchas (read before you build)

1. **The OpenSSL-rebuild trap (handled).** Re-running nginx's `./configure`
   bumps `objs/Makefile`'s mtime, and the next `make` then tries a *full*
   OpenSSL rebuild. The super-build guards against this: before each nginx
   `make` it touches `<openssl-src>/.openssl/include/openssl/ssl.h` if
   present (a no-op on the first build). You do not need to do this by hand.

2. **A new module source file requires a re-configure.** Adding a `.c` to
   `modules/ngx_http_waf/config` is not picked up by the `waf_module` fast
   target alone — the nginx tree must be re-configured. Drop the configure
   stamp so the nginx ExternalProject re-runs `./configure` + `make` on the
   next build (without re-downloading the sources):

   ```sh
   rm -f build/nginx_ext-prefix/src/nginx_ext-stamp/nginx_ext-configure
   cmake --build build -j
   ```

   (Or wipe `build/` entirely for a clean, re-downloading run.)

3. **A dynamic `.so` is NOT hot-reloaded.** `nginx -s reload` does not load
   new module *code*. After rebuilding the `.so`, do a full **stop + start**
   of the running nginx. (Config and the scanner list / geo DB *are*
   reloadable — see below; only the compiled module code is not.)


## Configuration

### Loading the module

```nginx
load_module /path/to/dist/modules/ngx_http_waf_module.so;
```

### Directive reference

All directives are valid in `http`, `server`, and `location` contexts and
inherit downward (merge), **except** `waf_mail_auth`, which is
`location`-only. `waf_blocklist`/`waf_allowlist`/`waf_trusted_proxy` take a
single CIDR each but may be repeated to build up a list.

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `waf` | `on`\|`off` | `off` | Master switch for the HTTP `POST_READ` + `PREACCESS` handlers (reputation, bot, scanner). Does **not** gate spoofing. |
| `waf_bot_block` | `on`\|`off` | `off` | Block known scanner User-Agents and empty/missing UA (→ 404). |
| `waf_scanner_list` | `<path>` | — | Load scanner path patterns from a file (compiled into action buckets). |
| `waf_server_token` | `<string>` | `Apache/2.4.68 (Unix)` | The fake `Server:` token and the error-page fingerprint. |
| `waf_geo_db` | `<path>` | — | Path to the libloc `location.db` (mmap'd read-only). |
| `waf_geo_block` | `<CC> …` | — | Block these country codes (ISO-3166 two-letter, plus IPFire specials A1/A2/A3/T1/XD). |
| `waf_flag_block` | `<flag> …` | — | Block by libloc network flag: `anonymous-proxy` (alias `anon`), `satellite`, `anycast`, `tor`, `drop`. |
| `waf_trusted_proxy` | `<cidr>` | — | Trust `X-Forwarded-For` only from these peers when deriving the canonical client IP. |
| `waf_blocklist` | `<cidr>` | — | Statically deny this network (→ 403). Repeatable. |
| `waf_allowlist` | `<cidr>` | — | Allow this network, short-circuiting all reputation checks. Repeatable. |
| `waf_mail_auth` | *(none)* | — | Turn this `location` into the `ngx_mail` `auth_http` endpoint. |
| `waf_mail_backend` | `<ip> <port>` | — | Upstream MTA returned as `Auth-Server`/`Auth-Port` on allow. **Numeric IP only** (the mail proxy cannot resolve hostnames). |

### Scanner list file format

One PCRE2 pattern per line, with an optional trailing action token:

```
<pattern>[ <action>]        # action ∈ { 404 (default), 403, 444 }
```

- Lines are trimmed; blank lines and `#` comments are ignored.
- **Anchor every pattern with `^`.** Patterns match the normalized request
  URI (`r->uri`) case-insensitively; an unanchored pattern can match
  mid-URI and block legitimate paths.
- Patterns sharing an action are concatenated into **one** anchored
  alternation regex and JIT-compiled once, so matching is a single regex
  exec per action bucket at request time — not one exec per pattern.
- Actions map to: `404` → `NGX_HTTP_NOT_FOUND`, `403` → `NGX_HTTP_FORBIDDEN`,
  `444` → `NGX_HTTP_CLOSE` (drop the connection).
- The file is **hot-reloadable**: `nginx -s reload` re-reads and recompiles
  it; the old regex is freed with the old config pool.

Example:

```
^/wp-
^/xmlrpc\.php$
^/\.git
^/phpmyadmin/ 403
^/owa 444
```

The bot User-Agent signatures (sqlmap, nikto, nmap, masscan, zgrab, nuclei,
dirbuster, gobuster, wpscan, acunetix, nessus, netsparker, fimap, hydra,
arachni, dirsearch) are compiled into the module and matched as
case-insensitive substrings; `waf_bot_block on` enables them.

### Geo / reputation

The geo database is the **IPFire libloc** database. Fetch and decompress it:

```sh
curl -fsSL -o geodb/location.db.xz \
    https://location.ipfire.org/databases/1/location.db.xz
xz -dk geodb/location.db.xz       # -> geodb/location.db
```

Reputation is evaluated in this fixed order (any deny wins, allowlist wins
over everything):

1. **allowlist** match → allow (short-circuit).
2. **blocklist** match → 403 (`static blocklist`).
3. **geo network flag** match (`flag_mask`) → 403 (`network flag`).
4. **geo country** match (`block_cc`) → 403 (`geo country`).

The database is `mmap`'d read-only and `munmap`'d on reload, so updating
it is a config reload — replace `geodb/location.db` atomically and run
`nginx -s reload` (no restart needed for a DB swap).

`waf_flag_block` is a convenience: each flag also adds the corresponding
IPFire special country code to the block list (`anonymous-proxy`→A1,
`satellite`→A2, `anycast`→A3, `drop`→XD). `tor` adds only the T1 country
code (Tor exits carry no dedicated flag bit). Note: the public IPFire DB
does not populate every special CC (e.g. Tor/T1 is typically absent).

### Client IP behind a proxy

With `waf_trusted_proxy` set and an `X-Forwarded-For` header present, the
`POST_READ` handler derives the canonical client address from XFF — but
**only** when the socket peer is itself a trusted proxy. Otherwise the
socket peer is used. The reputation check runs against this canonical
address.

### Mail (SMTP) protection

The stock `ngx_mail` proxy authenticates connections against an `auth_http`
endpoint. This module serves that endpoint: it reads the `Client-IP`
request header (the real SMTP peer, injected by `ngx_mail` from
`s->connection->addr_text` — unspoofable), runs the shared
`reputation_check`, and returns a header-only response:

- **Allow:** `Auth-Status: OK` + `Auth-Server`/`Auth-Port` (from
  `waf_mail_backend`). Both are mandatory or `ngx_mail` errors out.
- **Deny:** `Auth-Status: <reason>` — `ngx_mail` prepends its SMTP error
  code, e.g. `535 5.7.0 static blocklist`.
- **Fail-open:** missing/unparseable `Client-IP` → allow + a warning log,
  so a format error cannot break the whole mail flow.

**Critical:** the `auth_http` `location` must be on a server/location with
`waf off`. Otherwise the HTTP `PREACCESS` handler runs against the
*connection* peer (the loopback mail proxy) and can 403 the auth request
before the content handler runs. With `waf off`, `PREACCESS`/`POST_READ`
skip, but the content handler's `reputation_check` still uses the
location's `waf_blocklist`/`waf_geo_*` data (reputation is independent of
the `waf` flag). Bind the endpoint to `127.0.0.1` so it cannot be called
externally.

### Example configuration

A complete, runnable example lives in [`sandbox/nginx.conf`](sandbox/nginx.conf).
It wires up: the WAF on a public HTTP/2 + HTTP/3 server (ports 8080/8443),
a localhost-only `auth_http` endpoint (8081), and two SMTP heads — an
inbound MX (`smtp_auth none`, pure IP reputation) and a submission listener
(STARTTLS + SMTP AUTH). The sandbox uses high ports (2525/5870) because the
test nginx runs unprivileged; **production binds 25/587** (needs root or
`CAP_NET_BIND_SERVICE`).

Minimal HTTP example:

```nginx
load_module .../dist/modules/ngx_http_waf_module.so;

http {
    waf               on;
    waf_bot_block     on;
    waf_scanner_list  /etc/nginx/scanners.list;

    waf_geo_db        /etc/nginx/geodb/location.db;
    waf_geo_block     CN RU;
    waf_flag_block    anycast anonymous-proxy;
    waf_trusted_proxy 127.0.0.1;

    server {
        listen 443 ssl;
        listen 443 quic reuseport;
        http2  on;
        # ...
        location / {
            add_header Alt-Svc 'h3=":443"; ma=86400';
        }
    }
}
```


## Runtime behavior

- **`POST_READ` phase:** resolve the canonical client IP (peer, or XFF from
  a trusted proxy) and stash it for the reputation check.
- **`PREACCESS` phase** (cheap → expensive): IP reputation → bot UA
  heuristics → scanner path regex. The first match finalizes the request.
- **Header/body filters:** the `Server:` token is overridden to
  `waf_server_token` and built-in nginx error pages are rewritten to an
  Apache-style fingerprint. These filters install in `postconfiguration`
  and run **process-wide** (they will also stamp the `auth_http` response,
  which is harmless — `ngx_mail` ignores it).
- Subrequests and internal redirects are never re-scanned.


## Notes & limitations

- HTTP/3 client handshake is not exercised in the sandbox (the host curl
  has no QUIC backend); the QUIC listener comes up and HTTP/1.1 + HTTP/2
  are verified.
- Docker is not used in this environment; everything builds from source.
- `waf_mail_backend` does not validate that the MTA is reachable — it only
  validates that the address is a numeric IP and the port is in range.


## Reference

The `reference/` directory keeps the two source files the geo subsystem was
developed against — they are not compiled into the build, but document where
the embedded reader came from and how it is validated:

- **`reference/nanolibloc.c`** — the minimal, dependency-free libloc
  (`location.db`) reader by **arpi_esp**, from
  [`gereoffy/ipstat46`](https://github.com/gereoffy/ipstat46/blob/main/nanolibloc.c).
  The module's `waf_geo.c` is an in-tree adaptation of it (mmap'd, read-only,
  libc-only). Credit and thanks to arpi_esp for the original nanolibloc.
- **`reference/loctest.c`** — a standalone geo oracle: it resolves IPs against
  `location.db` independently of nginx, used to cross-check the module's
  country / network-flag lookups during development.
