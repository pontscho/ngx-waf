# Implementation Plan: WAF Module Feature Expansion (JA4, ASN, Method Filter, Detect Mode, location.db cron, Config Docs)

## Requirements Summary

Extend the existing vanilla-nginx dynamic WAF module (`modules/ngx_http_waf/`) with six features agreed with the partner. The module already provides HTTP + STREAM(L4) + SMTP(auth_http) heads over a shared reputation core, plus a completed lock-free stats/status subsystem. The six features:

1. **JA4 TLS-fingerprint detection (observability-only, NO blocking)** — compute the full FoxIO JA4 string (`a_b_c`) from the ClientHello, expose it as a new `$waf_ja4_hash` log variable, logged alongside the UA. Covers TCP-TLS (HTTP/1.1 + HTTP/2) **and** QUIC/HTTP-3. No decision branch on the hot path; the goal is data collection for a possible future blocklist.
2. **ASN-based blocking** — `waf_asn_block <asn>...;` directive (HTTP + STREAM). The geo lookup already extracts `res.asn`; add the decision branch in `reputation_check`, a new `WAF_REASON_ASN`, and stats integration. Fail-open when `asn == 0`.
3. **HTTP method filtering** — `waf_method_allow` (whitelist) + `waf_method_deny` (blacklist), evaluated in the preaccess handler; blocked methods return **404** (consistent with scanner blocks, hides the method policy). New `WAF_REASON_METHOD`.
4. **Detect mode** — the `waf` directive becomes a three-state enum `off | detect | enforce` (with `on` as an alias of `enforce` for backward compatibility). In `detect`, the verdict is computed, logged, and counted in stats, but the request is **not blocked** (`NGX_DECLINED`). A reason-indexed `would_block[]` counter records what would have been blocked.
5. **location.db daily refresh** — example cron shell script (download IPFire location.db → validate → atomic replace → `nginx -s reload`) plus README documentation. No C code.
6. **README config-level usage docs** — `map`-based pattern (not `if`) for `$waf_type` / `$waf_country` / `$waf_reason` category/country blocking at nginx-config level. No module code.

### Success Criteria

- [ ] `$waf_ja4_hash` produces a correct FoxIO JA4 string for TCP-TLS connections (validated bit-for-bit against Wireshark's JA4 field for at least one known client).
- [ ] `$waf_ja4_hash` produces a `q...`-prefixed JA4 for an HTTP/3 (QUIC) connection (empirical confirmation that the wrapped `client_hello_cb` fires on QUIC).
- [ ] SNI-based virtual hosts and certificate selection keep working after the JA4 wrapper is installed (no regression — the original `ngx_ssl_client_hello_callback` still runs).
- [ ] `waf_asn_block 64500 64501;` blocks requests/connections whose source IP resolves to those ASNs; non-listed ASNs and `asn==0` pass.
- [ ] `$waf_asn` shows the source ASN in the access log.
- [ ] `waf_method_allow GET POST HEAD;` returns 404 for any other method; `waf_method_deny TRACE TRACK;` returns 404 for those two.
- [ ] `waf detect;` lets all requests through (`NGX_DECLINED`) while the `would_block[reason]` counters increment exactly as the enforce-mode blocked counters would.
- [ ] `waf on;` still parses and behaves as `enforce` (backward compatibility).
- [ ] The stats endpoints (plain/json/prometheus) expose the new ASN/method reasons and the `would_block` counters.
- [ ] The cron script atomically replaces location.db only after validating it, and reloads nginx.
- [ ] Build is clean under `-Werror -W -Wall`; the curl integration harness passes (existing + new assertions).

### Scope

**In Scope:**
- JA4 computation (TCP + QUIC), `$waf_ja4_hash` variable, logging.
- `waf_asn_block` + `$waf_asn`.
- `waf_method_allow` / `waf_method_deny`, 404 response.
- `waf off|detect|enforce` three-state directive + `would_block[]` counters.
- Stats counter-struct + 3 serializers extended for the new reasons + would_block.
- location.db cron script + README docs.
- README `map`-pattern documentation.

**Out of Scope:**
- Any JA4-based **blocking** or blocklist (observability only this round).
- JA4_r / JA4_ro raw variants (the partner chose the hashed full string only).
- JA4 for the STREAM L4 head (L4 is TLS-passthrough; no termination, JA4 undefined there).
- Per-IP / top-N client tracking (high cardinality, explicitly excluded project-wide).
- Patching nginx or OpenSSL source (the wrapper-chain approach avoids both).
- A configurable action token for method blocking (fixed 404).

### Assumptions & Constraints

**Assumptions:**
- JA4 is stored on the `SSL*` via a module-owned `SSL_get_ex_new_index()` slot, set with `SSL_set_ex_data()` inside the wrapper cb, read from the HTTP variable getter through `r->connection->ssl->connection`.
- `SSL_client_hello_get1_extensions_present()` may be incomplete on this OpenSSL build (per hnakamur's report); the implementation must verify against Wireshark and, if needed, fall back to explicit `SSL_client_hello_get0_ext()` reads for the critical extensions.
- The wrapper passes `NULL` as the 3rd arg to `ngx_ssl_client_hello_callback()` — confirmed: nginx's cb ignores its `arg` param and sources `ngx_ssl_client_hello_arg` from the `ngx_ssl_client_hello_arg_index` ex_data (`ngx_event_openssl.c:2024-2026`). BUT the cb then dereferences `cb->servername` unconditionally (`:2063`), so the wrapper MUST NULL-guard that ex_data before chaining (see step 8, inspector C2) — otherwise a handshake crash.
- QUIC `client_hello_cb` invocation is source-confirmed (no QUIC guard in OpenSSL's `tls_early_post_process_client_hello`), but must be empirically verified by producing a `q...` JA4.
- Enum extension (ASN, METHOD reasons) grows the reason-indexed counter arrays; a fresh shm zone is required, which the new `.so` stop+start provides anyway.

**Constraints:**
- Vanilla nginx 1.30.2 dynamic module — no nginx/OpenSSL source patching.
- Bundled OpenSSL 3.5.7 (system OpenSSL 3.0.2 too old for QUIC).
- STREAM TU (`waf_stream.c`) may only include `waf_rep.h` (ngx_core-only); the shm layout stays HTTP-only. JA4 is HTTP-only; ASN/method/detect touch STREAM too — keep the opaque-pointer boundary.
- Build: CMake super-build, `NGX=build/nginx_ext-prefix/src/nginx_ext`. New `.c`/config → re-run `./configure` + `touch $SSL_H` (OpenSSL-rebuild trap) before `make -C $NGX modules` with `PATH=/usr/bin:/bin`; `cmake --build` is broken (PATH bug). New `.so` → nginx stop+start. All builds via `p:minion-builder`. Docker strictly forbidden.

### Non-Functional Requirements

- **Performance**: JA4 computed once per connection (in the ClientHello cb), cached on the `SSL*`; the variable getter is a pointer read. ASN check is a small integer-array scan inside the existing single geo lookup. Method check is an `r->method` bitmask test. No new per-request allocations on the hot path beyond the existing pattern. Detect mode adds one atomic increment.
- **Security**: JA4 string is computed from attacker-controlled ClientHello bytes — the parser must be bounds-checked against the lengths returned by the OpenSSL getters; no client PII is emitted (JA4 is not PII, it is a fingerprint of the TLS stack). The `$waf_ja4_hash`/`$waf_asn` values are bounded fixed-format strings (hex/digits); when surfaced via the stats endpoint they must follow the existing escaping discipline.
- **Scalability**: bounded dimensions only — no per-IP, no per-JA4 stats (JA4 is logged, not counted in shm).

## Architecture Analysis

Findings from codebase exploration (all `file:line` anchors verified against the live tree at `modules/ngx_http_waf/src/` and the nginx source at `build/nginx_ext-prefix/src/nginx_ext/`):

- **Decision chain**: `ngx_http_waf_reputation_check()` (`waf_reputation.c`) runs allowlist → blocklist → geo-flag → CC, with a write-only `out` verdict param NULL-guarded on every branch. `res.asn` (uint32) is already populated by `ngx_http_waf_geo_lookup()` (`waf_geo.c:254`) and available inside `reputation_check` after the lookup.
- **Reason model**: `ngx_http_waf_reason_e` enum (`waf_rep.h:43-54`) with `WAF_REASON_MAX` as the array sizer; `waf_reason_str[WAF_REASON_MAX]` table (`ngx_http_waf_module.c:43-53`), externed in `waf_status.h:132`. Counter arrays (`http_blocked[]`, `stream_denied[]`, vhost `blocked[]`) are all `[WAF_REASON_MAX]` and iterate `WAF_REASON_NONE+1 .. WAF_REASON_MAX`.
- **Directive pattern**: `waf_geo_block` (HTTP `ngx_http_waf_module.c:171-177` + STREAM `waf_stream.c:83-88`) with a custom set-handler writing to a `rep_conf` array — the template for `waf_asn_block` and the method directives. No `ngx_conf_enum_t` usage exists yet — `waf off|detect|enforce` introduces the first.
- **Preaccess handler** (`ngx_http_waf_module.c:457-630`): subrequest filter → enable check → ctx alloc → reputation_check → UA classify → scanner lookup, finalizing with return codes. The method check inserts after reputation_check, before UA classify.
- **Stats**: `ngx_http_waf_stat_shm_t` (`waf_status.h:69-94`) with reason-indexed arrays; 3 serializers iterate them (plain `waf_status.c:202-244`, json `:344-387`, prometheus `:472-511`, plus vhost loops). New reasons appear automatically; `would_block` is added as new reason-indexed arrays with explicit serializer rows.
- **Variable getters**: `$waf_country`/`$waf_type`/`$waf_reason` registered in `ngx_http_waf_preconfiguration` (`ngx_http_waf_module.c:1015-1042`), lazy pattern in `ngx_http_waf_country_variable` (`:1087-1137`) — the template for `$waf_ja4_hash` and `$waf_asn`.
- **Request ctx**: `ngx_http_waf_ctx_t` (`ngx_http_waf.h:89-104`) — extend with `ja4`/`ja4_done` and `asn`/`asn_done`.
- **JA4 hook (the key finding)**: nginx owns the single `client_hello_cb` (`ngx_event_openssl.c:1986`, for SNI), but the callback `ngx_ssl_client_hello_callback` is **non-static and declared in the header** (`ngx_event_openssl.h:299`, under `#ifdef SSL_CLIENT_HELLO_SUCCESS`), and `ngx_ssl_client_hello_arg_index` is `extern int` (`ngx_event_openssl.h:410`). This makes wrapper-chaining feasible from a dynamic module with no patching. The OpenSSL `client_hello_cb` fires on QUIC too (no QUIC guard in `tls_early_post_process_client_hello`, confirmed in OpenSSL 3.5 source).

## Captured Information (for implementation phase)

### File Locations

| Purpose | File Path | Location/Line |
|---------|-----------|---------------|
| reason enum + verdict struct + ASN field | `modules/ngx_http_waf/src/waf_rep.h` | append ASN/METHOD immediately before `WAF_REASON_MAX` at `:53` (NOT before `:52`/SCANNER_PATH — keeps indices stable); verdict struct `:64-69` |
| ASN decision branch | `modules/ngx_http_waf/src/waf_reputation.c` | after flag block (`:107`), before CC |
| ASN set-handler + array helper | `modules/ngx_http_waf/src/waf_reputation.c` | near `ngx_http_waf_country_add` (`:196`) |
| reason string table | `modules/ngx_http_waf/src/ngx_http_waf_module.c` | `:52` (add `ngx_string("asn")`, `ngx_string("method")`) |
| directives (asn/method/waf-enum) | `modules/ngx_http_waf/src/ngx_http_waf_module.c` | command array `:105-235` |
| set-handlers | `modules/ngx_http_waf/src/ngx_http_waf_module.c` | near `ngx_http_waf_set_geo_block` (`:826`) |
| preaccess method check | `modules/ngx_http_waf/src/ngx_http_waf_module.c` | before UA classify (`:552`) |
| enable→mode reads (HTTP) — **ALL sites** | `modules/ngx_http_waf/src/ngx_http_waf_module.c` | POST_READ `:288`, preaccess `:479`, create-default `:649` (→`NGX_CONF_UNSET_UINT`), merge `:663` (→`ngx_conf_merge_uint_value`) |
| enable→mode reads (STREAM) — **ALL sites** | `modules/ngx_http_waf/src/waf_stream.c` | handler read `:167`, create-default `:206` (→`NGX_CONF_UNSET_UINT`), merge `:218` (→`ngx_conf_merge_uint_value`) |
| variable getters ($waf_ja4_hash, $waf_asn) | `modules/ngx_http_waf/src/ngx_http_waf_module.c` | preconf `:1015-1042`; getter template `:1087-1137` |
| postconfig SSL_CTX walk + cb install | `modules/ngx_http_waf/src/ngx_http_waf_module.c` | postconfiguration (after stats vhost-walk) |
| request ctx fields | `modules/ngx_http_waf/src/ngx_http_waf.h` | `:103` (after `reason`) |
| stats shm struct (would_block) | `modules/ngx_http_waf/src/waf_status.h` | after `http_resp_444` (`:82`) and after `stream_denied[]` (`:89`) |
| serializer rows | `modules/ngx_http_waf/src/waf_status.c` | plain `:202-244`, json `:344-387`, prom `:472-511` |
| STREAM asn/method/detect | `modules/ngx_http_waf/src/waf_stream.c` | command array `:67-119`; handler `:155-192` |
| JA4 logic (NEW TU) | `modules/ngx_http_waf/src/waf_ja4.c` + `waf_ja4.h` | new files |
| build registration | `modules/ngx_http_waf/config` | add `waf_ja4.c` |
| cron script (NEW) | `modules/ngx_http_waf/scripts/update-location-db.sh` | new file |
| docs | `README.md` | new sections |

### Type Definitions (copy from codebase)

Reason enum — `waf_rep.h:43-54` (extend before `WAF_REASON_MAX`):
```c
typedef enum {
    WAF_REASON_NONE = 0,
    WAF_REASON_ALLOWLIST,
    WAF_REASON_BLOCKLIST,
    WAF_REASON_GEO,
    WAF_REASON_GEO_WHITELIST,
    WAF_REASON_FLAG,
    WAF_REASON_SCANNER_UA,
    WAF_REASON_EMPTY_UA,
    WAF_REASON_SCANNER_PATH,
    WAF_REASON_ASN,        /* NEW */
    WAF_REASON_METHOD,     /* NEW */
    WAF_REASON_MAX
} ngx_http_waf_reason_e;
```
NOTE: appending before `WAF_REASON_MAX` keeps existing indices stable; the `waf_reason_str[]` table (`ngx_http_waf_module.c:43-53`) must gain `ngx_string("asn")` and `ngx_string("method")` at the matching positions.

Verdict struct — `waf_rep.h:64-69` (add `asn`):
```c
typedef struct {
    ngx_http_waf_reason_e  reason;
    u_char                 country[2];
    uint16_t               flags;
    uint32_t               asn;          /* NEW — copied from res.asn */
    unsigned               geo_valid:1;
} ngx_http_waf_verdict_t;
```

Geo result — `waf_geo.h:53-58` (read-only reference, asn already present):
```c
typedef struct {
    ngx_uint_t   found;
    u_char       country[2];
    uint16_t     flags;
    uint32_t     asn;       /* waf_geo.c:254 fills this */
} ngx_http_waf_geo_result_t;
```

Request ctx — `ngx_http_waf.h:89-104` (extend after `reason`):
```c
    /* ASN — lazy resolved for $waf_asn */
    unsigned   asn_done:1;
    uint32_t   asn;
    /* JA4 — read from SSL ex_data on first access */
    unsigned   ja4_done:1;
    ngx_str_t  ja4;
```

`reputation_check` signature — `waf_rep.h:84` (unchanged):
```c
ngx_int_t ngx_http_waf_reputation_check(ngx_waf_rep_conf_t *rep,
    struct sockaddr *sa, ngx_str_t *reason, ngx_http_waf_verdict_t *out);
```

### Function/Method Signatures (new)

```c
/* waf_ja4.h — new TU */
/* Compute JA4 from a ClientHello inside the wrapper cb. Writes a pool/
 * OpenSSL-alloc'd NUL-terminated string. Returns NGX_OK / NGX_ERROR. */
ngx_int_t ngx_http_waf_ja4_compute(SSL *ssl, ngx_pool_t *pool, ngx_str_t *out);

/* The wrapper callback installed on each server SSL_CTX. */
int ngx_http_waf_ja4_client_hello_cb(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg);

/* ASN array helper, mirrors ngx_http_waf_country_add (waf_reputation.c) */
ngx_int_t ngx_http_waf_asn_add(ngx_conf_t *cf, ngx_array_t **arr, ngx_str_t *val);

/* STREAM-safe opaque would_block helper (inspector H3) — declared in waf_rep.h,
 * defined in ngx_http_waf_module.c. The stream TU must NOT see the HTTP-only
 * ngx_http_waf_stat_shm_t, so it pokes stream_would_block[] via this void* helper,
 * exactly like the existing ngx_http_waf_stat_stream_bump opaque pattern. */
void ngx_http_waf_stat_stream_would_block(void *shm, ngx_http_waf_reason_e reason);
/* NB: use ngx_http_waf_reason_e (not ngx_uint_t) to match the sibling
 * ngx_http_waf_stat_stream_bump signature; the enum is visible in waf_rep.h. */
```

nginx symbols the wrapper depends on (verified non-static, header-declared):
```c
/* ngx_event_openssl.h:296-299 */
ngx_int_t ngx_ssl_set_client_hello_callback(ngx_ssl_t *ssl,
    ngx_ssl_client_hello_arg *cb);
int ngx_ssl_client_hello_callback(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg);
/* ngx_event_openssl.h:410 */
extern int ngx_ssl_client_hello_arg_index;
/* ngx_event_openssl.h:198-202 */
typedef int (*ngx_ssl_servername_pt)(ngx_ssl_conn_t *, int *, void *);
typedef struct { ngx_ssl_servername_pt servername; } ngx_ssl_client_hello_arg;
```

OpenSSL 3.5 ClientHello getters used by `ngx_http_waf_ja4_compute`:
```c
typedef int (*SSL_client_hello_cb_fn)(SSL *s, int *al, void *arg);
unsigned int SSL_client_hello_get0_legacy_version(SSL *s);
size_t SSL_client_hello_get0_ciphers(SSL *s, const unsigned char **out);
int    SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen); /* caller OPENSSL_free(*out) */
int    SSL_client_hello_get0_ext(SSL *s, unsigned int type,
           const unsigned char **out, size_t *outlen); /* 1 present / 0 absent */
```

### Reference Implementation (the lazy variable getter to mirror)

`$waf_country` getter — `ngx_http_waf_module.c:1087-1137` (mirror for `$waf_asn` and `$waf_ja4_hash`):
```c
static ngx_int_t
ngx_http_waf_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) { ctx = ngx_pcalloc(...); ngx_http_set_ctx(...); }

    if (!ctx->geo_done) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        if (wlcf->rep.geo_db != NULL) {
            sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr;
            ngx_http_waf_geo_lookup(wlcf->rep.geo_db, sa, &res);
            if (res.found) { ctx->country[0] = res.country[0]; ctx->country[1] = res.country[1]; }
        }
        ctx->geo_done = 1;
    }
    if (ctx->country[0] == 0) { v->valid = 0; v->no_cacheable = 1; v->not_found = 1; return NGX_OK; }
    v->len = 2; v->data = ctx->country; v->valid = 1; v->no_cacheable = 1; v->not_found = 0;
    return NGX_OK;
}
```

For `$waf_ja4_hash`: the getter MUST null-check `r->connection->ssl` FIRST, then read `r->connection->ssl->connection` (the `SSL*`), then `SSL_get_ex_data(ssl, waf_ja4_ssl_index)`. The JA4 was computed and stored in the wrapper cb at handshake time (no lazy compute — it must happen in the cb because the raw ClientHello is gone afterward). The getter only surfaces the cached string; `not_found` if no SSL or no JA4.

The HTTP→SSL access pattern — guard pattern at `ngx_http_ssl_module.c:580-582` (inspector M1: those lines guard `r->connection->ssl`, they do NOT themselves show the `->connection` SSL* deref — the deref is valid because `ngx_ssl_connection_t` carries a `connection` SSL* field, but null-check the outer `ssl` first):
```c
if (r->connection->ssl) {                 /* guard FIRST */
    SSL *ssl = r->connection->ssl->connection;   /* then the SSL* */
    /* SSL_get_ex_data(ssl, waf_ja4_ssl_index) */
}
```

### Directive Registration Pattern (the template)

`waf_geo_block` command — `ngx_http_waf_module.c:171-177`:
```c
{ ngx_string("waf_geo_block"),
  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
  ngx_http_waf_set_geo_block,
  NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
```
Set-handler — `ngx_http_waf_module.c:826-841`:
```c
static char *
ngx_http_waf_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t *value = cf->args->elts;
    ngx_uint_t i;
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_country_add(cf, &wlcf->rep.block_cc, &value[i]) != NGX_OK)
            return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
```

`waf` three-state enum — replace the existing flag command (`ngx_http_waf_module.c:107-112`):
```c
static ngx_conf_enum_t  ngx_http_waf_mode[] = {
    { ngx_string("off"),     0 },   /* WAF_MODE_OFF */
    { ngx_string("detect"),  1 },   /* WAF_MODE_DETECT */
    { ngx_string("enforce"), 2 },   /* WAF_MODE_ENFORCE */
    { ngx_string("on"),      2 },   /* alias of enforce (backward compat) */
    { ngx_null_string,       0 }
};
/* command: */
{ ngx_string("waf"),
  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
  ngx_conf_set_enum_slot,
  NGX_HTTP_LOC_CONF_OFFSET,
  offsetof(ngx_http_waf_loc_conf_t, mode),
  &ngx_http_waf_mode },
```
`enable` (`ngx_flag_t`) becomes `mode` (`ngx_uint_t`) in `ngx_http_waf_loc_conf_t` (`ngx_http_waf.h:65`). The refactor is a **complete-inventory** change — miss a site and it either fails to compile or silently mis-gates. ALL sites (verified by the inspector):
- **HTTP create-default** `ngx_http_waf_module.c:649`: `conf->enable = NGX_CONF_UNSET;` → `conf->mode = NGX_CONF_UNSET_UINT;`
- **HTTP merge** `:663`: `ngx_conf_merge_value(...)` → `ngx_conf_merge_uint_value(conf->mode, prev->mode, WAF_MODE_ENFORCE)`
- **HTTP POST_READ read** `:288`: `if (!wlcf->enable)` → `if (wlcf->mode == WAF_MODE_OFF)`
- **HTTP preaccess read** `:479`: `if (!wlcf->enable)` → `if (wlcf->mode == WAF_MODE_OFF)`
- **STREAM create-default** `waf_stream.c:206`: → `NGX_CONF_UNSET_UINT`
- **STREAM merge** `:218`: → `ngx_conf_merge_uint_value(..., WAF_MODE_ENFORCE)`
- **STREAM handler read** `:167`: → `if (sscf->mode == WAF_MODE_OFF)`

Every block point additionally gains the detect branch (see Implementation step 4). STREAM `waf_stream` (`waf_stream.c:69-74`) gets the same enum command + the `ngx_conf_set_enum_slot`/`ngx_conf_enum_t` treatment. Define `WAF_MODE_OFF=0 / WAF_MODE_DETECT=1 / WAF_MODE_ENFORCE=2` as macros (e.g. in `waf_rep.h` so both HTTP and STREAM TUs see them).

**Fail-CLOSED invariant (security review, CWE-636):** the create-default is `NGX_CONF_UNSET_UINT` and the merge default is `WAF_MODE_ENFORCE`, so an omitted `waf` directive enforces (fail-safe, never accidentally observe-only). Reinforce this: the block-decision sites treat `detect` as the ONLY non-blocking value (`mode == WAF_MODE_DETECT` → bump would_block + DECLINED); everything else (including any unexpected/unmerged value) takes the blocking path. A missed conversion site must fail CLOSED (block), never open.

### Method Filtering Detail

`r->method` is a bitmask (`NGX_HTTP_GET`, `NGX_HTTP_POST`, …). Build an allowed-mask / denied-mask at config time from the directive args by mapping method names to the `NGX_HTTP_*` bits; for non-standard names (e.g. `TRACK`, `DEBUG`) that lack a bit, keep a small string list and compare `r->method_name`. Preaccess check (insert before UA classify, `ngx_http_waf_module.c:552`):
```c
/* method filter — whitelist wins, then blacklist narrows */
if (wlcf->method_allow_set && !ngx_http_waf_method_allowed(wlcf, r)) {
    /* detect-aware finalize -> 404 / would_block[WAF_REASON_METHOD] */
}
if (wlcf->method_deny_set && ngx_http_waf_method_denied(wlcf, r)) {
    /* detect-aware finalize -> 404 / would_block[WAF_REASON_METHOD] */
}
```

### Stats Counter Extension

`ngx_http_waf_stat_shm_t` (`waf_status.h:69-94`) — add after `http_resp_444` and after `stream_denied[]`:
```c
ngx_atomic_t  http_would_block[WAF_REASON_MAX];    /* detect-mode HTTP */
ngx_atomic_t  stream_would_block[WAF_REASON_MAX];  /* detect-mode L4 */
```
The new `WAF_REASON_ASN` / `WAF_REASON_METHOD` automatically extend `http_blocked[]`, `stream_denied[]`, vhost `blocked[]` and all their serializer loops. The `would_block[]` arrays need explicit serializer rows mirroring the `http_blocked` loops in all three serializers (plain `waf_status.c:202-244`, json `:344-387`, prometheus `:472-511`).

### Build System Entry

`modules/ngx_http_waf/config` — add `waf_ja4.c` to the source list (mirror the existing `waf_status.c` entry registered in Session 3, srcs at `config:23-30`). New `.c` requires `./configure` re-run + `touch $SSL_H` before `make modules`.

**Build precondition (inspector M2):** the postconfig SSL_CTX walk references the extern `ngx_http_ssl_module` and `ngx_http_ssl_srv_conf_t`, so it requires nginx built `--with-http_ssl_module` (already the case — the module needs SSL) and a `#include` of `ngx_http_ssl_module.h` in the WAF HTTP TU (`ngx_http_ssl_srv_conf_t.ssl` at `ngx_http_ssl_module.h:18`, `extern ngx_module_t ngx_http_ssl_module;` at `:72`). The Group B build-clean checkpoint must confirm the extern symbol links cleanly in the dynamic `.so`.

### Resource Ownership Rules

- JA4 string: allocated by the wrapper cb. Two options — (a) `OPENSSL_malloc` + `SSL_set_ex_data` with a free in an `SSL_CTX` ex_data free-callback registered at index creation; (b) allocate from `c->pool` (the `ngx_connection_t` reachable via `SSL_get_ex_data(ssl, ngx_ssl_connection_index)`), freed with the connection pool. **Prefer (b)** — ties JA4 lifetime to the connection, no manual free, matches nginx's allocation discipline. The getter then returns a pointer into `c->pool`, valid for the request lifetime.
- **`get1_extensions_present` leak (MANDATORY, CWE-401):** `SSL_client_hello_get1_extensions_present()` is the ONLY allocating getter — its `*out` MUST be `OPENSSL_free`d on **every** return path of the parser, including the early-exit / fallback-to-`get0_ext` / error / clamp-stop branches. This is the easiest place to leak per-connection memory; make it a single `goto cleanup` or RAII-style discipline.
- The sort scratch and any JA4 working buffers are freed (or pool-scoped) on every path; the parser holds no OpenSSL buffer beyond the cb's lifetime.
- ASN/method config arrays/masks: `cf->pool` (reload-safe), like the existing geo arrays.

### Error Handling Pattern

Fail-open on JA4 compute failure (cb returns `SSL_CLIENT_HELLO_SUCCESS` regardless, after still chaining to nginx's cb — a JA4 failure must never break the handshake). Fail-open on ASN when `asn==0`. Method filter: only acts when the directive is configured. Existing logging via `ngx_log_error(NGX_LOG_INFO/WARN, ...)`.

## Alternative Approaches Evaluated (JA4 hook)

### Option 1: OpenSSL minimal patch
**Pros:** clean raw-ClientHello access; module stays pure. **Cons:** patches bundled OpenSSL; rebase on version bumps.

### Option 2: nginx minimal patch
**Pros:** local change, API in hand. **Cons:** breaks "vanilla nginx"; rebase.

### Option 3: client_hello_cb takeover + SNI reproduction
**Pros:** no patch. **Cons:** must reproduce nginx SNI logic → fragile, risks breaking SNI vhosts.

### Option 4: msg_callback, TCP-only
**Pros:** free hook on TCP, no patch. **Cons:** does NOT cover QUIC.

### Recommended Approach: Wrapper-chain (partner's proposal — selected)
The module installs its own `client_hello_cb` on each server `SSL_CTX` in postconfiguration; the wrapper computes JA4, stores it on the `SSL*`, then **calls the public `ngx_ssl_client_hello_callback()`** so nginx's SNI processing runs unchanged.
**Rationale:** the only option that keeps BOTH vanilla nginx AND a pure dynamic module, while covering TCP+QUIC from one hook (the cb fires on QUIC too). Verified feasible: `ngx_ssl_client_hello_callback` is non-static + header-declared (`ngx_event_openssl.h:299`), `ngx_ssl_client_hello_arg_index` is `extern` (`:410`). No source patching, no SNI reproduction.

## Implementation Strategy

Group A (fast, independent, shares the reason-enum/stats edit so must build together) → Group B (JA4, large/risky) → Group C (docs/script). Build-clean checkpoints between groups via `p:minion-builder`.

### Data Model / API Changes
- Reason enum +2 (ASN, METHOD); verdict struct +`asn`; ctx +`asn`/`asn_done`/`ja4`/`ja4_done`; loc_conf `enable`→`mode` + method masks/lists + asn array; shm struct +`http_would_block[]`/`stream_would_block[]`. No on-disk format changes.

### Backwards Compatibility & Migration
- `waf on;` preserved via enum alias. Existing `waf off;` works (maps to mode 0). Shm layout grows → fresh zone on `.so` reload (stop+start), documented behavior (counters reset). No config migration required for existing deployments except optionally adopting `detect`.

### New Dependencies
- None. JA4 uses OpenSSL functions already linked (`SHA256`, `SSL_client_hello_get0_*`). No new libraries.

### Configuration Changes
- New directives: `waf_asn_block`, `waf_method_allow`, `waf_method_deny`; `waf` gains `detect`/`enforce`/`off`/`on`. New variables: `$waf_ja4_hash`, `$waf_asn`.

## Step-by-Step Implementation Plan

1. **Reason enum + string table + verdict.asn** (`waf_rep.h`, `ngx_http_waf_module.c:43-53`): add `WAF_REASON_ASN`, `WAF_REASON_METHOD`; add table strings; add `asn` to verdict struct. *(Group A — touches the shared enum, so steps 2-6 build together.)*
2. **ASN decision branch + set-handler + `$waf_asn`** (`waf_reputation.c`, `ngx_http_waf_module.c`): array `block_asn` in rep_conf; `waf_asn_block` directive (HTTP+STREAM); branch after flag (`waf_reputation.c:107`), `out->asn = res.asn`; `$waf_asn` lazy getter mirroring `$waf_country`.
3. **Method filter** (`ngx_http_waf_module.c`, `waf_stream.c`): `waf_method_allow`/`waf_method_deny` directives; config-time mask/list build; preaccess check before UA classify → 404; STREAM has no methods (HTTP-only — document; STREAM gets ASN + detect only).
4. **`waf` three-state enum + detect** (`ngx_http_waf.h`, `ngx_http_waf_module.c`, `waf_stream.c`): `enable`→`mode` (convert ALL 7 sites listed in the directive-pattern section — inspector C1/H1/H2); enum + `on` alias; `WAF_MODE_*` macros in `waf_rep.h`. Add a detect-aware finalize helper that, in `mode==WAF_MODE_DETECT`, bumps `would_block[reason]` and returns `NGX_DECLINED` instead of the block code, at every HTTP decision point. For STREAM, the detect path calls the new opaque `ngx_http_waf_stat_stream_would_block(shm, reason)` helper (inspector H3 — the stream TU cannot see the HTTP-only shm struct) and returns `NGX_DECLINED`.
5. **Stats would_block + new-reason serializer rows** (`waf_status.h`, `waf_status.c`): add `http_would_block[]`/`stream_would_block[]`; add serializer rows in all 3 formats; verify ASN/METHOD reasons render via the existing reason loops.
6. **Group A build-clean checkpoint** (`p:minion-builder`): `-Werror -W -Wall`, then run the curl harness with new ASN/method/detect assertions.
7. **JA4 TU + ctx + getter** (`waf_ja4.c/.h`, `ngx_http_waf.h`, `ngx_http_waf_module.c`, `config`): `ngx_http_waf_ja4_compute` (parse ciphers/extensions/sig-algs, GREASE filter `(v & 0x0f0f)==0x0a0a`, sort, SHA256[:12], assemble `a_b_c`); `$waf_ja4_hash` getter reading `SSL*` ex_data; register `waf_ja4.c` in config.
   - **The parser processes attacker-controlled ClientHello bytes — bounds-safety is MANDATORY (security review, CWE-125/787/190/401):**
     - **Count clamp (CWE-190):** the `a`-part counts are 2-digit decimal — clamp cipher/extension counts to `99` per the FoxIO spec. Define an explicit `WAF_JA4_MAX_ELEMS` bound; reject/stop processing beyond it so a GREASE-padded ClientHello with thousands of entries cannot overflow the sort scratch or format buffers.
     - **Bounded copy before sort (CWE-787):** sort a heap/pool **copy** sized `count * sizeof(uint16_t)` with `count` ALREADY clamped — never sort in place on the OpenSSL buffer, never alloc from an unclamped count.
     - **Fixed output buffer:** JA4 is bounded (`a`=10 + `_` + `b`=12 + `_` + `c`=12 = 36 bytes). Use a fixed buffer and `ngx_snprintf(buf, sizeof(buf), ...)` everywhere — assert no unbounded write.
     - **ALPN hex-fallback is a HARD invariant (CWE-116/117), not an edge case:** the `a`-part ALPN char comes from the attacker-controlled ALPN extension. If the first/last byte is not ASCII-alphanumeric, emit its hex representation (per spec). This is simultaneously the injection-safety control that keeps the JSON/plain/prometheus stats serializers safe — if skipped, a crafted ALPN could inject `"`/newline. Tie this to step 5.
     - **Every read bounded by the getter's returned length** (no trust in embedded length fields beyond the getter buffer); a zero-length / malformed return → fail-open (no JA4), never a crash.
8. **Wrapper cb + postconfig SSL_CTX walk** (`ngx_http_waf_module.c`): allocate a module `SSL_get_ex_new_index()` for JA4; in postconfiguration walk `cmcf->servers` → `sscf->ssl.ctx` (cast via `ngx_http_ssl_module.ctx_index`, mirroring the existing stats vhost-walk at `:1320-1323`), and for each ctx that already has nginx's client_hello cb installed, `SSL_CTX_set_client_hello_cb(ctx, ngx_http_waf_ja4_client_hello_cb, NULL)`; wrapper computes JA4 (protocol `q` if QUIC via `SSL_is_quic`, else `t`), stores on `SSL*`, then chains.
   - **CRITICAL — NULL-guard the chain (inspector C2).** nginx's `ngx_ssl_client_hello_callback` unconditionally dereferences `cb->servername` (`ngx_event_openssl.c:2063`), where `cb` comes from `SSL_CTX_get_ex_data(session_ctx, ngx_ssl_client_hello_arg_index)` (`:2024-2026`). nginx only populates that ex_data inside `ngx_ssl_set_client_hello_callback` (`:1982`), invoked from `ngx_http_ssl_module.c:778` **only under `#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME`**. The wrapper MUST: fetch `arg = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl_conn), ngx_ssl_client_hello_arg_index)` (nginx itself reads from `c->ssl->session_ctx` at `:2024`, but at ClientHello-callback time — before any SNI cert-callback CTX switch — `session_ctx == SSL_get_SSL_CTX(ssl_conn)`; add a code comment noting this equivalence to harden against future SNI-switch surprises); **if `arg == NULL`, skip the chain and return `SSL_CLIENT_HELLO_SUCCESS`** (do NOT call `ngx_ssl_client_hello_callback`); otherwise chain to `ngx_ssl_client_hello_callback(ssl_conn, ad, NULL)` and return its result.
   - **Ordering (inspector C2).** WAF postconfiguration must run AFTER `ngx_http_ssl_module` merge_srv_conf installed nginx's cb + arg ex_data. Module postconfiguration order follows module load order; verify the WAF module loads after `ngx_http_ssl_module` (it does, being an add-dynamic-module). Install the wrapper only on contexts where `sscf->ssl.ctx != NULL` AND the client_hello arg ex_data is already set — otherwise leave that ctx untouched (no SSL configured → no JA4 needed there anyway).
   - **Note:** the wrapper only intercepts the client_hello cb. nginx's *separate* `SSL_CTX_set_tlsext_servername_callback` (`ngx_http_ssl_module.c:782`) is untouched, so the SNI servername-callback path is unaffected (inspector note).
9. **Group B build-clean checkpoint** (`p:minion-builder`); then TCP JA4 test (openssl s_client) + **Wireshark bit-for-bit calibration**; if `get1_extensions_present` is incomplete, fall back to explicit `get0_ext` reads for 0x002b/0x0010/0x000d.
10. **QUIC empirical verification**: produce a `q...` JA4 over HTTP/3 (curl/nginx HTTP-3 listener); confirm the wrapper fires on QUIC and SNI/cert selection still works.
11. **location.db cron script + README** (`scripts/update-location-db.sh`, `README.md`): download → **verify authenticity** → validate → atomic rename → `nginx -s reload`; document placement, schedule, zone-reset caveat.
   - **Supply-chain integrity is MANDATORY (security review — magic-only validation is integrity-theater; `waf_geo.c:110` only checks the libloc magic, which a MITM/compromised-mirror controls trivially). A poisoned DB silently corrupts geo/ASN/country decisions AND `waf_asn_block` enforcement → control bypass or self-DoS.**
     - **CWE-494/CWE-345:** fetch over **HTTPS with certificate verification** (fixed, constant URL — never interpolated from anything external) AND **verify IPFire's published GPG signature** of the DB (or a pinned SHA256 from a separately-fetched signed manifest) BEFORE the swap. The libloc magic/version check is a sanity check, NOT the integrity control — state this explicitly in the script and README.
     - **CWE-367 (TOCTOU):** validate the SAME file that gets `rename()`d. Create the temp file **in the target directory** (same filesystem, so `rename(tmp, final)` is truly atomic — not `/tmp` across a mount); verify signature + magic on that temp file in place; never re-download between verify and rename; never validate one path and swap another.
     - **Least privilege:** the cron job runs as a non-root user that owns the DB file and is authorized to signal the nginx master for `-s reload`; document this. Do not run the whole download-then-reload chain as root.
12. **README map-pattern docs** (`README.md`): `map $waf_type $waf_deny { ... }` + `if ($waf_deny) return 403;`, plus the new `waf detect`, `waf_asn_block`, `waf_method_*`, `$waf_ja4_hash`, `$waf_asn`.

## Error Handling & Edge Cases

### Error Scenarios
- **JA4 compute fails / no extensions** → fail-open: still chain to nginx cb, return SUCCESS, leave JA4 unset (`$waf_ja4_hash` → not_found). Never break the handshake.
- **No SSL on connection** (plain HTTP) → `$waf_ja4_hash` not_found.
- **ASN lookup returns 0** → pass (fail-open).
- **Method directive unset** → no method filtering.

### Edge Cases
- GREASE values in ciphers/extensions/sig-algs → filtered from all lists (count and hash).
- ALPN absent → JA4 `a` part positions 9-10 = `00`; non-alphanumeric ALPN byte → hex-char fallback (per spec).
- supported_versions absent → use legacy_version for the `a` part version code.
- No sig-algs → omit the `_` and sig-alg segment in the `c` hash input.
- Internal redirect (index/try_files) re-runs preaccess → counters already re-count by design (Session 3 decision); detect would_block likewise.
- `waf on` legacy config → enum alias maps to enforce.

### Validation
- JA4 parser must bound every read by the length returned from the OpenSSL getter (no trust in embedded length fields beyond the getter's buffer).
- ASN args parsed as decimal uint32; reject non-numeric at config time.

## Testing Strategy

### Unit / Component
- JA4 assembly against the FoxIO canonical vector `t13d1516h2_8daaf6152771_e5627efa2ab1` (feed a known cipher/extension/sig-alg set, assert the exact string).
- GREASE filtering, ALPN hex-fallback, empty-sig-alg `c`-hash path.

### Integration (extend `modules/ngx_http_waf/tests/run-stat-tests.sh`)
- `waf_asn_block` blocks a matching ASN (needs a geo DB entry or a synthetic lookup); non-listed passes.
- `waf_method_allow GET POST HEAD` → `PUT`/`DELETE`/`TRACE` get 404.
- `waf_method_deny TRACE TRACK` → 404; `GET` passes.
- `waf detect` → request passes (200/expected) while `would_block[reason]` increments (assert via the stats endpoint).
- `waf on` parses and enforces.
- Stats endpoints expose `asn`/`method` reasons and `would_block` in all 3 formats.

### Manual / TLS
- [ ] `openssl s_client` with distinct cipher profiles → `$waf_ja4_hash` matches Wireshark JA4.
- [ ] HTTP/3 request → `q...` JA4 produced; SNI vhost + cert selection unaffected.
- [ ] Confirm `ngx_ssl_client_hello_callback` 3rd-arg NULL behavior via a multi-vhost SNI test.

### Security Testing
- [ ] Malformed/truncated ClientHello (fuzz vectors) → no crash, fail-open, handshake unaffected.
- [ ] **Oversized input (CWE-190/787):** ClientHello with thousands of GREASE-padded ciphers/extensions and a zero-length getter return → count clamp holds, no buffer overflow, no undersized alloc.
- [ ] **`get1_extensions_present` leak (CWE-401):** valgrind/ASAN a few thousand handshakes → no per-connection leak on any parser path.
- [ ] **ALPN injection (CWE-116/117):** craft an ALPN containing `"`/newline/non-alphanumeric bytes → JA4 `a`-part uses hex-fallback; the json/plain/prometheus stats output stays well-formed (no injection).
- [ ] JA4 string emitted to stats follows escaping discipline (fixed hex/charset; assert no injection via the prometheus/json serializers).

## Monitoring & Observability

### Logging
- Block events: existing `ngx_log_error(NGX_LOG_INFO, ...)` extended with ASN/method reasons.
- Access log: `$waf_ja4_hash`, `$waf_asn`, `$waf_country`, `$waf_reason`, `$waf_type` together.

### Metrics
- New reason counters (`asn`, `method`) in `http_blocked`/`stream_denied`/vhost `blocked`.
- `would_block[reason]` (HTTP + stream) for detect-mode observability.

### Debugging
- The stats endpoint is the primary observability surface; detect-mode `would_block` is the dry-run signal before enforcing.

## Documentation Updates Required

### Code Documentation
- [ ] Doxygen-style comments on `ngx_http_waf_ja4_compute` and the wrapper cb.
- [ ] Comment the enum alias and the detect-aware finalize helper.

### External Documentation (`README.md`)
- [ ] `waf off|detect|enforce` (+ `on` alias) directive.
- [ ] `waf_asn_block`, `waf_method_allow`, `waf_method_deny`.
- [ ] `$waf_ja4_hash`, `$waf_asn` variables.
- [ ] "Statistics" section: new reasons + would_block.
- [ ] `map`-based config-level blocking pattern.
- [ ] location.db cron usage + zone-reset caveat.

### New Documentation
- [ ] `scripts/update-location-db.sh` header comment documenting download URL, validation, atomic swap, reload.

## Dependencies & Sequencing

- Group A (steps 1-6) is self-contained and unblocks nothing external; build together due to shared enum/stats edits.
- Group B (steps 7-10) depends only on step 1 (the reason enum, though JA4 adds no reason — it is observability-only; no reason needed). JA4 is otherwise independent.
- Group C (steps 11-12) is docs/script, depends on the final directive/variable names.

## Potential Challenges

- **QUIC client_hello_cb (highest risk)**: source-confirmed to fire, but the nginx old-QUIC-API path is not publicly documented for this; step 10 is an explicit empirical gate. If it does NOT fire on QUIC, fall back to documenting JA4 as TCP-only for now (the `t` path still ships) and open a follow-up.
- **`get1_extensions_present` completeness**: may under-report extensions on this OpenSSL build; mitigated by explicit `get0_ext` reads + Wireshark calibration (step 9).
- **`waf` enum refactor regression surface**: every `enable` read across HTTP+STREAM changes; the Group A build-clean checkpoint + existing tests guard this.
- **Wrapper chain NULL-deref (CRITICAL, inspector C2)**: nginx's chained cb dereferences `cb->servername` from ex_data unconditionally; if that ex_data is unset on a ctx the wrapper touched, the handshake crashes. Mitigated by the mandatory NULL-guard + install-only-where-set + ordering rules in step 8.

## Critical Files for Implementation

- `modules/ngx_http_waf/src/waf_rep.h` — reason enum, verdict.asn.
- `modules/ngx_http_waf/src/waf_reputation.c` — ASN branch, asn_add helper.
- `modules/ngx_http_waf/src/ngx_http_waf_module.c` — directives, preaccess method check, enable→mode, detect finalize, getters, postconfig SSL walk, wrapper cb.
- `modules/ngx_http_waf/src/ngx_http_waf.h` — loc_conf mode + method config; ctx fields.
- `modules/ngx_http_waf/src/waf_status.h` / `waf_status.c` — would_block counters + serializer rows.
- `modules/ngx_http_waf/src/waf_stream.c` — STREAM ASN + detect (no method/JA4).
- `modules/ngx_http_waf/src/waf_ja4.c` / `waf_ja4.h` — NEW: JA4 parser + hash + wrapper cb.
- `modules/ngx_http_waf/config` — register `waf_ja4.c`.
- `modules/ngx_http_waf/scripts/update-location-db.sh` — NEW: cron script.
- `README.md` — all new directives/variables + map pattern + cron docs.

## Post-Implementation Checklist

- [ ] All outputs in English.
- [ ] Build clean `-Werror -W -Wall` (via p:minion-builder).
- [ ] Curl integration harness passes (existing + new).
- [ ] JA4 matches Wireshark (TCP); `q...` JA4 produced (QUIC) OR JA4 documented TCP-only with follow-up.
- [ ] SNI vhosts + cert selection unaffected by the wrapper.
- [ ] `waf on` backward compatibility verified.
- [ ] Detect-mode would_block counters verified against enforce-mode block counters.
- [ ] Stats endpoints expose new reasons + would_block in all 3 formats.
- [ ] cron script validates before atomic swap.
- [ ] README updated.
- [ ] Security review completed (Checkpoint 5 Phase B).
