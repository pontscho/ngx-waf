# Implementation Plan: heavybag Statistics / Status Module

## Requirements Summary

Add a lock-free statistics and status subsystem to the existing `ngx_http_heavybag` module
(which ships one `.so` containing both `ngx_http_heavybag_module` (HTTP) and
`ngx_stream_heavybag_module` (STREAM)). The subsystem must:

1. Maintain in-process, cross-worker counters of every heavybag verdict, the UA
   classification distribution, and a small set of bounded dimensional breakdowns
   (per-country, per-vhost), using a single shared-memory zone of `ngx_atomic_t`
   counters. No slab allocator, no rbtree, no mutex — the entire data path is
   lock-free.
2. Expose those counters over an HTTP endpoint analogous to `stub_status`, via a
   `waf_status;` content-handler directive, in three formats selected by URI path:
   `/waf/stat/prometheus`, `/waf/stat/json`, `/waf/stat/plain` (default).
3. Re-export the nginx core stub_status connection table (`ngx_stat_active`, …)
   behind `#if (NGX_STAT_STUB)` so the endpoint is a stub_status superset.
4. Add two new log-format variables, `$waf_country` and `$waf_reason`, alongside the
   existing `$waf_type`, all sharing one per-request verdict decision (one geo lookup
   per request, cached in the request ctx).

### Success Criteria

- [ ] `GET /waf/stat/plain` returns a stub_status-style plaintext block including heavybag
      verdict counters and (when `--with-http_stub_status_module` was compiled in) the
      core connection table.
- [ ] `GET /waf/stat/prometheus` returns valid Prometheus text-exposition output with
      bounded labels only (`reason`, `country`, `server`, `flag`) — never a raw client IP.
- [ ] `GET /waf/stat/json` returns a well-formed JSON object with the same data nested.
- [ ] Triggering each verdict class (blocklist 403, geo-country 403, network-flag 403,
      geo-not-whitelisted 404, scanner-UA 404, empty-UA 404, scanner-path 404/403/444)
      increments exactly the corresponding counter, verified across all three formats.
- [ ] A STREAM-level reputation block increments the STREAM counter block.
- [ ] `$waf_type` is unchanged; `$waf_country` resolves to the 2-letter ISO code when a
      geo record exists (and geo is configured), otherwise `not_found`; `$waf_reason`
      resolves to the verdict token (e.g. `scanner_path`, `geo`, `flag`, `blocklist`,
      `none`).
- [ ] At most ONE geo lookup is performed per request even when all of
      `$waf_country` + geo blocking + per-country counter are active (shared ctx cache).
- [ ] Per-country counters increment ONLY when a geo lookup actually ran (geo
      configured); with geo disabled there is no per-country data and no extra lookup.
- [ ] Counters survive a `nginx -s reload` (shm zone re-attach preserves values) AS LONG
      AS the zone size is unchanged; a change in `server{}` count changes the per-vhost
      array size, forces a fresh segment, and resets counters (documented, accepted).
- [ ] `nginx -t` passes; the `.so` loads; no regression in existing heavybag behaviour.

### Scope

**In Scope:**
- Single always-on shared-memory zone `waf_status` holding all counters.
- HTTP verdict counters, UA distribution, per-reason breakdown, per-flag breakdown,
  per-country `{total, blocked}`, per-vhost verdict counters.
- STREAM verdict counters (global block) feeding the shared per-country table when geo
  resolved.
- Health/meta fields: `heavybag_up`, start time (master cycle-init epoch) / uptime, `last_reload_time`, geo DB
  health (loaded?, libloc `created-at`, network count, vendor), loaded-list cardinalities.
- Core stub_status connection table re-export behind `#if (NGX_STAT_STUB)`.
- `waf_status` content-handler directive with path-based format selection (3 formats).
- New variables `$waf_country`, `$waf_reason`; extension of `ngx_http_heavybag_ctx_t`.
- Introduction of `ngx_http_heavybag_reason_e` enum + string tables as the single verdict
  source feeding counters, the `$waf_reason` variable, and the human log message.
- New module conf slots: `create_main_conf`/`init_main_conf` (shm pointer) and
  `create_srv_conf`/`merge_srv_conf` (per-vhost stat index).
- Build glue: register `src/heavybag_status.c` in the addon `config`.

**Out of Scope:**
- Top-N client-IP tracking (rejected by design — high-cardinality, log-redundant, and
  the only lock-requiring/flood-hot path; belongs in the access log + log aggregation).
- Per-IP labels in any output format.
- A STREAM-side `$waf_country`/`$waf_reason` log variable (STREAM uses
  `ngx_stream_log_module` variables; deferred — counters only at L4 for now).
- Persisting counters to disk across a full restart (only `reload` re-attach is in scope).
- An exact `reload_generation` counter (replaced by `last_reload_time`).
- Any new third-party dependency.

### Assumptions & Constraints

**Assumptions:**
- The heavybag `.so` is loaded as a dynamic module and nginx is built `--with-stream`
  (per the addon `config` header comment).
- The per-vhost index is derived by walking `cmcf->servers` at postconfiguration; a
  request whose server has no assigned index (theoretical edge) still updates the global
  counters and falls back to per-vhost index 0.
- libloc country codes are exactly 2 printable uppercase ASCII bytes in
  `res.country[0..1]`; no NUL terminator and no CC↔string conversion table is needed.
- The ISO-3166 country space plus the libloc specials (`A1`,`A2`,`A3`,`T1`,`XD`) is a
  closed set small enough (< ~512) for a fixed open-addressed table pre-sized at init.

**Constraints:**
- The counter HOT PATH MUST be lock-free (`ngx_atomic_fetch_add` only): no slab
  allocation, no rbtree, no shared mutex per request. Note: nginx core overlays an
  `ngx_slab_pool_t` header on EVERY shared zone (`ngx_init_zone_pool`), so the slab pool
  is unavoidably present — it is used ONLY for the one-time allocation of the fixed
  counter struct at zone init (`ngx_slab_alloc`), never on the request path.
- Counters MUST be cheap enough to live on the request hot path with negligible cost.
- MUST NOT add a geo lookup to requests that do not already perform one (geo disabled
  ⇒ no per-country, no forced lookup).
- `reputation_check` is shared by HTTP, STREAM, and SMTP-auth callers — its signature
  change MUST remain backward-safe for the callers that do not want geo output (pass
  NULL).
- Code, comments, and docs in English; tab indentation, `snake_case`, nginx idioms.

### Non-Functional Requirements
- **Performance**: per-request overhead = a handful of `ngx_atomic_fetch_add` calls on
  already-resolved data; zero added geo lookups; zero locks. Status-endpoint rendering
  is O(counters) and runs only on explicit scrape.
- **Security**: the endpoint exposes operational counters only (no PII, no client IPs,
  no request contents). It MUST be access-restricted by the operator
  (`allow`/`deny`); the plan documents this but does not enforce network policy.
  Mandatory security requirements to encode in the implementation (from plan-stage
  threat triage):
  - **Output escaping at the boundary (do NOT trust the geo DB).** The "2 printable
    uppercase ASCII" country-byte property is an ASSUMPTION about `location.db`, not a
    validated invariant — a malformed/hostile DB could carry bytes that break the output
    format. The JSON serializer MUST escape `"`, `\`, and control chars per RFC 8259; the
    Prometheus serializer MUST escape `\`, `"`, and `\n` in every label value (country,
    server, reason, flag) per the text-exposition spec. Server names (config-derived) and
    country bytes both flow through this escaping unconditionally.
  - **Integer-overflow guard** on the zone-size and buffer-size computations
    (`sizeof(shm) + nvhosts*sizeof(vhost_block)`, and the serializer upper-bound) before
    `ngx_slab_alloc` / buffer allocation.
  - **NULL-guard the new `out` param** in `reputation_check`: every `out->...` write MUST
    be skipped when `out == NULL` (the SMTP-auth caller passes NULL). The verdict
    `return rc` paths MUST stay byte-identical — `out` is write-only side data and MUST
    NOT alter the control flow of any of the three callers' security decision.
  - **Access-phase ordering**: the content handler runs in the content phase, AFTER the
    access phase, so operator `allow`/`deny` is enforced before any counter is rendered.
    Verify the handler does not short-circuit the access phase.
  - **No path/host leak** in the geo-DB health block: expose libloc `created-at`, vendor,
    and network count only — never the DB filesystem path or build-host details.
- **Scalability**: fixed memory footprint independent of traffic volume or attacker
  cardinality (bounded dimensions only).
- **Observability**: this feature *is* the observability surface; it must itself be
  debuggable via the existing `"waf: "` log convention.

## Architecture Analysis

Key findings from codebase exploration (all `file:line` anchors verified against the
live tree at `/mnt/nvme/imaginarium/openresty/modules/ngx_http_heavybag/`):

- **No shared state today.** `ngx_http_heavybag.h:57-61` explicitly documents that the
  module carries no shared writable state; workers are stateless w.r.t. each other.
  There is nothing to reuse — the shm zone is built from scratch.
- **Only loc conf exists.** `ngx_http_heavybag_module_ctx` (`ngx_http_heavybag_module.c:196-208`)
  has NULL `create_main_conf`, `create_srv_conf`. The stats subsystem needs a main conf
  (to hold the shm zone pointer) and a srv conf (to hold a per-vhost stat index).
- **All HTTP verdicts funnel through one handler.**
  `ngx_http_heavybag_preaccess_handler` (`ngx_http_heavybag_module.c:286-347`) is the single point
  where every HTTP verdict is decided and returned. Counter increments belong here.
- **All L4 verdicts funnel through one handler.** `ngx_stream_heavybag_handler`
  (`heavybag_stream.c:142-165`) — two outcomes only (`NGX_DECLINED` / `NGX_STREAM_FORBIDDEN`).
- **`reputation_check` is the shared verdict core** (`heavybag_reputation.c:14-98`), called
  by HTTP (`:316`), STREAM (`heavybag_stream.c:155`), and SMTP-auth (`heavybag_authhttp.c:65`). It
  computes the geo result into a *local* `res` and discards it; the reason is set via `ngx_str_set` to
  static human strings. It returns only `NGX_DECLINED` / `NGX_HTTP_FORBIDDEN` /
  `NGX_HTTP_NOT_FOUND`.
- **The 403 verdict is overloaded** — blocklist, network-flag, and geo-country all
  return `NGX_HTTP_FORBIDDEN`, distinguished only by the human `reason` string. To get
  per-reason counters and a clean `$waf_reason`, a `reason_e` enum must become the
  single source of truth (mirroring the existing `heavybag_type_str[]` table at
  `ngx_http_heavybag_module.c:26-33`).
- **Variable getter pattern is clean and copyable** — `$waf_type` getter at
  `ngx_http_heavybag_module.c:698-730`, registered in `ngx_http_heavybag_preconfiguration`
  (`:681-695`). New variables mirror this exactly.
- **Build is `config`-only.** Sources are a shell here-string in
  `modules/ngx_http_heavybag/config:22-28`; adding `src/heavybag_status.c` is a one-line edit +
  reconfigure. `CMakeLists.txt` already passes `--add-dynamic-module=` and provides the
  `heavybag_module` fast-rebuild target (`CMakeLists.txt:105-110`).
- **No test framework exists** for the module — testing is curl-based integration
  against the sandbox nginx.

### Logging / error-handling convention
Prefix `"waf: "`, `NGX_LOG_INFO` for verdicts, `NGX_LOG_WARN` for config warnings,
`NGX_LOG_EMERG`/`ngx_conf_log_error` for config errors; errno arg always `0`; `%V` for
`ngx_str_t *`, `%i` for `ngx_int_t`. New code follows this verbatim.

## Captured Information (for implementation phase)

**The implementation agent should not need to re-read source files. Everything needed
is captured below.**

### File Locations

| Purpose | File Path | Location |
|---------|-----------|----------|
| reason enum + verdict type | `modules/ngx_http_heavybag/src/heavybag_rep.h` | core-only header (`:43` proto region) |
| reason string table `heavybag_reason_str[]` | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | next to `heavybag_type_str[]` `:26-33` |
| ctx struct extension | `modules/ngx_http_heavybag/src/ngx_http_heavybag.h` | inside `ngx_http_heavybag_ctx_t` `:89-99` |
| shm counter struct defs | `modules/ngx_http_heavybag/src/heavybag_status.h` (NEW) | new file |
| main/srv conf structs | `modules/ngx_http_heavybag/src/ngx_http_heavybag.h` | new structs near loc conf `:64-81` |
| `reputation_check` out-param | `modules/ngx_http_heavybag/src/heavybag_reputation.c` | signature `:14`, body `:14-98` |
| `reputation_check` decl | `modules/ngx_http_heavybag/src/heavybag_rep.h` | `:43` |
| HTTP counter increments | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | in `preaccess_handler` `:286-347` |
| STREAM counter increments | `modules/ngx_http_heavybag/src/heavybag_stream.c` | in `ngx_stream_heavybag_handler` `:142-165` |
| new variables registration | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | in `preconfiguration` `:681-695` |
| new variable getters | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | after `$waf_type` getter `:730` |
| module ctx conf slots | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | `ngx_http_heavybag_module_ctx` `:196-208` |
| shm zone creation | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | `postconfiguration` `:733-761` or new `init_main_conf` |
| per-vhost index assignment | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | `postconfiguration` `:733-761` |
| `waf_status` command entry | `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` | `ngx_http_heavybag_commands[]` `:70-193` |
| status handler + serializers | `modules/ngx_http_heavybag/src/heavybag_status.c` (NEW) | new file |
| build registration | `modules/ngx_http_heavybag/config` | `heavybag_srcs` `:22-28`, `heavybag_deps` `:14-20` |

### Current `ngx_http_heavybag_ctx_t` (to extend) — `ngx_http_heavybag.h:89-99`
```c
typedef struct {
    unsigned          spoof_swap:1;   /* replace body with Apache error page */
    unsigned          spoof_done:1;   /* Apache body already emitted         */
    unsigned          classified:1;   /* ua field already computed            */
    ngx_str_t         spoof_body;     /* synthesized Apache error page        */

    struct sockaddr  *client_sa;      /* canonical client addr (POST_READ)    */
    socklen_t         client_socklen;

    ngx_http_heavybag_ua_e ua;             /* $waf_type outcome (valid iff classified) */
} ngx_http_heavybag_ctx_t;
```

**Planned extension** (append fields; keep bitfields packed):
```c
    unsigned              geo_done:1;   /* country[] resolved (lazy guard)        */
    unsigned              verdict_set:1;/* reason resolved by the preaccess handler*/
    u_char                country[2];   /* ISO-2 verbatim from geo; {0,0}=unknown  */
    ngx_http_heavybag_reason_e reason;       /* $waf_reason outcome (valid iff verdict_set) */
```

### `$waf_type` getter to mirror — `ngx_http_heavybag_module.c:698-730`
```c
static ngx_int_t
ngx_http_heavybag_type_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t                *s;
    ngx_http_heavybag_ctx_t       *ctx;
    ngx_http_heavybag_loc_conf_t  *wlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }
    if (!ctx->classified) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);
        ngx_http_heavybag_ua_classify(r, wlcf, ctx);
    }
    s = &heavybag_type_str[ctx->ua];
    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}
```
Registration — `ngx_http_heavybag_module.c:681-695`:
```c
static ngx_int_t
ngx_http_heavybag_preconfiguration(ngx_conf_t *cf)
{
    ngx_str_t             name = ngx_string("waf_type");
    ngx_http_variable_t  *var;
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) { return NGX_ERROR; }
    var->get_handler = ngx_http_heavybag_type_variable;
    return NGX_OK;
}
```

### `ngx_http_heavybag_preaccess_handler` (verdict decision points) — `ngx_http_heavybag_module.c:286-347`
```c
static ngx_int_t
ngx_http_heavybag_preaccess_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_str_t                 reason;
    struct sockaddr          *sa;
    ngx_http_heavybag_ctx_t       *ctx;
    ngx_http_heavybag_loc_conf_t  *wlcf;

    if (r != r->main) { return NGX_DECLINED; }
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);
    if (!wlcf->enable) { return NGX_DECLINED; }

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) { return NGX_ERROR; }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }

    sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr;

    rc = ngx_http_heavybag_reputation_check(&wlcf->rep, sa, &reason);
    if (rc != NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: reputation block (%V)", &reason);
        return rc;                    /* 403 or 404 */
    }

    ngx_http_heavybag_ua_classify(r, wlcf, ctx);

    if (wlcf->bot_block
        && (ctx->ua == HEAVYBAG_UA_SCANNER || ctx->ua == HEAVYBAG_UA_EMPTY)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: %V user-agent blocked", &heavybag_type_str[ctx->ua]);
        return NGX_HTTP_NOT_FOUND;
    }

    rc = ngx_http_heavybag_scanner_lookup(wlcf, &r->uri);
    if (rc != NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: scanner path \"%V\" blocked (%i)", &r->uri, rc);
        return rc;                    /* 404/403/444 */
    }

    return NGX_DECLINED;
}
```

### `ngx_http_heavybag_reputation_check` (to extend with geo/reason out) — `heavybag_reputation.c:14-98`
Current signature (`heavybag_rep.h:43`):
```c
ngx_int_t ngx_http_heavybag_reputation_check(ngx_heavybag_rep_conf_t *rep,
    struct sockaddr *sa, ngx_str_t *reason);
```
Key internals: geo lookup at `heavybag_reputation.c:46` into local `res`; packed code
`cc16 = (res.country[0] << 8) | res.country[1]` at `:67`. Decision branches set
`reason` via `ngx_str_set(...)` to: `"static blocklist"` (403), `"geo not whitelisted"`
(404), `"network flag"` (403), `"geo country"` (403). Returns `NGX_DECLINED` on allow.

**Planned new signature** (append an optional output struct; existing callers pass
NULL where they do not need it). The verdict type and reason enum live in **`heavybag_rep.h`**
(ngx_core-only), so they must NOT embed `ngx_http_heavybag_geo_result_t` by value (that type
lives in `heavybag_geo.h`, which the stream TU does not include). Store only the primitive
geo fields needed:
```c
/* in heavybag_rep.h, alongside the prototype */
typedef enum { /* ... */ } ngx_http_heavybag_reason_e;

typedef struct {
    ngx_http_heavybag_reason_e  reason;        /* HEAVYBAG_REASON_* token, set on every return */
    u_char                 country[2];    /* copied from res.country; {0,0} if none  */
    uint16_t               flags;         /* copied from res.flags                    */
    unsigned               geo_valid:1;   /* a geo lookup actually ran                */
} ngx_http_heavybag_verdict_t;

ngx_int_t ngx_http_heavybag_reputation_check(ngx_heavybag_rep_conf_t *rep,
    struct sockaddr *sa, ngx_str_t *reason, ngx_http_heavybag_verdict_t *out /* may be NULL */);
```
`out->geo_valid` is set iff a geo lookup ran; `out->reason` is set on every return.
The human `reason` string remains for log compatibility (or is derived from
`heavybag_reason_str[out->reason]`).

### Geo result type + lookup API — `heavybag_geo.h:53-70`
```c
typedef struct {
    ngx_uint_t   found;          /* 1 if a network matched the address */
    u_char       country[2];     /* ISO-2, or special A1/A2/A3/T1/XD   */
    uint16_t     flags;          /* NGX_HTTP_HEAVYBAG_GEO_FLAG_*            */
    uint32_t     asn;
} ngx_http_heavybag_geo_result_t;

ngx_http_heavybag_geo_db_t *ngx_http_heavybag_geo_open(ngx_conf_t *cf, ngx_str_t *path);
void ngx_http_heavybag_geo_lookup(ngx_http_heavybag_geo_db_t *db, struct sockaddr *sa,
    ngx_http_heavybag_geo_result_t *res);
```
Packed uint16 key for the per-country table: `cc16 = (country[0]<<8)|country[1]`.
Recover printable bytes: `cc[0]=(cc16>>8)&0xFF; cc[1]=cc16&0xFF;`.

### `ngx_stream_heavybag_handler` (L4 verdicts) — `heavybag_stream.c:142-165`
```c
static ngx_int_t
ngx_stream_heavybag_handler(ngx_stream_session_t *s)
{
    ngx_int_t                   rc;
    ngx_str_t                   reason;
    ngx_stream_heavybag_srv_conf_t  *sscf;
    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_heavybag_module);
    if (!sscf->enable) { return NGX_DECLINED; }
    rc = ngx_http_heavybag_reputation_check(&sscf->rep, s->connection->sockaddr, &reason);
    if (rc != NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "waf: stream reputation block (%V)", &reason);
        return NGX_STREAM_FORBIDDEN;
    }
    return NGX_DECLINED;
}
```

### Module ctx conf slots (to fill main + srv) — `ngx_http_heavybag_module.c:196-208`
```c
static ngx_http_module_t  ngx_http_heavybag_module_ctx = {
    ngx_http_heavybag_preconfiguration,     /* preconfiguration */
    ngx_http_heavybag_postconfiguration,    /* postconfiguration */
    NULL,                              /* create main configuration */  /* -> add */
    NULL,                              /* init main configuration   */  /* -> add */
    NULL,                              /* create server configuration*/ /* -> add */
    NULL,                              /* merge server configuration */ /* -> add */
    ngx_http_heavybag_create_loc_conf,      /* create location configuration */
    ngx_http_heavybag_merge_loc_conf        /* merge location configuration */
};
```

### postconfiguration (phase handler registration) — `ngx_http_heavybag_module.c:733-761`
```c
static ngx_int_t
ngx_http_heavybag_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) { return NGX_ERROR; }
    *h = ngx_http_heavybag_postread_handler;
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) { return NGX_ERROR; }
    *h = ngx_http_heavybag_preaccess_handler;
    if (ngx_http_heavybag_spoof_init(cf) != NGX_OK) { return NGX_ERROR; }
    return NGX_OK;
}
```
(Per-vhost index assignment walks `cmcf->servers` here; shm zone is added via
`ngx_shared_memory_add` here or in `init_main_conf`.)

### `waf_status` command entry (template) — add to `ngx_http_heavybag_commands[]` `:70-193`
Follow the `waf_mail_auth` NOARGS content-handler pattern (`:165-170`):
```c
    { ngx_string("waf_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_heavybag_set_status,        /* sets clcf->handler = ngx_http_heavybag_status_handler */
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
```
The `ngx_command_t` layout is `{name, type, set, conf, offset, post}`.

### Build registration — `modules/ngx_http_heavybag/config:22-28`
```sh
heavybag_srcs="$ngx_addon_dir/src/ngx_http_heavybag_module.c \
         $ngx_addon_dir/src/heavybag_match.c \
         $ngx_addon_dir/src/heavybag_spoof.c \
         $ngx_addon_dir/src/heavybag_geo.c \
         $ngx_addon_dir/src/heavybag_reputation.c \
         $ngx_addon_dir/src/heavybag_authhttp.c \
         $ngx_addon_dir/src/heavybag_stream.c"
```
Append `\\\n         $ngx_addon_dir/src/heavybag_status.c` to `heavybag_srcs`; add
`$ngx_addon_dir/src/heavybag_status.h` to `heavybag_deps` (`:14-20`).

### Core stub_status counters (re-export) — nginx core, behind `#if (NGX_STAT_STUB)`
```c
#if (NGX_STAT_STUB)
extern ngx_atomic_t  *ngx_stat_active;
extern ngx_atomic_t  *ngx_stat_reading;
extern ngx_atomic_t  *ngx_stat_writing;
extern ngx_atomic_t  *ngx_stat_waiting;
extern ngx_atomic_t  *ngx_stat_accepted;
extern ngx_atomic_t  *ngx_stat_handled;
extern ngx_atomic_t  *ngx_stat_requests;
#endif
```
(Declared in `src/event/ngx_event.h`; read with `*ngx_stat_active` etc. at render time.)

### Logging pattern (verbatim convention)
```c
ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
              "waf: reputation block (%V)", &reason);
```

### Resource Ownership Rules
- The shm zone is owned by nginx (created via `ngx_shared_memory_add`, lifetime = cycle).
  Core overlays an `ngx_slab_pool_t` at `shm.addr`; the fixed counter struct is allocated
  once from that pool via `ngx_slab_alloc` and its pointer stored in `shpool->data` /
  `zone->data`. On reload the `init(zone, data)` callback receives the PREVIOUS cycle's
  `zone->data` in the `data` argument (NOT via `zone->data`, which is NULL at init);
  values are preserved by reusing it. Preservation holds only while the zone size is
  unchanged (see size note in step 4).
- The counter struct is plain `ngx_atomic_t` fields + fixed arrays; no per-element
  allocation, no free path.
- ctx fields are request-pool owned (freed with the request); no manual cleanup.
- `reputation_check`’s `out` param is caller-stack owned (no allocation).

## Alternative Approaches Evaluated

### Option 1: Single fixed `ngx_atomic_t` struct in one shm zone (RECOMMENDED)
**Pros:**
- Fully lock-free (`ngx_atomic_fetch_add`); zero contention even under attack.
- Fixed memory footprint; trivial reload re-attach.
- Matches `stub_status` semantics and cost profile.
- Bounded dimensions (country closed-set, vhost config-time) fit naturally as fixed
  arrays inside the same struct.
**Cons:**
- Dimensions must be bounded at config time (no arbitrary runtime keys) — acceptable,
  since top-N IP is explicitly out of scope.

### Option 2: Per-worker local counters, summed at scrape time
**Pros:** no shared memory writes at all on the hot path.
**Cons:** requires a way to enumerate per-worker memory at scrape time (workers cannot
read each other’s heap); would need shm anyway to publish, or signaling. More complex
for no real gain over lock-free atomics. Rejected.

### Option 3: slab + rbtree keyed structure (vts-style)
**Pros:** supports unbounded dimensions (per-IP, arbitrary keys).
**Cons:** requires the slab mutex on the hot path — the exact flood-hot lock we set out
to avoid; unnecessary once top-N IP is out of scope. Rejected for the in-scope data.

### Sub-decision: reason representation
- **(a) Parse the human `reason` string in the handler** to pick a counter — brittle,
  string-compare on the hot path, couples counter logic to log wording. Rejected.
- **(b) `ngx_http_heavybag_reason_e` enum as single source** feeding counter index,
  `$waf_reason` string, and (optionally) the human log string via a parallel table —
  clean, O(1), one source of truth. RECOMMENDED.

### Recommended Approach
Option 1 (single fixed atomic struct) + sub-decision (b) (reason enum). Rationale:
meets the lock-free constraint, fixed footprint, and converges counters + variables +
logging onto one verdict decision computed once per request.

## Implementation Strategy

The verdict is computed once per request and recorded in ctx (`reason`, `country`,
`geo_done`, `verdict_set`). The preaccess handler, immediately before each `return`,
(1) sets `ctx->reason`, (2) increments the matching global + per-vhost + (if geo
resolved) per-country counters. The status content handler snapshots the shm struct and
renders it in the requested format. The new variables read ctx at log time, performing a
lazy geo lookup for `$waf_country` only if geo is configured and not already resolved.

### Data Model

**`ngx_http_heavybag_reason_e`** (new, in `heavybag_rep.h` — the ngx_core-only header, NOT
`ngx_http_heavybag.h`, so the stream TU which includes only `heavybag_rep.h` can name it):
```c
typedef enum {
    HEAVYBAG_REASON_NONE = 0,      /* allowed (no rule matched) */
    HEAVYBAG_REASON_ALLOWLIST,     /* allowlist short-circuit   */
    HEAVYBAG_REASON_BLOCKLIST,     /* static CIDR -> 403        */
    HEAVYBAG_REASON_GEO,           /* geo country block -> 403  */
    HEAVYBAG_REASON_GEO_WHITELIST, /* not whitelisted -> 404    */
    HEAVYBAG_REASON_FLAG,          /* network flag -> 403       */
    HEAVYBAG_REASON_SCANNER_UA,    /* scanner UA -> 404         */
    HEAVYBAG_REASON_EMPTY_UA,      /* empty UA -> 404           */
    HEAVYBAG_REASON_SCANNER_PATH,  /* scanner path -> 404/403/444 */
    HEAVYBAG_REASON_MAX
} ngx_http_heavybag_reason_e;
```
Parallel `static ngx_str_t heavybag_reason_str[HEAVYBAG_REASON_MAX]` with tokens:
`none, allowlist, blocklist, geo, geo_whitelist, flag, scanner_ua, empty_ua, scanner_path`.

**Shm counter struct** (new, in `heavybag_status.h`):
```c
#define HEAVYBAG_STAT_CC_SLOTS   512   /* closed-set country table, open-addressed */
#define HEAVYBAG_FLAG_SLOTS      4     /* anon, satellite, anycast, drop            */
/* NOTE: Tor has NO libloc flag bit (heavybag_geo.h:33-36 defines only 4 bits); Tor blocks
 * surface as a CC "T1" geo-country verdict (HEAVYBAG_REASON_GEO), NOT a flag verdict. The
 * flag breakdown therefore maps only the 4 real bits via an explicit bit->slot table. */

typedef struct {
    ngx_atomic_t  total;
    ngx_atomic_t  blocked;
    ngx_atomic_t  cc16;       /* packed key; 0 = empty slot                 */
} ngx_http_heavybag_stat_cc_t;

typedef struct {
    /* HTTP verdict counters (indexed conceptually by reason + status) */
    ngx_atomic_t  http_requests_total;
    ngx_atomic_t  http_allowed;
    ngx_atomic_t  http_allowlist_hits;
    ngx_atomic_t  http_blocked[HEAVYBAG_REASON_MAX]; /* per-reason block counts */
    ngx_atomic_t  http_scanner_path[3];         /* [0]=404 [1]=403 [2]=444 */
    ngx_atomic_t  http_resp_403;
    ngx_atomic_t  http_resp_404;
    ngx_atomic_t  http_resp_444;
    ngx_atomic_t  http_ua[HEAVYBAG_UA_MAX];          /* UA classification dist  */
    ngx_atomic_t  flag_blocked[HEAVYBAG_FLAG_SLOTS]; /* per-flag breakdown      */

    /* STREAM verdict counters */
    ngx_atomic_t  stream_connections_total;
    ngx_atomic_t  stream_allowed;
    ngx_atomic_t  stream_denied[HEAVYBAG_REASON_MAX];

    /* health/meta */
    ngx_atomic_t  start_time;       /* master cycle-init epoch (ngx_time() at zone alloc) */
    ngx_atomic_t  last_reload_time; /* set on re-attach           */

    /* bounded dimensions */
    ngx_http_heavybag_stat_cc_t  cc[HEAVYBAG_STAT_CC_SLOTS];
    /* per-vhost array follows, sized at init: nvhosts * sizeof(per-vhost block) */
} ngx_http_heavybag_stat_shm_t;
```
(Per-vhost block = the HTTP verdict subset; allocated contiguously after the fixed
struct, sized from the server count discovered at postconfiguration.)

**Main conf** (new): `{ ngx_shm_zone_t *stat_zone; ngx_uint_t nvhosts; }`.
**Srv conf** (new): `{ ngx_uint_t stat_index; }` (config-time assigned).

### Backwards Compatibility & Migration
- `reputation_check` gains a trailing `out` param (NULL = caller wants no verdict
  detail). The prototype lives in `heavybag_rep.h:43` (`heavybag_reputation.h` is a thin shim with
  NO prototype — do not edit it). All THREE call sites are updated in the same change:
  HTTP `ngx_http_heavybag_module.c:316`, STREAM `heavybag_stream.c:155`, SMTP-auth
  `heavybag_authhttp.c:65`. HTTP AND STREAM pass a real `ngx_http_heavybag_verdict_t *out` (HTTP
  needs it for `$waf_country`/`$waf_reason` + per-country; STREAM needs `out->reason` to
  index `stream_denied[reason]`). SMTP-auth passes NULL. The human `reason` string is
  kept on all paths for log / `Auth-Status` compatibility.
- Existing directives, verdicts, status codes, and `$waf_type` are unchanged.
- The shm zone is additive; if `NGX_STAT_STUB` is absent the core table is simply
  omitted from output (compile-time guarded). No config breakage.

### New Dependencies
None. PCRE2/atomics/shm all come from nginx core.

### Configuration Changes
- New directive `waf_status;` (loc, NOARGS) installing the content handler.
- Operators add an access-restricted location, e.g.:
```nginx
location /waf/stat/ { waf_status; allow 127.0.0.1; allow ::1; deny all; }
```
- No new env vars or feature flags.

## Step-by-Step Implementation Plan

1. **Reason enum + string tables**: add `ngx_http_heavybag_reason_e` AND
   `ngx_http_heavybag_verdict_t` to **`heavybag_rep.h`** (the ngx_core-only header included by the
   stream TU — NOT `ngx_http_heavybag.h`, which pulls `ngx_http.h`). Add `heavybag_reason_str[]` in
   `ngx_http_heavybag_module.c`. Keep the existing human `reason` strings in `reputation_check`
   or derive them from a second parallel table.
2. **Extend ctx** (`ngx_http_heavybag.h:89-99`): add `geo_done:1`, `verdict_set:1`,
   `country[2]`, `reason`.
3. **Extend `reputation_check`** (declaration `heavybag_rep.h:43`; body `heavybag_reputation.c:14-98`):
   add the `ngx_http_heavybag_verdict_t *out` param; set `out->reason` on EVERY branch
   (including both allow paths: `HEAVYBAG_REASON_ALLOWLIST` for the allowlist short-circuit at
   `:30`, `HEAVYBAG_REASON_NONE` for the geo-pass fall-through); copy `res` into `out->geo`
   and set `out->geo_valid=1` after the geo lookup at `:46`. Update all three call sites:
   HTTP `:316` (passes `out`; copies `out->geo.country` into `ctx->country` and sets
   `ctx->geo_done` when `out->geo_valid`), STREAM `heavybag_stream.c:155` (passes `out`; reads
   `out->reason` for `stream_denied[]`), SMTP-auth `heavybag_authhttp.c:65` (passes NULL).
   Do NOT touch `heavybag_reputation.h` (shim, no prototype). **NULL-guard:** every `out->...`
   write inside `reputation_check` MUST be skipped when `out == NULL` (SMTP-auth passes
   NULL); the `return rc` verdict paths stay byte-identical (`out` is write-only side
   data, never affecting the security decision).
4. **Shm struct + main conf + init/re-attach** (`heavybag_status.h`, `ngx_http_heavybag_module.c`):
   add `create_main_conf`/`init_main_conf`; in `init_main_conf` (or postconf) compute the
   server count, size the zone (`sizeof(shm) + nvhosts*sizeof(vhost_block)`, with an
   explicit integer-overflow guard on the multiply-then-add), call
   `ngx_shared_memory_add(cf, &name, size, &ngx_http_heavybag_module)` and store the returned
   `ngx_shm_zone_t *` in main conf. Pass a stable **`tag`** (`zone->tag =
   &ngx_http_heavybag_module`) so the SAME name+tag re-add from the STREAM module resolves to
   the SAME zone (see STREAM access below). Set `zone->init`.
   **The `init(ngx_shm_zone_t *zone, void *data)` callback** follows the `limit_req`
   pattern (`ngx_http_limit_req_module.c:728-741`) exactly — the misconception that
   `zone->data == NULL` signals fresh-start is WRONG; `zone->data` is always NULL at init:
   ```c
   shpool = (ngx_slab_pool_t *) zone->shm.addr;   /* core pre-overlays this */
   if (data) {                       /* reload, previous cycle's data handed in */
       zone->data = data;            /* reuse old struct -> counters preserved   */
       sh = data; sh->last_reload_time = ngx_time();
       return NGX_OK;
   }
   if (zone->shm.exists) {           /* re-attach to existing OS segment         */
       zone->data = shpool->data;
       return NGX_OK;
   }
   sh = ngx_slab_alloc(shpool, size);/* fresh: one-time alloc from the slab pool */
   if (sh == NULL) { return NGX_ERROR; }
   ngx_memzero(sh, size);
   sh->start_time = ngx_time();
   shpool->data = sh; zone->data = sh;
   ```
   **STREAM zone access:** the STREAM module is a distinct `ngx_stream_module_t` and
   cannot read the HTTP main conf. It obtains the SAME zone by calling
   `ngx_shared_memory_add` with the identical name + `tag = &ngx_http_heavybag_module` from its
   own stream postconfiguration, passing **`size = 0`** (resolve-only: the core guard
   `if (size && size != shm.size)` then skips the size-conflict check and returns the
   existing zone — a non-zero STREAM size that differs from HTTP's `sizeof(shm)+nvhosts*
   block` would EMERG and stop startup). **Only the HTTP module sets `zone->init`**; the
   STREAM re-add must NOT set its own init (a second init would clobber HTTP's). The
   stream handler reads `zone->data` (resolved after worker init). **Size note:** if the
   `server{}` count differs across a reload the size differs, `shm.exists` is false, a
   fresh segment is allocated, and counters reset — accepted and documented.
5. **Srv conf + per-vhost index** (`ngx_http_heavybag_module.c`): add
   `create_srv_conf`/`merge_srv_conf`; in `postconfiguration` walk `cmcf->servers` (each
   `ngx_http_core_srv_conf_t` exposes `->ctx->srv_conf[ngx_http_heavybag_module.ctx_index]`),
   assign each heavybag srv conf a sequential `stat_index`, store `nvhosts` in main conf. The
   `nvhosts` count drives the zone size in step 4, so this count must be known BEFORE the
   zone is added — do the walk and the `ngx_shared_memory_add` both in postconfiguration,
   walk first. (Server-count change across reload resets counters, per step 4.)
6. **Counter increments.** In `preaccess_handler` (`:286-347`), AFTER the early guards
   (`r != r->main`, `!wlcf->enable`) and the ctx-ensure block, fetch the two extra confs
   the increments need (the handler currently fetches only loc conf at `:299`):
   `wmcf = ngx_http_get_module_main_conf(r, ngx_http_heavybag_module)` (-> shm `sh = wmcf->stat_zone->data`)
   and `wscf = ngx_http_get_module_srv_conf(r, ngx_http_heavybag_module)` (-> `wscf->stat_index`,
   bounds-checked `< wmcf->nvhosts`, else fall back to 0). Bump `sh->http_requests_total`
   ONCE here (single choke point for enabled requests). Then at each verdict `return`, set
   `ctx->reason` + `ctx->verdict_set` and bump: `http_allowed` or `http_blocked[reason]`,
   `http_scanner_path[0|1|2]`, `http_resp_{403,404,444}`, `http_ua[ctx->ua]`,
   `flag_blocked[bit->slot]` (only for flag verdicts; map the matched `res.flags &
   flag_mask` bits via the explicit bit->slot table, NOT Tor), the per-vhost block at
   `stat_index`, and (if `ctx->geo_done`) the per-country slot via
   `ngx_http_heavybag_stat_cc_bump(sh, cc16, blocked?)`. `HEAVYBAG_REASON_ALLOWLIST` vs
   `HEAVYBAG_REASON_NONE` both map to `http_allowed` but are distinguished for `$waf_reason`.
   In `ngx_stream_heavybag_handler` (`heavybag_stream.c:142-165`) the handler reads the shm via the
   stream srv conf's zone pointer (step 4 STREAM access), bumps `stream_connections_total`
   once, then `stream_allowed` or `stream_denied[out.reason]`, and the shared per-country
   slot when `out.geo_valid`.
   **`cc_bump` claim protocol:** open-addressed probe on `cc16`; an empty slot has
   `cc16 == 0` (a real packed code is two printable uppercase ASCII bytes, so `\0` is
   unreachable — invariant guaranteed by `heavybag_reputation.c:67`). Claim an empty slot with
   `ngx_atomic_cmp_set(&slot->cc16, 0, key)`; on CAS failure re-read the slot key and, if
   it now equals `key`, use it, else probe the next slot. If all `HEAVYBAG_STAT_CC_SLOTS` are
   taken, bump a `cc_overflow` counter and skip (defensive; 512 >> ~250).
7. **New variables** (`ngx_http_heavybag_module.c`): register `$waf_country` and
   `$waf_reason` in `preconfiguration` (`:681-695`); add getters after `:730`.
   `$waf_country`: if `!geo_done && wlcf->rep.geo_db != NULL`, perform a lazy
   `ngx_http_heavybag_geo_lookup` and cache into `ctx->country`/`geo_done`; emit 2 bytes or
   `not_found`. `$waf_reason`: emit `heavybag_reason_str[ctx->reason]` (or `none` if unset).
8. **`waf_status` directive + content handler** (`ngx_http_heavybag_commands[]` `:70-193`,
   new `heavybag_status.c`): `ngx_http_heavybag_set_status` sets `clcf->handler =
   ngx_http_heavybag_status_handler`. The handler restricts to GET/HEAD, takes a snapshot of
   the shm struct, parses the last URI path segment, and dispatches to the serializer.
9. **Three serializers** (`heavybag_status.c`): `plain` (stub-style table; default for unknown
   segment), `json` (nested object), `prometheus` (text-exposition; metrics
   `heavybag_http_requests_total`, `heavybag_http_blocked_total{reason=...}`,
   `heavybag_http_blocked_total{reason="flag",flag=...}`, `heavybag_blocked_by_country_total{country=...,blocked|total}`,
   `heavybag_blocked_by_vhost_total{server=...,reason=...}`, `heavybag_ua_total{class=...}`,
   health gauges). All three include the `#if (NGX_STAT_STUB)` core connection table.
   **Output buffering:** the per-country (up to ~250) and per-vhost loops make the body
   size variable, so unlike `stub_status` (which pre-computes one exact buffer) the
   serializers build a chained `ngx_chain_t` of pool-allocated bufs (or one buf grown to a
   computed upper bound: `fixed_lines + nvhosts*per_vhost_len + n_cc*cc_line_len`). Set
   `Content-Type` per format (`text/plain` for plain & prometheus, `application/json` for
   json), compute `Content-Length` from the assembled chain, send headers then the chain.
   A consistent snapshot is taken by reading each atomic once into a local before render.
   **Escaping (mandatory):** every attacker-influenceable value emitted (country bytes,
   server names, reason/flag tokens) MUST be escaped at the output boundary — JSON per
   RFC 8259 (`"`, `\`, control chars), Prometheus label values per the text-exposition
   spec (`\`, `"`, `\n`). Do NOT rely on the geo DB yielding clean bytes; escape
   unconditionally. Guard the upper-bound buffer-size multiplication against overflow.
10. **Build glue** (`modules/ngx_http_heavybag/config:14-28`): add `src/heavybag_status.c` to
    `heavybag_srcs` and `src/heavybag_status.h` to `heavybag_deps`; reconfigure (touch the OpenSSL
    `ssl.h` first per the build-recipe memory) then `cmake --build build --target
    heavybag_module`.

## Error Handling & Edge Cases

### Error Scenarios
- **shm allocation fails at init** → return `NGX_ERROR` from `init_main_conf`; nginx
  fails to start with a clear `"waf: cannot allocate status zone"` emerg log.
- **`ngx_pcalloc` ctx fails in a getter/handler** → `NGX_ERROR` (existing convention).
- **Per-country table full** (all `HEAVYBAG_STAT_CC_SLOTS` claimed) → drop the increment for
  the overflow country silently but bump a `cc_overflow` counter so the loss is visible.
  (512 slots vs ~250 real codes makes this effectively impossible; the guard is defensive.)
- **`NGX_STAT_STUB` not compiled** → core connection table omitted; documented in output
  (`# stub_status not available` comment line in plaintext / absent metrics).

### Edge Cases
- **Allowlisted request** → `reputation_check` short-circuits before the geo lookup;
  `geo_done` stays 0, country unknown, not counted per-country (only global allowed++).
- **Geo configured but no record for IP** → `geo_valid=1`, `res.found=0`; `$waf_country`
  is `not_found`, per-country not bumped (no real CC), global counters still update.
- **Subrequest / internal redirect** → handler returns early (`r != r->main`); no
  double counting.
- **Multiple `server_name`s / default server** → per-vhost index is per server{} block,
  not per name; documented.
- **`waf_status` on a location where `waf` is off** → endpoint still serves (it only
  reads shm); counters reflect whatever locations have `waf on`.

### Validation
- Status handler rejects non-GET/HEAD with `NGX_HTTP_NOT_ALLOWED`.
- Path segment parsing is bounded to the final segment; unknown ⇒ plaintext default.

## Testing Strategy

### Unit Tests
No C unit-test framework exists in the module. The lock-free `cc_bump` open-addressing
claim is the only non-trivial pure function; it can be exercised indirectly via the
integration tests below (drive distinct countries, assert table contents).

### Integration Tests (curl vs sandbox nginx)
- Build the `.so`, load it in the sandbox config with a `waf_status` location and known
  block rules (a blocklist CIDR, a geo block, a scanner path list, a scanner UA list).
- For each verdict class: send a triggering request, then `GET /waf/stat/plain`,
  `/json`, `/prometheus` and assert the corresponding counter incremented by exactly 1.
- Assert allow path increments `http_allowed` + `http_requests_total` only.
- Assert a STREAM block increments `stream_denied[...]`.
- Assert `$waf_country` / `$waf_reason` appear correctly in a configured `log_format`
  (inspect the access log line).
- Assert one geo lookup per request (debug-log count, or reason/country consistency).

### Manual Testing
- [ ] `nginx -t` passes with the new directive.
- [ ] `/waf/stat/prometheus` validates against a Prometheus text-format linter
      (`promtool check metrics` if available).
- [ ] `/waf/stat/json` parses with `jq`.
- [ ] `nginx -s reload` preserves counter values (re-attach), `last_reload_time` updates.
- [ ] With nginx built WITHOUT stub_status, the endpoint still works and omits the core
      table.

### Security Testing
- [ ] Endpoint returns no client IPs or request bodies in any format.
- [ ] Endpoint honours `allow`/`deny` (verify the access phase runs before the content
      handler; a denied client never reaches the serializer).
- [ ] Output escaping: feed a server name containing `"`, `\`, and a newline; confirm the
      JSON output stays valid (parses with `jq`) and the Prometheus output stays valid
      (passes `promtool check metrics`) — i.e. the value is escaped, not injected.
- [ ] Hostile geo-DB resilience: a `location.db` with non-ASCII / control bytes in a
      country field must NOT break the output format (escaping is unconditional).
- [ ] `out == NULL` path (SMTP-auth): exercise the mail-auth flow and confirm no
      NULL-deref and no change to its allow/deny verdict.
- [ ] Integer-overflow guard on the zone/buffer size computation (reviewed).
- [ ] Geo-DB health block exposes no filesystem path or build-host detail.

### Edge Case Testing
- [ ] Per-country table near capacity → overflow counter increments, no corruption.
- [ ] Request to a vhost with no matching block rules → global counters only.

## Monitoring & Observability

### Logging
- Reuse the `"waf: "` convention. Emit one `NGX_LOG_EMERG` on shm allocation failure;
  optional `NGX_LOG_DEBUG_HTTP` trace in the status handler (format chosen, bytes
  written). No per-request stats logging (counters ARE the signal).

### Metrics/Telemetry
- The Prometheus endpoint is the telemetry surface. Recommended scrape of
  `/waf/stat/prometheus`; counters are monotonic → use `rate()`/`increase()` downstream.

### Alerts (operator-side, documented not implemented)
- Geo DB staleness: `time() - heavybag_geo_db_created_seconds` over threshold.
- Block-rate spikes per country/vhost via `rate(heavybag_http_blocked_total[5m])`.

### Debugging
- Plaintext endpoint doubles as the human debug view; include `heavybag_up`, uptime,
  `last_reload_time`, geo DB health, and loaded-list cardinalities so a misconfiguration
  (e.g. empty pattern list) is immediately visible.

## Documentation Updates Required

### Code Documentation
- [ ] Doxygen-style comments on `heavybag_status.c` public functions and the shm struct.
- [ ] Comment the lock-free `cc_bump` claim protocol.

### External Documentation
- [ ] Module README/usage: document `waf_status`, the three endpoints, the metric/label
      schema, and the `allow`/`deny` requirement.
- [ ] Document `$waf_country` / `$waf_reason` log variables next to `$waf_type`.

### New Documentation
- [ ] A short "heavybag metrics reference" listing every metric, its labels, and meaning.

## Dependencies & Sequencing
- Steps 1→2→3 are foundational (enum, ctx, reputation_check) and must land first.
- Step 4 (shm + main conf) and Step 5 (srv conf + index) can proceed in parallel after
  step 1, but both must precede step 6 (increments).
- Step 6 depends on 3+4+5. Step 7 (variables) depends on 2+3. Steps 8+9 (directive +
  serializers) depend on 4 (struct shape). Step 10 (build) is last.

## Potential Challenges
- **shm re-attach on reload**: the `init` callback distinguishes reload (the `data`
  ARGUMENT is non-NULL — previous cycle's struct), re-attach (`zone->shm.exists`), and
  fresh start (allocate from the slab pool, zero, stamp `start_time`). Keying off
  `zone->data == NULL` is WRONG (always NULL at init). Mitigation: copy the `limit_req`
  init verbatim (`ngx_http_limit_req_module.c:728-741`); use a `tag` so the STREAM re-add
  resolves the same zone (STREAM passes `size = 0`, sets no init of its own).
- **Per-vhost indexing correctness** with multiple/default servers: assign at
  postconfiguration by iterating `cmcf->servers`; verify index < `nvhosts` at runtime and
  fall back to 0 otherwise. Mitigation: cover with a 2-vhost integration test.
- **`NGX_STAT_STUB` availability**: guard all core-table references at compile time;
  never reference `ngx_stat_*` unguarded.
- **Three call sites of `reputation_check`**: all must be updated atomically in the same
  change or the build breaks; STREAM and mail pass NULL/ignore geo.
- **Lock-free country claim**: use `ngx_atomic_cmp_set` to claim an empty slot's `cc16`;
  a benign race may have two workers target the same slot — resolve by re-checking the
  key after a failed CAS and falling through to the next probe.

## Critical Files for Implementation
- `modules/ngx_http_heavybag/src/ngx_http_heavybag.h` — reason enum, ctx extension, main/srv conf
  structs.
- `modules/ngx_http_heavybag/src/ngx_http_heavybag_module.c` — conf slots, postconfiguration
  (shm + vhost index), command entry, variable registration + getters, counter
  increments in the preaccess handler.
- `modules/ngx_http_heavybag/src/heavybag_reputation.c` + `heavybag_rep.h` — `reputation_check` out-param.
- `modules/ngx_http_heavybag/src/heavybag_stream.c` — STREAM counter increments + call-site update.
- `modules/ngx_http_heavybag/src/heavybag_authhttp.c` — SMTP-auth `reputation_check` call-site update.
- `modules/ngx_http_heavybag/src/heavybag_status.c` (NEW) — shm struct, status handler, 3 serializers.
- `modules/ngx_http_heavybag/src/heavybag_status.h` (NEW) — shm struct + public API.
- `modules/ngx_http_heavybag/config` — register the new source/header.

## Post-Implementation Checklist
- [ ] All outputs in English
- [ ] Documentation follows English standards
- [ ] Integration tests passing (all verdict classes, all three formats)
- [ ] Error handling tested (shm alloc fail, cc overflow, no NGX_STAT_STUB)
- [ ] Logging in place (shm alloc emerg; debug trace optional)
- [ ] `waf_status` access-restriction documented
- [ ] Documentation updated (README, variables, metrics reference)
- [ ] Reload preserves counters (re-attach verified)
- [ ] No client IP / PII in any output format
- [ ] One geo lookup per request verified
- [ ] Existing heavybag behaviour unregressed (`$waf_type`, all verdicts, status codes)
