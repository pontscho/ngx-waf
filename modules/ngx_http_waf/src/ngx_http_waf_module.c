/*
 * ngx_http_waf_module - edge firewall for nginx
 *
 * Module glue: the single ngx_module_t, directives, configuration
 * create/merge, postconfiguration (phase + header-filter install) and
 * the master/worker init hooks (geo-DB load). Phase handlers are thin
 * and dispatch into the per-concern cores.
 */

#include "ngx_http_waf.h"
#include "waf_match.h"
#include "waf_spoof.h"
#include "waf_geo.h"
#include "waf_reputation.h"
#include "waf_authhttp.h"
#include "waf_status.h"
#include "waf_ja4.h"

#if (NGX_HTTP_SSL)
#include <ngx_http_ssl_module.h>
#endif


#define NGX_HTTP_WAF_DEFAULT_TOKEN  "Apache/2.4.68 (Unix)"


#if (NGX_HTTP_SSL)
/*
 * SSL ex-data index holding the per-connection JA4 string (an ngx_str_t* from
 * the connection pool, set by the client_hello callback at handshake time).
 * Allocated once in postconfiguration; -1 until then -> $waf_ja4_hash unset.
 */
static int  ngx_http_waf_ja4_ssl_index = -1;
#endif


/*
 * enum -> $waf_type string, indexed by ngx_http_waf_ua_e. The list-backed
 * categories occupy [0, WAF_UA_LIST_MAX); REGULAR and EMPTY follow. A hit is
 * returned by reference (static literal), never copied.
 */
ngx_str_t  waf_type_str[WAF_UA_MAX] = {
    ngx_string("scanner"),
    ngx_string("ai-crawler"),
    ngx_string("crawler"),
    ngx_string("bot"),
    ngx_string("regular"),
    ngx_string("empty")
};


/*
 * enum -> $waf_reason string, indexed by ngx_http_waf_reason_e. The single
 * source of truth (waf_rep.h) also indexes the per-reason counters; this
 * table only renders the token. A hit is returned by reference (static
 * literal), never copied. Must stay in lockstep with ngx_http_waf_reason_e.
 */
ngx_str_t  waf_reason_str[WAF_REASON_MAX] = {
    ngx_string("none"),
    ngx_string("allowlist"),
    ngx_string("blocklist"),
    ngx_string("geo"),
    ngx_string("geo_whitelist"),
    ngx_string("flag"),
    ngx_string("scanner_ua"),
    ngx_string("empty_ua"),
    ngx_string("scanner_path"),
    ngx_string("asn"),
    ngx_string("method")
};


/*
 * `waf` / `waf_stream` directive mode. Three-state so a config can observe
 * without blocking (detect). `on` is an alias for enforce (backward compat).
 * Fail-CLOSED: detect is the ONLY non-blocking value (see
 * ngx_http_waf_finalize_decision); any other value blocks.
 */
static ngx_conf_enum_t  ngx_http_waf_mode[] = {
    { ngx_string("off"),     WAF_MODE_OFF     },
    { ngx_string("detect"),  WAF_MODE_DETECT  },
    { ngx_string("enforce"), WAF_MODE_ENFORCE },
    { ngx_string("on"),      WAF_MODE_ENFORCE },
    { ngx_null_string, 0 }
};


static ngx_int_t ngx_http_waf_postread_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_waf_preaccess_handler(ngx_http_request_t *r);

static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_waf_set_scanner_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_ua_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_method_allow(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_method_deny(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_geo_whitelist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_trusted_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_mail_auth(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_mail_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_waf_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_waf_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_waf_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_waf_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_waf_stat_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_waf_stat_assign_vhosts(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_stat_add_zone(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_type_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_reason_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_asn_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_waf_commands[] = {

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, mode),
      &ngx_http_waf_mode },

    { ngx_string("waf_bot_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, bot_block),
      NULL },

    { ngx_string("waf_scanner_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_scanner_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* UA signature lists: one shared setter, category carried in cmd->post */
    { ngx_string("waf_scanner_ua_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) WAF_UA_SCANNER },

    { ngx_string("waf_ai_crawler_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) WAF_UA_AI_CRAWLER },

    { ngx_string("waf_crawler_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) WAF_UA_CRAWLER },

    { ngx_string("waf_bot_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) WAF_UA_BOT },

    { ngx_string("waf_server_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, server_token),
      NULL },

    { ngx_string("waf_geo_db"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_geo_db,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_set_geo_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_asn_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_set_asn_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_method_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_set_method_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_method_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_set_method_deny,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_whitelist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_set_geo_whitelist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_flag_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_set_flag_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_trusted_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_trusted_proxy,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_blocklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_blocklist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_allowlist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_set_allowlist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_mail_auth"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_waf_set_mail_auth,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_mail_backend"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_set_mail_backend,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_waf_set_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_waf_module_ctx = {
    ngx_http_waf_preconfiguration,     /* preconfiguration */
    ngx_http_waf_postconfiguration,    /* postconfiguration */

    ngx_http_waf_create_main_conf,     /* create main configuration */
    ngx_http_waf_init_main_conf,       /* init main configuration */

    ngx_http_waf_create_srv_conf,      /* create server configuration */
    ngx_http_waf_merge_srv_conf,       /* merge server configuration */

    ngx_http_waf_create_loc_conf,      /* create location configuration */
    ngx_http_waf_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,          /* module context */
    ngx_http_waf_commands,             /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * POST_READ phase. Resolve the canonical client address: the socket peer
 * by default, or -- only when the peer is a configured trusted proxy --
 * the real client taken from X-Forwarded-For. The result is stashed in
 * the request ctx for the reputation check to use.
 */
static ngx_int_t
ngx_http_waf_postread_handler(ngx_http_request_t *r)
{
    ngx_addr_t                addr;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->mode == WAF_MODE_OFF) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    ctx->client_sa = r->connection->sockaddr;
    ctx->client_socklen = r->connection->socklen;

    if (wlcf->trusted_proxy != NULL && r->headers_in.x_forwarded_for != NULL) {

        addr.sockaddr = r->connection->sockaddr;
        addr.socklen = r->connection->socklen;

        if (ngx_http_get_forwarded_addr(r, &addr,
                                        r->headers_in.x_forwarded_for, NULL,
                                        wlcf->trusted_proxy, 1)
            == NGX_OK)
        {
            ctx->client_sa = addr.sockaddr;
            ctx->client_socklen = addr.socklen;
        }
    }

    return NGX_DECLINED;
}


/*
 * Lock-free per-country counter bump (open-addressed, linear probe). cc16==0
 * is the empty-slot sentinel (no real ISO-2 code packs to 0), claimed once
 * with ngx_atomic_cmp_set; a lost race re-reads the winner and reuses the
 * slot if it matches. A full table bumps cc_overflow and drops the sample
 * rather than corrupt a slot. Shared by both heads (the STREAM head enters
 * here through the opaque pointer, never seeing the layout struct). NULL
 * zone is a no-op.
 */
void
ngx_http_waf_stat_cc_bump(void *shm, uint16_t cc16, ngx_uint_t blocked)
{
    ngx_uint_t                probe, slot;
    ngx_atomic_uint_t         cur;
    ngx_http_waf_stat_cc_t   *cc;
    ngx_http_waf_stat_shm_t  *sh = shm;

    if (sh == NULL || cc16 == 0) {
        return;
    }

    slot = (ngx_uint_t) cc16 % WAF_STAT_CC_SLOTS;

    for (probe = 0; probe < WAF_STAT_CC_SLOTS; probe++) {
        cc = &sh->cc[(slot + probe) % WAF_STAT_CC_SLOTS];

        cur = cc->cc16;
        if (cur == 0) {
            if (ngx_atomic_cmp_set(&cc->cc16, 0, cc16)) {
                cur = cc16;             /* we claimed this empty slot */
            } else {
                cur = cc->cc16;         /* lost the race; read the winner */
            }
        }

        if (cur == cc16) {
            (void) ngx_atomic_fetch_add(&cc->total, 1);
            if (blocked) {
                (void) ngx_atomic_fetch_add(&cc->blocked, 1);
            }
            return;
        }
        /* slot owned by another country: probe the next one */
    }

    (void) ngx_atomic_fetch_add(&sh->cc_overflow, 1);
}


/*
 * Record a STREAM (L4) verdict: one connection counted, then either allowed
 * or denied[reason]. Opaque-pointer entry for the stream head; NULL zone is
 * a no-op.
 */
void
ngx_http_waf_stat_stream_bump(void *shm, ngx_http_waf_reason_e reason,
    ngx_uint_t denied)
{
    ngx_http_waf_stat_shm_t  *sh = shm;

    if (sh == NULL) {
        return;
    }

    (void) ngx_atomic_fetch_add(&sh->stream_connections_total, 1);

    if (!denied) {
        (void) ngx_atomic_fetch_add(&sh->stream_allowed, 1);
        return;
    }

    if ((ngx_uint_t) reason < WAF_REASON_MAX) {
        (void) ngx_atomic_fetch_add(&sh->stream_denied[reason], 1);
    }
}


/*
 * Detect-mode STREAM counter: record what WOULD have been denied without
 * actually denying it. Opaque-pointer entry for the stream head (which never
 * sees ngx_http_waf_stat_shm_t); NULL zone is a no-op. Unlike
 * ngx_http_waf_stat_stream_bump it does NOT touch the connection/allowed
 * totals -- the detect path counts the connection as allowed separately.
 */
void
ngx_http_waf_stat_stream_would_block(void *shm, ngx_http_waf_reason_e reason)
{
    ngx_http_waf_stat_shm_t  *sh = shm;

    if (sh == NULL) {
        return;
    }

    if ((ngx_uint_t) reason < WAF_REASON_MAX) {
        (void) ngx_atomic_fetch_add(&sh->stream_would_block[reason], 1);
    }
}


/* libloc flag bit -> flag_blocked[] slot (Tor has no bit; it is a CC verdict) */
static const uint16_t  waf_flag_bits[WAF_FLAG_SLOTS] = {
    NGX_HTTP_WAF_GEO_FLAG_ANON_PROXY,
    NGX_HTTP_WAF_GEO_FLAG_SATELLITE,
    NGX_HTTP_WAF_GEO_FLAG_ANYCAST,
    NGX_HTTP_WAF_GEO_FLAG_DROP
};


/*
 * Record a blocked HTTP verdict: ctx state (so $waf_reason renders even with
 * no zone), then the global per-reason counter, the response-code counter
 * and the per-vhost slot. sh may be NULL (zone not yet populated). status is
 * the HTTP code being returned (403 / 404 / 444). reason is always a valid
 * enum value, so the array indexes need no extra bound check.
 */
static void
ngx_http_waf_stat_http_block(ngx_http_waf_stat_shm_t *sh, ngx_uint_t idx,
    ngx_http_waf_ctx_t *ctx, ngx_http_waf_reason_e reason, ngx_int_t status)
{
    ngx_http_waf_stat_vhost_t  *v;

    ctx->reason = reason;
    ctx->verdict_set = 1;

    if (sh == NULL) {
        return;
    }

    (void) ngx_atomic_fetch_add(&sh->http_blocked[reason], 1);

    switch (status) {
    case NGX_HTTP_FORBIDDEN:
        (void) ngx_atomic_fetch_add(&sh->http_resp_403, 1);
        break;
    case NGX_HTTP_NOT_FOUND:
        (void) ngx_atomic_fetch_add(&sh->http_resp_404, 1);
        break;
    case NGX_HTTP_CLOSE:
        (void) ngx_atomic_fetch_add(&sh->http_resp_444, 1);
        break;
    default:
        break;
    }

    if (idx < sh->nvhosts) {
        v = ngx_http_waf_stat_vhost(sh, idx);
        (void) ngx_atomic_fetch_add(&v->blocked[reason], 1);
    }
}


/*
 * Detect-aware block finalizer, the single chokepoint every HTTP block point
 * funnels through. In WAF_MODE_DETECT the verdict is observed only: the
 * global would_block[reason] counter is bumped, ctx->reason is set (so
 * $waf_reason still renders the would-be verdict) and NGX_DECLINED is
 * returned so the request proceeds. In every other (blocking) mode the
 * standard block accounting runs (ngx_http_waf_stat_http_block) and block_code
 * is returned. FAIL-CLOSED: detect is the ONLY non-blocking branch; any
 * unexpected mode value blocks. sh / idx are re-resolved from r so callers
 * need not thread them through.
 */
static ngx_int_t
ngx_http_waf_finalize_decision(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_reason_e reason,
    ngx_int_t block_code)
{
    ngx_uint_t                 idx;
    ngx_http_waf_stat_shm_t   *sh;
    ngx_http_waf_srv_conf_t   *wscf;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wscf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    sh = (wmcf->stat_zone != NULL) ? wmcf->stat_zone->data : NULL;
    idx = (wscf->stat_index < wmcf->nvhosts) ? wscf->stat_index : 0;

    if (wlcf->mode == WAF_MODE_DETECT) {
        ctx->reason = reason;
        ctx->verdict_set = 1;

        if (sh != NULL) {
            (void) ngx_atomic_fetch_add(&sh->http_would_block[reason], 1);
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: would-block (%V) [detect]", &waf_reason_str[reason]);

        return NGX_DECLINED;
    }

    ngx_http_waf_stat_http_block(sh, idx, ctx, reason, block_code);

    return block_code;
}


/*
 * Case-insensitive lookup of the request method name in a config list of
 * non-standard method tokens (e.g. TRACK, DEBUG) that nginx does not parse
 * into an NGX_HTTP_* bit. NULL list -> no match.
 */
static ngx_int_t
ngx_http_waf_method_in_list(ngx_http_request_t *r, ngx_array_t *list)
{
    ngx_str_t   *names;
    ngx_uint_t   i;

    if (list == NULL) {
        return 0;
    }

    names = list->elts;

    for (i = 0; i < list->nelts; i++) {
        if (r->method_name.len == names[i].len
            && ngx_strncasecmp(r->method_name.data, names[i].data,
                               names[i].len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/* The request method is on the whitelist (standard bit or non-standard name). */
static ngx_int_t
ngx_http_waf_method_allowed(ngx_http_waf_loc_conf_t *wlcf,
    ngx_http_request_t *r)
{
    return (r->method & wlcf->allow_mask)
           || ngx_http_waf_method_in_list(r, wlcf->allow_list);
}


/* The request method is on the blacklist (standard bit or non-standard name). */
static ngx_int_t
ngx_http_waf_method_denied(ngx_http_waf_loc_conf_t *wlcf,
    ngx_http_request_t *r)
{
    return (r->method & wlcf->deny_mask)
           || ngx_http_waf_method_in_list(r, wlcf->deny_list);
}


/*
 * PREACCESS phase. Order is cheap -> expensive: IP reputation
 * (blocklist/geo/flags) -> bot heuristics (string match) -> scanner regex.
 * Subrequests and internal redirects are never re-scanned.
 */
static ngx_int_t
ngx_http_waf_preaccess_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_str_t                   reason;
    uint16_t                    cc16, matched;
    ngx_uint_t                  idx, k;
    struct sockaddr            *sa;
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_waf_verdict_t      verdict;
    ngx_http_waf_stat_shm_t    *sh;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_srv_conf_t    *wscf;
    ngx_http_waf_main_conf_t   *wmcf;
    ngx_http_waf_stat_vhost_t  *v;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->mode == WAF_MODE_OFF) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    /* resolve the shared counters + this vhost's slot (slot 0 fallback) */
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    wscf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    sh = (wmcf->stat_zone != NULL) ? wmcf->stat_zone->data : NULL;
    idx = (wscf->stat_index < wmcf->nvhosts) ? wscf->stat_index : 0;

    /* count this request once, before any verdict is reached */
    if (sh != NULL) {
        (void) ngx_atomic_fetch_add(&sh->http_requests_total, 1);
        if (idx < sh->nvhosts) {
            v = ngx_http_waf_stat_vhost(sh, idx);
            (void) ngx_atomic_fetch_add(&v->requests, 1);
        }
    }

    sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr;

    rc = ngx_http_waf_reputation_check(&wlcf->rep, sa, &reason, &verdict);

    /*
     * Cache the single geo lookup result so $waf_country needs no second one
     * and the per-country counter can be bumped. cc16==0 ({0,0} country, i.e.
     * no geo / no record) makes cc_bump a no-op.
     */
    if (verdict.geo_valid) {
        ctx->country[0] = verdict.country[0];
        ctx->country[1] = verdict.country[1];
        ctx->geo_done = 1;
        ctx->asn = verdict.asn;
        ctx->asn_done = 1;
    }
    cc16 = (uint16_t) ((verdict.country[0] << 8) | verdict.country[1]);

    if (rc != NGX_DECLINED) {
        if (ngx_http_waf_finalize_decision(r, ctx, wlcf, verdict.reason, rc)
            == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: reputation block (%V)", &reason);

        /* per-flag breakdown only for a network-flag verdict */
        if (sh != NULL && verdict.reason == WAF_REASON_FLAG) {
            matched = verdict.flags & wlcf->rep.flag_mask;
            for (k = 0; k < WAF_FLAG_SLOTS; k++) {
                if (matched & waf_flag_bits[k]) {
                    (void) ngx_atomic_fetch_add(&sh->flag_blocked[k], 1);
                }
            }
        }

        if (verdict.geo_valid) {
            ngx_http_waf_stat_cc_bump(sh, cc16, 1);
        }

        return rc;
    }

    /*
     * Method filter -- whitelist wins, then blacklist narrows. Both routed
     * through the detect-aware finalizer, so detect mode records
     * would_block[method] and lets the request through. A non-whitelisted or
     * explicitly-denied method is hidden with a 404 (the policy is opaque to
     * the client, like scanner blocks).
     */
    if (wlcf->method_allow_set && !ngx_http_waf_method_allowed(wlcf, r)) {
        if (ngx_http_waf_finalize_decision(r, ctx, wlcf, WAF_REASON_METHOD,
                                           NGX_HTTP_NOT_FOUND) == NGX_DECLINED)
        {
            return NGX_DECLINED;
        }
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: method \"%V\" not allowed", &r->method_name);
        if (verdict.geo_valid) {
            ngx_http_waf_stat_cc_bump(sh, cc16, 1);
        }
        return NGX_HTTP_NOT_FOUND;
    }

    if (wlcf->method_deny_set && ngx_http_waf_method_denied(wlcf, r)) {
        if (ngx_http_waf_finalize_decision(r, ctx, wlcf, WAF_REASON_METHOD,
                                           NGX_HTTP_NOT_FOUND) == NGX_DECLINED)
        {
            return NGX_DECLINED;
        }
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: method \"%V\" denied", &r->method_name);
        if (verdict.geo_valid) {
            ngx_http_waf_stat_cc_bump(sh, cc16, 1);
        }
        return NGX_HTTP_NOT_FOUND;
    }

    /*
     * Classify the UA into ctx->ua ($waf_type) unconditionally; blocking is
     * a separate policy. With bot_block on, only the unambiguously-hostile
     * outcomes (scanner tools, missing UA) are dropped -- crawler/ai-crawler/
     * bot stay flag-only for the operator to act on via $waf_type.
     */
    ngx_http_waf_ua_classify(r, wlcf, ctx);

    /* UA distribution over every reputation-passed (classified) request */
    if (sh != NULL && (ngx_uint_t) ctx->ua < WAF_UA_MAX) {
        (void) ngx_atomic_fetch_add(&sh->http_ua[ctx->ua], 1);
    }

    if (wlcf->bot_block
        && (ctx->ua == WAF_UA_SCANNER || ctx->ua == WAF_UA_EMPTY))
    {
        if (ngx_http_waf_finalize_decision(r, ctx, wlcf,
                (ctx->ua == WAF_UA_SCANNER) ? WAF_REASON_SCANNER_UA
                                            : WAF_REASON_EMPTY_UA,
                NGX_HTTP_NOT_FOUND) == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: %V user-agent blocked", &waf_type_str[ctx->ua]);

        if (verdict.geo_valid) {
            ngx_http_waf_stat_cc_bump(sh, cc16, 1);
        }

        return NGX_HTTP_NOT_FOUND;
    }

    rc = ngx_http_waf_scanner_lookup(wlcf, &r->uri);
    if (rc != NGX_DECLINED) {
        if (ngx_http_waf_finalize_decision(r, ctx, wlcf, WAF_REASON_SCANNER_PATH,
                                           rc) == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: scanner path \"%V\" blocked (%i)", &r->uri, rc);

        if (sh != NULL) {
            switch (rc) {
            case NGX_HTTP_NOT_FOUND:
                (void) ngx_atomic_fetch_add(
                    &sh->http_scanner_path[WAF_ACTION_404], 1);
                break;
            case NGX_HTTP_FORBIDDEN:
                (void) ngx_atomic_fetch_add(
                    &sh->http_scanner_path[WAF_ACTION_403], 1);
                break;
            case NGX_HTTP_CLOSE:
                (void) ngx_atomic_fetch_add(
                    &sh->http_scanner_path[WAF_ACTION_444], 1);
                break;
            default:
                break;
            }
        }

        if (verdict.geo_valid) {
            ngx_http_waf_stat_cc_bump(sh, cc16, 1);
        }

        return rc;
    }

    /* allowed: record the (allowlist or none) reason and the allow counters */
    ctx->reason = verdict.reason;
    ctx->verdict_set = 1;

    if (sh != NULL) {
        (void) ngx_atomic_fetch_add(&sh->http_allowed, 1);
        if (verdict.reason == WAF_REASON_ALLOWLIST) {
            (void) ngx_atomic_fetch_add(&sh->http_allowlist_hits, 1);
        }
        if (idx < sh->nvhosts) {
            v = ngx_http_waf_stat_vhost(sh, idx);
            (void) ngx_atomic_fetch_add(&v->allowed, 1);
        }
    }

    if (verdict.geo_valid) {
        ngx_http_waf_stat_cc_bump(sh, cc16, 0);
    }

    return NGX_DECLINED;
}


static void *
ngx_http_waf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_waf_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * ngx_pcalloc() zeroes the block; pointers (scanner_re[]) and the
     * scanner_list str are therefore NULL/empty. Flags that need an
     * explicit "unset" sentinel use NGX_CONF_UNSET so merge can tell
     * inherited from default.
     */
    conf->mode = NGX_CONF_UNSET_UINT;
    conf->bot_block = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_loc_conf_t  *prev = parent;
    ngx_http_waf_loc_conf_t  *conf = child;
    ngx_uint_t                i;

    /* fail-CLOSED default: an unset waf gate enforces (never silently off) */
    ngx_conf_merge_uint_value(conf->mode, prev->mode, WAF_MODE_ENFORCE);
    ngx_conf_merge_value(conf->bot_block, prev->bot_block, 0);

    /* inherit the compiled buckets when this level defined no list */
    for (i = 0; i < WAF_ACTION_MAX; i++) {
        if (conf->scanner_re[i] == NULL) {
            conf->scanner_re[i] = prev->scanner_re[i];
        }
    }

    /* same inherit-when-NULL for the UA classification regex slots */
    for (i = 0; i < WAF_UA_LIST_MAX; i++) {
        if (conf->ua_re[i] == NULL) {
            conf->ua_re[i] = prev->ua_re[i];
        }
    }

    if (conf->scanner_list.data == NULL) {
        conf->scanner_list = prev->scanner_list;
    }

    ngx_conf_merge_str_value(conf->server_token, prev->server_token,
                             NGX_HTTP_WAF_DEFAULT_TOKEN);

    /* reputation data: inherit when this level defined none */
    if (conf->rep.geo_db == NULL) {
        conf->rep.geo_db = prev->rep.geo_db;
    }
    if (conf->rep.block_cc == NULL) {
        conf->rep.block_cc = prev->rep.block_cc;
    }
    if (conf->rep.block_asn == NULL) {
        conf->rep.block_asn = prev->rep.block_asn;
    }
    if (conf->rep.allow_cc == NULL) {
        conf->rep.allow_cc = prev->rep.allow_cc;
    }
    if (conf->rep.flag_mask == 0) {
        conf->rep.flag_mask = prev->rep.flag_mask;
    }

    /* a country whitelist without a geo database can never allow anyone */
    if (conf->rep.allow_cc != NULL && conf->rep.geo_db == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "waf_geo_whitelist is set but no waf_geo_db is configured; "
            "every request will be treated as not whitelisted (404)");
    }
    if (conf->rep.blocklist == NULL) {
        conf->rep.blocklist = prev->rep.blocklist;
    }
    if (conf->rep.allowlist == NULL) {
        conf->rep.allowlist = prev->rep.allowlist;
    }
    if (conf->trusted_proxy == NULL) {
        conf->trusted_proxy = prev->trusted_proxy;
    }

    /* method filter: inherit each list independently when unset at this level */
    if (!conf->method_allow_set) {
        conf->method_allow_set = prev->method_allow_set;
        conf->allow_mask = prev->allow_mask;
        conf->allow_list = prev->allow_list;
    }
    if (!conf->method_deny_set) {
        conf->method_deny_set = prev->method_deny_set;
        conf->deny_mask = prev->deny_mask;
        conf->deny_list = prev->deny_list;
    }

    /* backend MTA is set as a pair; inherit together when unset here */
    if (conf->mail_backend_addr.data == NULL) {
        conf->mail_backend_addr = prev->mail_backend_addr;
        conf->mail_backend_port = prev->mail_backend_port;
    }

    return NGX_CONF_OK;
}


/*
 * Per-server conf carries only the per-vhost status slot index. It is not
 * set by any directive: create leaves it UNSET and the postconfiguration
 * walk (ngx_http_waf_stat_assign_vhosts) assigns a sequential index per
 * server{}. The hot path bounds-checks the index against nvhosts and falls
 * back to slot 0 if it is somehow still UNSET.
 */
static void *
ngx_http_waf_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_waf_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->stat_index = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_waf_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    /* stat_index is assigned by the postconfiguration vhost walk, not merged */
    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_scanner_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;

    if (wlcf->scanner_list.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_http_waf_scanner_compile(cf, wlcf, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_{scanner_ua,ai_crawler,crawler,bot}_list <path>: load a UA signature
 * list into one ua_re[] slot. The category is carried in cmd->post so the
 * four directives share this single setter.
 */
static char *
ngx_http_waf_set_ua_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;
    ngx_http_waf_ua_e         cat;

    cat = (ngx_http_waf_ua_e) (uintptr_t) cmd->post;

    if (wlcf->ua_re[cat] != NULL) {
        return "is duplicate";
    }

    if (ngx_http_waf_ua_list_compile(cf, wlcf, &value[1], cat) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;

    if (wlcf->rep.geo_db != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    wlcf->rep.geo_db = ngx_http_waf_geo_open(cf, &value[1]);
    if (wlcf->rep.geo_db == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_country_add(cf, &wlcf->rep.block_cc, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_asn_block <ASN>...: deny any client whose source IP resolves (via the
 * geo database) to one of the listed autonomous systems. Decimal ASNs only;
 * asn==0 (no record) is never matched.
 */
static char *
ngx_http_waf_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_asn_add(cf, &wlcf->rep.block_asn, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * Standard HTTP method name -> NGX_HTTP_* request-method bit. Names not in
 * this table (TRACK, DEBUG, ...) are kept verbatim in a string list and
 * matched against r->method_name at runtime.
 */
static const struct {
    ngx_str_t   name;
    ngx_uint_t  bit;
} ngx_http_waf_method_bits[] = {
    { ngx_string("GET"),       NGX_HTTP_GET       },
    { ngx_string("HEAD"),      NGX_HTTP_HEAD      },
    { ngx_string("POST"),      NGX_HTTP_POST      },
    { ngx_string("PUT"),       NGX_HTTP_PUT       },
    { ngx_string("DELETE"),    NGX_HTTP_DELETE    },
    { ngx_string("MKCOL"),     NGX_HTTP_MKCOL     },
    { ngx_string("COPY"),      NGX_HTTP_COPY      },
    { ngx_string("MOVE"),      NGX_HTTP_MOVE      },
    { ngx_string("OPTIONS"),   NGX_HTTP_OPTIONS   },
    { ngx_string("PROPFIND"),  NGX_HTTP_PROPFIND  },
    { ngx_string("PROPPATCH"), NGX_HTTP_PROPPATCH },
    { ngx_string("LOCK"),      NGX_HTTP_LOCK      },
    { ngx_string("UNLOCK"),    NGX_HTTP_UNLOCK    },
    { ngx_string("PATCH"),     NGX_HTTP_PATCH     },
    { ngx_string("TRACE"),     NGX_HTTP_TRACE     },
    { ngx_null_string, 0 }
};


/*
 * Shared worker for waf_method_allow / waf_method_deny: map each argument to
 * its NGX_HTTP_* bit (OR-ed into *mask), or -- for a non-standard method name
 * -- append the verbatim token to *list (created on first use).
 */
static char *
ngx_http_waf_method_list_add(ngx_conf_t *cf, ngx_uint_t *mask,
    ngx_array_t **list)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t   *s;
    ngx_uint_t   i, j;

    for (i = 1; i < cf->args->nelts; i++) {

        for (j = 0; ngx_http_waf_method_bits[j].name.len; j++) {
            if (value[i].len == ngx_http_waf_method_bits[j].name.len
                && ngx_strncasecmp(value[i].data,
                                   ngx_http_waf_method_bits[j].name.data,
                                   value[i].len) == 0)
            {
                *mask |= ngx_http_waf_method_bits[j].bit;
                break;
            }
        }

        if (ngx_http_waf_method_bits[j].name.len != 0) {
            continue;   /* matched a standard method bit */
        }

        /* non-standard method name -> verbatim string list */
        if (*list == NULL) {
            *list = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
            if (*list == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        s = ngx_array_push(*list);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }

        *s = value[i];
    }

    return NGX_CONF_OK;
}


/*
 * waf_method_allow <METHOD>...: only the listed methods pass; everything else
 * is hidden (404). Whitelist; wins over waf_method_deny.
 */
static char *
ngx_http_waf_set_method_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    wlcf->method_allow_set = 1;

    return ngx_http_waf_method_list_add(cf, &wlcf->allow_mask,
                                        &wlcf->allow_list);
}


/*
 * waf_method_deny <METHOD>...: the listed methods are hidden (404); everything
 * else passes. Blacklist; narrows after the whitelist.
 */
static char *
ngx_http_waf_set_method_deny(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;

    wlcf->method_deny_set = 1;

    return ngx_http_waf_method_list_add(cf, &wlcf->deny_mask,
                                        &wlcf->deny_list);
}


/*
 * waf_geo_whitelist <CC>...: allow only the listed countries; every other
 * country -- and any IP with no geo record -- is hidden (404). Coexists with
 * waf_geo_block but wins over it: when a whitelist is set on a location the
 * block list is not consulted for the country decision.
 */
static char *
ngx_http_waf_set_geo_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_country_add(cf, &wlcf->rep.allow_cc, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_flag_add(cf, &wlcf->rep, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_trusted_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (ngx_http_waf_cidr_add(cf, &wlcf->trusted_proxy, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (ngx_http_waf_cidr_add(cf, &wlcf->rep.blocklist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (ngx_http_waf_cidr_add(cf, &wlcf->rep.allowlist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_mail_auth: turn this location into the ngx_mail auth_http endpoint
 * by installing the SMTP content handler. Reputation directives on the
 * same location (or inherited) drive the verdict.
 */
static char *
ngx_http_waf_set_mail_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_waf_authhttp_handler;

    return NGX_CONF_OK;
}


/*
 * waf_mail_backend <addr> <port>: the upstream MTA returned as
 * Auth-Server/Auth-Port on allow. <addr> must be a numeric IP -- the mail
 * module parses it with ngx_parse_addr(), which rejects hostnames.
 */
static char *
ngx_http_waf_set_mail_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;
    ngx_addr_t                addr;
    ngx_int_t                 port;

    if (wlcf->mail_backend_addr.data != NULL) {
        return "is duplicate";
    }

    if (ngx_parse_addr(cf->pool, &addr, value[1].data, value[1].len)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_mail_backend address \"%V\" is not a numeric "
                           "IP (the mail proxy cannot resolve hostnames)",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    port = ngx_atoi(value[2].data, value[2].len);
    if (port == NGX_ERROR || port < 1 || port > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_mail_backend port \"%V\" is invalid",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    wlcf->mail_backend_addr = value[1];
    wlcf->mail_backend_port = value[2];

    return NGX_CONF_OK;
}


/*
 * waf_status: turn this location into the lock-free statistics endpoint by
 * installing the content handler. Operators are expected to wrap it in an
 * access-restricted location (allow/deny); the access phase runs before this
 * content handler, so policy is enforced before any counter is rendered.
 */
static char *
ngx_http_waf_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_waf_status_handler;

    return NGX_CONF_OK;
}


/*
 * Register the three log variables, all NOCACHEABLE so the get_handler runs
 * on demand and works even where `waf off` skips the phase handlers (lazy
 * ctx alloc):
 *   $waf_type    - UA class (regular/crawler/ai-crawler/bot/scanner/empty)
 *   $waf_country - ISO-2 geo country (lazy lookup; one per request via ctx)
 *   $waf_reason  - verdict token from waf_reason_str[] ("none" when allowed)
 */
static ngx_int_t
ngx_http_waf_preconfiguration(ngx_conf_t *cf)
{
    ngx_str_t             type_name = ngx_string("waf_type");
    ngx_str_t             country_name = ngx_string("waf_country");
    ngx_str_t             reason_name = ngx_string("waf_reason");
    ngx_str_t             asn_name = ngx_string("waf_asn");
    ngx_str_t             ja4_name = ngx_string("waf_ja4_hash");
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &type_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_waf_type_variable;

    var = ngx_http_add_variable(cf, &country_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_waf_country_variable;

    var = ngx_http_add_variable(cf, &reason_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_waf_reason_variable;

    var = ngx_http_add_variable(cf, &asn_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_waf_asn_variable;

    var = ngx_http_add_variable(cf, &ja4_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_waf_ja4_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_type_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t                *s;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    if (!ctx->classified) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        ngx_http_waf_ua_classify(r, wlcf, ctx);
    }

    s = &waf_type_str[ctx->ua];

    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * $waf_country: the geo country (ISO-2) of the request client, or not_found
 * when no geo record exists / geo is not configured. Reuses the ctx geo cache
 * so at most ONE geo lookup happens per request even when the preaccess
 * handler, geo blocking and per-country counters are all active: once
 * geo_done is set the lookup is never repeated.
 */
static ngx_int_t
ngx_http_waf_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    struct sockaddr            *sa;
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_geo_result_t   res;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    if (!ctx->geo_done) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

        if (wlcf->rep.geo_db != NULL) {
            sa = (ctx->client_sa != NULL) ? ctx->client_sa
                                          : r->connection->sockaddr;
            ngx_http_waf_geo_lookup(wlcf->rep.geo_db, sa, &res);

            if (res.found) {
                ctx->country[0] = res.country[0];
                ctx->country[1] = res.country[1];
            }
        }

        ctx->geo_done = 1;
    }

    /* country[0]==0: no record (or geo disabled) -> the variable is unset */
    if (ctx->country[0] == 0) {
        v->valid = 0;
        v->no_cacheable = 1;
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = 2;
    v->data = ctx->country;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * $waf_reason: the verdict token (none/allowlist/blocklist/geo/geo_whitelist/
 * flag/scanner_ua/empty_ua/scanner_path). ctx->reason is zero (WAF_REASON_NONE
 * -> "none") until the preaccess handler resolves a verdict, so an allowed or
 * unclassified request renders "none".
 */
static ngx_int_t
ngx_http_waf_reason_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t           *s;
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    s = &waf_reason_str[ctx->reason];

    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * $waf_asn: the autonomous-system number of the request client (decimal), or
 * not_found when no geo record exists / geo is not configured / asn==0. Reuses
 * the ctx asn cache (filled by the preaccess reputation check) so no extra geo
 * lookup happens on the hot path; falls back to its own lookup on paths where
 * preaccess did not run (e.g. `waf off`).
 */
static ngx_int_t
ngx_http_waf_asn_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    struct sockaddr            *sa;
    ngx_http_waf_ctx_t         *ctx;
    ngx_http_waf_loc_conf_t    *wlcf;
    ngx_http_waf_geo_result_t   res;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    if (!ctx->asn_done) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

        if (wlcf->rep.geo_db != NULL) {
            sa = (ctx->client_sa != NULL) ? ctx->client_sa
                                          : r->connection->sockaddr;
            ngx_http_waf_geo_lookup(wlcf->rep.geo_db, sa, &res);

            if (res.found) {
                ctx->asn = res.asn;
            }
        }

        ctx->asn_done = 1;
    }

    /* asn==0: no record (or geo disabled) -> the variable is unset */
    if (ctx->asn == 0) {
        v->valid = 0;
        v->no_cacheable = 1;
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT32_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%uD", ctx->asn) - p;
    v->data = p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * $waf_ja4_hash: the JA4 TLS fingerprint computed by the client_hello callback
 * at handshake and stashed on the SSL connection (ex-data). NOT recomputed
 * here -- the raw ClientHello is long gone by request time. not_found on plain
 * HTTP, when no JA4 was stored, or before the ex-index is allocated.
 */
static ngx_int_t
ngx_http_waf_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HTTP_SSL)
    ngx_str_t       *j;
    ngx_ssl_conn_t  *ssl_conn;

    if (ngx_http_waf_ja4_ssl_index >= 0
        && r->connection->ssl != NULL
        && (ssl_conn = r->connection->ssl->connection) != NULL)
    {
        j = SSL_get_ex_data(ssl_conn, ngx_http_waf_ja4_ssl_index);
        if (j != NULL && j->len != 0) {
            v->len = j->len;
            v->data = j->data;
            v->valid = 1;
            v->no_cacheable = 1;
            v->not_found = 0;
            return NGX_OK;
        }
    }
#endif

    v->valid = 0;
    v->no_cacheable = 1;
    v->not_found = 1;
    return NGX_OK;
}


static void *
ngx_http_waf_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));
    if (wmcf == NULL) {
        return NULL;
    }

    /* pcalloc: stat_zone = NULL, nvhosts = 0 (filled in postconfiguration) */
    return wmcf;
}


static char *
ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf)
{
    /* the shm zone is added in postconfiguration, once nvhosts is known */
    return NGX_CONF_OK;
}


/*
 * Status shm zone init(zone, data). Follows ngx_http_limit_req_module: the
 * `data` argument is the PREVIOUS cycle's struct on reload (non-NULL),
 * shm.exists marks a worker re-attach, and a fresh segment is slab-allocated
 * and zeroed once. zone->data is keyed deliberately, NOT off zone->data==NULL
 * (which is always NULL here): at add time it holds the main conf so this
 * callback can size the allocation; afterwards it is swapped to the struct
 * pointer that the HTTP head (wmcf->stat_zone->data) and the STREAM head
 * (its resolved zone->data) both read at runtime.
 */
static ngx_int_t
ngx_http_waf_stat_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                     size;
    ngx_slab_pool_t           *shpool;
    ngx_http_waf_stat_shm_t   *sh;
    ngx_http_waf_stat_shm_t   *osh = data;
    ngx_http_waf_main_conf_t  *wmcf;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* reload: re-use the previous cycle's struct verbatim, stamp the reload */
    if (osh != NULL) {
        osh->last_reload_time = ngx_time();
        shm_zone->data = osh;
        return NGX_OK;
    }

    /* worker re-attach to an existing segment */
    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    /* fresh segment: shm_zone->data still holds the main conf (set at add) */
    wmcf = shm_zone->data;

    size = sizeof(ngx_http_waf_stat_shm_t)
           + wmcf->nvhosts * sizeof(ngx_http_waf_stat_vhost_t);

    sh = ngx_slab_alloc(shpool, size);
    if (sh == NULL) {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                      "waf: cannot allocate status zone");
        return NGX_ERROR;
    }

    ngx_memzero(sh, size);
    sh->start_time = ngx_time();
    sh->last_reload_time = sh->start_time;
    sh->nvhosts = wmcf->nvhosts;

    shpool->data = sh;
    shm_zone->data = sh;

    return NGX_OK;
}


/*
 * Add the always-on "waf_status" shm zone, sized from the fixed counter
 * struct plus the per-vhost array (nvhosts, set by the vhost walk just
 * before this). The multiply-then-add is integer-overflow guarded. The
 * STREAM head re-resolves the same name+tag with size 0 (no init). A few
 * extra pages cover the ngx_slab_pool_t header + page bookkeeping that core
 * overlays on every shm zone.
 */
static ngx_int_t
ngx_http_waf_stat_add_zone(ngx_conf_t *cf)
{
    size_t                     size;
    ngx_str_t                  name = ngx_string("waf_status");
    ngx_shm_zone_t            *zone;
    ngx_http_waf_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    if (wmcf->nvhosts
        > (NGX_MAX_SIZE_T_VALUE - sizeof(ngx_http_waf_stat_shm_t))
          / sizeof(ngx_http_waf_stat_vhost_t))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: too many server blocks for the status zone");
        return NGX_ERROR;
    }

    size = sizeof(ngx_http_waf_stat_shm_t)
           + wmcf->nvhosts * sizeof(ngx_http_waf_stat_vhost_t);

    size = ngx_align(size + 4 * ngx_pagesize, ngx_pagesize);

    zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_waf_module);
    if (zone == NULL) {
        return NGX_ERROR;
    }

    zone->init = ngx_http_waf_stat_init_zone;
    zone->data = wmcf;   /* init reads nvhosts, then swaps in the struct ptr */

    wmcf->stat_zone = zone;

    return NGX_OK;
}


/*
 * Walk every configured server{} and assign it a sequential per-vhost stat
 * slot (0..nvhosts-1), storing the final count in the main conf. MUST run
 * before ngx_http_waf_stat_add_zone, because nvhosts sizes the zone. The WAF
 * srv conf is reached through the core server conf's module context.
 */
static ngx_int_t
ngx_http_waf_stat_assign_vhosts(ngx_conf_t *cf)
{
    ngx_uint_t                   i;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_waf_srv_conf_t     *wscf;
    ngx_http_waf_main_conf_t    *wmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        wscf = cscfp[i]->ctx->srv_conf[ngx_http_waf_module.ctx_index];
        wscf->stat_index = i;
    }

    wmcf->nvhosts = cmcf->servers.nelts;

    return NGX_OK;
}


#if (NGX_HTTP_SSL) && defined(SSL_CLIENT_HELLO_SUCCESS)

/*
 * client_hello callback (wrapper-chain, partner-selected Option 5). Compute the
 * JA4 off the raw ClientHello and stash it on the SSL connection, then chain to
 * nginx's own ngx_ssl_client_hello_callback so SNI cert selection runs
 * unchanged. Covers TCP-TLS and QUIC from this one hook.
 *
 * NULL-guard (inspector C2): nginx's callback unconditionally dereferences the
 * arg it fetches from SSL_CTX ex-data; if that arg was never set on this CTX,
 * chaining would crash. So we chain only when the arg is present, otherwise we
 * return SUCCESS and let the handshake proceed. JA4 failure is always non-fatal.
 */
static int
ngx_http_waf_ja4_client_hello_cb(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    ngx_str_t         *ja4;
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c != NULL && ngx_http_waf_ja4_ssl_index >= 0) {
        ja4 = ngx_palloc(c->pool, sizeof(ngx_str_t));
        if (ja4 != NULL
            && ngx_http_waf_ja4_compute(ssl_conn, c->pool, ja4) == NGX_OK)
        {
            (void) SSL_set_ex_data(ssl_conn, ngx_http_waf_ja4_ssl_index, ja4);
        }
    }

    if (SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl_conn),
                            ngx_ssl_client_hello_arg_index)
        == NULL)
    {
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    return ngx_ssl_client_hello_callback(ssl_conn, ad, NULL);
}


/*
 * Allocate the JA4 SSL ex-data index (once) and install the wrapper callback on
 * every server SSL_CTX that nginx has already armed with its own client_hello
 * arg. Runs in postconfiguration, AFTER ngx_http_ssl_module's merge created the
 * contexts and set the arg ex-data, so the wrapper always has a valid chain
 * target. Contexts with no arg (no ssl{} on that server) are left untouched.
 */
static ngx_int_t
ngx_http_waf_ja4_init(ngx_conf_t *cf)
{
    ngx_uint_t                   i;
    SSL_CTX                     *ctx;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (ngx_http_waf_ja4_ssl_index < 0) {
        ngx_http_waf_ja4_ssl_index =
            SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (ngx_http_waf_ja4_ssl_index < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "waf: cannot allocate JA4 SSL ex-data index");
            return NGX_ERROR;
        }
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        sscf = cscfp[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            continue;
        }

        ctx = sscf->ssl.ctx;

        if (SSL_CTX_get_ex_data(ctx, ngx_ssl_client_hello_arg_index) == NULL) {
            continue;   /* nginx armed no client_hello arg here -> do not hook */
        }

        SSL_CTX_set_client_hello_cb(ctx, ngx_http_waf_ja4_client_hello_cb,
                                    NULL);
    }

    return NGX_OK;
}

#endif /* NGX_HTTP_SSL && SSL_CLIENT_HELLO_SUCCESS */


static ngx_int_t
ngx_http_waf_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_postread_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_preaccess_handler;

    /* Apache header + error-page spoofing filters */
    if (ngx_http_waf_spoof_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* assign each server{} a per-vhost counter slot (this sizes the zone) */
    if (ngx_http_waf_stat_assign_vhosts(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* add the always-on lock-free status zone, now that nvhosts is known */
    if (ngx_http_waf_stat_add_zone(cf) != NGX_OK) {
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL) && defined(SSL_CLIENT_HELLO_SUCCESS)
    /* install the JA4 client_hello wrapper on every server SSL_CTX (runs after
     * the ssl module's merge has created the contexts + armed its own arg) */
    if (ngx_http_waf_ja4_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}
