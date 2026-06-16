/*
 * ngx_http_heavybag_module - edge firewall for nginx
 *
 * Module glue: the single ngx_module_t, directives, configuration
 * create/merge, postconfiguration (phase + header-filter install) and
 * the master/worker init hooks (geo-DB load). Phase handlers are thin
 * and dispatch into the per-concern cores.
 */

#include "ngx_http_heavybag.h"
#include "heavybag_match.h"
#include "heavybag_spoof.h"
#include "heavybag_geo.h"
#include "heavybag_reputation.h"
#include "heavybag_authhttp.h"
#include "heavybag_status.h"
#include "heavybag_rate.h"
#include "heavybag_ja4.h"
#include "heavybag_ua_parse.h"

#if (NGX_HTTP_SSL)
#include <ngx_http_ssl_module.h>
#endif


#define NGX_HTTP_HEAVYBAG_DEFAULT_TOKEN  "Apache/2.4.68 (Unix)"


#if (NGX_HTTP_SSL)
/*
 * SSL ex-data index holding the per-connection JA4 string (an ngx_str_t* from
 * the connection pool, set by the client_hello callback at handshake time).
 * Allocated once in postconfiguration; -1 until then -> $waf_ja4_hash unset.
 */
static int  ngx_http_heavybag_ja4_ssl_index = -1;

/* saved next-in-chain for the opt-in X-WAF-Reason header filter; installed in
 * postconfiguration (see ngx_http_heavybag_reason_header_filter). */
static ngx_http_output_header_filter_pt  ngx_http_heavybag_next_reason_filter;
#endif


/*
 * enum -> $waf_type string, indexed by ngx_http_heavybag_ua_e. The list-backed
 * categories occupy [0, HEAVYBAG_UA_LIST_MAX); REGULAR and EMPTY follow. A hit is
 * returned by reference (static literal), never copied.
 */
ngx_str_t  heavybag_type_str[HEAVYBAG_UA_MAX] = {
    ngx_string("scanner"),
    ngx_string("ai-crawler"),
    ngx_string("crawler"),
    ngx_string("bot"),
    ngx_string("regular"),
    ngx_string("empty")
};


/*
 * enum -> $waf_reason string, indexed by ngx_http_heavybag_reason_e. The single
 * source of truth (heavybag_rep.h) also indexes the per-reason counters; this
 * table only renders the token. A hit is returned by reference (static
 * literal), never copied. Must stay in lockstep with ngx_http_heavybag_reason_e.
 */
ngx_str_t  heavybag_reason_str[HEAVYBAG_REASON_MAX] = {
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
    ngx_string("method"),
    ngx_string("args"),
    ngx_string("cookie"),
    ngx_string("referer"),
    ngx_string("fake_bot"),
    ngx_string("rate_limit")
};


/*
 * `waf` / `waf_stream` directive mode. Three-state so a config can observe
 * without blocking (detect). `on` is an alias for enforce (backward compat).
 * Fail-CLOSED: detect is the ONLY non-blocking value (see
 * ngx_http_heavybag_finalize_decision); any other value blocks.
 */
static ngx_conf_enum_t  ngx_http_heavybag_mode[] = {
    { ngx_string("off"),     HEAVYBAG_MODE_OFF     },
    { ngx_string("detect"),  HEAVYBAG_MODE_DETECT  },
    { ngx_string("enforce"), HEAVYBAG_MODE_ENFORCE },
    { ngx_string("on"),      HEAVYBAG_MODE_ENFORCE },
    { ngx_null_string, 0 }
};


static ngx_int_t ngx_http_heavybag_postread_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_heavybag_preaccess_handler(ngx_http_request_t *r);

static void *ngx_http_heavybag_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_heavybag_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_heavybag_set_scanner_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_ua_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_verified_bot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_ja4_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_sig_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_method_allow(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_method_deny(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_geo_whitelist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_trusted_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_mail_auth(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_mail_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_rate_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_heavybag_set_rate_limit(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_heavybag_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_heavybag_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_heavybag_reason_header_filter(ngx_http_request_t *r);
static void *ngx_http_heavybag_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_heavybag_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_heavybag_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_heavybag_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_heavybag_stat_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_heavybag_stat_assign_vhosts(ngx_conf_t *cf);
static ngx_int_t ngx_http_heavybag_stat_add_zone(ngx_conf_t *cf);
static ngx_int_t ngx_http_heavybag_type_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_reason_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_asn_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_ua_browser_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_ua_browser_version_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_ua_category_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_ua_vendor_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_heavybag_ua_spoofed_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_heavybag_commands[] = {

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_heavybag_loc_conf_t, mode),
      &ngx_http_heavybag_mode },

    { ngx_string("waf_bot_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_heavybag_loc_conf_t, bot_block),
      NULL },

    { ngx_string("waf_fake_bot_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_heavybag_loc_conf_t, fake_bot_block),
      NULL },

    { ngx_string("waf_scanner_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_scanner_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* UA signature lists: one shared setter, category carried in cmd->post */
    { ngx_string("waf_scanner_ua_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) HEAVYBAG_UA_SCANNER },

    { ngx_string("waf_ai_crawler_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) HEAVYBAG_UA_AI_CRAWLER },

    { ngx_string("waf_crawler_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) HEAVYBAG_UA_CRAWLER },

    { ngx_string("waf_bot_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_ua_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) HEAVYBAG_UA_BOT },

    /* verified-bot CIDR allowlist: "waf_verified_bot <class> <cidr-path>" --
     * the class string maps to a UA enum, so one directive covers every
     * positively verifiable class (crawler / ai_crawler) */
    { ngx_string("waf_verified_bot"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_heavybag_set_verified_bot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* request-field signature lists: one shared setter, subject in cmd->post */
    { ngx_string("waf_args_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_sig_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) HEAVYBAG_SIG_ARGS },

    { ngx_string("waf_cookie_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_sig_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) HEAVYBAG_SIG_COOKIE },

    { ngx_string("waf_referer_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_sig_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) HEAVYBAG_SIG_REFERER },

    { ngx_string("waf_server_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_heavybag_loc_conf_t, server_token),
      NULL },

    /* X-WAF-Reason debug header: OFF by default (no verdict disclosure in
     * production); the replay/test harness turns it on. */
    { ngx_string("waf_reason_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_heavybag_loc_conf_t, reason_header),
      NULL },

    { ngx_string("waf_geo_db"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_geo_db,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_heavybag_set_geo_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_asn_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_heavybag_set_asn_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_method_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_heavybag_set_method_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_method_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_heavybag_set_method_deny,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_whitelist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_heavybag_set_geo_whitelist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_flag_block"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_heavybag_set_flag_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_trusted_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_trusted_proxy,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_blocklist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_blocklist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_allowlist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_allowlist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_mail_auth"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_heavybag_set_mail_auth,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_mail_backend"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_heavybag_set_mail_backend,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_heavybag_set_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* one process-wide per-IP rate-limit shm zone, declared in http{} and
     * shared with the stream head; must precede any waf_rate_limit use */
    { ngx_string("waf_rate_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_rate_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_rate_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_heavybag_set_rate_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* waf_ja4_list <path>: load the JA4 fingerprint -> coarse-TLS-family table
     * consumed by $waf_ua_is_spoofed. Optional: absent -> the JA4 half of the
     * spoof signal is inert (CIDR-only). */
    { ngx_string("waf_ja4_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_heavybag_set_ja4_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_heavybag_module_ctx = {
    ngx_http_heavybag_preconfiguration,     /* preconfiguration */
    ngx_http_heavybag_postconfiguration,    /* postconfiguration */

    ngx_http_heavybag_create_main_conf,     /* create main configuration */
    ngx_http_heavybag_init_main_conf,       /* init main configuration */

    ngx_http_heavybag_create_srv_conf,      /* create server configuration */
    ngx_http_heavybag_merge_srv_conf,       /* merge server configuration */

    ngx_http_heavybag_create_loc_conf,      /* create location configuration */
    ngx_http_heavybag_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_heavybag_module = {
    NGX_MODULE_V1,
    &ngx_http_heavybag_module_ctx,          /* module context */
    ngx_http_heavybag_commands,             /* module directives */
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
ngx_http_heavybag_postread_handler(ngx_http_request_t *r)
{
    ngx_addr_t                addr;
    ngx_http_heavybag_ctx_t       *ctx;
    ngx_http_heavybag_loc_conf_t  *wlcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);

    if (wlcf->mode == HEAVYBAG_MODE_OFF) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
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

#if (NGX_HTTP_SSL)
    /*
     * Copy the per-connection JA4 (computed by the ClientHello callback at TLS
     * handshake, before any HTTP phase) into ctx HERE at POST_READ -- the
     * earliest phase -- so every later phase sees it, including REWRITE-phase
     * consumers of $waf_ua_is_spoofed (e.g. `if ($waf_ua_is_spoofed)`). Points
     * at the ex-data ngx_str_t (no copy); ctx->ja4.len 0 stays = no TLS ->
     * JA4 spoof half is inert. heavybag_ua_parse.c never sees the static ssl index.
     */
    if (ngx_http_heavybag_ja4_ssl_index >= 0
        && r->connection->ssl != NULL
        && r->connection->ssl->connection != NULL)
    {
        ngx_str_t  *ja4j;

        ja4j = SSL_get_ex_data(r->connection->ssl->connection,
                               ngx_http_heavybag_ja4_ssl_index);
        if (ja4j != NULL && ja4j->len != 0) {
            ctx->ja4 = *ja4j;
        }
    }
#endif

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
ngx_http_heavybag_stat_cc_bump(void *shm, uint16_t cc16, ngx_uint_t blocked)
{
    ngx_uint_t                probe, slot;
    ngx_atomic_uint_t         cur;
    ngx_http_heavybag_stat_cc_t   *cc;
    ngx_http_heavybag_stat_shm_t  *sh = shm;

    if (sh == NULL || cc16 == 0) {
        return;
    }

    slot = (ngx_uint_t) cc16 % HEAVYBAG_STAT_CC_SLOTS;

    for (probe = 0; probe < HEAVYBAG_STAT_CC_SLOTS; probe++) {
        cc = &sh->cc[(slot + probe) % HEAVYBAG_STAT_CC_SLOTS];

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
ngx_http_heavybag_stat_stream_bump(void *shm, ngx_http_heavybag_reason_e reason,
    ngx_uint_t denied)
{
    ngx_http_heavybag_stat_shm_t  *sh = shm;

    if (sh == NULL) {
        return;
    }

    (void) ngx_atomic_fetch_add(&sh->stream_connections_total, 1);

    if (!denied) {
        (void) ngx_atomic_fetch_add(&sh->stream_allowed, 1);
        return;
    }

    if ((ngx_uint_t) reason < HEAVYBAG_REASON_MAX) {
        (void) ngx_atomic_fetch_add(&sh->stream_denied[reason], 1);
    }
}


/*
 * Detect-mode STREAM counter: record what WOULD have been denied without
 * actually denying it. Opaque-pointer entry for the stream head (which never
 * sees ngx_http_heavybag_stat_shm_t); NULL zone is a no-op. Unlike
 * ngx_http_heavybag_stat_stream_bump it does NOT touch the connection/allowed
 * totals -- the detect path counts the connection as allowed separately.
 */
void
ngx_http_heavybag_stat_stream_would_block(void *shm, ngx_http_heavybag_reason_e reason)
{
    ngx_http_heavybag_stat_shm_t  *sh = shm;

    if (sh == NULL) {
        return;
    }

    if ((ngx_uint_t) reason < HEAVYBAG_REASON_MAX) {
        (void) ngx_atomic_fetch_add(&sh->stream_would_block[reason], 1);
    }
}


/* libloc flag bit -> flag_blocked[] slot (Tor has no bit; it is a CC verdict) */
static const uint16_t  heavybag_flag_bits[HEAVYBAG_FLAG_SLOTS] = {
    NGX_HTTP_HEAVYBAG_GEO_FLAG_ANON_PROXY,
    NGX_HTTP_HEAVYBAG_GEO_FLAG_SATELLITE,
    NGX_HTTP_HEAVYBAG_GEO_FLAG_ANYCAST,
    NGX_HTTP_HEAVYBAG_GEO_FLAG_DROP
};


/*
 * Record a blocked HTTP verdict: ctx state (so $waf_reason renders even with
 * no zone), then the global per-reason counter, the response-code counter
 * and the per-vhost slot. sh may be NULL (zone not yet populated). status is
 * the HTTP code being returned (403 / 404 / 444). reason is always a valid
 * enum value, so the array indexes need no extra bound check.
 */
static void
ngx_http_heavybag_stat_http_block(ngx_http_heavybag_stat_shm_t *sh, ngx_uint_t idx,
    ngx_http_heavybag_ctx_t *ctx, ngx_http_heavybag_reason_e reason, ngx_int_t status)
{
    ngx_http_heavybag_stat_vhost_t  *v;

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
    case NGX_HTTP_TOO_MANY_REQUESTS:
        (void) ngx_atomic_fetch_add(&sh->http_resp_429, 1);
        break;
    default:
        break;
    }

    if (idx < sh->nvhosts) {
        v = ngx_http_heavybag_stat_vhost(sh, idx);
        (void) ngx_atomic_fetch_add(&v->blocked[reason], 1);
    }
}


/*
 * Detect-aware block finalizer, the single chokepoint every HTTP block point
 * funnels through. In HEAVYBAG_MODE_DETECT the verdict is observed only: the
 * global would_block[reason] counter is bumped, ctx->reason is set (so
 * $waf_reason still renders the would-be verdict) and NGX_DECLINED is
 * returned so the request proceeds. In every other (blocking) mode the
 * standard block accounting runs (ngx_http_heavybag_stat_http_block) and block_code
 * is returned. FAIL-CLOSED: detect is the ONLY non-blocking branch; any
 * unexpected mode value blocks. sh / idx are re-resolved from r so callers
 * need not thread them through.
 */
static ngx_int_t
ngx_http_heavybag_finalize_decision(ngx_http_request_t *r, ngx_http_heavybag_ctx_t *ctx,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_http_heavybag_reason_e reason,
    ngx_int_t block_code)
{
    ngx_uint_t                 idx;
    ngx_http_heavybag_stat_shm_t   *sh;
    ngx_http_heavybag_srv_conf_t   *wscf;
    ngx_http_heavybag_main_conf_t  *wmcf;

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_heavybag_module);
    wscf = ngx_http_get_module_srv_conf(r, ngx_http_heavybag_module);
    sh = (wmcf->stat_zone != NULL) ? wmcf->stat_zone->data : NULL;
    idx = (wscf->stat_index < wmcf->nvhosts) ? wscf->stat_index : 0;

    if (wlcf->mode == HEAVYBAG_MODE_DETECT) {
        ctx->reason = reason;
        ctx->verdict_set = 1;

        if (sh != NULL) {
            (void) ngx_atomic_fetch_add(&sh->http_would_block[reason], 1);
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: would-block (%V) [detect]", &heavybag_reason_str[reason]);

        return NGX_DECLINED;
    }

    ngx_http_heavybag_stat_http_block(sh, idx, ctx, reason, block_code);

    return block_code;
}


/*
 * Case-insensitive lookup of the request method name in a config list of
 * non-standard method tokens (e.g. TRACK, DEBUG) that nginx does not parse
 * into an NGX_HTTP_* bit. NULL list -> no match.
 */
static ngx_int_t
ngx_http_heavybag_method_in_list(ngx_http_request_t *r, ngx_array_t *list)
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
ngx_http_heavybag_method_allowed(ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_http_request_t *r)
{
    return (r->method & wlcf->allow_mask)
           || ngx_http_heavybag_method_in_list(r, wlcf->allow_list);
}


/* The request method is on the blacklist (standard bit or non-standard name). */
static ngx_int_t
ngx_http_heavybag_method_denied(ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_http_request_t *r)
{
    return (r->method & wlcf->deny_mask)
           || ngx_http_heavybag_method_in_list(r, wlcf->deny_list);
}


/*
 * %-decode raw into an r->pool buffer, then match it against the action row
 * re_bucket. The scanner matches the already-decoded r->uri; r->args / Cookie
 * / Referer are raw, so we decode for byte-consistency (e.g. "%27union" must
 * match a "'union" pattern). An empty subject or a failed decode alloc yields
 * NGX_DECLINED (fail-open at the decode step only -- a genuine match still
 * blocks). Returns the scanner_lookup status code, or NGX_DECLINED on no hit.
 */
static ngx_int_t
ngx_http_heavybag_sig_lookup_decoded(ngx_http_request_t *r, ngx_regex_t **re_bucket,
    ngx_str_t *raw)
{
    u_char     *dst, *src;
    ngx_str_t   dec;

    if (raw->len == 0) {
        return NGX_DECLINED;
    }

    dst = ngx_pnalloc(r->pool, raw->len);
    if (dst == NULL) {
        return NGX_DECLINED;
    }

    dec.data = dst;
    src = raw->data;
    ngx_unescape_uri(&dst, &src, raw->len, 0);   /* %XX -> byte, in place */
    dec.len = dst - dec.data;

    return ngx_http_heavybag_scanner_lookup(re_bucket, &dec);
}


/*
 * Run the cookie signature row against every Cookie request header value
 * (a client may send more than one), decoding each before the match. A
 * generic header walk -- not the version-dependent r->headers_in.cookie
 * slot -- so the build is independent of the nginx header-struct layout.
 * Returns the first match's status code, or NGX_DECLINED when none match.
 */
static ngx_int_t
ngx_http_heavybag_sig_cookie_lookup(ngx_http_request_t *r, ngx_regex_t **re_bucket)
{
    ngx_int_t         rc;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == sizeof("Cookie") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Cookie",
                               sizeof("Cookie") - 1)
               == 0)
        {
            rc = ngx_http_heavybag_sig_lookup_decoded(r, re_bucket, &h[i].value);
            if (rc != NGX_DECLINED) {
                return rc;
            }
        }
    }

    return NGX_DECLINED;
}


/*
 * PREACCESS phase. Order is cheap -> expensive: IP reputation
 * (blocklist/geo/flags) -> bot heuristics (string match) -> scanner regex.
 * Subrequests and internal redirects are never re-scanned.
 */
static ngx_int_t
ngx_http_heavybag_preaccess_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_str_t                   reason;
    uint16_t                    cc16, matched;
    ngx_uint_t                  idx, k;
    struct sockaddr            *sa;
    ngx_http_heavybag_ctx_t         *ctx;
    ngx_http_heavybag_verdict_t      verdict;
    ngx_http_heavybag_stat_shm_t    *sh;
    ngx_http_heavybag_loc_conf_t    *wlcf;
    ngx_http_heavybag_srv_conf_t    *wscf;
    ngx_http_heavybag_main_conf_t   *wmcf;
    ngx_http_heavybag_stat_vhost_t  *v;
    ngx_http_heavybag_rate_rule_t   *rate_rule;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);

    if (wlcf->mode == HEAVYBAG_MODE_OFF) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }

    /* resolve the shared counters + this vhost's slot (slot 0 fallback) */
    wmcf = ngx_http_get_module_main_conf(r, ngx_http_heavybag_module);
    wscf = ngx_http_get_module_srv_conf(r, ngx_http_heavybag_module);
    sh = (wmcf->stat_zone != NULL) ? wmcf->stat_zone->data : NULL;
    idx = (wscf->stat_index < wmcf->nvhosts) ? wscf->stat_index : 0;

    /* count this request once, before any verdict is reached */
    if (sh != NULL) {
        (void) ngx_atomic_fetch_add(&sh->http_requests_total, 1);
        if (idx < sh->nvhosts) {
            v = ngx_http_heavybag_stat_vhost(sh, idx);
            (void) ngx_atomic_fetch_add(&v->requests, 1);
        }
    }

    sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr;

    rc = ngx_http_heavybag_reputation_check(&wlcf->rep, sa, &reason, &verdict);

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
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, verdict.reason, rc)
            == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: reputation block (%V)", &reason);

        /* per-flag breakdown only for a network-flag verdict */
        if (sh != NULL && verdict.reason == HEAVYBAG_REASON_FLAG) {
            matched = verdict.flags & wlcf->rep.flag_mask;
            for (k = 0; k < HEAVYBAG_FLAG_SLOTS; k++) {
                if (matched & heavybag_flag_bits[k]) {
                    (void) ngx_atomic_fetch_add(&sh->flag_blocked[k], 1);
                }
            }
        }

        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
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
    if (wlcf->method_allow_set && !ngx_http_heavybag_method_allowed(wlcf, r)) {
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, HEAVYBAG_REASON_METHOD,
                                           NGX_HTTP_NOT_FOUND) == NGX_DECLINED)
        {
            return NGX_DECLINED;
        }
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: method \"%V\" not allowed", &r->method_name);
        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
        }
        return NGX_HTTP_NOT_FOUND;
    }

    if (wlcf->method_deny_set && ngx_http_heavybag_method_denied(wlcf, r)) {
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, HEAVYBAG_REASON_METHOD,
                                           NGX_HTTP_NOT_FOUND) == NGX_DECLINED)
        {
            return NGX_DECLINED;
        }
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: method \"%V\" denied", &r->method_name);
        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
        }
        return NGX_HTTP_NOT_FOUND;
    }

    /*
     * Per-IP rate limit (token bucket). The rule is selected by reputation
     * (for_geo); a NULL rule means no limit applies to this client. The
     * backing zone is on the main conf (HTTP-owned, shared with the stream
     * head). NGX_BUSY -> 429, funnelled through the detect-aware finalizer
     * like every other block point. The manual cc_bump runs only when the
     * finalizer actually blocks (enforce), never in detect mode.
     */
    if (wlcf->rate_rules != NULL) {
        rate_rule = ngx_http_heavybag_rate_rule_select(wlcf->rate_rules, &verdict);
        if (rate_rule != NULL
            && ngx_http_heavybag_rate_check(
                   (wmcf->rate_zone != NULL) ? wmcf->rate_zone->data : NULL,
                   sa, rate_rule->rate_num_fp, rate_rule->period_ms,
                   rate_rule->burst_fp)
               == NGX_BUSY)
        {
            if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf,
                    HEAVYBAG_REASON_RATE_LIMIT, NGX_HTTP_TOO_MANY_REQUESTS)
                == NGX_DECLINED)
            {
                return NGX_DECLINED;   /* detect: would-block recorded, allow */
            }

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "heavybag: rate limit exceeded");

            if (verdict.geo_valid) {
                ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
            }

            return NGX_HTTP_TOO_MANY_REQUESTS;
        }
    }

    /*
     * Classify the UA into ctx->ua ($waf_type) unconditionally; blocking is
     * a separate policy. With bot_block on, only the unambiguously-hostile
     * outcomes (scanner tools, missing UA) are dropped -- crawler/ai-crawler/
     * bot stay flag-only for the operator to act on via $waf_type.
     */
    ngx_http_heavybag_ua_classify(r, wlcf, ctx);

    /* UA distribution over every reputation-passed (classified) request */
    if (sh != NULL && (ngx_uint_t) ctx->ua < HEAVYBAG_UA_MAX) {
        (void) ngx_atomic_fetch_add(&sh->http_ua[ctx->ua], 1);
    }

    /*
     * Descriptive-UA category distribution + spoof rate. Only computed when the
     * status zone is live: the parse + spoof eval are otherwise lazy (run on
     * first $waf_ua_* access), so a deployment using neither the variables nor
     * waf_status keeps paying nothing here. Once per main request.
     */
    if (sh != NULL) {
        ngx_http_heavybag_ua_parse(r, wlcf, ctx);        /* sets ctx->ua_category */
        ngx_http_heavybag_ua_spoof_eval(r, wlcf, ctx);   /* sets ctx->is_spoofed  */

        if ((ngx_uint_t) ctx->ua_category < HEAVYBAG_CAT_MAX) {
            (void) ngx_atomic_fetch_add(&sh->http_ua_cat[ctx->ua_category], 1);
        }
        if (ctx->is_spoofed) {
            (void) ngx_atomic_fetch_add(&sh->http_ua_spoofed, 1);
        }
    }

    if (wlcf->bot_block
        && (ctx->ua == HEAVYBAG_UA_SCANNER || ctx->ua == HEAVYBAG_UA_EMPTY))
    {
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf,
                (ctx->ua == HEAVYBAG_UA_SCANNER) ? HEAVYBAG_REASON_SCANNER_UA
                                            : HEAVYBAG_REASON_EMPTY_UA,
                NGX_HTTP_NOT_FOUND) == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: %V user-agent blocked", &heavybag_type_str[ctx->ua]);

        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
        }

        return NGX_HTTP_NOT_FOUND;
    }

    /*
     * Fake-bot: a request claiming to be a crawler whose canonical client IP is
     * outside the published range for that class. The class guard MUST stay to
     * the LEFT of the array index -- REGULAR/EMPTY are >= HEAVYBAG_UA_LIST_MAX and
     * would read past verified_bot_cidrs[]; a NULL slot (class unconfigured, or
     * an empty list -- cidr_add leaves the array NULL on zero entries) is
     * silently skipped, never treated as a block-all allowlist.
     */
    if (wlcf->fake_bot_block
        && (ctx->ua == HEAVYBAG_UA_CRAWLER || ctx->ua == HEAVYBAG_UA_AI_CRAWLER)
        && wlcf->verified_bot_cidrs[ctx->ua] != NULL
        && ngx_cidr_match(sa, wlcf->verified_bot_cidrs[ctx->ua]) != NGX_OK)
    {
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, HEAVYBAG_REASON_FAKE_BOT,
                                           NGX_HTTP_FORBIDDEN) == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: fake-bot blocked (%V claimed, IP out of range)",
                      &heavybag_type_str[ctx->ua]);

        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
        }

        return NGX_HTTP_FORBIDDEN;
    }

    rc = ngx_http_heavybag_scanner_lookup(wlcf->scanner_re, &r->uri);
    if (rc != NGX_DECLINED) {
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, HEAVYBAG_REASON_SCANNER_PATH,
                                           rc) == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: scanner path \"%V\" blocked (%i)", &r->uri, rc);

        if (sh != NULL) {
            switch (rc) {
            case NGX_HTTP_NOT_FOUND:
                (void) ngx_atomic_fetch_add(
                    &sh->http_scanner_path[HEAVYBAG_ACTION_404], 1);
                break;
            case NGX_HTTP_FORBIDDEN:
                (void) ngx_atomic_fetch_add(
                    &sh->http_scanner_path[HEAVYBAG_ACTION_403], 1);
                break;
            case NGX_HTTP_CLOSE:
                (void) ngx_atomic_fetch_add(
                    &sh->http_scanner_path[HEAVYBAG_ACTION_444], 1);
                break;
            default:
                break;
            }
        }

        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
        }

        return rc;
    }

    /*
     * Request-field signatures (args -> cookie -> referer). Same action-
     * bucketed machinery as the scanner path; the matched value is %-decoded
     * first so patterns see the same bytes as the decoded r->uri. First hit
     * wins and stops the chain. The per-reason counter is bumped inside
     * finalize_decision (http_blocked[HEAVYBAG_REASON_*]); there is no extra
     * action-split counter for these subjects.
     */
    rc = ngx_http_heavybag_sig_lookup_decoded(r, wlcf->sig_re[HEAVYBAG_SIG_ARGS],
                                         &r->args);
    if (rc != NGX_DECLINED) {
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, HEAVYBAG_REASON_ARGS, rc)
            == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: args signature blocked (%i)", rc);

        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
        }

        return rc;
    }

    rc = ngx_http_heavybag_sig_cookie_lookup(r, wlcf->sig_re[HEAVYBAG_SIG_COOKIE]);
    if (rc != NGX_DECLINED) {
        if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, HEAVYBAG_REASON_COOKIE, rc)
            == NGX_DECLINED)
        {
            return NGX_DECLINED;   /* detect: would-block recorded, allow */
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "heavybag: cookie signature blocked (%i)", rc);

        if (verdict.geo_valid) {
            ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
        }

        return rc;
    }

    if (r->headers_in.referer != NULL) {
        rc = ngx_http_heavybag_sig_lookup_decoded(r, wlcf->sig_re[HEAVYBAG_SIG_REFERER],
                                             &r->headers_in.referer->value);
        if (rc != NGX_DECLINED) {
            if (ngx_http_heavybag_finalize_decision(r, ctx, wlcf, HEAVYBAG_REASON_REFERER,
                                               rc) == NGX_DECLINED)
            {
                return NGX_DECLINED;   /* detect: would-block recorded, allow */
            }

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "heavybag: referer signature blocked (%i)", rc);

            if (verdict.geo_valid) {
                ngx_http_heavybag_stat_cc_bump(sh, cc16, 1);
            }

            return rc;
        }
    }

    /* allowed: record the (allowlist or none) reason and the allow counters */
    ctx->reason = verdict.reason;
    ctx->verdict_set = 1;

    if (sh != NULL) {
        (void) ngx_atomic_fetch_add(&sh->http_allowed, 1);
        if (verdict.reason == HEAVYBAG_REASON_ALLOWLIST) {
            (void) ngx_atomic_fetch_add(&sh->http_allowlist_hits, 1);
        }
        if (idx < sh->nvhosts) {
            v = ngx_http_heavybag_stat_vhost(sh, idx);
            (void) ngx_atomic_fetch_add(&v->allowed, 1);
        }
    }

    if (verdict.geo_valid) {
        ngx_http_heavybag_stat_cc_bump(sh, cc16, 0);
    }

    return NGX_DECLINED;
}


static void *
ngx_http_heavybag_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_heavybag_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_heavybag_loc_conf_t));
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
    conf->fake_bot_block = NGX_CONF_UNSET;
    conf->reason_header = NGX_CONF_UNSET;

    return conf;
}


/*
 * nginx merge step: for every conf field unset at this location level,
 * inherit the parent value -- mode (fail-closed default), the compiled
 * scanner and UA buckets, server token, all reputation data (geo db,
 * country/asn/flag lists, block and allow CIDR lists), trusted proxies,
 * the method allow/deny filters and the backend MTA pair. Warns when a
 * country whitelist is configured without a geo database.
 */
static char *
ngx_http_heavybag_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_heavybag_loc_conf_t  *prev = parent;
    ngx_http_heavybag_loc_conf_t  *conf = child;
    ngx_uint_t                i;

    /* fail-CLOSED default: an unset waf gate enforces (never silently off) */
    ngx_conf_merge_uint_value(conf->mode, prev->mode, HEAVYBAG_MODE_ENFORCE);
    ngx_conf_merge_value(conf->bot_block, prev->bot_block, 0);
    ngx_conf_merge_value(conf->fake_bot_block, prev->fake_bot_block, 0);
    ngx_conf_merge_value(conf->reason_header, prev->reason_header, 0);

    /* inherit the compiled buckets when this level defined no list */
    for (i = 0; i < HEAVYBAG_ACTION_MAX; i++) {
        if (conf->scanner_re[i] == NULL) {
            conf->scanner_re[i] = prev->scanner_re[i];
        }
    }

    /* same inherit-when-NULL for the UA classification regex slots */
    for (i = 0; i < HEAVYBAG_UA_LIST_MAX; i++) {
        if (conf->ua_re[i] == NULL) {
            conf->ua_re[i] = prev->ua_re[i];
        }
    }

    if (conf->scanner_list.data == NULL) {
        conf->scanner_list = prev->scanner_list;
    }

    /* inherit each whole sig_re[] row when this level defined no such list */
    for (i = 0; i < HEAVYBAG_SIG_LIST_MAX; i++) {
        if (conf->sig_list[i].data == NULL) {
            conf->sig_list[i] = prev->sig_list[i];
            ngx_memcpy(conf->sig_re[i], prev->sig_re[i],
                       sizeof(prev->sig_re[i]));
        }
    }

    /* inherit each verified-bot CIDR list + its path sentinel when unset here */
    for (i = 0; i < HEAVYBAG_UA_LIST_MAX; i++) {
        if (conf->verified_bot_list[i].data == NULL) {
            conf->verified_bot_list[i] = prev->verified_bot_list[i];
            conf->verified_bot_cidrs[i] = prev->verified_bot_cidrs[i];
        }
    }

    /* inherit the JA4 family table + its path sentinel when unset here */
    if (conf->ja4_list.data == NULL) {
        conf->ja4_list = prev->ja4_list;
        conf->ja4_table = prev->ja4_table;
    }

    ngx_conf_merge_str_value(conf->server_token, prev->server_token,
                             NGX_HTTP_HEAVYBAG_DEFAULT_TOKEN);

    /* reputation data: inherit when this level defined none */
    if (conf->rep.geo_db == NULL) {
        conf->rep.geo_db = prev->rep.geo_db;
    }
    if (conf->rep.block_cc == NULL) {
        conf->rep.block_cc = prev->rep.block_cc;
    }
    if (conf->rep.flag_cc == NULL) {
        conf->rep.flag_cc = prev->rep.flag_cc;
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

    /* rate-limit rules: inherit the whole set when this level defined none */
    if (conf->rate_rules == NULL) {
        conf->rate_rules = prev->rate_rules;
    }

    return NGX_CONF_OK;
}


/*
 * Per-server conf carries only the per-vhost status slot index. It is not
 * set by any directive: create leaves it UNSET and the postconfiguration
 * walk (ngx_http_heavybag_stat_assign_vhosts) assigns a sequential index per
 * server{}. The hot path bounds-checks the index against nvhosts and falls
 * back to slot 0 if it is somehow still UNSET.
 */
static void *
ngx_http_heavybag_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_heavybag_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_heavybag_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->stat_index = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_heavybag_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    /* stat_index is assigned by the postconfiguration vhost walk, not merged */
    return NGX_CONF_OK;
}


/*
 * waf_scanner_list <path>: load the scanner signature list. Guards against
 * a duplicate directive, then delegates to scanner_compile which reads the
 * file and compiles the per-action buckets.
 */
static char *
ngx_http_heavybag_set_scanner_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;

    if (wlcf->scanner_list.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_http_heavybag_scanner_compile(cf, &value[1], wlcf->scanner_re)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    wlcf->scanner_list = value[1];

    return NGX_CONF_OK;
}


/*
 * waf_{args,cookie,referer}_list <path>: load an action-bucketed signature
 * list into one sig_re[cat][] row. The subject category is carried in
 * cmd->post so the three directives share this single setter (mirrors
 * ngx_http_heavybag_set_ua_list). Reuses the scanner compile machinery verbatim;
 * the only WAF difference is which request field is matched at runtime.
 */
static char *
ngx_http_heavybag_set_sig_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;
    ngx_http_heavybag_sig_e        cat;

    cat = (ngx_http_heavybag_sig_e) (uintptr_t) cmd->post;

    if (wlcf->sig_list[cat].data != NULL) {
        return "is duplicate";
    }

    if (ngx_http_heavybag_scanner_compile(cf, &value[1], wlcf->sig_re[cat])
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    wlcf->sig_list[cat] = value[1];

    return NGX_CONF_OK;
}


/*
 * waf_{scanner_ua,ai_crawler,crawler,bot}_list <path>: load a UA signature
 * list into one ua_re[] slot. The category is carried in cmd->post so the
 * four directives share this single setter.
 */
static char *
ngx_http_heavybag_set_ua_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;
    ngx_http_heavybag_ua_e         cat;

    cat = (ngx_http_heavybag_ua_e) (uintptr_t) cmd->post;

    if (wlcf->ua_re[cat] != NULL) {
        return "is duplicate";
    }

    if (ngx_http_heavybag_ua_list_compile(cf, wlcf, &value[1], cat) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_ja4_list <path>: load the JA4 fingerprint -> coarse-TLS-family table.
 * ja4_list is the path sentinel for the duplicate guard and inherit-on-merge
 * (mirrors verified_bot_list[]). Optional directive; when absent the JA4 half
 * of $waf_ua_is_spoofed is inert and the signal degrades to CIDR-only.
 */
static char *
ngx_http_heavybag_set_ja4_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (wlcf->ja4_list.data != NULL) {
        return "is duplicate";
    }

    if (ngx_http_heavybag_ja4_list_compile(cf, wlcf, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    wlcf->ja4_list = value[1];

    return NGX_CONF_OK;
}


/*
 * waf_verified_bot <class> <cidr-path>: load a published CIDR allowlist for one
 * positively-verifiable UA class. The class token ("crawler" / "ai_crawler")
 * maps to a UA enum, so this single TAKE2 directive serves both classes; any
 * other class is a config error. A request claiming that class whose canonical
 * client IP falls outside the loaded range is a fake bot, blocked in PREACCESS
 * when waf_fake_bot_block is on. Unlike the ua/sig list setters this carries the
 * class in an argument, not cmd->post.
 */
static char *
ngx_http_heavybag_set_verified_bot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;
    ngx_http_heavybag_ua_e         cat;

    /*
     * Map the class token to a UA enum. The map MUST only ever yield a value
     * < HEAVYBAG_UA_LIST_MAX so verified_bot_cidrs[cat] is provably in bounds; an
     * unknown class is rejected, never silently ignored.
     */
    if (value[1].len == sizeof("crawler") - 1
        && ngx_strncmp(value[1].data, "crawler", value[1].len) == 0)
    {
        cat = HEAVYBAG_UA_CRAWLER;

    } else if (value[1].len == sizeof("ai_crawler") - 1
               && ngx_strncmp(value[1].data, "ai_crawler", value[1].len) == 0)
    {
        cat = HEAVYBAG_UA_AI_CRAWLER;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "waf_verified_bot: unknown class \"%V\" "
            "(expected \"crawler\" or \"ai_crawler\")", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (wlcf->verified_bot_list[cat].data != NULL) {
        return "is duplicate";
    }

    if (ngx_http_heavybag_verified_bot_compile(cf, &wlcf->verified_bot_cidrs[cat],
                                          &value[2])
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    wlcf->verified_bot_list[cat] = value[2];

    return NGX_CONF_OK;
}


/*
 * waf_geo_db <path>: mmap and attach the geo database for this level.
 * Rejects a duplicate directive; geo_open does the open and validation.
 */
static char *
ngx_http_heavybag_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;

    if (wlcf->rep.geo_db != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    wlcf->rep.geo_db = ngx_http_heavybag_geo_open(cf, &value[1]);
    if (wlcf->rep.geo_db == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_geo_block <CC>...: deny clients from the listed countries. Each
 * ISO-2 country-code argument is appended to the block_cc array.
 */
static char *
ngx_http_heavybag_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_country_add(cf, &wlcf->rep.block_cc, &value[i]) != NGX_OK) {
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
ngx_http_heavybag_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_asn_add(cf, &wlcf->rep.block_asn, &value[i]) != NGX_OK) {
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
} ngx_http_heavybag_method_bits[] = {
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
ngx_http_heavybag_method_list_add(ngx_conf_t *cf, ngx_uint_t *mask,
    ngx_array_t **list)
{
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t   *s;
    ngx_uint_t   i, j;

    for (i = 1; i < cf->args->nelts; i++) {

        for (j = 0; ngx_http_heavybag_method_bits[j].name.len; j++) {
            if (value[i].len == ngx_http_heavybag_method_bits[j].name.len
                && ngx_strncasecmp(value[i].data,
                                   ngx_http_heavybag_method_bits[j].name.data,
                                   value[i].len) == 0)
            {
                *mask |= ngx_http_heavybag_method_bits[j].bit;
                break;
            }
        }

        if (ngx_http_heavybag_method_bits[j].name.len != 0) {
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
ngx_http_heavybag_set_method_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;

    wlcf->method_allow_set = 1;

    return ngx_http_heavybag_method_list_add(cf, &wlcf->allow_mask,
                                        &wlcf->allow_list);
}


/*
 * waf_method_deny <METHOD>...: the listed methods are hidden (404); everything
 * else passes. Blacklist; narrows after the whitelist.
 */
static char *
ngx_http_heavybag_set_method_deny(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;

    wlcf->method_deny_set = 1;

    return ngx_http_heavybag_method_list_add(cf, &wlcf->deny_mask,
                                        &wlcf->deny_list);
}


/*
 * waf_geo_whitelist <CC>...: allow only the listed countries; every other
 * country -- and any IP with no geo record -- is hidden (404). Coexists with
 * waf_geo_block but wins over it: when a whitelist is set on a location the
 * block list is not consulted for the country decision.
 */
static char *
ngx_http_heavybag_set_geo_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_country_add(cf, &wlcf->rep.allow_cc, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_flag_block <flag>...: deny clients whose geo record carries one of
 * the named flags (anycast, satellite, ...). Each argument is parsed into
 * the reputation flag_mask via flag_add.
 */
static char *
ngx_http_heavybag_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_flag_add(cf, &wlcf->rep, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_trusted_proxy <CIDR>: append a network to the trusted-proxy list so
 * its forwarded-for client address is honoured instead of the peer IP.
 */
static char *
ngx_http_heavybag_set_trusted_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (ngx_http_heavybag_cidr_add(cf, &wlcf->trusted_proxy, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_blocklist <CIDR>: append a network to the reputation blocklist whose
 * clients are always denied.
 */
static char *
ngx_http_heavybag_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (ngx_http_heavybag_cidr_add(cf, &wlcf->rep.blocklist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_allowlist <CIDR>: append a network to the reputation allowlist whose
 * clients bypass the reputation checks.
 */
static char *
ngx_http_heavybag_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (ngx_http_heavybag_cidr_add(cf, &wlcf->rep.allowlist, &value[1]) != NGX_OK) {
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
ngx_http_heavybag_set_mail_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_heavybag_authhttp_handler;

    return NGX_CONF_OK;
}


/*
 * waf_mail_backend <addr> <port>: the upstream MTA returned as
 * Auth-Server/Auth-Port on allow. <addr> must be a numeric IP -- the mail
 * module parses it with ngx_parse_addr(), which rejects hostnames.
 */
static char *
ngx_http_heavybag_set_mail_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t  *wlcf = conf;
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
ngx_http_heavybag_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_heavybag_status_handler;

    return NGX_CONF_OK;
}


/*
 * waf_rate_zone size=<size>: declare the single process-wide per-IP rate-limit
 * shm zone (http{} main scope). Created immediately (like limit_req_zone) so a
 * later waf_rate_limit can verify the zone exists; the stream head resolves the
 * SAME zone size-0. The argument follows the standard "size=10m" form.
 */
static char *
ngx_http_heavybag_set_rate_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                    size;
    ngx_str_t                 *value, name, s;
    ngx_shm_zone_t            *zone;
    ngx_http_heavybag_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_heavybag_module);

    if (wmcf->rate_zone != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len <= 5 || ngx_strncmp(value[1].data, "size=", 5) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_rate_zone: expected \"size=<size>\"");
        return NGX_CONF_ERROR;
    }

    s.data = value[1].data + 5;
    s.len = value[1].len - 5;

    size = ngx_parse_size(&s);
    if (size == NGX_ERROR || size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_rate_zone: invalid or too-small size \"%V\" "
                           "(need at least %uz bytes)",
                           &value[1], (size_t) (8 * ngx_pagesize));
        return NGX_CONF_ERROR;
    }

    ngx_str_set(&name, "waf_rate");

    zone = ngx_shared_memory_add(cf, &name, (size_t) size,
                                 &ngx_http_heavybag_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (zone->init != NULL) {
        return "is duplicate";
    }

    zone->init = ngx_http_heavybag_rate_init_zone;
    /* zone->data left NULL: init sizes the table from shm.size */

    wmcf->rate_zone = zone;

    return NGX_CONF_OK;
}


/*
 * waf_rate_limit rate=Nr/s|Nr/m|Nr/h [burst=N] [for_geo=CC,...]: append a
 * per-IP token-bucket rule to this location. Requires waf_rate_zone to be
 * declared earlier in http{} (the shared backing store). The parse + bounds
 * checks live in ngx_http_heavybag_rate_rule_add (shared with the stream head).
 */
static char *
ngx_http_heavybag_set_rate_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_heavybag_loc_conf_t   *wlcf = conf;
    ngx_http_heavybag_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_heavybag_module);

    if (wmcf->rate_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_rate_limit requires a waf_rate_zone declared "
                           "earlier in http{}");
        return NGX_CONF_ERROR;
    }

    return ngx_http_heavybag_rate_rule_add(cf, &wlcf->rate_rules);
}


/*
 * Register the three log variables, all NOCACHEABLE so the get_handler runs
 * on demand and works even where `waf off` skips the phase handlers (lazy
 * ctx alloc):
 *   $waf_type    - UA class (regular/crawler/ai-crawler/bot/scanner/empty)
 *   $waf_country - ISO-2 geo country (lazy lookup; one per request via ctx)
 *   $waf_reason  - verdict token from heavybag_reason_str[] ("none" when allowed)
 */
static ngx_int_t
ngx_http_heavybag_preconfiguration(ngx_conf_t *cf)
{
    ngx_str_t             type_name = ngx_string("waf_type");
    ngx_str_t             country_name = ngx_string("waf_country");
    ngx_str_t             reason_name = ngx_string("waf_reason");
    ngx_str_t             asn_name = ngx_string("waf_asn");
    ngx_str_t             ja4_name = ngx_string("waf_ja4_hash");
    ngx_str_t             ua_browser_name = ngx_string("waf_ua_browser");
    ngx_str_t             ua_version_name = ngx_string("waf_ua_browser_version");
    ngx_str_t             ua_category_name = ngx_string("waf_ua_category");
    ngx_str_t             ua_vendor_name = ngx_string("waf_ua_vendor");
    ngx_str_t             ua_spoofed_name = ngx_string("waf_ua_is_spoofed");
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &type_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_type_variable;

    var = ngx_http_add_variable(cf, &country_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_country_variable;

    var = ngx_http_add_variable(cf, &reason_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_reason_variable;

    var = ngx_http_add_variable(cf, &asn_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_asn_variable;

    var = ngx_http_add_variable(cf, &ja4_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_ja4_variable;

    var = ngx_http_add_variable(cf, &ua_browser_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_ua_browser_variable;

    var = ngx_http_add_variable(cf, &ua_version_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_ua_browser_version_variable;

    var = ngx_http_add_variable(cf, &ua_category_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_ua_category_variable;

    var = ngx_http_add_variable(cf, &ua_vendor_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_ua_vendor_variable;

    var = ngx_http_add_variable(cf, &ua_spoofed_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_heavybag_ua_spoofed_variable;

    return NGX_OK;
}


/*
 * $waf_type: the UA classification of the client (bot, crawler, ...) as a
 * string. Allocates the request ctx on first touch and lazily runs the UA
 * classifier once, then returns the cached category name.
 */
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


/*
 * $waf_country: the geo country (ISO-2) of the request client, or not_found
 * when no geo record exists / geo is not configured. Reuses the ctx geo cache
 * so at most ONE geo lookup happens per request even when the preaccess
 * handler, geo blocking and per-country counters are all active: once
 * geo_done is set the lookup is never repeated.
 */
static ngx_int_t
ngx_http_heavybag_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    struct sockaddr            *sa;
    ngx_http_heavybag_ctx_t         *ctx;
    ngx_http_heavybag_loc_conf_t    *wlcf;
    ngx_http_heavybag_geo_result_t   res;

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }

    if (!ctx->geo_done) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);

        if (wlcf->rep.geo_db != NULL) {
            sa = (ctx->client_sa != NULL) ? ctx->client_sa
                                          : r->connection->sockaddr;
            ngx_http_heavybag_geo_lookup(wlcf->rep.geo_db, sa, &res);

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
 * flag/scanner_ua/empty_ua/scanner_path). ctx->reason is zero (HEAVYBAG_REASON_NONE
 * -> "none") until the preaccess handler resolves a verdict, so an allowed or
 * unclassified request renders "none".
 */
static ngx_int_t
ngx_http_heavybag_reason_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t           *s;
    ngx_http_heavybag_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }

    s = &heavybag_reason_str[ctx->reason];

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
ngx_http_heavybag_asn_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    struct sockaddr            *sa;
    ngx_http_heavybag_ctx_t         *ctx;
    ngx_http_heavybag_loc_conf_t    *wlcf;
    ngx_http_heavybag_geo_result_t   res;

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }

    if (!ctx->asn_done) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);

        if (wlcf->rep.geo_db != NULL) {
            sa = (ctx->client_sa != NULL) ? ctx->client_sa
                                          : r->connection->sockaddr;
            ngx_http_heavybag_geo_lookup(wlcf->rep.geo_db, sa, &res);

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
ngx_http_heavybag_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HTTP_SSL)
    ngx_str_t       *j;
    ngx_ssl_conn_t  *ssl_conn;

    if (ngx_http_heavybag_ja4_ssl_index >= 0
        && r->connection->ssl != NULL
        && (ssl_conn = r->connection->ssl->connection) != NULL)
    {
        j = SSL_get_ex_data(ssl_conn, ngx_http_heavybag_ja4_ssl_index);
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


/* $waf_ua_is_spoofed renders one of these two static literals. */
static ngx_str_t  heavybag_bool_str[] = {
    ngx_string("0"),
    ngx_string("1"),
};


/*
 * Shared helper for the four descriptive UA getters: fetch-or-alloc ctx and
 * lazily run the descriptive parse. Returns the ctx, or NULL on alloc failure.
 */
static ngx_http_heavybag_ctx_t *
ngx_http_heavybag_ua_ctx_parsed(ngx_http_request_t *r)
{
    ngx_http_heavybag_ctx_t       *ctx;
    ngx_http_heavybag_loc_conf_t  *wlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_heavybag_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_heavybag_module);
    }

    if (!ctx->ua_parsed) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);
        ngx_http_heavybag_ua_parse(r, wlcf, ctx);
    }

    return ctx;
}


static ngx_int_t
ngx_http_heavybag_ua_browser_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t           *s;
    ngx_http_heavybag_ctx_t  *ctx;

    ctx = ngx_http_heavybag_ua_ctx_parsed(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    s = ngx_http_heavybag_browser_str(ctx->ua_browser);

    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_heavybag_ua_browser_version_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_heavybag_ctx_t  *ctx;

    ctx = ngx_http_heavybag_ua_ctx_parsed(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* len 0: no version token (or it was all out-of-charset bytes) -> unset */
    if (ctx->ua_version.len == 0) {
        v->valid = 0;
        v->no_cacheable = 1;
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->ua_version.len;
    v->data = ctx->ua_version.data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_heavybag_ua_category_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t           *s;
    ngx_http_heavybag_ctx_t  *ctx;

    ctx = ngx_http_heavybag_ua_ctx_parsed(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    s = ngx_http_heavybag_category_str(ctx->ua_category);

    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_heavybag_ua_vendor_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t           *s;
    ngx_http_heavybag_ctx_t  *ctx;

    ctx = ngx_http_heavybag_ua_ctx_parsed(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    s = ngx_http_heavybag_vendor_str(ctx->ua_vendor);

    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_heavybag_ua_spoofed_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
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

    if (!ctx->spoof_evaluated) {
        wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);
        ngx_http_heavybag_ua_spoof_eval(r, wlcf, ctx);
    }

    s = &heavybag_bool_str[ctx->is_spoofed];

    v->len = s->len;
    v->data = s->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static void *
ngx_http_heavybag_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_heavybag_main_conf_t  *wmcf;

    wmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_heavybag_main_conf_t));
    if (wmcf == NULL) {
        return NULL;
    }

    /* pcalloc: stat_zone = NULL, nvhosts = 0 (filled in postconfiguration) */
    return wmcf;
}


static char *
ngx_http_heavybag_init_main_conf(ngx_conf_t *cf, void *conf)
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
ngx_http_heavybag_stat_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                     size;
    ngx_slab_pool_t           *shpool;
    ngx_http_heavybag_stat_shm_t   *sh;
    ngx_http_heavybag_stat_shm_t   *osh = data;
    ngx_http_heavybag_main_conf_t  *wmcf;

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

    size = sizeof(ngx_http_heavybag_stat_shm_t)
           + wmcf->nvhosts * sizeof(ngx_http_heavybag_stat_vhost_t);

    sh = ngx_slab_alloc(shpool, size);
    if (sh == NULL) {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                      "heavybag: cannot allocate status zone");
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
ngx_http_heavybag_stat_add_zone(ngx_conf_t *cf)
{
    size_t                     size;
    ngx_str_t                  name = ngx_string("waf_status");
    ngx_shm_zone_t            *zone;
    ngx_http_heavybag_main_conf_t  *wmcf;

    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_heavybag_module);

    if (wmcf->nvhosts
        > (NGX_MAX_SIZE_T_VALUE - sizeof(ngx_http_heavybag_stat_shm_t))
          / sizeof(ngx_http_heavybag_stat_vhost_t))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "heavybag: too many server blocks for the status zone");
        return NGX_ERROR;
    }

    size = sizeof(ngx_http_heavybag_stat_shm_t)
           + wmcf->nvhosts * sizeof(ngx_http_heavybag_stat_vhost_t);

    size = ngx_align(size + 4 * ngx_pagesize, ngx_pagesize);

    zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_heavybag_module);
    if (zone == NULL) {
        return NGX_ERROR;
    }

    zone->init = ngx_http_heavybag_stat_init_zone;
    zone->data = wmcf;   /* init reads nvhosts, then swaps in the struct ptr */

    wmcf->stat_zone = zone;

    return NGX_OK;
}


/*
 * Walk every configured server{} and assign it a sequential per-vhost stat
 * slot (0..nvhosts-1), storing the final count in the main conf. MUST run
 * before ngx_http_heavybag_stat_add_zone, because nvhosts sizes the zone. The WAF
 * srv conf is reached through the core server conf's module context.
 */
static ngx_int_t
ngx_http_heavybag_stat_assign_vhosts(ngx_conf_t *cf)
{
    ngx_uint_t                   i;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_heavybag_srv_conf_t     *wscf;
    ngx_http_heavybag_main_conf_t    *wmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    wmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_heavybag_module);

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        wscf = cscfp[i]->ctx->srv_conf[ngx_http_heavybag_module.ctx_index];
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
ngx_http_heavybag_ja4_client_hello_cb(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    ngx_str_t         *ja4;
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c != NULL && ngx_http_heavybag_ja4_ssl_index >= 0) {
        ja4 = ngx_palloc(c->pool, sizeof(ngx_str_t));
        if (ja4 != NULL
            && ngx_http_heavybag_ja4_compute(ssl_conn, c->pool, ja4) == NGX_OK)
        {
            (void) SSL_set_ex_data(ssl_conn, ngx_http_heavybag_ja4_ssl_index, ja4);
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
ngx_http_heavybag_ja4_init(ngx_conf_t *cf)
{
    ngx_uint_t                   i;
    SSL_CTX                     *ctx;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (ngx_http_heavybag_ja4_ssl_index < 0) {
        ngx_http_heavybag_ja4_ssl_index =
            SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (ngx_http_heavybag_ja4_ssl_index < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "heavybag: cannot allocate JA4 SSL ex-data index");
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

        SSL_CTX_set_client_hello_cb(ctx, ngx_http_heavybag_ja4_client_hello_cb,
                                    NULL);
    }

    return NGX_OK;
}

#endif /* NGX_HTTP_SSL && SSL_CLIENT_HELLO_SUCCESS */


/*
 * Module postconfiguration: register the POST_READ and PREACCESS phase
 * handlers, install the Apache header/error-page spoof filters, assign each
 * server{} a per-vhost counter slot and add the status shm zone, and (when
 * built with SSL) install the JA4 client_hello hook on every server SSL_CTX.
 */
static ngx_int_t
ngx_http_heavybag_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_heavybag_postread_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_heavybag_preaccess_handler;

    /* Apache header + error-page spoofing filters */
    if (ngx_http_heavybag_spoof_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* opt-in X-WAF-Reason header filter (waf_reason_header on); prepends onto
     * the chain above so each filter keeps its own saved next pointer. */
    ngx_http_heavybag_next_reason_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_heavybag_reason_header_filter;

    /* assign each server{} a per-vhost counter slot (this sizes the zone) */
    if (ngx_http_heavybag_stat_assign_vhosts(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    /* add the always-on lock-free status zone, now that nvhosts is known */
    if (ngx_http_heavybag_stat_add_zone(cf) != NGX_OK) {
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL) && defined(SSL_CLIENT_HELLO_SUCCESS)
    /* install the JA4 client_hello wrapper on every server SSL_CTX (runs after
     * the ssl module's merge has created the contexts + armed its own arg) */
    if (ngx_http_heavybag_ja4_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


/*
 * X-WAF-Reason header filter: when waf_reason_header is on for the location,
 * stamp the request's WAF verdict token onto the MAIN response (subrequests
 * pass through). OFF by default -- production must never disclose which rule
 * matched; the replay/test harness turns it on to read each request's verdict
 * on the wire. ctx may be absent (waf off, or no verdict resolved), in which
 * case ctx->reason is zero -> "none".
 */
static ngx_int_t
ngx_http_heavybag_reason_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t          *h;
    ngx_http_heavybag_ctx_t       *ctx;
    ngx_http_heavybag_loc_conf_t  *wlcf;
    ngx_http_heavybag_reason_e     reason;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);

    if (!wlcf->reason_header || r != r->main) {
        return ngx_http_heavybag_next_reason_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_heavybag_module);
    reason = (ctx != NULL) ? ctx->reason : HEAVYBAG_REASON_NONE;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "X-WAF-Reason");
    h->value = heavybag_reason_str[reason];

    return ngx_http_heavybag_next_reason_filter(r);
}
