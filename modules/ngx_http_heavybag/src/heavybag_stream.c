/*
 * ngx_stream_heavybag_module - L4 (TCP/UDP) reputation head
 *
 * The third head of the edge firewall. Where the HTTP PREACCESS phase and
 * the SMTP auth_http endpoint guard application traffic, this guards raw
 * stream connections: at the STREAM ACCESS phase it runs the same shared
 * ngx_http_heavybag_reputation_check() on the connection peer and closes the
 * connection (NGX_STREAM_FORBIDDEN) on any non-allow verdict.
 *
 * There is no X-Forwarded-For at L4 -- the peer address is taken verbatim
 * from s->connection->sockaddr (already rewritten by the stream realip /
 * proxy_protocol machinery if configured). Trusted-proxy / XFF handling is
 * HTTP-only.
 *
 * This module ships in the same .so as ngx_http_heavybag_module; the addon
 * config registers both. It shares the reputation core and config helpers
 * through the context-neutral heavybag_rep.h (no ngx_http.h pulled in here).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "heavybag_rep.h"
#include "heavybag_rate.h"


/*
 * The status shm zone is owned by the HTTP head (ngx_http_heavybag_module sizes
 * and inits it). The stream head resolves the SAME zone by name + tag and
 * pokes its counters through the opaque-pointer helpers declared in
 * heavybag_rep.h, so it never includes ngx_http.h / sees the layout struct. The
 * zone is a process-wide singleton, so a file-static pointer (set at config
 * time, inherited by workers on fork) is sufficient.
 */
extern ngx_module_t  ngx_http_heavybag_module;

static ngx_shm_zone_t  *ngx_stream_heavybag_stat_zone;

/*
 * The per-IP rate-limit zone is ALSO owned by the HTTP head (declared with
 * waf_rate_zone in http{}). The stream head resolves it by name+tag, size 0,
 * exactly like the status zone above. NULL when http{} declared no zone -> the
 * rate check fail-opens (NULL shm), so stream rate limiting needs the zone
 * declared in http{}.
 */
static ngx_shm_zone_t  *ngx_stream_heavybag_rate_zone;


typedef struct {
    ngx_uint_t          mode;       /* waf_stream off|detect|enforce|on */
    ngx_heavybag_rep_conf_t  rep;        /* geo / CC / flags / CIDRs */
    ngx_array_t        *rate_rules; /* waf_stream_rate_limit token-bucket rules */
} ngx_stream_heavybag_srv_conf_t;


/* waf_stream mode enum (mirrors ngx_http_heavybag_mode); `on` aliases enforce */
static ngx_conf_enum_t  ngx_stream_heavybag_mode[] = {
    { ngx_string("off"),     HEAVYBAG_MODE_OFF     },
    { ngx_string("detect"),  HEAVYBAG_MODE_DETECT  },
    { ngx_string("enforce"), HEAVYBAG_MODE_ENFORCE },
    { ngx_string("on"),      HEAVYBAG_MODE_ENFORCE },
    { ngx_null_string, 0 }
};


static ngx_int_t ngx_stream_heavybag_handler(ngx_stream_session_t *s);

static void *ngx_stream_heavybag_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_heavybag_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_heavybag_init(ngx_conf_t *cf);

static char *ngx_stream_heavybag_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_heavybag_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_heavybag_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_heavybag_set_geo_whitelist(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_heavybag_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_heavybag_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_heavybag_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_heavybag_set_rate_limit(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_heavybag_commands[] = {

    { ngx_string("waf_stream"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_heavybag_srv_conf_t, mode),
      &ngx_stream_heavybag_mode },

    { ngx_string("waf_geo_db"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_heavybag_set_geo_db,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_block"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_heavybag_set_geo_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_asn_block"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_heavybag_set_asn_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_whitelist"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_heavybag_set_geo_whitelist,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_flag_block"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_heavybag_set_flag_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_blocklist"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_heavybag_set_blocklist,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_allowlist"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_heavybag_set_allowlist,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_stream_rate_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_heavybag_set_rate_limit,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_heavybag_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_stream_heavybag_init,               /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_stream_heavybag_create_srv_conf,    /* create server configuration */
    ngx_stream_heavybag_merge_srv_conf      /* merge server configuration */
};


ngx_module_t  ngx_stream_heavybag_module = {
    NGX_MODULE_V1,
    &ngx_stream_heavybag_module_ctx,        /* module context */
    ngx_stream_heavybag_commands,           /* module directives */
    NGX_STREAM_MODULE,                 /* module type */
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
 * STREAM ACCESS phase. Pure IP reputation on the connection peer: any
 * non-allow verdict closes the connection. No headers exist at L4, so the
 * peer address is used verbatim.
 */
static ngx_int_t
ngx_stream_heavybag_handler(ngx_stream_session_t *s)
{
    void                       *sh, *rate_shm;
    ngx_int_t                   rc;
    ngx_str_t                   reason;
    uint16_t                    cc16;
    ngx_uint_t                  denied;
    struct sockaddr            *sa;
    ngx_http_heavybag_verdict_t      verdict;
    ngx_http_heavybag_reason_e       final_reason;
    ngx_http_heavybag_rate_rule_t   *rate_rule;
    ngx_stream_heavybag_srv_conf_t  *sscf;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_heavybag_module);

    if (sscf->mode == HEAVYBAG_MODE_OFF) {
        return NGX_DECLINED;
    }

    sa = s->connection->sockaddr;

    rc = ngx_http_heavybag_reputation_check(&sscf->rep, sa, &reason, &verdict);

    /* resolved zone -> struct pointer (NULL until the HTTP head's init ran) */
    sh = (ngx_stream_heavybag_stat_zone != NULL)
         ? ngx_stream_heavybag_stat_zone->data : NULL;

    /*
     * Detect mode for the reputation verdict: record what WOULD have been
     * denied via the opaque would_block helper, then downgrade to allow so the
     * connection proceeds. Fail-CLOSED: only HEAVYBAG_MODE_DETECT observes.
     */
    if (rc != NGX_DECLINED && sscf->mode == HEAVYBAG_MODE_DETECT) {
        ngx_http_heavybag_stat_stream_would_block(sh, verdict.reason);
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "heavybag: stream would-block (%V) [detect]", &reason);
        rc = NGX_DECLINED;
    }

    final_reason = verdict.reason;
    denied = (rc != NGX_DECLINED);

    /*
     * Reputation allowed: apply the per-IP rate limit. The rule is selected by
     * reputation (for_geo). Over limit -> deny (enforce) or would_block
     * (detect). The backing zone is the HTTP head's waf_rate_zone; a NULL zone
     * fail-opens (stream rate limiting needs waf_rate_zone declared in http{}).
     */
    if (!denied && sscf->rate_rules != NULL) {
        rate_rule = ngx_http_heavybag_rate_rule_select(sscf->rate_rules, &verdict);
        rate_shm = (ngx_stream_heavybag_rate_zone != NULL)
                   ? ngx_stream_heavybag_rate_zone->data : NULL;

        if (rate_rule != NULL
            && ngx_http_heavybag_rate_check(rate_shm, sa, rate_rule->rate_num_fp,
                   rate_rule->period_ms, rate_rule->burst_fp)
               == NGX_BUSY)
        {
            if (sscf->mode == HEAVYBAG_MODE_DETECT) {
                ngx_http_heavybag_stat_stream_would_block(sh,
                                                     HEAVYBAG_REASON_RATE_LIMIT);
                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "heavybag: stream rate limit [detect]");
            } else {
                denied = 1;
                final_reason = HEAVYBAG_REASON_RATE_LIMIT;
            }
        }
    }

    ngx_http_heavybag_stat_stream_bump(sh, final_reason, denied);

    if (verdict.geo_valid) {
        cc16 = (uint16_t) ((verdict.country[0] << 8) | verdict.country[1]);
        ngx_http_heavybag_stat_cc_bump(sh, cc16, denied);
    }

    if (denied) {
        if (final_reason == HEAVYBAG_REASON_RATE_LIMIT) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "heavybag: stream rate limit exceeded");
        } else {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "heavybag: stream reputation block (%V)", &reason);
        }
        return NGX_STREAM_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static void *
ngx_stream_heavybag_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_heavybag_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_heavybag_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* pcalloc zeroes rep (all NULL/0); only the mode needs an unset sentinel */
    conf->mode = NGX_CONF_UNSET_UINT;

    return conf;
}


/*
 * STREAM merge step: inherit the mode (fail-closed default) and every
 * reputation field unset at this server level -- geo db, block_cc,
 * block_asn, allow_cc, flag_mask, blocklist and allowlist. Warns when a
 * country whitelist is configured without a geo database.
 */
static char *
ngx_stream_heavybag_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_heavybag_srv_conf_t  *prev = parent;
    ngx_stream_heavybag_srv_conf_t  *conf = child;

    /* fail-CLOSED default: an unset waf_stream gate enforces */
    ngx_conf_merge_uint_value(conf->mode, prev->mode, HEAVYBAG_MODE_ENFORCE);

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
    if (conf->rep.blocklist == NULL) {
        conf->rep.blocklist = prev->rep.blocklist;
    }
    if (conf->rep.allowlist == NULL) {
        conf->rep.allowlist = prev->rep.allowlist;
    }
    if (conf->rate_rules == NULL) {
        conf->rate_rules = prev->rate_rules;
    }

    /* a country whitelist without a geo database can never allow anyone */
    if (conf->rep.allow_cc != NULL && conf->rep.geo_db == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "waf_geo_whitelist is set but no waf_geo_db is configured; "
            "every connection will be treated as not whitelisted");
    }

    return NGX_CONF_OK;
}


/*
 * STREAM postconfiguration: register the ACCESS-phase connection handler and
 * resolve (never create) the HTTP module's shared waf_status zone by name so
 * the stream handler can update the same counters the HTTP side owns.
 */
static ngx_int_t
ngx_stream_heavybag_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_heavybag_handler;

    /*
     * Resolve (never create) the HTTP head's status zone: size 0 so core
     * skips the size-conflict check and matches the existing zone by
     * name + tag. Set NO init here - a second init would clobber the HTTP
     * head's allocation. The handler reads zone->data once it is populated.
     */
    {
        ngx_str_t  name = ngx_string("waf_status");

        ngx_stream_heavybag_stat_zone = ngx_shared_memory_add(cf, &name, 0,
                                                       &ngx_http_heavybag_module);
        if (ngx_stream_heavybag_stat_zone == NULL) {
            return NGX_ERROR;
        }
    }

    /*
     * Resolve (never create) the HTTP head's per-IP rate-limit zone, size 0,
     * same as the status zone. Stays NULL if http{} declared no waf_rate_zone
     * -> ngx_http_heavybag_rate_check fail-opens.
     */
    {
        ngx_str_t  name = ngx_string("waf_rate");

        ngx_stream_heavybag_rate_zone = ngx_shared_memory_add(cf, &name, 0,
                                                       &ngx_http_heavybag_module);
        if (ngx_stream_heavybag_rate_zone == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * waf_geo_db <path>: open and attach the geo database for this stream
 * server. Rejects a duplicate directive; geo_open does the open/validation.
 */
static char *
ngx_stream_heavybag_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value;

    if (sscf->rep.geo_db != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->rep.geo_db = ngx_http_heavybag_geo_open(cf, &value[1]);
    if (sscf->rep.geo_db == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_geo_block <CC>...: deny connections from the listed countries. Each
 * ISO-2 country-code argument is appended to rep.block_cc.
 */
static char *
ngx_stream_heavybag_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_country_add(cf, &sscf->rep.block_cc, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_asn_block <ASN>...: deny connections whose source IP resolves to one
 * of the listed autonomous systems. Each argument is appended to
 * rep.block_asn.
 */
static char *
ngx_stream_heavybag_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_asn_add(cf, &sscf->rep.block_asn, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_geo_whitelist <CC>...: allow only connections from the listed
 * countries. Each ISO-2 country-code argument is appended to rep.allow_cc.
 */
static char *
ngx_stream_heavybag_set_geo_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_country_add(cf, &sscf->rep.allow_cc, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_flag_block <flag>...: deny connections whose geo record carries one
 * of the named flags. Each argument is parsed via flag_add into the
 * reputation flag_mask and flag_cc state.
 */
static char *
ngx_stream_heavybag_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_heavybag_flag_add(cf, &sscf->rep, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/*
 * waf_blocklist <CIDR>: append a network to the reputation blocklist whose
 * connections are always denied.
 */
static char *
ngx_stream_heavybag_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;

    if (ngx_http_heavybag_cidr_add(cf, &sscf->rep.blocklist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_allowlist <CIDR>: append a network to the reputation allowlist whose
 * connections bypass the reputation checks.
 */
static char *
ngx_stream_heavybag_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;

    if (ngx_http_heavybag_cidr_add(cf, &sscf->rep.allowlist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * waf_stream_rate_limit rate=Nr/s|Nr/m|Nr/h [burst=N] [for_geo=CC,...]: append
 * a per-IP token-bucket rule to this stream server. The backing store is the
 * HTTP head's waf_rate_zone (declared in http{}); when absent the check
 * fail-opens. Parse + bounds checks are shared via ngx_http_heavybag_rate_rule_add.
 */
static char *
ngx_stream_heavybag_set_rate_limit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_heavybag_srv_conf_t  *sscf = conf;

    return ngx_http_heavybag_rate_rule_add(cf, &sscf->rate_rules);
}
