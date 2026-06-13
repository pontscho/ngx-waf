/*
 * ngx_stream_waf_module - L4 (TCP/UDP) reputation head
 *
 * The third head of the edge firewall. Where the HTTP PREACCESS phase and
 * the SMTP auth_http endpoint guard application traffic, this guards raw
 * stream connections: at the STREAM ACCESS phase it runs the same shared
 * ngx_http_waf_reputation_check() on the connection peer and closes the
 * connection (NGX_STREAM_FORBIDDEN) on any non-allow verdict.
 *
 * There is no X-Forwarded-For at L4 -- the peer address is taken verbatim
 * from s->connection->sockaddr (already rewritten by the stream realip /
 * proxy_protocol machinery if configured). Trusted-proxy / XFF handling is
 * HTTP-only.
 *
 * This module ships in the same .so as ngx_http_waf_module; the addon
 * config registers both. It shares the reputation core and config helpers
 * through the context-neutral waf_rep.h (no ngx_http.h pulled in here).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "waf_rep.h"


/*
 * The status shm zone is owned by the HTTP head (ngx_http_waf_module sizes
 * and inits it). The stream head resolves the SAME zone by name + tag and
 * pokes its counters through the opaque-pointer helpers declared in
 * waf_rep.h, so it never includes ngx_http.h / sees the layout struct. The
 * zone is a process-wide singleton, so a file-static pointer (set at config
 * time, inherited by workers on fork) is sufficient.
 */
extern ngx_module_t  ngx_http_waf_module;

static ngx_shm_zone_t  *ngx_stream_waf_stat_zone;


typedef struct {
    ngx_uint_t          mode;       /* waf_stream off|detect|enforce|on */
    ngx_waf_rep_conf_t  rep;        /* geo / CC / flags / CIDRs */
} ngx_stream_waf_srv_conf_t;


/* waf_stream mode enum (mirrors ngx_http_waf_mode); `on` aliases enforce */
static ngx_conf_enum_t  ngx_stream_waf_mode[] = {
    { ngx_string("off"),     WAF_MODE_OFF     },
    { ngx_string("detect"),  WAF_MODE_DETECT  },
    { ngx_string("enforce"), WAF_MODE_ENFORCE },
    { ngx_string("on"),      WAF_MODE_ENFORCE },
    { ngx_null_string, 0 }
};


static ngx_int_t ngx_stream_waf_handler(ngx_stream_session_t *s);

static void *ngx_stream_waf_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_waf_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_waf_init(ngx_conf_t *cf);

static char *ngx_stream_waf_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_waf_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_waf_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_waf_set_geo_whitelist(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_waf_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_waf_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_waf_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_waf_commands[] = {

    { ngx_string("waf_stream"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_waf_srv_conf_t, mode),
      &ngx_stream_waf_mode },

    { ngx_string("waf_geo_db"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_waf_set_geo_db,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_block"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_waf_set_geo_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_asn_block"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_waf_set_asn_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_geo_whitelist"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_waf_set_geo_whitelist,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_flag_block"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_waf_set_flag_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_blocklist"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_waf_set_blocklist,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_allowlist"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_waf_set_allowlist,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_waf_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_stream_waf_init,               /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_stream_waf_create_srv_conf,    /* create server configuration */
    ngx_stream_waf_merge_srv_conf      /* merge server configuration */
};


ngx_module_t  ngx_stream_waf_module = {
    NGX_MODULE_V1,
    &ngx_stream_waf_module_ctx,        /* module context */
    ngx_stream_waf_commands,           /* module directives */
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
ngx_stream_waf_handler(ngx_stream_session_t *s)
{
    void                       *sh;
    ngx_int_t                   rc;
    ngx_str_t                   reason;
    uint16_t                    cc16;
    ngx_http_waf_verdict_t      verdict;
    ngx_stream_waf_srv_conf_t  *sscf;

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_waf_module);

    if (sscf->mode == WAF_MODE_OFF) {
        return NGX_DECLINED;
    }

    rc = ngx_http_waf_reputation_check(&sscf->rep, s->connection->sockaddr,
                                       &reason, &verdict);

    /* resolved zone -> struct pointer (NULL until the HTTP head's init ran) */
    sh = (ngx_stream_waf_stat_zone != NULL)
         ? ngx_stream_waf_stat_zone->data : NULL;

    /*
     * Detect mode: record what WOULD have been denied via the opaque
     * would_block helper, then downgrade the verdict to allow so the
     * connection proceeds (and is counted as allowed below). Fail-CLOSED:
     * only WAF_MODE_DETECT observes; any other mode keeps the deny verdict.
     */
    if (rc != NGX_DECLINED && sscf->mode == WAF_MODE_DETECT) {
        ngx_http_waf_stat_stream_would_block(sh, verdict.reason);
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "waf: stream would-block (%V) [detect]", &reason);
        rc = NGX_DECLINED;
    }

    ngx_http_waf_stat_stream_bump(sh, verdict.reason, rc != NGX_DECLINED);

    if (verdict.geo_valid) {
        cc16 = (uint16_t) ((verdict.country[0] << 8) | verdict.country[1]);
        ngx_http_waf_stat_cc_bump(sh, cc16, rc != NGX_DECLINED);
    }

    if (rc != NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "waf: stream reputation block (%V)", &reason);
        return NGX_STREAM_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static void *
ngx_stream_waf_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_waf_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_waf_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* pcalloc zeroes rep (all NULL/0); only the mode needs an unset sentinel */
    conf->mode = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_stream_waf_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_waf_srv_conf_t  *prev = parent;
    ngx_stream_waf_srv_conf_t  *conf = child;

    /* fail-CLOSED default: an unset waf_stream gate enforces */
    ngx_conf_merge_uint_value(conf->mode, prev->mode, WAF_MODE_ENFORCE);

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

    /* a country whitelist without a geo database can never allow anyone */
    if (conf->rep.allow_cc != NULL && conf->rep.geo_db == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "waf_geo_whitelist is set but no waf_geo_db is configured; "
            "every connection will be treated as not whitelisted");
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_waf_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_waf_handler;

    /*
     * Resolve (never create) the HTTP head's status zone: size 0 so core
     * skips the size-conflict check and matches the existing zone by
     * name + tag. Set NO init here - a second init would clobber the HTTP
     * head's allocation. The handler reads zone->data once it is populated.
     */
    {
        ngx_str_t  name = ngx_string("waf_status");

        ngx_stream_waf_stat_zone = ngx_shared_memory_add(cf, &name, 0,
                                                       &ngx_http_waf_module);
        if (ngx_stream_waf_stat_zone == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static char *
ngx_stream_waf_set_geo_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_waf_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value;

    if (sscf->rep.geo_db != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->rep.geo_db = ngx_http_waf_geo_open(cf, &value[1]);
    if (sscf->rep.geo_db == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_waf_set_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_waf_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_country_add(cf, &sscf->rep.block_cc, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_waf_set_asn_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_waf_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_asn_add(cf, &sscf->rep.block_asn, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_waf_set_geo_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_waf_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_country_add(cf, &sscf->rep.allow_cc, &value[i])
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_waf_set_flag_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_waf_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    ngx_uint_t                  i;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_http_waf_flag_add(cf, &sscf->rep, &value[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_waf_set_blocklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_waf_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;

    if (ngx_http_waf_cidr_add(cf, &sscf->rep.blocklist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_waf_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_waf_srv_conf_t  *sscf = conf;
    ngx_str_t                  *value = cf->args->elts;

    if (ngx_http_waf_cidr_add(cf, &sscf->rep.allowlist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
