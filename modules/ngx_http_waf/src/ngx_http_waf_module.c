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


#define NGX_HTTP_WAF_DEFAULT_TOKEN  "Apache/2.4.68 (Unix)"


/*
 * enum -> $waf_type string, indexed by ngx_http_waf_ua_e. The list-backed
 * categories occupy [0, WAF_UA_LIST_MAX); REGULAR and EMPTY follow. A hit is
 * returned by reference (static literal), never copied.
 */
static ngx_str_t  waf_type_str[WAF_UA_MAX] = {
    ngx_string("scanner"),
    ngx_string("ai-crawler"),
    ngx_string("crawler"),
    ngx_string("bot"),
    ngx_string("regular"),
    ngx_string("empty")
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
static ngx_int_t ngx_http_waf_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_type_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_waf_commands[] = {

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, enable),
      NULL },

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

      ngx_null_command
};


static ngx_http_module_t  ngx_http_waf_module_ctx = {
    ngx_http_waf_preconfiguration,     /* preconfiguration */
    ngx_http_waf_postconfiguration,    /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

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

    if (!wlcf->enable) {
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
 * PREACCESS phase. Order is cheap -> expensive: IP reputation
 * (blocklist/geo/flags) -> bot heuristics (string match) -> scanner regex.
 * Subrequests and internal redirects are never re-scanned.
 */
static ngx_int_t
ngx_http_waf_preaccess_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_str_t                 reason;
    struct sockaddr          *sa;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (!wlcf->enable) {
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

    sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr;

    rc = ngx_http_waf_reputation_check(wlcf, sa, &reason);
    if (rc != NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: reputation block (%V)", &reason);
        return rc;
    }

    /*
     * Classify the UA into ctx->ua ($waf_type) unconditionally; blocking is
     * a separate policy. With bot_block on, only the unambiguously-hostile
     * outcomes (scanner tools, missing UA) are dropped -- crawler/ai-crawler/
     * bot stay flag-only for the operator to act on via $waf_type.
     */
    ngx_http_waf_ua_classify(r, wlcf, ctx);

    if (wlcf->bot_block
        && (ctx->ua == WAF_UA_SCANNER || ctx->ua == WAF_UA_EMPTY))
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: %V user-agent blocked", &waf_type_str[ctx->ua]);
        return NGX_HTTP_NOT_FOUND;
    }

    rc = ngx_http_waf_scanner_lookup(wlcf, &r->uri);
    if (rc != NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: scanner path \"%V\" blocked (%i)", &r->uri, rc);
        return rc;
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
    conf->enable = NGX_CONF_UNSET;
    conf->bot_block = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_waf_loc_conf_t  *prev = parent;
    ngx_http_waf_loc_conf_t  *conf = child;
    ngx_uint_t                i;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
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
    if (conf->geo_db == NULL) {
        conf->geo_db = prev->geo_db;
    }
    if (conf->block_cc == NULL) {
        conf->block_cc = prev->block_cc;
    }
    if (conf->flag_mask == 0) {
        conf->flag_mask = prev->flag_mask;
    }
    if (conf->blocklist == NULL) {
        conf->blocklist = prev->blocklist;
    }
    if (conf->allowlist == NULL) {
        conf->allowlist = prev->allowlist;
    }
    if (conf->trusted_proxy == NULL) {
        conf->trusted_proxy = prev->trusted_proxy;
    }

    /* backend MTA is set as a pair; inherit together when unset here */
    if (conf->mail_backend_addr.data == NULL) {
        conf->mail_backend_addr = prev->mail_backend_addr;
        conf->mail_backend_port = prev->mail_backend_port;
    }

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

    if (wlcf->geo_db != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    wlcf->geo_db = ngx_http_waf_geo_open(cf, &value[1]);
    if (wlcf->geo_db == NULL) {
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
        if (ngx_http_waf_country_add(cf, &wlcf->block_cc, &value[i]) != NGX_OK) {
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
        if (ngx_http_waf_flag_add(cf, wlcf, &value[i]) != NGX_OK) {
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

    if (ngx_http_waf_cidr_add(cf, &wlcf->blocklist, &value[1]) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_waf_set_allowlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_loc_conf_t  *wlcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (ngx_http_waf_cidr_add(cf, &wlcf->allowlist, &value[1]) != NGX_OK) {
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
 * $waf_type: the UA classification string (regular/crawler/ai-crawler/bot/
 * scanner/empty). NOCACHEABLE so the get_handler runs on demand; works even
 * where `waf off` skips the phase handlers (pure-classification use), by
 * lazily allocating ctx and classifying once.
 */
static ngx_int_t
ngx_http_waf_preconfiguration(ngx_conf_t *cf)
{
    ngx_str_t             name = ngx_string("waf_type");
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_waf_type_variable;

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

    return NGX_OK;
}
