/*
 * ngx_http_waf_module - edge firewall for nginx
 *
 * Shared types, configuration structures and cross-module declarations.
 * A single ngx_module_t lives in ngx_http_waf_module.c; the other
 * translation units (waf_match, waf_geo, waf_spoof, waf_reputation,
 * waf_authhttp) export plain functions through this header.
 */

#ifndef _NGX_HTTP_WAF_H_INCLUDED_
#define _NGX_HTTP_WAF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * Block actions. Scanner patterns are grouped by action so each bucket
 * compiles to a single PCRE2 alternation regex (one exec per bucket,
 * not one exec per pattern). The enum doubles as the bucket index.
 */
typedef enum {
    WAF_ACTION_404 = 0,    /* NGX_HTTP_NOT_FOUND */
    WAF_ACTION_403,        /* NGX_HTTP_FORBIDDEN */
    WAF_ACTION_444,        /* NGX_HTTP_CLOSE     */
    WAF_ACTION_MAX
} ngx_http_waf_action_e;


/*
 * Per-{http,server,location} configuration.
 *
 * The module carries no shared writable state: the geo database is
 * read-only (shared across workers via fork copy-on-write) and every
 * list/pattern is resolved at configuration time. Workers are stateless
 * with respect to each other.
 */
/* defined in waf_geo.h; forward-declared here to avoid an include cycle */
struct ngx_http_waf_geo_db_s;


typedef struct {
    ngx_flag_t                     enable;       /* waf on|off            */
    ngx_flag_t                     bot_block;    /* waf_bot_block on|off  */

    ngx_str_t                      scanner_list; /* waf_scanner_list path */
    ngx_regex_t                   *scanner_re[WAF_ACTION_MAX];

    ngx_str_t                      server_token; /* waf_server_token      */

    struct ngx_http_waf_geo_db_s  *geo_db;       /* waf_geo_db            */
    ngx_array_t                   *block_cc;     /* uint16 packed CC codes*/
    uint16_t                       flag_mask;    /* libloc flags to block */

    ngx_array_t                   *blocklist;    /* ngx_cidr_t -> deny    */
    ngx_array_t                   *allowlist;    /* ngx_cidr_t -> allow   */
    ngx_array_t                   *trusted_proxy;/* ngx_cidr_t for XFF    */

    ngx_str_t                      mail_backend_addr; /* waf_mail_backend ip  */
    ngx_str_t                      mail_backend_port; /* waf_mail_backend port*/
} ngx_http_waf_loc_conf_t;


/*
 * Per-request state. Allocated lazily and attached with
 * ngx_http_set_ctx(r, ngx_http_waf_module). Currently only the Apache
 * error-page body swap needs it; later phases extend it.
 */
typedef struct {
    unsigned          spoof_swap:1;   /* replace body with Apache error page */
    unsigned          spoof_done:1;   /* Apache body already emitted         */
    ngx_str_t         spoof_body;     /* synthesized Apache error page        */

    struct sockaddr  *client_sa;      /* canonical client addr (POST_READ)    */
    socklen_t         client_socklen;
} ngx_http_waf_ctx_t;


extern ngx_module_t  ngx_http_waf_module;


#endif /* _NGX_HTTP_WAF_H_INCLUDED_ */
