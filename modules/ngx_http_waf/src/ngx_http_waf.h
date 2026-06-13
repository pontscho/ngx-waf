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

#include "waf_rep.h"   /* shared ngx_waf_rep_conf_t + reputation core */


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
 * User-Agent classification outcome, exposed as the $waf_type variable.
 *
 * The list-backed categories form a contiguous prefix [0, WAF_UA_LIST_MAX):
 * each indexes one config-file-driven regex slot in loc_conf.ua_re[] and is
 * matched in this exact priority order (scanner first, bot last). REGULAR
 * (nothing matched) and EMPTY (missing/empty UA) are result-only values that
 * never index a regex slot. classify() always lands on exactly one value.
 */
typedef enum {
    WAF_UA_SCANNER = 0,        /* security tools: sqlmap, nikto, ... (blocked) */
    WAF_UA_AI_CRAWLER,         /* GPTBot, ClaudeBot, CCBot, Bytespider, ...     */
    WAF_UA_CRAWLER,            /* Googlebot, bingbot, Baiduspider, ...          */
    WAF_UA_BOT,                /* social / monitor / feed / HTTP libraries      */
    WAF_UA_LIST_MAX,           /* == 4: number of ua_re[] regex slots           */

    WAF_UA_REGULAR = WAF_UA_LIST_MAX, /* no signature matched (assume human)    */
    WAF_UA_EMPTY,              /* missing / empty User-Agent (blocked)          */
    WAF_UA_MAX
} ngx_http_waf_ua_e;


/*
 * Per-{http,server,location} configuration.
 *
 * The module carries no shared writable state: the geo database is
 * read-only (shared across workers via fork copy-on-write) and every
 * list/pattern is resolved at configuration time. Workers are stateless
 * with respect to each other.
 */
typedef struct {
    ngx_uint_t                     mode;         /* waf off|detect|enforce|on */
    ngx_flag_t                     bot_block;    /* waf_bot_block on|off  */

    ngx_str_t                      scanner_list; /* waf_scanner_list path */
    ngx_regex_t                   *scanner_re[WAF_ACTION_MAX];

    /* UA classification: one compiled alternation per list-backed category */
    ngx_regex_t                   *ua_re[WAF_UA_LIST_MAX];

    ngx_str_t                      server_token; /* waf_server_token      */

    ngx_waf_rep_conf_t             rep;          /* geo / CC / flags / CIDRs */
    ngx_array_t                   *trusted_proxy;/* ngx_cidr_t for XFF (HTTP) */

    /* HTTP method filter (waf_method_allow / waf_method_deny -> 404) */
    unsigned                       method_allow_set:1; /* whitelist configured */
    unsigned                       method_deny_set:1;  /* blacklist configured */
    ngx_uint_t                     allow_mask;   /* NGX_HTTP_* bits, whitelist */
    ngx_uint_t                     deny_mask;    /* NGX_HTTP_* bits, blacklist */
    ngx_array_t                   *allow_list;   /* non-standard names (ngx_str_t) */
    ngx_array_t                   *deny_list;    /* non-standard names (ngx_str_t) */

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
    unsigned          classified:1;   /* ua field already computed            */
    ngx_str_t         spoof_body;     /* synthesized Apache error page        */

    struct sockaddr  *client_sa;      /* canonical client addr (POST_READ)    */
    socklen_t         client_socklen;

    ngx_http_waf_ua_e ua;             /* $waf_type outcome (valid iff classified) */

    unsigned              geo_done:1;    /* country[] resolved (lazy guard)        */
    unsigned              verdict_set:1; /* reason resolved by preaccess handler    */
    u_char                country[2];    /* ISO-2 verbatim; {0,0}=unknown          */
    ngx_http_waf_reason_e reason;         /* $waf_reason outcome (valid iff verdict_set) */

    unsigned              asn_done:1;     /* asn resolved (lazy guard)              */
    uint32_t              asn;            /* $waf_asn outcome; 0=unknown            */
} ngx_http_waf_ctx_t;


extern ngx_module_t  ngx_http_waf_module;


#endif /* _NGX_HTTP_WAF_H_INCLUDED_ */
