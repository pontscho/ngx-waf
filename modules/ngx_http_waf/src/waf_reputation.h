/*
 * ngx_http_waf_module - shared reputation core
 *
 * One decision function, two heads: the HTTP PREACCESS phase and the
 * SMTP auth_http endpoint both call ngx_http_waf_reputation_check() on a
 * client address. Order is cheap -> expensive:
 *
 *     allowlist (allow) -> blocklist (deny) -> geo country / network flag.
 *
 * The config-time helpers parse the directive arguments (CIDRs, ISO
 * country codes, libloc flag names) into the loc conf.
 */

#ifndef _WAF_REPUTATION_H_INCLUDED_
#define _WAF_REPUTATION_H_INCLUDED_


#include "ngx_http_waf.h"


/*
 * Verdict for *sa. Returns NGX_DECLINED to allow, NGX_HTTP_FORBIDDEN to
 * deny; on deny *reason is set to a static description for logging /
 * Auth-Status.
 */
ngx_int_t ngx_http_waf_reputation_check(ngx_http_waf_loc_conf_t *wlcf,
    struct sockaddr *sa, ngx_str_t *reason);

/* Append a "addr/prefix" CIDR to *arr (created on first use). */
ngx_int_t ngx_http_waf_cidr_add(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *text);

/* Append an ISO-3166 alpha-2 country code (packed uint16) to *arr. */
ngx_int_t ngx_http_waf_country_add(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *cc);

/* Map a flag name (anonymous-proxy/satellite/anycast/drop/tor) into wlcf. */
ngx_int_t ngx_http_waf_flag_add(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_str_t *tok);


#endif /* _WAF_REPUTATION_H_INCLUDED_ */
