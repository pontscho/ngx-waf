/*
 * ngx_http_waf_module - path scanner matching and bot heuristics
 *
 * Scanner patterns live in a hot-reloadable list file (one pattern per
 * line, optional action token). Patterns are bucketed by action and each
 * bucket is compiled to a single anchored PCRE2 alternation, JIT-compiled
 * and freed via the configuration cycle pool (reload-safe).
 */

#ifndef _WAF_MATCH_H_INCLUDED_
#define _WAF_MATCH_H_INCLUDED_


#include "ngx_http_waf.h"


/*
 * Read and compile the scanner list referenced by *path into wlcf's
 * per-action regex buckets. Runs at configuration time (directive setter).
 */
ngx_int_t ngx_http_waf_scanner_compile(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_str_t *path);

/*
 * Match uri against the compiled buckets in action order. Returns the
 * nginx status code to finalize with (NGX_HTTP_NOT_FOUND / _FORBIDDEN /
 * NGX_HTTP_CLOSE) on a hit, or NGX_DECLINED when nothing matches.
 */
ngx_int_t ngx_http_waf_scanner_lookup(ngx_http_waf_loc_conf_t *wlcf,
    ngx_str_t *uri);

/*
 * Cheap bot heuristic: empty User-Agent or a known scanner signature
 * (sqlmap, nikto, nmap, masscan, ...). Returns 1 on a hit, 0 otherwise.
 */
ngx_int_t ngx_http_waf_bot_match(ngx_http_request_t *r);


#endif /* _WAF_MATCH_H_INCLUDED_ */
