/*
 * ngx_http_waf_module - path scanner matching and User-Agent classification
 *
 * Scanner patterns live in a hot-reloadable list file (one pattern per
 * line, optional action token). Patterns are bucketed by action and each
 * bucket is compiled to a single anchored PCRE2 alternation, JIT-compiled
 * and freed via the configuration cycle pool (reload-safe). User-Agent
 * signature lists (scanner/ai-crawler/crawler/bot) use the same machinery,
 * one alternation per category, feeding the $waf_type classifier.
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
 * Read and compile one config-file UA signature list into wlcf's ua_re[cat]
 * slot. Each non-comment, non-blank line is a single case-insensitive PCRE2
 * fragment (no action token); the whole list compiles to one alternation.
 * Runs at configuration time (directive setter); reload-safe via cf->pool.
 */
ngx_int_t ngx_http_waf_ua_list_compile(ngx_conf_t *cf,
    ngx_http_waf_loc_conf_t *wlcf, ngx_str_t *path, ngx_http_waf_ua_e cat);

/*
 * Classify the request's User-Agent into ctx->ua and set ctx->classified.
 * Missing/empty UA -> WAF_UA_EMPTY; otherwise the first matching ua_re[]
 * bucket in priority order (SCANNER..BOT); no match -> WAF_UA_REGULAR.
 */
void ngx_http_waf_ua_classify(ngx_http_request_t *r,
    ngx_http_waf_loc_conf_t *wlcf, ngx_http_waf_ctx_t *ctx);


#endif /* _WAF_MATCH_H_INCLUDED_ */
