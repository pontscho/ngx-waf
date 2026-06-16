/*
 * ngx_http_heavybag_module - descriptive User-Agent parser + UA<->JA4 spoof eval.
 *
 * A second, independent layer on top of the threat classifier
 * (ngx_http_heavybag_ua_classify). It produces five read-only nginx variables
 * ($waf_ua_browser/_browser_version/_category/_vendor/_is_spoofed) and makes
 * NO blocking decision -- the consumer (nginx config) decides what to do.
 *
 * The parse is an ordered, case-insensitive substring chain over the raw UA
 * header, 1:1 with the (fixed) reference oracle user-agent.lua but with the
 * ordering caveats applied (Chromium-derivative tokens checked before the bare
 * Chrome/ token). Descriptive fields are allocation-free: four are static
 * enum-table strings, the version is a slice INTO the UA value (never copied),
 * charset-restricted to [0-9A-Za-z._-] at the source.
 *
 * The deterministic core (browser/os/category/vendor/version from UA bytes)
 * is nginx-free and compiled standalone for the unit test under
 * -DHEAVYBAG_UA_PARSE_UNIT_TEST; this header is the nginx-facing API and is NOT
 * included by the test.
 */

#ifndef _HEAVYBAG_UA_PARSE_H_INCLUDED_
#define _HEAVYBAG_UA_PARSE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_heavybag.h"


/**
 * Fill ctx->ua_browser / ua_os / ua_category / ua_vendor / ua_version from the
 * request User-Agent header. Lazy: a no-op once ctx->ua_parsed is set.
 *
 * Requires the threat classification (ctx->ua): if ctx->classified is unset it
 * calls ngx_http_heavybag_ua_classify() first, so ua_category can take over the
 * threat label (scanner/ai-crawler/crawler/bot) instead of the device class.
 *
 * @param r    current request (read-only access to headers_in.user_agent)
 * @param wlcf location config (for the classifier)
 * @param ctx  per-request WAF context to populate
 */
void ngx_http_heavybag_ua_parse(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_http_heavybag_ctx_t *ctx);


/**
 * Evaluate ctx->is_spoofed. Lazy via ctx->spoof_evaluated.
 *
 * spoofed = ja4_signal || cidr_signal, where
 *   ja4_signal  : TLS request whose JA4 coarse family contradicts the family
 *                 the parsed UA browser should present (both must be known);
 *   cidr_signal : UA claims a verified-bot class (crawler/ai-crawler) with a
 *                 configured verified CIDR list, but the client IP is outside
 *                 it (reuses the fake-bot CIDR check, same XFF trust boundary).
 *
 * @param r    current request
 * @param wlcf location config (ja4_table + verified_bot_cidrs)
 * @param ctx  per-request WAF context (uses ctx->ja4, ctx->ua_browser, ctx->ua)
 */
void ngx_http_heavybag_ua_spoof_eval(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_http_heavybag_ctx_t *ctx);


/**
 * Static string-table accessors for the variable getters. The returned
 * ngx_str_t points at an immutable static literal (never freed, never copied).
 *
 * @param b/c/v enum value (clamped to UNKNOWN if out of range)
 * @return pointer to the static name string for that enum value
 */
ngx_str_t *ngx_http_heavybag_browser_str(ngx_http_heavybag_ua_browser_e b);
ngx_str_t *ngx_http_heavybag_category_str(ngx_http_heavybag_ua_category_e c);
ngx_str_t *ngx_http_heavybag_vendor_str(ngx_http_heavybag_ua_vendor_e v);


/**
 * Map a JA4 fingerprint to its coarse TLS family via the loaded ja4.list
 * table (wlcf->ja4_table). Returns HEAVYBAG_TLSFAM_UNKNOWN when the table is
 * unconfigured, the fingerprint is absent, or it is ambiguous.
 *
 * @param wlcf location config holding the sorted ja4_table
 * @param ja4  fingerprint to look up (e.g. ctx->ja4)
 * @return coarse TLS family, or HEAVYBAG_TLSFAM_UNKNOWN
 */
ngx_http_heavybag_tls_family_e ngx_http_heavybag_ja4_family(
    ngx_http_heavybag_loc_conf_t *wlcf, ngx_str_t *ja4);


/**
 * Map a parsed UA browser to the coarse TLS family it SHOULD present at the
 * TLS layer. Chromium variants all map to HEAVYBAG_TLSFAM_CHROMIUM (JA4 cannot
 * split them). Returns HEAVYBAG_TLSFAM_UNKNOWN for browsers with no stable TLS
 * family expectation.
 *
 * @param b parsed UA browser enum
 * @return expected coarse TLS family, or HEAVYBAG_TLSFAM_UNKNOWN
 */
ngx_http_heavybag_tls_family_e ngx_http_heavybag_ua_expected_tls_family(
    ngx_http_heavybag_ua_browser_e b);


#endif /* _HEAVYBAG_UA_PARSE_H_INCLUDED_ */
