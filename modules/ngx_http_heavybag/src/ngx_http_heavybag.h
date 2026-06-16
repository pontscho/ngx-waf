/*
 * ngx_http_heavybag_module - edge firewall for nginx
 *
 * Shared types, configuration structures and cross-module declarations.
 * A single ngx_module_t lives in ngx_http_heavybag_module.c; the other
 * translation units (heavybag_match, heavybag_geo, heavybag_spoof, heavybag_reputation,
 * heavybag_authhttp) export plain functions through this header.
 */

#ifndef _NGX_HTTP_HEAVYBAG_H_INCLUDED_
#define _NGX_HTTP_HEAVYBAG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "heavybag_rep.h"   /* shared ngx_heavybag_rep_conf_t + reputation core */
#include "ngx_http_heavybag_ua_enums.h"  /* descriptive UA / TLS-family enums */


/*
 * Block actions. Scanner patterns are grouped by action so each bucket
 * compiles to a single PCRE2 alternation regex (one exec per bucket,
 * not one exec per pattern). The enum doubles as the bucket index.
 */
typedef enum {
    HEAVYBAG_ACTION_404 = 0,    /* NGX_HTTP_NOT_FOUND */
    HEAVYBAG_ACTION_403,        /* NGX_HTTP_FORBIDDEN */
    HEAVYBAG_ACTION_444,        /* NGX_HTTP_CLOSE     */
    HEAVYBAG_ACTION_MAX
} ngx_http_heavybag_action_e;


/*
 * User-Agent classification outcome, exposed as the $waf_type variable.
 *
 * The list-backed categories form a contiguous prefix [0, HEAVYBAG_UA_LIST_MAX):
 * each indexes one config-file-driven regex slot in loc_conf.ua_re[] and is
 * matched in this exact priority order (scanner first, bot last). REGULAR
 * (nothing matched) and EMPTY (missing/empty UA) are result-only values that
 * never index a regex slot. classify() always lands on exactly one value.
 */
typedef enum {
    HEAVYBAG_UA_SCANNER = 0,        /* security tools: sqlmap, nikto, ... (blocked) */
    HEAVYBAG_UA_AI_CRAWLER,         /* GPTBot, ClaudeBot, CCBot, Bytespider, ...     */
    HEAVYBAG_UA_CRAWLER,            /* Googlebot, bingbot, Baiduspider, ...          */
    HEAVYBAG_UA_BOT,                /* social / monitor / feed / HTTP libraries      */
    HEAVYBAG_UA_LIST_MAX,           /* == 4: number of ua_re[] regex slots           */

    HEAVYBAG_UA_REGULAR = HEAVYBAG_UA_LIST_MAX, /* no signature matched (assume human)    */
    HEAVYBAG_UA_EMPTY,              /* missing / empty User-Agent (blocked)          */
    HEAVYBAG_UA_MAX
} ngx_http_heavybag_ua_e;


/*
 * Request-field signature subjects beyond the URI path. Each value indexes
 * one config-file-driven, action-bucketed regex row in loc_conf.sig_re[][]
 * (same machinery as the scanner path list). The matched value is %-decoded
 * before the regex runs, so the patterns see the same bytes the scanner sees
 * on the already-decoded r->uri.
 */
typedef enum {
    HEAVYBAG_SIG_ARGS = 0,          /* r->args (query string)            */
    HEAVYBAG_SIG_COOKIE,            /* Cookie request header(s)          */
    HEAVYBAG_SIG_REFERER,           /* Referer request header            */
    HEAVYBAG_SIG_LIST_MAX           /* == 3: number of sig_re[] rows     */
} ngx_http_heavybag_sig_e;


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
    ngx_regex_t                   *scanner_re[HEAVYBAG_ACTION_MAX];

    /* UA classification: one compiled alternation per list-backed category */
    ngx_regex_t                   *ua_re[HEAVYBAG_UA_LIST_MAX];

    /* verified-bot CIDR allowlists: a claimed crawler whose canonical client
     * IP is outside the published range for its class is a fake bot (403).
     * Indexed by ngx_http_heavybag_ua_e; only the verifiable classes (crawler /
     * ai_crawler) ever get a list. A NULL slot means the class is unconfigured
     * and silently skipped (see the PREACCESS guard); verified_bot_list[] is the
     * path sentinel used for the duplicate guard and inherit-on-merge. */
    ngx_array_t                   *verified_bot_cidrs[HEAVYBAG_UA_LIST_MAX];
    ngx_str_t                      verified_bot_list[HEAVYBAG_UA_LIST_MAX];
    ngx_flag_t                     fake_bot_block; /* waf_fake_bot_block on|off */

    /* args/cookie/referer signatures: one action-bucketed row per subject */
    ngx_str_t        sig_list[HEAVYBAG_SIG_LIST_MAX];   /* dup-guard / merge sentinel */
    ngx_regex_t     *sig_re[HEAVYBAG_SIG_LIST_MAX][HEAVYBAG_ACTION_MAX];

    ngx_str_t                      server_token; /* waf_server_token      */

    /* waf_reason_header on|off: stamp X-WAF-Reason: <verdict> on every response.
     * OFF by default -- production must never disclose which rule matched; the
     * replay/test harness turns it on to read the per-request verdict on the
     * wire (test/observability only). */
    ngx_flag_t                     reason_header;

    ngx_heavybag_rep_conf_t             rep;          /* geo / CC / flags / CIDRs */
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

    /* JA4 fingerprint -> coarse TLS family table (waf_ja4_list <path>).
     * Sorted ngx_array_t of ngx_http_heavybag_ja4_entry_t, bsearch'd at runtime.
     * NULL = unconfigured -> ja4_family() yields UNKNOWN -> no JA4 spoof
     * signal (the feature degrades to the CIDR-only half). ja4_list is the
     * path sentinel for the duplicate guard and inherit-on-merge. */
    ngx_array_t                   *ja4_table;
    ngx_str_t                      ja4_list;

    /* per-IP token-bucket rate limit rules (waf_rate_limit); the default
     * rule -- if any -- is the one with a NULL geo_cc. NULL = no limiting.
     * Element type is ngx_http_heavybag_rate_rule_t (see heavybag_rate.h). */
    ngx_array_t                   *rate_rules;
} ngx_http_heavybag_loc_conf_t;


/*
 * Per-request state. Allocated lazily and attached with
 * ngx_http_set_ctx(r, ngx_http_heavybag_module). Currently only the Apache
 * error-page body swap needs it; later phases extend it.
 */
typedef struct {
    unsigned          spoof_swap:1;   /* replace body with Apache error page */
    unsigned          spoof_done:1;   /* Apache body already emitted         */
    unsigned          classified:1;   /* ua field already computed            */
    ngx_str_t         spoof_body;     /* synthesized Apache error page        */

    struct sockaddr  *client_sa;      /* canonical client addr (POST_READ)    */
    socklen_t         client_socklen;

    ngx_http_heavybag_ua_e ua;             /* $waf_type outcome (valid iff classified) */

    unsigned              geo_done:1;    /* country[] resolved (lazy guard)        */
    unsigned              verdict_set:1; /* reason resolved by preaccess handler    */
    u_char                country[2];    /* ISO-2 verbatim; {0,0}=unknown          */
    ngx_http_heavybag_reason_e reason;         /* $waf_reason outcome (valid iff verdict_set) */

    unsigned              asn_done:1;     /* asn resolved (lazy guard)              */
    uint32_t              asn;            /* $waf_asn outcome; 0=unknown            */

    /* descriptive UA parse (lazy via ua_parsed). The four enum fields index
     * static string tables; ua_version is a slice INTO the UA header value
     * (never copied), charset-restricted to [0-9A-Za-z._-] at the source. */
    unsigned                    ua_parsed:1;
    ngx_http_heavybag_ua_browser_e   ua_browser;
    ngx_http_heavybag_ua_os_e        ua_os;
    ngx_http_heavybag_ua_category_e  ua_category;
    ngx_http_heavybag_ua_vendor_e    ua_vendor;
    ngx_str_t                   ua_version;

    /* UA<->JA4 spoof (lazy via spoof_evaluated). ja4 points at the SSL
     * ex-data ngx_str_t copied in at PREACCESS; len 0 = no TLS. */
    unsigned                    spoof_evaluated:1;
    unsigned                    is_spoofed:1;
    ngx_str_t                   ja4;
} ngx_http_heavybag_ctx_t;


extern ngx_module_t  ngx_http_heavybag_module;


#endif /* _NGX_HTTP_HEAVYBAG_H_INCLUDED_ */
