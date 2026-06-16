/*
 * ngx_http_heavybag_module - descriptive User-Agent parser enums.
 *
 * Leaf header: plain enums only, NO nginx types and NO includes, so it can be
 * pulled into the standalone parser unit test (-DHEAVYBAG_UA_PARSE_UNIT_TEST) which
 * runs without the nginx headers -- the same isolation model heavybag_ja4.c uses.
 * ngx_http_heavybag.h includes this so the request ctx can carry the enum fields;
 * this is the single source of truth for the five families (no drift between
 * the production build and the test build).
 *
 * All enums use UNKNOWN == 0 so an ngx_pcalloc'd ctx defaults to "unknown".
 */

#ifndef _NGX_HTTP_HEAVYBAG_UA_ENUMS_H_INCLUDED_
#define _NGX_HTTP_HEAVYBAG_UA_ENUMS_H_INCLUDED_


/* Descriptive browser family -- values are stable string-table indices. */
typedef enum {
    HEAVYBAG_BROWSER_UNKNOWN = 0,
    HEAVYBAG_BROWSER_MSIE, HEAVYBAG_BROWSER_EDGE, HEAVYBAG_BROWSER_FIREFOX, HEAVYBAG_BROWSER_CHROME,
    HEAVYBAG_BROWSER_YABROWSER, HEAVYBAG_BROWSER_SAFARI, HEAVYBAG_BROWSER_SAMSUNG,
    HEAVYBAG_BROWSER_XIAOMIBROWSER, HEAVYBAG_BROWSER_OPERA, HEAVYBAG_BROWSER_SLEIPNIR,
    HEAVYBAG_BROWSER_VIVALDI, HEAVYBAG_BROWSER_ANDROIDBROWSER, HEAVYBAG_BROWSER_SILK,
    HEAVYBAG_BROWSER_CURL, HEAVYBAG_BROWSER_WGET, HEAVYBAG_BROWSER_FFMPEG,
    HEAVYBAG_BROWSER_APPLECOREMEDIA, HEAVYBAG_BROWSER_LIBMPV,
    /* 2026 additions */
    HEAVYBAG_BROWSER_DUCKDUCKGO, HEAVYBAG_BROWSER_WHALE, HEAVYBAG_BROWSER_UCBROWSER,
    HEAVYBAG_BROWSER_HUAWEIBROWSER, HEAVYBAG_BROWSER_OPERAGX,
    HEAVYBAG_BROWSER_HEADLESSCHROME, HEAVYBAG_BROWSER_PYTHON, HEAVYBAG_BROWSER_GOHTTP,
    HEAVYBAG_BROWSER_JAVA, HEAVYBAG_BROWSER_OKHTTP,
    HEAVYBAG_BROWSER_MAX
} ngx_http_heavybag_ua_browser_e;


typedef enum {
    HEAVYBAG_OS_UNKNOWN = 0,
    HEAVYBAG_OS_WINDOWS, HEAVYBAG_OS_IPHONE, HEAVYBAG_OS_IPAD, HEAVYBAG_OS_IPOD, HEAVYBAG_OS_MACOS,
    HEAVYBAG_OS_ANDROID, HEAVYBAG_OS_LINUX, HEAVYBAG_OS_BSD, HEAVYBAG_OS_CROS,
    HEAVYBAG_OS_XBOX360, HEAVYBAG_OS_XBOXONE, HEAVYBAG_OS_PSP, HEAVYBAG_OS_PSVITA,
    HEAVYBAG_OS_PS3, HEAVYBAG_OS_PS4, HEAVYBAG_OS_PS5,
    HEAVYBAG_OS_NINTENDO3DS, HEAVYBAG_OS_NINTENDODSI, HEAVYBAG_OS_NINTENDOWII, HEAVYBAG_OS_NINTENDOWIIU,
    HEAVYBAG_OS_INETTV, HEAVYBAG_OS_BLACKBERRY10, HEAVYBAG_OS_BLACKBERRY,
    HEAVYBAG_OS_WATCHOS, HEAVYBAG_OS_WEBOS, HEAVYBAG_OS_WPHONE,
    HEAVYBAG_OS_HARMONYOS,  /* 2026 addition -- match BEFORE the android fallback */
    HEAVYBAG_OS_MAX
} ngx_http_heavybag_ua_os_e;


/* Device class; the bot-class values mirror ngx_http_heavybag_ua_e and are taken
 * over from ctx->ua when it is a threat class. */
typedef enum {
    HEAVYBAG_CAT_UNKNOWN = 0,
    HEAVYBAG_CAT_MOBILE, HEAVYBAG_CAT_TABLET, HEAVYBAG_CAT_PC, HEAVYBAG_CAT_TV, HEAVYBAG_CAT_CONSOLE,
    HEAVYBAG_CAT_SCANNER, HEAVYBAG_CAT_AI_CRAWLER, HEAVYBAG_CAT_CRAWLER, HEAVYBAG_CAT_BOT,
    HEAVYBAG_CAT_MAX
} ngx_http_heavybag_ua_category_e;


typedef enum {
    HEAVYBAG_VENDOR_UNKNOWN = 0,
    HEAVYBAG_VENDOR_APPLE, HEAVYBAG_VENDOR_MOZILLA, HEAVYBAG_VENDOR_GOOGLE, HEAVYBAG_VENDOR_MS,
    HEAVYBAG_VENDOR_OPERA, HEAVYBAG_VENDOR_SAMSUNG, HEAVYBAG_VENDOR_XIAOMI, HEAVYBAG_VENDOR_MEGAINDEX,
    HEAVYBAG_VENDOR_YAHOO, HEAVYBAG_VENDOR_BAIDU, HEAVYBAG_VENDOR_YANDEX, HEAVYBAG_VENDOR_FACEBOOK,
    HEAVYBAG_VENDOR_DUCKDUCKGO, HEAVYBAG_VENDOR_PINTEREST, HEAVYBAG_VENDOR_ALEXA, HEAVYBAG_VENDOR_TWITTER,
    HEAVYBAG_VENDOR_HUAWEI, HEAVYBAG_VENDOR_NAVER,  /* additions */
    HEAVYBAG_VENDOR_MAX
} ngx_http_heavybag_ua_vendor_e;


/* Coarse TLS client family for JA4<->UA comparison. JA4 cannot split
 * Chromium variants, so chromium is one family. */
typedef enum {
    HEAVYBAG_TLSFAM_UNKNOWN = 0,
    HEAVYBAG_TLSFAM_CHROMIUM, HEAVYBAG_TLSFAM_FIREFOX, HEAVYBAG_TLSFAM_SAFARI,
    HEAVYBAG_TLSFAM_TOOL,   /* curl, go, python, java, okhttp, wget, ... */
    HEAVYBAG_TLSFAM_BOT,    /* fingerprints attributed to crawlers/automation */
    HEAVYBAG_TLSFAM_MAX
} ngx_http_heavybag_tls_family_e;


/*
 * One entry of the JA4-fingerprint -> coarse-TLS-family table loaded from
 * lists/ja4.list ("<ja4> <family>" per line). Built once at config time into
 * a cf->pool ngx_array_t, sorted by the ja4 bytes, looked up per request via
 * bsearch (O(log n)). Read-only at runtime.
 *
 * NOTE: this struct references ngx_str_t -- the includer MUST have ngx_str_t
 * defined first (ngx_http_heavybag.h gets it from ngx_core.h; the parser unit test
 * defines a minimal ngx_str_t in its shim before including this header).
 */
typedef struct {
    ngx_str_t                  ja4;     /* 36-char fingerprint (config pool) */
    ngx_http_heavybag_tls_family_e  family;  /* coarse family it maps to          */
} ngx_http_heavybag_ja4_entry_t;


#endif /* _NGX_HTTP_HEAVYBAG_UA_ENUMS_H_INCLUDED_ */
