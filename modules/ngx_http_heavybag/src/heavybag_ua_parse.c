/*
 * ngx_http_heavybag_module - descriptive User-Agent parser + UA<->JA4 spoof eval.
 *
 * The deterministic core (browser / os / device-category / vendor / version
 * from the raw UA bytes, plus the JA4-family bsearch and the expected-family
 * map) is nginx-free and is pulled into the standalone unit test under
 * -DHEAVYBAG_UA_PARSE_UNIT_TEST -- the same isolation model as heavybag_ja4.c. The
 * nginx-facing wrappers (request ctx population, CIDR spoof reinforcement,
 * loc-conf table lookup) sit behind #ifndef HEAVYBAG_UA_PARSE_UNIT_TEST.
 *
 * Matching is case-insensitive and bounded (heavybag_ua_find never reads past the
 * UA value length), 1:1 with the fixed reference oracle user-agent.lua but
 * with the Chromium-derivative tokens (Edge/OPR/YaBrowser/Samsung/Vivaldi/
 * HeadlessChrome/...) tested BEFORE the bare Chrome/ token so they are not
 * swallowed by the generic match (the dead Lua order is deliberately NOT
 * mirrored). The version is a slice INTO the UA value (never copied),
 * terminated at the first byte outside [0-9A-Za-z._-]; that charset clamp is a
 * security control -- ua_version is the only one of the five variables that
 * carries raw attacker bytes, so clamping neutralizes CR/LF/quote/control-char
 * injection into any downstream log_format / add_header sink at the source.
 */

#ifdef HEAVYBAG_UA_PARSE_UNIT_TEST

/* Standalone: minimal nginx shim, no nginx/SSL headers. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>   /* memcmp */
typedef unsigned char  u_char;
typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
#include "ngx_http_heavybag_ua_enums.h"

#else

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_heavybag.h"
#include "heavybag_ua_parse.h"
#include "heavybag_match.h"   /* ngx_http_heavybag_ua_classify */

#endif


/* ===================================================================== *
 *  Static string tables (immutable; shared read-only across workers)    *
 * ===================================================================== */

#define HEAVYBAG_S(s)  { sizeof(s) - 1, (u_char *) (s) }

static ngx_str_t  heavybag_browser_str[] = {
    HEAVYBAG_S("unknown"),        /* HEAVYBAG_BROWSER_UNKNOWN        */
    HEAVYBAG_S("msie"),           /* HEAVYBAG_BROWSER_MSIE           */
    HEAVYBAG_S("edge"),           /* HEAVYBAG_BROWSER_EDGE           */
    HEAVYBAG_S("firefox"),        /* HEAVYBAG_BROWSER_FIREFOX        */
    HEAVYBAG_S("chrome"),         /* HEAVYBAG_BROWSER_CHROME         */
    HEAVYBAG_S("yabrowser"),      /* HEAVYBAG_BROWSER_YABROWSER      */
    HEAVYBAG_S("safari"),         /* HEAVYBAG_BROWSER_SAFARI         */
    HEAVYBAG_S("samsung"),        /* HEAVYBAG_BROWSER_SAMSUNG        */
    HEAVYBAG_S("xiaomibrowser"),  /* HEAVYBAG_BROWSER_XIAOMIBROWSER  */
    HEAVYBAG_S("opera"),          /* HEAVYBAG_BROWSER_OPERA          */
    HEAVYBAG_S("sleipnir"),       /* HEAVYBAG_BROWSER_SLEIPNIR       */
    HEAVYBAG_S("vivaldi"),        /* HEAVYBAG_BROWSER_VIVALDI        */
    HEAVYBAG_S("androidbrowser"), /* HEAVYBAG_BROWSER_ANDROIDBROWSER */
    HEAVYBAG_S("silk"),           /* HEAVYBAG_BROWSER_SILK           */
    HEAVYBAG_S("curl"),           /* HEAVYBAG_BROWSER_CURL           */
    HEAVYBAG_S("wget"),           /* HEAVYBAG_BROWSER_WGET           */
    HEAVYBAG_S("ffmpeg"),         /* HEAVYBAG_BROWSER_FFMPEG         */
    HEAVYBAG_S("applecoremedia"), /* HEAVYBAG_BROWSER_APPLECOREMEDIA */
    HEAVYBAG_S("libmpv"),         /* HEAVYBAG_BROWSER_LIBMPV         */
    HEAVYBAG_S("duckduckgo"),     /* HEAVYBAG_BROWSER_DUCKDUCKGO     */
    HEAVYBAG_S("whale"),          /* HEAVYBAG_BROWSER_WHALE          */
    HEAVYBAG_S("ucbrowser"),      /* HEAVYBAG_BROWSER_UCBROWSER      */
    HEAVYBAG_S("huaweibrowser"),  /* HEAVYBAG_BROWSER_HUAWEIBROWSER  */
    HEAVYBAG_S("operagx"),        /* HEAVYBAG_BROWSER_OPERAGX        */
    HEAVYBAG_S("headlesschrome"), /* HEAVYBAG_BROWSER_HEADLESSCHROME */
    HEAVYBAG_S("python"),         /* HEAVYBAG_BROWSER_PYTHON         */
    HEAVYBAG_S("gohttp"),         /* HEAVYBAG_BROWSER_GOHTTP         */
    HEAVYBAG_S("java"),           /* HEAVYBAG_BROWSER_JAVA           */
    HEAVYBAG_S("okhttp"),         /* HEAVYBAG_BROWSER_OKHTTP         */
};

static ngx_str_t  heavybag_category_str[] = {
    HEAVYBAG_S("unknown"),     /* HEAVYBAG_CAT_UNKNOWN    */
    HEAVYBAG_S("mobile"),      /* HEAVYBAG_CAT_MOBILE     */
    HEAVYBAG_S("tablet"),      /* HEAVYBAG_CAT_TABLET     */
    HEAVYBAG_S("pc"),          /* HEAVYBAG_CAT_PC         */
    HEAVYBAG_S("tv"),          /* HEAVYBAG_CAT_TV         */
    HEAVYBAG_S("console"),     /* HEAVYBAG_CAT_CONSOLE    */
    HEAVYBAG_S("scanner"),     /* HEAVYBAG_CAT_SCANNER    */
    HEAVYBAG_S("ai-crawler"),  /* HEAVYBAG_CAT_AI_CRAWLER */
    HEAVYBAG_S("crawler"),     /* HEAVYBAG_CAT_CRAWLER    */
    HEAVYBAG_S("bot"),         /* HEAVYBAG_CAT_BOT        */
};

static ngx_str_t  heavybag_vendor_str[] = {
    HEAVYBAG_S("unknown"),     /* HEAVYBAG_VENDOR_UNKNOWN    */
    HEAVYBAG_S("apple"),       /* HEAVYBAG_VENDOR_APPLE      */
    HEAVYBAG_S("mozilla"),     /* HEAVYBAG_VENDOR_MOZILLA    */
    HEAVYBAG_S("google"),      /* HEAVYBAG_VENDOR_GOOGLE     */
    HEAVYBAG_S("microsoft"),   /* HEAVYBAG_VENDOR_MS         */
    HEAVYBAG_S("opera"),       /* HEAVYBAG_VENDOR_OPERA      */
    HEAVYBAG_S("samsung"),     /* HEAVYBAG_VENDOR_SAMSUNG    */
    HEAVYBAG_S("xiaomi"),      /* HEAVYBAG_VENDOR_XIAOMI     */
    HEAVYBAG_S("megaindex"),   /* HEAVYBAG_VENDOR_MEGAINDEX  */
    HEAVYBAG_S("yahoo"),       /* HEAVYBAG_VENDOR_YAHOO      */
    HEAVYBAG_S("baidu"),       /* HEAVYBAG_VENDOR_BAIDU      */
    HEAVYBAG_S("yandex"),      /* HEAVYBAG_VENDOR_YANDEX     */
    HEAVYBAG_S("facebook"),    /* HEAVYBAG_VENDOR_FACEBOOK   */
    HEAVYBAG_S("duckduckgo"),  /* HEAVYBAG_VENDOR_DUCKDUCKGO */
    HEAVYBAG_S("pinterest"),   /* HEAVYBAG_VENDOR_PINTEREST  */
    HEAVYBAG_S("alexa"),       /* HEAVYBAG_VENDOR_ALEXA      */
    HEAVYBAG_S("twitter"),     /* HEAVYBAG_VENDOR_TWITTER    */
    HEAVYBAG_S("huawei"),      /* HEAVYBAG_VENDOR_HUAWEI     */
    HEAVYBAG_S("naver"),       /* HEAVYBAG_VENDOR_NAVER      */
};


/* ===================================================================== *
 *  Bounded, case-insensitive substring search (the only scan primitive) *
 * ===================================================================== */

/*
 * Find needle (nlen bytes) inside hay (hlen bytes), ASCII-case-insensitive.
 * Returns a pointer into hay at the match start, or NULL. Never reads past
 * hay + hlen -- safe on non-NUL-terminated buffers and on binary/oversized
 * UA values.
 */
static const u_char *
heavybag_ua_find(const u_char *hay, size_t hlen, const char *needle, size_t nlen)
{
    size_t  i, j, last;
    u_char  a, b;

    if (nlen == 0 || nlen > hlen) {
        return NULL;
    }

    last = hlen - nlen;

    for (i = 0; i <= last; i++) {
        for (j = 0; j < nlen; j++) {
            a = hay[i + j];
            b = (u_char) needle[j];
            if (a >= 'A' && a <= 'Z') { a = (u_char) (a | 0x20); }
            if (b >= 'A' && b <= 'Z') { b = (u_char) (b | 0x20); }
            if (a != b) { break; }
        }
        if (j == nlen) {
            return hay + i;
        }
    }

    return NULL;
}

#define HEAVYBAG_HAS(h, hl, lit)  (heavybag_ua_find((h), (hl), (lit), sizeof(lit) - 1) != NULL)


/*
 * Slice the version token immediately following `token` in the UA. Sets
 * *vstart and *vlen to a slice INTO hay, bounded by hay+hlen and terminated at
 * the first byte outside the conservative version charset [0-9A-Za-z._-].
 * If the token is absent, or the byte right after it is out of charset,
 * *vlen is 0 (the getter then reports the version as not_found).
 */
static void
heavybag_ua_version(const u_char *hay, size_t hlen, const char *token, size_t tlen,
    const u_char **vstart, size_t *vlen)
{
    const u_char  *p, *s, *q, *end;
    u_char         c;

    *vstart = NULL;
    *vlen = 0;

    p = heavybag_ua_find(hay, hlen, token, tlen);
    if (p == NULL) {
        return;
    }

    s = p + tlen;
    end = hay + hlen;

    for (q = s; q < end; q++) {
        c = *q;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
              || (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-'))
        {
            break;
        }
    }

    *vstart = s;
    *vlen = (size_t) (q - s);
}

#define HEAVYBAG_VER(h, hl, lit, vs, vl) \
    heavybag_ua_version((h), (hl), (lit), sizeof(lit) - 1, (vs), (vl))


/* ===================================================================== *
 *  Operating system detection (try_os)                                  *
 * ===================================================================== */

static ngx_http_heavybag_ua_os_e
heavybag_ua_try_os(const u_char *ua, size_t n)
{
    /* 2026: HarmonyOS rides on a "Linux; Android"-shaped UA -- match first so
     * the Android fallback does not win. */
    if (HEAVYBAG_HAS(ua, n, "HarmonyOS")) { return HEAVYBAG_OS_HARMONYOS; }

    if (HEAVYBAG_HAS(ua, n, "Windows")) {
        /* more-specific console string before the bare "Xbox" token */
        if (HEAVYBAG_HAS(ua, n, "Xbox; Xbox One)")) { return HEAVYBAG_OS_XBOXONE; }
        if (HEAVYBAG_HAS(ua, n, "Xbox"))            { return HEAVYBAG_OS_XBOX360; }
        return HEAVYBAG_OS_WINDOWS;
    }

    if (HEAVYBAG_HAS(ua, n, "Mac OS X") || HEAVYBAG_HAS(ua, n, "Darwin")
        || HEAVYBAG_HAS(ua, n, "-iOS/"))
    {
        if (HEAVYBAG_HAS(ua, n, "like Mac OS X") || HEAVYBAG_HAS(ua, n, "iPhone")) {
            return HEAVYBAG_OS_IPHONE;
        }
        if (HEAVYBAG_HAS(ua, n, "CFNetwork")) { return HEAVYBAG_OS_IPHONE; }
        if (HEAVYBAG_HAS(ua, n, "iPad;"))     { return HEAVYBAG_OS_IPAD; }
        if (HEAVYBAG_HAS(ua, n, "iPod"))      { return HEAVYBAG_OS_IPOD; }
        return HEAVYBAG_OS_MACOS;
    }

    if (HEAVYBAG_HAS(ua, n, "Watch")) { return HEAVYBAG_OS_WATCHOS; }

    if (HEAVYBAG_HAS(ua, n, "Linux")) {
        if (HEAVYBAG_HAS(ua, n, "Windows Phone")) { return HEAVYBAG_OS_WPHONE; }
        if (HEAVYBAG_HAS(ua, n, "Android"))       { return HEAVYBAG_OS_ANDROID; }
        if (HEAVYBAG_HAS(ua, n, "Web0S;") || HEAVYBAG_HAS(ua, n, "webOS/")) {
            return HEAVYBAG_OS_WEBOS;
        }
        return HEAVYBAG_OS_LINUX;
    }

    if (HEAVYBAG_HAS(ua, n, "X11; FreeBSD "))                 { return HEAVYBAG_OS_BSD; }
    if (HEAVYBAG_HAS(ua, n, "PSP (PlayStation Portable);"))   { return HEAVYBAG_OS_PSP; }
    if (HEAVYBAG_HAS(ua, n, "PlayStation Vita"))              { return HEAVYBAG_OS_PSVITA; }
    if (HEAVYBAG_HAS(ua, n, "PLAYSTATION 3 ")
        || HEAVYBAG_HAS(ua, n, "PLAYSTATION 3;"))             { return HEAVYBAG_OS_PS3; }
    if (HEAVYBAG_HAS(ua, n, "PlayStation 4 "))                { return HEAVYBAG_OS_PS4; }
    if (HEAVYBAG_HAS(ua, n, "PlayStation 5 "))                { return HEAVYBAG_OS_PS5; }
    if (HEAVYBAG_HAS(ua, n, "Nintendo 3DS;"))                 { return HEAVYBAG_OS_NINTENDO3DS; }
    if (HEAVYBAG_HAS(ua, n, "Nintendo DSi;"))                 { return HEAVYBAG_OS_NINTENDODSI; }
    if (HEAVYBAG_HAS(ua, n, "Nintendo Wii;"))                 { return HEAVYBAG_OS_NINTENDOWII; }
    if (HEAVYBAG_HAS(ua, n, "(Nintendo WiiU)"))               { return HEAVYBAG_OS_NINTENDOWIIU; }
    if (HEAVYBAG_HAS(ua, n, "InettvBrowser/"))                { return HEAVYBAG_OS_INETTV; }
    if (HEAVYBAG_HAS(ua, n, "X11; CrOS "))                    { return HEAVYBAG_OS_CROS; }
    if (HEAVYBAG_HAS(ua, n, "(Win98;"))                       { return HEAVYBAG_OS_WINDOWS; }
    if (HEAVYBAG_HAS(ua, n, "Macintosh; U; PPC;"))            { return HEAVYBAG_OS_MACOS; }
    if (HEAVYBAG_HAS(ua, n, "Mac_PowerPC"))                   { return HEAVYBAG_OS_MACOS; }
    if (HEAVYBAG_HAS(ua, n, "BB10"))                          { return HEAVYBAG_OS_BLACKBERRY10; }
    if (HEAVYBAG_HAS(ua, n, "BlackBerry"))                    { return HEAVYBAG_OS_BLACKBERRY; }

    return HEAVYBAG_OS_UNKNOWN;
}


/* ===================================================================== *
 *  Browser detection (try_browser) + version slice                      *
 * ===================================================================== */

/*
 * Ordering note: every Chromium-derivative below carries the bare "Chrome/"
 * token, so each is tested BEFORE the generic Chrome/ branch. HeadlessChrome/
 * literally ends in "Chrome/", so it too is tested first. Brave and Arc ship a
 * Chrome-identical UA by design and are therefore reported as `chrome` -- do
 * NOT add a Brave/Arc matcher, it cannot fire from the UA alone.
 */
static ngx_http_heavybag_ua_browser_e
heavybag_ua_try_browser(const u_char *ua, size_t n, ngx_http_heavybag_ua_os_e os,
    const u_char **vs, size_t *vl)
{
    *vs = NULL;
    *vl = 0;

    /* --- Internet Explorer ------------------------------------------- */
    if (HEAVYBAG_HAS(ua, n, "compatible; MSIE")) { return HEAVYBAG_BROWSER_MSIE; }
    if (HEAVYBAG_HAS(ua, n, "Trident/"))  { HEAVYBAG_VER(ua, n, "Trident/", vs, vl);  return HEAVYBAG_BROWSER_MSIE; }
    if (HEAVYBAG_HAS(ua, n, "IEMobile/")) { HEAVYBAG_VER(ua, n, "IEMobile/", vs, vl); return HEAVYBAG_BROWSER_MSIE; }

    /* --- Edge (Chromium + legacy + mobile) --------------------------- */
    if (HEAVYBAG_HAS(ua, n, "Edge/"))    { HEAVYBAG_VER(ua, n, "Edge/", vs, vl);    return HEAVYBAG_BROWSER_EDGE; }
    if (HEAVYBAG_HAS(ua, n, "Edg/"))     { HEAVYBAG_VER(ua, n, "Edg/", vs, vl);     return HEAVYBAG_BROWSER_EDGE; }
    if (HEAVYBAG_HAS(ua, n, "EdgA/"))    { HEAVYBAG_VER(ua, n, "EdgA/", vs, vl);    return HEAVYBAG_BROWSER_EDGE; }
    if (HEAVYBAG_HAS(ua, n, "EdgiOS/"))  { HEAVYBAG_VER(ua, n, "EdgiOS/", vs, vl);  return HEAVYBAG_BROWSER_EDGE; }

    /* --- brand tokens that ride on Chrome/ / AppleWebKit ------------- */
    if (HEAVYBAG_HAS(ua, n, "DuckDuckGo/")) { HEAVYBAG_VER(ua, n, "DuckDuckGo/", vs, vl); return HEAVYBAG_BROWSER_DUCKDUCKGO; }
    if (HEAVYBAG_HAS(ua, n, "Ddg/"))        { HEAVYBAG_VER(ua, n, "Ddg/", vs, vl);        return HEAVYBAG_BROWSER_DUCKDUCKGO; }
    if (HEAVYBAG_HAS(ua, n, "OPRGX/"))      { HEAVYBAG_VER(ua, n, "OPRGX/", vs, vl);      return HEAVYBAG_BROWSER_OPERAGX; }
    if (HEAVYBAG_HAS(ua, n, "OPR/"))        { HEAVYBAG_VER(ua, n, "OPR/", vs, vl);        return HEAVYBAG_BROWSER_OPERA; }
    if (HEAVYBAG_HAS(ua, n, "SamsungBrowser/"))     { HEAVYBAG_VER(ua, n, "SamsungBrowser/", vs, vl);     return HEAVYBAG_BROWSER_SAMSUNG; }
    if (HEAVYBAG_HAS(ua, n, "YaBrowser/"))          { HEAVYBAG_VER(ua, n, "YaBrowser/", vs, vl);          return HEAVYBAG_BROWSER_YABROWSER; }
    if (HEAVYBAG_HAS(ua, n, "XiaoMi/MiuiBrowser/")) { HEAVYBAG_VER(ua, n, "XiaoMi/MiuiBrowser/", vs, vl); return HEAVYBAG_BROWSER_XIAOMIBROWSER; }
    if (HEAVYBAG_HAS(ua, n, "Vivaldi/"))            { HEAVYBAG_VER(ua, n, "Vivaldi/", vs, vl);            return HEAVYBAG_BROWSER_VIVALDI; }
    if (HEAVYBAG_HAS(ua, n, "HuaweiBrowser/"))      { HEAVYBAG_VER(ua, n, "HuaweiBrowser/", vs, vl);      return HEAVYBAG_BROWSER_HUAWEIBROWSER; }
    if (HEAVYBAG_HAS(ua, n, "UCBrowser/"))          { HEAVYBAG_VER(ua, n, "UCBrowser/", vs, vl);          return HEAVYBAG_BROWSER_UCBROWSER; }
    if (HEAVYBAG_HAS(ua, n, "Whale/"))              { HEAVYBAG_VER(ua, n, "Whale/", vs, vl);              return HEAVYBAG_BROWSER_WHALE; }
    if (HEAVYBAG_HAS(ua, n, "Sleipnir/"))           { HEAVYBAG_VER(ua, n, "Sleipnir/", vs, vl);           return HEAVYBAG_BROWSER_SLEIPNIR; }

    /* --- Firefox ----------------------------------------------------- */
    if (HEAVYBAG_HAS(ua, n, "Firefox/")) { HEAVYBAG_VER(ua, n, "Firefox/", vs, vl); return HEAVYBAG_BROWSER_FIREFOX; }
    if (HEAVYBAG_HAS(ua, n, "FxiOS/"))   { HEAVYBAG_VER(ua, n, "FxiOS/", vs, vl);   return HEAVYBAG_BROWSER_FIREFOX; }

    /* --- Chrome family (derivatives already excluded above) ---------- */
    if (HEAVYBAG_HAS(ua, n, "Chrome") && HEAVYBAG_HAS(ua, n, "wv")) { return HEAVYBAG_BROWSER_CHROME; } /* webview */
    if (HEAVYBAG_HAS(ua, n, "Silk/"))          { HEAVYBAG_VER(ua, n, "Silk/", vs, vl);          return HEAVYBAG_BROWSER_SILK; }
    if (HEAVYBAG_HAS(ua, n, "HeadlessChrome/")) { HEAVYBAG_VER(ua, n, "HeadlessChrome/", vs, vl); return HEAVYBAG_BROWSER_HEADLESSCHROME; }
    if (HEAVYBAG_HAS(ua, n, "CriOS/"))         { HEAVYBAG_VER(ua, n, "CriOS/", vs, vl);         return HEAVYBAG_BROWSER_CHROME; }
    if (HEAVYBAG_HAS(ua, n, "Chrome/"))        { HEAVYBAG_VER(ua, n, "Chrome/", vs, vl);        return HEAVYBAG_BROWSER_CHROME; }

    /* --- WebKit / Safari (android variant -> androidbrowser) --------- */
    if (HEAVYBAG_HAS(ua, n, "Outlook-iOS/")) {
        HEAVYBAG_VER(ua, n, "Outlook-iOS/", vs, vl);
        return (os == HEAVYBAG_OS_ANDROID) ? HEAVYBAG_BROWSER_ANDROIDBROWSER : HEAVYBAG_BROWSER_SAFARI;
    }
    if (HEAVYBAG_HAS(ua, n, "AppleWebKit/")) {
        HEAVYBAG_VER(ua, n, "Safari/", vs, vl);
        return (os == HEAVYBAG_OS_ANDROID) ? HEAVYBAG_BROWSER_ANDROIDBROWSER : HEAVYBAG_BROWSER_SAFARI;
    }
    if (HEAVYBAG_HAS(ua, n, "WeatherReport/")) {
        HEAVYBAG_VER(ua, n, "WeatherReport/", vs, vl);
        return (os == HEAVYBAG_OS_ANDROID) ? HEAVYBAG_BROWSER_ANDROIDBROWSER : HEAVYBAG_BROWSER_SAFARI;
    }
    if (HEAVYBAG_HAS(ua, n, "Safari/")) {
        HEAVYBAG_VER(ua, n, "Safari/", vs, vl);
        return (os == HEAVYBAG_OS_ANDROID) ? HEAVYBAG_BROWSER_ANDROIDBROWSER : HEAVYBAG_BROWSER_SAFARI;
    }

    /* --- Opera (Presto-era + bare) ----------------------------------- */
    if (HEAVYBAG_HAS(ua, n, "Presto/")) { HEAVYBAG_VER(ua, n, "Presto/", vs, vl); return HEAVYBAG_BROWSER_OPERA; }
    if (HEAVYBAG_HAS(ua, n, "Opera/"))  { HEAVYBAG_VER(ua, n, "Opera/", vs, vl);  return HEAVYBAG_BROWSER_OPERA; }
    if (HEAVYBAG_HAS(ua, n, "Opera"))   { return HEAVYBAG_BROWSER_OPERA; }

    /* --- non-browser clients / tools --------------------------------- */
    if (HEAVYBAG_HAS(ua, n, "curl/"))          { HEAVYBAG_VER(ua, n, "curl/", vs, vl);          return HEAVYBAG_BROWSER_CURL; }
    if (HEAVYBAG_HAS(ua, n, "libmpv"))         { HEAVYBAG_VER(ua, n, "libmpv", vs, vl);         return HEAVYBAG_BROWSER_LIBMPV; }
    if (HEAVYBAG_HAS(ua, n, "Wget/"))          { HEAVYBAG_VER(ua, n, "Wget/", vs, vl);          return HEAVYBAG_BROWSER_WGET; }
    if (HEAVYBAG_HAS(ua, n, "Lavf/"))          { HEAVYBAG_VER(ua, n, "Lavf/", vs, vl);          return HEAVYBAG_BROWSER_FFMPEG; }
    if (HEAVYBAG_HAS(ua, n, "AppleCoreMedia/")) { HEAVYBAG_VER(ua, n, "AppleCoreMedia/", vs, vl); return HEAVYBAG_BROWSER_APPLECOREMEDIA; }
    if (HEAVYBAG_HAS(ua, n, "Dalvik/"))        { HEAVYBAG_VER(ua, n, "Dalvik/", vs, vl);        return HEAVYBAG_BROWSER_ANDROIDBROWSER; }

    /* --- 2026 HTTP libraries (also threat-classified; still ID'd) ---- */
    if (HEAVYBAG_HAS(ua, n, "python-requests/")) { HEAVYBAG_VER(ua, n, "python-requests/", vs, vl); return HEAVYBAG_BROWSER_PYTHON; }
    if (HEAVYBAG_HAS(ua, n, "python-httpx/"))    { HEAVYBAG_VER(ua, n, "python-httpx/", vs, vl);    return HEAVYBAG_BROWSER_PYTHON; }
    if (HEAVYBAG_HAS(ua, n, "Python-urllib/"))   { HEAVYBAG_VER(ua, n, "Python-urllib/", vs, vl);   return HEAVYBAG_BROWSER_PYTHON; }
    if (HEAVYBAG_HAS(ua, n, "aiohttp/"))         { HEAVYBAG_VER(ua, n, "aiohttp/", vs, vl);         return HEAVYBAG_BROWSER_PYTHON; }
    if (HEAVYBAG_HAS(ua, n, "Go-http-client/"))  { HEAVYBAG_VER(ua, n, "Go-http-client/", vs, vl);  return HEAVYBAG_BROWSER_GOHTTP; }
    if (HEAVYBAG_HAS(ua, n, "Java/"))            { HEAVYBAG_VER(ua, n, "Java/", vs, vl);            return HEAVYBAG_BROWSER_JAVA; }
    if (HEAVYBAG_HAS(ua, n, "okhttp/"))          { HEAVYBAG_VER(ua, n, "okhttp/", vs, vl);          return HEAVYBAG_BROWSER_OKHTTP; }

    return HEAVYBAG_BROWSER_UNKNOWN;
}


/* ===================================================================== *
 *  Device category (try_device) -- device classes only; threat classes  *
 *  are layered on top from ctx->ua by the nginx wrapper.                 *
 * ===================================================================== */

static ngx_http_heavybag_ua_category_e
heavybag_ua_try_device(const u_char *ua, size_t n, ngx_http_heavybag_ua_os_e os,
    ngx_http_heavybag_ua_browser_e browser)
{
    /* os-driven device class */
    switch (os) {
    case HEAVYBAG_OS_IPHONE: case HEAVYBAG_OS_IPOD: case HEAVYBAG_OS_ANDROID:
    case HEAVYBAG_OS_BLACKBERRY10: case HEAVYBAG_OS_BLACKBERRY: case HEAVYBAG_OS_WPHONE:
    case HEAVYBAG_OS_WATCHOS: case HEAVYBAG_OS_HARMONYOS:
        return HEAVYBAG_CAT_MOBILE;
    case HEAVYBAG_OS_IPAD:
        return HEAVYBAG_CAT_TABLET;
    case HEAVYBAG_OS_WEBOS:
        return HEAVYBAG_CAT_TV;
    case HEAVYBAG_OS_XBOX360: case HEAVYBAG_OS_XBOXONE: case HEAVYBAG_OS_PSP:
    case HEAVYBAG_OS_PSVITA: case HEAVYBAG_OS_PS3: case HEAVYBAG_OS_PS4: case HEAVYBAG_OS_PS5:
    case HEAVYBAG_OS_NINTENDO3DS: case HEAVYBAG_OS_NINTENDODSI: case HEAVYBAG_OS_NINTENDOWII:
    case HEAVYBAG_OS_NINTENDOWIIU: case HEAVYBAG_OS_INETTV:
        return HEAVYBAG_CAT_CONSOLE;
    case HEAVYBAG_OS_WINDOWS: case HEAVYBAG_OS_MACOS: case HEAVYBAG_OS_LINUX:
    case HEAVYBAG_OS_BSD: case HEAVYBAG_OS_CROS:
        return HEAVYBAG_CAT_PC;
    default:
        break;
    }

    /* browser-driven device class */
    if (browser == HEAVYBAG_BROWSER_SILK) { return HEAVYBAG_CAT_TABLET; }

    /* substring fallbacks (1:1 with the Lua oracle) */
    if (HEAVYBAG_HAS(ua, n, "Table OS") || HEAVYBAG_HAS(ua, n, "SAMSUNG SM-T")
        || HEAVYBAG_HAS(ua, n, "; SM-T"))
    {
        return HEAVYBAG_CAT_TABLET;
    }

    if (HEAVYBAG_HAS(ua, n, "KDDI-") || HEAVYBAG_HAS(ua, n, "WILLCOM")
        || HEAVYBAG_HAS(ua, n, "DDIPOCKET") || HEAVYBAG_HAS(ua, n, "SymbianOS")
        || HEAVYBAG_HAS(ua, n, "Hatena-Mobile-Gateway/")
        || HEAVYBAG_HAS(ua, n, "livedoor-Mobile-Gateway/")
        || HEAVYBAG_HAS(ua, n, "Google Wireless Transcoder")
        || HEAVYBAG_HAS(ua, n, "Naver Transcoder") || HEAVYBAG_HAS(ua, n, "jig browser")
        || HEAVYBAG_HAS(ua, n, "emobile/") || HEAVYBAG_HAS(ua, n, "OpenBrowser")
        || HEAVYBAG_HAS(ua, n, "Browser/Obigo-Browser") || HEAVYBAG_HAS(ua, n, "SoftBank")
        || HEAVYBAG_HAS(ua, n, "Vodafone") || HEAVYBAG_HAS(ua, n, "Nokia")
        || HEAVYBAG_HAS(ua, n, "J-PHONE") || HEAVYBAG_HAS(ua, n, "DoCoMo")
        || HEAVYBAG_HAS(ua, n, ";FOMA;"))
    {
        return HEAVYBAG_CAT_MOBILE;
    }

    if (HEAVYBAG_HAS(ua, n, "Nintendo DSi;") || HEAVYBAG_HAS(ua, n, "Nintendo Wii;")) {
        return HEAVYBAG_CAT_CONSOLE;
    }

    return HEAVYBAG_CAT_UNKNOWN;
}


/* ===================================================================== *
 *  Vendor attribution (try_vendor)                                      *
 * ===================================================================== */

static ngx_http_heavybag_ua_vendor_e
heavybag_ua_try_vendor(const u_char *ua, size_t n, ngx_http_heavybag_ua_os_e os,
    ngx_http_heavybag_ua_browser_e browser)
{
    /* browser-driven vendor (ipad INCLUDED -- the fixed oracle bug) */
    if (browser == HEAVYBAG_BROWSER_SAFARI
        && (os == HEAVYBAG_OS_IPHONE || os == HEAVYBAG_OS_IPAD || os == HEAVYBAG_OS_IPOD
            || os == HEAVYBAG_OS_MACOS))
    {
        if (HEAVYBAG_HAS(ua, n, "FBNV/")) { return HEAVYBAG_VENDOR_FACEBOOK; }
        return HEAVYBAG_VENDOR_APPLE;
    }

    switch (browser) {
    case HEAVYBAG_BROWSER_SAMSUNG:        return HEAVYBAG_VENDOR_SAMSUNG;
    case HEAVYBAG_BROWSER_YABROWSER:      return HEAVYBAG_VENDOR_YANDEX;
    case HEAVYBAG_BROWSER_XIAOMIBROWSER:  return HEAVYBAG_VENDOR_XIAOMI;
    case HEAVYBAG_BROWSER_OPERA:
    case HEAVYBAG_BROWSER_OPERAGX:        return HEAVYBAG_VENDOR_OPERA;
    case HEAVYBAG_BROWSER_EDGE:           return HEAVYBAG_VENDOR_MS;
    case HEAVYBAG_BROWSER_FIREFOX:        return HEAVYBAG_VENDOR_MOZILLA;
    case HEAVYBAG_BROWSER_CHROME:
    case HEAVYBAG_BROWSER_ANDROIDBROWSER:
    case HEAVYBAG_BROWSER_HEADLESSCHROME: return HEAVYBAG_VENDOR_GOOGLE;
    case HEAVYBAG_BROWSER_MSIE:           return HEAVYBAG_VENDOR_MS;
    case HEAVYBAG_BROWSER_DUCKDUCKGO:     return HEAVYBAG_VENDOR_DUCKDUCKGO;
    case HEAVYBAG_BROWSER_WHALE:          return HEAVYBAG_VENDOR_NAVER;
    case HEAVYBAG_BROWSER_HUAWEIBROWSER:  return HEAVYBAG_VENDOR_HUAWEI;
    default:                         break;
    }

    if (os == HEAVYBAG_OS_HARMONYOS)                       { return HEAVYBAG_VENDOR_HUAWEI; }
    if (os == HEAVYBAG_OS_XBOXONE || os == HEAVYBAG_OS_XBOX360) { return HEAVYBAG_VENDOR_MS; }
    if (HEAVYBAG_HAS(ua, n, "AppleCoreMedia"))             { return HEAVYBAG_VENDOR_APPLE; }

    /* crawler-vendor attribution fallback (substrings are crawler-specific) */
    if (HEAVYBAG_HAS(ua, n, "Google"))                { return HEAVYBAG_VENDOR_GOOGLE; }
    if (HEAVYBAG_HAS(ua, n, "Applebot/"))             { return HEAVYBAG_VENDOR_APPLE; }
    if (HEAVYBAG_HAS(ua, n, "bingbot/")
        || HEAVYBAG_HAS(ua, n, "BingPreview/")
        || HEAVYBAG_HAS(ua, n, "msnbot/"))            { return HEAVYBAG_VENDOR_MS; }
    if (HEAVYBAG_HAS(ua, n, "DuckDuckGo"))            { return HEAVYBAG_VENDOR_DUCKDUCKGO; }
    if (HEAVYBAG_HAS(ua, n, "Pinterestbot/"))         { return HEAVYBAG_VENDOR_PINTEREST; }
    if (HEAVYBAG_HAS(ua, n, "Alexabot/")
        || HEAVYBAG_HAS(ua, n, "alexa.com"))          { return HEAVYBAG_VENDOR_ALEXA; }
    if (HEAVYBAG_HAS(ua, n, "facebookexternalhit/"))  { return HEAVYBAG_VENDOR_FACEBOOK; }
    if (HEAVYBAG_HAS(ua, n, "Yahoo"))                 { return HEAVYBAG_VENDOR_YAHOO; }
    if (HEAVYBAG_HAS(ua, n, "MegaIndex.ru/"))         { return HEAVYBAG_VENDOR_MEGAINDEX; }
    if (HEAVYBAG_HAS(ua, n, "Baiduspider"))           { return HEAVYBAG_VENDOR_BAIDU; }
    if (HEAVYBAG_HAS(ua, n, "Twitterbot/"))           { return HEAVYBAG_VENDOR_TWITTER; }
    if (HEAVYBAG_HAS(ua, n, "PanguBot"))              { return HEAVYBAG_VENDOR_HUAWEI; }
    if (HEAVYBAG_HAS(ua, n, "Yandex"))                { return HEAVYBAG_VENDOR_YANDEX; }

    return HEAVYBAG_VENDOR_UNKNOWN;
}


/* ===================================================================== *
 *  Deterministic core orchestrator (nginx-free, unit-tested directly)   *
 * ===================================================================== */

/*
 * Parse the raw UA bytes into the descriptive fields. device_cat is the pure
 * device class (mobile/tablet/pc/tv/console/unknown); the threat-class
 * override (scanner/ai-crawler/crawler/bot) is applied by the nginx wrapper
 * from ctx->ua. The *vstart and *vlen out-params slice INTO ua (never copied), vlen 0 when
 * no version is present.
 */
static void
heavybag_ua_parse_core(const u_char *ua, size_t n,
    ngx_http_heavybag_ua_browser_e *browser, ngx_http_heavybag_ua_os_e *os,
    ngx_http_heavybag_ua_category_e *device_cat, ngx_http_heavybag_ua_vendor_e *vendor,
    const u_char **vstart, size_t *vlen)
{
    ngx_http_heavybag_ua_os_e       o;
    ngx_http_heavybag_ua_browser_e  b;

    o = heavybag_ua_try_os(ua, n);
    b = heavybag_ua_try_browser(ua, n, o, vstart, vlen);

    *os = o;
    *browser = b;
    *device_cat = heavybag_ua_try_device(ua, n, o, b);
    *vendor = heavybag_ua_try_vendor(ua, n, o, b);
}


/* ===================================================================== *
 *  JA4 coarse-family helpers (core + table lookup)                      *
 * ===================================================================== */

/* Map a parsed UA browser to the coarse TLS family it should present. Only
 * browsers with a reliably-known TLS family are mapped; ambiguous / regional /
 * legacy clients return UNKNOWN so they can never produce a false-positive
 * spoof signal. */
ngx_http_heavybag_tls_family_e
ngx_http_heavybag_ua_expected_tls_family(ngx_http_heavybag_ua_browser_e b)
{
    switch (b) {
    case HEAVYBAG_BROWSER_CHROME:
    case HEAVYBAG_BROWSER_HEADLESSCHROME:
    case HEAVYBAG_BROWSER_EDGE:
    case HEAVYBAG_BROWSER_YABROWSER:
    case HEAVYBAG_BROWSER_SAMSUNG:
    case HEAVYBAG_BROWSER_OPERA:
    case HEAVYBAG_BROWSER_OPERAGX:
    case HEAVYBAG_BROWSER_VIVALDI:
        return HEAVYBAG_TLSFAM_CHROMIUM;
    case HEAVYBAG_BROWSER_FIREFOX:
        return HEAVYBAG_TLSFAM_FIREFOX;
    case HEAVYBAG_BROWSER_SAFARI:
        return HEAVYBAG_TLSFAM_SAFARI;
    case HEAVYBAG_BROWSER_CURL:
    case HEAVYBAG_BROWSER_WGET:
    case HEAVYBAG_BROWSER_FFMPEG:
    case HEAVYBAG_BROWSER_LIBMPV:
    case HEAVYBAG_BROWSER_APPLECOREMEDIA:
    case HEAVYBAG_BROWSER_PYTHON:
    case HEAVYBAG_BROWSER_GOHTTP:
    case HEAVYBAG_BROWSER_JAVA:
    case HEAVYBAG_BROWSER_OKHTTP:
        return HEAVYBAG_TLSFAM_TOOL;
    default:
        return HEAVYBAG_TLSFAM_UNKNOWN;
    }
}


/*
 * bsearch the sorted JA4 table (ascending by ja4 bytes) for `ja4`/`len`.
 * Returns the coarse family, or HEAVYBAG_TLSFAM_UNKNOWN when absent. The table is
 * built + sorted at config time by ngx_http_heavybag_ja4_list_compile (heavybag_match.c).
 */
static ngx_http_heavybag_tls_family_e
heavybag_ja4_family_lookup(const ngx_http_heavybag_ja4_entry_t *entries, ngx_uint_t n,
    const u_char *ja4, size_t len)
{
    ngx_int_t  lo, hi, mid, cmp;
    size_t     m;

    if (entries == NULL || n == 0 || ja4 == NULL || len == 0) {
        return HEAVYBAG_TLSFAM_UNKNOWN;
    }

    lo = 0;
    hi = (ngx_int_t) n - 1;

    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;

        m = entries[mid].ja4.len < len ? entries[mid].ja4.len : len;
        cmp = (m == 0) ? 0
                       : (ngx_int_t) memcmp(entries[mid].ja4.data, ja4, m);
        if (cmp == 0) {
            if (entries[mid].ja4.len < len)      { cmp = -1; }
            else if (entries[mid].ja4.len > len) { cmp = 1; }
        }

        if (cmp == 0) {
            return entries[mid].family;
        }
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    return HEAVYBAG_TLSFAM_UNKNOWN;
}


/* ===================================================================== *
 *  Static string-table accessors                                        *
 * ===================================================================== */

ngx_str_t *
ngx_http_heavybag_browser_str(ngx_http_heavybag_ua_browser_e b)
{
    if ((ngx_uint_t) b >= HEAVYBAG_BROWSER_MAX) { b = HEAVYBAG_BROWSER_UNKNOWN; }
    return &heavybag_browser_str[b];
}

ngx_str_t *
ngx_http_heavybag_category_str(ngx_http_heavybag_ua_category_e c)
{
    if ((ngx_uint_t) c >= HEAVYBAG_CAT_MAX) { c = HEAVYBAG_CAT_UNKNOWN; }
    return &heavybag_category_str[c];
}

ngx_str_t *
ngx_http_heavybag_vendor_str(ngx_http_heavybag_ua_vendor_e v)
{
    if ((ngx_uint_t) v >= HEAVYBAG_VENDOR_MAX) { v = HEAVYBAG_VENDOR_UNKNOWN; }
    return &heavybag_vendor_str[v];
}


#ifndef HEAVYBAG_UA_PARSE_UNIT_TEST

/* ===================================================================== *
 *  nginx-facing wrappers                                                *
 * ===================================================================== */

/* Map the threat classification (ctx->ua) to the category-override label. */
static ngx_http_heavybag_ua_category_e
heavybag_ua_threat_category(ngx_http_heavybag_ua_e ua)
{
    switch (ua) {
    case HEAVYBAG_UA_SCANNER:     return HEAVYBAG_CAT_SCANNER;
    case HEAVYBAG_UA_AI_CRAWLER:  return HEAVYBAG_CAT_AI_CRAWLER;
    case HEAVYBAG_UA_CRAWLER:     return HEAVYBAG_CAT_CRAWLER;
    case HEAVYBAG_UA_BOT:         return HEAVYBAG_CAT_BOT;
    default:                 return HEAVYBAG_CAT_UNKNOWN;
    }
}


void
ngx_http_heavybag_ua_parse(ngx_http_request_t *r, ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_http_heavybag_ctx_t *ctx)
{
    const u_char                *vs;
    size_t                       vl, n;
    ngx_str_t                   *ua;
    ngx_http_heavybag_ua_category_e   threat;

    if (ctx->ua_parsed) {
        return;
    }

    /* category override needs the threat classification */
    if (!ctx->classified) {
        ngx_http_heavybag_ua_classify(r, wlcf, ctx);
    }

    ua = (r->headers_in.user_agent != NULL)
         ? &r->headers_in.user_agent->value : NULL;

    if (ua == NULL || ua->len == 0) {
        /* empty UA: all descriptive fields stay UNKNOWN (pcalloc default) */
        ctx->ua_browser = HEAVYBAG_BROWSER_UNKNOWN;
        ctx->ua_os = HEAVYBAG_OS_UNKNOWN;
        ctx->ua_vendor = HEAVYBAG_VENDOR_UNKNOWN;
        ctx->ua_version.len = 0;
        ctx->ua_version.data = NULL;

        threat = heavybag_ua_threat_category(ctx->ua);
        ctx->ua_category = threat;   /* UNKNOWN for non-threat empty UA */
        ctx->ua_parsed = 1;
        return;
    }

    n = ua->len;
    heavybag_ua_parse_core(ua->data, n, &ctx->ua_browser, &ctx->ua_os,
                      &ctx->ua_category, &ctx->ua_vendor, &vs, &vl);

    ctx->ua_version.data = (u_char *) vs;
    ctx->ua_version.len = vl;

    /* threat class (if any) overrides the device class */
    threat = heavybag_ua_threat_category(ctx->ua);
    if (threat != HEAVYBAG_CAT_UNKNOWN) {
        ctx->ua_category = threat;
    }

    ctx->ua_parsed = 1;
}


ngx_http_heavybag_tls_family_e
ngx_http_heavybag_ja4_family(ngx_http_heavybag_loc_conf_t *wlcf, ngx_str_t *ja4)
{
    if (wlcf->ja4_table == NULL || ja4 == NULL || ja4->len == 0) {
        return HEAVYBAG_TLSFAM_UNKNOWN;
    }

    return heavybag_ja4_family_lookup(wlcf->ja4_table->elts, wlcf->ja4_table->nelts,
                                 ja4->data, ja4->len);
}


void
ngx_http_heavybag_ua_spoof_eval(ngx_http_request_t *r, ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_http_heavybag_ctx_t *ctx)
{
    ngx_http_heavybag_tls_family_e  fam_ja4, fam_ua;
    struct sockaddr           *sa;
    ngx_uint_t                 ja4_signal, cidr_signal;

    if (ctx->spoof_evaluated) {
        return;
    }

    if (!ctx->ua_parsed) {
        ngx_http_heavybag_ua_parse(r, wlcf, ctx);
    }

    /* ja4_signal: TLS request whose JA4 family contradicts the UA family.
     * Both families must be known; an unknown JA4 (absent/ambiguous) or an
     * unmapped UA browser yields no signal (avoids false positives). */
    ja4_signal = 0;
    if (ctx->ja4.len > 0) {
        fam_ja4 = ngx_http_heavybag_ja4_family(wlcf, &ctx->ja4);
        fam_ua = ngx_http_heavybag_ua_expected_tls_family(ctx->ua_browser);
        if (fam_ja4 != HEAVYBAG_TLSFAM_UNKNOWN && fam_ua != HEAVYBAG_TLSFAM_UNKNOWN
            && fam_ja4 != fam_ua)
        {
            ja4_signal = 1;
        }
    }

    /* cidr_signal: UA claims a verified-bot class with a configured CIDR list
     * but the client IP is outside it. Same check + same XFF trust boundary
     * as the fake-bot block. NULL-fallback for client_sa: a getter on a
     * `waf off` path can run before POST_READ sets ctx->client_sa. */
    cidr_signal = 0;
    if ((ctx->ua == HEAVYBAG_UA_CRAWLER || ctx->ua == HEAVYBAG_UA_AI_CRAWLER)
        && wlcf->verified_bot_cidrs[ctx->ua] != NULL)
    {
        sa = (ctx->client_sa != NULL) ? ctx->client_sa : r->connection->sockaddr;
        if (ngx_cidr_match(sa, wlcf->verified_bot_cidrs[ctx->ua]) != NGX_OK) {
            cidr_signal = 1;
        }
    }

    ctx->is_spoofed = (ja4_signal || cidr_signal) ? 1 : 0;
    ctx->spoof_evaluated = 1;
}

#endif /* HEAVYBAG_UA_PARSE_UNIT_TEST */
