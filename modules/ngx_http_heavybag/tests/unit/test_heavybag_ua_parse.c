/*
 * Unit tests for the descriptive User-Agent parser core.
 *
 * Compiled standalone: includes heavybag_ua_parse.c under -DHEAVYBAG_UA_PARSE_UNIT_TEST
 * so only the nginx-free core is pulled in (no nginx / SSL headers). Built +
 * run by run-unit-tests.sh with `cc -DHEAVYBAG_UA_PARSE_UNIT_TEST` (no libcrypto --
 * the parser core has no crypto). The static core functions are visible here
 * because the .c is #included directly into this translation unit.
 *
 * Coverage: browser / OS / device-category / vendor detection (incl. the 2026
 * tokens and the ordering caveats), the version charset clamp (security
 * control), the user-agent.lua bug-fix regressions, the JA4 family bsearch,
 * and the expected-TLS-family map + the ja4_signal contradiction logic.
 */

#ifndef HEAVYBAG_UA_PARSE_UNIT_TEST
#define HEAVYBAG_UA_PARSE_UNIT_TEST
#endif
#include "../../src/heavybag_ua_parse.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>


/* ---- parse helper ----------------------------------------------------- */

typedef struct {
    ngx_http_heavybag_ua_browser_e   b;
    ngx_http_heavybag_ua_os_e        o;
    ngx_http_heavybag_ua_category_e  c;
    ngx_http_heavybag_ua_vendor_e    v;
    const u_char               *vs;
    size_t                      vl;
} pr_t;

static pr_t
P(const char *ua)
{
    pr_t  r;
    heavybag_ua_parse_core((const u_char *) ua, strlen(ua),
                      &r.b, &r.o, &r.c, &r.v, &r.vs, &r.vl);
    return r;
}

/* version slice equals the expected NUL-terminated string */
static int
veq(pr_t r, const char *exp)
{
    return r.vl == strlen(exp) && memcmp(r.vs, exp, r.vl) == 0;
}


/* ===================================================================== *
 *  Browser detection + version slice                                    *
 * ===================================================================== */

CTEST(ua_browser, chrome_desktop)
{
    pr_t r = P("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CHROME, r.b);
    ASSERT_EQUAL(HEAVYBAG_OS_WINDOWS, r.o);
    ASSERT_TRUE(veq(r, "120.0.0.0"));
    ASSERT_EQUAL(HEAVYBAG_VENDOR_GOOGLE, r.v);
}

CTEST(ua_browser, firefox)
{
    pr_t r = P("Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 "
               "Firefox/124.0");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_FIREFOX, r.b);
    ASSERT_EQUAL(HEAVYBAG_OS_LINUX, r.o);
    ASSERT_TRUE(veq(r, "124.0"));
    ASSERT_EQUAL(HEAVYBAG_VENDOR_MOZILLA, r.v);
}

CTEST(ua_browser, safari_macos)
{
    pr_t r = P("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
               "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
               "Safari/605.1.15");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_SAFARI, r.b);
    ASSERT_EQUAL(HEAVYBAG_OS_MACOS, r.o);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_APPLE, r.v);
}

/* Chromium derivatives MUST win over the bare Chrome/ token they carry. */
CTEST(ua_browser, edge_over_chrome)
{
    pr_t r = P("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like "
               "Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_EDGE, r.b);
    ASSERT_TRUE(veq(r, "120.0.2210.91"));
    ASSERT_EQUAL(HEAVYBAG_VENDOR_MS, r.v);
}

CTEST(ua_browser, opera_over_chrome)
{
    pr_t r = P("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like "
               "Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_OPERA, r.b);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_OPERA, r.v);
}

CTEST(ua_browser, operagx_over_opr)
{
    pr_t r = P("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 "
               "Safari/537.36 OPR/106.0.0.0 OPRGX/106.0");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_OPERAGX, r.b);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_OPERA, r.v);
}

CTEST(ua_browser, yabrowser_over_chrome)
{
    pr_t r = P("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like "
               "Gecko) Chrome/118.0.0.0 YaBrowser/23.11 Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_YABROWSER, r.b);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_YANDEX, r.v);
}

CTEST(ua_browser, samsung_over_chrome)
{
    pr_t r = P("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, "
               "like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile "
               "Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_SAMSUNG, r.b);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_SAMSUNG, r.v);
}

/* HeadlessChrome/ literally ends in "Chrome/" -> must be tested first. */
CTEST(ua_browser, headlesschrome_over_chrome)
{
    pr_t r = P("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, "
               "like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_HEADLESSCHROME, r.b);
    ASSERT_TRUE(veq(r, "120.0.0.0"));
    ASSERT_EQUAL(HEAVYBAG_VENDOR_GOOGLE, r.v);
}

CTEST(ua_browser, duckduckgo_over_chrome)
{
    pr_t r = P("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 "
               "Mobile DuckDuckGo/5 Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_DUCKDUCKGO, r.b);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_DUCKDUCKGO, r.v);
}

CTEST(ua_browser, curl_tool)
{
    pr_t r = P("curl/8.5.0");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CURL, r.b);
    ASSERT_TRUE(veq(r, "8.5.0"));       /* version token at end, no trailing space */
}

CTEST(ua_browser, python_requests)
{
    pr_t r = P("python-requests/2.31.0");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_PYTHON, r.b);
    ASSERT_TRUE(veq(r, "2.31.0"));
}

CTEST(ua_browser, go_http_client)
{
    pr_t r = P("Go-http-client/2.0");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_GOHTTP, r.b);
}

CTEST(ua_browser, okhttp)
{
    pr_t r = P("okhttp/4.12.0");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_OKHTTP, r.b);
}

CTEST(ua_browser, empty_is_unknown)
{
    pr_t r = P("");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_UNKNOWN, r.b);
    ASSERT_EQUAL((size_t) 0, r.vl);
}


/* ===================================================================== *
 *  OS detection                                                         *
 * ===================================================================== */

CTEST(ua_os, iphone)
{
    pr_t r = P("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
               "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
               "Mobile/15E148 Safari/604.1");
    ASSERT_EQUAL(HEAVYBAG_OS_IPHONE, r.o);
    ASSERT_EQUAL(HEAVYBAG_CAT_MOBILE, r.c);
}

CTEST(ua_os, android)
{
    pr_t r = P("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_OS_ANDROID, r.o);
    ASSERT_EQUAL(HEAVYBAG_CAT_MOBILE, r.c);
}

/* HarmonyOS rides on a "Linux; Android"-shaped UA -> must win over android. */
CTEST(ua_os, harmonyos_over_android)
{
    pr_t r = P("Mozilla/5.0 (Linux; Android 10; HarmonyOS; HuaweiBrowser/14.0.0) "
               "AppleWebKit/537.36 Chrome/114.0 Mobile Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_OS_HARMONYOS, r.o);
    ASSERT_EQUAL(HEAVYBAG_BROWSER_HUAWEIBROWSER, r.b);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_HUAWEI, r.v);   /* HuaweiBrowser/ -> huawei */
}

CTEST(ua_os, windows_pc)
{
    pr_t r = P("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0");
    ASSERT_EQUAL(HEAVYBAG_OS_WINDOWS, r.o);
    ASSERT_EQUAL(HEAVYBAG_CAT_PC, r.c);
}

CTEST(ua_os, console_ps4)
{
    pr_t r = P("Mozilla/5.0 (PlayStation 4 8.50) AppleWebKit/605.1.15");
    ASSERT_EQUAL(HEAVYBAG_OS_PS4, r.o);
    ASSERT_EQUAL(HEAVYBAG_CAT_CONSOLE, r.c);
}


/* ===================================================================== *
 *  Vendor + crawler-vendor attribution                                  *
 * ===================================================================== */

CTEST(ua_vendor, googlebot)
{
    pr_t r = P("Mozilla/5.0 (compatible; Googlebot/2.1; "
               "+http://www.google.com/bot.html)");
    ASSERT_EQUAL(HEAVYBAG_VENDOR_GOOGLE, r.v);
}

CTEST(ua_vendor, bingbot)
{
    pr_t r = P("Mozilla/5.0 (compatible; bingbot/2.0; "
               "+http://www.bing.com/bingbot.htm)");
    ASSERT_EQUAL(HEAVYBAG_VENDOR_MS, r.v);
}

CTEST(ua_vendor, baidu)
{
    pr_t r = P("Mozilla/5.0 (compatible; Baiduspider/2.0; "
               "+http://www.baidu.com/search/spider.html)");
    ASSERT_EQUAL(HEAVYBAG_VENDOR_BAIDU, r.v);
}

/* Regression: the oracle compared os against the nonexistent key _oss.pad,
 * so an iPad Safari never resolved to the apple vendor. The fix uses ipad. */
CTEST(ua_vendor, ipad_safari_is_apple_regression)
{
    ASSERT_EQUAL(HEAVYBAG_VENDOR_APPLE,
        heavybag_ua_try_vendor((const u_char *) "x", 1,
                          HEAVYBAG_OS_IPAD, HEAVYBAG_BROWSER_SAFARI));
}


/* ===================================================================== *
 *  Version charset clamp (security control)                             *
 * ===================================================================== */

/* A CR/LF/quote injected at the version position is truncated at the first
 * out-of-charset byte, so no control bytes can reach a downstream sink. */
CTEST(ua_version, clamps_at_control_char)
{
    pr_t r = P("Mozilla/5.0 Chrome/120.0.0.0\r\nSet-Cookie: evil=1");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CHROME, r.b);
    ASSERT_TRUE(veq(r, "120.0.0.0"));   /* stops at the CR */
}

CTEST(ua_version, clamps_at_quote)
{
    pr_t r = P("curl/8.5.0\" onload=alert(1)");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CURL, r.b);
    ASSERT_TRUE(veq(r, "8.5.0"));       /* stops at the double-quote */
}

/* A token immediately followed by an out-of-charset byte yields len 0 (the
 * getter then reports browser_version as not_found). */
CTEST(ua_version, zero_len_when_no_digits)
{
    pr_t r = P("Mozilla/5.0 Chrome/ Safari");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CHROME, r.b);
    ASSERT_EQUAL((size_t) 0, r.vl);
}


/* ===================================================================== *
 *  Expected-TLS-family map                                              *
 * ===================================================================== */

CTEST(tls_family, expected_map)
{
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_CHROMIUM,
                 ngx_http_heavybag_ua_expected_tls_family(HEAVYBAG_BROWSER_CHROME));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_CHROMIUM,
                 ngx_http_heavybag_ua_expected_tls_family(HEAVYBAG_BROWSER_EDGE));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_FIREFOX,
                 ngx_http_heavybag_ua_expected_tls_family(HEAVYBAG_BROWSER_FIREFOX));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_SAFARI,
                 ngx_http_heavybag_ua_expected_tls_family(HEAVYBAG_BROWSER_SAFARI));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_TOOL,
                 ngx_http_heavybag_ua_expected_tls_family(HEAVYBAG_BROWSER_CURL));
    /* ambiguous / legacy browsers -> UNKNOWN (no false-positive spoof) */
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN,
                 ngx_http_heavybag_ua_expected_tls_family(HEAVYBAG_BROWSER_MSIE));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN,
                 ngx_http_heavybag_ua_expected_tls_family(HEAVYBAG_BROWSER_UNKNOWN));
}


/* ===================================================================== *
 *  JA4 family bsearch (table must be sorted by the ja4 bytes)           *
 * ===================================================================== */

/* Ascending by the lexicographic+length order ngx_http_heavybag_ja4_entry_cmp
 * imposes: 'c' < 'f' < 's' < 't' < 'z'. */
static const ngx_http_heavybag_ja4_entry_t  ja4_tbl[] = {
    { { sizeof("chrome_fp") - 1,    (u_char *) "chrome_fp" },    HEAVYBAG_TLSFAM_CHROMIUM },
    { { sizeof("firefox_fp") - 1,   (u_char *) "firefox_fp" },   HEAVYBAG_TLSFAM_FIREFOX },
    { { sizeof("safari_fp") - 1,    (u_char *) "safari_fp" },    HEAVYBAG_TLSFAM_SAFARI },
    { { sizeof("tool_fp") - 1,      (u_char *) "tool_fp" },      HEAVYBAG_TLSFAM_TOOL },
    { { sizeof("zzz_ambiguous") - 1,(u_char *) "zzz_ambiguous" },HEAVYBAG_TLSFAM_UNKNOWN },
};
#define JA4_N  (sizeof(ja4_tbl) / sizeof(ja4_tbl[0]))

static ngx_http_heavybag_tls_family_e
lk(const char *s)
{
    return heavybag_ja4_family_lookup(ja4_tbl, JA4_N,
                                 (const u_char *) s, strlen(s));
}

CTEST(ja4_family, known_fingerprints)
{
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_CHROMIUM, lk("chrome_fp"));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_FIREFOX,  lk("firefox_fp"));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_SAFARI,   lk("safari_fp"));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_TOOL,     lk("tool_fp"));
}

CTEST(ja4_family, ambiguous_is_unknown)
{
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN, lk("zzz_ambiguous"));
}

CTEST(ja4_family, absent_is_unknown)
{
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN, lk("absent_fp"));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN, lk("chrome_f"));   /* prefix, not exact */
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN, lk("chrome_fpX")); /* longer, not exact */
}

CTEST(ja4_family, empty_table_or_key_is_unknown)
{
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN,
                 heavybag_ja4_family_lookup(NULL, 0, (const u_char *) "x", 1));
    ASSERT_EQUAL(HEAVYBAG_TLSFAM_UNKNOWN,
                 heavybag_ja4_family_lookup(ja4_tbl, JA4_N, (const u_char *) "", 0));
}


/* ===================================================================== *
 *  ja4_signal contradiction logic (the TLS half of is_spoofed)          *
 * ===================================================================== */

/* Mirror of the boolean the nginx wrapper computes: both families known and
 * different => spoof. */
static int
ja4_signal(ngx_http_heavybag_tls_family_e fam_ja4, ngx_http_heavybag_ua_browser_e b)
{
    ngx_http_heavybag_tls_family_e  fam_ua = ngx_http_heavybag_ua_expected_tls_family(b);
    return fam_ja4 != HEAVYBAG_TLSFAM_UNKNOWN && fam_ua != HEAVYBAG_TLSFAM_UNKNOWN
           && fam_ja4 != fam_ua;
}

CTEST(spoof, tool_ja4_with_chrome_ua_is_spoof)
{
    /* curl's TLS fingerprint (tool) under a Chrome UA -> contradiction */
    ASSERT_TRUE(ja4_signal(HEAVYBAG_TLSFAM_TOOL, HEAVYBAG_BROWSER_CHROME));
}

CTEST(spoof, matching_family_is_not_spoof)
{
    ASSERT_FALSE(ja4_signal(HEAVYBAG_TLSFAM_CHROMIUM, HEAVYBAG_BROWSER_CHROME));
    ASSERT_FALSE(ja4_signal(HEAVYBAG_TLSFAM_FIREFOX, HEAVYBAG_BROWSER_FIREFOX));
}

CTEST(spoof, unknown_ja4_is_not_spoof)
{
    /* an unknown/absent JA4 never triggers (avoids false positives) */
    ASSERT_FALSE(ja4_signal(HEAVYBAG_TLSFAM_UNKNOWN, HEAVYBAG_BROWSER_CHROME));
}

CTEST(spoof, unmapped_ua_is_not_spoof)
{
    /* a UA browser with no stable TLS family (msie) never triggers */
    ASSERT_FALSE(ja4_signal(HEAVYBAG_TLSFAM_CHROMIUM, HEAVYBAG_BROWSER_MSIE));
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
