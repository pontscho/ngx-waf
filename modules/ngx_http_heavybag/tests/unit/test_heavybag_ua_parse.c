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


/* ===================================================================== *
 *  EDGE / FUZZ vectors (WF-3 ua-fuzz backlog, Test-matrix Phase 3)      *
 *                                                                       *
 *  These drive the two security-critical primitives DIRECTLY -- the     *
 *  bounded case-insensitive scan heavybag_ua_find() and the charset-     *
 *  clamped version slice heavybag_ua_version() (both `static`, reachable *
 *  because the .c is #included into this TU) -- plus the parse-core      *
 *  orchestrator at its boundary conditions. They are the byte-level      *
 *  robustness net the happy-path suites above do not cover.             *
 *                                                                       *
 *  OUT OF UNIT SCOPE (runtime-bound, NOT faked here): the nginx-facing   *
 *  wrappers ngx_http_heavybag_ua_parse() (request-ctx population,        *
 *  ua_parsed latch, threat-category override) and                       *
 *  ngx_http_heavybag_ua_spoof_eval() (live JA4 fetch from SSL ex-data +  *
 *  verified-bot CIDR signal) sit behind #ifndef HEAVYBAG_UA_PARSE_UNIT_  *
 *  TEST -- they need an ngx_http_request_t and a TLS connection. The     *
 *  ja4_signal contradiction boolean is already mirrored in the `spoof`   *
 *  suite; the live JA4 wire walk is Phase 6b. The CR/LF/quote clamp's    *
 *  downstream-sink protection (log_format / add_header) is an            *
 *  integration concern; the core only guarantees the slice TERMINATES    *
 *  at the first out-of-charset byte -- that termination is what we test. *
 * ===================================================================== */

/* parse-core helper taking an EXPLICIT length: P() above uses strlen(), so it
 * cannot carry an embedded NUL or a non-NUL-terminated oversized buffer. */
static pr_t
PN(const u_char *ua, size_t n)
{
    pr_t  r;
    heavybag_ua_parse_core(ua, n, &r.b, &r.o, &r.c, &r.v, &r.vs, &r.vl);
    return r;
}


/* ===================================================================== *
 *  heavybag_ua_find -- the bounded, case-insensitive scan primitive      *
 * ===================================================================== */

/* The scan must NEVER compute hlen-nlen when nlen>hlen: in size_t that
 * underflows to an astronomical `last` -> wild over-read. The nlen>hlen guard
 * returns NULL first. (Backlog: single-byte < every needle, underflow guard.) */
CTEST(ua_find, needle_longer_than_hay_no_underflow)
{
    ASSERT_NULL(heavybag_ua_find((const u_char *) "ab", 2, "abc", 3));
    ASSERT_NULL(heavybag_ua_find((const u_char *) "", 0, "x", 1));
}

/* nlen==hlen: last==0, the outer loop runs exactly once at i==0. */
CTEST(ua_find, exact_length_match_last_zero)
{
    const u_char  *hay = (const u_char *) "abc";
    ASSERT_TRUE(heavybag_ua_find(hay, 3, "abc", 3) == hay);
    ASSERT_NULL(heavybag_ua_find(hay, 3, "abd", 3));
}

/* nlen==0 short-circuits to NULL (the getter then reports not-found). */
CTEST(ua_find, empty_needle_is_null)
{
    ASSERT_NULL(heavybag_ua_find((const u_char *) "abc", 3, "", 0));
}

/* Match at the final valid offset i==last (the inclusive upper bound). */
CTEST(ua_find, match_at_final_position)
{
    const u_char  *hay = (const u_char *) "xxabc";
    ASSERT_TRUE(heavybag_ua_find(hay, 5, "abc", 3) == hay + 2);
}

/* The scan is LENGTH-driven, not NUL-terminated: a needle after an embedded
 * NUL is still found (strstr / strcasestr would stop at the NUL). */
CTEST(ua_find, nul_transparent_scan)
{
    static const u_char  hay[] = "a\0Chrome";   /* 8 bytes incl. the NUL */
    ASSERT_TRUE(heavybag_ua_find(hay, sizeof(hay) - 1, "Chrome", 6) == hay + 2);
}

/* ASCII case-fold applies to A-Z only (the |0x20 path on both operands). */
CTEST(ua_find, case_insensitive_fold)
{
    const u_char  *hay = (const u_char *) "fooCHROMEbar";
    ASSERT_TRUE(heavybag_ua_find(hay, 12, "chrome", 6) == hay + 3);
}


/* ===================================================================== *
 *  heavybag_ua_version -- the charset-clamped version slice (security)   *
 * ===================================================================== */

/* Token at the very end of the buffer: s==end, the charset loop never runs,
 * vlen 0, vstart points AT end (one past) -- but no byte beyond end is read. */
CTEST(ua_version, token_at_buffer_end_zero_len)
{
    const u_char  *hay = (const u_char *) "Chrome/";
    const u_char  *vs;
    size_t         vl;
    heavybag_ua_version(hay, 7, "Chrome/", 7, &vs, &vl);
    ASSERT_EQUAL((size_t) 0, vl);
    ASSERT_TRUE(vs == hay + 7);
}

/* A NUL byte is outside [0-9A-Za-z._-] -> it terminates the slice. */
CTEST(ua_version, nul_byte_terminates_version)
{
    static const u_char  hay[] = "curl/8.5\0.0";   /* 11 bytes incl. the NUL */
    const u_char        *vs;
    size_t               vl;
    heavybag_ua_version(hay, sizeof(hay) - 1, "curl/", 5, &vs, &vl);
    ASSERT_DATA((const unsigned char *) "8.5", 3, vs, vl);
}

/* A high-bit byte (>=0x80, e.g. a UTF-8 lead byte) is outside the ASCII
 * charset -> overlong / multibyte version sequences clamp at the first such
 * byte (no raw 8-bit bytes reach a downstream sink). */
CTEST(ua_version, high_bit_byte_terminates_version)
{
    const u_char  *hay = (const u_char *) "curl/8.5.0\xC3\xA9";
    const u_char  *vs;
    size_t         vl;
    heavybag_ua_version(hay, 12, "curl/", 5, &vs, &vl);
    ASSERT_DATA((const unsigned char *) "8.5.0", 5, vs, vl);
}

/* The full conservative charset (digits . _ - lower upper) is accepted. */
CTEST(ua_version, full_charset_accepted)
{
    const u_char  *hay = (const u_char *) "X/1.2.3-rc_4Z ";
    const u_char  *vs;
    size_t         vl;
    heavybag_ua_version(hay, 14, "X/", 2, &vs, &vl);
    ASSERT_DATA((const unsigned char *) "1.2.3-rc_4Z", 11, vs, vl);
}

/* Token absent -> vstart NULL + vlen 0 (out-params reset, poison overwritten). */
CTEST(ua_version, absent_token_null_slice)
{
    const u_char  *hay = (const u_char *) "Mozilla/5.0";
    const u_char  *vs = hay;   /* poison */
    size_t         vl = 99;    /* poison */
    heavybag_ua_version(hay, 11, "Chrome/", 7, &vs, &vl);
    ASSERT_NULL(vs);
    ASSERT_EQUAL((size_t) 0, vl);
}

/* The version is a zero-copy SLICE with NO upper length clamp -- a 4 KB
 * all-digit version is returned whole. Intentional; the note for downstream
 * sinks is that the slice length is attacker-influenced and must be bounded by
 * the consumer (the core neither copies nor truncates). */
CTEST(ua_version, enormous_all_digit_version)
{
    static u_char  big[7 + 4096];
    const u_char  *vs;
    size_t         vl;
    memcpy(big, "Chrome/", 7);
    memset(big + 7, '9', 4096);
    heavybag_ua_version(big, sizeof(big), "Chrome/", 7, &vs, &vl);
    ASSERT_EQUAL((size_t) 4096, vl);
    ASSERT_TRUE(vs == big + 7);
}

/* A space (the common token delimiter) terminates the slice. */
CTEST(ua_version, space_terminates_version)
{
    const u_char  *hay = (const u_char *) "Chrome/120 Safari";
    const u_char  *vs;
    size_t         vl;
    heavybag_ua_version(hay, 17, "Chrome/", 7, &vs, &vl);
    ASSERT_DATA((const unsigned char *) "120", 3, vs, vl);
}


/* ===================================================================== *
 *  parse-core orchestrator -- boundary / ordering edges                 *
 * ===================================================================== */

/* Empty UA: ALL FOUR descriptive fields stay UNKNOWN and the version is empty
 * -- every needle hits the nlen>hlen guard (hlen==0). (Complements
 * ua_browser/empty_is_unknown, which checks only the browser + vlen.) */
CTEST(ua_edge, empty_ua_all_fields_unknown)
{
    pr_t  r = P("");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_UNKNOWN, r.b);
    ASSERT_EQUAL(HEAVYBAG_OS_UNKNOWN, r.o);
    ASSERT_EQUAL(HEAVYBAG_CAT_UNKNOWN, r.c);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_UNKNOWN, r.v);
    ASSERT_EQUAL((size_t) 0, r.vl);
}

/* A single byte is shorter than every needle (the shortest is "wv", 2 bytes)
 * -> the underflow guard fires for all of them; nothing resolves, no over-read. */
CTEST(ua_edge, single_byte_ua_all_unknown)
{
    pr_t  r = P("M");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_UNKNOWN, r.b);
    ASSERT_EQUAL(HEAVYBAG_OS_UNKNOWN, r.o);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_UNKNOWN, r.v);
}

/* A multi-kilobyte UA with no recognized token runs every needle scan to
 * completion (i up to last across 8 KB) without over-reading; result UNKNOWN. */
CTEST(ua_edge, multi_kb_no_delimiter)
{
    static u_char  big[8192];
    pr_t           r;
    memset(big, 'a', sizeof(big));
    r = PN(big, sizeof(big));
    ASSERT_EQUAL(HEAVYBAG_BROWSER_UNKNOWN, r.b);
    ASSERT_EQUAL(HEAVYBAG_OS_UNKNOWN, r.o);
}

/* The Chrome webview form ("...; wv) ... Chrome/...") is detected as chrome via
 * the dedicated wv branch, which deliberately yields NO version slice (vl 0)
 * -- distinct from a normal Chrome UA that slices the Chrome/ version. */
CTEST(ua_edge, webview_wv_no_version)
{
    pr_t  r = P("Mozilla/5.0 (Linux; Android 13; wv) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile "
                "Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CHROME, r.b);
    ASSERT_EQUAL((size_t) 0, r.vl);
    ASSERT_EQUAL(HEAVYBAG_OS_ANDROID, r.o);
    ASSERT_EQUAL(HEAVYBAG_CAT_MOBILE, r.c);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_GOOGLE, r.v);
}

/* AppleWebKit present but NO Safari/ token -> SAFARI with an EMPTY version
 * (HEAVYBAG_VER on the absent "Safari/" yields len 0); vendor still apple. */
CTEST(ua_edge, applewebkit_without_safari_empty_version)
{
    pr_t  r = P("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko)");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_SAFARI, r.b);
    ASSERT_EQUAL((size_t) 0, r.vl);
    ASSERT_EQUAL(HEAVYBAG_OS_MACOS, r.o);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_APPLE, r.v);
}

/* CriOS/ (Chrome on iOS) is matched BEFORE the trailing Safari/ token, so an
 * iOS Chrome resolves to chrome/google, not safari/apple (ordering precedence). */
CTEST(ua_edge, crios_over_safari)
{
    pr_t  r = P("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 "
                "Mobile/15E148 Safari/604.1");
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CHROME, r.b);
    ASSERT_TRUE(veq(r, "120.0.6099.119"));
    ASSERT_EQUAL(HEAVYBAG_OS_IPHONE, r.o);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_GOOGLE, r.v);
}

/* HarmonyOS + bare Chrome: the OS resolves to harmonyos, but the VENDOR is
 * driven by the browser switch (chrome -> google), which precedes the
 * os==harmonyos -> huawei fallback. Browser-vendor wins over os-vendor. */
CTEST(ua_edge, harmonyos_browser_vendor_precedence)
{
    pr_t  r = P("Mozilla/5.0 (Linux; Android 10; HarmonyOS) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 "
                "Mobile Safari/537.36");
    ASSERT_EQUAL(HEAVYBAG_OS_HARMONYOS, r.o);
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CHROME, r.b);
    ASSERT_EQUAL(HEAVYBAG_VENDOR_GOOGLE, r.v);
    ASSERT_TRUE(veq(r, "114.0.0.0"));
}

/* End-to-end NUL transparency through the orchestrator: a recognized token
 * placed AFTER an embedded NUL (explicit length, NOT strlen) is still found,
 * so a UA cannot smuggle bytes past the parser with a NUL truncation. */
CTEST(ua_edge, embedded_nul_then_token_found)
{
    static const u_char  ua[] = "ab\0Chrome/120.0.0.0";  /* 19 bytes incl NUL */
    pr_t                  r = PN(ua, sizeof(ua) - 1);
    ASSERT_EQUAL(HEAVYBAG_BROWSER_CHROME, r.b);
    ASSERT_TRUE(veq(r, "120.0.0.0"));
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
