/*
 * Coverage for the PCRE1 #else arm of ngx_http_heavybag_regex_exec
 * (heavybag_match.c:308-316). The normal match unit build hard-defines
 * NGX_PCRE2, so that arm -- the legacy path for an --with-pcre (PCRE1) nginx,
 * which has no match-limit knob -- is dead and unreachable from test-match.c.
 *
 * This TU adds -DHEAVYBAG_MATCH_FORCE_PCRE1 on top of -DHEAVYBAG_MATCH_UNIT_TEST,
 * which (in heavybag_match.c's shim arm) leaves NGX_PCRE2 UNDEFINED, so the
 * #else regex_exec arm + the PCRE1 HEAVYBAG_RE_NOMATCH_RC compile and run. The
 * underlying engine is still real pcre2 (via the shim's ngx_regex_exec
 * wrapper) -- we are exercising the heavybag PCRE1 CODE PATH, not a PCRE1
 * engine. NGX_REGEX_NO_MATCHED is defined by the shim to PCRE2_ERROR_NOMATCH
 * (both == -1, verified) so a clean no-match classifies correctly.
 *
 * The production -Werror SSL build defines NEITHER test macro -> byte-
 * transparent; this is a pure test addition.
 *
 * Cases: clean match -> MATCH, no-match -> NOMATCH, and a non-NOMATCH negative
 * rc -> ERROR (fail CLOSED: the caller treats an unevaluable subject as a hit,
 * never a silent clean pass). The last is driven through the shared classifier
 * ngx_http_heavybag_re_classify -- the exact mapping the #else arm returns on an
 * internal PCRE error -- because a real pcre2 internal error cannot be forced
 * deterministically/quickly through a live match.
 */

#ifndef HEAVYBAG_MATCH_UNIT_TEST
#define HEAVYBAG_MATCH_UNIT_TEST
#endif
#ifndef HEAVYBAG_MATCH_FORCE_PCRE1
#define HEAVYBAG_MATCH_FORCE_PCRE1
#endif
#include "../../src/heavybag_match.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>


/* This TU MUST have compiled the PCRE1 arm: NGX_PCRE2 must be undefined here.
 * (If FORCE_PCRE1 ever stopped suppressing it, this would fire at build time.) */
#if (NGX_PCRE2)
#error "test-match-pcre1.c must build the PCRE1 arm: NGX_PCRE2 must be undefined"
#endif


/* compile a pattern via the shim's ngx_regex_compile (-> real pcre2_compile) */
static ngx_regex_t *
compile(const char *pat)
{
    ngx_regex_compile_t  rc;

    memset(&rc, 0, sizeof rc);
    rc.pattern.data = (u_char *) pat;
    rc.pattern.len = strlen(pat);
    rc.options = 0;
    if (ngx_regex_compile(&rc) != NGX_OK) {
        return NULL;
    }
    return rc.regex;
}

static ngx_http_heavybag_re_e
run(ngx_regex_t *re, const char *subject)
{
    ngx_str_t  s;

    s.data = (u_char *) subject;
    s.len = strlen(subject);
    return ngx_http_heavybag_regex_exec(re, &s);
}


/* ======================================================================= *
 *  M1  PCRE1 arm: a pattern that matches -> HEAVYBAG_RE_MATCH.             *
 * ======================================================================= */
CTEST(match_pcre1, clean_match)
{
    ngx_regex_t  *re = compile("abc");
    ASSERT_NOT_NULL(re);
    ASSERT_EQUAL(HEAVYBAG_RE_MATCH, run(re, "xx-abc-yy"));
}


/* ======================================================================= *
 *  M2  PCRE1 arm: a clean no-match -> HEAVYBAG_RE_NOMATCH (NGX_REGEX_NO_   *
 *  MATCHED == PCRE2_ERROR_NOMATCH == -1 classified as clean).             *
 * ======================================================================= */
CTEST(match_pcre1, clean_no_match)
{
    ngx_regex_t  *re = compile("abc");
    ASSERT_NOT_NULL(re);
    ASSERT_EQUAL(HEAVYBAG_RE_NOMATCH, run(re, "xyz123"));
}


/* ======================================================================= *
 *  M3  fail-CLOSED: a non-NOMATCH negative rc (internal PCRE error / blown *
 *  limit) maps to HEAVYBAG_RE_ERROR -- the caller treats the subject as a  *
 *  hit, never a silent clean pass -- and the once-per-worker warn fires.   *
 *  This is the exact mapping the PCRE1 #else arm returns on such an rc.    *
 * ======================================================================= */
CTEST(match_pcre1, internal_error_fails_closed)
{
    unsigned  before = heavybag_ut_regex_limit_count;

    /* PCRE2_ERROR_INTERNAL is a negative rc that is NOT NOMATCH */
    ASSERT_EQUAL(HEAVYBAG_RE_ERROR,
                 ngx_http_heavybag_re_classify(PCRE2_ERROR_INTERNAL));
    /* and the unevaluable subject was surfaced (not silently dropped) */
    ASSERT_EQUAL(before + 1, heavybag_ut_regex_limit_count);

    /* a >=0 rc is always a match; -1 (NOMATCH) is the only "clean negative" */
    ASSERT_EQUAL(HEAVYBAG_RE_MATCH,   ngx_http_heavybag_re_classify(0));
    ASSERT_EQUAL(HEAVYBAG_RE_NOMATCH, ngx_http_heavybag_re_classify(-1));
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
