/*
 * Unit tests for the scanner/UA match core (heavybag_match.c).
 *
 * Compiled standalone: includes heavybag_match.c under -DHEAVYBAG_MATCH_UNIT_TEST
 * so only the config-time list parser + the PCRE2 bucket compile/exec core is
 * pulled in (no nginx / SSL headers). The type shim lives in heavybag_match.h,
 * the runtime-symbol shim (arena, ngx_array, ngx_regex_compile -> real
 * pcre2_compile, config-log capture, in-memory read_file) in heavybag_match.c.
 * The real -Werror SSL module build stays the only correctness contract.
 *
 * REAL PCRE2 is linked (-lpcre2-8): the round-2 ReDoS match/depth-limit fix
 * (ngx_http_heavybag_regex_exec) is exercised end-to-end against pcre2_match(),
 * NOT a mock -- a mocked engine would make the fail-open assertion a tautology.
 * Built + run by run-unit-tests.sh with `cc -DHEAVYBAG_MATCH_UNIT_TEST ... -lpcre2-8`.
 *
 * The static next_line tokenizer, compile_bucket and the bounded-exec helper
 * are reachable because this TU includes the .c directly. scanner_compile is
 * driven by installing an in-memory list buffer in heavybag_ut_file (set_file).
 *
 * OUT OF UNIT SCOPE (honest limits, NOT faked here):
 *   - The percent-decode vectors of the WF-3 match-redos backlog -- bare
 *     trailing `%`, `%2g` 3-byte delete, `%2`-at-EOF nibble drop, `%00` NUL
 *     token-break, all-`%` contraction -- do NOT live in heavybag_match.c. They
 *     live in ngx_http_heavybag_module.c (sig_lookup_decoded + ngx_unescape_uri),
 *     which is ngx_http_request_t-bound -> integration (Phase 6).
 *   - Empty args/cookie short-circuit, cookie WHOLE-match (no `;`/`=` pair-walk)
 *     and the multi-Cookie ngx_list walk are likewise module.c request-path
 *     logic, not match.c -> integration (Phase 6).
 *   - The ReDoS *timing* proof (bounded 0.020s vs an unbounded ~2^40-step hang)
 *     belongs to the runtime layer (Fix-round-2 .claude/tmp/reverify2 measured
 *     it). Here we assert the OUTCOME the limit guarantees: catastrophic input
 *     fails to a no-match (security fail-open) and terminates, while a legit
 *     match still fires (the limit never clips it).
 *   - The nginx-glue tail (ua_list_compile / ja4_list_compile /
 *     verified_bot_compile / ua_classify) sits behind #ifndef -- it needs an
 *     ngx_http_request_t / cidr_add / the ja4 table -> integration / the ja4
 *     suite already covers the fingerprint table.
 */

#ifndef HEAVYBAG_MATCH_UNIT_TEST
#define HEAVYBAG_MATCH_UNIT_TEST
#endif
#include "../../src/heavybag_match.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>
#include <stdlib.h>


/* ---- helpers ----------------------------------------------------------- */

/* install the in-memory list the shimmed read_file serves to scanner_compile */
static void
set_file(const char *s)
{
    heavybag_ut_file.data = (u_char *) s;
    heavybag_ut_file.len = strlen(s);
}

/* compile a list into a fresh per-action bucket row */
static ngx_int_t
compile(const char *content, ngx_regex_t **re)
{
    ngx_conf_t  cf;
    ngx_str_t   path;

    memset(&cf, 0, sizeof(cf));
    path.data = (u_char *) "test.list";
    path.len = sizeof("test.list") - 1;
    set_file(content);
    return ngx_http_heavybag_scanner_compile(&cf, &path, re);
}

/* run a NUL-terminated subject through the compiled buckets */
static ngx_int_t
lookup(ngx_regex_t **re, const char *s)
{
    ngx_str_t  subj;

    subj.data = (u_char *) s;
    subj.len = strlen(s);
    return ngx_http_heavybag_scanner_lookup(re, &subj);
}


/* ======================================================================= *
 *  next_line tokenizer (pure: CR strip, ws-trim, blank/comment skip).      *
 *  Driven directly -- the static fn is reachable via the included .c.      *
 * ======================================================================= */

CTEST(match, next_line_crlf_stripped)
{
    u_char   buf[] = "ab\r\ncd\n";
    u_char  *p = buf, *end = buf + sizeof(buf) - 1, *ls, *le;

    ASSERT_EQUAL(NGX_OK, ngx_http_heavybag_next_line(&p, end, &ls, &le));
    ASSERT_EQUAL(2, (int) (le - ls));              /* \r stripped */
    ASSERT_TRUE(memcmp(ls, "ab", 2) == 0);

    ASSERT_EQUAL(NGX_OK, ngx_http_heavybag_next_line(&p, end, &ls, &le));
    ASSERT_TRUE(memcmp(ls, "cd", 2) == 0);

    ASSERT_EQUAL(NGX_DONE, ngx_http_heavybag_next_line(&p, end, &ls, &le));
}

CTEST(match, next_line_whitespace_trimmed)
{
    u_char   buf[] = "  \t^/x \t \n";
    u_char  *p = buf, *end = buf + sizeof(buf) - 1, *ls, *le;

    ASSERT_EQUAL(NGX_OK, ngx_http_heavybag_next_line(&p, end, &ls, &le));
    ASSERT_EQUAL(3, (int) (le - ls));              /* leading + trailing ws gone */
    ASSERT_TRUE(memcmp(ls, "^/x", 3) == 0);
}

CTEST(match, next_line_blank_and_comment_skipped)
{
    u_char   buf[] = "\n   \n# a full-line comment\n^/real\n";
    u_char  *p = buf, *end = buf + sizeof(buf) - 1, *ls, *le;

    ASSERT_EQUAL(NGX_OK, ngx_http_heavybag_next_line(&p, end, &ls, &le));
    ASSERT_EQUAL(6, (int) (le - ls));
    ASSERT_TRUE(memcmp(ls, "^/real", 6) == 0);     /* only the significant line */
    ASSERT_EQUAL(NGX_DONE, ngx_http_heavybag_next_line(&p, end, &ls, &le));
}

CTEST(match, next_line_last_line_no_newline)
{
    u_char   buf[] = "^/x";                        /* no trailing \n */
    u_char  *p = buf, *end = buf + sizeof(buf) - 1, *ls, *le;

    ASSERT_EQUAL(NGX_OK, ngx_http_heavybag_next_line(&p, end, &ls, &le));
    ASSERT_EQUAL(3, (int) (le - ls));              /* le == end, still yielded */
    ASSERT_TRUE(memcmp(ls, "^/x", 3) == 0);
    ASSERT_EQUAL(NGX_DONE, ngx_http_heavybag_next_line(&p, end, &ls, &le));
}

CTEST(match, next_line_hash_only_at_start_is_comment)
{
    /* '#' is a comment ONLY as the first significant char; mid-line '#' is
     * yielded whole (scanner_compile, not next_line, strips the action '#'). */
    u_char   buf[] = "^/a#b\n";
    u_char  *p = buf, *end = buf + sizeof(buf) - 1, *ls, *le;

    ASSERT_EQUAL(NGX_OK, ngx_http_heavybag_next_line(&p, end, &ls, &le));
    ASSERT_EQUAL(5, (int) (le - ls));
    ASSERT_TRUE(memcmp(ls, "^/a#b", 5) == 0);       /* mid-line # preserved */
}


/* ======================================================================= *
 *  scanner_compile action-parse (the round-2 inline-comment + fatal fix).  *
 *  Buckets verified by matching a subject through scanner_lookup.          *
 * ======================================================================= */

CTEST(match, action_explicit_buckets)
{
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    ASSERT_EQUAL(NGX_OK, compile("^/forbidden 403\n"
                                 "^/notfound 404\n"
                                 "^/closed 444\n", re));
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN, lookup(re, "/forbidden"));
    ASSERT_EQUAL(NGX_HTTP_NOT_FOUND, lookup(re, "/notfound"));
    ASSERT_EQUAL(NGX_HTTP_CLOSE,     lookup(re, "/closed"));
}

CTEST(match, action_inline_comment_after_action)
{
    /* round-2: "^/x 403 # note" -> the action region is truncated at '#' and
     * right-trimmed, so the bucket is 403, not an unknown-action abort. */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    heavybag_ut_emerg_count = 0;
    ASSERT_EQUAL(NGX_OK, compile("^/x 403 # inline note\n", re));
    ASSERT_EQUAL(0u, heavybag_ut_emerg_count);     /* not treated as a typo */
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN, lookup(re, "/x"));
}

CTEST(match, action_comment_only_defaults_404)
{
    /* "^/x # note": the action token is empty (comment only) -> default 404 */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    heavybag_ut_emerg_count = 0;
    ASSERT_EQUAL(NGX_OK, compile("^/x # just a note\n", re));
    ASSERT_EQUAL(0u, heavybag_ut_emerg_count);
    ASSERT_EQUAL(NGX_HTTP_NOT_FOUND, lookup(re, "/x"));
}

CTEST(match, action_unknown_is_fatal)
{
    /* round-2: a genuine typo aborts the config (fail-closed), never silently
     * degrades a mis-typed 403/444 rule to a 404 bucket. */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    heavybag_ut_emerg_count = 0;
    ASSERT_EQUAL(NGX_ERROR, compile("^/x bock\n", re));
    ASSERT_TRUE(heavybag_ut_emerg_count >= 1u);     /* EMERG was logged */
}

CTEST(match, action_hash_inside_pattern_safe)
{
    /* "^/a#b" with no whitespace: the whole token is the PATTERN (the action
     * region begins only after whitespace), so the '#' is part of the regex
     * and the rule lands in the default 404 bucket -- never an action strip. */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    heavybag_ut_emerg_count = 0;
    ASSERT_EQUAL(NGX_OK, compile("^/a#b\n", re));
    ASSERT_EQUAL(0u, heavybag_ut_emerg_count);
    ASSERT_EQUAL(NGX_HTTP_NOT_FOUND, lookup(re, "/a#b"));
}


/* ======================================================================= *
 *  compile_bucket alternation + scanner_lookup precedence + real PCRE2.    *
 * ======================================================================= */

CTEST(match, empty_list_null_buckets_declined)
{
    /* a comments-only / blank file yields NULL regex in every bucket; lookup
     * skips NULL slots and declines. */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    ASSERT_EQUAL(NGX_OK, compile("# only comments\n\n   \n", re));
    ASSERT_TRUE(re[HEAVYBAG_ACTION_404] == NULL);
    ASSERT_TRUE(re[HEAVYBAG_ACTION_403] == NULL);
    ASSERT_TRUE(re[HEAVYBAG_ACTION_444] == NULL);
    ASSERT_EQUAL(NGX_DECLINED, lookup(re, "/anything"));
}

CTEST(match, bucket_precedence_404_before_444)
{
    /* same subject matches a 404 and a 444 pattern; scanner_lookup walks the
     * buckets in action order (404, 403, 444) and returns the FIRST hit. */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    ASSERT_EQUAL(NGX_OK, compile("^/dup 404\n^/dup 444\n", re));
    ASSERT_EQUAL(NGX_HTTP_NOT_FOUND, lookup(re, "/dup"));   /* 404 wins, not CLOSE */
}

CTEST(match, caseless_match)
{
    /* compile_bucket sets NGX_REGEX_CASELESS -> ^/admin matches /ADMIN */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    ASSERT_EQUAL(NGX_OK, compile("^/admin 403\n", re));
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN, lookup(re, "/ADMIN"));
}

CTEST(match, alternation_second_pattern_matches)
{
    /* two patterns in one bucket compile to (?:^/aaa)|(?:^/bbb); a subject
     * matching only the second alternative still hits -> the join is correct. */
    ngx_regex_t  *re[HEAVYBAG_ACTION_MAX] = { 0 };

    ASSERT_EQUAL(NGX_OK, compile("^/aaa 403\n^/bbb 403\n", re));
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN, lookup(re, "/bbb"));
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN, lookup(re, "/aaa"));
}

CTEST(match, redos_failopen_bounded)
{
    /*
     * The round-2 fix: ngx_http_heavybag_regex_exec runs pcre2_match() with an
     * EXPLICIT module match/depth limit (HEAVYBAG_PCRE2_MATCH_LIMIT=100000,
     * _DEPTH_LIMIT=1000), far below PCRE2's built-in 10,000,000 default match
     * limit. The pattern is NOT JIT-compiled (the shim's ngx_regex_compile
     * calls only pcre2_compile), so pcre2_match() uses the interpreter and the
     * match/depth limits are honoured. Two things are asserted:
     *
     *  (1) terminal fail-open smoke: a heavily catastrophic input (40 'a's)
     *      yields a negative rc (no-match class) and the full lookup fails open
     *      to DECLINED -- no false block, CPU bounded, the test TERMINATES.
     *
     *  (2) LOAD-BEARING discrimination: a subject tuned so its backtracking
     *      cost sits BETWEEN the module's 100k limit and PCRE2's 10M default.
     *      A DEFAULT match context (mctx=NULL) completes the backtracking and
     *      returns EXACTLY PCRE2_ERROR_NOMATCH (-1) -- proving the input is
     *      under both the default match AND depth budget -- while the MODULE
     *      context trips MATCHLIMIT or DEPTHLIMIT (never NOMATCH) on the SAME
     *      input. If pcre2_set_match_limit/_depth_limit were removed or
     *      inflated, the module context would also return NOMATCH and assert
     *      (2) would FAIL. That is what makes this test guard the fix instead
     *      of being a tautology: the 10M default alone already trips at 40 'a's,
     *      so a `rc < 0` check proves nothing about the module's tighter bound.
     */
    ngx_regex_t       *re[HEAVYBAG_ACTION_MAX] = { 0 };
    ngx_str_t          subj;
    u_char             evil[64];
    pcre2_match_data  *dmd;
    int                default_rc, module_rc;
    /* N tuned so the (a+)+$ backtracking cost on N 'a's + 'X' lands strictly
     * between the module's 100k and PCRE2's 10M match budget. Verified by the
     * control assert below: at this N the default context returns exactly -1. */
    const size_t       N = 21;

    ASSERT_EQUAL(NGX_OK, compile("(a+)+$ 403\n", re));

    /* (1) terminal fail-open smoke: deeply catastrophic, trips the module limit */
    memset(evil, 'a', 40);
    evil[40] = 'X';
    subj.data = evil;
    subj.len = 41;
    ASSERT_TRUE(ngx_http_heavybag_regex_exec(re[HEAVYBAG_ACTION_403], &subj) < 0);
    /* full lookup path fails open to DECLINED (no false block from a blown limit) */
    ASSERT_EQUAL(NGX_DECLINED, ngx_http_heavybag_scanner_lookup(re, &subj));

    /* (2) discrimination vector: N 'a's + 'X' (cost between 100k and 10M) */
    memset(evil, 'a', N);
    evil[N] = 'X';
    subj.data = evil;
    subj.len = N + 1;

    /* control: a DEFAULT context (no module limit) completes the backtracking
     * and returns EXACTLY NOMATCH (-1). If N were too large the control would
     * itself trip a limit (rc != -1) and the discrimination below would be
     * meaningless -- so this assert pins N under the PCRE2 default budget. */
    dmd = pcre2_match_data_create(1, NULL);
    ASSERT_NOT_NULL(dmd);
    default_rc = pcre2_match((pcre2_code *) re[HEAVYBAG_ACTION_403],
                             subj.data, subj.len, 0, 0, dmd, NULL /* default ctx */);
    pcre2_match_data_free(dmd);
    ASSERT_EQUAL(PCRE2_ERROR_NOMATCH, default_rc);   /* exactly -1, not just < 0 */

    /* load-bearing: the MODULE context's tighter limit trips on the SAME input.
     * (a+)+ may hit the 1000 depth limit before the 100k match limit, so accept
     * either MATCHLIMIT or DEPTHLIMIT -- both are distinct from NOMATCH and both
     * mean "the module bounded the backtracking the default context did not". */
    module_rc = (int) ngx_http_heavybag_regex_exec(re[HEAVYBAG_ACTION_403], &subj);
    ASSERT_TRUE(module_rc == PCRE2_ERROR_MATCHLIMIT
                || module_rc == PCRE2_ERROR_DEPTHLIMIT);

    /* positive control: the limit never clips a genuine match */
    ASSERT_EQUAL(NGX_HTTP_FORBIDDEN, lookup(re, "aaaa"));
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
