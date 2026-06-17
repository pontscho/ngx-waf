/*
 * ngx_http_heavybag_module - path scanner matching and User-Agent classification
 *
 * The scanner list is read at configuration time. Each non-empty,
 * non-comment line is:
 *
 *     <pattern>[ <action>]
 *
 * where <pattern> is a PCRE2 fragment (anchored by the author, e.g.
 * "^/wp-") and <action> is one of 404 (default), 403 or 444. Patterns
 * sharing an action are concatenated into one anchored alternation and
 * compiled once -- a single JIT-ed exec per bucket at request time, not
 * one exec per pattern. The compiled code is bound to cf->pool, so a
 * configuration reload re-reads the file and frees the old regex.
 */

#include "heavybag_match.h"


/* Action bucket -> nginx finalize code. Indexed by ngx_http_heavybag_action_e. */
static ngx_uint_t  heavybag_action_code[HEAVYBAG_ACTION_MAX] = {
    NGX_HTTP_NOT_FOUND,    /* HEAVYBAG_ACTION_404 */
    NGX_HTTP_FORBIDDEN,    /* HEAVYBAG_ACTION_403 */
    NGX_HTTP_CLOSE         /* HEAVYBAG_ACTION_444 */
};


static ngx_int_t ngx_http_heavybag_read_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_str_t *out);
static ngx_int_t ngx_http_heavybag_next_line(u_char **pp, u_char *end,
    u_char **ls_out, u_char **le_out);
static ngx_int_t ngx_http_heavybag_compile_bucket(ngx_conf_t *cf,
    ngx_array_t *patterns, ngx_regex_t **out);


/*
 * Bounded regex exec. nginx's ngx_regex_exec() wrapper calls pcre2_match()
 * with a DEFAULT match context (no match/depth limit), so a pathological
 * operator-authored pattern on a crafted subject is a latent quadratic
 * CPU foot-gun. nginx exposes no match-limit knob, so we bypass the wrapper
 * with a module-local match context carrying explicit limits.
 *
 * On MATCHLIMIT/DEPTHLIMIT pcre2_match() returns negative -> treated as
 * no-match (fail-open): the CPU is bounded and legit traffic is not blocked
 * because an operator's pattern blew the limit (a config problem, not a
 * request). The statics are per-worker, single-threaded -> safe; they live
 * for the process lifetime (reclaimed at exit, like nginx's own global
 * ngx_regex_match_data) -- deliberately no exit_process handler for two
 * tiny objects. The PCRE1 path keeps working via the wrapper.
 */
#if (NGX_PCRE2)
#define HEAVYBAG_PCRE2_MATCH_LIMIT  100000   /* bound backtracking steps */
#define HEAVYBAG_PCRE2_DEPTH_LIMIT  1000     /* bound recursion depth */
static pcre2_match_context  *heavybag_mctx;
static pcre2_match_data     *heavybag_mdata;

static ngx_int_t
ngx_http_heavybag_regex_exec(ngx_regex_t *re, ngx_str_t *s)
{
    int  rc;

    if (heavybag_mctx == NULL) {
        heavybag_mctx = pcre2_match_context_create(NULL);
        if (heavybag_mctx == NULL) {
            return ngx_regex_exec(re, s, NULL, 0);   /* OOM -> wrapper */
        }
        pcre2_set_match_limit(heavybag_mctx, HEAVYBAG_PCRE2_MATCH_LIMIT);
        pcre2_set_depth_limit(heavybag_mctx, HEAVYBAG_PCRE2_DEPTH_LIMIT);
    }
    if (heavybag_mdata == NULL) {
        heavybag_mdata = pcre2_match_data_create(1, NULL);   /* boolean match */
        if (heavybag_mdata == NULL) {
            return ngx_regex_exec(re, s, NULL, 0);
        }
    }

    rc = pcre2_match((pcre2_code *) re, s->data, s->len, 0, 0,
                     heavybag_mdata, heavybag_mctx);

    return (ngx_int_t) rc;   /* >=0 match; <0 NOMATCH/MATCHLIMIT/DEPTHLIMIT */
}
#else
#define ngx_http_heavybag_regex_exec(re, s)  ngx_regex_exec((re), (s), NULL, 0)
#endif


/*
 * Config-time: resolve path against the prefix, open and stat it, and read
 * the whole file into a temp-pool buffer returned via out. Logs and returns
 * NGX_ERROR on any open/stat/short-read failure.
 */
static ngx_int_t
ngx_http_heavybag_read_file(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *out)
{
    u_char           *buf;
    size_t            size;
    ssize_t           n;
    ngx_fd_t          fd;
    ngx_str_t         full;
    ngx_file_info_t   fi;

    full = *path;

    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(full.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &full);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &full);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = (size_t) ngx_file_size(&fi);

    buf = ngx_palloc(cf->temp_pool, size ? size : 1);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, buf, size);

    ngx_close_file(fd);

    if (n == NGX_FILE_ERROR || (size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to read list file \"%V\"", &full);
        return NGX_ERROR;
    }

    out->data = buf;
    out->len = size;

    return NGX_OK;
}


/*
 * Yield the next significant line from the buffer [*pp, end): a trailing CR
 * and surrounding spaces/tabs are stripped, blank and '#'-comment lines are
 * skipped. On success advances *pp past the line, sets *ls_out and *le_out to the
 * trimmed bounds and returns NGX_OK; returns NGX_DONE at end of buffer.
 */
static ngx_int_t
ngx_http_heavybag_next_line(u_char **pp, u_char *end, u_char **ls_out,
    u_char **le_out)
{
    u_char  *p, *ls, *le;

    p = *pp;

    while (p < end) {

        ls = p;
        while (p < end && *p != '\n') {
            p++;
        }
        le = p;
        if (p < end) {
            p++;                       /* step over '\n' for next round */
        }

        if (le > ls && le[-1] == '\r') {
            le--;
        }

        while (ls < le && (*ls == ' ' || *ls == '\t')) {
            ls++;
        }
        while (le > ls && (le[-1] == ' ' || le[-1] == '\t')) {
            le--;
        }

        if (ls == le || *ls == '#') {
            continue;
        }

        *pp = p;
        *ls_out = ls;
        *le_out = le;
        return NGX_OK;
    }

    *pp = p;
    return NGX_DONE;
}


/*
 * Join the patterns into one caseless alternation -- each item wrapped as a
 * non-capturing group and separated by '|' -- then compile it to a single
 * regex returned via out. An empty list yields a NULL regex and NGX_OK.
 */
static ngx_int_t
ngx_http_heavybag_compile_bucket(ngx_conf_t *cf, ngx_array_t *patterns,
    ngx_regex_t **out)
{
    u_char               *p;
    size_t                len;
    ngx_str_t            *elt, combined;
    ngx_uint_t            i;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t   rc;

    if (patterns->nelts == 0) {
        *out = NULL;
        return NGX_OK;
    }

    elt = patterns->elts;

    /* "(?:" + pattern + ")" per item, "|" between items */
    len = 0;
    for (i = 0; i < patterns->nelts; i++) {
        len += sizeof("(?:") - 1 + elt[i].len + sizeof(")") - 1;
    }
    len += patterns->nelts - 1;   /* separators */

    combined.data = ngx_palloc(cf->temp_pool, len);
    if (combined.data == NULL) {
        return NGX_ERROR;
    }

    p = combined.data;
    for (i = 0; i < patterns->nelts; i++) {
        if (i > 0) {
            *p++ = '|';
        }
        p = ngx_cpymem(p, "(?:", sizeof("(?:") - 1);
        p = ngx_cpymem(p, elt[i].data, elt[i].len);
        *p++ = ')';
    }
    combined.len = p - combined.data;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pattern = combined;
    rc.pool = cf->pool;
    rc.options = NGX_REGEX_CASELESS;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    *out = rc.regex;

    return NGX_OK;
}


ngx_int_t
ngx_http_heavybag_scanner_compile(ngx_conf_t *cf, ngx_str_t *path,
    ngx_regex_t **re_bucket)
{
    u_char       *p, *end, *ls, *le, *ps, *pe, *as, *ae;
    ngx_str_t     content, *pat, action;
    ngx_uint_t    i, bucket, total;
    ngx_array_t  *buckets[HEAVYBAG_ACTION_MAX];

    if (ngx_http_heavybag_read_file(cf, path, &content) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < HEAVYBAG_ACTION_MAX; i++) {
        buckets[i] = ngx_array_create(cf->temp_pool, 32, sizeof(ngx_str_t));
        if (buckets[i] == NULL) {
            return NGX_ERROR;
        }
    }

    total = 0;
    p = content.data;
    end = p + content.len;

    while (ngx_http_heavybag_next_line(&p, end, &ls, &le) == NGX_OK) {

        /* pattern = up to first whitespace; optional action token follows */
        ps = ls;
        pe = ls;
        while (pe < le && *pe != ' ' && *pe != '\t') {
            pe++;
        }

        as = pe;
        while (as < le && (*as == ' ' || *as == '\t')) {
            as++;
        }

        /*
         * Action token = [as, ae): the action region minus an optional inline
         * comment, right-trimmed. The pattern (before pe) is untouched, so a
         * '#' inside a pattern is safe -- only the action region is stripped.
         */
        ae = as;
        while (ae < le && *ae != '#') {
            ae++;
        }
        while (ae > as && (ae[-1] == ' ' || ae[-1] == '\t')) {
            ae--;
        }

        bucket = HEAVYBAG_ACTION_404;

        if (ae > as) {
            action.data = as;
            action.len = ae - as;

            if (action.len == 3 && ngx_strncmp(action.data, "403", 3) == 0) {
                bucket = HEAVYBAG_ACTION_403;

            } else if (action.len == 3
                       && ngx_strncmp(action.data, "444", 3) == 0)
            {
                bucket = HEAVYBAG_ACTION_444;

            } else if (action.len == 3
                       && ngx_strncmp(action.data, "404", 3) == 0)
            {
                bucket = HEAVYBAG_ACTION_404;

            } else {
                /* a genuine typo is fail-closed: abort the config, never
                 * silently degrade a mis-typed 403/444 rule to 404 */
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "heavybag: unknown action \"%V\" in scanner list", &action);
                return NGX_ERROR;
            }
        }

        pat = ngx_array_push(buckets[bucket]);
        if (pat == NULL) {
            return NGX_ERROR;
        }

        pat->data = ps;
        pat->len = pe - ps;
        total++;
    }

    for (i = 0; i < HEAVYBAG_ACTION_MAX; i++) {
        if (ngx_http_heavybag_compile_bucket(cf, buckets[i], &re_bucket[i])
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "heavybag: loaded %ui signature pattern(s) from \"%V\"", total, path);

    return NGX_OK;
}


ngx_int_t
ngx_http_heavybag_scanner_lookup(ngx_regex_t **re_bucket, ngx_str_t *subject)
{
    ngx_uint_t  i;

    for (i = 0; i < HEAVYBAG_ACTION_MAX; i++) {

        if (re_bucket[i] == NULL) {
            continue;
        }

        if (ngx_http_heavybag_regex_exec(re_bucket[i], subject) >= 0) {
            return (ngx_int_t) heavybag_action_code[i];
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_heavybag_ua_list_compile(ngx_conf_t *cf, ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_str_t *path, ngx_http_heavybag_ua_e cat)
{
    u_char       *p, *end, *ls, *le;
    ngx_str_t     content, *tok;
    ngx_uint_t    total;
    ngx_array_t  *tokens;

    if (ngx_http_heavybag_read_file(cf, path, &content) != NGX_OK) {
        return NGX_ERROR;
    }

    tokens = ngx_array_create(cf->temp_pool, 64, sizeof(ngx_str_t));
    if (tokens == NULL) {
        return NGX_ERROR;
    }

    total = 0;
    p = content.data;
    end = p + content.len;

    while (ngx_http_heavybag_next_line(&p, end, &ls, &le) == NGX_OK) {

        /* the whole trimmed line is one PCRE2 fragment -- no action token */
        tok = ngx_array_push(tokens);
        if (tok == NULL) {
            return NGX_ERROR;
        }

        tok->data = ls;
        tok->len = le - ls;
        total++;
    }

    if (ngx_http_heavybag_compile_bucket(cf, tokens, &wlcf->ua_re[cat]) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "heavybag: loaded %ui UA pattern(s) from \"%V\"", total, path);

    return NGX_OK;
}


/* Map a family token from lists/ja4.list to the coarse-family enum. An
 * unrecognized token (including the literal "unknown" emitted for ambiguous
 * fingerprints) maps to HEAVYBAG_TLSFAM_UNKNOWN -> the lookup can never produce a
 * false-positive spoof for it. */
static ngx_http_heavybag_tls_family_e
ngx_http_heavybag_ja4_family_parse(u_char *s, size_t len)
{
    if (len == sizeof("chromium") - 1
        && ngx_strncasecmp(s, (u_char *) "chromium", len) == 0)
    {
        return HEAVYBAG_TLSFAM_CHROMIUM;
    }
    if (len == sizeof("firefox") - 1
        && ngx_strncasecmp(s, (u_char *) "firefox", len) == 0)
    {
        return HEAVYBAG_TLSFAM_FIREFOX;
    }
    if (len == sizeof("safari") - 1
        && ngx_strncasecmp(s, (u_char *) "safari", len) == 0)
    {
        return HEAVYBAG_TLSFAM_SAFARI;
    }
    if (len == sizeof("tool") - 1
        && ngx_strncasecmp(s, (u_char *) "tool", len) == 0)
    {
        return HEAVYBAG_TLSFAM_TOOL;
    }
    if (len == sizeof("bot") - 1
        && ngx_strncasecmp(s, (u_char *) "bot", len) == 0)
    {
        return HEAVYBAG_TLSFAM_BOT;
    }
    return HEAVYBAG_TLSFAM_UNKNOWN;
}


/* Total order over ja4 keys: lexicographic with a length tiebreak. MUST match
 * the bsearch comparison in heavybag_ua_parse.c:heavybag_ja4_family_lookup so the sorted
 * table is searchable. */
static int ngx_libc_cdecl
ngx_http_heavybag_ja4_entry_cmp(const void *a, const void *b)
{
    const ngx_http_heavybag_ja4_entry_t  *ea = a;
    const ngx_http_heavybag_ja4_entry_t  *eb = b;
    size_t                           m;
    ngx_int_t                        c;

    m = ea->ja4.len < eb->ja4.len ? ea->ja4.len : eb->ja4.len;
    c = m ? (ngx_int_t) ngx_memcmp(ea->ja4.data, eb->ja4.data, m) : 0;
    if (c != 0) {
        return (c < 0) ? -1 : 1;
    }
    if (ea->ja4.len < eb->ja4.len) { return -1; }
    if (ea->ja4.len > eb->ja4.len) { return 1; }
    return 0;
}


/*
 * Config-time loader for lists/ja4.list. Each significant line is
 *
 *     <ja4-fingerprint> <coarse-family>
 *
 * (e.g. "t13d1516h2_8daaf6152771_e5627efa2ab1 chromium"). The fingerprint is
 * copied into cf->pool (the temp-pool content buffer is freed after config),
 * paired with its parsed family, pushed into a cf->pool array, then sorted by
 * the ja4 bytes so the per-request lookup (ngx_http_heavybag_ja4_family) can
 * bsearch it. Lines missing the family token are skipped with a warning.
 */
ngx_int_t
ngx_http_heavybag_ja4_list_compile(ngx_conf_t *cf, ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_str_t *path)
{
    u_char                    *p, *end, *ls, *le, *ks, *ke, *fs, *kd;
    ngx_str_t                  content, key;
    ngx_uint_t                 total;
    ngx_array_t               *table;
    ngx_http_heavybag_ja4_entry_t  *e;

    if (ngx_http_heavybag_read_file(cf, path, &content) != NGX_OK) {
        return NGX_ERROR;
    }

    table = ngx_array_create(cf->pool, 64, sizeof(ngx_http_heavybag_ja4_entry_t));
    if (table == NULL) {
        return NGX_ERROR;
    }

    total = 0;
    p = content.data;
    end = p + content.len;

    while (ngx_http_heavybag_next_line(&p, end, &ls, &le) == NGX_OK) {

        /* key = up to first whitespace; family = first token after it */
        ks = ls;
        ke = ls;
        while (ke < le && *ke != ' ' && *ke != '\t') {
            ke++;
        }

        fs = ke;
        while (fs < le && (*fs == ' ' || *fs == '\t')) {
            fs++;
        }

        if (ke == ks || fs == le) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "heavybag: malformed ja4.list line in \"%V\" (need \"<ja4> <family>\"), "
                "skipping", path);
            continue;
        }

        key.len = ke - ks;
        kd = ngx_pnalloc(cf->pool, key.len);
        if (kd == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(kd, ks, key.len);
        key.data = kd;

        e = ngx_array_push(table);
        if (e == NULL) {
            return NGX_ERROR;
        }
        e->ja4 = key;
        e->family = ngx_http_heavybag_ja4_family_parse(fs, (size_t) (le - fs));
        total++;
    }

    if (table->nelts > 1) {
        ngx_qsort(table->elts, table->nelts,
                  sizeof(ngx_http_heavybag_ja4_entry_t), ngx_http_heavybag_ja4_entry_cmp);
    }

    wlcf->ja4_table = table;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "heavybag: loaded %ui ja4 fingerprint(s) from \"%V\"", total, path);

    return NGX_OK;
}


ngx_int_t
ngx_http_heavybag_verified_bot_compile(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *path)
{
    u_char      *p, *end, *ls, *le;
    ngx_str_t    content, line;
    ngx_uint_t   total;

    /*
     * A missing / unopenable file aborts the reload (fail-closed-to-old-config);
     * read_file already logged the cause. Done BEFORE the zero-entry check so an
     * absent file is never mistaken for a deliberately empty list.
     */
    if (ngx_http_heavybag_read_file(cf, path, &content) != NGX_OK) {
        return NGX_ERROR;
    }

    total = 0;
    p = content.data;
    end = p + content.len;

    while (ngx_http_heavybag_next_line(&p, end, &ls, &le) == NGX_OK) {

        line.data = ls;
        line.len = le - ls;

        /*
         * ngx_http_heavybag_cidr_add lazily allocates *arr on the first push, so a
         * comments-only file leaves *arr NULL and the class is skipped. A line
         * with sloppy host bits warns but is still accepted (ngx_ptocidr returns
         * NGX_DONE inside cidr_add); only a genuinely unparseable line returns
         * NGX_ERROR, which we propagate to abort the reload.
         */
        if (ngx_http_heavybag_cidr_add(cf, arr, &line) != NGX_OK) {
            return NGX_ERROR;
        }
        total++;
    }

    if (*arr == NULL || (*arr)->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "heavybag: verified-bot list \"%V\" has no usable CIDR entries; "
            "the class will not be verified", path);
        return NGX_OK;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "heavybag: loaded %ui verified-bot CIDR(s) from \"%V\"", total, path);

    return NGX_OK;
}


void
ngx_http_heavybag_ua_classify(ngx_http_request_t *r, ngx_http_heavybag_loc_conf_t *wlcf,
    ngx_http_heavybag_ctx_t *ctx)
{
    ngx_str_t         ua;
    ngx_uint_t        i;
    ngx_table_elt_t  *h;

    ctx->classified = 1;

    h = r->headers_in.user_agent;

    if (h == NULL || h->value.len == 0) {
        ctx->ua = HEAVYBAG_UA_EMPTY;
        return;
    }

    ua = h->value;

    /* priority order is the enum order: SCANNER, AI_CRAWLER, CRAWLER, BOT */
    for (i = 0; i < HEAVYBAG_UA_LIST_MAX; i++) {

        if (wlcf->ua_re[i] == NULL) {
            continue;
        }

        if (ngx_http_heavybag_regex_exec(wlcf->ua_re[i], &ua) >= 0) {
            ctx->ua = (ngx_http_heavybag_ua_e) i;
            return;
        }
    }

    ctx->ua = HEAVYBAG_UA_REGULAR;
}
