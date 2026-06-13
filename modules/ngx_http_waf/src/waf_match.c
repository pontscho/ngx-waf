/*
 * ngx_http_waf_module - path scanner matching and bot heuristics
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

#include "waf_match.h"


/* Action bucket -> nginx finalize code. Indexed by ngx_http_waf_action_e. */
static ngx_uint_t  waf_action_code[WAF_ACTION_MAX] = {
    NGX_HTTP_NOT_FOUND,    /* WAF_ACTION_404 */
    NGX_HTTP_FORBIDDEN,    /* WAF_ACTION_403 */
    NGX_HTTP_CLOSE         /* WAF_ACTION_444 */
};


/*
 * Known offensive scanner User-Agent signatures, lowercase. Matched
 * case-insensitively as substrings. Deliberately narrow: only tools whose
 * UA is unambiguously a scanner, never a legitimate client or crawler.
 */
static ngx_str_t  waf_bot_sigs[] = {
    ngx_string("sqlmap"),
    ngx_string("nikto"),
    ngx_string("nmap"),
    ngx_string("masscan"),
    ngx_string("zgrab"),
    ngx_string("nuclei"),
    ngx_string("dirbuster"),
    ngx_string("gobuster"),
    ngx_string("wpscan"),
    ngx_string("acunetix"),
    ngx_string("nessus"),
    ngx_string("netsparker"),
    ngx_string("fimap"),
    ngx_string("hydra"),
    ngx_string("arachni"),
    ngx_string("dirsearch"),
    ngx_null_string
};


static ngx_int_t ngx_http_waf_read_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_str_t *out);
static ngx_int_t ngx_http_waf_compile_bucket(ngx_conf_t *cf,
    ngx_array_t *patterns, ngx_regex_t **out);


static ngx_int_t
ngx_http_waf_read_file(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *out)
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
                           "failed to read scanner list \"%V\"", &full);
        return NGX_ERROR;
    }

    out->data = buf;
    out->len = size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_compile_bucket(ngx_conf_t *cf, ngx_array_t *patterns,
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
ngx_http_waf_scanner_compile(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_str_t *path)
{
    u_char       *p, *end, *ls, *le, *ps, *pe, *as;
    ngx_str_t     content, *pat, action;
    ngx_uint_t    i, bucket, total;
    ngx_array_t  *buckets[WAF_ACTION_MAX];

    if (ngx_http_waf_read_file(cf, path, &content) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < WAF_ACTION_MAX; i++) {
        buckets[i] = ngx_array_create(cf->temp_pool, 32, sizeof(ngx_str_t));
        if (buckets[i] == NULL) {
            return NGX_ERROR;
        }
    }

    total = 0;
    p = content.data;
    end = p + content.len;

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

        bucket = WAF_ACTION_404;

        if (as < le) {
            action.data = as;
            action.len = le - as;

            if (action.len == 3 && ngx_strncmp(action.data, "403", 3) == 0) {
                bucket = WAF_ACTION_403;

            } else if (action.len == 3
                       && ngx_strncmp(action.data, "444", 3) == 0)
            {
                bucket = WAF_ACTION_444;

            } else if (action.len == 3
                       && ngx_strncmp(action.data, "404", 3) == 0)
            {
                bucket = WAF_ACTION_404;

            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "waf: unknown action \"%V\" in scanner list, using 404",
                    &action);
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

    for (i = 0; i < WAF_ACTION_MAX; i++) {
        if (ngx_http_waf_compile_bucket(cf, buckets[i], &wlcf->scanner_re[i])
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    wlcf->scanner_list = *path;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "waf: loaded %ui scanner pattern(s) from \"%V\"", total, path);

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_scanner_lookup(ngx_http_waf_loc_conf_t *wlcf, ngx_str_t *uri)
{
    ngx_uint_t  i;

    for (i = 0; i < WAF_ACTION_MAX; i++) {

        if (wlcf->scanner_re[i] == NULL) {
            continue;
        }

        if (ngx_regex_exec(wlcf->scanner_re[i], uri, NULL, 0) >= 0) {
            return (ngx_int_t) waf_action_code[i];
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_waf_bot_match(ngx_http_request_t *r)
{
    u_char       *last;
    ngx_str_t     ua;
    ngx_uint_t    i;
    ngx_table_elt_t  *h;

    h = r->headers_in.user_agent;

    if (h == NULL || h->value.len == 0) {
        /* empty / missing User-Agent: replaces the old `if ($http_user_agent="")` */
        return 1;
    }

    ua = h->value;
    last = ua.data + ua.len;

    for (i = 0; waf_bot_sigs[i].len; i++) {
        if (ngx_strlcasestrn(ua.data, last, waf_bot_sigs[i].data,
                             waf_bot_sigs[i].len - 1)
            != NULL)
        {
            return 1;
        }
    }

    return 0;
}
