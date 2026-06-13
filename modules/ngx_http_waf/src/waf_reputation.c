/*
 * ngx_http_waf_module - shared reputation core
 *
 * See waf_reputation.h. Special IPFire country codes (A1 anonymous proxy,
 * A2 satellite, A3 anycast, T1 Tor exit, XD drop) are blocked through the
 * same packed-CC list as ISO countries; the libloc uint16 network-flags
 * field is matched separately via flag_mask. Either signal denies.
 */

#include "waf_reputation.h"
#include "waf_geo.h"


ngx_int_t
ngx_http_waf_reputation_check(ngx_http_waf_loc_conf_t *wlcf,
    struct sockaddr *sa, ngx_str_t *reason)
{
    uint16_t                    cc16, *codes;
    ngx_uint_t                  i;
    ngx_http_waf_geo_result_t   res;

    if (sa == NULL) {
        return NGX_DECLINED;
    }

    /* 1. allowlist short-circuits to allow */
    if (wlcf->allowlist
        && ngx_cidr_match(sa, wlcf->allowlist) == NGX_OK)
    {
        return NGX_DECLINED;
    }

    /* 2. static blocklist */
    if (wlcf->blocklist
        && ngx_cidr_match(sa, wlcf->blocklist) == NGX_OK)
    {
        ngx_str_set(reason, "static blocklist");
        return NGX_HTTP_FORBIDDEN;
    }

    /* 3. geo / network-flag reputation */
    if (wlcf->geo_db == NULL) {
        return NGX_DECLINED;
    }

    ngx_http_waf_geo_lookup(wlcf->geo_db, sa, &res);

    if (!res.found) {
        return NGX_DECLINED;
    }

    if (wlcf->flag_mask && (res.flags & wlcf->flag_mask)) {
        ngx_str_set(reason, "network flag");
        return NGX_HTTP_FORBIDDEN;
    }

    if (wlcf->block_cc) {
        cc16 = (uint16_t) ((res.country[0] << 8) | res.country[1]);
        codes = wlcf->block_cc->elts;

        for (i = 0; i < wlcf->block_cc->nelts; i++) {
            if (codes[i] == cc16) {
                ngx_str_set(reason, "geo country");
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_waf_cidr_add(ngx_conf_t *cf, ngx_array_t **arr, ngx_str_t *text)
{
    ngx_int_t    rc;
    ngx_cidr_t  *cidr;

    if (*arr == NULL) {
        *arr = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (*arr == NULL) {
            return NGX_ERROR;
        }
    }

    cidr = ngx_array_push(*arr);
    if (cidr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_ptocidr(text, cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid network address \"%V\"", text);
        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of \"%V\" are meaningless", text);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_country_add(ngx_conf_t *cf, ngx_array_t **arr, ngx_str_t *cc)
{
    uint16_t  *code;
    u_char     c0, c1;

    if (cc->len != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "country code \"%V\" must be two letters", cc);
        return NGX_ERROR;
    }

    if (*arr == NULL) {
        *arr = ngx_array_create(cf->pool, 8, sizeof(uint16_t));
        if (*arr == NULL) {
            return NGX_ERROR;
        }
    }

    code = ngx_array_push(*arr);
    if (code == NULL) {
        return NGX_ERROR;
    }

    /* libloc stores codes uppercase */
    c0 = ngx_toupper(cc->data[0]);
    c1 = ngx_toupper(cc->data[1]);

    *code = (uint16_t) ((c0 << 8) | c1);

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_flag_add(ngx_conf_t *cf, ngx_http_waf_loc_conf_t *wlcf,
    ngx_str_t *tok)
{
    uint16_t   flag;
    ngx_str_t  cc;

    flag = 0;
    ngx_str_null(&cc);

    if ((tok->len == 15 && ngx_strncmp(tok->data, "anonymous-proxy", 15) == 0)
        || (tok->len == 4 && ngx_strncmp(tok->data, "anon", 4) == 0))
    {
        flag = NGX_HTTP_WAF_GEO_FLAG_ANON_PROXY;
        ngx_str_set(&cc, "A1");

    } else if (tok->len == 9 && ngx_strncmp(tok->data, "satellite", 9) == 0) {
        flag = NGX_HTTP_WAF_GEO_FLAG_SATELLITE;
        ngx_str_set(&cc, "A2");

    } else if (tok->len == 7 && ngx_strncmp(tok->data, "anycast", 7) == 0) {
        flag = NGX_HTTP_WAF_GEO_FLAG_ANYCAST;
        ngx_str_set(&cc, "A3");

    } else if (tok->len == 4 && ngx_strncmp(tok->data, "drop", 4) == 0) {
        flag = NGX_HTTP_WAF_GEO_FLAG_DROP;
        ngx_str_set(&cc, "XD");

    } else if (tok->len == 3 && ngx_strncmp(tok->data, "tor", 3) == 0) {
        /* Tor exits carry the special country code T1; no flag bit */
        ngx_str_set(&cc, "T1");

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "unknown waf_flag_block value \"%V\" (expected one of: "
            "anonymous-proxy, satellite, anycast, tor, drop)", tok);
        return NGX_ERROR;
    }

    wlcf->flag_mask |= flag;

    if (cc.len) {
        if (ngx_http_waf_country_add(cf, &wlcf->block_cc, &cc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
