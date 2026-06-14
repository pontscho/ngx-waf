/*
 * ngx_http_waf_module - shared reputation core
 *
 * See waf_reputation.h. The special IPFire source codes from waf_flag_block
 * (A1 anonymous proxy, A2 satellite, A3 anycast, T1 Tor exit, XD drop) deny
 * in BOTH block and whitelist modes: via the libloc uint16 network-flags
 * field (flag_mask) and, for codes that carry no flag bit such as Tor's T1,
 * via the separate flag_cc packed-CC list. The plain ISO block_cc/allow_cc
 * lists are the mutually exclusive country policy. Any signal denies.
 */

#include "waf_reputation.h"
#include "waf_geo.h"


ngx_int_t
ngx_http_waf_reputation_check(ngx_waf_rep_conf_t *rep,
    struct sockaddr *sa, ngx_str_t *reason, ngx_http_waf_verdict_t *out)
{
    uint16_t                    cc16, *codes;
    uint32_t                   *asns;
    ngx_uint_t                  i;
    ngx_http_waf_geo_result_t   res;

    /*
     * Fully define the write-only verdict up front so callers never read an
     * uninitialised field: reason defaults to NONE, no geo lookup ran, no
     * country. Each return below only overrides reason; the geo branch fills
     * country/flags/geo_valid. Every write stays NULL-guarded (SMTP passes
     * NULL). The control flow / verdict is byte-identical to before.
     */
    if (out != NULL) {
        out->reason = WAF_REASON_NONE;
        out->country[0] = 0;
        out->country[1] = 0;
        out->flags = 0;
        out->asn = 0;
        out->geo_valid = 0;
    }

    if (sa == NULL) {
        return NGX_DECLINED;
    }

    /* 1. allowlist short-circuits to allow */
    if (rep->allowlist
        && ngx_cidr_match(sa, rep->allowlist) == NGX_OK)
    {
        if (out != NULL) {
            out->reason = WAF_REASON_ALLOWLIST;
        }
        return NGX_DECLINED;
    }

    /* 2. static blocklist */
    if (rep->blocklist
        && ngx_cidr_match(sa, rep->blocklist) == NGX_OK)
    {
        ngx_str_set(reason, "static blocklist");
        if (out != NULL) {
            out->reason = WAF_REASON_BLOCKLIST;
        }
        return NGX_HTTP_FORBIDDEN;
    }

    /* 3. geo / network-flag reputation */
    if (rep->geo_db == NULL) {
        return NGX_DECLINED;
    }

    ngx_http_waf_geo_lookup(rep->geo_db, sa, &res);

    /*
     * A geo lookup ran: publish the primitive geo fields to the caller's
     * verdict (write-only, never consulted for the decision below). On a
     * miss res.country/flags are undefined, so only copy them when found;
     * geo_valid still records that the lookup happened.
     */
    if (out != NULL) {
        out->geo_valid = 1;
        if (res.found) {
            out->country[0] = res.country[0];
            out->country[1] = res.country[1];
            out->flags = res.flags;
            out->asn = res.asn;
        }
    }

    if (!res.found) {
        /*
         * No geo record. In whitelist mode the country cannot be proven to
         * be on the allow list, so the resource is hidden (404); otherwise
         * an unknown IP is allowed through.
         */
        if (rep->allow_cc) {
            ngx_str_set(reason, "geo not whitelisted");
            if (out != NULL) {
                out->reason = WAF_REASON_GEO_WHITELIST;
            }
            return NGX_HTTP_NOT_FOUND;
        }
        return NGX_DECLINED;
    }

    /* network-flag blocks apply first, in both block and whitelist modes */
    if (rep->flag_mask && (res.flags & rep->flag_mask)) {
        ngx_str_set(reason, "network flag");
        if (out != NULL) {
            out->reason = WAF_REASON_FLAG;
        }
        return NGX_HTTP_FORBIDDEN;
    }

    /*
     * ASN block: an explicit deny list of autonomous systems, applied in
     * both block and whitelist modes (like the network-flag block above).
     * asn==0 (unknown / no record) fails open.
     */
    if (rep->block_asn && res.asn != 0) {
        asns = rep->block_asn->elts;

        for (i = 0; i < rep->block_asn->nelts; i++) {
            if (asns[i] == res.asn) {
                ngx_str_set(reason, "asn");
                if (out != NULL) {
                    out->reason = WAF_REASON_ASN;
                }
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    cc16 = (uint16_t) ((res.country[0] << 8) | res.country[1]);

    /*
     * Special source codes from waf_flag_block (A1/A2/A3/T1/XD) deny in both
     * modes, like flag_mask above: they mark the source itself (Tor / anon /
     * satellite / drop), independent of the country allow/deny policy. Tor
     * carries the T1 code but no flag bit, so flag_mask alone would miss it.
     */
    if (rep->flag_cc) {
        codes = rep->flag_cc->elts;

        for (i = 0; i < rep->flag_cc->nelts; i++) {
            if (codes[i] == cc16) {
                ngx_str_set(reason, "network flag");
                if (out != NULL) {
                    out->reason = WAF_REASON_FLAG;
                }
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    /*
     * Whitelist mode wins when set: the country must be listed or the
     * request is hidden (404). block_cc is not consulted in this mode.
     */
    if (rep->allow_cc) {
        codes = rep->allow_cc->elts;

        for (i = 0; i < rep->allow_cc->nelts; i++) {
            if (codes[i] == cc16) {
                return NGX_DECLINED;
            }
        }

        ngx_str_set(reason, "geo not whitelisted");
        if (out != NULL) {
            out->reason = WAF_REASON_GEO_WHITELIST;
        }
        return NGX_HTTP_NOT_FOUND;
    }

    if (rep->block_cc) {
        codes = rep->block_cc->elts;

        for (i = 0; i < rep->block_cc->nelts; i++) {
            if (codes[i] == cc16) {
                ngx_str_set(reason, "geo country");
                if (out != NULL) {
                    out->reason = WAF_REASON_GEO;
                }
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
ngx_http_waf_asn_add(ngx_conf_t *cf, ngx_array_t **arr, ngx_str_t *val)
{
    ngx_int_t   n;
    uint32_t   *asn;

    n = ngx_atoi(val->data, val->len);

    /* 4-byte ASN range 1..4294967295; 0 is reserved and fails open anyway */
    if (n == NGX_ERROR || n <= 0 || (uint64_t) n > 0xffffffffULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf_asn_block value \"%V\" is not a valid ASN "
                           "(expected a decimal number 1..4294967295)", val);
        return NGX_ERROR;
    }

    if (*arr == NULL) {
        *arr = ngx_array_create(cf->pool, 8, sizeof(uint32_t));
        if (*arr == NULL) {
            return NGX_ERROR;
        }
    }

    asn = ngx_array_push(*arr);
    if (asn == NULL) {
        return NGX_ERROR;
    }

    *asn = (uint32_t) n;

    return NGX_OK;
}


ngx_int_t
ngx_http_waf_flag_add(ngx_conf_t *cf, ngx_waf_rep_conf_t *rep,
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

    rep->flag_mask |= flag;

    if (cc.len) {
        if (ngx_http_waf_country_add(cf, &rep->flag_cc, &cc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
