/*
 * ngx_http_waf_module - geo / reputation database (libloc reader)
 *
 * See waf_geo.h. The radix-trie walk is taken 1:1 from nanolibloc (it is
 * the proven part); everything around it -- mmap lifetime, bounds checks,
 * context struct, flags parsing -- is rewritten for nginx.
 */

#include "waf_geo.h"

#include <sys/mman.h>


/* big-endian 32-bit read */
static ngx_inline uint32_t
ngx_http_waf_geo_u32(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}


static void
ngx_http_waf_geo_cleanup(void *data)
{
    ngx_http_waf_geo_db_t  *db = data;

    if (db->map != NULL && db->map != MAP_FAILED) {
        munmap(db->map, db->map_size);
        db->map = NULL;
    }
}


ngx_http_waf_geo_db_t *
ngx_http_waf_geo_open(ngx_conf_t *cf, ngx_str_t *path)
{
    u_char                  *base, *hdr, *p, *pend;
    size_t                   size;
    uint32_t                 off, len, nxt;
    ngx_fd_t                 fd;
    ngx_str_t                full;
    ngx_uint_t               i;
    ngx_file_info_t          fi;
    ngx_pool_cleanup_t      *cln;
    ngx_http_waf_geo_db_t   *db;

    full = *path;

    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NULL;
    }

    fd = ngx_open_file(full.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &full);
        return NULL;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &full);
        ngx_close_file(fd);
        return NULL;
    }

    size = (size_t) ngx_file_size(&fi);

    if (size < 8 + 64) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" is too small", &full);
        ngx_close_file(fd);
        return NULL;
    }

    base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

    ngx_close_file(fd);

    if (base == MAP_FAILED) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "mmap(\"%V\", %uz) failed", &full, size);
        return NULL;
    }

    db = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_geo_db_t));
    if (db == NULL) {
        munmap(base, size);
        return NULL;
    }

    db->map = base;
    db->map_size = size;
    db->path = *path;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        munmap(base, size);
        return NULL;
    }
    cln->handler = ngx_http_waf_geo_cleanup;
    cln->data = db;

    /* Magic: "LOCD" "BXX\x01"  ==  4C4F4344 42585801 */
    if (ngx_http_waf_geo_u32(base) != 0x4C4F4344
        || ngx_http_waf_geo_u32(base + 4) != 0x42585801)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" has a bad magic", &full);
        return NULL;
    }

    hdr = base + 8;

    for (i = 0; i < NGX_HTTP_WAF_GEO_BLOCKS; i++) {
        off = ngx_http_waf_geo_u32(hdr + 20 + i * 8);
        len = ngx_http_waf_geo_u32(hdr + 24 + i * 8);

        if ((size_t) off + len > size) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "geo database \"%V\" block %ui out of bounds", &full, i);
            return NULL;
        }

        db->block[i] = base + off;
        db->block_len[i] = len;
    }

    /* Descend the v6 trie to the IPv4-mapped root (::ffff:0:0/96). */
    nxt = 0;
    for (i = 0; i < 96; i++) {
        if ((size_t) nxt * 12 >= db->block_len[NGX_HTTP_WAF_GEO_NT]) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "geo database \"%V\" truncated network tree", &full);
            return NULL;
        }
        nxt = ngx_http_waf_geo_u32(db->block[NGX_HTTP_WAF_GEO_NT]
                                   + 12 * nxt + (i < 80 ? 0 : 4));
    }
    db->ipv4root = nxt;

    /* 10-bit country-code index into the country table. */
    ngx_memset(db->cc_map, 0xFF, sizeof(db->cc_map));
    i = 0;
    p = db->block[NGX_HTTP_WAF_GEO_CO];
    pend = p + db->block_len[NGX_HTTP_WAF_GEO_CO];
    for (; p + 8 <= pend; p += 8) {
        ngx_uint_t  key = p[0] ^ ((p[1] & 31) << 5);
        db->cc_map[key] = (uint16_t) i++;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "waf: geo database \"%V\" loaded (%uz bytes, %ui networks)",
        &full, size, db->block_len[NGX_HTTP_WAF_GEO_ND] / 12);

    return db;
}


/* address -> network leaf index, or -1. IPv6 / generic bit walk. */
static ngx_int_t
ngx_http_waf_geo_walk(ngx_http_waf_geo_db_t *db, const u_char *addr,
    ngx_uint_t addrlen, uint32_t nxt)
{
    u_char     *nt = db->block[NGX_HTTP_WAF_GEO_NT];
    uint32_t    ntlen = db->block_len[NGX_HTTP_WAF_GEO_NT];
    uint32_t    net;
    ngx_int_t   ret = -1;
    ngx_uint_t  mask = 0;
    ngx_uint_t  bit;

    do {
        nxt *= 12;
        if (nxt >= ntlen) {
            return -1;
        }

        net = ngx_http_waf_geo_u32(nt + nxt + 8);
        if (!(net & 0x80000000)) {
            ret = (ngx_int_t) net;
        }

        if (mask >> 3 >= addrlen) {
            break;
        }

        bit = (addr[mask >> 3] >> (7 - (mask & 7))) & 1;
        mask++;
        nxt = ngx_http_waf_geo_u32(nt + nxt + bit * 4);

    } while (nxt);

    return ret;
}


void
ngx_http_waf_geo_lookup(ngx_http_waf_geo_db_t *db, struct sockaddr *sa,
    ngx_http_waf_geo_result_t *res)
{
    u_char               *p;
    ngx_int_t             net;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    res->found = 0;

    if (db == NULL || sa == NULL) {
        return;
    }

    switch (sa->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        net = ngx_http_waf_geo_walk(db, (u_char *) &sin->sin_addr.s_addr, 4,
                                    db->ipv4root);
        break;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;

        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            net = ngx_http_waf_geo_walk(db, sin6->sin6_addr.s6_addr + 12, 4,
                                        db->ipv4root);
        } else {
            net = ngx_http_waf_geo_walk(db, sin6->sin6_addr.s6_addr, 16, 0);
        }
        break;

    default:
        return;
    }

    if (net < 0
        || (uint32_t) net * 12 + 12 > db->block_len[NGX_HTTP_WAF_GEO_ND])
    {
        return;
    }

    /*
     * 12-byte network leaf (libloc database format v1):
     *   [0,2)  country code        [2,4)  reserved
     *   [4,8)  ASN (uint32 BE)     [8,10) flags (uint16 BE)
     *   [10,12) reserved
     * nanolibloc reads cc and asn but skips flags; the flags are at
     * offset 8, NOT right after the country code.
     */
    p = db->block[NGX_HTTP_WAF_GEO_ND] + (uint32_t) net * 12;

    res->country[0] = p[0];
    res->country[1] = p[1];
    res->asn = ngx_http_waf_geo_u32(p + 4);
    res->flags = (uint16_t) ((p[8] << 8) | p[9]);
    res->found = 1;
}
