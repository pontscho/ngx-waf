/*
 * ngx_http_waf_module - geo / reputation database (libloc reader)
 *
 * Adapted from arpi's nanolibloc.c (gereoffy/ipstat46) as a starting
 * point, rewritten for nginx:
 *   - no global state: everything lives in ngx_http_waf_geo_db_t;
 *   - the IPFire "location.db" is mmap'd read-only (shared across workers
 *     by fork copy-on-write, never dirtied) instead of malloc+read;
 *   - the per-network flags field (anonymous proxy / satellite / anycast /
 *     drop) is parsed -- nanolibloc skips it;
 *   - the mmap is released by an ngx_pool_cleanup_t bound to the
 *     configuration cycle pool, so a reload re-maps and frees cleanly.
 *
 * The on-disk format is big-endian. Five blocks: AS numbers, network
 * data (leaves), network tree (radix trie), countries, and a string pool.
 */

#ifndef _WAF_GEO_H_INCLUDED_
#define _WAF_GEO_H_INCLUDED_


#include "ngx_http_waf.h"


#define NGX_HTTP_WAF_GEO_AS   0     /* AS number table   */
#define NGX_HTTP_WAF_GEO_ND   1     /* network leaf data */
#define NGX_HTTP_WAF_GEO_NT   2     /* network tree      */
#define NGX_HTTP_WAF_GEO_CO   3     /* country table     */
#define NGX_HTTP_WAF_GEO_PO   4     /* string pool       */
#define NGX_HTTP_WAF_GEO_BLOCKS 5

/* libloc per-network flags (uint16, big-endian, at ND entry offset 8) */
#define NGX_HTTP_WAF_GEO_FLAG_ANON_PROXY  0x0001
#define NGX_HTTP_WAF_GEO_FLAG_SATELLITE   0x0002
#define NGX_HTTP_WAF_GEO_FLAG_ANYCAST     0x0004
#define NGX_HTTP_WAF_GEO_FLAG_DROP        0x0008


typedef struct ngx_http_waf_geo_db_s {
    u_char      *map;                            /* mmap base address  */
    size_t       map_size;                       /* mmap length        */

    u_char      *block[NGX_HTTP_WAF_GEO_BLOCKS]; /* pointers into map  */
    uint32_t     block_len[NGX_HTTP_WAF_GEO_BLOCKS];

    uint32_t     ipv4root;                       /* IPv4 trie root node*/
    uint16_t     cc_map[32 * 32];                /* 10-bit CC index    */

    ngx_str_t    path;
} ngx_http_waf_geo_db_t;


typedef struct {
    ngx_uint_t   found;          /* 1 if a network matched the address */
    u_char       country[2];     /* ISO-2, or special A1/A2/A3/T1/XD   */
    uint16_t     flags;          /* NGX_HTTP_WAF_GEO_FLAG_*            */
    uint32_t     asn;
} ngx_http_waf_geo_result_t;


/*
 * mmap and validate the database at *path (config-time). The mapping is
 * released through a cleanup handler on cf->pool. Returns NULL on error
 * (already logged).
 */
ngx_http_waf_geo_db_t *ngx_http_waf_geo_open(ngx_conf_t *cf, ngx_str_t *path);

/* Look up an address (AF_INET / AF_INET6). Fills res (res->found=0 if none). */
void ngx_http_waf_geo_lookup(ngx_http_waf_geo_db_t *db, struct sockaddr *sa,
    ngx_http_waf_geo_result_t *res);


#endif /* _WAF_GEO_H_INCLUDED_ */
