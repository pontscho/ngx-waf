/*
 * ngx_http_heavybag_module - geo / reputation database (libloc reader)
 *
 * See heavybag_geo.h. The radix-trie walk is taken 1:1 from nanolibloc (it is
 * the proven part); everything around it -- mmap lifetime, bounds checks,
 * context struct, flags parsing -- is rewritten for nginx.
 */

#include "heavybag_geo.h"

#include <sys/mman.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>


/*
 * libloc signed-header layout (libloc 0.9.18, byte-exact). ONE coordinate
 * frame: the live mmap is read file-absolute as base+N; the stack header COPY
 * is indexed copy-local 0..4192, where copy-local N maps to file-absolute
 * base + 8 + N. The two buffers (mmap base vs stack copy) are never conflated.
 */
#define NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE   4192   /* on-disk header size after magic  */
#define NGX_HTTP_HEAVYBAG_GEO_DATA_OFF   (8 + NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE)  /* 4200    */
#define NGX_HTTP_HEAVYBAG_GEO_SIG_MAX    2048   /* per-slot signature blob capacity */
#define NGX_HTTP_HEAVYBAG_GEO_ZERO_BEG   60     /* copy-local: first u16 length     */
#define NGX_HTTP_HEAVYBAG_GEO_ZERO_END   4160   /* copy-local: end of sig2 blob     */
/* file-absolute signature offsets (base + 8 + copy-local): */
#define NGX_HTTP_HEAVYBAG_GEO_SIG1_LEN   (8 + 60)    /* 68   */
#define NGX_HTTP_HEAVYBAG_GEO_SIG2_LEN   (8 + 62)    /* 70   */
#define NGX_HTTP_HEAVYBAG_GEO_SIG1_OFF   (8 + 64)    /* 72   */
#define NGX_HTTP_HEAVYBAG_GEO_SIG2_OFF   (8 + 2112)  /* 2120 */

/*
 * Maximum accepted DB size. The real geodb/location.db measured 63,517,012
 * bytes (about 60.6 MiB) on 2026-06-12; this 512 MiB cap is roughly 8.5x that,
 * so an organically growing DB stays well under it, while a runaway or hostile
 * oversized file cannot stall a reload by being SHA-512'd first.
 */
#define NGX_HTTP_HEAVYBAG_GEO_MAX_SIZE   (512UL * 1024 * 1024)

/*
 * Pinned IPFire location database signing key (ECDSA P-521 / secp521r1,
 * created 2019-12-10 by Michael Tremer; stable since). Cross-sourced
 * byte-identical from git.ipfire.org and sources.debian.org; embedded PEM
 * block SHA-256:
 *   7d927e19042d9cf12ef4644d2d4fd3095e26e9b5815ebd9e82d973219497430e
 * A key rotation (multi-year horizon) requires rebuilding this module. The
 * key is a NUL-terminated string literal, loaded via BIO_new_mem_buf(key,-1).
 */
static const char  ngx_http_heavybag_geo_signing_key[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB1PzZdV9DE59LVCdXy/9cRgvTy9lx\n"
"L5tV10awZDilwQ9GR8x/irJE8ctGSnZ5HgbOk+gilurmC5JlJmTjZrW7tt8Awiu8\n"
"ir3y2n7XXyiVGIzTHrA6Tw7SG+H9LzuIl0wCg6s6svnXVDyho7b0tSZPUGKMI28q\n"
"CUXef0jvZ9+ncTiJh1w=\n"
"-----END PUBLIC KEY-----\n";


/* big-endian 32-bit read */
static ngx_inline uint32_t
ngx_http_heavybag_geo_u32(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}


static void
ngx_http_heavybag_geo_cleanup(void *data)
{
    ngx_http_heavybag_geo_db_t  *db = data;

    if (db->map != NULL && db->map != MAP_FAILED) {
        munmap(db->map, db->map_size);
        db->map = NULL;
    }
}


/*
 * Dedicated big-endian 16-bit read. MUST NOT reuse the 32-bit reader, which
 * would swallow the adjacent length field (sig1_len and sig2_len are packed
 * back-to-back).
 */
static ngx_inline uint16_t
ngx_http_heavybag_geo_u16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}


/*
 * Verify the database's embedded ECDSA P-521 / SHA-512 signature against the
 * pinned IPFire public key -- libloc loc_database_verify() reproduced with
 * OpenSSL (libcrypto is already linked, see heavybag_ja4.c; no libloc dependency).
 *
 * Mandatory and fail-closed: an unsigned (both slots absent), tampered, or
 * corrupted DB, or ANY OpenSSL error, returns NGX_ERROR. The hashed message
 * is magic(8) ++ header(4192, copy-local bytes [60,4160) zeroed) ++ the rest
 * of the file (base + DATA_OFF .. EOF). Dual signature for key rotation:
 * verify sig1, then sig2; accept if EITHER yields EVP_DigestVerifyFinal == 1
 * (neither signature is forgeable without the private key, so EITHER-valid is
 * rotation tolerance, not a weakness).
 *
 * The caller guarantees size >= NGX_HTTP_HEAVYBAG_GEO_DATA_OFF (pre-mmap guard).
 */
static ngx_int_t
ngx_http_heavybag_geo_verify(ngx_conf_t *cf, ngx_str_t *full,
    const u_char *base, size_t size)
{
    BIO            *bio = NULL;
    EVP_PKEY       *pkey = NULL;
    EVP_MD_CTX     *bctx = NULL;
    EVP_MD_CTX     *snap = NULL;
    ngx_int_t       rc = NGX_ERROR;
    int             valid = 0;
    ngx_uint_t      sig1_len, sig2_len, have1, have2;
    unsigned long   e;
    u_char          hdr[NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE];
    char            errbuf[256];

    sig1_len = ngx_http_heavybag_geo_u16(base + NGX_HTTP_HEAVYBAG_GEO_SIG1_LEN);
    sig2_len = ngx_http_heavybag_geo_u16(base + NGX_HTTP_HEAVYBAG_GEO_SIG2_LEN);

    /* a slot is present iff 1 <= len <= SIG_MAX; never Final an empty slot */
    have1 = (sig1_len >= 1 && sig1_len <= NGX_HTTP_HEAVYBAG_GEO_SIG_MAX);
    have2 = (sig2_len >= 1 && sig2_len <= NGX_HTTP_HEAVYBAG_GEO_SIG_MAX);

    if (!have1 && !have2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" is not signed", full);
        return NGX_ERROR;
    }

    /*
     * Drain any stale OpenSSL error left by earlier config-parse work, so the
     * error reported on a reject is guaranteed to be from this verification.
     */
    ERR_clear_error();

    bio = BIO_new_mem_buf(ngx_http_heavybag_geo_signing_key, -1);
    if (bio == NULL) {
        goto failed;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        goto failed;
    }

    bctx = EVP_MD_CTX_new();
    if (bctx == NULL) {
        goto failed;
    }

    /* NULL digest: OpenSSL selects SHA-512 for a P-521 key, matching libloc */
    if (EVP_DigestVerifyInit(bctx, NULL, NULL, NULL, pkey) != 1) {
        goto failed;
    }

    /*
     * Header copy: zero copy-local [60,4160) -- both u16 length fields and
     * both signature blobs -- leaving padding [4160,4192) intact, exactly as
     * libloc hashes it.
     */
    ngx_memcpy(hdr, base + 8, NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE);
    ngx_memzero(hdr + NGX_HTTP_HEAVYBAG_GEO_ZERO_BEG,
                NGX_HTTP_HEAVYBAG_GEO_ZERO_END - NGX_HTTP_HEAVYBAG_GEO_ZERO_BEG);

    if (EVP_DigestVerifyUpdate(bctx, base, 8) != 1
        || EVP_DigestVerifyUpdate(bctx, hdr, NGX_HTTP_HEAVYBAG_GEO_HDR_SIZE) != 1
        || EVP_DigestVerifyUpdate(bctx, base + NGX_HTTP_HEAVYBAG_GEO_DATA_OFF,
                                  size - NGX_HTTP_HEAVYBAG_GEO_DATA_OFF) != 1)
    {
        goto failed;
    }

    /*
     * Exactly one live snapshot at a time: copy the un-finalized base ctx,
     * Final, then free-and-NULL before testing the next slot. copy_ex is
     * always from bctx (never from an already-finalized snapshot), so the
     * epilogue cannot double-free. valid is set ONLY on an exact == 1
     * (0 = bad signature, <0 = error -- both must reject).
     */
    if (have1) {
        snap = EVP_MD_CTX_new();
        if (snap == NULL || EVP_MD_CTX_copy_ex(snap, bctx) != 1) {
            goto failed;
        }
        if (EVP_DigestVerifyFinal(snap, base + NGX_HTTP_HEAVYBAG_GEO_SIG1_OFF,
                                  sig1_len) == 1)
        {
            valid = 1;
        }
        EVP_MD_CTX_free(snap);
        snap = NULL;
    }

    if (!valid && have2) {
        snap = EVP_MD_CTX_new();
        if (snap == NULL || EVP_MD_CTX_copy_ex(snap, bctx) != 1) {
            goto failed;
        }
        if (EVP_DigestVerifyFinal(snap, base + NGX_HTTP_HEAVYBAG_GEO_SIG2_OFF,
                                  sig2_len) == 1)
        {
            valid = 1;
        }
        EVP_MD_CTX_free(snap);
        snap = NULL;
    }

    if (valid) {
        rc = NGX_OK;
        goto cleanup;
    }

failed:

    e = ERR_get_error();
    if (e != 0) {
        ERR_error_string_n(e, errbuf, sizeof(errbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" signature verification failed: %s",
            full, errbuf);
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "geo database \"%V\" signature verification failed", full);
    }

cleanup:

    if (snap != NULL) {
        EVP_MD_CTX_free(snap);
    }
    if (bctx != NULL) {
        EVP_MD_CTX_free(bctx);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }

    return rc;
}


ngx_http_heavybag_geo_db_t *
ngx_http_heavybag_geo_open(ngx_conf_t *cf, ngx_str_t *path)
{
    u_char                  *base, *hdr;
    size_t                   size;
    uint32_t                 off, len, nxt;
    ngx_fd_t                 fd;
    ngx_str_t                full;
    ngx_uint_t               i;
    ngx_file_info_t          fi;
    ngx_pool_cleanup_t      *cln;
    ngx_http_heavybag_geo_db_t   *db;

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

    /*
     * Strict: the signed header plus its trailing data offset is 4200 bytes,
     * so the verify pass can read magic ++ header ++ rest without underflow
     * (size is unsigned; size - DATA_OFF must not wrap). Reject before mmap.
     */
    if (size < NGX_HTTP_HEAVYBAG_GEO_DATA_OFF) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" is too small", &full);
        ngx_close_file(fd);
        return NULL;
    }

    /* cap before mmap so a giant file cannot stall a reload by hashing first */
    if (size > NGX_HTTP_HEAVYBAG_GEO_MAX_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" is too large (%uz bytes)",
                           &full, size);
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

    db = ngx_pcalloc(cf->pool, sizeof(ngx_http_heavybag_geo_db_t));
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
    cln->handler = ngx_http_heavybag_geo_cleanup;
    cln->data = db;

    /* Magic: "LOCD" "BXX\x01"  ==  4C4F4344 42585801 */
    if (ngx_http_heavybag_geo_u32(base) != 0x4C4F4344
        || ngx_http_heavybag_geo_u32(base + 4) != 0x42585801)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "geo database \"%V\" has a bad magic", &full);
        return NULL;
    }

    /*
     * Cryptographic gate, before any block offset is trusted: verify reads
     * the file linearly (magic ++ header ++ rest) and the pre-mmap guard
     * already ensures size >= DATA_OFF, so this is the correct first check.
     * On failure the pool cleanup (registered above) munmaps the mapping.
     */
    if (ngx_http_heavybag_geo_verify(cf, &full, base, size) != NGX_OK) {
        return NULL;
    }

    hdr = base + 8;

    for (i = 0; i < NGX_HTTP_HEAVYBAG_GEO_BLOCKS; i++) {
        off = ngx_http_heavybag_geo_u32(hdr + 20 + i * 8);
        len = ngx_http_heavybag_geo_u32(hdr + 24 + i * 8);

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
        size_t  off = (size_t) nxt * 12;

        if (off + 12 > db->block_len[NGX_HTTP_HEAVYBAG_GEO_NT]) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "geo database \"%V\" truncated network tree", &full);
            return NULL;
        }
        nxt = ngx_http_heavybag_geo_u32(db->block[NGX_HTTP_HEAVYBAG_GEO_NT]
                                   + off + (i < 80 ? 0 : 4));
    }
    db->ipv4root = nxt;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "heavybag: geo database \"%V\" loaded (%uz bytes, %ui networks)",
        &full, size, db->block_len[NGX_HTTP_HEAVYBAG_GEO_ND] / 12);

    return db;
}


/* address -> network leaf index, or -1. IPv6 / generic bit walk. */
static ngx_int_t
ngx_http_heavybag_geo_walk(ngx_http_heavybag_geo_db_t *db, const u_char *addr,
    ngx_uint_t addrlen, uint32_t nxt)
{
    u_char     *nt = db->block[NGX_HTTP_HEAVYBAG_GEO_NT];
    uint32_t    ntlen = db->block_len[NGX_HTTP_HEAVYBAG_GEO_NT];
    uint32_t    net;
    ngx_int_t   ret = -1;
    ngx_uint_t  mask = 0;
    ngx_uint_t  bit;
    size_t      off;

    do {
        /*
         * Offset in size_t so the index cannot wrap (nxt is an untrusted
         * 32-bit value from the DB), and require the whole 12-byte node to
         * fit -- guarding only its first byte over-reads a trailing node.
         */
        off = (size_t) nxt * 12;
        if (off + 12 > ntlen) {
            return -1;
        }

        net = ngx_http_heavybag_geo_u32(nt + off + 8);
        if (!(net & 0x80000000)) {
            ret = (ngx_int_t) net;
        }

        if (mask >> 3 >= addrlen) {
            break;
        }

        bit = (addr[mask >> 3] >> (7 - (mask & 7))) & 1;
        mask++;
        nxt = ngx_http_heavybag_geo_u32(nt + off + bit * 4);

    } while (nxt);

    return ret;
}


void
ngx_http_heavybag_geo_lookup(ngx_http_heavybag_geo_db_t *db, struct sockaddr *sa,
    ngx_http_heavybag_geo_result_t *res)
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
        net = ngx_http_heavybag_geo_walk(db, (u_char *) &sin->sin_addr.s_addr, 4,
                                    db->ipv4root);
        break;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;

        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            net = ngx_http_heavybag_geo_walk(db, sin6->sin6_addr.s6_addr + 12, 4,
                                        db->ipv4root);
        } else {
            net = ngx_http_heavybag_geo_walk(db, sin6->sin6_addr.s6_addr, 16, 0);
        }
        break;

    default:
        return;
    }

    if (net < 0
        || (size_t) net * 12 + 12 > db->block_len[NGX_HTTP_HEAVYBAG_GEO_ND])
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
    p = db->block[NGX_HTTP_HEAVYBAG_GEO_ND] + (size_t) net * 12;

    res->country[0] = p[0];
    res->country[1] = p[1];
    res->asn = ngx_http_heavybag_geo_u32(p + 4);
    res->flags = (uint16_t) ((p[8] << 8) | p[9]);
    res->found = 1;
}
