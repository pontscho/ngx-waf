/*
 * ngx_http_heavybag_module - JA4 TLS client fingerprint
 *
 * See heavybag_ja4.h. This file splits into two regions:
 *   - the PURE core (ngx_http_heavybag_ja4_build + helpers), nginx-free, compiled
 *     standalone under -DHEAVYBAG_JA4_UNIT_TEST for the JA4 unit test;
 *   - the SSL extractor / handshake callback, wrapped in
 *     `#ifndef HEAVYBAG_JA4_UNIT_TEST` so the core compiles without nginx/SSL.
 *
 * The pure core treats every input as attacker-controlled: GREASE-filtered
 * and clamped to HEAVYBAG_JA4_MAX_ELEMS before any copy/sort (CWE-190/787), output
 * via bounded snprintf into a fixed buffer (CWE-787), ALPN hex-escaped when
 * non-alphanumeric (CWE-116/117). SHA256 via the EVP one-shot (the low-level
 * SHA256() is deprecated in OpenSSL 3 and would break the -Werror build).
 */

#include "heavybag_ja4.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>


/* GREASE (RFC 8701): reserved values of the form 0x?a?a. */
static int
ja4_is_grease(uint16_t v)
{
    return (v & 0x0f0f) == 0x0a0a;
}


/* uint16 ascending comparator. For zero-padded 4-hex this numeric order is
 * identical to the lexicographic order of the rendered strings. */
static int
ja4_cmp_u16(const void *a, const void *b)
{
    uint16_t  x = *(const uint16_t *) a;
    uint16_t  y = *(const uint16_t *) b;

    return (x > y) - (x < y);
}


/* Map a TLS/DTLS version word to its 2-char JA4 code; "00" if unrecognised. */
static void
ja4_version_code(uint16_t v, char out[2])
{
    switch (v) {
    case 0x0304: out[0] = '1'; out[1] = '3'; break;  /* TLS 1.3  */
    case 0x0303: out[0] = '1'; out[1] = '2'; break;  /* TLS 1.2  */
    case 0x0302: out[0] = '1'; out[1] = '1'; break;  /* TLS 1.1  */
    case 0x0301: out[0] = '1'; out[1] = '0'; break;  /* TLS 1.0  */
    case 0x0300: out[0] = 's'; out[1] = '3'; break;  /* SSL 3.0  */
    case 0xfeff: out[0] = 'd'; out[1] = '1'; break;  /* DTLS 1.0 */
    case 0xfefd: out[0] = 'd'; out[1] = '2'; break;  /* DTLS 1.2 */
    case 0xfefc: out[0] = 'd'; out[1] = '3'; break;  /* DTLS 1.3 */
    default:     out[0] = '0'; out[1] = '0'; break;
    }
}


static int
ja4_is_alnum(uint8_t c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z');
}


static char
ja4_hex_digit(unsigned v)
{
    v &= 0x0f;
    return (char) (v < 10 ? '0' + v : 'a' + (v - 10));
}


/*
 * ALPN field (JA4_a bytes 8-9): the first and last char of the first ALPN
 * value. If either end byte is not ASCII-alphanumeric the value is hex-escaped
 * (high nibble of the first byte, low nibble of the last byte) so a hostile
 * ALPN cannot inject raw bytes into the fingerprint. No ALPN -> "00".
 */
static void
ja4_alpn_chars(const uint8_t *alpn, size_t len, char out[2])
{
    if (alpn == NULL || len == 0) {
        out[0] = '0';
        out[1] = '0';
        return;
    }

    if (ja4_is_alnum(alpn[0]) && ja4_is_alnum(alpn[len - 1])) {
        out[0] = (char) alpn[0];
        out[1] = (char) alpn[len - 1];
        return;
    }

    out[0] = ja4_hex_digit((unsigned) alpn[0] >> 4);
    out[1] = ja4_hex_digit((unsigned) alpn[len - 1]);
}


/* Copy the non-GREASE values of src into dst (capacity cap), preserving order;
 * returns the count written (clamped to cap). */
static size_t
ja4_filter_grease(const uint16_t *src, size_t n, uint16_t *dst, size_t cap)
{
    size_t  i, k;

    for (i = 0, k = 0; i < n && k < cap; i++) {
        if (!ja4_is_grease(src[i])) {
            dst[k++] = src[i];
        }
    }

    return k;
}


/* Append a comma-separated lowercase 4-hex list of vals[0..n) to buf (capacity
 * cap, kept NUL-terminated), advancing *pos. Stops cleanly if the buffer fills. */
static void
ja4_append_hex_csv(char *buf, size_t cap, size_t *pos,
    const uint16_t *vals, size_t n)
{
    size_t  i;
    int     w;

    for (i = 0; i < n; i++) {
        if (*pos + 1 >= cap) {
            break;
        }
        w = snprintf(buf + *pos, cap - *pos, "%s%04x",
                     (i == 0) ? "" : ",", vals[i]);
        if (w < 0 || (size_t) w >= cap - *pos) {
            break;            /* truncated; buf stays NUL-terminated */
        }
        *pos += (size_t) w;
    }
}


/* SHA256(in[0..len)) -> first 12 lowercase hex chars into out[13] (with NUL). */
static int
ja4_sha256_hex12(const char *in, size_t len, char out[13])
{
    unsigned char  md[EVP_MAX_MD_SIZE];
    unsigned int   mdlen;
    int            i;

    if (EVP_Digest(in, len, md, &mdlen, EVP_sha256(), NULL) != 1
        || mdlen < 6)
    {
        return -1;
    }

    for (i = 0; i < 6; i++) {
        out[i * 2]     = ja4_hex_digit((unsigned) md[i] >> 4);
        out[i * 2 + 1] = ja4_hex_digit((unsigned) md[i]);
    }
    out[12] = '\0';

    return 0;
}


int
ngx_http_heavybag_ja4_build(const uint16_t *ciphers, size_t n_ciphers,
    const uint16_t *exts, size_t n_exts,
    const uint16_t *sigalgs, size_t n_sigalgs,
    const uint8_t *alpn, size_t alpn_len,
    uint16_t version, int is_quic, char out[HEAVYBAG_JA4_LEN])
{
    char       a[11];
    char       jb[13];
    char       jc[13];
    char       ver[2];
    char       alpn_c[2];
    char       csv[HEAVYBAG_JA4_MAX_ELEMS * 5 * 2 + 4];
    uint16_t   list[HEAVYBAG_JA4_MAX_ELEMS];
    uint16_t   sig[HEAVYBAG_JA4_MAX_ELEMS];
    size_t     i, n, ns, pos;
    int        sni, ncip, next;

    if (out == NULL) {
        return -1;
    }

    /* --- JA4_a: t/q, version, SNI, cipher count, ext count, ALPN -------- */

    /* extension count (non-GREASE; SNI + ALPN ARE counted) + SNI presence */
    sni = 0;
    next = 0;
    for (i = 0; i < n_exts; i++) {
        if (ja4_is_grease(exts[i])) {
            continue;
        }
        if (exts[i] == 0x0000) {
            sni = 1;
        }
        next++;
    }

    ncip = 0;
    for (i = 0; i < n_ciphers; i++) {
        if (!ja4_is_grease(ciphers[i])) {
            ncip++;
        }
    }

    if (ncip > 99) { ncip = 99; }   /* 2-digit field clamp (CWE-190) */
    if (next > 99) { next = 99; }

    ja4_version_code(version, ver);
    ja4_alpn_chars(alpn, alpn_len, alpn_c);

    (void) snprintf(a, sizeof(a), "%c%c%c%c%02u%02u%c%c",
                    is_quic ? 'q' : 't', ver[0], ver[1], sni ? 'd' : 'i',
                    (unsigned) ncip, (unsigned) next, alpn_c[0], alpn_c[1]);

    /* --- JA4_b: SHA256 of the sorted cipher hex list ------------------- */
    n = ja4_filter_grease(ciphers, n_ciphers, list, HEAVYBAG_JA4_MAX_ELEMS);
    if (n > 1) {
        qsort(list, n, sizeof(uint16_t), ja4_cmp_u16);
    }
    if (n == 0) {
        /* FoxIO canonical: an empty cipher list renders as the literal
         * "000000000000", NOT SHA256("") (e3b0c44298fc). A blocklist / spoof
         * check keyed on the canonical JA4 must see the same zeros FoxIO
         * emits, or an only-GREASE / no-cipher ClientHello evades it. */
        memcpy(jb, "000000000000", sizeof("000000000000"));
    } else {
        pos = 0;
        csv[0] = '\0';
        ja4_append_hex_csv(csv, sizeof(csv), &pos, list, n);
        if (ja4_sha256_hex12(csv, pos, jb) != 0) {
            return -1;
        }
    }

    /* --- JA4_c: sorted exts (no SNI/ALPN/GREASE) + "_" + sigalgs ------- */
    n = 0;
    for (i = 0; i < n_exts && n < HEAVYBAG_JA4_MAX_ELEMS; i++) {
        if (ja4_is_grease(exts[i])
            || exts[i] == 0x0000     /* SNI: captured in byte 3      */
            || exts[i] == 0x0010)    /* ALPN: captured in bytes 8-9  */
        {
            continue;
        }
        list[n++] = exts[i];
    }
    if (n > 1) {
        qsort(list, n, sizeof(uint16_t), ja4_cmp_u16);
    }

    /* signature algorithms stay in ORIGINAL ClientHello order */
    ns = 0;
    if (sigalgs != NULL) {
        ns = ja4_filter_grease(sigalgs, n_sigalgs, sig, HEAVYBAG_JA4_MAX_ELEMS);
    }

    if (n == 0 && ns == 0) {
        /* FoxIO canonical: no extensions AND no sigalgs -> literal zeros,
         * not SHA256(""). Same evasion concern as JA4_b above. */
        memcpy(jc, "000000000000", sizeof("000000000000"));
    } else {
        pos = 0;
        csv[0] = '\0';
        ja4_append_hex_csv(csv, sizeof(csv), &pos, list, n);
        if (ns > 0) {
            if (pos + 1 < sizeof(csv)) {
                csv[pos++] = '_';
                csv[pos] = '\0';
            }
            ja4_append_hex_csv(csv, sizeof(csv), &pos, sig, ns);
        }
        if (ja4_sha256_hex12(csv, pos, jc) != 0) {
            return -1;
        }
    }

    (void) snprintf(out, HEAVYBAG_JA4_LEN, "%s_%s_%s", a, jb, jc);

    return 0;
}


#ifndef HEAVYBAG_JA4_UNIT_TEST

/*
 * ---------------------------------------------------------------------------
 * nginx / OpenSSL extractor + handshake callback.
 *
 * ngx_http_heavybag_ja4_compute() (task-014) reads the ClientHello getters off an
 * SSL* and feeds ngx_http_heavybag_ja4_build(); the client_hello callback + SSL_CTX
 * wiring (task-015) live in ngx_http_heavybag_module.c. Implemented in later tasks;
 * the includes are staged here so those additions drop straight in.
 *
 * The whole extractor (and the SSL_is_quic call it contains) requires OpenSSL.
 * Gate it on NGX_HTTP_SSL so --without-http_ssl_module builds skip it cleanly.
 * NGX_HTTP_SSL is set by ngx_auto_config.h (pulled in via ngx_config.h), so the
 * guard must come AFTER that include.
 * ---------------------------------------------------------------------------
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/ssl.h>

#if (NGX_HTTP_SSL)


/* GREASE test, duplicated here so the extractor needs no core helper. */
static int
ja4_compute_is_grease(uint16_t v)
{
    return (v & 0x0f0f) == 0x0a0a;
}


/*
 * Extract the ClientHello fields off *ssl and build the JA4 into *out, with
 * out->data from *pool (connection-scoped, freed with the connection). Every
 * getter read is bounded by the length the getter returns (CWE-125); the only
 * allocating getter, SSL_client_hello_get1_extensions_present(), is freed on
 * EVERY path through a single cleanup label (CWE-401). Fail-open: any malformed
 * or missing field yields NGX_ERROR and no fingerprint -- never a crash.
 */
ngx_int_t
ngx_http_heavybag_ja4_compute(SSL *ssl, ngx_pool_t *pool, ngx_str_t *out)
{
    int                   *ext_ids = NULL;
    const unsigned char   *p;
    size_t                 n, i, len, end, list;
    size_t                 n_cip, n_ext, n_sig, alpn_len;
    uint16_t               ciphers[HEAVYBAG_JA4_MAX_ELEMS];
    uint16_t               exts[HEAVYBAG_JA4_MAX_ELEMS];
    uint16_t               sigalgs[HEAVYBAG_JA4_MAX_ELEMS];
    uint16_t               version, hi, v;
    const uint8_t         *alpn;
    int                    is_quic;
    char                   buf[HEAVYBAG_JA4_LEN];
    u_char                *dst;
    ngx_int_t              rc = NGX_ERROR;

    if (ssl == NULL || pool == NULL || out == NULL) {
        return NGX_ERROR;
    }

    /* cipher_suites: a flat list of 2-byte big-endian values */
    n_cip = 0;
    len = SSL_client_hello_get0_ciphers(ssl, &p);
    for (i = 0; i + 1 < len && n_cip < HEAVYBAG_JA4_MAX_ELEMS; i += 2) {
        ciphers[n_cip++] = (uint16_t) ((p[i] << 8) | p[i + 1]);
    }

    /* extension types (ALLOCATES ext_ids -> OPENSSL_free on every path) */
    n_ext = 0;
    if (SSL_client_hello_get1_extensions_present(ssl, &ext_ids, &n) == 1
        && ext_ids != NULL)
    {
        for (i = 0; i < n && n_ext < HEAVYBAG_JA4_MAX_ELEMS; i++) {
            exts[n_ext++] = (uint16_t) ext_ids[i];
        }
    }

    /* version: highest non-GREASE supported_versions (0x002b), else legacy */
    version = (uint16_t) SSL_client_hello_get0_legacy_version(ssl);
    if (SSL_client_hello_get0_ext(ssl, 0x002b, &p, &len) == 1 && len >= 1) {
        list = p[0];
        end = 1 + list;
        if (end > len) {
            end = len;
        }
        hi = 0;
        for (i = 1; i + 1 < end; i += 2) {
            v = (uint16_t) ((p[i] << 8) | p[i + 1]);
            if (ja4_compute_is_grease(v)) {
                continue;
            }
            if (v > hi) {
                hi = v;
            }
        }
        if (hi != 0) {
            version = hi;
        }
    }

    /* signature_algorithms (0x000d): 2-byte list length, then 2-byte entries */
    n_sig = 0;
    if (SSL_client_hello_get0_ext(ssl, 0x000d, &p, &len) == 1 && len >= 2) {
        list = ((size_t) p[0] << 8) | p[1];
        end = 2 + list;
        if (end > len) {
            end = len;
        }
        for (i = 2; i + 1 < end && n_sig < HEAVYBAG_JA4_MAX_ELEMS; i += 2) {
            sigalgs[n_sig++] = (uint16_t) ((p[i] << 8) | p[i + 1]);
        }
    }

    /* ALPN (0x0010): 2-byte list len, then {1-byte proto len, proto bytes}... */
    alpn = NULL;
    alpn_len = 0;
    if (SSL_client_hello_get0_ext(ssl, 0x0010, &p, &len) == 1 && len >= 3) {
        list = p[2];                     /* length of the first ALPN protocol */
        if (list > 0 && 3 + list <= len) {
            alpn = (const uint8_t *) &p[3];
            alpn_len = list;
        }
    }

    is_quic = SSL_is_quic(ssl);

    if (ngx_http_heavybag_ja4_build(ciphers, n_cip, exts, n_ext, sigalgs, n_sig,
                               alpn, alpn_len, version, is_quic, buf) != 0)
    {
        goto cleanup;
    }

    n = ngx_strlen(buf);
    dst = ngx_pnalloc(pool, n);
    if (dst == NULL) {
        goto cleanup;
    }

    ngx_memcpy(dst, buf, n);
    out->data = dst;
    out->len = n;
    rc = NGX_OK;

cleanup:

    if (ext_ids != NULL) {
        OPENSSL_free(ext_ids);
    }

    return rc;
}

#endif /* NGX_HTTP_SSL */

#endif /* HEAVYBAG_JA4_UNIT_TEST */
