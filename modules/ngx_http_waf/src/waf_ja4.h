/*
 * ngx_http_waf_module - JA4 TLS client fingerprint (FoxIO JA4, observability)
 *
 * Two layers:
 *   ngx_http_waf_ja4_build()   - PURE core. Takes raw ClientHello field arrays
 *                                (uint16 cipher/ext/sigalg lists + ALPN bytes)
 *                                and emits the FoxIO JA4 string. Depends only
 *                                on stdint/string/stdio + OpenSSL SHA256, NO
 *                                nginx types, so it compiles and unit-tests
 *                                standalone under -DWAF_JA4_UNIT_TEST.
 *   ngx_http_waf_ja4_compute() - thin SSL extractor (task-014) that reads the
 *                                ClientHello getters off an SSL* and feeds the
 *                                pure core. Defined only in the full build.
 *
 * SECURITY: the pure core parses attacker-controlled ClientHello bytes. Every
 * list is GREASE-filtered and clamped to WAF_JA4_MAX_ELEMS before any copy or
 * sort (CWE-190/787); the output is a fixed WAF_JA4_LEN buffer written only
 * via bounded snprintf (CWE-787); the ALPN field is hex-escaped when it is not
 * ASCII-alphanumeric so a hostile ALPN cannot inject into the fingerprint
 * (CWE-116/117). The core never allocates and never reads past a given length.
 */

#ifndef _WAF_JA4_H_INCLUDED_
#define _WAF_JA4_H_INCLUDED_


#include <stddef.h>
#include <stdint.h>


/* "t13d1516h2_8daaf6152771_e5627efa2ab1" = 36 chars + NUL */
#define WAF_JA4_LEN        37

/* hard clamp on any parsed uint16 list before copy/sort (CWE-190/787) */
#define WAF_JA4_MAX_ELEMS  256


/*
 * Build a FoxIO JA4 fingerprint into out[WAF_JA4_LEN] (always NUL-terminated
 * on success). Inputs are raw ClientHello fields in wire order, GREASE values
 * INCLUDED (filtered internally):
 *   ciphers/n_ciphers       - cipher_suites list
 *   exts/n_exts             - extension types list (MUST include SNI 0x0000 and
 *                             ALPN 0x0010 when present: they drive byte 3 / the
 *                             count, and are excluded from the JA4_c hash here)
 *   sigalgs/n_sigalgs       - signature_algorithms (extension 0x000d) values,
 *                             kept in ORIGINAL order for JA4_c (NULL/0 if none)
 *   alpn/alpn_len           - bytes of the FIRST ALPN protocol (NULL/0 if none)
 *   version                 - the resolved TLS version (highest non-GREASE
 *                             supported_versions value, else legacy_version)
 *   is_quic                 - non-zero -> 'q' protocol char, else 't'
 * Returns 0 on success, -1 on a NULL out pointer.
 */
int ngx_http_waf_ja4_build(const uint16_t *ciphers, size_t n_ciphers,
    const uint16_t *exts, size_t n_exts,
    const uint16_t *sigalgs, size_t n_sigalgs,
    const uint8_t *alpn, size_t alpn_len,
    uint16_t version, int is_quic, char out[WAF_JA4_LEN]);


#ifndef WAF_JA4_UNIT_TEST

#include <ngx_config.h>
#include <ngx_core.h>

struct ssl_st;

/*
 * Extract the ClientHello fields off *ssl and build the JA4 into *out, with
 * *out->data allocated from *pool (connection-scoped). Returns NGX_OK on
 * success, NGX_ERROR on any failure (fail-open: the caller does not block).
 * Defined in waf_ja4.c (task-014).
 */
ngx_int_t ngx_http_waf_ja4_compute(struct ssl_st *ssl, ngx_pool_t *pool,
    ngx_str_t *out);

#endif /* WAF_JA4_UNIT_TEST */


#endif /* _WAF_JA4_H_INCLUDED_ */
