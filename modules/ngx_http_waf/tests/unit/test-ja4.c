/*
 * Unit tests for the pure JA4 core (ngx_http_waf_ja4_build).
 *
 * Compiled standalone: includes waf_ja4.c under -DWAF_JA4_UNIT_TEST so only the
 * nginx-free core is pulled in (no nginx / SSL headers). Built + run by
 * run-unit-tests.sh with `cc -DWAF_JA4_UNIT_TEST -lcrypto`.
 */

#ifndef WAF_JA4_UNIT_TEST
#define WAF_JA4_UNIT_TEST
#endif
#include "../../src/waf_ja4.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>


/*
 * The FoxIO canonical example. Cipher / extension order here is deliberately
 * the raw ClientHello order (GREASE included): the core filters GREASE, sorts
 * ciphers and extensions, and keeps signature algorithms in original order.
 * The expected fingerprint is the published FoxIO value.
 */
static const uint16_t  canon_ciphers[] = {
    0x5a5a,                         /* GREASE -> dropped               */
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
    0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
};

static const uint16_t  canon_exts[] = {
    0xfafa, 0x1a1a,                 /* GREASE -> dropped               */
    0x0000,                         /* SNI    -> counted, not in _c    */
    0x0010,                         /* ALPN   -> counted, not in _c    */
    0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b,
    0x0023, 0x002b, 0x002d, 0x0033, 0x4469, 0xff01
};

/* signature_algorithms (ext 0x000d) values, ORIGINAL order -> feeds _c */
static const uint16_t  canon_sigalgs[] = {
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
};

static const uint8_t   canon_alpn[] = { 'h', '2' };


CTEST(ja4, foxio_canonical_vector)
{
    char  out[WAF_JA4_LEN];
    int   rc;

    rc = ngx_http_waf_ja4_build(
        canon_ciphers, sizeof(canon_ciphers) / sizeof(canon_ciphers[0]),
        canon_exts,    sizeof(canon_exts)    / sizeof(canon_exts[0]),
        canon_sigalgs, sizeof(canon_sigalgs) / sizeof(canon_sigalgs[0]),
        canon_alpn,    sizeof(canon_alpn),
        0x0304 /* TLS 1.3 */, 0 /* not QUIC */, out);

    ASSERT_EQUAL(0, rc);
    ASSERT_STR("t13d1516h2_8daaf6152771_e5627efa2ab1", out);
}


/* GREASE values must be dropped from BOTH the counts and the hashes: the
 * fingerprint of a hello with extra GREASE must equal the one without. */
CTEST(ja4, grease_is_filtered)
{
    static const uint16_t  with_grease[]  = { 0x0a0a, 0x1301, 0x1a1a, 0x1302,
                                              0xfafa };
    static const uint16_t  without[]      = { 0x1301, 0x1302 };
    static const uint16_t  exts[]         = { 0x0000, 0x000d };
    char  a[WAF_JA4_LEN];
    char  b[WAF_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_waf_ja4_build(with_grease, 5, exts, 2,
                     NULL, 0, NULL, 0, 0x0303, 0, a));
    ASSERT_EQUAL(0, ngx_http_waf_ja4_build(without, 2, exts, 2,
                     NULL, 0, NULL, 0, 0x0303, 0, b));

    /* identical non-GREASE input -> identical fingerprint (cipher count "02") */
    ASSERT_STR(a, b);
    ASSERT_EQUAL('0', a[4]);
    ASSERT_EQUAL('2', a[5]);
}


/* A non-alphanumeric ALPN end byte is hex-escaped, never emitted raw. */
CTEST(ja4, alpn_hex_fallback)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    static const uint8_t   alpn[]    = { 0x01, 0xff };   /* both non-alnum */
    char  out[WAF_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_waf_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     alpn, sizeof(alpn), 0x0304, 0, out));

    /* bytes 8-9 = high nibble of 0x01 ('0'), low nibble of 0xff ('f') */
    ASSERT_EQUAL('0', out[8]);
    ASSERT_EQUAL('f', out[9]);
}


/* No ALPN -> "00"; protocol char 'q' for QUIC. */
CTEST(ja4, no_alpn_and_quic)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000 };
    char  out[WAF_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_waf_ja4_build(ciphers, 1, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 1 /* QUIC */, out));

    ASSERT_EQUAL('q', out[0]);
    ASSERT_EQUAL('0', out[8]);
    ASSERT_EQUAL('0', out[9]);
}


/*
 * Empty signature algorithms: the "_" + sigalg segment is omitted, so the _c
 * hash is taken over an empty string. With every extension excluded (SNI +
 * ALPN + GREASE only) and no sigalgs, _c == sha256("")[:12] == e3b0c44298fc.
 */
CTEST(ja4, empty_sigalgs_and_exts)
{
    static const uint16_t  ciphers[] = { 0x1301 };
    static const uint16_t  exts[]    = { 0x0000, 0x0010, 0x0a0a };
    char  out[WAF_JA4_LEN];

    ASSERT_EQUAL(0, ngx_http_waf_ja4_build(ciphers, 1, exts, 3, NULL, 0,
                     NULL, 0, 0x0304, 0, out));

    /* out = "t13d0100__<jb>_e3b0c44298fc" ; check the trailing _c segment */
    ASSERT_STR("e3b0c44298fc", out + WAF_JA4_LEN - 1 - 12);
}


/* Oversized cipher list: the 2-digit count clamps to 99 and nothing overflows. */
CTEST(ja4, count_clamp_no_overflow)
{
    uint16_t  ciphers[300];
    static const uint16_t  exts[] = { 0x0000 };
    char      out[WAF_JA4_LEN];
    int       i;

    for (i = 0; i < 300; i++) {
        ciphers[i] = (uint16_t) (0x0100 + i);   /* none match GREASE */
    }

    ASSERT_EQUAL(0, ngx_http_waf_ja4_build(ciphers, 300, exts, 1, NULL, 0,
                     NULL, 0, 0x0304, 0, out));

    /* cipher count field (bytes 4-5) clamps to "99" */
    ASSERT_EQUAL('9', out[4]);
    ASSERT_EQUAL('9', out[5]);
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
