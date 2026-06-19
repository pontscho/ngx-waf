/*
 * Unit tests for the JA4 SSL EXTRACTOR (ngx_http_heavybag_ja4_compute) -- the
 * #if (NGX_HTTP_SSL) half of heavybag_ja4.c that the core-only test-ja4.c
 * deliberately excludes. This is the Phase 6c "ja4 wire-walk" net.
 *
 * The extractor reads the raw ClientHello off the OpenSSL getters
 * (SSL_client_hello_get0_ciphers / _get1_extensions_present / _get0_ext /
 * _get0_legacy_version / SSL_is_quic) and feeds the pure core. Its security
 * job is to CLAMP every attacker-controlled inner length to the getter length
 * (CWE-125) and drop dangling/odd bytes before the bytes reach the core. Those
 * clamp branches are unreachable through a live OpenSSL handshake (OpenSSL
 * rejects a malformed inner length before the JA4 is observable on the wire),
 * so we drive them HERE with synthetic raw buffers behind mocked getters.
 *
 * Isolation: this file provides a byte-mirroring nginx type shim + mock SSL
 * getters, then #includes heavybag_ja4.c under -DHEAVYBAG_JA4_EXTRACT_UNIT_TEST.
 * That macro makes heavybag_ja4.{h,c} SKIP their <ngx_config.h>/<ngx_core.h>/
 * <openssl/ssl.h> includes (we supply the types + getters instead) while still
 * pulling in the real pure core (which uses real <openssl/evp.h> for SHA256).
 * The production build defines NEITHER test macro -> byte-transparent.
 *
 * Assertions are STRUCTURAL: fixed byte offsets in the 36-char JA4 string
 *   [0] proto t|q  [1..2] version  [3] SNI d|i  [4..5] cipher count
 *   [6..7] ext count  [8..9] ALPN  [10] _  [11..22] JA4_b  [23] _  [24..35] JA4_c
 * or two builds compared -- no hand-computed SHA256 literal (the core's hashes
 * are already pinned by test-ja4.c).
 *
 * Built + run by run-unit-tests.sh with -DHEAVYBAG_JA4_EXTRACT_UNIT_TEST -lcrypto.
 */

#ifndef HEAVYBAG_JA4_EXTRACT_UNIT_TEST
#define HEAVYBAG_JA4_EXTRACT_UNIT_TEST
#endif
#ifndef NGX_HTTP_SSL
#define NGX_HTTP_SSL 1
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/types.h>     /* SSL typedef (struct ssl_st) -- NOT ssl.h */
#include <openssl/crypto.h>    /* OPENSSL_malloc / OPENSSL_free */

/* --- nginx type shim (only what the extractor + the .h decl reference) ----- */
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef unsigned char   u_char;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct ngx_pool_s ngx_pool_t;     /* opaque: the extractor only passes it on */

#define NGX_OK      0
#define NGX_ERROR  -1

#define ngx_memcpy(d, s, n)   memcpy(d, s, n)
#define ngx_strlen(s)         strlen((const char *) (s))

/* ngx_pnalloc: the extractor allocates out->data from the connection pool. A
 * short-lived test process can just malloc (read the result, then exit).
 * g_pnalloc_fail forces a single NULL return so a vector can drive the
 * extractor's `dst == NULL -> goto cleanup` error path (L12). */
static int g_pnalloc_fail = 0;
static void *ngx_pnalloc(ngx_pool_t *pool, size_t n)
{
    (void) pool;
    if (g_pnalloc_fail) { return NULL; }
    return malloc(n);
}

/* --- mock SSL ClientHello state ------------------------------------------- */
/* struct ssl_st is only forward-declared by <openssl/types.h>; we define the
 * body. SSL (== struct ssl_st) is already typedef'd there. */
struct ssl_st {
    const unsigned char *ciphers;   size_t ciphers_len;   /* raw 2-byte-BE cipher list */
    int                 *exts;      size_t exts_n;        /* extension type ids */
    unsigned int         legacy_version;
    int                  is_quic;
    struct {
        unsigned int         type;
        const unsigned char *data;
        size_t               len;
    } ext[8];                                             /* SSL_client_hello_get0_ext store */
    int                  next_ext;
    int                  ext_freed;                       /* OPENSSL_free accounting */
};

static struct ssl_st *g_last;   /* so a test can inspect ext_freed after compute */

size_t
SSL_client_hello_get0_ciphers(SSL *s, const unsigned char **out)
{
    *out = s->ciphers;
    return s->ciphers_len;
}

int
SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen)
{
    if (s->exts == NULL || s->exts_n == 0) { *out = NULL; *outlen = 0; return 0; }
    int *p = OPENSSL_malloc(s->exts_n * sizeof(int));
    if (p == NULL) { return 0; }
    for (size_t i = 0; i < s->exts_n; i++) { p[i] = s->exts[i]; }
    *out = p;
    *outlen = s->exts_n;
    return 1;
}

unsigned int
SSL_client_hello_get0_legacy_version(SSL *s) { return s->legacy_version; }

int
SSL_client_hello_get0_ext(SSL *s, unsigned int type, const unsigned char **out, size_t *outlen)
{
    for (int i = 0; i < s->next_ext; i++) {
        if (s->ext[i].type == type) {
            *out = s->ext[i].data;
            *outlen = s->ext[i].len;
            return 1;
        }
    }
    return 0;
}

int SSL_is_quic(SSL *s) { return s->is_quic; }

/* wrap OPENSSL_free so a vector can assert ext_ids was reclaimed (CWE-401). The
 * extractor calls OPENSSL_free(ext_ids); count it via the last-used ssl. */
static void hb_test_free(void *p) { if (g_last && p) g_last->ext_freed++; OPENSSL_free(p); }
#undef  OPENSSL_free                /* drop crypto.h's macro before shadowing it */
#define OPENSSL_free(p)  hb_test_free(p)

/* pull in the extractor (and the pure core it calls) */
#include "../../src/heavybag_ja4.c"

#define CTEST_MAIN
#include "ctest.h"


/* run the extractor; copy the (non-NUL-terminated) JA4 into out[], terminate. */
static int
run_ja4(struct ssl_st *s, char out[64])
{
    ngx_str_t  o;
    ngx_int_t  rc;

    static char  dummy_arena[1];
    o.len = 0; o.data = NULL;
    g_last = s;
    /* pool must be non-NULL (the extractor's NULL-guard); ngx_pnalloc ignores it. */
    rc = ngx_http_heavybag_ja4_compute(s, (ngx_pool_t *) dummy_arena, &o);
    if (rc != NGX_OK) { return -1; }
    size_t n = o.len < 63 ? o.len : 63;
    memcpy(out, o.data, n);
    out[n] = '\0';
    return (int) o.len;
}

/* copy a [lo,lo+w) field of the JA4 string into a small NUL-terminated buffer */
static void
field(const char *ja4, int lo, int w, char *dst)
{
    memcpy(dst, ja4 + lo, (size_t) w);
    dst[w] = '\0';
}

#define INIT_SSL(s)  struct ssl_st s; memset(&s, 0, sizeof(s)); s.legacy_version = 0x0303


/* ===== cipher parse / clamp =============================================== */

/* 2-byte big-endian cipher decode + count field. */
CTEST(ja4x, cipher_two_byte_parse)
{
    static const unsigned char cip[] = { 0x13, 0x01, 0x13, 0x02 };
    char j[64], f[8];
    INIT_SSL(s); s.ciphers = cip; s.ciphers_len = sizeof(cip);
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 4, 2, f);
    ASSERT_STR("02", f);            /* two ciphers parsed */
}

/* odd trailing byte: i+1<len drops the dangling half-cipher. */
CTEST(ja4x, cipher_odd_trailing_byte_dropped)
{
    static const unsigned char cip[] = { 0x13, 0x01, 0xFF };   /* 3 bytes -> 1 cipher */
    char j[64], f[8];
    INIT_SSL(s); s.ciphers = cip; s.ciphers_len = sizeof(cip);
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 4, 2, f);
    ASSERT_STR("01", f);            /* trailing 0xFF dropped, not a 2nd cipher */
}

/* >256 ciphers: n_cip clamps to HEAVYBAG_JA4_MAX_ELEMS, count field clamps to 99. */
CTEST(ja4x, cipher_count_over_max_clamps)
{
    static unsigned char cip[600];
    char j[64], f[8];
    for (int i = 0; i < 300; i++) { cip[2*i] = (unsigned char)(i >> 8); cip[2*i+1] = (unsigned char) i; }
    INIT_SSL(s); s.ciphers = cip; s.ciphers_len = sizeof(cip);
    ASSERT_TRUE(run_ja4(&s, j) > 0);   /* no over-read / crash on 300 ciphers */
    field(j, 4, 2, f);
    ASSERT_STR("99", f);            /* count field clamped to 99 */
}


/* ===== supported_versions (0x002b) inner-length clamp ===================== */

/* inner list length lies far past the getter length -> clamped to len, the one
 * real version still parsed (no read past the buffer). */
CTEST(ja4x, supported_versions_inner_length_lie_clamped)
{
    static const unsigned char sv[] = { 0xFF, 0x03, 0x04 };   /* list says 255, body=3 */
    char j[64], f[8];
    INIT_SSL(s); s.legacy_version = 0x0301 /* TLS1.0 */;
    s.ext[0].type = 0x002b; s.ext[0].data = sv; s.ext[0].len = sizeof(sv); s.next_ext = 1;
    s.exts = (int[]){ 0x002b }; s.exts_n = 1;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 1, 2, f);
    ASSERT_STR("13", f);            /* 0x0304 read; lie clamped, version=TLS1.3 */
}

/* a too-short body (list>0 but no full entry) leaves version at legacy. */
CTEST(ja4x, supported_versions_short_body_falls_back)
{
    static const unsigned char sv[] = { 0x02, 0x03 };   /* list=2 but only 1 byte after */
    char j[64], f[8];
    INIT_SSL(s); s.legacy_version = 0x0303 /* TLS1.2 */;
    s.ext[0].type = 0x002b; s.ext[0].data = sv; s.ext[0].len = sizeof(sv); s.next_ext = 1;
    s.exts = (int[]){ 0x002b }; s.exts_n = 1;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 1, 2, f);
    ASSERT_STR("12", f);            /* no full version entry -> legacy TLS1.2 */
}


/* ===== signature_algorithms (0x000d) inner-length clamp + odd byte ======== */

/* lying 2-byte list length is clamped; the one sigalg still feeds JA4_c (so
 * JA4_c differs from a hello with no sigalgs ext). */
CTEST(ja4x, sigalgs_inner_length_lie_clamped)
{
    static const unsigned char sa[] = { 0x00, 0xFF, 0x04, 0x03 };   /* list says 255 */
    char j_with[64], j_without[64];
    INIT_SSL(a);
    a.ext[0].type = 0x000d; a.ext[0].data = sa; a.ext[0].len = sizeof(sa); a.next_ext = 1;
    a.exts = (int[]){ 0x000d }; a.exts_n = 1;
    ASSERT_TRUE(run_ja4(&a, j_with) > 0);
    INIT_SSL(b);
    b.exts = (int[]){ 0x0005 }; b.exts_n = 1;   /* no sigalgs ext */
    ASSERT_TRUE(run_ja4(&b, j_without) > 0);
    /* JA4_c (offset 24) must differ: one sigalg was parsed despite the lie */
    ASSERT_TRUE(memcmp(j_with + 24, j_without + 24, 12) != 0);
}

/* odd trailing byte after a clean 1-entry list is dropped (i+1<end), so JA4_c
 * equals the clean-list build. */
CTEST(ja4x, sigalgs_odd_trailing_byte_dropped)
{
    static const unsigned char odd[]   = { 0x00, 0x02, 0x04, 0x03, 0xFF };
    static const unsigned char clean[] = { 0x00, 0x02, 0x04, 0x03 };
    char j_odd[64], j_clean[64];
    INIT_SSL(a);
    a.ext[0].type = 0x000d; a.ext[0].data = odd; a.ext[0].len = sizeof(odd); a.next_ext = 1;
    a.exts = (int[]){ 0x000d }; a.exts_n = 1;
    ASSERT_TRUE(run_ja4(&a, j_odd) > 0);
    INIT_SSL(b);
    b.ext[0].type = 0x000d; b.ext[0].data = clean; b.ext[0].len = sizeof(clean); b.next_ext = 1;
    b.exts = (int[]){ 0x000d }; b.exts_n = 1;
    ASSERT_TRUE(run_ja4(&b, j_clean) > 0);
    ASSERT_TRUE(memcmp(j_odd + 24, j_clean + 24, 12) == 0);   /* odd byte not a half-entry */
}


/* ===== ALPN (0x0010) bounds ============================================== */

CTEST(ja4x, alpn_exact_fit)
{
    static const unsigned char al[] = { 0x00, 0x03, 0x02, 'h', '2' };  /* list len 2, fits */
    char j[64], f[8];
    INIT_SSL(s);
    s.ext[0].type = 0x0010; s.ext[0].data = al; s.ext[0].len = sizeof(al); s.next_ext = 1;
    s.exts = (int[]){ 0x0010 }; s.exts_n = 1;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 8, 2, f);
    ASSERT_STR("h2", f);
}

CTEST(ja4x, alpn_zero_len_is_00)
{
    static const unsigned char al[] = { 0x00, 0x01, 0x00 };   /* first proto len 0 */
    char j[64], f[8];
    INIT_SSL(s);
    s.ext[0].type = 0x0010; s.ext[0].data = al; s.ext[0].len = sizeof(al); s.next_ext = 1;
    s.exts = (int[]){ 0x0010 }; s.exts_n = 1;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 8, 2, f);
    ASSERT_STR("00", f);            /* list>0 guard fails -> no ALPN */
}

CTEST(ja4x, alpn_lying_length_rejected)
{
    static const unsigned char al[] = { 0x00, 0x09, 0x09, 'h', '2' };  /* proto len 9, body 2 */
    char j[64], f[8];
    INIT_SSL(s);
    s.ext[0].type = 0x0010; s.ext[0].data = al; s.ext[0].len = sizeof(al); s.next_ext = 1;
    s.exts = (int[]){ 0x0010 }; s.exts_n = 1;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 8, 2, f);
    ASSERT_STR("00", f);            /* 3+9>len -> rejected entirely, no over-read */
}

CTEST(ja4x, alpn_embedded_nul_length_driven)
{
    static const unsigned char al[] = { 0x00, 0x04, 0x03, 'h', 0x00, '2' };  /* proto {h,NUL,2} */
    char j[64], f[8];
    INIT_SSL(s);
    s.ext[0].type = 0x0010; s.ext[0].data = al; s.ext[0].len = sizeof(al); s.next_ext = 1;
    s.exts = (int[]){ 0x0010 }; s.exts_n = 1;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 8, 2, f);
    ASSERT_STR("h2", f);            /* length-driven (3 bytes), first 'h' last '2'; not strlen-cut at NUL */
}


/* ===== SNI byte / ext count / proto / cleanup ============================= */

CTEST(ja4x, sni_presence_byte)
{
    char j[64];
    INIT_SSL(a); a.exts = (int[]){ 0x0000, 0x0005 }; a.exts_n = 2;  /* SNI present */
    ASSERT_TRUE(run_ja4(&a, j) > 0);
    ASSERT_TRUE(j[3] == 'd');
    INIT_SSL(b); b.exts = (int[]){ 0x0005, 0x000a }; b.exts_n = 2;  /* no SNI */
    ASSERT_TRUE(run_ja4(&b, j) > 0);
    ASSERT_TRUE(j[3] == 'i');
}

CTEST(ja4x, ext_count_field)
{
    char j[64], f[8];
    INIT_SSL(s); s.exts = (int[]){ 0x0000, 0x0010, 0x0005, 0x000d }; s.exts_n = 4;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    field(j, 6, 2, f);
    ASSERT_STR("04", f);
}

CTEST(ja4x, is_quic_proto_char)
{
    char j[64];
    INIT_SSL(a); a.is_quic = 1; a.exts = (int[]){ 0x0005 }; a.exts_n = 1;
    ASSERT_TRUE(run_ja4(&a, j) > 0);
    ASSERT_TRUE(j[0] == 'q');
    INIT_SSL(b); b.is_quic = 0; b.exts = (int[]){ 0x0005 }; b.exts_n = 1;
    ASSERT_TRUE(run_ja4(&b, j) > 0);
    ASSERT_TRUE(j[0] == 't');
}

/* the allocating getter's buffer is freed on the success path (CWE-401). */
CTEST(ja4x, ext_ids_freed)
{
    char j[64];
    INIT_SSL(s); s.exts = (int[]){ 0x0000, 0x0005 }; s.exts_n = 2;
    ASSERT_TRUE(run_ja4(&s, j) > 0);
    ASSERT_EQUAL(1, s.ext_freed);   /* OPENSSL_free(ext_ids) ran exactly once */
}

/* NULL out pointer -> NGX_ERROR, no write (the extractor's hard error). */
CTEST(ja4x, null_out_is_error)
{
    static char  dummy_arena[1];
    INIT_SSL(s); s.exts = (int[]){ 0x0005 }; s.exts_n = 1;
    g_last = &s;
    /* non-NULL ssl + non-NULL pool + NULL out -> isolates the out==NULL guard. */
    ASSERT_EQUAL(NGX_ERROR,
        (int) ngx_http_heavybag_ja4_compute((SSL *) &s, (ngx_pool_t *) dummy_arena, NULL));
}


/* ===== array-fill caps + odd-end + error path (CWE-125/787/401) ========== */

/* >256 extension ids: the n_ext < HEAVYBAG_JA4_MAX_ELEMS cap must stop the
 * exts[256] fill. Under ASan a broken cap is a hard stack-buffer-overflow;
 * the count field clamps to 99 (mirrors cipher_count_over_max_clamps). */
CTEST(ja4x, ext_count_over_max_clamps)
{
    static int  many[400];
    char j[64], f[8];
    for (int i = 0; i < 400; i++) { many[i] = 0x0100 + i; }   /* distinct, non-GREASE */
    INIT_SSL(s); s.exts = many; s.exts_n = 400;
    ASSERT_TRUE(run_ja4(&s, j) > 0);   /* no over-write of exts[HEAVYBAG_JA4_MAX_ELEMS] */
    field(j, 6, 2, f);
    ASSERT_STR("99", f);               /* ext count field clamped to 99 */
}

/* signature_algorithms with an ODD `end`: list length 0x0003 -> end = 2 + 3 = 5
 * == len. The loop `i + 1 < end` reads EXACTLY ONE entry (p[2..3]=0x0403) at
 * i=2 and stops at i=4 (4+1 < 5 is false), dropping the dangling byte p[4]. A
 * regressed bound (`i + 1 <= end`) would read p[4..5] -- p[5] is one past this
 * EXACTLY-5-byte heap allocation, so ASan flags a heap-buffer-overflow. The
 * even-`end` vectors above could mask such an off-by-one; this one cannot. */
CTEST(ja4x, sigalgs_odd_end_exact_count)
{
    unsigned char  *sa = malloc(5);
    char            j_odd[64], j_clean[64];

    ASSERT_NOT_NULL(sa);
    sa[0] = 0x00; sa[1] = 0x03; sa[2] = 0x04; sa[3] = 0x03; sa[4] = 0x08;
    INIT_SSL(a);
    a.ext[0].type = 0x000d; a.ext[0].data = sa; a.ext[0].len = 5; a.next_ext = 1;
    a.exts = (int[]){ 0x000d }; a.exts_n = 1;
    ASSERT_TRUE(run_ja4(&a, j_odd) > 0);
    free(sa);

    /* EXACT count proof: a clean list carrying exactly that one sigalg (0x0403)
     * with identical extensions -> identical JA4_c. Had the trailing 0x08 been
     * (mis)read as a half/whole entry, n_sig would differ and JA4_c with it. */
    {
        static const unsigned char clean[] = { 0x00, 0x02, 0x04, 0x03 };  /* list=2, 1 entry */
        INIT_SSL(b);
        b.ext[0].type = 0x000d; b.ext[0].data = clean; b.ext[0].len = sizeof(clean); b.next_ext = 1;
        b.exts = (int[]){ 0x000d }; b.exts_n = 1;
        ASSERT_TRUE(run_ja4(&b, j_clean) > 0);
        ASSERT_TRUE(memcmp(j_odd + 24, j_clean + 24, 12) == 0);   /* EXACTLY one sigalg */
    }
}

/* error path: with extensions present (ext_ids ALLOCATED), force the out->data
 * allocation to fail so the extractor takes `goto cleanup` with rc=NGX_ERROR.
 * ext_ids must STILL be freed on this error path (CWE-401), not just on success.
 * The existing null_out_is_error test returns before ext_ids is ever allocated,
 * so it cannot prove the cleanup-label free fires on a mid-function failure. */
CTEST(ja4x, error_path_frees_ext_ids)
{
    char j[64];
    int  rc;
    INIT_SSL(s); s.exts = (int[]){ 0x0000, 0x0005 }; s.exts_n = 2;   /* ext_ids allocated */
    g_pnalloc_fail = 1;             /* dst = ngx_pnalloc(...) returns NULL -> goto cleanup */
    rc = run_ja4(&s, j);
    g_pnalloc_fail = 0;
    ASSERT_EQUAL(-1, rc);           /* extractor returned NGX_ERROR via the cleanup label */
    ASSERT_EQUAL(1, s.ext_freed);   /* ext_ids reclaimed on the ERROR path too */
}


/* ===== end-to-end real vector ============================================= *
 * The FoxIO canonical ClientHello, driven as RAW getter bytes through the
 * extractor, must reproduce the PUBLISHED JA4. Every other test in this file is
 * STRUCTURAL (byte offsets / two builds compared); this one pins the FULL
 * wire-parse -> core pipeline against a real, published fingerprint.
 *
 * The component values are the FoxIO reference vector (identical to the arrays
 * test-ja4.c feeds straight to the build core, expected
 * t13d1516h2_8daaf6152771_e5627efa2ab1) -- NOT invented. Its cipher hash
 * 8daaf6152771 is the same JA4_b carried by the Chromium row of
 * .claude/tmp/ja4plus-mapping.csv (t13d1516h2_8daaf6152771_02713d6af862), i.e.
 * this canonical hello shares Chrome's cipher list; the JA4_c differs only in
 * the extension/sigalg set, which the CSV does not carry as raw bytes (and we
 * refuse to fabricate per-browser ext lists). Here the raw bytes pass through
 * the cipher 2-byte decode, the supported_versions (0x002b) parse, the
 * signature_algorithms (0x000d) parse and the ALPN (0x0010) parse before
 * reaching the core -- so a regression in ANY getter-parse step would change
 * the published string.
 * ========================================================================= */
CTEST(ja4x, foxio_canonical_through_extractor)
{
    /* cipher_suites: GREASE 0x5a5a + the 15 real suites, 2-byte big-endian */
    static const unsigned char  cip[] = {
        0x5a,0x5a, 0x13,0x01, 0x13,0x02, 0x13,0x03, 0xc0,0x2b, 0xc0,0x2f,
        0xc0,0x2c, 0xc0,0x30, 0xcc,0xa9, 0xcc,0xa8, 0xc0,0x13, 0xc0,0x14,
        0x00,0x9c, 0x00,0x9d, 0x00,0x2f, 0x00,0x35
    };
    /* extensions present: 2 GREASE + SNI(0x0000) + ALPN(0x0010) + the rest,
     * incl sigalgs(0x000d) and supported_versions(0x002b) */
    static int  exts[] = {
        0xfafa, 0x1a1a, 0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d,
        0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
        0x4469, 0xff01
    };
    /* supported_versions (0x002b) body: 1-byte list len, then GREASE + 0x0304
     * -> the extractor skips GREASE and picks 0x0304 (TLS 1.3) */
    static const unsigned char  sv[] = { 0x04, 0x5a,0x5a, 0x03,0x04 };
    /* signature_algorithms (0x000d) body: 2-byte list len (16), then 8 entries
     * in ORIGINAL order (JA4 keeps sigalg order) */
    static const unsigned char  sa[] = {
        0x00,0x10, 0x04,0x03, 0x08,0x04, 0x04,0x01, 0x05,0x03,
        0x08,0x05, 0x05,0x01, 0x08,0x06, 0x06,0x01
    };
    /* ALPN (0x0010) body: 2-byte list len (3), 1-byte proto len (2), "h2" */
    static const unsigned char  al[] = { 0x00,0x03, 0x02, 'h','2' };
    char  j[64];

    INIT_SSL(s);                         /* legacy_version 0x0303 */
    s.ciphers = cip;  s.ciphers_len = sizeof(cip);
    s.exts = exts;    s.exts_n = sizeof(exts) / sizeof(exts[0]);
    s.ext[0].type = 0x002b; s.ext[0].data = sv; s.ext[0].len = sizeof(sv);
    s.ext[1].type = 0x000d; s.ext[1].data = sa; s.ext[1].len = sizeof(sa);
    s.ext[2].type = 0x0010; s.ext[2].data = al; s.ext[2].len = sizeof(al);
    s.next_ext = 3;

    ASSERT_EQUAL(36, run_ja4(&s, j));
    ASSERT_STR("t13d1516h2_8daaf6152771_e5627efa2ab1", j);
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
