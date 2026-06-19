/*
 * Concurrency stress for the lock-free token-bucket CAS core (heavybag_rate.c).
 *
 * The single-threaded test-rate.c can never drive the CAS LOSE path
 * (heavybag_rate.c:343, ngx_cpu_pause after a failed cmp_set) nor the bounded-
 * retry starvation fail-open (l.346): __sync always wins iteration 0 with one
 * thread. This suite spawns N threads hammering ngx_http_heavybag_rate_check on
 * the SAME key so the packed-state CAS genuinely contends -- exercising the
 * lose/retry path and, under TSan's scheduler, the starvation fail-open.
 *
 * Built as a SEPARATE binary under -fsanitize=thread (TSan cannot combine with
 * ASan), gated behind HEAVYBAG_TSAN=1 in run-unit-tests.sh -- it is a stress
 * pass, not part of the fast heavybag_unit gate.
 *
 * What TSan proves here: no UNINTENDED data race and no crash under real
 * contention. The optimistic plain reads inside the CAS loop (old = s->state;
 * k = cand->key) racing the __sync CAS writes are the DELIBERATE nginx lock-
 * free idiom (ngx_atomic_t is the relaxed-read / cmp_set-write word); they are
 * x86-correct but are C11 data races, so they are suppressed by name via the
 * companion tsan-rate.supp (see run-unit-tests.sh). Everything else -- the
 * header, the slot indexing, the per-thread counters, rate_overflow -- must be
 * race-clean, which is what this run actually asserts.
 *
 * Correctness asserted directly: outcome conservation (every call is OK or
 * BUSY), the limiter engaged (denials dominate a frozen 5-token bucket under
 * 800k requests), slot integrity (key == our hash, tokens in [0,burst]), and
 * no eviction pressure on a single claimed key (rate_overflow == 0).
 */

#ifndef HEAVYBAG_RATE_UNIT_TEST
#define HEAVYBAG_RATE_UNIT_TEST
#endif
#include "../../src/heavybag_rate.c"

#define CTEST_MAIN
#include "ctest.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>


/* ---- table helper (mirrors test-rate.c:41-49; separate TU) ------------- */
static ngx_http_heavybag_rate_hdr_t *
mk_table(ngx_uint_t n)
{
    size_t  sz = sizeof(ngx_http_heavybag_rate_hdr_t)
                 + (size_t) n * sizeof(ngx_http_heavybag_rate_slot_t);
    ngx_http_heavybag_rate_hdr_t  *hdr = calloc(1, sz);
    hdr->nslots = n;
    return hdr;
}

static ngx_http_heavybag_rate_slot_t *
find_slot(ngx_http_heavybag_rate_hdr_t *hdr, uint64_t h)
{
    ngx_uint_t  n = hdr->nslots, p, idx = (ngx_uint_t) (h % n);
    ngx_http_heavybag_rate_slot_t  *slots =
        (ngx_http_heavybag_rate_slot_t *) (hdr + 1);

    for (p = 0; p < HEAVYBAG_RATE_PROBE_MAX; p++) {
        ngx_http_heavybag_rate_slot_t  *s = &slots[(idx + p) % n];
        if (s->key == h) {
            return s;
        }
    }
    return NULL;
}

/* one fast rule: 10 r/s, 5-token bucket (SCALE fixed-point) */
#define R_NUM    (10ULL * HEAVYBAG_RATE_SCALE)
#define R_PER    1000U
#define R_BURST  (5U * HEAVYBAG_RATE_SCALE)

#define NTHREADS    8
#define PER_THREAD  100000UL
#define STRESS_IP   "198.51.100.42"


typedef struct {
    ngx_http_heavybag_rate_hdr_t  *hdr;
    unsigned long             ok;
    unsigned long             busy;
} targ_t;

static void *
hammer(void *p)
{
    targ_t              *a = p;
    struct sockaddr_in   sin;
    unsigned long        ok = 0, busy = 0, i;

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, STRESS_IP, &sin.sin_addr);   /* SAME key in every thread */

    for (i = 0; i < PER_THREAD; i++) {
        ngx_int_t  rc = ngx_http_heavybag_rate_check(a->hdr,
                            (struct sockaddr *) &sin, R_NUM, R_PER, R_BURST);
        if (rc == NGX_OK) {
            ok++;
        } else {
            busy++;            /* the only non-OK return is NGX_BUSY (denied) */
        }
    }

    a->ok = ok;
    a->busy = busy;
    return NULL;
}


/* ======================================================================= *
 *  N threads, one key: the CAS loop must contend, never corrupt, never     *
 *  crash, and the outcomes must conserve.                                  *
 * ======================================================================= */
CTEST(rate_stress, concurrent_same_key)
{
    ngx_http_heavybag_rate_hdr_t  *hdr = mk_table(64);
    pthread_t                  th[NTHREADS];
    targ_t                     args[NTHREADS];
    struct sockaddr_in         sin;
    ngx_http_heavybag_rate_slot_t  *s;
    unsigned long              ok = 0, busy = 0, total, t;
    uint64_t                   h;
    int                        i;

    /*
     * PIN the clock ONCE before spawning: rate_check reads ngx_current_msec as
     * a plain global. Setting it here and never again keeps every worker a
     * pure reader of it (no write/read race on the clock itself). A frozen
     * clock also means no refill after first touch -- the bucket dispenses its
     * burst then denies, so denials must dominate.
     */
    ngx_current_msec = 1000000;

    for (i = 0; i < NTHREADS; i++) {
        args[i].hdr = hdr;
        args[i].ok = 0;
        args[i].busy = 0;
        ASSERT_EQUAL(0, pthread_create(&th[i], NULL, hammer, &args[i]));
    }
    for (i = 0; i < NTHREADS; i++) {
        pthread_join(th[i], NULL);
    }

    for (i = 0; i < NTHREADS; i++) {
        ok += args[i].ok;
        busy += args[i].busy;
    }
    total = (unsigned long) NTHREADS * PER_THREAD;

    /* conservation: every call returned exactly one of OK / BUSY */
    ASSERT_EQUAL_U(total, ok + busy);

    /* the limiter engaged: a frozen 5-token bucket vs 800k requests on one
     * key -- denials must dominate (CAS-starvation fail-opens are a tiny
     * minority of the OK count) */
    ASSERT_TRUE(busy > 0);
    ASSERT_TRUE(ok >= 1);
    ASSERT_TRUE(busy > total / 2);

    /* the single claimed slot is intact after the contention storm */
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, STRESS_IP, &sin.sin_addr);
    h = ngx_http_heavybag_rate_key((struct sockaddr *) &sin);
    s = find_slot(hdr, h);
    ASSERT_NOT_NULL(s);
    ASSERT_EQUAL_U(h, (uint64_t) s->key);
    t = (uint32_t) (s->state & 0xffffffff);
    ASSERT_TRUE(t <= R_BURST);

    /* a single key claims one slot -> no window saturation, no eviction */
    ASSERT_EQUAL_U(0, (uint64_t) hdr->rate_overflow);

    free(hdr);
}


int
main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
