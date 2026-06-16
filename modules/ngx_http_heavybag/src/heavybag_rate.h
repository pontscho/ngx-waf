/*
 * ngx_http_heavybag_module - lock-free per-IP token-bucket rate limiter
 *
 * The roadmap's only stateful feature: a fixed-size, lock-free, open-addressed
 * per-IP table (modelled on the cc[512] country table, NOT nginx limit_req's
 * rbtree+mutex). One shared zone ("waf_rate", HTTP-owned, user-sized) is poked
 * by all three heads through the opaque API below; the slot/header layout is
 * private to heavybag_rate.c, so this header stays context-neutral (ngx_core only)
 * and is includable from the stream / mail translation units.
 *
 * Token bucket (leaky-bucket semantics, smooth rate): each rule carries a
 * fixed-point rate numerator, a period and a burst capacity (all SCALE-scaled,
 * SCALE = 1000). The caller resolves which rule applies (reputation-aware via
 * for_geo) and passes the parameters; heavybag_rate.c owns the math and the CAS.
 */

#ifndef _HEAVYBAG_RATE_H_INCLUDED_
#define _HEAVYBAG_RATE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "heavybag_rep.h"   /* ngx_http_heavybag_verdict_t for the rule selector */


/* fixed-point scale: 1 token == HEAVYBAG_RATE_SCALE internal units */
#define HEAVYBAG_RATE_SCALE  1000


/*
 * One rate rule. A NULL geo_cc marks the default rule (at most one per rule
 * set, enforced at config time); a non-NULL geo_cc is a reputation-scoped
 * override matched against the verdict country (packed uint16, same encoding
 * as ngx_http_heavybag_country_add). Stored in an ngx_array_t on the HTTP location
 * conf and the STREAM server conf. ngx_core-only so both heads share it.
 *
 * rate_num_fp / period_ms / burst_fp are pre-validated (see
 * ngx_http_heavybag_rate_rule_add): rate_num_fp in (0, UINT32_MAX], burst_fp in
 * (0, UINT32_MAX], period_ms in {1000, 60000, 3600000}. Refill is
 * added = elapsed_ms * rate_num_fp / period_ms, computed in 64-bit with the
 * division last; the bounds make the product provably non-overflowing.
 */
typedef struct {
    uint64_t      rate_num_fp;   /* tokens-per-period numerator * SCALE   */
    ngx_uint_t    period_ms;     /* 1000 (/s) | 60000 (/m) | 3600000 (/h) */
    ngx_uint_t    burst_fp;      /* bucket capacity in SCALE units        */
    ngx_array_t  *geo_cc;        /* packed uint16 CC list; NULL = default  */
} ngx_http_heavybag_rate_rule_t;


/*
 * Per-IP verdict for *sa under *rule. NGX_OK = allow, NGX_BUSY = deny (over
 * limit). A NULL shm (zone never declared / not yet populated) is fail-open
 * (NGX_OK), as is an unsupported address family and any CAS starvation: the
 * limiter never produces a false positive ban. shm is the resolved
 * zone->data.
 */
ngx_int_t ngx_http_heavybag_rate_check(void *shm, struct sockaddr *sa,
    uint64_t rate_num_fp, ngx_uint_t period_ms, ngx_uint_t burst_fp);

/*
 * Pick the rule for *verdict from *rules: the first for_geo rule whose CC list
 * contains the verdict country (only when a geo lookup actually ran), else the
 * default rule. Returns NULL when no rule applies (only for_geo rules and no
 * country match, with no default) -> the caller skips the check.
 */
ngx_http_heavybag_rate_rule_t *ngx_http_heavybag_rate_rule_select(ngx_array_t *rules,
    ngx_http_heavybag_verdict_t *verdict);

/*
 * Parse one "rate=Nr/s|Nr/m|Nr/h [burst=N] [for_geo=CC,CC,...]" directive
 * from cf->args and append the resulting rule to *rules (created on first
 * use). Shared by the HTTP and STREAM setters. Returns NGX_CONF_OK, a static
 * error string, or NGX_CONF_ERROR.
 */
char *ngx_http_heavybag_rate_rule_add(ngx_conf_t *cf, ngx_array_t **rules);

/* shm init callback for the waf_rate zone (user-sized; HTTP head installs it) */
ngx_int_t ngx_http_heavybag_rate_init_zone(ngx_shm_zone_t *shm_zone, void *data);

/* table-saturation drop count (eviction-CAS failures); 0 when shm is NULL */
ngx_atomic_uint_t ngx_http_heavybag_rate_overflow(void *shm);


#endif /* _HEAVYBAG_RATE_H_INCLUDED_ */
