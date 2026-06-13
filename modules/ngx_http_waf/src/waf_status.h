/*
 * ngx_http_waf_module - lock-free statistics / status subsystem
 *
 * One always-on shared-memory zone ("waf_status") holds a single fixed
 * ngx_atomic_t counter struct plus a trailing per-vhost array, allocated
 * once via ngx_slab_alloc at init. The request hot path only ever does
 * ngx_atomic_fetch_add / ngx_atomic_cmp_set against it - no slab, no rbtree,
 * no mutex. The HTTP head owns the layout and renders it through the
 * waf_status content handler; the STREAM head (which must not pull in
 * ngx_http.h) pokes the same zone through the opaque-pointer helpers
 * declared in waf_rep.h, so it never sees this struct.
 *
 * Dimensions are bounded by construction (closed-set country table, a
 * config-time vhost array) - never per-IP - so the zone size is fixed at
 * configuration time.
 */

#ifndef _WAF_STATUS_H_INCLUDED_
#define _WAF_STATUS_H_INCLUDED_


#include "ngx_http_waf.h"


/* Per-country open-addressed table: a closed set (ISO-3166 + libloc A1/A2/A3/
 * T1/XD specials) well under this bound. A power of two keeps the probe mask
 * cheap. */
#define WAF_STAT_CC_SLOTS  512

/* Real libloc network-flag bits: anon-proxy, satellite, anycast, drop. Tor
 * has NO flag bit (it surfaces as the CC "T1" geo verdict), so it is counted
 * via the per-country table, not here. */
#define WAF_FLAG_SLOTS     4


/*
 * One per-country slot, claimed lock-free by ngx_http_waf_stat_cc_bump():
 * cc16 == 0 marks an empty slot (no real ISO-2 code packs to 0 because both
 * bytes are printable uppercase ASCII), claimed with ngx_atomic_cmp_set.
 */
typedef struct {
    ngx_atomic_t  cc16;     /* packed ISO-2 (c0<<8|c1); 0 = empty slot   */
    ngx_atomic_t  total;    /* requests/connections seen from this CC    */
    ngx_atomic_t  blocked;  /* of those, how many were blocked           */
} ngx_http_waf_stat_cc_t;


/*
 * Per-vhost HTTP verdict subset, indexed by the server's stat_index. The
 * array of nvhosts of these is laid out contiguously right after the fixed
 * struct in the same shm allocation (see ngx_http_waf_stat_vhost()).
 */
typedef struct {
    ngx_atomic_t  requests;               /* requests routed to this vhost */
    ngx_atomic_t  allowed;                /* allowed (no block)            */
    ngx_atomic_t  blocked[WAF_REASON_MAX];/* blocks broken down by reason  */
} ngx_http_waf_stat_vhost_t;


/*
 * The fixed counter section. ngx_atomic_fetch_add only on the hot path.
 * start_time / last_reload_time are plain time_t stamped once at init /
 * reload. nvhosts is the length of the trailing per-vhost array, stored so
 * a snapshot reader is self-contained. Indices: http_blocked / stream_denied
 * by ngx_http_waf_reason_e; http_scanner_path by ngx_http_waf_action_e
 * (404/403/444); http_ua by ngx_http_waf_ua_e; flag_blocked by the bit->slot
 * mapping in waf_status.c.
 */
typedef struct {
    time_t        start_time;        /* fresh-segment creation stamp       */
    time_t        last_reload_time;  /* bumped on reload re-attach         */
    ngx_uint_t    nvhosts;           /* length of the trailing vhost array */

    /* HTTP global verdict counters */
    ngx_atomic_t  http_requests_total;
    ngx_atomic_t  http_allowed;
    ngx_atomic_t  http_allowlist_hits;
    ngx_atomic_t  http_blocked[WAF_REASON_MAX];
    ngx_atomic_t  http_would_block[WAF_REASON_MAX];  /* detect-mode: would block */
    ngx_atomic_t  http_scanner_path[WAF_ACTION_MAX]; /* 404 / 403 / 444     */
    ngx_atomic_t  http_resp_403;
    ngx_atomic_t  http_resp_404;
    ngx_atomic_t  http_resp_444;
    ngx_atomic_t  http_ua[WAF_UA_MAX];
    ngx_atomic_t  flag_blocked[WAF_FLAG_SLOTS];

    /* STREAM (L4) global verdict counters */
    ngx_atomic_t  stream_connections_total;
    ngx_atomic_t  stream_allowed;
    ngx_atomic_t  stream_denied[WAF_REASON_MAX];
    ngx_atomic_t  stream_would_block[WAF_REASON_MAX]; /* detect-mode: would deny */

    /* per-country open-addressed table (shared by HTTP + STREAM) */
    ngx_atomic_t            cc_overflow;          /* table-full drops       */
    ngx_http_waf_stat_cc_t  cc[WAF_STAT_CC_SLOTS];
} ngx_http_waf_stat_shm_t;


/*
 * Base of the per-vhost array, which follows the fixed struct in the same
 * allocation. sizeof(ngx_http_waf_stat_shm_t) is word-aligned and so is the
 * vhost struct, so the contiguous placement stays correctly aligned. Callers
 * must bounds-check idx < sh->nvhosts before use.
 */
#define ngx_http_waf_stat_vhost(sh, idx)                                      \
    (&((ngx_http_waf_stat_vhost_t *)                                          \
        ((u_char *) (sh) + sizeof(ngx_http_waf_stat_shm_t)))[idx])


/*
 * Per-{main,server} configuration for the HTTP head. The zone is added in
 * postconfiguration once nvhosts is known (it sizes the zone). stat_index is
 * assigned per server{} by the postconfiguration walk; NGX_CONF_UNSET means
 * unassigned (the hot path falls back to slot 0 after a bounds check).
 */
typedef struct {
    ngx_shm_zone_t  *stat_zone;
    ngx_uint_t       nvhosts;
} ngx_http_waf_main_conf_t;

typedef struct {
    ngx_uint_t  stat_index;
} ngx_http_waf_srv_conf_t;


/* The waf_status content handler (installed by the waf_status directive). */
ngx_int_t ngx_http_waf_status_handler(ngx_http_request_t *r);

/*
 * enum -> token string tables, defined in ngx_http_waf_module.c and consumed
 * by the serializers ($waf_type / $waf_reason tokens; reused as metric labels).
 */
extern ngx_str_t  waf_type_str[WAF_UA_MAX];
extern ngx_str_t  waf_reason_str[WAF_REASON_MAX];


#endif /* _WAF_STATUS_H_INCLUDED_ */
