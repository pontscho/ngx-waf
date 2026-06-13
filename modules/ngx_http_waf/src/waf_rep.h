/*
 * ngx_http_waf_module - shared reputation configuration + core
 *
 * One decision function feeds three heads: the HTTP PREACCESS phase, the
 * SMTP auth_http endpoint and the stream (L4) access phase. The reputation
 * inputs are gathered in ngx_waf_rep_conf_t, embedded in the HTTP location
 * conf and the stream server conf (the mail head reuses the HTTP one).
 *
 * This header is deliberately context-neutral (ngx_core only): it must be
 * includable from both the HTTP and the stream translation units without
 * pulling in ngx_http.h / ngx_stream.h.
 */

#ifndef _WAF_REP_H_INCLUDED_
#define _WAF_REP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* full type lives in waf_geo.h; only the pointer is stored here */
struct ngx_http_waf_geo_db_s;


typedef struct {
    struct ngx_http_waf_geo_db_s  *geo_db;     /* waf_geo_db               */
    ngx_array_t                   *block_cc;   /* uint16 packed CC, block  */
    ngx_array_t                   *allow_cc;   /* uint16 packed CC, allow  */
    ngx_array_t                   *block_asn;  /* uint32 ASN, block        */
    uint16_t                       flag_mask;  /* libloc flags to block    */
    ngx_array_t                   *blocklist;  /* ngx_cidr_t -> deny       */
    ngx_array_t                   *allowlist;  /* ngx_cidr_t -> allow      */
} ngx_waf_rep_conf_t;


/*
 * Block/deny reason - the single source of truth feeding the per-reason
 * counter index, the $waf_reason variable token and the human log string.
 * Lives here (ngx_core-only header) so the stream translation unit sees it
 * without pulling in ngx_http.h. Keep in lockstep with waf_reason_str[] in
 * ngx_http_waf_module.c (WAF_REASON_MAX == that table's cardinality).
 */
typedef enum {
    WAF_REASON_NONE = 0,       /* allowed: no rule matched          */
    WAF_REASON_ALLOWLIST,      /* allowlist CIDR short-circuit      */
    WAF_REASON_BLOCKLIST,      /* static blocklist CIDR (403)       */
    WAF_REASON_GEO,            /* geo country block (403)           */
    WAF_REASON_GEO_WHITELIST,  /* geo whitelist miss (404)          */
    WAF_REASON_FLAG,           /* libloc network flag (403)         */
    WAF_REASON_SCANNER_UA,     /* scanner / hostile UA (404)        */
    WAF_REASON_EMPTY_UA,       /* missing / empty UA (404)          */
    WAF_REASON_SCANNER_PATH,   /* scanner path regex (404/403/444)  */
    WAF_REASON_ASN,            /* ASN block (403)                   */
    WAF_REASON_METHOD,         /* HTTP method filter (404)          */
    WAF_REASON_MAX
} ngx_http_waf_reason_e;


/*
 * WAF gate mode (the `waf` / `waf_stream` directive). Three-state enum so a
 * config can observe-only (detect) without blocking. `on` is an alias for
 * enforce (backward compatibility). Fail-CLOSED invariant: detect is the ONLY
 * non-blocking value; any other value takes the blocking path.
 */
#define WAF_MODE_OFF      0
#define WAF_MODE_DETECT   1
#define WAF_MODE_ENFORCE  2


/*
 * Write-only side data filled by ngx_http_waf_reputation_check(): the caller
 * passes a stack instance, or NULL when it wants no side data (the SMTP-auth
 * head). It never alters the control flow / verdict; every write is
 * NULL-guarded. Primitive geo fields only (country/flags) - the full
 * ngx_http_waf_geo_result_t lives in waf_geo.h, invisible to the stream TU.
 */
typedef struct {
    ngx_http_waf_reason_e  reason;      /* set on every return path           */
    u_char                 country[2];  /* copied from res.country; {0,0}=none */
    uint16_t               flags;       /* copied from res.flags              */
    uint32_t               asn;         /* copied from res.asn; 0=unknown     */
    unsigned               geo_valid:1; /* a geo lookup actually ran          */
} ngx_http_waf_verdict_t;


/*
 * Verdict for *sa. Returns NGX_DECLINED to allow, or a forbidden status to
 * deny: NGX_HTTP_FORBIDDEN (403) for blocklist / network-flag / geo-block,
 * NGX_HTTP_NOT_FOUND (404) for a geo-whitelist miss. On deny *reason is set
 * to a static description for logging / Auth-Status. The numeric codes are
 * HTTP values; non-HTTP heads key off "!= NGX_DECLINED" and the reason.
 *
 * *out (when non-NULL) receives the reason enum on every return path, plus
 * the geo country/flags and geo_valid when a lookup actually ran. It is
 * write-only side data that never changes the verdict; the SMTP-auth head
 * passes NULL, so every out-> write is NULL-guarded.
 */
ngx_int_t ngx_http_waf_reputation_check(ngx_waf_rep_conf_t *rep,
    struct sockaddr *sa, ngx_str_t *reason, ngx_http_waf_verdict_t *out);

/* Append a "addr/prefix" CIDR to *arr (created on first use). */
ngx_int_t ngx_http_waf_cidr_add(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *text);

/* Append an ISO-3166 alpha-2 country code (packed uint16) to *arr. */
ngx_int_t ngx_http_waf_country_add(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *cc);

/* Append a decimal autonomous-system number (uint32) to *arr. */
ngx_int_t ngx_http_waf_asn_add(ngx_conf_t *cf, ngx_array_t **arr,
    ngx_str_t *val);

/* Map a flag name (anonymous-proxy/satellite/anycast/drop/tor) into *rep. */
ngx_int_t ngx_http_waf_flag_add(ngx_conf_t *cf, ngx_waf_rep_conf_t *rep,
    ngx_str_t *tok);

/*
 * Open and mmap the libloc geo database at *path (config-time); NULL on
 * error (already logged). Defined in waf_geo.c. Re-declared here (the full
 * ngx_http_waf_geo_db_t type lives in waf_geo.h) so the stream head can wire
 * waf_geo_db without including the HTTP-flavoured waf_geo.h / ngx_http.h.
 */
struct ngx_http_waf_geo_db_s *ngx_http_waf_geo_open(ngx_conf_t *cf,
    ngx_str_t *path);


/*
 * Lock-free status-counter helpers shared with the STREAM head.
 *
 * The shm layout type (ngx_http_waf_stat_shm_t) is HTTP-only - it sizes
 * arrays with WAF_UA_MAX etc. and lives in waf_status.h, which pulls in
 * ngx_http.h. The stream translation unit must stay ngx_core-only, so it
 * pokes the SAME zone through these opaque-pointer helpers (defined in the
 * HTTP unit where the full struct is visible) and never sees the struct.
 * *shm is the resolved zone->data (NULL-safe: a NULL shm is a no-op).
 */
void ngx_http_waf_stat_cc_bump(void *shm, uint16_t cc16, ngx_uint_t blocked);
void ngx_http_waf_stat_stream_bump(void *shm, ngx_http_waf_reason_e reason,
    ngx_uint_t denied);

/*
 * STREAM-safe detect-mode counter: bump stream_would_block[reason] in the shm
 * zone without the stream TU seeing ngx_http_waf_stat_shm_t. Mirrors
 * ngx_http_waf_stat_stream_bump; defined in the HTTP unit. NULL shm is a no-op.
 */
void ngx_http_waf_stat_stream_would_block(void *shm,
    ngx_http_waf_reason_e reason);


#endif /* _WAF_REP_H_INCLUDED_ */
