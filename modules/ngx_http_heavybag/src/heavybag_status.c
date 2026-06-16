/*
 * ngx_http_heavybag_module - waf_status content handler + serializers
 *
 * Installed by the `waf_status;` directive on a location. Restricts to
 * GET/HEAD, snapshots the lock-free shm counter struct once, parses the
 * last URI path segment to pick a format (/waf/stat/{prometheus,json,plain},
 * default plain) and renders the counter model. Runs in the CONTENT phase,
 * so the ACCESS phase (allow/deny) is enforced before any counter is shown.
 *
 * SECURITY: every attacker-influenceable byte (geo-DB country codes, server
 * names) is escaped UNCONDITIONALLY at the serializer boundary - JSON per
 * RFC 8259, Prometheus label values per the text-exposition rules. The geo
 * health block exposes only the network count and mapped size, never the
 * database path or build host. No client IP / PII is ever emitted.
 */

#include "ngx_http_heavybag.h"
#include "heavybag_geo.h"
#include "heavybag_status.h"
#include "heavybag_rate.h"
#include "heavybag_ua_parse.h"


#define HEAVYBAG_STAT_FMT_PLAIN       0
#define HEAVYBAG_STAT_FMT_JSON        1
#define HEAVYBAG_STAT_FMT_PROMETHEUS  2

/* generous per-metric-line upper bound (token + number + punctuation) */
#define HEAVYBAG_STAT_LINE            256


static ngx_str_t  heavybag_stat_ct_text = ngx_string("text/plain");
static ngx_str_t  heavybag_stat_ct_json = ngx_string("application/json");

/* flag_blocked[] slot labels, parallel to waf_flag_bits[] in the module TU */
static const char *heavybag_flag_label[HEAVYBAG_FLAG_SLOTS] = {
    "anon", "satellite", "anycast", "drop"
};


/* Pick the format from the last '/'-delimited URI segment; default plain. */
static ngx_uint_t
ngx_http_heavybag_status_format(ngx_str_t *uri)
{
    u_char  *p;
    size_t   len;

    p = uri->data + uri->len;
    while (p > uri->data && *(p - 1) != '/') {
        p--;
    }
    len = (size_t) (uri->data + uri->len - p);

    if (len == sizeof("prometheus") - 1
        && ngx_strncmp(p, "prometheus", len) == 0)
    {
        return HEAVYBAG_STAT_FMT_PROMETHEUS;
    }

    if (len == sizeof("json") - 1 && ngx_strncmp(p, "json", len) == 0) {
        return HEAVYBAG_STAT_FMT_JSON;
    }

    return HEAVYBAG_STAT_FMT_PLAIN;
}


/*
 * Append s[0..len) to *p (bounded by last), escaping Prometheus label-value
 * specials: backslash, double-quote and newline. Any other control byte
 * (< 0x20) has no text-exposition escape, so it is DROPPED - a hostile or
 * odd server_name cannot break the label or the scrape line. Printable bytes
 * are emitted verbatim; the caller owns the surrounding quotes.
 */
static u_char *
ngx_http_heavybag_prom_escape(u_char *p, u_char *last, u_char *s, size_t len)
{
    size_t  i;
    u_char  c;

    for (i = 0; i < len; i++) {
        c = s[i];

        if (c == '\\' || c == '"' || c == '\n') {
            if (last - p < 2) {
                break;
            }
            *p++ = '\\';
            *p++ = (c == '\n') ? 'n' : c;

        } else if (c < 0x20) {
            /* no text-format escape for other control bytes - drop it */
            continue;

        } else {
            if (p >= last) {
                break;
            }
            *p++ = c;
        }
    }

    return p;
}


/* Render a packed cc16 into two sanitized bytes for the human (plain) format:
 * keep [A-Z0-9], collapse anything else (hostile DB byte) to '?'. */
static void
ngx_http_heavybag_cc_chars(uint16_t cc16, u_char out[2])
{
    u_char  c0 = (u_char) (cc16 >> 8);
    u_char  c1 = (u_char) (cc16 & 0xff);

    out[0] = ((c0 >= 'A' && c0 <= 'Z') || (c0 >= '0' && c0 <= '9')) ? c0 : '?';
    out[1] = ((c1 >= 'A' && c1 <= 'Z') || (c1 >= '0' && c1 <= '9')) ? c1 : '?';
}


/*
 * Fixed (non per-country, non per-vhost) metric-line headroom: health plus all
 * global / reason / would_block / ua / ua_cat / spoofed / flag / scanner / resp
 * lines. A 128-line base covers the format-invariant scalar lines with ample
 * headroom; the enum-indexed counter arrays are added on top so adding a
 * reason / UA / category / action / flag value grows the bound automatically
 * instead of silently overflowing the rendered buffer.
 */
#define HEAVYBAG_STAT_FIXED_LINES                                             \
    (128                       /* format-invariant scalar / health lines */  \
     + 4 * HEAVYBAG_REASON_MAX /* http+stream blocked + would_block       */  \
     + HEAVYBAG_UA_MAX         /* http_ua                                 */  \
     + HEAVYBAG_CAT_MAX        /* http_ua_cat                             */  \
     + HEAVYBAG_ACTION_MAX     /* http_scanner_path                       */  \
     + HEAVYBAG_FLAG_SLOTS)    /* flag_blocked                            */

/*
 * Compute a true upper bound on the rendered body size. Each metric line is
 * capped at HEAVYBAG_STAT_LINE; per-vhost lines additionally carry the server
 * name, whose escaped form can expand up to 6x (JSON \u00XX worst case), so
 * 6*name.len is budgeted per occurrence. All multiplications are guarded
 * against size_t overflow (returns 0 on overflow, which the caller rejects).
 */
static size_t
ngx_http_heavybag_status_bufsize(ngx_uint_t nvhosts,
    ngx_http_core_srv_conf_t **cscfp)
{
    size_t      size, per_vhost_fixed, name_part;
    ngx_uint_t  i;

    /* fixed section: health + all global/reason/would_block/ua/flag/scanner/
     * resp lines (two extra HEAVYBAG_REASON_MAX loops for would_block headroom) */
    size = HEAVYBAG_STAT_FIXED_LINES * HEAVYBAG_STAT_LINE;

    /* per-country: up to two metric lines per slot */
    if (HEAVYBAG_STAT_CC_SLOTS > (NGX_MAX_SIZE_T_VALUE / (2 * HEAVYBAG_STAT_LINE))) {
        return 0;
    }
    size += (size_t) HEAVYBAG_STAT_CC_SLOTS * 2 * HEAVYBAG_STAT_LINE;

    /* per-vhost: (HEAVYBAG_REASON_MAX + 2) lines, each HEAVYBAG_STAT_LINE + name */
    per_vhost_fixed = (size_t) (HEAVYBAG_REASON_MAX + 2) * HEAVYBAG_STAT_LINE;

    for (i = 0; i < nvhosts; i++) {
        name_part = (size_t) (HEAVYBAG_REASON_MAX + 2) * 6 * cscfp[i]->server_name.len;

        if (name_part > NGX_MAX_SIZE_T_VALUE - per_vhost_fixed) {
            return 0;
        }
        name_part += per_vhost_fixed;

        if (name_part > NGX_MAX_SIZE_T_VALUE - size) {
            return 0;
        }
        size += name_part;
    }

    return size;
}


/* --- plain (stub_status-style) ------------------------------------------- */

/*
 * Render the counter snapshot as a stub_status-style plain-text dump into
 * the buffer [p, last): global totals followed by one line group per vhost
 * and per-country/flag breakdown. Returns the advanced write pointer.
 */
static u_char *
ngx_http_heavybag_status_plain(u_char *p, u_char *last,
    ngx_http_heavybag_stat_shm_t *snap, ngx_http_heavybag_stat_shm_t *sh,
    ngx_uint_t nvhosts, ngx_http_core_srv_conf_t **cscfp,
    ngx_http_heavybag_geo_db_t *geo_db, ngx_atomic_uint_t rate_overflow)
{
    u_char                      cc[2];
    time_t                      now;
    ngx_uint_t                  i, idx;
    ngx_http_heavybag_stat_vhost_t  *v;

    now = ngx_time();

    p = ngx_snprintf(p, last - p,
                     "heavybag_up 1\n"
                     "uptime_seconds %T\n"
                     "last_reload %T\n",
                     now - snap->start_time, snap->last_reload_time);

    if (geo_db != NULL) {
        p = ngx_snprintf(p, last - p,
                         "geo_configured 1\n"
                         "geo_networks %uz\n"
                         "geo_db_size_bytes %uz\n",
                         (size_t) (geo_db->block_len[NGX_HTTP_HEAVYBAG_GEO_ND] / 12),
                         geo_db->map_size);
    } else {
        p = ngx_snprintf(p, last - p, "geo_configured 0\n");
    }

    p = ngx_snprintf(p, last - p,
                     "http_requests_total %uA\n"
                     "http_allowed %uA\n"
                     "http_allowlist_hits %uA\n",
                     (ngx_atomic_uint_t) snap->http_requests_total,
                     (ngx_atomic_uint_t) snap->http_allowed,
                     (ngx_atomic_uint_t) snap->http_allowlist_hits);

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "http_blocked_%V %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->http_blocked[i]);
    }

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "http_would_block_%V %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->http_would_block[i]);
    }

    p = ngx_snprintf(p, last - p,
                     "http_resp_403 %uA\n"
                     "http_resp_404 %uA\n"
                     "http_resp_444 %uA\n"
                     "http_resp_429 %uA\n"
                     "http_scanner_path_404 %uA\n"
                     "http_scanner_path_403 %uA\n"
                     "http_scanner_path_444 %uA\n",
                     (ngx_atomic_uint_t) snap->http_resp_403,
                     (ngx_atomic_uint_t) snap->http_resp_404,
                     (ngx_atomic_uint_t) snap->http_resp_444,
                     (ngx_atomic_uint_t) snap->http_resp_429,
                     (ngx_atomic_uint_t) snap->http_scanner_path[HEAVYBAG_ACTION_404],
                     (ngx_atomic_uint_t) snap->http_scanner_path[HEAVYBAG_ACTION_403],
                     (ngx_atomic_uint_t) snap->http_scanner_path[HEAVYBAG_ACTION_444]);

    for (i = 0; i < HEAVYBAG_UA_MAX; i++) {
        p = ngx_snprintf(p, last - p, "http_ua_%V %uA\n",
                         &heavybag_type_str[i],
                         (ngx_atomic_uint_t) snap->http_ua[i]);
    }

    for (i = 0; i < HEAVYBAG_CAT_MAX; i++) {
        p = ngx_snprintf(p, last - p, "http_ua_cat_%V %uA\n",
                         ngx_http_heavybag_category_str((ngx_http_heavybag_ua_category_e) i),
                         (ngx_atomic_uint_t) snap->http_ua_cat[i]);
    }

    p = ngx_snprintf(p, last - p, "http_ua_spoofed %uA\n",
                     (ngx_atomic_uint_t) snap->http_ua_spoofed);

    for (i = 0; i < HEAVYBAG_FLAG_SLOTS; i++) {
        p = ngx_snprintf(p, last - p, "http_flag_%s %uA\n",
                         heavybag_flag_label[i],
                         (ngx_atomic_uint_t) snap->flag_blocked[i]);
    }

    p = ngx_snprintf(p, last - p,
                     "stream_connections_total %uA\n"
                     "stream_allowed %uA\n",
                     (ngx_atomic_uint_t) snap->stream_connections_total,
                     (ngx_atomic_uint_t) snap->stream_allowed);

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "stream_denied_%V %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->stream_denied[i]);
    }

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "stream_would_block_%V %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->stream_would_block[i]);
    }

    p = ngx_snprintf(p, last - p,
                     "cc_overflow %uA\n"
                     "rate_overflow %uA\n",
                     (ngx_atomic_uint_t) snap->cc_overflow,
                     rate_overflow);

    for (i = 0; i < HEAVYBAG_STAT_CC_SLOTS; i++) {
        if (snap->cc[i].cc16 == 0) {
            continue;
        }
        ngx_http_heavybag_cc_chars((uint16_t) snap->cc[i].cc16, cc);
        p = ngx_snprintf(p, last - p, "country %c%c total=%uA blocked=%uA\n",
                         cc[0], cc[1],
                         (ngx_atomic_uint_t) snap->cc[i].total,
                         (ngx_atomic_uint_t) snap->cc[i].blocked);
    }

    for (idx = 0; idx < nvhosts; idx++) {
        v = ngx_http_heavybag_stat_vhost(sh, idx);
        p = ngx_snprintf(p, last - p, "vhost \"%V\" requests=%uA allowed=%uA",
                         &cscfp[idx]->server_name,
                         (ngx_atomic_uint_t) v->requests,
                         (ngx_atomic_uint_t) v->allowed);
        for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
            p = ngx_snprintf(p, last - p, " blocked_%V=%uA",
                             &heavybag_reason_str[i],
                             (ngx_atomic_uint_t) v->blocked[i]);
        }
        p = ngx_snprintf(p, last - p, "\n");
    }

#if (NGX_STAT_STUB)
    {
        extern ngx_atomic_t  *ngx_stat_active;
        extern ngx_atomic_t  *ngx_stat_reading;
        extern ngx_atomic_t  *ngx_stat_writing;
        extern ngx_atomic_t  *ngx_stat_waiting;
        extern ngx_atomic_t  *ngx_stat_accepted;
        extern ngx_atomic_t  *ngx_stat_handled;
        extern ngx_atomic_t  *ngx_stat_requests;

        p = ngx_snprintf(p, last - p,
                         "stub_active %uA\n"
                         "stub_reading %uA\n"
                         "stub_writing %uA\n"
                         "stub_waiting %uA\n"
                         "stub_accepted %uA\n"
                         "stub_handled %uA\n"
                         "stub_requests %uA\n",
                         (ngx_atomic_uint_t) *ngx_stat_active,
                         (ngx_atomic_uint_t) *ngx_stat_reading,
                         (ngx_atomic_uint_t) *ngx_stat_writing,
                         (ngx_atomic_uint_t) *ngx_stat_waiting,
                         (ngx_atomic_uint_t) *ngx_stat_accepted,
                         (ngx_atomic_uint_t) *ngx_stat_handled,
                         (ngx_atomic_uint_t) *ngx_stat_requests);
    }
#else
    p = ngx_snprintf(p, last - p, "# stub_status not available\n");
#endif

    return p;
}


/* --- json (RFC 8259) ----------------------------------------------------- */

/*
 * Render the counter snapshot as an RFC 8259 JSON object into the buffer
 * [p, last): global totals plus a per-vhost array with country and flag
 * sub-objects. Returns the advanced write pointer.
 */
static u_char *
ngx_http_heavybag_status_json(u_char *p, u_char *last,
    ngx_http_heavybag_stat_shm_t *snap, ngx_http_heavybag_stat_shm_t *sh,
    ngx_uint_t nvhosts, ngx_http_core_srv_conf_t **cscfp,
    ngx_http_heavybag_geo_db_t *geo_db, ngx_atomic_uint_t rate_overflow)
{
    u_char                      cc[2];
    time_t                      now;
    ngx_str_t                  *name;
    ngx_uint_t                  i, idx, first;
    ngx_http_heavybag_stat_vhost_t  *v;

    now = ngx_time();

    p = ngx_snprintf(p, last - p,
                     "{\"heavybag_up\":1,\"uptime_seconds\":%T,\"last_reload\":%T,",
                     now - snap->start_time, snap->last_reload_time);

    if (geo_db != NULL) {
        p = ngx_snprintf(p, last - p,
            "\"geo\":{\"configured\":true,\"networks\":%uz,\"db_size_bytes\":%uz},",
            (size_t) (geo_db->block_len[NGX_HTTP_HEAVYBAG_GEO_ND] / 12),
            geo_db->map_size);
    } else {
        p = ngx_snprintf(p, last - p, "\"geo\":{\"configured\":false},");
    }

    p = ngx_snprintf(p, last - p,
                     "\"http\":{\"requests_total\":%uA,\"allowed\":%uA,"
                     "\"allowlist_hits\":%uA,\"blocked\":{",
                     (ngx_atomic_uint_t) snap->http_requests_total,
                     (ngx_atomic_uint_t) snap->http_allowed,
                     (ngx_atomic_uint_t) snap->http_allowlist_hits);

    for (i = HEAVYBAG_REASON_NONE + 1, first = 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "%s\"%V\":%uA", first ? "" : ",",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->http_blocked[i]);
        first = 0;
    }

    p = ngx_snprintf(p, last - p, "},\"would_block\":{");

    for (i = HEAVYBAG_REASON_NONE + 1, first = 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "%s\"%V\":%uA", first ? "" : ",",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->http_would_block[i]);
        first = 0;
    }

    p = ngx_snprintf(p, last - p,
                     "},\"responses\":{\"403\":%uA,\"404\":%uA,\"444\":%uA,"
                     "\"429\":%uA},"
                     "\"scanner_path\":{\"404\":%uA,\"403\":%uA,\"444\":%uA},"
                     "\"ua\":{",
                     (ngx_atomic_uint_t) snap->http_resp_403,
                     (ngx_atomic_uint_t) snap->http_resp_404,
                     (ngx_atomic_uint_t) snap->http_resp_444,
                     (ngx_atomic_uint_t) snap->http_resp_429,
                     (ngx_atomic_uint_t) snap->http_scanner_path[HEAVYBAG_ACTION_404],
                     (ngx_atomic_uint_t) snap->http_scanner_path[HEAVYBAG_ACTION_403],
                     (ngx_atomic_uint_t) snap->http_scanner_path[HEAVYBAG_ACTION_444]);

    for (i = 0, first = 1; i < HEAVYBAG_UA_MAX; i++) {
        p = ngx_snprintf(p, last - p, "%s\"%V\":%uA", first ? "" : ",",
                         &heavybag_type_str[i],
                         (ngx_atomic_uint_t) snap->http_ua[i]);
        first = 0;
    }

    p = ngx_snprintf(p, last - p, "},\"ua_cat\":{");
    for (i = 0, first = 1; i < HEAVYBAG_CAT_MAX; i++) {
        p = ngx_snprintf(p, last - p, "%s\"%V\":%uA", first ? "" : ",",
                         ngx_http_heavybag_category_str((ngx_http_heavybag_ua_category_e) i),
                         (ngx_atomic_uint_t) snap->http_ua_cat[i]);
        first = 0;
    }

    p = ngx_snprintf(p, last - p, "},\"spoofed\":%uA,\"flags\":{",
                     (ngx_atomic_uint_t) snap->http_ua_spoofed);
    for (i = 0; i < HEAVYBAG_FLAG_SLOTS; i++) {
        p = ngx_snprintf(p, last - p, "%s\"%s\":%uA", i ? "," : "",
                         heavybag_flag_label[i],
                         (ngx_atomic_uint_t) snap->flag_blocked[i]);
    }

    p = ngx_snprintf(p, last - p,
                     "}},\"stream\":{\"connections_total\":%uA,"
                     "\"allowed\":%uA,\"denied\":{",
                     (ngx_atomic_uint_t) snap->stream_connections_total,
                     (ngx_atomic_uint_t) snap->stream_allowed);

    for (i = HEAVYBAG_REASON_NONE + 1, first = 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "%s\"%V\":%uA", first ? "" : ",",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->stream_denied[i]);
        first = 0;
    }

    p = ngx_snprintf(p, last - p, "},\"would_block\":{");

    for (i = HEAVYBAG_REASON_NONE + 1, first = 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p, "%s\"%V\":%uA", first ? "" : ",",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->stream_would_block[i]);
        first = 0;
    }

    p = ngx_snprintf(p, last - p,
                     "}},\"cc_overflow\":%uA,\"rate_overflow\":%uA,"
                     "\"countries\":[",
                     (ngx_atomic_uint_t) snap->cc_overflow, rate_overflow);

    for (i = 0, first = 1; i < HEAVYBAG_STAT_CC_SLOTS; i++) {
        if (snap->cc[i].cc16 == 0) {
            continue;
        }
        ngx_http_heavybag_cc_chars((uint16_t) snap->cc[i].cc16, cc);
        p = ngx_snprintf(p, last - p,
                         "%s{\"cc\":\"%c%c\",\"total\":%uA,\"blocked\":%uA}",
                         first ? "" : ",", cc[0], cc[1],
                         (ngx_atomic_uint_t) snap->cc[i].total,
                         (ngx_atomic_uint_t) snap->cc[i].blocked);
        first = 0;
    }

    p = ngx_snprintf(p, last - p, "],\"vhosts\":[");

    for (idx = 0; idx < nvhosts; idx++) {
        v = ngx_http_heavybag_stat_vhost(sh, idx);
        name = &cscfp[idx]->server_name;

        p = ngx_snprintf(p, last - p, "%s{\"server\":\"", idx ? "," : "");
        if (last - p > 0) {
            p = (u_char *) ngx_escape_json(p, name->data, name->len);
        }
        p = ngx_snprintf(p, last - p,
                         "\",\"requests\":%uA,\"allowed\":%uA,\"blocked\":{",
                         (ngx_atomic_uint_t) v->requests,
                         (ngx_atomic_uint_t) v->allowed);
        for (i = HEAVYBAG_REASON_NONE + 1, first = 1; i < HEAVYBAG_REASON_MAX; i++) {
            p = ngx_snprintf(p, last - p, "%s\"%V\":%uA", first ? "" : ",",
                             &heavybag_reason_str[i],
                             (ngx_atomic_uint_t) v->blocked[i]);
            first = 0;
        }
        p = ngx_snprintf(p, last - p, "}}");
    }

    p = ngx_snprintf(p, last - p, "]}\n");

    return p;
}


/* --- prometheus (text exposition) ---------------------------------------- */

/*
 * Render the counter snapshot in the Prometheus text-exposition format into
 * the buffer [p, last): HELP/TYPE headers and metric lines labelled by
 * vhost, country and flag. Returns the advanced write pointer.
 */
static u_char *
ngx_http_heavybag_status_prometheus(u_char *p, u_char *last,
    ngx_http_heavybag_stat_shm_t *snap, ngx_http_heavybag_stat_shm_t *sh,
    ngx_uint_t nvhosts, ngx_http_core_srv_conf_t **cscfp,
    ngx_http_heavybag_geo_db_t *geo_db, ngx_atomic_uint_t rate_overflow)
{
    u_char                      cc[2];
    time_t                      now;
    ngx_str_t                  *name;
    ngx_uint_t                  i, idx;
    ngx_http_heavybag_stat_vhost_t  *v;

    now = ngx_time();

    p = ngx_snprintf(p, last - p,
                     "heavybag_up 1\n"
                     "heavybag_uptime_seconds %T\n"
                     "heavybag_last_reload_timestamp %T\n",
                     now - snap->start_time, snap->last_reload_time);

    if (geo_db != NULL) {
        p = ngx_snprintf(p, last - p,
                         "heavybag_geo_networks %uz\n"
                         "heavybag_geo_db_size_bytes %uz\n",
                         (size_t) (geo_db->block_len[NGX_HTTP_HEAVYBAG_GEO_ND] / 12),
                         geo_db->map_size);
    }

    p = ngx_snprintf(p, last - p,
                     "heavybag_http_requests_total %uA\n"
                     "heavybag_http_allowed_total %uA\n"
                     "heavybag_http_allowlist_hits_total %uA\n",
                     (ngx_atomic_uint_t) snap->http_requests_total,
                     (ngx_atomic_uint_t) snap->http_allowed,
                     (ngx_atomic_uint_t) snap->http_allowlist_hits);

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p,
                         "heavybag_http_blocked_total{reason=\"%V\"} %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->http_blocked[i]);
    }

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p,
                         "heavybag_http_would_block_total{reason=\"%V\"} %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->http_would_block[i]);
    }

    for (i = 0; i < HEAVYBAG_FLAG_SLOTS; i++) {
        p = ngx_snprintf(p, last - p,
            "heavybag_http_blocked_total{reason=\"flag\",flag=\"%s\"} %uA\n",
            heavybag_flag_label[i],
            (ngx_atomic_uint_t) snap->flag_blocked[i]);
    }

    p = ngx_snprintf(p, last - p,
                     "heavybag_http_responses_total{code=\"403\"} %uA\n"
                     "heavybag_http_responses_total{code=\"404\"} %uA\n"
                     "heavybag_http_responses_total{code=\"444\"} %uA\n"
                     "heavybag_http_responses_total{code=\"429\"} %uA\n",
                     (ngx_atomic_uint_t) snap->http_resp_403,
                     (ngx_atomic_uint_t) snap->http_resp_404,
                     (ngx_atomic_uint_t) snap->http_resp_444,
                     (ngx_atomic_uint_t) snap->http_resp_429);

    for (i = 0; i < HEAVYBAG_UA_MAX; i++) {
        p = ngx_snprintf(p, last - p, "heavybag_ua_total{class=\"%V\"} %uA\n",
                         &heavybag_type_str[i],
                         (ngx_atomic_uint_t) snap->http_ua[i]);
    }

    for (i = 0; i < HEAVYBAG_CAT_MAX; i++) {
        p = ngx_snprintf(p, last - p,
                         "heavybag_ua_cat_total{category=\"%V\"} %uA\n",
                         ngx_http_heavybag_category_str((ngx_http_heavybag_ua_category_e) i),
                         (ngx_atomic_uint_t) snap->http_ua_cat[i]);
    }

    p = ngx_snprintf(p, last - p, "heavybag_ua_spoofed_total %uA\n",
                     (ngx_atomic_uint_t) snap->http_ua_spoofed);

    p = ngx_snprintf(p, last - p,
                     "heavybag_stream_connections_total %uA\n"
                     "heavybag_stream_allowed_total %uA\n",
                     (ngx_atomic_uint_t) snap->stream_connections_total,
                     (ngx_atomic_uint_t) snap->stream_allowed);

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p,
                         "heavybag_stream_denied_total{reason=\"%V\"} %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->stream_denied[i]);
    }

    for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
        p = ngx_snprintf(p, last - p,
                         "heavybag_stream_would_block_total{reason=\"%V\"} %uA\n",
                         &heavybag_reason_str[i],
                         (ngx_atomic_uint_t) snap->stream_would_block[i]);
    }

    p = ngx_snprintf(p, last - p,
                     "heavybag_cc_overflow_total %uA\n"
                     "heavybag_rate_overflow_total %uA\n",
                     (ngx_atomic_uint_t) snap->cc_overflow, rate_overflow);

    for (i = 0; i < HEAVYBAG_STAT_CC_SLOTS; i++) {
        if (snap->cc[i].cc16 == 0) {
            continue;
        }
        ngx_http_heavybag_cc_chars((uint16_t) snap->cc[i].cc16, cc);
        p = ngx_snprintf(p, last - p,
                         "heavybag_country_total{country=\"%c%c\"} %uA\n"
                         "heavybag_country_blocked_total{country=\"%c%c\"} %uA\n",
                         cc[0], cc[1], (ngx_atomic_uint_t) snap->cc[i].total,
                         cc[0], cc[1], (ngx_atomic_uint_t) snap->cc[i].blocked);
    }

    for (idx = 0; idx < nvhosts; idx++) {
        v = ngx_http_heavybag_stat_vhost(sh, idx);
        name = &cscfp[idx]->server_name;

        for (i = HEAVYBAG_REASON_NONE + 1; i < HEAVYBAG_REASON_MAX; i++) {
            p = ngx_snprintf(p, last - p, "heavybag_vhost_blocked_total{server=\"");
            p = ngx_http_heavybag_prom_escape(p, last, name->data, name->len);
            p = ngx_snprintf(p, last - p, "\",reason=\"%V\"} %uA\n",
                             &heavybag_reason_str[i],
                             (ngx_atomic_uint_t) v->blocked[i]);
        }
    }

#if (NGX_STAT_STUB)
    {
        extern ngx_atomic_t  *ngx_stat_active;
        extern ngx_atomic_t  *ngx_stat_reading;
        extern ngx_atomic_t  *ngx_stat_writing;
        extern ngx_atomic_t  *ngx_stat_waiting;
        extern ngx_atomic_t  *ngx_stat_accepted;
        extern ngx_atomic_t  *ngx_stat_handled;
        extern ngx_atomic_t  *ngx_stat_requests;

        p = ngx_snprintf(p, last - p,
                         "nginx_connections_active %uA\n"
                         "nginx_connections_reading %uA\n"
                         "nginx_connections_writing %uA\n"
                         "nginx_connections_waiting %uA\n"
                         "nginx_accepted_total %uA\n"
                         "nginx_handled_total %uA\n"
                         "nginx_requests_total %uA\n",
                         (ngx_atomic_uint_t) *ngx_stat_active,
                         (ngx_atomic_uint_t) *ngx_stat_reading,
                         (ngx_atomic_uint_t) *ngx_stat_writing,
                         (ngx_atomic_uint_t) *ngx_stat_waiting,
                         (ngx_atomic_uint_t) *ngx_stat_accepted,
                         (ngx_atomic_uint_t) *ngx_stat_handled,
                         (ngx_atomic_uint_t) *ngx_stat_requests);
    }
#endif

    return p;
}


ngx_int_t
ngx_http_heavybag_status_handler(ngx_http_request_t *r)
{
    u_char                      *p, *last;
    size_t                       size;
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_uint_t                   fmt, nvhosts;
    ngx_chain_t                  out;
    ngx_atomic_uint_t            rate_overflow;
    ngx_http_heavybag_stat_shm_t      snap;
    ngx_http_heavybag_stat_shm_t     *sh;
    ngx_http_heavybag_loc_conf_t     *wlcf;
    ngx_http_heavybag_main_conf_t    *wmcf;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_heavybag_geo_db_t       *geo_db;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    wmcf = ngx_http_get_module_main_conf(r, ngx_http_heavybag_module);
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    sh = (wmcf->stat_zone != NULL) ? wmcf->stat_zone->data : NULL;
    if (sh == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "heavybag: status zone is not available");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* consistent snapshot of the fixed counter section (per-vhost read live) */
    snap = *sh;

    nvhosts = wmcf->nvhosts;
    cscfp = cmcf->servers.elts;
    if (nvhosts > cmcf->servers.nelts) {
        nvhosts = cmcf->servers.nelts;
    }

    geo_db = wlcf->rep.geo_db;
    fmt = ngx_http_heavybag_status_format(&r->uri);

    /* live read of the rate-limit table-saturation counter (separate zone) */
    rate_overflow = ngx_http_heavybag_rate_overflow(
        (wmcf->rate_zone != NULL) ? wmcf->rate_zone->data : NULL);

    size = ngx_http_heavybag_status_bufsize(nvhosts, cscfp);
    if (size == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "heavybag: status buffer size overflow");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = b->pos;
    last = b->end;

    switch (fmt) {
    case HEAVYBAG_STAT_FMT_JSON:
        p = ngx_http_heavybag_status_json(p, last, &snap, sh, nvhosts, cscfp, geo_db,
                                     rate_overflow);
        r->headers_out.content_type = heavybag_stat_ct_json;
        break;
    case HEAVYBAG_STAT_FMT_PROMETHEUS:
        p = ngx_http_heavybag_status_prometheus(p, last, &snap, sh, nvhosts, cscfp,
                                           geo_db, rate_overflow);
        r->headers_out.content_type = heavybag_stat_ct_text;
        break;
    default:
        p = ngx_http_heavybag_status_plain(p, last, &snap, sh, nvhosts, cscfp,
                                      geo_db, rate_overflow);
        r->headers_out.content_type = heavybag_stat_ct_text;
        break;
    }

    b->last = p;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
