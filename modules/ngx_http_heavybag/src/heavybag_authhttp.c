/*
 * ngx_http_heavybag_module - SMTP auth_http endpoint
 *
 * See heavybag_authhttp.h. The mail proxy puts the real peer in the Client-IP
 * header (no upstream content, not spoofable); we run the same verdict
 * function the HTTP PREACCESS phase uses and translate the result into the
 * response headers ngx_mail_auth_http_module expects. The response is a
 * header-only 200; ngx_mail ignores the status line and parses Auth-*.
 */

#include "ngx_http_heavybag.h"
#include "heavybag_authhttp.h"
#include "heavybag_reputation.h"
#include "heavybag_status.h"
#include "heavybag_rate.h"


static ngx_table_elt_t *ngx_http_heavybag_add_header(ngx_http_request_t *r,
    const char *key, size_t klen, u_char *val, size_t vlen);
static ngx_str_t *ngx_http_heavybag_client_ip(ngx_http_request_t *r);
static ngx_uint_t ngx_http_heavybag_authhttp_peer_trusted(ngx_connection_t *c);
static ngx_int_t ngx_http_heavybag_authhttp_finalize(ngx_http_request_t *r);
static ngx_int_t ngx_http_heavybag_authhttp_allow(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf);
static ngx_int_t ngx_http_heavybag_authhttp_deny(ngx_http_request_t *r,
    ngx_str_t *reason);


static ngx_str_t  ngx_http_heavybag_auth_status = ngx_string("Auth-Status");
static ngx_str_t  ngx_http_heavybag_auth_server = ngx_string("Auth-Server");
static ngx_str_t  ngx_http_heavybag_auth_port = ngx_string("Auth-Port");
static ngx_str_t  ngx_http_heavybag_auth_ok = ngx_string("OK");


ngx_int_t
ngx_http_heavybag_authhttp_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_str_t                  reason;
    ngx_str_t                 *client_ip = NULL;
    ngx_addr_t                 addr;
    struct sockaddr           *sa;
    ngx_http_heavybag_verdict_t     verdict;
    ngx_http_heavybag_loc_conf_t   *wlcf;
    ngx_http_heavybag_main_conf_t  *wmcf;
    ngx_http_heavybag_rate_rule_t  *rate_rule;
    ngx_http_heavybag_stat_shm_t   *sh;

    /* auth_http issues GET; discard any body and ignore the method. */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_heavybag_module);

    /*
     * The mail proxy reaches this endpoint over loopback and puts the real
     * peer in Client-IP. Only honour that header when the request actually
     * came from a trusted (loopback / unix) peer; otherwise the endpoint has
     * been exposed and Client-IP is attacker-spoofable, so judge the real
     * connection peer instead. (The location should also carry "waf off".)
     */
    if (ngx_http_heavybag_authhttp_peer_trusted(r->connection)) {

        client_ip = ngx_http_heavybag_client_ip(r);

        if (client_ip == NULL
            || ngx_parse_addr(r->pool, &addr, client_ip->data, client_ip->len)
               != NGX_OK)
        {
            /*
             * ngx_mail always sets Client-IP from the real peer, so a missing
             * or unparseable value means a malformed or external request.
             * Fail open (allow) rather than break mail delivery, but log it.
             */
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "heavybag: mail auth without parseable Client-IP, allowing");
            return ngx_http_heavybag_authhttp_allow(r, wlcf);
        }

        sa = addr.sockaddr;

    } else {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "heavybag: mail auth from untrusted peer, ignoring Client-IP "
                      "and judging the connection peer");
        sa = r->connection->sockaddr;
    }

    /*
     * The verdict side data drives the rate-limit rule selection (for_geo);
     * geo_valid stays 0 unless this location has a waf_geo_db, in which case
     * the default rule applies.
     */
    rc = ngx_http_heavybag_reputation_check(&wlcf->rep, sa, &reason, &verdict);

    if (rc != NGX_DECLINED) {
        if (client_ip != NULL) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "heavybag: mail reputation block %V (%V)",
                          client_ip, &reason);
        } else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "heavybag: mail reputation block peer (%V)", &reason);
        }
        return ngx_http_heavybag_authhttp_deny(r, &reason);
    }

    /*
     * Reputation allowed: per-IP rate limit. No detect mode here (the auth
     * endpoint always enforces). The mail head has no per-vhost slot, so a
     * rate deny is booked on the global http_blocked[RATE_LIMIT] + http_resp_429
     * counters. The backing zone is the HTTP head's waf_rate_zone.
     */
    if (wlcf->rate_rules != NULL) {
        rate_rule = ngx_http_heavybag_rate_rule_select(wlcf->rate_rules, &verdict);

        if (rate_rule != NULL) {
            wmcf = ngx_http_get_module_main_conf(r, ngx_http_heavybag_module);

            if (ngx_http_heavybag_rate_check(
                    (wmcf->rate_zone != NULL) ? wmcf->rate_zone->data : NULL,
                    sa, rate_rule->rate_num_fp, rate_rule->period_ms,
                    rate_rule->burst_fp)
                == NGX_BUSY)
            {
                ngx_str_t  rl = ngx_string("rate limit");

                sh = (wmcf->stat_zone != NULL) ? wmcf->stat_zone->data : NULL;
                if (sh != NULL) {
                    (void) ngx_atomic_fetch_add(
                        &sh->http_blocked[HEAVYBAG_REASON_RATE_LIMIT], 1);
                    (void) ngx_atomic_fetch_add(&sh->http_resp_429, 1);
                }

                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "heavybag: mail rate limit exceeded");

                return ngx_http_heavybag_authhttp_deny(r, &rl);
            }
        }
    }

    return ngx_http_heavybag_authhttp_allow(r, wlcf);
}


/*
 * Is the request peer trusted to dictate Client-IP? In this edge-firewall
 * topology the mail proxy reaches auth_http over loopback (or a unix socket),
 * so only those peers may set the address we judge.
 */
static ngx_uint_t
ngx_http_heavybag_authhttp_peer_trusted(ngx_connection_t *c)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (c->sockaddr == NULL) {
        return 0;
    }

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        return 1;
#endif

    case AF_INET:
        sin = (struct sockaddr_in *) c->sockaddr;
        /* 127.0.0.0/8, byte-order independent */
        return ((u_char *) &sin->sin_addr.s_addr)[0] == 127;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
            return 1;                       /* ::1 */
        }
        /* On a dual-stack (ipv6only=off) listener the loopback mail proxy
         * arrives as ::ffff:127.0.0.1, not ::1. Trust the v4-mapped loopback
         * /8 too, mirroring the rate keyer's v4-mapped handling (heavybag_rate
         * .c). Without this the loopback peer is judged untrusted and the
         * Client-IP it sets is dropped. */
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            return sin6->sin6_addr.s6_addr[12] == 127;   /* ::ffff:127.0.0.0/8 */
        }
        return 0;
#endif
    }

    return 0;
}


/*
 * Allow: "Auth-Status: OK" plus the backend MTA from waf_mail_backend.
 * ngx_mail rejects the session with an internal error if Auth-Server /
 * Auth-Port are missing, so a misconfigured backend is logged loudly.
 */
static ngx_int_t
ngx_http_heavybag_authhttp_allow(ngx_http_request_t *r,
    ngx_http_heavybag_loc_conf_t *wlcf)
{
    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_status.data,
                                ngx_http_heavybag_auth_status.len,
                                ngx_http_heavybag_auth_ok.data,
                                ngx_http_heavybag_auth_ok.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (wlcf->mail_backend_addr.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "heavybag: mail auth allowed but waf_mail_backend is not set; "
                      "the mail proxy will reject the session");
        return ngx_http_heavybag_authhttp_finalize(r);
    }

    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_server.data,
                                ngx_http_heavybag_auth_server.len,
                                wlcf->mail_backend_addr.data,
                                wlcf->mail_backend_addr.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_port.data,
                                ngx_http_heavybag_auth_port.len,
                                wlcf->mail_backend_port.data,
                                wlcf->mail_backend_port.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    return ngx_http_heavybag_authhttp_finalize(r);
}


/*
 * Deny: "Auth-Status: <reason>". reason points at a static string from the
 * reputation core ("static blocklist" / "network flag" / "geo country"),
 * never contains CRLF. ngx_mail prefixes the SMTP error code.
 */
static ngx_int_t
ngx_http_heavybag_authhttp_deny(ngx_http_request_t *r, ngx_str_t *reason)
{
    if (ngx_http_heavybag_add_header(r, (char *) ngx_http_heavybag_auth_status.data,
                                ngx_http_heavybag_auth_status.len,
                                reason->data, reason->len)
        == NULL)
    {
        return NGX_ERROR;
    }

    return ngx_http_heavybag_authhttp_finalize(r);
}


static ngx_int_t
ngx_http_heavybag_authhttp_finalize(ngx_http_request_t *r)
{
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    return ngx_http_send_header(r);
}


static ngx_table_elt_t *
ngx_http_heavybag_add_header(ngx_http_request_t *r, const char *key, size_t klen,
    u_char *val, size_t vlen)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NULL;
    }

    h->hash = 1;
    h->key.len = klen;
    h->key.data = (u_char *) key;
    h->value.len = vlen;
    h->value.data = val;
    h->next = NULL;

    return h;
}


/* Locate the Client-IP request header (not a standard slot). */
static ngx_str_t *
ngx_http_heavybag_client_ip(ngx_http_request_t *r)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == sizeof("Client-IP") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Client-IP",
                               sizeof("Client-IP") - 1)
               == 0)
        {
            return &h[i].value;
        }
    }

    return NULL;
}
