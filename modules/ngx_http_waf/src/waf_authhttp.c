/*
 * ngx_http_waf_module - SMTP auth_http endpoint
 *
 * See waf_authhttp.h. The mail proxy puts the real peer in the Client-IP
 * header (no upstream content, not spoofable); we run the same verdict
 * function the HTTP PREACCESS phase uses and translate the result into the
 * response headers ngx_mail_auth_http_module expects. The response is a
 * header-only 200; ngx_mail ignores the status line and parses Auth-*.
 */

#include "ngx_http_waf.h"
#include "waf_authhttp.h"
#include "waf_reputation.h"


static ngx_table_elt_t *ngx_http_waf_add_header(ngx_http_request_t *r,
    const char *key, size_t klen, u_char *val, size_t vlen);
static ngx_str_t *ngx_http_waf_client_ip(ngx_http_request_t *r);
static ngx_int_t ngx_http_waf_authhttp_finalize(ngx_http_request_t *r);
static ngx_int_t ngx_http_waf_authhttp_allow(ngx_http_request_t *r,
    ngx_http_waf_loc_conf_t *wlcf);
static ngx_int_t ngx_http_waf_authhttp_deny(ngx_http_request_t *r,
    ngx_str_t *reason);


static ngx_str_t  ngx_http_waf_auth_status = ngx_string("Auth-Status");
static ngx_str_t  ngx_http_waf_auth_server = ngx_string("Auth-Server");
static ngx_str_t  ngx_http_waf_auth_port = ngx_string("Auth-Port");
static ngx_str_t  ngx_http_waf_auth_ok = ngx_string("OK");


ngx_int_t
ngx_http_waf_authhttp_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_str_t                 reason;
    ngx_str_t                *client_ip;
    ngx_addr_t                addr;
    ngx_http_waf_loc_conf_t  *wlcf;

    /* auth_http issues GET; discard any body and ignore the method. */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    client_ip = ngx_http_waf_client_ip(r);

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
                      "waf: mail auth without parseable Client-IP, allowing");
        return ngx_http_waf_authhttp_allow(r, wlcf);
    }

    rc = ngx_http_waf_reputation_check(wlcf, addr.sockaddr, &reason);

    if (rc != NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "waf: mail reputation block %V (%V)", client_ip, &reason);
        return ngx_http_waf_authhttp_deny(r, &reason);
    }

    return ngx_http_waf_authhttp_allow(r, wlcf);
}


/*
 * Allow: "Auth-Status: OK" plus the backend MTA from waf_mail_backend.
 * ngx_mail rejects the session with an internal error if Auth-Server /
 * Auth-Port are missing, so a misconfigured backend is logged loudly.
 */
static ngx_int_t
ngx_http_waf_authhttp_allow(ngx_http_request_t *r,
    ngx_http_waf_loc_conf_t *wlcf)
{
    if (ngx_http_waf_add_header(r, (char *) ngx_http_waf_auth_status.data,
                                ngx_http_waf_auth_status.len,
                                ngx_http_waf_auth_ok.data,
                                ngx_http_waf_auth_ok.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (wlcf->mail_backend_addr.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "waf: mail auth allowed but waf_mail_backend is not set; "
                      "the mail proxy will reject the session");
        return ngx_http_waf_authhttp_finalize(r);
    }

    if (ngx_http_waf_add_header(r, (char *) ngx_http_waf_auth_server.data,
                                ngx_http_waf_auth_server.len,
                                wlcf->mail_backend_addr.data,
                                wlcf->mail_backend_addr.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (ngx_http_waf_add_header(r, (char *) ngx_http_waf_auth_port.data,
                                ngx_http_waf_auth_port.len,
                                wlcf->mail_backend_port.data,
                                wlcf->mail_backend_port.len)
        == NULL)
    {
        return NGX_ERROR;
    }

    return ngx_http_waf_authhttp_finalize(r);
}


/*
 * Deny: "Auth-Status: <reason>". reason points at a static string from the
 * reputation core ("static blocklist" / "network flag" / "geo country"),
 * never contains CRLF. ngx_mail prefixes the SMTP error code.
 */
static ngx_int_t
ngx_http_waf_authhttp_deny(ngx_http_request_t *r, ngx_str_t *reason)
{
    if (ngx_http_waf_add_header(r, (char *) ngx_http_waf_auth_status.data,
                                ngx_http_waf_auth_status.len,
                                reason->data, reason->len)
        == NULL)
    {
        return NGX_ERROR;
    }

    return ngx_http_waf_authhttp_finalize(r);
}


static ngx_int_t
ngx_http_waf_authhttp_finalize(ngx_http_request_t *r)
{
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    return ngx_http_send_header(r);
}


static ngx_table_elt_t *
ngx_http_waf_add_header(ngx_http_request_t *r, const char *key, size_t klen,
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
ngx_http_waf_client_ip(ngx_http_request_t *r)
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
