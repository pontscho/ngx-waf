/*
 * ngx_http_waf_module - Apache HTTP fingerprint spoofing
 *
 * See waf_spoof.h for the design. Detection of an nginx built-in error
 * page (as opposed to proxied content or a user-configured error_page)
 * happens at header-filter time using signals that are all set before
 * ngx_http_send_header() in ngx_http_send_special_response():
 *
 *     status >= 400, content-type "text/html", content_length_n > 0,
 *     main request, no upstream, and r->error_page unset.
 *
 * That combination is unique to the static error pages whose footer is
 * "<hr><center>nginx</center>" -- exactly the fingerprint we erase.
 */

#include "waf_spoof.h"


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/* Apache reason phrase + descriptive paragraph per status. */
typedef struct {
    ngx_uint_t   status;
    ngx_str_t    reason;
    ngx_str_t    detail;
} ngx_http_waf_errtext_t;


static ngx_http_waf_errtext_t  ngx_http_waf_errtexts[] = {
    { 400, ngx_string("Bad Request"),
           ngx_string("Your browser sent a request that this server could not "
                      "understand.") },
    { 401, ngx_string("Unauthorized"),
           ngx_string("This server could not verify that you are authorized to "
                      "access the document requested.") },
    { 403, ngx_string("Forbidden"),
           ngx_string("You don't have permission to access this resource.") },
    { 404, ngx_string("Not Found"),
           ngx_string("The requested URL was not found on this server.") },
    { 405, ngx_string("Method Not Allowed"),
           ngx_string("The requested method is not allowed for this URL.") },
    { 500, ngx_string("Internal Server Error"),
           ngx_string("The server encountered an internal error or "
                      "misconfiguration and was unable to complete your "
                      "request.") },
    { 502, ngx_string("Bad Gateway"),
           ngx_string("The proxy server received an invalid response from an "
                      "upstream server.") },
    { 503, ngx_string("Service Unavailable"),
           ngx_string("The server is temporarily unable to service your "
                      "request due to maintenance downtime or capacity "
                      "problems. Please try again later.") },
    { 504, ngx_string("Gateway Timeout"),
           ngx_string("The gateway did not receive a timely response from the "
                      "upstream server.") },
    { 0, ngx_null_string, ngx_null_string }
};


static ngx_str_t  ngx_http_waf_generic_reason = ngx_string("Error");
static ngx_str_t  ngx_http_waf_generic_detail =
    ngx_string("The server encountered an error processing your request.");


static ngx_int_t ngx_http_waf_spoof_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_waf_spoof_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_waf_build_error_page(ngx_http_request_t *r,
    ngx_str_t *token, ngx_str_t *out);


static void
ngx_http_waf_errtext_lookup(ngx_uint_t status, ngx_str_t **reason,
    ngx_str_t **detail)
{
    ngx_uint_t  i;

    for (i = 0; ngx_http_waf_errtexts[i].status; i++) {
        if (ngx_http_waf_errtexts[i].status == status) {
            *reason = &ngx_http_waf_errtexts[i].reason;
            *detail = &ngx_http_waf_errtexts[i].detail;
            return;
        }
    }

    *reason = &ngx_http_waf_generic_reason;
    *detail = &ngx_http_waf_generic_detail;
}


static ngx_int_t
ngx_http_waf_build_error_page(ngx_http_request_t *r, ngx_str_t *token,
    ngx_str_t *out)
{
    u_char      *p;
    size_t       size;
    in_port_t    port;
    ngx_str_t    host, *reason, *detail;
    ngx_uint_t   status;

    status = r->headers_out.status;

    ngx_http_waf_errtext_lookup(status, &reason, &detail);

    if (r->headers_in.server.len) {
        host = r->headers_in.server;
    } else {
        ngx_str_set(&host, "localhost");
    }

    port = 80;
    if (ngx_connection_local_sockaddr(r->connection, NULL, 0) == NGX_OK) {
        port = ngx_inet_get_port(r->connection->local_sockaddr);
    }

    /*
     * Apache 2.4 default error body, \n line endings. Fixed template plus
     * the variable strings; over-allocate the obvious upper bound.
     */
    size = sizeof("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                  "<html><head>\n<title> </title>\n</head><body>\n"
                  "<h1></h1>\n<p></p>\n<hr>\n"
                  "<address> Server at  Port </address>\n"
                  "</body></html>\n") - 1
           + NGX_INT_T_LEN              /* status        */
           + reason->len               /* <title>       */
           + reason->len               /* <h1>          */
           + detail->len               /* <p>           */
           + token->len                /* address token */
           + host.len                  /* host          */
           + sizeof("65535") - 1;      /* port          */

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;

    p = ngx_snprintf(p, size,
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        "<html><head>\n"
        "<title>%ui %V</title>\n"
        "</head><body>\n"
        "<h1>%V</h1>\n"
        "<p>%V</p>\n"
        "<hr>\n"
        "<address>%V Server at %V Port %ui</address>\n"
        "</body></html>\n",
        status, reason, reason, detail, token, &host, (ngx_uint_t) port);

    out->len = p - out->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_waf_spoof_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t          *h;
    ngx_http_waf_ctx_t       *ctx;
    ngx_http_waf_loc_conf_t  *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (wlcf->server_token.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    /* 1. Server header override -- every response. */

    if (r->headers_out.server) {
        r->headers_out.server->hash = 1;
        r->headers_out.server->value = wlcf->server_token;

    } else {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;
        h->next = NULL;
        ngx_str_set(&h->key, "Server");
        h->value = wlcf->server_token;

        r->headers_out.server = h;
    }

    /* 2. Apache error body -- only nginx's own built-in error pages. */

    if (r->headers_out.status >= NGX_HTTP_BAD_REQUEST
        && r == r->main
        && !r->error_page
        && r->upstream == NULL
        && r->headers_out.content_length_n > 0
        && r->headers_out.content_type.len == sizeof("text/html") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "text/html", sizeof("text/html") - 1)
           == 0)
    {
        ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }

        if (ngx_http_waf_build_error_page(r, &wlcf->server_token,
                                          &ctx->spoof_body)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->spoof_swap = 1;

        /* our body supersedes nginx's; correct the length before serialize */
        r->headers_out.content_length_n = ctx->spoof_body.len;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_waf_spoof_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t           *b;
    ngx_chain_t          out;
    ngx_http_waf_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx == NULL || !ctx->spoof_swap) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->spoof_done) {
        /* nginx's trailing buffers, if any, are dropped: body already sent */
        return NGX_OK;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = ctx->spoof_body.data;
    b->last = ctx->spoof_body.data + ctx->spoof_body.len;
    b->memory = 1;
    b->last_buf = (r == r->main);
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    ctx->spoof_done = 1;

    return ngx_http_next_body_filter(r, &out);
}


ngx_int_t
ngx_http_waf_spoof_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_waf_spoof_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_waf_spoof_body_filter;

    return NGX_OK;
}
