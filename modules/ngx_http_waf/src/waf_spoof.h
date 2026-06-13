/*
 * ngx_http_waf_module - Apache HTTP fingerprint spoofing
 *
 * Hides the nginx fingerprint at the HTTP layer (the partner's decision:
 * HTTP level only, no TLS-fingerprint work). Two filters, no source patch:
 *
 *   - header filter: overrides the Server header with the configured
 *     token on every response; for nginx's own built-in error pages it
 *     also rewrites Content-Length to the synthesized Apache body length.
 *   - body filter: replaces the nginx default error body with an
 *     Apache-style page ("<address>Apache/... Server at host Port n</address>").
 *
 * The header filter runs ahead of nginx's core header filter, so the
 * Server override and the new Content-Length are picked up before
 * serialization.
 */

#ifndef _WAF_SPOOF_H_INCLUDED_
#define _WAF_SPOOF_H_INCLUDED_


#include "ngx_http_waf.h"


/* Install the header and body filters. Called from postconfiguration. */
ngx_int_t ngx_http_waf_spoof_init(ngx_conf_t *cf);


#endif /* _WAF_SPOOF_H_INCLUDED_ */
