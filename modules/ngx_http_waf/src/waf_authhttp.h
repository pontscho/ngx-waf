/*
 * ngx_http_waf_module - SMTP auth_http endpoint
 *
 * Content handler for an internal HTTP location that speaks the ngx_mail
 * auth_http protocol. ngx_mail performs an auth_http GET before proxying
 * an SMTP/IMAP/POP3 session and puts the real, unspoofable peer address in
 * the Client-IP request header. The handler runs the shared
 * ngx_http_waf_reputation_check() on that address and answers in the
 * auth_http dialect:
 *
 *     allow -> "Auth-Status: OK" + Auth-Server/Auth-Port (the backend MTA
 *              from waf_mail_backend)
 *     deny  -> "Auth-Status: <reason>" (ngx_mail turns this into an SMTP
 *              5xx with the configured/default error code)
 *
 * One verdict function, two heads: this is the SMTP head; the HTTP
 * PREACCESS phase in ngx_http_waf_module.c is the other.
 */

#ifndef _WAF_AUTHHTTP_H_INCLUDED_
#define _WAF_AUTHHTTP_H_INCLUDED_


#include "ngx_http_waf.h"


/* Content handler installed on a location by the waf_mail_auth directive. */
ngx_int_t ngx_http_waf_authhttp_handler(ngx_http_request_t *r);


#endif /* _WAF_AUTHHTTP_H_INCLUDED_ */
