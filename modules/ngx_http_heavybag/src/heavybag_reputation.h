/*
 * ngx_http_heavybag_module - shared reputation core
 *
 * The reputation config struct (ngx_heavybag_rep_conf_t), the decision function
 * and the config-time helpers now live in the context-neutral heavybag_rep.h so
 * the stream (L4) head can share them without pulling in ngx_http.h. This
 * header is kept as a thin compatibility include for the HTTP/mail units.
 *
 * Order is cheap -> expensive:
 *     allowlist (allow) -> blocklist (deny) -> geo country / network flag.
 * Geo runs in two modes: a country block list (deny listed -> 403) or a
 * country whitelist (allow only listed; everyone else -> 404). The
 * whitelist wins when both are set.
 */

#ifndef _HEAVYBAG_REPUTATION_H_INCLUDED_
#define _HEAVYBAG_REPUTATION_H_INCLUDED_


#include "heavybag_rep.h"


#endif /* _HEAVYBAG_REPUTATION_H_INCLUDED_ */
