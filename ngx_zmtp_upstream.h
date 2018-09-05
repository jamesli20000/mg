/*
 author  jamesli20000

 */


#ifndef _NGX_ZMTP_UPSTREAM_H_INCLUDED_
#define _NGX_ZMTP_UPSTREAM_H_INCLUDED_
#include "ngx_zmtp.h"

ngx_zmtp_session_t*ngx_zmtp_get_upstream_session(ngx_zmtp_session_t *s, ngx_str_t peer, int peer_no);
void ngx_zmtp_upstream_cycle(ngx_zmtp_session_t *s);
void ngx_zmtp_upstream_send(ngx_event_t *wev);
void ngx_zmtp_upstream_recv(ngx_event_t *rev);
void ngx_zmtp_message_to_upstream(ngx_zmtp_session_t*s,ngx_buf_t *in, size_t size);
void ngx_zmtp_message_from_upstream(ngx_zmtp_session_t*s, ngx_buf_t *in, size_t size);
ngx_int_t ngx_zmtp_init_peer_connection(ngx_zmtp_session_t *s, ngx_str_t peerstring);
#endif