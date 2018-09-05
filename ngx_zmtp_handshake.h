/*
 author  jamesli20000

 */


#ifndef _NGX_ZMTP_H_INCLUDED_
#define _NGX_ZMTP_H_INCLUDED_
#include "ngx_zmtp.h"

#define NGX_ZMTP_CLIENT_HANDSHAKE_BUFSIZE                  100
#define NGX_ZMTP_CYCLE_BUFSIZE                  		1024



#define NGX_ZMTP_HANDSHAKE_SERVER_RECV_SIGNATURE    0
#define NGX_ZMTP_HANDSHAKE_SERVER_SEND_SIGNATURE    1
#define NGX_ZMTP_HANDSHAKE_SERVER_RECV_GREETING     2
#define NGX_ZMTP_HANDSHAKE_SERVER_SEND_GREETING     3
#define NGX_ZMTP_HANDSHAKE_SERVER_RECV_CMD_READY    4
#define NGX_ZMTP_HANDSHAKE_SERVER_SEND_CMD_READY    5
#define NGX_ZMTP_HANDSHAKE_SERVER_RECV_SOCKTYPE     6
#define NGX_ZMTP_HANDSHAKE_SERVER_RECV_SOCKTYPE_DON 7
#define NGX_ZMTP_HANDSHAKE_SERVER_DONE              8


#define NGX_ZMTP_HANDSHAKE_CLIENT_SEND_SIGNATURE    20
#define NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SIGNATURE    21
#define NGX_ZMTP_HANDSHAKE_CLIENT_SEND_GREETING     22
#define NGX_ZMTP_HANDSHAKE_CLIENT_RECV_GREETING     23
#define NGX_ZMTP_HANDSHAKE_CLIENT_SEND_CMD_READY    24
#define NGX_ZMTP_HANDSHAKE_CLIENT_RECV_CMD_READY    25
#define NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SOCKTYPE     26
#define NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SOCKTYPE_DON 27
#define NGX_ZMTP_HANDSHAKE_CLIENT_DONE              28





extern ngx_uint_t stage_buffer_size [] ;

void ngx_zmtp_start_peer_handshake(ngx_zmtp_session_t *s);
void ngx_zmtp_handshake(ngx_zmtp_session_t *s);
void  ngx_zmtp_handshake_recv(ngx_event_t *rev);
void ngx_zmtp_handshake_send(ngx_event_t *wev);
void ngx_zmtp_handshake_done(ngx_zmtp_session_t *s);
void ngx_zmtp_free_handshake_buffers(ngx_zmtp_session_t *s);




#endif
