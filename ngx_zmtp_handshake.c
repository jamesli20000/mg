/*
 author  jamesli20000

 */
#include <ngx_event.h> 
#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_zmtp.h"
#include "ngx_zmtp_handshake.h"
#include "ngx_zmtp_upstream.h"


ngx_uint_t stage_buffer_size [] = {
  10, 11, 54, 53, 8, 8, 100,100,0,0,  //0-9
  0,   0,  0,  0, 0, 0, 0,  0,  0,0,  //10-19
  11, 11, 53, 53, 8, 8, 100, 100, 0, 0 //20-29
};

 static u_char
 ngx_zmtp_signature[] = {
	0xff, 0, 0 ,0, 0,0,
	0,0,0x1,0x7f,0x3
 };

 static u_char
 ngx_zmtp_greeting[] = {
	0,0x4e,0x55,0x4c,0x4c,
	0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,
 };

 

 static u_char 
 ngx_zmtp_server_xpub[2][28] = {
 	{
	 0x4, 0x1a, 0x5, 
	 0x52,0x45,0x41,0x44,0x59,
	 0xb, 0x53,0x6f,0x63,0x6b,0x65,0x74,0x2d,0x54,0x79,0x70,0x65,
	 0x00,0x00,0x0,0x4,
	 0x58,0x53,0x55,0x42
 	},
 	{
	 0x4, 0x1a, 0x5, 
	 0x52,0x45,0x41,0x44,0x59,
	 0xb, 0x53,0x6f,0x63,0x6b,0x65,0x74,0x2d,0x54,0x79,0x70,0x65,
	 0x00,0x00,0x0,0x4,
	 0x58,0x50,0x55,0x42
 	},
 };

/*
 static u_char
 ngx_zmtp_server_sub_message[] = { 
	 0x0, 0x1c, 0x1, 
	 'm','e','s','s','a','g','e',
	 '/','1','2','3','4','/','d',
	 'u', 'o','b','e','i','s','t',
	 'r','e','a', 'm','i','n','g'
 };
*/
static u_char
ngx_zmtp_server_sub_message[] = { 
	0x0, 0x5, 0x1, 
	't','e','s','t',
};

  
 void
 ngx_zmtp_free_handshake_buffers(ngx_zmtp_session_t *s)
 {
 	return;
 /*
	 ngx_zmtp_core_srv_conf_t	*cscf;
	 ngx_chain_t				*cl;
 
	 if (s->hs_buf == NULL) {
		 return;
	 }
	 cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
	 cl = ngx_alloc_chain_link(s->connection->data);
	 if (cl == NULL) {
		 return;
	 }
	 cl->buf = s->hs_buf;
	 cl->next = cscf->free_hs;
	 cscf->free_hs = cl;
	 s->hs_buf = NULL;
	 */
 }

 
 static ngx_int_t
 ngx_zmtp_handshake_parse_challenge(ngx_zmtp_session_t *s)
 {
	 ngx_buf_t				*b;
 
	 b = s->hs_buf;
	 if (*b->pos != 0xff ||
	 	*(b->pos+9) != 0x7f) {
		 ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				 "handshake: unexpected ZMTP signature: %i,%i",
				 (ngx_int_t)*b->pos, (ngx_int_t)*(b->pos+9));
		 return NGX_ERROR;
	 }
	
	 return NGX_OK;
 }

 static ngx_int_t
 ngx_zmtp_handshake_prepare_submessage(ngx_zmtp_session_t *s)
 {
	 ngx_buf_t			*b;
 
	 b = s->hs_buf;
	 b->last = b->pos = b->start;
	 
	 for (; b->last < b->start + sizeof(ngx_zmtp_server_sub_message); ++b->last) {
        *b->last = ngx_zmtp_server_sub_message[b->last-b->start];
     }
	 ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
						 "prepare sub: last-start:%d", b->last-b->start);
	 return NGX_OK;
 }

static ngx_int_t
ngx_zmtp_handshake_prepare_signature(ngx_zmtp_session_t *s)
{
	ngx_buf_t 		 *b;

	b = s->hs_buf;
	b->last = b->pos = b->start;

	for (; b->last < b->start + sizeof(ngx_zmtp_signature); ++b->last) {
		*b->last = ngx_zmtp_signature[b->last-b->start];
	}
	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
			  "stage:%d, prepare ngx_zmtp_signature: last-start:%d",s->hs_stage,  b->last-b->start);
	return NGX_OK;
}

 static ngx_int_t
 ngx_zmtp_handshake_prepare_greeting(ngx_zmtp_session_t *s)
 {
	 ngx_buf_t		  *b;
 
	 b = s->hs_buf;
	 b->last = b->pos = b->start;
 
	 for (; b->last < b->start + sizeof(ngx_zmtp_greeting); ++b->last) {
		 *b->last = (ngx_zmtp_greeting)[b->last-b->start];
	 }
	 ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
			   "peer:%d,%s, stage:%d, prepare ngx_zmtp_greeting: last-start:%d", 
				s->peer_no, s->upstream_addr.data,
	 			s->hs_stage,  b->last-b->start);
	 return NGX_OK;
 }



static ngx_int_t
ngx_zmtp_handshake_parse_greeting(ngx_zmtp_session_t *s)
{
	ngx_buf_t				*b;

	b = s->hs_buf;
	if (*(b->pos+2) != 0x4e || *(b->pos+3) != 0x55 ||
		*(b->pos+4) != 0x4c || *(b->pos+5) != 0x4c) {
		 ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				 "handshake: unexpected ZMTP greeting: %i,%i",
				 (ngx_int_t)*(b->pos+2), (ngx_int_t)*(b->pos+5));
		 return NGX_ERROR;
	}else{
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "recv greeting OK");
	}
	
	return NGX_OK;
}

static ngx_int_t
ngx_zmtp_handshake_parse_socktype(ngx_zmtp_session_t *s)
{
	ngx_buf_t				*b;

	b = s->hs_buf;

	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				 "handshake: peer:%d sock type:%c,%c,%c,%c",
				 s->peer_no,
				 *(b->last-4), *(b->last-3),*(b->last-2),
				 *(b->last-1));
		
	if( s->zmtp_sock_type == ZMTP_SOCK_XPUB &&  
		ngx_strncmp(b->last-3, "SUB", 3) != 0){
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "listen on pub, but peer is not sub, peer is：%s",
			 b->last - 3);
		return NGX_ERROR;
	 }else if( s->zmtp_sock_type == ZMTP_SOCK_XSUB &&  
	 	ngx_strncmp(b->last-3, "PUB", 3) != 0){
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "listen on sub, but peer is not Pub, peer is:%s",
			b->last - 3);
		return NGX_ERROR;
	}	
	return NGX_OK;
}

static ngx_int_t
ngx_zmtp_handshake_parse_cmdready(ngx_zmtp_session_t *s)
{
	ngx_buf_t 			 *b;

	b = s->hs_buf;
	if (*b->pos != 0x4 || *(b->pos+2) != 0x5 ) {
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				  "handshake: unexpected ZMTP cmd ready: %i,%i",
				  (ngx_int_t)*(b->pos), (ngx_int_t)*(b->pos+2));
		return NGX_ERROR;
	}else if( s->hs_stage == NGX_ZMTP_HANDSHAKE_SERVER_SEND_CMD_READY ){
		s->hs_socktype_len = *(b->pos+1) + 2;
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				  "handshake: sock type len: %i",
				  (ngx_int_t)*(b->pos+1));
		stage_buffer_size[NGX_ZMTP_HANDSHAKE_SERVER_RECV_SOCKTYPE] = *(b->pos+1)-1-5;
	}else if ( NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SOCKTYPE == s->hs_stage ){
		s->hs_socktype_len = *(b->pos+1) + 2;
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				   "handshake: peer sock type len: %i, peerno:%d",
				   (ngx_int_t)*(b->pos+1), s->peer_no);
		stage_buffer_size[NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SOCKTYPE] = *(b->pos+1)-1-5;

	}
	
	return NGX_OK;
}



static ngx_int_t
ngx_zmtp_handshake_create_socktype(ngx_zmtp_session_t *s)
{
	ngx_buf_t			*b;

	b = s->hs_buf;
	b->last = b->pos = b->start;

	for (; b->last < b->start + sizeof(ngx_zmtp_server_xpub[s->zmtp_sock_type]); ++b->last) {
		*b->last = ngx_zmtp_server_xpub[s->zmtp_sock_type][b->last-b->start];
	}
	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
					 "create_socktype: last-start:%d", b->last-b->start);
	return NGX_OK;
}

 
void
ngx_zmtp_handshake_recv(ngx_event_t *rev)
{
	ssize_t					 n;
	ngx_connection_t			*c;
	ngx_zmtp_session_t 		*s;
	ngx_buf_t					*b;
	ngx_int_t                    rc;
	ngx_zmtp_core_srv_conf_t 	*cscf;

	c = rev->data;	 
	
	if (c->destroyed) {
		return;
	}
	s = c->data;
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
	if (rev->timedout) {
		ngx_log_error(NGX_LOG_WARN, c->log, NGX_ETIMEDOUT,
				 "handshake: recv: client timed out");
		c->timedout = 1;
		if( s->peer_no != 1 && s->peer_no != 2)
			ngx_zmtp_finalize_session(s);
		else
			ngx_zmtp_close_peer_connection(s);
		return;
	}
	
	if (rev->timer_set) {
		ngx_del_timer(rev);
	}


	b = s->hs_buf;
	ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
			 "handshake: stage %ui, before recv:%dbytes,stage size:%d", 
			 s->hs_stage, s->hs_pkt_size_count, stage_buffer_size[s->hs_stage]);
	while (s->hs_pkt_size_count < stage_buffer_size[s->hs_stage]) {
		if (rev->eof) {
			rc = NGX_ZMQ_OK;
			return;
		}

		if (!rev->ready) {
			if (ngx_handle_read_event(rev, 0) != NGX_OK) {
				rc = NGX_ERROR;
				break;
			}

			if (!rev->timer_set) {
				ngx_add_timer(rev, cscf->preread_timeout);
			}

			return ;
		}
		n = c->recv(c, b->last, stage_buffer_size[s->hs_stage] - s->hs_pkt_size_count);
		if (n == NGX_ERROR || n == 0) {
			if( s->peer_no != 1 && s->peer_no != 2)
			 	ngx_zmtp_finalize_session(s);
			else
			 	ngx_zmtp_close_peer_connection(s);
			rc = NGX_ZMQ_OK;
			return;
		}

		if (n > 0) {
			b->last += n;
			s->hs_pkt_size_count += n;
		}

		
	}

	if (rev->active) {
		ngx_del_event(rev, NGX_READ_EVENT, 0);
	}

	++s->hs_stage;
	ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
			"handshake: stage %ui, recv:%dbytes", s->hs_stage-1, s->hs_pkt_size_count);

	switch (s->hs_stage) {
		case NGX_ZMTP_HANDSHAKE_SERVER_SEND_SIGNATURE:
			if (ngx_zmtp_handshake_parse_challenge(s) != NGX_OK)
			{
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: error parsing signature");
				if( s->peer_no != 1 && s->peer_no != 2)
					ngx_zmtp_finalize_session(s);
				else
					ngx_zmtp_close_peer_connection(s);
				return;
			}
			b = s->hs_buf;
			b->pos = b->start;
			b->last = b->pos + stage_buffer_size[NGX_ZMTP_HANDSHAKE_SERVER_RECV_SIGNATURE];
			*b->last = 0x3;
			b->last++;
			ngx_zmtp_handshake_send(c->write);
			break;
		case NGX_ZMTP_HANDSHAKE_SERVER_SEND_GREETING:
			if (ngx_zmtp_handshake_parse_greeting(s) != NGX_OK)
			{
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: error parsing challenge");
				if( s->peer_no != 1 && s->peer_no != 2)
					ngx_zmtp_finalize_session(s);
				else
					ngx_zmtp_close_peer_connection(s);

				return;
			}
			s->hs_buf->pos = s->hs_buf->start + 1;
			
			ngx_zmtp_handshake_send(c->write);
			break;
		case NGX_ZMTP_HANDSHAKE_SERVER_SEND_CMD_READY:
				if (ngx_zmtp_handshake_parse_cmdready(s) != NGX_OK)
				{
					ngx_log_error(NGX_LOG_INFO, c->log, 0,
							"handshake: error parsing cmd ready");
					if( s->peer_no != 1 && s->peer_no != 2)
					   ngx_zmtp_finalize_session(s);
					else
					   ngx_zmtp_close_peer_connection(s);

					return;
				}
				ngx_zmtp_handshake_create_socktype(s);
				ngx_zmtp_handshake_send(c->write);
				break;
		case NGX_ZMTP_HANDSHAKE_SERVER_RECV_SOCKTYPE_DON:
				if (ngx_zmtp_handshake_parse_socktype(s) != NGX_OK)
				{
					ngx_log_error(NGX_LOG_INFO, c->log, 0,
							 "handshake: error parsing cmd ready");
					if( s->peer_no != 1 && s->peer_no != 2)
						ngx_zmtp_finalize_session(s);
					else
						ngx_zmtp_close_peer_connection(s);

					return;
				}
				
				if (ngx_zmtp_handshake_prepare_submessage(s) != NGX_OK)
				{
					ngx_log_error(NGX_LOG_INFO, c->log, 0,
							 "handshake: error prepare sub message");
					if( s->peer_no != 1 && s->peer_no != 2)
						ngx_zmtp_finalize_session(s);
					else
						ngx_zmtp_close_peer_connection(s);

					return;
				}
				ngx_zmtp_handshake_send(c->write);
				//ngx_zmtp_cycle(s);
				break;

		 case NGX_ZMTP_HANDSHAKE_SERVER_DONE:
			ngx_zmtp_handshake_done(s);
			break;
		case NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SOCKTYPE_DON:
			if (ngx_zmtp_handshake_parse_socktype(s) != NGX_OK)
			{
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: error parsing cmd ready");
				if( s->peer_no != 1 && s->peer_no != 2)
					ngx_zmtp_finalize_session(s);
				else
					ngx_zmtp_close_peer_connection(s);

				return;
			}
			ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: peer:%d init OK", s->peer_no);
			s->con_valid = 1;
			ngx_zmtp_upstream_cycle(s);
			break;
		
		case NGX_ZMTP_HANDSHAKE_CLIENT_SEND_GREETING:
			if (ngx_zmtp_handshake_prepare_greeting(s) != NGX_OK)
			{
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: error prepare peer greeting");
				if( s->peer_no != 1 && s->peer_no != 2)
					ngx_zmtp_finalize_session(s);
				else
					ngx_zmtp_close_peer_connection(s);

				return;
			}
			
			ngx_zmtp_handshake_send(c->write);
			break;

		case NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SOCKTYPE:
			if (ngx_zmtp_handshake_parse_cmdready(s) != NGX_OK)
			{
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: error peer parsing cmd ready");
				if( s->peer_no != 1 && s->peer_no != 2)
					ngx_zmtp_finalize_session(s);
				else
					ngx_zmtp_close_peer_connection(s);

				 return;
			 }
			 s->hs_buf->pos = s->hs_buf->last = s->hs_buf->start;
			 s->hs_pkt_size_count = 0;	
			 ngx_zmtp_handshake_recv(c->read);
			 break;
		case NGX_ZMTP_HANDSHAKE_CLIENT_SEND_CMD_READY:
			if (ngx_zmtp_handshake_prepare_greeting(s) != NGX_OK)
			{
				ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: error prepare peer greeting");
				if( s->peer_no != 1 && s->peer_no != 2)
					ngx_zmtp_finalize_session(s);
				else
					ngx_zmtp_close_peer_connection(s);

				return;
			}
			ngx_zmtp_handshake_create_socktype(s);
			ngx_zmtp_handshake_send(c->write);
			break;
		
		
		default:
			break;
	}
}


void
ngx_zmtp_handshake_send(ngx_event_t *wev)
{
	ngx_int_t					 n;
	ngx_connection_t			*c;
	ngx_zmtp_session_t 		*s;
	ngx_buf_t					*b;
	ngx_zmtp_core_srv_conf_t 	*cscf;
	c = wev->data;

	if (c->destroyed ) {
		return;
	}
	s = c->data;	
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
	if (wev->timedout) {
		ngx_log_error(NGX_LOG_WARN, c->log, NGX_ETIMEDOUT,
				 "handshake: send: client timed out");
		c->timedout = 1;
		if( s->peer_no != 1 && s->peer_no != 2)
			ngx_zmtp_finalize_session(s);
		else
			ngx_zmtp_close_peer_connection(s);
		return;
	}

	if (wev->timer_set) {
		ngx_del_timer(wev);
	}

	b = s->hs_buf;

	while(b->pos != b->last) {
		if (!wev->ready) {
			if (ngx_handle_write_event(wev, 0) != NGX_OK) {
				return;
			}

			if (!wev->timer_set) {
				ngx_add_timer(wev, cscf->preread_timeout);
			}

			return ;
		}
		n = c->send(c, b->pos, b->last - b->pos);

		if (n == NGX_ERROR) {
			ngx_log_error(NGX_LOG_WARN, c->log, 0,
				 "handshake: send err, peerno:%d", s->peer_no);
			if( s->peer_no != 1 && s->peer_no != 2)
				ngx_zmtp_finalize_session(s);
			else
				ngx_zmtp_close_peer_connection(s);
			return;
		}

		if (n == NGX_AGAIN || n == 0) {
			ngx_add_timer(c->write, s->timeout);
			if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
				if( s->peer_no != 1 && s->peer_no != 2)
					ngx_zmtp_finalize_session(s);
				else
					ngx_zmtp_close_peer_connection(s);
			}
			return;
		}

		b->pos += n;
	}

	if (wev->active) {
		 ngx_del_event(wev, NGX_WRITE_EVENT, 0);
	}

	++s->hs_stage;
	ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
			 "handshake: stage %ui, send:%dbytes", s->hs_stage-1, b->last-b->start);

	switch (s->hs_stage) {
		case NGX_ZMTP_HANDSHAKE_CLIENT_RECV_SIGNATURE:
			s->hs_buf->pos = s->hs_buf->last = s->hs_buf->start;
			s->hs_pkt_size_count = 0;
			ngx_zmtp_handshake_recv(c->read);
			
		case NGX_ZMTP_HANDSHAKE_SERVER_RECV_GREETING:	
		case NGX_ZMTP_HANDSHAKE_CLIENT_RECV_GREETING:
			 s->hs_buf->pos = s->hs_buf->last = s->hs_buf->start;
			s->hs_pkt_size_count = 0;
			 ngx_zmtp_handshake_recv(c->read);
			 break;
		 
		case NGX_ZMTP_HANDSHAKE_SERVER_RECV_CMD_READY:
		case NGX_ZMTP_HANDSHAKE_CLIENT_RECV_CMD_READY:
			 s->hs_buf->pos = s->hs_buf->last = s->hs_buf->start;
			 s->hs_pkt_size_count = 0;
			 ngx_zmtp_handshake_recv(c->read);
			 break;

		case NGX_ZMTP_HANDSHAKE_SERVER_RECV_SOCKTYPE:
			 s->hs_buf->pos = s->hs_buf->last = s->hs_buf->start;
			 s->hs_pkt_size_count = 0;
			 ngx_zmtp_handshake_recv(c->read);
			 break;
		case NGX_ZMTP_HANDSHAKE_SERVER_DONE:
			 ngx_log_error(NGX_LOG_INFO, c->log, 0,
						 "handshake: done");
			 ngx_zmtp_handshake_done(s);
	}
}

void
ngx_zmtp_handshake_done(ngx_zmtp_session_t *s)
{
	ngx_zmtp_core_srv_conf_t	 *cscf;
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
	
	//ngx_zmtp_free_handshake_buffers(s);
	
	
	if( s->proxy_protocol && ((cscf->peer1.len) > 0 ||
		(cscf->peer2.len) > 0) ){
		
		if( (cscf->peer1.len) > 0){
		 	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				 "handshake: done, proxy, peer1:%s", 
				 cscf->peer1.data);
			if( NULL != (s->peer1s = ngx_zmtp_get_upstream_session(s, cscf->peer1, 1)) &&
					s->peer1s->connection != NULL){
				ngx_str_set(&s->peer1s->upstream_addr , cscf->peer1.data);
				ngx_zmtp_start_peer_handshake(s->peer1s);
			}
		}
		if( (cscf->peer2.len) > 0){
		 	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				 "handshake: done, proxy, peer2:%s", 
				 cscf->peer2.data);
			if( NULL != (s->peer2s = ngx_zmtp_get_upstream_session(s, cscf->peer2, 2))&&
					s->peer2s->connection != NULL){
				ngx_str_set(&s->peer2s->upstream_addr, cscf->peer2.data);
				ngx_zmtp_start_peer_handshake(s->peer2s);
			}
		}
	}
	ngx_zmtp_upstream_checker_init(s);
	ngx_zmtp_cycle(s);
	
}
 
void ngx_zmtp_start_peer_handshake(ngx_zmtp_session_t *s)
{
	ngx_connection_t			 *c;
	ngx_zmtp_core_srv_conf_t	 *cscf;
	c = s->connection;
	
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
	
	c->read->handler =  ngx_zmtp_handshake_recv;
	c->write->handler = ngx_zmtp_handshake_send;
	c->data = s;
	if( s->hs_buf == NULL){
		s->hs_buf = ngx_create_temp_buf(s->in_pool, NGX_ZMTP_CLIENT_HANDSHAKE_BUFSIZE);
	}
	s->hs_stage = NGX_ZMTP_HANDSHAKE_CLIENT_SEND_SIGNATURE;
	s->hs_pkt_size_count = 0;
	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		"handshake: start peer handshake, pksize:%d", s->hs_pkt_size_count);
	ngx_zmtp_handshake_prepare_signature(s);
	ngx_zmtp_handshake_send(c->write);

}



void
ngx_zmtp_handshake(ngx_zmtp_session_t *s)
{
	ngx_connection_t			 *c;
	ngx_zmtp_core_srv_conf_t	 *cscf;
	c = s->connection;
	
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
	
	c->read->handler =  ngx_zmtp_handshake_recv;
	c->write->handler = ngx_zmtp_handshake_send;

	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		 "handshake: start server handshake, pksize:%d", s->hs_pkt_size_count);
 
	if( s->hs_buf == NULL){
		s->hs_buf = ngx_create_temp_buf(s->in_pool, NGX_ZMTP_CLIENT_HANDSHAKE_BUFSIZE);
	}
	s->hs_stage = NGX_ZMTP_HANDSHAKE_SERVER_RECV_SIGNATURE;

	ngx_zmtp_handshake_recv(c->read);
}

