#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include <ngx_event.h>
#include "ngx_zmtp_handshake.h"
#include "ngx_zmtp_upstream.h"
#include "ngx_zmtp.h"


//static void ngx_zmtp_upstream_recv(ngx_event_t *rev);

ngx_int_t  ngx_zmtp_init_peer_connection(
	ngx_zmtp_session_t *s, 
	ngx_str_t peerstring)
{
	
	ngx_socket_t       st;
	ngx_err_t          err;
	int rc;
	ngx_uint_t         level;
	ngx_connection_t   *con = NULL;
	ngx_addr_t 		peeraddr;
	
	
	//ngx_memzero(peeraddr, sizeof(ngx_addr_t));
	if (ngx_parse_addr_port(s->in_pool, 
			&peeraddr, 
			peerstring.data,
			strlen((char*)peerstring.data)) != NGX_OK) {
		return NGX_ERROR;
	}
	st = ngx_socket(peeraddr.sockaddr->sa_family, SOCK_STREAM, 0);

	ngx_log_error(NGX_LOG_DEBUG, s->log, 0, "stream socket %d",st);
	con = ngx_get_connection(st, s->log);		

	if (con == NULL) {
		if (ngx_close_socket(st) == -1) {
			ngx_log_error(NGX_LOG_WARN, s->log, ngx_socket_errno,
			          ngx_close_socket_n "failed");
		}

		return NGX_ERROR;
	}
	
	if (ngx_nonblocking(st) == -1) {
		ngx_log_error(NGX_LOG_WARN, s->log, ngx_socket_errno,
					  ngx_nonblocking_n " failed");

		return NGX_ERROR;
	}

	rc = connect(st, peeraddr.sockaddr, peeraddr.socklen);

	if (rc == -1) {
		err = ngx_socket_errno;

		ngx_log_error(NGX_LOG_WARN, s->log, ngx_socket_errno,
							  ngx_nonblocking_n " rc=-1,err=:%d, again=%d", err, NGX_EAGAIN);
		

		if (err != NGX_EINPROGRESS && err != NGX_EAGAIN)
		{
			if (err == NGX_ECONNREFUSED
				/*
				* Linux returns EAGAIN instead of ECONNREFUSED
				* for unix sockets if listen queue is full
				*/
				|| err == NGX_EAGAIN
				|| err == NGX_ECONNRESET
				|| err == NGX_ENETDOWN
				|| err == NGX_ENETUNREACH
				|| err == NGX_EHOSTDOWN
				|| err == NGX_EHOSTUNREACH)
			{
				level = NGX_LOG_ERR;

			} else {
				level = NGX_LOG_CRIT;
			}

			ngx_log_error(level, s->log, err, "connect() to %V failed",
			peerstring);

			ngx_close_connection(con);
			con = NULL;

			return NGX_ERROR;
		}
	}	
	s->connection = con;
	s->connection->data = s;
	s->connection->pool = s->in_pool;
		
	s->connection->recv = ngx_recv;
	s->connection->send = ngx_send;
	s->connection->recv_chain = ngx_recv_chain;
	s->connection->send_chain = ngx_send_chain;

	s->connection->sendfile = 1;
	return NGX_OK;		
}

ngx_zmtp_session_t* ngx_zmtp_init_peer_session(ngx_zmtp_session_t*s)
{
	ngx_zmtp_session_t*session;
	session = ngx_pcalloc(s->connection->pool, sizeof(ngx_zmtp_session_t));
	if (session == NULL) {
		return NULL;
	}
		
	session->signature = NGX_ZMTP_MODULE;
	session->main_conf = s->main_conf;
	session->srv_conf = s->srv_conf;

#if (NGX_ZMQP_SSL)
	session->ssl = s->ssl;
#endif
		
	session->ctx = ngx_pcalloc(s->connection->pool, sizeof(void *) * ngx_zmtp_max_module);
	if (session->ctx == NULL) {
		return NULL;
	}
	session->hs_buf = ngx_create_temp_buf(s->connection->pool, NGX_ZMTP_CLIENT_HANDSHAKE_BUFSIZE);
	 
	return session;
}


ngx_zmtp_session_t*
ngx_zmtp_get_upstream_session(ngx_zmtp_session_t *s, ngx_str_t peer, int peer_no)
{
	ngx_zmtp_session_t * news = NULL;
	if( peer.len > 0){
		if( NULL == 
				(news = ngx_zmtp_init_peer_session(s))){
			ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
									   "ngx_zmtp_init_peer_connection get peer:%s seesion: error",peer.data);
			
			ngx_zmtp_finalize_session(s);
			return news;
		}
		news->in_pool = ngx_create_pool(NGX_ZMTP_INPOOL_SIZE, s->connection->log);
		news->log = s->connection->log;
		news->parent = s;
		news->peer_no = peer_no;
		if( s->zmtp_sock_type == ZMTP_SOCK_XPUB ){
			news->zmtp_sock_type = ZMTP_SOCK_XSUB;
		}else{
			news->zmtp_sock_type = ZMTP_SOCK_XPUB;
		}
		
		if( NGX_OK != ngx_zmtp_init_peer_connection(news, peer) ){
			ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
									   "ngx_zmtp_init_peer_connection peer:%s: error", peer.data);
			news->connection = NULL;	
			return news;
		}
		
		ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
									   "start peer seesion:%s OK, fd:%d", peer.data, s->connection->fd);
						
	}
	return news;
}


void
ngx_zmtp_upstream_recv(ngx_event_t *rev)
{
	ngx_int_t					n;
	ngx_connection_t		   *c;
	ngx_zmtp_session_t	   *s;
	ngx_zmtp_core_srv_conf_t    *cscf;
	
	ngx_chain_t 			   *in;
	ngx_buf_t				   *b;
	u_char					   flag;
	size_t					   size, old_size;
	u_char                     *p, *old_pos;
	uint64_t					shortsize;
	c = rev->data;
	s = c->data;

	if( s->con_valid == 0){
		return;
	}

	old_pos = NULL;
	old_size = 0;
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
	ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
						"ngx_zmtp_upstream_recv:%s, enter, zmtp:%d,peerno:%d,con_valid:%d", 
						s->upstream_addr.data,
						s->zmtp_sock_type, s->peer_no, s->con_valid);

	if (c->destroyed) {
		ngx_log_error(NGX_LOG_WARN, c->log, 0,
					"upstream con destroyed");
		return;
	}

	if (rev->timer_set) {
		ngx_del_timer(rev);
	}

	for( ;; ) {

		if (rev->eof) {
			ngx_log_error(NGX_LOG_WARN, c->log, 0,
					"upstream rev eof");
			return;
		}
		
		if (s->cycle_in == NULL) {
			s->cycle_in = ngx_zmtp_alloc_in_buf(s);
			if (s->cycle_in == NULL) {
				ngx_log_error(NGX_LOG_WARN, c->log, 0,
							"upstream in buf alloc failed");
				ngx_zmtp_finalize_session(s);
				return;
			}
			ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
							"upstream allocate new buf for input");
		}

		in = s->cycle_in;
		b  = in->buf;

		if (old_size) {

			b->pos = b->start;
			b->last = ngx_movemem(b->pos, old_pos, old_size);

			ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
					"upstream, reusing formerly read data: %d, b->last-b->pos=%d", 
						old_size, b->last-b->pos);

		} else {

			//b->pos = b->last = b->start;
		}

		if (!rev->ready) {
			if (ngx_handle_read_event(rev, 0) != NGX_OK) {
				ngx_log_error(NGX_LOG_WARN, c->log, 0,
						"upstream in buf alloc failed");
				ngx_zmtp_finalize_session(s);
				return;
			}

			if (!rev->timer_set) {
				ngx_add_timer(rev, cscf->preread_timeout);
			}

			return ;
		}

		
		ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
					"new read: b->last-b->pos=%d", 
						b->last-b->pos);
		n = c->recv(c, b->last, b->end - b->last);
		

		if (n == NGX_ERROR || n == 0) {
			ngx_log_error(NGX_LOG_WARN, c->log, 0,
					"upstream peer:%d, receive n=0, fd:%d, type:%d, close", s->peer_no, 
					s->connection->fd, s->zmtp_sock_type);
			ngx_zmtp_close_peer_connection(s);
			return;
		}

		if (n == NGX_AGAIN) {
			ngx_add_timer(rev, cscf->preread_timeout);
			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				ngx_zmtp_finalize_session(s);
			}
			return;
		}

		b->last += n;
		s->in_bytes += n;
	
		shortsize = 0;
		flag = 0;

		old_pos = NULL;
		old_size = 0;
		
		 /* parse headers */
		while (b->pos < b->last) {
			p = b->pos;
			flag = *p++;
			if( flag == 0x0 ||
				flag == 0x1 ){
			//short size
				if (b->last - p < 1)
					break;
				shortsize = *p++;	
			}else if( flag == 0x2 ||
				flag == 0x3 ){
			//long size
				if (b->last - p < 2)
					break;

				shortsize = (uint64_t) *p << 56 |
						(uint64_t) *(p+1) << 48 |
						(uint64_t) *(p+2) << 40 |
						(uint64_t) *(p+3) << 32 |
						(uint64_t) *(p+4) << 24 |
						(uint64_t) *(p+5) << 16 |
						(uint64_t) *(p+6) << 8  |
						(uint64_t) *(p+7);
				if( s->zmtp_sock_type == ZMTP_SOCK_XSUB )
					ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
			 			"upstream long size message, flag:%d, n:%d", flag,shortsize);
				p += 8;
			}else{
				ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
			 		"upstream receive cmd message, flag:%d ", flag);
			}
		
			size = b->last-p;
			if( size < shortsize ){
				old_size = b->last - b->pos;
				old_pos = b->pos;
				break;
			}
			old_size = size - shortsize;
			old_pos = p + shortsize;	  
			

			ngx_zmtp_message_from_upstream(s, b, shortsize + p-b->pos);

			b->pos = old_pos;
		}
		if( old_size == 0){
			b->pos  = b->last = b->start;
		}
	}


}


void
ngx_zmtp_upstream_send(ngx_event_t *wev)
{
	ngx_int_t					 n;
	ngx_connection_t			*c;
	ngx_zmtp_session_t 		*s;
	ngx_buf_t					*b;
	ngx_zmtp_core_srv_conf_t	*cscf;
	c = wev->data;
	s = c->data;

	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);

	if( s->con_valid == 0){
		return;
	}


	if (c->destroyed) {
		return;
	}

	if (wev->timedout) {
		ngx_log_error(NGX_LOG_WARN, c->log, NGX_ETIMEDOUT,
			"handshake: send: client timed out");
		c->timedout = 1;
		ngx_zmtp_close_peer_connection(s);
		return;
	}

	if (wev->timer_set) {
		ngx_del_timer(wev);
	}

	b = s->cycle_out->buf;

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
			ngx_zmtp_close_peer_connection(s);
			return;
		}

		if (n == NGX_AGAIN || n == 0) {
			ngx_add_timer(c->write, s->timeout);
			if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
				ngx_zmtp_finalize_session(s);
			}
			return;
		}

		b->pos += n;
	}
	if( s->zmtp_sock_type == ZMTP_SOCK_XSUB)
		ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
				"peer cycle: send: %d bytes", b->last-b->start);

	b->pos = b->last = b->start;
	if (wev->active) {
		ngx_del_event(wev, NGX_WRITE_EVENT, 0);
	}

}

void
ngx_zmtp_upstream_cycle(ngx_zmtp_session_t *s)
{
	ngx_connection_t           *c;

	c = s->connection;
	c->read->handler =  ngx_zmtp_upstream_recv;
	c->write->handler = ngx_zmtp_upstream_send;

	if( s->parent->channel_name->last - s->parent->channel_name->start > 0){
		ngx_zmtp_message_to_upstream(s, s->parent->channel_name, 
						s->parent->channel_name->last - s->parent->channel_name->start);
	}
	ngx_zmtp_upstream_recv(c->read);
}

void
ngx_zmtp_message_to_upstream(ngx_zmtp_session_t*s,
	ngx_buf_t *in, size_t size){

	ngx_buf_t   *b;
	if( s->con_valid == 0){
		return;
	}
	
	if (s->cycle_out == NULL) {
		s->cycle_out = ngx_zmtp_alloc_in_buf(s);
		if (s->cycle_out == NULL) {
			ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
					"out buf alloc failed");
			ngx_zmtp_finalize_session(s);
			return;
		}
		//b->pos = b->last = b->start;
	}
	b  = s->cycle_out->buf;

	if( b->last + size < b->end){
		
		b->last = ngx_movemem(b->last, in->pos, size);
		//if( s->zmtp_sock_type == ZMTP_SOCK_XSUB)
		//ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
		//				"ngx_zmtp_upstream_incoming_message, enter, pkt size:%d, buffered:%d,"
		//				"zmtp:%d,peerno:%d", 
		//				b->last-b->pos, b->last-b->start, s->zmtp_sock_type, s->peer_no);
		ngx_zmtp_upstream_send(s->connection->write);
	}else{
		ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
					"drop packet as peer not fast enough");
	}
}

void 
ngx_zmtp_message_from_upstream(
	ngx_zmtp_session_t*s, ngx_buf_t *in, size_t size)
{
	ngx_buf_t	*b;
	
	if( s->con_valid == 0 || 
		s->parent->connection == NULL ||
		s->parent->connection->destroyed){
		return;
	}
	
	if (s->parent->cycle_out == NULL) {
		s->parent->cycle_out = ngx_zmtp_alloc_in_buf(s);
		if (s->parent->cycle_out == NULL) {
			ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
					"out buf alloc failed");
			ngx_zmtp_finalize_session(s);
			return;
		}
	}
	
	b  = s->parent->cycle_out->buf;
	if( b->last + size < b->end ){
		b->last = ngx_movemem(b->last, in->pos, size);
		ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
								"from peer:%d, remain size:%d, recv size:%d", 
								s->peer_no, b->last-b->pos, size);
	 
		ngx_zmtp_send(s->parent->connection->write);
	}else{
		ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
					"drop packet to client as client not fast enough");
	}
}

