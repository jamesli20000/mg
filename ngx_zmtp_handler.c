/*
 jamesli20000
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_zmtp.h"
#include "ngx_zmtp_handshake.h"
#include "ngx_zmtp_upstream.h"




//static void ngx_zmtp_proxy_protocol_handler(ngx_event_t *rev);

ngx_chain_t *
ngx_zmtp_alloc_in_buf(ngx_zmtp_session_t *s)
{
	ngx_chain_t        *cl;
	ngx_buf_t          *b;
	size_t              size;

	if ((cl = ngx_alloc_chain_link(s->in_pool)) == NULL
			|| (cl->buf = ngx_calloc_buf(s->in_pool)) == NULL)
	{
		return NULL;
	}

	cl->next = NULL;
	b = cl->buf;

	size = NGX_ZMTP_MAX_PKT_SIZE;

	b->start = b->last = b->pos = ngx_palloc(s->in_pool, size);
	if (b->start == NULL) {
		return NULL;
	}
	b->end = b->start + size;

	return cl;
}


void
ngx_zmtp_recv(ngx_event_t *rev)
{
	ngx_int_t					n;
	ngx_connection_t			*c;
	ngx_zmtp_session_t			*s;
	ngx_zmtp_core_srv_conf_t	*cscf;
	ngx_slab_pool_t            *shpool;
	ngx_shm_zone_t             *shm_zone;
	uint32_t           			*peerno;
	
	ngx_chain_t 				*in;
	ngx_buf_t					*b;
	u_char						flag;
	size_t						size, old_size;
	u_char						*p, *old_pos;
	uint64_t					shortsize;	
	c = rev->data;
	s = c->data;

	old_pos = NULL;
	old_size = 0;
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);
		
	shm_zone = cscf->shm_zone;
	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	peerno = shm_zone->data;
	
	if (c->destroyed) {
		return;
	}

	if (rev->timer_set) {
		ngx_del_timer(rev);
	}

	for( ;; ) {

		if (rev->eof) {
			return;
		}

		if (s->cycle_in == NULL) {
			s->cycle_in = ngx_zmtp_alloc_in_buf(s);
			if (s->cycle_in == NULL) {
				ngx_log_error(NGX_LOG_WARN, c->log, 0,
								"in buf alloc failed");
				ngx_zmtp_finalize_session(s);
				return;
			}
		}
		in = s->cycle_in;
		b  = in->buf;

		if (old_size) {

			ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
						"reusing formerly read data: %d", old_size);

			b->pos = b->start;
			b->last = ngx_movemem(b->pos, old_pos, old_size);

		}else{
		// b->pos = b->last = b->start;
		}

		if (!rev->ready) {
			if (ngx_handle_read_event(rev, 0) != NGX_OK) {
				ngx_zmtp_finalize_session(s);
				return;
			}

			if (!rev->timer_set) {
				ngx_add_timer(rev, cscf->preread_timeout);
			}

			return ;
		}		

		n = c->recv(c, b->last, b->end - b->last);

		if (n == NGX_ERROR || n == 0) {
			ngx_log_error(NGX_LOG_INFO, c->log, 0,
						"receive fin from other side: fd %d", c->fd);
			ngx_zmtp_finalize_session(s);
			return;
		}

		if (n == NGX_AGAIN) {
			ngx_add_timer(rev, s->timeout);
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
		while( b->pos < b->last ){	        
			p = b->pos;
			flag = *p++;
			if( flag == 0x0 ||
				flag == 0x1 ){
				//short size
				if (b->last - p < 1)
					break;
				shortsize = *p++;	
			}else if( flag == 0x02 ||
				flag == 0x03 ){
				//long size
				if (b->last - p < 8)
					break;

				shortsize = (uint64_t) *p << 56 |
						(uint64_t) *(p+1) << 48 |
						(uint64_t) *(p+2) << 40 |
						(uint64_t) *(p+3) << 32 |
						(uint64_t) *(p+4) << 24 |
						(uint64_t) *(p+5) << 16 |
						(uint64_t) *(p+6) << 8  |
						(uint64_t) *(p+7);
				if( s->zmtp_sock_type == ZMTP_SOCK_XPUB ){
					ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
							"long size message, flag:%d, n:%d", flag,shortsize);
				}
				p += 8;
			}
			
			size = b->last-p;
			if( size < shortsize ){
				break;
			}
			old_size = size - shortsize;
			old_pos = p + shortsize ;	

			if( s->zmtp_sock_type == ZMTP_SOCK_XPUB && *p == 0x1)//sub from upstream
			{
				if( s->channel_name->end - s->channel_name->last > shortsize+ p - b->pos  ) 
				{
					s->channel_name->last = ngx_movemem(s->channel_name->last, 
															b->pos, shortsize+ p- b->pos);
					ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
									"save subscribe %s,now total:%d ", 
									s->channel_name->last - shortsize + 1,
									s->channel_name->last - s->channel_name->pos);

					s->unsub_channel_name->last = ngx_movemem(s->unsub_channel_name->last,
															b->pos, shortsize+ p- b->pos);
					*(s->unsub_channel_name->last - shortsize) = 0x0;
				}
			}

			if( s->zmtp_sock_type == ZMTP_SOCK_XPUB && *p == 0x1)
			{
				ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
							" subscribe to %s,shortsize:%d", p+1, shortsize);	 				
			}

			if( *peerno != 2 ){
				//default to peer 1
				if( NULL != s->peer1s && NULL != s->peer1s->connection && 
						s->peer1s->con_valid == 1 ){			 
					if( s->zmtp_sock_type == ZMTP_SOCK_XPUB ){
						ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
										"pub send  to peer1 to sub ");	
					}
					s->active_peer_no = 1;
					ngx_zmtp_message_to_upstream(s->peer1s, b, shortsize+p-b->pos);
				}
				else if( NULL != s->peer2s && NULL != s->peer2s->connection &&
						s->peer2s->con_valid == 1){			
					if( s->zmtp_sock_type == ZMTP_SOCK_XPUB ){
						ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
								"pub send  to peer2 to sub ");	
					}
					s->active_peer_no = 2;
					ngx_zmtp_message_to_upstream(s->peer2s, b, shortsize+p-b->pos);
				}
			}else{
				if( NULL != s->peer2s && NULL != s->peer2s->connection && 
						s->peer2s->con_valid == 1 ){			 
					if( s->zmtp_sock_type == ZMTP_SOCK_XPUB ){
						ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
										"pub sendto peer2 to sub"); 
					}
					s->active_peer_no = 2;
					ngx_zmtp_message_to_upstream(s->peer2s, b, shortsize+p-b->pos);
				}
				else if( NULL != s->peer1s && NULL != s->peer1s->connection &&
						s->peer1s->con_valid == 1){ 		
					if( s->zmtp_sock_type == ZMTP_SOCK_XPUB ){
						ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
								"pub send to peer1 to sub"); 
					}
					s->active_peer_no = 1;
					ngx_zmtp_message_to_upstream(s->peer1s, b, shortsize+p-b->pos);
				}

			}

			b->pos = old_pos;
		}
		if( old_size == 0){
			b->pos = b->last = b->start;
		}
	}
}





void
ngx_zmtp_send(ngx_event_t *wev)
{
	ngx_int_t					 n;
	ngx_connection_t			*c;
	ngx_zmtp_session_t 		*s;
	ngx_buf_t					*b;
	ngx_zmtp_core_srv_conf_t	*cscf;
	c = wev->data;
	s = c->data;

	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);


	if (c->destroyed) {
		return;
	}

	if (wev->timedout) {
		ngx_log_error(NGX_LOG_WARN, c->log, NGX_ETIMEDOUT,
						"client send: client timed out");
		c->timedout = 1;
		ngx_zmtp_finalize_session(s);
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
			ngx_zmtp_finalize_session(s);
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
	ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
					"client cycle: send: %d bytes", b->last-b->start);
	b->pos = b->last = b->start;
	if (wev->active) {
		ngx_del_event(wev, NGX_WRITE_EVENT, 0);
	}

}


void
ngx_zmtp_init_connection(ngx_connection_t *c)
{

	ngx_uint_t                    i;
	struct sockaddr              *sa;
	ngx_zmtp_port_t            *port;
	struct sockaddr_in           *sin;
	ngx_zmtp_in_addr_t         *addr;
	ngx_zmtp_session_t         *s;
	ngx_zmtp_addr_conf_t       *addr_conf;
	ngx_zmtp_core_srv_conf_t	*cscf;
	ngx_pool_t  				*tmp_pool;


	port = c->listening->servers;

	if (port->naddrs > 1) {

	/*
	* There are several addresses on this port and one of them
	* is the "*:port" wildcard so getsockname() is needed to determine
	* the server address.
	*
	* AcceptEx() and recvmsg() already gave this address.
	*/

	if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
		ngx_zmtp_close_connection(c);
		return;
	}

	sa = c->local_sockaddr;

	switch (sa->sa_family) {



		default: /* AF_INET */
			sin = (struct sockaddr_in *) sa;

			addr = port->addrs;

		/* the last address is "*" */

			for (i = 0; i < port->naddrs - 1; i++) {
				if (addr[i].addr == sin->sin_addr.s_addr) {
					break;
				}
			}

			addr_conf = &addr[i].conf;

			break;
		}

	} else {
		switch (c->local_sockaddr->sa_family) {

			default: /* AF_INET */
				addr = port->addrs;
				addr_conf = &addr[0].conf;
				break;
		}
	}

	tmp_pool = ngx_create_pool(NGX_ZMTP_INPOOL_SIZE, c->log);
	s = ngx_pcalloc(tmp_pool, sizeof(ngx_zmtp_session_t));
	if (s == NULL) {
		ngx_zmtp_close_connection(c);
		return;
	}
	s->timer_enabled = 0;
	s->in_pool = tmp_pool;
	s->signature = NGX_ZMTP_MODULE;
	s->main_conf = addr_conf->ctx->main_conf;
	s->srv_conf = addr_conf->ctx->srv_conf;

	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);

	s->channel_name = ngx_create_temp_buf(s->in_pool, cscf->channel_len);
	s->channel_name->pos = s->channel_name->last = s->channel_name->start;
	
	s->unsub_channel_name = ngx_create_temp_buf(s->in_pool, cscf->channel_len);
	s->unsub_channel_name->pos = s->unsub_channel_name->last = s->unsub_channel_name->start;

	ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
									"channel len:%d", cscf->channel_len);

	
	s->active_peer_no = 0;
	s->peer1s = NULL;
	s->peer2s = NULL;

#if (NGX_ZMQP_SSL)
	s->ssl = addr_conf->ssl;
#endif
	
	if (c->buffer) {
		s->received += c->buffer->last - c->buffer->pos;
	}

	s->connection = c;
	c->data = s;
	s->log = c->log;
	/*
	s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_zmtp_max_module);
	if (s->ctx == NULL) {
		ngx_zmtp_close_connection(c);
		return;
	}
	*/
	s->hs_stage = NGX_ZMTP_HANDSHAKE_SERVER_RECV_SIGNATURE;
	s->hs_pkt_size_count = 0;
	s->zmtp_sock_type = addr_conf->zmtp_sock_type;
	s->proxy_protocol = addr_conf->proxy_protocol;
	ngx_zmtp_handshake(s);


}

void
ngx_zmtp_cycle(ngx_zmtp_session_t *s)
{
	ngx_connection_t           *c;

	c = s->connection;
	c->read->handler =  ngx_zmtp_recv;
	c->write->handler = ngx_zmtp_send;

	ngx_zmtp_recv(c->read);
}



void
ngx_zmtp_session_handler(ngx_event_t *rev)
{
	ssize_t 					n;
	ngx_connection_t      		*c;
	ngx_buf_t				    *b;
	ngx_zmtp_session_t 			*s;
	ngx_int_t                    rc;
	ngx_zmtp_core_srv_conf_t 	*cscf;
	size_t                       size;

	c = rev->data;		
	b = c->buffer;
	s = c->data;

	
	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);

	if (c->read->timedout) {
		rc = NGX_ZMQ_OK;

	} else if (c->read->timer_set) {
		rc = NGX_AGAIN;
	} else{
		rc = NGX_AGAIN;
	}
	
	while (rc == NGX_AGAIN) {

		size = c->buffer->end - c->buffer->last;
	
		if (size == 0) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "read buffer full");
			rc = NGX_ZMQ_BAD_REQUEST;
			break;
		}

		if (c->read->eof) {
			rc = NGX_ZMQ_OK;
			break;
		}
		
		if (!c->read->ready) {
			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				rc = NGX_ERROR;
				break;
			}

			if (!c->read->timer_set) {
				ngx_add_timer(c->read, cscf->preread_timeout);
			}

			c->read->handler = ngx_zmtp_session_handler;

			return ;
		}
		n = c->recv(c, b->last, b->end - b->last);
		if (n == NGX_ERROR) {
			rc = NGX_ZMQ_OK;
			break;
		}

		if (n > 0) {
			b->last += n;
		}

	}
	
	if (c->read->timer_set) {
		ngx_del_timer(c->read);
	}
	
	ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
						"zmq read ok");
}

void
ngx_zmtp_close_session_handler(ngx_event_t *e)
{
	ngx_zmtp_session_t                 *s;
	ngx_connection_t                   *c;
	
	s = e->data;
	c = s->connection;

	if( s->peer_no == 1 || s->peer_no == 2){
		ngx_zmtp_close_peer_connection(s);
		if( s->in_pool ){
			ngx_destroy_pool(s->in_pool);
		}
	
	}else{
		if( !s->timer_enabled ){
			ngx_zmtp_finalize_client_session(s);
		}
		//s->connection = NULL;
	}
}

void 
ngx_zmtp_finalize_client_session(ngx_zmtp_session_t *s)
{
	if( NULL != s->peer1s && NULL != s->peer1s->connection && 
			s->peer1s->con_valid == 1 &&
			s->peer1s->connection->destroyed !=1){

		if( s->peer1s->in_pool ){
			ngx_destroy_pool(s->peer1s->in_pool);
		}
		ngx_zmtp_close_peer_connection(s->peer1s);
		
	}
			
	if( NULL != s->peer2s && NULL != s->peer2s->connection &&
			s->peer2s->con_valid == 1 &&
			s->peer2s->connection->destroyed !=1){
	
		if( s->peer2s->in_pool ){
			ngx_destroy_pool(s->peer2s->in_pool);
		}
		ngx_zmtp_close_peer_connection(s->peer2s);
		
	}

	ngx_zmtp_close_connection(s->connection);
	if (s->in_pool) {
		ngx_destroy_pool(s->in_pool);
	}

}


void
ngx_zmtp_finalize_session(ngx_zmtp_session_t *s)
{
	ngx_event_t 	   *e;

	ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
				"finalize zmq session, peerno:%d,type:%d", 
				s->peer_no,s->zmtp_sock_type);

	if( s->connection->destroyed)
	{
		return;
	}
			
	s->connection->destroyed = 1;
    e = &s->close;
    e->data = s;
    e->handler = ngx_zmtp_close_session_handler;
    e->log = s->connection->log;

	ngx_post_event(e, &ngx_posted_events);
	

}

void
ngx_zmtp_close_peer_connection(ngx_zmtp_session_t *s)
{
	
	ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
					"close zmq peer connection, peerno:%d,type:%d", 
					s->peer_no,s->zmtp_sock_type);
	if( s->connection )
		ngx_close_connection(s->connection);
	s->connection->destroyed = 1;
	s->connection = NULL;
	s->con_valid = 0;
}


void
ngx_zmtp_close_connection(ngx_connection_t *c)
{
	ngx_pool_t  *pool;


	pool = c->pool;
	c->destroyed = 1;
	ngx_close_connection(c);

	ngx_destroy_pool(pool);
	ngx_log_error(NGX_LOG_INFO, c->log, 0,
	               "ngx_zmtp_close_connection: %d OK", c->fd);
}


void
ngx_zmtp_upstream_connection_monitor(ngx_event_t *ev) 
{
	ngx_zmtp_session_t *s;
	ngx_zmtp_core_srv_conf_t 	*cscf;
	ngx_slab_pool_t            *shpool;
	ngx_shm_zone_t             *shm_zone;
	uint32_t           *peerno;
	
	s = ev->data;
	//ngx_log_error(NGX_LOG_INFO, s->log, 0,
	//					   "ngx_zmtp_upstream_connection_monitor enter ");
	if( NULL == s->connection || 
		s->connection->destroyed){
		ngx_log_error(NGX_LOG_INFO, s->log, 0,
						   "ngx_zmtp_upstream_connection_monitor, connection lost with client,drop timer ");
		ngx_zmtp_finalize_client_session(s);
		return;
	}

	cscf = ngx_zmtp_get_module_srv_conf(s, ngx_zmtp_core_module);

	shm_zone = cscf->shm_zone;
	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	peerno = shm_zone->data;
	
	ngx_log_error(NGX_LOG_INFO, s->log, 0,
						   "ngx_zmtp_upstream_connection_monitor, choose peerno:%d,activepeer:%d,ztmtype:%d ", 
						   *peerno,s->active_peer_no, s->zmtp_sock_type);
	
	
	if( NULL != s->peer1s &&  NULL == s->peer1s->connection  ){
		if( NGX_OK == ngx_zmtp_init_peer_connection(s->peer1s, cscf->peer1)){
			ngx_zmtp_start_peer_handshake(s->peer1s);
		}

		ngx_log_error(NGX_LOG_INFO, s->log, 0,
					   "try re-handshake for peer1:%s ", cscf->peer1.data);
		
	}

	if( NULL != s->peer2s && NULL == s->peer2s->connection){			 
		if( NGX_OK == ngx_zmtp_init_peer_connection(s->peer2s, cscf->peer2)){
			ngx_zmtp_start_peer_handshake(s->peer2s);
		}
		 
		ngx_log_error(NGX_LOG_INFO, s->log, 0,
					   "try re-handshake for peer2:%s ", cscf->peer2.data);
		 
	}

	if( *peerno != 2){
	//default case, peer1 is the top priority
		if( s->active_peer_no != 1 && NULL != s->peer1s && s->peer1s->con_valid == 1 ){
			if( NGX_OK == ngx_zmtp_switch_peer(s->peer2s, s->peer1s, 
						s->channel_name, s->unsub_channel_name)){
				s->active_peer_no = 1;
				ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
							"switch con to peer:%d",s->active_peer_no);
			}
		}else if( s->active_peer_no != 2 && NULL != s->peer1s && s->peer1s->con_valid == 0){
			if( NGX_OK == ngx_zmtp_switch_peer(s->peer1s, s->peer2s, 
						s->channel_name, s->unsub_channel_name)){
				s->active_peer_no = 2;
				ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
							"switch con to peer:%d",s->active_peer_no);
			}	
		}
	}else {
		if( s->active_peer_no != 2 && NULL != s->peer2s && s->peer2s->con_valid == 1 ){
			if( NGX_OK == ngx_zmtp_switch_peer(s->peer1s, s->peer2s, 
						s->channel_name, s->unsub_channel_name)){
				s->active_peer_no = 2;
				ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
							"switch con to peer:%d",s->active_peer_no);
			}
		}else if( s->active_peer_no != 1 && NULL != s->peer2s && s->peer2s->con_valid == 0 ){
			if( NGX_OK == ngx_zmtp_switch_peer(s->peer2s, s->peer1s, 
						s->channel_name, s->unsub_channel_name)){
				s->active_peer_no = 1;
				ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
							"switch con to peer:%d",s->active_peer_no);
			}	
		}
	}

	ngx_add_timer(ev, 1500);
}
 
 
ngx_int_t
ngx_zmtp_upstream_checker_init(ngx_zmtp_session_t *s)
{
	ngx_log_error(NGX_LOG_DEBUG, s->log, 0,
						   "ngx_zmtp_upstream_checker_init enter,proxy:%d ",s->proxy_protocol);

	if( s->proxy_protocol && s->connection->destroyed != 1){
		//ngx_memzero(&s->con_monitor, sizeof(ngx_event_t));
			
		s->con_monitor.handler = ngx_zmtp_upstream_connection_monitor;
		s->con_monitor.log = s->log;
		s->con_monitor.data = s;
		s->timer_enabled = 1;
		ngx_add_timer(&s->con_monitor, 3000);
	 	
	}
	return NGX_OK;
}

ngx_int_t
ngx_zmtp_switch_peer(ngx_zmtp_session_t *s_old, 
				ngx_zmtp_session_t *s_new, 
				ngx_buf_t*channel_name,
				ngx_buf_t*unsub_channel_name)
{
	if( NULL != s_new && s_new->con_valid == 1 && 
		channel_name->last - channel_name->pos > 0){
		if( NULL != s_old && NULL != s_old->connection && s_old->con_valid == 1){
			ngx_zmtp_message_to_upstream(s_old, unsub_channel_name, 
						unsub_channel_name->last - unsub_channel_name->pos);
		}
		
		ngx_zmtp_message_to_upstream(s_new, channel_name, 
						channel_name->last - channel_name->pos);
		ngx_log_error(NGX_LOG_INFO, s_new->connection->log, 0,
						"resend subscribe to peer:%d", s_new->peer_no);
		
		return NGX_OK;
		
	}
	return NGX_ERROR;
}

