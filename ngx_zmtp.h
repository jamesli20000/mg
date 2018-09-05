/*
 author  jamesli20000

 */


#ifndef _NGX_ZMQ_H_INCLUDED_
#define _NGX_ZMQ_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

typedef enum ZMTP_SOCK_TYPE{
	ZMTP_SOCK_XSUB = 0,	
	ZMTP_SOCK_XPUB,
}e_zmtp_sock_type;

typedef struct {
    ngx_str_t                 addr;
    unsigned                  port;
	unsigned 				  valid:1;
} ngx_zmtp_endpoint_t;



struct ngx_zmtp_session_s {
    uint32_t                       	signature;         /* "STRM" */

    ngx_connection_t              	*connection;
    unsigned						con_valid:1;
	unsigned						timer_enabled:1;
	unsigned						peer_no;
	unsigned						active_peer_no;
	ngx_event_t						close;


    off_t                          	received;
    time_t                         	start_sec;
    ngx_msec_t                     	start_msec;
	ngx_msec_t					   	timeout;

    void                         	**ctx;
    void                         	**main_conf;
    void                         	**srv_conf;
	ngx_log_t          				*log;


    ngx_uint_t                     	status;

    unsigned                       	ssl:1;

    unsigned                		stat_processing:1;

    unsigned                		health_check:1;

	e_zmtp_sock_type				zmtp_sock_type;
	unsigned                		proxy_protocol:1;
	ngx_chain_t                		*cycle_in;
	ngx_chain_t                		*cycle_out;
	uint64_t                		in_bytes;
	uint64_t						out_bytes;

	ngx_buf_t						*channel_name;
	ngx_buf_t						*unsub_channel_name;
	ngx_str_t						upstream_addr;

	/* handshake data */
    ngx_buf_t              			*hs_buf;
    u_char                 			*hs_digest;
    unsigned                		hs_old:1;
    ngx_uint_t              		hs_stage;
	ngx_uint_t              		hs_socktype_len;
	ngx_uint_t						hs_pkt_size_count;
	
	struct ngx_zmtp_session_s		*parent;

	struct ngx_zmtp_session_s      	*peer1s;
	struct ngx_zmtp_session_s      	*peer2s;
	ngx_pool_t             			*in_pool;
	ngx_event_t 					con_monitor; 

};


typedef struct ngx_zmtp_session_s  ngx_zmtp_session_t;


#define NGX_ZMQ_OK                        200
#define NGX_ZMQ_BAD_REQUEST               400
#define NGX_ZMQ_FORBIDDEN                 403
#define NGX_ZMQ_INTERNAL_SERVER_ERROR     500

#define NGX_ZMTP_MAX_PKT_SIZE             3000
#define NGX_ZMTP_INPOOL_SIZE              4096

#define NGX_ZMTP_CHANNEL_NAME_LEN	      500



typedef struct {
    void                         **main_conf;
    void                         **srv_conf;
} ngx_zmtp_conf_ctx_t;


typedef struct {
    ngx_sockaddr_t                 sockaddr;
    socklen_t                      socklen;

    /* server ctx */
    ngx_zmtp_conf_ctx_t         *ctx;

    unsigned                       bind:1;
    unsigned                       wildcard:1;
    unsigned                       ssl:1;

    unsigned                       reuseport:1;
    unsigned                       so_keepalive:2;
    unsigned                       proxy_protocol:1;

    int                            backlog;
    int                            rcvbuf;
    int                            sndbuf;
    int                            type;
	e_zmtp_sock_type			   zmtp_sock_type;
	
} ngx_zmtp_listen_t;


typedef struct {
    ngx_zmtp_conf_ctx_t            *ctx;
    ngx_str_t                      addr_text;
    unsigned                       ssl:1;
    unsigned                       proxy_protocol:1;
	e_zmtp_sock_type			   zmtp_sock_type;
} ngx_zmtp_addr_conf_t;

typedef struct {
    in_addr_t                      addr;
    ngx_zmtp_addr_conf_t         conf;
} ngx_zmtp_in_addr_t;




typedef struct {
    /* ngx_zmtp_in_addr_t or ngx_zmtp_in6_addr_t */
    void                          *addrs;
    ngx_uint_t                     naddrs;
} ngx_zmtp_port_t;


typedef struct {
    int                            family;
    int                            type;
    in_port_t                      port;
    ngx_array_t                    addrs; /* array of ngx_zmtp_conf_addr_t */
} ngx_zmtp_conf_port_t;


typedef struct {
    ngx_zmtp_listen_t            opt;
} ngx_zmtp_conf_addr_t;


typedef struct {
    ngx_array_t                        peerlist;
} ngx_zmtp_srv_share_peer_t;


typedef struct {
    ngx_array_t                    servers;     /* ngx_stream_core_srv_conf_t */
    ngx_array_t                    listen;      /* ngx_stream_listen_t */


    ngx_hash_t                     variables_hash;

    ngx_array_t                    variables;        /* ngx_stream_variable_t */
    ngx_array_t                    prefix_variables; /* ngx_stream_variable_t */
    ngx_uint_t                     ncaptures;

    ngx_uint_t                     variables_hash_max_size;
    ngx_uint_t                     variables_hash_bucket_size;

    ngx_hash_keys_arrays_t        *variables_keys;


} ngx_zmtp_core_main_conf_t;

typedef struct {
    ngx_int_t                    (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t                    (*postconfiguration)(ngx_conf_t *cf);

    void                        *(*create_main_conf)(ngx_conf_t *cf);
    char                        *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                        *(*create_srv_conf)(ngx_conf_t *cf);
    char                        *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                                   void *conf);
} ngx_zmtp_module_t;

typedef struct {

	ngx_zmtp_conf_ctx_t				*ctx;
	ngx_str_t						peer1;
	ngx_str_t						peer2;

	u_char							*file_name;
	ngx_uint_t						line;


	ngx_flag_t						tcp_nodelay;
	size_t							preread_buffer_size;
	size_t							channel_len;
	ngx_msec_t						preread_timeout;

	ngx_log_t						*error_log;

	ngx_msec_t						resolver_timeout;
	ngx_resolver_t					*resolver;

	ngx_msec_t						proxy_protocol_timeout;

	ngx_uint_t						listen;  /* unsigned  listen:1; */

	ngx_chain_t						*free;
	ngx_chain_t						*free_hs;
	ngx_shm_zone_t					*shm_zone;
} ngx_zmtp_core_srv_conf_t;



typedef enum {
    NGX_ZMTP_POST_ACCEPT_PHASE = 0,
    NGX_ZMTP_PREACCESS_PHASE,
    NGX_ZMTP_ACCESS_PHASE,
    NGX_ZMTP_SSL_PHASE,
    NGX_ZMTP_PREREAD_PHASE,
    NGX_ZMTP_CONTENT_PHASE,
    NGX_ZMTP_LOG_PHASE
} ngx_zmtp_phases;


typedef struct ngx_zmtp_phase_handler_s  ngx_zmtp_phase_handler_t;

typedef ngx_int_t (*ngx_zmtp_phase_handler_pt)(ngx_zmtp_session_t *s,
    ngx_zmtp_phase_handler_t *ph);
typedef ngx_int_t (*ngx_zmtp_handler_pt)(ngx_zmtp_session_t *s);


#define NGX_ZMTP_MODULE       0x5a4d5450     /* "ZMTP" */

#define NGX_ZMTP_MAIN_CONF    0x02000000
#define NGX_ZMTP_SRV_CONF     0x04000000
#define NGX_ZMTP_UPS_CONF     0x08000000

#define NGX_ZMTP_MAIN_CONF_OFFSET  offsetof(ngx_zmtp_conf_ctx_t, main_conf)
#define NGX_ZMTP_SRV_CONF_OFFSET   offsetof(ngx_zmtp_conf_ctx_t, srv_conf)


#define ngx_zmtp_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_zmtp_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define ngx_zmtp_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define ngx_zmtp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_zmtp_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define ngx_zmtp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_zmtp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_zmtp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_zmtp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_zmtp_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[ngx_zmtp_module.index] ?                                \
        ((ngx_zmtp_conf_ctx_t *) cycle->conf_ctx[ngx_zmtp_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


extern ngx_module_t  ngx_zmtp_module;
extern ngx_uint_t    ngx_zmtp_max_module;
extern ngx_module_t  ngx_zmtp_core_module;
extern ngx_zmtp_core_main_conf_t      *ngx_zmtp_core_main_conf;

void ngx_zmtp_init_connection(ngx_connection_t *c);
void ngx_zmtp_finalize_session(ngx_zmtp_session_t *s);
void ngx_zmtp_init_session(ngx_zmtp_session_t*s);
void ngx_zmtp_session_handler(ngx_event_t *rev);

void ngx_zmtp_cycle(ngx_zmtp_session_t *s);
void ngx_zmtp_close_connection(ngx_connection_t *c);
ngx_chain_t *ngx_zmtp_alloc_in_buf(ngx_zmtp_session_t *s);


void ngx_zmtp_send(ngx_event_t *wev);
void ngx_zmtp_recv(ngx_event_t *wev);

void ngx_zmtp_upstream_connection_monitor(ngx_event_t *ev);
ngx_int_t ngx_zmtp_upstream_checker_init(ngx_zmtp_session_t *s);
void ngx_zmtp_close_peer_connection(ngx_zmtp_session_t *s);
ngx_int_t ngx_zmtp_switch_peer(ngx_zmtp_session_t *s_old, 
								ngx_zmtp_session_t *s_new, 
								ngx_buf_t*channel_name,
								ngx_buf_t*unsub_channel_name);
void ngx_zmtp_finalize_client_session(ngx_zmtp_session_t *s);




#endif /* _NGX_ZMTP_H_INCLUDED_ */
