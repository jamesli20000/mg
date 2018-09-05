
/*
jamesli20000
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_zmtp.h"


static ngx_int_t ngx_zmtp_core_preconfiguration(ngx_conf_t *cf);
static void *ngx_zmtp_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_zmtp_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_zmtp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_zmtp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,void *child);
static char *ngx_zmtp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static char *ngx_zmtp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static char *ngx_zmtp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static ngx_int_t ngx_zmtp_core_shm_init(ngx_shm_zone_t *shm_zone, void *data);


static ngx_command_t  ngx_zmtp_core_commands[] = {
    { ngx_string("server"),
      NGX_ZMTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_zmtp_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_ZMTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_zmtp_core_listen,
      NGX_ZMTP_SRV_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("zmtp_peer1"),
      NGX_ZMTP_MAIN_CONF|NGX_ZMTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_ZMTP_SRV_CONF_OFFSET,
      offsetof(ngx_zmtp_core_srv_conf_t, peer1),
      NULL
      },
    { ngx_string("zmtp_peer2"),
      NGX_ZMTP_MAIN_CONF|NGX_ZMTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_ZMTP_SRV_CONF_OFFSET,
      offsetof(ngx_zmtp_core_srv_conf_t, peer2),
      NULL
    },
    { ngx_string("error_log"),
      NGX_ZMTP_MAIN_CONF|NGX_ZMTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_zmtp_core_error_log,
      NGX_ZMTP_SRV_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("preread_buffer_size"),
      NGX_ZMTP_MAIN_CONF|NGX_ZMTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_ZMTP_SRV_CONF_OFFSET,
      offsetof(ngx_zmtp_core_srv_conf_t, preread_buffer_size),
      NULL },
    { ngx_string("channel_len"),
      NGX_ZMTP_MAIN_CONF|NGX_ZMTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_ZMTP_SRV_CONF_OFFSET,
      offsetof(ngx_zmtp_core_srv_conf_t, channel_len),
      NULL },  
      
      ngx_null_command
};


static ngx_zmtp_module_t  ngx_zmtp_core_module_ctx = {
    ngx_zmtp_core_preconfiguration,      /* preconfiguration */
    NULL,     /* postconfiguration */

    ngx_zmtp_core_create_main_conf,      /* create main configuration */
    ngx_zmtp_core_init_main_conf,        /* init main configuration */

    ngx_zmtp_core_create_srv_conf,       /* create server configuration */
    ngx_zmtp_core_merge_srv_conf         /* merge server configuration */
};


ngx_module_t  ngx_zmtp_core_module = {
    NGX_MODULE_V1,
    &ngx_zmtp_core_module_ctx,           /* module context */
    ngx_zmtp_core_commands,              /* module directives */
    NGX_ZMTP_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_zmtp_core_main_conf_t      *ngx_zmtp_core_main_conf;
ngx_str_t    shm_name;;


static ngx_int_t
ngx_zmtp_core_preconfiguration(ngx_conf_t *cf)
{
return 0;
  //  return ngx_zmtp_variables_add_core_vars(cf);
}


static void *
ngx_zmtp_core_create_main_conf(ngx_conf_t *cf)
{
	ngx_zmtp_core_main_conf_t  *cmcf;

	cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_zmtp_core_main_conf_t));
	if (cmcf == NULL) {
		return NULL;
	}
	ngx_zmtp_core_main_conf = cmcf;

	if (ngx_array_init(&cmcf->servers, cf->pool, 4,
			sizeof(ngx_zmtp_core_srv_conf_t *))
			!= NGX_OK)
	{
		return NULL;
	}

	if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_zmtp_listen_t))
			!= NGX_OK)
	{
		return NULL;
	}

	cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
	cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;

	return cmcf;
}


static char *
ngx_zmtp_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_zmtp_core_main_conf_t *cmcf = conf;

	ngx_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
	ngx_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

	cmcf->variables_hash_bucket_size =
	           ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);

	if (cmcf->ncaptures) {
		cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
	}

	return NGX_CONF_OK;
}


static void *
ngx_zmtp_core_create_srv_conf(ngx_conf_t *cf)
{
	ngx_zmtp_core_srv_conf_t  *cscf;

	cscf = ngx_pcalloc(cf->pool, sizeof(ngx_zmtp_core_srv_conf_t));
	if (cscf == NULL) {
		return NULL;
	}
	



	cscf->file_name = cf->conf_file->file.name.data;
	cscf->line = cf->conf_file->line;
	cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
	cscf->proxy_protocol_timeout = NGX_CONF_UNSET_MSEC;
	cscf->tcp_nodelay = NGX_CONF_UNSET;
	cscf->preread_buffer_size = NGX_CONF_UNSET_SIZE;
	cscf->preread_timeout = NGX_CONF_UNSET_MSEC;
	cscf->channel_len = NGX_CONF_UNSET_SIZE;

	return cscf;
}




static char *
ngx_zmtp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_zmtp_core_srv_conf_t *prev = parent;
	ngx_zmtp_core_srv_conf_t *conf = child;

	ngx_conf_merge_msec_value(conf->resolver_timeout,
						prev->resolver_timeout, 30000);

	if (conf->resolver == NULL) {

		if (prev->resolver == NULL) {

		/*
		* create dummy resolver in stream {} context
		* to inherit it in all servers
		*/

			prev->resolver = ngx_resolver_create(cf, NULL, 0);
			if (prev->resolver == NULL) {
				return NGX_CONF_ERROR;
			}
		}

		conf->resolver = prev->resolver;
	}


	if (conf->error_log == NULL) {
		if (prev->error_log) {
			conf->error_log = prev->error_log;
		} else {
			conf->error_log = &cf->cycle->new_log;
		}
	}

	ngx_conf_merge_msec_value(conf->proxy_protocol_timeout,
						prev->proxy_protocol_timeout, 30000);

	ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

	ngx_conf_merge_size_value(conf->preread_buffer_size,
						prev->preread_buffer_size, 16384);

	ngx_conf_merge_msec_value(conf->preread_timeout,
							prev->preread_timeout, 30000);

	ngx_conf_merge_size_value(conf->channel_len,
							prev->channel_len, NGX_ZMTP_CHANNEL_NAME_LEN);
	return NGX_CONF_OK;
}


static char *
ngx_zmtp_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_zmtp_core_srv_conf_t  *cscf = conf;

	return ngx_log_set_log(cf, &cscf->error_log);
}


static char *
ngx_zmtp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char                         *rv;
	void                         *mconf;
	ngx_uint_t                    m;
	ngx_conf_t                    pcf;
	ngx_zmtp_module_t          *module;
	ngx_zmtp_conf_ctx_t        *ctx, *stream_ctx;
	ngx_zmtp_core_srv_conf_t   *cscf, **cscfp;
	ngx_zmtp_core_main_conf_t  *cmcf;
	ngx_str_t                        *value;


	value = cf->args->elts;
	
	if (!value[1].len) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "invalid server name \"%V\"", &value[1]);
		return NGX_CONF_ERROR;
	}
		

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_zmtp_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	stream_ctx = cf->ctx;
	ctx->main_conf = stream_ctx->main_conf;

	/* the server{}'s srv_conf */

	ctx->srv_conf = ngx_pcalloc(cf->pool,
	                    sizeof(void *) * ngx_zmtp_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	for (m = 0; cf->cycle->modules[m]; m++) {
		if (cf->cycle->modules[m]->type != NGX_ZMTP_MODULE) {
			continue;
		}

		module = cf->cycle->modules[m]->ctx;

		if (module->create_srv_conf) {
			mconf = module->create_srv_conf(cf);
			if (mconf == NULL) {
				return NGX_CONF_ERROR;
			}

			ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
		}
	}

	/* the server configuration context */

	cscf = ctx->srv_conf[ngx_zmtp_core_module.ctx_index];
	cscf->ctx = ctx;

	
	cscf->shm_zone = ngx_shared_memory_add(cf, &value[1], ngx_pagesize * 2,
											   &ngx_zmtp_core_module);
	if (cscf->shm_zone == NULL) {
		return NGX_CONF_ERROR;
	}
	
	cscf->shm_zone->init = ngx_zmtp_core_shm_init;



	cmcf = ctx->main_conf[ngx_zmtp_core_module.ctx_index];

	cscfp = ngx_array_push(&cmcf->servers);
	if (cscfp == NULL) {
		return NGX_CONF_ERROR;
	}

	*cscfp = cscf;


	/* parse inside server{} */

	pcf = *cf;
	cf->ctx = ctx;
	cf->cmd_type = NGX_ZMTP_SRV_CONF;

	rv = ngx_conf_parse(cf, NULL);

	*cf = pcf;

	if (rv == NGX_CONF_OK && !cscf->listen) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
				"no \"listen\" is defined for server in %s:%ui",
				cscf->file_name, cscf->line);
		return NGX_CONF_ERROR;
	}

	return rv;
}


static char *
ngx_zmtp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_zmtp_core_srv_conf_t  *cscf = conf;

	ngx_str_t                    *value, size;
	ngx_url_t                     u;
	ngx_uint_t                    i, backlog;
	ngx_zmtp_listen_t          *ls, *als;
	ngx_zmtp_core_main_conf_t  *cmcf;


	cscf->listen = 1;

	value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.listen = 1;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"%s in \"%V\" of the \"listen\" directive",
							u.err, &u.url);
		}

		return NGX_CONF_ERROR;
	}

	cmcf = ngx_zmtp_conf_get_module_main_conf(cf, ngx_zmtp_core_module);
	//cscf = ngx_zmtp_conf_get_module_srv_conf(cf, ngx_zmtp_core_module);

	ls = ngx_array_push(&cmcf->listen);
	if (ls == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(ls, sizeof(ngx_zmtp_listen_t));

	ngx_memcpy(&ls->sockaddr.sockaddr, &u.sockaddr, u.socklen);

	ls->socklen = u.socklen;
	ls->backlog = NGX_LISTEN_BACKLOG;
	ls->rcvbuf = -1;
	ls->sndbuf = -1;
	ls->type = SOCK_STREAM;
	ls->wildcard = u.wildcard;
	ls->ctx = cf->ctx;



	backlog = 0;

	for (i = 2; i < cf->args->nelts; i++) {

#if !(NGX_WIN32)
		if (ngx_strcmp(value[i].data, "udp") == 0) {
			ls->type = SOCK_DGRAM;
			continue;
		}
#endif

		if (ngx_strcmp(value[i].data, "bind") == 0) {
			ls->bind = 1;
			continue;
		}

		if (ngx_strcmp(value[i].data, "sub") == 0) {
			ls->zmtp_sock_type = ZMTP_SOCK_XSUB;
			continue;
		}

		if (ngx_strcmp(value[i].data, "pub") == 0) {
			ls->zmtp_sock_type = ZMTP_SOCK_XPUB;
			continue;
		}		

		if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
			ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
			ls->bind = 1;

			if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"invalid backlog \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			backlog = 1;

			continue;
		}

		if (ngx_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
			size.len = value[i].len - 7;
			size.data = value[i].data + 7;

			ls->rcvbuf = ngx_parse_size(&size);
			ls->bind = 1;

			if (ls->rcvbuf == NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"invalid rcvbuf \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "sndbuf=", 7) == 0) {
			size.len = value[i].len - 7;
			size.data = value[i].data + 7;

			ls->sndbuf = ngx_parse_size(&size);
			ls->bind = 1;

			if (ls->sndbuf == NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"invalid sndbuf \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			continue;
		}



		if (ngx_strcmp(value[i].data, "reuseport") == 0) {
#if (NGX_HAVE_REUSEPORT)
			ls->reuseport = 1;
			ls->bind = 1;
#else
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		                   "reuseport is not supported "
		                   "on this platform, ignored");
#endif
			continue;
		}

		if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (NGX_ZMTP_SSL)
			ls->ssl = 1;
			continue;
#else
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"the \"ssl\" parameter requires "
						"ngx_zmtp_ssl_module");
			return NGX_CONF_ERROR;
#endif
		}

		if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

			if (ngx_strcmp(&value[i].data[13], "on") == 0) {
				ls->so_keepalive = 1;

			} else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
				ls->so_keepalive = 2;

			} else {


			}

			ls->bind = 1;

			continue;


		}

		if (ngx_strcmp(value[i].data, "proxy_protocol") == 0) {
			ls->proxy_protocol = 1;
			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		               "the invalid \"%V\" parameter", &value[i]);
		return NGX_CONF_ERROR;
	}

		if (ls->type == SOCK_DGRAM) {
			if (backlog) {
			return "\"backlog\" parameter is incompatible with \"udp\"";
		}

#if (NGX_ZMTP_SSL)
		if (ls->ssl) {
			return "\"ssl\" parameter is incompatible with \"udp\"";
		}
#endif

		if (ls->so_keepalive) {
			return "\"so_keepalive\" parameter is incompatible with \"udp\"";
		}

		if (ls->proxy_protocol) {
			return "\"proxy_protocol\" parameter is incompatible with \"udp\"";
		}
	}

	als = cmcf->listen.elts;

	for (i = 0; i < cmcf->listen.nelts - 1; i++) {
		if (ls->type != als[i].type) {
			continue;
		}

		if (ngx_cmp_sockaddr(&als[i].sockaddr.sockaddr, als[i].socklen,
		                 &ls->sockaddr.sockaddr, ls->socklen, 1)
		!= NGX_OK)
		{
			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"duplicate \"%V\" address and port pair", &u.url);
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_zmtp_core_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t    *shpool;
    uint32_t           *peerno;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    peerno = ngx_slab_alloc(shpool, 4);
    if (peerno == NULL) {
        return NGX_ERROR;
    }

    *peerno = 0;

    shm_zone->data = peerno;

    return NGX_OK;
}

