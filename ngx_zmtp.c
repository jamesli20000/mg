/*
 author  jamesli20000
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_zmtp.h"
#include "ngx_zmtp_handshake.h"




static char *ngx_zmtp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_zmtp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,ngx_zmtp_listen_t *listen);
static char *ngx_zmtp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
static ngx_int_t ngx_zmtp_add_addrs(ngx_conf_t *cf, ngx_zmtp_port_t *stport,ngx_zmtp_conf_addr_t *addr);
static ngx_int_t ngx_zmtp_cmp_conf_addrs(const void *one, const void *two);


ngx_uint_t  ngx_zmtp_max_module;


static ngx_command_t  ngx_zmtp_commands[] = {

	{ ngx_string("zmtp"),
	NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
	ngx_zmtp_block,
	0,
	0,
	NULL },

	ngx_null_command
};


static ngx_core_module_t  ngx_zmtp_module_ctx = {
	ngx_string("zmtp"),
	NULL,
	NULL
};


ngx_module_t  ngx_zmtp_module = {
	NGX_MODULE_V1,
	&ngx_zmtp_module_ctx,                /* module context */
	ngx_zmtp_commands,                   /* module directives */
	NGX_CORE_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


static char *
ngx_zmtp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char                          *rv;
	ngx_uint_t                     i, m, mi, s;
	ngx_conf_t                     pcf;
	ngx_array_t                    ports;
	ngx_zmtp_listen_t           *listen;
	ngx_zmtp_module_t           *module;
	ngx_zmtp_conf_ctx_t         *ctx;
	ngx_zmtp_core_srv_conf_t   **cscfp;
	ngx_zmtp_core_main_conf_t   *cmcf;

	if (*(ngx_zmtp_conf_ctx_t **) conf) {
		return "is duplicate";
	}

	/* the main stream context */

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_zmtp_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	*(ngx_zmtp_conf_ctx_t **) conf = ctx;

	/* count the number of the stream modules and set up their indices */

#if (nginx_version >= 1009011)
	
	ngx_zmtp_max_module = ngx_count_modules(cf->cycle, NGX_ZMTP_MODULE);
	
#else
	
	ngx_zmtp_max_module = 0;
	for (m = 0; ngx_modules[m]; m++) {
		if (ngx_modules[m]->type != NGX_ZMTP_MODULE) {
			continue;
		}

		ngx_modules[m]->ctx_index = ngx_zmtp_max_module++;
	}
	
#endif

    /* the stream main_conf context, it's the same in the all stream contexts */

	ctx->main_conf = ngx_pcalloc(cf->pool,
	     			sizeof(void *) * ngx_zmtp_max_module);
	if (ctx->main_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	/*
	* the stream null srv_conf context, it is used to merge
	* the server{}s' srv_conf's
	*/

	ctx->srv_conf = ngx_pcalloc(cf->pool,
				sizeof(void *) * ngx_zmtp_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR;
	}


    /*
     * create the main_conf's and the null srv_conf's of the all stream modules
     */

	for (m = 0; cf->cycle->modules[m]; m++) {
		if (cf->cycle->modules[m]->type != NGX_ZMTP_MODULE) {
			continue;
		}

		module = cf->cycle->modules[m]->ctx;
		mi = cf->cycle->modules[m]->ctx_index;

		if (module->create_main_conf) {
			ctx->main_conf[mi] = module->create_main_conf(cf);
			if (ctx->main_conf[mi] == NULL) {
				return NGX_CONF_ERROR;
			}
		}

		if (module->create_srv_conf) {
			ctx->srv_conf[mi] = module->create_srv_conf(cf);
			if (ctx->srv_conf[mi] == NULL) {
				return NGX_CONF_ERROR;
			}
		}
	}


	pcf = *cf;
	cf->ctx = ctx;

	for (m = 0; cf->cycle->modules[m]; m++) {
		if (cf->cycle->modules[m]->type != NGX_ZMTP_MODULE) {
			continue;
		}

		module = cf->cycle->modules[m]->ctx;

		if (module->preconfiguration) {
			if (module->preconfiguration(cf) != NGX_OK) {
				return NGX_CONF_ERROR;
			}
		}
	}


    /* parse inside the stream{} block */

	cf->module_type = NGX_ZMTP_MODULE;
	cf->cmd_type = NGX_ZMTP_MAIN_CONF;
	rv = ngx_conf_parse(cf, NULL);

	if (rv != NGX_CONF_OK) {
		*cf = pcf;
		return rv;
	}


	/* init stream{} main_conf's, merge the server{}s' srv_conf's */

	cmcf = ctx->main_conf[ngx_zmtp_core_module.ctx_index];
	cscfp = cmcf->servers.elts;

	for (m = 0; cf->cycle->modules[m]; m++) {
		if (cf->cycle->modules[m]->type != NGX_ZMTP_MODULE) {
			continue;
		}

		module = cf->cycle->modules[m]->ctx;
		mi = cf->cycle->modules[m]->ctx_index;

		cf->ctx = ctx;

		if (module->init_main_conf) {
			rv = module->init_main_conf(cf, ctx->main_conf[mi]);
			if (rv != NGX_CONF_OK) {
				*cf = pcf;
				return rv;
			}
		}

		for (s = 0; s < cmcf->servers.nelts; s++) {

			cf->ctx = cscfp[s]->ctx;

			if (module->merge_srv_conf) {
				rv = module->merge_srv_conf(cf,
				ctx->srv_conf[mi],
				cscfp[s]->ctx->srv_conf[mi]);
				if (rv != NGX_CONF_OK) {
					*cf = pcf;
					return rv;
				}
			}
		}
	}

	for (m = 0; cf->cycle->modules[m]; m++) {
		if (cf->cycle->modules[m]->type != NGX_ZMTP_MODULE) {
			continue;
		}

		module = cf->cycle->modules[m]->ctx;

		if (module->postconfiguration) {
			if (module->postconfiguration(cf) != NGX_OK) {
					return NGX_CONF_ERROR;
				}
			}
		}

		*cf = pcf;

		if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_zmtp_conf_port_t))
					!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}

		listen = cmcf->listen.elts;

		for (i = 0; i < cmcf->listen.nelts; i++) {
			if (ngx_zmtp_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	return ngx_zmtp_optimize_servers(cf, &ports);
}



static ngx_int_t
ngx_zmtp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_zmtp_listen_t *listen)
{
    in_port_t                p;
    ngx_uint_t               i;
    struct sockaddr         *sa;
    ngx_zmtp_conf_port_t  *port;
    ngx_zmtp_conf_addr_t  *addr;

    sa = &listen->sockaddr.sockaddr;
    p = ngx_inet_get_port(sa);

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {

        if (p == port[i].port
            && listen->type == port[i].type
            && sa->sa_family == port[i].family)
        {
            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->type = listen->type;
    port->port = p;

    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(ngx_zmtp_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->opt = *listen;

    return NGX_OK;
}


static char *
ngx_zmtp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
    ngx_uint_t                   i, p, last, bind_wildcard;
    ngx_listening_t             *ls;
    ngx_zmtp_port_t           *stport;
    ngx_zmtp_conf_port_t      *port;
    ngx_zmtp_conf_addr_t      *addr;
	ngx_zmtp_core_srv_conf_t  *cscf;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_zmtp_conf_addr_t), ngx_zmtp_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].opt.wildcard) {
            addr[last - 1].opt.bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            if (bind_wildcard && !addr[i].opt.bind) {
                i++;
                continue;
            }

            ls = ngx_create_listening(cf, &addr[i].opt.sockaddr.sockaddr,
                                      addr[i].opt.socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = ngx_zmtp_init_connection;
            ls->pool_size = 256;
            ls->type = addr[i].opt.type;

			
            cscf = addr->opt.ctx->srv_conf[ngx_zmtp_core_module.ctx_index];

            ls->logp = cscf->error_log;
           // ls->log.data = &ls->addr_text;
           // ls->log.handler = ngx_accept_log_error;
			
			
            ls->backlog = addr[i].opt.backlog;
            ls->rcvbuf = addr[i].opt.rcvbuf;
            ls->sndbuf = addr[i].opt.sndbuf;

            ls->wildcard = addr[i].opt.wildcard;


#if (NGX_HAVE_REUSEPORT)
            ls->reuseport = addr[i].opt.reuseport;
#endif

            stport = ngx_palloc(cf->pool, sizeof(ngx_zmtp_port_t));
            if (stport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = stport;

            stport->naddrs = i + 1;

            switch (ls->sockaddr->sa_family) {

            default: /* AF_INET */
                if (ngx_zmtp_add_addrs(cf, stport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            if (ngx_clone_listening(cf, ls) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_zmtp_add_addrs(ngx_conf_t *cf, ngx_zmtp_port_t *stport,
    ngx_zmtp_conf_addr_t *addr)
{
    u_char                *p;
    size_t                 len;
    ngx_uint_t             i;
    struct sockaddr_in    *sin;
    ngx_zmtp_in_addr_t  *addrs;
    u_char                 buf[NGX_SOCKADDR_STRLEN];

    stport->addrs = ngx_pcalloc(cf->pool,
                                stport->naddrs * sizeof(ngx_zmtp_in_addr_t));
    if (stport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin = &addr[i].opt.sockaddr.sockaddr_in;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].opt.ctx;
#if (NGX_STREAM_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
		addrs[i].conf.zmtp_sock_type = addr[i].opt.zmtp_sock_type;

        len = ngx_sock_ntop(&addr[i].opt.sockaddr.sockaddr, addr[i].opt.socklen,
                            buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}




static ngx_int_t
ngx_zmtp_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_zmtp_conf_addr_t  *first, *second;

    first = (ngx_zmtp_conf_addr_t *) one;
    second = (ngx_zmtp_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}
