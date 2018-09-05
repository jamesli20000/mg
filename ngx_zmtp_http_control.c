
/*
 * Copyright (C) jamesli20000
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_zmtp.h"


static char *ngx_zmtp_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_zmtp_control_create_loc_conf(ngx_conf_t *cf);
static char * ngx_zmtp_control_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


typedef const char * (*ngx_zmtp_control_handler_t)(ngx_http_request_t *r, ngx_zmtp_core_srv_conf_t *cscf);


#define NGX_ZMTP_CONTROL_ALL        0xff
#define NGX_ZMTP_CONTROL_SWITCH     0x01
#define NGX_ZMTP_CONTROL_DROP       0x02



enum {
	NGX_ZMTP_CONTROL_FILTER_CLIENT = 0,
	NGX_ZMTP_CONTROL_FILTER_PUBLISHER,
	NGX_ZMTP_CONTROL_FILTER_SUBSCRIBER
};


typedef struct {
	ngx_uint_t                      count;
	ngx_str_t                       path;
	ngx_uint_t                      filter;
	ngx_str_t                       method;
	ngx_array_t                     sessions; /* ngx_rtmp_session_t * */
} ngx_zmtp_control_ctx_t;


typedef struct {
    ngx_uint_t                      control;
} ngx_zmtp_control_loc_conf_t;


static ngx_conf_bitmask_t           ngx_zmtp_control_masks[] = {
	{ ngx_string("all"),            NGX_ZMTP_CONTROL_ALL       },
	{ ngx_string("switch"),         NGX_ZMTP_CONTROL_SWITCH    },
	{ ngx_string("drop"),           NGX_ZMTP_CONTROL_DROP      },
	{ ngx_null_string,              0                          }
};


static ngx_command_t  ngx_zmtp_control_commands[] = {

	{ ngx_string("zmtp_control"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
	ngx_zmtp_control,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_zmtp_control_loc_conf_t, control),
	ngx_zmtp_control_masks 
	},

	ngx_null_command
};


static ngx_http_module_t  ngx_zmtp_control_module_ctx = {
	NULL,                               /* preconfiguration */
	NULL,                               /* postconfiguration */

	NULL,                               /* create main configuration */
	NULL,                               /* init main configuration */

	NULL,                               /* create server configuration */
	NULL,                               /* merge server configuration */

	ngx_zmtp_control_create_loc_conf,   /* create location configuration */
	ngx_zmtp_control_merge_loc_conf,    /* merge location configuration */
};


ngx_module_t  ngx_zmtp_control_module = {
	NGX_MODULE_V1,
	&ngx_zmtp_control_module_ctx,       /* module context */
	ngx_zmtp_control_commands,          /* module directives */
	NGX_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	NULL,                               /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};



static const char *
ngx_zmtp_control_switch_handler(ngx_http_request_t *r, ngx_zmtp_core_srv_conf_t *cscf)
{
	ngx_str_t					act;

	ngx_slab_pool_t				*shpool;
	ngx_shm_zone_t				*shm_zone;
	uint32_t					*speerno, ipeerno;

	if (ngx_http_arg(r, (u_char *) "peerno", sizeof("peerno") - 1, &act) != NGX_OK) {
		return "cmd not right";
	}

	ipeerno = ngx_atoi(act.data, act.len);

	shm_zone = cscf->shm_zone;
	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	speerno = shm_zone->data;
	
	ngx_shmtx_lock(&shpool->mutex);
	*speerno = ipeerno;
	ngx_shmtx_unlock(&shpool->mutex);
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,"ngx_zmtp_control_switch_handler, peerno:%d,peer1:%s",
		*speerno, cscf->peer1.data);
	return NGX_CONF_OK;
}

/*
static const char *
ngx_zmtp_control_drop_handler(ngx_http_request_t *r, ngx_zmtp_session_t *s)
{
    ngx_zmtp_control_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_zmtp_control_module);

    ngx_zmtp_finalize_session(s);

    ++ctx->count;

    return NGX_CONF_OK;
}
*/


static const char *
ngx_zmtp_control_walk(ngx_http_request_t *r, ngx_zmtp_control_handler_t h)
{
	ngx_zmtp_core_main_conf_t  *cmcf = ngx_zmtp_core_main_conf;

	ngx_str_t					srv;
	ngx_uint_t					sn;
	ngx_zmtp_core_srv_conf_t	**pcscf;

	sn = 0;
	if (ngx_http_arg(r, (u_char *) "srv", sizeof("srv") - 1, &srv) == NGX_OK) {
		sn = ngx_atoi(srv.data, srv.len);
	}

	if (sn >= cmcf->servers.nelts) {
		return "Server index out of range";
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,"ngx_zmtp_control_walk, srv:%s",srv.data);
	

	pcscf  = cmcf->servers.elts;
	pcscf += sn;
	h(r, *pcscf);

/*
	shm_zone = *pcscf->shm_zone;
	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	peerno = shm_zone->data;
		
	ngx_shmtx_lock(&shpool->mutex);
	*peerno = 1;
	ngx_shmtx_unlock(&shpool->mutex);
*/
/*	
    msg = ngx_zmtp_control_walk_server(r, *pcscf);
    if (msg != NGX_CONF_OK) {
        return msg;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_zmtp_control_module);

    s = ctx->sessions.elts;
    for (n = 0; n < ctx->sessions.nelts; n++) {
        msg = h(r, s[n]);
        if (msg != NGX_CONF_OK) {
            return msg;
        }
    }
*/
	
	return NGX_CONF_OK;
}


static ngx_int_t
ngx_zmtp_control_switch(ngx_http_request_t *r, ngx_str_t *method)
{
	ngx_buf_t               *b;
	const char              *msg;
	ngx_chain_t              cl;
	ngx_zmtp_control_ctx_t  *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_zmtp_control_module);
	ctx->filter = NGX_ZMTP_CONTROL_FILTER_PUBLISHER;

	msg = ngx_zmtp_control_walk(r, ngx_zmtp_control_switch_handler);

	if (msg != NGX_CONF_OK) {
		goto error;
	}

	if (ctx->path.len == 0) {
	    return NGX_HTTP_NO_CONTENT;
	}

	/* output record path */

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = ctx->path.len;

	b = ngx_create_temp_buf(r->pool, ctx->path.len);
	if (b == NULL) {
		goto error;
	}

	ngx_memzero(&cl, sizeof(cl));
	cl.buf = b;

	b->last = ngx_cpymem(b->pos, ctx->path.data, ctx->path.len);
	b->last_buf = 1;

	ngx_http_send_header(r);

	return ngx_http_output_filter(r, &cl);

error:
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

#if 0

static ngx_int_t
ngx_zmtp_control_drop(ngx_http_request_t *r, ngx_str_t *method)
{
	return NGX_OK;

    size_t                   len;
    u_char                  *p;
    ngx_buf_t               *b;
    ngx_chain_t              cl;
    const char              *msg;
    ngx_zmtp_control_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_zmtp_control_module);

    if (ctx->method.len == sizeof("publisher") - 1 &&
        ngx_memcmp(ctx->method.data, "publisher", ctx->method.len) == 0)
    {
        ctx->filter = NGX_ZMTP_CONTROL_FILTER_PUBLISHER;

    } else if (ctx->method.len == sizeof("subscriber") - 1 &&
               ngx_memcmp(ctx->method.data, "subscriber", ctx->method.len)
               == 0)
    {
        ctx->filter = NGX_ZMTP_CONTROL_FILTER_SUBSCRIBER;

    } else if (method->len == sizeof("client") - 1 &&
               ngx_memcmp(ctx->method.data, "client", ctx->method.len) == 0)
    {
        ctx->filter = NGX_ZMTP_CONTROL_FILTER_CLIENT;

    } else {
        msg = "Undefined filter";
        goto error;
    }

    msg = ngx_zmtp_control_walk(r, ngx_zmtp_control_drop_handler);
    if (msg != NGX_CONF_OK) {
        goto error;
    }

    /* output count */

    len = NGX_INT_T_LEN;

    p = ngx_palloc(r->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = (size_t) (ngx_snprintf(p, len, "%ui", ctx->count) - p);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        goto error;
    }

    b->start = b->pos = p;
    b->end = b->last = p + len;
    b->temporary = 1;
    b->last_buf = 1;

    ngx_memzero(&cl, sizeof(cl));
    cl.buf = b;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &cl);

error:
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
	
}
#endif


static ngx_int_t
ngx_zmtp_control_handler(ngx_http_request_t *r)
{
	u_char                       *p;
	ngx_str_t                     section, method;
	ngx_uint_t                    n;
	ngx_zmtp_control_ctx_t       *ctx;
	ngx_zmtp_control_loc_conf_t  *llcf;

	llcf = ngx_http_get_module_loc_conf(r, ngx_zmtp_control_module);
	if (llcf->control == 0) {
		return NGX_DECLINED;
	}

	/* uri format: .../section/method?args */

	ngx_str_null(&section);
	ngx_str_null(&method);

	for (n = r->uri.len; n; --n) {
		p = &r->uri.data[n - 1];

		if (*p != '/') {
			continue;
		}

		if (method.data) {
			section.data = p + 1;
			section.len  = method.data - section.data - 1;
			break;
		}

		method.data = p + 1;
		method.len  = r->uri.data + r->uri.len - method.data;
	}

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"zmtp_control: section='%V' method='%V'",
				&section, &method);

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_zmtp_control_ctx_t));
	if (ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_http_set_ctx(r, ctx, ngx_zmtp_control_module);

	if (ngx_array_init(&ctx->sessions, r->pool, 1, sizeof(void *)) != NGX_OK) {
		return NGX_ERROR;
	}

	ctx->method = method;
	return ngx_zmtp_control_switch(r, &method);
/*
#define NGX_ZMTP_CONTROL_SECTION(flag, secname)                             \
    if (llcf->control & NGX_ZMTP_CONTROL_##flag &&                          \
        section.len == sizeof(#secname) - 1 &&                              \
        ngx_strncmp(section.data, #secname, sizeof(#secname) - 1) == 0)     \
    {                                                                       \
        return ngx_zmtp_control_##secname(r, &method);                      \
    }

    NGX_ZMTP_CONTROL_SECTION(SWITCH, switch);
    NGX_ZMTP_CONTROL_SECTION(DROP, drop);

#undef NGX_ZMTP_CONTROL_SECTION
*/

   // return NGX_DECLINED;
}


static void *
ngx_zmtp_control_create_loc_conf(ngx_conf_t *cf)
{
	ngx_zmtp_control_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_zmtp_control_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->control = 0;

	return conf;
}


static char *
ngx_zmtp_control_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_zmtp_control_loc_conf_t  *prev = parent;
	ngx_zmtp_control_loc_conf_t  *conf = child;

	ngx_conf_merge_bitmask_value(conf->control, prev->control, 0);

	return NGX_CONF_OK;
}


static char *
ngx_zmtp_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t  *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_zmtp_control_handler;

	return ngx_conf_set_bitmask_slot(cf, cmd, conf);
}

