#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#if (NGX_HTTP_V2)
#include <ngx_http_v2.h>
#endif

/* --- Struct Definitions --- */
typedef struct {
    ngx_http_upstream_init_pt original_init_upstream;
    ngx_http_upstream_init_peer_pt original_init_peer;
} ngx_http_upstream_ntlm_srv_conf_t;

/* Context representing the pinned state between a client and an upstream */
typedef struct {
    ngx_http_upstream_srv_conf_t *upstream_srv_conf;
    ngx_connection_t *upstream_conn;
    struct sockaddr *upstream_sockaddr;
    socklen_t upstream_socklen;
    ngx_str_t upstream_name;
    ngx_msec_t pinned_time;
} ngx_http_upstream_ntlm_ctx_t;

typedef struct {
    ngx_http_upstream_srv_conf_t *us;
} ngx_http_upstream_ntlm_req_ctx_t;

typedef struct {
    ngx_http_upstream_ntlm_ctx_t *ctx;
    void *original_peer_data;
    ngx_event_get_peer_pt original_get_peer;
    ngx_event_free_peer_pt original_free_peer;
#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt original_set_session;
    ngx_event_save_peer_session_pt original_save_session;
#endif
    ngx_flag_t cached;
} ngx_http_upstream_ntlm_peer_data_t;

/* --- Function Prototypes --- */
static void *ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_ntlm_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_upstream_init_ntlm(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_init_ntlm_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ntlm_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_free_ntlm_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc, void *data);
#endif

static void ngx_http_upstream_ntlm_client_cleanup(void *data);
static void ngx_http_upstream_ntlm_upstream_cleanup(void *data);
static void ngx_http_upstream_ntlm_close_upstream(ngx_connection_t *c);
static void ngx_http_upstream_ntlm_upstream_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev);

static ngx_http_upstream_ntlm_ctx_t *ngx_http_upstream_ntlm_client_get_ctx(ngx_connection_t *c, ngx_http_upstream_srv_conf_t *us, ngx_flag_t create);
static ngx_pool_cleanup_t *ngx_http_upstream_ntlm_get_upstream_cleanup(ngx_connection_t *c, ngx_flag_t create);

static ngx_int_t ngx_http_upstream_ntlm_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_ntlm_pinned_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_upstream_ntlm_postconfiguration(ngx_conf_t *cf);
#if (NGX_HTTP_V2)
static ngx_int_t ngx_http_upstream_ntlm_httpv2_send_rst_stream(ngx_http_v2_connection_t *h2c, ngx_uint_t sid, ngx_uint_t status);
static ngx_int_t ngx_http_upstream_ntlm_httpv2_send_goaway(ngx_http_v2_connection_t *h2c, ngx_uint_t status);
static ngx_int_t ngx_http_upstream_ntlm_httpv2_terminate_stream(ngx_http_v2_connection_t *h2c, ngx_http_v2_stream_t *stream, ngx_uint_t status);
static ngx_int_t ngx_http_upstream_ntlm_access_handler(ngx_http_request_t *r);
#endif

/* --- Module Variables --- */
static ngx_http_variable_t ngx_http_upstream_ntlm_vars[] = {
    { ngx_string("ntlm_pinned"), NULL,
      ngx_http_upstream_ntlm_pinned_var, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    ngx_http_null_variable
};

/* --- Module Registration --- */
static ngx_command_t ngx_http_upstream_ntlm_commands[] = {
    { ngx_string("ntlm"),
      NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS,
      ngx_http_upstream_ntlm_directive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_ntlm_module_ctx = {
    ngx_http_upstream_ntlm_add_variables,     /* preconfiguration */
    ngx_http_upstream_ntlm_postconfiguration, /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    ngx_http_upstream_ntlm_create_conf,       /* create server configuration */
    NULL,                                     /* merge server configuration */
    NULL,                                     /* create location configuration */
    NULL                                      /* merge location configuration */
};

ngx_module_t ngx_http_upstream_ntlm_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ntlm_module_ctx, /* module context */
    ngx_http_upstream_ntlm_commands,    /* module directives */
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

/* --- Variable $ntlm_pinned --- */
static ngx_int_t
ngx_http_upstream_ntlm_pinned_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_connection_t *c;
    ngx_http_upstream_ntlm_ctx_t *ctx;
    ngx_http_upstream_ntlm_req_ctx_t *rctx;
    ngx_http_upstream_srv_conf_t *us = NULL;

#if (NGX_HTTP_V2)
    if (r->stream) {
        c = r->stream->connection->connection;
    } else {
        c = r->connection;
    }
#else
    c = r->connection;
#endif

    if (c == NULL || c->pool == NULL || c->close) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ntlm: pinned var: client connection is already closing, skipping ctx");
        v->not_found = 1;
        return NGX_OK;
    }

    /* Try the cached value first, works at log phase too */
    rctx = ngx_http_get_module_ctx(r, ngx_http_upstream_ntlm_module);
    if (rctx) {
        us = rctx->us;
    } else if (r->upstream && r->upstream->upstream) {
        /* Fallback: variable evaluated before init_peer ran */
        us = r->upstream->upstream;
    }

    ctx = ngx_http_upstream_ntlm_client_get_ctx(c, us, 0);

    if (ctx != NULL && ctx->pinned_time != 0) {
        ngx_msec_t elapsed_ms = ngx_current_msec - ctx->pinned_time;

        v->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        v->len = ngx_sprintf(v->data, "%ui", elapsed_ms) - v->data;
    } else {
        v->len = 0;
        v->data = (u_char *) "";
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_ntlm_add_variables(ngx_conf_t *cf) {
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_upstream_ntlm_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

/* --- Configuration Boilerplate --- */
static void *
ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf) {
    ngx_http_upstream_ntlm_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ntlm_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_upstream_ntlm_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_http_upstream_ntlm_srv_conf_t *ncf = conf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    ncf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_upstream_init_ntlm;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_upstream_init_ntlm(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us) {
    ngx_http_upstream_ntlm_srv_conf_t *ncf;

    ncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    if (ncf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    ncf->original_init_peer = us->peer.init;
    us->peer.init = ngx_http_upstream_init_ntlm_peer;

    return NGX_OK;
}

/* --- State & Cleanup Management --- */

/* Get or Create the Context attached to the Client Connection */
static ngx_http_upstream_ntlm_ctx_t *
ngx_http_upstream_ntlm_client_get_ctx(ngx_connection_t *c, ngx_http_upstream_srv_conf_t *us, ngx_flag_t create) {
    ngx_pool_cleanup_t *cln;
    ngx_http_upstream_ntlm_ctx_t *ctx;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_upstream_ntlm_client_cleanup) {
            ctx = cln->data;
            if (us == NULL || ctx->upstream_srv_conf == us) {
                return ctx;
            }
        }
    }

    if (!create) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_upstream_ntlm_ctx_t));
    if (cln == NULL) {
        return NULL;
    }
    ctx = (ngx_http_upstream_ntlm_ctx_t *)cln->data;
    ngx_memzero(ctx, sizeof(ngx_http_upstream_ntlm_ctx_t));

    ctx->upstream_srv_conf = us;
    cln->handler = ngx_http_upstream_ntlm_client_cleanup;
    cln->data = ctx;

    return ctx;
}

/* Helper to find our cleanup in the Upstream Connection pool to avoid duplicates */
static ngx_pool_cleanup_t *
ngx_http_upstream_ntlm_get_upstream_cleanup(ngx_connection_t *c, ngx_flag_t create) {
    ngx_pool_cleanup_t *cln;
    if (!c->pool) {
        return NULL;
    }

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_upstream_ntlm_upstream_cleanup) {
            return cln;
        }
    }

    if (!create) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_upstream_ntlm_upstream_cleanup;

    return cln;
}

/* Triggered when Client drops/closes */
static void
ngx_http_upstream_ntlm_client_cleanup(void *data) {
    ngx_http_upstream_ntlm_ctx_t *ctx = data;
    ngx_connection_t *uc = ctx->upstream_conn;
    ngx_pool_cleanup_t *cln;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "ntlm: client cleanup %p", ctx);

    if (uc) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "ntlm: client dropped, closing pinned upstream %p", uc);

        ctx->upstream_conn = NULL;
        ctx->pinned_time = 0;

        /*
         * Nullify the upstream's reference back to us before we close it,
         * otherwise the upstream cleanup will try to access freed memory.
         */
        cln = ngx_http_upstream_ntlm_get_upstream_cleanup(uc, 0);
        if (cln) {
            cln->data = NULL;
        }

        /* Post an event which will close the upstream connection */
        uc->read->timedout = 1;
        ngx_post_event(uc->read, &ngx_posted_events);
    }
}

/* Triggered when Upstream is destroyed (e.g. backend timed out or closed) */
static void
ngx_http_upstream_ntlm_upstream_cleanup(void *data) {
    ngx_http_upstream_ntlm_ctx_t *ctx = data;

    if (ctx) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "ntlm: upstream cleanup %p", ctx);
        ctx->upstream_conn = NULL;
        ctx->pinned_time = 0;
    }
}

static void
ngx_http_upstream_ntlm_close_upstream(ngx_connection_t *c)
{
#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_ntlm_close_upstream;
            return;
        }
    }
#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}

/* --- Core Logic --- */

static ngx_int_t
ngx_http_upstream_init_ntlm_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
    ngx_connection_t *c;
    ngx_http_upstream_ntlm_peer_data_t *my_data;
    ngx_http_upstream_ntlm_srv_conf_t *ncf;
    ngx_http_upstream_ntlm_req_ctx_t *rctx;
    ngx_str_t auth_hdr;
    ngx_flag_t has_ntlm = 0;

#if (NGX_HTTP_V2)
    if (r->stream) {
        c = r->stream->connection->connection;
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ntlm: init peer called on HTTP/2 stream! Downgrade handler may not have run");
        return NGX_ERROR;
    } else {
        c = r->connection;
    }
#else
    c = r->connection;
#endif

    /* cache upstream for the request lifecycle */
    rctx = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ntlm_req_ctx_t));
    if (rctx == NULL) {
        return NGX_ERROR;
    }
    rctx->us = us;
    ngx_http_set_ctx(r, rctx, ngx_http_upstream_ntlm_module);

    ncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    my_data = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ntlm_peer_data_t));
    if (my_data == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(my_data, sizeof(ngx_http_upstream_ntlm_peer_data_t));

    if (ncf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->headers_in.authorization != NULL)
    {
        auth_hdr = r->headers_in.authorization->value;
        if ((auth_hdr.len >= 4 && ngx_strncasecmp(auth_hdr.data, (u_char *)"NTLM", 4) == 0) ||
            (auth_hdr.len >= 9 && ngx_strncasecmp(auth_hdr.data, (u_char *)"Negotiate", 9) == 0))
        {
            has_ntlm = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "ntlm: auth header found");
        }
    }

    my_data->ctx = ngx_http_upstream_ntlm_client_get_ctx(c, us, has_ntlm);
    if (my_data->ctx == NULL) {
        my_data->original_peer_data = r->upstream->peer.data;
        return NGX_OK;
    }

    my_data->original_peer_data = r->upstream->peer.data;
    my_data->original_get_peer  = r->upstream->peer.get;
    my_data->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = my_data;
    r->upstream->peer.get  = ngx_http_upstream_get_ntlm_peer;
    r->upstream->peer.free = ngx_http_upstream_free_ntlm_peer;

#if (NGX_HTTP_SSL)
    if (r->upstream->peer.set_session) {
        my_data->original_set_session = r->upstream->peer.set_session;
        r->upstream->peer.set_session = ngx_http_upstream_ntlm_set_session;
    }

    if (r->upstream->peer.save_session) {
        my_data->original_save_session = r->upstream->peer.save_session;
        r->upstream->peer.save_session = ngx_http_upstream_ntlm_save_session;
    }
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_get_ntlm_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_http_upstream_ntlm_peer_data_t *my_data = data;
    ngx_connection_t *c;

    if (my_data->ctx->pinned_time && my_data->ctx->upstream_conn != NULL) {
        c = my_data->ctx->upstream_conn;

        c->idle = 0;
        c->sent = 0;
        c->log = pc->log;
        c->read->log = pc->log;
        c->write->log = pc->log;
        c->pool->log = pc->log;

        pc->connection = c;
        pc->sockaddr = my_data->ctx->upstream_sockaddr;
        pc->socklen = my_data->ctx->upstream_socklen;
        pc->name = &my_data->ctx->upstream_name;
        pc->cached = 1;

        /* Claim it from nginx idle cache */
        my_data->ctx->upstream_conn = NULL;
        my_data->cached = 1;

        return NGX_DONE;
    }

    my_data->cached = 0;
    return my_data->original_get_peer(pc, my_data->original_peer_data);
}

static void
ngx_http_upstream_free_ntlm_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_http_upstream_ntlm_peer_data_t *my_data = data;
    ngx_http_upstream_ntlm_ctx_t *ctx = my_data->ctx;
    ngx_connection_t *c = pc->connection;
    ngx_pool_cleanup_t *cln;

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    /* Safety/Debug: Impossible to reach with HTTP/2 to HTTP/1.1 downgrade and return NGX_ERROR */
    if (ctx->upstream_conn != NULL && ctx->upstream_conn != c) {
        ngx_connection_t *old_c = ctx->upstream_conn;
        ngx_pool_cleanup_t *old_cln;

        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                  "ntlm: state desync detected!!! (ctx_conn:%p != curr_conn:%p); "
                  "safely closing orphaned HTTP/2 upstream %p",
                  ctx->upstream_conn, c, old_c);

        old_cln = ngx_http_upstream_ntlm_get_upstream_cleanup(old_c, 0);
        if (old_cln) {
            old_cln->data = NULL; /* Detach the context */
        }

        old_c->read->timedout = 1;
        ngx_post_event(old_c->read, &ngx_posted_events);
    }

    ctx->upstream_conn = c;
    pc->connection = NULL;
    if(!ctx->pinned_time) {
        ctx->pinned_time = ngx_current_msec;
    }

    if (!my_data->cached) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "ntlm: pinned upstream connection %p", c);

        cln = ngx_http_upstream_ntlm_get_upstream_cleanup(c, 1);
        if (cln == NULL) {
            goto invalid;
        }
        cln->data = ctx;

        ctx->upstream_sockaddr = ngx_palloc(c->pool, pc->socklen);
        if (ctx->upstream_sockaddr == NULL) {
            goto invalid;
        }
        ngx_memcpy(ctx->upstream_sockaddr, pc->sockaddr, pc->socklen);
        ctx->upstream_socklen = pc->socklen;

        ctx->upstream_name.data = ngx_pnalloc(c->pool, pc->name->len);
        if (ctx->upstream_name.data == NULL) {
            goto invalid;
        }
        ctx->upstream_name.len = pc->name->len;
        ngx_memcpy(ctx->upstream_name.data, pc->name->data, pc->name->len);

        my_data->original_free_peer(pc, my_data->original_peer_data, 0);
        my_data->original_peer_data = NULL;
    }

    c->read->delayed = 0;
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    c->write->handler = ngx_http_upstream_ntlm_dummy_handler;
    c->read->handler = ngx_http_upstream_ntlm_upstream_close_handler;

    if (c->read->ready) {
        ngx_http_upstream_ntlm_upstream_close_handler(c->read);
    }
    return;

invalid:
    ctx->upstream_conn = NULL;
    ctx->pinned_time = 0;
    if (!my_data->cached) {
        my_data->original_free_peer(pc, my_data->original_peer_data, state);
        my_data->original_peer_data = NULL;
    }
}

#if (NGX_HTTP_SSL)
static ngx_int_t
ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc, void *data) {
    ngx_http_upstream_ntlm_peer_data_t *my_data = data;
    if (my_data->cached) {
        return NGX_OK;  /* SSL session already active on pinned connection */
    }
    return my_data->original_set_session(pc, my_data->original_peer_data);
}

static void
ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc, void *data) {
    ngx_http_upstream_ntlm_peer_data_t *my_data = data;
    if (my_data->cached) {
        return;
    }
    my_data->original_save_session(pc, my_data->original_peer_data);
}
#endif

static void
ngx_http_upstream_ntlm_upstream_close_handler(ngx_event_t *ev) {
    ngx_connection_t *c = ev->data;
    ngx_pool_cleanup_t *cln;
    ngx_http_upstream_ntlm_ctx_t *ctx = NULL;
    char buf[1];
    int n;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);
    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }
        return;
    }

close:
    cln = ngx_http_upstream_ntlm_get_upstream_cleanup(c, 0);
    if (cln) {
        ctx = cln->data;
        cln->data = NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ntlm: upstream backend closed %p (cln: %p)", c, cln);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->read->handler = ngx_http_upstream_ntlm_dummy_handler;
    c->write->handler = ngx_http_upstream_ntlm_dummy_handler;

    if (ctx) {
        ctx->upstream_conn = NULL;
        ctx->pinned_time = 0;

        /* Zero out addresses which are owned by the dying upstream for safety. */
        ctx->upstream_sockaddr = NULL;
        ctx->upstream_socklen = 0;
        ctx->upstream_name.data = NULL;
        ctx->upstream_name.len = 0;
    }

    ngx_http_upstream_ntlm_close_upstream(c);
}

static void ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev) { }

static ngx_int_t
ngx_http_upstream_ntlm_postconfiguration(ngx_conf_t *cf)
{
#if (NGX_HTTP_V2)
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Early for actual NTLM clients */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_upstream_ntlm_access_handler;

    /* Late for NTLM header set from Lua */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_upstream_ntlm_access_handler;
#endif

    return NGX_OK;
}

/* --- HTTP/2 to HTTP/1.1 Downgrade Logic --- */
#if (NGX_HTTP_V2)
#define NGX_HTTP_V2_HTTP_1_1_REQUIRED 0xd
#define NGX_HTTP_V2_RST_STREAM_SIZE 4
#define NGX_HTTP_V2_GOAWAY_SIZE 8
#define NGX_HTTP_V2_FRAME_BUFFER_SIZE 24

static ngx_int_t
ngx_http_upstream_ntlm_httpv2_frame_handler(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame)
{
    ngx_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NGX_AGAIN;
    }

    frame->next = h2c->free_frames;
    h2c->free_frames = frame;

    h2c->total_bytes += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    return NGX_OK;
}

static ngx_http_v2_out_frame_t *
ngx_http_upstream_ntlm_httpv2_get_frame(ngx_http_v2_connection_t *h2c, size_t length,
    ngx_uint_t type, u_char flags, ngx_uint_t sid)
{
    ngx_buf_t                *buf;
    ngx_pool_t               *pool;
    ngx_http_v2_out_frame_t  *frame;

    frame = h2c->free_frames;

    if (frame) {
        h2c->free_frames = frame->next;

        buf = frame->first->buf;
        buf->pos = buf->start;

        frame->blocked = 0;

    } else if (h2c->frames < 10000) {
        pool = h2c->pool ? h2c->pool : h2c->connection->pool;

        frame = ngx_pcalloc(pool, sizeof(ngx_http_v2_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        frame->first = ngx_alloc_chain_link(pool);
        if (frame->first == NULL) {
            return NULL;
        }

        buf = ngx_create_temp_buf(pool, NGX_HTTP_V2_FRAME_BUFFER_SIZE);
        if (buf == NULL) {
            return NULL;
        }

        buf->last_buf = 1;

        frame->first->buf = buf;
        frame->last = frame->first;

        frame->handler = ngx_http_upstream_ntlm_httpv2_frame_handler;

        h2c->frames++;

    } else {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

#if (NGX_DEBUG)
    if (length > NGX_HTTP_V2_FRAME_BUFFER_SIZE - NGX_HTTP_V2_FRAME_HEADER_SIZE)
    {
        ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
                      "requested control frame is too large: %uz", length);
        return NULL;
    }
#endif

    frame->length = length;

    buf->last = ngx_http_v2_write_len_and_type(buf->pos, length, type);

    *buf->last++ = flags;

    buf->last = ngx_http_v2_write_sid(buf->last, sid);

    return frame;
}

static ngx_int_t
ngx_http_upstream_ntlm_httpv2_send_rst_stream(ngx_http_v2_connection_t *h2c, ngx_uint_t sid,
    ngx_uint_t status)
{
    ngx_buf_t                *buf;
    ngx_http_v2_out_frame_t  *frame;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send RST_STREAM frame sid:%ui, status:%ui",
                   sid, status);

    frame = ngx_http_upstream_ntlm_httpv2_get_frame(h2c, NGX_HTTP_V2_RST_STREAM_SIZE,
                                  NGX_HTTP_V2_RST_STREAM_FRAME,
                                  NGX_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    buf->last = ngx_http_v2_write_uint32(buf->last, status);

    ngx_http_v2_queue_blocked_frame(h2c, frame);

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_ntlm_httpv2_send_goaway(ngx_http_v2_connection_t *h2c, ngx_uint_t status)
{
    ngx_buf_t                *buf;
    ngx_http_v2_out_frame_t  *frame;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send GOAWAY frame: last sid %ui, error %ui",
                   h2c->last_sid, status);

    frame = ngx_http_upstream_ntlm_httpv2_get_frame(h2c, NGX_HTTP_V2_GOAWAY_SIZE,
                                  NGX_HTTP_V2_GOAWAY_FRAME,
                                  NGX_HTTP_V2_NO_FLAG, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    buf->last = ngx_http_v2_write_sid(buf->last, h2c->last_sid);
    buf->last = ngx_http_v2_write_uint32(buf->last, status);

    ngx_http_v2_queue_blocked_frame(h2c, frame);

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_ntlm_httpv2_terminate_stream(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_stream_t *stream, ngx_uint_t status)
{
    ngx_event_t       *rev;
    ngx_connection_t  *fc;

    if (stream->rst_sent) {
        return NGX_OK;
    }

    if (ngx_http_upstream_ntlm_httpv2_send_rst_stream(h2c, stream->node->id, status)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    stream->rst_sent = 1;
    stream->skip_data = 1;

    fc = stream->request->connection;
    fc->error = 1;

    rev = fc->read;
    ngx_post_event(rev, &ngx_posted_events);
    /*rev->handler(rev);*/

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_ntlm_access_handler(ngx_http_request_t *r)
{
    ngx_str_t auth_hdr;

    /* Not an H2 stream, already handled or no Authorization header */
    if (r->stream == NULL || r->header_sent || r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }

    auth_hdr = r->headers_in.authorization->value;
    if ((auth_hdr.len >= 4 && ngx_strncasecmp(auth_hdr.data, (u_char *)"NTLM", 4) == 0) ||
        (auth_hdr.len >= 9 && ngx_strncasecmp(auth_hdr.data, (u_char *)"Negotiate", 9) == 0))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "ntlm: NTLM/Negotiate on HTTP/2, forcing client retry over HTTP/1.1");

        if (!r->stream->connection->goaway) {
            r->stream->connection->goaway = 1;
            if (ngx_http_upstream_ntlm_httpv2_send_goaway(r->stream->connection, NGX_HTTP_V2_HTTP_1_1_REQUIRED) != NGX_ERROR) {
                (void) ngx_http_v2_send_output_queue(r->stream->connection);
            }
        }

        ngx_http_upstream_ntlm_httpv2_terminate_stream(r->stream->connection, r->stream, NGX_HTTP_V2_HTTP_1_1_REQUIRED);

        r->stream->waiting = 0;
        r->stream->queued = 0;

        return NGX_DONE;
    }

    return NGX_DECLINED;
}
#endif  /* NGX_HTTP_V2 */
