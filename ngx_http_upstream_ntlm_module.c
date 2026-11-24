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
    ngx_sockaddr_t upstream_sockaddr;
    socklen_t upstream_socklen;
    u_char upstream_name_buf[NGX_SOCKADDR_STRLEN];
    ngx_str_t upstream_name;
    ngx_msec_t pinned_time;
    unsigned pinned:1;
} ngx_http_upstream_ntlm_ctx_t;

typedef struct {
    ngx_http_upstream_srv_conf_t *us;
} ngx_http_upstream_ntlm_req_ctx_t;

typedef struct {
    ngx_http_upstream_ntlm_ctx_t *ctx;
    ngx_http_request_t *request;
    ngx_http_upstream_t *upstream;
    void *original_peer_data;
    ngx_event_get_peer_pt original_get_peer;
    ngx_event_free_peer_pt original_free_peer;
#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt original_set_session;
    ngx_event_save_peer_session_pt original_save_session;
#endif
    ngx_event_notify_peer_pt original_notify;
    ngx_str_t peer_name;
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
static void ngx_http_upstream_ntlm_notify_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t type);

static ngx_flag_t ngx_http_upstream_ntlm_has_auth_header(ngx_http_request_t *r);
static void ngx_http_upstream_ntlm_detach_pinned(ngx_http_upstream_ntlm_ctx_t *ctx);
static void ngx_http_upstream_ntlm_client_cleanup(void *data);
static void ngx_http_upstream_ntlm_upstream_cleanup(void *data);
static void ngx_http_upstream_ntlm_close_upstream(ngx_connection_t *c);
static void ngx_http_upstream_ntlm_upstream_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev);

static ngx_http_upstream_ntlm_ctx_t *ngx_http_upstream_ntlm_client_get_ctx(ngx_connection_t *c, ngx_http_upstream_srv_conf_t *us, ngx_flag_t create);
static ngx_http_upstream_ntlm_ctx_t *ngx_http_upstream_ntlm_client_get_ctx_by_name(ngx_connection_t *c, ngx_str_t *name);
static ngx_pool_cleanup_t *ngx_http_upstream_ntlm_get_upstream_cleanup(ngx_connection_t *c, ngx_flag_t create);

static ngx_int_t ngx_http_upstream_ntlm_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_ntlm_pinned_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_ntlm_pinned_prefix_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_upstream_ntlm_postconfiguration(ngx_conf_t *cf);
#if (NGX_HTTP_V2)
static ngx_int_t ngx_http_upstream_ntlm_httpv2_send_rst_stream(ngx_http_v2_connection_t *h2c, ngx_uint_t sid, ngx_uint_t status);
static ngx_int_t ngx_http_upstream_ntlm_httpv2_send_goaway(ngx_http_v2_connection_t *h2c, ngx_uint_t status);
static ngx_int_t ngx_http_upstream_ntlm_access_handler(ngx_http_request_t *r);
#endif

/* --- Module Variables --- */
static ngx_http_variable_t ngx_http_upstream_ntlm_vars[] = {
    { ngx_string("ntlm_pinned"), NULL,
      ngx_http_upstream_ntlm_pinned_var, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("ntlm_pinned_"), NULL,
      ngx_http_upstream_ntlm_pinned_prefix_var, 0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX, 0 },
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

/* --- Helpers --- */
static ngx_flag_t
ngx_http_upstream_ntlm_has_auth_header(ngx_http_request_t *r)
{
    ngx_str_t auth_hdr;

    if (r->headers_in.authorization == NULL) {
        return 0;
    }

    auth_hdr = r->headers_in.authorization->value;
    if ((auth_hdr.len >= 4
         && ngx_strncasecmp(auth_hdr.data, (u_char *) "NTLM", 4) == 0
         && (auth_hdr.len == 4 || auth_hdr.data[4] == ' '))
        || (auth_hdr.len >= 9
            && ngx_strncasecmp(auth_hdr.data, (u_char *) "Negotiate", 9) == 0
            && (auth_hdr.len == 9 || auth_hdr.data[9] == ' ')))
    {
        return 1;
    }

    return 0;
}

static void
ngx_http_upstream_ntlm_detach_pinned(ngx_http_upstream_ntlm_ctx_t *ctx)
{
    ngx_connection_t *uc = ctx->upstream_conn;
    ngx_pool_cleanup_t *cln;

    ctx->upstream_conn = NULL;
    ctx->pinned_time = 0;
    ctx->pinned = 0;
    ctx->upstream_socklen = 0;
    ctx->upstream_name.len = 0;
    ctx->upstream_name.data = NULL;

    if (uc) {
        cln = ngx_http_upstream_ntlm_get_upstream_cleanup(uc, 0);
        if (cln) {
            cln->data = NULL;
        }

        uc->read->timedout = 1;
        ngx_post_event(uc->read, &ngx_posted_events);
    }
}

/* --- Variables $ntlm_pinned and $ntlm_pinned_<upstream_name> --- */
static ngx_connection_t *
ngx_http_upstream_ntlm_get_client_conn(ngx_http_request_t *r)
{
#if (NGX_HTTP_V2)
    if (r->stream) {
        return r->stream->connection->connection;
    }
#endif
    return r->connection;
}

static ngx_int_t
ngx_http_upstream_ntlm_format_pinned_var(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_upstream_ntlm_ctx_t *ctx)
{
    if (ctx != NULL && ctx->pinned) {
        ngx_msec_t elapsed_ms = ngx_current_msec - ctx->pinned_time;

        v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }
        v->len = ngx_sprintf(v->data, "%M", elapsed_ms) - v->data;
    } else {
        v->len = 0;
        v->data = (u_char *) "";
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_ntlm_pinned_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_connection_t *c;
    ngx_http_upstream_ntlm_ctx_t *ctx;
    ngx_http_upstream_ntlm_req_ctx_t *rctx;
    ngx_http_upstream_srv_conf_t *us = NULL;

    c = ngx_http_upstream_ntlm_get_client_conn(r);

    if (c == NULL || c->pool == NULL || c->close) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                       r->connection ? r->connection->log : ngx_cycle->log, 0,
                       "ntlm: pinned var: client connection is already closing, skipping ctx");
        v->not_found = 1;
        return NGX_OK;
    }

    /* Try the cached value first, works at log phase too */
    rctx = ngx_http_get_module_ctx(r, ngx_http_upstream_ntlm_module);
    if (rctx) {
        us = rctx->us;
    } else if (r->upstream) {
        /* Fallback: variable evaluated before init_peer ran (e.g. proxy_set_header) */
        if (r->upstream->upstream) {
            us = r->upstream->upstream;
        } else if (r->upstream->conf) {
            us = r->upstream->conf->upstream;
        }
    }

    /*
     * Note: When evaluated in access_by_lua_* (NGX_HTTP_ACCESS_PHASE), r->upstream
     * has not been created yet so us is NULL; fall back to matching any pinned ctx
     * on the client connection so Lua auth handlers can check $ntlm_pinned.
     */
    ctx = ngx_http_upstream_ntlm_client_get_ctx(c, us, 0);

    return ngx_http_upstream_ntlm_format_pinned_var(r, v, ctx);
}

static ngx_int_t
ngx_http_upstream_ntlm_pinned_prefix_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_str_t *var_name = (ngx_str_t *) data;
    ngx_str_t upstream_name;
    ngx_connection_t *c;
    ngx_http_upstream_ntlm_ctx_t *ctx;
    size_t prefix_len = sizeof("ntlm_pinned_") - 1;

    c = ngx_http_upstream_ntlm_get_client_conn(r);

    if (c == NULL || c->pool == NULL || c->close) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                       r->connection ? r->connection->log : ngx_cycle->log, 0,
                       "ntlm: pinned prefix var: client connection is already closing, skipping ctx");
        v->not_found = 1;
        return NGX_OK;
    }

    if (var_name == NULL || var_name->len <= prefix_len) {
        return ngx_http_upstream_ntlm_format_pinned_var(r, v, NULL);
    }

    upstream_name.data = var_name->data + prefix_len;
    upstream_name.len = var_name->len - prefix_len;

    ctx = ngx_http_upstream_ntlm_client_get_ctx_by_name(c, &upstream_name);

    return ngx_http_upstream_ntlm_format_pinned_var(r, v, ctx);
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

    if (ncf->original_init_upstream != NULL) {
        return "is duplicate";
    }

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
    ctx = (ngx_http_upstream_ntlm_ctx_t *) cln->data;
    ngx_memzero(ctx, sizeof(ngx_http_upstream_ntlm_ctx_t));

    ctx->upstream_srv_conf = us;
    cln->handler = ngx_http_upstream_ntlm_client_cleanup;
    cln->data = ctx;

    return ctx;
}

/* Lookup Context attached to the Client Connection by upstream name (case-insensitive) */
static ngx_http_upstream_ntlm_ctx_t *
ngx_http_upstream_ntlm_client_get_ctx_by_name(ngx_connection_t *c, ngx_str_t *name) {
    ngx_pool_cleanup_t *cln;
    ngx_http_upstream_ntlm_ctx_t *ctx;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_upstream_ntlm_client_cleanup) {
            ctx = cln->data;
            if (ctx->upstream_srv_conf != NULL
                && ctx->upstream_srv_conf->host.len == name->len
                && ngx_strncasecmp(ctx->upstream_srv_conf->host.data, name->data, name->len) == 0)
            {
                return ctx;
            }
        }
    }

    return NULL;
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "ntlm: client cleanup %p", ctx);

    if (ctx->upstream_conn) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "ntlm: client dropped, closing pinned upstream %p", ctx->upstream_conn);
        ngx_http_upstream_ntlm_detach_pinned(ctx);
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
        ctx->pinned = 0;
        ctx->upstream_socklen = 0;
        ctx->upstream_name.len = 0;
        ctx->upstream_name.data = NULL;
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

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }
    ngx_close_connection(c);
}

/* --- Core Logic --- */

static ngx_int_t
ngx_http_upstream_init_ntlm_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
    ngx_connection_t *c;
    ngx_http_upstream_ntlm_peer_data_t *my_data;
    ngx_http_upstream_ntlm_srv_conf_t *ncf;
    ngx_http_upstream_ntlm_req_ctx_t *rctx;
    ngx_flag_t has_ntlm;

    ncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    has_ntlm = ngx_http_upstream_ntlm_has_auth_header(r);
    if (has_ntlm) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ntlm: auth header found");
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        if (has_ntlm) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ntlm: init peer called on HTTP/2 stream with NTLM/Negotiate auth");
            return NGX_ERROR;
        }
        /* Allow non-NTLM / initial unauthenticated HTTP/2 requests to proceed unpinned */
        return ncf->original_init_peer(r, us);
    }
#endif

#if (NGX_HTTP_V3)
    if (r->connection->quic) {
        if (has_ntlm) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ntlm: NTLM/Negotiate is incompatible with HTTP/3 (QUIC)");
            return NGX_ERROR;
        }
        /* Allow non-NTLM / initial unauthenticated HTTP/3 requests to proceed unpinned */
        return ncf->original_init_peer(r, us);
    }
#endif

    /* Do not share main request's pinned connection state with concurrent subrequests */
    if (r != r->main) {
        if (has_ntlm) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ntlm: NTLM/Negotiate pinning is not supported on subrequests");
            return NGX_ERROR;
        }
        return ncf->original_init_peer(r, us);
    }

    c = r->connection;

    /* cache upstream for the request lifecycle */
    rctx = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ntlm_req_ctx_t));
    if (rctx == NULL) {
        return NGX_ERROR;
    }
    rctx->us = us;
    ngx_http_set_ctx(r, rctx, ngx_http_upstream_ntlm_module);

    my_data = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_ntlm_peer_data_t));
    if (my_data == NULL) {
        return NGX_ERROR;
    }

    if (ncf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * If the client switched to a different non-empty Authorization scheme
     * (e.g. Basic/Bearer) on an already-pinned connection, tear down the NTLM pin
     * instead of mixing auth contexts. Ignore empty values (e.g. OpenResty's
     * ngx.req.set_header("Authorization", "")).
     */
    if (r->headers_in.authorization != NULL
        && r->headers_in.authorization->value.len > 0
        && !has_ntlm)
    {
        ngx_http_upstream_ntlm_ctx_t *existing = ngx_http_upstream_ntlm_client_get_ctx(c, us, 0);
        if (existing != NULL && existing->upstream_conn != NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ntlm: non-NTLM Authorization header on pinned connection, releasing pin");
            ngx_http_upstream_ntlm_detach_pinned(existing);
        }
        return NGX_OK;
    }

    my_data->ctx = ngx_http_upstream_ntlm_client_get_ctx(c, us, has_ntlm);
    if (my_data->ctx == NULL) {
        /* Fail closed on OOM when NTLM/Negotiate auth is present so it cannot leak to keepalive */
        return has_ntlm ? NGX_ERROR : NGX_OK;
    }

    my_data->request = r;
    my_data->upstream = r->upstream;
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

    if (r->upstream->peer.notify) {
        my_data->original_notify = r->upstream->peer.notify;
        r->upstream->peer.notify = ngx_http_upstream_ntlm_notify_peer;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_get_ntlm_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_http_upstream_ntlm_peer_data_t *my_data = data;
    ngx_http_upstream_ntlm_ctx_t *ctx = my_data->ctx;
    ngx_connection_t *c;

    if (ctx->pinned && ctx->upstream_conn != NULL) {
        c = ctx->upstream_conn;

        if (ctx->upstream_name.len > 0) {
            my_data->peer_name.data = ngx_pnalloc(my_data->request->pool, ctx->upstream_name.len);
            if (my_data->peer_name.data == NULL) {
                return NGX_ERROR;
            }
            my_data->peer_name.len = ctx->upstream_name.len;
            ngx_memcpy(my_data->peer_name.data, ctx->upstream_name.data, ctx->upstream_name.len);
            pc->name = &my_data->peer_name;
        } else {
            pc->name = &ctx->upstream_name;
        }

        c->idle = 0;
        c->sent = 0;
        c->data = NULL;
        c->log = pc->log;
        c->read->log = pc->log;
        c->write->log = pc->log;
        c->pool->log = pc->log;

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        pc->connection = c;
        pc->sockaddr = &ctx->upstream_sockaddr.sockaddr;
        pc->socklen = ctx->upstream_socklen;
        pc->cached = 1;

        /* Claim it from pinned idle state */
        ctx->upstream_conn = NULL;
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
    ngx_http_upstream_t *u = my_data->upstream;
    ngx_pool_cleanup_t *cln;
    size_t name_len;

    if ((state & (NGX_PEER_FAILED | NGX_PEER_NEXT))
        || c == NULL
        || !u->keepalive
        || !u->request_body_sent
        || ngx_terminate
        || ngx_exiting
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

    /* Perform all fallible operations before taking ownership (pc->connection = NULL) */
    cln = ngx_http_upstream_ntlm_get_upstream_cleanup(c, 1);
    if (cln == NULL) {
        goto invalid;
    }

    /* Safety/Debug: guard against unexpected desync where another upstream conn was pinned */
    if (ctx->upstream_conn != NULL && ctx->upstream_conn != c) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "ntlm: state desync detected (ctx_conn:%p != curr_conn:%p); "
                      "safely closing orphaned upstream %p",
                      ctx->upstream_conn, c, ctx->upstream_conn);
        ngx_http_upstream_ntlm_detach_pinned(ctx);
    }

    cln->data = ctx;
    ctx->upstream_conn = c;
    pc->connection = NULL;

    if (!ctx->pinned) {
        ctx->pinned_time = ngx_current_msec;
        ctx->pinned = 1;
    }

    if (!my_data->cached || ctx->upstream_socklen == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "ntlm: pinned upstream connection %p", c);

        if (pc->sockaddr && pc->socklen <= sizeof(ctx->upstream_sockaddr)) {
            ngx_memcpy(&ctx->upstream_sockaddr, pc->sockaddr, pc->socklen);
            ctx->upstream_socklen = pc->socklen;
        }

        if (pc->name && pc->name->len > 0) {
            name_len = ngx_min(pc->name->len, sizeof(ctx->upstream_name_buf));
            ngx_memcpy(ctx->upstream_name_buf, pc->name->data, name_len);
            ctx->upstream_name.data = ctx->upstream_name_buf;
            ctx->upstream_name.len = name_len;
        }
    }

    if (!my_data->cached) {
        my_data->original_free_peer(pc, my_data->original_peer_data, 0);
    }

    c->read->delayed = 0;
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->data = ctx;
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
    ctx->pinned = 0;
    if (!my_data->cached) {
        my_data->original_free_peer(pc, my_data->original_peer_data, state);
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
ngx_http_upstream_ntlm_notify_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t type) {
    ngx_http_upstream_ntlm_peer_data_t *my_data = data;

    if (!my_data->cached) {
        my_data->original_notify(pc, my_data->original_peer_data, type);
    }
}

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
    if (n == -1 && (ngx_socket_errno == NGX_EAGAIN || ngx_socket_errno == NGX_EINTR)) {
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
        ctx->pinned = 0;
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
    ngx_uint_t i;
    ngx_http_upstream_main_conf_t *umcf;
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_http_upstream_ntlm_srv_conf_t *ncf;
#if (NGX_HTTP_V2)
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
#endif

    /*
     * Wrap peer.init in postconfiguration (after all modules' init_main_conf,
     * including ngx_http_upstream_keepalive_module in Nginx 1.29.7+/1.31)
     * so NTLM is always the outermost peer wrapper regardless of module order.
     */
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->srv_conf == NULL || uscfp[i]->peer.init == NULL) {
            continue;
        }

        ncf = ngx_http_conf_upstream_srv_conf(uscfp[i], ngx_http_upstream_ntlm_module);
        if (ncf->original_init_upstream == NULL) {
            continue;
        }

        ncf->original_init_peer = uscfp[i]->peer.init;
        uscfp[i]->peer.init = ngx_http_upstream_init_ntlm_peer;
    }

#if (NGX_HTTP_V2)
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

    /*
     * Do not recycle locally allocated frames into core's h2c->free_frames
     * to avoid buffer-size ABI assumptions across Nginx versions.
     */
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

    if (h2c->frames >= 10000) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

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
ngx_http_upstream_ntlm_access_handler(ngx_http_request_t *r)
{
    ngx_http_v2_connection_t *h2c;

    /* Not an H2 stream, already handled, or no NTLM/Negotiate Authorization header */
    if (r->stream == NULL || r->header_sent || !ngx_http_upstream_ntlm_has_auth_header(r)) {
        return NGX_DECLINED;
    }

    h2c = r->stream->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ntlm: NTLM/Negotiate on HTTP/2, forcing client retry over HTTP/1.1");

    if (!h2c->goaway) {
        h2c->goaway = 1;
        (void) ngx_http_upstream_ntlm_httpv2_send_goaway(h2c, NGX_HTTP_V2_HTTP_1_1_REQUIRED);
    }

    if (!r->stream->rst_sent && r->stream->node != NULL) {
        if (ngx_http_upstream_ntlm_httpv2_send_rst_stream(h2c, r->stream->node->id,
                                                          NGX_HTTP_V2_HTTP_1_1_REQUIRED) == NGX_OK)
        {
            r->stream->rst_sent = 1;
            r->stream->skip_data = 1;
        }
    }

    (void) ngx_http_v2_send_output_queue(h2c);

    /*
     * Return NGX_HTTP_CLOSE so ngx_http_core_generic_phase calls
     * ngx_http_finalize_request(r, NGX_HTTP_CLOSE) -> ngx_http_v2_close_stream(),
     * cleanly decrementing h2c->processing and freeing the stream/connection.
     */
    return NGX_HTTP_CLOSE;
}
#endif  /* NGX_HTTP_V2 */
