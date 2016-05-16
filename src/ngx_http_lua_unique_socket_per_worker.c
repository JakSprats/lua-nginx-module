
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <sys/types.h>
#include <unistd.h>

#include <ngx_stream.h>

#include "ngx_http_lua_util.h"
#include "ngx_http_lua_unique_socket_per_worker.h"

//#define DEBUG_ELTS

static void debug_elts(ngx_http_request_t *r, ngx_listening_t *ls, int nelts) {
#ifdef DEBUG_ELTS
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "START: DEBUG_ELTS: N(%d)", nelts);
    for (int i = 0; i < nelts; i++) {
      int              fd = ls[i].fd;
      struct sockaddr *an = ls[i].sockaddr;
      if (an->sa_family == AF_INET) {
        struct sockaddr_in *in   = (struct sockaddr_in *)ls[i].sockaddr;
        int                 port = ntohs(in->sin_port);
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "LISTEN: I: %d FD: %d PORT: %d", i, fd, port);
      } else { // AF_UNIX
        struct sockaddr_un *un   = (struct sockaddr_un *)ls[i].sockaddr;
        char               *path = un->sun_path;
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "LISTEN: I: %d FD: %d PATH: %s", i, fd, path);
      }
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "END:DEBUG_ELTS");
#endif
}

static int
get_listening_socket_elt(ngx_listening_t *ls, int nelts, u_char *upath) {
    size_t ulen = strlen((char *)upath);
    for (int i = 0; i < nelts; i++) {
        size_t alen  = ls[i].addr_text.len;
        if (alen == ulen) {
            char *atext = (char *)ls[i].addr_text.data;
            if (!strcmp(atext, (char *)upath)) return i;
        }
    }
    return -1;
}

// NOTE: taken from: event/ngx_event.c ngx_event_process_init()
static ngx_int_t
__ngx_event_process_init(ngx_http_request_t *r, ngx_cycle_t *cycle,
                         ngx_listening_t *ls)
{
    ngx_event_t         *rev;
    ngx_connection_t    *c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "__ngx_event_process_init: FD: %d", ls->fd);

    c = ngx_get_connection(ls->fd, cycle->log);

    if (c == NULL) {
        return NGX_ERROR;
    }

    c->log = &(ls->log);

    c->listening = ls;
    ls->connection = c;

    rev = c->read;

    rev->log = c->log;
    rev->accept = 1;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    rev->deferred_accept = ls->deferred_accept;
#endif

    rev->handler = ngx_event_accept;

    if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


// NOTE: core/ngx_connection.c ngx_create_listening()
ngx_listening_t *
__ngx_create_listening(ngx_conf_t *cf, void *sockaddr, socklen_t socklen)
{
    size_t            len;
    ngx_listening_t  *ls;
    struct sockaddr  *sa;
    u_char            text[NGX_SOCKADDR_STRLEN];

    ls = ngx_palloc(cf->pool, sizeof(ngx_listening_t));
    if (ls == NULL) {
        return NULL;
    }

    ngx_memzero(ls, sizeof(ngx_listening_t));

    sa = ngx_palloc(cf->pool, socklen);
    if (sa == NULL) {
        return NULL;
    }

    ngx_memcpy(sa, sockaddr, socklen);

    ls->sockaddr = sa;
    ls->socklen = socklen;

    len = ngx_sock_ntop(sa, socklen, text, NGX_SOCKADDR_STRLEN, 1);
    ls->addr_text.len = len;

    switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6:
         ls->addr_text_max_len = NGX_INET6_ADDRSTRLEN;
         break;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
         ls->addr_text_max_len = NGX_UNIX_ADDRSTRLEN;
         len++;
         break;
#endif
    case AF_INET:
         ls->addr_text_max_len = NGX_INET_ADDRSTRLEN;
         break;
    default:
         ls->addr_text_max_len = NGX_SOCKADDR_STRLEN;
         break;
    }

    ls->addr_text.data = ngx_pnalloc(cf->pool, len);
    if (ls->addr_text.data == NULL) {
        return NULL;
    }

    ngx_memcpy(ls->addr_text.data, text, len);

    ls->fd = (ngx_socket_t) -1;
    ls->type = SOCK_STREAM;

    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;

#if (NGX_HAVE_SETFIB)
    ls->setfib = -1;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    ls->fastopen = -1;
#endif

    return ls;
}

void
overwrite_listening_elt(ngx_http_request_t *r, ngx_listening_t *ls,
                        struct sockaddr_un *naddr) {
    // CLEANUP OLD FD & ADDR_TEXT
    int   ofd   = ls->fd;
    void *oadtd = ls->addr_text.data;
    (void) close(ofd);
    ngx_pfree(r->pool, oadtd);
    // OVERWRITE WITH NEW FD & ADDR_TEXT
    ls->fd = -1;
    struct sockaddr_un *un = (struct sockaddr_un *)ls->sockaddr;
    strcpy(un->sun_path, naddr->sun_path);
    int slen               = strlen(naddr->sun_path);
    ls->addr_text.len      = slen + 5; // 5 for "unix:"
    int mlen               = ls->addr_text.len + 1; // NULL terminator
    ls->addr_text.data     = ngx_palloc(r->pool, mlen);
    memcpy(ls->addr_text.data, "unix:", 5);
    memcpy(ls->addr_text.data + 5, naddr->sun_path, slen);
    ls->addr_text.data[(mlen - 1)] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "overwrite_listening_elt: add_text: %s", ls->addr_text.data);
}

static int
ngx_http_lua_ngx_unique_socket_per_worker(lua_State *L)
{
    int                          n;
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    size_t                       len;
    u_char                      *upath;

    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_INIT_WORKER);

    upath = (u_char *) lua_tolstring(L, 1, &len);
    if (ngx_strncasecmp(upath, (u_char *) "unix:", 5) != 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "path must begin with 'unix:'");
        return 2;
    }

    if (ngx_use_accept_mutex) {
        return luaL_error(L, "unique_socket_per_worker only works with"
                             " directive: 'accept_mutex off'");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "ngx_http_lua_ngx_unique_socket_per_worker: path: %s", upath);

    ngx_http_core_loc_conf_t *clcf;
    clcf            = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_cycle_t     *cycle  = (ngx_cycle_t *)ngx_cycle;
    ngx_listening_t *ols    = cycle->listening.elts;
    int              onelts = cycle->listening.nelts;
    int              melt   = get_listening_socket_elt(ols, onelts, upath);
    ngx_listening_t *mls    = &(ols[melt]);
    if (melt == -1) {
        lua_pushnil(L);
        lua_pushliteral(L, "server not listening on path");
        return 2;
    }

    debug_elts(r, ols, onelts);

    struct sockaddr_un  naddr;
    int                 socklen = sizeof(struct sockaddr_un);
    struct sockaddr_un *un      = (struct sockaddr_un *)mls->sockaddr;
    char               *path    = un->sun_path;
    pid_t               pid     = getpid();

    memcpy(&naddr, un, socklen);
    snprintf(naddr.sun_path, 108, "%s_%u", path, pid);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "unique_path: %s", naddr.sun_path);

    ngx_conf_t cf;
    cf.pool = cycle->pool;
    ngx_listening_t *ls;
    ls = __ngx_create_listening(&cf, (struct sockaddr *)&naddr, socklen);
    if (ls == NULL) {
        return luaL_error(L, "ngx.socket listen: __ngx_create_listening");
    }

    overwrite_listening_elt(r, mls, &naddr);

    ls->logp        = clcf->error_log;
    ls->log.data    = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;
    ls->addr_ntop   = 1;
    ls->handler     = ngx_http_init_connection;

    if (ngx_open_listening_sockets(cycle) != NGX_OK) {
        return luaL_error(L, "ngx.socket listen: ngx_open_listening_sockets");
    }

    if (__ngx_event_process_init(r, cycle, mls) == NGX_ERROR) {
        return luaL_error(L, "ngx.socket listen: __ngx_event_process_init");
    }

    debug_elts(r, ols, onelts);

    lua_pushinteger(L, 1);
    return 1;
}

void
ngx_http_lua_inject_unique_socket_per_worker_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_unique_socket_per_worker);
    lua_setfield(L, -2, "unique_socket_per_worker");
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
