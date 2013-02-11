/*
 * fatcache - memcache on ssd.
 * Copyright (C) 2013 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fc_core.h>
#include <fc_server.h>

extern struct settings settings;

#define SERVER_BACKLOG 1024

static rstatus_t
server_accept(struct context *ctx, struct conn *s)
{
    rstatus_t status;
    struct conn *c;
    int sd;

    ASSERT(!s->client);
    ASSERT(s->sd > 0);
    ASSERT(s->recv_active && s->recv_ready);

    for (;;) {
        sd = accept(s->sd, NULL, NULL);
        if (sd < 0) {
            if (errno == EINTR) {
                log_debug(LOG_VERB, "accept on s %d not ready - eintr", s->sd);
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                log_debug(LOG_VERB, "accept on s %d not ready - eagain", s->sd);
                s->recv_ready = 0;
                return FC_OK;
            }

            log_error("accept on s %d failed: %s", s->sd, strerror(errno));
            return FC_ERROR;
        }

        break;
    }

    c = conn_get(sd, true);
    if (c == NULL) {
        log_error("get conn for c %d from s %d failed: %s", sd, s->sd,
                  strerror(errno));
        status = close(sd);
        if (status < 0) {
            log_error("close c %d failed, ignored: %s", sd, strerror(errno));
        }
        return FC_ENOMEM;
    }

    status = fc_set_nonblocking(sd);
    if (status < 0) {
        log_error("set nonblock on c %d failed: %s", sd, strerror(errno));
        return FC_ERROR;
    }

    status = fc_set_tcpnodelay(c->sd);
    if (status < 0) {
        log_warn("set tcp nodely on c %d failed, ignored: %s", sd,
                 strerror(errno));
    }

    status = event_add_conn(ctx->ep, c);
    if (status < 0) {
        log_error("event add conn e %d c %d failed: %s", ctx->ep, sd,
                  strerror(errno));
        return FC_ERROR;
    }

    log_debug(LOG_NOTICE, "accepted c %d on s %d", c->sd, s->sd);

    return FC_OK;
}

rstatus_t
server_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    ASSERT(!conn->client);
    ASSERT(conn->recv_active);

    conn->recv_ready = 1;
    do {
        status = server_accept(ctx, conn);
        if (status != FC_OK) {
            return status;
        }
    } while (conn->recv_ready);

    return FC_OK;
}

rstatus_t
server_listen(struct context *ctx)
{
    rstatus_t status;
    struct sockinfo si;
    struct string addrstr;
    int sd, family;
    socklen_t addrlen;
    struct sockaddr *addr;
    struct conn *s;

    string_set_raw(&addrstr, settings.addr);
    status = fc_resolve(&addrstr, settings.port, &si);
    if (status != FC_OK) {
        return FC_ERROR;
    }

    family = si.family;
    addrlen = si.addrlen;
    addr = (struct sockaddr *)&si.addr;

    sd = socket(family, SOCK_STREAM, 0);
    if (sd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return FC_ERROR;
    }

    status = fc_set_reuseaddr(sd);
    if (status != FC_OK) {
        log_error("reuse of sd %d failed: %s", sd, strerror(errno));
        return FC_ERROR;
    }

    status = bind(sd, addr, addrlen);
    if (status < 0) {
        log_error("bind on sd %d failed: %s", sd, strerror(errno));
        return FC_ERROR;
    }

    status = listen(sd, SERVER_BACKLOG);
    if (status < 0) {
        log_error("listen on sd %d failed: %s", sd, strerror(errno));
        return FC_ERROR;
    }

    status = fc_set_nonblocking(sd);
    if (status != FC_OK) {
        log_error("set nonblock on sd %d failed: %s", sd, strerror(errno));
        return FC_ERROR;
    }

    s = conn_get(sd, false);
    if (s == NULL) {
        log_error("get conn for s %d failed: %s", sd, strerror(errno));
        status = close(sd);
        if (status < 0) {
            log_error("close s %d failed, ignored: %s", sd, strerror(errno));
        }
        return FC_ENOMEM;
    }

    status = event_add_conn(ctx->ep, s);
    if (status < 0) {
        log_error("event add conn e %d s %d failed: %s", ctx->ep, sd,
                  strerror(errno));
        return FC_ERROR;
    }

    status = event_del_out(ctx->ep, s);
    if (status != FC_OK) {
        log_error("event del conn e %d s %d failed: %s", ctx->ep, sd,
                  strerror(errno));
        return status;
    }

    log_debug(LOG_NOTICE, "server listening on s %d", s->sd);

    return FC_OK;
}
