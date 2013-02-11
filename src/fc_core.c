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

#include <stdio.h>
#include <stdlib.h>

#include <fc_core.h>
#include <fc_server.h>

extern struct settings settings;

rstatus_t
core_init(void)
{
    rstatus_t status;

    status = log_init(settings.verbose, settings.log_filename);
    if (status != FC_OK) {
        return status;
    }

    status = signal_init();
    if (status != FC_OK) {
        return status;
    }

    status = time_init();
    if (status != FC_OK) {
        return status;
    }

    status = itemx_init();
    if (status != FC_OK) {
        return status;
    }

    conn_init();

    mbuf_init();

    msg_init();

    item_init();

    status = slab_init();
    if (status != FC_OK) {
        return status;
    }

    return FC_OK;
}

void
core_deinit(void)
{
}

static rstatus_t
core_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->recv(ctx, conn);
    if (status != FC_OK) {
        log_debug(LOG_INFO, "recv on %c %d failed: %s",
                  conn->client ? 'c' : 's', conn->sd,
                  strerror(errno));
    }

    return status;
}

static rstatus_t
core_send(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->send(ctx, conn);
    if (status != FC_OK) {
        log_debug(LOG_INFO, "send on %c %d failed: %s",
                  conn->client ? 'c' : 's', conn->sd,
                  strerror(errno));
    }

    return status;
}

static void
core_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type = conn->client ? 'c' : 's';

    ASSERT(conn->sd > 0);

    log_debug(LOG_NOTICE, "close %c %d on event %04"PRIX32" eof %d done "
              "%d rb %zu sb %zu%c %s", type, conn->sd, conn->events,
              conn->eof, conn->done, conn->recv_bytes, conn->send_bytes,
              conn->err ? ':' : ' ', conn->err ? strerror(conn->err) : "");

    status = event_del_conn(ctx->ep, conn);
    if (status < 0) {
        log_warn("event del conn e %d %c %d failed, ignored: %s", ctx->ep,
                 type, conn->sd, strerror(errno));
    }

    conn->close(ctx, conn);
}

static void
core_error(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type = conn->client ? 'c' : 's';

    status = fc_get_soerror(conn->sd);
    if (status < 0) {
        log_warn("get soerr on %c %d failed, ignored: %s", type, conn->sd,
                  strerror(errno));
    }
    conn->err = errno;

    core_close(ctx, conn);
}

static void
core_core(struct context *ctx, struct conn *conn, uint32_t events)
{
    rstatus_t status;

    log_debug(LOG_VERB, "event %04"PRIX32" on %d", events, conn->sd);

    conn->events = events;

    /* error takes precedence over read | write */
    if (events & EPOLLERR) {
        core_error(ctx, conn);
        return;
    }

    /* read takes precedence over write */
    if (events & (EPOLLIN | EPOLLHUP)) {
        status = core_recv(ctx, conn);
        if (status != FC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return;
        }
    }

    if (events & EPOLLOUT) {
        status = core_send(ctx, conn);
        if (status != FC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return;
        }
    }
}

rstatus_t
core_start(struct context *ctx)
{
    rstatus_t status;

    ctx->ep = -1;
    ctx->nevent = 1024;
    ctx->max_timeout = -1;
    ctx->timeout = ctx->max_timeout;
    ctx->event = NULL;

    status = event_init(ctx, 1024);
    if (status != FC_OK) {
        return status;
    }

    status = server_listen(ctx);
    if (status != FC_OK) {
        return status;
    }

    return FC_OK;
}

void
core_stop(struct context *ctx)
{
}

rstatus_t
core_loop(struct context *ctx)
{
    int i, nsd;

    nsd = event_wait(ctx->ep, ctx->event, ctx->nevent, ctx->timeout);
    if (nsd < 0) {
        return nsd;
    }

    for (i = 0; i < nsd; i++) {
        struct epoll_event *ev = &ctx->event[i];

        core_core(ctx, ev->data.ptr, ev->events);
    }

    return FC_OK;
}

