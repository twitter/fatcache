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
#include <fc_client.h>

extern struct settings settings;

static uint32_t nfree_connq;              /* # free conn q */
static struct conn_tqh free_connq;        /* free conn q */

static void conn_free(struct conn *conn);

void
conn_init(void)
{
    log_debug(LOG_DEBUG, "conn size %d", sizeof(struct conn));
    nfree_connq = 0;
    TAILQ_INIT(&free_connq);
}

void
conn_deinit(void)
{
    struct conn *conn, *nconn; /* current and next connection */

    for (conn = TAILQ_FIRST(&free_connq); conn != NULL;
         conn = nconn, nfree_connq--) {
        ASSERT(nfree_connq > 0);
        nconn = TAILQ_NEXT(conn, tqe);
        conn_free(conn);
    }
    ASSERT(nfree_connq == 0);
}

ssize_t
conn_recv(struct conn *conn, void *buf, size_t size)
{
    ssize_t n;

    ASSERT(buf != NULL);
    ASSERT(size > 0);
    ASSERT(conn->recv_ready);

    for (;;) {
        n = fc_read(conn->sd, buf, size);

        log_debug(LOG_VERB, "recv on sd %d %zd of %zu", conn->sd, n, size);

        if (n > 0) {
            if (n < (ssize_t) size) {
                conn->recv_ready = 0;
            }
            conn->recv_bytes += (size_t)n;
            return n;
        }

        if (n == 0) {
            conn->recv_ready = 0;
            conn->eof = 1;
            log_debug(LOG_INFO, "recv on sd %d eof rb %zu sb %zu", conn->sd,
                      conn->recv_bytes, conn->send_bytes);
            return n;
        }

        if (errno == EINTR) {
            log_debug(LOG_VERB, "recv on sd %d not ready - eintr", conn->sd);
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            conn->recv_ready = 0;
            log_debug(LOG_VERB, "recv on sd %d not ready - eagain", conn->sd);
            return FC_EAGAIN;
        } else {
            conn->recv_ready = 0;
            conn->err = errno;
            log_error("recv on sd %d failed: %s", conn->sd, strerror(errno));
            return FC_ERROR;
        }
    }

    NOT_REACHED();

    return FC_ERROR;
}

ssize_t
conn_sendv(struct conn *conn, struct array *sendv, size_t nsend)
{
    ssize_t n;

    ASSERT(array_n(sendv) > 0);
    ASSERT(nsend != 0);
    ASSERT(conn->send_ready);

    for (;;) {
        n = fc_writev(conn->sd, sendv->elem, sendv->nelem);

        log_debug(LOG_VERB, "sendv on sd %d %zd of %zu in %"PRIu32" buffers",
                  conn->sd, n, nsend, sendv->nelem);

        if (n > 0) {
            if (n < (ssize_t) nsend) {
                conn->send_ready = 0;
            }
            conn->send_bytes += (size_t)n;
            return n;
        }

        if (n == 0) {
            log_warn("sendv on sd %d returned zero", conn->sd);
            conn->send_ready = 0;
            return 0;
        }

        if (errno == EINTR) {
            log_debug(LOG_VERB, "sendv on sd %d not ready - eintr", conn->sd);
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            conn->send_ready = 0;
            log_debug(LOG_VERB, "sendv on sd %d not ready - eagain", conn->sd);
            return FC_EAGAIN;
        } else {
            conn->send_ready = 0;
            conn->err = errno;
            log_error("sendv on sd %d failed: %s", conn->sd, strerror(errno));
            return FC_ERROR;
        }
    }

    NOT_REACHED();

    return FC_ERROR;
}

static void
conn_free(struct conn *conn)
{
    log_debug(LOG_VVERB, "free conn %p", conn);
    fc_free(conn);
}

void
conn_put(struct conn *conn)
{
    ASSERT(conn->sd < 0);

    log_debug(LOG_VVERB, "put conn %p", conn);

    nfree_connq++;
    TAILQ_INSERT_HEAD(&free_connq, conn, tqe);
}

static struct conn *
_conn_get(void)
{
    struct conn *conn;

    if (!TAILQ_EMPTY(&free_connq)) {
        ASSERT(nfree_connq > 0);

        conn = TAILQ_FIRST(&free_connq);
        nfree_connq--;
        TAILQ_REMOVE(&free_connq, conn, tqe);
    } else {
        conn = fc_alloc(sizeof(*conn));
        if (conn == NULL) {
            return NULL;
        }
    }

    /* extra stuff */

    TAILQ_INIT(&conn->omsg_q);
    conn->rmsg = NULL;
    conn->smsg = NULL;

    conn->recv = NULL;
    conn->send = NULL;
    conn->close = NULL;
    conn->active = NULL;

    conn->send_bytes = 0;
    conn->recv_bytes = 0;

    conn->events = 0;
    conn->err = 0;
    conn->recv_active = 0;
    conn->recv_ready = 0;
    conn->send_active = 0;
    conn->send_ready = 0;

    conn->client = 0;
    conn->eof = 0;
    conn->done = 0;
    conn->noreply = 0;

    return conn;
}

struct conn *
conn_get(int sd, bool client)
{
    struct conn *c;

    c = _conn_get();
    if (c == NULL) {
        return NULL;
    }
    c->sd = sd;
    c->client = client ? 1 : 0;

    if (client) {
        c->recv = msg_recv;
        c->send = msg_send;
        c->close = client_close;
        c->active = client_active;
    } else {
        c->recv = server_recv;
        c->send = NULL;
        c->close = NULL;
        c->active = NULL;
    }

    log_debug(LOG_VVERB, "get conn %p c %d", c, c->sd);

    return c;
}
