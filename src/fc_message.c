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

#include <sys/uio.h>

#include <fc_core.h>

#if (IOV_MAX > 128)
#define FC_IOV_MAX 128
#else
#define FC_IOV_MAX IOV_MAX
#endif

#define DEFINE_ACTION(_hash, _name) string(_name),
struct string msg_strings[] = {
    MSG_CODEC( DEFINE_ACTION )
    null_string
};
#undef DEFINE_ACTION

static uint64_t msg_id;          /* message id counter */
static uint64_t frag_id;         /* fragment id counter */
static uint32_t nfree_msgq;      /* # free msg q */
static struct msg_tqh free_msgq; /* free msg q */

static struct msg *
_msg_get(void)
{
    struct msg *msg;

    if (!TAILQ_EMPTY(&free_msgq)) {
        ASSERT(nfree_msgq > 0);

        msg = TAILQ_FIRST(&free_msgq);
        nfree_msgq--;
        TAILQ_REMOVE(&free_msgq, msg, m_tqe);
        goto done;
    }

    msg = fc_alloc(sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }

done:
    /* c_tqe and m_tqe are left uninitialized */
    msg->id = ++msg_id;
    msg->peer = NULL;
    msg->owner = NULL;

    STAILQ_INIT(&msg->mhdr);
    msg->mlen = 0;

    msg->state = 0;
    msg->pos = NULL;
    msg->token = NULL;

    msg->parser = memcache_parse_req;
    msg->result = MSG_PARSE_OK;

    msg->type = MSG_UNKNOWN;

    msg->key_start = NULL;
    msg->key_end = NULL;
    msg->hash = 0;
    /* md[] is left uninitialized */

    msg->flags = 0;
    msg->expiry = 0;
    msg->vlen = 0;
    msg->rvlen = 0;
    msg->value = NULL;
    msg->cas = 0;
    msg->num = 0;

    msg->frag_owner = NULL;
    msg->nfrag = 0;
    msg->frag_id = 0;

    msg->err = 0;
    msg->error = 0;
    msg->request = 0;
    msg->quit = 0;
    msg->noreply = 0;
    msg->done = 0;
    msg->first_fragment = 0;
    msg->last_fragment = 0;
    msg->swallow = 0;

    return msg;
}

struct msg *
msg_get(struct conn *conn, bool request)
{
    struct msg *msg;

    msg = _msg_get();
    if (msg == NULL) {
        return NULL;
    }

    msg->owner = conn;
    msg->request = request ? 1 : 0;

    log_debug(LOG_VVERB, "get msg %p id %"PRIu64" request %d owner sd %d",
              msg, msg->id, msg->request, conn->sd);

    return msg;
}

static void
msg_free(struct msg *msg)
{
    ASSERT(STAILQ_EMPTY(&msg->mhdr));

    log_debug(LOG_VVERB, "free msg %p id %"PRIu64"", msg, msg->id);
    fc_free(msg);
}

void
msg_put(struct msg *msg)
{
    log_debug(LOG_VVERB, "put msg %p id %"PRIu64"", msg, msg->id);

    while (!STAILQ_EMPTY(&msg->mhdr)) {
        struct mbuf *mbuf = STAILQ_FIRST(&msg->mhdr);
        mbuf_remove(&msg->mhdr, mbuf);
        mbuf_put(mbuf);
    }

    nfree_msgq++;
    TAILQ_INSERT_HEAD(&free_msgq, msg, m_tqe);
}

bool
msg_empty(struct msg *msg)
{
    return msg->mlen == 0 ? true : false;
}

static rstatus_t
msg_parsed(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg *nmsg;
    struct mbuf *mbuf, *nbuf;

    mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    if (msg->pos == mbuf->last) {
        /* no more data to parse */
        req_recv_done(ctx, conn, msg, NULL);
        return FC_OK;
    }

    /*
     * Input mbuf has un-parsed data. Split mbuf of the current message msg
     * into (mbuf, nbuf), where mbuf is the portion of the message that has
     * been parsed and nbuf is the portion of the message that is un-parsed.
     * Parse nbuf as a new message nmsg in the next iteration.
     */
    nbuf = mbuf_split(&msg->mhdr, msg->pos, NULL, NULL);
    if (nbuf == NULL) {
        return FC_ENOMEM;
    }

    nmsg = msg_get(msg->owner, msg->request);
    if (nmsg == NULL) {
        mbuf_put(nbuf);
        return FC_ENOMEM;
    }
    mbuf_insert(&nmsg->mhdr, nbuf);
    nmsg->pos = nbuf->pos;

    /* update length of current (msg) and new message (nmsg) */
    nmsg->mlen = mbuf_length(nbuf);
    msg->mlen -= nmsg->mlen;

    req_recv_done(ctx, conn, msg, nmsg);

    return FC_OK;
}

static rstatus_t
msg_fragment(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;  /* return status */
    struct msg *nmsg;  /* new message */
    struct mbuf *nbuf; /* new mbuf */

    ASSERT(msg->request);

    nbuf = mbuf_split(&msg->mhdr, msg->pos, memcache_pre_splitcopy, msg);
    if (nbuf == NULL) {
        return FC_ENOMEM;
    }

    status = memcache_post_splitcopy(msg);
    if (status != FC_OK) {
        mbuf_put(nbuf);
        return status;
    }

    nmsg = msg_get(msg->owner, msg->request);
    if (nmsg == NULL) {
        mbuf_put(nbuf);
        return FC_ENOMEM;
    }
    mbuf_insert(&nmsg->mhdr, nbuf);
    nmsg->pos = nbuf->pos;

    /* update length of current (msg) and new message (nmsg) */
    nmsg->mlen = mbuf_length(nbuf);
    msg->mlen -= nmsg->mlen;

    /*
     * Attach unique fragment id to all fragments of the message vector. All
     * fragments of the message, including the first fragment point to the
     * first fragment through the frag_owner pointer. The first_fragment and
     * last_fragment identify first and last fragment respectively.
     *
     * For example, a message vector given below is split into 3 fragments:
     *  'get key1 key2 key3\r\n'
     *
     *   +--------------+
     *   |  msg vector  |
     *   |(original msg)|
     *   +--------------+
     *
     *       frag_owner         frag_owner
     *     /-----------+      /------------+
     *     |           |      |            |
     *     |           v      v            |
     *   +--------------------+     +---------------------+
     *   |   frag_id = 10     |     |   frag_id = 10      |
     *   | first_fragment = 1 |     |  first_fragment = 0 |
     *   | last_fragment = 0  |     |  last_fragment = 0  |
     *   |     nfrag = 3      |     |      nfrag = 0      |
     *   +--------------------+     +---------------------+
     *               ^
     *               |  frag_owner
     *               \-------------+
     *                             |
     *                             |
     *                  +---------------------+
     *                  |   frag_id = 10      |
     *                  |  first_fragment = 0 |
     *                  |  last_fragment = 1  |
     *                  |      nfrag = 0      |
     *                  +---------------------+
     *
     *
     */
    if (msg->frag_id == 0) {
        msg->frag_id = ++frag_id;
        msg->first_fragment = 1;
        msg->nfrag = 1;
        msg->frag_owner = msg;
    }
    nmsg->frag_id = msg->frag_id;
    msg->last_fragment = 0;
    nmsg->last_fragment = 1;
    nmsg->frag_owner = msg->frag_owner;
    msg->frag_owner->nfrag++;

    req_recv_done(ctx, conn, msg, nmsg);

    return FC_OK;
}

static rstatus_t
msg_repair(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct mbuf *nbuf;

    nbuf = mbuf_split(&msg->mhdr, msg->pos, NULL, NULL);
    if (nbuf == NULL) {
        return FC_ENOMEM;
    }
    mbuf_insert(&msg->mhdr, nbuf);
    msg->pos = nbuf->pos;

    return FC_OK;
}

static rstatus_t
msg_parse(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;

    if (msg_empty(msg)) {
        /* no data to parse */
        req_recv_done(ctx, conn, msg, NULL);
        return FC_OK;
    }

    msg->parser(msg);

    switch (msg->result) {
    case MSG_PARSE_OK:
        status = msg_parsed(ctx, conn, msg);
        break;

    case MSG_PARSE_FRAGMENT:
        status = msg_fragment(ctx, conn, msg);
        break;

    case MSG_PARSE_REPAIR:
        status = msg_repair(ctx, conn, msg);
        break;

    case MSG_PARSE_AGAIN:
        status = FC_OK;
        break;

    default:
        status = FC_ERROR;
        conn->err = errno;
        break;
    }

    return conn->err != 0 ? FC_ERROR : status;
}

static rstatus_t
msg_recv_chain(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;
    struct msg *nmsg;
    struct mbuf *mbuf;
    size_t msize;
    ssize_t n;

    mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    if (mbuf == NULL || mbuf_full(mbuf)) {
        mbuf = mbuf_get();
        if (mbuf == NULL) {
            return FC_ENOMEM;
        }
        mbuf_insert(&msg->mhdr, mbuf);
        msg->pos = mbuf->pos;
    }
    ASSERT(mbuf->end - mbuf->last > 0);

    msize = mbuf_size(mbuf);

    n = conn_recv(conn, mbuf->last, msize);
    if (n < 0) {
        if (n == FC_EAGAIN) {
            return FC_OK;
        }
        return FC_ERROR;
    }

    ASSERT((mbuf->last + n) <= mbuf->end);
    mbuf->last += n;
    msg->mlen += (uint32_t)n;

    for (;;) {
        status = msg_parse(ctx, conn, msg);
        if (status != FC_OK) {
            return status;
        }

        /* get next request to parse */
        nmsg = req_recv_next(ctx, conn, false);
        if (nmsg == NULL || nmsg == msg) {
            /* no more data to parse */
            break;
        }

        msg = nmsg;
    }

    return FC_OK;
}

rstatus_t
msg_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg;

    ASSERT(conn->client);
    ASSERT(conn->recv_active);

    conn->recv_ready = 1;
    do {
        msg = req_recv_next(ctx, conn, true);
        if (msg == NULL) {
            return FC_OK;
        }

        status = msg_recv_chain(ctx, conn, msg);
        if (status != FC_OK) {
            return status;
        }
    } while (conn->recv_ready);

    return FC_OK;
}

static rstatus_t
msg_send_chain(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg_tqh send_msgq;            /* send msg q */
    struct msg *nmsg;                    /* next msg */
    struct mbuf *mbuf, *nbuf;            /* current and next mbuf */
    size_t mlen;                         /* current mbuf data length */
    struct iovec *ciov, iov[FC_IOV_MAX]; /* current iovec */
    struct array sendv;                  /* send iovec */
    size_t nsend, nsent;                 /* bytes to send; bytes sent */
    size_t limit;                        /* bytes to send limit */
    ssize_t n;                           /* bytes sent by sendv */

    TAILQ_INIT(&send_msgq);

    array_set(&sendv, iov, sizeof(iov[0]), FC_IOV_MAX);

    /* preprocess - build iovec */

    nsend = 0;
    /*
     * readv() and writev() returns EINVAL if the sum of the iov_len values
     * overflows an ssize_t value Or, the vector count iovcnt is less than
     * zero or greater than the permitted maximum.
     */
    limit = SSIZE_MAX;

    for (;;) {
        ASSERT(conn->smsg == msg);

        TAILQ_INSERT_TAIL(&send_msgq, msg, m_tqe);

        for (mbuf = STAILQ_FIRST(&msg->mhdr);
             mbuf != NULL && array_n(&sendv) < FC_IOV_MAX && nsend < limit;
             mbuf = nbuf) {
            nbuf = STAILQ_NEXT(mbuf, next);

            if (mbuf_empty(mbuf)) {
                continue;
            }

            mlen = mbuf_length(mbuf);
            if ((nsend + mlen) > limit) {
                mlen = limit - nsend;
            }

            ciov = array_push(&sendv);
            ciov->iov_base = mbuf->pos;
            ciov->iov_len = mlen;

            nsend += mlen;
        }

        if (array_n(&sendv) >= FC_IOV_MAX || nsend >= limit) {
            break;
        }

        msg = rsp_send_next(ctx, conn);
        if (msg == NULL) {
            break;
        }
    }

    ASSERT(!TAILQ_EMPTY(&send_msgq));

    conn->smsg = NULL;

    if (nsend != 0) {
        n = conn_sendv(conn, &sendv, nsend);
    } else {
        NOT_REACHED();
        n = 0;
    }
    nsent = n > 0 ? (size_t)n : 0;

    /* postprocess - process sent messages in send_msgq */

    for (msg = TAILQ_FIRST(&send_msgq); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, m_tqe);

        TAILQ_REMOVE(&send_msgq, msg, m_tqe);

        if (nsent == 0) {
            if (msg->mlen == 0) {
                rsp_send_done(ctx, conn, msg);
            }
            continue;
        }

        /* adjust mbufs of the sent message */
        for (mbuf = STAILQ_FIRST(&msg->mhdr); mbuf != NULL; mbuf = nbuf) {
            nbuf = STAILQ_NEXT(mbuf, next);

            if (mbuf_empty(mbuf)) {
                continue;
            }

            mlen = mbuf_length(mbuf);
            if (nsent < mlen) {
                /* mbuf was sent partially; process remaining bytes later */
                mbuf->pos += nsent;
                ASSERT(mbuf->pos < mbuf->last);
                nsent = 0;
                break;
            }

            /* mbuf was sent completely; mark it empty */
            mbuf->pos = mbuf->last;
            nsent -= mlen;
        }

        /* message has been sent completely, finalize it */
        if (mbuf == NULL) {
            rsp_send_done(ctx, conn, msg);
        }
    }

    ASSERT(TAILQ_EMPTY(&send_msgq));

    if (n >= 0) {
        return FC_OK;
    }

    return (n == FC_EAGAIN) ? FC_OK : FC_ERROR;
}

rstatus_t
msg_send(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg;

    ASSERT(conn->client);
    ASSERT(conn->send_active);

    conn->send_ready = 1;
    do {
        msg = rsp_send_next(ctx, conn);
        if (msg == NULL) {
            /* nothing to send */
            return FC_OK;
        }

        status = msg_send_chain(ctx, conn, msg);
        if (status != FC_OK) {
            return status;
        }
    } while (conn->send_ready);

    return FC_OK;
}

void
msg_init(void)
{
    log_debug(LOG_DEBUG, "msg size %d", sizeof(struct msg));
    msg_id = 0;
    frag_id = 0;
    nfree_msgq = 0;
    TAILQ_INIT(&free_msgq);
}

void
msg_deinit(void)
{
    struct msg *msg, *nmsg;

    for (msg = TAILQ_FIRST(&free_msgq); msg != NULL;
         msg = nmsg, nfree_msgq--) {
        ASSERT(nfree_msgq > 0);
        nmsg = TAILQ_NEXT(msg, m_tqe);
        msg_free(msg);
    }
    ASSERT(nfree_msgq == 0);
}
