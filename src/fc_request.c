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

#include <fc_core.h>
#include <fc_event.h>

extern struct string msg_strings[];

struct msg *
req_get(struct conn *conn)
{
    struct msg *msg;

    msg = msg_get(conn, true);
    if (msg == NULL) {
        conn->err = errno;
    }

    return msg;
}

void
req_put(struct msg *msg)
{
    struct msg *pmsg; /* peer message (response) */

    ASSERT(msg->request);

    pmsg = msg->peer;
    if (pmsg != NULL) {
        ASSERT(!pmsg->request && pmsg->peer == msg);
        msg->peer = NULL;
        pmsg->peer = NULL;
        rsp_put(pmsg);
    }

    msg_put(msg);
}

/*
 * Return true if request is done, false otherwise
 */
bool
req_done(struct conn *conn, struct msg *msg)
{
    if (!msg->done) {
        return false;
    }

    return true;
}

void
req_enqueue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg)
{
    ASSERT(msg->request);
    ASSERT(!msg->noreply);

    TAILQ_INSERT_TAIL(&conn->omsg_q, msg, c_tqe);
}

void
req_dequeue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg)
{
    ASSERT(msg->request);
    ASSERT(!msg->noreply);

    TAILQ_REMOVE(&conn->omsg_q, msg, c_tqe);
}

struct msg *
req_recv_next(struct context *ctx, struct conn *conn, bool alloc)
{
    struct msg *msg;

    if (conn->eof) {
        msg = conn->rmsg;

        /* client sent eof before sending the entire request */
        if (msg != NULL) {
            conn->rmsg = NULL;

            ASSERT(msg->peer == NULL);
            ASSERT(msg->request && !msg->done);

            log_error("eof c %d discarding incomplete req %"PRIu64" len "
                      "%"PRIu32"", conn->sd, msg->id, msg->mlen);

            req_put(msg);
        }

#if 0
        /*
         * TCP half-close enables the client to terminate its half of the
         * connection (i.e. the client no longer sends data), but it still
         * is able to receive data from the proxy. The proxy closes its
         * half (by sending the second FIN) when the client has no
         * outstanding requests
         */
        if (!conn->active(conn)) {
            conn->done = 1;
            log_debug(LOG_INFO, "c %d is done", conn->sd);
        }
#endif

        return NULL;
    }

    msg = conn->rmsg;
    if (msg != NULL) {
        ASSERT(msg->request);
        return msg;
    }

    if (!alloc) {
        return NULL;
    }

    msg = req_get(conn);
    if (msg != NULL) {
        conn->rmsg = msg;
    }

    return msg;
}

static bool
req_filter(struct context *ctx, struct conn *conn, struct msg *msg)
{
    if (msg_empty(msg)) {
        ASSERT(conn->rmsg == NULL);
        log_debug(LOG_VERB, "filter empty req %"PRIu64" from c %d", msg->id,
                  conn->sd);
        req_put(msg);
        return true;
    }

    /*
     * Handle "quit\r\n", which is the protocol way of doing a
     * passive close
     */
    if (msg->quit) {
        ASSERT(conn->rmsg == NULL);
        log_debug(LOG_INFO, "filter quit req %"PRIu64" from c %d", msg->id,
                  conn->sd);
        conn->eof = 1;
        conn->recv_ready = 0;
        req_put(msg);
        return true;
    }

    return false;
}

static void
req_process_get(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct itemx *itx;
    struct item *it;

    itx = itemx_getx(msg->hash, msg->md);
    if (itx == NULL) {
        msg_type_t type;

        /*
         * On a miss, we send a "END\r\n" response, unless the request
         * is an intermediate fragment in a fragmented request.
         */
        if (msg->frag_id == 0 || msg->last_fragment) {
            type = MSG_RSP_END;
        } else {
            type = MSG_EMPTY;
        }

        rsp_send_status(ctx, conn, msg, type);
        return;
    }

    /*
     * On a hit, we read the item with address [sid, offset] and respond
     * with item value if the item hasn't expired yet.
     */
    it = slab_read_item(itx->sid, itx->offset);
    if (it == NULL) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, errno);
        return;
    }
    if (item_expired(it)) {
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return;
    }

    rsp_send_value(ctx, conn, msg, it, itx->cas);
}

static void
req_process_delete(struct context *ctx, struct conn *conn, struct msg *msg)
{
    bool found;

    found = itemx_removex(msg->hash, msg->md);
    if (!found) {
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return;
    }

    rsp_send_status(ctx, conn, msg, MSG_RSP_DELETED);
}

static void
req_process_set(struct context *ctx, struct conn *conn, struct msg *msg)
{
    uint8_t *key, nkey, cid;
    struct item *it;

    key = msg->key_start;
    nkey = (uint8_t)(msg->key_end - msg->key_start);

    cid = item_slabcid(nkey, msg->vlen);
    if (cid == SLABCLASS_INVALID_ID) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_CLIENT_ERROR, EINVAL);
        return;
    }

    itemx_removex(msg->hash, msg->md);

    it = item_get(key, nkey, cid, msg->vlen, time_reltime(msg->expiry),
                  msg->flags, msg->md, msg->hash);
    if (it == NULL) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, ENOMEM);
        return;
    }

    mbuf_copy_to(&msg->mhdr, msg->value, item_data(it), msg->vlen);

    rsp_send_status(ctx, conn, msg, MSG_RSP_STORED);
}

static void
req_process_add(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct itemx *itx;

    /* add, adds only if the mapping is not present */
    itx = itemx_getx(msg->hash, msg->md);
    if (itx != NULL) {
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_STORED);
        return;
    }

    req_process_set(ctx, conn, msg);
}

static void
req_process_replace(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct itemx *itx;

    /*  replace, only replaces if the mapping is present */
    itx = itemx_getx(msg->hash, msg->md);
    if (itx == NULL) {
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_STORED);
        return;
    }

    req_process_set(ctx, conn, msg);
}

static void
req_process_version(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rsp_send_status(ctx, conn, msg, MSG_RSP_VERSION);
}

static void
req_process_cas(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct itemx *itx;

    itx = itemx_getx(msg->hash, msg->md);
    if (itx == NULL) {
        /*
         * NOT_FOUND indicates that the item you are trying to store
         * with a cas does not exist.
         */
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return;
    }

    if (itx->cas != msg->cas) {
        /*
         * EXISTS indicates that the item you are trying to store with
         * a cas has been modified since you last fetched it.
         */
        rsp_send_status(ctx, conn, msg, MSG_RSP_EXISTS);
        return;
    }

    req_process_set(ctx, conn, msg);
}

static void
req_process_concat(struct context *ctx, struct conn *conn, struct msg *msg)
{
    uint8_t *key, nkey, cid;
    struct item *oit, *it;
    uint32_t ndata;
    struct itemx *itx;

    key = msg->key_start;
    nkey = (uint8_t)(msg->key_end - msg->key_start);

    /* 1). look up existing itemx */
    itx = itemx_getx(msg->hash, msg->md);
    if (itx == NULL) {
        /* 2a). miss -> return NOT_STORED */
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_STORED);
        return;
    }

    /* 2b). hit -> read existing item into oit */
    oit = slab_read_item(itx->sid, itx->offset);
    if (oit == NULL) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, errno);
        return;
    }
    if (item_expired(oit)) {
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_STORED);
        return;
    }

    ndata = msg->vlen + oit->ndata;
    cid = item_slabcid(nkey, ndata);
    if (cid == SLABCLASS_INVALID_ID) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_CLIENT_ERROR, EINVAL);
        return;
    }

    /* 3). remove existing itemx of oit */
    itemx_removex(msg->hash, msg->md);

    /* 4). alloc new item that can hold ndata worth of bytes */
    it = item_get(key, nkey, cid, ndata, time_reltime(msg->expiry),
                  msg->flags, msg->md, msg->hash);
    if (it == NULL) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, ENOMEM);
        return;
    }

    /* 5). copy data from msg to head or tail of new item it */
    switch (msg->type) {

    case MSG_REQ_PREPEND:
        mbuf_copy_to(&msg->mhdr, msg->value, item_data(it), msg->vlen);
        fc_memcpy(item_data(it) + msg->vlen, item_data(oit), oit->ndata);
        break;

    case MSG_REQ_APPEND:
        fc_memcpy(item_data(it), item_data(oit), oit->ndata);
        mbuf_copy_to(&msg->mhdr, msg->value, item_data(it) + oit->ndata, msg->vlen);
        break;

    default:
        NOT_REACHED();
    }

    rsp_send_status(ctx, conn, msg, MSG_RSP_STORED);
}

static void
req_process_num(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;
    uint8_t *key, nkey, cid;
    struct item *it;
    struct itemx *itx;
    uint64_t cnum, nnum;
    char numstr[FC_UINT64_MAXLEN];
    int n;

    key = msg->key_start;
    nkey = (uint8_t)(msg->key_end - msg->key_start);

    /* 1). look up existing itemx */
    itx = itemx_getx(msg->hash, msg->md);
    if (itx == NULL) {
        /* 2a). miss -> return NOT_FOUND */
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return;
    }

    /* 2b). hit -> read existing item into it */
    it = slab_read_item(itx->sid, itx->offset);
    if (it == NULL) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, errno);
        return;
    }
    if (item_expired(it)) {
        rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return;
    }

    /* 3). sanity check item data to be a number */
    status = fc_atou64(item_data(it), it->ndata, &cnum);
    if (status != FC_OK) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_CLIENT_ERROR, EINVAL);
        return;
    }

    /* 4). remove existing itemx of it */
    itemx_removex(msg->hash, msg->md);

    /* 5). compute the new incr/decr number nnum and numstr */
    if (msg->type == MSG_REQ_INCR) {
        nnum = cnum + msg->num;
    } else {
        if (cnum < msg->num) {
            nnum = 0;
        } else {
            nnum = cnum - msg->num;
        }
    }
    n = fc_scnprintf(numstr, sizeof(numstr), "%"PRIu64"", nnum);

    /* 6). alloc new item that can hold n worth of bytes */
    cid = item_slabcid(nkey, n);
    ASSERT(cid != SLABCLASS_INVALID_ID);

    it = item_get(key, nkey, cid, n, time_reltime(msg->expiry), msg->flags,
                   msg->md, msg->hash);
    if (it == NULL) {
        rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, ENOMEM);
        return;
    }

    /* 7). copy numstr to it */
    fc_memcpy(item_data(it), numstr, n);

    rsp_send_num(ctx, conn, msg, it);
}

void
req_process_error(struct context *ctx, struct conn *conn, struct msg *msg,
                  int err)
{
    rstatus_t status;

    /* mark request as done and error */
    msg->done = 1;
    msg->error = 1;
    msg->err = err != 0 ? err : errno;

    log_debug(LOG_INFO, "process req %"PRIu64" len %"PRIu32" type %d on sd %d "
              "failed: %s", msg->id, msg->mlen, msg->type, conn->sd,
              strerror(msg->err));

    /* noreply request don't expect any response */
    if (msg->noreply) {
        req_put(msg);
        return;
    }

    if (req_done(conn, TAILQ_FIRST(&conn->omsg_q))) {
        status = event_add_out(ctx->ep, conn);
        if (status != FC_OK) {
            conn->err = errno;
        }
    }
}

static void
req_process(struct context *ctx, struct conn *conn, struct msg *msg)
{
    uint8_t *key;
    size_t keylen;

    ASSERT(msg->request);
    ASSERT(msg->type >= MSG_REQ_GET && msg->type < MSG_REQ_QUIT);

    /* enqueue request into outq, if response is expected */
    if (!msg->noreply) {
        req_enqueue_omsgq(ctx, conn, msg);
    }

    ASSERT(msg->key_end > msg->key_start);
    key = msg->key_start;
    keylen = msg->key_end - msg->key_start;

    /*
     * Compute message digest followed by hash over the given request
     * key. Since this computation is expensive we trade memory over
     * CPU by storing the result in msg struct and doing this computation
     * only once over the lifetime of this request.
     */
    sha1(key, keylen, msg->md);
    msg->hash = sha1_hash(msg->md);

    switch (msg->type) {
    case MSG_REQ_GET:
    case MSG_REQ_GETS:
        req_process_get(ctx, conn, msg);
        break;

    case MSG_REQ_DELETE:
        req_process_delete(ctx, conn, msg);
        break;

    case MSG_REQ_CAS:
        req_process_cas(ctx, conn, msg);
        break;

    case MSG_REQ_SET:
        req_process_set(ctx, conn, msg);
        break;

    case MSG_REQ_ADD:
        req_process_add(ctx, conn, msg);
        break;

    case MSG_REQ_REPLACE:
        req_process_replace(ctx, conn, msg);
        break;

    case MSG_REQ_VERSION:
        req_process_version(ctx, conn, msg);
        break;

    case MSG_REQ_APPEND:
    case MSG_REQ_PREPEND:
        req_process_concat(ctx, conn, msg);
        break;

    case MSG_REQ_INCR:
    case MSG_REQ_DECR:
        req_process_num(ctx, conn, msg);
        break;

    default:
        NOT_REACHED();
    }
}

void
req_recv_done(struct context *ctx, struct conn *conn, struct msg *msg,
              struct msg *nmsg)
{
    ASSERT(msg->request);
    ASSERT(msg->owner == conn);
    ASSERT(conn->rmsg == msg);
    ASSERT(nmsg == NULL || nmsg->request);

    /* enqueue next message (request), if any */
    conn->rmsg = nmsg;

    if (req_filter(ctx, conn, msg)) {
        return;
    }

    req_process(ctx, conn, msg);
}
