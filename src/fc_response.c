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

extern struct string msg_strings[];

struct msg *
rsp_get(struct conn *conn)
{
    struct msg *msg;

    msg = msg_get(conn, false);
    if (msg == NULL) {
        conn->err = errno;
    }

    return msg;
}

void
rsp_put(struct msg *msg)
{
    ASSERT(!msg->request);
    ASSERT(msg->peer == NULL);
    msg_put(msg);
}

struct msg *
rsp_send_next(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg, *pmsg; /* response and peer request */

    pmsg = TAILQ_FIRST(&conn->omsg_q);
    if (pmsg == NULL || !pmsg->done) {
        /* nothing is outstanding, initiate close? */
        if (pmsg == NULL && conn->eof) {
            conn->done = 1;
            log_debug(LOG_INFO, "c %d is done", conn->sd);
        }

        status = event_del_out(ctx->ep, conn);
        if (status != FC_OK) {
            conn->err = errno;
        }

        return NULL;
    }

    msg = conn->smsg;
    if (msg != NULL) {
        ASSERT(!msg->request && msg->peer != NULL);
        ASSERT(req_done(conn, msg->peer));
        pmsg = TAILQ_NEXT(msg->peer, c_tqe);
    }

    if (pmsg == NULL || !pmsg->done) {
        conn->smsg = NULL;
        return NULL;
    }
    ASSERT(pmsg->request && !pmsg->swallow);

    msg = pmsg->peer;
    ASSERT(!msg->request);

    conn->smsg = msg;

    log_debug(LOG_VVERB, "send next rsp %"PRIu64" on c %d", msg->id, conn->sd);

    return msg;
}

void
rsp_send_done(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg *pmsg; /* peer message (request) */

    ASSERT(conn->smsg == NULL);

    log_debug(LOG_VVERB, "send done rsp %"PRIu64" on c %d", msg->id, conn->sd);

    pmsg = msg->peer;

    ASSERT(!msg->request && pmsg->request);
    ASSERT(pmsg->peer == msg);
    ASSERT(pmsg->done && !pmsg->swallow);

    req_dequeue_omsgq(ctx, conn, pmsg);

    req_put(pmsg);
}

void
rsp_send_status(struct context *ctx, struct conn *conn, struct msg *msg,
                msg_type_t rsp_type)
{
    rstatus_t status;   /* return status */
    struct msg *pmsg;   /* peer response */
    struct string *str; /* response string */

    ASSERT(rsp_type > MSG_RSP_NUM && rsp_type < MSG_SENTINEL);
    ASSERT(rsp_type != MSG_RSP_CLIENT_ERROR);
    ASSERT(rsp_type != MSG_RSP_SERVER_ERROR);

    if (msg->noreply) {
        req_put(msg);
        return;
    }

    pmsg = rsp_get(conn);
    if (pmsg == NULL) {
        req_process_error(ctx, conn, msg, ENOMEM);
        return;
    }

    ASSERT(msg->request);
    ASSERT(msg->peer == NULL);
    ASSERT(!msg->done);
    ASSERT(!pmsg->request);

    /* copy response string to pmsg mbuf */
    str = &msg_strings[rsp_type];
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /* mark response as done */
    msg->done = 1;
    msg->peer = pmsg;
    pmsg->peer = msg;

    status = event_add_out(ctx->ep, conn);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
}

void
rsp_send_error(struct context *ctx, struct conn *conn, struct msg *msg,
               msg_type_t rsp_type, int err)
{
    rstatus_t status;         /* return status */
    struct msg *pmsg;         /* peer response */
    struct string *str, pstr; /* response string */
    char *errstr;             /* error string */

    ASSERT(rsp_type == MSG_RSP_CLIENT_ERROR ||
           rsp_type == MSG_RSP_SERVER_ERROR);

    pmsg = rsp_get(conn);
    if (pmsg == NULL) {
        req_process_error(ctx, conn, msg, ENOMEM);
        return;
    }

    ASSERT(msg->request);
    ASSERT(msg->peer == NULL);
    ASSERT(!msg->done);
    ASSERT(!pmsg->request);

    /* copy response string to pmsg mbuf */
    str = &msg_strings[rsp_type];
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /* copy errno string to pmsg mbuf */
    errstr = err != 0 ? strerror(err) : "unknown";
    string_set_raw(&pstr, errstr);
    str = &pstr;
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /* copy crlf to pmsg mbuf */
    str = &msg_strings[MSG_CRLF];
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /* mark response as done */
    msg->done = 1;
    msg->peer = pmsg;
    pmsg->peer = msg;

    status = event_add_out(ctx->ep, conn);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
}

void
rsp_send_value(struct context *ctx, struct conn *conn, struct msg *msg,
               struct item *it, uint64_t cas)
{
    rstatus_t status;                   /* return status */
    struct msg *pmsg;                   /* peer response */
    struct string *str;                 /* response string */
    uint8_t num[FC_UINTMAX_MAXLEN + 1]; /* number string and single space */
    size_t n;                           /* returned bytes */

    pmsg = rsp_get(conn);
    if (pmsg == NULL) {
        req_process_error(ctx, conn, msg, ENOMEM);
        return;
    }

    ASSERT(msg->request);
    ASSERT(msg->peer == NULL);
    ASSERT(!msg->done);
    ASSERT(!pmsg->request);

    /* copy string "VALUE " to pmsg mbuf */
    str = &msg_strings[MSG_RSP_VALUE];
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /* copy key to pmsg mbuf */
    status = mbuf_copy_from(&pmsg->mhdr, item_key(it), it->nkey);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += it->nkey;

    /* copy flags as number string to pmsg mbuf */
    n = fc_scnprintf(num, sizeof(num), " %"PRIu32"", it->flags);
    status = mbuf_copy_from(&pmsg->mhdr, num, n);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += n;

    /* copy data length as number string to pmsg mbuf */
    n = fc_scnprintf(num, sizeof(num), " %"PRIu32"", it->ndata);
    status = mbuf_copy_from(&pmsg->mhdr, num, n);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += n;

    if (msg->type == MSG_REQ_GETS) {
        /* copy cas as number string to pmsg mbuf */
        n = fc_scnprintf(num, sizeof(num), " %"PRIu64"", cas);
        status = mbuf_copy_from(&pmsg->mhdr, num, n);
        if (status != FC_OK) {
            req_process_error(ctx, conn, msg, errno);
            return;
        }
        pmsg->mlen += n;
    }

    /* copy end of command header crlf to pmsg mbuf */
    str = &msg_strings[MSG_CRLF];
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /* copy data to pmsg mbuf */
    status = mbuf_copy_from(&pmsg->mhdr, item_data(it), it->ndata);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += it->ndata;

    /* copy end of dataa crlf to pmsg mbuf */
    str = &msg_strings[MSG_CRLF];
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /*
     * Copy "END\r\n" to pmsg mbuf, unless the request is an intermediate
     * fragment in a fragmented request.
     */
    if (msg->frag_id == 0 || msg->last_fragment) {
        str = &msg_strings[MSG_RSP_END];
        status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
        if (status != FC_OK) {
            req_process_error(ctx, conn, msg, errno);
            return;
        }
        pmsg->mlen += str->len;
    }

    /* mark response as done */
    msg->done = 1;
    msg->peer = pmsg;
    pmsg->peer = msg;

    status = event_add_out(ctx->ep, conn);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
}

void
rsp_send_num(struct context *ctx, struct conn *conn, struct msg *msg,
             struct item *it)
{
    rstatus_t status;   /* return status */
    struct msg *pmsg;   /* peer response */
    struct string *str; /* response string */

    pmsg = rsp_get(conn);
    if (pmsg == NULL) {
        req_process_error(ctx, conn, msg, ENOMEM);
        return;
    }

    ASSERT(msg->request);
    ASSERT(msg->peer == NULL);
    ASSERT(!msg->done);
    ASSERT(!pmsg->request);

    /* copy number string to pmsg mbuf */
    status = mbuf_copy_from(&pmsg->mhdr, item_data(it), it->ndata);
    if (status != FC_OK) {
        NOT_REACHED();
    }
    pmsg->mlen += it->ndata;

    /* copy crlf to pmsg mbuf */
    str = &msg_strings[MSG_CRLF];
    status = mbuf_copy_from(&pmsg->mhdr, str->data, str->len);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
    pmsg->mlen += str->len;

    /* mark response as done */
    msg->done = 1;
    msg->peer = pmsg;
    pmsg->peer = msg;

    status = event_add_out(ctx->ep, conn);
    if (status != FC_OK) {
        req_process_error(ctx, conn, msg, errno);
        return;
    }
}
