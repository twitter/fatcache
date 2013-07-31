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

#ifndef _FC_MESSAGE_H_
#define _FC_MESSAGE_H_

#include <fc_core.h>

typedef void (*msg_parse_t)(struct msg *);

#define MSG_CODEC(ACTION)                                \
    ACTION( UNKNOWN,            ""/* unknown */        ) \
    ACTION( REQ_GET,            "get  "                ) \
    ACTION( REQ_GETS,           "gets "                ) \
    ACTION( REQ_DELETE,         "delete "              ) \
    ACTION( REQ_CAS,            "cas "                 ) \
    ACTION( REQ_SET,            "set "                 ) \
    ACTION( REQ_ADD,            "add "                 ) \
    ACTION( REQ_REPLACE,        "replace "             ) \
    ACTION( REQ_APPEND,         "append  "             ) \
    ACTION( REQ_PREPEND,        "prepend "             ) \
    ACTION( REQ_INCR,           "incr "                ) \
    ACTION( REQ_DECR,           "decr "                ) \
    ACTION( REQ_VERSION,        "version "             ) \
    ACTION( REQ_QUIT,           "quit "                ) \
    ACTION( RSP_NUM,            "" /* na */            ) \
    ACTION( RSP_VALUE,          "VALUE "               ) \
    ACTION( RSP_END,            "END\r\n"              ) \
    ACTION( RSP_STORED,         "STORED\r\n"           ) \
    ACTION( RSP_NOT_STORED,     "NOT_STORED\r\n"       ) \
    ACTION( RSP_EXISTS,         "EXISTS\r\n"           ) \
    ACTION( RSP_NOT_FOUND,      "NOT_FOUND\r\n"        ) \
    ACTION( RSP_DELETED,        "DELETED\r\n"          ) \
    ACTION( RSP_CLIENT_ERROR,   "CLIENT_ERROR "        ) \
    ACTION( RSP_SERVER_ERROR,   "SERVER_ERROR "        ) \
    ACTION( RSP_VERSION,        "VERSION fatcache\r\n" ) \
    ACTION( CRLF,               "\r\n" /* empty */     ) \
    ACTION( EMPTY,              "" /* empty */         ) \

#define DEFINE_ACTION(_hash, _name) MSG_##_hash,
typedef enum msg_type {
    MSG_CODEC( DEFINE_ACTION )
    MSG_SENTINEL
} msg_type_t;
#undef DEFINE_ACTION

typedef enum msg_parse_result {
    MSG_PARSE_OK,                         /* parsing ok */
    MSG_PARSE_ERROR,                      /* parsing error */
    MSG_PARSE_REPAIR,                     /* more to parse -> repair parsed & unparsed data */
    MSG_PARSE_FRAGMENT,                   /* multi-vector request -> fragment */
    MSG_PARSE_AGAIN,                      /* incomplete -> parse again */
} msg_parse_result_t;

struct msg {
    TAILQ_ENTRY(msg)     c_tqe;           /* link in connection q */
    TAILQ_ENTRY(msg)     m_tqe;           /* link in send q / free q */

    uint64_t             id;              /* message id */
    struct msg           *peer;           /* message peer */
    struct conn          *owner;          /* message connection owner */

    struct mhdr          mhdr;            /* message mbuf header */
    uint32_t             mlen;            /* message length */

    int                  state;           /* current parser state */
    uint8_t              *pos;            /* parser position marker */
    uint8_t              *token;          /* token marker */

    msg_parse_t          parser;          /* message parser */
    msg_parse_result_t   result;          /* message parsing result */

    msg_type_t           type;            /* message type */

    uint8_t              *key_start;      /* key start */
    uint8_t              *key_end;        /* key end */

    uint32_t             hash;            /* key hash */
    uint8_t              md[20];          /* key message digest */

    uint32_t             flags;           /* flags */
    uint32_t             expiry;          /* expiry */
    uint32_t             vlen;            /* value length */
    uint32_t             rvlen;           /* running vlen used by parsing fsa */
    uint8_t              *value;          /* value marker */
    uint64_t             cas;             /* cas */
    uint64_t             num;             /* number */

    struct msg           *frag_owner;     /* owner of fragment message */
    uint32_t             nfrag;           /* # fragment */
    uint64_t             frag_id;         /* id of fragmented message */

    err_t                err;             /* errno on error? */
    unsigned             error:1;         /* error? */
    unsigned             request:1;       /* request? or response? */
    unsigned             quit:1;          /* quit request? */
    unsigned             noreply:1;       /* noreply? */
    unsigned             done:1;          /* done? */
    unsigned             first_fragment:1;/* first fragment? */
    unsigned             last_fragment:1; /* last fragment? */
    unsigned             swallow:1;       /* swallow response? */
};

TAILQ_HEAD(msg_tqh, msg);

bool msg_empty(struct msg *msg);
rstatus_t msg_recv(struct context *ctx, struct conn *conn);
rstatus_t msg_send(struct context *ctx, struct conn *conn);

struct msg *req_get(struct conn *conn);
void req_put(struct msg *msg);
struct msg *req_recv_next(struct context *ctx, struct conn *conn, bool alloc);

struct msg *msg_get(struct conn *conn, bool request);
void msg_put(struct msg *msg);

void msg_init(void);
void msg_deinit(void);

struct msg *rsp_get(struct conn *conn);
void rsp_put(struct msg *msg);

bool req_done(struct conn *conn, struct msg *msg);
struct msg *rsp_send_next(struct context *ctx, struct conn *conn);

void req_enqueue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_dequeue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void rsp_send_done(struct context *ctx, struct conn *conn, struct msg *msg);
void req_recv_done(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *nmsg);

void req_process_error(struct context *ctx, struct conn *conn, struct msg *msg, int err);


void rsp_send_status(struct context *ctx, struct conn *conn, struct msg *msg, msg_type_t rsp_type);
void rsp_send_error(struct context *ctx, struct conn *conn, struct msg *msg, msg_type_t rsp_type, int err);
void rsp_send_value(struct context *ctx, struct conn *conn, struct msg *msg, struct item *it, uint64_t cas);
void rsp_send_num(struct context *ctx, struct conn *conn, struct msg *msg, struct item *it);

#endif
