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

#ifndef _FC_CONNECTION_H_
#define _FC_CONNECTION_H_

typedef rstatus_t (*conn_recv_t)(struct context *, struct conn*);
typedef rstatus_t (*conn_send_t)(struct context *, struct conn*);

typedef struct msg* (*conn_send_next_t)(struct context *, struct conn *);
typedef void (*conn_send_done_t)(struct context *, struct conn *, struct msg *);

typedef void (*conn_close_t)(struct context *, struct conn *);
typedef bool (*conn_active_t)(struct conn *);

struct conn {
    int                sd;             /* socket descriptor */
    TAILQ_ENTRY(conn)  tqe;            /* link in free q */

    struct msg_tqh     omsg_q;         /* outstanding request Q */
    struct msg         *rmsg;          /* current request being rcvd */
    struct msg         *smsg;          /* current response being sent */

    conn_recv_t        recv;           /* recv (read) handler */
    conn_send_t        send;           /* send (write) handler */
    conn_close_t       close;          /* close handler */
    conn_active_t      active;         /* active? handler */

    size_t             recv_bytes;     /* received (read) bytes */
    size_t             send_bytes;     /* sent (written) bytes */

    uint32_t           events;         /* connection io events */
    err_t              err;            /* connection errno */
    unsigned           recv_active:1;  /* recv active? */
    unsigned           recv_ready:1;   /* recv ready? */
    unsigned           send_active:1;  /* send active? */
    unsigned           send_ready:1;   /* send ready? */

    unsigned           client:1;       /* client? */
    unsigned           eof:1;          /* eof? aka passive close? */
    unsigned           done:1;         /* done? aka close? */
    unsigned           noreply:1;      /* noreply? */
};

TAILQ_HEAD(conn_tqh, conn);

void conn_init(void);
void conn_deinit(void);

ssize_t conn_recv(struct conn *conn, void *buf, size_t size);
ssize_t conn_sendv(struct conn *conn, struct array *sendv, size_t nsend);

struct conn *conn_get(int sd, bool client);
void conn_put(struct conn *c);

#endif
