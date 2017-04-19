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

#ifndef _FC_CORE_H_
#define _FC_CORE_H_

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef HAVE_DEBUG_LOG
# define FC_DEBUG_LOG 1
#else
# define FC_DEBUG_LOG 0
#endif

#ifdef HAVE_ASSERT_PANIC
# define FC_ASSERT_PANIC 1
#else
# define FC_ASSERT_PANIC 0
#endif

#ifdef HAVE_ASSERT_LOG
# define FC_ASSERT_LOG 1
#else
# define FC_ASSERT_LOG 0
#endif

#ifdef HAVE_LITTLE_ENDIAN
# define FC_LITTLE_ENDIAN 1
#endif

#ifdef HAVE_BACKTRACE
#define FC_BACKTRACE 1
#endif

struct array;
struct context;
struct epoll_event;
struct conn;
struct conn_tqh;
struct msg;
struct msg_tqh;
struct mbuf;
struct mhdr;
struct item;
struct slab;
struct slabclass;
#include "fc_common.h"

#include <fc_array.h>
#include <fc_string.h>
#include <fc_queue.h>
#include <fc_log.h>
#include <fc_mbuf.h>
#include <fc_memcache.h>
#include <fc_message.h>

#include <fc_sha1.h>
#include <fc_time.h>
#include <fc_util.h>
#include <fc_event.h>

#include <fc_connection.h>
#include <fc_slab.h>
#include <fc_itemx.h>
#include <fc_item.h>
#include <fc_signal.h>

struct context {
    int                ep;          /* epoll device */
    int                nevent;      /* # epoll event */
    int                max_timeout; /* epoll wait max timeout in msec */
    int                timeout;     /* epoll wait timeout in msec */
    struct epoll_event *event;      /* epoll event */
};

#include "fc_settings.h"

rstatus_t core_init(void);
void core_deinit(void);

rstatus_t core_start(struct context *ctx);
void core_stop(struct context *ctx);
rstatus_t core_loop(struct context *ctx);

#endif
