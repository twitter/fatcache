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

#ifndef _FC_EVENT_H_
#define _FC_EVENT_H_

#include <fc_core.h>

int event_init(struct context *ctx, int size);
void event_deinit(struct context *ctx);

int event_add_out(int ep, struct conn *c);
int event_del_out(int ep, struct conn *c);
int event_add_conn(int ep, struct conn *c);
int event_del_conn(int ep, struct conn *c);

int event_wait(int ep, struct epoll_event *event, int nevent, int timeout);

#endif
