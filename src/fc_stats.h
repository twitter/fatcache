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

#ifndef _FC_STATS_H_
#define _FC_STATS_H_

#include <unistd.h>
#include <stdint.h>
#include <fc_core.h>

typedef struct {
    uint8_t *data;
    uint32_t nused;
    uint32_t nalloc;
} buffer;

typedef struct {
    uint64_t get;
    uint64_t get_hits;
    uint64_t set;
    uint64_t del;
    uint64_t del_hits;
    uint64_t incr;
    uint64_t incr_hits;
    uint64_t decr;
    uint64_t decr_hits;
    uint64_t cas;
    uint64_t cas_hits;
} stats_info;


#define STATS_INCR(type) stats_incr(SLABCLASS_INVALID_ID, type, 0)
#define SC_STATS_INCR(cid, type) stats_incr(cid, type, 0)
#define STATS_HIT_INCR(type)  stats_incr(SLABCLASS_INVALID_ID, type, 1)

#define STATS_GET(type) stats_get(SLABCLASS_INVALID_ID, type, 0)
#define SC_STATS_GET(cid, type) stats_get(cid, type, 0)
#define STATS_GET_MISS(type) stats_get(SLABCLASS_INVALID_ID, type, 1)

#define APPEND_STAT(b, name, fmt, val) \
    stats_append(b, SLABCLASS_INVALID_ID, name, fmt, val)
#define SC_APPEND_STAT(b, cid, name, fmt, val) \
    stats_append(b, cid, name, fmt, val)
#define APPEND_STAT_END(b) \
    stats_append(b, SLABCLASS_INVALID_ID, NULL, 0, NULL, 0)

buffer *stats_alloc_buffer(int n);
void stats_dealloc_buffer(buffer *buf);
void stats_append(buffer *buf, uint8_t cid, const char*name, const char *fmt, ...);
void stats_incr(uint8_t cid, msg_type_t type, int is_hit);
uint64_t stats_get(uint8_t cid, msg_type_t type, int is_miss);
buffer *stats_server(void);
buffer *stats_slabs(void);
buffer *stats_settings(void);
#endif
