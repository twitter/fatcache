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

#ifndef _FC_ITEMX_H_
#define _FC_ITEMX_H_

#define ITEMX_HASH_POWER    20

struct itemx {
    STAILQ_ENTRY(itemx) tqe;    /* link in index / free q */
    uint8_t             md[20]; /* sha1 message digest */
    uint32_t            sid;    /* owner slab id */
    uint32_t            offset; /* item offset from owner slab base */
    uint64_t            cas;    /* cas */
} __attribute__ ((__packed__));

STAILQ_HEAD(itemx_tqh, itemx);

rstatus_t itemx_init(void);
void itemx_deinit(void);

bool itemx_empty(void);
struct itemx *itemx_getx(uint32_t hash, uint8_t *md);
void itemx_putx(uint32_t hash, uint8_t *md, uint32_t sid, uint32_t ioff, uint64_t cas);
bool itemx_removex(uint32_t hash, uint8_t *md);

#endif
