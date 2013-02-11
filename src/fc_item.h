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

#ifndef _FC_ITEM_H_
#define _FC_ITEM_H_

#include <fc_slab.h>

struct item {
    uint32_t          magic;      /* item magic (const) */
    uint32_t          offset;     /* raw offset from owner slab base (const) */
    uint32_t          sid;        /* slab id (const) */
    uint8_t           cid;        /* slab class id (const) */
    uint8_t           unused[2];  /* unused */
    uint8_t           nkey;       /* key length */
    uint32_t          ndata;      /* date length */
    rel_time_t        expiry;     /* expiry in secs */
    uint32_t          flags;      /* flags opaque to the server */
    uint8_t           md[20];     /* key message digest */
    uint32_t          hash;       /* key hash */
    uint8_t           end[1];     /* item data */
};

#define ITEM_MAGIC      0xfeedface
#define ITEM_HDR_SIZE   offsetof(struct item, end)

/*
 * An item chunk is the portion of the memory carved out from the slab
 * for an item. An item chunk contains the item header followed by item
 * data.
 *
 * The smallest item data is actually a single byte key with a zero byte
 * value which internally is of sizeof("k"), as key is stored with
 * terminating '\0'.
 *
 * The largest item data is actually the room left in the slab_size()
 * slab, after the item header has been factored out
 */
#define ITEM_MIN_PAYLOAD_SIZE   (sizeof("k") + sizeof(uint64_t))
#define ITEM_MIN_CHUNK_SIZE     \
    FC_ALIGN(ITEM_HDR_SIZE + ITEM_MIN_PAYLOAD_SIZE, FC_ALIGNMENT)

#define ITEM_PAYLOAD_SIZE       32
#define ITEM_CHUNK_SIZE         \
    FC_ALIGN(ITEM_HDR_SIZE + ITEM_PAYLOAD_SIZE, FC_ALIGNMENT)

static inline uint8_t *
item_key(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return it->end;
}

static inline size_t
item_ntotal(uint8_t nkey, uint32_t ndata)
{
    return ITEM_HDR_SIZE + nkey + ndata;
}

static inline size_t
item_size(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return item_ntotal(it->nkey, it->ndata);
}

static inline uint8_t *
item_data(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return it->end + it->nkey;
}

bool item_expired(struct item *it);
struct slab *item_to_slab(struct item *it);
uint8_t item_slabcid(uint8_t nkey, uint32_t ndata);

struct item *item_get(uint8_t *key, uint8_t nkey, uint8_t cid, uint32_t ndata, rel_time_t expiry, uint32_t dataflags,  uint8_t *md, uint32_t hash);
void item_put(struct item *it);

void item_init(void);
void item_deinit(void);
#endif
