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

#include <stdlib.h>
#include <stdio.h>

#include <fc_core.h>

extern struct settings settings;

static uint64_t cas_id;

/*
 * Return true if the item has expired, otherwise return false. Items
 * with expiry of 0 are considered as unexpirable.
 */
bool
item_expired(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    return (it->expiry != 0 && it->expiry < time_now()) ? true : false;
}

/*
 * Return the owner slab of item it.
 */
struct slab *
item_to_slab(struct item *it)
{
    struct slab *slab;

    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(it->offset < settings.slab_size);

    slab = (struct slab *)((uint8_t *)it - it->offset);

    ASSERT(slab->magic == SLAB_MAGIC);

    return slab;
}

uint8_t
item_slabcid(uint8_t nkey, uint32_t ndata)
{
    size_t ntotal;
    uint8_t cid;

    ntotal = item_ntotal(nkey, ndata);

    cid = slab_cid(ntotal);
    if (cid == SLABCLASS_INVALID_ID) {
        log_debug(LOG_NOTICE, "slab class id out of range with %"PRIu8" bytes "
                  "key, %"PRIu32" bytes value and %zu item chunk size", nkey,
                  ndata, ntotal);
    }

    return cid;
}

struct item *
item_get(uint8_t *key, uint8_t nkey, uint8_t cid, uint32_t ndata,
         rel_time_t expiry, uint32_t flags, uint8_t *md, uint32_t hash)
{
    struct item *it;

    ASSERT(slab_valid_id(cid));

    it = slab_get_item(cid);
    if (it == NULL) {
        log_warn("server error on allocating item in slab %"PRIu8, cid);
        return NULL;
    }

    it->magic = ITEM_MAGIC;
    /* offset and sid are initialized by slab_get_item */
    it->cid = cid;
    it->nkey = nkey;
    it->ndata = ndata;
    it->expiry = expiry;
    it->flags = flags;
    fc_memcpy(it->md, md, sizeof(it->md));
    it->hash = hash;
    /* part of end[] that stores the key string is initialized here */
    fc_memcpy(item_key(it), key, nkey);

    log_debug(LOG_VERB, "get it '%.*s' at offset %"PRIu32" with cid %"PRIu8
              " expiry %u", it->nkey, item_key(it), it->offset, it->cid,
              it->expiry);

    itemx_putx(it->hash, it->md, it->sid, it->offset, ++cas_id);

    return it;
}

void
item_put(struct item *it)
{
    ASSERT(it->magic == ITEM_MAGIC);

    slab_put_item(it);
}

void
item_init(void)
{
    cas_id = 0ULL;
}

void
item_deinit(void)
{
}
