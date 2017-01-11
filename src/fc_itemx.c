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

#include <fc_core.h>

#define HASHSIZE(_n)    (1ULL << (_n))
#define HASHMASK(_n)    (HASHSIZE(_n) - 1)

extern struct settings settings;

static uint64_t nitx;                /* # item index */
static uint64_t nitx_table;          /* # item index table entries */
static struct itemx_tqh *itx_table;  /* item index table */

static uint64_t nalloc_itemx;        /* # nalloc itemx */
static uint64_t nfree_itemxq;        /* # free itemx q */
static struct itemx_tqh free_itemxq; /* free itemx q */

static struct itemx *istart;         /* itemx memory start */
static struct itemx *iend;           /* itemx memory end */

/*
 * Return true if the itemx has expired, otherwise return false. Itemx
 * with expiry of 0 are considered as unexpirable.
 */
bool
itemx_expired(struct itemx *itx)
{
    uint32_t hash;

    ASSERT(itx != NULL);

    if(itx->expiry != 0 && itx->expiry < time_now()) {
        hash = sha1_hash(itx->md);
        itemx_removex(hash, itx->md);
        return true;
    } else {
        return false;
    }
}

/*
 * Returns true, if there are no free item indexes, otherwise
 * return false.
 */
bool
itemx_empty(void)
{
    if (STAILQ_EMPTY(&free_itemxq)) {
        ASSERT(nfree_itemxq == 0);
        return true;
    }

    ASSERT(nfree_itemxq > 0);

    return false;
}

static struct itemx *
itemx_get(void)
{
    struct itemx *itx;

    ASSERT(!itemx_empty());

    itx = STAILQ_FIRST(&free_itemxq);
    nfree_itemxq--;
    STAILQ_REMOVE_HEAD(&free_itemxq, tqe);

    STAILQ_NEXT(itx, tqe) = NULL;
    /* md[] is left uninitialized */
    itx->sid = 0;
    itx->offset = 0;
    itx->cas = 0;

    log_debug(LOG_VVERB, "get itx %p", itx);

    return itx;
}

static void
itemx_put(struct itemx *itx)
{
    log_debug(LOG_VVERB, "put itx %p", itx);

    nfree_itemxq++;
    STAILQ_INSERT_HEAD(&free_itemxq, itx, tqe);
}

rstatus_t
itemx_init(void)
{
    struct itemx *itx; /* item index */
    uint64_t n;        /* # item index */
    uint64_t i;        /* item index iterator */

    nitx = 0ULL;
    nitx_table = 0ULL;
    itx_table = NULL;

    nfree_itemxq = 0;
    STAILQ_INIT(&free_itemxq);

    istart = NULL;
    iend = NULL;

    /* init item index table */
    nitx_table = HASHSIZE(settings.hash_power);
    itx_table = fc_alloc(sizeof(*itx_table) * nitx_table);
    if (itx_table == NULL) {
        return FC_ENOMEM;
    }
    for (i = 0ULL; i < nitx_table; i++) {
        STAILQ_INIT(&itx_table[i]);
    }

    n = settings.max_index_memory / sizeof(struct itemx);

    /* init item index memory */
    itx = fc_mmap(settings.max_index_memory);
    if (itx == NULL) {
        return FC_ENOMEM;
    }
    istart = itx;
    iend = itx + n;

    for (itx = istart; itx < iend; itx++) {
        itemx_put(itx);
    }
    nalloc_itemx = n;

    return FC_OK;
}

void
itemx_deinit(void)
{
    struct itemx *itx;

    while (!STAILQ_EMPTY(&free_itemxq)) {
        ASSERT(nfree_itemxq > 0);

        itx = STAILQ_FIRST(&free_itemxq);
        nfree_itemxq--;
        STAILQ_REMOVE_HEAD(&free_itemxq, tqe);
    }
    ASSERT(nfree_itemxq == 0);

    if (istart != NULL) {
        fc_munmap(istart, settings.max_index_memory);
    }

    if (itx_table != NULL) {
        fc_free(itx_table);
    }
}

static struct itemx_tqh *
itemx_bucket(uint32_t hash)
{
    struct itemx_tqh *bucket;
    uint64_t idx;

    idx = hash & HASHMASK(settings.hash_power);
    bucket = &itx_table[idx];

    return bucket;
}

struct itemx *
itemx_getx(uint32_t hash, uint8_t *md)
{
    struct itemx_tqh *bucket;
    struct itemx *itx;

    bucket = itemx_bucket(hash);

    STAILQ_FOREACH(itx, bucket, tqe) {
        if (memcmp(itx->md, md, sizeof(itx->md)) == 0) {
            break;
        }
    }

    return itx;
}

void
itemx_putx(uint32_t hash, uint8_t *md, uint32_t sid, uint32_t offset,
           rel_time_t expiry, uint64_t cas)
{
    struct itemx *itx;
    struct itemx_tqh *bucket;

    ASSERT(!itemx_empty());

    itx = itemx_get();
    itx->sid = sid;
    itx->offset = offset;
    itx->expiry = expiry;
    itx->cas = cas;
    fc_memcpy(itx->md, md, sizeof(itx->md));

    ASSERT(itemx_getx(hash, md) == NULL);

    bucket = itemx_bucket(hash);
    nitx++;
    STAILQ_INSERT_HEAD(bucket, itx, tqe);
    slab_incr_chunks_by_sid(itx->sid, 1);
}

bool
itemx_removex(uint32_t hash, uint8_t *md)
{
    struct itemx_tqh *bucket;
    struct itemx *itx;

    itx = itemx_getx(hash, md);
    if (itx == NULL) {
        return false;
    }

    bucket = itemx_bucket(hash);
    nitx--;
    STAILQ_REMOVE(bucket, itx, itemx, tqe);
    slab_incr_chunks_by_sid(itx->sid, -1);

    itemx_put(itx);

    return true;
}

uint64_t
itemx_nalloc(void)
{
    return nalloc_itemx;
}

uint64_t
itemx_nfree(void)
{
    return nfree_itemxq;
}
