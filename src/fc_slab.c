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

extern struct settings settings;

static uint32_t nfree_msinfoq;         /* # free memory slabinfo q */
static struct slabhinfo free_msinfoq;  /* free memory slabinfo q */
static uint32_t nfull_msinfoq;         /* # full memory slabinfo q */
static struct slabhinfo full_msinfoq;  /* # full memory slabinfo q */

static uint32_t nfree_dsinfoq;         /* # free disk slabinfo q */
static struct slabhinfo free_dsinfoq;  /* free disk slabinfo q */
static uint32_t nfull_dsinfoq;         /* # full disk slabinfo q */
static struct slabhinfo full_dsinfoq;  /* full disk slabinfo q */

static uint8_t nctable;                /* # class table entry */
static struct slabclass *ctable;       /* table of slabclass indexed by cid */

static uint32_t nstable;               /* # slab table entry */
static struct slabinfo *stable;        /* table of slabinfo indexed by sid */

static uint8_t *mstart;                /* memory slab start */
static uint8_t *mend;                  /* memory slab end */

static off_t dstart;                   /* disk start */
static off_t dend;                     /* disk end */
static int fd;                         /* disk file descriptor */

static size_t mspace;                  /* memory space */
static size_t dspace;                  /* disk space */
static uint32_t nmslab;                /* # memory slabs */
static uint32_t ndslab;                /* # disk slabs */

/*
 * Return the maximum space available for item sized chunks in a given
 * slab. Slab cannot contain more than 2^32 bytes (4G).
 */
size_t
slab_data_size(void)
{
    return settings.slab_size - SLAB_HDR_SIZE;
}

/*
 * Return true if slab class id cid is valid and within bounds, otherwise
 * return false.
 */
bool
slab_valid_id(uint8_t cid)
{
    if (cid >= SLABCLASS_MIN_ID && cid <= settings.profile_last_id) {
        return true;
    }

    return false;
}

void
slab_print(void)
{
    uint8_t cid;         /* slab class id */
    struct slabclass *c; /* slab class */

    loga("slab size %zu, slab hdr size %zu, item hdr size %zu, "
         "item chunk size %zu", settings.slab_size, SLAB_HDR_SIZE,
         ITEM_HDR_SIZE, settings.chunk_size);

    loga("index memory %zu, slab memory %zu, disk space %zu",
         0, mspace, dspace);

    for (cid = SLABCLASS_MIN_ID; cid < nctable; cid++) {
        c = &ctable[cid];
        loga("class %3"PRId8": items %7"PRIu32"  size %7zu  data %7zu  "
             "slack %7zu", cid, c->nitem, c->size, c->size - ITEM_HDR_SIZE,
             c->slack);
    }
}

/*
 * Return the cid of the slab which can store an item of a given size.
 *
 * Return SLABCLASS_INVALID_ID, for large items which cannot be stored in
 * any of the configured slabs.
 */
uint8_t
slab_cid(size_t size)
{
    uint8_t cid, imin, imax;

    ASSERT(size != 0);

    /* binary search */
    imin = SLABCLASS_MIN_ID;
    imax = nctable;
    while (imax >= imin) {
        cid = (imin + imax) / 2;
        if (size > ctable[cid].size) {
            imin = cid + 1;
        } else if (cid > SLABCLASS_MIN_ID && size <= ctable[cid - 1].size) {
            imax = cid - 1;
        } else {
            break;
        }
    }

    if (imin > imax) {
        /* size too big for any slab */
        return SLABCLASS_INVALID_ID;
    }

    return cid;
}

/*
 * Return true if all items in the slab have been allocated, else
 * return false.
 */
static bool
slab_full(struct slabinfo *sinfo)
{
    struct slabclass *c;

    ASSERT(sinfo->cid >= SLABCLASS_MIN_ID && sinfo->cid < nctable);
    c = &ctable[sinfo->cid];

    return (c->nitem == sinfo->nalloc) ? true : false;
}

/*
 * Return and optionally verify the memory slab with the given slab_size
 * offset from base mstart.
 */
static void *
slab_from_maddr(uint32_t addr, bool verify)
{
    struct slab *slab;
    off_t off;

    off = (off_t)addr * settings.slab_size;
    slab = (struct slab *)(mstart + off);
    if (verify) {
        ASSERT(mstart + off < mend);
        ASSERT(slab->magic == SLAB_MAGIC);
        ASSERT(slab->sid < nstable);
        ASSERT(stable[slab->sid].sid == slab->sid);
        ASSERT(stable[slab->sid].cid == slab->cid);
        ASSERT(stable[slab->sid].mem == 1);
    }

    return slab;
}

/*
 * Return the slab_size offset for the given disk slab from the base
 * of the disk.
 */
static off_t
slab_to_daddr(struct slabinfo *sinfo)
{
    off_t off;

    ASSERT(!sinfo->mem);

    off = dstart + ((off_t)sinfo->addr * settings.slab_size);
    ASSERT(off < dend);

    return off;
}

/*
 * Return and optionally verify the idx^th item with a given size in the
 * in given slab.
 */
static struct item *
slab_to_item(struct slab *slab, uint32_t idx, size_t size, bool verify)
{
    struct item *it;

    ASSERT(slab->magic == SLAB_MAGIC);
    ASSERT(idx <= stable[slab->sid].nalloc);
    ASSERT(idx * size < settings.slab_size);

    it = (struct item *)((uint8_t *)slab->data + (idx * size));
    if (verify) {
        ASSERT(it->magic == ITEM_MAGIC);
        ASSERT(it->cid == slab->cid);
        ASSERT(it->sid == slab->sid);
    }

    return it;
}

/* called when a slab eviction read completes. */
static void
slab_evict_callback(struct aio_op *op, int ret, void *buf)
{
    struct slabinfo *sinfo = op->evict.info;
    struct slabclass *c;    /* slab class */
    struct slab *slab;
    uint32_t idx;           /* idx^th item */

    if (ret <= 0) {
        log_error("evict slab disk read failed (sid %"PRIu32", addr %"PRIu32")",
            sinfo->sid, sinfo->addr);
        return;
    }

    slab = buf;
    ASSERT(slab->magic == SLAB_MAGIC);
    ASSERT(slab->sid == sinfo->sid);
    ASSERT(slab->cid == sinfo->cid);
    ASSERT(slab_full(sinfo));

    c = &ctable[sinfo->cid];
    ASSERT(c->evict_op == op);
    ASSERT(op->evict.sc == c);

    /* this op is now free, evictions hold no data */
    aio_op_detach(op);

    /* evict all items from the slab */
    for (c = &ctable[slab->cid], idx = 0; idx < c->nitem; idx++) {
        struct item *it = slab_to_item(slab, idx, c->size, true);
        if (itemx_getx(it->hash, it->md) != NULL) {
            itemx_removex(it->hash, it->md);
        }
    }

    log_debug(LOG_VERB, "evict slab finished at disk (sid %"PRIu32", addr %"PRIu32")",
              sinfo->sid, sinfo->addr);

    /* move disk slab from full to free q */
    nfree_dsinfoq++;
    TAILQ_INSERT_TAIL(&free_dsinfoq, sinfo, tqe);
}

/* removes a slab from disk by first reading it to determine what
 * items are there (to unindex them) and then marking the slab as free.
 *
 * Multiple evictions can happen simultaneously, but only one eviction
 * per slab class may happen at once.
 *
 * The slabclass parameter given here is the slab class we are needing a slab
 * in that has triggered this eviction.
 */
static rstatus_t
slab_evict(struct aio_op *op, struct slabclass *sc)
{
    struct slabinfo *sinfo; /* disk slabinfo */
    size_t size;            /* bytes to read */
    off_t off;              /* offset */
    rstatus_t status;

    /* If there already is an eviction happening now for this slab class then
     * there is no need to cause another eviction, we should wait for the original
     * eviction to finish.
     */
    if (sc->evict_op != NULL) {
        ASSERT(sc->evict_op != op);

        aio_op_depend(sc->evict_op, op);
        return FC_EAGAIN;
    }
    ASSERT(op->evict.sc == NULL);

    ASSERT(!TAILQ_EMPTY(&full_dsinfoq));
    ASSERT(nfull_dsinfoq > 0);

    sinfo = TAILQ_FIRST(&full_dsinfoq);
    nfull_dsinfoq--;
    TAILQ_REMOVE(&full_dsinfoq, sinfo, tqe);
    ASSERT(!sinfo->mem);
    ASSERT(sinfo->addr < ndslab);

    /* read the slab */
    size = settings.slab_size;
    off = slab_to_daddr(sinfo);
    status = aio_read(op, fd, size, off, slab_evict_callback);//, sinfo);
    if (status != FC_OK) {
        log_error("aio_read fd %d %zu bytes at offset %"PRIu64" failed",
                  size, (uint64_t)off);
        return status;
    }

    /* associate this slabclass with this op */
    sc->evict_op = op;
    op->type = OP_EVICT;
    op->evict.sc = sc;
    op->evict.info = sinfo;

    /* notify this op when it is finished */
    aio_op_depend(op, op);

    log_debug(LOG_VERB, "evict slab queued at disk (sid %"PRIu32", addr %"PRIu32")",
                sinfo->sid, sinfo->addr);

    return FC_EAGAIN;
}

static void
slab_swap_addr(struct slabinfo *msinfo, struct slabinfo *dsinfo)
{
    uint32_t m_addr;

    ASSERT(msinfo->mem);
    ASSERT(!dsinfo->mem);

    /* on address swap, sid and cid are left untouched */
    m_addr = msinfo->addr;

    msinfo->addr = dsinfo->addr;
    msinfo->mem = 0;

    dsinfo->addr = m_addr;
    dsinfo->mem = 1;
}

static void
slab_drain_callback(struct aio_op *op, int ret, void *buf)
{
    struct slabinfo *msinfo = op->drain.msinfo, *dsinfo = op->drain.dsinfo;

    log_debug(LOG_DEBUG, "finished drain slab at memory (sid %"PRIu32" addr %"PRIu32") "
              "to disk (sid %"PRIu32" addr %"PRIu32")", msinfo->sid,
              msinfo->addr, dsinfo->sid, dsinfo->addr);

    /* swap msinfo <> dsinfo addresses */
    slab_swap_addr(msinfo, dsinfo);

    /* move dsinfo (now a memory sinfo) to free q */
    nfree_msinfoq++;
    TAILQ_INSERT_TAIL(&free_msinfoq, dsinfo, tqe);

    /* move msinfo (now a disk sinfo) to full q */
    nfull_dsinfoq++;
    TAILQ_INSERT_TAIL(&full_dsinfoq, msinfo, tqe);

    /* this op is now free, drains hold no data */
    aio_op_detach(op);
}

static rstatus_t
_slab_drain(struct aio_op *op, struct slabclass *c)
{
    struct slabinfo *msinfo, *dsinfo; /* memory and disk slabinfo */
    struct slab *slab;                /* slab to write */
    size_t size;                      /* bytes to write */
    off_t off;                        /* offset to write at */
    rstatus_t status;

    if (c->drain_op != NULL) {
        ASSERT(c->drain_op->processing);

        /* there is already a drain operation for this slab, wait for it to complete */
        aio_op_depend(c->drain_op, op);
        return FC_EAGAIN;
    }

    ASSERT(!TAILQ_EMPTY(&full_msinfoq));
    ASSERT(nfull_msinfoq > 0);

    ASSERT(!TAILQ_EMPTY(&free_dsinfoq));
    ASSERT(nfree_dsinfoq > 0);

    /* get memory sinfo from full q */
    msinfo = TAILQ_FIRST(&full_msinfoq);
    nfull_msinfoq--;
    TAILQ_REMOVE(&full_msinfoq, msinfo, tqe);
    ASSERT(msinfo->mem);
    ASSERT(slab_full(msinfo));

    /* get disk sinfo from free q */
    dsinfo = TAILQ_FIRST(&free_dsinfoq);
    nfree_dsinfoq--;
    TAILQ_REMOVE(&free_dsinfoq, dsinfo, tqe);
    ASSERT(!dsinfo->mem);

    /* drain the memory to disk slab */
    slab = slab_from_maddr(msinfo->addr, true);
    size = settings.slab_size;
    off = slab_to_daddr(dsinfo);

    status = aio_write(op, fd, slab, size, off, slab_drain_callback);
    if (status != FC_OK) {
        log_error("aio_write fd %d %zu bytes at offset %"PRId64" failed",
                  fd, size, off);
        return status;
    }

    op->type = OP_DRAIN;

    c->drain_op = op;
    op->drain.sc = c;

    op->drain.msinfo = msinfo;
    msinfo->op = op;

    op->drain.dsinfo = dsinfo;
    dsinfo->op = op;

    aio_op_depend(op, op);

    log_debug(LOG_DEBUG, "queued drain slab at memory (sid %"PRIu32" addr %"PRIu32") "
              "to disk (sid %"PRIu32" addr %"PRIu32")", msinfo->sid,
              msinfo->addr, dsinfo->sid, dsinfo->addr);

    return FC_EAGAIN;
}

static rstatus_t
slab_drain(struct aio_op *op, struct slabclass *c)
{
    if (!TAILQ_EMPTY(&free_dsinfoq)) {
        ASSERT(nfree_dsinfoq > 0);
        return _slab_drain(op, c);
    }

    /* this always returns eagain or error */
    return slab_evict(op, c);
}

static struct item *
_slab_get_item(uint8_t cid)
{
    struct slabclass *c;
    struct slabinfo *sinfo;
    struct slab *slab;
    struct item *it;

    ASSERT(cid >= SLABCLASS_MIN_ID && cid < nctable);
    c = &ctable[cid];

    /* allocate new item from partial slab */
    ASSERT(!TAILQ_EMPTY(&c->partial_msinfoq));
    sinfo = TAILQ_FIRST(&c->partial_msinfoq);
    ASSERT(!slab_full(sinfo));
    slab = slab_from_maddr(sinfo->addr, true);

    /* consume an item from partial slab */
    it = slab_to_item(slab, sinfo->nalloc, c->size, false);
    it->offset = (uint32_t)((uint8_t *)it - (uint8_t *)slab);
    it->sid = slab->sid;
    sinfo->nalloc++;

    if (slab_full(sinfo)) {
        /* move memory slab from partial to full q */
        TAILQ_REMOVE(&c->partial_msinfoq, sinfo, tqe);
        nfull_msinfoq++;
        TAILQ_INSERT_TAIL(&full_msinfoq, sinfo, tqe);
    }

    log_debug(LOG_VERB, "get it at offset %"PRIu32" with cid %"PRIu8"",
              it->offset, it->cid);

    return it;
}

rstatus_t
slab_get_item(struct aio_op *op, uint8_t cid, struct item **item)
{
    struct slabclass *c;
    struct slabinfo *sinfo;
    struct slab *slab;

    ASSERT(cid >= SLABCLASS_MIN_ID && cid < nctable);
    c = &ctable[cid];

    if (itemx_empty()) {
        return slab_evict(op, c);
    }

    if (!TAILQ_EMPTY(&c->partial_msinfoq)) {
        *item = _slab_get_item(cid);
        return FC_OK;
    }

    if (!TAILQ_EMPTY(&free_msinfoq)) {
        /* move memory slab from free to partial q */
        sinfo = TAILQ_FIRST(&free_msinfoq);
        ASSERT(nfree_msinfoq > 0);
        nfree_msinfoq--;
        TAILQ_REMOVE(&free_msinfoq, sinfo, tqe);

        /* init partial sinfo */
        TAILQ_INSERT_HEAD(&c->partial_msinfoq, sinfo, tqe);
        /* sid is already initialized by slab_init */
        /* addr is already initialized by slab_init */
        sinfo->nalloc = 0;
        sinfo->nfree = 0;
        sinfo->cid = cid;
        /* mem is already initialized by slab_init */
        ASSERT(sinfo->mem == 1);

        /* init slab of partial sinfo */
        slab = slab_from_maddr(sinfo->addr, false);
        slab->magic = SLAB_MAGIC;
        slab->cid = cid;
        /* unused[] is left uninitialized */
        slab->sid = sinfo->sid;
        /* data[] is initialized on-demand */

        *item = _slab_get_item(cid);
        return FC_OK;
    }

    ASSERT(!TAILQ_EMPTY(&full_msinfoq));
    ASSERT(nfull_msinfoq > 0);

    return slab_drain(op, c);
}

void
slab_put_item(struct item *it)
{
    log_debug(LOG_INFO, "put it '%.*s' at offset %"PRIu32" with cid %"PRIu8,
              it->nkey, item_key(it), it->offset, it->cid);
}

rstatus_t
slab_read_item(struct aio_op *op, struct item **item, uint32_t sid, uint32_t addr)
{
    struct slabclass *c;    /* slab class */
    struct item *it;        /* item */
    struct slabinfo *sinfo; /* slab info */
    off_t off;              /* offset to read from */
    off_t aligned_off;      /* aligned offset to read from */
    size_t aligned_size;    /* aligned size to read */
    rstatus_t status;

    ASSERT(sid < nstable);
    ASSERT(addr < settings.slab_size);

    sinfo = &stable[sid];
    c = &ctable[sinfo->cid];

    if (sinfo->mem) {
        off = (off_t)sinfo->addr * settings.slab_size + addr;
        aio_op_detach(op);
        fc_memcpy(op->mem, mstart + off, c->size);
        it = (struct item *)op->mem;

        ASSERT(it->magic == ITEM_MAGIC);
        ASSERT(it->cid == sinfo->cid);
        ASSERT(it->sid == sinfo->sid);

        *item = it;
        return FC_OK;
    }

    off = slab_to_daddr(sinfo) + addr;
    aligned_off = ROUND_DOWN(off, 512);
    aligned_size = ROUND_UP((c->size + (off - aligned_off)), 512);

    /* check if this slab info already has an operation associated with it */
    if (sinfo->op != NULL) {
        ASSERT(sinfo->op->type == OP_READ);
        ASSERT(sinfo->op->read_si == sinfo);

        if (sinfo->op->processing) {
            /* this slab is already in the process of being read, wait for the pending operation to finish */
            ASSERT(sinfo->op != op);
            aio_op_depend(sinfo->op, op);
            return FC_EAGAIN;
        }
        else {
            if (op != sinfo->op) {
                ASSERT(op->read_si != sinfo);

                aio_op_detach(op);
                fc_memcpy(op->mem, sinfo->op->mem, settings.slab_size);
            }

            /* this slab has already been read and is still in memory */
            it = (struct item *)((uint8_t *)op->mem + (off - aligned_off));

            ASSERT(it->magic == ITEM_MAGIC);
            ASSERT(it->cid == sinfo->cid);
            ASSERT(it->sid == sinfo->sid);

            *item = it;
            return FC_OK;
        }

        NOT_REACHED();
    }
    ASSERT(op->read_si != sinfo);

    status = aio_read(op, fd, aligned_size, aligned_off, NULL);
    if (status != FC_OK) {
        log_error("aio_read fd %d %zu bytes at offset %"PRIu64" failed", fd,
                  aligned_size, (uint64_t)aligned_off);
        return status;
    }

    log_error("slab read started for slab %p with op %p", sinfo, op);
    /* this slabinfo is now being processed by this operation */
    sinfo->op = op;

    /* now associate this slab with this operation */
    op->type = OP_READ;
    op->read_si = sinfo;

    /* this operation depends on itself so we will notify it when it finishes */
    aio_op_depend(op, op);

    return FC_EAGAIN;
}

static rstatus_t
slab_init_ctable(void)
{
    struct slabclass *c;
    uint8_t cid;
    size_t *profile;

    ASSERT(settings.profile_last_id <= SLABCLASS_MAX_ID);

    profile = settings.profile;
    nctable = settings.profile_last_id + 1;
    ctable = fc_alloc(sizeof(*ctable) * nctable);
    if (ctable == NULL) {
        return FC_ENOMEM;
    }

    for (cid = SLABCLASS_MIN_ID; cid < nctable; cid++) {
        c = &ctable[cid];
        c->nitem = slab_data_size() / profile[cid];
        c->size = profile[cid];
        c->slack = slab_data_size() - (c->nitem * c->size);
        c->evict_op = NULL;
        c->drain_op = NULL;
        TAILQ_INIT(&c->partial_msinfoq);
    }

    return FC_OK;
}

static void
slab_deinit_ctable(void)
{
}

static rstatus_t
slab_init_stable(void)
{
    struct slabinfo *sinfo;
    uint32_t i, j;

    nstable = nmslab + ndslab;
    stable = fc_alloc(sizeof(*stable) * nstable);
    if (stable == NULL) {
        return FC_ENOMEM;
    }

    /* init memory slabinfo q  */
    for (i = 0; i < nmslab; i++) {
        sinfo = &stable[i];

        sinfo->sid = i;
        sinfo->addr = i;
        sinfo->nalloc = 0;
        sinfo->nfree = 0;
        sinfo->cid = SLABCLASS_INVALID_ID;
        sinfo->op = NULL;
        sinfo->mem = 1;

        nfree_msinfoq++;
        TAILQ_INSERT_TAIL(&free_msinfoq, sinfo, tqe);
    }

    /* init disk slabinfo q */
    for (j = 0; j < ndslab && i < nstable; i++, j++) {
        sinfo = &stable[i];

        sinfo->sid = i;
        sinfo->addr = j;
        sinfo->nalloc = 0;
        sinfo->nfree = 0;
        sinfo->cid = SLABCLASS_INVALID_ID;
        sinfo->op = NULL;
        sinfo->mem = 0;

        nfree_dsinfoq++;
        TAILQ_INSERT_TAIL(&free_dsinfoq, sinfo, tqe);
    }

    return FC_OK;
}

static void
slab_deinit_stable(void)
{
}

rstatus_t
slab_init(void)
{
    rstatus_t status;
    size_t size;
    uint32_t ndchunk;

    nfree_msinfoq = 0;
    TAILQ_INIT(&free_msinfoq);
    nfull_msinfoq = 0;
    TAILQ_INIT(&full_msinfoq);

    nfree_dsinfoq = 0;
    TAILQ_INIT(&free_dsinfoq);
    nfull_dsinfoq = 0;
    TAILQ_INIT(&full_dsinfoq);

    nctable = 0;
    ctable = NULL;

    nstable = 0;
    stable = NULL;

    mstart = NULL;
    mend = NULL;

    dstart = 0;
    dend = 0;
    fd = -1;

    mspace = 0;
    dspace = 0;
    nmslab = 0;
    ndslab = 0;

    if (settings.ssd_device == NULL) {
        log_error("ssd device file must be specified");
        return FC_ERROR;
    }

    /* init slab class table */
    status = slab_init_ctable();
    if (status != FC_OK) {
        return status;
    }

    /* init nmslab, mstart and mend */
    nmslab = MAX(nctable, settings.max_slab_memory / settings.slab_size);
    mspace = nmslab * settings.slab_size;
    mstart = fc_mmap(mspace);
    if (mstart == NULL) {
        log_error("mmap %zu bytes failed: %s", mspace, strerror(errno));
        return FC_ENOMEM;
    }
    mend = mstart + mspace;

    /* init ndslab, dstart and dend */
    status = fc_device_size(settings.ssd_device, &size);
    if (status != FC_OK) {
        return status;
    }
    ndchunk = size / settings.slab_size;
    ASSERT(settings.server_n <= ndchunk);
    ndslab = ndchunk / settings.server_n;
    dspace = ndslab * settings.slab_size;
    dstart = (settings.server_id * ndslab) * settings.slab_size;
    dend = ((settings.server_id + 1) * ndslab) * settings.slab_size;

    /* init disk descriptor */
    fd = open(settings.ssd_device, O_RDWR | O_DIRECT, 0644);
    if (fd < 0) {
        log_error("open '%s' failed: %s", settings.ssd_device, strerror(errno));
        return FC_ERROR;
    }

    /* init slab table */
    status = slab_init_stable();
    if (status != FC_OK) {
        return status;
    }

    return FC_OK;
}

void
slab_deinit(void)
{
    slab_deinit_ctable();
    slab_deinit_stable();
}
