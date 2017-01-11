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

static uint64_t nevict;
static uint8_t *evictbuf;              /* evict buffer */
static uint8_t *readbuf;               /* read buffer */

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

static rstatus_t
slab_evict(void)
{
    struct slabclass *c;    /* slab class */
    struct slabinfo *sinfo; /* disk slabinfo */
    struct slab *slab;      /* read slab */
    size_t size;            /* bytes to read */
    off_t off;              /* offset */
    int n;                  /* read bytes */
    uint32_t idx;           /* idx^th item */

    ASSERT(!TAILQ_EMPTY(&full_dsinfoq));
    ASSERT(nfull_dsinfoq > 0);

    sinfo = TAILQ_FIRST(&full_dsinfoq);
    nfull_dsinfoq--;
    TAILQ_REMOVE(&full_dsinfoq, sinfo, tqe);
    ASSERT(!sinfo->mem);
    ASSERT(sinfo->addr < ndslab);

    /* read the slab */
    slab = (struct slab *)evictbuf;
    size = settings.slab_size;
    off = slab_to_daddr(sinfo);
    n = pread(fd, slab, size, off);
    if (n < size) {
        log_error("pread fd %d %zu bytes at offset %"PRIu64" failed: %s", fd,
                  size, (uint64_t)off, strerror(errno));
        return FC_ERROR;
    }
    ASSERT(slab->magic == SLAB_MAGIC);
    ASSERT(slab->sid == sinfo->sid);
    ASSERT(slab->cid == sinfo->cid);
    ASSERT(slab_full(sinfo));

    /* evict all items from the slab */
    for (c = &ctable[slab->cid], idx = 0; idx < c->nitem; idx++) {
        struct item *it = slab_to_item(slab, idx, c->size, true);
        if (itemx_getx(it->hash, it->md) != NULL) {
            itemx_removex(it->hash, it->md);
        }
    }

    log_debug(LOG_DEBUG, "evict slab at disk (sid %"PRIu32", addr %"PRIu32")",
              sinfo->sid, sinfo->addr);

    /* move disk slab from full to free q */
    nfree_dsinfoq++;
    TAILQ_INSERT_TAIL(&free_dsinfoq, sinfo, tqe);
    nevict++;
    c->nevict++;
    c->ndslab--;

    return FC_OK;
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

static rstatus_t
_slab_drain(void)
{
    struct slabinfo *msinfo, *dsinfo; /* memory and disk slabinfo */
    struct slab *slab;                /* slab to write */
    size_t size;                      /* bytes to write */
    off_t off;                        /* offset to write at */
    int n;                            /* written bytes */

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
    n = pwrite(fd, slab, size, off);
    if (n < size) {
        log_error("pwrite fd %d %zu bytes at offset %"PRId64" failed: %s",
                  fd, size, off, strerror(errno));
        return FC_ERROR;
    }

    ctable[msinfo->cid].nmslab--;
    ctable[msinfo->cid].ndslab++;
    log_debug(LOG_DEBUG, "drain slab at memory (sid %"PRIu32" addr %"PRIu32") "
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

    return FC_OK;
}

static rstatus_t
slab_drain(void)
{
    rstatus_t status;

    if (!TAILQ_EMPTY(&free_dsinfoq)) {
        ASSERT(nfree_dsinfoq > 0);
        return _slab_drain();
    }

    status = slab_evict();
    if (status != FC_OK) {
        return status;
    }

    ASSERT(!TAILQ_EMPTY(&free_dsinfoq));
    ASSERT(nfree_dsinfoq > 0);

    return _slab_drain();
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

struct item *
slab_get_item(uint8_t cid)
{
    rstatus_t status;
    struct slabclass *c;
    struct slabinfo *sinfo;
    struct slab *slab;

    ASSERT(cid >= SLABCLASS_MIN_ID && cid < nctable);
    c = &ctable[cid];

    if (itemx_empty()) {
        status = slab_evict();
        if (status != FC_OK) {
            return NULL;
        }
    }

    if (!TAILQ_EMPTY(&c->partial_msinfoq)) {
        return _slab_get_item(cid);
    }

    if (!TAILQ_EMPTY(&free_msinfoq)) {
        /* move memory slab from free to partial q */
        sinfo = TAILQ_FIRST(&free_msinfoq);
        ASSERT(nfree_msinfoq > 0);
        nfree_msinfoq--;
        c->nmslab++;
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

        return _slab_get_item(cid);
    }

    ASSERT(!TAILQ_EMPTY(&full_msinfoq));
    ASSERT(nfull_msinfoq > 0);

    status = slab_drain();
    if (status != FC_OK) {
        return NULL;
    }

    return slab_get_item(cid);
}

void
slab_put_item(struct item *it)
{
    log_debug(LOG_INFO, "put it '%.*s' at offset %"PRIu32" with cid %"PRIu8,
              it->nkey, item_key(it), it->offset, it->cid);
}

struct item *
slab_read_item(uint32_t sid, uint32_t addr)
{
    struct slabclass *c;    /* slab class */
    struct item *it;        /* item */
    struct slabinfo *sinfo; /* slab info */
    int n;                  /* bytes read */
    off_t off;              /* offset to read from */
    size_t size;            /* size to read */
    off_t aligned_off;      /* aligned offset to read from */
    size_t aligned_size;    /* aligned size to read */

    ASSERT(sid < nstable);
    ASSERT(addr < settings.slab_size);

    sinfo = &stable[sid];
    c = &ctable[sinfo->cid];
    size = settings.slab_size;
    it = NULL;

    if (sinfo->mem) {
        off = (off_t)sinfo->addr * settings.slab_size + addr;
        fc_memcpy(readbuf, mstart + off, c->size);
        it = (struct item *)readbuf;
        goto done;
    }

    off = slab_to_daddr(sinfo) + addr;
    aligned_off = ROUND_DOWN(off, 512);
    aligned_size = ROUND_UP((c->size + (off - aligned_off)), 512);

    n = pread(fd, readbuf, aligned_size, aligned_off);
    if (n < aligned_size) {
        log_error("pread fd %d %zu bytes at offset %"PRIu64" failed: %s", fd,
                  aligned_size, (uint64_t)aligned_off, strerror(errno));
        return NULL;
    }
    it = (struct item *)(readbuf + (off - aligned_off));

done:
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(it->cid == sinfo->cid);
    ASSERT(it->sid == sinfo->sid);

    return it;
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
        TAILQ_INIT(&c->partial_msinfoq);
        c->nmslab = 0;
        c->ndslab = 0;
        c->nevict = 0;
        c->nused_item = 0;
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

    evictbuf = NULL;
    readbuf = NULL;

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

    /* init evictbuf and readbuf */
    evictbuf = fc_mmap(settings.slab_size);
    if (evictbuf == NULL) {
        log_error("mmap %zu bytes failed: %s", settings.slab_size,
                  strerror(errno));
        return FC_ENOMEM;
    }
    memset(evictbuf, 0xff, settings.slab_size);

    readbuf = fc_mmap(settings.slab_size);
    if (readbuf == NULL) {
        log_error("mmap %zu bytes failed: %s", settings.slab_size,
                  strerror(errno));
        return FC_ENOMEM;
    }
    memset(readbuf, 0xff, settings.slab_size);

    return FC_OK;
}

void
slab_deinit(void)
{
    slab_deinit_ctable();
    slab_deinit_stable();
}

uint32_t
slab_msinfo_nalloc(void)
{
    return nmslab;
}

uint32_t
slab_msinfo_nfree(void)
{
    return nfree_msinfoq;
}

uint32_t
slab_msinfo_nfull(void)
{
    return nfull_msinfoq;
}

uint32_t
slab_msinfo_npartial(void)
{
    return nmslab - nfree_msinfoq - nfull_msinfoq;
}

uint32_t
slab_dsinfo_nalloc(void)
{
    return ndslab;
}

uint32_t
slab_dsinfo_nfree(void)
{
    return nfree_dsinfoq;
}

uint32_t
slab_dsinfo_nfull(void)
{
    return nfull_dsinfoq;
}

uint64_t
slab_nevict(void)
{
    return nevict;
}

uint8_t
slab_max_cid(void)
{
    return nctable;
}

uint8_t
slab_get_cid(uint32_t sid)
{
    ASSERT(sid < nstable);
    return stable[sid].cid;
}

struct slabclass *
slab_get_class_by_cid(uint8_t cid)
{
    if (cid > nctable) {
        return NULL;
    }
    return &ctable[cid];
}

bool
slab_incr_chunks_by_sid(uint32_t sid, int n)
{
    struct slabinfo*sinfo;
    struct slabclass *c;

    sinfo = &stable[sid];
    if (sinfo == NULL) {
        return false;
    }
    c = &ctable[sinfo->cid];
    c->nused_item += n;
    return true;
}
