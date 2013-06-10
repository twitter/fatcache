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

#include <libaio.h>
#include <sys/eventfd.h>

extern struct settings settings;

static io_context_t io_ctx;
static int evfd;

rstatus_t
aio_init(struct context *ctx)
{
    int i;

    io_ctx = 0;
    i = io_queue_init(512 /* settings.? */, &io_ctx);
    if (i) {
        errno = -i;
        log_error("aio: io_setup failed: %s", strerror(errno));
        return FC_ERROR;
    }

    evfd = eventfd(0, EFD_NONBLOCK);
    if (evfd == -1) {
        io_queue_release(io_ctx);
        log_error("aio: eventfd failed: %s", strerror(errno));
        return FC_ERROR;
    }

    i = event_add_fd(ctx->ep, evfd);
    if (i) {
        aio_deinit();
        return FC_ERROR;
    }

    return FC_OK;
}

void
aio_deinit(void)
{
    io_queue_release(io_ctx);
    close(evfd);
}

void
aio_process(void)
{
    uint64_t nevents;

    if (read(evfd, &nevents, sizeof(nevents)) != sizeof(nevents)) {
        log_error("aio: aio_process failed on read from evfd: %s", strerror(errno));
        return;
    }

    log_debug(LOG_VERB, "aio: %ld i/o events finished", nevents);

    /* io_queue_run will consume more than nevents events and will not
     * tell us how many events are consumed, so we will just call io_getevents
     * directly */
    while (nevents > 0) {
        struct io_event event;
        struct timespec ts = { 0, 0 };
        io_callback_t cb;

        int i = io_getevents(io_ctx, 0, 1, &event, &ts);
        if (i < 0) {
            errno = -i;
            log_error("aio: process failed running queue: %s", strerror(errno));
            return;
        }
        else if (i == 0) {
            log_error("aio: io_getevents finished but there are still %ld events left?", nevents);
            return;
        }

        cb = event.data;
        cb(io_ctx, event.obj, event.res, event.res2);

        ASSERT(i <= nevents);
        nevents -= i;
    }
}

static void libaio_callback(io_context_t ctx, struct iocb *iocb, long res, long res2)
{
    struct aio_op *op = (struct aio_op *) iocb;
    struct aio_op *nop, *nnop;

    ASSERT(ctx == io_ctx);
    ASSERT(&op->iocb == iocb);

    log_debug(LOG_DEBUG, "aio: result came back for %p, res: %lu", op, res);

    if (iocb->u.c.nbytes != res) {
        log_error("aio: incomplete operation for %p! %lu != %lu", iocb, iocb->u.c.nbytes, res);
        res = -1;
    }

    if (op->callback != NULL) {
        op->callback(op, res, op->mem);
    }

    op->processing = false;

    /* notify clients waiting on this event that it has finished.
     * note we iterate from end->beginning so that objects added
     * during iteration are added from the end->on, preventing us
     * from iterating them
     */
    TAILQ_FOREACH_REVERSE_SAFE(nop, &op->waiting, waiting_queue, waiting_entry, nnop) {
        ASSERT(nop->waiting_op == op);

        log_debug(LOG_VVERB, "aio: notifying op %p", nop);

        aio_op_remove(op, nop);

        if (nop->waiting_callback != NULL) {
            nop->waiting_callback(nop, op, nop->waiting_data);
        }
    }

    log_debug(LOG_VVERB, "aio: done notifying");
}

rstatus_t
aio_write(struct aio_op *op, int fd, void *buf, size_t size, long long offset, aio_callback cb)
{
    struct iocb *iocb = &op->iocb;

    ASSERT(op->mem != NULL);
    ASSERT(size > 0 && size <= settings.slab_size);
    ASSERT(op->processing == false);

    aio_op_detach(op);

    log_debug(LOG_DEBUG, "aio: write request for %p on %d with %p (%d bytes) at offset %ld", op, fd, buf, size, offset);

    fc_memcpy(op->mem, buf, size);
    op->callback = cb;

    io_prep_pwrite(iocb, fd, op->mem, size, offset);
    io_set_eventfd(iocb, evfd);
    io_set_callback(iocb, libaio_callback);

    if (io_submit(io_ctx, 1, &iocb) != 1) {
        log_error("aio: write failed: %s", strerror(errno));
        return FC_ERROR;
    }

    op->processing = true;

    return FC_OK;
}

rstatus_t
aio_read(struct aio_op *op, int fd, size_t size, long long offset, aio_callback cb)
{
    struct iocb *iocb = &op->iocb;

    ASSERT(op->mem != NULL);
    ASSERT(size > 0 && size <= settings.slab_size);
    ASSERT(op->processing == false);

    aio_op_detach(op);

    log_debug(LOG_DEBUG, "aio: read request for %p on %d with %d bytes at offset %ld", op, fd, size, offset);

    op->callback = cb;

    io_prep_pread(iocb, fd, op->mem, size, offset);
    io_set_eventfd(iocb, evfd);
    io_set_callback(iocb, libaio_callback);

    if (io_submit(io_ctx, 1, &iocb) != 1) {
        log_error("aio: read failed: %s", strerror(errno));
        return FC_ERROR;
    }

    op->processing = true;

    return FC_OK;
}

void
aio_cancel(struct aio_op *op)
{
    struct io_event event;
    struct aio_op *nop, *nnop;

    log_debug(LOG_DEBUG, "aio: canceling %p", op);

    if (op->processing) {
        io_cancel(io_ctx, &op->iocb, &event);
        op->processing = false;
    }

    aio_op_detach(op);

    if (op->waiting_op != NULL) {
        aio_op_remove(op->waiting_op, op);
    }

    TAILQ_FOREACH_REVERSE_SAFE(nop, &op->waiting, waiting_queue, waiting_entry, nnop) {
        ASSERT(nop->waiting_op == op);

        log_debug(LOG_VVERB, "aio: notifying op %p", nop);

        aio_op_remove(op, nop);

        if (nop->waiting_callback != NULL) {
            nop->waiting_callback(nop, op, nop->waiting_data);
        }
    }
}

rstatus_t
aio_op_init(struct aio_op *op)
{
    memset(op, 0, sizeof(struct aio_op));

    op->mem = fc_mmap(settings.slab_size);
    TAILQ_INIT(&op->waiting);

    if (op->mem == NULL) {
        return FC_ENOMEM;
    }

    return FC_OK;
}

void
aio_op_free(struct aio_op *op)
{
    aio_cancel(op);
    fc_munmap(op->mem, settings.slab_size);
    op->mem = NULL;
}

void
aio_op_set_callback(struct aio_op *op, aio_operation_callback cb, void *data)
{
    op->waiting_callback = cb;
    op->waiting_data = data;
}

void
aio_op_depend(struct aio_op *waiting_on, struct aio_op *notify)
{
    ASSERT(notify->waiting_op == NULL);

    TAILQ_INSERT_TAIL(&waiting_on->waiting, notify, waiting_entry);

    notify->waiting_op = waiting_on;
}

void
aio_op_remove(struct aio_op *waiting_on, struct aio_op *notify)
{
    ASSERT(notify->waiting_op == waiting_on);

    TAILQ_REMOVE(&waiting_on->waiting, notify, waiting_entry);

    notify->waiting_op = NULL;
}

void
aio_op_detach(struct aio_op *op)
{
    switch (op->type)
    {
        case OP_READ:
            ASSERT(op->read_si->op == op);

            op->read_si->op = NULL;
            op->read_si = NULL;
            break;
        case OP_DRAIN:
            ASSERT(op->drain.msinfo != NULL);
            ASSERT(op->drain.dsinfo != NULL);
            ASSERT(op->drain.sc != NULL);

            ASSERT(op->drain.msinfo->op == op);
            ASSERT(op->drain.dsinfo->op == op);
            ASSERT(op->drain.sc->drain_op == op);

            op->drain.msinfo->op = NULL;
            op->drain.dsinfo->op = NULL;
            op->drain.sc->drain_op = NULL;

            op->drain.msinfo = NULL;
            op->drain.dsinfo = NULL;
            op->drain.sc = NULL;
            break;
        case OP_EVICT:
            ASSERT(op->evict.sc->evict_op == op);

            op->evict.sc->evict_op = NULL;
            op->evict.sc = NULL;
            break;
    }

    op->type = OP_NONE;
}
