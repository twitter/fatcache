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

#ifndef _FC_AIO_H_
#define _FC_AIO_H_

#include <libaio.h>

struct aio_op;

/* called when an aio operation completes
 * op - the operation that completed
 * ret - number of bytes read or written. only > 0 if all requested bytes were successfully read or written
 * buf - for read events, the data read. for write events, a copy of the buffer given to aio_write
 */
typedef void (*aio_callback)(struct aio_op *op, int ret, void *buf);

/*
 * called after an aio operation finishes (not necessarily successfully) that an operation is waiting on
 * using aio_op_depend
 * op - the operation that has been waiting for 'completed' to complete
 * completed - the operation that has completed, which triggered this callback
 * data - data associated with op from aio_op_set_callback
 */
typedef void (*aio_operation_callback)(struct aio_op *op, struct aio_op *completed, void *data);

enum
{
    OP_NONE,
    OP_READ,
    OP_DRAIN,
    OP_EVICT
};

struct aio_op
{
    struct iocb                         iocb;                  /* iocb used by libaio */

    void                                *mem;                  /* buffer this iocb operates on. mmaped() memory */
    aio_callback                        callback;              /* callback that is called once the operation is completed */
    void                                *data;                 /* ptr passed to callback */
    TAILQ_HEAD(waiting_queue, aio_op)   waiting;               /* other operations waiting on this operation to complete */

    struct aio_op                       *waiting_op;           /* i/o operation this operation is waiting on, if any */
    TAILQ_ENTRY(aio_op)                 waiting_entry;         /* entry into waiting_op's waiting list */
    aio_operation_callback              waiting_callback;      /* callback called once 'waiting_op' has completed */
    void                                *waiting_data;         /* data passed to waiting_callback */

    union
    {
        struct slabinfo                 *read_si;              /* the slabinfo (being) read by this operation */
        struct
        {
            struct slabclass            *sc;                   /* the class of the slab being drained */
            struct slabinfo             *msinfo, *dsinfo;      /* memory and disk slabinfo */
        } drain;
        struct
        {
            struct slabclass            *sc;                   /* the class of the slab this operation is evicting */
            struct slabinfo             *info;                 /* the slabinfo being evicted */
        } evict;
    };

    unsigned type:2;                                           /* the type of operation this is */
    bool processing:1;                                         /* true if this operation is running */
};

rstatus_t aio_init(struct context *ctx);
void aio_deinit(void);
void aio_process(void);
/* queues a disk write operation.
 * op - the aio_op to use for writing
 * fd - the fd to write to
 * buf - the buffer to write. this function first copies this buffer, and then writes that
 * size - the size of the buffer
 * offset - file offset to write to
 * cb - optional callback to call once the operation completes
 */
rstatus_t aio_write(struct aio_op *op, int fd, void *buf, size_t size, long long offset, aio_callback cb);
/* queues a disk read operation.
 * op - the aio_op to use for reading
 * fd - the fd to read from
 * size - the size/amount to read
 * offset - file offset to read from
 * cb - optional callback to call once the operation completes
 */
rstatus_t aio_read(struct aio_op *op, int fd, size_t size, long long offset, aio_callback cb);
/* cancel a pending i/o operation. notifies anything waiting on this operation */
void aio_cancel(struct aio_op *op);

/* initialize an aio_op structure */
rstatus_t aio_op_init(struct aio_op *op);
/* free an aio_op structure */
void aio_op_free(struct aio_op *op);

/* sets the callback and data called when the operation 'op' is waiting on completes */
void aio_op_set_callback(struct aio_op *op, aio_operation_callback cb, void *data);
/* makes operation 'notify' wait on 'waiting_on' - its callback (set by aio_op_set_callback)
 * is called when 'waiting_on' completes
 */
void aio_op_depend(struct aio_op *waiting_on, struct aio_op *notify);
/* removes a dependency for an operation */
void aio_op_remove(struct aio_op *waiting_on, struct aio_op *notify);

/* detach an operation from other structures. this essentially frees up the operation's
 * memory to be used for some other purpose. aio_read and aio_write do this automatically.
 */
void aio_op_detach(struct aio_op *op);

#endif
