#ifndef _FC_H_
#define _FC_H_

#include <fc_common.h>
#include <fc_queue.h>

#include <fc_sha1.h>
#include <fc_time.h>
#include <fc_util.h>

#include <fc_slab.h>
#include <fc_itemx.h>
#include <fc_item.h>
#include <fc_settings.h>

#define FC_CHUNK_SIZE       ITEM_CHUNK_SIZE
#define FC_SLAB_SIZE        SLAB_SIZE

#define FC_DAEMONIZE        true

#define FC_LOG_FILE         NULL
#define FC_LOG_DEFAULT      LOG_INFO
#define FC_LOG_MIN          LOG_EMERG
#define FC_LOG_MAX          LOG_PVERB

#define FC_PORT             11211
#define FC_ADDR             "0.0.0.0"

#define FC_HASH_POWER       ITEMX_HASH_POWER

#define FC_FACTOR           1.25

#define FC_INDEX_MEMORY     (64 * MB)
#define FC_SLAB_MEMORY      (64 * MB)

#define FC_SERVER_ID        0
#define FC_SERVER_N         1

void set_options(settings_t* s);
rstatus_t fc_generate_profile(void);
rstatus_t fc_init();

#endif
