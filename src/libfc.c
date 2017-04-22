#include <fc_common.h>
#include <fc_log.h>
#include <fc.h>
struct settings settings;          /* fatcache settings */

void set_options(settings_t* s){
    settings.daemonize = FC_DAEMONIZE;
    
    settings.log_filename = FC_LOG_FILE;
    settings.verbose = FC_LOG_DEFAULT;

    settings.port = FC_PORT;
    settings.addr = FC_ADDR;
    settings.hash_power = FC_HASH_POWER;

    settings.factor = FC_FACTOR;
    settings.max_index_memory = FC_INDEX_MEMORY;
    settings.max_slab_memory = FC_SLAB_MEMORY;
    settings.chunk_size = FC_CHUNK_SIZE;
    settings.slab_size = FC_SLAB_SIZE;

    memset(settings.profile, 0, sizeof(settings.profile));
    settings.profile_last_id = SLABCLASS_MAX_ID;

    settings.ssd_device = NULL;

    settings.server_id = FC_SERVER_ID;
    settings.server_n = FC_SERVER_N;
    // use config
    if (s == NULL)
        return;
    settings.log_filename = s->log_filename;
    settings.verbose = s->verbose;
    settings.ssd_device = s->ssd_device;
    settings.max_index_memory = s->max_index_memory;
    settings.max_slab_memory = s->max_slab_memory;
    settings.factor = s->factor;
    return;
}

rstatus_t
fc_generate_profile(void)
{
    size_t *profile = settings.profile; /* slab profile */
    uint8_t id;                         /* slab class id */
    size_t item_sz, last_item_sz;       /* current and last item chunk size */
    size_t min_item_sz, max_item_sz;    /* min and max item chunk size */

    ASSERT(settings.chunk_size % FC_ALIGNMENT == 0);
    ASSERT(settings.chunk_size <= slab_data_size());

    min_item_sz = settings.chunk_size;
    max_item_sz = slab_data_size();
    id = SLABCLASS_MIN_ID;
    item_sz = min_item_sz;

    while (id < SLABCLASS_MAX_ID && item_sz < max_item_sz) {
        /* save the cur item chunk size */
        last_item_sz = item_sz;
        profile[id] = item_sz;
        id++;

        /* get the next item chunk size */
        item_sz *= settings.factor;
        if (item_sz == last_item_sz) {
            item_sz++;
        }
        item_sz = FC_ALIGN(item_sz, FC_ALIGNMENT);
    }

    /* last profile entry always has a 1 item/slab of maximum size */
    profile[id] = max_item_sz;
    settings.profile_last_id = id;
    settings.max_chunk_size = max_item_sz;

    return FC_OK;
}

rstatus_t fc_init(){
    rstatus_t status;

    status = log_init(settings.verbose, settings.log_filename);
    if (status != FC_OK) {
        return status;
    }
    
    status = time_init();
    if (status != FC_OK) {
        return status;
    }
    
    status = itemx_init();
    if (status != FC_OK) {
        return status;
    }
    
    item_init();

    status = slab_init();
    if (status != FC_OK) {
        return status;
    }

    return FC_OK;
}
