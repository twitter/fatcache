//#include <fc_core.h>
#include <fc_common.h>

#include <fc_queue.h>
#include <fc_log.h>


#include <fc_sha1.h>
#include <fc_time.h>
#include <fc_util.h>

#include <fc_slab.h>
#include <fc_itemx.h>
#include <fc_item.h>
#include <fc_settings.h>

struct settings settings;          /* fatcache settings */

static void set_options(){

#define FC_CHUNK_SIZE       ITEM_CHUNK_SIZE
#define FC_SLAB_SIZE        SLAB_SIZE

#define FC_DAEMONIZE        true

    //#define FC_LOG_FILE         NULL
#define FC_LOG_FILE         "/home/yu/test/log2"
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
    
    settings.daemonize = FC_DAEMONIZE;

    settings.log_filename = FC_LOG_FILE;
    settings.verbose = 11;//FC_LOG_DEFAULT;

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

    settings.ssd_device = "/dev/sdc"; //NULL;

    settings.server_id = FC_SERVER_ID;
    settings.server_n = FC_SERVER_N;
    return;
}

static rstatus_t
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

rstatus_t init(){
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

int put(char* key, int nkey, char* value, int vlen, int expiry, int flags){
    uint8_t  md[20];
    uint32_t hash;

    uint8_t * tmp_key = key;
    sha1(tmp_key, nkey, md);
    hash = sha1_hash(md);
    uint8_t cid;
    struct item *it;
    
    cid = item_slabcid(nkey, vlen);
    if (cid == SLABCLASS_INVALID_ID) {
        return -1;
    }

    itemx_removex(hash, md);
    it = item_get(key, nkey, cid, vlen, time_reltime(expiry),
                  flags, md, hash);
    if (it == NULL) {
        return -1;
    }
    memcpy(item_data(it), value, (size_t)(vlen));
    return 0;
}

int get(char* key, int nkey, char* value){
    uint8_t  md[20];
    uint32_t hash;

    struct itemx *itx;
    struct item *it;

    uint8_t * tmp_key = key;
    sha1(tmp_key, nkey, md);
    hash = sha1_hash(md);
    
    itx = itemx_getx(hash,md);
    if (itx == NULL) {
        return 1;
    }
    if (itemx_expired(itx)) {
        return 2;
    }
    it = slab_read_item(itx->sid, itx->offset);
    if (it == NULL) {
        //        rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, errno);
        return -1;
    }
    memcpy(value, item_data(it), it->ndata);
    return 0;
}
int delete(char* key, int nkey){
    uint8_t  md[20];
    uint32_t hash;
    uint8_t * tmp_key = key;
    sha1(tmp_key, nkey, md);
    hash = sha1_hash(md);
    
    uint8_t cid;
    struct itemx *itx;

    itx = itemx_getx(hash, md);
    if (itx == NULL) {
        // rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return 0;
    }
    cid = slab_get_cid(itx->sid);
    itemx_removex(hash, md);   
    return 0;
}
int main(int argc, char** argv){
    set_options();
    fc_generate_profile();
    init();
    char key[5]= "test1";
    //char value[3]="100";
    char *value=NULL;
    char *ret=NULL;
    int vl = 0;
    if (argc > 1){
        printf("%d", strlen(argv[1]));
        vl =  strlen(argv[1]);
        value = malloc((strlen(argv[1])+1) * sizeof(char));
        ret = malloc((strlen(argv[1])+1) * sizeof(char));
        memcpy(value, argv[1], strlen(argv[1]));
    }else{
        ret = malloc(10 * sizeof(char));
    }
    
    if (get(key, 5, ret) == 1){
        printf("no data\n");
    }
    if (put(key, 5, value, strlen(value), 0, 1) == 0){
        printf("set data ok\n");
    }
    if (get(key, 5, ret) == 0){
        printf("get data %s\n", ret);
    }
    delete(key, 5);
    if (get(key, 5, ret) == 1){
        printf("delete no data\n");
    }
    

    
    return 0;
}
