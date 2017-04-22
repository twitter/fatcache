#include <fc.h>
#include <stdio.h>
#include <stdlib.h>
int put(char* key, int nkey, char* value, int vlen, int expiry, int flags);
int get(char* key, int nkey, char* value);
int delete(char* key, int nkey);
int num(char *src_key, int src_key_len, int num, int expiry, int flags);
int put(char* key, int nkey, char* value, int vlen, int expiry, int flags){
    uint8_t  md[20];
    uint32_t hash;

    uint8_t * tmp_key = (uint8_t*)key;
    sha1(tmp_key, nkey, md);
    hash = sha1_hash(md);
    uint8_t cid;
    struct item *it;
    
    cid = item_slabcid(nkey, vlen);
    if (cid == SLABCLASS_INVALID_ID) {
        return -1;
    }

    itemx_removex(hash, md);
    it = item_get(tmp_key, nkey, cid, vlen, time_reltime(expiry),
                  flags, md, hash);
    if (it == NULL) {
        return -2;
    }
    memcpy(item_data(it), value, (size_t)(vlen));
    return 0;
}

int get(char* key, int nkey, char* value){
    uint8_t  md[20];
    uint32_t hash;

    struct itemx *itx;
    struct item *it;

    uint8_t * tmp_key = (uint8_t*)key;
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
    uint8_t * tmp_key = (uint8_t*)key;
    sha1(tmp_key, nkey, md);
    hash = sha1_hash(md);
    
    //uint8_t cid;
    struct itemx *itx;

    itx = itemx_getx(hash, md);
    if (itx == NULL) {
        // rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return 0;
    }
    //cid = slab_get_cid(itx->sid);
    itemx_removex(hash, md);   
    return 0;
}

int num(char *src_key, int src_key_len, int num, int expiry, int flags){
    rstatus_t status;
    uint8_t *pkey, nkey, cid;
    struct item *it;
    struct itemx *itx;
    uint64_t cnum;
    int64_t nnum;
    char numstr[FC_UINT64_MAXLEN];
    int n;
    
    pkey = (uint8_t *)src_key;
    nkey = (uint8_t)(src_key_len);

    uint8_t  md[20];
    uint32_t hash;
    sha1(pkey, nkey, md);
    hash = sha1_hash(md);
    
    /* 1). look up existing itemx */
    itx = itemx_getx(hash, md);
    if (itx == NULL || itemx_expired(itx)) {
        /* 2a). miss -> return NOT_FOUND */
        //rsp_send_status(ctx, conn, msg, MSG_RSP_NOT_FOUND);
        return -1;
    }

    /* 2b). hit -> read existing item into it */
    it = slab_read_item(itx->sid, itx->offset);
    if (it == NULL) {
        //rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, errno);
        return -2;
    }

    /* 3). sanity check item data to be a number */
    status = fc_atou64(item_data(it), it->ndata, &cnum);
    if (status != FC_OK) {
        //rsp_send_error(ctx, conn, msg, MSG_RSP_CLIENT_ERROR, EINVAL);
        return -3;
    }

    /* 4). remove existing itemx of it */
    itemx_removex(hash, md);

    /* 5). compute the new incr/decr number nnum and numstr */
    nnum = cnum + num;
    if (nnum<0)
        nnum = 0;
    n = _scnprintf(numstr, sizeof(numstr), "%"PRIu64"", (uint64_t)nnum);

    /* 6). alloc new item that can hold n worth of bytes */
    cid = item_slabcid(nkey, n);
    ASSERT(cid != SLABCLASS_INVALID_ID);

    it = item_get(pkey, nkey, cid, n, time_reltime(expiry), flags,
                   md, hash);
    if (it == NULL) {
        //rsp_send_error(ctx, conn, msg, MSG_RSP_SERVER_ERROR, ENOMEM);
        return -2;
    }

    /* 7). copy numstr to it */
    memcpy(item_data(it), numstr, n);
    return 0;
}
int main(int argc, char** argv){
    char key[5]= "testk";
    char *value=NULL;
    char *ret=NULL;
    if (argc < 2){
        printf("%s <dev> [test value]\n", argv[0]);
        return 0;
    }

    settings_t t_s;
    t_s.log_filename = "fclog";
    t_s.verbose = 11;
    t_s.ssd_device = argv[1];
    t_s.max_index_memory = 64*1024*1024;
    t_s.max_slab_memory = 64*1024*1024;
    t_s.factor = 1.1;
    
    set_options(&t_s);
    fc_generate_profile();
    fc_init();
    if (argc > 2){
        printf("test value: %s\n", argv[2]);
        value = malloc((strlen(argv[2])+1) * sizeof(char));
        ret = malloc((strlen(argv[2])+1) * sizeof(char));
        memset(value, 0, (strlen(argv[2])+1) * sizeof(char));
        memcpy(value, argv[2], strlen(argv[2]));
    }else{
        ret = malloc(10 * sizeof(char));
        value = malloc(10 * sizeof(char));
        memcpy(value, "testv", 5);
        
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
        printf("after delete, no data\n");
    }
    printf("start check add count\n");
    if (put(key, 5, value, strlen(value), 0, 1) == 0){
        printf("set data ok\n");
    }
    if (get(key, 5, ret) == 1){
        printf("error, no data\n");
    }else{
        printf("get data: %s\n", ret);
    }
    if (num(key, 5, 12, 0, 1) == 0){
        printf("num data ok\n");
    }
    if (get(key, 5, ret) == 0){
        printf("get data: %s\n", ret);
    }
    return 0;
}
