#ifndef _FC_SETTINGS_H_
#define _FC_SETTINGS_H_
struct settings {
    bool     daemonize;                    /* daemonize? */

    char     *log_filename;                /* log filename */
    int      verbose;                      /* log verbosity level */

    int      port;                         /* listening port */
    char     *addr;                        /* listening address */

    int      hash_power;                   /* index hash table size as power of 2 */

    double   factor;                       /* item chunk size growth factor */
    size_t   max_slab_memory;              /* maximum memory allowed for slabs in bytes */
    size_t   max_index_memory;             /* maximum memory allowed for in bytes */
    size_t   chunk_size;                   /* minimum item chunk size */
    size_t   max_chunk_size;               /* maximum item chunk size */
    size_t   slab_size;                    /* slab size */

    size_t   profile[SLABCLASS_MAX_IDS];   /* slab profile */
    uint8_t  profile_last_id;              /* last id in slab profile */

    char     *ssd_device;                  /* path to ssd device file */

    uint32_t server_id;                    /* server id */
    uint32_t server_n;                     /* # server */
};
#endif //_FC_SETTINGS_H_
