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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fc_stats.h>

static stats_info st_info;
static stats_info sc_st_info[SLABCLASS_MAX_ID+1];
struct settings settings;

buffer *
stats_alloc_buffer(int n)
{
    if (n <= 0) n = 128;

    buffer *buf = fc_alloc(sizeof(*buf));
    buf->data = fc_alloc(n);
    buf->nused = 0;
    buf->nalloc = n;
    return buf;
}

void
stats_dealloc_buffer(buffer *buf)
{
    if (!buf) return;

    if (buf->data) fc_free(buf->data);
    fc_free(buf);
}

static void
_stats_append(buffer *buf, uint8_t cid, const char *key, int nkey, const char *val, int nval)
{
    int n, new_size, avail, bytes = 0;
    uint8_t *new;
    
    if (!buf) {
        return;
    }

    n = nkey + nval + 14; // +14 for "STAT :class \r\n"
    if (!buf->data) {
        buf->data = fc_alloc(n);
        buf->nused = 0;
        buf->nalloc = n;
    } else if (buf->nalloc - buf->nused < n) {
        new_size = buf->nalloc > n ? buf->nalloc * 2 :  buf->nalloc + 2 * n;
        new = fc_realloc(buf->data, new_size);
        if (new == NULL) {
            return;
        }
        buf->data = new;
        buf->nalloc = new_size;
    }

    avail = buf->nalloc - buf->nused;
    if (nkey == 0 && nval == 0) {
        bytes = fc_snprintf(buf->data + buf->nused, avail - 1, "END\r\n"); 
    } else if (nval == 0) {
        if (cid == SLABCLASS_INVALID_ID) {
            bytes = fc_snprintf(buf->data + buf->nused, avail - 1, "STAT %s\r\n", key);
        } else {
            bytes = fc_snprintf(buf->data + buf->nused, avail - 1, "STAT %u:%s\r\n", cid, key);
        }
    } else if (nkey > 0 && nval > 0) {
        if (cid == SLABCLASS_INVALID_ID) {
            bytes = fc_snprintf(buf->data + buf->nused, avail - 1, "STAT %s %s\r\n", key, val);
        } else {
            bytes = fc_snprintf(buf->data + buf->nused, avail - 1, "STAT %u:%s %s\r\n", cid, key, val);
        }
    }
    buf->nused += bytes;
    buf->data[buf->nused] = '\0';
}

void
stats_append(buffer *buf, uint8_t cid, const char*name, const char *fmt, ...)
{
    int n;
    va_list ap;
    char val[128];

    if (name && fmt) {
        va_start(ap, fmt);
        n = vsnprintf(val, sizeof(val) - 1, fmt, ap);
        va_end(ap);
        _stats_append(buf, cid, name, strlen(name), val, n);
    } else {
        _stats_append(buf, cid, NULL, 0, NULL, 0);
    }
}

uint64_t
stats_get(uint8_t cid, msg_type_t type, int is_miss)
{
    stats_info *info;

    info = cid == SLABCLASS_INVALID_ID ? &st_info : &sc_st_info[cid];

    switch(type) {
        case MSG_REQ_GET:
        case MSG_REQ_GETS:
            return is_miss? info->get - info->get_hits : info->get;
        case MSG_REQ_SET:
        case MSG_REQ_ADD:
        case MSG_REQ_APPEND:
        case MSG_REQ_PREPEND:
        case MSG_REQ_REPLACE:
            return info->set;
        case MSG_REQ_DELETE:
            return is_miss ? info->del - info->del_hits : info->del;
        case MSG_REQ_INCR:
            return is_miss ? info->incr - info->incr_hits : info->incr;
        case MSG_REQ_DECR:
            return is_miss ? info->decr - info->decr_hits : info->decr;
        case MSG_REQ_CAS:
            return is_miss ? info->cas - info->cas_hits : info->cas;
        default:
            return 0;
    }
}

void
stats_incr(uint8_t cid, msg_type_t type, int is_hit)
{
    stats_info *info;

    info = cid == SLABCLASS_INVALID_ID ? &st_info : &sc_st_info[cid];

    switch(type) {
    case MSG_REQ_GET:
    case MSG_REQ_GETS:
        is_hit ? info->get_hits++ : info->get++;
        break; 
    case MSG_REQ_SET:
    case MSG_REQ_ADD:
    case MSG_REQ_APPEND:
    case MSG_REQ_PREPEND:
    case MSG_REQ_REPLACE:
        info->set++;
        break;
    case MSG_REQ_DELETE:
        is_hit ? info->del_hits++ : info->del++;
        break;
    case MSG_REQ_INCR:
        is_hit ? info->incr_hits++ : info->incr++;
        break;
    case MSG_REQ_DECR:
        is_hit ? info->decr_hits++ : info->decr++;
        break;
    case MSG_REQ_CAS:
        is_hit ? info->cas_hits++ : info->cas++;
        break;
    default:
        break;
    }
}

buffer*
stats_server(void)
{
    buffer *stats_buf;

    stats_buf = stats_alloc_buffer(1024);
    if (stats_buf == NULL) {
        return NULL;
    }

    APPEND_STAT(stats_buf, "pid", "%u", getpid());
    APPEND_STAT(stats_buf, "uptime", "%u", time_started());
    APPEND_STAT(stats_buf, "version", "%s", FC_VERSION_STRING);
    APPEND_STAT(stats_buf, "pointer_size", "%u", sizeof(void*));
    APPEND_STAT(stats_buf, "curr_connection", "%u", conn_nused());
    APPEND_STAT(stats_buf, "free_connection", "%u", conn_nfree());
    APPEND_STAT(stats_buf, "total_connection", "%u", conn_total());
    APPEND_STAT(stats_buf, "cmd_get", "%llu", STATS_GET(MSG_REQ_GET));
    APPEND_STAT(stats_buf, "cmd_get_miss", "%llu", STATS_GET_MISS(MSG_REQ_GET));
    APPEND_STAT(stats_buf, "cmd_set", "%llu", STATS_GET(MSG_REQ_SET));
    APPEND_STAT(stats_buf, "cmd_del", "%llu", STATS_GET(MSG_REQ_DELETE));
    APPEND_STAT(stats_buf, "cmd_del_miss", "%llu", STATS_GET_MISS(MSG_REQ_DELETE));
    APPEND_STAT(stats_buf, "cmd_decr", "%llu", STATS_GET(MSG_REQ_DECR));
    APPEND_STAT(stats_buf, "cmd_decr_miss", "%llu", STATS_GET_MISS(MSG_REQ_DECR));
    APPEND_STAT(stats_buf, "cmd_incr", "%llu", STATS_GET(MSG_REQ_INCR));
    APPEND_STAT(stats_buf, "cmd_incr_miss", "%llu", STATS_GET_MISS(MSG_REQ_INCR));
    APPEND_STAT(stats_buf, "cmd_cas", "%llu", STATS_GET(MSG_REQ_CAS));
    APPEND_STAT(stats_buf, "cmd_cas_miss", "%llu", STATS_GET_MISS(MSG_REQ_CAS));
    APPEND_STAT(stats_buf, "alloc_itemx", "%llu", itemx_nalloc());
    APPEND_STAT(stats_buf, "free_itemx", "%llu", itemx_nfree());
    APPEND_STAT(stats_buf, "total_mem_slab", "%u", slab_msinfo_nalloc());
    APPEND_STAT(stats_buf, "free_mem_slab", "%u", slab_msinfo_nfree());
    APPEND_STAT(stats_buf, "full_mem_slab", "%u", slab_msinfo_nfull());
    APPEND_STAT(stats_buf, "partial_mem_slab", "%u", slab_msinfo_npartial());
    APPEND_STAT(stats_buf, "total_disk_slab", "%u", slab_dsinfo_nalloc());
    APPEND_STAT(stats_buf, "free_disk_slab", "%u", slab_dsinfo_nfree());
    APPEND_STAT(stats_buf, "full_disk_slab", "%u", slab_dsinfo_nfull());
    APPEND_STAT(stats_buf, "evict_time", "%llu", slab_nevict());
    APPEND_STAT_END(stats_buf);

    return stats_buf;
}

buffer*
stats_slabs(void)
{
    buffer *stats_buf;
    uint8_t cid, max_cid;
    uint64_t nget, nset, ndel, nincr, ndecr, ncas ;
    struct slabclass *sc;

    stats_buf = stats_alloc_buffer(512);
    if (stats_buf == NULL) {
        return NULL;
    }
    
    max_cid = slab_max_cid();
    for (cid = SLABCLASS_MIN_ID; cid < max_cid; cid++) {
        sc = slab_get_class_by_cid(cid);
        if (!sc) continue;

        nget = SC_STATS_GET(cid, MSG_REQ_GET);
        nset = SC_STATS_GET(cid, MSG_REQ_SET);
        ndel = SC_STATS_GET(cid, MSG_REQ_DELETE);
        ndecr = SC_STATS_GET(cid, MSG_REQ_DECR);
        nincr = SC_STATS_GET(cid, MSG_REQ_INCR);
        ncas = SC_STATS_GET(cid, MSG_REQ_CAS);
        if (sc->nmslab == 0 && sc->ndslab == 0 && sc->nevict == 0 && nget == 0
            && nset == 0 && ndel == 0 && ndecr == 0 && nincr == 0 && ncas == 0) {
            continue;
        }
        SC_APPEND_STAT(stats_buf, cid, "used_chunks", "%u", sc->nused_item);
        SC_APPEND_STAT(stats_buf, cid, "chunk_size", "%u", sc->size);
        SC_APPEND_STAT(stats_buf, cid, "chunks_per_slab", "%u", sc->nitem);
        SC_APPEND_STAT(stats_buf, cid, "slack", "%u", sc->slack);
        SC_APPEND_STAT(stats_buf, cid, "total_mem_slab", "%u", sc->nmslab);
        SC_APPEND_STAT(stats_buf, cid, "total_disk_slab", "%u", sc->ndslab);
        SC_APPEND_STAT(stats_buf, cid, "total_evict_time", "%lu", sc->nevict);
        SC_APPEND_STAT(stats_buf, cid, "cmd_get", "%llu", nget);
        SC_APPEND_STAT(stats_buf, cid, "cmd_set", "%llu", nset);
        SC_APPEND_STAT(stats_buf, cid, "cmd_del", "%llu", ndel);
        SC_APPEND_STAT(stats_buf, cid, "cmd_decr", "%llu", ndecr);
        SC_APPEND_STAT(stats_buf, cid, "cmd_incr", "%llu", nincr);
        SC_APPEND_STAT(stats_buf, cid, "cmd_cas", "%llu", ncas);
    }
    APPEND_STAT_END(stats_buf);

    return stats_buf;
}

buffer*
stats_settings(void)
{
    buffer *stats_buf;

    stats_buf = stats_alloc_buffer(256);
    if (stats_buf == NULL) {
        return NULL;
    }

    APPEND_STAT(stats_buf, "addr", "%s", settings.addr);
    APPEND_STAT(stats_buf, "port", "%d", settings.port);
    APPEND_STAT(stats_buf, "hash_power", "%d", settings.hash_power);
    APPEND_STAT(stats_buf, "factor", "%f", settings.factor);
    APPEND_STAT(stats_buf, "max_slab_memory", "%u", settings.max_slab_memory);
    APPEND_STAT(stats_buf, "max_index_memory", "%u", settings.max_index_memory);
    APPEND_STAT(stats_buf, "chunk_size", "%u", settings.chunk_size);
    APPEND_STAT(stats_buf, "max_chunk_size", "%u", settings.max_chunk_size);
    APPEND_STAT(stats_buf, "slab_size", "%u", settings.slab_size);
    APPEND_STAT(stats_buf, "ssd_device", "%s", settings.ssd_device);
    APPEND_STAT(stats_buf, "server_id", "%u", settings.server_id);
    APPEND_STAT(stats_buf, "server_count", "%u", settings.server_n);
    APPEND_STAT_END(stats_buf);

    return stats_buf;
}
