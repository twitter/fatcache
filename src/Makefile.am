bin_PROGRAMS = fatcache stg_ins_test

AM_CPPFLAGS = -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS = -g
AM_CFLAGS = -Wall
AM_CFLAGS += -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls
AM_CFLAGS += -fno-strict-aliasing
AM_CFLAGS += -Wunused-function -Wunused-value -Wunused-variable

LDFLAGS += -rdynamic

fatcache_SOURCES =			\
	fc_core.c fc_core.h		\
	fc_connection.c fc_connection.h	\
	fc_server.c fc_server.h		\
	fc_client.c fc_client.h		\
	fc_slab.c fc_slab.h		\
	fc_item.c fc_item.h		\
	fc_itemx.c fc_itemx.h		\
	fc_memcache.c fc_memcache.h	\
	fc_message.c fc_message.h	\
	fc_request.c			\
	fc_response.c			\
	fc_mbuf.c fc_mbuf.h		\
	fc_signal.c fc_signal.h		\
	fc_event.c fc_event.h		\
	fc_time.c fc_time.h		\
	fc_sha1.c fc_sha1.h		\
	fc_log.c fc_log.h		\
	fc_string.c fc_string.h		\
	fc_array.c fc_array.h		\
	fc_util.c fc_util.h		\
	fc_stats.c fc_stats.h		\
	fc_queue.h			\
	fc.c

stg_ins_test_SOURCES =			\
	fc_slab.c fc_slab.h		\
	fc_item.c fc_item.h		\
	fc_itemx.c fc_itemx.h		\
	fc_time.c fc_time.h		\
	fc_sha1.c fc_sha1.h		\
	fc_log.c fc_log.h		\
	fc_util.c fc_util.h		\
	fc_queue.h			\
    stg_ins_test.c
