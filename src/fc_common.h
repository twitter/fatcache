#ifndef _FC_COMMON_H_
#define _FC_COMMON_H_

#define FC_OK        0
#define FC_ERROR    -1
#define FC_EAGAIN   -2
#define FC_ENOMEM   -3

typedef int rstatus_t; /* return type */
typedef int err_t;     /* error type */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/mman.h>


#endif
