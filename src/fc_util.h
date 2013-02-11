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

#ifndef _FC_UTIL_H_
#define _FC_UTIL_H_

#include <stdarg.h>

#define LF              (uint8_t) 10
#define CR              (uint8_t) 13
#define CRLF            "\r\n"
#define CRLF_LEN        (uint32_t) (sizeof(CRLF) - 1)

#define NELEMS(a)       ((sizeof(a)) / sizeof((a)[0]))

#define KB              (1024)
#define MB              (1024 * KB)
#define GB              (1024 * MB)

#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))

#define SQUARE(d)           ((d) * (d))
#define VAR(s, s2, n)       (((n) < 2) ? 0.0 : ((s2) - SQUARE(s)/(n)) / ((n) - 1))
#define STDDEV(s, s2, n)    (((n) < 2) ? 0.0 : sqrt(VAR((s), (s2), (n))))

#define FC_INET4_ADDRSTRLEN (sizeof("255.255.255.255") - 1)
#define FC_INET6_ADDRSTRLEN \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define FC_INET_ADDRSTRLEN  MAX(FC_INET4_ADDRSTRLEN, FC_INET6_ADDRSTRLEN)
#define FC_UNIX_ADDRSTRLEN  \
    (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#define FC_MAXHOSTNAMELEN   256

/*
 * Length of 1 byte, 2 bytes, 4 bytes, 8 bytes and largest integral
 * type (uintmax_t) in ascii, including the null terminator '\0'
 *
 * From stdint.h, we have:
 * # define UINT8_MAX	(255)
 * # define UINT16_MAX	(65535)
 * # define UINT32_MAX	(4294967295U)
 * # define UINT64_MAX	(__UINT64_C(18446744073709551615))
 */
#define FC_UINT8_MAXLEN     (3 + 1)
#define FC_UINT16_MAXLEN    (5 + 1)
#define FC_UINT32_MAXLEN    (10 + 1)
#define FC_UINT64_MAXLEN    (20 + 1)
#define FC_UINTMAX_MAXLEN   FC_UINT64_MAXLEN

/* timeval to seconds */
#define TV_TO_SEC(_tv)  ((_tv)->tv_sec + (1e-6 * (_tv)->tv_usec))

/*
 * Make data 'd' or pointer 'p', n-byte aligned, where n is a power of 2
 * of 2.
 */
#define FC_ALIGNMENT        sizeof(unsigned long) /* platform word */
#define FC_ALIGN(d, n)      ((size_t)(((d) + (n - 1)) & ~(n - 1)))
#define FC_ALIGN_PTR(p, n)  \
    (void *) (((uintptr_t) (p) + ((uintptr_t) n - 1)) & ~((uintptr_t) n - 1))

/*
 * Return 'x' rounded up to the nearest multiple of 'step'. Only valid
 * for x >= 0, step >= 1.
 */
#define ROUND_UP(x, step)   (((x) + (step) - 1) / (step) * (step))

/*
 * Return 'x' rounded down to the nearest multiple of step. Only valid
 * for x >= 0, step >= 1.
 */
#define ROUND_DOWN(x, step) ((x) / (step) * (step))

/*
 * Memory allocation and free wrappers.
 *
 * These wrappers enables us to loosely detect double free, dangling
 * pointer access and zero-byte alloc.
 */
#define fc_alloc(_s)                    \
    _fc_alloc((size_t)(_s), __FILE__, __LINE__)

#define fc_zalloc(_s)                   \
    _fc_zalloc((size_t)(_s), __FILE__, __LINE__)

#define fc_calloc(_n, _s)               \
    _fc_calloc((size_t)(_n), (size_t)(_s), __FILE__, __LINE__)

#define fc_realloc(_p, _s)              \
    _fc_realloc(_p, (size_t)(_s), __FILE__, __LINE__)

#define fc_free(_p) do {                \
    _fc_free(_p, __FILE__, __LINE__);   \
    (_p) = NULL;                        \
} while (0)

#define fc_mmap(_s)                     \
    _fc_mmap((size_t)(_s), __FILE__, __LINE__)

#define fc_munmap(_p, _s)               \
    _fc_munmap(_p, (size_t)(_s), __FILE__, __LINE__)

void *_fc_alloc(size_t size, const char *name, int line);
void *_fc_zalloc(size_t size, const char *name, int line);
void *_fc_calloc(size_t nmemb, size_t size, const char *name, int line);
void *_fc_realloc(void *ptr, size_t size, const char *name, int line);
void _fc_free(void *ptr, const char *name, int line);
void *_fc_mmap(size_t size, const char *name, int line);
int _fc_munmap(void *p, size_t size, const char *name, int line);

/*
 * Wrapper to workaround well known, safe, implicit type conversion when
 * invoking system calls.
 */
#define fc_gethostname(_name, _len) \
    gethostname((char *)_name, (size_t)_len)

#define fc_atoi(_line, _n)          \
    _fc_atoi((uint8_t *)_line, (size_t)_n)

#define fc_atou32(_line, _n, _u32)  \
    _fc_atou32((uint8_t *)_line, (size_t)_n, _u32)

#define fc_atou64(_line, _n, _u64)  \
    _fc_atou64((uint8_t *)_line, (size_t)_n, _u64)

int _fc_atoi(uint8_t *line, size_t n);
rstatus_t _fc_atou32(uint8_t *line, size_t n, uint32_t *u32);
rstatus_t _fc_atou64(uint8_t *line, size_t n, uint64_t *u64);
bool fc_valid_port(int n);

int fc_set_blocking(int sd);
int fc_set_nonblocking(int sd);
int fc_set_directio(int fd);
int fc_set_reuseaddr(int sd);
int fc_set_tcpnodelay(int sd);
int fc_set_keepalive(int sd);
int fc_set_linger(int sd, int timeout);
int fc_unset_linger(int sd);
int fc_set_sndbuf(int sd, int size);
int fc_set_rcvbuf(int sd, int size);
int fc_get_soerror(int sd);
int fc_get_sndbuf(int sd);
int fc_get_rcvbuf(int sd);
void fc_maximize_sndbuf(int sd);
int64_t fc_usec_now(void);
rstatus_t fc_device_size(const char *path, size_t *size);

/*
 * Wrappers to read or write data to/from (multiple) buffers
 * to a file or socket descriptor.
 */
#define fc_read(_d, _b, _n)     \
    read(_d, _b, (size_t)(_n))

#define fc_readv(_d, _b, _n)    \
    readv(_d, _b, (int)(_n))

#define fc_write(_d, _b, _n)    \
    write(_d, _b, (size_t)(_n))

#define fc_writev(_d, _b, _n)   \
    writev(_d, _b, (int)(_n))

/*
 * Wrappers around strtoull, strtoll, strtoul, strtol that are safer and
 * easier to use. Returns true if conversion succeeds.
 */
bool fc_strtoull(const char *str, uint64_t *out);
bool fc_strtoll(const char *str, int64_t *out);
bool fc_strtoul(const char *str, uint32_t *out);
bool fc_strtol(const char *str, int32_t *out);
bool fc_str2oct(const char *str, int32_t *out);

/*
 * Wrappers for defining custom assert based on whether macro
 * FC_ASSERT_PANIC or FC_ASSERT_LOG was defined at the moment
 * ASSERT was called.
 */
#if defined FC_ASSERT_PANIC && FC_ASSERT_PANIC == 1

#define ASSERT(_x) do {                         \
    if (!(_x)) {                                \
        fc_assert(#_x, __FILE__, __LINE__, 1);  \
    }                                           \
} while (0)

#define NOT_REACHED() ASSERT(0)

#elif defined FC_ASSERT_LOG && FC_ASSERT_LOG == 1

#define ASSERT(_x) do {                         \
    if (!(_x)) {                                \
        fc_assert(#_x, __FILE__, __LINE__, 0);  \
    }                                           \
} while (0)

#define NOT_REACHED() ASSERT(0)

#else

#define ASSERT(_x)

#define NOT_REACHED()

#endif

void fc_stacktrace(int skip_count);
void fc_assert(const char *cond, const char *file, int line, int panic);

int _scnprintf(char *buf, size_t size, const char *fmt, ...);
int _vscnprintf(char *buf, size_t size, const char *fmt, va_list args);

/*
 * Address resolution for internet (ipv4 and ipv6) and unix domain
 * socket address.
 */
struct sockinfo {
    int       family;              /* socket address family */
    socklen_t addrlen;             /* socket address length */
    union {
        struct sockaddr_in  in;    /* ipv4 socket address */
        struct sockaddr_in6 in6;   /* ipv6 socket address */
        struct sockaddr_un  un;    /* unix domain address */
    } addr;
};

int fc_resolve(struct string *name, int port, struct sockinfo *si);

#endif
