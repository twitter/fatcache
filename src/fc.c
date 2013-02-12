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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <getopt.h>

#include <fc_core.h>

#define FC_CHUNK_SIZE       ITEM_CHUNK_SIZE
#define FC_SLAB_SIZE        SLAB_SIZE

#define FC_DAEMONIZE        false

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

struct settings settings;          /* fatcache settings */
static int show_help;              /* show fatcache help? */
static int show_version;           /* show fatcache version? */
static int show_sizes;             /* show fatcache struct sizes? */
static int parse_profile;          /* parse profile? */
static uint8_t *profile_optarg;    /* profile optarg */

static struct option long_options[] = {
    { "help",                 no_argument,        NULL,   'h' }, /* help */
    { "version",              no_argument,        NULL,   'V' }, /* version */
    { "daemonize",            no_argument,        NULL,   'd' }, /* daemon mode */
    { "show-sizes",           no_argument,        NULL,   'S' }, /* print slab, item and index sizes and exit */
    { "output",               required_argument,  NULL,   'o' }, /* output logfile */
    { "verbosity",            required_argument,  NULL,   'v' }, /* log verbosity level */
    { "port",                 required_argument,  NULL,   'p' }, /* port number to listen on */
    { "addr",                 required_argument,  NULL,   'a' }, /* address to listen on */
    { "hash-power",           required_argument,  NULL,   'e' }, /* item index hash table size as power of two */
    { "factor",               required_argument,  NULL,   'f' }, /* growth factor for slab items */
    { "min-item-chunk-size",  required_argument,  NULL,   'n' }, /* min item chunk size */
    { "slab-size",            required_argument,  NULL,   'I' }, /* slab size in MB */
    { "max-index-memory",     required_argument,  NULL,   'i' }, /* max memory for item index in MB */
    { "max-slab-memory",      required_argument,  NULL,   'm' }, /* max memory for slab in MB */
    { "slab-profile",         required_argument,  NULL,   'z' }, /* profile of slab item sizes */
    { "ssd-device",           required_argument,  NULL,   'D' }, /* path to ssd device file */
    { "server-id",            required_argument,  NULL,   's' }, /* server instance id */
    { NULL,                   0,                  NULL,    0  }
};

static char short_options[] =
    "h"  /* help */
    "V"  /* version */
    "d"  /* daemon mode */
    "S"  /* print slab, item and index sizes and exit */
    "o:" /* output logfile */
    "v:" /* log verbosity level */
    "p:" /* port number to listen on */
    "a:" /* address to listen on */
    "e:" /* item index hash table size as power of two */
    "f:" /* growth factor for slab items */
    "n:" /* min item size */
    "I:" /* slab size in MB */
    "i:" /* max memory for item index in MB */
    "m:" /* max memory for slab in MB */
    "z:" /* profile of slab item sizes */
    "D:" /* path to ssd device file */
    "s:" /* server instance id */
    ;

static void
fc_show_usage(void)
{
    log_stderr(
        "Usage: fatcache [-?hVdS] [-o output file] [-v verbosity level]" CRLF
        "           [-p port] [-a addr] [-e hash power]" CRLF
        "           [-f factor] [-n min item chunk size] [-I slab size]" CRLF
        "           [-i max index memory[ [-m max slab memory]" CRLF
        "           [-z slab profile] [-D ssd device] [-s server id]" CRLF
        " ");

    log_stderr(
        "Options:" CRLF
        "  -h, --help                  : this help" CRLF
        "  -V, --version               : show version and exit" CRLF
        "  -d, --daemonize             : run as a daemon" CRLF
        "  -S, --show-sizes            : print slab, item and index sizes and exit"
        "");

    log_stderr(
        "  -o, --output=S              : set the logging file (default: %s)" CRLF
        "  -v, --verbosity=N           : set the logging level (default: %d, min: %d, max: %d)" CRLF
        "  -p, --port=N                : set the port to listen on (default: %d)" CRLF
        "  -a, --addr=S                : set the address to listen on (default: %s)" CRLF
        "  -e, --hash-power=N          : set the item index hash table size as a power of two (default: %d)"
        "",
        FC_LOG_FILE != NULL ? FC_LOG_FILE : "stderr",
        FC_LOG_DEFAULT, FC_LOG_MIN, FC_LOG_MAX,
        FC_PORT, FC_ADDR,
        FC_HASH_POWER);

    log_stderr(
        "  -f, --factor=D              : set the growth factor of slab item sizes (default: %g)" CRLF
        "  -n, --min-item-chunk-size=N : set the minimum item chunk size in bytes (default: %d bytes)" CRLF
        "  -I, --slab-size=N           : set slab size in bytes (default: %d bytes)" CRLF
        "  -i, --max-index-memory=N    : set the maximum memory to use for item indexes in MB (default: %d MB)" CRLF
        "  -m, --max-slab-memory=N     : set the maximum memory to use for slabs in MB (default: %d MB)"
        "",
        FC_FACTOR,
        FC_CHUNK_SIZE,
        SLAB_SIZE,
        FC_INDEX_MEMORY / MB,
        FC_SLAB_MEMORY / MB);
    log_stderr(
        "  -z, --slab-profile=S        : set the profile of slab item chunk sizes (default: n/a)" CRLF
        "  -D, --ssd-device=S          : set the path to the ssd device file (default: n/a)" CRLF
        "  -s, --server-id=I/N         : set fatcache instance to be I out of total N instances (default: %d/%d)" CRLF
        "",
        FC_SERVER_ID, FC_SERVER_N);
}

static rstatus_t
fc_daemonize(int dump_core)
{
    rstatus_t status;
    pid_t pid, sid;
    int fd;

    /* 1st fork detaches child from terminal */
    pid = fork();
    switch (pid) {
    case -1:
        log_error("fork() failed: %s", strerror(errno));
        return FC_ERROR;

    case 0:
        break;

    default:
        /* parent terminates */
        _exit(0);
    }

    /* 1st child continues and becomes the session and process group leader */
    sid = setsid();
    if (sid < 0) {
        return FC_ERROR;
    }

    if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
        log_error("signal(SIGHUP, SIG_IGN) failed: %s", strerror(errno));
        return FC_ERROR;
    }

    /* 2nd fork turns child into a non-session leader: cannot acquire terminal */
    pid = fork();
    switch (pid) {
    case -1:
        log_error("fork() failed: %s", strerror(errno));
        return FC_ERROR;

    case 0:
        break;

    default:
        /* 1st child terminates */
        _exit(0);
    }

    /* change working directory */
    if (dump_core == 0) {
        status = chdir("/");
        if (status < 0) {
            log_error("chdir(\"/\") failed: %s", strerror(errno));
            return FC_ERROR;
        }
    }

    /* clear file mode creation mask */
    umask(0);

    /* redirect stdin, stdout and stderr to "/dev/null" */

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        log_error("open(\"/dev/null\") failed: %s", strerror(errno));
        return FC_ERROR;
    }

    status = dup2(fd, STDIN_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDIN) failed: %s", fd, strerror(errno));
        close(fd);
        return FC_ERROR;
    }

    status = dup2(fd, STDOUT_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDOUT) failed: %s", fd, strerror(errno));
        close(fd);
        return FC_ERROR;
    }

    status = dup2(fd, STDERR_FILENO);
    if (status < 0) {
        log_error("dup2(%d, STDERR) failed: %s", fd, strerror(errno));
        close(fd);
        return FC_ERROR;
    }

    if (fd > STDERR_FILENO) {
        status = close(fd);
        if (status < 0) {
            log_error("close(%d) failed: %s", fd, strerror(errno));
            return FC_ERROR;
        }
    }

    return FC_OK;
}

static void
fc_set_default_options(void)
{
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
}

static rstatus_t
fc_get_options(int argc, char **argv)
{
    int c, value;
    char *pos;

    opterr = 0;

    for (;;) {
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            /* no more options */
            break;
        }

        switch (c) {
        case 'h':
            show_version = 1;
            show_help = 1;
            break;

        case 'V':
            show_version = 1;
            break;

        case 'd':
            settings.daemonize = true;
            break;

        case 'S':
            show_sizes = 1;
            show_version = 1;
            break;

        case 'o':
            settings.log_filename = optarg;
            break;

        case 'v':
            value = fc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("fatcache: option -v requires a number");
                return FC_ERROR;
            }

            settings.verbose = value;
            break;

        case 'p':
            value = fc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("fatcache: option -p requires a non zero number");
                return FC_ERROR;
            }

            if (!fc_valid_port(value)) {
                log_stderr("fatcache: option -p value %d is not a valid port ",
                           value);
            }

            settings.port = value;
            break;

        case 'a':
            settings.addr = optarg;
            break;

        case 'e':
            value = fc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("fatcache: option -e requires a positive number");
                return FC_ERROR;
            }

            settings.hash_power = value;
            break;

        case 'f':
            settings.factor = atof(optarg);
            if (settings.factor <= 1.0) {
                log_stderr("fatcache: factor must be greater than 1.0");
                return FC_ERROR;
            }
            break;

        case 'n':
            value = fc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("fatcache: option -n requires a non zero number");
                return FC_ERROR;
            }

            if (value < ITEM_MIN_CHUNK_SIZE) {
                log_stderr("fatcache: minimum item chunk size cannot be less "
                           "than %zu", ITEM_MIN_CHUNK_SIZE);
                return FC_ERROR;
            }

            if (value % FC_ALIGNMENT != 0) {
                log_stderr("fatcache: minimum item chunk size must be %zu "
                           "bytes aligned", FC_ALIGNMENT);
                return FC_ERROR;
            }

            settings.chunk_size = value;
            break;

        case 'I':
            value = fc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("fatcache: option -I requires a non zero number");
                return FC_ERROR;
            }

            settings.slab_size = (size_t)value * MB;

            if (settings.slab_size < SLAB_MIN_SIZE) {
                log_stderr("fatcache: slab size must be at least %zu bytes",
                           SLAB_MIN_SIZE);
                return FC_ERROR;
            }

            if (settings.slab_size > SLAB_MAX_SIZE) {
                log_stderr("fatcache: slab size cannot be larger than %zu "
                           "bytes", SLAB_MAX_SIZE);
                return FC_ERROR;
            }

            break;

        case 'i':
            value = fc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("fatcache: option -i requires a non zero number");
                return FC_ERROR;
            }

            settings.max_index_memory = (size_t)value * MB;
            break;

        case 'm':
            value = fc_atoi(optarg, strlen(optarg));
            if (value <= 0) {
                log_stderr("fatcache: option -m requires a non zero number");
                return FC_ERROR;
            }

            settings.max_slab_memory = (size_t)value * MB;
            break;

        case 'z':
            parse_profile = 1;
            profile_optarg = (uint8_t *)optarg;
            break;

        case 'D':
            settings.ssd_device = optarg;
            break;

        case 's':
            pos = strchr(optarg, '/');
            if (pos == NULL) {
                log_stderr("fatcache: invalid server id format '%s'", optarg);
                return FC_ERROR;
            }
            *pos = '\0';

            value = fc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("fatcache : server id is not a number '%s'", optarg);
                return FC_ERROR;
            }
            settings.server_id = (uint32_t)value;

            optarg = pos + 1;

            value = fc_atoi(optarg, strlen(optarg));
            if (value < 0) {
                log_stderr("fatcache: number of server is not a number '%s'", optarg);
                return FC_ERROR;
            }
            settings.server_n = (uint32_t)value;

            if (settings.server_id >= settings.server_n) {
                log_stderr("fatcache: server id must be less than number of server");
                return FC_ERROR;
            }

            break;

        case '?':
            switch (optopt) {
            case 'o':
            case 'D':
                log_stderr("fatcache: option -%c requires a file name", optopt);
                break;

            case 'v':
            case 'p':
            case 'e':
            case 'f':
            case 'n':
            case 'I':
            case 'i':
            case 'm':
                log_stderr("fatcache: option -%c requires a number", optopt);
                break;

            case 'a':
            case 'z':
            case 's':
                log_stderr("fatcache: option -%c requires a string", optopt);
                break;

            default:
                log_stderr("fatcache: invalid option -- '%c'", optopt);
                break;
            }

            return FC_ERROR;

        default:
            log_stderr("fatcache: invalid option -- '%c'", optopt);
            return FC_ERROR;
        }
    }

    return FC_OK;
}

/*
 * Generate slab class sizes from a geometric sequence with the initial
 * term equal to minimum item chunk size (--min-item-chunk-size) and
 * the common ratio equal to factor (--factor)
 */
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

/*
 * Generate slab class sizes based on the sequence specified by the input
 * profile string (--slab-profile)
 */
static rstatus_t
fc_parse_profile(void)
{
    size_t *profile;
    uint8_t id, *ptr, *last;
    bool eos;

    profile = settings.profile;
    ptr = profile_optarg;
    last = ptr + fc_strlen(ptr);
    eos = false;
    id = SLABCLASS_MIN_ID;

    while (id < SLABCLASS_MAX_ID && !eos) {
        rstatus_t status;
        uint8_t *comma;
        int len;
        uint32_t item_sz;

        comma = fc_strchr(ptr, last, ',');
        if (comma != NULL) {
            len = comma - ptr;
        } else {
            len = fc_strlen(ptr);
            eos = true;
        }

        status = fc_atou32(ptr, len, &item_sz);
        if (status < 0) {
            log_stderr("fatcache: '%.*s' is not a valid number", len, ptr);
            return FC_ERROR;
        }

        if (item_sz % FC_ALIGNMENT != 0) {
            log_stderr("fatcache: item chunk size must be %zu bytes aligned",
                       FC_ALIGNMENT);
            return FC_ERROR;
        }

        if (item_sz < ITEM_MIN_CHUNK_SIZE) {
            log_stderr("fatcache: item chunk size cannot be less than %d "
                       "bytes", ITEM_MIN_CHUNK_SIZE);
            return FC_ERROR;
        }

        if (item_sz > slab_data_size()) {
            log_stderr("fatcache: item chunk size cannot be more than %zu "
                       "bytes", slab_data_size());
            return FC_ERROR;
        }

        if (id > SLABCLASS_MIN_ID && item_sz <= profile[id - 1]) {
            log_stderr("fatcache: item chunk sizes must be ascending and "
                       "> %zu bytes apart", FC_ALIGNMENT);
            return FC_ERROR;
        }

        profile[id++] = item_sz;
        ptr = comma + 1;
    }

    if (!eos) {
        log_stderr("fatcache: too many sizes, keep it under %d",
                   SLABCLASS_MAX_IDS);
        return FC_ERROR;
    }

    settings.chunk_size = profile[SLABCLASS_MIN_ID];
    settings.profile_last_id = id - 1;
    settings.max_chunk_size = profile[id - 1];

    return FC_OK;
}

/*
 * Set the slab profile in settings.profile. The last slab id is returned
 * in settings.last_slab_id
 */
static rstatus_t
fc_set_profile(void)
{
    /*
     * There are two ways to create a slab size profile:
     *
     * - Natually Grown:
     *   The lowest slab class will start with settings.chunk_size and
     *   grow by the expansion factor for the next slab class, until maximum
     *   number of slab classes or maximum item size is reached. Size of
     *   the last slab class will always be that of the largest item.
     *
     * - User specified:
     *   Users provide the data sizes they expect to store in fatcache through
     *   command line (--slab-profile). Slab classes will be tailored to host
     *   only those data sizes.
     *
     * User specified profile supercedes naturally grown profile if provided.
     * This means ---slab-profile option supercedes options --factor, and
     * --min-item-chunk-size when present.
     */

    if (parse_profile) {
        return fc_parse_profile();
    }

    return fc_generate_profile();
}

static void
fc_print_sizes(void)
{
    log_stderr("itemx_size %zu", sizeof(struct itemx));

    log_stderr("item_hdr_size %zu", ITEM_HDR_SIZE);
    log_stderr("item_chunk_size %zu", settings.chunk_size);

    log_stderr("slab_hdr_size %zu", SLAB_HDR_SIZE);
    log_stderr("slab_size %zu", settings.slab_size);
    log_stderr("slabinfo_size %zu", sizeof(struct slabinfo));
}

static void
fc_print(void)
{
    loga("%s-%s started on pid %d", PACKAGE, FC_VERSION_STRING, getpid());

    loga("configured with debug logs %s, asserts %s, panic %s",
         FC_DEBUG_LOG ? "enabled" : "disabled",
         FC_ASSERT_LOG ? "enabled" : "disabled",
         FC_ASSERT_PANIC ? "enabled" : "disabled");

    slab_print();
}

int
main(int argc, char **argv)
{
    rstatus_t status;
    struct context ctx;

    fc_set_default_options();

    status = fc_get_options(argc, argv);
    if (status != FC_OK) {
        fc_show_usage();
        exit(1);
    }

    if (show_version) {
        log_stderr("This is %s-%s" CRLF, PACKAGE, FC_VERSION_STRING);

        if (show_help) {
            fc_show_usage();
        }

        if (show_sizes) {
            fc_print_sizes();
        }

        exit(0);
    }

    if (settings.daemonize) {
        status = fc_daemonize(false);
        if (status != FC_OK) {
            exit(1);
        }
    }

    status = fc_set_profile();
    if (status != FC_OK) {
        exit(1);
    }

    status = core_init();
    if (status != FC_OK) {
        exit(1);
    }

    fc_print();

    status = core_start(&ctx);
    if (status != FC_OK) {
        exit(1);
    }

    for (;;) {
        status = core_loop(&ctx);
        if (status != FC_OK) {
            break;
        }
    }

    core_stop(&ctx);

    return 0;
}
