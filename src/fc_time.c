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

#include <fc_core.h>

extern struct settings settings;

/*
 * From memcache protocol specification:
 *
 * Some commands involve a client sending some kind of expiration time
 * (relative to an item or to an operation requested by the client) to
 * the server. In all such cases, the actual value sent may either be
 * Unix time (number of seconds since January 1, 1970, as a 32-bit
 * value), or a number of seconds starting from current time. In the
 * latter case, this number of seconds may not exceed 60*60*24*30 (number
 * of seconds in 30 days); if the number sent by a client is larger than
 * that, the server will consider it to be real Unix time value rather
 * than an offset from current time.
 */
#define TIME_MAXDELTA   (time_t)(60 * 60 * 24 * 30)

/*
 * Time when process was started expressed as absolute unix timestamp
 * with a time_t type
 */
static time_t process_started;

/*
 * We keep a cache of the current time of day in a global variable now
 * that is updated periodically by a timer event every second. This
 * saves us a bunch of time() system calls because we really only need
 * to get the time once a second, whereas there can be tens of thosands
 * of requests a second.
 *
 * Also keeping track of time as relative to server-start timestamp
 * instead of absolute unix timestamps gives us a space savings on
 * systems where sizeof(time_t) > sizeof(unsigned int)
 *
 * So, now actually holds 32-bit seconds since the server start time.
 */
static volatile rel_time_t now;

void
time_update(void)
{
    int status;
    struct timeval timer;

    status = gettimeofday(&timer, NULL);
    if (status < 0) {
        log_error("gettimeofday failed: %s", strerror(errno));
    }
    now = (rel_time_t) (timer.tv_sec - process_started);

    log_debug(LOG_PVERB, "time updated to %u", now);
}

rel_time_t
time_now(void)
{
    return now;
}

time_t
time_now_abs(void)
{
    return process_started + (time_t)now;
}

time_t
time_started(void)
{
    return process_started;
}

/*
 * Given time value that's either unix time or delta from current unix
 * time, return the time relative to process start.
 */
rel_time_t
time_reltime(time_t exptime)
{
    if (exptime == 0) { /* 0 means never expire */
        return 0;
    }

    if (exptime > TIME_MAXDELTA) {
        /*
         * If item expiration is at or before the server_started, give
         * it an expiration time of 1 second after the server started
         * becasue because 0 means don't expire.  Without this, we would
         * underflow and wrap around to some large value way in the
         * future, effectively making items expiring in the past
         * really expiring never
         */
        if (exptime <= process_started) {
            return (rel_time_t)1;
        }

        return (rel_time_t)(exptime - process_started);
    } else {
        return (rel_time_t)(exptime + now);
    }
}

static void *
time_loop(void *arg)
{
    struct epoll_event event; /* dummy event */
    int ep;                   /* epoll descriptor */
    int n;                    /* return status */

    ep = epoll_create(10);
    if (ep < 0) {
        log_error("epoll create failed: %s", strerror(errno));
        return NULL;
    }

    for (;;) {
        n = epoll_wait(ep, &event, 1, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("epoll wait on e %d failed: %s", ep, strerror(errno));
            break;
        }

        if (n == 0) {
            time_update();
            continue;
        }
    }

    return NULL;
}

rstatus_t
time_init(void)
{
    int status;
    pthread_t tid;

    /*
     * Make the time we started always be 2 seconds before we really
     * did, so time_now(0) - time.started is never zero. If so, things
     * like 'settings.oldest_live' which act as booleans as well as
     * values are now false in boolean context.
     */
    process_started = time(NULL) - 2;

    log_debug(LOG_DEBUG, "process started at %"PRId64, (int64_t)process_started);

    status = pthread_create(&tid, NULL, time_loop, NULL);
    if (status != 0) {
        log_error("stats aggregator create failed: %s", strerror(status));
        return FC_ERROR;
    }

    return FC_OK;
}

void
time_deinit(void)
{
}
