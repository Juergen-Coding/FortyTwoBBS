/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_password_worker_stub.h"

#include "authd_password.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static atomic_uint delay_milliseconds;
static atomic_size_t call_count;
static atomic_size_t active_calls;
static atomic_size_t maximum_parallel;

/* Record whether the coordinator selected the real or startup dummy hash. */
static void
record_hash_selection(const char *encoded_hash)
{
    const char *path = getenv("FORTYTWO_TEST_EVENT_LOG");
    const char *kind = strcmp(encoded_hash, "dummy") == 0 ? "dummy" : "real";
    char line[48];
    int length;
    int fd;

    if (path == NULL || path[0] == '\0') {
        return;
    }
    length = snprintf(line, sizeof(line), "password_verify:%s\n", kind);
    if (length <= 0 || (size_t)length >= sizeof(line)) {
        return;
    }
    fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    {
        size_t offset = 0;

        while (offset < (size_t)length) {
            ssize_t written = write(fd, line + offset,
                                    (size_t)length - offset);

            if (written > 0) {
                offset += (size_t)written;
            } else if (written < 0 && errno == EINTR) {
                continue;
            } else {
                break;
            }
        }
    }
    (void)close(fd);
}

/* Raise the recorded maximum without losing a concurrent larger value. */
static void
record_parallelism(size_t active)
{
    size_t observed = atomic_load_explicit(&maximum_parallel,
                                           memory_order_relaxed);

    while (active > observed &&
           !atomic_compare_exchange_weak_explicit(
               &maximum_parallel, &observed, active,
               memory_order_relaxed, memory_order_relaxed)) {
        /* observed is refreshed by compare_exchange_weak(). */
    }
}

/* Sleep long enough for deterministic queue and parallelism tests. */
static void
sleep_for_test_delay(void)
{
    unsigned int milliseconds = atomic_load_explicit(
        &delay_milliseconds, memory_order_relaxed);
    const char *environment = getenv("FORTYTWO_TEST_PASSWORD_DELAY_MS");
    struct timespec delay;

    if (environment != NULL && environment[0] != '\0') {
        char *end = NULL;
        unsigned long parsed = strtoul(environment, &end, 10);
        if (end != environment && *end == '\0' && parsed <= 60000UL) {
            milliseconds = (unsigned int)parsed;
        }
    }

    delay.tv_sec = (time_t)(milliseconds / 1000U);
    delay.tv_nsec = (long)(milliseconds % 1000U) * 1000000L;
    while (nanosleep(&delay, &delay) != 0) {
        /* Retry with the remaining interval after a signal. */
    }
}

void
authd_password_worker_stub_reset(unsigned int delay_ms)
{
    atomic_store_explicit(&delay_milliseconds, delay_ms,
                          memory_order_relaxed);
    atomic_store_explicit(&call_count, 0U, memory_order_relaxed);
    atomic_store_explicit(&active_calls, 0U, memory_order_relaxed);
    atomic_store_explicit(&maximum_parallel, 0U, memory_order_relaxed);
}

size_t
authd_password_worker_stub_call_count(void)
{
    return atomic_load_explicit(&call_count, memory_order_relaxed);
}

size_t
authd_password_worker_stub_max_parallel(void)
{
    return atomic_load_explicit(&maximum_parallel, memory_order_relaxed);
}

void
authd_password_policy_defaults(authd_password_policy_t *policy)
{
    if (policy != NULL) {
        memset(policy, 0, sizeof(*policy));
        policy->opslimit = 3U;
        policy->memlimit_bytes = 256U * 1024U * 1024U;
        policy->max_verify_opslimit = 3U;
        policy->max_verify_memlimit_bytes = 256U * 1024U * 1024U;
        policy->max_verify_parallelism = 1U;
    }
}

bool
authd_password_policy_is_valid(const authd_password_policy_t *policy)
{
    return policy != NULL && policy->opslimit > 0U &&
           policy->memlimit_bytes > 0U;
}

authd_password_result_t
authd_password_generate(const authd_password_policy_t *policy,
                        char *password,
                        size_t password_length,
                        size_t password_capacity,
                        char *encoded_hash,
                        size_t encoded_hash_size)
{
    authd_password_result_t result = AUTHD_PASSWORD_INVALID_INPUT;

    if (authd_password_policy_is_valid(policy) && password != NULL &&
        password_length > 0U && password_capacity >= password_length &&
        encoded_hash != NULL && encoded_hash_size >= sizeof("dummy")) {
        (void)snprintf(encoded_hash, encoded_hash_size, "%s", "dummy");
        result = AUTHD_PASSWORD_OK;
    }
    authd_password_wipe(password, password_capacity);
    return result;
}

authd_password_result_t
authd_password_verify(const authd_password_policy_t *policy,
                      const char *encoded_hash,
                      char *password,
                      size_t password_length,
                      size_t password_capacity,
                      bool *needs_rehash)
{
    size_t active;
    authd_password_result_t result;

    if (!authd_password_policy_is_valid(policy) || encoded_hash == NULL ||
        password == NULL || password_length == 0U ||
        password_capacity < password_length || needs_rehash == NULL) {
        authd_password_wipe(password, password_capacity);
        return AUTHD_PASSWORD_INVALID_INPUT;
    }

    record_hash_selection(encoded_hash);
    active = atomic_fetch_add_explicit(&active_calls, 1U,
                                       memory_order_relaxed) + 1U;
    record_parallelism(active);
    (void)atomic_fetch_add_explicit(&call_count, 1U, memory_order_relaxed);
    sleep_for_test_delay();

    *needs_rehash = strcmp(encoded_hash, "rehash") == 0;
    if (strcmp(encoded_hash, "invalid") == 0) {
        result = AUTHD_PASSWORD_INVALID_HASH;
    } else if (password_length == strlen("secret") &&
               memcmp(password, "secret", password_length) == 0) {
        result = AUTHD_PASSWORD_OK;
    } else {
        result = AUTHD_PASSWORD_MISMATCH;
    }

    authd_password_wipe(password, password_capacity);
    (void)atomic_fetch_sub_explicit(&active_calls, 1U,
                                    memory_order_relaxed);
    return result;
}

void
authd_password_wipe(void *buffer, size_t size)
{
    volatile unsigned char *position = buffer;

    while (position != NULL && size > 0U) {
        *position++ = 0U;
        --size;
    }
}
