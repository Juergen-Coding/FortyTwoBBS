/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Real libsodium verification through the worker-pool boundary.
 */

#include "authd_password.h"
#include "authd_worker_pool.h"

#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

static authd_worker_completion_t
wait_for_completion(authd_worker_pool_t *pool)
{
    struct pollfd descriptor;
    authd_worker_completion_t completion;

    descriptor.fd = authd_worker_pool_completion_fd(pool);
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    assert(poll(&descriptor, 1U, 5000) == 1);
    assert(authd_worker_pool_take_completion(pool, &completion));
    return completion;
}

static void
fill_password(char *buffer, size_t capacity, const char *text)
{
    memset(buffer, 0, capacity);
    memcpy(buffer, text, strlen(text));
}

int
main(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    authd_worker_token_t token = {12U, 3U, 44U};
    authd_worker_completion_t completion;
    char hash[128];
    char password[64];
    char error[AUTHD_WORKER_ERROR_MAX];
    uint64_t job_id;

    /* Use the smaller test profile while preserving bounded Argon2id. */
    authd_password_policy_defaults(&policy);
    policy.opslimit = 2U;
    policy.memlimit_bytes = 64U * 1024U * 1024U;

    fill_password(password, sizeof(password), "worker pool secret");
    assert(authd_password_generate(&policy,
                                   password,
                                   strlen("worker pool secret"),
                                   sizeof(password),
                                   hash,
                                   sizeof(hash)) == AUTHD_PASSWORD_OK);

    assert(authd_worker_pool_create(&policy, 1U, 2U, &pool,
                                    error, sizeof(error)) == 0);
    fill_password(password, sizeof(password), "worker pool secret");
    assert(authd_worker_pool_submit(
               pool, &token, hash, password, strlen("worker pool secret"),
               sizeof(password), &job_id) == AUTHD_WORKER_SUBMIT_OK);

    completion = wait_for_completion(pool);
    assert(completion.job_id == job_id);
    assert(completion.password_result == AUTHD_PASSWORD_OK);
    assert(!completion.needs_rehash);
    assert(completion.token.connection_generation == 3U);

    authd_worker_pool_destroy(pool);
    (void)puts("authd worker pool libsodium integration test: OK");
    return 0;
}
