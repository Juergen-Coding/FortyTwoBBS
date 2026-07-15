/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Real libsodium generation and verification through one worker pool.
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

    memset(&completion, 0, sizeof(completion));
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

static void
assert_completion_wiped(const authd_worker_completion_t *completion)
{
    const unsigned char *position = (const unsigned char *)completion;
    size_t index;

    for (index = 0U; index < sizeof(*completion); ++index) {
        assert(position[index] == 0U);
    }
}

int
main(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    authd_worker_token_t generate_token = {12U, 3U, 44U};
    authd_worker_token_t verify_token = {12U, 3U, 45U};
    authd_worker_completion_t completion;
    char hash[AUTHD_WORKER_HASH_MAX_BYTES + 1U];
    char password[64];
    char error[AUTHD_WORKER_ERROR_MAX];
    uint64_t generate_job_id;
    uint64_t verify_job_id;

    /* Use the smaller test profile while preserving bounded Argon2id. */
    authd_password_policy_defaults(&policy);
    policy.opslimit = 2U;
    policy.memlimit_bytes = 64U * 1024U * 1024U;

    assert(authd_worker_pool_create(&policy, 1U, 2U, &pool,
                                    error, sizeof(error)) == 0);

    fill_password(password, sizeof(password), "worker pool secret");
    assert(authd_worker_pool_submit_generate(
               pool, &generate_token, password, strlen("worker pool secret"),
               sizeof(password), &generate_job_id) == AUTHD_WORKER_SUBMIT_OK);
    completion = wait_for_completion(pool);
    assert(completion.job_id == generate_job_id);
    assert(completion.job_type == AUTHD_WORKER_JOB_GENERATE_PASSWORD_HASH);
    assert(completion.password_result == AUTHD_PASSWORD_OK);
    assert(!completion.needs_rehash);
    assert(strncmp(completion.encoded_hash, "$argon2id$", 10U) == 0);
    assert(strlen(completion.encoded_hash) < sizeof(hash));
    (void)snprintf(hash, sizeof(hash), "%s", completion.encoded_hash);
    authd_worker_completion_clear(&completion);
    assert_completion_wiped(&completion);

    fill_password(password, sizeof(password), "worker pool secret");
    assert(authd_worker_pool_submit_verify(
               pool, &verify_token, hash, password,
               strlen("worker pool secret"), sizeof(password),
               &verify_job_id) == AUTHD_WORKER_SUBMIT_OK);
    completion = wait_for_completion(pool);
    assert(completion.job_id == verify_job_id);
    assert(completion.job_type == AUTHD_WORKER_JOB_VERIFY_PASSWORD);
    assert(completion.password_result == AUTHD_PASSWORD_OK);
    assert(!completion.needs_rehash);
    assert(completion.encoded_hash[0] == '\0');
    assert(completion.token.connection_generation == 3U);
    authd_worker_completion_clear(&completion);
    assert_completion_wiped(&completion);

    authd_password_wipe(hash, sizeof(hash));
    authd_worker_pool_destroy(pool);
    (void)puts("authd worker pool libsodium integration test: OK");
    return 0;
}
