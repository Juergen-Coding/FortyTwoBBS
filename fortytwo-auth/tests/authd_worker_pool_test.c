/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_worker_pool.h"
#include "authd_password_worker_stub.h"

#include <assert.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void
fill_password(char *buffer, size_t capacity, const char *text)
{
    size_t length = strlen(text);

    assert(length <= capacity);
    memset(buffer, 0x5a, capacity);
    memcpy(buffer, text, length);
}

static void
assert_wiped(const void *buffer, size_t capacity)
{
    const unsigned char *position = buffer;
    size_t index;

    for (index = 0U; index < capacity; ++index) {
        assert(position[index] == 0U);
    }
}

/* Poll the completion descriptor instead of guessing worker timing. */
static authd_worker_completion_t
wait_for_completion(authd_worker_pool_t *pool)
{
    struct pollfd descriptor;
    authd_worker_completion_t completion;

    memset(&completion, 0, sizeof(completion));
    descriptor.fd = authd_worker_pool_completion_fd(pool);
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    assert(descriptor.fd >= 0);
    assert(poll(&descriptor, 1U, 3000) == 1);
    assert((descriptor.revents & POLLIN) != 0);
    assert(authd_worker_pool_take_completion(pool, &completion));
    return completion;
}

/* Wait only for a test counter; the production pool never uses this helper. */
static void
wait_for_stub_calls(size_t expected)
{
    struct timespec delay = {0, 1000000L};
    size_t attempts;

    for (attempts = 0U; attempts < 3000U; ++attempts) {
        if (authd_password_worker_stub_call_count() >= expected) {
            return;
        }
        (void)nanosleep(&delay, NULL);
    }
    assert(!"worker calls did not start before timeout");
}

static void
test_configuration_rejections(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    char error[AUTHD_WORKER_ERROR_MAX];

    authd_password_policy_defaults(&policy);
    assert(authd_worker_pool_create(&policy, 0U, 2U, &pool,
                                    error, sizeof(error)) != 0);
    assert(pool == NULL);
    assert(strstr(error, "configuration") != NULL);

    assert(authd_worker_pool_create(&policy, 3U, 2U, &pool,
                                    error, sizeof(error)) != 0);
    assert(pool == NULL);
    assert(strstr(error, "capacity") != NULL);
}

static void
test_bounded_parallel_verify_queue(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    authd_worker_token_t tokens[4];
    authd_worker_completion_t completion;
    bool seen[3] = {false, false, false};
    uint64_t job_ids[4];
    char passwords[4][32];
    char error[AUTHD_WORKER_ERROR_MAX];
    size_t index;

    authd_password_worker_stub_reset(200U);
    authd_password_policy_defaults(&policy);
    assert(authd_worker_pool_create(&policy, 2U, 3U, &pool,
                                    error, sizeof(error)) == 0);
    assert(pool != NULL);

    /* Three open jobs fill the entire bounded lifecycle capacity. */
    for (index = 0U; index < 3U; ++index) {
        tokens[index].connection_id = 100U + index;
        tokens[index].connection_generation = 7U;
        tokens[index].request_id = 1000U + index;
        fill_password(passwords[index], sizeof(passwords[index]), "secret");
        assert(authd_worker_pool_submit_verify(
                   pool, &tokens[index], index == 1U ? "rehash" : "ok",
                   passwords[index], strlen("secret"),
                   sizeof(passwords[index]), &job_ids[index]) ==
               AUTHD_WORKER_SUBMIT_OK);
        assert(job_ids[index] != 0U);
        assert_wiped(passwords[index], sizeof(passwords[index]));
    }
    assert(authd_worker_pool_outstanding(pool) == 3U);

    /* A rejected job is also consumed and wiped by the submission API. */
    tokens[3].connection_id = 999U;
    tokens[3].connection_generation = 1U;
    tokens[3].request_id = 9999U;
    fill_password(passwords[3], sizeof(passwords[3]), "secret");
    assert(authd_worker_pool_submit_verify(
               pool, &tokens[3], "ok", passwords[3], strlen("secret"),
               sizeof(passwords[3]), &job_ids[3]) == AUTHD_WORKER_SUBMIT_FULL);
    assert(job_ids[3] == 0U);
    assert_wiped(passwords[3], sizeof(passwords[3]));

    for (index = 0U; index < 3U; ++index) {
        size_t candidate;

        completion = wait_for_completion(pool);
        assert(completion.job_type == AUTHD_WORKER_JOB_VERIFY_PASSWORD);
        assert(completion.encoded_hash[0] == '\0');
        for (candidate = 0U; candidate < 3U; ++candidate) {
            if (completion.job_id == job_ids[candidate]) {
                assert(!seen[candidate]);
                seen[candidate] = true;
                assert(completion.token.connection_id ==
                       tokens[candidate].connection_id);
                assert(completion.token.connection_generation == 7U);
                assert(completion.token.request_id ==
                       tokens[candidate].request_id);
                assert(completion.password_result == AUTHD_PASSWORD_OK);
                assert(completion.needs_rehash == (candidate == 1U));
                break;
            }
        }
        assert(candidate < 3U);
        authd_worker_completion_clear(&completion);
        assert_wiped(&completion, sizeof(completion));
    }

    assert(authd_worker_pool_outstanding(pool) == 0U);
    assert(authd_password_worker_stub_call_count() == 3U);
    assert(authd_password_worker_stub_max_parallel() == 2U);
    assert(!authd_worker_pool_take_completion(pool, &completion));
    authd_worker_pool_destroy(pool);
}

static void
test_generate_job_and_shared_capacity(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    authd_worker_token_t verify_token = {41U, 2U, 90U};
    authd_worker_token_t generate_token = {42U, 2U, 91U};
    authd_worker_token_t rejected_token = {43U, 2U, 92U};
    authd_worker_completion_t completion;
    uint64_t verify_job_id;
    uint64_t generate_job_id;
    uint64_t rejected_job_id = 99U;
    char verify_password[32];
    char generate_password[32];
    char rejected_password[32];
    char error[AUTHD_WORKER_ERROR_MAX];
    bool saw_verify = false;
    bool saw_generate = false;
    size_t index;

    authd_password_worker_stub_reset(200U);
    authd_password_policy_defaults(&policy);
    assert(authd_worker_pool_create(&policy, 1U, 2U, &pool,
                                    error, sizeof(error)) == 0);

    fill_password(verify_password, sizeof(verify_password), "secret");
    assert(authd_worker_pool_submit_verify(
               pool, &verify_token, "ok", verify_password, strlen("secret"),
               sizeof(verify_password), &verify_job_id) ==
           AUTHD_WORKER_SUBMIT_OK);

    fill_password(generate_password, sizeof(generate_password), "new secret");
    assert(authd_worker_pool_submit_generate(
               pool, &generate_token, generate_password, strlen("new secret"),
               sizeof(generate_password), &generate_job_id) ==
           AUTHD_WORKER_SUBMIT_OK);

    fill_password(rejected_password, sizeof(rejected_password), "overflow");
    assert(authd_worker_pool_submit_generate(
               pool, &rejected_token, rejected_password, strlen("overflow"),
               sizeof(rejected_password), &rejected_job_id) ==
           AUTHD_WORKER_SUBMIT_FULL);
    assert(rejected_job_id == 0U);
    assert_wiped(rejected_password, sizeof(rejected_password));

    for (index = 0U; index < 2U; ++index) {
        completion = wait_for_completion(pool);
        if (completion.job_id == verify_job_id) {
            assert(completion.job_type == AUTHD_WORKER_JOB_VERIFY_PASSWORD);
            assert(completion.password_result == AUTHD_PASSWORD_OK);
            assert(completion.encoded_hash[0] == '\0');
            saw_verify = true;
        } else {
            assert(completion.job_id == generate_job_id);
            assert(completion.job_type ==
                   AUTHD_WORKER_JOB_GENERATE_PASSWORD_HASH);
            assert(completion.password_result == AUTHD_PASSWORD_OK);
            assert(!completion.needs_rehash);
            assert(strcmp(completion.encoded_hash, "dummy") == 0);
            saw_generate = true;
        }
        authd_worker_completion_clear(&completion);
        assert_wiped(&completion, sizeof(completion));
    }

    assert(saw_verify);
    assert(saw_generate);
    assert(authd_worker_pool_outstanding(pool) == 0U);
    assert(authd_password_worker_stub_call_count() == 1U);
    assert(authd_password_worker_stub_generate_call_count() == 1U);
    authd_worker_pool_destroy(pool);
}

static void
test_generation_token_and_results(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    authd_worker_token_t token = {42U, 9U, 100U};
    authd_worker_completion_t completion;
    uint64_t job_id;
    char password[32];
    char error[AUTHD_WORKER_ERROR_MAX];

    authd_password_worker_stub_reset(0U);
    authd_password_policy_defaults(&policy);
    assert(authd_worker_pool_create(&policy, 1U, 2U, &pool,
                                    error, sizeof(error)) == 0);

    fill_password(password, sizeof(password), "wrong");
    assert(authd_worker_pool_submit_verify(
               pool, &token, "ok", password, strlen("wrong"),
               sizeof(password), &job_id) == AUTHD_WORKER_SUBMIT_OK);
    completion = wait_for_completion(pool);
    assert(completion.job_id == job_id);
    assert(completion.job_type == AUTHD_WORKER_JOB_VERIFY_PASSWORD);
    assert(completion.token.connection_id == 42U);
    assert(completion.token.connection_generation == 9U);
    assert(completion.token.request_id == 100U);
    assert(completion.password_result == AUTHD_PASSWORD_MISMATCH);

    /*
     * The event loop will compare generation 9 with its current client slot.
     * The pool deliberately returns no pointer that could already be stale.
     */
    assert(completion.token.connection_generation != 10U);
    authd_worker_completion_clear(&completion);
    authd_worker_pool_destroy(pool);
}

static void
test_shutdown_discards_pending_jobs(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    authd_worker_token_t token = {1U, 1U, 1U};
    uint64_t job_id;
    char password[32];
    char error[AUTHD_WORKER_ERROR_MAX];
    size_t index;

    authd_password_worker_stub_reset(400U);
    authd_password_policy_defaults(&policy);
    assert(authd_worker_pool_create(&policy, 2U, 4U, &pool,
                                    error, sizeof(error)) == 0);

    for (index = 0U; index < 4U; ++index) {
        token.request_id = index + 1U;
        fill_password(password, sizeof(password), "secret");
        assert(authd_worker_pool_submit_verify(
                   pool, &token, "ok", password, strlen("secret"),
                   sizeof(password), &job_id) == AUTHD_WORKER_SUBMIT_OK);
    }

    wait_for_stub_calls(2U);
    authd_worker_pool_destroy(pool);

    /* Only the two already-running calls finish; queued jobs are discarded. */
    assert(authd_password_worker_stub_call_count() == 2U);
}

static void
test_invalid_submissions_wipe_password(void)
{
    authd_worker_token_t token = {1U, 1U, 1U};
    uint64_t job_id = 99U;
    char password[32];

    fill_password(password, sizeof(password), "secret");
    assert(authd_worker_pool_submit_verify(
               NULL, &token, "ok", password, strlen("secret"),
               sizeof(password), &job_id) == AUTHD_WORKER_SUBMIT_INVALID);
    assert(job_id == 0U);
    assert_wiped(password, sizeof(password));

    fill_password(password, sizeof(password), "secret");
    job_id = 99U;
    assert(authd_worker_pool_submit_generate(
               NULL, &token, password, strlen("secret"), sizeof(password),
               &job_id) == AUTHD_WORKER_SUBMIT_INVALID);
    assert(job_id == 0U);
    assert_wiped(password, sizeof(password));
}

static void
test_result_names(void)
{
    assert(strcmp(authd_worker_submit_result_name(AUTHD_WORKER_SUBMIT_OK),
                  "ok") == 0);
    assert(strcmp(authd_worker_submit_result_name(AUTHD_WORKER_SUBMIT_FULL),
                  "full") == 0);
    assert(strcmp(authd_worker_submit_result_name(
                      (authd_worker_submit_result_t)99),
                  "unknown") == 0);
}

int
main(void)
{
    test_configuration_rejections();
    test_bounded_parallel_verify_queue();
    test_generate_job_and_shared_capacity();
    test_generation_token_and_results();
    test_shutdown_discards_pending_jobs();
    test_invalid_submissions_wipe_password();
    test_result_names();
    (void)puts("authd worker pool tests: OK");
    return 0;
}
