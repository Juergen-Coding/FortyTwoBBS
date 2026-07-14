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
assert_wiped(const char *buffer, size_t capacity)
{
    size_t index;

    for (index = 0U; index < capacity; ++index) {
        assert(buffer[index] == '\0');
    }
}

/* Poll the completion descriptor instead of guessing worker timing. */
static authd_worker_completion_t
wait_for_completion(authd_worker_pool_t *pool)
{
    struct pollfd descriptor;
    authd_worker_completion_t completion;

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
test_bounded_parallel_queue(void)
{
    authd_password_policy_t policy;
    authd_worker_pool_t *pool = NULL;
    authd_worker_token_t tokens[4];
    authd_worker_completion_t completions[3];
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
        assert(authd_worker_pool_submit(
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
    assert(authd_worker_pool_submit(
               pool, &tokens[3], "ok", passwords[3], strlen("secret"),
               sizeof(passwords[3]), &job_ids[3]) == AUTHD_WORKER_SUBMIT_FULL);
    assert(job_ids[3] == 0U);
    assert_wiped(passwords[3], sizeof(passwords[3]));

    for (index = 0U; index < 3U; ++index) {
        size_t candidate;

        completions[index] = wait_for_completion(pool);
        for (candidate = 0U; candidate < 3U; ++candidate) {
            if (completions[index].job_id == job_ids[candidate]) {
                assert(!seen[candidate]);
                seen[candidate] = true;
                assert(completions[index].token.connection_id ==
                       tokens[candidate].connection_id);
                assert(completions[index].token.connection_generation == 7U);
                assert(completions[index].token.request_id ==
                       tokens[candidate].request_id);
                assert(completions[index].password_result ==
                       AUTHD_PASSWORD_OK);
                assert(completions[index].needs_rehash == (candidate == 1U));
                break;
            }
        }
        assert(candidate < 3U);
    }

    assert(authd_worker_pool_outstanding(pool) == 0U);
    assert(authd_password_worker_stub_call_count() == 3U);
    assert(authd_password_worker_stub_max_parallel() == 2U);
    assert(!authd_worker_pool_take_completion(pool, &completions[0]));
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
    assert(authd_worker_pool_submit(pool, &token, "ok", password,
                                    strlen("wrong"), sizeof(password),
                                    &job_id) == AUTHD_WORKER_SUBMIT_OK);
    completion = wait_for_completion(pool);
    assert(completion.job_id == job_id);
    assert(completion.token.connection_id == 42U);
    assert(completion.token.connection_generation == 9U);
    assert(completion.token.request_id == 100U);
    assert(completion.password_result == AUTHD_PASSWORD_MISMATCH);

    /*
     * The event loop will compare generation 9 with its current client slot.
     * The pool deliberately returns no pointer that could already be stale.
     */
    assert(completion.token.connection_generation != 10U);
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
        assert(authd_worker_pool_submit(pool, &token, "ok", password,
                                        strlen("secret"), sizeof(password),
                                        &job_id) == AUTHD_WORKER_SUBMIT_OK);
    }

    wait_for_stub_calls(2U);
    authd_worker_pool_destroy(pool);

    /* Only the two already-running calls finish; queued jobs are discarded. */
    assert(authd_password_worker_stub_call_count() == 2U);
}

static void
test_invalid_submission_wipes_password(void)
{
    authd_worker_token_t token = {1U, 1U, 1U};
    uint64_t job_id = 99U;
    char password[32];

    fill_password(password, sizeof(password), "secret");
    assert(authd_worker_pool_submit(NULL, &token, "ok", password,
                                    strlen("secret"), sizeof(password),
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
    test_bounded_parallel_queue();
    test_generation_token_and_results();
    test_shutdown_discards_pending_jobs();
    test_invalid_submission_wipes_password();
    test_result_names();
    (void)puts("authd worker pool tests: OK");
    return 0;
}
