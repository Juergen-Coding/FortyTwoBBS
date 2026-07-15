/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Bounded Argon2id worker pool for fortytwo-authd.
 */

#ifndef FORTYTWO_AUTHD_WORKER_POOL_H
#define FORTYTWO_AUTHD_WORKER_POOL_H

#include "authd_password.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUTHD_WORKER_MIN_THREADS 1U
#define AUTHD_WORKER_MAX_THREADS 8U
#define AUTHD_WORKER_DEFAULT_THREADS 2U
#define AUTHD_WORKER_MIN_CAPACITY 1U
#define AUTHD_WORKER_MAX_CAPACITY 64U
#define AUTHD_WORKER_DEFAULT_CAPACITY 16U
#define AUTHD_WORKER_HASH_MAX_BYTES 255U
#define AUTHD_WORKER_ERROR_MAX 256U

typedef struct authd_worker_pool authd_worker_pool_t;

/*
 * The event loop owns these values. A completion never contains a client
 * pointer, so a closed connection cannot become a dangling worker reference.
 */
typedef struct authd_worker_token {
    uint64_t connection_id;
    uint64_t connection_generation;
    uint64_t request_id;
} authd_worker_token_t;

typedef enum authd_worker_job_type {
    AUTHD_WORKER_JOB_VERIFY_PASSWORD = 0,
    AUTHD_WORKER_JOB_GENERATE_PASSWORD_HASH
} authd_worker_job_type_t;

typedef struct authd_worker_completion {
    uint64_t job_id;
    authd_worker_token_t token;
    authd_worker_job_type_t job_type;
    authd_password_result_t password_result;
    bool needs_rehash;
    char encoded_hash[AUTHD_WORKER_HASH_MAX_BYTES + 1U];
} authd_worker_completion_t;

typedef enum authd_worker_submit_result {
    AUTHD_WORKER_SUBMIT_OK = 0,
    AUTHD_WORKER_SUBMIT_FULL,
    AUTHD_WORKER_SUBMIT_STOPPING,
    AUTHD_WORKER_SUBMIT_INVALID,
    AUTHD_WORKER_SUBMIT_INTERNAL_ERROR
} authd_worker_submit_result_t;

int authd_worker_pool_create(
    const authd_password_policy_t *password_policy,
    size_t worker_count,
    size_t capacity,
    authd_worker_pool_t **pool,
    char *error,
    size_t error_size);

/* The returned descriptor is pollable and remains owned by the pool. */
int authd_worker_pool_completion_fd(const authd_worker_pool_t *pool);

/*
 * Submission consumes the caller's mutable password buffer. The complete
 * declared capacity is wiped whether the job is accepted or rejected.
 */
authd_worker_submit_result_t authd_worker_pool_submit_verify(
    authd_worker_pool_t *pool,
    const authd_worker_token_t *token,
    const char *encoded_hash,
    char *password,
    size_t password_length,
    size_t password_capacity,
    uint64_t *job_id);

authd_worker_submit_result_t authd_worker_pool_submit_generate(
    authd_worker_pool_t *pool,
    const authd_worker_token_t *token,
    char *password,
    size_t password_length,
    size_t password_capacity,
    uint64_t *job_id);

/* Returns false when no completion notification is currently available. */
bool authd_worker_pool_take_completion(
    authd_worker_pool_t *pool,
    authd_worker_completion_t *completion);

/* Wipe a generated PHC string and every other completion field. */
void authd_worker_completion_clear(authd_worker_completion_t *completion);

size_t authd_worker_pool_outstanding(const authd_worker_pool_t *pool);

/*
 * Destruction rejects new work, wipes queued passwords, waits for running
 * Argon2id calls, discards unclaimed completions, and releases all threads.
 */
void authd_worker_pool_destroy(authd_worker_pool_t *pool);

const char *authd_worker_submit_result_name(
    authd_worker_submit_result_t result);

#endif /* FORTYTWO_AUTHD_WORKER_POOL_H */
