/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Bounded Argon2id password hashing and verification for fortytwo-authd.
 */

#ifndef FORTYTWO_AUTHD_PASSWORD_H
#define FORTYTWO_AUTHD_PASSWORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUTHD_PASSWORD_MAX_BYTES 1024U
#define AUTHD_PASSWORD_MAX_BUFFER_BYTES (AUTHD_PASSWORD_MAX_BYTES + 1U)
#define AUTHD_PASSWORD_ARGON2_VERSION UINT32_C(19)
#define AUTHD_PASSWORD_DEFAULT_OPSLIMIT UINT64_C(3)
#define AUTHD_PASSWORD_DEFAULT_MEMLIMIT_BYTES ((size_t)268435456U)
#define AUTHD_PASSWORD_DEFAULT_MAX_OPSLIMIT UINT64_C(3)
#define AUTHD_PASSWORD_DEFAULT_MAX_MEMLIMIT_BYTES ((size_t)268435456U)
#define AUTHD_PASSWORD_DEFAULT_MAX_PARALLELISM UINT32_C(1)

typedef struct authd_password_policy {
    uint64_t opslimit;
    size_t memlimit_bytes;
    uint64_t max_verify_opslimit;
    size_t max_verify_memlimit_bytes;
    uint32_t max_verify_parallelism;
} authd_password_policy_t;

typedef struct authd_password_hash_info {
    uint32_t version;
    uint64_t memory_kib;
    uint32_t time_cost;
    uint32_t parallelism;
} authd_password_hash_info_t;

typedef enum authd_password_result {
    AUTHD_PASSWORD_OK = 0,
    AUTHD_PASSWORD_MISMATCH,
    AUTHD_PASSWORD_INVALID_INPUT,
    AUTHD_PASSWORD_INVALID_HASH,
    AUTHD_PASSWORD_RESOURCE_LIMIT,
    AUTHD_PASSWORD_INTERNAL_ERROR
} authd_password_result_t;

void authd_password_policy_defaults(authd_password_policy_t *policy);

bool authd_password_policy_is_valid(const authd_password_policy_t *policy);

bool authd_password_inspect_hash(const char *encoded_hash,
                                 authd_password_hash_info_t *info);

authd_password_result_t authd_password_generate(
    const authd_password_policy_t *policy,
    char *password,
    size_t password_length,
    size_t password_capacity,
    char *encoded_hash,
    size_t encoded_hash_size);

authd_password_result_t authd_password_verify(
    const authd_password_policy_t *policy,
    const char *encoded_hash,
    char *password,
    size_t password_length,
    size_t password_capacity,
    bool *needs_rehash);

void authd_password_wipe(void *buffer, size_t size);

const char *authd_password_result_name(authd_password_result_t result);

#endif /* FORTYTWO_AUTHD_PASSWORD_H */
