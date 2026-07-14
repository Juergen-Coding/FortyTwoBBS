/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_password.h"

#include <sodium.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

static bool
parse_u64_component(const char **cursor, char delimiter, uint64_t *value)
{
    const char *position;
    uint64_t parsed = UINT64_C(0);
    bool saw_digit = false;

    if (cursor == NULL || *cursor == NULL || value == NULL) {
        return false;
    }

    position = *cursor;
    while (*position >= '0' && *position <= '9') {
        uint64_t digit = (uint64_t)(unsigned int)(*position - '0');

        saw_digit = true;
        if (parsed > (UINT64_MAX - digit) / UINT64_C(10)) {
            return false;
        }
        parsed = parsed * UINT64_C(10) + digit;
        ++position;
    }

    if (!saw_digit || *position != delimiter) {
        return false;
    }

    *cursor = position + 1;
    *value = parsed;
    return true;
}

static bool
hash_tail_is_well_formed(const char *cursor)
{
    const char *separator;
    const char *position;

    if (cursor == NULL || cursor[0] == '\0') {
        return false;
    }

    separator = strchr(cursor, '$');
    if (separator == NULL || separator == cursor || separator[1] == '\0') {
        return false;
    }
    if (strchr(separator + 1, '$') != NULL) {
        return false;
    }

    for (position = cursor; *position != '\0'; ++position) {
        unsigned char character = (unsigned char)*position;
        bool valid = (character >= (unsigned char)'A' &&
                      character <= (unsigned char)'Z') ||
                     (character >= (unsigned char)'a' &&
                      character <= (unsigned char)'z') ||
                     (character >= (unsigned char)'0' &&
                      character <= (unsigned char)'9') ||
                     character == (unsigned char)'+' ||
                     character == (unsigned char)'/' ||
                     character == (unsigned char)'$';

        if (!valid) {
            return false;
        }
    }

    return true;
}

static bool
password_arguments_are_valid(char *password,
                             size_t password_length,
                             size_t password_capacity)
{
    return password != NULL &&
           password_length >= 1U &&
           password_length <= AUTHD_PASSWORD_MAX_BYTES &&
           password_capacity >= password_length &&
           password_capacity <= AUTHD_PASSWORD_MAX_BUFFER_BYTES;
}

static void
wipe_locked_or_plain(char *password, size_t password_capacity, bool locked)
{
    if (password == NULL || password_capacity == 0U) {
        return;
    }

    if (locked) {
        (void)sodium_munlock(password, password_capacity);
    } else {
        sodium_memzero(password, password_capacity);
    }
}

void
authd_password_policy_defaults(authd_password_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }

    policy->opslimit = AUTHD_PASSWORD_DEFAULT_OPSLIMIT;
    policy->memlimit_bytes = AUTHD_PASSWORD_DEFAULT_MEMLIMIT_BYTES;
    policy->max_verify_opslimit = AUTHD_PASSWORD_DEFAULT_MAX_OPSLIMIT;
    policy->max_verify_memlimit_bytes =
        AUTHD_PASSWORD_DEFAULT_MAX_MEMLIMIT_BYTES;
    policy->max_verify_parallelism =
        AUTHD_PASSWORD_DEFAULT_MAX_PARALLELISM;
}

bool
authd_password_policy_is_valid(const authd_password_policy_t *policy)
{
    if (policy == NULL) {
        return false;
    }

    return policy->opslimit >= crypto_pwhash_OPSLIMIT_MIN &&
           policy->opslimit <= crypto_pwhash_OPSLIMIT_MAX &&
           policy->memlimit_bytes >= crypto_pwhash_MEMLIMIT_MIN &&
           policy->memlimit_bytes <= crypto_pwhash_MEMLIMIT_MAX &&
           policy->max_verify_opslimit >= policy->opslimit &&
           policy->max_verify_opslimit <= crypto_pwhash_OPSLIMIT_MAX &&
           policy->max_verify_memlimit_bytes >= policy->memlimit_bytes &&
           policy->max_verify_memlimit_bytes <= crypto_pwhash_MEMLIMIT_MAX &&
           policy->max_verify_parallelism == UINT32_C(1);
}

bool
authd_password_inspect_hash(const char *encoded_hash,
                            authd_password_hash_info_t *info)
{
    static const char prefix[] = "$argon2id$v=";
    const char *cursor;
    uint64_t version;
    uint64_t memory_kib;
    uint64_t time_cost;
    uint64_t parallelism;
    size_t length;

    if (encoded_hash == NULL || info == NULL) {
        return false;
    }

    length = strnlen(encoded_hash, crypto_pwhash_STRBYTES);
    if (length == 0U || length >= crypto_pwhash_STRBYTES ||
        strncmp(encoded_hash, prefix, sizeof(prefix) - 1U) != 0) {
        return false;
    }

    cursor = encoded_hash + sizeof(prefix) - 1U;
    if (!parse_u64_component(&cursor, '$', &version) ||
        strncmp(cursor, "m=", 2U) != 0) {
        return false;
    }
    cursor += 2;
    if (!parse_u64_component(&cursor, ',', &memory_kib) ||
        strncmp(cursor, "t=", 2U) != 0) {
        return false;
    }
    cursor += 2;
    if (!parse_u64_component(&cursor, ',', &time_cost) ||
        strncmp(cursor, "p=", 2U) != 0) {
        return false;
    }
    cursor += 2;
    if (!parse_u64_component(&cursor, '$', &parallelism) ||
        !hash_tail_is_well_formed(cursor)) {
        return false;
    }

    if (version > UINT32_MAX ||
        time_cost == 0U || time_cost > UINT32_MAX ||
        parallelism == 0U || parallelism > UINT32_MAX ||
        memory_kib == 0U || memory_kib > SIZE_MAX / UINT64_C(1024)) {
        return false;
    }

    info->version = (uint32_t)version;
    info->memory_kib = memory_kib;
    info->time_cost = (uint32_t)time_cost;
    info->parallelism = (uint32_t)parallelism;
    return true;
}

static authd_password_result_t
hash_is_allowed(const authd_password_policy_t *policy,
                const char *encoded_hash,
                authd_password_hash_info_t *info)
{
    uint64_t memory_bytes;

    if (!authd_password_policy_is_valid(policy) ||
        !authd_password_inspect_hash(encoded_hash, info)) {
        return AUTHD_PASSWORD_INVALID_HASH;
    }

    if (info->version != AUTHD_PASSWORD_ARGON2_VERSION) {
        return AUTHD_PASSWORD_INVALID_HASH;
    }

    memory_bytes = info->memory_kib * UINT64_C(1024);
    if ((uint64_t)info->time_cost > policy->max_verify_opslimit ||
        memory_bytes > (uint64_t)policy->max_verify_memlimit_bytes ||
        info->parallelism > policy->max_verify_parallelism) {
        return AUTHD_PASSWORD_RESOURCE_LIMIT;
    }

    return AUTHD_PASSWORD_OK;
}

void
authd_password_wipe(void *buffer, size_t size)
{
    if (buffer != NULL && size > 0U) {
        sodium_memzero(buffer, size);
    }
}

authd_password_result_t
authd_password_generate(const authd_password_policy_t *policy,
                        char *password,
                        size_t password_length,
                        size_t password_capacity,
                        char *encoded_hash,
                        size_t encoded_hash_size)
{
    bool locked = false;
    authd_password_result_t result = AUTHD_PASSWORD_INVALID_INPUT;

    if (encoded_hash != NULL && encoded_hash_size > 0U) {
        encoded_hash[0] = '\0';
    }

    if (!password_arguments_are_valid(password, password_length,
                                      password_capacity) ||
        !authd_password_policy_is_valid(policy) ||
        encoded_hash == NULL ||
        encoded_hash_size < crypto_pwhash_STRBYTES) {
        goto finished;
    }
    if (sodium_init() < 0) {
        result = AUTHD_PASSWORD_INTERNAL_ERROR;
        goto finished;
    }

    locked = sodium_mlock(password, password_capacity) == 0;
    if (crypto_pwhash_str_alg(encoded_hash,
                              password,
                              (unsigned long long)password_length,
                              (unsigned long long)policy->opslimit,
                              policy->memlimit_bytes,
                              crypto_pwhash_ALG_ARGON2ID13) != 0) {
        encoded_hash[0] = '\0';
        result = AUTHD_PASSWORD_RESOURCE_LIMIT;
        goto finished;
    }

    result = AUTHD_PASSWORD_OK;

finished:
    wipe_locked_or_plain(password, password_capacity, locked);
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
    authd_password_hash_info_t info;
    authd_password_result_t result = AUTHD_PASSWORD_INVALID_INPUT;
    bool locked = false;
    int rehash_result;

    if (needs_rehash != NULL) {
        *needs_rehash = false;
    }

    if (!password_arguments_are_valid(password, password_length,
                                      password_capacity) ||
        !authd_password_policy_is_valid(policy) ||
        encoded_hash == NULL || needs_rehash == NULL) {
        goto finished;
    }
    if (sodium_init() < 0) {
        result = AUTHD_PASSWORD_INTERNAL_ERROR;
        goto finished;
    }

    result = hash_is_allowed(policy, encoded_hash, &info);
    if (result != AUTHD_PASSWORD_OK) {
        goto finished;
    }

    rehash_result = crypto_pwhash_str_needs_rehash(
        encoded_hash,
        (unsigned long long)policy->opslimit,
        policy->memlimit_bytes);
    if (rehash_result < 0) {
        result = AUTHD_PASSWORD_INVALID_HASH;
        goto finished;
    }

    locked = sodium_mlock(password, password_capacity) == 0;
    if (crypto_pwhash_str_verify(encoded_hash,
                                 password,
                                 (unsigned long long)password_length) != 0) {
        result = AUTHD_PASSWORD_MISMATCH;
        goto finished;
    }

    *needs_rehash = rehash_result != 0;
    result = AUTHD_PASSWORD_OK;

finished:
    wipe_locked_or_plain(password, password_capacity, locked);
    return result;
}

const char *
authd_password_result_name(authd_password_result_t result)
{
    switch (result) {
    case AUTHD_PASSWORD_OK:
        return "ok";
    case AUTHD_PASSWORD_MISMATCH:
        return "mismatch";
    case AUTHD_PASSWORD_INVALID_INPUT:
        return "invalid_input";
    case AUTHD_PASSWORD_INVALID_HASH:
        return "invalid_hash";
    case AUTHD_PASSWORD_RESOURCE_LIMIT:
        return "resource_limit";
    case AUTHD_PASSWORD_INTERNAL_ERROR:
        return "internal_error";
    default:
        return "unknown";
    }
}
