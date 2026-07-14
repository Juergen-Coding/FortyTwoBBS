/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_password.h"

#include <sodium.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void
fill_password(char *buffer, size_t capacity, const char *text)
{
    size_t length = strlen(text);

    assert(length <= capacity);
    memset(buffer, 0x5a, capacity);
    memcpy(buffer, text, length);
}

static void
assert_wiped(const char *buffer, size_t size)
{
    size_t index;

    for (index = 0U; index < size; ++index) {
        assert(buffer[index] == '\0');
    }
}

static void
test_policy(void)
{
    authd_password_policy_t policy;

    authd_password_policy_defaults(&policy);
    assert(policy.opslimit == 3U);
    assert(policy.memlimit_bytes == 256U * 1024U * 1024U);
    assert(policy.max_verify_opslimit == 3U);
    assert(policy.max_verify_memlimit_bytes == 256U * 1024U * 1024U);
    assert(policy.max_verify_parallelism == 1U);
    assert(authd_password_policy_is_valid(&policy));

    policy.max_verify_opslimit = 2U;
    assert(!authd_password_policy_is_valid(&policy));
}

static void
test_generate_and_verify(void)
{
    authd_password_policy_t policy;
    authd_password_hash_info_t info;
    char hash[crypto_pwhash_STRBYTES];
    char password[64];
    bool needs_rehash = true;

    authd_password_policy_defaults(&policy);
    fill_password(password, sizeof(password), "correct horse battery staple");
    assert(authd_password_generate(&policy,
                                   password,
                                   strlen("correct horse battery staple"),
                                   sizeof(password),
                                   hash,
                                   sizeof(hash)) == AUTHD_PASSWORD_OK);
    assert_wiped(password, sizeof(password));
    assert(strncmp(hash, "$argon2id$", 10U) == 0);

    assert(authd_password_inspect_hash(hash, &info));
    assert(info.version == 19U);
    assert(info.memory_kib == 262144U);
    assert(info.time_cost == 3U);
    assert(info.parallelism == 1U);

    fill_password(password, sizeof(password), "correct horse battery staple");
    assert(authd_password_verify(&policy,
                                 hash,
                                 password,
                                 strlen("correct horse battery staple"),
                                 sizeof(password),
                                 &needs_rehash) == AUTHD_PASSWORD_OK);
    assert(!needs_rehash);
    assert_wiped(password, sizeof(password));

    fill_password(password, sizeof(password), "wrong password");
    assert(authd_password_verify(&policy,
                                 hash,
                                 password,
                                 strlen("wrong password"),
                                 sizeof(password),
                                 &needs_rehash) == AUTHD_PASSWORD_MISMATCH);
    assert(!needs_rehash);
    assert_wiped(password, sizeof(password));
}

static void
test_rehash_detection(void)
{
    authd_password_policy_t weak_policy;
    authd_password_policy_t current_policy;
    char hash[crypto_pwhash_STRBYTES];
    char password[64];
    bool needs_rehash = false;

    authd_password_policy_defaults(&weak_policy);
    weak_policy.opslimit = 2U;
    weak_policy.memlimit_bytes = 64U * 1024U * 1024U;
    authd_password_policy_defaults(&current_policy);

    fill_password(password, sizeof(password), "upgrade me");
    assert(authd_password_generate(&weak_policy,
                                   password,
                                   strlen("upgrade me"),
                                   sizeof(password),
                                   hash,
                                   sizeof(hash)) == AUTHD_PASSWORD_OK);

    fill_password(password, sizeof(password), "upgrade me");
    assert(authd_password_verify(&current_policy,
                                 hash,
                                 password,
                                 strlen("upgrade me"),
                                 sizeof(password),
                                 &needs_rehash) == AUTHD_PASSWORD_OK);
    assert(needs_rehash);
    assert_wiped(password, sizeof(password));
}

static void
test_rejections_and_wiping(void)
{
    authd_password_policy_t policy;
    char password[32];
    bool needs_rehash = true;
    const char *over_limit =
        "$argon2id$v=19$m=262145,t=3,p=1$YWJjZA$YWJjZA";
    const char *wrong_algorithm =
        "$argon2i$v=19$m=65536,t=3,p=1$YWJjZA$YWJjZA";
    const char *malformed =
        "$argon2id$v=19$m=65536,t=3,p=1$missing_digest";

    authd_password_policy_defaults(&policy);

    fill_password(password, sizeof(password), "secret");
    assert(authd_password_verify(&policy,
                                 over_limit,
                                 password,
                                 strlen("secret"),
                                 sizeof(password),
                                 &needs_rehash) ==
           AUTHD_PASSWORD_RESOURCE_LIMIT);
    assert_wiped(password, sizeof(password));

    fill_password(password, sizeof(password), "secret");
    assert(authd_password_verify(&policy,
                                 wrong_algorithm,
                                 password,
                                 strlen("secret"),
                                 sizeof(password),
                                 &needs_rehash) == AUTHD_PASSWORD_INVALID_HASH);
    assert_wiped(password, sizeof(password));

    fill_password(password, sizeof(password), "secret");
    assert(authd_password_verify(&policy,
                                 malformed,
                                 password,
                                 strlen("secret"),
                                 sizeof(password),
                                 &needs_rehash) == AUTHD_PASSWORD_INVALID_HASH);
    assert_wiped(password, sizeof(password));

    fill_password(password, sizeof(password), "secret");
    assert(authd_password_verify(&policy,
                                 malformed,
                                 password,
                                 0U,
                                 sizeof(password),
                                 &needs_rehash) == AUTHD_PASSWORD_INVALID_INPUT);
    assert_wiped(password, sizeof(password));
}

static void
test_result_names(void)
{
    assert(strcmp(authd_password_result_name(AUTHD_PASSWORD_OK), "ok") == 0);
    assert(strcmp(authd_password_result_name(AUTHD_PASSWORD_MISMATCH),
                  "mismatch") == 0);
    assert(strcmp(authd_password_result_name((authd_password_result_t)99),
                  "unknown") == 0);
}

int
main(void)
{
    assert(sodium_init() >= 0);
    test_policy();
    test_generate_and_verify();
    test_rehash_detection();
    test_rejections_and_wiping();
    test_result_names();
    (void)puts("authd password tests: OK");
    return 0;
}
