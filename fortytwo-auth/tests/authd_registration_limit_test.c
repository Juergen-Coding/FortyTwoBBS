/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_registration_limit.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static authd_registration_limiter_t limiter;

static void
init_limiter(uint32_t attempts, uint32_t window_seconds)
{
    authd_registration_limit_policy_t policy;

    policy.attempts = attempts;
    policy.window_seconds = window_seconds;
    assert(authd_registration_limiter_init(&limiter, &policy));
}

static void
test_policy(void)
{
    authd_registration_limit_policy_t policy;

    authd_registration_limit_policy_defaults(&policy);
    assert(policy.attempts == 3U);
    assert(policy.window_seconds == 900U);
    assert(authd_registration_limit_policy_is_valid(&policy));

    policy.attempts = 0U;
    assert(!authd_registration_limit_policy_is_valid(&policy));
    policy.attempts = 3U;
    policy.window_seconds = 86401U;
    assert(!authd_registration_limit_policy_is_valid(&policy));
    assert(!authd_registration_limit_policy_is_valid(NULL));
    assert(!authd_registration_limiter_init(NULL, &policy));
}

static void
test_ipv4_limit_and_reset(void)
{
    uint32_t retry = 0U;

    init_limiter(3U, 10U);
    assert(authd_registration_limiter_record(
               &limiter, "192.0.2.42", 100U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    assert(authd_registration_limiter_record(
               &limiter, "192.0.2.42", 101U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    assert(authd_registration_limiter_record(
               &limiter, "192.0.2.42", 102U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    assert(authd_registration_limiter_record(
               &limiter, "192.0.2.42", 103U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_RATE_LIMITED);
    assert(retry == 7U);

    assert(authd_registration_limiter_record(
               &limiter, "192.0.2.42", 110U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    assert(retry == 0U);
}

static void
test_independent_ipv6_and_canonical_text(void)
{
    uint32_t retry = 0U;

    init_limiter(1U, 30U);
    assert(authd_registration_limiter_record(
               &limiter, "2001:db8::42", 50U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    assert(authd_registration_limiter_record(
               &limiter, "2001:db8::43", 50U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    assert(authd_registration_limiter_record(
               &limiter, "2001:db8::42", 51U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_RATE_LIMITED);
    assert(retry == 29U);

    assert(authd_registration_limiter_record(
               &limiter, "2001:0db8::42", 51U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_INVALID_ARGUMENT);
    assert(authd_registration_limiter_record(
               &limiter, "192.0.2.042", 51U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_INVALID_ARGUMENT);
    assert(authd_registration_limiter_record(
               &limiter, NULL, 51U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_INVALID_ARGUMENT);
}

static void
test_clock_rollback_reclaims_entry(void)
{
    uint32_t retry = 0U;

    init_limiter(1U, 30U);
    assert(authd_registration_limiter_record(
               &limiter, "198.51.100.4", 500U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    assert(authd_registration_limiter_record(
               &limiter, "198.51.100.4", 499U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
}

static void
test_capacity_fails_closed_and_recovers(void)
{
    char address[64];
    uint32_t retry = 0U;
    size_t index;

    init_limiter(1U, 20U);
    for (index = 0U; index < AUTHD_REGISTRATION_IP_LIMIT_CAPACITY; ++index) {
        unsigned int second = (unsigned int)(index / 256U);
        unsigned int third = (unsigned int)(index % 256U);
        int length = snprintf(address, sizeof(address), "10.%u.%u.1",
                              second, third);
        assert(length > 0 && (size_t)length < sizeof(address));
        assert(authd_registration_limiter_record(
                   &limiter, address, 1000U, &retry) ==
               AUTHD_REGISTRATION_LIMIT_ALLOWED);
    }

    assert(authd_registration_limiter_record(
               &limiter, "203.0.113.99", 1001U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_CAPACITY);
    assert(retry == 19U);

    assert(authd_registration_limiter_record(
               &limiter, "203.0.113.99", 1020U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
}

static void
test_clear(void)
{
    uint32_t retry = 0U;

    init_limiter(1U, 30U);
    assert(authd_registration_limiter_record(
               &limiter, "203.0.113.7", 10U, &retry) ==
           AUTHD_REGISTRATION_LIMIT_ALLOWED);
    authd_registration_limiter_clear(&limiter);
    assert(memcmp(&limiter, &(authd_registration_limiter_t){0},
                  sizeof(limiter)) == 0);
}

int
main(void)
{
    test_policy();
    test_ipv4_limit_and_reset();
    test_independent_ipv6_and_canonical_text();
    test_clock_rollback_reclaims_entry();
    test_capacity_fails_closed_and_recovers();
    test_clear();
    (void)puts("authd registration limit tests: OK");
    return 0;
}
