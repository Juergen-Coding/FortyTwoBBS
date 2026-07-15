/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_throttle.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Verify bounded defaults and all policy boundary checks. */
static void
test_policy(void)
{
    authd_throttle_policy_t policy;

    authd_throttle_policy_defaults(&policy);
    assert(policy.failure_threshold == 5U);
    assert(policy.failure_window_seconds == 900U);
    assert(policy.throttle_seconds == 900U);
    assert(authd_throttle_policy_is_valid(&policy));

    policy.failure_threshold = 0U;
    assert(!authd_throttle_policy_is_valid(&policy));
    policy.failure_threshold = 5U;
    policy.failure_window_seconds = 86401U;
    assert(!authd_throttle_policy_is_valid(&policy));
    policy.failure_window_seconds = 900U;
    policy.throttle_seconds = 0U;
    assert(!authd_throttle_policy_is_valid(&policy));
    assert(!authd_throttle_policy_is_valid(NULL));
}

/* Accept only FTAP protocol names and parseable IPv4 or IPv6 text. */
static void
test_transport_fields(void)
{
    assert(authd_login_protocol_is_valid("telnet"));
    assert(authd_login_protocol_is_valid("ssh"));
    assert(authd_login_protocol_is_valid("local"));
    assert(!authd_login_protocol_is_valid("SSH"));
    assert(!authd_login_protocol_is_valid("http"));
    assert(!authd_login_protocol_is_valid(NULL));

    assert(authd_source_ip_is_valid(NULL));
    assert(authd_source_ip_is_valid("192.0.2.42"));
    assert(authd_source_ip_is_valid("2001:db8::42"));
    assert(!authd_source_ip_is_valid(""));
    assert(!authd_source_ip_is_valid("999.0.2.42"));
    assert(!authd_source_ip_is_valid("not-an-address"));
}

/* Audit reason strings are stable machine-readable identifiers. */
static void
test_reason_names(void)
{
    assert(strcmp(authd_login_rejection_reason_name(
                      AUTHD_LOGIN_REJECTION_UNKNOWN_USER),
                  "unknown_user") == 0);
    assert(strcmp(authd_login_rejection_reason_name(
                      AUTHD_LOGIN_REJECTION_WRONG_PASSWORD),
                  "wrong_password") == 0);
    assert(strcmp(authd_login_rejection_reason_name(
                      AUTHD_LOGIN_REJECTION_THROTTLED),
                  "temporarily_throttled") == 0);
    assert(strcmp(authd_login_rejection_reason_name(
                      AUTHD_LOGIN_REJECTION_STALE_STATE),
                  "stale_login_state") == 0);
    assert(strcmp(authd_login_rejection_reason_name(
                      AUTHD_LOGIN_REJECTION_TRANSPORT_NOT_AUTHORIZED),
                  "transport_not_authorized") == 0);
    assert(strcmp(authd_login_rejection_reason_name(
                      (authd_login_rejection_reason_t)999),
                  "invalid") == 0);
}

int
main(void)
{
    test_policy();
    test_transport_fields();
    test_reason_names();
    (void)puts("authd throttle tests: OK");
    return 0;
}
