/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_throttle.h"

#include "ftap_protocol.h"

#include <arpa/inet.h>
#include <string.h>

/* Install the conservative pre-alpha user throttling policy. */
void
authd_throttle_policy_defaults(authd_throttle_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }

    policy->failure_threshold =
        AUTHD_THROTTLE_DEFAULT_FAILURE_THRESHOLD;
    policy->failure_window_seconds =
        AUTHD_THROTTLE_DEFAULT_WINDOW_SECONDS;
    policy->throttle_seconds = AUTHD_THROTTLE_DEFAULT_DURATION_SECONDS;
}

/* Reject policies that could disable protection or consume unbounded time. */
bool
authd_throttle_policy_is_valid(const authd_throttle_policy_t *policy)
{
    return policy != NULL &&
           policy->failure_threshold >=
               AUTHD_THROTTLE_MIN_FAILURE_THRESHOLD &&
           policy->failure_threshold <=
               AUTHD_THROTTLE_MAX_FAILURE_THRESHOLD &&
           policy->failure_window_seconds >=
               AUTHD_THROTTLE_MIN_WINDOW_SECONDS &&
           policy->failure_window_seconds <=
               AUTHD_THROTTLE_MAX_WINDOW_SECONDS &&
           policy->throttle_seconds >=
               AUTHD_THROTTLE_MIN_DURATION_SECONDS &&
           policy->throttle_seconds <=
               AUTHD_THROTTLE_MAX_DURATION_SECONDS;
}

/* Only protocol names admitted by FTAP 1.2 may enter audit records. */
bool
authd_login_protocol_is_valid(const char *protocol)
{
    return protocol != NULL &&
           (strcmp(protocol, FTAP_PROTOCOL_TELNET) == 0 ||
            strcmp(protocol, FTAP_PROTOCOL_SSH) == 0 ||
            strcmp(protocol, FTAP_PROTOCOL_LOCAL) == 0);
}

/* Validate optional IPv4 or IPv6 text before PostgreSQL casts it to inet. */
bool
authd_source_ip_is_valid(const char *source_ip)
{
    unsigned char address[sizeof(struct in6_addr)];
    size_t length;

    if (source_ip == NULL) {
        return true;
    }

    length = strlen(source_ip);
    if (length == 0U || length > FTAP_IP_ADDRESS_MAX) {
        return false;
    }

    return inet_pton(AF_INET, source_ip, address) == 1 ||
           inet_pton(AF_INET6, source_ip, address) == 1;
}

/* Return stable machine-readable identifiers for audit JSON. */
const char *
authd_login_rejection_reason_name(authd_login_rejection_reason_t reason)
{
    switch (reason) {
    case AUTHD_LOGIN_REJECTION_UNKNOWN_USER:
        return "unknown_user";
    case AUTHD_LOGIN_REJECTION_WRONG_PASSWORD:
        return "wrong_password";
    case AUTHD_LOGIN_REJECTION_PENDING:
        return "account_pending";
    case AUTHD_LOGIN_REJECTION_DISABLED:
        return "account_disabled";
    case AUTHD_LOGIN_REJECTION_LOCKED:
        return "account_locked";
    case AUTHD_LOGIN_REJECTION_DELETED:
        return "account_deleted";
    case AUTHD_LOGIN_REJECTION_THROTTLED:
        return "temporarily_throttled";
    case AUTHD_LOGIN_REJECTION_PASSWORD_CHANGE_REQUIRED:
        return "password_change_required";
    case AUTHD_LOGIN_REJECTION_INVALID_RECORD:
        return "invalid_account_record";
    case AUTHD_LOGIN_REJECTION_OVERLOADED:
        return "password_worker_overloaded";
    case AUTHD_LOGIN_REJECTION_STALE_STATE:
        return "stale_login_state";
    case AUTHD_LOGIN_REJECTION_TRANSPORT_NOT_AUTHORIZED:
        return "transport_not_authorized";
    case AUTHD_LOGIN_REJECTION_INTERNAL_ERROR:
        return "internal_error";
    default:
        return "invalid";
    }
}
