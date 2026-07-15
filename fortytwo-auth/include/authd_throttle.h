/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Password-failure throttling policy and audit reason names.
 */

#ifndef FORTYTWO_AUTHD_THROTTLE_H
#define FORTYTWO_AUTHD_THROTTLE_H

#include <stdbool.h>
#include <stdint.h>

#define AUTHD_THROTTLE_MIN_FAILURE_THRESHOLD UINT32_C(1)
#define AUTHD_THROTTLE_MAX_FAILURE_THRESHOLD UINT32_C(100)
#define AUTHD_THROTTLE_DEFAULT_FAILURE_THRESHOLD UINT32_C(5)
#define AUTHD_THROTTLE_MIN_WINDOW_SECONDS UINT32_C(1)
#define AUTHD_THROTTLE_MAX_WINDOW_SECONDS UINT32_C(86400)
#define AUTHD_THROTTLE_DEFAULT_WINDOW_SECONDS UINT32_C(900)
#define AUTHD_THROTTLE_MIN_DURATION_SECONDS UINT32_C(1)
#define AUTHD_THROTTLE_MAX_DURATION_SECONDS UINT32_C(86400)
#define AUTHD_THROTTLE_DEFAULT_DURATION_SECONDS UINT32_C(900)

typedef struct authd_throttle_policy {
    uint32_t failure_threshold;
    uint32_t failure_window_seconds;
    uint32_t throttle_seconds;
} authd_throttle_policy_t;

typedef enum authd_login_rejection_reason {
    AUTHD_LOGIN_REJECTION_UNKNOWN_USER = 0,
    AUTHD_LOGIN_REJECTION_WRONG_PASSWORD,
    AUTHD_LOGIN_REJECTION_PENDING,
    AUTHD_LOGIN_REJECTION_DISABLED,
    AUTHD_LOGIN_REJECTION_LOCKED,
    AUTHD_LOGIN_REJECTION_DELETED,
    AUTHD_LOGIN_REJECTION_THROTTLED,
    AUTHD_LOGIN_REJECTION_PASSWORD_CHANGE_REQUIRED,
    AUTHD_LOGIN_REJECTION_INVALID_RECORD,
    AUTHD_LOGIN_REJECTION_OVERLOADED,
    AUTHD_LOGIN_REJECTION_STALE_STATE,
    AUTHD_LOGIN_REJECTION_TRANSPORT_NOT_AUTHORIZED,
    AUTHD_LOGIN_REJECTION_INTERNAL_ERROR
} authd_login_rejection_reason_t;

void authd_throttle_policy_defaults(authd_throttle_policy_t *policy);
bool authd_throttle_policy_is_valid(const authd_throttle_policy_t *policy);
bool authd_login_protocol_is_valid(const char *protocol);
bool authd_source_ip_is_valid(const char *source_ip);
const char *authd_login_rejection_reason_name(
    authd_login_rejection_reason_t reason);

#endif /* FORTYTWO_AUTHD_THROTTLE_H */
