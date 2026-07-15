/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Bounded in-memory source-IP limiter for Telnet registrations.
 */

#ifndef FORTYTWO_AUTHD_REGISTRATION_LIMIT_H
#define FORTYTWO_AUTHD_REGISTRATION_LIMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUTHD_REGISTRATION_MIN_PASSWORD_BYTES UINT32_C(12)
#define AUTHD_REGISTRATION_MAX_PASSWORD_BYTES UINT32_C(1024)
#define AUTHD_REGISTRATION_DEFAULT_MIN_PASSWORD_BYTES UINT32_C(12)
#define AUTHD_REGISTRATION_MIN_TIMEOUT_SECONDS UINT32_C(60)
#define AUTHD_REGISTRATION_MAX_TIMEOUT_SECONDS UINT32_C(86400)
#define AUTHD_REGISTRATION_DEFAULT_TIMEOUT_SECONDS UINT32_C(600)
#define AUTHD_REGISTRATION_MIN_PENDING 1U
#define AUTHD_REGISTRATION_MAX_PENDING 1024U
#define AUTHD_REGISTRATION_DEFAULT_MAX_PENDING 16U
#define AUTHD_REGISTRATION_MIN_IP_ATTEMPTS UINT32_C(1)
#define AUTHD_REGISTRATION_MAX_IP_ATTEMPTS UINT32_C(100)
#define AUTHD_REGISTRATION_DEFAULT_IP_ATTEMPTS UINT32_C(3)
#define AUTHD_REGISTRATION_MIN_IP_WINDOW_SECONDS UINT32_C(1)
#define AUTHD_REGISTRATION_MAX_IP_WINDOW_SECONDS UINT32_C(86400)
#define AUTHD_REGISTRATION_DEFAULT_IP_WINDOW_SECONDS UINT32_C(900)
#define AUTHD_REGISTRATION_IP_LIMIT_CAPACITY 1024U
#define AUTHD_REGISTRATION_ADDRESS_BYTES 16U

typedef struct authd_registration_limit_policy {
    uint32_t attempts;
    uint32_t window_seconds;
} authd_registration_limit_policy_t;

typedef struct authd_registration_limit_entry {
    bool in_use;
    int address_family;
    unsigned char address[AUTHD_REGISTRATION_ADDRESS_BYTES];
    uint32_t attempts;
    uint64_t window_started_seconds;
} authd_registration_limit_entry_t;

typedef struct authd_registration_limiter {
    authd_registration_limit_policy_t policy;
    authd_registration_limit_entry_t
        entries[AUTHD_REGISTRATION_IP_LIMIT_CAPACITY];
} authd_registration_limiter_t;

typedef enum authd_registration_limit_result {
    AUTHD_REGISTRATION_LIMIT_ALLOWED = 0,
    AUTHD_REGISTRATION_LIMIT_RATE_LIMITED,
    AUTHD_REGISTRATION_LIMIT_CAPACITY,
    AUTHD_REGISTRATION_LIMIT_INVALID_ARGUMENT
} authd_registration_limit_result_t;

void authd_registration_limit_policy_defaults(
    authd_registration_limit_policy_t *policy);
bool authd_registration_limit_policy_is_valid(
    const authd_registration_limit_policy_t *policy);
bool authd_registration_limiter_init(
    authd_registration_limiter_t *limiter,
    const authd_registration_limit_policy_t *policy);
void authd_registration_limiter_clear(
    authd_registration_limiter_t *limiter);
authd_registration_limit_result_t authd_registration_limiter_record(
    authd_registration_limiter_t *limiter,
    const char *source_ip,
    uint64_t now_seconds,
    uint32_t *retry_after_seconds);

#endif /* FORTYTWO_AUTHD_REGISTRATION_LIMIT_H */
