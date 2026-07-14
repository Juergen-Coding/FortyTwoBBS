/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * PostgreSQL lifecycle and login-record access for fortytwo-authd.
 */

#ifndef FORTYTWO_AUTHD_DATABASE_H
#define FORTYTWO_AUTHD_DATABASE_H

#include "authd_config.h"
#include "ftap_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUTHD_DATABASE_ERROR_MAX 512U
#define AUTHD_DATABASE_UUID_HEX_SIZE 32U
#define AUTHD_DATABASE_PASSWORD_HASH_MAX 255U

typedef struct authd_database authd_database_t;

typedef struct authd_database_info {
    int server_version_num;
    size_t migration_count;
    unsigned int highest_migration;
} authd_database_info_t;

typedef enum authd_account_state {
    AUTHD_ACCOUNT_STATE_PENDING = 0,
    AUTHD_ACCOUNT_STATE_ACTIVE,
    AUTHD_ACCOUNT_STATE_DISABLED,
    AUTHD_ACCOUNT_STATE_LOCKED,
    AUTHD_ACCOUNT_STATE_DELETED
} authd_account_state_t;

typedef struct authd_login_record {
    uint8_t user_id[FTAP_UUID_SIZE];
    char login_name[FTAP_LOGIN_NAME_MAX + 1U];
    char display_name[FTAP_DISPLAY_NAME_MAX + 1U];
    char password_hash[AUTHD_DATABASE_PASSWORD_HASH_MAX + 1U];
    authd_account_state_t account_state;
    uint64_t auth_epoch;
    uint64_t authz_revision;
    bool deleted;
    bool throttled;
    uint64_t retry_after_ms;
    bool must_change;
    uint32_t failed_count;
    bool last_failed_at_set;
    int64_t last_failed_at_epoch_ms;
} authd_login_record_t;

typedef enum authd_database_lookup_result {
    AUTHD_DATABASE_LOOKUP_OK = 0,
    AUTHD_DATABASE_LOOKUP_NOT_FOUND,
    AUTHD_DATABASE_LOOKUP_INVALID_RECORD,
    AUTHD_DATABASE_LOOKUP_ERROR
} authd_database_lookup_result_t;

typedef enum authd_database_write_result {
    AUTHD_DATABASE_WRITE_OK = 0,
    AUTHD_DATABASE_WRITE_NOT_FOUND,
    AUTHD_DATABASE_WRITE_STALE_STATE,
    AUTHD_DATABASE_WRITE_INVALID_ARGUMENT,
    AUTHD_DATABASE_WRITE_INVALID_RECORD,
    AUTHD_DATABASE_WRITE_ERROR
} authd_database_write_result_t;

typedef struct authd_password_failure_update {
    uint32_t failed_count;
    bool throttled;
    uint64_t retry_after_ms;
} authd_password_failure_update_t;

typedef struct authd_terminal_session_result {
    uint8_t user_id[FTAP_UUID_SIZE];
    uint8_t session_id[FTAP_UUID_SIZE];
    uint64_t auth_epoch;
    uint64_t authz_revision;
} authd_terminal_session_result_t;

typedef enum authd_login_availability {
    AUTHD_LOGIN_AVAILABLE = 0,
    AUTHD_LOGIN_PENDING,
    AUTHD_LOGIN_DISABLED,
    AUTHD_LOGIN_LOCKED,
    AUTHD_LOGIN_DELETED,
    AUTHD_LOGIN_THROTTLED,
    AUTHD_LOGIN_PASSWORD_CHANGE_REQUIRED,
    AUTHD_LOGIN_INVALID_RECORD
} authd_login_availability_t;

int authd_database_open(const authd_config_t *config,
                        authd_database_t **database,
                        authd_database_info_t *info,
                        char *error,
                        size_t error_size);

int authd_database_health_check(authd_database_t *database,
                                char *error,
                                size_t error_size);

authd_database_lookup_result_t authd_database_lookup_login(
    authd_database_t *database,
    const char *canonical_login_name,
    authd_login_record_t *record,
    char *error,
    size_t error_size);

authd_database_write_result_t authd_database_record_password_failure(
    authd_database_t *database,
    const uint8_t user_id[FTAP_UUID_SIZE],
    const authd_throttle_policy_t *policy,
    const char *source_ip,
    const char *protocol,
    authd_password_failure_update_t *update,
    char *error,
    size_t error_size);

authd_database_write_result_t authd_database_audit_login_rejection(
    authd_database_t *database,
    const uint8_t *user_id,
    const char *canonical_login_name,
    authd_login_rejection_reason_t reason,
    const char *source_ip,
    const char *protocol,
    char *error,
    size_t error_size);

authd_database_write_result_t authd_database_create_password_session(
    authd_database_t *database,
    const authd_login_record_t *record,
    const char *source_ip,
    const char *protocol,
    const char *tty_device,
    const char *node_id,
    authd_terminal_session_result_t *session,
    char *error,
    size_t error_size);

authd_database_write_result_t authd_database_close_terminal_session(
    authd_database_t *database,
    const uint8_t session_id[FTAP_UUID_SIZE],
    const char *ended_reason,
    char *error,
    size_t error_size);

authd_login_availability_t authd_login_record_availability(
    const authd_login_record_t *record);

const char *authd_account_state_name(authd_account_state_t state);
const char *authd_database_lookup_result_name(
    authd_database_lookup_result_t result);
const char *authd_login_availability_name(
    authd_login_availability_t availability);
const char *authd_database_write_result_name(
    authd_database_write_result_t result);

void authd_database_close(authd_database_t *database);

#endif /* FORTYTWO_AUTHD_DATABASE_H */
