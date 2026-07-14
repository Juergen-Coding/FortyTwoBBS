/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Deterministic test-only database for daemon integration tests.
 */

#include "authd_database.h"
#include "authd_database_validation.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct authd_database {
    unsigned long health_checks;
    unsigned long fail_after;
    uint32_t failed_count;
    bool session_open;
    uint8_t session_id[FTAP_UUID_SIZE];
};

static unsigned long
read_unsigned_environment(const char *name)
{
    const char *text = getenv(name);
    char *end = NULL;
    unsigned long value;

    if (text == NULL || text[0] == '\0') {
        return 0UL;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return 0UL;
    }
    return value;
}

static void
set_error(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size > 0U) {
        (void)snprintf(error, error_size, "%s", message);
    }
}

static void
record_event(const char *event, const char *value)
{
    const char *path = getenv("FORTYTWO_TEST_EVENT_LOG");
    FILE *stream;

    if (path == NULL || path[0] == '\0') {
        return;
    }
    stream = fopen(path, "a");
    if (stream == NULL) {
        return;
    }
    (void)fprintf(stream, "%s:%s\n", event,
                  value != NULL ? value : "");
    (void)fclose(stream);
}

static void
fill_uuid(uint8_t uuid[FTAP_UUID_SIZE], uint8_t seed)
{
    size_t index;

    for (index = 0U; index < FTAP_UUID_SIZE; ++index) {
        uuid[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

int
authd_database_open(const authd_config_t *config,
                    authd_database_t **database,
                    authd_database_info_t *info,
                    char *error,
                    size_t error_size)
{
    authd_database_t *created;

    (void)config;
    if (database != NULL) {
        *database = NULL;
    }
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL) {
        return -1;
    }
    if (getenv("FORTYTWO_TEST_DB_OPEN_FAIL") != NULL) {
        set_error(error, error_size, "test database startup failure");
        return -1;
    }

    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        set_error(error, error_size, "out of memory");
        return -1;
    }
    created->fail_after =
        read_unsigned_environment("FORTYTWO_TEST_DB_HEALTH_FAIL_AFTER");
    fill_uuid(created->session_id, UINT8_C(0xa0));

    if (info != NULL) {
        info->server_version_num = 170010;
        info->migration_count = AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT;
        info->highest_migration =
            AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION;
    }
    *database = created;
    return 0;
}

int
authd_database_health_check(authd_database_t *database,
                            char *error,
                            size_t error_size)
{
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL) {
        return -1;
    }

    ++database->health_checks;
    if (database->fail_after != 0UL &&
        database->health_checks >= database->fail_after) {
        set_error(error, error_size, "test database health failure");
        return -1;
    }
    return 0;
}

authd_database_lookup_result_t
authd_database_lookup_login(authd_database_t *database,
                            const char *canonical_login_name,
                            authd_login_record_t *record,
                            char *error,
                            size_t error_size)
{
    uint8_t seed = UINT8_C(1);

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || canonical_login_name == NULL || record == NULL) {
        set_error(error, error_size, "invalid test lookup");
        return AUTHD_DATABASE_LOOKUP_ERROR;
    }
    memset(record, 0, sizeof(*record));

    if (strcmp(canonical_login_name, "lookupfail") == 0) {
        set_error(error, error_size, "test login lookup failure");
        return AUTHD_DATABASE_LOOKUP_ERROR;
    }
    if (strcmp(canonical_login_name, "invalidrecord") == 0) {
        return AUTHD_DATABASE_LOOKUP_INVALID_RECORD;
    }
    if (strcmp(canonical_login_name, "unknown") == 0) {
        return AUTHD_DATABASE_LOOKUP_NOT_FOUND;
    }

    if (strcmp(canonical_login_name, "locked") == 0) {
        seed = UINT8_C(2);
    } else if (strcmp(canonical_login_name, "disabled") == 0) {
        seed = UINT8_C(3);
    } else if (strcmp(canonical_login_name, "throttled") == 0) {
        seed = UINT8_C(4);
    } else if (strcmp(canonical_login_name, "stale") == 0) {
        seed = UINT8_C(5);
    } else if (strcmp(canonical_login_name, "sessionerror") == 0) {
        seed = UINT8_C(6);
    } else if (strcmp(canonical_login_name, "invalidhash") == 0) {
        seed = UINT8_C(7);
    }

    fill_uuid(record->user_id, seed);
    (void)snprintf(record->login_name, sizeof(record->login_name), "%s",
                   canonical_login_name);
    (void)snprintf(record->display_name, sizeof(record->display_name),
                   "Test %s", canonical_login_name);
    (void)snprintf(record->password_hash, sizeof(record->password_hash), "%s",
                   strcmp(canonical_login_name, "invalidhash") == 0
                       ? "invalid"
                       : "valid");
    record->account_state = AUTHD_ACCOUNT_STATE_ACTIVE;
    record->auth_epoch = UINT64_C(7);
    record->authz_revision = UINT64_C(11);
    record->failed_count = database->failed_count;

    if (strcmp(canonical_login_name, "locked") == 0) {
        record->account_state = AUTHD_ACCOUNT_STATE_LOCKED;
    } else if (strcmp(canonical_login_name, "disabled") == 0) {
        record->account_state = AUTHD_ACCOUNT_STATE_DISABLED;
    } else if (strcmp(canonical_login_name, "throttled") == 0) {
        record->throttled = true;
        record->retry_after_ms = UINT64_C(1234);
    }
    return AUTHD_DATABASE_LOOKUP_OK;
}

authd_database_write_result_t
authd_database_record_password_failure(
    authd_database_t *database,
    const uint8_t user_id[FTAP_UUID_SIZE],
    const authd_throttle_policy_t *policy,
    const char *source_ip,
    const char *protocol,
    authd_password_failure_update_t *update,
    char *error,
    size_t error_size)
{
    (void)user_id;
    (void)source_ip;
    (void)protocol;
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || policy == NULL || update == NULL) {
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    ++database->failed_count;
    memset(update, 0, sizeof(*update));
    update->failed_count = database->failed_count;
    if (database->failed_count >= policy->failure_threshold) {
        update->throttled = true;
        update->retry_after_ms =
            (uint64_t)policy->throttle_seconds * UINT64_C(1000);
    }
    record_event("password_failure", "wrong_password");
    return AUTHD_DATABASE_WRITE_OK;
}

authd_database_write_result_t
authd_database_audit_login_rejection(
    authd_database_t *database,
    const uint8_t *user_id,
    const char *canonical_login_name,
    authd_login_rejection_reason_t reason,
    const char *source_ip,
    const char *protocol,
    char *error,
    size_t error_size)
{
    (void)user_id;
    (void)canonical_login_name;
    (void)source_ip;
    (void)protocol;
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL) {
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    record_event("rejection", authd_login_rejection_reason_name(reason));
    return AUTHD_DATABASE_WRITE_OK;
}

authd_database_write_result_t
authd_database_create_password_session(
    authd_database_t *database,
    const authd_login_record_t *record,
    const char *source_ip,
    const char *protocol,
    const char *tty_device,
    const char *node_id,
    authd_terminal_session_result_t *session,
    char *error,
    size_t error_size)
{
    (void)source_ip;
    (void)protocol;
    (void)tty_device;
    (void)node_id;
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || record == NULL || session == NULL) {
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    if (strcmp(record->login_name, "stale") == 0) {
        set_error(error, error_size, "test stale login state");
        return AUTHD_DATABASE_WRITE_STALE_STATE;
    }
    if (strcmp(record->login_name, "sessionerror") == 0) {
        set_error(error, error_size, "test session creation failure");
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    memset(session, 0, sizeof(*session));
    memcpy(session->user_id, record->user_id, FTAP_UUID_SIZE);
    memcpy(session->session_id, database->session_id, FTAP_UUID_SIZE);
    session->auth_epoch = record->auth_epoch;
    session->authz_revision = record->authz_revision;
    database->failed_count = 0U;
    database->session_open = true;
    record_event("session_create", record->login_name);
    return AUTHD_DATABASE_WRITE_OK;
}

authd_database_write_result_t
authd_database_close_terminal_session(
    authd_database_t *database,
    const uint8_t session_id[FTAP_UUID_SIZE],
    const char *ended_reason,
    char *error,
    size_t error_size)
{
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || session_id == NULL || ended_reason == NULL) {
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    if (!database->session_open ||
        memcmp(session_id, database->session_id, FTAP_UUID_SIZE) != 0) {
        return AUTHD_DATABASE_WRITE_NOT_FOUND;
    }
    database->session_open = false;
    record_event("session_close", ended_reason);
    return AUTHD_DATABASE_WRITE_OK;
}

authd_login_availability_t
authd_login_record_availability(const authd_login_record_t *record)
{
    if (record == NULL || record->auth_epoch == 0U ||
        record->authz_revision == 0U || record->login_name[0] == '\0' ||
        record->display_name[0] == '\0' || record->password_hash[0] == '\0') {
        return AUTHD_LOGIN_INVALID_RECORD;
    }
    if (record->deleted ||
        record->account_state == AUTHD_ACCOUNT_STATE_DELETED) {
        return AUTHD_LOGIN_DELETED;
    }
    if (record->account_state == AUTHD_ACCOUNT_STATE_PENDING) {
        return AUTHD_LOGIN_PENDING;
    }
    if (record->account_state == AUTHD_ACCOUNT_STATE_DISABLED) {
        return AUTHD_LOGIN_DISABLED;
    }
    if (record->account_state == AUTHD_ACCOUNT_STATE_LOCKED) {
        return AUTHD_LOGIN_LOCKED;
    }
    if (record->account_state != AUTHD_ACCOUNT_STATE_ACTIVE) {
        return AUTHD_LOGIN_INVALID_RECORD;
    }
    if (record->throttled) {
        return AUTHD_LOGIN_THROTTLED;
    }
    if (record->must_change) {
        return AUTHD_LOGIN_PASSWORD_CHANGE_REQUIRED;
    }
    return AUTHD_LOGIN_AVAILABLE;
}

const char *
authd_account_state_name(authd_account_state_t state)
{
    (void)state;
    return "test";
}

const char *
authd_database_lookup_result_name(authd_database_lookup_result_t result)
{
    (void)result;
    return "test";
}

const char *
authd_login_availability_name(authd_login_availability_t availability)
{
    (void)availability;
    return "test";
}

const char *
authd_database_write_result_name(authd_database_write_result_t result)
{
    switch (result) {
    case AUTHD_DATABASE_WRITE_OK:
        return "ok";
    case AUTHD_DATABASE_WRITE_NOT_FOUND:
        return "not_found";
    case AUTHD_DATABASE_WRITE_STALE_STATE:
        return "stale_state";
    case AUTHD_DATABASE_WRITE_INVALID_ARGUMENT:
        return "invalid_argument";
    case AUTHD_DATABASE_WRITE_INVALID_RECORD:
        return "invalid_record";
    case AUTHD_DATABASE_WRITE_ERROR:
    default:
        return "error";
    }
}

void
authd_database_close(authd_database_t *database)
{
    free(database);
}
