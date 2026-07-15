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
    unsigned int open_session_count;
    unsigned int registration_counter;
    bool registration_pending;
    authd_registration_begin_result_t registration;
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
    } else if (strcmp(canonical_login_name, "nossh") == 0) {
        seed = UINT8_C(8);
    }

    fill_uuid(record->user_id, seed);
    (void)snprintf(record->login_name, sizeof(record->login_name), "%s",
                   canonical_login_name);
    (void)snprintf(record->display_name, sizeof(record->display_name),
                   "Test %s", canonical_login_name);
    (void)snprintf(record->legacy_name, sizeof(record->legacy_name),
                   "%s", strcmp(canonical_login_name, "alice") == 0
                              ? "alice" : "testuser");
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
    if (strcmp(record->login_name, "nossh") == 0 &&
        strcmp(protocol, FTAP_PROTOCOL_SSH) == 0) {
        database->failed_count = 0U;
        record_event("rejection", "transport_not_authorized");
        set_error(error, error_size,
                  "transport is not authorized for this account");
        return AUTHD_DATABASE_WRITE_ACCESS_DENIED;
    }

    memset(session, 0, sizeof(*session));
    memcpy(session->user_id, record->user_id, FTAP_UUID_SIZE);
    memcpy(session->session_id, database->session_id, FTAP_UUID_SIZE);
    session->auth_epoch = record->auth_epoch;
    session->authz_revision = record->authz_revision;
    database->failed_count = 0U;
    ++database->open_session_count;
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
    if (database->open_session_count == 0U ||
        memcmp(session_id, database->session_id, FTAP_UUID_SIZE) != 0) {
        return AUTHD_DATABASE_WRITE_NOT_FOUND;
    }
    --database->open_session_count;
    record_event("session_close", ended_reason);
    return AUTHD_DATABASE_WRITE_OK;
}

authd_database_registration_result_t
authd_database_begin_registration(
    authd_database_t *database,
    const char *canonical_login_name,
    const char *display_name,
    const char *password_hash,
    const char *legacy_name,
    const char *source_ip,
    const char *tty_device,
    const char *node_id,
    uint32_t timeout_seconds,
    size_t max_pending,
    authd_registration_begin_result_t *registration,
    char *error,
    size_t error_size)
{
    (void)password_hash;
    (void)source_ip;
    (void)tty_device;
    (void)node_id;
    (void)timeout_seconds;
    (void)max_pending;
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || canonical_login_name == NULL ||
        display_name == NULL || legacy_name == NULL || registration == NULL) {
        return AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT;
    }
    if (strcmp(canonical_login_name, "taken") == 0) {
        return AUTHD_DATABASE_REGISTRATION_NAME_UNAVAILABLE;
    }
    if (strcmp(canonical_login_name, "dberror") == 0) {
        set_error(error, error_size, "test registration database failure");
        return AUTHD_DATABASE_REGISTRATION_ERROR;
    }
    if (strcmp(canonical_login_name, "dblimit") == 0 ||
        database->registration_pending) {
        return AUTHD_DATABASE_REGISTRATION_LIMIT_REACHED;
    }
    if (strcmp(canonical_login_name, "collide") == 0 &&
        strcmp(legacy_name, "collide") == 0) {
        record_event("registration_legacy_conflict", legacy_name);
        return AUTHD_DATABASE_REGISTRATION_LEGACY_CONFLICT;
    }

    ++database->registration_counter;
    memset(&database->registration, 0, sizeof(database->registration));
    fill_uuid(database->registration.registration_id,
              (uint8_t)(UINT8_C(0x40) + database->registration_counter));
    fill_uuid(database->registration.user_id,
              (uint8_t)(UINT8_C(0x20) + database->registration_counter));
    (void)snprintf(database->registration.login_name,
                   sizeof(database->registration.login_name), "%s",
                   canonical_login_name);
    (void)snprintf(database->registration.display_name,
                   sizeof(database->registration.display_name), "%s",
                   display_name);
    (void)snprintf(database->registration.legacy_name,
                   sizeof(database->registration.legacy_name), "%s",
                   legacy_name);
    database->registration.auth_epoch = UINT64_C(1);
    database->registration.authz_revision = UINT64_C(1);
    database->registration_pending = true;
    *registration = database->registration;
    record_event("registration_begin", legacy_name);
    return AUTHD_DATABASE_REGISTRATION_OK;
}

authd_database_registration_result_t
authd_database_commit_registration(
    authd_database_t *database,
    const authd_registration_begin_result_t *registration,
    const char *source_ip,
    const char *tty_device,
    const char *node_id,
    authd_registration_commit_result_t *commit,
    char *error,
    size_t error_size)
{
    (void)source_ip;
    (void)tty_device;
    (void)node_id;
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || registration == NULL || commit == NULL) {
        return AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT;
    }
    if (!database->registration_pending) {
        return AUTHD_DATABASE_REGISTRATION_NOT_FOUND;
    }
    if (memcmp(registration->registration_id,
               database->registration.registration_id,
               FTAP_UUID_SIZE) != 0 ||
        memcmp(registration->user_id, database->registration.user_id,
               FTAP_UUID_SIZE) != 0 ||
        strcmp(registration->login_name,
               database->registration.login_name) != 0) {
        return AUTHD_DATABASE_REGISTRATION_STALE_STATE;
    }
    if (strcmp(registration->login_name, "commitstale") == 0) {
        return AUTHD_DATABASE_REGISTRATION_STALE_STATE;
    }

    memset(commit, 0, sizeof(*commit));
    memcpy(commit->registration_id, registration->registration_id,
           FTAP_UUID_SIZE);
    memcpy(commit->session.user_id, registration->user_id, FTAP_UUID_SIZE);
    memcpy(commit->session.session_id, database->session_id, FTAP_UUID_SIZE);
    commit->session.auth_epoch = registration->auth_epoch;
    commit->session.authz_revision = registration->authz_revision + UINT64_C(1);
    (void)snprintf(commit->login_name, sizeof(commit->login_name), "%s",
                   registration->login_name);
    (void)snprintf(commit->display_name, sizeof(commit->display_name), "%s",
                   registration->display_name);
    (void)snprintf(commit->legacy_name, sizeof(commit->legacy_name), "%s",
                   registration->legacy_name);
    database->registration_pending = false;
    ++database->open_session_count;
    record_event("registration_commit", registration->login_name);
    return AUTHD_DATABASE_REGISTRATION_OK;
}

authd_database_registration_result_t
authd_database_abort_registration(
    authd_database_t *database,
    const uint8_t registration_id[FTAP_UUID_SIZE],
    const uint8_t user_id[FTAP_UUID_SIZE],
    const char *reason,
    char *error,
    size_t error_size)
{
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || registration_id == NULL || user_id == NULL ||
        reason == NULL) {
        return AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT;
    }
    if (!database->registration_pending) {
        return AUTHD_DATABASE_REGISTRATION_NOT_FOUND;
    }
    if (memcmp(registration_id, database->registration.registration_id,
               FTAP_UUID_SIZE) != 0 ||
        memcmp(user_id, database->registration.user_id,
               FTAP_UUID_SIZE) != 0) {
        return AUTHD_DATABASE_REGISTRATION_STALE_STATE;
    }
    database->registration_pending = false;
    record_event("registration_abort", reason);
    return AUTHD_DATABASE_REGISTRATION_OK;
}

authd_database_registration_result_t
authd_database_expire_registrations(
    authd_database_t *database,
    size_t batch_limit,
    size_t *expired_count,
    char *error,
    size_t error_size)
{
    (void)batch_limit;
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || expired_count == NULL) {
        return AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT;
    }
    *expired_count = 0U;
    return AUTHD_DATABASE_REGISTRATION_OK;
}

authd_login_availability_t
authd_login_record_availability(const authd_login_record_t *record)
{
    if (record == NULL || record->auth_epoch == 0U ||
        record->authz_revision == 0U || record->login_name[0] == '\0' ||
        record->display_name[0] == '\0' || record->legacy_name[0] == '\0' ||
        record->password_hash[0] == '\0') {
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
    case AUTHD_DATABASE_WRITE_ACCESS_DENIED:
        return "access_denied";
    case AUTHD_DATABASE_WRITE_INVALID_ARGUMENT:
        return "invalid_argument";
    case AUTHD_DATABASE_WRITE_INVALID_RECORD:
        return "invalid_record";
    case AUTHD_DATABASE_WRITE_ERROR:
    default:
        return "error";
    }
}

const char *
authd_database_registration_result_name(
    authd_database_registration_result_t result)
{
    switch (result) {
    case AUTHD_DATABASE_REGISTRATION_OK:
        return "ok";
    case AUTHD_DATABASE_REGISTRATION_NAME_UNAVAILABLE:
        return "name_unavailable";
    case AUTHD_DATABASE_REGISTRATION_LEGACY_CONFLICT:
        return "legacy_conflict";
    case AUTHD_DATABASE_REGISTRATION_LIMIT_REACHED:
        return "limit_reached";
    case AUTHD_DATABASE_REGISTRATION_NOT_FOUND:
        return "not_found";
    case AUTHD_DATABASE_REGISTRATION_STALE_STATE:
        return "stale_state";
    case AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT:
        return "invalid_argument";
    case AUTHD_DATABASE_REGISTRATION_INVALID_RECORD:
        return "invalid_record";
    case AUTHD_DATABASE_REGISTRATION_ERROR:
    default:
        return "error";
    }
}

void
authd_database_close(authd_database_t *database)
{
    free(database);
}
