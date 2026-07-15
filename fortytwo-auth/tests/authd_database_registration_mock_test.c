/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Linker-wrapped transaction and result-shape tests for registration storage.
 */

#include "authd_config.h"
#include "authd_database.h"
#include "authd_database_validation.h"

#include <libpq-fe.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FAKE_ROWS 16
#define MAX_FAKE_FIELDS 17

static const char user_hex[] = "00112233445566778899aabbccddeeff";
static const char user_text[] = "00112233-4455-6677-8899-aabbccddeeff";
static const char registration_hex[] =
    "102132435465768798a9bacbdcedfe0f";
static const char registration_text[] =
    "10213243-5465-7687-98a9-bacbdcedfe0f";
static const char session_hex[] = "ffeeddccbbaa99887766554433221100";

typedef enum test_mode {
    TEST_MODE_OK = 0,
    TEST_MODE_BEGIN_LIMIT,
    TEST_MODE_BEGIN_NAME_CONFLICT,
    TEST_MODE_BEGIN_LEGACY_CONFLICT,
    TEST_MODE_COMMIT_NOT_FOUND,
    TEST_MODE_COMMIT_STALE,
    TEST_MODE_ABORT_NOT_FOUND,
    TEST_MODE_ABORT_STALE
} test_mode_t;

struct fake_connection {
    int marker;
};

struct fake_result {
    ExecStatusType status;
    int rows;
    int fields;
    const char *values[MAX_FAKE_ROWS][MAX_FAKE_FIELDS];
};

static struct fake_connection fake_connection;
static test_mode_t test_mode;
static char migration_versions[AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT][32];

PGconn *__wrap_PQconnectdbParams(const char *const *keywords,
                                 const char *const *values,
                                 int expand_dbname);
PQnoticeProcessor __wrap_PQsetNoticeProcessor(PGconn *connection,
                                              PQnoticeProcessor processor,
                                              void *argument);
ConnStatusType __wrap_PQstatus(const PGconn *connection);
int __wrap_PQprotocolVersion(const PGconn *connection);
int __wrap_PQconnectionUsedPassword(const PGconn *connection);
int __wrap_PQsetClientEncoding(PGconn *connection, const char *encoding);
PGresult *__wrap_PQexec(PGconn *connection, const char *sql);
PGresult *__wrap_PQexecParams(PGconn *connection,
                              const char *command,
                              int parameter_count,
                              const Oid *parameter_types,
                              const char *const *parameter_values,
                              const int *parameter_lengths,
                              const int *parameter_formats,
                              int result_format);
ExecStatusType __wrap_PQresultStatus(const PGresult *result);
int __wrap_PQntuples(const PGresult *result);
int __wrap_PQnfields(const PGresult *result);
int __wrap_PQgetisnull(const PGresult *result, int row, int column);
char *__wrap_PQgetvalue(const PGresult *result, int row, int column);
char *__wrap_PQresultErrorMessage(const PGresult *result);
char *__wrap_PQerrorMessage(const PGconn *connection);
void __wrap_PQclear(PGresult *result);
void __wrap_PQfinish(PGconn *connection);

static struct fake_result *
new_result(ExecStatusType status, int rows, int fields)
{
    struct fake_result *result;

    assert(rows >= 0 && rows <= MAX_FAKE_ROWS);
    assert(fields >= 0 && fields <= MAX_FAKE_FIELDS);
    result = calloc(1U, sizeof(*result));
    assert(result != NULL);
    result->status = status;
    result->rows = rows;
    result->fields = fields;
    return result;
}

static void
set_value(struct fake_result *result, int row, int column, const char *value)
{
    assert(result != NULL);
    assert(row >= 0 && row < result->rows);
    assert(column >= 0 && column < result->fields);
    result->values[row][column] = value;
}

static struct fake_result *
single_value(const char *value)
{
    struct fake_result *result = new_result(PGRES_TUPLES_OK, 1, 1);
    set_value(result, 0, 0, value);
    return result;
}

PGconn *
__wrap_PQconnectdbParams(const char *const *keywords,
                         const char *const *values,
                         int expand_dbname)
{
    (void)keywords;
    (void)values;
    assert(expand_dbname == 0);
    return (PGconn *)&fake_connection;
}

PQnoticeProcessor
__wrap_PQsetNoticeProcessor(PGconn *connection,
                            PQnoticeProcessor processor,
                            void *argument)
{
    (void)connection;
    (void)processor;
    (void)argument;
    return NULL;
}

ConnStatusType
__wrap_PQstatus(const PGconn *connection)
{
    assert(connection == (const PGconn *)&fake_connection);
    return CONNECTION_OK;
}

int
__wrap_PQprotocolVersion(const PGconn *connection)
{
    assert(connection == (const PGconn *)&fake_connection);
    return 3;
}

int
__wrap_PQconnectionUsedPassword(const PGconn *connection)
{
    assert(connection == (const PGconn *)&fake_connection);
    return 0;
}

int
__wrap_PQsetClientEncoding(PGconn *connection, const char *encoding)
{
    assert(connection == (PGconn *)&fake_connection);
    assert(strcmp(encoding, "UTF8") == 0);
    return 0;
}

PGresult *
__wrap_PQexec(PGconn *connection, const char *sql)
{
    struct fake_result *result;
    size_t count;
    size_t row;
    const authd_migration_record_t *migrations;

    assert(connection == (PGconn *)&fake_connection);
    assert(sql != NULL);

    if (strcmp(sql, "BEGIN") == 0 || strcmp(sql, "COMMIT") == 0 ||
        strcmp(sql, "ROLLBACK") == 0) {
        return (PGresult *)new_result(PGRES_COMMAND_OK, 0, 0);
    }
    if (strstr(sql, "set_config") != NULL) {
        return (PGresult *)new_result(PGRES_TUPLES_OK, 1, 4);
    }
    if (strstr(sql, "CURRENT_USER") != NULL) {
        result = new_result(PGRES_TUPLES_OK, 1, 4);
        set_value(result, 0, 0, "fortytwo_authd");
        set_value(result, 0, 1, "fortytwo");
        set_value(result, 0, 2, "170010");
        set_value(result, 0, 3, "off");
        return (PGresult *)result;
    }
    if (strstr(sql, "fortytwo_schema_migrations") != NULL) {
        migrations = authd_database_required_migrations(&count);
        assert(count == AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT);
        result = new_result(PGRES_TUPLES_OK, (int)count, 3);
        for (row = 0U; row < count; ++row) {
            (void)snprintf(migration_versions[row],
                           sizeof(migration_versions[row]), "%zu", row + 1U);
            set_value(result, (int)row, 0, migration_versions[row]);
            set_value(result, (int)row, 1, migrations[row].name);
            set_value(result, (int)row, 2, migrations[row].checksum);
        }
        return (PGresult *)result;
    }

    assert(!"unexpected PQexec SQL");
    return NULL;
}

static struct fake_result *
commit_lock_result(void)
{
    struct fake_result *result;

    if (test_mode == TEST_MODE_COMMIT_NOT_FOUND) {
        return new_result(PGRES_TUPLES_OK, 0, 17);
    }
    result = new_result(PGRES_TUPLES_OK, 1, 17);
    set_value(result, 0, 0, registration_hex);
    set_value(result, 0, 1, user_hex);
    set_value(result, 0, 2, "neo67");
    set_value(result, 0, 3, "Neo 67");
    set_value(result, 0, 4, "neo67");
    set_value(result, 0, 5, "neo67");
    set_value(result, 0, 6,
              test_mode == TEST_MODE_COMMIT_STALE ? "completed" :
                                                     "pending_legacy");
    set_value(result, 0, 7, "telnet");
    set_value(result, 0, 8, "1");
    set_value(result, 0, 9, "1");
    set_value(result, 0, 10, "1");
    set_value(result, 0, 11, "pending");
    set_value(result, 0, 12, "0");
    set_value(result, 0, 13, "1");
    set_value(result, 0, 14, "1");
    set_value(result, 0, 15, "0");
    set_value(result, 0, 16, "0");
    return result;
}

static struct fake_result *
abort_lock_result(void)
{
    struct fake_result *result;

    if (test_mode == TEST_MODE_ABORT_NOT_FOUND) {
        return new_result(PGRES_TUPLES_OK, 0, 4);
    }
    result = new_result(PGRES_TUPLES_OK, 1, 4);
    set_value(result, 0, 0,
              test_mode == TEST_MODE_ABORT_STALE ? "completed" :
                                                    "pending_legacy");
    set_value(result, 0, 1, "pending");
    set_value(result, 0, 2, "0");
    set_value(result, 0, 3, "1");
    return result;
}

PGresult *
__wrap_PQexecParams(PGconn *connection,
                    const char *command,
                    int parameter_count,
                    const Oid *parameter_types,
                    const char *const *parameter_values,
                    const int *parameter_lengths,
                    const int *parameter_formats,
                    int result_format)
{
    struct fake_result *result;

    assert(connection == (PGconn *)&fake_connection);
    assert(command != NULL);
    assert(parameter_types == NULL);
    assert(parameter_values != NULL);
    assert(parameter_lengths == NULL);
    assert(parameter_formats == NULL);
    assert(result_format == 0);

    if (strstr(command, "WITH expired AS MATERIALIZED") != NULL) {
        assert(parameter_count == 1);
        assert(strstr(command, "FOR UPDATE OF r, u SKIP LOCKED") != NULL);
        assert(strstr(command, "registration_timeout") != NULL);
        return (PGresult *)single_value("2");
    }
    if (strstr(command, "pg_advisory_xact_lock") != NULL) {
        assert(parameter_count == 1);
        assert(strcmp(parameter_values[0], "16") == 0);
        return (PGresult *)single_value(
            test_mode == TEST_MODE_BEGIN_LIMIT ? "0" : "1");
    }
    if (strstr(command, "INSERT INTO public.bbs_users ") != NULL) {
        assert(parameter_count == 1);
        assert(strcmp(parameter_values[0], "neo67") == 0);
        if (test_mode == TEST_MODE_BEGIN_NAME_CONFLICT) {
            return (PGresult *)new_result(PGRES_TUPLES_OK, 0, 3);
        }
        result = new_result(PGRES_TUPLES_OK, 1, 3);
        set_value(result, 0, 0, user_hex);
        set_value(result, 0, 1, "1");
        set_value(result, 0, 2, "1");
        return (PGresult *)result;
    }
    if (strstr(command, "INSERT INTO public.bbs_user_profiles") != NULL) {
        assert(parameter_count == 2);
        assert(strcmp(parameter_values[0], user_text) == 0);
        assert(strcmp(parameter_values[1], "Neo 67") == 0);
        return (PGresult *)single_value(user_hex);
    }
    if (strstr(command,
               "INSERT INTO public.bbs_password_credentials") != NULL) {
        assert(parameter_count == 2);
        assert(strcmp(parameter_values[0], user_text) == 0);
        assert(strncmp(parameter_values[1], "$argon2id$", 10U) == 0);
        return (PGresult *)single_value(user_hex);
    }
    if (strstr(command,
               "INSERT INTO public.bbs_legacy_mbse_bindings") != NULL) {
        assert(parameter_count == 2);
        assert(strcmp(parameter_values[0], user_text) == 0);
        assert(strcmp(parameter_values[1], "neo67") == 0);
        if (test_mode == TEST_MODE_BEGIN_LEGACY_CONFLICT) {
            return (PGresult *)new_result(PGRES_TUPLES_OK, 0, 1);
        }
        return (PGresult *)single_value(user_hex);
    }
    if (strstr(command,
               "INSERT INTO public.bbs_registration_attempts") != NULL) {
        assert(parameter_count == 6);
        assert(strcmp(parameter_values[0], user_text) == 0);
        assert(strcmp(parameter_values[1], "neo67") == 0);
        assert(strcmp(parameter_values[2], "192.0.2.42") == 0);
        assert(strcmp(parameter_values[5], "600") == 0);
        return (PGresult *)single_value(registration_hex);
    }
    if (strstr(command, "auth.registration_started") != NULL) {
        assert(parameter_count == 7);
        assert(strcmp(parameter_values[0], user_text) == 0);
        assert(strcmp(parameter_values[2], registration_text) == 0);
        return (PGresult *)single_value("41");
    }
    if (strstr(command, "FOR UPDATE OF r, u, p, m") != NULL) {
        assert(parameter_count == 5);
        assert(strcmp(parameter_values[0], registration_text) == 0);
        assert(strcmp(parameter_values[1], user_text) == 0);
        return (PGresult *)commit_lock_result();
    }
    if (strstr(command, "INSERT INTO public.bbs_user_roles") != NULL) {
        assert(parameter_count == 1);
        assert(strstr(command, "role_name = 'bbs_user'") != NULL);
        assert(strstr(command, "ssh_access") == NULL);
        return (PGresult *)single_value("1");
    }
    if (strstr(command, "authz_revision = authz_revision + 1") != NULL) {
        result = new_result(PGRES_TUPLES_OK, 1, 2);
        set_value(result, 0, 0, "1");
        set_value(result, 0, 1, "2");
        return (PGresult *)result;
    }
    if (strstr(command, "registration_state = 'completed'") != NULL) {
        assert(parameter_count == 2);
        return (PGresult *)single_value(registration_hex);
    }
    if (strstr(command, "INSERT INTO public.bbs_terminal_sessions") != NULL) {
        assert(parameter_count == 5);
        assert(strstr(command, "'telnet', 'password'") != NULL);
        return (PGresult *)single_value(session_hex);
    }
    if (strstr(command, "auth.registration_completed") != NULL ||
        strstr(command, "auth.login_succeeded") != NULL) {
        assert(parameter_count == 10);
        assert(strcmp(parameter_values[3], registration_text) == 0);
        return (PGresult *)single_value("42");
    }
    if (strstr(command, "FOR UPDATE OF r, u") != NULL &&
        strstr(command, "SKIP LOCKED") == NULL) {
        assert(parameter_count == 2);
        return (PGresult *)abort_lock_result();
    }
    if (strstr(command, "registration_state = 'aborted'") != NULL) {
        assert(parameter_count == 3);
        assert(strcmp(parameter_values[2], "client_cancelled") == 0);
        return (PGresult *)single_value(registration_hex);
    }
    if (strstr(command, "auth_epoch = auth_epoch + 1") != NULL &&
        strstr(command, "account_state = 'deleted'") != NULL &&
        strstr(command, "WITH expired AS MATERIALIZED") == NULL) {
        assert(parameter_count == 1);
        return (PGresult *)single_value("2");
    }
    if (strstr(command, "DELETE FROM public.bbs_user_roles") != NULL) {
        assert(parameter_count == 1);
        return (PGresult *)new_result(PGRES_TUPLES_OK, 0, 1);
    }
    if (strstr(command,
               "DELETE FROM public.bbs_password_credentials") != NULL ||
        strstr(command, "DELETE FROM public.bbs_user_profiles") != NULL ||
        strstr(command,
               "DELETE FROM public.bbs_legacy_mbse_bindings") != NULL) {
        assert(parameter_count == 1);
        return (PGresult *)single_value(user_hex);
    }
    if (strstr(command, "auth.registration_aborted") != NULL) {
        assert(parameter_count == 3);
        return (PGresult *)single_value("43");
    }

    assert(!"unexpected PQexecParams SQL");
    return NULL;
}

ExecStatusType
__wrap_PQresultStatus(const PGresult *result)
{
    return ((const struct fake_result *)result)->status;
}

int
__wrap_PQntuples(const PGresult *result)
{
    return ((const struct fake_result *)result)->rows;
}

int
__wrap_PQnfields(const PGresult *result)
{
    return ((const struct fake_result *)result)->fields;
}

int
__wrap_PQgetisnull(const PGresult *result, int row, int column)
{
    const struct fake_result *fake = (const struct fake_result *)result;
    assert(row >= 0 && row < fake->rows);
    assert(column >= 0 && column < fake->fields);
    return fake->values[row][column] == NULL;
}

char *
__wrap_PQgetvalue(const PGresult *result, int row, int column)
{
    const struct fake_result *fake = (const struct fake_result *)result;
    assert(row >= 0 && row < fake->rows);
    assert(column >= 0 && column < fake->fields);
    assert(fake->values[row][column] != NULL);
    return (char *)fake->values[row][column];
}

char *
__wrap_PQresultErrorMessage(const PGresult *result)
{
    (void)result;
    return (char *)"mock registration query failure\n";
}

char *
__wrap_PQerrorMessage(const PGconn *connection)
{
    (void)connection;
    return (char *)"mock registration connection failure\n";
}

void
__wrap_PQclear(PGresult *result)
{
    free(result);
}

void
__wrap_PQfinish(PGconn *connection)
{
    assert(connection == (PGconn *)&fake_connection);
}

static authd_database_t *
open_database(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    char error[AUTHD_DATABASE_ERROR_MAX];

    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);
    assert(info.migration_count == AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT);
    return database;
}

static void
fill_registration(authd_registration_begin_result_t *registration)
{
    static const uint8_t registration_id[FTAP_UUID_SIZE] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f
    };
    static const uint8_t user_id[FTAP_UUID_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    memset(registration, 0, sizeof(*registration));
    memcpy(registration->registration_id, registration_id, FTAP_UUID_SIZE);
    memcpy(registration->user_id, user_id, FTAP_UUID_SIZE);
    (void)snprintf(registration->login_name,
                   sizeof(registration->login_name), "%s", "neo67");
    (void)snprintf(registration->display_name,
                   sizeof(registration->display_name), "%s", "Neo 67");
    (void)snprintf(registration->legacy_name,
                   sizeof(registration->legacy_name), "%s", "neo67");
    registration->auth_epoch = 1U;
    registration->authz_revision = 1U;
}

static void
test_begin(authd_database_t *database)
{
    static const char hash[] =
        "$argon2id$v=19$m=262144,t=3,p=1$c2FsdA$aGFzaA";
    authd_registration_begin_result_t registration;
    char error[AUTHD_DATABASE_ERROR_MAX];

    test_mode = TEST_MODE_OK;
    assert(authd_database_begin_registration(
        database, "neo67", "Neo 67", hash, "neo67", "192.0.2.42",
        "/dev/pts/7", "node-a", 600U, 16U, &registration,
        error, sizeof(error)) == AUTHD_DATABASE_REGISTRATION_OK);
    assert(memcmp(registration.user_id,
                  (const uint8_t[]){
                      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                  FTAP_UUID_SIZE) == 0);
    assert(strcmp(registration.login_name, "neo67") == 0);
    assert(registration.auth_epoch == 1U);

    test_mode = TEST_MODE_BEGIN_LIMIT;
    assert(authd_database_begin_registration(
        database, "neo67", "Neo 67", hash, "neo67", "192.0.2.42",
        NULL, NULL, 600U, 16U, &registration, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_LIMIT_REACHED);

    test_mode = TEST_MODE_BEGIN_NAME_CONFLICT;
    assert(authd_database_begin_registration(
        database, "neo67", "Neo 67", hash, "neo67", "192.0.2.42",
        NULL, NULL, 600U, 16U, &registration, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_NAME_UNAVAILABLE);

    test_mode = TEST_MODE_BEGIN_LEGACY_CONFLICT;
    assert(authd_database_begin_registration(
        database, "neo67", "Neo 67", hash, "neo67", "192.0.2.42",
        NULL, NULL, 600U, 16U, &registration, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_LEGACY_CONFLICT);

    test_mode = TEST_MODE_OK;
    assert(authd_database_begin_registration(
        database, "Neo67", "Neo 67", hash, "neo67", "192.0.2.42",
        NULL, NULL, 600U, 16U, &registration, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT);
    assert(authd_database_begin_registration(
        database, "neo67", "Neo 67", "not-a-hash", "neo67",
        "192.0.2.42", NULL, NULL, 600U, 16U, &registration,
        error, sizeof(error)) == AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT);
}

static void
test_commit(authd_database_t *database)
{
    authd_registration_begin_result_t registration;
    authd_registration_commit_result_t commit;
    char error[AUTHD_DATABASE_ERROR_MAX];

    fill_registration(&registration);
    test_mode = TEST_MODE_OK;
    assert(authd_database_commit_registration(
        database, &registration, "192.0.2.42", "/dev/pts/7", "node-a",
        &commit, error, sizeof(error)) == AUTHD_DATABASE_REGISTRATION_OK);
    assert(memcmp(commit.registration_id, registration.registration_id,
                  FTAP_UUID_SIZE) == 0);
    assert(memcmp(commit.session.user_id, registration.user_id,
                  FTAP_UUID_SIZE) == 0);
    assert(commit.session.auth_epoch == 1U);
    assert(commit.session.authz_revision == 2U);
    assert(strcmp(commit.login_name, "neo67") == 0);

    test_mode = TEST_MODE_COMMIT_NOT_FOUND;
    assert(authd_database_commit_registration(
        database, &registration, "192.0.2.42", "/dev/pts/7", "node-a",
        &commit, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_NOT_FOUND);

    test_mode = TEST_MODE_COMMIT_STALE;
    assert(authd_database_commit_registration(
        database, &registration, "192.0.2.42", "/dev/pts/7", "node-a",
        &commit, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_STALE_STATE);

    test_mode = TEST_MODE_OK;
    assert(authd_database_commit_registration(
        database, &registration, "invalid-ip", "/dev/pts/7", "node-a",
        &commit, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT);
}

static void
test_abort_and_expire(authd_database_t *database)
{
    authd_registration_begin_result_t registration;
    size_t expired_count;
    char error[AUTHD_DATABASE_ERROR_MAX];

    fill_registration(&registration);
    test_mode = TEST_MODE_OK;
    assert(authd_database_abort_registration(
        database, registration.registration_id, registration.user_id,
        "client_cancelled", error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_OK);

    test_mode = TEST_MODE_ABORT_NOT_FOUND;
    assert(authd_database_abort_registration(
        database, registration.registration_id, registration.user_id,
        "client_cancelled", error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_NOT_FOUND);

    test_mode = TEST_MODE_ABORT_STALE;
    assert(authd_database_abort_registration(
        database, registration.registration_id, registration.user_id,
        "client_cancelled", error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_STALE_STATE);

    test_mode = TEST_MODE_OK;
    assert(authd_database_abort_registration(
        database, registration.registration_id, registration.user_id,
        "Client Cancelled", error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT);

    assert(authd_database_expire_registrations(
        database, 16U, &expired_count, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_OK);
    assert(expired_count == 2U);
    assert(authd_database_expire_registrations(
        database, 0U, &expired_count, error, sizeof(error)) ==
        AUTHD_DATABASE_REGISTRATION_INVALID_ARGUMENT);
}

int
main(void)
{
    authd_database_t *database = open_database();

    test_begin(database);
    test_commit(database);
    test_abort_and_expire(database);
    assert(strcmp(authd_database_registration_result_name(
                      AUTHD_DATABASE_REGISTRATION_LEGACY_CONFLICT),
                  "legacy_conflict") == 0);
    authd_database_close(database);
    (void)puts("authd database registration wrapper tests: OK");
    return 0;
}
