/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Linker-wrapped libpq test for the production database module.
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

struct fake_connection {
    int marker;
};

typedef enum fake_result_kind {
    FAKE_RESULT_SESSION,
    FAKE_RESULT_IDENTITY,
    FAKE_RESULT_MIGRATIONS,
    FAKE_RESULT_LOGIN,
    FAKE_RESULT_HEALTH,
    FAKE_RESULT_ERROR
} fake_result_kind_t;

struct fake_result {
    fake_result_kind_t kind;
};

typedef struct fake_scenario {
    ConnStatusType connection_status;
    int protocol_version;
    int used_password;
    int encoding_result;
    const char *role;
    const char *database;
    const char *server_version;
    const char *read_only;
    size_t migration_count;
    bool migration_checksum_bad;
    bool login_found;
    bool login_query_error;
    int login_null_column;
    const char *login_values[12];
    bool health_ok;
} fake_scenario_t;

static struct fake_connection fake_connection;
static fake_scenario_t scenario;
static char migration_versions[AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT][16];

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

static void
reset_scenario(void)
{
    size_t index;

    memset(&scenario, 0, sizeof(scenario));
    scenario.connection_status = CONNECTION_OK;
    scenario.protocol_version = 3;
    scenario.role = "fortytwo_authd";
    scenario.database = "fortytwo";
    scenario.server_version = "170010";
    scenario.read_only = "off";
    scenario.migration_count = AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT;
    scenario.login_found = true;
    scenario.login_null_column = -1;
    scenario.login_values[0] = "00112233445566778899aabbccddeeff";
    scenario.login_values[1] = "neo67";
    scenario.login_values[2] = "active";
    scenario.login_values[3] = "0";
    scenario.login_values[4] = "0";
    scenario.login_values[5] = "7";
    scenario.login_values[6] = "0";
    scenario.login_values[7] = "Neo 67";
    scenario.login_values[8] =
        "$argon2id$v=19$m=262144,t=3,p=1$test$test";
    scenario.login_values[9] = "0";
    scenario.login_values[10] = "2";
    scenario.login_values[11] = "1720000000000";
    scenario.health_ok = true;

    for (index = 0U; index < AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT; ++index) {
        (void)snprintf(migration_versions[index],
                       sizeof(migration_versions[index]), "%zu", index + 1U);
    }
}

PGconn *
__wrap_PQconnectdbParams(const char *const *keywords,
                         const char *const *values,
                         int expand_dbname)
{
    size_t index;
    bool saw_host = false;
    bool saw_user = false;
    bool saw_target = false;

    assert(expand_dbname == 0);
    assert(keywords != NULL);
    assert(values != NULL);
    for (index = 0U; keywords[index] != NULL; ++index) {
        assert(values[index] != NULL);
        if (strcmp(keywords[index], "host") == 0) {
            assert(values[index][0] == '/');
            saw_host = true;
        } else if (strcmp(keywords[index], "user") == 0) {
            assert(strcmp(values[index], "fortytwo_authd") == 0);
            saw_user = true;
        } else if (strcmp(keywords[index], "target_session_attrs") == 0) {
            assert(strcmp(values[index], "read-write") == 0);
            saw_target = true;
        }
    }
    assert(saw_host && saw_user && saw_target);
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
    return scenario.connection_status;
}

int
__wrap_PQprotocolVersion(const PGconn *connection)
{
    assert(connection == (const PGconn *)&fake_connection);
    return scenario.protocol_version;
}

int
__wrap_PQconnectionUsedPassword(const PGconn *connection)
{
    assert(connection == (const PGconn *)&fake_connection);
    return scenario.used_password;
}

int
__wrap_PQsetClientEncoding(PGconn *connection, const char *encoding)
{
    assert(connection == (PGconn *)&fake_connection);
    assert(strcmp(encoding, "UTF8") == 0);
    return scenario.encoding_result;
}

PGresult *
__wrap_PQexec(PGconn *connection, const char *sql)
{
    struct fake_result *result;

    assert(connection == (PGconn *)&fake_connection);
    assert(sql != NULL);
    result = calloc(1U, sizeof(*result));
    assert(result != NULL);

    if (strstr(sql, "set_config") != NULL) {
        result->kind = FAKE_RESULT_SESSION;
    } else if (strstr(sql, "CURRENT_USER") != NULL) {
        result->kind = FAKE_RESULT_IDENTITY;
    } else if (strcmp(
                   sql,
                   "SELECT migration_version::pg_catalog.text, "
                   "migration_name, checksum_sha256 "
                   "FROM public.fortytwo_schema_migrations "
                   "ORDER BY migration_version") == 0) {
        result->kind = FAKE_RESULT_MIGRATIONS;
    } else if (strcmp(sql, "SELECT 1") == 0) {
        result->kind = scenario.health_ok ? FAKE_RESULT_HEALTH :
                                            FAKE_RESULT_ERROR;
    } else {
        assert(!"unexpected SQL in database module");
    }

    return (PGresult *)result;
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
    assert(strstr(command, "FROM public.bbs_users AS u") != NULL);
    assert(strstr(command, "WHERE u.login_name = $1") != NULL);
    assert(strstr(command, "neo67") == NULL);
    assert(parameter_count == 1);
    assert(parameter_types == NULL);
    assert(parameter_values != NULL);
    assert(strcmp(parameter_values[0], "neo67") == 0);
    assert(parameter_lengths == NULL);
    assert(parameter_formats == NULL);
    assert(result_format == 0);

    result = calloc(1U, sizeof(*result));
    assert(result != NULL);
    result->kind = scenario.login_query_error ? FAKE_RESULT_ERROR :
                                                FAKE_RESULT_LOGIN;
    return (PGresult *)result;
}

ExecStatusType
__wrap_PQresultStatus(const PGresult *result)
{
    const struct fake_result *fake = (const struct fake_result *)result;

    if (fake->kind == FAKE_RESULT_ERROR) {
        return PGRES_FATAL_ERROR;
    }
    if (fake->kind == FAKE_RESULT_SESSION) {
        return PGRES_TUPLES_OK;
    }
    return PGRES_TUPLES_OK;
}

int
__wrap_PQntuples(const PGresult *result)
{
    const struct fake_result *fake = (const struct fake_result *)result;

    switch (fake->kind) {
    case FAKE_RESULT_SESSION:
        return 1;
    case FAKE_RESULT_IDENTITY:
        return 1;
    case FAKE_RESULT_MIGRATIONS:
        return (int)scenario.migration_count;
    case FAKE_RESULT_LOGIN:
        return scenario.login_found ? 1 : 0;
    case FAKE_RESULT_HEALTH:
        return 1;
    case FAKE_RESULT_ERROR:
        return 0;
    default:
        assert(!"invalid fake result kind");
        return 0;
    }
}

int
__wrap_PQnfields(const PGresult *result)
{
    const struct fake_result *fake = (const struct fake_result *)result;

    switch (fake->kind) {
    case FAKE_RESULT_SESSION:
        return 4;
    case FAKE_RESULT_IDENTITY:
        return 4;
    case FAKE_RESULT_MIGRATIONS:
        return 3;
    case FAKE_RESULT_LOGIN:
        return 12;
    case FAKE_RESULT_HEALTH:
        return 1;
    case FAKE_RESULT_ERROR:
        return 0;
    default:
        assert(!"invalid fake result kind");
        return 0;
    }
}

int
__wrap_PQgetisnull(const PGresult *result, int row, int column)
{
    const struct fake_result *fake = (const struct fake_result *)result;

    (void)row;
    if (fake->kind == FAKE_RESULT_LOGIN &&
        column == scenario.login_null_column) {
        return 1;
    }
    return 0;
}

char *
__wrap_PQgetvalue(const PGresult *result, int row, int column)
{
    const struct fake_result *fake = (const struct fake_result *)result;
    size_t count;
    const authd_migration_record_t *required;

    if (fake->kind == FAKE_RESULT_IDENTITY) {
        assert(row == 0);
        switch (column) {
        case 0:
            return (char *)scenario.role;
        case 1:
            return (char *)scenario.database;
        case 2:
            return (char *)scenario.server_version;
        case 3:
            return (char *)scenario.read_only;
        default:
            assert(!"invalid identity column");
        }
    }

    if (fake->kind == FAKE_RESULT_MIGRATIONS) {
        required = authd_database_required_migrations(&count);
        assert(row >= 0 && (size_t)row < count);
        switch (column) {
        case 0:
            return migration_versions[row];
        case 1:
            return (char *)required[row].name;
        case 2:
            if (scenario.migration_checksum_bad && row == 3) {
                return (char *)
                    "0000000000000000000000000000000000000000000000000000000000000000";
            }
            return (char *)required[row].checksum;
        default:
            assert(!"invalid migration column");
        }
    }

    if (fake->kind == FAKE_RESULT_LOGIN) {
        assert(row == 0);
        assert(column >= 0 && column < 12);
        return (char *)scenario.login_values[column];
    }

    if (fake->kind == FAKE_RESULT_HEALTH) {
        assert(row == 0 && column == 0);
        return (char *)"1";
    }

    assert(!"PQgetvalue called for unsupported result");
    return (char *)"";
}

char *
__wrap_PQresultErrorMessage(const PGresult *result)
{
    const struct fake_result *fake = (const struct fake_result *)result;
    return fake->kind == FAKE_RESULT_ERROR ? (char *)"mock query failure\n" :
                                             (char *)"";
}

char *
__wrap_PQerrorMessage(const PGconn *connection)
{
    (void)connection;
    return (char *)"mock connection failure\n";
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

static void
expect_open_failure(const char *error_fragment)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    char error[AUTHD_DATABASE_ERROR_MAX];

    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) != 0);
    assert(database == NULL);
    assert(strstr(error, error_fragment) != NULL);
}

static void
test_success_and_health(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    char error[AUTHD_DATABASE_ERROR_MAX];

    reset_scenario();
    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);
    assert(database != NULL);
    assert(info.server_version_num == 170010);
    assert(info.migration_count == AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT);
    assert(info.highest_migration ==
           AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION);
    assert(authd_database_health_check(database,
                                       error, sizeof(error)) == 0);

    scenario.health_ok = false;
    assert(authd_database_health_check(database,
                                       error, sizeof(error)) != 0);
    assert(strstr(error, "health check") != NULL);
    authd_database_close(database);
}

static void
test_login_lookup(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    authd_login_record_t record;
    char error[AUTHD_DATABASE_ERROR_MAX];

    reset_scenario();
    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);

    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_OK);
    assert(record.user_id[0] == 0x00U);
    assert(record.user_id[1] == 0x11U);
    assert(record.user_id[15] == 0xffU);
    assert(strcmp(record.login_name, "neo67") == 0);
    assert(strcmp(record.display_name, "Neo 67") == 0);
    assert(record.account_state == AUTHD_ACCOUNT_STATE_ACTIVE);
    assert(record.auth_epoch == 7U);
    assert(!record.deleted);
    assert(!record.throttled);
    assert(record.retry_after_ms == 0U);
    assert(!record.must_change);
    assert(record.failed_count == 2U);
    assert(record.last_failed_at_set);
    assert(record.last_failed_at_epoch_ms == INT64_C(1720000000000));
    assert(authd_login_record_availability(&record) ==
           AUTHD_LOGIN_AVAILABLE);

    scenario.login_found = false;
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_NOT_FOUND);

    scenario.login_found = true;
    scenario.login_values[2] = "locked";
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_OK);
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_LOCKED);

    scenario.login_values[2] = "active";
    scenario.login_values[3] = "1";
    scenario.login_values[4] = "1200";
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_OK);
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_THROTTLED);
    assert(record.retry_after_ms == 1200U);

    scenario.login_values[3] = "0";
    scenario.login_values[4] = "0";
    scenario.login_values[9] = "1";
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_OK);
    assert(authd_login_record_availability(&record) ==
           AUTHD_LOGIN_PASSWORD_CHANGE_REQUIRED);

    scenario.login_values[9] = "0";
    scenario.login_null_column = 8;
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_INVALID_RECORD);
    assert(strstr(error, "required field") != NULL);

    scenario.login_null_column = -1;
    scenario.login_query_error = true;
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_ERROR);
    assert(strstr(error, "lookup failed") != NULL);

    scenario.login_query_error = false;
    assert(authd_database_lookup_login(database, "Neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_ERROR);
    assert(strstr(error, "arguments") != NULL);

    authd_database_close(database);
}

static void
test_login_availability(void)
{
    authd_login_record_t record;

    memset(&record, 0, sizeof(record));
    record.auth_epoch = 1U;
    (void)snprintf(record.login_name, sizeof(record.login_name), "%s",
                   "neo67");
    (void)snprintf(record.display_name, sizeof(record.display_name), "%s",
                   "Neo 67");
    (void)snprintf(record.password_hash, sizeof(record.password_hash), "%s",
                   "$argon2id$v=19$m=262144,t=3,p=1$test$test");

    record.account_state = AUTHD_ACCOUNT_STATE_PENDING;
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_PENDING);
    record.account_state = AUTHD_ACCOUNT_STATE_DISABLED;
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_DISABLED);
    record.account_state = AUTHD_ACCOUNT_STATE_LOCKED;
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_LOCKED);
    record.account_state = AUTHD_ACCOUNT_STATE_DELETED;
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_DELETED);

    record.account_state = AUTHD_ACCOUNT_STATE_ACTIVE;
    record.deleted = true;
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_DELETED);
    record.deleted = false;
    record.throttled = true;
    record.retry_after_ms = 1U;
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_THROTTLED);
    record.throttled = false;
    record.retry_after_ms = 0U;
    record.must_change = true;
    assert(authd_login_record_availability(&record) ==
           AUTHD_LOGIN_PASSWORD_CHANGE_REQUIRED);
    record.must_change = false;
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_AVAILABLE);

    record.auth_epoch = 0U;
    assert(authd_login_record_availability(&record) ==
           AUTHD_LOGIN_INVALID_RECORD);
}

static void
test_rejections(void)
{
    reset_scenario();
    scenario.used_password = 1;
    expect_open_failure("password authentication");

    reset_scenario();
    scenario.role = "fortytwo_db_owner";
    expect_open_failure("role");

    reset_scenario();
    scenario.read_only = "on";
    expect_open_failure("read-only");

    reset_scenario();
    scenario.migration_count = 3U;
    expect_open_failure("registered migrations");

    reset_scenario();
    scenario.migration_checksum_bad = true;
    expect_open_failure("checksum mismatch");
}

int
main(void)
{
    test_success_and_health();
    test_login_lookup();
    test_login_availability();
    test_rejections();
    (void)puts("authd database libpq-wrapper tests: OK");
    return 0;
}
