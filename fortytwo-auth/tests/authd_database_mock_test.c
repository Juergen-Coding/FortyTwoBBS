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
    (void)result;
    (void)row;
    (void)column;
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
    assert(info.highest_migration == 4U);
    assert(authd_database_health_check(database,
                                       error, sizeof(error)) == 0);

    scenario.health_ok = false;
    assert(authd_database_health_check(database,
                                       error, sizeof(error)) != 0);
    assert(strstr(error, "health check") != NULL);
    authd_database_close(database);
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
    test_rejections();
    (void)puts("authd database libpq-wrapper tests: OK");
    return 0;
}
