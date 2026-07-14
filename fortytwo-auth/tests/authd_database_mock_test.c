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
    FAKE_RESULT_SESSION_CREATE,
    FAKE_RESULT_SESSION_CLOSE,
    FAKE_RESULT_PASSWORD_FAILURE,
    FAKE_RESULT_AUDIT,
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
    const char *login_values[13];
    bool session_create_found;
    bool session_create_query_error;
    int session_create_null_column;
    const char *session_create_values[5];
    bool session_close_found;
    bool session_close_query_error;
    bool session_close_null;
    const char *session_close_event_id;
    bool failure_found;
    bool failure_query_error;
    int failure_null_column;
    const char *failure_values[3];
    bool audit_query_error;
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
    scenario.login_values[6] = "9";
    scenario.login_values[7] = "0";
    scenario.login_values[8] = "Neo 67";
    scenario.login_values[9] =
        "$argon2id$v=19$m=262144,t=3,p=1$test$test";
    scenario.login_values[10] = "0";
    scenario.login_values[11] = "2";
    scenario.login_values[12] = "1720000000000";
    scenario.session_create_found = true;
    scenario.session_create_null_column = -1;
    scenario.session_create_values[0] =
        "ffeeddccbbaa99887766554433221100";
    scenario.session_create_values[1] =
        "00112233445566778899aabbccddeeff";
    scenario.session_create_values[2] = "7";
    scenario.session_create_values[3] = "9";
    scenario.session_create_values[4] = "42";
    scenario.session_close_found = true;
    scenario.session_close_event_id = "43";
    scenario.failure_found = true;
    scenario.failure_null_column = -1;
    scenario.failure_values[0] = "3";
    scenario.failure_values[1] = "0";
    scenario.failure_values[2] = "0";
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
    assert(parameter_types == NULL);
    assert(parameter_values != NULL);
    assert(parameter_lengths == NULL);
    assert(parameter_formats == NULL);
    assert(result_format == 0);

    result = calloc(1U, sizeof(*result));
    assert(result != NULL);

    if (strstr(command, "FROM public.bbs_users AS u") != NULL &&
        strstr(command, "WHERE u.login_name = $1") != NULL) {
        assert(strstr(command, "WHERE u.login_name = $1") != NULL);
        assert(strstr(command, "neo67") == NULL);
        assert(parameter_count == 1);
        assert(strcmp(parameter_values[0], "neo67") == 0);
        result->kind = scenario.login_query_error ? FAKE_RESULT_ERROR :
                                                    FAKE_RESULT_LOGIN;
    } else if (strstr(command, "auth.login_succeeded") != NULL) {
        assert(strstr(command, "eligible_user") != NULL);
        assert(strstr(command, "FOR UPDATE OF u") != NULL);
        assert(strstr(command, "credential_reset") != NULL);
        assert(strstr(command, "session_insert") != NULL);
        assert(strstr(command, "audit_insert") != NULL);
        assert(strstr(command, "u.login_name = $8 COLLATE") != NULL);
        assert(strstr(command, "c.password_hash = $9") != NULL);
        assert(strstr(command, "neo67") == NULL);
        assert(parameter_count == 9);
        assert(strcmp(parameter_values[0],
                      "00112233-4455-6677-8899-aabbccddeeff") == 0);
        assert(strcmp(parameter_values[1], "7") == 0);
        assert(strcmp(parameter_values[2], "9") == 0);
        assert(strcmp(parameter_values[3], "ssh") == 0);
        assert(strcmp(parameter_values[4], "192.0.2.42") == 0);
        assert(strcmp(parameter_values[5], "/dev/pts/7") == 0);
        assert(strcmp(parameter_values[6], "node-a") == 0);
        assert(strcmp(parameter_values[7], "neo67") == 0);
        assert(strncmp(parameter_values[8], "$argon2id$", 10U) == 0);
        result->kind = scenario.session_create_query_error ?
            FAKE_RESULT_ERROR : FAKE_RESULT_SESSION_CREATE;
    } else if (strstr(command, "auth.terminal_session_closed") != NULL) {
        assert(strstr(command, "closed_at = CURRENT_TIMESTAMP") != NULL);
        assert(strstr(command, "closed_at IS NULL") != NULL);
        assert(strstr(command, "audit_insert") != NULL);
        assert(parameter_count == 2);
        assert(strcmp(parameter_values[0],
                      "ffeeddcc-bbaa-9988-7766-554433221100") == 0);
        assert(strcmp(parameter_values[1], "peer_disconnected") == 0);
        result->kind = scenario.session_close_query_error
                           ? FAKE_RESULT_ERROR
                           : FAKE_RESULT_SESSION_CLOSE;
    } else if (strstr(command, "auth.password_failed") != NULL) {
        assert(strstr(command, "credential_update") != NULL);
        assert(strstr(command, "audit_insert") != NULL);
        assert(parameter_count == 6);
        assert(strcmp(parameter_values[0],
                      "00112233-4455-6677-8899-aabbccddeeff") == 0);
        assert(strcmp(parameter_values[1], "900") == 0);
        assert(strcmp(parameter_values[2], "5") == 0);
        assert(strcmp(parameter_values[3], "900") == 0);
        assert(strcmp(parameter_values[4], "192.0.2.42") == 0);
        assert(strcmp(parameter_values[5], "ssh") == 0);
        result->kind = scenario.failure_query_error ? FAKE_RESULT_ERROR :
                                                      FAKE_RESULT_PASSWORD_FAILURE;
    } else if (strstr(command, "auth.login_rejected") != NULL) {
        assert(parameter_count == 5);
        assert(parameter_values[2] != NULL);
        assert(strcmp(parameter_values[3], "neo67") == 0);
        assert(strcmp(parameter_values[4], "telnet") == 0);
        if (strcmp(parameter_values[2], "unknown_user") == 0) {
            assert(parameter_values[0] == NULL);
        }
        result->kind = scenario.audit_query_error ? FAKE_RESULT_ERROR :
                                                    FAKE_RESULT_AUDIT;
    } else {
        assert(!"unexpected parameterized SQL in database module");
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
    case FAKE_RESULT_LOGIN:
        return scenario.login_found ? 1 : 0;
    case FAKE_RESULT_SESSION_CREATE:
        return scenario.session_create_found ? 1 : 0;
    case FAKE_RESULT_SESSION_CLOSE:
        return scenario.session_close_found ? 1 : 0;
    case FAKE_RESULT_PASSWORD_FAILURE:
        return scenario.failure_found ? 1 : 0;
    case FAKE_RESULT_AUDIT:
        return 1;
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
        return 13;
    case FAKE_RESULT_SESSION_CREATE:
        return 5;
    case FAKE_RESULT_SESSION_CLOSE:
        return 1;
    case FAKE_RESULT_PASSWORD_FAILURE:
        return 3;
    case FAKE_RESULT_AUDIT:
        return 1;
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
    if (fake->kind == FAKE_RESULT_SESSION_CREATE &&
        column == scenario.session_create_null_column) {
        return 1;
    }
    if (fake->kind == FAKE_RESULT_SESSION_CLOSE &&
        scenario.session_close_null) {
        return 1;
    }
    if (fake->kind == FAKE_RESULT_PASSWORD_FAILURE &&
        column == scenario.failure_null_column) {
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
        assert(column >= 0 && column < 13);
        return (char *)scenario.login_values[column];
    }

    if (fake->kind == FAKE_RESULT_SESSION_CREATE) {
        assert(row == 0);
        assert(column >= 0 && column < 5);
        return (char *)scenario.session_create_values[column];
    }

    if (fake->kind == FAKE_RESULT_SESSION_CLOSE) {
        assert(row == 0 && column == 0);
        return (char *)scenario.session_close_event_id;
    }

    if (fake->kind == FAKE_RESULT_PASSWORD_FAILURE) {
        assert(row == 0);
        assert(column >= 0 && column < 3);
        return (char *)scenario.failure_values[column];
    }

    if (fake->kind == FAKE_RESULT_AUDIT) {
        assert(row == 0 && column == 0);
        return (char *)"42";
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
    assert(record.authz_revision == 9U);
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
    scenario.login_values[10] = "1";
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_OK);
    assert(authd_login_record_availability(&record) ==
           AUTHD_LOGIN_PASSWORD_CHANGE_REQUIRED);

    scenario.login_values[10] = "0";
    scenario.login_null_column = 9;
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
test_password_session_creation(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    authd_login_record_t record;
    authd_terminal_session_result_t session;
    char overlong_tty[FTAP_TTY_DEVICE_MAX + 2U];
    char error[AUTHD_DATABASE_ERROR_MAX];

    reset_scenario();
    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);
    assert(authd_database_lookup_login(database, "neo67", &record,
                                       error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_OK);

    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) == AUTHD_DATABASE_WRITE_OK);
    assert(memcmp(session.user_id, record.user_id, FTAP_UUID_SIZE) == 0);
    assert(session.session_id[0] == 0xffU);
    assert(session.session_id[15] == 0x00U);
    assert(session.auth_epoch == 7U);
    assert(session.authz_revision == 9U);

    scenario.session_create_found = false;
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) == AUTHD_DATABASE_WRITE_STALE_STATE);
    scenario.session_create_found = true;

    scenario.session_create_null_column = 0;
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_RECORD);
    scenario.session_create_null_column = -1;

    scenario.session_create_values[0] =
        "00000000000000000000000000000000";
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_RECORD);
    scenario.session_create_values[0] =
        "ffeeddccbbaa99887766554433221100";

    scenario.session_create_values[2] = "8";
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_RECORD);
    scenario.session_create_values[2] = "7";

    scenario.session_create_query_error = true;
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) == AUTHD_DATABASE_WRITE_ERROR);
    scenario.session_create_query_error = false;

    memset(overlong_tty, 'x', sizeof(overlong_tty));
    overlong_tty[sizeof(overlong_tty) - 1U] = '\0';
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", overlong_tty, "node-a",
        &session, error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);
    assert(authd_database_create_password_session(
        database, &record, "invalid-ip", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "SSH", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "", "node-a",
        &session, error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);

    record.auth_epoch = 0U;
    assert(authd_database_create_password_session(
        database, &record, "192.0.2.42", "ssh", "/dev/pts/7", "node-a",
        &session, error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);

    assert(strcmp(authd_database_write_result_name(
                      AUTHD_DATABASE_WRITE_STALE_STATE),
                  "stale_state") == 0);
    authd_database_close(database);
}

static void
test_terminal_session_close(void)
{
    static const uint8_t session_id[FTAP_UUID_SIZE] = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    static const uint8_t zero_session_id[FTAP_UUID_SIZE] = {0};
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    char error[AUTHD_DATABASE_ERROR_MAX];

    reset_scenario();
    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);

    assert(authd_database_close_terminal_session(
        database, session_id, "peer_disconnected", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_OK);

    scenario.session_close_found = false;
    assert(authd_database_close_terminal_session(
        database, session_id, "peer_disconnected", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_NOT_FOUND);
    scenario.session_close_found = true;

    scenario.session_close_null = true;
    assert(authd_database_close_terminal_session(
        database, session_id, "peer_disconnected", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_RECORD);
    scenario.session_close_null = false;

    scenario.session_close_event_id = "not-a-number";
    assert(authd_database_close_terminal_session(
        database, session_id, "peer_disconnected", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_RECORD);
    scenario.session_close_event_id = "43";

    scenario.session_close_query_error = true;
    assert(authd_database_close_terminal_session(
        database, session_id, "peer_disconnected", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_ERROR);
    scenario.session_close_query_error = false;

    assert(authd_database_close_terminal_session(
        database, zero_session_id, "peer_disconnected", error,
        sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);
    assert(authd_database_close_terminal_session(
        database, session_id, "Peer Disconnected", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);
    assert(authd_database_close_terminal_session(
        database, session_id, "", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);

    authd_database_close(database);
}

static void
test_password_failure_and_audit(void)
{
    static const uint8_t user_id[FTAP_UUID_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    authd_throttle_policy_t policy;
    authd_password_failure_update_t update;
    char error[AUTHD_DATABASE_ERROR_MAX];

    reset_scenario();
    authd_config_defaults(&config);
    authd_throttle_policy_defaults(&policy);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);

    assert(authd_database_record_password_failure(
        database, user_id, &policy, "192.0.2.42", "ssh", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_OK);
    assert(update.failed_count == 3U);
    assert(!update.throttled);
    assert(update.retry_after_ms == 0U);

    scenario.failure_values[0] = "5";
    scenario.failure_values[1] = "1";
    scenario.failure_values[2] = "900000";
    assert(authd_database_record_password_failure(
        database, user_id, &policy, "192.0.2.42", "ssh", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_OK);
    assert(update.failed_count == 5U);
    assert(update.throttled);
    assert(update.retry_after_ms == 900000U);

    scenario.failure_found = false;
    assert(authd_database_record_password_failure(
        database, user_id, &policy, "192.0.2.42", "ssh", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_NOT_FOUND);
    scenario.failure_found = true;

    scenario.failure_null_column = 0;
    assert(authd_database_record_password_failure(
        database, user_id, &policy, "192.0.2.42", "ssh", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_RECORD);
    scenario.failure_null_column = -1;

    scenario.failure_query_error = true;
    assert(authd_database_record_password_failure(
        database, user_id, &policy, "192.0.2.42", "ssh", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_ERROR);
    scenario.failure_query_error = false;

    policy.failure_threshold = 0U;
    assert(authd_database_record_password_failure(
        database, user_id, &policy, "192.0.2.42", "ssh", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);
    authd_throttle_policy_defaults(&policy);
    assert(authd_database_record_password_failure(
        database, user_id, &policy, "invalid-ip", "ssh", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);
    assert(authd_database_record_password_failure(
        database, user_id, &policy, "192.0.2.42", "SSH", &update,
        error, sizeof(error)) == AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);

    assert(authd_database_audit_login_rejection(
        database, NULL, "neo67", AUTHD_LOGIN_REJECTION_UNKNOWN_USER,
        NULL, "telnet", error, sizeof(error)) == AUTHD_DATABASE_WRITE_OK);
    assert(authd_database_audit_login_rejection(
        database, user_id, "neo67", AUTHD_LOGIN_REJECTION_LOCKED,
        "192.0.2.42", "telnet", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_OK);
    assert(authd_database_audit_login_rejection(
        database, user_id, "neo67", AUTHD_LOGIN_REJECTION_WRONG_PASSWORD,
        "192.0.2.42", "telnet", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_INVALID_ARGUMENT);

    scenario.audit_query_error = true;
    assert(authd_database_audit_login_rejection(
        database, NULL, "neo67", AUTHD_LOGIN_REJECTION_UNKNOWN_USER,
        NULL, "telnet", error, sizeof(error)) ==
        AUTHD_DATABASE_WRITE_ERROR);

    assert(strcmp(authd_database_write_result_name(
                      AUTHD_DATABASE_WRITE_INVALID_RECORD),
                  "invalid_record") == 0);
    authd_database_close(database);
}

static void
test_login_availability(void)
{
    authd_login_record_t record;

    memset(&record, 0, sizeof(record));
    record.auth_epoch = 1U;
    record.authz_revision = 1U;
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
    record.auth_epoch = 1U;
    record.authz_revision = 0U;
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
    test_password_session_creation();
    test_terminal_session_close();
    test_password_failure_and_audit();
    test_login_availability();
    test_rejections();
    (void)puts("authd database libpq-wrapper tests: OK");
    return 0;
}
