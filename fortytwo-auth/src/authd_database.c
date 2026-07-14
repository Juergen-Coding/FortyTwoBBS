/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * PostgreSQL startup validation and health checks for fortytwo-authd.
 */

#include "authd_database.h"

#include "authd_database_validation.h"

#include <libpq-fe.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct authd_database {
    PGconn *connection;
};

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
static void
set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0U) {
        return;
    }

    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static int
precision_from_length(size_t length)
{
    return length > (size_t)INT_MAX ? INT_MAX : (int)length;
}

static void
copy_libpq_error(char *error,
                 size_t error_size,
                 const char *prefix,
                 const PGconn *connection)
{
    const char *message = connection != NULL ? PQerrorMessage(connection) : NULL;
    size_t length;

    if (message == NULL || message[0] == '\0') {
        set_error(error, error_size, "%s", prefix);
        return;
    }

    length = strlen(message);
    while (length > 0U &&
           (message[length - 1U] == '\n' || message[length - 1U] == '\r')) {
        --length;
    }
    set_error(error, error_size, "%s: %.*s", prefix,
              precision_from_length(length), message);
}

static void
ignore_notice(void *argument, const char *message)
{
    (void)argument;
    (void)message;
}

static bool
parse_int_strict(const char *text, int *value)
{
    char *end = NULL;
    long parsed;

    if (text == NULL || text[0] == '\0' || value == NULL) {
        return false;
    }

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        parsed < INT_MIN || parsed > INT_MAX) {
        return false;
    }

    *value = (int)parsed;
    return true;
}

static bool
parse_u32_strict(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || text[0] == '\0' || value == NULL || text[0] == '-') {
        return false;
    }

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
        return false;
    }

    *value = (uint32_t)parsed;
    return true;
}

static int
execute_command(PGconn *connection,
                const char *sql,
                char *error,
                size_t error_size)
{
    PGresult *result;
    ExecStatusType status;

    result = PQexec(connection, sql);
    if (result == NULL) {
        copy_libpq_error(error, error_size, "database command failed",
                         connection);
        return -1;
    }

    status = PQresultStatus(result);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        const char *message = PQresultErrorMessage(result);
        if (message != NULL && message[0] != '\0') {
            size_t length = strlen(message);
            while (length > 0U &&
                   (message[length - 1U] == '\n' ||
                    message[length - 1U] == '\r')) {
                --length;
            }
            set_error(error, error_size, "database command failed: %.*s",
                      precision_from_length(length), message);
        } else {
            copy_libpq_error(error, error_size, "database command failed",
                             connection);
        }
        PQclear(result);
        return -1;
    }

    PQclear(result);
    return 0;
}

static int
configure_session(PGconn *connection, char *error, size_t error_size)
{
    static const char sql[] =
        "SELECT "
        "pg_catalog.set_config('search_path', 'pg_catalog,public', false), "
        "pg_catalog.set_config('statement_timeout', '5000', false), "
        "pg_catalog.set_config('lock_timeout', '2000', false), "
        "pg_catalog.set_config('idle_in_transaction_session_timeout', "
        "'5000', false)";

    return execute_command(connection, sql, error, error_size);
}

static int
verify_identity(PGconn *connection,
                const authd_config_t *config,
                authd_database_info_t *info,
                char *error,
                size_t error_size)
{
    static const char sql[] =
        "SELECT CURRENT_USER, "
        "pg_catalog.current_database(), "
        "pg_catalog.current_setting('server_version_num'), "
        "pg_catalog.current_setting('transaction_read_only')";
    PGresult *result;
    int server_version_num;
    bool read_only;
    bool valid;

    result = PQexec(connection, sql);
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "database identity query failed", connection);
        return -1;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQntuples(result) != 1 || PQnfields(result) != 4 ||
        PQgetisnull(result, 0, 0) || PQgetisnull(result, 0, 1) ||
        PQgetisnull(result, 0, 2) || PQgetisnull(result, 0, 3)) {
        set_error(error, error_size,
                  "database identity query returned an invalid shape");
        PQclear(result);
        return -1;
    }

    if (!parse_int_strict(PQgetvalue(result, 0, 2), &server_version_num)) {
        set_error(error, error_size,
                  "database returned an invalid server version");
        PQclear(result);
        return -1;
    }

    if (strcmp(PQgetvalue(result, 0, 3), "on") == 0) {
        read_only = true;
    } else if (strcmp(PQgetvalue(result, 0, 3), "off") == 0) {
        read_only = false;
    } else {
        set_error(error, error_size,
                  "database returned an invalid read-only setting");
        PQclear(result);
        return -1;
    }

    valid = authd_database_validate_identity(
        PQgetvalue(result, 0, 0),
        PQgetvalue(result, 0, 1),
        server_version_num,
        read_only,
        config->db_name,
        error,
        error_size);
    PQclear(result);
    if (!valid) {
        return -1;
    }

    if (info != NULL) {
        info->server_version_num = server_version_num;
    }
    return 0;
}

static int
verify_migrations(PGconn *connection,
                  authd_database_info_t *info,
                  char *error,
                  size_t error_size)
{
    static const char sql[] =
        "SELECT migration_version::pg_catalog.text, migration_name, "
        "checksum_sha256 "
        "FROM public.fortytwo_schema_migrations "
        "ORDER BY migration_version";
    authd_migration_record_t records[AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT];
    PGresult *result;
    int rows;
    int row;

    memset(records, 0, sizeof(records));
    result = PQexec(connection, sql);
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "schema-version query failed", connection);
        return -1;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQnfields(result) != 3) {
        const char *message = PQresultErrorMessage(result);
        if (message != NULL && message[0] != '\0') {
            size_t length = strlen(message);
            while (length > 0U &&
                   (message[length - 1U] == '\n' ||
                    message[length - 1U] == '\r')) {
                --length;
            }
            set_error(error, error_size,
                      "schema-version query failed: %.*s",
                      precision_from_length(length), message);
        } else {
            set_error(error, error_size,
                      "schema-version query returned an invalid result");
        }
        PQclear(result);
        return -1;
    }

    rows = PQntuples(result);
    if (rows < 0 ||
        (size_t)rows != AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT) {
        set_error(error, error_size,
                  "database has %d registered migrations, binary requires %u",
                  rows, AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT);
        PQclear(result);
        return -1;
    }

    for (row = 0; row < rows; ++row) {
        uint32_t version;
        if (PQgetisnull(result, row, 0) ||
            PQgetisnull(result, row, 1) ||
            PQgetisnull(result, row, 2) ||
            !parse_u32_strict(PQgetvalue(result, row, 0), &version)) {
            set_error(error, error_size,
                      "migration row %d is invalid", row + 1);
            PQclear(result);
            return -1;
        }
        records[row].version = version;
        records[row].name = PQgetvalue(result, row, 1);
        records[row].checksum = PQgetvalue(result, row, 2);
    }

    if (!authd_database_validate_migrations(
            records, (size_t)rows, error, error_size)) {
        PQclear(result);
        return -1;
    }

    if (info != NULL) {
        info->migration_count = (size_t)rows;
        info->highest_migration =
            rows > 0 ? (unsigned int)records[rows - 1].version : 0U;
    }
    PQclear(result);
    return 0;
}

int
authd_database_open(const authd_config_t *config,
                    authd_database_t **database,
                    authd_database_info_t *info,
                    char *error,
                    size_t error_size)
{
    const char *keywords[] = {
        "host",
        "port",
        "dbname",
        "user",
        "application_name",
        "connect_timeout",
        "target_session_attrs",
        NULL
    };
    const char *values[8];
    char port_text[6];
    char timeout_text[4];
    authd_database_t *created = NULL;
    PGconn *connection = NULL;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database != NULL) {
        *database = NULL;
    }
    if (info != NULL) {
        memset(info, 0, sizeof(*info));
    }

    if (config == NULL || database == NULL || config->db_host[0] != '/' ||
        config->db_name[0] == '\0' || config->db_port == 0U ||
        config->db_connect_timeout_seconds == 0U) {
        set_error(error, error_size,
                  "invalid database configuration");
        return -1;
    }

    (void)snprintf(port_text, sizeof(port_text), "%u",
                   (unsigned int)config->db_port);
    (void)snprintf(timeout_text, sizeof(timeout_text), "%u",
                   (unsigned int)config->db_connect_timeout_seconds);

    values[0] = config->db_host;
    values[1] = port_text;
    values[2] = config->db_name;
    values[3] = AUTHD_DATABASE_REQUIRED_ROLE;
    values[4] = "fortytwo-authd";
    values[5] = timeout_text;
    values[6] = "read-write";
    values[7] = NULL;

    connection = PQconnectdbParams(keywords, values, 0);
    if (connection == NULL) {
        set_error(error, error_size,
                  "libpq could not allocate a database connection");
        return -1;
    }
    PQsetNoticeProcessor(connection, ignore_notice, NULL);

    if (PQstatus(connection) != CONNECTION_OK) {
        copy_libpq_error(error, error_size,
                         "database connection failed", connection);
        PQfinish(connection);
        return -1;
    }
    if (PQprotocolVersion(connection) < 3) {
        set_error(error, error_size,
                  "PostgreSQL protocol version %d is unsupported",
                  PQprotocolVersion(connection));
        PQfinish(connection);
        return -1;
    }
    if (PQconnectionUsedPassword(connection) != 0) {
        set_error(error, error_size,
                  "database password authentication is not permitted; "
                  "use local peer authentication");
        PQfinish(connection);
        return -1;
    }
    if (PQsetClientEncoding(connection, "UTF8") != 0) {
        copy_libpq_error(error, error_size,
                         "could not select UTF-8 database encoding",
                         connection);
        PQfinish(connection);
        return -1;
    }
    if (configure_session(connection, error, error_size) != 0 ||
        verify_identity(connection, config, info, error, error_size) != 0 ||
        verify_migrations(connection, info, error, error_size) != 0) {
        PQfinish(connection);
        return -1;
    }

    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        set_error(error, error_size,
                  "out of memory while opening database");
        PQfinish(connection);
        return -1;
    }
    created->connection = connection;
    *database = created;
    return 0;
}

int
authd_database_health_check(authd_database_t *database,
                            char *error,
                            size_t error_size)
{
    PGresult *result;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || database->connection == NULL) {
        set_error(error, error_size,
                  "database connection is not open");
        return -1;
    }
    if (PQstatus(database->connection) != CONNECTION_OK) {
        copy_libpq_error(error, error_size,
                         "database connection is unavailable",
                         database->connection);
        return -1;
    }

    result = PQexec(database->connection, "SELECT 1");
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "database health check failed",
                         database->connection);
        return -1;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQntuples(result) != 1 || PQnfields(result) != 1 ||
        PQgetisnull(result, 0, 0) ||
        strcmp(PQgetvalue(result, 0, 0), "1") != 0) {
        set_error(error, error_size,
                  "database health check returned an invalid result");
        PQclear(result);
        return -1;
    }

    PQclear(result);
    return 0;
}

void
authd_database_close(authd_database_t *database)
{
    if (database == NULL) {
        return;
    }
    if (database->connection != NULL) {
        PQfinish(database->connection);
    }
    memset(database, 0, sizeof(*database));
    free(database);
}
