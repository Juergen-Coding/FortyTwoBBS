/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * PostgreSQL startup validation and health checks for fortytwo-authd.
 */

#include "authd_database.h"

#include "authd_database_validation.h"
#include "authd_identity.h"

#include <libpq-fe.h>

#include <errno.h>
#include <inttypes.h>
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

static bool
parse_u64_strict(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || text[0] == '\0' || value == NULL || text[0] == '-') {
        return false;
    }

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT64_MAX) {
        return false;
    }

    *value = (uint64_t)parsed;
    return true;
}

static bool
parse_i64_strict(const char *text, int64_t *value)
{
    char *end = NULL;
    long long parsed;

    if (text == NULL || text[0] == '\0' || value == NULL) {
        return false;
    }

    errno = 0;
    parsed = strtoll(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        parsed < INT64_MIN || parsed > INT64_MAX) {
        return false;
    }

    *value = (int64_t)parsed;
    return true;
}

static bool
parse_boolean_digit(const char *text, bool *value)
{
    if (text == NULL || value == NULL) {
        return false;
    }
    if (strcmp(text, "0") == 0) {
        *value = false;
        return true;
    }
    if (strcmp(text, "1") == 0) {
        *value = true;
        return true;
    }
    return false;
}

static bool
copy_bounded_text(char *destination,
                  size_t destination_size,
                  const char *source,
                  size_t maximum_length)
{
    size_t length;

    if (destination == NULL || destination_size == 0U || source == NULL) {
        return false;
    }
    length = strlen(source);
    if (length == 0U || length > maximum_length ||
        length >= destination_size) {
        return false;
    }
    memcpy(destination, source, length + 1U);
    return true;
}

static bool
hex_nibble(unsigned char character, uint8_t *value)
{
    if (character >= (unsigned char)'0' &&
        character <= (unsigned char)'9') {
        *value = (uint8_t)(character - (unsigned char)'0');
        return true;
    }
    if (character >= (unsigned char)'a' &&
        character <= (unsigned char)'f') {
        *value = (uint8_t)(character - (unsigned char)'a' + 10U);
        return true;
    }
    if (character >= (unsigned char)'A' &&
        character <= (unsigned char)'F') {
        *value = (uint8_t)(character - (unsigned char)'A' + 10U);
        return true;
    }
    return false;
}

static bool
parse_uuid_hex(const char *text, uint8_t output[FTAP_UUID_SIZE])
{
    size_t index;

    if (text == NULL || output == NULL ||
        strlen(text) != AUTHD_DATABASE_UUID_HEX_SIZE) {
        return false;
    }
    for (index = 0U; index < (size_t)FTAP_UUID_SIZE; ++index) {
        uint8_t high;
        uint8_t low;

        if (!hex_nibble((unsigned char)text[index * 2U], &high) ||
            !hex_nibble((unsigned char)text[index * 2U + 1U], &low)) {
            memset(output, 0, FTAP_UUID_SIZE);
            return false;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static bool
parse_account_state(const char *text, authd_account_state_t *state)
{
    if (text == NULL || state == NULL) {
        return false;
    }
    if (strcmp(text, "pending") == 0) {
        *state = AUTHD_ACCOUNT_STATE_PENDING;
    } else if (strcmp(text, "active") == 0) {
        *state = AUTHD_ACCOUNT_STATE_ACTIVE;
    } else if (strcmp(text, "disabled") == 0) {
        *state = AUTHD_ACCOUNT_STATE_DISABLED;
    } else if (strcmp(text, "locked") == 0) {
        *state = AUTHD_ACCOUNT_STATE_LOCKED;
    } else if (strcmp(text, "deleted") == 0) {
        *state = AUTHD_ACCOUNT_STATE_DELETED;
    } else {
        return false;
    }
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

authd_database_lookup_result_t
authd_database_lookup_login(authd_database_t *database,
                            const char *canonical_login_name,
                            authd_login_record_t *record,
                            char *error,
                            size_t error_size)
{
    static const char sql[] =
        "SELECT "
        "pg_catalog.encode(pg_catalog.uuid_send(u.user_id), 'hex'), "
        "u.login_name, u.account_state, "
        "CASE WHEN u.throttled_until > CURRENT_TIMESTAMP "
        "THEN '1' ELSE '0' END, "
        "CASE WHEN u.throttled_until > CURRENT_TIMESTAMP THEN "
        "GREATEST(1, pg_catalog.ceil(pg_catalog.date_part('epoch', "
        "u.throttled_until - CURRENT_TIMESTAMP) * 1000.0)"
        "::pg_catalog.int8)::pg_catalog.text ELSE '0' END, "
        "u.auth_epoch::pg_catalog.text, "
        "u.authz_revision::pg_catalog.text, "
        "CASE WHEN u.deleted_at IS NULL THEN '0' ELSE '1' END, "
        "p.display_name, m.legacy_name, c.password_hash, "
        "CASE WHEN c.must_change THEN '1' ELSE '0' END, "
        "c.failed_count::pg_catalog.text, "
        "CASE WHEN c.last_failed_at IS NULL THEN NULL ELSE "
        "pg_catalog.floor(pg_catalog.date_part('epoch', c.last_failed_at) "
        "* 1000.0)::pg_catalog.int8::pg_catalog.text END "
        "FROM public.bbs_users AS u "
        "LEFT JOIN public.bbs_user_profiles AS p ON p.user_id = u.user_id "
        "LEFT JOIN public.bbs_password_credentials AS c "
        "ON c.user_id = u.user_id "
        "JOIN public.bbs_legacy_mbse_bindings AS m "
        "ON m.user_id = u.user_id "
        "WHERE u.login_name = $1 COLLATE \"C\"";
    const char *parameter_values[1];
    PGresult *result;
    int rows;
    uint64_t auth_epoch;
    uint64_t authz_revision;
    uint64_t retry_after_ms;
    uint32_t failed_count;
    bool deleted;
    bool throttled;
    bool must_change;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (record != NULL) {
        memset(record, 0, sizeof(*record));
    }
    if (database == NULL || database->connection == NULL ||
        canonical_login_name == NULL || record == NULL ||
        !authd_login_name_is_canonical(canonical_login_name)) {
        set_error(error, error_size, "invalid login lookup arguments");
        return AUTHD_DATABASE_LOOKUP_ERROR;
    }
    if (PQstatus(database->connection) != CONNECTION_OK) {
        copy_libpq_error(error, error_size,
                         "database connection is unavailable",
                         database->connection);
        return AUTHD_DATABASE_LOOKUP_ERROR;
    }

    parameter_values[0] = canonical_login_name;
    result = PQexecParams(database->connection,
                          sql,
                          1,
                          NULL,
                          parameter_values,
                          NULL,
                          NULL,
                          0);
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "login lookup failed", database->connection);
        return AUTHD_DATABASE_LOOKUP_ERROR;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQnfields(result) != 14) {
        const char *message = PQresultErrorMessage(result);
        if (message != NULL && message[0] != '\0') {
            size_t length = strlen(message);
            while (length > 0U &&
                   (message[length - 1U] == '\n' ||
                    message[length - 1U] == '\r')) {
                --length;
            }
            set_error(error, error_size, "login lookup failed: %.*s",
                      precision_from_length(length), message);
        } else {
            set_error(error, error_size,
                      "login lookup returned an invalid result");
        }
        PQclear(result);
        return AUTHD_DATABASE_LOOKUP_ERROR;
    }

    rows = PQntuples(result);
    if (rows == 0) {
        PQclear(result);
        return AUTHD_DATABASE_LOOKUP_NOT_FOUND;
    }
    if (rows != 1) {
        set_error(error, error_size,
                  "login lookup returned %d rows", rows);
        PQclear(result);
        return AUTHD_DATABASE_LOOKUP_INVALID_RECORD;
    }

    if (PQgetisnull(result, 0, 0) ||
        PQgetisnull(result, 0, 1) ||
        PQgetisnull(result, 0, 2) ||
        PQgetisnull(result, 0, 3) ||
        PQgetisnull(result, 0, 4) ||
        PQgetisnull(result, 0, 5) ||
        PQgetisnull(result, 0, 6) ||
        PQgetisnull(result, 0, 7) ||
        PQgetisnull(result, 0, 8) ||
        PQgetisnull(result, 0, 9) ||
        PQgetisnull(result, 0, 10) ||
        PQgetisnull(result, 0, 11) ||
        PQgetisnull(result, 0, 12)) {
        set_error(error, error_size,
                  "login record is missing a required field");
        PQclear(result);
        return AUTHD_DATABASE_LOOKUP_INVALID_RECORD;
    }

    if (!parse_uuid_hex(PQgetvalue(result, 0, 0), record->user_id) ||
        !copy_bounded_text(record->login_name,
                           sizeof(record->login_name),
                           PQgetvalue(result, 0, 1),
                           FTAP_LOGIN_NAME_MAX) ||
        !authd_login_name_is_canonical(record->login_name) ||
        strcmp(record->login_name, canonical_login_name) != 0 ||
        !parse_account_state(PQgetvalue(result, 0, 2),
                             &record->account_state) ||
        !parse_boolean_digit(PQgetvalue(result, 0, 3), &throttled) ||
        !parse_u64_strict(PQgetvalue(result, 0, 4), &retry_after_ms) ||
        !parse_u64_strict(PQgetvalue(result, 0, 5), &auth_epoch) ||
        auth_epoch == 0U ||
        !parse_u64_strict(PQgetvalue(result, 0, 6), &authz_revision) ||
        authz_revision == 0U ||
        !parse_boolean_digit(PQgetvalue(result, 0, 7), &deleted) ||
        !copy_bounded_text(record->display_name,
                           sizeof(record->display_name),
                           PQgetvalue(result, 0, 8),
                           FTAP_DISPLAY_NAME_MAX) ||
        !copy_bounded_text(record->legacy_name,
                           sizeof(record->legacy_name),
                           PQgetvalue(result, 0, 9),
                           FTAP_LEGACY_NAME_MAX) ||
        !authd_legacy_name_is_valid(record->legacy_name) ||
        !copy_bounded_text(record->password_hash,
                           sizeof(record->password_hash),
                           PQgetvalue(result, 0, 10),
                           AUTHD_DATABASE_PASSWORD_HASH_MAX) ||
        !parse_boolean_digit(PQgetvalue(result, 0, 11), &must_change) ||
        !parse_u32_strict(PQgetvalue(result, 0, 12), &failed_count) ||
        (throttled && retry_after_ms == 0U) ||
        (!throttled && retry_after_ms != 0U)) {
        memset(record, 0, sizeof(*record));
        set_error(error, error_size,
                  "login record contains an invalid field");
        PQclear(result);
        return AUTHD_DATABASE_LOOKUP_INVALID_RECORD;
    }

    record->auth_epoch = auth_epoch;
    record->authz_revision = authz_revision;
    record->deleted = deleted;
    record->throttled = throttled;
    record->retry_after_ms = retry_after_ms;
    record->must_change = must_change;
    record->failed_count = failed_count;

    if (PQgetisnull(result, 0, 13)) {
        record->last_failed_at_set = false;
        record->last_failed_at_epoch_ms = 0;
    } else if (!parse_i64_strict(PQgetvalue(result, 0, 13),
                                 &record->last_failed_at_epoch_ms)) {
        memset(record, 0, sizeof(*record));
        set_error(error, error_size,
                  "login record contains an invalid failure timestamp");
        PQclear(result);
        return AUTHD_DATABASE_LOOKUP_INVALID_RECORD;
    } else {
        record->last_failed_at_set = true;
    }

    PQclear(result);
    return AUTHD_DATABASE_LOOKUP_OK;
}

/* Reject the all-zero UUID for identities and generated sessions alike. */
static bool
uuid_is_valid(const uint8_t user_id[FTAP_UUID_SIZE])
{
    size_t index;

    if (user_id == NULL) {
        return false;
    }
    for (index = 0U; index < (size_t)FTAP_UUID_SIZE; ++index) {
        if (user_id[index] != 0U) {
            return true;
        }
    }
    return false;
}

/* Convert the binary FTAP UUID into PostgreSQL's canonical text form. */
static void
format_uuid_text(const uint8_t user_id[FTAP_UUID_SIZE], char output[37])
{
    (void)snprintf(
        output,
        37U,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
        "%02x%02x%02x%02x%02x%02x",
        (unsigned int)user_id[0], (unsigned int)user_id[1],
        (unsigned int)user_id[2], (unsigned int)user_id[3],
        (unsigned int)user_id[4], (unsigned int)user_id[5],
        (unsigned int)user_id[6], (unsigned int)user_id[7],
        (unsigned int)user_id[8], (unsigned int)user_id[9],
        (unsigned int)user_id[10], (unsigned int)user_id[11],
        (unsigned int)user_id[12], (unsigned int)user_id[13],
        (unsigned int)user_id[14], (unsigned int)user_id[15]);
}

/* Copy a libpq result error while trimming its trailing newline. */
static void
copy_result_error(char *error,
                  size_t error_size,
                  const char *prefix,
                  const PGresult *result)
{
    const char *message = result != NULL ? PQresultErrorMessage(result) : NULL;
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

/*
 * Update one known user's persistent failure window and append its audit event
 * in the same PostgreSQL statement. If the audit insert fails, PostgreSQL rolls
 * back the counter and throttle updates with the rest of the statement.
 */
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
    static const char sql[] =
        "WITH credential_update AS ("
        "UPDATE public.bbs_password_credentials AS c SET "
        "failed_count = CASE WHEN c.last_failed_at IS NULL OR "
        "c.last_failed_at < CURRENT_TIMESTAMP - "
        "($2::pg_catalog.int4 * INTERVAL '1 second') THEN 1 ELSE "
        "LEAST(c.failed_count::pg_catalog.int8 + 1, 2147483647)"
        "::pg_catalog.int4 END, "
        "last_failed_at = CURRENT_TIMESTAMP "
        "WHERE c.user_id = $1::pg_catalog.uuid "
        "RETURNING c.failed_count"
        "), user_update AS ("
        "UPDATE public.bbs_users AS u SET "
        "throttled_until = CASE "
        "WHEN cu.failed_count >= $3::pg_catalog.int4 THEN "
        "GREATEST(COALESCE(u.throttled_until, CURRENT_TIMESTAMP), "
        "CURRENT_TIMESTAMP + ($4::pg_catalog.int4 * INTERVAL '1 second')) "
        "WHEN u.throttled_until <= CURRENT_TIMESTAMP THEN NULL "
        "ELSE u.throttled_until END, "
        "updated_at = CURRENT_TIMESTAMP "
        "FROM credential_update AS cu "
        "WHERE u.user_id = $1::pg_catalog.uuid "
        "RETURNING u.user_id, cu.failed_count, u.throttled_until"
        "), audit_insert AS ("
        "INSERT INTO public.bbs_audit_events "
        "(subject_user_id, event_type, source_ip, detail) "
        "SELECT uu.user_id, 'auth.password_failed', $5::pg_catalog.inet, "
        "pg_catalog.jsonb_build_object("
        "'reason', 'wrong_password', "
        "'protocol', $6::pg_catalog.text, "
        "'failed_count', uu.failed_count, "
        "'throttled', uu.throttled_until > CURRENT_TIMESTAMP) "
        "FROM user_update AS uu RETURNING event_id"
        ") SELECT uu.failed_count::pg_catalog.text, "
        "CASE WHEN uu.throttled_until > CURRENT_TIMESTAMP "
        "THEN '1' ELSE '0' END, "
        "CASE WHEN uu.throttled_until > CURRENT_TIMESTAMP THEN "
        "GREATEST(1, pg_catalog.ceil(pg_catalog.date_part('epoch', "
        "uu.throttled_until - CURRENT_TIMESTAMP) * 1000.0)"
        "::pg_catalog.int8)::pg_catalog.text ELSE '0' END "
        "FROM user_update AS uu CROSS JOIN audit_insert AS ai";
    const char *parameter_values[6];
    char uuid_text[37];
    char window_text[16];
    char threshold_text[16];
    char throttle_text[16];
    PGresult *result;
    int rows;
    uint32_t failed_count;
    uint64_t retry_after_ms;
    bool throttled;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (update != NULL) {
        memset(update, 0, sizeof(*update));
    }

    if (database == NULL || database->connection == NULL ||
        !uuid_is_valid(user_id) ||
        !authd_throttle_policy_is_valid(policy) ||
        !authd_source_ip_is_valid(source_ip) ||
        !authd_login_protocol_is_valid(protocol) || update == NULL) {
        set_error(error, error_size,
                  "invalid password failure update arguments");
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    if (PQstatus(database->connection) != CONNECTION_OK) {
        copy_libpq_error(error, error_size,
                         "database connection is unavailable",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    format_uuid_text(user_id, uuid_text);
    (void)snprintf(window_text, sizeof(window_text), "%" PRIu32,
                   policy->failure_window_seconds);
    (void)snprintf(threshold_text, sizeof(threshold_text), "%" PRIu32,
                   policy->failure_threshold);
    (void)snprintf(throttle_text, sizeof(throttle_text), "%" PRIu32,
                   policy->throttle_seconds);

    parameter_values[0] = uuid_text;
    parameter_values[1] = window_text;
    parameter_values[2] = threshold_text;
    parameter_values[3] = throttle_text;
    parameter_values[4] = source_ip;
    parameter_values[5] = protocol;

    result = PQexecParams(database->connection, sql, 6, NULL,
                          parameter_values, NULL, NULL, 0);
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "password failure update failed",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQnfields(result) != 3) {
        copy_result_error(error, error_size,
                          "password failure update failed", result);
        PQclear(result);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    rows = PQntuples(result);
    if (rows == 0) {
        set_error(error, error_size,
                  "password failure target no longer exists");
        PQclear(result);
        return AUTHD_DATABASE_WRITE_NOT_FOUND;
    }
    if (rows != 1 || PQgetisnull(result, 0, 0) ||
        PQgetisnull(result, 0, 1) || PQgetisnull(result, 0, 2) ||
        !parse_u32_strict(PQgetvalue(result, 0, 0), &failed_count) ||
        !parse_boolean_digit(PQgetvalue(result, 0, 1), &throttled) ||
        !parse_u64_strict(PQgetvalue(result, 0, 2), &retry_after_ms) ||
        failed_count == 0U ||
        (throttled && retry_after_ms == 0U) ||
        (!throttled && retry_after_ms != 0U)) {
        set_error(error, error_size,
                  "password failure update returned an invalid record");
        PQclear(result);
        return AUTHD_DATABASE_WRITE_INVALID_RECORD;
    }

    update->failed_count = failed_count;
    update->throttled = throttled;
    update->retry_after_ms = retry_after_ms;
    PQclear(result);
    return AUTHD_DATABASE_WRITE_OK;
}

/*
 * Append an audit-only rejection for unknown users, account-state denials,
 * overload, or internal failure. Wrong passwords must use the atomic counter
 * function above so audit and throttling cannot diverge.
 */
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
    static const char sql[] =
        "INSERT INTO public.bbs_audit_events "
        "(subject_user_id, event_type, source_ip, detail) VALUES ("
        "$1::pg_catalog.uuid, 'auth.login_rejected', "
        "$2::pg_catalog.inet, pg_catalog.jsonb_build_object("
        "'reason', $3::pg_catalog.text, "
        "'login_name', $4::pg_catalog.text, "
        "'protocol', $5::pg_catalog.text)) "
        "RETURNING event_id::pg_catalog.text";
    const char *parameter_values[5];
    char uuid_text[37];
    const char *reason_name;
    PGresult *result;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }

    reason_name = authd_login_rejection_reason_name(reason);
    if (database == NULL || database->connection == NULL ||
        canonical_login_name == NULL ||
        !authd_login_name_is_canonical(canonical_login_name) ||
        strcmp(reason_name, "invalid") == 0 ||
        reason == AUTHD_LOGIN_REJECTION_WRONG_PASSWORD ||
        !authd_source_ip_is_valid(source_ip) ||
        !authd_login_protocol_is_valid(protocol) ||
        (user_id != NULL && !uuid_is_valid(user_id)) ||
        (reason == AUTHD_LOGIN_REJECTION_UNKNOWN_USER && user_id != NULL)) {
        set_error(error, error_size,
                  "invalid login rejection audit arguments");
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    if (PQstatus(database->connection) != CONNECTION_OK) {
        copy_libpq_error(error, error_size,
                         "database connection is unavailable",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    if (user_id != NULL) {
        format_uuid_text(user_id, uuid_text);
        parameter_values[0] = uuid_text;
    } else {
        parameter_values[0] = NULL;
    }
    parameter_values[1] = source_ip;
    parameter_values[2] = reason_name;
    parameter_values[3] = canonical_login_name;
    parameter_values[4] = protocol;

    result = PQexecParams(database->connection, sql, 5, NULL,
                          parameter_values, NULL, NULL, 0);
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "login rejection audit failed",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQntuples(result) != 1 || PQnfields(result) != 1 ||
        PQgetisnull(result, 0, 0)) {
        copy_result_error(error, error_size,
                          "login rejection audit failed", result);
        PQclear(result);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    PQclear(result);
    return AUTHD_DATABASE_WRITE_OK;
}

/* Validate optional terminal metadata before it is passed to PostgreSQL. */
static bool
optional_session_text_is_valid(const char *text, size_t maximum_length)
{
    size_t length;

    if (text == NULL) {
        return true;
    }

    length = strlen(text);
    return length > 0U && length <= maximum_length;
}

/*
 * Commit a successful password login as one data-modifying statement. The
 * locking user selection rechecks the current security state after the
 * expensive Argon2id work. Credential reset, session insertion, and success
 * audit are then chained through RETURNING rows, so any failure rolls back the
 * complete statement and no partial authenticated state can remain.
 */
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
    static const char sql[] =
        "WITH eligible_user AS MATERIALIZED ("
        "SELECT u.user_id, u.auth_epoch, u.authz_revision "
        "FROM public.bbs_users AS u "
        "JOIN public.bbs_legacy_mbse_bindings AS m "
        "ON m.user_id = u.user_id "
        "WHERE u.user_id = $1::pg_catalog.uuid "
        "AND u.auth_epoch = $2::pg_catalog.int8 "
        "AND u.authz_revision = $3::pg_catalog.int8 "
        "AND u.login_name = $8 COLLATE \"C\" "
        "AND m.legacy_name = $10 COLLATE \"C\" "
        "AND u.account_state = 'active' "
        "AND u.deleted_at IS NULL "
        "AND (u.throttled_until IS NULL "
        "OR u.throttled_until <= CURRENT_TIMESTAMP) "
        "FOR UPDATE OF u), "
        "credential_reset AS ("
        "UPDATE public.bbs_password_credentials AS c "
        "SET failed_count = 0, last_failed_at = NULL "
        "FROM eligible_user AS u "
        "WHERE c.user_id = u.user_id AND c.must_change = FALSE "
        "AND c.password_hash = $9::pg_catalog.text "
        "RETURNING c.user_id, u.auth_epoch, u.authz_revision), "
        "session_insert AS ("
        "INSERT INTO public.bbs_terminal_sessions "
        "(user_id, protocol, auth_method, source_ip, tty_device, node_id, "
        "auth_epoch) "
        "SELECT c.user_id, $4::pg_catalog.text, 'password', "
        "$5::pg_catalog.inet, $6::pg_catalog.text, $7::pg_catalog.text, "
        "c.auth_epoch FROM credential_reset AS c "
        "RETURNING session_id, user_id, auth_epoch), "
        "audit_insert AS ("
        "INSERT INTO public.bbs_audit_events "
        "(actor_user_id, subject_user_id, session_id, event_type, "
        "source_ip, detail) "
        "SELECT s.user_id, s.user_id, s.session_id, "
        "'auth.login_succeeded', $5::pg_catalog.inet, "
        "pg_catalog.jsonb_build_object("
        "'login_name', $8::pg_catalog.text, "
        "'legacy_name', $10::pg_catalog.text, "
        "'protocol', $4::pg_catalog.text, "
        "'auth_method', 'password', "
        "'auth_epoch', s.auth_epoch, "
        "'authz_revision', c.authz_revision, "
        "'tty_device', $6::pg_catalog.text, "
        "'node_id', $7::pg_catalog.text) "
        "FROM session_insert AS s "
        "JOIN credential_reset AS c USING (user_id) "
        "RETURNING event_id, session_id) "
        "SELECT "
        "pg_catalog.encode(pg_catalog.uuid_send(s.session_id), 'hex'), "
        "pg_catalog.encode(pg_catalog.uuid_send(s.user_id), 'hex'), "
        "s.auth_epoch::pg_catalog.text, "
        "c.authz_revision::pg_catalog.text, "
        "a.event_id::pg_catalog.text "
        "FROM session_insert AS s "
        "JOIN credential_reset AS c USING (user_id) "
        "JOIN audit_insert AS a USING (session_id)";
    const char *parameter_values[10];
    char user_id_text[37];
    char auth_epoch_text[32];
    char authz_revision_text[32];
    PGresult *result;
    uint64_t auth_epoch;
    uint64_t authz_revision;
    uint64_t event_id;
    int rows;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (session != NULL) {
        memset(session, 0, sizeof(*session));
    }

    /* Reject stale or malformed snapshots before acquiring a database lock. */
    if (database == NULL || database->connection == NULL || record == NULL ||
        session == NULL || !uuid_is_valid(record->user_id) ||
        !authd_login_name_is_canonical(record->login_name) ||
        !authd_legacy_name_is_valid(record->legacy_name) ||
        authd_login_record_availability(record) != AUTHD_LOGIN_AVAILABLE ||
        !authd_source_ip_is_valid(source_ip) ||
        !authd_login_protocol_is_valid(protocol) ||
        !optional_session_text_is_valid(tty_device, FTAP_TTY_DEVICE_MAX) ||
        !optional_session_text_is_valid(node_id, FTAP_NODE_ID_MAX)) {
        set_error(error, error_size,
                  "invalid password session creation arguments");
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    if (PQstatus(database->connection) != CONNECTION_OK) {
        copy_libpq_error(error, error_size,
                         "database connection is unavailable",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    /* All externally supplied values remain libpq parameters, never SQL text. */
    format_uuid_text(record->user_id, user_id_text);
    (void)snprintf(auth_epoch_text, sizeof(auth_epoch_text), "%llu",
                   (unsigned long long)record->auth_epoch);
    (void)snprintf(authz_revision_text, sizeof(authz_revision_text), "%llu",
                   (unsigned long long)record->authz_revision);

    parameter_values[0] = user_id_text;
    parameter_values[1] = auth_epoch_text;
    parameter_values[2] = authz_revision_text;
    parameter_values[3] = protocol;
    parameter_values[4] = source_ip;
    parameter_values[5] = tty_device;
    parameter_values[6] = node_id;
    parameter_values[7] = record->login_name;
    parameter_values[8] = record->password_hash;
    parameter_values[9] = record->legacy_name;

    result = PQexecParams(database->connection, sql, 10, NULL,
                          parameter_values, NULL, NULL, 0);
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "password session creation failed",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQnfields(result) != 5) {
        copy_result_error(error, error_size,
                          "password session creation failed", result);
        PQclear(result);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    /* No row means the account changed after its password was verified. */
    rows = PQntuples(result);
    if (rows == 0) {
        set_error(error, error_size,
                  "password session state changed during authentication");
        PQclear(result);
        return AUTHD_DATABASE_WRITE_STALE_STATE;
    }
    if (rows != 1 || PQgetisnull(result, 0, 0) ||
        PQgetisnull(result, 0, 1) || PQgetisnull(result, 0, 2) ||
        PQgetisnull(result, 0, 3) || PQgetisnull(result, 0, 4) ||
        !parse_uuid_hex(PQgetvalue(result, 0, 0), session->session_id) ||
        !parse_uuid_hex(PQgetvalue(result, 0, 1), session->user_id) ||
        !uuid_is_valid(session->session_id) ||
        !parse_u64_strict(PQgetvalue(result, 0, 2), &auth_epoch) ||
        !parse_u64_strict(PQgetvalue(result, 0, 3), &authz_revision) ||
        !parse_u64_strict(PQgetvalue(result, 0, 4), &event_id) ||
        auth_epoch == 0U || authz_revision == 0U || event_id == 0U ||
        memcmp(session->user_id, record->user_id, FTAP_UUID_SIZE) != 0 ||
        auth_epoch != record->auth_epoch ||
        authz_revision != record->authz_revision) {
        memset(session, 0, sizeof(*session));
        set_error(error, error_size,
                  "password session creation returned an invalid record");
        PQclear(result);
        return AUTHD_DATABASE_WRITE_INVALID_RECORD;
    }

    session->auth_epoch = auth_epoch;
    session->authz_revision = authz_revision;
    PQclear(result);
    return AUTHD_DATABASE_WRITE_OK;
}

/* Keep persisted session-end reasons inside the FTAP reason namespace. */
static bool
ended_reason_is_valid(const char *reason)
{
    size_t index;
    size_t length;

    if (reason == NULL) {
        return false;
    }
    length = strlen(reason);
    if (length == 0U || length > FTAP_ENDED_REASON_MAX ||
        reason[0] < 'a' || reason[0] > 'z') {
        return false;
    }
    for (index = 1U; index < length; ++index) {
        char character = reason[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') ||
              character == '.' || character == '-' || character == '_')) {
            return false;
        }
    }
    return true;
}

/*
 * Close an open terminal session and append its lifecycle audit atomically.
 * Repeated cleanup is harmless: an already closed or unknown session returns
 * NOT_FOUND and cannot overwrite its original end reason.
 */
authd_database_write_result_t
authd_database_close_terminal_session(
    authd_database_t *database,
    const uint8_t session_id[FTAP_UUID_SIZE],
    const char *ended_reason,
    char *error,
    size_t error_size)
{
    static const char sql[] =
        "WITH closed_session AS ("
        "UPDATE public.bbs_terminal_sessions "
        "SET closed_at = CURRENT_TIMESTAMP, ended_reason = $2::pg_catalog.text "
        "WHERE session_id = $1::pg_catalog.uuid AND closed_at IS NULL "
        "RETURNING session_id, user_id), "
        "audit_insert AS ("
        "INSERT INTO public.bbs_audit_events "
        "(actor_user_id, subject_user_id, session_id, event_type, detail) "
        "SELECT c.user_id, c.user_id, c.session_id, "
        "'auth.terminal_session_closed', "
        "pg_catalog.jsonb_build_object('ended_reason', $2::pg_catalog.text) "
        "FROM closed_session AS c RETURNING event_id) "
        "SELECT event_id::pg_catalog.text FROM audit_insert";
    const char *parameter_values[2];
    char session_id_text[37];
    PGresult *result;
    uint64_t event_id;
    int rows;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (database == NULL || database->connection == NULL ||
        !uuid_is_valid(session_id) || !ended_reason_is_valid(ended_reason)) {
        set_error(error, error_size,
                  "invalid terminal session close arguments");
        return AUTHD_DATABASE_WRITE_INVALID_ARGUMENT;
    }
    if (PQstatus(database->connection) != CONNECTION_OK) {
        copy_libpq_error(error, error_size,
                         "database connection is unavailable",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    format_uuid_text(session_id, session_id_text);
    parameter_values[0] = session_id_text;
    parameter_values[1] = ended_reason;

    result = PQexecParams(database->connection, sql, 2, NULL,
                          parameter_values, NULL, NULL, 0);
    if (result == NULL) {
        copy_libpq_error(error, error_size,
                         "terminal session close failed",
                         database->connection);
        return AUTHD_DATABASE_WRITE_ERROR;
    }
    if (PQresultStatus(result) != PGRES_TUPLES_OK ||
        PQnfields(result) != 1) {
        copy_result_error(error, error_size,
                          "terminal session close failed", result);
        PQclear(result);
        return AUTHD_DATABASE_WRITE_ERROR;
    }

    rows = PQntuples(result);
    if (rows == 0) {
        PQclear(result);
        return AUTHD_DATABASE_WRITE_NOT_FOUND;
    }
    if (rows != 1 || PQgetisnull(result, 0, 0) ||
        !parse_u64_strict(PQgetvalue(result, 0, 0), &event_id) ||
        event_id == 0U) {
        set_error(error, error_size,
                  "terminal session close returned an invalid record");
        PQclear(result);
        return AUTHD_DATABASE_WRITE_INVALID_RECORD;
    }

    PQclear(result);
    return AUTHD_DATABASE_WRITE_OK;
}

authd_login_availability_t
authd_login_record_availability(const authd_login_record_t *record)
{
    if (record == NULL || record->auth_epoch == 0U ||
        record->authz_revision == 0U ||
        record->login_name[0] == '\0' || record->display_name[0] == '\0' ||
        !authd_legacy_name_is_valid(record->legacy_name) ||
        record->password_hash[0] == '\0' ||
        (record->throttled && record->retry_after_ms == 0U) ||
        (!record->throttled && record->retry_after_ms != 0U)) {
        return AUTHD_LOGIN_INVALID_RECORD;
    }
    if (record->deleted ||
        record->account_state == AUTHD_ACCOUNT_STATE_DELETED) {
        return AUTHD_LOGIN_DELETED;
    }
    switch (record->account_state) {
    case AUTHD_ACCOUNT_STATE_PENDING:
        return AUTHD_LOGIN_PENDING;
    case AUTHD_ACCOUNT_STATE_DISABLED:
        return AUTHD_LOGIN_DISABLED;
    case AUTHD_ACCOUNT_STATE_LOCKED:
        return AUTHD_LOGIN_LOCKED;
    case AUTHD_ACCOUNT_STATE_DELETED:
        return AUTHD_LOGIN_DELETED;
    case AUTHD_ACCOUNT_STATE_ACTIVE:
        break;
    default:
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
    switch (state) {
    case AUTHD_ACCOUNT_STATE_PENDING:
        return "pending";
    case AUTHD_ACCOUNT_STATE_ACTIVE:
        return "active";
    case AUTHD_ACCOUNT_STATE_DISABLED:
        return "disabled";
    case AUTHD_ACCOUNT_STATE_LOCKED:
        return "locked";
    case AUTHD_ACCOUNT_STATE_DELETED:
        return "deleted";
    default:
        return "invalid";
    }
}

const char *
authd_database_lookup_result_name(authd_database_lookup_result_t result)
{
    switch (result) {
    case AUTHD_DATABASE_LOOKUP_OK:
        return "ok";
    case AUTHD_DATABASE_LOOKUP_NOT_FOUND:
        return "not_found";
    case AUTHD_DATABASE_LOOKUP_INVALID_RECORD:
        return "invalid_record";
    case AUTHD_DATABASE_LOOKUP_ERROR:
        return "error";
    default:
        return "invalid";
    }
}

const char *
authd_login_availability_name(authd_login_availability_t availability)
{
    switch (availability) {
    case AUTHD_LOGIN_AVAILABLE:
        return "available";
    case AUTHD_LOGIN_PENDING:
        return "pending";
    case AUTHD_LOGIN_DISABLED:
        return "disabled";
    case AUTHD_LOGIN_LOCKED:
        return "locked";
    case AUTHD_LOGIN_DELETED:
        return "deleted";
    case AUTHD_LOGIN_THROTTLED:
        return "throttled";
    case AUTHD_LOGIN_PASSWORD_CHANGE_REQUIRED:
        return "password_change_required";
    case AUTHD_LOGIN_INVALID_RECORD:
        return "invalid_record";
    default:
        return "invalid";
    }
}

/* Return stable diagnostic names for database mutation outcomes. */
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
        return "error";
    default:
        return "invalid";
    }
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
