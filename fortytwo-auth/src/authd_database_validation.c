/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_database_validation.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const authd_migration_record_t required_migrations[] = {
    {
        UINT32_C(1),
        "0001_identity_and_terminal_sessions.sql",
        "6b019da94bb5bb48ba90d8ba9f2be1bff1c72781e41b332b63cee482c4851b37"
    },
    {
        UINT32_C(2),
        "0002_runtime_privileges.sql",
        "14ba5df3fe9563ba919d248c82fd0ae765686bbe0bff93bf1b8a475480bb6314"
    },
    {
        UINT32_C(3),
        "0003_schema_migration_history.sql",
        "320e49d6a0750a866ffba83c88e8b9f6c649f30ac7eb03ed2314705c22bba00b"
    },
    {
        UINT32_C(4),
        "0004_authd_schema_history_read.sql",
        "5e6bd5fe7bf2ebaaffa49674185d6d3b3b613f7047a47041806ec3b16a9c2f9c"
    },
    {
        UINT32_C(5),
        "0005_login_name_policy.sql",
        "8a272139d18764ad7ec75a91e1aab841047059610886bfd3429b0f6198551002"
    },
    {
        UINT32_C(6),
        "0006_authorization_revision.sql",
        "0492f1763633aa87737cbea1b0456c9521e35adce9257af86534ef84896b1d1c"
    }
};

_Static_assert(
    sizeof(required_migrations) / sizeof(required_migrations[0]) ==
        AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT,
    "required migration count mismatch");

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

const authd_migration_record_t *
authd_database_required_migrations(size_t *count)
{
    if (count != NULL) {
        *count = sizeof(required_migrations) / sizeof(required_migrations[0]);
    }
    return required_migrations;
}

bool
authd_database_validate_identity(const char *current_user,
                                 const char *current_database,
                                 int server_version_num,
                                 bool transaction_read_only,
                                 const char *expected_database,
                                 char *error,
                                 size_t error_size)
{
    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }

    if (current_user == NULL || current_database == NULL ||
        expected_database == NULL) {
        set_error(error, error_size,
                  "database identity response is incomplete");
        return false;
    }
    if (strcmp(current_user, AUTHD_DATABASE_REQUIRED_ROLE) != 0) {
        set_error(error, error_size,
                  "database role must be '%s', connected as '%s'",
                  AUTHD_DATABASE_REQUIRED_ROLE, current_user);
        return false;
    }
    if (strcmp(current_database, expected_database) != 0) {
        set_error(error, error_size,
                  "connected database is '%s', expected '%s'",
                  current_database, expected_database);
        return false;
    }
    if (server_version_num < AUTHD_DATABASE_MIN_SERVER_VERSION_NUM) {
        set_error(error, error_size,
                  "PostgreSQL server version %d is older than required %d",
                  server_version_num,
                  AUTHD_DATABASE_MIN_SERVER_VERSION_NUM);
        return false;
    }
    if (transaction_read_only) {
        set_error(error, error_size,
                  "database connection is read-only");
        return false;
    }

    return true;
}

bool
authd_database_validate_migrations(const authd_migration_record_t *actual,
                                   size_t actual_count,
                                   char *error,
                                   size_t error_size)
{
    size_t expected_count;
    const authd_migration_record_t *expected;
    size_t index;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }

    expected = authd_database_required_migrations(&expected_count);
    if (actual == NULL && actual_count != 0U) {
        set_error(error, error_size,
                  "migration result is missing");
        return false;
    }
    if (actual_count != expected_count) {
        set_error(error, error_size,
                  "database has %zu registered migrations, binary requires %zu",
                  actual_count, expected_count);
        return false;
    }

    for (index = 0U; index < expected_count; ++index) {
        if (actual[index].name == NULL || actual[index].checksum == NULL) {
            set_error(error, error_size,
                      "migration row %zu is incomplete", index + 1U);
            return false;
        }
        if (actual[index].version != expected[index].version) {
            set_error(error, error_size,
                      "migration row %zu has version %u, expected %u",
                      index + 1U,
                      (unsigned int)actual[index].version,
                      (unsigned int)expected[index].version);
            return false;
        }
        if (strcmp(actual[index].name, expected[index].name) != 0) {
            set_error(error, error_size,
                      "migration %u name mismatch: '%s' instead of '%s'",
                      (unsigned int)expected[index].version,
                      actual[index].name,
                      expected[index].name);
            return false;
        }
        if (strcmp(actual[index].checksum, expected[index].checksum) != 0) {
            set_error(error, error_size,
                      "migration %u checksum mismatch",
                      (unsigned int)expected[index].version);
            return false;
        }
    }

    return true;
}
