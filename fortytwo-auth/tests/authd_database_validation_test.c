/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_database_validation.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void
test_identity(void)
{
    char error[256];

    assert(authd_database_validate_identity(
        "fortytwo_authd", "fortytwo", 170010, false, "fortytwo",
        error, sizeof(error)));

    assert(!authd_database_validate_identity(
        "fortytwo_db_owner", "fortytwo", 170010, false, "fortytwo",
        error, sizeof(error)));
    assert(strstr(error, "role") != NULL);

    assert(!authd_database_validate_identity(
        "fortytwo_authd", "other", 170010, false, "fortytwo",
        error, sizeof(error)));
    assert(strstr(error, "expected") != NULL);

    assert(!authd_database_validate_identity(
        "fortytwo_authd", "fortytwo", 160999, false, "fortytwo",
        error, sizeof(error)));
    assert(strstr(error, "older") != NULL);

    assert(!authd_database_validate_identity(
        "fortytwo_authd", "fortytwo", 170010, true, "fortytwo",
        error, sizeof(error)));
    assert(strstr(error, "read-only") != NULL);
}

static void
test_migrations(void)
{
    authd_migration_record_t records[AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT];
    const authd_migration_record_t *required;
    size_t count;
    size_t index;
    char error[256];

    required = authd_database_required_migrations(&count);
    assert(required != NULL);
    assert(count == AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT);
    assert(required[count - 1U].version ==
           AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION);
    assert(strcmp(required[count - 1U].name,
                  "0009_telnet_registration.sql") == 0);
    assert(strcmp(required[count - 1U].checksum,
                  "e6a2c4f44460de538e6d6846bae333228793c539776ed6112d06993e4a060547") == 0);
    for (index = 0U; index < count; ++index) {
        records[index] = required[index];
    }

    assert(authd_database_validate_migrations(records, count,
                                              error, sizeof(error)));

    assert(!authd_database_validate_migrations(records, count - 1U,
                                               error, sizeof(error)));
    assert(strstr(error, "registered migrations") != NULL);

    records[1].version = UINT32_C(99);
    assert(!authd_database_validate_migrations(records, count,
                                               error, sizeof(error)));
    assert(strstr(error, "version") != NULL);
    records[1] = required[1];

    records[2].name = "wrong.sql";
    assert(!authd_database_validate_migrations(records, count,
                                               error, sizeof(error)));
    assert(strstr(error, "name mismatch") != NULL);
    records[2] = required[2];

    records[count - 1U].checksum =
        "0000000000000000000000000000000000000000000000000000000000000000";
    assert(!authd_database_validate_migrations(records, count,
                                               error, sizeof(error)));
    assert(strstr(error, "checksum mismatch") != NULL);
}

int
main(void)
{
    test_identity();
    test_migrations();
    (void)puts("authd database validation tests: OK");
    return 0;
}
