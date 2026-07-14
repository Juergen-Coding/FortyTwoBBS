/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Test-only database implementation for daemon integration tests.
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
        if (error != NULL && error_size > 0U) {
            (void)snprintf(error, error_size,
                           "test database startup failure");
        }
        return -1;
    }

    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        if (error != NULL && error_size > 0U) {
            (void)snprintf(error, error_size, "out of memory");
        }
        return -1;
    }
    created->fail_after =
        read_unsigned_environment("FORTYTWO_TEST_DB_HEALTH_FAIL_AFTER");

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
        if (error != NULL && error_size > 0U) {
            (void)snprintf(error, error_size,
                           "test database health failure");
        }
        return -1;
    }
    return 0;
}

void
authd_database_close(authd_database_t *database)
{
    free(database);
}
