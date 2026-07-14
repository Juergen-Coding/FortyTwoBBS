/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Pure validation helpers for the fortytwo-authd PostgreSQL connection.
 */

#ifndef FORTYTWO_AUTHD_DATABASE_VALIDATION_H
#define FORTYTWO_AUTHD_DATABASE_VALIDATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUTHD_DATABASE_REQUIRED_ROLE "fortytwo_authd"
#define AUTHD_DATABASE_MIN_SERVER_VERSION_NUM 170000
#define AUTHD_DATABASE_REQUIRED_MIGRATION_COUNT 5U
#define AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION 5U

typedef struct authd_migration_record {
    uint32_t version;
    const char *name;
    const char *checksum;
} authd_migration_record_t;

const authd_migration_record_t *
authd_database_required_migrations(size_t *count);

bool authd_database_validate_identity(
    const char *current_user,
    const char *current_database,
    int server_version_num,
    bool transaction_read_only,
    const char *expected_database,
    char *error,
    size_t error_size);

bool authd_database_validate_migrations(
    const authd_migration_record_t *actual,
    size_t actual_count,
    char *error,
    size_t error_size);

#endif /* FORTYTWO_AUTHD_DATABASE_VALIDATION_H */
