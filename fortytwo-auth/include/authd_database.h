/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * PostgreSQL lifecycle for fortytwo-authd.
 */

#ifndef FORTYTWO_AUTHD_DATABASE_H
#define FORTYTWO_AUTHD_DATABASE_H

#include "authd_config.h"

#include <stddef.h>

#define AUTHD_DATABASE_ERROR_MAX 512U

typedef struct authd_database authd_database_t;

typedef struct authd_database_info {
    int server_version_num;
    size_t migration_count;
    unsigned int highest_migration;
} authd_database_info_t;

int authd_database_open(const authd_config_t *config,
                        authd_database_t **database,
                        authd_database_info_t *info,
                        char *error,
                        size_t error_size);

int authd_database_health_check(authd_database_t *database,
                                char *error,
                                size_t error_size);

void authd_database_close(authd_database_t *database);

#endif /* FORTYTWO_AUTHD_DATABASE_H */
