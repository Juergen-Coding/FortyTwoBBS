/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This test deliberately connects to a nonexistent local socket directory.
 * It verifies that startup fails closed without creating a database object.
 */

#include "authd_config.h"
#include "authd_database.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    char error[AUTHD_DATABASE_ERROR_MAX];

    authd_config_defaults(&config);
    (void)snprintf(config.db_host, sizeof(config.db_host), "%s",
                   "/tmp/fortytwo-authd-no-postgres-here");
    config.db_connect_timeout_seconds = 1U;

    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) != 0);
    assert(database == NULL);
    assert(error[0] != '\0');
    assert(strstr(error, "connection failed") != NULL);

    (void)puts("authd database fail-closed test: OK");
    return 0;
}
