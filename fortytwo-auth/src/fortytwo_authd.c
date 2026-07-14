/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_config.h"
#include "authd_database.h"
#include "authd_server.h"

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
    authd_config_t config;
    authd_config_result_t parse_result;
    authd_database_t *database = NULL;
    authd_database_info_t database_info;
    char error[AUTHD_DATABASE_ERROR_MAX];
    int result;

    parse_result = authd_config_parse(&config, argc, argv,
                                      error, sizeof(error));
    switch (parse_result) {
    case AUTHD_CONFIG_HELP:
        authd_config_print_usage(stdout, argv[0]);
        return EXIT_SUCCESS;
    case AUTHD_CONFIG_VERSION:
        authd_config_print_version(stdout);
        return EXIT_SUCCESS;
    case AUTHD_CONFIG_ERROR:
        (void)fprintf(stderr, "%s: %s\n", argv[0], error);
        authd_config_print_usage(stderr, argv[0]);
        return EXIT_FAILURE;
    case AUTHD_CONFIG_OK:
        break;
    default:
        (void)fprintf(stderr, "%s: internal configuration error\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (config.check_config) {
        authd_config_print_effective(stdout, &config);
        if (!config.check_database) {
            return EXIT_SUCCESS;
        }
    }

    if (authd_database_open(&config, &database, &database_info,
                            error, sizeof(error)) != 0) {
        (void)fprintf(stderr,
                      "fortytwo-authd: database startup check failed: %s\n",
                      error);
        return EXIT_FAILURE;
    }

    (void)fprintf(stderr,
                  "fortytwo-authd: database ready: PostgreSQL %d, schema %u\n",
                  database_info.server_version_num,
                  database_info.highest_migration);

    if (config.check_database) {
        (void)printf("database=ready\n");
        (void)printf("server_version_num=%d\n",
                     database_info.server_version_num);
        (void)printf("migration_count=%zu\n",
                     database_info.migration_count);
        (void)printf("highest_migration=%u\n",
                     database_info.highest_migration);
        authd_database_close(database);
        return EXIT_SUCCESS;
    }

    result = authd_server_run(&config, database);
    authd_database_close(database);
    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
