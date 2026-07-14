/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_config.h"
#include "authd_server.h"

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
    authd_config_t config;
    authd_config_result_t parse_result;
    char error[256];

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
        return EXIT_SUCCESS;
    }

    return authd_server_run(&config) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
