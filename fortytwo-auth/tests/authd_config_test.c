/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static authd_config_result_t
parse_arguments(authd_config_t *config, int argc, char *argv[], char *error)
{
    return authd_config_parse(config, argc, argv, error, 256U);
}

static void
test_defaults(void)
{
    authd_config_t config;

    authd_config_defaults(&config);
    assert(strcmp(config.socket_path, "/run/fortytwo/auth.sock") == 0);
    assert(config.socket_mode == (mode_t)0660);
    assert(config.allowed_uid_count == 1U);
    assert(config.allowed_uids[0] == geteuid());
    assert(config.max_clients == 64U);
    assert(config.backlog == 64);
    assert(config.hello_timeout_ms == 5000U);
}

static void
test_complete_configuration(void)
{
    authd_config_t config;
    char error[256];
    char *argv[] = {
        (char *)"fortytwo-authd",
        (char *)"--socket", (char *)"/tmp/fortytwo-authd-test.sock",
        (char *)"--socket-mode", (char *)"0620",
        (char *)"--socket-gid", (char *)"42",
        (char *)"--allow-uid", (char *)"1000",
        (char *)"--allow-uid", (char *)"1001",
        (char *)"--allow-uid", (char *)"1000",
        (char *)"--max-clients", (char *)"12",
        (char *)"--backlog", (char *)"13",
        (char *)"--hello-timeout-ms", (char *)"750",
        (char *)"--verbose",
        (char *)"--check-config"
    };

    assert(parse_arguments(&config,
                           (int)(sizeof(argv) / sizeof(argv[0])),
                           argv, error) == AUTHD_CONFIG_OK);
    assert(strcmp(config.socket_path, "/tmp/fortytwo-authd-test.sock") == 0);
    assert(config.socket_mode == (mode_t)0620);
    assert(config.socket_gid_set);
    assert(config.socket_gid == (gid_t)42);
    assert(config.allowed_uid_count == 2U);
    assert(config.allowed_uids[0] == (uid_t)1000);
    assert(config.allowed_uids[1] == (uid_t)1001);
    assert(config.max_clients == 12U);
    assert(config.backlog == 13);
    assert(config.hello_timeout_ms == 750U);
    assert(config.verbose);
    assert(config.check_config);
    assert(authd_config_uid_is_allowed(&config, (uid_t)1001));
    assert(!authd_config_uid_is_allowed(&config, (uid_t)1002));
}

static void
expect_error(int argc, char *argv[], const char *fragment)
{
    authd_config_t config;
    char error[256];

    assert(parse_arguments(&config, argc, argv, error) == AUTHD_CONFIG_ERROR);
    assert(strstr(error, fragment) != NULL);
}

static void
test_invalid_values(void)
{
    char *relative[] = {(char *)"authd", (char *)"--socket", (char *)"x.sock"};
    char *mode[] = {(char *)"authd", (char *)"--socket-mode", (char *)"0888"};
    char *uid[] = {(char *)"authd", (char *)"--allow-uid", (char *)"-1"};
    char *clients[] = {(char *)"authd", (char *)"--max-clients", (char *)"0"};
    char *timeout[] = {(char *)"authd", (char *)"--hello-timeout-ms", (char *)"99"};
    char *positional[] = {(char *)"authd", (char *)"unexpected"};

    expect_error(3, relative, "absolute");
    expect_error(3, mode, "octal");
    expect_error(3, uid, "numeric UID");
    expect_error(3, clients, "between");
    expect_error(3, timeout, "between");
    expect_error(2, positional, "positional");
}

static void
test_help_and_version(void)
{
    authd_config_t config;
    char error[256];
    char *help[] = {(char *)"authd", (char *)"--help"};
    char *version[] = {(char *)"authd", (char *)"--version"};

    assert(parse_arguments(&config, 2, help, error) == AUTHD_CONFIG_HELP);
    assert(parse_arguments(&config, 2, version, error) == AUTHD_CONFIG_VERSION);
}

int
main(void)
{
    test_defaults();
    test_complete_configuration();
    test_invalid_values();
    test_help_and_version();
    (void)puts("authd config tests: OK");
    return 0;
}
