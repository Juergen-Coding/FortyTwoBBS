/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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
    assert(config.password_workers == 2U);
    assert(config.password_queue_capacity == 16U);
    assert(strcmp(config.db_host, "/var/run/postgresql") == 0);
    assert(strcmp(config.db_name, "fortytwo") == 0);
    assert(config.db_port == 5432U);
    assert(config.db_connect_timeout_seconds == 5U);
    assert(config.db_health_interval_ms == 5000U);
    assert(!config.check_database);
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
        (char *)"--password-workers", (char *)"3",
        (char *)"--password-queue-capacity", (char *)"19",
        (char *)"--db-host", (char *)"/run/postgresql-test",
        (char *)"--db-port", (char *)"5544",
        (char *)"--db-name", (char *)"fortytwo_test",
        (char *)"--db-connect-timeout-seconds", (char *)"7",
        (char *)"--db-health-interval-ms", (char *)"900",
        (char *)"--verbose",
        (char *)"--check-config",
        (char *)"--check-database"
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
    assert(config.password_workers == 3U);
    assert(config.password_queue_capacity == 19U);
    assert(strcmp(config.db_host, "/run/postgresql-test") == 0);
    assert(config.db_port == 5544U);
    assert(strcmp(config.db_name, "fortytwo_test") == 0);
    assert(config.db_connect_timeout_seconds == 7U);
    assert(config.db_health_interval_ms == 900U);
    assert(config.verbose);
    assert(config.check_config);
    assert(config.check_database);
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
    char *workers[] = {(char *)"authd", (char *)"--password-workers", (char *)"0"};
    char *queue[] = {(char *)"authd", (char *)"--password-queue-capacity", (char *)"65"};
    char *queue_too_small[] = {
        (char *)"authd",
        (char *)"--password-workers", (char *)"4",
        (char *)"--password-queue-capacity", (char *)"3"
    };
    char *db_host[] = {(char *)"authd", (char *)"--db-host", (char *)"localhost"};
    char *db_port[] = {(char *)"authd", (char *)"--db-port", (char *)"0"};
    char *db_name[] = {(char *)"authd", (char *)"--db-name", (char *)"bad name"};
    char *db_connect[] = {(char *)"authd", (char *)"--db-connect-timeout-seconds", (char *)"0"};
    char *db_health[] = {(char *)"authd", (char *)"--db-health-interval-ms", (char *)"99"};
    char *positional[] = {(char *)"authd", (char *)"unexpected"};

    expect_error(3, relative, "absolute");
    expect_error(3, mode, "octal");
    expect_error(3, uid, "numeric UID");
    expect_error(3, clients, "between");
    expect_error(3, timeout, "between");
    expect_error(3, workers, "between");
    expect_error(3, queue, "between");
    expect_error(5, queue_too_small, "at least");
    expect_error(3, db_host, "absolute Unix-socket");
    expect_error(3, db_port, "between");
    expect_error(3, db_name, "ASCII letters");
    expect_error(3, db_connect, "between");
    expect_error(3, db_health, "between");
    expect_error(2, positional, "positional");
}

static void
test_printed_configuration(void)
{
    authd_config_t config;
    char *usage = NULL;
    char *effective = NULL;
    size_t usage_size = 0U;
    size_t effective_size = 0U;
    FILE *usage_stream;
    FILE *effective_stream;

    authd_config_defaults(&config);
    config.check_database = true;

    usage_stream = open_memstream(&usage, &usage_size);
    assert(usage_stream != NULL);
    authd_config_print_usage(usage_stream, "fortytwo-authd");
    assert(fclose(usage_stream) == 0);
    assert(usage != NULL);
    assert(usage_size > 0U);
    assert(strstr(usage, "--password-workers") != NULL);
    assert(strstr(usage, "--password-queue-capacity") != NULL);
    assert(strstr(usage, "--db-host") != NULL);
    assert(strstr(usage, "--check-database") != NULL);

    effective_stream = open_memstream(&effective, &effective_size);
    assert(effective_stream != NULL);
    authd_config_print_effective(effective_stream, &config);
    assert(fclose(effective_stream) == 0);
    assert(effective != NULL);
    assert(effective_size > 0U);
    assert(strstr(effective, "password_workers=2") != NULL);
    assert(strstr(effective, "password_queue_capacity=16") != NULL);
    assert(strstr(effective, "db_host=/var/run/postgresql") != NULL);
    assert(strstr(effective, "db_port=5432") != NULL);
    assert(strstr(effective, "db_name=fortytwo") != NULL);
    assert(strstr(effective, "check_database=yes") != NULL);

    free(effective);
    free(usage);
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
    test_printed_configuration();
    test_help_and_version();
    (void)puts("authd config tests: OK");
    return 0;
}
