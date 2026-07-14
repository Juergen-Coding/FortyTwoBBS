/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Command-line configuration for fortytwo-authd.
 */

#ifndef FORTYTWO_AUTHD_CONFIG_H
#define FORTYTWO_AUTHD_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/un.h>

#define AUTHD_VERSION "0.2.1"
#define AUTHD_MAX_ALLOWED_UIDS 32U
#define AUTHD_MIN_CLIENTS 1U
#define AUTHD_MAX_CLIENTS 256U
#define AUTHD_MIN_BACKLOG 1U
#define AUTHD_MAX_BACKLOG 4096U
#define AUTHD_MIN_HELLO_TIMEOUT_MS UINT32_C(100)
#define AUTHD_MAX_HELLO_TIMEOUT_MS UINT32_C(300000)

#define AUTHD_DB_HOST_MAX 255U
#define AUTHD_DB_NAME_MAX 63U
#define AUTHD_DB_MIN_PORT 1U
#define AUTHD_DB_MAX_PORT 65535U
#define AUTHD_DB_MIN_CONNECT_TIMEOUT_SECONDS UINT32_C(1)
#define AUTHD_DB_MAX_CONNECT_TIMEOUT_SECONDS UINT32_C(60)
#define AUTHD_DB_MIN_HEALTH_INTERVAL_MS UINT32_C(100)
#define AUTHD_DB_MAX_HEALTH_INTERVAL_MS UINT32_C(300000)

/* The path array matches sockaddr_un.sun_path including its trailing NUL. */
typedef struct authd_config {
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    mode_t socket_mode;
    gid_t socket_gid;
    bool socket_gid_set;
    uid_t allowed_uids[AUTHD_MAX_ALLOWED_UIDS];
    size_t allowed_uid_count;
    size_t max_clients;
    int backlog;
    uint32_t hello_timeout_ms;
    char db_host[AUTHD_DB_HOST_MAX + 1U];
    char db_name[AUTHD_DB_NAME_MAX + 1U];
    uint16_t db_port;
    uint32_t db_connect_timeout_seconds;
    uint32_t db_health_interval_ms;
    bool verbose;
    bool check_config;
    bool check_database;
} authd_config_t;

typedef enum authd_config_result {
    AUTHD_CONFIG_OK = 0,
    AUTHD_CONFIG_HELP,
    AUTHD_CONFIG_VERSION,
    AUTHD_CONFIG_ERROR
} authd_config_result_t;

void authd_config_defaults(authd_config_t *config);

authd_config_result_t authd_config_parse(
    authd_config_t *config,
    int argc,
    char *const argv[],
    char *error,
    size_t error_size);

bool authd_config_uid_is_allowed(const authd_config_t *config, uid_t uid);
void authd_config_print_usage(FILE *stream, const char *program_name);
void authd_config_print_version(FILE *stream);
void authd_config_print_effective(FILE *stream, const authd_config_t *config);

#endif /* FORTYTWO_AUTHD_CONFIG_H */
