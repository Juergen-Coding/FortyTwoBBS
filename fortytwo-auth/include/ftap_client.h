/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Synchronous client for one local FTAP terminal session.
 */

#ifndef FORTYTWO_FTAP_CLIENT_H
#define FORTYTWO_FTAP_CLIENT_H

#include "ftap_codec.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FTAP_CLIENT_DEFAULT_TIMEOUT_MS UINT32_C(5000)
#define FTAP_CLIENT_ERROR_TEXT_SIZE (FTAP_ERROR_TEXT_MAX + 1U)

typedef struct ftap_client {
    int fd;
    ftap_connection_state_t state;
    uint64_t next_request_id;
    uint32_t timeout_ms;
} ftap_client_t;

typedef struct ftap_client_error {
    ftap_status_t status;
    int system_errno;
    uint32_t protocol_error;
    uint32_t retry_after_ms;
    bool server_error;
    bool outcome_unknown;
    char text[FTAP_CLIENT_ERROR_TEXT_SIZE];
} ftap_client_error_t;

typedef struct ftap_terminal_context {
    uint8_t user_id[FTAP_UUID_SIZE];
    uint8_t session_id[FTAP_UUID_SIZE];
    char login_name[FTAP_LOGIN_NAME_MAX + 1U];
    char display_name[FTAP_DISPLAY_NAME_MAX + 1U];
    char legacy_name[FTAP_LEGACY_NAME_MAX + 1U];
    char protocol[FTAP_PROTOCOL_NAME_MAX + 1U];
    char auth_method[FTAP_AUTH_METHOD_MAX + 1U];
    uint64_t auth_epoch;
    uint64_t authz_revision;
} ftap_terminal_context_t;

typedef struct ftap_password_metadata {
    const char *protocol;
    const char *source_ip;
    const char *tty_device;
    const char *node_id;
} ftap_password_metadata_t;

typedef struct ftap_registration_metadata {
    const char *protocol;
    const char *source_ip;
    const char *tty_device;
    const char *node_id;
} ftap_registration_metadata_t;

typedef struct ftap_registration_context {
    uint8_t registration_id[FTAP_UUID_SIZE];
    uint8_t user_id[FTAP_UUID_SIZE];
    char login_name[FTAP_LOGIN_NAME_MAX + 1U];
    char display_name[FTAP_DISPLAY_NAME_MAX + 1U];
    char legacy_name[FTAP_LEGACY_NAME_MAX + 1U];
} ftap_registration_context_t;

void ftap_client_init(ftap_client_t *client, uint32_t timeout_ms);
void ftap_client_error_clear(ftap_client_error_t *error);

int ftap_client_connect(ftap_client_t *client,
                        const char *socket_path,
                        ftap_client_error_t *error);

int ftap_client_adopt_bound_fd(ftap_client_t *client,
                               int fd,
                               uint32_t timeout_ms,
                               ftap_client_error_t *error);

int ftap_client_hello(ftap_client_t *client,
                      const char *client_name,
                      const char *client_version,
                      ftap_client_error_t *error);

int ftap_client_authenticate_password(
    ftap_client_t *client,
    const char *login_name,
    const uint8_t *password,
    size_t password_length,
    const ftap_password_metadata_t *metadata,
    ftap_terminal_context_t *result,
    ftap_client_error_t *error);

int ftap_client_registration_begin(
    ftap_client_t *client,
    const char *login_name,
    const char *display_name,
    const uint8_t *password,
    size_t password_length,
    const ftap_registration_metadata_t *metadata,
    ftap_registration_context_t *result,
    ftap_client_error_t *error);

int ftap_client_registration_commit(
    ftap_client_t *client,
    const ftap_registration_context_t *registration,
    ftap_terminal_context_t *result,
    ftap_client_error_t *error);

int ftap_client_registration_abort(
    ftap_client_t *client,
    const ftap_registration_context_t *registration,
    const char *reason,
    ftap_client_error_t *error);

int ftap_client_session_context(ftap_client_t *client,
                                ftap_terminal_context_t *context,
                                ftap_client_error_t *error);

int ftap_client_session_close(ftap_client_t *client,
                              const char *ended_reason,
                              ftap_client_error_t *error);

int ftap_client_move_to_inherited_fd(ftap_client_t *client,
                                     ftap_client_error_t *error);

void ftap_client_close(ftap_client_t *client);

#endif /* FORTYTWO_FTAP_CLIENT_H */
