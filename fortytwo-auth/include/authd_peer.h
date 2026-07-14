/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Linux Unix-domain peer credential handling for fortytwo-authd.
 */

#ifndef FORTYTWO_AUTHD_PEER_H
#define FORTYTWO_AUTHD_PEER_H

#include "authd_config.h"

#include <stdbool.h>
#include <sys/types.h>

typedef struct authd_peer_credentials {
    pid_t pid;
    uid_t uid;
    gid_t gid;
} authd_peer_credentials_t;

int authd_peer_credentials_read(int socket_fd,
                                authd_peer_credentials_t *credentials);

bool authd_peer_credentials_are_allowed(
    const authd_config_t *config,
    const authd_peer_credentials_t *credentials);

#endif /* FORTYTWO_AUTHD_PEER_H */
