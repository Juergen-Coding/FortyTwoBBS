/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_peer.h"

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

int
authd_peer_credentials_read(int socket_fd,
                            authd_peer_credentials_t *credentials)
{
    struct ucred peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);

    if (socket_fd < 0 || credentials == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED,
                   &peer, &peer_length) != 0) {
        return -1;
    }
    if (peer_length != (socklen_t)sizeof(peer)) {
        errno = EPROTO;
        return -1;
    }

    credentials->pid = peer.pid;
    credentials->uid = peer.uid;
    credentials->gid = peer.gid;
    return 0;
}

bool
authd_peer_credentials_are_allowed(
    const authd_config_t *config,
    const authd_peer_credentials_t *credentials)
{
    return config != NULL && credentials != NULL &&
           credentials->pid > 0 &&
           authd_config_uid_is_allowed(config, credentials->uid);
}
