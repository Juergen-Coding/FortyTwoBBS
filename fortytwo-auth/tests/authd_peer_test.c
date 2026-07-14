/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_peer.h"

#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int
main(void)
{
    int sockets[2];
    authd_peer_credentials_t peer;
    authd_config_t config;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(authd_peer_credentials_read(sockets[0], &peer) == 0);
    assert(peer.pid == getpid());
    assert(peer.uid == geteuid());
    assert(peer.gid == getegid());

    authd_config_defaults(&config);
    assert(authd_peer_credentials_are_allowed(&config, &peer));
    config.allowed_uids[0] = peer.uid == (uid_t)0 ? (uid_t)1 : (uid_t)0;
    assert(!authd_peer_credentials_are_allowed(&config, &peer));

    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
    (void)puts("authd peer tests: OK");
    return 0;
}
