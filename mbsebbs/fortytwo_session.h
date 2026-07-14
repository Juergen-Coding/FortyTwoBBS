#ifndef _FORTYTWO_SESSION_H
#define _FORTYTWO_SESSION_H

#include <stddef.h>

#define FORTYTWO_SESSION_ERROR_MAX 256
#define FORTYTWO_LEGACY_NAME_SIZE 9

/*
 * Adopt the authenticated FTAP stream inherited on descriptor 3 and recover
 * the legacy users.data key bound to that exact socket session.
 */
int FortyTwoSessionBootstrap(
    char legacy_name[FORTYTWO_LEGACY_NAME_SIZE],
    char *error,
    size_t error_size);

/*
 * Create private per-session state and hold an exclusive legacy-user lock.
 * A return value of 1 means that the same legacy user already has a session.
 */
int FortyTwoSessionPrepare(
    const char *mbse_root,
    const char *legacy_name,
    char *error,
    size_t error_size);

const char *FortyTwoSessionExitinfoPath(void);

/* Close the database-backed terminal session and release local state. */
void FortyTwoSessionClose(const char *ended_reason);

#endif
