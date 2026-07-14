/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Exec'd child that exercises the same descriptor-bound bootstrap used by
 * mbsebbs without exposing identity through process arguments or environment.
 */

#include "../../mbsebbs/fortytwo_session.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int
main(void)
{
    char legacy_name[FORTYTWO_LEGACY_NAME_SIZE];
    char error[FORTYTWO_SESSION_ERROR_MAX];
    char tmp_path[4096];
    const char *state_path;
    char saved_state_path[4096];
    const char *mbse_root = getenv("MBSE_ROOT");
    char hold_path[4096];
    char ready_path[4096];
    char release_path[4096];
    int prepare_result;
    int fd;

    assert(mbse_root != NULL && mbse_root[0] == '/');
    assert(getenv("HOME") != NULL);
    assert(strcmp(getenv("HOME"), mbse_root) == 0);
    assert(getenv("PATH") != NULL);
    assert(strcmp(getenv("PATH"), "/usr/bin:/bin") == 0);
    assert(getenv("LOGNAME") == NULL);
    assert(getenv("USER") == NULL);
    assert(getenv("MBSE_USER_ID") == NULL);
    assert(getenv("MBSE_SESSION_ID") == NULL);
    assert(getenv("FORTYTWO_TEST_SECRET") == NULL);

    assert(snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", mbse_root) > 0);
    assert(mkdir(tmp_path, 0700) == 0 || access(tmp_path, F_OK) == 0);

    assert(FortyTwoSessionBootstrap(legacy_name, error, sizeof(error)) == 0);
    assert(strcmp(legacy_name, "alice") == 0);
    prepare_result = FortyTwoSessionPrepare(mbse_root, legacy_name,
                                            error, sizeof(error));
    if (prepare_result == 1) {
        FortyTwoSessionClose("duplicate_login");
        assert(write(STDOUT_FILENO, "FORTYTWO_SESSION_DUPLICATE\r\n",
                     strlen("FORTYTWO_SESSION_DUPLICATE\r\n")) ==
               (ssize_t)strlen("FORTYTWO_SESSION_DUPLICATE\r\n"));
        return 2;
    }
    assert(prepare_result == 0);

    state_path = FortyTwoSessionExitinfoPath();
    assert(state_path != NULL);
    assert(snprintf(saved_state_path, sizeof(saved_state_path), "%s",
                    state_path) > 0);
    fd = open(state_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, "state", 5U) == 5);
    assert(close(fd) == 0);

    assert(snprintf(hold_path, sizeof(hold_path), "%s/hold-session",
                    mbse_root) > 0);
    if (access(hold_path, F_OK) == 0) {
        assert(snprintf(ready_path, sizeof(ready_path), "%s/session-ready",
                        mbse_root) > 0);
        assert(snprintf(release_path, sizeof(release_path),
                        "%s/release-session", mbse_root) > 0);
        fd = open(ready_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0);
        assert(close(fd) == 0);
        while (access(release_path, F_OK) != 0) {
            assert(usleep(10000U) == 0);
        }
    }

    FortyTwoSessionClose("normal_logout");
    assert(access(saved_state_path, F_OK) != 0);

    assert(write(STDOUT_FILENO, "FORTYTWO_SESSION_CHILD_OK\r\n",
                 strlen("FORTYTWO_SESSION_CHILD_OK\r\n")) ==
           (ssize_t)strlen("FORTYTWO_SESSION_CHILD_OK\r\n"));
    return 0;
}
