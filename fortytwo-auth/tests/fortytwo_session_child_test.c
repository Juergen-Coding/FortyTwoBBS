/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Child program used to prove the authenticated FTAP descriptor survives
 * execve() without exposing identity values through the environment.
 */

#include "ftap_client.h"
#include "ftap_protocol.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool
uuid_is_nonzero(const uint8_t uuid[FTAP_UUID_SIZE])
{
    size_t index;

    for (index = 0U; index < FTAP_UUID_SIZE; ++index) {
        if (uuid[index] != 0U) {
            return true;
        }
    }
    return false;
}

int
main(void)
{
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_terminal_context_t context;
    const char *mbse_root = getenv("MBSE_ROOT");

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

    memset(&context, 0, sizeof(context));
    ftap_client_init(&client, FTAP_CLIENT_DEFAULT_TIMEOUT_MS);
    ftap_client_error_clear(&error);
    assert(ftap_client_adopt_bound_fd(&client, FTAP_INHERITED_SESSION_FD,
                                      FTAP_CLIENT_DEFAULT_TIMEOUT_MS,
                                      &error) == 0);
    assert(ftap_client_session_context(&client, &context, &error) == 0);
    assert(uuid_is_nonzero(context.user_id));
    assert(uuid_is_nonzero(context.session_id));
    assert(strcmp(context.login_name, "alice") == 0);
    assert(strcmp(context.display_name, "Test alice") == 0);
    assert(strcmp(context.protocol, FTAP_PROTOCOL_SSH) == 0);
    assert(strcmp(context.auth_method, FTAP_AUTH_METHOD_PASSWORD) == 0);
    assert(context.auth_epoch == UINT64_C(7));
    assert(context.authz_revision == UINT64_C(11));
    assert(ftap_client_session_close(&client, "normal_logout", &error) == 0);
    ftap_client_close(&client);

    assert(write(STDOUT_FILENO, "FORTYTWO_SESSION_CHILD_OK\r\n",
                 strlen("FORTYTWO_SESSION_CHILD_OK\r\n")) ==
           (ssize_t)strlen("FORTYTWO_SESSION_CHILD_OK\r\n"));
    return 0;
}
