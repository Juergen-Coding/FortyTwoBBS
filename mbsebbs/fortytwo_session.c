/*
 * Descriptor-bound FortyTwo identity bootstrap for the legacy MBSE session.
 */

#include "fortytwo_session.h"

#include "../fortytwo-auth/include/ftap_client.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FORTYTWO_SESSION_TIMEOUT_MS UINT32_C(1000)

struct fortytwo_session_state {
    ftap_client_t client;
    ftap_terminal_context_t context;
    bool bootstrapped;
    bool prepared;
    int lock_fd;
    char runtime_directory[PATH_MAX];
    char exitinfo_path[PATH_MAX];
};

static struct fortytwo_session_state session_state = {
    .client = {.fd = -1},
    .lock_fd = -1
};

static void
set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0U) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static void
secure_clear(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;

    while (size > 0U) {
        *bytes++ = 0U;
        --size;
    }
}

static bool
legacy_name_is_valid(const char *name)
{
    size_t index;
    size_t length;

    if (name == NULL) {
        return false;
    }
    length = strlen(name);
    if (length == 0U || length > 8U) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char character = (unsigned char)name[index];
        bool valid = (character >= (unsigned char)'a' &&
                      character <= (unsigned char)'z') ||
                     (character >= (unsigned char)'0' &&
                      character <= (unsigned char)'9');

        if (index > 0U) {
            valid = valid || character == (unsigned char)'.' ||
                    character == (unsigned char)'_' ||
                    character == (unsigned char)'-';
        }
        if (!valid) {
            return false;
        }
    }
    return true;
}

static void
uuid_to_hex(const uint8_t uuid[FTAP_UUID_SIZE], char output[33])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < (size_t)FTAP_UUID_SIZE; ++index) {
        output[index * 2U] = digits[(uuid[index] >> 4) & 0x0fU];
        output[index * 2U + 1U] = digits[uuid[index] & 0x0fU];
    }
    output[32] = '\0';
}

/* Session directories contain identity-derived state and must not be shared. */
static int
ensure_private_directory(const char *path, char *error, size_t error_size)
{
    struct stat status;

    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        set_error(error, error_size, "cannot create %s: %s",
                  path, strerror(errno));
        return -1;
    }
    if (lstat(path, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != geteuid() || (status.st_mode & 0077) != 0) {
        set_error(error, error_size,
                  "session directory is not private and service-owned: %s",
                  path);
        return -1;
    }
    return 0;
}

static int
make_path(char *output, size_t output_size, const char *format, ...)
{
    va_list arguments;
    int length;

    va_start(arguments, format);
    length = vsnprintf(output, output_size, format, arguments);
    va_end(arguments);
    return length >= 0 && (size_t)length < output_size ? 0 : -1;
}

int
FortyTwoSessionBootstrap(char legacy_name[FORTYTWO_LEGACY_NAME_SIZE],
                         char *error,
                         size_t error_size)
{
    ftap_client_error_t client_error;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (legacy_name != NULL) {
        memset(legacy_name, 0, FORTYTWO_LEGACY_NAME_SIZE);
    }
    if (legacy_name == NULL || session_state.bootstrapped) {
        set_error(error, error_size, "invalid FortyTwo session bootstrap");
        return -1;
    }

    memset(&session_state, 0, sizeof(session_state));
    session_state.client.fd = -1;
    session_state.lock_fd = -1;
    ftap_client_error_clear(&client_error);

    if (ftap_client_adopt_bound_fd(
            &session_state.client, FTAP_INHERITED_SESSION_FD,
            FORTYTWO_SESSION_TIMEOUT_MS, &client_error) != 0 ||
        ftap_client_session_context(
            &session_state.client, &session_state.context,
            &client_error) != 0) {
        set_error(error, error_size, "%s",
                  client_error.text[0] != '\0' ? client_error.text :
                  "authenticated FTAP session is unavailable");
        ftap_client_close(&session_state.client);
        secure_clear(&session_state, sizeof(session_state));
        session_state.client.fd = -1;
        session_state.lock_fd = -1;
        return -1;
    }
    if (!legacy_name_is_valid(session_state.context.legacy_name)) {
        set_error(error, error_size,
                  "FTAP session has no valid legacy MBSE binding");
        ftap_client_close(&session_state.client);
        secure_clear(&session_state, sizeof(session_state));
        session_state.client.fd = -1;
        session_state.lock_fd = -1;
        return -1;
    }

    (void)snprintf(legacy_name, FORTYTWO_LEGACY_NAME_SIZE, "%s",
                   session_state.context.legacy_name);
    session_state.bootstrapped = true;
    return 0;
}

static int
acquire_user_lock(const char *locks_directory,
                  const char *legacy_name,
                  char *error,
                  size_t error_size)
{
    char lock_path[PATH_MAX];
    struct stat status;
    struct flock lock;
    int fd;

    if (make_path(lock_path, sizeof(lock_path), "%s/%s.lock",
                  locks_directory, legacy_name) != 0) {
        set_error(error, error_size, "legacy-user lock path is too long");
        return -1;
    }

    fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        set_error(error, error_size, "cannot open user lock: %s",
                  strerror(errno));
        return -1;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid()) {
        set_error(error, error_size, "legacy-user lock is not service-owned");
        (void)close(fd);
        return -1;
    }
    if (fchmod(fd, 0600) != 0) {
        set_error(error, error_size, "cannot protect user lock: %s",
                  strerror(errno));
        (void)close(fd);
        return -1;
    }

    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &lock) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        if (saved_errno == EACCES || saved_errno == EAGAIN) {
            return 1;
        }
        set_error(error, error_size, "cannot lock legacy user: %s",
                  strerror(saved_errno));
        return -1;
    }

    session_state.lock_fd = fd;
    return 0;
}

int
FortyTwoSessionPrepare(const char *mbse_root,
                       const char *legacy_name,
                       char *error,
                       size_t error_size)
{
    char root_directory[PATH_MAX];
    char locks_directory[PATH_MAX];
    char session_hex[33];
    int lock_result;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }
    if (!session_state.bootstrapped || session_state.prepared ||
        mbse_root == NULL || mbse_root[0] != '/' ||
        !legacy_name_is_valid(legacy_name) ||
        strcmp(legacy_name, session_state.context.legacy_name) != 0) {
        set_error(error, error_size, "invalid FortyTwo session preparation");
        return -1;
    }

    if (make_path(root_directory, sizeof(root_directory),
                  "%s/tmp/fortytwo-sessions", mbse_root) != 0 ||
        make_path(locks_directory, sizeof(locks_directory),
                  "%s/locks", root_directory) != 0) {
        set_error(error, error_size, "FortyTwo session path is too long");
        return -1;
    }
    if (ensure_private_directory(root_directory, error, error_size) != 0 ||
        ensure_private_directory(locks_directory, error, error_size) != 0) {
        return -1;
    }

    lock_result = acquire_user_lock(locks_directory, legacy_name,
                                    error, error_size);
    if (lock_result != 0) {
        return lock_result;
    }

    uuid_to_hex(session_state.context.session_id, session_hex);
    if (make_path(session_state.runtime_directory,
                  sizeof(session_state.runtime_directory), "%s/%s",
                  root_directory, session_hex) != 0 ||
        make_path(session_state.exitinfo_path,
                  sizeof(session_state.exitinfo_path), "%s/exitinfo",
                  session_state.runtime_directory) != 0) {
        set_error(error, error_size, "per-session state path is too long");
        (void)close(session_state.lock_fd);
        session_state.lock_fd = -1;
        return -1;
    }
    if (mkdir(session_state.runtime_directory, 0700) != 0) {
        set_error(error, error_size, "cannot create session state: %s",
                  strerror(errno));
        (void)close(session_state.lock_fd);
        session_state.lock_fd = -1;
        return -1;
    }

    session_state.prepared = true;
    return 0;
}

const char *
FortyTwoSessionExitinfoPath(void)
{
    return session_state.prepared ? session_state.exitinfo_path : NULL;
}

void
FortyTwoSessionClose(const char *ended_reason)
{
    ftap_client_error_t error;

    if (session_state.bootstrapped &&
        session_state.client.state == FTAP_STATE_SESSION_BOUND) {
        ftap_client_error_clear(&error);
        (void)ftap_client_session_close(&session_state.client,
                                        ended_reason, &error);
    }
    ftap_client_close(&session_state.client);

    if (session_state.prepared) {
        (void)unlink(session_state.exitinfo_path);
        (void)rmdir(session_state.runtime_directory);
    }
    if (session_state.lock_fd >= 0) {
        (void)close(session_state.lock_fd);
    }

    secure_clear(&session_state, sizeof(session_state));
    session_state.client.fd = -1;
    session_state.lock_fd = -1;
}
