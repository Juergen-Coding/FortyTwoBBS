/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Local FTAP server and asynchronous password-login coordinator.
 */

#include "authd_server.h"

#include "authd_database.h"
#include "authd_identity.h"
#include "authd_password.h"
#include "authd_peer.h"
#include "authd_throttle.h"
#include "authd_worker_pool.h"
#include "ftap_codec.h"
#include "ftap_schema.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#include <time.h>
#include <unistd.h>

#define AUTHD_RESPONSE_BUFFER_SIZE 512U
#define AUTHD_POLL_MAXIMUM_MS 1000

typedef struct authd_socket_identity {
    dev_t device;
    ino_t inode;
    bool valid;
} authd_socket_identity_t;

typedef struct authd_login_attempt {
    bool active;
    uint64_t request_id;
    uint64_t worker_job_id;
    char login_name[AUTHD_LOGIN_NAME_BUFFER_SIZE];
    char protocol[FTAP_PROTOCOL_NAME_MAX + 1U];
    char source_ip[FTAP_IP_ADDRESS_MAX + 1U];
    char tty_device[FTAP_TTY_DEVICE_MAX + 1U];
    char node_id[FTAP_NODE_ID_MAX + 1U];
    bool source_ip_set;
    bool tty_device_set;
    bool node_id_set;
    bool record_loaded;
    authd_login_record_t record;
    bool deferred_rejection;
    authd_login_rejection_reason_t rejection_reason;
} authd_login_attempt_t;

typedef struct authd_bound_session_context {
    char login_name[FTAP_LOGIN_NAME_MAX + 1U];
    char display_name[FTAP_DISPLAY_NAME_MAX + 1U];
    char legacy_name[FTAP_LEGACY_NAME_MAX + 1U];
    char protocol[FTAP_PROTOCOL_NAME_MAX + 1U];
    char auth_method[FTAP_AUTH_METHOD_MAX + 1U];
} authd_bound_session_context_t;

typedef struct authd_client {
    int fd;
    uint64_t connection_id;
    uint64_t connection_generation;
    ftap_connection_state_t state;
    authd_peer_credentials_t peer;
    uint8_t *input;
    size_t input_used;
    size_t expected_frame_size;
    uint8_t output[AUTHD_RESPONSE_BUFFER_SIZE];
    size_t output_length;
    size_t output_offset;
    bool close_after_write;
    uint64_t hello_deadline_ms;
    authd_login_attempt_t login;
    bool session_open;
    authd_terminal_session_result_t session;
    authd_bound_session_context_t session_context;
    char pending_end_reason[FTAP_ENDED_REASON_MAX + 1U];
} authd_client_t;

typedef struct authd_signal_state {
    int read_fd;
    int write_fd;
    struct sigaction old_sigint;
    struct sigaction old_sigterm;
    struct sigaction old_sigpipe;
    bool installed;
} authd_signal_state_t;

typedef struct authd_server_context {
    authd_database_t *database;
    authd_worker_pool_t *worker_pool;
    authd_throttle_policy_t throttle_policy;
    char dummy_password_hash[AUTHD_DATABASE_PASSWORD_HASH_MAX + 1U];
} authd_server_context_t;

static volatile sig_atomic_t signal_pipe_write_fd = -1;

static void
authd_signal_handler(int signal_number)
{
    int saved_errno = errno;
    uint8_t byte = (uint8_t)signal_number;
    int fd = (int)signal_pipe_write_fd;

    if (fd >= 0) {
        ssize_t ignored = write(fd, &byte, sizeof(byte));
        (void)ignored;
    }

    errno = saved_errno;
}

#if !defined(__linux__)
static int
set_nonblocking_cloexec(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        return -1;
    }

    return 0;
}
#endif

static int
signal_state_install(authd_signal_state_t *state)
{
    struct sigaction action;
    struct sigaction ignore_action;
    int pipe_fds[2] = {-1, -1};

    if (state == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(state, 0, sizeof(*state));
    state->read_fd = -1;
    state->write_fd = -1;

#if defined(__linux__)
    if (pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC) != 0) {
        return -1;
    }
#else
    if (pipe(pipe_fds) != 0) {
        return -1;
    }
    if (set_nonblocking_cloexec(pipe_fds[0]) != 0 ||
        set_nonblocking_cloexec(pipe_fds[1]) != 0) {
        int saved_errno = errno;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
#endif

    memset(&action, 0, sizeof(action));
    action.sa_handler = authd_signal_handler;
    (void)sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    memset(&ignore_action, 0, sizeof(ignore_action));
    ignore_action.sa_handler = SIG_IGN;
    (void)sigemptyset(&ignore_action.sa_mask);

    signal_pipe_write_fd = pipe_fds[1];
    if (sigaction(SIGINT, &action, &state->old_sigint) != 0) {
        int saved_errno = errno;
        signal_pipe_write_fd = -1;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    if (sigaction(SIGTERM, &action, &state->old_sigterm) != 0) {
        int saved_errno = errno;
        (void)sigaction(SIGINT, &state->old_sigint, NULL);
        signal_pipe_write_fd = -1;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }
    if (sigaction(SIGPIPE, &ignore_action, &state->old_sigpipe) != 0) {
        int saved_errno = errno;
        (void)sigaction(SIGTERM, &state->old_sigterm, NULL);
        (void)sigaction(SIGINT, &state->old_sigint, NULL);
        signal_pipe_write_fd = -1;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        errno = saved_errno;
        return -1;
    }

    state->read_fd = pipe_fds[0];
    state->write_fd = pipe_fds[1];
    state->installed = true;
    return 0;
}

static void
signal_state_restore(authd_signal_state_t *state)
{
    if (state == NULL) {
        return;
    }

    signal_pipe_write_fd = -1;
    if (state->installed) {
        (void)sigaction(SIGINT, &state->old_sigint, NULL);
        (void)sigaction(SIGTERM, &state->old_sigterm, NULL);
        (void)sigaction(SIGPIPE, &state->old_sigpipe, NULL);
    }
    if (state->read_fd >= 0) {
        (void)close(state->read_fd);
    }
    if (state->write_fd >= 0) {
        (void)close(state->write_fd);
    }
    memset(state, 0, sizeof(*state));
    state->read_fd = -1;
    state->write_fd = -1;
}

static int
monotonic_milliseconds(uint64_t *milliseconds)
{
    struct timespec now;
    uint64_t seconds;
    uint64_t nanos;

    if (milliseconds == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    if (now.tv_sec < 0 || now.tv_nsec < 0) {
        errno = EOVERFLOW;
        return -1;
    }

    seconds = (uint64_t)now.tv_sec;
    nanos = (uint64_t)now.tv_nsec;
    if (seconds > (UINT64_MAX - nanos / UINT64_C(1000000)) /
                      UINT64_C(1000)) {
        errno = EOVERFLOW;
        return -1;
    }

    *milliseconds = seconds * UINT64_C(1000) +
                    nanos / UINT64_C(1000000);
    return 0;
}

static void
log_peer(const authd_config_t *config,
         const char *event,
         const authd_peer_credentials_t *peer)
{
    if (config == NULL || !config->verbose || event == NULL || peer == NULL) {
        return;
    }

    (void)fprintf(stderr, "fortytwo-authd: %s pid=%jd uid=%ju gid=%ju\n",
                  event,
                  (intmax_t)peer->pid,
                  (uintmax_t)peer->uid,
                  (uintmax_t)peer->gid);
}

static int
prepare_existing_socket_path(const char *path)
{
    struct stat status;

    if (lstat(path, &status) != 0) {
        return errno == ENOENT ? 0 : -1;
    }

    if (!S_ISSOCK(status.st_mode)) {
        errno = EEXIST;
        return -1;
    }
    if (status.st_uid != geteuid()) {
        errno = EPERM;
        return -1;
    }

    return unlink(path);
}

static int
create_listener(const authd_config_t *config,
                authd_socket_identity_t *identity)
{
    struct sockaddr_un address;
    struct stat status;
    mode_t previous_umask;
    int listener = -1;
    int saved_errno;

    if (config == NULL || identity == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(identity, 0, sizeof(*identity));
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                   config->socket_path);

    if (prepare_existing_socket_path(config->socket_path) != 0) {
        return -1;
    }

    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        return -1;
    }

    previous_umask = umask((mode_t)0077);
    if (bind(listener, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) != 0) {
        saved_errno = errno;
        (void)umask(previous_umask);
        (void)close(listener);
        errno = saved_errno;
        return -1;
    }
    (void)umask(previous_umask);

    if (chmod(config->socket_path, config->socket_mode) != 0) {
        goto fail;
    }
    if (config->socket_gid_set &&
        chown(config->socket_path, (uid_t)-1, config->socket_gid) != 0) {
        goto fail;
    }
    if (listen(listener, config->backlog) != 0) {
        goto fail;
    }
    if (lstat(config->socket_path, &status) != 0) {
        goto fail;
    }
    if (!S_ISSOCK(status.st_mode)) {
        errno = EPROTO;
        goto fail;
    }

    identity->device = status.st_dev;
    identity->inode = status.st_ino;
    identity->valid = true;
    return listener;

fail:
    saved_errno = errno;
    (void)close(listener);
    (void)unlink(config->socket_path);
    errno = saved_errno;
    return -1;
}

static void
remove_listener_path(const char *path,
                     const authd_socket_identity_t *identity)
{
    struct stat status;

    if (path == NULL || identity == NULL || !identity->valid) {
        return;
    }

    if (lstat(path, &status) == 0 && S_ISSOCK(status.st_mode) &&
        status.st_dev == identity->device &&
        status.st_ino == identity->inode) {
        (void)unlink(path);
    }
}

static void
login_attempt_clear(authd_login_attempt_t *attempt)
{
    if (attempt != NULL) {
        authd_password_wipe(attempt, sizeof(*attempt));
    }
}

/*
 * A database session lives exactly as long as its authenticated FTAP socket.
 * Cleanup is best-effort during fatal database failure, but every ordinary
 * disconnect records the first terminal end reason atomically with its audit.
 */
static void
client_reset(authd_client_t *client,
             authd_database_t *database,
             const char *ended_reason)
{
    uint64_t connection_id;
    uint64_t connection_generation;

    if (client == NULL) {
        return;
    }

    if (client->session_open && database != NULL && ended_reason != NULL) {
        char error[AUTHD_DATABASE_ERROR_MAX];
        authd_database_write_result_t close_result;

        close_result = authd_database_close_terminal_session(
            database, client->session.session_id, ended_reason,
            error, sizeof(error));
        if (close_result != AUTHD_DATABASE_WRITE_OK &&
            close_result != AUTHD_DATABASE_WRITE_NOT_FOUND) {
            (void)fprintf(stderr,
                          "fortytwo-authd: session close failed: %s\n",
                          error[0] != '\0' ? error :
                          authd_database_write_result_name(close_result));
        }
    }

    if (client->fd >= 0) {
        (void)close(client->fd);
    }
    if (client->input != NULL) {
        authd_password_wipe(client->input, (size_t)FTAP_MAX_FRAME_SIZE);
        free(client->input);
    }
    login_attempt_clear(&client->login);
    authd_password_wipe(client->output, sizeof(client->output));

    connection_id = client->connection_id;
    connection_generation = client->connection_generation;
    memset(client, 0, sizeof(*client));
    client->fd = -1;
    client->connection_id = connection_id;
    client->connection_generation = connection_generation;
}

static void
client_array_initialize(authd_client_t *clients, size_t count)
{
    size_t index;

    for (index = 0U; index < count; ++index) {
        memset(&clients[index], 0, sizeof(clients[index]));
        clients[index].fd = -1;
        clients[index].connection_id = (uint64_t)index + UINT64_C(1);
    }
}

static authd_client_t *
find_free_client(authd_client_t *clients, size_t count)
{
    size_t index;

    for (index = 0U; index < count; ++index) {
        if (clients[index].fd < 0) {
            return &clients[index];
        }
    }

    return NULL;
}

static int
queue_frame(authd_client_t *client,
            uint16_t message_type,
            uint16_t flags,
            uint64_t request_id,
            const uint8_t *payload,
            size_t payload_length,
            bool close_after_write)
{
    ftap_frame_header_t header;
    ftap_status_t status;
    size_t frame_length;

    if (client == NULL ||
        (payload == NULL && payload_length != 0U) ||
        client->output_length != client->output_offset ||
        payload_length > AUTHD_RESPONSE_BUFFER_SIZE - FTAP_FRAME_HEADER_SIZE) {
        errno = EINVAL;
        return -1;
    }

    frame_length = FTAP_FRAME_HEADER_SIZE + payload_length;
    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = message_type;
    header.flags = flags;
    header.payload_length = (uint32_t)payload_length;
    header.request_id = request_id;

    status = ftap_frame_header_encode(client->output, &header);
    if (status != FTAP_STATUS_OK) {
        errno = EPROTO;
        return -1;
    }
    if (payload_length > 0U) {
        memcpy(client->output + FTAP_FRAME_HEADER_SIZE,
               payload, payload_length);
    }

    client->output_offset = 0U;
    client->output_length = frame_length;
    client->close_after_write = close_after_write;
    return 0;
}

static const char *
error_text(uint32_t error_code)
{
    switch (error_code) {
    case FTAP_ERR_UNSUPPORTED_VERSION:
        return "unsupported FTAP version";
    case FTAP_ERR_UNSUPPORTED_FIELD:
        return "unsupported critical field";
    case FTAP_ERR_INVALID_STATE:
        return "message not allowed in current state";
    case FTAP_ERR_MESSAGE_TOO_LARGE:
        return "FTAP frame is too large";
    case FTAP_ERR_ACCESS_DENIED:
        return "access denied";
    case FTAP_ERR_INVALID_CREDENTIALS:
    case FTAP_ERR_ACCOUNT_UNAVAILABLE:
        return "authentication failed";
    case FTAP_ERR_RATE_LIMITED:
        return "authentication temporarily rate limited";
    case FTAP_ERR_DATABASE_UNAVAILABLE:
        return "database unavailable";
    case FTAP_ERR_INTERNAL:
        return "internal service error";
    case FTAP_ERR_PROTOCOL:
    default:
        return "invalid FTAP message";
    }
}

static uint32_t
map_status_to_error(ftap_status_t status)
{
    switch (status) {
    case FTAP_STATUS_ERR_VERSION:
    case FTAP_STATUS_NEWER_MINOR:
        return FTAP_ERR_UNSUPPORTED_VERSION;
    case FTAP_STATUS_ERR_UNSUPPORTED_FIELD:
        return FTAP_ERR_UNSUPPORTED_FIELD;
    case FTAP_STATUS_ERR_INVALID_STATE:
        return FTAP_ERR_INVALID_STATE;
    case FTAP_STATUS_ERR_CAPACITY:
        return FTAP_ERR_MESSAGE_TOO_LARGE;
    case FTAP_STATUS_ERR_LENGTH:
        return FTAP_ERR_PROTOCOL;
    default:
        return FTAP_ERR_PROTOCOL;
    }
}

static int
queue_error_with_retry(authd_client_t *client,
                       uint64_t request_id,
                       uint32_t error_code,
                       uint64_t retry_after_ms)
{
    uint8_t payload[AUTHD_RESPONSE_BUFFER_SIZE - FTAP_FRAME_HEADER_SIZE];
    ftap_tlv_writer_t writer;
    ftap_status_t status;
    const char *text = error_text(error_code);

    if (client == NULL || request_id < FTAP_FIRST_CLIENT_REQUEST_ID) {
        errno = EPROTO;
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_u32(&writer, FTAP_FIELD_ERROR_CODE,
                                         0, error_code);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_ERROR_TEXT, 0,
            (const uint8_t *)text, strlen(text), FTAP_ERROR_TEXT_MAX);
    }
    if (status == FTAP_STATUS_OK && retry_after_ms > 0U) {
        uint32_t bounded_retry = retry_after_ms > UINT32_MAX
                                     ? UINT32_MAX
                                     : (uint32_t)retry_after_ms;
        status = ftap_tlv_writer_put_u32(&writer, FTAP_FIELD_RETRY_AFTER_MS,
                                         0, bounded_retry);
    }
    if (status != FTAP_STATUS_OK) {
        errno = EPROTO;
        return -1;
    }

    return queue_frame(client, FTAP_MSG_ERROR,
                       (uint16_t)(FTAP_FRAME_FLAG_RESPONSE |
                                  FTAP_FRAME_FLAG_ERROR),
                       request_id, payload, writer.length, true);
}

static int
queue_error(authd_client_t *client,
            uint64_t request_id,
            uint32_t error_code)
{
    return queue_error_with_retry(client, request_id, error_code, 0U);
}

static int
hello_versions_are_supported(const uint8_t *payload,
                             size_t payload_length)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    uint16_t major = 0U;
    uint16_t minor = 0U;

    status = ftap_tlv_reader_init(&reader, payload, payload_length);
    if (status != FTAP_STATUS_OK) {
        return 0;
    }

    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            return 0;
        }
        if (field.type == FTAP_FIELD_SUPPORTED_MAJOR) {
            if (ftap_tlv_get_u16(&field, &major) != FTAP_STATUS_OK) {
                return 0;
            }
        } else if (field.type == FTAP_FIELD_SUPPORTED_MINOR) {
            if (ftap_tlv_get_u16(&field, &minor) != FTAP_STATUS_OK) {
                return 0;
            }
        }
    }

    return major == FTAP_VERSION_MAJOR && minor >= FTAP_VERSION_MINOR;
}

static const char *
login_source_ip(const authd_login_attempt_t *attempt)
{
    return attempt->source_ip_set ? attempt->source_ip : NULL;
}

static const char *
login_tty_device(const authd_login_attempt_t *attempt)
{
    return attempt->tty_device_set ? attempt->tty_device : NULL;
}

static const char *
login_node_id(const authd_login_attempt_t *attempt)
{
    return attempt->node_id_set ? attempt->node_id : NULL;
}

static bool
copy_field_text(const ftap_tlv_t *field, char *output, size_t output_size)
{
    if (field == NULL || output == NULL || output_size == 0U ||
        (size_t)field->length >= output_size) {
        return false;
    }
    memcpy(output, field->value, field->length);
    output[field->length] = '\0';
    return true;
}

static authd_login_rejection_reason_t
availability_rejection_reason(authd_login_availability_t availability)
{
    switch (availability) {
    case AUTHD_LOGIN_PENDING:
        return AUTHD_LOGIN_REJECTION_PENDING;
    case AUTHD_LOGIN_DISABLED:
        return AUTHD_LOGIN_REJECTION_DISABLED;
    case AUTHD_LOGIN_LOCKED:
        return AUTHD_LOGIN_REJECTION_LOCKED;
    case AUTHD_LOGIN_DELETED:
        return AUTHD_LOGIN_REJECTION_DELETED;
    case AUTHD_LOGIN_THROTTLED:
        return AUTHD_LOGIN_REJECTION_THROTTLED;
    case AUTHD_LOGIN_PASSWORD_CHANGE_REQUIRED:
        return AUTHD_LOGIN_REJECTION_PASSWORD_CHANGE_REQUIRED;
    case AUTHD_LOGIN_INVALID_RECORD:
    default:
        return AUTHD_LOGIN_REJECTION_INVALID_RECORD;
    }
}

static int
audit_login_rejection(authd_server_context_t *context,
                      const authd_login_attempt_t *attempt,
                      authd_login_rejection_reason_t reason)
{
    const uint8_t *user_id = NULL;
    char error[AUTHD_DATABASE_ERROR_MAX];
    authd_database_write_result_t result;

    if (attempt->record_loaded &&
        reason != AUTHD_LOGIN_REJECTION_UNKNOWN_USER) {
        user_id = attempt->record.user_id;
    }
    result = authd_database_audit_login_rejection(
        context->database, user_id, attempt->login_name, reason,
        login_source_ip(attempt), attempt->protocol,
        error, sizeof(error));
    if (result != AUTHD_DATABASE_WRITE_OK) {
        (void)fprintf(stderr,
                      "fortytwo-authd: login rejection audit failed: %s\n",
                      error[0] != '\0' ? error :
                      authd_database_write_result_name(result));
        return -1;
    }
    return 0;
}

static int
queue_authentication_result(authd_client_t *client,
                            uint64_t request_id,
                            const authd_login_attempt_t *attempt,
                            const authd_terminal_session_result_t *session)
{
    uint8_t payload[AUTHD_RESPONSE_BUFFER_SIZE - FTAP_FRAME_HEADER_SIZE];
    ftap_tlv_writer_t writer;
    ftap_status_t status;

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_USER_ID, 0,
                                          session->user_id);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_SESSION_ID, 0,
                                          session->session_id);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_LOGIN_NAME, 0,
            (const uint8_t *)attempt->record.login_name,
            strlen(attempt->record.login_name), FTAP_LOGIN_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_DISPLAY_NAME, 0,
            (const uint8_t *)attempt->record.display_name,
            strlen(attempt->record.display_name), FTAP_DISPLAY_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_LEGACY_NAME, 0,
            (const uint8_t *)attempt->record.legacy_name,
            strlen(attempt->record.legacy_name), FTAP_LEGACY_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_u64(&writer, FTAP_FIELD_AUTH_EPOCH, 0,
                                         session->auth_epoch);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_u64(&writer, FTAP_FIELD_AUTHZ_REVISION, 0,
                                         session->authz_revision);
    }
    if (status != FTAP_STATUS_OK) {
        errno = EPROTO;
        return -1;
    }

    return queue_frame(client, FTAP_MSG_AUTH_PASSWORD_RESULT,
                       FTAP_FRAME_FLAG_RESPONSE, request_id,
                       payload, writer.length, false);
}

/*
 * Reconstruct the authenticated identity only from state bound to this socket.
 * No caller-supplied user or session identifier participates in this response.
 */
static int
queue_session_context_result(authd_client_t *client, uint64_t request_id)
{
    uint8_t payload[AUTHD_RESPONSE_BUFFER_SIZE - FTAP_FRAME_HEADER_SIZE];
    ftap_tlv_writer_t writer;
    ftap_status_t status;

    if (client == NULL || !client->session_open) {
        errno = EINVAL;
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_USER_ID, 0,
                                          client->session.user_id);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_SESSION_ID, 0,
                                          client->session.session_id);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_LOGIN_NAME, 0,
            (const uint8_t *)client->session_context.login_name,
            strlen(client->session_context.login_name), FTAP_LOGIN_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_DISPLAY_NAME, 0,
            (const uint8_t *)client->session_context.display_name,
            strlen(client->session_context.display_name),
            FTAP_DISPLAY_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_LEGACY_NAME, 0,
            (const uint8_t *)client->session_context.legacy_name,
            strlen(client->session_context.legacy_name),
            FTAP_LEGACY_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_PROTOCOL, 0,
            (const uint8_t *)client->session_context.protocol,
            strlen(client->session_context.protocol), FTAP_PROTOCOL_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_AUTH_METHOD, 0,
            (const uint8_t *)client->session_context.auth_method,
            strlen(client->session_context.auth_method), FTAP_AUTH_METHOD_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_u64(&writer, FTAP_FIELD_AUTH_EPOCH, 0,
                                         client->session.auth_epoch);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_u64(&writer, FTAP_FIELD_AUTHZ_REVISION, 0,
                                         client->session.authz_revision);
    }
    if (status != FTAP_STATUS_OK) {
        errno = EPROTO;
        return -1;
    }

    {
        int result = queue_frame(client, FTAP_MSG_SESSION_CONTEXT_RESULT,
                                 FTAP_FRAME_FLAG_RESPONSE, request_id,
                                 payload, writer.length, false);
        authd_password_wipe(payload, sizeof(payload));
        return result;
    }
}

/* Parse one validated password request without retaining payload pointers. */
static bool
parse_password_request(const uint8_t *payload,
                       size_t payload_length,
                       authd_login_attempt_t *attempt,
                       char password[AUTHD_PASSWORD_MAX_BUFFER_BYTES],
                       size_t *password_length)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool login_seen = false;
    bool password_seen = false;

    memset(attempt, 0, sizeof(*attempt));
    memset(password, 0, AUTHD_PASSWORD_MAX_BUFFER_BYTES);
    *password_length = 0U;

    status = ftap_tlv_reader_init(&reader, payload, payload_length);
    if (status != FTAP_STATUS_OK) {
        return false;
    }
    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            return false;
        }

        switch (field.type) {
        case FTAP_FIELD_LOGIN_NAME:
            if (!authd_login_name_canonicalize(
                    (const char *)field.value, field.length,
                    attempt->login_name)) {
                return false;
            }
            login_seen = true;
            break;
        case FTAP_FIELD_PASSWORD:
            if ((size_t)field.length > AUTHD_PASSWORD_MAX_BYTES) {
                return false;
            }
            memcpy(password, field.value, field.length);
            *password_length = field.length;
            password_seen = true;
            break;
        case FTAP_FIELD_PROTOCOL:
            if (!copy_field_text(&field, attempt->protocol,
                                 sizeof(attempt->protocol))) {
                return false;
            }
            break;
        case FTAP_FIELD_SOURCE_IP:
            if (!copy_field_text(&field, attempt->source_ip,
                                 sizeof(attempt->source_ip))) {
                return false;
            }
            attempt->source_ip_set = true;
            break;
        case FTAP_FIELD_TTY_DEVICE:
            if (!copy_field_text(&field, attempt->tty_device,
                                 sizeof(attempt->tty_device))) {
                return false;
            }
            attempt->tty_device_set = true;
            break;
        case FTAP_FIELD_NODE_ID:
            if (!copy_field_text(&field, attempt->node_id,
                                 sizeof(attempt->node_id))) {
                return false;
            }
            attempt->node_id_set = true;
            break;
        case FTAP_FIELD_AUTH_METHOD:
            break;
        default:
            return false;
        }
    }

    return login_seen && password_seen && attempt->protocol[0] != '\0';
}

/* Copy the optional protocol reason, otherwise use the normal logout reason. */
static bool
parse_session_close_reason(const uint8_t *payload,
                           size_t payload_length,
                           char reason[FTAP_ENDED_REASON_MAX + 1U])
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;

    (void)snprintf(reason, FTAP_ENDED_REASON_MAX + 1U, "%s",
                   "normal_logout");
    status = ftap_tlv_reader_init(&reader, payload, payload_length);
    if (status != FTAP_STATUS_OK) {
        return false;
    }

    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            return true;
        }
        if (status != FTAP_STATUS_OK ||
            field.type != FTAP_FIELD_ENDED_REASON ||
            !copy_field_text(&field, reason,
                             FTAP_ENDED_REASON_MAX + 1U)) {
            return false;
        }
    }
}

/*
 * SESSION_CLOSE has no response in FTAP 1.2. Close the database lifecycle
 * first, then let the event loop close the bound socket. A transient database
 * failure leaves the reason on the client so client_reset() can retry once.
 */
static int
close_bound_session(authd_client_t *client,
                    const uint8_t *payload,
                    size_t payload_length,
                    authd_server_context_t *context)
{
    char reason[FTAP_ENDED_REASON_MAX + 1U];
    char error[AUTHD_DATABASE_ERROR_MAX];
    authd_database_write_result_t result;

    if (!client->session_open ||
        !parse_session_close_reason(payload, payload_length, reason)) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }

    result = authd_database_close_terminal_session(
        context->database, client->session.session_id, reason,
        error, sizeof(error));
    if (result == AUTHD_DATABASE_WRITE_OK ||
        result == AUTHD_DATABASE_WRITE_NOT_FOUND) {
        client->session_open = false;
        authd_password_wipe(&client->session, sizeof(client->session));
        authd_password_wipe(&client->session_context,
                            sizeof(client->session_context));
    } else {
        (void)snprintf(client->pending_end_reason,
                       sizeof(client->pending_end_reason), "%s", reason);
        (void)fprintf(stderr,
                      "fortytwo-authd: ordered session close failed: %s\n",
                      error[0] != '\0' ? error :
                      authd_database_write_result_name(result));
    }
    authd_password_wipe(reason, sizeof(reason));
    client->state = FTAP_STATE_CLOSING;
    return -1;
}

/*
 * Begin one asynchronous login. Unknown and administratively unavailable
 * accounts use the startup dummy hash, preserving the outer timing and error
 * class while retaining exact internal audit reasons.
 */
static int
start_password_login(authd_client_t *client,
                     const ftap_frame_header_t *header,
                     const uint8_t *payload,
                     size_t payload_length,
                     authd_server_context_t *context)
{
    authd_login_attempt_t attempt;
    authd_database_lookup_result_t lookup_result;
    authd_login_availability_t availability = AUTHD_LOGIN_INVALID_RECORD;
    authd_worker_token_t token;
    authd_worker_submit_result_t submit_result;
    char password[AUTHD_PASSWORD_MAX_BUFFER_BYTES];
    size_t password_length = 0U;
    const char *verification_hash;
    uint64_t job_id = UINT64_C(0);
    char error[AUTHD_DATABASE_ERROR_MAX];

    if (client->login.active || client->state != FTAP_STATE_HELLO_COMPLETE) {
        login_attempt_clear(&client->login);
        client->state = FTAP_STATE_CLOSING;
        return queue_error(client, header->request_id,
                           FTAP_ERR_INVALID_STATE);
    }
    if (!parse_password_request(payload, payload_length, &attempt,
                                password, &password_length)) {
        authd_password_wipe(password, sizeof(password));
        login_attempt_clear(&attempt);
        client->state = FTAP_STATE_CLOSING;
        return queue_error(client, header->request_id, FTAP_ERR_PROTOCOL);
    }
    attempt.request_id = header->request_id;

    lookup_result = authd_database_lookup_login(
        context->database, attempt.login_name, &attempt.record,
        error, sizeof(error));
    if (lookup_result == AUTHD_DATABASE_LOOKUP_ERROR) {
        authd_password_wipe(password, sizeof(password));
        login_attempt_clear(&attempt);
        (void)fprintf(stderr, "fortytwo-authd: login lookup failed: %s\n",
                      error[0] != '\0' ? error : "database error");
        client->state = FTAP_STATE_CLOSING;
        return queue_error(client, header->request_id,
                           FTAP_ERR_DATABASE_UNAVAILABLE);
    }

    if (lookup_result == AUTHD_DATABASE_LOOKUP_OK) {
        attempt.record_loaded = true;
        availability = authd_login_record_availability(&attempt.record);
    }

    /* Temporary account throttling is deliberately explicit in FTAP 1.2. */
    if (lookup_result == AUTHD_DATABASE_LOOKUP_OK &&
        availability == AUTHD_LOGIN_THROTTLED) {
        uint64_t retry_after_ms = attempt.record.retry_after_ms;
        int audit_result;

        authd_password_wipe(password, sizeof(password));
        audit_result = audit_login_rejection(
            context, &attempt, AUTHD_LOGIN_REJECTION_THROTTLED);
        login_attempt_clear(&attempt);
        client->state = FTAP_STATE_CLOSING;
        if (audit_result != 0) {
            return queue_error(client, header->request_id,
                               FTAP_ERR_DATABASE_UNAVAILABLE);
        }
        return queue_error_with_retry(client, header->request_id,
                                      FTAP_ERR_RATE_LIMITED,
                                      retry_after_ms);
    }

    if (lookup_result == AUTHD_DATABASE_LOOKUP_OK &&
        availability == AUTHD_LOGIN_AVAILABLE) {
        verification_hash = attempt.record.password_hash;
    } else {
        verification_hash = context->dummy_password_hash;
        attempt.deferred_rejection = true;
        if (lookup_result == AUTHD_DATABASE_LOOKUP_NOT_FOUND) {
            attempt.rejection_reason = AUTHD_LOGIN_REJECTION_UNKNOWN_USER;
        } else if (lookup_result == AUTHD_DATABASE_LOOKUP_INVALID_RECORD) {
            attempt.rejection_reason = AUTHD_LOGIN_REJECTION_INVALID_RECORD;
        } else {
            attempt.rejection_reason = availability_rejection_reason(
                availability);
        }
    }

    memset(&token, 0, sizeof(token));
    token.connection_id = client->connection_id;
    token.connection_generation = client->connection_generation;
    token.request_id = header->request_id;
    submit_result = authd_worker_pool_submit(
        context->worker_pool, &token, verification_hash,
        password, password_length, sizeof(password), &job_id);
    if (submit_result != AUTHD_WORKER_SUBMIT_OK) {
        int audit_result;

        attempt.record_loaded =
            lookup_result == AUTHD_DATABASE_LOOKUP_OK;
        audit_result = audit_login_rejection(
            context, &attempt, AUTHD_LOGIN_REJECTION_OVERLOADED);
        login_attempt_clear(&attempt);
        client->state = FTAP_STATE_CLOSING;
        if (audit_result != 0) {
            return queue_error(client, header->request_id,
                               FTAP_ERR_DATABASE_UNAVAILABLE);
        }
        return queue_error(client, header->request_id, FTAP_ERR_INTERNAL);
    }

    attempt.active = true;
    attempt.worker_job_id = job_id;
    client->login = attempt;
    login_attempt_clear(&attempt);
    client->state = FTAP_STATE_AUTHENTICATING;
    return 0;
}

static int
complete_password_login(authd_client_t *client,
                        const authd_worker_completion_t *completion,
                        authd_server_context_t *context)
{
    authd_login_attempt_t *attempt = &client->login;
    uint64_t request_id = attempt->request_id;
    char error[AUTHD_DATABASE_ERROR_MAX];

    if (attempt->deferred_rejection) {
        authd_login_rejection_reason_t reason = attempt->rejection_reason;
        int audit_result = audit_login_rejection(context, attempt, reason);

        login_attempt_clear(attempt);
        client->state = FTAP_STATE_CLOSING;
        return audit_result == 0
                   ? queue_error(client, request_id,
                                 FTAP_ERR_INVALID_CREDENTIALS)
                   : queue_error(client, request_id,
                                 FTAP_ERR_DATABASE_UNAVAILABLE);
    }

    if (completion->password_result == AUTHD_PASSWORD_MISMATCH) {
        authd_password_failure_update_t update;
        authd_database_write_result_t result;

        result = authd_database_record_password_failure(
            context->database, attempt->record.user_id,
            &context->throttle_policy, login_source_ip(attempt),
            attempt->protocol, &update, error, sizeof(error));
        login_attempt_clear(attempt);
        client->state = FTAP_STATE_CLOSING;
        if (result != AUTHD_DATABASE_WRITE_OK) {
            (void)fprintf(stderr,
                          "fortytwo-authd: password failure update failed: %s\n",
                          error[0] != '\0' ? error :
                          authd_database_write_result_name(result));
            return queue_error(client, request_id,
                               FTAP_ERR_DATABASE_UNAVAILABLE);
        }
        return queue_error(client, request_id,
                           FTAP_ERR_INVALID_CREDENTIALS);
    }

    if (completion->password_result == AUTHD_PASSWORD_OK) {
        authd_terminal_session_result_t session;
        authd_database_write_result_t result;

        result = authd_database_create_password_session(
            context->database, &attempt->record,
            login_source_ip(attempt), attempt->protocol,
            login_tty_device(attempt), login_node_id(attempt),
            &session, error, sizeof(error));
        if (result == AUTHD_DATABASE_WRITE_OK) {
            client->session = session;
            client->session_open = true;
            (void)snprintf(client->session_context.login_name,
                           sizeof(client->session_context.login_name), "%s",
                           attempt->record.login_name);
            (void)snprintf(client->session_context.display_name,
                           sizeof(client->session_context.display_name), "%s",
                           attempt->record.display_name);
            (void)snprintf(client->session_context.legacy_name,
                           sizeof(client->session_context.legacy_name), "%s",
                           attempt->record.legacy_name);
            (void)snprintf(client->session_context.protocol,
                           sizeof(client->session_context.protocol), "%s",
                           attempt->protocol);
            (void)snprintf(client->session_context.auth_method,
                           sizeof(client->session_context.auth_method), "%s",
                           FTAP_AUTH_METHOD_PASSWORD);
            client->state = FTAP_STATE_SESSION_BOUND;
            if (queue_authentication_result(client, request_id,
                                            attempt, &session) != 0) {
                (void)snprintf(client->pending_end_reason,
                               sizeof(client->pending_end_reason), "%s",
                               "auth_response_failed");
                login_attempt_clear(attempt);
                return -1;
            }
            login_attempt_clear(attempt);
            return 0;
        }

        if (result == AUTHD_DATABASE_WRITE_STALE_STATE) {
            int audit_result = audit_login_rejection(
                context, attempt, AUTHD_LOGIN_REJECTION_STALE_STATE);
            login_attempt_clear(attempt);
            client->state = FTAP_STATE_CLOSING;
            return audit_result == 0
                       ? queue_error(client, request_id,
                                     FTAP_ERR_INVALID_CREDENTIALS)
                       : queue_error(client, request_id,
                                     FTAP_ERR_DATABASE_UNAVAILABLE);
        }

        (void)fprintf(stderr,
                      "fortytwo-authd: password session creation failed: %s\n",
                      error[0] != '\0' ? error :
                      authd_database_write_result_name(result));
        login_attempt_clear(attempt);
        client->state = FTAP_STATE_CLOSING;
        return queue_error(client, request_id,
                           FTAP_ERR_DATABASE_UNAVAILABLE);
    }

    {
        authd_login_rejection_reason_t reason =
            completion->password_result == AUTHD_PASSWORD_INVALID_HASH ||
            completion->password_result == AUTHD_PASSWORD_RESOURCE_LIMIT
                ? AUTHD_LOGIN_REJECTION_INVALID_RECORD
                : AUTHD_LOGIN_REJECTION_INTERNAL_ERROR;
        int audit_result = audit_login_rejection(context, attempt, reason);

        login_attempt_clear(attempt);
        client->state = FTAP_STATE_CLOSING;
        return audit_result == 0
                   ? queue_error(client, request_id, FTAP_ERR_INTERNAL)
                   : queue_error(client, request_id,
                                 FTAP_ERR_DATABASE_UNAVAILABLE);
    }
}

/* Consume every ready completion and bind it only to the exact live job. */
static void
process_worker_completions(authd_client_t *clients,
                           size_t client_count,
                           authd_server_context_t *context)
{
    authd_worker_completion_t completion;

    while (authd_worker_pool_take_completion(context->worker_pool,
                                              &completion)) {
        authd_client_t *client;
        size_t slot;

        if (completion.token.connection_id == 0U ||
            completion.token.connection_id > client_count) {
            continue;
        }
        slot = (size_t)(completion.token.connection_id - UINT64_C(1));
        client = &clients[slot];
        if (client->fd < 0 || !client->login.active ||
            client->connection_generation !=
                completion.token.connection_generation ||
            client->login.request_id != completion.token.request_id ||
            client->login.worker_job_id != completion.job_id) {
            continue;
        }

        if (complete_password_login(client, &completion, context) != 0) {
            client_reset(client, context->database, "auth_response_failed");
        }
    }
}

static int
handle_complete_frame(authd_client_t *client,
                      const ftap_frame_header_t *header,
                      const uint8_t *payload,
                      size_t payload_length,
                      authd_server_context_t *context)
{
    ftap_validation_error_t validation_error;
    ftap_status_t status;

    status = ftap_validate_message(client->state, header,
                                   payload, payload_length,
                                   &validation_error);
    if (status != FTAP_STATUS_OK) {
        if (client->login.active) {
            login_attempt_clear(&client->login);
            client->state = FTAP_STATE_CLOSING;
        }
        return queue_error(client, header->request_id,
                           map_status_to_error(status));
    }

    if (client->state == FTAP_STATE_CONNECTED &&
        header->message_type == FTAP_MSG_HELLO) {
        if (!hello_versions_are_supported(payload, payload_length)) {
            return queue_error(client, header->request_id,
                               FTAP_ERR_UNSUPPORTED_VERSION);
        }
        if (queue_frame(client, FTAP_MSG_HELLO_OK,
                        FTAP_FRAME_FLAG_RESPONSE,
                        header->request_id, NULL, 0U, false) != 0) {
            return -1;
        }
        client->state = FTAP_STATE_HELLO_COMPLETE;
        client->hello_deadline_ms = 0U;
        return 0;
    }

    if (header->message_type == FTAP_MSG_AUTH_PASSWORD_REQUEST) {
        return start_password_login(client, header, payload,
                                    payload_length, context);
    }
    if (header->message_type == FTAP_MSG_SESSION_CONTEXT_REQUEST &&
        client->state == FTAP_STATE_SESSION_BOUND) {
        return queue_session_context_result(client, header->request_id);
    }
    if (header->message_type == FTAP_MSG_SESSION_CLOSE &&
        client->state == FTAP_STATE_SESSION_BOUND) {
        return close_bound_session(client, payload, payload_length, context);
    }

    client->state = FTAP_STATE_CLOSING;
    return queue_error(client, header->request_id, FTAP_ERR_INTERNAL);
}

static void
consume_input(authd_client_t *client, size_t consumed, bool sensitive)
{
    size_t old_used;
    size_t remaining;

    if (client == NULL || consumed > client->input_used) {
        return;
    }

    old_used = client->input_used;
    remaining = old_used - consumed;
    if (sensitive) {
        authd_password_wipe(client->input, consumed);
    }
    if (remaining > 0U) {
        memmove(client->input, client->input + consumed, remaining);
    }
    if (sensitive) {
        authd_password_wipe(client->input + remaining, consumed);
    }
    client->input_used = remaining;
    client->expected_frame_size = 0U;
}

static int
process_client_input(authd_client_t *client,
                     authd_server_context_t *context)
{
    for (;;) {
        ftap_frame_header_t header;
        ftap_status_t status;
        size_t frame_size;

        if (client->output_offset < client->output_length ||
            client->close_after_write) {
            return 0;
        }
        if (client->input_used < FTAP_FRAME_HEADER_SIZE) {
            return 0;
        }

        memset(&header, 0, sizeof(header));
        status = ftap_frame_header_decode(client->input,
                                          client->input_used,
                                          &header);
        if (status != FTAP_STATUS_OK) {
            if (status == FTAP_STATUS_ERR_MAGIC ||
                header.request_id < FTAP_FIRST_CLIENT_REQUEST_ID) {
                return -1;
            }
            if (client->login.active) {
                login_attempt_clear(&client->login);
                client->state = FTAP_STATE_CLOSING;
            }
            if (queue_error(
                    client, header.request_id,
                    status == FTAP_STATUS_ERR_LENGTH
                        ? FTAP_ERR_MESSAGE_TOO_LARGE
                        : map_status_to_error(status)) != 0) {
                return -1;
            }
            return 0;
        }

        frame_size = FTAP_FRAME_HEADER_SIZE + (size_t)header.payload_length;
        client->expected_frame_size = frame_size;
        if (client->input_used < frame_size) {
            return 0;
        }

        if (handle_complete_frame(
                client, &header,
                client->input + FTAP_FRAME_HEADER_SIZE,
                (size_t)header.payload_length, context) != 0) {
            return -1;
        }
        consume_input(client, frame_size,
                      header.message_type == FTAP_MSG_AUTH_PASSWORD_REQUEST);
    }
}

static int
read_client(authd_client_t *client, authd_server_context_t *context)
{
    for (;;) {
        ssize_t received;
        size_t capacity;

        if (client->output_offset < client->output_length ||
            client->close_after_write) {
            return 0;
        }
        if (client->input_used >= FTAP_MAX_FRAME_SIZE) {
            return -1;
        }

        capacity = FTAP_MAX_FRAME_SIZE - client->input_used;
        received = recv(client->fd, client->input + client->input_used,
                        capacity, 0);
        if (received > 0) {
            client->input_used += (size_t)received;
            if (process_client_input(client, context) != 0) {
                return -1;
            }
            if (client->output_offset < client->output_length) {
                return 0;
            }
            continue;
        }
        if (received == 0) {
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

static ssize_t
send_client_bytes(int fd, const uint8_t *buffer, size_t length)
{
#if defined(AUTHD_TESTING)
    const char *fail_auth_result = getenv(
        "FORTYTWO_TEST_FAIL_AUTH_RESULT_SEND");
    if (fail_auth_result != NULL && fail_auth_result[0] != '\0' &&
        length >= FTAP_FRAME_HEADER_SIZE &&
        buffer[FTAP_HEADER_MESSAGE_TYPE_OFFSET] == 0U &&
        buffer[FTAP_HEADER_MESSAGE_TYPE_OFFSET + 1U] ==
            (uint8_t)FTAP_MSG_AUTH_PASSWORD_RESULT) {
        errno = EPIPE;
        return -1;
    }
#endif
    return send(fd, buffer, length, MSG_NOSIGNAL);
}

static int
write_client(authd_client_t *client, authd_server_context_t *context)
{
    while (client->output_offset < client->output_length) {
        ssize_t sent = send_client_bytes(
            client->fd, client->output + client->output_offset,
            client->output_length - client->output_offset);
        if (sent > 0) {
            client->output_offset += (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return -1;
    }

    client->output_length = 0U;
    client->output_offset = 0U;
    if (client->close_after_write) {
        return -1;
    }

    return process_client_input(client, context);
}

static int
accept_clients(int listener,
               authd_client_t *clients,
               size_t client_count,
               const authd_config_t *config,
               uint64_t now_ms)
{
    for (;;) {
        authd_client_t *client;
        authd_peer_credentials_t peer;
        int fd = accept4(listener, NULL, NULL,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }

        if (authd_peer_credentials_read(fd, &peer) != 0) {
            (void)close(fd);
            continue;
        }
        if (!authd_peer_credentials_are_allowed(config, &peer)) {
            log_peer(config, "rejected peer", &peer);
            (void)close(fd);
            continue;
        }

        client = find_free_client(clients, client_count);
        if (client == NULL) {
            log_peer(config, "rejected peer: capacity", &peer);
            (void)close(fd);
            continue;
        }

        client->input = malloc((size_t)FTAP_MAX_FRAME_SIZE);
        if (client->input == NULL) {
            (void)close(fd);
            return -1;
        }
        ++client->connection_generation;
        if (client->connection_generation == UINT64_C(0)) {
            client->connection_generation = UINT64_C(1);
        }
        client->fd = fd;
        client->state = FTAP_STATE_CONNECTED;
        client->peer = peer;
        client->hello_deadline_ms =
            now_ms + (uint64_t)config->hello_timeout_ms;
        log_peer(config, "accepted peer", &peer);
    }
}

static int
compute_poll_timeout(const authd_client_t *clients,
                     size_t client_count,
                     uint64_t now_ms)
{
    uint64_t nearest = UINT64_MAX;
    size_t index;

    for (index = 0U; index < client_count; ++index) {
        if (clients[index].fd >= 0 &&
            clients[index].state == FTAP_STATE_CONNECTED &&
            clients[index].hello_deadline_ms < nearest) {
            nearest = clients[index].hello_deadline_ms;
        }
    }

    if (nearest == UINT64_MAX) {
        return AUTHD_POLL_MAXIMUM_MS;
    }
    if (nearest <= now_ms) {
        return 0;
    }
    if (nearest - now_ms > (uint64_t)AUTHD_POLL_MAXIMUM_MS) {
        return AUTHD_POLL_MAXIMUM_MS;
    }
    return (int)(nearest - now_ms);
}

static void
expire_hello_deadlines(authd_client_t *clients,
                       size_t client_count,
                       uint64_t now_ms,
                       const authd_config_t *config,
                       authd_database_t *database)
{
    size_t index;

    for (index = 0U; index < client_count; ++index) {
        if (clients[index].fd >= 0 &&
            clients[index].state == FTAP_STATE_CONNECTED &&
            clients[index].hello_deadline_ms <= now_ms) {
            log_peer(config, "HELLO timeout", &clients[index].peer);
            client_reset(&clients[index], database, "hello_timeout");
        }
    }
}

static bool
drain_signal_pipe(int fd)
{
    uint8_t buffer[64];
    bool stop = false;

    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        size_t index;

        if (count > 0) {
            for (index = 0U; index < (size_t)count; ++index) {
                if (buffer[index] == (uint8_t)SIGINT ||
                    buffer[index] == (uint8_t)SIGTERM) {
                    stop = true;
                }
            }
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    return stop;
}

static int
random_bytes(void *buffer, size_t size)
{
    uint8_t *position = buffer;
    size_t remaining = size;

#if defined(__linux__)
    while (remaining > 0U) {
        ssize_t count = getrandom(position, remaining, 0);
        if (count > 0) {
            position += (size_t)count;
            remaining -= (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    while (remaining > 0U) {
        ssize_t count = read(fd, position, remaining);
        if (count > 0) {
            position += (size_t)count;
            remaining -= (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        (void)close(fd);
        return -1;
    }
    return close(fd);
#endif
}

/* Prepare one process-local account-independent Argon2id timing target. */
static int
prepare_dummy_password_hash(const authd_password_policy_t *policy,
                            char *encoded_hash,
                            size_t encoded_hash_size)
{
    char random_password[32];
    authd_password_result_t result;

    memset(random_password, 0, sizeof(random_password));
    if (random_bytes(random_password, sizeof(random_password)) != 0) {
        authd_password_wipe(random_password, sizeof(random_password));
        return -1;
    }
    result = authd_password_generate(policy, random_password,
                                     sizeof(random_password),
                                     sizeof(random_password),
                                     encoded_hash, encoded_hash_size);
    return result == AUTHD_PASSWORD_OK ? 0 : -1;
}

static const char *
client_io_end_reason(const authd_client_t *client)
{
    if (client != NULL && client->session_open) {
        if (client->pending_end_reason[0] != '\0') {
            return client->pending_end_reason;
        }
        if (client->state == FTAP_STATE_SESSION_BOUND &&
            client->output_offset < client->output_length &&
            !client->close_after_write) {
            return "auth_response_failed";
        }
        if (client->close_after_write) {
            return "protocol_error";
        }
    }
    return "peer_disconnected";
}

int
authd_server_run(const authd_config_t *config, authd_database_t *database)
{
    authd_server_context_t context;
    authd_password_policy_t password_policy;
    authd_signal_state_t signals;
    authd_socket_identity_t socket_identity;
    authd_client_t *clients = NULL;
    struct pollfd *poll_fds = NULL;
    size_t *poll_slots = NULL;
    int listener = -1;
    int result = -1;
    int failure_errno = 0;
    bool stopping = false;
    uint64_t next_database_health_ms = 0U;
    size_t index;

    errno = 0;
    if (config == NULL || database == NULL ||
        config->max_clients < AUTHD_MIN_CLIENTS ||
        config->max_clients > AUTHD_MAX_CLIENTS ||
        config->password_workers < AUTHD_WORKER_MIN_THREADS ||
        config->password_workers > AUTHD_WORKER_MAX_THREADS ||
        config->password_queue_capacity < AUTHD_WORKER_MIN_CAPACITY ||
        config->password_queue_capacity > AUTHD_WORKER_MAX_CAPACITY ||
        config->db_health_interval_ms < AUTHD_DB_MIN_HEALTH_INTERVAL_MS ||
        config->db_health_interval_ms > AUTHD_DB_MAX_HEALTH_INTERVAL_MS) {
        errno = EINVAL;
        return -1;
    }

    memset(&signals, 0, sizeof(signals));
    signals.read_fd = -1;
    signals.write_fd = -1;
    memset(&socket_identity, 0, sizeof(socket_identity));
    memset(&context, 0, sizeof(context));
    context.database = database;
    context.throttle_policy.failure_threshold =
        config->password_failure_threshold;
    context.throttle_policy.failure_window_seconds =
        config->password_failure_window_seconds;
    context.throttle_policy.throttle_seconds =
        config->password_throttle_seconds;
    if (!authd_throttle_policy_is_valid(&context.throttle_policy)) {
        failure_errno = EINVAL;
        goto cleanup;
    }

    authd_password_policy_defaults(&password_policy);
    if (!authd_password_policy_is_valid(&password_policy) ||
        prepare_dummy_password_hash(&password_policy,
                                    context.dummy_password_hash,
                                    sizeof(context.dummy_password_hash)) != 0) {
        failure_errno = EIO;
        goto cleanup;
    }
    {
        char worker_error[AUTHD_WORKER_ERROR_MAX];
        if (authd_worker_pool_create(&password_policy,
                                     config->password_workers,
                                     config->password_queue_capacity,
                                     &context.worker_pool,
                                     worker_error,
                                     sizeof(worker_error)) != 0) {
            (void)fprintf(stderr,
                          "fortytwo-authd: worker pool startup failed: %s\n",
                          worker_error);
            failure_errno = EIO;
            goto cleanup;
        }
    }

    clients = calloc(config->max_clients, sizeof(*clients));
    if (clients == NULL) {
        failure_errno = errno != 0 ? errno : ENOMEM;
        goto cleanup;
    }
    client_array_initialize(clients, config->max_clients);

    poll_fds = calloc(config->max_clients + 3U, sizeof(*poll_fds));
    poll_slots = calloc(config->max_clients + 3U, sizeof(*poll_slots));
    if (poll_fds == NULL || poll_slots == NULL) {
        failure_errno = errno != 0 ? errno : ENOMEM;
        goto cleanup;
    }

    if (signal_state_install(&signals) != 0) {
        failure_errno = errno != 0 ? errno : EIO;
        goto cleanup;
    }
    listener = create_listener(config, &socket_identity);
    if (listener < 0) {
        failure_errno = errno != 0 ? errno : EIO;
        goto cleanup;
    }

    if (monotonic_milliseconds(&next_database_health_ms) != 0) {
        failure_errno = errno != 0 ? errno : EIO;
        goto cleanup;
    }
    if (UINT64_MAX - next_database_health_ms <
        (uint64_t)config->db_health_interval_ms) {
        failure_errno = EOVERFLOW;
        goto cleanup;
    }
    next_database_health_ms += (uint64_t)config->db_health_interval_ms;

    (void)fprintf(stderr, "fortytwo-authd: listening on %s\n",
                  config->socket_path);

    while (!stopping) {
        uint64_t now_ms;
        size_t poll_count = 0U;
        int timeout;
        int poll_result;

        if (monotonic_milliseconds(&now_ms) != 0) {
            failure_errno = errno != 0 ? errno : EIO;
            goto cleanup;
        }
        if (now_ms >= next_database_health_ms) {
            char database_error[AUTHD_DATABASE_ERROR_MAX];
            if (authd_database_health_check(database,
                                            database_error,
                                            sizeof(database_error)) != 0) {
                (void)fprintf(stderr,
                              "fortytwo-authd: database unavailable: %s\n",
                              database_error);
                failure_errno = EIO;
                goto cleanup;
            }
            if (UINT64_MAX - now_ms <
                (uint64_t)config->db_health_interval_ms) {
                failure_errno = EOVERFLOW;
                goto cleanup;
            }
            next_database_health_ms =
                now_ms + (uint64_t)config->db_health_interval_ms;
        }
        expire_hello_deadlines(clients, config->max_clients,
                               now_ms, config, database);

        poll_fds[poll_count].fd = signals.read_fd;
        poll_fds[poll_count].events = POLLIN;
        poll_slots[poll_count] = SIZE_MAX;
        ++poll_count;

        poll_fds[poll_count].fd = listener;
        poll_fds[poll_count].events = POLLIN;
        poll_slots[poll_count] = SIZE_MAX - 1U;
        ++poll_count;

        poll_fds[poll_count].fd =
            authd_worker_pool_completion_fd(context.worker_pool);
        poll_fds[poll_count].events = POLLIN;
        poll_slots[poll_count] = SIZE_MAX - 2U;
        ++poll_count;

        for (index = 0U; index < config->max_clients; ++index) {
            short events = 0;
            if (clients[index].fd < 0) {
                continue;
            }
            if (clients[index].output_offset < clients[index].output_length) {
                events |= POLLOUT;
            } else if (!clients[index].close_after_write) {
                events |= POLLIN;
            }
            poll_fds[poll_count].fd = clients[index].fd;
            poll_fds[poll_count].events = events;
            poll_slots[poll_count] = index;
            ++poll_count;
        }

        timeout = compute_poll_timeout(clients, config->max_clients, now_ms);
        if (next_database_health_ms <= now_ms) {
            timeout = 0;
        } else if (next_database_health_ms - now_ms < (uint64_t)timeout) {
            timeout = (int)(next_database_health_ms - now_ms);
        }
        poll_result = poll(poll_fds, (nfds_t)poll_count, timeout);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            failure_errno = errno != 0 ? errno : EIO;
            goto cleanup;
        }

        if ((poll_fds[0].revents & POLLIN) != 0 &&
            drain_signal_pipe(signals.read_fd)) {
            stopping = true;
        }
        if (stopping) {
            break;
        }

        if ((poll_fds[1].revents & POLLIN) != 0) {
            if (monotonic_milliseconds(&now_ms) != 0) {
                failure_errno = EIO;
                goto cleanup;
            }
            if (accept_clients(listener, clients, config->max_clients,
                               config, now_ms) != 0) {
                failure_errno = EIO;
                goto cleanup;
            }
        }
        if ((poll_fds[1].revents & (POLLERR | POLLNVAL)) != 0) {
            failure_errno = EIO;
            goto cleanup;
        }

        if ((poll_fds[2].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            failure_errno = EIO;
            goto cleanup;
        }

        for (index = 3U; index < poll_count; ++index) {
            size_t slot = poll_slots[index];
            short revents = poll_fds[index].revents;
            authd_client_t *client;

            if (slot >= config->max_clients || revents == 0) {
                continue;
            }
            client = &clients[slot];
            if (client->fd < 0 || client->fd != poll_fds[index].fd) {
                continue;
            }

            if ((revents & POLLOUT) != 0 &&
                write_client(client, &context) != 0) {
                const char *reason = client_io_end_reason(client);
                client_reset(client, database, reason);
                continue;
            }
            if (client->fd >= 0 && (revents & POLLIN) != 0 &&
                read_client(client, &context) != 0) {
                const char *reason = client_io_end_reason(client);
                client_reset(client, database, reason);
                continue;
            }
            if (client->fd >= 0 &&
                (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                const char *reason = client_io_end_reason(client);
                client_reset(client, database, reason);
            }
        }


        /* Socket close/error events win over stale worker completions. */
        if ((poll_fds[2].revents & POLLIN) != 0) {
            process_worker_completions(clients, config->max_clients,
                                       &context);
        }
    }

    result = 0;

cleanup:
    if (result != 0) {
        if (failure_errno == 0) {
            failure_errno = EIO;
        }
        (void)fprintf(stderr, "fortytwo-authd: %s\n",
                      strerror(failure_errno));
    }
    if (clients != NULL) {
        for (index = 0U; index < config->max_clients; ++index) {
            client_reset(&clients[index], database,
                         result == 0 ? "authd_shutdown" : "authd_failure");
        }
    }
    authd_worker_pool_destroy(context.worker_pool);
    context.worker_pool = NULL;
    authd_password_wipe(context.dummy_password_hash,
                        sizeof(context.dummy_password_hash));
    if (listener >= 0) {
        (void)close(listener);
    }
    remove_listener_path(config != NULL ? config->socket_path : NULL,
                         &socket_identity);
    signal_state_restore(&signals);
    free(poll_slots);
    free(poll_fds);
    free(clients);
    return result;
}
