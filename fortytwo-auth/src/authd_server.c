/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Phase B2 server: secure local listener, peer checks, database health,
 * partial-frame I/O,
 * HELLO/HELLO_OK, HELLO timeout and controlled shutdown.
 */

#include "authd_server.h"

#include "authd_peer.h"
#include "authd_database.h"
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
#include <time.h>
#include <unistd.h>

#define AUTHD_RESPONSE_BUFFER_SIZE 512U
#define AUTHD_POLL_MAXIMUM_MS 1000

typedef struct authd_socket_identity {
    dev_t device;
    ino_t inode;
    bool valid;
} authd_socket_identity_t;

typedef struct authd_client {
    int fd;
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
} authd_client_t;

typedef struct authd_signal_state {
    int read_fd;
    int write_fd;
    struct sigaction old_sigint;
    struct sigaction old_sigterm;
    struct sigaction old_sigpipe;
    bool installed;
} authd_signal_state_t;

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
client_reset(authd_client_t *client)
{
    if (client == NULL) {
        return;
    }

    if (client->fd >= 0) {
        (void)close(client->fd);
    }
    free(client->input);
    memset(client, 0, sizeof(*client));
    client->fd = -1;
}

static void
client_array_initialize(authd_client_t *clients, size_t count)
{
    size_t index;

    for (index = 0U; index < count; ++index) {
        memset(&clients[index], 0, sizeof(clients[index]));
        clients[index].fd = -1;
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
    case FTAP_ERR_INTERNAL:
        return "operation is not implemented in authd phase B1";
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
queue_error(authd_client_t *client,
            uint64_t request_id,
            uint32_t error_code)
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

static int
handle_complete_frame(authd_client_t *client,
                      const ftap_frame_header_t *header,
                      const uint8_t *payload,
                      size_t payload_length)
{
    ftap_validation_error_t validation_error;
    ftap_status_t status;

    status = ftap_validate_message(client->state, header,
                                   payload, payload_length,
                                   &validation_error);
    if (status != FTAP_STATUS_OK) {
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

    return queue_error(client, header->request_id, FTAP_ERR_INTERNAL);
}

static void
consume_input(authd_client_t *client, size_t consumed)
{
    size_t remaining;

    if (client == NULL || consumed > client->input_used) {
        return;
    }

    remaining = client->input_used - consumed;
    if (remaining > 0U) {
        memmove(client->input, client->input + consumed, remaining);
    }
    client->input_used = remaining;
    client->expected_frame_size = 0U;
}

static int
process_client_input(authd_client_t *client)
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
                (size_t)header.payload_length) != 0) {
            return -1;
        }
        consume_input(client, frame_size);
    }
}

static int
read_client(authd_client_t *client)
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
            if (process_client_input(client) != 0) {
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

static int
write_client(authd_client_t *client)
{
    while (client->output_offset < client->output_length) {
        ssize_t sent = send(client->fd,
                            client->output + client->output_offset,
                            client->output_length - client->output_offset,
                            MSG_NOSIGNAL);
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

    return process_client_input(client);
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
                       const authd_config_t *config)
{
    size_t index;

    for (index = 0U; index < client_count; ++index) {
        if (clients[index].fd >= 0 &&
            clients[index].state == FTAP_STATE_CONNECTED &&
            clients[index].hello_deadline_ms <= now_ms) {
            log_peer(config, "HELLO timeout", &clients[index].peer);
            client_reset(&clients[index]);
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

int
authd_server_run(const authd_config_t *config, authd_database_t *database)
{
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
        config->db_health_interval_ms < AUTHD_DB_MIN_HEALTH_INTERVAL_MS ||
        config->db_health_interval_ms > AUTHD_DB_MAX_HEALTH_INTERVAL_MS) {
        errno = EINVAL;
        return -1;
    }

    memset(&signals, 0, sizeof(signals));
    signals.read_fd = -1;
    signals.write_fd = -1;
    memset(&socket_identity, 0, sizeof(socket_identity));

    clients = calloc(config->max_clients, sizeof(*clients));
    if (clients == NULL) {
        failure_errno = errno != 0 ? errno : ENOMEM;
        goto cleanup;
    }
    client_array_initialize(clients, config->max_clients);

    poll_fds = calloc(config->max_clients + 2U, sizeof(*poll_fds));
    poll_slots = calloc(config->max_clients + 2U, sizeof(*poll_slots));
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
                               now_ms, config);

        poll_fds[poll_count].fd = signals.read_fd;
        poll_fds[poll_count].events = POLLIN;
        poll_slots[poll_count] = SIZE_MAX;
        ++poll_count;

        poll_fds[poll_count].fd = listener;
        poll_fds[poll_count].events = POLLIN;
        poll_slots[poll_count] = SIZE_MAX - 1U;
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

        for (index = 2U; index < poll_count; ++index) {
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

            if ((revents & POLLOUT) != 0 && write_client(client) != 0) {
                client_reset(client);
                continue;
            }
            if (client->fd >= 0 && (revents & POLLIN) != 0 &&
                read_client(client) != 0) {
                client_reset(client);
                continue;
            }
            if (client->fd >= 0 &&
                (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                client_reset(client);
            }
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
            client_reset(&clients[index]);
        }
    }
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
