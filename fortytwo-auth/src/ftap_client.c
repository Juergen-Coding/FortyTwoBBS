/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ftap_client.h"
#include "ftap_schema.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define FTAP_CLIENT_RESPONSE_SIZE FTAP_MAX_FRAME_SIZE

typedef struct ftap_received_frame {
    ftap_frame_header_t header;
    uint8_t payload[FTAP_MAX_PAYLOAD_SIZE];
    size_t payload_length;
} ftap_received_frame_t;

static void
secure_wipe(void *memory, size_t length)
{
    volatile unsigned char *bytes = memory;

    while (length > 0U) {
        *bytes++ = 0U;
        --length;
    }
}

static int
monotonic_milliseconds(uint64_t *milliseconds)
{
    struct timespec now;

    if (milliseconds == NULL ||
        clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    *milliseconds = ((uint64_t)now.tv_sec * UINT64_C(1000)) +
                    ((uint64_t)now.tv_nsec / UINT64_C(1000000));
    return 0;
}


/* One absolute deadline bounds all partial reads or writes of one FTAP step. */
static int
deadline_after(uint32_t timeout_ms, uint64_t *deadline_ms)
{
    uint64_t now;

    if (deadline_ms == NULL || monotonic_milliseconds(&now) != 0) {
        return -1;
    }
    *deadline_ms = now > UINT64_MAX - (uint64_t)timeout_ms
                       ? UINT64_MAX
                       : now + (uint64_t)timeout_ms;
    return 0;
}

void
ftap_client_error_clear(ftap_client_error_t *error)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->status = FTAP_STATUS_OK;
    }
}

static void
set_local_error(ftap_client_error_t *error,
                ftap_status_t status,
                int system_errno,
                const char *text)
{
    if (error == NULL) {
        return;
    }

    ftap_client_error_clear(error);
    error->status = status;
    error->system_errno = system_errno;
    if (text != NULL) {
        (void)snprintf(error->text, sizeof(error->text), "%s", text);
    }
}

void
ftap_client_init(ftap_client_t *client, uint32_t timeout_ms)
{
    if (client == NULL) {
        return;
    }

    memset(client, 0, sizeof(*client));
    client->fd = -1;
    client->state = FTAP_STATE_CONNECTED;
    client->next_request_id = FTAP_FIRST_CLIENT_REQUEST_ID;
    client->timeout_ms = timeout_ms == 0U
                             ? FTAP_CLIENT_DEFAULT_TIMEOUT_MS
                             : timeout_ms;
}

static int
remaining_timeout(uint64_t deadline_ms)
{
    uint64_t now;
    uint64_t remaining;

    if (monotonic_milliseconds(&now) != 0) {
        return -1;
    }
    if (now >= deadline_ms) {
        return 0;
    }
    remaining = deadline_ms - now;
    return remaining > (uint64_t)INT32_MAX
               ? INT32_MAX
               : (int)remaining;
}

static int
wait_for_socket(int fd, short events, uint64_t deadline_ms)
{
    struct pollfd descriptor;

    for (;;) {
        int timeout = remaining_timeout(deadline_ms);
        int result;

        if (timeout < 0) {
            return -1;
        }
        if (timeout == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        descriptor.fd = fd;
        descriptor.events = events;
        descriptor.revents = 0;
        result = poll(&descriptor, 1, timeout);
        if (result > 0) {
            if ((descriptor.revents & POLLNVAL) != 0) {
                errno = EBADF;
                return -1;
            }
            if ((descriptor.revents & events) != 0 ||
                (descriptor.revents & (POLLHUP | POLLERR)) != 0) {
                return 0;
            }
            continue;
        }
        if (result == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
}

static int
send_all(int fd, const uint8_t *buffer, size_t length, uint64_t deadline_ms)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t sent;

        if (wait_for_socket(fd, POLLOUT, deadline_ms) != 0) {
            return -1;
        }
        sent = send(fd, buffer + offset, length - offset, MSG_NOSIGNAL);
        if (sent > 0) {
            offset += (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (sent == 0) {
            errno = EPIPE;
        }
        return -1;
    }

    return 0;
}

static int
receive_exact(int fd, uint8_t *buffer, size_t length, uint64_t deadline_ms)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t received;

        if (wait_for_socket(fd, POLLIN, deadline_ms) != 0) {
            return -1;
        }
        received = recv(fd, buffer + offset, length - offset, 0);
        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (received == 0) {
            errno = ECONNRESET;
        }
        return -1;
    }

    return 0;
}

static int
receive_frame(ftap_client_t *client,
              ftap_received_frame_t *frame,
              uint64_t deadline_ms,
              ftap_client_error_t *error)
{
    uint8_t header_bytes[FTAP_FRAME_HEADER_SIZE];
    ftap_validation_error_t validation_error;
    ftap_status_t status;

    memset(frame, 0, sizeof(*frame));
    if (receive_exact(client->fd, header_bytes, sizeof(header_bytes),
                      deadline_ms) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, errno,
                        "cannot read FTAP frame header");
        return -1;
    }

    status = ftap_frame_header_decode(header_bytes, sizeof(header_bytes),
                                      &frame->header);
    if (status != FTAP_STATUS_OK ||
        frame->header.payload_length > FTAP_MAX_PAYLOAD_SIZE) {
        set_local_error(error, status == FTAP_STATUS_OK
                                   ? FTAP_STATUS_ERR_LENGTH
                                   : status,
                        EPROTO, "invalid FTAP frame header");
        return -1;
    }

    frame->payload_length = (size_t)frame->header.payload_length;
    if (frame->payload_length > 0U &&
        receive_exact(client->fd, frame->payload, frame->payload_length,
                      deadline_ms) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, errno,
                        "cannot read FTAP frame payload");
        return -1;
    }

    status = ftap_validate_message(client->state, &frame->header,
                                   frame->payload, frame->payload_length,
                                   &validation_error);
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EPROTO, "invalid FTAP response");
        return -1;
    }
    return 0;
}

static int
send_frame(ftap_client_t *client,
           uint16_t message_type,
           uint64_t request_id,
           const uint8_t *payload,
           size_t payload_length,
           ftap_client_error_t *error)
{
    uint8_t frame[FTAP_CLIENT_RESPONSE_SIZE];
    ftap_frame_header_t header;
    ftap_status_t status;
    uint64_t deadline_ms;

    if (client == NULL || client->fd < 0 ||
        (payload == NULL && payload_length != 0U) ||
        payload_length > FTAP_MAX_PAYLOAD_SIZE) {
        set_local_error(error, FTAP_STATUS_ERR_ARGUMENT, EINVAL,
                        "invalid FTAP client argument");
        return -1;
    }

    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = message_type;
    header.payload_length = (uint32_t)payload_length;
    header.request_id = request_id;
    status = ftap_frame_header_encode(frame, &header);
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EPROTO, "cannot encode FTAP frame");
        return -1;
    }
    if (payload_length > 0U) {
        memcpy(frame + FTAP_FRAME_HEADER_SIZE, payload, payload_length);
    }

    if (deadline_after(client->timeout_ms, &deadline_ms) != 0) {
        int saved_errno = errno;
        secure_wipe(frame, sizeof(frame));
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, saved_errno,
                        "cannot read monotonic clock");
        return -1;
    }
    if (send_all(client->fd, frame,
                 FTAP_FRAME_HEADER_SIZE + payload_length,
                 deadline_ms) != 0) {
        int saved_errno = errno;
        secure_wipe(frame, sizeof(frame));
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, saved_errno,
                        "cannot send FTAP frame");
        return -1;
    }
    secure_wipe(frame, sizeof(frame));
    return 0;
}

static bool
copy_text_field(const ftap_tlv_t *field, char *output, size_t output_size)
{
    if (field == NULL || output == NULL || output_size == 0U ||
        (size_t)field->length >= output_size) {
        return false;
    }
    memcpy(output, field->value, field->length);
    output[field->length] = '\0';
    return true;
}

static int
parse_error_frame(const ftap_received_frame_t *frame,
                  ftap_client_error_t *error)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;

    ftap_client_error_clear(error);
    if (error != NULL) {
        error->status = FTAP_STATUS_ERR_INVALID_VALUE;
        error->server_error = true;
    }
    status = ftap_tlv_reader_init(&reader, frame->payload,
                                  frame->payload_length);
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EPROTO, "invalid FTAP error payload");
        return -1;
    }

    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP error field");
            return -1;
        }
        if (error == NULL) {
            continue;
        }
        if (field.type == FTAP_FIELD_ERROR_CODE) {
            if (ftap_tlv_get_u32(&field, &error->protocol_error) !=
                FTAP_STATUS_OK) {
                set_local_error(error, FTAP_STATUS_ERR_INVALID_VALUE,
                                EPROTO, "invalid FTAP error code");
                return -1;
            }
        } else if (field.type == FTAP_FIELD_RETRY_AFTER_MS) {
            if (ftap_tlv_get_u32(&field, &error->retry_after_ms) !=
                FTAP_STATUS_OK) {
                set_local_error(error, FTAP_STATUS_ERR_INVALID_VALUE,
                                EPROTO, "invalid FTAP retry interval");
                return -1;
            }
        } else if (field.type == FTAP_FIELD_ERROR_TEXT) {
            if (!copy_text_field(&field, error->text,
                                 sizeof(error->text))) {
                set_local_error(error, FTAP_STATUS_ERR_LENGTH, EPROTO,
                                "invalid FTAP error text");
                return -1;
            }
        }
    }

    return -1;
}


/* Consume relevant server pushes without accepting a response for another request. */
static int
wait_for_response(ftap_client_t *client,
                  uint16_t expected_message_type,
                  uint64_t request_id,
                  ftap_received_frame_t *response,
                  ftap_client_error_t *error)
{
    uint64_t deadline_ms;

    if (deadline_after(client->timeout_ms, &deadline_ms) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, errno,
                        "cannot read monotonic clock");
        return -1;
    }

    for (;;) {
        if (receive_frame(client, response, deadline_ms, error) != 0) {
            return -1;
        }

        if ((response->header.flags & FTAP_FRAME_FLAG_SERVER_PUSH) != 0U) {
            if (response->header.message_type == FTAP_MSG_SESSION_REVOKED) {
                set_local_error(error, FTAP_STATUS_ERR_INVALID_STATE,
                                EACCES, "FTAP session was revoked");
                if (error != NULL) {
                    error->protocol_error = FTAP_ERR_SESSION_REVOKED;
                }
                client->state = FTAP_STATE_CLOSING;
                return -1;
            }
            if (response->header.message_type ==
                FTAP_MSG_SESSION_AUTHZ_CHANGED) {
                continue;
            }
            set_local_error(error, FTAP_STATUS_ERR_INVALID_MESSAGE,
                            EPROTO, "unexpected FTAP server push");
            return -1;
        }

        if (response->header.request_id != request_id) {
            set_local_error(error, FTAP_STATUS_ERR_REQUEST_ID, EPROTO,
                            "unexpected FTAP response request ID");
            return -1;
        }
        if (response->header.message_type == FTAP_MSG_ERROR) {
            return parse_error_frame(response, error);
        }
        if (response->header.message_type != expected_message_type) {
            set_local_error(error, FTAP_STATUS_ERR_INVALID_MESSAGE,
                            EPROTO, "unexpected FTAP response type");
            return -1;
        }
        return 0;
    }
}

static uint64_t
next_request_id(ftap_client_t *client)
{
    uint64_t request_id = client->next_request_id;

    client->next_request_id++;
    if (client->next_request_id < FTAP_FIRST_CLIENT_REQUEST_ID) {
        client->next_request_id = FTAP_FIRST_CLIENT_REQUEST_ID;
    }
    return request_id;
}

int
ftap_client_connect(ftap_client_t *client,
                    const char *socket_path,
                    ftap_client_error_t *error)
{
    struct sockaddr_un address;
    uint64_t deadline_ms;
    int fd;
    int connect_error = 0;
    socklen_t connect_error_length = (socklen_t)sizeof(connect_error);

    if (client == NULL || client->fd >= 0 ||
        socket_path == NULL || socket_path[0] != '/' ||
        strlen(socket_path) >= sizeof(address.sun_path)) {
        set_local_error(error, FTAP_STATUS_ERR_ARGUMENT, EINVAL,
                        "invalid FTAP socket path");
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, errno,
                        "cannot create FTAP socket");
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                   socket_path);
    if (connect(fd, (const struct sockaddr *)&address,
                (socklen_t)sizeof(address)) != 0) {
        if (errno != EINPROGRESS ||
            deadline_after(client->timeout_ms, &deadline_ms) != 0 ||
            wait_for_socket(fd, POLLOUT, deadline_ms) != 0 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &connect_error,
                       &connect_error_length) != 0 ||
            connect_error != 0) {
            int saved_errno = connect_error != 0 ? connect_error : errno;
            (void)close(fd);
            set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, saved_errno,
                            "cannot connect to fortytwo-authd");
            return -1;
        }
    }

    client->fd = fd;
    client->state = FTAP_STATE_CONNECTED;
    client->next_request_id = FTAP_FIRST_CLIENT_REQUEST_ID;
    ftap_client_error_clear(error);
    return 0;
}

/* Adopt only the already-authenticated stream inherited from fortytwo-login. */
int
ftap_client_adopt_bound_fd(ftap_client_t *client,
                           int fd,
                           uint32_t timeout_ms,
                           ftap_client_error_t *error)
{
    int socket_type;
    int descriptor_flags;
    socklen_t socket_type_length = (socklen_t)sizeof(socket_type);

    if (client == NULL || client->fd >= 0 || fd < 0) {
        set_local_error(error, FTAP_STATUS_ERR_ARGUMENT, EINVAL,
                        "invalid inherited FTAP descriptor");
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type,
                   &socket_type_length) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_ARGUMENT, errno,
                        "inherited FTAP descriptor is not a socket");
        return -1;
    }
    if (socket_type != SOCK_STREAM) {
        set_local_error(error, FTAP_STATUS_ERR_ARGUMENT, ENOTSOCK,
                        "inherited FTAP descriptor is not a stream socket");
        return -1;
    }
    descriptor_flags = fcntl(fd, F_GETFL, 0);
    if (descriptor_flags < 0 ||
        fcntl(fd, F_SETFL, descriptor_flags | O_NONBLOCK) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, errno,
                        "cannot make inherited FTAP descriptor nonblocking");
        return -1;
    }

    ftap_client_init(client, timeout_ms);
    client->fd = fd;
    client->state = FTAP_STATE_SESSION_BOUND;
    ftap_client_error_clear(error);
    return 0;
}

int
ftap_client_hello(ftap_client_t *client,
                  const char *client_name,
                  const char *client_version,
                  ftap_client_error_t *error)
{
    uint8_t payload[256];
    ftap_tlv_writer_t writer;
    ftap_received_frame_t response;
    ftap_status_t status;
    uint64_t request_id;

    if (client == NULL || client->state != FTAP_STATE_CONNECTED ||
        client_name == NULL || client_version == NULL) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_STATE, EINVAL,
                        "FTAP HELLO is not allowed now");
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_CLIENT_NAME, 0,
            (const uint8_t *)client_name, strlen(client_name),
            FTAP_CLIENT_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_CLIENT_VERSION, 0,
            (const uint8_t *)client_version, strlen(client_version),
            FTAP_CLIENT_VERSION_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_u16(
            &writer, FTAP_FIELD_SUPPORTED_MAJOR, 0, FTAP_VERSION_MAJOR);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_u16(
            &writer, FTAP_FIELD_SUPPORTED_MINOR, 0, FTAP_VERSION_MINOR);
    }
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EINVAL, "cannot build FTAP HELLO");
        return -1;
    }

    request_id = next_request_id(client);
    if (send_frame(client, FTAP_MSG_HELLO, request_id,
                   payload, writer.length, error) != 0 ||
        wait_for_response(client, FTAP_MSG_HELLO_OK, request_id,
                          &response, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }

    client->state = FTAP_STATE_HELLO_COMPLETE;
    ftap_client_error_clear(error);
    return 0;
}


/* Decode identity only after the schema has proved every mandatory field. */
static int
parse_terminal_context(const ftap_received_frame_t *frame,
                       bool include_transport,
                       ftap_terminal_context_t *context,
                       ftap_client_error_t *error)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;

    memset(context, 0, sizeof(*context));
    status = ftap_tlv_reader_init(&reader, frame->payload,
                                  frame->payload_length);
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EPROTO,
                        "invalid FTAP session context");
        return -1;
    }

    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP session context field");
            return -1;
        }
        switch (field.type) {
        case FTAP_FIELD_USER_ID:
            status = ftap_tlv_get_uuid(&field, context->user_id);
            break;
        case FTAP_FIELD_SESSION_ID:
            status = ftap_tlv_get_uuid(&field, context->session_id);
            break;
        case FTAP_FIELD_LOGIN_NAME:
            status = copy_text_field(&field, context->login_name,
                                     sizeof(context->login_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            break;
        case FTAP_FIELD_DISPLAY_NAME:
            status = copy_text_field(&field, context->display_name,
                                     sizeof(context->display_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            break;
        case FTAP_FIELD_LEGACY_NAME:
            status = copy_text_field(&field, context->legacy_name,
                                     sizeof(context->legacy_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            break;
        case FTAP_FIELD_PROTOCOL:
            status = include_transport &&
                     copy_text_field(&field, context->protocol,
                                     sizeof(context->protocol))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_INVALID_MESSAGE;
            break;
        case FTAP_FIELD_AUTH_METHOD:
            status = include_transport &&
                     copy_text_field(&field, context->auth_method,
                                     sizeof(context->auth_method))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_INVALID_MESSAGE;
            break;
        case FTAP_FIELD_AUTH_EPOCH:
            status = ftap_tlv_get_u64(&field, &context->auth_epoch);
            break;
        case FTAP_FIELD_AUTHZ_REVISION:
            status = ftap_tlv_get_u64(&field, &context->authz_revision);
            break;
        case FTAP_FIELD_CAPABILITY:
            status = FTAP_STATUS_OK;
            break;
        default:
            status = FTAP_STATUS_ERR_INVALID_MESSAGE;
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP session context value");
            memset(context, 0, sizeof(*context));
            return -1;
        }
    }
    return 0;
}

int
ftap_client_authenticate_password(
    ftap_client_t *client,
    const char *login_name,
    const uint8_t *password,
    size_t password_length,
    const ftap_password_metadata_t *metadata,
    ftap_terminal_context_t *result,
    ftap_client_error_t *error)
{
    uint8_t payload[FTAP_MAX_PAYLOAD_SIZE];
    ftap_tlv_writer_t writer;
    ftap_received_frame_t response;
    ftap_status_t status;
    uint64_t request_id;

    if (client == NULL || client->state != FTAP_STATE_HELLO_COMPLETE ||
        login_name == NULL || password == NULL || password_length == 0U ||
        metadata == NULL || metadata->protocol == NULL || result == NULL) {
        set_local_error(error, FTAP_STATUS_ERR_ARGUMENT, EINVAL,
                        "invalid password-login argument");
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_LOGIN_NAME, 0,
            (const uint8_t *)login_name, strlen(login_name),
            FTAP_LOGIN_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_PASSWORD, 0, password, password_length,
            FTAP_PASSWORD_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_PROTOCOL, 0,
            (const uint8_t *)metadata->protocol, strlen(metadata->protocol),
            FTAP_PROTOCOL_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK && metadata->source_ip != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_SOURCE_IP, 0,
            (const uint8_t *)metadata->source_ip, strlen(metadata->source_ip),
            FTAP_IP_ADDRESS_MAX);
    }
    if (status == FTAP_STATUS_OK && metadata->tty_device != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_TTY_DEVICE, 0,
            (const uint8_t *)metadata->tty_device,
            strlen(metadata->tty_device), FTAP_TTY_DEVICE_MAX);
    }
    if (status == FTAP_STATUS_OK && metadata->node_id != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_NODE_ID, 0,
            (const uint8_t *)metadata->node_id, strlen(metadata->node_id),
            FTAP_NODE_ID_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_AUTH_METHOD, 0,
            (const uint8_t *)FTAP_AUTH_METHOD_PASSWORD,
            strlen(FTAP_AUTH_METHOD_PASSWORD), FTAP_AUTH_METHOD_MAX);
    }
    if (status != FTAP_STATUS_OK) {
        secure_wipe(payload, sizeof(payload));
        set_local_error(error, status, EINVAL,
                        "cannot build FTAP password request");
        return -1;
    }

    request_id = next_request_id(client);
    if (send_frame(client, FTAP_MSG_AUTH_PASSWORD_REQUEST, request_id,
                   payload, writer.length, error) != 0) {
        secure_wipe(payload, sizeof(payload));
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    secure_wipe(payload, sizeof(payload));
    client->state = FTAP_STATE_AUTHENTICATING;
    if (wait_for_response(client, FTAP_MSG_AUTH_PASSWORD_RESULT, request_id,
                          &response, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    if (parse_terminal_context(&response, false, result, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }

    client->state = FTAP_STATE_SESSION_BOUND;
    ftap_client_error_clear(error);
    return 0;
}


static bool
field_text_equals(const ftap_tlv_t *field, const char *expected)
{
    size_t expected_length;

    if (field == NULL || expected == NULL) {
        return false;
    }
    expected_length = strlen(expected);
    return (size_t)field->length == expected_length &&
           memcmp(field->value, expected, expected_length) == 0;
}

static void
mark_outcome_unknown(ftap_client_error_t *error)
{
    if (error != NULL && !error->server_error) {
        error->outcome_unknown = true;
    }
}

/* Decode and retain the exact pending identity returned by Begin. */
static int
parse_registration_begin_context(
    const ftap_received_frame_t *frame,
    ftap_registration_context_t *registration,
    ftap_client_error_t *error)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool seen[7] = {false};
    size_t index;

    memset(registration, 0, sizeof(*registration));
    status = ftap_tlv_reader_init(&reader, frame->payload,
                                  frame->payload_length);
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EPROTO,
                        "invalid FTAP registration begin result");
        return -1;
    }

    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP registration begin field");
            memset(registration, 0, sizeof(*registration));
            return -1;
        }
        switch (field.type) {
        case FTAP_FIELD_REGISTRATION_ID:
            status = ftap_tlv_get_uuid(&field,
                                       registration->registration_id);
            seen[0] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_REGISTRATION_STATE:
            status = field_text_equals(
                         &field,
                         FTAP_REGISTRATION_STATE_PENDING_LEGACY)
                         ? FTAP_STATUS_OK
                         : FTAP_STATUS_ERR_INVALID_VALUE;
            seen[1] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_USER_ID:
            status = ftap_tlv_get_uuid(&field, registration->user_id);
            seen[2] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_LOGIN_NAME:
            status = copy_text_field(&field, registration->login_name,
                                     sizeof(registration->login_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            seen[3] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_DISPLAY_NAME:
            status = copy_text_field(&field, registration->display_name,
                                     sizeof(registration->display_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            seen[4] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_LEGACY_NAME:
            status = copy_text_field(&field, registration->legacy_name,
                                     sizeof(registration->legacy_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            seen[5] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_ACCOUNT_STATE:
            status = field_text_equals(&field, FTAP_ACCOUNT_STATE_PENDING)
                         ? FTAP_STATUS_OK
                         : FTAP_STATUS_ERR_INVALID_VALUE;
            seen[6] = status == FTAP_STATUS_OK;
            break;
        default:
            status = FTAP_STATUS_ERR_INVALID_MESSAGE;
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP registration begin value");
            memset(registration, 0, sizeof(*registration));
            return -1;
        }
    }

    for (index = 0U; index < sizeof(seen) / sizeof(seen[0]); ++index) {
        if (!seen[index]) {
            set_local_error(error, FTAP_STATUS_ERR_MISSING_FIELD, EPROTO,
                            "incomplete FTAP registration begin result");
            memset(registration, 0, sizeof(*registration));
            return -1;
        }
    }
    return 0;
}

/* Commit must return the same pending identity plus one bound terminal session. */
static int
parse_registration_commit_context(
    const ftap_received_frame_t *frame,
    const ftap_registration_context_t *registration,
    ftap_terminal_context_t *context,
    ftap_client_error_t *error)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    uint8_t registration_id[FTAP_UUID_SIZE];
    bool seen[12] = {false};
    size_t index;

    memset(registration_id, 0, sizeof(registration_id));
    memset(context, 0, sizeof(*context));
    status = ftap_tlv_reader_init(&reader, frame->payload,
                                  frame->payload_length);
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EPROTO,
                        "invalid FTAP registration commit result");
        return -1;
    }

    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP registration commit field");
            memset(context, 0, sizeof(*context));
            return -1;
        }
        switch (field.type) {
        case FTAP_FIELD_REGISTRATION_ID:
            status = ftap_tlv_get_uuid(&field, registration_id);
            seen[0] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_REGISTRATION_STATE:
            status = field_text_equals(
                         &field, FTAP_REGISTRATION_STATE_COMPLETED)
                         ? FTAP_STATUS_OK
                         : FTAP_STATUS_ERR_INVALID_VALUE;
            seen[1] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_USER_ID:
            status = ftap_tlv_get_uuid(&field, context->user_id);
            seen[2] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_SESSION_ID:
            status = ftap_tlv_get_uuid(&field, context->session_id);
            seen[3] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_LOGIN_NAME:
            status = copy_text_field(&field, context->login_name,
                                     sizeof(context->login_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            seen[4] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_DISPLAY_NAME:
            status = copy_text_field(&field, context->display_name,
                                     sizeof(context->display_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            seen[5] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_LEGACY_NAME:
            status = copy_text_field(&field, context->legacy_name,
                                     sizeof(context->legacy_name))
                         ? FTAP_STATUS_OK : FTAP_STATUS_ERR_LENGTH;
            seen[6] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_ACCOUNT_STATE:
            status = field_text_equals(&field, FTAP_ACCOUNT_STATE_ACTIVE)
                         ? FTAP_STATUS_OK
                         : FTAP_STATUS_ERR_INVALID_VALUE;
            seen[7] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_PROTOCOL:
            status = copy_text_field(&field, context->protocol,
                                     sizeof(context->protocol)) &&
                     strcmp(context->protocol, FTAP_PROTOCOL_TELNET) == 0
                         ? FTAP_STATUS_OK
                         : FTAP_STATUS_ERR_INVALID_VALUE;
            seen[8] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_AUTH_METHOD:
            status = copy_text_field(&field, context->auth_method,
                                     sizeof(context->auth_method)) &&
                     strcmp(context->auth_method,
                            FTAP_AUTH_METHOD_PASSWORD) == 0
                         ? FTAP_STATUS_OK
                         : FTAP_STATUS_ERR_INVALID_VALUE;
            seen[9] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_AUTH_EPOCH:
            status = ftap_tlv_get_u64(&field, &context->auth_epoch);
            seen[10] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_AUTHZ_REVISION:
            status = ftap_tlv_get_u64(&field, &context->authz_revision);
            seen[11] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_CAPABILITY:
            status = FTAP_STATUS_OK;
            break;
        default:
            status = FTAP_STATUS_ERR_INVALID_MESSAGE;
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP registration commit value");
            memset(context, 0, sizeof(*context));
            return -1;
        }
    }

    for (index = 0U; index < sizeof(seen) / sizeof(seen[0]); ++index) {
        if (!seen[index]) {
            set_local_error(error, FTAP_STATUS_ERR_MISSING_FIELD, EPROTO,
                            "incomplete FTAP registration commit result");
            memset(context, 0, sizeof(*context));
            return -1;
        }
    }
    if (memcmp(registration_id, registration->registration_id,
               FTAP_UUID_SIZE) != 0 ||
        memcmp(context->user_id, registration->user_id,
               FTAP_UUID_SIZE) != 0 ||
        strcmp(context->login_name, registration->login_name) != 0 ||
        strcmp(context->display_name, registration->display_name) != 0 ||
        strcmp(context->legacy_name, registration->legacy_name) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_VALUE, EPROTO,
                        "FTAP registration commit identity mismatch");
        memset(context, 0, sizeof(*context));
        return -1;
    }
    return 0;
}

static int
parse_registration_abort_result(
    const ftap_received_frame_t *frame,
    const ftap_registration_context_t *registration,
    ftap_client_error_t *error)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    uint8_t registration_id[FTAP_UUID_SIZE];
    uint8_t user_id[FTAP_UUID_SIZE];
    bool seen[3] = {false};
    size_t index;

    memset(registration_id, 0, sizeof(registration_id));
    memset(user_id, 0, sizeof(user_id));
    status = ftap_tlv_reader_init(&reader, frame->payload,
                                  frame->payload_length);
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EPROTO,
                        "invalid FTAP registration abort result");
        return -1;
    }

    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP registration abort field");
            return -1;
        }
        switch (field.type) {
        case FTAP_FIELD_REGISTRATION_ID:
            status = ftap_tlv_get_uuid(&field, registration_id);
            seen[0] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_REGISTRATION_STATE:
            status = field_text_equals(
                         &field, FTAP_REGISTRATION_STATE_ABORTED)
                         ? FTAP_STATUS_OK
                         : FTAP_STATUS_ERR_INVALID_VALUE;
            seen[1] = status == FTAP_STATUS_OK;
            break;
        case FTAP_FIELD_USER_ID:
            status = ftap_tlv_get_uuid(&field, user_id);
            seen[2] = status == FTAP_STATUS_OK;
            break;
        default:
            status = FTAP_STATUS_ERR_INVALID_MESSAGE;
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_local_error(error, status, EPROTO,
                            "invalid FTAP registration abort value");
            return -1;
        }
    }

    for (index = 0U; index < sizeof(seen) / sizeof(seen[0]); ++index) {
        if (!seen[index]) {
            set_local_error(error, FTAP_STATUS_ERR_MISSING_FIELD, EPROTO,
                            "incomplete FTAP registration abort result");
            return -1;
        }
    }
    if (memcmp(registration_id, registration->registration_id,
               FTAP_UUID_SIZE) != 0 ||
        memcmp(user_id, registration->user_id, FTAP_UUID_SIZE) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_VALUE, EPROTO,
                        "FTAP registration abort identity mismatch");
        return -1;
    }
    return 0;
}

static bool
registration_abort_reason_is_allowed(const char *reason)
{
    return reason == NULL ||
           strcmp(reason, FTAP_REGISTRATION_REASON_CLIENT_CANCELLED) == 0 ||
           strcmp(reason, FTAP_REGISTRATION_REASON_LEGACY_WRITE_FAILED) == 0;
}

int
ftap_client_registration_begin(
    ftap_client_t *client,
    const char *login_name,
    const char *display_name,
    const uint8_t *password,
    size_t password_length,
    const ftap_registration_metadata_t *metadata,
    ftap_registration_context_t *result,
    ftap_client_error_t *error)
{
    uint8_t payload[FTAP_MAX_PAYLOAD_SIZE];
    ftap_tlv_writer_t writer;
    ftap_received_frame_t response;
    ftap_status_t status;
    uint64_t request_id;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (client == NULL || client->state != FTAP_STATE_HELLO_COMPLETE ||
        login_name == NULL || display_name == NULL || password == NULL ||
        password_length == 0U || metadata == NULL ||
        metadata->protocol == NULL ||
        strcmp(metadata->protocol, FTAP_PROTOCOL_TELNET) != 0 ||
        metadata->source_ip == NULL || result == NULL) {
        set_local_error(error, FTAP_STATUS_ERR_ARGUMENT, EINVAL,
                        "invalid FTAP registration begin argument");
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_LOGIN_NAME, 0,
            (const uint8_t *)login_name, strlen(login_name),
            FTAP_LOGIN_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_DISPLAY_NAME, 0,
            (const uint8_t *)display_name, strlen(display_name),
            FTAP_DISPLAY_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_PASSWORD, 0, password, password_length,
            FTAP_PASSWORD_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_PROTOCOL, 0,
            (const uint8_t *)metadata->protocol, strlen(metadata->protocol),
            FTAP_PROTOCOL_NAME_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_SOURCE_IP, 0,
            (const uint8_t *)metadata->source_ip,
            strlen(metadata->source_ip), FTAP_IP_ADDRESS_MAX);
    }
    if (status == FTAP_STATUS_OK && metadata->tty_device != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_TTY_DEVICE, 0,
            (const uint8_t *)metadata->tty_device,
            strlen(metadata->tty_device), FTAP_TTY_DEVICE_MAX);
    }
    if (status == FTAP_STATUS_OK && metadata->node_id != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_NODE_ID, 0,
            (const uint8_t *)metadata->node_id, strlen(metadata->node_id),
            FTAP_NODE_ID_MAX);
    }
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_AUTH_METHOD, 0,
            (const uint8_t *)FTAP_AUTH_METHOD_PASSWORD,
            strlen(FTAP_AUTH_METHOD_PASSWORD), FTAP_AUTH_METHOD_MAX);
    }
    if (status != FTAP_STATUS_OK) {
        secure_wipe(payload, sizeof(payload));
        set_local_error(error, status, EINVAL,
                        "cannot build FTAP registration begin request");
        return -1;
    }

    request_id = next_request_id(client);
    if (send_frame(client, FTAP_MSG_REGISTRATION_BEGIN_REQUEST, request_id,
                   payload, writer.length, error) != 0) {
        secure_wipe(payload, sizeof(payload));
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    secure_wipe(payload, sizeof(payload));
    client->state = FTAP_STATE_REGISTERING;
    if (wait_for_response(client, FTAP_MSG_REGISTRATION_BEGIN_RESULT,
                          request_id, &response, error) != 0 ||
        parse_registration_begin_context(&response, result, error) != 0) {
        memset(result, 0, sizeof(*result));
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }

    ftap_client_error_clear(error);
    return 0;
}

int
ftap_client_registration_commit(
    ftap_client_t *client,
    const ftap_registration_context_t *registration,
    ftap_terminal_context_t *result,
    ftap_client_error_t *error)
{
    uint8_t payload[FTAP_TLV_HEADER_SIZE + FTAP_UUID_SIZE];
    ftap_tlv_writer_t writer;
    ftap_received_frame_t response;
    ftap_status_t status;
    uint64_t request_id;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (client == NULL || client->state != FTAP_STATE_REGISTERING ||
        registration == NULL || result == NULL) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_STATE, EINVAL,
                        "no pending FTAP registration to commit");
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_uuid(
            &writer, FTAP_FIELD_REGISTRATION_ID, 0,
            registration->registration_id);
    }
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EINVAL,
                        "cannot build FTAP registration commit request");
        return -1;
    }

    request_id = next_request_id(client);
    if (send_frame(client, FTAP_MSG_REGISTRATION_COMMIT_REQUEST, request_id,
                   payload, writer.length, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    if (wait_for_response(client, FTAP_MSG_REGISTRATION_COMMIT_RESULT,
                          request_id, &response, error) != 0) {
        if (error == NULL || !error->server_error) {
            mark_outcome_unknown(error);
        }
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    if (parse_registration_commit_context(&response, registration,
                                          result, error) != 0) {
        mark_outcome_unknown(error);
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }

    client->state = FTAP_STATE_SESSION_BOUND;
    ftap_client_error_clear(error);
    return 0;
}

int
ftap_client_registration_abort(
    ftap_client_t *client,
    const ftap_registration_context_t *registration,
    const char *reason,
    ftap_client_error_t *error)
{
    uint8_t payload[FTAP_TLV_HEADER_SIZE + FTAP_UUID_SIZE +
                    FTAP_TLV_HEADER_SIZE + FTAP_REGISTRATION_REASON_MAX];
    ftap_tlv_writer_t writer;
    ftap_received_frame_t response;
    ftap_status_t status;
    uint64_t request_id;

    if (client == NULL || client->state != FTAP_STATE_REGISTERING ||
        registration == NULL ||
        !registration_abort_reason_is_allowed(reason)) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_STATE, EINVAL,
                        "no pending FTAP registration to abort");
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK) {
        status = ftap_tlv_writer_put_uuid(
            &writer, FTAP_FIELD_REGISTRATION_ID, 0,
            registration->registration_id);
    }
    if (status == FTAP_STATUS_OK && reason != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_REGISTRATION_REASON, 0,
            (const uint8_t *)reason, strlen(reason),
            FTAP_REGISTRATION_REASON_MAX);
    }
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EINVAL,
                        "cannot build FTAP registration abort request");
        return -1;
    }

    request_id = next_request_id(client);
    if (send_frame(client, FTAP_MSG_REGISTRATION_ABORT_REQUEST, request_id,
                   payload, writer.length, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    if (wait_for_response(client, FTAP_MSG_REGISTRATION_ABORT_RESULT,
                          request_id, &response, error) != 0) {
        if (error == NULL || !error->server_error) {
            mark_outcome_unknown(error);
        }
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    if (parse_registration_abort_result(&response, registration, error) != 0) {
        mark_outcome_unknown(error);
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }

    client->state = FTAP_STATE_HELLO_COMPLETE;
    ftap_client_error_clear(error);
    return 0;
}

int
ftap_client_session_context(ftap_client_t *client,
                            ftap_terminal_context_t *context,
                            ftap_client_error_t *error)
{
    ftap_received_frame_t response;
    uint64_t request_id;

    if (client == NULL || client->state != FTAP_STATE_SESSION_BOUND ||
        context == NULL) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_STATE, EINVAL,
                        "FTAP session context is not available");
        return -1;
    }

    request_id = next_request_id(client);
    if (send_frame(client, FTAP_MSG_SESSION_CONTEXT_REQUEST,
                   request_id, NULL, 0U, error) != 0 ||
        wait_for_response(client, FTAP_MSG_SESSION_CONTEXT_RESULT,
                          request_id, &response, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    if (parse_terminal_context(&response, true, context, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }

    ftap_client_error_clear(error);
    return 0;
}

int
ftap_client_session_close(ftap_client_t *client,
                          const char *ended_reason,
                          ftap_client_error_t *error)
{
    uint8_t payload[FTAP_TLV_HEADER_SIZE + FTAP_ENDED_REASON_MAX];
    ftap_tlv_writer_t writer;
    ftap_status_t status;
    uint64_t request_id;

    if (client == NULL || client->state != FTAP_STATE_SESSION_BOUND) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_STATE, EINVAL,
                        "no bound FTAP session to close");
        return -1;
    }

    status = ftap_tlv_writer_init(&writer, payload, sizeof(payload));
    if (status == FTAP_STATUS_OK && ended_reason != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_ENDED_REASON, 0,
            (const uint8_t *)ended_reason, strlen(ended_reason),
            FTAP_ENDED_REASON_MAX);
    }
    if (status != FTAP_STATUS_OK) {
        set_local_error(error, status, EINVAL,
                        "cannot build FTAP session close");
        return -1;
    }

    request_id = next_request_id(client);
    if (send_frame(client, FTAP_MSG_SESSION_CLOSE, request_id,
                   payload, writer.length, error) != 0) {
        client->state = FTAP_STATE_CLOSING;
        return -1;
    }
    client->state = FTAP_STATE_CLOSING;
    ftap_client_error_clear(error);
    return 0;
}


/* Descriptor 3 is the sole authenticated identity channel across execve(). */
int
ftap_client_move_to_inherited_fd(ftap_client_t *client,
                                 ftap_client_error_t *error)
{
    int flags;

    if (client == NULL || client->fd < 0 ||
        client->state != FTAP_STATE_SESSION_BOUND) {
        set_local_error(error, FTAP_STATUS_ERR_INVALID_STATE, EINVAL,
                        "no bound FTAP session for descriptor handoff");
        return -1;
    }

    if (client->fd != FTAP_INHERITED_SESSION_FD) {
        if (dup2(client->fd, FTAP_INHERITED_SESSION_FD) < 0) {
            set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, errno,
                            "cannot move FTAP session to descriptor 3");
            return -1;
        }
        (void)close(client->fd);
        client->fd = FTAP_INHERITED_SESSION_FD;
    }

    flags = fcntl(client->fd, F_GETFD, 0);
    if (flags < 0 ||
        fcntl(client->fd, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
        set_local_error(error, FTAP_STATUS_ERR_TRUNCATED, errno,
                        "cannot preserve FTAP session across exec");
        return -1;
    }

    ftap_client_error_clear(error);
    return 0;
}

void
ftap_client_close(ftap_client_t *client)
{
    if (client == NULL) {
        return;
    }
    if (client->fd >= 0) {
        (void)close(client->fd);
    }
    ftap_client_init(client, client->timeout_ms);
}
