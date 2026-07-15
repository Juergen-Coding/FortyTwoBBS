/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * End-to-end FTAP registration state-machine tests against test-only workers
 * and the deterministic in-process database implementation.
 */

#include "ftap_codec.h"
#include "ftap_schema.h"

#include <assert.h>
#include <dirent.h>
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TEST_TIMEOUT_MS 4000

typedef struct received_frame {
    ftap_frame_header_t header;
    uint8_t payload[FTAP_MAX_PAYLOAD_SIZE];
    size_t payload_length;
} received_frame_t;

typedef struct begin_snapshot {
    uint8_t registration_id[FTAP_UUID_SIZE];
    uint8_t user_id[FTAP_UUID_SIZE];
    char login_name[FTAP_LOGIN_NAME_MAX + 1U];
    char display_name[FTAP_DISPLAY_NAME_MAX + 1U];
    char legacy_name[FTAP_LEGACY_NAME_MAX + 1U];
} begin_snapshot_t;

static void
sleep_milliseconds(long milliseconds)
{
    struct timespec delay;

    delay.tv_sec = milliseconds / 1000L;
    delay.tv_nsec = (milliseconds % 1000L) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        /* Continue with the remaining interval. */
    }
}

static int
wait_for_fd(int fd, short events, int timeout_ms)
{
    struct pollfd descriptor;
    int result;

    descriptor.fd = fd;
    descriptor.events = events;
    descriptor.revents = 0;
    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result <= 0 ||
        (descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
        return -1;
    }
    return 0;
}

static int
send_all(int fd, const uint8_t *buffer, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t sent = send(fd, buffer + offset, length - offset,
                            MSG_NOSIGNAL);
        if (sent > 0) {
            offset += (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            wait_for_fd(fd, POLLOUT, TEST_TIMEOUT_MS) == 0) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int
receive_exact(int fd, uint8_t *buffer, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t received;

        if (wait_for_fd(fd, POLLIN, TEST_TIMEOUT_MS) != 0) {
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
        return -1;
    }
    return 0;
}

static int
receive_frame(int fd, received_frame_t *frame)
{
    uint8_t header_bytes[FTAP_FRAME_HEADER_SIZE];

    memset(frame, 0, sizeof(*frame));
    if (receive_exact(fd, header_bytes, sizeof(header_bytes)) != 0 ||
        ftap_frame_header_decode(header_bytes, sizeof(header_bytes),
                                 &frame->header) != FTAP_STATUS_OK ||
        frame->header.payload_length > FTAP_MAX_PAYLOAD_SIZE) {
        return -1;
    }
    frame->payload_length = (size_t)frame->header.payload_length;
    if (frame->payload_length > 0U &&
        receive_exact(fd, frame->payload, frame->payload_length) != 0) {
        return -1;
    }
    return 0;
}

static size_t
finish_frame(uint8_t frame[FTAP_MAX_FRAME_SIZE],
             ftap_tlv_writer_t *writer,
             uint16_t message_type,
             uint64_t request_id)
{
    ftap_frame_header_t header;

    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = message_type;
    header.payload_length = (uint32_t)writer->length;
    header.request_id = request_id;
    assert(ftap_frame_header_encode(frame, &header) == FTAP_STATUS_OK);
    return FTAP_FRAME_HEADER_SIZE + writer->length;
}

static size_t
build_hello(uint8_t frame[FTAP_MAX_FRAME_SIZE], uint64_t request_id)
{
    ftap_tlv_writer_t writer;
    uint8_t *payload = frame + FTAP_FRAME_HEADER_SIZE;

    assert(ftap_tlv_writer_init(&writer, payload,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_CLIENT_NAME, 0,
               (const uint8_t *)"registration-state-test",
               strlen("registration-state-test"),
               FTAP_CLIENT_NAME_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_CLIENT_VERSION, 0,
               (const uint8_t *)"1.0", strlen("1.0"),
               FTAP_CLIENT_VERSION_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_u16(
               &writer, FTAP_FIELD_SUPPORTED_MAJOR, 0,
               FTAP_VERSION_MAJOR) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_u16(
               &writer, FTAP_FIELD_SUPPORTED_MINOR, 0,
               FTAP_VERSION_MINOR) == FTAP_STATUS_OK);
    return finish_frame(frame, &writer, FTAP_MSG_HELLO, request_id);
}

static size_t
build_registration_begin(uint8_t frame[FTAP_MAX_FRAME_SIZE],
                         uint64_t request_id,
                         const char *login_name,
                         const char *display_name,
                         const char *password,
                         const char *source_ip)
{
    ftap_tlv_writer_t writer;
    uint8_t *payload = frame + FTAP_FRAME_HEADER_SIZE;

    assert(ftap_tlv_writer_init(&writer, payload,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_LOGIN_NAME, 0,
               (const uint8_t *)login_name, strlen(login_name),
               FTAP_LOGIN_NAME_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_DISPLAY_NAME, 0,
               (const uint8_t *)display_name, strlen(display_name),
               FTAP_DISPLAY_NAME_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_PASSWORD, 0,
               (const uint8_t *)password, strlen(password),
               FTAP_PASSWORD_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_PROTOCOL, 0,
               (const uint8_t *)FTAP_PROTOCOL_TELNET,
               strlen(FTAP_PROTOCOL_TELNET),
               FTAP_PROTOCOL_NAME_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_SOURCE_IP, 0,
               (const uint8_t *)source_ip, strlen(source_ip),
               FTAP_IP_ADDRESS_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_TTY_DEVICE, 0,
               (const uint8_t *)"pts/42", strlen("pts/42"),
               FTAP_TTY_DEVICE_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_NODE_ID, 0,
               (const uint8_t *)"node-42", strlen("node-42"),
               FTAP_NODE_ID_MAX) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_text(
               &writer, FTAP_FIELD_AUTH_METHOD, 0,
               (const uint8_t *)FTAP_AUTH_METHOD_PASSWORD,
               strlen(FTAP_AUTH_METHOD_PASSWORD),
               FTAP_AUTH_METHOD_MAX) == FTAP_STATUS_OK);
    return finish_frame(frame, &writer,
                        FTAP_MSG_REGISTRATION_BEGIN_REQUEST, request_id);
}

static size_t
build_registration_id_request(
    uint8_t frame[FTAP_MAX_FRAME_SIZE],
    uint16_t message_type,
    uint64_t request_id,
    const uint8_t registration_id[FTAP_UUID_SIZE],
    const char *reason)
{
    ftap_tlv_writer_t writer;
    uint8_t *payload = frame + FTAP_FRAME_HEADER_SIZE;

    assert(ftap_tlv_writer_init(&writer, payload,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_uuid(
               &writer, FTAP_FIELD_REGISTRATION_ID, 0,
               registration_id) == FTAP_STATUS_OK);
    if (reason != NULL) {
        assert(ftap_tlv_writer_put_text(
                   &writer, FTAP_FIELD_REGISTRATION_REASON, 0,
                   (const uint8_t *)reason, strlen(reason),
                   FTAP_REGISTRATION_REASON_MAX) == FTAP_STATUS_OK);
    }
    return finish_frame(frame, &writer, message_type, request_id);
}

static size_t
build_empty_request(uint8_t frame[FTAP_MAX_FRAME_SIZE],
                    uint16_t message_type,
                    uint64_t request_id)
{
    ftap_tlv_writer_t writer;

    assert(ftap_tlv_writer_init(&writer,
                                frame + FTAP_FRAME_HEADER_SIZE,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    return finish_frame(frame, &writer, message_type, request_id);
}

static void
perform_hello(int client, uint64_t request_id)
{
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    received_frame_t response;
    size_t length = build_hello(frame, request_id);

    assert(send_all(client, frame, length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(response.header.message_type == FTAP_MSG_HELLO_OK);
    assert(response.header.request_id == request_id);
}

static uint32_t
error_code(const received_frame_t *frame)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    uint32_t value = 0U;

    assert(frame->header.message_type == FTAP_MSG_ERROR);
    assert(ftap_tlv_reader_init(&reader, frame->payload,
                                frame->payload_length) == FTAP_STATUS_OK);
    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        assert(status == FTAP_STATUS_OK);
        if (field.type == FTAP_FIELD_ERROR_CODE) {
            assert(ftap_tlv_get_u32(&field, &value) == FTAP_STATUS_OK);
        }
    }
    return value;
}

static void
copy_tlv_text(const ftap_tlv_t *field, char *output, size_t output_size,
              size_t maximum)
{
    const uint8_t *text = NULL;
    size_t text_length = 0U;

    assert(ftap_tlv_get_text(field, &text, &text_length,
                             maximum) == FTAP_STATUS_OK);
    assert(text_length < output_size);
    memcpy(output, text, text_length);
    output[text_length] = '\0';
}

static void
parse_begin_result(const received_frame_t *frame,
                   uint64_t request_id,
                   begin_snapshot_t *snapshot)
{
    ftap_validation_error_t validation_error;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool seen[7] = {false};
    char value[FTAP_REGISTRATION_STATE_MAX + 1U];
    size_t index;

    memset(snapshot, 0, sizeof(*snapshot));
    assert(frame->header.message_type == FTAP_MSG_REGISTRATION_BEGIN_RESULT);
    assert(frame->header.request_id == request_id);
    assert(ftap_validate_message(FTAP_STATE_REGISTERING, &frame->header,
                                 frame->payload, frame->payload_length,
                                 &validation_error) == FTAP_STATUS_OK);
    assert(ftap_tlv_reader_init(&reader, frame->payload,
                                frame->payload_length) == FTAP_STATUS_OK);
    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        assert(status == FTAP_STATUS_OK);
        switch (field.type) {
        case FTAP_FIELD_REGISTRATION_ID:
            assert(ftap_tlv_get_uuid(&field, snapshot->registration_id) ==
                   FTAP_STATUS_OK);
            seen[0] = true;
            break;
        case FTAP_FIELD_REGISTRATION_STATE:
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_REGISTRATION_STATE_MAX);
            assert(strcmp(value,
                          FTAP_REGISTRATION_STATE_PENDING_LEGACY) == 0);
            seen[1] = true;
            break;
        case FTAP_FIELD_USER_ID:
            assert(ftap_tlv_get_uuid(&field, snapshot->user_id) ==
                   FTAP_STATUS_OK);
            seen[2] = true;
            break;
        case FTAP_FIELD_LOGIN_NAME:
            copy_tlv_text(&field, snapshot->login_name,
                          sizeof(snapshot->login_name), FTAP_LOGIN_NAME_MAX);
            seen[3] = true;
            break;
        case FTAP_FIELD_DISPLAY_NAME:
            copy_tlv_text(&field, snapshot->display_name,
                          sizeof(snapshot->display_name),
                          FTAP_DISPLAY_NAME_MAX);
            seen[4] = true;
            break;
        case FTAP_FIELD_LEGACY_NAME:
            copy_tlv_text(&field, snapshot->legacy_name,
                          sizeof(snapshot->legacy_name), FTAP_LEGACY_NAME_MAX);
            seen[5] = true;
            break;
        case FTAP_FIELD_ACCOUNT_STATE:
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_ACCOUNT_STATE_MAX);
            assert(strcmp(value, FTAP_ACCOUNT_STATE_PENDING) == 0);
            seen[6] = true;
            break;
        default:
            assert(false);
        }
    }
    for (index = 0U; index < 7U; ++index) {
        assert(seen[index]);
    }
}

static void
assert_abort_result(const received_frame_t *frame,
                    uint64_t request_id,
                    const begin_snapshot_t *snapshot)
{
    ftap_validation_error_t validation_error;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool id_seen = false;
    bool user_seen = false;
    bool state_seen = false;

    assert(frame->header.message_type == FTAP_MSG_REGISTRATION_ABORT_RESULT);
    assert(frame->header.request_id == request_id);
    assert(ftap_validate_message(FTAP_STATE_REGISTERING, &frame->header,
                                 frame->payload, frame->payload_length,
                                 &validation_error) == FTAP_STATUS_OK);
    assert(ftap_tlv_reader_init(&reader, frame->payload,
                                frame->payload_length) == FTAP_STATUS_OK);
    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        assert(status == FTAP_STATUS_OK);
        if (field.type == FTAP_FIELD_REGISTRATION_ID) {
            uint8_t value[FTAP_UUID_SIZE];
            assert(ftap_tlv_get_uuid(&field, value) == FTAP_STATUS_OK);
            assert(memcmp(value, snapshot->registration_id,
                          FTAP_UUID_SIZE) == 0);
            id_seen = true;
        } else if (field.type == FTAP_FIELD_USER_ID) {
            uint8_t value[FTAP_UUID_SIZE];
            assert(ftap_tlv_get_uuid(&field, value) == FTAP_STATUS_OK);
            assert(memcmp(value, snapshot->user_id, FTAP_UUID_SIZE) == 0);
            user_seen = true;
        } else if (field.type == FTAP_FIELD_REGISTRATION_STATE) {
            char value[FTAP_REGISTRATION_STATE_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_REGISTRATION_STATE_MAX);
            assert(strcmp(value, FTAP_REGISTRATION_STATE_ABORTED) == 0);
            state_seen = true;
        } else {
            assert(false);
        }
    }
    assert(id_seen && user_seen && state_seen);
}

static void
assert_commit_result(const received_frame_t *frame,
                     uint64_t request_id,
                     const begin_snapshot_t *snapshot)
{
    ftap_validation_error_t validation_error;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool seen[11] = {false};
    size_t index;

    assert(frame->header.message_type == FTAP_MSG_REGISTRATION_COMMIT_RESULT);
    assert(frame->header.request_id == request_id);
    assert(ftap_validate_message(FTAP_STATE_REGISTERING, &frame->header,
                                 frame->payload, frame->payload_length,
                                 &validation_error) == FTAP_STATUS_OK);
    assert(ftap_tlv_reader_init(&reader, frame->payload,
                                frame->payload_length) == FTAP_STATUS_OK);
    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        assert(status == FTAP_STATUS_OK);
        switch (field.type) {
        case FTAP_FIELD_REGISTRATION_ID: {
            uint8_t value[FTAP_UUID_SIZE];
            assert(ftap_tlv_get_uuid(&field, value) == FTAP_STATUS_OK);
            assert(memcmp(value, snapshot->registration_id,
                          FTAP_UUID_SIZE) == 0);
            seen[0] = true;
            break;
        }
        case FTAP_FIELD_REGISTRATION_STATE: {
            char value[FTAP_REGISTRATION_STATE_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_REGISTRATION_STATE_MAX);
            assert(strcmp(value, FTAP_REGISTRATION_STATE_COMPLETED) == 0);
            seen[1] = true;
            break;
        }
        case FTAP_FIELD_USER_ID: {
            uint8_t value[FTAP_UUID_SIZE];
            assert(ftap_tlv_get_uuid(&field, value) == FTAP_STATUS_OK);
            assert(memcmp(value, snapshot->user_id, FTAP_UUID_SIZE) == 0);
            seen[2] = true;
            break;
        }
        case FTAP_FIELD_SESSION_ID:
            seen[3] = true;
            break;
        case FTAP_FIELD_LOGIN_NAME: {
            char value[FTAP_LOGIN_NAME_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value), FTAP_LOGIN_NAME_MAX);
            assert(strcmp(value, snapshot->login_name) == 0);
            seen[4] = true;
            break;
        }
        case FTAP_FIELD_DISPLAY_NAME: {
            char value[FTAP_DISPLAY_NAME_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_DISPLAY_NAME_MAX);
            assert(strcmp(value, snapshot->display_name) == 0);
            seen[5] = true;
            break;
        }
        case FTAP_FIELD_LEGACY_NAME: {
            char value[FTAP_LEGACY_NAME_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value), FTAP_LEGACY_NAME_MAX);
            assert(strcmp(value, snapshot->legacy_name) == 0);
            seen[6] = true;
            break;
        }
        case FTAP_FIELD_ACCOUNT_STATE: {
            char value[FTAP_ACCOUNT_STATE_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_ACCOUNT_STATE_MAX);
            assert(strcmp(value, FTAP_ACCOUNT_STATE_ACTIVE) == 0);
            seen[7] = true;
            break;
        }
        case FTAP_FIELD_PROTOCOL: {
            char value[FTAP_PROTOCOL_NAME_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_PROTOCOL_NAME_MAX);
            assert(strcmp(value, FTAP_PROTOCOL_TELNET) == 0);
            seen[8] = true;
            break;
        }
        case FTAP_FIELD_AUTH_METHOD: {
            char value[FTAP_AUTH_METHOD_MAX + 1U];
            copy_tlv_text(&field, value, sizeof(value),
                          FTAP_AUTH_METHOD_MAX);
            assert(strcmp(value, FTAP_AUTH_METHOD_PASSWORD) == 0);
            seen[9] = true;
            break;
        }
        case FTAP_FIELD_AUTH_EPOCH:
        case FTAP_FIELD_AUTHZ_REVISION:
            seen[10] = true;
            break;
        case FTAP_FIELD_CAPABILITY:
            break;
        default:
            assert(false);
        }
    }
    for (index = 0U; index < 11U; ++index) {
        assert(seen[index]);
    }
}

static int
connect_unix_socket(const char *path)
{
    struct sockaddr_un address;
    int elapsed;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    assert(strlen(path) < sizeof(address.sun_path));
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    for (elapsed = 0; elapsed < TEST_TIMEOUT_MS; elapsed += 10) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return -1;
        }
        if (connect(fd, (const struct sockaddr *)&address,
                    (socklen_t)sizeof(address)) == 0) {
            return fd;
        }
        (void)close(fd);
        sleep_milliseconds(10);
    }
    errno = ETIMEDOUT;
    return -1;
}

static pid_t
start_daemon(const char *daemon_path,
             const char *socket_path,
             const char *daemon_log,
             bool registration_enabled,
             const char *ip_attempts)
{
    pid_t child = fork();
    char uid_text[32];

    assert(child >= 0);
    (void)snprintf(uid_text, sizeof(uid_text), "%ju", (uintmax_t)geteuid());
    if (child == 0) {
        char *arguments[36];
        size_t count = 0U;
        int log_fd = open(daemon_log,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          (mode_t)0600);

        if (log_fd >= 0) {
            (void)dup2(log_fd, STDERR_FILENO);
            (void)close(log_fd);
        }
        arguments[count++] = (char *)daemon_path;
        arguments[count++] = "--socket";
        arguments[count++] = (char *)socket_path;
        arguments[count++] = "--socket-mode";
        arguments[count++] = "0600";
        arguments[count++] = "--allow-uid";
        arguments[count++] = uid_text;
        arguments[count++] = "--max-clients";
        arguments[count++] = "8";
        arguments[count++] = "--backlog";
        arguments[count++] = "8";
        arguments[count++] = "--hello-timeout-ms";
        arguments[count++] = "1000";
        arguments[count++] = "--password-workers";
        arguments[count++] = "2";
        arguments[count++] = "--password-queue-capacity";
        arguments[count++] = "8";
        arguments[count++] = "--db-health-interval-ms";
        arguments[count++] = "100";
        if (registration_enabled) {
            arguments[count++] = "--registration-enabled";
        }
        arguments[count++] = "--registration-min-password-bytes";
        arguments[count++] = "12";
        arguments[count++] = "--registration-timeout-seconds";
        arguments[count++] = "60";
        arguments[count++] = "--registration-max-pending";
        arguments[count++] = "16";
        arguments[count++] = "--registration-ip-attempts";
        arguments[count++] = (char *)ip_attempts;
        arguments[count++] = "--registration-ip-window-seconds";
        arguments[count++] = "900";
        arguments[count] = NULL;
        execv(daemon_path, arguments);
        _exit(127);
    }
    return child;
}

static int
wait_for_exit(pid_t child, int timeout_ms, int *status)
{
    int elapsed;

    for (elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) {
            return 0;
        }
        if (result < 0) {
            return -1;
        }
        sleep_milliseconds(10);
    }
    return -1;
}

static void
stop_daemon(pid_t child)
{
    int status = 0;

    assert(kill(child, SIGTERM) == 0);
    if (wait_for_exit(child, TEST_TIMEOUT_MS, &status) != 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
        assert(false);
    }
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
}

static void
expect_closed(int fd)
{
    uint8_t byte;

    assert(wait_for_fd(fd, POLLIN | POLLHUP, TEST_TIMEOUT_MS) == 0);
    assert(recv(fd, &byte, sizeof(byte), 0) == 0);
}

static size_t
count_event(const char *path, const char *needle)
{
    FILE *stream = fopen(path, "r");
    char line[256];
    size_t count = 0U;

    if (stream == NULL) {
        return 0U;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (strstr(line, needle) != NULL) {
            ++count;
        }
    }
    assert(fclose(stream) == 0);
    return count;
}

static void
wait_for_event(const char *path, const char *needle)
{
    int elapsed;

    for (elapsed = 0; elapsed < TEST_TIMEOUT_MS; elapsed += 10) {
        if (count_event(path, needle) > 0U) {
            return;
        }
        sleep_milliseconds(10);
    }
    assert(false);
}

static void
prepare_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  (mode_t)0600);
    assert(fd >= 0);
    assert(close(fd) == 0);
}

/* Remove the private flat fixture directory after a successful test run. */
static void
remove_test_directory(const char *directory)
{
    DIR *stream = opendir(directory);
    struct dirent *entry;

    assert(stream != NULL);
    while ((entry = readdir(stream)) != NULL) {
        char path[512];
        int length;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        length = snprintf(path, sizeof(path), "%s/%s", directory,
                          entry->d_name);
        assert(length > 0 && (size_t)length < sizeof(path));
        assert(unlink(path) == 0 || errno == ENOENT);
    }
    assert(closedir(stream) == 0);
    assert(rmdir(directory) == 0);
}

static void
send_begin(int client,
           uint64_t request_id,
           const char *login_name,
           const char *display_name,
           const char *password,
           const char *source_ip)
{
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    size_t length = build_registration_begin(
        frame, request_id, login_name, display_name, password, source_ip);
    assert(send_all(client, frame, length) == 0);
}

static void
test_disabled_and_password_policy(const char *daemon_path,
                                  const char *directory)
{
    char socket_path[256];
    char daemon_log[256];
    char event_log[256];
    pid_t daemon;
    int client;
    received_frame_t response;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/disabled.sock",
                   directory);
    (void)snprintf(daemon_log, sizeof(daemon_log), "%s/disabled.log",
                   directory);
    (void)snprintf(event_log, sizeof(event_log), "%s/disabled.events",
                   directory);
    prepare_file(event_log);
    assert(setenv("FORTYTWO_TEST_EVENT_LOG", event_log, 1) == 0);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, false, "3");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "newuser", "New User",
               "long-enough-password", "203.0.113.10");
    assert(receive_frame(client, &response) == 0);
    assert(error_code(&response) == FTAP_ERR_ACCESS_DENIED);
    expect_closed(client);
    assert(close(client) == 0);
    stop_daemon(daemon);

    (void)snprintf(socket_path, sizeof(socket_path), "%s/policy.sock",
                   directory);
    (void)snprintf(daemon_log, sizeof(daemon_log), "%s/policy.log",
                   directory);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "3");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "newuser", "New User",
               "short", "203.0.113.11");
    assert(receive_frame(client, &response) == 0);
    assert(error_code(&response) == FTAP_ERR_PASSWORD_POLICY);
    expect_closed(client);
    assert(close(client) == 0);
    stop_daemon(daemon);
}

static void
test_commit_lifecycle(const char *daemon_path, const char *directory)
{
    char socket_path[256];
    char daemon_log[256];
    char event_log[256];
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    received_frame_t response;
    begin_snapshot_t snapshot;
    pid_t daemon;
    int client;
    size_t length;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/commit.sock",
                   directory);
    (void)snprintf(daemon_log, sizeof(daemon_log), "%s/commit.log",
                   directory);
    (void)snprintf(event_log, sizeof(event_log), "%s/commit.events",
                   directory);
    prepare_file(event_log);
    assert(setenv("FORTYTWO_TEST_EVENT_LOG", event_log, 1) == 0);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "5");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));

    send_begin(client, UINT64_C(2), "newuser", "New User",
               "long-enough-password", "203.0.113.12");
    assert(receive_frame(client, &response) == 0);
    parse_begin_result(&response, UINT64_C(2), &snapshot);
    assert(strcmp(snapshot.login_name, "newuser") == 0);
    assert(strcmp(snapshot.display_name, "New User") == 0);
    assert(strcmp(snapshot.legacy_name, "newuser") == 0);

    length = build_registration_id_request(
        frame, FTAP_MSG_REGISTRATION_COMMIT_REQUEST, UINT64_C(3),
        snapshot.registration_id, NULL);
    assert(send_all(client, frame, length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert_commit_result(&response, UINT64_C(3), &snapshot);

    length = build_empty_request(frame, FTAP_MSG_SESSION_CONTEXT_REQUEST,
                                 UINT64_C(4));
    assert(send_all(client, frame, length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(response.header.message_type == FTAP_MSG_SESSION_CONTEXT_RESULT);
    assert(response.header.request_id == UINT64_C(4));

    length = build_empty_request(frame, FTAP_MSG_SESSION_CLOSE,
                                 UINT64_C(5));
    assert(send_all(client, frame, length) == 0);
    expect_closed(client);
    assert(close(client) == 0);
    wait_for_event(event_log, "registration_commit:newuser");
    wait_for_event(event_log, "session_close:normal_logout");
    stop_daemon(daemon);
}

static void
test_abort_retry_collision_and_rate_limit(const char *daemon_path,
                                          const char *directory)
{
    char socket_path[256];
    char daemon_log[256];
    char event_log[256];
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    received_frame_t response;
    begin_snapshot_t first;
    begin_snapshot_t second;
    pid_t daemon;
    int client;
    size_t length;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/abort.sock",
                   directory);
    (void)snprintf(daemon_log, sizeof(daemon_log), "%s/abort.log",
                   directory);
    (void)snprintf(event_log, sizeof(event_log), "%s/abort.events",
                   directory);
    prepare_file(event_log);
    assert(setenv("FORTYTWO_TEST_EVENT_LOG", event_log, 1) == 0);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "2");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));

    send_begin(client, UINT64_C(2), "collide", "Collision User",
               "long-enough-password", "203.0.113.13");
    assert(receive_frame(client, &response) == 0);
    parse_begin_result(&response, UINT64_C(2), &first);
    assert(strlen(first.legacy_name) == 8U);
    assert(strcmp(first.legacy_name, "collide") != 0);
    length = build_registration_id_request(
        frame, FTAP_MSG_REGISTRATION_ABORT_REQUEST, UINT64_C(3),
        first.registration_id, FTAP_REGISTRATION_REASON_LEGACY_WRITE_FAILED);
    assert(send_all(client, frame, length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert_abort_result(&response, UINT64_C(3), &first);

    send_begin(client, UINT64_C(4), "second", "Second User",
               "long-enough-password", "203.0.113.13");
    assert(receive_frame(client, &response) == 0);
    parse_begin_result(&response, UINT64_C(4), &second);
    length = build_registration_id_request(
        frame, FTAP_MSG_REGISTRATION_ABORT_REQUEST, UINT64_C(5),
        second.registration_id, NULL);
    assert(send_all(client, frame, length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert_abort_result(&response, UINT64_C(5), &second);
    assert(shutdown(client, SHUT_WR) == 0);
    expect_closed(client);
    assert(close(client) == 0);

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "third", "Third User",
               "long-enough-password", "203.0.113.13");
    assert(receive_frame(client, &response) == 0);
    assert(error_code(&response) == FTAP_ERR_RATE_LIMITED);
    expect_closed(client);
    assert(close(client) == 0);
    wait_for_event(event_log, "registration_legacy_conflict:collide");
    wait_for_event(event_log,
                   "registration_abort:legacy_write_failed");
    wait_for_event(event_log, "registration_abort:client_cancelled");
    stop_daemon(daemon);
}

static void
test_disconnect_bound_and_hash_pending(const char *daemon_path,
                                       const char *directory)
{
    char socket_path[256];
    char daemon_log[256];
    char event_log[256];
    received_frame_t response;
    begin_snapshot_t snapshot;
    pid_t daemon;
    int client;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/disconnect.sock",
                   directory);
    (void)snprintf(daemon_log, sizeof(daemon_log), "%s/disconnect.log",
                   directory);
    (void)snprintf(event_log, sizeof(event_log), "%s/disconnect.events",
                   directory);
    prepare_file(event_log);
    assert(setenv("FORTYTWO_TEST_EVENT_LOG", event_log, 1) == 0);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "5");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "dropuser", "Drop User",
               "long-enough-password", "203.0.113.14");
    assert(receive_frame(client, &response) == 0);
    parse_begin_result(&response, UINT64_C(2), &snapshot);
    assert(close(client) == 0);
    wait_for_event(event_log,
                   "registration_abort:client_disconnected");
    stop_daemon(daemon);

    prepare_file(event_log);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "5");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "shutdownuser", "Shutdown User",
               "long-enough-password", "203.0.113.20");
    assert(receive_frame(client, &response) == 0);
    parse_begin_result(&response, UINT64_C(2), &snapshot);
    stop_daemon(daemon);
    wait_for_event(event_log, "registration_abort:daemon_shutdown");
    expect_closed(client);
    assert(close(client) == 0);

    prepare_file(event_log);
    assert(setenv("FORTYTWO_TEST_DB_HEALTH_FAIL_AFTER", "5", 1) == 0);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "5");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "dbdrop", "Database Drop",
               "long-enough-password", "203.0.113.21");
    assert(receive_frame(client, &response) == 0);
    parse_begin_result(&response, UINT64_C(2), &snapshot);
    {
        int status = 0;

        assert(wait_for_exit(daemon, TEST_TIMEOUT_MS, &status) == 0);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) != 0);
    }
    wait_for_event(event_log, "registration_abort:database_failure");
    expect_closed(client);
    assert(close(client) == 0);
    assert(unsetenv("FORTYTWO_TEST_DB_HEALTH_FAIL_AFTER") == 0);

    prepare_file(event_log);
    assert(setenv("FORTYTWO_TEST_PASSWORD_DELAY_MS", "250", 1) == 0);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "5");
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "hashdrop", "Hash Drop",
               "long-enough-password", "203.0.113.15");
    assert(close(client) == 0);
    sleep_milliseconds(500);
    assert(count_event(event_log, "registration_begin:") == 0U);
    assert(count_event(event_log, "registration_abort:") == 0U);
    stop_daemon(daemon);
    assert(unsetenv("FORTYTWO_TEST_PASSWORD_DELAY_MS") == 0);
}

static void
test_database_result_mappings(const char *daemon_path,
                              const char *directory)
{
    char socket_path[256];
    char daemon_log[256];
    char event_log[256];
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    received_frame_t response;
    begin_snapshot_t snapshot;
    pid_t daemon;
    int client;
    size_t length;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/mappings.sock",
                   directory);
    (void)snprintf(daemon_log, sizeof(daemon_log), "%s/mappings.log",
                   directory);
    (void)snprintf(event_log, sizeof(event_log), "%s/mappings.events",
                   directory);
    prepare_file(event_log);
    assert(setenv("FORTYTWO_TEST_EVENT_LOG", event_log, 1) == 0);
    daemon = start_daemon(daemon_path, socket_path, daemon_log, true, "10");

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "taken", "Taken User",
               "long-enough-password", "203.0.113.16");
    assert(receive_frame(client, &response) == 0);
    assert(error_code(&response) == FTAP_ERR_LOGIN_NAME_UNAVAILABLE);
    expect_closed(client);
    assert(close(client) == 0);

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "dberror", "Database Error",
               "long-enough-password", "203.0.113.17");
    assert(receive_frame(client, &response) == 0);
    assert(error_code(&response) == FTAP_ERR_DATABASE_UNAVAILABLE);
    expect_closed(client);
    assert(close(client) == 0);

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "dblimit", "Database Limit",
               "long-enough-password", "203.0.113.18");
    assert(receive_frame(client, &response) == 0);
    assert(error_code(&response) == FTAP_ERR_RATE_LIMITED);
    expect_closed(client);
    assert(close(client) == 0);

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1));
    send_begin(client, UINT64_C(2), "commitstale", "Commit Stale",
               "long-enough-password", "203.0.113.19");
    assert(receive_frame(client, &response) == 0);
    parse_begin_result(&response, UINT64_C(2), &snapshot);
    length = build_registration_id_request(
        frame, FTAP_MSG_REGISTRATION_COMMIT_REQUEST, UINT64_C(3),
        snapshot.registration_id, NULL);
    assert(send_all(client, frame, length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(error_code(&response) == FTAP_ERR_ACCOUNT_UNAVAILABLE);
    expect_closed(client);
    assert(close(client) == 0);
    wait_for_event(event_log,
                   "registration_abort:client_disconnected");

    stop_daemon(daemon);
}

int
main(int argc, char **argv)
{
    char directory_template[] = "/tmp/fortytwo-registration-test-XXXXXX";
    char *directory;

    assert(argc == 2);
    directory = mkdtemp(directory_template);
    assert(directory != NULL);

    test_disabled_and_password_policy(argv[1], directory);
    test_commit_lifecycle(argv[1], directory);
    test_abort_retry_collision_and_rate_limit(argv[1], directory);
    test_disconnect_bound_and_hash_pending(argv[1], directory);
    test_database_result_mappings(argv[1], directory);

    assert(unsetenv("FORTYTWO_TEST_EVENT_LOG") == 0);
    remove_test_directory(directory);
    (void)printf("authd registration server integration tests: OK\n");
    return 0;
}
