/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * End-to-end FTAP tests for the B3.7 daemon login coordinator.
 */

#include "ftap_codec.h"
#include "ftap_schema.h"

#include <assert.h>
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

#define TEST_TIMEOUT_MS 3000

typedef struct received_frame {
    ftap_frame_header_t header;
    uint8_t payload[FTAP_MAX_PAYLOAD_SIZE];
    size_t payload_length;
} received_frame_t;

static void
sleep_milliseconds(long milliseconds)
{
    struct timespec delay;

    delay.tv_sec = milliseconds / 1000L;
    delay.tv_nsec = (milliseconds % 1000L) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        /* Continue sleeping for the remaining duration. */
    }
}

static int
wait_for_fd(int fd, short events, int timeout_ms)
{
    struct pollfd poll_fd;
    int result;

    poll_fd.fd = fd;
    poll_fd.events = events;
    poll_fd.revents = 0;

    do {
        result = poll(&poll_fd, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);

    if (result <= 0) {
        return -1;
    }
    if ((poll_fd.revents & (POLLERR | POLLNVAL)) != 0) {
        return -1;
    }
    return 0;
}

static int
send_all_chunked(int fd, const uint8_t *buffer, size_t length, size_t chunk)
{
    size_t offset = 0U;

    while (offset < length) {
        size_t amount = length - offset;
        ssize_t sent;

        if (amount > chunk) {
            amount = chunk;
        }
        sent = send(fd, buffer + offset, amount, MSG_NOSIGNAL);
        if (sent > 0) {
            offset += (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (wait_for_fd(fd, POLLOUT, TEST_TIMEOUT_MS) != 0) {
                return -1;
            }
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
    ftap_status_t status;

    memset(frame, 0, sizeof(*frame));
    if (receive_exact(fd, header_bytes, sizeof(header_bytes)) != 0) {
        return -1;
    }

    status = ftap_frame_header_decode(header_bytes, sizeof(header_bytes),
                                      &frame->header);
    if (status != FTAP_STATUS_OK ||
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
build_hello(uint8_t frame[FTAP_MAX_FRAME_SIZE],
            uint64_t request_id,
            bool duplicate_client_name)
{
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;
    ftap_status_t status;
    uint8_t *payload = frame + FTAP_FRAME_HEADER_SIZE;

    status = ftap_tlv_writer_init(&writer, payload, FTAP_MAX_PAYLOAD_SIZE);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_CLIENT_NAME, 0,
        (const uint8_t *)"authd-integration-test",
        strlen("authd-integration-test"), FTAP_CLIENT_NAME_MAX);
    assert(status == FTAP_STATUS_OK);
    if (duplicate_client_name) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_CLIENT_NAME, 0,
            (const uint8_t *)"duplicate",
            strlen("duplicate"), FTAP_CLIENT_NAME_MAX);
        assert(status == FTAP_STATUS_OK);
    }
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_CLIENT_VERSION, 0,
        (const uint8_t *)"1.0", strlen("1.0"), FTAP_CLIENT_VERSION_MAX);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_u16(
        &writer, FTAP_FIELD_SUPPORTED_MAJOR, 0, FTAP_VERSION_MAJOR);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_u16(
        &writer, FTAP_FIELD_SUPPORTED_MINOR, 0, FTAP_VERSION_MINOR);
    assert(status == FTAP_STATUS_OK);

    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = FTAP_MSG_HELLO;
    header.flags = 0;
    header.payload_length = (uint32_t)writer.length;
    header.request_id = request_id;
    assert(ftap_frame_header_encode(frame, &header) == FTAP_STATUS_OK);

    return FTAP_FRAME_HEADER_SIZE + writer.length;
}

static size_t
build_password_request(uint8_t frame[FTAP_MAX_FRAME_SIZE],
                       uint64_t request_id,
                       const char *login_name,
                       const char *password)
{
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;
    ftap_status_t status;
    uint8_t *payload = frame + FTAP_FRAME_HEADER_SIZE;

    status = ftap_tlv_writer_init(&writer, payload, FTAP_MAX_PAYLOAD_SIZE);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_LOGIN_NAME, 0,
        (const uint8_t *)login_name, strlen(login_name), FTAP_LOGIN_NAME_MAX);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_PASSWORD, 0,
        (const uint8_t *)password, strlen(password), FTAP_PASSWORD_MAX);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_PROTOCOL, 0,
        (const uint8_t *)FTAP_PROTOCOL_SSH, strlen(FTAP_PROTOCOL_SSH),
        FTAP_PROTOCOL_NAME_MAX);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_SOURCE_IP, 0,
        (const uint8_t *)"192.0.2.10", strlen("192.0.2.10"),
        FTAP_IP_ADDRESS_MAX);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_TTY_DEVICE, 0,
        (const uint8_t *)"pts/42", strlen("pts/42"), FTAP_TTY_DEVICE_MAX);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_NODE_ID, 0,
        (const uint8_t *)"test-node", strlen("test-node"), FTAP_NODE_ID_MAX);
    assert(status == FTAP_STATUS_OK);
    status = ftap_tlv_writer_put_text(
        &writer, FTAP_FIELD_AUTH_METHOD, 0,
        (const uint8_t *)FTAP_AUTH_METHOD_PASSWORD,
        strlen(FTAP_AUTH_METHOD_PASSWORD), FTAP_AUTH_METHOD_MAX);
    assert(status == FTAP_STATUS_OK);

    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = FTAP_MSG_AUTH_PASSWORD_REQUEST;
    header.payload_length = (uint32_t)writer.length;
    header.request_id = request_id;
    assert(ftap_frame_header_encode(frame, &header) == FTAP_STATUS_OK);
    return FTAP_FRAME_HEADER_SIZE + writer.length;
}

static size_t
build_session_close(uint8_t frame[FTAP_MAX_FRAME_SIZE],
                    uint64_t request_id,
                    const char *ended_reason)
{
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;
    ftap_status_t status;
    uint8_t *payload = frame + FTAP_FRAME_HEADER_SIZE;

    status = ftap_tlv_writer_init(&writer, payload, FTAP_MAX_PAYLOAD_SIZE);
    assert(status == FTAP_STATUS_OK);
    if (ended_reason != NULL) {
        status = ftap_tlv_writer_put_text(
            &writer, FTAP_FIELD_ENDED_REASON, 0,
            (const uint8_t *)ended_reason, strlen(ended_reason),
            FTAP_ENDED_REASON_MAX);
        assert(status == FTAP_STATUS_OK);
    }

    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = FTAP_MSG_SESSION_CLOSE;
    header.payload_length = (uint32_t)writer.length;
    header.request_id = request_id;
    assert(ftap_frame_header_encode(frame, &header) == FTAP_STATUS_OK);
    return FTAP_FRAME_HEADER_SIZE + writer.length;
}

static void
send_session_close(int fd, uint64_t request_id, const char *ended_reason)
{
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    size_t length = build_session_close(frame, request_id, ended_reason);

    assert(send_all_chunked(fd, frame, length, length) == 0);
}

static uint32_t
error_code_from_frame(const received_frame_t *frame)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    uint32_t code = 0U;

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
            assert(ftap_tlv_get_u32(&field, &code) == FTAP_STATUS_OK);
        }
    }
    return code;
}

static uint32_t
retry_after_from_frame(const received_frame_t *frame)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    uint32_t retry_after = 0U;

    assert(ftap_tlv_reader_init(&reader, frame->payload,
                                frame->payload_length) == FTAP_STATUS_OK);
    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        assert(status == FTAP_STATUS_OK);
        if (field.type == FTAP_FIELD_RETRY_AFTER_MS) {
            assert(ftap_tlv_get_u32(&field, &retry_after) == FTAP_STATUS_OK);
        }
    }
    return retry_after;
}

static void
assert_authentication_result(const received_frame_t *frame,
                             uint64_t request_id)
{
    ftap_validation_error_t validation_error;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool user_id_seen = false;
    bool session_id_seen = false;

    assert(frame->header.message_type == FTAP_MSG_AUTH_PASSWORD_RESULT);
    assert(frame->header.request_id == request_id);
    assert(ftap_validate_message(FTAP_STATE_AUTHENTICATING,
                                 &frame->header,
                                 frame->payload,
                                 frame->payload_length,
                                 &validation_error) == FTAP_STATUS_OK);
    assert(ftap_tlv_reader_init(&reader, frame->payload,
                                frame->payload_length) == FTAP_STATUS_OK);
    for (;;) {
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        assert(status == FTAP_STATUS_OK);
        if (field.type == FTAP_FIELD_USER_ID ||
            field.type == FTAP_FIELD_SESSION_ID) {
            uint8_t uuid[FTAP_UUID_SIZE];
            size_t index;
            bool nonzero = false;
            assert(ftap_tlv_get_uuid(&field, uuid) == FTAP_STATUS_OK);
            for (index = 0U; index < sizeof(uuid); ++index) {
                nonzero = nonzero || uuid[index] != 0U;
            }
            assert(nonzero);
            if (field.type == FTAP_FIELD_USER_ID) {
                user_id_seen = true;
            } else {
                session_id_seen = true;
            }
        }
    }
    assert(user_id_seen && session_id_seen);
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

    /*
     * bind() creates the pathname before listen() makes the socket ready.
     * Retry that narrow startup window instead of making integration tests
     * depend on scheduler timing under sanitizer or thread-heavy builds.
     */
    for (elapsed = 0; elapsed < TEST_TIMEOUT_MS; elapsed += 10) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

        if (fd < 0) {
            return -1;
        }
        if (connect(fd, (const struct sockaddr *)&address,
                    (socklen_t)sizeof(address)) == 0) {
            return fd;
        }

        if (errno != ENOENT && errno != ECONNREFUSED && errno != EINTR) {
            int saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return -1;
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
             uid_t allowed_uid,
             const char *log_path,
             const char *hello_timeout,
             bool database_open_failure,
             const char *database_health_fail_after)
{
    pid_t child;
    char uid_text[32];

    (void)snprintf(uid_text, sizeof(uid_text), "%ju", (uintmax_t)allowed_uid);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        const char *max_clients = getenv("FORTYTWO_TEST_MAX_CLIENTS");
        const char *password_workers = getenv("FORTYTWO_TEST_PASSWORD_WORKERS");
        const char *password_capacity = getenv("FORTYTWO_TEST_PASSWORD_CAPACITY");
        int log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          (mode_t)0600);
        if (log_fd >= 0) {
            (void)dup2(log_fd, STDERR_FILENO);
            (void)close(log_fd);
        }
        if (database_open_failure) {
            assert(setenv("FORTYTWO_TEST_DB_OPEN_FAIL", "1", 1) == 0);
        }
        if (database_health_fail_after != NULL) {
            assert(setenv("FORTYTWO_TEST_DB_HEALTH_FAIL_AFTER",
                          database_health_fail_after, 1) == 0);
        }
        if (max_clients == NULL || max_clients[0] == '\0') {
            max_clients = "8";
        }
        if (password_workers == NULL || password_workers[0] == '\0') {
            password_workers = "2";
        }
        if (password_capacity == NULL || password_capacity[0] == '\0') {
            password_capacity = "16";
        }
        execl(daemon_path, daemon_path,
              "--socket", socket_path,
              "--socket-mode", "0600",
              "--allow-uid", uid_text,
              "--max-clients", max_clients,
              "--backlog", "8",
              "--hello-timeout-ms", hello_timeout,
              "--password-workers", password_workers,
              "--password-queue-capacity", password_capacity,
              "--db-health-interval-ms", "100",
              (char *)NULL);
        _exit(127);
    }
    return child;
}

static int
wait_for_socket(const char *path, pid_t child)
{
    int elapsed;

    for (elapsed = 0; elapsed < TEST_TIMEOUT_MS; elapsed += 10) {
        struct stat status;
        int child_status;
        pid_t wait_result;

        if (lstat(path, &status) == 0 && S_ISSOCK(status.st_mode)) {
            return 0;
        }
        wait_result = waitpid(child, &child_status, WNOHANG);
        if (wait_result == child) {
            return -1;
        }
        sleep_milliseconds(10);
    }
    return -1;
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
stop_daemon(pid_t child, bool expect_success)
{
    int status = 0;

    assert(kill(child, SIGTERM) == 0);
    if (wait_for_exit(child, TEST_TIMEOUT_MS, &status) != 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
        assert(!"daemon did not stop after SIGTERM");
    }
    assert(WIFEXITED(status));
    if (expect_success) {
        assert(WEXITSTATUS(status) == 0);
    }
}

static void
expect_connection_closed(int fd, int timeout_ms)
{
    struct pollfd poll_fd;
    uint8_t byte;
    ssize_t received;

    poll_fd.fd = fd;
    poll_fd.events = POLLIN | POLLHUP;
    poll_fd.revents = 0;
    assert(poll(&poll_fd, 1, timeout_ms) > 0);
    received = recv(fd, &byte, sizeof(byte), 0);
    assert(received == 0);
}

static void
perform_hello(int client, uint64_t request_id)
{
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    received_frame_t response;
    size_t frame_length = build_hello(frame, request_id, false);

    assert(send_all_chunked(client, frame, frame_length, frame_length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(response.header.message_type == FTAP_MSG_HELLO_OK);
    assert(response.header.request_id == request_id);
}

static void
send_password_request(int client,
                      uint64_t request_id,
                      const char *login_name,
                      const char *password)
{
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    size_t frame_length = build_password_request(
        frame, request_id, login_name, password);

    assert(send_all_chunked(client, frame, frame_length, frame_length) == 0);
}

static size_t
count_text_occurrences(const char *path, const char *needle)
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
prepare_event_log(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  (mode_t)0600);
    assert(fd >= 0);
    assert(close(fd) == 0);
    assert(setenv("FORTYTWO_TEST_EVENT_LOG", path, 1) == 0);
}

static void
clear_login_test_environment(void)
{
    assert(unsetenv("FORTYTWO_TEST_EVENT_LOG") == 0);
    assert(unsetenv("FORTYTWO_TEST_PASSWORD_DELAY_MS") == 0);
    assert(unsetenv("FORTYTWO_TEST_PASSWORD_WORKERS") == 0);
    assert(unsetenv("FORTYTWO_TEST_PASSWORD_CAPACITY") == 0);
    assert(unsetenv("FORTYTWO_TEST_MAX_CLIENTS") == 0);
    assert(unsetenv("FORTYTWO_TEST_FAIL_AUTH_RESULT_SEND") == 0);
}


static void
write_u32_big_endian(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static void
test_parallel_hello_clients(const char *socket_path)
{
    enum { CLIENT_COUNT = 8 };
    int clients[CLIENT_COUNT];
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    received_frame_t response;
    size_t frame_length;
    size_t index;

    for (index = 0U; index < CLIENT_COUNT; ++index) {
        clients[index] = connect_unix_socket(socket_path);
        assert(clients[index] >= 0);
        frame_length = build_hello(frame, UINT64_C(100) + index, false);
        assert(send_all_chunked(clients[index], frame, frame_length,
                                3U + index) == 0);
    }

    for (index = 0U; index < CLIENT_COUNT; ++index) {
        assert(receive_frame(clients[index], &response) == 0);
        assert(response.header.message_type == FTAP_MSG_HELLO_OK);
        assert(response.header.request_id == UINT64_C(100) + index);
        assert(close(clients[index]) == 0);
    }
}

static void
test_invalid_headers(const char *socket_path)
{
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    received_frame_t response;
    size_t frame_length;
    int client;

    /* An oversized declared payload is rejected from the header alone. */
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    frame_length = build_hello(frame, UINT64_C(200), false);
    (void)frame_length;
    write_u32_big_endian(frame + FTAP_HEADER_PAYLOAD_LENGTH_OFFSET,
                         FTAP_MAX_PAYLOAD_SIZE + UINT32_C(1));
    assert(send_all_chunked(client, frame, FTAP_FRAME_HEADER_SIZE,
                            FTAP_FRAME_HEADER_SIZE) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(error_code_from_frame(&response) == FTAP_ERR_MESSAGE_TOO_LARGE);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);

    /* With invalid magic, no request metadata is trusted and the peer closes. */
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    frame_length = build_hello(frame, UINT64_C(201), false);
    frame[0] = (uint8_t)'X';
    assert(send_all_chunked(client, frame, frame_length, frame_length) == 0);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);
}

static void
test_hello_and_protocol_errors(const char *daemon_path,
                               const char *directory)
{
    char socket_path[256];
    char log_path[256];
    uint8_t frame[FTAP_MAX_FRAME_SIZE];
    size_t frame_length;
    received_frame_t response;
    ftap_validation_error_t validation_error;
    pid_t daemon;
    int client;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/auth.sock", directory);
    (void)snprintf(log_path, sizeof(log_path), "%s/auth.log", directory);
    daemon = start_daemon(daemon_path, socket_path, geteuid(), log_path, "300", false, NULL);
    assert(wait_for_socket(socket_path, daemon) == 0);

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    frame_length = build_hello(frame, UINT64_C(1), false);
    assert(send_all_chunked(client, frame, frame_length, 1U) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(response.header.message_type == FTAP_MSG_HELLO_OK);
    assert(response.header.request_id == UINT64_C(1));
    assert(ftap_validate_message(FTAP_STATE_CONNECTED,
                                 &response.header,
                                 response.payload,
                                 response.payload_length,
                                 &validation_error) == FTAP_STATUS_OK);

    /* A second HELLO is invalid after the connection reached HELLO_COMPLETE. */
    frame_length = build_hello(frame, UINT64_C(2), false);
    assert(send_all_chunked(client, frame, frame_length, frame_length) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(response.header.request_id == UINT64_C(2));
    assert(error_code_from_frame(&response) == FTAP_ERR_INVALID_STATE);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);

    /* Duplicate non-repeatable TLV fields are a protocol error. */
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    frame_length = build_hello(frame, UINT64_C(3), true);
    assert(send_all_chunked(client, frame, frame_length, 7U) == 0);
    assert(receive_frame(client, &response) == 0);
    assert(error_code_from_frame(&response) == FTAP_ERR_PROTOCOL);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);

    test_parallel_hello_clients(socket_path);
    test_invalid_headers(socket_path);

    /* A connected peer that never sends HELLO is closed at the deadline. */
    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);

    stop_daemon(daemon, true);
    assert(access(socket_path, F_OK) != 0 && errno == ENOENT);
}

static void
test_unauthorized_peer(const char *daemon_path, const char *directory)
{
    char socket_path[256];
    char log_path[256];
    uid_t denied_uid = geteuid() == (uid_t)1 ? (uid_t)2 : (uid_t)1;
    pid_t daemon;
    int client;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/denied.sock", directory);
    (void)snprintf(log_path, sizeof(log_path), "%s/denied.log", directory);
    daemon = start_daemon(daemon_path, socket_path, denied_uid, log_path, "300", false, NULL);
    assert(wait_for_socket(socket_path, daemon) == 0);

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);

    stop_daemon(daemon, true);
    assert(access(socket_path, F_OK) != 0 && errno == ENOENT);
}

static void
test_existing_non_socket_is_refused(const char *daemon_path,
                                    const char *directory)
{
    char socket_path[256];
    char target_path[256];
    char log_path[256];
    int target_fd;
    int status = 0;
    pid_t daemon;
    struct stat link_status;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/link.sock", directory);
    (void)snprintf(target_path, sizeof(target_path), "%s/target", directory);
    (void)snprintf(log_path, sizeof(log_path), "%s/link.log", directory);

    target_fd = open(target_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                     (mode_t)0600);
    assert(target_fd >= 0);
    assert(close(target_fd) == 0);
    assert(symlink(target_path, socket_path) == 0);

    daemon = start_daemon(daemon_path, socket_path, geteuid(), log_path, "300", false, NULL);
    assert(wait_for_exit(daemon, TEST_TIMEOUT_MS, &status) == 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) != 0);
    assert(lstat(socket_path, &link_status) == 0);
    assert(S_ISLNK(link_status.st_mode));
    assert(unlink(socket_path) == 0);
    assert(unlink(target_path) == 0);
}


static void
test_database_open_failure_is_fail_closed(const char *daemon_path,
                                          const char *directory)
{
    char socket_path[256];
    char log_path[256];
    int status = 0;
    pid_t daemon;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/db-open.sock",
                   directory);
    (void)snprintf(log_path, sizeof(log_path), "%s/db-open.log", directory);

    daemon = start_daemon(daemon_path, socket_path, geteuid(), log_path,
                          "300", true, NULL);
    assert(wait_for_exit(daemon, TEST_TIMEOUT_MS, &status) == 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) != 0);
    assert(access(socket_path, F_OK) != 0 && errno == ENOENT);
}

static void
test_database_health_failure_stops_daemon(const char *daemon_path,
                                          const char *directory)
{
    char socket_path[256];
    char log_path[256];
    int status = 0;
    pid_t daemon;
    int client;

    (void)snprintf(socket_path, sizeof(socket_path), "%s/db-health.sock",
                   directory);
    (void)snprintf(log_path, sizeof(log_path), "%s/db-health.log", directory);

    daemon = start_daemon(daemon_path, socket_path, geteuid(), log_path,
                          "1000", false, "1");
    assert(wait_for_socket(socket_path, daemon) == 0);

    client = connect_unix_socket(socket_path);
    assert(client >= 0);
    assert(wait_for_exit(daemon, TEST_TIMEOUT_MS, &status) == 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) != 0);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);
    assert(access(socket_path, F_OK) != 0 && errno == ENOENT);
}

typedef struct login_fixture {
    char socket_path[256];
    char log_path[256];
    char event_path[256];
    pid_t daemon;
} login_fixture_t;

static void
start_login_fixture(login_fixture_t *fixture,
                    const char *daemon_path,
                    const char *directory,
                    const char *name)
{
    (void)snprintf(fixture->socket_path, sizeof(fixture->socket_path),
                   "%s/%s.sock", directory, name);
    (void)snprintf(fixture->log_path, sizeof(fixture->log_path),
                   "%s/%s.log", directory, name);
    (void)snprintf(fixture->event_path, sizeof(fixture->event_path),
                   "%s/%s.events", directory, name);
    prepare_event_log(fixture->event_path);
    fixture->daemon = start_daemon(daemon_path, fixture->socket_path,
                                   geteuid(), fixture->log_path,
                                   "1000", false, NULL);
    assert(wait_for_socket(fixture->socket_path, fixture->daemon) == 0);
}

static void
finish_login_fixture(login_fixture_t *fixture, bool daemon_running)
{
    if (daemon_running) {
        stop_daemon(fixture->daemon, true);
    }
    assert(access(fixture->socket_path, F_OK) != 0 && errno == ENOENT);
    assert(unlink(fixture->log_path) == 0);
    assert(unlink(fixture->event_path) == 0);
    clear_login_test_environment();
}

static void
expect_login_error(const char *socket_path,
                   uint64_t request_id,
                   const char *login_name,
                   const char *password,
                   uint32_t expected_error)
{
    received_frame_t response;
    int client = connect_unix_socket(socket_path);

    assert(client >= 0);
    perform_hello(client, request_id - UINT64_C(1));
    send_password_request(client, request_id, login_name, password);
    assert(receive_frame(client, &response) == 0);
    assert(response.header.request_id == request_id);
    assert(error_code_from_frame(&response) == expected_error);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);
}

static void
test_password_login_outcomes(const char *daemon_path, const char *directory)
{
    login_fixture_t fixture;
    received_frame_t response;
    int client;

    assert(setenv("FORTYTWO_TEST_PASSWORD_DELAY_MS", "20", 1) == 0);
    start_login_fixture(&fixture, daemon_path, directory, "login-outcomes");

    client = connect_unix_socket(fixture.socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1000));
    send_password_request(client, UINT64_C(1001), "Alice", "secret");
    assert(receive_frame(client, &response) == 0);
    assert_authentication_result(&response, UINT64_C(1001));
    send_session_close(client, UINT64_C(1002), NULL);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);
    sleep_milliseconds(50);

    expect_login_error(fixture.socket_path, UINT64_C(1011),
                       "alice", "wrong", FTAP_ERR_INVALID_CREDENTIALS);
    expect_login_error(fixture.socket_path, UINT64_C(1021),
                       "unknown", "wrong", FTAP_ERR_INVALID_CREDENTIALS);
    expect_login_error(fixture.socket_path, UINT64_C(1031),
                       "locked", "wrong", FTAP_ERR_INVALID_CREDENTIALS);
    expect_login_error(fixture.socket_path, UINT64_C(1041),
                       "disabled", "wrong", FTAP_ERR_INVALID_CREDENTIALS);

    client = connect_unix_socket(fixture.socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(1050));
    send_password_request(client, UINT64_C(1051), "throttled", "wrong");
    assert(receive_frame(client, &response) == 0);
    assert(error_code_from_frame(&response) == FTAP_ERR_RATE_LIMITED);
    assert(retry_after_from_frame(&response) == UINT32_C(1234));
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);

    expect_login_error(fixture.socket_path, UINT64_C(1061),
                       "stale", "secret", FTAP_ERR_INVALID_CREDENTIALS);
    expect_login_error(fixture.socket_path, UINT64_C(1071),
                       "sessionerror", "secret",
                       FTAP_ERR_DATABASE_UNAVAILABLE);
    expect_login_error(fixture.socket_path, UINT64_C(1081),
                       "invalidhash", "secret", FTAP_ERR_INTERNAL);

    stop_daemon(fixture.daemon, true);
    assert(count_text_occurrences(fixture.event_path,
                                  "session_create:alice") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "session_close:normal_logout") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "password_failure:wrong_password") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "rejection:unknown_user") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "rejection:account_locked") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "rejection:account_disabled") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "rejection:temporarily_throttled") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "rejection:stale_login_state") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "password_verify:dummy") == 3U);
    assert(count_text_occurrences(fixture.event_path,
                                  "password_verify:real") == 5U);
    finish_login_fixture(&fixture, false);
}

static void
test_disconnect_and_slot_generation(const char *daemon_path,
                                    const char *directory)
{
    login_fixture_t fixture;
    received_frame_t response;
    int first;
    int second;

    assert(setenv("FORTYTWO_TEST_PASSWORD_DELAY_MS", "200", 1) == 0);
    assert(setenv("FORTYTWO_TEST_MAX_CLIENTS", "1", 1) == 0);
    assert(setenv("FORTYTWO_TEST_PASSWORD_WORKERS", "2", 1) == 0);
    assert(setenv("FORTYTWO_TEST_PASSWORD_CAPACITY", "4", 1) == 0);
    start_login_fixture(&fixture, daemon_path, directory, "generation");

    first = connect_unix_socket(fixture.socket_path);
    assert(first >= 0);
    perform_hello(first, UINT64_C(2000));
    send_password_request(first, UINT64_C(2001), "alice", "secret");
    assert(close(first) == 0);
    sleep_milliseconds(50);

    second = connect_unix_socket(fixture.socket_path);
    assert(second >= 0);
    perform_hello(second, UINT64_C(2010));
    send_password_request(second, UINT64_C(2011), "alice", "secret");
    assert(receive_frame(second, &response) == 0);
    assert_authentication_result(&response, UINT64_C(2011));
    assert(close(second) == 0);
    sleep_milliseconds(50);

    stop_daemon(fixture.daemon, true);
    assert(count_text_occurrences(fixture.event_path,
                                  "session_create:alice") == 1U);
    finish_login_fixture(&fixture, false);
}

static void
test_duplicate_request_and_worker_overload(const char *daemon_path,
                                           const char *directory)
{
    login_fixture_t fixture;
    received_frame_t response;
    int first;
    int second;

    assert(setenv("FORTYTWO_TEST_PASSWORD_DELAY_MS", "250", 1) == 0);
    assert(setenv("FORTYTWO_TEST_PASSWORD_WORKERS", "1", 1) == 0);
    assert(setenv("FORTYTWO_TEST_PASSWORD_CAPACITY", "1", 1) == 0);
    start_login_fixture(&fixture, daemon_path, directory, "overload");

    first = connect_unix_socket(fixture.socket_path);
    assert(first >= 0);
    perform_hello(first, UINT64_C(3000));
    send_password_request(first, UINT64_C(3001), "alice", "secret");
    send_password_request(first, UINT64_C(3002), "alice", "secret");
    assert(receive_frame(first, &response) == 0);
    assert(response.header.request_id == UINT64_C(3002));
    assert(error_code_from_frame(&response) == FTAP_ERR_INVALID_STATE);
    expect_connection_closed(first, TEST_TIMEOUT_MS);
    assert(close(first) == 0);
    sleep_milliseconds(300);

    second = connect_unix_socket(fixture.socket_path);
    assert(second >= 0);
    perform_hello(second, UINT64_C(3010));
    send_password_request(second, UINT64_C(3011), "alice", "secret");

    first = connect_unix_socket(fixture.socket_path);
    assert(first >= 0);
    perform_hello(first, UINT64_C(3020));
    send_password_request(first, UINT64_C(3021), "alice", "secret");
    assert(receive_frame(first, &response) == 0);
    assert(error_code_from_frame(&response) == FTAP_ERR_INTERNAL);
    expect_connection_closed(first, TEST_TIMEOUT_MS);
    assert(close(first) == 0);
    assert(close(second) == 0);
    sleep_milliseconds(300);

    stop_daemon(fixture.daemon, true);
    assert(count_text_occurrences(fixture.event_path,
                                  "rejection:password_worker_overloaded") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "session_create:") == 0U);
    finish_login_fixture(&fixture, false);
}

static void
test_shutdown_with_running_job(const char *daemon_path,
                               const char *directory)
{
    login_fixture_t fixture;
    int client;

    assert(setenv("FORTYTWO_TEST_PASSWORD_DELAY_MS", "250", 1) == 0);
    start_login_fixture(&fixture, daemon_path, directory, "shutdown-job");
    client = connect_unix_socket(fixture.socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(4000));
    send_password_request(client, UINT64_C(4001), "alice", "secret");
    stop_daemon(fixture.daemon, true);
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);
    assert(count_text_occurrences(fixture.event_path,
                                  "session_create:") == 0U);
    finish_login_fixture(&fixture, false);
}

static void
test_failed_authentication_response_closes_session(
    const char *daemon_path,
    const char *directory)
{
    login_fixture_t fixture;
    int client;

    assert(setenv("FORTYTWO_TEST_FAIL_AUTH_RESULT_SEND", "1", 1) == 0);
    start_login_fixture(&fixture, daemon_path, directory, "send-failure");
    client = connect_unix_socket(fixture.socket_path);
    assert(client >= 0);
    perform_hello(client, UINT64_C(5000));
    send_password_request(client, UINT64_C(5001), "alice", "secret");
    expect_connection_closed(client, TEST_TIMEOUT_MS);
    assert(close(client) == 0);
    sleep_milliseconds(50);
    stop_daemon(fixture.daemon, true);
    assert(count_text_occurrences(fixture.event_path,
                                  "session_create:alice") == 1U);
    assert(count_text_occurrences(fixture.event_path,
                                  "session_close:auth_response_failed") == 1U);
    finish_login_fixture(&fixture, false);
}

int
main(int argc, char *argv[])
{
    char directory_template[] = "/tmp/fortytwo-authd-test-XXXXXX";
    char *directory;

    assert(argc == 2);
    directory = mkdtemp(directory_template);
    assert(directory != NULL);

    test_hello_and_protocol_errors(argv[1], directory);
    test_unauthorized_peer(argv[1], directory);
    test_existing_non_socket_is_refused(argv[1], directory);
    test_database_open_failure_is_fail_closed(argv[1], directory);
    test_database_health_failure_stops_daemon(argv[1], directory);
    test_password_login_outcomes(argv[1], directory);
    test_disconnect_and_slot_generation(argv[1], directory);
    test_duplicate_request_and_worker_overload(argv[1], directory);
    test_shutdown_with_running_job(argv[1], directory);
    test_failed_authentication_response_closes_session(argv[1], directory);

    {
        static const char *const logs[] = {
            "auth.log", "denied.log", "link.log",
            "db-open.log", "db-health.log"
        };
        size_t index;
        for (index = 0U; index < sizeof(logs) / sizeof(logs[0]); ++index) {
            char path[256];
            (void)snprintf(path, sizeof(path), "%s/%s", directory, logs[index]);
            assert(unlink(path) == 0);
        }
        assert(rmdir(directory) == 0);
    }

    (void)puts("authd integration tests: OK");
    return 0;
}
