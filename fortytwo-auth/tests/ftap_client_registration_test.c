/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ftap_client.h"
#include "ftap_schema.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_TIMEOUT_MS UINT32_C(2000)

typedef struct received_frame {
    ftap_frame_header_t header;
    uint8_t payload[FTAP_MAX_PAYLOAD_SIZE];
    size_t payload_length;
} received_frame_t;

typedef enum server_script {
    SERVER_COMMIT_SUCCESS = 0,
    SERVER_ABORT_SUCCESS,
    SERVER_BEGIN_PASSWORD_ERROR,
    SERVER_COMMIT_IDENTITY_MISMATCH
} server_script_t;

static const uint8_t registration_id[FTAP_UUID_SIZE] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t user_id[FTAP_UUID_SIZE] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static const uint8_t session_id[FTAP_UUID_SIZE] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

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
        return -1;
    }
    return 0;
}

static int
receive_exact(int fd, uint8_t *buffer, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t received = recv(fd, buffer + offset, length - offset, 0);
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
    uint8_t header[FTAP_FRAME_HEADER_SIZE];

    memset(frame, 0, sizeof(*frame));
    if (receive_exact(fd, header, sizeof(header)) != 0 ||
        ftap_frame_header_decode(header, sizeof(header), &frame->header) !=
            FTAP_STATUS_OK ||
        frame->header.payload_length > FTAP_MAX_PAYLOAD_SIZE) {
        return -1;
    }
    frame->payload_length = frame->header.payload_length;
    if (frame->payload_length > 0U &&
        receive_exact(fd, frame->payload, frame->payload_length) != 0) {
        return -1;
    }
    return 0;
}

static size_t
finish_frame(uint8_t frame[FTAP_MAX_FRAME_SIZE],
             const ftap_tlv_writer_t *writer,
             uint16_t message_type,
             uint16_t flags,
             uint64_t request_id)
{
    ftap_frame_header_t header;

    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = message_type;
    header.flags = flags;
    header.payload_length = (uint32_t)writer->length;
    header.request_id = request_id;
    assert(ftap_frame_header_encode(frame, &header) == FTAP_STATUS_OK);
    return FTAP_FRAME_HEADER_SIZE + writer->length;
}

static void
put_text(ftap_tlv_writer_t *writer, uint16_t type, const char *text,
         size_t maximum)
{
    assert(ftap_tlv_writer_put_text(
               writer, type, 0, (const uint8_t *)text, strlen(text),
               maximum) == FTAP_STATUS_OK);
}

static size_t
build_begin_result(uint8_t frame[FTAP_MAX_FRAME_SIZE], uint64_t request_id)
{
    ftap_tlv_writer_t writer;

    assert(ftap_tlv_writer_init(&writer, frame + FTAP_FRAME_HEADER_SIZE,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_REGISTRATION_ID, 0,
                                    registration_id) == FTAP_STATUS_OK);
    put_text(&writer, FTAP_FIELD_REGISTRATION_STATE,
             FTAP_REGISTRATION_STATE_PENDING_LEGACY,
             FTAP_REGISTRATION_STATE_MAX);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_USER_ID, 0,
                                    user_id) == FTAP_STATUS_OK);
    put_text(&writer, FTAP_FIELD_LOGIN_NAME, "newuser", FTAP_LOGIN_NAME_MAX);
    put_text(&writer, FTAP_FIELD_DISPLAY_NAME, "New User",
             FTAP_DISPLAY_NAME_MAX);
    put_text(&writer, FTAP_FIELD_LEGACY_NAME, "newuser",
             FTAP_LEGACY_NAME_MAX);
    put_text(&writer, FTAP_FIELD_ACCOUNT_STATE, FTAP_ACCOUNT_STATE_PENDING,
             FTAP_ACCOUNT_STATE_MAX);
    return finish_frame(frame, &writer, FTAP_MSG_REGISTRATION_BEGIN_RESULT,
                        FTAP_FRAME_FLAG_RESPONSE, request_id);
}

static size_t
build_abort_result(uint8_t frame[FTAP_MAX_FRAME_SIZE], uint64_t request_id)
{
    ftap_tlv_writer_t writer;

    assert(ftap_tlv_writer_init(&writer, frame + FTAP_FRAME_HEADER_SIZE,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_REGISTRATION_ID, 0,
                                    registration_id) == FTAP_STATUS_OK);
    put_text(&writer, FTAP_FIELD_REGISTRATION_STATE,
             FTAP_REGISTRATION_STATE_ABORTED,
             FTAP_REGISTRATION_STATE_MAX);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_USER_ID, 0,
                                    user_id) == FTAP_STATUS_OK);
    return finish_frame(frame, &writer, FTAP_MSG_REGISTRATION_ABORT_RESULT,
                        FTAP_FRAME_FLAG_RESPONSE, request_id);
}

static size_t
build_commit_result(uint8_t frame[FTAP_MAX_FRAME_SIZE], uint64_t request_id,
                    bool mismatch)
{
    ftap_tlv_writer_t writer;
    uint8_t returned_user_id[FTAP_UUID_SIZE];

    memcpy(returned_user_id, user_id, sizeof(returned_user_id));
    if (mismatch) {
        returned_user_id[0] ^= UINT8_C(0xff);
    }
    assert(ftap_tlv_writer_init(&writer, frame + FTAP_FRAME_HEADER_SIZE,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_REGISTRATION_ID, 0,
                                    registration_id) == FTAP_STATUS_OK);
    put_text(&writer, FTAP_FIELD_REGISTRATION_STATE,
             FTAP_REGISTRATION_STATE_COMPLETED,
             FTAP_REGISTRATION_STATE_MAX);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_USER_ID, 0,
                                    returned_user_id) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_SESSION_ID, 0,
                                    session_id) == FTAP_STATUS_OK);
    put_text(&writer, FTAP_FIELD_LOGIN_NAME, "newuser", FTAP_LOGIN_NAME_MAX);
    put_text(&writer, FTAP_FIELD_DISPLAY_NAME, "New User",
             FTAP_DISPLAY_NAME_MAX);
    put_text(&writer, FTAP_FIELD_LEGACY_NAME, "newuser",
             FTAP_LEGACY_NAME_MAX);
    put_text(&writer, FTAP_FIELD_ACCOUNT_STATE, FTAP_ACCOUNT_STATE_ACTIVE,
             FTAP_ACCOUNT_STATE_MAX);
    put_text(&writer, FTAP_FIELD_PROTOCOL, FTAP_PROTOCOL_TELNET,
             FTAP_PROTOCOL_NAME_MAX);
    put_text(&writer, FTAP_FIELD_AUTH_METHOD, FTAP_AUTH_METHOD_PASSWORD,
             FTAP_AUTH_METHOD_MAX);
    assert(ftap_tlv_writer_put_u64(&writer, FTAP_FIELD_AUTH_EPOCH, 0,
                                   UINT64_C(1)) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_u64(&writer, FTAP_FIELD_AUTHZ_REVISION, 0,
                                   UINT64_C(2)) == FTAP_STATUS_OK);
    return finish_frame(frame, &writer, FTAP_MSG_REGISTRATION_COMMIT_RESULT,
                        FTAP_FRAME_FLAG_RESPONSE, request_id);
}

static size_t
build_error(uint8_t frame[FTAP_MAX_FRAME_SIZE], uint64_t request_id,
            uint32_t error_code)
{
    ftap_tlv_writer_t writer;

    assert(ftap_tlv_writer_init(&writer, frame + FTAP_FRAME_HEADER_SIZE,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_u32(&writer, FTAP_FIELD_ERROR_CODE, 0,
                                   error_code) == FTAP_STATUS_OK);
    return finish_frame(frame, &writer, FTAP_MSG_ERROR,
                        (uint16_t)(FTAP_FRAME_FLAG_RESPONSE |
                                   FTAP_FRAME_FLAG_ERROR),
                        request_id);
}

static void
assert_begin_request(const received_frame_t *frame)
{
    ftap_validation_error_t validation_error;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool password_seen = false;
    bool source_seen = false;

    assert(frame->header.message_type == FTAP_MSG_REGISTRATION_BEGIN_REQUEST);
    assert(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &frame->header,
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
        if (field.type == FTAP_FIELD_PASSWORD) {
            assert(field.length == 13U);
            assert(memcmp(field.value, "correct horse", 13U) == 0);
            password_seen = true;
        } else if (field.type == FTAP_FIELD_SOURCE_IP) {
            assert(field.length == strlen("192.0.2.42"));
            assert(memcmp(field.value, "192.0.2.42", field.length) == 0);
            source_seen = true;
        }
    }
    assert(password_seen && source_seen);
}

static void
assert_registration_id_request(const received_frame_t *frame,
                               uint16_t message_type,
                               const char *expected_reason)
{
    ftap_validation_error_t validation_error;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool id_seen = false;
    bool reason_seen = false;

    assert(frame->header.message_type == message_type);
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
            assert(memcmp(value, registration_id, FTAP_UUID_SIZE) == 0);
            id_seen = true;
        } else if (field.type == FTAP_FIELD_REGISTRATION_REASON) {
            assert(expected_reason != NULL);
            assert(field.length == strlen(expected_reason));
            assert(memcmp(field.value, expected_reason, field.length) == 0);
            reason_seen = true;
        } else {
            assert(false);
        }
    }
    assert(id_seen);
    assert(reason_seen == (expected_reason != NULL));
}

static void
run_server(int fd, server_script_t script)
{
    received_frame_t request;
    uint8_t response[FTAP_MAX_FRAME_SIZE];
    size_t length;

    assert(receive_frame(fd, &request) == 0);
    assert_begin_request(&request);
    if (script == SERVER_BEGIN_PASSWORD_ERROR) {
        length = build_error(response, request.header.request_id,
                             FTAP_ERR_PASSWORD_POLICY);
        assert(send_all(fd, response, length) == 0);
        (void)close(fd);
        _exit(EXIT_SUCCESS);
    }

    length = build_begin_result(response, request.header.request_id);
    assert(send_all(fd, response, length) == 0);
    assert(receive_frame(fd, &request) == 0);

    if (script == SERVER_ABORT_SUCCESS) {
        assert_registration_id_request(
            &request, FTAP_MSG_REGISTRATION_ABORT_REQUEST,
            FTAP_REGISTRATION_REASON_LEGACY_WRITE_FAILED);
        length = build_abort_result(response, request.header.request_id);
    } else {
        assert_registration_id_request(
            &request, FTAP_MSG_REGISTRATION_COMMIT_REQUEST, NULL);
        length = build_commit_result(
            response, request.header.request_id,
            script == SERVER_COMMIT_IDENTITY_MISMATCH);
    }
    assert(send_all(fd, response, length) == 0);
    (void)close(fd);
    _exit(EXIT_SUCCESS);
}

static pid_t
start_server(int sockets[2], server_script_t script)
{
    pid_t child;

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        (void)close(sockets[0]);
        run_server(sockets[1], script);
    }
    (void)close(sockets[1]);
    return child;
}

static void
wait_server(pid_t child)
{
    int status;

    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void
prepare_client(ftap_client_t *client, int fd)
{
    ftap_client_init(client, TEST_TIMEOUT_MS);
    client->fd = fd;
    client->state = FTAP_STATE_HELLO_COMPLETE;
}

static void
begin_registration(ftap_client_t *client,
                   ftap_registration_context_t *registration,
                   ftap_client_error_t *error)
{
    static const uint8_t password[] = "correct horse";
    const ftap_registration_metadata_t metadata = {
        FTAP_PROTOCOL_TELNET,
        "192.0.2.42",
        "/dev/pts/42",
        "telnet-test"
    };

    assert(ftap_client_registration_begin(
               client, "NewUser", "New User", password,
               sizeof(password) - 1U, &metadata, registration, error) == 0);
    assert(client->state == FTAP_STATE_REGISTERING);
    assert(memcmp(registration->registration_id, registration_id,
                  FTAP_UUID_SIZE) == 0);
    assert(memcmp(registration->user_id, user_id, FTAP_UUID_SIZE) == 0);
    assert(strcmp(registration->login_name, "newuser") == 0);
    assert(strcmp(registration->display_name, "New User") == 0);
    assert(strcmp(registration->legacy_name, "newuser") == 0);
}

static void
test_commit_success(void)
{
    int sockets[2];
    pid_t child = start_server(sockets, SERVER_COMMIT_SUCCESS);
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_registration_context_t registration;
    ftap_terminal_context_t context;

    prepare_client(&client, sockets[0]);
    begin_registration(&client, &registration, &error);
    assert(ftap_client_registration_commit(
               &client, &registration, &context, &error) == 0);
    assert(client.state == FTAP_STATE_SESSION_BOUND);
    assert(memcmp(context.session_id, session_id, FTAP_UUID_SIZE) == 0);
    assert(strcmp(context.protocol, FTAP_PROTOCOL_TELNET) == 0);
    assert(strcmp(context.auth_method, FTAP_AUTH_METHOD_PASSWORD) == 0);
    assert(context.auth_epoch == UINT64_C(1));
    assert(context.authz_revision == UINT64_C(2));
    assert(!error.server_error && !error.outcome_unknown);
    ftap_client_close(&client);
    wait_server(child);
}

static void
test_abort_success(void)
{
    int sockets[2];
    pid_t child = start_server(sockets, SERVER_ABORT_SUCCESS);
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_registration_context_t registration;

    prepare_client(&client, sockets[0]);
    begin_registration(&client, &registration, &error);
    assert(ftap_client_registration_abort(
               &client, &registration,
               FTAP_REGISTRATION_REASON_LEGACY_WRITE_FAILED,
               &error) == 0);
    assert(client.state == FTAP_STATE_HELLO_COMPLETE);
    assert(!error.server_error && !error.outcome_unknown);
    ftap_client_close(&client);
    wait_server(child);
}

static void
test_begin_server_error(void)
{
    int sockets[2];
    pid_t child = start_server(sockets, SERVER_BEGIN_PASSWORD_ERROR);
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_registration_context_t registration;
    static const uint8_t password[] = "correct horse";
    const ftap_registration_metadata_t metadata = {
        FTAP_PROTOCOL_TELNET, "192.0.2.42", NULL, NULL
    };

    prepare_client(&client, sockets[0]);
    assert(ftap_client_registration_begin(
               &client, "newuser", "New User", password,
               sizeof(password) - 1U, &metadata, &registration,
               &error) != 0);
    assert(client.state == FTAP_STATE_CLOSING);
    assert(error.server_error);
    assert(!error.outcome_unknown);
    assert(error.protocol_error == FTAP_ERR_PASSWORD_POLICY);
    ftap_client_close(&client);
    wait_server(child);
}

static void
test_commit_identity_mismatch_is_unknown(void)
{
    int sockets[2];
    pid_t child = start_server(sockets, SERVER_COMMIT_IDENTITY_MISMATCH);
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_registration_context_t registration;
    ftap_terminal_context_t context;

    prepare_client(&client, sockets[0]);
    begin_registration(&client, &registration, &error);
    assert(ftap_client_registration_commit(
               &client, &registration, &context, &error) != 0);
    assert(client.state == FTAP_STATE_CLOSING);
    assert(error.outcome_unknown);
    assert(!error.server_error);
    assert(context.login_name[0] == '\0');
    ftap_client_close(&client);
    wait_server(child);
}

static void
test_argument_guards(void)
{
    ftap_client_t client;
    ftap_client_error_t error;
    ftap_registration_context_t registration;

    ftap_client_init(&client, TEST_TIMEOUT_MS);
    client.state = FTAP_STATE_REGISTERING;
    memset(&registration, 0, sizeof(registration));
    assert(ftap_client_registration_abort(
               &client, &registration, "database_failure", &error) != 0);
    assert(error.status == FTAP_STATUS_ERR_INVALID_STATE);
    assert(!error.server_error && !error.outcome_unknown);
}

int
main(void)
{
    test_commit_success();
    test_abort_success();
    test_begin_server_error();
    test_commit_identity_mismatch_is_unknown();
    test_argument_guards();
    (void)puts("FTAP client registration tests: OK");
    return EXIT_SUCCESS;
}
