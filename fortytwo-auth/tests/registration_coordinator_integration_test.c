/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "registration_coordinator.h"
#include "ftap_schema.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#pragma pack(push, 1)
#include "../../lib/users.h"
#pragma pack(pop)

#define TEST_TIMEOUT_MS UINT32_C(2000)

typedef enum server_script {
    SERVER_SUCCESS = 0,
    SERVER_COMMIT_REPLY_LOST,
    SERVER_EXPECT_ABORT
} server_script_t;

typedef struct received_frame {
    ftap_frame_header_t header;
    uint8_t payload[FTAP_MAX_PAYLOAD_SIZE];
    size_t payload_length;
} received_frame_t;

typedef struct integration_fixture {
    char root[PATH_MAX];
    char etc[PATH_MAX];
    char runtime_parent[PATH_MAX];
    char users_directory[PATH_MAX];
    char users_file[PATH_MAX];
} integration_fixture_t;

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

static void
write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;
    size_t completed = 0U;

    while (completed < length) {
        ssize_t written = write(fd, bytes + completed, length - completed);

        if (written > 0) {
            completed += (size_t)written;
        } else {
            assert(written < 0 && errno == EINTR);
        }
    }
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
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
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
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
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
             uint64_t request_id)
{
    ftap_frame_header_t header;

    memset(&header, 0, sizeof(header));
    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = message_type;
    header.flags = FTAP_FRAME_FLAG_RESPONSE;
    header.payload_length = (uint32_t)writer->length;
    header.request_id = request_id;
    assert(ftap_frame_header_encode(frame, &header) == FTAP_STATUS_OK);
    return FTAP_FRAME_HEADER_SIZE + writer->length;
}

static void
put_text(ftap_tlv_writer_t *writer,
         uint16_t type,
         const char *text,
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
                        request_id);
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
                        request_id);
}

static size_t
build_commit_result(uint8_t frame[FTAP_MAX_FRAME_SIZE], uint64_t request_id)
{
    ftap_tlv_writer_t writer;

    assert(ftap_tlv_writer_init(&writer, frame + FTAP_FRAME_HEADER_SIZE,
                                FTAP_MAX_PAYLOAD_SIZE) == FTAP_STATUS_OK);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_REGISTRATION_ID, 0,
                                    registration_id) == FTAP_STATUS_OK);
    put_text(&writer, FTAP_FIELD_REGISTRATION_STATE,
             FTAP_REGISTRATION_STATE_COMPLETED,
             FTAP_REGISTRATION_STATE_MAX);
    assert(ftap_tlv_writer_put_uuid(&writer, FTAP_FIELD_USER_ID, 0,
                                    user_id) == FTAP_STATUS_OK);
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
                        request_id);
}

static void
assert_registration_id_request(const received_frame_t *frame,
                               uint16_t expected_type)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    bool id_seen = false;

    assert(frame->header.message_type == expected_type);
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
            assert(memcmp(value, registration_id, sizeof(value)) == 0);
            id_seen = true;
        }
    }
    assert(id_seen);
}

static off_t
file_size(const char *path)
{
    struct stat status;

    assert(stat(path, &status) == 0);
    return status.st_size;
}

static void
path_for(char output[PATH_MAX], const char *base, const char *name)
{
    assert(snprintf(output, PATH_MAX, "%s/%s", base, name) > 0);
}

static void
assert_marker_state(const integration_fixture_t *fixture, const char *state)
{
    char user_path[PATH_MAX];
    char marker_path[PATH_MAX];
    char buffer[512];
    char expected[64];
    ssize_t length;
    int fd;

    path_for(user_path, fixture->users_directory, "newuser");
    path_for(marker_path, user_path, LEGACY_USERDB_MARKER_FILE);
    fd = open(marker_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    length = read(fd, buffer, sizeof(buffer) - 1U);
    assert(length > 0);
    buffer[length] = '\0';
    assert(close(fd) == 0);
    assert(snprintf(expected, sizeof(expected), "state=%s\n", state) > 0);
    assert(strstr(buffer, expected) != NULL);
}

static void
assert_prepared_local_state(const integration_fixture_t *fixture)
{
    assert(file_size(fixture->users_file) ==
           (off_t)LEGACY_USERDB_HEADER_SIZE +
               (off_t)LEGACY_USERDB_RECORD_SIZE);
    assert_marker_state(fixture, "prepared");
}

static void
run_server(int fd,
           server_script_t script,
           const integration_fixture_t *fixture)
{
    received_frame_t request;
    uint8_t response[FTAP_MAX_FRAME_SIZE];
    size_t length;

    assert(receive_frame(fd, &request) == 0);
    assert(request.header.message_type == FTAP_MSG_REGISTRATION_BEGIN_REQUEST);
    length = build_begin_result(response, request.header.request_id);
    assert(send_all(fd, response, length) == 0);

    assert(receive_frame(fd, &request) == 0);
    if (script == SERVER_EXPECT_ABORT) {
        assert_registration_id_request(
            &request, FTAP_MSG_REGISTRATION_ABORT_REQUEST);
        length = build_abort_result(response, request.header.request_id);
        assert(send_all(fd, response, length) == 0);
    } else {
        assert_registration_id_request(
            &request, FTAP_MSG_REGISTRATION_COMMIT_REQUEST);
        assert_prepared_local_state(fixture);
        if (script == SERVER_SUCCESS) {
            length = build_commit_result(response, request.header.request_id);
            assert(send_all(fd, response, length) == 0);
        }
    }
    assert(close(fd) == 0);
    _exit(EXIT_SUCCESS);
}

static pid_t
start_server(int sockets[2],
             server_script_t script,
             const integration_fixture_t *fixture)
{
    pid_t child;

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        (void)close(sockets[0]);
        run_server(sockets[1], script, fixture);
    }
    assert(close(sockets[1]) == 0);
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
remove_tree(const char *path)
{
    struct stat status;
    DIR *directory;
    struct dirent *entry;

    if (lstat(path, &status) != 0) {
        assert(errno == ENOENT);
        return;
    }
    if (!S_ISDIR(status.st_mode)) {
        assert(unlink(path) == 0);
        return;
    }
    directory = opendir(path);
    assert(directory != NULL);
    while ((entry = readdir(directory)) != NULL) {
        char child[PATH_MAX];

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        path_for(child, path, entry->d_name);
        remove_tree(child);
    }
    assert(closedir(directory) == 0);
    assert(rmdir(path) == 0);
}

static void
make_fixture(integration_fixture_t *fixture)
{
    char template_path[] = "/tmp/fortytwo-coordinate-XXXXXX";
    char *created = mkdtemp(template_path);
    struct userhdr header;
    int fd;

    assert(created != NULL);
    memset(fixture, 0, sizeof(*fixture));
    assert(snprintf(fixture->root, sizeof(fixture->root), "%s", created) > 0);
    path_for(fixture->etc, fixture->root, "etc");
    path_for(fixture->runtime_parent, fixture->root, "tmp");
    path_for(fixture->users_directory, fixture->root, "home");
    path_for(fixture->users_file, fixture->etc, "users.data");
    assert(mkdir(fixture->etc, 0700) == 0);
    assert(mkdir(fixture->runtime_parent, 0700) == 0);
    assert(mkdir(fixture->users_directory, 0770) == 0);
    assert(chmod(fixture->users_directory, 0770) == 0);

    header.hdrsize = (int)LEGACY_USERDB_HEADER_SIZE;
    header.recsize = (int)LEGACY_USERDB_RECORD_SIZE;
    fd = open(fixture->users_file,
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0660);
    assert(fd >= 0);
    write_all(fd, &header, sizeof(header));
    assert(fchmod(fd, 0660) == 0);
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
}

static fortytwo_registration_request_t
make_request(ftap_client_t *client,
             const integration_fixture_t *fixture,
             legacy_userdb_record_defaults_t *defaults,
             legacy_userdb_provision_policy_t *policy)
{
    static const uint8_t password[] = "correct horse";
    static const ftap_registration_metadata_t metadata = {
        FTAP_PROTOCOL_TELNET, "192.0.2.42", "/dev/pts/42", "integration"
    };
    fortytwo_registration_request_t request;

    legacy_userdb_provision_policy_defaults(policy);
    memset(defaults, 0, sizeof(*defaults));
    defaults->security_level = 20U;
    defaults->language = (int32_t)'D';
    defaults->charset = 1;
    defaults->message_editor = LEGACY_USERDB_EDITOR_FULLSCREEN;
    defaults->protocol = "Zmodem";
    defaults->email = true;
    defaults->mail_scan = true;
    defaults->new_file_scan = true;

    memset(&request, 0, sizeof(request));
    request.client = client;
    request.mbse_root = fixture->root;
    request.bbs_users_directory = fixture->users_directory;
    request.login_name = "NewUser";
    request.display_name = "New User";
    request.password = password;
    request.password_length = sizeof(password) - 1U;
    request.metadata = &metadata;
    request.registered_at = INT64_C(1784180000);
    request.legacy_defaults = defaults;
    request.legacy_policy = policy;
    return request;
}

static void
prepare_client(ftap_client_t *client, int fd)
{
    ftap_client_init(client, TEST_TIMEOUT_MS);
    client->fd = fd;
    client->state = FTAP_STATE_HELLO_COMPLETE;
}

static void
assert_record_has_no_password(const integration_fixture_t *fixture)
{
    struct userrec record;
    size_t index;
    int fd = open(fixture->users_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    assert(fd >= 0);
    assert(pread(fd, &record, sizeof(record),
                 (off_t)LEGACY_USERDB_HEADER_SIZE) == (ssize_t)sizeof(record));
    assert(close(fd) == 0);
    assert(strcmp(record.Name, "newuser") == 0);
    assert(strcmp(record.sUserName, "New User") == 0);
    assert(record.xPassword == 0U);
    for (index = 0U; index < sizeof(record.Password); ++index) {
        assert(record.Password[index] == '\0');
    }
}

static void
test_success(void)
{
    integration_fixture_t fixture;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;
    ftap_client_t client;
    int sockets[2];
    pid_t child;

    make_fixture(&fixture);
    child = start_server(sockets, SERVER_SUCCESS, &fixture);
    prepare_client(&client, sockets[0]);
    request = make_request(&client, &fixture, &defaults, &policy);
    assert(fortytwo_registration_coordinate(&request, &result, &error) == 0);
    assert(result.committed && !result.marker_pending);
    assert(client.state == FTAP_STATE_SESSION_BOUND);
    assert(memcmp(result.terminal.session_id, session_id,
                  sizeof(session_id)) == 0);
    assert_marker_state(&fixture, "committed");
    assert_record_has_no_password(&fixture);
    ftap_client_close(&client);
    wait_server(child);
    remove_tree(fixture.root);
}

static void
test_unknown_commit_retains_prepared_state(void)
{
    integration_fixture_t fixture;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;
    ftap_client_t client;
    int sockets[2];
    pid_t child;

    make_fixture(&fixture);
    child = start_server(sockets, SERVER_COMMIT_REPLY_LOST, &fixture);
    prepare_client(&client, sockets[0]);
    request = make_request(&client, &fixture, &defaults, &policy);
    assert(fortytwo_registration_coordinate(&request, &result, &error) == -1);
    assert(error.status == FORTYTWO_REGISTRATION_COMMIT_OUTCOME_UNKNOWN);
    assert(error.outcome_unknown);
    assert(result.marker_pending && result.repair_required);
    assert(result.legacy.prepared && result.legacy.commit_started);
    assert_marker_state(&fixture, "prepared");
    assert_record_has_no_password(&fixture);
    ftap_client_close(&client);
    wait_server(child);
    remove_tree(fixture.root);
}

static void
test_local_failure_aborts_without_append(void)
{
    integration_fixture_t fixture;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;
    ftap_client_t client;
    char existing_target[PATH_MAX];
    int sockets[2];
    pid_t child;

    make_fixture(&fixture);
    path_for(existing_target, fixture.users_directory, "newuser");
    assert(mkdir(existing_target, 0770) == 0);
    assert(chmod(existing_target, 0770) == 0);
    child = start_server(sockets, SERVER_EXPECT_ABORT, &fixture);
    prepare_client(&client, sockets[0]);
    request = make_request(&client, &fixture, &defaults, &policy);
    assert(fortytwo_registration_coordinate(&request, &result, &error) == -1);
    assert(error.status == FORTYTWO_REGISTRATION_LEGACY_PREPARE_FAILED);
    assert(!result.marker_pending);
    assert(file_size(fixture.users_file) ==
           (off_t)LEGACY_USERDB_HEADER_SIZE);
    assert(client.state == FTAP_STATE_HELLO_COMPLETE);
    ftap_client_close(&client);
    wait_server(child);
    remove_tree(fixture.root);
}

int
main(void)
{
    test_success();
    test_unknown_commit_retains_prepared_state();
    test_local_failure_aborts_without_append();
    (void)printf("registration coordinator integration tests: OK\n");
    return 0;
}
