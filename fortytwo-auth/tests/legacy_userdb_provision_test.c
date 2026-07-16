/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "legacy_userdb.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#pragma pack(push, 1)
#include "../../lib/users.h"
#pragma pack(pop)

_Static_assert(sizeof(struct userhdr) == LEGACY_USERDB_HEADER_SIZE,
               "test header layout changed");
_Static_assert(sizeof(struct userrec) == LEGACY_USERDB_RECORD_SIZE,
               "test record layout changed");

typedef struct provision_fixture {
    char root[PATH_MAX];
    char etc[PATH_MAX];
    char runtime_parent[PATH_MAX];
    char users_directory[PATH_MAX];
    char users_file[PATH_MAX];
    off_t original_size;
} provision_fixture_t;

static void
write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;
    size_t completed = 0U;

    while (completed < length) {
        ssize_t written = write(fd, bytes + completed, length - completed);

        if (written > 0) {
            completed += (size_t)written;
            continue;
        }
        assert(written < 0 && errno == EINTR);
    }
}

static void
pread_all(int fd, void *buffer, size_t length, off_t offset)
{
    unsigned char *bytes = buffer;
    size_t completed = 0U;

    while (completed < length) {
        ssize_t received = pread(fd, bytes + completed, length - completed,
                                 offset + (off_t)completed);

        if (received > 0) {
            completed += (size_t)received;
            continue;
        }
        assert(received < 0 && errno == EINTR);
    }
}

static void
pwrite_all(int fd, const void *buffer, size_t length, off_t offset)
{
    const unsigned char *bytes = buffer;
    size_t completed = 0U;

    while (completed < length) {
        ssize_t written = pwrite(fd, bytes + completed, length - completed,
                                 offset + (off_t)completed);

        if (written > 0) {
            completed += (size_t)written;
            continue;
        }
        assert(written < 0 && errno == EINTR);
    }
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
        assert(snprintf(child, sizeof(child), "%s/%s", path,
                        entry->d_name) > 0);
        remove_tree(child);
    }
    assert(closedir(directory) == 0);
    assert(rmdir(path) == 0);
}

static void
init_existing_record(struct userrec *record,
                     const char *legacy_name,
                     const char *display_name,
                     const char *handle)
{
    memset(record, 0, sizeof(*record));
    assert(snprintf(record->Name, sizeof(record->Name), "%s",
                    legacy_name) > 0);
    assert(snprintf(record->sUserName, sizeof(record->sUserName), "%s",
                    display_name) > 0);
    if (handle != NULL) {
        assert(snprintf(record->sHandle, sizeof(record->sHandle), "%s",
                        handle) > 0);
    }
}

static void
make_fixture(provision_fixture_t *fixture)
{
    char template_path[] = "/tmp/fortytwo-provision-XXXXXX";
    char *created = mkdtemp(template_path);
    struct userhdr header;
    struct userrec existing;
    int fd;

    assert(created != NULL);
    memset(fixture, 0, sizeof(*fixture));
    assert(snprintf(fixture->root, sizeof(fixture->root), "%s", created) > 0);
    assert(snprintf(fixture->etc, sizeof(fixture->etc), "%s/etc",
                    fixture->root) > 0);
    assert(snprintf(fixture->runtime_parent,
                    sizeof(fixture->runtime_parent), "%s/tmp",
                    fixture->root) > 0);
    assert(snprintf(fixture->users_directory,
                    sizeof(fixture->users_directory), "%s/home",
                    fixture->root) > 0);
    assert(snprintf(fixture->users_file, sizeof(fixture->users_file),
                    "%s/users.data", fixture->etc) > 0);

    assert(mkdir(fixture->etc, 0700) == 0);
    assert(mkdir(fixture->runtime_parent, 0700) == 0);
    assert(mkdir(fixture->users_directory, 0770) == 0);
    assert(chmod(fixture->users_directory, 0770) == 0);

    header.hdrsize = (int)LEGACY_USERDB_HEADER_SIZE;
    header.recsize = (int)LEGACY_USERDB_RECORD_SIZE;
    init_existing_record(&existing, "neo67", "Existing User",
                         "Existing Handle");
    fd = open(fixture->users_file,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0660);
    assert(fd >= 0);
    write_all(fd, &header, sizeof(header));
    write_all(fd, &existing, sizeof(existing));
    assert(fchmod(fd, 0660) == 0);
    assert(close(fd) == 0);
    fixture->original_size =
        (off_t)LEGACY_USERDB_HEADER_SIZE + (off_t)LEGACY_USERDB_RECORD_SIZE;
}

static void
remove_fixture(const provision_fixture_t *fixture)
{
    remove_tree(fixture->root);
}

static legacy_userdb_provision_policy_t
default_policy(void)
{
    legacy_userdb_provision_policy_t policy;

    legacy_userdb_provision_policy_defaults(&policy);
    return policy;
}

static legacy_userdb_registration_t
default_registration(void)
{
    legacy_userdb_registration_t registration;
    size_t index;

    memset(&registration, 0, sizeof(registration));
    for (index = 0U; index < LEGACY_USERDB_UUID_SIZE; ++index) {
        registration.registration_id[index] = (uint8_t)(index + 1U);
        registration.user_id[index] = (uint8_t)(0x80U + index);
    }
    registration.legacy_name = "newuser";
    registration.display_name = "New User";
    registration.registered_at = INT64_C(1784178000);
    registration.defaults.security_level = 20U;
    registration.defaults.security_flags = 0U;
    registration.defaults.security_notflags = 0U;
    registration.defaults.language = (int32_t)'D';
    registration.defaults.charset = 1;
    registration.defaults.message_editor = LEGACY_USERDB_EDITOR_FULLSCREEN;
    registration.defaults.protocol = "Zmodem-8K (ZedZap)";
    registration.defaults.email = true;
    registration.defaults.mail_scan = true;
    registration.defaults.new_file_scan = true;
    return registration;
}

static void
path_for(char output[PATH_MAX], const char *base, const char *name)
{
    assert(snprintf(output, PATH_MAX, "%s/%s", base, name) > 0);
}

static bool
path_exists(const char *path)
{
    struct stat status;

    if (lstat(path, &status) == 0) {
        return true;
    }
    assert(errno == ENOENT);
    return false;
}

static off_t
file_size(const char *path)
{
    struct stat status;

    assert(stat(path, &status) == 0);
    return status.st_size;
}

static mode_t
path_mode(const char *path)
{
    struct stat status;

    assert(lstat(path, &status) == 0);
    return status.st_mode & (mode_t)07777;
}

static void
format_registration_hex(const uint8_t id[LEGACY_USERDB_UUID_SIZE],
                        char output[33])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < LEGACY_USERDB_UUID_SIZE; ++index) {
        output[index * 2U] = digits[id[index] >> 4U];
        output[index * 2U + 1U] = digits[id[index] & 0x0fU];
    }
    output[32] = '\0';
}

static void
staging_path(const provision_fixture_t *fixture,
             const legacy_userdb_registration_t *registration,
             char output[PATH_MAX])
{
    char hex[33];
    char name[64];

    format_registration_hex(registration->registration_id, hex);
    assert(snprintf(name, sizeof(name), "%s%s",
                    LEGACY_USERDB_STAGING_PREFIX, hex) > 0);
    path_for(output, fixture->users_directory, name);
}

static void
assert_clean_after_failure(const provision_fixture_t *fixture,
                           const legacy_userdb_registration_t *registration)
{
    char final_path[PATH_MAX];
    char stage_path[PATH_MAX];

    path_for(final_path, fixture->users_directory, registration->legacy_name);
    staging_path(fixture, registration, stage_path);
    assert(file_size(fixture->users_file) == fixture->original_size);
    assert(!path_exists(final_path));
    assert(!path_exists(stage_path));
}

static void
read_record(const provision_fixture_t *fixture,
            size_t record_number,
            struct userrec *record)
{
    int fd = open(fixture->users_file, O_RDONLY | O_CLOEXEC);
    off_t offset = (off_t)LEGACY_USERDB_HEADER_SIZE +
                   (off_t)(record_number * LEGACY_USERDB_RECORD_SIZE);

    assert(fd >= 0);
    pread_all(fd, record, sizeof(*record), offset);
    assert(close(fd) == 0);
}

static void
assert_password_empty(const struct userrec *record)
{
    size_t index;

    assert(record->xPassword == 0U);
    for (index = 0U; index < sizeof(record->Password); ++index) {
        assert(record->Password[index] == '\0');
    }
}

static void
assert_success_tree(const provision_fixture_t *fixture,
                    const legacy_userdb_registration_t *registration)
{
    char user_path[PATH_MAX];
    char maildir_path[PATH_MAX];
    char child_path[PATH_MAX];
    char marker_path[PATH_MAX];
    int marker_fd;
    char marker[512];
    ssize_t marker_length;

    path_for(user_path, fixture->users_directory, registration->legacy_name);
    path_for(maildir_path, user_path, "Maildir");
    path_for(marker_path, user_path, LEGACY_USERDB_MARKER_FILE);
    assert(path_exists(user_path));
    assert(path_mode(user_path) == 0770);
    assert(path_mode(maildir_path) == 0700);
    path_for(child_path, maildir_path, "cur");
    assert(path_mode(child_path) == 0700);
    path_for(child_path, maildir_path, "new");
    assert(path_mode(child_path) == 0700);
    path_for(child_path, maildir_path, "tmp");
    assert(path_mode(child_path) == 0700);
    assert(path_mode(marker_path) == 0600);

    marker_fd = open(marker_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(marker_fd >= 0);
    marker_length = read(marker_fd, marker, sizeof(marker) - 1U);
    assert(marker_length > 0);
    marker[marker_length] = '\0';
    assert(strstr(marker, "format_version=1\n") != NULL);
    assert(strstr(marker,
                  "registration_id=01020304-0506-0708-090a-0b0c0d0e0f10\n") !=
           NULL);
    assert(strstr(marker,
                  "user_id=80818283-8485-8687-8889-8a8b8c8d8e8f\n") !=
           NULL);
    assert(strstr(marker, "legacy_name=newuser\n") != NULL);
    assert(strstr(marker, "record_number=1\n") != NULL);
    assert(strstr(marker, "state=prepared\n") != NULL);
    assert(close(marker_fd) == 0);
}

static void
test_success_and_rollback(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    struct userrec record;
    char stage_path[PATH_MAX];
    char expected_comment[81];
    char hex[33];

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(error.status == LEGACY_USERDB_OK);
    assert(prepared.prepared);
    assert(prepared.record_number == 1U);
    assert(prepared.original_size == fixture.original_size);
    assert(file_size(fixture.users_file) ==
           fixture.original_size + (off_t)LEGACY_USERDB_RECORD_SIZE);

    read_record(&fixture, 1U, &record);
    assert(strcmp(record.Name, "newuser") == 0);
    assert(strcmp(record.sUserName, "New User") == 0);
    assert(record.sHandle[0] == '\0');
    assert_password_empty(&record);
    assert(record.Security.level == 20U);
    assert(record.Security.flags == 0U);
    assert(record.Security.notflags == 0U);
    assert(memcmp(&record.Security, &record.ExpirySec,
                  sizeof(record.Security)) == 0);
    assert(strcmp(record.sExpiryDate, "00-00-0000") == 0);
    assert(strcmp(record.sSex, "Unknown") == 0);
    assert(record.tFirstLoginDate == (int32_t)registration.registered_at);
    assert(record.tLastLoginDate == 0);
    assert(record.tLastPwdChange == (int32_t)registration.registered_at);
    assert(record.iTimeLeft == 20);
    assert(record.MsgEditor == LEGACY_USERDB_EDITOR_FULLSCREEN);
    assert(record.iLastFileArea == 1);
    assert(record.iLastMsgArea == 1);
    assert(strcmp(record.sProtocol, "Zmodem-8K (ZedZap)") == 0);
    assert(record.iLanguage == (int32_t)'D');
    assert(record.Charset == 1);
    assert(record.GraphMode == 1U);
    assert(record.HotKeys == 1U);
    assert(record.Cls == 1U);
    assert(record.More == 1U);
    assert(record.MailScan == 1U);
    assert(record.ieFILE == 1U);
    assert(record.ieNEWS == 1U);
    assert(record.ieASCII8 == 1U);
    assert(record.Email == 1U);

    format_registration_hex(registration.registration_id, hex);
    assert(snprintf(expected_comment, sizeof(expected_comment), "%s%s",
                    LEGACY_USERDB_RECORD_MARKER_PREFIX, hex) > 0);
    assert(strcmp(record.sComment, expected_comment) == 0);
    assert(memcmp(&record, prepared.record_bytes, sizeof(record)) == 0);

    assert_success_tree(&fixture, &registration);
    staging_path(&fixture, &registration, stage_path);
    assert(!path_exists(stage_path));

    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert(error.status == LEGACY_USERDB_OK);
    assert(!prepared.prepared);
    assert_clean_after_failure(&fixture, &registration);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    remove_fixture(&fixture);
}

static void
expect_fault_cleanup(legacy_userdb_test_fault_t fault,
                     legacy_userdb_status_t expected_status)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;

    make_fixture(&fixture);
    legacy_userdb_test_set_fault(fault);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    legacy_userdb_test_set_fault(LEGACY_USERDB_TEST_FAULT_NONE);
    if (error.status != expected_status) {
        (void)fprintf(stderr, "fault %d expected %s, got %s: %s\n",
                      (int)fault,
                      legacy_userdb_status_name(expected_status),
                      legacy_userdb_status_name(error.status), error.text);
    }
    assert(error.status == expected_status);
    assert(!error.repair_required);
    assert(!prepared.prepared);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
test_injected_failures_roll_back(void)
{
    expect_fault_cleanup(LEGACY_USERDB_TEST_FAULT_CREATE_STAGING,
                         LEGACY_USERDB_CREATE_DIRECTORY_FAILED);
    expect_fault_cleanup(LEGACY_USERDB_TEST_FAULT_MARKER_WRITE,
                         LEGACY_USERDB_WRITE_MARKER_FAILED);
    expect_fault_cleanup(LEGACY_USERDB_TEST_FAULT_RECORD_SHORT_WRITE,
                         LEGACY_USERDB_WRITE_FAILED);
    expect_fault_cleanup(LEGACY_USERDB_TEST_FAULT_RECORD_SYNC,
                         LEGACY_USERDB_SYNC_FAILED);
    expect_fault_cleanup(LEGACY_USERDB_TEST_FAULT_READBACK_MISMATCH,
                         LEGACY_USERDB_VERIFY_FAILED);
    expect_fault_cleanup(
        LEGACY_USERDB_TEST_FAULT_POSTAPPEND_NAME_COLLISION,
        LEGACY_USERDB_NAME_COLLISION);
    expect_fault_cleanup(LEGACY_USERDB_TEST_FAULT_RENAME,
                         LEGACY_USERDB_RENAME_FAILED);
    expect_fault_cleanup(LEGACY_USERDB_TEST_FAULT_USERS_DIRECTORY_SYNC,
                         LEGACY_USERDB_SYNC_FAILED);
}

static void
test_collisions_and_existing_targets(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    char target[PATH_MAX];
    char stage[PATH_MAX];
    char hex[33];
    struct userrec existing;
    int fd;

    make_fixture(&fixture);
    registration.legacy_name = "neo67";
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_NAME_COLLISION);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    read_record(&fixture, 0U, &existing);
    format_registration_hex(registration.registration_id, hex);
    assert(snprintf(existing.sComment, sizeof(existing.sComment), "%s%s",
                    LEGACY_USERDB_RECORD_MARKER_PREFIX, hex) > 0);
    fd = open(fixture.users_file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    pwrite_all(fd, &existing, sizeof(existing),
               (off_t)LEGACY_USERDB_HEADER_SIZE);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_REGISTRATION_EXISTS);
    assert(error.repair_required);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    registration.display_name = "existing user";
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_NAME_COLLISION);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    registration.display_name = "neo67";
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_NAME_COLLISION);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    read_record(&fixture, 0U, &existing);
    assert(snprintf(existing.sHandle, sizeof(existing.sHandle), "%s",
                    "takenkey") > 0);
    fd = open(fixture.users_file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    pwrite_all(fd, &existing, sizeof(existing),
               (off_t)LEGACY_USERDB_HEADER_SIZE);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    registration.legacy_name = "takenkey";
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_NAME_COLLISION);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    path_for(target, fixture.users_directory, registration.legacy_name);
    assert(mkdir(target, 0770) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_TARGET_EXISTS);
    assert(file_size(fixture.users_file) == fixture.original_size);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    staging_path(&fixture, &registration, stage);
    assert(mkdir(stage, 0770) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_STAGING_EXISTS);
    assert(error.repair_required);
    assert(file_size(fixture.users_file) == fixture.original_size);
    remove_fixture(&fixture);
}

static void
test_database_validation(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    struct userhdr header;
    struct userrec existing;
    int fd;

    make_fixture(&fixture);
    assert(chmod(fixture.users_file, 0600) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_MODE_MISMATCH);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    header.hdrsize = (int)LEGACY_USERDB_HEADER_SIZE;
    header.recsize = 599;
    fd = open(fixture.users_file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    pwrite_all(fd, &header, sizeof(header), 0);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_HEADER_MISMATCH);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    fd = open(fixture.users_file, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    write_all(fd, "X", 1U);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_SIZE_MISMATCH);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    read_record(&fixture, 0U, &existing);
    memset(existing.sComment, 'X', sizeof(existing.sComment));
    fd = open(fixture.users_file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    pwrite_all(fd, &existing, sizeof(existing),
               (off_t)LEGACY_USERDB_HEADER_SIZE);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_RECORD);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    read_record(&fixture, 0U, &existing);
    fd = open(fixture.users_file, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    write_all(fd, &existing, sizeof(existing));
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_DUPLICATE_LEGACY_NAME);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    policy = default_policy();
    policy.database.max_records = 1U;
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_TOO_MANY_RECORDS);
    remove_fixture(&fixture);
}

static void
test_directory_policy_and_input_validation(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;

    make_fixture(&fixture);
    assert(chmod(fixture.users_directory, 0755) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_USERS_DIRECTORY_POLICY_MISMATCH);
    assert(file_size(fixture.users_file) == fixture.original_size);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    registration.defaults.protocol = "";
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_REGISTRATION);
    registration = default_registration();
    registration.registered_at = INT64_C(2147483648);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_REGISTRATION);
    registration = default_registration();
    registration.defaults.charset = LEGACY_USERDB_CHARSET_MAX + 1;
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_REGISTRATION);
    registration = default_registration();
    memset(registration.registration_id, 0,
           sizeof(registration.registration_id));
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_REGISTRATION);
    remove_fixture(&fixture);
}

static void
test_global_lock_serializes(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    char lock_path[PATH_MAX];
    struct flock same_process_lock;
    int same_process_fd;
    struct flock database_read_lock;
    int database_read_fd;
    int ready_pipe[2];
    int release_pipe[2];
    pid_t child;
    char byte;
    int status;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);

    assert(snprintf(lock_path, sizeof(lock_path),
                    "%s/fortytwo-registration/users-data.lock",
                    fixture.runtime_parent) > 0);

    same_process_fd = open(lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(same_process_fd >= 0);
    memset(&same_process_lock, 0, sizeof(same_process_lock));
    same_process_lock.l_type = F_WRLCK;
    same_process_lock.l_whence = SEEK_SET;
    assert(fcntl(same_process_fd, F_OFD_SETLK, &same_process_lock) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_GLOBAL_BUSY);
    assert(close(same_process_fd) == 0);
    assert_clean_after_failure(&fixture, &registration);

    database_read_fd = open(fixture.users_file,
                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(database_read_fd >= 0);
    memset(&database_read_lock, 0, sizeof(database_read_lock));
    database_read_lock.l_type = F_RDLCK;
    database_read_lock.l_whence = SEEK_SET;
    assert(fcntl(database_read_fd, F_OFD_SETLK,
                 &database_read_lock) == 0);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_BUSY);
    assert(close(database_read_fd) == 0);
    assert_clean_after_failure(&fixture, &registration);

    assert(pipe(ready_pipe) == 0);
    assert(pipe(release_pipe) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        struct flock lock;
        int fd;

        (void)close(ready_pipe[0]);
        (void)close(release_pipe[1]);
        fd = open(lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            _exit(10);
        }
        memset(&lock, 0, sizeof(lock));
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        if (fcntl(fd, F_SETLK, &lock) != 0) {
            _exit(11);
        }
        if (write(ready_pipe[1], "R", 1U) != 1) {
            _exit(12);
        }
        if (read(release_pipe[0], &byte, 1U) != 1) {
            _exit(13);
        }
        (void)close(fd);
        _exit(0);
    }

    (void)close(ready_pipe[1]);
    (void)close(release_pipe[0]);
    assert(read(ready_pipe[0], &byte, 1U) == 1);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == -1);
    assert(error.status == LEGACY_USERDB_GLOBAL_BUSY);
    assert(write(release_pipe[1], "X", 1U) == 1);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    (void)close(ready_pipe[0]);
    (void)close(release_pipe[1]);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
read_file_bytes(const char *path, char *buffer, size_t capacity,
                size_t *length)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t received;

    assert(fd >= 0);
    received = read(fd, buffer, capacity);
    assert(received >= 0);
    *length = (size_t)received;
    assert(close(fd) == 0);
}

static void
write_file_bytes(const char *path, const char *buffer, size_t length)
{
    int fd = open(path,
                  O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);

    assert(fd >= 0);
    write_all(fd, buffer, length);
    assert(fchmod(fd, 0600) == 0);
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
}

static void
assert_marker_state(const provision_fixture_t *fixture,
                    const legacy_userdb_registration_t *registration,
                    const char *state)
{
    char user_path[PATH_MAX];
    char marker_path[PATH_MAX];
    char marker[512];
    char expected[64];
    size_t marker_length;

    path_for(user_path, fixture->users_directory, registration->legacy_name);
    path_for(marker_path, user_path, LEGACY_USERDB_MARKER_FILE);
    read_file_bytes(marker_path, marker, sizeof(marker) - 1U, &marker_length);
    marker[marker_length] = '\0';
    assert(snprintf(expected, sizeof(expected), "state=%s\n", state) > 0);
    assert(strstr(marker, expected) != NULL);
}

static void
test_commit_boundary_and_finalize(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    char user_path[PATH_MAX];

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(prepared.prepared);
    assert(!prepared.commit_started);
    assert(legacy_userdb_mark_commit_started(&prepared, &error) == 0);
    assert(prepared.commit_started);
    assert(error.status == LEGACY_USERDB_OK);

    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(file_size(fixture.users_file) ==
           fixture.original_size + (off_t)LEGACY_USERDB_RECORD_SIZE);

    assert(legacy_userdb_finalize_committed(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert(error.status == LEGACY_USERDB_OK);
    assert(!prepared.prepared);
    assert_marker_state(&fixture, &registration, "committed");
    path_for(user_path, fixture.users_directory, registration.legacy_name);
    assert(path_exists(user_path));
    assert(file_size(fixture.users_file) ==
           fixture.original_size + (off_t)LEGACY_USERDB_RECORD_SIZE);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert(path_exists(user_path));
    remove_fixture(&fixture);
}

static void
test_finalize_requires_commit_boundary(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(legacy_userdb_finalize_committed(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_COMMIT_STATE_INVALID);
    assert(error.repair_required);
    assert_marker_state(&fixture, &registration, "prepared");
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
expect_finalize_retry(legacy_userdb_test_fault_t fault,
                      bool marker_may_already_be_committed)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(legacy_userdb_mark_commit_started(&prepared, &error) == 0);
    legacy_userdb_test_set_fault(fault);
    assert(legacy_userdb_finalize_committed(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    legacy_userdb_test_set_fault(LEGACY_USERDB_TEST_FAULT_NONE);
    assert(error.status == LEGACY_USERDB_FINALIZE_FAILED);
    assert(error.repair_required);
    assert(prepared.prepared && prepared.commit_started);
    assert(file_size(fixture.users_file) ==
           fixture.original_size + (off_t)LEGACY_USERDB_RECORD_SIZE);
    if (!marker_may_already_be_committed) {
        assert_marker_state(&fixture, &registration, "prepared");
    }
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(legacy_userdb_finalize_committed(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert(!prepared.prepared);
    assert_marker_state(&fixture, &registration, "committed");
    remove_fixture(&fixture);
}

static void
test_finalize_faults_are_nondestructive_and_retryable(void)
{
    expect_finalize_retry(
        LEGACY_USERDB_TEST_FAULT_COMMITTED_MARKER_WRITE, false);
    expect_finalize_retry(
        LEGACY_USERDB_TEST_FAULT_COMMITTED_MARKER_RENAME, false);
    expect_finalize_retry(
        LEGACY_USERDB_TEST_FAULT_COMMITTED_DIRECTORY_SYNC, true);
}

static void
test_rollback_rejects_marker_mismatch(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    char user_path[PATH_MAX];
    char marker_path[PATH_MAX];
    char marker[512];
    size_t marker_length;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    path_for(user_path, fixture.users_directory, registration.legacy_name);
    path_for(marker_path, user_path, LEGACY_USERDB_MARKER_FILE);
    read_file_bytes(marker_path, marker, sizeof(marker), &marker_length);
    assert(marker_length > 0U);
    marker[0] = marker[0] == 'X' ? 'Y' : 'X';
    write_file_bytes(marker_path, marker, marker_length);

    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(file_size(fixture.users_file) ==
           fixture.original_size + (off_t)LEGACY_USERDB_RECORD_SIZE);
    assert(path_exists(user_path));

    marker[0] = 'f';
    write_file_bytes(marker_path, marker, marker_length);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
test_rollback_rejects_record_or_length_change(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    int fd;
    unsigned char changed;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    fd = open(fixture.users_file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    changed = prepared.record_bytes[0] ^ 0x01U;
    pwrite_all(fd, &changed, 1U, prepared.original_size);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);

    fd = open(fixture.users_file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    pwrite_all(fd, prepared.record_bytes, LEGACY_USERDB_RECORD_SIZE,
               prepared.original_size);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    fd = open(fixture.users_file,
              O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    write_all(fd, "X", 1U);
    assert(fdatasync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(truncate(fixture.users_file,
                    fixture.original_size +
                        (off_t)LEGACY_USERDB_RECORD_SIZE) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
test_rollback_rejects_storage_path_replacement(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    struct userhdr header;
    char saved_path[PATH_MAX];
    int fd;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(snprintf(saved_path, sizeof(saved_path), "%s.saved",
                    fixture.users_file) > 0);
    assert(rename(fixture.users_file, saved_path) == 0);
    header.hdrsize = (int)LEGACY_USERDB_HEADER_SIZE;
    header.recsize = (int)LEGACY_USERDB_RECORD_SIZE;
    fd = open(fixture.users_file,
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0660);
    assert(fd >= 0);
    write_all(fd, &header, sizeof(header));
    assert(fchmod(fd, 0660) == 0);
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(unlink(fixture.users_file) == 0);
    assert(rename(saved_path, fixture.users_file) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(snprintf(saved_path, sizeof(saved_path), "%s.saved",
                    fixture.users_directory) > 0);
    assert(rename(fixture.users_directory, saved_path) == 0);
    assert(mkdir(fixture.users_directory, 0770) == 0);
    assert(chmod(fixture.users_directory, 0770) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(rmdir(fixture.users_directory) == 0);
    assert(rename(saved_path, fixture.users_directory) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
test_rollback_rejects_storage_metadata_change(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(chmod(fixture.users_file, 0600) == 0);
    policy.database.check_mode = false;
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(chmod(fixture.users_file, 0660) == 0);
    policy = default_policy();
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);

    make_fixture(&fixture);
    registration = default_registration();
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    assert(chmod(fixture.users_directory, 0750) == 0);
    policy.users_directory.check_mode = false;
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(chmod(fixture.users_directory, 0770) == 0);
    policy = default_policy();
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
test_rollback_rejects_unknown_directory_entry(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;
    char user_path[PATH_MAX];
    char extra_path[PATH_MAX];
    int fd;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    path_for(user_path, fixture.users_directory, registration.legacy_name);
    path_for(extra_path, user_path, "unexpected");
    fd = open(extra_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    assert(close(fd) == 0);

    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_ROLLBACK_UNSAFE);
    assert(error.repair_required);
    assert(file_size(fixture.users_file) ==
           fixture.original_size + (off_t)LEGACY_USERDB_RECORD_SIZE);

    /* The first attempt already hid and privatized the marked directory. */
    {
        char stage_path[PATH_MAX];
        staging_path(&fixture, &registration, stage_path);
        path_for(extra_path, stage_path, "unexpected");
    }
    assert(unlink(extra_path) == 0);
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
test_rollback_rejects_corrupt_context(void)
{
    provision_fixture_t fixture;
    legacy_userdb_provision_policy_t policy = default_policy();
    legacy_userdb_registration_t registration = default_registration();
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t error;

    make_fixture(&fixture);
    assert(legacy_userdb_prepare_registration(
               fixture.root, fixture.users_directory, &policy, &registration,
               &prepared, &error) == 0);
    ++prepared.original_size;
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_CONTEXT_INVALID);
    assert(error.repair_required);
    --prepared.original_size;
    prepared.record_bytes[offsetof(struct userrec, Password) + 1U] = 1U;
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == -1);
    assert(error.status == LEGACY_USERDB_CONTEXT_INVALID);
    assert(error.repair_required);
    prepared.record_bytes[offsetof(struct userrec, Password) + 1U] = 0U;
    assert(legacy_userdb_rollback_precommit(
               fixture.root, fixture.users_directory, &policy, &prepared,
               &error) == 0);
    assert_clean_after_failure(&fixture, &registration);
    remove_fixture(&fixture);
}

static void
test_public_status_names(void)
{
    legacy_userdb_status_t status;

    for (status = LEGACY_USERDB_OK;
         status <= LEGACY_USERDB_ROLLBACK_FAILED;
         status = (legacy_userdb_status_t)((int)status + 1)) {
        assert(strcmp(legacy_userdb_status_name(status), "unknown") != 0);
    }
}

int
main(void)
{
    test_success_and_rollback();
    test_injected_failures_roll_back();
    test_collisions_and_existing_targets();
    test_database_validation();
    test_directory_policy_and_input_validation();
    test_global_lock_serializes();
    test_commit_boundary_and_finalize();
    test_finalize_requires_commit_boundary();
    test_finalize_faults_are_nondestructive_and_retryable();
    test_rollback_rejects_marker_mismatch();
    test_rollback_rejects_record_or_length_change();
    test_rollback_rejects_storage_path_replacement();
    test_rollback_rejects_storage_metadata_change();
    test_rollback_rejects_unknown_directory_entry();
    test_rollback_rejects_corrupt_context();
    test_public_status_names();
    (void)printf("legacy users.data provisioning tests: OK\n");
    return 0;
}
