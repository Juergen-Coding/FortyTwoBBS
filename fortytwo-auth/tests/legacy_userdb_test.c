/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "legacy_userdb.h"

#include <assert.h>
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

typedef struct test_root {
    char path[PATH_MAX];
    char etc_path[PATH_MAX];
    char users_path[PATH_MAX];
} test_root_t;

static void
write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;
    size_t offset = 0U;

    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        assert(written < 0 && errno == EINTR);
    }
}

static void
init_record(struct userrec *record,
            const char *legacy_name,
            const char *display_name,
            const char *handle)
{
    memset(record, 0, sizeof(*record));
    if (legacy_name != NULL) {
        assert(snprintf(record->Name, sizeof(record->Name), "%s",
                        legacy_name) > 0);
    }
    if (display_name != NULL) {
        assert(snprintf(record->sUserName, sizeof(record->sUserName), "%s",
                        display_name) > 0);
    }
    if (handle != NULL) {
        assert(snprintf(record->sHandle, sizeof(record->sHandle), "%s",
                        handle) > 0);
    }
}

static void
make_test_root(test_root_t *root)
{
    char template_path[] = "/tmp/fortytwo-legacy-userdb-XXXXXX";
    char *created;

    memset(root, 0, sizeof(*root));
    created = mkdtemp(template_path);
    assert(created != NULL);
    assert(snprintf(root->path, sizeof(root->path), "%s", created) > 0);
    assert(snprintf(root->etc_path, sizeof(root->etc_path), "%s/etc",
                    root->path) > 0);
    assert(snprintf(root->users_path, sizeof(root->users_path),
                    "%s/users.data", root->etc_path) > 0);
    assert(mkdir(root->etc_path, 0700) == 0);
}

static void
remove_test_root(const test_root_t *root)
{
    char extra_path[PATH_MAX];

    assert(snprintf(extra_path, sizeof(extra_path), "%s/users.link",
                    root->etc_path) > 0);
    (void)unlink(extra_path);
    assert(snprintf(extra_path, sizeof(extra_path), "%s/users.real",
                    root->etc_path) > 0);
    (void)unlink(extra_path);
    (void)unlink(root->users_path);
    (void)rmdir(root->users_path);
    assert(rmdir(root->etc_path) == 0);
    assert(rmdir(root->path) == 0);
}

static void
create_users_file(const test_root_t *root,
                  const struct userrec *records,
                  size_t record_count,
                  int header_size,
                  int record_size,
                  size_t trailing_bytes)
{
    struct userhdr header;
    unsigned char trailing[LEGACY_USERDB_RECORD_SIZE];
    size_t index;
    int fd;

    assert(trailing_bytes <= sizeof(trailing));
    memset(trailing, 0xa5, sizeof(trailing));
    header.hdrsize = header_size;
    header.recsize = record_size;

    fd = open(root->users_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    assert(fd >= 0);
    write_all(fd, &header, sizeof(header));
    for (index = 0U; index < record_count; ++index) {
        write_all(fd, &records[index], sizeof(records[index]));
    }
    if (trailing_bytes > 0U) {
        write_all(fd, trailing, trailing_bytes);
    }
    assert(fchmod(fd, 0660) == 0);
    assert(close(fd) == 0);
}

static legacy_userdb_policy_t
default_policy(void)
{
    legacy_userdb_policy_t policy;

    legacy_userdb_policy_defaults(&policy);
    return policy;
}

static void
expect_status(const test_root_t *root,
              const legacy_userdb_policy_t *policy,
              const legacy_userdb_query_t *query,
              legacy_userdb_status_t expected_status,
              size_t expected_record)
{
    legacy_userdb_scan_result_t result;
    legacy_userdb_error_t error;

    assert(legacy_userdb_inspect(root->path, policy, query, &result,
                                 &error) == -1);
    if (error.status != expected_status) {
        (void)fprintf(stderr, "expected %s, got %s: %s\n",
                      legacy_userdb_status_name(expected_status),
                      legacy_userdb_status_name(error.status), error.text);
    }
    assert(error.status == expected_status);
    assert(strcmp(legacy_userdb_status_name(error.status), "unknown") != 0);
    assert(error.record_number == expected_record);
    assert(error.text[0] != '\0');
}

static void
test_valid_scan_and_collisions(void)
{
    test_root_t root;
    struct userrec records[3];
    legacy_userdb_policy_t policy = default_policy();
    legacy_userdb_query_t query;
    legacy_userdb_scan_result_t result;
    legacy_userdb_error_t error;

    make_test_root(&root);
    init_record(&records[0], "neo67", "Juergen Ihlau", "neo");
    init_record(&records[1], "marta", "Marta Test", "Marta42");
    init_record(&records[2], "other", "Alice Smith", "Alias");
    create_users_file(&root, records, 3U, 8, 598, 0U);

    query.legacy_name = "MARTA";
    query.display_name = "ALICE SMITH";
    assert(legacy_userdb_inspect(root.path, &policy, &query, &result,
                                 &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_ARGUMENT);

    query.legacy_name = "marta";
    assert(legacy_userdb_inspect(root.path, &policy, &query, &result,
                                 &error) == 0);
    assert(error.status == LEGACY_USERDB_OK);
    assert(result.record_count == 3U);
    assert(result.legacy_name_exists);
    assert(result.legacy_name_record == 1U);
    assert(result.display_name_exists);
    assert(result.display_name_record == 2U);
    assert(!result.handle_exists);
    assert(result.handle_record == LEGACY_USERDB_NO_RECORD);

    query.legacy_name = "fresh42";
    query.display_name = "mArTa42";
    assert(legacy_userdb_inspect(root.path, &policy, &query, &result,
                                 &error) == 0);
    assert(!result.legacy_name_exists);
    assert(!result.display_name_exists);
    assert(result.handle_exists);
    assert(result.handle_record == 1U);

    assert(legacy_userdb_inspect(root.path, &policy, NULL, &result,
                                 &error) == 0);
    assert(result.record_count == 3U);
    remove_test_root(&root);
}

static void
test_header_and_size_validation(void)
{
    test_root_t root;
    struct userrec record;
    legacy_userdb_policy_t policy = default_policy();

    init_record(&record, "test", "Test User", NULL);

    make_test_root(&root);
    {
        int fd = open(root.users_path,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        uint32_t short_header = 8U;
        assert(fd >= 0);
        write_all(fd, &short_header, sizeof(short_header));
        assert(fchmod(fd, 0660) == 0);
        assert(close(fd) == 0);
    }
    expect_status(&root, &policy, NULL, LEGACY_USERDB_HEADER_TRUNCATED,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);

    make_test_root(&root);
    create_users_file(&root, &record, 1U, 4, 598, 0U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_HEADER_MISMATCH,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);

    make_test_root(&root);
    create_users_file(&root, &record, 1U, 8, 612, 0U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_HEADER_MISMATCH,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);

    make_test_root(&root);
    create_users_file(&root, &record, 1U, 8, 598, 1U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_SIZE_MISMATCH,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);
}

static void
test_path_and_file_policy(void)
{
    test_root_t root;
    struct userrec record;
    legacy_userdb_policy_t policy;
    char real_path[PATH_MAX];

    init_record(&record, "test", "Test User", NULL);

    make_test_root(&root);
    create_users_file(&root, &record, 1U, 8, 598, 0U);
    assert(snprintf(real_path, sizeof(real_path), "%s/users.real",
                    root.etc_path) > 0);
    assert(rename(root.users_path, real_path) == 0);
    assert(symlink("users.real", root.users_path) == 0);
    policy = default_policy();
    expect_status(&root, &policy, NULL, LEGACY_USERDB_OPEN_FILE_FAILED,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);

    make_test_root(&root);
    assert(mkdir(root.users_path, 0700) == 0);
    policy = default_policy();
    expect_status(&root, &policy, NULL, LEGACY_USERDB_NOT_REGULAR,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);

    make_test_root(&root);
    create_users_file(&root, &record, 1U, 8, 598, 0U);
    assert(chmod(root.users_path, 0640) == 0);
    policy = default_policy();
    expect_status(&root, &policy, NULL, LEGACY_USERDB_MODE_MISMATCH,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);

    make_test_root(&root);
    create_users_file(&root, &record, 1U, 8, 598, 0U);
    policy = default_policy();
    policy.expected_uid = (uid_t)(geteuid() + 1U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_OWNER_MISMATCH,
                  LEGACY_USERDB_NO_RECORD);
    policy = default_policy();
    policy.expected_gid = (gid_t)(getegid() + 1U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_GROUP_MISMATCH,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);

    make_test_root(&root);
    create_users_file(&root, &record, 1U, 8, 598, 0U);
    assert(snprintf(real_path, sizeof(real_path), "%s/users.link",
                    root.etc_path) > 0);
    assert(link(root.users_path, real_path) == 0);
    policy = default_policy();
    expect_status(&root, &policy, NULL,
                  LEGACY_USERDB_LINK_COUNT_MISMATCH,
                  LEGACY_USERDB_NO_RECORD);
    remove_test_root(&root);
}

static void
test_invalid_records_and_duplicates(void)
{
    test_root_t root;
    struct userrec records[2];
    legacy_userdb_policy_t policy = default_policy();

    init_record(&records[0], "first", "First User", NULL);
    memset(records[0].Name, 'x', sizeof(records[0].Name));
    make_test_root(&root);
    create_users_file(&root, records, 1U, 8, 598, 0U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_INVALID_RECORD, 0U);
    remove_test_root(&root);

    init_record(&records[0], "first", "First User", NULL);
    memset(records[0].sUserName, 'x', sizeof(records[0].sUserName));
    make_test_root(&root);
    create_users_file(&root, records, 1U, 8, 598, 0U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_INVALID_RECORD, 0U);
    remove_test_root(&root);

    init_record(&records[0], "first", "First User", NULL);
    memset(records[0].sHandle, 'x', sizeof(records[0].sHandle));
    make_test_root(&root);
    create_users_file(&root, records, 1U, 8, 598, 0U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_INVALID_RECORD, 0U);
    remove_test_root(&root);

    init_record(&records[0], "first", "First User", NULL);
    memset(records[0].Password, 'x', sizeof(records[0].Password));
    make_test_root(&root);
    create_users_file(&root, records, 1U, 8, 598, 0U);
    expect_status(&root, &policy, NULL, LEGACY_USERDB_INVALID_RECORD, 0U);
    remove_test_root(&root);

    init_record(&records[0], "same", "First User", NULL);
    init_record(&records[1], "SAME", "Second User", NULL);
    make_test_root(&root);
    create_users_file(&root, records, 2U, 8, 598, 0U);
    expect_status(&root, &policy, NULL,
                  LEGACY_USERDB_DUPLICATE_LEGACY_NAME, 1U);
    remove_test_root(&root);
}

static void
test_query_and_policy_validation(void)
{
    test_root_t root;
    struct userrec records[2];
    legacy_userdb_policy_t policy = default_policy();
    legacy_userdb_query_t query;
    legacy_userdb_scan_result_t result;
    legacy_userdb_error_t error;
    char control_name[] = {'A', '\x01', 'B', '\0'};
    char c1_name[] = {'A', (char)0xc2, (char)0x80, 'B', '\0'};
    char invalid_utf8[] = {'A', (char)0xc0, (char)0xaf, '\0'};

    assert(legacy_userdb_legacy_name_is_valid("neo67"));
    assert(legacy_userdb_legacy_name_is_valid("a-b.c_2"));
    assert(!legacy_userdb_legacy_name_is_valid(""));
    assert(!legacy_userdb_legacy_name_is_valid("Upper"));
    assert(!legacy_userdb_legacy_name_is_valid("-start"));
    assert(!legacy_userdb_legacy_name_is_valid("toolong99"));

    assert(legacy_userdb_display_name_is_compatible("Jürgen"));
    assert(!legacy_userdb_display_name_is_compatible(" Leading"));
    assert(!legacy_userdb_display_name_is_compatible("Trailing "));
    assert(!legacy_userdb_display_name_is_compatible(control_name));
    assert(!legacy_userdb_display_name_is_compatible(c1_name));
    assert(!legacy_userdb_display_name_is_compatible(invalid_utf8));

    init_record(&records[0], "one", "One User", NULL);
    init_record(&records[1], "two", "Two User", NULL);
    make_test_root(&root);
    create_users_file(&root, records, 2U, 8, 598, 0U);

    query.legacy_name = NULL;
    query.display_name = NULL;
    assert(legacy_userdb_inspect(root.path, &policy, &query, &result,
                                 &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_ARGUMENT);

    query.legacy_name = "Upper";
    query.display_name = "Valid Name";
    assert(legacy_userdb_inspect(root.path, &policy, &query, &result,
                                 &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_ARGUMENT);

    policy = default_policy();
    policy.max_records = 1U;
    assert(legacy_userdb_inspect(root.path, &policy, NULL, &result,
                                 &error) == -1);
    assert(error.status == LEGACY_USERDB_TOO_MANY_RECORDS);

    policy = default_policy();
    policy.max_records = 0U;
    assert(legacy_userdb_inspect(root.path, &policy, NULL, &result,
                                 &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_ARGUMENT);

    policy = default_policy();
    assert(legacy_userdb_inspect("relative", &policy, NULL, &result,
                                 &error) == -1);
    assert(error.status == LEGACY_USERDB_INVALID_ARGUMENT);
    remove_test_root(&root);
}

static void
test_busy_lock(void)
{
    test_root_t root;
    struct userrec record;
    legacy_userdb_policy_t policy = default_policy();
    legacy_userdb_scan_result_t result;
    legacy_userdb_error_t error;
    int ready_pipe[2];
    int release_pipe[2];
    struct flock same_process_lock;
    int same_process_fd;
    pid_t child;
    int status;

    init_record(&record, "locked", "Locked User", NULL);
    make_test_root(&root);
    create_users_file(&root, &record, 1U, 8, 598, 0U);

    same_process_fd = open(root.users_path, O_RDWR | O_CLOEXEC);
    assert(same_process_fd >= 0);
    memset(&same_process_lock, 0, sizeof(same_process_lock));
    same_process_lock.l_type = F_WRLCK;
    same_process_lock.l_whence = SEEK_SET;
    assert(fcntl(same_process_fd, F_OFD_SETLK,
                 &same_process_lock) == 0);
    assert(legacy_userdb_inspect(root.path, &policy, NULL, &result,
                                 &error) == -1);
    assert(error.status == LEGACY_USERDB_BUSY);
    assert(close(same_process_fd) == 0);

    assert(pipe(ready_pipe) == 0);
    assert(pipe(release_pipe) == 0);

    child = fork();
    assert(child >= 0);
    if (child == 0) {
        struct flock lock;
        char byte = 'x';
        int fd;

        (void)close(ready_pipe[0]);
        (void)close(release_pipe[1]);
        fd = open(root.users_path, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            _exit(2);
        }
        memset(&lock, 0, sizeof(lock));
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        if (fcntl(fd, F_SETLK, &lock) != 0) {
            _exit(3);
        }
        if (write(ready_pipe[1], &byte, 1U) != 1) {
            _exit(4);
        }
        if (read(release_pipe[0], &byte, 1U) != 1) {
            _exit(5);
        }
        (void)close(fd);
        _exit(0);
    }

    (void)close(ready_pipe[1]);
    (void)close(release_pipe[0]);
    {
        char byte;
        assert(read(ready_pipe[0], &byte, 1U) == 1);
        assert(legacy_userdb_inspect(root.path, &policy, NULL, &result,
                                     &error) == -1);
        assert(error.status == LEGACY_USERDB_BUSY);
        assert(write(release_pipe[1], &byte, 1U) == 1);
    }
    (void)close(ready_pipe[0]);
    (void)close(release_pipe[1]);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    remove_test_root(&root);
}

static void
test_status_names_and_error_clear(void)
{
    legacy_userdb_error_t error;
    legacy_userdb_status_t status;

    memset(&error, 0xff, sizeof(error));
    legacy_userdb_error_clear(&error);
    assert(error.status == LEGACY_USERDB_OK);
    assert(error.system_errno == 0);
    assert(error.record_number == LEGACY_USERDB_NO_RECORD);
    assert(error.text[0] == '\0');

    for (status = LEGACY_USERDB_OK;
         status <= LEGACY_USERDB_CHANGED_DURING_SCAN;
         status = (legacy_userdb_status_t)(status + 1)) {
        assert(strcmp(legacy_userdb_status_name(status), "unknown") != 0);
    }
    assert(strcmp(legacy_userdb_status_name(
                      (legacy_userdb_status_t)999), "unknown") == 0);
}

int
main(void)
{
    test_valid_scan_and_collisions();
    test_header_and_size_validation();
    test_path_and_file_policy();
    test_invalid_records_and_duplicates();
    test_query_and_policy_validation();
    test_busy_lock();
    test_status_names_and_error_clear();
    (void)puts("legacy users.data read-only gateway tests: OK");
    return 0;
}
