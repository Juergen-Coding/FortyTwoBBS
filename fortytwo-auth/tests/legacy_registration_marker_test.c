/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "legacy_registration_marker.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct marker_fixture {
    char base_path[PATH_MAX];
    char user_path[PATH_MAX];
    char marker_path[PATH_MAX];
} marker_fixture_t;

static const char valid_prepared_marker[] =
    "format_version=1\n"
    "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
    "user_id=abcdef01-2345-4678-9abc-def012345678\n"
    "legacy_name=neo67\n"
    "record_number=42\n"
    "state=prepared\n";

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
make_fixture(marker_fixture_t *fixture, const char *contents)
{
    char template_path[] = "/tmp/fortytwo-marker-XXXXXX";
    char *created;
    int fd;

    memset(fixture, 0, sizeof(*fixture));
    created = mkdtemp(template_path);
    assert(created != NULL);
    assert(snprintf(fixture->base_path, sizeof(fixture->base_path), "%s",
                    created) > 0);
    assert(chmod(fixture->base_path,
                 LEGACY_REGISTRATION_MARKER_DIRECTORY_MODE) == 0);
    assert(snprintf(fixture->user_path, sizeof(fixture->user_path), "%s/neo67",
                    fixture->base_path) > 0);
    assert(snprintf(fixture->marker_path, sizeof(fixture->marker_path), "%s/%s",
                    fixture->user_path, LEGACY_USERDB_MARKER_FILE) > 0);
    assert(mkdir(fixture->user_path,
                 LEGACY_REGISTRATION_MARKER_DIRECTORY_MODE) == 0);
    assert(chmod(fixture->user_path,
                 LEGACY_REGISTRATION_MARKER_DIRECTORY_MODE) == 0);

    fd = open(fixture->marker_path,
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    write_all(fd, contents, strlen(contents));
    assert(fchmod(fd, LEGACY_REGISTRATION_MARKER_MODE) == 0);
    assert(close(fd) == 0);
}

static void
replace_marker(const marker_fixture_t *fixture, const char *contents)
{
    int fd = open(fixture->marker_path,
                  O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);

    assert(fd >= 0);
    write_all(fd, contents, strlen(contents));
    assert(fchmod(fd, LEGACY_REGISTRATION_MARKER_MODE) == 0);
    assert(close(fd) == 0);
}

static void
remove_fixture(const marker_fixture_t *fixture)
{
    char path[PATH_MAX];

    assert(snprintf(path, sizeof(path), "%s/marker.link",
                    fixture->user_path) > 0);
    (void)unlink(path);
    assert(snprintf(path, sizeof(path), "%s/marker.real",
                    fixture->user_path) > 0);
    (void)unlink(path);
    (void)unlink(fixture->marker_path);
    assert(rmdir(fixture->user_path) == 0);
    assert(rmdir(fixture->base_path) == 0);
}

static legacy_registration_marker_policy_t
default_policy(void)
{
    legacy_registration_marker_policy_t policy;

    legacy_registration_marker_policy_defaults(&policy);
    return policy;
}

static void
expect_failure(const marker_fixture_t *fixture,
               const legacy_registration_marker_policy_t *policy,
               legacy_registration_marker_status_t expected)
{
    legacy_registration_marker_t marker;
    legacy_registration_marker_error_t error;

    legacy_registration_marker_clear(&marker);
    assert(legacy_registration_marker_read(
               fixture->base_path, "neo67", policy, &marker, &error) == -1);
    if (error.status != expected) {
        (void)fprintf(stderr, "expected %s, got %s: %s\n",
                      legacy_registration_marker_status_name(expected),
                      legacy_registration_marker_status_name(error.status),
                      error.text);
    }
    assert(error.status == expected);
    assert(error.text[0] != '\0');
}

static void
test_valid_prepared_and_committed(void)
{
    marker_fixture_t fixture;
    legacy_registration_marker_policy_t policy = default_policy();
    legacy_registration_marker_t marker;
    legacy_registration_marker_error_t error;
    const char committed_marker[] =
        "state=committed\n"
        "record_number=0\n"
        "legacy_name=neo67\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "format_version=1\n";

    make_fixture(&fixture, valid_prepared_marker);
    legacy_registration_marker_clear(&marker);
    if (legacy_registration_marker_read(
            fixture.base_path, "neo67", &policy, &marker, &error) != 0) {
        (void)fprintf(stderr, "valid marker failed: %s: %s errno=%d\n",
                      legacy_registration_marker_status_name(error.status),
                      error.text, error.system_errno);
        assert(false);
    }
    assert(error.status == LEGACY_REGISTRATION_MARKER_OK);
    assert(marker.format_version == 1U);
    assert(marker.record_number == 42U);
    assert(marker.state == LEGACY_REGISTRATION_MARKER_PREPARED);
    assert(strcmp(marker.legacy_name, "neo67") == 0);
    assert(marker.registration_id[0] == 0x12U);
    assert(marker.registration_id[15] == 0xabU);
    assert(marker.user_id[0] == 0xabU);
    assert(marker.user_id[15] == 0x78U);
    assert(S_ISREG(marker.file_status.st_mode));

    replace_marker(&fixture, committed_marker);
    legacy_registration_marker_clear(&marker);
    assert(legacy_registration_marker_read(
               fixture.base_path, "neo67", &policy, &marker, &error) == 0);
    assert(marker.record_number == 0U);
    assert(marker.state == LEGACY_REGISTRATION_MARKER_COMMITTED);
    assert(strcmp(legacy_registration_marker_state_name(marker.state),
                  "committed") == 0);
    remove_fixture(&fixture);
}

static void
test_failed_read_clears_output(void)
{
    marker_fixture_t fixture;
    legacy_registration_marker_policy_t policy = default_policy();
    legacy_registration_marker_t marker;
    legacy_registration_marker_error_t error;
    const char invalid_state_marker[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "record_number=42\n"
        "state=pending\n";

    make_fixture(&fixture, valid_prepared_marker);
    legacy_registration_marker_clear(&marker);
    assert(legacy_registration_marker_read(
               fixture.base_path, "neo67", &policy, &marker, &error) == 0);
    assert(marker.state == LEGACY_REGISTRATION_MARKER_PREPARED);

    replace_marker(&fixture, invalid_state_marker);
    assert(legacy_registration_marker_read(
               fixture.base_path, "neo67", &policy, &marker, &error) == -1);
    assert(error.status == LEGACY_REGISTRATION_MARKER_INVALID_STATE);
    assert(marker.format_version == 0U);
    assert(marker.registration_id[0] == 0U);
    assert(marker.user_id[0] == 0U);
    assert(marker.legacy_name[0] == '\0');
    assert(marker.record_number == 0U);
    assert(marker.state == LEGACY_REGISTRATION_MARKER_STATE_INVALID);
    remove_fixture(&fixture);
}

static void
test_format_validation(void)
{
    marker_fixture_t fixture;
    legacy_registration_marker_policy_t policy = default_policy();
    const char unknown_key[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "record_number=42\n"
        "surprise=prepared\n";
    const char duplicate_key[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "record_number=42\n"
        "state=prepared\n";
    const char invalid_uuid[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4ABC-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "record_number=42\n"
        "state=prepared\n";
    const char oversized_record[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "record_number=65536\n"
        "state=prepared\n";
    const char wrong_name[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=marta\n"
        "record_number=42\n"
        "state=prepared\n";
    const char missing_newline[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "record_number=42\n"
        "state=prepared";
    const char missing_key[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "state=prepared\n";
    const char invalid_state[] =
        "format_version=1\n"
        "registration_id=12345678-1234-4abc-8def-1234567890ab\n"
        "user_id=abcdef01-2345-4678-9abc-def012345678\n"
        "legacy_name=neo67\n"
        "record_number=42\n"
        "state=pending\n";

    make_fixture(&fixture, unknown_key);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_UNKNOWN_KEY);
    replace_marker(&fixture, duplicate_key);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_DUPLICATE_KEY);
    replace_marker(&fixture, invalid_uuid);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_INVALID_UUID);
    replace_marker(&fixture, oversized_record);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_INVALID_RECORD_NUMBER);
    replace_marker(&fixture, wrong_name);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_LEGACY_NAME_MISMATCH);
    replace_marker(&fixture, missing_newline);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_INVALID_FORMAT);
    replace_marker(&fixture, missing_key);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_MISSING_KEY);
    replace_marker(&fixture, invalid_state);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_INVALID_STATE);
    remove_fixture(&fixture);
}

static void
test_file_and_directory_policy(void)
{
    marker_fixture_t fixture;
    legacy_registration_marker_policy_t policy = default_policy();
    char real_path[PATH_MAX];
    char link_path[PATH_MAX];

    make_fixture(&fixture, valid_prepared_marker);
    assert(chmod(fixture.marker_path, 0640) == 0);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_MODE_MISMATCH);
    assert(chmod(fixture.marker_path, 0600) == 0);

    assert(snprintf(link_path, sizeof(link_path), "%s/marker.link",
                    fixture.user_path) > 0);
    assert(link(fixture.marker_path, link_path) == 0);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_LINK_COUNT_MISMATCH);
    assert(unlink(link_path) == 0);

    assert(snprintf(real_path, sizeof(real_path), "%s/marker.real",
                    fixture.user_path) > 0);
    assert(rename(fixture.marker_path, real_path) == 0);
    assert(symlink("marker.real", fixture.marker_path) == 0);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_OPEN_FILE_FAILED);
    assert(unlink(fixture.marker_path) == 0);
    assert(rename(real_path, fixture.marker_path) == 0);

    assert(unlink(fixture.marker_path) == 0);
    assert(mkfifo(fixture.marker_path, 0600) == 0);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_NOT_REGULAR);
    assert(unlink(fixture.marker_path) == 0);
    {
        int marker_fd = open(fixture.marker_path,
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(marker_fd >= 0);
        write_all(marker_fd, valid_prepared_marker,
                  strlen(valid_prepared_marker));
        assert(close(marker_fd) == 0);
    }

    assert(chmod(fixture.user_path, 0700) == 0);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_USER_DIRECTORY_POLICY_MISMATCH);
    assert(chmod(fixture.user_path, 0770) == 0);
    assert(chmod(fixture.base_path, 0700) == 0);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_BASE_POLICY_MISMATCH);
    assert(chmod(fixture.base_path, 0770) == 0);
    remove_fixture(&fixture);
}

static void
test_changed_during_read(void)
{
    marker_fixture_t fixture;
    legacy_registration_marker_policy_t policy = default_policy();

    make_fixture(&fixture, valid_prepared_marker);
    legacy_registration_marker_test_set_fault(
        LEGACY_REGISTRATION_MARKER_TEST_FAULT_CHANGE_AFTER_READ);
    expect_failure(&fixture, &policy,
                   LEGACY_REGISTRATION_MARKER_CHANGED_DURING_READ);
    legacy_registration_marker_test_set_fault(
        LEGACY_REGISTRATION_MARKER_TEST_FAULT_NONE);
    remove_fixture(&fixture);
}

static void
test_argument_and_status_helpers(void)
{
    marker_fixture_t fixture;
    legacy_registration_marker_policy_t policy = default_policy();
    legacy_registration_marker_t marker;
    legacy_registration_marker_error_t error;
    legacy_registration_marker_status_t status;

    make_fixture(&fixture, valid_prepared_marker);
    assert(legacy_registration_marker_read(
               "relative", "neo67", &policy, &marker, &error) == -1);
    assert(error.status == LEGACY_REGISTRATION_MARKER_INVALID_ARGUMENT);
    assert(legacy_registration_marker_read(
               fixture.base_path, "Upper", &policy, &marker, &error) == -1);
    assert(error.status == LEGACY_REGISTRATION_MARKER_INVALID_ARGUMENT);
    policy.max_size = 0U;
    assert(legacy_registration_marker_read(
               fixture.base_path, "neo67", &policy, &marker, &error) == -1);
    assert(error.status == LEGACY_REGISTRATION_MARKER_INVALID_ARGUMENT);

    for (status = LEGACY_REGISTRATION_MARKER_OK;
         status <= LEGACY_REGISTRATION_MARKER_INVALID_STATE;
         status = (legacy_registration_marker_status_t)(status + 1)) {
        assert(strcmp(legacy_registration_marker_status_name(status),
                      "unknown") != 0);
    }
    assert(strcmp(legacy_registration_marker_status_name(
                      (legacy_registration_marker_status_t)999),
                  "unknown") == 0);
    assert(strcmp(legacy_registration_marker_state_name(
                      LEGACY_REGISTRATION_MARKER_STATE_INVALID),
                  "invalid") == 0);
    assert(strcmp(legacy_registration_marker_state_name(
                      (legacy_registration_marker_state_t)999),
                  "unknown") == 0);
    remove_fixture(&fixture);
}

int
main(void)
{
    test_valid_prepared_and_committed();
    test_failed_read_clears_output();
    test_format_validation();
    test_file_and_directory_policy();
    test_changed_during_read();
    test_argument_and_status_helpers();
    (void)puts("legacy registration marker read-only parser tests: OK");
    return 0;
}
