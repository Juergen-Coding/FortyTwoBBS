/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "legacy_registration_marker.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MARKER_REQUIRED_KEYS 6U

#ifdef LEGACY_REGISTRATION_MARKER_TESTING
static legacy_registration_marker_test_fault_t active_test_fault;

void
legacy_registration_marker_test_set_fault(
    legacy_registration_marker_test_fault_t fault)
{
    active_test_fault = fault;
}
#endif

static void
set_error(legacy_registration_marker_error_t *error,
          legacy_registration_marker_status_t status,
          int system_errno,
          const char *text)
{
    if (error == NULL) {
        return;
    }

    memset(error, 0, sizeof(*error));
    error->status = status;
    error->system_errno = system_errno;
    if (text != NULL) {
        (void)snprintf(error->text, sizeof(error->text), "%s", text);
    }
}

void
legacy_registration_marker_error_clear(
    legacy_registration_marker_error_t *error)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->status = LEGACY_REGISTRATION_MARKER_OK;
    }
}

void
legacy_registration_marker_clear(legacy_registration_marker_t *marker)
{
    if (marker != NULL) {
        memset(marker, 0, sizeof(*marker));
    }
}

void
legacy_registration_marker_policy_defaults(
    legacy_registration_marker_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }

    memset(policy, 0, sizeof(*policy));
    policy->base_directory.check_owner = true;
    policy->base_directory.expected_uid = geteuid();
    policy->base_directory.check_group = true;
    policy->base_directory.expected_gid = getegid();
    policy->base_directory.check_mode = true;
    policy->base_directory.expected_mode =
        LEGACY_REGISTRATION_MARKER_DIRECTORY_MODE;
    policy->user_directory = policy->base_directory;
    policy->check_marker_owner = true;
    policy->expected_marker_uid = geteuid();
    policy->check_marker_group = true;
    policy->expected_marker_gid = getegid();
    policy->check_marker_mode = true;
    policy->expected_marker_mode = LEGACY_REGISTRATION_MARKER_MODE;
    policy->require_single_link = true;
    policy->max_size = LEGACY_REGISTRATION_MARKER_MAX_SIZE;
}

const char *
legacy_registration_marker_status_name(
    legacy_registration_marker_status_t status)
{
    switch (status) {
    case LEGACY_REGISTRATION_MARKER_OK:
        return "ok";
    case LEGACY_REGISTRATION_MARKER_INVALID_ARGUMENT:
        return "invalid_argument";
    case LEGACY_REGISTRATION_MARKER_OPEN_BASE_FAILED:
        return "open_base_failed";
    case LEGACY_REGISTRATION_MARKER_BASE_POLICY_MISMATCH:
        return "base_policy_mismatch";
    case LEGACY_REGISTRATION_MARKER_OPEN_USER_DIRECTORY_FAILED:
        return "open_user_directory_failed";
    case LEGACY_REGISTRATION_MARKER_USER_DIRECTORY_POLICY_MISMATCH:
        return "user_directory_policy_mismatch";
    case LEGACY_REGISTRATION_MARKER_OPEN_FILE_FAILED:
        return "open_file_failed";
    case LEGACY_REGISTRATION_MARKER_STAT_FAILED:
        return "stat_failed";
    case LEGACY_REGISTRATION_MARKER_NOT_REGULAR:
        return "not_regular";
    case LEGACY_REGISTRATION_MARKER_OWNER_MISMATCH:
        return "owner_mismatch";
    case LEGACY_REGISTRATION_MARKER_GROUP_MISMATCH:
        return "group_mismatch";
    case LEGACY_REGISTRATION_MARKER_MODE_MISMATCH:
        return "mode_mismatch";
    case LEGACY_REGISTRATION_MARKER_LINK_COUNT_MISMATCH:
        return "link_count_mismatch";
    case LEGACY_REGISTRATION_MARKER_SIZE_INVALID:
        return "size_invalid";
    case LEGACY_REGISTRATION_MARKER_READ_FAILED:
        return "read_failed";
    case LEGACY_REGISTRATION_MARKER_CHANGED_DURING_READ:
        return "changed_during_read";
    case LEGACY_REGISTRATION_MARKER_INVALID_FORMAT:
        return "invalid_format";
    case LEGACY_REGISTRATION_MARKER_UNKNOWN_KEY:
        return "unknown_key";
    case LEGACY_REGISTRATION_MARKER_DUPLICATE_KEY:
        return "duplicate_key";
    case LEGACY_REGISTRATION_MARKER_MISSING_KEY:
        return "missing_key";
    case LEGACY_REGISTRATION_MARKER_INVALID_UUID:
        return "invalid_uuid";
    case LEGACY_REGISTRATION_MARKER_INVALID_LEGACY_NAME:
        return "invalid_legacy_name";
    case LEGACY_REGISTRATION_MARKER_LEGACY_NAME_MISMATCH:
        return "legacy_name_mismatch";
    case LEGACY_REGISTRATION_MARKER_INVALID_RECORD_NUMBER:
        return "invalid_record_number";
    case LEGACY_REGISTRATION_MARKER_INVALID_STATE:
        return "invalid_state";
    default:
        return "unknown";
    }
}

const char *
legacy_registration_marker_state_name(
    legacy_registration_marker_state_t state)
{
    switch (state) {
    case LEGACY_REGISTRATION_MARKER_STATE_INVALID:
        return "invalid";
    case LEGACY_REGISTRATION_MARKER_PREPARED:
        return "prepared";
    case LEGACY_REGISTRATION_MARKER_COMMITTED:
        return "committed";
    default:
        return "unknown";
    }
}

static bool
directory_policy_is_valid(const legacy_userdb_directory_policy_t *policy)
{
    return policy != NULL &&
           (!policy->check_mode ||
            (policy->expected_mode & ~(mode_t)07777) == 0);
}

static bool
policy_is_valid(const legacy_registration_marker_policy_t *policy)
{
    return policy != NULL &&
           directory_policy_is_valid(&policy->base_directory) &&
           directory_policy_is_valid(&policy->user_directory) &&
           (!policy->check_marker_mode ||
            (policy->expected_marker_mode & ~(mode_t)07777) == 0) &&
           policy->max_size > 0U &&
           policy->max_size <= LEGACY_REGISTRATION_MARKER_MAX_SIZE;
}

static bool
directory_policy_matches(const struct stat *status,
                         const legacy_userdb_directory_policy_t *policy)
{
    return S_ISDIR(status->st_mode) &&
           (!policy->check_owner || status->st_uid == policy->expected_uid) &&
           (!policy->check_group || status->st_gid == policy->expected_gid) &&
           (!policy->check_mode ||
            (status->st_mode & (mode_t)07777) == policy->expected_mode);
}

static bool
same_timestamp(const struct timespec *left, const struct timespec *right)
{
    return left->tv_sec == right->tv_sec && left->tv_nsec == right->tv_nsec;
}

static bool
file_snapshot_is_unchanged(const struct stat *before,
                           const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before->st_uid == after->st_uid &&
           before->st_gid == after->st_gid &&
           before->st_mode == after->st_mode &&
           before->st_nlink == after->st_nlink &&
           same_timestamp(&before->st_mtim, &after->st_mtim) &&
           same_timestamp(&before->st_ctim, &after->st_ctim);
}

static int
open_absolute_directory_nofollow(const char *path)
{
    char component[NAME_MAX + 1U];
    const char *cursor;
    int current_fd = -1;

    if (path == NULL || path[0] != '/' || path[1] == '\0') {
        errno = EINVAL;
        return -1;
    }

    current_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_fd < 0) {
        return -1;
    }
    cursor = path + 1;
    while (*cursor != '\0') {
        const char *separator = strchr(cursor, '/');
        size_t length = separator == NULL
                            ? strlen(cursor)
                            : (size_t)(separator - cursor);
        int next_fd;

        if (length == 0U || length > NAME_MAX ||
            (length == 1U && cursor[0] == '.') ||
            (length == 2U && cursor[0] == '.' && cursor[1] == '.')) {
            (void)close(current_fd);
            errno = EINVAL;
            return -1;
        }
        memcpy(component, cursor, length);
        component[length] = '\0';
        next_fd = openat(current_fd, component,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved_errno = errno;
            (void)close(current_fd);
            errno = saved_errno;
            return -1;
        }
        (void)close(current_fd);
        current_fd = next_fd;
        if (separator == NULL) {
            cursor += length;
        } else {
            cursor = separator + 1;
            if (*cursor == '\0') {
                (void)close(current_fd);
                errno = EINVAL;
                return -1;
            }
        }
    }
    return current_fd;
}

static int
read_exact(int fd, void *buffer, size_t length)
{
    unsigned char *bytes = buffer;
    size_t completed = 0U;

    while (completed < length) {
        ssize_t received = read(fd, bytes + completed, length - completed);

        if (received > 0) {
            completed += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received == 0) {
            errno = EIO;
        }
        return -1;
    }
    return 0;
}

static int
lower_hex_value(unsigned char value)
{
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return (int)(value - (unsigned char)'a') + 10;
    }
    return -1;
}

static bool
uuid_is_nonzero(const uint8_t value[LEGACY_USERDB_UUID_SIZE])
{
    size_t index;

    for (index = 0U; index < LEGACY_USERDB_UUID_SIZE; ++index) {
        if (value[index] != 0U) {
            return true;
        }
    }
    return false;
}

static int
parse_uuid(const char *text, uint8_t output[LEGACY_USERDB_UUID_SIZE])
{
    static const size_t hyphen_positions[] = {8U, 13U, 18U, 23U};
    size_t input_index = 0U;
    size_t output_index = 0U;
    size_t hyphen_index = 0U;

    if (strlen(text) != LEGACY_USERDB_UUID_TEXT_SIZE - 1U) {
        return -1;
    }
    memset(output, 0, LEGACY_USERDB_UUID_SIZE);
    while (input_index < LEGACY_USERDB_UUID_TEXT_SIZE - 1U) {
        int high;
        int low;

        if (hyphen_index < sizeof(hyphen_positions) /
                                sizeof(hyphen_positions[0]) &&
            input_index == hyphen_positions[hyphen_index]) {
            if (text[input_index] != '-') {
                return -1;
            }
            ++hyphen_index;
            ++input_index;
            continue;
        }
        if (input_index + 1U >= LEGACY_USERDB_UUID_TEXT_SIZE - 1U ||
            output_index >= LEGACY_USERDB_UUID_SIZE) {
            return -1;
        }
        high = lower_hex_value((unsigned char)text[input_index]);
        low = lower_hex_value((unsigned char)text[input_index + 1U]);
        if (high < 0 || low < 0) {
            return -1;
        }
        output[output_index++] =
            (uint8_t)((unsigned int)high * 16U + (unsigned int)low);
        input_index += 2U;
    }
    return output_index == LEGACY_USERDB_UUID_SIZE && uuid_is_nonzero(output)
               ? 0
               : -1;
}

static int
parse_record_number(const char *text, size_t *record_number)
{
    uint32_t value = 0U;
    size_t length;
    size_t index;

    length = strlen(text);
    if (length == 0U || (length > 1U && text[0] == '0')) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char byte = (unsigned char)text[index];

        if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
            return -1;
        }
        value = value * 10U + (uint32_t)(byte - (unsigned char)'0');
        if (value > UINT32_C(65535)) {
            return -1;
        }
    }
    *record_number = (size_t)value;
    return 0;
}

typedef enum marker_key_index {
    MARKER_KEY_FORMAT_VERSION = 0,
    MARKER_KEY_REGISTRATION_ID,
    MARKER_KEY_USER_ID,
    MARKER_KEY_LEGACY_NAME,
    MARKER_KEY_RECORD_NUMBER,
    MARKER_KEY_STATE
} marker_key_index_t;

static int
parse_marker_text(char *text,
                  const char *expected_legacy_name,
                  legacy_registration_marker_t *marker,
                  legacy_registration_marker_error_t *error)
{
    bool seen[MARKER_REQUIRED_KEYS] = {false};
    char *cursor = text;
    size_t seen_count = 0U;

    if (text[0] == '\0' || text[strlen(text) - 1U] != '\n') {
        set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_FORMAT, 0,
                  "registration marker must end with one complete line");
        return -1;
    }

    while (*cursor != '\0') {
        char *newline = strchr(cursor, '\n');
        char *separator;
        const char *key;
        const char *value;
        marker_key_index_t key_index;

        if (newline == NULL || newline == cursor) {
            set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_FORMAT, 0,
                      "registration marker contains an incomplete or empty line");
            return -1;
        }
        *newline = '\0';
        separator = strchr(cursor, '=');
        if (separator == NULL || separator == cursor ||
            strchr(separator + 1, '=') != NULL) {
            set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_FORMAT, 0,
                      "registration marker line is not canonical key=value");
            return -1;
        }
        *separator = '\0';
        key = cursor;
        value = separator + 1;
        if (strcmp(key, "format_version") == 0) {
            key_index = MARKER_KEY_FORMAT_VERSION;
        } else if (strcmp(key, "registration_id") == 0) {
            key_index = MARKER_KEY_REGISTRATION_ID;
        } else if (strcmp(key, "user_id") == 0) {
            key_index = MARKER_KEY_USER_ID;
        } else if (strcmp(key, "legacy_name") == 0) {
            key_index = MARKER_KEY_LEGACY_NAME;
        } else if (strcmp(key, "record_number") == 0) {
            key_index = MARKER_KEY_RECORD_NUMBER;
        } else if (strcmp(key, "state") == 0) {
            key_index = MARKER_KEY_STATE;
        } else {
            set_error(error, LEGACY_REGISTRATION_MARKER_UNKNOWN_KEY, 0,
                      "registration marker contains an unknown key");
            return -1;
        }
        if (seen[key_index]) {
            set_error(error, LEGACY_REGISTRATION_MARKER_DUPLICATE_KEY, 0,
                      "registration marker contains a duplicate key");
            return -1;
        }
        seen[key_index] = true;
        ++seen_count;

        switch (key_index) {
        case MARKER_KEY_FORMAT_VERSION:
            if (strcmp(value, "1") != 0) {
                set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_FORMAT, 0,
                          "registration marker format version is unsupported");
                return -1;
            }
            marker->format_version =
                LEGACY_REGISTRATION_MARKER_FORMAT_VERSION;
            break;
        case MARKER_KEY_REGISTRATION_ID:
            if (parse_uuid(value, marker->registration_id) != 0) {
                set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_UUID, 0,
                          "registration marker registration_id is invalid");
                return -1;
            }
            break;
        case MARKER_KEY_USER_ID:
            if (parse_uuid(value, marker->user_id) != 0) {
                set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_UUID, 0,
                          "registration marker user_id is invalid");
                return -1;
            }
            break;
        case MARKER_KEY_LEGACY_NAME:
            if (!legacy_userdb_legacy_name_is_valid(value)) {
                set_error(error,
                          LEGACY_REGISTRATION_MARKER_INVALID_LEGACY_NAME, 0,
                          "registration marker legacy_name is invalid");
                return -1;
            }
            if (strcmp(value, expected_legacy_name) != 0) {
                set_error(error,
                          LEGACY_REGISTRATION_MARKER_LEGACY_NAME_MISMATCH, 0,
                          "registration marker legacy_name does not match directory");
                return -1;
            }
            (void)snprintf(marker->legacy_name,
                           sizeof(marker->legacy_name), "%s", value);
            break;
        case MARKER_KEY_RECORD_NUMBER:
            if (parse_record_number(value, &marker->record_number) != 0) {
                set_error(error,
                          LEGACY_REGISTRATION_MARKER_INVALID_RECORD_NUMBER, 0,
                          "registration marker record_number is invalid");
                return -1;
            }
            break;
        case MARKER_KEY_STATE:
            if (strcmp(value, "prepared") == 0) {
                marker->state = LEGACY_REGISTRATION_MARKER_PREPARED;
            } else if (strcmp(value, "committed") == 0) {
                marker->state = LEGACY_REGISTRATION_MARKER_COMMITTED;
            } else {
                set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_STATE, 0,
                          "registration marker state is invalid");
                return -1;
            }
            break;
        }
        cursor = newline + 1;
    }

    if (seen_count != MARKER_REQUIRED_KEYS) {
        set_error(error, LEGACY_REGISTRATION_MARKER_MISSING_KEY, 0,
                  "registration marker is missing a required key");
        return -1;
    }
    return 0;
}

int
legacy_registration_marker_read(
    const char *bbs_users_directory,
    const char *legacy_name,
    const legacy_registration_marker_policy_t *policy,
    legacy_registration_marker_t *marker,
    legacy_registration_marker_error_t *error)
{
    legacy_registration_marker_t candidate;
    struct stat base_status;
    struct stat base_after;
    struct stat user_status;
    struct stat user_after;
    struct stat before;
    struct stat after;
    char buffer[LEGACY_REGISTRATION_MARKER_MAX_SIZE + 1U];
    int base_fd = -1;
    int user_fd = -1;
    int marker_fd = -1;
    int result = -1;

    legacy_registration_marker_clear(&candidate);
    if (marker != NULL) {
        legacy_registration_marker_clear(marker);
    }
    legacy_registration_marker_error_clear(error);
    if (bbs_users_directory == NULL || bbs_users_directory[0] != '/' ||
        !legacy_userdb_legacy_name_is_valid(legacy_name) ||
        !policy_is_valid(policy) || marker == NULL) {
        set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_ARGUMENT, EINVAL,
                  "invalid registration marker argument");
        return -1;
    }

    base_fd = open_absolute_directory_nofollow(bbs_users_directory);
    if (base_fd < 0) {
        set_error(error, LEGACY_REGISTRATION_MARKER_OPEN_BASE_FAILED, errno,
                  "cannot open legacy users base directory");
        goto finished;
    }
    if (fstat(base_fd, &base_status) != 0) {
        set_error(error, LEGACY_REGISTRATION_MARKER_OPEN_BASE_FAILED, errno,
                  "cannot inspect legacy users base directory");
        goto finished;
    }
    if (!directory_policy_matches(&base_status, &policy->base_directory)) {
        set_error(error,
                  LEGACY_REGISTRATION_MARKER_BASE_POLICY_MISMATCH, 0,
                  "legacy users base directory violates policy");
        goto finished;
    }

    user_fd = openat(base_fd, legacy_name,
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (user_fd < 0) {
        set_error(error,
                  LEGACY_REGISTRATION_MARKER_OPEN_USER_DIRECTORY_FAILED,
                  errno, "cannot open legacy user directory");
        goto finished;
    }
    if (fstat(user_fd, &user_status) != 0) {
        set_error(error,
                  LEGACY_REGISTRATION_MARKER_OPEN_USER_DIRECTORY_FAILED,
                  errno, "cannot inspect legacy user directory");
        goto finished;
    }
    if (!directory_policy_matches(&user_status, &policy->user_directory)) {
        set_error(error,
                  LEGACY_REGISTRATION_MARKER_USER_DIRECTORY_POLICY_MISMATCH,
                  0, "legacy user directory violates policy");
        goto finished;
    }

    marker_fd = openat(user_fd, LEGACY_USERDB_MARKER_FILE,
                       O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (marker_fd < 0) {
        set_error(error, LEGACY_REGISTRATION_MARKER_OPEN_FILE_FAILED, errno,
                  "cannot open registration marker");
        goto finished;
    }
    if (fstat(marker_fd, &before) != 0) {
        set_error(error, LEGACY_REGISTRATION_MARKER_STAT_FAILED, errno,
                  "cannot inspect registration marker");
        goto finished;
    }
    if (!S_ISREG(before.st_mode)) {
        set_error(error, LEGACY_REGISTRATION_MARKER_NOT_REGULAR, 0,
                  "registration marker is not a regular file");
        goto finished;
    }
    if (policy->check_marker_owner &&
        before.st_uid != policy->expected_marker_uid) {
        set_error(error, LEGACY_REGISTRATION_MARKER_OWNER_MISMATCH, 0,
                  "registration marker owner does not match policy");
        goto finished;
    }
    if (policy->check_marker_group &&
        before.st_gid != policy->expected_marker_gid) {
        set_error(error, LEGACY_REGISTRATION_MARKER_GROUP_MISMATCH, 0,
                  "registration marker group does not match policy");
        goto finished;
    }
    if (policy->check_marker_mode &&
        (before.st_mode & (mode_t)07777) != policy->expected_marker_mode) {
        set_error(error, LEGACY_REGISTRATION_MARKER_MODE_MISMATCH, 0,
                  "registration marker mode does not match policy");
        goto finished;
    }
    if (policy->require_single_link && before.st_nlink != 1) {
        set_error(error,
                  LEGACY_REGISTRATION_MARKER_LINK_COUNT_MISMATCH, 0,
                  "registration marker has an unexpected link count");
        goto finished;
    }
    if (before.st_size <= 0 ||
        before.st_size > (off_t)policy->max_size) {
        set_error(error, LEGACY_REGISTRATION_MARKER_SIZE_INVALID, 0,
                  "registration marker size is invalid");
        goto finished;
    }

    memset(buffer, 0, sizeof(buffer));
    if (read_exact(marker_fd, buffer, (size_t)before.st_size) != 0) {
        set_error(error, LEGACY_REGISTRATION_MARKER_READ_FAILED, errno,
                  "cannot read registration marker");
        goto finished;
    }
    if (memchr(buffer, '\0', (size_t)before.st_size) != NULL) {
        set_error(error, LEGACY_REGISTRATION_MARKER_INVALID_FORMAT, 0,
                  "registration marker contains a NUL byte");
        goto finished;
    }
    buffer[(size_t)before.st_size] = '\0';

#ifdef LEGACY_REGISTRATION_MARKER_TESTING
    if (active_test_fault ==
        LEGACY_REGISTRATION_MARKER_TEST_FAULT_CHANGE_AFTER_READ) {
        struct timespec times[2];

        times[0].tv_sec = 0;
        times[0].tv_nsec = UTIME_OMIT;
        if (clock_gettime(CLOCK_REALTIME, &times[1]) != 0 ||
            futimens(marker_fd, times) != 0) {
            set_error(error, LEGACY_REGISTRATION_MARKER_READ_FAILED, errno,
                      "cannot inject registration marker test change");
            goto finished;
        }
    }
#endif

    if (fstat(marker_fd, &after) != 0 ||
        fstat(user_fd, &user_after) != 0 ||
        fstat(base_fd, &base_after) != 0) {
        set_error(error, LEGACY_REGISTRATION_MARKER_STAT_FAILED, errno,
                  "cannot recheck registration marker path");
        goto finished;
    }
    if (!file_snapshot_is_unchanged(&before, &after) ||
        !file_snapshot_is_unchanged(&user_status, &user_after) ||
        !file_snapshot_is_unchanged(&base_status, &base_after)) {
        set_error(error,
                  LEGACY_REGISTRATION_MARKER_CHANGED_DURING_READ, 0,
                  "registration marker path changed during read");
        goto finished;
    }
    if (parse_marker_text(buffer, legacy_name, &candidate, error) != 0) {
        goto finished;
    }

    candidate.base_directory_status = base_status;
    candidate.user_directory_status = user_status;
    candidate.file_status = before;
    *marker = candidate;
    legacy_registration_marker_error_clear(error);
    result = 0;

finished:
    if (marker_fd >= 0) {
        (void)close(marker_fd);
    }
    if (user_fd >= 0) {
        (void)close(user_fd);
    }
    if (base_fd >= 0) {
        (void)close(base_fd);
    }
    return result;
}
