/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "legacy_userdb.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#pragma pack(push, 1)
#include "../../lib/users.h"
#pragma pack(pop)

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "legacy users.data gateway requires the little-endian MBSE ABI"
#endif

_Static_assert(CHAR_BIT == 8, "legacy users.data requires 8-bit bytes");
_Static_assert(sizeof(struct userhdr) == LEGACY_USERDB_HEADER_SIZE,
               "legacy users.data header layout changed");
_Static_assert(sizeof(struct userrec) == LEGACY_USERDB_RECORD_SIZE,
               "legacy users.data record layout changed");
_Static_assert(offsetof(struct userrec, sUserName) == 0U,
               "legacy display-name offset changed");
_Static_assert(offsetof(struct userrec, Name) == 36U,
               "legacy name offset changed");
_Static_assert(offsetof(struct userrec, sHandle) == 510U,
               "legacy handle offset changed");
_Static_assert(offsetof(struct userrec, Password) == 563U,
               "legacy cleartext-password offset changed");

#ifndef F_OFD_SETLK
#error "legacy users.data gateway requires Linux open-file-description locks"
#endif

typedef struct legacy_name_entry {
    char name[LEGACY_USERDB_LEGACY_NAME_MAX + 1U];
    size_t record_number;
} legacy_name_entry_t;

static void
set_error(legacy_userdb_error_t *error,
          legacy_userdb_status_t status,
          int system_errno,
          size_t record_number,
          const char *text)
{
    if (error == NULL) {
        return;
    }

    memset(error, 0, sizeof(*error));
    error->status = status;
    error->system_errno = system_errno;
    error->record_number = record_number;
    if (text != NULL) {
        (void)snprintf(error->text, sizeof(error->text), "%s", text);
    }
}

void
legacy_userdb_error_clear(legacy_userdb_error_t *error)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->status = LEGACY_USERDB_OK;
        error->record_number = LEGACY_USERDB_NO_RECORD;
    }
}

void
legacy_userdb_policy_defaults(legacy_userdb_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }

    memset(policy, 0, sizeof(*policy));
    policy->check_owner = true;
    policy->expected_uid = geteuid();
    policy->check_group = true;
    policy->expected_gid = getegid();
    policy->check_mode = true;
    policy->expected_mode = (mode_t)0660;
    policy->require_single_link = true;
    policy->max_records = LEGACY_USERDB_DEFAULT_MAX_RECORDS;
}

const char *
legacy_userdb_status_name(legacy_userdb_status_t status)
{
    switch (status) {
    case LEGACY_USERDB_OK:
        return "ok";
    case LEGACY_USERDB_INVALID_ARGUMENT:
        return "invalid_argument";
    case LEGACY_USERDB_OPEN_ROOT_FAILED:
        return "open_root_failed";
    case LEGACY_USERDB_OPEN_ETC_FAILED:
        return "open_etc_failed";
    case LEGACY_USERDB_OPEN_FILE_FAILED:
        return "open_file_failed";
    case LEGACY_USERDB_STAT_FAILED:
        return "stat_failed";
    case LEGACY_USERDB_NOT_REGULAR:
        return "not_regular";
    case LEGACY_USERDB_OWNER_MISMATCH:
        return "owner_mismatch";
    case LEGACY_USERDB_GROUP_MISMATCH:
        return "group_mismatch";
    case LEGACY_USERDB_MODE_MISMATCH:
        return "mode_mismatch";
    case LEGACY_USERDB_LINK_COUNT_MISMATCH:
        return "link_count_mismatch";
    case LEGACY_USERDB_BUSY:
        return "busy";
    case LEGACY_USERDB_LOCK_FAILED:
        return "lock_failed";
    case LEGACY_USERDB_HEADER_TRUNCATED:
        return "header_truncated";
    case LEGACY_USERDB_HEADER_MISMATCH:
        return "header_mismatch";
    case LEGACY_USERDB_SIZE_MISMATCH:
        return "size_mismatch";
    case LEGACY_USERDB_TOO_MANY_RECORDS:
        return "too_many_records";
    case LEGACY_USERDB_READ_FAILED:
        return "read_failed";
    case LEGACY_USERDB_INVALID_RECORD:
        return "invalid_record";
    case LEGACY_USERDB_DUPLICATE_LEGACY_NAME:
        return "duplicate_legacy_name";
    case LEGACY_USERDB_MEMORY_FAILED:
        return "memory_failed";
    case LEGACY_USERDB_CHANGED_DURING_SCAN:
        return "changed_during_scan";
    case LEGACY_USERDB_INVALID_REGISTRATION:
        return "invalid_registration";
    case LEGACY_USERDB_ABI_MISMATCH:
        return "abi_mismatch";
    case LEGACY_USERDB_OPEN_RUNTIME_FAILED:
        return "open_runtime_failed";
    case LEGACY_USERDB_RUNTIME_POLICY_MISMATCH:
        return "runtime_policy_mismatch";
    case LEGACY_USERDB_CREATE_LOCK_FAILED:
        return "create_lock_failed";
    case LEGACY_USERDB_GLOBAL_BUSY:
        return "global_busy";
    case LEGACY_USERDB_OPEN_USERS_DIRECTORY_FAILED:
        return "open_users_directory_failed";
    case LEGACY_USERDB_USERS_DIRECTORY_POLICY_MISMATCH:
        return "users_directory_policy_mismatch";
    case LEGACY_USERDB_NAME_COLLISION:
        return "name_collision";
    case LEGACY_USERDB_REGISTRATION_EXISTS:
        return "registration_exists";
    case LEGACY_USERDB_TARGET_EXISTS:
        return "target_exists";
    case LEGACY_USERDB_STAGING_EXISTS:
        return "staging_exists";
    case LEGACY_USERDB_CREATE_DIRECTORY_FAILED:
        return "create_directory_failed";
    case LEGACY_USERDB_CREATE_MARKER_FAILED:
        return "create_marker_failed";
    case LEGACY_USERDB_WRITE_MARKER_FAILED:
        return "write_marker_failed";
    case LEGACY_USERDB_WRITE_FAILED:
        return "write_failed";
    case LEGACY_USERDB_SYNC_FAILED:
        return "sync_failed";
    case LEGACY_USERDB_VERIFY_FAILED:
        return "verify_failed";
    case LEGACY_USERDB_RENAME_FAILED:
        return "rename_failed";
    case LEGACY_USERDB_CONTEXT_INVALID:
        return "context_invalid";
    case LEGACY_USERDB_ROLLBACK_UNSAFE:
        return "rollback_unsafe";
    case LEGACY_USERDB_ROLLBACK_FAILED:
        return "rollback_failed";
    default:
        return "unknown";
    }
}

static unsigned char
ascii_fold(unsigned char value)
{
    if (value >= (unsigned char)'A' && value <= (unsigned char)'Z') {
        return (unsigned char)(value - (unsigned char)'A' +
                               (unsigned char)'a');
    }
    return value;
}

static int
ascii_case_compare(const char *left, const char *right)
{
    size_t index = 0U;

    for (;;) {
        unsigned char left_value = ascii_fold((unsigned char)left[index]);
        unsigned char right_value = ascii_fold((unsigned char)right[index]);

        if (left_value != right_value) {
            return left_value < right_value ? -1 : 1;
        }
        if (left_value == 0U) {
            return 0;
        }
        ++index;
    }
}

static int
legacy_name_entry_compare(const void *left, const void *right)
{
    const legacy_name_entry_t *left_entry = left;
    const legacy_name_entry_t *right_entry = right;
    int comparison = ascii_case_compare(left_entry->name, right_entry->name);

    if (comparison != 0) {
        return comparison;
    }
    if (left_entry->record_number < right_entry->record_number) {
        return -1;
    }
    if (left_entry->record_number > right_entry->record_number) {
        return 1;
    }
    return 0;
}

bool
legacy_userdb_legacy_name_is_valid(const char *legacy_name)
{
    size_t length;
    size_t index;

    if (legacy_name == NULL) {
        return false;
    }
    length = strnlen(legacy_name, LEGACY_USERDB_LEGACY_NAME_MAX + 1U);
    if (length == 0U || length > LEGACY_USERDB_LEGACY_NAME_MAX) {
        return false;
    }

    for (index = 0U; index < length; ++index) {
        unsigned char value = (unsigned char)legacy_name[index];
        bool alpha = value >= (unsigned char)'a' &&
                     value <= (unsigned char)'z';
        bool digit = value >= (unsigned char)'0' &&
                     value <= (unsigned char)'9';
        bool separator = index > 0U &&
                         (value == (unsigned char)'.' ||
                          value == (unsigned char)'_' ||
                          value == (unsigned char)'-');

        if (!alpha && !digit && !separator) {
            return false;
        }
    }
    return true;
}

static bool
utf8_sequence_is_valid(const unsigned char *text,
                       size_t length,
                       size_t *consumed)
{
    unsigned char first;
    uint32_t codepoint;
    size_t sequence_length;
    size_t index;

    if (text == NULL || consumed == NULL || length == 0U) {
        return false;
    }

    first = text[0];
    if (first <= 0x7fU) {
        *consumed = 1U;
        return first >= 0x20U && first != 0x7fU;
    }
    if (first >= 0xc2U && first <= 0xdfU) {
        sequence_length = 2U;
        codepoint = (uint32_t)(first & 0x1fU);
    } else if (first >= 0xe0U && first <= 0xefU) {
        sequence_length = 3U;
        codepoint = (uint32_t)(first & 0x0fU);
    } else if (first >= 0xf0U && first <= 0xf4U) {
        sequence_length = 4U;
        codepoint = (uint32_t)(first & 0x07U);
    } else {
        return false;
    }
    if (sequence_length > length) {
        return false;
    }

    for (index = 1U; index < sequence_length; ++index) {
        unsigned char continuation = text[index];

        if ((continuation & 0xc0U) != 0x80U) {
            return false;
        }
        codepoint = (codepoint << 6U) | (uint32_t)(continuation & 0x3fU);
    }

    if ((sequence_length == 3U && codepoint < UINT32_C(0x800)) ||
        (sequence_length == 4U && codepoint < UINT32_C(0x10000)) ||
        codepoint > UINT32_C(0x10ffff) ||
        (codepoint >= UINT32_C(0xd800) && codepoint <= UINT32_C(0xdfff)) ||
        (codepoint >= UINT32_C(0x80) && codepoint <= UINT32_C(0x9f))) {
        return false;
    }

    *consumed = sequence_length;
    return true;
}

bool
legacy_userdb_display_name_is_compatible(const char *display_name)
{
    const unsigned char *bytes = (const unsigned char *)display_name;
    size_t length;
    size_t offset = 0U;

    if (display_name == NULL) {
        return false;
    }
    length = strnlen(display_name, LEGACY_USERDB_DISPLAY_NAME_MAX + 1U);
    if (length == 0U || length > LEGACY_USERDB_DISPLAY_NAME_MAX ||
        bytes[0] == (unsigned char)' ' ||
        bytes[length - 1U] == (unsigned char)' ') {
        return false;
    }

    while (offset < length) {
        size_t consumed = 0U;

        if (!utf8_sequence_is_valid(bytes + offset, length - offset,
                                    &consumed)) {
            return false;
        }
        offset += consumed;
    }
    return true;
}

static bool
fixed_text_is_terminated(const char *text, size_t capacity)
{
    return text != NULL && memchr(text, '\0', capacity) != NULL;
}

static int
read_exact_at(int fd, void *buffer, size_t length, off_t offset)
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

static bool
same_timestamp(const struct timespec *left, const struct timespec *right)
{
    return left->tv_sec == right->tv_sec && left->tv_nsec == right->tv_nsec;
}

static bool
file_snapshot_is_unchanged(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           same_timestamp(&before->st_mtim, &after->st_mtim) &&
           same_timestamp(&before->st_ctim, &after->st_ctim);
}

static int
open_users_file(const char *mbse_root,
                const legacy_userdb_policy_t *policy,
                struct stat *snapshot,
                legacy_userdb_error_t *error)
{
    struct flock lock;
    struct stat file_status;
    int root_fd = -1;
    int etc_fd = -1;
    int users_fd = -1;

    root_fd = open(mbse_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        set_error(error, LEGACY_USERDB_OPEN_ROOT_FAILED, errno,
                  LEGACY_USERDB_NO_RECORD, "cannot open MBSE root directory");
        goto failed;
    }
    etc_fd = openat(root_fd, "etc",
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (etc_fd < 0) {
        set_error(error, LEGACY_USERDB_OPEN_ETC_FAILED, errno,
                  LEGACY_USERDB_NO_RECORD, "cannot open MBSE etc directory");
        goto failed;
    }
    users_fd = openat(etc_fd, "users.data",
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (users_fd < 0) {
        set_error(error, LEGACY_USERDB_OPEN_FILE_FAILED, errno,
                  LEGACY_USERDB_NO_RECORD, "cannot open legacy users database");
        goto failed;
    }
    if (fstat(users_fd, &file_status) != 0) {
        set_error(error, LEGACY_USERDB_STAT_FAILED, errno,
                  LEGACY_USERDB_NO_RECORD, "cannot inspect legacy users database");
        goto failed;
    }
    if (!S_ISREG(file_status.st_mode)) {
        set_error(error, LEGACY_USERDB_NOT_REGULAR, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database is not a regular file");
        goto failed;
    }
    if (policy->check_owner && file_status.st_uid != policy->expected_uid) {
        set_error(error, LEGACY_USERDB_OWNER_MISMATCH, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database owner does not match policy");
        goto failed;
    }
    if (policy->check_group && file_status.st_gid != policy->expected_gid) {
        set_error(error, LEGACY_USERDB_GROUP_MISMATCH, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database group does not match policy");
        goto failed;
    }
    if (policy->check_mode &&
        (file_status.st_mode & (mode_t)07777) != policy->expected_mode) {
        set_error(error, LEGACY_USERDB_MODE_MISMATCH, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database mode does not match policy");
        goto failed;
    }
    if (policy->require_single_link && file_status.st_nlink != 1) {
        set_error(error, LEGACY_USERDB_LINK_COUNT_MISMATCH, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database has an unexpected link count");
        goto failed;
    }

    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_RDLCK;
    lock.l_whence = SEEK_SET;
    /* OFD locks also serialize independent threads in one auth process. */
    if (fcntl(users_fd, F_OFD_SETLK, &lock) != 0) {
        legacy_userdb_status_t status =
            errno == EACCES || errno == EAGAIN
                ? LEGACY_USERDB_BUSY : LEGACY_USERDB_LOCK_FAILED;
        set_error(error, status, errno, LEGACY_USERDB_NO_RECORD,
                  status == LEGACY_USERDB_BUSY
                      ? "legacy users database is locked"
                      : "cannot lock legacy users database");
        goto failed;
    }

    *snapshot = file_status;
    (void)close(etc_fd);
    (void)close(root_fd);
    return users_fd;

failed:
    if (users_fd >= 0) {
        (void)close(users_fd);
    }
    if (etc_fd >= 0) {
        (void)close(etc_fd);
    }
    if (root_fd >= 0) {
        (void)close(root_fd);
    }
    return -1;
}

static bool
policy_is_valid(const legacy_userdb_policy_t *policy)
{
    return policy != NULL && policy->max_records > 0U &&
           policy->max_records <= LEGACY_USERDB_DEFAULT_MAX_RECORDS &&
           (!policy->check_mode ||
            (policy->expected_mode & ~(mode_t)07777) == 0);
}

static bool
query_is_valid(const legacy_userdb_query_t *query)
{
    if (query == NULL) {
        return true;
    }
    if (query->legacy_name != NULL &&
        !legacy_userdb_legacy_name_is_valid(query->legacy_name)) {
        return false;
    }
    if (query->display_name != NULL &&
        !legacy_userdb_display_name_is_compatible(query->display_name)) {
        return false;
    }
    return query->legacy_name != NULL || query->display_name != NULL;
}

static int
scan_records(int fd,
             size_t record_count,
             const legacy_userdb_query_t *query,
             legacy_userdb_scan_result_t *result,
             legacy_userdb_error_t *error)
{
    legacy_name_entry_t *names = NULL;
    size_t name_count = 0U;
    size_t record_number;

    if (record_count > 0U) {
        names = calloc(record_count, sizeof(*names));
        if (names == NULL) {
            set_error(error, LEGACY_USERDB_MEMORY_FAILED, errno,
                      LEGACY_USERDB_NO_RECORD,
                      "cannot allocate legacy-name scan table");
            return -1;
        }
    }

    for (record_number = 0U; record_number < record_count; ++record_number) {
        struct userrec record;
        off_t offset = (off_t)LEGACY_USERDB_HEADER_SIZE +
                       (off_t)(record_number * LEGACY_USERDB_RECORD_SIZE);

        memset(&record, 0, sizeof(record));
        if (read_exact_at(fd, &record, sizeof(record), offset) != 0) {
            int saved_errno = errno;
            free(names);
            set_error(error, LEGACY_USERDB_READ_FAILED, saved_errno,
                      record_number, "cannot read legacy user record");
            return -1;
        }
        if (!fixed_text_is_terminated(record.Name, sizeof(record.Name)) ||
            !fixed_text_is_terminated(record.sUserName,
                                      sizeof(record.sUserName)) ||
            !fixed_text_is_terminated(record.sHandle,
                                      sizeof(record.sHandle)) ||
            !fixed_text_is_terminated(record.Password,
                                      sizeof(record.Password))) {
            free(names);
            set_error(error, LEGACY_USERDB_INVALID_RECORD, 0, record_number,
                      "legacy user record contains unterminated text");
            return -1;
        }

        if (record.Name[0] != '\0') {
            (void)snprintf(names[name_count].name,
                           sizeof(names[name_count].name), "%s", record.Name);
            names[name_count].record_number = record_number;
            ++name_count;
        }

        if (query != NULL && query->legacy_name != NULL &&
            ascii_case_compare(record.Name, query->legacy_name) == 0) {
            if (!result->legacy_name_exists) {
                result->legacy_name_exists = true;
                result->legacy_name_record = record_number;
            }
        }
        if (query != NULL && query->display_name != NULL &&
            ascii_case_compare(record.sUserName, query->display_name) == 0) {
            if (!result->display_name_exists) {
                result->display_name_exists = true;
                result->display_name_record = record_number;
            }
        }
        if (query != NULL && query->display_name != NULL &&
            record.sHandle[0] != '\0' &&
            ascii_case_compare(record.sHandle, query->display_name) == 0) {
            if (!result->handle_exists) {
                result->handle_exists = true;
                result->handle_record = record_number;
            }
        }
    }

    if (name_count > 1U) {
        size_t index;

        qsort(names, name_count, sizeof(*names), legacy_name_entry_compare);
        for (index = 1U; index < name_count; ++index) {
            if (ascii_case_compare(names[index - 1U].name,
                                   names[index].name) == 0) {
                size_t duplicate_record = names[index].record_number;
                free(names);
                set_error(error, LEGACY_USERDB_DUPLICATE_LEGACY_NAME, 0,
                          duplicate_record,
                          "legacy users database contains duplicate names");
                return -1;
            }
        }
    }

    free(names);
    return 0;
}

int
legacy_userdb_inspect(const char *mbse_root,
                      const legacy_userdb_policy_t *policy,
                      const legacy_userdb_query_t *query,
                      legacy_userdb_scan_result_t *result,
                      legacy_userdb_error_t *error)
{
    struct userhdr header;
    struct stat before;
    struct stat after;
    off_t payload_size;
    size_t record_count;
    int fd;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->legacy_name_record = LEGACY_USERDB_NO_RECORD;
        result->display_name_record = LEGACY_USERDB_NO_RECORD;
        result->handle_record = LEGACY_USERDB_NO_RECORD;
    }
    legacy_userdb_error_clear(error);

    if (mbse_root == NULL || mbse_root[0] != '/' ||
        !policy_is_valid(policy) || !query_is_valid(query) || result == NULL) {
        set_error(error, LEGACY_USERDB_INVALID_ARGUMENT, EINVAL,
                  LEGACY_USERDB_NO_RECORD,
                  "invalid legacy users database argument");
        return -1;
    }

    fd = open_users_file(mbse_root, policy, &before, error);
    if (fd < 0) {
        return -1;
    }
    if (before.st_size < (off_t)LEGACY_USERDB_HEADER_SIZE) {
        (void)close(fd);
        set_error(error, LEGACY_USERDB_HEADER_TRUNCATED, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database header is truncated");
        return -1;
    }
    if (read_exact_at(fd, &header, sizeof(header), 0) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        set_error(error, LEGACY_USERDB_READ_FAILED, saved_errno,
                  LEGACY_USERDB_NO_RECORD,
                  "cannot read legacy users database header");
        return -1;
    }
    if (header.hdrsize != (int)LEGACY_USERDB_HEADER_SIZE ||
        header.recsize != (int)LEGACY_USERDB_RECORD_SIZE) {
        (void)close(fd);
        set_error(error, LEGACY_USERDB_HEADER_MISMATCH, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database layout does not match this build");
        return -1;
    }

    payload_size = before.st_size - (off_t)LEGACY_USERDB_HEADER_SIZE;
    if (payload_size < 0 ||
        payload_size % (off_t)LEGACY_USERDB_RECORD_SIZE != 0) {
        (void)close(fd);
        set_error(error, LEGACY_USERDB_SIZE_MISMATCH, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database ends with a partial record");
        return -1;
    }
    record_count = (size_t)(payload_size /
                            (off_t)LEGACY_USERDB_RECORD_SIZE);
    if (record_count > policy->max_records) {
        (void)close(fd);
        set_error(error, LEGACY_USERDB_TOO_MANY_RECORDS, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database exceeds the configured limit");
        return -1;
    }

    result->record_count = record_count;
    if (scan_records(fd, record_count, query, result, error) != 0) {
        (void)close(fd);
        return -1;
    }
    if (fstat(fd, &after) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        set_error(error, LEGACY_USERDB_STAT_FAILED, saved_errno,
                  LEGACY_USERDB_NO_RECORD,
                  "cannot recheck legacy users database");
        return -1;
    }
    if (!file_snapshot_is_unchanged(&before, &after)) {
        (void)close(fd);
        set_error(error, LEGACY_USERDB_CHANGED_DURING_SCAN, 0,
                  LEGACY_USERDB_NO_RECORD,
                  "legacy users database changed during scan");
        return -1;
    }

    (void)close(fd);
    legacy_userdb_error_clear(error);
    return 0;
}
