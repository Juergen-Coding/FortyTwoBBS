/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Controlled append-only provisioning for the legacy MBSE users.data.
 */

#include "legacy_userdb.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#pragma pack(push, 1)
#include "../../lib/users.h"
#pragma pack(pop)

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "legacy users.data provisioning requires the little-endian MBSE ABI"
#endif

_Static_assert(CHAR_BIT == 8, "legacy users.data requires 8-bit bytes");
_Static_assert(sizeof(int) == 4U, "legacy users.data requires 32-bit int");
_Static_assert(sizeof(unsigned int) == 4U,
               "legacy users.data requires 32-bit unsigned int");
_Static_assert(sizeof(struct userhdr) == LEGACY_USERDB_HEADER_SIZE,
               "legacy users.data header layout changed");
_Static_assert(sizeof(struct userrec) == LEGACY_USERDB_RECORD_SIZE,
               "legacy users.data record layout changed");
_Static_assert(sizeof(securityrec) == 12U,
               "legacy security record layout changed");
_Static_assert(sizeof(((struct userrec *)0)->Password) == 15U,
               "legacy cleartext-password field changed");
_Static_assert(sizeof(LEGACY_USERDB_RECORD_MARKER_PREFIX) - 1U + 32U <
                   sizeof(((struct userrec *)0)->sComment),
               "registration marker no longer fits legacy comment field");
_Static_assert(offsetof(struct userrec, sUserName) == 0U,
               "legacy display-name offset changed");
_Static_assert(offsetof(struct userrec, Name) == 36U,
               "legacy name offset changed");
_Static_assert(offsetof(struct userrec, xPassword) == 45U,
               "legacy password-state offset changed");
_Static_assert(offsetof(struct userrec, tFirstLoginDate) == 252U,
               "legacy first-login offset changed");
_Static_assert(offsetof(struct userrec, Security) == 260U,
               "legacy security offset changed");
_Static_assert(offsetof(struct userrec, sComment) == 272U,
               "legacy comment offset changed");
_Static_assert(offsetof(struct userrec, sExpiryDate) == 353U,
               "legacy expiry-date offset changed");
_Static_assert(offsetof(struct userrec, ExpirySec) == 365U,
               "legacy expiry-security offset changed");
_Static_assert(offsetof(struct userrec, iTotalCalls) == 387U,
               "legacy primary option-bit layout changed");
_Static_assert(offsetof(struct userrec, MsgEditor) == 423U,
               "legacy message-editor offset changed");
_Static_assert(offsetof(struct userrec, iLastFileArea) == 437U,
               "legacy last-file-area offset changed");
_Static_assert(offsetof(struct userrec, sProtocol) == 445U,
               "legacy protocol offset changed");
_Static_assert(offsetof(struct userrec, iLastMsgArea) == 494U,
               "legacy last-message-area offset changed");
_Static_assert(offsetof(struct userrec, iLanguage) == 506U,
               "legacy language offset changed");
_Static_assert(offsetof(struct userrec, sHandle) == 510U,
               "legacy handle offset changed");
_Static_assert(offsetof(struct userrec, Password) == 563U,
               "legacy cleartext-password offset changed");
_Static_assert(offsetof(struct userrec, Charset) == 578U,
               "legacy charset offset changed");

#define LEGACY_RUNTIME_PARENT "tmp"
#define LEGACY_RUNTIME_DIRECTORY "fortytwo-registration"
#define LEGACY_RUNTIME_LOCK "users-data.lock"
#define LEGACY_RUNTIME_DIRECTORY_MODE ((mode_t)0700)
#define LEGACY_RUNTIME_LOCK_MODE ((mode_t)0600)
#define LEGACY_STAGING_DIRECTORY_MODE ((mode_t)0700)
#define LEGACY_USER_DIRECTORY_MODE ((mode_t)0770)
#define LEGACY_MAIL_DIRECTORY_MODE ((mode_t)0700)
#define LEGACY_MARKER_MODE ((mode_t)0600)
#define LEGACY_MARKER_BUFFER_SIZE 320U
#define LEGACY_MARKER_STATE_PREPARED "prepared"
#define LEGACY_MARKER_STATE_COMMITTED "committed"
#define LEGACY_COMMITTED_MARKER_TEMP ".fortytwo-registration.committed.tmp"
#define LEGACY_STAGING_NAME_SIZE \
    (sizeof(LEGACY_USERDB_STAGING_PREFIX) - 1U + 32U + 1U)
#define LEGACY_RECORD_MARKER_SIZE \
    (sizeof(LEGACY_USERDB_RECORD_MARKER_PREFIX) - 1U + 32U + 1U)
#define LEGACY_PRIMARY_OPTION_BITS_OFFSET 385U
#define LEGACY_SECONDARY_OPTION_BITS_OFFSET 386U
#define LEGACY_IEMSI_OPTION_BITS_OFFSET 562U

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

#ifndef F_OFD_SETLK
#error "controlled legacy provisioning requires Linux open-file-description locks"
#endif

typedef struct legacy_name_entry {
    char name[LEGACY_USERDB_LEGACY_NAME_MAX + 1U];
    size_t record_number;
} legacy_name_entry_t;

typedef struct provision_handles {
    int root_fd;
    int etc_fd;
    int lock_fd;
    int users_fd;
    int users_directory_fd;
    struct stat root_status;
    struct stat etc_status;
    struct stat database_status;
    struct stat users_directory_status;
} provision_handles_t;

#ifdef LEGACY_USERDB_TESTING
static legacy_userdb_test_fault_t active_test_fault;
static unsigned int active_test_fault_hits;

void
legacy_userdb_test_set_fault(legacy_userdb_test_fault_t fault)
{
    active_test_fault = fault;
    active_test_fault_hits = 0U;
}

static bool
test_fault_once(legacy_userdb_test_fault_t fault)
{
    if (active_test_fault == fault && active_test_fault_hits == 0U) {
        ++active_test_fault_hits;
        return true;
    }
    return false;
}
#endif

static void
provision_set_error(legacy_userdb_error_t *error,
                    legacy_userdb_status_t status,
                    int system_errno,
                    size_t record_number,
                    bool repair_required,
                    const char *text)
{
    if (error == NULL) {
        return;
    }

    memset(error, 0, sizeof(*error));
    error->status = status;
    error->system_errno = system_errno;
    error->record_number = record_number;
    error->repair_required = repair_required;
    if (text != NULL) {
        (void)snprintf(error->text, sizeof(error->text), "%s", text);
    }
}

/* Reset all rollback proof material to an explicit non-prepared state. */
void
legacy_userdb_prepared_registration_clear(
    legacy_userdb_prepared_registration_t *prepared)
{
    if (prepared != NULL) {
        memset(prepared, 0, sizeof(*prepared));
        prepared->record_number = LEGACY_USERDB_NO_RECORD;
        prepared->original_size = (off_t)-1;
    }
}

/* Use the effective technical account and the reviewed 0660/0770/0700 modes. */
void
legacy_userdb_provision_policy_defaults(
    legacy_userdb_provision_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }

    memset(policy, 0, sizeof(*policy));
    legacy_userdb_policy_defaults(&policy->database);

    policy->users_directory.check_owner = true;
    policy->users_directory.expected_uid = geteuid();
    policy->users_directory.check_group = true;
    policy->users_directory.expected_gid = getegid();
    policy->users_directory.check_mode = true;
    policy->users_directory.expected_mode = LEGACY_USER_DIRECTORY_MODE;

    policy->runtime_directory.check_owner = true;
    policy->runtime_directory.expected_uid = geteuid();
    policy->runtime_directory.check_group = true;
    policy->runtime_directory.expected_gid = getegid();
    policy->runtime_directory.check_mode = true;
    policy->runtime_directory.expected_mode = LEGACY_RUNTIME_DIRECTORY_MODE;
}

static void
handles_init(provision_handles_t *handles)
{
    memset(handles, 0, sizeof(*handles));
    handles->root_fd = -1;
    handles->etc_fd = -1;
    handles->lock_fd = -1;
    handles->users_fd = -1;
    handles->users_directory_fd = -1;
}

static void
handles_close(provision_handles_t *handles)
{
    if (handles == NULL) {
        return;
    }
    if (handles->users_directory_fd >= 0) {
        (void)close(handles->users_directory_fd);
    }
    if (handles->users_fd >= 0) {
        (void)close(handles->users_fd);
    }
    if (handles->lock_fd >= 0) {
        (void)close(handles->lock_fd);
    }
    if (handles->etc_fd >= 0) {
        (void)close(handles->etc_fd);
    }
    if (handles->root_fd >= 0) {
        (void)close(handles->root_fd);
    }
    handles_init(handles);
}

static bool
mode_value_is_valid(mode_t mode)
{
    return (mode & ~(mode_t)07777) == 0;
}

static bool
provision_policy_is_valid(const legacy_userdb_provision_policy_t *policy)
{
    return policy != NULL && policy->database.max_records > 0U &&
           policy->database.max_records <= LEGACY_USERDB_DEFAULT_MAX_RECORDS &&
           (!policy->database.check_mode ||
            mode_value_is_valid(policy->database.expected_mode)) &&
           (!policy->users_directory.check_mode ||
            mode_value_is_valid(policy->users_directory.expected_mode)) &&
           (!policy->runtime_directory.check_mode ||
            mode_value_is_valid(policy->runtime_directory.expected_mode));
}

static bool
uuid_is_nonzero(const uint8_t uuid[LEGACY_USERDB_UUID_SIZE])
{
    size_t index;
    unsigned int combined = 0U;

    if (uuid == NULL) {
        return false;
    }
    for (index = 0U; index < LEGACY_USERDB_UUID_SIZE; ++index) {
        combined |= uuid[index];
    }
    return combined != 0U;
}

static void
format_uuid_hex(const uint8_t uuid[LEGACY_USERDB_UUID_SIZE],
                char output[33])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < LEGACY_USERDB_UUID_SIZE; ++index) {
        output[index * 2U] = digits[uuid[index] >> 4U];
        output[index * 2U + 1U] = digits[uuid[index] & 0x0fU];
    }
    output[32] = '\0';
}

static void
format_uuid_text(const uint8_t uuid[LEGACY_USERDB_UUID_SIZE],
                 char output[LEGACY_USERDB_UUID_TEXT_SIZE])
{
    char hex[33];

    format_uuid_hex(uuid, hex);
    (void)snprintf(output, LEGACY_USERDB_UUID_TEXT_SIZE,
                   "%.8s-%.4s-%.4s-%.4s-%.12s",
                   hex, hex + 8, hex + 12, hex + 16, hex + 20);
}

static bool
protocol_is_valid(const char *protocol)
{
    size_t length;
    size_t index;

    if (protocol == NULL) {
        return false;
    }
    length = strnlen(protocol, LEGACY_USERDB_PROTOCOL_MAX + 1U);
    if (length == 0U || length > LEGACY_USERDB_PROTOCOL_MAX) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char value = (unsigned char)protocol[index];

        if (value < 0x20U || value > 0x7eU) {
            return false;
        }
    }
    return true;
}

static bool
registration_is_valid(const legacy_userdb_registration_t *registration)
{
    return registration != NULL &&
           uuid_is_nonzero(registration->registration_id) &&
           uuid_is_nonzero(registration->user_id) &&
           legacy_userdb_legacy_name_is_valid(registration->legacy_name) &&
           legacy_userdb_display_name_is_compatible(
               registration->display_name) &&
           registration->registered_at > 0 &&
           registration->registered_at <= INT32_MAX &&
           registration->defaults.language > 0 &&
           registration->defaults.language <= UCHAR_MAX &&
           registration->defaults.charset >= 0 &&
           registration->defaults.charset <= LEGACY_USERDB_CHARSET_MAX &&
           registration->defaults.message_editor >=
               LEGACY_USERDB_EDITOR_LINE &&
           registration->defaults.message_editor <=
               LEGACY_USERDB_EDITOR_EXTERNAL &&
           protocol_is_valid(registration->defaults.protocol);
}

static void
build_names(const uint8_t registration_id[LEGACY_USERDB_UUID_SIZE],
            char staging_name[LEGACY_STAGING_NAME_SIZE],
            char record_marker[LEGACY_RECORD_MARKER_SIZE])
{
    char registration_hex[33];

    format_uuid_hex(registration_id, registration_hex);
    (void)snprintf(staging_name, LEGACY_STAGING_NAME_SIZE, "%s%s",
                   LEGACY_USERDB_STAGING_PREFIX, registration_hex);
    (void)snprintf(record_marker, LEGACY_RECORD_MARKER_SIZE, "%s%s",
                   LEGACY_USERDB_RECORD_MARKER_PREFIX, registration_hex);
}

static int
build_marker(const legacy_userdb_prepared_registration_t *prepared,
             const char *state,
             char marker[LEGACY_MARKER_BUFFER_SIZE],
             size_t *marker_length)
{
    char registration_text[LEGACY_USERDB_UUID_TEXT_SIZE];
    char user_text[LEGACY_USERDB_UUID_TEXT_SIZE];
    int length;

    if (strcmp(state, LEGACY_MARKER_STATE_PREPARED) != 0 &&
        strcmp(state, LEGACY_MARKER_STATE_COMMITTED) != 0) {
        errno = EINVAL;
        return -1;
    }
    format_uuid_text(prepared->registration_id, registration_text);
    format_uuid_text(prepared->user_id, user_text);
    length = snprintf(marker, LEGACY_MARKER_BUFFER_SIZE,
                      "format_version=1\n"
                      "registration_id=%s\n"
                      "user_id=%s\n"
                      "legacy_name=%s\n"
                      "record_number=%zu\n"
                      "state=%s\n",
                      registration_text, user_text, prepared->legacy_name,
                      prepared->record_number, state);
    if (length < 0 || (size_t)length >= LEGACY_MARKER_BUFFER_SIZE) {
        errno = EOVERFLOW;
        return -1;
    }
    *marker_length = (size_t)length;
    return 0;
}

/*
 * Construct the entire native record from a zeroed buffer.  Only reviewed
 * compatibility fields are populated; no password is accepted by this API and
 * both historical password representations remain zero.
 */
static int
build_record(const legacy_userdb_registration_t *registration,
             struct userrec *record)
{
    char staging_name[LEGACY_STAGING_NAME_SIZE];
    char record_marker[LEGACY_RECORD_MARKER_SIZE];
    size_t display_length = strlen(registration->display_name);
    size_t legacy_length = strlen(registration->legacy_name);
    size_t protocol_length = strlen(registration->defaults.protocol);

    memset(record, 0, sizeof(*record));
    build_names(registration->registration_id, staging_name, record_marker);

    memcpy(record->sUserName, registration->display_name,
           display_length + 1U);
    memcpy(record->Name, registration->legacy_name, legacy_length + 1U);
    memcpy(record->sComment, record_marker, strlen(record_marker) + 1U);
    memcpy(record->sExpiryDate, "00-00-0000", sizeof("00-00-0000"));
    memcpy(record->sSex, "Unknown", sizeof("Unknown"));
    memcpy(record->sProtocol, registration->defaults.protocol,
           protocol_length + 1U);

    record->xPassword = 0U;
    record->tFirstLoginDate = (int32_t)registration->registered_at;
    record->tLastLoginDate = 0;
    record->Security.level = registration->defaults.security_level;
    record->Security.flags = registration->defaults.security_flags;
    record->Security.notflags = registration->defaults.security_notflags;
    record->ExpirySec = record->Security;
    record->GraphMode = 1U;
    record->HotKeys = 1U;
    record->Cls = 1U;
    record->More = 1U;
    record->MailScan = registration->defaults.mail_scan ? 1U : 0U;
    record->ieFILE = registration->defaults.new_file_scan ? 1U : 0U;
    record->ieNEWS = 1U;
    record->ieASCII8 = 1U;
    record->Email = registration->defaults.email ? 1U : 0U;
    record->iTimeLeft = 20;
    record->tLastPwdChange = (int32_t)registration->registered_at;
    record->MsgEditor = registration->defaults.message_editor;
    record->iLastFileArea = 1;
    record->iLastMsgArea = 1;
    record->iLanguage = registration->defaults.language;
    record->Charset = registration->defaults.charset;

    {
        const unsigned char *bytes = (const unsigned char *)record;
        unsigned char secondary_bits =
            (unsigned char)(0x03U |
                            (registration->defaults.mail_scan ? 0x08U : 0U));
        unsigned char iemsi_bits =
            (unsigned char)(0x18U |
                            (registration->defaults.new_file_scan ? 0x20U : 0U) |
                            (registration->defaults.email ? 0x40U : 0U));
        size_t password_index;

        if (bytes[LEGACY_PRIMARY_OPTION_BITS_OFFSET] != 0x06U ||
            bytes[LEGACY_SECONDARY_OPTION_BITS_OFFSET] != secondary_bits ||
            bytes[LEGACY_IEMSI_OPTION_BITS_OFFSET] != iemsi_bits ||
            record->xPassword != 0U) {
            errno = EINVAL;
            return -1;
        }
        for (password_index = 0U;
             password_index < sizeof(record->Password); ++password_index) {
            if (record->Password[password_index] != '\0') {
                errno = EINVAL;
                return -1;
            }
        }
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

static bool
fixed_text_is_terminated(const char *text, size_t capacity)
{
    return text != NULL && memchr(text, '\0', capacity) != NULL;
}

static bool
record_identifier_matches(const struct userrec *record, const char *value)
{
    return ascii_case_compare(record->Name, value) == 0 ||
           ascii_case_compare(record->sUserName, value) == 0 ||
           (record->sHandle[0] != '\0' &&
            ascii_case_compare(record->sHandle, value) == 0);
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
write_exact(int fd, const void *buffer, size_t length, bool marker_write)
{
    const unsigned char *bytes = buffer;
    size_t completed = 0U;

    while (completed < length) {
        ssize_t written;

#ifdef LEGACY_USERDB_TESTING
        if (marker_write &&
            test_fault_once(LEGACY_USERDB_TEST_FAULT_MARKER_WRITE)) {
            errno = ENOSPC;
            return -1;
        }
#else
        (void)marker_write;
#endif
        written = write(fd, bytes + completed, length - completed);
        if (written > 0) {
            completed += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written == 0) {
            errno = EIO;
        }
        return -1;
    }
    return 0;
}

static ssize_t
record_pwrite(int fd, const void *buffer, size_t length, off_t offset)
{
#ifdef LEGACY_USERDB_TESTING
    if (active_test_fault == LEGACY_USERDB_TEST_FAULT_RECORD_SHORT_WRITE) {
        if (active_test_fault_hits == 0U) {
            size_t partial = length > 32U ? 32U : length;
            ssize_t written;

            ++active_test_fault_hits;
            written = pwrite(fd, buffer, partial, offset);
            return written;
        }
        if (active_test_fault_hits == 1U) {
            ++active_test_fault_hits;
            errno = ENOSPC;
            return -1;
        }
    }
#endif
    return pwrite(fd, buffer, length, offset);
}

static int
write_record_at(int fd,
                const unsigned char record[LEGACY_USERDB_RECORD_SIZE],
                off_t offset,
                size_t *bytes_written)
{
    size_t completed = 0U;

    while (completed < LEGACY_USERDB_RECORD_SIZE) {
        ssize_t written = record_pwrite(
            fd, record + completed, LEGACY_USERDB_RECORD_SIZE - completed,
            offset + (off_t)completed);

        if (written > 0) {
            completed += (size_t)written;
            *bytes_written = completed;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written == 0) {
            errno = EIO;
        }
        return -1;
    }
    return 0;
}

static int
sync_database(int fd)
{
#ifdef LEGACY_USERDB_TESTING
    if (test_fault_once(LEGACY_USERDB_TEST_FAULT_RECORD_SYNC)) {
        errno = EIO;
        return -1;
    }
#endif
    return fdatasync(fd);
}

static int
sync_users_directory(int fd)
{
#ifdef LEGACY_USERDB_TESTING
    if (active_test_fault ==
        LEGACY_USERDB_TEST_FAULT_USERS_DIRECTORY_SYNC) {
        if (active_test_fault_hits == 1U) {
            ++active_test_fault_hits;
            errno = EIO;
            return -1;
        }
        ++active_test_fault_hits;
    }
#endif
    return fsync(fd);
}

static bool
directory_policy_matches(const struct stat *status,
                         const legacy_userdb_directory_policy_t *policy)
{
    return S_ISDIR(status->st_mode) &&
           (!policy->check_owner ||
            status->st_uid == policy->expected_uid) &&
           (!policy->check_group ||
            status->st_gid == policy->expected_gid) &&
           (!policy->check_mode ||
            (status->st_mode & (mode_t)07777) == policy->expected_mode);
}

static bool
database_policy_matches(const struct stat *status,
                        const legacy_userdb_policy_t *policy,
                        legacy_userdb_status_t *failure)
{
    if (!S_ISREG(status->st_mode)) {
        *failure = LEGACY_USERDB_NOT_REGULAR;
        return false;
    }
    if (policy->check_owner && status->st_uid != policy->expected_uid) {
        *failure = LEGACY_USERDB_OWNER_MISMATCH;
        return false;
    }
    if (policy->check_group && status->st_gid != policy->expected_gid) {
        *failure = LEGACY_USERDB_GROUP_MISMATCH;
        return false;
    }
    if (policy->check_mode &&
        (status->st_mode & (mode_t)07777) != policy->expected_mode) {
        *failure = LEGACY_USERDB_MODE_MISMATCH;
        return false;
    }
    if (policy->require_single_link && status->st_nlink != 1) {
        *failure = LEGACY_USERDB_LINK_COUNT_MISMATCH;
        return false;
    }
    return true;
}

static int
lock_fd_nonblocking(int fd, short lock_type)
{
    struct flock lock;

    memset(&lock, 0, sizeof(lock));
    lock.l_type = lock_type;
    lock.l_whence = SEEK_SET;
    return fcntl(fd, F_OFD_SETLK, &lock);
}

/*
 * Serialize every new gateway writer with a private runtime lock.  Linux OFD
 * locks are used so independent threads in one auth process conflict as well
 * as separate processes; a persistent lock filename is not itself a lock.
 */
static int
open_runtime_lock(const char *mbse_root,
                  const legacy_userdb_provision_policy_t *policy,
                  provision_handles_t *handles,
                  legacy_userdb_error_t *error)
{
    struct stat status;
    int tmp_fd = -1;
    int runtime_fd = -1;
    int lock_fd = -1;
    bool runtime_created = false;
    bool lock_created = false;

    handles->root_fd = open(mbse_root,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (handles->root_fd < 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_ROOT_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot open MBSE root directory");
        return -1;
    }
    if (fstat(handles->root_fd, &handles->root_status) != 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_ROOT_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect MBSE root directory");
        return -1;
    }
    tmp_fd = openat(handles->root_fd, LEGACY_RUNTIME_PARENT,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (tmp_fd < 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_RUNTIME_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot open MBSE runtime parent directory");
        goto failed;
    }

    if (mkdirat(tmp_fd, LEGACY_RUNTIME_DIRECTORY,
                LEGACY_RUNTIME_DIRECTORY_MODE) == 0) {
        runtime_created = true;
    } else if (errno != EEXIST) {
        provision_set_error(error, LEGACY_USERDB_OPEN_RUNTIME_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot create registration runtime directory");
        goto failed;
    }
    runtime_fd = openat(tmp_fd, LEGACY_RUNTIME_DIRECTORY,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (runtime_fd < 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_RUNTIME_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot open registration runtime directory");
        goto failed;
    }
    if (runtime_created &&
        fchmod(runtime_fd, LEGACY_RUNTIME_DIRECTORY_MODE) != 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_RUNTIME_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot set registration runtime directory mode");
        goto failed;
    }
    if (fstat(runtime_fd, &status) != 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_RUNTIME_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect registration runtime directory");
        goto failed;
    }
    if (!directory_policy_matches(&status, &policy->runtime_directory)) {
        provision_set_error(error, LEGACY_USERDB_RUNTIME_POLICY_MISMATCH, 0,
                            LEGACY_USERDB_NO_RECORD, false,
                            "registration runtime directory violates policy");
        goto failed;
    }
    if (runtime_created && fsync(tmp_fd) != 0) {
        provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot synchronize registration runtime parent");
        goto failed;
    }

    lock_fd = openat(runtime_fd, LEGACY_RUNTIME_LOCK,
                     O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     LEGACY_RUNTIME_LOCK_MODE);
    if (lock_fd >= 0) {
        lock_created = true;
    } else if (errno == EEXIST) {
        lock_fd = openat(runtime_fd, LEGACY_RUNTIME_LOCK,
                         O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    }
    if (lock_fd < 0) {
        provision_set_error(error, LEGACY_USERDB_CREATE_LOCK_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot open registration lock file");
        goto failed;
    }
    if (lock_created && fchmod(lock_fd, LEGACY_RUNTIME_LOCK_MODE) != 0) {
        provision_set_error(error, LEGACY_USERDB_CREATE_LOCK_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot set registration lock file mode");
        goto failed;
    }
    if (fstat(lock_fd, &status) != 0) {
        provision_set_error(error, LEGACY_USERDB_CREATE_LOCK_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect registration lock file");
        goto failed;
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        status.st_gid != getegid() ||
        (status.st_mode & (mode_t)07777) != LEGACY_RUNTIME_LOCK_MODE ||
        status.st_nlink != 1) {
        provision_set_error(error, LEGACY_USERDB_CREATE_LOCK_FAILED, EPERM,
                            LEGACY_USERDB_NO_RECORD, false,
                            "registration lock file violates policy");
        goto failed;
    }
    if (lock_created && fsync(runtime_fd) != 0) {
        provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot synchronize registration runtime directory");
        goto failed;
    }
    if (lock_fd_nonblocking(lock_fd, F_WRLCK) != 0) {
        legacy_userdb_status_t lock_status =
            errno == EACCES || errno == EAGAIN
                ? LEGACY_USERDB_GLOBAL_BUSY : LEGACY_USERDB_LOCK_FAILED;
        provision_set_error(error, lock_status, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            lock_status == LEGACY_USERDB_GLOBAL_BUSY
                                ? "another legacy registration is active"
                                : "cannot lock registration lock file");
        goto failed;
    }

    handles->lock_fd = lock_fd;
    (void)close(runtime_fd);
    (void)close(tmp_fd);
    return 0;

failed:
    if (lock_fd >= 0) {
        (void)close(lock_fd);
    }
    if (runtime_fd >= 0) {
        (void)close(runtime_fd);
    }
    if (tmp_fd >= 0) {
        (void)close(tmp_fd);
    }
    return -1;
}

/*
 * Resolve the configured user base one path component at a time.  Refusing
 * symlinks and dot components prevents a late path redirect from escaping the
 * directory whose identity is retained in the rollback context.
 */
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
open_users_directory(const char *path,
                     const legacy_userdb_provision_policy_t *policy,
                     provision_handles_t *handles,
                     legacy_userdb_error_t *error)
{
    int fd = open_absolute_directory_nofollow(path);
    struct stat status;

    if (fd < 0) {
        provision_set_error(error,
                            LEGACY_USERDB_OPEN_USERS_DIRECTORY_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot open legacy users directory");
        return -1;
    }
    if (fstat(fd, &status) != 0) {
        provision_set_error(error,
                            LEGACY_USERDB_OPEN_USERS_DIRECTORY_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect legacy users directory");
        (void)close(fd);
        return -1;
    }
    if (!directory_policy_matches(&status, &policy->users_directory)) {
        provision_set_error(
            error, LEGACY_USERDB_USERS_DIRECTORY_POLICY_MISMATCH, 0,
            LEGACY_USERDB_NO_RECORD, false,
            "legacy users directory violates owner, group or mode policy");
        (void)close(fd);
        return -1;
    }

    handles->users_directory_fd = fd;
    handles->users_directory_status = status;
    return 0;
}

static int
open_users_database(const legacy_userdb_provision_policy_t *policy,
                    provision_handles_t *handles,
                    legacy_userdb_error_t *error)
{
    legacy_userdb_status_t policy_failure = LEGACY_USERDB_OK;
    struct stat status;
    int users_fd = -1;

    handles->etc_fd = openat(handles->root_fd, "etc",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                 O_NOFOLLOW);
    if (handles->etc_fd < 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_ETC_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot open MBSE etc directory");
        return -1;
    }
    if (fstat(handles->etc_fd, &handles->etc_status) != 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_ETC_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect MBSE etc directory");
        return -1;
    }
    users_fd = openat(handles->etc_fd, "users.data",
                      O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (users_fd < 0) {
        provision_set_error(error, LEGACY_USERDB_OPEN_FILE_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot open legacy users database for writing");
        return -1;
    }
    if (fstat(users_fd, &status) != 0) {
        provision_set_error(error, LEGACY_USERDB_STAT_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect legacy users database");
        (void)close(users_fd);
        return -1;
    }
    if (!database_policy_matches(&status, &policy->database,
                                 &policy_failure)) {
        provision_set_error(error, policy_failure, 0,
                            LEGACY_USERDB_NO_RECORD, false,
                            "legacy users database violates policy");
        (void)close(users_fd);
        return -1;
    }
    if (lock_fd_nonblocking(users_fd, F_WRLCK) != 0) {
        legacy_userdb_status_t lock_status =
            errno == EACCES || errno == EAGAIN
                ? LEGACY_USERDB_BUSY : LEGACY_USERDB_LOCK_FAILED;
        provision_set_error(error, lock_status, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            lock_status == LEGACY_USERDB_BUSY
                                ? "legacy users database is locked"
                                : "cannot lock legacy users database");
        (void)close(users_fd);
        return -1;
    }

    handles->users_fd = users_fd;
    handles->database_status = status;
    return 0;
}

/*
 * Validate the whole legacy file before append and repeat the same collision
 * scan after append and publication.  Deleted slots are deliberately not reused
 * because the record index is referenced by historical JAM last-read state.
 */
static int
validate_database_for_registration(
    int fd,
    const struct stat *initial_status,
    const legacy_userdb_policy_t *policy,
    const legacy_userdb_registration_t *registration,
    size_t owned_record,
    const unsigned char expected_owned_record[LEGACY_USERDB_RECORD_SIZE],
    size_t *record_count,
    legacy_userdb_error_t *error)
{
    struct userhdr header;
    struct stat after_status;
    legacy_name_entry_t *names = NULL;
    char expected_record_marker[LEGACY_RECORD_MARKER_SIZE];
    size_t name_count = 0U;
    size_t count;
    size_t record_number;
    off_t payload_size;
    bool postappend = owned_record != LEGACY_USERDB_NO_RECORD;

    {
        char staging_name[LEGACY_STAGING_NAME_SIZE];
        build_names(registration->registration_id, staging_name,
                    expected_record_marker);
    }

    if (initial_status->st_size < (off_t)LEGACY_USERDB_HEADER_SIZE) {
        provision_set_error(error, LEGACY_USERDB_HEADER_TRUNCATED, 0,
                            LEGACY_USERDB_NO_RECORD, false,
                            "legacy users database header is truncated");
        return -1;
    }
    if (read_exact_at(fd, &header, sizeof(header), 0) != 0) {
        provision_set_error(error, LEGACY_USERDB_READ_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot read legacy users database header");
        return -1;
    }
    if (header.hdrsize != (int)LEGACY_USERDB_HEADER_SIZE ||
        header.recsize != (int)LEGACY_USERDB_RECORD_SIZE) {
        provision_set_error(error, LEGACY_USERDB_HEADER_MISMATCH, 0,
                            LEGACY_USERDB_NO_RECORD, false,
                            "legacy users database header does not match ABI");
        return -1;
    }
    payload_size = initial_status->st_size -
                   (off_t)LEGACY_USERDB_HEADER_SIZE;
    if (payload_size < 0 ||
        payload_size % (off_t)LEGACY_USERDB_RECORD_SIZE != 0) {
        provision_set_error(error, LEGACY_USERDB_SIZE_MISMATCH, 0,
                            LEGACY_USERDB_NO_RECORD, false,
                            "legacy users database has a partial record");
        return -1;
    }
    count = (size_t)(payload_size / (off_t)LEGACY_USERDB_RECORD_SIZE);
    if ((!postappend && count >= policy->max_records) ||
        (postappend && count > policy->max_records)) {
        provision_set_error(error, LEGACY_USERDB_TOO_MANY_RECORDS, 0,
                            LEGACY_USERDB_NO_RECORD, false,
                            "legacy users database reached its record limit");
        return -1;
    }
    if (postappend &&
        (expected_owned_record == NULL || owned_record >= count)) {
        provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, EINVAL,
                            owned_record, false,
                            "appended legacy record position is invalid");
        return -1;
    }
    if (count > 0U) {
        names = calloc(count, sizeof(*names));
        if (names == NULL) {
            provision_set_error(error, LEGACY_USERDB_MEMORY_FAILED, errno,
                                LEGACY_USERDB_NO_RECORD, false,
                                "cannot allocate legacy-name scan table");
            return -1;
        }
    }

    for (record_number = 0U; record_number < count; ++record_number) {
        struct userrec record;
        off_t offset = (off_t)LEGACY_USERDB_HEADER_SIZE +
                       (off_t)(record_number * LEGACY_USERDB_RECORD_SIZE);
        bool is_owned_record = postappend && record_number == owned_record;

        memset(&record, 0, sizeof(record));
        if (read_exact_at(fd, &record, sizeof(record), offset) != 0) {
            int saved_errno = errno;
            free(names);
            provision_set_error(error, LEGACY_USERDB_READ_FAILED,
                                saved_errno, record_number, false,
                                "cannot read legacy user record");
            return -1;
        }
        if (!fixed_text_is_terminated(record.Name, sizeof(record.Name)) ||
            !fixed_text_is_terminated(record.sUserName,
                                      sizeof(record.sUserName)) ||
            !fixed_text_is_terminated(record.sHandle,
                                      sizeof(record.sHandle)) ||
            !fixed_text_is_terminated(record.sComment,
                                      sizeof(record.sComment)) ||
            !fixed_text_is_terminated(record.Password,
                                      sizeof(record.Password))) {
            free(names);
            provision_set_error(error, LEGACY_USERDB_INVALID_RECORD, 0,
                                record_number, false,
                                "legacy user record contains unterminated text");
            return -1;
        }
        if (is_owned_record &&
            memcmp(&record, expected_owned_record, sizeof(record)) != 0) {
            free(names);
            provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, EINVAL,
                                record_number, false,
                                "appended legacy user record changed");
            return -1;
        }
        if (strcmp(record.sComment, expected_record_marker) == 0 &&
            !is_owned_record) {
            free(names);
            provision_set_error(
                error, LEGACY_USERDB_REGISTRATION_EXISTS, 0,
                record_number, true,
                "registration marker already exists in legacy database");
            return -1;
        }
        if (record.Name[0] != '\0') {
            (void)snprintf(names[name_count].name,
                           sizeof(names[name_count].name), "%s", record.Name);
            names[name_count].record_number = record_number;
            ++name_count;
        }
        if (!is_owned_record &&
            (record_identifier_matches(&record,
                                       registration->legacy_name) ||
             record_identifier_matches(&record,
                                       registration->display_name))) {
            free(names);
            provision_set_error(error, LEGACY_USERDB_NAME_COLLISION, 0,
                                record_number, false,
                                "legacy name or display name already exists");
            return -1;
        }
    }

    if (name_count > 1U) {
        qsort(names, name_count, sizeof(*names), legacy_name_entry_compare);
        for (record_number = 1U; record_number < name_count; ++record_number) {
            if (ascii_case_compare(names[record_number - 1U].name,
                                   names[record_number].name) == 0) {
                size_t duplicate_record = names[record_number].record_number;
                free(names);
                provision_set_error(
                    error, LEGACY_USERDB_DUPLICATE_LEGACY_NAME, 0,
                    duplicate_record, false,
                    "legacy users database contains duplicate names");
                return -1;
            }
        }
    }
    free(names);

    if (fstat(fd, &after_status) != 0) {
        provision_set_error(error, LEGACY_USERDB_STAT_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot recheck legacy users database");
        return -1;
    }
    if (!file_snapshot_is_unchanged(initial_status, &after_status)) {
        provision_set_error(error, LEGACY_USERDB_CHANGED_DURING_SCAN, 0,
                            LEGACY_USERDB_NO_RECORD, false,
                            "legacy users database changed during scan");
        return -1;
    }
    *record_count = count;
    return 0;
}

static int
revalidate_postappend_records(
    int fd,
    const legacy_userdb_policy_t *policy,
    const legacy_userdb_registration_t *registration,
    const legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    struct stat status;
    size_t count = 0U;

#ifdef LEGACY_USERDB_TESTING
    if (test_fault_once(
            LEGACY_USERDB_TEST_FAULT_POSTAPPEND_NAME_COLLISION)) {
        struct userrec existing;

        if (read_exact_at(fd, &existing, sizeof(existing),
                          (off_t)LEGACY_USERDB_HEADER_SIZE) != 0) {
            provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, errno,
                                0U, false,
                                "cannot inject post-append collision");
            return -1;
        }
        memset(existing.sHandle, 0, sizeof(existing.sHandle));
        (void)snprintf(existing.sHandle, sizeof(existing.sHandle), "%s",
                       registration->legacy_name);
        {
            size_t injected_bytes = 0U;

            if (write_record_at(
                    fd, (const unsigned char *)&existing,
                    (off_t)LEGACY_USERDB_HEADER_SIZE,
                    &injected_bytes) != 0 ||
                fdatasync(fd) != 0) {
                provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED,
                                    errno, 0U, false,
                                    "cannot inject post-append collision");
                return -1;
            }
        }
    }
#endif
    if (fstat(fd, &status) != 0) {
        provision_set_error(error, LEGACY_USERDB_STAT_FAILED, errno,
                            prepared->record_number, false,
                            "cannot inspect appended legacy database");
        return -1;
    }
    if (validate_database_for_registration(
            fd, &status, policy, registration, prepared->record_number,
            prepared->record_bytes, &count, error) != 0) {
        return -1;
    }
    if (count != prepared->record_number + 1U) {
        provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, EINVAL,
                            prepared->record_number, false,
                            "appended legacy record is not the final record");
        return -1;
    }
    return 0;
}

static int
entry_status(int parent_fd, const char *name, struct stat *status)
{
    if (fstatat(parent_fd, name, status, AT_SYMLINK_NOFOLLOW) == 0) {
        return 1;
    }
    if (errno == ENOENT) {
        return 0;
    }
    return -1;
}

static int
ensure_target_names_absent(int users_directory_fd,
                           const char *legacy_name,
                           const char *staging_name,
                           legacy_userdb_error_t *error)
{
    struct stat status;
    int state = entry_status(users_directory_fd, legacy_name, &status);

    if (state > 0) {
        provision_set_error(error, LEGACY_USERDB_TARGET_EXISTS, EEXIST,
                            LEGACY_USERDB_NO_RECORD, false,
                            "legacy user directory already exists");
        return -1;
    }
    if (state < 0) {
        provision_set_error(error, LEGACY_USERDB_STAT_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect legacy user directory target");
        return -1;
    }

    state = entry_status(users_directory_fd, staging_name, &status);
    if (state > 0) {
        provision_set_error(error, LEGACY_USERDB_STAGING_EXISTS, EEXIST,
                            LEGACY_USERDB_NO_RECORD, true,
                            "registration staging directory already exists");
        return -1;
    }
    if (state < 0) {
        provision_set_error(error, LEGACY_USERDB_STAT_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot inspect registration staging target");
        return -1;
    }
    return 0;
}

static int
create_owned_directory_at(int parent_fd,
                          const char *name,
                          mode_t mode,
                          int *directory_fd,
                          bool *created)
{
    struct stat status;
    int fd;

    if (created != NULL) {
        *created = false;
    }
    if (mkdirat(parent_fd, name, mode) != 0) {
        return -1;
    }
    if (created != NULL) {
        *created = true;
    }
    fd = openat(parent_fd, name,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    if (fchmod(fd, mode) != 0 || fstat(fd, &status) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        status.st_gid != getegid() ||
        (status.st_mode & (mode_t)07777) != mode) {
        (void)close(fd);
        errno = EPERM;
        return -1;
    }
    *directory_fd = fd;
    return 0;
}

static int
create_marker_file(int staging_fd,
                   const char *marker,
                   size_t marker_length)
{
    struct stat status;
    int marker_fd = openat(staging_fd, LEGACY_USERDB_MARKER_FILE,
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                               O_NOFOLLOW,
                           LEGACY_MARKER_MODE);

    if (marker_fd < 0) {
        return -1;
    }
    if (fchmod(marker_fd, LEGACY_MARKER_MODE) != 0 ||
        write_exact(marker_fd, marker, marker_length, true) != 0 ||
        fsync(marker_fd) != 0 || fstat(marker_fd, &status) != 0) {
        int saved_errno = errno;
        (void)close(marker_fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        status.st_gid != getegid() || status.st_nlink != 1 ||
        (status.st_mode & (mode_t)07777) != LEGACY_MARKER_MODE ||
        status.st_size != (off_t)marker_length) {
        (void)close(marker_fd);
        errno = EIO;
        return -1;
    }
    if (close(marker_fd) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Build the user tree under a registration-specific private name.  The top
 * directory stays mode 0700 until record verification is complete; only then
 * is it promoted to the final 0770 compatibility mode and published.
 */
static int
create_staging_tree(int users_directory_fd,
                    const char *staging_name,
                    const char *marker,
                    size_t marker_length,
                    bool *staging_created,
                    bool *marker_created,
                    legacy_userdb_error_t *error)
{
    int staging_fd = -1;
    int maildir_fd = -1;
    int child_fd = -1;
    static const char *const children[] = {"cur", "new", "tmp"};
    size_t index;

#ifdef LEGACY_USERDB_TESTING
    if (test_fault_once(LEGACY_USERDB_TEST_FAULT_CREATE_STAGING)) {
        errno = ENOSPC;
        provision_set_error(error, LEGACY_USERDB_CREATE_DIRECTORY_FAILED,
                            errno, LEGACY_USERDB_NO_RECORD, false,
                            "cannot create registration staging directory");
        return -1;
    }
#endif
    if (create_owned_directory_at(users_directory_fd, staging_name,
                                  LEGACY_STAGING_DIRECTORY_MODE,
                                  &staging_fd, staging_created) != 0) {
        provision_set_error(error, LEGACY_USERDB_CREATE_DIRECTORY_FAILED,
                            errno, LEGACY_USERDB_NO_RECORD, false,
                            "cannot create registration staging directory");
        return -1;
    }

    if (create_owned_directory_at(staging_fd, "Maildir",
                                  LEGACY_MAIL_DIRECTORY_MODE,
                                  &maildir_fd, NULL) != 0) {
        provision_set_error(error, LEGACY_USERDB_CREATE_DIRECTORY_FAILED,
                            errno, LEGACY_USERDB_NO_RECORD, false,
                            "cannot create legacy Maildir");
        goto failed;
    }
    for (index = 0U; index < sizeof(children) / sizeof(children[0]); ++index) {
        if (create_owned_directory_at(maildir_fd, children[index],
                                      LEGACY_MAIL_DIRECTORY_MODE,
                                      &child_fd, NULL) != 0) {
            provision_set_error(error,
                                LEGACY_USERDB_CREATE_DIRECTORY_FAILED, errno,
                                LEGACY_USERDB_NO_RECORD, false,
                                "cannot create legacy Maildir child");
            goto failed;
        }
        if (fsync(child_fd) != 0) {
            provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                                LEGACY_USERDB_NO_RECORD, false,
                                "cannot synchronize legacy Maildir child");
            goto failed;
        }
        (void)close(child_fd);
        child_fd = -1;
    }
    if (fsync(maildir_fd) != 0) {
        provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot synchronize legacy Maildir");
        goto failed;
    }
    if (create_marker_file(staging_fd, marker, marker_length) != 0) {
        provision_set_error(
            error,
            errno == EEXIST ? LEGACY_USERDB_CREATE_MARKER_FAILED
                             : LEGACY_USERDB_WRITE_MARKER_FAILED,
            errno, LEGACY_USERDB_NO_RECORD, false,
            "cannot create registration marker");
        goto failed;
    }
    *marker_created = true;
    if (fsync(staging_fd) != 0) {
        provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                            LEGACY_USERDB_NO_RECORD, false,
                            "cannot synchronize registration staging directory");
        goto failed;
    }
    (void)close(maildir_fd);
    (void)close(staging_fd);
    return 0;

failed:
    if (child_fd >= 0) {
        (void)close(child_fd);
    }
    if (maildir_fd >= 0) {
        (void)close(maildir_fd);
    }
    if (staging_fd >= 0) {
        (void)close(staging_fd);
    }
    return -1;
}

static int
rename_noreplace(int old_parent_fd,
                 const char *old_name,
                 int new_parent_fd,
                 const char *new_name)
{
#ifdef LEGACY_USERDB_TESTING
    if (test_fault_once(LEGACY_USERDB_TEST_FAULT_RENAME)) {
        errno = EIO;
        return -1;
    }
#endif
#if defined(SYS_renameat2)
    return (int)syscall(SYS_renameat2, old_parent_fd, old_name,
                        new_parent_fd, new_name, RENAME_NOREPLACE);
#else
    (void)old_parent_fd;
    (void)old_name;
    (void)new_parent_fd;
    (void)new_name;
    errno = ENOTSUP;
    return -1;
#endif
}

static int
marker_matches(int top_fd, const char *expected, size_t expected_length)
{
    struct stat status;
    char actual[LEGACY_MARKER_BUFFER_SIZE];
    int marker_fd;

    if (expected_length >= sizeof(actual)) {
        errno = EOVERFLOW;
        return -1;
    }
    marker_fd = openat(top_fd, LEGACY_USERDB_MARKER_FILE,
                       O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (marker_fd < 0) {
        return -1;
    }
    if (fstat(marker_fd, &status) != 0 ||
        read_exact(marker_fd, actual, expected_length) != 0) {
        int saved_errno = errno;
        (void)close(marker_fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        status.st_gid != getegid() || status.st_nlink != 1 ||
        (status.st_mode & (mode_t)07777) != LEGACY_MARKER_MODE ||
        status.st_size != (off_t)expected_length ||
        memcmp(actual, expected, expected_length) != 0) {
        (void)close(marker_fd);
        errno = EINVAL;
        return -1;
    }
    if (close(marker_fd) != 0) {
        return -1;
    }
    return 0;
}

static int
open_owned_directory_at(int parent_fd, const char *name,
                         mode_t expected_mode)
{
    struct stat status;
    int fd = openat(parent_fd, name,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &status) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        status.st_gid != getegid() ||
        (status.st_mode & (mode_t)07777) != expected_mode) {
        (void)close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

static int
promote_staging_directory(int users_directory_fd,
                          const char *staging_name,
                          bool *promoted)
{
    struct stat status;
    int fd = open_owned_directory_at(users_directory_fd, staging_name,
                                      LEGACY_STAGING_DIRECTORY_MODE);

    if (fd < 0) {
        return -1;
    }
    if (fchmod(fd, LEGACY_USER_DIRECTORY_MODE) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    *promoted = true;
    if (fsync(fd) != 0 || fstat(fd, &status) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        status.st_gid != getegid() ||
        (status.st_mode & (mode_t)07777) != LEGACY_USER_DIRECTORY_MODE) {
        (void)close(fd);
        errno = EPERM;
        return -1;
    }
    if (close(fd) != 0) {
        return -1;
    }
    return 0;
}

static int
privatize_staging_directory(int users_directory_fd,
                            const char *staging_name,
                            mode_t current_mode)
{
    int fd = open_owned_directory_at(users_directory_fd, staging_name,
                                      current_mode);

    if (fd < 0) {
        return -1;
    }
    if (current_mode != LEGACY_STAGING_DIRECTORY_MODE &&
        fchmod(fd, LEGACY_STAGING_DIRECTORY_MODE) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (fsync(fd) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int
directory_has_exact_entries(int directory_fd,
                            const char *const *expected,
                            size_t expected_count)
{
    bool seen[4] = {false, false, false, false};
    DIR *directory;
    struct dirent *entry;
    int duplicate_fd;
    size_t found = 0U;

    if (expected_count > sizeof(seen) / sizeof(seen[0])) {
        errno = EOVERFLOW;
        return -1;
    }
    duplicate_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
    if (duplicate_fd < 0) {
        return -1;
    }
    directory = fdopendir(duplicate_fd);
    if (directory == NULL) {
        int saved_errno = errno;
        (void)close(duplicate_fd);
        errno = saved_errno;
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        size_t index;
        bool matched = false;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        for (index = 0U; index < expected_count; ++index) {
            if (strcmp(entry->d_name, expected[index]) == 0 && !seen[index]) {
                seen[index] = true;
                ++found;
                matched = true;
                break;
            }
        }
        if (!matched) {
            errno = EINVAL;
            break;
        }
    }
    if (errno != 0 || found != expected_count) {
        int saved_errno = errno == 0 ? EINVAL : errno;
        (void)closedir(directory);
        errno = saved_errno;
        return -1;
    }
    return closedir(directory);
}

static int
verify_exact_registration_tree(int users_directory_fd,
                               const char *top_name,
                               mode_t top_mode,
                               const char *marker,
                               size_t marker_length)
{
    static const char *const top_entries[] = {
        "Maildir", LEGACY_USERDB_MARKER_FILE};
    static const char *const mail_entries[] = {"cur", "new", "tmp"};
    int top_fd = -1;
    int maildir_fd = -1;
    int child_fd = -1;
    size_t index;
    int saved_errno;

    top_fd = open_owned_directory_at(users_directory_fd, top_name, top_mode);
    if (top_fd < 0 || marker_matches(top_fd, marker, marker_length) != 0 ||
        directory_has_exact_entries(top_fd, top_entries,
                                    sizeof(top_entries) /
                                        sizeof(top_entries[0])) != 0) {
        goto failed;
    }
    maildir_fd = open_owned_directory_at(top_fd, "Maildir",
                                         LEGACY_MAIL_DIRECTORY_MODE);
    if (maildir_fd < 0 ||
        directory_has_exact_entries(maildir_fd, mail_entries,
                                    sizeof(mail_entries) /
                                        sizeof(mail_entries[0])) != 0) {
        goto failed;
    }
    for (index = 0U;
         index < sizeof(mail_entries) / sizeof(mail_entries[0]); ++index) {
        child_fd = open_owned_directory_at(maildir_fd, mail_entries[index],
                                           LEGACY_MAIL_DIRECTORY_MODE);
        if (child_fd < 0 ||
            directory_has_exact_entries(child_fd, NULL, 0U) != 0) {
            goto failed;
        }
        (void)close(child_fd);
    }
    (void)close(maildir_fd);
    return close(top_fd);

failed:
    saved_errno = errno;
    if (child_fd >= 0) {
        (void)close(child_fd);
    }
    if (maildir_fd >= 0) {
        (void)close(maildir_fd);
    }
    if (top_fd >= 0) {
        (void)close(top_fd);
    }
    errno = saved_errno;
    return -1;
}

static int
remove_directory_if_present(int parent_fd, const char *name)
{
    if (unlinkat(parent_fd, name, AT_REMOVEDIR) == 0 || errno == ENOENT) {
        return 0;
    }
    return -1;
}

/*
 * Remove only the bounded tree shape created by this provisioner.  Any extra
 * entry, changed type, ownership/mode mismatch or marker mismatch makes the
 * operation fail instead of recursively deleting unknown data.
 */
static int
remove_known_tree(int users_directory_fd,
                  const char *top_name,
                  const char *expected_marker,
                  size_t expected_marker_length,
                  bool require_marker,
                  mode_t expected_top_mode)
{
    int top_fd = open_owned_directory_at(users_directory_fd, top_name,
                                          expected_top_mode);
    int maildir_fd = -1;
    int saved_errno;

    if (top_fd < 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (require_marker &&
        marker_matches(top_fd, expected_marker, expected_marker_length) != 0) {
        saved_errno = errno;
        (void)close(top_fd);
        errno = saved_errno;
        return -1;
    }

    maildir_fd = openat(top_fd, "Maildir",
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (maildir_fd >= 0) {
        if (remove_directory_if_present(maildir_fd, "cur") != 0 ||
            remove_directory_if_present(maildir_fd, "new") != 0 ||
            remove_directory_if_present(maildir_fd, "tmp") != 0) {
            saved_errno = errno;
            (void)close(maildir_fd);
            (void)close(top_fd);
            errno = saved_errno;
            return -1;
        }
        (void)close(maildir_fd);
        if (remove_directory_if_present(top_fd, "Maildir") != 0) {
            saved_errno = errno;
            (void)close(top_fd);
            errno = saved_errno;
            return -1;
        }
    } else if (errno != ENOENT) {
        saved_errno = errno;
        (void)close(top_fd);
        errno = saved_errno;
        return -1;
    }

    if (unlinkat(top_fd, LEGACY_USERDB_MARKER_FILE, 0) != 0 &&
        errno != ENOENT) {
        saved_errno = errno;
        (void)close(top_fd);
        errno = saved_errno;
        return -1;
    }
    if (close(top_fd) != 0) {
        return -1;
    }
    return remove_directory_if_present(users_directory_fd, top_name);
}

static int
verify_database_identity(int fd,
                         const legacy_userdb_prepared_registration_t *prepared)
{
    struct stat status;

    if (fstat(fd, &status) != 0) {
        return -1;
    }
    if (status.st_dev != prepared->database_device ||
        status.st_ino != prepared->database_inode ||
        status.st_uid != prepared->database_uid ||
        status.st_gid != prepared->database_gid ||
        (status.st_mode & (mode_t)07777) != prepared->database_mode ||
        status.st_nlink != prepared->database_links) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int
verify_active_database_path(
    const char *mbse_root,
    const provision_handles_t *handles,
    const legacy_userdb_prepared_registration_t *prepared)
{
    struct stat root_status;
    struct stat etc_status;
    struct stat status;
    int root_fd;

    root_fd = open(mbse_root,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        return -1;
    }
    if (fstat(root_fd, &root_status) != 0) {
        int saved_errno = errno;
        (void)close(root_fd);
        errno = saved_errno;
        return -1;
    }
    (void)close(root_fd);
    if (root_status.st_dev != handles->root_status.st_dev ||
        root_status.st_ino != handles->root_status.st_ino) {
        errno = ESTALE;
        return -1;
    }
    if (fstatat(handles->root_fd, "etc", &etc_status,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!S_ISDIR(etc_status.st_mode) ||
        etc_status.st_dev != handles->etc_status.st_dev ||
        etc_status.st_ino != handles->etc_status.st_ino) {
        errno = ESTALE;
        return -1;
    }

    if (handles->etc_fd < 0 ||
        fstatat(handles->etc_fd, "users.data", &status,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!S_ISREG(status.st_mode) ||
        status.st_dev != prepared->database_device ||
        status.st_ino != prepared->database_inode) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int
verify_users_directory_identity(
    int fd, const legacy_userdb_prepared_registration_t *prepared)
{
    struct stat status;

    if (fstat(fd, &status) != 0) {
        return -1;
    }
    if (status.st_dev != prepared->users_directory_device ||
        status.st_ino != prepared->users_directory_inode ||
        status.st_uid != prepared->users_directory_uid ||
        status.st_gid != prepared->users_directory_gid ||
        (status.st_mode & (mode_t)07777) !=
            prepared->users_directory_mode) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int
verify_open_users_directory_stable(const provision_handles_t *handles)
{
    struct stat status;

    if (fstat(handles->users_directory_fd, &status) != 0) {
        return -1;
    }
    if (status.st_dev != handles->users_directory_status.st_dev ||
        status.st_ino != handles->users_directory_status.st_ino ||
        status.st_uid != handles->users_directory_status.st_uid ||
        status.st_gid != handles->users_directory_status.st_gid ||
        (status.st_mode & (mode_t)07777) !=
            (handles->users_directory_status.st_mode & (mode_t)07777)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int
verify_active_users_directory_path(
    const char *bbs_users_directory,
    const legacy_userdb_prepared_registration_t *prepared)
{
    struct stat status;
    int fd = open_absolute_directory_nofollow(bbs_users_directory);

    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &status) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    (void)close(fd);
    if (status.st_dev != prepared->users_directory_device ||
        status.st_ino != prepared->users_directory_inode ||
        status.st_uid != prepared->users_directory_uid ||
        status.st_gid != prepared->users_directory_gid ||
        (status.st_mode & (mode_t)07777) !=
            prepared->users_directory_mode) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int
verify_postappend_database(
    const char *mbse_root,
    const provision_handles_t *handles,
    const legacy_userdb_prepared_registration_t *prepared,
    size_t expected_record_bytes)
{
    struct stat status;
    unsigned char actual_record[LEGACY_USERDB_RECORD_SIZE];

    if (verify_database_identity(handles->users_fd, prepared) != 0 ||
        verify_active_database_path(mbse_root, handles, prepared) != 0 ||
        fstat(handles->users_fd, &status) != 0) {
        return -1;
    }
    if (status.st_size !=
        prepared->original_size + (off_t)expected_record_bytes) {
        errno = ESTALE;
        return -1;
    }
    if (status.st_uid != handles->database_status.st_uid ||
        status.st_gid != handles->database_status.st_gid ||
        (status.st_mode & (mode_t)07777) !=
            (handles->database_status.st_mode & (mode_t)07777) ||
        status.st_nlink != handles->database_status.st_nlink) {
        errno = ESTALE;
        return -1;
    }
    if (expected_record_bytes > sizeof(actual_record)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (expected_record_bytes > 0U &&
        read_exact_at(handles->users_fd, actual_record,
                      expected_record_bytes,
                      prepared->original_size) != 0) {
        return -1;
    }
    if (expected_record_bytes > 0U &&
        memcmp(actual_record, prepared->record_bytes,
               expected_record_bytes) != 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/*
 * Reverse a local prepare while both OFD locks are held.  Exact path/inode,
 * file length, tail bytes and marker checks must all pass before truncation or
 * directory removal is attempted.
 */
static int
rollback_locked(provision_handles_t *handles,
                const char *mbse_root,
                const char *bbs_users_directory,
                legacy_userdb_prepared_registration_t *prepared,
                size_t expected_record_bytes,
                bool require_marker,
                mode_t expected_staging_mode,
                legacy_userdb_error_t *error)
{
    char staging_name[LEGACY_STAGING_NAME_SIZE];
    char record_marker[LEGACY_RECORD_MARKER_SIZE];
    char marker[LEGACY_MARKER_BUFFER_SIZE];
    size_t marker_length = 0U;
    unsigned char actual_record[LEGACY_USERDB_RECORD_SIZE];
    struct stat database_status;
    struct stat entry;
    bool record_present = false;
    bool final_present = false;
    bool staging_present = false;
    mode_t staging_mode = expected_staging_mode;
    int final_state;
    int staging_state;

    build_names(prepared->registration_id, staging_name, record_marker);
    (void)record_marker;
    if (build_marker(prepared, LEGACY_MARKER_STATE_PREPARED,
                     marker, &marker_length) != 0) {
        provision_set_error(error, LEGACY_USERDB_CONTEXT_INVALID, errno,
                            prepared->record_number, true,
                            "cannot rebuild registration marker");
        return -1;
    }
    if (verify_database_identity(handles->users_fd, prepared) != 0 ||
        verify_active_database_path(mbse_root, handles, prepared) != 0 ||
        verify_users_directory_identity(handles->users_directory_fd,
                                        prepared) != 0 ||
        verify_open_users_directory_stable(handles) != 0 ||
        verify_active_users_directory_path(bbs_users_directory,
                                           prepared) != 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, errno,
                            prepared->record_number, true,
                            "legacy storage identity changed before rollback");
        return -1;
    }
    if (fstat(handles->users_fd, &database_status) != 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, errno,
                            prepared->record_number, true,
                            "cannot inspect legacy database before rollback");
        return -1;
    }
    if (database_status.st_size ==
        prepared->original_size + (off_t)expected_record_bytes) {
        if (expected_record_bytes > 0U) {
            if (read_exact_at(handles->users_fd, actual_record,
                              expected_record_bytes,
                              prepared->original_size) != 0) {
                provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE,
                                    errno, prepared->record_number, true,
                                    "cannot verify legacy record for rollback");
                return -1;
            }
            if (memcmp(actual_record, prepared->record_bytes,
                       expected_record_bytes) != 0) {
                provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE,
                                    EINVAL, prepared->record_number, true,
                                    "legacy record no longer matches rollback context");
                return -1;
            }
            record_present = true;
        }
    } else if (database_status.st_size != prepared->original_size) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, 0,
                            prepared->record_number, true,
                            "legacy database length changed after provisioning");
        return -1;
    }

    final_state = entry_status(handles->users_directory_fd,
                               prepared->legacy_name, &entry);
    if (final_state < 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, errno,
                            prepared->record_number, true,
                            "cannot inspect final legacy user directory");
        return -1;
    }
    final_present = final_state > 0;
    staging_state = entry_status(handles->users_directory_fd,
                                 staging_name, &entry);
    if (staging_state < 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, errno,
                            prepared->record_number, true,
                            "cannot inspect registration staging directory");
        return -1;
    }
    staging_present = staging_state > 0;
    if (staging_present) {
        mode_t actual_mode = entry.st_mode & (mode_t)07777;

        if (!S_ISDIR(entry.st_mode) || entry.st_uid != geteuid() ||
            entry.st_gid != getegid() ||
            (actual_mode != expected_staging_mode &&
             !(expected_staging_mode == LEGACY_USER_DIRECTORY_MODE &&
               actual_mode == LEGACY_STAGING_DIRECTORY_MODE))) {
            provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, EPERM,
                                prepared->record_number, true,
                                "registration staging directory changed");
            return -1;
        }
        staging_mode = actual_mode;
    }
    if (final_present && staging_present) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, 0,
                            prepared->record_number, true,
                            "both final and staging directories exist");
        return -1;
    }
    if (record_present && !final_present && !staging_present) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, 0,
                            prepared->record_number, true,
                            "legacy record exists without its marked directory");
        return -1;
    }

    if (final_present) {
        int top_fd = open_owned_directory_at(handles->users_directory_fd,
                                              prepared->legacy_name,
                                              LEGACY_USER_DIRECTORY_MODE);
        if (top_fd < 0 ||
            (require_marker &&
             marker_matches(top_fd, marker, marker_length) != 0)) {
            int saved_errno = errno;
            if (top_fd >= 0) {
                (void)close(top_fd);
            }
            provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE,
                                saved_errno, prepared->record_number, true,
                                "final legacy directory marker does not match");
            return -1;
        }
        (void)close(top_fd);
        if (rename_noreplace(handles->users_directory_fd,
                             prepared->legacy_name,
                             handles->users_directory_fd,
                             staging_name) != 0 ||
            fsync(handles->users_directory_fd) != 0) {
            provision_set_error(error, LEGACY_USERDB_ROLLBACK_FAILED, errno,
                                prepared->record_number, true,
                                "cannot hide final directory during rollback");
            return -1;
        }
        staging_present = true;
        staging_mode = LEGACY_USER_DIRECTORY_MODE;
    }

    if (staging_present && require_marker) {
        int top_fd = open_owned_directory_at(handles->users_directory_fd,
                                              staging_name, staging_mode);
        if (top_fd < 0 || marker_matches(top_fd, marker, marker_length) != 0) {
            int saved_errno = errno;
            if (top_fd >= 0) {
                (void)close(top_fd);
            }
            provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE,
                                saved_errno, prepared->record_number, true,
                                "staging directory marker does not match");
            return -1;
        }
        (void)close(top_fd);
    }
    if (staging_present &&
        privatize_staging_directory(handles->users_directory_fd,
                                    staging_name, staging_mode) != 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_FAILED, errno,
                            prepared->record_number, true,
                            "cannot privatize registration directory");
        return -1;
    }
    if (staging_present) {
        staging_mode = LEGACY_STAGING_DIRECTORY_MODE;
    }
    if (staging_present && require_marker &&
        verify_exact_registration_tree(handles->users_directory_fd,
                                       staging_name, staging_mode,
                                       marker, marker_length) != 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, errno,
                            prepared->record_number, true,
                            "registration directory tree changed");
        return -1;
    }

    if (record_present) {
        if (ftruncate(handles->users_fd, prepared->original_size) != 0 ||
            fdatasync(handles->users_fd) != 0) {
            provision_set_error(error, LEGACY_USERDB_ROLLBACK_FAILED, errno,
                                prepared->record_number, true,
                                "cannot remove appended legacy record");
            return -1;
        }
    }
    if (staging_present &&
        remove_known_tree(handles->users_directory_fd, staging_name,
                          marker, marker_length, require_marker,
                          staging_mode) != 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_FAILED, errno,
                            prepared->record_number, true,
                            "cannot remove marked registration directory");
        return -1;
    }
    if (fsync(handles->users_directory_fd) != 0) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_FAILED, errno,
                            prepared->record_number, true,
                            "cannot synchronize users directory after rollback");
        return -1;
    }
    return 0;
}

static bool
prepared_context_is_valid(
    const legacy_userdb_prepared_registration_t *prepared)
{
    struct userrec record;
    char staging_name[LEGACY_STAGING_NAME_SIZE];
    char expected_record_marker[LEGACY_RECORD_MARKER_SIZE];
    size_t password_index;
    bool password_zero = true;

    if (prepared == NULL || !prepared->prepared ||
        !uuid_is_nonzero(prepared->registration_id) ||
        !uuid_is_nonzero(prepared->user_id) ||
        !legacy_userdb_legacy_name_is_valid(prepared->legacy_name) ||
        !legacy_userdb_display_name_is_compatible(prepared->display_name) ||
        prepared->record_number == LEGACY_USERDB_NO_RECORD ||
        prepared->record_number >= LEGACY_USERDB_DEFAULT_MAX_RECORDS ||
        !mode_value_is_valid(prepared->database_mode) ||
        !mode_value_is_valid(prepared->users_directory_mode) ||
        prepared->database_links == 0 ||
        prepared->original_size !=
            (off_t)LEGACY_USERDB_HEADER_SIZE +
                (off_t)(prepared->record_number *
                        LEGACY_USERDB_RECORD_SIZE)) {
        return false;
    }

    memcpy(&record, prepared->record_bytes, sizeof(record));
    for (password_index = 0U;
         password_index < sizeof(record.Password); ++password_index) {
        if (record.Password[password_index] != '\0') {
            password_zero = false;
        }
    }
    build_names(prepared->registration_id, staging_name,
                expected_record_marker);
    (void)staging_name;
    return fixed_text_is_terminated(record.Name, sizeof(record.Name)) &&
           fixed_text_is_terminated(record.sUserName,
                                    sizeof(record.sUserName)) &&
           fixed_text_is_terminated(record.sComment,
                                    sizeof(record.sComment)) &&
           fixed_text_is_terminated(record.Password,
                                    sizeof(record.Password)) &&
           strcmp(record.Name, prepared->legacy_name) == 0 &&
           strcmp(record.sUserName, prepared->display_name) == 0 &&
           strcmp(record.sComment, expected_record_marker) == 0 &&
           record.xPassword == 0U && password_zero;
}

/*
 * Prepare the complete local legacy side without contacting FTAP.  Success
 * leaves one durable appended record and one atomically published directory;
 * the returned context is the proof required for a pre-commit rollback.
 */
int
legacy_userdb_prepare_registration(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    const legacy_userdb_registration_t *registration,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    provision_handles_t handles;
    legacy_userdb_prepared_registration_t context;
    struct userrec record;
    char staging_name[LEGACY_STAGING_NAME_SIZE];
    char record_marker[LEGACY_RECORD_MARKER_SIZE];
    char marker[LEGACY_MARKER_BUFFER_SIZE];
    size_t marker_length = 0U;
    size_t record_count = 0U;
    size_t bytes_written = 0U;
    bool staging_created = false;
    bool marker_created = false;
    bool staging_promoted = false;
    bool final_directory = false;
    legacy_userdb_error_t original_error;
    int result = -1;

    handles_init(&handles);
    legacy_userdb_prepared_registration_clear(&context);
    legacy_userdb_error_clear(error);
    if (prepared != NULL) {
        legacy_userdb_prepared_registration_clear(prepared);
    }

    if (mbse_root == NULL || mbse_root[0] != '/' ||
        bbs_users_directory == NULL || bbs_users_directory[0] != '/' ||
        !provision_policy_is_valid(policy) ||
        !registration_is_valid(registration) || prepared == NULL) {
        provision_set_error(error, LEGACY_USERDB_INVALID_REGISTRATION, EINVAL,
                            LEGACY_USERDB_NO_RECORD, false,
                            "invalid legacy registration request");
        return -1;
    }

    if (open_runtime_lock(mbse_root, policy, &handles, error) != 0 ||
        open_users_directory(bbs_users_directory, policy, &handles,
                             error) != 0 ||
        open_users_database(policy, &handles, error) != 0 ||
        validate_database_for_registration(
            handles.users_fd, &handles.database_status, &policy->database,
            registration, LEGACY_USERDB_NO_RECORD, NULL, &record_count,
            error) != 0) {
        goto done;
    }

    build_names(registration->registration_id, staging_name, record_marker);
    if (ensure_target_names_absent(handles.users_directory_fd,
                                   registration->legacy_name,
                                   staging_name, error) != 0) {
        goto done;
    }
    if (build_record(registration, &record) != 0) {
        provision_set_error(error, LEGACY_USERDB_ABI_MISMATCH, errno,
                            record_count, false,
                            "compiler bit-field ABI cannot encode legacy record");
        goto done;
    }

    context.prepared = true;
    memcpy(context.registration_id, registration->registration_id,
           sizeof(context.registration_id));
    memcpy(context.user_id, registration->user_id, sizeof(context.user_id));
    (void)snprintf(context.legacy_name, sizeof(context.legacy_name), "%s",
                   registration->legacy_name);
    (void)snprintf(context.display_name, sizeof(context.display_name), "%s",
                   registration->display_name);
    context.record_number = record_count;
    context.original_size = handles.database_status.st_size;
    context.database_device = handles.database_status.st_dev;
    context.database_inode = handles.database_status.st_ino;
    context.database_uid = handles.database_status.st_uid;
    context.database_gid = handles.database_status.st_gid;
    context.database_mode =
        handles.database_status.st_mode & (mode_t)07777;
    context.database_links = handles.database_status.st_nlink;
    context.users_directory_device = handles.users_directory_status.st_dev;
    context.users_directory_inode = handles.users_directory_status.st_ino;
    context.users_directory_uid = handles.users_directory_status.st_uid;
    context.users_directory_gid = handles.users_directory_status.st_gid;
    context.users_directory_mode =
        handles.users_directory_status.st_mode & (mode_t)07777;
    memcpy(context.record_bytes, &record, sizeof(record));

    if (build_marker(&context, LEGACY_MARKER_STATE_PREPARED,
                     marker, &marker_length) != 0) {
        provision_set_error(error, LEGACY_USERDB_INVALID_REGISTRATION, errno,
                            record_count, false,
                            "cannot build registration marker");
        goto done;
    }
    if (create_staging_tree(handles.users_directory_fd, staging_name,
                            marker, marker_length, &staging_created,
                            &marker_created, error) != 0 ||
        sync_users_directory(handles.users_directory_fd) != 0) {
        if (error != NULL && error->status == LEGACY_USERDB_OK) {
            provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                                record_count, false,
                                "cannot synchronize registration staging tree");
        }
        goto rollback;
    }

    if (write_record_at(handles.users_fd, context.record_bytes,
                        context.original_size, &bytes_written) != 0) {
        provision_set_error(error, LEGACY_USERDB_WRITE_FAILED, errno,
                            record_count, false,
                            "cannot append complete legacy user record");
        goto rollback;
    }
    if (sync_database(handles.users_fd) != 0) {
        provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                            record_count, false,
                            "cannot synchronize appended legacy user record");
        goto rollback;
    }
    {
        unsigned char verification[LEGACY_USERDB_RECORD_SIZE];

        if (read_exact_at(handles.users_fd, verification,
                          sizeof(verification), context.original_size) != 0) {
            provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, errno,
                                record_count, false,
                                "cannot read back appended legacy user record");
            goto rollback;
        }
#ifdef LEGACY_USERDB_TESTING
        if (test_fault_once(LEGACY_USERDB_TEST_FAULT_READBACK_MISMATCH)) {
            verification[0] ^= 0x01U;
        }
#endif
        if (memcmp(verification, context.record_bytes,
                   sizeof(verification)) != 0) {
            provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, EIO,
                                record_count, false,
                                "appended legacy user record did not verify");
            goto rollback;
        }
    }

    if (verify_postappend_database(mbse_root, &handles, &context,
                                   LEGACY_USERDB_RECORD_SIZE) != 0 ||
        verify_users_directory_identity(handles.users_directory_fd,
                                        &context) != 0 ||
        verify_open_users_directory_stable(&handles) != 0 ||
        verify_active_users_directory_path(bbs_users_directory,
                                           &context) != 0) {
        provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, errno,
                            record_count, false,
                            "legacy storage changed during provisioning");
        goto rollback;
    }
    if (revalidate_postappend_records(
            handles.users_fd, &policy->database, registration, &context,
            error) != 0) {
        goto rollback;
    }
    if (promote_staging_directory(handles.users_directory_fd,
                                  staging_name,
                                  &staging_promoted) != 0) {
        provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                            record_count, false,
                            "cannot finalize registration staging mode");
        goto rollback;
    }

    if (rename_noreplace(handles.users_directory_fd, staging_name,
                         handles.users_directory_fd,
                         context.legacy_name) != 0) {
        provision_set_error(error, LEGACY_USERDB_RENAME_FAILED, errno,
                            record_count, false,
                            "cannot publish legacy user directory");
        goto rollback;
    }
    final_directory = true;
    staging_created = false;
    if (sync_users_directory(handles.users_directory_fd) != 0) {
        provision_set_error(error, LEGACY_USERDB_SYNC_FAILED, errno,
                            record_count, false,
                            "cannot synchronize published user directory");
        goto rollback;
    }
    if (verify_exact_registration_tree(handles.users_directory_fd,
                                       context.legacy_name,
                                       LEGACY_USER_DIRECTORY_MODE,
                                       marker, marker_length) != 0 ||
        verify_postappend_database(mbse_root, &handles, &context,
                                   LEGACY_USERDB_RECORD_SIZE) != 0 ||
        verify_users_directory_identity(handles.users_directory_fd,
                                        &context) != 0 ||
        verify_open_users_directory_stable(&handles) != 0 ||
        verify_active_users_directory_path(bbs_users_directory,
                                           &context) != 0) {
        provision_set_error(error, LEGACY_USERDB_VERIFY_FAILED, errno,
                            record_count, false,
                            "legacy storage changed before local prepare completed");
        goto rollback;
    }
    if (revalidate_postappend_records(
            handles.users_fd, &policy->database, registration, &context,
            error) != 0) {
        goto rollback;
    }

    *prepared = context;
    result = 0;
    goto done;

rollback:
    original_error = error != NULL ? *error : (legacy_userdb_error_t){0};
    if (final_directory || staging_created || bytes_written > 0U) {
        if (rollback_locked(
                &handles, mbse_root, bbs_users_directory, &context, bytes_written,
                marker_created,
                staging_promoted ? LEGACY_USER_DIRECTORY_MODE
                                 : LEGACY_STAGING_DIRECTORY_MODE,
                error) != 0) {
            if (error != NULL) {
                char text[LEGACY_USERDB_ERROR_TEXT_SIZE];
                (void)snprintf(text, sizeof(text),
                               "cleanup after %s failed; reconciliation required",
                               legacy_userdb_status_name(original_error.status));
                provision_set_error(
                    error,
                    error->status == LEGACY_USERDB_ROLLBACK_UNSAFE
                        ? LEGACY_USERDB_ROLLBACK_UNSAFE
                        : LEGACY_USERDB_ROLLBACK_FAILED,
                    error->system_errno, record_count, true, text);
            }
            *prepared = context;
            goto done;
        }
    }
    if (error != NULL) {
        *error = original_error;
    }
    legacy_userdb_prepared_registration_clear(&context);

done:
    handles_close(&handles);
    return result;
}

/*
 * Cross the irreversible coordinator boundary before any FTAP Commit bytes are
 * sent.  From this point onward the local proof remains available only for
 * finalization or later reconciliation, never for automatic rollback.
 */
int
legacy_userdb_mark_commit_started(
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    legacy_userdb_error_clear(error);
    if (!prepared_context_is_valid(prepared)) {
        provision_set_error(error, LEGACY_USERDB_CONTEXT_INVALID, EINVAL,
                            LEGACY_USERDB_NO_RECORD,
                            prepared != NULL && prepared->prepared,
                            "invalid legacy commit-boundary context");
        return -1;
    }
    prepared->commit_started = true;
    return 0;
}

static int
write_committed_marker(int users_directory_fd,
                       const legacy_userdb_prepared_registration_t *prepared,
                       const char *prepared_marker,
                       size_t prepared_marker_length,
                       const char *committed_marker,
                       size_t committed_marker_length)
{
    struct stat status;
    int top_fd = -1;
    int marker_fd = -1;
    bool renamed = false;
    int saved_errno;

    if (verify_exact_registration_tree(
            users_directory_fd, prepared->legacy_name,
            LEGACY_USER_DIRECTORY_MODE, prepared_marker,
            prepared_marker_length) != 0) {
        return -1;
    }
    top_fd = open_owned_directory_at(users_directory_fd,
                                     prepared->legacy_name,
                                     LEGACY_USER_DIRECTORY_MODE);
    if (top_fd < 0) {
        return -1;
    }
    marker_fd = openat(top_fd, LEGACY_COMMITTED_MARKER_TEMP,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                       LEGACY_MARKER_MODE);
    if (marker_fd < 0) {
        goto failed;
    }
#ifdef LEGACY_USERDB_TESTING
    if (test_fault_once(LEGACY_USERDB_TEST_FAULT_COMMITTED_MARKER_WRITE)) {
        errno = EIO;
        goto failed;
    }
#endif
    if (fchmod(marker_fd, LEGACY_MARKER_MODE) != 0 ||
        write_exact(marker_fd, committed_marker,
                    committed_marker_length, false) != 0 ||
        fsync(marker_fd) != 0 || fstat(marker_fd, &status) != 0) {
        goto failed;
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        status.st_gid != getegid() || status.st_nlink != 1 ||
        (status.st_mode & (mode_t)07777) != LEGACY_MARKER_MODE ||
        status.st_size != (off_t)committed_marker_length) {
        errno = EPERM;
        goto failed;
    }
    if (close(marker_fd) != 0) {
        marker_fd = -1;
        goto failed;
    }
    marker_fd = -1;
#ifdef LEGACY_USERDB_TESTING
    if (test_fault_once(LEGACY_USERDB_TEST_FAULT_COMMITTED_MARKER_RENAME)) {
        errno = EIO;
        goto failed;
    }
#endif
    if (renameat(top_fd, LEGACY_COMMITTED_MARKER_TEMP,
                 top_fd, LEGACY_USERDB_MARKER_FILE) != 0) {
        goto failed;
    }
    renamed = true;
#ifdef LEGACY_USERDB_TESTING
    if (test_fault_once(LEGACY_USERDB_TEST_FAULT_COMMITTED_DIRECTORY_SYNC)) {
        errno = EIO;
        goto failed;
    }
#endif
    if (fsync(top_fd) != 0 ||
        marker_matches(top_fd, committed_marker,
                       committed_marker_length) != 0) {
        goto failed;
    }
    if (close(top_fd) != 0) {
        return -1;
    }
    return 0;

failed:
    saved_errno = errno;
    if (marker_fd >= 0) {
        (void)close(marker_fd);
    }
    if (top_fd >= 0) {
        if (!renamed) {
            (void)unlinkat(top_fd, LEGACY_COMMITTED_MARKER_TEMP, 0);
        }
        (void)close(top_fd);
    }
    errno = saved_errno;
    return -1;
}

static int
sync_existing_committed_marker(
    int users_directory_fd,
    const legacy_userdb_prepared_registration_t *prepared,
    const char *committed_marker,
    size_t committed_marker_length)
{
    int top_fd;
    int saved_errno;

    if (verify_exact_registration_tree(
            users_directory_fd, prepared->legacy_name,
            LEGACY_USER_DIRECTORY_MODE, committed_marker,
            committed_marker_length) != 0) {
        return -1;
    }
    top_fd = open_owned_directory_at(users_directory_fd,
                                     prepared->legacy_name,
                                     LEGACY_USER_DIRECTORY_MODE);
    if (top_fd < 0) {
        return -1;
    }
    if (fsync(top_fd) != 0) {
        saved_errno = errno;
        (void)close(top_fd);
        errno = saved_errno;
        return -1;
    }
    if (close(top_fd) != 0) {
        return -1;
    }
    return verify_exact_registration_tree(
        users_directory_fd, prepared->legacy_name,
        LEGACY_USER_DIRECTORY_MODE, committed_marker,
        committed_marker_length);
}

/*
 * Confirm only the persistent marker after PostgreSQL has returned a valid
 * Commit result.  The record and user tree are never removed on failure.
 */
int
legacy_userdb_finalize_committed(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    provision_handles_t handles;
    char prepared_marker[LEGACY_MARKER_BUFFER_SIZE];
    char committed_marker[LEGACY_MARKER_BUFFER_SIZE];
    size_t prepared_marker_length = 0U;
    size_t committed_marker_length = 0U;
    int result = -1;

    handles_init(&handles);
    legacy_userdb_error_clear(error);
    if (mbse_root == NULL || mbse_root[0] != '/' ||
        bbs_users_directory == NULL || bbs_users_directory[0] != '/' ||
        !provision_policy_is_valid(policy) ||
        !prepared_context_is_valid(prepared) ||
        !prepared->commit_started) {
        provision_set_error(error, LEGACY_USERDB_COMMIT_STATE_INVALID, EINVAL,
                            prepared != NULL ? prepared->record_number
                                             : LEGACY_USERDB_NO_RECORD,
                            prepared != NULL && prepared->prepared,
                            "legacy registration is not at the commit boundary");
        return -1;
    }
    if (build_marker(prepared, LEGACY_MARKER_STATE_PREPARED,
                     prepared_marker, &prepared_marker_length) != 0 ||
        build_marker(prepared, LEGACY_MARKER_STATE_COMMITTED,
                     committed_marker, &committed_marker_length) != 0) {
        provision_set_error(error, LEGACY_USERDB_FINALIZE_FAILED, errno,
                            prepared->record_number, true,
                            "cannot build committed registration marker");
        return -1;
    }

    if (open_runtime_lock(mbse_root, policy, &handles, error) != 0 ||
        open_users_directory(bbs_users_directory, policy, &handles,
                             error) != 0 ||
        open_users_database(policy, &handles, error) != 0) {
        if (error != NULL) {
            int saved_errno = error->system_errno;
            provision_set_error(error, LEGACY_USERDB_FINALIZE_FAILED,
                                saved_errno, prepared->record_number, true,
                                "cannot safely reacquire legacy storage after commit");
        }
        goto done;
    }
    if (verify_postappend_database(mbse_root, &handles, prepared,
                                   LEGACY_USERDB_RECORD_SIZE) != 0 ||
        verify_users_directory_identity(handles.users_directory_fd,
                                        prepared) != 0 ||
        verify_open_users_directory_stable(&handles) != 0 ||
        verify_active_users_directory_path(bbs_users_directory,
                                           prepared) != 0) {
        provision_set_error(error, LEGACY_USERDB_FINALIZE_FAILED, errno,
                            prepared->record_number, true,
                            "legacy storage changed after registration commit");
        goto done;
    }

    /* A retry after rename must repeat the directory durability barrier. */
    if (verify_exact_registration_tree(
            handles.users_directory_fd, prepared->legacy_name,
            LEGACY_USER_DIRECTORY_MODE, committed_marker,
            committed_marker_length) == 0) {
        if (sync_existing_committed_marker(
                handles.users_directory_fd, prepared, committed_marker,
                committed_marker_length) != 0 ||
            verify_postappend_database(mbse_root, &handles, prepared,
                                       LEGACY_USERDB_RECORD_SIZE) != 0) {
            provision_set_error(
                error, LEGACY_USERDB_FINALIZE_FAILED, errno,
                prepared->record_number, true,
                "cannot confirm committed legacy marker durability");
            goto done;
        }
    } else if (write_committed_marker(
                   handles.users_directory_fd, prepared,
                   prepared_marker, prepared_marker_length,
                   committed_marker, committed_marker_length) != 0 ||
               verify_postappend_database(
                   mbse_root, &handles, prepared,
                   LEGACY_USERDB_RECORD_SIZE) != 0 ||
               verify_exact_registration_tree(
                   handles.users_directory_fd, prepared->legacy_name,
                   LEGACY_USER_DIRECTORY_MODE, committed_marker,
                   committed_marker_length) != 0) {
        provision_set_error(error, LEGACY_USERDB_FINALIZE_FAILED, errno,
                            prepared->record_number, true,
                            "cannot durably finalize committed legacy registration");
        goto done;
    }

    legacy_userdb_prepared_registration_clear(prepared);
    result = 0;

done:
    handles_close(&handles);
    return result;
}

/*
 * Public rollback entry point for callers that have not begun an FTAP Commit
 * request.  A completed or uncertain Commit must instead be reconciled and
 * must never call this destructive pre-commit path.
 */
int
legacy_userdb_rollback_precommit(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    provision_handles_t handles;
    bool context_claims_prepared = prepared != NULL && prepared->prepared;
    int result = -1;

    handles_init(&handles);
    legacy_userdb_error_clear(error);
    if (prepared != NULL && !prepared->prepared) {
        return 0;
    }
    if (prepared != NULL && prepared->prepared && prepared->commit_started) {
        provision_set_error(error, LEGACY_USERDB_ROLLBACK_UNSAFE, EPERM,
                            prepared->record_number, true,
                            "FTAP commit boundary already crossed; rollback forbidden");
        return -1;
    }
    if (mbse_root == NULL || mbse_root[0] != '/' ||
        bbs_users_directory == NULL || bbs_users_directory[0] != '/' ||
        !provision_policy_is_valid(policy) ||
        !prepared_context_is_valid(prepared)) {
        provision_set_error(error, LEGACY_USERDB_CONTEXT_INVALID, EINVAL,
                            LEGACY_USERDB_NO_RECORD,
                            context_claims_prepared,
                            "invalid legacy rollback context");
        return -1;
    }

    if (open_runtime_lock(mbse_root, policy, &handles, error) != 0 ||
        open_users_directory(bbs_users_directory, policy, &handles,
                             error) != 0 ||
        open_users_database(policy, &handles, error) != 0) {
        if (error != NULL &&
            error->status != LEGACY_USERDB_GLOBAL_BUSY &&
            error->status != LEGACY_USERDB_BUSY) {
            int saved_errno = error->system_errno;
            provision_set_error(
                error, LEGACY_USERDB_ROLLBACK_UNSAFE, saved_errno,
                prepared->record_number, true,
                "cannot safely reacquire legacy storage for rollback");
        }
        goto done;
    }
    if (rollback_locked(&handles, mbse_root, bbs_users_directory, prepared,
                        LEGACY_USERDB_RECORD_SIZE, true,
                        LEGACY_USER_DIRECTORY_MODE, error) != 0) {
        goto done;
    }

    legacy_userdb_prepared_registration_clear(prepared);
    result = 0;

done:
    handles_close(&handles);
    return result;
}
