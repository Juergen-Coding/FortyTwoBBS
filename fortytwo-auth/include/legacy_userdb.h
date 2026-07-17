/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Validated access and controlled provisioning for the legacy MBSE users.data.
 * The implementation intentionally targets Linux OFD locks and renameat2.
 */

#ifndef FORTYTWO_LEGACY_USERDB_H
#define FORTYTWO_LEGACY_USERDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LEGACY_USERDB_HEADER_SIZE 8U
#define LEGACY_USERDB_RECORD_SIZE 598U
#define LEGACY_USERDB_LEGACY_NAME_MAX 8U
#define LEGACY_USERDB_DISPLAY_NAME_MAX 35U
#define LEGACY_USERDB_HANDLE_MAX 35U
#define LEGACY_USERDB_PROTOCOL_MAX 20U
#define LEGACY_USERDB_CHARSET_NONE 0
#define LEGACY_USERDB_CHARSET_CP437 1
#define LEGACY_USERDB_CHARSET_MAX 14
#define LEGACY_USERDB_UUID_SIZE 16U
#define LEGACY_USERDB_UUID_TEXT_SIZE 37U
#define LEGACY_USERDB_DEFAULT_MAX_RECORDS 65536U
#define LEGACY_USERDB_NO_RECORD SIZE_MAX
#define LEGACY_USERDB_ERROR_TEXT_SIZE 160U
#define LEGACY_USERDB_MARKER_FILE ".fortytwo-registration"
#define LEGACY_USERDB_STAGING_PREFIX ".ft42reg-"
#define LEGACY_USERDB_RECORD_MARKER_PREFIX "FT42REG:"

/* Historical MSGEDITOR values from lib/users.h. */
#define LEGACY_USERDB_EDITOR_LINE 0
#define LEGACY_USERDB_EDITOR_FULLSCREEN 1
#define LEGACY_USERDB_EDITOR_EXTERNAL 2

typedef enum legacy_userdb_status {
    LEGACY_USERDB_OK = 0,
    LEGACY_USERDB_INVALID_ARGUMENT,
    LEGACY_USERDB_OPEN_ROOT_FAILED,
    LEGACY_USERDB_OPEN_ETC_FAILED,
    LEGACY_USERDB_OPEN_FILE_FAILED,
    LEGACY_USERDB_STAT_FAILED,
    LEGACY_USERDB_NOT_REGULAR,
    LEGACY_USERDB_OWNER_MISMATCH,
    LEGACY_USERDB_GROUP_MISMATCH,
    LEGACY_USERDB_MODE_MISMATCH,
    LEGACY_USERDB_LINK_COUNT_MISMATCH,
    LEGACY_USERDB_BUSY,
    LEGACY_USERDB_LOCK_FAILED,
    LEGACY_USERDB_HEADER_TRUNCATED,
    LEGACY_USERDB_HEADER_MISMATCH,
    LEGACY_USERDB_SIZE_MISMATCH,
    LEGACY_USERDB_TOO_MANY_RECORDS,
    LEGACY_USERDB_READ_FAILED,
    LEGACY_USERDB_INVALID_RECORD,
    LEGACY_USERDB_DUPLICATE_LEGACY_NAME,
    LEGACY_USERDB_MEMORY_FAILED,
    LEGACY_USERDB_CHANGED_DURING_SCAN,
    LEGACY_USERDB_INVALID_REGISTRATION,
    LEGACY_USERDB_ABI_MISMATCH,
    LEGACY_USERDB_OPEN_RUNTIME_FAILED,
    LEGACY_USERDB_RUNTIME_POLICY_MISMATCH,
    LEGACY_USERDB_CREATE_LOCK_FAILED,
    LEGACY_USERDB_GLOBAL_BUSY,
    LEGACY_USERDB_OPEN_USERS_DIRECTORY_FAILED,
    LEGACY_USERDB_USERS_DIRECTORY_POLICY_MISMATCH,
    LEGACY_USERDB_NAME_COLLISION,
    LEGACY_USERDB_REGISTRATION_EXISTS,
    LEGACY_USERDB_TARGET_EXISTS,
    LEGACY_USERDB_STAGING_EXISTS,
    LEGACY_USERDB_CREATE_DIRECTORY_FAILED,
    LEGACY_USERDB_CREATE_MARKER_FAILED,
    LEGACY_USERDB_WRITE_MARKER_FAILED,
    LEGACY_USERDB_WRITE_FAILED,
    LEGACY_USERDB_SYNC_FAILED,
    LEGACY_USERDB_VERIFY_FAILED,
    LEGACY_USERDB_RENAME_FAILED,
    LEGACY_USERDB_CONTEXT_INVALID,
    LEGACY_USERDB_COMMIT_STATE_INVALID,
    LEGACY_USERDB_FINALIZE_FAILED,
    LEGACY_USERDB_ROLLBACK_UNSAFE,
    LEGACY_USERDB_ROLLBACK_FAILED
} legacy_userdb_status_t;

typedef struct legacy_userdb_policy {
    bool check_owner;
    uid_t expected_uid;
    bool check_group;
    gid_t expected_gid;
    bool check_mode;
    mode_t expected_mode;
    bool require_single_link;
    size_t max_records;
} legacy_userdb_policy_t;

typedef struct legacy_userdb_directory_policy {
    bool check_owner;
    uid_t expected_uid;
    bool check_group;
    gid_t expected_gid;
    bool check_mode;
    mode_t expected_mode;
} legacy_userdb_directory_policy_t;

typedef struct legacy_userdb_provision_policy {
    legacy_userdb_policy_t database;
    legacy_userdb_directory_policy_t users_directory;
    legacy_userdb_directory_policy_t runtime_directory;
} legacy_userdb_provision_policy_t;

typedef struct legacy_userdb_query {
    const char *legacy_name;
    const char *display_name;
} legacy_userdb_query_t;

typedef struct legacy_userdb_scan_result {
    size_t record_count;
    bool legacy_name_exists;
    size_t legacy_name_record;
    bool display_name_exists;
    size_t display_name_record;
    bool handle_exists;
    size_t handle_record;
} legacy_userdb_scan_result_t;

/*
 * Sanitized read-only view used by reconciliation and audit tools. Sensitive
 * legacy fields never leave the gateway through this structure.
 */
typedef struct legacy_userdb_audit_record {
    size_t record_number;
    char legacy_name[LEGACY_USERDB_LEGACY_NAME_MAX + 1U];
    char display_name[LEGACY_USERDB_DISPLAY_NAME_MAX + 1U];
    char handle[LEGACY_USERDB_HANDLE_MAX + 1U];
    bool empty;
    bool deleted;
    bool locked_out;
    bool registration_marker_present;
    uint8_t registration_id[LEGACY_USERDB_UUID_SIZE];
} legacy_userdb_audit_record_t;

typedef struct legacy_userdb_audit_snapshot {
    legacy_userdb_audit_record_t *records;
    size_t record_count;
    struct stat file_status;
    int header_size;
    int record_size;
} legacy_userdb_audit_snapshot_t;

typedef struct legacy_userdb_record_defaults {
    uint32_t security_level;
    uint32_t security_flags;
    uint32_t security_notflags;
    int32_t language;
    int32_t charset;
    int32_t message_editor;
    const char *protocol;
    bool email;
    bool mail_scan;
    bool new_file_scan;
} legacy_userdb_record_defaults_t;

typedef struct legacy_userdb_registration {
    uint8_t registration_id[LEGACY_USERDB_UUID_SIZE];
    uint8_t user_id[LEGACY_USERDB_UUID_SIZE];
    const char *legacy_name;
    const char *display_name;
    int64_t registered_at;
    legacy_userdb_record_defaults_t defaults;
} legacy_userdb_registration_t;

/*
 * This context contains no password. Its record copy exists solely so a later
 * pre-commit rollback can prove that the last record is exactly the one this
 * provisioning attempt appended.
 */
typedef struct legacy_userdb_prepared_registration {
    bool prepared;
    bool commit_started;
    uint8_t registration_id[LEGACY_USERDB_UUID_SIZE];
    uint8_t user_id[LEGACY_USERDB_UUID_SIZE];
    char legacy_name[LEGACY_USERDB_LEGACY_NAME_MAX + 1U];
    char display_name[LEGACY_USERDB_DISPLAY_NAME_MAX + 1U];
    size_t record_number;
    off_t original_size;
    dev_t database_device;
    ino_t database_inode;
    uid_t database_uid;
    gid_t database_gid;
    mode_t database_mode;
    nlink_t database_links;
    dev_t users_directory_device;
    ino_t users_directory_inode;
    uid_t users_directory_uid;
    gid_t users_directory_gid;
    mode_t users_directory_mode;
    unsigned char record_bytes[LEGACY_USERDB_RECORD_SIZE];
} legacy_userdb_prepared_registration_t;

typedef struct legacy_userdb_error {
    legacy_userdb_status_t status;
    int system_errno;
    size_t record_number;
    bool repair_required;
    char text[LEGACY_USERDB_ERROR_TEXT_SIZE];
} legacy_userdb_error_t;

void legacy_userdb_policy_defaults(legacy_userdb_policy_t *policy);
void legacy_userdb_provision_policy_defaults(
    legacy_userdb_provision_policy_t *policy);
void legacy_userdb_prepared_registration_clear(
    legacy_userdb_prepared_registration_t *prepared);
void legacy_userdb_error_clear(legacy_userdb_error_t *error);
const char *legacy_userdb_status_name(legacy_userdb_status_t status);

bool legacy_userdb_legacy_name_is_valid(const char *legacy_name);
bool legacy_userdb_display_name_is_compatible(const char *display_name);

int legacy_userdb_inspect(const char *mbse_root,
                          const legacy_userdb_policy_t *policy,
                          const legacy_userdb_query_t *query,
                          legacy_userdb_scan_result_t *result,
                          legacy_userdb_error_t *error);

void legacy_userdb_audit_snapshot_clear(
    legacy_userdb_audit_snapshot_t *snapshot);
void legacy_userdb_audit_snapshot_free(
    legacy_userdb_audit_snapshot_t *snapshot);

/*
 * Read and validate the complete users.data file under the same policy and OFD
 * lock used by legacy_userdb_inspect(). The caller must pass a cleared
 * snapshot; ownership of the allocated record array transfers on success.
 */
int legacy_userdb_read_audit_snapshot(
    const char *mbse_root,
    const legacy_userdb_policy_t *policy,
    legacy_userdb_audit_snapshot_t *snapshot,
    legacy_userdb_error_t *error);

/*
 * Create one durable local record and marked user tree without contacting
 * FTAP.  The returned proof context must be retained until Commit or rollback.
 */
int legacy_userdb_prepare_registration(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    const legacy_userdb_registration_t *registration,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error);

/*
 * Cross the irreversible local Commit boundary. After this succeeds, the
 * prepared registration must be retained for reconciliation and may no longer
 * be removed by the pre-Commit rollback operation.
 */
int legacy_userdb_mark_commit_started(
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error);

/*
 * After a confirmed FTAP Commit, durably transition the local marker from
 * prepared to committed. Failure never removes the local record or directory.
 */
int legacy_userdb_finalize_committed(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error);

/*
 * This operation is permitted only before a registration Commit request has
 * begun. It is fail-closed and removes data only after exact marker, inode,
 * length and record-byte verification.
 */
int legacy_userdb_rollback_precommit(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error);

#ifdef LEGACY_USERDB_TESTING
typedef enum legacy_userdb_test_fault {
    LEGACY_USERDB_TEST_FAULT_NONE = 0,
    LEGACY_USERDB_TEST_FAULT_CREATE_STAGING,
    LEGACY_USERDB_TEST_FAULT_MARKER_WRITE,
    LEGACY_USERDB_TEST_FAULT_RECORD_SHORT_WRITE,
    LEGACY_USERDB_TEST_FAULT_RECORD_SYNC,
    LEGACY_USERDB_TEST_FAULT_READBACK_MISMATCH,
    LEGACY_USERDB_TEST_FAULT_POSTAPPEND_NAME_COLLISION,
    LEGACY_USERDB_TEST_FAULT_RENAME,
    LEGACY_USERDB_TEST_FAULT_USERS_DIRECTORY_SYNC,
    LEGACY_USERDB_TEST_FAULT_COMMITTED_MARKER_WRITE,
    LEGACY_USERDB_TEST_FAULT_COMMITTED_MARKER_RENAME,
    LEGACY_USERDB_TEST_FAULT_COMMITTED_DIRECTORY_SYNC
} legacy_userdb_test_fault_t;

void legacy_userdb_test_set_fault(legacy_userdb_test_fault_t fault);
#endif

#endif /* FORTYTWO_LEGACY_USERDB_H */
