/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Read-only validation and collision scan for the legacy MBSE users.data.
 */

#ifndef FORTYTWO_LEGACY_USERDB_H
#define FORTYTWO_LEGACY_USERDB_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LEGACY_USERDB_HEADER_SIZE 8U
#define LEGACY_USERDB_RECORD_SIZE 598U
#define LEGACY_USERDB_LEGACY_NAME_MAX 8U
#define LEGACY_USERDB_DISPLAY_NAME_MAX 35U
#define LEGACY_USERDB_HANDLE_MAX 35U
#define LEGACY_USERDB_DEFAULT_MAX_RECORDS 65536U
#define LEGACY_USERDB_NO_RECORD SIZE_MAX
#define LEGACY_USERDB_ERROR_TEXT_SIZE 160U

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
    LEGACY_USERDB_CHANGED_DURING_SCAN
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

typedef struct legacy_userdb_error {
    legacy_userdb_status_t status;
    int system_errno;
    size_t record_number;
    char text[LEGACY_USERDB_ERROR_TEXT_SIZE];
} legacy_userdb_error_t;

void legacy_userdb_policy_defaults(legacy_userdb_policy_t *policy);
void legacy_userdb_error_clear(legacy_userdb_error_t *error);
const char *legacy_userdb_status_name(legacy_userdb_status_t status);

bool legacy_userdb_legacy_name_is_valid(const char *legacy_name);
bool legacy_userdb_display_name_is_compatible(const char *display_name);

int legacy_userdb_inspect(const char *mbse_root,
                          const legacy_userdb_policy_t *policy,
                          const legacy_userdb_query_t *query,
                          legacy_userdb_scan_result_t *result,
                          legacy_userdb_error_t *error);

#endif /* FORTYTWO_LEGACY_USERDB_H */
