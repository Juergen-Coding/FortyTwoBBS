/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Strict read-only parser for FortyTwo legacy registration markers.
 */

#ifndef FORTYTWO_LEGACY_REGISTRATION_MARKER_H
#define FORTYTWO_LEGACY_REGISTRATION_MARKER_H

#include "legacy_userdb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LEGACY_REGISTRATION_MARKER_FORMAT_VERSION 1U
#define LEGACY_REGISTRATION_MARKER_MAX_SIZE 320U
#define LEGACY_REGISTRATION_MARKER_MODE ((mode_t)0600)
#define LEGACY_REGISTRATION_MARKER_DIRECTORY_MODE ((mode_t)0770)
#define LEGACY_REGISTRATION_MARKER_ERROR_TEXT_SIZE 160U

typedef enum legacy_registration_marker_state {
    LEGACY_REGISTRATION_MARKER_STATE_INVALID = 0,
    LEGACY_REGISTRATION_MARKER_PREPARED,
    LEGACY_REGISTRATION_MARKER_COMMITTED
} legacy_registration_marker_state_t;

typedef enum legacy_registration_marker_status {
    LEGACY_REGISTRATION_MARKER_OK = 0,
    LEGACY_REGISTRATION_MARKER_INVALID_ARGUMENT,
    LEGACY_REGISTRATION_MARKER_OPEN_BASE_FAILED,
    LEGACY_REGISTRATION_MARKER_BASE_POLICY_MISMATCH,
    LEGACY_REGISTRATION_MARKER_OPEN_USER_DIRECTORY_FAILED,
    LEGACY_REGISTRATION_MARKER_USER_DIRECTORY_POLICY_MISMATCH,
    LEGACY_REGISTRATION_MARKER_OPEN_FILE_FAILED,
    LEGACY_REGISTRATION_MARKER_STAT_FAILED,
    LEGACY_REGISTRATION_MARKER_NOT_REGULAR,
    LEGACY_REGISTRATION_MARKER_OWNER_MISMATCH,
    LEGACY_REGISTRATION_MARKER_GROUP_MISMATCH,
    LEGACY_REGISTRATION_MARKER_MODE_MISMATCH,
    LEGACY_REGISTRATION_MARKER_LINK_COUNT_MISMATCH,
    LEGACY_REGISTRATION_MARKER_SIZE_INVALID,
    LEGACY_REGISTRATION_MARKER_READ_FAILED,
    LEGACY_REGISTRATION_MARKER_CHANGED_DURING_READ,
    LEGACY_REGISTRATION_MARKER_INVALID_FORMAT,
    LEGACY_REGISTRATION_MARKER_UNKNOWN_KEY,
    LEGACY_REGISTRATION_MARKER_DUPLICATE_KEY,
    LEGACY_REGISTRATION_MARKER_MISSING_KEY,
    LEGACY_REGISTRATION_MARKER_INVALID_UUID,
    LEGACY_REGISTRATION_MARKER_INVALID_LEGACY_NAME,
    LEGACY_REGISTRATION_MARKER_LEGACY_NAME_MISMATCH,
    LEGACY_REGISTRATION_MARKER_INVALID_RECORD_NUMBER,
    LEGACY_REGISTRATION_MARKER_INVALID_STATE
} legacy_registration_marker_status_t;

typedef struct legacy_registration_marker_policy {
    legacy_userdb_directory_policy_t base_directory;
    legacy_userdb_directory_policy_t user_directory;
    bool check_marker_owner;
    uid_t expected_marker_uid;
    bool check_marker_group;
    gid_t expected_marker_gid;
    bool check_marker_mode;
    mode_t expected_marker_mode;
    bool require_single_link;
    size_t max_size;
} legacy_registration_marker_policy_t;

typedef struct legacy_registration_marker {
    unsigned int format_version;
    uint8_t registration_id[LEGACY_USERDB_UUID_SIZE];
    uint8_t user_id[LEGACY_USERDB_UUID_SIZE];
    char legacy_name[LEGACY_USERDB_LEGACY_NAME_MAX + 1U];
    size_t record_number;
    legacy_registration_marker_state_t state;
    struct stat base_directory_status;
    struct stat user_directory_status;
    struct stat file_status;
} legacy_registration_marker_t;

typedef struct legacy_registration_marker_error {
    legacy_registration_marker_status_t status;
    int system_errno;
    char text[LEGACY_REGISTRATION_MARKER_ERROR_TEXT_SIZE];
} legacy_registration_marker_error_t;

void legacy_registration_marker_policy_defaults(
    legacy_registration_marker_policy_t *policy);
void legacy_registration_marker_clear(
    legacy_registration_marker_t *marker);
void legacy_registration_marker_error_clear(
    legacy_registration_marker_error_t *error);
const char *legacy_registration_marker_status_name(
    legacy_registration_marker_status_t status);
const char *legacy_registration_marker_state_name(
    legacy_registration_marker_state_t state);

int legacy_registration_marker_read(
    const char *bbs_users_directory,
    const char *legacy_name,
    const legacy_registration_marker_policy_t *policy,
    legacy_registration_marker_t *marker,
    legacy_registration_marker_error_t *error);

#ifdef LEGACY_REGISTRATION_MARKER_TESTING
typedef enum legacy_registration_marker_test_fault {
    LEGACY_REGISTRATION_MARKER_TEST_FAULT_NONE = 0,
    LEGACY_REGISTRATION_MARKER_TEST_FAULT_CHANGE_AFTER_READ
} legacy_registration_marker_test_fault_t;

void legacy_registration_marker_test_set_fault(
    legacy_registration_marker_test_fault_t fault);
#endif

#endif /* FORTYTWO_LEGACY_REGISTRATION_MARKER_H */
