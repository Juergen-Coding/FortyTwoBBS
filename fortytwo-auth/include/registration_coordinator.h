/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * One-shot coordinator for FTAP registration and local MBSE provisioning.
 */

#ifndef FORTYTWO_REGISTRATION_COORDINATOR_H
#define FORTYTWO_REGISTRATION_COORDINATOR_H

#include "ftap_client.h"
#include "legacy_userdb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FORTYTWO_REGISTRATION_ERROR_TEXT_SIZE 192U

typedef enum fortytwo_registration_status {
    FORTYTWO_REGISTRATION_OK = 0,
    FORTYTWO_REGISTRATION_INVALID_ARGUMENT,
    FORTYTWO_REGISTRATION_BEGIN_FAILED,
    FORTYTWO_REGISTRATION_LEGACY_PREPARE_FAILED,
    FORTYTWO_REGISTRATION_LEGACY_ROLLBACK_FAILED,
    FORTYTWO_REGISTRATION_ABORT_FAILED,
    FORTYTWO_REGISTRATION_COMMIT_GUARD_FAILED,
    FORTYTWO_REGISTRATION_COMMIT_FAILED,
    FORTYTWO_REGISTRATION_COMMIT_OUTCOME_UNKNOWN
} fortytwo_registration_status_t;

typedef struct fortytwo_registration_request {
    ftap_client_t *client;
    const char *mbse_root;
    const char *bbs_users_directory;
    const char *login_name;
    const char *display_name;
    const uint8_t *password;
    size_t password_length;
    const ftap_registration_metadata_t *metadata;
    int64_t registered_at;
    const legacy_userdb_record_defaults_t *legacy_defaults;
    const legacy_userdb_provision_policy_t *legacy_policy;
} fortytwo_registration_request_t;

typedef struct fortytwo_registration_result {
    bool committed;
    bool marker_pending;
    bool repair_required;
    bool commit_outcome_unknown;
    ftap_registration_context_t registration;
    ftap_terminal_context_t terminal;
    legacy_userdb_prepared_registration_t legacy;
    legacy_userdb_error_t finalize_error;
} fortytwo_registration_result_t;

typedef struct fortytwo_registration_error {
    fortytwo_registration_status_t status;
    bool repair_required;
    bool outcome_unknown;
    bool abort_outcome_unknown;
    ftap_client_error_t ftap;
    legacy_userdb_error_t legacy;
    legacy_userdb_error_t rollback;
    char text[FORTYTWO_REGISTRATION_ERROR_TEXT_SIZE];
} fortytwo_registration_error_t;

void fortytwo_registration_result_clear(
    fortytwo_registration_result_t *result);
void fortytwo_registration_error_clear(
    fortytwo_registration_error_t *error);
const char *fortytwo_registration_status_name(
    fortytwo_registration_status_t status);

/*
 * Coordinate Begin -> local prepare -> Commit.  A confirmed Commit remains a
 * success even if the non-destructive marker finalization needs reconciliation.
 */
int fortytwo_registration_coordinate(
    const fortytwo_registration_request_t *request,
    fortytwo_registration_result_t *result,
    fortytwo_registration_error_t *error);

#endif /* FORTYTWO_REGISTRATION_COORDINATOR_H */
