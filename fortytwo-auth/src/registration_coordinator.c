/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * FTAP and local legacy registration coordinator.
 */

#include "registration_coordinator.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void
set_error(fortytwo_registration_error_t *error,
          fortytwo_registration_status_t status,
          const char *text)
{
    if (error == NULL) {
        return;
    }
    error->status = status;
    if (text != NULL) {
        (void)snprintf(error->text, sizeof(error->text), "%s", text);
    }
}

void
fortytwo_registration_result_clear(fortytwo_registration_result_t *result)
{
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        legacy_userdb_prepared_registration_clear(&result->legacy);
        legacy_userdb_error_clear(&result->finalize_error);
    }
}

void
fortytwo_registration_error_clear(fortytwo_registration_error_t *error)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->status = FORTYTWO_REGISTRATION_OK;
        ftap_client_error_clear(&error->ftap);
        legacy_userdb_error_clear(&error->legacy);
        legacy_userdb_error_clear(&error->rollback);
    }
}

const char *
fortytwo_registration_status_name(fortytwo_registration_status_t status)
{
    switch (status) {
    case FORTYTWO_REGISTRATION_OK:
        return "ok";
    case FORTYTWO_REGISTRATION_INVALID_ARGUMENT:
        return "invalid_argument";
    case FORTYTWO_REGISTRATION_BEGIN_FAILED:
        return "begin_failed";
    case FORTYTWO_REGISTRATION_LEGACY_PREPARE_FAILED:
        return "legacy_prepare_failed";
    case FORTYTWO_REGISTRATION_LEGACY_ROLLBACK_FAILED:
        return "legacy_rollback_failed";
    case FORTYTWO_REGISTRATION_ABORT_FAILED:
        return "abort_failed";
    case FORTYTWO_REGISTRATION_COMMIT_GUARD_FAILED:
        return "commit_guard_failed";
    case FORTYTWO_REGISTRATION_COMMIT_FAILED:
        return "commit_failed";
    case FORTYTWO_REGISTRATION_COMMIT_OUTCOME_UNKNOWN:
        return "commit_outcome_unknown";
    default:
        return "unknown";
    }
}

static bool
request_is_valid(const fortytwo_registration_request_t *request,
                 const fortytwo_registration_result_t *result)
{
    return request != NULL && result != NULL && request->client != NULL &&
           request->client->state == FTAP_STATE_HELLO_COMPLETE &&
           request->mbse_root != NULL && request->mbse_root[0] == '/' &&
           request->bbs_users_directory != NULL &&
           request->bbs_users_directory[0] == '/' &&
           request->login_name != NULL && request->display_name != NULL &&
           request->password != NULL && request->password_length > 0U &&
           request->metadata != NULL && request->registered_at > 0 &&
           request->legacy_defaults != NULL &&
           request->legacy_policy != NULL;
}

static void
copy_prepared_result(fortytwo_registration_result_t *result,
                     const legacy_userdb_prepared_registration_t *prepared)
{
    if (prepared->prepared) {
        result->legacy = *prepared;
        result->marker_pending = true;
        result->repair_required = true;
    }
}

static int
abort_after_local_failure(
    const fortytwo_registration_request_t *request,
    const ftap_registration_context_t *registration,
    legacy_userdb_prepared_registration_t *prepared,
    const legacy_userdb_error_t *primary_legacy_error,
    fortytwo_registration_status_t primary_status,
    fortytwo_registration_result_t *result,
    fortytwo_registration_error_t *error)
{
    legacy_userdb_error_t rollback_error;
    ftap_client_error_t abort_error;
    bool rollback_failed = false;
    bool abort_failed;

    legacy_userdb_error_clear(&rollback_error);
    ftap_client_error_clear(&abort_error);
    if (primary_legacy_error != NULL && error != NULL) {
        error->legacy = *primary_legacy_error;
    }

    if (prepared->prepared &&
        legacy_userdb_rollback_precommit(
            request->mbse_root, request->bbs_users_directory,
            request->legacy_policy, prepared, &rollback_error) != 0) {
        rollback_failed = true;
        if (error != NULL) {
            error->rollback = rollback_error;
            error->repair_required = true;
        }
        copy_prepared_result(result, prepared);
    }

    abort_failed = ftap_client_registration_abort(
        request->client, registration,
        FTAP_REGISTRATION_REASON_LEGACY_WRITE_FAILED,
        &abort_error) != 0;
    if (abort_failed && error != NULL) {
        error->ftap = abort_error;
        error->outcome_unknown = abort_error.outcome_unknown;
        error->abort_outcome_unknown = abort_error.outcome_unknown;
    }

    if (rollback_failed) {
        set_error(error, FORTYTWO_REGISTRATION_LEGACY_ROLLBACK_FAILED,
                  "local registration cleanup failed; reconciliation required");
    } else if (abort_failed) {
        set_error(error, FORTYTWO_REGISTRATION_ABORT_FAILED,
                  "FTAP registration abort was not confirmed");
    } else {
        set_error(error, primary_status,
                  "local legacy registration could not be prepared");
    }
    return -1;
}

int
fortytwo_registration_coordinate(
    const fortytwo_registration_request_t *request,
    fortytwo_registration_result_t *result,
    fortytwo_registration_error_t *error)
{
    ftap_registration_context_t registration;
    ftap_terminal_context_t terminal;
    ftap_client_error_t ftap_error;
    legacy_userdb_registration_t legacy_registration;
    legacy_userdb_prepared_registration_t prepared;
    legacy_userdb_error_t legacy_error;

    fortytwo_registration_result_clear(result);
    fortytwo_registration_error_clear(error);
    memset(&registration, 0, sizeof(registration));
    memset(&terminal, 0, sizeof(terminal));
    memset(&legacy_registration, 0, sizeof(legacy_registration));
    legacy_userdb_prepared_registration_clear(&prepared);
    legacy_userdb_error_clear(&legacy_error);
    ftap_client_error_clear(&ftap_error);

    if (!request_is_valid(request, result)) {
        set_error(error, FORTYTWO_REGISTRATION_INVALID_ARGUMENT,
                  "invalid registration coordinator request");
        if (error != NULL) {
            error->ftap.status = FTAP_STATUS_ERR_ARGUMENT;
            error->ftap.system_errno = EINVAL;
        }
        return -1;
    }

    if (ftap_client_registration_begin(
            request->client, request->login_name, request->display_name,
            request->password, request->password_length, request->metadata,
            &registration, &ftap_error) != 0) {
        if (error != NULL) {
            error->ftap = ftap_error;
            error->outcome_unknown = ftap_error.outcome_unknown;
        }
        set_error(error, FORTYTWO_REGISTRATION_BEGIN_FAILED,
                  "FTAP registration begin failed");
        return -1;
    }
    result->registration = registration;

    memcpy(legacy_registration.registration_id,
           registration.registration_id,
           sizeof(legacy_registration.registration_id));
    memcpy(legacy_registration.user_id, registration.user_id,
           sizeof(legacy_registration.user_id));
    legacy_registration.legacy_name = registration.legacy_name;
    legacy_registration.display_name = registration.display_name;
    legacy_registration.registered_at = request->registered_at;
    legacy_registration.defaults = *request->legacy_defaults;

    if (legacy_userdb_prepare_registration(
            request->mbse_root, request->bbs_users_directory,
            request->legacy_policy, &legacy_registration, &prepared,
            &legacy_error) != 0) {
        return abort_after_local_failure(
            request, &registration, &prepared, &legacy_error,
            FORTYTWO_REGISTRATION_LEGACY_PREPARE_FAILED,
            result, error);
    }

    if (legacy_userdb_mark_commit_started(&prepared, &legacy_error) != 0) {
        return abort_after_local_failure(
            request, &registration, &prepared, &legacy_error,
            FORTYTWO_REGISTRATION_COMMIT_GUARD_FAILED,
            result, error);
    }

    if (ftap_client_registration_commit(
            request->client, &registration, &terminal, &ftap_error) != 0) {
        copy_prepared_result(result, &prepared);
        result->commit_outcome_unknown = ftap_error.outcome_unknown;
        if (error != NULL) {
            error->ftap = ftap_error;
            error->repair_required = true;
            error->outcome_unknown = ftap_error.outcome_unknown;
        }
        set_error(error,
                  ftap_error.outcome_unknown
                      ? FORTYTWO_REGISTRATION_COMMIT_OUTCOME_UNKNOWN
                      : FORTYTWO_REGISTRATION_COMMIT_FAILED,
                  ftap_error.outcome_unknown
                      ? "FTAP commit outcome is unknown; local data retained"
                      : "FTAP commit failed; local data retained for reconciliation");
        return -1;
    }

    result->committed = true;
    result->terminal = terminal;
    if (legacy_userdb_finalize_committed(
            request->mbse_root, request->bbs_users_directory,
            request->legacy_policy, &prepared, &legacy_error) != 0) {
        result->legacy = prepared;
        result->marker_pending = true;
        result->repair_required = true;
        result->finalize_error = legacy_error;
    }

    fortytwo_registration_error_clear(error);
    return 0;
}
