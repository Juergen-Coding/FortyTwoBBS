/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "registration_coordinator.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef enum test_scenario {
    TEST_SUCCESS = 0,
    TEST_BEGIN_FAIL,
    TEST_PREPARE_FAIL_CLEAN,
    TEST_PREPARE_FAIL_DIRTY,
    TEST_PREPARE_FAIL_ROLLBACK_FAIL,
    TEST_PREPARE_FAIL_ABORT_KNOWN,
    TEST_PREPARE_FAIL_ABORT_UNKNOWN,
    TEST_GUARD_FAIL,
    TEST_COMMIT_FAIL_KNOWN,
    TEST_COMMIT_FAIL_UNKNOWN,
    TEST_FINALIZE_FAIL
} test_scenario_t;

typedef struct call_counts {
    unsigned int begin;
    unsigned int prepare;
    unsigned int rollback;
    unsigned int abort;
    unsigned int guard;
    unsigned int commit;
    unsigned int finalize;
} call_counts_t;

static test_scenario_t scenario;
static call_counts_t calls;
static bool legacy_snapshot_checked;

static const uint8_t expected_registration_id[FTAP_UUID_SIZE] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t expected_user_id[FTAP_UUID_SIZE] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

void
ftap_client_error_clear(ftap_client_error_t *error)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->status = FTAP_STATUS_OK;
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
legacy_userdb_prepared_registration_clear(
    legacy_userdb_prepared_registration_t *prepared)
{
    if (prepared != NULL) {
        memset(prepared, 0, sizeof(*prepared));
        prepared->record_number = LEGACY_USERDB_NO_RECORD;
        prepared->original_size = (off_t)-1;
    }
}

int
ftap_client_registration_begin(
    ftap_client_t *client,
    const char *login_name,
    const char *display_name,
    const uint8_t *password,
    size_t password_length,
    const ftap_registration_metadata_t *metadata,
    ftap_registration_context_t *result,
    ftap_client_error_t *error)
{
    ++calls.begin;
    assert(strcmp(login_name, "RequestedUser") == 0);
    assert(strcmp(display_name, "Requested Display") == 0);
    assert(password_length == 12U);
    assert(memcmp(password, "dummy secret", 12U) == 0);
    assert(strcmp(metadata->protocol, FTAP_PROTOCOL_TELNET) == 0);
    if (scenario == TEST_BEGIN_FAIL) {
        client->state = FTAP_STATE_CLOSING;
        ftap_client_error_clear(error);
        error->server_error = true;
        error->protocol_error = FTAP_ERR_LOGIN_NAME_UNAVAILABLE;
        return -1;
    }

    memset(result, 0, sizeof(*result));
    memcpy(result->registration_id, expected_registration_id,
           sizeof(result->registration_id));
    memcpy(result->user_id, expected_user_id, sizeof(result->user_id));
    (void)snprintf(result->login_name, sizeof(result->login_name),
                   "%s", "requesteduser");
    (void)snprintf(result->display_name, sizeof(result->display_name),
                   "%s", "Requested Display");
    (void)snprintf(result->legacy_name, sizeof(result->legacy_name),
                   "%s", "requser");
    client->state = FTAP_STATE_REGISTERING;
    ftap_client_error_clear(error);
    return 0;
}

int
legacy_userdb_prepare_registration(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    const legacy_userdb_registration_t *registration,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    ++calls.prepare;
    assert(strcmp(mbse_root, "/srv/fortytwo") == 0);
    assert(strcmp(bbs_users_directory, "/srv/fortytwo/home") == 0);
    assert(policy != NULL);
    assert(memcmp(registration->registration_id, expected_registration_id,
                  LEGACY_USERDB_UUID_SIZE) == 0);
    assert(memcmp(registration->user_id, expected_user_id,
                  LEGACY_USERDB_UUID_SIZE) == 0);
    assert(strcmp(registration->legacy_name, "requser") == 0);
    assert(strcmp(registration->display_name, "Requested Display") == 0);
    assert(registration->registered_at == INT64_C(1784180000));
    assert(registration->defaults.security_level == 20U);
    assert(strcmp(registration->defaults.protocol, "Zmodem") == 0);
    legacy_snapshot_checked = true;

    legacy_userdb_prepared_registration_clear(prepared);
    legacy_userdb_error_clear(error);
    if (scenario == TEST_PREPARE_FAIL_CLEAN ||
        scenario == TEST_PREPARE_FAIL_ABORT_KNOWN ||
        scenario == TEST_PREPARE_FAIL_ABORT_UNKNOWN) {
        error->status = LEGACY_USERDB_WRITE_FAILED;
        error->system_errno = EIO;
        return -1;
    }
    prepared->prepared = true;
    prepared->record_number = 7U;
    prepared->original_size = (off_t)4194;
    memcpy(prepared->registration_id, expected_registration_id,
           sizeof(prepared->registration_id));
    memcpy(prepared->user_id, expected_user_id,
           sizeof(prepared->user_id));
    (void)snprintf(prepared->legacy_name, sizeof(prepared->legacy_name),
                   "%s", "requser");
    (void)snprintf(prepared->display_name, sizeof(prepared->display_name),
                   "%s", "Requested Display");
    if (scenario == TEST_PREPARE_FAIL_DIRTY ||
        scenario == TEST_PREPARE_FAIL_ROLLBACK_FAIL) {
        error->status = LEGACY_USERDB_ROLLBACK_FAILED;
        error->system_errno = EIO;
        error->repair_required = true;
        return -1;
    }
    return 0;
}

int
legacy_userdb_rollback_precommit(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    (void)mbse_root;
    (void)bbs_users_directory;
    (void)policy;
    ++calls.rollback;
    assert(prepared->prepared);
    assert(!prepared->commit_started);
    legacy_userdb_error_clear(error);
    if (scenario == TEST_PREPARE_FAIL_ROLLBACK_FAIL) {
        error->status = LEGACY_USERDB_ROLLBACK_UNSAFE;
        error->system_errno = ESTALE;
        error->repair_required = true;
        return -1;
    }
    legacy_userdb_prepared_registration_clear(prepared);
    return 0;
}

int
ftap_client_registration_abort(
    ftap_client_t *client,
    const ftap_registration_context_t *registration,
    const char *reason,
    ftap_client_error_t *error)
{
    ++calls.abort;
    assert(memcmp(registration->registration_id, expected_registration_id,
                  FTAP_UUID_SIZE) == 0);
    assert(strcmp(reason, FTAP_REGISTRATION_REASON_LEGACY_WRITE_FAILED) == 0);
    ftap_client_error_clear(error);
    if (scenario == TEST_PREPARE_FAIL_ABORT_KNOWN ||
        scenario == TEST_PREPARE_FAIL_ABORT_UNKNOWN) {
        client->state = FTAP_STATE_CLOSING;
        if (scenario == TEST_PREPARE_FAIL_ABORT_KNOWN) {
            error->server_error = true;
            error->protocol_error = FTAP_ERR_INVALID_STATE;
        } else {
            error->status = FTAP_STATUS_ERR_TRUNCATED;
            error->system_errno = ECONNRESET;
            error->outcome_unknown = true;
        }
        return -1;
    }
    client->state = FTAP_STATE_HELLO_COMPLETE;
    return 0;
}

int
legacy_userdb_mark_commit_started(
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    ++calls.guard;
    assert(prepared->prepared);
    legacy_userdb_error_clear(error);
    if (scenario == TEST_GUARD_FAIL) {
        error->status = LEGACY_USERDB_CONTEXT_INVALID;
        error->repair_required = true;
        return -1;
    }
    prepared->commit_started = true;
    return 0;
}

int
ftap_client_registration_commit(
    ftap_client_t *client,
    const ftap_registration_context_t *registration,
    ftap_terminal_context_t *result,
    ftap_client_error_t *error)
{
    ++calls.commit;
    assert(memcmp(registration->registration_id, expected_registration_id,
                  FTAP_UUID_SIZE) == 0);
    ftap_client_error_clear(error);
    if (scenario == TEST_COMMIT_FAIL_KNOWN ||
        scenario == TEST_COMMIT_FAIL_UNKNOWN) {
        client->state = FTAP_STATE_CLOSING;
        error->server_error = scenario == TEST_COMMIT_FAIL_KNOWN;
        error->protocol_error = scenario == TEST_COMMIT_FAIL_KNOWN
                                    ? FTAP_ERR_ACCOUNT_UNAVAILABLE : 0U;
        error->outcome_unknown = scenario == TEST_COMMIT_FAIL_UNKNOWN;
        return -1;
    }
    memset(result, 0, sizeof(*result));
    memcpy(result->user_id, expected_user_id, sizeof(result->user_id));
    result->session_id[0] = UINT8_C(0x42);
    (void)snprintf(result->login_name, sizeof(result->login_name),
                   "%s", "requesteduser");
    (void)snprintf(result->legacy_name, sizeof(result->legacy_name),
                   "%s", "requser");
    client->state = FTAP_STATE_SESSION_BOUND;
    return 0;
}

int
legacy_userdb_finalize_committed(
    const char *mbse_root,
    const char *bbs_users_directory,
    const legacy_userdb_provision_policy_t *policy,
    legacy_userdb_prepared_registration_t *prepared,
    legacy_userdb_error_t *error)
{
    (void)mbse_root;
    (void)bbs_users_directory;
    (void)policy;
    ++calls.finalize;
    assert(prepared->prepared && prepared->commit_started);
    legacy_userdb_error_clear(error);
    if (scenario == TEST_FINALIZE_FAIL) {
        error->status = LEGACY_USERDB_FINALIZE_FAILED;
        error->system_errno = EIO;
        error->repair_required = true;
        return -1;
    }
    legacy_userdb_prepared_registration_clear(prepared);
    return 0;
}

static fortytwo_registration_request_t
default_request(ftap_client_t *client,
                legacy_userdb_record_defaults_t *defaults,
                legacy_userdb_provision_policy_t *policy)
{
    static const uint8_t password[] = "dummy secret";
    static const ftap_registration_metadata_t metadata = {
        FTAP_PROTOCOL_TELNET, "192.0.2.44", "/dev/pts/44", "test-node"
    };
    fortytwo_registration_request_t request;

    memset(&request, 0, sizeof(request));
    memset(defaults, 0, sizeof(*defaults));
    memset(policy, 0, sizeof(*policy));
    defaults->security_level = 20U;
    defaults->language = (int32_t)'D';
    defaults->message_editor = LEGACY_USERDB_EDITOR_FULLSCREEN;
    defaults->protocol = "Zmodem";
    request.client = client;
    request.mbse_root = "/srv/fortytwo";
    request.bbs_users_directory = "/srv/fortytwo/home";
    request.login_name = "RequestedUser";
    request.display_name = "Requested Display";
    request.password = password;
    request.password_length = sizeof(password) - 1U;
    request.metadata = &metadata;
    request.registered_at = INT64_C(1784180000);
    request.legacy_defaults = defaults;
    request.legacy_policy = policy;
    return request;
}

static void
reset_scenario(test_scenario_t selected, ftap_client_t *client)
{
    scenario = selected;
    memset(&calls, 0, sizeof(calls));
    legacy_snapshot_checked = false;
    memset(client, 0, sizeof(*client));
    client->fd = 8;
    client->state = FTAP_STATE_HELLO_COMPLETE;
}

static void
test_success(void)
{
    ftap_client_t client;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;

    reset_scenario(TEST_SUCCESS, &client);
    request = default_request(&client, &defaults, &policy);
    assert(fortytwo_registration_coordinate(&request, &result, &error) == 0);
    assert(result.committed);
    assert(!result.marker_pending && !result.repair_required);
    assert(result.terminal.session_id[0] == UINT8_C(0x42));
    assert(!result.legacy.prepared);
    assert(error.status == FORTYTWO_REGISTRATION_OK);
    assert(legacy_snapshot_checked);
    assert(calls.begin == 1U && calls.prepare == 1U && calls.guard == 1U);
    assert(calls.commit == 1U && calls.finalize == 1U);
    assert(calls.rollback == 0U && calls.abort == 0U);
}

static void
test_begin_failure(void)
{
    ftap_client_t client;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;

    reset_scenario(TEST_BEGIN_FAIL, &client);
    request = default_request(&client, &defaults, &policy);
    assert(fortytwo_registration_coordinate(&request, &result, &error) == -1);
    assert(error.status == FORTYTWO_REGISTRATION_BEGIN_FAILED);
    assert(error.ftap.server_error);
    assert(calls.begin == 1U && calls.prepare == 0U && calls.abort == 0U);
}

static void
test_prepare_failure_paths(void)
{
    static const struct {
        test_scenario_t scenario;
        fortytwo_registration_status_t status;
        unsigned int rollback_calls;
        bool marker_pending;
        bool outcome_unknown;
    } cases[] = {
        {TEST_PREPARE_FAIL_CLEAN,
         FORTYTWO_REGISTRATION_LEGACY_PREPARE_FAILED, 0U, false, false},
        {TEST_PREPARE_FAIL_DIRTY,
         FORTYTWO_REGISTRATION_LEGACY_PREPARE_FAILED, 1U, false, false},
        {TEST_PREPARE_FAIL_ROLLBACK_FAIL,
         FORTYTWO_REGISTRATION_LEGACY_ROLLBACK_FAILED, 1U, true, false},
        {TEST_PREPARE_FAIL_ABORT_KNOWN,
         FORTYTWO_REGISTRATION_ABORT_FAILED, 0U, false, false},
        {TEST_PREPARE_FAIL_ABORT_UNKNOWN,
         FORTYTWO_REGISTRATION_ABORT_FAILED, 0U, false, true}
    };
    size_t index;

    for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        ftap_client_t client;
        legacy_userdb_record_defaults_t defaults;
        legacy_userdb_provision_policy_t policy;
        fortytwo_registration_request_t request;
        fortytwo_registration_result_t result;
        fortytwo_registration_error_t error;

        reset_scenario(cases[index].scenario, &client);
        request = default_request(&client, &defaults, &policy);
        assert(fortytwo_registration_coordinate(
                   &request, &result, &error) == -1);
        assert(error.status == cases[index].status);
        assert(calls.prepare == 1U && calls.abort == 1U);
        assert(calls.rollback == cases[index].rollback_calls);
        assert(calls.guard == 0U && calls.commit == 0U);
        assert(result.marker_pending == cases[index].marker_pending);
        assert(error.outcome_unknown == cases[index].outcome_unknown);
    }
}

static void
test_guard_failure_rolls_back_and_aborts(void)
{
    ftap_client_t client;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;

    reset_scenario(TEST_GUARD_FAIL, &client);
    request = default_request(&client, &defaults, &policy);
    assert(fortytwo_registration_coordinate(&request, &result, &error) == -1);
    assert(error.status == FORTYTWO_REGISTRATION_COMMIT_GUARD_FAILED);
    assert(calls.guard == 1U && calls.rollback == 1U && calls.abort == 1U);
    assert(calls.commit == 0U);
    assert(!result.marker_pending);
}

static void
test_commit_failures_never_roll_back(void)
{
    static const struct {
        test_scenario_t scenario;
        fortytwo_registration_status_t status;
        bool unknown;
    } cases[] = {
        {TEST_COMMIT_FAIL_KNOWN, FORTYTWO_REGISTRATION_COMMIT_FAILED, false},
        {TEST_COMMIT_FAIL_UNKNOWN,
         FORTYTWO_REGISTRATION_COMMIT_OUTCOME_UNKNOWN, true}
    };
    size_t index;

    for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        ftap_client_t client;
        legacy_userdb_record_defaults_t defaults;
        legacy_userdb_provision_policy_t policy;
        fortytwo_registration_request_t request;
        fortytwo_registration_result_t result;
        fortytwo_registration_error_t error;

        reset_scenario(cases[index].scenario, &client);
        request = default_request(&client, &defaults, &policy);
        assert(fortytwo_registration_coordinate(
                   &request, &result, &error) == -1);
        assert(error.status == cases[index].status);
        assert(error.outcome_unknown == cases[index].unknown);
        assert(result.commit_outcome_unknown == cases[index].unknown);
        assert(result.marker_pending && result.repair_required);
        assert(result.legacy.prepared && result.legacy.commit_started);
        assert(calls.commit == 1U && calls.rollback == 0U && calls.abort == 0U);
        assert(calls.finalize == 0U);
    }
}

static void
test_finalize_failure_is_success_with_reconciliation_marker(void)
{
    ftap_client_t client;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;

    reset_scenario(TEST_FINALIZE_FAIL, &client);
    request = default_request(&client, &defaults, &policy);
    assert(fortytwo_registration_coordinate(&request, &result, &error) == 0);
    assert(result.committed);
    assert(result.marker_pending && result.repair_required);
    assert(result.legacy.prepared && result.legacy.commit_started);
    assert(result.finalize_error.status == LEGACY_USERDB_FINALIZE_FAILED);
    assert(error.status == FORTYTWO_REGISTRATION_OK);
    assert(calls.commit == 1U && calls.finalize == 1U);
    assert(calls.rollback == 0U && calls.abort == 0U);
}

static void
test_invalid_request_and_status_names(void)
{
    ftap_client_t client;
    legacy_userdb_record_defaults_t defaults;
    legacy_userdb_provision_policy_t policy;
    fortytwo_registration_request_t request;
    fortytwo_registration_result_t result;
    fortytwo_registration_error_t error;
    fortytwo_registration_status_t status;

    reset_scenario(TEST_SUCCESS, &client);
    request = default_request(&client, &defaults, &policy);
    request.password_length = 0U;
    assert(fortytwo_registration_coordinate(&request, &result, &error) == -1);
    assert(error.status == FORTYTWO_REGISTRATION_INVALID_ARGUMENT);
    assert(calls.begin == 0U);

    for (status = FORTYTWO_REGISTRATION_OK;
         status <= FORTYTWO_REGISTRATION_COMMIT_OUTCOME_UNKNOWN;
         status = (fortytwo_registration_status_t)((int)status + 1)) {
        assert(strcmp(fortytwo_registration_status_name(status),
                      "unknown") != 0);
    }
}

int
main(void)
{
    test_success();
    test_begin_failure();
    test_prepare_failure_paths();
    test_guard_failure_rolls_back_and_aborts();
    test_commit_failures_never_roll_back();
    test_finalize_failure_is_success_with_reconciliation_marker();
    test_invalid_request_and_status_names();
    (void)printf("registration coordinator tests: OK\n");
    return 0;
}
