/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Real PostgreSQL integration test for the durable registration lifecycle.
 * The companion shell script owns fixture creation, verification, and cleanup.
 */

#include "authd_config.h"
#include "authd_database.h"
#include "authd_database_validation.h"
#include "authd_registration_limit.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char password_hash[] =
    "$argon2id$v=19$m=262144,t=3,p=1$"
    "fkgpSimfYvKpqEKw0geS4Q$"
    "JQR4U/Z9oepG9cd7Ta9Xoacb8PfGW2BnMYi8RZz6qZw";

static void
require_registration_result(authd_database_registration_result_t actual,
                            authd_database_registration_result_t expected,
                            const char *operation,
                            const char *error)
{
    if (actual == expected) {
        return;
    }
    (void)fprintf(stderr, "%s returned %s instead of %s: %s\n",
                  operation,
                  authd_database_registration_result_name(actual),
                  authd_database_registration_result_name(expected),
                  error != NULL && error[0] != '\0' ? error : "no detail");
    assert(actual == expected);
}

static void
begin_registration(authd_database_t *database,
                   const char *login_name,
                   const char *display_name,
                   const char *legacy_name,
                   const char *source_ip,
                   const char *tty_device,
                   const char *node_id,
                   size_t max_pending,
                   authd_registration_begin_result_t *registration)
{
    char error[AUTHD_DATABASE_ERROR_MAX];
    authd_database_registration_result_t result;

    result = authd_database_begin_registration(
        database, login_name, display_name, password_hash, legacy_name,
        source_ip, tty_device, node_id,
        AUTHD_REGISTRATION_DEFAULT_TIMEOUT_SECONDS, max_pending,
        registration, error, sizeof(error));
    require_registration_result(result, AUTHD_DATABASE_REGISTRATION_OK,
                                "begin registration", error);
    assert(registration->auth_epoch == UINT64_C(1));
    assert(registration->authz_revision == UINT64_C(1));
    assert(strcmp(registration->login_name, login_name) == 0);
    assert(strcmp(registration->display_name, display_name) == 0);
    assert(strcmp(registration->legacy_name, legacy_name) == 0);
}

static void
abort_registration(authd_database_t *database,
                   const authd_registration_begin_result_t *registration,
                   const char *reason)
{
    char error[AUTHD_DATABASE_ERROR_MAX];
    authd_database_registration_result_t result;

    result = authd_database_abort_registration(
        database, registration->registration_id, registration->user_id,
        reason, error, sizeof(error));
    require_registration_result(result, AUTHD_DATABASE_REGISTRATION_OK,
                                "abort registration", error);
}

int
main(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    authd_registration_begin_result_t commit_registration;
    authd_registration_begin_result_t abort_registration_one;
    authd_registration_begin_result_t abort_registration_two;
    authd_registration_begin_result_t limit_registration;
    authd_registration_begin_result_t rejected_registration;
    authd_registration_commit_result_t commit;
    authd_database_registration_result_t registration_result;
    authd_database_write_result_t write_result;
    size_t expired_count = 0U;
    char error[AUTHD_DATABASE_ERROR_MAX];

    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);
    assert(database != NULL);
    assert(info.highest_migration ==
           AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION);

    /* The administrative fixture is already expired and must be retired. */
    registration_result = authd_database_expire_registrations(
        database, 16U, &expired_count, error, sizeof(error));
    require_registration_result(registration_result,
                                AUTHD_DATABASE_REGISTRATION_OK,
                                "expire registrations", error);
    assert(expired_count == 1U);

    /* A completed registration activates Telnet only and opens one session. */
    begin_registration(database,
                       "b432_dbapi_commit_test",
                       "B4.3.2 DB API Commit Test",
                       "b43com",
                       "192.0.2.210",
                       "/dev/pts/210",
                       "b432-dbapi-commit",
                       AUTHD_REGISTRATION_DEFAULT_MAX_PENDING,
                       &commit_registration);

    registration_result = authd_database_commit_registration(
        database, &commit_registration, "192.0.2.210", "/dev/pts/210",
        "b432-dbapi-commit", &commit, error, sizeof(error));
    require_registration_result(registration_result,
                                AUTHD_DATABASE_REGISTRATION_OK,
                                "commit registration", error);
    assert(memcmp(commit.registration_id,
                  commit_registration.registration_id,
                  FTAP_UUID_SIZE) == 0);
    assert(memcmp(commit.session.user_id, commit_registration.user_id,
                  FTAP_UUID_SIZE) == 0);
    assert(commit.session.auth_epoch == UINT64_C(1));
    assert(commit.session.authz_revision == UINT64_C(2));
    assert(strcmp(commit.login_name, "b432_dbapi_commit_test") == 0);
    assert(strcmp(commit.legacy_name, "b43com") == 0);

    /* The active canonical login name cannot be registered a second time. */
    memset(&rejected_registration, 0, sizeof(rejected_registration));
    registration_result = authd_database_begin_registration(
        database, "b432_dbapi_commit_test", "Duplicate Login Test",
        password_hash, "b43dup", "192.0.2.210", "/dev/pts/210",
        "b432-dbapi-duplicate", AUTHD_REGISTRATION_DEFAULT_TIMEOUT_SECONDS,
        AUTHD_REGISTRATION_DEFAULT_MAX_PENDING, &rejected_registration,
        error, sizeof(error));
    require_registration_result(
        registration_result, AUTHD_DATABASE_REGISTRATION_NAME_UNAVAILABLE,
        "duplicate login registration", error);
    assert(rejected_registration.auth_epoch == 0U);

    /* Abort removes the reservation so both login and legacy key are reusable. */
    begin_registration(database,
                       "b432_dbapi_abort_test",
                       "B4.3.2 DB API Abort Test One",
                       "b43abt",
                       "192.0.2.211",
                       "/dev/pts/211",
                       "b432-dbapi-abort-one",
                       AUTHD_REGISTRATION_DEFAULT_MAX_PENDING,
                       &abort_registration_one);
    abort_registration(database, &abort_registration_one,
                       "legacy_write_failed");

    begin_registration(database,
                       "b432_dbapi_abort_test",
                       "B4.3.2 DB API Abort Test Two",
                       "b43abt",
                       "192.0.2.211",
                       "/dev/pts/211",
                       "b432-dbapi-abort-two",
                       AUTHD_REGISTRATION_DEFAULT_MAX_PENDING,
                       &abort_registration_two);
    assert(memcmp(abort_registration_one.user_id,
                  abort_registration_two.user_id,
                  FTAP_UUID_SIZE) != 0);
    abort_registration(database, &abort_registration_two,
                       "client_cancelled");

    /* The advisory-lock protected global pending limit rejects client B. */
    begin_registration(database,
                       "b432_dbapi_limit_a",
                       "B4.3.2 DB API Limit Test A",
                       "b43lma",
                       "192.0.2.212",
                       "/dev/pts/212",
                       "b432-dbapi-limit-a",
                       1U,
                       &limit_registration);

    memset(&rejected_registration, 0, sizeof(rejected_registration));
    registration_result = authd_database_begin_registration(
        database, "b432_dbapi_limit_b", "B4.3.2 DB API Limit Test B",
        password_hash, "b43lmb", "192.0.2.213", "/dev/pts/213",
        "b432-dbapi-limit-b", AUTHD_REGISTRATION_DEFAULT_TIMEOUT_SECONDS,
        1U, &rejected_registration, error, sizeof(error));
    require_registration_result(
        registration_result, AUTHD_DATABASE_REGISTRATION_LIMIT_REACHED,
        "pending limit registration", error);
    assert(rejected_registration.auth_epoch == 0U);
    abort_registration(database, &limit_registration, "integration_complete");

    /* Close the session so verification can also inspect lifecycle auditing. */
    write_result = authd_database_close_terminal_session(
        database, commit.session.session_id, "integration_test_complete",
        error, sizeof(error));
    if (write_result != AUTHD_DATABASE_WRITE_OK) {
        (void)fprintf(stderr, "registration session close failed: %s: %s\n",
                      authd_database_write_result_name(write_result),
                      error[0] != '\0' ? error : "no detail");
        assert(write_result == AUTHD_DATABASE_WRITE_OK);
    }

    authd_database_close(database);
    (void)puts("authd real PostgreSQL registration lifecycle test: OK");
    return 0;
}
