/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Real PostgreSQL integration test for atomic successful-login persistence.
 * The companion shell script owns fixture creation, verification, and cleanup.
 */

#include "authd_config.h"
#include "authd_database.h"
#include "authd_database_validation.h"
#include "authd_identity.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t expected_user_id[FTAP_UUID_SIZE] = {
    0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x45, 0x55,
    0x86, 0x66, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77
};

int
main(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    authd_login_record_t record;
    authd_terminal_session_result_t session;
    authd_terminal_session_result_t created_session;
    char canonical[AUTHD_LOGIN_NAME_BUFFER_SIZE];
    char error[AUTHD_DATABASE_ERROR_MAX];

    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);
    assert(database != NULL);
    assert(info.highest_migration ==
           AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION);

    assert(authd_login_name_canonicalize(
        "B3_Session_Test_3333",
        strlen("B3_Session_Test_3333"),
        canonical));
    assert(strcmp(canonical, "b3_session_test_3333") == 0);
    {
        authd_database_lookup_result_t lookup_result;

        lookup_result = authd_database_lookup_login(
            database, canonical, &record, error, sizeof(error));
        if (lookup_result != AUTHD_DATABASE_LOOKUP_OK) {
            (void)fprintf(stderr,
                          "real session fixture lookup failed: %s: %s\n",
                          authd_database_lookup_result_name(lookup_result),
                          error[0] != '\0' ? error : "no detail");
            authd_database_close(database);
            return 1;
        }
    }
    assert(memcmp(record.user_id, expected_user_id,
                  sizeof(expected_user_id)) == 0);
    assert(strcmp(record.legacy_name, "b3sess") == 0);
    assert(record.auth_epoch == UINT64_C(42));
    assert(record.authz_revision == UINT64_C(7));
    assert(record.failed_count == UINT32_C(4));
    assert(record.last_failed_at_set);

    /* Persist the complete successful-login state through the runtime role. */
    {
        authd_database_write_result_t write_result;

        write_result = authd_database_create_password_session(
            database, &record, "192.0.2.99", "ssh", "/dev/pts/42",
            "node-session-test", &session, error, sizeof(error));
        if (write_result != AUTHD_DATABASE_WRITE_OK) {
            (void)fprintf(stderr,
                          "real session creation failed: %s: %s\n",
                          authd_database_write_result_name(write_result),
                          error[0] != '\0' ? error : "no detail");
            authd_database_close(database);
            return 1;
        }
    }
    assert(memcmp(session.user_id, expected_user_id,
                  sizeof(expected_user_id)) == 0);
    assert(session.auth_epoch == UINT64_C(42));
    assert(session.authz_revision == UINT64_C(7));
    created_session = session;

    /* A stale post-Argon2 snapshot must not create a second session. */
    ++record.auth_epoch;
    {
        authd_database_write_result_t write_result;

        write_result = authd_database_create_password_session(
            database, &record, "192.0.2.99", "ssh", "/dev/pts/42",
            "node-session-test", &session, error, sizeof(error));
        if (write_result != AUTHD_DATABASE_WRITE_STALE_STATE) {
            (void)fprintf(stderr,
                          "stale session snapshot was not rejected: %s: %s\n",
                          authd_database_write_result_name(write_result),
                          error[0] != '\0' ? error : "no detail");
            authd_database_close(database);
            return 1;
        }
    }

    /* The runtime role must also close and audit the bound socket lifecycle. */
    {
        authd_database_write_result_t write_result;

        write_result = authd_database_close_terminal_session(
            database, created_session.session_id, "integration_test_complete",
            error, sizeof(error));
        if (write_result != AUTHD_DATABASE_WRITE_OK) {
            (void)fprintf(stderr,
                          "real session close failed: %s: %s\n",
                          authd_database_write_result_name(write_result),
                          error[0] != '\0' ? error : "no detail");
            authd_database_close(database);
            return 1;
        }
        assert(authd_database_close_terminal_session(
                   database, created_session.session_id,
                   "integration_test_complete", error, sizeof(error)) ==
               AUTHD_DATABASE_WRITE_NOT_FOUND);
    }

    authd_database_close(database);
    (void)puts("authd real PostgreSQL session success test: OK");
    return 0;
}
