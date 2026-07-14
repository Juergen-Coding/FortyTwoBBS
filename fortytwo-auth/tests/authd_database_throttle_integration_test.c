/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Real PostgreSQL integration test for persistent password throttling.
 */

#include "authd_config.h"
#include "authd_database.h"
#include "authd_database_validation.h"
#include "authd_throttle.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t fixture_user_id[FTAP_UUID_SIZE] = {
    0x7f, 0x4a, 0x42, 0xb3, 0x00, 0x05, 0x4a, 0x11,
    0x8b, 0x32, 0x42, 0xb3, 0xf0, 0x0d, 0x00, 0x51
};

/* Report database failures with their internal result name and detail. */
static int
report_write_failure(const char *operation,
                     authd_database_write_result_t result,
                     const char *error)
{
    (void)fprintf(stderr, "%s failed: %s: %s\n",
                  operation,
                  authd_database_write_result_name(result),
                  error != NULL && error[0] != '\0' ? error : "no detail");
    return 1;
}

int
main(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    authd_throttle_policy_t policy;
    authd_password_failure_update_t update;
    authd_login_record_t record;
    char error[AUTHD_DATABASE_ERROR_MAX];
    uint32_t expected_count;

    authd_config_defaults(&config);
    authd_throttle_policy_defaults(&policy);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);
    assert(database != NULL);
    assert(info.highest_migration ==
           AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION);

    /*
     * The fixture starts with four failures older than the 15-minute window.
     * The first new failure must therefore reset the persistent count to one.
     */
    for (expected_count = 1U; expected_count <= 5U; ++expected_count) {
        authd_database_write_result_t result;

        result = authd_database_record_password_failure(
            database,
            fixture_user_id,
            &policy,
            "192.0.2.42",
            "ssh",
            &update,
            error,
            sizeof(error));
        if (result != AUTHD_DATABASE_WRITE_OK) {
            authd_database_close(database);
            return report_write_failure("password failure update",
                                        result, error);
        }

        assert(update.failed_count == expected_count);
        if (expected_count < policy.failure_threshold) {
            assert(!update.throttled);
            assert(update.retry_after_ms == 0U);
        } else {
            assert(update.throttled);
            assert(update.retry_after_ms > 0U);
            assert(update.retry_after_ms <=
                   (uint64_t)policy.throttle_seconds * UINT64_C(1000));
        }
    }

    /* The normal login snapshot must immediately observe the stored throttle. */
    assert(authd_database_lookup_login(
        database, "b3_throttle_test_7f4a", &record,
        error, sizeof(error)) == AUTHD_DATABASE_LOOKUP_OK);
    assert(record.failed_count == 5U);
    assert(record.throttled);
    assert(record.retry_after_ms > 0U);
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_THROTTLED);

    /* Unknown-user attempts are audited without inventing a subject UUID. */
    {
        authd_database_write_result_t result;

        result = authd_database_audit_login_rejection(
            database,
            NULL,
            "b3_throttle_missing_7f4a",
            AUTHD_LOGIN_REJECTION_UNKNOWN_USER,
            NULL,
            "telnet",
            error,
            sizeof(error));
        if (result != AUTHD_DATABASE_WRITE_OK) {
            authd_database_close(database);
            return report_write_failure("unknown-user audit", result, error);
        }
    }

    authd_database_close(database);
    (void)puts("authd real PostgreSQL throttle test: OK");
    return 0;
}
