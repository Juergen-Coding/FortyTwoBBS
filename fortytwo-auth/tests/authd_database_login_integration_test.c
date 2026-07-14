/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Real PostgreSQL integration test for the parameterized login lookup.
 * The companion shell script creates and removes the fixed fixture.
 */

#include "authd_config.h"
#include "authd_database.h"
#include "authd_database_validation.h"
#include "authd_identity.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const unsigned char expected_user_id[FTAP_UUID_SIZE] = {
    0x7f, 0x4a, 0x42, 0xb3, 0x00, 0x05, 0x4a, 0x11,
    0x8b, 0x32, 0x42, 0xb3, 0xf0, 0x0d, 0x00, 0x01
};

int
main(void)
{
    authd_config_t config;
    authd_database_t *database = NULL;
    authd_database_info_t info;
    authd_login_record_t record;
    char canonical[AUTHD_LOGIN_NAME_BUFFER_SIZE];
    char error[AUTHD_DATABASE_ERROR_MAX];

    authd_config_defaults(&config);
    assert(authd_database_open(&config, &database, &info,
                               error, sizeof(error)) == 0);
    assert(database != NULL);
    assert(info.highest_migration ==
           AUTHD_DATABASE_REQUIRED_HIGHEST_MIGRATION);

    assert(authd_login_name_canonicalize(
        "B3_Lookup_Test_7F4A",
        strlen("B3_Lookup_Test_7F4A"),
        canonical));
    assert(strcmp(canonical, "b3_lookup_test_7f4a") == 0);

    {
        authd_database_lookup_result_t lookup_result;

        lookup_result = authd_database_lookup_login(
            database, canonical, &record, error, sizeof(error));
        if (lookup_result != AUTHD_DATABASE_LOOKUP_OK) {
            (void)fprintf(stderr,
                          "real login lookup failed: %s: %s\n",
                          authd_database_lookup_result_name(lookup_result),
                          error[0] != '\0' ? error : "no detail");
            authd_database_close(database);
            return 1;
        }
    }
    assert(memcmp(record.user_id, expected_user_id,
                  sizeof(expected_user_id)) == 0);
    assert(strcmp(record.login_name, "b3_lookup_test_7f4a") == 0);
    assert(strcmp(record.display_name, "B3 PostgreSQL Lookup Test") == 0);
    assert(strncmp(record.password_hash, "$argon2id$", 10U) == 0);
    assert(record.account_state == AUTHD_ACCOUNT_STATE_ACTIVE);
    assert(record.auth_epoch == UINT64_C(42));
    assert(record.authz_revision == UINT64_C(7));
    assert(!record.deleted);
    assert(!record.throttled);
    assert(record.retry_after_ms == UINT64_C(0));
    assert(!record.must_change);
    assert(record.failed_count == UINT32_C(2));
    assert(record.last_failed_at_set);
    assert(record.last_failed_at_epoch_ms == INT64_C(1784030400000));
    assert(authd_login_record_availability(&record) == AUTHD_LOGIN_AVAILABLE);

    assert(authd_database_lookup_login(
        database, "b3_lookup_missing_7f4a", &record,
        error, sizeof(error)) == AUTHD_DATABASE_LOOKUP_NOT_FOUND);
    assert(record.login_name[0] == '\0');

    assert(authd_database_lookup_login(database, "B3_Lookup_Test_7F4A",
                                       &record, error, sizeof(error)) ==
           AUTHD_DATABASE_LOOKUP_ERROR);
    assert(strstr(error, "invalid login lookup arguments") != NULL);

    authd_database_close(database);
    (void)puts("authd real PostgreSQL login lookup test: OK");
    return 0;
}
