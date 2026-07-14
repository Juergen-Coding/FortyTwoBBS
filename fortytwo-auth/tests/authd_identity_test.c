/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_identity.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void
test_canonicalization(void)
{
    char output[AUTHD_LOGIN_NAME_BUFFER_SIZE];
    const char mixed[] = "Neo67.Test_User-1";

    assert(authd_login_name_canonicalize(
        mixed, sizeof(mixed) - 1U, output));
    assert(strcmp(output, "neo67.test_user-1") == 0);
    assert(authd_login_name_is_canonical("neo67.test_user-1"));
    assert(!authd_login_name_is_canonical("Neo67"));
}

static void
test_boundaries_and_rejections(void)
{
    char output[AUTHD_LOGIN_NAME_BUFFER_SIZE];
    char maximum[AUTHD_LOGIN_NAME_BUFFER_SIZE];
    char embedded_nul[] = {'a', '\0', 'b'};

    memset(maximum, 'a', sizeof(maximum) - 1U);
    maximum[sizeof(maximum) - 1U] = '\0';

    assert(authd_login_name_canonicalize(
        maximum, sizeof(maximum) - 1U, output));
    assert(strcmp(output, maximum) == 0);

    assert(!authd_login_name_canonicalize("", 0U, output));
    assert(!authd_login_name_canonicalize(".neo67", 6U, output));
    assert(!authd_login_name_canonicalize("neo 67", 6U, output));
    assert(!authd_login_name_canonicalize("n\xc3\xa9o", 4U, output));
    assert(!authd_login_name_canonicalize(
        embedded_nul, sizeof(embedded_nul), output));
    assert(!authd_login_name_canonicalize(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 33U, output));
    assert(output[0] == '\0');
}

int
main(void)
{
    test_canonicalization();
    test_boundaries_and_rejections();
    (void)puts("authd identity tests: OK");
    return 0;
}
