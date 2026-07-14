/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Canonical internal login-name handling for fortytwo-authd.
 */

#ifndef FORTYTWO_AUTHD_IDENTITY_H
#define FORTYTWO_AUTHD_IDENTITY_H

#include "ftap_protocol.h"

#include <stdbool.h>
#include <stddef.h>

#define AUTHD_LOGIN_NAME_BUFFER_SIZE ((size_t)FTAP_LOGIN_NAME_MAX + 1U)
#define AUTHD_LEGACY_NAME_BUFFER_SIZE ((size_t)FTAP_LEGACY_NAME_MAX + 1U)

bool authd_login_name_canonicalize(
    const char *input,
    size_t input_length,
    char output[AUTHD_LOGIN_NAME_BUFFER_SIZE]);

bool authd_login_name_is_canonical(const char *login_name);

bool authd_legacy_name_is_valid(const char *legacy_name);

#endif /* FORTYTWO_AUTHD_IDENTITY_H */
