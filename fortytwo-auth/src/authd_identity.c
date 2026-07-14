/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "authd_identity.h"

#include <string.h>

static bool
is_ascii_letter(unsigned char character)
{
    return (character >= (unsigned char)'A' &&
            character <= (unsigned char)'Z') ||
           (character >= (unsigned char)'a' &&
            character <= (unsigned char)'z');
}

static bool
is_ascii_digit(unsigned char character)
{
    return character >= (unsigned char)'0' &&
           character <= (unsigned char)'9';
}

bool
authd_login_name_canonicalize(
    const char *input,
    size_t input_length,
    char output[AUTHD_LOGIN_NAME_BUFFER_SIZE])
{
    size_t index;

    if (output != NULL) {
        memset(output, 0, AUTHD_LOGIN_NAME_BUFFER_SIZE);
    }
    if (input == NULL || output == NULL || input_length == 0U ||
        input_length > (size_t)FTAP_LOGIN_NAME_MAX) {
        return false;
    }

    for (index = 0U; index < input_length; ++index) {
        unsigned char character = (unsigned char)input[index];
        bool valid;

        if (character == (unsigned char)'\0') {
            memset(output, 0, AUTHD_LOGIN_NAME_BUFFER_SIZE);
            return false;
        }
        if (index == 0U) {
            valid = is_ascii_letter(character) || is_ascii_digit(character);
        } else {
            valid = is_ascii_letter(character) || is_ascii_digit(character) ||
                    character == (unsigned char)'.' ||
                    character == (unsigned char)'_' ||
                    character == (unsigned char)'-';
        }
        if (!valid) {
            memset(output, 0, AUTHD_LOGIN_NAME_BUFFER_SIZE);
            return false;
        }

        if (character >= (unsigned char)'A' &&
            character <= (unsigned char)'Z') {
            character = (unsigned char)(character - (unsigned char)'A' +
                                        (unsigned char)'a');
        }
        output[index] = (char)character;
    }
    output[input_length] = '\0';
    return true;
}

bool
authd_login_name_is_canonical(const char *login_name)
{
    char canonical[AUTHD_LOGIN_NAME_BUFFER_SIZE];
    size_t length;
    bool valid;

    if (login_name == NULL) {
        return false;
    }
    length = strlen(login_name);
    valid = authd_login_name_canonicalize(login_name, length, canonical);
    return valid && strcmp(login_name, canonical) == 0;
}
