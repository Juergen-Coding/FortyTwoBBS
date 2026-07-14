/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Message-level validation for FTAP 1.2, document revision 1.4.
 */

#ifndef FORTYTWO_FTAP_SCHEMA_H
#define FORTYTWO_FTAP_SCHEMA_H

#include "ftap_codec.h"

#include <stddef.h>
#include <stdint.h>

typedef struct ftap_validation_error {
    ftap_status_t status;
    uint16_t message_type;
    uint16_t field_type;
} ftap_validation_error_t;

ftap_status_t ftap_validate_message(
    ftap_connection_state_t state,
    const ftap_frame_header_t *header,
    const uint8_t *payload,
    size_t payload_length,
    ftap_validation_error_t *error);

#endif /* FORTYTWO_FTAP_SCHEMA_H */
