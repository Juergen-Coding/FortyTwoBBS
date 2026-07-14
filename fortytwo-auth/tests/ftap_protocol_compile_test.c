/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Compile-time contract test for FTAP 1.1 wire constants.
 */

#include "ftap_protocol.h"

_Static_assert(FTAP_MAGIC_U32 == UINT32_C(0x46544150),
               "FTAP magic must encode FTAP");
_Static_assert(FTAP_VERSION_MAJOR == 1,
               "Unexpected FTAP major version");
_Static_assert(FTAP_VERSION_MINOR == 1,
               "Unexpected FTAP minor version");
_Static_assert(FTAP_FRAME_HEADER_SIZE == 24,
               "FTAP frame header must be 24 bytes");
_Static_assert(FTAP_TLV_HEADER_SIZE == 8,
               "FTAP TLV header must be 8 bytes");
_Static_assert(FTAP_HEADER_MAGIC_OFFSET == 0,
               "Invalid magic offset");
_Static_assert(FTAP_HEADER_MAJOR_OFFSET == 4,
               "Invalid major-version offset");
_Static_assert(FTAP_HEADER_MINOR_OFFSET == 6,
               "Invalid minor-version offset");
_Static_assert(FTAP_HEADER_MESSAGE_TYPE_OFFSET == 8,
               "Invalid message-type offset");
_Static_assert(FTAP_HEADER_FLAGS_OFFSET == 10,
               "Invalid flags offset");
_Static_assert(FTAP_HEADER_PAYLOAD_LENGTH_OFFSET == 12,
               "Invalid payload-length offset");
_Static_assert(FTAP_HEADER_REQUEST_ID_OFFSET == 16,
               "Invalid request-id offset");
_Static_assert(FTAP_MAX_PAYLOAD_SIZE == 65536,
               "Unexpected maximum FTAP payload");
_Static_assert(FTAP_MAX_FRAME_SIZE == 65560,
               "Unexpected maximum FTAP frame size");
_Static_assert(FTAP_FRAME_FLAG_KNOWN_MASK == UINT16_C(0x0007),
               "Unexpected frame flag mask");
_Static_assert(FTAP_FIELD_FLAG_KNOWN_MASK == UINT16_C(0x0001),
               "Unexpected field flag mask");
_Static_assert(FTAP_ACCOUNT_STATE_MAX == 16,
               "Unexpected account-state limit");
_Static_assert(FTAP_RESOURCE_TYPE_MAX == 64,
               "Unexpected resource-type limit");
_Static_assert(FTAP_RESOURCE_ID_MAX == 128,
               "Unexpected resource-id limit");
_Static_assert(FTAP_ENDED_REASON_MAX == 64,
               "Unexpected ended-reason limit");
_Static_assert(FTAP_REVOKE_REASON_MAX == 64,
               "Unexpected revoke-reason limit");
_Static_assert(FTAP_MSG_SERVICE_BIND_REQUEST == 4,
               "Unexpected service-bind message value");
_Static_assert(FTAP_MSG_AUTH_PASSWORD_REQUEST == 100,
               "Unexpected password-request message value");
_Static_assert(FTAP_MSG_SESSION_REVOKED == 131,
               "Unexpected session-revoked message value");
_Static_assert(FTAP_MSG_TOKEN_CONTEXT_RESULT == 141,
               "Unexpected token-context message value");
_Static_assert(FTAP_FIELD_ACCESS_TOKEN == 60,
               "Unexpected access-token field value");
_Static_assert(FTAP_FIELD_API_SESSION_ID == 61,
               "Unexpected API-session field value");
_Static_assert(FTAP_STATE_SESSION_BOUND != FTAP_STATE_SERVICE_BOUND,
               "Session and service states must differ");

int
main(void)
{
    return 0;
}
