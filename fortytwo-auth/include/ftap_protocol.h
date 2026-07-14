/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * FortyTwo Authentication Protocol (FTAP)
 * Wire constants for FTAP 1.1 (document revision 1.2).
 *
 * Source of truth:
 *   fortytwo-auth/protocol/FTAP-1.md
 *
 * IMPORTANT:
 * Native C structures must never be written directly to the wire.
 * Headers and TLV values are encoded and decoded field by field in
 * network byte order.
 */

#ifndef FORTYTWO_FTAP_PROTOCOL_H
#define FORTYTWO_FTAP_PROTOCOL_H

#include <stdint.h>

/* Local transport. */
#define FTAP_DEFAULT_SOCKET_PATH          "/run/fortytwo/auth.sock"
#define FTAP_INHERITED_SESSION_FD         3

/* Wire identification and version. */
#define FTAP_MAGIC_U32                    UINT32_C(0x46544150) /* "FTAP" */
#define FTAP_VERSION_MAJOR                UINT16_C(1)
#define FTAP_VERSION_MINOR                UINT16_C(1)

/* Fixed wire sizes and offsets. */
#define FTAP_FRAME_HEADER_SIZE            UINT32_C(24)
#define FTAP_TLV_HEADER_SIZE              UINT32_C(8)

#define FTAP_HEADER_MAGIC_OFFSET          UINT32_C(0)
#define FTAP_HEADER_MAJOR_OFFSET          UINT32_C(4)
#define FTAP_HEADER_MINOR_OFFSET          UINT32_C(6)
#define FTAP_HEADER_MESSAGE_TYPE_OFFSET   UINT32_C(8)
#define FTAP_HEADER_FLAGS_OFFSET          UINT32_C(10)
#define FTAP_HEADER_PAYLOAD_LENGTH_OFFSET UINT32_C(12)
#define FTAP_HEADER_REQUEST_ID_OFFSET     UINT32_C(16)

/* Global wire limits. */
#define FTAP_MAX_PAYLOAD_SIZE             UINT32_C(65536)
#define FTAP_MAX_FRAME_SIZE               \
    (FTAP_FRAME_HEADER_SIZE + FTAP_MAX_PAYLOAD_SIZE)

#define FTAP_UUID_SIZE                    UINT32_C(16)
#define FTAP_BOOLEAN_SIZE                 UINT32_C(1)
#define FTAP_SERVER_PUSH_REQUEST_ID       UINT64_C(0)
#define FTAP_FIRST_CLIENT_REQUEST_ID       UINT64_C(1)

/* Text and byte-string limits from FTAP 1.1. */
#define FTAP_LOGIN_NAME_MAX               UINT32_C(32)
#define FTAP_DISPLAY_NAME_MAX             UINT32_C(64)
#define FTAP_CAPABILITY_NAME_MAX          UINT32_C(96)
#define FTAP_PROTOCOL_NAME_MAX            UINT32_C(16)
#define FTAP_AUTH_METHOD_MAX              UINT32_C(32)
#define FTAP_TTY_DEVICE_MAX               UINT32_C(128)
#define FTAP_NODE_ID_MAX                  UINT32_C(64)
#define FTAP_IP_ADDRESS_MAX               UINT32_C(45)
#define FTAP_CLIENT_NAME_MAX              UINT32_C(64)
#define FTAP_CLIENT_VERSION_MAX           UINT32_C(32)
#define FTAP_SERVICE_NAME_MAX             UINT32_C(64)
#define FTAP_ERROR_TEXT_MAX               UINT32_C(256)
#define FTAP_PASSWORD_MAX                 UINT32_C(1024)
#define FTAP_ACCESS_TOKEN_MAX             UINT32_C(512)

/* Normative string values for FTAP 1.1. */
#define FTAP_PROTOCOL_TELNET              "telnet"
#define FTAP_PROTOCOL_SSH                 "ssh"
#define FTAP_PROTOCOL_LOCAL               "local"

#define FTAP_AUTH_METHOD_PASSWORD         "password"

#define FTAP_SERVICE_FORTYTWO_API         "fortytwo-api"

/*
 * Frame flags.
 * Any bit outside FTAP_FRAME_FLAG_KNOWN_MASK is a protocol error.
 */
typedef enum ftap_frame_flag {
    FTAP_FRAME_FLAG_RESPONSE    = UINT16_C(1) << 0,
    FTAP_FRAME_FLAG_SERVER_PUSH = UINT16_C(1) << 1,
    FTAP_FRAME_FLAG_ERROR       = UINT16_C(1) << 2
} ftap_frame_flag_t;

#define FTAP_FRAME_FLAG_KNOWN_MASK \
    ((uint16_t)(FTAP_FRAME_FLAG_RESPONSE | \
                FTAP_FRAME_FLAG_SERVER_PUSH | \
                FTAP_FRAME_FLAG_ERROR))

/*
 * TLV field flags.
 * Any bit outside FTAP_FIELD_FLAG_KNOWN_MASK is a protocol error.
 */
typedef enum ftap_field_flag {
    FTAP_FIELD_FLAG_CRITICAL = UINT16_C(1) << 0
} ftap_field_flag_t;

#define FTAP_FIELD_FLAG_KNOWN_MASK \
    ((uint16_t)FTAP_FIELD_FLAG_CRITICAL)

/* FTAP connection state machine. */
typedef enum ftap_connection_state {
    FTAP_STATE_CONNECTED = 0,
    FTAP_STATE_HELLO_COMPLETE,
    FTAP_STATE_AUTHENTICATING,
    FTAP_STATE_SESSION_BOUND,
    FTAP_STATE_SERVICE_BOUND,
    FTAP_STATE_CLOSING
} ftap_connection_state_t;

/* FTAP message types. */
typedef enum ftap_message_type {
    FTAP_MSG_HELLO                    = 1,
    FTAP_MSG_HELLO_OK                 = 2,
    FTAP_MSG_ERROR                    = 3,
    FTAP_MSG_SERVICE_BIND_REQUEST     = 4,
    FTAP_MSG_SERVICE_BIND_RESULT      = 5,

    FTAP_MSG_AUTH_PASSWORD_REQUEST    = 100,
    FTAP_MSG_AUTH_PASSWORD_RESULT     = 101,

    FTAP_MSG_SESSION_CONTEXT_REQUEST  = 110,
    FTAP_MSG_SESSION_CONTEXT_RESULT   = 111,
    FTAP_MSG_SESSION_HEARTBEAT        = 112,
    FTAP_MSG_SESSION_AUTHZ_CHANGED    = 113,

    FTAP_MSG_AUTHZ_CHECK_REQUEST      = 120,
    FTAP_MSG_AUTHZ_CHECK_RESULT       = 121,

    FTAP_MSG_SESSION_CLOSE            = 130,
    FTAP_MSG_SESSION_REVOKED          = 131,

    FTAP_MSG_TOKEN_CONTEXT_REQUEST    = 140,
    FTAP_MSG_TOKEN_CONTEXT_RESULT     = 141
} ftap_message_type_t;

/* FTAP TLV field types. */
typedef enum ftap_field_type {
    FTAP_FIELD_CLIENT_NAME        = 1,
    FTAP_FIELD_CLIENT_VERSION     = 2,
    FTAP_FIELD_SUPPORTED_MAJOR    = 3,
    FTAP_FIELD_SUPPORTED_MINOR    = 4,
    FTAP_FIELD_SERVICE_NAME       = 5,

    FTAP_FIELD_LOGIN_NAME         = 10,
    FTAP_FIELD_PASSWORD           = 11,
    FTAP_FIELD_PROTOCOL           = 12,
    FTAP_FIELD_SOURCE_IP          = 13,
    FTAP_FIELD_TTY_DEVICE         = 14,
    FTAP_FIELD_NODE_ID            = 15,
    FTAP_FIELD_AUTH_METHOD        = 16,

    FTAP_FIELD_USER_ID            = 20,
    FTAP_FIELD_SESSION_ID         = 21,
    FTAP_FIELD_DISPLAY_NAME       = 22,
    FTAP_FIELD_ACCOUNT_STATE      = 23,
    FTAP_FIELD_AUTH_EPOCH         = 24,
    FTAP_FIELD_AUTHZ_REVISION     = 25,
    FTAP_FIELD_CAPABILITY         = 26,

    FTAP_FIELD_RESOURCE_TYPE      = 30,
    FTAP_FIELD_RESOURCE_ID        = 31,
    FTAP_FIELD_AUTHZ_ALLOWED      = 32,

    FTAP_FIELD_ENDED_REASON       = 40,
    FTAP_FIELD_REVOKE_REASON      = 41,

    FTAP_FIELD_ERROR_CODE         = 50,
    FTAP_FIELD_ERROR_TEXT         = 51,
    FTAP_FIELD_RETRY_AFTER_MS     = 52,

    FTAP_FIELD_ACCESS_TOKEN       = 60,
    FTAP_FIELD_API_SESSION_ID     = 61
} ftap_field_type_t;

/* FTAP protocol error codes. */
typedef enum ftap_error_code {
    FTAP_ERR_PROTOCOL              = 1,
    FTAP_ERR_UNSUPPORTED_VERSION   = 2,
    FTAP_ERR_UNSUPPORTED_FIELD     = 3,
    FTAP_ERR_INVALID_STATE         = 4,
    FTAP_ERR_MESSAGE_TOO_LARGE     = 5,
    FTAP_ERR_ACCESS_DENIED         = 6,
    FTAP_ERR_INVALID_CREDENTIALS   = 7,
    FTAP_ERR_ACCOUNT_UNAVAILABLE   = 8,
    FTAP_ERR_RATE_LIMITED          = 9,
    FTAP_ERR_SESSION_REVOKED       = 10,
    FTAP_ERR_DATABASE_UNAVAILABLE  = 11,
    FTAP_ERR_INTERNAL              = 12
} ftap_error_code_t;

#endif /* FORTYTWO_FTAP_PROTOCOL_H */
