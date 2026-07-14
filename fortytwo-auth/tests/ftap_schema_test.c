/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ftap_schema.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned int failures;

#define CHECK(condition_)                                                     \
    do {                                                                      \
        if (!(condition_)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                    \
                    __FILE__, __LINE__, #condition_);                         \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

#define CHECK_STATUS(expression_, expected_)                                  \
    do {                                                                      \
        ftap_status_t actual_ = (expression_);                                \
        if (actual_ != (expected_)) {                                         \
            fprintf(stderr, "%s:%d: status %s, expected %s\n",              \
                    __FILE__, __LINE__, ftap_status_string(actual_),          \
                    ftap_status_string((expected_)));                         \
            ++failures;                                                       \
        }                                                                     \
    } while (0)

static ftap_frame_header_t
make_header(uint16_t message_type,
            uint16_t flags,
            uint32_t payload_length,
            uint64_t request_id)
{
    ftap_frame_header_t header;

    header.major = FTAP_VERSION_MAJOR;
    header.minor = FTAP_VERSION_MINOR;
    header.message_type = message_type;
    header.flags = flags;
    header.payload_length = payload_length;
    header.request_id = request_id;
    return header;
}

static void
test_valid_hello(void)
{
    uint8_t payload[256];
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_CLIENT_NAME, 0,
                     (const uint8_t *)"fortytwo-login",
                     strlen("fortytwo-login"),
                     FTAP_CLIENT_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_CLIENT_VERSION, 0,
                     (const uint8_t *)"0.1", 3,
                     FTAP_CLIENT_VERSION_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_u16(
                     &writer, FTAP_FIELD_SUPPORTED_MAJOR, 0,
                     FTAP_VERSION_MAJOR),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_u16(
                     &writer, FTAP_FIELD_SUPPORTED_MINOR, 0,
                     FTAP_VERSION_MINOR),
                 FTAP_STATUS_OK);

    header = make_header(FTAP_MSG_HELLO, 0,
                         (uint32_t)writer.length, 1);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_CONNECTED, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);
}

static void
test_duplicate_and_missing_fields(void)
{
    uint8_t payload[256];
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;
    ftap_validation_error_t error;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"neo67", 5,
                     FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"other", 5,
                     FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_PASSWORD, 0,
                     (const uint8_t *)"secret", 6,
                     FTAP_PASSWORD_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_PROTOCOL, 0,
                     (const uint8_t *)FTAP_PROTOCOL_SSH,
                     strlen(FTAP_PROTOCOL_SSH), FTAP_PROTOCOL_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_AUTH_METHOD, 0,
                     (const uint8_t *)FTAP_AUTH_METHOD_PASSWORD,
                     strlen(FTAP_AUTH_METHOD_PASSWORD), FTAP_AUTH_METHOD_MAX),
                 FTAP_STATUS_OK);

    header = make_header(FTAP_MSG_AUTH_PASSWORD_REQUEST, 0,
                         (uint32_t)writer.length, 2);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &header,
                                       payload, writer.length, &error),
                 FTAP_STATUS_ERR_DUPLICATE_FIELD);
    CHECK(error.field_type == FTAP_FIELD_LOGIN_NAME);

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"neo67", 5,
                     FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    header.payload_length = (uint32_t)writer.length;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &header,
                                       payload, writer.length, &error),
                 FTAP_STATUS_ERR_MISSING_FIELD);
    CHECK(error.field_type == FTAP_FIELD_PASSWORD);
}

static void
test_unknown_fields(void)
{
    uint8_t payload[64];
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put(&writer, UINT16_C(500), 0, NULL, 0),
                 FTAP_STATUS_OK);
    header = make_header(FTAP_MSG_SESSION_HEARTBEAT, 0,
                         (uint32_t)writer.length, 3);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SESSION_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put(&writer, UINT16_C(500),
                                     FTAP_FIELD_FLAG_CRITICAL, NULL, 0),
                 FTAP_STATUS_OK);
    header.payload_length = (uint32_t)writer.length;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SESSION_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_UNSUPPORTED_FIELD);
}

static void
test_service_and_session_authz(void)
{
    uint8_t payload[256];
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_CAPABILITY, 0,
                     (const uint8_t *)"message.read", 12,
                     FTAP_CAPABILITY_NAME_MAX),
                 FTAP_STATUS_OK);
    header = make_header(FTAP_MSG_AUTHZ_CHECK_REQUEST, 0,
                         (uint32_t)writer.length, 4);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SESSION_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SERVICE_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_MISSING_FIELD);

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put(
                     &writer, FTAP_FIELD_ACCESS_TOKEN, 0,
                     "opaque-token", 12),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_CAPABILITY, 0,
                     (const uint8_t *)"message.read", 12,
                     FTAP_CAPABILITY_NAME_MAX),
                 FTAP_STATUS_OK);
    header.payload_length = (uint32_t)writer.length;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SERVICE_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SESSION_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_FORBIDDEN_FIELD);

    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_CAPABILITY, 0,
                     (const uint8_t *)"message.write", 13,
                     FTAP_CAPABILITY_NAME_MAX),
                 FTAP_STATUS_OK);
    header.payload_length = (uint32_t)writer.length;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SERVICE_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_DUPLICATE_FIELD);
}

static void
test_repeated_capabilities_in_result(void)
{
    uint8_t payload[512];
    uint8_t uuid[FTAP_UUID_SIZE] = { 0 };
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_uuid(
                     &writer, FTAP_FIELD_USER_ID, 0, uuid),
                 FTAP_STATUS_OK);
    uuid[0] = 1;
    CHECK_STATUS(ftap_tlv_writer_put_uuid(
                     &writer, FTAP_FIELD_API_SESSION_ID, 0, uuid),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"neo67", 5,
                     FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_DISPLAY_NAME, 0,
                     (const uint8_t *)"Jürgen", 7,
                     FTAP_DISPLAY_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_u64(
                     &writer, FTAP_FIELD_AUTH_EPOCH, 0, 1),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_u64(
                     &writer, FTAP_FIELD_AUTHZ_REVISION, 0, 9),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_CAPABILITY, 0,
                     (const uint8_t *)"message.read", 12,
                     FTAP_CAPABILITY_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_CAPABILITY, 0,
                     (const uint8_t *)"message.write", 13,
                     FTAP_CAPABILITY_NAME_MAX),
                 FTAP_STATUS_OK);

    header = make_header(FTAP_MSG_TOKEN_CONTEXT_RESULT,
                         FTAP_FRAME_FLAG_RESPONSE,
                         (uint32_t)writer.length, 5);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SERVICE_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);
}

static void
test_flags_state_and_service_name(void)
{
    uint8_t payload[128];
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_SERVICE_NAME, 0,
                     (const uint8_t *)"fortytwo-api",
                     strlen("fortytwo-api"),
                     FTAP_SERVICE_NAME_MAX),
                 FTAP_STATUS_OK);

    header = make_header(FTAP_MSG_SERVICE_BIND_REQUEST, 0,
                         (uint32_t)writer.length, 6);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_CONNECTED, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_INVALID_STATE);

    header.flags = FTAP_FRAME_FLAG_RESPONSE;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_FLAGS);

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_SERVICE_NAME, 0,
                     (const uint8_t *)"wrong-service", 13,
                     FTAP_SERVICE_NAME_MAX),
                 FTAP_STATUS_OK);
    header.flags = 0;
    header.payload_length = (uint32_t)writer.length;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_INVALID_VALUE);
}


static void
test_canonical_ip(void)
{
    uint8_t payload[256];
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"neo67", 5,
                     FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_PASSWORD, 0,
                     (const uint8_t *)"secret", 6,
                     FTAP_PASSWORD_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_PROTOCOL, 0,
                     (const uint8_t *)FTAP_PROTOCOL_TELNET,
                     strlen(FTAP_PROTOCOL_TELNET), FTAP_PROTOCOL_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_AUTH_METHOD, 0,
                     (const uint8_t *)FTAP_AUTH_METHOD_PASSWORD,
                     strlen(FTAP_AUTH_METHOD_PASSWORD), FTAP_AUTH_METHOD_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_SOURCE_IP, 0,
                     (const uint8_t *)"2001:db8::1", 11,
                     FTAP_IP_ADDRESS_MAX),
                 FTAP_STATUS_OK);

    header = make_header(FTAP_MSG_AUTH_PASSWORD_REQUEST, 0,
                         (uint32_t)writer.length, 7);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"neo67", 5,
                     FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_PASSWORD, 0,
                     (const uint8_t *)"secret", 6,
                     FTAP_PASSWORD_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_PROTOCOL, 0,
                     (const uint8_t *)FTAP_PROTOCOL_TELNET,
                     strlen(FTAP_PROTOCOL_TELNET), FTAP_PROTOCOL_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_AUTH_METHOD, 0,
                     (const uint8_t *)FTAP_AUTH_METHOD_PASSWORD,
                     strlen(FTAP_AUTH_METHOD_PASSWORD), FTAP_AUTH_METHOD_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_SOURCE_IP, 0,
                     (const uint8_t *)"2001:0db8:0:0:0:0:0:1",
                     strlen("2001:0db8:0:0:0:0:0:1"),
                     FTAP_IP_ADDRESS_MAX),
                 FTAP_STATUS_OK);
    header.payload_length = (uint32_t)writer.length;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_HELLO_COMPLETE, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_INVALID_VALUE);
}

static void
test_push_and_payload_length(void)
{
    uint8_t payload[64];
    ftap_tlv_writer_t writer;
    ftap_frame_header_t header;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, payload, sizeof(payload)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_REVOKE_REASON, 0,
                     (const uint8_t *)"account_locked", 14,
                     FTAP_MAX_PAYLOAD_SIZE),
                 FTAP_STATUS_OK);

    header = make_header(FTAP_MSG_SESSION_REVOKED,
                         FTAP_FRAME_FLAG_SERVER_PUSH,
                         (uint32_t)writer.length,
                         FTAP_SERVER_PUSH_REQUEST_ID);
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SESSION_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_OK);

    header.request_id = 7;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SESSION_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_REQUEST_ID);

    header.request_id = FTAP_SERVER_PUSH_REQUEST_ID;
    header.payload_length++;
    CHECK_STATUS(ftap_validate_message(FTAP_STATE_SESSION_BOUND, &header,
                                       payload, writer.length, NULL),
                 FTAP_STATUS_ERR_LENGTH);
}

int
main(void)
{
    test_valid_hello();
    test_duplicate_and_missing_fields();
    test_unknown_fields();
    test_service_and_session_authz();
    test_repeated_capabilities_in_result();
    test_flags_state_and_service_name();
    test_canonical_ip();
    test_push_and_payload_length();

    if (failures != 0U) {
        fprintf(stderr, "%u FTAP schema test(s) failed\n", failures);
        return 1;
    }

    puts("FTAP schema tests: OK");
    return 0;
}
