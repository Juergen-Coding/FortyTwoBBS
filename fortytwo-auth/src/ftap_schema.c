/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ftap_schema.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FIELD_BIT(field_) (UINT64_C(1) << (field_))

_Static_assert(FTAP_FIELD_API_SESSION_ID < 64,
               "FTAP 1.1 known field ids must fit in the schema bitset");

static void
set_error(ftap_validation_error_t *error,
          ftap_status_t status,
          uint16_t message_type,
          uint16_t field_type)
{
    if (error != NULL) {
        error->status = status;
        error->message_type = message_type;
        error->field_type = field_type;
    }
}

static bool
text_equals(const ftap_tlv_t *field, const char *expected)
{
    size_t expected_length = strlen(expected);

    return field->length == expected_length &&
           memcmp(field->value, expected, expected_length) == 0;
}

static ftap_status_t
validate_text(const ftap_tlv_t *field, size_t maximum, bool allow_empty)
{
    const uint8_t *text;
    size_t length;
    ftap_status_t status;

    status = ftap_tlv_get_text(field, &text, &length, maximum);
    if (status != FTAP_STATUS_OK) {
        return status;
    }
    (void)text;

    if (!allow_empty && length == 0U) {
        return FTAP_STATUS_ERR_INVALID_VALUE;
    }

    return FTAP_STATUS_OK;
}


static ftap_status_t
validate_canonical_ip(const ftap_tlv_t *field)
{
    char input[FTAP_IP_ADDRESS_MAX + 1U];
    char canonical[INET6_ADDRSTRLEN];
    struct in_addr address4;
    struct in6_addr address6;

    if (field->length == 0U || field->length > FTAP_IP_ADDRESS_MAX) {
        return FTAP_STATUS_ERR_LENGTH;
    }
    if (!ftap_utf8_text_is_valid(field->value, field->length)) {
        return FTAP_STATUS_ERR_ENCODING;
    }

    memcpy(input, field->value, field->length);
    input[field->length] = '\0';

    if (inet_pton(AF_INET, input, &address4) == 1) {
        if (inet_ntop(AF_INET, &address4, canonical, sizeof(canonical)) == NULL) {
            return FTAP_STATUS_ERR_INVALID_VALUE;
        }
        return strcmp(input, canonical) == 0
                   ? FTAP_STATUS_OK
                   : FTAP_STATUS_ERR_INVALID_VALUE;
    }

    if (inet_pton(AF_INET6, input, &address6) == 1) {
        if (inet_ntop(AF_INET6, &address6, canonical, sizeof(canonical)) == NULL) {
            return FTAP_STATUS_ERR_INVALID_VALUE;
        }
        return strcmp(input, canonical) == 0
                   ? FTAP_STATUS_OK
                   : FTAP_STATUS_ERR_INVALID_VALUE;
    }

    return FTAP_STATUS_ERR_INVALID_VALUE;
}

static ftap_status_t
validate_field_value(const ftap_tlv_t *field)
{
    uint16_t u16_value;
    uint32_t u32_value;
    uint64_t u64_value;
    bool bool_value;
    uint8_t uuid[FTAP_UUID_SIZE];
    ftap_status_t status;

    switch (field->type) {
    case FTAP_FIELD_CLIENT_NAME:
        return validate_text(field, FTAP_CLIENT_NAME_MAX, false);
    case FTAP_FIELD_CLIENT_VERSION:
        return validate_text(field, FTAP_CLIENT_VERSION_MAX, false);
    case FTAP_FIELD_SUPPORTED_MAJOR:
    case FTAP_FIELD_SUPPORTED_MINOR:
        return ftap_tlv_get_u16(field, &u16_value);
    case FTAP_FIELD_SERVICE_NAME:
        status = validate_text(field, FTAP_SERVICE_NAME_MAX, false);
        if (status != FTAP_STATUS_OK) {
            return status;
        }
        return text_equals(field, FTAP_SERVICE_FORTYTWO_API)
                   ? FTAP_STATUS_OK
                   : FTAP_STATUS_ERR_INVALID_VALUE;
    case FTAP_FIELD_LOGIN_NAME:
        return validate_text(field, FTAP_LOGIN_NAME_MAX, false);
    case FTAP_FIELD_PASSWORD:
        return validate_text(field, FTAP_PASSWORD_MAX, false);
    case FTAP_FIELD_PROTOCOL:
        status = validate_text(field, FTAP_PROTOCOL_NAME_MAX, false);
        if (status != FTAP_STATUS_OK) {
            return status;
        }
        return (text_equals(field, FTAP_PROTOCOL_TELNET) ||
                text_equals(field, FTAP_PROTOCOL_SSH) ||
                text_equals(field, FTAP_PROTOCOL_LOCAL))
                   ? FTAP_STATUS_OK
                   : FTAP_STATUS_ERR_INVALID_VALUE;
    case FTAP_FIELD_SOURCE_IP:
        return validate_canonical_ip(field);
    case FTAP_FIELD_TTY_DEVICE:
        return validate_text(field, FTAP_TTY_DEVICE_MAX, false);
    case FTAP_FIELD_NODE_ID:
        return validate_text(field, FTAP_NODE_ID_MAX, false);
    case FTAP_FIELD_AUTH_METHOD:
        status = validate_text(field, FTAP_AUTH_METHOD_MAX, false);
        if (status != FTAP_STATUS_OK) {
            return status;
        }
        return text_equals(field, FTAP_AUTH_METHOD_PASSWORD)
                   ? FTAP_STATUS_OK
                   : FTAP_STATUS_ERR_INVALID_VALUE;
    case FTAP_FIELD_USER_ID:
    case FTAP_FIELD_SESSION_ID:
    case FTAP_FIELD_API_SESSION_ID:
        return ftap_tlv_get_uuid(field, uuid);
    case FTAP_FIELD_DISPLAY_NAME:
        return validate_text(field, FTAP_DISPLAY_NAME_MAX, false);
    case FTAP_FIELD_ACCOUNT_STATE:
        return validate_text(field, FTAP_MAX_PAYLOAD_SIZE, false);
    case FTAP_FIELD_AUTH_EPOCH:
    case FTAP_FIELD_AUTHZ_REVISION:
        return ftap_tlv_get_u64(field, &u64_value);
    case FTAP_FIELD_CAPABILITY:
        return validate_text(field, FTAP_CAPABILITY_NAME_MAX, false);
    case FTAP_FIELD_RESOURCE_TYPE:
    case FTAP_FIELD_RESOURCE_ID:
    case FTAP_FIELD_ENDED_REASON:
    case FTAP_FIELD_REVOKE_REASON:
        return validate_text(field, FTAP_MAX_PAYLOAD_SIZE, false);
    case FTAP_FIELD_AUTHZ_ALLOWED:
        return ftap_tlv_get_bool(field, &bool_value);
    case FTAP_FIELD_ERROR_CODE:
        status = ftap_tlv_get_u32(field, &u32_value);
        if (status != FTAP_STATUS_OK) {
            return status;
        }
        return (u32_value >= FTAP_ERR_PROTOCOL &&
                u32_value <= FTAP_ERR_INTERNAL)
                   ? FTAP_STATUS_OK
                   : FTAP_STATUS_ERR_INVALID_VALUE;
    case FTAP_FIELD_ERROR_TEXT:
        return validate_text(field, FTAP_ERROR_TEXT_MAX, false);
    case FTAP_FIELD_RETRY_AFTER_MS:
        return ftap_tlv_get_u32(field, &u32_value);
    case FTAP_FIELD_ACCESS_TOKEN:
        if (field->length == 0U || field->length > FTAP_ACCESS_TOKEN_MAX) {
            return FTAP_STATUS_ERR_LENGTH;
        }
        return FTAP_STATUS_OK;
    default:
        return FTAP_STATUS_ERR_UNSUPPORTED_FIELD;
    }
}

static ftap_status_t
expected_flags(uint16_t message_type, uint16_t *flags)
{
    if (flags == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    switch (message_type) {
    case FTAP_MSG_HELLO:
    case FTAP_MSG_SERVICE_BIND_REQUEST:
    case FTAP_MSG_AUTH_PASSWORD_REQUEST:
    case FTAP_MSG_SESSION_CONTEXT_REQUEST:
    case FTAP_MSG_SESSION_HEARTBEAT:
    case FTAP_MSG_AUTHZ_CHECK_REQUEST:
    case FTAP_MSG_SESSION_CLOSE:
    case FTAP_MSG_TOKEN_CONTEXT_REQUEST:
        *flags = 0;
        return FTAP_STATUS_OK;
    case FTAP_MSG_HELLO_OK:
    case FTAP_MSG_SERVICE_BIND_RESULT:
    case FTAP_MSG_AUTH_PASSWORD_RESULT:
    case FTAP_MSG_SESSION_CONTEXT_RESULT:
    case FTAP_MSG_AUTHZ_CHECK_RESULT:
    case FTAP_MSG_TOKEN_CONTEXT_RESULT:
        *flags = FTAP_FRAME_FLAG_RESPONSE;
        return FTAP_STATUS_OK;
    case FTAP_MSG_ERROR:
        *flags = (uint16_t)(FTAP_FRAME_FLAG_RESPONSE |
                            FTAP_FRAME_FLAG_ERROR);
        return FTAP_STATUS_OK;
    case FTAP_MSG_SESSION_AUTHZ_CHANGED:
    case FTAP_MSG_SESSION_REVOKED:
        *flags = FTAP_FRAME_FLAG_SERVER_PUSH;
        return FTAP_STATUS_OK;
    default:
        return FTAP_STATUS_ERR_INVALID_MESSAGE;
    }
}

static bool
state_allows_message(ftap_connection_state_t state, uint16_t message_type)
{
    if (message_type == FTAP_MSG_ERROR) {
        return state != FTAP_STATE_CLOSING;
    }

    switch (message_type) {
    case FTAP_MSG_HELLO:
    case FTAP_MSG_HELLO_OK:
        return state == FTAP_STATE_CONNECTED;
    case FTAP_MSG_SERVICE_BIND_REQUEST:
    case FTAP_MSG_SERVICE_BIND_RESULT:
        return state == FTAP_STATE_HELLO_COMPLETE;
    case FTAP_MSG_AUTH_PASSWORD_REQUEST:
    case FTAP_MSG_AUTH_PASSWORD_RESULT:
        return state == FTAP_STATE_HELLO_COMPLETE ||
               state == FTAP_STATE_AUTHENTICATING;
    case FTAP_MSG_SESSION_CONTEXT_REQUEST:
    case FTAP_MSG_SESSION_CONTEXT_RESULT:
    case FTAP_MSG_SESSION_HEARTBEAT:
    case FTAP_MSG_SESSION_AUTHZ_CHANGED:
    case FTAP_MSG_SESSION_CLOSE:
    case FTAP_MSG_SESSION_REVOKED:
        return state == FTAP_STATE_SESSION_BOUND;
    case FTAP_MSG_AUTHZ_CHECK_REQUEST:
    case FTAP_MSG_AUTHZ_CHECK_RESULT:
        return state == FTAP_STATE_SESSION_BOUND ||
               state == FTAP_STATE_SERVICE_BOUND;
    case FTAP_MSG_TOKEN_CONTEXT_REQUEST:
    case FTAP_MSG_TOKEN_CONTEXT_RESULT:
        return state == FTAP_STATE_SERVICE_BOUND;
    default:
        return false;
    }
}

static ftap_status_t
message_masks(ftap_connection_state_t state,
              uint16_t message_type,
              uint64_t *allowed,
              uint64_t *required,
              uint64_t *repeatable)
{
    uint64_t a = 0;
    uint64_t r = 0;
    uint64_t p = 0;

    if (allowed == NULL || required == NULL || repeatable == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    switch (message_type) {
    case FTAP_MSG_HELLO:
        a = FIELD_BIT(FTAP_FIELD_CLIENT_NAME) |
            FIELD_BIT(FTAP_FIELD_CLIENT_VERSION) |
            FIELD_BIT(FTAP_FIELD_SUPPORTED_MAJOR) |
            FIELD_BIT(FTAP_FIELD_SUPPORTED_MINOR);
        r = a;
        break;
    case FTAP_MSG_HELLO_OK:
    case FTAP_MSG_SERVICE_BIND_RESULT:
    case FTAP_MSG_SESSION_CONTEXT_REQUEST:
    case FTAP_MSG_SESSION_HEARTBEAT:
        break;
    case FTAP_MSG_ERROR:
        a = FIELD_BIT(FTAP_FIELD_ERROR_CODE) |
            FIELD_BIT(FTAP_FIELD_ERROR_TEXT) |
            FIELD_BIT(FTAP_FIELD_RETRY_AFTER_MS);
        r = FIELD_BIT(FTAP_FIELD_ERROR_CODE);
        break;
    case FTAP_MSG_SERVICE_BIND_REQUEST:
        a = FIELD_BIT(FTAP_FIELD_SERVICE_NAME);
        r = a;
        break;
    case FTAP_MSG_AUTH_PASSWORD_REQUEST:
        a = FIELD_BIT(FTAP_FIELD_LOGIN_NAME) |
            FIELD_BIT(FTAP_FIELD_PASSWORD) |
            FIELD_BIT(FTAP_FIELD_PROTOCOL) |
            FIELD_BIT(FTAP_FIELD_SOURCE_IP) |
            FIELD_BIT(FTAP_FIELD_TTY_DEVICE) |
            FIELD_BIT(FTAP_FIELD_NODE_ID) |
            FIELD_BIT(FTAP_FIELD_AUTH_METHOD);
        r = FIELD_BIT(FTAP_FIELD_LOGIN_NAME) |
            FIELD_BIT(FTAP_FIELD_PASSWORD) |
            FIELD_BIT(FTAP_FIELD_PROTOCOL) |
            FIELD_BIT(FTAP_FIELD_AUTH_METHOD);
        break;
    case FTAP_MSG_AUTH_PASSWORD_RESULT:
        a = FIELD_BIT(FTAP_FIELD_USER_ID) |
            FIELD_BIT(FTAP_FIELD_SESSION_ID) |
            FIELD_BIT(FTAP_FIELD_LOGIN_NAME) |
            FIELD_BIT(FTAP_FIELD_DISPLAY_NAME) |
            FIELD_BIT(FTAP_FIELD_AUTH_EPOCH) |
            FIELD_BIT(FTAP_FIELD_AUTHZ_REVISION) |
            FIELD_BIT(FTAP_FIELD_CAPABILITY);
        r = a & ~FIELD_BIT(FTAP_FIELD_CAPABILITY);
        p = FIELD_BIT(FTAP_FIELD_CAPABILITY);
        break;
    case FTAP_MSG_SESSION_CONTEXT_RESULT:
        a = FIELD_BIT(FTAP_FIELD_USER_ID) |
            FIELD_BIT(FTAP_FIELD_SESSION_ID) |
            FIELD_BIT(FTAP_FIELD_LOGIN_NAME) |
            FIELD_BIT(FTAP_FIELD_DISPLAY_NAME) |
            FIELD_BIT(FTAP_FIELD_PROTOCOL) |
            FIELD_BIT(FTAP_FIELD_AUTH_METHOD) |
            FIELD_BIT(FTAP_FIELD_AUTH_EPOCH) |
            FIELD_BIT(FTAP_FIELD_AUTHZ_REVISION) |
            FIELD_BIT(FTAP_FIELD_CAPABILITY);
        r = a & ~FIELD_BIT(FTAP_FIELD_CAPABILITY);
        p = FIELD_BIT(FTAP_FIELD_CAPABILITY);
        break;
    case FTAP_MSG_SESSION_AUTHZ_CHANGED:
        a = FIELD_BIT(FTAP_FIELD_AUTHZ_REVISION);
        r = a;
        break;
    case FTAP_MSG_AUTHZ_CHECK_REQUEST:
        a = FIELD_BIT(FTAP_FIELD_CAPABILITY) |
            FIELD_BIT(FTAP_FIELD_RESOURCE_TYPE) |
            FIELD_BIT(FTAP_FIELD_RESOURCE_ID);
        r = FIELD_BIT(FTAP_FIELD_CAPABILITY);
        if (state == FTAP_STATE_SERVICE_BOUND) {
            a |= FIELD_BIT(FTAP_FIELD_ACCESS_TOKEN);
            r |= FIELD_BIT(FTAP_FIELD_ACCESS_TOKEN);
        }
        break;
    case FTAP_MSG_AUTHZ_CHECK_RESULT:
        a = FIELD_BIT(FTAP_FIELD_AUTHZ_ALLOWED) |
            FIELD_BIT(FTAP_FIELD_AUTHZ_REVISION);
        r = a;
        break;
    case FTAP_MSG_SESSION_CLOSE:
        a = FIELD_BIT(FTAP_FIELD_ENDED_REASON);
        break;
    case FTAP_MSG_SESSION_REVOKED:
        a = FIELD_BIT(FTAP_FIELD_REVOKE_REASON);
        r = a;
        break;
    case FTAP_MSG_TOKEN_CONTEXT_REQUEST:
        a = FIELD_BIT(FTAP_FIELD_ACCESS_TOKEN);
        r = a;
        break;
    case FTAP_MSG_TOKEN_CONTEXT_RESULT:
        a = FIELD_BIT(FTAP_FIELD_USER_ID) |
            FIELD_BIT(FTAP_FIELD_API_SESSION_ID) |
            FIELD_BIT(FTAP_FIELD_LOGIN_NAME) |
            FIELD_BIT(FTAP_FIELD_DISPLAY_NAME) |
            FIELD_BIT(FTAP_FIELD_AUTH_EPOCH) |
            FIELD_BIT(FTAP_FIELD_AUTHZ_REVISION) |
            FIELD_BIT(FTAP_FIELD_CAPABILITY);
        r = a & ~FIELD_BIT(FTAP_FIELD_CAPABILITY);
        p = FIELD_BIT(FTAP_FIELD_CAPABILITY);
        break;
    default:
        return FTAP_STATUS_ERR_INVALID_MESSAGE;
    }

    *allowed = a;
    *required = r;
    *repeatable = p;
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_validate_message(ftap_connection_state_t state,
                      const ftap_frame_header_t *header,
                      const uint8_t *payload,
                      size_t payload_length,
                      ftap_validation_error_t *error)
{
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    ftap_status_t status;
    uint16_t flags;
    uint64_t allowed;
    uint64_t required;
    uint64_t repeatable;
    uint64_t seen = 0;

    set_error(error, FTAP_STATUS_OK, 0, 0);

    if (header == NULL || (payload == NULL && payload_length != 0U)) {
        set_error(error, FTAP_STATUS_ERR_ARGUMENT, 0, 0);
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    if (!ftap_message_type_is_known(header->message_type)) {
        set_error(error, FTAP_STATUS_ERR_INVALID_MESSAGE,
                  header->message_type, 0);
        return FTAP_STATUS_ERR_INVALID_MESSAGE;
    }

    if (header->major != FTAP_VERSION_MAJOR ||
        header->minor > FTAP_VERSION_MINOR) {
        set_error(error, FTAP_STATUS_ERR_VERSION, header->message_type, 0);
        return FTAP_STATUS_ERR_VERSION;
    }

    if (header->payload_length != payload_length ||
        payload_length > FTAP_MAX_PAYLOAD_SIZE) {
        set_error(error, FTAP_STATUS_ERR_LENGTH, header->message_type, 0);
        return FTAP_STATUS_ERR_LENGTH;
    }

    if ((header->flags & (uint16_t)~FTAP_FRAME_FLAG_KNOWN_MASK) != 0U) {
        set_error(error, FTAP_STATUS_ERR_FLAGS, header->message_type, 0);
        return FTAP_STATUS_ERR_FLAGS;
    }

    status = expected_flags(header->message_type, &flags);
    if (status != FTAP_STATUS_OK || header->flags != flags) {
        set_error(error, FTAP_STATUS_ERR_FLAGS, header->message_type, 0);
        return FTAP_STATUS_ERR_FLAGS;
    }

    if ((header->flags & FTAP_FRAME_FLAG_SERVER_PUSH) != 0U) {
        if (header->request_id != FTAP_SERVER_PUSH_REQUEST_ID) {
            set_error(error, FTAP_STATUS_ERR_REQUEST_ID,
                      header->message_type, 0);
            return FTAP_STATUS_ERR_REQUEST_ID;
        }
    } else if (header->request_id < FTAP_FIRST_CLIENT_REQUEST_ID) {
        set_error(error, FTAP_STATUS_ERR_REQUEST_ID,
                  header->message_type, 0);
        return FTAP_STATUS_ERR_REQUEST_ID;
    }

    if (!state_allows_message(state, header->message_type)) {
        set_error(error, FTAP_STATUS_ERR_INVALID_STATE,
                  header->message_type, 0);
        return FTAP_STATUS_ERR_INVALID_STATE;
    }

    status = message_masks(state, header->message_type,
                           &allowed, &required, &repeatable);
    if (status != FTAP_STATUS_OK) {
        set_error(error, status, header->message_type, 0);
        return status;
    }

    status = ftap_tlv_reader_init(&reader, payload, payload_length);
    if (status != FTAP_STATUS_OK) {
        set_error(error, status, header->message_type, 0);
        return status;
    }

    for (;;) {
        uint64_t bit;

        memset(&field, 0, sizeof(field));
        status = ftap_tlv_reader_next(&reader, &field);
        if (status == FTAP_STATUS_DONE) {
            break;
        }
        if (status != FTAP_STATUS_OK) {
            set_error(error, status, header->message_type, field.type);
            return status;
        }

        status = ftap_tlv_check_supported(&field);
        if (status != FTAP_STATUS_OK) {
            set_error(error, status, header->message_type, field.type);
            return status;
        }

        if (!ftap_field_type_is_known(field.type)) {
            continue;
        }

        bit = FIELD_BIT(field.type);
        if ((allowed & bit) == 0U) {
            set_error(error, FTAP_STATUS_ERR_FORBIDDEN_FIELD,
                      header->message_type, field.type);
            return FTAP_STATUS_ERR_FORBIDDEN_FIELD;
        }

        if ((seen & bit) != 0U && (repeatable & bit) == 0U) {
            set_error(error, FTAP_STATUS_ERR_DUPLICATE_FIELD,
                      header->message_type, field.type);
            return FTAP_STATUS_ERR_DUPLICATE_FIELD;
        }

        status = validate_field_value(&field);
        if (status != FTAP_STATUS_OK) {
            set_error(error, status, header->message_type, field.type);
            return status;
        }

        seen |= bit;
    }

    if ((seen & required) != required) {
        uint16_t field_type;
        for (field_type = 1; field_type < 64; ++field_type) {
            uint64_t bit = FIELD_BIT(field_type);
            if ((required & bit) != 0U && (seen & bit) == 0U) {
                set_error(error, FTAP_STATUS_ERR_MISSING_FIELD,
                          header->message_type, field_type);
                break;
            }
        }
        return FTAP_STATUS_ERR_MISSING_FIELD;
    }

    return FTAP_STATUS_OK;
}
