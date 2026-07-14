/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ftap_schema.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARRAY_COUNT(array_) (sizeof(array_) / sizeof((array_)[0]))
#define FTAP_SCHEMA_MAX_RULES_PER_MESSAGE 16U

/*
 * Cardinality is indexed by a rule's position, never by the numeric field ID.
 * Field IDs therefore retain the full uint16_t namespace, including values
 * above 63 that may be introduced by later protocol versions.
 */
typedef struct ftap_field_rule {
    uint16_t type;
    bool required;
    bool repeatable;
} ftap_field_rule_t;

typedef struct ftap_message_schema {
    const ftap_field_rule_t *rules;
    size_t rule_count;
} ftap_message_schema_t;

#define RULE_REQUIRED(field_)   { (field_), true, false }
#define RULE_OPTIONAL(field_)   { (field_), false, false }
#define RULE_REPEATABLE(field_) { (field_), false, true }
#define ASSERT_RULE_COUNT(name_)                                             \
    _Static_assert(ARRAY_COUNT(name_) <= FTAP_SCHEMA_MAX_RULES_PER_MESSAGE,  \
                   #name_ " exceeds FTAP_SCHEMA_MAX_RULES_PER_MESSAGE")

static const ftap_field_rule_t hello_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_CLIENT_NAME),
    RULE_REQUIRED(FTAP_FIELD_CLIENT_VERSION),
    RULE_REQUIRED(FTAP_FIELD_SUPPORTED_MAJOR),
    RULE_REQUIRED(FTAP_FIELD_SUPPORTED_MINOR)
};

static const ftap_field_rule_t error_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_ERROR_CODE),
    RULE_OPTIONAL(FTAP_FIELD_ERROR_TEXT),
    RULE_OPTIONAL(FTAP_FIELD_RETRY_AFTER_MS)
};

static const ftap_field_rule_t service_bind_request_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_SERVICE_NAME)
};

static const ftap_field_rule_t auth_password_request_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_LOGIN_NAME),
    RULE_REQUIRED(FTAP_FIELD_PASSWORD),
    RULE_REQUIRED(FTAP_FIELD_PROTOCOL),
    RULE_OPTIONAL(FTAP_FIELD_SOURCE_IP),
    RULE_OPTIONAL(FTAP_FIELD_TTY_DEVICE),
    RULE_OPTIONAL(FTAP_FIELD_NODE_ID),
    RULE_REQUIRED(FTAP_FIELD_AUTH_METHOD)
};

static const ftap_field_rule_t auth_password_result_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_USER_ID),
    RULE_REQUIRED(FTAP_FIELD_SESSION_ID),
    RULE_REQUIRED(FTAP_FIELD_LOGIN_NAME),
    RULE_REQUIRED(FTAP_FIELD_DISPLAY_NAME),
    RULE_REQUIRED(FTAP_FIELD_LEGACY_NAME),
    RULE_REQUIRED(FTAP_FIELD_AUTH_EPOCH),
    RULE_REQUIRED(FTAP_FIELD_AUTHZ_REVISION),
    RULE_REPEATABLE(FTAP_FIELD_CAPABILITY)
};

static const ftap_field_rule_t session_context_result_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_USER_ID),
    RULE_REQUIRED(FTAP_FIELD_SESSION_ID),
    RULE_REQUIRED(FTAP_FIELD_LOGIN_NAME),
    RULE_REQUIRED(FTAP_FIELD_DISPLAY_NAME),
    RULE_REQUIRED(FTAP_FIELD_LEGACY_NAME),
    RULE_REQUIRED(FTAP_FIELD_PROTOCOL),
    RULE_REQUIRED(FTAP_FIELD_AUTH_METHOD),
    RULE_REQUIRED(FTAP_FIELD_AUTH_EPOCH),
    RULE_REQUIRED(FTAP_FIELD_AUTHZ_REVISION),
    RULE_REPEATABLE(FTAP_FIELD_CAPABILITY)
};

static const ftap_field_rule_t session_authz_changed_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_AUTHZ_REVISION)
};

static const ftap_field_rule_t session_authz_check_request_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_CAPABILITY),
    RULE_OPTIONAL(FTAP_FIELD_RESOURCE_TYPE),
    RULE_OPTIONAL(FTAP_FIELD_RESOURCE_ID)
};

static const ftap_field_rule_t service_authz_check_request_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_ACCESS_TOKEN),
    RULE_REQUIRED(FTAP_FIELD_CAPABILITY),
    RULE_OPTIONAL(FTAP_FIELD_RESOURCE_TYPE),
    RULE_OPTIONAL(FTAP_FIELD_RESOURCE_ID)
};

static const ftap_field_rule_t authz_check_result_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_AUTHZ_ALLOWED),
    RULE_REQUIRED(FTAP_FIELD_AUTHZ_REVISION)
};

static const ftap_field_rule_t session_close_rules[] = {
    RULE_OPTIONAL(FTAP_FIELD_ENDED_REASON)
};

static const ftap_field_rule_t session_revoked_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_REVOKE_REASON)
};

static const ftap_field_rule_t token_context_request_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_ACCESS_TOKEN)
};

static const ftap_field_rule_t token_context_result_rules[] = {
    RULE_REQUIRED(FTAP_FIELD_USER_ID),
    RULE_REQUIRED(FTAP_FIELD_API_SESSION_ID),
    RULE_REQUIRED(FTAP_FIELD_LOGIN_NAME),
    RULE_REQUIRED(FTAP_FIELD_DISPLAY_NAME),
    RULE_REQUIRED(FTAP_FIELD_AUTH_EPOCH),
    RULE_REQUIRED(FTAP_FIELD_AUTHZ_REVISION),
    RULE_REPEATABLE(FTAP_FIELD_CAPABILITY)
};

ASSERT_RULE_COUNT(hello_rules);
ASSERT_RULE_COUNT(error_rules);
ASSERT_RULE_COUNT(service_bind_request_rules);
ASSERT_RULE_COUNT(auth_password_request_rules);
ASSERT_RULE_COUNT(auth_password_result_rules);
ASSERT_RULE_COUNT(session_context_result_rules);
ASSERT_RULE_COUNT(session_authz_changed_rules);
ASSERT_RULE_COUNT(session_authz_check_request_rules);
ASSERT_RULE_COUNT(service_authz_check_request_rules);
ASSERT_RULE_COUNT(authz_check_result_rules);
ASSERT_RULE_COUNT(session_close_rules);
ASSERT_RULE_COUNT(session_revoked_rules);
ASSERT_RULE_COUNT(token_context_request_rules);
ASSERT_RULE_COUNT(token_context_result_rules);

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

static bool
is_reason_first_character(uint8_t character)
{
    return character >= (uint8_t)'a' && character <= (uint8_t)'z';
}

static bool
is_reason_character(uint8_t character)
{
    return is_reason_first_character(character) ||
           (character >= (uint8_t)'0' && character <= (uint8_t)'9') ||
           character == (uint8_t)'.' ||
           character == (uint8_t)'-' ||
           character == (uint8_t)'_';
}

static bool
is_legacy_name_first_character(uint8_t character)
{
    return (character >= (uint8_t)'a' && character <= (uint8_t)'z') ||
           (character >= (uint8_t)'0' && character <= (uint8_t)'9');
}

static bool
is_legacy_name_character(uint8_t character)
{
    return is_legacy_name_first_character(character) ||
           character == (uint8_t)'.' ||
           character == (uint8_t)'_' ||
           character == (uint8_t)'-';
}

/* The legacy record key is an exact, lower-case ASCII filesystem component. */
static ftap_status_t
validate_legacy_name(const ftap_tlv_t *field)
{
    size_t i;
    ftap_status_t status;

    status = validate_text(field, FTAP_LEGACY_NAME_MAX, false);
    if (status != FTAP_STATUS_OK) {
        return status;
    }
    if (!is_legacy_name_first_character(field->value[0])) {
        return FTAP_STATUS_ERR_INVALID_VALUE;
    }
    for (i = 1U; i < field->length; ++i) {
        if (!is_legacy_name_character(field->value[i])) {
            return FTAP_STATUS_ERR_INVALID_VALUE;
        }
    }
    return FTAP_STATUS_OK;
}

static ftap_status_t
validate_reason(const ftap_tlv_t *field, size_t maximum)
{
    size_t i;
    ftap_status_t status;

    status = validate_text(field, maximum, false);
    if (status != FTAP_STATUS_OK) {
        return status;
    }

    if (!is_reason_first_character(field->value[0])) {
        return FTAP_STATUS_ERR_INVALID_VALUE;
    }

    for (i = 1U; i < field->length; ++i) {
        if (!is_reason_character(field->value[i])) {
            return FTAP_STATUS_ERR_INVALID_VALUE;
        }
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
    case FTAP_FIELD_LEGACY_NAME:
        return validate_legacy_name(field);
    case FTAP_FIELD_AUTH_EPOCH:
    case FTAP_FIELD_AUTHZ_REVISION:
        return ftap_tlv_get_u64(field, &u64_value);
    case FTAP_FIELD_CAPABILITY:
        return validate_text(field, FTAP_CAPABILITY_NAME_MAX, false);
    case FTAP_FIELD_RESOURCE_TYPE:
        return validate_text(field, FTAP_RESOURCE_TYPE_MAX, false);
    case FTAP_FIELD_RESOURCE_ID:
        return validate_text(field, FTAP_RESOURCE_ID_MAX, false);
    case FTAP_FIELD_AUTHZ_ALLOWED:
        return ftap_tlv_get_bool(field, &bool_value);
    case FTAP_FIELD_ENDED_REASON:
        return validate_reason(field, FTAP_ENDED_REASON_MAX);
    case FTAP_FIELD_REVOKE_REASON:
        return validate_reason(field, FTAP_REVOKE_REASON_MAX);
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
message_schema(ftap_connection_state_t state,
               uint16_t message_type,
               ftap_message_schema_t *schema)
{
    if (schema == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    schema->rules = NULL;
    schema->rule_count = 0U;

    switch (message_type) {
    case FTAP_MSG_HELLO:
        schema->rules = hello_rules;
        schema->rule_count = ARRAY_COUNT(hello_rules);
        break;
    case FTAP_MSG_HELLO_OK:
    case FTAP_MSG_SERVICE_BIND_RESULT:
    case FTAP_MSG_SESSION_CONTEXT_REQUEST:
    case FTAP_MSG_SESSION_HEARTBEAT:
        break;
    case FTAP_MSG_ERROR:
        schema->rules = error_rules;
        schema->rule_count = ARRAY_COUNT(error_rules);
        break;
    case FTAP_MSG_SERVICE_BIND_REQUEST:
        schema->rules = service_bind_request_rules;
        schema->rule_count = ARRAY_COUNT(service_bind_request_rules);
        break;
    case FTAP_MSG_AUTH_PASSWORD_REQUEST:
        schema->rules = auth_password_request_rules;
        schema->rule_count = ARRAY_COUNT(auth_password_request_rules);
        break;
    case FTAP_MSG_AUTH_PASSWORD_RESULT:
        schema->rules = auth_password_result_rules;
        schema->rule_count = ARRAY_COUNT(auth_password_result_rules);
        break;
    case FTAP_MSG_SESSION_CONTEXT_RESULT:
        schema->rules = session_context_result_rules;
        schema->rule_count = ARRAY_COUNT(session_context_result_rules);
        break;
    case FTAP_MSG_SESSION_AUTHZ_CHANGED:
        schema->rules = session_authz_changed_rules;
        schema->rule_count = ARRAY_COUNT(session_authz_changed_rules);
        break;
    case FTAP_MSG_AUTHZ_CHECK_REQUEST:
        if (state == FTAP_STATE_SERVICE_BOUND) {
            schema->rules = service_authz_check_request_rules;
            schema->rule_count = ARRAY_COUNT(service_authz_check_request_rules);
        } else {
            schema->rules = session_authz_check_request_rules;
            schema->rule_count = ARRAY_COUNT(session_authz_check_request_rules);
        }
        break;
    case FTAP_MSG_AUTHZ_CHECK_RESULT:
        schema->rules = authz_check_result_rules;
        schema->rule_count = ARRAY_COUNT(authz_check_result_rules);
        break;
    case FTAP_MSG_SESSION_CLOSE:
        schema->rules = session_close_rules;
        schema->rule_count = ARRAY_COUNT(session_close_rules);
        break;
    case FTAP_MSG_SESSION_REVOKED:
        schema->rules = session_revoked_rules;
        schema->rule_count = ARRAY_COUNT(session_revoked_rules);
        break;
    case FTAP_MSG_TOKEN_CONTEXT_REQUEST:
        schema->rules = token_context_request_rules;
        schema->rule_count = ARRAY_COUNT(token_context_request_rules);
        break;
    case FTAP_MSG_TOKEN_CONTEXT_RESULT:
        schema->rules = token_context_result_rules;
        schema->rule_count = ARRAY_COUNT(token_context_result_rules);
        break;
    default:
        return FTAP_STATUS_ERR_INVALID_MESSAGE;
    }

    return FTAP_STATUS_OK;
}

static const ftap_field_rule_t *
find_rule(const ftap_message_schema_t *schema,
          uint16_t field_type,
          size_t *rule_index)
{
    size_t i;

    if (schema == NULL || rule_index == NULL || schema->rules == NULL) {
        return NULL;
    }

    for (i = 0U; i < schema->rule_count; ++i) {
        if (schema->rules[i].type == field_type) {
            *rule_index = i;
            return &schema->rules[i];
        }
    }

    return NULL;
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
    ftap_message_schema_t schema;
    bool seen[FTAP_SCHEMA_MAX_RULES_PER_MESSAGE] = { false };
    ftap_status_t status;
    uint16_t flags;
    size_t i;

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

    status = message_schema(state, header->message_type, &schema);
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
        const ftap_field_rule_t *rule;
        size_t rule_index;

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

        rule = find_rule(&schema, field.type, &rule_index);
        if (rule == NULL) {
            set_error(error, FTAP_STATUS_ERR_FORBIDDEN_FIELD,
                      header->message_type, field.type);
            return FTAP_STATUS_ERR_FORBIDDEN_FIELD;
        }

        if (seen[rule_index] && !rule->repeatable) {
            set_error(error, FTAP_STATUS_ERR_DUPLICATE_FIELD,
                      header->message_type, field.type);
            return FTAP_STATUS_ERR_DUPLICATE_FIELD;
        }

        status = validate_field_value(&field);
        if (status != FTAP_STATUS_OK) {
            set_error(error, status, header->message_type, field.type);
            return status;
        }

        seen[rule_index] = true;
    }

    for (i = 0U; i < schema.rule_count; ++i) {
        if (schema.rules[i].required && !seen[i]) {
            set_error(error, FTAP_STATUS_ERR_MISSING_FIELD,
                      header->message_type, schema.rules[i].type);
            return FTAP_STATUS_ERR_MISSING_FIELD;
        }
    }

    return FTAP_STATUS_OK;
}
