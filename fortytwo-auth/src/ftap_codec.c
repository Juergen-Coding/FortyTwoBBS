/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ftap_codec.h"

#include <limits.h>
#include <string.h>

static uint16_t
read_u16_be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t
read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint64_t
read_u64_be(const uint8_t *p)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; ++i) {
        value = (value << 8) | (uint64_t)p[i];
    }

    return value;
}

static void
write_u16_be(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void
write_u32_be(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void
write_u64_be(uint8_t *p, uint64_t value)
{
    size_t i;

    for (i = 0; i < 8; ++i) {
        p[7 - i] = (uint8_t)value;
        value >>= 8;
    }
}

static ftap_status_t
validate_header_common(const ftap_frame_header_t *header, bool encoding)
{
    if (header == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    if ((header->flags & (uint16_t)~FTAP_FRAME_FLAG_KNOWN_MASK) != 0U) {
        return FTAP_STATUS_ERR_FLAGS;
    }

    if (header->payload_length > FTAP_MAX_PAYLOAD_SIZE) {
        return FTAP_STATUS_ERR_LENGTH;
    }

    if ((header->flags & FTAP_FRAME_FLAG_SERVER_PUSH) != 0U) {
        if (header->request_id != FTAP_SERVER_PUSH_REQUEST_ID) {
            return FTAP_STATUS_ERR_REQUEST_ID;
        }
    } else if (header->request_id < FTAP_FIRST_CLIENT_REQUEST_ID) {
        return FTAP_STATUS_ERR_REQUEST_ID;
    }

    if (encoding &&
        (header->major != FTAP_VERSION_MAJOR ||
         header->minor != FTAP_VERSION_MINOR)) {
        return FTAP_STATUS_ERR_VERSION;
    }

    return FTAP_STATUS_OK;
}

const char *
ftap_status_string(ftap_status_t status)
{
    switch (status) {
    case FTAP_STATUS_OK:
        return "ok";
    case FTAP_STATUS_DONE:
        return "done";
    case FTAP_STATUS_NEWER_MINOR:
        return "newer minor version";
    case FTAP_STATUS_ERR_ARGUMENT:
        return "invalid argument";
    case FTAP_STATUS_ERR_TRUNCATED:
        return "truncated data";
    case FTAP_STATUS_ERR_MAGIC:
        return "invalid magic";
    case FTAP_STATUS_ERR_VERSION:
        return "unsupported version";
    case FTAP_STATUS_ERR_FLAGS:
        return "invalid flags";
    case FTAP_STATUS_ERR_LENGTH:
        return "invalid length";
    case FTAP_STATUS_ERR_OVERFLOW:
        return "integer overflow";
    case FTAP_STATUS_ERR_ENCODING:
        return "invalid text encoding";
    case FTAP_STATUS_ERR_UNSUPPORTED_FIELD:
        return "unsupported critical field";
    case FTAP_STATUS_ERR_DUPLICATE_FIELD:
        return "duplicate field";
    case FTAP_STATUS_ERR_FORBIDDEN_FIELD:
        return "forbidden field";
    case FTAP_STATUS_ERR_MISSING_FIELD:
        return "missing required field";
    case FTAP_STATUS_ERR_INVALID_STATE:
        return "invalid connection state";
    case FTAP_STATUS_ERR_INVALID_MESSAGE:
        return "invalid message";
    case FTAP_STATUS_ERR_INVALID_VALUE:
        return "invalid field value";
    case FTAP_STATUS_ERR_REQUEST_ID:
        return "invalid request id";
    case FTAP_STATUS_ERR_CAPACITY:
        return "insufficient buffer capacity";
    default:
        return "unknown status";
    }
}

bool
ftap_message_type_is_known(uint16_t message_type)
{
    switch (message_type) {
    case FTAP_MSG_HELLO:
    case FTAP_MSG_HELLO_OK:
    case FTAP_MSG_ERROR:
    case FTAP_MSG_SERVICE_BIND_REQUEST:
    case FTAP_MSG_SERVICE_BIND_RESULT:
    case FTAP_MSG_AUTH_PASSWORD_REQUEST:
    case FTAP_MSG_AUTH_PASSWORD_RESULT:
    case FTAP_MSG_SESSION_CONTEXT_REQUEST:
    case FTAP_MSG_SESSION_CONTEXT_RESULT:
    case FTAP_MSG_SESSION_HEARTBEAT:
    case FTAP_MSG_SESSION_AUTHZ_CHANGED:
    case FTAP_MSG_AUTHZ_CHECK_REQUEST:
    case FTAP_MSG_AUTHZ_CHECK_RESULT:
    case FTAP_MSG_SESSION_CLOSE:
    case FTAP_MSG_SESSION_REVOKED:
    case FTAP_MSG_TOKEN_CONTEXT_REQUEST:
    case FTAP_MSG_TOKEN_CONTEXT_RESULT:
        return true;
    default:
        return false;
    }
}

bool
ftap_field_type_is_known(uint16_t field_type)
{
    switch (field_type) {
    case FTAP_FIELD_CLIENT_NAME:
    case FTAP_FIELD_CLIENT_VERSION:
    case FTAP_FIELD_SUPPORTED_MAJOR:
    case FTAP_FIELD_SUPPORTED_MINOR:
    case FTAP_FIELD_SERVICE_NAME:
    case FTAP_FIELD_LOGIN_NAME:
    case FTAP_FIELD_PASSWORD:
    case FTAP_FIELD_PROTOCOL:
    case FTAP_FIELD_SOURCE_IP:
    case FTAP_FIELD_TTY_DEVICE:
    case FTAP_FIELD_NODE_ID:
    case FTAP_FIELD_AUTH_METHOD:
    case FTAP_FIELD_USER_ID:
    case FTAP_FIELD_SESSION_ID:
    case FTAP_FIELD_DISPLAY_NAME:
    case FTAP_FIELD_ACCOUNT_STATE:
    case FTAP_FIELD_AUTH_EPOCH:
    case FTAP_FIELD_AUTHZ_REVISION:
    case FTAP_FIELD_CAPABILITY:
    case FTAP_FIELD_RESOURCE_TYPE:
    case FTAP_FIELD_RESOURCE_ID:
    case FTAP_FIELD_AUTHZ_ALLOWED:
    case FTAP_FIELD_ENDED_REASON:
    case FTAP_FIELD_REVOKE_REASON:
    case FTAP_FIELD_ERROR_CODE:
    case FTAP_FIELD_ERROR_TEXT:
    case FTAP_FIELD_RETRY_AFTER_MS:
    case FTAP_FIELD_ACCESS_TOKEN:
    case FTAP_FIELD_API_SESSION_ID:
        return true;
    default:
        return false;
    }
}

ftap_status_t
ftap_frame_header_encode(uint8_t output[FTAP_FRAME_HEADER_SIZE],
                         const ftap_frame_header_t *header)
{
    ftap_status_t status;

    if (output == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    status = validate_header_common(header, true);
    if (status != FTAP_STATUS_OK) {
        return status;
    }

    output[0] = (uint8_t)'F';
    output[1] = (uint8_t)'T';
    output[2] = (uint8_t)'A';
    output[3] = (uint8_t)'P';
    write_u16_be(output + FTAP_HEADER_MAJOR_OFFSET, header->major);
    write_u16_be(output + FTAP_HEADER_MINOR_OFFSET, header->minor);
    write_u16_be(output + FTAP_HEADER_MESSAGE_TYPE_OFFSET,
                 header->message_type);
    write_u16_be(output + FTAP_HEADER_FLAGS_OFFSET, header->flags);
    write_u32_be(output + FTAP_HEADER_PAYLOAD_LENGTH_OFFSET,
                 header->payload_length);
    write_u64_be(output + FTAP_HEADER_REQUEST_ID_OFFSET,
                 header->request_id);

    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_frame_header_decode(const uint8_t *input,
                         size_t input_length,
                         ftap_frame_header_t *header)
{
    ftap_status_t status;

    if (input == NULL || header == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    if (input_length < FTAP_FRAME_HEADER_SIZE) {
        return FTAP_STATUS_ERR_TRUNCATED;
    }

    if (input[0] != (uint8_t)'F' || input[1] != (uint8_t)'T' ||
        input[2] != (uint8_t)'A' || input[3] != (uint8_t)'P') {
        return FTAP_STATUS_ERR_MAGIC;
    }

    header->major = read_u16_be(input + FTAP_HEADER_MAJOR_OFFSET);
    header->minor = read_u16_be(input + FTAP_HEADER_MINOR_OFFSET);
    header->message_type =
        read_u16_be(input + FTAP_HEADER_MESSAGE_TYPE_OFFSET);
    header->flags = read_u16_be(input + FTAP_HEADER_FLAGS_OFFSET);
    header->payload_length =
        read_u32_be(input + FTAP_HEADER_PAYLOAD_LENGTH_OFFSET);
    header->request_id =
        read_u64_be(input + FTAP_HEADER_REQUEST_ID_OFFSET);

    status = validate_header_common(header, false);
    if (status != FTAP_STATUS_OK) {
        return status;
    }

    if (header->major != FTAP_VERSION_MAJOR) {
        return FTAP_STATUS_ERR_VERSION;
    }

    if (header->minor > FTAP_VERSION_MINOR) {
        return FTAP_STATUS_NEWER_MINOR;
    }

    return FTAP_STATUS_OK;
}

bool
ftap_utf8_text_is_valid(const uint8_t *text, size_t length)
{
    size_t i = 0;

    if (text == NULL && length != 0U) {
        return false;
    }

    while (i < length) {
        uint8_t c = text[i];

        if (c == 0U) {
            return false;
        }

        if (c <= 0x7fU) {
            ++i;
            continue;
        }

        if (c >= 0xc2U && c <= 0xdfU) {
            if (i + 1U >= length ||
                text[i + 1U] < 0x80U || text[i + 1U] > 0xbfU) {
                return false;
            }
            i += 2U;
            continue;
        }

        if (c == 0xe0U) {
            if (i + 2U >= length ||
                text[i + 1U] < 0xa0U || text[i + 1U] > 0xbfU ||
                text[i + 2U] < 0x80U || text[i + 2U] > 0xbfU) {
                return false;
            }
            i += 3U;
            continue;
        }

        if ((c >= 0xe1U && c <= 0xecU) ||
            (c >= 0xeeU && c <= 0xefU)) {
            if (i + 2U >= length ||
                text[i + 1U] < 0x80U || text[i + 1U] > 0xbfU ||
                text[i + 2U] < 0x80U || text[i + 2U] > 0xbfU) {
                return false;
            }
            i += 3U;
            continue;
        }

        if (c == 0xedU) {
            if (i + 2U >= length ||
                text[i + 1U] < 0x80U || text[i + 1U] > 0x9fU ||
                text[i + 2U] < 0x80U || text[i + 2U] > 0xbfU) {
                return false;
            }
            i += 3U;
            continue;
        }

        if (c == 0xf0U) {
            if (i + 3U >= length ||
                text[i + 1U] < 0x90U || text[i + 1U] > 0xbfU ||
                text[i + 2U] < 0x80U || text[i + 2U] > 0xbfU ||
                text[i + 3U] < 0x80U || text[i + 3U] > 0xbfU) {
                return false;
            }
            i += 4U;
            continue;
        }

        if (c >= 0xf1U && c <= 0xf3U) {
            if (i + 3U >= length ||
                text[i + 1U] < 0x80U || text[i + 1U] > 0xbfU ||
                text[i + 2U] < 0x80U || text[i + 2U] > 0xbfU ||
                text[i + 3U] < 0x80U || text[i + 3U] > 0xbfU) {
                return false;
            }
            i += 4U;
            continue;
        }

        if (c == 0xf4U) {
            if (i + 3U >= length ||
                text[i + 1U] < 0x80U || text[i + 1U] > 0x8fU ||
                text[i + 2U] < 0x80U || text[i + 2U] > 0xbfU ||
                text[i + 3U] < 0x80U || text[i + 3U] > 0xbfU) {
                return false;
            }
            i += 4U;
            continue;
        }

        return false;
    }

    return true;
}

ftap_status_t
ftap_tlv_writer_init(ftap_tlv_writer_t *writer,
                     uint8_t *buffer,
                     size_t capacity)
{
    if (writer == NULL || (buffer == NULL && capacity != 0U)) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    writer->buffer = buffer;
    writer->capacity = capacity;
    writer->length = 0;
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_writer_put(ftap_tlv_writer_t *writer,
                    uint16_t type,
                    uint16_t flags,
                    const void *value,
                    size_t value_length)
{
    size_t needed;
    uint8_t *destination;

    if (writer == NULL || type == 0U ||
        (value == NULL && value_length != 0U)) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    if ((flags & (uint16_t)~FTAP_FIELD_FLAG_KNOWN_MASK) != 0U) {
        return FTAP_STATUS_ERR_FLAGS;
    }

    if (value_length > UINT32_MAX) {
        return FTAP_STATUS_ERR_LENGTH;
    }

    if (value_length > SIZE_MAX - FTAP_TLV_HEADER_SIZE) {
        return FTAP_STATUS_ERR_OVERFLOW;
    }
    needed = FTAP_TLV_HEADER_SIZE + value_length;

    if (writer->length > FTAP_MAX_PAYLOAD_SIZE ||
        needed > FTAP_MAX_PAYLOAD_SIZE - writer->length) {
        return FTAP_STATUS_ERR_LENGTH;
    }

    if (writer->length > writer->capacity ||
        needed > writer->capacity - writer->length) {
        return FTAP_STATUS_ERR_CAPACITY;
    }

    destination = writer->buffer + writer->length;
    write_u16_be(destination, type);
    write_u16_be(destination + 2, flags);
    write_u32_be(destination + 4, (uint32_t)value_length);
    if (value_length != 0U) {
        memcpy(destination + FTAP_TLV_HEADER_SIZE, value, value_length);
    }

    writer->length += needed;
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_writer_put_text(ftap_tlv_writer_t *writer,
                         uint16_t type,
                         uint16_t flags,
                         const uint8_t *text,
                         size_t text_length,
                         size_t maximum_length)
{
    if (text_length > maximum_length) {
        return FTAP_STATUS_ERR_LENGTH;
    }

    if (!ftap_utf8_text_is_valid(text, text_length)) {
        return FTAP_STATUS_ERR_ENCODING;
    }

    return ftap_tlv_writer_put(writer, type, flags, text, text_length);
}

ftap_status_t
ftap_tlv_writer_put_u16(ftap_tlv_writer_t *writer,
                        uint16_t type,
                        uint16_t flags,
                        uint16_t value)
{
    uint8_t encoded[2];
    write_u16_be(encoded, value);
    return ftap_tlv_writer_put(writer, type, flags, encoded, sizeof(encoded));
}

ftap_status_t
ftap_tlv_writer_put_u32(ftap_tlv_writer_t *writer,
                        uint16_t type,
                        uint16_t flags,
                        uint32_t value)
{
    uint8_t encoded[4];
    write_u32_be(encoded, value);
    return ftap_tlv_writer_put(writer, type, flags, encoded, sizeof(encoded));
}

ftap_status_t
ftap_tlv_writer_put_u64(ftap_tlv_writer_t *writer,
                        uint16_t type,
                        uint16_t flags,
                        uint64_t value)
{
    uint8_t encoded[8];
    write_u64_be(encoded, value);
    return ftap_tlv_writer_put(writer, type, flags, encoded, sizeof(encoded));
}

ftap_status_t
ftap_tlv_writer_put_bool(ftap_tlv_writer_t *writer,
                         uint16_t type,
                         uint16_t flags,
                         bool value)
{
    uint8_t encoded = value ? 1U : 0U;
    return ftap_tlv_writer_put(writer, type, flags, &encoded, sizeof(encoded));
}

ftap_status_t
ftap_tlv_writer_put_uuid(ftap_tlv_writer_t *writer,
                         uint16_t type,
                         uint16_t flags,
                         const uint8_t uuid[FTAP_UUID_SIZE])
{
    if (uuid == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }
    return ftap_tlv_writer_put(writer, type, flags, uuid, FTAP_UUID_SIZE);
}

ftap_status_t
ftap_tlv_reader_init(ftap_tlv_reader_t *reader,
                     const uint8_t *buffer,
                     size_t length)
{
    if (reader == NULL || (buffer == NULL && length != 0U)) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    if (length > FTAP_MAX_PAYLOAD_SIZE) {
        return FTAP_STATUS_ERR_LENGTH;
    }

    reader->buffer = buffer;
    reader->length = length;
    reader->offset = 0;
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_reader_next(ftap_tlv_reader_t *reader, ftap_tlv_t *field)
{
    size_t remaining;
    uint32_t value_length;

    if (reader == NULL || field == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    if (reader->offset == reader->length) {
        return FTAP_STATUS_DONE;
    }

    if (reader->offset > reader->length) {
        return FTAP_STATUS_ERR_OVERFLOW;
    }

    remaining = reader->length - reader->offset;
    if (remaining < FTAP_TLV_HEADER_SIZE) {
        return FTAP_STATUS_ERR_TRUNCATED;
    }

    field->type = read_u16_be(reader->buffer + reader->offset);
    field->flags = read_u16_be(reader->buffer + reader->offset + 2);
    value_length = read_u32_be(reader->buffer + reader->offset + 4);
    field->length = value_length;

    if (field->type == 0U) {
        return FTAP_STATUS_ERR_INVALID_VALUE;
    }

    if ((field->flags & (uint16_t)~FTAP_FIELD_FLAG_KNOWN_MASK) != 0U) {
        return FTAP_STATUS_ERR_FLAGS;
    }

    if ((size_t)value_length > remaining - FTAP_TLV_HEADER_SIZE) {
        return FTAP_STATUS_ERR_TRUNCATED;
    }

    field->value = reader->buffer + reader->offset + FTAP_TLV_HEADER_SIZE;
    reader->offset += FTAP_TLV_HEADER_SIZE + (size_t)value_length;
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_check_supported(const ftap_tlv_t *field)
{
    if (field == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }

    if (!ftap_field_type_is_known(field->type) &&
        (field->flags & FTAP_FIELD_FLAG_CRITICAL) != 0U) {
        return FTAP_STATUS_ERR_UNSUPPORTED_FIELD;
    }

    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_get_u16(const ftap_tlv_t *field, uint16_t *value)
{
    if (field == NULL || value == NULL || field->value == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }
    if (field->length != 2U) {
        return FTAP_STATUS_ERR_LENGTH;
    }
    *value = read_u16_be(field->value);
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_get_u32(const ftap_tlv_t *field, uint32_t *value)
{
    if (field == NULL || value == NULL || field->value == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }
    if (field->length != 4U) {
        return FTAP_STATUS_ERR_LENGTH;
    }
    *value = read_u32_be(field->value);
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_get_u64(const ftap_tlv_t *field, uint64_t *value)
{
    if (field == NULL || value == NULL || field->value == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }
    if (field->length != 8U) {
        return FTAP_STATUS_ERR_LENGTH;
    }
    *value = read_u64_be(field->value);
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_get_bool(const ftap_tlv_t *field, bool *value)
{
    if (field == NULL || value == NULL || field->value == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }
    if (field->length != FTAP_BOOLEAN_SIZE ||
        (field->value[0] != 0U && field->value[0] != 1U)) {
        return FTAP_STATUS_ERR_INVALID_VALUE;
    }
    *value = field->value[0] == 1U;
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_get_uuid(const ftap_tlv_t *field,
                  uint8_t uuid[FTAP_UUID_SIZE])
{
    if (field == NULL || uuid == NULL || field->value == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }
    if (field->length != FTAP_UUID_SIZE) {
        return FTAP_STATUS_ERR_LENGTH;
    }
    memcpy(uuid, field->value, FTAP_UUID_SIZE);
    return FTAP_STATUS_OK;
}

ftap_status_t
ftap_tlv_get_text(const ftap_tlv_t *field,
                  const uint8_t **text,
                  size_t *text_length,
                  size_t maximum_length)
{
    if (field == NULL || text == NULL || text_length == NULL) {
        return FTAP_STATUS_ERR_ARGUMENT;
    }
    if ((size_t)field->length > maximum_length) {
        return FTAP_STATUS_ERR_LENGTH;
    }
    if (!ftap_utf8_text_is_valid(field->value, field->length)) {
        return FTAP_STATUS_ERR_ENCODING;
    }
    *text = field->value;
    *text_length = field->length;
    return FTAP_STATUS_OK;
}
