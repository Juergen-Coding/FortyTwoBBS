/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Safe field-by-field codec for FTAP 1.1.
 *
 * This interface never casts native C structures onto wire data and never
 * allocates memory. Callers own all input and output buffers.
 */

#ifndef FORTYTWO_FTAP_CODEC_H
#define FORTYTWO_FTAP_CODEC_H

#include "ftap_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum ftap_status {
    FTAP_STATUS_OK = 0,
    FTAP_STATUS_DONE = 1,
    FTAP_STATUS_NEWER_MINOR = 2,

    FTAP_STATUS_ERR_ARGUMENT = -1,
    FTAP_STATUS_ERR_TRUNCATED = -2,
    FTAP_STATUS_ERR_MAGIC = -3,
    FTAP_STATUS_ERR_VERSION = -4,
    FTAP_STATUS_ERR_FLAGS = -5,
    FTAP_STATUS_ERR_LENGTH = -6,
    FTAP_STATUS_ERR_OVERFLOW = -7,
    FTAP_STATUS_ERR_ENCODING = -8,
    FTAP_STATUS_ERR_UNSUPPORTED_FIELD = -9,
    FTAP_STATUS_ERR_DUPLICATE_FIELD = -10,
    FTAP_STATUS_ERR_FORBIDDEN_FIELD = -11,
    FTAP_STATUS_ERR_MISSING_FIELD = -12,
    FTAP_STATUS_ERR_INVALID_STATE = -13,
    FTAP_STATUS_ERR_INVALID_MESSAGE = -14,
    FTAP_STATUS_ERR_INVALID_VALUE = -15,
    FTAP_STATUS_ERR_REQUEST_ID = -16,
    FTAP_STATUS_ERR_CAPACITY = -17
} ftap_status_t;

/* Host-side representation only. Never write this structure to a socket. */
typedef struct ftap_frame_header {
    uint16_t major;
    uint16_t minor;
    uint16_t message_type;
    uint16_t flags;
    uint32_t payload_length;
    uint64_t request_id;
} ftap_frame_header_t;

typedef struct ftap_tlv {
    uint16_t type;
    uint16_t flags;
    const uint8_t *value;
    uint32_t length;
} ftap_tlv_t;

typedef struct ftap_tlv_writer {
    uint8_t *buffer;
    size_t capacity;
    size_t length;
} ftap_tlv_writer_t;

typedef struct ftap_tlv_reader {
    const uint8_t *buffer;
    size_t length;
    size_t offset;
} ftap_tlv_reader_t;

const char *ftap_status_string(ftap_status_t status);

bool ftap_message_type_is_known(uint16_t message_type);
bool ftap_field_type_is_known(uint16_t field_type);

ftap_status_t ftap_frame_header_encode(
    uint8_t output[FTAP_FRAME_HEADER_SIZE],
    const ftap_frame_header_t *header);

ftap_status_t ftap_frame_header_decode(
    const uint8_t *input,
    size_t input_length,
    ftap_frame_header_t *header);

bool ftap_utf8_text_is_valid(const uint8_t *text, size_t length);

ftap_status_t ftap_tlv_writer_init(
    ftap_tlv_writer_t *writer,
    uint8_t *buffer,
    size_t capacity);

ftap_status_t ftap_tlv_writer_put(
    ftap_tlv_writer_t *writer,
    uint16_t type,
    uint16_t flags,
    const void *value,
    size_t value_length);

ftap_status_t ftap_tlv_writer_put_text(
    ftap_tlv_writer_t *writer,
    uint16_t type,
    uint16_t flags,
    const uint8_t *text,
    size_t text_length,
    size_t maximum_length);

ftap_status_t ftap_tlv_writer_put_u16(
    ftap_tlv_writer_t *writer,
    uint16_t type,
    uint16_t flags,
    uint16_t value);

ftap_status_t ftap_tlv_writer_put_u32(
    ftap_tlv_writer_t *writer,
    uint16_t type,
    uint16_t flags,
    uint32_t value);

ftap_status_t ftap_tlv_writer_put_u64(
    ftap_tlv_writer_t *writer,
    uint16_t type,
    uint16_t flags,
    uint64_t value);

ftap_status_t ftap_tlv_writer_put_bool(
    ftap_tlv_writer_t *writer,
    uint16_t type,
    uint16_t flags,
    bool value);

ftap_status_t ftap_tlv_writer_put_uuid(
    ftap_tlv_writer_t *writer,
    uint16_t type,
    uint16_t flags,
    const uint8_t uuid[FTAP_UUID_SIZE]);

ftap_status_t ftap_tlv_reader_init(
    ftap_tlv_reader_t *reader,
    const uint8_t *buffer,
    size_t length);

ftap_status_t ftap_tlv_reader_next(
    ftap_tlv_reader_t *reader,
    ftap_tlv_t *field);

ftap_status_t ftap_tlv_check_supported(const ftap_tlv_t *field);
ftap_status_t ftap_tlv_get_u16(const ftap_tlv_t *field, uint16_t *value);
ftap_status_t ftap_tlv_get_u32(const ftap_tlv_t *field, uint32_t *value);
ftap_status_t ftap_tlv_get_u64(const ftap_tlv_t *field, uint64_t *value);
ftap_status_t ftap_tlv_get_bool(const ftap_tlv_t *field, bool *value);
ftap_status_t ftap_tlv_get_uuid(
    const ftap_tlv_t *field,
    uint8_t uuid[FTAP_UUID_SIZE]);
ftap_status_t ftap_tlv_get_text(
    const ftap_tlv_t *field,
    const uint8_t **text,
    size_t *text_length,
    size_t maximum_length);

#endif /* FORTYTWO_FTAP_CODEC_H */
