/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ftap_codec.h"

#include <stdbool.h>
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

static void
test_header_round_trip(void)
{
    ftap_frame_header_t input = {
        FTAP_VERSION_MAJOR,
        FTAP_VERSION_MINOR,
        FTAP_MSG_AUTHZ_CHECK_REQUEST,
        0,
        0x00000304U,
        UINT64_C(0x0102030405060708)
    };
    ftap_frame_header_t output;
    uint8_t wire[FTAP_FRAME_HEADER_SIZE];
    static const uint8_t expected[FTAP_FRAME_HEADER_SIZE] = {
        0x46, 0x54, 0x41, 0x50,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x78, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x04,
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    CHECK_STATUS(ftap_frame_header_encode(wire, &input), FTAP_STATUS_OK);
    CHECK(memcmp(wire, expected, sizeof(expected)) == 0);
    CHECK_STATUS(ftap_frame_header_decode(wire, sizeof(wire), &output),
                 FTAP_STATUS_OK);
    CHECK(output.major == input.major);
    CHECK(output.minor == input.minor);
    CHECK(output.message_type == input.message_type);
    CHECK(output.flags == input.flags);
    CHECK(output.payload_length == input.payload_length);
    CHECK(output.request_id == input.request_id);
}

static void
test_header_rejections(void)
{
    ftap_frame_header_t header = {
        FTAP_VERSION_MAJOR,
        FTAP_VERSION_MINOR,
        FTAP_MSG_HELLO,
        0,
        0,
        1
    };
    ftap_frame_header_t decoded;
    uint8_t wire[FTAP_FRAME_HEADER_SIZE];

    CHECK_STATUS(ftap_frame_header_encode(wire, &header), FTAP_STATUS_OK);
    wire[0] = (uint8_t)'X';
    CHECK_STATUS(ftap_frame_header_decode(wire, sizeof(wire), &decoded),
                 FTAP_STATUS_ERR_MAGIC);

    CHECK_STATUS(ftap_frame_header_encode(wire, &header), FTAP_STATUS_OK);
    wire[5] = 2;
    CHECK_STATUS(ftap_frame_header_decode(wire, sizeof(wire), &decoded),
                 FTAP_STATUS_ERR_VERSION);

    CHECK_STATUS(ftap_frame_header_encode(wire, &header), FTAP_STATUS_OK);
    wire[7] = 2;
    CHECK_STATUS(ftap_frame_header_decode(wire, sizeof(wire), &decoded),
                 FTAP_STATUS_NEWER_MINOR);

    CHECK_STATUS(ftap_frame_header_decode(wire, 23, &decoded),
                 FTAP_STATUS_ERR_TRUNCATED);

    header.flags = UINT16_C(0x8000);
    CHECK_STATUS(ftap_frame_header_encode(wire, &header),
                 FTAP_STATUS_ERR_FLAGS);

    header.flags = FTAP_FRAME_FLAG_SERVER_PUSH;
    header.request_id = 1;
    CHECK_STATUS(ftap_frame_header_encode(wire, &header),
                 FTAP_STATUS_ERR_REQUEST_ID);

    header.flags = 0;
    header.request_id = 0;
    CHECK_STATUS(ftap_frame_header_encode(wire, &header),
                 FTAP_STATUS_ERR_REQUEST_ID);

    header.request_id = 1;
    header.payload_length = FTAP_MAX_PAYLOAD_SIZE + 1U;
    CHECK_STATUS(ftap_frame_header_encode(wire, &header),
                 FTAP_STATUS_ERR_LENGTH);
}

static void
test_utf8(void)
{
    static const uint8_t ascii[] = "neo67";
    static const uint8_t umlaut[] = { 0x4a, 0xc3, 0xbc, 0x72, 0x67, 0x65, 0x6e };
    static const uint8_t emoji[] = { 0xf0, 0x9f, 0x98, 0x80 };
    static const uint8_t embedded_nul[] = { 'a', 0, 'b' };
    static const uint8_t overlong[] = { 0xc0, 0xaf };
    static const uint8_t surrogate[] = { 0xed, 0xa0, 0x80 };
    static const uint8_t too_large[] = { 0xf4, 0x90, 0x80, 0x80 };
    static const uint8_t truncated[] = { 0xe2, 0x82 };

    CHECK(ftap_utf8_text_is_valid(ascii, sizeof(ascii) - 1U));
    CHECK(ftap_utf8_text_is_valid(umlaut, sizeof(umlaut)));
    CHECK(ftap_utf8_text_is_valid(emoji, sizeof(emoji)));
    CHECK(!ftap_utf8_text_is_valid(embedded_nul, sizeof(embedded_nul)));
    CHECK(!ftap_utf8_text_is_valid(overlong, sizeof(overlong)));
    CHECK(!ftap_utf8_text_is_valid(surrogate, sizeof(surrogate)));
    CHECK(!ftap_utf8_text_is_valid(too_large, sizeof(too_large)));
    CHECK(!ftap_utf8_text_is_valid(truncated, sizeof(truncated)));
}

static void
test_tlv_round_trip(void)
{
    uint8_t buffer[256];
    uint8_t uuid[FTAP_UUID_SIZE];
    uint8_t decoded_uuid[FTAP_UUID_SIZE];
    ftap_tlv_writer_t writer;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;
    uint16_t u16_value;
    uint32_t u32_value;
    uint64_t u64_value;
    bool bool_value;
    const uint8_t *text;
    size_t text_length;
    size_t i;

    for (i = 0; i < sizeof(uuid); ++i) {
        uuid[i] = (uint8_t)i;
    }

    CHECK_STATUS(ftap_tlv_writer_init(&writer, buffer, sizeof(buffer)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"neo67", 5, FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_u16(
                     &writer, FTAP_FIELD_SUPPORTED_MAJOR, 0, 1),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_u32(
                     &writer, FTAP_FIELD_RETRY_AFTER_MS, 0, 2500),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_u64(
                     &writer, FTAP_FIELD_AUTH_EPOCH, 0,
                     UINT64_C(0x0102030405060708)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_bool(
                     &writer, FTAP_FIELD_AUTHZ_ALLOWED, 0, true),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_uuid(
                     &writer, FTAP_FIELD_USER_ID, 0, uuid),
                 FTAP_STATUS_OK);

    CHECK_STATUS(ftap_tlv_reader_init(&reader, buffer, writer.length),
                 FTAP_STATUS_OK);

    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_OK);
    CHECK(field.type == FTAP_FIELD_LOGIN_NAME);
    CHECK_STATUS(ftap_tlv_get_text(&field, &text, &text_length,
                                   FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_OK);
    CHECK(text_length == 5 && memcmp(text, "neo67", 5) == 0);

    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_get_u16(&field, &u16_value), FTAP_STATUS_OK);
    CHECK(u16_value == 1);

    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_get_u32(&field, &u32_value), FTAP_STATUS_OK);
    CHECK(u32_value == 2500);

    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_get_u64(&field, &u64_value), FTAP_STATUS_OK);
    CHECK(u64_value == UINT64_C(0x0102030405060708));

    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_get_bool(&field, &bool_value), FTAP_STATUS_OK);
    CHECK(bool_value);

    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_get_uuid(&field, decoded_uuid), FTAP_STATUS_OK);
    CHECK(memcmp(uuid, decoded_uuid, sizeof(uuid)) == 0);

    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_DONE);
    CHECK(reader.offset == reader.length);
}

static void
test_tlv_rejections(void)
{
    uint8_t small[8];
    uint8_t malformed[9] = {
        0x00, FTAP_FIELD_LOGIN_NAME,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,
        'x'
    };
    uint8_t unknown_critical[8] = {
        0x7f, 0xff,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00
    };
    ftap_tlv_writer_t writer;
    ftap_tlv_reader_t reader;
    ftap_tlv_t field;

    CHECK_STATUS(ftap_tlv_writer_init(&writer, small, sizeof(small)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_writer_put_text(
                     &writer, FTAP_FIELD_LOGIN_NAME, 0,
                     (const uint8_t *)"x", 1, FTAP_LOGIN_NAME_MAX),
                 FTAP_STATUS_ERR_CAPACITY);

    CHECK_STATUS(ftap_tlv_reader_init(&reader, malformed,
                                      sizeof(malformed)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field),
                 FTAP_STATUS_ERR_TRUNCATED);

    CHECK_STATUS(ftap_tlv_reader_init(&reader, unknown_critical,
                                      sizeof(unknown_critical)),
                 FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_reader_next(&reader, &field), FTAP_STATUS_OK);
    CHECK_STATUS(ftap_tlv_check_supported(&field),
                 FTAP_STATUS_ERR_UNSUPPORTED_FIELD);
}

int
main(void)
{
    test_header_round_trip();
    test_header_rejections();
    test_utf8();
    test_tlv_round_trip();
    test_tlv_rejections();

    if (failures != 0U) {
        fprintf(stderr, "%u FTAP codec test(s) failed\n", failures);
        return 1;
    }

    puts("FTAP codec tests: OK");
    return 0;
}
