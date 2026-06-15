/* test_mqtt_packet.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfMQTT is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* mqtt_client.h must be included before mqtt_packet.h: it pulls in
 * wolfmqtt/options.h (WOLFMQTT_V5 et al.) for non-autotools builds. */
#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_packet.h"
#include "tests/unit_test.h"

void run_mqtt_packet_tests(void);

static void setup(void)     { }
static void teardown(void)  { }

/* ============================================================================
 * MqttEncode_Num / MqttDecode_Num
 * ============================================================================ */

TEST(encode_num_basic)
{
    byte buf[2];
    int ret = MqttEncode_Num(buf, 0x1234);
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ASSERT_EQ(0x12, buf[0]);
    ASSERT_EQ(0x34, buf[1]);
}

TEST(encode_num_zero)
{
    byte buf[2];
    int ret = MqttEncode_Num(buf, 0);
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, buf[1]);
}

TEST(encode_num_max)
{
    byte buf[2];
    int ret = MqttEncode_Num(buf, 0xFFFF);
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ASSERT_EQ(0xFF, buf[0]);
    ASSERT_EQ(0xFF, buf[1]);
}

TEST(encode_num_null_buf)
{
    /* NULL buf: length-only probe; returns size without writing */
    int ret = MqttEncode_Num(NULL, 0x1234);
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
}

TEST(decode_num_basic)
{
    byte buf[2] = { 0x12, 0x34 };
    word16 val = 0;
    int ret = MqttDecode_Num(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ASSERT_EQ(0x1234, val);
}

TEST(decode_num_zero)
{
    byte buf[2] = { 0x00, 0x00 };
    word16 val = 0xFFFF;
    int ret = MqttDecode_Num(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ASSERT_EQ(0, val);
}

TEST(decode_num_max)
{
    byte buf[2] = { 0xFF, 0xFF };
    word16 val = 0;
    int ret = MqttDecode_Num(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ASSERT_EQ(0xFFFF, val);
}

TEST(decode_num_buffer_too_small)
{
    byte buf[1] = { 0x12 };
    word16 val = 0;
    int ret = MqttDecode_Num(buf, &val, 1);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, ret);
}

TEST(encode_decode_num_roundtrip)
{
    byte buf[2];
    word16 val;
    int ret;

    ret = MqttEncode_Num(buf, 0xABCD);
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ret = MqttDecode_Num(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_DATA_LEN_SIZE, ret);
    ASSERT_EQ(0xABCD, val);
}

/* ============================================================================
 * MqttEncode_Vbi / MqttDecode_Vbi
 * ============================================================================ */

TEST(encode_vbi_one_byte)
{
    byte buf[4];
    int len = MqttEncode_Vbi(buf, 127);
    ASSERT_EQ(1, len);
    ASSERT_EQ(0x7F, buf[0]);
}

TEST(encode_vbi_two_bytes)
{
    byte buf[4];
    int len = MqttEncode_Vbi(buf, 128);
    ASSERT_EQ(2, len);
}

TEST(encode_vbi_three_bytes)
{
    byte buf[4];
    int len = MqttEncode_Vbi(buf, 16384);
    ASSERT_EQ(3, len);
}

TEST(encode_vbi_four_bytes)
{
    byte buf[4];
    int len = MqttEncode_Vbi(buf, 2097152);
    ASSERT_EQ(4, len);
}

TEST(encode_vbi_null_buf)
{
    ASSERT_EQ(1, MqttEncode_Vbi(NULL, 127));
    ASSERT_EQ(2, MqttEncode_Vbi(NULL, 128));
    ASSERT_EQ(3, MqttEncode_Vbi(NULL, 16384));
    ASSERT_EQ(4, MqttEncode_Vbi(NULL, 2097152));
}

/* [MQTT-2.2.3] Values above 268,435,455 must be rejected. Without the guard,
 * the encoding loop's rc < 4 terminator would silently truncate the value
 * to 4 bytes and produce a valid-looking but incorrect encoding. */
TEST(encode_vbi_overflow_above_max)
{
    byte buf[4];
    int rc = MqttEncode_Vbi(buf, 268435456);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(encode_vbi_overflow_u32_max)
{
    byte buf[4];
    int rc = MqttEncode_Vbi(buf, 0xFFFFFFFF);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(encode_vbi_overflow_null_buf)
{
    int rc = MqttEncode_Vbi(NULL, 268435456);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_vbi_one_byte_zero)
{
    byte buf[1] = { 0x00 };
    word32 val = 0xFFFFFFFF;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(1, rc);
    ASSERT_EQ(0, val);
}

TEST(decode_vbi_one_byte_max)
{
    byte buf[1] = { 0x7F };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(1, rc);
    ASSERT_EQ(127, val);
}

TEST(decode_vbi_two_bytes_min)
{
    byte buf[2] = { 0x80, 0x01 };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(2, rc);
    ASSERT_EQ(128, val);
}

TEST(decode_vbi_two_bytes_max)
{
    byte buf[2] = { 0xFF, 0x7F };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(2, rc);
    ASSERT_EQ(16383, val);
}

TEST(decode_vbi_three_bytes_max)
{
    byte buf[3] = { 0xFF, 0xFF, 0x7F };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(3, rc);
    ASSERT_EQ(2097151, val);
}

TEST(decode_vbi_four_bytes_max)
{
    byte buf[4] = { 0xFF, 0xFF, 0xFF, 0x7F };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(4, rc);
    ASSERT_EQ(268435455, val);
}

TEST(decode_vbi_five_byte_malformed)
{
    byte buf[5] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_vbi_buffer_too_small)
{
    byte buf[1] = { 0x80 };   /* needs a continuation byte */
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, 1);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

/* [MQTT-1.5.5-1] Overlong encodings must be rejected */
TEST(decode_vbi_overlong_2byte_zero)
{
    byte buf[2] = { 0x80, 0x00 };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_vbi_overlong_3byte_zero)
{
    byte buf[3] = { 0x80, 0x80, 0x00 };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_vbi_overlong_4byte_zero)
{
    byte buf[4] = { 0x80, 0x80, 0x80, 0x00 };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_vbi_overlong_2byte_127)
{
    byte buf[2] = { 0xFF, 0x00 };
    word32 val = 0;
    int rc = MqttDecode_Vbi(buf, &val, sizeof(buf));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(encode_decode_vbi_roundtrip)
{
    byte buf[4];
    word32 val;
    int enc, dec;

    /* Boundary values covering each VBI size */
    const word32 cases[] = { 0, 127, 128, 16383, 16384, 2097151, 2097152,
                             268435455 };
    size_t i;
    for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        enc = MqttEncode_Vbi(buf, cases[i]);
        ASSERT_TRUE(enc > 0);
        val = 0;
        dec = MqttDecode_Vbi(buf, &val, sizeof(buf));
        ASSERT_EQ(enc, dec);
        ASSERT_EQ(cases[i], val);
    }
}

/* ============================================================================
 * UTF-8 well-formedness validation [MQTT-1.5.3-1]
 *
 * MqttDecode_String validates that the bytes following the 2-byte length
 * prefix are well-formed UTF-8 per RFC 3629, including the surrogate-code-
 * point ban (U+D800..U+DFFF). The internal validator is static; we exercise
 * it through the protocol-level decoders (Subscribe, Publish, Connect) since
 * those are what enforce the spec rule on the wire.
 *
 * Each test below builds a SUBSCRIBE packet whose topic-filter bytes carry
 * the UTF-8 sequence under test, and asserts:
 *   - well-formed bytes -> decode succeeds (rc > 0)
 *   - ill-formed bytes  -> MQTT_CODE_ERROR_MALFORMED_DATA (which the broker's
 *     existing error path translates into a connection close).
 *
 * Bytes used by the tests:
 *   ASCII "ab"               61 62
 *   2-byte U+00E9 (é)        C3 A9
 *   3-byte U+20AC (€)        E2 82 AC
 *   3-byte U+0800 (low edge) E0 A0 80
 *   3-byte U+D7FF (last pre- ED 9F BF
 *                  surrogate)
 *   3-byte U+E000 (first post-EE 80 80
 *                  surrogate)
 *   4-byte U+10000           F0 90 80 80
 *   4-byte U+10FFFF (max)    F4 8F BF BF
 *   overlong 2-byte 0x2F     C0 AF
 *   overlong 3-byte 0x2F     E0 80 AF
 *   overlong 4-byte 0x2F     F0 80 80 AF
 *   surrogate U+D800         ED A0 80
 *   surrogate U+DFFF         ED BF BF
 *   > U+10FFFF               F4 90 80 80
 *   F5+ leading byte         F5 80 80 80
 *   lone continuation        80
 *   truncated 2-byte         C2
 *   truncated 4-byte         F0 90 80
 *   invalid leading FE/FF    FE / FF
 * ============================================================================ */

#ifdef WOLFMQTT_BROKER
/* Build a v3.1.1 SUBSCRIBE wire buffer with the given topic_filter bytes
 * and write it into out. Returns the total wire length. */
static int build_subscribe_with_topic(byte* out, size_t out_sz,
    const byte* topic, word16 topic_len)
{
    /* type=0x82, remain=VBI, packet_id=0x0001, topic_len=word16,
     * topic..., options=0x01. remain = 2 + 2 + topic_len + 1 = topic_len+5 */
    int remain = (int)topic_len + 5;
    int written = 0;
    if ((size_t)remain + 2 > out_sz || remain > 127) {
        return -1;
    }
    out[written++] = 0x82;
    out[written++] = (byte)remain;
    out[written++] = 0x00; out[written++] = 0x01;            /* packet_id */
    out[written++] = (byte)(topic_len >> 8);
    out[written++] = (byte)(topic_len & 0xFF);
    if (topic_len > 0) {
        XMEMCPY(out + written, topic, topic_len);
        written += topic_len;
    }
    out[written++] = 0x01; /* options: QoS 1 */
    return written;
}

/* Run a SUBSCRIBE through the decoder with the given topic-filter bytes and
 * return the decoder's return code. */
static int decode_subscribe_with_topic(const byte* topic, word16 topic_len)
{
    byte rx_buf[128];
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int wire_len = build_subscribe_with_topic(rx_buf, sizeof(rx_buf),
        topic, topic_len);
    if (wire_len < 0) {
        return -1;
    }
    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    return MqttDecode_Subscribe(rx_buf, wire_len, &sub);
}

TEST(decode_string_utf8_valid_ascii)
{
    byte t[] = { 'a', 'b' };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_TRUE(rc > 0);
}

TEST(decode_string_utf8_valid_2byte)
{
    /* "café" tail: U+00E9 = C3 A9 */
    byte t[] = { 'c', 0xC3, 0xA9 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_TRUE(rc > 0);
}

TEST(decode_string_utf8_valid_3byte)
{
    /* U+20AC € = E2 82 AC */
    byte t[] = { 0xE2, 0x82, 0xAC };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_TRUE(rc > 0);
}

TEST(decode_string_utf8_valid_4byte)
{
    /* U+10000 = F0 90 80 80 */
    byte t[] = { 0xF0, 0x90, 0x80, 0x80 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_TRUE(rc > 0);
}

TEST(decode_string_utf8_valid_max_codepoint)
{
    /* U+10FFFF = F4 8F BF BF */
    byte t[] = { 0xF4, 0x8F, 0xBF, 0xBF };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_TRUE(rc > 0);
}

TEST(decode_string_utf8_valid_d7ff_just_below_surrogate)
{
    /* U+D7FF = ED 9F BF (last code point before the surrogate range) */
    byte t[] = { 0xED, 0x9F, 0xBF };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_TRUE(rc > 0);
}

TEST(decode_string_utf8_valid_e000_just_above_surrogate)
{
    /* U+E000 = EE 80 80 (first code point after the surrogate range) */
    byte t[] = { 0xEE, 0x80, 0x80 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_TRUE(rc > 0);
}

TEST(decode_string_utf8_invalid_overlong_2byte)
{
    /* 0xC0 0xAF encodes '/' (0x2F) overlong; RFC 3629 forbids overlong. */
    byte t[] = { 0xC0, 0xAF };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_overlong_3byte)
{
    /* 0xE0 0x80 0xAF encodes '/' overlong */
    byte t[] = { 0xE0, 0x80, 0xAF };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_overlong_4byte)
{
    /* 0xF0 0x80 0x80 0xAF encodes '/' overlong */
    byte t[] = { 0xF0, 0x80, 0x80, 0xAF };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_surrogate_low)
{
    /* U+D800 = ED A0 80 - first surrogate, [MQTT-1.5.3-1] forbids. */
    byte t[] = { 0xED, 0xA0, 0x80 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_surrogate_high)
{
    /* U+DFFF = ED BF BF - last surrogate */
    byte t[] = { 0xED, 0xBF, 0xBF };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_above_max)
{
    /* F4 90 80 80 encodes U+110000 (above U+10FFFF). */
    byte t[] = { 0xF4, 0x90, 0x80, 0x80 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_f5_leading)
{
    /* F5..FF are not valid UTF-8 leading bytes. */
    byte t[] = { 0xF5, 0x80, 0x80, 0x80 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_lone_continuation)
{
    /* 0x80 alone - continuation byte without a leading byte. */
    byte t[] = { 0x80 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_truncated_2byte)
{
    /* 0xC2 needs one continuation but is alone. */
    byte t[] = { 0xC2 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_truncated_4byte)
{
    /* 0xF0 0x90 0x80 needs one more continuation. */
    byte t[] = { 0xF0, 0x90, 0x80 };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_string_utf8_invalid_FE_FF)
{
    /* FE / FF are not valid UTF-8 anywhere. */
    byte t[] = { 0xFE };
    int rc = decode_subscribe_with_topic(t, (word16)sizeof(t));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_connect_invalid_utf8_clientid_overlong)
{
    /* CONNECT v3.1.1 with ClientId bytes 0xC0 0xAF (overlong). Reporter's
     * dynamic test case `connect_clientid_overlong` - should now refuse.
     * Wire: 0x10 + remain=14, "MQTT", level=4, flags=0x02, keepalive=60,
     *       client_id_len=0x0002, [C0 AF]. */
    byte rx_buf[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,
        0x00, 0x3C,
        0x00, 0x02, 0xC0, 0xAF
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(rx_buf, (int)sizeof(rx_buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_connect_invalid_utf8_clientid_surrogate)
{
    /* Reporter's `connect_clientid_surrogate` case: ClientId bytes ED A0 80
     * (U+D800). */
    byte rx_buf[] = {
        0x10, 15,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,
        0x00, 0x3C,
        0x00, 0x03, 0xED, 0xA0, 0x80
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(rx_buf, (int)sizeof(rx_buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-2] U+0000 is forbidden in every MQTT UTF-8 string field,
 * not just Will Topic. Pin client_id as a separate entry point so a
 * future regression that bypasses Utf8WellFormed on this field (e.g.,
 * a bespoke client_id decoder) is caught by CI. */
TEST(decode_connect_clientid_contains_u0000_rejected)
{
    /* ClientId "a\\0b" (length 3 with U+0000 at position 1). */
    byte rx_buf[] = {
        0x10, 15,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,
        0x00, 0x3C,
        0x00, 0x03, 'a', 0x00, 'b'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(rx_buf, (int)sizeof(rx_buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}
#endif /* WOLFMQTT_BROKER */

TEST(decode_publish_invalid_utf8_topic)
{
    /* PUBLISH QoS 0 with topic bytes ED A0 80 (surrogate U+D800).
     * Wire: 0x30, remain=7, topic_len=0x0003, [ED A0 80], payload "x". */
    byte buf[] = {
        0x30, 7,
        0x00, 0x03, 0xED, 0xA0, 0x80,
        'x', 'x' /* dummy payload bytes */
    };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

#ifdef WOLFMQTT_BROKER
/* CONNECT with a binary (non-UTF-8) password must decode successfully,
 * because MQTT defines the Password field as Binary Data - not a UTF-8
 * string. The diff routes the password decode around MqttDecode_String to
 * avoid spuriously rejecting valid binary passwords containing bytes like
 * 0xC0 (which are not legal UTF-8 leading bytes). */
TEST(decode_connect_v311_binary_password)
{
    /* Hand-built v3.1.1 CONNECT wire:
     *   fixed:   0x10, remain=20
     *   var hdr: "MQTT" (4 + len2), level 4, flags 0xC2 (user|pass|clean),
     *            keepalive 60
     *   payload: client_id "c" (3), username "u" (3),
     *            password [0xC0 0xAF] (length 2 + 2 = 4)
     * remain = 10 + 3 + 3 + 4 = 20 */
    byte rx_buf[] = {
        0x10, 20,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0xC2,           /* flags: USER|PASS|CLEAN */
        0x00, 0x3C,
        0x00, 0x01, 'c',
        0x00, 0x01, 'u',
        0x00, 0x02, 0xC0, 0xAF
    };
    MqttConnect dec;
    int rc;
    word16 plen = 0;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(rx_buf, (int)sizeof(rx_buf), &dec);
    ASSERT_TRUE(rc > 0);
    ASSERT_NOT_NULL(dec.password);

    /* The broker reads the password length by stepping back 2 bytes from
     * the password pointer (see src/mqtt_broker.c). Pin that contract: the
     * 2 bytes preceding mc_connect->password must encode 0x0002. */
    ASSERT_EQ(MQTT_DATA_LEN_SIZE,
        MqttDecode_Num((byte*)dec.password - MQTT_DATA_LEN_SIZE,
            &plen, MQTT_DATA_LEN_SIZE));
    ASSERT_EQ(2, plen);
    ASSERT_EQ((byte)0xC0, ((byte*)dec.password)[0]);
    ASSERT_EQ((byte)0xAF, ((byte*)dec.password)[1]);
}

/* CONNECT with an invalid UTF-8 username must be refused. Username is a
 * UTF-8 string per [MQTT-3.1.3.4] and goes through MqttDecode_String. */
TEST(decode_connect_invalid_utf8_username)
{
    /* Same shape as decode_connect_v311_binary_password but no password
     * flag; username = surrogate ED A0 80.
     * remain = 10 + 3 + 5 = 18 */
    byte rx_buf[] = {
        0x10, 18,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x82,           /* flags: USER|CLEAN */
        0x00, 0x3C,
        0x00, 0x01, 'c',
        0x00, 0x03, 0xED, 0xA0, 0x80
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(rx_buf, (int)sizeof(rx_buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-1] / [MQTT-3.1.3-11]: ill-formed UTF-8 in CONNECT User
 * Name MUST cause the receiver to close the connection. The companion
 * test above covers a surrogate; this one covers the overlong-encoding
 * bucket (C0 AF - the overlong representation of '/'). MqttDecode_String
 * routes the field through Utf8WellFormed, which rejects both. */
TEST(decode_connect_invalid_utf8_username_overlong)
{
    /* User name = C0 AF (2-byte overlong representation of U+002F).
     * remain = 10 + 3 + 4 = 17 */
    byte rx_buf[] = {
        0x10, 17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x82,
        0x00, 0x3C,
        0x00, 0x01, 'c',
        0x00, 0x02, 0xC0, 0xAF
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(rx_buf, (int)sizeof(rx_buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}
#endif /* WOLFMQTT_BROKER */

/* ============================================================================
 * MqttEncode_Publish
 * ============================================================================ */

TEST(encode_publish_qos1_packet_id_zero)
{
    byte tx_buf[256];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "test/topic";
    pub.qos = MQTT_QOS_1;
    pub.packet_id = 0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

TEST(encode_publish_qos2_packet_id_zero)
{
    byte tx_buf[256];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "test/topic";
    pub.qos = MQTT_QOS_2;
    pub.packet_id = 0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

TEST(encode_publish_qos0_packet_id_zero_ok)
{
    byte tx_buf[256];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "test/topic";
    pub.qos = MQTT_QOS_0;
    pub.packet_id = 0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
}

TEST(encode_publish_qos1_valid)
{
    byte tx_buf[256];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "test/topic";
    pub.qos = MQTT_QOS_1;
    pub.packet_id = 1;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
}

/* Verify the fixed-header flag bits (retain/QoS/dup) are actually emitted.
 * Covers deletion mutations of the retain / qos / duplicate branches in
 * MqttEncode_FixedHeader. */
TEST(encode_publish_qos1_retain_flags_in_header)
{
    byte tx_buf[256];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "test/topic";
    pub.qos = MQTT_QOS_1;
    pub.retain = 1;
    pub.duplicate = 0;
    pub.packet_id = 1;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH,
              MQTT_PACKET_TYPE_GET(tx_buf[0]));
    ASSERT_EQ(MQTT_QOS_1,
              (int)MQTT_PACKET_FLAGS_GET_QOS(tx_buf[0]));
    ASSERT_TRUE((MQTT_PACKET_FLAGS_GET(tx_buf[0]) &
                 MQTT_PACKET_FLAG_RETAIN) != 0);
    ASSERT_TRUE((MQTT_PACKET_FLAGS_GET(tx_buf[0]) &
                 MQTT_PACKET_FLAG_DUPLICATE) == 0);
}

TEST(encode_publish_qos2_duplicate_flags_in_header)
{
    byte tx_buf[256];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "test/topic";
    pub.qos = MQTT_QOS_2;
    pub.retain = 0;
    pub.duplicate = 1;
    pub.packet_id = 1;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH,
              MQTT_PACKET_TYPE_GET(tx_buf[0]));
    ASSERT_EQ(MQTT_QOS_2,
              (int)MQTT_PACKET_FLAGS_GET_QOS(tx_buf[0]));
    ASSERT_TRUE((MQTT_PACKET_FLAGS_GET(tx_buf[0]) &
                 MQTT_PACKET_FLAG_DUPLICATE) != 0);
    ASSERT_TRUE((MQTT_PACKET_FLAGS_GET(tx_buf[0]) &
                 MQTT_PACKET_FLAG_RETAIN) == 0);
}

/* QoS 0, no retain, no dup -> flag nibble must be 0. Catches any mutation
 * that unconditionally sets flag bits. */
TEST(encode_publish_qos0_no_flags_in_header)
{
    byte tx_buf[256];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "test/topic";
    pub.qos = MQTT_QOS_0;
    pub.retain = 0;
    pub.duplicate = 0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH,
              MQTT_PACKET_TYPE_GET(tx_buf[0]));
    ASSERT_EQ(0, (int)MQTT_PACKET_FLAGS_GET(tx_buf[0]));
}

/* [MQTT-3.3.1-2] DUP MUST be 0 for all QoS 0 messages. The encoder must
 * refuse the forbidden combination at the API boundary so the library can't
 * produce a wire packet that the decoder (and any spec-compliant receiver)
 * would reject as malformed. */
TEST(encode_publish_qos0_with_dup_rejected)
{
    byte tx_buf[64];
    byte payload[] = { 'x' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "a";
    pub.qos = MQTT_QOS_0;
    pub.duplicate = 1;
    pub.buffer = payload;
    pub.total_len = sizeof(payload);

    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* QoS 1 with DUP=1 is a legitimate retransmission shape per [MQTT-4.3.2].
 * Pin that the new check is QoS-0-specific and doesn't break retransmits. */
TEST(encode_publish_qos1_with_dup_accepted)
{
    byte tx_buf[64];
    byte payload[] = { 'x' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "a";
    pub.qos = MQTT_QOS_1;
    pub.packet_id = 42;
    pub.duplicate = 1;
    pub.buffer = payload;
    pub.total_len = sizeof(payload);

    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
    /* Fixed-header low nibble: DUP|QoS1 = 0x8 | 0x2 = 0xA. */
    ASSERT_EQ(0xA, (int)MQTT_PACKET_FLAGS_GET(tx_buf[0]));
}

/* QoS 2 with DUP=1 is also a legitimate retransmission shape per [MQTT-4.3.3]. */
TEST(encode_publish_qos2_with_dup_accepted)
{
    byte tx_buf[64];
    byte payload[] = { 'x' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "a";
    pub.qos = MQTT_QOS_2;
    pub.packet_id = 42;
    pub.duplicate = 1;
    pub.buffer = payload;
    pub.total_len = sizeof(payload);

    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
    /* DUP|QoS2 = 0x8 | 0x4 = 0xC. */
    ASSERT_EQ(0xC, (int)MQTT_PACKET_FLAGS_GET(tx_buf[0]));
}

/* f-2360: topic_name with strlen > 65535 must not produce a "successful"
 * encode. MqttEncode_String returns -1 for oversize strings; the encoder
 * must surface that as a negative return rather than adding -1 to the
 * tx_payload pointer and reporting header_len+remain_len as success. */
TEST(encode_publish_topic_oversized_rejected)
{
    const int str_len = 0x10000; /* one byte past MQTT UTF-8 limit */
    const int buf_len = str_len + 64;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *topic = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttPublish pub;
    int rc;

    if (tx_buf == NULL || topic == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(topic);
        FAIL("allocation failed");
    }
    XMEMSET(topic, 'A', str_len);
    topic[str_len] = '\0';

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = topic;
    pub.qos = MQTT_QOS_0;
    rc = MqttEncode_Publish(tx_buf, buf_len, &pub, 0);

    WOLFMQTT_FREE(topic);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* Pin the helper truth table for both v3.1.1 (level=0/4) and v5
 * (level=5). Wildcards are forbidden in either version
 * ([MQTT-3.3.2-2]); empty is rejected in v3.1.1 ([MQTT-4.7.3-1]) but
 * permitted in v5 (section 3.3.2.3.4 - empty Topic Name with Topic Alias). */
TEST(topic_name_valid_helper_table)
{
    byte v311 = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    byte v5   = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    /* Empty: rejected in v3.1.1, accepted in v5 - but only via empty
     * string, not NULL. NULL is API misuse regardless of len; v5 Topic
     * Alias placeholders must use "". */
    ASSERT_EQ(0, MqttPacket_TopicNameValid(NULL, 0, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("", 0, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid(NULL, 0, v5));
    ASSERT_EQ(1, MqttPacket_TopicNameValid("", 0, v5));
    /* NULL with non-zero len is also malformed. */
    ASSERT_EQ(0, MqttPacket_TopicNameValid(NULL, 1, v5));
    /* Plain topics. */
    ASSERT_EQ(1, MqttPacket_TopicNameValid("a", 1, v311));
    ASSERT_EQ(1, MqttPacket_TopicNameValid("sensor/value", 12, v311));
    ASSERT_EQ(1, MqttPacket_TopicNameValid("/", 1, v311));
    /* Wildcards are forbidden in both versions regardless of position. */
    ASSERT_EQ(0, MqttPacket_TopicNameValid("#", 1, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("+", 1, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("sensor/#", 8, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("sensor/+", 8, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("sen+sor", 7, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("sen#sor", 7, v311));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("sensor/#", 8, v5));
    ASSERT_EQ(0, MqttPacket_TopicNameValid("sensor/+", 8, v5));
}

/* MqttEncode_Publish must reject a malformed Topic Name before
 * serializing the packet; the broker rejects on inbound, so silent
 * encoder acceptance produces a packet that strict peers will refuse. */
TEST(encode_publish_empty_topic_rejected)
{
    byte tx_buf[64];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "";
    pub.qos = MQTT_QOS_0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(encode_publish_wildcard_topic_rejected)
{
    byte tx_buf[64];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = "sensor/#";
    pub.qos = MQTT_QOS_0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);

    pub.topic_name = "sensor/+";
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* NULL topic_name is API misuse (separate from a malformed wire
 * packet) - surface it as BAD_ARG to match the surrounding NULL-check
 * convention in this function. */
TEST(encode_publish_null_topic_returns_bad_arg)
{
    byte tx_buf[64];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.topic_name = NULL;
    pub.qos = MQTT_QOS_0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

#ifdef WOLFMQTT_V5
/* MQTT v5 section 3.3.2.3.4: a zero-length Topic Name is permitted when paired
 * with a Topic Alias property. The encoder must not reject the empty
 * topic on the v5 path; the alias-empty pairing is the application's
 * responsibility. */
TEST(encode_publish_v5_empty_topic_accepted)
{
    byte tx_buf[64];
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    pub.topic_name = "";
    pub.qos = MQTT_QOS_0;
    rc = MqttEncode_Publish(tx_buf, (int)sizeof(tx_buf), &pub, 0);
    ASSERT_TRUE(rc > 0);
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * MqttDecode_Publish
 * ============================================================================ */

TEST(decode_publish_qos0_valid)
{
    /* Fixed header (PUBLISH, QoS 0, remain_len=7), topic "a/b",
     * payload "HI". Using nonzero payload bytes catches a
     * qos>MQTT_QOS_0 -> qos>=MQTT_QOS_0 mutation that would read
     * the first 2 payload bytes as a spurious packet_id. */
    byte buf[] = { 0x30, 7,
                   0x00, 0x03, 'a', '/', 'b',
                   'H', 'I' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_QOS_0, pub.qos);
    ASSERT_EQ(0, pub.packet_id);
    ASSERT_EQ(3, pub.topic_name_len);
    ASSERT_EQ(0, XMEMCMP(pub.topic_name, "a/b", 3));
    ASSERT_EQ(2, (int)pub.total_len);
    ASSERT_EQ(2, (int)pub.buffer_len);
    ASSERT_EQ('H', pub.buffer[0]);
    ASSERT_EQ('I', pub.buffer[1]);
}

TEST(decode_publish_qos1_valid)
{
    /* Fixed header (PUBLISH | QoS 1 = 0x32, remain_len=7),
     * topic "t", packet_id=42, payload "xy". */
    byte buf[] = { 0x32, 7,
                   0x00, 0x01, 't',
                   0x00, 0x2A,
                   'x', 'y' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_QOS_1, pub.qos);
    ASSERT_EQ(42, pub.packet_id);
    ASSERT_EQ(1, pub.topic_name_len);
    ASSERT_EQ(0, XMEMCMP(pub.topic_name, "t", 1));
    ASSERT_EQ(2, (int)pub.total_len);
    ASSERT_EQ(2, (int)pub.buffer_len);
    ASSERT_EQ('x', pub.buffer[0]);
    ASSERT_EQ('y', pub.buffer[1]);
}

/* Zero-payload PUBLISH is valid per spec; catches a
 * variable_len>remain_len -> variable_len>=remain_len mutation. */
TEST(decode_publish_qos0_zero_payload)
{
    byte buf[] = { 0x30, 3,
                   0x00, 0x01, 'a' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_QOS_0, pub.qos);
    ASSERT_EQ(1, pub.topic_name_len);
    ASSERT_EQ(0, (int)pub.total_len);
    ASSERT_EQ(0, (int)pub.buffer_len);
}

/* Fixed header claims remain_len=3, but topic declares length=5
 * (consuming 7 bytes of variable header). After decoding the topic,
 * variable_len (7) exceeds remain_len (3), which must be rejected. */
TEST(decode_publish_malformed_variable_exceeds_remain)
{
    byte buf[] = { 0x30, 3,
                   0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

/* [MQTT-1.5.3-2] / [MQTT-4.7.3-2]: a topic name containing U+0000 must be
 * rejected. Without this check, downstream broker logic uses C-string
 * semantics on the stored topic and a publish to "se\0cret" would route
 * to subscribers of "se". */
TEST(decode_publish_rejects_nul_in_topic)
{
    byte buf[] = { 0x30, 10,
                   0x00, 0x07, 's', 'e', 0x00, 'c', 'r', 'e', 't',
                   'X' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-4.7.3-1] PUBLISH Topic Name length 0x0000 is malformed. Wire
 * shape: PUBLISH | QoS 0, remain=3, topic_len=0, single payload byte. */
TEST(decode_publish_empty_topic_rejected)
{
    byte buf[] = { 0x30, 0x03, 0x00, 0x00, 'x' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.3.2-2] / [MQTT-4.7.1-1] PUBLISH Topic Names MUST NOT contain
 * wildcards. Wire encodes "sensor/#" / "sensor/+" as the Topic Name. */
TEST(decode_publish_wildcard_hash_topic_rejected)
{
    byte buf[] = {
        0x30, 0x0B,
        0x00, 0x08, 's', 'e', 'n', 's', 'o', 'r', '/', '#',
        'x'
    };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_publish_wildcard_plus_topic_rejected)
{
    byte buf[] = {
        0x30, 0x0B,
        0x00, 0x08, 's', 'e', 'n', 's', 'o', 'r', '/', '+',
        'x'
    };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-2] U+0000 forbidden in PUBLISH Topic Name as well - broaden
 * coverage of the new check to a non-CONNECT entry point. */
TEST(decode_publish_topic_contains_u0000_rejected)
{
    /* PUBLISH QoS 0, remain=6, topic "a\0b", payload "x". */
    byte buf[] = {
        0x30, 0x06,
        0x00, 0x03, 'a', 0x00, 'b',
        'x'
    };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

#ifdef WOLFMQTT_V5
/* MQTT v5 section 3.3.2.3.4: a zero-length Topic Name is permitted (paired
 * with a Topic Alias property at the application layer). Wire shape:
 * PUBLISH | QoS 0, remain=4, topic_len=0, props_len=0, payload "x". */
TEST(decode_publish_v5_empty_topic_accepted)
{
    byte buf[] = { 0x30, 0x04, 0x00, 0x00, 0x00, 'x' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(0, pub.topic_name_len);
}
#endif /* WOLFMQTT_V5 */

/* [MQTT-2.3.1-1] PUBLISH with QoS > 0 must carry a non-zero Packet
 * Identifier. The encoder rejects packet_id=0 already; this guards the
 * symmetric decode-side check so a peer cannot smuggle in a malformed
 * packet that downstream logic would treat as an absent / unset id. */
TEST(decode_publish_qos1_packet_id_zero_rejected)
{
    /* PUBLISH | QoS 1 = 0x32, remain_len=7, topic "t", packet_id=0, "xy" */
    byte buf[] = { 0x32, 7,
                   0x00, 0x01, 't',
                   0x00, 0x00,
                   'x', 'y' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

TEST(decode_publish_qos2_packet_id_zero_rejected)
{
    /* PUBLISH | QoS 2 = 0x34, remain_len=7, topic "t", packet_id=0, "xy" */
    byte buf[] = { 0x34, 7,
                   0x00, 0x01, 't',
                   0x00, 0x00,
                   'x', 'y' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

/* QoS 2 with non-zero Packet Identifier is the matching positive case so a
 * future regression that turns the zero check into "always reject" would
 * trip here as well as in decode_publish_qos1_valid. */
TEST(decode_publish_qos2_packet_id_one_valid)
{
    byte buf[] = { 0x34, 7,
                   0x00, 0x01, 't',
                   0x00, 0x01,
                   'x', 'y' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_QOS_2, pub.qos);
    ASSERT_EQ(1, pub.packet_id);
}


#ifdef WOLFMQTT_V5
/* Hand-validated MQTT v5 PUBLISH packet (independent oracle, not produced by
 * MqttEncode_Publish) so encode and decode cannot hide a shared bug:
 *   fixed header:     0x30 (PUBLISH, QoS 0), remain_len = 21
 *   topic:            "a/b"             (2-byte len + 3 bytes)
 *   props length:     0x0D (13)
 *   property:         0x03 CONTENT_TYPE, 2-byte len 0x000A, "text/plain"
 *   payload:          "HI"
 */
TEST(decode_publish_v5_content_type_property)
{
    byte buf[] = {
        0x30, 21,
        0x00, 0x03, 'a', '/', 'b',
        0x0D,
        0x03, 0x00, 0x0A,
        't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n',
        'H', 'I'
    };
    MqttPublish pub;
    MqttProp* prop;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_QOS_0, pub.qos);
    ASSERT_EQ(0, pub.packet_id);
    ASSERT_EQ(3, pub.topic_name_len);
    ASSERT_EQ(0, XMEMCMP(pub.topic_name, "a/b", 3));
    ASSERT_EQ(2, (int)pub.total_len);

    for (prop = pub.props; prop != NULL; prop = prop->next) {
        if (prop->type == MQTT_PROP_CONTENT_TYPE)
            break;
    }
    ASSERT_TRUE(prop != NULL);
    ASSERT_EQ(MQTT_PROP_CONTENT_TYPE, prop->type);
    ASSERT_EQ(10, (int)prop->data_str.len);
    ASSERT_EQ(0, XMEMCMP(prop->data_str.str, "text/plain", 10));

    MqttProps_Free(pub.props);
}

/* [MQTT-1.5.4-2]: an embedded NUL in a v5 STRING property must be
 * rejected. Uses a PUBLISH packet with a Content Type property whose
 * value contains 0x00. MqttDecode_Props propagates MALFORMED_DATA from
 * MqttDecode_String distinctly from generic MQTT_CODE_ERROR_PROPERTY. */
TEST(decode_publish_v5_rejects_nul_in_string_property)
{
    /* Wire: PUBLISH QoS 0, remain_len=13, topic "a/b", props_len=7,
     *       prop 0x03 CONTENT_TYPE, str_len=4, "t\0xt". No payload. */
    byte buf[] = {
        0x30, 13,
        0x00, 0x03, 'a', '/', 'b',
        0x07,
        0x03, 0x00, 0x04, 't', 0x00, 'x', 't'
    };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
    MqttProps_Free(pub.props);
}

/* STRING_PAIR (USER_PROPERTY) NUL rejection - first string of pair. The
 * MqttDecode_Props path runs MqttDecode_String twice for STRING_PAIR;
 * this pins coverage on the first sub-decode propagating MALFORMED_DATA. */
TEST(decode_publish_v5_rejects_nul_in_user_prop_key)
{
    /* Wire: PUBLISH QoS 0, remain_len=14, topic "a/b", props_len=8,
     *       prop 0x26 USER_PROPERTY, key_len=2 "k\0", val_len=1 "v". */
    byte buf[] = {
        0x30, 14,
        0x00, 0x03, 'a', '/', 'b',
        0x08,
        0x26, 0x00, 0x02, 'k', 0x00,
              0x00, 0x01, 'v'
    };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
    MqttProps_Free(pub.props);
}

/* STRING_PAIR (USER_PROPERTY) NUL rejection - second string of pair.
 * Pins coverage on the second sub-decode propagating MALFORMED_DATA. */
TEST(decode_publish_v5_rejects_nul_in_user_prop_value)
{
    /* Wire: PUBLISH QoS 0, remain_len=14, topic "a/b", props_len=8,
     *       prop 0x26 USER_PROPERTY, key_len=1 "k", val_len=2 "v\0". */
    byte buf[] = {
        0x30, 14,
        0x00, 0x03, 'a', '/', 'b',
        0x08,
        0x26, 0x00, 0x01, 'k',
              0x00, 0x02, 'v', 0x00
    };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    pub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
    MqttProps_Free(pub.props);
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * MqttDecode_ConnectAck
 * ============================================================================ */

TEST(decode_connack_valid)
{
    byte buf[4];
    MqttConnectAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_CONNECT_ACK);
    buf[1] = 2;
    buf[2] = 0;
    buf[3] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_ConnectAck(buf, 4, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(0, ack.return_code);
}

TEST(decode_connack_malformed_remain_len_zero)
{
    byte buf[2];
    MqttConnectAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_CONNECT_ACK);
    buf[1] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_ConnectAck(buf, 2, &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_connack_malformed_remain_len_one)
{
    byte buf[3];
    MqttConnectAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_CONNECT_ACK);
    buf[1] = 1;
    buf[2] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_ConnectAck(buf, 3, &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* Single-byte buffer carries only the type byte — no Remaining Length VBI
 * byte is present. The fixed-header decoder must reject this rather than
 * deref header->len (which points one past the only valid byte). */
TEST(decode_connack_truncated_one_byte_buffer)
{
    byte buf[1];
    MqttConnectAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_CONNECT_ACK);
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

/* Fixed header claims remain_len=2 but the caller-supplied buffer does
 * not actually contain both variable-header bytes; MqttDecode_ConnectAck
 * must reject this rather than read flags/return_code past the buffer end. */
TEST(decode_connack_truncated_no_var_header)
{
    byte buf[2];
    MqttConnectAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_CONNECT_ACK);
    buf[1] = 2;  /* remain_len claims 2 bytes follow, but none are present */
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(decode_connack_truncated_partial_var_header)
{
    byte buf[3];
    MqttConnectAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_CONNECT_ACK);
    buf[1] = 2;  /* remain_len=2 but only 1 var-header byte present */
    buf[2] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

/* [MQTT-3.2.2-1] / [MQTT-3.2.2-4] CONNACK Flags receive-side validation.
 *
 * The Connect Acknowledge Flags byte has only bit 0 (Session Present)
 * defined; bits 7-1 are reserved and MUST be 0. Additionally, a non-zero
 * return code (refusal) MUST come back with Session Present = 0. The
 * decoder must reject violations so the client closes the connection
 * per [MQTT-4.8.0-1].
 *
 * Helper: build a 4-byte v3.1.1 CONNACK with the given flags+return_code
 * and ask MqttDecode_ConnectAck what it returns. */
static int decode_connack_flags(byte flags, byte return_code)
{
    byte buf[4];
    MqttConnectAck ack;
    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_CONNECT_ACK);
    buf[1] = 2;
    buf[2] = flags;
    buf[3] = return_code;
    XMEMSET(&ack, 0, sizeof(ack));
    return MqttDecode_ConnectAck(buf, (int)sizeof(buf), &ack);
}

TEST(decode_connack_flags_session_present_accepted)
{
    /* SP=1 with return_code=0 is the canonical resumed-session case. */
    int rc = decode_connack_flags(0x01, MQTT_CONNECT_ACK_CODE_ACCEPTED);
    ASSERT_TRUE(rc > 0);
}

TEST(decode_connack_flags_no_session_accepted)
{
    int rc = decode_connack_flags(0x00, MQTT_CONNECT_ACK_CODE_ACCEPTED);
    ASSERT_TRUE(rc > 0);
}

TEST(decode_connack_flags_reserved_bit_1_rejected)
{
    /* 0x02: bit 1 set (reserved). */
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA,
        decode_connack_flags(0x02, MQTT_CONNECT_ACK_CODE_ACCEPTED));
}

TEST(decode_connack_flags_reserved_bit_7_rejected)
{
    /* 0x80: bit 7 set (reserved). */
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA,
        decode_connack_flags(0x80, MQTT_CONNECT_ACK_CODE_ACCEPTED));
}

TEST(decode_connack_flags_all_reserved_rejected)
{
    /* 0xFE: bits 7-1 all set, SP=0. */
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA,
        decode_connack_flags(0xFE, MQTT_CONNECT_ACK_CODE_ACCEPTED));
}

TEST(decode_connack_flags_all_bits_rejected)
{
    /* 0xFF: bits 7-1 set + SP=1. Reserved-bit check fires first. */
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA,
        decode_connack_flags(0xFF, MQTT_CONNECT_ACK_CODE_ACCEPTED));
}

TEST(decode_connack_refused_with_session_present_rejected)
{
    /* [MQTT-3.2.2-4]: refused CONNACK MUST have SP=0. flags=0x01 with a
     * non-zero return code is malformed. */
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA,
        decode_connack_flags(0x01, MQTT_CONNECT_ACK_CODE_REFUSED_PROTO));
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA,
        decode_connack_flags(0x01, MQTT_CONNECT_ACK_CODE_REFUSED_ID));
}

TEST(decode_connack_refused_without_session_present_accepted)
{
    /* Refusal with SP=0 is the legal shape. */
    int rc = decode_connack_flags(0x00, MQTT_CONNECT_ACK_CODE_REFUSED_PROTO);
    ASSERT_TRUE(rc > 0);
}

/* ============================================================================
 * MqttEncode_Subscribe
 * ============================================================================ */

TEST(encode_subscribe_packet_id_zero)
{
    byte tx_buf[256];
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 0;
    rc = MqttEncode_Subscribe(tx_buf, (int)sizeof(tx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

TEST(encode_subscribe_valid)
{
    byte tx_buf[256];
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, (int)sizeof(tx_buf), &sub);
    ASSERT_TRUE(rc > 0);
}

/* [MQTT-3.8.1-1] SUBSCRIBE fixed header flags must be 0b0010 (reserved).
 * Verifies the QoS branch in MqttEncode_FixedHeader fires even for non-
 * PUBLISH packets. */
TEST(encode_subscribe_fixed_header_flags)
{
    byte tx_buf[256];
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, (int)sizeof(tx_buf), &sub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_PACKET_TYPE_SUBSCRIBE,
              MQTT_PACKET_TYPE_GET(tx_buf[0]));
    ASSERT_EQ(0x2, (int)MQTT_PACKET_FLAGS_GET(tx_buf[0]));
}

/* [MQTT-3.8.3-1] Payload options byte bits 0-1 carry QoS. Remaining bits
 * carry v5-only No Local (bit 2), Retain As Published (bit 3), and Retain
 * Handling (bits 4-5); bits 6-7 are reserved. The encoded options byte is
 * the last byte of a single-topic SUBSCRIBE packet. */
TEST(encode_subscribe_options_byte_qos0)
{
    byte tx_buf[256];
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "a";
    topic.qos = MQTT_QOS_0;
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, (int)sizeof(tx_buf), &sub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(0x00, tx_buf[rc - 1]);
}

TEST(encode_subscribe_options_byte_qos1)
{
    byte tx_buf[256];
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "a";
    topic.qos = MQTT_QOS_1;
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, (int)sizeof(tx_buf), &sub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(0x01, tx_buf[rc - 1]);
}

TEST(encode_subscribe_options_byte_qos2)
{
    byte tx_buf[256];
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "a";
    topic.qos = MQTT_QOS_2;
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, (int)sizeof(tx_buf), &sub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(0x02, tx_buf[rc - 1]);
}

/* f-2360: topic_filter with strlen > 65535 must be rejected with a negative
 * return. Guards the unchecked tx_payload += MqttEncode_String(...) in the
 * SUBSCRIBE payload loop. */
TEST(encode_subscribe_topic_filter_oversized_rejected)
{
    const int str_len = 0x10000; /* one byte past MQTT UTF-8 limit */
    const int buf_len = str_len + 64;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *filter = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    if (tx_buf == NULL || filter == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(filter);
        FAIL("allocation failed");
    }
    XMEMSET(filter, 'A', str_len);
    filter[str_len] = '\0';

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = filter;
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, buf_len, &sub);

    WOLFMQTT_FREE(filter);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* when multiple topics are supplied and a later one is oversized,
 * the encoder must still reject - the length-validation loop covers every
 * entry, not just the first. */
TEST(encode_subscribe_topic_filter_oversized_second_rejected)
{
    const int str_len = 0x10000;
    const int buf_len = str_len + 128;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *filter = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttSubscribe sub;
    MqttTopic topics[2];
    int rc;

    if (tx_buf == NULL || filter == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(filter);
        FAIL("allocation failed");
    }
    XMEMSET(filter, 'B', str_len);
    filter[str_len] = '\0';

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topics, 0, sizeof(topics));
    topics[0].topic_filter = "ok/topic";
    topics[1].topic_filter = filter;
    sub.topics = topics;
    sub.topic_count = 2;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, buf_len, &sub);

    WOLFMQTT_FREE(filter);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* [MQTT-3.8.1-1] SUBSCRIBE fixed header reserved flags MUST equal 0b0010,
 * which encodes QoS 1. Verifies the QoS 1 bit directly via
 * MQTT_PACKET_FLAGS_GET_QOS so a mutation of MQTT_QOS_1 to MQTT_QOS_0 in
 * MqttEncode_Subscribe's call to MqttEncode_FixedHeader is detected. */
TEST(encode_subscribe_has_qos1_flag)
{
    byte tx_buf[256];
    MqttSubscribe sub;
    MqttTopic topic;
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    sub.topics = &topic;
    sub.topic_count = 1;
    sub.packet_id = 1;
    rc = MqttEncode_Subscribe(tx_buf, (int)sizeof(tx_buf), &sub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_QOS_1, MQTT_PACKET_FLAGS_GET_QOS(tx_buf[0]));
}

/* ============================================================================
 * MqttEncode_Unsubscribe
 * ============================================================================ */

TEST(encode_unsubscribe_packet_id_zero)
{
    byte tx_buf[256];
    MqttUnsubscribe unsub;
    MqttTopic topic;
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    unsub.topics = &topic;
    unsub.topic_count = 1;
    unsub.packet_id = 0;
    rc = MqttEncode_Unsubscribe(tx_buf, (int)sizeof(tx_buf), &unsub);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

TEST(encode_unsubscribe_valid)
{
    byte tx_buf[256];
    MqttUnsubscribe unsub;
    MqttTopic topic;
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    unsub.topics = &topic;
    unsub.topic_count = 1;
    unsub.packet_id = 1;
    rc = MqttEncode_Unsubscribe(tx_buf, (int)sizeof(tx_buf), &unsub);
    ASSERT_TRUE(rc > 0);
}

/* [MQTT-3.10.1-1] UNSUBSCRIBE fixed header flags must be 0b0010. */
TEST(encode_unsubscribe_fixed_header_flags)
{
    byte tx_buf[256];
    MqttUnsubscribe unsub;
    MqttTopic topic;
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    unsub.topics = &topic;
    unsub.topic_count = 1;
    unsub.packet_id = 1;
    rc = MqttEncode_Unsubscribe(tx_buf, (int)sizeof(tx_buf), &unsub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_PACKET_TYPE_UNSUBSCRIBE,
              MQTT_PACKET_TYPE_GET(tx_buf[0]));
    ASSERT_EQ(0x2, (int)MQTT_PACKET_FLAGS_GET(tx_buf[0]));
}

/* topic_filter with strlen > 65535 must be rejected with a negative
 * return. Guards the unchecked tx_payload += MqttEncode_String(...) in the
 * UNSUBSCRIBE payload loop. */
TEST(encode_unsubscribe_topic_filter_oversized_rejected)
{
    const int str_len = 0x10000; /* one byte past MQTT UTF-8 limit */
    const int buf_len = str_len + 64;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *filter = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttUnsubscribe unsub;
    MqttTopic topic;
    int rc;

    if (tx_buf == NULL || filter == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(filter);
        FAIL("allocation failed");
    }
    XMEMSET(filter, 'A', str_len);
    filter[str_len] = '\0';

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = filter;
    unsub.topics = &topic;
    unsub.topic_count = 1;
    unsub.packet_id = 1;
    rc = MqttEncode_Unsubscribe(tx_buf, buf_len, &unsub);

    WOLFMQTT_FREE(filter);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* when multiple topics are supplied and a later one is oversized,
 * the encoder must still reject - the length-validation loop covers every
 * entry, not just the first. */
TEST(encode_unsubscribe_topic_filter_oversized_second_rejected)
{
    const int str_len = 0x10000;
    const int buf_len = str_len + 128;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *filter = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttUnsubscribe unsub;
    MqttTopic topics[2];
    int rc;

    if (tx_buf == NULL || filter == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(filter);
        FAIL("allocation failed");
    }
    XMEMSET(filter, 'B', str_len);
    filter[str_len] = '\0';

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topics, 0, sizeof(topics));
    topics[0].topic_filter = "ok/topic";
    topics[1].topic_filter = filter;
    unsub.topics = topics;
    unsub.topic_count = 2;
    unsub.packet_id = 1;
    rc = MqttEncode_Unsubscribe(tx_buf, buf_len, &unsub);

    WOLFMQTT_FREE(filter);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* [MQTT-3.10.1-1] UNSUBSCRIBE fixed header reserved flags MUST equal 0b0010,
 * which encodes QoS 1. Verifies the QoS 1 bit directly via
 * MQTT_PACKET_FLAGS_GET_QOS so a mutation of MQTT_QOS_1 to MQTT_QOS_0 in
 * MqttEncode_Unsubscribe's call to MqttEncode_FixedHeader is detected. */
TEST(encode_unsubscribe_has_qos1_flag)
{
    byte tx_buf[256];
    MqttUnsubscribe unsub;
    MqttTopic topic;
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(&topic, 0, sizeof(topic));
    topic.topic_filter = "test/topic";
    unsub.topics = &topic;
    unsub.topic_count = 1;
    unsub.packet_id = 1;
    rc = MqttEncode_Unsubscribe(tx_buf, (int)sizeof(tx_buf), &unsub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_QOS_1, MQTT_PACKET_FLAGS_GET_QOS(tx_buf[0]));
}

/* ============================================================================
 * MqttEncode_Connect
 * ============================================================================ */

/* [MQTT-3.1.2-22] Password must not be present without username */
TEST(encode_connect_password_without_username)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    conn.username = NULL;
    conn.password = "secret";
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(encode_connect_username_and_password)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    conn.username = "user";
    conn.password = "secret";
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
}

TEST(encode_connect_username_only)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    conn.username = "user";
    conn.password = NULL;
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
}

TEST(encode_connect_no_credentials)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    conn.username = NULL;
    conn.password = NULL;
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
}

/* [MQTT-3.1.1] CONNECT fixed header flags must be all zero. */
TEST(encode_connect_fixed_header_flags)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_PACKET_TYPE_CONNECT,
              MQTT_PACKET_TYPE_GET(tx_buf[0]));
    ASSERT_EQ(0, (int)MQTT_PACKET_FLAGS_GET(tx_buf[0]));
}

/* CONNECT variable header layout: 2-byte protocol name length + 4-byte "MQTT"
 * + 1-byte protocol level + 1-byte connect flags. Offset computed from the
 * decoded VBI instead of assuming a 1-byte remaining-length encoding. */
static int connect_flags_offset(const byte *tx_buf, int tx_buf_len)
{
    word32 remain_len = 0;
    int vbi_len = MqttDecode_Vbi((byte*)&tx_buf[1], &remain_len,
                                 (word32)(tx_buf_len - 1));
    if (vbi_len < 0) {
        return vbi_len;
    }
    return 1 + vbi_len + 2 + 4 + 1;
}

/* [MQTT-3.1.2] CONNECT variable header flags byte encodes credential and
 * clean-session bits. */
TEST(encode_connect_flags_username_password_clean)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;
    int flags_off;
    byte flags;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    conn.username = "user";
    conn.password = "pass";
    conn.clean_session = 1;
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
    flags_off = connect_flags_offset(tx_buf, rc);
    ASSERT_TRUE(flags_off > 0 && flags_off < rc);
    flags = tx_buf[flags_off];
    ASSERT_EQ(MQTT_CONNECT_FLAG_USERNAME,
              flags & MQTT_CONNECT_FLAG_USERNAME);
    ASSERT_EQ(MQTT_CONNECT_FLAG_PASSWORD,
              flags & MQTT_CONNECT_FLAG_PASSWORD);
    ASSERT_EQ(MQTT_CONNECT_FLAG_CLEAN_SESSION,
              flags & MQTT_CONNECT_FLAG_CLEAN_SESSION);
    ASSERT_EQ(0, flags & MQTT_CONNECT_FLAG_WILL_FLAG);
    ASSERT_EQ(0, flags & MQTT_CONNECT_FLAG_WILL_RETAIN);
    ASSERT_EQ(0, flags & MQTT_CONNECT_FLAG_WILL_QOS_MASK);
    ASSERT_EQ(0, flags & MQTT_CONNECT_FLAG_RESERVED);
}

TEST(encode_connect_flags_none)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;
    int flags_off;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
    flags_off = connect_flags_offset(tx_buf, rc);
    ASSERT_TRUE(flags_off > 0 && flags_off < rc);
    ASSERT_EQ(0, (int)tx_buf[flags_off]);
}

TEST(encode_connect_flags_clean_session_only)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;
    int flags_off;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    conn.clean_session = 1;
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
    flags_off = connect_flags_offset(tx_buf, rc);
    ASSERT_TRUE(flags_off > 0 && flags_off < rc);
    ASSERT_EQ(MQTT_CONNECT_FLAG_CLEAN_SESSION, (int)tx_buf[flags_off]);
}

TEST(encode_connect_flags_username_only)
{
    byte tx_buf[256];
    MqttConnect conn;
    int rc;
    int flags_off;

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "test_client";
    conn.username = "user";
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
    flags_off = connect_flags_offset(tx_buf, rc);
    ASSERT_TRUE(flags_off > 0 && flags_off < rc);
    ASSERT_EQ(MQTT_CONNECT_FLAG_USERNAME,
              tx_buf[flags_off] & MQTT_CONNECT_FLAG_USERNAME);
    ASSERT_EQ(0, tx_buf[flags_off] & MQTT_CONNECT_FLAG_PASSWORD);
}

TEST(encode_connect_flags_lwt_qos1_retain)
{
    byte tx_buf[256];
    byte lwt_payload[] = {'b', 'y', 'e'};
    MqttConnect conn;
    MqttMessage lwt;
    int rc;
    int flags_off;
    byte flags;

    XMEMSET(&conn, 0, sizeof(conn));
    XMEMSET(&lwt, 0, sizeof(lwt));
    lwt.topic_name = "will/topic";
    lwt.buffer = lwt_payload;
    lwt.total_len = (word32)sizeof(lwt_payload);
    lwt.qos = MQTT_QOS_1;
    lwt.retain = 1;

    conn.client_id = "test_client";
    conn.enable_lwt = 1;
    conn.lwt_msg = &lwt;
    rc = MqttEncode_Connect(tx_buf, (int)sizeof(tx_buf), &conn);
    ASSERT_TRUE(rc > 0);
    flags_off = connect_flags_offset(tx_buf, rc);
    ASSERT_TRUE(flags_off > 0 && flags_off < rc);
    flags = tx_buf[flags_off];
    ASSERT_EQ(MQTT_CONNECT_FLAG_WILL_FLAG,
              flags & MQTT_CONNECT_FLAG_WILL_FLAG);
    ASSERT_EQ(MQTT_CONNECT_FLAG_WILL_RETAIN,
              flags & MQTT_CONNECT_FLAG_WILL_RETAIN);
    ASSERT_EQ((int)MQTT_QOS_1,
              (int)MQTT_CONNECT_FLAG_GET_QOS(flags));
    ASSERT_EQ(0, flags & MQTT_CONNECT_FLAG_USERNAME);
    ASSERT_EQ(0, flags & MQTT_CONNECT_FLAG_PASSWORD);
    ASSERT_EQ(0, flags & MQTT_CONNECT_FLAG_CLEAN_SESSION);
}

/* f-2360: client_id with strlen > 65535 must be rejected with a negative
 * return. MqttEncode_String returns -1 for such strings; the encoder must
 * not report header_len+remain_len as a successful encode while tx_payload
 * silently moves backward by one byte. */
TEST(encode_connect_client_id_oversized_rejected)
{
    const int str_len = 0x10000; /* one byte past MQTT UTF-8 limit */
    const int buf_len = str_len + 64;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *client_id = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttConnect conn;
    int rc;

    if (tx_buf == NULL || client_id == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(client_id);
        FAIL("allocation failed");
    }
    XMEMSET(client_id, 'A', str_len);
    client_id[str_len] = '\0';

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = client_id;
    rc = MqttEncode_Connect(tx_buf, buf_len, &conn);

    WOLFMQTT_FREE(client_id);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* f-2360: username with strlen > 65535. Password is supplied so the
 * USERNAME+PASSWORD branch exercises both credential encodes. */
TEST(encode_connect_username_oversized_rejected)
{
    const int str_len = 0x10000;
    const int buf_len = str_len + 128;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *username = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttConnect conn;
    int rc;

    if (tx_buf == NULL || username == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(username);
        FAIL("allocation failed");
    }
    XMEMSET(username, 'U', str_len);
    username[str_len] = '\0';

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "cid";
    conn.username = username;
    conn.password = "pw";
    rc = MqttEncode_Connect(tx_buf, buf_len, &conn);

    WOLFMQTT_FREE(username);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* f-2360: password with strlen > 65535. */
TEST(encode_connect_password_oversized_rejected)
{
    const int str_len = 0x10000;
    const int buf_len = str_len + 128;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *password = (char*)WOLFMQTT_MALLOC(str_len + 1);
    MqttConnect conn;
    int rc;

    if (tx_buf == NULL || password == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(password);
        FAIL("allocation failed");
    }
    XMEMSET(password, 'P', str_len);
    password[str_len] = '\0';

    XMEMSET(&conn, 0, sizeof(conn));
    conn.client_id = "cid";
    conn.username = "user";
    conn.password = password;
    rc = MqttEncode_Connect(tx_buf, buf_len, &conn);

    WOLFMQTT_FREE(password);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* f-2360: LWT topic_name with strlen > 65535. */
TEST(encode_connect_lwt_topic_oversized_rejected)
{
    const int str_len = 0x10000;
    const int buf_len = str_len + 128;
    byte *tx_buf = (byte*)WOLFMQTT_MALLOC(buf_len);
    char *lwt_topic = (char*)WOLFMQTT_MALLOC(str_len + 1);
    byte lwt_payload[] = { 'b', 'y', 'e' };
    MqttConnect conn;
    MqttMessage lwt;
    int rc;

    if (tx_buf == NULL || lwt_topic == NULL) {
        WOLFMQTT_FREE(tx_buf);
        WOLFMQTT_FREE(lwt_topic);
        FAIL("allocation failed");
    }
    XMEMSET(lwt_topic, 'T', str_len);
    lwt_topic[str_len] = '\0';

    XMEMSET(&conn, 0, sizeof(conn));
    XMEMSET(&lwt, 0, sizeof(lwt));
    lwt.topic_name = lwt_topic;
    lwt.buffer = lwt_payload;
    lwt.total_len = (word32)sizeof(lwt_payload);
    conn.client_id = "cid";
    conn.enable_lwt = 1;
    conn.lwt_msg = &lwt;
    rc = MqttEncode_Connect(tx_buf, buf_len, &conn);

    WOLFMQTT_FREE(lwt_topic);
    WOLFMQTT_FREE(tx_buf);
    ASSERT_TRUE(rc < 0);
}

/* ============================================================================
 * MqttDecode_Connect (broker-side)
 * ============================================================================ */

#ifdef WOLFMQTT_BROKER
/* (a) Valid v3.1.1 CONNECT with username + password: decoder must surface both
 * credential strings and the session/keep-alive fields. */
TEST(decode_connect_v311_username_password)
{
    byte buf[256];
    MqttConnect enc, dec;
    int enc_len, dec_len;

    XMEMSET(&enc, 0, sizeof(enc));
    enc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    enc.client_id      = "test_client";
    enc.username       = "user";
    enc.password       = "pass";
    enc.clean_session  = 1;
    enc.keep_alive_sec = 60;

    enc_len = MqttEncode_Connect(buf, (int)sizeof(buf), &enc);
    ASSERT_TRUE(enc_len > 0);

    XMEMSET(&dec, 0, sizeof(dec));
    dec_len = MqttDecode_Connect(buf, enc_len, &dec);
    ASSERT_EQ(enc_len, dec_len);
    ASSERT_EQ(MQTT_CONNECT_PROTOCOL_LEVEL_4, dec.protocol_level);
    ASSERT_EQ(1, dec.clean_session);
    ASSERT_EQ(0, dec.enable_lwt);
    ASSERT_EQ(60, dec.keep_alive_sec);
    ASSERT_NOT_NULL(dec.client_id);
    ASSERT_EQ(0, XMEMCMP(dec.client_id, "test_client",
                         XSTRLEN("test_client")));
    ASSERT_NOT_NULL(dec.username);
    ASSERT_EQ(0, XMEMCMP(dec.username, "user", 4));
    ASSERT_NOT_NULL(dec.password);
    ASSERT_EQ(0, XMEMCMP(dec.password, "pass", 4));
}

/* (b) CONNECT with USERNAME/PASSWORD flags clear: decoder must NULL the
 * credential fields so the caller never observes uninitialized rx_buf
 * bytes as credentials. Pre-poison the struct to make the clearing visible. */
TEST(decode_connect_v311_no_credentials)
{
    byte buf[256];
    MqttConnect enc, dec;
    int enc_len, dec_len;

    XMEMSET(&enc, 0, sizeof(enc));
    enc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    enc.client_id      = "c1";
    enc.clean_session  = 1;

    enc_len = MqttEncode_Connect(buf, (int)sizeof(buf), &enc);
    ASSERT_TRUE(enc_len > 0);

    XMEMSET(&dec, 0, sizeof(dec));
    dec.username = (const char*)0x1;
    dec.password = (const char*)0x1;
    dec_len = MqttDecode_Connect(buf, enc_len, &dec);
    ASSERT_EQ(enc_len, dec_len);
    ASSERT_NULL(dec.username);
    ASSERT_NULL(dec.password);
}

/* (c) Wrong protocol name ("MQT_" with correct length=4) must be rejected
 * with MQTT_CODE_ERROR_MALFORMED_DATA. Catches an '||' -> '&&' mutation of
 * the protocol-name guard, where an acceptance would require both the
 * length and name to simultaneously be wrong. */
TEST(decode_connect_wrong_protocol_name)
{
    byte buf[] = {
        0x10, 0x10,                     /* CONNECT, remain_len = 16 */
        0x00, 0x04,                     /* protocol name length = 4 */
        'M', 'Q', 'T', '_',             /* WRONG protocol name */
        0x04,                           /* protocol level = v3.1.1 */
        0x02,                           /* flags: clean_session */
        0x00, 0x3C,                     /* keep alive = 60 */
        0x00, 0x04, 'c', 'i', 'd', '1'  /* client_id "cid1" */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* (d) Wrong protocol length (3 instead of 4) must be rejected with
 * MQTT_CODE_ERROR_MALFORMED_DATA. Paired with (c) this covers both sides
 * of the length/name disjunction. */
TEST(decode_connect_wrong_protocol_length)
{
    byte buf[] = {
        0x10, 0x10,
        0x00, 0x03,                     /* WRONG protocol name length = 3 */
        'M', 'Q', 'T', 'T',
        0x04,
        0x02,
        0x00, 0x3C,
        0x00, 0x04, 'c', 'i', 'd', '1'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* (e) CONNECT with WILL_FLAG set: decoder must set enable_lwt=1 and populate
 * lwt_msg topic/payload/qos/retain from the flags and payload. Catches a
 * mutation that flips the enable_lwt boolean, which would drop LWT decoding
 * entirely. */
TEST(decode_connect_v311_with_lwt)
{
    byte buf[256];
    byte lwt_payload[] = { 'b', 'y', 'e' };
    MqttConnect enc, dec;
    MqttMessage enc_lwt, dec_lwt;
    int enc_len, dec_len;

    XMEMSET(&enc, 0, sizeof(enc));
    XMEMSET(&enc_lwt, 0, sizeof(enc_lwt));
    enc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    enc.client_id      = "c1";
    enc.enable_lwt     = 1;
    enc.lwt_msg        = &enc_lwt;
    enc_lwt.topic_name = "will/topic";
    enc_lwt.buffer     = lwt_payload;
    enc_lwt.total_len  = (word32)sizeof(lwt_payload);
    enc_lwt.qos        = MQTT_QOS_1;
    enc_lwt.retain     = 1;

    enc_len = MqttEncode_Connect(buf, (int)sizeof(buf), &enc);
    ASSERT_TRUE(enc_len > 0);

    XMEMSET(&dec, 0, sizeof(dec));
    XMEMSET(&dec_lwt, 0, sizeof(dec_lwt));
    dec.lwt_msg = &dec_lwt;
    dec_len = MqttDecode_Connect(buf, enc_len, &dec);
    ASSERT_EQ(enc_len, dec_len);
    ASSERT_EQ(1, dec.enable_lwt);
    ASSERT_EQ((int)MQTT_QOS_1, (int)dec_lwt.qos);
    ASSERT_EQ(1, dec_lwt.retain);
    ASSERT_EQ((int)XSTRLEN("will/topic"), (int)dec_lwt.topic_name_len);
    ASSERT_EQ(0, XMEMCMP(dec_lwt.topic_name, "will/topic",
                         XSTRLEN("will/topic")));
    ASSERT_EQ((word32)sizeof(lwt_payload), dec_lwt.total_len);
    ASSERT_EQ((word32)sizeof(lwt_payload), dec_lwt.buffer_len);
    ASSERT_NOT_NULL(dec_lwt.buffer);
    ASSERT_EQ(0, XMEMCMP(dec_lwt.buffer, lwt_payload, sizeof(lwt_payload)));
}

/* [MQTT-1.5.3-2]: an embedded NUL in the ClientId must be rejected.
 * Otherwise BrokerClient_FindByClientId() (which uses XSTRCMP) will treat
 * "ad\0min" as "ad" and collide with an existing "ad" session. */
TEST(decode_connect_rejects_nul_in_client_id)
{
    byte buf[] = {
        0x10, 0x12,                         /* CONNECT, remain_len = 18 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',     /* protocol name */
        0x04,                               /* protocol level v3.1.1 */
        0x02,                               /* flags: clean_session */
        0x00, 0x3C,                         /* keep alive */
        0x00, 0x06, 'a', 'd', 0x00, 'm', 'i', 'n'  /* client_id with NUL */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.1.2-20] Password Flag=0 means no password field is present in the
 * payload. A peer that sets User Name Flag=1, Password Flag=0 but appends
 * password-shaped bytes after the user name produces a CONNECT whose
 * Remaining Length covers more than the flagged fields. The decoder must
 * reject the trailing bytes as malformed instead of silently treating the
 * packet as username-only-with-extra-trailer. Hand-built wire mirrors the
 * issue's reproducer exactly. */
TEST(decode_connect_password_flag_zero_with_extra_payload_rejected)
{
    byte buf[] = {
        0x10, 0x1D,                     /* CONNECT, remain_len = 29 */
        0x00, 0x04, 'M', 'Q', 'T', 'T', /* protocol name */
        0x04,                           /* protocol level = 4 (v3.1.1) */
        0x82,                           /* flags: clean_session|user_name */
        0x00, 0x3C,                     /* keep alive = 60 */
        0x00, 0x03, 'c', 'i', 'd',      /* client_id "cid" */
        0x00, 0x04, 'u', 's', 'e', 'r', /* username "user" */
        0x00, 0x06, 's', 'e', 'c', 'r', /* extra password-shaped bytes */
        'e', 't'                        /* "secret" - must not be accepted */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-2]: an embedded NUL in the username must be rejected.
 * Otherwise BrokerStrCompare() (which uses XSTRLEN) will treat
 * "us\0er" as "us" and accept it against a configured "us" credential. */
TEST(decode_connect_rejects_nul_in_username)
{
    byte buf[] = {
        0x10, 0x15,                         /* CONNECT, remain_len = 21 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x82,                               /* clean_session + USERNAME */
        0x00, 0x3C,
        0x00, 0x02, 'c', '1',               /* client_id "c1" */
        0x00, 0x05, 'u', 's', 0x00, 'e', 'r'  /* username with NUL */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* User Name Flag=0 cannot legally be followed by a username (and any
 * trailing bytes therefore include none of the flagged fields). The
 * payload-consumption check rejects the trailer regardless of which flag
 * the bytes are shaped like. */
TEST(decode_connect_username_flag_zero_with_extra_payload_rejected)
{
    byte buf[] = {
        0x10, 0x15,                     /* CONNECT, remain_len = 21 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,                           /* flags: clean_session only */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd',      /* client_id */
        0x00, 0x04, 'u', 's', 'e', 'r'  /* username-shaped extra bytes */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-2] / [MQTT-4.7.3-2]: a Will Topic with embedded NUL must
 * be rejected. The same C-string truncation that affects PUBLISH topics
 * applies to Will Topics persisted by the broker. */
TEST(decode_connect_rejects_nul_in_will_topic)
{
    byte buf[] = {
        0x10, 0x16,                         /* CONNECT, remain_len = 22 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x06,                               /* clean_session + WILL_FLAG */
        0x00, 0x3C,
        0x00, 0x02, 'c', '1',               /* client_id */
        0x00, 0x03, 't', 0x00, 'p',         /* will topic with NUL */
        0x00, 0x01, 'X'                     /* will payload */
    };
    MqttConnect dec;
    MqttMessage lwt;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    XMEMSET(&lwt, 0, sizeof(lwt));
    dec.lwt_msg = &lwt;
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.1.2-11] Will Flag=0 forbids Will Topic and Will Message fields
 * in the payload. Wire matches the issue's reproducer: ClientId "cid"
 * followed by a complete Will Topic/Message pair after Will Flag is
 * cleared. The CONNECT consumed-length check rejects the trailing
 * bytes regardless of which fields they look like. */
TEST(decode_connect_will_flag_zero_with_will_topic_and_message_rejected)
{
    byte buf[] = {
        0x10, 0x21,                     /* CONNECT, remain_len = 33 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,                           /* flags: clean_session only */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd',
        0x00, 0x0A, 'w', 'i', 'l', 'l', '/', 't', 'o', 'p', 'i', 'c',
        0x00, 0x04, 'b', 'o', 'o', 'm'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* Will Flag=0 with will-topic-shaped trailing bytes is the symmetric case
 * for the LWT half of the payload. Pins the same consumed-length invariant
 * for the will fields. */
TEST(decode_connect_will_flag_zero_with_extra_payload_rejected)
{
    byte buf[] = {
        0x10, 0x17,                     /* CONNECT, remain_len = 23 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,                           /* flags: clean_session only */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd',
        0x00, 0x06, 'w', '/', 't', 'o', 'p', 'i'  /* extra "w/topi" */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.1.2-3] CONNECT flags bit 0 is reserved and MUST be 0. Applies
 * regardless of protocol level. Flags 0x03 = reserved | clean_session. */
TEST(decode_connect_reserved_flag_bit_rejected)
{
    byte buf[] = {
        0x10, 0x0F,                     /* CONNECT, remain_len = 15 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,                           /* protocol level = 4 */
        0x03,                           /* flags: reserved | clean_session */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.1.2-13] If Will Flag is 0, Will QoS MUST be 0. Flags 0x0A =
 * clean_session | will_qos=1 with Will Flag clear. */
TEST(decode_connect_will_qos_with_will_flag_zero_rejected)
{
    byte buf[] = {
        0x10, 0x0F,                     /* CONNECT, remain_len = 15 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x0A,                           /* will_qos=1 but will_flag=0 */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.1.2-15] If Will Flag is 0, Will Retain MUST be 0. Flags 0x22 =
 * clean_session | will_retain with Will Flag clear. */
TEST(decode_connect_will_retain_with_will_flag_zero_rejected)
{
    byte buf[] = {
        0x10, 0x0F,                     /* CONNECT, remain_len = 15 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x22,                           /* will_retain but will_flag=0 */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.1.2-14] Will QoS = 3 is reserved. Flags 0x1E set the full QoS
 * mask (bits 4-3 = 0b11) along with Will Flag and Clean Session. The
 * earlier Will-Flag-0 check would not catch this - only the QoS-value
 * check fires. Provides full Will fields so a regression that drops the
 * QoS=3 check returns success rather than tripping a downstream
 * OUT_OF_BUFFER. */
TEST(decode_connect_will_qos3_rejected)
{
    byte buf[] = {
        0x10, 0x1C,                     /* CONNECT, remain_len = 28 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x1E,                           /* clean | will_flag | will_qos=3 */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd',
        0x00, 0x06, 'w', '/', 't', 'o', 'p', 'c', /* will topic */
        0x00, 0x03, 'b', 'y', 'e'                  /* will payload */
    };
    MqttConnect dec;
    MqttMessage lwt;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    XMEMSET(&lwt, 0, sizeof(lwt));
    dec.lwt_msg = &lwt;
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-1] / [MQTT-3.1.3-10] CONNECT Will Topic must be a
 * well-formed UTF-8 string. Wire flag 0x06 = clean | will_flag, Will
 * QoS = 0, ClientId "cid", Will Topic = C0 AF (overlong representation
 * of '/'). MqttDecode_String routes the field through Utf8WellFormed
 * which catches the malformed encoding before the decoder accepts. */
TEST(decode_connect_will_topic_invalid_utf8_rejected)
{
    /* remain = 6 + 1 + 1 + 2 + 5 + 4 + 3 = 22 bytes */
    byte buf[] = {
        0x10, 0x16,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x06,                                  /* clean | will_flag */
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd',
        0x00, 0x02, 0xC0, 0xAF,                /* overlong UTF-8 */
        0x00, 0x01, 'm'
    };
    MqttConnect dec;
    MqttMessage lwt;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    XMEMSET(&lwt, 0, sizeof(lwt));
    dec.lwt_msg = &lwt;
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-2] U+0000 MUST NOT appear in any MQTT UTF-8 encoded
 * string. Wire is the issue's reproducer: Will Topic "a\\0b" has a
 * length-valid 3-byte string with U+0000 embedded. */
TEST(decode_connect_will_topic_contains_u0000_rejected)
{
    /* remain = 6 + 1 + 1 + 2 + 5 + 5 + 3 = 23 bytes */
    byte buf[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x06,
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd',
        0x00, 0x03, 'a', 0x00, 'b',            /* embedded U+0000 */
        0x00, 0x01, 'm'
    };
    MqttConnect dec;
    MqttMessage lwt;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    XMEMSET(&lwt, 0, sizeof(lwt));
    dec.lwt_msg = &lwt;
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.1.2-22] If the User Name Flag is 0, the Password Flag MUST be 0.
 * The encoder already enforces this; the decoder must too. Wire is
 * flags 0x42 = clean_session | password, with client_id "cid" followed
 * by a "secret" password field. Catches a regression that drops the
 * receive-side flag-pair check and silently accepts a password without
 * a user name. */
TEST(decode_connect_password_flag_without_username_flag_rejected)
{
    byte buf[] = {
        0x10, 0x17,                     /* CONNECT, remain_len = 23 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,                           /* protocol level = 4 (v3.1.1) */
        0x42,                           /* flags: clean_session|password */
        0x00, 0x3C,                     /* keep alive = 60 */
        0x00, 0x03, 'c', 'i', 'd',      /* client_id "cid" */
        0x00, 0x06, 's', 'e', 'c', 'r', /* password "secret" */
        'e', 't'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* Single-byte trailing garbage (no flag fields beyond client_id) catches
 * an off-by-one form of the consumption check. The non-malformed case
 * (decode_connect_v311_no_credentials above) is the partner that prevents
 * a "reject everything" mutation. */
TEST(decode_connect_trailing_garbage_rejected)
{
    byte buf[] = {
        0x10, 0x10,                     /* CONNECT, remain_len = 16 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,
        0x00, 0x3C,
        0x00, 0x03, 'c', 'i', 'd',
        0xFF                            /* one trailing junk byte */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

#ifdef WOLFMQTT_V5
/* MQTT v5 has a different decode path than v3.1.1 (properties walked
 * before client_id, separate LWT properties), but the NUL rejection
 * lives inside MqttDecode_String and so applies uniformly. This pins
 * coverage on the v5 branch so a future refactor cannot quietly bypass
 * the check on one protocol level. */
TEST(decode_connect_v5_rejects_nul_in_client_id)
{
    byte buf[] = {
        0x10, 0x13,                         /* CONNECT, remain_len = 19 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,                               /* protocol level v5 */
        0x02,                               /* flags: clean_session */
        0x00, 0x3C,                         /* keep alive */
        0x00,                               /* props_len = 0 (VBI) */
        0x00, 0x06, 'a', 'd', 0x00, 'm', 'i', 'n'  /* client_id with NUL */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    dec.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
    MqttProps_Free(dec.props);
}

/* MQTT v5 section 3.1.2.9 explicitly allows Password without User Name -
 * "This version of the protocol allows the sending of a Password with no
 * User Name, where MQTT v3.1.1 did not." Pins the protocol-level gate on
 * the [MQTT-3.1.2-22] check: a future change that drops the level guard
 * would reject this valid v5 wire and trip this test. The companion
 * negative case is decode_connect_password_flag_without_username_flag_-
 * rejected above (level=4). */
TEST(decode_connect_v5_password_without_username_accepted)
{
    byte buf[] = {
        0x10, 0x18,                     /* CONNECT, remain_len = 24 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,                           /* protocol level = 5 */
        0x42,                           /* flags: clean_session|password */
        0x00, 0x3C,                     /* keep alive */
        0x00,                           /* properties length = 0 */
        0x00, 0x03, 'c', 'i', 'd',      /* client_id "cid" */
        0x00, 0x06, 's', 'e', 'c', 'r', /* password "secret" */
        'e', 't'
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    dec.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_CONNECT_PROTOCOL_LEVEL_5, dec.protocol_level);
    ASSERT_NULL(dec.username);
    ASSERT_NOT_NULL(dec.password);
    ASSERT_EQ(0, XMEMCMP(dec.password, "secret", 6));
    MqttProps_Free(dec.props);
}

/* Pins the goto-cleanup path: when a v5 CONNECT decode succeeds through
 * the Properties block but fails on a later field (here the client_id
 * trips the embedded-NUL check inside MqttDecode_String), the decoder
 * must free the already-allocated property list and null the pointer
 * before returning. A regression that drops the cleanup label and goes
 * back to bare returns would leak the User Property allocation - this
 * test alone won't see the leak (no valgrind in CI), but it does catch
 * the structural invariant: dec.props == NULL on error. */
TEST(decode_connect_v5_props_freed_on_client_id_error)
{
    byte buf[] = {
        0x10, 0x1A,                         /* CONNECT, remain_len = 26 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,                               /* protocol level v5 */
        0x02,                               /* flags: clean_session */
        0x00, 0x3C,                         /* keep alive */
        0x07,                               /* props_len VBI = 7 */
        0x26,                               /* User Property */
        0x00, 0x01, 'k',                    /* key "k" */
        0x00, 0x01, 'v',                    /* value "v" */
        0x00, 0x06, 'a', 'd', 0x00, 'm', 'i', 'n'  /* client_id with NUL */
    };
    MqttConnect dec;
    int rc;

    XMEMSET(&dec, 0, sizeof(dec));
    dec.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Connect(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
    /* Cleanup must have freed the props list and nulled the pointer. */
    ASSERT_NULL(dec.props);
}
#endif /* WOLFMQTT_V5 */
#endif /* WOLFMQTT_BROKER */

/* ============================================================================
 * MqttDecode_Subscribe (broker-side)
 * ============================================================================ */

#ifdef WOLFMQTT_BROKER
/* Hand-built v3.1.1 SUBSCRIBE wire buffer serves as an independent oracle.
 * Wire: type|flags=0x82, remaining=6, packet_id=0x0001, topic_len=0x0001,
 *       "a", options=0x01 (QoS 1). */
TEST(decode_subscribe_v311_single_topic)
{
    byte rx_buf[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01,
        0x61,
        0x01
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(1, sub.packet_id);
    ASSERT_EQ(1, sub.topic_count);
    ASSERT_EQ(MQTT_QOS_1, topic_arr[0].qos);
    ASSERT_NOT_NULL(topic_arr[0].topic_filter);
    ASSERT_EQ(0, XMEMCMP(topic_arr[0].topic_filter, "a", 1));
}

/* MQTT 3.1.1 section 3.8.3.1: Requested QoS bits (0-1) = 0b11 is reserved and
 * MUST be rejected. Pre-fix the decoder forwarded the raw value and
 * relied on the broker's defensive QoS cap; the broker cap is now dead
 * code on the decoded path but kept for safety. */
TEST(decode_subscribe_v311_qos3_rejected)
{
    byte rx_buf[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01,
        0x61,
        0x03
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* MQTT 3.1.1 section 3.8.3.1: bits 2-7 of the options byte are reserved and
 * MUST be 0. Wire has the high six bits set (0xFC) with low bits = QoS
 * 0. The unmasked v3.x decoder used to drop the reserved bits and
 * accept QoS 0 silently. */
TEST(decode_subscribe_v311_options_reserved_bits_qos0_rejected)
{
    byte rx_buf[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01,
        0x61,
        0xFC
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* Same as above, but with low bits = QoS 1. Pairs with the QoS-0 case to
 * pin the reserved-bit check independently of the QoS check. */
TEST(decode_subscribe_v311_options_reserved_bits_qos1_rejected)
{
    byte rx_buf[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01,
        0x61,
        0xFD
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-1.5.3-2] / [MQTT-4.7.3-2]: a topic filter containing U+0000 must
 * be rejected. Without this check, a stored filter "a\0b" would match
 * topic "a" once iteration hits the embedded NUL in BrokerTopicMatch. */
TEST(decode_subscribe_rejects_nul_in_filter)
{
    byte rx_buf[] = {
        0x82, 0x08,
        0x00, 0x01,                    /* packet_id */
        0x00, 0x03, 'a', 0x00, 'b',    /* filter "a\0b" */
        0x00                           /* options: QoS 0 */
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.8.3-3] The payload of a SUBSCRIBE packet MUST contain at least
 * one Topic Filter / QoS pair. Wire is exactly the issue's repro: type
 * byte 0x82, remain_len=2, just the Packet Identifier with no topic
 * elements. Without the fix the decoder returned 4 (the packet length)
 * with topic_count=0. */
TEST(decode_subscribe_empty_payload_rejected)
{
    byte rx_buf[] = {
        0x82, 0x02,
        0x00, 0x01                     /* packet_id only - no topics */
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

#ifdef WOLFMQTT_V5
/* v5 section 3.8.3 carries the same minimum-cardinality requirement as
 * [MQTT-3.8.3-3]. The v5 path is distinct: it consumes a Properties VBI
 * before reaching the topic loop. Wire is remain_len=3 = packet_id +
 * props_len=0, so the topic loop runs zero iterations. Without this
 * test, a future refactor of the v5 properties block could silently stop
 * the empty-payload guard from firing on v5 while v3.1.1 stays covered. */
TEST(decode_subscribe_v5_empty_payload_rejected)
{
    byte rx_buf[] = {
        0x82, 0x03,
        0x00, 0x01,                    /* packet_id */
        0x00                           /* properties length = 0 */
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    sub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}
#endif /* WOLFMQTT_V5 */

/* [MQTT-4.7.3-1] / [MQTT-4.7.1-2] / [MQTT-4.7.1-3] Topic Filter syntax
 * pinned at the helper level so the rules stay table-checked across
 * future refactors. Every entry maps directly to a spec-cited example. */
TEST(topic_filter_valid_helper_table)
{
    /* Empty filter is invalid [MQTT-4.7.3-1]. */
    ASSERT_EQ(0, MqttPacket_TopicFilterValid(NULL, 0));
    ASSERT_EQ(0, MqttPacket_TopicFilterValid("", 0));

    /* '#' alone is the canonical multi-level wildcard. */
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("#", 1));
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("sport/#", 7));
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("sport/tennis/#", 14));
    /* Spec non-normative invalid examples. */
    ASSERT_EQ(0, MqttPacket_TopicFilterValid("sport/tennis#", 13));
    ASSERT_EQ(0, MqttPacket_TopicFilterValid("sport/#/ranking", 15));
    ASSERT_EQ(0, MqttPacket_TopicFilterValid("a#", 2));

    /* '+' single-level wildcard placement. */
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("+", 1));
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("+/tennis/#", 10));
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("sport/+", 7));
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("sport/+/player1", 15));
    /* Spec non-normative invalid examples. */
    ASSERT_EQ(0, MqttPacket_TopicFilterValid("sport+", 6));
    ASSERT_EQ(0, MqttPacket_TopicFilterValid("sport+/player1", 14));
    ASSERT_EQ(0, MqttPacket_TopicFilterValid("a+b", 3));

    /* Plain non-wildcard topics. */
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("a", 1));
    ASSERT_EQ(1, MqttPacket_TopicFilterValid("sport/tennis", 12));
}

/* [MQTT-4.7.3-1] zero-length Topic Filter rejected by SUBSCRIBE decoder. */
TEST(decode_subscribe_empty_topic_filter_rejected)
{
    byte rx_buf[] = {
        0x82, 0x05,
        0x00, 0x01,                    /* packet_id */
        0x00, 0x00,                    /* topic_len = 0 */
        0x00                           /* options */
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-4.7.1-2] '#' must be solo or follow '/' and be the last char. */
TEST(decode_subscribe_bad_hash_placement_rejected)
{
    /* "a#" - '#' embedded in a level. */
    byte rx_buf[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00, 0x02, 'a', '#',
        0x00
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_subscribe_hash_not_last_rejected)
{
    /* "sp/#/r" - '#' is not the final character. */
    byte rx_buf[] = {
        0x82, 0x0B,
        0x00, 0x01,
        0x00, 0x06, 's', 'p', '/', '#', '/', 'r',
        0x00
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-4.7.1-3] '+' must occupy an entire topic level. */
TEST(decode_subscribe_bad_plus_placement_rejected)
{
    /* "a+b" - '+' embedded in a level. */
    byte rx_buf[] = {
        0x82, 0x08,
        0x00, 0x01,
        0x00, 0x03, 'a', '+', 'b',
        0x00
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-2.3.1-1] SUBSCRIBE must carry a non-zero Packet Identifier on the
 * receive path as well as the transmit path. */
TEST(decode_subscribe_packet_id_zero_rejected)
{
    byte rx_buf[] = {
        0x82, 0x06,
        0x00, 0x00,                    /* packet_id = 0 */
        0x00, 0x01,
        0x61,
        0x01
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}


#ifdef WOLFMQTT_V5
/* [MQTT-3.8.3] v5 SUBSCRIBE options byte carries QoS (bits 0-1), No Local
 * (bit 2), Retain As Published (bit 3), and Retain Handling (bits 4-5).
 * Hand-built wire with options = 0x2D (RH=2, RAP=1, NL=1, QoS=1). The
 * decoder must accept the packet and surface QoS. */
TEST(decode_subscribe_v5_options_byte_qos_extracted)
{
    /* Wire: type|flags=0x82, remaining=7, packet_id=0x0001, props_len=0x00,
     *       topic_len=0x0001, "a", options=0x2D. */
    byte rx_buf[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01,
        0x61,
        0x2D
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    sub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(1, sub.packet_id);
    ASSERT_EQ(1, sub.topic_count);
    ASSERT_EQ(MQTT_QOS_1, topic_arr[0].qos);
}

/* MQTT v5 section 3.8.3.1: Requested QoS = 3 is reserved. The v3.1.1 test
 * above takes a different branch (protocol_level = 0), so without this
 * test the v5 `(options & 0x03) > MQTT_QOS_2` clause is only covered
 * transitively through the broader options-byte check. A refactor that
 * dropped the v5 QoS check on the assumption that the reserved-bits or
 * Retain-Handling checks subsume it would slip past CI silently. */
TEST(decode_subscribe_v5_qos3_rejected)
{
    byte rx_buf[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01,
        0x61,
        0x03                            /* QoS = 3, other bits clear */
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    sub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* MQTT v5 section 3.8.3.1: Retain Handling = 3 is reserved and MUST be
 * rejected. Bits 4-5 = 0b11 sets that condition. */
TEST(decode_subscribe_v5_retain_handling_3_rejected)
{
    byte rx_buf[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01,
        0x61,
        0x30                            /* Retain Handling = 0b11 */
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    sub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* MQTT v5 section 3.8.3.1: bits 6-7 of the options byte are reserved and MUST
 * be 0. Bits 0-5 are otherwise valid (QoS 0, RH=0, RAP=0, NL=0). */
TEST(decode_subscribe_v5_options_reserved_bits_rejected)
{
    byte rx_buf[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01,
        0x61,
        0xC0                            /* reserved bits 6-7 set */
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    sub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * MqttDecode_Unsubscribe (broker-side)
 * ============================================================================ */

/* [MQTT-1.5.3-2] / [MQTT-4.7.3-2]: a topic filter containing U+0000 in an
 * UNSUBSCRIBE must be rejected - MqttDecode_Unsubscribe shares the same
 * MqttDecode_String chokepoint that SUBSCRIBE uses. */
TEST(decode_unsubscribe_rejects_nul_in_filter)
{
    byte rx_buf[] = {
        0xA2, 0x07,
        0x00, 0x01,                    /* packet_id */
        0x00, 0x03, 'a', 0x00, 'b'     /* filter "a\0b" */
    };
    MqttUnsubscribe unsub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    unsub.topics = topic_arr;
    rc = MqttDecode_Unsubscribe(rx_buf, (int)sizeof(rx_buf), &unsub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.10.3-2] The Payload of an UNSUBSCRIBE packet MUST contain at
 * least one Topic Filter. Wire matches the issue's repro: type byte
 * 0xA2, remain_len=2, just the Packet Identifier with no topic elements.
 * Without the fix the decoder returned 4 with topic_count=0. */
TEST(decode_unsubscribe_empty_payload_rejected)
{
    byte rx_buf[] = {
        0xA2, 0x02,
        0x00, 0x01                     /* packet_id only - no topics */
    };
    MqttUnsubscribe unsub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    unsub.topics = topic_arr;
    rc = MqttDecode_Unsubscribe(rx_buf, (int)sizeof(rx_buf), &unsub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

#ifdef WOLFMQTT_V5
/* v5 section 3.10.3 carries the same minimum-cardinality requirement as
 * [MQTT-3.10.3-2]. Wire is remain_len=3 = packet_id + props_len=0. */
TEST(decode_unsubscribe_v5_empty_payload_rejected)
{
    byte rx_buf[] = {
        0xA2, 0x03,
        0x00, 0x01,                    /* packet_id */
        0x00                           /* properties length = 0 */
    };
    MqttUnsubscribe unsub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    unsub.topics = topic_arr;
    unsub.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_Unsubscribe(rx_buf, (int)sizeof(rx_buf), &unsub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}
#endif /* WOLFMQTT_V5 */

/* UNSUBSCRIBE shares the same Topic Filter syntax rules as SUBSCRIBE
 * ([MQTT-4.7.3-1], [MQTT-4.7.1-2], [MQTT-4.7.1-3]). The decoder uses
 * the same MqttPacket_TopicFilterValid helper so a single sample per
 * rule is enough - exhaustive coverage lives in the helper table test. */
TEST(decode_unsubscribe_empty_topic_filter_rejected)
{
    byte rx_buf[] = {
        0xA2, 0x04,
        0x00, 0x01,                    /* packet_id */
        0x00, 0x00                     /* topic_len = 0 */
    };
    MqttUnsubscribe unsub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    unsub.topics = topic_arr;
    rc = MqttDecode_Unsubscribe(rx_buf, (int)sizeof(rx_buf), &unsub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_unsubscribe_bad_plus_placement_rejected)
{
    /* "a+b" - '+' embedded in a level. */
    byte rx_buf[] = {
        0xA2, 0x07,
        0x00, 0x01,
        0x00, 0x03, 'a', '+', 'b'
    };
    MqttUnsubscribe unsub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    unsub.topics = topic_arr;
    rc = MqttDecode_Unsubscribe(rx_buf, (int)sizeof(rx_buf), &unsub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-2.3.1-1] UNSUBSCRIBE must carry a non-zero Packet Identifier on
 * the receive path as well as the transmit path. */
TEST(decode_unsubscribe_packet_id_zero_rejected)
{
    byte rx_buf[] = {
        0xA2, 0x05,
        0x00, 0x00,                    /* packet_id = 0 */
        0x00, 0x01, 'a'
    };
    MqttUnsubscribe unsub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    unsub.topics = topic_arr;
    rc = MqttDecode_Unsubscribe(rx_buf, (int)sizeof(rx_buf), &unsub);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}
#endif /* WOLFMQTT_BROKER */

/* ============================================================================
 * QoS 2 next-ack arithmetic (PUBLISH_REC -> REL -> COMP)
 * ============================================================================ */

TEST(qos2_ack_arithmetic)
{
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_REL,
              MQTT_PACKET_TYPE_PUBLISH_REC + 1);
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_COMP,
              MQTT_PACKET_TYPE_PUBLISH_REL + 1);
    ASSERT_EQ(5, MQTT_PACKET_TYPE_PUBLISH_REC);
    ASSERT_EQ(6, MQTT_PACKET_TYPE_PUBLISH_REL);
    ASSERT_EQ(7, MQTT_PACKET_TYPE_PUBLISH_COMP);
}

/* ============================================================================
 * MqttDecode_SubscribeAck
 * ============================================================================ */

TEST(decode_suback_valid)
{
    byte buf[5];
    MqttSubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    buf[1] = 3;
    buf[2] = 0;
    buf[3] = 1;
    buf[4] = MQTT_QOS_2;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_SubscribeAck(buf, 5, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(1, ack.packet_id);
    ASSERT_EQ(MQTT_QOS_2, ack.return_codes[0]);
}

TEST(decode_suback_multiple_return_codes)
{
    byte buf[7];
    MqttSubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    buf[1] = 5;
    buf[2] = 0;
    buf[3] = 1;
    buf[4] = MQTT_QOS_1;
    buf[5] = MQTT_QOS_2;
    buf[6] = MQTT_SUBSCRIBE_ACK_CODE_FAILURE;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_SubscribeAck(buf, 7, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(1, ack.packet_id);
    ASSERT_EQ(MQTT_QOS_1, ack.return_codes[0]);
    ASSERT_EQ(MQTT_QOS_2, ack.return_codes[1]);
    ASSERT_EQ(MQTT_SUBSCRIBE_ACK_CODE_FAILURE, ack.return_codes[2]);
}

TEST(decode_suback_malformed_remain_len_zero)
{
    byte buf[2];
    MqttSubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    buf[1] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_SubscribeAck(buf, 2, &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_suback_malformed_remain_len_one)
{
    byte buf[3];
    MqttSubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    buf[1] = 1;
    buf[2] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_SubscribeAck(buf, 3, &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* [MQTT-3.9.3-2] v3.1.1 SUBACK return codes are restricted to
 * {0x00, 0x01, 0x02, 0x80}. Wire carries a reserved value
 * (0x03 / 0x7F) in the payload. */
static void decode_suback_v311_reserved_helper(byte reserved_code)
{
    byte buf[5];
    MqttSubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    buf[1] = 3;
    buf[2] = 0;
    buf[3] = 1;
    buf[4] = reserved_code;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_SubscribeAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_suback_v311_reserved_code_0x03_rejected)
{
    decode_suback_v311_reserved_helper(0x03);
}

TEST(decode_suback_v311_reserved_code_0x7F_rejected)
{
    decode_suback_v311_reserved_helper(0x7F);
}

/* Pins all four spec-allowed v3.1.1 codes via MqttPacket_SubAckReturnCodeValid
 * so a future change to the helper's table catches every entry. */
TEST(suback_return_code_v311_allowed_set)
{
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x00, 0));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x01, 0));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x02, 0));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x80, 0));
    /* Reserved values out of the v3.1.1 set */
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0x03, 0));
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0x04, 0));
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0x7F, 0));
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0x81, 0));
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0xFF, 0));
}

#ifdef WOLFMQTT_V5
/* v5 section 3.9.3: SUBACK Reason Code set is broader. The decoder must accept
 * v5 reason codes that are not in the v3.1.1 set when protocol_level=5. */
TEST(decode_suback_v5_not_authorized_accepted)
{
    /* Wire: SUBACK type 0x90, remain_len = 4 (packet_id + props_len(0)
     * + 1 reason byte), packet_id=1, props_len=0, reason=0x87. */
    byte buf[] = { 0x90, 0x04, 0x00, 0x01, 0x00, 0x87 };
    MqttSubscribeAck ack;
    int rc;

    XMEMSET(&ack, 0, sizeof(ack));
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_SubscribeAck(buf, (int)sizeof(buf), &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(0x87, ack.return_codes[0]);
}

/* Pin v5's broadened set via the helper. */
TEST(suback_return_code_v5_allowed_set)
{
    byte v5 = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    /* QoS 0/1/2 and the spec-defined v5 reason codes. */
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x00, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x80, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x83, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x87, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x8F, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x91, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x97, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0x9E, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0xA1, v5));
    ASSERT_TRUE(MqttPacket_SubAckReturnCodeValid(0xA2, v5));
    /* Codes that aren't in the v5 SUBACK set either. */
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0x03, v5));
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0x81, v5));
    ASSERT_FALSE(MqttPacket_SubAckReturnCodeValid(0xFF, v5));
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * MqttDecode_PublishResp
 * ============================================================================ */

TEST(decode_publish_resp_valid)
{
    byte buf[4];
    MqttPublishResp resp;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PUBLISH_ACK);
    buf[1] = 2;
    buf[2] = 0;
    buf[3] = 1;
    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, 4, MQTT_PACKET_TYPE_PUBLISH_ACK, &resp);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(1, resp.packet_id);
}

TEST(decode_publish_resp_malformed_remain_len_zero)
{
    byte buf[2];
    MqttPublishResp resp;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PUBLISH_ACK);
    buf[1] = 0;
    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, 2, MQTT_PACKET_TYPE_PUBLISH_ACK, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_publish_resp_malformed_remain_len_one)
{
    byte buf[3];
    MqttPublishResp resp;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PUBLISH_ACK);
    buf[1] = 1;
    buf[2] = 0;
    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, 3, MQTT_PACKET_TYPE_PUBLISH_ACK, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* VBI continuation bit set on the last available buffer byte.
 * MqttDecode_FixedHeader is static, so exercise it via PUBCOMP. The VBI
 * decoder must be told it has rx_buf_len-1 bytes (header->len points at
 * rx_buf+1), otherwise it reads one byte past the end of the buffer. */
TEST(decode_publish_resp_vbi_continuation_oob)
{
    byte buf[2];
    MqttPublishResp resp;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PUBLISH_COMP);
    buf[1] = 0x80;  /* VBI continuation bit set, no further bytes available */
    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

/* MQTT 3.1.1 sections 3.4-3.7: PUBACK/PUBREC/PUBREL/PUBCOMP have a fixed
 * Remaining Length of 2 (the Packet Identifier only). Any extra byte
 * after the Packet Identifier is malformed in v3.x. v5 sections 3.4-3.7
 * relaxes this with an optional Reason Code and Properties; the
 * `protocol_level` field on the response struct selects between the
 * strict and relaxed decoders. The wire carries an extra trailing
 * zero byte after the Packet Identifier. */
TEST(decode_puback_v311_extra_payload_rejected)
{
    byte buf[] = { 0x40, 0x03, 0x00, 0x07, 0x00 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_ACK, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_pubrec_v311_extra_payload_rejected)
{
    byte buf[] = { 0x50, 0x03, 0x00, 0x07, 0x00 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_pubrel_v311_extra_payload_rejected)
{
    byte buf[] = { 0x62, 0x03, 0x00, 0x07, 0x00 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_pubcomp_v311_extra_payload_rejected)
{
    byte buf[] = { 0x70, 0x03, 0x00, 0x07, 0x00 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* Positive cases for PUBREC/PUBREL/PUBCOMP - decode_publish_resp_valid
 * already covers PUBACK. Without these, a regression that flips the
 * length check into "always reject" would still leave 3/4 packet types
 * silently broken with only PUBACK signalling failure. */
TEST(decode_pubrec_v311_valid)
{
    byte buf[] = { 0x50, 0x02, 0x00, 0x07 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(7, resp.packet_id);
}

TEST(decode_pubrel_v311_valid)
{
    byte buf[] = { 0x62, 0x02, 0x00, 0x07 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(7, resp.packet_id);
}

TEST(decode_pubcomp_v311_valid)
{
    byte buf[] = { 0x70, 0x02, 0x00, 0x07 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(7, resp.packet_id);
}

/* publish_resp == NULL takes the strict-length path even under
 * WOLFMQTT_V5: with no struct to consume reason_code/props, anything
 * beyond the Packet Identifier is unreachable extra payload. Pins the
 * `publish_resp == NULL` arm of the gate so a refactor that narrows the
 * predicate to `protocol_level < 5` cannot regress NULL callers. */
TEST(decode_puback_null_resp_extra_payload_rejected)
{
    byte buf[] = { 0x40, 0x03, 0x00, 0x07, 0x00 };
    int rc;

    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_ACK, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

#ifdef WOLFMQTT_V5
/* v5 sections 3.4-3.7 explicitly allow longer PUBACK/PUBREC/PUBREL/PUBCOMP with
 * a Reason Code (1 byte) and a Properties block. Pins the v5 gate so the
 * v3.x exact-length check doesn't regress onto v5 - the wire is
 * remain_len = 4 = packet_id + reason_code + props_len(0). */
TEST(decode_puback_v5_with_reason_code_accepted)
{
    byte buf[] = { 0x40, 0x04, 0x00, 0x07, 0x00, 0x00 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    resp.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_ACK, &resp);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(7, resp.packet_id);
    ASSERT_EQ(0, resp.reason_code);
    MqttProps_Free(resp.props);
}

/* Remaining Length claims a Reason Code (3) but the buffer ends right after
 * the Packet Identifier, so the reason-code read must be rejected rather
 * than stepping past rx_buf. */
TEST(decode_puback_v5_truncated_reason_code_oob)
{
    byte buf[4] = { 0x40, 0x03, 0x00, 0x01 };
    MqttPublishResp resp;
    int rc;

    XMEMSET(&resp, 0, sizeof(resp));
    resp.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_PublishResp(buf, (int)sizeof(buf),
        MQTT_PACKET_TYPE_PUBLISH_ACK, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * MqttEncode_PublishResp fixed-header QoS bits
 *
 * MQTT-3.6.1-1: PUBREL fixed header reserved flags MUST be 0010 (QoS 1 bit).
 * All other publish response types (PUBACK/PUBREC/PUBCOMP) use QoS 0 flags.
 * ============================================================================ */

TEST(encode_publish_rel_has_qos1_flag)
{
    byte buf[8];
    MqttPublishResp resp;
    int enc_len;

    XMEMSET(&resp, 0, sizeof(resp));
    resp.packet_id = 1;

    enc_len = MqttEncode_PublishResp(buf, (int)sizeof(buf),
                  MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    ASSERT_TRUE(enc_len > 0);

    /* Fixed header: packet type PUBREL (6) in upper nibble, QoS 1 in flags */
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_REL,
              MQTT_PACKET_TYPE_GET(buf[0]));
    ASSERT_EQ(0x02, buf[0] & MQTT_PACKET_FLAG_QOS_MASK);
}

TEST(encode_publish_ack_has_qos0_flag)
{
    byte buf[8];
    MqttPublishResp resp;
    int enc_len;

    XMEMSET(&resp, 0, sizeof(resp));
    resp.packet_id = 1;

    enc_len = MqttEncode_PublishResp(buf, (int)sizeof(buf),
                  MQTT_PACKET_TYPE_PUBLISH_ACK, &resp);
    ASSERT_TRUE(enc_len > 0);

    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_ACK,
              MQTT_PACKET_TYPE_GET(buf[0]));
    ASSERT_EQ(0x00, buf[0] & MQTT_PACKET_FLAG_QOS_MASK);
}

TEST(encode_publish_rec_has_qos0_flag)
{
    byte buf[8];
    MqttPublishResp resp;
    int enc_len;

    XMEMSET(&resp, 0, sizeof(resp));
    resp.packet_id = 1;

    enc_len = MqttEncode_PublishResp(buf, (int)sizeof(buf),
                  MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
    ASSERT_TRUE(enc_len > 0);

    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_REC,
              MQTT_PACKET_TYPE_GET(buf[0]));
    ASSERT_EQ(0x00, buf[0] & MQTT_PACKET_FLAG_QOS_MASK);
}

TEST(encode_publish_comp_has_qos0_flag)
{
    byte buf[8];
    MqttPublishResp resp;
    int enc_len;

    XMEMSET(&resp, 0, sizeof(resp));
    resp.packet_id = 1;

    enc_len = MqttEncode_PublishResp(buf, (int)sizeof(buf),
                  MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    ASSERT_TRUE(enc_len > 0);

    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_COMP,
              MQTT_PACKET_TYPE_GET(buf[0]));
    ASSERT_EQ(0x00, buf[0] & MQTT_PACKET_FLAG_QOS_MASK);
}

/* ============================================================================
 * MqttDecode_UnsubscribeAck
 * ============================================================================ */

TEST(decode_unsuback_valid)
{
    byte buf[4];
    MqttUnsubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK);
    buf[1] = 2;
    buf[2] = 0;
    buf[3] = 1;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_UnsubscribeAck(buf, 4, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(1, ack.packet_id);
}

TEST(decode_unsuback_malformed_remain_len_zero)
{
    byte buf[2];
    MqttUnsubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK);
    buf[1] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_UnsubscribeAck(buf, 2, &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_unsuback_malformed_remain_len_one)
{
    byte buf[3];
    MqttUnsubscribeAck ack;
    int rc;

    buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK);
    buf[1] = 1;
    buf[2] = 0;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = MqttDecode_UnsubscribeAck(buf, 3, &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* ============================================================================
 * MqttDecode_Ping (PINGRESP) and MqttDecode_Disconnect length validation
 *
 * MQTT 3.1.1 section 3.13 / section 3.14 and v5 section 3.13: PINGRESP has no variable header
 * and no payload. v3.1.1 section 3.14: DISCONNECT also has none. The decoders
 * must reject Remaining Length != 0; otherwise a peer can smuggle in
 * trailing bytes that downstream code silently drops.
 * ============================================================================ */

TEST(decode_pingresp_valid)
{
    byte buf[] = { 0xD0, 0x00 };
    MqttPing ping;
    int rc;

    XMEMSET(&ping, 0, sizeof(ping));
    rc = MqttDecode_Ping(buf, (int)sizeof(buf), &ping);
    ASSERT_EQ(2, rc);
}

/* PINGRESP with one trailing byte - must be rejected as malformed.
 * Without the fix the decoder returned 3 (the packet length). */
TEST(decode_pingresp_nonzero_remain_len_rejected)
{
    byte buf[] = { 0xD0, 0x01, 0x00 };
    MqttPing ping;
    int rc;

    XMEMSET(&ping, 0, sizeof(ping));
    rc = MqttDecode_Ping(buf, (int)sizeof(buf), &ping);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

#if defined(WOLFMQTT_BROKER) && !defined(WOLFMQTT_V5)
TEST(decode_disconnect_v311_valid)
{
    byte buf[] = { 0xE0, 0x00 };
    MqttDisconnect disc;
    int rc;

    XMEMSET(&disc, 0, sizeof(disc));
    rc = MqttDecode_Disconnect(buf, (int)sizeof(buf), &disc);
    ASSERT_EQ(2, rc);
}

/* v3.1.1 DISCONNECT with one trailing byte must be rejected as
 * malformed. The v3.1.1 spec defines DISCONNECT as fixed-header-only;
 * the WOLFMQTT_V5 decoder below legitimately accepts a Reason Code and
 * Properties. */
TEST(decode_disconnect_v311_nonzero_remain_len_rejected)
{
    byte buf[] = { 0xE0, 0x01, 0x00 };
    MqttDisconnect disc;
    int rc;

    XMEMSET(&disc, 0, sizeof(disc));
    rc = MqttDecode_Disconnect(buf, (int)sizeof(buf), &disc);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* MQTT 3.1.1 section 3.14.1 / [MQTT-2.2.2-2]: DISCONNECT fixed-header low
 * nibble MUST be 0000. Wire 0xE1 sets bit 0 of the reserved nibble.
 * The check fires inside MqttDecode_FixedHeader via
 * MqttPacket_FixedHeaderFlagsValid; this test pins the per-decoder
 * surface so a future caller that builds its own header path can't
 * silently accept a malformed disconnect. */
TEST(decode_disconnect_v311_invalid_fixed_header_flags_rejected)
{
    byte buf[] = { 0xE1, 0x00 };
    MqttDisconnect disc;
    int rc;

    XMEMSET(&disc, 0, sizeof(disc));
    rc = MqttDecode_Disconnect(buf, (int)sizeof(buf), &disc);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}
#endif /* WOLFMQTT_BROKER && !WOLFMQTT_V5 */

#ifdef WOLFMQTT_V5
/* v5 section 3.14 keeps the same fixed-header reserved-flag rule. Pins the v5
 * decoder against the same regression on its independent code path. */
TEST(decode_disconnect_v5_invalid_fixed_header_flags_rejected)
{
    byte buf[] = { 0xE1, 0x00 };
    MqttDisconnect disc;
    int rc;

    XMEMSET(&disc, 0, sizeof(disc));
    rc = MqttDecode_Disconnect(buf, (int)sizeof(buf), &disc);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* v5 section 3.14: DISCONNECT may carry an optional Reason Code (1 byte) and a
 * Properties block. Pins the v5 decoder against a regression that would
 * tighten the v3.1.1 remain_len rule onto v5 by mistake. Wire is
 * remain_len = 2 = reason_code + props_len=0. */
TEST(decode_disconnect_v5_with_reason_code_accepted)
{
    byte buf[] = {
        0xE0, 0x02,
        0x00,                           /* reason code = Normal Disc */
        0x00                            /* properties length = 0 */
    };
    MqttDisconnect disc;
    int rc;

    XMEMSET(&disc, 0, sizeof(disc));
    rc = MqttDecode_Disconnect(buf, (int)sizeof(buf), &disc);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(0, disc.reason_code);
    MqttProps_Free(disc.props);
}

/* Remaining Length claims a Reason Code (1) but only the fixed header is
 * present, so the reason-code read must be rejected rather than stepping
 * past rx_buf. */
TEST(decode_disconnect_v5_truncated_reason_code_oob)
{
    byte buf[2] = { 0xE0, 0x01 };
    MqttDisconnect disc;
    int rc;

    XMEMSET(&disc, 0, sizeof(disc));
    rc = MqttDecode_Disconnect(buf, (int)sizeof(buf), &disc);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * Fixed-header reserved-flag validation [MQTT-2.2.2-2]
 *
 * The first byte of every MQTT packet packs the type (high nibble) and a
 * reserved-flag nibble. Most packet types fix that nibble to a single
 * required value; PUBLISH carries DUP/QoS/RETAIN. Invalid values MUST be
 * treated as malformed and cause the receiver to close the connection.
 *
 * MqttPacket_FixedHeaderFlagsValid is the single source of truth used by
 * MqttDecode_FixedHeader (covers SUBSCRIBE, UNSUBSCRIBE, PUBREL, etc.) and
 * by the broker dispatch (covers types with no decoder: PUBACK, PUBCOMP,
 * PINGREQ, DISCONNECT). These tests pin both surfaces.
 * ============================================================================ */

TEST(fixed_header_flags_valid_canonical_values)
{
    /* Canonical first-byte values for each fixed-flag packet type. */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x10)); /* CONNECT */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x20)); /* CONNACK */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x40)); /* PUBACK */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x50)); /* PUBREC */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x62)); /* PUBREL */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x70)); /* PUBCOMP */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x82)); /* SUBSCRIBE */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x90)); /* SUBACK */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0xA2)); /* UNSUBSCRIBE */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0xB0)); /* UNSUBACK */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0xC0)); /* PINGREQ */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0xD0)); /* PINGRESP */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0xE0)); /* DISCONNECT */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0xF0)); /* AUTH (v5) */
}

/* Type 0 (RESERVED) is not a defined MQTT packet type. The helper must
 * reject it so callers - including the broker pre-dispatch check - can
 * treat any accepted byte as a known type. */
TEST(fixed_header_flags_valid_reserved_type_rejected)
{
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x00));
    /* Every flag-nibble combination on the reserved type must be
     * rejected - the type itself is the failure, not the nibble. */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x01));
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x0F));
}

#ifdef WOLFMQTT_BROKER
/* Reserved-type packet on the wire - broker pre-dispatch must reject
 * via the FixedHeaderFlagsValid gate. Exercises the decoder boundary
 * separately from the helper unit test above. */
TEST(decode_fixed_header_reserved_type_rejected)
{
    /* SUBSCRIBE wire shape but type byte set to RESERVED (0x00).
     * MqttDecode_Subscribe runs MqttDecode_FixedHeader with the
     * expected type SUBSCRIBE, so the type-mismatch path returns
     * MQTT_CODE_ERROR_PACKET_TYPE first; that is correct on this
     * decoder path. The broker dispatch path uses
     * MqttPacket_FixedHeaderFlagsValid directly and is covered by the
     * helper test above. */
    byte rx_buf[] = {
        0x00, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'a',
        0x01
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;

    XMEMSET(&sub, 0, sizeof(sub));
    XMEMSET(topic_arr, 0, sizeof(topic_arr));
    sub.topics = topic_arr;
    rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
    ASSERT_TRUE(rc < 0);
}
#endif /* WOLFMQTT_BROKER */

TEST(fixed_header_flags_valid_zero_required_rejects_nonzero)
{
    /* Types whose reserved nibble MUST be 0000. Each non-zero permutation
     * is malformed. */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x11)); /* CONNECT */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x18));
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x21)); /* CONNACK */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x42)); /* PUBACK */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x52)); /* PUBREC */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x72)); /* PUBCOMP */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x91)); /* SUBACK */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0xB2)); /* UNSUBACK */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0xC1)); /* PINGREQ */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0xD1)); /* PINGRESP */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0xE2)); /* DISCONNECT */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0xFF)); /* AUTH */
}

TEST(fixed_header_flags_valid_two_required_rejects_other)
{
    /* [MQTT-3.6.1-1] PUBREL, [MQTT-3.8.1-1] SUBSCRIBE, [MQTT-3.10.1-1]
     * UNSUBSCRIBE all require the low nibble = 0010. Any other value is
     * malformed. */
    int v;
    for (v = 0x60; v <= 0x6F; v++) {
        if (v == 0x62) continue;
        ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid((byte)v));
    }
    for (v = 0x80; v <= 0x8F; v++) {
        if (v == 0x82) continue;
        ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid((byte)v));
    }
    for (v = 0xA0; v <= 0xAF; v++) {
        if (v == 0xA2) continue;
        ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid((byte)v));
    }
}

TEST(fixed_header_flags_valid_publish_qos_and_dup)
{
    /* PUBLISH carries DUP/QoS/RETAIN: 0x3X where X = DUP|QoS|RETAIN. */
    /* QoS 0..2 with DUP=0 are all legal regardless of RETAIN. */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x30)); /* QoS0, no DUP */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x31)); /* QoS0, RETAIN */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x32)); /* QoS1 */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x33)); /* QoS1, RETAIN */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x34)); /* QoS2 */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x35)); /* QoS2, RETAIN */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x3A)); /* QoS1, DUP */
    ASSERT_EQ(1, MqttPacket_FixedHeaderFlagsValid(0x3C)); /* QoS2, DUP */

    /* [MQTT-3.3.1-4] QoS = 3 (bits 1-2 = 11) is reserved/malformed. */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x36));
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x37));
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x3E));
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x3F));

    /* [MQTT-3.3.1-2] DUP MUST be 0 when QoS = 0. */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x38)); /* QoS0, DUP=1 */
    ASSERT_EQ(0, MqttPacket_FixedHeaderFlagsValid(0x39)); /* QoS0, DUP, RET */
}

/* End-to-end: the SUBSCRIBE decoder rejects each invalid first-byte
 * variant cited in the issue report (0x80, 0x81, 0x83) and the broker's
 * dispatch uses the same helper, so both surfaces close the connection. */
#ifdef WOLFMQTT_BROKER
TEST(decode_subscribe_invalid_fixed_header_flags)
{
    /* Body matches the valid SUBSCRIBE wire from decode_subscribe_v311_
     * single_topic; only the leading type+flags byte varies. */
    byte rx_buf[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01,
        0x61,
        0x01
    };
    MqttSubscribe sub;
    MqttTopic topic_arr[1];
    int rc;
    byte invalid[] = { 0x80, 0x81, 0x83, 0x84, 0x86, 0x88, 0x8F };
    size_t i;

    for (i = 0; i < sizeof(invalid); i++) {
        rx_buf[0] = invalid[i];
        XMEMSET(&sub, 0, sizeof(sub));
        XMEMSET(topic_arr, 0, sizeof(topic_arr));
        sub.topics = topic_arr;
        rc = MqttDecode_Subscribe(rx_buf, (int)sizeof(rx_buf), &sub);
        ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
    }
}

TEST(decode_unsubscribe_invalid_fixed_header_flags)
{
    /* Wire: type|flags=0xA2, remaining=5, packet_id=0x0001, topic_len=0x0001,
     * "a". Per [MQTT-3.10.1-1] only 0xA2 is legal. */
    byte rx_buf[] = {
        0xA2, 0x05,
        0x00, 0x01,
        0x00, 0x01,
        0x61
    };
    MqttUnsubscribe unsub;
    MqttTopic topic_arr[1];
    int rc;
    byte invalid[] = { 0xA0, 0xA1, 0xA3, 0xA4, 0xA6, 0xA8, 0xAF };
    size_t i;

    for (i = 0; i < sizeof(invalid); i++) {
        rx_buf[0] = invalid[i];
        XMEMSET(&unsub, 0, sizeof(unsub));
        XMEMSET(topic_arr, 0, sizeof(topic_arr));
        unsub.topics = topic_arr;
        rc = MqttDecode_Unsubscribe(rx_buf, (int)sizeof(rx_buf), &unsub);
        ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
    }
}
#endif /* WOLFMQTT_BROKER */

TEST(decode_pubrel_invalid_fixed_header_flags)
{
    /* Wire: type|flags=0x62, remain=2, packet_id=0x0001. */
    byte rx_buf[] = { 0x62, 0x02, 0x00, 0x01 };
    MqttPublishResp resp;
    int rc;

    rx_buf[0] = 0x60; /* PUBREL with reserved nibble = 0000 */
    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(rx_buf, (int)sizeof(rx_buf),
            MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);

    rx_buf[0] = 0x63;
    XMEMSET(&resp, 0, sizeof(resp));
    rc = MqttDecode_PublishResp(rx_buf, (int)sizeof(rx_buf),
            MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_publish_qos3_rejected)
{
    /* [MQTT-3.3.1-4] QoS 3 (reserved) MUST be treated as malformed. */
    byte buf[] = { 0x36, 7,
                   0x00, 0x03, 'a', '/', 'b',
                   'H', 'I' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(decode_publish_qos0_with_dup_rejected)
{
    /* [MQTT-3.3.1-2] DUP MUST be 0 when QoS = 0. */
    byte buf[] = { 0x38, 5,
                   0x00, 0x03, 'a', '/', 'b' };
    MqttPublish pub;
    int rc;

    XMEMSET(&pub, 0, sizeof(pub));
    rc = MqttDecode_Publish(buf, (int)sizeof(buf), &pub);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

/* ============================================================================
 * MqttEncode/Decode_PublishResp v5 roundtrip
 * ============================================================================ */

#ifdef WOLFMQTT_V5
TEST(publish_resp_v5_success_with_props_roundtrip)
{
    byte buf[256];
    MqttPublishResp enc, dec;
    MqttProp prop;
    int enc_len, dec_len;
    char reason_str[] = "ok";

    XMEMSET(&enc, 0, sizeof(enc));
    XMEMSET(&prop, 0, sizeof(prop));
    prop.type = MQTT_PROP_REASON_STR;
    prop.data_str.str = reason_str;
    prop.data_str.len = (word16)XSTRLEN(reason_str);
    prop.next = NULL;
    enc.packet_id = 1;
    enc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    enc.reason_code = MQTT_REASON_SUCCESS;
    enc.props = &prop;

    enc_len = MqttEncode_PublishResp(buf, (int)sizeof(buf),
                  MQTT_PACKET_TYPE_PUBLISH_ACK, &enc);
    ASSERT_TRUE(enc_len > 0);

    XMEMSET(&dec, 0, sizeof(dec));
    dec.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    dec_len = MqttDecode_PublishResp(buf, enc_len,
                  MQTT_PACKET_TYPE_PUBLISH_ACK, &dec);
    ASSERT_TRUE(dec_len > 0);
    ASSERT_EQ(1, dec.packet_id);
    ASSERT_EQ(MQTT_REASON_SUCCESS, dec.reason_code);
    if (dec.props) {
        MqttProps_Free(dec.props);
    }
}

TEST(publish_resp_v5_error_no_props_roundtrip)
{
    byte buf[256];
    MqttPublishResp enc, dec;
    int enc_len, dec_len;

    XMEMSET(&enc, 0, sizeof(enc));
    enc.packet_id = 2;
    enc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    enc.reason_code = 0x80;  /* Unspecified error */
    enc.props = NULL;

    enc_len = MqttEncode_PublishResp(buf, (int)sizeof(buf),
                  MQTT_PACKET_TYPE_PUBLISH_ACK, &enc);
    ASSERT_TRUE(enc_len > 0);

    XMEMSET(&dec, 0, sizeof(dec));
    dec.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    dec_len = MqttDecode_PublishResp(buf, enc_len,
                  MQTT_PACKET_TYPE_PUBLISH_ACK, &dec);
    ASSERT_TRUE(dec_len > 0);
    ASSERT_EQ(0x80, dec.reason_code);
}

TEST(publish_resp_v5_success_no_props_roundtrip)
{
    byte buf[256];
    MqttPublishResp enc, dec;
    int enc_len, dec_len;

    XMEMSET(&enc, 0, sizeof(enc));
    enc.packet_id = 3;
    enc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    enc.reason_code = MQTT_REASON_SUCCESS;
    enc.props = NULL;

    enc_len = MqttEncode_PublishResp(buf, (int)sizeof(buf),
                  MQTT_PACKET_TYPE_PUBLISH_ACK, &enc);
    ASSERT_TRUE(enc_len > 0);

    XMEMSET(&dec, 0, sizeof(dec));
    dec.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    dec_len = MqttDecode_PublishResp(buf, enc_len,
                  MQTT_PACKET_TYPE_PUBLISH_ACK, &dec);
    ASSERT_TRUE(dec_len > 0);
    ASSERT_EQ(MQTT_REASON_SUCCESS, dec.reason_code);
}

/* ============================================================================
 * MqttEncode/Decode_Auth roundtrip
 *
 * Every reason code accepted by MqttEncode_Auth must round-trip through
 * MqttDecode_Auth. MQTT 5.0 section 3.15.1 lists SUCCESS (0x00), CONT_AUTH
 * (0x18), and REAUTH (0x19) as valid AUTH reason codes.
 * ============================================================================ */

static void auth_roundtrip_with_method(byte reason_code)
{
    byte buf[256];
    MqttAuth enc, dec;
    MqttProp prop;
    int enc_len, dec_len;
    char auth_method[] = "SCRAM-SHA-256";

    XMEMSET(&enc, 0, sizeof(enc));
    XMEMSET(&prop, 0, sizeof(prop));
    prop.type = MQTT_PROP_AUTH_METHOD;
    prop.data_str.str = auth_method;
    prop.data_str.len = (word16)XSTRLEN(auth_method);
    prop.next = NULL;
    enc.reason_code = reason_code;
    enc.props = &prop;

    enc_len = MqttEncode_Auth(buf, (int)sizeof(buf), &enc);
    ASSERT_TRUE(enc_len > 0);

    XMEMSET(&dec, 0, sizeof(dec));
    dec_len = MqttDecode_Auth(buf, enc_len, &dec);
    ASSERT_TRUE(dec_len > 0);
    ASSERT_EQ(enc_len, dec_len);
    ASSERT_EQ(reason_code, dec.reason_code);
    ASSERT_NOT_NULL(dec.props);
    ASSERT_EQ(MQTT_PROP_AUTH_METHOD, dec.props->type);
    if (dec.props) {
        MqttProps_Free(dec.props);
    }
}

TEST(auth_v5_cont_auth_roundtrip)
{
    auth_roundtrip_with_method(MQTT_REASON_CONT_AUTH);
}

TEST(auth_v5_reauth_roundtrip)
{
    auth_roundtrip_with_method(MQTT_REASON_REAUTH);
}

TEST(auth_v5_reauth_decodes_without_error)
{
    /* Decode a hand-built REAUTH packet to guard against encoder changes
     * masking a decoder-only regression. */
    byte buf[64];
    MqttAuth enc, dec;
    MqttProp prop;
    int enc_len, dec_len;
    char auth_method[] = "OAUTH";

    XMEMSET(&enc, 0, sizeof(enc));
    XMEMSET(&prop, 0, sizeof(prop));
    prop.type = MQTT_PROP_AUTH_METHOD;
    prop.data_str.str = auth_method;
    prop.data_str.len = (word16)XSTRLEN(auth_method);
    prop.next = NULL;
    enc.reason_code = MQTT_REASON_REAUTH;
    enc.props = &prop;

    enc_len = MqttEncode_Auth(buf, (int)sizeof(buf), &enc);
    ASSERT_TRUE(enc_len > 0);
    ASSERT_EQ(MQTT_REASON_REAUTH, buf[2]);

    XMEMSET(&dec, 0, sizeof(dec));
    dec_len = MqttDecode_Auth(buf, enc_len, &dec);
    ASSERT_NE(MQTT_CODE_ERROR_MALFORMED_DATA, dec_len);
    ASSERT_TRUE(dec_len > 0);
    if (dec.props) {
        MqttProps_Free(dec.props);
    }
}

TEST(auth_v5_success_remaining_length_zero)
{
    /* Per MQTT 5.0 3.15.2, a Remaining Length of 0 means SUCCESS with no
     * properties. Build that wire form directly since MqttEncode_Auth does
     * not emit it. */
    byte buf[2];
    MqttAuth dec;
    int dec_len;

    buf[0] = (byte)(MQTT_PACKET_TYPE_AUTH << 4);
    buf[1] = 0x00; /* Remaining Length */

    XMEMSET(&dec, 0, sizeof(dec));
    dec_len = MqttDecode_Auth(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(2, dec_len);
    ASSERT_EQ(MQTT_REASON_SUCCESS, dec.reason_code);
    ASSERT_NULL(dec.props);
}

TEST(auth_v5_invalid_reason_code_rejected)
{
    /* A reason code outside {SUCCESS, CONT_AUTH, REAUTH} must not decode
     * as a valid AUTH packet. Use 0x7F which is not assigned for AUTH. */
    byte buf[8];
    MqttAuth dec;
    int dec_len;

    buf[0] = (byte)(MQTT_PACKET_TYPE_AUTH << 4);
    buf[1] = 0x02; /* Remaining Length */
    buf[2] = 0x7F; /* Invalid reason code */
    buf[3] = 0x00; /* Property Length = 0 */

    XMEMSET(&dec, 0, sizeof(dec));
    dec_len = MqttDecode_Auth(buf, 4, &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, dec_len);
}

/* Remaining Length claims a Reason Code (1) but only the fixed header is
 * present, so the reason-code read must be rejected rather than stepping
 * past rx_buf. */
TEST(decode_auth_truncated_reason_code_oob)
{
    byte buf[2];
    MqttAuth dec;
    int dec_len;

    buf[0] = (byte)(MQTT_PACKET_TYPE_AUTH << 4);
    buf[1] = 0x01; /* Remaining Length claims one payload byte */

    XMEMSET(&dec, 0, sizeof(dec));
    dec_len = MqttDecode_Auth(buf, (int)sizeof(buf), &dec);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, dec_len);
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * Test Suite Runner
 * ============================================================================ */

void run_mqtt_packet_tests(void)
{
#ifdef WOLFMQTT_V5
    MqttProps_Init();
#endif

    TEST_SUITE_BEGIN("mqtt_packet", setup, teardown);

    /* MqttEncode_Num / MqttDecode_Num */
    RUN_TEST(encode_num_basic);
    RUN_TEST(encode_num_zero);
    RUN_TEST(encode_num_max);
    RUN_TEST(encode_num_null_buf);
    RUN_TEST(decode_num_basic);
    RUN_TEST(decode_num_zero);
    RUN_TEST(decode_num_max);
    RUN_TEST(decode_num_buffer_too_small);
    RUN_TEST(encode_decode_num_roundtrip);

    /* MqttEncode_Vbi / MqttDecode_Vbi */
    RUN_TEST(encode_vbi_one_byte);
    RUN_TEST(encode_vbi_two_bytes);
    RUN_TEST(encode_vbi_three_bytes);
    RUN_TEST(encode_vbi_four_bytes);
    RUN_TEST(encode_vbi_null_buf);
    RUN_TEST(encode_vbi_overflow_above_max);
    RUN_TEST(encode_vbi_overflow_u32_max);
    RUN_TEST(encode_vbi_overflow_null_buf);
    RUN_TEST(decode_vbi_one_byte_zero);
    RUN_TEST(decode_vbi_one_byte_max);
    RUN_TEST(decode_vbi_two_bytes_min);
    RUN_TEST(decode_vbi_two_bytes_max);
    RUN_TEST(decode_vbi_three_bytes_max);
    RUN_TEST(decode_vbi_four_bytes_max);
    RUN_TEST(decode_vbi_five_byte_malformed);
    RUN_TEST(decode_vbi_buffer_too_small);
    RUN_TEST(decode_vbi_overlong_2byte_zero);
    RUN_TEST(decode_vbi_overlong_3byte_zero);
    RUN_TEST(decode_vbi_overlong_4byte_zero);
    RUN_TEST(decode_vbi_overlong_2byte_127);
    RUN_TEST(encode_decode_vbi_roundtrip);

    /* UTF-8 well-formedness validation [MQTT-1.5.3-1] */
#ifdef WOLFMQTT_BROKER
    RUN_TEST(decode_string_utf8_valid_ascii);
    RUN_TEST(decode_string_utf8_valid_2byte);
    RUN_TEST(decode_string_utf8_valid_3byte);
    RUN_TEST(decode_string_utf8_valid_4byte);
    RUN_TEST(decode_string_utf8_valid_max_codepoint);
    RUN_TEST(decode_string_utf8_valid_d7ff_just_below_surrogate);
    RUN_TEST(decode_string_utf8_valid_e000_just_above_surrogate);
    RUN_TEST(decode_string_utf8_invalid_overlong_2byte);
    RUN_TEST(decode_string_utf8_invalid_overlong_3byte);
    RUN_TEST(decode_string_utf8_invalid_overlong_4byte);
    RUN_TEST(decode_string_utf8_invalid_surrogate_low);
    RUN_TEST(decode_string_utf8_invalid_surrogate_high);
    RUN_TEST(decode_string_utf8_invalid_above_max);
    RUN_TEST(decode_string_utf8_invalid_f5_leading);
    RUN_TEST(decode_string_utf8_invalid_lone_continuation);
    RUN_TEST(decode_string_utf8_invalid_truncated_2byte);
    RUN_TEST(decode_string_utf8_invalid_truncated_4byte);
    RUN_TEST(decode_string_utf8_invalid_FE_FF);
    RUN_TEST(decode_connect_invalid_utf8_clientid_overlong);
    RUN_TEST(decode_connect_clientid_contains_u0000_rejected);
    RUN_TEST(decode_connect_invalid_utf8_clientid_surrogate);
    RUN_TEST(decode_connect_v311_binary_password);
    RUN_TEST(decode_connect_invalid_utf8_username);
    RUN_TEST(decode_connect_invalid_utf8_username_overlong);
#endif
    RUN_TEST(decode_publish_invalid_utf8_topic);

    /* MqttEncode_Publish */
    RUN_TEST(encode_publish_qos1_packet_id_zero);
    RUN_TEST(encode_publish_qos2_packet_id_zero);
    RUN_TEST(encode_publish_qos0_packet_id_zero_ok);
    RUN_TEST(encode_publish_qos1_valid);
    RUN_TEST(encode_publish_qos1_retain_flags_in_header);
    RUN_TEST(encode_publish_qos2_duplicate_flags_in_header);
    RUN_TEST(encode_publish_qos0_no_flags_in_header);
    RUN_TEST(encode_publish_qos0_with_dup_rejected);
    RUN_TEST(encode_publish_qos1_with_dup_accepted);
    RUN_TEST(encode_publish_qos2_with_dup_accepted);
    RUN_TEST(encode_publish_topic_oversized_rejected);
    RUN_TEST(topic_name_valid_helper_table);
    RUN_TEST(encode_publish_empty_topic_rejected);
    RUN_TEST(encode_publish_wildcard_topic_rejected);
    RUN_TEST(encode_publish_null_topic_returns_bad_arg);
#ifdef WOLFMQTT_V5
    RUN_TEST(encode_publish_v5_empty_topic_accepted);
#endif

    /* MqttDecode_Publish */
    RUN_TEST(decode_publish_qos0_valid);
    RUN_TEST(decode_publish_qos1_valid);
    RUN_TEST(decode_publish_qos0_zero_payload);
    RUN_TEST(decode_publish_malformed_variable_exceeds_remain);
    RUN_TEST(decode_publish_rejects_nul_in_topic);
    RUN_TEST(decode_publish_empty_topic_rejected);
    RUN_TEST(decode_publish_wildcard_hash_topic_rejected);
    RUN_TEST(decode_publish_wildcard_plus_topic_rejected);
    RUN_TEST(decode_publish_topic_contains_u0000_rejected);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_publish_v5_empty_topic_accepted);
#endif
    RUN_TEST(decode_publish_qos1_packet_id_zero_rejected);
    RUN_TEST(decode_publish_qos2_packet_id_zero_rejected);
    RUN_TEST(decode_publish_qos2_packet_id_one_valid);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_publish_v5_content_type_property);
    RUN_TEST(decode_publish_v5_rejects_nul_in_string_property);
    RUN_TEST(decode_publish_v5_rejects_nul_in_user_prop_key);
    RUN_TEST(decode_publish_v5_rejects_nul_in_user_prop_value);
#endif

    /* MqttDecode_ConnectAck */
    RUN_TEST(decode_connack_valid);
    RUN_TEST(decode_connack_malformed_remain_len_zero);
    RUN_TEST(decode_connack_malformed_remain_len_one);
    RUN_TEST(decode_connack_truncated_one_byte_buffer);
    RUN_TEST(decode_connack_truncated_no_var_header);
    RUN_TEST(decode_connack_truncated_partial_var_header);
    RUN_TEST(decode_connack_flags_session_present_accepted);
    RUN_TEST(decode_connack_flags_no_session_accepted);
    RUN_TEST(decode_connack_flags_reserved_bit_1_rejected);
    RUN_TEST(decode_connack_flags_reserved_bit_7_rejected);
    RUN_TEST(decode_connack_flags_all_reserved_rejected);
    RUN_TEST(decode_connack_flags_all_bits_rejected);
    RUN_TEST(decode_connack_refused_with_session_present_rejected);
    RUN_TEST(decode_connack_refused_without_session_present_accepted);

    /* MqttEncode_Subscribe */
    RUN_TEST(encode_subscribe_packet_id_zero);
    RUN_TEST(encode_subscribe_valid);
    RUN_TEST(encode_subscribe_fixed_header_flags);
    RUN_TEST(encode_subscribe_options_byte_qos0);
    RUN_TEST(encode_subscribe_options_byte_qos1);
    RUN_TEST(encode_subscribe_options_byte_qos2);
    RUN_TEST(encode_subscribe_topic_filter_oversized_rejected);
    RUN_TEST(encode_subscribe_topic_filter_oversized_second_rejected);
    RUN_TEST(encode_subscribe_has_qos1_flag);

    /* MqttEncode_Unsubscribe */
    RUN_TEST(encode_unsubscribe_packet_id_zero);
    RUN_TEST(encode_unsubscribe_valid);
    RUN_TEST(encode_unsubscribe_fixed_header_flags);
    RUN_TEST(encode_unsubscribe_topic_filter_oversized_rejected);
    RUN_TEST(encode_unsubscribe_topic_filter_oversized_second_rejected);
    RUN_TEST(encode_unsubscribe_has_qos1_flag);

    /* MqttEncode_Connect */
    RUN_TEST(encode_connect_password_without_username);
    RUN_TEST(encode_connect_username_and_password);
    RUN_TEST(encode_connect_username_only);
    RUN_TEST(encode_connect_no_credentials);
    RUN_TEST(encode_connect_fixed_header_flags);
    RUN_TEST(encode_connect_flags_username_password_clean);
    RUN_TEST(encode_connect_flags_none);
    RUN_TEST(encode_connect_flags_clean_session_only);
    RUN_TEST(encode_connect_flags_username_only);
    RUN_TEST(encode_connect_flags_lwt_qos1_retain);
    RUN_TEST(encode_connect_client_id_oversized_rejected);
    RUN_TEST(encode_connect_username_oversized_rejected);
    RUN_TEST(encode_connect_password_oversized_rejected);
    RUN_TEST(encode_connect_lwt_topic_oversized_rejected);

#ifdef WOLFMQTT_BROKER
    /* MqttDecode_Connect */
    RUN_TEST(decode_connect_v311_username_password);
    RUN_TEST(decode_connect_v311_no_credentials);
    RUN_TEST(decode_connect_wrong_protocol_name);
    RUN_TEST(decode_connect_wrong_protocol_length);
    RUN_TEST(decode_connect_v311_with_lwt);
    RUN_TEST(decode_connect_rejects_nul_in_client_id);
    RUN_TEST(decode_connect_rejects_nul_in_username);
    /* Note: decode_connect_v311_binary_password covers the password path -
     * Password is Binary Data per [MQTT-3.1.3.5] and decoding is routed
     * around MqttDecode_String, so the U+0000 ban does not apply there. */
    RUN_TEST(decode_connect_rejects_nul_in_will_topic);
    RUN_TEST(decode_connect_password_flag_zero_with_extra_payload_rejected);
    RUN_TEST(decode_connect_username_flag_zero_with_extra_payload_rejected);
    RUN_TEST(decode_connect_will_flag_zero_with_will_topic_and_message_rejected);
    RUN_TEST(decode_connect_will_flag_zero_with_extra_payload_rejected);
    RUN_TEST(decode_connect_reserved_flag_bit_rejected);
    RUN_TEST(decode_connect_will_qos_with_will_flag_zero_rejected);
    RUN_TEST(decode_connect_will_retain_with_will_flag_zero_rejected);
    RUN_TEST(decode_connect_will_qos3_rejected);
    RUN_TEST(decode_connect_will_topic_invalid_utf8_rejected);
    RUN_TEST(decode_connect_will_topic_contains_u0000_rejected);
    RUN_TEST(decode_connect_password_flag_without_username_flag_rejected);
    RUN_TEST(decode_connect_trailing_garbage_rejected);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_connect_v5_rejects_nul_in_client_id);
    RUN_TEST(decode_connect_v5_password_without_username_accepted);
    RUN_TEST(decode_connect_v5_props_freed_on_client_id_error);
#endif

    /* MqttDecode_Subscribe */
    RUN_TEST(decode_subscribe_v311_single_topic);
    RUN_TEST(decode_subscribe_v311_qos3_rejected);
    RUN_TEST(decode_subscribe_v311_options_reserved_bits_qos0_rejected);
    RUN_TEST(decode_subscribe_v311_options_reserved_bits_qos1_rejected);
    RUN_TEST(decode_subscribe_rejects_nul_in_filter);
    RUN_TEST(decode_subscribe_packet_id_zero_rejected);
    RUN_TEST(topic_filter_valid_helper_table);
    RUN_TEST(decode_subscribe_empty_topic_filter_rejected);
    RUN_TEST(decode_subscribe_bad_hash_placement_rejected);
    RUN_TEST(decode_subscribe_hash_not_last_rejected);
    RUN_TEST(decode_subscribe_bad_plus_placement_rejected);
    RUN_TEST(decode_subscribe_empty_payload_rejected);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_subscribe_v5_empty_payload_rejected);
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_subscribe_v5_options_byte_qos_extracted);
    RUN_TEST(decode_subscribe_v5_qos3_rejected);
    RUN_TEST(decode_subscribe_v5_retain_handling_3_rejected);
    RUN_TEST(decode_subscribe_v5_options_reserved_bits_rejected);
#endif

    /* MqttDecode_Unsubscribe */
    RUN_TEST(decode_unsubscribe_rejects_nul_in_filter);
    RUN_TEST(decode_unsubscribe_packet_id_zero_rejected);
    RUN_TEST(decode_unsubscribe_empty_payload_rejected);
    RUN_TEST(decode_unsubscribe_empty_topic_filter_rejected);
    RUN_TEST(decode_unsubscribe_bad_plus_placement_rejected);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_unsubscribe_v5_empty_payload_rejected);
#endif
#endif

    /* QoS 2 ack arithmetic */
    RUN_TEST(qos2_ack_arithmetic);

    /* MqttDecode_SubscribeAck */
    RUN_TEST(decode_suback_valid);
    RUN_TEST(decode_suback_multiple_return_codes);
    RUN_TEST(decode_suback_malformed_remain_len_zero);
    RUN_TEST(decode_suback_malformed_remain_len_one);
    RUN_TEST(decode_suback_v311_reserved_code_0x03_rejected);
    RUN_TEST(decode_suback_v311_reserved_code_0x7F_rejected);
    RUN_TEST(suback_return_code_v311_allowed_set);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_suback_v5_not_authorized_accepted);
    RUN_TEST(suback_return_code_v5_allowed_set);
#endif

    /* MqttDecode_PublishResp */
    RUN_TEST(decode_publish_resp_valid);
    RUN_TEST(decode_publish_resp_malformed_remain_len_zero);
    RUN_TEST(decode_publish_resp_malformed_remain_len_one);
    RUN_TEST(decode_publish_resp_vbi_continuation_oob);
    RUN_TEST(decode_puback_v311_extra_payload_rejected);
    RUN_TEST(decode_pubrec_v311_extra_payload_rejected);
    RUN_TEST(decode_pubrel_v311_extra_payload_rejected);
    RUN_TEST(decode_pubcomp_v311_extra_payload_rejected);
    RUN_TEST(decode_pubrec_v311_valid);
    RUN_TEST(decode_pubrel_v311_valid);
    RUN_TEST(decode_pubcomp_v311_valid);
    RUN_TEST(decode_puback_null_resp_extra_payload_rejected);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_puback_v5_with_reason_code_accepted);
    RUN_TEST(decode_puback_v5_truncated_reason_code_oob);
#endif

    /* MqttEncode_PublishResp fixed-header QoS bits */
    RUN_TEST(encode_publish_rel_has_qos1_flag);
    RUN_TEST(encode_publish_ack_has_qos0_flag);
    RUN_TEST(encode_publish_rec_has_qos0_flag);
    RUN_TEST(encode_publish_comp_has_qos0_flag);

    /* MqttDecode_UnsubscribeAck */
    RUN_TEST(decode_unsuback_valid);
    RUN_TEST(decode_unsuback_malformed_remain_len_zero);
    RUN_TEST(decode_unsuback_malformed_remain_len_one);

    /* MqttDecode_Ping (PINGRESP) length validation */
    RUN_TEST(decode_pingresp_valid);
    RUN_TEST(decode_pingresp_nonzero_remain_len_rejected);

    /* MqttDecode_Disconnect length validation */
#if defined(WOLFMQTT_BROKER) && !defined(WOLFMQTT_V5)
    RUN_TEST(decode_disconnect_v311_valid);
    RUN_TEST(decode_disconnect_v311_nonzero_remain_len_rejected);
    RUN_TEST(decode_disconnect_v311_invalid_fixed_header_flags_rejected);
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_disconnect_v5_invalid_fixed_header_flags_rejected);
    RUN_TEST(decode_disconnect_v5_with_reason_code_accepted);
    RUN_TEST(decode_disconnect_v5_truncated_reason_code_oob);
#endif

    /* Fixed-header reserved-flag validation [MQTT-2.2.2-2] */
    RUN_TEST(fixed_header_flags_valid_canonical_values);
    RUN_TEST(fixed_header_flags_valid_reserved_type_rejected);
    RUN_TEST(fixed_header_flags_valid_zero_required_rejects_nonzero);
    RUN_TEST(fixed_header_flags_valid_two_required_rejects_other);
    RUN_TEST(fixed_header_flags_valid_publish_qos_and_dup);
#ifdef WOLFMQTT_BROKER
    RUN_TEST(decode_subscribe_invalid_fixed_header_flags);
    RUN_TEST(decode_unsubscribe_invalid_fixed_header_flags);
    RUN_TEST(decode_fixed_header_reserved_type_rejected);
#endif
    RUN_TEST(decode_pubrel_invalid_fixed_header_flags);
    RUN_TEST(decode_publish_qos3_rejected);
    RUN_TEST(decode_publish_qos0_with_dup_rejected);

#ifdef WOLFMQTT_V5
    RUN_TEST(publish_resp_v5_success_with_props_roundtrip);
    RUN_TEST(publish_resp_v5_error_no_props_roundtrip);
    RUN_TEST(publish_resp_v5_success_no_props_roundtrip);

    /* MqttEncode/Decode_Auth */
    RUN_TEST(auth_v5_cont_auth_roundtrip);
    RUN_TEST(auth_v5_reauth_roundtrip);
    RUN_TEST(auth_v5_reauth_decodes_without_error);
    RUN_TEST(auth_v5_success_remaining_length_zero);
    RUN_TEST(auth_v5_invalid_reason_code_rejected);
    RUN_TEST(decode_auth_truncated_reason_code_oob);
#endif

    TEST_SUITE_END();

#ifdef WOLFMQTT_V5
    MqttProps_ShutDown();
#endif
}
