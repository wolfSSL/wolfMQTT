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

/* STRING_PAIR (USER_PROPERTY) NUL rejection — first string of pair. The
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

/* STRING_PAIR (USER_PROPERTY) NUL rejection — second string of pair.
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
 * the encoder must still reject — the length-validation loop covers every
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
 * the encoder must still reject — the length-validation loop covers every
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

/* [MQTT-1.5.3-2]: an embedded NUL in the password must be rejected.
 * Same auth-bypass mechanism as the username test, applied to the
 * password field. */
TEST(decode_connect_rejects_nul_in_password)
{
    byte buf[] = {
        0x10, 0x16,                         /* CONNECT, remain_len = 22 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0xC2,                               /* clean_session + USER + PASS */
        0x00, 0x3C,
        0x00, 0x02, 'c', '1',
        0x00, 0x01, 'u',                    /* username "u" */
        0x00, 0x03, 'p', 0x00, 'w'          /* password with NUL */
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

#ifdef WOLFMQTT_V5
/* MQTT v5 has a different decode path than v3.1.1 (properties walked
 * before client_id, separate LWT properties), but the NUL rejection
 * lives inside MqttDecode_String / MqttDecode_Password and so applies
 * uniformly. This pins coverage on the v5 branch so a future refactor
 * cannot quietly bypass the check on one protocol level. */
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

/* Options byte QoS bits (0-1) = 0b11 is reserved. The decoder forwards the
 * raw value verbatim (options & 0x03 == 3), so the broker's
 * BrokerHandle_Subscribe cap at MQTT_QOS_2 is the only thing preventing
 * QoS=3 from propagating into BrokerSubs_Add / the SUBACK return code.
 * This test pins the precondition: if the decoder ever starts rejecting
 * QoS=3, the broker cap becomes dead code and this test will flag it. */
TEST(decode_subscribe_v311_qos3_reserved)
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
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(1, sub.topic_count);
    ASSERT_EQ(MQTT_QOS_3, topic_arr[0].qos);
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
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * MqttDecode_Unsubscribe (broker-side)
 * ============================================================================ */

/* [MQTT-1.5.3-2] / [MQTT-4.7.3-2]: a topic filter containing U+0000 in an
 * UNSUBSCRIBE must be rejected — MqttDecode_Unsubscribe shares the same
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

    /* MqttEncode_Publish */
    RUN_TEST(encode_publish_qos1_packet_id_zero);
    RUN_TEST(encode_publish_qos2_packet_id_zero);
    RUN_TEST(encode_publish_qos0_packet_id_zero_ok);
    RUN_TEST(encode_publish_qos1_valid);
    RUN_TEST(encode_publish_qos1_retain_flags_in_header);
    RUN_TEST(encode_publish_qos2_duplicate_flags_in_header);
    RUN_TEST(encode_publish_qos0_no_flags_in_header);
    RUN_TEST(encode_publish_topic_oversized_rejected);

    /* MqttDecode_Publish */
    RUN_TEST(decode_publish_qos0_valid);
    RUN_TEST(decode_publish_qos1_valid);
    RUN_TEST(decode_publish_qos0_zero_payload);
    RUN_TEST(decode_publish_malformed_variable_exceeds_remain);
    RUN_TEST(decode_publish_rejects_nul_in_topic);
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
    RUN_TEST(decode_connect_rejects_nul_in_password);
    RUN_TEST(decode_connect_rejects_nul_in_will_topic);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_connect_v5_rejects_nul_in_client_id);
#endif

    /* MqttDecode_Subscribe */
    RUN_TEST(decode_subscribe_v311_single_topic);
    RUN_TEST(decode_subscribe_v311_qos3_reserved);
    RUN_TEST(decode_subscribe_rejects_nul_in_filter);
#ifdef WOLFMQTT_V5
    RUN_TEST(decode_subscribe_v5_options_byte_qos_extracted);
#endif

    /* MqttDecode_Unsubscribe */
    RUN_TEST(decode_unsubscribe_rejects_nul_in_filter);
#endif

    /* QoS 2 ack arithmetic */
    RUN_TEST(qos2_ack_arithmetic);

    /* MqttDecode_SubscribeAck */
    RUN_TEST(decode_suback_valid);
    RUN_TEST(decode_suback_multiple_return_codes);
    RUN_TEST(decode_suback_malformed_remain_len_zero);
    RUN_TEST(decode_suback_malformed_remain_len_one);

    /* MqttDecode_PublishResp */
    RUN_TEST(decode_publish_resp_valid);
    RUN_TEST(decode_publish_resp_malformed_remain_len_zero);
    RUN_TEST(decode_publish_resp_malformed_remain_len_one);

    /* MqttEncode_PublishResp fixed-header QoS bits */
    RUN_TEST(encode_publish_rel_has_qos1_flag);
    RUN_TEST(encode_publish_ack_has_qos0_flag);
    RUN_TEST(encode_publish_rec_has_qos0_flag);
    RUN_TEST(encode_publish_comp_has_qos0_flag);

    /* MqttDecode_UnsubscribeAck */
    RUN_TEST(decode_unsuback_valid);
    RUN_TEST(decode_unsuback_malformed_remain_len_zero);
    RUN_TEST(decode_unsuback_malformed_remain_len_one);

    /* Fixed-header reserved-flag validation [MQTT-2.2.2-2] */
    RUN_TEST(fixed_header_flags_valid_canonical_values);
    RUN_TEST(fixed_header_flags_valid_zero_required_rejects_nonzero);
    RUN_TEST(fixed_header_flags_valid_two_required_rejects_other);
    RUN_TEST(fixed_header_flags_valid_publish_qos_and_dup);
#ifdef WOLFMQTT_BROKER
    RUN_TEST(decode_subscribe_invalid_fixed_header_flags);
    RUN_TEST(decode_unsubscribe_invalid_fixed_header_flags);
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
#endif

    TEST_SUITE_END();

#ifdef WOLFMQTT_V5
    MqttProps_ShutDown();
#endif
}
