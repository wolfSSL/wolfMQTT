/* test_mqtt_sn.c
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

/* Standalone unit tests for the MQTT-SN packet decoders.
 *
 * The SN_Decode_* routines are WOLFMQTT_LOCAL (hidden visibility), so they
 * cannot be linked from libwolfmqtt; src/mqtt_sn_packet.c is therefore built
 * directly into this binary (with -DWOLFMQTT_SN) the same way mqtt_broker.c is
 * built into test_broker_connect. The tests hand-build malformed and
 * well-formed SN frames and feed them through the decoders, asserting on the
 * return code and decoded fields.
 *
 * Coverage focuses on the declared-length bounds checks in SN_Decode_Header,
 * SN_Decode_GWInfo and SN_Decode_Register: each guard rejects a total_len that
 * does not cover the bytes the decoder still needs to read, which would
 * otherwise over-read the caller-supplied buffer (or, in Register, underflow
 * the topic-name length and write the NUL terminator before the field). The
 * GWINFO suite also pins the extended-length (IND) gateway-address length: the
 * copy must derive its length from the bytes actually consumed (1-byte short
 * form vs 3-byte IND form) so the IND form cannot read past the frame.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_sn_packet.h"

/* Provide storage for the unit-test framework's global counters. Must be
 * defined before unit_test.h is included. */
#define UNIT_TEST_IMPLEMENTATION
#include "tests/unit_test.h"

/* I/O test doubles.
 *
 * src/mqtt_sn_packet.c is compiled into this binary so its WOLFMQTT_LOCAL
 * decoders are reachable. That translation unit also contains the SN
 * network send/receive wrappers, which reference these WOLFMQTT_LOCAL socket
 * helpers. They are hidden in libwolfmqtt and never exercised by the decoder
 * tests, so we satisfy the link with stubs that simply report no data. */
int MqttSocket_Read(struct _MqttClient *client, byte* buf, int buf_len,
    int timeout_ms)
{
    (void)client; (void)buf; (void)buf_len; (void)timeout_ms;
    return MQTT_CODE_ERROR_NETWORK;
}
int MqttSocket_Peek(struct _MqttClient *client, byte* buf, int buf_len,
    int timeout_ms)
{
    (void)client; (void)buf; (void)buf_len; (void)timeout_ms;
    return MQTT_CODE_ERROR_NETWORK;
}
int MqttPacket_HandleNetError(MqttClient *client, int rc)
{
    (void)client;
    return rc;
}

static void setup(void)    { }
static void teardown(void) { }

/* ============================================================================
 * SN_Decode_Header
 * ============================================================================ */

TEST(sn_header_short_form_valid)
{
    /* [len=2][type=PING_REQ] */
    byte buf[2] = { 0x02, SN_MSG_TYPE_PING_REQ };
    SN_MsgType type = SN_MSG_TYPE_RESERVED;
    int rc = SN_Decode_Header(buf, (int)sizeof(buf), &type, NULL);
    ASSERT_EQ(2, rc);
    ASSERT_EQ(SN_MSG_TYPE_PING_REQ, type);
}

TEST(sn_header_regack_packet_id_extracted)
{
    /* [len][type=REGACK][topicId(2)][packetId(2)][retcode] */
    byte buf[7] = { 0x07, SN_MSG_TYPE_REGACK, 0x00, 0x01, 0x12, 0x34, 0x00 };
    SN_MsgType type = SN_MSG_TYPE_RESERVED;
    word16 packet_id = 0;
    int rc = SN_Decode_Header(buf, (int)sizeof(buf), &type, &packet_id);
    ASSERT_EQ(7, rc);
    ASSERT_EQ(SN_MSG_TYPE_REGACK, type);
    ASSERT_EQ(0x1234, packet_id);
}

TEST(sn_header_ind_form_total_len_equals_consumed_rejected)
{
    /* Extended-length (IND) header whose declared length (3) only covers the
     * 3 header bytes already consumed, leaving nothing for the message-type
     * read. Must be rejected rather than reading buf[3] one past the end. */
    byte buf[3] = { SN_PACKET_LEN_IND, 0x00, 0x03 };
    SN_MsgType type = SN_MSG_TYPE_RESERVED;
    int rc = SN_Decode_Header(buf, (int)sizeof(buf), &type, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_header_total_len_exceeds_buffer_rejected)
{
    byte buf[2] = { 0x05, SN_MSG_TYPE_PING_REQ };
    int rc = SN_Decode_Header(buf, (int)sizeof(buf), NULL, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(sn_header_null_buf_rejected)
{
    int rc = SN_Decode_Header(NULL, 4, NULL, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(sn_header_buf_too_short_rejected)
{
    byte buf[1] = { 0x02 };
    int rc = SN_Decode_Header(buf, (int)sizeof(buf), NULL, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * SN_Decode_GWInfo
 * ============================================================================ */

TEST(sn_gwinfo_short_form_no_addr_valid)
{
    /* [len=3][type=GWINFO][gwId] - no gateway address present */
    byte buf[3] = { 0x03, SN_MSG_TYPE_GWINFO, 0x09 };
    SN_GwInfo info;
    int rc;
    XMEMSET(&info, 0, sizeof(info));
    rc = SN_Decode_GWInfo(buf, (int)sizeof(buf), &info);
    ASSERT_EQ(3, rc);
    ASSERT_EQ(0x09, info.gwId);
}

TEST(sn_gwinfo_short_form_with_addr_valid)
{
    /* [len=5][type=GWINFO][gwId][addr0][addr1] */
    byte buf[5] = { 0x05, SN_MSG_TYPE_GWINFO, 0x09, 0xAA, 0xBB };
    const byte expect[2] = { 0xAA, 0xBB };
    SN_GwAddr addr;
    SN_GwInfo info;
    int rc;
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&addr, 0, sizeof(addr));
    info.gwAddr = &addr;
    rc = SN_Decode_GWInfo(buf, (int)sizeof(buf), &info);
    ASSERT_EQ(5, rc);
    ASSERT_EQ(0x09, info.gwId);
    ASSERT_MEM_EQ(expect, &addr, sizeof(addr));
}

TEST(sn_gwinfo_short_form_total_len_too_small_rejected)
{
    /* total_len=2 cannot cover type + gwId. */
    byte buf[2] = { 0x02, SN_MSG_TYPE_GWINFO };
    SN_GwInfo info;
    int rc;
    XMEMSET(&info, 0, sizeof(info));
    rc = SN_Decode_GWInfo(buf, (int)sizeof(buf), &info);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_gwinfo_ind_form_total_len_equals_consumed_rejected)
{
    /* IND header consumes 3 bytes; total_len=3 leaves nothing for the
     * type + gwId reads. Must be rejected, not walk past the buffer. */
    byte buf[3] = { SN_PACKET_LEN_IND, 0x00, 0x03 };
    SN_GwInfo info;
    int rc;
    XMEMSET(&info, 0, sizeof(info));
    rc = SN_Decode_GWInfo(buf, (int)sizeof(buf), &info);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_gwinfo_ind_form_no_addr_no_overread)
{
    /* IND form, total_len=5: the 5 bytes are exactly [IND][len(2)][type][gwId]
     * with NO address. The address length must be computed from the 5 bytes
     * actually consumed (not a fixed 3), so no copy happens and gwAddr is left
     * untouched. The old "total_len - 3" math would copy 2 bytes from offset 5,
     * two bytes past this 5-byte buffer. */
    byte buf[5] = { SN_PACKET_LEN_IND, 0x00, 0x05, SN_MSG_TYPE_GWINFO, 0x09 };
    SN_GwAddr addr;
    SN_GwInfo info;
    int rc;
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&addr, 0x5A, sizeof(addr)); /* sentinel: must stay unchanged */
    info.gwAddr = &addr;
    rc = SN_Decode_GWInfo(buf, (int)sizeof(buf), &info);
    ASSERT_EQ(5, rc);
    ASSERT_EQ(0x09, info.gwId);
    ASSERT_EQ(0x5A5A, addr); /* no spurious copy */
}

TEST(sn_gwinfo_ind_form_with_addr_valid)
{
    /* IND form, total_len=7 with a 2-byte address at offset 5. Proves the
     * copy reads from the correct offset for the extended-length form. */
    byte buf[7] = { SN_PACKET_LEN_IND, 0x00, 0x07, SN_MSG_TYPE_GWINFO, 0x09,
                    0xAA, 0xBB };
    const byte expect[2] = { 0xAA, 0xBB };
    SN_GwAddr addr;
    SN_GwInfo info;
    int rc;
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&addr, 0, sizeof(addr));
    info.gwAddr = &addr;
    rc = SN_Decode_GWInfo(buf, (int)sizeof(buf), &info);
    ASSERT_EQ(7, rc);
    ASSERT_EQ(0x09, info.gwId);
    ASSERT_MEM_EQ(expect, &addr, sizeof(addr));
}

TEST(sn_gwinfo_wrong_type_rejected)
{
    byte buf[3] = { 0x03, SN_MSG_TYPE_ADVERTISE, 0x09 };
    SN_GwInfo info;
    int rc;
    XMEMSET(&info, 0, sizeof(info));
    rc = SN_Decode_GWInfo(buf, (int)sizeof(buf), &info);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_TYPE, rc);
}

/* ============================================================================
 * SN_Decode_Register
 * ============================================================================ */

TEST(sn_register_short_form_valid)
{
    /* [len=8][type=REGISTER][topicId=0x0102][packetId=0x0304]['a']['b'][\0] */
    byte buf[9] = { 0x08, SN_MSG_TYPE_REGISTER, 0x01, 0x02, 0x03, 0x04,
                    'a', 'b', 0x00 };
    SN_Register reg;
    int rc;
    XMEMSET(&reg, 0, sizeof(reg));
    rc = SN_Decode_Register(buf, (int)sizeof(buf), &reg);
    ASSERT_EQ(8, rc);
    ASSERT_EQ(0x0102, reg.topicId);
    ASSERT_EQ(0x0304, reg.packet_id);
    ASSERT_NOT_NULL(reg.topicName);
    ASSERT_STR_EQ("ab", reg.topicName);
}

TEST(sn_register_ind_form_valid)
{
    /* IND form: [IND][len=0x000A][type][topicId][packetId]['a']['b'][\0] */
    byte buf[11] = { SN_PACKET_LEN_IND, 0x00, 0x0A, SN_MSG_TYPE_REGISTER,
                     0x01, 0x02, 0x03, 0x04, 'a', 'b', 0x00 };
    SN_Register reg;
    int rc;
    XMEMSET(&reg, 0, sizeof(reg));
    rc = SN_Decode_Register(buf, (int)sizeof(buf), &reg);
    ASSERT_EQ(10, rc);
    ASSERT_EQ(0x0102, reg.topicId);
    ASSERT_EQ(0x0304, reg.packet_id);
    ASSERT_NOT_NULL(reg.topicName);
    ASSERT_STR_EQ("ab", reg.topicName);
}

TEST(sn_register_ind_form_total_len_too_small_rejected)
{
    /* IND form consumes 8 bytes (len + type + topicId + packetId). total_len=7
     * is below that, so the topic-name length would underflow and the NUL
     * terminator would be written before topicName. Must be rejected.
     * rx_buf_len is 8 (> total_len) so the OUT_OF_BUFFER check is passed and
     * the new lower-bound guard is what rejects it. */
    byte buf[8] = { SN_PACKET_LEN_IND, 0x00, 0x07, SN_MSG_TYPE_REGISTER,
                    0x01, 0x02, 0x03, 0x04 };
    SN_Register reg;
    int rc;
    XMEMSET(&reg, 0, sizeof(reg));
    rc = SN_Decode_Register(buf, (int)sizeof(buf), &reg);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_register_total_len_below_fixed_min_rejected)
{
    /* total_len=6 is below the 7-byte minimum REGISTER. rx_buf_len is larger
     * so this exercises the fixed minimum, not the buffer check. */
    byte buf[10] = { 0x06, SN_MSG_TYPE_REGISTER, 0x01, 0x02, 0x03, 0x04,
                     'a', 'b', 'c', 0x00 };
    SN_Register reg;
    int rc;
    XMEMSET(&reg, 0, sizeof(reg));
    rc = SN_Decode_Register(buf, (int)sizeof(buf), &reg);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_register_wrong_type_rejected)
{
    byte buf[9] = { 0x08, SN_MSG_TYPE_PUBLISH, 0x01, 0x02, 0x03, 0x04,
                    'a', 'b', 0x00 };
    SN_Register reg;
    int rc;
    XMEMSET(&reg, 0, sizeof(reg));
    rc = SN_Decode_Register(buf, (int)sizeof(buf), &reg);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_TYPE, rc);
}

/* ============================================================================
 * SN_Decode_ConnectAck
 *
 * The MQTT-SN CONNACK is a fixed 3-byte frame: [len=3][type=CONNACK][retcode].
 * SN_Client_HandlePacket routes CONNACK through this decoder, so the length,
 * buffer-size and packet-type guards here are what stop a malformed gateway
 * frame (e.g. an over-long packet with a benign trailing byte) from being
 * accepted as a successful connect by SN_Client_Connect.
 * ============================================================================ */

TEST(sn_connack_accepted_valid)
{
    /* [len=3][type=CONNACK][return_code=ACCEPTED] */
    byte buf[3] = { 0x03, SN_MSG_TYPE_CONNACK, SN_RC_ACCEPTED };
    SN_ConnectAck ack;
    int rc;
    XMEMSET(&ack, 0xFF, sizeof(ack)); /* poison: decoder must overwrite */
    rc = SN_Decode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(3, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, ack.return_code);
}

TEST(sn_connack_rejected_valid)
{
    /* A well-formed CONNACK that refuses the connection. The decoder must
     * succeed (rc=3) and surface the gateway's reject code unchanged so the
     * caller can map it to MQTT_CODE_ERROR_CONNECT_REFUSED. */
    byte buf[3] = { 0x03, SN_MSG_TYPE_CONNACK, SN_RC_CONGESTION };
    SN_ConnectAck ack;
    int rc;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = SN_Decode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(3, rc);
    ASSERT_EQ(SN_RC_CONGESTION, ack.return_code);
}

TEST(sn_connack_short_len_rejected)
{
    /* total_len=2 cannot cover the 3-byte fixed CONNACK. rx_buf_len is larger
     * so this exercises the fixed-length check, not the buffer guard. */
    byte buf[3] = { 0x02, SN_MSG_TYPE_CONNACK, SN_RC_ACCEPTED };
    SN_ConnectAck ack;
    int rc;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = SN_Decode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_connack_long_len_rejected)
{
    /* Regression for the trusted-last-byte bug: a 4-byte frame whose declared
     * length is 4. The old handler read buf[buf_len-1] (the trailing ACCEPTED
     * byte) and reported success even though the real return code (offset 2)
     * was a reject. The decoder must reject the non-3 length outright. */
    byte buf[4] = { 0x04, SN_MSG_TYPE_CONNACK, SN_RC_CONGESTION,
                    SN_RC_ACCEPTED };
    SN_ConnectAck ack;
    int rc;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = SN_Decode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_connack_total_len_exceeds_buffer_rejected)
{
    /* Declared length 3 but only 2 bytes are actually available. Must be
     * rejected by the buffer guard rather than reading buf[2] past the end. */
    byte buf[2] = { 0x03, SN_MSG_TYPE_CONNACK };
    SN_ConnectAck ack;
    int rc;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = SN_Decode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(sn_connack_wrong_type_rejected)
{
    /* Correct length but a non-CONNACK message type. */
    byte buf[3] = { 0x03, SN_MSG_TYPE_WILLTOPICREQ, SN_RC_ACCEPTED };
    SN_ConnectAck ack;
    int rc;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = SN_Decode_ConnectAck(buf, (int)sizeof(buf), &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_TYPE, rc);
}

TEST(sn_connack_null_buf_rejected)
{
    SN_ConnectAck ack;
    int rc;
    XMEMSET(&ack, 0, sizeof(ack));
    rc = SN_Decode_ConnectAck(NULL, 3, &ack);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * SN_Packet_TypeDesc
 * ============================================================================ */

/* The QoS 2 PUBREC/PUBREL branch of SN_Client_HandlePacket logs the response
 * message type (SN_MSG_TYPE_PUBREL or SN_MSG_TYPE_PUBCOMP) for its debug trace.
 * MQTT-SN message-type values do not align with the standard MqttPacketType
 * values, so describing them with MqttPacket_TypeDesc mis-renders PUBCOMP
 * (0x0E) as "Disconnect" and PUBREL (0x10) as "Unknown". These tests pin the
 * correct SN descriptions, including the two values that branch can produce. */
#ifndef WOLFMQTT_NO_ERROR_STRINGS
TEST(sn_typedesc_pubcomp)
{
    /* 0x0E: would be "Disconnect" if described as an MqttPacketType. */
    ASSERT_STR_EQ("Publish complete", SN_Packet_TypeDesc(SN_MSG_TYPE_PUBCOMP));
}

TEST(sn_typedesc_pubrel)
{
    /* 0x10: outside the MqttPacketType range, would be "Unknown". */
    ASSERT_STR_EQ("Publish Release", SN_Packet_TypeDesc(SN_MSG_TYPE_PUBREL));
}

TEST(sn_typedesc_pubrec)
{
    ASSERT_STR_EQ("Publish Received", SN_Packet_TypeDesc(SN_MSG_TYPE_PUBREC));
}

TEST(sn_typedesc_unknown_type)
{
    /* 0x11 is reserved and unhandled, so it falls through to the default. */
    ASSERT_STR_EQ("Unknown", SN_Packet_TypeDesc((SN_MsgType)0x11));
}
#endif /* !WOLFMQTT_NO_ERROR_STRINGS */

/* ============================================================================
 * SN_Encode_Publish
 *
 * publish->total_len is a caller-supplied word32 payload length. The encoder
 * must keep its length arithmetic in an unsigned wide type and reject oversized
 * lengths before they can wrap negative/small and slip past the
 * SN_PACKET_MAX_LEN / tx_buf_len bounds checks (which previously preceded a
 * XMEMCPY of the full word32 length - report 5510).
 * ============================================================================ */

TEST(sn_encode_publish_short_topic_valid)
{
    /* QoS1, SHORT topic "tp", packet id 0x1234, payload "hi" -> 9-byte packet:
     * [len=9][PUBLISH][flags][t][p][id hi][id lo][h][i] */
    byte tx_buf[32];
    char topic[2] = { 't', 'p' };
    byte payload[2] = { 'h', 'i' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos        = MQTT_QOS_1;
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = sizeof(payload);

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(9, rc);
    ASSERT_EQ(9, tx_buf[0]);
    ASSERT_EQ(SN_MSG_TYPE_PUBLISH, tx_buf[1]);
    /* flags = (QOS_MASK & (1<<5)) | (TOPICIDTYPE_MASK & SHORT) = 0x20 | 0x02 */
    ASSERT_EQ(0x22, tx_buf[2]);
    ASSERT_EQ('t', tx_buf[3]);
    ASSERT_EQ('p', tx_buf[4]);
    ASSERT_EQ(0x12, tx_buf[5]);
    ASSERT_EQ(0x34, tx_buf[6]);
    ASSERT_EQ('h', tx_buf[7]);
    ASSERT_EQ('i', tx_buf[8]);
}

TEST(sn_encode_publish_ind_form_valid)
{
    /* A 300-byte payload pushes the packet past SN_PACKET_MAX_SMALL_SIZE, so the
     * length is encoded in the 3-byte extended (IND) form. Total = 300 + 9. */
    static byte tx_buf[512];
    static byte payload[300];
    char topic[2] = { 't', 'p' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = sizeof(payload);

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(309, rc);
    ASSERT_EQ(SN_PACKET_LEN_IND, tx_buf[0]);
    /* 309 = 0x0135, big-endian */
    ASSERT_EQ(0x01, tx_buf[1]);
    ASSERT_EQ(0x35, tx_buf[2]);
    ASSERT_EQ(SN_MSG_TYPE_PUBLISH, tx_buf[3]);
}

TEST(sn_encode_publish_oversized_total_len_rejected)
{
    /* Regression for report 5510: total_len = 0xFFFFFFFF. The old code cast this
     * to int (-1), added 7 (=6), passed both bounds checks, then XMEMCPY'd
     * 0xFFFFFFFF bytes. A valid topic and buffer are supplied so the pre-fix
     * path would have reached that copy; the fix must reject up front. */
    byte tx_buf[32];
    char topic[2] = { 't', 'p' };
    byte payload[2] = { 'h', 'i' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = 0xFFFFFFFFU;

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(sn_encode_publish_total_len_int_max_rejected)
{
    /* total_len = INT_MAX (0x7FFFFFFF): adding the 7-byte header overflows
     * signed int (wraps negative under -fwrapv), which the old code let slip
     * past the bounds checks. Must be rejected. */
    byte tx_buf[32];
    char topic[2] = { 't', 'p' };
    byte payload[2] = { 'h', 'i' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = 0x7FFFFFFFU;

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(sn_encode_publish_total_len_over_max_rejected)
{
    /* One byte past the largest encodable payload (SN_PACKET_MAX_LEN - 9). The
     * buffer length is not the limiting factor here - the payload itself cannot
     * fit in a valid MQTT-SN packet. */
    static byte tx_buf[SN_PACKET_MAX_LEN];
    char topic[2] = { 't', 'p' };
    byte payload[2] = { 'h', 'i' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = (word32)(SN_PACKET_MAX_LEN - 9) + 1;

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(sn_encode_publish_max_payload_accepted)
{
    /* The largest payload that still fits a valid packet: SN_PACKET_MAX_LEN - 9
     * encodes to exactly SN_PACKET_MAX_LEN bytes (extended length form). Guards
     * the bounds check against being off-by-one and rejecting a valid maximum. */
    static byte tx_buf[SN_PACKET_MAX_LEN];
    static byte payload[SN_PACKET_MAX_LEN - 9];
    char topic[2] = { 't', 'p' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = (word32)sizeof(payload);

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(SN_PACKET_MAX_LEN, rc);
    ASSERT_EQ(SN_PACKET_LEN_IND, tx_buf[0]);
}

TEST(sn_encode_publish_buffer_too_small_rejected)
{
    /* total_len is encodable, but tx_buf cannot hold the resulting packet. The
     * tx_buf_len bounds check (now unsigned) must still reject it. */
    byte tx_buf[8]; /* packet would need 9 bytes */
    char topic[2] = { 't', 'p' };
    byte payload[2] = { 'h', 'i' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = sizeof(payload);

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(sn_encode_publish_negative_buf_len_rejected)
{
    /* A negative tx_buf_len must not be sign-converted into a huge unsigned
     * limit that lets the bounds check pass. */
    byte tx_buf[32];
    char topic[2] = { 't', 'p' };
    byte payload[2] = { 'h', 'i' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
    publish.topic_name = topic;
    publish.packet_id  = 0x1234;
    publish.buffer     = payload;
    publish.total_len  = sizeof(payload);

    rc = SN_Encode_Publish(tx_buf, -1, &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, rc);
}

TEST(sn_encode_publish_null_args_rejected)
{
    byte tx_buf[32];
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));

    rc = SN_Encode_Publish(NULL, (int)sizeof(tx_buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);

    rc = SN_Encode_Publish(tx_buf, (int)sizeof(tx_buf), NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * SN_Decode_Publish
 *
 * The PUBLISH flags byte carries the topic id type in bits[1:0]. MQTT-SN v1.2
 * defines only NORMAL (0), PREDEF (1) and SHORT (2); value 3 (0b11) is reserved
 * and must not appear on the wire. The decoder must reject it rather than
 * fail-open and hand topic_type=3 to the application callback, which would
 * mis-classify the message (report 4659). These tests pin the rejection of the
 * reserved value and confirm the three defined values still decode (boundary at
 * SHORT=2).
 *
 * Frame layout (short form, 7-byte header):
 *   [len][PUBLISH][flags][topic hi][topic lo][id hi][id lo] payload...
 * ============================================================================ */

TEST(sn_decode_publish_reserved_topic_type_rejected)
{
    /* Report 4659 PoC: flags=0x03 sets the reserved topic id type 0b11. The
     * pre-fix decoder returned 7 (success) with topic_type=3. */
    byte buf[7] = { 0x07, 0x0C, 0x03, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
}

TEST(sn_decode_publish_normal_topic_type_valid)
{
    /* topic_type bits = 0b00 (NORMAL): must still decode. */
    byte buf[7] = { 0x07, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(7, rc);
    ASSERT_EQ(SN_TOPIC_ID_TYPE_NORMAL, publish.topic_type);
}

TEST(sn_decode_publish_predef_topic_type_valid)
{
    /* topic_type bits = 0b01 (PREDEF): must still decode. */
    byte buf[7] = { 0x07, 0x0C, 0x01, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(7, rc);
    ASSERT_EQ(SN_TOPIC_ID_TYPE_PREDEF, publish.topic_type);
}

TEST(sn_decode_publish_short_topic_type_valid)
{
    /* topic_type bits = 0b10 (SHORT): the boundary value the guard must accept.
     * Full frame with QoS1, topic "tp", packet id 0x1234 and payload "hi"; pins
     * the other decoded flag fields too. */
    byte buf[9] = { 0x09, 0x0C, 0x22, 't', 'p', 0x12, 0x34, 'h', 'i' };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(9, rc);
    /* flags = 0x22 -> QoS1, no retain/dup, SHORT topic type */
    ASSERT_EQ(SN_TOPIC_ID_TYPE_SHORT, publish.topic_type);
    ASSERT_EQ(MQTT_QOS_1, publish.qos);
    ASSERT_EQ(0, publish.retain);
    ASSERT_EQ(0, publish.duplicate);
    ASSERT_EQ(0x1234, publish.packet_id);
    ASSERT_EQ(2, publish.total_len);
}

TEST(sn_decode_publish_null_args_rejected)
{
    byte buf[7] = { 0x07, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));

    rc = SN_Decode_Publish(NULL, (int)sizeof(buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);

    rc = SN_Decode_Publish(buf, (int)sizeof(buf), NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ----------------------------------------------------------------------------
 * MsgId=0 guard for QoS > 0 (report 4248)
 *
 * MQTT-SN v1.2 §5.2.10 requires a QoS 1 or QoS 2 PUBLISH to carry a non-zero
 * MsgId. The pre-fix decoder returned success with packet_id=0, so
 * SN_Client_HandlePacket emitted a PUBACK/PUBREC carrying MsgId=0 that no
 * conformant gateway can correlate; the gateway then retransmits the same
 * PUBLISH, replaying the message to msg_cb. The guard rejects MsgId=0 for
 * QoS > 0 while still accepting MsgId=0 for QoS 0 (where no response is sent).
 *
 * Frame layout (short form, 7-byte header):
 *   [len][PUBLISH][flags][topic hi][topic lo][id hi][id lo] payload...
 * flags QoS bits = bits[6:5]: 0x20 -> QoS1, 0x40 -> QoS2.
 * -------------------------------------------------------------------------- */

TEST(sn_decode_publish_qos1_zero_packet_id_rejected)
{
    /* Report 4248 PoC: flags=0x20 -> QoS1, MsgId=0x0000. */
    byte buf[7] = { 0x07, 0x0C, 0x20, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

TEST(sn_decode_publish_qos2_zero_packet_id_rejected)
{
    /* flags=0x40 -> QoS2, MsgId=0x0000. */
    byte buf[7] = { 0x07, 0x0C, 0x40, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);
}

TEST(sn_decode_publish_qos0_zero_packet_id_valid)
{
    /* QoS0 (flags=0x00) carries no MsgId and sends no response, so MsgId=0
     * is legal and must still decode. */
    byte buf[7] = { 0x07, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(7, rc);
    ASSERT_EQ(MQTT_QOS_0, publish.qos);
    ASSERT_EQ(0, publish.packet_id);
}

TEST(sn_decode_publish_qos1_nonzero_packet_id_valid)
{
    /* flags=0x20 -> QoS1 with a valid non-zero MsgId 0x1234 must decode. */
    byte buf[7] = { 0x07, 0x0C, 0x20, 0x00, 0x01, 0x12, 0x34 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(7, rc);
    ASSERT_EQ(MQTT_QOS_1, publish.qos);
    ASSERT_EQ(0x1234, publish.packet_id);
}

TEST(sn_decode_publish_qosneg1_zero_packet_id_valid)
{
    /* flags=0x60 -> QoS bits 0b11 = MQTT_QOS_3, MQTT-SN's QoS -1
     * (connectionless publish). It sends no PUBACK/PUBREC and uses MsgId=0,
     * so the guard must NOT reject it. */
    byte buf[7] = { 0x07, 0x0C, 0x60, 0x00, 0x01, 0x00, 0x00 };
    SN_Publish publish;
    int rc;

    XMEMSET(&publish, 0, sizeof(publish));
    rc = SN_Decode_Publish(buf, (int)sizeof(buf), &publish);
    ASSERT_EQ(7, rc);
    ASSERT_EQ(MQTT_QOS_3, publish.qos);
    ASSERT_EQ(0, publish.packet_id);
}

/* ============================================================================
 * Suite runner
 * ============================================================================ */

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    TEST_RUNNER_BEGIN();

    TEST_SUITE_BEGIN("mqtt_sn_packet", setup, teardown);

    /* SN_Decode_Header */
    RUN_TEST(sn_header_short_form_valid);
    RUN_TEST(sn_header_regack_packet_id_extracted);
    RUN_TEST(sn_header_ind_form_total_len_equals_consumed_rejected);
    RUN_TEST(sn_header_total_len_exceeds_buffer_rejected);
    RUN_TEST(sn_header_null_buf_rejected);
    RUN_TEST(sn_header_buf_too_short_rejected);

    /* SN_Decode_GWInfo */
    RUN_TEST(sn_gwinfo_short_form_no_addr_valid);
    RUN_TEST(sn_gwinfo_short_form_with_addr_valid);
    RUN_TEST(sn_gwinfo_short_form_total_len_too_small_rejected);
    RUN_TEST(sn_gwinfo_ind_form_total_len_equals_consumed_rejected);
    RUN_TEST(sn_gwinfo_ind_form_no_addr_no_overread);
    RUN_TEST(sn_gwinfo_ind_form_with_addr_valid);
    RUN_TEST(sn_gwinfo_wrong_type_rejected);

    /* SN_Decode_Register */
    RUN_TEST(sn_register_short_form_valid);
    RUN_TEST(sn_register_ind_form_valid);
    RUN_TEST(sn_register_ind_form_total_len_too_small_rejected);
    RUN_TEST(sn_register_total_len_below_fixed_min_rejected);
    RUN_TEST(sn_register_wrong_type_rejected);

    /* SN_Decode_ConnectAck */
    RUN_TEST(sn_connack_accepted_valid);
    RUN_TEST(sn_connack_rejected_valid);
    RUN_TEST(sn_connack_short_len_rejected);
    RUN_TEST(sn_connack_long_len_rejected);
    RUN_TEST(sn_connack_total_len_exceeds_buffer_rejected);
    RUN_TEST(sn_connack_wrong_type_rejected);
    RUN_TEST(sn_connack_null_buf_rejected);

    /* SN_Encode_Publish */
    RUN_TEST(sn_encode_publish_short_topic_valid);
    RUN_TEST(sn_encode_publish_ind_form_valid);
    RUN_TEST(sn_encode_publish_oversized_total_len_rejected);
    RUN_TEST(sn_encode_publish_total_len_int_max_rejected);
    RUN_TEST(sn_encode_publish_total_len_over_max_rejected);
    RUN_TEST(sn_encode_publish_max_payload_accepted);
    RUN_TEST(sn_encode_publish_buffer_too_small_rejected);
    RUN_TEST(sn_encode_publish_negative_buf_len_rejected);
    RUN_TEST(sn_encode_publish_null_args_rejected);

    /* SN_Decode_Publish */
    RUN_TEST(sn_decode_publish_reserved_topic_type_rejected);
    RUN_TEST(sn_decode_publish_normal_topic_type_valid);
    RUN_TEST(sn_decode_publish_predef_topic_type_valid);
    RUN_TEST(sn_decode_publish_short_topic_type_valid);
    RUN_TEST(sn_decode_publish_null_args_rejected);
    RUN_TEST(sn_decode_publish_qos1_zero_packet_id_rejected);
    RUN_TEST(sn_decode_publish_qos2_zero_packet_id_rejected);
    RUN_TEST(sn_decode_publish_qos0_zero_packet_id_valid);
    RUN_TEST(sn_decode_publish_qos1_nonzero_packet_id_valid);
    RUN_TEST(sn_decode_publish_qosneg1_zero_packet_id_valid);

    /* SN_Packet_TypeDesc */
#ifndef WOLFMQTT_NO_ERROR_STRINGS
    RUN_TEST(sn_typedesc_pubcomp);
    RUN_TEST(sn_typedesc_pubrel);
    RUN_TEST(sn_typedesc_pubrec);
    RUN_TEST(sn_typedesc_unknown_type);
#endif

    TEST_SUITE_END();

    TEST_RUNNER_END();
}
