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

    TEST_SUITE_END();

    TEST_RUNNER_END();
}
