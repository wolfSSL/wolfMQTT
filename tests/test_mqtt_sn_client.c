/* test_mqtt_sn_client.c
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

/* Client-level (state machine) unit tests for the MQTT-SN client.
 *
 * These tests drive the public SN_Client_* entry points through a mock
 * MqttNet so the will-handshake state machine is exercised end to end. The
 * suite builds in any SN configuration: the happy-path test runs in blocking
 * builds too (guarding the refactored BEGIN/WAIT/HEADER flow against a dropped
 * FALL_THROUGH/transition), while the retry tests are compiled only under
 * WOLFMQTT_NONBLOCK. There the mock gateway returns MQTT_CODE_CONTINUE between
 * scripted SN frames so every wait is re-entered at least once, the same way an
 * application would call the API repeatedly.
 *
 * Regression focus: the Last-Will (LWT) connect handshake. SN_WillTopic and
 * SN_WillMessage used to add their pending response to client->firstPendResp
 * on *every* invocation. Under WOLFMQTT_MULTITHREAD + WOLFMQTT_NONBLOCK the
 * first MQTT_CODE_CONTINUE left the entry linked, so the next SN_Client_Connect
 * call re-added the same MqttPendResp and MqttClient_RespList_Add rejected the
 * duplicate with MQTT_CODE_ERROR_BAD_ARG, permanently failing the connect.
 * The add now happens once (in the MQTT_MSG_BEGIN state) and the helpers resume
 * instead of restarting, so repeated calls converge on success.
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

#ifdef WOLFMQTT_SN

/* A dangling pending response can only exist (and only be inspected) in
 * multi-thread builds, where SN_Will keeps a MqttPendResp. Elsewhere this
 * assertion is a no-op. */
#ifdef WOLFMQTT_MULTITHREAD
    #define ASSERT_NO_PENDRESP() ASSERT_NULL(g_client.firstPendResp)
#else
    #define ASSERT_NO_PENDRESP() do {} while (0)
#endif

/* ============================================================================
 * Mock MqttNet
 *
 * Models a datagram gateway driven through the SN datagram (IS_DTLS) read path:
 * SN_Packet_Read pulls the 2-byte header then the remaining body with
 * sequential reads, so the mock serves each scripted frame byte-region in
 * order via read(). `continues` MQTT_CODE_CONTINUE results are returned at each
 * frame boundary so the client's non-blocking wait is forced to re-enter, the
 * same way an application would call the API repeatedly under WOLFMQTT_NONBLOCK.
 * ============================================================================ */

#define MOCK_MAX_FRAMES 8
#define MOCK_OUT_LEN    1024

typedef struct MockNet {
    const byte* in_frame[MOCK_MAX_FRAMES];
    int         in_len[MOCK_MAX_FRAMES];
    int         in_count;
    int         in_idx;        /* current frame being delivered */
    int         in_off;        /* read offset within the current frame */
    int         continues;     /* CONTINUE results remaining before this frame */
    int         continues_cfg; /* CONTINUE results to arm before each frame */

    byte        out[MOCK_OUT_LEN];
    int         out_len;       /* bytes captured from write() */

    int         write_fail_rc; /* if nonzero, write() returns this instead of
                                * accepting the buffer (simulate short/failed
                                * write) */

    int         read_calls;
    int         write_calls;
} MockNet;

static int mock_connect(void *ctx, const char* host, word16 port,
        int timeout_ms)
{
    (void)ctx; (void)host; (void)port; (void)timeout_ms;
    return MQTT_CODE_SUCCESS;
}

static int mock_disconnect(void *ctx)
{
    (void)ctx;
    return MQTT_CODE_SUCCESS;
}

static int mock_write(void *ctx, const byte* buf, int buf_len, int timeout_ms)
{
    MockNet* net = (MockNet*)ctx;
    (void)timeout_ms;
    net->write_calls++;
    if (net->write_fail_rc != 0) {
        /* Simulate a short/failed write so the caller's rc != xfer error path is
         * exercised. The buffer is left as the caller encoded it (not captured),
         * matching a real transport that errored mid-send. */
        return net->write_fail_rc;
    }
    if (buf_len > 0 && net->out_len + buf_len <= MOCK_OUT_LEN) {
        XMEMCPY(&net->out[net->out_len], buf, (size_t)buf_len);
        net->out_len += buf_len;
    }
    return buf_len; /* accept all bytes */
}

static int mock_read(void *ctx, byte* buf, int buf_len, int timeout_ms)
{
    MockNet* net = (MockNet*)ctx;
    int avail, n;
    (void)timeout_ms;
    net->read_calls++;

    if (net->in_idx >= net->in_count) {
        return MQTT_CODE_CONTINUE; /* nothing left to deliver */
    }

    /* At a frame boundary, optionally simulate "would block" first. */
    if (net->in_off == 0 && net->continues > 0) {
        net->continues--;
        return MQTT_CODE_CONTINUE;
    }

    avail = net->in_len[net->in_idx] - net->in_off;
    n = (buf_len < avail) ? buf_len : avail;
    XMEMCPY(buf, &net->in_frame[net->in_idx][net->in_off], (size_t)n);
    net->in_off += n;

    /* Advance to the next frame once this one is fully consumed. */
    if (net->in_off >= net->in_len[net->in_idx]) {
        net->in_idx++;
        net->in_off = 0;
        net->continues = net->continues_cfg;
    }
    return n;
}

/* peek is required by MqttSocket for the non-DTLS SN path, but the datagram
 * (IS_DTLS) path used by these tests never calls it. Provide a non-consuming
 * implementation for completeness. */
static int mock_peek(void *ctx, byte* buf, int buf_len, int timeout_ms)
{
    MockNet* net = (MockNet*)ctx;
    int avail, n;
    (void)timeout_ms;

    if (net->in_idx >= net->in_count) {
        return MQTT_CODE_CONTINUE;
    }
    if (net->in_off == 0 && net->continues > 0) {
        return MQTT_CODE_CONTINUE;
    }
    avail = net->in_len[net->in_idx] - net->in_off;
    n = (buf_len < avail) ? buf_len : avail;
    XMEMCPY(buf, &net->in_frame[net->in_idx][net->in_off], (size_t)n);
    return n;
}

static void mock_net_init(MockNet* net, MqttNet* mqttNet, int continues_cfg)
{
    XMEMSET(net, 0, sizeof(*net));
    net->continues_cfg = continues_cfg;
    net->continues = continues_cfg;

    XMEMSET(mqttNet, 0, sizeof(*mqttNet));
    mqttNet->context = net;
    mqttNet->connect = mock_connect;
    mqttNet->disconnect = mock_disconnect;
    mqttNet->read = mock_read;
    mqttNet->write = mock_write;
    mqttNet->peek = mock_peek;
}

static void mock_net_push(MockNet* net, const byte* frame, int len)
{
    if (net->in_count < MOCK_MAX_FRAMES) {
        net->in_frame[net->in_count] = frame;
        net->in_len[net->in_count] = len;
        net->in_count++;
    }
}

/* Scripted gateway frames for the LWT connect handshake. */
static const byte WILLTOPICREQ_FRAME[] = { 0x02, SN_MSG_TYPE_WILLTOPICREQ };
static const byte WILLMSGREQ_FRAME[]   = { 0x02, SN_MSG_TYPE_WILLMSGREQ };
static const byte CONNACK_FRAME[]      = { 0x03, SN_MSG_TYPE_CONNACK,
                                           SN_RC_ACCEPTED };

/* Gateway response to a WILLMSGUPD: total_len=3, type, return_code. */
static const byte WILLMSGRESP_FRAME[]  = { 0x03, SN_MSG_TYPE_WILLMSGRESP,
                                           SN_RC_ACCEPTED };

/* Scripted SUBACK for packet_id 1: total_len=8, type, flags=0,
 * topicId=0x000A, packet_id=0x0001, return_code=SN_RC_ACCEPTED. */
#define SN_TEST_SUB_PACKET_ID 1
#define SN_TEST_SUB_TOPIC_ID  0x0A
static const byte SUBACK_FRAME[] = { 0x08, SN_MSG_TYPE_SUBACK, 0x00,
                                     0x00, SN_TEST_SUB_TOPIC_ID,
                                     0x00, SN_TEST_SUB_PACKET_ID,
                                     SN_RC_ACCEPTED };

/* Scripted SUBACK rejecting packet_id 1: same framing as SUBACK_FRAME but the
 * gateway returns SN_RC_INVTOPICNAME and topicId 0x0000 (no topic assigned),
 * as a gateway does when it declines the subscription. */
static const byte SUBACK_REJECT_FRAME[] = { 0x08, SN_MSG_TYPE_SUBACK, 0x00,
                                            0x00, 0x00,
                                            0x00, SN_TEST_SUB_PACKET_ID,
                                            SN_RC_INVTOPICNAME };

/* Gateway PINGRESP: total_len=2, type. */
static const byte PINGRESP_FRAME[] = { 0x02, SN_MSG_TYPE_PING_RESP };

/* Scripted publish-response frames for packet_id 1.
 * PUBACK:  total_len=7, type, topicId(2), packet_id(2), return_code.
 * PUBREC:  total_len=4, type, packet_id(2).
 * PUBCOMP: total_len=4, type, packet_id(2). */
#define SN_TEST_PUB_PACKET_ID 1
#define SN_TEST_PUB_TOPIC_ID  0x0A
static const byte PUBACK_FRAME[] = { 0x07, SN_MSG_TYPE_PUBACK,
                                     0x00, SN_TEST_PUB_TOPIC_ID,
                                     0x00, SN_TEST_PUB_PACKET_ID,
                                     SN_RC_ACCEPTED };
static const byte PUBREC_FRAME[]  = { 0x04, SN_MSG_TYPE_PUBREC,
                                      0x00, SN_TEST_PUB_PACKET_ID };
static const byte PUBCOMP_FRAME[] = { 0x04, SN_MSG_TYPE_PUBCOMP,
                                      0x00, SN_TEST_PUB_PACKET_ID };

/* Scripted UNSUBACK echoing packet_id 1: total_len=4, type, packet_id(2). */
#define SN_TEST_UNSUB_PACKET_ID 1
static const byte UNSUBACK_FRAME[] = { 0x04, SN_MSG_TYPE_UNSUBACK,
                                       0x00, SN_TEST_UNSUB_PACKET_ID };

/* Server-pushed QoS1 PUBLISH: total_len=9, type, flags=QoS1|NORMAL (0x20),
 * topicId=0x000A, packet_id=0x0007, payload(2). */
static const byte SN_PUBLISH_QOS1_FRAME[] = { 0x09, SN_MSG_TYPE_PUBLISH,
                                              0x20, 0x00, 0x0A,
                                              0x00, 0x07, 0x01, 0x02 };

/* ============================================================================
 * Test fixtures
 * ============================================================================ */

static MqttClient g_client;
static MqttNet    g_net;
static MockNet    g_mock;
static byte       g_tx[512];
static byte       g_rx[512];

static void sn_will_setup_connect(SN_Connect* mc)
{
    XMEMSET(mc, 0, sizeof(*mc));
    mc->keep_alive_sec = 60;
    mc->clean_session = 1;
    mc->client_id = "wolfMQTT-sn-test";
    mc->protocol_level = SN_PROTOCOL_ID;
    mc->enable_lwt = 1;
    mc->will.qos = 0;
    mc->will.retain = 0;
    mc->will.willTopic = "wolf/lwt";
    mc->will.willMsg = (byte*)"offline";
    mc->will.willMsgLen = 7;
}

static int sn_client_init(int continues_cfg)
{
    int rc;
    mock_net_init(&g_mock, &g_net, continues_cfg);
    rc = MqttClient_Init(&g_client, &g_net, NULL,
            g_tx, (int)sizeof(g_tx), g_rx, (int)sizeof(g_rx),
            1000 /* cmd_timeout_ms */);
    /* MQTT-SN runs over datagrams; select the datagram framing in the SN
     * packet reader (no TLS is enabled, so this only affects read framing). */
    MqttClient_Flags(&g_client, 0, MQTT_CLIENT_FLAG_IS_DTLS);
    return rc;
}

/* Drive SN_Client_Connect until it returns something other than CONTINUE, or
 * until we exceed a sane iteration cap. Returns the terminal code and the
 * number of iterations through *iters. */
static int sn_connect_pump(SN_Connect* mc, int* iters)
{
    int rc = MQTT_CODE_CONTINUE;
    int i;
    const int max_iters = 50;
    for (i = 0; i < max_iters; i++) {
        rc = SN_Client_Connect(&g_client, mc);
        if (rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }
    if (iters) {
        /* On an early break i is the 0-based index of the terminating call, so
         * the count is i + 1; if the cap was hit (rc still CONTINUE) exactly
         * max_iters calls ran and i already equals that count. */
        *iters = (rc == MQTT_CODE_CONTINUE) ? i : (i + 1);
    }
    return rc;
}

static void sn_subscribe_setup(SN_Subscribe* s)
{
    XMEMSET(s, 0, sizeof(*s));
    s->duplicate = 0;
    s->qos = MQTT_QOS_0;
    s->topic_type = SN_TOPIC_ID_TYPE_NORMAL;
    s->topicNameId = "wolf/topic";
    s->packet_id = SN_TEST_SUB_PACKET_ID;
}

/* Drive SN_Client_Subscribe until it returns something other than CONTINUE, or
 * until we exceed a sane iteration cap. Returns the terminal code and the
 * number of iterations through *iters. */
static int sn_subscribe_pump(SN_Subscribe* s, int* iters)
{
    int rc = MQTT_CODE_CONTINUE;
    int i;
    const int max_iters = 50;
    for (i = 0; i < max_iters; i++) {
        rc = SN_Client_Subscribe(&g_client, s);
        if (rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }
    if (iters) {
        /* On an early break i is the 0-based index of the terminating call, so
         * the count is i + 1; if the cap was hit (rc still CONTINUE) exactly
         * max_iters calls ran and i already equals that count. */
        *iters = (rc == MQTT_CODE_CONTINUE) ? i : (i + 1);
    }
    return rc;
}

/* Drive SN_Client_Ping until it returns something other than CONTINUE, or until
 * we exceed a sane iteration cap. `ping` may be NULL to exercise the internal
 * fallback. Returns the terminal code and the iteration count through *iters. */
static int sn_ping_pump(SN_PingReq* ping, int* iters)
{
    int rc = MQTT_CODE_CONTINUE;
    int i;
    const int max_iters = 50;
    for (i = 0; i < max_iters; i++) {
        rc = SN_Client_Ping(&g_client, ping);
        if (rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }
    if (iters) {
        /* On an early break i is the 0-based index of the terminating call, so
         * the count is i + 1; if the cap was hit (rc still CONTINUE) exactly
         * max_iters calls ran and i already equals that count. */
        *iters = (rc == MQTT_CODE_CONTINUE) ? i : (i + 1);
    }
    return rc;
}

/* Build a NORMAL-topic-ID publish. topicId must outlive every SN_Client_Publish
 * call: SN_Encode_Publish reads the 2-byte topic ID through publish->topic_name,
 * so the caller owns the storage and passes its address here. */
static void sn_publish_setup(SN_Publish* p, const word16* topicId, MqttQoS qos)
{
    XMEMSET(p, 0, sizeof(*p));
    p->retain = 0;
    p->qos = qos;
    p->duplicate = 0;
    p->topic_type = SN_TOPIC_ID_TYPE_NORMAL;
    p->topic_name = (const char*)topicId;
    /* QoS 0 publishes carry no packet id (and expect no ACK). */
    p->packet_id = (qos == MQTT_QOS_0) ? 0 : SN_TEST_PUB_PACKET_ID;
    p->buffer = (byte*)"test";
    p->total_len = 4;
}

/* Drive SN_Client_Publish until it returns something other than CONTINUE, or
 * until we exceed a sane iteration cap. Returns the terminal code and the
 * number of iterations through *iters. */
static int sn_publish_pump(SN_Publish* p, int* iters)
{
    int rc = MQTT_CODE_CONTINUE;
    int i;
    const int max_iters = 50;
    for (i = 0; i < max_iters; i++) {
        rc = SN_Client_Publish(&g_client, p);
        if (rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }
    if (iters) {
        /* On an early break i is the 0-based index of the terminating call, so
         * the count is i + 1; if the cap was hit (rc still CONTINUE) exactly
         * max_iters calls ran and i already equals that count. */
        *iters = (rc == MQTT_CODE_CONTINUE) ? i : (i + 1);
    }
    return rc;
}

static void sn_unsubscribe_setup(SN_Unsubscribe* u)
{
    XMEMSET(u, 0, sizeof(*u));
    u->duplicate = 0;
    u->qos = MQTT_QOS_0;
    u->topic_type = SN_TOPIC_ID_TYPE_NORMAL;
    u->topicNameId = "wolf/topic";
    u->packet_id = SN_TEST_UNSUB_PACKET_ID;
}

/* Drive SN_Client_Unsubscribe until it returns something other than CONTINUE,
 * or until we exceed a sane iteration cap. Returns the terminal code and the
 * number of iterations through *iters. */
static int sn_unsubscribe_pump(SN_Unsubscribe* u, int* iters)
{
    int rc = MQTT_CODE_CONTINUE;
    int i;
    const int max_iters = 50;
    for (i = 0; i < max_iters; i++) {
        rc = SN_Client_Unsubscribe(&g_client, u);
        if (rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }
    if (iters) {
        /* On an early break i is the 0-based index of the terminating call, so
         * the count is i + 1; if the cap was hit (rc still CONTINUE) exactly
         * max_iters calls ran and i already equals that count. */
        *iters = (rc == MQTT_CODE_CONTINUE) ? i : (i + 1);
    }
    return rc;
}

static void setup(void)    { }
static void teardown(void)
{
    MqttClient_DeInit(&g_client);
}

/* memcmp-style search: returns 1 if `needle` (nlen bytes) appears in `hay`. */
static int sn_buf_contains(const byte* hay, int hlen,
        const byte* needle, int nlen)
{
    int i;
    if (hay == NULL || nlen <= 0 || hlen < nlen) {
        return 0;
    }
    for (i = 0; i + nlen <= hlen; i++) {
        if (XMEMCMP(&hay[i], needle, (size_t)nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Shared body for the #3137 will-payload scrub tests. Runs the scripted LWT
 * connect (with `continues` MQTT_CODE_CONTINUE armed before each gateway frame)
 * and asserts the will payload is scrubbed from tx_buf once the WILLMSG has been
 * sent. The ASSERT_* macros bail out of this helper on failure and set the
 * shared failure flag that RUN_TEST inspects, so factoring this out is safe. */
static void sn_will_scrub_check(int continues)
{
    SN_Connect mc;
    int rc, i;
    const byte* willMsg;
    int willMsgLen, willPktLen;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(continues));

    mock_net_push(&g_mock, WILLTOPICREQ_FRAME, (int)sizeof(WILLTOPICREQ_FRAME));
    mock_net_push(&g_mock, WILLMSGREQ_FRAME,   (int)sizeof(WILLMSGREQ_FRAME));
    mock_net_push(&g_mock, CONNACK_FRAME,      (int)sizeof(CONNACK_FRAME));

    sn_will_setup_connect(&mc);
    willMsg = mc.will.willMsg;
    willMsgLen = (int)mc.will.willMsgLen;
    /* Small WILLMSG packet: 1-byte length + 1-byte type + payload. */
    willPktLen = 2 + willMsgLen;

    rc = sn_connect_pump(&mc, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, mc.ack.return_code);

    /* Positive control: the will payload really was written to the wire, so the
     * scrub assertions below cannot pass trivially. */
    ASSERT_TRUE(sn_buf_contains(g_mock.out, g_mock.out_len,
                                willMsg, willMsgLen));

    /* Core #3137 assertion: the will payload must not linger anywhere in the
     * client tx buffer once the WILLMSG has been sent. */
    ASSERT_FALSE(sn_buf_contains(g_client.tx_buf, g_client.tx_buf_len,
                                 willMsg, willMsgLen));

    /* Stronger boundary check: every byte of the WILLMSG packet region must be
     * zero. Catches both deletion of the CLIENT_FORCE_ZERO call and an
     * xfer -> 0 mutation that turns the wipe into a no-op. */
    for (i = 0; i < willPktLen; i++) {
        if (g_client.tx_buf[i] != 0) {
            FAIL("tx_buf within WILLMSG range is non-zero after connect");
        }
    }

    ASSERT_NO_PENDRESP();
}

/* Drive SN_Client_WillMsgUpdate until it returns something other than CONTINUE,
 * or until we exceed a sane iteration cap. Returns the terminal code. */
static int sn_will_msg_update_pump(SN_Will* will)
{
    int rc = MQTT_CODE_CONTINUE;
    int i;
    const int max_iters = 50;
    for (i = 0; i < max_iters; i++) {
        rc = SN_Client_WillMsgUpdate(&g_client, will);
        if (rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }
    return rc;
}

/* Shared body for the #3138 WILLMSGUPD scrub tests. Drives a scripted
 * SN_Client_WillMsgUpdate exchange (with `continues` MQTT_CODE_CONTINUE armed
 * before the WILLMSGRESP) and asserts the updated will payload is scrubbed from
 * tx_buf once the WILLMSGUPD has been sent. Mirrors sn_will_scrub_check, but for
 * the standalone will-message update API rather than the connect handshake. */
static void sn_will_msg_update_scrub_check(int continues)
{
    SN_Will will;
    int rc, i;
    /* A distinctive "rotated secret" payload so the scrub assertions below
     * cannot pass by coincidence (e.g. against an already-zero buffer). */
    static const byte secret[] = "s3cret-rotated-will-payload";
    const int secretLen = (int)sizeof(secret) - 1; /* drop terminating NUL */
    /* Small WILLMSGUPD packet: 1-byte length + 1-byte type + payload. */
    const int willPktLen = 2 + secretLen;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(continues));

    mock_net_push(&g_mock, WILLMSGRESP_FRAME, (int)sizeof(WILLMSGRESP_FRAME));

    XMEMSET(&will, 0, sizeof(will));
    will.qos = 0;
    will.retain = 0;
    will.willTopic = "wolf/lwt";
    will.willMsg = (byte*)secret;
    will.willMsgLen = (word16)secretLen;

    rc = sn_will_msg_update_pump(&will);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, will.resp.msgResp.return_code);

    /* Positive control: the will payload really was written to the wire, so the
     * scrub assertions below cannot pass trivially. */
    ASSERT_TRUE(sn_buf_contains(g_mock.out, g_mock.out_len,
                                secret, secretLen));

    /* Core #3138 assertion: the updated will payload must not linger anywhere in
     * the client tx buffer once the WILLMSGUPD has been sent. */
    ASSERT_FALSE(sn_buf_contains(g_client.tx_buf, g_client.tx_buf_len,
                                 secret, secretLen));

    /* Stronger boundary check: every byte of the WILLMSGUPD packet region must
     * be zero. Catches both deletion of the CLIENT_FORCE_ZERO call and an
     * xfer -> 0 mutation that turns the wipe into a no-op. */
    for (i = 0; i < willPktLen; i++) {
        if (g_client.tx_buf[i] != 0) {
            FAIL("tx_buf within WILLMSGUPD range is non-zero after update");
        }
    }

    ASSERT_NO_PENDRESP();
}

/* ============================================================================
 * SN LWT connect regression tests
 * ============================================================================ */

/* Happy path: no induced CONTINUE, frames are immediately available. This runs
 * in every SN configuration (blocking and non-blocking) and is the guard for
 * the refactored BEGIN/WAIT/HEADER state machine: a dropped FALL_THROUGH or
 * transition would break the will handshake here even in blocking builds. */
TEST(sn_connect_lwt_no_continue)
{
    SN_Connect mc;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, WILLTOPICREQ_FRAME, (int)sizeof(WILLTOPICREQ_FRAME));
    mock_net_push(&g_mock, WILLMSGREQ_FRAME,   (int)sizeof(WILLMSGREQ_FRAME));
    mock_net_push(&g_mock, CONNACK_FRAME,      (int)sizeof(CONNACK_FRAME));

    sn_will_setup_connect(&mc);

    rc = sn_connect_pump(&mc, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, mc.ack.return_code);
    /* The client sent CONNECT, WILLTOPIC and WILLMSG. */
    ASSERT_TRUE(g_mock.write_calls >= 3);
    ASSERT_NO_PENDRESP();
}

/* ============================================================================
 * SN will-payload scrub test (#3137)
 *
 * SN_WillMessage encodes the last-will payload into client->tx_buf via
 * SN_Encode_WillMsg and used to leave it there after the WILLMSG had been sent,
 * so local memory inspection could recover the will plaintext until the next
 * encode overwrote it. SN_WillMessage now scrubs tx_buf (CLIENT_FORCE_ZERO)
 * before releasing lockSend once the send completes, mirroring the
 * MqttClient_Connect credential mitigation. This runs in every SN build because
 * the scrub happens on the send-complete path regardless of WOLFMQTT_NONBLOCK.
 * ============================================================================ */
TEST(sn_will_payload_scrubbed_after_send)
{
    sn_will_scrub_check(0 /* no CONTINUE */);
}

/* ============================================================================
 * SN will-message-update scrub test (#3138)
 *
 * SN_Client_WillMsgUpdate encodes the new last-will payload into client->tx_buf
 * via SN_Encode_WillMsgUpdate and used to leave it there after the WILLMSGUPD
 * had been sent, so a local attacker could recover the rotated will plaintext
 * (until the next encode overwrote it) via memory inspection or a core dump.
 * SN_Client_WillMsgUpdate now scrubs tx_buf (CLIENT_FORCE_ZERO) before releasing
 * lockSend on both the success and short-write paths, mirroring SN_WillMessage
 * and the MqttClient_Connect credential mitigation. This runs in every SN build
 * because the scrub happens on the send path regardless of WOLFMQTT_NONBLOCK.
 * ============================================================================ */
TEST(sn_willmsgupd_payload_scrubbed_after_send)
{
    sn_will_msg_update_scrub_check(0 /* no CONTINUE */);
}

/* #3138 error-path coverage. The success-path tests above never reach the
 * rc != xfer branch because mock_write() always accepts the whole buffer, so
 * the error-path CLIENT_FORCE_ZERO (and the pendResp removal beside it) would go
 * untested. Here the mock is armed to fail the WILLMSGUPD write, forcing that
 * branch: the will payload - already encoded into tx_buf before the write failed
 * - must still be scrubbed, and the pending response removed, before the error
 * is returned. Runs in every SN build (the write failure is independent of
 * WOLFMQTT_NONBLOCK). */
TEST(sn_willmsgupd_payload_scrubbed_on_write_error)
{
    SN_Will will;
    int rc, i;
    static const byte secret[] = "s3cret-rotated-will-payload";
    const int secretLen = (int)sizeof(secret) - 1; /* drop terminating NUL */
    const int willPktLen = 2 + secretLen;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    /* Arm the mock so the WILLMSGUPD write returns a network error, forcing the
     * rc != xfer branch in SN_Client_WillMsgUpdate. */
    g_mock.write_fail_rc = MQTT_CODE_ERROR_NETWORK;

    XMEMSET(&will, 0, sizeof(will));
    will.willTopic = "wolf/lwt";
    will.willMsg = (byte*)secret;
    will.willMsgLen = (word16)secretLen;

    rc = SN_Client_WillMsgUpdate(&g_client, &will);

    /* The failed send surfaces the network error to the caller. */
    ASSERT_EQ(MQTT_CODE_ERROR_NETWORK, rc);

    /* The will payload was encoded into tx_buf before the write failed; the
     * error-path scrub must have wiped it. Deleting the rc != xfer
     * CLIENT_FORCE_ZERO leaves the plaintext here and fails these assertions. */
    ASSERT_FALSE(sn_buf_contains(g_client.tx_buf, g_client.tx_buf_len,
                                 secret, secretLen));
    for (i = 0; i < willPktLen; i++) {
        if (g_client.tx_buf[i] != 0) {
            FAIL("tx_buf within WILLMSGUPD range is non-zero after write error");
        }
    }

    /* The pending response added before the send must be removed on the error
     * path so no dangling entry is left behind. */
    ASSERT_NO_PENDRESP();
}

/* ============================================================================
 * SN subscribe pending-response lifecycle tests
 *
 * SN_Client_Subscribe registers &subscribe->pendResp in client->firstPendResp
 * (MULTITHREAD) and must remove it exactly once the SUBACK arrives. Under
 * WOLFMQTT_NONBLOCK the entry stays linked across MQTT_CODE_CONTINUE returns so
 * a reader thread can route the response - which is precisely why the caller
 * must keep retrying and must not free the subscribe object until the exchange
 * completes. These tests pin both halves of that contract: no entry is leaked
 * once subscribe finishes, and the entry IS still linked while a call is
 * in-flight (so a "remove before CONTINUE" change would be caught here).
 * ============================================================================ */

/* Happy path: SUBACK is immediately available. Runs in every SN build and
 * guards that the pending response is removed once the subscribe completes. */
TEST(sn_subscribe_no_continue)
{
    SN_Subscribe sub;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, SUBACK_FRAME, (int)sizeof(SUBACK_FRAME));

    sn_subscribe_setup(&sub);

    rc = sn_subscribe_pump(&sub, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, sub.subAck.return_code);
    ASSERT_EQ(SN_TEST_SUB_TOPIC_ID, sub.subAck.topicId);
    /* The client sent SUBSCRIBE. */
    ASSERT_TRUE(g_mock.write_calls >= 1);
    /* No pending response may be left dangling once subscribe completes. */
    ASSERT_NO_PENDRESP();
}

/* #2756: when the gateway rejects the subscription the SUBACK still decodes
 * cleanly, so SN_Client_WaitType normalizes the non-negative decode result to
 * MQTT_CODE_SUCCESS. Pre-fix SN_Client_Subscribe returned that SUCCESS verbatim
 * and a caller would wait forever for messages the gateway never delivers. The
 * function must now map a non-ACCEPTED subAck.return_code to
 * MQTT_CODE_ERROR_SUBSCRIBE_REJECTED while still leaving the raw gateway code
 * visible for diagnosis. Runs in every SN build. */
TEST(sn_subscribe_rejected)
{
    SN_Subscribe sub;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, SUBACK_REJECT_FRAME,
            (int)sizeof(SUBACK_REJECT_FRAME));

    sn_subscribe_setup(&sub);

    rc = sn_subscribe_pump(&sub, NULL);

    /* Pre-fix this returned MQTT_CODE_SUCCESS. */
    ASSERT_EQ(MQTT_CODE_ERROR_SUBSCRIBE_REJECTED, rc);
    /* The raw gateway reject code is still surfaced for the caller. */
    ASSERT_EQ(SN_RC_INVTOPICNAME, sub.subAck.return_code);
    /* The client still sent the SUBSCRIBE before the rejection came back. */
    ASSERT_TRUE(g_mock.write_calls >= 1);
    /* No pending response may be left dangling, even on the reject path. */
    ASSERT_NO_PENDRESP();
}

/* ============================================================================
 * SN publish pending-response lifecycle tests
 *
 * For QoS 1/2 SN_Client_Publish registers &publish->pendResp in
 * client->firstPendResp (MULTITHREAD) and must remove it exactly once the
 * PUBACK (QoS 1) / PUBCOMP (QoS 2) arrives. Under WOLFMQTT_NONBLOCK the entry
 * stays linked across MQTT_CODE_CONTINUE returns (the write path returns before
 * removal, and the wait path breaks before removal) so a reader thread can
 * route the response - which is exactly why the caller must keep retrying and
 * must not free the publish object until the exchange completes. The
 * sn-multithread publish_task stack-allocates SN_Publish and used to call
 * SN_Client_Publish exactly once: on a CONTINUE it returned, freeing the stack
 * frame while &publish->pendResp was still linked, and the concurrent
 * waitMessage_task / ping_task threads dereferenced the dangling entry
 * (use-after-free). These tests pin both halves of the contract: no entry is
 * leaked once publish finishes, and the entry IS still linked (pointing back
 * into the caller's object) while a call is in-flight.
 * ============================================================================ */

/* Happy path, QoS 1: PUBACK is immediately available. Runs in every SN build
 * and guards that the pending response is removed once the publish completes. */
TEST(sn_publish_qos1_no_continue)
{
    SN_Publish pub;
    word16 topicId = SN_TEST_PUB_TOPIC_ID;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, PUBACK_FRAME, (int)sizeof(PUBACK_FRAME));

    sn_publish_setup(&pub, &topicId, MQTT_QOS_1);

    rc = sn_publish_pump(&pub, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, pub.return_code);
    /* The client sent the PUBLISH. */
    ASSERT_TRUE(g_mock.write_calls >= 1);
    /* No pending response may be left dangling once publish completes. */
    ASSERT_NO_PENDRESP();
}

/* Happy path, QoS 2: the gateway answers PUBREC then PUBCOMP. The client must
 * send PUBREL in between (so >= 2 writes) and converge to SUCCESS with no
 * dangling pending response. Runs in every SN build. */
TEST(sn_publish_qos2_no_continue)
{
    SN_Publish pub;
    word16 topicId = SN_TEST_PUB_TOPIC_ID;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, PUBREC_FRAME,  (int)sizeof(PUBREC_FRAME));
    mock_net_push(&g_mock, PUBCOMP_FRAME, (int)sizeof(PUBCOMP_FRAME));

    sn_publish_setup(&pub, &topicId, MQTT_QOS_2);

    rc = sn_publish_pump(&pub, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    /* PUBLISH plus the PUBREL sent in response to PUBREC. */
    ASSERT_TRUE(g_mock.write_calls >= 2);
    /* Both gateway frames consumed. */
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);
    ASSERT_NO_PENDRESP();
}

/* QoS 0 publish expects no ACK, so SN_Client_Publish must never register a
 * pending response: it completes after the write with nothing left on the
 * respList. Guards that the no-ACK path cannot leak an entry. Runs in every
 * SN build. */
TEST(sn_publish_qos0_no_pendresp)
{
    SN_Publish pub;
    word16 topicId = SN_TEST_PUB_TOPIC_ID;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    sn_publish_setup(&pub, &topicId, MQTT_QOS_0);

    rc = sn_publish_pump(&pub, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    /* The client sent the PUBLISH. */
    ASSERT_TRUE(g_mock.write_calls >= 1);
    /* A QoS 0 publish never adds a pending response. */
    ASSERT_NO_PENDRESP();
}

/* ============================================================================
 * SN unsubscribe pending-response lifecycle tests (#6047)
 *
 * SN_Client_Unsubscribe registers &unsubscribe->pendResp in
 * client->firstPendResp (MULTITHREAD) so a reader thread can route the UNSUBACK
 * back to the unsubscribing thread. The entry must be keyed by the real Packet
 * Identifier: MqttClient_RespList_Find matches on (packet_type, packet_id), and
 * an UNSUBACK echoes the MsgId that SN_Decode_UnsubscribeAck recovers as the
 * non-zero packet_id. Pre-fix the entry was added with a hard-coded id of 0, so
 * a reader thread's RespList_Find(UNSUBACK, real_id) never matched and the
 * UNSUBACK was swallowed into the generic object, leaving the unsubscribing
 * thread blocked until cmd_timeout_ms. The same-thread case was masked because
 * SN_Client_WaitType also matches directly on wait_packet_id, so the
 * cross-thread test below is the one that pins the fix.
 * ============================================================================ */

/* Happy path: UNSUBACK is immediately available and read by the unsubscribing
 * call itself. Runs in every SN build and guards that the pending response is
 * removed once the unsubscribe completes. */
TEST(sn_unsubscribe_no_continue)
{
    SN_Unsubscribe unsub;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, UNSUBACK_FRAME, (int)sizeof(UNSUBACK_FRAME));

    sn_unsubscribe_setup(&unsub);

    rc = sn_unsubscribe_pump(&unsub, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_TEST_UNSUB_PACKET_ID, unsub.ack.packet_id);
    /* The client sent UNSUBSCRIBE. */
    ASSERT_TRUE(g_mock.write_calls >= 1);
    /* No pending response may be left dangling once unsubscribe completes. */
    ASSERT_NO_PENDRESP();
}

/* ============================================================================
 * SN incoming-PUBLISH with no message callback (#6217)
 *
 * The SN test harness initializes the client with a NULL msg_cb. An SN client
 * that receives a PUBLISH used to decode and discard it, return success, and
 * (for QoS>0) send a PUBACK/PUBREC falsely confirming delivery to the gateway.
 * SN_Client_HandlePacket now returns MQTT_CODE_ERROR_CALLBACK when no callback
 * is registered, so the message is reported as undeliverable and not ACKed.
 * Runs in every SN build (the fix is independent of NONBLOCK/MULTITHREAD).
 * ============================================================================ */
TEST(sn_publish_incoming_null_msg_cb_errors_no_ack)
{
    int rc, i;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, SN_PUBLISH_QOS1_FRAME,
            (int)sizeof(SN_PUBLISH_QOS1_FRAME));

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 20 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = SN_Client_WaitMessage(&g_client, 1000);
    }

    /* Pre-fix this returned MQTT_CODE_SUCCESS. */
    ASSERT_EQ(MQTT_CODE_ERROR_CALLBACK, rc);
    /* The gateway must NOT be told the QoS1 message was delivered: pre-fix a
     * PUBACK was written here, falsely confirming a dropped message. */
    ASSERT_EQ(0, g_mock.write_calls);
}

/* The non-blocking retry behavior is the actual regression and only applies
 * when WOLFMQTT_NONBLOCK is built (otherwise SN_Client_WaitType blocks and
 * never returns MQTT_CODE_CONTINUE). */
#ifdef WOLFMQTT_NONBLOCK

/* The headline regression: with a CONTINUE armed before every gateway frame
 * the connect must still converge to SUCCESS and never surface BAD_ARG from a
 * duplicate pending-response add. */
TEST(sn_connect_lwt_nonblock_retry)
{
    SN_Connect mc;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1 /* one CONTINUE per frame */));

    mock_net_push(&g_mock, WILLTOPICREQ_FRAME, (int)sizeof(WILLTOPICREQ_FRAME));
    mock_net_push(&g_mock, WILLMSGREQ_FRAME,   (int)sizeof(WILLMSGREQ_FRAME));
    mock_net_push(&g_mock, CONNACK_FRAME,      (int)sizeof(CONNACK_FRAME));

    sn_will_setup_connect(&mc);

    rc = sn_connect_pump(&mc, &iters);

    /* Pre-fix this returned MQTT_CODE_ERROR_BAD_ARG on the second call. */
    ASSERT_NE(MQTT_CODE_ERROR_BAD_ARG, rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, mc.ack.return_code);

    /* All three gateway frames were consumed and we re-entered at least once
     * per frame (proving the non-blocking retry path was actually taken). */
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);
    ASSERT_TRUE(iters >= 4);

    /* The client sent CONNECT, WILLTOPIC and WILLMSG. */
    ASSERT_TRUE(g_mock.write_calls >= 3);

    /* No pending response may be left dangling once connect completes. */
    ASSERT_NO_PENDRESP();
}

/* With multiple CONTINUE results armed before each frame the connect must
 * still converge: the wait states resume rather than re-adding their pending
 * response, regardless of how many times the application re-enters. */
TEST(sn_connect_lwt_many_continues)
{
    SN_Connect mc;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(3 /* three CONTINUE per frame */));

    mock_net_push(&g_mock, WILLTOPICREQ_FRAME, (int)sizeof(WILLTOPICREQ_FRAME));
    mock_net_push(&g_mock, WILLMSGREQ_FRAME,   (int)sizeof(WILLMSGREQ_FRAME));
    mock_net_push(&g_mock, CONNACK_FRAME,      (int)sizeof(CONNACK_FRAME));

    sn_will_setup_connect(&mc);

    rc = sn_connect_pump(&mc, &iters);

    ASSERT_NE(MQTT_CODE_ERROR_BAD_ARG, rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_NO_PENDRESP();
}

/* Reusing the same client/connect struct for a second connect must work: the
 * will write-state and will_done must have been reset so the second handshake
 * adds its pending responses cleanly. */
TEST(sn_connect_lwt_reconnect)
{
    SN_Connect mc;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1));

    /* First connect. */
    mock_net_push(&g_mock, WILLTOPICREQ_FRAME, (int)sizeof(WILLTOPICREQ_FRAME));
    mock_net_push(&g_mock, WILLMSGREQ_FRAME,   (int)sizeof(WILLMSGREQ_FRAME));
    mock_net_push(&g_mock, CONNACK_FRAME,      (int)sizeof(CONNACK_FRAME));
    sn_will_setup_connect(&mc);
    rc = sn_connect_pump(&mc, NULL);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_NO_PENDRESP();

    /* Re-arm the gateway and connect again with the same struct. */
    g_mock.in_count = 0;
    g_mock.in_idx = 0;
    g_mock.in_off = 0;
    g_mock.continues = g_mock.continues_cfg;
    mock_net_push(&g_mock, WILLTOPICREQ_FRAME, (int)sizeof(WILLTOPICREQ_FRAME));
    mock_net_push(&g_mock, WILLMSGREQ_FRAME,   (int)sizeof(WILLMSGREQ_FRAME));
    mock_net_push(&g_mock, CONNACK_FRAME,      (int)sizeof(CONNACK_FRAME));

    rc = sn_connect_pump(&mc, NULL);
    ASSERT_NE(MQTT_CODE_ERROR_BAD_ARG, rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_NO_PENDRESP();
}

/* #3137 through the non-blocking retry path: with a CONTINUE armed before each
 * gateway frame the will payload must still be scrubbed from tx_buf once the
 * connect completes. */
TEST(sn_will_payload_scrubbed_nonblock)
{
    sn_will_scrub_check(1 /* one CONTINUE per frame */);
}

/* #3138 through the non-blocking retry path: with a CONTINUE armed before the
 * WILLMSGRESP the updated will payload must still be scrubbed from tx_buf once
 * the update completes. The scrub happens on the send-complete path (before the
 * wait re-enters), so re-entry after CONTINUE must not resurrect the plaintext. */
TEST(sn_willmsgupd_payload_scrubbed_nonblock)
{
    sn_will_msg_update_scrub_check(1 /* one CONTINUE per frame */);
}

/* The headline regression. With a CONTINUE armed before the SUBACK the
 * subscribe must converge to SUCCESS and remove its pending response exactly
 * once. Under MULTITHREAD it also pins the dangling-pointer contract directly:
 * after the first in-flight CONTINUE the entry IS linked and points back into
 * the caller's subscribe object - the exact pointer the sn-multithread
 * subscribe_task used to abandon (freeing the stack frame) by returning on
 * CONTINUE instead of retrying. */
TEST(sn_subscribe_nonblock_pendresp_lifecycle)
{
    SN_Subscribe sub;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1 /* one CONTINUE per frame */));

    mock_net_push(&g_mock, SUBACK_FRAME, (int)sizeof(SUBACK_FRAME));

    sn_subscribe_setup(&sub);

    /* First call sends SUBSCRIBE and the armed CONTINUE forces an in-flight
     * return before the SUBACK is delivered. */
    rc = SN_Client_Subscribe(&g_client, &sub);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);
#ifdef WOLFMQTT_MULTITHREAD
    /* The pending response must stay registered while the exchange is in
     * flight (so a reader thread could route the SUBACK) and must point back
     * into the caller-owned object. This is the entry that becomes a dangling
     * pointer if the caller returns/frees the object instead of retrying. */
    ASSERT_NOT_NULL(g_client.firstPendResp);
    ASSERT_EQ((void*)&sub.pendResp, (void*)g_client.firstPendResp);
#endif

    /* Keep retrying, as a correct non-blocking caller must, until it resolves.*/
    rc = sn_subscribe_pump(&sub, &iters);

    /* Pre-fix subscribe_task would have returned on the CONTINUE above. */
    ASSERT_NE(MQTT_CODE_ERROR_BAD_ARG, rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, sub.subAck.return_code);
    ASSERT_EQ(SN_TEST_SUB_TOPIC_ID, sub.subAck.topicId);

    /* All scripted frames consumed and the non-blocking retry path was taken. */
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);

    /* The pending response is gone once subscribe completes - no dangling
     * entry remains for another thread to dereference. */
    ASSERT_NO_PENDRESP();
}

/* With multiple CONTINUE results armed before the SUBACK the subscribe must
 * still converge: repeated re-entry resumes the wait rather than re-adding the
 * pending response (which would surface MQTT_CODE_ERROR_BAD_ARG as a duplicate).
 */
TEST(sn_subscribe_many_continues)
{
    SN_Subscribe sub;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(3 /* three CONTINUE per frame */));

    mock_net_push(&g_mock, SUBACK_FRAME, (int)sizeof(SUBACK_FRAME));

    sn_subscribe_setup(&sub);

    rc = sn_subscribe_pump(&sub, &iters);

    ASSERT_NE(MQTT_CODE_ERROR_BAD_ARG, rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, sub.subAck.return_code);
    ASSERT_TRUE(iters >= 2);
    ASSERT_NO_PENDRESP();
}

/* #2756 through the non-blocking retry path: a rejected SUBACK arriving after a
 * CONTINUE must still resolve to MQTT_CODE_ERROR_SUBSCRIBE_REJECTED. The
 * rejection mapping must run only once the wait converges - the in-flight
 * CONTINUE is returned verbatim and must never be turned into a rejection. */
TEST(sn_subscribe_rejected_nonblock)
{
    SN_Subscribe sub;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1 /* one CONTINUE per frame */));

    mock_net_push(&g_mock, SUBACK_REJECT_FRAME,
            (int)sizeof(SUBACK_REJECT_FRAME));

    sn_subscribe_setup(&sub);

    /* The armed CONTINUE forces an in-flight return before the SUBACK arrives;
     * it must be surfaced as CONTINUE, not prematurely mapped to a rejection. */
    rc = SN_Client_Subscribe(&g_client, &sub);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* Keep retrying until the rejected SUBACK is delivered and resolved. */
    rc = sn_subscribe_pump(&sub, &iters);

    ASSERT_EQ(MQTT_CODE_ERROR_SUBSCRIBE_REJECTED, rc);
    ASSERT_EQ(SN_RC_INVTOPICNAME, sub.subAck.return_code);
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);
    ASSERT_NO_PENDRESP();
}

/* The headline regression. With a CONTINUE armed before the PUBACK the
 * QoS 1 publish must converge to SUCCESS and remove its pending response exactly
 * once. Under MULTITHREAD it also pins the dangling-pointer contract directly:
 * after the first in-flight CONTINUE the entry IS linked and points back into
 * the caller's publish object - the exact pointer the sn-multithread
 * publish_task used to abandon (freeing the stack frame) by returning on
 * CONTINUE instead of retrying. */
TEST(sn_publish_qos1_nonblock_pendresp_lifecycle)
{
    SN_Publish pub;
    word16 topicId = SN_TEST_PUB_TOPIC_ID;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1 /* one CONTINUE per frame */));

    mock_net_push(&g_mock, PUBACK_FRAME, (int)sizeof(PUBACK_FRAME));

    sn_publish_setup(&pub, &topicId, MQTT_QOS_1);

    /* First call sends PUBLISH and the armed CONTINUE forces an in-flight
     * return before the PUBACK is delivered. */
    rc = SN_Client_Publish(&g_client, &pub);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);
#ifdef WOLFMQTT_MULTITHREAD
    /* The pending response must stay registered while the exchange is in
     * flight (so a reader thread could route the PUBACK) and must point back
     * into the caller-owned object. This is the entry that becomes a dangling
     * pointer if the caller returns/frees the object instead of retrying. */
    ASSERT_NOT_NULL(g_client.firstPendResp);
    ASSERT_EQ((void*)&pub.pendResp, (void*)g_client.firstPendResp);
#endif

    /* Keep retrying, as a correct non-blocking caller must, until it resolves.*/
    rc = sn_publish_pump(&pub, &iters);

    /* Pre-fix publish_task would have returned on the CONTINUE above. */
    ASSERT_NE(MQTT_CODE_ERROR_BAD_ARG, rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, pub.return_code);

    /* All scripted frames consumed and the non-blocking retry path was taken. */
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);

    /* The pending response is gone once publish completes - no dangling entry
     * remains for another thread to dereference. */
    ASSERT_NO_PENDRESP();
}

/* With multiple CONTINUE results armed before the PUBACK the publish must still
 * converge: repeated re-entry resumes the wait rather than re-adding the pending
 * response (which would surface MQTT_CODE_ERROR_BAD_ARG as a duplicate). */
TEST(sn_publish_qos1_many_continues)
{
    SN_Publish pub;
    word16 topicId = SN_TEST_PUB_TOPIC_ID;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(3 /* three CONTINUE per frame */));

    mock_net_push(&g_mock, PUBACK_FRAME, (int)sizeof(PUBACK_FRAME));

    sn_publish_setup(&pub, &topicId, MQTT_QOS_1);

    rc = sn_publish_pump(&pub, &iters);

    ASSERT_NE(MQTT_CODE_ERROR_BAD_ARG, rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_RC_ACCEPTED, pub.return_code);
    ASSERT_TRUE(iters >= 2);
    ASSERT_NO_PENDRESP();
}

/* #6047 headline regression: cross-thread UNSUBACK routing. The unsubscribing
 * thread arms a pending response and returns in-flight (CONTINUE) before the
 * UNSUBACK arrives, then a separate reader thread (modeled by
 * SN_Client_WaitMessage) consumes it. The fix registers the pending response
 * under the real packet_id, so the reader's RespList_Find(UNSUBACK, real_id)
 * matches and routes the UNSUBACK back to the unsubscribing thread; pre-fix the
 * entry was keyed by id 0, so the match failed and the unsubscribe never
 * resolved. Needs MULTITHREAD (the respList routing and firstPendResp only exist
 * there) on top of NONBLOCK (to interleave the reader between the unsubscribing
 * thread's send and wait within a single test thread). */
#ifdef WOLFMQTT_MULTITHREAD
TEST(sn_unsubscribe_crossthread_unsuback_routing)
{
    SN_Unsubscribe unsub;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1 /* one CONTINUE per frame */));

    mock_net_push(&g_mock, UNSUBACK_FRAME, (int)sizeof(UNSUBACK_FRAME));

    sn_unsubscribe_setup(&unsub);

    /* First call sends UNSUBSCRIBE and registers the pending UNSUBACK response.
     * The armed CONTINUE forces an in-flight return before the UNSUBACK is read,
     * so the unsubscribing thread leaves without consuming it. */
    rc = SN_Client_Unsubscribe(&g_client, &unsub);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* The pending response must be keyed by the real packet_id so a reader
     * thread can route the UNSUBACK to it. Pre-fix it was added under id 0. */
    ASSERT_NOT_NULL(g_client.firstPendResp);
    ASSERT_EQ(SN_TEST_UNSUB_PACKET_ID, g_client.firstPendResp->packet_id);

    /* Model a separate reader thread (waitMessage_task) consuming the UNSUBACK
     * via the generic wait path. With the fix the UNSUBACK is matched by type+id
     * to the registered pending response, handled into the unsubscribing
     * thread's ack object, and the entry is marked done; the read therefore
     * belongs to another thread and returns CONTINUE here. Pre-fix the id-0
     * entry never matched the real id, so the UNSUBACK was swallowed into the
     * reader's generic object and the entry was left pending. */
    rc = SN_Client_WaitMessage(&g_client, 1000);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* The unsubscribing thread resumes. With the fix CheckPendResp finds the
     * entry already marked done and returns SUCCESS without another read.
     * Pre-fix the entry is still pending (the UNSUBACK was swallowed), so this
     * would spin on CONTINUE and never resolve. */
    rc = sn_unsubscribe_pump(&unsub, &iters);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(SN_TEST_UNSUB_PACKET_ID, unsub.ack.packet_id);

    /* The reader consumed the only UNSUBACK frame and no pending response is
     * left dangling once the unsubscribe completes. */
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);
    ASSERT_NO_PENDRESP();
}
#endif /* WOLFMQTT_MULTITHREAD */

#endif /* WOLFMQTT_NONBLOCK */

/* ============================================================================
 * SN ping pending-response lifecycle tests (use-after-scope regression, #3132)
 *
 * SN_Client_Ping accepts a NULL 'ping' and falls back to a function-local
 * SN_PingReq (loc_ping) on the stack. Under WOLFMQTT_MULTITHREAD it registers
 * &ping->pendResp on client->firstPendResp. Under WOLFMQTT_NONBLOCK an in-flight
 * MQTT_CODE_CONTINUE used to be returned verbatim - which, for the NULL
 * fallback, left &loc_ping.pendResp linked on the respList after the stack frame
 * unwound. A later call reused the stack address, so the stale entry could be
 * dereferenced by the receive path (use-after-scope). The fix removes the entry
 * before any CONTINUE return for the NULL fallback, while a caller-owned object
 * (which persists across calls) still keeps its entry linked so it can resume.
 * These tests pin both halves of that contract.
 * ============================================================================ */

/* Happy path with a caller-owned ping: PINGRESP is immediately available. Runs
 * in every SN build and guards that the pending response is removed once the
 * ping completes. */
TEST(sn_ping_no_continue)
{
    SN_PingReq ping;
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, PINGRESP_FRAME, (int)sizeof(PINGRESP_FRAME));

    XMEMSET(&ping, 0, sizeof(ping));

    rc = sn_ping_pump(&ping, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    /* The client sent PINGREQ. */
    ASSERT_TRUE(g_mock.write_calls >= 1);
    /* No pending response may be left dangling once the ping completes. */
    ASSERT_NO_PENDRESP();
}

/* Happy path with ping==NULL: exercises the internal loc_ping fallback. Runs in
 * every SN build and guards that the fallback's pending response is removed once
 * the ping completes (no entry leaked for a blocking single-call ping). */
TEST(sn_ping_null_no_continue)
{
    int rc;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(0 /* no CONTINUE */));

    mock_net_push(&g_mock, PINGRESP_FRAME, (int)sizeof(PINGRESP_FRAME));

    rc = sn_ping_pump(NULL, NULL);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_TRUE(g_mock.write_calls >= 1);
    ASSERT_NO_PENDRESP();
}

/* The non-blocking dangling-pointer regression only manifests under
 * WOLFMQTT_NONBLOCK (otherwise SN_Client_WaitType blocks and never returns
 * MQTT_CODE_CONTINUE, so the early-return path that leaked the entry is never
 * taken). */
#ifdef WOLFMQTT_NONBLOCK

/* The headline #3132 regression. With a CONTINUE armed before the PINGRESP, a
 * ping==NULL call returns in-flight while &loc_ping.pendResp would (pre-fix)
 * still be linked - a pointer into the now-dead stack frame. Under MULTITHREAD
 * this pins the dangling-pointer contract directly: after the in-flight CONTINUE
 * NO pending response may remain. The retry must still converge to SUCCESS. */
TEST(sn_ping_null_nonblock_no_dangling_pendresp)
{
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1 /* one CONTINUE per frame */));

    mock_net_push(&g_mock, PINGRESP_FRAME, (int)sizeof(PINGRESP_FRAME));

    /* First call sends PINGREQ and the armed CONTINUE forces an in-flight return
     * before the PINGRESP is delivered. With ping==NULL the request is built on
     * a stack-local SN_PingReq that does not survive this return. */
    rc = SN_Client_Ping(&g_client, NULL);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);
#ifdef WOLFMQTT_MULTITHREAD
    /* Pre-fix &loc_ping.pendResp was left linked on the client respList here and
     * dangled once SN_Client_Ping returned. The fix removes it before the
     * CONTINUE return for the NULL fallback, so no entry may remain. */
    ASSERT_NULL(g_client.firstPendResp);
#endif

    /* A correct non-blocking caller keeps retrying until the ping resolves. */
    rc = sn_ping_pump(NULL, &iters);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    /* All scripted frames consumed and no dangling entry remains. */
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);
    ASSERT_NO_PENDRESP();
}

/* The complementary half of the contract: for a caller-owned ping the pending
 * response MUST stay linked across an in-flight CONTINUE (so a reader thread can
 * route the PINGRESP and the wait can resume), and must point back into the
 * caller's object. A "remove before every CONTINUE" change would be caught here.
 */
TEST(sn_ping_nonblock_pendresp_lifecycle)
{
    SN_PingReq ping;
    int rc, iters = 0;

    ASSERT_EQ(MQTT_CODE_SUCCESS, sn_client_init(1 /* one CONTINUE per frame */));

    mock_net_push(&g_mock, PINGRESP_FRAME, (int)sizeof(PINGRESP_FRAME));

    XMEMSET(&ping, 0, sizeof(ping));

    /* First call sends PINGREQ; the armed CONTINUE forces an in-flight return
     * before the PINGRESP is delivered. */
    rc = SN_Client_Ping(&g_client, &ping);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);
#ifdef WOLFMQTT_MULTITHREAD
    /* The entry stays registered while the exchange is in flight and points back
     * into the caller-owned object - the fix must NOT remove it here (only the
     * stack-local NULL fallback is cleaned up on CONTINUE). */
    ASSERT_NOT_NULL(g_client.firstPendResp);
    ASSERT_EQ((void*)&ping.pendResp, (void*)g_client.firstPendResp);
#endif

    /* Resume until the PINGRESP is delivered and the ping resolves. */
    rc = sn_ping_pump(&ping, &iters);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(g_mock.in_count, g_mock.in_idx);
    /* The pending response is gone once the ping completes - no dangling entry
     * remains for another thread to dereference. */
    ASSERT_NO_PENDRESP();
}

#endif /* WOLFMQTT_NONBLOCK */

#endif /* WOLFMQTT_SN */

/* ============================================================================
 * Suite runner
 * ============================================================================ */

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    TEST_RUNNER_BEGIN();

#ifdef WOLFMQTT_SN
    TEST_SUITE_BEGIN("mqtt_sn_client", setup, teardown);

    /* Happy path runs in every SN build (blocking and non-blocking). */
    RUN_TEST(sn_connect_lwt_no_continue);
    RUN_TEST(sn_will_payload_scrubbed_after_send);
    RUN_TEST(sn_willmsgupd_payload_scrubbed_after_send);
    RUN_TEST(sn_willmsgupd_payload_scrubbed_on_write_error);
    RUN_TEST(sn_subscribe_no_continue);
    RUN_TEST(sn_subscribe_rejected);
    RUN_TEST(sn_publish_qos1_no_continue);
    RUN_TEST(sn_publish_qos2_no_continue);
    RUN_TEST(sn_publish_qos0_no_pendresp);
    RUN_TEST(sn_unsubscribe_no_continue);
    RUN_TEST(sn_publish_incoming_null_msg_cb_errors_no_ack);
    RUN_TEST(sn_ping_no_continue);
    RUN_TEST(sn_ping_null_no_continue);

    /* The non-blocking retry regression only exists under WOLFMQTT_NONBLOCK. */
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(sn_connect_lwt_nonblock_retry);
    RUN_TEST(sn_connect_lwt_many_continues);
    RUN_TEST(sn_connect_lwt_reconnect);
    RUN_TEST(sn_will_payload_scrubbed_nonblock);
    RUN_TEST(sn_willmsgupd_payload_scrubbed_nonblock);
    RUN_TEST(sn_subscribe_nonblock_pendresp_lifecycle);
    RUN_TEST(sn_subscribe_many_continues);
    RUN_TEST(sn_subscribe_rejected_nonblock);
    RUN_TEST(sn_publish_qos1_nonblock_pendresp_lifecycle);
    RUN_TEST(sn_publish_qos1_many_continues);
#ifdef WOLFMQTT_MULTITHREAD
    RUN_TEST(sn_unsubscribe_crossthread_unsuback_routing);
#endif
    RUN_TEST(sn_ping_null_nonblock_no_dangling_pendresp);
    RUN_TEST(sn_ping_nonblock_pendresp_lifecycle);
#endif

    TEST_SUITE_END();
#else
    PRINTF("test_mqtt_sn_client: skipped (requires WOLFMQTT_SN)");
#endif

    TEST_RUNNER_END();
}
