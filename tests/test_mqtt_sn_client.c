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
        *iters = i + 1;
    }
    return rc;
}

static void setup(void)    { }
static void teardown(void)
{
    MqttClient_DeInit(&g_client);
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

    /* The non-blocking retry regression only exists under WOLFMQTT_NONBLOCK. */
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(sn_connect_lwt_nonblock_retry);
    RUN_TEST(sn_connect_lwt_many_continues);
    RUN_TEST(sn_connect_lwt_reconnect);
#endif

    TEST_SUITE_END();
#else
    PRINTF("test_mqtt_sn_client: skipped (requires WOLFMQTT_SN)");
#endif

    TEST_RUNNER_END();
}
