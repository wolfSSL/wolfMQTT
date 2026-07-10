/* test_mqtt_client.c
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

#include "wolfmqtt/mqtt_client.h"
#include "tests/unit_test.h"

void run_mqtt_client_tests(void);

/* ============================================================================
 * Test Fixtures
 * ============================================================================ */

#define TEST_TX_BUF_SIZE 256
#define TEST_RX_BUF_SIZE 256
#define TEST_CMD_TIMEOUT_MS 1000

static MqttClient test_client;
static MqttNet test_net;
static byte test_tx_buf[TEST_TX_BUF_SIZE];
static byte test_rx_buf[TEST_RX_BUF_SIZE];

/* Mock network callbacks - just return errors since we're not actually
 * connecting to anything */
static int mock_net_connect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    (void)context; (void)host; (void)port; (void)timeout_ms;
    return MQTT_CODE_ERROR_NETWORK;
}

static int mock_net_read(void *context, byte* buf, int buf_len, int timeout_ms)
{
    (void)context; (void)buf; (void)buf_len; (void)timeout_ms;
    return MQTT_CODE_ERROR_NETWORK;
}

static int mock_net_write(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    (void)context; (void)buf; (void)buf_len; (void)timeout_ms;
    return MQTT_CODE_ERROR_NETWORK;
}

static int mock_net_disconnect(void *context)
{
    (void)context;
    return MQTT_CODE_SUCCESS;
}

static int test_client_inited;

static void setup(void)
{
    XMEMSET(&test_client, 0, sizeof(test_client));
    XMEMSET(&test_net, 0, sizeof(test_net));
    XMEMSET(test_tx_buf, 0, sizeof(test_tx_buf));
    XMEMSET(test_rx_buf, 0, sizeof(test_rx_buf));
    test_client_inited = 0;

    /* Setup mock network callbacks */
    test_net.connect = mock_net_connect;
    test_net.read = mock_net_read;
    test_net.write = mock_net_write;
    test_net.disconnect = mock_net_disconnect;
}

static void teardown(void)
{
    /* Only DeInit if Init succeeded - DeInit calls MqttProps_ShutDown
     * which decrements a ref counter that must be balanced with Init. */
    if (test_client_inited) {
        MqttClient_DeInit(&test_client);
    }
}

static int test_init_client(void)
{
    int rc = MqttClient_Init(&test_client, &test_net, NULL,
                             test_tx_buf, TEST_TX_BUF_SIZE,
                             test_rx_buf, TEST_RX_BUF_SIZE,
                             TEST_CMD_TIMEOUT_MS);
    if (rc == MQTT_CODE_SUCCESS) {
        test_client_inited = 1;
    }
    return rc;
}

/* ============================================================================
 * MqttClient_Init Tests
 * ============================================================================ */

TEST(init_null_client)
{
    int rc;

    rc = MqttClient_Init(NULL, &test_net, NULL,
                         test_tx_buf, TEST_TX_BUF_SIZE,
                         test_rx_buf, TEST_RX_BUF_SIZE,
                         TEST_CMD_TIMEOUT_MS);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(init_null_tx_buf)
{
    int rc;

    rc = MqttClient_Init(&test_client, &test_net, NULL,
                         NULL, TEST_TX_BUF_SIZE,
                         test_rx_buf, TEST_RX_BUF_SIZE,
                         TEST_CMD_TIMEOUT_MS);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(init_zero_tx_buf_len)
{
    int rc;

    rc = MqttClient_Init(&test_client, &test_net, NULL,
                         test_tx_buf, 0,
                         test_rx_buf, TEST_RX_BUF_SIZE,
                         TEST_CMD_TIMEOUT_MS);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(init_null_rx_buf)
{
    int rc;

    rc = MqttClient_Init(&test_client, &test_net, NULL,
                         test_tx_buf, TEST_TX_BUF_SIZE,
                         NULL, TEST_RX_BUF_SIZE,
                         TEST_CMD_TIMEOUT_MS);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(init_zero_rx_buf_len)
{
    int rc;

    rc = MqttClient_Init(&test_client, &test_net, NULL,
                         test_tx_buf, TEST_TX_BUF_SIZE,
                         test_rx_buf, 0,
                         TEST_CMD_TIMEOUT_MS);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(init_success)
{
    int rc;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    /* Verify client structure is set up correctly */
    ASSERT_TRUE(test_client.tx_buf == test_tx_buf);
    ASSERT_EQ(TEST_TX_BUF_SIZE, test_client.tx_buf_len);
    ASSERT_TRUE(test_client.rx_buf == test_rx_buf);
    ASSERT_EQ(TEST_RX_BUF_SIZE, test_client.rx_buf_len);
    ASSERT_EQ(TEST_CMD_TIMEOUT_MS, test_client.cmd_timeout_ms);
}

TEST(init_negative_tx_buf_len)
{
    int rc;

    rc = MqttClient_Init(&test_client, &test_net, NULL,
                         test_tx_buf, -1,
                         test_rx_buf, TEST_RX_BUF_SIZE,
                         TEST_CMD_TIMEOUT_MS);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(init_negative_rx_buf_len)
{
    int rc;

    rc = MqttClient_Init(&test_client, &test_net, NULL,
                         test_tx_buf, TEST_TX_BUF_SIZE,
                         test_rx_buf, -1,
                         TEST_CMD_TIMEOUT_MS);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * MqttClient_DeInit Tests
 * ============================================================================ */

TEST(deinit_null_client)
{
    /* MqttClient_DeInit(NULL) still calls MqttProps_ShutDown() under
     * WOLFMQTT_V5, which decrements a refcount. Pair it with MqttProps_Init()
     * so the refcount stays balanced across test runs. */
#ifdef WOLFMQTT_V5
    (void)MqttProps_Init();
#endif
    /* Should not crash with NULL client */
    MqttClient_DeInit(NULL);
    /* If we reach here, test passes */
    ASSERT_TRUE(1);
}

TEST(deinit_after_init)
{
    int rc;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    /* DeInit should not crash */
    MqttClient_DeInit(&test_client);
    test_client_inited = 0;
    ASSERT_TRUE(1);
}

/* ============================================================================
 * MqttClient_Connect Tests
 * ============================================================================ */

TEST(connect_null_client)
{
    int rc;
    MqttConnect connect;

    XMEMSET(&connect, 0, sizeof(connect));

    rc = MqttClient_Connect(NULL, &connect);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(connect_null_connect)
{
    int rc;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    rc = MqttClient_Connect(&test_client, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(connect_both_null)
{
    int rc;

    rc = MqttClient_Connect(NULL, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(connect_with_mock_network)
{
    int rc;
    MqttConnect connect;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";

    /* Connect will fail at the network write stage since mock returns error */
    rc = MqttClient_Connect(&test_client, &connect);
    /* Should fail with network error since mock network write returns error */
    ASSERT_EQ(MQTT_CODE_ERROR_NETWORK, rc);
}

/* Regression test for tx_buf credential zeroing after CONNECT is sent.
 * Guards CLIENT_FORCE_ZERO(client->tx_buf, xfer) in MqttClient_Connect: the
 * original issue being prevented is plaintext credentials lingering in the
 * client's tx_buf after the CONNECT packet is written. Without this test, a
 * regression that deletes that line (or passes length 0) would pass silently. */
#define TEST_CONNECT_USERNAME "user"
#define TEST_CONNECT_PASSWORD "secret"

static int connect_mock_xfer;
static byte connect_mock_sent[TEST_TX_BUF_SIZE];

/* Set when a PUBREL (fixed header type 6) is written, so tests can assert the
 * QoS 2 handshake either did or did not emit one. */
static int g_pubrel_written;

/* Set when a PUBACK (type 4) or PUBREC (type 5) is written, so tests can assert
 * that an incoming QoS>0 PUBLISH was (or was not) acknowledged to the broker. */
static int g_pubresp_written;

/* Records the fixed-header packet type (4..7) of the most recent PUBLISH
 * response frame written to the wire, or MQTT_PACKET_TYPE_RESERVED when none was
 * written. Lets a test assert exactly which QoS acknowledgement (if any)
 * MqttClient_HandlePacket emitted for an incoming PUBLISH response. */
static int g_last_ack_written;

/* Counts every frame the client writes to the wire, of any type. A "no ack"
 * test asserts this stayed zero, which is stronger than only checking that no
 * known ack type was recorded: it also catches a frame whose type falls outside
 * the 4..7 range that g_last_ack_written tracks. */
static int g_frames_written;

/* Packet id carried by the most recent PUBLISH-response frame written to the
 * wire. For a v3.1.1 ack the two-byte id sits right after the fixed header, so a
 * test can confirm the client echoed the id of the PUBLISH it is acknowledging. */
static int g_last_ack_id;

static int mock_net_write_accept(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    byte ack_type;
    (void)context; (void)timeout_ms;
    if (buf != NULL && buf_len > 0) {
        ack_type = (byte)((buf[0] & 0xF0) >> 4);

        if (buf_len <= (int)sizeof(connect_mock_sent)) {
            XMEMCPY(connect_mock_sent, buf, (size_t)buf_len);
            connect_mock_xfer = buf_len;
        }

        /* Count the frame regardless of type. */
        g_frames_written++;

        if (ack_type == MQTT_PACKET_TYPE_PUBLISH_REL) {
            g_pubrel_written = 1;
        }
        if (ack_type == MQTT_PACKET_TYPE_PUBLISH_ACK ||
            ack_type == MQTT_PACKET_TYPE_PUBLISH_REC) {
            g_pubresp_written = 1;
        }
        /* Record which QoS acknowledgement reached the wire. The PUBREC/PUBREL
         * filter in MqttClient_HandlePacket decides this, so a test can read
         * back the exact ack type and catch a spurious or wrong-type frame. */
        if (ack_type == MQTT_PACKET_TYPE_PUBLISH_ACK ||
            ack_type == MQTT_PACKET_TYPE_PUBLISH_REC ||
            ack_type == MQTT_PACKET_TYPE_PUBLISH_REL ||
            ack_type == MQTT_PACKET_TYPE_PUBLISH_COMP) {
            g_last_ack_written = ack_type;
            if (buf_len >= 4) {
                g_last_ack_id = (buf[2] << 8) | buf[3];
            }
        }
    }
    /* Pretend the full packet was sent so MqttClient_Connect reaches the
     * CLIENT_FORCE_ZERO step. */
    return buf_len;
}

static int buf_contains(const byte* buf, int buf_len,
    const char* needle, int needle_len)
{
    int i;
    if (buf == NULL || needle_len <= 0 || buf_len < needle_len) {
        return 0;
    }
    for (i = 0; i + needle_len <= buf_len; i++) {
        if (XMEMCMP(&buf[i], needle, (size_t)needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

TEST(connect_clears_tx_buf_credentials)
{
    int rc;
    int i;
    MqttConnect connect;
    const int user_len = (int)sizeof(TEST_CONNECT_USERNAME) - 1;
    const int pass_len = (int)sizeof(TEST_CONNECT_PASSWORD) - 1;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    /* Swap in a write mock that accepts the packet and records what was
     * sent. Read still returns MQTT_CODE_ERROR_NETWORK so MqttClient_Connect
     * returns after the CLIENT_FORCE_ZERO step. */
    connect_mock_xfer = 0;
    XMEMSET(connect_mock_sent, 0, sizeof(connect_mock_sent));
    test_net.write = mock_net_write_accept;

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";
    connect.username = TEST_CONNECT_USERNAME;
    connect.password = TEST_CONNECT_PASSWORD;

    rc = MqttClient_Connect(&test_client, &connect);
    /* The read mock cannot deliver a CONNECT_ACK, so a successful return
     * would be wrong regardless of the zeroing step. */
    ASSERT_NE(MQTT_CODE_SUCCESS, rc);

    /* Confirm the write path actually ran with credentials present. Without
     * this, the zeroing assertion below could pass trivially. */
    ASSERT_TRUE(connect_mock_xfer > 0);
    ASSERT_TRUE(buf_contains(connect_mock_sent, connect_mock_xfer,
                             TEST_CONNECT_USERNAME, user_len));
    ASSERT_TRUE(buf_contains(connect_mock_sent, connect_mock_xfer,
                             TEST_CONNECT_PASSWORD, pass_len));

    /* Core regression check: credentials must not remain in tx_buf after
     * MqttClient_Connect returns. Scans the full buffer because the zeroed
     * region covers [0..xfer) and the remainder was zero-initialized at
     * setup. */
    ASSERT_FALSE(buf_contains(test_client.tx_buf, TEST_TX_BUF_SIZE,
                              TEST_CONNECT_USERNAME, user_len));
    ASSERT_FALSE(buf_contains(test_client.tx_buf, TEST_TX_BUF_SIZE,
                              TEST_CONNECT_PASSWORD, pass_len));

    /* Stronger boundary check: every byte the mock observed being written
     * must now be zero. This catches both deletion of the CLIENT_FORCE_ZERO
     * call and an `xfer` -> `0` mutation that turns the wipe into a no-op. */
    for (i = 0; i < connect_mock_xfer; i++) {
        if (test_client.tx_buf[i] != 0) {
            FAIL("tx_buf byte within xfer range is non-zero after CONNECT");
        }
    }
}

/* Serves a pre-staged response packet (e.g. a SUBACK) one chunk per read so a
 * full client request/response round-trip can run against the mock net. */
static byte g_canned_buf[64];
static int g_canned_len;
static int g_canned_pos;

static int mock_net_read_canned(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    int n;
    (void)context; (void)timeout_ms;
    n = g_canned_len - g_canned_pos;
    if (n <= 0) {
        return 0; /* exhausted -> MQTT_CODE_CONTINUE under nonblock */
    }
    if (n > buf_len) {
        n = buf_len;
    }
    XMEMCPY(buf, g_canned_buf + g_canned_pos, n);
    g_canned_pos += n;
    return n;
}

/* A broker that accepts the connection returns a CONNACK whose return code is
 * MQTT_CONNECT_ACK_CODE_ACCEPTED (0). MqttClient_Connect must surface this as
 * MQTT_CODE_SUCCESS. Paired with the refusal test below so a boundary mutation
 * of the return-code check cannot pass both cases. */
TEST(connect_accepted_connack_returns_success)
{
    int rc;
    int i;
    MqttConnect connect;
    /* CONNACK v3.1.1: type=0x20, remain=2, flags=0x00, return_code=0x00. */
    static const byte connack[] = { 0x20, 0x02, 0x00, 0x00 };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
#ifdef WOLFMQTT_V5
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, connack, sizeof(connack));
    g_canned_len = (int)sizeof(connack);
    g_canned_pos = 0;

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Connect(&test_client, &connect);
    }

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, connect.ack.return_code);
}

/* A broker that refuses the connection returns a CONNACK whose return code is
 * non-zero (0x05 = not authorized here). MqttClient_Connect must surface this
 * as MQTT_CODE_ERROR_CONNECT_REFUSED rather than MQTT_CODE_SUCCESS, else an
 * application using the connect result as its authentication gate would treat a
 * rejected login as a live session. This pins detection that previously had no
 * round-trip test. */
TEST(connect_refused_connack_returns_connect_refused)
{
    int rc;
    int i;
    MqttConnect connect;
    /* CONNACK v3.1.1: type=0x20, remain=2, flags=0x00, return_code=0x05
     * (not authorized). */
    static const byte connack[] = { 0x20, 0x02, 0x00, 0x05 };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
#ifdef WOLFMQTT_V5
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, connack, sizeof(connack));
    g_canned_len = (int)sizeof(connack);
    g_canned_pos = 0;

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Connect(&test_client, &connect);
    }

    ASSERT_EQ(MQTT_CODE_ERROR_CONNECT_REFUSED, rc);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_NOT_AUTH, connect.ack.return_code);
}

#if defined(WOLFMQTT_V5)
/* MQTT v5: an accepted CONNACK (return code 0) that advertises server
 * properties must latch them into long-lived client state so the publish and
 * packet-size guards stay meaningful without a registered property callback.
 * Feeds Maximum QoS=1, Retain Available=0 and Maximum Packet Size=1024 and
 * asserts each field was updated. Paired with the refusal test below so the
 * accept-only gate that guards this mutation is exercised from both sides. */
TEST(connect_accepted_connack_latches_v5_props)
{
    int rc;
    int i;
    MqttConnect connect;
    /* CONNACK v5: type=0x20, remain=0x0C, flags=0x00, return_code=0x00,
     * prop_len=0x09, [0x24 0x01]=Max QoS 1, [0x25 0x00]=Retain Avail 0,
     * [0x27 00 00 04 00]=Max Packet Size 1024. */
    static const byte connack[] = {
        0x20, 0x0C, 0x00, 0x00, 0x09,
        0x24, 0x01,
        0x25, 0x00,
        0x27, 0x00, 0x00, 0x04, 0x00
    };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, connack, sizeof(connack));
    g_canned_len = (int)sizeof(connack);
    g_canned_pos = 0;

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Connect(&test_client, &connect);
    }

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, connect.ack.return_code);
    /* Advertised Max QoS 1 is narrowed against this build's WOLFMQTT_MAX_QOS,
     * so a QoS-capped (WOLFMQTT_MAX_QOS=0) build latches 0 rather than 1. */
    ASSERT_EQ((WOLFMQTT_MAX_QOS < MQTT_QOS_1) ? (byte)WOLFMQTT_MAX_QOS :
              MQTT_QOS_1, test_client.max_qos);
    ASSERT_EQ(0, test_client.retain_avail);
    ASSERT_EQ(1024, test_client.packet_sz_max);
}

/* An accepted v5 CONNACK can carry MQTT_PROP_AUTH_DATA, which decodes as a
 * pointer into rx_buf with no copy. After MqttClient_Connect returns that
 * plaintext must not linger in rx_buf. Feed a CONNACK with a distinctive
 * AUTH_DATA blob and assert it is scrubbed. */
TEST(connect_v5_scrubs_connack_auth_data_from_rx_buf)
{
    int rc;
    int i;
    MqttConnect connect;
    /* CONNACK v5: type=0x20, remain=0x14, flags=0x00, return_code=0x00,
     * prop_len=0x11, then AUTH_DATA (0x16) binary length 14 =
     * "SASLfinalPROOF". */
    static const byte connack[] = {
        0x20, 0x14, 0x00, 0x00, 0x11,
        0x16, 0x00, 0x0E,
        'S', 'A', 'S', 'L', 'f', 'i', 'n', 'a', 'l', 'P', 'R', 'O', 'O', 'F'
    };
    static const char blob[] = "SASLfinalPROOF";
    const int blob_len = (int)sizeof(blob) - 1;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, connack, sizeof(connack));
    g_canned_len = (int)sizeof(connack);
    g_canned_pos = 0;

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Connect(&test_client, &connect);
    }

    /* Success + accepted proves the AUTH_DATA CONNACK was decoded (and thus
     * was resident in rx_buf). */
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, connect.ack.return_code);
    /* The AUTH_DATA plaintext must not remain anywhere in rx_buf. rx_buf was
     * zero-initialized at setup, so scanning the full length reads only
     * initialized bytes. */
    ASSERT_FALSE(buf_contains(test_client.rx_buf, test_client.rx_buf_len,
                             blob, blob_len));
}

/* MQTT v5: a refused CONNACK (non-zero return code) must NOT mutate long-lived
 * client state even when it carries server properties, otherwise a rejected or
 * malicious broker could shrink the client's packet-size cap or lower its QoS
 * ceiling and have those corrupted limits persist onto a later reconnect on the
 * same client struct. Feeds the same properties as the acceptance test but with
 * a not-authorized return code and asserts every field keeps its pre-CONNACK
 * default. Deleting the accept-only gate, or flipping its equality test, would
 * latch these values and fail this test. */
TEST(connect_refused_connack_preserves_v5_defaults)
{
    int rc;
    int i;
    MqttConnect connect;
    /* Same properties as the acceptance test, but return_code=0x05
     * (not authorized). */
    static const byte connack[] = {
        0x20, 0x0C, 0x00, 0x05, 0x09,
        0x24, 0x01,
        0x25, 0x00,
        0x27, 0x00, 0x00, 0x04, 0x00
    };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, connack, sizeof(connack));
    g_canned_len = (int)sizeof(connack);
    g_canned_pos = 0;

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Connect(&test_client, &connect);
    }

    ASSERT_EQ(MQTT_CODE_ERROR_CONNECT_REFUSED, rc);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_NOT_AUTH, connect.ack.return_code);
    /* Pre-CONNACK defaults established by MqttClient_Connect must be intact. */
    ASSERT_EQ((byte)WOLFMQTT_MAX_QOS, test_client.max_qos);
    ASSERT_EQ(1, test_client.retain_avail);
    ASSERT_EQ(0, test_client.packet_sz_max);
}

/* MQTT v5 [3.1.2.11.6]: only Max QoS 0 or 1 are legal. A non-conforming or
 * malicious broker that advertises a larger value (2 here) must be clamped to
 * MQTT_QOS_1 before being narrowed against this build's WOLFMQTT_MAX_QOS, so the
 * client-side publish guard cannot be tricked into permitting QoS 2. Exercises
 * the clamp branch that the in-spec acceptance test above does not reach. */
TEST(connect_accepted_connack_clamps_illegal_max_qos)
{
    int rc;
    int i;
    MqttConnect connect;
    /* CONNACK v5 with an out-of-spec Max QoS of 2: type=0x20, remain=0x05,
     * flags=0x00, return_code=0x00, prop_len=0x02, [0x24 0x02]=Max QoS 2. */
    static const byte connack[] = {
        0x20, 0x05, 0x00, 0x00, 0x02,
        0x24, 0x02
    };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, connack, sizeof(connack));
    g_canned_len = (int)sizeof(connack);
    g_canned_pos = 0;

    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = "test_client";

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Connect(&test_client, &connect);
    }

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, connect.ack.return_code);
    /* Illegal QoS 2 is clamped to 1, then narrowed against WOLFMQTT_MAX_QOS. */
    ASSERT_EQ((WOLFMQTT_MAX_QOS < MQTT_QOS_1) ? (byte)WOLFMQTT_MAX_QOS :
              MQTT_QOS_1, test_client.max_qos);
}
#endif /* WOLFMQTT_V5 */

/* A broker that rejects a subscription returns a SUBACK whose
 * per-topic return code has the high bit set (0x80 in v3.1.1, any reason
 * code >= 0x80 in v5). MqttClient_Subscribe must surface this as
 * MQTT_CODE_ERROR_SUBSCRIBE_REJECTED rather than MQTT_CODE_SUCCESS, else the
 * application waits forever for messages on a filter the broker never
 * installed. This pins the detection that previously had no test. */
TEST(subscribe_broker_rejection_returns_subscribe_rejected)
{
    int rc;
    int i;
    MqttSubscribe subscribe;
    MqttTopic topics[1];
    /* SUBACK v3.1.1: type=0x90, remain=3, packet_id=42, return_code=0x80. */
    static const byte suback[] = { 0x90, 0x03, 0x00, 0x2A, 0x80 };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
#ifdef WOLFMQTT_V5
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, suback, sizeof(suback));
    g_canned_len = (int)sizeof(suback);
    g_canned_pos = 0;

    XMEMSET(&subscribe, 0, sizeof(subscribe));
    XMEMSET(topics, 0, sizeof(topics));
    topics[0].topic_filter = "test/topic";
    topics[0].qos = MQTT_QOS_0;
    subscribe.packet_id = 42;
    subscribe.topic_count = 1;
    subscribe.topics = topics;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Subscribe(&test_client, &subscribe);
    }

    ASSERT_EQ(MQTT_CODE_ERROR_SUBSCRIBE_REJECTED, rc);
    ASSERT_EQ(MQTT_SUBSCRIBE_ACK_CODE_FAILURE,
        subscribe.topics[0].return_code);
}

#ifdef WOLFMQTT_V5
/* A v5 UNSUBACK whose per-topic reason code has the high bit set means the
 * broker refused the unsubscribe; MqttClient_Unsubscribe must surface that as
 * MQTT_CODE_ERROR_UNSUBSCRIBE_REJECTED rather than success. */
TEST(unsubscribe_broker_rejection_returns_unsubscribe_rejected)
{
    int rc;
    int i;
    MqttUnsubscribe unsub;
    MqttTopic topics[1];
    /* v5 UNSUBACK: type=0xB0, remain=4, packet_id=43, props_len=0,
     * reason=0x87 (NOT_AUTHORIZED). */
    static const byte unsuback[] = { 0xB0, 0x04, 0x00, 0x2B, 0x00, 0x87 };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, unsuback, sizeof(unsuback));
    g_canned_len = (int)sizeof(unsuback);
    g_canned_pos = 0;

    XMEMSET(&unsub, 0, sizeof(unsub));
    XMEMSET(topics, 0, sizeof(topics));
    topics[0].topic_filter = "test/topic";
    unsub.packet_id = 43;
    unsub.topic_count = 1;
    unsub.topics = topics;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 10 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Unsubscribe(&test_client, &unsub);
    }

    ASSERT_EQ(MQTT_CODE_ERROR_UNSUBSCRIBE_REJECTED, rc);
}
#endif /* WOLFMQTT_V5 */

/* ============================================================================
 * MqttClient_Disconnect Tests
 * ============================================================================ */

TEST(disconnect_null_client)
{
    int rc;

    rc = MqttClient_Disconnect(NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * MqttClient_GetProtocolVersion Tests
 * ============================================================================ */

TEST(get_protocol_version_default)
{
    int rc;
    int version;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    version = MqttClient_GetProtocolVersion(&test_client);
    /* Default protocol version should be 4 (v3.1.1) or 5 (v5.0) depending
     * on build options */
#ifdef WOLFMQTT_V5
    ASSERT_EQ(MQTT_CONNECT_PROTOCOL_LEVEL_5, version);
#else
    ASSERT_EQ(MQTT_CONNECT_PROTOCOL_LEVEL_4, version);
#endif
}

TEST(get_protocol_version_string)
{
    int rc;
    const char* version_str;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    version_str = MqttClient_GetProtocolVersionString(&test_client);
    ASSERT_NOT_NULL(version_str);
    /* Should be "v3.1.1" or "v5" depending on build options */
#ifdef WOLFMQTT_V5
    ASSERT_STR_EQ("v5", version_str);
#else
    ASSERT_STR_EQ("v3.1.1", version_str);
#endif
}

/* ============================================================================
 * MqttClient_Ping Tests
 * ============================================================================ */

TEST(ping_null_client)
{
    int rc;

    rc = MqttClient_Ping(NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * MqttClient_Subscribe Tests
 * ============================================================================ */

TEST(subscribe_null_client)
{
    int rc;
    MqttSubscribe subscribe;

    XMEMSET(&subscribe, 0, sizeof(subscribe));

    rc = MqttClient_Subscribe(NULL, &subscribe);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(subscribe_null_subscribe)
{
    int rc;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    rc = MqttClient_Subscribe(&test_client, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * MqttClient_Unsubscribe Tests
 * ============================================================================ */

TEST(unsubscribe_null_client)
{
    int rc;
    MqttUnsubscribe unsubscribe;

    XMEMSET(&unsubscribe, 0, sizeof(unsubscribe));

    rc = MqttClient_Unsubscribe(NULL, &unsubscribe);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(unsubscribe_null_unsubscribe)
{
    int rc;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    rc = MqttClient_Unsubscribe(&test_client, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* ============================================================================
 * MqttClient_Publish Tests
 * ============================================================================ */

TEST(publish_null_client)
{
    int rc;
    MqttPublish publish;

    XMEMSET(&publish, 0, sizeof(publish));

    rc = MqttClient_Publish(NULL, &publish);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(publish_null_publish)
{
    int rc;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    rc = MqttClient_Publish(&test_client, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

#ifdef WOLFMQTT_V5
/* Drives one QoS>0 publish to completion against the canned-response mock and
 * returns the final MqttClient_Publish result. The caller stages the broker's
 * PUBACK/PUBCOMP (plus any intermediate PUBREC for QoS 2) in g_canned_buf. */
static int run_publish_with_canned_resp(MqttPublish* publish,
    const byte* resp, int resp_len, byte proto_level)
{
    int rc;
    int i;

    rc = test_init_client();
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
    test_client.protocol_level = proto_level;

    g_pubrel_written = 0;
    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, resp, (size_t)resp_len);
    g_canned_len = resp_len;
    g_canned_pos = 0;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 20 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_Publish(&test_client, publish);
    }
    return rc;
}

/* A v5 broker can ACK a QoS 1 PUBLISH at the protocol layer yet still reject
 * the message with a PUBACK reason code >= 0x80 (ACL deny, quota, invalid
 * topic/payload). MqttClient_Publish must surface that as
 * MQTT_CODE_ERROR_PUBLISH_REJECTED rather than MQTT_CODE_SUCCESS, else the
 * application proceeds as if the message was delivered. This pins the
 * detection that the publish path previously lacked (known issue 3626). */
TEST(publish_qos1_v5_broker_rejection_returns_publish_rejected)
{
    int rc;
    MqttPublish publish;
    static byte payload[] = "hello";
    /* v5 PUBACK: type=0x40, remain=3, packet_id=7, reason=0x87 NOT_AUTHORIZED */
    static const byte puback[] = { 0x40, 0x03, 0x00, 0x07, 0x87 };

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_1;
    publish.packet_id = 7;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = run_publish_with_canned_resp(&publish, puback, (int)sizeof(puback),
        MQTT_CONNECT_PROTOCOL_LEVEL_5);

    ASSERT_EQ(MQTT_CODE_ERROR_PUBLISH_REJECTED, rc);
    ASSERT_EQ(MQTT_REASON_NOT_AUTHORIZED, publish.resp.reason_code);
}

/* A v5 PUBACK with reason code Success (0x00) means the broker accepted the
 * message; MqttClient_Publish must still return success and not false-trip the
 * new rejection check. */
TEST(publish_qos1_v5_success_returns_success)
{
    int rc;
    MqttPublish publish;
    static byte payload[] = "hello";
    /* v5 PUBACK: type=0x40, remain=3, packet_id=8, reason=0x00 Success */
    static const byte puback[] = { 0x40, 0x03, 0x00, 0x08, 0x00 };

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_1;
    publish.packet_id = 8;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = run_publish_with_canned_resp(&publish, puback, (int)sizeof(puback),
        MQTT_CONNECT_PROTOCOL_LEVEL_5);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_REASON_SUCCESS, publish.resp.reason_code);
}

/* Not every non-zero v5 reason code is a rejection: the high bit distinguishes
 * error (>= 0x80) from success-class codes. A broker legitimately returns
 * 0x10 No matching subscribers for a QoS 1 PUBLISH that matched no
 * subscriptions, and the message WAS accepted. The check uses
 * (reason_code & 0x80) precisely so 0x10 stays a success; this pins that
 * boundary against a regression to e.g. (reason_code != 0). */
TEST(publish_qos1_v5_no_matching_subscribers_returns_success)
{
    int rc;
    MqttPublish publish;
    static byte payload[] = "hello";
    /* v5 PUBACK: type=0x40, remain=3, packet_id=12, reason=0x10 No match sub */
    static const byte puback[] = { 0x40, 0x03, 0x00, 0x0C, 0x10 };

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_1;
    publish.packet_id = 12;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = run_publish_with_canned_resp(&publish, puback, (int)sizeof(puback),
        MQTT_CONNECT_PROTOCOL_LEVEL_5);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_REASON_NO_MATCH_SUB, publish.resp.reason_code);
}

/* QoS 2 completes the PUBLISH -> PUBREC -> PUBREL -> PUBCOMP handshake. A v5
 * broker can reject at the PUBCOMP with a reason code >= 0x80 (e.g. 0x92
 * Packet Identifier not found); MqttClient_Publish must surface that as
 * MQTT_CODE_ERROR_PUBLISH_REJECTED. The mock serves a success PUBREC followed
 * by the failing PUBCOMP, and accepts the client's PUBREL. */
TEST(publish_qos2_v5_broker_rejection_returns_publish_rejected)
{
    int rc;
    MqttPublish publish;
    static byte payload[] = "hello";
    /* PUBREC (success, no reason byte): type=0x50, remain=2, packet_id=9.
     * PUBCOMP (reject): type=0x70, remain=3, packet_id=9, reason=0x92. */
    static const byte resp[] = {
        0x50, 0x02, 0x00, 0x09,
        0x70, 0x03, 0x00, 0x09, 0x92
    };

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_2;
    publish.packet_id = 9;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = run_publish_with_canned_resp(&publish, resp, (int)sizeof(resp),
        MQTT_CONNECT_PROTOCOL_LEVEL_5);

    ASSERT_EQ(MQTT_CODE_ERROR_PUBLISH_REJECTED, rc);
    ASSERT_EQ(MQTT_REASON_PACKET_ID_NOT_FOUND, publish.resp.reason_code);
    /* The PUBREC succeeded, so the handshake must have advanced to PUBREL
     * before the PUBCOMP rejection arrived. */
    ASSERT_TRUE(g_pubrel_written);
}

/* QoS 2 full happy path: success PUBREC -> PUBREL -> success PUBCOMP must
 * return MQTT_CODE_SUCCESS. The post-wait rejection check now runs for every
 * v5 QoS 2 publish, so this pins that a terminal success PUBCOMP is not
 * false-tripped and that the handshake emits a PUBREL. */
TEST(publish_qos2_v5_success_returns_success)
{
    int rc;
    MqttPublish publish;
    static byte payload[] = "hello";
    /* PUBREC success (no reason byte): type=0x50, remain=2, packet_id=14.
     * PUBCOMP success (no reason byte): type=0x70, remain=2, packet_id=14. */
    static const byte resp[] = {
        0x50, 0x02, 0x00, 0x0E,
        0x70, 0x02, 0x00, 0x0E
    };

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_2;
    publish.packet_id = 14;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = run_publish_with_canned_resp(&publish, resp, (int)sizeof(resp),
        MQTT_CONNECT_PROTOCOL_LEVEL_5);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_REASON_SUCCESS, publish.resp.reason_code);
    ASSERT_TRUE(g_pubrel_written);
}

/* The primary QoS 2 rejection point is the PUBREC: a v5 broker reports
 * authorization/quota/topic/payload failures there with a reason code >= 0x80.
 * Per [MQTT-4.3.3] the sender must not send PUBREL and the exchange is
 * complete, so MqttClient_Publish must return MQTT_CODE_ERROR_PUBLISH_REJECTED
 * directly from the PUBREC rather than emitting an illegal PUBREL and blocking
 * for a PUBCOMP that never arrives. The mock serves only the failing PUBREC. */
TEST(publish_qos2_v5_pubrec_rejection_returns_publish_rejected)
{
    int rc;
    MqttPublish publish;
    static byte payload[] = "hello";
    /* v5 PUBREC: type=0x50, remain=3, packet_id=11, reason=0x87 NOT_AUTHORIZED */
    static const byte pubrec[] = { 0x50, 0x03, 0x00, 0x0B, 0x87 };

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_2;
    publish.packet_id = 11;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = run_publish_with_canned_resp(&publish, pubrec, (int)sizeof(pubrec),
        MQTT_CONNECT_PROTOCOL_LEVEL_5);

    ASSERT_EQ(MQTT_CODE_ERROR_PUBLISH_REJECTED, rc);
    ASSERT_EQ(MQTT_REASON_NOT_AUTHORIZED, publish.resp.reason_code);
    /* Per [MQTT-4.3.3] a PUBREC reason code >= 0x80 ends the exchange: the
     * client must NOT emit a PUBREL. Directly pin that no PUBREL was written. */
    ASSERT_FALSE(g_pubrel_written);
}

/* A v3.1.1 PUBACK carries no reason code, so the rejection check must not run
 * for protocol level < 5. Pre-seed resp.reason_code with a failure byte to
 * prove the protocol_level guard prevents a stale value from being misread as
 * a broker rejection. */
TEST(publish_v311_ack_not_misread_as_rejected)
{
    int rc;
    MqttPublish publish;
    static byte payload[] = "hello";
    /* v3.1.1 PUBACK: type=0x40, remain=2, packet_id=10 (no reason code). */
    static const byte puback[] = { 0x40, 0x02, 0x00, 0x0A };

    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_1;
    publish.packet_id = 10;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;
    /* Stale failure byte that must be ignored for a v3.1.1 ACK. */
    publish.resp.reason_code = MQTT_REASON_NOT_AUTHORIZED;

    rc = run_publish_with_canned_resp(&publish, puback, (int)sizeof(puback),
        MQTT_CONNECT_PROTOCOL_LEVEL_4);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
}

#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_NONBLOCK)
/* Pins the documented WOLFMQTT_MULTITHREAD divergence for a QoS 2 PUBREC
 * rejection. A write-only publish registers a pending response for the PUBCOMP
 * and returns without reading; a separate "reading thread" (simulated here by
 * MqttClient_WaitMessage) then processes the rejecting PUBREC. Expected, per
 * the code comment in MqttClient_HandlePacket and the ChangeLog:
 *   - the reading thread receives MQTT_CODE_ERROR_PUBLISH_REJECTED directly;
 *   - no PUBREL is emitted ([MQTT-4.3.3]);
 *   - the PUBREC reason code is decoded into the shared client->msg object, not
 *     the publisher's MqttPublish, because RespList_Find matches PUBREC against
 *     the PUBCOMP-keyed pendResp and finds nothing — so the publisher's
 *     publish.resp is left untouched and it must rely on the reader to observe
 *     the rejection. This test locks that behavior so a future change can't
 *     silently alter it. */
TEST(publish_qos2_v5_pubrec_rejection_multithread_reader)
{
    int rc;
    int i;
    /* static so the registered pendResp does not point into freed stack after
     * the call returns (the client is zeroed by setup() before the next test;
     * MqttClient_DeInit does not walk the pending-response list). */
    static MqttPublish publish;
    static byte payload[] = "hello";
    /* v5 PUBREC: type=0x50, remain=3, packet_id=13, reason=0x87 NOT_AUTHORIZED */
    static const byte pubrec[] = { 0x50, 0x03, 0x00, 0x0D, 0x87 };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;

    g_pubrel_written = 0;
    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;

    /* Write-only QoS 2 publish: sends PUBLISH, registers the PUBCOMP pending
     * response, returns CONTINUE without reading (response is another thread's
     * job). */
    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_2;
    publish.packet_id = 13;
    publish.topic_name = "test/topic";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = MqttClient_Publish_WriteOnly(&test_client, &publish, NULL);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* Reading thread processes the rejecting PUBREC. */
    XMEMCPY(g_canned_buf, pubrec, sizeof(pubrec));
    g_canned_len = (int)sizeof(pubrec);
    g_canned_pos = 0;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 20 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_WaitMessage(&test_client, TEST_CMD_TIMEOUT_MS);
    }

    ASSERT_EQ(MQTT_CODE_ERROR_PUBLISH_REJECTED, rc);
    ASSERT_FALSE(g_pubrel_written);
    /* The publisher's own struct is NOT updated on this path. */
    ASSERT_EQ(MQTT_REASON_SUCCESS, publish.resp.reason_code);
}
#endif /* WOLFMQTT_MULTITHREAD && WOLFMQTT_NONBLOCK */
#endif /* WOLFMQTT_V5 */

/* Regression test for MQTT Packet Identifier in-use collision check. The
 * MQTT spec (3.1.1 section 2.3.1, 5.0 section 2.2.1) requires that a new QoS-related
 * Control Packet use a Packet Identifier that is not currently in use;
 * the identifier only becomes reusable after the matching acknowledgement
 * flow completes. Before the fix, MqttClient_RespList_Add only checked
 * that the same MqttPendResp object pointer was not already in the list -
 * it did not reject a different pending entry that reused an in-flight
 * Packet Identifier. The repro requires both MULTITHREAD (so the pending
 * response list is in use) and NONBLOCK (so the write-only publish leaves
 * the pendResp in the list across the call boundary). */
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_NONBLOCK)
TEST(publish_writeonly_rejects_duplicate_in_flight_packet_id)
{
    int rc;
    MqttPublish publish1, publish2;
    static byte payload1[] = "hello1";
    static byte payload2[] = "hello2";

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    /* Mock writes accept everything so the publish state machine reaches
     * MQTT_MSG_WAIT and returns MQTT_CODE_CONTINUE while the pendResp is
     * still registered. */
    connect_mock_xfer = 0;
    XMEMSET(connect_mock_sent, 0, sizeof(connect_mock_sent));
    test_net.write = mock_net_write_accept;

    /* First publish: QoS 1, packet_id=7. After this returns, the
     * pendResp for PUBLISH_ACK with packet_id=7 remains in the list. */
    XMEMSET(&publish1, 0, sizeof(publish1));
    publish1.qos = MQTT_QOS_1;
    publish1.packet_id = 7;
    publish1.topic_name = "test/topic1";
    publish1.buffer = payload1;
    publish1.total_len = (word32)(sizeof(payload1) - 1);
    publish1.buffer_len = publish1.total_len;

    rc = MqttClient_Publish_WriteOnly(&test_client, &publish1, NULL);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* Second publish reusing the same packet_id must be rejected. Without
     * the fix this returned MQTT_CODE_CONTINUE and silently registered a
     * second pendResp with the same Packet Identifier. */
    XMEMSET(&publish2, 0, sizeof(publish2));
    publish2.qos = MQTT_QOS_1;
    publish2.packet_id = 7;
    publish2.topic_name = "test/topic2";
    publish2.buffer = payload2;
    publish2.total_len = (word32)(sizeof(payload2) - 1);
    publish2.buffer_len = publish2.total_len;

    rc = MqttClient_Publish_WriteOnly(&test_client, &publish2, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);

    /* A different packet_id is allowed even while packet_id=7 is in use. */
    publish2.packet_id = 8;
    publish2.stat.write = MQTT_MSG_BEGIN;
    publish2.buffer_pos = 0;
    rc = MqttClient_Publish_WriteOnly(&test_client, &publish2, NULL);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* After the in-flight entry is released, the same Packet Identifier
     * becomes reusable. */
    rc = MqttClient_CancelMessage(&test_client, (MqttObject*)&publish1);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    XMEMSET(&publish1, 0, sizeof(publish1));
    publish1.qos = MQTT_QOS_1;
    publish1.packet_id = 7;
    publish1.topic_name = "test/topic1";
    publish1.buffer = payload1;
    publish1.total_len = (word32)(sizeof(payload1) - 1);
    publish1.buffer_len = publish1.total_len;
    rc = MqttClient_Publish_WriteOnly(&test_client, &publish1, NULL);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* Cleanup remaining pending responses. */
    (void)MqttClient_CancelMessage(&test_client, (MqttObject*)&publish1);
    (void)MqttClient_CancelMessage(&test_client, (MqttObject*)&publish2);
}

/* Cross-packet-type collision: an in-flight SUBSCRIBE_ACK and a new QoS 1
 * publish must not share a Packet Identifier. The MQTT spec treats the
 * in-use set as global across all packet types that carry a Packet
 * Identifier, so the check in MqttClient_RespList_Add must reject the
 * collision regardless of whether the existing entry is a PUBLISH_ACK,
 * SUBSCRIBE_ACK, UNSUBSCRIBE_ACK, etc. This test guards against a future
 * narrowing of the check to a single packet_type family. */
static int mock_net_read_continue(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    (void)context; (void)buf; (void)buf_len; (void)timeout_ms;
    /* Return 0 bytes - under WOLFMQTT_NONBLOCK the socket layer translates
     * this into MQTT_CODE_CONTINUE so MqttClient_Subscribe returns with
     * its pendResp still registered. */
    return 0;
}

TEST(subscribe_in_flight_blocks_publish_with_same_packet_id)
{
    int rc;
    MqttSubscribe subscribe;
    MqttTopic topics[1];
    MqttPublish publish;
    static byte payload[] = "payload";

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_continue;

    /* Issue a SUBSCRIBE that writes successfully but cannot complete the
     * SUBACK read; the pendResp for SUBSCRIBE_ACK + packet_id=42 is left
     * in the list. */
    XMEMSET(&subscribe, 0, sizeof(subscribe));
    XMEMSET(topics, 0, sizeof(topics));
    topics[0].topic_filter = "test/topic";
    topics[0].qos = MQTT_QOS_0;
    subscribe.packet_id = 42;
    subscribe.topic_count = 1;
    subscribe.topics = topics;

    rc = MqttClient_Subscribe(&test_client, &subscribe);
    ASSERT_EQ(MQTT_CODE_CONTINUE, rc);

    /* A QoS 1 publish reusing packet_id=42 must be rejected even though
     * the in-flight entry is for SUBSCRIBE_ACK, not PUBLISH_ACK. */
    XMEMSET(&publish, 0, sizeof(publish));
    publish.qos = MQTT_QOS_1;
    publish.packet_id = 42;
    publish.topic_name = "test/publish";
    publish.buffer = payload;
    publish.total_len = (word32)(sizeof(payload) - 1);
    publish.buffer_len = publish.total_len;

    rc = MqttClient_Publish_WriteOnly(&test_client, &publish, NULL);
    ASSERT_EQ(MQTT_CODE_ERROR_PACKET_ID, rc);

    /* Cleanup. */
    (void)MqttClient_CancelMessage(&test_client, (MqttObject*)&subscribe);
    (void)MqttClient_CancelMessage(&test_client, (MqttObject*)&publish);
}
#endif /* WOLFMQTT_MULTITHREAD && WOLFMQTT_NONBLOCK */


/* ============================================================================
 * MqttClient_WaitMessage Tests
 * ============================================================================ */

TEST(wait_message_null_client)
{
    int rc;

    rc = MqttClient_WaitMessage(NULL, 1000);
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

/* Stage `frame` as a server-pushed packet and drive MqttClient_WaitMessage to
 * completion against the canned-response mock. The client is initialized with a
 * NULL msg_cb (test_init_client passes NULL). Returns the terminal result. */
static int run_wait_message_with_frame(const byte* frame, int frame_len)
{
    int rc;
    int i;

    rc = test_init_client();
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#ifdef WOLFMQTT_V5
    /* Decode the v3.1.1-format frame below without expecting v5 properties. */
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif

    g_pubresp_written = 0;
    g_last_ack_written = MQTT_PACKET_TYPE_RESERVED;
    g_frames_written = 0;
    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, frame, (size_t)frame_len);
    g_canned_len = frame_len;
    g_canned_pos = 0;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 20 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_WaitMessage(&test_client, TEST_CMD_TIMEOUT_MS);
    }
    return rc;
}

/* #6217: a client initialized with a NULL msg_cb that receives a QoS 1 PUBLISH
 * used to silently drain and discard the payload, return MQTT_CODE_SUCCESS, and
 * then send a PUBACK telling the broker the message was delivered. The
 * application never saw the message yet the broker considered it acknowledged.
 * MqttClient_Publish_ReadPayload now returns MQTT_CODE_ERROR_CALLBACK when no
 * callback is registered, so MqttClient_HandlePacket does not populate an ACK
 * and no PUBACK is sent. */
TEST(wait_message_qos1_null_msg_cb_errors_no_ack)
{
    int rc;
    /* v3.1.1 QoS1 PUBLISH: type|qos1=0x32, remain=7, topic "a" (0x0001 'a'),
     * packet_id=7 (0x0007), payload "hi". */
    static const byte publish_qos1[] = { 0x32, 0x07, 0x00, 0x01, 'a',
                                         0x00, 0x07, 'h', 'i' };

    rc = run_wait_message_with_frame(publish_qos1, (int)sizeof(publish_qos1));

    /* Pre-fix this returned MQTT_CODE_SUCCESS. */
    ASSERT_EQ(MQTT_CODE_ERROR_CALLBACK, rc);
    /* The broker must NOT be told the message was delivered. Pre-fix a PUBACK
     * was emitted here, falsely confirming delivery of a dropped message. */
    ASSERT_FALSE(g_pubresp_written);
}

/* #6217 (QoS 0 half): a QoS 0 PUBLISH carries no acknowledgement, so the false
 * ACK does not apply, but with a NULL msg_cb the message was still silently
 * dropped with MQTT_CODE_SUCCESS. The caller now receives a distinct error
 * instead of believing nothing arrived. */
TEST(wait_message_qos0_null_msg_cb_errors)
{
    int rc;
    /* v3.1.1 QoS0 PUBLISH: type=0x30, remain=5, topic "a" (0x0001 'a'),
     * payload "hi" (no packet id for QoS 0). */
    static const byte publish_qos0[] = { 0x30, 0x05, 0x00, 0x01, 'a', 'h', 'i' };

    rc = run_wait_message_with_frame(publish_qos0, (int)sizeof(publish_qos0));

    /* Pre-fix this returned MQTT_CODE_SUCCESS while discarding the message. */
    ASSERT_EQ(MQTT_CODE_ERROR_CALLBACK, rc);
    /* QoS 0 never acknowledges, with or without the fix. */
    ASSERT_FALSE(g_pubresp_written);
}

/* #6217 (QoS 2): a QoS 2 incoming PUBLISH with no msg_cb must error without
 * sending the PUBREC. QoS 2 is where the suppressed acknowledgement matters
 * most: a false PUBREC starts a delivery handshake the broker then completes
 * for a message the application never received. */
TEST(wait_message_qos2_null_msg_cb_errors_no_ack)
{
    int rc;
    /* v3.1.1 QoS2 PUBLISH: type|qos2=0x34, remain=7, topic "a" (0x0001 'a'),
     * packet_id=9 (0x0009), payload "hi". */
    static const byte publish_qos2[] = { 0x34, 0x07, 0x00, 0x01, 'a',
                                         0x00, 0x09, 'h', 'i' };

    rc = run_wait_message_with_frame(publish_qos2, (int)sizeof(publish_qos2));

    /* Pre-fix this returned MQTT_CODE_SUCCESS. */
    ASSERT_EQ(MQTT_CODE_ERROR_CALLBACK, rc);
    /* No PUBREC may be sent: pre-fix one was, falsely starting a QoS 2
     * handshake for a dropped message. */
    ASSERT_FALSE(g_pubresp_written);
}

#ifdef WOLFMQTT_V5
/* #6217 property-leak regression: a v5 incoming PUBLISH carrying properties must
 * not leak its retained property list when there is no msg_cb. The decoder keeps
 * the property list to be freed after the callback; on the no-callback error
 * path MqttClient_HandlePacket must still free it (skipping the free leaked the
 * static property pool, or the heap under WOLFMQTT_DYN_PROP). Asserts the error
 * is returned, no PUBACK is sent, and the retained property list was released.
 * Uses protocol level 5 so the property bytes are actually parsed (the shared
 * helper forces level 4 to keep its frames v3.1.1). */
TEST(wait_message_v5_props_null_msg_cb_frees_props)
{
    int rc;
    int i;
    /* v5 QoS1 PUBLISH: type|qos1=0x32, remain=0x0A, topic "a" (0x0001 'a'),
     * packet_id=9 (0x0009), prop_len=2, Payload Format Indicator (0x01)=0,
     * payload "hi". */
    static const byte publish_v5[] = { 0x32, 0x0A, 0x00, 0x01, 'a',
                                       0x00, 0x09, 0x02, 0x01, 0x00,
                                       'h', 'i' };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;

    g_pubresp_written = 0;
    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, publish_v5, sizeof(publish_v5));
    g_canned_len = (int)sizeof(publish_v5);
    g_canned_pos = 0;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 20 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_WaitMessage(&test_client, TEST_CMD_TIMEOUT_MS);
    }

    ASSERT_EQ(MQTT_CODE_ERROR_CALLBACK, rc);
    ASSERT_FALSE(g_pubresp_written);
    /* The retained v5 property list must have been freed on the error path;
     * pre-fix it leaked, leaving publish->props non-NULL. */
    ASSERT_NULL(test_client.msg.publish.props);
}
#endif /* WOLFMQTT_V5 */

/* Counts deliveries for the positive-control test below. */
static int g_msg_cb_calls;
static int test_accept_message_cb(MqttClient* client, MqttMessage* msg,
    byte msg_new, byte msg_done)
{
    (void)client; (void)msg; (void)msg_new; (void)msg_done;
    g_msg_cb_calls++;
    return MQTT_CODE_SUCCESS;
}

/* Positive control for #6217: with a real msg_cb registered, an incoming QoS 1
 * PUBLISH must still be delivered to the callback AND acknowledged with a
 * PUBACK. The no-callback error is gated on msg_cb == NULL, so the normal
 * acknowledge path must be unchanged. Without this, every new test runs with a
 * NULL callback and only asserts the FALSE direction of g_pubresp_written, so a
 * regression that suppressed ACKs outright would go unnoticed. */
TEST(wait_message_qos1_with_msg_cb_delivers_and_acks)
{
    int rc;
    int i;
    /* v3.1.1 QoS1 PUBLISH: type|qos1=0x32, remain=7, topic "a" (0x0001 'a'),
     * packet_id=7 (0x0007), payload "hi". */
    static const byte publish_qos1[] = { 0x32, 0x07, 0x00, 0x01, 'a',
                                         0x00, 0x07, 'h', 'i' };

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
#ifdef WOLFMQTT_V5
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif
    /* Register a real callback so the normal deliver-and-ACK path is taken. */
    test_client.msg_cb = test_accept_message_cb;
    g_msg_cb_calls = 0;

    g_pubresp_written = 0;
    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, publish_qos1, sizeof(publish_qos1));
    g_canned_len = (int)sizeof(publish_qos1);
    g_canned_pos = 0;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 20 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_WaitMessage(&test_client, TEST_CMD_TIMEOUT_MS);
    }

    /* The message was delivered to the callback and the PUBACK was sent. */
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_TRUE(g_msg_cb_calls > 0);
    ASSERT_TRUE(g_pubresp_written);
}

/* Stage `frame` as a server-pushed PUBLISH and drive MqttClient_WaitMessage
 * with a real msg_cb registered, so the message is delivered and the QoS
 * acknowledgement (if any) reaches the wire. The shared run_wait_message_with_
 * frame helper leaves msg_cb NULL, which now short-circuits with an error before
 * the ack selector runs, so it cannot observe which ack a received PUBLISH
 * produces; this variant can. Returns the terminal result. */
static int run_wait_publish_delivered(const byte* frame, int frame_len)
{
    int rc;
    int i;

    rc = test_init_client();
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#ifdef WOLFMQTT_V5
    /* Decode the v3.1.1-format frames below without expecting v5 properties. */
    test_client.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif
    test_client.msg_cb = test_accept_message_cb;
    g_msg_cb_calls = 0;

    g_pubresp_written = 0;
    g_last_ack_written = MQTT_PACKET_TYPE_RESERVED;
    g_last_ack_id = 0;
    g_frames_written = 0;
    test_net.write = mock_net_write_accept;
    test_net.read = mock_net_read_canned;
    XMEMCPY(g_canned_buf, frame, (size_t)frame_len);
    g_canned_len = frame_len;
    g_canned_pos = 0;

    rc = MQTT_CODE_CONTINUE;
    for (i = 0; i < 20 && rc == MQTT_CODE_CONTINUE; i++) {
        rc = MqttClient_WaitMessage(&test_client, TEST_CMD_TIMEOUT_MS);
    }
    return rc;
}

/* An incoming PUBLISH is acknowledged, and with which packet type, purely by its
 * QoS. MqttClient_HandlePacket decides this in two steps: it short-circuits with
 * `if (packet_qos == MQTT_QOS_0) break;` before any ack, then selects the ack
 * type with `resp->packet_type = (packet_qos == MQTT_QOS_1) ? PUBACK : PUBREC`.
 * The three tests below pin one QoS each and assert the exact ack the client put
 * on the wire. The mutations they catch:
 *   - `== MQTT_QOS_0` -> `!= MQTT_QOS_0`: a QoS 1/2 PUBLISH takes the no-ack
 *     break and is never acknowledged (caught by the QoS 1 and QoS 2 cases),
 *     while a QoS 0 PUBLISH falls through to emit a spurious PUBREC (caught by
 *     the QoS 0 case).
 *   - `== MQTT_QOS_1` -> `== MQTT_QOS_2`: a QoS 1 PUBLISH is acknowledged with a
 *     PUBREC, breaking the QoS 1 handshake (caught by the QoS 1 case).
 *   - Swapping the selector branches: QoS 1 emits PUBREC and QoS 2 emits PUBACK
 *     (caught by both the QoS 1 and QoS 2 cases).
 * The QoS 1 positive control above only checks g_pubresp_written, which both
 * PUBACK and PUBREC set, so it cannot tell the two ack types apart; these read
 * back the exact type and the echoed packet id. */
TEST(wait_message_qos0_publish_no_ack)
{
    int rc;
    /* v3.1.1 QoS0 PUBLISH: type=0x30, remain=5, topic "a" (0x0001 'a'),
     * payload "hi" (no packet id for QoS 0). */
    static const byte publish_qos0[] = { 0x30, 0x05, 0x00, 0x01, 'a', 'h', 'i' };

    rc = run_wait_publish_delivered(publish_qos0, (int)sizeof(publish_qos0));

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_TRUE(g_msg_cb_calls > 0);
    /* QoS 0 carries no acknowledgement. Nothing of any type may reach the
     * wire; inverting the QoS 0 guard would emit a spurious PUBREC here. */
    ASSERT_EQ(MQTT_PACKET_TYPE_RESERVED, g_last_ack_written);
    ASSERT_EQ(0, g_frames_written);
}

TEST(wait_message_qos1_publish_acks_puback)
{
    int rc;
    /* v3.1.1 QoS1 PUBLISH: type|qos1=0x32, remain=7, topic "a" (0x0001 'a'),
     * packet_id=7 (0x0007), payload "hi". */
    static const byte publish_qos1[] = { 0x32, 0x07, 0x00, 0x01, 'a',
                                         0x00, 0x07, 'h', 'i' };

    rc = run_wait_publish_delivered(publish_qos1, (int)sizeof(publish_qos1));

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_TRUE(g_msg_cb_calls > 0);
    /* QoS 1 completes in one step: a PUBACK echoing the PUBLISH packet id. */
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_ACK, g_last_ack_written);
    ASSERT_EQ(7, g_last_ack_id);
}

TEST(wait_message_qos2_publish_acks_pubrec)
{
    int rc;
    /* v3.1.1 QoS2 PUBLISH: type|qos2=0x34, remain=7, topic "a" (0x0001 'a'),
     * packet_id=9 (0x0009), payload "hi". */
    static const byte publish_qos2[] = { 0x34, 0x07, 0x00, 0x01, 'a',
                                         0x00, 0x09, 'h', 'i' };

    rc = run_wait_publish_delivered(publish_qos2, (int)sizeof(publish_qos2));

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_TRUE(g_msg_cb_calls > 0);
    /* QoS 2 opens the handshake with a PUBREC echoing the PUBLISH packet id. */
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_REC, g_last_ack_written);
    ASSERT_EQ(9, g_last_ack_id);
}

/* The four PUBLISH-response packet types (PUBACK 4, PUBREC 5, PUBREL 6,
 * PUBCOMP 7) all decode through the same branch of MqttClient_HandlePacket, but
 * only PUBREC and PUBREL may advance the QoS handshake. The branch gates this
 * with `if (type != PUBREC && type != PUBREL) break;` before the
 * `resp->packet_type = type + 1` next-ack arithmetic, so an incoming:
 *   - PUBREC  (5) must emit a PUBREL  (6),
 *   - PUBREL  (6) must emit a PUBCOMP (7),
 *   - PUBACK  (4) must emit nothing (a QoS 1 transaction is already complete;
 *     advancing would put a spurious PUBREC on the wire), and
 *   - PUBCOMP (7) must emit nothing (a QoS 2 transaction is complete).
 * Each test drives one response type through MqttClient_WaitMessage and checks
 * the exact ack the client wrote. The mutations these catch:
 *   - Deleting the filter is caught by the PUBACK case: type 4 then advances to
 *     type 5 PUBREC, a valid pub-resp frame, which is written to the wire.
 *   - Widening the filter (&& -> ||, or == in place of one !=) is caught by the
 *     PUBREC and PUBREL cases: the handshake stops advancing and no PUBREL or
 *     PUBCOMP is emitted.
 * The PUBCOMP case cannot detect filter deletion on its own: a deleted filter
 * computes type 8 SUBSCRIBE, which the MqttIsPubRespPacket gate in
 * MqttClient_WaitType (src/mqtt_client.c) refuses to write, so nothing reaches
 * the wire either way. It still pins the correct terminal no-ack behavior and,
 * via g_frames_written, would catch any change that turned a PUBCOMP into an
 * outbound frame. The shared helper forces protocol level 4 so these v3.1.1
 * frames carry no reason code or properties. */
TEST(wait_message_pubrec_emits_pubrel)
{
    int rc;
    /* PUBREC v3.1.1: type=0x50, remain=2, packet_id=5. */
    static const byte pubrec[] = { 0x50, 0x02, 0x00, 0x05 };

    rc = run_wait_message_with_frame(pubrec, (int)sizeof(pubrec));

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_REL, g_last_ack_written);
}

TEST(wait_message_pubrel_emits_pubcomp)
{
    int rc;
    /* PUBREL v3.1.1: type=0x62 (reserved flags 0x2 are required for PUBREL),
     * remain=2, packet_id=6. */
    static const byte pubrel[] = { 0x62, 0x02, 0x00, 0x06 };

    rc = run_wait_message_with_frame(pubrel, (int)sizeof(pubrel));

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_PACKET_TYPE_PUBLISH_COMP, g_last_ack_written);
}

TEST(wait_message_puback_emits_no_ack)
{
    int rc;
    /* PUBACK v3.1.1: type=0x40, remain=2, packet_id=4. */
    static const byte puback[] = { 0x40, 0x02, 0x00, 0x04 };

    rc = run_wait_message_with_frame(puback, (int)sizeof(puback));

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_PACKET_TYPE_RESERVED, g_last_ack_written);
    /* Nothing of any type may reach the wire. Pre-fix (filter deleted) a
     * spurious PUBREC was emitted here. */
    ASSERT_EQ(0, g_frames_written);
}

TEST(wait_message_pubcomp_emits_no_ack)
{
    int rc;
    /* PUBCOMP v3.1.1: type=0x70, remain=2, packet_id=7. */
    static const byte pubcomp[] = { 0x70, 0x02, 0x00, 0x07 };

    rc = run_wait_message_with_frame(pubcomp, (int)sizeof(pubcomp));

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(MQTT_PACKET_TYPE_RESERVED, g_last_ack_written);
    /* A completed QoS 2 transaction emits no further frame of any type. */
    ASSERT_EQ(0, g_frames_written);
}

/* ============================================================================
 * MqttClient_ReturnCodeToString Tests
 * ============================================================================ */

#ifndef WOLFMQTT_NO_ERROR_STRINGS
TEST(return_code_to_string_success)
{
    const char* str;

    str = MqttClient_ReturnCodeToString(MQTT_CODE_SUCCESS);
    ASSERT_NOT_NULL(str);
    /* Should contain "Success" or similar */
    ASSERT_TRUE(str[0] != '\0');
}

TEST(return_code_to_string_bad_arg)
{
    const char* str;

    str = MqttClient_ReturnCodeToString(MQTT_CODE_ERROR_BAD_ARG);
    ASSERT_NOT_NULL(str);
    ASSERT_TRUE(str[0] != '\0');
}

TEST(return_code_to_string_network)
{
    const char* str;

    str = MqttClient_ReturnCodeToString(MQTT_CODE_ERROR_NETWORK);
    ASSERT_NOT_NULL(str);
    ASSERT_TRUE(str[0] != '\0');
}
#endif /* WOLFMQTT_NO_ERROR_STRINGS */

/* ============================================================================
 * MqttClient_Flags Tests
 * ============================================================================ */

TEST(client_flags_set_clear)
{
    int rc;
    word32 flags;

    rc = test_init_client();
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);

    /* Initially no flags should be set */
    flags = MqttClient_Flags(&test_client, 0, 0);
    ASSERT_EQ(0, (int)(flags & MQTT_CLIENT_FLAG_IS_CONNECTED));

    /* Set connected flag */
    flags = MqttClient_Flags(&test_client, 0, MQTT_CLIENT_FLAG_IS_CONNECTED);
    ASSERT_TRUE((flags & MQTT_CLIENT_FLAG_IS_CONNECTED) != 0);

    /* Clear connected flag */
    flags = MqttClient_Flags(&test_client, MQTT_CLIENT_FLAG_IS_CONNECTED, 0);
    ASSERT_EQ(0, (int)(flags & MQTT_CLIENT_FLAG_IS_CONNECTED));
}

/* ============================================================================
 * Test Suite Runner
 * ============================================================================ */

void run_mqtt_client_tests(void)
{
    TEST_SUITE_BEGIN("mqtt_client", setup, teardown);

    /* MqttClient_Init tests */
    RUN_TEST(init_null_client);
    RUN_TEST(init_null_tx_buf);
    RUN_TEST(init_zero_tx_buf_len);
    RUN_TEST(init_null_rx_buf);
    RUN_TEST(init_zero_rx_buf_len);
    RUN_TEST(init_success);
    RUN_TEST(init_negative_tx_buf_len);
    RUN_TEST(init_negative_rx_buf_len);

    /* MqttClient_DeInit tests */
    RUN_TEST(deinit_null_client);
    RUN_TEST(deinit_after_init);

    /* MqttClient_Connect tests */
    RUN_TEST(connect_null_client);
    RUN_TEST(connect_null_connect);
    RUN_TEST(connect_both_null);
    RUN_TEST(connect_with_mock_network);
    RUN_TEST(connect_clears_tx_buf_credentials);
    RUN_TEST(connect_accepted_connack_returns_success);
    RUN_TEST(connect_refused_connack_returns_connect_refused);
#if defined(WOLFMQTT_V5)
    RUN_TEST(connect_accepted_connack_latches_v5_props);
    RUN_TEST(connect_v5_scrubs_connack_auth_data_from_rx_buf);
    RUN_TEST(connect_refused_connack_preserves_v5_defaults);
    RUN_TEST(connect_accepted_connack_clamps_illegal_max_qos);
#endif

    /* MqttClient_Disconnect tests */
    RUN_TEST(disconnect_null_client);

    /* MqttClient_GetProtocolVersion tests */
    RUN_TEST(get_protocol_version_default);
    RUN_TEST(get_protocol_version_string);

    /* MqttClient_Ping tests */
    RUN_TEST(ping_null_client);

    /* MqttClient_Subscribe tests */
    RUN_TEST(subscribe_null_client);
    RUN_TEST(subscribe_null_subscribe);
    RUN_TEST(subscribe_broker_rejection_returns_subscribe_rejected);
#ifdef WOLFMQTT_V5
    RUN_TEST(unsubscribe_broker_rejection_returns_unsubscribe_rejected);
#endif

    /* MqttClient_Unsubscribe tests */
    RUN_TEST(unsubscribe_null_client);
    RUN_TEST(unsubscribe_null_unsubscribe);

    /* MqttClient_Publish tests */
    RUN_TEST(publish_null_client);
    RUN_TEST(publish_null_publish);
#ifdef WOLFMQTT_V5
    RUN_TEST(publish_qos1_v5_broker_rejection_returns_publish_rejected);
    RUN_TEST(publish_qos1_v5_success_returns_success);
    RUN_TEST(publish_qos1_v5_no_matching_subscribers_returns_success);
    RUN_TEST(publish_qos2_v5_broker_rejection_returns_publish_rejected);
    RUN_TEST(publish_qos2_v5_success_returns_success);
    RUN_TEST(publish_qos2_v5_pubrec_rejection_returns_publish_rejected);
    RUN_TEST(publish_v311_ack_not_misread_as_rejected);
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_NONBLOCK)
    RUN_TEST(publish_qos2_v5_pubrec_rejection_multithread_reader);
#endif
#endif
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_NONBLOCK)
    RUN_TEST(publish_writeonly_rejects_duplicate_in_flight_packet_id);
    RUN_TEST(subscribe_in_flight_blocks_publish_with_same_packet_id);
#endif

    /* MqttClient_WaitMessage tests */
    RUN_TEST(wait_message_null_client);
    RUN_TEST(wait_message_qos1_null_msg_cb_errors_no_ack);
    RUN_TEST(wait_message_qos0_null_msg_cb_errors);
    RUN_TEST(wait_message_qos2_null_msg_cb_errors_no_ack);
#ifdef WOLFMQTT_V5
    RUN_TEST(wait_message_v5_props_null_msg_cb_frees_props);
#endif
    RUN_TEST(wait_message_qos1_with_msg_cb_delivers_and_acks);
    RUN_TEST(wait_message_qos0_publish_no_ack);
    RUN_TEST(wait_message_qos1_publish_acks_puback);
    RUN_TEST(wait_message_qos2_publish_acks_pubrec);
    RUN_TEST(wait_message_pubrec_emits_pubrel);
    RUN_TEST(wait_message_pubrel_emits_pubcomp);
    RUN_TEST(wait_message_puback_emits_no_ack);
    RUN_TEST(wait_message_pubcomp_emits_no_ack);

#ifndef WOLFMQTT_NO_ERROR_STRINGS
    /* MqttClient_ReturnCodeToString tests */
    RUN_TEST(return_code_to_string_success);
    RUN_TEST(return_code_to_string_bad_arg);
    RUN_TEST(return_code_to_string_network);
#endif

    /* MqttClient_Flags tests */
    RUN_TEST(client_flags_set_clear);

    TEST_SUITE_END();
}
