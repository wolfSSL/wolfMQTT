/* test_broker_connect.c
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

/* Standalone unit tests for the broker CONNECT handler.
 *
 * mqtt_broker.c is built into this binary with WOLFMQTT_BROKER_CUSTOM_NET so
 * the default sockets layer is replaced with in-process mock callbacks. The
 * harness feeds a hand-built CONNECT packet through MqttBroker_Step() and
 * captures the CONNACK bytes the broker writes back, so we can assert on the
 * return code and properties without spinning up a real broker.
 *
 * These tests pin the [MQTT-3.1.3-6] / [MQTT-3.1.3-8] zero-length ClientId
 * rules: v3.1.1 + clean=0 + empty ID must be refused with CONNACK 0x02;
 * v3.1.1 + clean=1 + empty ID must be accepted; v5 still emits the Assigned
 * Client Identifier property.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_broker.h"
#include "wolfmqtt/mqtt_packet.h"

/* Provide storage for the unit-test framework's global counters. Must be
 * defined before unit_test.h is included. */
#define UNIT_TEST_IMPLEMENTATION
#include "tests/unit_test.h"

/* Mock socket constants */
#define MOCK_LISTEN_SOCK       100
#define MOCK_CLIENT_SOCK_BASE  101 /* sock = base + index */
#define MOCK_BUF_SZ            1024
#define MOCK_MAX_CLIENTS       4

/* Per-mock-client state. Multi-client tests (e.g. QoS 2 dedup) need a
 * subscriber and a publisher running through the same broker instance. */
typedef struct MockClient {
    byte   in_buf[MOCK_BUF_SZ];
    size_t in_len;
    size_t in_pos;
    byte   out_buf[MOCK_BUF_SZ];
    size_t out_len;
    int    closed;
    int    read_err; /* when set, mock_read returns a network error (peer RST) */
    int    write_err; /* when set, mock_write returns a network error */
} MockClient;

static MockClient g_clients[MOCK_MAX_CLIENTS];
static int g_clients_active;   /* how many clients accept() will hand out */
static int g_accept_count;     /* incremented per successful accept() */

/* Legacy single-client tests use g_in_buf / g_out_buf / g_client_closed
 * directly. Map them to client 0 so existing code keeps working. */
#define g_in_buf         (g_clients[0].in_buf)
#define g_in_len         (g_clients[0].in_len)
#define g_in_pos         (g_clients[0].in_pos)
#define g_out_buf        (g_clients[0].out_buf)
#define g_out_len        (g_clients[0].out_len)
#define g_client_closed  (g_clients[0].closed)

static int sock_to_idx(BROKER_SOCKET_T sock)
{
    int idx = (int)(sock - MOCK_CLIENT_SOCK_BASE);
    if (idx < 0 || idx >= MOCK_MAX_CLIENTS) {
        return -1;
    }
    return idx;
}

/* -------------------------------------------------------------------------- */
/* Mock network callbacks                                                      */
/* -------------------------------------------------------------------------- */

static int mock_listen(void* ctx, BROKER_SOCKET_T* sock,
    word16 port, int backlog)
{
    (void)ctx; (void)port; (void)backlog;
    *sock = MOCK_LISTEN_SOCK;
    return MQTT_CODE_SUCCESS;
}

static int mock_accept(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock)
{
    (void)ctx; (void)listen_sock;
    if (g_accept_count < g_clients_active) {
        *client_sock =
            (BROKER_SOCKET_T)(MOCK_CLIENT_SOCK_BASE + g_accept_count);
        g_accept_count++;
        return MQTT_CODE_SUCCESS;
    }
    return MQTT_CODE_ERROR_TIMEOUT;
}

static int mock_read(void* ctx, BROKER_SOCKET_T sock,
    byte* buf, int buf_len, int timeout_ms)
{
    int avail;
    int idx = sock_to_idx(sock);
    MockClient* mc;
    (void)ctx; (void)timeout_ms;
    if (idx < 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    mc = &g_clients[idx];
    if (mc->read_err) {
        return MQTT_CODE_ERROR_NETWORK; /* simulate peer RST / abrupt FIN */
    }
    if (mc->closed || mc->in_pos >= mc->in_len) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    avail = (int)(mc->in_len - mc->in_pos);
    if (buf_len > avail) {
        buf_len = avail;
    }
    XMEMCPY(buf, mc->in_buf + mc->in_pos, (size_t)buf_len);
    mc->in_pos += (size_t)buf_len;
    return buf_len;
}

static int mock_write(void* ctx, BROKER_SOCKET_T sock,
    const byte* buf, int buf_len, int timeout_ms)
{
    int idx = sock_to_idx(sock);
    MockClient* mc;
    (void)ctx; (void)timeout_ms;
    if (idx < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    mc = &g_clients[idx];
    if (mc->out_len + (size_t)buf_len > sizeof(mc->out_buf)) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    /* Capture the bytes handed to the socket even when simulating a failure,
     * so a test can positively assert what the broker produced (i.e. that a
     * scrub target was actually written) before checking it was scrubbed. */
    XMEMCPY(mc->out_buf + mc->out_len, buf, (size_t)buf_len);
    mc->out_len += (size_t)buf_len;
    if (mc->write_err) {
        return MQTT_CODE_ERROR_NETWORK; /* simulate a hard write failure */
    }
    return buf_len;
}

static int mock_close(void* ctx, BROKER_SOCKET_T sock)
{
    int idx = sock_to_idx(sock);
    (void)ctx;
    if (idx >= 0) {
        g_clients[idx].closed = 1;
    }
    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Test fixture                                                                */
/* -------------------------------------------------------------------------- */

static void reset_mock_clients(int n_clients)
{
    int i;
    for (i = 0; i < MOCK_MAX_CLIENTS; i++) {
        XMEMSET(&g_clients[i], 0, sizeof(g_clients[i]));
    }
    g_clients_active = n_clients;
    g_accept_count = 0;
}

/* Append bytes to a client's input queue (i.e., what it appears to send to
 * the broker). May be called multiple times to feed packets in stages. */
static void mock_client_input_append(int idx, const byte* buf, size_t len)
{
    MockClient* mc = &g_clients[idx];
    if (mc->in_len + len > sizeof(mc->in_buf)) return;
    XMEMCPY(mc->in_buf + mc->in_len, buf, len);
    mc->in_len += len;
}

static void reset_mock_state(const byte* connect_buf, size_t connect_len)
{
    reset_mock_clients(1);
    if (connect_buf && connect_len > 0) {
        mock_client_input_append(0, connect_buf, connect_len);
    }
}

static void install_mock_net(MqttBrokerNet* net)
{
    XMEMSET(net, 0, sizeof(*net));
    net->listen = mock_listen;
    net->accept = mock_accept;
    net->read   = mock_read;
    net->write  = mock_write;
    net->close  = mock_close;
}

/* Drive the broker through enough Step() calls to consume the CONNECT and
 * emit the CONNACK. The first Step() accepts the client; the second reads
 * and dispatches the CONNECT, which writes the CONNACK and may close. */
static void run_broker_one_connect(MqttBroker* broker)
{
    int i;
    for (i = 0; i < 4; i++) {
        MqttBroker_Step(broker);
        if (g_in_pos >= g_in_len && g_out_len > 0) {
            break;
        }
    }
}

static void setup(void)    { }
static void teardown(void) { }

/* -------------------------------------------------------------------------- */
/* CONNECT wire helpers                                                        */
/* -------------------------------------------------------------------------- */

/* Build a v3.1.1 CONNECT packet with zero-length ClientId.
 *   Fixed header: 0x10, remain=12
 *   Variable header: protocol "MQTT" (4), level 4, flags, keepalive=60
 *   Payload: ClientId length 0x0000 (no bytes)
 * The connect_flags byte encodes CleanSession in bit 1 (0x02). */
static size_t build_v311_connect_emptyid(byte* out, byte connect_flags)
{
    static const byte tmpl[] = {
        0x10, 12,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x00, /* connect_flags placeholder */
        0x00, 0x3C,
        0x00, 0x00
    };
    XMEMCPY(out, tmpl, sizeof(tmpl));
    out[9] = connect_flags;
    return sizeof(tmpl);
}

#ifdef WOLFMQTT_V5
/* Build a v5 CONNECT packet with zero-length ClientId.
 *   Fixed header: 0x10, remain=13
 *   Variable header: "MQTT" (4), level 5, flags, keepalive=60, props_len=0
 *   Payload: ClientId length 0x0000 */
static size_t build_v5_connect_emptyid(byte* out, byte connect_flags)
{
    static const byte tmpl[] = {
        0x10, 13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x00, /* connect_flags placeholder */
        0x00, 0x3C,
        0x00, /* properties length = 0 */
        0x00, 0x00
    };
    XMEMCPY(out, tmpl, sizeof(tmpl));
    out[9] = connect_flags;
    return sizeof(tmpl);
}
#endif

/* -------------------------------------------------------------------------- */
/* Tests                                                                       */
/* -------------------------------------------------------------------------- */

/* [MQTT-3.1.3-8] v3.1.1: zero-length ClientId with CleanSession=0 must be
 * rejected with CONNACK reason 0x02 (Identifier rejected) and the network
 * connection must be closed. */
TEST(connect_v311_emptyid_clean0_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[64];
    size_t connect_len;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* connect_flags = 0x00: CleanSession=0, no will, no auth */
    connect_len = build_v311_connect_emptyid(connect, 0x00);
    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    /* CONNACK: 0x20 0x02 0x00 0x02
     * byte[0] = CONNACK type+flags
     * byte[1] = remaining length (2 in v3.1.1)
     * byte[2] = session-present flag (must be 0 for any non-zero return)
     * byte[3] = return code 0x02 = Identifier rejected */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_ID, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.1.3-6] v3.1.1: zero-length ClientId with CleanSession=1 must be
 * accepted, and the broker MUST assign a unique ClientId server-side. v3.1.1
 * has no protocol field for echoing the assigned ID, so we verify the
 * assignment ran by checking that broker->next_auto_id advanced. */
TEST(connect_v311_emptyid_clean1_accepted)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[64];
    size_t connect_len;
    word32 auto_id_before;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    auto_id_before = broker.next_auto_id;

    /* connect_flags = 0x02: CleanSession=1 */
    connect_len = build_v311_connect_emptyid(connect, 0x02);
    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_out_buf[3]);
    ASSERT_FALSE(g_client_closed);
    /* The auto-id branch must have run (counter advanced). Catches a
     * regression where BROKER_STORE_STR silently no-ops or the v3.1.1 path
     * gets re-gated to v5-only. */
    ASSERT_TRUE(broker.next_auto_id > auto_id_before);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Sanity: a normal v3.1.1 CONNECT with a non-empty ClientId is accepted
 * regardless of CleanSession. Pins that the new empty-ID checks didn't
 * regress the normal path. */
TEST(connect_v311_nonempty_clean0_accepted)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* Same as build_v311_connect_emptyid but with ClientId "id" (2 bytes).
     * Remaining length grows by 2; ClientId length field becomes 0x0002. */
    byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x00, /* CleanSession = 0 */
        0x00, 0x3C,
        0x00, 0x02, 'i', 'd'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_out_buf[3]);
    ASSERT_FALSE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* The broker reserves the "auto-" prefix for server-assigned IDs. An
 * explicit client_id starting with "auto-" must be refused, otherwise an
 * attacker could observe their own assigned ID, predict a future value, and
 * collide with a victim via the duplicate-takeover path. */
TEST(connect_v311_explicit_auto_prefix_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* CONNECT with client_id "auto-foo" (8 bytes). Remaining = 12 (header) + 8.
     * ClientId length field = 0x0008. */
    byte connect[] = {
        0x10, 20,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02, /* CleanSession = 1 */
        0x00, 0x3C,
        0x00, 0x08, 'a', 'u', 't', 'o', '-', 'f', 'o', 'o'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_ID, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.1.2-2] Unsupported Protocol Level must be refused with CONNACK
 * 0x01 (REFUSED_PROTO) followed by disconnect. The CONNACK MUST come back
 * in v3.1.1 wire shape (4 bytes: type, remain=2, flags, code) regardless
 * of the level the client claimed - we don't know what their wire format
 * actually is, and the spec text specifies "CONNACK return code 0x01"
 * verbatim.
 *
 * Cases below mirror the dynamic test evidence in the issue report:
 *   level 0x03 -> refused
 *   level 0x06 -> refused (and not silently accepted as v5 just because
 *                          the encoder uses level >= 5 as a mode switch).
 */
static void run_unsupported_level(byte level)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* Wire matches the reporter's case for level X with ClientId "A":
     *   10 0d 00 04 4d 51 54 54 LL 02 00 3c 00 01 41
     * (15 bytes total: fixed header 2 + remain 13 = type+nameLen+name+
     *  level+flags+keepalive+idLen+id) */
    byte connect[] = {
        0x10, 13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x00, /* protocol_level placeholder */
        0x02, /* CleanSession=1 */
        0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    connect[8] = level;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    /* Expect a v3.1.1-shaped CONNACK: 0x20, 0x02, flags, REFUSED_PROTO.
     * [MQTT-3.1.2-2] mandates 0x01 for any unsupported level regardless of
     * what the client claimed they spoke. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_PROTO, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(connect_unsupported_level_3_refused)
{
    run_unsupported_level(0x03);
}

TEST(connect_unsupported_level_6_refused)
{
    /* Catches the secondary issue the reporter flagged in section 3 of #496:
     * pre-fix MqttDecode_Connect treated `protocol_level >= 5` as v5, so for
     * level 6 the decoder consumed the byte at the v5 props_len position
     * (0x00 here, parsed as zero-length props), then read the next two bytes
     * (0x00 0x01) as the ClientId length prefix and 'A' as the start of a
     * 1-byte ClientId. With WOLFMQTT_V5 the decoder still returned success
     * for this particular wire, but it produced a misaligned MqttConnect with
     * ClientId="" - so the test below also fails on the post-decode path
     * unless the broker's [MQTT-3.1.2-2] check rejects the level. (For wires
     * without enough trailing bytes, the pre-fix decoder instead returned
     * OUT_OF_BUFFER and never emitted a CONNACK at all, which would also
     * fail the `g_out_len >= 4` assertion.) Either way, this test pins the
     * fix at both layers. */
    run_unsupported_level(0x06);
}

TEST(connect_unsupported_level_127_refused)
{
    /* Top of the byte range - guards against a future "treat high values
     * as latest known" mutation. */
    run_unsupported_level(0x7F);
}

#ifdef WOLFMQTT_BROKER_AUTH
/* Regression: [MQTT-3.1.3.5] Password is Binary Data and may legally
 * contain 0x00. The broker must not use XSTRLEN-based length recovery on
 * bc->password, which would truncate at the first embedded NUL and turn
 * the constant-time auth compare into a prefix compare - letting a
 * client that sends "abc\0<anything>" authenticate against auth_pass
 * "abc". The fix tracks bc->password_len explicitly. */
TEST(connect_v311_binary_password_with_embedded_nul_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* CONNECT v3.1.1, username="user", password = "abc\0xyz" (7 bytes,
     * embedded NUL at offset 3). Configured auth_pass is "abc"; under
     * XSTRLEN truncation, the broker would read bc->password as "abc"
     * and authenticate the client. With password_len tracking, the
     * length mismatch (3 vs 7) is folded into the compare and auth
     * fails. */
    static const byte connect[] = {
        0x10, 29,                                  /* fixed header */
        0x00, 0x04, 'M', 'Q', 'T', 'T',            /* protocol name */
        0x04,                                      /* level 4 (v3.1.1) */
        0xC2,                                      /* flags: user+pass+clean */
        0x00, 0x3C,                                /* keep-alive 60 */
        0x00, 0x02, 'i', 'd',                      /* ClientId "id" */
        0x00, 0x04, 'u', 's', 'e', 'r',            /* Username "user" */
        0x00, 0x07, 'a', 'b', 'c', 0x00,           /* Password binary, */
        'x', 'y', 'z'                              /*   length 7 */
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = "user";
    broker.auth_pass = "abc";
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    /* Auth must fail - CONNACK return code 0x04 (Bad user/pass) and the
     * connection is closed. Pre-fix, XSTRLEN truncation would let this
     * authenticate and emit return code 0x00. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Companion: a binary password that exactly matches the configured
 * auth_pass bytes still authenticates. Pins that the length-aware
 * compare doesn't over-correct and break the equal-length case. */
TEST(connect_v311_binary_password_exact_match_accepted)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* password = "abc" (3 bytes, no embedded NUL); auth_pass = "abc". */
    static const byte connect[] = {
        0x10, 25,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0xC2,
        0x00, 0x3C,
        0x00, 0x02, 'i', 'd',
        0x00, 0x04, 'u', 's', 'e', 'r',
        0x00, 0x03, 'a', 'b', 'c'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = "user";
    broker.auth_pass = "abc";
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_out_buf[3]);
    ASSERT_FALSE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Guard the length-fold backstop in BrokerBufCompare. The constant-time
 * byte loop clamps an out-of-range index to position 0, so it cannot see a
 * length mismatch when the shorter input's bytes repeat through the longer
 * one. Username "a" against configured "aaaaa" must be refused by the length
 * fold alone; deleting the fold would authenticate it. */
TEST(connect_auth_username_length_fold_repeating_byte_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* CONNECT v3.1.1, ClientId "id", Username "a" (len 1), Password
     * "aaaaa" (len 5, exact match for auth_pass). connect_flags 0xC2 =
     * username + password + clean session. */
    static const byte connect[] = {
        0x10, 24,                                  /* fixed header, rl 24 */
        0x00, 0x04, 'M', 'Q', 'T', 'T',            /* protocol name */
        0x04,                                      /* level 4 (v3.1.1) */
        0xC2,                                      /* flags: user+pass+clean */
        0x00, 0x3C,                                /* keep-alive 60 */
        0x00, 0x02, 'i', 'd',                      /* ClientId "id" */
        0x00, 0x01, 'a',                           /* Username "a" */
        0x00, 0x05, 'a', 'a', 'a', 'a', 'a'        /* Password "aaaaa" */
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = "aaaaa";
    broker.auth_pass = "aaaaa";
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    /* Auth must fail - CONNACK return code 0x04 (Bad user/pass) and the
     * connection closed. Deleting the length fold would authenticate the
     * shorter repeating-byte username and emit return code 0x00. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* An unauthenticated CONNECT must not mutate another
 * client's session. A victim authenticates and stays connected; an attacker
 * then reuses the victim's client_id with a wrong password. The broker must
 * reject the attacker at the credential gate BEFORE the duplicate-takeover
 * path, so the victim is never disconnected. Pre-fix, takeover ran before
 * auth and closed the victim - g_clients[0].closed is the load-bearing
 * assertion. */
TEST(connect_unauth_client_id_does_not_take_over_victim)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* Victim: client_id "vic", user "user", pass "pass", CleanSession=1. */
    static const byte victim[] = {
        0x10, 0x1B,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0xC2, 0x00, 0x3C,
        0x00, 0x03, 'v', 'i', 'c',
        0x00, 0x04, 'u', 's', 'e', 'r',
        0x00, 0x04, 'p', 'a', 's', 's'
    };
    /* Attacker: same client_id "vic", user "user", WRONG pass "bad". */
    static const byte attacker[] = {
        0x10, 0x1A,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0xC2, 0x00, 0x3C,
        0x00, 0x03, 'v', 'i', 'c',
        0x00, 0x04, 'u', 's', 'e', 'r',
        0x00, 0x03, 'b', 'a', 'd'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = "user";
    broker.auth_pass = "pass";
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, victim, sizeof(victim));
    mock_client_input_append(1, attacker, sizeof(attacker));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Victim authenticated and must remain connected. */
    ASSERT_TRUE(g_clients[0].out_len >= 4);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_clients[0].out_buf[3]);
    ASSERT_FALSE(g_clients[0].closed);
    /* Attacker rejected on auth, not via session takeover. */
    ASSERT_TRUE(g_clients[1].out_len >= 4);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD,
        g_clients[1].out_buf[3]);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Regression (issue 3393): configuring only auth_user leaves the password
 * side unchecked, so any (or no) password authenticates as long as the
 * username matches. MqttBroker_Start must reject the partial config instead
 * of silently enabling single-factor auth. */
TEST(connect_auth_user_only_start_rejected)
{
    MqttBroker broker;
    MqttBrokerNet net;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = "user";
    broker.auth_pass = NULL;
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, MqttBroker_Start(&broker));

    MqttBroker_Free(&broker);
}

/* Symmetric case: only auth_pass configured must also be rejected at start. */
TEST(connect_auth_pass_only_start_rejected)
{
    MqttBroker broker;
    MqttBrokerNet net;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = NULL;
    broker.auth_pass = "pass";
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, MqttBroker_Start(&broker));

    MqttBroker_Free(&broker);
}

/* Defense in depth: the MqttBroker struct is public, so a caller can set
 * auth_user after a successful no-auth start (or ignore the start error),
 * bypassing the MqttBroker_Start pairing check. The connect-time gate must
 * still fail closed when only one credential is configured. A CONNECT whose
 * username matches but carries no password must be refused, not accepted on
 * the username alone. */
TEST(connect_auth_partial_config_fails_closed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* CONNECT v3.1.1, ClientId "id", Username "user", no password.
     * connect_flags 0x82 = username + clean session. */
    static const byte connect[] = {
        0x10, 20,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x82,
        0x00, 0x3C,
        0x00, 0x02, 'i', 'd',
        0x00, 0x04, 'u', 's', 'e', 'r'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    /* Start with auth disabled, then enable only the username post-start. */
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    broker.auth_user = "user";

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    /* Pre-fix the username matched and the absent password was never
     * checked, so the broker accepted (return code 0x00). The gate must now
     * refuse with 0x04 (Bad user/pass) and close the connection. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Symmetric defense-in-depth case: only auth_pass set post-start. Without the
 * gate, any username with a matching password authenticates (the username side
 * is never checked). A CONNECT carrying the matching password under an
 * arbitrary username must be refused, not accepted on the password alone. */
TEST(connect_auth_partial_pass_only_fails_closed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* CONNECT v3.1.1, ClientId "id", Username "anyone", Password "pass".
     * connect_flags 0xC2 = username + password + clean session. */
    static const byte connect[] = {
        0x10, 28,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0xC2,
        0x00, 0x3C,
        0x00, 0x02, 'i', 'd',
        0x00, 0x06, 'a', 'n', 'y', 'o', 'n', 'e',
        0x00, 0x04, 'p', 'a', 's', 's'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    /* Start with auth disabled, then enable only the password post-start. */
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    broker.auth_pass = "pass";

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    /* Pre-fix the password matched and the username was never checked, so the
     * broker accepted (return code 0x00). The gate must now refuse with 0x04
     * (Bad user/pass) and close the connection. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_AUTH */

#ifdef WOLFMQTT_V5
/* v5 dropped the [MQTT-3.1.3-8] CleanSession=1-only restriction; an empty
 * ClientId is acceptable with any Clean Start value. The broker MUST emit
 * the Assigned Client Identifier property in CONNACK. */
TEST(connect_v5_emptyid_assigned_id_emitted)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[64];
    size_t connect_len;
    word16 assigned_id_len;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Clean Start = 1 (bit 1) */
    connect_len = build_v5_connect_emptyid(connect, 0x02);
    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    /* v5 CONNACK layout for our small response:
     *   [0] 0x20         CONNACK type+flags
     *   [1] remaining_len (VBI; expect 1 byte for our payload)
     *   [2] session_present
     *   [3] reason_code (0x00 = Success)
     *   [4] properties_len (VBI; expect 1 byte)
     *   [5] first property tag - MUST be 0x12 (ASSIGNED_CLIENT_ID)
     *   [6..7] string length (big-endian word16)
     *   [8..]  UTF-8 string ("auto-XXXXXXXX")
     * MqttProps_Add appends to the end of the prop list (mqtt_packet.c
     * MqttProps_Add walks to the tail), and the broker adds ASSIGNED_CLIENT_
     * ID before the feature properties, so it MUST be the first tag in the
     * encoded output. */
    ASSERT_TRUE(g_out_len >= 8);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_REASON_SUCCESS, g_out_buf[3]);
    ASSERT_EQ(MQTT_PROP_ASSIGNED_CLIENT_ID, g_out_buf[5]);

    /* The string length must be non-zero and the bytes must look like our
     * "auto-" prefix. This catches a regression where the property tag is
     * present but the value isn't actually filled in. */
    assigned_id_len = (word16)((g_out_buf[6] << 8) | g_out_buf[7]);
    ASSERT_TRUE(assigned_id_len > 5);
    ASSERT_TRUE((size_t)8 + assigned_id_len <= g_out_len);
    ASSERT_EQ(0, XMEMCMP(&g_out_buf[8], "auto-", 5));
    ASSERT_FALSE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* v5: empty ClientId + Clean Start = 0 must also be accepted. v5 dropped
 * [MQTT-3.1.3-8]; the protocol_level<5 predicate in the broker's rejection
 * gate must keep this case out of the refuse path. Pins that the v5 escape
 * hatch in the gate doesn't regress. */
TEST(connect_v5_emptyid_clean0_accepted)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[64];
    size_t connect_len;
    word32 auto_id_before;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    auto_id_before = broker.next_auto_id;

    /* Clean Start = 0 */
    connect_len = build_v5_connect_emptyid(connect, 0x00);
    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 6);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_REASON_SUCCESS, g_out_buf[3]);
    ASSERT_EQ(MQTT_PROP_ASSIGNED_CLIENT_ID, g_out_buf[5]);
    ASSERT_FALSE(g_client_closed);
    ASSERT_TRUE(broker.next_auto_id > auto_id_before);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */

/* -------------------------------------------------------------------------- */
/* QoS 2 inbound duplicate-dedup tests [MQTT-4.3.3]                            */
/* -------------------------------------------------------------------------- */

/* Walk a captured packet stream and count packets whose type-nibble matches
 * `target`. Parses each fixed header's variable-length remaining length so a
 * stream of multiple packets is handled correctly. Stops scanning on any
 * malformed VBI or arithmetic overflow rather than guessing past it. */
static int count_packets_of_type(const byte* buf, size_t len, byte target)
{
    size_t pos = 0;
    int count = 0;
    while (pos < len) {
        byte type = (byte)((buf[pos] >> 4) & 0x0F);
        size_t remain = 0;
        size_t mult = 1;
        size_t hdr_len = 1;
        int vbi_complete = 0;
        while (pos + hdr_len < len && hdr_len <= 5) {
            byte b = buf[pos + hdr_len];
            remain += (size_t)(b & 0x7F) * mult;
            hdr_len++;
            if ((b & 0x80) == 0) {
                vbi_complete = 1;
                break;
            }
            mult *= 128;
        }
        if (!vbi_complete) {
            /* malformed VBI or buffer ran out mid-VBI: hard stop */
            break;
        }
        if (type == target) {
            count++;
        }
        /* Overflow-safe truncation check: hdr_len + remain must fit in
         * (len - pos) without wrapping. */
        if (remain > len - pos - hdr_len) {
            break;
        }
        pos += hdr_len + remain;
    }
    return count;
}

/* find_broker_client / the out_q-cap tests below inspect dynamic-mode-only
 * BrokerClient state (the linked client list, out_q_count); guard the whole
 * group so static-memory broker builds (where MqttBroker.clients is an array
 * and BrokerClient has no next/out_q_count) still compile. */
#ifndef WOLFMQTT_STATIC_MEMORY
/* Find the broker-side BrokerClient with the given client_id, walking the
 * dynamic-mode client list. Returns NULL if absent. Used to inspect internal
 * per-subscriber queue state (out_q_count) that has no wire-visible signal. */
static BrokerClient* find_broker_client(MqttBroker* broker, const char* id)
{
    BrokerClient* c = broker->clients;
    while (c != NULL) {
        if (c->client_id != NULL && XSTRCMP(c->client_id, id) == 0) {
            return c;
        }
        c = c->next;
    }
    return NULL;
}

#ifdef WOLFMQTT_BROKER_AUTH
/* Return 1 if the byte sequence `needle` (length nlen) appears anywhere in
 * the first hlen bytes of `hay`, else 0. Used to prove credential plaintext
 * has been scrubbed from a buffer. */
static int region_contains(const byte* hay, int hlen,
    const char* needle, int nlen)
{
    int i;
    if (hay == NULL || nlen <= 0 || hlen < nlen) {
        return 0;
    }
    for (i = 0; i + nlen <= hlen; i++) {
        if (XMEMCMP(hay + i, needle, (size_t)nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/* After an accepted CONNECT the plaintext credentials must not linger for
 * the connection lifetime. BrokerHandle_Connect scrubs bc->rx_buf and
 * bc->password on the accepted path; verify the password is gone from rx_buf
 * and bc->password_len is cleared. Dynamic-memory only. */
TEST(connect_credentials_scrubbed_after_accept)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* bc;
    /* CONNECT v3.1.1, ClientId "id", Username "alice", Password "s3cr3tPW".
     * connect_flags 0xC2 = username + password + clean session. */
    static const byte connect[] = {
        0x10, 31,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0xC2,
        0x00, 0x3C,
        0x00, 0x02, 'i', 'd',
        0x00, 0x05, 'a', 'l', 'i', 'c', 'e',
        0x00, 0x08, 's', '3', 'c', 'r', '3', 't', 'P', 'W'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = "alice";
    broker.auth_pass = "s3cr3tPW";
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    /* Auth accepted (0x00) and the client is retained. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_out_buf[3]);
    ASSERT_FALSE(g_client_closed);

    bc = find_broker_client(&broker, "id");
    ASSERT_TRUE(bc != NULL);

    /* Password copy wiped: verify the length is cleared AND the buffer bytes
     * are zeroed as independent checks - a regression that dropped only the
     * buffer wipe while keeping password_len = 0 must still be caught. The
     * dynamic store allocates password_len+1 bytes, so scanning the 8-byte
     * plaintext stays within the allocation. */
    ASSERT_EQ(0, (int)bc->password_len);
    ASSERT_EQ(0, region_contains((const byte*)bc->password, 8, "s3cr3tPW", 8));
    /* Both credential fields lived in the decoded CONNECT; neither plaintext
     * may remain in the receive buffer. Scan only the received packet region
     * (== the scrubbed rx_len); rx_buf is malloc'd without zeroing, so the
     * bytes past the packet are uninitialized and must not be read. */
    ASSERT_EQ(0, region_contains(bc->rx_buf, (int)sizeof(connect),
        "s3cr3tPW", 8));
    ASSERT_EQ(0, region_contains(bc->rx_buf, (int)sizeof(connect),
        "alice", 5));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_AUTH */

#ifdef WOLFMQTT_V5
/* Return the Reason Code byte of the first DISCONNECT packet in a captured
 * stream, or -1 if none carries a reason code. A v5 DISCONNECT with a
 * non-success reason and no properties encodes as 0xE0 <remain> <reason>;
 * the reason is the first byte of the variable header. Only referenced by the
 * v5 cap test, so it lives under WOLFMQTT_V5 to avoid an unused-function
 * warning (the build runs with -Werror -Wunused). */
static int first_disconnect_reason(const byte* buf, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        byte type = (byte)((buf[pos] >> 4) & 0x0F);
        size_t remain = 0;
        size_t mult = 1;
        size_t hdr_len = 1;
        int vbi_complete = 0;
        while (pos + hdr_len < len && hdr_len <= 5) {
            byte b = buf[pos + hdr_len];
            remain += (size_t)(b & 0x7F) * mult;
            hdr_len++;
            if ((b & 0x80) == 0) { vbi_complete = 1; break; }
            mult *= 128;
        }
        if (!vbi_complete) {
            break;
        }
        if (type == MQTT_PACKET_TYPE_DISCONNECT) {
            if (remain >= 1 && pos + hdr_len < len) {
                return buf[pos + hdr_len];
            }
            return -1;
        }
        if (remain > len - pos - hdr_len) {
            break;
        }
        pos += hdr_len + remain;
    }
    return -1;
}
#endif /* WOLFMQTT_V5 */
#endif /* !WOLFMQTT_STATIC_MEMORY */

/* [MQTT-4.3.3] / Method B: when the broker receives a duplicate QoS 2
 * PUBLISH carrying a packet ID that's still awaiting PUBREL, it MUST send
 * another PUBREC to the publisher but MUST NOT re-deliver the application
 * message to subscribers. This test wires up a subscriber and a publisher
 * through the same broker, has the publisher send the same QoS 2 PUBLISH
 * twice (the second with DUP=1), then send PUBREL, and verifies:
 *
 *   subscriber out: exactly one forwarded PUBLISH
 *   publisher out:  two PUBRECs (one per inbound PUBLISH) and one PUBCOMP
 *
 * Pre-fix the broker fanned out twice and the subscriber would see two
 * forwarded PUBLISHes, breaking exactly-once delivery. */
TEST(qos2_duplicate_publish_dedup)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int sub_pubs;
    int pub_pubrecs;
    int pub_pubcomps;

    /* CONNECT for subscriber, ClientId "A" (clean=1, level=4). */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,
        0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* CONNECT for publisher, ClientId "B". */
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0x02,
        0x00, 0x3C,
        0x00, 0x01, 'B'
    };
    /* SUBSCRIBE packet_id=1, filter "x", QoS 2. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x02
    };
    /* PUBLISH QoS 2, packet_id=7, topic "x", payload "first".
     * remain = topic_len(2) + topic(1) + packet_id(2) + payload(5) = 10 */
    static const byte publish[] = {
        0x34, 0x0A,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'f', 'i', 'r', 's', 't'
    };
    /* Duplicate PUBLISH with DUP=1, same packet_id and payload. */
    static const byte publish_dup[] = {
        0x3C, 0x0A,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'f', 'i', 'r', 's', 't'
    };
    /* PUBREL packet_id=7. */
    static const byte pubrel[] = {
        0x62, 0x02,
        0x00, 0x07
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    /* Subscriber: CONNECT then SUBSCRIBE. */
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    /* Publisher: CONNECT, PUBLISH, duplicate PUBLISH, PUBREL. */
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish, sizeof(publish));
    mock_client_input_append(1, publish_dup, sizeof(publish_dup));
    mock_client_input_append(1, pubrel, sizeof(pubrel));

    /* Run enough Step() calls for the broker to: accept both clients,
     * process subscriber's CONNECT+SUBSCRIBE (write CONNACK+SUBACK),
     * process publisher's CONNECT (write CONNACK), process PUBLISH (fan
     * out, write PUBREC), process duplicate PUBLISH (write PUBREC, no
     * fan-out), process PUBREL (write PUBCOMP). */
    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
    }

    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    pub_pubrecs = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);
    pub_pubcomps = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_COMP);

    ASSERT_EQ(1, sub_pubs);     /* dedup: only the first PUBLISH forwarded */
    ASSERT_EQ(2, pub_pubrecs);  /* one PUBREC per inbound PUBLISH */
    ASSERT_EQ(1, pub_pubcomps); /* one PUBCOMP per PUBREL */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A PUBLISH with DUP=1 whose packet_id is NOT in the dedup set must be
 * treated as a fresh delivery. The DUP flag is informational; correctness
 * is determined by the per-client dedup state, not the wire flag. This is
 * the recovering-client / cross-restart case: after the broker drops state
 * (no inflight persistence today), a client retransmitting an in-flight
 * PUBLISH with DUP=1 should still get its message delivered. */
TEST(qos2_phantom_dup_publish_is_fresh)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int sub_pubs;
    int pub_pubrecs;

    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'A'
    };
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'B'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x02
    };
    /* PUBLISH QoS 2 with DUP=1 set, but packet_id never appeared before.
     * remain = 3+2+5 = 10 */
    static const byte publish_dup_only[] = {
        0x3C, 0x0A, 0x00, 0x01, 'x', 0x00, 0x07,
        'f', 'i', 'r', 's', 't'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish_dup_only, sizeof(publish_dup_only));

    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    pub_pubrecs = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);

    /* Subscriber gets one forwarded PUBLISH; publisher gets one PUBREC.
     * The DUP flag does NOT suppress fan-out - only an actual matching
     * dedup-set entry does. */
    ASSERT_EQ(1, sub_pubs);
    ASSERT_EQ(1, pub_pubrecs);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* After PUBREL clears the awaiting-PUBREL state, a subsequent PUBLISH with
 * the same packet ID is a fresh delivery, not a duplicate. Pin the state
 * removal so a regression in BrokerInboundQos2_Remove would surface. */
TEST(qos2_publish_after_pubrel_is_fresh)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int sub_pubs;

    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'A'
    };
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'B'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x02
    };
    static const byte publish[] = {
        0x34, 0x0A, 0x00, 0x01, 'x', 0x00, 0x07,
        'f', 'i', 'r', 's', 't'
    };
    static const byte pubrel[] = {
        0x62, 0x02, 0x00, 0x07
    };
    /* Second PUBLISH reuses packet_id=7 AFTER PUBREL has cleared it. This
     * is now a fresh delivery (no DUP flag). remain = 3+2+6 = 11 */
    static const byte publish_again[] = {
        0x34, 0x0B, 0x00, 0x01, 'x', 0x00, 0x07,
        's', 'e', 'c', 'o', 'n', 'd'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish, sizeof(publish));
    mock_client_input_append(1, pubrel, sizeof(pubrel));
    mock_client_input_append(1, publish_again, sizeof(publish_again));

    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
    }

    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);

    /* Expect TWO forwarded PUBLISHes: the dedup state was cleared by the
     * PUBREL, so the second PUBLISH with packet_id=7 is treated as fresh. */
    ASSERT_EQ(2, sub_pubs);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Build a minimal QoS 2 PUBLISH wire packet with topic "x" and payload "p"
 * for the given packet_id. Used by the cap-reached and clear-state tests
 * which need many in-flight QoS 2 packets without the boilerplate of
 * spelling out each one. Returns the encoded length (always 8). */
static size_t build_qos2_pub(byte* out, word16 packet_id)
{
    /* remain = topic_len(2) + topic(1) + packet_id(2) + payload(1) = 6 */
    out[0] = 0x34;
    out[1] = 0x06;
    out[2] = 0x00; out[3] = 0x01; out[4] = 'x';
    out[5] = (byte)(packet_id >> 8);
    out[6] = (byte)(packet_id & 0xFF);
    out[7] = 'p';
    return 8;
}

/* Build a v3.1.1 QoS 1 PUBLISH to topic "x" (payload "p") with the given
 * packet_id. Used to flood a slow subscriber's outbound queue. The v3.1.1
 * wire form has no property field, so the encoding is identical to the QoS 2
 * helper except for the QoS bits in the fixed header. Returns length (8).
 * Only used by the dynamic-mode out_q-cap tests, so guarded to avoid an
 * unused-function warning under -Werror in static-memory builds. */
#ifndef WOLFMQTT_STATIC_MEMORY
static size_t build_qos1_pub(byte* out, word16 packet_id)
{
    /* remain = topic_len(2) + topic(1) + packet_id(2) + payload(1) = 6 */
    out[0] = 0x32; /* PUBLISH, QoS 1 */
    out[1] = 0x06;
    out[2] = 0x00; out[3] = 0x01; out[4] = 'x';
    out[5] = (byte)(packet_id >> 8);
    out[6] = (byte)(packet_id & 0xFF);
    out[7] = 'p';
    return 8;
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

/* The per-client cap on in-flight QoS 2 packet IDs (BROKER_MAX_INBOUND_QOS2,
 * default 16) MUST disconnect a client that exceeds it. Without the cap, a
 * misbehaving client could exhaust broker memory by sending many distinct
 * QoS 2 PUBLISH packets without ever sending the matching PUBRELs. */
TEST(qos2_inbound_cap_reached_disconnects)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int pub_pubrecs;
    int closed_after;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'B'
    };
    byte pub_buf[8];

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    /* Feed BROKER_MAX_INBOUND_QOS2 + 1 distinct in-flight PUBLISHes. The
     * first cap accepted; the (cap+1)th must trigger a fatal close.
     * v3.1.1 has no DISCONNECT-with-reason path so the broker closes the
     * socket directly; v5 clients additionally receive a DISCONNECT
     * with MQTT_REASON_QUOTA_EXCEEDED before the close. */
    for (i = 1; i <= BROKER_MAX_INBOUND_QOS2 + 1; i++) {
        size_t n = build_qos2_pub(pub_buf, (word16)i);
        mock_client_input_append(0, pub_buf, n);
    }

    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
    }

    pub_pubrecs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);
    closed_after = g_clients[0].closed;

    /* The first BROKER_MAX_INBOUND_QOS2 PUBLISHes get a PUBREC each; the
     * (cap+1)th is rejected before the PUBREC send, so no PUBREC for it. */
    ASSERT_EQ(BROKER_MAX_INBOUND_QOS2, pub_pubrecs);
    ASSERT_TRUE(closed_after);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Disconnecting a client with non-empty inbound QoS 2 state must free that
 * state. We can't directly inspect freed pointers from the test, but ASan/
 * valgrind in CI catch a regression where BrokerInboundQos2_Clear becomes a
 * no-op. This test exercises the cleanup path so a sanitizer build fails on
 * a leak rather than the bug going unnoticed. */
TEST(qos2_state_freed_on_client_disconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'B'
    };
    /* Normal DISCONNECT packet - drives the broker through the
     * clean-disconnect cleanup path. */
    static const byte disconnect[] = { 0xE0, 0x00 };
    byte pub_buf[8];

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    /* Three in-flight QoS 2 PUBLISHes with no matching PUBRELs. */
    for (i = 1; i <= 3; i++) {
        size_t n = build_qos2_pub(pub_buf, (word16)i);
        mock_client_input_append(0, pub_buf, n);
    }
    mock_client_input_append(0, disconnect, sizeof(disconnect));

    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Sanity: client did get processed and is now closed. The actual
     * leak-check is the responsibility of the sanitizer harness. */
    ASSERT_TRUE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* PUBREL for an unknown packet ID is idempotent: the broker MUST still
 * respond with PUBCOMP. The dedup-set's Remove is a no-op for unknown IDs. */
TEST(qos2_pubrel_unknown_id_still_pubcomps)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int pub_pubcomps;

    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'B'
    };
    /* PUBREL packet_id=99 with no preceding PUBLISH. */
    static const byte pubrel[] = {
        0x62, 0x02, 0x00, 0x63
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, pubrel, sizeof(pubrel));

    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }

    pub_pubcomps = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH_COMP);
    ASSERT_EQ(1, pub_pubcomps);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Regression for the SIGPIPE-on-PUBREC-write bug. When a publisher sent a
 * QoS 2 PUBLISH and immediately closed its socket, the broker's subsequent
 * write of PUBREC into the peer-closed socket would deliver SIGPIPE and
 * terminate the broker process (SIGPIPE's default action terminates the
 * process; it is not SIGTERM).
 * The fix uses MSG_NOSIGNAL (Linux/BSDs) and SO_NOSIGPIPE (macOS) on the
 * broker's POSIX socket layer, plus an explicit signal(SIGPIPE, SIG_IGN)
 * in the standalone broker main as belt-and-suspenders.
 *
 * The mock-net used by these unit tests never generates SIGPIPE - this
 * test pins the protocol-level state-machine path (orphaned subscriber +
 * publisher publishes QoS 2 + immediate DISCONNECT) so a future regression
 * in the QoS 2 dispatch is caught alongside the wire-level SIGPIPE fix
 * verified end-to-end with the paho reproducer the reporter provided. */
TEST(qos2_publish_with_offline_durable_subscriber)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int pub_connacks;
    int pub_pubrecs;

    /* Subscriber CONNECT: ClientId "S", clean_session=0 (flags=0x00). */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id=1, filter "x", QoS 2. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x02
    };
    /* Clean DISCONNECT. */
    static const byte disconnect[] = { 0xE0, 0x00 };
    /* Publisher CONNECT: ClientId "P", clean_session=0. */
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* PUBLISH QoS 2, packet_id=7, topic "x", payload "p".
     * remain = 2+1+2+1 = 6 */
    static const byte publish[] = {
        0x34, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Phase 1: subscriber connects, subscribes, then disconnects cleanly.
     * After this the broker should have an orphaned sub with client=NULL
     * and client_id="S" still in broker->subs. */
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
        if (g_clients[0].closed) {
            break;
        }
    }
    ASSERT_TRUE(g_clients[0].closed);

    /* Phase 2: publisher connects, publishes QoS 2, and disconnects - all
     * bytes appended in one shot so the broker may read PUBLISH + DISCONNECT
     * back-to-back with no Step() between, exactly as the paho client does
     * without a sleep before disconnect(). */
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish, sizeof(publish));
    mock_client_input_append(1, disconnect, sizeof(disconnect));
    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
        if (g_clients[1].closed) {
            break;
        }
    }
    ASSERT_TRUE(g_clients[1].closed);

    /* Sanity: the broker did process the PUBLISH (one PUBREC out) before
     * tearing down the publisher. The orphaned sub is offline so no
     * forwarded PUBLISH on g_clients[0]. The strong assertion is that
     * MqttBroker_Stop/Free do not crash or trip ASan below. */
    pub_connacks = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_CONNECT_ACK);
    pub_pubrecs = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);
    ASSERT_EQ(1, pub_connacks);
    ASSERT_EQ(1, pub_pubrecs);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Same crash scenario as above but the publisher's TCP goes away abruptly
 * (read returns network error) instead of sending a clean DISCONNECT.
 * Exercises the BrokerClient_AbnormalClose branch. */
TEST(qos2_publish_then_abrupt_close_offline_subscriber)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int pub_pubrecs;
    MockClient* mc;

    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x02
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish[] = {
        0x34, 0x06, 0x00, 0x01, 'x', 0x00, 0x07, 'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
        if (g_clients[0].closed) break;
    }
    ASSERT_TRUE(g_clients[0].closed);

    /* Publisher sends CONNECT + PUBLISH, then we drive Steps so the broker
     * processes both and writes PUBREC. The peer then disappears abruptly,
     * simulated below by mc->read_err (mock_read returns a network error),
     * which exercises the BrokerClient_AbnormalClose branch. */
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish, sizeof(publish));
    /* Drive enough Steps to process CONNECT and PUBLISH. */
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }
    /* Now simulate the peer going away abruptly: the next mock_read returns
     * MQTT_CODE_ERROR_NETWORK (as a real RST/abrupt FIN would), driving the
     * BrokerClient_AbnormalClose branch this test is meant to cover. The
     * PUBREC has already been written to out_buf before this point. */
    mc = &g_clients[1];
    mc->read_err = 1;
    for (i = 0; i < 4; i++) {
        MqttBroker_Step(&broker);
    }

    pub_pubrecs = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);
    ASSERT_EQ(1, pub_pubrecs);

    /* The read error drives BrokerClient_Process -> BrokerClient_AbnormalClose
     * -> BrokerClient_Remove -> BrokerClient_Free -> net->close (mock_close),
     * which marks the mock closed. This proves the abnormal-close teardown ran
     * (publisher has clean_session=0, so its subs are orphaned and the client
     * is freed). MqttBroker_Free below must not trip ASan on the QoS 2 state
     * that was pending when the connection dropped. */
    ASSERT_TRUE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* The out_q-cap tests are dynamic-memory-only (they inspect out_q_count and
 * the linked client list); the v5 variant additionally uses the v5-only
 * MQTT_REASON_QUOTA_EXCEEDED. Guard accordingly so the non-V5 and
 * static-memory broker CI matrix entries compile. */
#ifndef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_V5
/* Issue 6222: a connected QoS>=1 subscriber that stops acking must NOT be able
 * to grow its outbound queue without bound. The inflight cap only limits
 * PUBLISHes on the wire; entries beyond it sit QUEUED and, pre-fix, were
 * appended to out_q with no depth limit - one heap-copied PUBLISH (topic +
 * attacker-sized payload) per matching message, until the broker OOMs.
 *
 * Repro: subscriber subscribes to "x" at QoS 1 and then never PUBACKs; a
 * publisher floods more than BROKER_MAX_QUEUED_MSGS_PER_SUB matching QoS 1
 * PUBLISHes. The fix bounds out_q_count at the cap and disconnects the slow
 * subscriber (v5: DISCONNECT reason 0x97 Quota Exceeded). We assert the queue
 * stopped growing at the cap, the subscriber's socket was torn down, and at
 * most the inflight window ever reached the wire. */
TEST(online_qos1_flood_disconnects_slow_v5_subscriber)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int flood = BROKER_MAX_QUEUED_MSGS_PER_SUB + 8;
    int sub_pubs;
    int sub_disconnects;
    BrokerClient* sub_bc;

    /* Subscriber CONNECT: v5, ClientId "S", clean_session=1. */
    static const byte connect_sub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,                   /* properties length = 0 */
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE (v5): packet_id=1, props_len=0, filter "x", QoS 1. */
    static const byte subscribe_x[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,                   /* properties length = 0 */
        0x00, 0x01, 'x',
        0x01
    };
    /* Publisher CONNECT: v3.1.1, ClientId "P", clean_session=1. */
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    byte pub_buf[8];

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);

    /* Phase 1: subscriber connects and subscribes (and stays connected).
     * Establish the subscription before the flood so every published message
     * matches and is fanned out to this subscriber. */
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_TRUE(sub_bc != NULL);
    ASSERT_TRUE(sub_bc->connected);

    /* Phase 2: publisher connects and floods QoS 1 PUBLISHes to "x". The
     * subscriber never PUBACKs, so the inflight window saturates and every
     * further message is queued (pre-fix: forever). */
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < flood; i++) {
        size_t n = build_qos1_pub(pub_buf, (word16)(i + 1));
        mock_client_input_append(1, pub_buf, n);
    }
    for (i = 0; i < flood + 32; i++) {
        MqttBroker_Step(&broker);
    }

    /* The subscriber's queue must have stopped growing at the cap rather than
     * tracking the flood size, and the broker must have torn the socket down. */
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_TRUE(sub_bc != NULL);
    ASSERT_EQ(BROKER_MAX_QUEUED_MSGS_PER_SUB, sub_bc->out_q_count);
    ASSERT_FALSE(sub_bc->connected);
    ASSERT_TRUE(g_clients[0].closed);

    /* Only the inflight window ever reached the wire - far fewer than the
     * flood, proving the cap bounds wire traffic too. */
    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    ASSERT_TRUE(sub_pubs >= 1);
    ASSERT_TRUE(sub_pubs <= BROKER_MAX_INFLIGHT_PER_SUB);

    /* v5 subscriber gets a DISCONNECT with reason 0x97 Quota Exceeded. */
    sub_disconnects = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_DISCONNECT);
    ASSERT_EQ(1, sub_disconnects);
    ASSERT_EQ(MQTT_REASON_QUOTA_EXCEEDED,
        first_disconnect_reason(g_clients[0].out_buf, g_clients[0].out_len));

    /* The publisher is a separate, well-behaved client and must be untouched. */
    ASSERT_FALSE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#endif /* WOLFMQTT_V5 */

/* Same overflow scenario with a v3.1.1 subscriber. v3.1.1 has no
 * DISCONNECT-with-reason path, so the broker simply closes the socket; the
 * queue must still be bounded at the cap. */
TEST(online_qos1_flood_disconnects_slow_v311_subscriber)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int flood = BROKER_MAX_QUEUED_MSGS_PER_SUB + 8;
    int sub_disconnects;
    BrokerClient* sub_bc;

    /* Subscriber CONNECT: v3.1.1, ClientId "S", clean_session=1. */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE (v3.1.1): packet_id=1, filter "x", QoS 1. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    byte pub_buf[8];

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_TRUE(sub_bc != NULL);
    ASSERT_TRUE(sub_bc->connected);

    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < flood; i++) {
        size_t n = build_qos1_pub(pub_buf, (word16)(i + 1));
        mock_client_input_append(1, pub_buf, n);
    }
    for (i = 0; i < flood + 32; i++) {
        MqttBroker_Step(&broker);
    }

    sub_bc = find_broker_client(&broker, "S");
    ASSERT_TRUE(sub_bc != NULL);
    ASSERT_EQ(BROKER_MAX_QUEUED_MSGS_PER_SUB, sub_bc->out_q_count);
    ASSERT_FALSE(sub_bc->connected);
    ASSERT_TRUE(g_clients[0].closed);

    /* v3.1.1 has no DISCONNECT reason code: the broker closes silently. */
    sub_disconnects = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_DISCONNECT);
    ASSERT_EQ(0, sub_disconnects);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Boundary check: a slow subscriber that reaches but does not exceed the cap
 * stays connected. Publishing exactly BROKER_MAX_QUEUED_MSGS_PER_SUB messages
 * fills out_q to the cap; only the (cap+1)th would trip the disconnect. Guards
 * the >= comparison against an off-by-one that would evict at the cap. */
TEST(online_qos1_at_cap_keeps_subscriber)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int at_cap = BROKER_MAX_QUEUED_MSGS_PER_SUB;
    BrokerClient* sub_bc;

    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    byte pub_buf[8];

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_TRUE(sub_bc != NULL);

    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < at_cap; i++) {
        size_t n = build_qos1_pub(pub_buf, (word16)(i + 1));
        mock_client_input_append(1, pub_buf, n);
    }
    for (i = 0; i < at_cap + 32; i++) {
        MqttBroker_Step(&broker);
    }

    sub_bc = find_broker_client(&broker, "S");
    ASSERT_TRUE(sub_bc != NULL);
    ASSERT_EQ(BROKER_MAX_QUEUED_MSGS_PER_SUB, sub_bc->out_q_count);
    ASSERT_TRUE(sub_bc->connected);
    ASSERT_FALSE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#ifdef WOLFMQTT_V5
/* v5 variant: same orphan-then-publish-then-disconnect pattern but the
 * PUBLISH carries a property block. Tests the suspected use-after-free in
 * the fan-out path where pub.props is shared across subscribers and then
 * freed at the end of BrokerHandle_Publish. With only an orphaned sub
 * matching, the fan-out body does not execute, but the broker's MqttClient
 * still has to decode and free the props. */
TEST(qos2_publish_v5_props_with_offline_durable_subscriber)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int pub_pubrecs;

    /* v5 CONNECT subscriber, ClientId "S", clean_session=0, props_len=0.
     * remain = MQTT_hdr(6)+level(1)+flags(1)+keepalive(2)+props_len(1)+
     *          clientid_hdr(2)+clientid(1) = 14 */
    static const byte connect_sub_v5[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE packet_id=1, props_len=0, filter "x", options=QoS 2. */
    static const byte subscribe_v5[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'x',
        0x02
    };
    /* v5 DISCONNECT (0xE0 0x00 with no reason / props - allowed). */
    static const byte disconnect_v5[] = { 0xE0, 0x00 };
    /* v5 CONNECT publisher, ClientId "P". remain = 14 (same as subscriber). */
    static const byte connect_pub_v5[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };
    /* v5 PUBLISH QoS 2 packet_id=7, topic "x", one Message Expiry Interval
     * property (id=0x02, 4-byte int=60), payload "p".
     * remain = topic_hdr(2)+topic(1)+packet_id(2)+prop_len_vbi(1)+prop(5)+
     *         payload(1) = 12 */
    static const byte publish_v5[] = {
        0x34, 0x0C,
        0x00, 0x01, 'x',
        0x00, 0x07,
        0x05,                       /* prop block length = 5 */
        0x02, 0x00, 0x00, 0x00, 0x3C, /* Message Expiry Interval = 60 */
        'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub_v5, sizeof(connect_sub_v5));
    mock_client_input_append(0, subscribe_v5, sizeof(subscribe_v5));
    mock_client_input_append(0, disconnect_v5, sizeof(disconnect_v5));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
        if (g_clients[0].closed) break;
    }
    ASSERT_TRUE(g_clients[0].closed);

    mock_client_input_append(1, connect_pub_v5, sizeof(connect_pub_v5));
    mock_client_input_append(1, publish_v5, sizeof(publish_v5));
    mock_client_input_append(1, disconnect_v5, sizeof(disconnect_v5));
    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
        if (g_clients[1].closed) break;
    }
    ASSERT_TRUE(g_clients[1].closed);

    pub_pubrecs = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);
    ASSERT_EQ(1, pub_pubrecs);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */

/* MQTT 3.1.1 section 3.12 / v5 section 3.12: PINGREQ has no variable header and no
 * payload, so Remaining Length MUST be 0. Broker dispatch must reject a
 * malformed PINGREQ with an abnormal close instead of emitting a
 * PINGRESP.
 *
 * The valid case is paired so a regression that reverses the conditional
 * (rejecting valid PINGREQs) trips the positive test. */
TEST(pingreq_valid_emits_pingresp)
{
    MqttBroker broker;
    MqttBrokerNet net;
    static const byte connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    static const byte pingreq_valid[] = { 0xC0, 0x00 };
    int i;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, pingreq_valid, sizeof(pingreq_valid));
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(1, count_packets_of_type(g_out_buf, g_out_len,
        MQTT_PACKET_TYPE_PING_RESP));
    ASSERT_FALSE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(pingreq_nonzero_remain_len_closes_no_pingresp)
{
    MqttBroker broker;
    MqttBrokerNet net;
    static const byte connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* C0 01 00 - PINGREQ with one trailing byte. The fixed-header-only
     * rule makes this malformed. */
    static const byte pingreq_bad[] = { 0xC0, 0x01, 0x00 };
    int i;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, pingreq_bad, sizeof(pingreq_bad));
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(0, count_packets_of_type(g_out_buf, g_out_len,
        MQTT_PACKET_TYPE_PING_RESP));
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MQTT 3.1.1 section 3.14: DISCONNECT has no variable header and no payload, so
 * Remaining Length MUST be 0. The strong observable for "malformed
 * DISCONNECT was rejected" is the Last Will: a normal DISCONNECT clears
 * the will, but AbnormalClose fires it. Two clients - subscriber on the
 * will topic, publisher with an LWT - let us assert the broker dispatched
 * the malformed packet through AbnormalClose by observing the will
 * delivery. v5 has its own decoder that legitimately accepts Reason Code
 * + Properties, so the broker's remain_len check (and this test) is
 * v3.1.1-only. */
#ifndef WOLFMQTT_V5
TEST(disconnect_v311_nonzero_remain_len_fires_will)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* Subscriber CONNECT (clean=1, ClientId "S") then SUBSCRIBE to "lwt". */
    static const byte sub_connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte sub_subscribe[] = {
        0x82, 0x08,
        0x00, 0x01,
        0x00, 0x03, 'l', 'w', 't',
        0x00
    };
    /* Publisher CONNECT with LWT: flags = 0x06 = will_flag | clean_session;
     * will_qos=0, will_retain=0; will_topic "lwt"; will_payload "bye". */
    static const byte pub_connect[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x06, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* E0 01 00 - malformed v3.1.1 DISCONNECT (nonzero remain_len). */
    static const byte disconnect_bad[] = { 0xE0, 0x01, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, pub_connect, sizeof(pub_connect));
    mock_client_input_append(1, disconnect_bad, sizeof(disconnect_bad));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Subscriber must receive a PUBLISH (the will message). The bug case
     * dispatches the malformed DISCONNECT through the normal-close path
     * which clears the will, so no PUBLISH would reach the subscriber. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    /* Publisher's connection was closed regardless of which path the
     * broker took, so g_client_closed alone wouldn't catch the bug. */
    ASSERT_TRUE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_V5 */

/* The broker switch's default branch must close the connection on any
 * unhandled packet type rather than silently no-op'ing. Wire is an
 * AUTH packet (type 15) from a v3.1.1 client - AUTH is undefined in
 * v3.1.1 and this broker doesn't implement enhanced authentication
 * even on v5, so AUTH is always unhandled. The pre-dispatch
 * FixedHeaderFlagsValid gate accepts AUTH (it is a defined type 15
 * with required flag nibble 0x0); rejection has to happen at dispatch. */
TEST(broker_unhandled_packet_type_closes)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* AUTH (type 15) with empty body. v3.1.1 doesn't define AUTH. */
    static const byte auth[] = { 0xF0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, auth, sizeof(auth));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.1.0-1]: a client's first packet MUST be CONNECT. The broker's
 * pre-dispatch guard closes any client that sends another packet type
 * first. A PUBLISH from a never-connected client must be dropped and the
 * client closed - it must NOT fan out to subscribers. A deletion of the
 * guard would let BrokerHandle_Publish run on the unauthenticated client,
 * so the subscriber receiving zero PUBLISH packets is the load-bearing
 * assertion. */
TEST(broker_publish_before_connect_closes)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* Subscriber: CONNECT then SUBSCRIBE to "t" (qos 0). */
    static const byte sub_connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte sub_subscribe[] = {
        0x82, 0x06,
        0x00, 0x01,                    /* packet_id */
        0x00, 0x01, 't',
        0x00
    };
    /* Attacker: PUBLISH "t"/"x" as the very first packet, no CONNECT. */
    static const byte pub_no_connect[] = {
        0x30, 0x04,
        0x00, 0x01, 't',
        'x'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, pub_no_connect, sizeof(pub_no_connect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Attacker connection closed for violating [MQTT-3.1.0-1]. */
    ASSERT_TRUE(g_clients[1].closed);
    /* Subscriber must have received no fan-out from the pre-CONNECT PUBLISH. */
    ASSERT_EQ(0, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#if !defined(WOLFMQTT_STATIC_MEMORY) && \
    (defined(WOLFMQTT_BROKER_RETAINED) || defined(WOLFMQTT_BROKER_WILL))
/* Return 1 if the byte sequence `needle` (nlen bytes) occurs within the first
 * hlen bytes of `hay`, else 0. Used to prove a delivered payload was scrubbed
 * from a broker-side tx_buf. */
static int scrub_region_contains(const byte* hay, int hlen,
    const char* needle, int nlen)
{
    int i;
    if (hay == NULL || nlen <= 0 || hlen < nlen) {
        return 0;
    }
    for (i = 0; i + nlen <= hlen; i++) {
        if (XMEMCMP(hay + i, needle, (size_t)nlen) == 0) {
            return 1;
        }
    }
    return 0;
}
#endif

#if defined(WOLFMQTT_BROKER_RETAINED) && !defined(WOLFMQTT_STATIC_MEMORY)
/* f-6950: after a retained message is delivered on a completed write, the
 * plaintext payload must not linger in the subscriber's broker-side tx_buf.
 * Deliver a distinctive retained payload, let the mock write complete, and
 * assert the payload reached the wire but was scrubbed from tx_buf. Deleting
 * the BROKER_FORCE_ZERO would leave the payload resident and trip this. */
TEST(broker_retained_scrub_after_completed_write)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    int i;
    /* v3.1.1 CONNECT, ClientId "P" / "S", clean_session=1. */
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    /* Retained PUBLISH: topic "r/q", payload "RETAINSECRET" (QoS 0, retain). */
    static const byte publish[] = {
        0x31, 0x11, 0x00, 0x03, 'r', '/', 'q',
        'R', 'E', 'T', 'A', 'I', 'N', 'S', 'E', 'C', 'R', 'E', 'T'
    };
    /* SUBSCRIBE to "r/q" at QoS 0. */
    static const byte subscribe[] = {
        0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'r', '/', 'q', 0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    /* Publisher stores the retained message before the subscriber attaches. */
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish, sizeof(publish));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe, sizeof(subscribe));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* The retained PUBLISH reached the subscriber's wire... */
    ASSERT_EQ(1, scrub_region_contains(g_clients[1].out_buf,
        (int)g_clients[1].out_len, "RETAINSECRET", 12));
    /* ...but the plaintext was scrubbed from the broker-side tx_buf. */
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    ASSERT_EQ(0, scrub_region_contains(sub_bc->tx_buf, sub_bc->tx_buf_len,
        "RETAINSECRET", 12));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_RETAINED && !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_BROKER_WILL) && !defined(WOLFMQTT_STATIC_MEMORY)
/* f-6950 / F-4524: the immediate-will fan-out must scrub the subscriber tx_buf
 * even when the delivery write fails hard (only the in-progress
 * MQTT_CODE_CONTINUE case is skipped). Connect and subscribe first (writes
 * succeed), then force the subscriber's writes to fail and trigger the
 * publisher's abnormal disconnect so the will fan-out write returns a network
 * error. With the error-path scrub the will plaintext is gone from tx_buf;
 * without it (a scrub gated only on wr == enc_rc) it would linger. */
TEST(broker_will_scrub_after_failed_write)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    int i;
    /* Subscriber v3.1.1 CONNECT "S" (clean) then SUBSCRIBE to "lwt". */
    static const byte sub_connect[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte sub_subscribe[] = {
        0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'l', 'w', 't', 0x00
    };
    /* Publisher v3.1.1 CONNECT "P" with LWT: flags 0x06 (will | clean),
     * will_topic "lwt", will_payload "WILLSECRET" (10 bytes). */
    static const byte pub_connect[] = {
        0x10, 0x1E, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x06, 0x00, 0x3C, 0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x0A, 'W', 'I', 'L', 'L', 'S', 'E', 'C', 'R', 'E', 'T'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    /* Establish both clients; the will has not fired yet. */
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, pub_connect, sizeof(pub_connect));
    for (i = 0; i < 12; i++) {
        MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* Force the subscriber's writes to fail, then drop the publisher's socket
     * so its will fans out to the subscriber over the failing write. */
    g_clients[0].write_err = 1;
    g_clients[1].read_err = 1;
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }

    /* Positive control: the will was encoded and handed to the (failing) write,
     * so the scrub path genuinely had plaintext to remove. Without this the
     * scrub assertion below could pass vacuously if the will never reached the
     * subscriber's tx_buf (e.g. a topic-match or fan-out regression). */
    ASSERT_EQ(1, scrub_region_contains(g_clients[0].out_buf,
        (int)g_clients[0].out_len, "WILLSECRET", 10));

    /* The will fan-out does not tear the subscriber down on a failed write, so
     * it is still present - and its tx_buf must not retain the will plaintext. */
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    ASSERT_EQ(0, scrub_region_contains(sub_bc->tx_buf, sub_bc->tx_buf_len,
        "WILLSECRET", 10));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_WILL && !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_BROKER_RETAINED) && !defined(WOLFMQTT_STATIC_MEMORY)
/* The dynamic retained-message list must be bounded. A client that
 * publishes RETAIN=1 to more than BROKER_MAX_RETAINED distinct topics must not
 * grow the list past the cap - pre-fix it grew without bound, enabling
 * heap-exhaustion DoS. */
TEST(broker_retained_list_capped)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    byte pub[8];
    static const byte connect[] = {
        0x10, 0x0F,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x03, 'p', 'u', 'b'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    /* Publish RETAIN=1 (QoS 0) to BROKER_MAX_RETAINED + 5 distinct topics. */
    for (i = 0; i < BROKER_MAX_RETAINED + 5; i++) {
        pub[0] = 0x31;                          /* PUBLISH, retain=1 */
        pub[1] = 0x06;                          /* remain = 6 */
        pub[2] = 0x00; pub[3] = 0x03;           /* topic len 3 */
        pub[4] = 'r';
        pub[5] = (byte)('0' + (i / 10));
        pub[6] = (byte)('0' + (i % 10));
        pub[7] = 'x';                           /* payload */
        mock_client_input_append(0, pub, sizeof(pub));
    }
    for (i = 0; i < BROKER_MAX_RETAINED + 12; i++) {
        MqttBroker_Step(&broker);
    }

    /* The list is capped, not grown to BROKER_MAX_RETAINED + 5. */
    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A backward clock step must not make live retained messages look expired.
 * Entries stamped in the "future" (store_time > now) would, with an unguarded
 * unsigned subtraction, wrap to a huge elapsed value and be wrongly reaped;
 * the now >= store_time guard keeps them. Test time is pinned to 0, so a node
 * stamped at tick 1 models a clock that has since rolled back to 0. */
TEST(broker_retained_clock_rollback_not_expired)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerRetainedMsg* rm;
    int i;
    byte pub[8];
    static const byte connect[] = {
        0x10, 0x0F,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x03, 'p', 'u', 'b'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    /* Fill the cap with distinct retained topics. */
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        pub[0] = 0x31;                          /* PUBLISH, retain=1 */
        pub[1] = 0x06;
        pub[2] = 0x00; pub[3] = 0x03;
        pub[4] = 'r';
        pub[5] = (byte)('0' + (i / 10));
        pub[6] = (byte)('0' + (i % 10));
        pub[7] = 'x';
        mock_client_input_append(0, pub, sizeof(pub));
    }
    for (i = 0; i < BROKER_MAX_RETAINED + 4; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    /* Stamp every entry in the future relative to the pinned now=0 clock. */
    for (rm = broker.retained; rm != NULL; rm = rm->next) {
        rm->store_time = 1;
        rm->expiry_sec = 1;
    }

    /* A new retained topic triggers the reap path. The future-stamped entries
     * must be kept (not falsely expired), so the cap still rejects the new
     * topic and the count is unchanged. */
    pub[0] = 0x31;
    pub[1] = 0x06;
    pub[2] = 0x00; pub[3] = 0x03;
    pub[4] = 'n'; pub[5] = '0'; pub[6] = '0';
    pub[7] = 'y';
    mock_client_input_append(0, pub, sizeof(pub));
    for (i = 0; i < 4; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_RETAINED && !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* A single client cannot occupy more than BROKER_MAX_SUBS_PER_CLIENT
 * slots in the shared subscription table; excess SUBSCRIBEs are refused so
 * other clients are not denied service. */
TEST(broker_per_client_subscription_cap)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    byte sub[10];
    static const byte connect[] = {
        0x10, 0x0F,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x03, 's', 'u', 'b'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    /* Subscribe to BROKER_MAX_SUBS_PER_CLIENT + 3 distinct filters. */
    for (i = 0; i < BROKER_MAX_SUBS_PER_CLIENT + 3; i++) {
        sub[0] = 0x82;                       /* SUBSCRIBE */
        sub[1] = 0x08;                       /* remain = 8 */
        sub[2] = (byte)((i + 1) >> 8);       /* packet_id hi */
        sub[3] = (byte)((i + 1) & 0xFF);     /* packet_id lo */
        sub[4] = 0x00; sub[5] = 0x03;        /* filter len 3 */
        sub[6] = 'f';
        sub[7] = (byte)('0' + (i / 10));
        sub[8] = (byte)('0' + (i % 10));
        sub[9] = 0x00;                       /* options: QoS 0 */
        mock_client_input_append(0, sub, sizeof(sub));
    }
    for (i = 0; i < BROKER_MAX_SUBS_PER_CLIENT + 12; i++) {
        MqttBroker_Step(&broker);
    }

    /* Capped, not grown to BROKER_MAX_SUBS_PER_CLIENT + 3. */
    ASSERT_TRUE(broker.clients != NULL);
    ASSERT_EQ(BROKER_MAX_SUBS_PER_CLIENT, broker.clients->sub_count);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#ifdef WOLFMQTT_V5
/* [MQTT-3.3.4-6] A client PUBLISH carrying a Subscription Identifier is a
 * Protocol Error; the broker must reject and close, not forward the foreign
 * id to subscribers. */
TEST(broker_publish_with_subscription_id_closes)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,                          /* props len = 0 */
        0x00, 0x01, 'P'
    };
    static const byte publish[] = {
        0x30, 0x06,
        0x00, 0x01, 't',
        0x02, 0x0B, 0x05               /* props: SUBSCRIPTION_ID = 5 */
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, publish, sizeof(publish));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */

/* [MQTT-2.3.1-1] / [MQTT-4.13]: a SUBSCRIBE packet with Packet
 * Identifier = 0 is malformed and the broker MUST close the connection.
 * MqttDecode_Subscribe returns MQTT_CODE_ERROR_PACKET_ID; this test
 * pins that BrokerRcIsFatal classifies that rc as fatal so the dispatch
 * takes the close path. Without PACKET_ID in the fatal set, the broker
 * silently drops the packet and leaves the client connected. */
TEST(broker_subscribe_packet_id_zero_closes)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE with packet_id=0x0000 - violates [MQTT-2.3.1-1].
     * Body: packet_id (2) + topic_len (2) + "t" (1) + qos (1) = 6. */
    static const byte sub_pid_zero[] = {
        0x82, 0x06,
        0x00, 0x00,                    /* packet_id = 0 (illegal) */
        0x00, 0x01, 't',
        0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, sub_pid_zero, sizeof(sub_pid_zero));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MQTT 3.1.1 section 3.14.1 / [MQTT-2.2.2-2]: DISCONNECT fixed-header low
 * nibble MUST be 0000. The broker dispatch enforces this via the
 * MqttPacket_FixedHeaderFlagsValid pre-check that runs before per-type
 * handlers, so a malformed DISCONNECT (e.g. 0xE1) takes the abnormal-
 * close path. Same LWT observable as the nonzero-remain-len test:
 * abnormal close fires the will, normal close clears it. */
TEST(disconnect_invalid_fixed_header_flags_fires_will)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte sub_connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte sub_subscribe[] = {
        0x82, 0x08,
        0x00, 0x01,
        0x00, 0x03, 'l', 'w', 't',
        0x00
    };
    static const byte pub_connect[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x06, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* 0xE1 - DISCONNECT type with reserved bit 0 set. */
    static const byte disconnect_bad[] = { 0xE1, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, pub_connect, sizeof(pub_connect));
    mock_client_input_append(1, disconnect_bad, sizeof(disconnect_bad));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Subscriber receives the will because the broker took the abnormal-
     * close path. The malformed-bug case would have routed through the
     * normal DISCONNECT branch, clearing the will and producing 0
     * PUBLISH packets to the subscriber. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_TRUE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Parsed details of a single PUBLISH packet on the wire. found = 0 means
 * no PUBLISH was present in the buffer; subsequent fields are zero. */
typedef struct {
    int    found;
    byte   first_byte;     /* type | DUP | QoS | RETAIN */
    size_t remain_len;     /* fixed-header Remaining Length value */
    word16 packet_id;      /* 0 if QoS 0 (no packet identifier on wire) */
} PublishInfo;

/* Find the first PUBLISH packet (high nibble = 0x3) in `buf` and return
 * its first byte plus parsed remaining-length and packet identifier.
 * Mirrors count_packets_of_type's VBI walk so any malformed input stops
 * cleanly instead of overrunning. */
static PublishInfo first_publish_info(const byte* buf, size_t len)
{
    PublishInfo info;
    size_t pos = 0;
    XMEMSET(&info, 0, sizeof(info));
    while (pos < len) {
        byte type = (byte)((buf[pos] >> 4) & 0x0F);
        size_t remain = 0;
        size_t mult = 1;
        size_t hdr_len = 1;
        int vbi_complete = 0;
        while (pos + hdr_len < len && hdr_len <= 5) {
            byte b = buf[pos + hdr_len];
            remain += (size_t)(b & 0x7F) * mult;
            hdr_len++;
            if ((b & 0x80) == 0) {
                vbi_complete = 1;
                break;
            }
            mult *= 128;
        }
        if (!vbi_complete) {
            break;
        }
        if (type == MQTT_PACKET_TYPE_PUBLISH) {
            byte qos = (byte)((buf[pos] >> 1) & 0x03);
            info.found = 1;
            info.first_byte = buf[pos];
            info.remain_len = remain;
            if (qos >= MQTT_QOS_1) {
                /* Skip the 2-byte topic length + topic to reach the
                 * 2-byte packet identifier that follows for QoS >= 1. */
                size_t var_off = pos + hdr_len;
                if (var_off + 2 <= len) {
                    word16 topic_len =
                        (word16)((buf[var_off] << 8) | buf[var_off + 1]);
                    size_t pid_off = var_off + 2 + topic_len;
                    if (pid_off + 2 <= len) {
                        info.packet_id = (word16)(
                            (buf[pid_off] << 8) | buf[pid_off + 1]);
                    }
                }
            }
            return info;
        }
        if (remain > len - pos - hdr_len) {
            break;
        }
        pos += hdr_len + remain;
    }
    return info;
}

/* [MQTT-3.2.2-2] When a CleanSession=0 connection is accepted and the
 * broker has stored session state for the supplied Client Identifier,
 * Session Present in the CONNACK MUST be 1.
 *
 * Two-phase mock harness: client 0 connects clean=0, subscribes, and
 * disconnects (orphaning the sub); client 1 then connects clean=0 with
 * the same client_id and must receive CONNACK 20 02 01 00. The accept
 * count is gated to 1 across the first phase so client 1's accept
 * happens after client 0 has been removed (avoids the takeover branch
 * which is the same code path but reaches it differently). */
TEST(connack_session_present_set_on_resumed_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect0[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,         /* clean_session = 0 */
        0x00, 0x01, 'K'
    };
    static const byte subscribe0[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'k',
        0x00
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };
    static const byte connect1[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'K'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Phase 1: only client 0 is acceptable. Pre-stage client 1's input
     * in slot 1 so the read callback sees it once accept hands out the
     * second sock. */
    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, subscribe0, sizeof(subscribe0));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    mock_client_input_append(1, connect1, sizeof(connect1));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    /* Phase 2: open the second slot and let the broker accept client 1. */
    g_clients_active = 2;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Client 1's CONNACK must carry Session Present = 1. */
    ASSERT_TRUE(g_clients[1].out_len >= 4);
    ASSERT_EQ(0x20, g_clients[1].out_buf[0]);   /* CONNACK type | flags */
    ASSERT_EQ(0x02, g_clients[1].out_buf[1]);   /* remain_len = 2 */
    ASSERT_EQ(0x01, g_clients[1].out_buf[2]);   /* Session Present */
    ASSERT_EQ(0x00, g_clients[1].out_buf[3]);   /* return_code = Accepted */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.2.2-2] Session Present must also be set on the takeover
 * branch: a CleanSession=0 connect with the same Client Identifier
 * while the previous client is still connected reassociates the
 * existing subs to the new client, which counts as "stored session
 * state" for the new connection. Distinct from the orphan-resume test
 * above because BrokerHandle_Connect reaches the helper through the
 * `if (old != NULL)` branch with `s->client != NULL`, not the
 * `else if` branch with orphaned subs. */
TEST(connack_session_present_set_on_takeover)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect0[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'K'
    };
    static const byte subscribe0[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'k',
        0x00
    };
    static const byte connect1[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'K'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Phase 1: only client 0 connects and subscribes (no DISCONNECT). */
    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, subscribe0, sizeof(subscribe0));
    mock_client_input_append(1, connect1, sizeof(connect1));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    /* Client 0 is still connected - sub registered, no DISCONNECT yet. */
    ASSERT_FALSE(g_clients[0].closed);

    /* Phase 2: client 1 connects with the same client_id. The takeover
     * branch reassociates client 0's still-active sub to client 1. */
    g_clients_active = 2;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_TRUE(g_clients[1].out_len >= 4);
    ASSERT_EQ(0x20, g_clients[1].out_buf[0]);
    ASSERT_EQ(0x02, g_clients[1].out_buf[1]);
    ASSERT_EQ(0x01, g_clients[1].out_buf[2]);   /* Session Present = 1 */
    ASSERT_EQ(0x00, g_clients[1].out_buf[3]);
    /* Client 0 was kicked off by the takeover. */
    ASSERT_TRUE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Negative case: a clean_session=1 reconnect with the same Client
 * Identifier MUST get Session Present = 0 even if there were prior
 * subscriptions, because clean_session=1 discards stored state. */
TEST(connack_session_present_clear_on_clean_session_reconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect0[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,         /* clean_session = 0 */
        0x00, 0x01, 'K'
    };
    static const byte subscribe0[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'k',
        0x00
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };
    static const byte connect1[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,         /* clean_session = 1 */
        0x00, 0x01, 'K'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, subscribe0, sizeof(subscribe0));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    mock_client_input_append(1, connect1, sizeof(connect1));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    g_clients_active = 2;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_TRUE(g_clients[1].out_len >= 4);
    ASSERT_EQ(0x20, g_clients[1].out_buf[0]);
    ASSERT_EQ(0x02, g_clients[1].out_buf[1]);
    ASSERT_EQ(0x00, g_clients[1].out_buf[2]);   /* Session Present = 0 */
    ASSERT_EQ(0x00, g_clients[1].out_buf[3]);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_V5
/* v5 covers the same orphan-resume scenario but the CONNACK wire format
 * differs (Properties Length VBI between return code and payload). The
 * test decodes the CONNACK via MqttDecode_ConnectAck rather than
 * pinning fixed byte offsets, so a future change to v5 CONNACK encoding
 * doesn't silently regress the Session Present semantic. */
TEST(connack_session_present_v5_set_on_resumed_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttConnectAck ack;
    int rc;
    int i;
    /* v5 CONNECT clean=0, level=5, props_len=0, client_id="K". remain
     * = 6 + 1 + 1 + 2 + 1 + 3 = 14. */
    static const byte connect0[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x00,                              /* clean_start = 0 */
        0x00, 0x3C,
        0x00,                              /* properties length = 0 */
        0x00, 0x01, 'K'
    };
    static const byte subscribe0[] = {
        /* v5 SUBSCRIBE: type|flags=0x82, remain = 7
         * (packet_id 2 + props_len 1 + topic 3 + options 1). */
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'k',
        0x00
    };
    /* v5 DISCONNECT with Reason Code 0 (Normal disconnection) and no
     * properties. remain = 1 + 1 = 2. */
    static const byte disconnect0[] = { 0xE0, 0x02, 0x00, 0x00 };
    static const byte connect1[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x00,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'K'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, subscribe0, sizeof(subscribe0));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    mock_client_input_append(1, connect1, sizeof(connect1));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    g_clients_active = 2;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    XMEMSET(&ack, 0, sizeof(ack));
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_ConnectAck(g_clients[1].out_buf,
        (int)g_clients[1].out_len, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT,
              (int)(ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT));
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, ack.return_code);
    if (ack.props != NULL) {
        (void)MqttProps_Free(ack.props);
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */

#ifndef WOLFMQTT_BROKER_WILDCARDS
/* [MQTT-3.8.3-2] (v3.1.1 section 3.8.3): when the server does not support
 * wildcard subscriptions it MUST reject any Subscription request whose
 * filter contains '#' or '+'. v5 section 3.9.3 reserves reason code 0xA2
 * (Wildcard Subscriptions not supported) for this case, paired with
 * the v5 section 3.2.2.3.20 Wildcard Subscription Available CONNACK property.
 * The decoder still accepts the syntactically-valid wildcard filter;
 * rejection lives in the broker's per-topic SUBACK entry. The plain-
 * topic case is paired so a "reject everything" mutation also trips. */
TEST(broker_no_wildcards_suback_failure_for_wildcard_filter)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* SUBSCRIBE filter "+/r" (valid syntax; wildcard). */
    static const byte subscribe_wild[] = {
        0x82, 0x08,
        0x00, 0x07,
        0x00, 0x03, '+', '/', 'r',
        0x00
    };
    int last_byte;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, subscribe_wild, sizeof(subscribe_wild));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Output buffer carries CONNACK then SUBACK. SUBACK wire is
     * 0x90 0x03 packet_id_hi packet_id_lo return_code. The last byte is
     * the per-topic return code: must be Failure (0x80). */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    last_byte = g_clients[0].out_buf[g_clients[0].out_len - 1];
    ASSERT_EQ(MQTT_SUBSCRIBE_ACK_CODE_FAILURE, last_byte);
    ASSERT_FALSE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Pair: a plain (non-wildcard) filter must still be granted under the
 * no-wildcards build. Catches a regression that rejects everything. */
TEST(broker_no_wildcards_suback_grants_plain_filter)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* SUBSCRIBE filter "x" (no wildcard). */
    static const byte subscribe_plain[] = {
        0x82, 0x06,
        0x00, 0x07,
        0x00, 0x01, 'x',
        0x00
    };
    int last_byte;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, subscribe_plain, sizeof(subscribe_plain));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    last_byte = g_clients[0].out_buf[g_clients[0].out_len - 1];
    ASSERT_EQ(MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0, last_byte);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_V5
/* v5 section 3.9.3: Wildcard Subscriptions not supported uses Reason Code
 * 0xA2 rather than the generic 0x80 Failure that v3.1.1 returns. The
 * broker must surface that distinction so v5 clients receive an
 * actionable diagnostic. */
TEST(broker_no_wildcards_suback_v5_reason_code)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* v5 CONNECT, clean=1, level=5, props_len=0, client_id="A".
     * remain = 6 + 1 + 1 + 2 + 1 + 3 = 14. */
    static const byte connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x02,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };
    /* v5 SUBSCRIBE filter "+/r": type|flags=0x82, remain = 9
     * (packet_id 2 + props_len 1 + topic 5 + options 1). */
    static const byte subscribe_wild[] = {
        0x82, 0x09,
        0x00, 0x07,
        0x00,
        0x00, 0x03, '+', '/', 'r',
        0x00
    };
    int last_byte;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, subscribe_wild, sizeof(subscribe_wild));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    last_byte = g_clients[0].out_buf[g_clients[0].out_len - 1];
    ASSERT_EQ(MQTT_REASON_WILDCARD_SUB_NOT_SUP, last_byte);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */
#endif /* !WOLFMQTT_BROKER_WILDCARDS */

/* [MQTT-3.9.3-2] The broker SUBACK helper must reject reserved return
 * codes before serializing them to the wire. The normal subscribe path
 * only ever produces values in {0, 1, 2, 0x80}, so this defense is
 * unreachable from production code today; the test calls the helper
 * directly with a reserved code to pin the rejection branch.
 *
 * BrokerSend_SubAck is declared as WOLFMQTT_LOCAL in mqtt_broker.h, which
 * the test harness has already included above. The test binary compiles
 * mqtt_broker.c in directly so the symbol resolves at link.
 *
 * Gated on dynamic-memory builds: the test substitutes a small external
 * tx_buf into BrokerClient, which only works when tx_buf is a pointer
 * field. Under WOLFMQTT_STATIC_MEMORY tx_buf is an embedded byte array
 * and cannot be reassigned. The validation logic is layout-agnostic, so
 * skipping the test in static-memory builds doesn't lose coverage of
 * the rejection branch. */
#ifndef WOLFMQTT_STATIC_MEMORY
TEST(broker_suback_reserved_v311_code_rejected)
{
    BrokerClient bc;
    MqttBroker broker;
    byte tx_buf[16];
    /* Reserved values: anything outside {0, 1, 2, 0x80} for v3.1.1. */
    static const byte reserved_codes[] = { 0x03, 0x7F, 0x81, 0xFF };
    size_t i;

    XMEMSET(&bc, 0, sizeof(bc));
    XMEMSET(&broker, 0, sizeof(broker));
    bc.broker = &broker;
    bc.tx_buf = tx_buf;
    bc.tx_buf_len = (int)sizeof(tx_buf);
    bc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;

    for (i = 0; i < sizeof(reserved_codes); i++) {
        int rc;
        XMEMSET(tx_buf, 0xAA, sizeof(tx_buf));
        rc = BrokerSend_SubAck(&bc, 1, &reserved_codes[i], 1);
        ASSERT_EQ(MQTT_CODE_ERROR_MALFORMED_DATA, rc);
        /* No SUBACK bytes should have hit the buffer - first byte still
         * the 0xAA poison. */
        ASSERT_EQ(0xAA, (int)tx_buf[0]);
    }
}

/* Pair: a valid v3.1.1 code (0x80 = Failure) must succeed and overwrite
 * the buffer. Without this a "reject everything" mutation of the helper
 * would not be caught. The harness has no real network, so the call
 * fails at MqttPacket_Write - we only assert that the helper got past
 * the validation branch and into encoding (the type byte ends up at
 * tx_buf[0]). */
TEST(broker_suback_valid_v311_failure_code_encoded)
{
    BrokerClient bc;
    MqttBroker broker;
    byte tx_buf[16];
    byte code = MQTT_SUBSCRIBE_ACK_CODE_FAILURE;
    int rc;

    XMEMSET(&bc, 0, sizeof(bc));
    XMEMSET(&broker, 0, sizeof(broker));
    bc.broker = &broker;
    bc.tx_buf = tx_buf;
    bc.tx_buf_len = (int)sizeof(tx_buf);
    bc.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;

    XMEMSET(tx_buf, 0xAA, sizeof(tx_buf));
    rc = BrokerSend_SubAck(&bc, 1, &code, 1);
    /* Validation passed; the actual write fails with no real network,
     * but the encoded bytes are already in tx_buf. */
    (void)rc;
    ASSERT_EQ(MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK),
              tx_buf[0]);
    ASSERT_EQ(0x03, (int)tx_buf[1]);             /* remain_len = 3 */
    ASSERT_EQ(0x00, (int)tx_buf[2]);             /* packet_id MSB */
    ASSERT_EQ(0x01, (int)tx_buf[3]);             /* packet_id LSB */
    ASSERT_EQ(MQTT_SUBSCRIBE_ACK_CODE_FAILURE, tx_buf[4]);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#ifdef WOLFMQTT_BROKER_RETAINED
/* [MQTT-3.3.1-5] The broker MUST store the Application Message and its
 * QoS, so retained delivery can use min(stored QoS, subscriber QoS).
 * Pre-fix the retained store had no qos field and
 * BrokerRetained_DeliverToClient hard-coded outgoing QoS to 0,
 * downgrading QoS≥1 retained payloads.
 *
 * Wire pattern: publisher CONNECT, then retained PUBLISH at the test's
 * stored QoS; subscriber CONNECT (separate client), SUBSCRIBE at the
 * test's requested QoS; assert the delivered PUBLISH carries the
 * expected min(stored, sub) QoS. */
static void retained_qos_case(byte stored_qos, byte sub_qos,
                              byte expected_qos)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    PublishInfo info;
    /* Body shape: topic_len(2) + topic(3) + (packet_id(2) when QoS>=1)
     * + payload(1). 5 base bytes plus 2 for packet_id when applicable. */
    size_t expected_remain = (expected_qos >= MQTT_QOS_1) ? 8 : 6;
    /* Publisher CONNECT (ClientId "P"). */
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* Subscriber CONNECT (ClientId "S"). */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* Retained PUBLISH "r/q" / "x". remain = 2+3+2(packet_id)+1 = 8.
     * Wire: byte[0] = 0x30 | retain(0x01) | (stored_qos << 1). */
    byte publish[12];
    /* SUBSCRIBE filter "r/q", QoS = sub_qos. remain = 2+2+3+1 = 8. */
    byte subscribe[10];
    size_t publish_len;
    size_t subscribe_len;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Build PUBLISH wire. For QoS 0 the spec omits the packet identifier
     * (remain = 6: topic_len + topic + payload). For QoS≥1 the wire
     * carries packet_id = 1 (remain = 8). */
    {
        byte first = (byte)(0x30 | 0x01 | (byte)(stored_qos << 1));
        if (stored_qos == 0) {
            /* QoS 0 PUBLISH: no packet_id. Body = topic_len + topic +
             * payload = 2 + 3 + 1 = 6 bytes. */
            const byte tmpl[] = {
                0x00, 0x03, 'r', '/', 'q',
                'x'
            };
            publish[0] = first;
            publish[1] = (byte)sizeof(tmpl);
            XMEMCPY(publish + 2, tmpl, sizeof(tmpl));
            publish_len = 2 + sizeof(tmpl);
        }
        else {
            const byte tmpl[] = {
                0x00, 0x03, 'r', '/', 'q',
                0x00, 0x01,
                'x'
            };
            publish[0] = first;
            publish[1] = (byte)sizeof(tmpl);
            XMEMCPY(publish + 2, tmpl, sizeof(tmpl));
            publish_len = 2 + sizeof(tmpl);
        }
    }
    /* Build SUBSCRIBE wire. */
    {
        const byte tmpl[] = {
            0x82, 0x08,
            0x00, 0x01,
            0x00, 0x03, 'r', '/', 'q',
            0x00                        /* options placeholder */
        };
        XMEMCPY(subscribe, tmpl, sizeof(tmpl));
        subscribe[9] = sub_qos;
        subscribe_len = sizeof(tmpl);
    }

    reset_mock_clients(2);
    /* Publisher first so the retained store is populated before the
     * subscriber attaches. */
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish, publish_len);
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe, subscribe_len);
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));
    info = first_publish_info(g_clients[1].out_buf, g_clients[1].out_len);
    ASSERT_TRUE(info.found);
    /* Expect PUBLISH | retain | (expected_qos << 1), DUP = 0. */
    ASSERT_EQ((int)(0x30 | 0x01 | (expected_qos << 1)), (int)info.first_byte);
    /* Pin the wire size so a regression that emits a stale packet_id on a
     * downgraded-to-QoS-0 retained delivery (or omits it on a QoS>=1
     * delivery) trips here, not silently. */
    ASSERT_EQ((int)expected_remain, (int)info.remain_len);
    if (expected_qos >= MQTT_QOS_1) {
        /* [MQTT-2.3.1-1]: QoS>=1 PUBLISH must carry a non-zero packet
         * identifier. */
        ASSERT_TRUE(info.packet_id != 0);
    }
    else {
        ASSERT_EQ(0, info.packet_id);
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(retained_qos_stored_1_sub_1_delivers_qos1)
{
    retained_qos_case(MQTT_QOS_1, MQTT_QOS_1, MQTT_QOS_1);
}

TEST(retained_qos_stored_2_sub_1_delivers_qos1)
{
    retained_qos_case(MQTT_QOS_2, MQTT_QOS_1, MQTT_QOS_1);
}

TEST(retained_qos_stored_1_sub_0_delivers_qos0)
{
    retained_qos_case(MQTT_QOS_1, MQTT_QOS_0, MQTT_QOS_0);
}

TEST(retained_qos_stored_0_sub_1_delivers_qos0)
{
    retained_qos_case(MQTT_QOS_0, MQTT_QOS_1, MQTT_QOS_0);
}

/* Pins the QoS 2 outbound wire shape (first byte 0x35, packet_id
 * present). Without this case the QoS 2 outbound branch of
 * BrokerRetained_DeliverToClient never produces QoS 2 on the wire of any
 * test - the stored=2/sub=1 case caps to QoS 1. */
TEST(retained_qos_stored_2_sub_2_delivers_qos2)
{
    retained_qos_case(MQTT_QOS_2, MQTT_QOS_2, MQTT_QOS_2);
}

/* Steepest downgrade: stored QoS 2, subscriber QoS 0 - verifies the
 * retained delivery omits the packet identifier and emits the QoS-0
 * wire shape, not a stale identifier from the stored message. */
TEST(retained_qos_stored_2_sub_0_delivers_qos0)
{
    retained_qos_case(MQTT_QOS_2, MQTT_QOS_0, MQTT_QOS_0);
}
#endif /* WOLFMQTT_BROKER_RETAINED */

/* -------------------------------------------------------------------------- */
/* Runner                                                                      */
/* -------------------------------------------------------------------------- */

int main(int argc, char** argv)
{
    (void)argc; (void)argv;

    TEST_RUNNER_BEGIN();

    TEST_SUITE_BEGIN("broker_connect", setup, teardown);
    RUN_TEST(connect_v311_emptyid_clean0_refused);
    RUN_TEST(connect_v311_emptyid_clean1_accepted);
    RUN_TEST(connect_v311_nonempty_clean0_accepted);
    RUN_TEST(connect_v311_explicit_auto_prefix_refused);
    RUN_TEST(connect_unsupported_level_3_refused);
    RUN_TEST(connect_unsupported_level_6_refused);
    RUN_TEST(connect_unsupported_level_127_refused);
#ifdef WOLFMQTT_BROKER_AUTH
    RUN_TEST(connect_v311_binary_password_with_embedded_nul_refused);
    RUN_TEST(connect_v311_binary_password_exact_match_accepted);
    RUN_TEST(connect_auth_username_length_fold_repeating_byte_refused);
    RUN_TEST(connect_unauth_client_id_does_not_take_over_victim);
    RUN_TEST(connect_auth_user_only_start_rejected);
    RUN_TEST(connect_auth_pass_only_start_rejected);
    RUN_TEST(connect_auth_partial_config_fails_closed);
    RUN_TEST(connect_auth_partial_pass_only_fails_closed);
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_credentials_scrubbed_after_accept);
#endif
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(connect_v5_emptyid_assigned_id_emitted);
    RUN_TEST(connect_v5_emptyid_clean0_accepted);
#endif
    RUN_TEST(qos2_duplicate_publish_dedup);
    RUN_TEST(qos2_phantom_dup_publish_is_fresh);
    RUN_TEST(qos2_publish_after_pubrel_is_fresh);
    RUN_TEST(qos2_inbound_cap_reached_disconnects);
    RUN_TEST(qos2_state_freed_on_client_disconnect);
    RUN_TEST(qos2_pubrel_unknown_id_still_pubcomps);
    RUN_TEST(qos2_publish_with_offline_durable_subscriber);
    RUN_TEST(qos2_publish_then_abrupt_close_offline_subscriber);
#ifndef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_V5
    RUN_TEST(online_qos1_flood_disconnects_slow_v5_subscriber);
#endif /* WOLFMQTT_V5 */
    RUN_TEST(online_qos1_flood_disconnects_slow_v311_subscriber);
    RUN_TEST(online_qos1_at_cap_keeps_subscriber);
#endif /* !WOLFMQTT_STATIC_MEMORY */
#ifdef WOLFMQTT_V5
    RUN_TEST(qos2_publish_v5_props_with_offline_durable_subscriber);
#endif
    RUN_TEST(pingreq_valid_emits_pingresp);
    RUN_TEST(pingreq_nonzero_remain_len_closes_no_pingresp);
#ifndef WOLFMQTT_V5
    RUN_TEST(disconnect_v311_nonzero_remain_len_fires_will);
#endif
    RUN_TEST(disconnect_invalid_fixed_header_flags_fires_will);
#if defined(WOLFMQTT_BROKER_WILL) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(broker_will_scrub_after_failed_write);
#endif
    RUN_TEST(broker_unhandled_packet_type_closes);
    RUN_TEST(broker_publish_before_connect_closes);
#if defined(WOLFMQTT_BROKER_RETAINED) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(broker_retained_list_capped);
    RUN_TEST(broker_retained_clock_rollback_not_expired);
    RUN_TEST(broker_retained_scrub_after_completed_write);
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(broker_per_client_subscription_cap);
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(broker_publish_with_subscription_id_closes);
#endif
    RUN_TEST(broker_subscribe_packet_id_zero_closes);
    RUN_TEST(connack_session_present_set_on_resumed_session);
    RUN_TEST(connack_session_present_set_on_takeover);
    RUN_TEST(connack_session_present_clear_on_clean_session_reconnect);
#ifdef WOLFMQTT_V5
    RUN_TEST(connack_session_present_v5_set_on_resumed_session);
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(broker_suback_reserved_v311_code_rejected);
    RUN_TEST(broker_suback_valid_v311_failure_code_encoded);
#endif
#ifndef WOLFMQTT_BROKER_WILDCARDS
    RUN_TEST(broker_no_wildcards_suback_failure_for_wildcard_filter);
    RUN_TEST(broker_no_wildcards_suback_grants_plain_filter);
#ifdef WOLFMQTT_V5
    RUN_TEST(broker_no_wildcards_suback_v5_reason_code);
#endif
#endif
#ifdef WOLFMQTT_BROKER_RETAINED
    RUN_TEST(retained_qos_stored_1_sub_1_delivers_qos1);
    RUN_TEST(retained_qos_stored_2_sub_1_delivers_qos1);
    RUN_TEST(retained_qos_stored_1_sub_0_delivers_qos0);
    RUN_TEST(retained_qos_stored_0_sub_1_delivers_qos0);
    RUN_TEST(retained_qos_stored_2_sub_2_delivers_qos2);
    RUN_TEST(retained_qos_stored_2_sub_0_delivers_qos0);
#endif
    TEST_SUITE_END();

    TEST_RUNNER_END();
}
