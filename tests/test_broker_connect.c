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
    XMEMCPY(mc->out_buf + mc->out_len, buf, (size_t)buf_len);
    mc->out_len += (size_t)buf_len;
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
 * of the level the client claimed — we don't know what their wire format
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
     * ClientId="" — so the test below also fails on the post-decode path
     * unless the broker's [MQTT-3.1.2-2] check rejects the level. (For wires
     * without enough trailing bytes, the pre-fix decoder instead returned
     * OUT_OF_BUFFER and never emitted a CONNACK at all, which would also
     * fail the `g_out_len >= 4` assertion.) Either way, this test pins the
     * fix at both layers. */
    run_unsupported_level(0x06);
}

TEST(connect_unsupported_level_127_refused)
{
    /* Top of the byte range — guards against a future "treat high values
     * as latest known" mutation. */
    run_unsupported_level(0x7F);
}

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
     *   [5] first property tag — MUST be 0x12 (ASSIGNED_CLIENT_ID)
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
     * The DUP flag does NOT suppress fan-out — only an actual matching
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
     * first cap accepted; the (cap+1)th must trigger malformed-data close. */
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
    /* Normal DISCONNECT packet — drives the broker through the
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

/* MQTT 3.1.1 §3.12 / v5 §3.12: PINGREQ has no variable header and no
 * payload, so Remaining Length MUST be 0. Broker dispatch must reject a
 * malformed PINGREQ with an abnormal close instead of emitting a
 * PINGRESP. Issue #515.
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
    /* Issue #515 reproducer wire: C0 01 00 — PINGREQ with one trailing
     * byte. The fixed-header-only rule makes this malformed. */
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

/* MQTT 3.1.1 §3.14: DISCONNECT has no variable header and no payload, so
 * Remaining Length MUST be 0. The strong observable for "malformed
 * DISCONNECT was rejected" is the Last Will: a normal DISCONNECT clears
 * the will, but AbnormalClose fires it. Two clients — subscriber on the
 * will topic, publisher with an LWT — let us assert the broker dispatched
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
    /* Issue #515 reproducer wire: E0 01 00 — malformed v3.1.1 DISCONNECT. */
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
    RUN_TEST(pingreq_valid_emits_pingresp);
    RUN_TEST(pingreq_nonzero_remain_len_closes_no_pingresp);
#ifndef WOLFMQTT_V5
    RUN_TEST(disconnect_v311_nonzero_remain_len_fires_will);
#endif
    TEST_SUITE_END();

    TEST_RUNNER_END();
}
