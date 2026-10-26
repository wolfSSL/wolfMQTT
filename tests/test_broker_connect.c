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

#ifdef WOLFMQTT_BROKER_PERSIST
    #ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
        #include <wolfssl/wolfcrypt/aes.h>
    #endif
    #include <dirent.h>
    #include <errno.h>
    #include <limits.h>
    #include <fcntl.h>
    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <sys/un.h>
    #include <sys/wait.h>
    #include <unistd.h>
#endif

/* Provide storage for the unit-test framework's global counters. Must be
 * defined before unit_test.h is included. */
#define UNIT_TEST_IMPLEMENTATION
#include "tests/unit_test.h"

static int g_alloc_fail_after = -1;
static int g_alloc_failure_count;
static int g_alloc_success_count;
static int g_alloc_free_count;
static unsigned long g_broker_time_s;
static size_t g_capture_alloc_size;
static void* g_capture_alloc_ptr;
static byte g_capture_freed[64];
static size_t g_capture_freed_len;
static int g_capture_free_seen;
static size_t g_alloc_fail_size; /* fail the next malloc of exactly this size */
static void* g_free_watch_ptr;
static int g_free_watch_count;

void* wolfmqtt_test_broker_malloc(size_t size)
{
    void* ptr;

    if (g_alloc_fail_after == 0) {
        g_alloc_fail_after = -1;
        g_alloc_failure_count++;
        return NULL;
    }
    if (g_alloc_fail_size != 0 && size == g_alloc_fail_size) {
        g_alloc_fail_size = 0;
        g_alloc_failure_count++;
        return NULL;
    }
    if (g_alloc_fail_after > 0) {
        g_alloc_fail_after--;
    }
    ptr = malloc(size);
    if (ptr != NULL) {
        g_alloc_success_count++;
        if (g_capture_alloc_size == size &&
                size <= sizeof(g_capture_freed) &&
                g_capture_alloc_ptr == NULL) {
            g_capture_alloc_ptr = ptr;
            XMEMSET(ptr, 0xA5, size);
        }
    }
    return ptr;
}

void wolfmqtt_test_broker_free(void* ptr)
{
    if (ptr != NULL) {
        g_alloc_free_count++;
        if (ptr == g_free_watch_ptr) {
            g_free_watch_count++;
        }
        if (ptr == g_capture_alloc_ptr) {
            g_capture_freed_len = g_capture_alloc_size;
            XMEMCPY(g_capture_freed, ptr, g_capture_freed_len);
            g_capture_free_seen = 1;
            g_capture_alloc_ptr = NULL;
        }
    }
    free(ptr);
}

unsigned long wolfmqtt_test_broker_time_s(void)
{
    return g_broker_time_s;
}

#ifdef WOLFMQTT_BROKER_PERSIST
/* When set, fsync of a directory fails with EIO so a test can exercise the
 * POSIX persistence backend's durability error paths. */
static int g_fsync_dir_fail;

int wolfmqtt_test_broker_fsync(int fd)
{
    struct stat st;

    if (g_fsync_dir_fail && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        errno = EIO;
        return -1;
    }
    return fsync(fd);
}
#endif

#ifndef WOLFMQTT_STATIC_MEMORY
/* Count frees of one allocation, so a test can assert on a single object
 * rather than a total that unrelated activity moves. */
static void broker_test_watch_free(void* ptr)
{
    g_free_watch_ptr = ptr;
    g_free_watch_count = 0;
}

static int broker_test_watched_frees(void)
{
    return g_free_watch_count;
}
#endif

#ifndef WOLFMQTT_STATIC_MEMORY
static void broker_test_fail_alloc_after(int successful_allocations)
{
    g_alloc_fail_after = successful_allocations;
    g_alloc_failure_count = 0;
}

static void broker_test_disable_alloc_failure(void)
{
    g_alloc_fail_after = -1;
}
#endif

#if defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT) || \
    (defined(WOLFMQTT_BROKER_PERSIST) && !defined(WOLFMQTT_STATIC_MEMORY))
static void broker_test_capture_free(size_t allocation_size)
{
    g_capture_alloc_size = allocation_size;
    g_capture_alloc_ptr = NULL;
    g_capture_freed_len = 0;
    g_capture_free_seen = 0;
    XMEMSET(g_capture_freed, 0, sizeof(g_capture_freed));
}

static void broker_test_disable_free_capture(void)
{
    g_capture_alloc_size = 0;
    g_capture_alloc_ptr = NULL;
}
#endif

/* Mock socket constants */
#define MOCK_LISTEN_SOCK       100
#define MOCK_CLIENT_SOCK_BASE  101 /* sock = base + index */
#define MOCK_BUF_SZ            1024
/* Room for a PUBLISH that fills the broker receive buffer */
#define MOCK_IN_BUF_SZ         (BROKER_RX_BUF_SZ + 64)
#define MOCK_MAX_CLIENTS       4

/* Per-mock-client state. Multi-client tests (e.g. QoS 2 dedup) need a
 * subscriber and a publisher running through the same broker instance. */
typedef struct MockClient {
    byte   in_buf[MOCK_IN_BUF_SZ];
    size_t in_len;
    size_t in_pos;
    byte   out_buf[MOCK_BUF_SZ];
    size_t out_len;
    int    closed;
    int    close_count; /* net->close calls on this socket */
    int    publish_writes; /* PUBLISH frames the broker tried to write */
    int    read_err; /* when set, mock_read returns a network error (peer RST) */
    int    write_err; /* when set, mock_write returns a network error */
    int    write_continue; /* when set, mock_write reports would-block */
    int    write_limit_once; /* positive: short-write the next callback */
    /* positive: short-write the next callback to this many bytes and arm
     * write_err_pending, so the callback after it fails. Models a blocking
     * transport that gets part of a packet out before the socket errors -
     * a sequence the one-shot knobs above cannot express on their own. */
    int    write_limit_then_err;
    int    write_err_pending; /* next mock_write call returns a network error */
    /* When set, the next PUBLISH frame (and only that) fails. Lets a test aim
     * at a delivery without also failing the SUBACK that precedes it. */
    int    write_err_on_publish;
    /* positive: short-write the next PUBLISH frame to this many bytes */
    int    write_limit_on_publish;
    /* Next mock_write call reports a transient timeout: the socket is alive,
     * select() just did not report it writable in time. */
    int    write_timeout_pending;
} MockClient;

static MockClient g_clients[MOCK_MAX_CLIENTS];
static int g_clients_active;   /* how many clients accept() will hand out */
static int g_accept_count;     /* incremented per successful accept() */
static int g_accept_fail_rc;   /* non-zero: accept() returns this */
static int g_listen_count;
static int g_listen_close_count;
static int g_listen_fail_on_call;

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
    g_listen_count++;
    if (g_listen_count == g_listen_fail_on_call) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    *sock = MOCK_LISTEN_SOCK;
    return MQTT_CODE_SUCCESS;
}

static int mock_accept(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock)
{
    (void)ctx; (void)listen_sock;
    if (g_accept_fail_rc != 0) {
        return g_accept_fail_rc;
    }
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

#ifndef WOLFMQTT_STATIC_MEMORY
/* One-shot hook run from inside the first PUBLISH the broker writes. The mock
 * network has no lws_service, so this is how a test reproduces the mutation a
 * re-entrant WebSocket close performs part way through a fan-out. */
static void (*g_write_publish_hook)(void);
#endif

static int mock_write(void* ctx, BROKER_SOCKET_T sock,
    const byte* buf, int buf_len, int timeout_ms)
{
    int idx = sock_to_idx(sock);
    int write_len = buf_len;
    MockClient* mc;
    (void)ctx; (void)timeout_ms;
    if (idx < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    mc = &g_clients[idx];
    if (buf != NULL && buf_len > 0 &&
            ((buf[0] & 0xF0) >> 4) == MQTT_PACKET_TYPE_PUBLISH) {
        mc->publish_writes++;
    }
    if (mc->write_err_pending) {
        mc->write_err_pending = 0;
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (mc->write_timeout_pending) {
        mc->write_timeout_pending = 0;
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (mc->write_err_on_publish && buf != NULL && buf_len > 0 &&
            ((buf[0] & 0xF0) >> 4) == MQTT_PACKET_TYPE_PUBLISH) {
        mc->write_err_on_publish = 0;
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (mc->write_continue) {
        return MQTT_CODE_CONTINUE;
    }
    if (mc->write_limit_on_publish > 0 && buf != NULL && buf_len > 0 &&
            ((buf[0] & 0xF0) >> 4) == MQTT_PACKET_TYPE_PUBLISH) {
        if (write_len > mc->write_limit_on_publish) {
            write_len = mc->write_limit_on_publish;
        }
        mc->write_limit_on_publish = 0;
    }
    if (mc->write_limit_then_err > 0) {
        if (write_len > mc->write_limit_then_err) {
            write_len = mc->write_limit_then_err;
        }
        mc->write_limit_then_err = 0;
        mc->write_err_pending = 1;
    }
    if (mc->write_limit_once > 0) {
        if (write_len > mc->write_limit_once) {
            write_len = mc->write_limit_once;
        }
        mc->write_limit_once = 0;
    }
    if (mc->out_len + (size_t)write_len > sizeof(mc->out_buf)) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    /* Capture the bytes handed to the socket even when simulating a failure,
     * so a test can positively assert what the broker produced (i.e. that a
     * scrub target was actually written) before checking it was scrubbed. */
    XMEMCPY(mc->out_buf + mc->out_len, buf, (size_t)write_len);
    mc->out_len += (size_t)write_len;
#ifndef WOLFMQTT_STATIC_MEMORY
    if (g_write_publish_hook != NULL && write_len > 0 &&
            ((buf[0] & 0xF0) >> 4) == MQTT_PACKET_TYPE_PUBLISH) {
        void (*hook)(void) = g_write_publish_hook;
        g_write_publish_hook = NULL; /* one shot */
        hook();
    }
#endif
    if (mc->write_err) {
        return MQTT_CODE_ERROR_NETWORK; /* simulate a hard write failure */
    }
    return write_len;
}

static int mock_close(void* ctx, BROKER_SOCKET_T sock)
{
    int idx = sock_to_idx(sock);
    (void)ctx;
    if (idx >= 0) {
        g_clients[idx].closed = 1;
        g_clients[idx].close_count++;
    }
    else if (sock == MOCK_LISTEN_SOCK) {
        g_listen_close_count++;
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
    g_accept_fail_rc = 0;
#ifndef WOLFMQTT_STATIC_MEMORY
    g_write_publish_hook = NULL;
#endif
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

static void setup(void)
{
    g_broker_time_s = 0;
    g_listen_count = 0;
    g_listen_close_count = 0;
    g_listen_fail_on_call = 0;
}
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

#ifdef WOLFMQTT_BROKER_WILL
/* Build a v5 CONNECT with a Will from the wire layout in MQTT 5.0 section
 * 3.1.2 and 3.1.3. The Remaining Length uses the section 1.5.5 algorithm. */
static size_t build_v5_connect_will(byte* out, size_t out_sz,
    word16 topic_len, word16 payload_len)
{
    word32 remain_len = 11u + 3u + 1u + 2u + topic_len + 2u + payload_len;
    word32 value = remain_len;
    size_t pos = 0;
    word16 i;

    if (out == NULL || remain_len + 5u > out_sz) {
        return 0;
    }
    out[pos++] = 0x10;
    do {
        byte encoded = (byte)(value % 128u);
        value /= 128u;
        if (value > 0) {
            encoded |= 0x80;
        }
        out[pos++] = encoded;
    } while (value > 0);

    out[pos++] = 0x00;
    out[pos++] = 0x04;
    out[pos++] = 'M';
    out[pos++] = 'Q';
    out[pos++] = 'T';
    out[pos++] = 'T';
    out[pos++] = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    out[pos++] = 0x06; /* Clean Start and Will Flag. */
    out[pos++] = 0x00;
    out[pos++] = 0x3C;
    out[pos++] = 0x00; /* CONNECT Properties length. */
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 'i';
    out[pos++] = 0x00; /* Will Properties length. */
    out[pos++] = (byte)(topic_len >> 8);
    out[pos++] = (byte)topic_len;
    for (i = 0; i < topic_len; i++) {
        out[pos++] = 't';
    }
    out[pos++] = (byte)(payload_len >> 8);
    out[pos++] = (byte)payload_len;
    for (i = 0; i < payload_len; i++) {
        out[pos++] = 0xA5;
    }
    return pos;
}
#endif
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

#ifndef WOLFMQTT_STATIC_MEMORY
TEST(connect_v311_client_id_alloc_failure_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x02, 'i', 'd'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    /* Client object and its two I/O buffers precede ClientId storage. */
    broker_test_fail_alloc_after(3);
    run_broker_one_connect(&broker);
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_V5
TEST(connect_v5_client_id_alloc_failure_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    static const byte connect[] = {
        0x10, 15,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x02, 'i', 'd'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    broker_test_fail_alloc_after(3);
    run_broker_one_connect(&broker);
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_TRUE(g_out_len >= 5);
    ASSERT_EQ(MQTT_REASON_SERVER_UNAVAILABLE, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif
#endif

#if !defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_BROKER_WILL)
/* A Will that cannot be stored in full must not be accepted in altered form:
 * a missing Will Topic would drop the Will and a missing Will Payload would
 * publish an empty one (MQTT 3.1.1 section 3.1.2.5). The CONNECT is refused
 * with "Server unavailable" instead. fail_after selects the Will Topic or
 * Will Payload copy. */
static void connect_will_alloc_failure_refused(int fail_after)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* CONNECT with Will: flags 0x06 (will_flag | clean_session), ClientId
     * "P", Will Topic "lwt", Will Payload "bye". */
    static const byte connect[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x06, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    broker_test_fail_alloc_after(fail_after);
    run_broker_one_connect(&broker);
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(connect_will_topic_alloc_failure_refused)
{
    /* Client object, two I/O buffers and ClientId precede the Will Topic. */
    connect_will_alloc_failure_refused(4);
}

TEST(connect_will_payload_alloc_failure_refused)
{
    connect_will_alloc_failure_refused(5);
}

/* CleanSession 0 with no stored Session also creates a new Session. A
 * refused CONNECT must not orphan it either, since nothing was resumed. */
TEST(connect_v311_resume_will_alloc_failure_leaves_no_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* CONNECT with Will: flags 0x04 (will_flag, CleanSession 0), ClientId
     * "P", Will Topic "lwt", Will Payload "bye". */
    static const byte connect[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x04, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    int orphans;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    /* Client object, two I/O buffers and ClientId precede the Will Topic. */
    broker_test_fail_alloc_after(4);
    run_broker_one_connect(&broker);
    broker_test_disable_alloc_failure();
    orphans = broker.orphan_session_count;

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);
    ASSERT_EQ(0, orphans);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_V5
/* A refused CONNECT must not leave behind a Session it created. With Clean
 * Start and a non-zero Session Expiry Interval, the Session is new and empty;
 * orphaning it after the refusal would hold (and at capacity evict for) a
 * Session nobody can resume [MQTT-3.2.2-4]. */
TEST(connect_v5_will_alloc_failure_leaves_no_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* v5 CONNECT: flags 0x06 (will_flag | clean_start), keep alive 60,
     * properties: Session Expiry Interval (0x11) = 60, ClientId "P", Will
     * Properties length 0, Will Topic "lwt", Will Payload "bye".
     * Remaining Length 30. */
    static const byte connect[] = {
        0x10, 0x1E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x06, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    int orphans;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    /* Client object, two I/O buffers and ClientId precede the Will Topic. */
    broker_test_fail_alloc_after(4);
    run_broker_one_connect(&broker);
    broker_test_disable_alloc_failure();
    orphans = broker.orphan_session_count;

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_REASON_SERVER_UNAVAILABLE, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);
    ASSERT_EQ(0, orphans);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */

static int count_packets_of_type(const byte* buf, size_t len, byte type);

/* A CONNECT refused because its Will cannot be stored must not take over the
 * connected client that holds the same ClientId: that client stays connected
 * with its Session (here, its subscription) unchanged. */
TEST(connect_will_alloc_failure_keeps_incumbent_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int incumbent_closed;
    int incumbent_publishes;
    /* CONNECT: CleanSession 0, keep alive 60, ClientId "P". */
    static const byte incumbent_connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* SUBSCRIBE packet id 1, filter "t", QoS 0. */
    static const byte incumbent_subscribe[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 't',
        0x00
    };
    /* CONNECT with Will: flags 0x04 (will_flag, CleanSession 0), ClientId
     * "P", Will Topic "lwt", Will Payload "bye". */
    static const byte takeover_connect[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x04, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* QoS 0 PUBLISH to "t", payload "x". */
    static const byte publish[] = {
        0x30, 0x04,
        0x00, 0x01, 't',
        'x'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, incumbent_connect, sizeof(incumbent_connect));
    mock_client_input_append(0, incumbent_subscribe,
        sizeof(incumbent_subscribe));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Both connections are already accepted; the ClientId copy precedes the
     * Will Topic. */
    mock_client_input_append(1, takeover_connect, sizeof(takeover_connect));
    broker_test_fail_alloc_after(1);
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();

    mock_client_input_append(0, publish, sizeof(publish));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    incumbent_closed = g_clients[0].closed;
    incumbent_publishes = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_TRUE(g_clients[1].out_len >= 4);
    ASSERT_EQ(0x20, g_clients[1].out_buf[0]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL, g_clients[1].out_buf[3]);
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_FALSE(incumbent_closed);
    ASSERT_EQ(1, incumbent_publishes);
}
#endif /* !WOLFMQTT_STATIC_MEMORY && WOLFMQTT_BROKER_WILL */

#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
TEST(connect_v5_oversize_will_payload_emits_connack)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[MOCK_BUF_SZ];
    size_t connect_len;

    connect_len = build_v5_connect_will(connect, sizeof(connect), 1,
        BROKER_MAX_WILL_PAYLOAD_LEN + 1);
    ASSERT_TRUE(connect_len > 0);

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    /* [MQTT-3.2.2-2] A refused v5 CONNECT carries a valid Reason Code. */
    ASSERT_TRUE(g_out_len >= 5);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x03, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_REASON_PACKET_TOO_LARGE, g_out_buf[3]);
    ASSERT_EQ(0x00, g_out_buf[4]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_STATIC_MEMORY
/* A static Session cannot store Will Properties larger than
 * BROKER_MAX_WILL_PROPS_LEN. Dropping some would publish the Will altered, so
 * the CONNECT is refused instead. Wire: v5 CONNECT with Will Flag and Clean
 * Start, ClientId "P", Will Properties holding one User Property (0x26)
 * "k" = BROKER_MAX_WILL_PROPS_LEN bytes of 'v', Will Topic "lwt", Will
 * Payload "bye". */
TEST(connect_v5_oversize_will_props_emits_connack)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[MOCK_BUF_SZ];
    size_t pos = 0;
    word32 value_len = BROKER_MAX_WILL_PROPS_LEN;
    word32 props_len = 1 + 3 + 2 + value_len;
    word32 remain;
    word32 v;

    remain = 11 + 3 + ((props_len > 127) ? 2 : 1) + props_len + 5 + 5;
    ASSERT_TRUE(remain + 3 <= sizeof(connect));
    connect[pos++] = 0x10;
    for (v = remain; ; ) {
        connect[pos] = (byte)(v & 0x7F);
        v >>= 7;
        if (v == 0) {
            pos++;
            break;
        }
        connect[pos++] |= 0x80;
    }
    XMEMCPY(&connect[pos], "\x00\x04MQTT\x05\x06\x00\x3C\x00", 11);
    pos += 11;
    XMEMCPY(&connect[pos], "\x00\x01P", 3);
    pos += 3;
    for (v = props_len; ; ) {
        connect[pos] = (byte)(v & 0x7F);
        v >>= 7;
        if (v == 0) {
            pos++;
            break;
        }
        connect[pos++] |= 0x80;
    }
    connect[pos++] = MQTT_PROP_USER_PROP;
    XMEMCPY(&connect[pos], "\x00\x01k", 3);
    pos += 3;
    connect[pos++] = (byte)(value_len >> 8);
    connect[pos++] = (byte)value_len;
    XMEMSET(&connect[pos], 'v', value_len);
    pos += value_len;
    XMEMCPY(&connect[pos], "\x00\x03lwt\x00\x03" "bye", 10);
    pos += 10;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, pos);
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 5);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_REASON_PACKET_TOO_LARGE, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#if BROKER_MAX_STATIC_OFFLINE_DATA_LEN - 5 < BROKER_MAX_WILL_PAYLOAD_LEN && \
    WOLFMQTT_MAX_QOS >= 1
/* Builds a v5 CONNECT, MQTT 5.0 section 3.1: Clean Start, Will Flag, Will QoS
 * 1, Keep Alive 60, ClientId "P", Will Properties holding a Message Expiry
 * Interval (0x02) of 60 when with_expiry is set (otherwise an empty Will
 * Properties length of 0), Will Topic "lwt" and payload_len bytes of 'x'. */
static size_t build_v5_connect_will_expiry(byte* buf, size_t buf_sz,
    word32 payload_len, int with_expiry)
{
    size_t pos = 0;
    word32 remain = 11 + 3 + 1 + (with_expiry ? 5 : 0) + 5 + 2 + payload_len;
    word32 v;

    if (remain + 4 > buf_sz) {
        return 0;
    }
    buf[pos++] = 0x10;
    for (v = remain; ; ) {
        buf[pos] = (byte)(v & 0x7F);
        v >>= 7;
        if (v == 0) {
            pos++;
            break;
        }
        buf[pos++] |= 0x80;
    }
    XMEMCPY(&buf[pos], "\x00\x04MQTT\x05\x0E\x00\x3C\x00", 11);
    pos += 11;
    XMEMCPY(&buf[pos], "\x00\x01P", 3);
    pos += 3;
    if (with_expiry) {
        XMEMCPY(&buf[pos], "\x05\x02\x00\x00\x00\x3C", 6);
        pos += 6;
    }
    else {
        buf[pos++] = 0x00;
    }
    XMEMCPY(&buf[pos], "\x00\x03lwt", 5);
    pos += 5;
    buf[pos++] = (byte)(payload_len >> 8);
    buf[pos++] = (byte)payload_len;
    XMEMSET(&buf[pos], 'x', payload_len);
    pos += payload_len;
    return pos;
}

/* Builds a v3.1.1 CONNECT, MQTT 3.1.1 section 3.1: Clean Session, Will Flag,
 * Will QoS will_qos, Keep Alive 60, ClientId "P", Will Topic "lwt" and
 * payload_len bytes of 'x'. */
static size_t build_v311_connect_will_qos(byte* buf, size_t buf_sz,
    byte will_qos, word32 payload_len)
{
    size_t pos = 0;
    word32 remain = 10 + 3 + 5 + 2 + payload_len;
    word32 v;

    if (remain + 4 > buf_sz) {
        return 0;
    }
    buf[pos++] = 0x10;
    for (v = remain; ; ) {
        buf[pos] = (byte)(v & 0x7F);
        v >>= 7;
        if (v == 0) {
            pos++;
            break;
        }
        buf[pos++] |= 0x80;
    }
    XMEMCPY(&buf[pos], "\x00\x04MQTT\x04", 7);
    pos += 7;
    buf[pos++] = (byte)(0x06 | (will_qos << 3));
    buf[pos++] = 0x00;
    buf[pos++] = 0x3C;
    XMEMCPY(&buf[pos], "\x00\x01P", 3);
    pos += 3;
    XMEMCPY(&buf[pos], "\x00\x03lwt", 5);
    pos += 5;
    buf[pos++] = (byte)(payload_len >> 8);
    buf[pos++] = (byte)payload_len;
    XMEMSET(&buf[pos], 'x', payload_len);
    pos += payload_len;
    return pos;
}

/* Runs one CONNECT and returns the CONNACK return or Reason Code, or -1. */
static int connect_connack_code(const byte* connect, size_t connect_len)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int reason = -1;

    if (connect_len == 0) {
        return -1;
    }
    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS) {
        return -1;
    }
    if (MqttBroker_Start(&broker) == MQTT_CODE_SUCCESS) {
        reset_mock_state(connect, connect_len);
        run_broker_one_connect(&broker);
        if (g_out_len >= 4 && g_out_buf[0] == 0x20) {
            reason = g_out_buf[3];
        }
        MqttBroker_Stop(&broker);
    }
    MqttBroker_Free(&broker);
    return reason;
}

/* Runs one v5 Will CONNECT and returns the CONNACK Reason Code, or -1. */
static int will_expiry_connack(word32 payload_len, int with_expiry)
{
    byte connect[MOCK_BUF_SZ];

    return connect_connack_code(connect,
        build_v5_connect_will_expiry(connect, sizeof(connect), payload_len,
            with_expiry));
}

/* Runs one v3.1.1 Will CONNECT and returns the CONNACK return code, or -1. */
static int v311_will_connack(byte will_qos, word32 payload_len)
{
    byte connect[MOCK_BUF_SZ];

    return connect_connack_code(connect,
        build_v311_connect_will_qos(connect, sizeof(connect), will_qos,
            payload_len));
}

/* A static QoS 1/2 Will may have to be queued for an offline Session, where
 * its payload and properties share one BROKER_MAX_STATIC_OFFLINE_DATA_LEN
 * slot. One that cannot fit is refused at CONNECT rather than accepted and
 * then dropped when it is published. */
TEST(connect_v5_static_will_exceeding_offline_slot_refused)
{
    /* Payload plus the 5-byte Message Expiry Interval fills the slot. */
    ASSERT_EQ(MQTT_REASON_SUCCESS,
        will_expiry_connack(BROKER_MAX_STATIC_OFFLINE_DATA_LEN - 5, 1));
    ASSERT_EQ(MQTT_REASON_PACKET_TOO_LARGE,
        will_expiry_connack(BROKER_MAX_STATIC_OFFLINE_DATA_LEN - 4, 1));
    ASSERT_TRUE(g_client_closed);
}

#if BROKER_MAX_STATIC_OFFLINE_DATA_LEN < BROKER_MAX_WILL_PAYLOAD_LEN
/* A Will with no publishable properties must also fit the offline slot. */
TEST(connect_v5_static_payload_only_will_exceeding_offline_slot_refused)
{
    ASSERT_EQ(MQTT_REASON_SUCCESS,
        will_expiry_connack(BROKER_MAX_STATIC_OFFLINE_DATA_LEN, 0));
    ASSERT_EQ(MQTT_REASON_PACKET_TOO_LARGE,
        will_expiry_connack(BROKER_MAX_STATIC_OFFLINE_DATA_LEN + 1, 0));
    ASSERT_TRUE(g_client_closed);
}

/* The same limit applies to a v3.1.1 QoS 1 Will, refused with return code
 * 0x03 Server unavailable (MQTT 3.1.1 section 3.2.2.3). A QoS 0 Will is never
 * queued offline, so it only has to fit BROKER_MAX_WILL_PAYLOAD_LEN. */
TEST(connect_v311_static_will_exceeding_offline_slot_refused)
{
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED,
        v311_will_connack(1, BROKER_MAX_STATIC_OFFLINE_DATA_LEN));
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL,
        v311_will_connack(1, BROKER_MAX_STATIC_OFFLINE_DATA_LEN + 1));
    ASSERT_TRUE(g_client_closed);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED,
        v311_will_connack(0, BROKER_MAX_STATIC_OFFLINE_DATA_LEN + 1));
}
#endif
#endif

TEST(connect_v5_oversize_will_topic_emits_connack)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[MOCK_BUF_SZ];
    size_t connect_len;

    connect_len = build_v5_connect_will(connect, sizeof(connect),
        BROKER_MAX_TOPIC_LEN, 0);
    ASSERT_TRUE(connect_len > 0);

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    /* [MQTT-3.2.2-2] The server reports a rejected Will Topic in CONNACK. */
    ASSERT_TRUE(g_out_len >= 5);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x03, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_REASON_TOPIC_NAME_INVALID, g_out_buf[3]);
    ASSERT_EQ(0x00, g_out_buf[4]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif
#endif

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

/* The body of a CONNECT is laid out by its Protocol Level, so a level this
 * build does not speak may not decode at all. [MQTT-3.1.2-2] still requires
 * CONNACK 0x01 rather than a silent close, which is also what lets an MQTT 5
 * client fall back to 3.1.1 against a broker built without v5. */
static void run_undecodable_unsupported_level(const byte* connect,
    size_t connect_len)
{
    MqttBroker broker;
    MqttBrokerNet net;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x02, g_out_buf[1]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_PROTO, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(connect_unsupported_level_undecodable_refused)
{
    /* Level 6, ClientId length 5 with one byte present: malformed whether
     * the body is read with or without a v5 Property Length. */
    static const byte connect[] = {
        0x10, 13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x06, /* unsupported protocol level */
        0x02, /* CleanSession=1 */
        0x00, 0x3C,
        0x00, 0x05, 'A'
    };

    run_undecodable_unsupported_level(connect, sizeof(connect));
}

#ifndef WOLFMQTT_V5
TEST(connect_v5_to_non_v5_broker_refused)
{
    /* A well-formed MQTT 5 CONNECT (MQTT 5.0 section 3.1.2) with a Session
     * Expiry Interval property. Read as 3.1.1, the Property Length 0x05 and
     * the property identifier 0x11 become a 0x0511-byte ClientId length. */
    static const byte connect[] = {
        0x10, 19,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, /* MQTT 5.0 */
        0x02, /* CleanStart=1 */
        0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C, /* Session Expiry = 60 */
        0x00, 0x01, 'A'
    };

    run_undecodable_unsupported_level(connect, sizeof(connect));
}
#endif

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
    ASSERT_EQ(0, g_listen_count);
    ASSERT_EQ(BROKER_SOCKET_INVALID, broker.listen_sock);

    broker.auth_pass = "pass";
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    ASSERT_EQ(1, g_listen_count);

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

#ifdef ENABLE_MQTT_TLS
TEST(broker_start_partial_listener_failure_cleans_up)
{
    MqttBroker broker;
    MqttBrokerNet net;
    WOLFSSL_CTX* external_tls_ctx;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    external_tls_ctx = (WOLFSSL_CTX*)&broker;
    broker.tls_ctx = external_tls_ctx;
    broker.use_tls = 1;
    broker.port_tls = (word16)(broker.port + 1);
    g_listen_fail_on_call = 2;

    ASSERT_EQ(MQTT_CODE_ERROR_NETWORK, MqttBroker_Start(&broker));
    ASSERT_EQ(2, g_listen_count);
    ASSERT_EQ(1, g_listen_close_count);
    ASSERT_EQ(BROKER_SOCKET_INVALID, broker.listen_sock);
    ASSERT_EQ(BROKER_SOCKET_INVALID, broker.listen_sock_tls);
    ASSERT_TRUE(broker.tls_ctx == external_tls_ctx);

    g_listen_fail_on_call = 0;
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    ASSERT_EQ(4, g_listen_count);

    broker.tls_ctx = NULL;
    MqttBroker_Free(&broker);
}

/* A TLS accept with no tls_ctx fails BrokerClient_Add after the socket was
 * recorded in the client. The caller closes the rejected socket, so the
 * failed add must not close it too; a second close could hit a reused fd. */
TEST(broker_add_failure_closes_socket_once)
{
    MqttBroker broker;
    MqttBrokerNet net;

    install_mock_net(&net);
    reset_mock_clients(1);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    ASSERT_TRUE(broker.tls_ctx == NULL);

    /* Route the next accept through the TLS listener only */
    broker.listen_sock = BROKER_SOCKET_INVALID;
    broker.listen_sock_tls = MOCK_LISTEN_SOCK;

    MqttBroker_Step(&broker);
    ASSERT_EQ(1, g_accept_count);
    ASSERT_EQ(1, g_clients[0].close_count);

    broker.listen_sock = MOCK_LISTEN_SOCK;
    broker.listen_sock_tls = BROKER_SOCKET_INVALID;
    MqttBroker_Free(&broker);
}
#endif

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

/* ---------------------------------------------------------------------------
 * wolfmqtt_broker_set_auth_pass: the CLI -P copy/length/scrub logic. The
 * argument loop in wolfmqtt_broker is unreachable in the CUSTOM_NET test build
 * (it returns before parsing), so the helper is exercised directly.
 * ------------------------------------------------------------------------- */

TEST(broker_set_auth_pass_valid)
{
    MqttBroker broker;
    char pass_arg[BROKER_MAX_PASSWORD_LEN];
    char auth_pass_buf[BROKER_MAX_PASSWORD_LEN];

    XMEMSET(&broker, 0, sizeof(broker));
    /* Non-zero fill proves the helper clears the destination before copying. */
    XMEMSET(auth_pass_buf, 0xAA, sizeof(auth_pass_buf));
    XMEMSET(pass_arg, 0, sizeof(pass_arg));
    XMEMCPY(pass_arg, "secretpw", 8);

    ASSERT_EQ(MQTT_CODE_SUCCESS, wolfmqtt_broker_set_auth_pass(&broker,
        pass_arg, auth_pass_buf, (word32)sizeof(auth_pass_buf)));
    ASSERT_TRUE(broker.auth_pass == auth_pass_buf);
    ASSERT_EQ(0, XSTRCMP(auth_pass_buf, "secretpw"));
    /* Source argv slot scrubbed. */
    ASSERT_EQ('\0', pass_arg[0]);
}

TEST(broker_set_auth_pass_max_len_valid)
{
    MqttBroker broker;
    char pass_arg[BROKER_MAX_PASSWORD_LEN + 1];
    char auth_pass_buf[BROKER_MAX_PASSWORD_LEN];
    int i;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(auth_pass_buf, 0, sizeof(auth_pass_buf));
    XMEMSET(pass_arg, 0, sizeof(pass_arg));
    /* BROKER_MAX_PASSWORD_LEN-1 characters is the longest accepted. */
    for (i = 0; i < BROKER_MAX_PASSWORD_LEN - 1; i++) {
        pass_arg[i] = 'a';
    }

    ASSERT_EQ(MQTT_CODE_SUCCESS, wolfmqtt_broker_set_auth_pass(&broker,
        pass_arg, auth_pass_buf, (word32)sizeof(auth_pass_buf)));
    ASSERT_EQ(BROKER_MAX_PASSWORD_LEN - 1, (int)XSTRLEN(auth_pass_buf));
}

TEST(broker_set_auth_pass_too_long_rejected)
{
    MqttBroker broker;
    char pass_arg[BROKER_MAX_PASSWORD_LEN + 8];
    char auth_pass_buf[BROKER_MAX_PASSWORD_LEN];
    int i;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(auth_pass_buf, 0, sizeof(auth_pass_buf));
    XMEMSET(pass_arg, 0, sizeof(pass_arg));
    /* BROKER_MAX_PASSWORD_LEN characters is one too many. */
    for (i = 0; i < BROKER_MAX_PASSWORD_LEN; i++) {
        pass_arg[i] = 'a';
    }

    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, wolfmqtt_broker_set_auth_pass(&broker,
        pass_arg, auth_pass_buf, (word32)sizeof(auth_pass_buf)));
    /* The over-long argv slot is still scrubbed. */
    ASSERT_EQ('\0', pass_arg[0]);
}

TEST(broker_set_auth_pass_too_long_wipes_prior)
{
    /* Repeated -P: a valid password followed by a too-long one must not leave
     * the first password resident in the broker-owned buffer. */
    MqttBroker broker;
    char first[BROKER_MAX_PASSWORD_LEN];
    char second[BROKER_MAX_PASSWORD_LEN + 8];
    char auth_pass_buf[BROKER_MAX_PASSWORD_LEN];
    char zero[BROKER_MAX_PASSWORD_LEN];
    int i;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(auth_pass_buf, 0, sizeof(auth_pass_buf));
    XMEMSET(zero, 0, sizeof(zero));
    XMEMSET(first, 0, sizeof(first));
    XMEMSET(second, 0, sizeof(second));
    XMEMCPY(first, "firstpw", 7);
    for (i = 0; i < BROKER_MAX_PASSWORD_LEN; i++) {
        second[i] = 'b';
    }

    ASSERT_EQ(MQTT_CODE_SUCCESS, wolfmqtt_broker_set_auth_pass(&broker,
        first, auth_pass_buf, (word32)sizeof(auth_pass_buf)));
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, wolfmqtt_broker_set_auth_pass(&broker,
        second, auth_pass_buf, (word32)sizeof(auth_pass_buf)));
    /* No residue of "firstpw" survives the rejected second argument. */
    ASSERT_EQ(0, XMEMCMP(auth_pass_buf, zero, sizeof(auth_pass_buf)));
}

TEST(broker_set_auth_pass_shorter_second_no_residue)
{
    /* A shorter second -P must not leave the first password's tail past the
     * new NUL terminator. */
    MqttBroker broker;
    char first[BROKER_MAX_PASSWORD_LEN];
    char second[BROKER_MAX_PASSWORD_LEN];
    char auth_pass_buf[BROKER_MAX_PASSWORD_LEN];
    char zero[BROKER_MAX_PASSWORD_LEN];

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(auth_pass_buf, 0, sizeof(auth_pass_buf));
    XMEMSET(zero, 0, sizeof(zero));
    XMEMSET(first, 0, sizeof(first));
    XMEMSET(second, 0, sizeof(second));
    XMEMCPY(first, "longpassword", 12);
    XMEMCPY(second, "x", 1);

    ASSERT_EQ(MQTT_CODE_SUCCESS, wolfmqtt_broker_set_auth_pass(&broker,
        first, auth_pass_buf, (word32)sizeof(auth_pass_buf)));
    ASSERT_EQ(MQTT_CODE_SUCCESS, wolfmqtt_broker_set_auth_pass(&broker,
        second, auth_pass_buf, (word32)sizeof(auth_pass_buf)));
    ASSERT_EQ(0, XSTRCMP(auth_pass_buf, "x"));
    /* Everything after "x\0" is zero - no "longpassword" tail. */
    ASSERT_EQ(0, XMEMCMP(auth_pass_buf + 1, zero, sizeof(auth_pass_buf) - 1));
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

/* Build a v5 CONNECT with an empty ClientId and n_props minimal User
 * Properties. Returns the packet length, or 0 if it would not fit in out_sz. */
static size_t build_v5_connect_emptyid_userprops(byte* out, size_t out_sz,
    int n_props)
{
    static const byte one_prop[] = {
        0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v'  /* User Property "k"="v" */
    };
    word32 props_len = (word32)n_props * (word32)sizeof(one_prop);
    byte props_len_vbi[5];
    int props_len_sz;
    word32 remain;
    byte remain_vbi[5];
    int remain_sz;
    size_t pos = 0;
    int i;

    props_len_sz = MqttEncode_Vbi(props_len_vbi, props_len);
    remain = 6 + 1 + 1 + 2 + (word32)props_len_sz + props_len + 2;
    remain_sz = MqttEncode_Vbi(remain_vbi, remain);
    if ((size_t)(1 + remain_sz) + remain > out_sz) {
        return 0;
    }

    out[pos++] = 0x10;                       /* CONNECT */
    XMEMCPY(out + pos, remain_vbi, (size_t)remain_sz);
    pos += (size_t)remain_sz;
    out[pos++] = 0x00; out[pos++] = 0x04;
    out[pos++] = 'M'; out[pos++] = 'Q'; out[pos++] = 'T'; out[pos++] = 'T';
    out[pos++] = 0x05;                       /* protocol level 5 */
    out[pos++] = 0x02;                       /* Clean Start */
    out[pos++] = 0x00; out[pos++] = 0x3C;    /* keepalive 60 */
    XMEMCPY(out + pos, props_len_vbi, (size_t)props_len_sz);
    pos += (size_t)props_len_sz;
    for (i = 0; i < n_props; i++) {
        XMEMCPY(out + pos, one_prop, sizeof(one_prop));
        pos += sizeof(one_prop);
    }
    out[pos++] = 0x00; out[pos++] = 0x00;    /* empty ClientId */
    return pos;
}

/* A v5 CONNECT with an empty ClientId that also fills the shared property pool
 * with User Properties must still receive its mandatory Assigned Client
 * Identifier in CONNACK: the decoded CONNECT properties are released before the
 * CONNACK properties are built. */
TEST(connect_v5_emptyid_assigned_id_survives_prop_pool_pressure)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[MQTT_MAX_PROPS * 7 + 64];
    size_t connect_len;
    word16 assigned_id_len;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    connect_len = build_v5_connect_emptyid_userprops(connect, sizeof(connect),
        MQTT_MAX_PROPS);
    ASSERT_TRUE(connect_len > 0);
    reset_mock_state(connect, connect_len);
    run_broker_one_connect(&broker);

    /* CONNACK must be accepted and carry the Assigned Client Identifier as its
     * first property (see connect_v5_emptyid_assigned_id_emitted for layout). */
    ASSERT_TRUE(g_out_len >= 8);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_REASON_SUCCESS, g_out_buf[3]);
    ASSERT_EQ(MQTT_PROP_ASSIGNED_CLIENT_ID, g_out_buf[5]);
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

TEST(unsubscribe_v5_reason_codes)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int rc;
    MqttUnsubscribeAck ack;
    /* CONNECT subscriber "A". */
    static const byte connect_sub[] = {
        0x10, 0x0E, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };
    /* SUBSCRIBE packet_id=1, filter "x", QoS 0, properties length 0. */
    static const byte subscribe_x[] = {
        0x82, 0x07,             /* Fixed header, remaining length 7. */
        0x00, 0x01,             /* Packet Identifier 1. */
        0x00,                   /* Properties length 0 (MQTT 5). */
        0x00, 0x01, 'x', 0x00  /* Filter "x", QoS 0. */
    };
    /* UNSUBSCRIBE packet_id=2, filter "x", properties length 0. */
    static const byte unsubscribe_x[] = {
        0xA2, 0x06, 0x00, 0x02, 0x00, 0x00, 0x01, 'x'
    };
    /* UNSUBSCRIBE packet_id=3, filter "y", properties length 0. */
    static const byte unsubscribe_y[] = {
        0xA2, 0x06, 0x00, 0x03, 0x00, 0x00, 0x01, 'y'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
    }

    /* Discard the CONNECT/SUBACK bytes so the next captured stream contains
     * only the UNSUBACK being checked. */
    ASSERT_FALSE(g_clients[0].closed);
    g_clients[0].out_len = 0;

    /* Filter "x" will be successfully unsubscribed. */
    mock_client_input_append(0, unsubscribe_x, sizeof(unsubscribe_x));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Confirms reason code is MQTT_REASON_SUCCESS. */
    ASSERT_TRUE(g_clients[0].out_len > 0);
    XMEMSET(&ack, 0, sizeof(ack));
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_UnsubscribeAck(g_clients[0].out_buf,
        (int)g_clients[0].out_len, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(2, ack.packet_id);
    ASSERT_EQ(1, ack.reason_code_count);
    ASSERT_EQ(MQTT_REASON_SUCCESS, ack.reason_codes[0]);

    /* Filter "y" was never subscribed.
     * Reason code should be MQTT_REASON_NO_SUB_EXIST. */
    g_clients[0].out_len = 0;
    mock_client_input_append(0, unsubscribe_y, sizeof(unsubscribe_y));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    XMEMSET(&ack, 0, sizeof(ack));
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_UnsubscribeAck(g_clients[0].out_buf,
        (int)g_clients[0].out_len, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(3, ack.packet_id);
    ASSERT_EQ(1, ack.reason_code_count);
    ASSERT_EQ(MQTT_REASON_NO_SUB_EXIST, ack.reason_codes[0]);

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

#ifdef WOLFMQTT_NONBLOCK
/* A refused CONNECT whose CONNACK cannot be written at once keeps the client
 * until the write finishes or times out. Its credentials are not needed for
 * that, so they must be wiped as on the accepted path rather than stay in
 * rx_buf and the username/password copies for the whole deferred write.
 * Only nonblocking builds defer the write; a blocking write completes it. */
TEST(connect_refused_deferred_connack_scrubs_credentials)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* bc;
    /* CONNECT v3.1.1, ClientId "id", Username "alice", Password "wrongPW1"
     * (the broker expects "s3cr3tPW"). connect_flags 0xC2 = username +
     * password + clean session. */
    static const byte connect[] = {
        0x10, 31,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04,
        0xC2,
        0x00, 0x3C,
        0x00, 0x02, 'i', 'd',
        0x00, 0x05, 'a', 'l', 'i', 'c', 'e',
        0x00, 0x08, 'w', 'r', 'o', 'n', 'g', 'P', 'W', '1'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    broker.auth_user = "alice";
    broker.auth_pass = "s3cr3tPW";
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    /* Only one CONNACK byte goes out, so the refusal is deferred. */
    g_clients[0].write_limit_once = 1;
    run_broker_one_connect(&broker);

    bc = broker.clients;
    ASSERT_NOT_NULL(bc);
    ASSERT_EQ(1, (int)bc->connack_refused);
    ASSERT_EQ(0, (int)bc->connected);

    ASSERT_EQ(0, (int)bc->password_len);
    if (bc->password != NULL) {
        ASSERT_EQ(0, region_contains((const byte*)bc->password, 8,
            "wrongPW1", 8));
    }
    ASSERT_EQ(0, region_contains(bc->rx_buf, (int)sizeof(connect),
        "wrongPW1", 8));
    ASSERT_EQ(0, region_contains(bc->rx_buf, (int)sizeof(connect),
        "alice", 5));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK */
#endif /* WOLFMQTT_BROKER_AUTH */

#ifndef WOLFMQTT_STATIC_MEMORY
/* One v3.1.1 CONNECT with CleanSession 0 for ClientId "c<NNN>" (MQTT 3.1.1
 * section 3.1), optionally followed by DISCONNECT, through mock client 0.
 * Returns the CONNACK return code, or -1 if none was written. */
static int session_cap_connect(MqttBroker* broker, int n, int disconnect)
{
    static const byte disc[] = { 0xE0, 0x00 };
    byte connect[] = {
        0x10, 16,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C, /* level 4, CleanSession 0 */
        0x00, 0x04, 'c', '0', '0', '0'
    };
    int i;

    connect[15] = (byte)('0' + (n / 100) % 10);
    connect[16] = (byte)('0' + (n / 10) % 10);
    connect[17] = (byte)('0' + n % 10);
    reset_mock_state(connect, sizeof(connect));
    if (disconnect) {
        mock_client_input_append(0, disc, sizeof(disc));
    }
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(broker);
        if (g_client_closed) {
            break;
        }
    }
    if (g_out_len < 4 || g_out_buf[0] != 0x20) {
        return -1;
    }
    return g_out_buf[3];
}

static int session_cap_has_orphan(MqttBroker* broker, const char* client_id)
{
    BrokerOrphanSession* o;

    for (o = broker->orphan_sessions; o != NULL; o = o->next) {
        if (o->client_id != NULL && XSTRCMP(o->client_id, client_id) == 0) {
            return 1;
        }
    }
    return 0;
}

/* With BROKER_MAX_PERSIST_SESSIONS persistent Sessions held, a CONNECT asking
 * for another one must be refused (CONNACK 0x03 Server unavailable, MQTT
 * 3.1.1 section 3.2.2.3) rather than accepted and later admitted by evicting
 * another client's saved Session. A client resuming its own Session does not
 * add one and is still accepted. */
TEST(connect_persistent_session_cap_refuses_new_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int n;
    int rc;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    for (n = 0; n < BROKER_MAX_PERSIST_SESSIONS; n++) {
        rc = session_cap_connect(&broker, n, 1);
        if (rc != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
            FAIL("persistent session below the cap was not accepted");
        }
    }
    ASSERT_EQ(BROKER_MAX_PERSIST_SESSIONS, broker.orphan_session_count);

    /* A new ClientId would be one Session too many. */
    rc = session_cap_connect(&broker, BROKER_MAX_PERSIST_SESSIONS, 1);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL, rc);
    ASSERT_EQ(BROKER_MAX_PERSIST_SESSIONS, broker.orphan_session_count);
    ASSERT_TRUE(session_cap_has_orphan(&broker, "c000"));

    /* The oldest client resumes its own Session at the cap. */
    rc = session_cap_connect(&broker, 0, 0);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, rc);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Build a CleanSession 0 CONNECT for ClientId "c<NNN>" into out: v3.1.1
 * (MQTT 3.1.1 section 3.1), or at level 5 a v5 CONNECT with Session Expiry
 * Interval 60 (MQTT 5.0 section 3.1.2.11.2). Returns its length. */
static size_t session_cap_build_connect(byte* out, int n, int v5)
{
    size_t len = 0;
    byte rl = (byte)(v5 ? 22 : 16);

    out[len++] = 0x10;
    out[len++] = rl;
    out[len++] = 0x00; out[len++] = 0x04;
    out[len++] = 'M'; out[len++] = 'Q'; out[len++] = 'T'; out[len++] = 'T';
    out[len++] = (byte)(v5 ? 0x05 : 0x04);
    out[len++] = 0x00;                       /* CleanSession / Clean Start 0 */
    out[len++] = 0x00; out[len++] = 0x3C;    /* keep alive 60 */
    if (v5) {
        out[len++] = 0x05;                   /* Properties length */
        out[len++] = 0x11;                   /* Session Expiry Interval */
        out[len++] = 0x00; out[len++] = 0x00;
        out[len++] = 0x00; out[len++] = 0x3C;
    }
    out[len++] = 0x00; out[len++] = 0x04;
    out[len++] = 'c';
    out[len++] = (byte)('0' + (n / 100) % 10);
    out[len++] = (byte)('0' + (n / 10) % 10);
    out[len++] = (byte)('0' + n % 10);
    return len;
}

/* The cap counts connected persistent clients as well as offline Sessions.
 * With BROKER_MAX_PERSIST_SESSIONS - 1 offline Sessions and one connected
 * persistent client, a new ClientId is refused - with Quota Exceeded 0x97
 * for a v5 client (MQTT 5.0 section 3.2.2.2) - while a second connection
 * taking over the connected client's own Session is still accepted. */
TEST(connect_persistent_session_cap_counts_live_sessions)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[32];
    size_t len;
    int n;
    int i;
    int rc;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    for (n = 0; n < BROKER_MAX_PERSIST_SESSIONS - 1; n++) {
        rc = session_cap_connect(&broker, n, 1);
        if (rc != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
            FAIL("persistent session below the cap was not accepted");
        }
    }
    ASSERT_EQ(BROKER_MAX_PERSIST_SESSIONS - 1, broker.orphan_session_count);

    reset_mock_clients(3);
    /* Client 0 takes the last slot and stays connected. */
    len = session_cap_build_connect(connect, 200, 0);
    mock_client_input_append(0, connect, len);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].out_len >= 4);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_clients[0].out_buf[3]);

    /* Client 1, a new ClientId, is one Session too many. */
#ifdef WOLFMQTT_V5
    len = session_cap_build_connect(connect, 201, 1);
#else
    len = session_cap_build_connect(connect, 201, 0);
#endif
    mock_client_input_append(1, connect, len);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].out_len >= 4);
#ifdef WOLFMQTT_V5
    ASSERT_EQ(MQTT_REASON_QUOTA_EXCEEDED, g_clients[1].out_buf[3]);
#else
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL, g_clients[1].out_buf[3]);
#endif
    ASSERT_TRUE(g_clients[1].closed);

    /* Client 2 takes over client 0's Session ("c200") at the cap. */
    len = session_cap_build_connect(connect, 200, 0);
    mock_client_input_append(2, connect, len);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[2].out_len >= 4);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_clients[2].out_buf[3]);
    ASSERT_TRUE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#endif /* !WOLFMQTT_STATIC_MEMORY */

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
#ifndef WOLFMQTT_STATIC_MEMORY
/* The fan-out loop re-validates a snapshotted successor only when the broker's
 * subscription generation changed during the write, keeping the common case
 * O(1). This pins two things: an ordinary PUBLISH is still delivered to a
 * matching subscriber, and removing a subscription (UNSUBSCRIBE) bumps the
 * generation, so a re-entrant free during a later fan-out is still detected. */
TEST(fanout_subs_generation_bumped_on_unsubscribe)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int sub_pubs;
    word32 gen_after_sub;
    /* CONNECT subscriber "A". */
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* CONNECT publisher "B". */
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'B'
    };
    /* SUBSCRIBE packet_id=1, filter "x", QoS 0. */
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x00
    };
    /* PUBLISH QoS 0, topic "x", payload "hi". remain = 2+1+2 = 5. */
    static const byte publish_x[] = {
        0x30, 0x05, 0x00, 0x01, 'x', 'h', 'i'
    };
    /* UNSUBSCRIBE packet_id=2, filter "x". remain = 2 + (2+1) = 5. */
    static const byte unsubscribe_x[] = {
        0xA2, 0x05, 0x00, 0x02, 0x00, 0x01, 'x'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish_x, sizeof(publish_x));
    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
    }

    /* The common-case fan-out delivered the PUBLISH to the subscriber. */
    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    ASSERT_EQ(1, sub_pubs);
    gen_after_sub = broker.subs_gen;

    /* UNSUBSCRIBE removes the BrokerSub and must bump the generation. */
    mock_client_input_append(0, unsubscribe_x, sizeof(unsubscribe_x));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(broker.subs_gen != gen_after_sub);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Broker under test for the re-entrant fan-out hooks below. */
static MqttBroker* g_fanout_broker;

/* Unlink and free the second subscription in broker->subs, mirroring what
 * BrokerSubs_RemoveClient does to a peer whose WebSocket closes part way
 * through another subscriber's fan-out write. The second node is exactly the
 * successor a single-pass walk would have snapshotted before that write. */
static void fanout_drop_second_sub(void)
{
    BrokerSub* first;
    BrokerSub* victim;

    if (g_fanout_broker == NULL) {
        return;
    }
    first = g_fanout_broker->subs;
    if (first == NULL || first->next == NULL) {
        return;
    }
    victim = first->next;
    first->next = victim->next;
    if (victim->filter != NULL) {
        WOLFMQTT_FREE(victim->filter);
    }
    if (victim->client_id != NULL) {
        WOLFMQTT_FREE(victim->client_id);
    }
    WOLFMQTT_FREE(victim);
    g_fanout_broker->subs_gen++;
}

/* A fan-out write can re-entrantly free BrokerSub nodes, including the one a
 * single-pass walk saved as its successor. Abandoning the walk there is not
 * safe either: every still-connected subscriber further down the list silently
 * loses the message while the publisher is acknowledged as though delivery
 * completed. Three subscribers share topic "x"; the subscription behind the
 * first one written to is freed from inside that write, and all three must
 * still receive exactly one PUBLISH. */
TEST(fanout_survives_reentrant_sub_free)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* CONNECT for subscribers "A", "B", "C" and publisher "P". */
    static const byte connect_a[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    static const byte connect_b[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'B'
    };
    static const byte connect_c[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'C'
    };
    static const byte connect_p[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* SUBSCRIBE packet_id=1, filter "x", QoS 0. */
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x00
    };
    /* PUBLISH QoS 0, topic "x", payload "hi". */
    static const byte publish_x[] = {
        0x30, 0x05, 0x00, 0x01, 'x', 'h', 'i'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(4);
    mock_client_input_append(0, connect_a, sizeof(connect_a));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_b, sizeof(connect_b));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(2, connect_c, sizeof(connect_c));
    mock_client_input_append(2, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(3, connect_p, sizeof(connect_p));
    for (i = 0; i < 48; i++) {
        MqttBroker_Step(&broker);
    }

    /* All three subscriptions are in place before the publish. */
    ASSERT_NOT_NULL(broker.subs);
    ASSERT_NOT_NULL(broker.subs->next);
    ASSERT_NOT_NULL(broker.subs->next->next);

    g_fanout_broker = &broker;
    g_write_publish_hook = fanout_drop_second_sub;

    mock_client_input_append(3, publish_x, sizeof(publish_x));
    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
    }

    /* The hook fired, so the fan-out really did run over a mutated list. */
    ASSERT_NULL(g_write_publish_hook);

    /* Every subscriber collected before the write is served. Pre-fix the walk
     * stopped at the freed successor and the trailing subscribers got 0. */
    for (i = 0; i < 3; i++) {
        ASSERT_EQ(1, count_packets_of_type(g_clients[i].out_buf,
            g_clients[i].out_len, MQTT_PACKET_TYPE_PUBLISH));
    }

    g_fanout_broker = NULL;
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* The drain holds a queue entry across the write that sends it, and that write
 * can service this client's close callback, which hands the whole queue to the
 * carrier holding the Session. BrokerSubs_OrphanClient does that through
 * file-local helpers, so the hook stages the same transfer directly. */
static MqttBroker* g_handoff_broker;
static BrokerClient* g_handoff_client;
static void handoff_out_queue_mid_write(void)
{
    MqttBroker* broker = g_handoff_broker;
    BrokerClient* bc = g_handoff_client;
    BrokerOrphanSession* o;
    size_t id_len;

    if (broker == NULL || bc == NULL || bc->client_id == NULL ||
            bc->out_q_head == NULL) {
        return;
    }
    o = (BrokerOrphanSession*)WOLFMQTT_MALLOC(sizeof(*o));
    if (o == NULL) {
        return;
    }
    XMEMSET(o, 0, sizeof(*o));
    id_len = XSTRLEN(bc->client_id);
    o->client_id = (char*)WOLFMQTT_MALLOC(id_len + 1);
    if (o->client_id == NULL) {
        WOLFMQTT_FREE(o);
        return;
    }
    XMEMCPY(o->client_id, bc->client_id, id_len + 1);
    o->protocol_level = bc->protocol_level;
    o->session_expiry_sec = bc->session_expiry_sec;
    o->orphan_since = wolfmqtt_test_broker_time_s();

    /* Watch the entry the drain holds, to see if it frees the carrier's. */
    broker_test_watch_free(bc->out_q_head);

    o->out_q_head     = bc->out_q_head;
    o->out_q_tail     = bc->out_q_tail;
    o->out_q_count    = bc->out_q_count;
    o->out_q_inflight = bc->out_q_inflight;
    bc->out_q_head     = NULL;
    bc->out_q_tail     = NULL;
    bc->out_q_count    = 0;
    bc->out_q_inflight = 0;

    o->next = broker->orphan_sessions;
    broker->orphan_sessions = o;
    broker->orphan_session_count++;

#ifdef WOLFMQTT_BROKER_PERSIST
    /* BrokerOrphan_Take shadow-writes here, before the write it interrupted
     * has returned, so the stored copy records an unsent entry. */
    (void)BrokerPersist_PutOrphanSession(broker, o->client_id,
        o->protocol_level, o->session_expiry_sec, o->orphan_since);
    {
        BrokerOutPub* e;
        word64 seq = 1;

        for (e = o->out_q_head; e != NULL; e = e->next) {
            e->enqueue_seq = seq++;
            if (e->qos > MQTT_QOS_0) {
                (void)BrokerPersist_PutOutPub(broker, o->client_id, e);
            }
        }
    }
#endif
}

TEST(drain_stops_when_session_handoff_takes_queue)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOrphanSession* o;
    int i;
    /* Publisher "P". */
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* CleanSession=0, so the Session survives and has a carrier. */
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id=1, filter "x", granted QoS 0. */
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x00
    };
    /* QoS 0 PUBLISH, topic "x", payload "ABC". */
    static const byte publish_x[] = {
        0x30, 0x06, 0x00, 0x01, 'x', 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    ASSERT_NULL(sub_bc->out_q_head);

    broker_test_watch_free(NULL);
    g_handoff_broker = &broker;
    g_handoff_client = sub_bc;
    g_write_publish_hook = handoff_out_queue_mid_write;

    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);

    /* The hand-off ran from inside the write. */
    ASSERT_NULL(g_write_publish_hook);
    /* The delivery completed, which is what makes the entry spent. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));

    /* The carrier took the queue, and the delivered QoS 0 entry is retired
     * from it: MQTT 3.1.1 section 4.3.1 allows no retry. */
    o = broker.orphan_sessions;
    ASSERT_NOT_NULL(o);
    ASSERT_EQ(1, broker.orphan_session_count);
    ASSERT_EQ(0, o->out_q_count);
    ASSERT_NULL(o->out_q_head);
    ASSERT_NULL(o->out_q_tail);

    /* Released once by the owner that retired it: more would mean the drain
     * freed a carrier entry, none would leak it. */
    ASSERT_EQ(1, broker_test_watched_frees());

    /* And no trace of it left on the client. */
    ASSERT_EQ(0, sub_bc->out_q_count);
    ASSERT_EQ(0, sub_bc->out_q_inflight);
    ASSERT_NULL(sub_bc->out_q_head);
    ASSERT_NULL(sub_bc->out_q_tail);
    ASSERT_EQ(0, sub_bc->out_q_pending_len);

    g_handoff_broker = NULL;
    g_handoff_client = NULL;
    broker_test_watch_free(NULL);
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#if WOLFMQTT_MAX_QOS >= 1
/* The QoS > 0 half. A completed at-least-once delivery is still unacknowledged
 * so it stays with the carrier, but the subscriber has seen it, so the resume
 * copy must be marked a duplicate [MQTT-3.3.1-1]. */
TEST(handoff_marks_sent_qos1_for_redelivery)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOrphanSession* o;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* CleanSession=0, so the Session survives and has a carrier. */
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id=1, filter "x", granted QoS 1. */
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    /* QoS 1 PUBLISH, Packet Identifier 7, topic "x", payload "ABC". */
    static const byte publish_x[] = {
        0x32, 0x08, 0x00, 0x01, 'x', 0x00, 0x07, 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    ASSERT_NULL(sub_bc->out_q_head);

    broker_test_watch_free(NULL);
    g_handoff_broker = &broker;
    g_handoff_client = sub_bc;
    g_write_publish_hook = handoff_out_queue_mid_write;

    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);

    ASSERT_NULL(g_write_publish_hook);
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));

    /* Still the carrier's, awaiting its PUBACK, and nothing freed. */
    o = broker.orphan_sessions;
    ASSERT_NOT_NULL(o);
    ASSERT_EQ(1, o->out_q_count);
    ASSERT_NOT_NULL(o->out_q_head);
    ASSERT_EQ(0, broker_test_watched_frees());
    /* Flagged, so the resume sends it with DUP set. */
    ASSERT_EQ(1, (int)o->out_q_head->retransmit_dup);
    ASSERT_EQ(MQTT_QOS_1, (int)o->out_q_head->qos);

    ASSERT_EQ(0, sub_bc->out_q_count);
    ASSERT_NULL(sub_bc->out_q_head);

    g_handoff_broker = NULL;
    g_handoff_client = NULL;
    broker_test_watch_free(NULL);
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* The same hand-off, but the write only placed part of the PUBLISH. Those
 * bytes still reached the subscriber, so the resume copy is a re-delivery and
 * [MQTT-3.3.1-1] requires DUP, exactly as for a completed write. The drain
 * would have set the flag below, but the entry is already gone. */
TEST(handoff_marks_partly_sent_qos1_for_redelivery)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOrphanSession* o;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    static const byte publish_x[] = {
        0x32, 0x08, 0x00, 0x01, 'x', 0x00, 0x07, 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    ASSERT_NULL(sub_bc->out_q_head);

    broker_test_watch_free(NULL);
    g_handoff_broker = &broker;
    g_handoff_client = sub_bc;
    g_write_publish_hook = handoff_out_queue_mid_write;
    /* One byte of the PUBLISH goes out, then the hand-off takes the queue. */
    g_clients[1].write_limit_on_publish = 1;

    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);

    ASSERT_NULL(g_write_publish_hook);

    o = broker.orphan_sessions;
    ASSERT_NOT_NULL(o);
    ASSERT_EQ(1, o->out_q_count);
    ASSERT_NOT_NULL(o->out_q_head);
    ASSERT_EQ(0, broker_test_watched_frees());
    ASSERT_EQ(MQTT_QOS_1, (int)o->out_q_head->qos);
    ASSERT_EQ(1, (int)o->out_q_head->retransmit_dup);

    ASSERT_EQ(0, sub_bc->out_q_count);
    ASSERT_NULL(sub_bc->out_q_head);

    g_handoff_broker = NULL;
    g_handoff_client = NULL;
    broker_test_watch_free(NULL);
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_MAX_QOS >= 1 */

#ifdef WOLFMQTT_BROKER_WILL
/* Same hazard on the Will fan-out, which runs its own subscription walk. The
 * publisher's socket drops, the broker fans its Will out to three subscribers,
 * and a subscription is freed from inside the first delivery write. */
TEST(will_fanout_survives_reentrant_sub_free)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect_a[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    static const byte connect_b[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'B'
    };
    static const byte connect_c[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'C'
    };
    /* Publisher "P" with LWT: flags 0x06 (will | clean), will_topic "lwt",
     * will_payload "bye". */
    static const byte connect_p_will[] = {
        0x10, 0x17, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x06, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* SUBSCRIBE packet_id=1, filter "lwt", QoS 0. */
    static const byte subscribe_lwt[] = {
        0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'l', 'w', 't', 0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(4);
    mock_client_input_append(0, connect_a, sizeof(connect_a));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(1, connect_b, sizeof(connect_b));
    mock_client_input_append(1, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(2, connect_c, sizeof(connect_c));
    mock_client_input_append(2, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(3, connect_p_will, sizeof(connect_p_will));
    for (i = 0; i < 48; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_NOT_NULL(broker.subs);
    ASSERT_NOT_NULL(broker.subs->next);
    ASSERT_NOT_NULL(broker.subs->next->next);

    g_fanout_broker = &broker;
    g_write_publish_hook = fanout_drop_second_sub;

    /* Drop the publisher's socket so its Will fans out. */
    g_clients[3].read_err = 1;
    for (i = 0; i < 32; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_NULL(g_write_publish_hook);
    for (i = 0; i < 3; i++) {
        ASSERT_EQ(1, count_packets_of_type(g_clients[i].out_buf,
            g_clients[i].out_len, MQTT_PACKET_TYPE_PUBLISH));
    }

    g_fanout_broker = NULL;
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* The Will is fanned out before it is cleared, and a write inside that fan-out
 * can service the owner's own close callback, which publishes the same Will.
 * It must find nothing left to publish [MQTT-3.1.2-8]. The hook samples the
 * flag that nested path tests, from inside the first delivery. */
static BrokerClient* g_will_owner;
static int g_will_claimed_during_fanout;
static int g_will_topic_live_during_fanout;
static void sample_will_state_mid_write(void)
{
    if (g_will_owner == NULL) {
        return;
    }
    g_will_claimed_during_fanout = !g_will_owner->has_will;
    g_will_topic_live_during_fanout = (g_will_owner->will_topic != NULL);
}

TEST(takeover_will_claimed_before_fanout)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* Subscribers "A" and "B", CleanSession=1. */
    static const byte connect_a[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    static const byte connect_b[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'B'
    };
    /* SUBSCRIBE packet_id=1, filter "w", QoS 0. */
    static const byte subscribe_w[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'w', 0x00
    };
    /* v3.1.1 CONNECT for "W" carrying a Will: flags 0x06 = CleanSession +
     * Will Flag, Will Topic "w", Will Payload "bye". Remaining Length 21. */
    static const byte connect_w_will[] = {
        0x10, 0x15, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x06, 0x00, 0x3C,
        0x00, 0x01, 'W',
        0x00, 0x01, 'w',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* Second CONNECT with the same ClientId takes the Session over, which
     * publishes the old connection's Will. */
    static const byte connect_w_dup[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'W'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_a, sizeof(connect_a));
    mock_client_input_append(0, subscribe_w, sizeof(subscribe_w));
    mock_client_input_append(1, connect_b, sizeof(connect_b));
    mock_client_input_append(1, subscribe_w, sizeof(subscribe_w));
    mock_client_input_append(2, connect_w_will, sizeof(connect_w_will));
    for (i = 0; i < 24; i++) {
        (void)MqttBroker_Step(&broker);
    }

    g_will_owner = find_broker_client(&broker, "W");
    ASSERT_NOT_NULL(g_will_owner);
    ASSERT_EQ(1, (int)g_will_owner->has_will);
    ASSERT_NOT_NULL(g_will_owner->will_topic);
    /* Nothing published yet, so the hook cannot be consumed early. */
    ASSERT_EQ(0, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));

    g_will_claimed_during_fanout = -1;
    g_will_topic_live_during_fanout = -1;
    g_write_publish_hook = sample_will_state_mid_write;

    mock_client_input_append(3, connect_w_dup, sizeof(connect_w_dup));
    g_clients_active = 4;
    for (i = 0; i < 24; i++) {
        (void)MqttBroker_Step(&broker);
    }

    /* The Will really was fanned out, so the sample is meaningful. */
    ASSERT_NULL(g_write_publish_hook);

    /* Claimed before the first write: a close callback delivered during the
     * fan-out returns without republishing or freeing anything. */
    ASSERT_EQ(1, g_will_claimed_during_fanout);
    /* And the buffers it lends the encoder are still owned. */
    ASSERT_EQ(1, g_will_topic_live_during_fanout);

    /* Exactly one copy reaches each subscriber [MQTT-3.1.2-8]. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));

    g_will_owner = NULL;
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_WILL */

#endif /* !WOLFMQTT_STATIC_MEMORY */

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

#ifndef WOLFMQTT_STATIC_MEMORY
/* A QoS 2 PUBLISH whose topic copy fails was never delivered, so its Packet
 * Identifier must not stay recorded as awaiting PUBREL. Otherwise the
 * retransmission after reconnect is treated as a duplicate and acknowledged
 * without delivery, losing the message [MQTT-4.3.3-2]. */
TEST(qos2_topic_alloc_failure_retransmit_delivered)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* v3.1.1 CONNECT, CleanSession=1, ClientId "S" */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet id 1, filter "x", QoS 0 */
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x00
    };
    /* v3.1.1 CONNECT, CleanSession=0, ClientId "P" */
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* PUBLISH QoS 2 (MQTT 3.1.1 section 3.3): topic "x", packet id 1,
     * payload "hi". */
    static const byte publish_q2[] = {
        0x34, 0x07, 0x00, 0x01, 'x', 0x00, 0x01, 'h', 'i'
    };
    /* Same PUBLISH retransmitted with DUP set [MQTT-4.4.0-1] */
    static const byte publish_q2_dup[] = {
        0x3C, 0x07, 0x00, 0x01, 'x', 0x00, 0x01, 'h', 'i'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* The inbound QoS 2 record allocates first and succeeds; the topic
     * copy is the next allocation and fails. */
    broker_test_fail_alloc_after(1);
    mock_client_input_append(1, publish_q2, sizeof(publish_q2));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();
    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(0, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));

    /* Resume the Session and retransmit */
    mock_client_input_append(2, connect_pub, sizeof(connect_pub));
    mock_client_input_append(2, publish_q2_dup, sizeof(publish_q2_dup));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH_REC));
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

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

/* Packet Identifiers are scoped to one client session [MQTT-2.2.1-4].
 * A value held by one slow subscriber must remain available to another. */
TEST(outbound_packet_ids_are_scoped_per_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_a;
    BrokerClient* sub_b;
    int i;
    static const byte connect_a[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    static const byte connect_b[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'B'
    };
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte subscribe_a[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'a', 0x01
    };
    static const byte subscribe_b[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'b', 0x01
    };
    static const byte publish_a[] = {
        0x32, 0x06, 0x00, 0x01, 'a', 0x00, 0x01, 'p'
    };
    static const byte publish_b[] = {
        0x32, 0x06, 0x00, 0x01, 'b', 0x00, 0x02, 'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_a, sizeof(connect_a));
    mock_client_input_append(0, subscribe_a, sizeof(subscribe_a));
    mock_client_input_append(1, connect_b, sizeof(connect_b));
    mock_client_input_append(1, subscribe_b, sizeof(subscribe_b));
    mock_client_input_append(2, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 24; i++) {
        MqttBroker_Step(&broker);
    }

    sub_a = find_broker_client(&broker, "A");
    sub_b = find_broker_client(&broker, "B");
    ASSERT_NOT_NULL(sub_a);
    ASSERT_NOT_NULL(sub_b);

    mock_client_input_append(2, publish_a, sizeof(publish_a));
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_NOT_NULL(sub_a->out_q_head);
    ASSERT_EQ(1, sub_a->out_q_head->packet_id);

    broker.next_packet_id = 1;
    mock_client_input_append(2, publish_b, sizeof(publish_b));
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_NOT_NULL(sub_b->out_q_head);
    ASSERT_EQ(1, sub_b->out_q_head->packet_id);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_NONBLOCK
TEST(outbound_queue_short_write_resumes_on_next_step)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    size_t sub_before;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x00
    };
    /* Hand-built MQTT v3.1.1 QoS 0 PUBLISH: topic "x", payload "ABC". */
    static const byte publish_x[] = {
        0x30, 0x06,
        0x00, 0x01, 'x',
        'A', 'B', 'C'
    };
    /* MQTT v3.1.1 section 3.13.2 requires an empty PINGRESP. */
    static const byte ping_req[] = { 0xC0, 0x00 };
    static const byte expected[] = {
        0xD0, 0x00,
        0x30, 0x06,
        0x00, 0x01, 'x',
        'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Accept the publisher first so the later subscriber sits at the list
     * head and is processed before the publisher on each broker step. */
    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    sub_before = g_clients[1].out_len;

    /* Defer PINGRESP after one byte, then queue a PUBLISH in the same tick. */
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(1, ping_req, sizeof(ping_req));
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(1, sub_bc->out_q_count);
    ASSERT_TRUE(sub_bc->client.write.pos > 0);
    ASSERT_EQ((int)sizeof(ping_req), sub_bc->direct_pending_len);
    ASSERT_EQ(1, g_clients[1].out_len - sub_before);
    ASSERT_EQ(0xD0, g_clients[1].out_buf[sub_before]);
    ASSERT_EQ(0, count_packets_of_type(g_clients[1].out_buf + sub_before,
        g_clients[1].out_len - sub_before, MQTT_PACKET_TYPE_PUBLISH));

    /* A bare later tick must finish PINGRESP before draining the PUBLISH. */
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(0, sub_bc->out_q_count);
    ASSERT_EQ(0, sub_bc->client.write.pos);
    ASSERT_EQ(0, sub_bc->direct_pending_len);
    ASSERT_EQ(sizeof(expected), g_clients[1].out_len - sub_before);
    ASSERT_MEM_EQ(expected, g_clients[1].out_buf + sub_before,
        sizeof(expected));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_BROKER_RETAINED
TEST(retained_publish_waits_for_partial_suback)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    size_t sub_before;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte publish_retained[] = {
        0x31, 0x04,
        0x00, 0x01, 'x',
        'R'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x00
    };
    /* Hand-built MQTT v3.1.1 SUBACK followed by the retained PUBLISH. */
    static const byte expected[] = {
        0x90, 0x03, 0x00, 0x01, 0x00,
        0x31, 0x04, 0x00, 0x01, 'x', 'R'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_retained, sizeof(publish_retained));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    sub_before = g_clients[1].out_len;

    g_clients[1].write_limit_once = 1;
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(1, sub_bc->out_q_count);
    ASSERT_EQ((int)sizeof(expected) - (int)sizeof(publish_retained),
        sub_bc->direct_pending_len);

    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(0, sub_bc->out_q_count);
    ASSERT_EQ(sizeof(expected), g_clients[1].out_len - sub_before);
    ASSERT_MEM_EQ(expected, g_clients[1].out_buf + sub_before,
        sizeof(expected));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_RETAINED */

TEST(self_publish_waits_for_partial_puback)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* bc;
    size_t before;
    int i;
    static const byte connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    static const byte publish_x[] = {
        0x32, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'P'
    };
    /* Hand-built MQTT v3.1.1 PUBACK followed by the self-delivery. */
    static const byte expected[] = {
        0x40, 0x02, 0x00, 0x07,
        0x32, 0x06, 0x00, 0x01, 'x', 0x00, 0x01, 'P'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&broker);
    }
    bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(bc);
    before = g_clients[0].out_len;

    g_clients[0].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(1, bc->out_q_count);
    ASSERT_EQ(4, bc->direct_pending_len);

    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(1, bc->out_q_count);
    ASSERT_EQ(sizeof(expected), g_clients[0].out_len - before);
    ASSERT_MEM_EQ(expected, g_clients[0].out_buf + before,
        sizeof(expected));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MQTT 3.1.1 section 3.1.4: when a CONNECT check fails the Server "SHOULD send
 * an appropriate CONNACK response with a non-zero return code ... and it MUST
 * close the Network Connection". Closing the moment the write returns leaves a
 * short write truncated, so the client sees only part of the CONNACK and never
 * learns why it was refused. The refusal must be delivered in full first.
 *
 * Refusal used: [MQTT-3.1.3-8], zero-length ClientId with CleanSession=0,
 * answered with return code 0x02 (Identifier rejected). */
TEST(refused_connack_short_write_delivers_return_code_before_close)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[64];
    size_t connect_len;
    /* v3.1.1 CONNACK: type 0x20, Remaining Length 2, Session Present 0
     * ([MQTT-3.2.2-4] on a refusal), return code 0x02. */
    static const byte expected[] = {
        0x20, 0x02, 0x00, MQTT_CONNECT_ACK_CODE_REFUSED_ID
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    connect_len = build_v311_connect_emptyid(connect, 0x00);
    reset_mock_state(connect, connect_len);

    /* Accept only the first byte of the refused CONNACK. */
    g_clients[0].write_limit_once = 1;
    run_broker_one_connect(&broker);

    /* Only 0x20 is out so far, and the socket is still open - closing here is
     * what used to strand the return code. */
    ASSERT_EQ((size_t)1, g_out_len);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_FALSE(g_client_closed);

    /* A later broker step finishes the write and only then closes. */
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(sizeof(expected), g_out_len);
    ASSERT_MEM_EQ(expected, g_out_buf, sizeof(expected));
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* The refused client must never count as connected while its CONNACK drains,
 * and must leave no BrokerClient behind once it does. */
TEST(refused_connack_short_write_leaves_no_client)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[64];
    size_t connect_len;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    connect_len = build_v311_connect_emptyid(connect, 0x00);
    reset_mock_state(connect, connect_len);

    g_clients[0].write_limit_once = 1;
    run_broker_one_connect(&broker);
    ASSERT_NOT_NULL(broker.clients);
    ASSERT_EQ(0, (int)broker.clients->connected);
    ASSERT_EQ(1, (int)broker.clients->connack_refused);

    (void)MqttBroker_Step(&broker);
    ASSERT_NULL(broker.clients);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* If the resumed write of a refused CONNACK itself fails, the client is torn
 * down without publishing a Will: a CONNECT refused before the Will was stored
 * established no Session at all. */
TEST(refused_connack_resume_write_failure_drops_client)
{
    MqttBroker broker;
    MqttBrokerNet net;
    byte connect[64];
    size_t connect_len;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    connect_len = build_v311_connect_emptyid(connect, 0x00);
    reset_mock_state(connect, connect_len);

    g_clients[0].write_limit_once = 1;
    run_broker_one_connect(&broker);
    ASSERT_NOT_NULL(broker.clients);
    ASSERT_EQ(1, (int)broker.clients->connack_refused);

    /* The rest of the refusal never makes it out. */
    g_clients[0].write_err = 1;
    (void)MqttBroker_Step(&broker);
    ASSERT_NULL(broker.clients);
    ASSERT_EQ(0, broker.orphan_session_count);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A peer that never drains its socket must not hold a client slot forever
 * while its accepted CONNACK is pending. Keep alive monitoring is held off
 * for that window, so the handshake is bounded by BROKER_CONNECT_TIMEOUT_SEC
 * measured from the CONNECT that produced the CONNACK. */
TEST(accepted_connack_pending_times_out_and_closes)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* bc;
    /* v3.1.1 CONNECT: CleanSession=1, Keep Alive 0 (no keepalive at all, so
     * only the handshake bound can close this client), ClientId "id". */
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02,
        0x00, 0x00,
        0x00, 0x02, 'i', 'd'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    g_clients[0].write_limit_once = 1;
    run_broker_one_connect(&broker);

    bc = find_broker_client(&broker, "id");
    ASSERT_NOT_NULL(bc);
    ASSERT_EQ(4, bc->connack_pending_len);

    /* Still pending but inside the bound: the client survives. */
    g_clients[0].write_continue = 1;
    g_broker_time_s = BROKER_CONNECT_TIMEOUT_SEC;
    (void)MqttBroker_Step(&broker);
    ASSERT_FALSE(g_client_closed);
    ASSERT_NOT_NULL(find_broker_client(&broker, "id"));

    /* Past the bound with the CONNACK still unwritten: the slot is reclaimed. */
    g_broker_time_s = BROKER_CONNECT_TIMEOUT_SEC + 1;
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(g_client_closed);
    ASSERT_NULL(find_broker_client(&broker, "id"));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MQTT 3.1.1 section 3.1.4 lists "Start message delivery and keep alive
 * monitoring" as the step after acknowledging the CONNECT. An accepted CONNACK
 * that is still only partly written must therefore not be cut short by its own
 * client's keepalive deadline - the broker withholds reads until that write
 * finishes, so last_rx cannot advance and the deadline would always win.
 *
 * Keep Alive is 2, so the 1.5x deadline [MQTT-3.1.2-24] falls at t=3. */
TEST(accepted_connack_pending_survives_keepalive_deadline)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* bc;
    /* v3.1.1 CONNECT: CleanSession=1, Keep Alive 2, ClientId "id". */
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02,
        0x00, 0x02,
        0x00, 0x02, 'i', 'd'
    };
    static const byte expected[] = { 0x20, 0x02, 0x00, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    g_clients[0].write_limit_once = 1;
    run_broker_one_connect(&broker);

    bc = find_broker_client(&broker, "id");
    ASSERT_NOT_NULL(bc);
    ASSERT_EQ(4, bc->connack_pending_len);
    ASSERT_EQ((size_t)1, g_out_len);

    /* Past the keepalive deadline with the CONNACK still pending: the client
     * must survive, since keep alive monitoring has not started yet. */
    g_broker_time_s = 3;
    g_clients[0].write_continue = 1;
    (void)MqttBroker_Step(&broker);
    ASSERT_FALSE(g_client_closed);
    ASSERT_NOT_NULL(find_broker_client(&broker, "id"));

    /* Once the CONNACK completes the deadline is re-baselined off that
     * moment, so the client is still live at the same clock reading. */
    g_clients[0].write_continue = 0;
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(sizeof(expected), g_out_len);
    ASSERT_MEM_EQ(expected, g_out_buf, sizeof(expected));
    ASSERT_FALSE(g_client_closed);
    bc = find_broker_client(&broker, "id");
    ASSERT_NOT_NULL(bc);
    ASSERT_EQ(0, bc->connack_pending_len);

    /* Keep alive monitoring is running now: 1.5x past the new baseline
     * closes the client as usual. */
    g_broker_time_s = 6;
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(pending_write_does_not_bypass_keepalive)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* bc;
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02,
        0x00, 0x02,
        0x00, 0x02, 'i', 'd'
    };
    static const byte ping_req[] = { 0xC0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);
    bc = find_broker_client(&broker, "id");
    ASSERT_NOT_NULL(bc);

    g_clients[0].write_continue = 1;
    mock_client_input_append(0, ping_req, sizeof(ping_req));
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ((int)sizeof(ping_req), bc->direct_pending_len);
    ASSERT_FALSE(g_client_closed);

    /* [MQTT-3.1.2-24] Keep Alive 2 expires at the exact 1.5x deadline. */
    g_broker_time_s = 3;
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK */
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

#ifdef WOLFMQTT_BROKER_WILL
/* Shared scenario for the direct-response write-failure tests. Subscriber "S"
 * is subscribed to "lwt"; publisher "P" holds a QoS 0 Will on that topic. Both
 * sessions are established, then every write to P's socket fails and `pkt` is
 * fed to P. The response named by `ack_type` still reaches the failing socket,
 * so it is the write error - not a decode error or the keep-alive timer - that
 * must close P and publish its Will [MQTT-3.1.2-8]. */
static void will_fires_on_response_write_failure(const byte* pkt,
    size_t pkt_len, byte ack_type)
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
    /* QoS 0 PUBLISH "lwt"/"bye" - the Will as it appears on the wire. */
    static const byte will_publish[] = {
        0x30, 0x08,
        0x00, 0x03, 'l', 'w', 't',
        'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, pub_connect, sizeof(pub_connect));
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }
    /* Both sessions are up and the Will has not fired. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_CONNECT_ACK));
    ASSERT_EQ(0, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_FALSE(g_clients[1].closed);

    g_clients[1].write_err = 1;
    mock_client_input_append(1, pkt, pkt_len);
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }

    /* The response was encoded and handed to the failing socket, so the
     * packet itself was accepted; only its write failed. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, ack_type));
    ASSERT_TRUE(g_clients[1].closed);
    /* Exactly one PUBLISH reached the subscriber, and it is the Will. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_TRUE(g_clients[0].out_len >= sizeof(will_publish));
    ASSERT_MEM_EQ(will_publish,
        g_clients[0].out_buf + g_clients[0].out_len - sizeof(will_publish),
        sizeof(will_publish));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.1.2-8]: the Will is published when the Network Connection closes
 * without a DISCONNECT, which includes an I/O error the Server detects. A
 * failed PINGRESP write is such an error, so the publisher must be closed and
 * its Will delivered rather than left connected with the failure ignored. */
TEST(pingresp_write_failure_fires_will)
{
    static const byte pingreq[] = { 0xC0, 0x00 };
    will_fires_on_response_write_failure(pingreq, sizeof(pingreq),
        MQTT_PACKET_TYPE_PING_RESP);
}

TEST(suback_write_failure_fires_will)
{
    /* SUBSCRIBE to "x" at QoS 0, packet_id 2. */
    static const byte subscribe[] = {
        0x82, 0x06,
        0x00, 0x02,
        0x00, 0x01, 'x',
        0x00
    };
    will_fires_on_response_write_failure(subscribe, sizeof(subscribe),
        MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
}

#if WOLFMQTT_MAX_QOS >= 1
TEST(puback_write_failure_fires_will)
{
    /* QoS 1 PUBLISH "x"/"p", packet_id 3. No subscriber matches "x", so the
     * only PUBLISH the subscriber can see is the Will. */
    static const byte publish_qos1[] = {
        0x32, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x03,
        'p'
    };
    will_fires_on_response_write_failure(publish_qos1, sizeof(publish_qos1),
        MQTT_PACKET_TYPE_PUBLISH_ACK);
}
#endif
#endif /* WOLFMQTT_BROKER_WILL */

/* A listener whose accept callback reports a hard failure must surface it
 * from MqttBroker_Step, so MqttBroker_Run stops instead of spinning forever on
 * a dead listener. Idle results (CONTINUE/TIMEOUT) stay silent, and existing
 * clients are still serviced in the step that reports the failure. */
TEST(broker_step_reports_listener_accept_failure)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int rc;
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x02, 'i', 'd'
    };
    static const byte pingreq[] = { 0xC0, 0x00 };
    size_t out_mark;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);
    ASSERT_FALSE(g_client_closed);

    /* Idle listener: nothing to report. */
    rc = MqttBroker_Step(&broker);
    ASSERT_TRUE(rc >= 0 || rc == MQTT_CODE_CONTINUE);

    out_mark = g_out_len;
    mock_client_input_append(0, pingreq, sizeof(pingreq));
    g_accept_fail_rc = MQTT_CODE_ERROR_NETWORK;
    rc = MqttBroker_Step(&broker);
    g_accept_fail_rc = 0;

    ASSERT_EQ(MQTT_CODE_ERROR_NETWORK, rc);
    /* The connected client was still serviced: PINGRESP went out. */
    ASSERT_EQ(1, count_packets_of_type(g_out_buf + out_mark,
        g_out_len - out_mark, MQTT_PACKET_TYPE_PING_RESP));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(broker_keepalive_expires_at_exact_deadline)
{
    MqttBroker broker;
    MqttBrokerNet net;
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02,
        0x00, 0x02,
        0x00, 0x02, 'i', 'd'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);
    ASSERT_FALSE(g_client_closed);

    g_broker_time_s = 2;
    (void)MqttBroker_Step(&broker);
    ASSERT_FALSE(g_client_closed);

    /* Keep Alive 2 has an exact 1.5x deadline at tick 3. */
    g_broker_time_s = 3;
    (void)MqttBroker_Step(&broker);
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
#if !defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
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
#endif /* !WOLFMQTT_V5 && WOLFMQTT_BROKER_WILL */

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
/* After a completed retained delivery the payload must be scrubbed from the
 * subscriber's tx_buf: assert it reached the wire but not tx_buf. */
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

#ifdef WOLFMQTT_NONBLOCK
TEST(retained_short_write_preserves_following_delivery)
{
    MqttBroker broker;
    MqttBrokerNet net;
    size_t sub_before;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    /* Hand-built retained QoS 0 PUBLISH packets for r/a and r/b. */
    static const byte publish_one[] = {
        0x31, 0x08, 0x00, 0x03, 'r', '/', 'a', 'O', 'N', 'E'
    };
    static const byte publish_two[] = {
        0x31, 0x08, 0x00, 0x03, 'r', '/', 'b', 'T', 'W', 'O'
    };
    static const byte subscribe_all[] = {
        0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'r', '/', '#', 0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_one, sizeof(publish_one));
    mock_client_input_append(0, publish_two, sizeof(publish_two));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&broker);
    }

    sub_before = g_clients[1].out_len;
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(1, subscribe_all, sizeof(subscribe_all));
    (void)MqttBroker_Step(&broker);
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }

    ASSERT_EQ(2, count_packets_of_type(g_clients[1].out_buf + sub_before,
        g_clients[1].out_len - sub_before, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_EQ(1, scrub_region_contains(g_clients[1].out_buf + sub_before,
        (int)(g_clients[1].out_len - sub_before), "ONE", 3));
    ASSERT_EQ(1, scrub_region_contains(g_clients[1].out_buf + sub_before,
        (int)(g_clients[1].out_len - sub_before), "TWO", 3));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK */
#endif /* WOLFMQTT_BROKER_RETAINED && !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_BROKER_WILL) && !defined(WOLFMQTT_STATIC_MEMORY)
/* The immediate-will fan-out must scrub the subscriber tx_buf even when the
 * delivery write fails hard (only an in-progress MQTT_CODE_CONTINUE is
 * skipped). Force the subscriber's write to fail during the will fan-out and
 * assert the will plaintext is gone from tx_buf. */
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

#ifdef WOLFMQTT_NONBLOCK
TEST(pending_publish_preserves_qos0_will)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    size_t sub_before;
    int i;
    static const byte sub_connect[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte subscribe_all[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, '#', 0x00
    };
    static const byte pub_connect[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    /* v3.1.1 CONNECT with a QoS 0 Will on topic lwt. */
    static const byte will_connect[] = {
        0x10, 0x18, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x06, 0x00, 0x3C, 0x00, 0x01, 'W',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x04, 'W', 'I', 'L', 'L'
    };
    static const byte publish_x[] = {
        0x30, 0x04, 0x00, 0x01, 'x', 'Q'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    /* List order becomes Will, subscriber, publisher. */
    mock_client_input_append(0, pub_connect, sizeof(pub_connect));
    mock_client_input_append(1, sub_connect, sizeof(sub_connect));
    mock_client_input_append(1, subscribe_all, sizeof(subscribe_all));
    mock_client_input_append(2, will_connect, sizeof(will_connect));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    sub_before = g_clients[1].out_len;

    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(sub_bc->out_q_pending_len > 0);

    g_clients[2].read_err = 1;
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }

    ASSERT_EQ(2, count_packets_of_type(g_clients[1].out_buf + sub_before,
        g_clients[1].out_len - sub_before, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_EQ(1, scrub_region_contains(g_clients[1].out_buf + sub_before,
        (int)(g_clients[1].out_len - sub_before), "WILL", 4));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK */
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

#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 1
/* Return the Reason Code of the first PUBACK/PUBREC in a captured stream. A v5
 * response that omits the reason byte (remain <= 2) means Success; -1 means no
 * such packet was found. */
static int first_publish_resp_reason(const byte* buf, size_t len)
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
        if (type == MQTT_PACKET_TYPE_PUBLISH_ACK ||
                type == MQTT_PACKET_TYPE_PUBLISH_REC) {
            if (remain <= 2) {
                return MQTT_REASON_SUCCESS;
            }
            if (pos + hdr_len + 2 < len) {
                return buf[pos + hdr_len + 2];
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
#endif /* WOLFMQTT_V5 && WOLFMQTT_MAX_QOS >= 1 */

#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 2
/* Best-effort retain: a v5 QoS 2 PUBLISH whose retained store is full is still
 * delivered live to subscribers and answered with a success PUBREC. Only the
 * retained copy is skipped; the store stays at capacity. */
TEST(qos2_retained_store_full_delivers_live)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    byte fill[8];
    int sub_pubs;
    int pub_pubrecs;

    /* v3.1.1 subscriber "A" on "z". */
    static const byte connect_sub_z[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'A'
    };
    static const byte subscribe_z[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'z', 0x02
    };
    /* v5 publisher "B". */
    static const byte connect_pub[] = {
        0x10, 0x0E, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C, 0x00, 0x00, 0x01, 'B'
    };
    /* v3.1.1 filler "F" used to exhaust the retained store. */
    static const byte connect_fill[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'F'
    };
    /* v5 QoS 2 retained PUBLISH, packet_id=7, topic "z", payload "first".
     * remain = topic(3) + id(2) + props(1) + payload(5) = 11 */
    static const byte publish_retain[] = {
        0x35, 0x0B, 0x00, 0x01, 'z', 0x00, 0x07, 0x00,
        'f', 'i', 'r', 's', 't'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub_z, sizeof(connect_sub_z));
    mock_client_input_append(0, subscribe_z, sizeof(subscribe_z));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(2, connect_fill, sizeof(connect_fill));
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        fill[0] = 0x31;                        /* PUBLISH, retain=1, QoS 0 */
        fill[1] = 0x06;                        /* remain = 6 */
        fill[2] = 0x00; fill[3] = 0x03;        /* topic len 3 */
        fill[4] = 'r';
        fill[5] = (byte)('0' + (i / 10));
        fill[6] = (byte)('0' + (i % 10));
        fill[7] = 'x';                         /* payload */
        mock_client_input_append(2, fill, sizeof(fill));
    }
    for (i = 0; i < BROKER_MAX_RETAINED + 32; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    /* Table is full, so the retained copy is skipped, but the message is still
     * delivered live and answered with a success PUBREC. */
    mock_client_input_append(1, publish_retain, sizeof(publish_retain));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    pub_pubrecs = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);

    ASSERT_EQ(1, sub_pubs);     /* delivered live despite full table */
    ASSERT_EQ(1, pub_pubrecs);
    ASSERT_EQ(MQTT_REASON_SUCCESS,
        first_publish_resp_reason(g_clients[1].out_buf,
            g_clients[1].out_len));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 && WOLFMQTT_MAX_QOS >= 2 */

#if WOLFMQTT_MAX_QOS >= 2
/* Best-effort retain: a v3.1.1 QoS 2 PUBLISH whose retained store is full is
 * still delivered live to subscribers, and its handshake completes normally.
 * Only the retained copy is skipped. */
TEST(qos2_retained_store_full_v311_delivers_live)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    byte fill[8];
    int sub_pubs;
    int pub_pubrecs;
    int pub_pubcomps;

    /* v3.1.1 subscriber "A", subscribes to "x" at QoS 2. */
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'A'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x02
    };
    /* v3.1.1 publisher "B". */
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'B'
    };
    /* v3.1.1 filler "F" used to exhaust the retained store. */
    static const byte connect_fill[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'F'
    };
    /* v3.1.1 QoS 2 retained PUBLISH, packet_id=7, topic "x", payload "live".
     * remain = topic(3) + id(2) + payload(4) = 9 */
    static const byte publish_retain[] = {
        0x35, 0x09, 0x00, 0x01, 'x', 0x00, 0x07,
        'l', 'i', 'v', 'e'
    };
    static const byte pubrel[] = {
        0x62, 0x02, 0x00, 0x07
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(2, connect_fill, sizeof(connect_fill));
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        fill[0] = 0x31;                        /* PUBLISH, retain=1, QoS 0 */
        fill[1] = 0x06;                        /* remain = 6 */
        fill[2] = 0x00; fill[3] = 0x03;        /* topic len 3 */
        fill[4] = 'r';
        fill[5] = (byte)('0' + (i / 10));
        fill[6] = (byte)('0' + (i % 10));
        fill[7] = 'x';                         /* payload */
        mock_client_input_append(2, fill, sizeof(fill));
    }
    for (i = 0; i < BROKER_MAX_RETAINED + 32; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    /* Table is full, so the retained copy is skipped, but the message is still
     * delivered live and the v3.1.1 handshake completes normally. */
    mock_client_input_append(1, publish_retain, sizeof(publish_retain));
    mock_client_input_append(1, pubrel, sizeof(pubrel));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    pub_pubrecs = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);
    pub_pubcomps = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_COMP);

    ASSERT_EQ(1, sub_pubs);     /* delivered live despite full table */
    ASSERT_EQ(1, pub_pubrecs);
    ASSERT_EQ(1, pub_pubcomps); /* handshake completes normally */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_MAX_QOS >= 2 */

#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 1
/* Best-effort retain on the QoS 1 path most applications hit: a v5 QoS 1
 * PUBLISH whose retained store is full is still delivered live and answered
 * with a success PUBACK. Only the retained copy is skipped. */
TEST(qos1_retained_store_full_delivers_live)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    byte fill[8];
    int sub_pubs;
    int pub_pubacks;

    /* v3.1.1 subscriber "A" on "x". */
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'A'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    /* v5 publisher "B". */
    static const byte connect_pub[] = {
        0x10, 0x0E, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C, 0x00, 0x00, 0x01, 'B'
    };
    /* v3.1.1 filler "F" used to exhaust the retained store. */
    static const byte connect_fill[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'F'
    };
    /* v5 QoS 1 retained PUBLISH, packet_id=7, topic "x", payload "live".
     * remain = topic(3) + id(2) + props(1) + payload(4) = 10 */
    static const byte publish_retain[] = {
        0x33, 0x0A, 0x00, 0x01, 'x', 0x00, 0x07, 0x00,
        'l', 'i', 'v', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(2, connect_fill, sizeof(connect_fill));
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        fill[0] = 0x31;                        /* PUBLISH, retain=1, QoS 0 */
        fill[1] = 0x06;                        /* remain = 6 */
        fill[2] = 0x00; fill[3] = 0x03;        /* topic len 3 */
        fill[4] = 'r';
        fill[5] = (byte)('0' + (i / 10));
        fill[6] = (byte)('0' + (i % 10));
        fill[7] = 'x';                         /* payload */
        mock_client_input_append(2, fill, sizeof(fill));
    }
    for (i = 0; i < BROKER_MAX_RETAINED + 32; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    mock_client_input_append(1, publish_retain, sizeof(publish_retain));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_MAX_RETAINED, broker.retained_count);

    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    pub_pubacks = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_ACK);

    ASSERT_EQ(1, sub_pubs);     /* delivered live despite full table */
    ASSERT_EQ(1, pub_pubacks);
    ASSERT_EQ(MQTT_REASON_SUCCESS,
        first_publish_resp_reason(g_clients[1].out_buf,
            g_clients[1].out_len));
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifndef WOLFMQTT_STATIC_MEMORY
/* Best-effort retain also covers a transient store failure: an allocation
 * failure in the retained store still delivers the message live and
 * acknowledges success, and stores nothing. */
TEST(qos1_retained_store_alloc_failure_delivers_live)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int sub_pubs;
    int pub_pubacks;

    /* v3.1.1 subscriber "A" on "x". */
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'A'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    /* v5 publisher "B". */
    static const byte connect_pub[] = {
        0x10, 0x0E, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C, 0x00, 0x00, 0x01, 'B'
    };
    /* v5 QoS 1 retained PUBLISH, packet_id=7, topic "x", payload "live".
     * remain = topic(3) + id(2) + props(1) + payload(4) = 10 */
    static const byte publish_retain[] = {
        0x33, 0x0A, 0x00, 0x01, 'x', 0x00, 0x07, 0x00,
        'l', 'i', 'v', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* The retained table is far below capacity, so the store fails only because
     * the injected allocation fails. The topic copy allocates first and
     * succeeds; the next allocation is the retained store's, which fails. */
    broker_test_fail_alloc_after(1);
    mock_client_input_append(1, publish_retain, sizeof(publish_retain));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();

    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    pub_pubacks = count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_ACK);

    ASSERT_EQ(1, g_alloc_failure_count);   /* the retained store did fail */
    ASSERT_EQ(0, broker.retained_count);   /* nothing was stored */
    ASSERT_EQ(1, sub_pubs);                /* but still delivered live */
    ASSERT_EQ(1, pub_pubacks);
    ASSERT_EQ(MQTT_REASON_SUCCESS,
        first_publish_resp_reason(g_clients[1].out_buf,
            g_clients[1].out_len));        /* acked success, not Quota */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */
#endif /* WOLFMQTT_V5 && WOLFMQTT_MAX_QOS >= 1 */
#endif /* WOLFMQTT_BROKER_RETAINED && !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* Subscription state is committed only after its filter and persistent
 * client identifier have both been stored successfully. */
TEST(broker_subscription_client_id_alloc_failure_atomic)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int alloc_balance;
    int i;
    static const byte connect[] = {
        0x10, 0x0F,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x03, 's', 'u', 'b'
    };
    /* MQTT v3.1.1 sections 3.8.2 and 3.8.3: packet id 1, filter "x",
     * requested QoS 0. */
    static const byte subscribe[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    run_broker_one_connect(&broker);
    ASSERT_TRUE(broker.clients != NULL);
    ASSERT_EQ(0, broker.clients->sub_count);

    /* BrokerSubs_Add allocates the node and filter before the client id. */
    alloc_balance = g_alloc_success_count - g_alloc_free_count;
    broker_test_fail_alloc_after(2);
    mock_client_input_append(0, subscribe, sizeof(subscribe));
    for (i = 0; i < 4; i++) {
        MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_EQ(alloc_balance, g_alloc_success_count - g_alloc_free_count);
    ASSERT_EQ(0, broker.clients->sub_count);
    ASSERT_TRUE(broker.subs == NULL);
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    ASSERT_EQ(MQTT_SUBSCRIBE_ACK_CODE_FAILURE,
        g_clients[0].out_buf[g_clients[0].out_len - 1]);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

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
#ifdef WOLFMQTT_BROKER_WILL
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
#endif /* WOLFMQTT_BROKER_WILL */

#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
/* A v5 DISCONNECT that fails to decode is a Malformed Packet, not a normal
 * disconnect: the Server closes the Network Connection and the Will Message
 * is published (MQTT 5.0 sections 3.1.2.5 and 4.13). Only a successfully
 * decoded DISCONNECT with Reason Code 0x00 discards the Will [MQTT-3.14.4-3]. */
TEST(disconnect_v5_malformed_fires_will)
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
    /* v5 CONNECT with Will: flags 0x06 (will_flag | clean_start), keep
     * alive 60, Properties length 0, ClientId "P", Will Properties length 0,
     * Will Topic "lwt", Will Payload "bye". Remaining Length 25. */
    static const byte pub_connect[] = {
        0x10, 0x19,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x06, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 DISCONNECT, Reason Code 0x00, Property Length 5 with no property
     * bytes following: the declared Properties overrun the packet. */
    static const byte disconnect_bad[] = { 0xE0, 0x02, 0x00, 0x05 };

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

    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_TRUE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Connect a v5 publisher with a Will and a v3.1.1 subscriber to its Will
 * topic, then send a well-formed DISCONNECT carrying only reason_code.
 * Returns the number of PUBLISH packets the subscriber received. */
static int disconnect_v5_reason_wills(byte reason_code, int* closed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int publishes;
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
    /* Same v5 CONNECT with Will as disconnect_v5_malformed_fires_will. */
    static const byte pub_connect[] = {
        0x10, 0x19,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x06, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 DISCONNECT (MQTT 5.0 section 3.14): Remaining Length 1, Reason
     * Code only, Property Length omitted (section 3.14.2.2.1). */
    byte disconnect[] = { 0xE0, 0x01, 0x00 };
    disconnect[2] = reason_code;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    reset_mock_clients(2);
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, pub_connect, sizeof(pub_connect));
    mock_client_input_append(1, disconnect, sizeof(disconnect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    publishes = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    *closed = g_clients[1].closed;

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return publishes;
}

/* Only Reason Code 0x00 discards the Will [MQTT-3.14.4-3]. */
TEST(disconnect_v5_reason_0_discards_will)
{
    int closed = 0;

    ASSERT_EQ(0, disconnect_v5_reason_wills(MQTT_REASON_SUCCESS, &closed));
    ASSERT_TRUE(closed);
}

TEST(disconnect_v5_reason_4_publishes_will)
{
    int closed = 0;

    ASSERT_EQ(1, disconnect_v5_reason_wills(
        MQTT_REASON_DISCONNECT_W_WILL_MSG, &closed));
    ASSERT_TRUE(closed);
}

/* Any other Reason Code is not a normal disconnection, so the Will is
 * published (MQTT 5.0 section 3.1.2.5, [MQTT-3.1.2-10]). */
TEST(disconnect_v5_reason_error_publishes_will)
{
    int closed = 0;

    ASSERT_EQ(1, disconnect_v5_reason_wills(MQTT_REASON_UNSPECIFIED_ERR,
        &closed));
    ASSERT_TRUE(closed);
}

/* Connect a v3.1.1 subscriber to "lwt" and a v5 client "P" with a Will on
 * "lwt", then take over "P" from a second v5 connection. Returns the number
 * of PUBLISH packets the subscriber received by the time the Will Delay of
 * the old connection would have elapsed. */
static int takeover_v5_wills(word32 session_expiry, word32 will_delay,
    int new_clean_start, int* old_closed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int publishes;
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
    /* v5 CONNECT (MQTT 5.0 section 3.1): flags 0x04 (Will, Clean Start 0),
     * keep alive 60, Properties length 5 holding Session Expiry Interval
     * (0x11, four byte integer), ClientId "P", Will Properties length 5
     * holding Will Delay Interval (0x18, four byte integer), Will Topic
     * "lwt", Will Payload "bye". Remaining Length 35. */
    byte old_connect[] = {
        0x10, 0x23,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x04, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 'P',
        0x05, 0x18, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 CONNECT, no Will, Properties length 0, ClientId "P". Flags byte is
     * 0x02 for Clean Start 1 or 0x00 for Clean Start 0. Remaining Length 14. */
    byte new_connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };

    old_connect[14] = (byte)(session_expiry >> 24);
    old_connect[15] = (byte)(session_expiry >> 16);
    old_connect[16] = (byte)(session_expiry >> 8);
    old_connect[17] = (byte)session_expiry;
    old_connect[23] = (byte)(will_delay >> 24);
    old_connect[24] = (byte)(will_delay >> 16);
    old_connect[25] = (byte)(will_delay >> 8);
    old_connect[26] = (byte)will_delay;
    if (new_clean_start) {
        new_connect[9] = 0x02;
    }

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    reset_mock_clients(3);
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, old_connect, sizeof(old_connect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    mock_client_input_append(2, new_connect, sizeof(new_connect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    /* Let any deferred Will come due */
    g_broker_time_s += will_delay + 1;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    publishes = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    *old_closed = g_clients[1].closed;

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return publishes;
}

/* Number of packets in the capture after the first packet of type `after`
 * that have type `target`, or -1 if no `after` packet is present. */
static int count_packets_after(const byte* buf, size_t len, byte after,
    byte target)
{
    size_t pos = 0;
    int seen = 0;
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
        if (!vbi_complete || remain > len - pos - hdr_len) {
            break;
        }
        if (seen && type == target) {
            count++;
        }
        if (type == after) {
            seen = 1;
        }
        pos += hdr_len + remain;
    }
    return seen ? count : -1;
}

/* [MQTT-3.14.4-1] Nothing may be sent on a connection after its DISCONNECT.
 * On a v5 takeover the broker sends the old connection DISCONNECT 0x8E and
 * publishes its Will; when the old client subscribes to its own Will topic,
 * that copy must not reach it after the DISCONNECT. Will Delay 0 and Session
 * Expiry 0, so the Will is published at the takeover. */
TEST(takeover_v5_own_will_not_sent_after_disconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* v5 CONNECT for "P" with Will "lwt"/"bye", Session Expiry 0, Will
     * Delay 0 (layout as in takeover_v5_wills). */
    static const byte old_connect[] = {
        0x10, 0x23,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x04, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 'P',
        0x05, 0x18, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 SUBSCRIBE (MQTT 5.0 section 3.8): packet id 1, Properties length
     * 0, filter "lwt", options 0 (QoS 0). Remaining Length 9. */
    static const byte old_subscribe[] = {
        0x82, 0x09,
        0x00, 0x01,
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00
    };
    /* v5 CONNECT for "P", Clean Start 1, no Will, no properties. */
    static const byte new_connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, old_connect, sizeof(old_connect));
    mock_client_input_append(0, old_subscribe, sizeof(old_subscribe));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    mock_client_input_append(1, new_connect, sizeof(new_connect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_TRUE(g_clients[0].closed);
    ASSERT_EQ(0, count_packets_after(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_DISCONNECT,
        MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#if defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
/* A short write of the old client's own Will copy must not leave the
 * Session Taken Over DISCONNECT unsent behind it [MQTT-3.14.4-1]. The QoS 0
 * self-copy is not started on a connection that is closing, so the old client
 * receives exactly one complete DISCONNECT 0x8E after its SUBACK. */
TEST(takeover_v5_own_will_partial_write_still_disconnects)
{
    MqttBroker broker;
    MqttBrokerNet net;
    size_t before;
    int publishes_before;
    int i;
    /* v5 CONNECT for "P" with Will "lwt"/"bye", Session Expiry 0, Will
     * Delay 0 (layout as in takeover_v5_wills). */
    static const byte old_connect[] = {
        0x10, 0x23,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x04, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 'P',
        0x05, 0x18, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 SUBSCRIBE (MQTT 5.0 section 3.8): packet id 1, Properties length
     * 0, filter "lwt", options 0 (QoS 0). Remaining Length 9. */
    static const byte old_subscribe[] = {
        0x82, 0x09,
        0x00, 0x01,
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00
    };
    /* v5 CONNECT for "P", Clean Start 1, no Will, no properties. */
    static const byte new_connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, old_connect, sizeof(old_connect));
    mock_client_input_append(0, old_subscribe, sizeof(old_subscribe));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    before = g_clients[0].out_len;
    publishes_before = g_clients[0].publish_writes;
    g_clients[0].write_limit_on_publish = 1;
    mock_client_input_append(1, new_connect, sizeof(new_connect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_TRUE(g_clients[0].closed);
    ASSERT_EQ(publishes_before, g_clients[0].publish_writes);
    /* MQTT 5.0 section 3.14: fixed header 0xE0, Remaining Length, Reason
     * Code 0x8E Session taken over, and nothing after the frame. */
    ASSERT_TRUE(g_clients[0].out_len >= before + 3);
    ASSERT_EQ(0xE0, g_clients[0].out_buf[before]);
    ASSERT_EQ(MQTT_REASON_SESSION_TAKEN_OVER,
        g_clients[0].out_buf[before + 2]);
    ASSERT_EQ(before + 2 + g_clients[0].out_buf[before + 1],
        g_clients[0].out_len);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif

/* MQTT 5.0 section 3.1.4: with a zero Will Delay the old Will is published
 * because its Network Connection is closed, even though the Session
 * survives the takeover. */
TEST(takeover_v5_zero_will_delay_publishes_will)
{
    int closed = 0;

    ASSERT_EQ(1, takeover_v5_wills(60, 0, 0, &closed));
    ASSERT_TRUE(closed);
}

/* The Session resumes before the Will Delay elapses, so the Will is not
 * sent [MQTT-3.1.3-9]. */
TEST(takeover_v5_will_delay_resumed_session_discards_will)
{
    int closed = 0;

    ASSERT_EQ(0, takeover_v5_wills(60, 30, 0, &closed));
    ASSERT_TRUE(closed);
}

/* Clean Start 1 ends the old Session at takeover, which publishes the Will
 * ahead of its delay (MQTT 5.0 sections 3.1.3.2.2 and 3.1.4). */
TEST(takeover_v5_clean_start_publishes_will)
{
    int closed = 0;

    ASSERT_EQ(1, takeover_v5_wills(60, 30, 1, &closed));
    ASSERT_TRUE(closed);
}

/* A zero Session Expiry ends the old Session at takeover, so the Will is
 * published (MQTT 5.0 section 3.1.4). */
TEST(takeover_v5_zero_session_expiry_publishes_will)
{
    int closed = 0;

    ASSERT_EQ(1, takeover_v5_wills(0, 30, 0, &closed));
    ASSERT_TRUE(closed);
}

#ifndef WOLFMQTT_DYN_PROP
/* Connect a v5 publisher with a Will and a v3.1.1 subscriber to its Will
 * topic, leave the shared property pool one slot short of the publisher's
 * DISCONNECT Properties, then send that DISCONNECT with reason_code. Returns
 * the number of PUBLISH packets the subscriber received. */
static int disconnect_v5_props_pool_exhausted_wills(byte reason_code,
    int* closed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttProp* hold = NULL;
    int free_slots = 0;
    int i;
    int publishes;
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
    /* Same v5 CONNECT with Will as disconnect_v5_malformed_fires_will. */
    static const byte pub_connect[] = {
        0x10, 0x19,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x06, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 DISCONNECT (MQTT 5.0 section 3.14): Remaining Length 16, Reason
     * Code, Property Length 14, then two User Properties (identifier 0x26,
     * UTF-8 String Pair "k" / "v"). */
    byte disconnect[] = {
        0xE0, 0x10,
        0x00,
        0x0E,
        0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v',
        0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v'
    };
    disconnect[2] = reason_code;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    reset_mock_clients(2);
    mock_client_input_append(0, sub_connect, sizeof(sub_connect));
    mock_client_input_append(0, sub_subscribe, sizeof(sub_subscribe));
    mock_client_input_append(1, pub_connect, sizeof(pub_connect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Hold a property-stack reference of our own (see
     * connect_v5_refused_when_shared_sub_property_unavailable), then leave
     * a single free slot: the DISCONNECT is well formed, but its second
     * User Property cannot be allocated. */
    publishes = -1;
    if (MqttProps_Init() == MQTT_CODE_SUCCESS) {
        while (MqttProps_Add(&hold) != NULL) {
            free_slots++;
        }
        (void)MqttProps_Free(hold);
        hold = NULL;
        for (i = 0; i < free_slots - 1; i++) {
            (void)MqttProps_Add(&hold);
        }

        mock_client_input_append(1, disconnect, sizeof(disconnect));
        for (i = 0; i < 16; i++) {
            MqttBroker_Step(&broker);
        }
        (void)MqttProps_Free(hold);
        (void)MqttProps_ShutDown();

        if (free_slots >= 2) {
            publishes = count_packets_of_type(g_clients[0].out_buf,
                g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
        }
    }
    *closed = g_clients[1].closed;

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return publishes;
}

/* A well-formed v5 DISCONNECT whose Properties cannot be allocated is not a
 * Malformed Packet. Reason Code 0x00 is a normal disconnection, so the Will
 * is discarded [MQTT-3.14.4-3]. */
TEST(disconnect_v5_props_pool_exhausted_reason_0_discards_will)
{
    int closed = 0;

    ASSERT_EQ(0, disconnect_v5_props_pool_exhausted_wills(
        MQTT_REASON_SUCCESS, &closed));
    ASSERT_TRUE(closed);
}

/* Reason Code 0x04 still publishes the Will when the DISCONNECT Properties
 * cannot be allocated [MQTT-3.14.4-3]. */
TEST(disconnect_v5_props_pool_exhausted_reason_4_publishes_will)
{
    int closed = 0;

    ASSERT_EQ(1, disconnect_v5_props_pool_exhausted_wills(
        MQTT_REASON_DISCONNECT_W_WILL_MSG, &closed));
    ASSERT_TRUE(closed);
}

/* An error Reason Code publishes the Will when the DISCONNECT Properties
 * cannot be allocated (MQTT 5.0 section 3.1.2.5). */
TEST(disconnect_v5_props_pool_exhausted_reason_error_publishes_will)
{
    int closed = 0;

    ASSERT_EQ(1, disconnect_v5_props_pool_exhausted_wills(
        MQTT_REASON_UNSPECIFIED_ERR, &closed));
    ASSERT_TRUE(closed);
}
#endif /* !WOLFMQTT_DYN_PROP */
#endif /* WOLFMQTT_V5 && WOLFMQTT_BROKER_WILL */

#ifdef WOLFMQTT_V5
#if defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_NONBLOCK)
    /* Static clients cannot resume a deferred write, so these builds close
     * without the error DISCONNECT rather than risk truncating it. */
    #define ERROR_DISCONNECT_REASON(reason) (-1)
#else
    #define ERROR_DISCONNECT_REASON(reason) (reason)
#endif

/* MQTT 5.0 section 4.13.1: a Server that detects a Malformed Packet or
 * Protocol Error in a packet other than CONNECT SHOULD send DISCONNECT with
 * the Reason Code before closing. Connect a v5 client, send one bad packet,
 * and return the Reason Code of the DISCONNECT the broker sent (-1 if none);
 * *closed reports whether the connection was closed. */
static int v5_bad_packet_disconnect_reason(const byte* bad, size_t bad_len,
    int* closed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int reason;
    /* v5 CONNECT, CleanStart, keep alive 60, no properties, ClientId "A". */
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        *closed = 0;
        return -2;
    }
    reset_mock_state(connect, sizeof(connect));
    mock_client_input_append(0, bad, bad_len);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    reason = first_disconnect_reason(g_out_buf, g_out_len);
    *closed = g_client_closed;
    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return reason;
}

/* [MQTT-2.2.2-2] PUBACK fixed-header flags must be 0000: Malformed Packet. */
TEST(v5_invalid_fixed_header_flags_sends_malformed_disconnect)
{
    static const byte puback[] = { 0x41, 0x02, 0x00, 0x01 };
    int closed = 0;

    ASSERT_EQ(ERROR_DISCONNECT_REASON(MQTT_REASON_MALFORMED_PACKET),
        v5_bad_packet_disconnect_reason(puback, sizeof(puback), &closed));
    ASSERT_TRUE(closed);
}

/* [MQTT-3.1.0-2] A second CONNECT is a Protocol Error. */
TEST(v5_second_connect_sends_protocol_error_disconnect)
{
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };
    int closed = 0;

    ASSERT_EQ(ERROR_DISCONNECT_REASON(MQTT_REASON_PROTOCOL_ERR),
        v5_bad_packet_disconnect_reason(connect, sizeof(connect), &closed));
    ASSERT_TRUE(closed);
}

/* MQTT 5.0 section 3.12: PINGREQ has no variable header or payload, so a
 * non-zero Remaining Length is a Malformed Packet. */
TEST(v5_pingreq_with_body_sends_malformed_disconnect)
{
    static const byte pingreq[] = { 0xC0, 0x01, 0x00 };
    int closed = 0;

    ASSERT_EQ(ERROR_DISCONNECT_REASON(MQTT_REASON_MALFORMED_PACKET),
        v5_bad_packet_disconnect_reason(pingreq, sizeof(pingreq), &closed));
    ASSERT_TRUE(closed);
}

/* MQTT 5.0 section 4.12: without an Authentication Method in CONNECT the
 * Client must not send AUTH, so an AUTH here is a Protocol Error. Wire: AUTH
 * with Remaining Length 0 (Success, section 3.15.2.1). */
TEST(v5_unexpected_auth_sends_protocol_error_disconnect)
{
    static const byte auth[] = { 0xF0, 0x00 };
    int closed = 0;

    ASSERT_EQ(ERROR_DISCONNECT_REASON(MQTT_REASON_PROTOCOL_ERR),
        v5_bad_packet_disconnect_reason(auth, sizeof(auth), &closed));
    ASSERT_TRUE(closed);
}

#if defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
/* When the DISCONNECT before an error close cannot be written at once, the
 * connection stays open until it is fully written and is closed then, so the
 * Reason Code still reaches the client. Every write is held back with
 * MQTT_CODE_CONTINUE once the CONNACK is out, then released. */
TEST(v5_error_close_waits_for_deferred_disconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };
    /* PINGREQ with a body: a Malformed Packet (MQTT 5.0 section 3.12). */
    static const byte pingreq[] = { 0xC0, 0x01, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_out_buf[3]);

    g_clients[0].write_continue = 1;
    mock_client_input_append(0, pingreq, sizeof(pingreq));
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_FALSE(g_client_closed);
    ASSERT_EQ(-1, first_disconnect_reason(g_out_buf, g_out_len));

    g_clients[0].write_continue = 0;
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(MQTT_REASON_MALFORMED_PACKET,
        first_disconnect_reason(g_out_buf, g_out_len));
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK && !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_STATIC_MEMORY)
/* A static client cannot resume a deferred write, so an error close must not
 * start a DISCONNECT it may be unable to finish: a short write would leave a
 * truncated packet on the wire before the close. The connection is closed
 * with nothing written after the CONNACK. */
TEST(v5_static_error_close_leaves_no_partial_disconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    size_t connack_len;
    int i;
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };
    /* PINGREQ with a body: a Malformed Packet (MQTT 5.0 section 3.12). */
    static const byte pingreq[] = { 0xC0, 0x01, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, g_out_buf[3]);
    connack_len = g_out_len;

    g_clients[0].write_limit_once = 1;
    mock_client_input_append(0, pingreq, sizeof(pingreq));
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_client_closed);
    ASSERT_EQ(connack_len, g_out_len);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK && WOLFMQTT_STATIC_MEMORY */
#endif /* WOLFMQTT_V5 */

#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
/* Leave a v5 Session for "P" with Session Expiry 60, resume it with
 * reconnect, and return the Session Expiry Interval the resumed client
 * ends up with (0 on setup failure). */
static word32 reclaim_session_expiry(const byte* reconnect,
    size_t reconnect_len)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* bc;
    word32 expiry = 0;
    int i;
    /* v5 CONNECT (MQTT 5.0 section 3.1): Clean Start 0, keep alive 60,
     * Properties length 5 holding Session Expiry Interval 60 (0x11),
     * ClientId "P". Remaining Length 19. */
    static const byte connect_60[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* v5 DISCONNECT, Remaining Length 0: Reason Code 0x00 */
    static const byte disconnect[] = { 0xE0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return 0;
    }

    reset_mock_clients(2);
    mock_client_input_append(0, connect_60, sizeof(connect_60));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    if (broker.orphan_sessions != NULL &&
            broker.orphan_sessions->session_expiry_sec == 60) {
        mock_client_input_append(1, reconnect, reconnect_len);
        for (i = 0; i < 16; i++) {
            MqttBroker_Step(&broker);
        }
        bc = find_broker_client(&broker, "P");
        if (bc != NULL && broker.orphan_sessions == NULL) {
            expiry = bc->session_expiry_sec;
        }
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return expiry;
}

/* [MQTT-3.1.2.11.2] The resuming CONNECT's explicit 0xFFFFFFFF means the
 * Session never expires; it must not be replaced by the old interval. */
TEST(reclaim_keeps_explicit_v5_never_expire)
{
    /* As connect_60 in reclaim_session_expiry, with Session Expiry
     * 0xFFFFFFFF */
    static const byte connect_never[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x01, 'P'
    };

    ASSERT_EQ(0xFFFFFFFFu, reclaim_session_expiry(connect_never,
        sizeof(connect_never)));
}

/* A v3.1.1 CleanSession=0 Session never expires (MQTT 3.1.1 section
 * 3.1.2.4), even when it resumes a Session created over v5. */
TEST(reclaim_v311_resume_never_expires)
{
    static const byte connect_v311[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };

    ASSERT_EQ(0xFFFFFFFFu, reclaim_session_expiry(connect_v311,
        sizeof(connect_v311)));
}
#endif /* WOLFMQTT_V5 && !WOLFMQTT_STATIC_MEMORY */

#ifdef WOLFMQTT_V5
/* Build a v3.1.1 QoS 0 PUBLISH to "x" that exactly fills the broker receive
 * buffer (MQTT 3.1.1 section 3.3): fixed header byte, two byte Remaining
 * Length, Topic Name "x", then payload. Forwarded to a v5 subscriber it gains
 * a Property Length byte and no longer fits the transmit buffer. */
static size_t build_full_rx_publish(byte* buf, size_t buf_sz, byte retain)
{
    word32 remain_len = (word32)BROKER_RX_BUF_SZ - 3;
    size_t i;

    if (buf_sz < (size_t)BROKER_RX_BUF_SZ || remain_len < 128 ||
            remain_len > 16383) {
        return 0;
    }
    buf[0] = (byte)(0x30 | (retain ? 0x01 : 0x00));
    buf[1] = (byte)((remain_len & 0x7F) | 0x80);
    buf[2] = (byte)(remain_len >> 7);
    buf[3] = 0x00;
    buf[4] = 0x01;
    buf[5] = 'x';
    for (i = 6; i < (size_t)BROKER_RX_BUF_SZ; i++) {
        buf[i] = 'A';
    }
    return (size_t)BROKER_RX_BUF_SZ;
}

/* A forwarded PUBLISH that does not fit the subscriber's transmit buffer
 * must not be written: a clamped payload under the full Remaining Length
 * would desynchronize the subscriber (MQTT 3.1.1 section 2.2.3). Returns the
 * subscriber's PUBLISH writes, or -1 on setup failure. */
static int oversize_forward_publish_writes(int retained, int* sub_closed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    static byte big[BROKER_RX_BUF_SZ];
    size_t big_len;
    int i;
    int writes;
    /* v5 CONNECT, Clean Start, ClientId "S" */
    static const byte connect_sub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE packet id 1, Properties length 0, filter "x", QoS 0 */
    static const byte subscribe_x[] = {
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'x', 0x00
    };
    /* v3.1.1 CONNECT, CleanSession=1, ClientId "P" */
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };

    big_len = build_full_rx_publish(big, sizeof(big), (byte)retained);
    if (big_len == 0) {
        return -1;
    }
    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    reset_mock_clients(2);
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    if (!retained) {
        mock_client_input_append(0, connect_sub, sizeof(connect_sub));
        mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    }
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    mock_client_input_append(1, big, big_len);
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    if (retained) {
        /* The retained copy is delivered on subscribe */
        mock_client_input_append(0, connect_sub, sizeof(connect_sub));
        mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
        for (i = 0; i < 16; i++) {
            MqttBroker_Step(&broker);
        }
    }

    writes = g_clients[0].publish_writes;
    *sub_closed = g_clients[0].closed;

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return writes;
}

TEST(live_forward_exceeding_tx_buf_not_sent_truncated)
{
    int closed = 1;

    ASSERT_EQ(0, oversize_forward_publish_writes(0, &closed));
    ASSERT_FALSE(closed);
}

TEST(retained_delivery_exceeding_tx_buf_not_sent_truncated)
{
    int closed = 1;

    ASSERT_EQ(0, oversize_forward_publish_writes(1, &closed));
    ASSERT_FALSE(closed);
}
#endif /* WOLFMQTT_V5 */

#if !defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_BROKER_WILL)
/* A QoS 0 Will written directly to a subscriber whose transmit buffer cannot
 * hold it must be skipped rather than sent with a clamped payload (MQTT 3.1.1
 * section 2.2.3). */
TEST(will_qos0_exceeding_tx_buf_not_sent_truncated)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    int i;
    /* v3.1.1 CONNECT, CleanSession=1, ClientId "S" */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet id 1, filter "lwt", QoS 0 */
    static const byte subscribe_lwt[] = {
        0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'l', 'w', 't', 0x00
    };
    /* v3.1.1 CONNECT, Will Flag (QoS 0) and CleanSession, ClientId "P",
     * Will Topic "lwt", Will Message "bye". Remaining Length 23. */
    static const byte connect_pub[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x06, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* The Will PUBLISH is 10 bytes: fixed header 2, Topic Name 5, payload 3 */
    sub_bc->tx_buf_len = 8;
    g_clients[1].read_err = 1;
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(0, g_clients[0].publish_writes);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A QoS 1 Will matching an offline persistent subscriber is queued in its
 * Session and delivered when it reconnects, as a QoS 1 PUBLISH would be
 * [MQTT-3.1.2-4]. */
TEST(will_qos1_queued_for_offline_persistent_subscriber)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* v3.1.1 CONNECT, CleanSession=0, ClientId "S" */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet id 1, filter "lwt", QoS 1 */
    static const byte subscribe_lwt[] = {
        0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'l', 'w', 't', 0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    /* v3.1.1 CONNECT, Will Flag, Will QoS 1 and CleanSession, ClientId "P",
     * Will Topic "lwt", Will Message "bye". Remaining Length 23. */
    static const byte connect_pub[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x0E, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);
    ASSERT_NOT_NULL(broker.orphan_sessions);

    /* The Will publisher drops, firing its Will while "S" is offline */
    g_clients[1].read_err = 1;
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);

    /* "S" resumes its Session and receives the queued Will */
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY && WOLFMQTT_BROKER_WILL */

#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
/* Returns 1 if needle occurs in hay. */
static int will_bytes_found(const byte* hay, size_t hay_len,
    const byte* needle, size_t needle_len)
{
    size_t i;

    for (i = 0; i + needle_len <= hay_len; i++) {
        if (XMEMCMP(hay + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

#ifndef WOLFMQTT_DYN_PROP
/* Take every free entry of the shared property pool, so a decode through it
 * fails as it would under load. Release with MqttProps_Free. */
static MqttProp* will_test_exhaust_prop_pool(void)
{
    MqttProp* head = NULL;

    while (MqttProps_Add(&head) != NULL) {
    }
    return head;
}
#endif

/* Most User Properties will_props_reach_live_subscriber can carry while the
 * CONNECT and PUBLISH Remaining Lengths stay one byte long. */
#define WILL_TEST_MAX_USER_PROPS 12

/* A v5 Will carries its Will Properties, other than the Will Delay Interval,
 * onto the Will PUBLISH in their original order (MQTT 5.0 section 3.1.3.2,
 * [MQTT-3.1.3-10]). The Will Properties are a Content Type "t" followed by
 * user_props User Properties "k" = "v". With_delay adds a Will Delay
 * Interval; Session Expiry 0 then publishes through the pending-Will path at
 * once. With exhaust_pool the shared property pool is full while the Will is
 * published, which must not drop or strip it. Returns 1 when a live v5
 * subscriber receives exactly the expected PUBLISH. */
static int will_props_reach_live_subscriber(int with_delay, int exhaust_pool,
    int user_props)
{
    MqttBroker broker;
    MqttBrokerNet net;
#ifndef WOLFMQTT_DYN_PROP
    MqttProp* held = NULL;
#endif
    int i;
    int found;
    byte connect_pub[128];
    byte expected[128];
    int pos = 0;
    int exp_pos = 0;
    /* v5 CONNECT, Clean Start, no properties, ClientId "S" */
    static const byte connect_sub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE packet id 1, Properties length 0, filter "lwt", QoS 0 */
    static const byte subscribe_lwt[] = {
        0x82, 0x09, 0x00, 0x01, 0x00, 0x00, 0x03, 'l', 'w', 't', 0x00
    };
    /* Will Delay Interval (0x18) 5 seconds */
    static const byte will_delay[] = { 0x18, 0x00, 0x00, 0x00, 0x05 };
    /* Content Type (0x03) "t" */
    static const byte content_type[] = { 0x03, 0x00, 0x01, 't' };
    /* User Property (0x26) "k" = "v" */
    static const byte user_prop[] = {
        0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v'
    };
    int pub_props_len;
    int props_len;

    if (user_props < 0 || user_props > WILL_TEST_MAX_USER_PROPS) {
        return -1;
    }
    pub_props_len = (int)sizeof(content_type) +
        user_props * (int)sizeof(user_prop);
    props_len = pub_props_len + (with_delay ? (int)sizeof(will_delay) : 0);

    /* v5 CONNECT (MQTT 5.0 section 3.1): Will Flag and Clean Start, keep
     * alive 60, no CONNECT properties, ClientId "P", Will Properties, Will
     * Topic "lwt", Will Payload "bye". */
    connect_pub[pos++] = 0x10;
    connect_pub[pos++] = (byte)(11 + 3 + 1 + props_len + 5 + 5);
    XMEMCPY(&connect_pub[pos], "\x00\x04MQTT\x05\x06\x00\x3C\x00", 11);
    pos += 11;
    XMEMCPY(&connect_pub[pos], "\x00\x01P", 3);
    pos += 3;
    connect_pub[pos++] = (byte)props_len;
    if (with_delay) {
        XMEMCPY(&connect_pub[pos], will_delay, sizeof(will_delay));
        pos += (int)sizeof(will_delay);
    }
    XMEMCPY(&connect_pub[pos], content_type, sizeof(content_type));
    pos += (int)sizeof(content_type);
    for (i = 0; i < user_props; i++) {
        XMEMCPY(&connect_pub[pos], user_prop, sizeof(user_prop));
        pos += (int)sizeof(user_prop);
    }
    XMEMCPY(&connect_pub[pos], "\x00\x03lwt\x00\x03" "bye", 10);
    pos += 10;

    /* Expected v5 QoS 0 PUBLISH (MQTT 5.0 section 3.3): topic "lwt", the
     * Will Properties without the Will Delay Interval, payload "bye". */
    expected[exp_pos++] = 0x30;
    expected[exp_pos++] = (byte)(5 + 1 + pub_props_len + 3);
    XMEMCPY(&expected[exp_pos], "\x00\x03lwt", 5);
    exp_pos += 5;
    expected[exp_pos++] = (byte)pub_props_len;
    XMEMCPY(&expected[exp_pos], content_type, sizeof(content_type));
    exp_pos += (int)sizeof(content_type);
    for (i = 0; i < user_props; i++) {
        XMEMCPY(&expected[exp_pos], user_prop, sizeof(user_prop));
        exp_pos += (int)sizeof(user_prop);
    }
    XMEMCPY(&expected[exp_pos], "bye", 3);
    exp_pos += 3;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(1, connect_pub, (size_t)pos);
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
#ifndef WOLFMQTT_DYN_PROP
    if (exhaust_pool) {
        held = will_test_exhaust_prop_pool();
        if (held == NULL) {
            exhaust_pool = -1;
        }
    }
#else
    if (exhaust_pool) {
        exhaust_pool = -1; /* no shared pool to exhaust */
    }
#endif
    g_clients[1].read_err = 1;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
#ifndef WOLFMQTT_DYN_PROP
    if (held != NULL) {
        (void)MqttProps_Free(held);
    }
#endif

    found = will_bytes_found(g_clients[0].out_buf, g_clients[0].out_len,
        expected, (size_t)exp_pos);
    if (count_packets_of_type(g_clients[0].out_buf, g_clients[0].out_len,
            MQTT_PACKET_TYPE_PUBLISH) != 1 || exhaust_pool < 0) {
        found = 0;
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return found;
}

TEST(will_props_forwarded_to_live_subscriber)
{
    ASSERT_EQ(1, will_props_reach_live_subscriber(0, 0, 1));
}

TEST(delayed_will_props_forwarded_to_live_subscriber)
{
    ASSERT_EQ(1, will_props_reach_live_subscriber(1, 0, 1));
}

#ifndef WOLFMQTT_DYN_PROP
#ifdef WOLFMQTT_STATIC_MEMORY
/* User Properties, after the Content Type, in the largest Will this static
 * build accepts that will_props_reach_live_subscriber can carry. */
#define WILL_TEST_STATIC_USER_PROPS_BY_LEN ((BROKER_MAX_WILL_PROPS_LEN - 4) / 7)
#define WILL_TEST_STATIC_USER_PROPS_BY_ENTRIES \
    (BROKER_WILL_PROPS_STACK_ENTRIES - 1)
#define WILL_TEST_STATIC_USER_PROPS_MIN2(a, b) (((a) < (b)) ? (a) : (b))
#define WILL_TEST_STATIC_USER_PROPS WILL_TEST_STATIC_USER_PROPS_MIN2( \
    WILL_TEST_STATIC_USER_PROPS_MIN2(WILL_TEST_STATIC_USER_PROPS_BY_LEN, \
        WILL_TEST_STATIC_USER_PROPS_BY_ENTRIES), WILL_TEST_MAX_USER_PROPS)
#endif

/* Will Properties are rebuilt without the shared property pool, so a full
 * pool can neither drop the Will nor strip its properties, on the immediate
 * or the deferred path. In a static build the largest accepted Will still
 * fits the stack entries. */
TEST(will_props_published_with_prop_pool_exhausted)
{
    ASSERT_EQ(1, will_props_reach_live_subscriber(0, 1, 0));
    ASSERT_EQ(1, will_props_reach_live_subscriber(1, 1, 0));
#if !defined(WOLFMQTT_STATIC_MEMORY) || BROKER_WILL_PROPS_STACK_ENTRIES >= 2
    ASSERT_EQ(1, will_props_reach_live_subscriber(0, 1, 1));
    ASSERT_EQ(1, will_props_reach_live_subscriber(1, 1, 1));
#endif
#ifdef WOLFMQTT_STATIC_MEMORY
    ASSERT_EQ(1, will_props_reach_live_subscriber(0, 1,
        WILL_TEST_STATIC_USER_PROPS));
#endif
}
#endif

#if !defined(WOLFMQTT_STATIC_MEMORY) && \
    BROKER_WILL_PROPS_STACK_ENTRIES < WILL_TEST_MAX_USER_PROPS
/* A dynamic build rebuilds a Will with more properties than the stack
 * entries on the heap; all of them still reach the subscriber in order. */
TEST(will_props_beyond_stack_entries_forwarded)
{
    ASSERT_EQ(1, will_props_reach_live_subscriber(0, 0,
        WILL_TEST_MAX_USER_PROPS));
}
#endif

#if WOLFMQTT_MAX_QOS >= 1
/* A delayed Will can fire after every client has been freed, which releases
 * the last MqttClient_Init reference to the shared property pool. The Will
 * Properties must still be decoded: the copy queued for the offline Session
 * keeps them (MQTT 5.0 section 3.1.3.2) and delivers them on resume. */
TEST(delayed_will_props_decoded_with_no_clients)
{
    MqttBroker broker;
    MqttBrokerNet net;
    const byte* out;
    size_t out_len;
    size_t pos;
    int found = 0;
    int i;
    /* v5 CONNECT, Clean Start 0, Properties length 5 holding Session Expiry
     * Interval 300 (0x11), ClientId "S". Remaining Length 19. */
    static const byte connect_sub[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE packet id 1, Properties length 0, filter "lwt", QoS 1 */
    static const byte subscribe_lwt[] = {
        0x82, 0x09, 0x00, 0x01, 0x00, 0x00, 0x03, 'l', 'w', 't', 0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    /* v5 CONNECT for "P": Will Flag, Will QoS 1, Clean Start 0, Properties
     * length 5 holding Session Expiry Interval 60 (0x11), Will Properties
     * length 14 holding Will Delay Interval (0x18) 2, Message Expiry
     * Interval (0x02) 100 and Content Type (0x03) "t", Will Topic "lwt",
     * Will Payload "bye". Remaining Length 44. */
    static const byte connect_pub[] = {
        0x10, 0x2C,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x0C, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x0E,
        0x18, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x64,
        0x03, 0x00, 0x01, 't',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* Forwarded QoS 1 PUBLISH (MQTT 5.0 section 3.3), Remaining Length 20:
     * topic "lwt", a broker-assigned packet id (skipped), then this. */
    static const byte expected_props[] = {
        0x09,
        0x02, 0x00, 0x00, 0x00, 0x64,
        0x03, 0x00, 0x01, 't',
        'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    g_broker_time_s = 100;
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    g_clients[1].read_err = 1;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    /* Both connections are gone before the Will Delay ends. */
    ASSERT_TRUE(g_clients[0].closed);
    ASSERT_TRUE(g_clients[1].closed);
    g_broker_time_s += 3;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    g_clients_active = 3;
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    out = g_clients[2].out_buf;
    out_len = g_clients[2].out_len;
    for (pos = 0; pos + 9 + sizeof(expected_props) <= out_len; pos++) {
        if ((out[pos] & 0xF7) == 0x32 && out[pos + 1] == 0x14 &&
                XMEMCMP(&out[pos + 2], "\x00\x03lwt", 5) == 0 &&
                XMEMCMP(&out[pos + 9], expected_props,
                    sizeof(expected_props)) == 0) {
            found = 1;
            break;
        }
    }
    g_broker_time_s = 0;
    ASSERT_EQ(1, found);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif

#if WOLFMQTT_MAX_QOS >= 1
/* A QoS 1 Will with Message Expiry Interval `expiry` is queued for an offline
 * v5 subscriber, which resumes after wait_sec. Returns the PUBLISH packets it
 * receives and sets *wire_expiry to the forwarded Message Expiry Interval
 * (-1 if none). */
static int queued_will_after_wait(word32 wait_sec, byte expiry,
    long* wire_expiry)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int publishes;
    size_t pos;
    const byte* out;
    size_t out_len;
    /* v5 CONNECT, Clean Start 0, Properties length 5 holding Session Expiry
     * Interval 300 (0x11), ClientId "S". Remaining Length 19. */
    static const byte connect_sub[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE packet id 1, Properties length 0, filter "lwt", QoS 1 */
    static const byte subscribe_lwt[] = {
        0x82, 0x09, 0x00, 0x01, 0x00, 0x00, 0x03, 'l', 'w', 't', 0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    /* v5 CONNECT: Will Flag, Will QoS 1 and Clean Start, no CONNECT
     * properties, ClientId "P", Will Properties length 5 holding Message
     * Expiry Interval (0x02) 10 (low byte at offset 21, set from expiry),
     * Will Topic "lwt", Will Payload "bye". Remaining Length 30. */
    byte connect_pub[] = {
        0x10, 0x1E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x0E, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P',
        0x05, 0x02, 0x00, 0x00, 0x00, 0x0A,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };

    *wire_expiry = -1;
    connect_pub[21] = expiry;
    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    g_broker_time_s = 100;
    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    g_clients[1].read_err = 1;
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    g_broker_time_s += wait_sec;
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    out = g_clients[2].out_buf;
    out_len = g_clients[2].out_len;
    publishes = count_packets_of_type(out, out_len,
        MQTT_PACKET_TYPE_PUBLISH);
    /* Forwarded layout: 0x32 0x10, topic "lwt", 2 byte packet id, Properties
     * length 5, then 0x02 and the four byte Message Expiry Interval. */
    for (pos = 0; pos + 16 <= out_len; pos++) {
        if ((out[pos] & 0xF6) == 0x32 && out[pos + 1] == 0x10 &&
                out[pos + 2] == 0x00 && out[pos + 3] == 0x03 &&
                out[pos + 4] == 'l' && out[pos + 9] == 0x05 &&
                out[pos + 10] == MQTT_PROP_MSG_EXPIRY_INTERVAL) {
            *wire_expiry = ((long)out[pos + 11] << 24) |
                ((long)out[pos + 12] << 16) | ((long)out[pos + 13] << 8) |
                (long)out[pos + 14];
            break;
        }
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    g_broker_time_s = 0;
    return publishes;
}

/* [MQTT-3.3.2-5] A queued Will whose Message Expiry Interval passed before
 * the subscriber resumed is deleted, not delivered. */
TEST(queued_will_expired_before_delivery_dropped)
{
    long wire_expiry;

    ASSERT_EQ(0, queued_will_after_wait(11, 10, &wire_expiry));
}

/* [MQTT-3.3.2-6] A queued Will is delivered with its Message Expiry Interval
 * minus the time it waited. */
TEST(queued_will_expiry_reduced_by_wait)
{
    long wire_expiry;

    ASSERT_EQ(1, queued_will_after_wait(4, 10, &wire_expiry));
    ASSERT_EQ(6, wire_expiry);
}

/* MQTT 5.0 section 3.3.2.3.3: an explicit Message Expiry Interval of 0 has
 * passed by the time an offline subscriber resumes, so the queued Will is
 * deleted rather than treated as never expiring. */
TEST(queued_will_zero_expiry_dropped)
{
    long wire_expiry;

    ASSERT_EQ(0, queued_will_after_wait(1, 0, &wire_expiry));
}
#endif /* WOLFMQTT_MAX_QOS >= 1 */
#endif /* WOLFMQTT_V5 && WOLFMQTT_BROKER_WILL */

#if defined(WOLFMQTT_BROKER_WILL) && defined(WOLFMQTT_BROKER_WILDCARDS) && \
    WOLFMQTT_MAX_QOS >= 2
/* [MQTT-3.3.4-2] An offline Session whose QoS 1 and QoS 2 subscriptions both
 * match a QoS 2 Will gets it at QoS 2. One copy is queued, at the highest
 * matching QoS, so a full queue cannot evict that copy for the other. */
TEST(will_offline_overlapping_subs_queue_max_qos_once)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    size_t pos;
    int qos2 = 0;
    /* v3.1.1 CONNECT, CleanSession=0, ClientId "S" */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet id 1, filter "lwt" QoS 1, then packet id 2, filter
     * "+" QoS 2 */
    static const byte subscribe_lwt[] = {
        0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'l', 'w', 't', 0x01
    };
    static const byte subscribe_any[] = {
        0x82, 0x06, 0x00, 0x02, 0x00, 0x01, '+', 0x02
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    /* v3.1.1 CONNECT, Will Flag, Will QoS 2 and CleanSession, ClientId "P",
     * Will Topic "lwt", Will Message "bye". Remaining Length 23. */
    static const byte connect_pub[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x16, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(0, subscribe_any, sizeof(subscribe_any));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    g_clients[1].read_err = 1;
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);

    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));
    for (pos = 0; pos + 4 < g_clients[2].out_len; pos++) {
        if ((g_clients[2].out_buf[pos] & 0xF0) == 0x30 &&
                g_clients[2].out_buf[pos + 2] == 0x00 &&
                g_clients[2].out_buf[pos + 3] == 0x03 &&
                g_clients[2].out_buf[pos + 4] == 'l') {
            qos2 = ((g_clients[2].out_buf[pos] & 0x06) == 0x04);
            break;
        }
    }
    ASSERT_TRUE(qos2);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif

#if !defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_V5)
/* Queue a v5 QoS 1 PUBLISH with Message Expiry Interval `expiry` for an
 * offline persistent subscriber, let wait_sec pass, then resume the Session.
 * Returns the PUBLISH packets delivered and sets *wire_expiry to the Message
 * Expiry Interval of the first one (-1 if not found). */
static int queued_publish_after_wait(word32 wait_sec, byte expiry,
    long* wire_expiry)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int publishes;
    size_t pos;
    const byte* out;
    size_t out_len;
    /* v5 CONNECT, Clean Start 0, Properties length 5 holding Session Expiry
     * Interval 300 (0x11), ClientId "S". Remaining Length 19. */
    static const byte connect_sub[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE packet id 1, Properties length 0, filter "x", QoS 1 */
    static const byte subscribe_x[] = {
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'x', 0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    /* v5 CONNECT, Clean Start 1, Properties length 0, ClientId "P" */
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };
    /* v5 PUBLISH QoS 1 (MQTT 5.0 section 3.3): topic "x", packet id 1,
     * Properties length 5 holding Message Expiry Interval 10 (0x02, low byte
     * at offset 12, set from expiry), payload "hi". Remaining Length 13. */
    byte publish_x[] = {
        0x32, 0x0D,
        0x00, 0x01, 'x',
        0x00, 0x01,
        0x05, 0x02, 0x00, 0x00, 0x00, 0x0A,
        'h', 'i'
    };

    *wire_expiry = -1;
    publish_x[12] = expiry;
    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    g_broker_time_s = 100;
    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    mock_client_input_append(1, publish_x, sizeof(publish_x));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    g_broker_time_s += wait_sec;
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    out = g_clients[2].out_buf;
    out_len = g_clients[2].out_len;
    publishes = count_packets_of_type(out, out_len,
        MQTT_PACKET_TYPE_PUBLISH);
    /* Forwarded layout: 0x32 0x0D, topic "x", 2 byte packet id, Properties
     * length 5, then 0x02 and the four byte Message Expiry Interval. */
    for (pos = 0; pos + 13 <= out_len; pos++) {
        if (out[pos] == 0x32 && out[pos + 1] == 0x0D &&
                out[pos + 2] == 0x00 && out[pos + 3] == 0x01 &&
                out[pos + 4] == 'x' && out[pos + 7] == 0x05 &&
                out[pos + 8] == MQTT_PROP_MSG_EXPIRY_INTERVAL) {
            *wire_expiry = ((long)out[pos + 9] << 24) |
                ((long)out[pos + 10] << 16) | ((long)out[pos + 11] << 8) |
                (long)out[pos + 12];
            break;
        }
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    g_broker_time_s = 0;
    return publishes;
}

/* [MQTT-3.3.2-5] A queued copy whose Message Expiry Interval passed before
 * onward delivery started is deleted, not delivered. */
TEST(queued_publish_expired_before_delivery_dropped)
{
    long wire_expiry;

    ASSERT_EQ(0, queued_publish_after_wait(11, 10, &wire_expiry));
}

/* [MQTT-3.3.2-6] A queued copy is delivered with the received Message Expiry
 * Interval minus the time it waited in the Server. */
TEST(queued_publish_expiry_reduced_by_wait)
{
    long wire_expiry;

    ASSERT_EQ(1, queued_publish_after_wait(4, 10, &wire_expiry));
    ASSERT_EQ(6, wire_expiry);
}

/* MQTT 5.0 section 3.3.2.3.3: an explicit Message Expiry Interval of 0 is
 * not "no expiry". A copy still queued once a second has passed is deleted;
 * one whose delivery starts within the same second goes out with 0. */
TEST(queued_publish_zero_expiry_dropped)
{
    long wire_expiry;

    ASSERT_EQ(0, queued_publish_after_wait(1, 0, &wire_expiry));
    ASSERT_EQ(1, queued_publish_after_wait(0, 0, &wire_expiry));
    ASSERT_EQ(0, wire_expiry);
}
#endif /* !WOLFMQTT_STATIC_MEMORY && WOLFMQTT_V5 */

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

#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL) && \
    !defined(WOLFMQTT_STATIC_MEMORY) && WOLFMQTT_MAX_QOS >= 1
/* The old client subscribes at QoS 1 to its own QoS 1 Will topic and is
 * taken over with Will Delay 0. The copy for the old connection is queued
 * rather than written, so the old connection ends with its DISCONNECT 0x8E
 * [MQTT-3.14.4-1]. A resumed Session delivers it once on the new connection
 * [MQTT-4.4.0-1]; a Clean Start ends the Session and frees it. Returns the
 * PUBLISH count on the new connection, or -1 on a setup or leak failure, and
 * sets *first_byte to the first PUBLISH's fixed header byte. */
static int takeover_qos1_self_will(int new_clean_start, byte* first_byte)
{
    MqttBroker broker;
    MqttBrokerNet net;
    PublishInfo info;
    size_t before;
    int publishes_before;
    int live_before;
    int publishes;
    int i;
    /* v5 CONNECT for "P": Will Flag, Will QoS 1, Clean Start 0, Properties
     * length 5 holding Session Expiry Interval 300 (0x11), Will Properties
     * length 0, Will Topic "lwt", Will Payload "bye". Remaining Length 30. */
    static const byte old_connect[] = {
        0x10, 0x1E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x0C, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'P',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 SUBSCRIBE packet id 1, Properties length 0, filter "lwt", QoS 1 */
    static const byte old_subscribe[] = {
        0x82, 0x09, 0x00, 0x01, 0x00, 0x00, 0x03, 'l', 'w', 't', 0x01
    };
    /* v5 CONNECT for "P", Clean Start 0, Session Expiry Interval 300 */
    static const byte resume_connect[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'P'
    };
    /* v5 CONNECT for "P", Clean Start 1, no properties */
    static const byte clean_connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };

    *first_byte = 0;
    live_before = g_alloc_success_count - g_alloc_free_count;
    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    reset_mock_clients(2);
    mock_client_input_append(0, old_connect, sizeof(old_connect));
    mock_client_input_append(0, old_subscribe, sizeof(old_subscribe));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    before = g_clients[0].out_len;
    publishes_before = g_clients[0].publish_writes;
    if (new_clean_start) {
        mock_client_input_append(1, clean_connect, sizeof(clean_connect));
    }
    else {
        mock_client_input_append(1, resume_connect, sizeof(resume_connect));
    }
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* MQTT 5.0 section 3.14: the old connection's output after its SUBACK
     * is one DISCONNECT (0xE0) carrying Reason Code 0x8E and nothing else. */
    if (!g_clients[0].closed ||
            g_clients[0].publish_writes != publishes_before ||
            g_clients[0].out_len < before + 3 ||
            g_clients[0].out_buf[before] != 0xE0 ||
            g_clients[0].out_buf[before + 2] !=
                MQTT_REASON_SESSION_TAKEN_OVER ||
            g_clients[0].out_len !=
                before + 2 + g_clients[0].out_buf[before + 1]) {
        publishes = -1;
    }
    else {
        publishes = count_packets_of_type(g_clients[1].out_buf,
            g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH);
        info = first_publish_info(g_clients[1].out_buf, g_clients[1].out_len);
        if (info.found) {
            *first_byte = info.first_byte;
            if (info.packet_id == 0) {
                publishes = -1;
            }
        }
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    if (g_alloc_success_count - g_alloc_free_count != live_before) {
        publishes = -1;
    }
    return publishes;
}

TEST(takeover_v5_resumed_session_gets_queued_self_will)
{
    byte first_byte;

    /* MQTT 5.0 section 3.3.1: QoS 1, DUP 0, RETAIN 0 */
    ASSERT_EQ(1, takeover_qos1_self_will(0, &first_byte));
    ASSERT_EQ(0x32, first_byte);
}

TEST(takeover_v5_clean_start_frees_queued_self_will)
{
    byte first_byte;

    ASSERT_EQ(0, takeover_qos1_self_will(1, &first_byte));
}
#endif

#if !defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_V5)
/* v5 PUBLISH QoS 1 on "x" with Message Expiry Interval 10 (MQTT 5.0
 * section 3.3.2.3.3), packet id `pid`, payload "hi". Remaining Length 13. */
static void expiry_publish_frame(byte* out, byte pid)
{
    static const byte frame[] = {
        0x32, 0x0D,
        0x00, 0x01, 'x',
        0x00, 0x01,
        0x05, 0x02, 0x00, 0x00, 0x00, 0x0A,
        'h', 'i'
    };
    XMEMCPY(out, frame, sizeof(frame));
    out[6] = pid;
}

/* A connected v5 subscriber with Receive Maximum 1 holds one message in
 * flight; a second queued behind it expires before the window opens again,
 * so after the PUBACK it is deleted instead of delivered [MQTT-3.3.2-5]. */
TEST(queued_publish_expired_behind_inflight_cap_dropped)
{
    MqttBroker broker;
    MqttBrokerNet net;
    PublishInfo first;
    byte publish[15];
    byte puback[4];
    int i;
    /* v5 CONNECT, Clean Start 1, Properties length 3 holding Receive
     * Maximum 1 (0x21), ClientId "R". Remaining Length 17. */
    static const byte connect_sub[] = {
        0x10, 0x11,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x03, 0x21, 0x00, 0x01,
        0x00, 0x01, 'R'
    };
    static const byte subscribe_x[] = {
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'x', 0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    g_broker_time_s = 100;
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    expiry_publish_frame(publish, 1);
    mock_client_input_append(1, publish, sizeof(publish));
    expiry_publish_frame(publish, 2);
    mock_client_input_append(1, publish, sizeof(publish));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    first = first_publish_info(g_clients[0].out_buf, g_clients[0].out_len);
    ASSERT_TRUE(first.found);

    /* The queued copy expires, then the window opens. */
    g_broker_time_s += 11;
    puback[0] = 0x40;
    puback[1] = 0x02;
    puback[2] = (byte)(first.packet_id >> 8);
    puback[3] = (byte)first.packet_id;
    mock_client_input_append(0, puback, sizeof(puback));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    g_broker_time_s = 0;
}

/* [MQTT-4.4.0-1] An unacknowledged QoS 1 PUBLISH is re-sent with DUP set when
 * the Session resumes. It was already delivered once, so its Message Expiry
 * no longer applies: the retransmission goes out even after the interval has
 * passed. */
TEST(inflight_publish_resent_after_expiry)
{
    MqttBroker broker;
    MqttBrokerNet net;
    PublishInfo resent;
    byte publish[15];
    int i;
    /* v5 CONNECT, Clean Start 0, Session Expiry Interval 300, ClientId "S" */
    static const byte connect_sub[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'x', 0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    g_broker_time_s = 100;
    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    expiry_publish_frame(publish, 1);
    mock_client_input_append(1, publish, sizeof(publish));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    /* Delivered once, left unacknowledged, then the subscriber leaves. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    g_broker_time_s += 11;
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    resent = first_publish_info(g_clients[2].out_buf, g_clients[2].out_len);
    ASSERT_TRUE(resent.found);
    ASSERT_NE(0, resent.first_byte & 0x08); /* DUP */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    g_broker_time_s = 0;
}

#ifdef WOLFMQTT_BROKER_PERSIST
static int g_expiry_outq_dels;

static int expiry_kv_put(void* ctx, byte ns, const byte* key, word16 key_len,
    const byte* blob, word32 blob_len)
{
    (void)ctx; (void)ns; (void)key; (void)key_len; (void)blob;
    (void)blob_len;
    return MQTT_CODE_SUCCESS;
}

static int expiry_kv_get(void* ctx, byte ns, const byte* key, word16 key_len,
    byte* out, word32* inout_len)
{
    (void)ctx; (void)ns; (void)key; (void)key_len; (void)out;
    (void)inout_len;
    return MQTT_CODE_ERROR_NOT_FOUND;
}

static int expiry_kv_del(void* ctx, byte ns, const byte* key, word16 key_len)
{
    (void)ctx; (void)key; (void)key_len;
    if (ns == BROKER_PERSIST_NS_OUTQ) {
        g_expiry_outq_dels++;
    }
    return MQTT_CODE_SUCCESS;
}

static int expiry_kv_iter(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
    void* cb_ctx)
{
    (void)ctx; (void)ns; (void)cb; (void)cb_ctx;
    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
static int expiry_derive_key(void* ctx, byte* out_key, word32 key_len)
{
    (void)ctx;
    XMEMSET(out_key, 0x11, key_len);
    return MQTT_CODE_SUCCESS;
}
#endif

/* Queue a QoS 1 copy with Message Expiry 10 for an offline persistent
 * subscriber, let wait_sec pass and resume the Session. Returns the number
 * of OUTQ records the broker deleted. */
static int expiry_outq_dels_after_wait(int wait_sec)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    byte publish[15];
    int i;
    static const byte connect_sub[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'x', 0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    hooks.kv_put = expiry_kv_put;
    hooks.kv_get = expiry_kv_get;
    hooks.kv_del = expiry_kv_del;
    hooks.kv_iter = expiry_kv_iter;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = expiry_derive_key;
#endif
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_SetPersistHooks(&broker, &hooks) !=
                MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    g_broker_time_s = 100;
    reset_mock_clients(3);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    expiry_publish_frame(publish, 1);
    mock_client_input_append(1, publish, sizeof(publish));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    g_broker_time_s += wait_sec;
    g_expiry_outq_dels = 0;
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    g_broker_time_s = 0;
    return g_expiry_outq_dels;
}

/* An expired queued copy is deleted from the persistent store too, so a
 * restart cannot replay it [MQTT-3.3.2-5]. Measured against the same flow
 * where the copy has not expired and is only delivered. */
TEST(queued_publish_expired_deletes_persisted_record)
{
    int expired_dels = expiry_outq_dels_after_wait(11);
    int live_dels = expiry_outq_dels_after_wait(4);

    ASSERT_TRUE(expired_dels >= 0);
    ASSERT_TRUE(live_dels >= 0);
    ASSERT_TRUE(expired_dels > live_dels);
}
#endif /* WOLFMQTT_BROKER_PERSIST */
#endif /* !WOLFMQTT_STATIC_MEMORY && WOLFMQTT_V5 */


#ifdef WOLFMQTT_STATIC_MEMORY
/* Reads the broker's outbound in-flight table directly; the library helper
 * has internal linkage. */
static int static_out_id_in_use(const BrokerClient* bc, word16 packet_id)
{
    int i;

    for (i = 0; i < BROKER_MAX_INFLIGHT_PER_SUB; i++) {
        if (bc->out_inflight[i].packet_id == packet_id) {
            return 1;
        }
    }
    return 0;
}

/* Static-memory counterpart of find_broker_client: clients live in a fixed
 * array rather than a list. */
static BrokerClient* find_static_broker_client(MqttBroker* broker,
    const char* id)
{
    int i;

    for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
        if (broker->clients[i].in_use &&
                XSTRCMP(broker->clients[i].client_id, id) == 0) {
            return &broker->clients[i];
        }
    }
    return NULL;
}

#ifdef WOLFMQTT_V5
/* A CONNECT refused because the static persistent-Session quota is full gets a
 * CONNACK with Reason Code 0x97 and no properties: in particular no Assigned
 * Client Identifier the refused client could never use (MQTT 5.0 section
 * 3.2.2.3.7 applies to an accepted connection). */
TEST(static_quota_refusal_connack_has_no_properties)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* v5 CONNECT: Clean Start, keep alive 60, properties: Session Expiry
     * Interval (0x11) = 60, empty ClientId. Remaining Length 18. */
    static const byte connect[] = {
        0x10, 0x12,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Every persistent-Session slot holds an unexpired Session. */
    for (i = 0; i < BROKER_MAX_STATIC_ORPHAN_SESSIONS; i++) {
        broker.static_orphans[i].in_use = 1;
        XSNPRINTF(broker.static_orphans[i].client_id,
            sizeof(broker.static_orphans[i].client_id), "q%d", i);
        broker.static_orphans[i].protocol_level =
            MQTT_CONNECT_PROTOCOL_LEVEL_5;
        broker.static_orphans[i].session_expiry_sec = 3600;
        broker.static_orphans[i].orphan_since = g_broker_time_s;
    }

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    /* CONNACK: Remaining Length 3 = flags, Reason Code, Property Length 0. */
    ASSERT_TRUE(g_out_len >= 5);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x03, g_out_buf[1]);
    ASSERT_EQ(MQTT_REASON_QUOTA_EXCEEDED, g_out_buf[3]);
    ASSERT_EQ(0x00, g_out_buf[4]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */

/* [MQTT-2.3.1-4] holds a Server sending a QoS > 0 PUBLISH to the same
 * identifier rule as a Client: the value stays in use until the matching
 * PUBACK is processed [MQTT-2.3.1-3]. The static-memory fan-out has no
 * per-subscriber queue to derive that from, so it keeps its own in-flight
 * table. Two deliveries with no PUBACK in between must not share an id, and
 * the id must come back once the subscriber acknowledges it. */
TEST(static_fanout_does_not_reuse_unacked_packet_id)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    word16 first_id;
    word16 second_id;
    size_t before;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* Subscribe to "x" at QoS 1 so the fan-out carries a Packet Identifier. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    /* Hand-built MQTT v3.1.1 QoS 1 PUBLISH: Packet Identifier 7, topic "x",
     * payload "A"; built from section 3.3, independent of the encoder. */
    static const byte publish_x[] = {
        0x32, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'A'
    };
    PublishInfo info;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_static_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* First delivery, left unacknowledged. */
    before = g_clients[1].out_len;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    info = first_publish_info(g_clients[1].out_buf + before,
        g_clients[1].out_len - before);
    ASSERT_TRUE(info.found);
    first_id = info.packet_id;
    ASSERT_TRUE(first_id != 0);
    ASSERT_TRUE(static_out_id_in_use(sub_bc, first_id));

    /* Second delivery while the first is still outstanding. */
    before = g_clients[1].out_len;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    info = first_publish_info(g_clients[1].out_buf + before,
        g_clients[1].out_len - before);
    ASSERT_TRUE(info.found);
    second_id = info.packet_id;
    ASSERT_TRUE(second_id != 0);
    ASSERT_TRUE(second_id != first_id);

    /* The subscriber acknowledges the first: that id becomes reusable. */
    {
        byte puback[4];
        puback[0] = 0x40;
        puback[1] = 0x02;
        puback[2] = (byte)(first_id >> 8);
        puback[3] = (byte)(first_id & 0xFF);
        mock_client_input_append(1, puback, sizeof(puback));
    }
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_FALSE(static_out_id_in_use(sub_bc, first_id));
    ASSERT_TRUE(static_out_id_in_use(sub_bc, second_id));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Bring up a publisher on slot 0 and a QoS-`sub_qos` subscriber "S" on slot 1,
 * both subscribed to topic "x". Returns the subscriber's BrokerClient. */
static BrokerClient* static_setup_pub_sub(MqttBroker* broker,
    MqttBrokerNet* net, byte proto_level, byte sub_qos)
{
    int i;
    /* v3.1.1 CONNECT: remain 13 = 6 name + 1 level + 1 flags + 2 keepalive
     * + 2+1 ClientId. */
    byte connect_v4[15] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* v5 CONNECT: the variable header gains a Properties Length byte, so
     * remain is 14 [MQTT-3.1.2.11]. */
    byte connect_v5[16] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };
    /* v3.1.1 SUBSCRIBE: packet id + one filter "x" + options. */
    byte subscribe_v4[8] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x00
    };
    /* v5 SUBSCRIBE adds a Properties Length byte [MQTT-3.8.2.1]. */
    byte subscribe_v5[9] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'x',
        0x00
    };
    byte* connect_pub;
    byte* connect_sub;
    byte* subscribe_x;
    int connect_len;
    int subscribe_len;

    if (proto_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        connect_pub = connect_v5;
        connect_len = (int)sizeof(connect_v5);
        subscribe_x = subscribe_v5;
        subscribe_len = (int)sizeof(subscribe_v5);
    }
    else {
        connect_pub = connect_v4;
        connect_len = (int)sizeof(connect_v4);
        subscribe_x = subscribe_v4;
        subscribe_len = (int)sizeof(subscribe_v4);
    }
    subscribe_x[subscribe_len - 1] = sub_qos;

    install_mock_net(net);
    XMEMSET(broker, 0, sizeof(*broker));
    if (MqttBroker_Init(broker, net) != MQTT_CODE_SUCCESS) {
        return NULL;
    }
    if (MqttBroker_Start(broker) != MQTT_CODE_SUCCESS) {
        return NULL;
    }

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, (size_t)connect_len);
    /* Same packet with ClientId "S" for the subscriber. */
    connect_sub = connect_pub;
    connect_sub[connect_len - 1] = 'S';
    mock_client_input_append(1, connect_sub, (size_t)connect_len);
    connect_sub[connect_len - 1] = 'P';
    mock_client_input_append(1, subscribe_x, (size_t)subscribe_len);
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(broker);
    }
    return find_static_broker_client(broker, "S");
}

/* Count the identifiers the subscriber is currently waiting on. */
static int static_out_id_count(const BrokerClient* bc)
{
    int i;
    int n = 0;

    for (i = 0; i < BROKER_MAX_INFLIGHT_PER_SUB; i++) {
        if (bc->out_inflight[i].packet_id != 0) {
            n++;
        }
    }
    return n;
}

/* A retained PUBLISH the broker encoded but could not write is over: no PUBACK
 * will ever arrive for it, and unlike the live fan-out this path leaves the
 * subscriber connected, so the identifier must be given back rather than held
 * for the life of the connection [MQTT-2.3.1-3]. */
TEST(static_retained_releases_packet_id_on_write_failure)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* Retained QoS 1 PUBLISH (RETAIN bit set), packet id 7, topic "x". */
    static const byte publish_retained[] = {
        0x33, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'A'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    /* Store the retained message before anyone subscribes, so it is delivered
     * from the retained store rather than by live fan-out. */
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_retained, sizeof(publish_retained));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }

    /* Now subscribe, failing only the retained delivery itself: the SUBACK
     * that precedes it still goes out. */
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    g_clients[1].write_err_on_publish = 1;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }

    sub_bc = find_static_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    /* The write failed, so nothing can acknowledge it: no slot may be held. */
    ASSERT_EQ(0, static_out_id_count(sub_bc));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-2.3.1-4] With every identifier outstanding the broker has none left
 * to assign, so the delivery is skipped rather than reusing one the subscriber
 * has not acknowledged. */
TEST(static_fanout_drops_delivery_when_ids_exhausted)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    int i;
    int n;
    size_t before;
    PublishInfo info;
    static const byte publish_x[] = {
        0x32, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'A'
    };

    sub_bc = static_setup_pub_sub(&broker, &net,
        MQTT_CONNECT_PROTOCOL_LEVEL_4, 0x01);
    ASSERT_NOT_NULL(sub_bc);

    /* Fill every slot, acknowledging none. */
    for (n = 0; n < BROKER_MAX_INFLIGHT_PER_SUB; n++) {
        mock_client_input_append(0, publish_x, sizeof(publish_x));
        for (i = 0; i < 8; i++) {
            (void)MqttBroker_Step(&broker);
        }
    }
    ASSERT_EQ(BROKER_MAX_INFLIGHT_PER_SUB, static_out_id_count(sub_bc));

    /* One more: nothing may reach the subscriber. */
    before = g_clients[1].out_len;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    info = first_publish_info(g_clients[1].out_buf + before,
        g_clients[1].out_len - before);
    ASSERT_FALSE(info.found);
    ASSERT_EQ(BROKER_MAX_INFLIGHT_PER_SUB, static_out_id_count(sub_bc));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 2
/* [MQTT-4.3.3] A v5 subscriber rejecting a QoS 2 delivery at the PUBREC stage
 * ends the exchange: no PUBREL, no PUBCOMP. Nothing else will release the
 * identifier, so the broker must release it there or the subscriber runs out
 * of them for the life of the connection. */
TEST(static_fanout_releases_packet_id_on_v5_pubrec_reject)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    int i;
    word16 id;
    size_t before;
    PublishInfo info;
    byte pubrec[6];
    /* v5 QoS 2 PUBLISH, packet id 9, topic "x", payload "A". The variable
     * header carries a Properties Length byte [MQTT-3.3.2.2]. */
    static const byte publish_x[] = {
        0x34, 0x07,
        0x00, 0x01, 'x',
        0x00, 0x09,
        0x00,
        'A'
    };

    sub_bc = static_setup_pub_sub(&broker, &net,
        MQTT_CONNECT_PROTOCOL_LEVEL_5, 0x02);
    ASSERT_NOT_NULL(sub_bc);

    before = g_clients[1].out_len;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    info = first_publish_info(g_clients[1].out_buf + before,
        g_clients[1].out_len - before);
    ASSERT_TRUE(info.found);
    id = info.packet_id;
    ASSERT_TRUE(id != 0);
    ASSERT_TRUE(static_out_id_in_use(sub_bc, id));

    /* v5 PUBREC with reason 0x87 (Not authorized). */
    pubrec[0] = 0x50;
    pubrec[1] = 0x03;
    pubrec[2] = (byte)(id >> 8);
    pubrec[3] = (byte)(id & 0xFF);
    pubrec[4] = 0x87;
    mock_client_input_append(1, pubrec, 5);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }

    ASSERT_FALSE(static_out_id_in_use(sub_bc, id));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 && WOLFMQTT_MAX_QOS >= 2 */

#endif /* WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* Find the orphan session carrying a disconnected client's Session state. The
 * BrokerClient itself is freed by the close, so anything a test wants to check
 * about the preserved queue must be read from here. */
static BrokerOrphanSession* find_orphan_session(MqttBroker* broker,
    const char* id)
{
    BrokerOrphanSession* o = broker->orphan_sessions;

    while (o != NULL) {
        if (o->client_id != NULL && XSTRCMP(o->client_id, id) == 0) {
            return o;
        }
        o = o->next;
    }
    return NULL;
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* When the broker cannot queue a QoS 1/2 delivery for a matching subscriber,
 * it must not acknowledge the PUBLISH as successful (MQTT 3.1.1 section 4.3.2:
 * PUBACK transfers ownership of the message). v3.1.1 has no failure ack, so
 * the publisher is disconnected without a PUBACK. */
TEST(publish_fanout_alloc_failure_v311_not_acked)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    size_t pub_mark;
    size_t sub_mark;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id 1, filter "x", QoS 1. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    /* PUBLISH QoS 1, topic "x", packet_id 7, payload "p". */
    static const byte publish_x[] = {
        0x32, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    g_clients_active = 2;
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    pub_mark = g_clients[0].out_len;
    sub_mark = g_clients[1].out_len;

    /* The topic copy succeeds; the subscriber's queued copy does not. */
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    broker_test_fail_alloc_after(1);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_EQ((int)sub_mark, (int)g_clients[1].out_len);
    ASSERT_EQ(0, count_packets_of_type(g_clients[0].out_buf + pub_mark,
        g_clients[0].out_len - pub_mark, MQTT_PACKET_TYPE_PUBLISH_ACK));
    ASSERT_TRUE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* The same holds when the subscriber is offline: its QoS 1/2 copy is queued
 * on the orphaned Session, and failing to allocate that copy must not be
 * acknowledged as a successful publish either. */
TEST(publish_offline_fanout_alloc_failure_v311_not_acked)
{
    MqttBroker broker;
    MqttBrokerNet net;
    size_t pub_mark;
    int i;
    /* Subscriber "S" with CleanSession 0 so its Session outlives it. */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id 1, filter "x", QoS 1. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* PUBLISH QoS 1, topic "x", packet_id 7, payload "p". */
    static const byte publish_x[] = {
        0x32, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'p'
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
        (void)MqttBroker_Step(&broker);
        if (g_clients[0].closed) {
            break;
        }
    }
    ASSERT_TRUE(g_clients[0].closed);
    ASSERT_EQ(1, broker.orphan_session_count);

    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    pub_mark = g_clients[1].out_len;

    /* The topic copy succeeds; the offline subscriber's queued copy does
     * not. */
    mock_client_input_append(1, publish_x, sizeof(publish_x));
    broker_test_fail_alloc_after(1);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_EQ(0, count_packets_of_type(g_clients[1].out_buf + pub_mark,
        g_clients[1].out_len - pub_mark, MQTT_PACKET_TYPE_PUBLISH_ACK));
    ASSERT_TRUE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_V5
/* A v5 publisher is told with a failure Reason Code instead (MQTT 5.0
 * section 3.5.2.1). A PUBREC with a Reason Code of 0x80 or greater ends the
 * QoS 2 exchange (section 4.3.3), so the Packet Identifier must not stay
 * marked as awaiting PUBREL: a later PUBLISH reusing it is a new message. */
TEST(publish_fanout_alloc_failure_v5_qos2_pubrec_failure)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    size_t pub_mark;
    size_t sub_mark;
    int i;
    /* v5 CONNECT, clean=1, props_len=0, ClientId "P". Remaining Length 14. */
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id 1, filter "x", QoS 2. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x02
    };
    /* v5 PUBLISH QoS 2, topic "x", packet_id 7, props_len 0, payload "p".
     * Remaining Length 7. */
    static const byte publish_x[] = {
        0x34, 0x07,
        0x00, 0x01, 'x',
        0x00, 0x07,
        0x00,
        'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    g_clients_active = 2;
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    pub_mark = g_clients[0].out_len;
    sub_mark = g_clients[1].out_len;

    /* The v5 PUBLISH makes one more allocation than v3.1.1 before the
     * topic copy; fail the subscriber's queued copy after both. */
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    broker_test_fail_alloc_after(2);
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_EQ((int)sub_mark, (int)g_clients[1].out_len);
    ASSERT_FALSE(g_clients[0].closed);
    /* PUBREC: type 5, Remaining Length >= 3, packet_id 7, Reason 0x80. */
    ASSERT_TRUE(g_clients[0].out_len >= pub_mark + 5);
    ASSERT_EQ(0x50, g_clients[0].out_buf[pub_mark]);
    ASSERT_EQ(0x07, g_clients[0].out_buf[pub_mark + 3]);
    ASSERT_EQ(MQTT_REASON_UNSPECIFIED_ERR, g_clients[0].out_buf[pub_mark + 4]);

    /* Reusing packet_id 7 delivers a new message rather than being treated
     * as a retransmission of the refused one. */
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf + sub_mark,
        g_clients[1].out_len - sub_mark, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */
#endif /* !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* A PUBACK belongs only to a QoS 1 exchange (MQTT 3.1.1 section 4.3.2). A
 * subscriber that answers a QoS 2 delivery with PUBACK must not complete it:
 * the entry keeps its packet identifier and inflight slot until the real
 * PUBREC/PUBCOMP exchange (section 4.3.3) finishes. */
TEST(outbound_qos2_puback_does_not_complete_delivery)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOutPub* e;
    word16 pid;
    int inflight;
    int i;
    byte ack[4];
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id 1, filter "x", QoS 2. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x02
    };
    /* PUBLISH QoS 2, topic "x", packet_id 7, payload "p". */
    static const byte publish_x[] = {
        0x34, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    g_clients_active = 2;
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    mock_client_input_append(0, publish_x, sizeof(publish_x));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    e = sub_bc->out_q_head;
    ASSERT_NOT_NULL(e);
    ASSERT_EQ(MQTT_QOS_2, e->qos);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT, e->state);
    pid = e->packet_id;
    inflight = sub_bc->out_q_inflight;

    /* PUBACK: type 4, remain 2, packet_id of the QoS 2 delivery. */
    ack[0] = 0x40;
    ack[1] = 0x02;
    ack[2] = (byte)(pid >> 8);
    ack[3] = (byte)(pid & 0xFF);
    mock_client_input_append(1, ack, sizeof(ack));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(sub_bc->out_q_head == e);
    ASSERT_EQ(pid, e->packet_id);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT, e->state);
    ASSERT_EQ(inflight, sub_bc->out_q_inflight);

    /* The real PUBREC still drives the exchange forward with a PUBREL. */
    ack[0] = 0x50;
    mock_client_input_append(1, ack, sizeof(ack));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_OUTQ_PUBREL_SENT, e->state);
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH_REL));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* MQTT 3.1.1 section 2.2.3: Remaining Length counts every byte that follows
 * in the packet. When a queued delivery does not fit the subscriber's
 * transmit buffer, the encoder copies only part of the payload while the
 * fixed header still declares all of it. The drain must drop that entry
 * rather than send a short frame that desynchronizes the subscriber. */
TEST(outbound_publish_exceeding_tx_buf_not_sent_truncated)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    size_t sub_out_mark;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id 1, filter "x", QoS 0. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x00
    };
    /* QoS 0 PUBLISH to "x": Remaining Length 23 = 3 topic bytes + 20
     * payload bytes. Forwarded, it encodes to 25 bytes. */
    static const byte publish_x[] = {
        0x30, 0x17,
        0x00, 0x01, 'x',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    g_clients_active = 2;
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* Subscriber transmit buffer smaller than the forwarded frame, as with a
     * build whose receive buffer exceeds its transmit buffer. */
    sub_bc->tx_buf_len = 16;
    sub_out_mark = g_clients[1].out_len;

    mock_client_input_append(0, publish_x, sizeof(publish_x));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }

    ASSERT_EQ((int)sub_out_mark, (int)g_clients[1].out_len);
    ASSERT_NULL(sub_bc->out_q_head);
    ASSERT_EQ(0, sub_bc->out_q_count);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_V5
/* A QoS 1 or QoS 2 copy that cannot fit a subscriber's transmit buffer is
 * never delivered, so the v5 publisher must not be told the PUBLISH was
 * accepted: its PUBACK or PUBREC carries Reason Code 0x80 (MQTT 5.0 sections
 * 3.4.2.1 and 3.5.2.1). Returns 0 when that holds. */
static int publish_exceeding_sub_tx_buf_not_acked(MqttQoS qos)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    size_t pub_out_mark;
    size_t sub_out_mark;
    int i;
    int result = -1;
    /* v5 CONNECT: Clean Start, keep alive 60, Property Length 0, ClientId
     * "P". Remaining Length 14. */
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet_id 1, filter "x", QoS 2. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x02
    };
    /* v5 PUBLISH to "x", packet id 7, Property Length 0, 20 payload bytes:
     * Remaining Length 26. The QoS bits are set below. Forwarded at the same
     * QoS to a v3.1.1 subscriber, it encodes to 27 bytes. */
    byte publish_x[] = {
        0x30, 0x1A,
        0x00, 0x01, 'x',
        0x00, 0x07,
        0x00,
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };
    publish_x[0] = (byte)(0x30 | ((byte)qos << 1));

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    if (MqttBroker_Init(&broker, &net) != MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&broker) != MQTT_CODE_SUCCESS) {
        return -1;
    }

    reset_mock_clients(3);
    g_clients_active = 2;
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    if (sub_bc != NULL) {
        /* Subscriber transmit buffer smaller than the forwarded frame, as
         * with a build whose receive buffer exceeds its transmit buffer. */
        sub_bc->tx_buf_len = 16;
        pub_out_mark = g_clients[0].out_len;
        sub_out_mark = g_clients[1].out_len;

        mock_client_input_append(0, publish_x, sizeof(publish_x));
        for (i = 0; i < 8; i++) {
            (void)MqttBroker_Step(&broker);
        }

        /* The response's first byte is PUBACK (0x40) or PUBREC (0x50), and
         * its Reason Code follows the 2-byte Packet Identifier. */
        if (g_clients[0].out_len >= pub_out_mark + 5 &&
                g_clients[0].out_buf[pub_out_mark] ==
                    ((qos == MQTT_QOS_1) ? 0x40 : 0x50) &&
                g_clients[0].out_buf[pub_out_mark + 4] ==
                    MQTT_REASON_UNSPECIFIED_ERR &&
                g_clients[1].out_len == sub_out_mark &&
                sub_bc->out_q_count == 0) {
            result = 0;
        }
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
    return result;
}

TEST(publish_qos1_exceeding_sub_tx_buf_not_acked)
{
    ASSERT_EQ(0, publish_exceeding_sub_tx_buf_not_acked(MQTT_QOS_1));
}

#if WOLFMQTT_MAX_QOS >= 2
TEST(publish_qos2_exceeding_sub_tx_buf_not_acked)
{
    ASSERT_EQ(0, publish_exceeding_sub_tx_buf_not_acked(MQTT_QOS_2));
}
#endif
#endif /* WOLFMQTT_V5 */
#endif /* !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
/* A zero-progress would-block result means none of the first transmission has
 * reached the network, so its later retry must still carry DUP=0
 * [MQTT-3.3.1-1]. */
TEST(outbound_zero_progress_retry_keeps_dup_clear)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    PublishInfo info;
    size_t sub_before;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    /* Hand-built MQTT v3.1.1 QoS 1 PUBLISH: Packet Identifier 7, topic "x",
     * payload "ABC"; this fixture is independent of the broker encoder. */
    static const byte publish_x[] = {
        0x32, 0x08,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    sub_before = g_clients[1].out_len;

    g_clients[1].write_continue = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_NOT_NULL(sub_bc->out_q_head);
    ASSERT_TRUE(sub_bc->out_q_pending_len > 0);
    ASSERT_EQ(0, sub_bc->client.write.pos);
    ASSERT_EQ(0, sub_bc->out_q_head->retransmit_dup);
    ASSERT_EQ(sub_before, g_clients[1].out_len);

    g_clients[1].write_continue = 0;
    (void)MqttBroker_Step(&broker);
    info = first_publish_info(g_clients[1].out_buf + sub_before,
        g_clients[1].out_len - sub_before);
    ASSERT_TRUE(info.found);
    ASSERT_EQ(0x32, info.first_byte); /* PUBLISH | QoS 1, DUP = 0 */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MQTT 3.1.1 section 4.3.1: at QoS 0 "no retry is performed by the sender" and
 * the message "arrives at the receiver either once or not at all". A QoS 0
 * fan-out whose write starts and then fails has been attempted, so it must not
 * follow the persistent Session into an orphan and be delivered a second time
 * on reconnect. Section 4.1 makes only QoS 0 messages *pending transmission*
 * optional Session state. */
TEST(outbound_qos0_partial_failure_not_replayed_on_reconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOrphanSession* orphan;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* CleanSession=0 so the Session survives the failed write. */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* Granted QoS 0, so the fan-out to this subscriber is QoS 0. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x00
    };
    /* Hand-built MQTT v3.1.1 QoS 0 PUBLISH: topic "x", payload "ABC". */
    static const byte publish_x[] = {
        0x30, 0x06,
        0x00, 0x01, 'x',
        'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* One byte of the QoS 0 delivery goes out, then the socket errors. */
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_NOT_NULL(sub_bc->out_q_head);
    ASSERT_EQ(MQTT_QOS_0, sub_bc->out_q_head->qos);
    ASSERT_TRUE(sub_bc->client.write.pos > 0);

    /* The failing write closes the client, so sub_bc is freed from here on and
     * the preserved queue must be inspected through the orphan session. */
    g_clients[1].write_err = 1;
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(1, broker.orphan_session_count);

    /* The attempted QoS 0 message did not follow the Session into the orphan;
     * only QoS > 0 state is preserved for replay. */
    orphan = find_orphan_session(&broker, "S");
    ASSERT_NOT_NULL(orphan);
    ASSERT_NULL(orphan->out_q_head);
    ASSERT_EQ(0, orphan->out_q_count);

    /* Reconnect the same persistent Session: only the CONNACK comes back,
     * with no second copy of the QoS 0 PUBLISH. */
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    g_clients_active = 3;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(0, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MQTT_CODE_ERROR_TIMEOUT is not a dead socket: BrokerPosix_Write returns it
 * when select() merely times out, so the drain must not treat it as a reason
 * to discard a partially written QoS 0 entry - that would clear
 * client.write.pos and let the next queued PUBLISH go out behind the truncated
 * prefix. The entry stays queued, and MQTT 3.1.1 section 4.3.1 ("no retry is
 * performed by the sender") is honoured at the orphan hand-off instead: bytes
 * of it are already on the wire, so it must not follow the Session and be
 * delivered a second time after reconnect. */
TEST(outbound_qos0_transient_timeout_not_replayed_on_reconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOrphanSession* orphan;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* CleanSession=0 so the Session survives the close. */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* Granted QoS 0, so the fan-out to this subscriber is QoS 0. */
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x00
    };
    /* Hand-built MQTT v3.1.1 QoS 0 PUBLISH: topic "x", payload "ABC". */
    static const byte publish_x[] = {
        0x30, 0x06,
        0x00, 0x01, 'x',
        'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    g_clients_active = 2;
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* One byte of the QoS 0 delivery goes out, then the write would block. */
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_NOT_NULL(sub_bc->out_q_head);
    ASSERT_EQ(MQTT_QOS_0, sub_bc->out_q_head->qos);
    ASSERT_TRUE(sub_bc->client.write.pos > 0);

    /* The resume reports a transient timeout. The broker's main loop still
     * tears the connection down on a negative drain result, so the Session
     * becomes an orphan; sub_bc is freed from here on. */
    g_clients[1].write_timeout_pending = 1;
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(1, broker.orphan_session_count);

    /* The half-sent QoS 0 message did not follow the Session. */
    orphan = find_orphan_session(&broker, "S");
    ASSERT_NOT_NULL(orphan);
    ASSERT_NULL(orphan->out_q_head);
    ASSERT_EQ(0, orphan->out_q_count);

    /* Reconnect the same persistent Session: no second copy of the PUBLISH. */
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    g_clients_active = 3;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(0, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* BrokerClient_DrainOutQueue walks past entries awaiting an acknowledgement, so
 * the partially written entry is the first one still QUEUED - not necessarily
 * out_q_head. With a sent-but-unacked QoS 1 entry ahead of it, a half-written
 * QoS 0 message must still be dropped at the orphan hand-off rather than
 * follow the Session and be delivered a second time (section 4.3.1). */
TEST(outbound_qos0_partial_behind_unacked_qos1_not_replayed)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOrphanSession* orphan;
    BrokerOutPub* e;
    int queued = 0;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* CleanSession=0 so the Session survives the close. */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* Two filters: "q" granted QoS 1, "x" granted QoS 0. */
    static const byte subscribe_q[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'q',
        0x01
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x02,
        0x00, 0x01, 'x',
        0x00
    };
    static const byte publish_q[] = {
        0x32, 0x06,
        0x00, 0x01, 'q',
        0x00, 0x21,
        'Q'
    };
    static const byte publish_x[] = {
        0x30, 0x06,
        0x00, 0x01, 'x',
        'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(3);
    g_clients_active = 2;
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_q, sizeof(subscribe_q));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* QoS 1 delivery goes out in full and stays queued awaiting its PUBACK. */
    mock_client_input_append(0, publish_q, sizeof(publish_q));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_NOT_NULL(sub_bc->out_q_head);
    ASSERT_TRUE(sub_bc->out_q_head->state != BROKER_OUTQ_QUEUED);

    /* QoS 0 delivery behind it gets one byte out, then would block. */
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(sub_bc->client.write.pos > 0);
    /* The unacked QoS 1 entry is still ahead of the partial QoS 0 one. */
    ASSERT_EQ(MQTT_QOS_1, sub_bc->out_q_head->qos);

    /* Tear the connection down through a transient timeout: the drain keeps
     * the entry (a timeout is not a dead socket), so the orphan hand-off is
     * what has to drop it. A hard error would take the drain's own QoS 0 drop
     * branch instead and never exercise this path. */
    g_clients[1].write_timeout_pending = 1;
    for (i = 0; i < 6; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);

    orphan = find_orphan_session(&broker, "S");
    ASSERT_NOT_NULL(orphan);
    /* The QoS 1 entry is Session state and stays; the half-sent QoS 0 one
     * must not be there. */
    for (e = orphan->out_q_head; e != NULL; e = e->next) {
        queued++;
        ASSERT_TRUE(e->qos != MQTT_QOS_0);
    }
    ASSERT_EQ(1, queued);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}


/* MQTT 3.1.1 section 4.3.1: a partly transmitted QoS 0 publication does
 * not follow a surviving Session onto a replacement connection. */
TEST(takeover_drops_partial_qos0_after_unacked_qos1)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* old;
    BrokerClient* resumed;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte subscribe_q[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'q', 0x01
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x02, 0x00, 0x01, 'x', 0x00
    };
    static const byte publish_q[] = {
        0x32, 0x06, 0x00, 0x01, 'q', 0x00, 0x21, 'Q'
    };
    static const byte publish_x[] = {
        0x30, 0x06, 0x00, 0x01, 'x', 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_q, sizeof(subscribe_q));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    old = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(old);

    mock_client_input_append(0, publish_q, sizeof(publish_q));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_NOT_NULL(old->out_q_head);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT, old->out_q_head->state);
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(old->client.write.pos > 0);
    ASSERT_EQ(2, old->out_q_count);
    ASSERT_EQ(MQTT_QOS_0, old->out_q_tail->qos);

    g_clients[1].write_continue = 1;
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    g_clients_active = 3;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    resumed = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(resumed);
    ASSERT_EQ(1, resumed->out_q_count);
    ASSERT_EQ(MQTT_QOS_1, resumed->out_q_head->qos);
    ASSERT_EQ(1, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A partial direct PINGRESP does not mark an unrelated queued QoS 0
 * PUBLISH as sent. MQTT 3.1.1 section 4.1 permits the pending message
 * to follow the surviving Session. */
TEST(takeover_keeps_qos0_behind_partial_direct_write)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* old;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x00
    };
    static const byte publish_x[] = {
        0x30, 0x06, 0x00, 0x01, 'x', 'A', 'B', 'C'
    };
    static const byte ping_req[] = { 0xC0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    old = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(old);

    g_clients[1].write_limit_once = 1;
    mock_client_input_append(1, ping_req, sizeof(ping_req));
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(1, old->out_q_count);
    ASSERT_EQ(MQTT_QOS_0, old->out_q_head->qos);
    ASSERT_EQ(0, old->out_q_head->partial_send);
    ASSERT_TRUE(old->client.write.pos > 0);
    ASSERT_EQ((int)sizeof(ping_req), old->direct_pending_len);

    g_clients[1].write_continue = 1;
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    g_clients_active = 3;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A QoS 1 PUBLISH whose transport write starts but fails before completion has
 * still been attempted. If the persistent Session reconnects, the broker must
 * re-deliver it with DUP=1 and the same Packet Identifier [MQTT-3.3.1-1]. */
TEST(outbound_partial_failure_reconnect_sets_dup)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    PublishInfo info;
    word16 packet_id;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    /* Hand-built MQTT v3.1.1 QoS 1 PUBLISH: Packet Identifier 7, topic "x",
     * payload "ABC"; this is independent of the encoder under test. */
    static const byte publish_x[] = {
        0x32, 0x08,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* Accept one byte of the queued delivery, then fail its continuation. */
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(sub_bc->out_q_pending_len > 0);
    ASSERT_NOT_NULL(sub_bc->out_q_head);
    ASSERT_EQ(1, sub_bc->out_q_head->retransmit_dup);
    packet_id = sub_bc->out_q_head->packet_id;
    ASSERT_TRUE(packet_id != 0);

    g_clients[1].write_err = 1;
    (void)MqttBroker_Step(&broker);
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(1, broker.orphan_session_count);

    /* Reconnect the same persistent Session and inspect its replayed PUBLISH. */
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    g_clients_active = 3;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    info = first_publish_info(g_clients[2].out_buf, g_clients[2].out_len);
    ASSERT_TRUE(info.found);
    ASSERT_EQ(0x3A, info.first_byte); /* PUBLISH | DUP | QoS 1 */
    ASSERT_EQ(packet_id, info.packet_id);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK && !WOLFMQTT_STATIC_MEMORY */

#if !defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
/* Blocking-transport counterpart of outbound_partial_failure_reconnect_sets_dup.
 * MqttSocket_Write loops until the packet is out or the transport errors, so a
 * transport that accepts some bytes and then fails does both inside one
 * MqttPacket_Write call - there is no MQTT_CODE_CONTINUE step to mark the
 * entry with. Those bytes still reached the subscriber, so the replay after
 * session recovery is a re-delivery and [MQTT-3.3.1-1] requires DUP=1. */
TEST(outbound_blocking_partial_failure_reconnect_sets_dup)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    BrokerOrphanSession* orphan;
    PublishInfo info;
    word16 packet_id;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* CleanSession=0 so the Session survives the failed write. */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    /* Hand-built MQTT v3.1.1 QoS 1 PUBLISH: Packet Identifier 7, topic "x",
     * payload "ABC"; this is independent of the encoder under test. */
    static const byte publish_x[] = {
        0x32, 0x08,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* One byte of the queued delivery goes out, then the socket errors -
     * both within the single blocking write. That failure closes the client,
     * so sub_bc is freed and the entry must be inspected via the orphan. */
    g_clients[1].write_limit_then_err = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);

    /* The fan-out drain discards its result, so the close lands on a later
     * step. It frees sub_bc, hence the orphan lookup below. */
    g_clients[1].write_err = 1;
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(1, broker.orphan_session_count);

    orphan = find_orphan_session(&broker, "S");
    ASSERT_NOT_NULL(orphan);
    ASSERT_NOT_NULL(orphan->out_q_head);
    ASSERT_EQ(1, orphan->out_q_head->retransmit_dup);
    packet_id = orphan->out_q_head->packet_id;
    ASSERT_TRUE(packet_id != 0);

    /* Reconnect the same persistent Session and inspect its replayed PUBLISH. */
    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    g_clients_active = 3;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    info = first_publish_info(g_clients[2].out_buf, g_clients[2].out_len);
    ASSERT_TRUE(info.found);
    ASSERT_EQ(0x3A, info.first_byte); /* PUBLISH | DUP | QoS 1 */
    ASSERT_EQ(packet_id, info.packet_id);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_NONBLOCK && !WOLFMQTT_STATIC_MEMORY */

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

#ifndef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_BROKER_PERSIST
static int takeover_setup_persist(MqttBroker* broker,
    MqttBrokerPersistHooks* hooks);
static int kv_outq_count(void);
#endif

/* [MQTT-4.4.0-1] A resumed Session retains pending and unacknowledged
 * QoS 1 deliveries, including their Packet Identifiers. */
static void takeover_resumes_outbound_qos1_queue(int persist)
{
    MqttBroker broker;
    MqttBrokerNet net;
#ifdef WOLFMQTT_BROKER_PERSIST
    MqttBrokerPersistHooks hooks;
#endif
    BrokerClient* old;
    BrokerClient* resumed;
    PublishInfo info;
    word16 first_id;
    word16 second_id;
    byte puback[] = { 0x40, 0x02, 0x00, 0x00 };
    int old_idx = 0;
    int resume_idx = 2;
    int i;
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    /* MQTT 3.1.1 section 3.3: QoS 1 PUBLISH, topic x, id 7, payload A. */
    static const byte publish_a[] = {
        0x32, 0x06, 0x00, 0x01, 'x', 0x00, 0x07, 'A'
    };
    static const byte publish_b[] = {
        0x32, 0x06, 0x00, 0x01, 'x', 0x00, 0x08, 'B'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));
    }
#else
    (void)persist;
#endif
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    old = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(old);
    old->client_receive_max = 1;

    mock_client_input_append(1, publish_a, sizeof(publish_a));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    mock_client_input_append(1, publish_b, sizeof(publish_b));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(2, old->out_q_count);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT, old->out_q_head->state);
    ASSERT_EQ(BROKER_OUTQ_QUEUED, old->out_q_tail->state);
    first_id = old->out_q_head->packet_id;
    second_id = old->out_q_tail->packet_id;
    ASSERT_NE(0, first_id);
    ASSERT_NE(first_id, second_id);
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        /* Disconnect and reclaim first so the live Session carries records
         * previously committed by the orphan persistence path. */
        old->connected = 0;
        g_clients[0].read_err = 1;
        for (i = 0; i < 8; i++) {
            (void)MqttBroker_Step(&broker);
        }
        ASSERT_EQ(2, kv_outq_count());
        mock_client_input_append(2, connect_sub, sizeof(connect_sub));
        g_clients_active = 3;
        for (i = 0; i < 16; i++) {
            (void)MqttBroker_Step(&broker);
        }
        ASSERT_EQ(0, broker.orphan_session_count);
        old_idx = 2;
        resume_idx = 3;
    }
#endif

    mock_client_input_append(resume_idx, connect_sub, sizeof(connect_sub));
    g_clients_active = resume_idx + 1;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[old_idx].closed);
    ASSERT_EQ(0x01, g_clients[resume_idx].out_buf[2]);
    resumed = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(resumed);
    ASSERT_EQ(2, resumed->out_q_count);
    ASSERT_EQ(first_id, resumed->out_q_head->packet_id);
    ASSERT_EQ(second_id, resumed->out_q_tail->packet_id);
    info = first_publish_info(g_clients[resume_idx].out_buf,
        g_clients[resume_idx].out_len);
    ASSERT_TRUE(info.found);
    ASSERT_EQ(0x3A, info.first_byte);
    ASSERT_EQ(first_id, info.packet_id);
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        ASSERT_EQ(2, kv_outq_count());
    }
#endif

    puback[2] = (byte)(first_id >> 8);
    puback[3] = (byte)first_id;
    mock_client_input_append(resume_idx, puback, sizeof(puback));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, resumed->out_q_count);
    ASSERT_EQ(second_id, resumed->out_q_head->packet_id);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT, resumed->out_q_head->state);
    ASSERT_EQ(2, count_packets_of_type(g_clients[resume_idx].out_buf,
        g_clients[resume_idx].out_len, MQTT_PACKET_TYPE_PUBLISH));
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        ASSERT_EQ(1, kv_outq_count());
    }
#endif

    puback[2] = (byte)(second_id >> 8);
    puback[3] = (byte)second_id;
    mock_client_input_append(resume_idx, puback, sizeof(puback));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(0, resumed->out_q_count);
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        ASSERT_EQ(0, kv_outq_count());
    }
#endif

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(takeover_resumes_outbound_qos1_queue)
{
    takeover_resumes_outbound_qos1_queue(0);
}

#if WOLFMQTT_MAX_QOS >= 2
/* [MQTT-4.4.0-1] A resumed QoS 2 delivery continues from PUBREL with its
 * original Packet Identifier. */
static void takeover_resumes_outbound_qos2_pubrel(int persist)
{
    MqttBroker broker;
    MqttBrokerNet net;
#ifdef WOLFMQTT_BROKER_PERSIST
    MqttBrokerPersistHooks hooks;
#endif
    BrokerClient* old;
    BrokerClient* resumed;
    word16 packet_id;
    byte pubrec[] = { 0x50, 0x02, 0x00, 0x00 };
    byte pubcomp[] = { 0x70, 0x02, 0x00, 0x00 };
    int old_idx = 0;
    int resume_idx = 2;
    int i;
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x02
    };
    /* MQTT 3.1.1 section 3.3: QoS 2 PUBLISH, topic x, id 7, payload A. */
    static const byte publish_x[] = {
        0x34, 0x06, 0x00, 0x01, 'x', 0x00, 0x07, 'A'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));
    }
#else
    (void)persist;
#endif
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish_x, sizeof(publish_x));
    for (i = 0; i < 24; i++) {
        (void)MqttBroker_Step(&broker);
    }
    old = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(old);
    ASSERT_NOT_NULL(old->out_q_head);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT, old->out_q_head->state);
    packet_id = old->out_q_head->packet_id;
    ASSERT_NE(0, packet_id);

    pubrec[2] = (byte)(packet_id >> 8);
    pubrec[3] = (byte)packet_id;
    mock_client_input_append(0, pubrec, sizeof(pubrec));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(BROKER_OUTQ_PUBREL_SENT, old->out_q_head->state);
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        old->connected = 0;
        g_clients[0].read_err = 1;
        for (i = 0; i < 8; i++) {
            (void)MqttBroker_Step(&broker);
        }
        ASSERT_EQ(1, kv_outq_count());
        mock_client_input_append(2, connect_sub, sizeof(connect_sub));
        g_clients_active = 3;
        for (i = 0; i < 16; i++) {
            (void)MqttBroker_Step(&broker);
        }
        ASSERT_EQ(0, broker.orphan_session_count);
        old_idx = 2;
        resume_idx = 3;
    }
#endif

    mock_client_input_append(resume_idx, connect_sub, sizeof(connect_sub));
    g_clients_active = resume_idx + 1;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    resumed = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(resumed);
    ASSERT_EQ(1, resumed->out_q_count);
    ASSERT_EQ(1, resumed->out_q_inflight);
    ASSERT_EQ(packet_id, resumed->out_q_head->packet_id);
    ASSERT_EQ(BROKER_OUTQ_PUBREL_SENT, resumed->out_q_head->state);
    ASSERT_TRUE(g_clients[old_idx].closed);
    ASSERT_EQ(1, count_packets_of_type(g_clients[resume_idx].out_buf,
        g_clients[resume_idx].out_len, MQTT_PACKET_TYPE_PUBLISH_REL));
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        ASSERT_EQ(1, kv_outq_count());
    }
#endif

    pubcomp[2] = (byte)(packet_id >> 8);
    pubcomp[3] = (byte)packet_id;
    mock_client_input_append(resume_idx, pubcomp, sizeof(pubcomp));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(0, resumed->out_q_count);
    ASSERT_EQ(0, resumed->out_q_inflight);
#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist) {
        ASSERT_EQ(0, kv_outq_count());
    }
#endif

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(takeover_resumes_outbound_qos2_pubrel)
{
    takeover_resumes_outbound_qos2_pubrel(0);
}
#endif /* WOLFMQTT_MAX_QOS >= 2 */

#ifdef WOLFMQTT_V5
#ifdef WOLFMQTT_NONBLOCK
/* MQTT 5.0 section 2.1.1 forbids splicing DISCONNECT into a PUBLISH;
 * [MQTT-4.4.0-1] does not authorize retrying a partial QoS 0 delivery. */
TEST(takeover_v5_partial_qos0_closes_without_splicing)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* old;
    size_t old_len_before;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    /* MQTT 5 CONNECT: Clean Start=0, Session Expiry Interval=60. */
    static const byte connect_sub[] = {
        0x10, 0x13, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C, 0x05,
        0x11, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'x', 0x00
    };
    static const byte publish_x[] = {
        0x30, 0x06, 0x00, 0x01, 'x', 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    old = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(old);
    old_len_before = g_clients[1].out_len;
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(1, old->out_q_count);
    ASSERT_EQ(1, old->out_q_head->partial_send);
    ASSERT_EQ(1, old->client.write.pos);
    ASSERT_EQ(1, g_clients[1].out_len - old_len_before);

    mock_client_input_append(2, connect_sub, sizeof(connect_sub));
    g_clients_active = 3;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(1, g_clients[1].out_len - old_len_before);
    ASSERT_EQ(0x30, g_clients[1].out_buf[old_len_before]);
    ASSERT_EQ(0, count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_EQ(0, find_broker_client(&broker, "S")->out_q_count);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK */

/* MQTT 5.0 section 3.3.2.3 adds Property Length to PUBLISH; the Session's
 * deliveries use the resumed connection's packet format. */
TEST(takeover_outbound_publish_uses_resumed_protocol)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* old;
    word16 packet_id;
    int direction;
    int path;
    int i;
    static const byte connect_v311[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte connect_v5[] = {
        0x10, 0x13, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C, 0x05,
        0x11, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x01, 'S'
    };
    static const byte subscribe_v311[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    static const byte subscribe_v5[] = {
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, 'x', 0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'P'
    };
    static const byte publish_x[] = {
        0x32, 0x06, 0x00, 0x01, 'x', 0x00, 0x07, 'A'
    };
    /* [MQTT-4.4.0-1] Retransmit with DUP and the original Packet ID. */
    byte expected_v311[] = {
        0x3A, 0x06, 0x00, 0x01, 'x', 0x00, 0x00, 'A'
    };
    byte expected_v5[] = {
        0x3A, 0x07, 0x00, 0x01, 'x', 0x00, 0x00, 0x00, 'A'
    };

    for (path = 0; path < 4; path++) {
        const byte* expected;
        size_t expected_len;

        direction = path % 2;

        install_mock_net(&net);
        XMEMSET(&broker, 0, sizeof(broker));
        ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
        ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));
        reset_mock_clients(2);
        if (direction == 0) {
            mock_client_input_append(0, connect_v311,
                sizeof(connect_v311));
            mock_client_input_append(0, subscribe_v311,
                sizeof(subscribe_v311));
        }
        else {
            mock_client_input_append(0, connect_v5, sizeof(connect_v5));
            mock_client_input_append(0, subscribe_v5,
                sizeof(subscribe_v5));
        }
        mock_client_input_append(1, connect_pub, sizeof(connect_pub));
        mock_client_input_append(1, publish_x, sizeof(publish_x));
        for (i = 0; i < 24; i++) {
            (void)MqttBroker_Step(&broker);
        }
        old = find_broker_client(&broker, "S");
        ASSERT_NOT_NULL(old);
        ASSERT_NOT_NULL(old->out_q_head);
        packet_id = old->out_q_head->packet_id;
        ASSERT_NE(0, packet_id);

        if (path >= 2) {
            /* Exercise BrokerOrphan_Reclaim as well as live takeover.
             * [MQTT-4.4.0-1] keeps the unacknowledged PUBLISH in either
             * resumed Session, encoded for the new protocol level. */
            g_clients[0].read_err = 1;
            for (i = 0; i < 4; i++) {
                (void)MqttBroker_Step(&broker);
            }
            ASSERT_NOT_NULL(find_orphan_session(&broker, "S"));
        }

        if (direction == 0) {
            mock_client_input_append(2, connect_v5, sizeof(connect_v5));
            expected = expected_v5;
            expected_len = sizeof(expected_v5);
        }
        else {
            mock_client_input_append(2, connect_v311,
                sizeof(connect_v311));
            expected = expected_v311;
            expected_len = sizeof(expected_v311);
        }
        expected_v311[5] = (byte)(packet_id >> 8);
        expected_v311[6] = (byte)packet_id;
        expected_v5[5] = (byte)(packet_id >> 8);
        expected_v5[6] = (byte)packet_id;
        g_clients_active = 3;
        for (i = 0; i < 16; i++) {
            (void)MqttBroker_Step(&broker);
        }
        ASSERT_EQ(1, count_packets_of_type(g_clients[2].out_buf,
            g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH));
        ASSERT_TRUE(g_clients[2].out_len >= expected_len);
        ASSERT_MEM_EQ(expected,
            g_clients[2].out_buf + g_clients[2].out_len - expected_len,
            expected_len);
        if (path == 1) {
            ASSERT_EQ(MQTT_REASON_SESSION_TAKEN_OVER,
                first_disconnect_reason(g_clients[0].out_buf,
                    g_clients[0].out_len));
        }

        MqttBroker_Stop(&broker);
        MqttBroker_Free(&broker);
    }
}
#endif /* WOLFMQTT_V5 */
#endif /* !WOLFMQTT_STATIC_MEMORY */

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
    /* v5 CONNECT clean=0, level=5, Session Expiry=60 (persistent session so a
     * same-id reconnect resumes it), client_id="K". props = 5 (0x11 + u32).
     * remain = 6 + 1 + 1 + 2 + (1+5) + 3 = 19. */
    static const byte connect0[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x00,                              /* clean_start = 0 */
        0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,/* props_len=5, SessionExpiry=60 */
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
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x00,
        0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,/* props_len=5, SessionExpiry=60 */
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

#ifdef WOLFMQTT_V5
/* The broker has no Shared Subscription routing, so it must not let a v5
 * client believe otherwise. MQTT 5.0 section 3.2.2.3.15: an absent Shared
 * Subscription Available property means "supported", so CONNACK must carry
 * it with value 0. A '$share/' filter (section 4.8.2) is then refused with
 * SUBACK Reason Code 0x9E (section 3.9.3) instead of being stored and matched
 * literally. */
TEST(broker_shared_subscription_not_supported_v5)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttConnectAck ack;
    MqttProp* prop;
    int shared_avail = -1;
    int last_byte;
    int rc;
    int i;
    /* v5 CONNECT, clean=1, props_len=0, client_id="A". Remaining Length 14. */
    static const byte connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x02,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };
    /* v5 SUBSCRIBE packet_id 7, props_len 0, filter "$share/g/x", options
     * QoS 0. Remaining Length = 2 + 1 + 2 + 10 + 1 = 16. */
    static const byte subscribe_shared[] = {
        0x82, 0x10,
        0x00, 0x07,
        0x00,
        0x00, 0x0A, '$', 's', 'h', 'a', 'r', 'e', '/', 'g', '/', 'x',
        0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, subscribe_shared, sizeof(subscribe_shared));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    XMEMSET(&ack, 0, sizeof(ack));
    ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
    rc = MqttDecode_ConnectAck(g_clients[0].out_buf,
        (int)g_clients[0].out_len, &ack);
    ASSERT_TRUE(rc > 0);
    ASSERT_EQ(MQTT_CONNECT_ACK_CODE_ACCEPTED, ack.return_code);
    for (prop = ack.props; prop != NULL; prop = prop->next) {
        if (prop->type == MQTT_PROP_SHARED_SUBSCRIPTION_AVAIL) {
            shared_avail = prop->data_byte;
        }
    }
    if (ack.props != NULL) {
        (void)MqttProps_Free(ack.props);
    }
    ASSERT_EQ(0, shared_avail);

    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    last_byte = g_clients[0].out_buf[g_clients[0].out_len - 1];
    ASSERT_EQ(MQTT_REASON_SS_NOT_SUPPORTED, last_byte);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 */

#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_DYN_PROP)
/* An absent Shared Subscription Available property means "supported" (MQTT
 * 5.0 section 3.2.2.3.15). If the property cannot be allocated, the CONNECT
 * is refused rather than accepted with a CONNACK that advertises a feature
 * the broker does not have. */
TEST(connect_v5_refused_when_shared_sub_property_unavailable)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttProp* hold = NULL;
    int free_slots = 0;
    int held = 0;
    int i;
    int last_byte_code;
    /* v5 CONNECT, clean=1, props_len=0, client_id="A". Remaining Length 14. */
    static const byte connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x02,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Hold a property-stack reference of our own: no client exists yet,
     * and in multithread builds the stack lock is only initialized while
     * one does. */
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttProps_Init());

    /* Count the free property slots, then hold all but two: enough for
     * Retain Available and Wildcard Subscription Available, not for Shared
     * Subscription Available. */
    while (MqttProps_Add(&hold) != NULL) {
        free_slots++;
    }
    (void)MqttProps_Free(hold);
    hold = NULL;
    for (i = 0; i < free_slots - 2; i++) {
        if (MqttProps_Add(&hold) != NULL) {
            held++;
        }
    }

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);
    (void)MqttProps_Free(hold);
    (void)MqttProps_ShutDown();

    ASSERT_TRUE(free_slots > 2);
    ASSERT_EQ(free_slots - 2, held);
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    last_byte_code = g_out_buf[3];
    ASSERT_EQ(MQTT_REASON_SERVER_UNAVAILABLE, last_byte_code);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Receive Maximum and, when this build caps QoS below 2, Maximum QoS are
 * also capability statements: their absence means 65535 and QoS 2 (MQTT 5.0
 * sections 3.2.2.3.3 and 3.2.2.3.4). With room for only the three
 * availability properties, the CONNECT must be refused rather than accepted
 * without them. */
TEST(connect_v5_refused_when_receive_max_property_unavailable)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttProp* hold = NULL;
    int free_slots = 0;
    int held = 0;
    int i;
    int last_byte_code;
    /* v5 CONNECT, clean=1, props_len=0, client_id="A". Remaining Length 14. */
    static const byte connect[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x02,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* See connect_v5_refused_when_shared_sub_property_unavailable for the
     * property-stack reference. Leave three free slots: Retain Available,
     * Wildcard Subscription Available and Shared Subscription Available. */
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttProps_Init());
    while (MqttProps_Add(&hold) != NULL) {
        free_slots++;
    }
    (void)MqttProps_Free(hold);
    hold = NULL;
    for (i = 0; i < free_slots - 3; i++) {
        if (MqttProps_Add(&hold) != NULL) {
            held++;
        }
    }

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);
    (void)MqttProps_Free(hold);
    (void)MqttProps_ShutDown();

    ASSERT_TRUE(free_slots > 3);
    ASSERT_EQ(free_slots - 3, held);
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    last_byte_code = g_out_buf[3];
    ASSERT_EQ(MQTT_REASON_SERVER_UNAVAILABLE, last_byte_code);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A CONNECT refused because a required CONNACK property cannot be allocated
 * must not take over the connected client that holds the same ClientId: that
 * client stays connected with its Session (here, its subscription)
 * unchanged. */
TEST(connect_v5_connack_property_failure_keeps_incumbent_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttProp* hold = NULL;
    int free_slots = 0;
    int held = 0;
    int i;
    int incumbent_closed;
    int incumbent_publishes;
    /* v5 CONNECT: Clean Start 0, keep alive 60, properties: Session Expiry
     * Interval (0x11) = 60, ClientId "P". Remaining Length 19. Used by both
     * the incumbent and the takeover attempt. */
    static const byte connect[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* v5 SUBSCRIBE packet id 1, Property Length 0, filter "t", options 0. */
    static const byte subscribe[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 't',
        0x00
    };
    /* v5 QoS 0 PUBLISH to "t", Property Length 0, payload "x". */
    static const byte publish[] = {
        0x30, 0x05,
        0x00, 0x01, 't',
        0x00,
        'x'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect, sizeof(connect));
    mock_client_input_append(0, subscribe, sizeof(subscribe));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Hold a property-stack reference of our own (see
     * connect_v5_refused_when_shared_sub_property_unavailable), then leave
     * two free slots: enough to decode the CONNECT's Session Expiry Interval
     * and later to hold Retain Available and Wildcard Subscription
     * Available, not Shared Subscription Available. */
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttProps_Init());
    while (MqttProps_Add(&hold) != NULL) {
        free_slots++;
    }
    (void)MqttProps_Free(hold);
    hold = NULL;
    for (i = 0; i < free_slots - 2; i++) {
        if (MqttProps_Add(&hold) != NULL) {
            held++;
        }
    }

    mock_client_input_append(1, connect, sizeof(connect));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    (void)MqttProps_Free(hold);
    (void)MqttProps_ShutDown();

    mock_client_input_append(0, publish, sizeof(publish));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    incumbent_closed = g_clients[0].closed;
    incumbent_publishes = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);

    ASSERT_TRUE(free_slots > 2);
    ASSERT_EQ(free_slots - 2, held);
    ASSERT_TRUE(g_clients[1].out_len >= 4);
    ASSERT_EQ(0x20, g_clients[1].out_buf[0]);
    ASSERT_EQ(MQTT_REASON_SERVER_UNAVAILABLE, g_clients[1].out_buf[3]);
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_FALSE(incumbent_closed);
    ASSERT_EQ(1, incumbent_publishes);
}
#endif /* WOLFMQTT_V5 && !WOLFMQTT_DYN_PROP */

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

#ifndef WOLFMQTT_STATIC_MEMORY
/* [MQTT-3.3.1-9] A successful subscription must receive the matching retained
 * Application Message. If the broker cannot allocate that delivery, it must
 * close without claiming success in a SUBACK. */
TEST(retained_delivery_alloc_failure_prevents_success_suback)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish_retained[] = {
        0x31, 0x04, 0x00, 0x01, 'x', 'r'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_retained, sizeof(publish_retained));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&broker);
    }

    /* BrokerSubs_Add allocates the subscription, filter, and client ID. Fail
     * the next allocation, which creates the retained outbound-queue entry. */
    broker_test_fail_alloc_after(3);
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&broker);
    }
    broker_test_disable_alloc_failure();

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_EQ(0, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    ASSERT_EQ(0, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_TRUE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */
#endif /* WOLFMQTT_BROKER_RETAINED */

#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
/* QoS 2 dedup state must survive a disconnect/reconnect cycle; a
 * retransmitted PUBLISH must not be re-fanned-out to the subscriber. */
TEST(qos2_dedup_survives_disconnect_reconnect)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    int sub_pubs;
    int reconnect_pubrecs;
    static const byte connect_sub[] = {
        0x10, 0x0F,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x03, 'S', 'u', 'b'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x02
    };
    /* Publisher CONNECT clean_session=0 (persistent), ClientId "Pub". */
    static const byte connect_pub[] = {
        0x10, 0x0F,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x03, 'P', 'u', 'b'
    };
    static const byte publish_qos2[] = {
        0x34, 0x0A,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'f', 'i', 'r', 's', 't'
    };
    /* Same PUBLISH, DUP=1, retransmitted after reconnect. */
    static const byte publish_qos2_dup[] = {
        0x3C, 0x0A,
        0x00, 0x01, 'x',
        0x00, 0x07,
        'f', 'i', 'r', 's', 't'
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Phase 1: subscriber + publisher's first connection. Publisher
     * sends the QoS 2 PUBLISH, then disconnects WITHOUT a PUBREL - the
     * broker's dedup state for packet_id=7 must be preserved, not
     * dropped, by the disconnect cleanup. */
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish_qos2, sizeof(publish_qos2));
    mock_client_input_append(1, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 24; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);
    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    ASSERT_EQ(1, sub_pubs); /* delivered exactly once so far */

    /* Phase 2: publisher reconnects with the SAME Client Identifier and
     * retransmits the identical QoS 2 PUBLISH (DUP=1, same packet_id).
     * The reconnect must reclaim the dedup state before this PUBLISH is
     * processed. */
    g_clients_active = 3;
    mock_client_input_append(2, connect_pub, sizeof(connect_pub));
    mock_client_input_append(2, publish_qos2_dup, sizeof(publish_qos2_dup));
    for (i = 0; i < 24; i++) {
        MqttBroker_Step(&broker);
    }

    reconnect_pubrecs = count_packets_of_type(g_clients[2].out_buf,
        g_clients[2].out_len, MQTT_PACKET_TYPE_PUBLISH_REC);
    /* The QoS 2 handshake with the reconnected publisher must still
     * complete (PUBREC sent)... */
    ASSERT_EQ(1, reconnect_pubrecs);
    /* ...but the retransmit must NOT be re-fanned-out to the
     * subscriber. Pre-fix, BrokerOrphan_Take never carried
     * bc->qos2_pending into the orphan record (only out_q was
     * transferred) and BrokerClient_Free's BrokerInboundQos2_Clear then
     * discarded it, so the reconnected publisher's retransmit was
     * treated as brand new: it would be fanned out a second time here,
     * making this total 2. */
    sub_pubs = count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH);
    ASSERT_EQ(1, sub_pubs);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.1.2.11.3]: Receive Maximum = 0 in CONNECT must close, not "unset". */
TEST(connect_v5_receive_max_zero_protocol_error)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* v5 CONNECT, ClientId "A", props: Receive Maximum (0x21) = 0x0000.
     * remain = 6("MQTT")+1(level)+1(flags)+2(keepalive)+1(props_len)+
     *          3(prop TLV)+2(clientid_len)+1(clientid) = 17 */
    static const byte connect[] = {
        0x10, 17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x02,                       /* CleanStart = 1 */
        0x00, 0x3C,
        0x03,                       /* props_len = 3 */
        0x21, 0x00, 0x00,           /* Receive Maximum = 0 */
        0x00, 0x01, 'A'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_REASON_PROTOCOL_ERR, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MQTT 5.0 section 3.14.2.2.2: when CONNECT set a Session Expiry Interval of
 * zero, a DISCONNECT carrying a non-zero interval is a Protocol Error
 * [MQTT-3.14.2-1]. The Server does not treat it as a valid DISCONNECT and
 * sends DISCONNECT with Reason Code 0x82 before closing (section 4.13). */
TEST(disconnect_v5_session_expiry_raise_sends_protocol_error)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    /* v5 CONNECT, CleanStart, keep alive 60, no properties (Session Expiry
     * Interval 0), ClientId "A". Remaining Length 14. */
    static const byte connect[] = {
        0x10, 14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'A'
    };
    /* v5 DISCONNECT, Reason Code 0x00, Properties length 5: Session Expiry
     * Interval (0x11) = 60. Remaining Length 7. */
    static const byte disconnect[] = {
        0xE0, 0x07,
        0x00,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x3C
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }

    ASSERT_EQ(MQTT_REASON_PROTOCOL_ERR,
        first_disconnect_reason(g_out_buf, g_out_len));
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}


/* v5 CONNECT with Clean Start=0, no Session Expiry: must default to 0,
 * not the v3.1.1 0xFFFFFFFF "never" sentinel. */
TEST(connect_v5_clean0_no_se_prop_orphan_expiry_zero)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerOrphanSession* o;
    /* v5 CONNECT clean=0, no props, ClientId "K". remain = 14. */
    static const byte connect0[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'K'
    };
    static const byte subscribe0[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'k',
        0x00
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, subscribe0, sizeof(subscribe0));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    /* [MQTT-3.1.2.11.2] A v5 Clean Start=0 CONNECT without a Session Expiry
     * property defaults the interval to 0, so the Session ends when the
     * connection closes: no orphan is retained and a same-id reconnect gets a
     * fresh session. */
    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "K") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o == NULL);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* Zero subs + positive Session Expiry must still create an orphan. */
TEST(disconnect_v5_zero_subs_nonzero_expiry_creates_orphan)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerOrphanSession* o;
    /* v5 CONNECT clean=0, ClientId "K2", props: Session Expiry Interval
     * (0x11) = 60. No SUBSCRIBE at all. remain = 6+1+1+2+1+5+2+2 = 20 */
    static const byte connect0[] = {
        0x10, 20,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x02, 'K', '2'
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    /* Pre-fix, BrokerSubs_OrphanClient returned early on count==0 before
     * BrokerOrphan_Take was ever called, so no orphan exists here. */
    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "K2") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o != NULL);
    ASSERT_EQ((word32)60, o->session_expiry_sec);
    ASSERT_EQ(0, o->out_q_count);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* MqttBroker_Step must sweep expired orphan Sessions. Time is pinned at
 * 0, so a finite expiry of 0 is already expired; nonzero never is. */
TEST(orphan_expire_sweep_removes_zero_expiry_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerOrphanSession* o;
    /* Client "K3": clean=0, no SE prop (expiry defaults to 0 per #7668),
     * one sub -> orphan created via the count>0 path. remain = 15
     * (2-byte ClientId "K3"). */
    static const byte connect_k3[] = {
        0x10, 0x0F,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x00,
        0x00, 0x02, 'K', '3'
    };
    static const byte subscribe_k3[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'k',
        0x00
    };
    /* Client "K4": clean=0, SE prop = 60, no subs -> orphan created via
     * the #7669 count==0 path with a nonzero expiry. remain = 20. */
    static const byte connect_k4[] = {
        0x10, 20,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x02, 'K', '4'
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_k3, sizeof(connect_k3));
    mock_client_input_append(0, subscribe_k3, sizeof(subscribe_k3));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    mock_client_input_append(1, connect_k4, sizeof(connect_k4));
    mock_client_input_append(1, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 24; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);
    ASSERT_TRUE(g_clients[1].closed);

    /* [MQTT-3.1.2.11.2] K3's Session Expiry is 0, so its Session ends when the
     * connection closes: no orphan is retained at all (removed immediately at
     * disconnect, not left reclaimable for the once-per-second sweep). */
    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "K3") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o == NULL);

    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "K4") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o != NULL); /* expiry=60, not yet elapsed -> survives */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_BROKER_WILL
/* [MQTT-3.14.2-1]: DISCONNECT setting Session Expiry 0-to-nonzero is a
 * Protocol Error; confirmed via the immediate Will fired on abnormal close. */
TEST(disconnect_v5_session_expiry_0_to_nonzero_protocol_error)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_lwt[] = {
        0x82, 0x08,
        0x00, 0x01,
        0x00, 0x03, 'l', 'w', 't',
        0x00
    };
    /* v5 CONNECT publisher, ClientId "P", Will flag set (topic "lwt",
     * payload "bye"), no CONNECT props, no Will props (delay=0). remain =
     * 6+1+1+2+1(props_len=0)+2+1('P')+1(will_props_len=0)+2+3+2+3 = 25 */
    static const byte connect_pub[] = {
        0x10, 25,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x04,                       /* Will flag, CleanStart=0 */
        0x00, 0x3C,
        0x00,                       /* connect props_len = 0 */
        0x00, 0x01, 'P',
        0x00,                       /* will props_len = 0 */
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* v5 DISCONNECT, reason=Normal(0x00), props: Session Expiry Interval
     * (0x11) = 30. remain = 1(reason)+1(props_len)+5(prop) = 7 */
    static const byte disconnect_se[] = {
        0xE0, 0x07,
        0x00,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x1E
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, disconnect_se, sizeof(disconnect_se));
    for (i = 0; i < 24; i++) {
        MqttBroker_Step(&broker);
    }

    /* Pre-fix: SE update was silently ignored (or, for BROKER_WILL
     * builds, only read for the Will-reason-code check), no protocol
     * error was raised, and the graceful path cleared the Will without
     * publishing it -> 0 PUBLISH to the subscriber. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_TRUE(g_clients[1].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#if defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
/* The Protocol Error DISCONNECT (Reason Code 0x82, MQTT 5.0 section
 * 3.14.2.2.2) for a 0-to-nonzero Session Expiry change must reach the client
 * in full before the Network Connection is closed, even when the transport
 * takes it in more than one write. */
TEST(disconnect_v5_session_expiry_protocol_error_short_write_completes)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    size_t pub_mark;
    int closed_after_first;
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_lwt[] = {
        0x82, 0x08,
        0x00, 0x01,
        0x00, 0x03, 'l', 'w', 't',
        0x00
    };
    /* Same publisher CONNECT and DISCONNECT as
     * disconnect_v5_session_expiry_0_to_nonzero_protocol_error. */
    static const byte connect_pub[] = {
        0x10, 25,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x04,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    static const byte disconnect_se[] = {
        0xE0, 0x07,
        0x00,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x1E
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* The transport takes only the first byte of the DISCONNECT. */
    pub_mark = g_clients[1].out_len;
    g_clients[1].write_limit_once = 1;
    mock_client_input_append(1, disconnect_se, sizeof(disconnect_se));
    MqttBroker_Step(&broker);
    closed_after_first = g_clients[1].closed;
    for (i = 0; i < 8; i++) {
        MqttBroker_Step(&broker);
    }

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);

    ASSERT_FALSE(closed_after_first);
    /* DISCONNECT: type 0xE0, Remaining Length, Reason Code 0x82 first. */
    ASSERT_TRUE(g_clients[1].out_len >= pub_mark + 3);
    ASSERT_EQ(0xE0, g_clients[1].out_buf[pub_mark]);
    ASSERT_EQ(g_clients[1].out_len - pub_mark,
        (size_t)2 + g_clients[1].out_buf[pub_mark + 1]);
    ASSERT_EQ(MQTT_REASON_PROTOCOL_ERR, g_clients[1].out_buf[pub_mark + 2]);
    ASSERT_TRUE(g_clients[1].closed);
    /* The close is still abnormal, so the Will is published. */
    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
}
#endif /* WOLFMQTT_NONBLOCK && !WOLFMQTT_STATIC_MEMORY */
#endif /* WOLFMQTT_BROKER_WILL */

#ifdef WOLFMQTT_BROKER_RETAINED
/* [MQTT-3.3.1-9..11]: Retain Handling = 2 must not deliver on subscribe. */
TEST(subscribe_v5_retain_handling_2_never_delivers)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* Retained QoS 0 PUBLISH, topic "x", payload "r". */
    static const byte publish_retained[] = {
        0x31, 0x04,
        0x00, 0x01, 'x', 'r'
    };
    /* v5 CONNECT subscriber, ClientId "S", props_len=0. remain = 14. */
    static const byte connect_sub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE, filter "x", options = Retain Handling 2 (0x20) |
     * QoS 0. remain = 2+1+2+1+1 = 7 */
    static const byte subscribe_rh2[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'x',
        0x20
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_retained, sizeof(publish_retained));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_rh2, sizeof(subscribe_rh2));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Pre-fix, Retain Handling bits were never read and retained delivery
     * was unconditional -> this would be 1. */
    ASSERT_EQ(0, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_RETAINED */

/* v5 PUBLISH properties must survive QoS>=1 fan-out through out_q. */
TEST(publish_v5_props_survive_queued_delivery)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    PublishInfo info;
    static const byte connect_sub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE QoS 1, filter "x", options = QoS1 (0x01). remain = 7 */
    static const byte subscribe_x[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'x',
        0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };
    /* PUBLISH QoS 1, packet_id=5, topic "x", one property (Payload
     * Format Indicator = 1), payload "p". remain =
     * 2+1+2+1(props_len)+2(prop)+1(payload) = 9 */
    static const byte publish_v5[] = {
        0x32, 0x09,
        0x00, 0x01, 'x',
        0x00, 0x05,
        0x02,
        0x01, 0x01,
        'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish_v5, sizeof(publish_v5));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    info = first_publish_info(g_clients[0].out_buf, g_clients[0].out_len);
    ASSERT_TRUE(info.found);
    /* Pre-fix, BrokerOutPub had no props field and out_pub.props was
     * never set, so the encoder would write an empty (1-byte, value 0)
     * properties block instead: remain would be 7, not 9. */
    ASSERT_EQ(9, (int)info.remain_len);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_BROKER_RETAINED
/* An unacked QoS>=1 retained delivery must survive into the orphan's
 * out_q on disconnect, same as normal PUBLISH fan-out. */
TEST(retained_qos1_delivery_survives_via_outq)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerOrphanSession* o;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* Retained QoS 1 PUBLISH, packet_id=1, topic "x", payload "r". */
    static const byte publish_retained[] = {
        0x33, 0x06,
        0x00, 0x01, 'x',
        0x00, 0x01,
        'r'
    };
    /* Subscriber CONNECT v3.1.1, clean_session=0, ClientId "S". */
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'x',
        0x01
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_retained, sizeof(publish_retained));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 24; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[1].closed);

    /* Pre-fix: retained QoS>=1 delivery was a direct MqttPacket_Write
     * with no BrokerOutPub entry, so the orphan's out_q would be empty
     * (out_q_count == 0) here. */
    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "S") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o != NULL);
    ASSERT_EQ(1, o->out_q_count);
    ASSERT_EQ(1, o->out_q_inflight);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_RETAINED */

#ifdef WOLFMQTT_BROKER_WILL
/* A shorter Session Expiry than Will Delay must publish the Will at
 * Session end, not the full delay. */
TEST(pending_will_publish_time_uses_min_of_delay_and_session_expiry)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerPendingWill* pw;
    /* v5 CONNECT, Will flag, ClientId "M". CONNECT props: Session
     * Expiry Interval = 30. Will props: Will Delay Interval = 3600.
     * remain = 35 (same shape as will_delay_interval_capped). */
    static const byte connect_m[] = {
        0x10, 35,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x04,
        0x00, 0x3C,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x1E, /* Session Expiry Interval = 30 */
        0x00, 0x01, 'M',
        0x05,
        0x18, 0x00, 0x00, 0x0E, 0x10, /* Will Delay Interval = 3600 */
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    static const byte disconnect_bad[] = { 0xE1, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect_m, sizeof(connect_m));
    mock_client_input_append(0, disconnect_bad, sizeof(disconnect_bad));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    pw = broker.pending_wills;
    while (pw != NULL && (pw->client_id == NULL ||
            XSTRCMP(pw->client_id, "M") != 0)) {
        pw = pw->next;
    }
    ASSERT_TRUE(pw != NULL);
    /* Pre-fix, BrokerPendingWill_Add computed publish_time from
     * will_delay_sec alone (now + 3600); Session Expiry was never
     * consulted. */
    ASSERT_EQ((WOLFMQTT_BROKER_TIME_T)30, pw->publish_time);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* A Will Delay Interval above BROKER_MAX_WILL_DELAY_SEC is clamped so a
 * client cannot monopolize a deferred-will slot indefinitely. */
#if WOLFMQTT_MAX_QOS < 2
/* [MQTT-3.2.2-11] A v5 Server whose Maximum QoS is below the requested Will
 * QoS must refuse the CONNECT with reason 0x9B (QoS not supported) and close,
 * rather than silently downgrading the stored Will QoS. Only reachable in a
 * build whose WOLFMQTT_MAX_QOS is below 2. */
TEST(connect_v5_will_qos_exceeds_max_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* v5 CONNECT: clean + Will flag + Will QoS 2 (flags 0x16), ClientId "W",
     * empty CONNECT and Will props, Will topic "lwt", Will payload "bye".
     * remain = 25 (0x19). */
    static const byte connect_wq2[] = {
        0x10, 0x19,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x16,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'W',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect_wq2, sizeof(connect_wq2));
    run_broker_one_connect(&broker);

    /* v5 CONNACK: 0x20, remain, ack flags, reason. The connection must be
     * refused with QoS-not-supported and then closed, not accepted. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_REASON_QOS_NOT_SUPPORTED, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_MAX_QOS < 2 */

#ifndef WOLFMQTT_BROKER_RETAINED
/* A v5 Server that does not support retained messages must refuse a CONNECT
 * whose Will Retain is set with reason 0x9A (Retain not supported) and close,
 * rather than accepting it while advertising Retain Available = 0. */
TEST(connect_v5_will_retain_unsupported_refused)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* v5 CONNECT: clean + Will flag + Will Retain (flags 0x26), Will QoS 0,
     * ClientId "W", empty CONNECT and Will props, Will topic "lwt", Will
     * payload "bye". remain = 25 (0x19). */
    static const byte connect_wretain[] = {
        0x10, 0x19,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x26,
        0x00, 0x3C,
        0x00,
        0x00, 0x01, 'W',
        0x00,
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect_wretain, sizeof(connect_wretain));
    run_broker_one_connect(&broker);

    /* v5 CONNACK: 0x20, remain, ack flags, reason. Must be refused with
     * Retain-not-supported and closed, not accepted. */
    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(0x00, g_out_buf[2]);
    ASSERT_EQ(MQTT_REASON_RETAIN_NOT_SUPPORTED, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_RETAINED */

TEST(will_delay_interval_capped)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerPendingWill* pw;
    /* v5 CONNECT, Will flag, ClientId "W". CONNECT props: Session
     * Expiry Interval = 0xFFFFFFFF. Will props: Will Delay Interval =
     * 4600 (> BROKER_MAX_WILL_DELAY_SEC's default of 3600). remain = 35 */
    static const byte connect_w[] = {
        0x10, 35,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x04,
        0x00, 0x3C,
        0x05,
        0x11, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x01, 'W',
        0x05,
        0x18, 0x00, 0x00, 0x11, 0xF8, /* Will Delay Interval = 4600 */
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* Malformed DISCONNECT (reserved flag bit set) drives the abnormal
     * (immediate-teardown) close path, which still defers via
     * BrokerPendingWill_Add when will_delay_sec > 0. */
    static const byte disconnect_bad[] = { 0xE1, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect_w, sizeof(connect_w));
    mock_client_input_append(0, disconnect_bad, sizeof(disconnect_bad));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    pw = broker.pending_wills;
    while (pw != NULL && (pw->client_id == NULL ||
            XSTRCMP(pw->client_id, "W") != 0)) {
        pw = pw->next;
    }
    ASSERT_TRUE(pw != NULL);
    /* 4600 exceeds the 3600 cap; with mock time pinned at 0 and an infinite
     * Session Expiry the publish time is the clamped delay. */
    ASSERT_EQ((WOLFMQTT_BROKER_TIME_T)BROKER_MAX_WILL_DELAY_SEC,
        pw->publish_time);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_WILL */
#endif /* WOLFMQTT_V5 && !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* A fatal PUBACK decode failure must close, same as PUBLISH/PUBREC/PUBREL. */
TEST(puback_malformed_closes_connection)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect0[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* PUBACK with remain_len = 0 (no Packet Identifier at all). */
    static const byte puback_bad[] = { 0x40, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, puback_bad, sizeof(puback_bad));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    /* Pre-fix, the decode failure was silently discarded and the
     * connection stayed open. */
    ASSERT_TRUE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
/* No Enhanced Authentication support; a CONNECT with Auth Method must
 * be refused, not silently accepted. */
TEST(connect_v5_auth_method_present_rejected)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* props: Authentication Method (0x15) = "PLAIN" (UTF8, 5 bytes).
     * prop TLV = 1(type)+2(len)+5(str) = 8. remain = 6+1+1+2+1+8+2+1 = 22 */
    static const byte connect[] = {
        0x10, 22,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x02,
        0x00, 0x3C,
        0x08,
        0x15, 0x00, 0x05, 'P', 'L', 'A', 'I', 'N',
        0x00, 0x01, 'A'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    ASSERT_TRUE(g_out_len >= 4);
    ASSERT_EQ(0x20, g_out_buf[0]);
    ASSERT_EQ(MQTT_REASON_BAD_AUTH_METHOD, g_out_buf[3]);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.1.2.11.4]: Maximum Packet Size 0 in CONNECT is a Protocol Error.
 * Rejected at decode time (mqtt_packet.c), so no CONNACK is ever sent -
 * just a close, same as any other malformed CONNECT. */
TEST(connect_v5_max_packet_size_zero_protocol_error)
{
    MqttBroker broker;
    MqttBrokerNet net;
    /* props: Maximum Packet Size (0x27) = 0x00000000 (5 bytes). remain =
     * 6+1+1+2+1+5+2+1 = 19 */
    static const byte connect[] = {
        0x10, 19,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05,
        0x02,
        0x00, 0x3C,
        0x05,
        0x27, 0x00, 0x00, 0x00, 0x00, /* Maximum Packet Size = 0 */
        0x00, 0x01, 'B'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect, sizeof(connect));
    run_broker_one_connect(&broker);

    ASSERT_EQ(0, g_out_len);
    ASSERT_TRUE(g_client_closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 && !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* [MQTT-3.7] A malformed PUBCOMP (Remaining Length 0, no Packet Identifier)
 * must fail to decode and close the connection - the PUBCOMP twin of
 * puback_malformed_closes_connection. */
TEST(pubcomp_malformed_closes_connection)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect0[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'A'
    };
    /* PUBCOMP with remain_len = 0 (no Packet Identifier at all). */
    static const byte pubcomp_bad[] = { 0x70, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, pubcomp_bad, sizeof(pubcomp_bad));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_TRUE(g_clients[0].closed);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
/* [MQTT-3.14.4] A valid v5 DISCONNECT carrying a Session Expiry Interval must
 * update the client's session expiry (any change other than 0->nonzero is
 * allowed). The orphan created on close must carry the updated value. */
TEST(disconnect_v5_session_expiry_updated_on_valid)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerOrphanSession* o;
    /* v5 CONNECT clean=0, ClientId "U", props: Session Expiry = 60. */
    static const byte connect0[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'U'
    };
    static const byte subscribe0[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'u',
        0x00
    };
    /* v5 DISCONNECT reason=Normal(0x00), props: Session Expiry = 30. */
    static const byte disconnect_se[] = {
        0xE0, 0x07,
        0x00,
        0x05,
        0x11, 0x00, 0x00, 0x00, 0x1E
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect0, sizeof(connect0));
    mock_client_input_append(0, subscribe0, sizeof(subscribe0));
    mock_client_input_append(0, disconnect_se, sizeof(disconnect_se));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "U") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o != NULL);
    /* Updated by the DISCONNECT from 60 to 30. */
    ASSERT_EQ((word32)30, o->session_expiry_sec);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 && !WOLFMQTT_STATIC_MEMORY */

#ifndef WOLFMQTT_STATIC_MEMORY
/* BrokerOrphan_ExpireSweep must not expire a session whose orphan_since is in
 * the future relative to the (frozen at 0) clock - a backward clock jump must
 * never drop a live session early. Companion to the retained clock-rollback
 * guard. */
TEST(orphan_expire_sweep_backward_clock_keeps_session)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerOrphanSession* o;
#ifdef WOLFMQTT_V5
    /* Client "K3": clean=0, Session Expiry=60 (persistent session, so a
     * backward clock jump must not sweep it), one sub -> orphan. */
    static const byte connect_k3[] = {
        0x10, 0x14,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,
        0x00, 0x02, 'K', '3'
    };
    static const byte subscribe_k3[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'k',
        0x00
    };
#else
    /* MQTT 3.1.1 sections 3.1.2/3.1.3: level 4, clean=0, ClientId K3.
     * Section 3.8.2/3.8.3: packet ID 1, filter k, QoS 0, no Properties. */
    static const byte connect_k3[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x02, 'K', '3'
    };
    static const byte subscribe_k3[] = {
        0x82, 0x06,
        0x00, 0x01,
        0x00, 0x01, 'k',
        0x00
    };
#endif
    static const byte disconnect0[] = { 0xE0, 0x00 };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(1);
    mock_client_input_append(0, connect_k3, sizeof(connect_k3));
    mock_client_input_append(0, subscribe_k3, sizeof(subscribe_k3));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(g_clients[0].closed);

    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "K3") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o != NULL);

    /* Stamp orphan_since in the future relative to now=0 and keep expiry=0.
     * Without the now >= orphan_since guard, (now - orphan_since) underflows
     * and the entry would be falsely expired. */
    o->orphan_since = 1;
    o->session_expiry_sec = 0;

    broker.orphan_last_expire_check = 1;
    MqttBroker_Step(&broker);

    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "K3") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o != NULL); /* future-stamped -> not swept */

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
/* An offline durable subscriber's queued PUBLISH must carry a deep copy of the
 * v5 Application Message properties (BrokerProps_Clone). The cloned string and
 * binary property values must survive after the source PUBLISH is freed. */
TEST(orphan_offline_queue_clones_v5_publish_props)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    BrokerOrphanSession* o;
    MqttProp* p;
    int saw_content_type = 0;
    int saw_correlation = 0;
    static const byte connect_sub[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x00, 0x3C,/* Session Expiry=60 -> persists */
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE QoS 1, filter "x". */
    static const byte subscribe_x[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'x',
        0x01
    };
    static const byte disconnect0[] = { 0xE0, 0x00 };
    static const byte connect_pub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P'
    };
    /* PUBLISH QoS 1, packet_id=7, topic "x", props: Content Type = "text/plain"
     * and Correlation Data = DE AD BE EF, payload "p". props block = 20 bytes,
     * remain = 3+2+1+20+1 = 27. */
    static const byte publish_v5[] = {
        0x32, 0x1B,
        0x00, 0x01, 'x',
        0x00, 0x07,
        0x14,
        0x03, 0x00, 0x0A, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n',
        0x09, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
        'p'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(0, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
        if (g_clients[0].closed) break;
    }
    ASSERT_TRUE(g_clients[0].closed);

    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish_v5, sizeof(publish_v5));
    mock_client_input_append(1, disconnect0, sizeof(disconnect0));
    for (i = 0; i < 24; i++) {
        MqttBroker_Step(&broker);
        if (g_clients[1].closed) break;
    }

    o = broker.orphan_sessions;
    while (o != NULL && (o->client_id == NULL ||
            XSTRCMP(o->client_id, "S") != 0)) {
        o = o->next;
    }
    ASSERT_TRUE(o != NULL);
    ASSERT_EQ(1, o->out_q_count);
    ASSERT_TRUE(o->out_q_head != NULL);

    for (p = o->out_q_head->props; p != NULL; p = p->next) {
        if (p->type == MQTT_PROP_CONTENT_TYPE) {
            saw_content_type = 1;
            ASSERT_EQ(10, (int)p->data_str.len);
            ASSERT_EQ(0, XMEMCMP(p->data_str.str, "text/plain", 10));
        }
        else if (p->type == MQTT_PROP_CORRELATION_DATA) {
            saw_correlation = 1;
            ASSERT_EQ(4, (int)p->data_bin.len);
            ASSERT_EQ(0xDE, p->data_bin.data[0]);
            ASSERT_EQ(0xEF, p->data_bin.data[3]);
        }
    }
    ASSERT_TRUE(saw_content_type);
    ASSERT_TRUE(saw_correlation);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_V5 && !WOLFMQTT_STATIC_MEMORY */

#if defined(WOLFMQTT_BROKER_RETAINED) && defined(WOLFMQTT_V5)
/* [MQTT-3.3.1-9] Retain Handling = 0 must always deliver the matching retained
 * message on subscribe (positive control for the Retain Handling = 2 test). */
TEST(subscribe_v5_retain_handling_0_delivers)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish_retained[] = {
        0x31, 0x04,
        0x00, 0x01, 'x', 'r'
    };
    static const byte connect_sub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE filter "x", options = Retain Handling 0 (0x00) | QoS 0. */
    static const byte subscribe_rh0[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'x',
        0x00
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_retained, sizeof(publish_retained));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_rh0, sizeof(subscribe_rh0));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&broker);
    }

    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

/* [MQTT-3.3.1-10] Retain Handling = 1 delivers the retained message only if
 * the subscription did not already exist. A second identical subscribe must
 * not re-deliver. */
TEST(subscribe_v5_retain_handling_1_only_if_new)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish_retained[] = {
        0x31, 0x04,
        0x00, 0x01, 'x', 'r'
    };
    static const byte connect_sub[] = {
        0x10, 0x0E,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x02, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE filter "x", options = Retain Handling 1 (0x10) | QoS 0. */
    static const byte subscribe_rh1[] = {
        0x82, 0x07,
        0x00, 0x01,
        0x00,
        0x00, 0x01, 'x',
        0x10
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish_retained, sizeof(publish_retained));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_rh1, sizeof(subscribe_rh1));
    mock_client_input_append(1, subscribe_rh1, sizeof(subscribe_rh1));
    for (i = 0; i < 20; i++) {
        MqttBroker_Step(&broker);
    }

    /* Two SUBSCRIBEs -> two SUBACKs, but the retained message is delivered
     * only on the first (new) subscription. */
    ASSERT_EQ(2, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_SUBSCRIBE_ACK));
    ASSERT_EQ(1, count_packets_of_type(g_clients[1].out_buf,
        g_clients[1].out_len, MQTT_PACKET_TYPE_PUBLISH));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_RETAINED && WOLFMQTT_V5 */

#if defined(WOLFMQTT_BROKER_WILL) && !defined(WOLFMQTT_STATIC_MEMORY)
/* BrokerClient_PublishWillImmediate must route a QoS >= 1 Will through the
 * tracked outbound queue, so a subscriber that requested QoS 1 receives the
 * Will as a QoS 1 PUBLISH carrying a Packet Identifier. */
TEST(will_qos1_routes_through_outq)
{
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
    PublishInfo info;
    static const byte sub_connect[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE filter "lwt", QoS 1. */
    static const byte sub_subscribe[] = {
        0x82, 0x08,
        0x00, 0x01,
        0x00, 0x03, 'l', 'w', 't',
        0x01
    };
    /* Publisher CONNECT with a QoS 1 Will: flags = will_flag(0x04) |
     * will_qos1(0x08) | clean_session(0x02) = 0x0E. */
    static const byte pub_connect[] = {
        0x10, 0x17,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x0E, 0x00, 0x3C,
        0x00, 0x01, 'P',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* 0xE1 - DISCONNECT type with reserved bit set -> abnormal close fires
     * the Will. */
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

    ASSERT_EQ(1, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH));
    ASSERT_TRUE(g_clients[1].closed);

    /* The delivered Will must be QoS 1 (out_q route) with a Packet Id. */
    info = first_publish_info(g_clients[0].out_buf, g_clients[0].out_len);
    ASSERT_TRUE(info.found);
    ASSERT_EQ(MQTT_QOS_1, (int)((info.first_byte >> 1) & 0x03));
    ASSERT_NE(0, (int)info.packet_id);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_BROKER_WILL && !WOLFMQTT_STATIC_MEMORY */

#if !defined(WOLFMQTT_STATIC_MEMORY) && (WOLFMQTT_MAX_QOS >= 2)
/* A PUBREC belongs only to a QoS 2 exchange. One arriving for an outbound QoS 1
 * PUBLISH must not advance that entry to PUBREL_SENT nor trigger a PUBREL: the
 * message stays unacknowledged until its PUBACK. */
TEST(pubrec_for_qos1_publish_not_advanced)
{
    MqttBroker broker;
    MqttBrokerNet net;
    BrokerClient* sub_bc;
    word16 packet_id;
    int i;
    byte pubrec[] = { 0x50, 0x02, 0x00, 0x00 };
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish_x[] = {
        0x32, 0x08, 0x00, 0x01, 'x', 0x00, 0x07, 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Subscriber "S" gets one QoS 1 PUBLISH in flight, awaiting PUBACK. */
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    mock_client_input_append(1, publish_x, sizeof(publish_x));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_NOT_NULL(sub_bc->out_q_head);
    ASSERT_EQ(MQTT_QOS_1, (int)sub_bc->out_q_head->qos);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT, sub_bc->out_q_head->state);
    packet_id = sub_bc->out_q_head->packet_id;

    /* The subscriber wrongly answers the QoS 1 PUBLISH with a PUBREC. */
    pubrec[2] = (byte)(packet_id >> 8);
    pubrec[3] = (byte)(packet_id & 0xFF);
    mock_client_input_append(0, pubrec, sizeof(pubrec));
    for (i = 0; i < 8; i++) {
        (void)MqttBroker_Step(&broker);
    }

    /* Pre-fix the entry advanced to PUBREL_SENT and a PUBREL was sent while
     * the connection stayed open. A PUBREC on a QoS 1 PUBLISH is a Protocol
     * Error [MQTT-4.13.1-1]: no PUBREL may be sent and the peer is closed. The
     * persistent session is orphaned with the entry still awaiting its PUBACK.
     * sub_bc is freed by the close, so the entry is inspected via the orphan. */
    ASSERT_EQ(0, count_packets_of_type(g_clients[0].out_buf,
        g_clients[0].out_len, MQTT_PACKET_TYPE_PUBLISH_REL));
    ASSERT_TRUE(g_clients[0].closed);
    ASSERT_EQ(1, broker.orphan_session_count);
    ASSERT_NOT_NULL(broker.orphan_sessions);
    ASSERT_NOT_NULL(broker.orphan_sessions->out_q_head);
    ASSERT_EQ(BROKER_OUTQ_PUBLISH_SENT,
        broker.orphan_sessions->out_q_head->state);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* !WOLFMQTT_STATIC_MEMORY && WOLFMQTT_MAX_QOS >= 2 */

#ifdef WOLFMQTT_BROKER_PERSIST
static int persist_test_write_file(const char* path, const byte* data,
    word32 data_len)
{
    word32 written = 0;
    int fd;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -1;
    }
    while (written < data_len) {
        ssize_t write_len = write(fd, data + written, data_len - written);
        if (write_len <= 0) {
            (void)close(fd);
            return -1;
        }
        written += (word32)write_len;
    }
    return close(fd);
}

typedef struct PersistIterCapture {
    byte key[8];
    byte blob[32];
    word16 key_len;
    word32 blob_len;
    int calls;
} PersistIterCapture;

#ifndef WOLFMQTT_STATIC_MEMORY
#define PERSIST_ORDER_KEY_MAX   16
#define PERSIST_ORDER_BLOB_MAX  128

typedef struct PersistOrderRecord {
    byte key[PERSIST_ORDER_KEY_MAX];
    byte blob[PERSIST_ORDER_BLOB_MAX];
    word16 key_len;
    word32 blob_len;
} PersistOrderRecord;

typedef struct PersistOrderStore {
    PersistOrderRecord meta;
    PersistOrderRecord session;
    PersistOrderRecord subs;
    PersistOrderRecord outq[3];
    int outq_count;
    int reverse_outq;
} PersistOrderStore;

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
static int persist_order_derive_key(void* ctx, byte* out_key, word32 key_len)
{
    (void)ctx;
    XMEMSET(out_key, 0x11, key_len);
    return MQTT_CODE_SUCCESS;
}
#endif

static int persist_order_put(void* ctx, byte ns, const byte* key,
    word16 key_len, const byte* blob, word32 blob_len)
{
    PersistOrderStore* store = (PersistOrderStore*)ctx;
    PersistOrderRecord* record = NULL;

    if (ns == BROKER_PERSIST_NS_META) {
        record = &store->meta;
    }
    else if (ns == BROKER_PERSIST_NS_SESSION) {
        record = &store->session;
    }
    else if (ns == BROKER_PERSIST_NS_SUBS) {
        record = &store->subs;
    }
    else if (ns == BROKER_PERSIST_NS_OUTQ && store->outq_count < 3) {
        record = &store->outq[store->outq_count++];
    }
    if (record == NULL || key_len > sizeof(record->key) ||
            blob_len > sizeof(record->blob)) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMCPY(record->key, key, key_len);
    XMEMCPY(record->blob, blob, blob_len);
    record->key_len = key_len;
    record->blob_len = blob_len;
    return MQTT_CODE_SUCCESS;
}

static int persist_order_get(void* ctx, byte ns, const byte* key,
    word16 key_len, byte* out, word32* inout_len)
{
    PersistOrderStore* store = (PersistOrderStore*)ctx;
    PersistOrderRecord* record = &store->meta;

    if (ns != BROKER_PERSIST_NS_META || record->blob_len == 0 ||
            key_len != record->key_len ||
            XMEMCMP(key, record->key, key_len) != 0) {
        return MQTT_CODE_ERROR_NOT_FOUND;
    }
    if (out == NULL || inout_len == NULL || *inout_len < record->blob_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMCPY(out, record->blob, record->blob_len);
    *inout_len = record->blob_len;
    return MQTT_CODE_SUCCESS;
}

static int persist_order_iter(void* ctx, byte ns,
    MqttBrokerPersist_IterCb cb, void* cb_ctx)
{
    PersistOrderStore* store = (PersistOrderStore*)ctx;
    int i;
    int rc;

    if (ns == BROKER_PERSIST_NS_SESSION && store->session.blob_len > 0) {
        return cb(store->session.key, store->session.key_len,
            store->session.blob, store->session.blob_len, cb_ctx);
    }
    if (ns == BROKER_PERSIST_NS_SUBS && store->subs.blob_len > 0) {
        return cb(store->subs.key, store->subs.key_len,
            store->subs.blob, store->subs.blob_len, cb_ctx);
    }
    if (ns == BROKER_PERSIST_NS_OUTQ) {
        for (i = 0; i < store->outq_count; i++) {
            int index = store->reverse_outq ? store->outq_count - 1 - i : i;

            rc = cb(store->outq[index].key, store->outq[index].key_len,
                store->outq[index].blob, store->outq[index].blob_len, cb_ctx);
            if (rc != 0) {
                return rc;
            }
        }
    }
    return MQTT_CODE_SUCCESS;
}

static BrokerOutPub* persist_order_make_out(const char* topic, MqttQoS qos,
    word16 packet_id)
{
    BrokerOutPub* out = (BrokerOutPub*)WOLFMQTT_MALLOC(sizeof(*out));
    size_t topic_len;

    if (out == NULL) {
        return NULL;
    }
    XMEMSET(out, 0, sizeof(*out));
    topic_len = XSTRLEN(topic);
    out->topic = (char*)WOLFMQTT_MALLOC(topic_len + 1);
    if (out->topic == NULL) {
        WOLFMQTT_FREE(out);
        return NULL;
    }
    XMEMCPY(out->topic, topic, topic_len + 1);
    out->qos = qos;
    out->packet_id = packet_id;
    out->state = BROKER_OUTQ_QUEUED;
    out->protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    return out;
}

/* Counts deletions of durable outbound-queue records so a test can assert an
 * orphan reclaim does not wipe them. */
static int g_reclaim_outq_del;
static int persist_reclaim_kv_del(void* ctx, byte ns, const byte* key,
    word16 key_len)
{
    (void)ctx; (void)key; (void)key_len;
    if (ns == BROKER_PERSIST_NS_OUTQ) {
        g_reclaim_outq_del++;
    }
    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_NONBLOCK
/* A partially transmitted QoS 1 PUBLISH is a retransmission after a broker
 * restart, so its replay must carry DUP=1 [MQTT-3.3.1-1]. */
TEST(persist_partial_publish_restart_keeps_dup)
{
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistOrderStore store;
    BrokerClient* sub_bc;
    PublishInfo info;
    word16 packet_id;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    static const byte publish_x[] = {
        0x32, 0x08,
        0x00, 0x01, 'x', 0x00, 0x07, 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&source, 0, sizeof(source));
    XMEMSET(&restored, 0, sizeof(restored));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&store, 0, sizeof(store));
    hooks.kv_put = persist_order_put;
    hooks.kv_get = persist_order_get;
    hooks.kv_iter = persist_order_iter;
    hooks.ctx = &store;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&source, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&source, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&source));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&source));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&source);
    }
    sub_bc = find_broker_client(&source, "S");
    ASSERT_NOT_NULL(sub_bc);

    g_clients[1].write_limit_once = 1;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&source);
    ASSERT_NOT_NULL(sub_bc->out_q_head);
    ASSERT_EQ(1, sub_bc->out_q_head->retransmit_dup);
    packet_id = sub_bc->out_q_head->packet_id;

    g_clients[1].write_err = 1;
    (void)MqttBroker_Step(&source);
    ASSERT_TRUE(g_clients[1].closed);
    ASSERT_EQ(1, store.outq_count);

    MqttBroker_Stop(&source);
    MqttBroker_Free(&source);

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&restored, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&restored, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&restored));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&restored));
    reset_mock_clients(1);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&restored);
    }

    info = first_publish_info(g_clients[0].out_buf, g_clients[0].out_len);
    ASSERT_TRUE(info.found);
    ASSERT_EQ(0x3A, info.first_byte);
    ASSERT_EQ(packet_id, info.packet_id);

    MqttBroker_Stop(&restored);
    MqttBroker_Free(&restored);
}

#endif

/* Keyed variant: a record written again under the same key replaces it, as a
 * real backend does. persist_order_put appends, which would turn a re-write
 * into a second queue entry. */
static int persist_keyed_put(void* ctx, byte ns, const byte* key,
    word16 key_len, const byte* blob, word32 blob_len)
{
    PersistOrderStore* store = (PersistOrderStore*)ctx;
    int i;

    if (ns == BROKER_PERSIST_NS_OUTQ) {
        for (i = 0; i < store->outq_count; i++) {
            if (store->outq[i].key_len == key_len &&
                    XMEMCMP(store->outq[i].key, key, key_len) == 0) {
                if (blob_len > sizeof(store->outq[i].blob)) {
                    return MQTT_CODE_ERROR_OUT_OF_BUFFER;
                }
                XMEMCPY(store->outq[i].blob, blob, blob_len);
                store->outq[i].blob_len = blob_len;
                return MQTT_CODE_SUCCESS;
            }
        }
    }
    return persist_order_put(ctx, ns, key, key_len, blob, blob_len);
}

#if WOLFMQTT_MAX_QOS >= 1
/* The same requirement when the Session hand-off takes the queue mid-write.
 * BrokerOrphan_Take shadow-writes each entry before that write returns, so the
 * stored copy still says it was never sent; the completed delivery has to be
 * written through, or a restart before reconnect re-sends it without DUP
 * [MQTT-3.3.1-1]. */
TEST(persist_handoff_sent_qos1_restart_keeps_dup)
{
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistOrderStore store;
    BrokerClient* sub_bc;
    PublishInfo info;
    word16 packet_id;
    int i;
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    /* CleanSession=0, so the Session survives and has a carrier. */
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    static const byte publish_x[] = {
        0x32, 0x08, 0x00, 0x01, 'x', 0x00, 0x07, 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&source, 0, sizeof(source));
    XMEMSET(&restored, 0, sizeof(restored));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&store, 0, sizeof(store));
    hooks.kv_put = persist_keyed_put;
    hooks.kv_get = persist_order_get;
    hooks.kv_iter = persist_order_iter;
    hooks.ctx = &store;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&source, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&source, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&source));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&source));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, connect_sub, sizeof(connect_sub));
    mock_client_input_append(1, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&source);
    }
    sub_bc = find_broker_client(&source, "S");
    ASSERT_NOT_NULL(sub_bc);

    /* The hand-off runs from inside the write, which then completes. */
    broker_test_watch_free(NULL);
    g_handoff_broker = &source;
    g_handoff_client = sub_bc;
    g_write_publish_hook = handoff_out_queue_mid_write;
    mock_client_input_append(0, publish_x, sizeof(publish_x));
    (void)MqttBroker_Step(&source);
    ASSERT_NULL(g_write_publish_hook);
    g_handoff_broker = NULL;
    g_handoff_client = NULL;

    ASSERT_NOT_NULL(source.orphan_sessions);
    ASSERT_NOT_NULL(source.orphan_sessions->out_q_head);
    ASSERT_EQ(1, (int)source.orphan_sessions->out_q_head->retransmit_dup);
    packet_id = source.orphan_sessions->out_q_head->packet_id;
    ASSERT_EQ(1, store.outq_count);

    MqttBroker_Stop(&source);
    MqttBroker_Free(&source);

    /* Restart before the subscriber reconnects. */
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&restored, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&restored, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&restored));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&restored));
    reset_mock_clients(1);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&restored);
    }

    info = first_publish_info(g_clients[0].out_buf, g_clients[0].out_len);
    ASSERT_TRUE(info.found);
    /* 0x3A = PUBLISH | DUP | QoS 1. */
    ASSERT_EQ(0x3A, info.first_byte);
    ASSERT_EQ(packet_id, info.packet_id);

    MqttBroker_Stop(&restored);
    MqttBroker_Free(&restored);
}
#endif /* WOLFMQTT_MAX_QOS >= 1 */

#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL) && \
    WOLFMQTT_MAX_QOS >= 1
/* A Will queued for an offline v5 Session keeps its Properties across a
 * broker restart (MQTT 5.0 section 3.1.3.2), and the forwarded Message
 * Expiry Interval is reduced by the time waited [MQTT-3.3.2-6]. */
TEST(persist_restart_keeps_queued_will_props)
{
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistOrderStore store;
    const byte* out;
    size_t out_len;
    size_t pos;
    int found = 0;
    int i;
    /* v5 CONNECT, Clean Start 0, Properties length 5 holding Session Expiry
     * Interval 300 (0x11), ClientId "S". Remaining Length 19. */
    static const byte connect_sub[] = {
        0x10, 0x13,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x00, 0x00, 0x3C,
        0x05, 0x11, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x01, 'S'
    };
    /* v5 SUBSCRIBE packet id 1, Properties length 0, filter "lwt", QoS 1 */
    static const byte subscribe_lwt[] = {
        0x82, 0x09, 0x00, 0x01, 0x00, 0x00, 0x03, 'l', 'w', 't', 0x01
    };
    static const byte disconnect[] = { 0xE0, 0x00 };
    /* v5 CONNECT: Will Flag, Will QoS 1 and Clean Start, no CONNECT
     * properties, ClientId "P", Will Properties length 16 holding Message
     * Expiry Interval (0x02) 60, Content Type (0x03) "t" and User Property
     * (0x26) "k"="v", Will Topic "lwt", Will Payload "bye".
     * Remaining Length 41. */
    static const byte connect_pub[] = {
        0x10, 0x29,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x05, 0x0E, 0x00, 0x3C,
        0x00,
        0x00, 0x01, 'P',
        0x10,
        0x02, 0x00, 0x00, 0x00, 0x3C,
        0x03, 0x00, 0x01, 't',
        0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v',
        0x00, 0x03, 'l', 'w', 't',
        0x00, 0x03, 'b', 'y', 'e'
    };
    /* Forwarded PUBLISH QoS 1 (MQTT 5.0 section 3.3), Remaining Length 27:
     * topic "lwt", a broker-assigned packet id (skipped), then this. The
     * Message Expiry Interval is 60 less the 4 seconds waited. */
    static const byte expected_props[] = {
        0x10,
        0x02, 0x00, 0x00, 0x00, 0x38,
        0x03, 0x00, 0x01, 't',
        0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v',
        'b', 'y', 'e'
    };

    install_mock_net(&net);
    XMEMSET(&source, 0, sizeof(source));
    XMEMSET(&restored, 0, sizeof(restored));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&store, 0, sizeof(store));
    hooks.kv_put = persist_order_put;
    hooks.kv_get = persist_order_get;
    hooks.kv_iter = persist_order_iter;
    hooks.ctx = &store;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    g_broker_time_s = 100;
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&source, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&source, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&source));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&source));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_lwt, sizeof(subscribe_lwt));
    mock_client_input_append(0, disconnect, sizeof(disconnect));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&source);
    }
    g_clients[1].read_err = 1;
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&source);
    }
    ASSERT_EQ(1, store.outq_count);
    MqttBroker_Stop(&source);
    MqttBroker_Free(&source);

    g_broker_time_s += 4;
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&restored, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&restored, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&restored));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&restored));
    reset_mock_clients(1);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&restored);
    }

    out = g_clients[0].out_buf;
    out_len = g_clients[0].out_len;
    for (pos = 0; pos + 9 + sizeof(expected_props) <= out_len; pos++) {
        if ((out[pos] & 0xF7) == 0x32 && out[pos + 1] == 0x1B &&
                XMEMCMP(&out[pos + 2], "\x00\x03lwt", 5) == 0 &&
                XMEMCMP(&out[pos + 9], expected_props,
                    sizeof(expected_props)) == 0) {
            found = 1;
            break;
        }
    }
    g_broker_time_s = 0;
    ASSERT_EQ(1, found);

    MqttBroker_Stop(&restored);
    MqttBroker_Free(&restored);
}
#endif

/* Non-persisted QoS 0 nodes still occupy FIFO positions. Assigning sequence
 * numbers only to durable nodes can make a later offline QoS 1 enqueue reuse
 * an earlier sequence and restore ahead of older messages. */
TEST(persist_mixed_qos_queue_preserves_fifo)
{
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistOrderStore store;
    BrokerClient* sub_bc;
    BrokerOrphanSession* orphan;
    BrokerOutPub* first;
    BrokerOutPub* second;
    BrokerOutPub* volatile_tail;
    int i;
    static const byte connect_sub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_t[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 't', 0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish_t[] = {
        0x32, 0x06, 0x00, 0x01, 't', 0x00, 0x07, 'p'
    };

    install_mock_net(&net);
    XMEMSET(&source, 0, sizeof(source));
    XMEMSET(&restored, 0, sizeof(restored));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&store, 0, sizeof(store));
    hooks.kv_put = persist_order_put;
    hooks.kv_get = persist_order_get;
    hooks.kv_iter = persist_order_iter;
    hooks.ctx = &store;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&source, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&source, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&source));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&source));
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_t, sizeof(subscribe_t));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&source);
    }
    sub_bc = find_broker_client(&source, "S");
    ASSERT_NOT_NULL(sub_bc);

    first = persist_order_make_out("first", MQTT_QOS_1, 10);
    second = persist_order_make_out("second", MQTT_QOS_1, 11);
    volatile_tail = persist_order_make_out("volatile", MQTT_QOS_0, 0);
    ASSERT_NOT_NULL(first);
    ASSERT_NOT_NULL(second);
    ASSERT_NOT_NULL(volatile_tail);
    first->next = second;
    second->next = volatile_tail;
    sub_bc->out_q_head = first;
    sub_bc->out_q_tail = volatile_tail;
    sub_bc->out_q_count = 3;

    sub_bc->connected = 0;
    g_clients[0].read_err = 1;
    (void)MqttBroker_Step(&source);
    ASSERT_EQ(1, source.orphan_session_count);
    orphan = source.orphan_sessions;
    ASSERT_NOT_NULL(orphan);

    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    mock_client_input_append(1, publish_t, sizeof(publish_t));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&source);
    }
    ASSERT_EQ(4, orphan->out_q_count);
    ASSERT_NOT_NULL(orphan->out_q_tail);
    ASSERT_EQ(4, orphan->out_q_tail->enqueue_seq);
    ASSERT_EQ(3, store.outq_count);

    MqttBroker_Stop(&source);
    MqttBroker_Free(&source);

    /* Storage iteration order is not defined. Restore must sort by the durable
     * enqueue sequence rather than trusting backend insertion order. */
    store.reverse_outq = 1;
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&restored, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&restored, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&restored));
    orphan = restored.orphan_sessions;
    ASSERT_NOT_NULL(orphan);
    ASSERT_EQ(3, orphan->out_q_count);
    ASSERT_NOT_NULL(orphan->out_q_head);
    ASSERT_TRUE(XSTRCMP("first", orphan->out_q_head->topic) == 0);
    ASSERT_NOT_NULL(orphan->out_q_head->next);
    ASSERT_TRUE(XSTRCMP("second", orphan->out_q_head->next->topic) == 0);
    ASSERT_NOT_NULL(orphan->out_q_tail);
    ASSERT_TRUE(XSTRCMP("t", orphan->out_q_tail->topic) == 0);

    MqttBroker_Free(&restored);
}

/* An orphan reclaim must keep the durable outbound-queue records: each is
 * removed only by its own terminal acknowledgement. Wiping them at reclaim
 * loses every unacknowledged QoS message if the broker restarts after the
 * reclaim but before the resumed session acknowledges. */
TEST(orphan_reclaim_keeps_persisted_outq)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistOrderStore store;
    BrokerClient* sub_bc;
    int i;
    static const byte connect_sub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    static const byte connect_pub[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish_x[] = {
        0x32, 0x08, 0x00, 0x01, 'x', 0x00, 0x07, 'A', 'B', 'C'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&store, 0, sizeof(store));
    hooks.kv_put = persist_order_put;
    hooks.kv_get = persist_order_get;
    hooks.kv_del = persist_reclaim_kv_del;
    hooks.kv_iter = persist_order_iter;
    hooks.ctx = &store;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    /* Persistent subscriber "S" subscribes; publisher "P" sends one QoS 1
     * message. The subscriber never PUBACKs, so it stays persisted and
     * unacknowledged. */
    reset_mock_clients(2);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    mock_client_input_append(1, connect_pub, sizeof(connect_pub));
    for (i = 0; i < 16; i++) {
        (void)MqttBroker_Step(&broker);
    }
    sub_bc = find_broker_client(&broker, "S");
    ASSERT_NOT_NULL(sub_bc);
    mock_client_input_append(1, publish_x, sizeof(publish_x));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_NOT_NULL(sub_bc->out_q_head);

    /* Drop the subscriber so its session is orphaned; BrokerOrphan_Take
     * shadow-writes the unacknowledged QoS 1 message to durable storage. */
    sub_bc->connected = 0;
    g_clients[0].read_err = 1;
    (void)MqttBroker_Step(&broker);
    ASSERT_EQ(1, broker.orphan_session_count);
    ASSERT_EQ(1, store.outq_count);

    /* Reconnect the same persistent client id, which reclaims the orphan. The
     * reclaim must not delete the durable OUTQ records. */
    g_reclaim_outq_del = 0;
    reset_mock_clients(1);
    mock_client_input_append(0, connect_sub, sizeof(connect_sub));
    for (i = 0; i < 12; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(0, broker.orphan_session_count);
    ASSERT_EQ(0, g_reclaim_outq_del);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

TEST(persist_restore_packet_id_wrap_preserves_fifo)
{
    MqttBroker source;
    MqttBroker restored;
    MqttBroker restored_again;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistOrderStore store;
    BrokerOutPub out;
    BrokerOrphanSession* orphan;
    BrokerSub* sub;
    int i;
    char topic[] = "t";
    static const byte connect_pub[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3C,
        0x00, 0x01, 'P'
    };
    static const byte publish[] = {
        0x32, 0x06, 0x00, 0x01, 't', 0x00, 0x07, 'p'
    };

    install_mock_net(&net);
    XMEMSET(&source, 0, sizeof(source));
    XMEMSET(&restored, 0, sizeof(restored));
    XMEMSET(&restored_again, 0, sizeof(restored_again));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&store, 0, sizeof(store));
    hooks.kv_put = persist_order_put;
    hooks.kv_get = persist_order_get;
    hooks.kv_iter = persist_order_iter;
    hooks.ctx = &store;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&source, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&source, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&source));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutOrphanSession(&source,
        "cid", MQTT_CONNECT_PROTOCOL_LEVEL_4, 0xFFFFFFFFu,
        (WOLFMQTT_BROKER_TIME_T)1));
    sub = (BrokerSub*)WOLFMQTT_MALLOC(sizeof(*sub));
    ASSERT_NOT_NULL(sub);
    XMEMSET(sub, 0, sizeof(*sub));
    sub->filter = (char*)WOLFMQTT_MALLOC(2);
    sub->client_id = (char*)WOLFMQTT_MALLOC(4);
    ASSERT_NOT_NULL(sub->filter);
    ASSERT_NOT_NULL(sub->client_id);
    XMEMCPY(sub->filter, "t", 2);
    XMEMCPY(sub->client_id, "cid", 4);
    sub->qos = MQTT_QOS_1;
    source.subs = sub;
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutSubs(&source, "cid"));

    XMEMSET(&out, 0, sizeof(out));
    out.topic = topic;
    out.qos = MQTT_QOS_1;
    out.state = BROKER_OUTQ_QUEUED;
    out.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    out.enq_time = (WOLFMQTT_BROKER_TIME_T)1;
    out.enqueue_seq = 1;
    out.packet_id = 1;
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        BrokerPersist_PutOutPub(&source, "cid", &out));
    out.enqueue_seq = 2;
    out.packet_id = 0xFFFF;
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        BrokerPersist_PutOutPub(&source, "cid", &out));

    store.reverse_outq = 1;
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&restored, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&restored, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&restored));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&restored));

    g_broker_time_s = 1;
    reset_mock_clients(1);
    mock_client_input_append(0, connect_pub, sizeof(connect_pub));
    mock_client_input_append(0, publish, sizeof(publish));
    for (i = 0; i < 16; i++) {
        MqttBroker_Step(&restored);
    }

    orphan = restored.orphan_sessions;
    ASSERT_NOT_NULL(orphan);
    ASSERT_EQ(3, orphan->out_q_count);
    ASSERT_NOT_NULL(orphan->out_q_tail);
    ASSERT_EQ(2, orphan->out_q_tail->packet_id);

    MqttBroker_Stop(&restored);
    MqttBroker_Free(&restored);

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&restored_again, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&restored_again, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&restored_again));

    orphan = restored_again.orphan_sessions;
    ASSERT_NOT_NULL(orphan);
    ASSERT_EQ(3, orphan->out_q_count);
    ASSERT_NOT_NULL(orphan->out_q_head);
    ASSERT_EQ(1, orphan->out_q_head->packet_id);
    ASSERT_NOT_NULL(orphan->out_q_head->next);
    ASSERT_EQ(0xFFFF, orphan->out_q_head->next->packet_id);
    ASSERT_NOT_NULL(orphan->out_q_tail);
    ASSERT_EQ(2, orphan->out_q_tail->packet_id);

    MqttBroker_Free(&restored_again);
    MqttBroker_Free(&source);
}

/* An OUTQ record is keyed by client_id || 0x00 || Packet Identifier and also
 * carries the identifier in its body. Restore must only load a record whose
 * two copies agree and are non-zero ([MQTT-2.2.1-3]: a QoS > 0 PUBLISH has a
 * non-zero Packet Identifier). A record whose key disagrees with its body
 * could not be deleted by the identifier it would be acknowledged under, and
 * could collide with another queued entry. */
TEST(persist_restore_rejects_outq_packet_id_mismatch)
{
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistOrderStore store;
    BrokerOutPub out;
    BrokerOrphanSession* orphan;
    PersistOrderRecord* rec;
    char topic[] = "t";

    install_mock_net(&net);
    XMEMSET(&source, 0, sizeof(source));
    XMEMSET(&restored, 0, sizeof(restored));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&store, 0, sizeof(store));
    hooks.kv_put = persist_order_put;
    hooks.kv_get = persist_order_get;
    hooks.kv_iter = persist_order_iter;
    hooks.ctx = &store;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&source, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&source, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&source));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutOrphanSession(&source,
        "cid", MQTT_CONNECT_PROTOCOL_LEVEL_4, 0xFFFFFFFFu,
        (WOLFMQTT_BROKER_TIME_T)1));

    XMEMSET(&out, 0, sizeof(out));
    out.topic = topic;
    out.qos = MQTT_QOS_1;
    out.state = BROKER_OUTQ_QUEUED;
    out.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    out.enq_time = (WOLFMQTT_BROKER_TIME_T)1;
    /* Packet Identifier 1: valid. */
    out.enqueue_seq = 1;
    out.packet_id = 1;
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        BrokerPersist_PutOutPub(&source, "cid", &out));
    /* Packet Identifier 2, then its key retagged to 3. */
    out.enqueue_seq = 2;
    out.packet_id = 2;
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        BrokerPersist_PutOutPub(&source, "cid", &out));
    /* Packet Identifier 0 in both key and body. */
    out.enqueue_seq = 3;
    out.packet_id = 0;
    (void)BrokerPersist_PutOutPub(&source, "cid", &out);
    ASSERT_EQ(3, store.outq_count);

    rec = &store.outq[1];
    ASSERT_EQ(3 + 3, (int)rec->key_len);   /* "cid" 0x00 pid_hi pid_lo */
    ASSERT_EQ(0x02, rec->key[5]);
    rec->key[5] = 0x03;

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&restored, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&restored, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&restored));

    orphan = restored.orphan_sessions;
    ASSERT_NOT_NULL(orphan);
    ASSERT_EQ(1, orphan->out_q_count);
    ASSERT_NOT_NULL(orphan->out_q_head);
    ASSERT_EQ(1, orphan->out_q_head->packet_id);

    MqttBroker_Free(&restored);
    MqttBroker_Free(&source);
}

typedef struct PersistSubsCount {
    int puts;
    int dels;
} PersistSubsCount;

static int persist_subs_count_put(void* ctx, byte ns, const byte* key,
    word16 key_len, const byte* blob, word32 blob_len)
{
    (void)key;
    (void)key_len;
    (void)blob;
    (void)blob_len;
    if (ns == BROKER_PERSIST_NS_SUBS) {
        ((PersistSubsCount*)ctx)->puts++;
    }
    return MQTT_CODE_SUCCESS;
}

static int persist_subs_count_get(void* ctx, byte ns, const byte* key,
    word16 key_len, byte* out, word32* inout_len)
{
    (void)ctx;
    (void)ns;
    (void)key;
    (void)key_len;
    (void)out;
    (void)inout_len;
    return MQTT_CODE_ERROR_NOT_FOUND;
}

static int persist_subs_count_del(void* ctx, byte ns, const byte* key,
    word16 key_len)
{
    (void)key;
    (void)key_len;
    if (ns == BROKER_PERSIST_NS_SUBS) {
        ((PersistSubsCount*)ctx)->dels++;
    }
    return MQTT_CODE_SUCCESS;
}

static int persist_subs_count_iter(void* ctx, byte ns,
    MqttBrokerPersist_IterCb cb, void* cb_ctx)
{
    (void)ctx;
    (void)ns;
    (void)cb;
    (void)cb_ctx;
    return MQTT_CODE_SUCCESS;
}

/* SUBSCRIBE and UNSUBSCRIBE change the Session's subscription list before
 * the SUBACK or UNSUBACK is written, so the persisted list must follow the
 * change even when that write fails and the connection closes; otherwise a
 * restart restores the list from before the change. */
TEST(persist_subs_written_when_ack_write_fails)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistSubsCount count;
    int i;
    int puts_before;
    /* v3.1.1 CONNECT, CleanSession=0, keep alive 60, ClientId "S" */
    static const byte connect_s[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet id 1, filter "x", QoS 1 (MQTT 3.1.1 section 3.8) */
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&count, 0, sizeof(count));
    hooks.kv_put = persist_subs_count_put;
    hooks.kv_get = persist_subs_count_get;
    hooks.kv_del = persist_subs_count_del;
    hooks.kv_iter = persist_subs_count_iter;
    hooks.ctx = &count;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect_s, sizeof(connect_s));
    run_broker_one_connect(&broker);
    ASSERT_EQ(1, count_packets_of_type(g_out_buf, g_out_len,
        MQTT_PACKET_TYPE_CONNECT_ACK));

    /* The SUBACK write fails and the connection closes. */
    puts_before = count.puts;
    g_clients[0].write_err_pending = 1;
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_TRUE(count.puts > puts_before);

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}

#ifdef WOLFMQTT_NONBLOCK
/* A SUBACK or UNSUBACK whose write is deferred must still shadow-write the
 * persistent session's subscription list; otherwise a restart restores the
 * list from before the change. */
TEST(persist_subs_written_when_ack_deferred)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    PersistSubsCount count;
    int i;
    int puts_before;
    int dels_before;
    /* v3.1.1 CONNECT, CleanSession=0, keep alive 60, ClientId "S" */
    static const byte connect_s[] = {
        0x10, 0x0D,
        0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x00, 0x00, 0x3C,
        0x00, 0x01, 'S'
    };
    /* SUBSCRIBE packet id 1, filter "x", QoS 1 (MQTT 3.1.1 section 3.8) */
    static const byte subscribe_x[] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'x', 0x01
    };
    /* UNSUBSCRIBE packet id 2, filter "x" (MQTT 3.1.1 section 3.10) */
    static const byte unsubscribe_x[] = {
        0xA2, 0x05, 0x00, 0x02, 0x00, 0x01, 'x'
    };

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&count, 0, sizeof(count));
    hooks.kv_put = persist_subs_count_put;
    hooks.kv_get = persist_subs_count_get;
    hooks.kv_del = persist_subs_count_del;
    hooks.kv_iter = persist_subs_count_iter;
    hooks.ctx = &count;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = persist_order_derive_key;
#endif

    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Start(&broker));

    reset_mock_state(connect_s, sizeof(connect_s));
    run_broker_one_connect(&broker);
    ASSERT_EQ(1, count_packets_of_type(g_out_buf, g_out_len,
        MQTT_PACKET_TYPE_CONNECT_ACK));

    /* SUBACK write defers */
    puts_before = count.puts;
    g_clients[0].write_continue = 1;
    mock_client_input_append(0, subscribe_x, sizeof(subscribe_x));
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(puts_before + 1, count.puts);

    g_clients[0].write_continue = 0;
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_out_buf, g_out_len,
        MQTT_PACKET_TYPE_SUBSCRIBE_ACK));

    /* UNSUBACK write defers; the now empty list is deleted */
    dels_before = count.dels;
    g_clients[0].write_continue = 1;
    mock_client_input_append(0, unsubscribe_x, sizeof(unsubscribe_x));
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(dels_before + 1, count.dels);

    g_clients[0].write_continue = 0;
    for (i = 0; i < 4; i++) {
        (void)MqttBroker_Step(&broker);
    }
    ASSERT_EQ(1, count_packets_of_type(g_out_buf, g_out_len,
        MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK));

    MqttBroker_Stop(&broker);
    MqttBroker_Free(&broker);
}
#endif /* WOLFMQTT_NONBLOCK */
#endif

static int persist_test_stream_open(void* ctx, byte ns, const byte* key,
    word16 key_len, int mode, void** handle)
{
    int* calls = (int*)ctx;

    (void)ns;
    (void)key;
    (void)key_len;
    (void)mode;
    (void)handle;
    (*calls)++;
    return MQTT_CODE_SUCCESS;
}

static int persist_test_stream_read(void* ctx, void* handle, byte* buf,
    word32 len, word32* out_len)
{
    int* calls = (int*)ctx;

    (void)handle;
    (void)buf;
    (void)len;
    (void)out_len;
    (*calls)++;
    return MQTT_CODE_SUCCESS;
}

static int persist_test_stream_write(void* ctx, void* handle,
    const byte* buf, word32 len)
{
    int* calls = (int*)ctx;

    (void)handle;
    (void)buf;
    (void)len;
    (*calls)++;
    return MQTT_CODE_SUCCESS;
}

static int persist_test_stream_close(void* ctx, void* handle)
{
    int* calls = (int*)ctx;

    (void)handle;
    (*calls)++;
    return MQTT_CODE_SUCCESS;
}

TEST(persist_stream_only_hooks_rejected)
{
    MqttBroker broker;
    MqttBrokerPersistHooks hooks;
    int calls = 0;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    hooks.stream_open = persist_test_stream_open;
    hooks.stream_read = persist_test_stream_read;
    hooks.stream_write = persist_test_stream_write;
    hooks.stream_close = persist_test_stream_close;
    hooks.ctx = &calls;

    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG,
        MqttBroker_SetPersistHooks(&broker, &hooks));
    ASSERT_NULL(broker.persist);
    ASSERT_EQ(0, calls);
}

static int persist_test_kv_put_noop(void* ctx, byte ns, const byte* key,
    word16 key_len, const byte* blob, word32 blob_len)
{
    (void)ctx;
    (void)ns;
    (void)key;
    (void)key_len;
    (void)blob;
    (void)blob_len;
    return MQTT_CODE_SUCCESS;
}

static int persist_test_kv_get_not_found(void* ctx, byte ns, const byte* key,
    word16 key_len, byte* out, word32* inout_len)
{
    (void)ctx;
    (void)ns;
    (void)key;
    (void)key_len;
    (void)out;
    (void)inout_len;
    return MQTT_CODE_ERROR_NOT_FOUND;
}

static int persist_test_kv_del_noop(void* ctx, byte ns, const byte* key,
    word16 key_len)
{
    (void)ctx;
    (void)ns;
    (void)key;
    (void)key_len;
    return MQTT_CODE_SUCCESS;
}

static int persist_test_kv_iter_noop(void* ctx, byte ns,
    MqttBrokerPersist_IterCb cb, void* cb_ctx)
{
    (void)ctx;
    (void)ns;
    (void)cb;
    (void)cb_ctx;
    return MQTT_CODE_SUCCESS;
}

/* Deprecated stream members may coexist with a complete KV backend. The
 * broker uses only the KV family, so rejecting this previously supported
 * mixed structure would be an unnecessary API compatibility break. */
TEST(persist_mixed_kv_and_stream_hooks_accepted)
{
    MqttBroker broker;
    MqttBrokerPersistHooks hooks;
    int calls = 0;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    hooks.kv_put = persist_test_kv_put_noop;
    hooks.kv_get = persist_test_kv_get_not_found;
    hooks.kv_del = persist_test_kv_del_noop;
    hooks.kv_iter = persist_test_kv_iter_noop;
    hooks.stream_open = persist_test_stream_open;
    hooks.stream_read = persist_test_stream_read;
    hooks.stream_write = persist_test_stream_write;
    hooks.stream_close = persist_test_stream_close;
    hooks.ctx = &calls;

    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&broker, &hooks));
    ASSERT_TRUE(broker.persist == &hooks);
    ASSERT_EQ(0, calls);
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
static int persist_test_put_noop(void* ctx, byte ns, const byte* key,
    word16 key_len, const byte* blob, word32 blob_len)
{
    (void)ctx;
    (void)ns;
    (void)key;
    (void)key_len;
    (void)blob;
    (void)blob_len;
    return MQTT_CODE_SUCCESS;
}

static int persist_test_derive_partial_failure(void* ctx, byte* out_key,
    word32 key_len)
{
    (void)ctx;
    XMEMSET(out_key, 0xA5, key_len / 2);
    return MQTT_CODE_ERROR_SYSTEM;
}

static int persist_test_derive_success(void* ctx, byte* out_key,
    word32 key_len)
{
    (void)ctx;
    XMEMSET(out_key, 0x11, key_len);
    return MQTT_CODE_SUCCESS;
}

typedef struct PersistKeyDeriveCtx {
    byte fill;
    int calls;
} PersistKeyDeriveCtx;

static int persist_test_derive_from_ctx(void* ctx, byte* out_key,
    word32 key_len)
{
    PersistKeyDeriveCtx* derive = (PersistKeyDeriveCtx*)ctx;

    derive->calls++;
    XMEMSET(out_key, derive->fill, key_len);
    return MQTT_CODE_SUCCESS;
}

static int persist_test_get_bad_tag(void* ctx, byte ns, const byte* key,
    word16 key_len, byte* out, word32* inout_len)
{
    const word32 encrypted_meta_len = 44;

    (void)ctx;
    (void)ns;
    (void)key;
    (void)key_len;
    if (out == NULL || inout_len == NULL ||
            *inout_len < encrypted_meta_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMSET(out, 0xA5, encrypted_meta_len);
    *inout_len = encrypted_meta_len;
    return MQTT_CODE_SUCCESS;
}

TEST(persist_failed_key_derivation_scrubs_cache)
{
    MqttBroker broker;
    MqttBrokerPersistHooks hooks;
    int rc;
    word32 i;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    hooks.kv_put = persist_test_put_noop;
    hooks.derive_key = persist_test_derive_partial_failure;
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker, &hooks));

    rc = BrokerPersist_PutOrphanSession(&broker, "client", 4, 60,
        (WOLFMQTT_BROKER_TIME_T)1);
    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, rc);
    ASSERT_EQ(0, broker.persist_key_loaded);
    for (i = 0; i < (word32)sizeof(broker.persist_key_cache); i++) {
        ASSERT_EQ(0, broker.persist_key_cache[i]);
    }
}

TEST(persist_bad_tag_scrubs_plaintext_before_free)
{
    MqttBroker broker;
    MqttBrokerPersistHooks hooks;
    int rc;
    int capture_seen;
    size_t i;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&hooks, 0, sizeof(hooks));
    hooks.kv_get = persist_test_get_bad_tag;
    hooks.derive_key = persist_test_derive_success;
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker, &hooks));

    /* 44 encrypted META bytes decode into a 16-byte plaintext allocation. */
    broker_test_capture_free(16);
    rc = BrokerPersist_Restore(&broker);
    capture_seen = g_capture_free_seen;
    broker_test_disable_free_capture();

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_TRUE(capture_seen);
    ASSERT_EQ(16, g_capture_freed_len);
    for (i = 0; i < g_capture_freed_len; i++) {
        ASSERT_EQ(0, g_capture_freed[i]);
    }
}

TEST(persist_hook_replacement_rekeys_cache)
{
    MqttBroker broker;
    MqttBrokerPersistHooks first_hooks;
    MqttBrokerPersistHooks second_hooks;
    PersistKeyDeriveCtx first_ctx;
    PersistKeyDeriveCtx second_ctx;
    word32 i;

    XMEMSET(&broker, 0, sizeof(broker));
    XMEMSET(&first_hooks, 0, sizeof(first_hooks));
    XMEMSET(&second_hooks, 0, sizeof(second_hooks));
    XMEMSET(&first_ctx, 0, sizeof(first_ctx));
    XMEMSET(&second_ctx, 0, sizeof(second_ctx));
    first_ctx.fill = 0x11;
    second_ctx.fill = 0x22;
    first_hooks.kv_put = persist_test_put_noop;
    first_hooks.derive_key = persist_test_derive_from_ctx;
    first_hooks.ctx = &first_ctx;
    second_hooks.kv_put = persist_test_put_noop;
    second_hooks.derive_key = persist_test_derive_from_ctx;
    second_hooks.ctx = &second_ctx;

    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&broker, &first_hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutOrphanSession(&broker,
        "first", MQTT_CONNECT_PROTOCOL_LEVEL_4, 60,
        (WOLFMQTT_BROKER_TIME_T)1));
    ASSERT_EQ(1, first_ctx.calls);
    ASSERT_EQ(1, broker.persist_key_loaded);
    for (i = 0; i < (word32)sizeof(broker.persist_key_cache); i++) {
        ASSERT_EQ(0x11, broker.persist_key_cache[i]);
    }

    ASSERT_EQ(MQTT_CODE_SUCCESS,
        MqttBroker_SetPersistHooks(&broker, &second_hooks));
    ASSERT_EQ(0, broker.persist_key_loaded);
    for (i = 0; i < (word32)sizeof(broker.persist_key_cache); i++) {
        ASSERT_EQ(0, broker.persist_key_cache[i]);
    }

    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutOrphanSession(&broker,
        "second", MQTT_CONNECT_PROTOCOL_LEVEL_4, 60,
        (WOLFMQTT_BROKER_TIME_T)2));
    ASSERT_EQ(1, first_ctx.calls);
    ASSERT_EQ(1, second_ctx.calls);
    ASSERT_EQ(1, broker.persist_key_loaded);
    for (i = 0; i < (word32)sizeof(broker.persist_key_cache); i++) {
        ASSERT_EQ(0x22, broker.persist_key_cache[i]);
    }
}
#endif /* WOLFMQTT_BROKER_PERSIST_ENCRYPT */

static int persist_test_iter_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* ctx)
{
    PersistIterCapture* capture = (PersistIterCapture*)ctx;

    if (key_len <= sizeof(capture->key) &&
            blob_len <= sizeof(capture->blob)) {
        XMEMCPY(capture->key, key, key_len);
        XMEMCPY(capture->blob, blob, blob_len);
        capture->key_len = key_len;
        capture->blob_len = blob_len;
    }
    capture->calls++;
    return 0;
}

TEST(persist_parent_component_rejected_as_bad_argument)
{
    MqttBrokerPersistHooks hooks;
    int rc;

    XMEMSET(&hooks, 0, sizeof(hooks));
    rc = MqttBrokerNet_PersistPosix_Init(&hooks,
        "../wolfmqtt-persist-invalid");
    if (rc == MQTT_CODE_SUCCESS) {
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }
    ASSERT_EQ(MQTT_CODE_ERROR_BAD_ARG, rc);
}

TEST(persist_iter_skips_fifo_without_blocking)
{
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    char fifo_path[680];
    MqttBrokerPersistHooks hooks;
    PersistIterCapture capture;
    char* root;
    pid_t child;
    pid_t waited;
    int status = 0;
    int paths_ok = 0;
    int init_rc;

    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&capture, 0, sizeof(capture));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    if (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0 &&
            snprintf(fifo_path, sizeof(fifo_path), "%s/1234.bin",
                ns_path) > 0) {
        paths_ok = 1;
    }
    ASSERT_TRUE(paths_ok);
    ASSERT_EQ(0, mkdir(ns_path, 0700));
    ASSERT_EQ(0, mkfifo(fifo_path, 0600));

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        int iter_rc;

        (void)alarm(2);
        iter_rc = hooks.kv_iter(hooks.ctx, 7, persist_test_iter_cb, &capture);
        _exit((iter_rc == MQTT_CODE_SUCCESS && capture.calls == 0) ? 0 : 1);
    }
    waited = waitpid(child, &status, 0);

    MqttBrokerNet_PersistPosix_Free(&hooks);
    (void)unlink(fifo_path);
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_EQ((int)child, (int)waited);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));
}

/* kv_iter and kv_del take the same opaque key bytes, so any key the POSIX
 * backend yields while iterating must be removable through kv_del; the static
 * DelOutQueue loop repeats iterate-and-delete until nothing matches and would
 * otherwise never finish. The broker names records in lowercase hex, so a
 * record file named in uppercase hex (created outside the broker) must not
 * be yielded as a key that kv_del then cannot find. */
TEST(persist_iter_keys_are_deletable)
{
    static const byte blob[] = "x";
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    char rec_path[680];
    MqttBrokerPersistHooks hooks;
    PersistIterCapture capture;
    char* root;
    FILE* f;
    int paths_ok = 0;
    int init_rc;
    int iter1_rc = MQTT_CODE_ERROR_SYSTEM;
    int del_rc = MQTT_CODE_SUCCESS;
    int iter2_rc = MQTT_CODE_ERROR_SYSTEM;
    int iter2_calls = -1;

    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&capture, 0, sizeof(capture));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    if (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0 &&
            snprintf(rec_path, sizeof(rec_path), "%s/ABCD.bin",
                ns_path) > 0) {
        paths_ok = 1;
    }
    ASSERT_TRUE(paths_ok);
    ASSERT_EQ(0, mkdir(ns_path, 0700));
    f = fopen(rec_path, "wb");
    ASSERT_NOT_NULL(f);
    ASSERT_EQ(sizeof(blob), fwrite(blob, 1, sizeof(blob), f));
    ASSERT_EQ(0, fclose(f));

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        iter1_rc = hooks.kv_iter(hooks.ctx, 7, persist_test_iter_cb,
            &capture);
        if (capture.calls > 0) {
            del_rc = hooks.kv_del(hooks.ctx, 7, capture.key,
                capture.key_len);
        }
        XMEMSET(&capture, 0, sizeof(capture));
        iter2_rc = hooks.kv_iter(hooks.ctx, 7, persist_test_iter_cb,
            &capture);
        iter2_calls = capture.calls;
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }

    (void)unlink(rec_path);
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, iter1_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, del_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, iter2_rc);
    ASSERT_EQ(0, iter2_calls);
}

#ifdef __MACH__
/* macOS exposes /tmp as a trusted operating-system symlink to /private/tmp.
 * A persistence root below that standard alias must initialize without
 * weakening the no-follow checks on namespaces or record files. */
TEST(persist_root_below_macos_tmp_alias_accepted)
{
    char root_template[] = "/tmp/wolfmqtt-persist-XXXXXX";
    MqttBrokerPersistHooks hooks;
    char* root;
    int rc;

    XMEMSET(&hooks, 0, sizeof(hooks));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);

    rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (rc == MQTT_CODE_SUCCESS) {
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }
    ASSERT_EQ(0, rmdir(root));
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
}
#endif

static int persist_test_init_root_mode(mode_t mode)
{
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    MqttBrokerPersistHooks hooks;
    char* root;
    int rc;

    XMEMSET(&hooks, 0, sizeof(hooks));
    root = mkdtemp(root_template);
    if (root == NULL) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (chmod(root, mode) != 0) {
        (void)rmdir(root);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (rc == MQTT_CODE_SUCCESS) {
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }
    (void)rmdir(root);
    return rc;
}

TEST(persist_root_readable_permissions_accepted)
{
    ASSERT_EQ(MQTT_CODE_SUCCESS, persist_test_init_root_mode(0755));
}

TEST(persist_root_writable_permissions_rejected)
{
    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, persist_test_init_root_mode(0777));
}

#ifndef WOLFMQTT_STATIC_MEMORY
/* Remove root/<ns>/<record> left by the POSIX backend. */
static void persist_remove_tree(const char* root)
{
    char dir_path[640];
    char rec_path[1024];
    struct dirent* ent;
    struct dirent* sub;
    DIR* d;
    DIR* sd;

    d = opendir(root);
    if (d == NULL) {
        return;
    }
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        if (snprintf(dir_path, sizeof(dir_path), "%s/%s", root,
                ent->d_name) <= 0) {
            continue;
        }
        sd = opendir(dir_path);
        if (sd == NULL) {
            (void)unlink(dir_path);
            continue;
        }
        while ((sub = readdir(sd)) != NULL) {
            if (sub->d_name[0] != '.' &&
                    snprintf(rec_path, sizeof(rec_path), "%s/%s", dir_path,
                        sub->d_name) > 0) {
                (void)unlink(rec_path);
            }
        }
        (void)closedir(sd);
        (void)rmdir(dir_path);
    }
    (void)closedir(d);
    (void)rmdir(root);
}

/* Whether the captured freed allocation was all zero. */
static int persist_captured_free_zeroed(void)
{
    size_t i;

    for (i = 0; i < g_capture_freed_len; i++) {
        if (g_capture_freed[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* A 40-character topic: its heap copy is 41 bytes, a size nothing else
 * allocates during these restores, so the free capture sees only it. */
#define PERSIST_SCRUB_TOPIC "secret/plant-7/valve-control/setpoint-01"

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
static int scrub_derive_key(void* ctx, byte* out_key, word32 key_len)
{
    (void)ctx;
    XMEMSET(out_key, 0x11, key_len);
    return MQTT_CODE_SUCCESS;
}
#endif

/* A 37-byte payload: an allocation size nothing else uses in these restores,
 * so the targeted allocation failure hits the payload copy. */
#define PERSIST_SCRUB_PAYLOAD_LEN 37

/* Persist one record through `put`, then restore it with the payload copy's
 * allocation failing and the freed topic copy captured. Returns 1 if the
 * topic copy was freed and all zero, 0 if it was freed with data left, -1 if
 * the flow did not reach that point. */
static int persist_restore_alloc_failure_scrub(int outq)
{
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
#ifdef WOLFMQTT_BROKER_RETAINED
    BrokerRetainedMsg rm;
#endif
    BrokerOutPub out;
    char topic[] = PERSIST_SCRUB_TOPIC;
    byte payload[PERSIST_SCRUB_PAYLOAD_LEN];
    char* root;
    int rc;
    int result = -1;

    install_mock_net(&net);
    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(payload, 'p', sizeof(payload));
    root = mkdtemp(root_template);
    if (root == NULL) {
        return -1;
    }
    if (MqttBrokerNet_PersistPosix_Init(&hooks, root) != MQTT_CODE_SUCCESS) {
        persist_remove_tree(root);
        return -1;
    }
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks.derive_key = scrub_derive_key;
#endif

    XMEMSET(&source, 0, sizeof(source));
    rc = MqttBroker_Init(&source, &net);
    if (rc == MQTT_CODE_SUCCESS) {
        rc = MqttBroker_SetPersistHooks(&source, &hooks);
    }
    if (rc == MQTT_CODE_SUCCESS) {
        rc = BrokerPersist_Restore(&source);
    }
    if (rc == MQTT_CODE_SUCCESS && outq) {
        rc = BrokerPersist_PutOrphanSession(&source, "cid",
            MQTT_CONNECT_PROTOCOL_LEVEL_4, 0xFFFFFFFFu,
            (WOLFMQTT_BROKER_TIME_T)1);
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(&out, 0, sizeof(out));
            out.topic = topic;
            out.payload = payload;
            out.payload_len = (word32)sizeof(payload);
            out.qos = MQTT_QOS_1;
            out.packet_id = 1;
            out.state = BROKER_OUTQ_QUEUED;
            out.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
            out.enq_time = (WOLFMQTT_BROKER_TIME_T)1;
            out.enqueue_seq = 1;
            rc = BrokerPersist_PutOutPub(&source, "cid", &out);
        }
    }
#ifdef WOLFMQTT_BROKER_RETAINED
    else if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(&rm, 0, sizeof(rm));
        rm.topic = topic;
        rm.payload = payload;
        rm.payload_len = (word32)sizeof(payload);
        rm.qos = MQTT_QOS_0;
        rm.store_time = (WOLFMQTT_BROKER_TIME_T)1;
        rc = BrokerPersist_PutRetained(&source, &rm);
    }
#else
    else {
        rc = MQTT_CODE_ERROR_BAD_ARG; /* no retained store in this build */
    }
#endif
    MqttBroker_Free(&source);

    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(&restored, 0, sizeof(restored));
        broker_test_capture_free(sizeof(topic));
        g_alloc_fail_size = sizeof(payload);
        if (MqttBroker_Init(&restored, &net) == MQTT_CODE_SUCCESS &&
                MqttBroker_SetPersistHooks(&restored, &hooks) ==
                    MQTT_CODE_SUCCESS) {
            (void)BrokerPersist_Restore(&restored);
            if (g_capture_free_seen) {
                result = persist_captured_free_zeroed();
            }
        }
        g_alloc_fail_size = 0;
        broker_test_disable_free_capture();
        MqttBroker_Free(&restored);
    }
    MqttBrokerNet_PersistPosix_Free(&hooks);
    persist_remove_tree(root);
    return result;
}

#ifdef WOLFMQTT_BROKER_RETAINED
/* When the payload copy cannot be allocated while restoring a retained
 * message, the topic copy already made is wiped before it is freed. */
TEST(persist_restore_retained_alloc_failure_scrubs_topic)
{
    ASSERT_EQ(1, persist_restore_alloc_failure_scrub(0));
}
#endif

/* The same for a queued outbound message of an offline Session. */
TEST(persist_restore_outq_alloc_failure_scrubs_topic)
{
    ASSERT_EQ(1, persist_restore_alloc_failure_scrub(1));
}

#ifndef WOLFMQTT_BROKER_PERSIST_ENCRYPT
/* Drop the last cut bytes of the only record in root/<ns> and lower the
 * header's body length to match (record header: magic(4) version(2) kind(1)
 * wrap(1) body_len(4, big-endian)), so the record stays self-consistent and
 * only the payload length inside the body overruns. Returns 0 on success. */
static int persist_truncate_only_record(const char* root, byte ns,
    long cut)
{
    char dir_path[640];
    char rec_path[1024];
    byte hdr[12];
    struct stat st;
    struct dirent* ent;
    DIR* d;
    FILE* f;
    word32 body_len;
    int rc = -1;

    if (snprintf(dir_path, sizeof(dir_path), "%s/%u", root,
            (unsigned)ns) <= 0) {
        return -1;
    }
    d = opendir(dir_path);
    if (d == NULL) {
        return -1;
    }
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] != '.') {
            break;
        }
    }
    if (ent != NULL &&
            snprintf(rec_path, sizeof(rec_path), "%s/%s", dir_path,
                ent->d_name) > 0 &&
            stat(rec_path, &st) == 0 && st.st_size > cut + (long)sizeof(hdr)) {
        f = fopen(rec_path, "r+b");
        if (f != NULL) {
            if (fread(hdr, 1, sizeof(hdr), f) == sizeof(hdr)) {
                body_len = ((word32)hdr[8] << 24) | ((word32)hdr[9] << 16) |
                    ((word32)hdr[10] << 8) | (word32)hdr[11];
                body_len -= (word32)cut;
                hdr[8] = (byte)(body_len >> 24);
                hdr[9] = (byte)(body_len >> 16);
                hdr[10] = (byte)(body_len >> 8);
                hdr[11] = (byte)body_len;
                if (fseek(f, 0, SEEK_SET) == 0 &&
                        fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr)) {
                    rc = 0;
                }
            }
            if (fclose(f) != 0) {
                rc = -1;
            }
        }
        if (rc == 0 && truncate(rec_path, st.st_size - cut) != 0) {
            rc = -1;
        }
    }
    (void)closedir(d);
    return rc;
}

#ifdef WOLFMQTT_BROKER_RETAINED
/* Restore copies a persisted topic to the heap before it reads the payload.
 * When the record turns out to be malformed the copy is freed; topic strings
 * are application data the broker scrubs before freeing elsewhere, so it must
 * be wiped first. The record is cut short on disk so its declared payload
 * overruns the file. */
TEST(persist_restore_malformed_retained_scrubs_topic)
{
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    BrokerRetainedMsg rm;
    char topic[] = PERSIST_SCRUB_TOPIC;
    byte payload[8] = { 'p', 'a', 'y', 'l', 'o', 'a', 'd', '!' };
    char* root;
    int init_rc;
    int put_rc = MQTT_CODE_ERROR_SYSTEM;
    int cut_rc = -1;
    int restore_rc = MQTT_CODE_ERROR_SYSTEM;
    int seen = 0;
    int zeroed = 0;
    int retained_empty = 0;

    install_mock_net(&net);
    XMEMSET(&hooks, 0, sizeof(hooks));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        XMEMSET(&source, 0, sizeof(source));
        XMEMSET(&rm, 0, sizeof(rm));
        rm.topic = topic;
        rm.payload = payload;
        rm.payload_len = (word32)sizeof(payload);
        rm.qos = MQTT_QOS_0;
        rm.store_time = (WOLFMQTT_BROKER_TIME_T)1;
        if (MqttBroker_Init(&source, &net) == MQTT_CODE_SUCCESS &&
                MqttBroker_SetPersistHooks(&source, &hooks) ==
                    MQTT_CODE_SUCCESS &&
                BrokerPersist_Restore(&source) == MQTT_CODE_SUCCESS) {
            put_rc = BrokerPersist_PutRetained(&source, &rm);
        }
        MqttBroker_Free(&source);
        cut_rc = persist_truncate_only_record(root,
            BROKER_PERSIST_NS_RETAINED, (long)sizeof(payload));

        XMEMSET(&restored, 0, sizeof(restored));
        broker_test_capture_free(sizeof(topic));
        if (MqttBroker_Init(&restored, &net) == MQTT_CODE_SUCCESS &&
                MqttBroker_SetPersistHooks(&restored, &hooks) ==
                    MQTT_CODE_SUCCESS) {
            restore_rc = BrokerPersist_Restore(&restored);
        }
        seen = g_capture_free_seen;
        zeroed = persist_captured_free_zeroed();
        broker_test_disable_free_capture();
        retained_empty = (restored.retained == NULL);
        MqttBroker_Free(&restored);
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }
    persist_remove_tree(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, put_rc);
    ASSERT_EQ(0, cut_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, restore_rc);
    ASSERT_TRUE(retained_empty);
    ASSERT_TRUE(seen);
    ASSERT_TRUE(zeroed);
}

#endif /* WOLFMQTT_BROKER_RETAINED */

/* The same for a queued outbound message of an offline Session. */
TEST(persist_restore_malformed_outq_scrubs_topic)
{
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    BrokerOutPub out;
    char topic[] = PERSIST_SCRUB_TOPIC;
    byte payload[8] = { 'p', 'a', 'y', 'l', 'o', 'a', 'd', '!' };
    char* root;
    int init_rc;
    int put_rc = MQTT_CODE_ERROR_SYSTEM;
    int cut_rc = -1;
    int restore_rc = MQTT_CODE_ERROR_SYSTEM;
    int seen = 0;
    int zeroed = 0;
    int queue_len = -1;

    install_mock_net(&net);
    XMEMSET(&hooks, 0, sizeof(hooks));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        XMEMSET(&source, 0, sizeof(source));
        XMEMSET(&out, 0, sizeof(out));
        out.topic = topic;
        out.payload = payload;
        out.payload_len = (word32)sizeof(payload);
        out.qos = MQTT_QOS_1;
        out.packet_id = 1;
        out.state = BROKER_OUTQ_QUEUED;
        out.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
        out.enq_time = (WOLFMQTT_BROKER_TIME_T)1;
        out.enqueue_seq = 1;
        if (MqttBroker_Init(&source, &net) == MQTT_CODE_SUCCESS &&
                MqttBroker_SetPersistHooks(&source, &hooks) ==
                    MQTT_CODE_SUCCESS &&
                BrokerPersist_Restore(&source) == MQTT_CODE_SUCCESS &&
                BrokerPersist_PutOrphanSession(&source, "cid",
                    MQTT_CONNECT_PROTOCOL_LEVEL_4, 0xFFFFFFFFu,
                    (WOLFMQTT_BROKER_TIME_T)1) == MQTT_CODE_SUCCESS) {
            put_rc = BrokerPersist_PutOutPub(&source, "cid", &out);
        }
        MqttBroker_Free(&source);
        cut_rc = persist_truncate_only_record(root, BROKER_PERSIST_NS_OUTQ,
            (long)sizeof(payload));

        XMEMSET(&restored, 0, sizeof(restored));
        broker_test_capture_free(sizeof(topic));
        if (MqttBroker_Init(&restored, &net) == MQTT_CODE_SUCCESS &&
                MqttBroker_SetPersistHooks(&restored, &hooks) ==
                    MQTT_CODE_SUCCESS) {
            restore_rc = BrokerPersist_Restore(&restored);
        }
        seen = g_capture_free_seen;
        zeroed = persist_captured_free_zeroed();
        broker_test_disable_free_capture();
        if (restored.orphan_sessions != NULL) {
            queue_len = restored.orphan_sessions->out_q_count;
        }
        MqttBroker_Free(&restored);
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }
    persist_remove_tree(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, put_rc);
    ASSERT_EQ(0, cut_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, restore_rc);
    ASSERT_EQ(0, queue_len);
    ASSERT_TRUE(seen);
    ASSERT_TRUE(zeroed);
}

#ifdef WOLFMQTT_V5
/* Ways to corrupt a schema 6 NS_OUTQ record body (layout in
 * BrokerPersist_PutOutPub): flags(1) at offset 5, topic_len(2) at 28, then
 * topic, payload_len(4), payload, props_len(4) and props. */
enum {
    OUTQ_MUT_RESERVED_FLAG,  /* set reserved flags bit 1 */
    OUTQ_MUT_EXPIRY_FLAG,    /* set has_expiry with no expiry property */
    OUTQ_MUT_PROPS_LEN_LONG, /* props_len one more than the bytes left */
    OUTQ_MUT_PROPS_LEN_SHORT,/* props_len one less than the bytes left */
    OUTQ_MUT_BAD_PROP_ID,    /* property identifier 0x7F is not defined */
    OUTQ_MUT_PROP_TRAILING   /* a stray byte after the last property */
};

static word32 persist_rd32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16) |
        ((word32)p[2] << 8) | (word32)p[3];
}

static void persist_wr32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

/* Rewrite the only record in root/<ns> with one corruption. The record
 * header is magic(4) version(2) kind(1) wrap(1) body_len(4). Returns 0. */
static int persist_mutate_only_outq(const char* root, int kind)
{
    char dir_path[640];
    char rec_path[1024];
    byte rec[512];
    struct dirent* ent;
    DIR* d;
    FILE* f;
    size_t len = 0;
    size_t body = 12;
    size_t props_len_off;
    word32 topic_len;
    word32 payload_len;
    word32 props_len;
    int rc = -1;

    if (snprintf(dir_path, sizeof(dir_path), "%s/%u", root,
            (unsigned)BROKER_PERSIST_NS_OUTQ) <= 0) {
        return -1;
    }
    d = opendir(dir_path);
    if (d == NULL) {
        return -1;
    }
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] != '.') {
            break;
        }
    }
    if (ent != NULL && snprintf(rec_path, sizeof(rec_path), "%s/%s",
            dir_path, ent->d_name) > 0) {
        f = fopen(rec_path, "rb");
        if (f != NULL) {
            len = fread(rec, 1, sizeof(rec) - 1, f);
            if (fclose(f) == 0 && len > body + 30) {
                rc = 0;
            }
        }
    }
    (void)closedir(d);
    if (rc != 0) {
        return -1;
    }

    topic_len = ((word32)rec[body + 28] << 8) | rec[body + 29];
    payload_len = persist_rd32(&rec[body + 30 + topic_len]);
    props_len_off = body + 34 + topic_len + payload_len;
    if (props_len_off + 4 > len) {
        return -1;
    }
    props_len = persist_rd32(&rec[props_len_off]);
    switch (kind) {
        case OUTQ_MUT_RESERVED_FLAG:
            rec[body + 5] |= 0x02;
            break;
        case OUTQ_MUT_EXPIRY_FLAG:
            rec[body + 5] |= 0x01;
            break;
        case OUTQ_MUT_PROPS_LEN_LONG:
            persist_wr32(&rec[props_len_off], props_len + 1);
            break;
        case OUTQ_MUT_PROPS_LEN_SHORT:
            persist_wr32(&rec[props_len_off], props_len - 1);
            break;
        case OUTQ_MUT_BAD_PROP_ID:
            rec[props_len_off + 4] = 0x7F;
            break;
        case OUTQ_MUT_PROP_TRAILING:
            /* 0x01 starts a Payload Format Indicator with no value byte. */
            rec[len++] = 0x01;
            persist_wr32(&rec[props_len_off], props_len + 1);
            persist_wr32(&rec[8], persist_rd32(&rec[8]) + 1);
            break;
        default:
            return -1;
    }

    rc = -1;
    f = fopen(rec_path, "wb");
    if (f != NULL) {
        if (fwrite(rec, 1, len, f) == len) {
            rc = 0;
        }
        if (fclose(f) != 0) {
            rc = -1;
        }
    }
    return rc;
}

/* A 53-byte payload, a size nothing else allocates during these restores. */
#define PERSIST_SCRUB_PAYLOAD \
    "payload-secret-0123456789-0123456789-0123456789-01234"

/* Persist a v5 QoS 1 OUTQ record carrying a Payload Format Indicator,
 * corrupt it with `kind`, and restore it. The record must be skipped without
 * failing the restore. capture_size picks the heap copy whose free must be
 * scrubbed (0 when the record is rejected before any copy is made). Returns
 * 1 when all of that holds. */
static int persist_restore_mutated_outq(int kind, size_t capture_size)
{
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    MqttBroker source;
    MqttBroker restored;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    BrokerOutPub out;
    MqttProp prop;
    char topic[] = PERSIST_SCRUB_TOPIC;
    byte payload[] = PERSIST_SCRUB_PAYLOAD;
    char* root;
    int ok = 0;
    int put_rc = MQTT_CODE_ERROR_SYSTEM;
    int restore_rc = MQTT_CODE_ERROR_SYSTEM;
    int queue_len = -1;
    int seen = 0;
    int zeroed = 0;

    install_mock_net(&net);
    XMEMSET(&hooks, 0, sizeof(hooks));
    root = mkdtemp(root_template);
    if (root == NULL) {
        return 0;
    }
    if (MqttBrokerNet_PersistPosix_Init(&hooks, root) == MQTT_CODE_SUCCESS) {
        XMEMSET(&source, 0, sizeof(source));
        XMEMSET(&out, 0, sizeof(out));
        XMEMSET(&prop, 0, sizeof(prop));
        prop.type = MQTT_PROP_PAYLOAD_FORMAT_IND;
        prop.data_byte = 1;
        out.topic = topic;
        out.payload = payload;
        out.payload_len = (word32)sizeof(payload);
        out.qos = MQTT_QOS_1;
        out.packet_id = 1;
        out.state = BROKER_OUTQ_QUEUED;
        out.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_5;
        out.enq_time = (WOLFMQTT_BROKER_TIME_T)1;
        out.enqueue_seq = 1;
        out.props = &prop;
        if (MqttBroker_Init(&source, &net) == MQTT_CODE_SUCCESS &&
                MqttBroker_SetPersistHooks(&source, &hooks) ==
                    MQTT_CODE_SUCCESS &&
                BrokerPersist_Restore(&source) == MQTT_CODE_SUCCESS &&
                BrokerPersist_PutOrphanSession(&source, "cid",
                    MQTT_CONNECT_PROTOCOL_LEVEL_5, 0xFFFFFFFFu,
                    (WOLFMQTT_BROKER_TIME_T)1) == MQTT_CODE_SUCCESS) {
            put_rc = BrokerPersist_PutOutPub(&source, "cid", &out);
        }
        MqttBroker_Free(&source);

        if (put_rc == MQTT_CODE_SUCCESS &&
                persist_mutate_only_outq(root, kind) == 0) {
            XMEMSET(&restored, 0, sizeof(restored));
            if (capture_size != 0) {
                broker_test_capture_free(capture_size);
            }
            if (MqttBroker_Init(&restored, &net) == MQTT_CODE_SUCCESS &&
                    MqttBroker_SetPersistHooks(&restored, &hooks) ==
                        MQTT_CODE_SUCCESS) {
                restore_rc = BrokerPersist_Restore(&restored);
            }
            seen = g_capture_free_seen;
            zeroed = persist_captured_free_zeroed();
            broker_test_disable_free_capture();
            if (restored.orphan_sessions != NULL) {
                queue_len = restored.orphan_sessions->out_q_count;
            }
            MqttBroker_Free(&restored);
            ok = (restore_rc == MQTT_CODE_SUCCESS && queue_len == 0 &&
                (capture_size == 0 || (seen && zeroed)));
        }
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }
    persist_remove_tree(root);
    return ok;
}

/* Schema 6 restore rejects each malformed OUTQ record on its own, skipping
 * it instead of failing the whole restore, and wipes any topic or payload
 * copy it already made. */
TEST(persist_restore_rejects_malformed_outq_props)
{
    ASSERT_EQ(1, persist_restore_mutated_outq(OUTQ_MUT_RESERVED_FLAG, 0));
    ASSERT_EQ(1, persist_restore_mutated_outq(OUTQ_MUT_PROPS_LEN_LONG,
        sizeof(PERSIST_SCRUB_TOPIC)));
    ASSERT_EQ(1, persist_restore_mutated_outq(OUTQ_MUT_PROPS_LEN_SHORT,
        sizeof(PERSIST_SCRUB_TOPIC)));
    ASSERT_EQ(1, persist_restore_mutated_outq(OUTQ_MUT_BAD_PROP_ID,
        sizeof(PERSIST_SCRUB_PAYLOAD)));
    ASSERT_EQ(1, persist_restore_mutated_outq(OUTQ_MUT_PROP_TRAILING,
        sizeof(PERSIST_SCRUB_PAYLOAD)));
    ASSERT_EQ(1, persist_restore_mutated_outq(OUTQ_MUT_EXPIRY_FLAG,
        sizeof(PERSIST_SCRUB_PAYLOAD)));
}
#endif /* WOLFMQTT_V5 */
#endif /* !WOLFMQTT_BROKER_PERSIST_ENCRYPT */
#endif /* !WOLFMQTT_STATIC_MEMORY */

/* The POSIX backend names a record "<hex key>.bin" and writes it through
 * "<hex key>.bin.tmp", so a key can be at most (NAME_MAX - 8) / 2 bytes. A
 * longer key must be refused up front as MQTT_CODE_ERROR_OUT_OF_BUFFER, the
 * backend's documented "key too long" result, not surface later as a generic
 * system error from the filesystem. */
TEST(persist_key_longer_than_name_limit_rejected)
{
    byte key[2 * 256];
    static const byte value[] = "v";
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    MqttBrokerPersistHooks hooks;
    byte out[8];
    word32 out_len;
    char* root;
    int max_len = (NAME_MAX - 8) / 2;
    int init_rc;
    int fit_put_rc = MQTT_CODE_ERROR_SYSTEM;
    int fit_del_rc = MQTT_CODE_ERROR_SYSTEM;
    int long_put_rc = MQTT_CODE_SUCCESS;
    int long_get_rc = MQTT_CODE_SUCCESS;
    int long_del_rc = MQTT_CODE_SUCCESS;
    int path_ok;

    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(key, 'k', sizeof(key));
    ASSERT_TRUE(max_len + 1 <= (int)sizeof(key));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    path_ok = (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0);
    ASSERT_TRUE(path_ok);

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        fit_put_rc = hooks.kv_put(hooks.ctx, 7, key, (word16)max_len,
            value, (word32)sizeof(value));
        fit_del_rc = hooks.kv_del(hooks.ctx, 7, key, (word16)max_len);
        long_put_rc = hooks.kv_put(hooks.ctx, 7, key, (word16)(max_len + 1),
            value, (word32)sizeof(value));
        out_len = (word32)sizeof(out);
        long_get_rc = hooks.kv_get(hooks.ctx, 7, key, (word16)(max_len + 1),
            out, &out_len);
        long_del_rc = hooks.kv_del(hooks.ctx, 7, key, (word16)(max_len + 1));
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, fit_put_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, fit_del_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, long_put_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, long_get_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, long_del_rc);
}

/* kv_get fills at most *inout_len bytes. A record larger than that must be
 * reported as MQTT_CODE_ERROR_OUT_OF_BUFFER rather than returned truncated as
 * if it were the whole record; the META check relies on that result to treat
 * an oversized record as a schema mismatch. */
TEST(persist_get_reports_record_larger_than_buffer)
{
    static const byte key[] = { 0x9a };
    static const byte value[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    char rec_path[680];
    MqttBrokerPersistHooks hooks;
    byte out[sizeof(value)];
    word32 out_len;
    char* root;
    int init_rc;
    int put_rc = MQTT_CODE_ERROR_SYSTEM;
    int short_rc = MQTT_CODE_SUCCESS;
    int exact_rc = MQTT_CODE_ERROR_SYSTEM;
    word32 exact_len = 0;
    int paths_ok = 0;

    XMEMSET(&hooks, 0, sizeof(hooks));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    if (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0 &&
            snprintf(rec_path, sizeof(rec_path), "%s/9a.bin",
                ns_path) > 0) {
        paths_ok = 1;
    }
    ASSERT_TRUE(paths_ok);

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        put_rc = hooks.kv_put(hooks.ctx, 7, key, (word16)sizeof(key),
            value, (word32)sizeof(value));
        out_len = 4;
        short_rc = hooks.kv_get(hooks.ctx, 7, key, (word16)sizeof(key),
            out, &out_len);
        out_len = (word32)sizeof(out);
        exact_rc = hooks.kv_get(hooks.ctx, 7, key, (word16)sizeof(key),
            out, &out_len);
        exact_len = out_len;
        MqttBrokerNet_PersistPosix_Free(&hooks);
    }

    (void)unlink(rec_path);
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, put_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_OUT_OF_BUFFER, short_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, exact_rc);
    ASSERT_EQ((word32)sizeof(value), exact_len);
    ASSERT_EQ(0, XMEMCMP(out, value, sizeof(value)));
}

/* A rename or unlink is not durable until its namespace directory is
 * flushed, so the POSIX backend must report a failed directory fsync rather
 * than claim the update was committed. */
TEST(persist_put_del_report_namespace_fsync_failure)
{
    static const byte key[] = { 0x56, 0x78 };
    static const byte value[] = "value";
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    char final_path[680];
    MqttBrokerPersistHooks hooks;
    char* root;
    int init_rc = MQTT_CODE_ERROR_SYSTEM;
    int put_fail_rc = MQTT_CODE_SUCCESS;
    int put_ok_rc = MQTT_CODE_ERROR_SYSTEM;
    int del_fail_rc = MQTT_CODE_SUCCESS;
    int paths_ok = 0;

    XMEMSET(&hooks, 0, sizeof(hooks));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    if (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0 &&
            snprintf(final_path, sizeof(final_path), "%s/5678.bin",
                ns_path) > 0) {
        paths_ok = 1;
    }
    ASSERT_TRUE(paths_ok);

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        g_fsync_dir_fail = 1;
        put_fail_rc = hooks.kv_put(hooks.ctx, 7, key, (word16)sizeof(key),
            value, (word32)sizeof(value));
        g_fsync_dir_fail = 0;
        put_ok_rc = hooks.kv_put(hooks.ctx, 7, key, (word16)sizeof(key),
            value, (word32)sizeof(value));
        g_fsync_dir_fail = 1;
        del_fail_rc = hooks.kv_del(hooks.ctx, 7, key, (word16)sizeof(key));
        g_fsync_dir_fail = 0;
    }

    MqttBrokerNet_PersistPosix_Free(&hooks);
    (void)unlink(final_path);
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, put_fail_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, put_ok_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, del_fail_rc);
}

/* A record the backend cannot open is an I/O failure, not a record to skip:
 * reporting success would let restore or a delete scan finish with durable
 * state silently left out. Deliberately non-record entries (wrong suffix,
 * non-regular files) are still skipped. */
TEST(persist_iter_reports_unreadable_record)
{
    static const byte value[] = "value";
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    char good_path[680];
    char bad_path[680];
    char other_path[680];
    MqttBrokerPersistHooks hooks;
    PersistIterCapture capture;
    char* root;
    int init_rc = MQTT_CODE_ERROR_SYSTEM;
    int clean_iter_rc = MQTT_CODE_ERROR_SYSTEM;
    int iter_rc = MQTT_CODE_SUCCESS;
    int bad_unreadable = 0;
    int fd;
    int paths_ok = 0;

    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&capture, 0, sizeof(capture));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    if (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0 &&
            snprintf(good_path, sizeof(good_path), "%s/1111.bin",
                ns_path) > 0 &&
            snprintf(bad_path, sizeof(bad_path), "%s/2222.bin",
                ns_path) > 0 &&
            snprintf(other_path, sizeof(other_path), "%s/notes.txt",
                ns_path) > 0) {
        paths_ok = 1;
    }
    ASSERT_TRUE(paths_ok);
    ASSERT_EQ(0, mkdir(ns_path, 0700));
    ASSERT_EQ(0, persist_test_write_file(good_path, value,
        (word32)sizeof(value)));
    ASSERT_EQ(0, persist_test_write_file(other_path, value,
        (word32)sizeof(value)));

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        /* Readable record plus a non-record file: iteration succeeds. */
        clean_iter_rc = hooks.kv_iter(hooks.ctx, 7, persist_test_iter_cb,
            &capture);
        /* Add a record the backend owns but cannot open. Mode 0 does not
         * stop a privileged process (root in container CI), so only check
         * the error path when the open really fails. */
        if (persist_test_write_file(bad_path, value,
                (word32)sizeof(value)) == 0 && chmod(bad_path, 0) == 0) {
            fd = open(bad_path, O_RDONLY);
            if (fd >= 0) {
                (void)close(fd);
            }
            else {
                bad_unreadable = 1;
                iter_rc = hooks.kv_iter(hooks.ctx, 7, persist_test_iter_cb,
                    &capture);
            }
        }
    }

    MqttBrokerNet_PersistPosix_Free(&hooks);
    (void)unlink(good_path);
    (void)unlink(bad_path);
    (void)unlink(other_path);
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, clean_iter_rc);
    if (bad_unreadable) {
        ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, iter_rc);
    }
}

/* Entries named like records that are not regular files the broker owns - a
 * UNIX socket, a symlink - are skipped by type before any open, so their
 * platform-specific open errors (ENXIO, ELOOP/EMLINK) cannot fail restore. */
TEST(persist_iter_skips_socket_and_symlink_entries)
{
    static const byte value[] = "value";
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    char good_path[680];
    char sock_path[680];
    char link_path[680];
    MqttBrokerPersistHooks hooks;
    PersistIterCapture capture;
    struct sockaddr_un sun;
    char* root;
    int sock = -1;
    int init_rc = MQTT_CODE_ERROR_SYSTEM;
    int iter_rc = MQTT_CODE_ERROR_SYSTEM;
    int sock_ok = 0;
    int paths_ok = 0;

    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&capture, 0, sizeof(capture));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);
    if (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0 &&
            snprintf(good_path, sizeof(good_path), "%s/1111.bin",
                ns_path) > 0 &&
            snprintf(sock_path, sizeof(sock_path), "%s/3333.bin",
                ns_path) > 0 &&
            snprintf(link_path, sizeof(link_path), "%s/4444.bin",
                ns_path) > 0) {
        paths_ok = 1;
    }
    ASSERT_TRUE(paths_ok);
    ASSERT_EQ(0, mkdir(ns_path, 0700));
    ASSERT_EQ(0, persist_test_write_file(good_path, value,
        (word32)sizeof(value)));
    ASSERT_EQ(0, symlink("1111.bin", link_path));

    XMEMSET(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    if (strlen(sock_path) < sizeof(sun.sun_path)) {
        XMEMCPY(sun.sun_path, sock_path, strlen(sock_path) + 1);
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock >= 0 && bind(sock, (struct sockaddr*)&sun,
                (socklen_t)sizeof(sun)) == 0) {
            sock_ok = 1;
        }
    }

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        iter_rc = hooks.kv_iter(hooks.ctx, 7, persist_test_iter_cb,
            &capture);
    }

    MqttBrokerNet_PersistPosix_Free(&hooks);
    if (sock >= 0) {
        (void)close(sock);
    }
    (void)unlink(sock_path);
    (void)unlink(link_path);
    (void)unlink(good_path);
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_TRUE(sock_ok);
    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, iter_rc);
    ASSERT_EQ(1, capture.calls);
}

TEST(persist_put_rejects_existing_temp_symlink)
{
    static const byte key[] = { 0x12, 0x34 };
    static const byte original[] = "original";
    static const byte replacement[] = "replacement";
    char root_template[] = "./wolfmqtt-persist-XXXXXX";
    char ns_path[640];
    char victim_path[640];
    char temp_path[680];
    char final_path[680];
    byte actual[sizeof(replacement)] = { 0 };
    byte stored[sizeof(replacement)] = { 0 };
    PersistIterCapture capture;
    MqttBrokerPersistHooks hooks;
    char* root;
    word32 stored_len = (word32)sizeof(stored);
    word32 retrieved_len = 0;
    ssize_t read_len = -1;
    int fd = -1;
    int put_rc = MQTT_CODE_SUCCESS;
    int stale_create_rc = -1;
    int clean_put_rc = MQTT_CODE_ERROR_SYSTEM;
    int get_rc = MQTT_CODE_ERROR_SYSTEM;
    int iter_rc = MQTT_CODE_ERROR_SYSTEM;
    int sync_rc = MQTT_CODE_ERROR_SYSTEM;
    int del_rc = MQTT_CODE_ERROR_SYSTEM;
    int missing_rc = MQTT_CODE_ERROR_SYSTEM;
    int init_rc = MQTT_CODE_ERROR_SYSTEM;
    int paths_ok = 0;

    XMEMSET(&hooks, 0, sizeof(hooks));
    XMEMSET(&capture, 0, sizeof(capture));
    root = mkdtemp(root_template);
    ASSERT_NOT_NULL(root);

    if (snprintf(ns_path, sizeof(ns_path), "%s/7", root) > 0 &&
            snprintf(victim_path, sizeof(victim_path), "%s/victim.bin",
                root) > 0 &&
            snprintf(temp_path, sizeof(temp_path), "%s/1234.bin.tmp",
                ns_path) > 0 &&
            snprintf(final_path, sizeof(final_path), "%s/1234.bin",
                ns_path) > 0) {
        paths_ok = 1;
    }
    ASSERT_TRUE(paths_ok);
    ASSERT_EQ(0, mkdir(ns_path, 0700));
    ASSERT_EQ(0, persist_test_write_file(victim_path, original,
        (word32)sizeof(original)));
    ASSERT_EQ(0, symlink("../victim.bin", temp_path));

    init_rc = MqttBrokerNet_PersistPosix_Init(&hooks, root);
    if (init_rc == MQTT_CODE_SUCCESS) {
        put_rc = hooks.kv_put(hooks.ctx, 7, key, (word16)sizeof(key),
            replacement, (word32)sizeof(replacement));
    }

    fd = open(victim_path, O_RDONLY);
    if (fd >= 0) {
        read_len = read(fd, actual, sizeof(actual));
        (void)close(fd);
    }

    /* Remove either the rejected temp symlink or the vulnerable backend's
     * renamed final symlink, then verify normal descriptor-relative storage. */
    (void)unlink(temp_path);
    (void)unlink(final_path);
    if (init_rc == MQTT_CODE_SUCCESS) {
        stale_create_rc = persist_test_write_file(temp_path, original,
            (word32)sizeof(original));
        clean_put_rc = hooks.kv_put(hooks.ctx, 7, key,
            (word16)sizeof(key), replacement, (word32)sizeof(replacement));
        get_rc = hooks.kv_get(hooks.ctx, 7, key, (word16)sizeof(key),
            stored, &stored_len);
        retrieved_len = stored_len;
        iter_rc = hooks.kv_iter(hooks.ctx, 7, persist_test_iter_cb,
            &capture);
        sync_rc = hooks.sync(hooks.ctx);
        del_rc = hooks.kv_del(hooks.ctx, 7, key, (word16)sizeof(key));
        stored_len = (word32)sizeof(stored);
        missing_rc = hooks.kv_get(hooks.ctx, 7, key, (word16)sizeof(key),
            stored, &stored_len);
    }

    MqttBrokerNet_PersistPosix_Free(&hooks);
    (void)unlink(temp_path);
    (void)unlink(final_path);
    (void)unlink(victim_path);
    (void)rmdir(ns_path);
    (void)rmdir(root);

    ASSERT_EQ(MQTT_CODE_SUCCESS, init_rc);
    ASSERT_NE(MQTT_CODE_SUCCESS, put_rc);
    ASSERT_EQ((int)sizeof(original), (int)read_len);
    ASSERT_MEM_EQ(original, actual, sizeof(original));
    ASSERT_EQ(0, stale_create_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, clean_put_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, get_rc);
    ASSERT_EQ((int)sizeof(replacement), (int)retrieved_len);
    ASSERT_MEM_EQ(replacement, stored, sizeof(replacement));
    ASSERT_EQ(MQTT_CODE_SUCCESS, iter_rc);
    ASSERT_EQ(1, capture.calls);
    ASSERT_EQ((int)sizeof(key), (int)capture.key_len);
    ASSERT_MEM_EQ(key, capture.key, sizeof(key));
    ASSERT_EQ((int)sizeof(replacement), (int)capture.blob_len);
    ASSERT_MEM_EQ(replacement, capture.blob, sizeof(replacement));
    ASSERT_EQ(MQTT_CODE_SUCCESS, sync_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, del_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_NOT_FOUND, missing_rc);
}
#endif /* WOLFMQTT_BROKER_PERSIST */

/* -------------------------------------------------------------------------- */
/* Runner                                                                      */
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
/* Retained-message persistence                                                */
/* -------------------------------------------------------------------------- */
/* A retained message carrying a v5 Message Expiry Interval must not outlive
 * that interval in the persistence backend. These drive real PUBLISH packets
 * through the mock net above against an in-RAM MqttBrokerPersistHooks, then
 * assert on the record count the backend holds. They are the only tests here
 * that move the clock - nothing can expire while it is pinned. */
/* Fixed-size so the backend behaves the same in both allocation profiles.
 * Sized past 3 * BROKER_MAX_RETAINED for the backlog test. */
#if defined(WOLFMQTT_BROKER_PERSIST) && (!defined(WOLFMQTT_STATIC_MEMORY) || \
    (defined(WOLFMQTT_BROKER_RETAINED) && defined(WOLFMQTT_V5)))
#define KV_MAX_RECS   80
#define KV_MAX_BLOB   512

typedef struct KvRec {
    byte   in_use;
    byte   ns;
    word16 key_len;
    byte   key[BROKER_MAX_TOPIC_LEN];
    word32 blob_len;
    byte   blob[KV_MAX_BLOB];
} KvRec;

static KvRec g_kv[KV_MAX_RECS];
static int g_kv_sync_rc; /* result kv_sync reports */
static int g_kv_del_rc;  /* non-zero: kv_del fails with this, keeping data */
static int g_kv_del_fail_ns; /* namespace g_kv_del_rc applies to, -1 = all */
static int g_kv_iter_rc; /* result kv_iter reports after visiting records */

static void kv_reset(void)
{
    XMEMSET(g_kv, 0, sizeof(g_kv));
    g_kv_sync_rc = 0;
    g_kv_del_rc = 0;
    g_kv_del_fail_ns = -1;
    g_kv_iter_rc = 0;
}

static KvRec* kv_find(byte ns, const byte* key, word16 key_len)
{
    int i;
    for (i = 0; i < KV_MAX_RECS; i++) {
        if (g_kv[i].in_use && g_kv[i].ns == ns &&
                g_kv[i].key_len == key_len &&
                XMEMCMP(g_kv[i].key, key, key_len) == 0) {
            return &g_kv[i];
        }
    }
    return NULL;
}

static int kv_put(void* ctx, byte ns, const byte* key, word16 key_len,
    const byte* blob, word32 blob_len)
{
    KvRec* r;
    int i;
    (void)ctx;
    if (key_len > BROKER_MAX_TOPIC_LEN || blob_len > KV_MAX_BLOB) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    r = kv_find(ns, key, key_len);
    if (r == NULL) {
        for (i = 0; i < KV_MAX_RECS; i++) {
            if (!g_kv[i].in_use) {
                r = &g_kv[i];
                break;
            }
        }
        if (r == NULL) {
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        r->in_use = 1;
        r->ns = ns;
        r->key_len = key_len;
        XMEMCPY(r->key, key, key_len);
    }
    XMEMCPY(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    return 0;
}

static int kv_get(void* ctx, byte ns, const byte* key, word16 key_len,
    byte* out, word32* inout_len)
{
    KvRec* r;
    (void)ctx;
    r = kv_find(ns, key, key_len);
    if (r == NULL) {
        return MQTT_CODE_ERROR_NOT_FOUND;
    }
    if (*inout_len < r->blob_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMCPY(out, r->blob, r->blob_len);
    *inout_len = r->blob_len;
    return 0;
}

static int kv_del(void* ctx, byte ns, const byte* key, word16 key_len)
{
    KvRec* r;
    (void)ctx;
    if (g_kv_del_rc != 0 &&
            (g_kv_del_fail_ns < 0 || g_kv_del_fail_ns == (int)ns)) {
        return g_kv_del_rc;
    }
    r = kv_find(ns, key, key_len);
    if (r != NULL) {
        XMEMSET(r, 0, sizeof(*r));
    }
    return 0; /* absent key is not an error */
}

static int kv_iter(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
    void* cb_ctx)
{
    int i;
    (void)ctx;
    for (i = 0; i < KV_MAX_RECS; i++) {
        if (g_kv[i].in_use && g_kv[i].ns == ns) {
            /* Hand the callback its own copy: a backend may invalidate the
             * buffer once the callback returns, so the sweep must not depend
             * on it staying live. */
            byte   tmp_key[BROKER_MAX_TOPIC_LEN];
            byte   tmp_blob[KV_MAX_BLOB];
            word16 tmp_key_len = g_kv[i].key_len;
            word32 tmp_blob_len = g_kv[i].blob_len;
            XMEMCPY(tmp_key, g_kv[i].key, tmp_key_len);
            XMEMCPY(tmp_blob, g_kv[i].blob, tmp_blob_len);
            if (cb(tmp_key, tmp_key_len, tmp_blob, tmp_blob_len, cb_ctx) != 0) {
                break;
            }
        }
    }
    return g_kv_iter_rc;
}

static int kv_sync(void* ctx)
{
    (void)ctx;
    return g_kv_sync_rc;
}

#ifndef WOLFMQTT_STATIC_MEMORY
static int kv_outq_count(void)
{
    int i;
    int count = 0;

    for (i = 0; i < KV_MAX_RECS; i++) {
        if (g_kv[i].in_use && g_kv[i].ns == BROKER_PERSIST_NS_OUTQ) {
            count++;
        }
    }
    return count;
}

static int takeover_setup_persist(MqttBroker* broker,
    MqttBrokerPersistHooks* hooks)
{
    kv_reset();
    XMEMSET(hooks, 0, sizeof(*hooks));
    hooks->kv_put = kv_put;
    hooks->kv_get = kv_get;
    hooks->kv_del = kv_del;
    hooks->kv_iter = kv_iter;
    hooks->sync = kv_sync;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    hooks->derive_key = persist_order_derive_key;
#endif
    return MqttBroker_SetPersistHooks(broker, hooks);
}

/* A write or delete is only committed once the backend's sync hook has made
 * it durable. A failing sync must reach the caller instead of being reported
 * as a successful commit. */
TEST(persist_commit_reports_sync_failure)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    int put_fail_rc;
    int del_fail_rc;
    int put_ok_rc;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));

    g_kv_sync_rc = MQTT_CODE_ERROR_SYSTEM;
    put_fail_rc = BrokerPersist_PutOrphanSession(&broker, "C",
        MQTT_CONNECT_PROTOCOL_LEVEL_4, 60, 0);
    del_fail_rc = BrokerPersist_DelSession(&broker, "C");
    g_kv_sync_rc = 0;
    put_ok_rc = BrokerPersist_PutOrphanSession(&broker, "C",
        MQTT_CONNECT_PROTOCOL_LEVEL_4, 60, 0);

    MqttBroker_Free(&broker);

    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, put_fail_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, del_fail_rc);
    ASSERT_EQ(MQTT_CODE_SUCCESS, put_ok_rc);
}

/* Seed two outbound-queue records for ClientId "C". The OUTQ key is the
 * ClientId, a 0x00 separator, then the Packet Identifier. Only keys matter
 * to BrokerPersist_DelOutQueue. */
static void delq_seed_two(void)
{
    static const byte key1[] = { 'C', 0x00, 0x00, 0x01 };
    static const byte key2[] = { 'C', 0x00, 0x00, 0x02 };
    static const byte blob[] = { 0x00 };

    (void)kv_put(NULL, BROKER_PERSIST_NS_OUTQ, key1, (word16)sizeof(key1),
        blob, (word32)sizeof(blob));
    (void)kv_put(NULL, BROKER_PERSIST_NS_OUTQ, key2, (word16)sizeof(key2),
        blob, (word32)sizeof(blob));
}

/* Deleting a client's persisted outbound queue must report every way the
 * deletion can be incomplete or not durable, rather than a non-negative
 * count that callers take as success. */
TEST(persist_del_outqueue_reports_failures)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    int del_fail_rc;
    int sync_fail_rc;
    int iter_fail_rc;
    int alloc_fail_rc;
    int ok_rc;
    int left_after_ok;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));

    delq_seed_two();
    g_kv_del_rc = MQTT_CODE_ERROR_SYSTEM;
    del_fail_rc = BrokerPersist_DelOutQueue(&broker, "C");
    g_kv_del_rc = 0;

    g_kv_sync_rc = MQTT_CODE_ERROR_SYSTEM;
    sync_fail_rc = BrokerPersist_DelOutQueue(&broker, "C");
    g_kv_sync_rc = 0;

    delq_seed_two();
    g_kv_iter_rc = MQTT_CODE_ERROR_SYSTEM;
    iter_fail_rc = BrokerPersist_DelOutQueue(&broker, "C");
    g_kv_iter_rc = 0;

    delq_seed_two();
    broker_test_fail_alloc_after(0);
    alloc_fail_rc = BrokerPersist_DelOutQueue(&broker, "C");
    broker_test_disable_alloc_failure();

    delq_seed_two();
    ok_rc = BrokerPersist_DelOutQueue(&broker, "C");
    left_after_ok = kv_outq_count();

    MqttBroker_Free(&broker);

    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, del_fail_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, sync_fail_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, iter_fail_rc);
    ASSERT_EQ(MQTT_CODE_ERROR_MEMORY, alloc_fail_rc);
    ASSERT_EQ(2, ok_rc);
    ASSERT_EQ(0, left_after_ok);
}

/* Schema-mismatch recovery wipes every record and then stamps a current
 * META. If the wipe is incomplete, stamping META would mark it done and the
 * leftover old-schema records would never be wiped. The old META must stay
 * in place, and restore must fail, until a later wipe completes. */
TEST(persist_schema_wipe_failure_keeps_old_meta)
{
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    static const byte meta_key[] = { 0x00 };
    static const byte outq_key[] = { 'C', 0x00, 0x00, 0x01 };
    byte bad_meta[32];
    static const byte blob[] = { 0x00 };
    KvRec* meta;
    int fail_rc;
    int fail_restored;
    int meta_kept;
    int ok_rc;
    int ok_restored;
    int outq_left;
    int meta_replaced;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));

    /* A META record that is not a valid header for this build forces the
     * schema-mismatch wipe. */
    XMEMSET(bad_meta, 0xEE, sizeof(bad_meta));
    (void)kv_put(NULL, BROKER_PERSIST_NS_META, meta_key,
        (word16)sizeof(meta_key), bad_meta, (word32)sizeof(bad_meta));
    (void)kv_put(NULL, BROKER_PERSIST_NS_OUTQ, outq_key,
        (word16)sizeof(outq_key), blob, (word32)sizeof(blob));

    /* Deleting the old outbound-queue record fails. */
    g_kv_del_rc = MQTT_CODE_ERROR_SYSTEM;
    g_kv_del_fail_ns = BROKER_PERSIST_NS_OUTQ;
    fail_rc = BrokerPersist_Restore(&broker);
    fail_restored = broker.persist_restored;
    meta = kv_find(BROKER_PERSIST_NS_META, meta_key,
        (word16)sizeof(meta_key));
    meta_kept = (meta != NULL && meta->blob_len == sizeof(bad_meta) &&
        XMEMCMP(meta->blob, bad_meta, sizeof(bad_meta)) == 0);
    g_kv_del_rc = 0;
    g_kv_del_fail_ns = -1;

    /* With the backend healthy again the wipe completes. */
    ok_rc = BrokerPersist_Restore(&broker);
    ok_restored = broker.persist_restored;
    outq_left = kv_outq_count();
    meta = kv_find(BROKER_PERSIST_NS_META, meta_key,
        (word16)sizeof(meta_key));
    meta_replaced = (meta != NULL &&
        XMEMCMP(meta->blob, bad_meta, sizeof(bad_meta)) != 0);

    MqttBroker_Free(&broker);

    ASSERT_EQ(MQTT_CODE_ERROR_SYSTEM, fail_rc);
    ASSERT_EQ(0, fail_restored);
    ASSERT_TRUE(meta_kept);
    ASSERT_EQ(MQTT_CODE_SUCCESS, ok_rc);
    ASSERT_EQ(1, ok_restored);
    ASSERT_EQ(0, outq_left);
    ASSERT_TRUE(meta_replaced);
}

/* Running out of memory while restoring a durable record is not a malformed
 * record to skip: restore must fail and roll back rather than start with part
 * of the persisted Session state silently missing. */
TEST(persist_restore_alloc_failure_is_fatal)
{
    MqttBroker broker;
    MqttBroker broker2;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    int fail_rc;
    int fail_restored;
    int fail_has_orphan;
    int ok_rc;
    int ok_has_orphan;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));
    /* Stamp META, then persist one orphaned Session for ClientId "C". */
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutOrphanSession(&broker, "C",
        MQTT_CONNECT_PROTOCOL_LEVEL_4, 3600, 0));
    MqttBroker_Free(&broker);

    /* A fresh broker over the same backend restores it. The first allocation
     * made for the Session record fails: in encrypt-at-rest builds that is
     * the Session's decrypted copy, after META's decrypt has allocated its
     * own copy and its AAD buffer; otherwise the orphan Session itself. */
    XMEMSET(&broker2, 0, sizeof(broker2));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker2, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker2, &hooks));
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    broker_test_fail_alloc_after(2);
#else
    broker_test_fail_alloc_after(0);
#endif
    fail_rc = BrokerPersist_Restore(&broker2);
    broker_test_disable_alloc_failure();
    fail_restored = broker2.persist_restored;
    fail_has_orphan = (broker2.orphan_sessions != NULL);

    ok_rc = BrokerPersist_Restore(&broker2);
    ok_has_orphan = (broker2.orphan_sessions != NULL);
    MqttBroker_Free(&broker2);

    ASSERT_EQ(1, g_alloc_failure_count);
    ASSERT_EQ(MQTT_CODE_ERROR_MEMORY, fail_rc);
    ASSERT_EQ(0, fail_restored);
    ASSERT_FALSE(fail_has_orphan);
    ASSERT_EQ(MQTT_CODE_SUCCESS, ok_rc);
    ASSERT_TRUE(ok_has_orphan);
}

/* More persisted Sessions than BROKER_MAX_PERSIST_SESSIONS is a normal state
 * (records are written per CONNECT; the cap is enforced on orphaning), so
 * restore skips the excess rather than failing startup. Only a genuine
 * allocation failure is fatal. */
TEST(persist_restore_skips_sessions_over_cap)
{
    MqttBroker broker;
    MqttBroker broker2;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    char cid[16];
    int i;
    int rc;
    int restored;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&broker));
    for (i = 0; i < BROKER_MAX_PERSIST_SESSIONS + 1; i++) {
        XSNPRINTF(cid, sizeof(cid), "c%d", i);
        ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutOrphanSession(&broker,
            cid, MQTT_CONNECT_PROTOCOL_LEVEL_4, 3600, 0));
    }
    MqttBroker_Free(&broker);

    XMEMSET(&broker2, 0, sizeof(broker2));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker2, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker2, &hooks));
    rc = BrokerPersist_Restore(&broker2);
    restored = broker2.orphan_session_count;
    MqttBroker_Free(&broker2);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(BROKER_MAX_PERSIST_SESSIONS, restored);
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
/* An encrypted record is bound to the namespace and storage key it was
 * written under (AES-GCM additional data). A valid ciphertext moved to a
 * different key by someone with write access to the store must fail
 * authentication instead of being restored under the new key. */
TEST(persist_encrypted_record_bound_to_storage_key)
{
    MqttBroker broker;
    MqttBroker broker2;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    static const byte key_a[] = { 'A' };
    static const byte key_b[] = { 'B' };
    KvRec* rec;
    int moved = 0;
    int rc;

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_Restore(&broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, BrokerPersist_PutOrphanSession(&broker, "A",
        MQTT_CONNECT_PROTOCOL_LEVEL_4, 3600, 0));
    MqttBroker_Free(&broker);

    /* Relocate the unchanged ciphertext from key "A" to key "B". */
    rec = kv_find(BROKER_PERSIST_NS_SESSION, key_a, (word16)sizeof(key_a));
    if (rec != NULL) {
        XMEMCPY(rec->key, key_b, sizeof(key_b));
        moved = 1;
    }
    ASSERT_TRUE(moved);
    ASSERT_NOT_NULL(kv_find(BROKER_PERSIST_NS_SESSION, key_b,
        (word16)sizeof(key_b)));

    XMEMSET(&broker2, 0, sizeof(broker2));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker2, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker2, &hooks));
    rc = BrokerPersist_Restore(&broker2);
    moved = (broker2.orphan_sessions != NULL);
    MqttBroker_Free(&broker2);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    /* The relocated record was rejected, so no Session was restored. */
    ASSERT_FALSE(moved);
}

/* Migration: a store encrypted before the storage key was bound has a META
 * whose tag covers only the 12-byte header. Built here directly with
 * wolfCrypt, it must fail authentication under the new additional data, so
 * restore takes the schema-mismatch path: wipe every record, then stamp a
 * META the current build can read. */
TEST(persist_header_only_aad_store_is_wiped)
{
    MqttBroker broker;
    MqttBroker broker2;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    Aes aes;
    byte key[32];
    byte old_meta[12 + 12 + 4 + 16];
    byte body[4];
    static const byte meta_key[] = { 0x00 };
    static const byte outq_key[] = { 'C', 0x00, 0x00, 0x01 };
    static const byte blob[] = { 0x00 };
    KvRec* meta;
    int enc_rc;
    int rc;
    int rc2;
    int outq_left;
    int meta_changed;

    /* Header: "WMQB", schema version, rec_kind META, wrap AES-GCM, body
     * length 4. Body: schema version as a 32-bit big-endian value. */
    XMEMSET(old_meta, 0, sizeof(old_meta));
    old_meta[0] = WOLFMQTT_BROKER_PERSIST_MAGIC0;
    old_meta[1] = WOLFMQTT_BROKER_PERSIST_MAGIC1;
    old_meta[2] = WOLFMQTT_BROKER_PERSIST_MAGIC2;
    old_meta[3] = WOLFMQTT_BROKER_PERSIST_MAGIC3;
    old_meta[4] = (byte)(WOLFMQTT_BROKER_PERSIST_SCHEMA_VER >> 8);
    old_meta[5] = (byte)(WOLFMQTT_BROKER_PERSIST_SCHEMA_VER & 0xFF);
    old_meta[6] = BROKER_PERSIST_NS_META;
    old_meta[7] = WOLFMQTT_BROKER_PERSIST_WRAP_AES_GCM;
    old_meta[11] = 4;
    body[0] = 0;
    body[1] = 0;
    body[2] = (byte)(WOLFMQTT_BROKER_PERSIST_SCHEMA_VER >> 8);
    body[3] = (byte)(WOLFMQTT_BROKER_PERSIST_SCHEMA_VER & 0xFF);
    /* Nonce bytes 12..23 stay zero. Key matches persist_order_derive_key. */
    XMEMSET(key, 0x11, sizeof(key));
    enc_rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (enc_rc == 0) {
        enc_rc = wc_AesGcmSetKey(&aes, key, (word32)sizeof(key));
        if (enc_rc == 0) {
            enc_rc = wc_AesGcmEncrypt(&aes, &old_meta[24], body,
                (word32)sizeof(body), &old_meta[12], 12, &old_meta[28], 16,
                old_meta, 12);
        }
        wc_AesFree(&aes);
    }
    ASSERT_EQ(0, enc_rc);

    install_mock_net(&net);
    XMEMSET(&broker, 0, sizeof(broker));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, takeover_setup_persist(&broker, &hooks));
    (void)kv_put(NULL, BROKER_PERSIST_NS_META, meta_key,
        (word16)sizeof(meta_key), old_meta, (word32)sizeof(old_meta));
    (void)kv_put(NULL, BROKER_PERSIST_NS_OUTQ, outq_key,
        (word16)sizeof(outq_key), blob, (word32)sizeof(blob));

    rc = BrokerPersist_Restore(&broker);
    outq_left = kv_outq_count();
    meta = kv_find(BROKER_PERSIST_NS_META, meta_key,
        (word16)sizeof(meta_key));
    meta_changed = (meta != NULL && (meta->blob_len != sizeof(old_meta) ||
        XMEMCMP(meta->blob, old_meta, sizeof(old_meta)) != 0));
    MqttBroker_Free(&broker);

    /* The restamped META is readable by the current build: a second start
     * restores normally. */
    XMEMSET(&broker2, 0, sizeof(broker2));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_Init(&broker2, &net));
    ASSERT_EQ(MQTT_CODE_SUCCESS, MqttBroker_SetPersistHooks(&broker2, &hooks));
    rc2 = BrokerPersist_Restore(&broker2);
    MqttBroker_Free(&broker2);

    ASSERT_EQ(MQTT_CODE_SUCCESS, rc);
    ASSERT_EQ(0, outq_left);
    ASSERT_TRUE(meta_changed);
    ASSERT_EQ(MQTT_CODE_SUCCESS, rc2);
}
#endif /* WOLFMQTT_BROKER_PERSIST_ENCRYPT */

TEST(persist_takeover_resumes_outbound_qos1_queue)
{
    takeover_resumes_outbound_qos1_queue(1);
}

#if WOLFMQTT_MAX_QOS >= 2
TEST(persist_takeover_resumes_outbound_qos2_pubrel)
{
    takeover_resumes_outbound_qos2_pubrel(1);
}
#endif
#endif /* !WOLFMQTT_STATIC_MEMORY */
#endif /* Persistence backend users */

#if defined(WOLFMQTT_BROKER_PERSIST) && defined(WOLFMQTT_BROKER_RETAINED) && \
    defined(WOLFMQTT_V5)
static int retained_recs(void)
{
    int i, n = 0;
    for (i = 0; i < KV_MAX_RECS; i++) {
        if (g_kv[i].in_use && g_kv[i].ns == BROKER_PERSIST_NS_RETAINED) {
            n++;
        }
    }
    return n;
}

typedef struct PersistFixture {
    MqttBroker broker;
    MqttBrokerNet net;
    MqttBrokerPersistHooks hooks;
    int started;
} PersistFixture;

/* Live retained entries, in whichever allocation profile is built. */
static int retained_live(PersistFixture* f)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i, n = 0;
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        if (f->broker.retained[i].in_use) {
            n++;
        }
    }
    return n;
#else
    return f->broker.retained_count;
#endif
}

/* v5 CONNECT, clean start, ClientId "pt". */
static const byte g_persist_connect[] = {
    0x10, 0x0F,
    0x00, 0x04, 'M', 'Q', 'T', 'T',
    0x05, 0x02, 0x00, 0x3C,
    0x00,
    0x00, 0x02, 'p', 't'
};

/* QoS 0 PUBLISH, RETAIN=1. expiry_sec > 0 adds a Message Expiry Interval;
 * payload_len 0 makes it a retained-delete. */
static size_t build_retained_publish(byte* out, size_t out_sz,
    const char* topic, word32 expiry_sec, int payload_len)
{
    size_t tlen = XSTRLEN(topic);
    size_t proplen = (expiry_sec > 0) ? 5 : 0;
    size_t remain = 2 + tlen + 1 + proplen + (size_t)payload_len;
    size_t i = 0;
    int j;

    if (remain > 127 || out_sz < remain + 2) {
        return 0;
    }
    out[i++] = 0x31;                /* PUBLISH, QoS 0, RETAIN=1 */
    out[i++] = (byte)remain;
    out[i++] = (byte)(tlen >> 8);
    out[i++] = (byte)(tlen & 0xFF);
    XMEMCPY(&out[i], topic, tlen); i += tlen;
    out[i++] = (byte)proplen;
    if (expiry_sec > 0) {
        out[i++] = MQTT_PROP_MSG_EXPIRY_INTERVAL;
        out[i++] = (byte)(expiry_sec >> 24);
        out[i++] = (byte)(expiry_sec >> 16);
        out[i++] = (byte)(expiry_sec >> 8);
        out[i++] = (byte)(expiry_sec);
    }
    for (j = 0; j < payload_len; j++) {
        out[i++] = (byte)('a' + (j % 26));
    }
    return i;
}

static void persist_pump(PersistFixture* f, int steps)
{
    int i;
    for (i = 0; i < steps; i++) {
        MqttBroker_Step(&f->broker);
    }
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
/* Encrypt-at-rest needs a key before the first record is written. A fixed
 * key is enough here: the fixture checks record lifetimes, not secrecy. */
static int persist_fixture_derive_key(void* ctx, byte* out_key,
    word32 key_len)
{
    (void)ctx;
    XMEMSET(out_key, 0x22, key_len);
    return MQTT_CODE_SUCCESS;
}
#endif

/* Bring a broker up over whatever the backend currently holds. */
static int persist_up(PersistFixture* f)
{
    XMEMSET(&f->broker, 0, sizeof(f->broker));
    install_mock_net(&f->net);
    XMEMSET(&f->hooks, 0, sizeof(f->hooks));
    f->hooks.kv_put  = kv_put;
    f->hooks.kv_get  = kv_get;
    f->hooks.kv_del  = kv_del;
    f->hooks.kv_iter = kv_iter;
    f->hooks.sync    = kv_sync;
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    f->hooks.derive_key = persist_fixture_derive_key;
#endif
    reset_mock_clients(1);
    if (MqttBroker_Init(&f->broker, &f->net) != MQTT_CODE_SUCCESS ||
            MqttBroker_SetPersistHooks(&f->broker, &f->hooks) !=
                MQTT_CODE_SUCCESS ||
            MqttBroker_Start(&f->broker) != MQTT_CODE_SUCCESS) {
        return 0;
    }
    f->started = 1;
    return 1;
}

static void persist_down(PersistFixture* f)
{
    if (f->started) {
        (void)MqttBroker_Stop(&f->broker);
        (void)MqttBroker_Free(&f->broker);
        f->started = 0;
    }
}

static int persist_connect(PersistFixture* f)
{
    mock_client_input_append(0, g_persist_connect, sizeof(g_persist_connect));
    persist_pump(f, 4);
#ifdef WOLFMQTT_STATIC_MEMORY
    return f->broker.clients[0].connected;
#else
    return f->broker.clients != NULL && f->broker.clients->connected;
#endif
}

/* Publish n retained topics "<pfx>/NN", each with expiry_sec. */
static int persist_fill(PersistFixture* f, const char* pfx, int n,
    word32 expiry_sec)
{
    byte pkt[192];
    char topic[64];
    int i;
    for (i = 0; i < n; i++) {
        size_t len;
        if (XSNPRINTF(topic, sizeof(topic), "%s/%02d", pfx, i) < 0) {
            return 0;
        }
        len = build_retained_publish(pkt, sizeof(pkt), topic, expiry_sec, 8);
        if (len == 0) {
            return 0;
        }
        mock_client_input_append(0, pkt, len);
    }
    persist_pump(f, n + 4);
    return 1;
}

/* Expiry while the broker is running must retire the stored record, not just
 * the RAM entry. The reap runs off any retained publish. */
TEST(broker_persist_retained_runtime_expiry_drops_record)
{
    PersistFixture f;
    byte pkt[192];
    size_t len;

    kv_reset();
    g_broker_time_s = 1000;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_TRUE(persist_connect(&f));
    ASSERT_TRUE(persist_fill(&f, "run", BROKER_MAX_RETAINED, 60));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_live(&f));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());

    g_broker_time_s += 61;
    len = build_retained_publish(pkt, sizeof(pkt), "run/next", 0, 8);
    ASSERT_TRUE(len > 0);
    mock_client_input_append(0, pkt, len);
    persist_pump(&f, 4);

    ASSERT_EQ(1, retained_live(&f));
    ASSERT_EQ(1, retained_recs());
    persist_down(&f);
}

/* Records written live, then expiring while the broker is down, are the case
 * a running broker can never reach again: nothing holds them in RAM, so only
 * the restore sweep can retire them. One restart must clear the whole batch. */
TEST(broker_persist_retained_offline_expiry_swept_on_restart)
{
    PersistFixture f;

    kv_reset();
    g_broker_time_s = 1000;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_TRUE(persist_connect(&f));
    ASSERT_TRUE(persist_fill(&f, "off", BROKER_MAX_RETAINED, 60));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());

    /* Clean shutdown: retained records are meant to survive it. */
    persist_down(&f);
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());

    g_broker_time_s += 61;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_EQ(0, retained_live(&f));
    ASSERT_EQ(0, retained_recs());
    persist_down(&f);
}

/* A store carrying more stale records than the live cap - what an unpatched
 * broker left behind - must drain inside a single BrokerPersist_Restore, not
 * one record per restart. Built from real broker-written blobs so the sweep
 * parses exactly what the writer produces. */
TEST(broker_persist_retained_backlog_swept_in_one_restore)
{
    PersistFixture f;
    KvRec saved[3 * BROKER_MAX_RETAINED];
    int saved_n = 0;
    int round, i;

    g_broker_time_s = 1000;
    for (round = 0; round < 3; round++) {
        char pfx[16];
        /* Keep the format string out of the assert: ASSERT_TRUE stringifies
         * the expression into its own printf format. */
        int n = XSNPRINTF(pfx, sizeof(pfx), "old%d", round);
        ASSERT_TRUE(n > 0);
        kv_reset();
        ASSERT_TRUE(persist_up(&f));
        ASSERT_TRUE(persist_connect(&f));
        ASSERT_TRUE(persist_fill(&f, pfx, BROKER_MAX_RETAINED, 60));
        ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());
        persist_down(&f);
        for (i = 0; i < KV_MAX_RECS; i++) {
            if (g_kv[i].in_use &&
                    g_kv[i].ns == BROKER_PERSIST_NS_RETAINED) {
                saved[saved_n++] = g_kv[i];
            }
        }
    }
    ASSERT_EQ(3 * BROKER_MAX_RETAINED, saved_n);

    /* Fold the earlier rounds into the last round's store, which still carries
     * its META record - restore treats a store without one as a first run and
     * returns before the sweep. */
    for (i = 0; i < saved_n; i++) {
        ASSERT_EQ(0, kv_put(NULL, saved[i].ns, saved[i].key, saved[i].key_len,
            saved[i].blob, saved[i].blob_len));
    }
    ASSERT_EQ(3 * BROKER_MAX_RETAINED, retained_recs());

    g_broker_time_s += 61;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_EQ(0, retained_live(&f));
    ASSERT_EQ(0, retained_recs());
    persist_down(&f);
}

/* The sweep keys off the Message Expiry Interval, so a retained message
 * without one has to survive it - including across a restart, which is the
 * whole point of persisting retained messages. */
TEST(broker_persist_retained_without_expiry_survives_sweep)
{
    PersistFixture f;

    kv_reset();
    g_broker_time_s = 1000;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_TRUE(persist_connect(&f));
    ASSERT_TRUE(persist_fill(&f, "keep", BROKER_MAX_RETAINED, 0));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());
    persist_down(&f);

    g_broker_time_s += 100000;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_live(&f));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());
    persist_down(&f);
}

/* A zero-payload retained PUBLISH removes exactly its own record. */
TEST(broker_persist_retained_explicit_delete_drops_one_record)
{
    PersistFixture f;
    byte pkt[192];
    size_t len;

    kv_reset();
    g_broker_time_s = 1000;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_TRUE(persist_connect(&f));
    ASSERT_TRUE(persist_fill(&f, "del", 2, 0));
    ASSERT_EQ(2, retained_recs());

    len = build_retained_publish(pkt, sizeof(pkt), "del/00", 0, 0);
    ASSERT_TRUE(len > 0);
    mock_client_input_append(0, pkt, len);
    persist_pump(&f, 4);

    ASSERT_EQ(1, retained_live(&f));
    ASSERT_EQ(1, retained_recs());
    ASSERT_TRUE(kv_find(BROKER_PERSIST_NS_RETAINED,
        (const byte*)"del/01", 6) != NULL);
    persist_down(&f);
}

/* A backward clock step must not make live records look expired - the sweep
 * deletes what it judges expired, so a wrong judgement destroys live data. */
TEST(broker_persist_retained_clock_rollback_keeps_records)
{
    PersistFixture f;

    kv_reset();
    g_broker_time_s = 1000;
    ASSERT_TRUE(persist_up(&f));
    ASSERT_TRUE(persist_connect(&f));
    ASSERT_TRUE(persist_fill(&f, "back", BROKER_MAX_RETAINED, 60));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());
    persist_down(&f);

    g_broker_time_s -= 500; /* records are now stamped in the future */
    ASSERT_TRUE(persist_up(&f));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_live(&f));
    ASSERT_EQ(BROKER_MAX_RETAINED, retained_recs());
    persist_down(&f);
}

#endif /* WOLFMQTT_BROKER_PERSIST && WOLFMQTT_BROKER_RETAINED && WOLFMQTT_V5 */

int main(int argc, char** argv)
{
    (void)argc; (void)argv;

    TEST_RUNNER_BEGIN();

    TEST_SUITE_BEGIN("broker_connect", setup, teardown);
    RUN_TEST(connect_v311_emptyid_clean0_refused);
    RUN_TEST(connect_v311_emptyid_clean1_accepted);
    RUN_TEST(connect_v311_nonempty_clean0_accepted);
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_v311_client_id_alloc_failure_refused);
#ifdef WOLFMQTT_V5
    RUN_TEST(connect_v5_client_id_alloc_failure_refused);
#endif
#endif
#if !defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_BROKER_WILL)
    RUN_TEST(connect_will_topic_alloc_failure_refused);
    RUN_TEST(connect_will_payload_alloc_failure_refused);
    RUN_TEST(connect_v311_resume_will_alloc_failure_leaves_no_session);
#ifdef WOLFMQTT_V5
    RUN_TEST(connect_v5_will_alloc_failure_leaves_no_session);
#endif
    RUN_TEST(connect_will_alloc_failure_keeps_incumbent_session);
#endif
#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
    RUN_TEST(connect_v5_oversize_will_payload_emits_connack);
    #ifdef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_v5_oversize_will_props_emits_connack);
    #if BROKER_MAX_STATIC_OFFLINE_DATA_LEN - 5 < BROKER_MAX_WILL_PAYLOAD_LEN && \
        WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(connect_v5_static_will_exceeding_offline_slot_refused);
    #endif
    #if BROKER_MAX_STATIC_OFFLINE_DATA_LEN < BROKER_MAX_WILL_PAYLOAD_LEN && \
        WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(connect_v5_static_payload_only_will_exceeding_offline_slot_refused);
    RUN_TEST(connect_v311_static_will_exceeding_offline_slot_refused);
    #endif
    RUN_TEST(connect_v5_oversize_will_topic_emits_connack);
    #endif
#endif
#ifdef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_V5
    RUN_TEST(static_quota_refusal_connack_has_no_properties);
#endif
    RUN_TEST(static_fanout_does_not_reuse_unacked_packet_id);
    RUN_TEST(static_retained_releases_packet_id_on_write_failure);
    RUN_TEST(static_fanout_drops_delivery_when_ids_exhausted);
#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 2
    RUN_TEST(static_fanout_releases_packet_id_on_v5_pubrec_reject);
#endif
#endif
    RUN_TEST(connect_v311_explicit_auto_prefix_refused);
    RUN_TEST(connect_unsupported_level_3_refused);
    RUN_TEST(connect_unsupported_level_6_refused);
    RUN_TEST(connect_unsupported_level_127_refused);
    RUN_TEST(connect_unsupported_level_undecodable_refused);
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_persistent_session_cap_refuses_new_session);
    RUN_TEST(connect_persistent_session_cap_counts_live_sessions);
#endif
#ifndef WOLFMQTT_V5
    RUN_TEST(connect_v5_to_non_v5_broker_refused);
#endif
#ifdef WOLFMQTT_BROKER_AUTH
    RUN_TEST(connect_v311_binary_password_with_embedded_nul_refused);
    RUN_TEST(connect_v311_binary_password_exact_match_accepted);
    RUN_TEST(connect_auth_username_length_fold_repeating_byte_refused);
    RUN_TEST(connect_unauth_client_id_does_not_take_over_victim);
    RUN_TEST(connect_auth_user_only_start_rejected);
    RUN_TEST(connect_auth_pass_only_start_rejected);
    RUN_TEST(connect_auth_partial_config_fails_closed);
    RUN_TEST(connect_auth_partial_pass_only_fails_closed);
    RUN_TEST(broker_set_auth_pass_valid);
    RUN_TEST(broker_set_auth_pass_max_len_valid);
    RUN_TEST(broker_set_auth_pass_too_long_rejected);
    RUN_TEST(broker_set_auth_pass_too_long_wipes_prior);
    RUN_TEST(broker_set_auth_pass_shorter_second_no_residue);
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_credentials_scrubbed_after_accept);
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(connect_refused_deferred_connack_scrubs_credentials);
#endif
#endif
#endif
#ifdef ENABLE_MQTT_TLS
    RUN_TEST(broker_start_partial_listener_failure_cleans_up);
    RUN_TEST(broker_add_failure_closes_socket_once);
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(connect_v5_emptyid_assigned_id_emitted);
    RUN_TEST(connect_v5_emptyid_assigned_id_survives_prop_pool_pressure);
    RUN_TEST(connect_v5_emptyid_clean0_accepted);
    RUN_TEST(unsubscribe_v5_reason_codes);
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(fanout_subs_generation_bumped_on_unsubscribe);
    RUN_TEST(fanout_survives_reentrant_sub_free);
#ifdef WOLFMQTT_BROKER_WILL
    RUN_TEST(will_fanout_survives_reentrant_sub_free);
    RUN_TEST(takeover_will_claimed_before_fanout);
#endif
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
    RUN_TEST(qos2_topic_alloc_failure_retransmit_delivered);
#ifdef WOLFMQTT_V5
    RUN_TEST(online_qos1_flood_disconnects_slow_v5_subscriber);
#endif /* WOLFMQTT_V5 */
    RUN_TEST(online_qos1_flood_disconnects_slow_v311_subscriber);
    RUN_TEST(online_qos1_at_cap_keeps_subscriber);
    RUN_TEST(outbound_packet_ids_are_scoped_per_session);
    RUN_TEST(outbound_publish_exceeding_tx_buf_not_sent_truncated);
#ifdef WOLFMQTT_V5
    RUN_TEST(publish_qos1_exceeding_sub_tx_buf_not_acked);
#if WOLFMQTT_MAX_QOS >= 2
    RUN_TEST(publish_qos2_exceeding_sub_tx_buf_not_acked);
#endif
#endif
    RUN_TEST(outbound_qos2_puback_does_not_complete_delivery);
    RUN_TEST(publish_fanout_alloc_failure_v311_not_acked);
    RUN_TEST(publish_offline_fanout_alloc_failure_v311_not_acked);
#ifdef WOLFMQTT_V5
    RUN_TEST(publish_fanout_alloc_failure_v5_qos2_pubrec_failure);
#endif
    RUN_TEST(drain_stops_when_session_handoff_takes_queue);
#if WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(handoff_marks_sent_qos1_for_redelivery);
    RUN_TEST(handoff_marks_partly_sent_qos1_for_redelivery);
#endif
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(outbound_queue_short_write_resumes_on_next_step);
#ifdef WOLFMQTT_BROKER_RETAINED
    RUN_TEST(retained_publish_waits_for_partial_suback);
#endif
    RUN_TEST(self_publish_waits_for_partial_puback);
    RUN_TEST(refused_connack_short_write_delivers_return_code_before_close);
    RUN_TEST(refused_connack_short_write_leaves_no_client);
    RUN_TEST(refused_connack_resume_write_failure_drops_client);
    RUN_TEST(accepted_connack_pending_times_out_and_closes);
    RUN_TEST(accepted_connack_pending_survives_keepalive_deadline);
    RUN_TEST(pending_write_does_not_bypass_keepalive);
    RUN_TEST(outbound_zero_progress_retry_keeps_dup_clear);
    RUN_TEST(outbound_qos0_partial_failure_not_replayed_on_reconnect);
    RUN_TEST(outbound_qos0_transient_timeout_not_replayed_on_reconnect);
    RUN_TEST(outbound_qos0_partial_behind_unacked_qos1_not_replayed);
    RUN_TEST(takeover_drops_partial_qos0_after_unacked_qos1);
    RUN_TEST(takeover_keeps_qos0_behind_partial_direct_write);
    RUN_TEST(outbound_partial_failure_reconnect_sets_dup);
#endif
#if !defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(outbound_blocking_partial_failure_reconnect_sets_dup);
#endif
#endif /* !WOLFMQTT_STATIC_MEMORY */
#ifdef WOLFMQTT_V5
    RUN_TEST(qos2_publish_v5_props_with_offline_durable_subscriber);
#endif
    RUN_TEST(pingreq_valid_emits_pingresp);
    RUN_TEST(pingreq_nonzero_remain_len_closes_no_pingresp);
#ifdef WOLFMQTT_BROKER_WILL
    RUN_TEST(pingresp_write_failure_fires_will);
    RUN_TEST(suback_write_failure_fires_will);
#if WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(puback_write_failure_fires_will);
#endif
#endif
    RUN_TEST(broker_keepalive_expires_at_exact_deadline);
    RUN_TEST(broker_step_reports_listener_accept_failure);
#if !defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
    RUN_TEST(disconnect_v311_nonzero_remain_len_fires_will);
#endif
#ifdef WOLFMQTT_BROKER_WILL
    RUN_TEST(disconnect_invalid_fixed_header_flags_fires_will);
#endif
#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
    RUN_TEST(disconnect_v5_malformed_fires_will);
    RUN_TEST(disconnect_v5_reason_0_discards_will);
    RUN_TEST(disconnect_v5_reason_4_publishes_will);
    RUN_TEST(disconnect_v5_reason_error_publishes_will);
    RUN_TEST(takeover_v5_zero_will_delay_publishes_will);
    RUN_TEST(takeover_v5_own_will_not_sent_after_disconnect);
#if !defined(WOLFMQTT_STATIC_MEMORY) && WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(takeover_v5_resumed_session_gets_queued_self_will);
    RUN_TEST(takeover_v5_clean_start_frees_queued_self_will);
#endif
#if defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(takeover_v5_own_will_partial_write_still_disconnects);
#endif
    RUN_TEST(takeover_v5_will_delay_resumed_session_discards_will);
    RUN_TEST(takeover_v5_clean_start_publishes_will);
    RUN_TEST(takeover_v5_zero_session_expiry_publishes_will);
#ifndef WOLFMQTT_DYN_PROP
    RUN_TEST(disconnect_v5_props_pool_exhausted_reason_0_discards_will);
    RUN_TEST(disconnect_v5_props_pool_exhausted_reason_4_publishes_will);
    RUN_TEST(disconnect_v5_props_pool_exhausted_reason_error_publishes_will);
#endif
#endif
#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(reclaim_keeps_explicit_v5_never_expire);
    RUN_TEST(reclaim_v311_resume_never_expires);
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(live_forward_exceeding_tx_buf_not_sent_truncated);
    RUN_TEST(retained_delivery_exceeding_tx_buf_not_sent_truncated);
#endif
#if !defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_BROKER_WILL)
    RUN_TEST(will_qos0_exceeding_tx_buf_not_sent_truncated);
    RUN_TEST(will_qos1_queued_for_offline_persistent_subscriber);
#endif
#if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
    RUN_TEST(will_props_forwarded_to_live_subscriber);
    RUN_TEST(delayed_will_props_forwarded_to_live_subscriber);
#if WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(delayed_will_props_decoded_with_no_clients);
#endif
#ifndef WOLFMQTT_DYN_PROP
    RUN_TEST(will_props_published_with_prop_pool_exhausted);
#endif
#if !defined(WOLFMQTT_STATIC_MEMORY) && \
    BROKER_WILL_PROPS_STACK_ENTRIES < WILL_TEST_MAX_USER_PROPS
    RUN_TEST(will_props_beyond_stack_entries_forwarded);
#endif
#if WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(queued_will_expired_before_delivery_dropped);
    RUN_TEST(queued_will_expiry_reduced_by_wait);
    RUN_TEST(queued_will_zero_expiry_dropped);
#endif
#endif
#if defined(WOLFMQTT_BROKER_WILL) && defined(WOLFMQTT_BROKER_WILDCARDS) && \
    WOLFMQTT_MAX_QOS >= 2
    RUN_TEST(will_offline_overlapping_subs_queue_max_qos_once);
#endif
#if !defined(WOLFMQTT_STATIC_MEMORY) && defined(WOLFMQTT_V5)
    RUN_TEST(queued_publish_expired_before_delivery_dropped);
    RUN_TEST(queued_publish_expiry_reduced_by_wait);
    RUN_TEST(queued_publish_zero_expiry_dropped);
    RUN_TEST(queued_publish_expired_behind_inflight_cap_dropped);
    RUN_TEST(inflight_publish_resent_after_expiry);
#ifdef WOLFMQTT_BROKER_PERSIST
    RUN_TEST(queued_publish_expired_deletes_persisted_record);
#endif
#endif
#if defined(WOLFMQTT_BROKER_WILL) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(broker_will_scrub_after_failed_write);
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(pending_publish_preserves_qos0_will);
#endif
#endif
    RUN_TEST(broker_unhandled_packet_type_closes);
    RUN_TEST(broker_publish_before_connect_closes);
#if defined(WOLFMQTT_BROKER_RETAINED) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(broker_retained_list_capped);
    RUN_TEST(broker_retained_clock_rollback_not_expired);
#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 2
    RUN_TEST(qos2_retained_store_full_delivers_live);
#endif
#if WOLFMQTT_MAX_QOS >= 2
    RUN_TEST(qos2_retained_store_full_v311_delivers_live);
#endif
#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(qos1_retained_store_full_delivers_live);
    RUN_TEST(qos1_retained_store_alloc_failure_delivers_live);
#endif
    RUN_TEST(broker_retained_scrub_after_completed_write);
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(retained_short_write_preserves_following_delivery);
#endif
#endif
/* Both allocation profiles: the retained store and its expiry paths have
 * separate implementations, so each has to be swept correctly. */
#if defined(WOLFMQTT_BROKER_PERSIST) && defined(WOLFMQTT_BROKER_RETAINED) && \
    defined(WOLFMQTT_V5)
    RUN_TEST(broker_persist_retained_runtime_expiry_drops_record);
    RUN_TEST(broker_persist_retained_offline_expiry_swept_on_restart);
    RUN_TEST(broker_persist_retained_backlog_swept_in_one_restore);
    RUN_TEST(broker_persist_retained_without_expiry_survives_sweep);
    RUN_TEST(broker_persist_retained_explicit_delete_drops_one_record);
    RUN_TEST(broker_persist_retained_clock_rollback_keeps_records);
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(broker_subscription_client_id_alloc_failure_atomic);
    RUN_TEST(broker_per_client_subscription_cap);
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(broker_publish_with_subscription_id_closes);
#endif
    RUN_TEST(broker_subscribe_packet_id_zero_closes);
    RUN_TEST(connack_session_present_set_on_resumed_session);
    RUN_TEST(connack_session_present_set_on_takeover);
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(takeover_resumes_outbound_qos1_queue);
#if WOLFMQTT_MAX_QOS >= 2
    RUN_TEST(takeover_resumes_outbound_qos2_pubrel);
#endif
#ifdef WOLFMQTT_V5
    RUN_TEST(takeover_outbound_publish_uses_resumed_protocol);
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(takeover_v5_partial_qos0_closes_without_splicing);
#endif
#endif
#endif
    RUN_TEST(connack_session_present_clear_on_clean_session_reconnect);
#ifdef WOLFMQTT_V5
    RUN_TEST(connack_session_present_v5_set_on_resumed_session);
    RUN_TEST(broker_shared_subscription_not_supported_v5);
#ifndef WOLFMQTT_DYN_PROP
    RUN_TEST(connect_v5_refused_when_shared_sub_property_unavailable);
    RUN_TEST(connect_v5_refused_when_receive_max_property_unavailable);
    RUN_TEST(connect_v5_connack_property_failure_keeps_incumbent_session);
#endif
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
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(retained_delivery_alloc_failure_prevents_success_suback);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(qos2_dedup_survives_disconnect_reconnect);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_v5_receive_max_zero_protocol_error);
    RUN_TEST(disconnect_v5_session_expiry_raise_sends_protocol_error);
#endif
    RUN_TEST(v5_invalid_fixed_header_flags_sends_malformed_disconnect);
    RUN_TEST(v5_second_connect_sends_protocol_error_disconnect);
    RUN_TEST(v5_pingreq_with_body_sends_malformed_disconnect);
    RUN_TEST(v5_unexpected_auth_sends_protocol_error_disconnect);
#if defined(WOLFMQTT_NONBLOCK) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(v5_error_close_waits_for_deferred_disconnect);
#endif
#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(v5_static_error_close_leaves_no_partial_disconnect);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_v5_clean0_no_se_prop_orphan_expiry_zero);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(disconnect_v5_zero_subs_nonzero_expiry_creates_orphan);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(orphan_expire_sweep_removes_zero_expiry_session);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_BROKER_WILL
    RUN_TEST(disconnect_v5_session_expiry_0_to_nonzero_protocol_error);
#ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(disconnect_v5_session_expiry_protocol_error_short_write_completes);
#endif
#endif
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_BROKER_RETAINED
    RUN_TEST(subscribe_v5_retain_handling_2_never_delivers);
#endif
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(publish_v5_props_survive_queued_delivery);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_BROKER_RETAINED
    RUN_TEST(retained_qos1_delivery_survives_via_outq);
#endif
#endif
#endif
#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY) && \
    defined(WOLFMQTT_BROKER_WILL)
    RUN_TEST(pending_will_publish_time_uses_min_of_delay_and_session_expiry);
    RUN_TEST(will_delay_interval_capped);
#if WOLFMQTT_MAX_QOS < 2
    RUN_TEST(connect_v5_will_qos_exceeds_max_refused);
#endif
#ifndef WOLFMQTT_BROKER_RETAINED
    RUN_TEST(connect_v5_will_retain_unsupported_refused);
#endif
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(puback_malformed_closes_connection);
    RUN_TEST(pubcomp_malformed_closes_connection);
    RUN_TEST(orphan_expire_sweep_backward_clock_keeps_session);
#endif
#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(disconnect_v5_session_expiry_updated_on_valid);
    RUN_TEST(orphan_offline_queue_clones_v5_publish_props);
#endif
#if defined(WOLFMQTT_BROKER_RETAINED) && defined(WOLFMQTT_V5)
    RUN_TEST(subscribe_v5_retain_handling_0_delivers);
    RUN_TEST(subscribe_v5_retain_handling_1_only_if_new);
#endif
#if defined(WOLFMQTT_BROKER_WILL) && !defined(WOLFMQTT_STATIC_MEMORY)
    RUN_TEST(will_qos1_routes_through_outq);
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_v5_auth_method_present_rejected);
#endif
#endif
#ifdef WOLFMQTT_V5
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(connect_v5_max_packet_size_zero_protocol_error);
#endif
#endif
#if !defined(WOLFMQTT_STATIC_MEMORY) && (WOLFMQTT_MAX_QOS >= 2)
    RUN_TEST(pubrec_for_qos1_publish_not_advanced);
#endif
#ifdef WOLFMQTT_BROKER_PERSIST
    #ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(persist_commit_reports_sync_failure);
    RUN_TEST(persist_del_outqueue_reports_failures);
    RUN_TEST(persist_schema_wipe_failure_keeps_old_meta);
    RUN_TEST(persist_restore_alloc_failure_is_fatal);
    RUN_TEST(persist_restore_skips_sessions_over_cap);
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    RUN_TEST(persist_encrypted_record_bound_to_storage_key);
    RUN_TEST(persist_header_only_aad_store_is_wiped);
#endif
    RUN_TEST(persist_takeover_resumes_outbound_qos1_queue);
        #if WOLFMQTT_MAX_QOS >= 2
    RUN_TEST(persist_takeover_resumes_outbound_qos2_pubrel);
        #endif
    #endif
    RUN_TEST(persist_parent_component_rejected_as_bad_argument);
    RUN_TEST(persist_iter_skips_fifo_without_blocking);
    RUN_TEST(persist_iter_keys_are_deletable);
#ifndef WOLFMQTT_STATIC_MEMORY
    RUN_TEST(persist_restore_packet_id_wrap_preserves_fifo);
    RUN_TEST(persist_restore_rejects_outq_packet_id_mismatch);
    RUN_TEST(persist_subs_written_when_ack_write_fails);
    #ifdef WOLFMQTT_NONBLOCK
    RUN_TEST(persist_subs_written_when_ack_deferred);
    RUN_TEST(persist_partial_publish_restart_keeps_dup);
    #endif
#if WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(persist_handoff_sent_qos1_restart_keeps_dup);
#endif
    RUN_TEST(persist_mixed_qos_queue_preserves_fifo);
    #if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL) && \
        WOLFMQTT_MAX_QOS >= 1
    RUN_TEST(persist_restart_keeps_queued_will_props);
    #endif
    RUN_TEST(orphan_reclaim_keeps_persisted_outq);
#endif
    RUN_TEST(persist_stream_only_hooks_rejected);
    RUN_TEST(persist_mixed_kv_and_stream_hooks_accepted);
    #ifdef __MACH__
    RUN_TEST(persist_root_below_macos_tmp_alias_accepted);
    #endif
    RUN_TEST(persist_root_readable_permissions_accepted);
    RUN_TEST(persist_root_writable_permissions_rejected);
    RUN_TEST(persist_put_rejects_existing_temp_symlink);
    RUN_TEST(persist_put_del_report_namespace_fsync_failure);
    RUN_TEST(persist_get_reports_record_larger_than_buffer);
    RUN_TEST(persist_key_longer_than_name_limit_rejected);
#ifndef WOLFMQTT_STATIC_MEMORY
#ifdef WOLFMQTT_BROKER_RETAINED
    RUN_TEST(persist_restore_retained_alloc_failure_scrubs_topic);
#endif
    RUN_TEST(persist_restore_outq_alloc_failure_scrubs_topic);
#ifndef WOLFMQTT_BROKER_PERSIST_ENCRYPT
#ifdef WOLFMQTT_BROKER_RETAINED
    RUN_TEST(persist_restore_malformed_retained_scrubs_topic);
#endif
    RUN_TEST(persist_restore_malformed_outq_scrubs_topic);
#ifdef WOLFMQTT_V5
    RUN_TEST(persist_restore_rejects_malformed_outq_props);
#endif
#endif
#endif
    RUN_TEST(persist_iter_reports_unreadable_record);
    RUN_TEST(persist_iter_skips_socket_and_symlink_entries);
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    RUN_TEST(persist_failed_key_derivation_scrubs_cache);
    RUN_TEST(persist_bad_tag_scrubs_plaintext_before_free);
    RUN_TEST(persist_hook_replacement_rekeys_cache);
#endif
#endif
    TEST_SUITE_END();

    TEST_RUNNER_END();
}
