/* broker_fuzz.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* libFuzzer harness for the wolfMQTT broker.
 *
 * Mocks the MqttBrokerNet callbacks to feed raw MQTT packets from the fuzzer
 * into the broker's accept -> read -> process path via MqttBroker_Step().
 *
 * The fuzzer input is treated as a raw byte stream that may contain one or
 * more MQTT packets. The broker processes one packet per Step() call:
 *   - Step 1: accept client + read/process first packet (must be CONNECT)
 *   - Step 2-N: read/process subsequent packets (PUBLISH, SUBSCRIBE, etc.)
 *
 * Seed corpus includes multi-packet sequences (CONNECT + PUBLISH, etc.)
 * so the fuzzer learns the CONNECT-first requirement via coverage feedback.
 *
 * Build: ./configure --enable-broker --enable-v5 --enable-fuzz --disable-tls
 *        make CC=clang \
 *          CFLAGS="-fsanitize=fuzzer-no-link,address -g" \
 *          LDFLAGS="-fsanitize=fuzzer,address"
 *
 * Run:   ./tests/fuzz/broker_fuzz tests/fuzz/corpus/ -dict=tests/fuzz/mqtt.dict \
 *          -max_len=4096 -timeout=10
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfmqtt/mqtt_types.h>

#ifdef WOLFMQTT_BROKER

#include <wolfmqtt/mqtt_broker.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* libFuzzer entry point prototypes */
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Fake socket constants */
#define FUZZ_FAKE_LISTEN_SOCK  100
#define FUZZ_FAKE_SOCK         101

/* Maximum Step() calls per input — enough for CONNECT + several packets */
#define FUZZ_MAX_STEPS         6

/* Input size limits */
#define FUZZ_MIN_INPUT_SIZE    2       /* MQTT fixed header minimum */
#define FUZZ_MAX_INPUT_SIZE    BROKER_RX_BUF_SZ  /* 4096 */

/* Global broker state */
static MqttBroker g_broker;
static MqttBrokerNet g_net;
static int g_initialized = 0;

/* Per-iteration fuzzer data */
static const uint8_t *g_fuzz_data = NULL;
static size_t g_fuzz_size = 0;
static size_t g_fuzz_pos = 0;
static int g_client_accepted = 0;

/* -------------------------------------------------------------------------- */
/* Mock network callbacks                                                      */
/* -------------------------------------------------------------------------- */

static int fuzz_listen(void* ctx, BROKER_SOCKET_T* sock,
    word16 port, int backlog)
{
    (void)ctx;
    (void)port;
    (void)backlog;
    *sock = FUZZ_FAKE_LISTEN_SOCK;
    return MQTT_CODE_SUCCESS;
}

static int fuzz_accept(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock)
{
    (void)ctx;
    (void)listen_sock;

    if (!g_client_accepted) {
        g_client_accepted = 1;
        *client_sock = FUZZ_FAKE_SOCK;
        return MQTT_CODE_SUCCESS;
    }
    return MQTT_CODE_ERROR_TIMEOUT;
}

static int fuzz_read(void* ctx, BROKER_SOCKET_T sock,
    byte* buf, int buf_len, int timeout_ms)
{
    int avail;

    (void)ctx;
    (void)timeout_ms;

    if (sock != FUZZ_FAKE_SOCK) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }

    if (g_fuzz_pos >= g_fuzz_size) {
        return MQTT_CODE_ERROR_TIMEOUT; /* data exhausted */
    }

    avail = (int)(g_fuzz_size - g_fuzz_pos);
    if (buf_len > avail) {
        buf_len = avail;
    }
    XMEMCPY(buf, g_fuzz_data + g_fuzz_pos, (size_t)buf_len);
    g_fuzz_pos += (size_t)buf_len;
    return buf_len;
}

static int fuzz_write(void* ctx, BROKER_SOCKET_T sock,
    const byte* buf, int buf_len, int timeout_ms)
{
    (void)ctx;
    (void)sock;
    (void)buf;
    (void)timeout_ms;
    return buf_len; /* discard output */
}

static int fuzz_close(void* ctx, BROKER_SOCKET_T sock)
{
    (void)ctx;
    (void)sock;
    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Broker init/cleanup helpers                                                 */
/* -------------------------------------------------------------------------- */

static int fuzz_broker_init(void)
{
    int rc;
    XMEMSET(&g_broker, 0, sizeof(g_broker));
    rc = MqttBroker_Init(&g_broker, &g_net);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
    return MqttBroker_Start(&g_broker);
}

static void fuzz_broker_cleanup(void)
{
    MqttBroker_Stop(&g_broker);
    MqttBroker_Free(&g_broker);
}

/* -------------------------------------------------------------------------- */
/* libFuzzer entry points                                                      */
/* -------------------------------------------------------------------------- */

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    XMEMSET(&g_net, 0, sizeof(g_net));
    g_net.listen = fuzz_listen;
    g_net.accept = fuzz_accept;
    g_net.read   = fuzz_read;
    g_net.write  = fuzz_write;
    g_net.close  = fuzz_close;

    if (fuzz_broker_init() == MQTT_CODE_SUCCESS) {
        g_initialized = 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int i;

    if (!g_initialized) {
        return 0;
    }

    if (size < FUZZ_MIN_INPUT_SIZE || size > FUZZ_MAX_INPUT_SIZE) {
        return 0;
    }

    /* Set up fuzzer data for mock callbacks */
    g_fuzz_data = data;
    g_fuzz_size = size;
    g_fuzz_pos = 0;
    g_client_accepted = 0;

    /* Run multiple steps to process multi-packet sequences.
     * Step 1: accept + process first packet (should be CONNECT).
     * Steps 2-N: process subsequent packets (PUBLISH, SUBSCRIBE, etc.).
     * Stop early if all data is consumed. */
    for (i = 0; i < FUZZ_MAX_STEPS; i++) {
        MqttBroker_Step(&g_broker);
        if (g_fuzz_pos >= g_fuzz_size) {
            /* Run one more step to process any pending responses */
            MqttBroker_Step(&g_broker);
            break;
        }
    }

    /* Clean up client state so accept() can create a fresh one next time */
    fuzz_broker_cleanup();
    fuzz_broker_init();

    return 0;
}

#else /* !WOLFMQTT_BROKER */

#include <stdint.h>
#include <stddef.h>

/* Stub when broker is not enabled */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}

#endif /* WOLFMQTT_BROKER */
