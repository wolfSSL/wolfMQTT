/* test_mqtt_tls_host.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"

#if defined(ENABLE_MQTT_TLS) && !defined(ENABLE_MQTT_CURL) && \
    !defined(_WIN32) && !defined(WOLFMQTT_NO_FILESYSTEM) && \
    !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_CERT) && \
    !defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_TLS12)

#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TEST_CERT_FILE WOLFMQTT_TEST_CERT_DIR "/tls-host-test-cert.pem"
#define TEST_KEY_FILE  WOLFMQTT_TEST_CERT_DIR "/client-key.pem"

typedef struct TlsTestNet {
    int fd;
} TlsTestNet;

typedef struct TlsTestServer {
    WOLFSSL* ssl;
    int result;
} TlsTestServer;

static const char* g_tls_test_identity;
static int g_tls_test_precreate;

static int tls_test_connect(void* context, const char* host, word16 port,
    int timeout_ms)
{
    (void)context;
    (void)host;
    (void)port;
    (void)timeout_ms;
    return MQTT_CODE_SUCCESS;
}

static int tls_test_read(void* context, byte* buf, int len, int timeout_ms)
{
    TlsTestNet* net = (TlsTestNet*)context;
    int rc;

    (void)timeout_ms;
    rc = (int)recv(net->fd, buf, (size_t)len, 0);
    return rc > 0 ? rc : MQTT_CODE_ERROR_NETWORK;
}

static int tls_test_write(void* context, const byte* buf, int len,
    int timeout_ms)
{
    TlsTestNet* net = (TlsTestNet*)context;
    int rc;

    (void)timeout_ms;
    rc = (int)send(net->fd, buf, (size_t)len, 0);
    return rc > 0 ? rc : MQTT_CODE_ERROR_NETWORK;
}

static int tls_test_disconnect(void* context)
{
    TlsTestNet* net = (TlsTestNet*)context;

    if (net->fd >= 0) {
        (void)close(net->fd);
        net->fd = -1;
    }
    return MQTT_CODE_SUCCESS;
}

static int tls_test_setup_client(MqttClient* client)
{
    int rc;

    client->tls.ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (client->tls.ctx == NULL) {
        return WOLFSSL_FAILURE;
    }
    wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER, NULL);
    rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx,
        TEST_CERT_FILE, NULL);
    if (rc == WOLFSSL_SUCCESS && (g_tls_test_identity != NULL ||
            g_tls_test_precreate)) {
#ifdef HAVE_SNI
        if (g_tls_test_identity != NULL) {
            rc = wolfSSL_CTX_UseSNI(client->tls.ctx,
                WOLFSSL_SNI_HOST_NAME, g_tls_test_identity,
                (word16)XSTRLEN(g_tls_test_identity));
            if (rc != WOLFSSL_SUCCESS) {
                return rc;
            }
        }
#endif
        client->tls.ssl = wolfSSL_new(client->tls.ctx);
        if (client->tls.ssl == NULL) {
            return WOLFSSL_FAILURE;
        }
        if (g_tls_test_identity != NULL) {
            rc = wolfSSL_check_domain_name(client->tls.ssl,
                g_tls_test_identity);
            if (rc == WOLFSSL_SUCCESS) {
                (void)MqttClient_Flags(client, 0,
                    MQTT_CLIENT_FLAG_TLS_CUSTOM_PEER_NAME);
            }
        }
    }
    return rc;
}

static void* tls_test_server_run(void* arg)
{
    TlsTestServer* server = (TlsTestServer*)arg;

    server->result = wolfSSL_accept(server->ssl);
    return NULL;
}

static int tls_test_host(const char* host, const char* identity,
    int precreate, int expected)
{
    MqttClient client;
    MqttNet net;
    TlsTestNet client_net;
    TlsTestServer server;
    WOLFSSL_CTX* server_ctx = NULL;
    pthread_t thread;
    byte tx_buf[256];
    byte rx_buf[256];
    struct timeval timeout;
    int sockets[2] = { -1, -1 };
    int client_inited = 0;
    int thread_started = 0;
    int rc = 1;
    int connect_rc;

    XMEMSET(&client, 0, sizeof(client));
    XMEMSET(&net, 0, sizeof(net));
    XMEMSET(&server, 0, sizeof(server));
    client_net.fd = -1;
    g_tls_test_identity = identity;
    g_tls_test_precreate = precreate;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        goto cleanup;
    }
    client_net.fd = sockets[0];
    sockets[0] = -1;
    (void)setsockopt(client_net.fd, SOL_SOCKET, SO_RCVTIMEO,
        &timeout, sizeof(timeout));
    (void)setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO,
        &timeout, sizeof(timeout));
#ifdef SO_NOSIGPIPE
    {
        int no_sigpipe = 1;
        (void)setsockopt(client_net.fd, SOL_SOCKET, SO_NOSIGPIPE,
            &no_sigpipe, sizeof(no_sigpipe));
        (void)setsockopt(sockets[1], SOL_SOCKET, SO_NOSIGPIPE,
            &no_sigpipe, sizeof(no_sigpipe));
    }
#endif

    server_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (server_ctx == NULL ||
            wolfSSL_CTX_use_certificate_file(server_ctx, TEST_CERT_FILE,
                WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_use_PrivateKey_file(server_ctx, TEST_KEY_FILE,
                WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        goto cleanup;
    }
    server.ssl = wolfSSL_new(server_ctx);
    if (server.ssl == NULL ||
            wolfSSL_set_fd(server.ssl, sockets[1]) != WOLFSSL_SUCCESS) {
        goto cleanup;
    }

    net.context = &client_net;
    net.connect = tls_test_connect;
    net.read = tls_test_read;
    net.write = tls_test_write;
    net.disconnect = tls_test_disconnect;
    if (MqttClient_Init(&client, &net, NULL, tx_buf, sizeof(tx_buf),
            rx_buf, sizeof(rx_buf), 3000) != MQTT_CODE_SUCCESS) {
        goto cleanup;
    }
    client_inited = 1;
    if (pthread_create(&thread, NULL, tls_test_server_run, &server) != 0) {
        goto cleanup;
    }
    thread_started = 1;

    connect_rc = MqttClient_NetConnect(&client, host, 8883, 3000, 1,
        tls_test_setup_client);
    if (connect_rc == MQTT_CODE_SUCCESS) {
        (void)MqttClient_NetDisconnect(&client);
    }
    if (connect_rc != expected) {
        PRINTF("  TLS host %s: expected %d, got %d, TLS error %d", host,
            expected, connect_rc, client.tls.lastError);
        goto cleanup;
    }
    rc = 0;

cleanup:
    g_tls_test_identity = NULL;
    g_tls_test_precreate = 0;
    (void)tls_test_disconnect(&client_net);
    if (thread_started) {
        (void)pthread_join(thread, NULL);
    }
    if (client_inited) {
        MqttClient_DeInit(&client);
    }
    if (server.ssl != NULL) {
        wolfSSL_free(server.ssl);
    }
    if (server_ctx != NULL) {
        wolfSSL_CTX_free(server_ctx);
    }
    if (sockets[1] >= 0) {
        (void)close(sockets[1]);
    }
    return rc;
}

int main(void)
{
    int rc;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return 1;
    }
    rc = tls_test_host("other.example.com", NULL, 0,
        MQTT_CODE_ERROR_TLS_CONNECT);
    if (rc == 0) {
        rc = tls_test_host("example.com", NULL, 0, MQTT_CODE_SUCCESS);
    }
    if (rc == 0) {
        rc = tls_test_host("broker", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    /* The fixture has a dNSName SAN for 0x7f.0.0.1. A DNS check would
     * accept it, but a resolver interprets it as a numeric IP address. */
    if (rc == 0) {
        rc = tls_test_host("0x7f.0.0.1", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    if (rc == 0) {
        rc = tls_test_host("127.1", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    if (rc == 0) {
        rc = tls_test_host("0177.0.0.1", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    if (rc == 0) {
        rc = tls_test_host("[::1]", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    if (rc == 0) {
        rc = tls_test_host("fe80::1%en0", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
#if defined(WOLFSSL_IP_ALT_NAME) && \
    defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX >= 0x05009001
    if (rc == 0) {
        rc = tls_test_host("127.0.0.1", NULL, 0, MQTT_CODE_SUCCESS);
    }
#else
    if (rc == 0) {
        rc = tls_test_host("127.0.0.1", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
#endif
    if (rc == 0) {
        rc = tls_test_host("127.0.0.2", NULL, 0,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    if (rc == 0) {
        rc = tls_test_host("other.example.com", NULL, 1,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    if (rc == 0) {
        rc = tls_test_host("example.com", NULL, 1, MQTT_CODE_SUCCESS);
    }
    if (rc == 0) {
        rc = tls_test_host("proxy.example.net", "example.com", 1,
            MQTT_CODE_SUCCESS);
    }
    if (rc == 0) {
        rc = tls_test_host("example.com", "other.example.com", 1,
            MQTT_CODE_ERROR_TLS_CONNECT);
    }
    (void)wolfSSL_Cleanup();
    PRINTF("tls_host_verification: %s", rc == 0 ? "PASS" : "FAIL");
    return rc;
}

#else
int main(void)
{
    return 77;
}
#endif
