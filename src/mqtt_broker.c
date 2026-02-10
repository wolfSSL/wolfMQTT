/* mqtt_broker.c
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_broker.h"
#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_packet.h"
#include "wolfmqtt/mqtt_socket.h"

#include <stdlib.h>
#include <string.h>

#ifdef WOLFMQTT_BROKER

/* -------------------------------------------------------------------------- */
/* Platform includes - only for default POSIX backend                          */
/* -------------------------------------------------------------------------- */
#ifndef WOLFMQTT_BROKER_CUSTOM_NET
    #include <errno.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <sys/select.h>
    #include <sys/socket.h>
    #include <time.h>
    #include <unistd.h>
#endif /* !WOLFMQTT_BROKER_CUSTOM_NET */

/* -------------------------------------------------------------------------- */
/* Default time abstraction                                                    */
/* -------------------------------------------------------------------------- */
#ifndef WOLFMQTT_BROKER_GET_TIME_S
    #define WOLFMQTT_BROKER_GET_TIME_S() \
        ((WOLFMQTT_BROKER_TIME_T)time(NULL))
#endif

/* -------------------------------------------------------------------------- */
/* Default sleep abstraction                                                   */
/* -------------------------------------------------------------------------- */
#ifndef BROKER_SLEEP_MS
    #ifdef USE_WINDOWS_API
        #define BROKER_SLEEP_MS(ms) Sleep(ms)
    #else
        #define BROKER_SLEEP_MS(ms) usleep((unsigned)(ms) * 1000)
    #endif
#endif

/* Logging macros with level filtering.
 * Define WOLFMQTT_BROKER_NO_LOG to strip all broker log calls at compile time. */
#ifdef WOLFMQTT_BROKER_NO_LOG
    #define WBLOG_ERR(b, ...)   do { (void)(b); } while(0)
    #define WBLOG_INFO(b, ...)  do { (void)(b); } while(0)
    #define WBLOG_DBG(b, ...)   do { (void)(b); } while(0)
#else
    #define WBLOG(b, level, ...) \
        do { if ((b)->log_level >= (level)) PRINTF(__VA_ARGS__); } while(0)
    #define WBLOG_ERR(b, ...)   WBLOG(b, BROKER_LOG_ERROR, __VA_ARGS__)
    #define WBLOG_INFO(b, ...)  WBLOG(b, BROKER_LOG_INFO, __VA_ARGS__)
    #define WBLOG_DBG(b, ...)   WBLOG(b, BROKER_LOG_DEBUG, __VA_ARGS__)
#endif

/* Buffer size accessors - unify static/dynamic code paths */
#ifdef WOLFMQTT_STATIC_MEMORY
    #define BROKER_CLIENT_TX_SZ(bc) BROKER_TX_BUF_SZ
    #define BROKER_CLIENT_RX_SZ(bc) BROKER_RX_BUF_SZ
#else
    #define BROKER_CLIENT_TX_SZ(bc) ((bc)->tx_buf_len)
    #define BROKER_CLIENT_RX_SZ(bc) ((bc)->rx_buf_len)
#endif

/* String validity check - static arrays vs dynamic pointers */
#ifdef WOLFMQTT_STATIC_MEMORY
    #define BROKER_STR_VALID(s) ((s)[0] != '\0')
#else
    #define BROKER_STR_VALID(s) ((s) != NULL)
#endif

/* No-op stubs when features are compiled out */
#ifndef WOLFMQTT_BROKER_RETAINED
    #define BrokerRetained_Store(b, t, p, l, e)         (0)
    #define BrokerRetained_Delete(b, t)                 do {} while(0)
    #define BrokerRetained_FreeAll(b)                   do {} while(0)
    #define BrokerRetained_DeliverToClient(b, c, f, q)  do {} while(0)
#endif
#ifndef WOLFMQTT_BROKER_WILL
    #define BrokerClient_ClearWill(bc)                  do {} while(0)
    #define BrokerClient_PublishWill(b, bc)             do {} while(0)
    #define BrokerPendingWill_Cancel(b, id)             do {} while(0)
    #define BrokerPendingWill_Process(b)                (0)
    #define BrokerPendingWill_FreeAll(b)                do {} while(0)
#endif

#ifdef WOLFMQTT_BROKER_AUTH
/* Constant-time string comparison to prevent timing attacks on auth.
 * Compares all bytes regardless of where differences occur.
 * Returns 0 if equal, non-zero if different. */
static int BrokerStrCompare(const char* a, const char* b)
{
    int result = 0;
    int len_a = (int)XSTRLEN(a);
    int len_b = (int)XSTRLEN(b);
    int len = (len_a < len_b) ? len_a : len_b;
    int i;
    for (i = 0; i < len; i++) {
        result |= (a[i] ^ b[i]);
    }
    result |= (len_a ^ len_b);
    return result;
}
#endif /* WOLFMQTT_BROKER_AUTH */

/* Store a string of known length into a BrokerClient field.
 * Static mode: copies into fixed-size buffer with truncation.
 * Dynamic mode: frees old value, allocates new buffer, copies. */
#ifdef WOLFMQTT_STATIC_MEMORY
static void BrokerStore_String(char* dst, int max_len,
    const char* src, word16 src_len)
{
    if (src_len >= (word16)max_len) {
        src_len = (word16)(max_len - 1);
    }
    XMEMCPY(dst, src, src_len);
    dst[src_len] = '\0';
}
#else
static void BrokerStore_String(char** dst_ptr,
    const char* src, word16 src_len)
{
    if (*dst_ptr != NULL) {
        WOLFMQTT_FREE(*dst_ptr);
        *dst_ptr = NULL;
    }
    *dst_ptr = (char*)WOLFMQTT_MALLOC(src_len + 1);
    if (*dst_ptr != NULL) {
        XMEMCPY(*dst_ptr, src, src_len);
        (*dst_ptr)[src_len] = '\0';
    }
}
#endif

/* Wrapper macro to unify static/dynamic calling convention */
#ifdef WOLFMQTT_STATIC_MEMORY
    #define BROKER_STORE_STR(dst, src, len, maxlen) \
        BrokerStore_String(dst, maxlen, src, len)
#else
    #define BROKER_STORE_STR(dst, src, len, maxlen) \
        BrokerStore_String(&(dst), src, len)
#endif

/* -------------------------------------------------------------------------- */
/* Default POSIX network backend                                               */
/* -------------------------------------------------------------------------- */
#ifndef WOLFMQTT_BROKER_CUSTOM_NET

static int BrokerPosix_SetNonBlocking(BROKER_SOCKET_T fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    return MQTT_CODE_SUCCESS;
}

static int BrokerPosix_Listen(void* ctx, BROKER_SOCKET_T* sock,
    word16 port, int backlog)
{
    struct sockaddr_in addr;
    int opt = 1;
    BROKER_SOCKET_T fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: socket failed (%d)", errno);
        return MQTT_CODE_ERROR_NETWORK;
    }

    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (BrokerPosix_SetNonBlocking(fd) != MQTT_CODE_SUCCESS) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: set nonblocking failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: bind failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (listen(fd, backlog) < 0) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: listen failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_NETWORK;
    }

    *sock = fd;
    return MQTT_CODE_SUCCESS;
}

static int BrokerPosix_Accept(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock)
{
    BROKER_SOCKET_T fd;
    (void)ctx;

    fd = accept(listen_sock, NULL, NULL);
    if (fd < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return MQTT_CODE_CONTINUE;
        }
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (BrokerPosix_SetNonBlocking(fd) != MQTT_CODE_SUCCESS) {
        close(fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    *client_sock = fd;
    return MQTT_CODE_SUCCESS;
}

static int BrokerPosix_Read(void* ctx, BROKER_SOCKET_T sock,
    byte* buf, int buf_len, int timeout_ms)
{
    fd_set rfds;
    struct timeval tv;
    int rc;

    if (buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(sock + 1, &rfds, NULL, NULL, &tv);
    if (rc == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (rc < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    rc = (int)recv(sock, buf, (size_t)buf_len, 0);
    if (rc <= 0) {
        if (rc < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return MQTT_CODE_CONTINUE;
        }
        WBLOG_ERR((MqttBroker*)ctx, "broker: recv error sock=%d rc=%d errno=%d",
            (int)sock, rc, errno);
        return MQTT_CODE_ERROR_NETWORK;
    }
    return rc;
}

static int BrokerPosix_Write(void* ctx, BROKER_SOCKET_T sock,
    const byte* buf, int buf_len, int timeout_ms)
{
    fd_set wfds;
    struct timeval tv;
    int rc;

    if (buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (rc == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (rc < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    rc = (int)send(sock, buf, (size_t)buf_len, 0);
    if (rc <= 0) {
        if (rc < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return MQTT_CODE_CONTINUE;
        }
        WBLOG_ERR((MqttBroker*)ctx, "broker: send error sock=%d rc=%d errno=%d",
            (int)sock, rc, errno);
        return MQTT_CODE_ERROR_NETWORK;
    }
    return rc;
}

static int BrokerPosix_Close(void* ctx, BROKER_SOCKET_T sock)
{
    (void)ctx;
    if (sock != BROKER_SOCKET_INVALID) {
        close(sock);
    }
    return MQTT_CODE_SUCCESS;
}

int MqttBrokerNet_Init(MqttBrokerNet* net)
{
    if (net == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    XMEMSET(net, 0, sizeof(*net));
    net->listen = BrokerPosix_Listen;
    net->accept = BrokerPosix_Accept;
    net->read   = BrokerPosix_Read;
    net->write  = BrokerPosix_Write;
    net->close  = BrokerPosix_Close;
    net->ctx    = NULL;
    return MQTT_CODE_SUCCESS;
}

#ifdef ENABLE_MQTT_TLS
static int BrokerTls_Init(MqttBroker* broker)
{
    WOLFSSL_CTX* ctx = NULL;
    int rc;

    rc = wolfSSL_Init();
    if (rc != WOLFSSL_SUCCESS) {
        WBLOG_ERR(broker, "broker: wolfSSL_Init failed %d", rc);
        rc = MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Select TLS method based on version preference */
    if (rc == WOLFSSL_SUCCESS) {
        if (broker->tls_version == 12) {
            ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
        }
        else if (broker->tls_version == 13) {
            ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
        }
        else {
            ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
        }
        if (ctx == NULL) {
            WBLOG_ERR(broker, "broker: wolfSSL_CTX_new failed");
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }

    /* Load server certificate */
    if (rc == WOLFSSL_SUCCESS) {
        if (broker->tls_cert == NULL) {
            WBLOG_ERR(broker, "broker: TLS cert not set (-c)");
            rc = MQTT_CODE_ERROR_BAD_ARG;
        }
    }
    if (rc == WOLFSSL_SUCCESS) {
        rc = wolfSSL_CTX_use_certificate_file(ctx, broker->tls_cert,
            WOLFSSL_FILETYPE_PEM);
        if (rc != WOLFSSL_SUCCESS) {
            WBLOG_ERR(broker, "broker: load cert failed %d (%s)", rc, broker->tls_cert);
            rc = MQTT_CODE_ERROR_BAD_ARG;
        }
    }

    /* Load server private key */
    if (rc == WOLFSSL_SUCCESS) {
        if (broker->tls_key == NULL) {
            WBLOG_ERR(broker, "broker: TLS key not set (-K)");
            rc = MQTT_CODE_ERROR_BAD_ARG;
        }
    }
    if (rc == WOLFSSL_SUCCESS) {
        rc = wolfSSL_CTX_use_PrivateKey_file(ctx, broker->tls_key,
            WOLFSSL_FILETYPE_PEM);
        if (rc != WOLFSSL_SUCCESS) {
            WBLOG_ERR(broker, "broker: load key failed %d (%s)", rc, broker->tls_key);
            rc = MQTT_CODE_ERROR_BAD_ARG;
        }
    }

    /* Set wolfSSL IO callbacks */
    if (rc == WOLFSSL_SUCCESS) {
        wolfSSL_CTX_SetIORecv(ctx, MqttSocket_TlsSocketReceive);
        wolfSSL_CTX_SetIOSend(ctx, MqttSocket_TlsSocketSend);
    }

    /* Mutual TLS: load CA and require client certificate */
    if (rc == WOLFSSL_SUCCESS && broker->tls_ca != NULL) {
        rc = wolfSSL_CTX_load_verify_locations(ctx, broker->tls_ca, NULL);
        if (rc != WOLFSSL_SUCCESS) {
            WBLOG_ERR(broker, "broker: load CA failed %d (%s)", rc, broker->tls_ca);
            rc = MQTT_CODE_ERROR_BAD_ARG;
        }
        else {
            wolfSSL_CTX_set_verify(ctx,
                WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                NULL);
            WBLOG_INFO(broker, "broker: mutual TLS enabled (CA=%s)", broker->tls_ca);
        }
    }

    if (rc == WOLFSSL_SUCCESS) {
        broker->tls_ctx = ctx;
        rc = MQTT_CODE_SUCCESS;
    }
    else {
        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
        }
        wolfSSL_Cleanup();
    }
    return rc;
}

static void BrokerTls_Free(MqttBroker* broker)
{
    if (broker->tls_ctx != NULL) {
        wolfSSL_CTX_free(broker->tls_ctx);
        broker->tls_ctx = NULL;
    }
    wolfSSL_Cleanup();
}
#endif /* ENABLE_MQTT_TLS */

#endif /* !WOLFMQTT_BROKER_CUSTOM_NET */

/* -------------------------------------------------------------------------- */
/* Per-client MqttNet callbacks (route through MqttBrokerNet)                  */
/* -------------------------------------------------------------------------- */
static int BrokerNetConnect(void* context, const char* host, word16 port,
    int timeout_ms)
{
    /* Server side: connection already established via accept() */
    (void)context;
    (void)host;
    (void)port;
    (void)timeout_ms;
    return MQTT_CODE_SUCCESS;
}

static int BrokerNetRead(void* context, byte* buf, int buf_len,
    int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    if (bc == NULL || bc->broker == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    return bc->broker->net.read(bc->broker->net.ctx, bc->sock,
        buf, buf_len, timeout_ms);
}

static int BrokerNetWrite(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    if (bc == NULL || bc->broker == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    return bc->broker->net.write(bc->broker->net.ctx, bc->sock,
        buf, buf_len, timeout_ms);
}

static int BrokerNetDisconnect(void* context)
{
    BrokerClient* bc = (BrokerClient*)context;
    if (bc != NULL && bc->broker != NULL &&
        bc->sock != BROKER_SOCKET_INVALID) {
        WBLOG_INFO(bc->broker, "broker: disconnect sock=%d", (int)bc->sock);
        bc->broker->net.close(bc->broker->net.ctx, bc->sock);
        bc->sock = BROKER_SOCKET_INVALID;
    }
    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Client management                                                           */
/* -------------------------------------------------------------------------- */
static void BrokerClient_Free(BrokerClient* bc)
{
    if (bc == NULL) {
        return;
    }
    (void)BrokerNetDisconnect(bc);
#ifdef ENABLE_MQTT_TLS
    if (bc->client.tls.ssl) {
        /* Only send close_notify if handshake completed successfully */
        if (bc->tls_handshake_done) {
            wolfSSL_shutdown(bc->client.tls.ssl);
        }
        wolfSSL_free(bc->client.tls.ssl);
        bc->client.tls.ssl = NULL;
    }
#endif
    MqttClient_DeInit(&bc->client);
#ifdef WOLFMQTT_STATIC_MEMORY
    XMEMSET(bc, 0, sizeof(*bc));
    /* in_use is now 0 after memset */
#else
    if (bc->client_id) {
        WOLFMQTT_FREE(bc->client_id);
    }
#ifdef WOLFMQTT_BROKER_AUTH
    if (bc->username) {
        WOLFMQTT_FREE(bc->username);
    }
    if (bc->password) {
        WOLFMQTT_FREE(bc->password);
    }
#endif
#ifdef WOLFMQTT_BROKER_WILL
    if (bc->will_topic) {
        WOLFMQTT_FREE(bc->will_topic);
    }
    if (bc->will_payload) {
        WOLFMQTT_FREE(bc->will_payload);
    }
#endif
    if (bc->tx_buf) {
        WOLFMQTT_FREE(bc->tx_buf);
    }
    if (bc->rx_buf) {
        WOLFMQTT_FREE(bc->rx_buf);
    }
    WOLFMQTT_FREE(bc);
#endif
}

static BrokerClient* BrokerClient_Add(MqttBroker* broker,
    BROKER_SOCKET_T sock)
{
    BrokerClient* bc = NULL;
    int rc = MQTT_CODE_SUCCESS;

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
            if (!broker->clients[i].in_use) {
                bc = &broker->clients[i];
                break;
            }
        }
        if (bc == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(bc, 0, sizeof(*bc));
            bc->in_use = 1;
        }
    }
#else
    bc = (BrokerClient*)WOLFMQTT_MALLOC(sizeof(BrokerClient));
    if (bc == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(bc, 0, sizeof(*bc));
        bc->tx_buf_len = BROKER_TX_BUF_SZ;
        bc->rx_buf_len = BROKER_RX_BUF_SZ;
        bc->tx_buf = (byte*)WOLFMQTT_MALLOC(bc->tx_buf_len);
        bc->rx_buf = (byte*)WOLFMQTT_MALLOC(bc->rx_buf_len);
        if (bc->tx_buf == NULL || bc->rx_buf == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        bc->sock = sock;
        bc->broker = broker;
        bc->protocol_level = 0;
        bc->keep_alive_sec = 0;
        bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();

        bc->net.context = bc;
        bc->net.connect = BrokerNetConnect;
        bc->net.read = BrokerNetRead;
        bc->net.write = BrokerNetWrite;
        bc->net.disconnect = BrokerNetDisconnect;

        rc = MqttClient_Init(&bc->client, &bc->net, NULL,
                bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
                bc->rx_buf, BROKER_CLIENT_RX_SZ(bc), BROKER_TIMEOUT_MS);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: client init failed rc=%d", rc);
        }
    }

#ifdef ENABLE_MQTT_TLS
    if (rc == MQTT_CODE_SUCCESS) {
        if (broker->use_tls && broker->tls_ctx) {
            bc->client.tls.ssl = wolfSSL_new(broker->tls_ctx);
            if (bc->client.tls.ssl == NULL) {
                WBLOG_ERR(broker, "broker: wolfSSL_new failed sock=%d", (int)sock);
                rc = MQTT_CODE_ERROR_MEMORY;
            }
            else {
                wolfSSL_SetIOReadCtx(bc->client.tls.ssl, &bc->client);
                wolfSSL_SetIOWriteCtx(bc->client.tls.ssl, &bc->client);
                MqttClient_Flags(&bc->client, 0, MQTT_CLIENT_FLAG_IS_TLS);
                bc->tls_handshake_done = 0;
            }
        }
        else {
            bc->tls_handshake_done = 1;
        }
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
#ifndef WOLFMQTT_STATIC_MEMORY
        /* Prepend to linked list */
        bc->next = broker->clients;
        broker->clients = bc;
#endif
    }
    else if (bc != NULL) {
        BrokerClient_Free(bc);
        bc = NULL;
    }

    return bc;
}

static void BrokerClient_Remove(MqttBroker* broker, BrokerClient* bc)
{
    if (broker == NULL || bc == NULL) {
        return;
    }

#ifndef WOLFMQTT_STATIC_MEMORY
    {
        BrokerClient* cur = broker->clients;
        BrokerClient* prev = NULL;
        while (cur) {
            if (cur == bc) {
                if (prev) {
                    prev->next = cur->next;
                }
                else {
                    broker->clients = cur->next;
                }
                break;
            }
            prev = cur;
            cur = cur->next;
        }
    }
#endif
    BrokerClient_Free(bc);
}

/* -------------------------------------------------------------------------- */
/* Subscription management                                                     */
/* -------------------------------------------------------------------------- */
static void BrokerSubs_RemoveClient(MqttBroker* broker, BrokerClient* bc)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        if (broker->subs[i].in_use && broker->subs[i].client == bc) {
            XMEMSET(&broker->subs[i], 0, sizeof(BrokerSub));
        }
    }
#else
    BrokerSub* cur = broker->subs;
    BrokerSub* prev = NULL;

    while (cur) {
        BrokerSub* next = cur->next;
        if (cur->client == bc) {
            if (prev) {
                prev->next = next;
            }
            else {
                broker->subs = next;
            }
            if (cur->filter) {
                WOLFMQTT_FREE(cur->filter);
            }
            WOLFMQTT_FREE(cur);
        }
        else {
            prev = cur;
        }
        cur = next;
    }
#endif
}

static int BrokerSubs_Add(MqttBroker* broker, BrokerClient* bc,
    const char* filter, word16 filter_len, MqttQoS qos)
{
    BrokerSub* sub = NULL;
    int rc = MQTT_CODE_SUCCESS;

    /* Check for existing subscription to same filter by same client */
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            if (broker->subs[i].in_use && broker->subs[i].client == bc &&
                (word16)XSTRLEN(broker->subs[i].filter) == filter_len &&
                XMEMCMP(broker->subs[i].filter, filter, filter_len) == 0) {
                broker->subs[i].qos = qos;
                WBLOG_INFO(broker, "broker: sub update sock=%d filter=%s qos=%d",
                    (int)bc->sock, broker->subs[i].filter, qos);
                return MQTT_CODE_SUCCESS;
            }
        }
    }
#else
    {
        BrokerSub* cur = broker->subs;
        while (cur) {
            if (cur->client == bc && cur->filter != NULL &&
                (word16)XSTRLEN(cur->filter) == filter_len &&
                XMEMCMP(cur->filter, filter, filter_len) == 0) {
                cur->qos = qos;
                WBLOG_INFO(broker, "broker: sub update sock=%d filter=%s qos=%d",
                    (int)bc->sock, cur->filter, qos);
                return MQTT_CODE_SUCCESS;
            }
            cur = cur->next;
        }
    }
#endif

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            if (!broker->subs[i].in_use) {
                sub = &broker->subs[i];
                break;
            }
        }
        if (sub == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(sub, 0, sizeof(*sub));
            sub->in_use = 1;
            if (filter_len >= BROKER_MAX_FILTER_LEN) {
                filter_len = BROKER_MAX_FILTER_LEN - 1;
            }
            XMEMCPY(sub->filter, filter, filter_len);
            sub->filter[filter_len] = '\0';
        }
    }
#else
    sub = (BrokerSub*)WOLFMQTT_MALLOC(sizeof(BrokerSub));
    if (sub == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(sub, 0, sizeof(*sub));
        sub->filter = (char*)WOLFMQTT_MALLOC(filter_len + 1);
        if (sub->filter == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMCPY(sub->filter, filter, filter_len);
        sub->filter[filter_len] = '\0';
        sub->next = broker->subs;
        broker->subs = sub;
    }
    else if (sub != NULL) {
        WOLFMQTT_FREE(sub);
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        sub->client = bc;
        sub->qos = qos;
        WBLOG_INFO(broker, "broker: sub add sock=%d filter=%s qos=%d",
            (int)bc->sock, sub->filter, qos);
    }
    return rc;
}

static void BrokerSubs_Remove(MqttBroker* broker, BrokerClient* bc,
    const char* filter, word16 filter_len)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        BrokerSub* s = &broker->subs[i];
        if (s->in_use && s->client == bc &&
            s->filter[0] != '\0' &&
            (word16)XSTRLEN(s->filter) == filter_len &&
            XMEMCMP(s->filter, filter, filter_len) == 0) {
            WBLOG_INFO(broker, "broker: sub remove sock=%d filter=%s",
                (int)bc->sock, s->filter);
            XMEMSET(s, 0, sizeof(BrokerSub));
            return;
        }
    }
#else
    BrokerSub* cur = broker->subs;
    BrokerSub* prev = NULL;

    while (cur) {
        BrokerSub* next = cur->next;
        if (cur->client == bc &&
            cur->filter != NULL &&
            (word16)XSTRLEN(cur->filter) == filter_len &&
            XMEMCMP(cur->filter, filter, filter_len) == 0) {
            if (prev) {
                prev->next = next;
            }
            else {
                broker->subs = next;
            }
            WBLOG_INFO(broker, "broker: sub remove sock=%d filter=%s",
                (int)bc->sock, cur->filter);
            WOLFMQTT_FREE(cur->filter);
            WOLFMQTT_FREE(cur);
            return;
        }
        prev = cur;
        cur = next;
    }
#endif
}

/* -------------------------------------------------------------------------- */
/* Packet ID generation                                                        */
/* -------------------------------------------------------------------------- */
static word16 BrokerNextPacketId(MqttBroker* broker)
{
    word16 id = broker->next_packet_id;
    broker->next_packet_id++;
    if (broker->next_packet_id == 0) {
        broker->next_packet_id = 1; /* wrap: skip 0 */
    }
    return id;
}

/* -------------------------------------------------------------------------- */
/* Client lookup by ID                                                         */
/* -------------------------------------------------------------------------- */
static BrokerClient* BrokerClient_FindByClientId(MqttBroker* broker,
    const char* client_id, BrokerClient* exclude)
{
    if (broker == NULL || client_id == NULL || client_id[0] == '\0') {
        return NULL;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
            BrokerClient* bc = &broker->clients[i];
            if (!bc->in_use) continue;
            if (bc != exclude && BROKER_STR_VALID(bc->client_id) &&
                XSTRCMP(bc->client_id, client_id) == 0) {
                return bc;
            }
        }
    }
#else
    {
        BrokerClient* bc = broker->clients;
        while (bc) {
            if (bc != exclude && BROKER_STR_VALID(bc->client_id) &&
                XSTRCMP(bc->client_id, client_id) == 0) {
                return bc;
            }
            bc = bc->next;
        }
    }
#endif
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Subscription helpers for clean session                                      */
/* -------------------------------------------------------------------------- */
static void BrokerSubs_RemoveByClientId(MqttBroker* broker,
    const char* client_id)
{
    if (broker == NULL || client_id == NULL || client_id[0] == '\0') {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            BrokerSub* s = &broker->subs[i];
            if (s->in_use && s->client != NULL &&
                s->client->client_id[0] != '\0' &&
                XSTRCMP(s->client->client_id, client_id) == 0) {
                XMEMSET(s, 0, sizeof(BrokerSub));
            }
        }
    }
#else
    {
        BrokerSub* cur = broker->subs;
        BrokerSub* prev = NULL;
        while (cur) {
            BrokerSub* next = cur->next;
            if (cur->client != NULL && cur->client->client_id != NULL &&
                XSTRCMP(cur->client->client_id, client_id) == 0) {
                if (prev) {
                    prev->next = next;
                }
                else {
                    broker->subs = next;
                }
                if (cur->filter) {
                    WOLFMQTT_FREE(cur->filter);
                }
                WOLFMQTT_FREE(cur);
            }
            else {
                prev = cur;
            }
            cur = next;
        }
    }
#endif
}

static void BrokerSubs_ReassociateClient(MqttBroker* broker,
    const char* client_id, BrokerClient* new_bc)
{
    if (broker == NULL || client_id == NULL || client_id[0] == '\0' ||
        new_bc == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            BrokerSub* s = &broker->subs[i];
            if (!s->in_use) continue;
            if (s->client != NULL && BROKER_STR_VALID(s->client->client_id) &&
                XSTRCMP(s->client->client_id, client_id) == 0) {
                s->client = new_bc;
            }
        }
    }
#else
    {
        BrokerSub* s = broker->subs;
        while (s) {
            if (s->client != NULL && BROKER_STR_VALID(s->client->client_id) &&
                XSTRCMP(s->client->client_id, client_id) == 0) {
                s->client = new_bc;
            }
            s = s->next;
        }
    }
#endif
}

/* -------------------------------------------------------------------------- */
/* Retained message management                                                 */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_RETAINED
static int BrokerRetained_Store(MqttBroker* broker, const char* topic,
    const byte* payload, word16 payload_len, word32 expiry_sec)
{
    BrokerRetainedMsg* msg = NULL;
    int rc = MQTT_CODE_SUCCESS;

    if (broker == NULL || topic == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        /* Look for existing retained msg on this topic */
        for (i = 0; i < BROKER_MAX_RETAINED; i++) {
            if (broker->retained[i].in_use &&
                XSTRCMP(broker->retained[i].topic, topic) == 0) {
                msg = &broker->retained[i];
                break;
            }
        }
        /* If not found, find a free slot */
        if (msg == NULL) {
            for (i = 0; i < BROKER_MAX_RETAINED; i++) {
                if (!broker->retained[i].in_use) {
                    msg = &broker->retained[i];
                    break;
                }
            }
        }
        if (msg == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            int tlen = (int)XSTRLEN(topic);
            XMEMSET(msg, 0, sizeof(*msg));
            msg->in_use = 1;
            if (tlen >= BROKER_MAX_TOPIC_LEN) {
                tlen = BROKER_MAX_TOPIC_LEN - 1;
            }
            XMEMCPY(msg->topic, topic, (size_t)tlen);
            msg->topic[tlen] = '\0';
            if (payload_len > 0 && payload != NULL) {
                if (payload_len > BROKER_MAX_PAYLOAD_LEN) {
                    payload_len = BROKER_MAX_PAYLOAD_LEN;
                }
                XMEMCPY(msg->payload, payload, payload_len);
            }
            msg->payload_len = payload_len;
        }
    }
#else
    {
        byte is_new = 0;
        BrokerRetainedMsg* cur = broker->retained;
        while (cur) {
            if (cur->topic != NULL && XSTRCMP(cur->topic, topic) == 0) {
                msg = cur;
                break;
            }
            cur = cur->next;
        }
        if (msg != NULL) {
            /* Replace existing: free old payload */
            if (msg->payload) {
                WOLFMQTT_FREE(msg->payload);
                msg->payload = NULL;
            }
            msg->payload_len = 0;
        }
        else {
            /* Allocate new */
            int tlen = (int)XSTRLEN(topic);
            msg = (BrokerRetainedMsg*)WOLFMQTT_MALLOC(
                sizeof(BrokerRetainedMsg));
            if (msg == NULL) {
                rc = MQTT_CODE_ERROR_MEMORY;
            }
            if (rc == MQTT_CODE_SUCCESS) {
                XMEMSET(msg, 0, sizeof(*msg));
                msg->topic = (char*)WOLFMQTT_MALLOC((size_t)tlen + 1);
                if (msg->topic == NULL) {
                    rc = MQTT_CODE_ERROR_MEMORY;
                }
            }
            if (rc == MQTT_CODE_SUCCESS) {
                XMEMCPY(msg->topic, topic, (size_t)tlen);
                msg->topic[tlen] = '\0';
                is_new = 1;
            }
        }
        if (rc == MQTT_CODE_SUCCESS && payload_len > 0 && payload != NULL) {
            msg->payload = (byte*)WOLFMQTT_MALLOC(payload_len);
            if (msg->payload == NULL) {
                rc = MQTT_CODE_ERROR_MEMORY;
            }
            else {
                XMEMCPY(msg->payload, payload, payload_len);
            }
        }
        if (rc == MQTT_CODE_SUCCESS) {
            msg->payload_len = payload_len;
            if (is_new) {
                msg->next = broker->retained;
                broker->retained = msg;
            }
        }
        else if (is_new && msg != NULL) {
            if (msg->topic) {
                WOLFMQTT_FREE(msg->topic);
            }
            WOLFMQTT_FREE(msg);
        }
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        msg->store_time = WOLFMQTT_BROKER_GET_TIME_S();
        msg->expiry_sec = expiry_sec;
        WBLOG_DBG(broker, "broker: retained store topic=%s len=%u expiry=%u", topic,
            (unsigned)payload_len, (unsigned)expiry_sec);
    }
    return rc;
}

static void BrokerRetained_Delete(MqttBroker* broker, const char* topic)
{
    if (broker == NULL || topic == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_RETAINED; i++) {
            if (broker->retained[i].in_use &&
                XSTRCMP(broker->retained[i].topic, topic) == 0) {
                WBLOG_DBG(broker, "broker: retained delete topic=%s", topic);
                XMEMSET(&broker->retained[i], 0, sizeof(BrokerRetainedMsg));
                return;
            }
        }
    }
#else
    {
        BrokerRetainedMsg* cur = broker->retained;
        BrokerRetainedMsg* prev = NULL;
        while (cur) {
            BrokerRetainedMsg* next = cur->next;
            if (cur->topic != NULL && XSTRCMP(cur->topic, topic) == 0) {
                WBLOG_DBG(broker, "broker: retained delete topic=%s", topic);
                if (prev) {
                    prev->next = next;
                }
                else {
                    broker->retained = next;
                }
                WOLFMQTT_FREE(cur->topic);
                if (cur->payload) {
                    WOLFMQTT_FREE(cur->payload);
                }
                WOLFMQTT_FREE(cur);
                return;
            }
            prev = cur;
            cur = next;
        }
    }
#endif
}

static void BrokerRetained_FreeAll(MqttBroker* broker)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_RETAINED; i++) {
            XMEMSET(&broker->retained[i], 0, sizeof(BrokerRetainedMsg));
        }
    }
#else
    {
        BrokerRetainedMsg* cur = broker->retained;
        while (cur) {
            BrokerRetainedMsg* next = cur->next;
            if (cur->topic) {
                WOLFMQTT_FREE(cur->topic);
            }
            if (cur->payload) {
                WOLFMQTT_FREE(cur->payload);
            }
            WOLFMQTT_FREE(cur);
            cur = next;
        }
        broker->retained = NULL;
    }
#endif
}
#endif /* WOLFMQTT_BROKER_RETAINED */

/* Forward declaration - used by retained delivery, will publish, and PUBLISH handler */
static int BrokerTopicMatch(const char* filter, const char* topic);

/* -------------------------------------------------------------------------- */
/* LWT (Last Will and Testament) helpers                                       */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_WILL
static void BrokerClient_ClearWill(BrokerClient* bc)
{
    if (bc == NULL) {
        return;
    }
    bc->has_will = 0;
    bc->will_qos = MQTT_QOS_0;
    bc->will_retain = 0;
    bc->will_delay_sec = 0;
    bc->will_payload_len = 0;
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->will_topic[0] = '\0';
#else
    if (bc->will_topic) {
        WOLFMQTT_FREE(bc->will_topic);
        bc->will_topic = NULL;
    }
    if (bc->will_payload) {
        WOLFMQTT_FREE(bc->will_payload);
        bc->will_payload = NULL;
    }
#endif
}

/* -------------------------------------------------------------------------- */
/* Pending will management (v5 Will Delay Interval)                            */
/* -------------------------------------------------------------------------- */

/* Add a pending will to be published after delay expires */
static int BrokerPendingWill_Add(MqttBroker* broker, BrokerClient* bc)
{
    BrokerPendingWill* pw = NULL;
    WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();
    int rc = MQTT_CODE_SUCCESS;

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_PENDING_WILLS; i++) {
            if (!broker->pending_wills[i].in_use) {
                pw = &broker->pending_wills[i];
                break;
            }
        }
        if (pw == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(pw, 0, sizeof(*pw));
            pw->in_use = 1;
            {
                int len = (int)XSTRLEN(bc->client_id);
                if (len >= BROKER_MAX_CLIENT_ID_LEN) {
                    len = BROKER_MAX_CLIENT_ID_LEN - 1;
                }
                XMEMCPY(pw->client_id, bc->client_id, len);
                pw->client_id[len] = '\0';
            }
            {
                int len = (int)XSTRLEN(bc->will_topic);
                if (len >= BROKER_MAX_TOPIC_LEN) {
                    len = BROKER_MAX_TOPIC_LEN - 1;
                }
                XMEMCPY(pw->topic, bc->will_topic, len);
                pw->topic[len] = '\0';
            }
            if (bc->will_payload_len > 0) {
                word16 len = bc->will_payload_len;
                if (len > BROKER_MAX_WILL_PAYLOAD_LEN) {
                    len = BROKER_MAX_WILL_PAYLOAD_LEN;
                }
                XMEMCPY(pw->payload, bc->will_payload, len);
                pw->payload_len = len;
            }
        }
    }
#else
    pw = (BrokerPendingWill*)WOLFMQTT_MALLOC(sizeof(BrokerPendingWill));
    if (pw == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        int id_len = (int)XSTRLEN(bc->client_id);
        int t_len = (int)XSTRLEN(bc->will_topic);
        XMEMSET(pw, 0, sizeof(*pw));
        pw->client_id = (char*)WOLFMQTT_MALLOC((size_t)id_len + 1);
        if (pw->client_id != NULL) {
            XMEMCPY(pw->client_id, bc->client_id, (size_t)id_len + 1);
        }
        else {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            pw->topic = (char*)WOLFMQTT_MALLOC((size_t)t_len + 1);
            if (pw->topic != NULL) {
                XMEMCPY(pw->topic, bc->will_topic, (size_t)t_len + 1);
            }
            else {
                rc = MQTT_CODE_ERROR_MEMORY;
            }
        }
        if (rc == MQTT_CODE_SUCCESS && bc->will_payload_len > 0) {
            pw->payload = (byte*)WOLFMQTT_MALLOC(bc->will_payload_len);
            if (pw->payload != NULL) {
                XMEMCPY(pw->payload, bc->will_payload, bc->will_payload_len);
                pw->payload_len = bc->will_payload_len;
            }
            else {
                rc = MQTT_CODE_ERROR_MEMORY;
            }
        }
    }
    if (rc == MQTT_CODE_SUCCESS) {
        pw->next = broker->pending_wills;
        broker->pending_wills = pw;
    }
    else if (pw != NULL) {
        if (pw->topic) {
            WOLFMQTT_FREE(pw->topic);
        }
        if (pw->client_id) {
            WOLFMQTT_FREE(pw->client_id);
        }
        WOLFMQTT_FREE(pw);
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        pw->qos = bc->will_qos;
        pw->retain = bc->will_retain;
        pw->publish_time = now + (WOLFMQTT_BROKER_TIME_T)bc->will_delay_sec;
        WBLOG_DBG(broker, "broker: will deferred sock=%d client_id=%s delay=%u",
            (int)bc->sock, bc->client_id, (unsigned)bc->will_delay_sec);
    }
    return rc;
}

/* Cancel a pending will for the given client_id (client reconnected) */
static void BrokerPendingWill_Cancel(MqttBroker* broker,
    const char* client_id)
{
    if (broker == NULL || client_id == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_PENDING_WILLS; i++) {
            if (broker->pending_wills[i].in_use &&
                XSTRCMP(broker->pending_wills[i].client_id, client_id) == 0) {
                WBLOG_DBG(broker, "broker: will cancelled client_id=%s", client_id);
                XMEMSET(&broker->pending_wills[i], 0,
                    sizeof(BrokerPendingWill));
                return;
            }
        }
    }
#else
    {
        BrokerPendingWill* pw = broker->pending_wills;
        BrokerPendingWill* prev = NULL;
        while (pw) {
            BrokerPendingWill* next = pw->next;
            if (pw->client_id != NULL &&
                XSTRCMP(pw->client_id, client_id) == 0) {
                WBLOG_DBG(broker, "broker: will cancelled client_id=%s", client_id);
                if (prev) {
                    prev->next = next;
                }
                else {
                    broker->pending_wills = next;
                }
                WOLFMQTT_FREE(pw->client_id);
                if (pw->topic) WOLFMQTT_FREE(pw->topic);
                if (pw->payload) WOLFMQTT_FREE(pw->payload);
                WOLFMQTT_FREE(pw);
                return;
            }
            prev = pw;
            pw = next;
        }
    }
#endif
}

static void BrokerPendingWill_FreeAll(MqttBroker* broker)
{
    if (broker == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    XMEMSET(broker->pending_wills, 0, sizeof(broker->pending_wills));
#else
    {
        BrokerPendingWill* pw = broker->pending_wills;
        while (pw) {
            BrokerPendingWill* next = pw->next;
            if (pw->client_id) WOLFMQTT_FREE(pw->client_id);
            if (pw->topic) WOLFMQTT_FREE(pw->topic);
            if (pw->payload) WOLFMQTT_FREE(pw->payload);
            WOLFMQTT_FREE(pw);
            pw = next;
        }
        broker->pending_wills = NULL;
    }
#endif
}

#ifdef WOLFMQTT_BROKER_WILL
static void BrokerClient_PublishWillImmediate(MqttBroker* broker,
    const char* topic, const byte* payload, word16 payload_len,
    MqttQoS qos, byte retain);
#endif

/* Process pending wills - publish any that have expired their delay */
static int BrokerPendingWill_Process(MqttBroker* broker)
{
    int activity = 0;
    WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();

    if (broker == NULL) {
        return 0;
    }

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_PENDING_WILLS; i++) {
            BrokerPendingWill* pw = &broker->pending_wills[i];
            if (!pw->in_use) {
                continue;
            }
            if (now >= pw->publish_time) {
                WBLOG_DBG(broker, "broker: LWT deferred publish client_id=%s topic=%s "
                    "len=%u", pw->client_id, pw->topic,
                    (unsigned)pw->payload_len);
                BrokerClient_PublishWillImmediate(broker, pw->topic,
                    pw->payload, pw->payload_len, pw->qos, pw->retain);
                XMEMSET(pw, 0, sizeof(BrokerPendingWill));
                activity = 1;
            }
        }
    }
#else
    {
        BrokerPendingWill* pw = broker->pending_wills;
        BrokerPendingWill* prev = NULL;
        while (pw) {
            BrokerPendingWill* next = pw->next;
            if (now >= pw->publish_time) {
                WBLOG_DBG(broker, "broker: LWT deferred publish client_id=%s topic=%s "
                    "len=%u", pw->client_id, pw->topic,
                    (unsigned)pw->payload_len);
                BrokerClient_PublishWillImmediate(broker, pw->topic,
                    pw->payload, pw->payload_len, pw->qos, pw->retain);
                if (prev) {
                    prev->next = next;
                }
                else {
                    broker->pending_wills = next;
                }
                if (pw->client_id) WOLFMQTT_FREE(pw->client_id);
                if (pw->topic) WOLFMQTT_FREE(pw->topic);
                if (pw->payload) WOLFMQTT_FREE(pw->payload);
                WOLFMQTT_FREE(pw);
                activity = 1;
            }
            else {
                prev = pw;
            }
            pw = next;
        }
    }
#endif

    return activity;
}
#endif /* WOLFMQTT_BROKER_WILL */

#ifdef WOLFMQTT_BROKER_RETAINED
static void BrokerRetained_DeliverToClient(MqttBroker* broker,
    BrokerClient* bc, const char* filter, MqttQoS sub_qos)
{
    WOLFMQTT_BROKER_TIME_T now;
    (void)sub_qos; /* retained always delivered at QoS 0 in this broker */

    if (broker == NULL || bc == NULL || filter == NULL) {
        return;
    }
    now = WOLFMQTT_BROKER_GET_TIME_S();

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_RETAINED; i++) {
            BrokerRetainedMsg* rm = &broker->retained[i];
            if (!rm->in_use || rm->topic[0] == '\0') {
                continue;
            }
            /* Skip expired messages */
            if (rm->expiry_sec > 0 &&
                (now - rm->store_time) >= rm->expiry_sec) {
                WBLOG_DBG(broker, "broker: retained expired topic=%s", rm->topic);
                XMEMSET(rm, 0, sizeof(BrokerRetainedMsg));
                continue;
            }
            if (BrokerTopicMatch(filter, rm->topic)) {
                MqttPublish out_pub;
                int enc_rc;
                XMEMSET(&out_pub, 0, sizeof(out_pub));
                out_pub.topic_name = rm->topic;
                out_pub.qos = MQTT_QOS_0;
                out_pub.retain = 1;
                out_pub.duplicate = 0;
                out_pub.buffer = (rm->payload_len > 0) ? rm->payload : NULL;
                out_pub.total_len = rm->payload_len;
#ifdef WOLFMQTT_V5
                out_pub.protocol_level = bc->protocol_level;
#endif
                enc_rc = MqttEncode_Publish(bc->tx_buf,
                    BROKER_CLIENT_TX_SZ(bc), &out_pub, 0);
                if (enc_rc > 0) {
                    WBLOG_DBG(broker, "broker: retained deliver sock=%d topic=%s "
                        "len=%u", (int)bc->sock, rm->topic,
                        (unsigned)rm->payload_len);
                    (void)MqttPacket_Write(&bc->client, bc->tx_buf, enc_rc);
                }
            }
        }
    }
#else
    {
        BrokerRetainedMsg* rm = broker->retained;
        BrokerRetainedMsg* rm_prev = NULL;
        while (rm) {
            BrokerRetainedMsg* rm_next = rm->next;
            /* Skip and remove expired messages */
            if (rm->expiry_sec > 0 &&
                (now - rm->store_time) >= rm->expiry_sec) {
                WBLOG_DBG(broker, "broker: retained expired topic=%s", rm->topic);
                if (rm_prev) {
                    rm_prev->next = rm_next;
                }
                else {
                    broker->retained = rm_next;
                }
                if (rm->topic) WOLFMQTT_FREE(rm->topic);
                if (rm->payload) WOLFMQTT_FREE(rm->payload);
                WOLFMQTT_FREE(rm);
                rm = rm_next;
                continue;
            }
            if (rm->topic != NULL && BrokerTopicMatch(filter, rm->topic)) {
                MqttPublish out_pub;
                int enc_rc;
                XMEMSET(&out_pub, 0, sizeof(out_pub));
                out_pub.topic_name = rm->topic;
                out_pub.qos = MQTT_QOS_0;
                out_pub.retain = 1;
                out_pub.duplicate = 0;
                out_pub.buffer = (rm->payload_len > 0) ? rm->payload : NULL;
                out_pub.total_len = rm->payload_len;
#ifdef WOLFMQTT_V5
                out_pub.protocol_level = bc->protocol_level;
#endif
                enc_rc = MqttEncode_Publish(bc->tx_buf,
                    BROKER_CLIENT_TX_SZ(bc), &out_pub, 0);
                if (enc_rc > 0) {
                    WBLOG_DBG(broker, "broker: retained deliver sock=%d topic=%s "
                        "len=%u", (int)bc->sock, rm->topic,
                        (unsigned)rm->payload_len);
                    (void)MqttPacket_Write(&bc->client, bc->tx_buf, enc_rc);
                }
            }
            rm_prev = rm;
            rm = rm_next;
        }
    }
#endif
}
#endif /* WOLFMQTT_BROKER_RETAINED */

#ifdef WOLFMQTT_BROKER_WILL
static void BrokerClient_PublishWill(MqttBroker* broker, BrokerClient* bc)
{
    if (broker == NULL || bc == NULL || !bc->has_will) {
        return;
    }
    if (!BROKER_STR_VALID(bc->will_topic)) {
        return;
    }

    /* v5 Will Delay Interval: defer publication */
    if (bc->will_delay_sec > 0) {
        if (BrokerPendingWill_Add(broker, bc) == MQTT_CODE_SUCCESS) {
            BrokerClient_ClearWill(bc);
            return; /* will deferred, not published now */
        }
        /* If add failed (out of slots), publish immediately as fallback */
    }

    WBLOG_DBG(broker, "broker: LWT publish sock=%d topic=%s len=%u",
        (int)bc->sock, bc->will_topic, (unsigned)bc->will_payload_len);

    BrokerClient_PublishWillImmediate(broker, bc->will_topic,
        bc->will_payload, bc->will_payload_len, bc->will_qos,
        bc->will_retain);
    BrokerClient_ClearWill(bc);
}

/* Publish a will message immediately (shared by direct and deferred paths) */
static void BrokerClient_PublishWillImmediate(MqttBroker* broker,
    const char* topic, const byte* payload, word16 payload_len,
    MqttQoS qos, byte retain)
{
    if (broker == NULL || topic == NULL) {
        return;
    }

    /* Handle retain flag on will message */
    if (retain) {
        if (payload_len == 0) {
            BrokerRetained_Delete(broker, topic);
        }
        else {
            (void)BrokerRetained_Store(broker, topic, payload,
                payload_len, 0);
        }
    }

    /* Fan out to matching subscribers */
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            BrokerSub* sub = &broker->subs[i];
            if (!sub->in_use) continue;
#else
    {
        BrokerSub* sub = broker->subs;
        while (sub) {
#endif
            if (sub->client != NULL && sub->client->protocol_level != 0 &&
                BROKER_STR_VALID(sub->filter) &&
                BrokerTopicMatch(sub->filter, topic)) {
                MqttPublish out_pub;
                MqttQoS eff_qos;
                int enc_rc;
                XMEMSET(&out_pub, 0, sizeof(out_pub));
                out_pub.topic_name = (char*)topic;
                eff_qos = (qos < sub->qos) ? qos : sub->qos;
                out_pub.qos = eff_qos;
                out_pub.retain = 0;
                out_pub.duplicate = 0;
                out_pub.buffer = (payload_len > 0) ? (byte*)payload : NULL;
                out_pub.total_len = payload_len;
                if (eff_qos >= MQTT_QOS_1) {
                    out_pub.packet_id = BrokerNextPacketId(broker);
                }
#ifdef WOLFMQTT_V5
                out_pub.protocol_level = sub->client->protocol_level;
#endif
                enc_rc = MqttEncode_Publish(sub->client->tx_buf,
                    BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
                if (enc_rc > 0) {
                    (void)MqttPacket_Write(&sub->client->client,
                        sub->client->tx_buf, enc_rc);
                }
            }
#ifndef WOLFMQTT_STATIC_MEMORY
            sub = sub->next;
#endif
        }
    }
}
#endif /* WOLFMQTT_BROKER_WILL */

/* -------------------------------------------------------------------------- */
/* Topic matching                                                              */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_WILDCARDS
static int BrokerTopicMatch(const char* filter, const char* topic)
{
    const char* f = filter;
    const char* t = topic;

    if (filter == NULL || topic == NULL) {
        return 0;
    }

    while (*f && *t) {
        if (*f == '#') {
            return (f[1] == '\0');
        }
        if (*f == '+') {
            while (*t && *t != '/') {
                t++;
            }
            f++;
        }
        else {
            if (*f != *t) {
                return 0;
            }
            f++;
            t++;
        }
        if (*t == '/' && *f == '/') {
            t++;
            f++;
        }
        else if (*t == '/' || *f == '/') {
            return 0;
        }
    }

    if (*f == '#') {
        return (f[1] == '\0');
    }
    return (*f == '\0' && *t == '\0');
}
#else
/* Exact match only when wildcards are disabled */
static int BrokerTopicMatch(const char* filter, const char* topic)
{
    if (filter == NULL || topic == NULL) {
        return 0;
    }
    return (XSTRCMP(filter, topic) == 0);
}
#endif /* WOLFMQTT_BROKER_WILDCARDS */

/* -------------------------------------------------------------------------- */
/* Packet send helpers                                                         */
/* -------------------------------------------------------------------------- */
static int BrokerSend_PingResp(BrokerClient* bc)
{
    if (bc == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    WBLOG_DBG(bc->broker, "broker: PINGREQ -> PINGRESP sock=%d", (int)bc->sock);
    bc->tx_buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PING_RESP);
    bc->tx_buf[1] = 0;
    return MqttPacket_Write(&bc->client, bc->tx_buf, 2);
}

static int BrokerSend_SubAck(BrokerClient* bc, word16 packet_id,
    const byte* return_codes, int return_code_count)
{
    int remain_len;
    int pos = 0;
    int i;

    if (bc == NULL || return_codes == NULL || return_code_count <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    WBLOG_INFO(bc->broker, "broker: SUBACK sock=%d packet_id=%u topics=%d",
        (int)bc->sock, packet_id, return_code_count);
    remain_len = MQTT_DATA_LEN_SIZE + return_code_count;
#ifdef WOLFMQTT_V5
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        remain_len += 1; /* property length (0) */
    }
#endif

    bc->tx_buf[pos++] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    pos += MqttEncode_Vbi(&bc->tx_buf[pos], remain_len);
    pos += MqttEncode_Num(&bc->tx_buf[pos], packet_id);
#ifdef WOLFMQTT_V5
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        bc->tx_buf[pos++] = 0; /* property length */
    }
#endif
    for (i = 0; i < return_code_count; i++) {
        bc->tx_buf[pos++] = return_codes[i];
    }

    return MqttPacket_Write(&bc->client, bc->tx_buf, pos);
}

#ifdef WOLFMQTT_V5
/* Find a property by type in a property list */
static MqttProp* BrokerProps_Find(MqttProp* head, MqttPropertyType type)
{
    MqttProp* prop = head;
    while (prop != NULL) {
        if (prop->type == type) {
            return prop;
        }
        prop = prop->next;
    }
    return NULL;
}

static int BrokerSend_Disconnect(BrokerClient* bc, byte reason_code)
{
    int rc;
    MqttDisconnect disc;

    if (bc == NULL ||
        bc->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        return 0;
    }

    XMEMSET(&disc, 0, sizeof(disc));
    disc.protocol_level = bc->protocol_level;
    disc.reason_code = reason_code;

    rc = MqttEncode_Disconnect(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &disc);
    if (rc > 0) {
        WBLOG_DBG(bc->broker, "broker: DISCONNECT send sock=%d reason=0x%02x",
            (int)bc->sock, reason_code);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }
    return rc;
}
#endif

/* -------------------------------------------------------------------------- */
/* Packet handlers                                                             */
/* -------------------------------------------------------------------------- */

/* Returns: > 0 success, 0 auth rejected (CONNACK sent with refused),
 *          < 0 error */
static int BrokerHandle_Connect(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    MqttConnect mc;
    MqttConnectAck ack;
    MqttMessage lwt;

    XMEMSET(&mc, 0, sizeof(mc));
    XMEMSET(&ack, 0, sizeof(ack));
    XMEMSET(&lwt, 0, sizeof(lwt));
    mc.lwt_msg = &lwt;

    WBLOG_INFO(broker, "broker: CONNECT recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: CONNECT decode failed rc=%d", rc);
        return rc;
    }

    /* Store client ID */
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->client_id[0] = '\0';
#endif
    if (mc.client_id) {
        word16 id_len = 0;
        if (MqttDecode_Num((byte*)mc.client_id - MQTT_DATA_LEN_SIZE,
                &id_len, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            BROKER_STORE_STR(bc->client_id, mc.client_id, id_len,
                BROKER_MAX_CLIENT_ID_LEN);
        }
    }

    bc->protocol_level = mc.protocol_level;
    bc->keep_alive_sec = mc.keep_alive_sec;
    bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();
    WBLOG_INFO(broker, "broker: CONNECT proto=%u clean=%d will=%d client_id=%s",
        mc.protocol_level, mc.clean_session, mc.enable_lwt,
        BROKER_STR_VALID(bc->client_id) ? bc->client_id : "(null)");

    /* Client ID uniqueness and clean session handling */
    bc->clean_session = mc.clean_session;
    if (BROKER_STR_VALID(bc->client_id)) {
        BrokerClient* old;

        /* Cancel any pending will for this client_id (reconnect) */
        BrokerPendingWill_Cancel(broker, bc->client_id);

        old = BrokerClient_FindByClientId(broker, bc->client_id, bc);
        if (old != NULL) {
            WBLOG_INFO(broker, "broker: duplicate client_id=%s, disconnecting "
                "old sock=%d", bc->client_id, (int)old->sock);
            /* Publish old client's will on takeover */
#ifdef WOLFMQTT_V5
            if (old->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                BrokerClient_PublishWill(broker, old);
            }
            else {
                BrokerSend_Disconnect(old,
                    MQTT_REASON_SESSION_TAKEN_OVER);
                BrokerClient_ClearWill(old);
            }
#else
            BrokerClient_PublishWill(broker, old);
#endif
            if (!mc.clean_session) {
                /* Reassociate old client's subs to new client */
                BrokerSubs_ReassociateClient(broker, bc->client_id, bc);
            }
            BrokerSubs_RemoveClient(broker, old);
            BrokerClient_Remove(broker, old);
        }
        if (mc.clean_session) {
            /* Remove any remaining subs for this client_id */
            BrokerSubs_RemoveByClientId(broker, bc->client_id);
        }
    }

    /* Store Last Will and Testament */
    BrokerClient_ClearWill(bc);
#ifdef WOLFMQTT_BROKER_WILL
    if (mc.enable_lwt && mc.lwt_msg != NULL) {
        if (mc.lwt_msg->topic_name != NULL &&
            mc.lwt_msg->topic_name_len > 0) {
            BROKER_STORE_STR(bc->will_topic, mc.lwt_msg->topic_name,
                mc.lwt_msg->topic_name_len, BROKER_MAX_TOPIC_LEN);
        }
        if (mc.lwt_msg->total_len > 0 && mc.lwt_msg->buffer != NULL) {
            word16 wp_len = (word16)mc.lwt_msg->total_len;
#ifdef WOLFMQTT_STATIC_MEMORY
            if (wp_len > BROKER_MAX_WILL_PAYLOAD_LEN) {
                wp_len = BROKER_MAX_WILL_PAYLOAD_LEN;
            }
            XMEMCPY(bc->will_payload, mc.lwt_msg->buffer, wp_len);
#else
            bc->will_payload = (byte*)WOLFMQTT_MALLOC(wp_len);
            if (bc->will_payload != NULL) {
                XMEMCPY(bc->will_payload, mc.lwt_msg->buffer, wp_len);
            }
#endif
            bc->will_payload_len = wp_len;
        }
        bc->will_qos = mc.lwt_msg->qos;
        bc->will_retain = mc.lwt_msg->retain;
        bc->will_delay_sec = 0;
#ifdef WOLFMQTT_V5
        if (mc.lwt_msg->props != NULL) {
            MqttProp* prop = BrokerProps_Find(mc.lwt_msg->props,
                MQTT_PROP_WILL_DELAY_INTERVAL);
            if (prop != NULL) {
                bc->will_delay_sec = prop->data_int;
            }
        }
#endif
        bc->has_will = 1;
        WBLOG_DBG(broker, "broker: LWT stored sock=%d topic=%s qos=%d retain=%d "
            "len=%u delay=%u", (int)bc->sock, bc->will_topic,
            bc->will_qos, bc->will_retain,
            (unsigned)bc->will_payload_len,
            (unsigned)bc->will_delay_sec);
    }
#endif /* WOLFMQTT_BROKER_WILL */

    /* Store credentials */
#ifdef WOLFMQTT_BROKER_AUTH
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->username[0] = '\0';
    bc->password[0] = '\0';
#endif
    if (mc.username) {
        word16 ulen = 0;
        if (MqttDecode_Num((byte*)mc.username - MQTT_DATA_LEN_SIZE,
                &ulen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            BROKER_STORE_STR(bc->username, mc.username, ulen,
                BROKER_MAX_USERNAME_LEN);
        }
    }
    if (mc.password) {
        word16 plen = 0;
        if (MqttDecode_Num((byte*)mc.password - MQTT_DATA_LEN_SIZE,
                &plen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            BROKER_STORE_STR(bc->password, mc.password, plen,
                BROKER_MAX_PASSWORD_LEN);
        }
    }
#endif /* WOLFMQTT_BROKER_AUTH */

    /* Check auth before sending CONNACK */
    ack.flags = 0;
    ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
#ifdef WOLFMQTT_V5
    ack.protocol_level = mc.protocol_level;
    ack.props = NULL;
#endif

#ifdef WOLFMQTT_BROKER_AUTH
    if (broker->auth_user || broker->auth_pass) {
        int auth_ok = 1;
        if (broker->auth_user && (
        #ifndef WOLFMQTT_STATIC_MEMORY
            bc->username == NULL ||
        #endif
            bc->username[0] == '\0' ||
            BrokerStrCompare(broker->auth_user, bc->username) != 0)) {
            auth_ok = 0;
        }
        if (broker->auth_pass && (
        #ifndef WOLFMQTT_STATIC_MEMORY
            bc->password == NULL ||
        #endif
            bc->password[0] == '\0' ||
            BrokerStrCompare(broker->auth_pass, bc->password) != 0)) {
            auth_ok = 0;
        }
        if (!auth_ok) {
            WBLOG_ERR(broker, "broker: auth failed sock=%d user=%s", (int)bc->sock,
            #ifdef WOLFMQTT_STATIC_MEMORY
                bc->username[0] ? bc->username : "(null)");
            #else
                (bc->username && bc->username[0]) ? bc->username : "(null)");
            #endif
        #ifdef WOLFMQTT_V5
            if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                ack.return_code = MQTT_REASON_BAD_USER_OR_PASS;
            }
            else
        #endif
            {
                ack.return_code =
                    MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD;
            }
        }
    }
#endif /* WOLFMQTT_BROKER_AUTH */

#ifdef WOLFMQTT_V5
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
        ack.return_code == MQTT_CONNECT_ACK_CODE_ACCEPTED) {
        MqttProp* prop;

        /* If client sent empty client ID, generate one and inform client */
        if (!BROKER_STR_VALID(bc->client_id)) {
            char auto_id[32];
            int id_len = XSNPRINTF(auto_id, (int)sizeof(auto_id),
                "auto-%04x", broker->next_packet_id++);
            if (id_len > 0) {
                BROKER_STORE_STR(bc->client_id, auto_id, (word16)id_len,
                    BROKER_MAX_CLIENT_ID_LEN);
            }
            prop = MqttProps_Add(&ack.props);
            if (prop != NULL) {
                prop->type = MQTT_PROP_ASSIGNED_CLIENT_ID;
                prop->data_str.str = bc->client_id;
                prop->data_str.len = (word16)XSTRLEN(bc->client_id);
            }
        }

        /* Advertise feature availability */
        prop = MqttProps_Add(&ack.props);
        if (prop != NULL) {
            prop->type = MQTT_PROP_RETAIN_AVAIL;
    #ifdef WOLFMQTT_BROKER_RETAINED
            prop->data_byte = 1;
    #else
            prop->data_byte = 0;
    #endif
        }
        prop = MqttProps_Add(&ack.props);
        if (prop != NULL) {
            prop->type = MQTT_PROP_WILDCARD_SUB_AVAIL;
    #ifdef WOLFMQTT_BROKER_WILDCARDS
            prop->data_byte = 1;
    #else
            prop->data_byte = 0;
    #endif
        }
        prop = MqttProps_Add(&ack.props);
        if (prop != NULL) {
            prop->type = MQTT_PROP_MAX_QOS;
            prop->data_byte = MQTT_QOS_2;
        }
    }
#endif

    rc = MqttEncode_ConnectAck(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &ack);
    if (rc > 0) {
        WBLOG_INFO(broker, "broker: CONNACK send sock=%d code=%d", (int)bc->sock,
            ack.return_code);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }

#ifdef WOLFMQTT_V5
    if (ack.props) {
        (void)MqttProps_Free(ack.props);
    }
    if (mc.props) {
        (void)MqttProps_Free(mc.props);
    }
    if (lwt.props) {
        (void)MqttProps_Free(lwt.props);
    }
#endif

    /* Return 0 if auth rejected so caller can disconnect */
    if (ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
        return 0;
    }
    return rc;
}

static int BrokerHandle_Subscribe(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    int i;
    MqttSubscribe sub;
    MqttTopic topic_buf[MAX_MQTT_TOPICS];
    byte return_codes[MAX_MQTT_TOPICS];

    XMEMSET(&sub, 0, sizeof(sub));
#ifdef WOLFMQTT_V5
    sub.protocol_level = bc->protocol_level;
#endif
    XMEMSET(topic_buf, 0, sizeof(topic_buf));
    sub.topics = topic_buf;

    WBLOG_INFO(broker, "broker: SUBSCRIBE recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Subscribe(bc->rx_buf, rx_len, &sub);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: SUBSCRIBE decode failed rc=%d", rc);
        return rc;
    }

    /* Register subscriptions and build return codes */
    for (i = 0; i < sub.topic_count && i < MAX_MQTT_TOPICS; i++) {
        const char* f = sub.topics[i].topic_filter;
        word16 flen = 0;
        MqttQoS topic_qos = sub.topics[i].qos;
        MqttQoS granted_qos;

        /* Cap at QoS 2 */
        if (topic_qos > MQTT_QOS_2) {
            topic_qos = MQTT_QOS_2;
        }
        granted_qos = topic_qos;

        if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
                &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            (void)BrokerSubs_Add(broker, bc, f, flen, topic_qos);

#ifdef WOLFMQTT_BROKER_RETAINED
            /* Deliver retained messages matching this filter */
            {
                char filter_z[BROKER_MAX_FILTER_LEN];
                word16 copy_len = flen;
                if (copy_len >= BROKER_MAX_FILTER_LEN) {
                    copy_len = BROKER_MAX_FILTER_LEN - 1;
                }
                XMEMCPY(filter_z, f, copy_len);
                filter_z[copy_len] = '\0';
                BrokerRetained_DeliverToClient(broker, bc, filter_z,
                    topic_qos);
            }
#endif
        }
        return_codes[i] = (byte)granted_qos;
    }

    rc = BrokerSend_SubAck(bc, sub.packet_id, return_codes,
            sub.topic_count);

#ifdef WOLFMQTT_V5
    if (sub.props) {
        (void)MqttProps_Free(sub.props);
    }
#endif
    return rc;
}

static int BrokerHandle_Unsubscribe(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    int i;
    MqttUnsubscribe unsub;
    MqttUnsubscribeAck ack;
    MqttTopic topic_buf[MAX_MQTT_TOPICS];
#ifdef WOLFMQTT_V5
    byte reasons[MAX_MQTT_TOPICS];
#endif

    XMEMSET(&unsub, 0, sizeof(unsub));
#ifdef WOLFMQTT_V5
    unsub.protocol_level = bc->protocol_level;
#endif
    XMEMSET(topic_buf, 0, sizeof(topic_buf));
    unsub.topics = topic_buf;

    WBLOG_INFO(broker, "broker: UNSUBSCRIBE recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Unsubscribe(bc->rx_buf, rx_len, &unsub);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: UNSUBSCRIBE decode failed rc=%d", rc);
        return rc;
    }

    /* Remove subscriptions and populate reason codes */
    for (i = 0; i < unsub.topic_count && i < MAX_MQTT_TOPICS; i++) {
        const char* f = unsub.topics[i].topic_filter;
        word16 flen = 0;
        if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
                &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            BrokerSubs_Remove(broker, bc, f, flen);
        }
#ifdef WOLFMQTT_V5
        reasons[i] = MQTT_REASON_SUCCESS;
#endif
    }

    XMEMSET(&ack, 0, sizeof(ack));
    ack.packet_id = unsub.packet_id;
#ifdef WOLFMQTT_V5
    ack.protocol_level = bc->protocol_level;
    ack.props = NULL;
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        ack.reason_codes = reasons;
        ack.reason_code_count = (word16)unsub.topic_count;
    }
    else {
        ack.reason_codes = NULL;
        ack.reason_code_count = 0;
    }
#endif
    rc = MqttEncode_UnsubscribeAck(bc->tx_buf,
            BROKER_CLIENT_TX_SZ(bc), &ack);
    if (rc > 0) {
        WBLOG_INFO(broker, "broker: UNSUBACK send sock=%d packet_id=%u",
            (int)bc->sock, ack.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }

#ifdef WOLFMQTT_V5
    if (unsub.props) {
        (void)MqttProps_Free(unsub.props);
    }
#endif
    return rc;
}

static int BrokerHandle_Publish(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    MqttPublish pub;
    MqttPublishResp resp;
    byte* payload = NULL;
    char* topic = NULL;
#ifdef WOLFMQTT_STATIC_MEMORY
    char topic_buf[BROKER_MAX_TOPIC_LEN];
#endif

    XMEMSET(&pub, 0, sizeof(pub));
#ifdef WOLFMQTT_V5
    pub.protocol_level = bc->protocol_level;
#endif
    WBLOG_DBG(broker, "broker: PUBLISH recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Publish(bc->rx_buf, rx_len, &pub);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: PUBLISH decode failed rc=%d", rc);
        return rc;
    }

    /* Create null-terminated topic copy for matching/logging */
    if (pub.topic_name && pub.topic_name_len > 0) {
#ifdef WOLFMQTT_STATIC_MEMORY
        word16 tlen = pub.topic_name_len;
        if (tlen >= BROKER_MAX_TOPIC_LEN) {
            tlen = BROKER_MAX_TOPIC_LEN - 1;
        }
        XMEMCPY(topic_buf, pub.topic_name, tlen);
        topic_buf[tlen] = '\0';
        topic = topic_buf;
#else
        topic = (char*)WOLFMQTT_MALLOC(pub.topic_name_len + 1);
        if (topic != NULL) {
            XMEMCPY(topic, pub.topic_name, pub.topic_name_len);
            topic[pub.topic_name_len] = '\0';
        }
#endif
    }
    /* Use payload pointer directly from decoded packet — rx_buf is not
     * modified during fan-out (each subscriber encodes into their own
     * tx_buf), so this pointer remains valid throughout. */
    payload = pub.buffer;

#ifdef WOLFMQTT_BROKER_RETAINED
    /* Handle retained messages */
    if (topic != NULL && pub.retain) {
        if (pub.total_len == 0) {
            BrokerRetained_Delete(broker, topic);
        }
        else if (payload != NULL) {
            word32 expiry = 0;
#ifdef WOLFMQTT_V5
            if (pub.props != NULL) {
                MqttProp* prop = BrokerProps_Find(pub.props,
                    MQTT_PROP_MSG_EXPIRY_INTERVAL);
                if (prop != NULL) {
                    expiry = prop->data_int;
                }
            }
#endif
            (void)BrokerRetained_Store(broker, topic, payload,
                (word16)pub.total_len, expiry);
        }
    }
#endif /* WOLFMQTT_BROKER_RETAINED */

    if (topic != NULL && (payload != NULL || pub.total_len == 0)) {
        /* Fan out to matching subscribers */
#ifdef WOLFMQTT_STATIC_MEMORY
        {
            int i;
            for (i = 0; i < BROKER_MAX_SUBS; i++) {
                BrokerSub* sub = &broker->subs[i];
                if (!sub->in_use) continue;
#else
        {
            BrokerSub* sub = broker->subs;
            while (sub) {
#endif
                if (sub->client != NULL &&
                    sub->client->protocol_level != 0 &&
                    BROKER_STR_VALID(sub->filter) &&
                    BrokerTopicMatch(sub->filter, topic)) {
                    MqttPublish out_pub;
                    MqttQoS eff_qos;
                    XMEMSET(&out_pub, 0, sizeof(out_pub));
                    out_pub.topic_name = topic;
                    eff_qos = (pub.qos < sub->qos) ? pub.qos : sub->qos;
                    out_pub.qos = eff_qos;
                    if (eff_qos >= MQTT_QOS_1) {
                        out_pub.packet_id = BrokerNextPacketId(broker);
                    }
                    out_pub.retain = 0;
                    out_pub.duplicate = 0;
                    out_pub.buffer = payload;
                    out_pub.total_len = pub.total_len;
#ifdef WOLFMQTT_V5
                    out_pub.protocol_level = sub->client->protocol_level;
                    if (sub->client->protocol_level >=
                        MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                        out_pub.props = pub.props;
                    }
#endif
                    rc = MqttEncode_Publish(sub->client->tx_buf,
                            BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
                    if (rc > 0) {
                        WBLOG_DBG(broker, "broker: PUBLISH fwd sock=%d -> sock=%d "
                            "topic=%s qos=%d len=%u",
                            (int)bc->sock, (int)sub->client->sock,
                            topic, eff_qos, (unsigned)pub.total_len);
                        (void)MqttPacket_Write(&sub->client->client,
                            sub->client->tx_buf, rc);
                    }
                }
#ifndef WOLFMQTT_STATIC_MEMORY
                sub = sub->next;
#endif
            }
        }
    }

    if (pub.qos == MQTT_QOS_1 || pub.qos == MQTT_QOS_2) {
        XMEMSET(&resp, 0, sizeof(resp));
        resp.packet_id = pub.packet_id;
#ifdef WOLFMQTT_V5
        resp.protocol_level = bc->protocol_level;
        resp.reason_code = MQTT_REASON_SUCCESS;
        resp.props = NULL;
#endif
        rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
                (pub.qos == MQTT_QOS_1) ? MQTT_PACKET_TYPE_PUBLISH_ACK :
                MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
        if (rc > 0) {
            WBLOG_DBG(broker, "broker: PUBRESP send sock=%d qos=%d packet_id=%u",
                (int)bc->sock, pub.qos, pub.packet_id);
            rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
        }
    }

#ifdef WOLFMQTT_V5
    if (pub.props) {
        (void)MqttProps_Free(pub.props);
    }
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    if (topic) {
        WOLFMQTT_FREE(topic);
    }
#endif

    return rc;
}

static int BrokerHandle_PublishRel(BrokerClient* bc, int rx_len)
{
    int rc;
    MqttPublishResp resp;

    XMEMSET(&resp, 0, sizeof(resp));
#ifdef WOLFMQTT_V5
    resp.protocol_level = bc->protocol_level;
#endif
    WBLOG_DBG(bc->broker, "broker: PUBLISH_REL recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
            MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    if (rc < 0) {
        WBLOG_ERR(bc->broker, "broker: PUBLISH_REL decode failed rc=%d", rc);
        return rc;
    }

#ifdef WOLFMQTT_V5
    resp.reason_code = MQTT_REASON_SUCCESS;
    resp.props = NULL;
#endif
    rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
            MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    if (rc > 0) {
        WBLOG_DBG(bc->broker, "broker: PUBCOMP send sock=%d packet_id=%u",
            (int)bc->sock, resp.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }
#ifdef WOLFMQTT_V5
    if (resp.props) {
        (void)MqttProps_Free(resp.props);
    }
#endif
    return rc;
}

/* Handle PUBREC from subscriber: broker sent QoS 2 PUBLISH, subscriber
 * responds with PUBREC, broker sends PUBREL */
static int BrokerHandle_PublishRec(BrokerClient* bc, int rx_len)
{
    int rc;
    MqttPublishResp resp;

    XMEMSET(&resp, 0, sizeof(resp));
#ifdef WOLFMQTT_V5
    resp.protocol_level = bc->protocol_level;
#endif
    WBLOG_DBG(bc->broker, "broker: PUBLISH_REC recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
            MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
    if (rc < 0) {
        WBLOG_ERR(bc->broker, "broker: PUBLISH_REC decode failed rc=%d", rc);
        return rc;
    }

#ifdef WOLFMQTT_V5
    resp.reason_code = MQTT_REASON_SUCCESS;
    resp.props = NULL;
#endif
    rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
            MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    if (rc > 0) {
        WBLOG_DBG(bc->broker, "broker: PUBREL send sock=%d packet_id=%u",
            (int)bc->sock, resp.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }
#ifdef WOLFMQTT_V5
    if (resp.props) {
        (void)MqttProps_Free(resp.props);
    }
#endif
    return rc;
}

/* -------------------------------------------------------------------------- */
/* Per-client processing (called from Step)                                    */
/* -------------------------------------------------------------------------- */
static int BrokerClient_Process(MqttBroker* broker, BrokerClient* bc)
{
    int rc;
    int activity = 0;

#ifdef ENABLE_MQTT_TLS
    /* Complete TLS handshake before processing MQTT packets */
    if (!bc->tls_handshake_done) {
        int ret;
        bc->client.tls.timeout_ms_read = BROKER_TIMEOUT_MS;
        bc->client.tls.timeout_ms_write = BROKER_TIMEOUT_MS;
        ret = wolfSSL_accept(bc->client.tls.ssl);
        if (ret == WOLFSSL_SUCCESS) {
            bc->tls_handshake_done = 1;
            WBLOG_INFO(broker, "broker: TLS handshake done sock=%d %s",
                (int)bc->sock, wolfSSL_get_version(bc->client.tls.ssl));
            /* Log client certificate CN if mutual TLS.
             * Requires wolfSSL built with KEEP_PEER_CERT or similar. */
        #if defined(KEEP_PEER_CERT) || defined(OPENSSL_EXTRA) || \
            defined(OPENSSL_EXTRA_X509_SMALL) || defined(SESSION_CERTS)
            if (broker->tls_ca != NULL) {
                WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(
                    bc->client.tls.ssl);
                if (peer != NULL) {
                    char* cn = wolfSSL_X509_get_subjectCN(peer);
                    (void)cn; /* may be unused if logging disabled */
                    WBLOG_INFO(broker, "broker: TLS client cert sock=%d CN=%s",
                        (int)bc->sock, cn ? cn : "(unknown)");
                    wolfSSL_X509_free(peer);
                }
            }
        #endif
            return 1; /* activity */
        }
        else {
            int err = wolfSSL_get_error(bc->client.tls.ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE) {
                return 0; /* handshake in progress */
            }
            WBLOG_ERR(broker, "broker: TLS handshake failed sock=%d err=%d",
                (int)bc->sock, err);
            BrokerSubs_RemoveClient(broker, bc);
            BrokerClient_Remove(broker, bc);
            return 0;
        }
    }
#endif

    /* Try non-blocking read (timeout=0) */
    rc = MqttPacket_Read(&bc->client, bc->rx_buf, BROKER_CLIENT_RX_SZ(bc), 0);

    if (rc == MQTT_CODE_ERROR_TIMEOUT || rc == MQTT_CODE_CONTINUE) {
        /* No data available - not an error */
        rc = 0;
    }
    else if (rc < 0) {
        WBLOG_ERR(broker, "broker: read failed sock=%d rc=%d", (int)bc->sock, rc);
        BrokerClient_PublishWill(broker, bc); /* abnormal disconnect */
        BrokerSubs_RemoveClient(broker, bc);
        BrokerClient_Remove(broker, bc);
        return 0;
    }

    if (rc > 0) {
        byte type = MQTT_PACKET_TYPE_GET(bc->rx_buf[0]);
        bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();
        activity = 1;
        WBLOG_DBG(broker, "broker: packet sock=%d type=%u len=%d",
            (int)bc->sock, type, rc);
        switch (type) {
            case MQTT_PACKET_TYPE_CONNECT:
            {
                int c_rc = BrokerHandle_Connect(bc, rc, broker);
                if (c_rc == 0) {
                    /* Auth rejected, disconnect */
                    BrokerSubs_RemoveClient(broker, bc);
                    BrokerClient_Remove(broker, bc);
                    return 0;
                }
                break;
            }
            case MQTT_PACKET_TYPE_PUBLISH:
                (void)BrokerHandle_Publish(bc, rc, broker);
                break;
            case MQTT_PACKET_TYPE_PUBLISH_ACK:
                /* QoS 1 ack from subscriber - delivery complete */
                break;
            case MQTT_PACKET_TYPE_PUBLISH_REC:
                /* QoS 2 step 2: subscriber sends PUBREC, broker
                 * responds with PUBREL */
                (void)BrokerHandle_PublishRec(bc, rc);
                break;
            case MQTT_PACKET_TYPE_PUBLISH_REL:
                /* QoS 2 step 3: publisher sends PUBREL, broker
                 * responds with PUBCOMP */
                (void)BrokerHandle_PublishRel(bc, rc);
                break;
            case MQTT_PACKET_TYPE_PUBLISH_COMP:
                /* QoS 2 step 4: subscriber sends PUBCOMP - delivery
                 * complete */
                break;
            case MQTT_PACKET_TYPE_SUBSCRIBE:
                (void)BrokerHandle_Subscribe(bc, rc, broker);
                break;
            case MQTT_PACKET_TYPE_UNSUBSCRIBE:
                (void)BrokerHandle_Unsubscribe(bc, rc, broker);
                break;
            case MQTT_PACKET_TYPE_PING_REQ:
                (void)BrokerSend_PingResp(bc);
                break;
            case MQTT_PACKET_TYPE_DISCONNECT:
                BrokerClient_ClearWill(bc); /* normal disconnect */
                BrokerSubs_RemoveClient(broker, bc);
                BrokerClient_Remove(broker, bc);
                return 0;
            default:
                break;
        }
    }

    /* Check keepalive timeout (MQTT spec 3.1.2.10: 1.5x keep alive) */
    if (bc->keep_alive_sec > 0) {
        WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();
        if ((now - bc->last_rx) >
            (WOLFMQTT_BROKER_TIME_T)(bc->keep_alive_sec * 3 / 2)) {
            WBLOG_ERR(broker, "broker: keepalive timeout sock=%d", (int)bc->sock);
        #ifdef WOLFMQTT_V5
            BrokerSend_Disconnect(bc, MQTT_REASON_KEEP_ALIVE_TIMEOUT);
        #endif
            BrokerClient_PublishWill(broker, bc); /* abnormal disconnect */
            BrokerSubs_RemoveClient(broker, bc);
            BrokerClient_Remove(broker, bc);
            return 0;
        }
    }

    return activity;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */
int MqttBroker_Init(MqttBroker* broker, MqttBrokerNet* net)
{
    if (broker == NULL || net == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    XMEMSET(broker, 0, sizeof(*broker));
    XMEMCPY(&broker->net, net, sizeof(MqttBrokerNet));
    broker->listen_sock = BROKER_SOCKET_INVALID;
    broker->port = MQTT_DEFAULT_PORT;
    broker->running = 0;
    broker->log_level = BROKER_LOG_LEVEL_DEFAULT;
    broker->next_packet_id = 1;

#ifndef WOLFMQTT_BROKER_CUSTOM_NET
    /* For the default POSIX backend, the net callbacks expect ctx to be a
     * MqttBroker* for logging via WBLOG_*. If no context was provided,
     * default to using this broker instance to avoid NULL-dereference. */
    if (broker->net.ctx == NULL) {
        broker->net.ctx = broker;
    }
#endif

    return MQTT_CODE_SUCCESS;
}

int MqttBroker_Step(MqttBroker* broker)
{
    int activity = 0;
    BROKER_SOCKET_T new_sock = BROKER_SOCKET_INVALID;
    int rc;

    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (!broker->running) {
        return MQTT_CODE_SUCCESS;
    }

    /* 1. Try to accept a new connection (non-blocking) */
    rc = broker->net.accept(broker->net.ctx, broker->listen_sock, &new_sock);
    if (rc == MQTT_CODE_SUCCESS && new_sock != BROKER_SOCKET_INVALID) {
        WBLOG_INFO(broker, "broker: accept sock=%d", (int)new_sock);
        if (BrokerClient_Add(broker, new_sock) == NULL) {
            WBLOG_ERR(broker, "broker: accept sock=%d rejected (alloc)", (int)new_sock);
            broker->net.close(broker->net.ctx, new_sock);
        }
        activity = 1;
    }

    /* 2. Process each client */
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
            BrokerClient* bc = &broker->clients[i];
            if (!bc->in_use) {
                continue;
            }
            rc = BrokerClient_Process(broker, bc);
            if (rc > 0) {
                activity = 1;
            }
        }
    }
#else
    {
        BrokerClient* bc = broker->clients;
        while (bc) {
            BrokerClient* next = bc->next;
            rc = BrokerClient_Process(broker, bc);
            if (rc > 0) {
                activity = 1;
            }
            /* BrokerClient_Process may remove another client (e.g. client ID
             * takeover), which could free the node that next points to.
             * Validate next is still in the linked list before dereferencing */
            if (next != NULL) {
                BrokerClient* v = broker->clients;
                while (v != NULL && v != next) {
                    v = v->next;
                }
                if (v == NULL) {
                    break; /* next was freed; remaining clients handled next step */
                }
            }
            bc = next;
        }
    }
#endif

    /* 3. Process pending wills (v5 Will Delay Interval) */
    if (BrokerPendingWill_Process(broker) > 0) {
        activity = 1;
    }

    return activity ? MQTT_CODE_SUCCESS : MQTT_CODE_CONTINUE;
}

int MqttBroker_Run(MqttBroker* broker)
{
    int rc;

    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Start listening */
    rc = broker->net.listen(broker->net.ctx, &broker->listen_sock,
        broker->port, BROKER_LISTEN_BACKLOG);
    if (rc != MQTT_CODE_SUCCESS) {
        WBLOG_ERR(broker, "broker: listen failed rc=%d", rc);
        return rc;
    }

#if defined(ENABLE_MQTT_TLS) && !defined(WOLFMQTT_BROKER_CUSTOM_NET)
    if (broker->use_tls) {
        rc = BrokerTls_Init(broker);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: TLS init failed rc=%d", rc);
            return rc;
        }
        WBLOG_INFO(broker, "broker: listening on port %d (TLS)", broker->port);
    }
    else
#endif
    {
        WBLOG_INFO(broker, "broker: listening on port %d (no TLS)", broker->port);
    }
#ifdef WOLFMQTT_BROKER_AUTH
    if (broker->auth_user || broker->auth_pass) {
        WBLOG_INFO(broker, "broker: auth enabled user=%s",
            broker->auth_user ? broker->auth_user : "(null)");
    }
#endif

    broker->running = 1;
    while (broker->running) {
        rc = MqttBroker_Step(broker);
        if (rc == MQTT_CODE_CONTINUE) {
            /* Idle - sleep briefly to avoid busy-waiting */
            BROKER_SLEEP_MS(10);
        }
        else if (rc < 0 && rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }

    return MQTT_CODE_SUCCESS;
}

int MqttBroker_Stop(MqttBroker* broker)
{
    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    broker->running = 0;
    return MQTT_CODE_SUCCESS;
}

int MqttBroker_Free(MqttBroker* broker)
{
    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Disconnect and free all clients and subscriptions */
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
            if (broker->clients[i].in_use) {
                BrokerSubs_RemoveClient(broker, &broker->clients[i]);
                BrokerClient_Free(&broker->clients[i]);
            }
        }
    }
#else
    while (broker->clients) {
        BrokerSubs_RemoveClient(broker, broker->clients);
        BrokerClient_Remove(broker, broker->clients);
    }
#endif

    /* Clean up pending wills and retained messages */
    BrokerPendingWill_FreeAll(broker);
    BrokerRetained_FreeAll(broker);

#if defined(ENABLE_MQTT_TLS) && !defined(WOLFMQTT_BROKER_CUSTOM_NET)
    BrokerTls_Free(broker);
#endif

    /* Close listen socket */
    if (broker->listen_sock != BROKER_SOCKET_INVALID) {
        broker->net.close(broker->net.ctx, broker->listen_sock);
        broker->listen_sock = BROKER_SOCKET_INVALID;
    }

    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* CLI wrapper                                                                 */
/* -------------------------------------------------------------------------- */
static void BrokerUsage(const char* prog)
{
    PRINTF("usage: %s [-p port] [-v level]"
#ifdef WOLFMQTT_BROKER_AUTH
           " [-u user] [-P pass]"
#endif
#ifdef ENABLE_MQTT_TLS
           " [-t] [-V ver] [-c cert] [-K key] [-A ca]"
#endif
           , prog);
    PRINTF("  -v <level>  Log level: 1=error, 2=info (default), 3=debug");
#ifdef ENABLE_MQTT_TLS
    PRINTF("  -t          Enable TLS");
    PRINTF("  -V <ver>    TLS version: 12=TLS 1.2, 13=TLS 1.3 (default: auto)");
    PRINTF("  -c <file>   Server certificate file (PEM)");
    PRINTF("  -K <file>   Server private key file (PEM)");
    PRINTF("  -A <file>   CA certificate for mutual TLS (PEM)");
#endif
    PRINTF("Features:"
#ifdef WOLFMQTT_BROKER_RETAINED
           " retained"
#endif
#ifdef WOLFMQTT_BROKER_WILL
           " will"
#endif
#ifdef WOLFMQTT_BROKER_WILDCARDS
           " wildcards"
#endif
#ifdef WOLFMQTT_BROKER_AUTH
           " auth"
#endif
#ifdef ENABLE_MQTT_TLS
           " tls"
#endif
           );
}

static MqttBroker* g_broker = NULL;

#if !defined(WOLFMQTT_BROKER_CUSTOM_NET) && !defined(NO_MAIN_DRIVER)
#include <signal.h>
static void broker_signal_handler(int signo)
{
    if (g_broker != NULL) {
        PRINTF("broker: received signal %d, shutting down", signo);
        MqttBroker_Stop(g_broker);
    }
}
#endif

int wolfmqtt_broker(int argc, char** argv)
{
    int rc;
    MqttBroker broker;
    MqttBrokerNet net;
    int i;

    /* Set stdout to unbuffered for immediate output */
#ifndef WOLFMQTT_NO_STDIO
    setvbuf(stdout, NULL, _IONBF, 0);
#endif

#ifndef WOLFMQTT_BROKER_CUSTOM_NET
    rc = MqttBrokerNet_Init(&net);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#else
    XMEMSET(&net, 0, sizeof(net));
    PRINTF("broker: custom net requires callbacks to be set");
    return MQTT_CODE_ERROR_BAD_ARG;
#endif

    rc = MqttBroker_Init(&broker, &net);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-p") == 0 && i + 1 < argc) {
            broker.port = (word16)XATOI(argv[++i]);
        }
        else if (XSTRCMP(argv[i], "-v") == 0 && i + 1 < argc) {
            broker.log_level = (byte)XATOI(argv[++i]);
        }
#ifdef WOLFMQTT_BROKER_AUTH
        else if (XSTRCMP(argv[i], "-u") == 0 && i + 1 < argc) {
            broker.auth_user = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-P") == 0 && i + 1 < argc) {
            broker.auth_pass = argv[++i];
        }
#endif
#ifdef ENABLE_MQTT_TLS
        else if (XSTRCMP(argv[i], "-t") == 0) {
            broker.use_tls = 1;
            if (broker.port == MQTT_DEFAULT_PORT) {
                broker.port = MQTT_SECURE_PORT;
            }
        }
        else if (XSTRCMP(argv[i], "-V") == 0 && i + 1 < argc) {
            broker.tls_version = (byte)XATOI(argv[++i]);
        }
        else if (XSTRCMP(argv[i], "-c") == 0 && i + 1 < argc) {
            broker.tls_cert = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-K") == 0 && i + 1 < argc) {
            broker.tls_key = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-A") == 0 && i + 1 < argc) {
            broker.tls_ca = argv[++i];
        }
#endif
        else if (XSTRCMP(argv[i], "-h") == 0) {
            BrokerUsage(argv[0]);
            return 0;
        }
        else {
            BrokerUsage(argv[0]);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
    }

#if !defined(WOLFMQTT_BROKER_CUSTOM_NET) && !defined(NO_MAIN_DRIVER)
    g_broker = &broker;
    signal(SIGINT, broker_signal_handler);
    signal(SIGTERM, broker_signal_handler);
#endif

    rc = MqttBroker_Run(&broker);

#if !defined(WOLFMQTT_BROKER_CUSTOM_NET) && !defined(NO_MAIN_DRIVER)
    g_broker = NULL;
#endif

    MqttBroker_Free(&broker);
    return rc;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    return wolfmqtt_broker(argc, argv);
}
#endif

#else /* WOLFMQTT_BROKER */
#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    PRINTF("broker: not built (configure with --enable-broker)");
    return 0;
}
#endif
#endif /* WOLFMQTT_BROKER */
