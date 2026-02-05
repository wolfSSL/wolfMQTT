/* mqtt_broker.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
    #ifndef WOLFMQTT_BROKER_CUSTOM_NET
        #define WOLFMQTT_BROKER_GET_TIME_S() \
            ((WOLFMQTT_BROKER_TIME_T)time(NULL))
    #else
        #error "WOLFMQTT_BROKER_CUSTOM_NET requires " \
               "WOLFMQTT_BROKER_GET_TIME_S to be defined"
    #endif
#endif

/* -------------------------------------------------------------------------- */
/* Default sleep abstraction                                                   */
/* -------------------------------------------------------------------------- */
#ifndef BROKER_SLEEP_MS
    #ifdef USE_WINDOWS_API
        #define BROKER_SLEEP_MS(ms) Sleep(ms)
    #elif !defined(WOLFMQTT_BROKER_CUSTOM_NET)
        #define BROKER_SLEEP_MS(ms) usleep((unsigned)(ms) * 1000)
    #else
        #error "WOLFMQTT_BROKER_CUSTOM_NET requires " \
               "BROKER_SLEEP_MS to be defined"
    #endif
#endif

#ifndef BROKER_LOG_PKT
    #define BROKER_LOG_PKT 1
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
    (void)ctx;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        PRINTF("broker: socket failed (%d)", errno);
        return MQTT_CODE_ERROR_NETWORK;
    }

    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (BrokerPosix_SetNonBlocking(fd) != MQTT_CODE_SUCCESS) {
        PRINTF("broker: set nonblocking failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PRINTF("broker: bind failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (listen(fd, backlog) < 0) {
        PRINTF("broker: listen failed (%d)", errno);
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
    (void)ctx;

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
        PRINTF("broker: recv error sock=%d rc=%d errno=%d",
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
    (void)ctx;

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
        PRINTF("broker: send error sock=%d rc=%d errno=%d",
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
        PRINTF("broker: disconnect sock=%d", (int)bc->sock);
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
    MqttClient_DeInit(&bc->client);
#ifdef WOLFMQTT_STATIC_MEMORY
    XMEMSET(bc, 0, sizeof(*bc));
    /* in_use is now 0 after memset */
#else
    if (bc->client_id) {
        WOLFMQTT_FREE(bc->client_id);
    }
    if (bc->username) {
        WOLFMQTT_FREE(bc->username);
    }
    if (bc->password) {
        WOLFMQTT_FREE(bc->password);
    }
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
    int rc;

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
            return NULL;
        }
        XMEMSET(bc, 0, sizeof(*bc));
        bc->in_use = 1;
    }
#else
    bc = (BrokerClient*)WOLFMQTT_MALLOC(sizeof(BrokerClient));
    if (bc == NULL) {
        return NULL;
    }
    XMEMSET(bc, 0, sizeof(*bc));
    bc->tx_buf_len = BROKER_TX_BUF_SZ;
    bc->rx_buf_len = BROKER_RX_BUF_SZ;
    bc->tx_buf = (byte*)WOLFMQTT_MALLOC(bc->tx_buf_len);
    bc->rx_buf = (byte*)WOLFMQTT_MALLOC(bc->rx_buf_len);
    if (bc->tx_buf == NULL || bc->rx_buf == NULL) {
        BrokerClient_Free(bc);
        return NULL;
    }
#endif

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

#ifdef WOLFMQTT_STATIC_MEMORY
    rc = MqttClient_Init(&bc->client, &bc->net, NULL,
            bc->tx_buf, BROKER_TX_BUF_SZ, bc->rx_buf, BROKER_RX_BUF_SZ,
            BROKER_TIMEOUT_MS);
#else
    rc = MqttClient_Init(&bc->client, &bc->net, NULL,
            bc->tx_buf, bc->tx_buf_len, bc->rx_buf, bc->rx_buf_len,
            BROKER_TIMEOUT_MS);
#endif
    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("broker: client init failed rc=%d", rc);
        BrokerClient_Free(bc);
        return NULL;
    }

#ifndef WOLFMQTT_STATIC_MEMORY
    /* Prepend to linked list */
    bc->next = broker->clients;
    broker->clients = bc;
#endif

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
    const char* filter, word16 filter_len)
{
    BrokerSub* sub = NULL;

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
            return MQTT_CODE_ERROR_MEMORY;
        }
        XMEMSET(sub, 0, sizeof(*sub));
        sub->in_use = 1;
        if (filter_len >= BROKER_MAX_FILTER_LEN) {
            filter_len = BROKER_MAX_FILTER_LEN - 1;
        }
        XMEMCPY(sub->filter, filter, filter_len);
        sub->filter[filter_len] = '\0';
    }
#else
    sub = (BrokerSub*)WOLFMQTT_MALLOC(sizeof(BrokerSub));
    if (sub == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(sub, 0, sizeof(*sub));
    sub->filter = (char*)WOLFMQTT_MALLOC(filter_len + 1);
    if (sub->filter == NULL) {
        WOLFMQTT_FREE(sub);
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMCPY(sub->filter, filter, filter_len);
    sub->filter[filter_len] = '\0';
    sub->next = broker->subs;
    broker->subs = sub;
#endif

    sub->client = bc;
    PRINTF("broker: sub add sock=%d filter=%s", (int)bc->sock, sub->filter);
    return MQTT_CODE_SUCCESS;
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
            PRINTF("broker: sub remove sock=%d filter=%s",
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
            PRINTF("broker: sub remove sock=%d filter=%s",
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
/* Topic matching                                                              */
/* -------------------------------------------------------------------------- */
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

/* -------------------------------------------------------------------------- */
/* Packet send helpers                                                         */
/* -------------------------------------------------------------------------- */
static int BrokerSend_PingResp(BrokerClient* bc)
{
    if (bc == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    PRINTF("broker: PINGREQ -> PINGRESP sock=%d", (int)bc->sock);
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->tx_buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PING_RESP);
    bc->tx_buf[1] = 0;
    return MqttPacket_Write(&bc->client, bc->tx_buf, 2);
#else
    bc->tx_buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PING_RESP);
    bc->tx_buf[1] = 0;
    return MqttPacket_Write(&bc->client, bc->tx_buf, 2);
#endif
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

    PRINTF("broker: SUBACK sock=%d packet_id=%u topics=%d",
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

    PRINTF("broker: CONNECT recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
    if (rc < 0) {
        PRINTF("broker: CONNECT decode failed rc=%d", rc);
        return rc;
    }

    /* Store client ID */
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->client_id[0] = '\0';
    if (mc.client_id) {
        word16 id_len = 0;
        if (MqttDecode_Num((byte*)mc.client_id - MQTT_DATA_LEN_SIZE,
                &id_len, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            if (id_len >= BROKER_MAX_CLIENT_ID_LEN) {
                id_len = BROKER_MAX_CLIENT_ID_LEN - 1;
            }
            XMEMCPY(bc->client_id, mc.client_id, id_len);
            bc->client_id[id_len] = '\0';
        }
    }
#else
    if (bc->client_id) {
        WOLFMQTT_FREE(bc->client_id);
        bc->client_id = NULL;
    }
    if (mc.client_id) {
        word16 id_len = 0;
        if (MqttDecode_Num((byte*)mc.client_id - MQTT_DATA_LEN_SIZE,
                &id_len, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            bc->client_id = (char*)WOLFMQTT_MALLOC(id_len + 1);
            if (bc->client_id != NULL) {
                XMEMCPY(bc->client_id, mc.client_id, id_len);
                bc->client_id[id_len] = '\0';
            }
        }
    }
#endif

    bc->protocol_level = mc.protocol_level;
    bc->keep_alive_sec = mc.keep_alive_sec;
    bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();
    PRINTF("broker: CONNECT proto=%u clean=%d will=%d client_id=%s",
        mc.protocol_level, mc.clean_session, mc.enable_lwt,
        bc->client_id[0] ? bc->client_id : "(null)");

    /* Store credentials */
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->username[0] = '\0';
    if (mc.username) {
        word16 ulen = 0;
        if (MqttDecode_Num((byte*)mc.username - MQTT_DATA_LEN_SIZE,
                &ulen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            if (ulen >= BROKER_MAX_USERNAME_LEN) {
                ulen = BROKER_MAX_USERNAME_LEN - 1;
            }
            XMEMCPY(bc->username, mc.username, ulen);
            bc->username[ulen] = '\0';
        }
    }
    bc->password[0] = '\0';
    if (mc.password) {
        word16 plen = 0;
        if (MqttDecode_Num((byte*)mc.password - MQTT_DATA_LEN_SIZE,
                &plen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            if (plen >= BROKER_MAX_PASSWORD_LEN) {
                plen = BROKER_MAX_PASSWORD_LEN - 1;
            }
            XMEMCPY(bc->password, mc.password, plen);
            bc->password[plen] = '\0';
        }
    }
#else
    if (bc->username) {
        WOLFMQTT_FREE(bc->username);
        bc->username = NULL;
    }
    if (bc->password) {
        WOLFMQTT_FREE(bc->password);
        bc->password = NULL;
    }
    if (mc.username) {
        word16 ulen = 0;
        if (MqttDecode_Num((byte*)mc.username - MQTT_DATA_LEN_SIZE,
                &ulen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            bc->username = (char*)WOLFMQTT_MALLOC(ulen + 1);
            if (bc->username) {
                XMEMCPY(bc->username, mc.username, ulen);
                bc->username[ulen] = '\0';
            }
        }
    }
    if (mc.password) {
        word16 plen = 0;
        if (MqttDecode_Num((byte*)mc.password - MQTT_DATA_LEN_SIZE,
                &plen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            bc->password = (char*)WOLFMQTT_MALLOC(plen + 1);
            if (bc->password) {
                XMEMCPY(bc->password, mc.password, plen);
                bc->password[plen] = '\0';
            }
        }
    }
#endif

    /* Check auth before sending CONNACK */
    ack.flags = 0;
    ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
#ifdef WOLFMQTT_V5
    ack.protocol_level = mc.protocol_level;
    ack.props = NULL;
#endif

    if (broker->auth_user || broker->auth_pass) {
        int auth_ok = 1;
        if (broker->auth_user && (bc->username[0] == '\0' ||
            XSTRCMP(broker->auth_user, bc->username) != 0)) {
            auth_ok = 0;
        }
        if (broker->auth_pass && (bc->password[0] == '\0' ||
            XSTRCMP(broker->auth_pass, bc->password) != 0)) {
            auth_ok = 0;
        }
        if (!auth_ok) {
            PRINTF("broker: auth failed sock=%d user=%s", (int)bc->sock,
                bc->username[0] ? bc->username : "(null)");
            ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD;
        }
    }

    rc = MqttEncode_ConnectAck(bc->tx_buf,
#ifdef WOLFMQTT_STATIC_MEMORY
        BROKER_TX_BUF_SZ,
#else
        bc->tx_buf_len,
#endif
        &ack);
    if (rc > 0) {
        PRINTF("broker: CONNACK send sock=%d code=%d", (int)bc->sock,
            ack.return_code);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }

#ifdef WOLFMQTT_V5
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
    byte return_codes[MAX_MQTT_TOPICS];

    XMEMSET(&sub, 0, sizeof(sub));
#ifdef WOLFMQTT_V5
    sub.protocol_level = bc->protocol_level;
#endif
    sub.topics = (MqttTopic*)WOLFMQTT_MALLOC(
        sizeof(MqttTopic) * MAX_MQTT_TOPICS);
    if (sub.topics == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(sub.topics, 0, sizeof(MqttTopic) * MAX_MQTT_TOPICS);

    PRINTF("broker: SUBSCRIBE recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Subscribe(bc->rx_buf, rx_len, &sub);
    if (rc < 0) {
        PRINTF("broker: SUBSCRIBE decode failed rc=%d", rc);
        WOLFMQTT_FREE(sub.topics);
        return rc;
    }

    /* Register subscriptions and build return codes */
    for (i = 0; i < sub.topic_count && i < MAX_MQTT_TOPICS; i++) {
        const char* f = sub.topics[i].topic_filter;
        word16 flen = 0;
        if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
                &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            (void)BrokerSubs_Add(broker, bc, f, flen);
        }
        return_codes[i] = MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0;
    }

    rc = BrokerSend_SubAck(bc, sub.packet_id, return_codes,
            sub.topic_count);

#ifdef WOLFMQTT_V5
    if (sub.props) {
        (void)MqttProps_Free(sub.props);
    }
#endif
    WOLFMQTT_FREE(sub.topics);
    return rc;
}

static int BrokerHandle_Unsubscribe(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    int i;
    MqttUnsubscribe unsub;
    MqttUnsubscribeAck ack;

    XMEMSET(&unsub, 0, sizeof(unsub));
#ifdef WOLFMQTT_V5
    unsub.protocol_level = bc->protocol_level;
#endif
    unsub.topics = (MqttTopic*)WOLFMQTT_MALLOC(
        sizeof(MqttTopic) * MAX_MQTT_TOPICS);
    if (unsub.topics == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(unsub.topics, 0, sizeof(MqttTopic) * MAX_MQTT_TOPICS);

    PRINTF("broker: UNSUBSCRIBE recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Unsubscribe(bc->rx_buf, rx_len, &unsub);
    if (rc < 0) {
        PRINTF("broker: UNSUBSCRIBE decode failed rc=%d", rc);
        WOLFMQTT_FREE(unsub.topics);
        return rc;
    }

    /* Remove subscriptions */
    for (i = 0; i < unsub.topic_count && i < MAX_MQTT_TOPICS; i++) {
        const char* f = unsub.topics[i].topic_filter;
        word16 flen = 0;
        if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
                &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            BrokerSubs_Remove(broker, bc, f, flen);
        }
    }

    XMEMSET(&ack, 0, sizeof(ack));
    ack.packet_id = unsub.packet_id;
#ifdef WOLFMQTT_V5
    ack.protocol_level = bc->protocol_level;
    ack.props = NULL;
    ack.reason_codes = NULL;
#endif
    rc = MqttEncode_UnsubscribeAck(bc->tx_buf,
#ifdef WOLFMQTT_STATIC_MEMORY
        BROKER_TX_BUF_SZ,
#else
        bc->tx_buf_len,
#endif
        &ack);
    if (rc > 0) {
        PRINTF("broker: UNSUBACK send sock=%d packet_id=%u",
            (int)bc->sock, ack.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }

#ifdef WOLFMQTT_V5
    if (unsub.props) {
        (void)MqttProps_Free(unsub.props);
    }
#endif
    WOLFMQTT_FREE(unsub.topics);
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

    XMEMSET(&pub, 0, sizeof(pub));
#ifdef WOLFMQTT_V5
    pub.protocol_level = bc->protocol_level;
#endif
    PRINTF("broker: PUBLISH recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Publish(bc->rx_buf, rx_len, &pub);
    if (rc < 0) {
        PRINTF("broker: PUBLISH decode failed rc=%d", rc);
        return rc;
    }

    if (pub.topic_name && pub.topic_name_len > 0) {
        topic = (char*)WOLFMQTT_MALLOC(pub.topic_name_len + 1);
        if (topic != NULL) {
            XMEMCPY(topic, pub.topic_name, pub.topic_name_len);
            topic[pub.topic_name_len] = '\0';
        }
    }
    if (pub.total_len > 0 && pub.buffer != NULL) {
        payload = (byte*)WOLFMQTT_MALLOC(pub.total_len);
        if (payload != NULL) {
            XMEMCPY(payload, pub.buffer, pub.total_len);
        }
    }

    if (topic != NULL && (payload != NULL || pub.total_len == 0)) {
        /* Fan out to matching subscribers */
#ifdef WOLFMQTT_STATIC_MEMORY
        int si;
        for (si = 0; si < BROKER_MAX_SUBS; si++) {
            BrokerSub* sub = &broker->subs[si];
            if (!sub->in_use) {
                continue;
            }
            if (sub->client && sub->client->protocol_level != 0 &&
                sub->filter[0] != '\0' &&
                BrokerTopicMatch(sub->filter, topic)) {
                MqttPublish out_pub;
                XMEMSET(&out_pub, 0, sizeof(out_pub));
                out_pub.topic_name = topic;
                out_pub.qos = MQTT_QOS_0;
                out_pub.retain = pub.retain;
                out_pub.duplicate = 0;
                out_pub.buffer = payload;
                out_pub.total_len = pub.total_len;
#ifdef WOLFMQTT_V5
                out_pub.protocol_level = sub->client->protocol_level;
#endif
                rc = MqttEncode_Publish(sub->client->tx_buf,
                        BROKER_TX_BUF_SZ, &out_pub, 0);
                if (rc > 0) {
                    PRINTF("broker: PUBLISH fwd sock=%d -> sock=%d "
                        "topic=%s len=%u",
                        (int)bc->sock, (int)sub->client->sock,
                        topic, (unsigned)pub.total_len);
                    (void)MqttPacket_Write(&sub->client->client,
                        sub->client->tx_buf, rc);
                }
            }
        }
#else
        {
            BrokerSub* sub = broker->subs;
            while (sub) {
                if (sub->client && sub->client->protocol_level != 0 &&
                    sub->filter && BrokerTopicMatch(sub->filter, topic)) {
                    MqttPublish out_pub;
                    XMEMSET(&out_pub, 0, sizeof(out_pub));
                    out_pub.topic_name = topic;
                    out_pub.qos = MQTT_QOS_0;
                    out_pub.retain = pub.retain;
                    out_pub.duplicate = 0;
                    out_pub.buffer = payload;
                    out_pub.total_len = pub.total_len;
#ifdef WOLFMQTT_V5
                    out_pub.protocol_level = sub->client->protocol_level;
#endif
                    rc = MqttEncode_Publish(sub->client->tx_buf,
                            sub->client->tx_buf_len, &out_pub, 0);
                    if (rc > 0) {
                        PRINTF("broker: PUBLISH fwd sock=%d -> sock=%d "
                            "topic=%s len=%u",
                            (int)bc->sock, (int)sub->client->sock,
                            topic, (unsigned)pub.total_len);
                        (void)MqttPacket_Write(&sub->client->client,
                            sub->client->tx_buf, rc);
                    }
                }
                sub = sub->next;
            }
        }
#endif
    }

    if (pub.qos == MQTT_QOS_1 || pub.qos == MQTT_QOS_2) {
        XMEMSET(&resp, 0, sizeof(resp));
        resp.packet_id = pub.packet_id;
#ifdef WOLFMQTT_V5
        resp.protocol_level = bc->protocol_level;
        resp.reason_code = MQTT_REASON_SUCCESS;
        resp.props = NULL;
#endif
        rc = MqttEncode_PublishResp(bc->tx_buf,
#ifdef WOLFMQTT_STATIC_MEMORY
                BROKER_TX_BUF_SZ,
#else
                bc->tx_buf_len,
#endif
                (pub.qos == MQTT_QOS_1) ? MQTT_PACKET_TYPE_PUBLISH_ACK :
                MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
        if (rc > 0) {
            PRINTF("broker: PUBRESP send sock=%d qos=%d packet_id=%u",
                (int)bc->sock, pub.qos, pub.packet_id);
            rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
        }
    }

#ifdef WOLFMQTT_V5
    if (pub.props) {
        (void)MqttProps_Free(pub.props);
    }
#endif
    if (payload) {
        WOLFMQTT_FREE(payload);
    }
    if (topic) {
        WOLFMQTT_FREE(topic);
    }

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
    PRINTF("broker: PUBLISH_REL recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
            MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    if (rc < 0) {
        PRINTF("broker: PUBLISH_REL decode failed rc=%d", rc);
        return rc;
    }

#ifdef WOLFMQTT_V5
    resp.reason_code = MQTT_REASON_SUCCESS;
    resp.props = NULL;
#endif
    rc = MqttEncode_PublishResp(bc->tx_buf,
#ifdef WOLFMQTT_STATIC_MEMORY
            BROKER_TX_BUF_SZ,
#else
            bc->tx_buf_len,
#endif
            MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    if (rc > 0) {
        PRINTF("broker: PUBCOMP send sock=%d packet_id=%u",
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

    /* Try non-blocking read (timeout=0) */
#ifdef WOLFMQTT_STATIC_MEMORY
    rc = MqttPacket_Read(&bc->client, bc->rx_buf, BROKER_RX_BUF_SZ, 0);
#else
    rc = MqttPacket_Read(&bc->client, bc->rx_buf, bc->rx_buf_len, 0);
#endif

    if (rc == MQTT_CODE_ERROR_TIMEOUT || rc == MQTT_CODE_CONTINUE) {
        /* No data available - not an error */
        rc = 0;
    }
    else if (rc < 0) {
        PRINTF("broker: read failed sock=%d rc=%d", (int)bc->sock, rc);
        BrokerSubs_RemoveClient(broker, bc);
        BrokerClient_Remove(broker, bc);
        return 0;
    }

    if (rc > 0) {
        byte type = MQTT_PACKET_TYPE_GET(bc->rx_buf[0]);
        bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();
        activity = 1;
#if BROKER_LOG_PKT
        PRINTF("broker: packet sock=%d type=%u len=%d",
            (int)bc->sock, type, rc);
#endif
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
            case MQTT_PACKET_TYPE_PUBLISH_REL:
                (void)BrokerHandle_PublishRel(bc, rc);
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
                BrokerSubs_RemoveClient(broker, bc);
                BrokerClient_Remove(broker, bc);
                return 0;
            default:
                break;
        }
    }

    /* Check keepalive timeout */
    if (bc->keep_alive_sec > 0) {
        WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();
        if ((now - bc->last_rx) >
            (WOLFMQTT_BROKER_TIME_T)(bc->keep_alive_sec * 2)) {
            PRINTF("broker: keepalive timeout sock=%d", (int)bc->sock);
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
        PRINTF("broker: accept sock=%d", (int)new_sock);
        if (BrokerClient_Add(broker, new_sock) == NULL) {
            PRINTF("broker: accept sock=%d rejected (alloc)", (int)new_sock);
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
            bc = next;
        }
    }
#endif

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
        PRINTF("broker: listen failed rc=%d", rc);
        return rc;
    }

    PRINTF("broker: listening on port %d (no TLS)", broker->port);
    if (broker->auth_user || broker->auth_pass) {
        PRINTF("broker: auth enabled user=%s",
            broker->auth_user ? broker->auth_user : "(null)");
    }

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
    PRINTF("usage: %s [-p port] [-u user] [-P pass]", prog);
}

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
        else if (XSTRCMP(argv[i], "-u") == 0 && i + 1 < argc) {
            broker.auth_user = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-P") == 0 && i + 1 < argc) {
            broker.auth_pass = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-h") == 0) {
            BrokerUsage(argv[0]);
            return 0;
        }
        else {
            BrokerUsage(argv[0]);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
    }

    rc = MqttBroker_Run(&broker);
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
