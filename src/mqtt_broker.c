
/* mqtt_broker.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef WOLFMQTT_BROKER

int wolfmqtt_broker(int argc, char** argv);

typedef struct BrokerClient {
    int fd;
    byte protocol_level;
    char* client_id;
    char* username;
    char* password;
    word16 keep_alive_sec;
    time_t last_rx;
    MqttNet net;
    MqttClient client;
    byte* tx_buf;
    byte* rx_buf;
    int tx_buf_len;
    int rx_buf_len;
    struct BrokerClient* next;
} BrokerClient;

typedef struct BrokerSub {
    char* filter;
    BrokerClient* client;
    struct BrokerSub* next;
} BrokerSub;

#define BROKER_RX_BUF_SZ 4096
#define BROKER_TX_BUF_SZ 4096
#define BROKER_TIMEOUT_MS 1000
#define BROKER_LISTEN_BACKLOG 8
#define BROKER_LOG_PKT 1

static int BrokerSocket_SetNonBlocking(int fd)
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

static int BrokerNetConnect(void* context, const char* host, word16 port,
    int timeout_ms)
{
    (void)context;
    (void)host;
    (void)port;
    (void)timeout_ms;
    PRINTF("broker: net connect ctx=%p host=%s port=%u timeout=%d",
        context, host ? host : "(null)", port, timeout_ms);
    return MQTT_CODE_SUCCESS;
}

static int BrokerNetRead(void* context, byte* buf, int buf_len, int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    fd_set rfds;
    struct timeval tv;
    int rc;

    if (bc == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    FD_ZERO(&rfds);
    FD_SET(bc->fd, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(bc->fd + 1, &rfds, NULL, NULL, &tv);
    if (rc == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (rc < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    rc = (int)recv(bc->fd, buf, buf_len, 0);
    if (rc <= 0) {
        if (rc < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return MQTT_CODE_CONTINUE;
        }
        PRINTF("broker: recv error fd=%d rc=%d errno=%d", bc->fd, rc, errno);
        return MQTT_CODE_ERROR_NETWORK;
    }
    PRINTF("broker: recv fd=%d len=%d", bc->fd, rc);
    return rc;
}

static int BrokerNetWrite(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    fd_set wfds;
    struct timeval tv;
    int rc;

    if (bc == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    FD_ZERO(&wfds);
    FD_SET(bc->fd, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(bc->fd + 1, NULL, &wfds, NULL, &tv);
    if (rc == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (rc < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    rc = (int)send(bc->fd, buf, buf_len, 0);
    if (rc <= 0) {
        if (rc < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return MQTT_CODE_CONTINUE;
        }
        PRINTF("broker: send error fd=%d rc=%d errno=%d", bc->fd, rc, errno);
        return MQTT_CODE_ERROR_NETWORK;
    }
    PRINTF("broker: send fd=%d len=%d", bc->fd, rc);
    return rc;
}

static int BrokerNetDisconnect(void* context)
{
    BrokerClient* bc = (BrokerClient*)context;
    if (bc && bc->fd >= 0) {
        PRINTF("broker: disconnect fd=%d", bc->fd);
        close(bc->fd);
        bc->fd = -1;
    }
    return MQTT_CODE_SUCCESS;
}

static void BrokerClient_Free(BrokerClient* bc)
{
    if (bc == NULL) {
        return;
    }
    (void)BrokerNetDisconnect(bc);
    MqttClient_DeInit(&bc->client);
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
}

static BrokerClient* BrokerClient_Add(BrokerClient** head, int fd)
{
    BrokerClient* bc;
    int rc;

    bc = (BrokerClient*)WOLFMQTT_MALLOC(sizeof(BrokerClient));
    if (bc == NULL) {
        return NULL;
    }
    XMEMSET(bc, 0, sizeof(BrokerClient));
    bc->fd = fd;
    bc->protocol_level = 0;
    bc->keep_alive_sec = 0;
    bc->last_rx = time(NULL);
    bc->tx_buf_len = BROKER_TX_BUF_SZ;
    bc->rx_buf_len = BROKER_RX_BUF_SZ;
    bc->tx_buf = (byte*)WOLFMQTT_MALLOC(bc->tx_buf_len);
    bc->rx_buf = (byte*)WOLFMQTT_MALLOC(bc->rx_buf_len);
    if (bc->tx_buf == NULL || bc->rx_buf == NULL) {
        BrokerClient_Free(bc);
        return NULL;
    }

    bc->net.context = bc;
    bc->net.connect = BrokerNetConnect;
    bc->net.read = BrokerNetRead;
    bc->net.write = BrokerNetWrite;
    bc->net.disconnect = BrokerNetDisconnect;

    rc = MqttClient_Init(&bc->client, &bc->net, NULL,
            bc->tx_buf, bc->tx_buf_len, bc->rx_buf, bc->rx_buf_len,
            BROKER_TIMEOUT_MS);
    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("broker: client init failed rc=%d", rc);
        BrokerClient_Free(bc);
        return NULL;
    }

    bc->next = *head;
    *head = bc;
    return bc;
}

static void BrokerClient_Remove(BrokerClient** head, BrokerClient* bc)
{
    BrokerClient* cur;
    BrokerClient* prev = NULL;

    if (head == NULL || bc == NULL) {
        return;
    }
    cur = *head;
    while (cur) {
        if (cur == bc) {
            if (prev) {
                prev->next = cur->next;
            }
            else {
                *head = cur->next;
            }
            BrokerClient_Free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

static void BrokerSubs_RemoveClient(BrokerSub** head, BrokerClient* bc)
{
    BrokerSub* cur = *head;
    BrokerSub* prev = NULL;

    while (cur) {
        BrokerSub* next = cur->next;
        if (cur->client == bc) {
            if (prev) {
                prev->next = next;
            }
            else {
                *head = next;
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

static int BrokerSubs_Add(BrokerSub** head, BrokerClient* bc,
    const char* filter, word16 filter_len)
{
    BrokerSub* sub;

    sub = (BrokerSub*)WOLFMQTT_MALLOC(sizeof(BrokerSub));
    if (sub == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(sub, 0, sizeof(BrokerSub));
    sub->filter = (char*)WOLFMQTT_MALLOC(filter_len + 1);
    if (sub->filter == NULL) {
        WOLFMQTT_FREE(sub);
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMCPY(sub->filter, filter, filter_len);
    sub->filter[filter_len] = '\0';
    sub->client = bc;
    sub->next = *head;
    *head = sub;
    PRINTF("broker: sub add fd=%d filter=%s", bc->fd, sub->filter);
    return MQTT_CODE_SUCCESS;
}

static void BrokerSubs_Remove(BrokerSub** head, BrokerClient* bc,
    const char* filter, word16 filter_len)
{
    BrokerSub* cur = *head;
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
                *head = next;
            }
            PRINTF("broker: sub remove fd=%d filter=%s",
                bc->fd, cur->filter);
            WOLFMQTT_FREE(cur->filter);
            WOLFMQTT_FREE(cur);
            return;
        }
        prev = cur;
        cur = next;
    }
}

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

static int BrokerSend_PingResp(BrokerClient* bc)
{
    if (bc == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    PRINTF("broker: PINGREQ -> PINGRESP fd=%d", bc->fd);
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

    PRINTF("broker: SUBACK fd=%d packet_id=%u topics=%d",
        bc->fd, packet_id, return_code_count);
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

static int BrokerHandle_Connect(BrokerClient* bc, int rx_len)
{
    int rc;
    MqttConnect mc;
    MqttConnectAck ack;
    MqttMessage lwt;

    XMEMSET(&mc, 0, sizeof(mc));
    XMEMSET(&ack, 0, sizeof(ack));
    XMEMSET(&lwt, 0, sizeof(lwt));
    mc.lwt_msg = &lwt;

    PRINTF("broker: CONNECT recv fd=%d len=%d", bc->fd, rx_len);
    rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
    if (rc < 0) {
        PRINTF("broker: CONNECT decode failed rc=%d", rc);
        return rc;
    }

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
    bc->protocol_level = mc.protocol_level;
    bc->keep_alive_sec = mc.keep_alive_sec;
    bc->last_rx = time(NULL);
    PRINTF("broker: CONNECT proto=%u clean=%d will=%d",
        mc.protocol_level, mc.clean_session, mc.enable_lwt);

    ack.flags = 0;
    ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
#ifdef WOLFMQTT_V5
    ack.protocol_level = mc.protocol_level;
    ack.props = NULL;
#endif

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
#ifdef WOLFMQTT_V5
    ack.protocol_level = mc.protocol_level;
    ack.props = NULL;
#endif
    rc = MqttEncode_ConnectAck(bc->tx_buf, bc->tx_buf_len, &ack);
    if (rc > 0) {
        PRINTF("broker: CONNACK send fd=%d", bc->fd);
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
    return rc;
}

static int BrokerHandle_Subscribe(BrokerClient* bc, int rx_len)
{
    int rc;
    int i;
    MqttSubscribe sub;
    byte return_codes[MAX_MQTT_TOPICS];

    XMEMSET(&sub, 0, sizeof(sub));
#ifdef WOLFMQTT_V5
    sub.protocol_level = bc->protocol_level;
#endif
    sub.topics = (MqttTopic*)WOLFMQTT_MALLOC(sizeof(MqttTopic) * MAX_MQTT_TOPICS);
    if (sub.topics == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(sub.topics, 0, sizeof(MqttTopic) * MAX_MQTT_TOPICS);

    PRINTF("broker: SUBSCRIBE recv fd=%d len=%d", bc->fd, rx_len);
    rc = MqttDecode_Subscribe(bc->rx_buf, rx_len, &sub);
    if (rc < 0) {
        PRINTF("broker: SUBSCRIBE decode failed rc=%d", rc);
        WOLFMQTT_FREE(sub.topics);
        return rc;
    }

    for (i = 0; i < sub.topic_count && i < MAX_MQTT_TOPICS; i++) {
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

static int BrokerHandle_Unsubscribe(BrokerClient* bc, int rx_len)
{
    int rc;
    MqttUnsubscribe unsub;
    MqttUnsubscribeAck ack;

    XMEMSET(&unsub, 0, sizeof(unsub));
#ifdef WOLFMQTT_V5
    unsub.protocol_level = bc->protocol_level;
#endif
    unsub.topics = (MqttTopic*)WOLFMQTT_MALLOC(sizeof(MqttTopic) * MAX_MQTT_TOPICS);
    if (unsub.topics == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(unsub.topics, 0, sizeof(MqttTopic) * MAX_MQTT_TOPICS);

    PRINTF("broker: UNSUBSCRIBE recv fd=%d len=%d", bc->fd, rx_len);
    rc = MqttDecode_Unsubscribe(bc->rx_buf, rx_len, &unsub);
    if (rc < 0) {
        PRINTF("broker: UNSUBSCRIBE decode failed rc=%d", rc);
        WOLFMQTT_FREE(unsub.topics);
        return rc;
    }

    XMEMSET(&ack, 0, sizeof(ack));
    ack.packet_id = unsub.packet_id;
#ifdef WOLFMQTT_V5
    ack.protocol_level = bc->protocol_level;
    ack.props = NULL;
    ack.reason_codes = NULL;
#endif
    rc = MqttEncode_UnsubscribeAck(bc->tx_buf, bc->tx_buf_len, &ack);
    if (rc > 0) {
        PRINTF("broker: UNSUBACK send fd=%d packet_id=%u",
            bc->fd, ack.packet_id);
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
    BrokerSub* subs)
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
    PRINTF("broker: PUBLISH recv fd=%d len=%d", bc->fd, rx_len);
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
        BrokerSub* sub = subs;
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
                        sub->client->tx_buf_len,
                        &out_pub, 0);
                if (rc > 0) {
                    PRINTF("broker: PUBLISH fwd fd=%d -> fd=%d topic=%s len=%u",
                        bc->fd, sub->client->fd, topic ? topic : "(null)",
                        (unsigned)pub.total_len);
                    (void)MqttPacket_Write(&sub->client->client,
                        sub->client->tx_buf, rc);
                }
            }
            sub = sub->next;
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
        rc = MqttEncode_PublishResp(bc->tx_buf, bc->tx_buf_len,
                (pub.qos == MQTT_QOS_1) ? MQTT_PACKET_TYPE_PUBLISH_ACK :
                MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
        if (rc > 0) {
            PRINTF("broker: PUBRESP send fd=%d qos=%d packet_id=%u",
                bc->fd, pub.qos, pub.packet_id);
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
    PRINTF("broker: PUBLISH_REL recv fd=%d len=%d", bc->fd, rx_len);
    rc = MqttDecode_PublishResp(bc->rx_buf, rx_len, MQTT_PACKET_TYPE_PUBLISH_REL,
            &resp);
    if (rc < 0) {
        PRINTF("broker: PUBLISH_REL decode failed rc=%d", rc);
        return rc;
    }

#ifdef WOLFMQTT_V5
    resp.reason_code = MQTT_REASON_SUCCESS;
    resp.props = NULL;
#endif
    rc = MqttEncode_PublishResp(bc->tx_buf, bc->tx_buf_len,
            MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    if (rc > 0) {
        PRINTF("broker: PUBCOMP send fd=%d packet_id=%u",
            bc->fd, resp.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }
#ifdef WOLFMQTT_V5
    if (resp.props) {
        (void)MqttProps_Free(resp.props);
    }
#endif
    return rc;
}

static void BrokerUsage(const char* prog)
{
    PRINTF("usage: %s [-p port] [-u user] [-P pass]", prog);
}

int wolfmqtt_broker(int argc, char** argv)
{
    int ret = 0;
    int listen_fd;
    struct sockaddr_in addr;
    BrokerClient* clients = NULL;
    BrokerSub* subs = NULL;
    const char* auth_user = NULL;
    const char* auth_pass = NULL;
    int port = MQTT_DEFAULT_PORT;
    int i;

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-p") == 0 && i + 1 < argc) {
            port = XATOI(argv[++i]);
        }
        else if (XSTRCMP(argv[i], "-u") == 0 && i + 1 < argc) {
            auth_user = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-P") == 0 && i + 1 < argc) {
            auth_pass = argv[++i];
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

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        PRINTF("broker: socket failed (%d)", errno);
        return MQTT_CODE_ERROR_NETWORK;
    }
    {
        int opt = 1;
        (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    }

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((word16)port);

    if (BrokerSocket_SetNonBlocking(listen_fd) != MQTT_CODE_SUCCESS) {
        PRINTF("broker: set nonblocking failed (%d)", errno);
        close(listen_fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PRINTF("broker: bind failed (%d)", errno);
        close(listen_fd);
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (listen(listen_fd, BROKER_LISTEN_BACKLOG) < 0) {
        PRINTF("broker: listen failed (%d)", errno);
        close(listen_fd);
        return MQTT_CODE_ERROR_NETWORK;
    }

    PRINTF("broker: listening on port %d (no TLS)", port);
    if (auth_user || auth_pass) {
        PRINTF("broker: auth enabled user=%s", auth_user ? auth_user : "(null)");
    }

    while (1) {
        fd_set rfds;
        int maxfd = listen_fd;
        BrokerClient* bc;

        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);

        for (bc = clients; bc; bc = bc->next) {
            FD_SET(bc->fd, &rfds);
            if (bc->fd > maxfd) {
                maxfd = bc->fd;
            }
        }

        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            PRINTF("broker: select failed (%d)", errno);
            ret = MQTT_CODE_ERROR_NETWORK;
            break;
        }

        if (FD_ISSET(listen_fd, &rfds)) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd >= 0) {
                (void)BrokerSocket_SetNonBlocking(client_fd);
                PRINTF("broker: accept fd=%d", client_fd);
                if (BrokerClient_Add(&clients, client_fd) == NULL) {
                    PRINTF("broker: accept fd=%d rejected (alloc)", client_fd);
                    close(client_fd);
                }
            }
        }

        bc = clients;
        while (bc) {
            BrokerClient* next = bc->next;
            if (FD_ISSET(bc->fd, &rfds)) {
                int rc = MqttPacket_Read(&bc->client, bc->rx_buf,
                        bc->rx_buf_len, BROKER_TIMEOUT_MS);
                if (rc < 0) {
                    PRINTF("broker: read failed fd=%d rc=%d", bc->fd, rc);
                    BrokerSubs_RemoveClient(&subs, bc);
                    BrokerClient_Remove(&clients, bc);
                }
                else if (rc > 0) {
                    byte type = MQTT_PACKET_TYPE_GET(bc->rx_buf[0]);
                    bc->last_rx = time(NULL);
#if BROKER_LOG_PKT
                    PRINTF("broker: packet fd=%d type=%u len=%d",
                        bc->fd, type, rc);
#endif
                    switch (type) {
                        case MQTT_PACKET_TYPE_CONNECT:
                            (void)BrokerHandle_Connect(bc, rc);
                            if (auth_user || auth_pass) {
                                int ok = 1;
                                if (auth_user && (!bc->username ||
                                    XSTRCMP(auth_user, bc->username) != 0)) {
                                    ok = 0;
                                }
                                if (auth_pass && (!bc->password ||
                                    XSTRCMP(auth_pass, bc->password) != 0)) {
                                    ok = 0;
                                }
                                if (!ok) {
                                    MqttConnectAck nack;
                                    XMEMSET(&nack, 0, sizeof(nack));
                                    nack.flags = 0;
                                    nack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD;
#ifdef WOLFMQTT_V5
                                    nack.protocol_level = bc->protocol_level;
                                    nack.props = NULL;
#endif
                                    {
                                        int nrc = MqttEncode_ConnectAck(
                                                bc->tx_buf, bc->tx_buf_len,
                                                &nack);
                                        if (nrc > 0) {
                                            (void)MqttPacket_Write(&bc->client,
                                                bc->tx_buf, nrc);
                                        }
                                    }
                                    PRINTF("broker: auth failed fd=%d", bc->fd);
                                    BrokerSubs_RemoveClient(&subs, bc);
                                    BrokerClient_Remove(&clients, bc);
                                }
                            }
                            break;
                        case MQTT_PACKET_TYPE_PUBLISH:
                            (void)BrokerHandle_Publish(bc, rc, subs);
                            break;
                        case MQTT_PACKET_TYPE_PUBLISH_REL:
                            (void)BrokerHandle_PublishRel(bc, rc);
                            break;
                        case MQTT_PACKET_TYPE_SUBSCRIBE:
                        {
                            int s_rc = BrokerHandle_Subscribe(bc, rc);
                            if (s_rc >= 0) {
                                int idx;
                                MqttSubscribe sub;
                                XMEMSET(&sub, 0, sizeof(sub));
#ifdef WOLFMQTT_V5
                                sub.protocol_level = bc->protocol_level;
#endif
                                sub.topics = (MqttTopic*)WOLFMQTT_MALLOC(
                                        sizeof(MqttTopic) * MAX_MQTT_TOPICS);
                                if (sub.topics) {
                                    XMEMSET(sub.topics, 0,
                                            sizeof(MqttTopic) * MAX_MQTT_TOPICS);
                                    if (MqttDecode_Subscribe(bc->rx_buf, rc,
                                            &sub) >= 0) {
                                        for (idx = 0; idx < sub.topic_count;
                                             idx++) {
                                            const char* f = sub.topics[idx].topic_filter;
                                            word16 flen = 0;
                                            if (f &&
                                                MqttDecode_Num((byte*)f -
                                                    MQTT_DATA_LEN_SIZE,
                                                    &flen,
                                                    MQTT_DATA_LEN_SIZE) ==
                                                    MQTT_DATA_LEN_SIZE) {
                                                (void)BrokerSubs_Add(&subs, bc,
                                                    f, flen);
                                            }
                                        }
                                    }
#ifdef WOLFMQTT_V5
                                    if (sub.props) {
                                        (void)MqttProps_Free(sub.props);
                                    }
#endif
                                    WOLFMQTT_FREE(sub.topics);
                                }
                            }
                            break;
                        }
                        case MQTT_PACKET_TYPE_UNSUBSCRIBE:
                        {
                            int u_rc = BrokerHandle_Unsubscribe(bc, rc);
                            if (u_rc >= 0) {
                                int idx;
                                MqttUnsubscribe unsub;
                                XMEMSET(&unsub, 0, sizeof(unsub));
#ifdef WOLFMQTT_V5
                                unsub.protocol_level = bc->protocol_level;
#endif
                                unsub.topics = (MqttTopic*)WOLFMQTT_MALLOC(
                                        sizeof(MqttTopic) * MAX_MQTT_TOPICS);
                                if (unsub.topics) {
                                    XMEMSET(unsub.topics, 0,
                                            sizeof(MqttTopic) * MAX_MQTT_TOPICS);
                                    if (MqttDecode_Unsubscribe(bc->rx_buf, rc,
                                            &unsub) >= 0) {
                                        for (idx = 0; idx < unsub.topic_count;
                                             idx++) {
                                            const char* f = unsub.topics[idx].topic_filter;
                                            word16 flen = 0;
                                            if (f &&
                                                MqttDecode_Num((byte*)f -
                                                    MQTT_DATA_LEN_SIZE,
                                                    &flen,
                                                    MQTT_DATA_LEN_SIZE) ==
                                                    MQTT_DATA_LEN_SIZE) {
                                                BrokerSubs_Remove(&subs, bc,
                                                    f, flen);
                                            }
                                        }
                                    }
#ifdef WOLFMQTT_V5
                                    if (unsub.props) {
                                        (void)MqttProps_Free(unsub.props);
                                    }
#endif
                                    WOLFMQTT_FREE(unsub.topics);
                                }
                            }
                            break;
                        }
                        case MQTT_PACKET_TYPE_PING_REQ:
                            (void)BrokerSend_PingResp(bc);
                            break;
                        case MQTT_PACKET_TYPE_DISCONNECT:
                            BrokerSubs_RemoveClient(&subs, bc);
                            BrokerClient_Remove(&clients, bc);
                            break;
                        default:
                            break;
                    }
                }
            }
            if (bc && bc->keep_alive_sec > 0) {
                time_t now = time(NULL);
                if ((now - bc->last_rx) > (time_t)(bc->keep_alive_sec * 2)) {
                    PRINTF("broker: keepalive timeout fd=%d", bc->fd);
                    BrokerSubs_RemoveClient(&subs, bc);
                    BrokerClient_Remove(&clients, bc);
                }
            }
            bc = next;
        }
    }

    while (clients) {
        BrokerSubs_RemoveClient(&subs, clients);
        BrokerClient_Remove(&clients, clients);
    }
    close(listen_fd);

    return ret;
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
