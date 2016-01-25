/* mqtt_client.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"

/* Options */
//#define WOLFMQTT_DEBUG_CLIENT
#ifdef WOLFMQTT_NO_STDIO
    #undef WOLFMQTT_DEBUG_CLIENT
#endif

/* Private functions */
static int MqttClient_WaitType(MqttClient *client, int timeout_ms,
    byte wait_type, word16 wait_packet_id, void* p_decode)
{
    int rc;
    MqttPacket* header;
    byte msg_type, msg_qos;
    word16 packet_id = 0;
    int packet_len;

    while (1) {
        /* Wait for packet */
        rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len,
            timeout_ms);
        if (rc <= 0) { return rc; }
        packet_len = rc;

        /* Determine packet type */
        header = (MqttPacket*)client->rx_buf;
        msg_type = MQTT_PACKET_TYPE_GET(header->type_flags);
        msg_qos = MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);

#ifdef WOLFMQTT_DEBUG_CLIENT
        printf("Read Packet: Len %d, Type %d, Qos %d\n",
            packet_len, msg_type, msg_qos);
#endif

        switch(msg_type) {
            case MQTT_PACKET_TYPE_CONNECT_ACK:
            {
                /* Decode connect ack */
                MqttConnectAck connect_ack, *p_connect_ack = &connect_ack;
                if (p_decode) {
                    p_connect_ack = (MqttConnectAck*)p_decode;
                }
                rc = MqttDecode_ConenctAck(client->rx_buf, packet_len,
                    p_connect_ack);
                if (rc <= 0) { return rc; }
                break;
            }
            case MQTT_PACKET_TYPE_PUBLISH:
            {
                MqttMessage msg;
                byte msg_new = 1;
                byte msg_done;

                /* Decode publish message */
                rc = MqttDecode_Publish(client->rx_buf, packet_len, &msg);
                if (rc <= 0) { return rc; }

                /* Handle packet callback and read remaining payload */
                do {
                    /* Determine if message is done */
                    msg_done =
                        ((msg.buffer_pos + msg.buffer_len) >= msg.total_len) ?
                        1 : 0;

                    /* Issue callback for new message */
                    if (client->msg_cb) {
                        if (!msg_new) {
                            /* Reset topic name since valid on new message only */
                            msg.topic_name = NULL;
                            msg.topic_name_len = 0;
                        }
                        rc = client->msg_cb(client, &msg, msg_new, msg_done);
                        if (rc != MQTT_CODE_SUCCESS) { return rc; };
                    }

                    /* Read payload */
                    if (!msg_done) {
                        int msg_len;

                        msg.buffer_pos += msg.buffer_len;
                        msg.buffer_len = 0;

                        msg_len = (msg.total_len - msg.buffer_pos);
                        if (msg_len > client->rx_buf_len) {
                            msg_len = client->rx_buf_len;
                        }
                        rc = MqttSocket_Read(client, client->rx_buf, msg_len,
                            timeout_ms);
                        if (rc != msg_len) { return rc; }

                        /* Update message */
                        msg.buffer = client->rx_buf;
                        msg.buffer_len = msg_len;
                    }
                    msg_new = 0;
                } while (!msg_done);

                /* Handle Qos */
                if (msg_qos > MQTT_QOS_0) {
                    MqttPublishResp publish_resp;
                    MqttPacketType type;

                    packet_id = msg.packet_id;

                    /* Determine packet type to write */
                    type = (msg_qos == MQTT_QOS_1) ?
                        MQTT_PACKET_TYPE_PUBLISH_ACK :
                        MQTT_PACKET_TYPE_PUBLISH_REC;
                    publish_resp.packet_id = packet_id;

                    /* Encode publish response */
                    rc = MqttEncode_PublishResp(client->tx_buf,
                        client->tx_buf_len, type, &publish_resp);
                    if (rc <= 0) { return rc; }
                    packet_len = rc;

                    /* Send packet */
                    rc = MqttPacket_Write(client, client->tx_buf, packet_len);
                    if (rc != packet_len) { return rc; }
                }
                break;
            }
            case MQTT_PACKET_TYPE_PUBLISH_ACK:
            case MQTT_PACKET_TYPE_PUBLISH_REC:
            case MQTT_PACKET_TYPE_PUBLISH_REL:
            case MQTT_PACKET_TYPE_PUBLISH_COMP:
            {
                MqttPublishResp publish_resp, *p_publish_resp = &publish_resp;
                if (p_decode) {
                    p_publish_resp = (MqttPublishResp*)p_decode;
                }

                /* Decode publish response message */
                rc = MqttDecode_PublishResp(client->rx_buf, packet_len,
                    msg_type, p_publish_resp);
                if (rc <= 0) { return rc; }
                packet_id = p_publish_resp->packet_id;

                /* If Qos then send response */
                if (msg_type == MQTT_PACKET_TYPE_PUBLISH_REC ||
                    msg_type == MQTT_PACKET_TYPE_PUBLISH_REL) {

                    /* Encode publish response */
                    publish_resp.packet_id = packet_id;
                    rc = MqttEncode_PublishResp(client->tx_buf,
                        client->tx_buf_len, msg_type+1, &publish_resp);
                    if (rc <= 0) { return rc; }
                    packet_len = rc;

                    /* Send packet */
                    rc = MqttPacket_Write(client, client->tx_buf, packet_len);
                    if (rc != packet_len) { return rc; }
                }
                break;
            }
            case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
            {
                /* Decode subscribe ack */
                MqttSubscribeAck subscribe_ack;
                MqttSubscribeAck *p_subscribe_ack = &subscribe_ack;
                if (p_decode) {
                    p_subscribe_ack = (MqttSubscribeAck*)p_decode;
                }
                rc = MqttDecode_SubscribeAck(client->rx_buf, packet_len,
                    p_subscribe_ack);
                if (rc <= 0) { return rc; }
                packet_id = p_subscribe_ack->packet_id;
                break;
            }
            case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
            {
                /* Decode unsubscribe ack */
                MqttUnsubscribeAck unsubscribe_ack;
                MqttUnsubscribeAck *p_unsubscribe_ack = &unsubscribe_ack;

                if (p_decode) {
                    p_unsubscribe_ack = (MqttUnsubscribeAck*)p_decode;
                }
                rc = MqttDecode_UnsubscribeAck(client->rx_buf, packet_len,
                    p_unsubscribe_ack);
                if (rc <= 0) { return rc; }
                packet_id = p_unsubscribe_ack->packet_id;
                break;
            }
            case MQTT_PACKET_TYPE_PING_RESP:
                /* Decode ping */
                rc = MqttDecode_Ping(client->rx_buf, packet_len);
                if (rc <= 0) { return rc; }
                break;

            default:
                /* Other types are server side only, ignore */
#ifdef WOLFMQTT_DEBUG_CLIENT
                printf("MqttClient_WaitMessage: Invalid client packet type %u!\n",
                    msg_type);
#endif
                break;
        }

        /* Check for type and packet id */
        if (wait_type < MQTT_PACKET_TYPE_MAX) {
            if (wait_type == msg_type) {
                if (wait_packet_id == 0 || wait_packet_id == packet_id) {
                    /* We found the packet type and id */
                    break;
                }
            }
        }
        else {
            /* We got a message, so return now */
            break;
        }
    }

    return MQTT_CODE_SUCCESS;
}

/* Public Functions */
int MqttClient_Init(MqttClient *client, MqttNet* net,
    MqttMsgCb msg_cb,
    byte* tx_buf, int tx_buf_len,
    byte* rx_buf, int rx_buf_len,
    int cmd_timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;

    /* Check arguments */
    if (client == NULL ||
        tx_buf == NULL || tx_buf_len <= 0 ||
        rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Initialize the client structure to zero */
    XMEMSET(client, 0, sizeof(MqttClient));

    /* Setup client structure */
    client->msg_cb = msg_cb;
    client->flags = 0;
    client->tx_buf = tx_buf;
    client->tx_buf_len = tx_buf_len;
    client->rx_buf = rx_buf;
    client->rx_buf_len = rx_buf_len;
    client->cmd_timeout_ms = cmd_timeout_ms;

    /* Init socket */
    rc = MqttSocket_Init(client, net);

    return rc;
}

int MqttClient_Connect(MqttClient *client, MqttConnect *connect)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL || connect == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the connect packet */
    rc = MqttEncode_Connect(client->tx_buf, client->tx_buf_len, connect);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send connect packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) { return rc; }

    /* Wait for connect ack packet */
    rc = MqttClient_WaitType(client, client->cmd_timeout_ms,
        MQTT_PACKET_TYPE_CONNECT_ACK, 0, &connect->ack);

    return rc;
}

int MqttClient_Publish(MqttClient *client, MqttPublish *publish)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the publish packet */
    rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len, publish);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send packet and payload */
    do {
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }
        publish->buffer_pos += publish->buffer_len;
        publish->buffer_len = 0;

        /* Check if there is anything left to send */
        if (publish->buffer_pos >= publish->total_len) {
            rc = MQTT_CODE_SUCCESS;
            break;
        }

        /* Build packet payload to send */
        len = (publish->total_len - publish->buffer_pos);
        if (len > client->tx_buf_len) {
            len = client->tx_buf_len;
        }
        publish->buffer_len = len;
        XMEMCPY(client->tx_buf, &publish->buffer[publish->buffer_pos], len);
    } while (publish->buffer_pos < publish->total_len);

    /* Handle QoS */
    if (publish->qos > MQTT_QOS_0) {
        /* Determine packet type to wait for */
        MqttPacketType type = (publish->qos == MQTT_QOS_1) ?
            MQTT_PACKET_TYPE_PUBLISH_ACK : MQTT_PACKET_TYPE_PUBLISH_COMP;

        /* Wait for publish response packet */
        rc = MqttClient_WaitType(client, client->cmd_timeout_ms,
            type, publish->packet_id, NULL);
    }

    return rc;
}

int MqttClient_Subscribe(MqttClient *client, MqttSubscribe *subscribe)
{
    int rc, len, i;
    MqttSubscribeAck subscribe_ack;
    MqttTopic* topic;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the subscribe packet */
    rc = MqttEncode_Subscribe(client->tx_buf, client->tx_buf_len, subscribe);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send subscribe packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) { return rc; }

    /* Wait for subscribe ack packet */
    rc = MqttClient_WaitType(client, client->cmd_timeout_ms,
        MQTT_PACKET_TYPE_SUBSCRIBE_ACK, subscribe->packet_id, &subscribe_ack);

    /* Populate return codes */
    if (rc == MQTT_CODE_SUCCESS) {
        for (i = 0; i < subscribe->topic_count; i++) {
            topic = &subscribe->topics[i];
            topic->return_code = subscribe_ack.return_codes[i];
        }
    }

    return rc;
}

int MqttClient_Unsubscribe(MqttClient *client, MqttUnsubscribe *unsubscribe)
{
    int rc, len;
    MqttUnsubscribeAck unsubscribe_ack;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the subscribe packet */
    rc = MqttEncode_Unsubscribe(client->tx_buf, client->tx_buf_len,
        unsubscribe);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send unsubscribe packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) { return rc; }

    /* Wait for unsubscribe ack packet */
    rc = MqttClient_WaitType(client, client->cmd_timeout_ms,
        MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK, unsubscribe->packet_id,
            &unsubscribe_ack);

    return rc;
}

int MqttClient_Ping(MqttClient *client)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the subscribe packet */
    rc = MqttEncode_Ping(client->tx_buf, client->tx_buf_len);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send ping req packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) { return rc; }

    /* Wait for ping resp packet */
    rc = MqttClient_WaitType(client, client->cmd_timeout_ms,
        MQTT_PACKET_TYPE_PING_RESP, 0, NULL);

    return rc;
}

int MqttClient_Disconnect(MqttClient *client)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the disconnect packet */
    rc = MqttEncode_Disconnect(client->tx_buf, client->tx_buf_len);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send disconnect packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) { return rc; }

    /* No response for MQTT disconnect packet */

    return MQTT_CODE_SUCCESS;
}


int MqttClient_WaitMessage(MqttClient *client, int timeout_ms)
{
    return MqttClient_WaitType(client, timeout_ms, MQTT_PACKET_TYPE_MAX, 
        0, NULL);
}

int MqttClient_NetConnect(MqttClient *client, const char* host,
    word16 port, int timeout_ms, int use_tls, MqttTlsCb cb)
{
    return MqttSocket_Connect(client, host, port, timeout_ms, use_tls, cb);
}

int MqttClient_NetDisconnect(MqttClient *client)
{
    return MqttSocket_Disconnect(client);
}

const char* MqttClient_ReturnCodeToString(int return_code)
{
    switch(return_code) {
        case MQTT_CODE_SUCCESS:
            return "Success";
        case MQTT_CODE_ERROR_BAD_ARG:
            return "Error (Bad argument)";
        case MQTT_CODE_ERROR_OUT_OF_BUFFER:
            return "Error (Out of buffer)";
        case MQTT_CODE_ERROR_MALFORMED_DATA:
            return "Error (Malformed Remaining Length)";
        case MQTT_CODE_ERROR_PACKET_TYPE:
            return "Error (Packet Type Mismatch)";
        case MQTT_CODE_ERROR_PACKET_ID:
            return "Error (Packet Id Mismatch)";
        case MQTT_CODE_ERROR_TLS_CONNECT:
            return "Error (TLS Connect)";
        case MQTT_CODE_ERROR_TIMEOUT:
            return "Error (Timeout)";
        case MQTT_CODE_ERROR_NETWORK:
            return "Error (Network)";
    }
    return "Unknown";
}
