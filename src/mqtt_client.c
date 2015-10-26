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


int MqttClient_Init(MqttClient *client, MqttNet* net,
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
    client->flags = 0;
    client->tx_buf = tx_buf;
    client->tx_buf_len = tx_buf_len;
    client->rx_buf = rx_buf;
    client->rx_buf_len = rx_buf_len;
    client->cmd_timeout_ms = cmd_timeout_ms;

    /* Init socket specific items */
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
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Send connect packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) {
        return rc;
    }

    /* Wait for connect ack packet */
    rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, client->cmd_timeout_ms);
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Decode connect ack */
    rc = MqttDecode_ConenctAck(client->rx_buf, len, &connect->ack);
    if (rc <= 0) {
        return rc;
    }

    return MQTT_CODE_SUCCESS;
}

int MqttClient_Publish(MqttClient *client, MqttPublish *publish)
{
    int rc, len, qos;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the publish packet */
    rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len, publish);
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Send publish packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) {
        return rc;
    }

    /* Handle QoS */
    for (qos = MQTT_QOS_0; qos < (int)publish->qos; qos++) {
        MqttPublishResp publish_resp;
        MqttPacketType type;

        /* Determine packet type to read */
        type = (publish->qos == MQTT_QOS_1) ? MQTT_PACKET_TYPE_PUBLISH_ACK :
            (qos == MQTT_QOS_0) ? MQTT_PACKET_TYPE_PUBLISH_REC : MQTT_PACKET_TYPE_PUBLISH_COMP;
        publish_resp.packet_id = 0;

        /* Wait for publish response packet */
        rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, client->cmd_timeout_ms);
        if (rc <= 0) {
            return rc;
        }
        len = rc;

        /* Decode publish response */
        rc = MqttDecode_PublishResp(client->rx_buf, len, type, &publish_resp);

        /* Validate Packet Id */
        if (publish->packet_id != publish_resp.packet_id) {
            printf("Publish Packet Id Mismatch %u != %u\n",
                publish->packet_id, publish_resp.packet_id);
            return MQTT_CODE_ERROR_PACKET_ID;
        }

        /* For QOS2 send PUBLISH_REL and wait for PUBLISH_COMP */
        if (qos == MQTT_QOS_0 && publish->qos == MQTT_QOS_2) {
            /* Encode the publish rel packet */
            rc = MqttEncode_PublishResp(client->tx_buf, client->tx_buf_len,
                MQTT_PACKET_TYPE_PUBLISH_REL, &publish_resp);
            if (rc <= 0) {
                return rc;
            }
            len = rc;

            /* Send packet */
            rc = MqttPacket_Write(client, client->tx_buf, len);
            if (rc != len) {
                return rc;
            }
        }
    }

    return MQTT_CODE_SUCCESS;
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
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Send subscribe packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) {
        return rc;
    }

    /* Wait for subscribe ack packet */
    rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, client->cmd_timeout_ms);
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Decode subscribe ack */
    rc = MqttDecode_SubscribeAck(client->rx_buf, len, &subscribe_ack);
    if (rc <= 0) {
        return 0;
    }

    /* Populate return codes */
    for (i = 0; i < subscribe->topic_count; i++) {
        topic = &subscribe->topics[i];
        topic->return_code = subscribe_ack.return_codes[i];
    }

    /* Validate Packet Id */
    if (subscribe->packet_id != subscribe_ack.packet_id) {
        printf("Subscribe Packet Id Mismatch %u != %u\n",
            subscribe->packet_id, subscribe_ack.packet_id);
        return MQTT_CODE_ERROR_PACKET_ID;
    }

    return MQTT_CODE_SUCCESS;
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
    rc = MqttEncode_Unsubscribe(client->tx_buf, client->tx_buf_len, unsubscribe);
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Send unsubscribe packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) {
        return rc;
    }

    /* Wait for subscribe ack packet */
    rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, client->cmd_timeout_ms);
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Decode unsubscribe ack */
    rc = MqttDecode_UnsubscribeAck(client->rx_buf, len, &unsubscribe_ack);
    if (rc <= 0) {
        return 0;
    }

    /* Validate Packet Id */
    if (unsubscribe->packet_id != unsubscribe_ack.packet_id) {
        printf("Unsubscribe Packet Id Mismatch %u != %u\n",
            unsubscribe->packet_id, unsubscribe_ack.packet_id);
        return MQTT_CODE_ERROR_PACKET_ID;
    }

    return MQTT_CODE_SUCCESS;
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
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Send ping req packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) {
        return rc;
    }

    /* Wait for ping resp packet */
    rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, client->cmd_timeout_ms);
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Decode subscribe ack */
    rc = MqttDecode_Ping(client->rx_buf, len);
    if (rc <= 0) {
        return 0;
    }

    return MQTT_CODE_SUCCESS;
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
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Send disconnect packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) {
        return rc;
    }

    /* No response for MQTT disconnect packet */

    return MQTT_CODE_SUCCESS;
}

int MqttClient_WaitMessage(MqttClient *client, MqttMessage *message,
    int timeout_ms)
{
    int rc, len;
    MqttPacket* header;
    byte msg_type, msg_qos, qos;

    /* Wait for packet */
    rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, timeout_ms);
    if (rc <= 0) {
        return rc;
    }
    len = rc;

    /* Determine packet type */
    header = (MqttPacket*)client->rx_buf;
    msg_type = MQTT_PACKET_TYPE_GET(header->type_flags);
    msg_qos = MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);

    switch(msg_type) {
        case MQTT_PACKET_TYPE_PUBLISH:
        {
            /* Decode publish message */
            rc = MqttDecode_Publish(client->rx_buf, len, message);

            /* Handle Qos */
            for (qos = MQTT_QOS_0; qos < msg_qos; qos++) {
                MqttPublishResp publish_resp;
                MqttPacketType type;

                /* Determine packet type to write */
                type = (msg_qos == MQTT_QOS_1) ? MQTT_PACKET_TYPE_PUBLISH_ACK :
                    (qos == MQTT_QOS_0) ? MQTT_PACKET_TYPE_PUBLISH_REC : MQTT_PACKET_TYPE_PUBLISH_COMP;
                publish_resp.packet_id = message->packet_id;

                /* Encode publish response */
                rc = MqttEncode_PublishResp(client->tx_buf, client->tx_buf_len, type, &publish_resp);
                if (rc <= 0) {
                    return rc;
                }
                len = rc;

                /* Send packet */
                rc = MqttPacket_Write(client, client->tx_buf, len);
                if (rc != len) {
                    return rc;
                }

                /* For QOS2 wait for PUBLISH_REL */
                if (qos == MQTT_QOS_0 && msg_qos == MQTT_QOS_2) {
                    /* Wait for publish release packet */
                    rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, client->cmd_timeout_ms);
                    if (rc <= 0) {
                        return 0;
                    }
                    len = rc;

                    /* Decode publish release */
                    rc = MqttDecode_PublishResp(client->rx_buf, len, MQTT_PACKET_TYPE_PUBLISH_REL, &publish_resp);
                    if (rc <= 0) {
                        return rc;
                    }

                    /* Validate Packet Id */
                    if (message->packet_id != publish_resp.packet_id) {
                        printf("Publish Packet Id Mismatch %u != %u\n",
                            message->packet_id, publish_resp.packet_id);
                        return MQTT_CODE_ERROR_PACKET_ID;
                    }
                }
            }

            break;
        }
        case MQTT_PACKET_TYPE_CONNECT_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
        case MQTT_PACKET_TYPE_PING_RESP:
            printf("MqttClient_WaitMessage: Unhandled type %u!\n", msg_type);
            return MQTT_CODE_ERROR_PACKET_TYPE;
        default:
            /* Other types are server side only */
            printf("MqttClient_WaitMessage: Unhandled server type %u!\n", msg_type);
            return MQTT_CODE_ERROR_PACKET_TYPE;
    }

    return MQTT_CODE_SUCCESS;
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
    }
    return "Unknown";
}
