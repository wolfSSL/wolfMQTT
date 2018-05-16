/* mqtt_client.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

#include "wolfmqtt/mqtt_client.h"

/* Options */
//#define WOLFMQTT_DEBUG_CLIENT
#ifdef WOLFMQTT_NO_STDIO
    #undef WOLFMQTT_DEBUG_CLIENT
#endif

/* Private functions */
static int MqttClient_HandlePayload(MqttClient* client, MqttMessage* msg,
    int timeout_ms, void* p_decode, word16* packet_id)
{
    int rc = MQTT_CODE_SUCCESS;

    switch (msg->type)
    {
        case MQTT_PACKET_TYPE_CONNECT_ACK:
        {
            /* Decode connect ack */
            MqttConnectAck connect_ack, *p_connect_ack = &connect_ack;
            if (p_decode) {
                p_connect_ack = (MqttConnectAck*)p_decode;
            }
            rc = MqttDecode_ConnectAck(client->rx_buf, client->packet.buf_len,
                                                                p_connect_ack);
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH:
        {
            byte msg_done;

            if (msg->buffer_new) {
                /* Decode publish message */
                rc = MqttDecode_Publish(client->rx_buf, client->packet.buf_len, msg);
                if (rc <= 0) {
                    return rc;
                }
            }

            /* Handle packet callback and read remaining payload */
            do {
                /* Determine if message is done */
                msg_done = ((msg->buffer_pos + msg->buffer_len) >= msg->total_len) ? 1 : 0;

                if (msg->stat != MQTT_MSG_READ_PAYLOAD) {
                    /* Issue callback for new message */
                    if (client->msg_cb) {
                        if (!msg->buffer_new) {
                            /* Reset topic name since valid on new message only */
                            msg->topic_name = NULL;
                            msg->topic_name_len = 0;
                        }
                        /* if using the temp publish message buffer,
                           then populate message context with client context */
                        if (&client->msg == msg)
                            msg->ctx = client->ctx;
                        rc = client->msg_cb(client, msg, msg->buffer_new, msg_done);
                        if (rc != MQTT_CODE_SUCCESS) {
                            return rc;
                        };
                    }
                    msg->buffer_new = 0;
                }

                /* Read payload */
                if (!msg_done) {
                    int msg_len;

                    /* add last length to position and reset len */
                    msg->buffer_pos += msg->buffer_len;
                    msg->buffer_len = 0;

                    /* set state to reading payload */
                    msg->stat = MQTT_MSG_READ_PAYLOAD;

                    msg_len = (msg->total_len - msg->buffer_pos);
                    if (msg_len > client->rx_buf_len) {
                        msg_len = client->rx_buf_len;
                    }

                    /* make sure there is something to read */
                    rc = MQTT_CODE_SUCCESS;
                    if (msg_len > 0) {
                        rc = MqttSocket_Read(client, client->rx_buf, msg_len, timeout_ms);
                        if (rc > 0) {
                            /* make sure state is back to read */
                            msg->stat = MQTT_MSG_READ;

                            /* Update message */
                            msg->buffer = client->rx_buf;
                            msg->buffer_len = rc;
                            rc = MQTT_CODE_SUCCESS;
                        }
                    }
                    if (rc < 0) {
                        return rc;
                    }
                }
            } while (!msg_done);

            /* Handle Qos */
            if (msg->qos > MQTT_QOS_0) {
                MqttPublishResp publish_resp;
                MqttPacketType type;

                *packet_id = msg->packet_id;

                /* Determine packet type to write */
                type = (msg->qos == MQTT_QOS_1) ?
                    MQTT_PACKET_TYPE_PUBLISH_ACK :
                    MQTT_PACKET_TYPE_PUBLISH_REC;
                publish_resp.packet_id = msg->packet_id;

                /* Encode publish response */
                rc = MqttEncode_PublishResp(client->tx_buf,
                                    client->tx_buf_len, type, &publish_resp);
                if (rc <= 0) {
                    return rc;
                }
                client->packet.buf_len = rc;

                /* Send packet */
                msg->stat = MQTT_MSG_BEGIN;
                rc = MqttPacket_Write(client, client->tx_buf,
                                                    client->packet.buf_len);
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
            rc = MqttDecode_PublishResp(client->rx_buf, client->packet.buf_len,
                msg->type, p_publish_resp);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_publish_resp->packet_id;

            /* If Qos then send response */
            if (msg->type == MQTT_PACKET_TYPE_PUBLISH_REC ||
                msg->type == MQTT_PACKET_TYPE_PUBLISH_REL) {

                /* Encode publish response */
                publish_resp.packet_id = p_publish_resp->packet_id;
                rc = MqttEncode_PublishResp(client->tx_buf,
                    client->tx_buf_len, msg->type+1, &publish_resp);
                if (rc <= 0) {
                    return rc;
                }
                client->packet.buf_len = rc;

                /* Send packet */
                msg->stat = MQTT_MSG_BEGIN;
                rc = MqttPacket_Write(client, client->tx_buf, client->packet.buf_len);
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
            rc = MqttDecode_SubscribeAck(client->rx_buf, client->packet.buf_len,
                p_subscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_subscribe_ack->packet_id;
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
            rc = MqttDecode_UnsubscribeAck(client->rx_buf, client->packet.buf_len,
                p_unsubscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_unsubscribe_ack->packet_id;
            break;
        }
        case MQTT_PACKET_TYPE_PING_RESP:
        {
            /* Decode ping */
            rc = MqttDecode_Ping(client->rx_buf, client->packet.buf_len);
            break;
        }
        default:
        {
            /* Other types are server side only, ignore */
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_WaitMessage: Invalid client packet type %u!",
                msg->type);
        #endif
            break;
        }
    } /* switch (msg->type) */

    return rc;
}

static int MqttClient_WaitType(MqttClient *client, MqttMessage* msg,
    int timeout_ms, byte wait_type, word16 wait_packet_id, void* p_decode)
{
    int rc;
    word16 packet_id = 0;

wait_again:

    switch (msg->stat)
    {
        case MQTT_MSG_BEGIN:
        {
            /* reset the packet state */
            client->packet.stat = MQTT_PK_BEGIN;

            FALL_THROUGH;
        }
        case MQTT_MSG_WAIT:
        {
            MqttPacket* header;

            /* Wait for packet */
            rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len, timeout_ms);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE && client->read.pos > 0) {
                /* advance state, so we don't reset packet state */
                msg->stat = MQTT_MSG_WAIT;
            }
        #endif
            if (rc <= 0) {
                return rc;
            }

            msg->stat = MQTT_MSG_WAIT;
            client->packet.buf_len = rc;

            /* Determine packet type */
            header = (MqttPacket*)client->rx_buf;
            msg->type = MQTT_PACKET_TYPE_GET(header->type_flags);
            msg->qos = (MqttQoS)MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);
            msg->buffer_new = 1;

        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Read Packet: Len %d, Type %d, Qos %d",
                client->packet.buf_len, msg->type, msg->qos);
        #endif

            msg->stat = MQTT_MSG_READ;

            FALL_THROUGH;
        }

        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        {
            rc = MqttClient_HandlePayload(client, msg, timeout_ms, p_decode,
                                                                &packet_id);
            if (rc < 0) {
                return rc;
            }
            rc = MQTT_CODE_SUCCESS;

            /* Check for type and packet id */
            if (wait_type < MQTT_PACKET_TYPE_MAX) {
                if (wait_type == msg->type) {
                    if (wait_packet_id == 0 || wait_packet_id == packet_id) {
                        /* We found the packet type and id */
                        break;
                    }
                }

                msg->stat = MQTT_MSG_BEGIN;
                goto wait_again;
            }
            break;
        }

        case MQTT_MSG_WRITE:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_WaitType: Invalid state %d!",
                msg->stat);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
        }
    } /* switch (msg->stat) */

    /* reset state */
    msg->stat = MQTT_MSG_BEGIN;

    return rc;
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
    client->tx_buf = tx_buf;
    client->tx_buf_len = tx_buf_len;
    client->rx_buf = rx_buf;
    client->rx_buf_len = rx_buf_len;
    client->cmd_timeout_ms = cmd_timeout_ms;

    /* Init socket */
    rc = MqttSocket_Init(client, net);

    return rc;
}

#ifdef WOLFMQTT_DISCONNECT_CB
int MqttClient_SetDisconnectCallback(MqttClient *client, MqttDisconnectCb cb,
    void* ctx)
{
    if (client == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

    client->disconnect_cb = cb;
    client->disconnect_ctx = ctx;

    return MQTT_CODE_SUCCESS;
}
#endif

int MqttClient_Connect(MqttClient *client, MqttConnect *connect)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL || connect == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (connect->stat == MQTT_MSG_BEGIN) {

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
        connect->stat = MQTT_MSG_WAIT;
    }

    /* Wait for connect ack packet */
    rc = MqttClient_WaitType(client, &client->msg, client->cmd_timeout_ms,
        MQTT_PACKET_TYPE_CONNECT_ACK, 0, &connect->ack);

    return rc;
}

int MqttClient_Publish(MqttClient *client, MqttPublish *publish)
{
    int rc = MQTT_CODE_SUCCESS;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    switch (publish->stat)
    {
        case MQTT_MSG_BEGIN:
        {
            /* Encode the publish packet */
            rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len, publish);
            if (rc <= 0) {
                return rc;
            }

            client->write.len = rc;

            FALL_THROUGH;
        }

        case MQTT_MSG_WRITE:
        {
            publish->stat = MQTT_MSG_WRITE;

            /* Send packet and payload */
            do {
                rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
                if (rc < 0) {
                    return rc;
                }

                publish->buffer_pos += publish->buffer_len;
                publish->buffer_len = 0;

                /* Check if we are done sending publish message */
                if (publish->buffer_pos >= publish->total_len) {
                    rc = MQTT_CODE_SUCCESS;
                    break;
                }

                /* Build packet payload to send */
                client->write.len = (publish->total_len - publish->buffer_pos);
                if (client->write.len > client->tx_buf_len) {
                    client->write.len = client->tx_buf_len;
                }
                publish->buffer_len = client->write.len;
                XMEMCPY(client->tx_buf, &publish->buffer[publish->buffer_pos],
                    client->write.len);

            #ifdef WOLFMQTT_NONBLOCK
                return MQTT_CODE_CONTINUE;
            #endif

            } while (publish->buffer_pos < publish->total_len);

            /* if not expecting a reply, the reset state and exit */
            if (publish->qos == MQTT_QOS_0) {
                publish->stat = MQTT_MSG_BEGIN;
                break;
            }

            FALL_THROUGH;
        }

        case MQTT_MSG_WAIT:
        {
            publish->stat = MQTT_MSG_WAIT;

            /* Handle QoS */
            if (publish->qos > MQTT_QOS_0) {
                /* Determine packet type to wait for */
                MqttPacketType type = (publish->qos == MQTT_QOS_1) ?
                    MQTT_PACKET_TYPE_PUBLISH_ACK : MQTT_PACKET_TYPE_PUBLISH_COMP;

                /* Wait for publish response packet */
                rc = MqttClient_WaitType(client, &client->msg,
                    client->cmd_timeout_ms, type, publish->packet_id, NULL);
            }

            break;
        }

        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_Publish: Invalid state %d!",
                publish->stat);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
    } /* switch (publish->stat) */

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

    if (subscribe->stat == MQTT_MSG_BEGIN) {
        /* Encode the subscribe packet */
        rc = MqttEncode_Subscribe(client->tx_buf, client->tx_buf_len, subscribe);
        if (rc <= 0) { return rc; }
        len = rc;

        /* Send subscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }

        subscribe->stat = MQTT_MSG_WAIT;
    }

    /* Wait for subscribe ack packet */
    rc = MqttClient_WaitType(client, &client->msg, client->cmd_timeout_ms,
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

    if (unsubscribe->stat == MQTT_MSG_BEGIN) {
        /* Encode the subscribe packet */
        rc = MqttEncode_Unsubscribe(client->tx_buf, client->tx_buf_len,
            unsubscribe);
        if (rc <= 0) { return rc; }
        len = rc;

        /* Send unsubscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }

        unsubscribe->stat = MQTT_MSG_WAIT;
    }

    /* Wait for unsubscribe ack packet */
    rc = MqttClient_WaitType(client, &client->msg, client->cmd_timeout_ms,
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

    if (client->msg.stat == MQTT_MSG_BEGIN) {
        /* Encode the subscribe packet */
        rc = MqttEncode_Ping(client->tx_buf, client->tx_buf_len);
        if (rc <= 0) { return rc; }
        len = rc;

        /* Send ping req packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }

        client->msg.stat = MQTT_MSG_WAIT;
    }

    /* Wait for ping resp packet */
    rc = MqttClient_WaitType(client, &client->msg, client->cmd_timeout_ms,
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
    return MqttClient_WaitType(client, &client->msg, timeout_ms,
        MQTT_PACKET_TYPE_MAX, 0, NULL);
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

#ifndef WOLFMQTT_NO_ERROR_STRINGS
const char* MqttClient_ReturnCodeToString(int return_code)
{
    switch(return_code) {
        case MQTT_CODE_SUCCESS:
            return "Success";
        case MQTT_CODE_CONTINUE:
            return "Continue"; /* would block */
        case MQTT_CODE_STDIN_WAKE:
            return "STDIN Wake";
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
        case MQTT_CODE_ERROR_MEMORY:
            return "Error (Memory)";
        case MQTT_CODE_ERROR_STAT:
            return "Error (State)";
    }
    return "Unknown";
}
#endif /* !WOLFMQTT_NO_ERROR_STRINGS */

