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
#ifdef WOLFMQTT_V5
            p_connect_ack->props = NULL;
#endif
            rc = MqttDecode_ConnectAck(client->rx_buf, client->packet.buf_len,
                                                                p_connect_ack);
            if (rc > 0) {
#ifdef WOLFMQTT_PROPERTY_CB
                /* Check for properties set by the server */
                if (client->property_cb) {
                    rc = client->property_cb(client, p_connect_ack->props,
                            NULL);
                }
#endif
#ifdef WOLFMQTT_V5
                /* Free the properties */
                MqttProps_Free(p_connect_ack->props);
#endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH:
        {
            byte msg_done;

            if (msg->buffer_new) {
#ifdef WOLFMQTT_V5
                msg->props = NULL;
#endif
                /* Decode publish message */
                rc = MqttDecode_Publish(client->rx_buf, client->packet.buf_len,
                       msg);
                if (rc <= 0) {
                    return rc;
                }
#ifdef WOLFMQTT_PROPERTY_CB
                /* Check for properties set by the server */
                if (client->property_cb) {
                    rc = client->property_cb(client, msg->props,
                            NULL);
                }
#endif
#ifdef WOLFMQTT_V5
                /* Free the properties */
                MqttProps_Free(msg->props);
#endif
            }

            /* Handle packet callback and read remaining payload */
            do {
                /* Determine if message is done */
                msg_done = ((msg->buffer_pos + msg->buffer_len) >=
                            msg->total_len) ? 1 : 0;

                if (msg->stat != MQTT_MSG_READ_PAYLOAD) {
                    /* Issue callback for new message */
                    if (client->msg_cb) {
                        if (!msg->buffer_new) {
                            /* Reset topic name since valid
                               on new message only */
                            msg->topic_name = NULL;
                            msg->topic_name_len = 0;
                        }
                        /* if using the temp publish message buffer,
                           then populate message context with client context */
                        if (&client->msg == msg)
                            msg->ctx = client->ctx;
                        rc = client->msg_cb(client, msg, msg->buffer_new,
                                msg_done);
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
                        rc = MqttSocket_Read(client, client->rx_buf, msg_len,
                                timeout_ms);
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
#ifdef WOLFMQTT_V5
            p_publish_resp->props = NULL;
#endif
            /* Decode publish response message */
            rc = MqttDecode_PublishResp(client->rx_buf, client->packet.buf_len,
                msg->type, p_publish_resp);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_publish_resp->packet_id;

#ifdef WOLFMQTT_PROPERTY_CB
            /* Check for properties set by the server */
            if (client->property_cb) {
                rc = client->property_cb(client, p_publish_resp->props,
                        NULL);
            }
#endif
#ifdef WOLFMQTT_V5
            /* Free the properties */
            MqttProps_Free(p_publish_resp->props);
#endif

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
                rc = MqttPacket_Write(client, client->tx_buf,
                        client->packet.buf_len);
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
#ifdef WOLFMQTT_V5
            p_subscribe_ack->props = NULL;
#endif
            rc = MqttDecode_SubscribeAck(client->rx_buf, client->packet.buf_len,
                p_subscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_subscribe_ack->packet_id;

#ifdef WOLFMQTT_PROPERTY_CB
            /* Check for properties set by the server */
            if (client->property_cb) {
                rc = client->property_cb(client, p_subscribe_ack->props,
                        NULL);
            }
#endif
#ifdef WOLFMQTT_V5
            /* Free the properties */
            MqttProps_Free(p_subscribe_ack->props);
#endif

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
#ifdef WOLFMQTT_V5
            p_unsubscribe_ack->props = NULL;
#endif
            rc = MqttDecode_UnsubscribeAck(client->rx_buf,
                    client->packet.buf_len, p_unsubscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_unsubscribe_ack->packet_id;

#ifdef WOLFMQTT_PROPERTY_CB
            /* Check for properties set by the server */
            if (client->property_cb) {
                rc = client->property_cb(client, p_unsubscribe_ack->props,
                        NULL);
            }
#endif
#ifdef WOLFMQTT_V5
            /* Free the properties */
            MqttProps_Free(p_unsubscribe_ack->props);
#endif
            break;
        }
        case MQTT_PACKET_TYPE_PING_RESP:
        {
            /* Decode ping */
            rc = MqttDecode_Ping(client->rx_buf, client->packet.buf_len);
            break;
        }
#ifdef WOLFMQTT_V5
        case MQTT_PACKET_TYPE_AUTH:
        {
            MqttAuth auth, *p_auth = &auth;

            p_auth->props = NULL;
            /* Decode authorization */
            rc = MqttDecode_Auth(client->rx_buf, client->packet.buf_len,
                    p_auth);

            if (rc > 0) {
#ifdef WOLFMQTT_PROPERTY_CB
                /* Check for properties set by the server */
                if (client->property_cb) {
                    rc = client->property_cb(client, p_auth->props,
                            NULL);
                }
#endif
                /* Free the properties */
                MqttProps_Free(p_auth->props);
            }

            break;
        }

        case MQTT_PACKET_TYPE_DISCONNECT:
        {
            MqttDisconnect disc, *p_disc = &disc;

            p_disc->props = NULL;

            /* Decode disconnect */
            rc = MqttDecode_Disconnect(client->rx_buf, client->packet.buf_len,
                    p_disc);
            if (rc > 0) {
#ifdef WOLFMQTT_PROPERTY_CB
                /* Check for properties set by the server */
                if (client->property_cb) {
                    rc = client->property_cb(client, p_disc->props,
                            NULL);
                }
#endif
                /* Free the properties */
                MqttProps_Free(p_disc->props);
            }

            break;
        }
#endif
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
    #ifdef WOLFMQTT_V5
        case MQTT_MSG_AUTH:
    #endif
        case MQTT_MSG_WAIT:
        {
            MqttPacket* header;

            /* Wait for packet */
            rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len,
                    timeout_ms);
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
            if (wait_type < MQTT_PACKET_TYPE_ANY) {
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
#ifdef WOLFMQTT_V5
    client->max_qos = MQTT_QOS_2;
    client->retain_avail = 1;
#endif

    /* Init socket */
    rc = MqttSocket_Init(client, net);

    return rc;
}

#ifdef WOLFMQTT_DISCONNECT_CB
int MqttClient_SetDisconnectCallback(MqttClient *client,
        MqttDisconnectCb discCb, void* ctx)
{
    if (client == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

    client->disconnect_cb = discCb;
    client->disconnect_ctx = ctx;

    return MQTT_CODE_SUCCESS;
}
#endif

#ifdef WOLFMQTT_PROPERTY_CB
int MqttClient_SetPropertyCallback(MqttClient *client, MqttPropertyCb propCb,
    void* ctx)
{
    if (client == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

    client->property_cb = propCb;
    client->property_ctx = ctx;

    return MQTT_CODE_SUCCESS;
}
#endif

int MqttClient_Connect(MqttClient *client, MqttConnect *connect)
{
    int rc, len = 0;

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
    #ifdef WOLFMQTT_V5
        /* Enhanced authentication */
        if (client->enable_eauth == 1) {
            connect->stat = MQTT_MSG_AUTH;
        }
        else
    #endif
        {
            connect->stat = MQTT_MSG_WAIT;
        }
    }

#ifdef WOLFMQTT_V5
    /* Enhanced authentication */
    if (connect->stat == MQTT_MSG_AUTH) {
        MqttAuth auth, *p_auth = &auth;
        MqttProp* prop, *conn_prop;

        /* Find the AUTH property in the connect structure */
        for (conn_prop = connect->props;
             (conn_prop != NULL) && (conn_prop->type != MQTT_PROP_AUTH_METHOD);
             conn_prop = conn_prop->next);

        if (conn_prop == NULL) {
            /* AUTH property was not set in connect structure */
            return MQTT_CODE_ERROR_BAD_ARG;
        }

        XMEMSET((void*)p_auth, 0, sizeof(MqttAuth));

        /* Set the authentication reason */
        p_auth->reason_code = MQTT_REASON_CONT_AUTH;

        /* Use the same authentication method property from connect */
        prop = MqttProps_Add(&p_auth->props);
        prop->type = MQTT_PROP_AUTH_METHOD;
        prop->data_str.str = conn_prop->data_str.str;
        prop->data_str.len = conn_prop->data_str.len;

        /* Send the AUTH packet */
        rc = MqttClient_Auth(client, p_auth);
        if (rc != len) {
            return rc;
        }

        MqttClient_PropsFree(p_auth->props);
    }
#endif

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

#ifdef WOLFMQTT_V5
    /* Validate publish request against server properties */
    if ((publish->qos > client->max_qos) ||
        ((publish->retain == 1) && (client->retain_avail == 0)))
    {
        return MQTT_CODE_ERROR_SERVER_PROP;
    }
#endif

    switch (publish->stat)
    {
        case MQTT_MSG_BEGIN:
        {
            /* Encode the publish packet */
            rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len,
                    publish, 0);
            if (rc <= 0) {
                return rc;
            }

            client->write.len = rc;
            publish->buffer_pos = 0;

            /* Backwards compatibility for chunk transfers */
            if (publish->buffer_len == 0) {
                publish->buffer_len = publish->total_len;
            }

            FALL_THROUGH;
        }
        case MQTT_MSG_WRITE:
        {
            publish->stat = MQTT_MSG_WRITE;

            if (publish->buffer_pos > 0) {
                XMEMCPY(client->tx_buf, publish->buffer,
                    client->write.len);
            }
            /* Send packet and payload */
            do {
                rc = MqttPacket_Write(client, client->tx_buf,
                        client->write.len);
                if (rc < 0) {
                    return rc;
                }

                publish->intBuf_pos += publish->intBuf_len;
                publish->intBuf_len = 0;

                /* Check if we are done sending publish message */
                if (publish->intBuf_pos >= publish->buffer_len) {
                    rc = MQTT_CODE_SUCCESS;
                    break;
                }

                /* Build packet payload to send */
                client->write.len = (publish->buffer_len - publish->intBuf_pos);
                if (client->write.len > client->tx_buf_len) {
                    client->write.len = client->tx_buf_len;
                }
                publish->intBuf_len = client->write.len;
                XMEMCPY(client->tx_buf, &publish->buffer[publish->intBuf_pos],
                    client->write.len);

            #ifdef WOLFMQTT_NONBLOCK
                return MQTT_CODE_CONTINUE;
            #endif

            } while (publish->intBuf_pos < publish->buffer_len);

            /* If transferring more chunks */
            publish->buffer_pos += publish->intBuf_pos;
            if (publish->buffer_pos < publish->total_len) {
                /* Build next payload to send */
                client->write.len = (publish->total_len - publish->buffer_pos);
                if (client->write.len > client->tx_buf_len) {
                    client->write.len = client->tx_buf_len;
                }
                return MQTT_CODE_CONTINUE;
            }
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
                    MQTT_PACKET_TYPE_PUBLISH_ACK :
                    MQTT_PACKET_TYPE_PUBLISH_COMP;

                /* Wait for publish response packet */
                rc = MqttClient_WaitType(client, &client->msg,
                    client->cmd_timeout_ms, type, publish->packet_id, NULL);
            }

            break;
        }

    #ifdef WOLFMQTT_V5
        case MQTT_MSG_AUTH:
    #endif
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

int MqttClient_Publish_ex(MqttClient *client, MqttPublish *publish,
                            MqttPublishCb pubCb)
{
    int rc = MQTT_CODE_SUCCESS;

    /* Validate required arguments */
    if (client == NULL || publish == NULL || pubCb == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_V5
    /* Validate publish request against server properties */
    if ((publish->qos > client->max_qos) ||
        ((publish->retain == 1) && (client->retain_avail == 0)))
    {
        return MQTT_CODE_ERROR_SERVER_PROP;
    }
#endif

    switch (publish->stat)
    {
        case MQTT_MSG_BEGIN:
        {
            /* Encode the publish packet */
            rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len,
                    publish, 1);
            if (rc <= 0) {
                return rc;
            }

            client->write.len = rc;

            /* Send packet */
            rc = MqttPacket_Write(client, client->tx_buf,
                    client->write.len);
            if (rc < 0) {
                return rc;
            }
            publish->buffer_pos = 0;

            FALL_THROUGH;
        }
        case MQTT_MSG_WRITE:
        {
            word32 tmp_len = publish->buffer_len;
            publish->stat = MQTT_MSG_WRITE;

            do {
                /* Use the callback to get payload */
                if ((client->write.len = pubCb(publish)) < 0) {
                    return MQTT_CODE_ERROR_CALLBACK;
                }

                if ((word32)client->write.len < publish->buffer_len) {
                    /* Last read */
                    tmp_len = (word32)client->write.len;
                }

                /* Send payload */
                do {
                    if (client->write.len > client->tx_buf_len) {
                        client->write.len = client->tx_buf_len;
                    }
                    publish->intBuf_len = client->write.len;
                    XMEMCPY(client->tx_buf, &publish->buffer[publish->intBuf_pos],
                        client->write.len);

                    rc = MqttPacket_Write(client, client->tx_buf,
                            client->write.len);
                    if (rc < 0) {
                        return rc;
                    }

                    publish->intBuf_pos += publish->intBuf_len;
                    publish->intBuf_len = 0;

                } while (publish->intBuf_pos < tmp_len);

                publish->buffer_pos += publish->intBuf_pos;
                publish->intBuf_pos = 0;

            } while (publish->buffer_pos < publish->total_len);

            /* if not expecting a reply, the reset state and exit */
            if (publish->qos == MQTT_QOS_0) {
                publish->stat = MQTT_MSG_BEGIN;
                if (rc > 0) {
                    rc = MQTT_CODE_SUCCESS;
                }
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
                    MQTT_PACKET_TYPE_PUBLISH_ACK :
                    MQTT_PACKET_TYPE_PUBLISH_COMP;

                /* Wait for publish response packet */
                rc = MqttClient_WaitType(client, &client->msg,
                    client->cmd_timeout_ms, type, publish->packet_id, NULL);
            }

            break;
        }

    #ifdef WOLFMQTT_V5
        case MQTT_MSG_AUTH:
    #endif
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
        rc = MqttEncode_Subscribe(client->tx_buf, client->tx_buf_len,
                subscribe);
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

#ifdef WOLFMQTT_V5
    if (unsubscribe_ack.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(unsubscribe_ack.props);
    }
#endif

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
    return MqttClient_Disconnect_ex(client, NULL);
}

int MqttClient_Disconnect_ex(MqttClient *client, MqttDisconnect *disconnect)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the disconnect packet */
    rc = MqttEncode_Disconnect(client->tx_buf, client->tx_buf_len, disconnect);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send disconnect packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) { return rc; }

    /* No response for MQTT disconnect packet */

    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_V5
int MqttClient_Auth(MqttClient *client, MqttAuth* auth)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (client->msg.stat == MQTT_MSG_BEGIN) {
        /* Encode the authentication packet */
        rc = MqttEncode_Auth(client->tx_buf, client->tx_buf_len, auth);
        if (rc <= 0) { return rc; }
        len = rc;

        /* Send authentication packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }

        client->msg.stat = MQTT_MSG_WAIT;
    }

    /* Wait for auth packet */
    rc = MqttClient_WaitType(client, &client->msg, client->cmd_timeout_ms,
        MQTT_PACKET_TYPE_AUTH, 0, NULL);

    return rc;
}

MqttProp* MqttClient_PropsAdd(MqttProp **head)
{
    return MqttProps_Add(head);
}

void MqttClient_PropsFree(MqttProp *head)
{
    MqttProps_Free(head);
}

#endif /* WOLFMQTT_V5 */

int MqttClient_WaitMessage(MqttClient *client, int timeout_ms)
{
    return MqttClient_WaitType(client, &client->msg, timeout_ms,
        MQTT_PACKET_TYPE_ANY, 0, NULL);
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
        case MQTT_CODE_ERROR_PROPERTY:
            return "Error (Property)";
        case MQTT_CODE_ERROR_SERVER_PROP:
            return "Error (Server Property)";
        case MQTT_CODE_ERROR_CALLBACK:
            return "Error (Error in Callback)";

    }
    return "Unknown";
}
#endif /* !WOLFMQTT_NO_ERROR_STRINGS */

#ifdef WOLFMQTT_SN

/* Private functions */
static int SN_Client_HandlePayload(MqttClient* client, MqttMessage* msg,
    int timeout, void* p_decode, word16* packet_id)
{
    int rc = MQTT_CODE_SUCCESS;
    (void)timeout;

    switch (msg->type)
    {
        case SN_MSG_TYPE_GWINFO:
        {
            SN_GwInfo info, *p_info = &info;
            rc = SN_Decode_GWInfo(client->rx_buf, client->packet.buf_len, p_info);
            if (rc <= 0) {
                return rc;
            }
            break;
        }
        case SN_MSG_TYPE_CONNACK:
        {
            /* Decode connect ack */
            SN_ConnectAck connect_ack, *p_connect_ack = &connect_ack;
            if (p_decode) {
                p_connect_ack = (SN_ConnectAck*)p_decode;
            }
            p_connect_ack->return_code = client->rx_buf[client->packet.buf_len-1];

            break;
        }
        case SN_MSG_TYPE_REGACK:
        {
            /* Decode register ack */
            SN_RegAck regack_s, *regack = &regack_s;
            if (p_decode) {
                regack = (SN_RegAck*)p_decode;
            }

            rc = SN_Decode_RegAck(client->rx_buf, client->packet.buf_len, regack);

            if (rc > 0) {
                *packet_id = regack->packet_id;
            }

            break;
        }
        case SN_MSG_TYPE_PUBLISH:
        {
            /* Decode publish message */
            rc = SN_Decode_Publish(client->rx_buf, client->packet.buf_len,
                   msg);
            if (rc <= 0) {
                return rc;
            }

            /* Issue callback for new message */
            if (client->msg_cb) {
                /* if using the temp publish message buffer,
                   then populate message context with client context */
                if (&client->msg == msg)
                    msg->ctx = client->ctx;
                rc = client->msg_cb(client, msg, 1, 1);
                if (rc != MQTT_CODE_SUCCESS) {
                    return rc;
                };
            }

            /* Handle Qos */
            if (msg->qos > MQTT_QOS_0) {
                SN_PublishResp publish_resp;
                SN_MsgType type;

                *packet_id = msg->packet_id;

                /* Determine packet type to write */
                type = (msg->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBREC;
                publish_resp.packet_id = msg->packet_id;

                /* Encode publish response */
                rc = SN_Encode_PublishResp(client->tx_buf,
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
        case SN_MSG_TYPE_PUBACK:
        case SN_MSG_TYPE_PUBCOMP:
        case SN_MSG_TYPE_PUBREC:
        case SN_MSG_TYPE_PUBREL:
        {
            SN_PublishResp publish_resp, *p_publish_resp = &publish_resp;
            if (p_decode) {
                p_publish_resp = (SN_PublishResp*)p_decode;
            }
            else
            {
                XMEMSET(p_publish_resp, 0, sizeof(SN_PublishResp));
            }
            /* Decode publish response message */
            rc = SN_Decode_PublishResp(client->rx_buf, client->packet.buf_len,
                msg->type, p_publish_resp);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_publish_resp->packet_id;

            /* If Qos then send response */
            if (msg->type == SN_MSG_TYPE_PUBREC ||
                msg->type == SN_MSG_TYPE_PUBREL) {

                /* Encode publish response */
                publish_resp.packet_id = p_publish_resp->packet_id;
                rc = SN_Encode_PublishResp(client->tx_buf,
                    client->tx_buf_len, msg->type+1, &publish_resp);
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
        case SN_MSG_TYPE_SUBACK:
        {
            /* Decode subscribe ack */
            SN_SubAck subscribe_ack, *p_subscribe_ack = &subscribe_ack;
            if (p_decode) {
                p_subscribe_ack = (SN_SubAck*)p_decode;
            }
            else {
                XMEMSET(p_subscribe_ack, 0, sizeof(SN_SubAck));
            }

            rc = SN_Decode_SubscribeAck(client->rx_buf, client->packet.buf_len,
                    p_subscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_subscribe_ack->packet_id;

            break;
        }
        case SN_MSG_TYPE_UNSUBACK:
        {
            /* Decode unsubscribe ack */
            SN_UnsubscribeAck unsubscribe_ack;
            SN_UnsubscribeAck *p_unsubscribe_ack = &unsubscribe_ack;

            if (p_decode) {
                p_unsubscribe_ack = (SN_UnsubscribeAck*)p_decode;
            }
            rc = SN_Decode_UnsubscribeAck(client->rx_buf,
                    client->packet.buf_len, p_unsubscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            *packet_id = p_unsubscribe_ack->packet_id;

            break;
        }
        case SN_MSG_TYPE_PING_RESP:
        {
            /* Decode ping */
            rc = SN_Decode_Ping(client->rx_buf, client->packet.buf_len);
            break;
        }
        default:
        {
            /* Other types are server side only, ignore */
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_WaitMessage: Invalid client packet type %u!",
                msg->type);
        #endif
            break;
        }
    } /* switch (msg->type) */

    return rc;
}
static int SN_Client_WaitType(MqttClient *client, MqttMessage* msg,
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
            /* Wait for packet */
            rc = SN_Packet_Read(client, client->rx_buf, client->rx_buf_len,
                    timeout_ms);
            if (rc <= 0) {
                return rc;
            }

            msg->stat = MQTT_MSG_WAIT;
            client->packet.buf_len = rc;

            /* Determine packet type */
            if (client->rx_buf[0] == 0x01) {
                /* Type is in fourth byte */
                msg->type = client->rx_buf[3];
            }
            else {
                /* Type is in second byte */
                msg->type = client->rx_buf[1];
            }

        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Read Packet: Len %d, Type %d",
                client->packet.buf_len, msg->type);
        #endif

            msg->stat = MQTT_MSG_READ;

            FALL_THROUGH;
        }

        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        {
            rc = SN_Client_HandlePayload(client, msg, timeout_ms, p_decode,
                                                                &packet_id);
            if (rc < 0) {
                return rc;
            }
            rc = MQTT_CODE_SUCCESS;

            /* Check for type and packet id */
            if (wait_type == msg->type) {
                if (wait_packet_id == 0 || wait_packet_id == packet_id) {
                    /* We found the packet type and id */
                    break;
                }
            }

            msg->stat = MQTT_MSG_BEGIN;
            goto wait_again;
        }

    #ifdef WOLFMQTT_V5
        case MQTT_MSG_AUTH:
    #endif
        case MQTT_MSG_WRITE:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_WaitType: Invalid state %d!",
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
int SN_Client_SearchGW(MqttClient *client, SN_SearchGw *search)
{
    int rc, len = 0;

    /* Validate required arguments */
    if (client == NULL || search == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (search->stat == MQTT_MSG_BEGIN) {

        /* Encode the search packet */
        rc = SN_Encode_SearchGW(client->tx_buf, client->tx_buf_len,
                search->radius);
        if (rc <= 0) {
            return rc;
        }
        len = rc;

        /* Send search for gateway packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) {
            return rc;
        }
        search->stat = MQTT_MSG_WAIT;
    }

    /* Wait for gateway info packet */
    rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
            SN_MSG_TYPE_GWINFO, 0, &search->gwInfo);

    return rc;
}

int SN_Client_Connect(MqttClient *client, SN_Connect *connect)
{
    int rc = 0, len = 0;

    /* Validate required arguments */
    if ((client == NULL) || (connect == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (connect->stat == MQTT_MSG_BEGIN) {

        /* Encode the connect packet */
        rc = SN_Encode_Connect(client->tx_buf, client->tx_buf_len, connect);
        if (rc <= 0) {
            return rc;
        }
        len = rc;

        /* Send connect packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc == len) {
            rc = 0;
            connect->stat = MQTT_MSG_WAIT;
        }
        else
        {
            if (rc == 0) {
                /* Some other error */
                rc = -1;
            }
        }
    }

    if ((rc == 0) && (connect->enable_lwt != 0)) {
        /* If the will is enabled, then the gateway requests the topic and
           message in separate packets. */
        rc = SN_Client_Will(client, &connect->will);
    }

    if (rc == 0) {
        connect->enable_lwt = 0;

        /* Wait for connect ack packet */
        rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
                SN_MSG_TYPE_CONNACK, 0, &connect->ack);
    }

    return rc;
}

int SN_Client_Will(MqttClient *client, SN_Will *will)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Wait for Will Topic Request packet */
    rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
            SN_MSG_TYPE_WILLTOPICREQ, 0, NULL);
    if (rc == 0) {

        /* Encode Will Topic */
        len = rc = SN_Encode_WillTopic(client->tx_buf, client->tx_buf_len, will);
        if (rc > 0) {

            /* Send Will Topic packet */
            rc = MqttPacket_Write(client, client->tx_buf, len);
            if ((will != NULL) && (rc == len)) {

                /* Wait for Will Message Request */
                rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
                        SN_MSG_TYPE_WILLMSGREQ, 0, NULL);

                if (rc == 0) {

                    /* Encode Will Message */
                    len = rc = SN_Encode_WillMsg(client->tx_buf, client->tx_buf_len, will);
                    if (rc > 0) {

                        /* Send Will Topic packet */
                        rc = MqttPacket_Write(client, client->tx_buf, len);
                        if (rc == len)
                            rc = 0;
                    }
                }
            }
        }
    }

    return rc;

}

int SN_Client_WillTopicUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0, len = 0;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode Will Topic Update */
    len = rc = SN_Encode_WillTopicUpdate(client->tx_buf, client->tx_buf_len, will);
    if (rc > 0) {

        /* Send Will Topic Update packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if ((will != NULL) && (rc == len)) {

            if (will != NULL) {
                /* Wait for Will Topic Update Response packet */
                rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
                        SN_MSG_TYPE_WILLTOPICREQ, 0, NULL);
            }
        }
    }

    return rc;

}

int SN_Client_WillMsgUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0, len = 0;

    /* Validate required arguments */
    if ((client == NULL) || (will == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode Will Message Update */
    len = rc = SN_Encode_WillMsgUpdate(client->tx_buf, client->tx_buf_len, will);
    if (rc > 0) {

        /* Send Will Message Update packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if ((will != NULL) && (rc == len)) {

            if (will != NULL) {
                /* Wait for Will Message Update Response packet */
                rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
                        SN_MSG_TYPE_WILLMSGRESP, 0, NULL);
            }
        }
    }

    return rc;

}

int SN_Client_Subscribe(MqttClient *client, SN_Subscribe *subscribe)
{
    int rc = -1, len;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (subscribe->stat == MQTT_MSG_BEGIN) {
        /* Encode the subscribe packet */
        rc = SN_Encode_Subscribe(client->tx_buf, client->tx_buf_len,
                subscribe);
        if (rc <= 0) { return rc; }
        len = rc;

        /* Send subscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }

        subscribe->stat = MQTT_MSG_WAIT;
    }

    /* Wait for subscribe ack packet */
    rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
            SN_MSG_TYPE_SUBACK, subscribe->packet_id, &subscribe->subAck);

    return rc;
}

int SN_Client_Publish(MqttClient *client, SN_Publish *publish)
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
            rc = SN_Encode_Publish(client->tx_buf, client->tx_buf_len,
                    publish);
            if (rc <= 0) {
                return rc;
            }

            client->write.len = rc;
            publish->buffer_pos = 0;

            FALL_THROUGH;
        }
        case MQTT_MSG_WRITE:
        {
            publish->stat = MQTT_MSG_WRITE;

            /* Send packet and payload */
            rc = MqttPacket_Write(client, client->tx_buf,
                    client->write.len);
            if (rc < 0) {
                return rc;
            }

            if (rc == client->write.len) {
                rc = MQTT_CODE_SUCCESS;
            }
            else {
                rc = -1;
            }

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
                SN_PublishResp publish_resp;
                XMEMSET(&publish_resp, 0, sizeof(SN_PublishResp));

                /* Determine packet type to wait for */
                SN_MsgType type = (publish->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBCOMP;

                /* Wait for publish response packet */
                rc = SN_Client_WaitType(client, &client->msg,
                    client->cmd_timeout_ms, type, publish->packet_id, &publish_resp);

                publish->return_code = publish_resp.return_code;
            }

            break;
        }

    #ifdef WOLFMQTT_V5
        case MQTT_MSG_AUTH:
    #endif
        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_Publish: Invalid state %d!",
                publish->stat);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
    } /* switch (publish->stat) */

    return rc;
}


int SN_Client_Unsubscribe(MqttClient *client, SN_Unsubscribe *unsubscribe)
{
    int rc, len;
    SN_UnsubscribeAck unsubscribe_ack;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (unsubscribe->stat == MQTT_MSG_BEGIN) {
        /* Encode the subscribe packet */
        rc = SN_Encode_Unsubscribe(client->tx_buf, client->tx_buf_len,
            unsubscribe);
        if (rc <= 0) { return rc; }
        len = rc;

        /* Send unsubscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }

        unsubscribe->stat = MQTT_MSG_WAIT;
    }

    /* Wait for unsubscribe ack packet */
    rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
            SN_MSG_TYPE_UNSUBACK, unsubscribe->packet_id,
            &unsubscribe_ack);

    return rc;
}

int SN_Client_Register(MqttClient *client, SN_Register *regist)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (client->msg.stat == MQTT_MSG_BEGIN) {
        /* Encode the register packet */
        rc = SN_Encode_Register(client->tx_buf, client->tx_buf_len, regist);
        if (rc <= 0) {
            return rc;
        }
        len = rc;

        /* Send packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) {
            return rc;
        }

        client->msg.stat = MQTT_MSG_WAIT;
    }

    /* Wait for register acknowledge packet */
    rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
            SN_MSG_TYPE_REGACK, regist->packet_id, &regist->regack);

    return rc;
}

int SN_Client_Ping(MqttClient *client, SN_PingReq *ping)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (client->msg.stat == MQTT_MSG_BEGIN) {
        /* Encode the ping packet */
        rc = SN_Encode_Ping(client->tx_buf, client->tx_buf_len, ping);
        if (rc <= 0) { return rc; }
        len = rc;

        /* Send ping req packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
        if (rc != len) { return rc; }

        client->msg.stat = MQTT_MSG_WAIT;
    }

    /* Wait for ping resp packet */
    rc = SN_Client_WaitType(client, &client->msg, client->cmd_timeout_ms,
            SN_MSG_TYPE_PING_RESP, 0, NULL);

    return rc;
}

int SN_Client_Disconnect(MqttClient *client)
{
    return SN_Client_Disconnect_ex(client, NULL);
}

int SN_Client_Disconnect_ex(MqttClient *client, SN_Disconnect *disconnect)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode the disconnect packet */
    rc = SN_Encode_Disconnect(client->tx_buf, client->tx_buf_len, disconnect);
    if (rc <= 0) { return rc; }
    len = rc;

    /* Send disconnect packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
    if (rc != len) { return rc; }

    /* No response for MQTT disconnect packet */

    return MQTT_CODE_SUCCESS;
}

int SN_Client_WaitMessage(MqttClient *client, int timeout_ms)
{
    return SN_Client_WaitType(client, &client->msg, timeout_ms,
        MQTT_PACKET_TYPE_ANY, 0, NULL);
}

#endif /* defined WOLFMQTT_SN */

