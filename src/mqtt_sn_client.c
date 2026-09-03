/* mqtt_sn_client.c
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_sn_client.h"

#ifdef WOLFMQTT_SN

/* Private functions */
static int SN_Client_WriteResponse(MqttClient* client, MqttMsgStat* stat,
    int encoded_len, MqttMsgState retry_ack)
{
    int rc;
    int xfer;

    (void)retry_ack;

    if (encoded_len > 0) {
        /* MqttWriteStart owns the writer, but MQTT-SN send paths can leave
         * completed-operation counters populated after releasing lockSend. */
        client->write.pos = 0;
        client->write.total = 0;
        client->write.len = encoded_len;
        stat->ack = MQTT_MSG_HEADER;
    }
    else if (stat->ack != MQTT_MSG_HEADER) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
    }

    xfer = client->write.len;
    rc = MqttPacket_Write(client, client->tx_buf, xfer);
    if (rc == MQTT_CODE_CONTINUE) {
    #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
        if (client->write.total == 0) {
            /* No bytes depend on tx_buf, so allow another operation to use
             * the writer. Restore the pre-encode state so the response can
             * be regenerated without replaying application callbacks. */
            MqttWriteStop(client, stat);
            stat->ack = retry_ack;
        }
    #endif
        return rc;
    }
    MqttWriteStop(client, stat);
    stat->ack = MQTT_MSG_BEGIN;

    if (rc == xfer) {
        rc = MQTT_CODE_SUCCESS;
    }
    return rc;
}

static int SN_Client_HandlePacket(MqttClient* client, SN_MsgType packet_type,
    void* packet_obj, MqttMsgStat* wait_stat, byte* response_pending,
    int timeout)
{
    int rc = MQTT_CODE_SUCCESS;
    word16 packet_id = 0;

    (void)timeout;
    *response_pending = 0;

    if (wait_stat->ack == MQTT_MSG_HEADER) {
        *response_pending = 1;
        return SN_Client_WriteResponse(client, wait_stat, 0,
            MQTT_MSG_HEADER);
    }

    switch ((int)packet_type)
    {
        case SN_MSG_TYPE_GWINFO:
        {
            SN_GwInfo info, *p_info = &info;
            if (packet_obj) {
                p_info = (SN_GwInfo*)packet_obj;
            }
            else {
                XMEMSET(p_info, 0, sizeof(SN_GwInfo));
            }
            /* Default to the struct's own backing storage so the decoder
             * never writes through a NULL gwAddr, but honor a
             * caller-supplied destination if one was set. */
            if (p_info->gwAddr == NULL) {
                p_info->gwAddr = &p_info->gwAddrBuf;
            }

            rc = SN_Decode_GWInfo(client->rx_buf, client->packet.buf_len,
                    p_info);
            if (rc <= 0) {
                return rc;
            }
            break;
        }
        case SN_MSG_TYPE_CONNACK:
        {
            /* Decode connect ack */
            SN_ConnectAck connect_ack, *p_connect_ack = &connect_ack;
            if (packet_obj) {
                p_connect_ack = (SN_ConnectAck*)packet_obj;
            }
            else {
                XMEMSET(p_connect_ack, 0, sizeof(SN_ConnectAck));
            }

            /* Validate the fixed-length CONNACK (length, buffer size and
               packet type) rather than blindly trusting the last byte. */
            rc = SN_Decode_ConnectAck(client->rx_buf, client->packet.buf_len,
                    p_connect_ack);
            if (rc <= 0) {
                return rc;
            }

            break;
        }
        case SN_MSG_TYPE_WILLTOPICREQ:
        {
            rc = SN_Decode_WillTopicReq(client->rx_buf, client->packet.buf_len);
            break;
        }
        case SN_MSG_TYPE_WILLMSGREQ:
        {
            rc = SN_Decode_WillMsgReq(client->rx_buf, client->packet.buf_len);
            break;
        }
        case SN_MSG_TYPE_REGISTER:
        {
            /* Decode register */
            SN_Register reg_s;

            XMEMSET(&reg_s, 0, sizeof(SN_Register));

            /* Pass the full receive-buffer capacity (rx_buf_len), not the
             * decoded packet length (packet.buf_len). SN_Decode_Register
             * NUL-terminates topicName in place one byte past the packet, so
             * its strict bounds check needs the writable buffer size to leave
             * room for that terminator. Passing packet.buf_len (== total_len)
             * made the check reject every valid REGISTER. */
            rc = SN_Decode_Register(client->rx_buf, client->rx_buf_len,
                    &reg_s);

            if (rc > 0) {
                /* Initialize the regack */
                reg_s.regack.packet_id = reg_s.packet_id;
                reg_s.regack.topicId = reg_s.topicId;
                reg_s.regack.return_code = SN_RC_NOTSUPPORTED;

                /* Call the register callback to allow app to
                 * handle new topic ID assignment. Do this before acquiring
                 * the response writer so the callback may safely call a
                 * client send API. The ack state records completion and the
                 * result so a busy writer does not replay the callback. */
                if (wait_stat->ack == MQTT_MSG_BEGIN) {
                    if (client->reg_cb != NULL) {
                        rc = client->reg_cb(reg_s.topicId,
                            reg_s.topicName, client->reg_ctx);
                        wait_stat->ack = (rc >= 0) ? MQTT_MSG_WAIT :
                            MQTT_MSG_AUTH;
                    }
                    else {
                        wait_stat->ack = MQTT_MSG_PAYLOAD2;
                    }
                }

                if (wait_stat->ack == MQTT_MSG_WAIT) {
                    reg_s.regack.return_code = SN_RC_ACCEPTED;
                }
                else if (wait_stat->ack == MQTT_MSG_AUTH) {
                    reg_s.regack.return_code = SN_RC_INVTOPICNAME;
                }
                else if (wait_stat->ack != MQTT_MSG_PAYLOAD2) {
                    wait_stat->ack = MQTT_MSG_BEGIN;
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
                }

                *response_pending = 1;
                rc = MqttWriteStart(client, wait_stat);
                if (rc != MQTT_CODE_SUCCESS) {
                    if (rc != MQTT_CODE_CONTINUE) {
                        wait_stat->ack = MQTT_MSG_BEGIN;
                    }
                    return rc;
                }

                /* Encode the register acknowledgment */
                rc = SN_Encode_RegAck(client->tx_buf, client->tx_buf_len,
                        &reg_s.regack);
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d",
                    rc, SN_Packet_TypeDesc(SN_MSG_TYPE_REGACK),
                    SN_MSG_TYPE_REGACK, reg_s.packet_id);
            #endif
                if (rc <= 0) {
                    MqttWriteStop(client, wait_stat);
                    wait_stat->ack = MQTT_MSG_BEGIN;
                    return rc;
                }
                return SN_Client_WriteResponse(client, wait_stat, rc,
                    wait_stat->ack);
            }

            break;
        }
        case SN_MSG_TYPE_REGACK:
        {
            /* Decode register ack */
            SN_RegAck regack_s, *p_regack = &regack_s;
            if (packet_obj) {
                p_regack = (SN_RegAck*)packet_obj;
            }
            else {
                XMEMSET(p_regack, 0, sizeof(SN_RegAck));
            }

            rc = SN_Decode_RegAck(client->rx_buf, client->packet.buf_len,
                    p_regack);
            if (rc > 0) {
                packet_id = p_regack->packet_id;
            }

            break;
        }
        case SN_MSG_TYPE_PUBLISH:
        {
            SN_Publish pub, *p_pub = &pub;
            if (packet_obj) {
                p_pub = (SN_Publish*)packet_obj;
            }
            else {
                XMEMSET(p_pub, 0, sizeof(SN_Publish));
            }

            /* Decode publish message */
            rc = SN_Decode_Publish(client->rx_buf, client->packet.buf_len,
                   p_pub);
            if (rc <= 0) {
                return rc;
            }

            /* Notify the application before acquiring the response writer so
             * the callback may safely call a client send API. MQTT_MSG_WAIT
             * records successful delivery across a busy-writer retry. */
            if (wait_stat->ack == MQTT_MSG_BEGIN) {
                if (client->msg_cb) {
                    /* if using the temp publish message buffer,
                       then populate message context with client context */
                    if (&client->msgSN.publish == p_pub)
                        p_pub->ctx = client->ctx;
                    rc = client->msg_cb(client, (MqttMessage*)p_pub, 1, 1);
                    if (rc != MQTT_CODE_SUCCESS) {
                        return rc;
                    }
                    wait_stat->ack = MQTT_MSG_WAIT;
                }
                else {
                    /* No callback registered to deliver this PUBLISH. Return
                     * a distinct error instead of reporting success: for QoS
                     * 0 this replaces a silent discard, and for QoS>0 it also
                     * avoids falsely ACKing a message the application never
                     * saw. */
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_CALLBACK);
                }
            }

            /* Handle Qos */
            if (p_pub->qos > MQTT_QOS_0) {
                SN_MsgType type;

                if (wait_stat->ack != MQTT_MSG_WAIT) {
                    wait_stat->ack = MQTT_MSG_BEGIN;
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
                }
                *response_pending = 1;
                rc = MqttWriteStart(client, wait_stat);
                if (rc != MQTT_CODE_SUCCESS) {
                    if (rc != MQTT_CODE_CONTINUE) {
                        wait_stat->ack = MQTT_MSG_BEGIN;
                    }
                    return rc;
                }

                packet_id = p_pub->packet_id;

                /* Determine packet type to write */
                type = (p_pub->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBREC;
                /* [MQTT-SN-1.2 5.4.4] The response MUST echo the received
                 * PUBLISH TopicId; topic_name holds the 2-byte TopicId. */
                (void)MqttDecode_Num((byte*)p_pub->topic_name,
                        &p_pub->resp.topicId, MQTT_DATA_LEN_SIZE);
                p_pub->resp.return_code = SN_RC_ACCEPTED;
                p_pub->resp.packet_id = packet_id;

                /* Encode publish response */
                rc = SN_Encode_PublishResp(client->tx_buf,
                                    client->tx_buf_len, type, &p_pub->resp);
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d,"
                        " QoS %d",
                    rc, SN_Packet_TypeDesc(type), type, packet_id,
                    p_pub->qos);
            #endif
                if (rc <= 0) {
                    MqttWriteStop(client, wait_stat);
                    wait_stat->ack = MQTT_MSG_BEGIN;
                    return rc;
                }
                return SN_Client_WriteResponse(client, wait_stat, rc,
                    wait_stat->ack);
            }
            wait_stat->ack = MQTT_MSG_BEGIN;
            break;
        }
        case SN_MSG_TYPE_PUBACK:
        case SN_MSG_TYPE_PUBCOMP:
        case SN_MSG_TYPE_PUBREC:
        case SN_MSG_TYPE_PUBREL:
        {
            SN_PublishResp publish_resp, *p_publish_resp = &publish_resp;
            if (packet_obj) {
                p_publish_resp = (SN_PublishResp*)packet_obj;
            }
            else {
                XMEMSET(p_publish_resp, 0, sizeof(SN_PublishResp));
            }

            /* Decode publish response message */
            rc = SN_Decode_PublishResp(client->rx_buf, client->packet.buf_len,
                packet_type, p_publish_resp);
            if (rc <= 0) {
                return rc;
            }
            packet_id = p_publish_resp->packet_id;

            /* If Qos then send response */
            if (packet_type == SN_MSG_TYPE_PUBREC ||
                packet_type == SN_MSG_TYPE_PUBREL) {

                byte resp_type = (packet_type == SN_MSG_TYPE_PUBREC) ?
                        SN_MSG_TYPE_PUBREL : SN_MSG_TYPE_PUBCOMP;

                *response_pending = 1;
                rc = MqttWriteStart(client, wait_stat);
                if (rc != MQTT_CODE_SUCCESS) {
                    return rc;
                }

                /* Encode publish response */
                p_publish_resp->packet_id = packet_id;
                rc = SN_Encode_PublishResp(client->tx_buf,
                    client->tx_buf_len, resp_type, p_publish_resp);
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d",
                    rc, SN_Packet_TypeDesc((SN_MsgType)resp_type), resp_type,
                    packet_id);
            #endif
                if (rc <= 0) {
                    MqttWriteStop(client, wait_stat);
                    return rc;
                }
                return SN_Client_WriteResponse(client, wait_stat, rc,
                    MQTT_MSG_BEGIN);
            }
            break;
        }
        case SN_MSG_TYPE_SUBACK:
        {
            /* Decode subscribe ack */
            SN_SubAck subscribe_ack, *p_subscribe_ack = &subscribe_ack;
            if (packet_obj) {
                p_subscribe_ack = (SN_SubAck*)packet_obj;
            }
            else {
                XMEMSET(p_subscribe_ack, 0, sizeof(SN_SubAck));
            }

            rc = SN_Decode_SubscribeAck(client->rx_buf, client->packet.buf_len,
                    p_subscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            packet_id = p_subscribe_ack->packet_id;

            break;
        }
        case SN_MSG_TYPE_UNSUBACK:
        {
            /* Decode unsubscribe ack */
            SN_UnsubscribeAck unsubscribe_ack,
                              *p_unsubscribe_ack = &unsubscribe_ack;
            if (packet_obj) {
                p_unsubscribe_ack = (SN_UnsubscribeAck*)packet_obj;
            }
            else {
                XMEMSET(p_unsubscribe_ack, 0, sizeof(SN_UnsubscribeAck));
            }
            rc = SN_Decode_UnsubscribeAck(client->rx_buf,
                    client->packet.buf_len, p_unsubscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            packet_id = p_unsubscribe_ack->packet_id;

            break;
        }
        case SN_MSG_TYPE_PING_RESP:
        {
            /* Decode ping */
            rc = SN_Decode_Ping(client->rx_buf, client->packet.buf_len);
            break;
        }
        case SN_MSG_TYPE_PING_REQ:
        {
            /* Decode ping */
            rc = SN_Decode_Ping(client->rx_buf, client->packet.buf_len);
            if (rc <= 0) { return rc; }

            *response_pending = 1;
            rc = MqttWriteStart(client, wait_stat);
            if (rc != MQTT_CODE_SUCCESS) {
                return rc;
            }

            /* Encode the ping packet as a response */
            rc = SN_Encode_Ping(client->tx_buf, client->tx_buf_len, NULL,
                    SN_MSG_TYPE_PING_RESP);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PING_RESP),
                SN_MSG_TYPE_PING_RESP);
        #endif
            if (rc <= 0) {
                MqttWriteStop(client, wait_stat);
                return rc;
            }
            return SN_Client_WriteResponse(client, wait_stat, rc,
                MQTT_MSG_BEGIN);
        }
        case SN_MSG_TYPE_WILLTOPICRESP:
        {
            /* Decode Will Topic Response */
            SN_WillTopicResp resp_s, *resp = &resp_s;
            if (packet_obj) {
                resp = (SN_WillTopicResp*)packet_obj;
            }
            else {
                XMEMSET(resp, 0, sizeof(SN_WillTopicResp));
            }
            rc = SN_Decode_WillTopicResponse(client->rx_buf,
                    client->packet.buf_len, &resp->return_code);
            break;
        }
        case SN_MSG_TYPE_WILLMSGRESP:
        {
            /* Decode Will Message Response */
            SN_WillMsgResp resp_s, *resp = &resp_s;
            if (packet_obj) {
                resp = (SN_WillMsgResp*)packet_obj;
            }
            else {
                XMEMSET(resp, 0, sizeof(SN_WillMsgResp));
            }
            rc = SN_Decode_WillMsgResponse(client->rx_buf,
                    client->packet.buf_len, &resp->return_code);
            break;
        }
        case SN_MSG_TYPE_DISCONNECT:
        {
            SN_Disconnect disc_s, *disc = &disc_s;
            if (packet_obj) {
                disc = (SN_Disconnect*)packet_obj;
            }
            else {
                XMEMSET(disc, 0, sizeof(SN_Disconnect));
            }
            /* Decode Disconnect */
            rc = SN_Decode_Disconnect(client->rx_buf, client->packet.buf_len);

#ifdef WOLFMQTT_DISCONNECT_CB
            /* Call disconnect callback to allow handling broker disconnect */
            if ((client->disconnect_cb != NULL) && (disc->sleepTmr == 0)) {
                client->disconnect_cb(client, rc, client->disconnect_ctx);
            }
#endif
            break;
        }

        default:
        {
            /* Other types are server side only, ignore */
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_HandlePacket: Invalid client packet type %u!",
                packet_type);
        #endif
            break;
        }
    } /* switch (packet_type) */

    (void)packet_id;

    return rc;
}

/* Helper for clearing the contents of an object buffer based on packet type */
static void MqttSNClient_PacketReset(SN_MsgType packet_type, void* packet_obj)
{
    size_t objSz = 0;
    size_t offset = sizeof(MqttMsgStat);
    switch (packet_type) {
        case SN_MSG_TYPE_ADVERTISE:
            objSz = sizeof(SN_Advertise);
            break;
        case SN_MSG_TYPE_SEARCHGW:
            objSz = sizeof(SN_SearchGw);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_GWINFO:
            objSz = sizeof(SN_GwInfo);
            break;
        case SN_MSG_TYPE_CONNECT:
            objSz = sizeof(SN_Connect);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_CONNACK:
            objSz = sizeof(SN_ConnectAck);
            break;
        case SN_MSG_TYPE_WILLTOPICREQ:
        case SN_MSG_TYPE_WILLTOPIC:
        case SN_MSG_TYPE_WILLMSGREQ:
        case SN_MSG_TYPE_WILLMSG:
            objSz = sizeof(SN_Will);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_REGISTER:
            objSz = sizeof(SN_Register);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_REGACK:
            objSz = sizeof(SN_RegAck);
            break;
        case SN_MSG_TYPE_PUBLISH:
            objSz = sizeof(SN_Publish);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_PUBACK:
        case SN_MSG_TYPE_PUBCOMP:
        case SN_MSG_TYPE_PUBREC:
        case SN_MSG_TYPE_PUBREL:
            objSz = sizeof(SN_PublishResp);
            break;
        case SN_MSG_TYPE_SUBSCRIBE:
            objSz = sizeof(SN_Subscribe);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_SUBACK:
            objSz = sizeof(SN_SubAck);
            break;
        case SN_MSG_TYPE_UNSUBSCRIBE:
            objSz = sizeof(SN_Unsubscribe);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_UNSUBACK:
            objSz = sizeof(SN_UnsubscribeAck);
            break;
        case SN_MSG_TYPE_PING_REQ:
        case SN_MSG_TYPE_PING_RESP:
            objSz = sizeof(SN_PingReq);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_DISCONNECT:
            objSz = sizeof(SN_Disconnect);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_WILLTOPICUPD:
        case SN_MSG_TYPE_WILLMSGUPD:
            objSz = sizeof(SN_Will);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case SN_MSG_TYPE_WILLTOPICRESP:
        case SN_MSG_TYPE_WILLMSGRESP:
            objSz = sizeof(SN_WillTopicResp);
            break;
        case SN_MSG_TYPE_ENCAPMSG:
        case SN_MSG_TYPE_ANY:
        default:
            break;
    } /* switch (packet_type) */
    if (objSz > offset) {
        XMEMSET((byte*)packet_obj + offset, 0, objSz - offset);
    }
}

static int SN_Client_WaitType(MqttClient *client, void* packet_obj,
    byte wait_type, word16 wait_packet_id, int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    word16 packet_id;
    SN_MsgType packet_type;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp *pendResp;
#endif
    MqttMsgStat* mms_stat;
    int waitMatchFound;
    byte response_pending;
    void* use_packet_obj = NULL;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* all packet type structures must have MqttMsgStat at top */
    mms_stat = (MqttMsgStat*)packet_obj;

wait_again:

    /* initialize variables */
    if (mms_stat->read == MQTT_MSG_PAYLOAD ||
            mms_stat->read == MQTT_MSG_PAYLOAD2) {
        packet_id = client->sn_wait_packet_id;
        packet_type = client->sn_wait_packet_type;
    }
    else {
        packet_id = 0;
        packet_type = SN_MSG_TYPE_RESERVED;
    }
#ifdef WOLFMQTT_MULTITHREAD
    pendResp = NULL;
#endif
    waitMatchFound = 0;
    response_pending = 0;

#ifdef WOLFMQTT_DEBUG_CLIENT
    #ifdef WOLFMQTT_NONBLOCK
    if (client->lastRc != MQTT_CODE_CONTINUE)
    #endif
    {
        PRINTF("SN_Client_WaitType: Type %s (%d), ID %d, State %d-%d",
                SN_Packet_TypeDesc((SN_MsgType)wait_type),
                    wait_type, wait_packet_id, mms_stat->read, mms_stat->write);
    }
#endif

    switch (mms_stat->read)
    {
        case MQTT_MSG_BEGIN:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            /* Check to see if packet type and id have already completed */
            rc = MqttClient_CheckPendResp(client, wait_type, wait_packet_id);
            if (rc != MQTT_CODE_ERROR_NOT_FOUND && rc != MQTT_CODE_CONTINUE) {
                return rc;
            }
        #endif

            if ((rc = MqttReadStart(client, mms_stat)) != 0) {
                return rc;
            }

            mms_stat->read = MQTT_MSG_WAIT;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        case MQTT_MSG_HEADER:
        {
            /* Wait for packet */
            rc = SN_Packet_Read(client, client->rx_buf, client->rx_buf_len,
                    timeout_ms);
            /* handle failure */
            if (rc <= 0) {
            #ifdef WOLFMQTT_NONBLOCK
                if (rc == MQTT_CODE_CONTINUE &&
                    (client->packet.stat > MQTT_PK_BEGIN ||
                     client->read.total > 0)
                ) {
                    /* advance state, since we received some data */
                    mms_stat->read = MQTT_MSG_HEADER;
                }
            #endif
                break;
            }

            /* advance state, since we received some data */
            mms_stat->read = MQTT_MSG_HEADER;

            client->packet.buf_len = rc;

            /* Decode header */
            rc = SN_Decode_Header(client->rx_buf, client->packet.buf_len,
                    &packet_type, &packet_id);
            if (rc < 0) {
                break;
            }
            client->sn_wait_packet_type = packet_type;
            client->sn_wait_packet_id = packet_id;

            /* Clear shared union for next call */
            MqttSNClient_PacketReset(packet_type, &client->msgSN);

        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Read Packet: Len %d, Type %d, ID %d",
                client->packet.buf_len, packet_type, packet_id);
        #endif

            mms_stat->read = MQTT_MSG_PAYLOAD;
        }
        FALL_THROUGH;

        case MQTT_MSG_PAYLOAD:
        case MQTT_MSG_PAYLOAD2:
        {
            SN_MsgType use_packet_type;

            /* Determine if we received data for this request */
            if ((wait_type == SN_MSG_TYPE_ANY || wait_type == packet_type) &&
                (wait_packet_id == 0 || wait_packet_id == packet_id))
            {
                use_packet_obj = packet_obj;
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("Using INCOMING packet_obj %p", use_packet_obj);
            #endif
                waitMatchFound = 1;
            }
            else {
                /* use generic packet object */
                use_packet_obj = &client->msgSN;
            }
            use_packet_type = packet_type;

        #ifdef WOLFMQTT_MULTITHREAD
            /* Check to see if we have a pending response for this packet */
            pendResp = NULL;
            rc = wm_SemLock(&client->lockClient);
            if (rc == 0) {
                if (MqttClient_RespList_Find(client,
                        (MqttPacketType)packet_type, packet_id, &pendResp)) {
                    /* we found packet match this incoming read packet */
                    pendResp->packetProcessing = 1;
                    if (pendResp->packet_obj != packet_obj) {
                        use_packet_obj = pendResp->packet_obj;
                        use_packet_type = (SN_MsgType)pendResp->packet_type;
                        /* req from another thread... not a match */
                        waitMatchFound = 0;
                    }
                }
                wm_SemUnlock(&client->lockClient);
            }
            else {
                break; /* error */
            }
        #endif /* WOLFMQTT_MULTITHREAD */

            rc = SN_Client_HandlePacket(client, use_packet_type, use_packet_obj,
                    mms_stat, &response_pending, timeout_ms);

            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }

            /* handle success case */
            if (rc >= 0) {
                rc = MQTT_CODE_SUCCESS;
            }

        #ifdef WOLFMQTT_MULTITHREAD
            if (pendResp) {
                /* Mark pending response entry done */
                if (wm_SemLock(&client->lockClient) == 0) {
                    pendResp->packetDone = 1;
                    pendResp->packet_ret = rc;
                #ifdef WOLFMQTT_DEBUG_CLIENT
                    PRINTF("PendResp Marked Done %p", pendResp);
                #endif
                    pendResp = NULL;
                    wm_SemUnlock(&client->lockClient);
                }
            }
        #endif /* WOLFMQTT_MULTITHREAD */

            /* done reading */
            client->sn_wait_packet_type = SN_MSG_TYPE_RESERVED;
            client->sn_wait_packet_id = 0;
            MqttReadStop(client, mms_stat);
            break;
        }

        case MQTT_MSG_ACK: /* ack handled in SN_Client_HandlePacket */
        case MQTT_MSG_AUTH:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_WaitType: Invalid read state %d!",
                mms_stat->read);
        #endif
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
            break;
        }
    } /* switch (mms_stat->read) */

    /* no data read, then reset state */
    if (mms_stat->read == MQTT_MSG_WAIT) {
        mms_stat->read = MQTT_MSG_BEGIN;
    }

    /* Keep the read lock for a partial packet, or while an automatic response
     * is waiting for either a partial transport write or another writer. */
    if (rc == MQTT_CODE_CONTINUE &&
            (mms_stat->read == MQTT_MSG_HEADER || response_pending)) {
    #ifdef WOLFMQTT_NONBLOCK
        return rc;
    #else
        if (response_pending && mms_stat->isWriteActive) {
            /* An asynchronous write already owns the response state, so a
             * blocking API can finish it before returning. If no response
             * write started, CONTINUE denotes same-thread writer re-entry;
             * fall through so the active writer can unwind. */
            goto wait_again;
        }
    #endif
    }

    client->sn_wait_packet_type = SN_MSG_TYPE_RESERVED;
    client->sn_wait_packet_id = 0;
    MqttReadStop(client, mms_stat);
    if (rc == MQTT_CODE_CONTINUE) {
        /* CONTINUE from an application callback is a terminal callback result,
         * not an internal automatic-response retry. Consume the packet so a
         * later wait cannot replay the callback. */
        mms_stat->read = MQTT_MSG_BEGIN;
    }

#ifdef WOLFMQTT_NONBLOCK
    #ifdef WOLFMQTT_DEBUG_CLIENT
    #ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0)
    #endif
    {
        client->lastRc = rc;
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }
    #endif /* WOLFMQTT_DEBUG_CLIENT */
    if (rc == MQTT_CODE_CONTINUE) {
        return rc;
    }
#endif

    if (rc < 0) {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        if (rc != MQTT_CODE_CONTINUE) {
            PRINTF("SN_Client_WaitType: Failure: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }
    #endif
        return rc;
    }

    if (!waitMatchFound) {
        /* if we get here, then the we are still waiting for a packet */
        mms_stat->read = MQTT_MSG_BEGIN;
    #ifdef WOLFMQTT_NONBLOCK
        /* for non-blocking return with code continue instead of waiting again
         * if called with packet type and id of 'any' */
        if (wait_type == SN_MSG_TYPE_ANY && wait_packet_id == 0) {
            return MQTT_CODE_CONTINUE;
        }
    #endif
        MQTT_TRACE_MSG("Wait Again");
        goto wait_again;
    }
#ifdef WOLFMQTT_DEBUG_CLIENT
    if (rc != MQTT_CODE_CONTINUE) {
        PRINTF("SN_Client_WaitType: rc %d, state %d-%d",
            rc, mms_stat->read, mms_stat->write);
    }
#endif

    return rc;
}

/* Public Functions */

int SN_Client_SetRegisterCallback(MqttClient *client,
        SN_ClientRegisterCb regCb,
        void* ctx)
{
    int rc = MQTT_CODE_SUCCESS;

    if (client == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);

#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
#endif

        client->reg_cb = regCb;
        client->reg_ctx = ctx;

#ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    }
#endif

    return rc;
}

#ifdef WOLFMQTT_MULTITHREAD
/* Unlink a pending response registered for a send that will not be resumed. */
static void SN_Client_UnlinkPendResp(MqttClient* client,
    MqttPendResp* pendResp)
{
    if (pendResp != NULL && wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, pendResp);
        wm_SemUnlock(&client->lockClient);
    }
}
#endif

/* Send the tx_buf packet under the ownership taken by MqttWriteStart. On
 * MQTT_CODE_CONTINUE ownership and the pending response are kept for resume
 * (released and reset to BEGIN only when a zero-progress ALLOW_NODATA_UNLOCK
 * write occurred); on success/short/failed writes the writer is released. */
static int SN_Client_WriteOwned(MqttClient* client, MqttMsgStat* stat
#ifdef WOLFMQTT_MULTITHREAD
    , MqttPendResp* pendResp
#endif
    )
{
    int xfer;
    int rc;

    /* Snapshot under ownership: once the writer is released another sender may
     * re-encode and change client->write.len before the comparison below. */
    xfer = client->write.len;
    rc = MqttPacket_Write(client, client->tx_buf, xfer);
    if (rc == MQTT_CODE_CONTINUE) {
    #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
        if (client->write.total == 0) {
            MqttWriteStop(client, stat);
        #ifdef WOLFMQTT_MULTITHREAD
            SN_Client_UnlinkPendResp(client, pendResp);
        #endif
            stat->write = MQTT_MSG_BEGIN;
        }
    #endif
        return rc;
    }
    MqttWriteStop(client, stat);
    if (rc != xfer) {
    #ifdef WOLFMQTT_MULTITHREAD
        SN_Client_UnlinkPendResp(client, pendResp);
    #endif
        stat->write = MQTT_MSG_BEGIN;
        /* A non-negative short write (e.g. 0 bytes) is not success: report a
         * network error so callers do not advance to awaiting a reply for a
         * packet that never fully reached the transport. */
        return (rc >= 0) ? MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK) : rc;
    }
    return MQTT_CODE_SUCCESS;
}

int SN_Client_SearchGW(MqttClient *client, SN_SearchGw *search)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || search == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (search->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &search->stat);
        if (rc != 0) {
            return rc;
        }

        /* Encode the search packet */
        rc = SN_Encode_SearchGW(client->tx_buf, client->tx_buf_len,
                search->radius);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_SEARCHGW),
            SN_MSG_TYPE_SEARCHGW);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &search->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_GWINFO, 0,
                    &search->pendResp, &search->gwInfo);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &search->stat);
            return rc; /* Error locking client */
        }
    #endif

        search->stat.write = MQTT_MSG_HEADER;
    }
    if (search->stat.write == MQTT_MSG_HEADER) {
        /* Send search for gateway packet */
        rc = SN_Client_WriteOwned(client, &search->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , &search->pendResp
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }

        search->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for gateway info packet */
    rc = SN_Client_WaitType(client, &search->gwInfo, SN_MSG_TYPE_GWINFO, 0,
        client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &search->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    search->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

static int SN_WillTopic(MqttClient *client, SN_Will *will)
{
    int rc = 0;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* The will exchange is a wait-then-respond flow. Track progress in
     * will->stat.write so that an MQTT_CODE_CONTINUE return resumes where it
     * left off rather than re-running the whole
     * function. In particular the pending-response is added only once (in
     * MQTT_MSG_BEGIN); re-adding it on a retry would be rejected as a
     * duplicate by MqttClient_RespList_Add. */
    switch (will->stat.write)
    {
        case MQTT_MSG_BEGIN:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            rc = wm_SemLock(&client->lockClient);
            if (rc == 0) {
                /* inform other threads of expected response */
                rc = MqttClient_RespList_Add(client,
                        (MqttPacketType)SN_MSG_TYPE_WILLTOPICREQ, 0,
                        &will->pendResp, &will->resp.topicResp);
                wm_SemUnlock(&client->lockClient);
            }
            if (rc != 0) {
                return rc; /* Error locking client */
            }
        #endif

            will->stat.write = MQTT_MSG_WAIT;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        {
            /* Wait for Will Topic Request packet */
            rc = SN_Client_WaitType(client, &will->resp.topicResp,
                    SN_MSG_TYPE_WILLTOPICREQ, 0, client->cmd_timeout_ms);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                return rc; /* stay in MQTT_MSG_WAIT, do not re-add */
            }
        #endif

        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif

            if (rc != 0) {
                /* reset state on error */
                will->stat.write = MQTT_MSG_BEGIN;
                return rc;
            }

            will->stat.write = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        {
            /* Take write ownership; a write already in progress on this thread
             * is reported as MQTT_CODE_CONTINUE instead of deadlocking. */
            rc = MqttWriteStart(client, &will->stat);
            if (rc != 0) {
                return rc;
            }

            /* Encode Will Topic */
            rc = SN_Encode_WillTopic(client->tx_buf, client->tx_buf_len,
                    will);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("EncodePacket: Len %d, Type %s (%d)",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPIC),
                SN_MSG_TYPE_WILLTOPIC);
        #endif
            if (rc > 0) {
                client->write.len = rc;
                will->stat.write = MQTT_MSG_PAYLOAD;
            }
            else {
                MqttWriteStop(client, &will->stat);
                will->stat.write = MQTT_MSG_BEGIN;
                break;
            }
        }
        FALL_THROUGH;

        case MQTT_MSG_PAYLOAD:
        {
            /* Send Will Topic packet; on MQTT_CODE_CONTINUE ownership is kept
             * and this state resumes the write rather than re-encoding. */
            rc = SN_Client_WriteOwned(client, &will->stat
            #ifdef WOLFMQTT_MULTITHREAD
                , NULL
            #endif
                );
            if (rc == MQTT_CODE_CONTINUE) {
                /* A zero-progress release under WOLFMQTT_ALLOW_NODATA_UNLOCK
                 * resets to BEGIN, but the WILLTOPICREQ was already consumed:
                 * retry from the send phase, not the request wait. */
                if (will->stat.write == MQTT_MSG_BEGIN) {
                    will->stat.write = MQTT_MSG_HEADER;
                }
                return rc;
            }

            /* reset state */
            will->stat.write = MQTT_MSG_BEGIN;
            break;
        }

        case MQTT_MSG_AUTH:
        case MQTT_MSG_PAYLOAD2:
        case MQTT_MSG_ACK:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_WillTopic: Invalid write state %d!", will->stat.write);
        #endif
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
            break;
        }
    } /* switch (will->stat.write) */

    return rc;
}

static int SN_WillMessage(MqttClient *client, SN_Will *will)
{
    int rc = 0;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* See SN_WillTopic: will->stat.write tracks progress so the pending
     * response is added exactly once and a CONTINUE retry resumes
     * instead of re-adding it (which would be rejected as a duplicate). */
    switch (will->stat.write)
    {
        case MQTT_MSG_BEGIN:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            rc = wm_SemLock(&client->lockClient);
            if (rc == 0) {
                /* inform other threads of expected response */
                rc = MqttClient_RespList_Add(client,
                        (MqttPacketType)SN_MSG_TYPE_WILLMSGREQ, 0,
                        &will->pendResp, &will->resp.msgResp);
                wm_SemUnlock(&client->lockClient);
            }
            if (rc != 0) {
                return rc; /* Error locking client */
            }
        #endif

            will->stat.write = MQTT_MSG_WAIT;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        {
            /* Wait for Will Message Request */
            rc = SN_Client_WaitType(client, &will->resp.msgResp,
                    SN_MSG_TYPE_WILLMSGREQ, 0, client->cmd_timeout_ms);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                return rc; /* stay in MQTT_MSG_WAIT, do not re-add */
            }
        #endif

        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif

            if (rc != 0) {
                /* reset state on error */
                will->stat.write = MQTT_MSG_BEGIN;
                return rc;
            }

            will->stat.write = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        {
            /* Take write ownership; a write already in progress on this thread
             * is reported as MQTT_CODE_CONTINUE instead of deadlocking. */
            rc = MqttWriteStart(client, &will->stat);
            if (rc != 0) {
                return rc;
            }
            /* Encode Will Message */
            rc = SN_Encode_WillMsg(client->tx_buf,
                client->tx_buf_len, will);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("EncodePacket: Len %d, Type %s (%d)",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLMSG),
                SN_MSG_TYPE_WILLMSG);
        #endif
            if (rc > 0) {
                client->write.len = rc;
                will->stat.write = MQTT_MSG_PAYLOAD;
            }
            else {
                CLIENT_FORCE_ZERO(client->tx_buf, client->write.len);
                MqttWriteStop(client, &will->stat);
                will->stat.write = MQTT_MSG_BEGIN;
                break;
            }
        }
        FALL_THROUGH;

        case MQTT_MSG_PAYLOAD:
        {
            int xfer;

            /* Send Will Message packet. The length is snapshotted under
             * ownership so the completion check cannot be skewed by another
             * sender once the writer is released. */
            xfer = client->write.len;
            rc = MqttPacket_Write(client, client->tx_buf, xfer);
            if (rc == MQTT_CODE_CONTINUE) {
            #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
                if (client->write.total == 0) {
                    /* Nothing reached the transport: scrub and release the
                     * writer so other operations proceed; re-encode next. */
                    CLIENT_FORCE_ZERO(client->tx_buf, xfer);
                    MqttWriteStop(client, &will->stat);
                    will->stat.write = MQTT_MSG_HEADER;
                }
            #endif
                /* Unfinished write: tx_buf still holds the will payload and is
                 * needed to resume, so keep ownership, do not scrub, and resume
                 * here on the next call rather than re-encoding. */
                return rc;
            }

            /* Scrub the will payload from tx_buf before releasing the writer so
             * another thread cannot observe residual plaintext. */
            CLIENT_FORCE_ZERO(client->tx_buf, xfer);
            MqttWriteStop(client, &will->stat);
            if (rc == xfer) {
                rc = 0;
            }

            /* reset state */
            will->stat.write = MQTT_MSG_BEGIN;
            break;
        }

        case MQTT_MSG_AUTH:
        case MQTT_MSG_PAYLOAD2:
        case MQTT_MSG_ACK:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_WillMessage: Invalid write state %d!",
                will->stat.write);
        #endif
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
            break;
        }
    } /* switch (will->stat.write) */

    return rc;
}

/* Progress of the two-step SN Last-Will exchange, stored in
 * SN_Connect.will_done. The "all done" value is kept at 1 to preserve the
 * previous boolean use of this field. */
enum {
    SN_WILL_DONE_NONE  = 0, /* will exchange not started */
    SN_WILL_DONE_ALL   = 1, /* will topic and message both sent */
    SN_WILL_DONE_TOPIC = 2  /* will topic sent, message still pending */
};

int SN_Client_Connect(MqttClient *client, SN_Connect *mc_connect)
{
    int rc = 0;

    /* Validate required arguments */
    if ((client == NULL) || (mc_connect == NULL)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (mc_connect->stat.write == MQTT_MSG_BEGIN) {

        mc_connect->will_done = SN_WILL_DONE_NONE;

        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &mc_connect->stat);
        if (rc != 0) {
            return rc;
        }

    /* Encode the connect packet */
        rc = SN_Encode_Connect(client->tx_buf, client->tx_buf_len, mc_connect);
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
        rc, SN_Packet_TypeDesc(SN_MSG_TYPE_CONNECT),
        SN_MSG_TYPE_CONNECT, 0, 0);
#endif
        if (rc <= 0) {
            MqttWriteStop(client, &mc_connect->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_CONNACK, 0,
                    &mc_connect->pendResp, &mc_connect->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &mc_connect->stat);
            return rc; /* Error locking client */
        }
    #endif

        mc_connect->stat.write = MQTT_MSG_HEADER;
    }
    if (mc_connect->stat.write == MQTT_MSG_HEADER) {
        /* Send connect packet */
        rc = SN_Client_WriteOwned(client, &mc_connect->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , &mc_connect->pendResp
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }

        mc_connect->stat.write = MQTT_MSG_WAIT;
    }

    if ((mc_connect->enable_lwt == 1) &&
        (mc_connect->will_done != SN_WILL_DONE_ALL)) {
        /* If the will is enabled, then the gateway requests the topic and
           message in separate packets. will_done tracks how far the two-step
           exchange has progressed so a non-blocking retry does not restart a
           sub-step that already completed (which would re-add its pending
           response). */
        if (mc_connect->will_done == SN_WILL_DONE_NONE) {
            rc = SN_WillTopic(client, &mc_connect->will);
            if (rc != 0) {
                return rc;
            }
            mc_connect->will_done = SN_WILL_DONE_TOPIC;
        }

        rc = SN_WillMessage(client, &mc_connect->will);
        if (rc != 0) {
            return rc;
        }
        mc_connect->will_done = SN_WILL_DONE_ALL;
    }

    /* Wait for connect ack packet */
    rc = SN_Client_WaitType(client, &mc_connect->ack,
            SN_MSG_TYPE_CONNACK, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &mc_connect->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    mc_connect->stat.write = MQTT_MSG_BEGIN;

    /* CONNACK was received and decoded, but the gateway refused the
     * connection. The specific reason is in mc_connect->ack.return_code
     * (SN_ReturnCodes). */
    if (rc == MQTT_CODE_SUCCESS &&
            mc_connect->ack.return_code != SN_RC_ACCEPTED) {
        rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_CONNECT_REFUSED);
    }

    return rc;
}

int SN_Client_WillTopicUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0;

    /* Validate required arguments */
    if ((client == NULL) || (will == NULL)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (will->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &will->stat);
        if (rc != 0) {
            return rc;
        }

        /* Encode Will Topic Update */
        rc = SN_Encode_WillTopicUpdate(client->tx_buf,
                client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPICUPD),
            SN_MSG_TYPE_WILLTOPICUPD);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &will->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_WILLTOPICRESP,
                    0, &will->pendResp, &will->resp.topicResp);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &will->stat);
            return rc; /* Error locking client */
        }
    #endif

        will->stat.write = MQTT_MSG_HEADER;
    }
    if (will->stat.write == MQTT_MSG_HEADER) {
        /* Send Will Topic Update packet */
        rc = SN_Client_WriteOwned(client, &will->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , &will->pendResp
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }

        will->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for Will Topic Update Response packet */
    rc = SN_Client_WaitType(client, &will->resp.topicResp,
            SN_MSG_TYPE_WILLTOPICRESP, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &will->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    will->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_WillMsgUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0;

    /* Validate required arguments */
    if ((client == NULL) || (will == NULL)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (will->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &will->stat);
        if (rc != 0) {
            return rc;
        }
        /* Encode Will Message Update */
        rc = SN_Encode_WillMsgUpdate(client->tx_buf,
                client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLMSGUPD),
            SN_MSG_TYPE_WILLMSGUPD);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &will->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_WILLMSGRESP,
                    0, &will->pendResp, &will->resp.msgResp);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            CLIENT_FORCE_ZERO(client->tx_buf, client->write.len);
            MqttWriteStop(client, &will->stat);
            return rc; /* Error locking client */
        }
    #endif

        will->stat.write = MQTT_MSG_HEADER;
    }
    if (will->stat.write == MQTT_MSG_HEADER) {
        int xfer;

        /* The encoded WILLMSGUPD holds a possibly secret will payload that must
         * not stay in tx_buf across a return, so it is re-encoded each pass:
         * a partial send scrubs, the next pass regenerates the identical bytes,
         * and MqttPacket_Write resumes from the preserved write offset. */
        rc = SN_Encode_WillMsgUpdate(client->tx_buf, client->tx_buf_len, will);
        if (rc <= 0) {
            MqttWriteStop(client, &will->stat);
        #ifdef WOLFMQTT_MULTITHREAD
            SN_Client_UnlinkPendResp(client, &will->pendResp);
        #endif
            will->stat.write = MQTT_MSG_BEGIN;
            return rc;
        }
        client->write.len = rc;
        xfer = rc;
        rc = MqttPacket_Write(client, client->tx_buf, xfer);
        if (rc == MQTT_CODE_CONTINUE) {
            /* Never leave the will payload in tx_buf between calls; the resume
             * pass re-encodes it. */
            CLIENT_FORCE_ZERO(client->tx_buf, xfer);
        #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
            if (client->write.total == 0) {
                /* Nothing reached the transport: release the writer and the
                 * pending response so other operations proceed. */
                MqttWriteStop(client, &will->stat);
            #ifdef WOLFMQTT_MULTITHREAD
                SN_Client_UnlinkPendResp(client, &will->pendResp);
            #endif
                will->stat.write = MQTT_MSG_BEGIN;
            }
        #endif
            /* Unfinished write: keep ownership and the pending response and
             * resume here on the next call. */
            return rc;
        }
        /* Scrub the will payload from tx_buf before releasing the writer so
         * another thread, or a later memory/core-dump inspection, cannot
         * recover residual plaintext. */
        CLIENT_FORCE_ZERO(client->tx_buf, xfer);
        MqttWriteStop(client, &will->stat);
        if (rc != xfer) {
        #ifdef WOLFMQTT_MULTITHREAD
            SN_Client_UnlinkPendResp(client, &will->pendResp);
        #endif
            will->stat.write = MQTT_MSG_BEGIN;
            return rc;
        }

        will->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for Will Message Update Response packet */
    rc = SN_Client_WaitType(client, &will->resp.msgResp,
            SN_MSG_TYPE_WILLMSGRESP, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &will->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    will->stat.write = MQTT_MSG_BEGIN;

    return rc;

}

int SN_Client_Subscribe(MqttClient *client, SN_Subscribe *subscribe)
{
    int rc = -1;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (subscribe->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &subscribe->stat);
        if (rc != 0) {
            return rc;
        }

        /* Encode the subscribe packet */
        rc = SN_Encode_Subscribe(client->tx_buf, client->tx_buf_len,
                subscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), QoS %d",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_SUBSCRIBE),
            SN_MSG_TYPE_SUBSCRIBE, subscribe->qos);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &subscribe->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_SUBACK, subscribe->packet_id,
                    &subscribe->pendResp, &subscribe->subAck);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &subscribe->stat);
            return rc; /* Error locking client */
        }
    #endif

        subscribe->stat.write = MQTT_MSG_HEADER;
    }
    if (subscribe->stat.write == MQTT_MSG_HEADER) {
        /* Send subscribe packet */
        rc = SN_Client_WriteOwned(client, &subscribe->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , &subscribe->pendResp
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }

        subscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for subscribe ack packet */
    rc = SN_Client_WaitType(client, &subscribe->subAck,
            SN_MSG_TYPE_SUBACK, subscribe->packet_id, client->cmd_timeout_ms);

#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &subscribe->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    subscribe->stat.write = MQTT_MSG_BEGIN;

    /* SUBACK was received and decoded, but the gateway rejected the
     * subscription. The specific reason is in subscribe->subAck.return_code
     * (SN_ReturnCodes): SN_RC_CONGESTION, SN_RC_INVTOPICNAME, or
     * SN_RC_NOTSUPPORTED. Unlike v3.1.1/v5 SUBSCRIBE there is only a single
     * per-packet topic, so the one return code is the whole result. Surface a
     * distinct error so a caller checking only the function return value does
     * not wait for messages the gateway will never deliver. */
    if (rc == MQTT_CODE_SUCCESS &&
            subscribe->subAck.return_code != SN_RC_ACCEPTED) {
        rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SUBSCRIBE_REJECTED);
    }

    return rc;
}

int SN_Client_Publish(MqttClient *client, SN_Publish *publish)
{
    int rc = MQTT_CODE_SUCCESS;
    SN_MsgType resp_type;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    switch (publish->stat.write)
    {
        case MQTT_MSG_BEGIN:
        {
            /* Take write ownership; a write already in progress on this thread
             * is reported as MQTT_CODE_CONTINUE instead of deadlocking. */
            rc = MqttWriteStart(client, &publish->stat);
            if (rc != 0) {
                return rc;
            }

            /* Encode the publish packet */
            rc = SN_Encode_Publish(client->tx_buf, client->tx_buf_len,
                    publish);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d,"
                    " QoS %d",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PUBLISH),
                SN_MSG_TYPE_PUBLISH, publish->packet_id,
                publish->qos);
        #endif
            if (rc <= 0) {
                MqttWriteStop(client, &publish->stat);
                return rc;
            }

            client->write.len = rc;
            publish->buffer_pos = 0;

        #ifdef WOLFMQTT_MULTITHREAD
            if ((publish->qos == MQTT_QOS_1) ||
                (publish->qos == MQTT_QOS_2)) {
                resp_type = (publish->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBCOMP;

                rc = wm_SemLock(&client->lockClient);
                if (rc == 0) {
                    /* inform other threads of expected response */
                    rc = MqttClient_RespList_Add(client,
                            (MqttPacketType)resp_type, publish->packet_id,
                            &publish->pendResp, &publish->resp);
                    wm_SemUnlock(&client->lockClient);
                }
                if (rc != 0) {
                    MqttWriteStop(client, &publish->stat);
                    return rc; /* Error locking client */
                }
            }
        #endif

            publish->stat.write = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        case MQTT_MSG_PAYLOAD:
        case MQTT_MSG_PAYLOAD2:
        {
            int xfer;

            /* Send packet and payload. The length is snapshotted under
             * ownership so the completion check cannot be skewed by another
             * sender once the writer is released. */
            xfer = client->write.len;
            rc = MqttPacket_Write(client, client->tx_buf, xfer);
            if (rc == MQTT_CODE_CONTINUE) {
            #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
                if (client->write.total == 0) {
                    /* Nothing reached the transport: release the writer so
                     * other operations proceed; re-encode on the next call. */
                    MqttWriteStop(client, &publish->stat);
                #ifdef WOLFMQTT_MULTITHREAD
                    SN_Client_UnlinkPendResp(client, &publish->pendResp);
                #endif
                    publish->stat.write = MQTT_MSG_BEGIN;
                }
            #endif
                /* Unfinished write: keep ownership and the pending response
                 * and resume here on the next call. */
                return rc;
            }
            MqttWriteStop(client, &publish->stat);

            if (rc < 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                SN_Client_UnlinkPendResp(client, &publish->pendResp);
            #endif
                /* The writer was released and its state cleared, so the object
                 * must re-encode on its next use rather than resume. */
                publish->stat.write = MQTT_MSG_BEGIN;
                return rc;
            }

            if (rc == xfer) {
                rc = MQTT_CODE_SUCCESS;
            }
            else {
                rc = -1;
            }

            /* if not expecting a reply, the reset state and exit */
            if ((publish->qos == MQTT_QOS_0) ||
                (publish->qos == MQTT_QOS_3)) {
                break;
            }

            publish->stat.write = MQTT_MSG_WAIT;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        {
            /* Handle QoS */
            if ((publish->qos == MQTT_QOS_1) ||
                (publish->qos == MQTT_QOS_2)) {

                /* Determine packet type to wait for */
                resp_type = (publish->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBCOMP;

                /* Wait for publish response packet */
                rc = SN_Client_WaitType(client, &publish->resp,
                    resp_type, publish->packet_id, client->cmd_timeout_ms);
            #ifdef WOLFMQTT_NONBLOCK
                if (rc == MQTT_CODE_CONTINUE)
                    break;
            #endif
            #ifdef WOLFMQTT_MULTITHREAD
                if (wm_SemLock(&client->lockClient) == 0) {
                    MqttClient_RespList_Remove(client, &publish->pendResp);
                    wm_SemUnlock(&client->lockClient);
                }
            #endif

                publish->return_code = publish->resp.return_code;
            }

            break;
        }

        case MQTT_MSG_ACK:
        case MQTT_MSG_AUTH:
        default:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_Publish: Invalid state %d!",
                publish->stat.write);
        #endif
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
            break;
    } /* switch (publish->stat) */

    /* reset state */
    if (rc != MQTT_CODE_CONTINUE)
    {
        publish->stat.write = MQTT_MSG_BEGIN;
    }
    if (rc > 0) {
        rc = MQTT_CODE_SUCCESS;
    }

    return rc;
}

int SN_Client_Unsubscribe(MqttClient *client, SN_Unsubscribe *unsubscribe)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (unsubscribe->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &unsubscribe->stat);
        if (rc != 0) {
            return rc;
        }

        /* Encode the subscribe packet */
        rc = SN_Encode_Unsubscribe(client->tx_buf, client->tx_buf_len,
            unsubscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_UNSUBSCRIBE),
            SN_MSG_TYPE_UNSUBSCRIBE);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &unsubscribe->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_UNSUBACK,
                    unsubscribe->packet_id, &unsubscribe->pendResp,
                    &unsubscribe->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &unsubscribe->stat);
            return rc; /* Error locking client */
        }
    #endif

        unsubscribe->stat.write = MQTT_MSG_HEADER;
    }
    if (unsubscribe->stat.write == MQTT_MSG_HEADER) {
        /* Send unsubscribe packet */
        rc = SN_Client_WriteOwned(client, &unsubscribe->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , &unsubscribe->pendResp
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }

        unsubscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for unsubscribe ack packet */
    rc = SN_Client_WaitType(client, &unsubscribe->ack,
            SN_MSG_TYPE_UNSUBACK, unsubscribe->packet_id,
            client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0) {
            MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
            wm_SemUnlock(&client->lockClient);
        }
    #endif

    /* reset state */
    unsubscribe->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Register(MqttClient *client, SN_Register *regist)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || regist == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (regist->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &regist->stat);
        if (rc != 0) {
            return rc;
        }

        /* Encode the register packet */
        rc = SN_Encode_Register(client->tx_buf, client->tx_buf_len, regist);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_REGISTER),
            SN_MSG_TYPE_REGISTER);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &regist->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_REGACK,
                    regist->packet_id, &regist->pendResp, &regist->regack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &regist->stat);
            return rc; /* Error locking client */
        }
    #endif

        regist->stat.write = MQTT_MSG_HEADER;
    }
    if (regist->stat.write == MQTT_MSG_HEADER) {
        /* Send register packet */
        rc = SN_Client_WriteOwned(client, &regist->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , &regist->pendResp
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }

        regist->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for register acknowledge packet */
    rc = SN_Client_WaitType(client, &regist->regack,
            SN_MSG_TYPE_REGACK, regist->packet_id, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &regist->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    regist->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

static int SN_Client_PingInternalClaim(MqttClient *client)
{
#ifdef WOLFMQTT_MULTITHREAD
    int rc;

    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
        if (client->pingSN_busy) {
            rc = MQTT_CODE_CONTINUE;
        }
        else {
            client->pingSN_busy = 1;
        }
        wm_SemUnlock(&client->lockClient);
    }
    return rc;
#else
    if (client->pingSN_busy) {
        return MQTT_CODE_CONTINUE;
    }
    client->pingSN_busy = 1;
    return MQTT_CODE_SUCCESS;
#endif
}

static void SN_Client_PingInternalRelease(MqttClient *client)
{
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        client->pingSN_busy = 0;
        wm_SemUnlock(&client->lockClient);
    }
#else
    client->pingSN_busy = 0;
#endif
}

int SN_Client_Ping(MqttClient *client, SN_PingReq *ping)
{
    int rc;
    int internal_ping = 0;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (ping == NULL) {
        rc = SN_Client_PingInternalClaim(client);
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }
        internal_ping = 1;
        ping = &client->pingSN;
        /* write == BEGIN means no NULL-ping exchange is active. Clear any
         * terminal read state before this client-owned object is reused. */
        if (ping->stat.write == MQTT_MSG_BEGIN) {
            XMEMSET(ping, 0, sizeof(*ping));
        }
    }

    if (ping->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &ping->stat);
        if (rc != 0) {
            goto ping_done;
        }

        /* Encode the ping packet as a request */
        rc = SN_Encode_Ping(client->tx_buf, client->tx_buf_len, ping,
                SN_MSG_TYPE_PING_REQ);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PING_REQ),
            SN_MSG_TYPE_PING_REQ);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &ping->stat);
            goto ping_done;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_PING_RESP, 0,
                    &ping->pendResp, NULL);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &ping->stat);
            goto ping_done; /* Error locking client */
        }
    #endif

        ping->stat.write = MQTT_MSG_HEADER;
    }
    if (ping->stat.write == MQTT_MSG_HEADER) {
        /* Send ping req packet */
        rc = SN_Client_WriteOwned(client, &ping->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , &ping->pendResp
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            goto ping_done;
        }

        ping->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for ping resp packet */
    rc = SN_Client_WaitType(client, ping,
            SN_MSG_TYPE_PING_RESP, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE) {
        goto ping_done;
    }
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &ping->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    ping->stat.write = MQTT_MSG_BEGIN;

ping_done:
    if (internal_ping) {
        /* This is a per-call re-entry guard, not ownership of the persistent
         * ping state. Release it on CONTINUE so the next invocation can resume
         * client->pingSN while concurrent calls are still rejected. */
        SN_Client_PingInternalRelease(client);
    }
    return rc;
}

/* Per-call claim on the client-owned disconnectSN, mirroring the NULL ping's
 * pingSN_busy: it rejects re-entry and concurrent callers for the duration of
 * one call, while write ownership serializes the resumable send itself. */
static int SN_Client_DisconnectInternalClaim(MqttClient *client)
{
#ifdef WOLFMQTT_MULTITHREAD
    int rc;

    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
        if (client->disconnectSN_busy) {
            rc = MQTT_CODE_CONTINUE;
        }
        else {
            client->disconnectSN_busy = 1;
        }
        wm_SemUnlock(&client->lockClient);
    }
    return rc;
#else
    if (client->disconnectSN_busy) {
        return MQTT_CODE_CONTINUE;
    }
    client->disconnectSN_busy = 1;
    return MQTT_CODE_SUCCESS;
#endif
}

static void SN_Client_DisconnectInternalRelease(MqttClient *client)
{
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        client->disconnectSN_busy = 0;
        wm_SemUnlock(&client->lockClient);
    }
#else
    client->disconnectSN_busy = 0;
#endif
}

int SN_Client_Disconnect(MqttClient *client)
{
    int rc;

    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    rc = SN_Client_DisconnectInternalClaim(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
    /* A plain disconnect uses the client-owned object so a partial write keeps
     * its resume position across MQTT_CODE_CONTINUE. write == BEGIN means no
     * exchange is active, so stale terminal state is cleared before reuse. */
    if (client->disconnectSN.stat.write == MQTT_MSG_BEGIN) {
        XMEMSET(&client->disconnectSN, 0, sizeof(client->disconnectSN));
    }
    rc = SN_Client_Disconnect_ex(client, &client->disconnectSN);
    /* Release the per-call claim on every result, including CONTINUE, so the
     * next invocation can resume while concurrent calls are still rejected. */
    SN_Client_DisconnectInternalRelease(client);
    return rc;
}

int SN_Client_Disconnect_ex(MqttClient *client, SN_Disconnect *disconnect)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    if (disconnect == NULL) {
        /* A plain disconnect goes through the guarded wrapper, which claims the
         * client-owned disconnectSN for this call and passes it back here. */
        return SN_Client_Disconnect(client);
    }

    if (disconnect->stat.write == MQTT_MSG_BEGIN) {
        /* Take write ownership; a write already in progress on this thread is
         * reported as MQTT_CODE_CONTINUE instead of deadlocking on lockSend. */
        rc = MqttWriteStart(client, &disconnect->stat);
        if (rc != 0) {
            return rc;
        }

        /* Encode the disconnect packet */
        rc = SN_Encode_Disconnect(client->tx_buf, client->tx_buf_len,
                disconnect);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_DISCONNECT),
            SN_MSG_TYPE_DISCONNECT);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &disconnect->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        if (disconnect->sleepTmr != 0) {
            rc = wm_SemLock(&client->lockClient);
            if (rc == 0) {
                /* inform other threads of expected response */
                rc = MqttClient_RespList_Add(client,
                        (MqttPacketType)SN_MSG_TYPE_DISCONNECT, 0,
                        &disconnect->pendResp, NULL);
                wm_SemUnlock(&client->lockClient);
            }
            if (rc != 0) {
                MqttWriteStop(client, &disconnect->stat);
                return rc; /* Error locking client */
            }
        }
    #endif

        disconnect->stat.write = MQTT_MSG_HEADER;
    }
    if (disconnect->stat.write == MQTT_MSG_HEADER) {
        /* Send disconnect packet */
        rc = SN_Client_WriteOwned(client, &disconnect->stat
        #ifdef WOLFMQTT_MULTITHREAD
            , (disconnect->sleepTmr != 0) ? &disconnect->pendResp : NULL
        #endif
            );
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }

        /* Only a sleep request is acknowledged by the gateway */
        if (disconnect->sleepTmr == 0) {
            disconnect->stat.write = MQTT_MSG_BEGIN;
            return MQTT_CODE_SUCCESS;
        }

        disconnect->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for the gateway's DISCONNECT acknowledging the sleep request */
    rc = SN_Client_WaitType(client, disconnect,
            SN_MSG_TYPE_DISCONNECT, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE) {
        return rc;
    }
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &disconnect->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    disconnect->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_WaitMessage_ex(MqttClient *client, SN_Object* packet_obj,
        int timeout_ms)
{
    return SN_Client_WaitType(client, packet_obj,
        SN_MSG_TYPE_ANY, 0, timeout_ms);
}

int SN_Client_WaitMessage(MqttClient *client, int timeout_ms)
{
    if (client == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    return SN_Client_WaitMessage_ex(client, &client->msgSN, timeout_ms);
}

#endif /* defined WOLFMQTT_SN */
