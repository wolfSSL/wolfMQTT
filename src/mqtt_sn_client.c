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
static int SN_Client_HandlePacket(MqttClient* client, SN_MsgType packet_type,
    void* packet_obj, int timeout)
{
    int rc = MQTT_CODE_SUCCESS;
    word16 packet_id = 0;

    (void)timeout;

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
                   handle new topic ID assignment. */
                if (client->reg_cb != NULL) {
                     rc = client->reg_cb(reg_s.topicId,
                            reg_s.topicName, client->reg_ctx);
                     /* Set the regack return code */
                     reg_s.regack.return_code = (rc >= 0) ? SN_RC_ACCEPTED :
                             SN_RC_INVTOPICNAME;
                }

            #ifdef WOLFMQTT_MULTITHREAD
                /* Lock send socket mutex */
                rc = wm_SemLock(&client->lockSend);
                if (rc != 0) {
                    return rc;
                }
            #endif

                /* Encode the register acknowledgment */
                rc = SN_Encode_RegAck(client->tx_buf, client->tx_buf_len,
                        &reg_s.regack);
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d",
                    rc, SN_Packet_TypeDesc(SN_MSG_TYPE_REGACK),
                    SN_MSG_TYPE_REGACK, reg_s.packet_id);
            #endif
                if (rc <= 0) {
                #ifdef WOLFMQTT_MULTITHREAD
                    wm_SemUnlock(&client->lockSend);
                #endif
                    return rc;
                }
                client->write.len = rc;

                /* Send regack packet */
                rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
                if (rc != client->write.len) {
                #ifdef WOLFMQTT_MULTITHREAD
                    wm_SemUnlock(&client->lockSend);
                #endif
                    return rc;
                }
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
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

            /* Issue callback for new message */
            if (client->msg_cb) {
                /* if using the temp publish message buffer,
                   then populate message context with client context */
                if (&client->msgSN.publish == p_pub)
                    p_pub->ctx = client->ctx;
                rc = client->msg_cb(client, (MqttMessage*)p_pub, 1, 1);
                if (rc != MQTT_CODE_SUCCESS) {
                    return rc;
                };
            }

            /* Handle Qos */
            if (p_pub->qos > MQTT_QOS_0) {
                SN_MsgType type;

                packet_id = p_pub->packet_id;

                /* Determine packet type to write */
                type = (p_pub->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBREC;
                p_pub->resp.packet_id = packet_id;

            #ifdef WOLFMQTT_MULTITHREAD
                /* Lock send socket mutex */
                rc = wm_SemLock(&client->lockSend);
                if (rc != 0) {
                    return rc;
                }
            #endif

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
                #ifdef WOLFMQTT_MULTITHREAD
                    wm_SemUnlock(&client->lockSend);
                #endif
                    return rc;
                }
                client->write.len = rc;

                /* Send packet */
                rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
            }
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

            #ifdef WOLFMQTT_MULTITHREAD
                /* Lock send socket mutex */
                rc = wm_SemLock(&client->lockSend);
                if (rc != 0) {
                    return rc;
                }
            #endif

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
                #ifdef WOLFMQTT_MULTITHREAD
                    wm_SemUnlock(&client->lockSend);
                #endif
                    return rc;
                }
                client->write.len = rc;

                /* Send packet */
                rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
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

        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif

            /* Encode the ping packet as a response */
            rc = SN_Encode_Ping(client->tx_buf, client->tx_buf_len, NULL,
                    SN_MSG_TYPE_PING_RESP);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PING_RESP),
                SN_MSG_TYPE_PING_RESP);
        #endif
            if (rc <= 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                return rc;
            }
            client->write.len = rc;

            /* Send ping resp packet */
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            if (rc != client->write.len) {
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                return rc;
            }
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif

            break;
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
            break;
        case SN_MSG_TYPE_WILLTOPICUPD:
        case SN_MSG_TYPE_WILLTOPICRESP:
        case SN_MSG_TYPE_WILLMSGUPD:
        case SN_MSG_TYPE_WILLMSGRESP:
            objSz = sizeof(SN_Will);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
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
    void* use_packet_obj = NULL;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* all packet type structures must have MqttMsgStat at top */
    mms_stat = (MqttMsgStat*)packet_obj;

wait_again:

    /* initialize variables */
    packet_id = 0;
    packet_type = SN_MSG_TYPE_RESERVED;
#ifdef WOLFMQTT_MULTITHREAD
    pendResp = NULL;
#endif
    waitMatchFound = 0;

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

            /* Clear shared union for next call */
            MqttSNClient_PacketReset(packet_type, &client->msg);

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
                    timeout_ms);

        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
        #endif

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

#ifdef WOLFMQTT_NONBLOCK
    /* if nonblocking and some data has been read, do not release read lock */
    if (rc == MQTT_CODE_CONTINUE && mms_stat->read > MQTT_MSG_WAIT) {
        return rc;
    }
#endif

    MqttReadStop(client, mms_stat);

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

int SN_Client_SearchGW(MqttClient *client, SN_SearchGw *search)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || search == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (search->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the search packet */
        rc = SN_Encode_SearchGW(client->tx_buf, client->tx_buf_len,
                search->radius);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_SEARCHGW),
            SN_MSG_TYPE_SEARCHGW);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send search for gateway packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &search->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

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
     * will->stat.write so that, under WOLFMQTT_NONBLOCK, a MQTT_CODE_CONTINUE
     * return resumes where it left off rather than re-running the whole
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
            rc = SN_Client_WaitType(client, will,
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
        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif

            /* Encode Will Topic */
            rc = SN_Encode_WillTopic(client->tx_buf, client->tx_buf_len,
                    will);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("EncodePacket: Len %d, Type %s (%d)",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPIC),
                SN_MSG_TYPE_WILLTOPIC);
        #endif
            if (rc > 0) {
                /* Send Will Topic packet */
                client->write.len = rc;
                rc = MqttPacket_Write(client, client->tx_buf,
                        client->write.len);
                if (rc == client->write.len) {
                    rc = 0;
                }
            }
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif

        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                return rc; /* resume send on next call */
            }
        #endif

            /* reset state */
            will->stat.write = MQTT_MSG_BEGIN;
            break;
        }

        case MQTT_MSG_AUTH:
        case MQTT_MSG_PAYLOAD:
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
     * response is added exactly once and a WOLFMQTT_NONBLOCK retry resumes
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
        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif
            /* Encode Will Message */
            rc = SN_Encode_WillMsg(client->tx_buf,
                client->tx_buf_len, will);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("EncodePacket: Len %d, Type %s (%d)",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLMSG),
                SN_MSG_TYPE_WILLMSG);
        #endif
            if (rc > 0) {
                /* Send Will Message packet */
                client->write.len = rc;
                rc = MqttPacket_Write(client, client->tx_buf,
                        client->write.len);
                if (rc == client->write.len) {
                    rc = 0;
                }
            }

        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                /* Send not complete: tx_buf still holds the will payload and is
                 * needed to resume, so do not scrub it yet. */
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                return rc; /* resume send on next call */
            }
        #endif

            /* The encoded WILLMSG contains the will payload (potentially
             * sensitive). Scrub tx_buf before releasing lockSend so another
             * thread cannot observe residual plaintext (mirrors the mitigation
             * in MqttClient_Connect). */
            CLIENT_FORCE_ZERO(client->tx_buf, client->write.len);
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif

            /* reset state */
            will->stat.write = MQTT_MSG_BEGIN;
            break;
        }

        case MQTT_MSG_AUTH:
        case MQTT_MSG_PAYLOAD:
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

    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

    /* Encode the connect packet */
        rc = SN_Encode_Connect(client->tx_buf, client->tx_buf_len, mc_connect);
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
        rc, SN_Packet_TypeDesc(SN_MSG_TYPE_CONNECT),
        SN_MSG_TYPE_CONNECT, 0, 0);
#endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send connect packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &mc_connect->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

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
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode Will Topic Update */
        rc = SN_Encode_WillTopicUpdate(client->tx_buf,
                client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPICUPD),
            SN_MSG_TYPE_WILLTOPICUPD);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send Will Topic Update packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

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
        int xfer = 0;
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif
        /* Encode Will Message Update */
        rc = SN_Encode_WillMsgUpdate(client->tx_buf,
                client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLMSGUPD),
            SN_MSG_TYPE_WILLMSGUPD);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send Will Message Update packet. Save write.len into xfer first: the
         * encoded WILLMSGUPD holds will->willMsg (a possibly rotated/secret will
         * payload) in tx_buf, which must be scrubbed before lockSend is released
         * on every return path below.
         *
         * This differs intentionally from MqttClient_Connect and SN_WillMessage:
         * those keep a resume state (MQTT_MSG_HEADER) and so must NOT scrub on
         * MQTT_CODE_CONTINUE, because tx_buf is still needed to finish a partial
         * non-blocking send. This function has no such resume state - it re-runs
         * this whole MQTT_MSG_BEGIN block (re-encoding tx_buf) on every call. A
         * non-blocking partial write returns MQTT_CODE_CONTINUE, which is != xfer
         * and therefore lands in the error branch below; scrubbing there is safe
         * because the next call re-encodes the identical bytes before the write
         * resumes. */
        xfer = client->write.len;
        rc = MqttPacket_Write(client, client->tx_buf, xfer);
        if (rc != xfer) {
            /* Send failed (or returned MQTT_CODE_CONTINUE): scrub the will
             * payload from tx_buf before releasing lockSend so another thread -
             * or a later memory/core-dump inspection - cannot recover residual
             * plaintext. */
            CLIENT_FORCE_ZERO(client->tx_buf, xfer);
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
        /* WILLMSGUPD sent: scrub the will payload from tx_buf before releasing
         * lockSend, for the same reason as the error path above. */
        CLIENT_FORCE_ZERO(client->tx_buf, xfer);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

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
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the subscribe packet */
        rc = SN_Encode_Subscribe(client->tx_buf, client->tx_buf_len,
                subscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), QoS %d",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_SUBSCRIBE),
            SN_MSG_TYPE_SUBSCRIBE, subscribe->qos);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send subscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &subscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

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
        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif

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
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
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
                    wm_SemUnlock(&client->lockSend);
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
            /* Send packet and payload */
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE)
                return rc;
        #endif
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif

            if (rc < 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                if (wm_SemLock(&client->lockClient) == 0) {
                    MqttClient_RespList_Remove(client, &publish->pendResp);
                    wm_SemUnlock(&client->lockClient);
                }
            #endif
                return rc;
            }

            if (rc == client->write.len) {
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
#ifdef WOLFMQTT_NONBLOCK
    if (rc != MQTT_CODE_CONTINUE)
#endif
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
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the subscribe packet */
        rc = SN_Encode_Unsubscribe(client->tx_buf, client->tx_buf_len,
            unsubscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_UNSUBSCRIBE),
            SN_MSG_TYPE_UNSUBSCRIBE);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send unsubscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

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
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the register packet */
        rc = SN_Encode_Register(client->tx_buf, client->tx_buf_len, regist);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_REGISTER),
            SN_MSG_TYPE_REGISTER);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send register packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &regist->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

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

int SN_Client_Ping(MqttClient *client, SN_PingReq *ping)
{
    int rc;
    SN_PingReq loc_ping;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (ping == NULL) {
        XMEMSET(&loc_ping, 0, sizeof(SN_PingReq));
        ping = &loc_ping;
    }

    if (ping->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the ping packet as a request */
        rc = SN_Encode_Ping(client->tx_buf, client->tx_buf_len, ping,
                SN_MSG_TYPE_PING_REQ);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PING_REQ),
            SN_MSG_TYPE_PING_REQ);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
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
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send ping req packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &ping->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif

        ping->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for ping resp packet */
    rc = SN_Client_WaitType(client, ping,
            SN_MSG_TYPE_PING_RESP, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE && ping != &loc_ping) {
        /* Caller owns 'ping': the object (and, under MULTITHREAD, its
         * registered pendResp) lives across calls, so leave the pending
         * response linked and let the caller resume on the next call. */
        return rc;
    }
    /* For the ping==NULL fallback we used the stack-local loc_ping, which
     * cannot persist across calls. Returning CONTINUE here would leave
     * &loc_ping.pendResp linked on client->firstPendResp after this frame
     * unwinds; a later call reuses the stack address, so the stale entry
     * could be dereferenced by MqttClient_CheckPendResp on the receive path
     * (use-after-scope). Fall through to remove the entry before returning,
     * even on a CONTINUE result. */
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &ping->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    ping->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Disconnect(MqttClient *client)
{
    return SN_Client_Disconnect_ex(client, NULL);
}

int SN_Client_Disconnect_ex(MqttClient *client, SN_Disconnect *disconnect)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

#ifdef WOLFMQTT_MULTITHREAD
    /* Lock send socket mutex */
    rc = wm_SemLock(&client->lockSend);
    if (rc != 0) {
        return rc;
    }
#endif

    /* Encode the disconnect packet */
    rc = SN_Encode_Disconnect(client->tx_buf, client->tx_buf_len, disconnect);
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
        rc, SN_Packet_TypeDesc(SN_MSG_TYPE_DISCONNECT),
        SN_MSG_TYPE_DISCONNECT);
#endif
    if (rc <= 0) {
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        return rc;
    }
    client->write.len = rc;

#ifdef WOLFMQTT_MULTITHREAD
    if ((disconnect != NULL) && (disconnect->sleepTmr != 0)) {
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_DISCONNECT, 0,
                    &disconnect->pendResp, NULL);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    }
#endif

    /* Send disconnect packet */
    rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    if (rc != client->write.len) {
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
        if ((disconnect != NULL) && (disconnect->sleepTmr != 0)) {
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &disconnect->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        }
    #endif
        return rc;
    }
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockSend);
#endif

    rc = MQTT_CODE_SUCCESS;

    /* If sleep was set, wait for response disconnect packet */
    if ((disconnect != NULL) && (disconnect->sleepTmr != 0)) {
        rc = SN_Client_WaitType(client, disconnect,
                SN_MSG_TYPE_DISCONNECT, 0, client->cmd_timeout_ms);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE)
            return rc;
    #endif
    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0) {
            MqttClient_RespList_Remove(client, &disconnect->pendResp);
            wm_SemUnlock(&client->lockClient);
        }
    #endif
    }

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
