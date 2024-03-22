/* mqtt_sn_packet.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#include "wolfmqtt/mqtt_sn_client.h"
#include "wolfmqtt/mqtt_sn_packet.h"

#ifdef WOLFMQTT_SN
const char* SN_Packet_TypeDesc(SN_MsgType packet_type)
{
    switch (packet_type) {
        case SN_MSG_TYPE_ADVERTISE:
            return "Advertise";
        case SN_MSG_TYPE_SEARCHGW:
            return "Search gateway";
        case SN_MSG_TYPE_GWINFO:
            return "Gateway info";
        case SN_MSG_TYPE_CONNECT:
            return "Connect";
        case SN_MSG_TYPE_CONNACK:
            return "Connect Ack";
        case SN_MSG_TYPE_WILLTOPICREQ:
            return "Will topic request";
        case SN_MSG_TYPE_WILLTOPIC:
            return "Will topic set";
        case SN_MSG_TYPE_WILLMSGREQ:
            return "Will message request";
        case SN_MSG_TYPE_WILLMSG:
            return "Will message set";
        case SN_MSG_TYPE_REGISTER:
            return "Register";
        case SN_MSG_TYPE_REGACK:
            return "Register Ack";
        case SN_MSG_TYPE_PUBLISH:
            return "Publish";
        case SN_MSG_TYPE_PUBACK:
            return "Publish Ack";
        case SN_MSG_TYPE_PUBCOMP:
            return "Publish complete";
        case SN_MSG_TYPE_PUBREC:
            return "Publish Received";
        case SN_MSG_TYPE_PUBREL:
            return "Publish Release";
        case SN_MSG_TYPE_SUBSCRIBE:
            return "Subscribe";
        case SN_MSG_TYPE_SUBACK:
            return "Subscribe Ack";
        case SN_MSG_TYPE_UNSUBSCRIBE:
            return "Unsubscribe";
        case SN_MSG_TYPE_UNSUBACK:
            return "Unsubscribe Ack";
        case SN_MSG_TYPE_PING_REQ:
            return "Ping Req";
        case SN_MSG_TYPE_PING_RESP:
            return "Ping Resp";
        case SN_MSG_TYPE_DISCONNECT:
            return "Disconnect";
        case SN_MSG_TYPE_WILLTOPICUPD:
            return "Will topic update";
        case SN_MSG_TYPE_WILLTOPICRESP:
            return "WIll topic response";
        case SN_MSG_TYPE_WILLMSGUPD:
            return "Will message update";
        case SN_MSG_TYPE_WILLMSGRESP:
            return "Will message response";
        case SN_MSG_TYPE_ENCAPMSG:
            return "Encapsulated message";
        case SN_MSG_TYPE_ANY:
            return "Any";
        default:
            break;
    }
    return "Unknown";
}

int SN_Decode_Header(byte *rx_buf, int rx_buf_len,
    SN_MsgType* p_packet_type, word16* p_packet_id)
{
    SN_MsgType packet_type;
    word16 total_len;

    if (rx_buf == NULL || rx_buf_len < MQTT_PACKET_HEADER_MIN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_buf++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rx_buf += MqttDecode_Num(rx_buf, &total_len);
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Message Type */
    packet_type = (SN_MsgType)*rx_buf++;

    if (p_packet_type)
        *p_packet_type = packet_type;

    if (p_packet_id) {
        switch(packet_type) {
            case SN_MSG_TYPE_REGACK:
            case SN_MSG_TYPE_PUBACK:
                /* octet 4-5 */
                MqttDecode_Num(rx_buf + 2, p_packet_id);
                break;
            case SN_MSG_TYPE_PUBCOMP:
            case SN_MSG_TYPE_PUBREC:
            case SN_MSG_TYPE_PUBREL:
            case SN_MSG_TYPE_UNSUBACK:
                /* octet 2-3 */
                MqttDecode_Num(rx_buf, p_packet_id);
                break;
            case SN_MSG_TYPE_SUBACK:
                /* octet 5-6 */
                MqttDecode_Num(rx_buf + 3, p_packet_id);
                break;
            case SN_MSG_TYPE_ADVERTISE:
            case SN_MSG_TYPE_SEARCHGW:
            case SN_MSG_TYPE_GWINFO:
            case SN_MSG_TYPE_CONNECT:
            case SN_MSG_TYPE_CONNACK:
            case SN_MSG_TYPE_WILLTOPICREQ:
            case SN_MSG_TYPE_WILLTOPIC:
            case SN_MSG_TYPE_WILLMSGREQ:
            case SN_MSG_TYPE_WILLMSG:
            case SN_MSG_TYPE_REGISTER:
            case SN_MSG_TYPE_PUBLISH:
            case SN_MSG_TYPE_SUBSCRIBE:
            case SN_MSG_TYPE_UNSUBSCRIBE:
            case SN_MSG_TYPE_PING_REQ:
            case SN_MSG_TYPE_PING_RESP:
            case SN_MSG_TYPE_DISCONNECT:
            case SN_MSG_TYPE_WILLTOPICUPD:
            case SN_MSG_TYPE_WILLTOPICRESP:
            case SN_MSG_TYPE_WILLMSGUPD:
            case SN_MSG_TYPE_WILLMSGRESP:
            case SN_MSG_TYPE_ENCAPMSG:
            case SN_MSG_TYPE_RESERVED:
            default:
                *p_packet_id = 0;
                break;
        }
    }

    return (int)total_len;
}

int SN_Decode_Advertise(byte *rx_buf, int rx_buf_len, SN_Advertise *gw_info)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;

    /* Check message type */
    type = *rx_payload++;
    if (total_len != 5) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    if (type != SN_MSG_TYPE_ADVERTISE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode gateway info */
    if (gw_info != NULL) {
        gw_info->gwId = *rx_payload++;

        rx_payload += MqttDecode_Num(rx_payload, &gw_info->duration);
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_SearchGW(byte *tx_buf, int tx_buf_len, byte hops)
{
    int total_len;
    byte *tx_payload = tx_buf;

    /* Packet length is not variable */
    total_len = 3;

    /* Validate required arguments */
    if (tx_buf == NULL || tx_buf_len < total_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Encode length */
    *tx_payload++ = total_len;

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_SEARCHGW;

    /* Encode radius */
    *tx_payload++ = hops;
    (void)tx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_GWInfo(byte *rx_buf, int rx_buf_len, SN_GwInfo *gw_info)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rx_payload += MqttDecode_Num(rx_payload, (word16*)&total_len);
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    if (total_len < 3) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }
    /* Check message type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_GWINFO) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode gateway info */
    if (gw_info != NULL) {
        gw_info->gwId = *rx_payload++;

        /* TODO: validate size of gwAddr */
        if (total_len - 3 > 0) {
            /* The gateway address is only present if sent by a client */
            XMEMCPY(gw_info->gwAddr, rx_payload, total_len - 3);
        }
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

/* Packet Type Encoders/Decoders */
int SN_Encode_Connect(byte *tx_buf, int tx_buf_len, SN_Connect *mc_connect)
{
    word16 total_len, id_len;
    byte flags = 0;
    byte *tx_payload = tx_buf;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (mc_connect == NULL) ||
        (mc_connect->client_id == NULL) || (mc_connect->protocol_level == 0)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    total_len = 6; /* Len + Message Type + Flags + ProtocolID + Duration(2) */

    /* Client ID size */
    id_len = (word16)XSTRLEN(mc_connect->client_id);
    id_len = (id_len <= SN_CLIENTID_MAX_LEN) ? id_len : SN_CLIENTID_MAX_LEN;

    total_len += id_len;

    if (total_len > tx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode length (max size is 29 bytes, so no need for var len check) */
    *tx_payload++ = (byte)total_len;

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_CONNECT;

    /* Encode flags */
    if (mc_connect->clean_session) {
        flags |= SN_PACKET_FLAG_CLEANSESSION;
    }
    if (mc_connect->enable_lwt) {
        flags |= SN_PACKET_FLAG_WILL;
    }
    *tx_payload++ = flags;

    /* Protocol version */
    *tx_payload++ = mc_connect->protocol_level;

    /* Encode duration (keep-alive) */
    tx_payload += MqttEncode_Num(tx_payload, mc_connect->keep_alive_sec);

    /* Encode Client ID */
     XMEMCPY(tx_payload, mc_connect->client_id, id_len);
     tx_payload += id_len;
     (void)tx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_WillTopicReq(byte *rx_buf, int rx_buf_len)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Length and MsgType */
    total_len = *rx_payload++;
    if (total_len != 2) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLTOPICREQ) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

/* An empty WILLTOPIC message is a WILLTOPIC message without Flags and
   WillTopic field (i.e. it is exactly 2 octets long). It is used by a client
   to delete the Will topic and the Will message stored in the server */
int SN_Encode_WillTopic(byte *tx_buf, int tx_buf_len, SN_Will *willTopic)
{
    int total_len;
    byte *tx_payload, flags = 0;

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Length and MsgType */
    total_len = 2;

    /* Determine packet length */
    if (willTopic != NULL) {
        /* Will Topic is a string */
        total_len += (int)XSTRLEN(willTopic->willTopic);

        /* Flags */
        total_len++;

        if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
            /* Length is stored in bytes 1 and 2 */
            total_len += 2;
        }
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode length */
    tx_payload = tx_buf;

    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_WILLTOPIC;

    if (willTopic != NULL) {
        int will_len;

        /* Encode flags */
        flags |= ((willTopic->qos << SN_PACKET_FLAG_QOS_SHIFT) &
                  SN_PACKET_FLAG_QOS_MASK);
        flags |= (willTopic->retain != 0) ? SN_PACKET_FLAG_RETAIN : 0;
        *tx_payload++ = flags;

        /* Encode Will Topic */
        will_len = (int)XSTRLEN(willTopic->willTopic);
        XMEMCPY(tx_payload, willTopic->willTopic, will_len);
        tx_payload += will_len;
    }
    (void)tx_payload;

    return total_len;
}

int SN_Decode_WillMsgReq(byte *rx_buf, int rx_buf_len)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;

    /* Length and MsgType */
    if (total_len != 2){
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* Message Type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLMSGREQ) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_WillMsg(byte *tx_buf, int tx_buf_len, SN_Will *willMsg)
{
    int total_len;
    byte *tx_payload;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (willMsg == NULL)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Length and MsgType */
    total_len = 2;

    /* Determine packet length */
    /* Add Will Message len */
    total_len += willMsg->willMsgLen;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        /* Length is stored in bytes 1 and 2 */
        total_len += 2;
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode length */
    tx_payload = tx_buf;

    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_WILLMSG;

    /* Encode Will Message */
    XMEMCPY(tx_payload, willMsg->willMsg, willMsg->willMsgLen);
    tx_payload += willMsg->willMsgLen;
    (void)tx_payload;

    return total_len;
}

int SN_Encode_WillTopicUpdate(byte *tx_buf, int tx_buf_len, SN_Will *willTopic)
{
    int total_len;
    byte *tx_payload, flags = 0;

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Length and MsgType */
    total_len = 2;

    /* Determine packet length */
    if (willTopic != NULL) {
        /* Will Topic is a string */
        total_len += (int)XSTRLEN(willTopic->willTopic);

        /* Flags */
        total_len++;

        if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
            /* Length is stored in bytes 1 and 2 */
            total_len += 2;
        }
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode length */
    tx_payload = tx_buf;

    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_WILLTOPICUPD;

    if (willTopic != NULL) {
        int will_len;

        /* Encode flags */
        flags |= ((willTopic->qos << SN_PACKET_FLAG_QOS_SHIFT) &
                  SN_PACKET_FLAG_QOS_MASK);
        flags |= (willTopic->retain != 0) ? SN_PACKET_FLAG_RETAIN : 0;
        *tx_payload++ = flags;

        /* Encode Will Topic */
        will_len = (int)XSTRLEN(willTopic->willTopic);
        XMEMCPY(tx_payload, willTopic->willTopic, will_len);
        tx_payload += will_len;
    }
    (void)tx_payload;

    return total_len;

}

int SN_Decode_WillTopicResponse(byte *rx_buf, int rx_buf_len, byte *ret_code)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 3) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLTOPICRESP) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Return Code */
    *ret_code = *rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_WillMsgUpdate(byte *tx_buf, int tx_buf_len, SN_Will *willMsg)
{
    int total_len;
    byte *tx_payload;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (willMsg == NULL)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Length and MsgType */
    total_len = 2;

    /* Determine packet length */
    /* Add Will Message len */
    total_len += willMsg->willMsgLen;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        /* Length is stored in bytes 1 and 2 */
        total_len += 2;
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode length */
    tx_payload = tx_buf;

    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_WILLMSGUPD;

    /* Encode Will Message */
    XMEMCPY(tx_payload, willMsg->willMsg, willMsg->willMsgLen);
    tx_payload += willMsg->willMsgLen;
    (void)tx_payload;

    return total_len;
}

int SN_Decode_WillMsgResponse(byte *rx_buf, int rx_buf_len, byte *ret_code)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 3) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLMSGRESP) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Return Code */
    *ret_code = *rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_ConnectAck(byte *rx_buf, int rx_buf_len,
        SN_ConnectAck *connect_ack)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 3) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_CONNACK) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode variable header */
    if (connect_ack) {
        connect_ack->return_code = *rx_payload++;
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Register(byte *tx_buf, int tx_buf_len, SN_Register *regist)
{
    int total_len, topic_len;
    byte *tx_payload;

    /* Validate required arguments */
    if (tx_buf == NULL || regist == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    /* Topic name is a string */
    total_len = (int)XSTRLEN(regist->topicName);

    /* Length, MsgType, TopicID (2), and packet_id (2) */
    total_len += 6;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        /* Length is stored in bytes 1 and 2 */
        total_len += 2;
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode length */
    tx_payload = tx_buf;

    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_REGISTER;

    /* Encode Topic ID */
    tx_payload += MqttEncode_Num(tx_payload, regist->topicId);

    /* Encode Packet ID */
    tx_payload += MqttEncode_Num(tx_payload, regist->packet_id);

    /* Encode Topic Name */
    topic_len = (int)XSTRLEN(regist->topicName);
    XMEMCPY(tx_payload, regist->topicName, topic_len);
    tx_payload += topic_len;
    (void)tx_payload;

    return total_len;
}

int SN_Decode_Register(byte *rx_buf, int rx_buf_len, SN_Register *regist)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rx_payload += MqttDecode_Num(rx_payload, (word16*)&total_len);
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    if (total_len < 7) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* Check message type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_REGISTER) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    if (regist != NULL) {
        /* Decode Topic ID assigned by GW */
        rx_payload += MqttDecode_Num(rx_payload, &regist->topicId);

        /* Decode packet ID */
        rx_payload += MqttDecode_Num(rx_payload, &regist->packet_id);

        /* Decode Topic Name */
        regist->topicName = (char*)rx_payload;

        /* Terminate the string */
        rx_payload[total_len-6] = '\0';
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_RegAck(byte *tx_buf, int tx_buf_len, SN_RegAck *regack)
{
    int total_len;
    byte *tx_payload;

    /* Validate required arguments */
    if (tx_buf == NULL || regack == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    /* Length, MsgType, TopicID (2), and MsgId (2), Return Code */
    total_len = 7;

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    tx_payload = tx_buf;

    /* Encode length */
    *tx_payload++ = total_len;

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_REGACK;

    /* Encode Topic ID */
    tx_payload += MqttEncode_Num(tx_payload, regack->topicId);

    /* Encode Message ID */
    tx_payload += MqttEncode_Num(tx_payload, regack->packet_id);

    /* Encode Return Code */
    *tx_payload += regack->return_code;

    (void)tx_payload;

    return total_len;
}

int SN_Decode_RegAck(byte *rx_buf, int rx_buf_len, SN_RegAck *regack)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 7) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_REGACK) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    if (regack != NULL) {
        /* Decode Topic ID assigned by GW */
        rx_payload += MqttDecode_Num(rx_payload, &regack->topicId);

        /* Decode packet ID */
        rx_payload += MqttDecode_Num(rx_payload, &regack->packet_id);

        /* Decode return code */
        regack->return_code = *rx_payload++;
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Subscribe(byte *tx_buf, int tx_buf_len, SN_Subscribe *subscribe)
{
    int total_len;
    byte *tx_payload, flags = 0x00;

    /* Validate required arguments */
    if (tx_buf == NULL || subscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    if (subscribe->topic_type == SN_TOPIC_ID_TYPE_NORMAL) {
        /* Topic name is a string */
        total_len = (int)XSTRLEN(subscribe->topicNameId);
    }
    else {
        /* Topic ID or Short name */
        total_len = 2;
    }

    /* Length, MsgType, Flags, and MsgID (2) */
    total_len += 5;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        /* Length is stored in bytes 1 and 2 */
        total_len += 2;
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode length */
    tx_payload = tx_buf;

    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_SUBSCRIBE;

    /* Set flags */
    if (subscribe->duplicate)
        flags |= SN_PACKET_FLAG_DUPLICATE;
    flags |= (SN_PACKET_FLAG_QOS_MASK &
            (subscribe->qos << SN_PACKET_FLAG_QOS_SHIFT));
    flags |= (SN_PACKET_FLAG_TOPICIDTYPE_MASK & subscribe->topic_type);

    *tx_payload++ = flags;

    /* Encode packet ID */
    tx_payload += MqttEncode_Num(tx_payload, subscribe->packet_id);

    /* Encode topic */
    if (subscribe->topic_type == SN_TOPIC_ID_TYPE_NORMAL) {
        /* Topic name is a string */
        XMEMCPY(tx_payload, subscribe->topicNameId, XSTRLEN(subscribe->topicNameId));
    }
    else {
        /* Topic ID */
        XMEMCPY(tx_payload, subscribe->topicNameId, 2);
    }
    (void)tx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_SubscribeAck(byte* rx_buf, int rx_buf_len,
        SN_SubAck *subscribe_ack)
{
    word16 total_len;
    byte* rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 8) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_SUBACK) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Decode SubAck fields */
    if (subscribe_ack) {
        subscribe_ack->flags = *rx_payload++;
        rx_payload += MqttDecode_Num(rx_payload, &subscribe_ack->topicId);
        rx_payload += MqttDecode_Num(rx_payload, &subscribe_ack->packet_id);
        subscribe_ack->return_code = *rx_payload++;
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Publish(byte *tx_buf, int tx_buf_len, SN_Publish *publish)
{
    word16 total_len;
    byte *tx_payload = tx_buf;
    byte flags = 0;

    /* Validate required arguments */
    if (tx_buf == NULL || publish == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    total_len = publish->total_len;

    /* Add length, msgType, flags, topic ID (2), and msgID (2) */
    total_len += 7;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        /* Length is stored in bytes 1 and 2 */
        total_len += 2;
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode header */
    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = (byte)total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    *tx_payload++ = SN_MSG_TYPE_PUBLISH;

    /* Set flags */
    if (publish->duplicate)
        flags |= SN_PACKET_FLAG_DUPLICATE;
    flags |= (SN_PACKET_FLAG_QOS_MASK &
            (publish->qos << SN_PACKET_FLAG_QOS_SHIFT));
    if (publish->retain)
        flags |= SN_PACKET_FLAG_RETAIN;
    flags |= (SN_PACKET_FLAG_TOPICIDTYPE_MASK & publish->topic_type);

    *tx_payload++ = flags;

    /* Encode topic */
    if ((publish->topic_type == SN_TOPIC_ID_TYPE_SHORT) ||
        (publish->topic_type == SN_TOPIC_ID_TYPE_PREDEF)) {
        /* Short and predefined topic names are 2 chars */
        XMEMCPY(tx_payload, publish->topic_name, 2);
        tx_payload += 2;
    }
    else {
        /* Topic ID */
        tx_payload += MqttEncode_Num(tx_payload, *(word16*)publish->topic_name);
    }

    tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);

    /* Encode payload */
    XMEMCPY(tx_payload, publish->buffer, publish->total_len);
    tx_payload += publish->total_len;

    (void)tx_payload;

    /* Return length of packet placed into tx_buf */
    return total_len;
}

int SN_Decode_Publish(byte *rx_buf, int rx_buf_len, SN_Publish *publish)
{
    word16 total_len;
    byte *rx_payload = rx_buf;
    byte flags = 0, type;

    /* Validate required arguments */
    if (rx_buf == NULL || publish == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rx_payload += MqttDecode_Num(rx_payload, &total_len);
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    if (total_len < 7) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* Message Type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_PUBLISH) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    flags = *rx_payload++;

    publish->topic_name = (char*)rx_payload;
    rx_payload += MQTT_DATA_LEN_SIZE;
    publish->topic_name_len = MQTT_DATA_LEN_SIZE;

    rx_payload += MqttDecode_Num(rx_payload, &publish->packet_id);

    /* Set flags */
    publish->duplicate = flags & SN_PACKET_FLAG_DUPLICATE;

    publish->qos = (MqttQoS)((flags & SN_PACKET_FLAG_QOS_MASK) >>
            SN_PACKET_FLAG_QOS_SHIFT);

    publish->retain = flags & SN_PACKET_FLAG_RETAIN;

    publish->topic_type = flags & SN_PACKET_FLAG_TOPICIDTYPE_MASK;

    /* Decode payload */

    publish->total_len = total_len - 7;
    publish->buffer = rx_payload;
    publish->buffer_pos = 0;
    publish->buffer_len = publish->total_len;

    /* Return length of packet read from rx_buf */
    return total_len;
}

int SN_Encode_PublishResp(byte* tx_buf, int tx_buf_len, byte type,
    SN_PublishResp *publish_resp)
{
    int total_len;
    byte *tx_payload = tx_buf;

    /* Validate required arguments */
    if (tx_buf == NULL || publish_resp == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    total_len = (type == SN_MSG_TYPE_PUBACK) ? 7 : 4;

    if (total_len > tx_buf_len)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);

    /* Encode */
    *tx_payload++ = (byte)total_len;

    *tx_payload++ = type;

    if (type == SN_MSG_TYPE_PUBACK) {
        tx_payload += MqttEncode_Num(tx_payload, publish_resp->topicId);
    }

    tx_payload += MqttEncode_Num(tx_payload, publish_resp->packet_id);

    if (type == SN_MSG_TYPE_PUBACK) {
        *tx_payload++ = publish_resp->return_code;
    }
    (void)tx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_PublishResp(byte* rx_buf, int rx_buf_len, byte type,
    SN_PublishResp *publish_resp)
{
    int total_len;
    byte rec_type, *rx_payload = rx_buf;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode */
    total_len = *rx_payload++;

    if(total_len > rx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Validate packet type */
    rec_type = *rx_payload++;
    if (rec_type != type) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    if (publish_resp) {
        if (type == SN_MSG_TYPE_PUBACK) {
            rx_payload += MqttDecode_Num(rx_payload, &publish_resp->topicId);
        }

        rx_payload += MqttDecode_Num(rx_payload, &publish_resp->packet_id);

        if (type == SN_MSG_TYPE_PUBACK) {
            publish_resp->return_code = *rx_payload++;
        }
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Unsubscribe(byte *tx_buf, int tx_buf_len,
        SN_Unsubscribe *unsubscribe)
{
    int total_len;
    byte *tx_payload, flags = 0x00;

    /* Validate required arguments */
    if (tx_buf == NULL || unsubscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    if (unsubscribe->topic_type == SN_TOPIC_ID_TYPE_NORMAL) {
        /* Topic name is a string */
        total_len = (int)XSTRLEN(unsubscribe->topicNameId);
    }
    else {
        /* Topic ID or Short name */
        total_len = 2;
    }

    /* Length, MsgType, Flags, and MsgID (2) */
    total_len += 5;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        /* Length is stored in bytes 1 and 2 */
        total_len += 2;
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode header */
    tx_payload = tx_buf;

    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    *tx_payload++ = SN_MSG_TYPE_UNSUBSCRIBE;

    /* Set flags */
    if (unsubscribe->duplicate)
        flags |= SN_PACKET_FLAG_DUPLICATE;
    flags |= (SN_PACKET_FLAG_QOS_MASK &
            (unsubscribe->qos << SN_PACKET_FLAG_QOS_SHIFT));
    flags |= (SN_PACKET_FLAG_TOPICIDTYPE_MASK & unsubscribe->topic_type);

    *tx_payload++ = flags;

    tx_payload += MqttEncode_Num(tx_payload, unsubscribe->packet_id);

    /* Encode topic */
    if (unsubscribe->topic_type == SN_TOPIC_ID_TYPE_NORMAL) {
        /* Topic name is a string */
        XMEMCPY(tx_payload, unsubscribe->topicNameId,
                XSTRLEN(unsubscribe->topicNameId));
    }
    else {
        /* Topic ID or Short name */
        XMEMCPY(tx_payload, unsubscribe->topicNameId, 2);
    }

    (void)tx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_UnsubscribeAck(byte *rx_buf, int rx_buf_len,
        SN_UnsubscribeAck *unsubscribe_ack)
{
    word16 total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 4) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_UNSUBACK) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode SubAck fields */
    if (unsubscribe_ack) {
        rx_payload += MqttDecode_Num(rx_payload, &unsubscribe_ack->packet_id);
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Disconnect(byte *tx_buf, int tx_buf_len,
        SN_Disconnect* disconnect)
{
    int total_len = 2; /* length and message type */
    byte *tx_payload = tx_buf;;

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if ((disconnect != NULL) && (disconnect->sleepTmr > 0)) {
        total_len += 2; /* Sleep duration is set */
    }

    if (total_len > tx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode message */
    *tx_payload++ = total_len;

    *tx_payload++ = SN_MSG_TYPE_DISCONNECT;

    if ((disconnect != NULL) && (disconnect->sleepTmr > 0)) {
        tx_payload += MqttEncode_Num(tx_payload, disconnect->sleepTmr);
    }
    (void)tx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_Disconnect(byte *rx_buf, int rx_buf_len)
{
    word16 total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 2) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_DISCONNECT) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Ping(byte *tx_buf, int tx_buf_len, SN_PingReq *ping, byte type)
{
    int total_len = 2, clientId_len = 0;
    byte *tx_payload = tx_buf;

    /* Validate required arguments */
    if ((tx_buf == NULL) ||
        ((type != SN_MSG_TYPE_PING_REQ) && (type != SN_MSG_TYPE_PING_RESP))) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if ((type == SN_MSG_TYPE_PING_REQ) && (ping != NULL) &&
        (ping->clientId != NULL)) {
        total_len += clientId_len = (int)XSTRLEN(ping->clientId);
    }

    if (total_len > tx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    *tx_payload++ = (byte)total_len;

    *tx_payload++ = type;

    if (clientId_len > 0) {
        XMEMCPY(tx_payload, ping->clientId, clientId_len);
        tx_payload += clientId_len;
    }
    (void)tx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Decode_Ping(byte *rx_buf, int rx_buf_len)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    total_len = *rx_payload++;
    if (total_len != 2) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    type = *rx_payload++;
    if ((type != SN_MSG_TYPE_PING_REQ) &&
        (type != SN_MSG_TYPE_PING_RESP)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Return total length of packet */
    return total_len;
}

/* Read return code is length when > 0 */
int SN_Packet_Read(MqttClient *client, byte* rx_buf, int rx_buf_len,
    int timeout_ms)
{
    int rc, len = 0, remain_read = 0;
    word16 total_len = 0, idx = 0;

    switch (client->packet.stat)
    {
        case MQTT_PK_BEGIN:
        {
            /* Read first 2 bytes */
            if (MqttClient_Flags(client,0,0) & MQTT_CLIENT_FLAG_IS_DTLS) {
                rc = MqttSocket_Read(client, rx_buf, 2, timeout_ms);
            } else {
                rc = MqttSocket_Peek(client, rx_buf, 2, timeout_ms);
            }
            if (rc < 0) {
                return MqttPacket_HandleNetError(client, rc);
            }
            else if (rc != 2) {
                return MqttPacket_HandleNetError(client,
                         MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK));
            }

            len = rc;

            if (rx_buf[0] == SN_PACKET_LEN_IND){
                /* Read length stored in first three bytes, type in fourth */
                if (MqttClient_Flags(client,0,0) & MQTT_CLIENT_FLAG_IS_DTLS) {
                    rc = MqttSocket_Read(client, rx_buf+len, 2, timeout_ms);
                    if (rc < 0) {
                        return MqttPacket_HandleNetError(client, rc);
                    }
                    else if (rc != 2) {
                        return MqttPacket_HandleNetError(client,
                                 MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK));
                    }
                    len += rc;
                }
                else {
                    rc = MqttSocket_Peek(client, rx_buf, 4, timeout_ms);
                    if (rc < 0) {
                        return MqttPacket_HandleNetError(client, rc);
                    }
                    else if (rc != 4) {
                        return MqttPacket_HandleNetError(client,
                                 MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK));
                    }
                    len = rc;
                }

                (void)MqttDecode_Num(&rx_buf[1], &total_len);
                client->packet.header_len = len;
            }
            else {
                /* Length is stored in first byte, type in second */
                total_len = rx_buf[0];
                client->packet.header_len = len;
            }
        }
        FALL_THROUGH;

        case MQTT_PK_READ_HEAD:
        {
            client->packet.stat = MQTT_PK_READ_HEAD;
        }
        FALL_THROUGH;

        case MQTT_PK_READ:
        {
            client->packet.stat = MQTT_PK_READ;

            if (total_len > len) {
                client->packet.remain_len = total_len - len;
            }
            else if ((total_len == 2) || (total_len == 4)) {
                /* Handle peek */
                if (MqttClient_Flags(client,0,0) & MQTT_CLIENT_FLAG_IS_DTLS) {
                    client->packet.remain_len = total_len - len;
                }
                else {
                    client->packet.remain_len = total_len;
                }
            }
            else {
                client->packet.remain_len = 0;
            }

            /* Make sure it does not overflow rx_buf */
            if (client->packet.remain_len >
                (rx_buf_len - client->packet.header_len)) {
                client->packet.remain_len = rx_buf_len -
                                            client->packet.header_len;
            }
            if (MqttClient_Flags(client,0,0) & MQTT_CLIENT_FLAG_IS_DTLS) {
                total_len -= client->packet.header_len;
                idx = client->packet.header_len;
            }
            /* Read whole message */
            if (client->packet.remain_len > 0) {
                rc = MqttSocket_Read(client, &rx_buf[idx],
                        total_len, timeout_ms);
                if (rc <= 0) {
                    return MqttPacket_HandleNetError(client, rc);
                }
                remain_read = rc;
            }
            if (MqttClient_Flags(client,0,0) & MQTT_CLIENT_FLAG_IS_DTLS) {
                remain_read += client->packet.header_len;
            }

            break;
        }
    } /* switch (client->packet.stat) */

    /* reset state */
    client->packet.stat = MQTT_PK_BEGIN;

    /* Return read length */
    return remain_read;
}

#endif /* WOLFMQTT_SN */
