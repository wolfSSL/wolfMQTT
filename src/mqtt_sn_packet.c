/* mqtt_sn_packet.c
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
    int rc;
    SN_MsgType packet_type;
    word16 total_len;
    byte *rx_buf_orig = rx_buf;

    if (rx_buf == NULL || rx_buf_len < MQTT_PACKET_HEADER_MIN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_buf++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rc = MqttDecode_Num(rx_buf, &total_len, rx_buf_len - 1);
        if (rc < 0) {
            return rc;
        }
        rx_buf += rc;
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    /* Reject a declared total_len that does not cover the bytes already
     * consumed plus the upcoming message-type read. Without this, a peer
     * crafted SN_PACKET_LEN_IND packet whose 2-byte length field decodes
     * to a value equal to rx_buf_len (e.g., rx_buf_len == 3 with
     * total_len == 3) slips past the > rx_buf_len check above and the
     * *rx_buf++ below reads one byte past the caller-supplied buffer. */
    if (total_len < (word16)(rx_buf - rx_buf_orig) + 1) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* Message Type */
    packet_type = (SN_MsgType)*rx_buf++;

    if (p_packet_type)
        *p_packet_type = packet_type;

    if (p_packet_id) {
        /* Bytes already consumed from rx_buf_orig: the 1-byte length field
         * (plus the 2-byte extended length when SN_PACKET_LEN_IND was used)
         * and the 1-byte message type. The 2-byte MsgId sits id_offset bytes
         * past the current rx_buf position; where it begins depends on the
         * packet type. */
        int consumed = (int)(rx_buf - rx_buf_orig);
        int id_offset;

        switch(packet_type) {
            case SN_MSG_TYPE_REGACK:
            case SN_MSG_TYPE_PUBACK:
                /* TopicId(2) precedes the MsgId(2): octet 4-5 */
                id_offset = 2;
                break;
            case SN_MSG_TYPE_PUBCOMP:
            case SN_MSG_TYPE_PUBREC:
            case SN_MSG_TYPE_PUBREL:
            case SN_MSG_TYPE_UNSUBACK:
                /* MsgId(2) immediately follows the type: octet 2-3 */
                id_offset = 0;
                break;
            case SN_MSG_TYPE_SUBACK:
                /* Flags(1) + TopicId(2) precede the MsgId(2): octet 5-6 */
                id_offset = 3;
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
                /* No MsgId carried in this packet type */
                id_offset = -1;
                break;
        }

        if (id_offset < 0) {
            *p_packet_id = 0;
        }
        else {
            /* Bytes the declared packet leaves for the MsgId at
             * rx_buf + id_offset. Bound the read by total_len (the declared
             * packet length, already validated <= rx_buf_len above), not by
             * rx_buf_len: this keeps the read inside the buffer (CWE-125) and
             * additionally rejects a frame whose declared length stops short
             * of the MsgId rather than reading adjacent bytes. Evaluate as a
             * signed int and reject before the unsigned cast below, so a short
             * frame cannot wrap to a huge length and slip past MqttDecode_Num's
             * internal bound check. Measuring from consumed keeps the bound
             * correct for the IND form, where the header occupies 4 bytes
             * rather than 2. */
            int id_avail = (int)total_len - consumed - id_offset;
            if (id_avail < (int)MQTT_DATA_LEN_SIZE) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
            }
            rc = MqttDecode_Num(rx_buf + id_offset, p_packet_id,
                (word32)id_avail);
            if (rc < 0) {
                return rc;
            }
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
    if (total_len != 5) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Check message type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_ADVERTISE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode gateway info */
    if (gw_info != NULL) {
        int rc;
        gw_info->gwId = *rx_payload++;

        rc = MqttDecode_Num(rx_payload, &gw_info->duration,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;
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
    word16 total_len;
    int rc;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rc = MqttDecode_Num(rx_payload, &total_len,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    /* Reject a frame whose total_len cannot cover the bytes still to be read
     * after the length-indicator block (message type + gateway ID). The
     * short-form header consumes one byte and the extended-length form
     * consumes three, so the prior fixed "< 3" minimum was only valid for
     * the short form: an extended-length GWINFO with total_len <= the
     * header bytes already consumed would slip past it and the
     * *rx_payload++ reads below would walk past the caller-supplied
     * buffer. */
    if (total_len < (word16)(rx_payload - rx_buf) + 2) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }
    /* Check message type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_GWINFO) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode gateway info */
    if (gw_info != NULL) {
        word16 consumed;

        gw_info->gwId = *rx_payload++;

        /* Use the bytes actually consumed so far (1-byte short-form or
         * 3-byte extended-length header, plus type + gwId) rather than a
         * fixed 3, so the address length is correct for both forms and the
         * copy below cannot read past the buffer in the IND form. */
        consumed = (word16)(rx_payload - rx_buf);
        if (total_len > consumed) {
            /* The gateway address is only present if sent by a client */
            word16 addr_len = total_len - consumed;
            if (addr_len > (word16)sizeof(SN_GwAddr)) {
                addr_len = (word16)sizeof(SN_GwAddr);
            }
            XMEMCPY(gw_info->gwAddr, rx_payload, addr_len);
        }
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

/* Packet Type Encoders/Decoders */
int SN_Encode_Connect(byte *tx_buf, int tx_buf_len, SN_Connect *mc_connect)
{
    word16 total_len;
    size_t id_len;
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
    id_len = XSTRLEN(mc_connect->client_id);
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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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

    /* Validate required arguments. A NULL willTopic is valid: it produces an
     * empty WILLTOPIC message (2 octets) used to delete the will. But when
     * willTopic is non-NULL its willTopic string is dereferenced by XSTRLEN
     * (and XMEMCPY) below, so a non-NULL struct carrying a NULL string must be
     * rejected here rather than crashing in XSTRLEN(NULL). */
    if (tx_buf == NULL ||
            (willTopic != NULL && willTopic->willTopic == NULL)) {
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

    if (total_len > SN_PACKET_MAX_LEN || total_len > tx_buf_len) {
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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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

    if (total_len > SN_PACKET_MAX_LEN || total_len > tx_buf_len) {
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

    /* Validate required arguments. A NULL willTopic is valid: it produces an
     * empty WILLTOPICUPD message (2 octets) used to delete the will. But when
     * willTopic is non-NULL its willTopic string is dereferenced by XSTRLEN
     * (and XMEMCPY) below, so a non-NULL struct carrying a NULL string must be
     * rejected here rather than crashing in XSTRLEN(NULL). */
    if (tx_buf == NULL ||
            (willTopic != NULL && willTopic->willTopic == NULL)) {
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

    if (total_len > SN_PACKET_MAX_LEN || total_len > tx_buf_len) {
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
    if (rx_buf == NULL || rx_buf_len <= 0 || ret_code == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 3) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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

    if (total_len > SN_PACKET_MAX_LEN || total_len > tx_buf_len) {
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
    if (rx_buf == NULL || rx_buf_len <= 0 || ret_code == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 3) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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

    /* Validate required arguments. topicName is dereferenced unconditionally
     * via XSTRLEN below (and again before the XMEMCPY), so reject NULL up front.
     * A caller that zero-initializes an SN_Register and forgets to set topicName
     * would otherwise crash in XSTRLEN(NULL) instead of getting BAD_ARG. */
    if (tx_buf == NULL || regist == NULL || regist->topicName == NULL) {
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

    if (total_len > SN_PACKET_MAX_LEN || total_len > tx_buf_len) {
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

/* Note: rx_buf_len must be the writable capacity of rx_buf, not the decoded
 * packet length. Unlike the other SN decoders this one NUL-terminates topicName
 * in place at offset total_len (one byte past the packet), so the strict
 * total_len >= rx_buf_len guard below relies on rx_buf_len leaving room for that
 * terminator. Callers therefore pass client->rx_buf_len (see
 * SN_Client_HandlePacket), not client->packet.buf_len. */
int SN_Decode_Register(byte *rx_buf, int rx_buf_len, SN_Register *regist)
{
    word16 total_len;
    int rc;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rc = MqttDecode_Num(rx_payload, &total_len,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;
    }

    if (total_len >= rx_buf_len) {
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
        rc = MqttDecode_Num(rx_payload, &regist->topicId,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;

        /* Decode packet ID */
        rc = MqttDecode_Num(rx_payload, &regist->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;

        /* total_len must cover at least the bytes consumed so far
         * (length + type + topicId + packet_id); otherwise the topic-name
         * length computation below underflows and the NUL terminator is
         * written before regist->topicName, leaving the field pointing at
         * non-terminated memory past the parsed packet. */
        if (total_len < (word16)(rx_payload - rx_buf)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }

        /* Decode Topic Name */
        regist->topicName = (char*)rx_payload;

        /* Terminate the string */
        rx_payload[total_len - (rx_payload - rx_buf)] = '\0';
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
    *tx_payload = regack->return_code;

    (void)tx_payload;

    return total_len;
}

int SN_Decode_RegAck(byte *rx_buf, int rx_buf_len, SN_RegAck *regack)
{
    int rc, total_len;
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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_REGACK) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    if (regack != NULL) {
        /* Decode Topic ID assigned by GW */
        rc = MqttDecode_Num(rx_payload, &regack->topicId,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;

        /* Decode packet ID */
        rc = MqttDecode_Num(rx_payload, &regack->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;

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

    /* Validate required arguments. topicNameId is dereferenced for every
     * topic_type below (XSTRLEN on the NORMAL path, a 2-byte XMEMCPY
     * otherwise), so reject NULL up front. topic_type is SN_TOPIC_ID_TYPE_NORMAL
     * (0x0) when the SN_Subscribe is zero-initialized, so a caller that forgets
     * to assign topicNameId would otherwise crash in XSTRLEN(NULL). */
    if (tx_buf == NULL || subscribe == NULL ||
            subscribe->topicNameId == NULL) {
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

    if (total_len > SN_PACKET_MAX_LEN || total_len > tx_buf_len) {
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
    int rc;
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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_SUBACK) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode SubAck fields */
    if (subscribe_ack) {
        subscribe_ack->flags = *rx_payload++;
        rc = MqttDecode_Num(rx_payload, &subscribe_ack->topicId,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;
        rc = MqttDecode_Num(rx_payload, &subscribe_ack->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;
        subscribe_ack->return_code = *rx_payload++;
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Publish(byte *tx_buf, int tx_buf_len, SN_Publish *publish)
{
    word32 total_len;
    byte *tx_payload = tx_buf;
    byte flags = 0;

    /* Validate required arguments */
    if (tx_buf == NULL || publish == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    if (tx_buf_len < 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* publish->total_len is a caller-supplied word32. Reject any payload large
     * enough that adding the MQTT-SN header overhead would overflow or exceed
     * the maximum packet length, before the length arithmetic below. The header
     * is at most 9 bytes: a 3-byte extended length field, msgType, flags, topic
     * ID (2), and msgID (2). Validating the word32 up front keeps the payload
     * copy bounded and prevents the narrowing wrap that could bypass the
     * SN_PACKET_MAX_LEN / tx_buf_len checks. */
    if (publish->total_len > (word32)(SN_PACKET_MAX_LEN - 9)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Determine packet length */
    total_len = publish->total_len;

    /* Add length, msgType, flags, topic ID (2), and msgID (2) */
    total_len += 7;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        /* Length is stored in bytes 1 and 2 */
        total_len += 2;
    }

    if (total_len > SN_PACKET_MAX_LEN || total_len > (word32)tx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode header */
    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = (byte)total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, (word16)total_len);
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
    if (publish->topic_name == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    if ((publish->topic_type == SN_TOPIC_ID_TYPE_SHORT) ||
        (publish->topic_type == SN_TOPIC_ID_TYPE_PREDEF)) {
        /* Short and predefined topic names are 2 chars */
        XMEMCPY(tx_payload, publish->topic_name, 2);
        tx_payload += 2;
    }
    else {
        /* Topic ID */
        word16 topic_id;
        XMEMCPY(&topic_id, publish->topic_name, sizeof(topic_id));
        tx_payload += MqttEncode_Num(tx_payload, topic_id);
    }

    tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);

    /* Encode payload */
    if (publish->total_len > 0 && publish->buffer == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    XMEMCPY(tx_payload, publish->buffer, publish->total_len);
    tx_payload += publish->total_len;

    (void)tx_payload;

    /* Return length of packet placed into tx_buf */
    return (int)total_len;
}

int SN_Decode_Publish(byte *rx_buf, int rx_buf_len, SN_Publish *publish)
{
    int rc;
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
        rc = MqttDecode_Num(rx_payload, &total_len,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;
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

    rc = MqttDecode_Num(rx_payload, &publish->packet_id,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
    if (rc < 0) {
        return rc;
    }
    rx_payload += rc;

    /* Set flags */
    publish->duplicate = flags & SN_PACKET_FLAG_DUPLICATE;

    publish->qos = (MqttQoS)((flags & SN_PACKET_FLAG_QOS_MASK) >>
            SN_PACKET_FLAG_QOS_SHIFT);

    /* MQTT-SN v1.2 §5.2.10: a QoS 1 or QoS 2 PUBLISH must carry a non-zero
     * MsgId so the matching PUBACK/PUBREC can be correlated. Reject MsgId=0
     * here; otherwise SN_Client_HandlePacket would emit a response carrying
     * MsgId=0 that no conformant gateway can match, leaving its retransmit
     * timer to replay the same message (CWE-20). Mirrors the standard MQTT
     * decoder guard in mqtt_packet.c. QoS 0 and QoS -1 (MQTT_QOS_3, the
     * connectionless publish) send no response and legitimately use MsgId=0,
     * so they are intentionally excluded. */
    if ((publish->qos == MQTT_QOS_1 || publish->qos == MQTT_QOS_2) &&
            publish->packet_id == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
    }

    publish->retain = flags & SN_PACKET_FLAG_RETAIN;

    publish->topic_type = flags & SN_PACKET_FLAG_TOPICIDTYPE_MASK;

    /* Reject the reserved topic id type (0b11). MQTT-SN v1.2 defines only
     * NORMAL (0), PREDEF (1) and SHORT (2); value 3 must not appear on the
     * wire. Without this guard a spoofed gateway could hand topic_type=3 to
     * the application callback, which mis-classifies the message. */
    if (publish->topic_type > SN_TOPIC_ID_TYPE_SHORT) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* Decode payload: use pointer difference to account for both short (7)
     * and extended-length (9) header formats */
    if (total_len < (word16)(rx_payload - rx_buf)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }
    publish->total_len = total_len - (word16)(rx_payload - rx_buf);
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
    int rc, total_len;
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
            rc = MqttDecode_Num(rx_payload, &publish_resp->topicId,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
            if (rc < 0) {
                return rc;
            }
            rx_payload += rc;
        }

        rc = MqttDecode_Num(rx_payload, &publish_resp->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;

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

    /* Validate required arguments. topicNameId is dereferenced for every
     * topic_type below (XSTRLEN on the NORMAL path, a 2-byte XMEMCPY
     * otherwise), so reject NULL up front. topic_type is SN_TOPIC_ID_TYPE_NORMAL
     * (0x0) when the SN_Unsubscribe is zero-initialized, so a caller that forgets
     * to assign topicNameId would otherwise crash in XSTRLEN(NULL). */
    if (tx_buf == NULL || unsubscribe == NULL ||
            unsubscribe->topicNameId == NULL) {
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

    if (total_len > SN_PACKET_MAX_LEN || total_len > tx_buf_len) {
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
    int rc;
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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_UNSUBACK) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Decode SubAck fields */
    if (unsubscribe_ack) {
        rc = MqttDecode_Num(rx_payload, &unsubscribe_ack->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (rc < 0) {
            return rc;
        }
        rx_payload += rc;
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_Disconnect(byte *tx_buf, int tx_buf_len,
        SN_Disconnect* disconnect)
{
    int total_len = 2; /* length and message type */
    byte *tx_payload = tx_buf;

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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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

    if (total_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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

                rc = MqttDecode_Num(&rx_buf[1], &total_len, (word32)(rx_buf_len - 1));
                if (rc < 0) {
                    return MqttPacket_HandleNetError(client, rc);
                }
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
        }
        FALL_THROUGH;

        case MQTT_PK_READ:
        {
            client->packet.stat = MQTT_PK_READ;

            if (MqttClient_Flags(client,0,0) & MQTT_CLIENT_FLAG_IS_DTLS) {
                idx = client->packet.header_len;
            }
            /* Read whole message */
            if (client->packet.remain_len > 0) {
                rc = MqttSocket_Read(client, &rx_buf[idx],
                        client->packet.remain_len, timeout_ms);
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
