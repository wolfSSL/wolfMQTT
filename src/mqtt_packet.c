/* mqtt_packet.c
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

#include "wolfmqtt/mqtt_packet.h"
#include "wolfmqtt/mqtt_client.h"

#ifdef WOLFMQTT_V5
struct MqttPropMatrix {
    MqttPropertyType prop;
    MqttDataType data;
    word16 packet_type_mask; /* allowed packets */
};
static const struct MqttPropMatrix gPropMatrix[] = {
    { MQTT_PROP_PLAYLOAD_FORMAT_IND,        MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_MSG_EXPIRY_INTERVAL,        MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_CONTENT_TYPE,               MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_RESP_TOPIC,                 MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_CORRELATION_DATA,           MQTT_DATA_TYPE_BINARY,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_SUBSCRIPTION_ID,            MQTT_DATA_TYPE_VAR_INT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) |
        (1 << MQTT_PACKET_TYPE_SUBSCRIBE) },
    { MQTT_PROP_SESSION_EXPIRY_INTERVAL,    MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_DISCONNECT) },
    { MQTT_PROP_ASSIGNED_CLIENT_ID,         MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_SERVER_KEEP_ALIVE,          MQTT_DATA_TYPE_SHORT,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_AUTH_METHOD,                MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_AUTH) },
    { MQTT_PROP_AUTH_DATA,                  MQTT_DATA_TYPE_BINARY,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_AUTH) },
    { MQTT_PROP_REQ_PROB_INFO,              MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_CONNECT) },
    { MQTT_PROP_WILL_DELAY_INTERVAL,        MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_REQ_RESP_INFO,              MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_CONNECT) },
    { MQTT_PROP_RESP_INFO,                  MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_SERVER_REF,                 MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_DISCONNECT) },
    { MQTT_PROP_REASON_STR,                 MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_PUBLISH_ACK) |
        (1 << MQTT_PACKET_TYPE_PUBLISH_REC) |
        (1 << MQTT_PACKET_TYPE_PUBLISH_REL) |
        (1 << MQTT_PACKET_TYPE_PUBLISH_COMP) |
        (1 << MQTT_PACKET_TYPE_SUBSCRIBE_ACK) |
        (1 << MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK) |
        (1 << MQTT_PACKET_TYPE_DISCONNECT) |
        (1 << MQTT_PACKET_TYPE_AUTH) },
    { MQTT_PROP_RECEIVE_MAX,                MQTT_DATA_TYPE_SHORT,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_TOPIC_ALIAS_MAX,            MQTT_DATA_TYPE_SHORT,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_TOPIC_ALIAS,                MQTT_DATA_TYPE_SHORT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_MAX_QOS,                    MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_RETAIN_AVAIL,               MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_USER_PROP,                  MQTT_DATA_TYPE_STRING_PAIR,
        0xFFFF /* ALL */ },
    { MQTT_PROP_MAX_PACKET_SZ,              MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_WILDCARD_SUB_AVAIL,         MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_SUBSCRIPTION_ID_AVAIL,      MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_SHARED_SUBSCRIPTION_AVAIL, MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_TYPE_MAX, 0, 0 }
};
#endif /* WOLFMQTT_V5 */

/* Positive return value is header length, zero or negative indicates error */
static int MqttEncode_FixedHeader(byte *tx_buf, int tx_buf_len, int remain_len,
    byte type, byte retain, byte qos, byte duplicate)
{
    int header_len;
    MqttPacket* header = (MqttPacket*)tx_buf;

    /* Encode fixed header */
    header->type_flags = MQTT_PACKET_TYPE_SET(type) | MQTT_PACKET_FLAGS_SET(0);
    if (retain) {
        header->type_flags |= MQTT_PACKET_FLAGS_SET(MQTT_PACKET_FLAG_RETAIN);
    }
    if (qos) {
        header->type_flags |= MQTT_PACKET_FLAGS_SET_QOS(qos);
    }
    if (duplicate) {
        header->type_flags |=
            MQTT_PACKET_FLAGS_SET(MQTT_PACKET_FLAG_DUPLICATE);
    }

    /* Encode the length remaining into the header */
    header_len = MqttEncode_RemainLen(header, tx_buf_len, remain_len);
    if (header_len < 0) {
        return header_len;
    }

    return header_len;
}

static int MqttDecode_FixedHeader(byte *rx_buf, int rx_buf_len,
    int *remain_len, byte type, MqttQoS *p_qos, byte *p_retain,
    byte *p_duplicate)
{
    int header_len;
    MqttPacket* header = (MqttPacket*)rx_buf;

    /* Decode the length remaining */
    header_len = MqttDecode_RemainLen(header, rx_buf_len, remain_len);
    if (header_len < 0) {
        return header_len;
    }

    /* Validate packet type */
    if (MQTT_PACKET_TYPE_GET(header->type_flags) != type) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
    }

    /* Extract header flags */
    if (p_qos) {
        *p_qos = (MqttQoS)MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);
    }
    if (p_retain) {
        *p_retain = (MQTT_PACKET_FLAGS_GET(header->type_flags) &
            MQTT_PACKET_FLAG_RETAIN) ? 1 : 0;
    }
    if (p_duplicate) {
        *p_duplicate = (MQTT_PACKET_FLAGS_GET(header->type_flags) &
            MQTT_PACKET_FLAG_DUPLICATE) ? 1 : 0;
    }

    return header_len;
}


/* Packet Element Encoders/Decoders */
/* Returns number of decoded bytes, errors are negative value */
int MqttDecode_RemainLen(MqttPacket *header, int buf_len, int *remain_len)
{
    int decode_bytes = 0;
    int multiplier = 1;
    byte tmp_len;

    if (header == NULL || remain_len == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    *remain_len = 0;
    do {
        /* Check decoded length byte count */
        if ((decode_bytes + 1) >= buf_len) {
            return 0; /* Zero indicates we need another byte */
        }
        if (decode_bytes >= MQTT_PACKET_MAX_LEN_BYTES) {
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }

        /* Decode Length */
        tmp_len = header->len[decode_bytes++];
        *remain_len += (tmp_len & ~MQTT_PACKET_LEN_ENCODE_MASK) * multiplier;
        multiplier *= MQTT_PACKET_LEN_ENCODE_MASK;
    } while (tmp_len & MQTT_PACKET_LEN_ENCODE_MASK);

    return decode_bytes + 1; /* Add byte for header flags/type */
}

/* Returns number of encoded bytes, errors are negative value */
int MqttEncode_RemainLen(MqttPacket *header, int buf_len, int remain_len)
{
    int encode_bytes = 0;
    byte tmp_len;

    if (header == NULL || remain_len < 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    do {
        /* Check decoded length byte count */
        if ((encode_bytes + 1) >= buf_len) {
            return 0; /* Zero indicates we need another byte */
        }
        if (encode_bytes >= MQTT_PACKET_MAX_LEN_BYTES) {
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }

        /* Encode length */
        tmp_len = (remain_len % MQTT_PACKET_LEN_ENCODE_MASK);
        remain_len /= MQTT_PACKET_LEN_ENCODE_MASK;

        /* If more length, set the top bit of this byte */
        if (remain_len > 0) {
            tmp_len |= MQTT_PACKET_LEN_ENCODE_MASK;
        }
        header->len[encode_bytes++] = tmp_len;
    } while (remain_len > 0);

    return encode_bytes + 1; /* Add byte for header flags/type */
}

/* Returns number of buffer bytes decoded */
int MqttDecode_Num(byte* buf, word16 *len)
{
    if (len) {
        *len = buf[0];
        *len = (*len << 8) | buf[1];
    }
    return MQTT_DATA_LEN_SIZE;
}

/* Returns number of buffer bytes encoded */
int MqttEncode_Num(byte *buf, word16 len)
{
    buf[0] = len >> 8;
    buf[1] = len & 0xFF;
    return MQTT_DATA_LEN_SIZE;
}

/* Returns number of buffer bytes decoded */
/* Returns pointer to string (which is not guaranteed to be null terminated) */
int MqttDecode_String(byte *buf, const char **pstr, word16 *pstr_len)
{
    int len;
    word16 str_len;
    len = MqttDecode_Num(buf, &str_len);
    buf += len;
    if (pstr_len) {
        *pstr_len = str_len;
    }
    if (pstr) {
        *pstr = (char*)buf;
    }
    return len + str_len;
}

/* Returns number of buffer bytes encoded */
int MqttEncode_String(byte *buf, const char *str)
{
    int str_len = (int)XSTRLEN(str);
    int len = (int)MqttEncode_Num(buf, (word16)str_len);
    buf += len;
    XMEMCPY(buf, str, str_len);
    return len + str_len;
}

/* Returns number of buffer bytes encoded */
int MqttEncode_Data(byte *buf, const byte *data, word16 data_len)
{
    int len = (int)MqttEncode_Num(buf, data_len);
    buf += len;
    XMEMCPY(buf, data, data_len);
    return len + data_len;
}

/* Returns positive number of buffer bytes decoded or negative error. "value"
   is the decoded variable byte integer */
// TODO: Update other functions to use these generic routines
int MqttDecode_Vbi(byte *buf, word32 *value)
{
    int rc = 0;
    int multiplier = 1;
    byte encodedByte;

    *value = 0;
    do {
       encodedByte = *(buf++);
       *value += (encodedByte & 127) * multiplier;
       if (multiplier > 128*128*128) {
          return MQTT_CODE_ERROR_MALFORMED_DATA;
       }
       multiplier *= 128;
       rc++;
    } while ((encodedByte & 128) != 0);

    return rc;
}

/* Encodes to buf a non-negative integer "x" in a Variable Byte Integer scheme.
   Returns the number of bytes encoded. */
int MqttEncode_Vbi(byte *buf, word32 x)
{
    int rc = 0;
    byte encodedByte;

    do {
       encodedByte = x % 128;
       x /= 128;
       // if there are more data to encode, set the top bit of this byte
       if (x > 0) {
          encodedByte |= 128;
       }
       *(buf++) = encodedByte;
       rc++;
    } while (x > 0);

    return rc;
}

#ifdef WOLFMQTT_V5
int MqttEncode_Props(MqttPacketType packet, MqttProp* props, byte* buf)
{
    /* Validate property type is allowed for packet type */

    /* Example: MQTT_PACKET_TYPE_CONNECT: Allowed properties: MQTT_PROP_SESSION_EXPIRY_INTERVAL,
    MQTT_PROP_RECEIVE_MAX, MQTT_PROP_MAX_PACKET_SZ,
    MQTT_PROP_TOPIC_ALIAS_MAX, MQTT_PROP_REQ_RESP_INFO,
    MQTT_PROP_REQ_PROB_INFO, MQTT_PROP_USER_PROP,
    MQTT_PROP_AUTH_METHOD, MQTT_PROP_AUTH_DATA */

#if 0
    typedef struct MqttProp {
        struct MqttProp* next;
        void* data;
        int dataSz;
        MqttPropertyType type;
    } MqttProp;

    struct MqttPropMatrix {
        MqttPropertyType prop;
        MqttDataType data;
        word16 packet_type_mask; /* allowed packets */
    };

    gPropMatrix up to MQTT_PROP_TYPE_MAX
#endif
    (void)gPropMatrix;

    /* TODO: Encode props */
    (void)packet;
    (void)props;
    (void)buf;

    return 0;
}

int MqttDecode_Props(MqttPacketType packet, MqttProp* props, byte* buf)
{
    /* Validate property type is allowed for packet type */

    /* Example: MQTT_PACKET_TYPE_CONNECT: Allowed properties: MQTT_PROP_SESSION_EXPIRY_INTERVAL,
    MQTT_PROP_RECEIVE_MAX, MQTT_PROP_MAX_PACKET_SZ,
    MQTT_PROP_TOPIC_ALIAS_MAX, MQTT_PROP_REQ_RESP_INFO,
    MQTT_PROP_REQ_PROB_INFO, MQTT_PROP_USER_PROP,
    MQTT_PROP_AUTH_METHOD, MQTT_PROP_AUTH_DATA */

#if 0
    typedef struct MqttProp {
        struct MqttProp* next;
        void* data;
        int dataSz;
        MqttPropertyType type;
    } MqttProp;

    struct MqttPropMatrix {
        MqttPropertyType prop;
        MqttDataType data;
        word16 packet_type_mask; /* allowed packets */
    };

    gPropMatrix up to MQTT_PROP_TYPE_MAX
#endif
    (void)gPropMatrix;

    /* TODO: Encode props */
    (void)packet;
    (void)props;
    (void)buf;

    return 0;
}
#endif

/* Packet Type Encoders/Decoders */
int MqttEncode_Connect(byte *tx_buf, int tx_buf_len, MqttConnect *connect)
{
    int header_len, remain_len;
    MqttConnectPacket packet = MQTT_CONNECT_INIT;
    byte *tx_payload;

    /* Validate required arguments */
    if (tx_buf == NULL || connect == NULL || connect->client_id == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    /* MQTT Version 4/5 header is 10 bytes */
    remain_len = sizeof(MqttConnectPacket);
#ifdef WOLFMQTT_V5
    remain_len += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT, connect->props, NULL);
#endif
    remain_len += (int)XSTRLEN(connect->client_id) + MQTT_DATA_LEN_SIZE;
    if (connect->enable_lwt) {
        /* Verify all required fields are present */
        if (connect->lwt_msg == NULL ||
            connect->lwt_msg->topic_name == NULL ||
            connect->lwt_msg->buffer == NULL ||
            connect->lwt_msg->total_len <= 0)
        {
            return MQTT_CODE_ERROR_BAD_ARG;
        }

        remain_len += (int)XSTRLEN(connect->lwt_msg->topic_name);
        remain_len += MQTT_DATA_LEN_SIZE;
        remain_len += connect->lwt_msg->total_len;
        remain_len += MQTT_DATA_LEN_SIZE;
    }
    if (connect->username) {
        remain_len += (int)XSTRLEN(connect->username) + MQTT_DATA_LEN_SIZE;
    }
    if (connect->password) {
        remain_len += (int)XSTRLEN(connect->password) + MQTT_DATA_LEN_SIZE;
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_CONNECT, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    /* Protocol version */
    if (connect->protocol_level != 0) {
        packet.protocol_level = connect->protocol_level;
    }

    /* Set connection flags */
    if (connect->clean_session) {
        packet.flags |= MQTT_CONNECT_FLAG_CLEAN_SESSION;
    }
    if (connect->enable_lwt) {
        packet.flags |= MQTT_CONNECT_FLAG_WILL_FLAG;

        if (connect->lwt_msg->qos) {
            packet.flags |= MQTT_CONNECT_FLAG_SET_QOS(connect->lwt_msg->qos);
        }
        if (connect->lwt_msg->retain) {
            packet.flags |= MQTT_CONNECT_FLAG_WILL_RETAIN;
        }
    }
    if (connect->username) {
        packet.flags |= MQTT_CONNECT_FLAG_USERNAME;
    }
    if (connect->password) {
        packet.flags |= MQTT_CONNECT_FLAG_PASSWORD;
    }
    MqttEncode_Num((byte*)&packet.keep_alive, connect->keep_alive_sec);
    XMEMCPY(tx_payload, &packet, sizeof(MqttConnectPacket));
    tx_payload += sizeof(MqttConnectPacket);

#ifdef WOLFMQTT_V5
    /* Encode properties */
    tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT, connect->props, tx_payload);
#endif

    /* Encode payload */
    tx_payload += MqttEncode_String(tx_payload, connect->client_id);
    if (connect->enable_lwt) {
        tx_payload += MqttEncode_String(tx_payload,
            connect->lwt_msg->topic_name);
        tx_payload += MqttEncode_Data(tx_payload,
            connect->lwt_msg->buffer, (word16)connect->lwt_msg->total_len);
    }
    if (connect->username) {
        tx_payload += MqttEncode_String(tx_payload, connect->username);
    }
    if (connect->password) {
        tx_payload += MqttEncode_String(tx_payload, connect->password);
    }
    (void)tx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttDecode_ConnectAck(byte *rx_buf, int rx_buf_len,
    MqttConnectAck *connect_ack)
{
    int header_len, remain_len;
    byte *rx_payload;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_CONNECT_ACK, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    if (connect_ack) {
        connect_ack->flags = rx_payload[0];
        connect_ack->return_code = rx_payload[1];
    }

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Publish(byte *tx_buf, int tx_buf_len, MqttPublish *publish)
{
    int header_len, variable_len, payload_len = 0;
    byte *tx_payload;

    /* Validate required arguments */
    if (tx_buf == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    variable_len = (int)XSTRLEN(publish->topic_name) + MQTT_DATA_LEN_SIZE;
    if (publish->qos > MQTT_QOS_0) {
        if (publish->packet_id == 0) {
            return MQTT_CODE_ERROR_PACKET_ID;
        }
        variable_len += MQTT_DATA_LEN_SIZE; /* For packet_id */
    }
    if (publish->buffer && publish->total_len > 0) {
        payload_len = publish->total_len;
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len,
        variable_len + payload_len, MQTT_PACKET_TYPE_PUBLISH,
        publish->retain, publish->qos, publish->duplicate);
    if (header_len < 0) {
        return header_len;
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_String(tx_payload, publish->topic_name);
    if (publish->qos > MQTT_QOS_0) {
        tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);
    }

    /* Encode payload */
    if (payload_len > 0) {

        /* Determine max size to copy into tx_payload */
        if (payload_len > (tx_buf_len - (header_len + variable_len))) {
            payload_len = (tx_buf_len - (header_len + variable_len));
        }
        XMEMCPY(tx_payload, publish->buffer, payload_len);
    }
    publish->buffer_pos = 0;
    publish->buffer_len = payload_len;

    /* Return length of packet placed into tx_buf */
    return header_len + variable_len + payload_len;
}

int MqttDecode_Publish(byte *rx_buf, int rx_buf_len, MqttPublish *publish)
{
    int header_len, remain_len, variable_len, payload_len;
    byte *rx_payload;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0 || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len,
        &remain_len, MQTT_PACKET_TYPE_PUBLISH, &publish->qos,
        &publish->retain, &publish->duplicate);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    variable_len = MqttDecode_String(rx_payload, &publish->topic_name,
        &publish->topic_name_len);
    rx_payload += variable_len;

    /* If QoS > 0 then get packet Id */
    if (publish->qos > MQTT_QOS_0) {
        variable_len += MqttDecode_Num(rx_payload, &publish->packet_id);
        rx_payload += MQTT_DATA_LEN_SIZE;
    }

    /* Decode Payload */
    payload_len = remain_len - variable_len;
    publish->buffer = rx_payload;
    publish->buffer_pos = 0;
    publish->buffer_len = payload_len;
    publish->total_len = payload_len;

    /* Only return the length provided in rx_buf_len */
    if ((int)publish->buffer_len >
        (rx_buf_len - (header_len + variable_len)))
    {
        publish->buffer_len = (rx_buf_len - (header_len + variable_len));
    }

    return header_len + variable_len + payload_len;
}

int MqttEncode_PublishResp(byte* tx_buf, int tx_buf_len, byte type,
    MqttPublishResp *publish_resp)
{
    int header_len, remain_len;
    byte *tx_payload;
    MqttQoS qos;

    /* Validate required arguments */
    if (tx_buf == NULL || publish_resp == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */

    /* Determine Qos value */
    qos = (type == MQTT_PACKET_TYPE_PUBLISH_REL) ? MQTT_QOS_1 : MQTT_QOS_0;

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        type, 0, qos, 0);
    if (header_len < 0) {
        return header_len;
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], publish_resp->packet_id);
    (void)tx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttDecode_PublishResp(byte* rx_buf, int rx_buf_len, byte type,
    MqttPublishResp *publish_resp)
{
    int header_len, remain_len;
    byte *rx_payload;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        type, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    if (publish_resp) {
        rx_payload += MqttDecode_Num(rx_payload, &publish_resp->packet_id);
    }
    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Subscribe(byte *tx_buf, int tx_buf_len,
    MqttSubscribe *subscribe)
{
    int header_len, remain_len, i;
    byte *tx_payload;
    MqttTopic *topic;

    /* Validate required arguments */
    if (tx_buf == NULL || subscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
    for (i = 0; i < subscribe->topic_count; i++) {
        topic = &subscribe->topics[i];
        remain_len += (int)XSTRLEN(topic->topic_filter) + MQTT_DATA_LEN_SIZE;
        remain_len++; /* For QoS */
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_SUBSCRIBE, 0, MQTT_QOS_1, 0);
    if (header_len < 0) {
        return header_len;
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], subscribe->packet_id);

    /* Encode payload */
    for (i = 0; i < subscribe->topic_count; i++) {
        topic = &subscribe->topics[i];
        tx_payload += MqttEncode_String(tx_payload, topic->topic_filter);
        *tx_payload = topic->qos;
        tx_payload++;
    }

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttDecode_SubscribeAck(byte* rx_buf, int rx_buf_len,
    MqttSubscribeAck *subscribe_ack)
{
    int header_len, remain_len;
    byte *rx_payload;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0 || subscribe_ack == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_SUBSCRIBE_ACK, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    if (subscribe_ack) {
        rx_payload += MqttDecode_Num(rx_payload, &subscribe_ack->packet_id);
        subscribe_ack->return_codes = rx_payload; /* List of return codes */
    }

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Unsubscribe(byte *tx_buf, int tx_buf_len,
    MqttUnsubscribe *unsubscribe)
{
    int header_len, remain_len, i;
    byte *tx_payload;
    MqttTopic *topic;

    /* Validate required arguments */
    if (tx_buf == NULL || unsubscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
    for (i = 0; i < unsubscribe->topic_count; i++) {
        topic = &unsubscribe->topics[i];
        remain_len += (int)XSTRLEN(topic->topic_filter) + MQTT_DATA_LEN_SIZE;
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_UNSUBSCRIBE, 0, MQTT_QOS_1, 0);
    if (header_len < 0) {
        return header_len;
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], unsubscribe->packet_id);

    /* Encode payload */
    for (i = 0; i < unsubscribe->topic_count; i++) {
        topic = &unsubscribe->topics[i];
        tx_payload += MqttEncode_String(tx_payload, topic->topic_filter);
    }

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttDecode_UnsubscribeAck(byte *rx_buf, int rx_buf_len,
    MqttUnsubscribeAck *unsubscribe_ack)
{
    int header_len, remain_len;
    byte *rx_payload;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0 || unsubscribe_ack == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    if (unsubscribe_ack) {
        rx_payload += MqttDecode_Num(rx_payload, &unsubscribe_ack->packet_id);
    }
    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Ping(byte *tx_buf, int tx_buf_len)
{
    int header_len, remain_len = 0;

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_PING_REQ, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttDecode_Ping(byte *rx_buf, int rx_buf_len)
{
    int header_len, remain_len;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_PING_RESP, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Disconnect(byte *tx_buf, int tx_buf_len)
{
    int header_len;

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, 0,
        MQTT_PACKET_TYPE_DISCONNECT, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }

    /* Return total length of packet */
    return header_len;
}

#ifdef WOLFMQTT_V5
int MqttEncode_Auth(byte *tx_buf, int tx_buf_len, MqttAuth *auth)
{
    int header_len, remain_len = 0;
    byte* tx_payload;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (tx_buf_len <= 0) || (auth == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
                  MQTT_PACKET_TYPE_AUTH, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }

    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    if ((auth->reason_code == MQTT_REASON_CONT_AUTH) ||
        (auth->reason_code == MQTT_REASON_REAUTH)) {

        *tx_payload++ = auth->reason_code;
        if (auth->prop_len > 0) {
            int rc;

            /* Encode the length of Properties */
            *tx_payload += MqttEncode_Vbi(tx_payload, auth->prop_len);

            rc = MqttEncode_Props(MQTT_PACKET_TYPE_AUTH, auth->props, tx_payload);
            if (rc != 0) {return rc;}
        }
        else {
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
    }
    else {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }


    /* Return total length of packet */
    return header_len + remain_len;

}

int MqttDecode_Auth(byte *rx_buf, int rx_buf_len, MqttAuth *auth)
{
    int header_len, remain_len;
    byte *rx_payload;

    /* Validate required arguments */
    if ((rx_buf == NULL) || (rx_buf_len <= 0) || (auth == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
                  MQTT_PACKET_TYPE_AUTH, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    auth->reason_code = *rx_payload++;
    if ((auth->reason_code == MQTT_REASON_SUCCESS) ||
        (auth->reason_code == MQTT_REASON_CONT_AUTH)) {

        rx_payload += MqttDecode_Vbi(rx_payload, &auth->prop_len);
        if (auth->prop_len > 0) {
            int rc;
            /* Parse the AUTH Properties */
            rc = MqttDecode_Props(MQTT_PACKET_TYPE_AUTH, auth->props, rx_payload);
            if (rc == 0) {
                /* Must have Authentication Method */

                /* Must have Authentication Data */

                /* May have zero or more User Property pairs */
            }
            else {
                return MQTT_CODE_ERROR_MALFORMED_DATA;
            }
        }
        else if (auth->reason_code != MQTT_REASON_SUCCESS) {
            /* The Reason Code and Property Length can be omitted if the
               Reason Code is 0x00 (Success) and there are no Properties.
               In this case the AUTH has a Remaining Length of 0. */
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
    }
    else {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    /* Return total length of packet */
    return header_len + remain_len;
}
#endif /* WOLFMQTT_V5 */

static int MqttPacket_HandleNetError(MqttClient *client, int rc)
{
    (void)client;
#ifdef WOLFMQTT_DISCONNECT_CB
    if (rc < 0 &&
        rc != MQTT_CODE_CONTINUE &&
        rc != MQTT_CODE_STDIN_WAKE)
    {
        /* don't use return code for now - future use */
        if (client->disconnect_cb)
            client->disconnect_cb(client, rc, client->disconnect_ctx);
    }
#endif
    return rc;
}

int MqttPacket_Write(MqttClient *client, byte* tx_buf, int tx_buf_len)
{
    int rc;
    rc = MqttSocket_Write(client, tx_buf, tx_buf_len, client->cmd_timeout_ms);

    return MqttPacket_HandleNetError(client, rc);
}

/* Read return code is length when > 0 */
int MqttPacket_Read(MqttClient *client, byte* rx_buf, int rx_buf_len,
    int timeout_ms)
{
    int rc, len, remain_read = 0;
    MqttPacket* header = (MqttPacket*)rx_buf;

    switch (client->packet.stat)
    {
        case MQTT_PK_BEGIN:
        {
            client->packet.header_len = 2;
            client->packet.remain_len = 0;

            /* Read fix header portion */
            rc = MqttSocket_Read(client, rx_buf, client->packet.header_len, timeout_ms);
            if (rc < 0) {
                return MqttPacket_HandleNetError(client, rc);
            }
            else if (rc != client->packet.header_len) {
                return MqttPacket_HandleNetError(client, MQTT_CODE_ERROR_NETWORK);
            }

            FALL_THROUGH;
        }

        case MQTT_PK_READ_HEAD:
        {
            client->packet.stat = MQTT_PK_READ_HEAD;

            do {
                /* Try and decode remaining length */
                rc = MqttDecode_RemainLen(header, client->packet.header_len, &client->packet.remain_len);
                if (rc < 0) { /* Indicates error */
                    return MqttPacket_HandleNetError(client, rc);
                }
                /* Indicates decode success and rc is len of header */
                else if (rc > 0) {
                    client->packet.header_len = rc;
                    break; /* exit while */
                }

                /* Read next byte and try decode again */
                len = 1;
                rc = MqttSocket_Read(client, &rx_buf[client->packet.header_len], len, timeout_ms);
                if (rc < 0) {
                    return MqttPacket_HandleNetError(client, rc);
                }
                else if (rc != len) {
                    return MqttPacket_HandleNetError(client, MQTT_CODE_ERROR_NETWORK);
                }
                client->packet.header_len += len;

            } while (client->packet.header_len < MQTT_PACKET_MAX_SIZE);

            FALL_THROUGH;
        }

        case MQTT_PK_READ:
        {
            client->packet.stat = MQTT_PK_READ;

            /* Make sure it does not overflow rx_buf */
            if (client->packet.remain_len > (rx_buf_len - client->packet.header_len)) {
                client->packet.remain_len = rx_buf_len - client->packet.header_len;
            }

            /* Read remaining */
            if (client->packet.remain_len > 0) {
                rc = MqttSocket_Read(client, &rx_buf[client->packet.header_len],
                    client->packet.remain_len, timeout_ms);
                if (rc <= 0) {
                    return MqttPacket_HandleNetError(client, rc);
                }
                remain_read = rc;
            }

            break;
        }
    } /* switch (client->packet.stat) */

    /* reset state */
    client->packet.stat = MQTT_PK_BEGIN;

    /* Return read length */
    return client->packet.header_len + remain_read;
}
