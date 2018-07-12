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
    { 0, 0, 0 },
    { MQTT_PROP_PLAYLOAD_FORMAT_IND,        MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_MSG_EXPIRY_INTERVAL,        MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_CONTENT_TYPE,               MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { 0, 0, 0 },
    { 0, 0, 0 },
    { 0, 0, 0 },
    { 0, 0, 0 },
    { MQTT_PROP_RESP_TOPIC,                 MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_CORRELATION_DATA,           MQTT_DATA_TYPE_BINARY,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { 0, 0, 0 },
    { MQTT_PROP_SUBSCRIPTION_ID,            MQTT_DATA_TYPE_VAR_INT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) |
        (1 << MQTT_PACKET_TYPE_SUBSCRIBE) },
    { 0, 0, 0 },
    { 0, 0, 0 },
    { 0, 0, 0 },
    { 0, 0, 0 },
    { 0, 0, 0 },
    { MQTT_PROP_SESSION_EXPIRY_INTERVAL,    MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_DISCONNECT) },
    { MQTT_PROP_ASSIGNED_CLIENT_ID,         MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_SERVER_KEEP_ALIVE,          MQTT_DATA_TYPE_SHORT,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { 0, 0, 0 },
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
    { 0, 0, 0 },
    { MQTT_PROP_SERVER_REF,                 MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_DISCONNECT) },
    { 0, 0, 0 },
    { 0, 0, 0 },
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
    { 0, 0, 0 },
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
       *value += (encodedByte & ~MQTT_PACKET_LEN_ENCODE_MASK) * multiplier;
       if (multiplier > (MQTT_PACKET_LEN_ENCODE_MASK *
                         MQTT_PACKET_LEN_ENCODE_MASK *
                         MQTT_PACKET_LEN_ENCODE_MASK))
       {
          return MQTT_CODE_ERROR_MALFORMED_DATA;
       }
       multiplier *= MQTT_PACKET_LEN_ENCODE_MASK;
       rc++;
    } while ((encodedByte & MQTT_PACKET_LEN_ENCODE_MASK) != 0);

    return rc;
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

/* Encodes to buf a non-negative integer "x" in a Variable Byte Integer scheme.
   Returns the number of bytes encoded.
   If buf is NULL, return number of bytes that would be encoded. */
int MqttEncode_Vbi(byte *buf, word32 x)
{
    int rc = 0;
    byte encodedByte;

    do {
       encodedByte = x % MQTT_PACKET_LEN_ENCODE_MASK;
       x /= MQTT_PACKET_LEN_ENCODE_MASK;
       // if there are more data to encode, set the top bit of this byte
       if (x > 0) {
          encodedByte |= MQTT_PACKET_LEN_ENCODE_MASK;
       }
       if (buf != NULL) {
           *(buf++) = encodedByte;
       }
       rc++;
    } while (x > 0);

    return rc;
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

/* Returns number of buffer bytes encoded
   If buf is NULL, return number of bytes that would be encoded. */
int MqttEncode_Num(byte *buf, word16 len)
{
    if (buf != NULL) {
        buf[0] = len >> 8;
        buf[1] = len & 0xFF;
    }
    return MQTT_DATA_LEN_SIZE;
}

/* Returns number of buffer bytes decoded */
int MqttDecode_Int(byte* buf, word32* len)
{
    if (len) {
        *len = buf[0];
        *len = (*len <<  8) | buf[1];
        *len = (*len << 16) | buf[2];
        *len = (*len << 24) | buf[3];
    }
    return MQTT_DATA_INT_SIZE;
}

/* Returns number of buffer bytes encoded
   If buf is NULL, return number of bytes that would be encoded. */
int MqttEncode_Int(byte* buf, word32 len)
{
    if (buf != NULL) {
        buf[0] = len >> 24;
        buf[1] = (len >> 16) & 0xFF;
        buf[2] = (len >> 8) & 0xFF;
        buf[3] = len & 0xFF;
    }
    return MQTT_DATA_INT_SIZE;
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

/* Returns number of buffer bytes encoded
   If buf is NULL, return number of bytes that would be encoded. */
int MqttEncode_String(byte *buf, const char *str)
{
    int str_len = (int)XSTRLEN(str);
    int len = MqttEncode_Num(buf, (word16)str_len);

    if (buf != NULL) {
        buf += len;
        XMEMCPY(buf, str, str_len);
    }
    return len + str_len;
}

/* Returns number of buffer bytes encoded
   If buf is NULL, return number of bytes that would be encoded. */
int MqttEncode_Data(byte *buf, const byte *data, word16 data_len)
{
    int len = MqttEncode_Num(buf, data_len);

    if (buf != NULL) {
        buf += len;
        XMEMCPY(buf, data, data_len);
    }
    return len + data_len;
}


#ifdef WOLFMQTT_V5



/* Returns the (positive) number of bytes encoded, or a (negative) error code.
   If buf is null, the number of bytes encoded is stored in prop_len. Else prop_len value is encoded.
   If pointer to buf is NULL, then only calculate the length of properties.
 */
int MqttEncode_Props(MqttPacketType packet, MqttProp* props, byte* buf, word32* prop_len)
{
    int rc = 0, tmp;
    MqttProp* cur_prop = props;
    int num_props = 0;

    // TODO: Check against max size. Sometimes all properties are not expected to be added
    /* TODO: Validate property type is allowed for packet type */

    if (buf != NULL) {
        tmp = MqttEncode_Vbi(buf, *prop_len);
        rc += tmp;
        if (buf != NULL) {
            buf += tmp;
        }
    }

    /* Example: MQTT_PACKET_TYPE_CONNECT: Allowed properties: MQTT_PROP_SESSION_EXPIRY_INTERVAL,
    MQTT_PROP_RECEIVE_MAX, MQTT_PROP_MAX_PACKET_SZ,
    MQTT_PROP_TOPIC_ALIAS_MAX, MQTT_PROP_REQ_RESP_INFO,
    MQTT_PROP_REQ_PROB_INFO, MQTT_PROP_USER_PROP,
    MQTT_PROP_AUTH_METHOD, MQTT_PROP_AUTH_DATA */

    /* loop through the list properties */
    while (cur_prop != NULL)
    {
        /* TODO: validate packet type */
        (void)packet;

        /* Encode the Identifier */
        tmp = MqttEncode_Vbi(buf, (word32)cur_prop->type);
        rc += tmp;
        if (buf != NULL) {
            buf += tmp;
        }

        switch (gPropMatrix[cur_prop->type].data)
        {
            case MQTT_DATA_TYPE_BYTE:
            {
                if (buf != NULL) {
                    *(buf++) = *((byte*)cur_prop->data);
                }
                rc++;
                break;
            }
            case MQTT_DATA_TYPE_SHORT:
            {
                tmp = MqttEncode_Num(buf, *((word16*)cur_prop->data));
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_INT:
            {
                tmp = MqttEncode_Int(buf, *((word32*)cur_prop->data));
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_STRING:
            {
                tmp = MqttEncode_String(buf, (const char*)cur_prop->data);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_VAR_INT:
            {
                tmp = MqttEncode_Vbi(buf, *((word32*)cur_prop->data));
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_BINARY:
            {
                /* Binary type is a two byte integer "length" followed by that number of bytes */
                word16 len = *((word16*)cur_prop->data);

                tmp = MqttEncode_Num(buf, *((word16*)cur_prop->data));
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }

                tmp = MqttEncode_Data(buf, &((const byte*)cur_prop->data)[2], len);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_STRING_PAIR:
            {
                /* String is prefixed with a Two Byte Integer length field that gives the number of bytes */
                word16 len = *((word16*)cur_prop->data);

                tmp = MqttEncode_String(buf, (const char*)cur_prop->data);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }

                tmp = MqttEncode_String(buf, &((const char*)cur_prop->data)[len]);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            default:
            {
                /* Do nothing */
                break;
            }
        }

        num_props++;

        cur_prop = cur_prop->next;
    }

    if (buf == NULL) {
        *prop_len = rc;
    }

    return rc;
}

/* Returns the (positive) number of bytes decoded, or a (negative) error code.
   Allocates MqttProp structures for all properties. Head of list is stored in props. */
int MqttDecode_Props(MqttPacketType packet, MqttProp** props, byte* buf)
{
    /* TODO: Validate property type is allowed for packet type */

    int rc = 0;
    word32 prop_len, tmp;
    MqttProp* cur_prop, * prev_prop = NULL;

    *props = NULL;

    /* The Property Length is encoded as a Variable Byte Integer.
     * The Property Length does not include the bytes used to encode itself,
     * but includes the length of the Properties. If there are no properties,
     * this MUST be indicated by including a Property Length of zero.  */
    tmp = MqttDecode_Vbi(buf, &prop_len);
    buf += tmp;
    rc += (int)tmp;

    while (prop_len > 0)
    {
        /* Allocate a structure */
        cur_prop = WOLFMQTT_MALLOC(sizeof(MqttProp));
        if (cur_prop == NULL) {
            //TODO: Clean up list
            return MQTT_CODE_ERROR_MEMORY;
        }
        memset(cur_prop, 0, sizeof(MqttProp));

        /* Decode the Identifier */
        tmp = MqttDecode_Vbi(buf, (word32*)cur_prop->type);
        buf += tmp;
        rc += (int)tmp;
        prop_len -= tmp;

        /* TODO: validate packet type */
        (void)packet;

        switch (gPropMatrix[cur_prop->type].data)
        {
            case MQTT_DATA_TYPE_BYTE:
            {
                cur_prop->data = (void*)buf++;
                tmp++;
                rc++;
                prop_len--;
                break;
            }
            case MQTT_DATA_TYPE_SHORT:
            {
                tmp = MqttDecode_Num(buf, (word16*)cur_prop->data);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_INT:
            {
                tmp = MqttDecode_Int(buf, (word32*)cur_prop->data);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_STRING:
            {
                tmp = MqttDecode_String(buf, (const char**)&cur_prop->data, NULL);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_VAR_INT:
            {
                tmp = MqttDecode_Vbi(buf, (word32*)cur_prop->data);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_BINARY:
            {
                /* Binary type is a two byte integer "length" followed by that number of bytes */
                word16 len;

                tmp = MqttDecode_Num(buf, (word16*)cur_prop->data);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;

                len = *((word16*)cur_prop->data);

                buf += len;
                rc += (int)len;
                prop_len -= len;
                break;
            }
            case MQTT_DATA_TYPE_STRING_PAIR:
            {
                /* String is prefixed with a Two Byte Integer length field that gives the number of bytes */
                tmp = MqttDecode_String(buf, (const char**)&cur_prop->data, NULL);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;

                tmp = MqttDecode_String(buf, NULL, NULL);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            default:
            {
                /* Do nothing */
                break;
            }
        }

        if (*props == NULL) {
            /* Store the list head */
            *props = cur_prop;
        }
        else {
            /* Add to list */
            prev_prop->next = cur_prop;
        }

        prev_prop = cur_prop;
    };

    return rc;
}
#endif

/* Packet Type Encoders/Decoders */
int MqttEncode_Connect(byte *tx_buf, int tx_buf_len, MqttConnect *connect)
{
    int header_len, remain_len;
#ifdef WOLFMQTT_V5
    word32 props_len;
#endif
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
    if (connect->props) {
        remain_len += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT, connect->props, NULL, &props_len);
    }
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
    tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT, connect->props, tx_payload, &props_len);
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

            rc = MqttEncode_Props(MQTT_PACKET_TYPE_AUTH, auth->props, tx_payload, NULL);
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
            rc = MqttDecode_Props(MQTT_PACKET_TYPE_AUTH, &auth->props, rx_payload);
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
