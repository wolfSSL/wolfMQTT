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
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_PLAYLOAD_FORMAT_IND,        MQTT_DATA_TYPE_BYTE,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_MSG_EXPIRY_INTERVAL,        MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_CONTENT_TYPE,               MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_RESP_TOPIC,                 MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_CORRELATION_DATA,           MQTT_DATA_TYPE_BINARY,
        (1 << MQTT_PACKET_TYPE_PUBLISH) },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_SUBSCRIPTION_ID,            MQTT_DATA_TYPE_VAR_INT,
        (1 << MQTT_PACKET_TYPE_PUBLISH) |
        (1 << MQTT_PACKET_TYPE_SUBSCRIBE) },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_SESSION_EXPIRY_INTERVAL,    MQTT_DATA_TYPE_INT,
        (1 << MQTT_PACKET_TYPE_CONNECT) |
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_DISCONNECT) },
    { MQTT_PROP_ASSIGNED_CLIENT_ID,         MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_SERVER_KEEP_ALIVE,          MQTT_DATA_TYPE_SHORT,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
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
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_SERVER_REF,                 MQTT_DATA_TYPE_STRING,
        (1 << MQTT_PACKET_TYPE_CONNECT_ACK) |
        (1 << MQTT_PACKET_TYPE_DISCONNECT) },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
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
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
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
    { MQTT_PROP_TYPE_MAX, MQTT_DATA_TYPE_NONE, 0 }
};

#ifndef MQTT_MAX_PROPS
#define MQTT_MAX_PROPS 10
#endif

/* Property structure allocation array. Property type equal
   to zero indicates unused element. */
MqttProp clientPropStack[MQTT_MAX_PROPS];
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
    header_len = MqttEncode_Vbi(header->len, remain_len);
    if (header_len > 0) {
        header_len++; /* Add one for type and flags */
    }

    (void) tx_buf_len;

    return header_len;
}

static int MqttDecode_FixedHeader(byte *rx_buf, int rx_buf_len, int *remain_len,
    byte type, MqttQoS *p_qos, byte *p_retain, byte *p_duplicate)
{
    int header_len;
    MqttPacket* header = (MqttPacket*)rx_buf;

    /* Decode the length remaining */
    header_len = MqttDecode_Vbi(header->len, (word32*)remain_len);
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

    header_len += sizeof(header->type_flags); /* Add size of type and flags */

    (void)rx_buf_len;

    return header_len;
}


/* Returns positive number of buffer bytes decoded or negative error. "value"
   is the decoded variable byte integer */
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
   If pointer to buf is NULL, then only calculate the length of properties. */
int MqttEncode_Props(MqttPacketType packet, MqttProp* props, byte* buf)
{
    int rc = 0, tmp;
    MqttProp* cur_prop = props;
    int num_props = 0;

    /* TODO: Check against max size. Sometimes all properties are not
             expected to be added */
    // TODO: Validate property type is allowed for packet type

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
                    *(buf++) = cur_prop->data_byte;
                }
                rc++;
                break;
            }
            case MQTT_DATA_TYPE_SHORT:
            {
                tmp = MqttEncode_Num(buf, cur_prop->data_short);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_INT:
            {
                tmp = MqttEncode_Int(buf, cur_prop->data_int);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_STRING:
            {
                tmp = MqttEncode_String(buf,
                        (const char*)cur_prop->data_str.str);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_VAR_INT:
            {
                tmp = MqttEncode_Vbi(buf, cur_prop->data_int);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_BINARY:
            {
                /* Binary type is a two byte integer "length"
                   followed by that number of bytes */
                tmp = MqttEncode_Num(buf, cur_prop->data_bin.len);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }

                tmp = MqttEncode_Data(buf, (const byte*)cur_prop->data_bin.data,
                        cur_prop->data_bin.len);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_STRING_PAIR:
            {
                /* String is prefixed with a Two Byte Integer length field that
                   gives the number of bytes */
                tmp = MqttEncode_String(buf,
                        (const char*)cur_prop->data_str.str);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }

                tmp = MqttEncode_String(buf,
                        (const char*)cur_prop->data_str2.str);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_NONE:
            default:
            {
                /* Do nothing */
                break;
            }
        }

        num_props++;

        cur_prop = cur_prop->next;
    }

    return rc;
}

/* Returns the (positive) number of bytes decoded, or a (negative) error code.
   Allocates MqttProp structures for all properties.
   Head of list is stored in props. */
int MqttDecode_Props(MqttPacketType packet, MqttProp** props, byte* buf,
        word32 prop_len)
{
    /* TODO: Validate property type is allowed for packet type */

    int rc = 0;
    word32 tmp;
    MqttProp* cur_prop;

    *props = NULL;

    while (prop_len > 0)
    {
        /* Allocate a structure and add to head. */
        cur_prop = MqttProps_Add(props);
        if (cur_prop == NULL) {
            MqttProps_Free(*props);
            return MQTT_CODE_ERROR_MEMORY;
        }
        XMEMSET(cur_prop, 0, sizeof(MqttProp));

        /* Decode the Identifier */
        tmp = MqttDecode_Vbi(buf, (word32*)&cur_prop->type);
        buf += tmp;
        rc += (int)tmp;
        prop_len -= tmp;

        /* TODO: validate packet type */
        (void)packet;

        switch (gPropMatrix[cur_prop->type].data)
        {
            case MQTT_DATA_TYPE_BYTE:
            {
                cur_prop->data_byte = *buf++;
                tmp++;
                rc++;
                prop_len--;
                break;
            }
            case MQTT_DATA_TYPE_SHORT:
            {
                tmp = MqttDecode_Num(buf, &cur_prop->data_short);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_INT:
            {
                tmp = MqttDecode_Int(buf, &cur_prop->data_int);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_STRING:
            {
                tmp = MqttDecode_String(buf,
                        (const char**)&cur_prop->data_str.str,
                        &cur_prop->data_str.len);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_VAR_INT:
            {
                tmp = MqttDecode_Vbi(buf, &cur_prop->data_int);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_BINARY:
            {
                /* Binary type is a two byte integer "length"
                   followed by that number of bytes */
                tmp = MqttDecode_Num(buf, &cur_prop->data_bin.len);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;

                cur_prop->data_bin.data = buf;
                buf += cur_prop->data_bin.len;
                rc += (int)cur_prop->data_bin.len;
                prop_len -= cur_prop->data_bin.len;
                break;
            }
            case MQTT_DATA_TYPE_STRING_PAIR:
            {
                /* String is prefixed with a Two Byte Integer length
                   field that gives the number of bytes */
                tmp = MqttDecode_String(buf,
                        (const char**)&cur_prop->data_str.str,
                        &cur_prop->data_str.len);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;

                tmp = MqttDecode_String(buf,
                        (const char**)&cur_prop->data_str2.str,
                        &cur_prop->data_str2.len);
                buf += tmp;
                rc += (int)tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_NONE:
            default:
            {
                /* Do nothing */
                break;
            }
        }
    };

    return rc;
}
#endif

/* Packet Type Encoders/Decoders */
int MqttEncode_Connect(byte *tx_buf, int tx_buf_len, MqttConnect *connect)
{
    int header_len, remain_len;
#ifdef WOLFMQTT_V5
    word32 props_len = 0;
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
    /* Determine length of properties */
    remain_len += props_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
            connect->props, NULL);

    /* Determine the length of the "property length" */
    remain_len += MqttEncode_Vbi(NULL, props_len);
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
    /* Encode the property length */
    tx_payload += MqttEncode_Vbi(tx_payload, props_len);

    /* Encode properties */
    tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT, connect->props,
                    tx_payload);
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
    else {
        /* A Server MAY allow a Client to supply a ClientID that has a length
         * of zero bytes, however if it does so the Server MUST treat this as a
         * special case and assign a unique ClientID to that Client
         * [MQTT-3.1.3-6]. It MUST then process the CONNECT packet as if the
         * Client had provided that unique ClientID, and MUST return the
         * Assigned Client Identifier in the CONNACK packet [MQTT-3.1.3-7].
         */
        tx_payload += MqttEncode_Num(tx_payload, (word16)0);
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
        connect_ack->flags = *rx_payload++;
        connect_ack->return_code = *rx_payload++;

#ifdef WOLFMQTT_V5
        {
            word32 props_len = 0;
            /* Decode Length of Properties */
            rx_payload += MqttDecode_Vbi(rx_payload, &props_len);
            if (props_len > 0) {
                /* Decode the Properties */
                rx_payload += MqttDecode_Props(MQTT_PACKET_TYPE_CONNECT_ACK,
                               &connect_ack->props, rx_payload, props_len);
            }
        }
#endif
    }

    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Publish(byte *tx_buf, int tx_buf_len, MqttPublish *publish,
                        byte use_cb)
{
    int header_len, variable_len, payload_len = 0;
    byte *tx_payload;
#ifdef WOLFMQTT_V5
    word32 props_len = 0;
#endif

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

#ifdef WOLFMQTT_V5
    /* Determine length of properties */
    variable_len += props_len = MqttEncode_Props(MQTT_PACKET_TYPE_PUBLISH,
                      publish->props, NULL);

    /* Determine the length of the "property length" */
    variable_len += MqttEncode_Vbi(NULL, props_len);
#endif

    if (((publish->buffer != NULL) || (use_cb == 1)) &&
        (publish->total_len > 0)) {
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

    if (use_cb == 1) {
        /* The callback will encode the payload */
        payload_len = 0;
    }

    /* Encode variable header */
    tx_payload += MqttEncode_String(tx_payload, publish->topic_name);
    if (publish->qos > MQTT_QOS_0) {
        tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);
    }

#ifdef WOLFMQTT_V5
    /* Encode the property length */
    tx_payload += MqttEncode_Vbi(tx_payload, props_len);

    /* Encode properties */
    tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_PUBLISH, publish->props,
                    tx_payload);
#endif

    /* Encode payload */
    if (payload_len > 0) {

        /* Determine max size to copy into tx_payload */
        if (payload_len > (tx_buf_len - (header_len + variable_len))) {
            payload_len = (tx_buf_len - (header_len + variable_len));
        }
        XMEMCPY(tx_payload, publish->buffer, payload_len);
    }
    publish->intBuf_pos = 0;
    publish->intBuf_len = payload_len;

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

#ifdef WOLFMQTT_V5
    {
        word32 props_len = 0;
        int tmp;

        /* Decode Length of Properties */
        tmp = MqttDecode_Vbi(rx_payload, &props_len);
        rx_payload += tmp;
        variable_len += tmp + props_len;
        if (props_len > 0) {
            /* Decode the Properties */
            rx_payload += MqttDecode_Props(MQTT_PACKET_TYPE_PUBLISH,
                           &publish->props, rx_payload, props_len);
            if (publish->props != NULL) {
                /* Parse properties. */
            }
        }
    }
#endif

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
#ifdef WOLFMQTT_V5
    word32 props_len = 0;
#endif


    /* Validate required arguments */
    if (tx_buf == NULL || publish_resp == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */

#ifdef WOLFMQTT_V5
    if ((publish_resp->reason_code != MQTT_REASON_SUCCESS) ||
        (publish_resp->props != NULL))
    {
        /* Reason Code */
        remain_len++;

        /* Determine length of properties */
        remain_len += props_len = MqttEncode_Props((MqttPacketType)type,
                        publish_resp->props, NULL);

        /* Determine the length of the "property length" */
        remain_len += MqttEncode_Vbi(NULL, props_len);
    }
#endif

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

#ifdef WOLFMQTT_V5
    if ((publish_resp->reason_code != MQTT_REASON_SUCCESS) ||
        (publish_resp->props != NULL))
    {
        /* Encode the Reason Code */
        *tx_payload++ = publish_resp->reason_code;

        /* Encode the property length */
        tx_payload += MqttEncode_Vbi(tx_payload, props_len);

        /* Encode properties */
        tx_payload += MqttEncode_Props((MqttPacketType)type,
                        publish_resp->props, tx_payload);
    }
#endif

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

#ifdef WOLFMQTT_V5
        if (remain_len > MQTT_DATA_LEN_SIZE) {
            word32 props_len = 0;

            /* Decode the Reason Code */
            publish_resp->reason_code = *rx_payload++;

            /* Decode Length of Properties */
            rx_payload += MqttDecode_Vbi(rx_payload, &props_len);
            if (props_len > 0) {
                /* Decode the Properties */
                rx_payload += MqttDecode_Props((MqttPacketType)type,
                                &publish_resp->props, rx_payload, props_len);
            }
        }
        else {
            publish_resp->reason_code = MQTT_REASON_SUCCESS;
        }
#endif
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
#ifdef WOLFMQTT_V5
    word32 props_len = 0;
#endif

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
#ifdef WOLFMQTT_V5
    /* Determine length of properties */
    remain_len += props_len = MqttEncode_Props(MQTT_PACKET_TYPE_SUBSCRIBE,
                                subscribe->props, NULL);

    /* Determine the length of the "property length" */
    remain_len += MqttEncode_Vbi(NULL, props_len);
#endif


    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_SUBSCRIBE, 0, MQTT_QOS_1, 0);
    if (header_len < 0) {
        return header_len;
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], subscribe->packet_id);

#ifdef WOLFMQTT_V5
    /* Encode the property length */
    tx_payload += MqttEncode_Vbi(tx_payload, props_len);

    /* Encode properties */
    tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_SUBSCRIBE, subscribe->props,
                    tx_payload);
#endif

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

#ifdef WOLFMQTT_V5
        if (remain_len > MQTT_DATA_LEN_SIZE) {
            word32 props_len = 0;

            /* Decode Length of Properties */
            rx_payload += MqttDecode_Vbi(rx_payload, &props_len);
            if (props_len > 0) {
                /* Decode the Properties */
                rx_payload += MqttDecode_Props(MQTT_PACKET_TYPE_SUBSCRIBE_ACK,
                               &subscribe_ack->props, rx_payload, props_len);
            }
        }
#endif

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
#ifdef WOLFMQTT_V5
    word32 props_len = 0;
#endif

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
#ifdef WOLFMQTT_V5
    /* Determine length of properties */
    remain_len += props_len = MqttEncode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE,
                                unsubscribe->props, NULL);

    /* Determine the length of the "property length" */
    remain_len += MqttEncode_Vbi(NULL, props_len);
#endif

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_UNSUBSCRIBE, 0, MQTT_QOS_1, 0);
    if (header_len < 0) {
        return header_len;
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], unsubscribe->packet_id);
#ifdef WOLFMQTT_V5
    /* Encode the property length */
    tx_payload += MqttEncode_Vbi(tx_payload, props_len);

    /* Encode properties */
    tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE,
                    unsubscribe->props, tx_payload);
#endif


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
#ifdef WOLFMQTT_V5
        if (remain_len > MQTT_DATA_LEN_SIZE) {
            word32 props_len = 0;
            /* Decode Length of Properties */
            rx_payload += MqttDecode_Vbi(rx_payload, &props_len);
            if (props_len > 0) {
                /* Decode the Properties */
                rx_payload += MqttDecode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK,
                               &unsubscribe_ack->props, rx_payload, props_len);
            }
        }

        /* Reason codes are stored in the payload */
        unsubscribe_ack->reason_codes = rx_payload;
#endif
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

int MqttEncode_Disconnect(byte *tx_buf, int tx_buf_len,
        MqttDisconnect* disconnect)
{
    int header_len;
    int remain_len = 0;
#ifdef WOLFMQTT_V5
    word32 props_len = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_V5
    if ((disconnect != NULL) &&
        ((disconnect->reason_code != MQTT_REASON_SUCCESS) ||
         (disconnect->props != NULL)))
    {
        /* Length of Reason Code */
        remain_len++;

        /* Determine length of properties */
        remain_len += props_len = MqttEncode_Props(MQTT_PACKET_TYPE_DISCONNECT,
                                    disconnect->props, NULL);

        /* Determine the length of the "property length" */
        remain_len += MqttEncode_Vbi(NULL, props_len);
    }
#endif

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_DISCONNECT, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }

#ifdef WOLFMQTT_V5
    if ((disconnect != NULL) &&
        ((disconnect->reason_code != MQTT_REASON_SUCCESS) ||
         (disconnect->props != NULL)))
    {
        byte* tx_payload = &tx_buf[header_len];

        /* Encode the Reason Code */
        *tx_payload++ = disconnect->reason_code;

        /* Encode the property length */
        tx_payload += MqttEncode_Vbi(tx_payload, props_len);

        /* Encode properties */
        tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
                        disconnect->props, tx_payload);

        (void)tx_payload;
    }
#else
    (void)disconnect;
#endif

    /* Return total length of packet */
    return header_len + remain_len;
}

#ifdef WOLFMQTT_V5
int MqttDecode_Disconnect(byte *rx_buf, int rx_buf_len, MqttDisconnect *disc)
{
    int header_len, remain_len;
    byte *rx_payload;
    word32 props_len = 0;

    /* Validate required arguments */
    if ((rx_buf == NULL) || (rx_buf_len <= 0) || (disc == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_DISCONNECT, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    if (remain_len > 0) {
        /* Decode variable header */
        disc->reason_code = *rx_payload++;

        if (remain_len > 1) {
            /* Decode Length of Properties */
            rx_payload += MqttDecode_Vbi(rx_payload, &props_len);
            if (props_len > 0) {
                /* Decode the AUTH Properties */
                rx_payload += MqttDecode_Props(MQTT_PACKET_TYPE_DISCONNECT,
                                &disc->props, rx_payload, props_len);
            }
        }
    }

    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Auth(byte *tx_buf, int tx_buf_len, MqttAuth *auth)
{
    int header_len, remain_len = 0;
    byte* tx_payload;
    word32 props_len = 0;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (tx_buf_len <= 0) || (auth == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Length of Reason Code */
    remain_len++;

    /* Determine length of properties */
    remain_len += props_len = MqttEncode_Props(MQTT_PACKET_TYPE_AUTH,
                                auth->props, NULL);

    /* Determine the length of the "property length" */
    remain_len += MqttEncode_Vbi(NULL, props_len);

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

        /* Encode the property length */
        tx_payload += MqttEncode_Vbi(tx_payload, props_len);

        /* Encode properties */
        tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_AUTH, auth->props,
                        tx_payload);
    }
    else {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    (void)tx_payload;

    /* Return total length of packet */
    return header_len + remain_len;

}

int MqttDecode_Auth(byte *rx_buf, int rx_buf_len, MqttAuth *auth)
{
    int header_len, remain_len;
    byte *rx_payload;
    word32 props_len = 0;


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
        (auth->reason_code == MQTT_REASON_CONT_AUTH))
    {
        /* Decode Length of Properties */
        rx_payload += MqttDecode_Vbi(rx_payload, &props_len);
        if (props_len > 0) {
            /* Decode the AUTH Properties */
            rx_payload += MqttDecode_Props(MQTT_PACKET_TYPE_AUTH, &auth->props,
                          rx_payload, props_len);
            if (auth->props != NULL) {
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

    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}


/* Add property */
// TODO: Need a mutex here
MqttProp* MqttProps_Add(MqttProp **head)
{
    MqttProp *new_prop = NULL, *prev = NULL, *cur;
    int i;

    if (head == NULL) {
        return NULL;
    }

    cur = *head;

    /* Find the end of the parameter list */
    while (cur != NULL) {
        prev = cur;
        cur = cur->next;
    };

    /* Find a free element */
    for (i = 0; i < MQTT_MAX_PROPS; i++) {
        if (clientPropStack[i].type == 0) {
            /* Found one */
            new_prop = &clientPropStack[i];
            XMEMSET(new_prop, 0, sizeof(MqttProp));
        }
    }

    if (new_prop != NULL) {
        if (prev == NULL) {
            /* Start a new list */
            *head = new_prop;
        }
        else {
            /* Add to the existing list */
            prev->next = new_prop;
        }
    }

    return new_prop;
}

/* Free properties */
// TODO: Need a mutex here
void MqttProps_Free(MqttProp *head)
{
    while (head != NULL) {
        head->type = (MqttPropertyType)0;
        head = head->next;
    }
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
#ifdef WOLFMQTT_V5
    if ((client->packet_sz_max > 0) && (tx_buf_len >
        (int)client->packet_sz_max))
    {
        rc = MQTT_CODE_ERROR_SERVER_PROP;
    }
    else
#endif
    {
        rc = MqttSocket_Write(client, tx_buf, tx_buf_len,
                client->cmd_timeout_ms);
    }

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
            rc = MqttSocket_Read(client, rx_buf, client->packet.header_len,
                    timeout_ms);
            if (rc < 0) {
                return MqttPacket_HandleNetError(client, rc);
            }
            else if (rc != client->packet.header_len) {
                return MqttPacket_HandleNetError(client,
                         MQTT_CODE_ERROR_NETWORK);
            }

            FALL_THROUGH;
        }

        case MQTT_PK_READ_HEAD:
        {
            int i;
            client->packet.stat = MQTT_PK_READ_HEAD;

            for (i = 0; i < MQTT_PACKET_MAX_LEN_BYTES; i++) {
                /* Check if another byte is needed */
                if ((header->len[i] & MQTT_PACKET_LEN_ENCODE_MASK) == 0) {
                    /* Variable byte length can be determined */
                    break;
                }

                /* Read next byte and try decode again */
                len = 1;
                rc = MqttSocket_Read(client, &rx_buf[client->packet.header_len],
                        len, timeout_ms);
                if (rc < 0) {
                    return MqttPacket_HandleNetError(client, rc);
                }
                else if (rc != len) {
                    return MqttPacket_HandleNetError(client,
                             MQTT_CODE_ERROR_NETWORK);
                }
                client->packet.header_len += len;
            }

            if (i == MQTT_PACKET_MAX_LEN_BYTES) {
                return MqttPacket_HandleNetError(client,
                        MQTT_CODE_ERROR_MALFORMED_DATA);
            }

            /* Try and decode remaining length */
            rc = MqttDecode_Vbi(header->len,
                    (word32*)&client->packet.remain_len);
            if (rc < 0) { /* Indicates error */
                return MqttPacket_HandleNetError(client, rc);
            }
            /* Indicates decode success and rc is len of header */
            else {
                /* Add size of type and flags */
                rc += sizeof(header->type_flags);
                client->packet.header_len = rc;
            }

            FALL_THROUGH;
        }

        case MQTT_PK_READ:
        {
            client->packet.stat = MQTT_PK_READ;

            /* Make sure it does not overflow rx_buf */
            if (client->packet.remain_len >
                (rx_buf_len - client->packet.header_len)) {
                client->packet.remain_len = rx_buf_len -
                                            client->packet.header_len;
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


#ifdef WOLFMQTT_SN
int SN_Decode_Advertise(byte *rx_buf, int rx_buf_len, SN_Advertise *gw_info)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;

    /* Check message type */
    type = *rx_payload++;
    if (total_len != 5) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    if (type != SN_MSG_TYPE_ADVERTISE) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
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
        return MQTT_CODE_ERROR_BAD_ARG;
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rx_payload += MqttDecode_Num(rx_payload, (word16*)&total_len);
    }

    if (total_len > rx_buf_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    if (total_len < 3) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    /* Check message type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_GWINFO) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
    }

    /* Decode gateway info */
    if (gw_info != NULL) {
        gw_info->gwId = *rx_payload++;

        //TODO: validate size of gwAddr
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
int SN_Encode_Connect(byte *tx_buf, int tx_buf_len, SN_Connect *connect)
{
    word16 total_len, id_len;
    byte flags = 0;
    byte *tx_payload = tx_buf;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (connect == NULL) ||
        (connect->client_id == NULL) || (connect->protocol_level == 0)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    total_len = 6; /* Len + Message Type + Flags + ProtocolID + Duration(2) */

    /* Client ID size */
    id_len = (word16)XSTRLEN(connect->client_id);
    id_len = (id_len <= SN_CLIENTID_MAX_LEN) ? id_len : SN_CLIENTID_MAX_LEN;

    total_len += id_len;

    if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
        total_len += 2; /* Store len in three bytes */
    }

    if (total_len > tx_buf_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }

    /* Encode length */
    if (total_len <= SN_PACKET_MAX_SMALL_SIZE) {
        *tx_payload++ = (byte)total_len;
    }
    else {
        *tx_payload++ = SN_PACKET_LEN_IND;
        tx_payload += MqttEncode_Num(tx_payload, total_len);
    }

    /* Encode message type */
    *tx_payload++ = SN_MSG_TYPE_CONNECT;

    /* Encode flags */
    if (connect->clean_session) {
        flags |= SN_PACKET_FLAG_CLEANSESSION;
    }
    if (connect->enable_lwt) {
        flags |= SN_PACKET_FLAG_WILL;
    }
    *tx_payload++ = flags;

    /* Protocol version */
    *tx_payload++ = connect->protocol_level;

    /* Encode duration (keep-alive) */
    tx_payload += MqttEncode_Num(tx_payload, connect->keep_alive_sec);

    /* Encode Client ID */
     XMEMCPY(tx_payload, connect->client_id, id_len);
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Length and MsgType */
    total_len = *rx_payload++;
    if (total_len != 2) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLTOPICREQ) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Length and MsgType */
    total_len = 2;

    /* Determine packet length */
    if (willTopic != NULL) {
        /* Will Topic is a string */
        total_len += XSTRLEN(willTopic->willTopic);

        /* Flags */
        total_len++;

        if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
            /* Length is stored in bytes 1 and 2 */
            total_len += 2;
        }
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;

    /* Length and MsgType */
    if (total_len != 2){
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    /* Message Type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLMSGREQ) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
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
        return MQTT_CODE_ERROR_BAD_ARG;
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
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Length and MsgType */
    total_len = 2;

    /* Determine packet length */
    if (willTopic != NULL) {
        /* Will Topic is a string */
        total_len += XSTRLEN(willTopic->willTopic);

        /* Flags */
        total_len++;

        if (total_len > SN_PACKET_MAX_SMALL_SIZE) {
            /* Length is stored in bytes 1 and 2 */
            total_len += 2;
        }
    }

    if (total_len > tx_buf_len) {
        /* Buffer too small */
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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

int SN_Decode_WillTopicResponse(byte *rx_buf, int rx_buf_len)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 2) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLTOPICRESP) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
    }
    (void)rx_payload;

    /* Return total length of packet */
    return total_len;
}

int SN_Encode_WillMsgUpdate(byte *tx_buf, int tx_buf_len, SN_Will *willMsg)
{
    int total_len;
    byte *tx_payload;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (willMsg == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
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
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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

int SN_Decode_WillMsgResponse(byte *rx_buf, int rx_buf_len)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 2) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_WILLMSGRESP) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
    }
    (void)rx_payload;

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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 3) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_CONNACK) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
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
        return MQTT_CODE_ERROR_BAD_ARG;
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
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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

int SN_Decode_RegAck(byte *rx_buf, int rx_buf_len, SN_RegAck *regack)
{
    int total_len;
    byte *rx_payload = rx_buf, type;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 7) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_REGACK) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    if ((subscribe->topic_type & SN_PACKET_FLAG_TOPICIDTYPE_MASK) ==
            SN_TOPIC_ID_TYPE_NORMAL) {
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
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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
    if ((subscribe->topic_type & SN_PACKET_FLAG_TOPICIDTYPE_MASK) !=
            SN_TOPIC_ID_TYPE_PREDEF) {
        /* Topic name is a string */
        XMEMCPY(tx_payload, subscribe->topicNameId, XSTRLEN(subscribe->topicNameId));
    }
    else {
        /* Topic ID */
        tx_payload += MqttEncode_Num(tx_payload,
                (word16)subscribe->topicNameId[0]);
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 8) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_SUBACK) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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

int SN_Encode_Publish(byte *tx_buf, int tx_buf_len, MqttPublish *publish)
{
    word16 total_len;
    byte *tx_payload = tx_buf;
    byte flags = 0;

    /* Validate required arguments */
    if (tx_buf == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
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
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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

    tx_payload += MqttEncode_Num(tx_payload, (word16)*publish->topic_name);
    tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);

    /* Encode payload */
    XMEMCPY(tx_payload, publish->buffer, publish->total_len);
    tx_payload += publish->total_len;

    (void)tx_payload;

    /* Return length of packet placed into tx_buf */
    return total_len;
}

int SN_Decode_Publish(byte *rx_buf, int rx_buf_len, MqttPublish *publish)
{
    word16 total_len;
    byte *rx_payload = rx_buf;
    byte flags = 0, type;

    /* Validate required arguments */
    if (rx_buf == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len == SN_PACKET_LEN_IND) {
        /* The length is stored in the next two bytes */
        rx_payload += MqttDecode_Num(rx_payload, &total_len);
    }

    if (total_len > rx_buf_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }

    if (total_len < 7) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    /* Message Type */
    type = *rx_payload++;
    if (type != SN_MSG_TYPE_PUBLISH) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
    }

    flags = *rx_payload++;

    rx_payload += MqttDecode_Num(rx_payload, (word16*)publish->topic_name);

    rx_payload += MqttDecode_Num(rx_payload, &publish->packet_id);

    /* Set flags */
    publish->duplicate = flags & SN_PACKET_FLAG_DUPLICATE;

    publish->qos = (MqttQoS)((flags >> SN_PACKET_FLAG_QOS_SHIFT) & SN_PACKET_FLAG_QOS_MASK);

    publish->retain = flags & SN_PACKET_FLAG_RETAIN;

    publish->type = flags & SN_PACKET_FLAG_TOPICIDTYPE_MASK;

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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    total_len = (type == SN_MSG_TYPE_PUBACK) ? 7 : 4;

    if (total_len > tx_buf_len)
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;

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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode */
    total_len = *rx_payload++;

    if(total_len > rx_buf_len) {
        /* Buffer too small */
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }

    /* Validate packet type */
    rec_type = *rx_payload++;
    if (rec_type != type) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Determine packet length */
    if ((unsubscribe->topic_type & SN_PACKET_FLAG_TOPICIDTYPE_MASK) ==
            SN_TOPIC_ID_TYPE_NORMAL) {
        /* Topic name is a string */
        total_len = MqttEncode_String(NULL, unsubscribe->topicNameId);
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
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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
    if ((unsubscribe->topic_type & SN_PACKET_FLAG_TOPICIDTYPE_MASK) ==
            SN_TOPIC_ID_TYPE_NORMAL) {
        /* Topic name is a string */
        tx_payload += MqttEncode_String(tx_payload, unsubscribe->topicNameId);
    }
    else {
        /* Topic ID or Short name */
        tx_payload += MqttEncode_Num(tx_payload,
                (word16)unsubscribe->topicNameId[0]);
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode fixed header */
    total_len = *rx_payload++;
    if (total_len != 4) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_UNSUBACK) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if ((disconnect != NULL) && (disconnect->sleepTmr > 0)) {
        total_len += 2; /* Sleep duration is set */
    }

    if (total_len > tx_buf_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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

int SN_Encode_Ping(byte *tx_buf, int tx_buf_len, SN_PingReq *ping)
{
    int total_len = 2, clientId_len = 0;
    byte *tx_payload = tx_buf;

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (ping != NULL && ping->clientId != NULL) {
        total_len += clientId_len = (int)XSTRLEN(ping->clientId);
    }

    if (total_len > tx_buf_len) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }

    *tx_payload++ = (byte)total_len;

    *tx_payload++ = SN_MSG_TYPE_PING_REQ;

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
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    total_len = *rx_payload++;
    if (total_len != 2) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    type = *rx_payload++;
    if (type != SN_MSG_TYPE_PING_RESP) {
        return MQTT_CODE_ERROR_PACKET_TYPE;
    }

    /* Return total length of packet */
    return total_len;
}

static int SN_Packet_HandleNetError(MqttClient *client, int rc)
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

/* Read return code is length when > 0 */
int SN_Packet_Read(MqttClient *client, byte* rx_buf, int rx_buf_len,
    int timeout_ms)
{
    int rc, len = 0, remain_read = 0;
    word16 total_len = 0;

    switch (client->packet.stat)
    {
        case MQTT_PK_BEGIN:
        {
            /* Read first 2 bytes using MSG_PEEK */
            rc = MqttSocket_Peek(client, rx_buf, 2, timeout_ms);
            if (rc < 0) {
                return SN_Packet_HandleNetError(client, rc);
            }
            else if (rc != 2) {
                return SN_Packet_HandleNetError(client,
                         MQTT_CODE_ERROR_NETWORK);
            }

            len = rc;

            if (rx_buf[0] == SN_PACKET_LEN_IND){
                /* Read length stored in first three bytes, type in fourth */
                rc = MqttSocket_Peek(client, rx_buf, 4, timeout_ms);
                if (rc < 0) {
                    return SN_Packet_HandleNetError(client, rc);
                }
                else if (rc != 4) {
                    return SN_Packet_HandleNetError(client,
                             MQTT_CODE_ERROR_NETWORK);
                }

                len = rc;
                (void)MqttDecode_Num(&rx_buf[1], &total_len);
                client->packet.header_len = len;
            }
            else {
                /* Length is stored in first byte, type in second */
                total_len = rx_buf[0];
                client->packet.header_len = len;
            }

            FALL_THROUGH;
        }

        case MQTT_PK_READ_HEAD:
        {
            client->packet.stat = MQTT_PK_READ_HEAD;

            FALL_THROUGH;
        }

        case MQTT_PK_READ:
        {
            client->packet.stat = MQTT_PK_READ;

            if (total_len > len) {
                client->packet.remain_len = total_len - len;
            }
            else if ((total_len == 2) || (total_len == 4)) {
                /* Handle peek */
                client->packet.remain_len = total_len;
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

            /* Read whole message */
            if (client->packet.remain_len > 0) {
                rc = MqttSocket_Read(client, &rx_buf[0],
                        total_len, timeout_ms);
                if (rc <= 0) {
                    return SN_Packet_HandleNetError(client, rc);
                }
                remain_read = rc;
            }

            break;
        }
    } /* switch (client->packet.stat) */

    /* reset state */
    client->packet.stat = MQTT_PK_BEGIN;

    /* Return read length */
    return remain_read;
}
#endif /* defined WOLFMQTT_SN */
