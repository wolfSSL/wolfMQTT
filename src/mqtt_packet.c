/* mqtt_packet.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include "wolfmqtt/mqtt_packet.h"

#ifdef WOLFMQTT_V5
struct MqttPropMatrix {
    MqttPropertyType prop;
    MqttDataType data;
    word16 packet_type_mask; /* allowed packets */
};
static const struct MqttPropMatrix gPropMatrix[] = {
    { MQTT_PROP_NONE, MQTT_DATA_TYPE_NONE, 0 },
    { MQTT_PROP_PAYLOAD_FORMAT_IND,         MQTT_DATA_TYPE_BYTE,
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

/* WOLFMQTT_DYN_PROP allows property allocation using malloc */
#ifndef WOLFMQTT_DYN_PROP

/* Maximum number of active static properties - overridable */
#ifndef MQTT_MAX_PROPS
#define MQTT_MAX_PROPS 30
#endif

/* Property structure allocation array. Property type equal
   to zero indicates unused element. */
static MqttProp clientPropStack[MQTT_MAX_PROPS];

#ifdef WOLFMQTT_MULTITHREAD
static volatile int clientPropStack_lockInit = 0;
static wm_Sem clientPropStack_lock;
#endif
#endif /* WOLFMQTT_DYN_PROP */
#endif /* WOLFMQTT_V5 */

/* Positive return value is header length, zero or negative indicates error */
static int MqttEncode_FixedHeader(byte *tx_buf, int tx_buf_len, int remain_len,
    byte type, byte retain, byte qos, byte duplicate)
{
    int header_len;
    MqttPacket* header = (MqttPacket*)tx_buf;

    /* make sure destination buffer has space for header */
    if (tx_buf_len < MQTT_PACKET_MAX_LEN_BYTES+1) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

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
    header_len = MqttDecode_Vbi(header->len, (word32*)remain_len, rx_buf_len);
    if (header_len < 0) {
        return header_len;
    }

    /* Validate packet type */
    if (MQTT_PACKET_TYPE_GET(header->type_flags) != type) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
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

/* Returns positive number of buffer bytes decoded (max 4) or negative error.
 * "value" is the decoded variable byte integer
 * buf_len is the max number of bytes in buf */
int MqttDecode_Vbi(byte *buf, word32 *value, word32 buf_len)
{
    word32 rc = 0;
    word32 multiplier = 1;
    byte encodedByte;

    *value = 0;
    do {
        if (buf_len < rc + 1) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        if (rc >= 4) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }

        encodedByte = *(buf++);
        *value += (word32)(encodedByte & ~MQTT_PACKET_LEN_ENCODE_MASK) *
                           multiplier;
        multiplier *= MQTT_PACKET_LEN_ENCODE_MASK;
        rc++;
    } while ((encodedByte & MQTT_PACKET_LEN_ENCODE_MASK) != 0);

    return (int)rc;
}

/* Encodes to buf a non-negative integer "x" in a Variable Byte Integer scheme.
   Returns the number of bytes encoded.
   If buf is NULL, return number of bytes that would be encoded. */
int MqttEncode_Vbi(byte *buf, word32 x)
{
    int rc = 0;
    byte encodedByte;

    do {
        encodedByte = (x & ~MQTT_PACKET_LEN_ENCODE_MASK) & 0xFF;
        x >>= 7;
        /* if there are more data to encode, set the top bit of this byte */
        if (x > 0) {
            encodedByte |= MQTT_PACKET_LEN_ENCODE_MASK;
        }
        if (buf != NULL) {
            *(buf++) = encodedByte;
        }
        rc++;
    } while (x > 0 && rc < 4);

    return rc;
}

/* Returns number of buffer bytes decoded */
int MqttDecode_Num(byte* buf, word16 *len, word32 buf_len)
{
    if (buf_len < MQTT_DATA_LEN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    if (len) {
        *len =  (word32)buf[0] << 8;
        *len += buf[1];
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
        *len =  (word32)buf[0] << 24;
        *len += (word32)buf[1] << 16;
        *len += (word32)buf[2] << 8;
        *len += buf[3];
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
int MqttDecode_String(byte *buf, const char **pstr, word16 *pstr_len, word32 buf_len)
{
    int len;
    word16 str_len;
    len = MqttDecode_Num(buf, &str_len, buf_len);
    if (len < 0) {
        return len;
    }
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

    if ((buf != NULL) && (data != NULL)) {
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

    /* TODO: Check against max size. Sometimes all properties are not
             expected to be added */
    /* TODO: Validate property type is allowed for packet type */

    /* loop through the list properties */
    while ((cur_prop != NULL) && (rc >= 0))
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
                /* Invalid property data type */
                rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
                break;
            }
        }

        cur_prop = cur_prop->next;
    }

    return rc;
}

/* Returns the (positive) number of bytes decoded, or a (negative) error code.
   Allocates MqttProp structures for all properties.
   Head of list is stored in props. */
int MqttDecode_Props(MqttPacketType packet, MqttProp** props, byte* pbuf,
        word32 buf_len, word32 prop_len)
{
    int rc = 0;
    int total, tmp;
    MqttProp* cur_prop;
    byte* buf = pbuf;

    total = 0;

    while (((int)prop_len > 0) && (rc >= 0))
    {
        /* Allocate a structure and add to head. */
        cur_prop = MqttProps_Add(props);
        if (cur_prop == NULL) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MEMORY);
            break;
        }

        /* Decode the Identifier */
        if (buf_len < (word32)(buf - pbuf)) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            break;
        }
        rc = MqttDecode_Vbi(buf, (word32*)&cur_prop->type,
                (word32)(buf_len - (buf - pbuf)));
        if (rc < 0) {
            break;
        }
        tmp = rc;
        buf += tmp;
        total += tmp;
        prop_len -= tmp;

        /* TODO: Validate property type is allowed for packet type */
        (void)packet;

        if (cur_prop->type >= sizeof(gPropMatrix) / sizeof(gPropMatrix[0])) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
            break;
        }

        switch (gPropMatrix[cur_prop->type].data)
        {
            case MQTT_DATA_TYPE_BYTE:
            {
                cur_prop->data_byte = *buf++;
                tmp++;
                total++;
                prop_len--;
                break;
            }
            case MQTT_DATA_TYPE_SHORT:
            {
                tmp = MqttDecode_Num(buf, &cur_prop->data_short,
                        (word32)(buf_len - (buf - pbuf)));
                if (tmp < 0) {
                    rc = tmp;
                    break;
                }
                buf += tmp;
                total += tmp;
                prop_len -= (word32)tmp;
                break;
            }
            case MQTT_DATA_TYPE_INT:
            {
                tmp = MqttDecode_Int(buf, &cur_prop->data_int);
                buf += tmp;
                total += tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_STRING:
            {
                tmp = MqttDecode_String(buf,
                        (const char**)&cur_prop->data_str.str,
                        &cur_prop->data_str.len,
                        (word32)(buf_len - (buf - pbuf)));
                if ((tmp >= 0) && ((word32)tmp <= (buf_len - (buf - pbuf)))) {
                    buf += tmp;
                    total += tmp;
                    prop_len -= (word32)tmp;
                }
                else {
                    /* Invalid length */
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
                }
                break;
            }
            case MQTT_DATA_TYPE_VAR_INT:
            {
                if (buf_len < (word32)(buf - pbuf)) {
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                    break;
                }
                tmp = MqttDecode_Vbi(buf, &cur_prop->data_int,
                        (word32)(buf_len - (buf - pbuf)));
                if (tmp < 0) {
                    return tmp;
                }
                buf += tmp;
                total += tmp;
                prop_len -= (word32)tmp;
                break;
            }
            case MQTT_DATA_TYPE_BINARY:
            {
                /* Binary type is a two byte integer "length"
                   followed by that number of bytes */
                tmp = MqttDecode_Num(buf, &cur_prop->data_bin.len,
                        (word32)(buf_len - (buf - pbuf)));
                if (tmp < 0) {
                    rc = tmp;
                    break;
                }
                buf += tmp;
                total += tmp;
                prop_len -= tmp;

                if (cur_prop->data_bin.len <= (buf_len - (buf - pbuf))) {
                    cur_prop->data_bin.data = buf;
                    buf += cur_prop->data_bin.len;
                    total += (int)cur_prop->data_bin.len;
                    prop_len -= cur_prop->data_bin.len;
                }
                else {
                    /* Invalid length */
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
                }
                break;
            }
            case MQTT_DATA_TYPE_STRING_PAIR:
            {
                /* String is prefixed with a Two Byte Integer length
                   field that gives the number of bytes */
                tmp = MqttDecode_String(buf,
                        (const char**)&cur_prop->data_str.str,
                        &cur_prop->data_str.len,
                        (word32)(buf_len - (buf - pbuf)));
                if ((tmp >= 0) && ((word32)tmp <= (buf_len - (buf - pbuf)))) {
                    buf += tmp;
                    total += tmp;
                    prop_len -= (word32)tmp;
                    if ((buf_len - (buf - pbuf)) > 0) {
                        tmp = MqttDecode_String(buf,
                                (const char**)&cur_prop->data_str2.str,
                                &cur_prop->data_str2.len,
                                (word32)(buf_len - (buf - pbuf)));
                        if ((tmp >= 0) && ((word32)tmp <=
                            (buf_len - (buf - pbuf)))) {
                            buf += tmp;
                            total += tmp;
                            prop_len -= (word32)tmp;
                        }
                        else {
                            /* Invalid length */
                            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
                        }
                    }
                    else {
                        /* Invalid length */
                        rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
                    }
                }
                else {
                    /* Invalid length */
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
                }
                break;
            }
            case MQTT_DATA_TYPE_NONE:
            default:
            {
                /* Invalid property data type */
                rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
                break;
            }
        }
    };

    if (rc < 0) {
        /* Free the property */
        MqttProps_Free(*props);
        *props = NULL;
    }
    else {
        rc = total;
    }

    return rc;
}
#endif

/* Packet Type Encoders/Decoders */
int MqttEncode_Connect(byte *tx_buf, int tx_buf_len, MqttConnect *mc_connect)
{
    int header_len, remain_len;
#ifdef WOLFMQTT_V5
    int props_len = 0, lwt_props_len = 0;
#endif
    MqttConnectPacket packet = MQTT_CONNECT_INIT;
    byte *tx_payload;

    /* Validate required arguments */
    if (tx_buf == NULL || mc_connect == NULL || mc_connect->client_id == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    /* MQTT Version 4/5 header is 10 bytes */
    remain_len = sizeof(MqttConnectPacket);

#ifdef WOLFMQTT_V5
    if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        props_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
                mc_connect->props, NULL);
        if (props_len >= 0) {
            remain_len += props_len;

            /* Determine the length of the "property length" */
            remain_len += MqttEncode_Vbi(NULL, props_len);
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif

    remain_len += (int)XSTRLEN(mc_connect->client_id) + MQTT_DATA_LEN_SIZE;
    if (mc_connect->enable_lwt) {
        /* Verify all required fields are present */
        if (mc_connect->lwt_msg == NULL ||
            mc_connect->lwt_msg->topic_name == NULL ||
            (mc_connect->lwt_msg->buffer == NULL &&
             mc_connect->lwt_msg->total_len != 0))
        {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }

        remain_len += (int)XSTRLEN(mc_connect->lwt_msg->topic_name);
        remain_len += MQTT_DATA_LEN_SIZE;
        remain_len += mc_connect->lwt_msg->total_len;
        remain_len += MQTT_DATA_LEN_SIZE;
#ifdef WOLFMQTT_V5
    if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        lwt_props_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
                mc_connect->lwt_msg->props, NULL);
        if (lwt_props_len >= 0) {
            remain_len += lwt_props_len;

            /* Determine the length of the "lwt property length" */
            remain_len += MqttEncode_Vbi(NULL, lwt_props_len);
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif
    }
    if (mc_connect->username) {
        remain_len += (int)XSTRLEN(mc_connect->username) + MQTT_DATA_LEN_SIZE;
    }
    if (mc_connect->password) {
        remain_len += (int)XSTRLEN(mc_connect->password) + MQTT_DATA_LEN_SIZE;
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_CONNECT, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    /* Protocol version */
    if (mc_connect->protocol_level != 0) {
        packet.protocol_level = mc_connect->protocol_level;
    }

    /* Set connection flags */
    if (mc_connect->clean_session) {
        packet.flags |= MQTT_CONNECT_FLAG_CLEAN_SESSION;
    }
    if (mc_connect->enable_lwt) {
        packet.flags |= MQTT_CONNECT_FLAG_WILL_FLAG;

        if (mc_connect->lwt_msg->qos) {
            packet.flags |= MQTT_CONNECT_FLAG_SET_QOS(mc_connect->lwt_msg->qos);
        }
        if (mc_connect->lwt_msg->retain) {
            packet.flags |= MQTT_CONNECT_FLAG_WILL_RETAIN;
        }
    }
    if (mc_connect->username) {
        packet.flags |= MQTT_CONNECT_FLAG_USERNAME;
    }
    if (mc_connect->password) {
        packet.flags |= MQTT_CONNECT_FLAG_PASSWORD;
    }
    MqttEncode_Num((byte*)&packet.keep_alive, mc_connect->keep_alive_sec);
    XMEMCPY(tx_payload, &packet, sizeof(MqttConnectPacket));
    tx_payload += sizeof(MqttConnectPacket);

#ifdef WOLFMQTT_V5
    if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Encode the property length */
        tx_payload += MqttEncode_Vbi(tx_payload, props_len);

        /* Encode properties */
        tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT, mc_connect->props,
                        tx_payload);
    }
#endif

    /* Encode payload */
    tx_payload += MqttEncode_String(tx_payload, mc_connect->client_id);
    if (mc_connect->enable_lwt) {
#ifdef WOLFMQTT_V5
    if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Encode the lwt property length */
        tx_payload += MqttEncode_Vbi(tx_payload, lwt_props_len);

        /* Encode lwt properties */
        tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
                mc_connect->lwt_msg->props, tx_payload);
    }
#endif
        tx_payload += MqttEncode_String(tx_payload,
            mc_connect->lwt_msg->topic_name);
        tx_payload += MqttEncode_Data(tx_payload,
            mc_connect->lwt_msg->buffer, (word16)mc_connect->lwt_msg->total_len);
    }
    if (mc_connect->username) {
        tx_payload += MqttEncode_String(tx_payload, mc_connect->username);
    }
    if (mc_connect->password) {
        tx_payload += MqttEncode_String(tx_payload, mc_connect->password);
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
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
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
        connect_ack->props = NULL;
        if (connect_ack->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
            word32 props_len = 0;
            int props_tmp;
            /* Decode Length of Properties */
            if (rx_buf_len < (rx_payload - rx_buf)) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            props_tmp = MqttDecode_Vbi(rx_payload, &props_len,
                    (word32)(rx_buf_len - (rx_payload - rx_buf)));
            if (props_tmp < 0) {
                return props_tmp;
            }
            rx_payload += props_tmp;
            if (props_len > 0) {
                /* Decode the Properties */
                props_tmp = MqttDecode_Props(MQTT_PACKET_TYPE_CONNECT_ACK,
                               &connect_ack->props, rx_payload,
                               (word32)(rx_buf_len - (rx_payload - rx_buf)),
                               props_len);
                if (props_tmp < 0)
                    return props_tmp;
                rx_payload += props_tmp;
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
    int props_len = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL || publish == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    variable_len = (int)XSTRLEN(publish->topic_name) + MQTT_DATA_LEN_SIZE;
    if (publish->qos > MQTT_QOS_0) {
        if (publish->packet_id == 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
        }
        variable_len += MQTT_DATA_LEN_SIZE; /* For packet_id */
    }

#ifdef WOLFMQTT_V5
    if (publish->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        props_len = MqttEncode_Props(MQTT_PACKET_TYPE_PUBLISH,
                          publish->props, NULL);
        if (props_len >= 0) {
            variable_len += props_len;

            /* Determine the length of the "property length" */
            variable_len += MqttEncode_Vbi(NULL, props_len);
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif

    if (((publish->buffer != NULL) || (use_cb == 1)) &&
        (publish->total_len > 0)) {
        payload_len = publish->total_len;
    }

    /* Encode fixed header */
    publish->type = MQTT_PACKET_TYPE_PUBLISH;
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len,
        variable_len + payload_len, publish->type,
        publish->retain, publish->qos, publish->duplicate);
    if (header_len < 0) {
        return header_len;
    }

    tx_payload = &tx_buf[header_len];

    if (use_cb == 1) {
        /* The callback will encode the payload */
        payload_len = 0;
    }

    /* Check for buffer room */
    if (tx_buf_len < header_len + variable_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Encode variable header */
    tx_payload += MqttEncode_String(tx_payload, publish->topic_name);
    if (publish->qos > MQTT_QOS_0) {
        tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);
    }

#ifdef WOLFMQTT_V5
    if (publish->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Encode the property length */
        tx_payload += MqttEncode_Vbi(tx_payload, props_len);

        /* Encode properties */
        tx_payload += MqttEncode_Props((MqttPacketType)publish->type,
            publish->props, tx_payload);
    }
#endif

    /* Encode payload */
    if (payload_len > 0) {
        /* Check for buffer room */
        if (tx_buf_len < header_len + variable_len) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        /* Determine max size to copy into tx_payload */
        if (payload_len > (tx_buf_len - (header_len + variable_len))) {
            payload_len = (tx_buf_len - (header_len + variable_len));
        }
        if (tx_payload != NULL) {
            XMEMCPY(tx_payload, publish->buffer, payload_len);
        }
        /* mark how much data was sent */
        publish->buffer_pos = payload_len;

        /* Backwards compatibility for chunk transfers */
        if (publish->buffer_len == 0) {
            publish->buffer_len = publish->total_len;
        }
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
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    publish->type = MQTT_PACKET_TYPE_PUBLISH;
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len,
        &remain_len, publish->type, &publish->qos,
        &publish->retain, &publish->duplicate);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    variable_len = MqttDecode_String(rx_payload, &publish->topic_name,
        &publish->topic_name_len, (word32)(rx_buf_len - (rx_payload - rx_buf)));
    if (variable_len + header_len <= rx_buf_len) {
        rx_payload += variable_len;
    }
    else {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* If QoS > 0 then get packet Id */
    if (publish->qos > MQTT_QOS_0) {
        int tmp;
        if (rx_payload - rx_buf + MQTT_DATA_LEN_SIZE > rx_buf_len) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        tmp = MqttDecode_Num(rx_payload, &publish->packet_id,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        variable_len += tmp;
        if (variable_len + header_len <= rx_buf_len) {
            rx_payload += MQTT_DATA_LEN_SIZE;
        }
        else {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
    }

#ifdef WOLFMQTT_V5
    publish->props = NULL;
    if (publish->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        word32 props_len = 0;
        int tmp;

        /* Decode Length of Properties */
        if (rx_buf_len < (rx_payload - rx_buf)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        tmp = MqttDecode_Vbi(rx_payload, &props_len,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0)
            return tmp;
        variable_len += tmp + props_len;
        if (variable_len + header_len <= rx_buf_len) {
            rx_payload += tmp;
            if (props_len > 0) {
                /* Decode the Properties */
                tmp = MqttDecode_Props((MqttPacketType)publish->type,
                    &publish->props, rx_payload,
                    (word32)(rx_buf_len - (rx_payload - rx_buf)), props_len);
                if (tmp < 0)
                    return tmp;
                rx_payload += tmp;
            }
        }
        else {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
    }
#endif

    /* Decode Payload */
    payload_len = remain_len - variable_len;
    publish->buffer = rx_payload;
    publish->buffer_new = 1;
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
    int props_len = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL || publish_resp == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */

#ifdef WOLFMQTT_V5
    if (publish_resp->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5)
    {
        if (publish_resp->reason_code != MQTT_REASON_SUCCESS) {
            /* Reason Code */
            remain_len++;
        }
        if (publish_resp->props != NULL) {
            /* Determine length of properties */
            props_len = MqttEncode_Props((MqttPacketType)type,
                            publish_resp->props, NULL);
            if (props_len >= 0) {
                remain_len += props_len;
                /* Determine the length of the "property length" */
                remain_len += MqttEncode_Vbi(NULL, props_len);
            }
            else
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
        }
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
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], publish_resp->packet_id);

#ifdef WOLFMQTT_V5
    if (publish_resp->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5)
    {
        if (publish_resp->reason_code != MQTT_REASON_SUCCESS) {
            /* Encode the Reason Code */
            *tx_payload++ = publish_resp->reason_code;
        }
        if (publish_resp->props != NULL) {
            /* Encode the property length */
            tx_payload += MqttEncode_Vbi(tx_payload, props_len);

            /* Encode properties */
            tx_payload += MqttEncode_Props((MqttPacketType)type,
                            publish_resp->props, tx_payload);
        }
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
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
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
        int tmp;
        tmp = MqttDecode_Num(rx_payload, &publish_resp->packet_id,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        rx_payload += tmp;

#ifdef WOLFMQTT_V5
        publish_resp->props = NULL;
        if (publish_resp->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
            if (remain_len > MQTT_DATA_LEN_SIZE) {
                /* Decode the Reason Code */
                publish_resp->reason_code = *rx_payload++;
            }
            else {
                publish_resp->reason_code = MQTT_REASON_SUCCESS;
            }

            if (remain_len > MQTT_DATA_LEN_SIZE+1) {
                word32 props_len = 0;
                int props_tmp;

                /* Decode Length of Properties */
                if (rx_buf_len < (rx_payload - rx_buf)) {
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                }
                props_tmp = MqttDecode_Vbi(rx_payload, &props_len,
                        (word32)(rx_buf_len - (rx_payload - rx_buf)));
                if (tmp < 0)
                    return tmp;

                if (props_len <= (word32)(rx_buf_len - (rx_payload - rx_buf))) {
                    rx_payload += props_tmp;
                    if (props_len > 0) {
                        /* Decode the Properties */
                        props_tmp = MqttDecode_Props((MqttPacketType)type,
                                &publish_resp->props, rx_payload,
                                (word32)(rx_buf_len - (rx_payload - rx_buf)),
                                props_len);
                        if (props_tmp < 0)
                            return props_tmp;
                        rx_payload += props_tmp;
                    }
                }
                else {
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                }
            }
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
    int props_len = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL || subscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
    for (i = 0; i < subscribe->topic_count; i++) {
        topic = &subscribe->topics[i];
        if ((topic != NULL) && (topic->topic_filter != NULL)) {
            remain_len += (int)XSTRLEN(topic->topic_filter) + MQTT_DATA_LEN_SIZE;
            remain_len++; /* For QoS */
        }
        else {
            /* Topic count is invalid */
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
    }
#ifdef WOLFMQTT_V5
    if (subscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        props_len = MqttEncode_Props(MQTT_PACKET_TYPE_SUBSCRIBE,
                                    subscribe->props, NULL);
        if (props_len >= 0) {
            remain_len += props_len;

            /* Determine the length of the "property length" */
            remain_len += MqttEncode_Vbi(NULL, props_len);
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif


    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_SUBSCRIBE, 0, MQTT_QOS_1, 0);
    if (header_len < 0) {
        return header_len;
    }
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], subscribe->packet_id);

#ifdef WOLFMQTT_V5
    if (subscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Encode the property length */
        tx_payload += MqttEncode_Vbi(tx_payload, props_len);

        /* Encode properties */
        tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_SUBSCRIBE, subscribe->props,
                        tx_payload);
    }
#endif

    /* Encode payload */
    for (i = 0; i < subscribe->topic_count; i++) {
        topic = &subscribe->topics[i];
        tx_payload += MqttEncode_String(tx_payload, topic->topic_filter);
        /* Sanity check for compilers */
        if (tx_payload != NULL) {
            *tx_payload = topic->qos;
        }
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
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
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
        int tmp;
        tmp = MqttDecode_Num(rx_payload, &subscribe_ack->packet_id,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        rx_payload += tmp;

#ifdef WOLFMQTT_V5
        subscribe_ack->props = NULL;
        if ((subscribe_ack->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) &&
            (remain_len > MQTT_DATA_LEN_SIZE)) {
            word32 props_len = 0;
            int props_tmp;

            /* Decode Length of Properties */
            if (rx_buf_len < (rx_payload - rx_buf)) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            props_tmp = MqttDecode_Vbi(rx_payload, &props_len,
                    (word32)(rx_buf_len - (rx_payload - rx_buf)));
            if (props_tmp < 0)
                return props_tmp;

            if (props_len <= (word32)(rx_buf_len - (rx_payload - rx_buf))) {
                rx_payload += props_tmp;
                if (props_len > 0) {
                    /* Decode the Properties */
                    props_tmp = MqttDecode_Props(MQTT_PACKET_TYPE_SUBSCRIBE_ACK,
                                &subscribe_ack->props, rx_payload,
                                (word32)(rx_buf_len - (rx_payload - rx_buf)),
                                props_len);
                    if (props_tmp < 0)
                        return props_tmp;
                    rx_payload += props_tmp;
                }
            }
            else {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
        }
#endif

        /* payload is list of return codes (MqttSubscribeAckReturnCodes) */
        if (remain_len > MAX_MQTT_TOPICS)
            remain_len = MAX_MQTT_TOPICS;
        XMEMCPY(subscribe_ack->return_codes, rx_payload, remain_len);
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
    int props_len = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL || unsubscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
    for (i = 0; i < unsubscribe->topic_count; i++) {
        topic = &unsubscribe->topics[i];
        if ((topic != NULL) && (topic->topic_filter != NULL)) {
            remain_len += (int)XSTRLEN(topic->topic_filter) +
                                MQTT_DATA_LEN_SIZE;
        }
        else {
            /* Topic count is invalid */
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
    }
#ifdef WOLFMQTT_V5
    if (unsubscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        props_len = MqttEncode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE,
                                            unsubscribe->props, NULL);
        if (props_len >= 0) {
            remain_len += props_len;
            /* Determine the length of the "property length" */
            remain_len += MqttEncode_Vbi(NULL, props_len);
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_UNSUBSCRIBE, 0, MQTT_QOS_1, 0);
    if (header_len < 0) {
        return header_len;
    }
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], unsubscribe->packet_id);
#ifdef WOLFMQTT_V5
    if (unsubscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Encode the property length */
        tx_payload += MqttEncode_Vbi(tx_payload, props_len);

        /* Encode properties */
        tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE,
                        unsubscribe->props, tx_payload);
    }
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
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
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
        int tmp;
        tmp = MqttDecode_Num(rx_payload, &unsubscribe_ack->packet_id,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        rx_payload += tmp;
#ifdef WOLFMQTT_V5
        unsubscribe_ack->props = NULL;
        if (unsubscribe_ack->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
            if (remain_len > MQTT_DATA_LEN_SIZE) {
                word32 props_len = 0;
                int props_tmp;

                /* Decode Length of Properties */
                if (rx_buf_len < (rx_payload - rx_buf)) {
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                }
                props_tmp = MqttDecode_Vbi(rx_payload, &props_len,
                        (word32)(rx_buf_len - (rx_payload - rx_buf)));
                if (tmp < 0)
                    return tmp;

                if (props_len <= (word32)(rx_buf_len - (rx_payload - rx_buf))) {
                    rx_payload += props_tmp;
                    if (props_len > 0) {
                        /* Decode the Properties */
                        props_tmp = MqttDecode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK,
                                &unsubscribe_ack->props, rx_payload,
                                (word32)(rx_buf_len - (rx_payload - rx_buf)),
                                props_len);
                        if (props_tmp < 0)
                            return props_tmp;
                        rx_payload += props_tmp;
                    }
                }
                else {
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                }
            }

            /* Reason codes are stored in the payload */
            unsubscribe_ack->reason_codes = rx_payload;
        }
#endif
    }
    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttEncode_Ping(byte *tx_buf, int tx_buf_len, MqttPing* ping)
{
    int header_len, remain_len = 0;

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_PING_REQ, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }

    if (ping) {
        /* nothing to encode */
    }

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttDecode_Ping(byte *rx_buf, int rx_buf_len, MqttPing* ping)
{
    int header_len, remain_len;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_PING_RESP, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }

    if (ping) {
        /* nothing to decode */
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
    int props_len = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

#ifdef WOLFMQTT_V5
    if ((disconnect != NULL) &&
        (disconnect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5)) {

        if (disconnect->props != NULL) {
            /* Determine length of properties */
            props_len = MqttEncode_Props(MQTT_PACKET_TYPE_DISCONNECT,
                                        disconnect->props, NULL);
            if (props_len >= 0) {
                remain_len += props_len;
                /* Determine the length of the "property length" */
                remain_len += MqttEncode_Vbi(NULL, props_len);
            }
            else
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
        }
        if ((remain_len != 0) ||
            (disconnect->reason_code != MQTT_REASON_SUCCESS)) {
            /* Length of Reason Code */
            remain_len++;
        }
    }
#endif

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_DISCONNECT, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

#ifdef WOLFMQTT_V5
    if ((disconnect != NULL) &&
        (disconnect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5)) {
        byte* tx_payload = &tx_buf[header_len];
        if ((remain_len != 0) ||
            (disconnect->reason_code != MQTT_REASON_SUCCESS)) {
            /* Encode the Reason Code */
            *tx_payload++ = disconnect->reason_code;
        }

        if (disconnect->props != NULL) {
            /* Encode the property length */
            tx_payload += MqttEncode_Vbi(tx_payload, props_len);

            /* Encode properties */
            tx_payload += MqttEncode_Props(MQTT_PACKET_TYPE_DISCONNECT,
                            disconnect->props, tx_payload);
        }
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
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_DISCONNECT, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    rx_payload = &rx_buf[header_len];

    disc->props = NULL;
    if (remain_len > 0) {
        /* Decode variable header */
        disc->reason_code = *rx_payload++;

        if (remain_len > 1) {
            int props_tmp;
            /* Decode Length of Properties */
            if (rx_buf_len < (rx_payload - rx_buf)) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            props_tmp = MqttDecode_Vbi(rx_payload, &props_len,
                    (word32)(rx_buf_len - (rx_payload - rx_buf)));
            if (props_tmp < 0)
                return props_tmp;

            if (props_len <= (word32)(rx_buf_len - (rx_payload - rx_buf))) {
                rx_payload += props_tmp;
                if (props_len > 0) {
                    /* Decode the Properties */
                    props_tmp = MqttDecode_Props(MQTT_PACKET_TYPE_DISCONNECT,
                            &disc->props, rx_payload,
                            (word32)(rx_buf_len - (rx_payload - rx_buf)),
                            props_len);
                    if (props_tmp < 0)
                        return props_tmp;
                    rx_payload += props_tmp;
                }
            }
            else {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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
    int props_len = 0;

    /* Validate required arguments */
    if ((tx_buf == NULL) || (tx_buf_len <= 0) || (auth == NULL)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Length of Reason Code */
    remain_len++;

    /* Determine length of properties */
    props_len = MqttEncode_Props(MQTT_PACKET_TYPE_AUTH,
                                auth->props, NULL);
    if (props_len >= 0) {
        remain_len += props_len;
        /* Determine the length of the "property length" */
        remain_len += MqttEncode_Vbi(NULL, props_len);
    }
    else
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
                  MQTT_PACKET_TYPE_AUTH, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
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
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    (void)tx_payload;

    /* Return total length of packet */
    return header_len + remain_len;

}

int MqttDecode_Auth(byte *rx_buf, int rx_buf_len, MqttAuth *auth)
{
    int header_len, remain_len, tmp;
    byte *rx_payload;
    word32 props_len = 0;


    /* Validate required arguments */
    if ((rx_buf == NULL) || (rx_buf_len <= 0) || (auth == NULL)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
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
        auth->props = NULL;

        /* Decode Length of Properties */
        if (rx_buf_len < (rx_payload - rx_buf)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        tmp = MqttDecode_Vbi(rx_payload, &props_len,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0)
            return tmp;

        if (props_len <= (word32)(rx_buf_len - (rx_payload - rx_buf))) {
            rx_payload += tmp;
            if ((rx_payload - rx_buf) > rx_buf_len) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            if (props_len > 0) {
                /* Decode the Properties */
                tmp = MqttDecode_Props(MQTT_PACKET_TYPE_AUTH,
                        &auth->props, rx_payload,
                        (word32)(rx_buf_len - (rx_payload - rx_buf)),
                        props_len);
                if (tmp < 0)
                    return tmp;
                rx_payload += tmp;
            }
            else if (auth->reason_code != MQTT_REASON_SUCCESS) {
                /* The Reason Code and Property Length can be omitted if the
                   Reason Code is 0x00 (Success) and there are no Properties.
                   In this case the AUTH has a Remaining Length of 0. */
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
            }
            if (auth->props != NULL) {
                /* Must have Authentication Method */

                /* Must have Authentication Data */

                /* May have zero or more User Property pairs */
            }
            else {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
            }
        }
        else {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
    }
    else {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

int MqttProps_Init(void)
{
    int ret = MQTT_CODE_SUCCESS;
#if !defined(WOLFMQTT_DYN_PROP) && defined(WOLFMQTT_MULTITHREAD)
    if (clientPropStack_lockInit == 0) {
        clientPropStack_lockInit++;
        ret = wm_SemInit(&clientPropStack_lock);
    }
#endif
    return  ret;
}

int MqttProps_ShutDown(void)
{
    int ret = MQTT_CODE_SUCCESS;
#if !defined(WOLFMQTT_DYN_PROP) && defined(WOLFMQTT_MULTITHREAD)
    clientPropStack_lockInit--;
    if (clientPropStack_lockInit == 0) {
        ret = wm_SemFree(&clientPropStack_lock);
    }
#endif
    return ret;
}

/* Add property */
MqttProp* MqttProps_Add(MqttProp **head)
{
    MqttProp *new_prop = NULL, *prev = NULL, *cur;
#ifndef WOLFMQTT_DYN_PROP
    int i;
#endif

    if (head == NULL) {
        return NULL;
    }

#if !defined(WOLFMQTT_DYN_PROP) && defined(WOLFMQTT_MULTITHREAD)
    if (wm_SemLock(&clientPropStack_lock) != 0) {
        return NULL;
    }
#endif

    cur = *head;

    /* Find the end of the parameter list */
    while (cur != NULL) {
        prev = cur;
        cur = cur->next;
    };

#ifndef WOLFMQTT_DYN_PROP
    /* Find a free element */
    for (i = 0; i < MQTT_MAX_PROPS; i++) {
        if (clientPropStack[i].type == MQTT_PROP_NONE) {
            /* Found one */
            new_prop = &clientPropStack[i];
            XMEMSET(new_prop, 0, sizeof(MqttProp));
            break;
        }
    }
#else
    /* Allocate a new prop */
    new_prop = WOLFMQTT_MALLOC(sizeof(MqttProp));
    if (new_prop != NULL) {
        XMEMSET(new_prop, 0, sizeof(MqttProp));
    }
#endif

    if (new_prop != NULL) {
        /* set placeholder until caller sets it to a real type */
        new_prop->type = MQTT_PROP_TYPE_MAX;
        if (prev == NULL) {
            /* Start a new list */
            *head = new_prop;
        }
        else {
            /* Add to the existing list */
            prev->next = new_prop;
        }
    }
    else {
        /* Could not allocate property */
        (void)MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }

#if !defined(WOLFMQTT_DYN_PROP) && defined(WOLFMQTT_MULTITHREAD)
    (void)wm_SemUnlock(&clientPropStack_lock);
#endif

    return new_prop;
}

/* Free properties */
int MqttProps_Free(MqttProp *head)
{
    int ret = MQTT_CODE_SUCCESS;
#if !defined(WOLFMQTT_DYN_PROP) && defined(WOLFMQTT_MULTITHREAD)
    if ((ret = wm_SemLock(&clientPropStack_lock)) != 0) {
        return ret;
    }
#endif
    while (head != NULL) {
#ifndef WOLFMQTT_DYN_PROP
        head->type = MQTT_PROP_NONE; /* available */
        head = head->next;
#else
        MqttProp *tmp;

        tmp = head->next;
        WOLFMQTT_FREE(head);
        head = tmp;
#endif
    }
#if !defined(WOLFMQTT_DYN_PROP) && defined(WOLFMQTT_MULTITHREAD)
    (void)wm_SemUnlock(&clientPropStack_lock);
#endif
    return ret;
}

#endif /* WOLFMQTT_V5 */

int MqttPacket_HandleNetError(MqttClient *client, int rc)
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
        rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
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
            client->packet.header_len = MQTT_PACKET_HEADER_MIN_SIZE;
            client->packet.remain_len = 0;

            /* Read fix header portion */
            rc = MqttSocket_Read(client, rx_buf, client->packet.header_len,
                    timeout_ms);
            if (rc < 0) {
                return MqttPacket_HandleNetError(client, rc);
            }
            else if (rc != client->packet.header_len) {
                return MqttPacket_HandleNetError(client,
                         MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK));
            }
        }
        FALL_THROUGH;

        case MQTT_PK_READ_HEAD:
        {
            int i;
            client->packet.stat = MQTT_PK_READ_HEAD;

            for (i = (client->packet.header_len - MQTT_PACKET_HEADER_MIN_SIZE);
                 i < MQTT_PACKET_MAX_LEN_BYTES;
                 i++) {
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
                             MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK));
                }
                client->packet.header_len += len;
            }

            if (i == MQTT_PACKET_MAX_LEN_BYTES) {
                return MqttPacket_HandleNetError(client,
                        MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA));
            }

            /* Try and decode remaining length */
            if (rx_buf_len < (client->packet.header_len - (i + 1))) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            rc = MqttDecode_Vbi(header->len,
                    (word32*)&client->packet.remain_len,
                    rx_buf_len - (client->packet.header_len - (i + 1)));
            if (rc < 0) { /* Indicates error */
                return MqttPacket_HandleNetError(client, rc);
            }
            /* Indicates decode success and rc is len of header */
            else {
                /* Add size of type and flags */
                rc += sizeof(header->type_flags);
                client->packet.header_len = rc;
            }
        }
        FALL_THROUGH;

        case MQTT_PK_READ:
        {
            /* read remainder of packet */
            remain_read = client->packet.remain_len;
            client->packet.stat = MQTT_PK_READ;

            /* Make sure it does not overflow rx_buf */
            if (rx_buf_len < client->packet.header_len) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            if (remain_read > rx_buf_len - client->packet.header_len) {
                remain_read = rx_buf_len - client->packet.header_len;
            }

            /* Read remaining */
            if (client->packet.remain_len > 0) {
                rc = MqttSocket_Read(client, &rx_buf[client->packet.header_len],
                    remain_read, timeout_ms);
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

#ifndef WOLFMQTT_NO_ERROR_STRINGS
const char* MqttPacket_TypeDesc(MqttPacketType packet_type)
{
    switch (packet_type) {
        case MQTT_PACKET_TYPE_CONNECT:
            return "Connect";
        case MQTT_PACKET_TYPE_CONNECT_ACK:
            return "Connect Ack";
        case MQTT_PACKET_TYPE_PUBLISH:
            return "Publish";
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
            return "Publish Ack";
        case MQTT_PACKET_TYPE_PUBLISH_REC:
            return "Publish Received";
        case MQTT_PACKET_TYPE_PUBLISH_REL:
            return "Publish Release";
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
            return "Publish Complete";
        case MQTT_PACKET_TYPE_SUBSCRIBE:
            return "Subscribe";
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
            return "Subscribe Ack";
        case MQTT_PACKET_TYPE_UNSUBSCRIBE:
            return "Unsubscribe";
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
            return "Unsubscribe Ack";
        case MQTT_PACKET_TYPE_PING_REQ:
            return "Ping Req";
        case MQTT_PACKET_TYPE_PING_RESP:
            return "Ping Resp";
        case MQTT_PACKET_TYPE_DISCONNECT:
            return "Disconnect";
        case MQTT_PACKET_TYPE_AUTH:
            return "Auth";
        case MQTT_PACKET_TYPE_RESERVED:
            return "Reserved";
        case MQTT_PACKET_TYPE_ANY:
            return "Any";
        default:
            break;
    }
    return "Unknown";
}

#endif
