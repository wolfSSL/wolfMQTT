/* mqtt_packet.c
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
        (1 << MQTT_PACKET_TYPE_CONNECT) |
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
        (1 << MQTT_PACKET_TYPE_CONNECT) },
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

/* Maximum number of active properties - overridable */
#ifndef MQTT_MAX_PROPS
#define MQTT_MAX_PROPS 30
#endif

/* WOLFMQTT_DYN_PROP allows property allocation using malloc */
#ifndef WOLFMQTT_DYN_PROP

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

/* [MQTT-2.2.2-2] Required fixed-header reserved-flag values per packet type.
 * PUBLISH (type 3) carries DUP/QoS/RETAIN and is validated separately. */
static int FixedHeaderFlagsExpected(byte type, byte *expected)
{
    switch (type) {
        case MQTT_PACKET_TYPE_CONNECT:
        case MQTT_PACKET_TYPE_CONNECT_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
        case MQTT_PACKET_TYPE_PING_REQ:
        case MQTT_PACKET_TYPE_PING_RESP:
        case MQTT_PACKET_TYPE_DISCONNECT:
        case MQTT_PACKET_TYPE_AUTH:
            *expected = 0x0;
            return 1;
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_SUBSCRIBE:
        case MQTT_PACKET_TYPE_UNSUBSCRIBE:
            *expected = 0x2;
            return 1;
        default:
            return 0;
    }
}

/* [MQTT-3.9.3-2] Validate a SUBACK return code against the spec-allowed
 * set. v3.1.1 §3.9.3 restricts the payload to exactly four values
 * {0x00, 0x01, 0x02, 0x80}. v5 §3.9.3 broadens the set to include
 * additional Reason Codes (Implementation specific error, Not authorized,
 * Topic Filter invalid, Packet Identifier in use, Quota exceeded,
 * Shared Subscriptions not supported, Subscription Identifiers not
 * supported, Wildcard Subscriptions not supported). Anything outside
 * the level-appropriate set is reserved and MUST be treated as
 * malformed. protocol_level is taken as a byte (not enum) so callers
 * that don't compile WOLFMQTT_V5 can still pass 0 unambiguously. */
int MqttPacket_SubAckReturnCodeValid(byte code, byte protocol_level)
{
    if (code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0 ||
        code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS1 ||
        code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS2 ||
        code == MQTT_SUBSCRIBE_ACK_CODE_FAILURE) {
        return 1;
    }
#ifdef WOLFMQTT_V5
    if (protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        switch (code) {
            case MQTT_REASON_IMPL_SPECIFIC_ERR:    /* 0x83 */
            case MQTT_REASON_NOT_AUTHORIZED:       /* 0x87 */
            case MQTT_REASON_TOPIC_FILTER_INVALID: /* 0x8F */
            case MQTT_REASON_PACKET_ID_IN_USE:     /* 0x91 */
            case MQTT_REASON_QUOTA_EXCEEDED:       /* 0x97 */
            case MQTT_REASON_SS_NOT_SUPPORTED:     /* 0x9E */
            case MQTT_REASON_SUB_ID_NOT_SUP:       /* 0xA1 */
            case MQTT_REASON_WILDCARD_SUB_NOT_SUP: /* 0xA2 */
                return 1;
            default:
                break;
        }
    }
#else
    (void)protocol_level;
#endif
    return 0;
}

/* Validate an MQTT Topic Filter against the syntax rules from
 * [MQTT-4.7.3-1] (minimum length one character), [MQTT-4.7.1-2]
 * (multi-level wildcard '#' must be either the whole filter or directly
 * follow '/', and must be the final character), and [MQTT-4.7.1-3]
 * (single-level wildcard '+' must occupy an entire level). v5 §4.7
 * carries the same rules. Returns 1 if the filter is well-formed, 0 if
 * it must be treated as malformed. The length is decoded by the caller
 * via MqttDecode_String so this helper takes (filter, len) rather than
 * a NUL-terminated string. */
int MqttPacket_TopicFilterValid(const char* filter, word16 len)
{
    word16 i;
    if (filter == NULL || len == 0) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        char c = filter[i];
        if (c == '#') {
            if (i != 0 && filter[i - 1] != '/') {
                return 0;
            }
            if (i != (word16)(len - 1)) {
                return 0;
            }
        }
        else if (c == '+') {
            if (i != 0 && filter[i - 1] != '/') {
                return 0;
            }
            if (i != (word16)(len - 1) && filter[i + 1] != '/') {
                return 0;
            }
        }
    }
    return 1;
}

/* Validate an MQTT PUBLISH Topic Name against [MQTT-3.3.2-2] /
 * [MQTT-4.7.1-1] (Topic Names MUST NOT contain wildcard characters '#'
 * or '+'; applies to both v3.1.1 and v5) and [MQTT-4.7.3-1] (minimum
 * length one character) — but the latter is gated to v3.1.1 because
 * v5 §3.3.2.3.4 explicitly permits a zero-length Topic Name when
 * paired with a Topic Alias property. The pairing check (alias must
 * be present when the topic is empty) is left to the caller because
 * the property block hasn't been decoded yet at the wildcard-scan
 * point. NULL topic_name with non-zero len is malformed regardless. */
int MqttPacket_TopicNameValid(const char* topic_name, word16 len,
    byte protocol_level)
{
    word16 i;
    if (topic_name == NULL && len > 0) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (topic_name[i] == '#' || topic_name[i] == '+') {
            return 0;
        }
    }
    if (len == 0 && protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        return 0;
    }
    return 1;
}

/* Return 1 if the Topic Filter contains a multi-level ('#') or
 * single-level ('+') wildcard, 0 otherwise. The decoder has already
 * validated wildcard *placement* via MqttPacket_TopicFilterValid, so a
 * matching byte here is necessarily a real wildcard rather than a
 * misplaced one. Centralizes wildcard detection so the broker's
 * wildcard-disabled policy doesn't have to duplicate the scan. */
int MqttPacket_TopicFilterIsWildcard(const char* filter, word16 len)
{
    word16 i;
    if (filter == NULL) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (filter[i] == '#' || filter[i] == '+') {
            return 1;
        }
    }
    return 0;
}

int MqttPacket_FixedHeaderFlagsValid(byte type_flags)
{
    byte type = (byte)MQTT_PACKET_TYPE_GET(type_flags);
    byte flags = (byte)MQTT_PACKET_FLAGS_GET(type_flags);
    byte expected;

    if (type == MQTT_PACKET_TYPE_PUBLISH) {
        byte qos = (byte)MQTT_PACKET_FLAGS_GET_QOS(type_flags);
        byte dup = (flags & MQTT_PACKET_FLAG_DUPLICATE) ? 1 : 0;
        if (qos > MQTT_QOS_2) {
            return 0;
        }
        if (qos == MQTT_QOS_0 && dup) {
            return 0;
        }
        return 1;
    }
    if (FixedHeaderFlagsExpected(type, &expected)) {
        return (flags == expected) ? 1 : 0;
    }
    /* Reserved (type 0) or otherwise unrecognized packet type — reject so
     * this helper is safe to use as a protocol-level malformed-packet
     * gate. The broker uses it pre-dispatch, so anything it accepts has
     * to be a known type. */
    return 0;
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

    /* [MQTT-2.2.2-2] Reject invalid fixed-header reserved flags. */
    if (!MqttPacket_FixedHeaderFlagsValid(header->type_flags)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
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

    /* [MQTT-1.5.5-1] Reject non-canonical overlong encodings */
    if (rc > 1 && encodedByte == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    return (int)rc;
}

/* Encodes to buf a non-negative integer "x" in a Variable Byte Integer scheme.
   Returns the number of bytes encoded.
   If buf is NULL, return number of bytes that would be encoded. */
int MqttEncode_Vbi(byte *buf, word32 x)
{
    int rc = 0;
    byte encodedByte;

    /* [MQTT-2.2.3]: Max value is 268,435,455 (0x0FFFFFFF) */
    if (x > MQTT_PACKET_MAX_REMAIN_LEN) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

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
int MqttDecode_Int(byte* buf, word32* len, word32 buf_len)
{
    if (buf_len < MQTT_DATA_INT_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
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

/* MQTT 3.1.1 §1.5.3 / v5 §1.5.4: validate that the given byte sequence
 * is a well-formed MQTT UTF-8 encoded string. This combines:
 *   [MQTT-1.5.3-1] RFC 3629 well-formedness (no overlongs, no surrogate
 *                  code points U+D800..U+DFFF, no codepoints above
 *                  U+10FFFF, no lone continuation, no truncated multi-
 *                  byte sequences).
 *   [MQTT-1.5.3-2] U+0000 (the NUL character) MUST NOT be included in
 *                  any MQTT UTF-8 encoded string.
 * Returns 1 if valid, 0 if malformed.
 *
 * RFC 3629 byte-pattern table:
 *   1-byte: 01..7F                             -> U+0001..U+007F
 *   2-byte: C2..DF 80..BF                      -> U+0080..U+07FF
 *   3-byte: E0    A0..BF 80..BF                -> U+0800..U+0FFF
 *           E1..EC 80..BF 80..BF               -> U+1000..U+CFFF
 *           ED    80..9F 80..BF                -> U+D000..U+D7FF
 *           EE..EF 80..BF 80..BF               -> U+E000..U+FFFF
 *   4-byte: F0    90..BF 80..BF 80..BF         -> U+10000..U+3FFFF
 *           F1..F3 80..BF 80..BF 80..BF        -> U+40000..U+FFFFF
 *           F4    80..8F 80..BF 80..BF         -> U+100000..U+10FFFF
 * Note: 0x00 (U+0000) is excluded from the 1-byte range above per
 * [MQTT-1.5.3-2]. */
static int Utf8WellFormed(const byte* s, word16 len)
{
    word16 i = 0;
    while (i < len) {
        byte b0 = s[i];
        byte b1, b2, b3;

        if (b0 == 0x00) {
            /* [MQTT-1.5.3-2] U+0000 forbidden in MQTT UTF-8 strings. */
            return 0;
        }
        if (b0 < 0x80) {
            i++;
            continue;
        }
        if (b0 < 0xC2 || b0 > 0xF4) {
            /* C0/C1 are overlong-only; F5..FF exceed U+10FFFF or are not
             * UTF-8 leading bytes. */
            return 0;
        }
        if (b0 < 0xE0) {
            /* 2-byte */
            if ((word32)i + 1 >= (word32)len) return 0;
            b1 = s[i+1];
            if ((b1 & 0xC0) != 0x80) return 0;
            i += 2;
        }
        else if (b0 < 0xF0) {
            /* 3-byte */
            if ((word32)i + 2 >= (word32)len) return 0;
            b1 = s[i+1];
            b2 = s[i+2];
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) return 0;
            if (b0 == 0xE0 && b1 < 0xA0) return 0;          /* overlong */
            if (b0 == 0xED && b1 >= 0xA0) return 0;         /* surrogate */
            i += 3;
        }
        else {
            /* 4-byte (b0 in F0..F4) */
            if ((word32)i + 3 >= (word32)len) return 0;
            b1 = s[i+1];
            b2 = s[i+2];
            b3 = s[i+3];
            if ((b1 & 0xC0) != 0x80 ||
                (b2 & 0xC0) != 0x80 ||
                (b3 & 0xC0) != 0x80) return 0;
            if (b0 == 0xF0 && b1 < 0x90) return 0;          /* overlong */
            if (b0 == 0xF4 && b1 >= 0x90) return 0;         /* > U+10FFFF */
            i += 4;
        }
    }
    return 1;
}

/* Returns pointer to string (which is not guaranteed to be null terminated).
 * [MQTT-1.5.3-1] Rejects ill-formed UTF-8 with MQTT_CODE_ERROR_MALFORMED_DATA;
 * receivers MUST close the network connection on malformed packets, which the
 * existing decode-error propagation in the broker handles. */
int MqttDecode_String(byte *buf, const char **pstr, word16 *pstr_len, word32 buf_len)
{
    int len;
    word16 str_len;
    len = MqttDecode_Num(buf, &str_len, buf_len);
    if (len < 0) {
        return len;
    }
    if ((word32)str_len > buf_len - (word32)len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    buf += len;
    if (str_len > 0) {
        /* [MQTT-1.5.3-1] Reject ill-formed UTF-8 (RFC 3629). */
        if (!Utf8WellFormed(buf, str_len)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
        /* [MQTT-1.5.3-2] / [MQTT-1.5.4-2]: an MQTT UTF-8 encoded string
         * MUST NOT include the null character (U+0000). Although U+0000
         * is well-formed UTF-8, it is forbidden in MQTT string fields —
         * downstream C-string handling would otherwise be tricked by an
         * embedded NUL truncating the value (e.g., a topic "se\0cret"
         * would route to subscribers of "se"). The CONNECT Password
         * field is Binary Data per [MQTT-3.1.3.5] and bypasses this
         * helper; binary fields tolerate embedded NULs. */
        if (XMEMCHR(buf, 0x00, str_len) != NULL) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
    }
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
    int len;

    /* MQTT UTF-8 strings are limited to 65535 bytes [MQTT-1.5.3] */
    if (str_len > (int)0xFFFF) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    len = MqttEncode_Num(buf, (word16)str_len);

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
    int prop_count = 0;
    MqttProp* cur_prop = props;

    /* loop through the list properties */
    while ((cur_prop != NULL) && (rc >= 0))
    {
        /* Guard against a corrupted or circular property list */
        if (++prop_count > MQTT_MAX_PROPS) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
            break;
        }
        if (cur_prop->type >= sizeof(gPropMatrix) / sizeof(gPropMatrix[0])) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
            break;
        }

        /* Validate property type is allowed for this packet type */
        if (!(gPropMatrix[cur_prop->type].packet_type_mask & (1 << packet))) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY_MISMATCH);
            break;
        }

        /* Encode the Identifier */
        tmp = MqttEncode_Vbi(buf, (word32)cur_prop->type);
        if (tmp < 0) {
            return tmp;
        }
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
                tmp = MqttEncode_Data(buf,
                        (const byte*)cur_prop->data_str.str,
                        cur_prop->data_str.len);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }
                break;
            }
            case MQTT_DATA_TYPE_VAR_INT:
            {
                tmp = MqttEncode_Vbi(buf, cur_prop->data_int);
                if (tmp < 0) {
                    return tmp;
                }
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
                tmp = MqttEncode_Data(buf,
                        (const byte*)cur_prop->data_str.str,
                        cur_prop->data_str.len);
                rc += tmp;
                if (buf != NULL) {
                    buf += tmp;
                }

                tmp = MqttEncode_Data(buf,
                        (const byte*)cur_prop->data_str2.str,
                        cur_prop->data_str2.len);
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

        /* Check cumulative size against MQTT v5 max remaining length */
        if (rc > (int)MQTT_PACKET_MAX_REMAIN_LEN) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            break;
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

        /* Check boundary before VBI decoding */
        if ((buf - pbuf) > (int)buf_len) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            break;
        }
        /* Decode the Identifier */
        rc = MqttDecode_Vbi(buf, (word32*)&cur_prop->type,
                (word32)(buf_len - (buf - pbuf)));
        if (rc < 0) {
            break;
        }
        tmp = rc;
        buf += tmp;
        total += tmp;
        prop_len -= tmp;

        if (cur_prop->type >= sizeof(gPropMatrix) / sizeof(gPropMatrix[0])) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
            break;
        }

        /* Validate property type is allowed for packet type */
        if (!(gPropMatrix[cur_prop->type].packet_type_mask & (1 << packet))) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY_MISMATCH);
            break;
        }

        switch (gPropMatrix[cur_prop->type].data)
        {
            case MQTT_DATA_TYPE_BYTE:
            {
                if ((buf - pbuf) >= (int)buf_len || prop_len < 1) {
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                    break;
                }
                cur_prop->data_byte = *buf++;
                tmp++;
                total++;
                prop_len--;
                break;
            }
            case MQTT_DATA_TYPE_SHORT:
            {
                if ((buf - pbuf) > (int)buf_len) {
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                    break;
                }
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
                if ((buf - pbuf) > (int)buf_len ||
                     prop_len < MQTT_DATA_INT_SIZE) {
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                    break;
                }
                tmp = MqttDecode_Int(buf, &cur_prop->data_int,
                        (word32)(buf_len - (buf - pbuf)));
                if (tmp < 0) {
                    rc = tmp;
                    break;
                }
                buf += tmp;
                total += tmp;
                prop_len -= tmp;
                break;
            }
            case MQTT_DATA_TYPE_STRING:
            {
                if ((buf - pbuf) > (int)buf_len) {
                    /* Should already be caught earlier, but safe to recheck */
                    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
                    break;
                }
                tmp = MqttDecode_String(buf,
                        (const char**)&cur_prop->data_str.str,
                        &cur_prop->data_str.len,
                        (word32)(buf_len - (buf - pbuf)));
                if (tmp < 0) {
                    /* Preserve specific error (e.g., MALFORMED_DATA from
                     * UTF-8 check) instead of masking as PROPERTY. */
                    rc = tmp;
                }
                else if ((word32)tmp <= (buf_len - (buf - pbuf))) {
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
                    rc = tmp;
                    break;
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
                if (tmp < 0) {
                    rc = tmp;
                }
                else if ((word32)tmp <= (buf_len - (buf - pbuf))) {
                    buf += tmp;
                    total += tmp;
                    prop_len -= (word32)tmp;
                    if ((buf_len - (buf - pbuf)) > 0) {
                        tmp = MqttDecode_String(buf,
                                (const char**)&cur_prop->data_str2.str,
                                &cur_prop->data_str2.len,
                                (word32)(buf_len - (buf - pbuf)));
                        if (tmp < 0) {
                            rc = tmp;
                        }
                        else if ((word32)tmp <=
                                 (buf_len - (buf - pbuf))) {
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

    /* [MQTT-3.1.2-22]: If the User Name Flag is set to 0, the Password Flag
     * MUST be set to 0 */
    if (mc_connect->password != NULL && mc_connect->username == NULL) {
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
            int tmp_len = MqttEncode_Vbi(NULL, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            remain_len += props_len;

            /* Determine the length of the "property length" */
            remain_len += tmp_len;
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif

    /* MQTT UTF-8 strings are limited to 65535 bytes [MQTT-1.5.3]. Check here
     * (before writing the fixed header) so a later MqttEncode_String failure
     * cannot corrupt tx_payload via `tx_payload += -1`. */
    {
        size_t str_len = XSTRLEN(mc_connect->client_id);
        if (str_len > (size_t)0xFFFF) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
        remain_len += (int)str_len + MQTT_DATA_LEN_SIZE;
    }
    if (mc_connect->enable_lwt) {
        size_t str_len;
        /* Verify all required fields are present */
        if (mc_connect->lwt_msg == NULL ||
            mc_connect->lwt_msg->topic_name == NULL ||
            (mc_connect->lwt_msg->buffer == NULL &&
             mc_connect->lwt_msg->total_len != 0))
        {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
        str_len = XSTRLEN(mc_connect->lwt_msg->topic_name);
        if (str_len > (size_t)0xFFFF) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }

        remain_len += (int)str_len;
        remain_len += MQTT_DATA_LEN_SIZE;
        /* LWT payload uses word16 length prefix, validate it fits */
        if (mc_connect->lwt_msg->total_len > (word32)0xFFFF) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
        remain_len += mc_connect->lwt_msg->total_len;
        remain_len += MQTT_DATA_LEN_SIZE;
#ifdef WOLFMQTT_V5
    if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        lwt_props_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
                mc_connect->lwt_msg->props, NULL);
        if (lwt_props_len >= 0) {
            int tmp_len = MqttEncode_Vbi(NULL, lwt_props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            remain_len += lwt_props_len;

            /* Determine the length of the "lwt property length" */
            remain_len += tmp_len;
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif
    }
    if (mc_connect->username) {
        size_t str_len = XSTRLEN(mc_connect->username);
        if (str_len > (size_t)0xFFFF) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
        remain_len += (int)str_len + MQTT_DATA_LEN_SIZE;
    }
    if (mc_connect->password) {
        size_t str_len = XSTRLEN(mc_connect->password);
        if (str_len > (size_t)0xFFFF) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
        remain_len += (int)str_len + MQTT_DATA_LEN_SIZE;
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
        int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        /* Encode the property length */
        tx_payload += tmp_len;

        tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
             mc_connect->props, tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        /* Encode properties */
        tx_payload += tmp_len;
    }
#endif

    /* Encode payload */
    tx_payload += MqttEncode_String(tx_payload, mc_connect->client_id);
    if (mc_connect->enable_lwt) {
#ifdef WOLFMQTT_V5
    if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        int tmp_len = MqttEncode_Vbi(tx_payload, lwt_props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        /* Encode the lwt property length */
        tx_payload += tmp_len;

        tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT,
            mc_connect->lwt_msg->props, tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        /* Encode lwt properties */
        tx_payload += tmp_len;
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

#ifdef WOLFMQTT_BROKER
int MqttDecode_Connect(byte *rx_buf, int rx_buf_len, MqttConnect *mc_connect)
{
    int header_len, remain_len;
    byte *rx_payload;
    MqttConnectPacket packet;
    word16 protocol_len = 0;
    int tmp;
#ifdef WOLFMQTT_V5
    word32 props_len = 0;
#endif

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0 || mc_connect == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_CONNECT, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    if (rx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    rx_payload = &rx_buf[header_len];

    if ((int)sizeof(MqttConnectPacket) > remain_len ||
        (rx_buf_len < header_len + (int)sizeof(MqttConnectPacket))) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }

    /* Decode variable header */
    XMEMCPY(&packet, rx_payload, sizeof(MqttConnectPacket));
    rx_payload += sizeof(MqttConnectPacket);

    tmp = MqttDecode_Num(packet.protocol_len, &protocol_len,
        MQTT_DATA_LEN_SIZE);
    if (tmp < 0) {
        return tmp;
    }
    if ((protocol_len != MQTT_CONNECT_PROTOCOL_NAME_LEN) ||
        (XMEMCMP(packet.protocol_name, MQTT_CONNECT_PROTOCOL_NAME,
            MQTT_CONNECT_PROTOCOL_NAME_LEN) != 0)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    mc_connect->protocol_level = packet.protocol_level;
    mc_connect->clean_session =
        (packet.flags & MQTT_CONNECT_FLAG_CLEAN_SESSION) ? 1 : 0;
    mc_connect->enable_lwt =
        (packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) ? 1 : 0;
    mc_connect->username = NULL;
    mc_connect->password = NULL;

    /* [MQTT-3.1.2-3] CONNECT flags bit 0 is reserved and MUST be 0.
     * Applies to both v3.1.1 and v5. */
    if (packet.flags & MQTT_CONNECT_FLAG_RESERVED) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* [MQTT-3.1.2-13] / [MQTT-3.1.2-15] If the Will Flag is 0, Will QoS
     * MUST be 0 and Will Retain MUST be 0. Applies to both v3.1.1 and v5
     * (v5 section 3.1.2.6 / 3.1.2.5 carry the same constraint). */
    if (!(packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) &&
        (packet.flags & (MQTT_CONNECT_FLAG_WILL_QOS_MASK |
                         MQTT_CONNECT_FLAG_WILL_RETAIN))) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* [MQTT-3.1.2-14] Will QoS = 3 is reserved and MUST NOT be used.
     * Only meaningful when Will Flag = 1; the Will-Flag-0 check above
     * already rejects nonzero QoS bits in that case. */
    if ((packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) &&
        MQTT_CONNECT_FLAG_GET_QOS(packet.flags) == MQTT_QOS_3) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* [MQTT-3.1.2-22] (v3.1.1 only) If the User Name Flag is 0, the
     * Password Flag MUST be 0. MQTT v5 section 3.1.2.9 explicitly relaxes
     * this — "This version of the protocol allows the sending of a
     * Password with no User Name, where MQTT v3.1.1 did not." — so the
     * check is gated on the protocol level. mc_connect->protocol_level was
     * just populated above. */
    if (mc_connect->protocol_level == MQTT_CONNECT_PROTOCOL_LEVEL_4 &&
        (packet.flags & MQTT_CONNECT_FLAG_PASSWORD) &&
        !(packet.flags & MQTT_CONNECT_FLAG_USERNAME)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    tmp = MqttDecode_Num((byte*)&packet.keep_alive, &mc_connect->keep_alive_sec,
        MQTT_DATA_LEN_SIZE);
    if (tmp < 0) {
        return tmp;
    }

#ifdef WOLFMQTT_V5
    mc_connect->props = NULL;
    /* Only decode v5 properties when the level is exactly 5. Treating any
     * level >= 5 as v5 incorrectly consumes a properties-length byte for
     * unsupported levels (e.g., 6) — the broker's [MQTT-3.1.2-2] rejection
     * runs after this function, so we must let the wire decode under the
     * level the spec actually defines for it (here: nothing, fall through
     * to the v3.1.1-shape payload).
     *
     * Corner case: a peer claiming level 6 but sending a v5-shape wire
     * (extra properties-length VBI present) will misparse on the v3.1.1
     * path and the strict tail-consumption check below returns
     * MALFORMED_DATA, which the broker translates to a silent socket
     * close — CONNACK 0x01 is emitted only when the v3.1.1-shape decode
     * succeeds. This is a best-effort spec compliance trade-off; clients
     * that misrepresent their protocol level should not expect the broker
     * to reverse-engineer the wire shape. */
    if (mc_connect->protocol_level == MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Decode Length of Properties */
        if (rx_buf_len < (rx_payload - rx_buf)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        tmp = MqttDecode_Vbi(rx_payload, &props_len,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        rx_payload += tmp;
        if (props_len > 0) {
            /* Decode the Properties */
            tmp = MqttDecode_Props(MQTT_PACKET_TYPE_CONNECT,
                    &mc_connect->props, rx_payload,
                    (word32)(rx_buf_len - (rx_payload - rx_buf)), props_len);
            if (tmp < 0) {
                return tmp;
            }
            rx_payload += tmp;
        }
    }
#endif

    /* Decode payload */
    tmp = MqttDecode_String(rx_payload, &mc_connect->client_id, NULL,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
    if (tmp < 0) {
        return tmp;
    }
    if ((rx_payload - rx_buf) + tmp > header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    rx_payload += tmp;

    if (mc_connect->enable_lwt) {
        if (mc_connect->lwt_msg == NULL) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }

        mc_connect->lwt_msg->qos =
            (MqttQoS)MQTT_CONNECT_FLAG_GET_QOS(packet.flags);
        mc_connect->lwt_msg->retain =
            (packet.flags & MQTT_CONNECT_FLAG_WILL_RETAIN) ? 1 : 0;

#ifdef WOLFMQTT_V5
        mc_connect->lwt_msg->props = NULL;
        /* See note above: only level 5 carries v5 LWT properties on the wire. */
        if (mc_connect->protocol_level == MQTT_CONNECT_PROTOCOL_LEVEL_5) {
            word32 lwt_props_len = 0;
            int lwt_tmp;
            /* Decode Length of LWT Properties */
            if (rx_buf_len < (rx_payload - rx_buf)) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            lwt_tmp = MqttDecode_Vbi(rx_payload, &lwt_props_len,
                    (word32)(rx_buf_len - (rx_payload - rx_buf)));
            if (lwt_tmp < 0) {
                return lwt_tmp;
            }
            rx_payload += lwt_tmp;
            if (lwt_props_len > 0) {
                /* Decode LWT Properties */
                lwt_tmp = MqttDecode_Props(MQTT_PACKET_TYPE_CONNECT,
                        &mc_connect->lwt_msg->props, rx_payload,
                        (word32)(rx_buf_len - (rx_payload - rx_buf)),
                        lwt_props_len);
                if (lwt_tmp < 0) {
                    return lwt_tmp;
                }
                rx_payload += lwt_tmp;
            }
        }
#endif

        tmp = MqttDecode_String(rx_payload, &mc_connect->lwt_msg->topic_name,
                &mc_connect->lwt_msg->topic_name_len,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        if ((rx_payload - rx_buf) + tmp > header_len + remain_len) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        rx_payload += tmp;

        {
            word16 lwt_len = 0;
            tmp = MqttDecode_Num(rx_payload, &lwt_len,
                    (word32)(rx_buf_len - (rx_payload - rx_buf)));
            if (tmp < 0) {
                return tmp;
            }
            mc_connect->lwt_msg->total_len = lwt_len;
        }
        rx_payload += tmp;
        if ((rx_payload - rx_buf) +
            (int)mc_connect->lwt_msg->total_len > header_len + remain_len) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        mc_connect->lwt_msg->buffer = rx_payload;
        mc_connect->lwt_msg->buffer_len = mc_connect->lwt_msg->total_len;
        mc_connect->lwt_msg->buffer_pos = 0;
        rx_payload += mc_connect->lwt_msg->total_len;
    }

    if (packet.flags & MQTT_CONNECT_FLAG_USERNAME) {
        tmp = MqttDecode_String(rx_payload, &mc_connect->username, NULL,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        if ((rx_payload - rx_buf) + tmp > header_len + remain_len) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        rx_payload += tmp;
    }

    if (packet.flags & MQTT_CONNECT_FLAG_PASSWORD) {
        /* Password is binary data, not a UTF-8 string ([MQTT-3.1.3.5]). Decode
         * the length prefix directly so MqttDecode_String's UTF-8 validation
         * does not reject non-UTF-8 password bytes. */
        word16 plen = 0;
        tmp = MqttDecode_Num(rx_payload, &plen,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        if ((word32)plen >
            (word32)(rx_buf_len - (rx_payload - rx_buf) - tmp)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        if ((rx_payload - rx_buf) + tmp + (int)plen >
            header_len + remain_len) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
        }
        mc_connect->password = (char*)(rx_payload + tmp);
        rx_payload += tmp + plen;
    }

    /* [MQTT-3.1.2-20] / [MQTT-3.1.2-22] and the payload-shape rules in
     * 3.1.3: only fields whose CONNECT flags are set may appear in the
     * payload. After decoding every flag-gated field the consumed length
     * must equal Remaining Length exactly. Trailing bytes mean the wire
     * carries fields the flags say are absent (e.g. Password Flag=0 with
     * a password-shaped suffix), which the receiver must reject as
     * malformed instead of silently dropping. */
    if ((rx_payload - rx_buf) != header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    /* Return total length of packet */
    return header_len + remain_len;
}
#endif /* WOLFMQTT_BROKER */

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

    /* Validate remain_len */
    if (remain_len < 2) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    rx_payload = &rx_buf[header_len];

    /* Decode variable header */
    if (connect_ack) {
        connect_ack->flags = *rx_payload++;
        connect_ack->return_code = *rx_payload++;

        /* [MQTT-3.2.2-1] Bits 7-1 of the Connect Acknowledge Flags byte are
         * reserved and MUST be 0. Any other value is a protocol violation;
         * [MQTT-4.8.0-1] requires the receiver to close the connection. */
        if ((connect_ack->flags &
             (byte)~MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) != 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
        /* [MQTT-3.2.2-4] If the CONNACK return code is non-zero (CONNECT
         * refused), Session Present MUST be 0. A refused CONNACK that
         * claims an existing session is malformed. */
        if (connect_ack->return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED &&
            (connect_ack->flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }

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

#ifdef WOLFMQTT_BROKER
int MqttEncode_ConnectAck(byte *tx_buf, int tx_buf_len,
    MqttConnectAck *connect_ack)
{
    int header_len, remain_len;
    byte *tx_payload;
#ifdef WOLFMQTT_V5
    int props_len = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL || connect_ack == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    remain_len = 2; /* flags + return code */
#ifdef WOLFMQTT_V5
    if (connect_ack->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        props_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT_ACK,
                        connect_ack->props, NULL);
        if (props_len >= 0) {
            /* Determine the length of the "property length" */
            int tmp_len = MqttEncode_Vbi(NULL, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            remain_len += props_len;
            remain_len += tmp_len;
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
    }
#endif

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_CONNECT_ACK, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    *tx_payload++ = connect_ack->flags;
    *tx_payload++ = connect_ack->return_code;

#ifdef WOLFMQTT_V5
    if (connect_ack->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Encode the property length */
        int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;

        /* Encode properties */
        tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_CONNECT_ACK,
                        connect_ack->props, tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;
    }
#endif

    (void)tx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}
#endif /* WOLFMQTT_BROKER */

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
    /* MQTT UTF-8 strings are limited to 65535 bytes [MQTT-1.5.3]. Check here
     * before writing the fixed header so a later MqttEncode_String failure
     * cannot corrupt tx_payload via `tx_payload += -1`. NULL topic_name
     * is API misuse (BAD_ARG); callers using v5 Topic Alias must pass
     * an empty string "" rather than NULL. */
    {
        size_t str_len;
        byte level = 0;
        if (publish->topic_name == NULL) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
        str_len = XSTRLEN(publish->topic_name);
        if (str_len > (size_t)0xFFFF) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
    #ifdef WOLFMQTT_V5
        level = publish->protocol_level;
    #endif
        /* [MQTT-3.3.2-2] / [MQTT-4.7.1-1] wildcards always forbidden in
         * Topic Names. [MQTT-4.7.3-1] empty Topic Names rejected for
         * v3.1.1; allowed for v5 with caller-managed Topic Alias. */
        if (!MqttPacket_TopicNameValid(publish->topic_name,
                                       (word16)str_len, level)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }

        /* Determine packet length */
        variable_len = (int)str_len + MQTT_DATA_LEN_SIZE;
    }
    if (publish->qos > MQTT_QOS_0) {
        if (publish->packet_id == 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
        }
        variable_len += MQTT_DATA_LEN_SIZE; /* For packet_id */
    }
    else if (publish->duplicate) {
        /* [MQTT-3.3.1-2] DUP MUST be 0 for all QoS 0 PUBLISH messages.
         * The decoder rejects this combination via MqttPacket_FixedHeader
         * FlagsValid; mirror the constraint at the encoder boundary so the
         * library never produces a forbidden wire packet for a caller. */
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

#ifdef WOLFMQTT_V5
    if (publish->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        props_len = MqttEncode_Props(MQTT_PACKET_TYPE_PUBLISH,
                          publish->props, NULL);
        if (props_len >= 0) {
            /* Determine the length of the "property length" */
            int tmp_len = MqttEncode_Vbi(NULL, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            variable_len += props_len;
            variable_len += tmp_len;
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
        int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;

        /* Encode properties */
        tmp_len = MqttEncode_Props((MqttPacketType)publish->type,
            publish->props, tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;
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
    if (variable_len < 0) {
        /* Preserve specific error (e.g., MALFORMED_DATA from UTF-8 check). */
        return variable_len;
    }
    if (variable_len + header_len > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    /* [MQTT-3.3.2-2] / [MQTT-4.7.1-1] Reject Topic Names containing
     * wildcards (both versions). [MQTT-4.7.3-1] Reject empty Topic
     * Names for v3.1.1; v5 §3.3.2.3.4 permits a zero-length Topic Name
     * paired with a Topic Alias property — the alias-empty pairing is
     * left to the caller because the property block is decoded later
     * in this function. */
    {
        byte level = 0;
    #ifdef WOLFMQTT_V5
        level = publish->protocol_level;
    #endif
        if (!MqttPacket_TopicNameValid(publish->topic_name,
                                       publish->topic_name_len, level)) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
    }
    rx_payload += variable_len;

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
        /* [MQTT-2.3.1-1] PUBLISH packets with QoS > 0 must carry a non-zero
         * Packet Identifier. */
        if (publish->packet_id == 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
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
    if (variable_len > remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
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
        if (publish_resp->props != NULL) {
            /* Determine length of properties */
            props_len = MqttEncode_Props((MqttPacketType)type,
                            publish_resp->props, NULL);
            if (props_len >= 0) {
                /* Determine the length of the "property length" */
                int tmp_len = MqttEncode_Vbi(NULL, props_len);
                if (tmp_len < 0) {
                    return tmp_len;
                }
                remain_len += props_len;
                remain_len += tmp_len;
            }
            else
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);
        }
        if (publish_resp->reason_code != MQTT_REASON_SUCCESS ||
            publish_resp->props != NULL) {
            /* Reason Code */
            remain_len++;
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
        if (publish_resp->reason_code != MQTT_REASON_SUCCESS ||
            publish_resp->props != NULL) {
            /* Encode the Reason Code */
            *tx_payload++ = publish_resp->reason_code;
        }
        if (publish_resp->props != NULL) {
            /* Encode the property length */
            int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            tx_payload += tmp_len;

            /* Encode properties */
            tmp_len = MqttEncode_Props((MqttPacketType)type,
                            publish_resp->props, tx_payload);
            if (tmp_len < 0) {
                return tmp_len;
            }
            tx_payload += tmp_len;
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

    /* MQTT 3.1.1 §3.4-3.7: PUBACK/PUBREC/PUBREL/PUBCOMP variable header is
     * exactly the two-byte Packet Identifier and there is no payload —
     * Remaining Length is fixed at 2. v5 §3.4-3.7 relaxes this to allow
     * an optional Reason Code and Properties block, so the longer form is
     * only valid when the caller has identified the connection as v5.
     * (publish_resp == NULL takes the strict path: with no struct to
     * carry reason_code/props, anything beyond the Packet Identifier
     * cannot be consumed and is therefore extra payload.) */
#ifdef WOLFMQTT_V5
    if (publish_resp != NULL &&
        publish_resp->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        if (remain_len < MQTT_DATA_LEN_SIZE) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
    }
    else
#endif
    {
        if (remain_len != MQTT_DATA_LEN_SIZE) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
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
                if (props_tmp < 0)
                    return props_tmp;

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

    /* [MQTT-2.3.1-1] SUBSCRIBE packets require a non-zero packet identifier */
    if (subscribe->packet_id == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
    for (i = 0; i < subscribe->topic_count; i++) {
        topic = &subscribe->topics[i];
        if ((topic != NULL) && (topic->topic_filter != NULL)) {
            /* MQTT UTF-8 strings are limited to 65535 bytes [MQTT-1.5.3] */
            size_t str_len = XSTRLEN(topic->topic_filter);
            if (str_len > (size_t)0xFFFF) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
            }
            remain_len += (int)str_len + MQTT_DATA_LEN_SIZE;
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
            /* Determine the length of the "property length" */
            int tmp_len = MqttEncode_Vbi(NULL, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            remain_len += props_len;
            remain_len += tmp_len;
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
        int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;

        /* Encode properties */
        tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_SUBSCRIBE,
                        subscribe->props, tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;
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

#ifdef WOLFMQTT_BROKER
int MqttDecode_Subscribe(byte *rx_buf, int rx_buf_len, MqttSubscribe *subscribe)
{
    int header_len, remain_len;
    byte *rx_payload;
    byte *rx_end;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0 || subscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_SUBSCRIBE, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    if (rx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    rx_payload = &rx_buf[header_len];
    rx_end = rx_payload + remain_len;

    /* Decode variable header */
    if (subscribe) {
        int tmp;
        tmp = MqttDecode_Num(rx_payload, &subscribe->packet_id,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        /* [MQTT-2.3.1-1] SUBSCRIBE packets must carry a non-zero
         * Packet Identifier. */
        if (subscribe->packet_id == 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
        }
        rx_payload += tmp;

#ifdef WOLFMQTT_V5
        subscribe->props = NULL;
        if (subscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
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
                props_tmp = MqttDecode_Props(MQTT_PACKET_TYPE_SUBSCRIBE,
                        &subscribe->props, rx_payload,
                        (word32)(rx_buf_len - (rx_payload - rx_buf)),
                        props_len);
                if (props_tmp < 0) {
                    return props_tmp;
                }
                rx_payload += props_tmp;
            }
        }
#endif

        subscribe->topic_count = 0;
        if (subscribe->topics == NULL) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }

        while (rx_payload < rx_end) {
            MqttTopic *topic;
            byte options;
            word16 filter_len = 0;
            if (subscribe->topic_count >= MAX_MQTT_TOPICS) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            topic = &subscribe->topics[subscribe->topic_count];
            tmp = MqttDecode_String(rx_payload, &topic->topic_filter,
                    &filter_len, (word32)(rx_end - rx_payload));
            if (tmp < 0) {
                return tmp;
            }
            if (rx_payload + tmp > rx_end) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            /* [MQTT-4.7.3-1] / [MQTT-4.7.1-2] / [MQTT-4.7.1-3] Reject
             * empty filters and malformed wildcard placement. */
            if (!MqttPacket_TopicFilterValid(topic->topic_filter,
                                             filter_len)) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
            }
            rx_payload += tmp;
            if (rx_payload >= rx_end) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            options = *rx_payload++;
            /* MQTT 3.1.1 §3.8.3.1: bits 2-7 of the SUBSCRIBE options byte
             * are reserved and MUST be 0; Requested QoS (bits 0-1) MUST
             * be 0, 1, or 2. v5 §3.8.3.1 redefines bits 2-5 as No Local,
             * Retain As Published, and Retain Handling — bits 6-7 stay
             * reserved, Retain Handling = 3 is also reserved, and QoS = 3
             * remains invalid. The fixed-header [MQTT-3.8.1-1] reserved-
             * flag check has already run by this point; this check covers
             * the per-topic options byte the broker would otherwise be
             * forced to silently normalize. */
        #ifdef WOLFMQTT_V5
            if (subscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                if ((options & 0xC0) != 0 ||
                    (options & 0x03) > MQTT_QOS_2 ||
                    ((options >> 4) & 0x03) == 0x03) {
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
                }
            }
            else
        #endif
            {
                if ((options & 0xFC) != 0 ||
                    (options & 0x03) > MQTT_QOS_2) {
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
                }
            }
            topic->qos = (MqttQoS)(options & 0x03);
            subscribe->topic_count++;
        }

        /* [MQTT-3.8.3-3] The payload of a SUBSCRIBE packet MUST contain at
         * least one Topic Filter / QoS pair. v5 §3.8.3 carries the same
         * minimum-cardinality requirement. */
        if (subscribe->topic_count == 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
    }

    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}
#endif /* WOLFMQTT_BROKER */

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

    /* Validate remain_len (need at least packet_id) */
    if (remain_len < MQTT_DATA_LEN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
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
        {
            int payload_len = remain_len -
                    (int)(rx_payload - &rx_buf[header_len]);
            int buf_remain = rx_buf_len - (int)(rx_payload - rx_buf);
            byte level = 0;
            int i;
            if (payload_len < 0 || buf_remain < 0) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            if (payload_len > buf_remain) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            if (payload_len > MAX_MQTT_TOPICS)
                payload_len = MAX_MQTT_TOPICS;
        #ifdef WOLFMQTT_V5
            level = subscribe_ack->protocol_level;
        #endif
            /* [MQTT-3.9.3-2] Reject reserved SUBACK return codes before
             * the bytes are copied into the caller's struct so a
             * malformed broker response never surfaces to upper-layer
             * subscription handling. Under v5 the property block has
             * already been allocated above; free it before returning so
             * a malformed-broker stream doesn't leak per-SUBACK. */
            for (i = 0; i < payload_len; i++) {
                if (!MqttPacket_SubAckReturnCodeValid(rx_payload[i], level)) {
                #ifdef WOLFMQTT_V5
                    if (subscribe_ack->props != NULL) {
                        (void)MqttProps_Free(subscribe_ack->props);
                        subscribe_ack->props = NULL;
                    }
                #endif
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
                }
            }
            XMEMSET(subscribe_ack->return_codes, 0, MAX_MQTT_TOPICS);
            XMEMCPY(subscribe_ack->return_codes, rx_payload, payload_len);
        }
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

    /* [MQTT-2.3.1-1] UNSUBSCRIBE packets require a non-zero packet identifier */
    if (unsubscribe->packet_id == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
    for (i = 0; i < unsubscribe->topic_count; i++) {
        topic = &unsubscribe->topics[i];
        if ((topic != NULL) && (topic->topic_filter != NULL)) {
            /* MQTT UTF-8 strings are limited to 65535 bytes [MQTT-1.5.3] */
            size_t str_len = XSTRLEN(topic->topic_filter);
            if (str_len > (size_t)0xFFFF) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
            }
            remain_len += (int)str_len + MQTT_DATA_LEN_SIZE;
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
            /* Determine the length of the "property length" */
            int tmp_len = MqttEncode_Vbi(NULL, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            remain_len += props_len;
            remain_len += tmp_len;
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
        int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;

        /* Encode properties */
        tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE,
                        unsubscribe->props, tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;
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

#ifdef WOLFMQTT_BROKER
int MqttDecode_Unsubscribe(byte *rx_buf, int rx_buf_len, MqttUnsubscribe *unsubscribe)
{
    int header_len, remain_len;
    byte *rx_payload;
    byte *rx_end;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0 || unsubscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_UNSUBSCRIBE, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }
    if (rx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    rx_payload = &rx_buf[header_len];
    rx_end = rx_payload + remain_len;

    /* Decode variable header */
    if (unsubscribe) {
        int tmp;
        tmp = MqttDecode_Num(rx_payload, &unsubscribe->packet_id,
                (word32)(rx_buf_len - (rx_payload - rx_buf)));
        if (tmp < 0) {
            return tmp;
        }
        /* [MQTT-2.3.1-1] UNSUBSCRIBE packets must carry a non-zero
         * Packet Identifier. */
        if (unsubscribe->packet_id == 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
        }
        rx_payload += tmp;

#ifdef WOLFMQTT_V5
        unsubscribe->props = NULL;
        if (unsubscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
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
                props_tmp = MqttDecode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE,
                        &unsubscribe->props, rx_payload,
                        (word32)(rx_buf_len - (rx_payload - rx_buf)),
                        props_len);
                if (props_tmp < 0) {
                    return props_tmp;
                }
                rx_payload += props_tmp;
            }
        }
#endif

        unsubscribe->topic_count = 0;
        if (unsubscribe->topics == NULL) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }

        while (rx_payload < rx_end) {
            MqttTopic *topic;
            word16 filter_len = 0;
            if (unsubscribe->topic_count >= MAX_MQTT_TOPICS) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            topic = &unsubscribe->topics[unsubscribe->topic_count];
            tmp = MqttDecode_String(rx_payload, &topic->topic_filter,
                    &filter_len, (word32)(rx_end - rx_payload));
            if (tmp < 0) {
                return tmp;
            }
            if (rx_payload + tmp > rx_end) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
            }
            /* [MQTT-4.7.3-1] / [MQTT-4.7.1-2] / [MQTT-4.7.1-3]: an
             * UNSUBSCRIBE Topic Filter must obey the same syntax rules
             * as a SUBSCRIBE Topic Filter. */
            if (!MqttPacket_TopicFilterValid(topic->topic_filter,
                                             filter_len)) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
            }
            rx_payload += tmp;
            unsubscribe->topic_count++;
        }

        /* [MQTT-3.10.3-2] The Payload of an UNSUBSCRIBE packet MUST
         * contain at least one Topic Filter. v5 §3.10.3 carries the same
         * minimum-cardinality requirement. */
        if (unsubscribe->topic_count == 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
    }

    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}
#endif /* WOLFMQTT_BROKER */

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

    /* Validate remain_len (need at least packet_id) */
    if (remain_len < MQTT_DATA_LEN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
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
                if (props_tmp < 0)
                    return props_tmp;

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

#ifdef WOLFMQTT_BROKER
int MqttEncode_UnsubscribeAck(byte *tx_buf, int tx_buf_len, MqttUnsubscribeAck *unsubscribe_ack)
{
    int header_len, remain_len;
    byte *tx_payload;
#ifdef WOLFMQTT_V5
    int props_len = 0;
    int reason_code_count = 0;
#endif

    /* Validate required arguments */
    if (tx_buf == NULL || unsubscribe_ack == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Determine packet length */
    remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
#ifdef WOLFMQTT_V5
    if (unsubscribe_ack->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Determine length of properties */
        props_len = MqttEncode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK,
                        unsubscribe_ack->props, NULL);
        if (props_len >= 0) {
            /* Determine the length of the "property length" */
            int tmp_len = MqttEncode_Vbi(NULL, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            remain_len += props_len;
            remain_len += tmp_len;
        }
        else
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PROPERTY);

        if (unsubscribe_ack->reason_codes != NULL &&
            unsubscribe_ack->reason_code_count > 0) {
            reason_code_count = unsubscribe_ack->reason_code_count;
            remain_len += reason_code_count;
        }
    }
#endif

    /* Encode fixed header */
    header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
        MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK, 0, 0, 0);
    if (header_len < 0) {
        return header_len;
    }
    /* Check for buffer room */
    if (tx_buf_len < header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    tx_payload = &tx_buf[header_len];

    /* Encode variable header */
    tx_payload += MqttEncode_Num(&tx_buf[header_len], unsubscribe_ack->packet_id);

#ifdef WOLFMQTT_V5
    if (unsubscribe_ack->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        /* Encode the property length */
        int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;

        /* Encode properties */
        tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK,
                        unsubscribe_ack->props, tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;

        /* Encode reason codes (one per topic) */
        if (reason_code_count > 0) {
            int i;
            for (i = 0; i < reason_code_count; i++) {
                *tx_payload++ = unsubscribe_ack->reason_codes[i];
            }
        }
    }
#endif

    (void)tx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}
#endif /* WOLFMQTT_BROKER */

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

    /* MQTT 3.1.1 §3.13 / v5 §3.13: PINGRESP has no variable header and no
     * payload, so Remaining Length MUST be 0. */
    if (remain_len != 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
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
                /* Determine the length of the "property length" */
                int tmp_len = MqttEncode_Vbi(NULL, props_len);
                if (tmp_len < 0) {
                    return tmp_len;
                }
                remain_len += props_len;
                remain_len += tmp_len;
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
            int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
            if (tmp_len < 0) {
                return tmp_len;
            }
            tx_payload += tmp_len;

            /* Encode properties */
            tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_DISCONNECT,
                            disconnect->props, tx_payload);
            if (tmp_len < 0) {
                return tmp_len;
            }
            tx_payload += tmp_len;
        }
        (void)tx_payload;
    }
#else
    (void)disconnect;
#endif

    /* Return total length of packet */
    return header_len + remain_len;
}

#if defined(WOLFMQTT_BROKER) && !defined(WOLFMQTT_V5)
int MqttDecode_Disconnect(byte *rx_buf, int rx_buf_len, MqttDisconnect* disc)
{
    int header_len, remain_len;

    /* Validate required arguments */
    if (rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode fixed header */
    header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
        MQTT_PACKET_TYPE_DISCONNECT, NULL, NULL, NULL);
    if (header_len < 0) {
        return header_len;
    }

    /* MQTT 3.1.1 §3.14: DISCONNECT has no variable header and no payload,
     * so Remaining Length MUST be 0. The WOLFMQTT_V5 decoder below
     * legitimately accepts remain_len > 0 for the Reason Code and
     * Properties. */
    if (remain_len != 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }

    if (disc) {
        /* nothing to decode for v3.1.1 */
    }

    /* Return total length of packet */
    return header_len + remain_len;
}
#endif /* WOLFMQTT_BROKER && !WOLFMQTT_V5 */


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
        /* Determine the length of the "property length" */
        int tmp_len = MqttEncode_Vbi(NULL, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        remain_len += props_len;
        remain_len += tmp_len;
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
        int tmp_len = MqttEncode_Vbi(tx_payload, props_len);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;

        /* Encode properties */
        tmp_len = MqttEncode_Props(MQTT_PACKET_TYPE_AUTH, auth->props,
                        tx_payload);
        if (tmp_len < 0) {
            return tmp_len;
        }
        tx_payload += tmp_len;
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

    auth->props = NULL;
    if (remain_len > 0) {
        /* Decode variable header */
        auth->reason_code = *rx_payload++;
        if ((auth->reason_code == MQTT_REASON_SUCCESS) ||
            (auth->reason_code == MQTT_REASON_CONT_AUTH) ||
            (auth->reason_code == MQTT_REASON_REAUTH))
        {
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
                    /* The Reason Code and Property Length can be omitted if
                       the Reason Code is 0x00 (Success) and there are no
                       Properties. In this case the AUTH has a Remaining
                       Length of 0. */
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
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
            }
        }
        else {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
    }
    else {
        /* Per MQTT 5.0 section 3.15.2: Remaining Length of 0 implies
           Reason Code of 0x00 (Success) with no Properties */
        auth->reason_code = MQTT_REASON_SUCCESS;
    }

    (void)rx_payload;

    /* Return total length of packet */
    return header_len + remain_len;
}

/* Must be called once from a single thread before any concurrent access
 * to MQTTv5 property functions. Not thread-safe if called concurrently. */
int MqttProps_Init(void)
{
    int ret = MQTT_CODE_SUCCESS;
#if !defined(WOLFMQTT_DYN_PROP) && defined(WOLFMQTT_MULTITHREAD)
    if (clientPropStack_lockInit == 0) {
        ret = wm_SemInit(&clientPropStack_lock);
    }
    clientPropStack_lockInit++;
#endif
    return  ret;
}

/* Must be called once from a single thread after all concurrent access
 * to MQTTv5 property functions has ceased. Not thread-safe if called
 * concurrently. */
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
