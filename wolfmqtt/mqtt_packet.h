/* mqtt_packet.h
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

/* Implementation by: David Garske
 * Based on specification for MQTT v3.1.1 and v5.0
 * See http://mqtt.org/documentation for additional MQTT documentation.
 */

#ifndef WOLFMQTT_PACKET_H
#define WOLFMQTT_PACKET_H

#ifdef __cplusplus
    extern "C" {
#endif

#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_socket.h"


/* Size of a data length elements in protocol */
#define MQTT_DATA_LEN_SIZE   2
#define MQTT_DATA_INT_SIZE   4

#ifndef MAX_PACKET_ID
#define MAX_PACKET_ID        ((1 << 16) - 1)
#endif

/* maximum list of topics to subscribe at once */
#ifndef MAX_MQTT_TOPICS
#define MAX_MQTT_TOPICS      12
#endif

/* WOLFMQTT_NO_UTF8_VALIDATION
 *   Define to disable RFC 3629 UTF-8 well-formedness validation in
 *   MqttDecode_String. Spec requirement [MQTT-1.5.3-1] (v3.1.1 1.5.3 /
 *   v5 1.5.4) makes ill-formed UTF-8 a "MUST close the network
 *   connection" condition; disabling the check trades that compliance
 *   for ~300 bytes of .text on x86-64 (~200 bytes on ARM Thumb-2) and
 *   should only be considered for severely flash-constrained targets
 *   where the peer is known-trusted. The independent embedded-NUL
 *   check ([MQTT-1.5.3-2]) remains active either way because it also
 *   guards downstream C-string handling. */

#ifdef WOLFMQTT_V5

#define MQTT_PACKET_SZ_MAX  0xA0000005

/* DATA TYPES */
typedef enum MqttDataType {
    MQTT_DATA_TYPE_NONE = 0,
    MQTT_DATA_TYPE_BYTE,
    MQTT_DATA_TYPE_SHORT,
    MQTT_DATA_TYPE_INT,
    MQTT_DATA_TYPE_STRING,
    MQTT_DATA_TYPE_VAR_INT,
    MQTT_DATA_TYPE_BINARY,
    MQTT_DATA_TYPE_STRING_PAIR
} MqttDataType;

/* PROPERTIES */
typedef enum MqttPropertyType {
    MQTT_PROP_NONE = 0,
    MQTT_PROP_PAYLOAD_FORMAT_IND = 1,
    MQTT_PROP_MSG_EXPIRY_INTERVAL = 2,
    MQTT_PROP_CONTENT_TYPE = 3,
    MQTT_PROP_RESP_TOPIC = 8,
    MQTT_PROP_CORRELATION_DATA = 9,
    MQTT_PROP_SUBSCRIPTION_ID = 11,
    MQTT_PROP_SESSION_EXPIRY_INTERVAL = 17,
    MQTT_PROP_ASSIGNED_CLIENT_ID = 18,
    MQTT_PROP_SERVER_KEEP_ALIVE = 19,
    MQTT_PROP_AUTH_METHOD = 21,
    MQTT_PROP_AUTH_DATA = 22,
    MQTT_PROP_REQ_PROB_INFO = 23,
    MQTT_PROP_WILL_DELAY_INTERVAL = 24,
    MQTT_PROP_REQ_RESP_INFO = 25,
    MQTT_PROP_RESP_INFO = 26,
    MQTT_PROP_SERVER_REF = 28,
    MQTT_PROP_REASON_STR = 31,
    MQTT_PROP_RECEIVE_MAX = 33,
    MQTT_PROP_TOPIC_ALIAS_MAX = 34,
    MQTT_PROP_TOPIC_ALIAS = 35,
    MQTT_PROP_MAX_QOS = 36,
    MQTT_PROP_RETAIN_AVAIL = 37,
    MQTT_PROP_USER_PROP = 38,
    MQTT_PROP_MAX_PACKET_SZ = 39,
    MQTT_PROP_WILDCARD_SUB_AVAIL = 40,
    MQTT_PROP_SUBSCRIPTION_ID_AVAIL = 41,
    MQTT_PROP_SHARED_SUBSCRIPTION_AVAIL = 42,
    MQTT_PROP_TYPE_MAX = 0xFF
} MqttPropertyType;

/* backwards compatibility for anyone using the typo name */
#define MQTT_PROP_PLAYLOAD_FORMAT_IND MQTT_PROP_PAYLOAD_FORMAT_IND

struct _MqttProp_Str {
    word16  len;
    char    *str;
};

struct _MqttProp_Bin {
    word16  len;
    byte    *data;
};

/* Property list */
typedef struct _MqttProp {
    struct  _MqttProp* next;
    MqttPropertyType type;
    byte    data_byte;
    word16  data_short;
    word32  data_int;
    struct _MqttProp_Str data_str;
    struct _MqttProp_Bin data_bin;
    struct _MqttProp_Str data_str2;
} MqttProp;

/* REASON CODES */
enum MqttReasonCodes {
    MQTT_REASON_SUCCESS = 0x00,
    MQTT_REASON_NORMAL_DISCONNECTION = 0x00,
    MQTT_REASON_GRANTED_QOS_0 = 0x00,
    MQTT_REASON_GRANTED_QOS_1 = 0x01,
    MQTT_REASON_GRANTED_QOS_2 = 0x02,
    MQTT_REASON_DISCONNECT_W_WILL_MSG = 0x04,
    MQTT_REASON_NO_MATCH_SUB = 0x10,
    MQTT_REASON_NO_SUB_EXIST = 0x11,
    MQTT_REASON_CONT_AUTH = 0x18,
    MQTT_REASON_REAUTH = 0x19,

    /* begin error codes */
    MQTT_REASON_UNSPECIFIED_ERR = 0x80,
    MQTT_REASON_MALFORMED_PACKET = 0x81,
    MQTT_REASON_PROTOCOL_ERR = 0x82,
    MQTT_REASON_IMPL_SPECIFIC_ERR = 0x83,
    MQTT_REASON_UNSUP_PROTO_VER = 0x84,
    MQTT_REASON_CLIENT_ID_NOT_VALID = 0x85,
    MQTT_REASON_BAD_USER_OR_PASS = 0x86,
    MQTT_REASON_NOT_AUTHORIZED = 0x87,
    MQTT_REASON_SERVER_UNAVAILABLE = 0x88,
    MQTT_REASON_SERVER_BUSY = 0x89,
    MQTT_REASON_BANNED = 0x8A,
    MQTT_REASON_SERVER_SHUTTING_DOWN = 0x8B,
    MQTT_REASON_BAD_AUTH_METHOD = 0x8C,
    MQTT_REASON_KEEP_ALIVE_TIMEOUT = 0x8D,
    MQTT_REASON_SESSION_TAKEN_OVER = 0x8E,
    MQTT_REASON_TOPIC_FILTER_INVALID = 0x8F,
    MQTT_REASON_TOPIC_NAME_INVALID = 0x90,
    MQTT_REASON_PACKET_ID_IN_USE = 0x91,
    MQTT_REASON_PACKET_ID_NOT_FOUND = 0x92,
    MQTT_REASON_RX_MAX_EXCEEDED = 0x93,
    MQTT_REASON_TOPIC_ALIAS_INVALID = 0x94,
    MQTT_REASON_PACKET_TOO_LARGE = 0x95,
    MQTT_REASON_MSG_RATE_TOO_HIGH = 0x96,
    MQTT_REASON_QUOTA_EXCEEDED = 0x97,
    MQTT_REASON_ADMIN_ACTION = 0x98,
    MQTT_REASON_PAYLOAD_FORMAT_INVALID = 0x99,
    MQTT_REASON_RETAIN_NOT_SUPPORTED = 0x9A,
    MQTT_REASON_QOS_NOT_SUPPORTED = 0x9B,
    MQTT_REASON_USE_ANOTHER_SERVER = 0x9C,
    MQTT_REASON_SERVER_MOVED = 0x9D,
    MQTT_REASON_SS_NOT_SUPPORTED = 0x9E,
    MQTT_REASON_CON_RATE_EXCEED = 0x9F,
    MQTT_REASON_MAX_CON_TIME = 0xA0,
    MQTT_REASON_SUB_ID_NOT_SUP = 0xA1,
    MQTT_REASON_WILDCARD_SUB_NOT_SUP = 0xA2
};
#endif /* WOLFMQTT_V5 */



/* QoS */
typedef enum _MqttQoS {
    MQTT_QOS_0 = 0, /* At most once delivery */
    MQTT_QOS_1 = 1, /* At least once delivery */
    MQTT_QOS_2 = 2, /* Exactly once delivery */
    MQTT_QOS_3 = 3  /* MQTT - Reserved - must not be used
                       MQTT-SN - QoS -1 allows publish without connection */
} MqttQoS;

/* Maximum QoS supported by this build. Legal values: 0, 1, 2. Default 2.
 * Define in user_settings.h to compile a QoS-capped client/broker. Wired
 * into broker CONNACK Maximum QoS property emission today; broader code
 * gating lives on the mqtt_qos_max branch. */
#ifndef WOLFMQTT_MAX_QOS
    #define WOLFMQTT_MAX_QOS 2
#endif
#if (WOLFMQTT_MAX_QOS < 0) || (WOLFMQTT_MAX_QOS > 2)
    #error "WOLFMQTT_MAX_QOS must be 0, 1, or 2"
#endif


#ifdef WOLFMQTT_V5
/* MQTT v5 SUBSCRIBE options byte (section 3.8.3.1), stored in
 * MqttTopic.sub_options in their on-the-wire bit positions. QoS (bits 0-1)
 * is carried separately in MqttTopic.qos; bits 6-7 are reserved (MUST be 0).
 * The encoder trusts the caller and emits sub_options verbatim (masked to
 * bits 2-5), so supply only spec-valid combinations - in particular Retain
 * Handling must be 0-2 (the value 3 is reserved and a broker will reject it). */
#define MQTT_SUBSCRIBE_NO_LOCAL             0x04 /* bit 2 */
#define MQTT_SUBSCRIBE_RETAIN_AS_PUBLISHED  0x08 /* bit 3 */
#define MQTT_SUBSCRIBE_RETAIN_HANDLING_0    0x00 /* bits 4-5: send at subscribe */
#define MQTT_SUBSCRIBE_RETAIN_HANDLING_1    0x10 /* send at subscribe if new */
#define MQTT_SUBSCRIBE_RETAIN_HANDLING_2    0x20 /* do not send at subscribe */
#define MQTT_SUBSCRIBE_OPTIONS_MASK         0x3C /* bits 2-5 */
#endif

/* Topic */
typedef struct _MqttTopic {
    const char* topic_filter;

    /* These are only on subscribe */
    MqttQoS     qos; /* Bits 0-1 = MqttQoS */
    byte        return_code; /* MqttSubscribeAckReturnCodes */
#ifdef WOLFMQTT_V5
    word16      alias;
    byte        sub_options; /* v5 SUBSCRIBE options bits 2-5 (No Local,
                              * Retain As Published, Retain Handling); see
                              * MQTT_SUBSCRIBE_*. Zero-initialize MqttTopic so
                              * unset options default to 0 - the v5 encoder now
                              * reads this field. */
#endif
} MqttTopic;

/* Topic naming */
/* Be specific, use readable characters only.
 * Use forward slashes to denote levels.
 * Do not start name with forward slash (/) or $ (reserved for broker)
 * Example: "main/sub/detail/unique" */

/* The forward slash is used to define levels of topic matching */
#define TOPIC_LEVEL_SEPERATOR   '/'

/* These are available for Topic Filters on Subscribe only */
/* The plus is used to match on a single level */
/* Example: "user/home/+/light" */
#define TOPIC_LEVEL_SINGLE      '+'

/* The hash is used to match on a multiple levels */
/* Example: "user/home/#" */
#define TOPIC_LEVEL_MULTI       '#'


/* PACKET HEADER */
/* Packet types: Located in first byte of packet in bits 4-7 */
#define MQTT_PACKET_TYPE_GET(x)  (((x) >> 4) & 0xF)
#define MQTT_PACKET_TYPE_SET(x)  (((x) & 0xF) << 4)
typedef enum _MqttPacketType {
    MQTT_PACKET_TYPE_RESERVED = 0,
    MQTT_PACKET_TYPE_CONNECT = 1,
    MQTT_PACKET_TYPE_CONNECT_ACK = 2,       /* Acknowledgment */
    MQTT_PACKET_TYPE_PUBLISH = 3,
    MQTT_PACKET_TYPE_PUBLISH_ACK = 4,       /* Acknowledgment */
    MQTT_PACKET_TYPE_PUBLISH_REC = 5,       /* Received */
    MQTT_PACKET_TYPE_PUBLISH_REL= 6,        /* Release */
    MQTT_PACKET_TYPE_PUBLISH_COMP = 7,      /* Complete */
    MQTT_PACKET_TYPE_SUBSCRIBE = 8,
    MQTT_PACKET_TYPE_SUBSCRIBE_ACK = 9,     /* Acknowledgment */
    MQTT_PACKET_TYPE_UNSUBSCRIBE = 10,
    MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK = 11,  /* Acknowledgment */
    MQTT_PACKET_TYPE_PING_REQ = 12,         /* Request */
    MQTT_PACKET_TYPE_PING_RESP = 13,        /* Response */
    MQTT_PACKET_TYPE_DISCONNECT = 14,
    MQTT_PACKET_TYPE_AUTH = 15,             /* Authentication (MQTT 5) */
    MQTT_PACKET_TYPE_ANY = 16
} MqttPacketType;

/* Packet flag bit-mask: Located in first byte of packet in bits 0-3 */
#define MQTT_PACKET_FLAGS_GET(x) ((x) & 0xF)
#define MQTT_PACKET_FLAGS_SET(x) (x)
#define MQTT_PACKET_FLAGS_GET_QOS(type_flags)   \
    ((MQTT_PACKET_FLAGS_GET((type_flags)) & \
        MQTT_PACKET_FLAG_QOS_MASK) >> MQTT_PACKET_FLAG_QOS_SHIFT)
#define MQTT_PACKET_FLAGS_SET_QOS(qos)   \
    (MQTT_PACKET_FLAGS_SET(((qos) << MQTT_PACKET_FLAG_QOS_SHIFT) & \
        MQTT_PACKET_FLAG_QOS_MASK))
enum MqttPacketFlags {
    MQTT_PACKET_FLAG_RETAIN = 0x1,
    MQTT_PACKET_FLAG_QOS_SHIFT = 0x1,
    MQTT_PACKET_FLAG_QOS_MASK = 0x6,
    MQTT_PACKET_FLAG_DUPLICATE = 0x8
};

/* Packet Header: Size is variable 2 - 5 bytes */
#define MQTT_PACKET_MAX_LEN_BYTES   4
#define MQTT_PACKET_LEN_ENCODE_MASK 0x80UL
/* [MQTT-2.2.3] Maximum value encodable by the Variable Byte Integer scheme */
#define MQTT_PACKET_MAX_REMAIN_LEN  0x0FFFFFFFUL /* 268,435,455 */
typedef struct _MqttPacket {
    /* Type = bits 4-7, Flags = 0-3 are flags */
    byte        type_flags; /* MqttPacketType and MqttPacketFlags */

    /* Remaining Length: variable 1-4 bytes, encoded using scheme
       where bit 7 = continuation bit */
    byte        len[MQTT_PACKET_MAX_LEN_BYTES];

    /* Then packet_id if type is PUBLISH through UNSUBSCRIBE_ACK */
    /* Packet Id: Included for types PUBLISH_ACK through UNSUBSCRIBE_ACK */
    /* Note: Also included in PUBLISH after topic field (see MqttPublish) */
    /* Must be non-zero value */
} WOLFMQTT_PACK MqttPacket;
#define MQTT_PACKET_HEADER_MIN_SIZE        (2)


/* Generic Message */
typedef enum _MqttMsgState {
    MQTT_MSG_BEGIN = 0, /* must be zero, so memset will setup state */
    MQTT_MSG_WAIT,
    MQTT_MSG_AUTH,
    MQTT_MSG_HEADER,
    MQTT_MSG_PAYLOAD,
    MQTT_MSG_PAYLOAD2,
    MQTT_MSG_ACK
} MqttMsgState;

/* Generic message status tracking */
typedef struct _MqttMsgStat {
    MqttMsgState read;
    MqttMsgState write;
    MqttMsgState ack;

    byte isReadActive:1;
    byte isWriteActive:1;
} MqttMsgStat;

#ifdef WOLFMQTT_MULTITHREAD
/* Pending Response Structure */
typedef struct _MqttPendResp {
    word16          packet_id;
    MqttPacketType  packet_type;
    int             packet_ret;
    void*           packet_obj;

    /* bits */
    word16          packetDone:1;       /* task completed it */
    word16          packetProcessing:1; /* task processing it */

    /* double linked list */
    struct _MqttPendResp* next;
    struct _MqttPendResp* prev;
} MqttPendResp;
#endif /* WOLFMQTT_MULTITHREAD */


/* CONNECT PACKET */
/* Connect flag bit-mask: Located in byte 8 of the MqttConnect packet */
#define MQTT_CONNECT_FLAG_GET_QOS(flags) \
    (((flags) & MQTT_CONNECT_FLAG_WILL_QOS_MASK) >> \
        MQTT_CONNECT_FLAG_WILL_QOS_SHIFT)
#define MQTT_CONNECT_FLAG_SET_QOS(qos) \
    (((qos) << MQTT_CONNECT_FLAG_WILL_QOS_SHIFT) & \
        MQTT_CONNECT_FLAG_WILL_QOS_MASK)
enum MqttConnectFlags {
    MQTT_CONNECT_FLAG_RESERVED = 0x01,
    MQTT_CONNECT_FLAG_CLEAN_SESSION = 0x02, /* Old v3.1.1 name */
    MQTT_CONNECT_FLAG_CLEAN_START   = 0x02,
    MQTT_CONNECT_FLAG_WILL_FLAG = 0x04,
    MQTT_CONNECT_FLAG_WILL_QOS_SHIFT = 3,
    MQTT_CONNECT_FLAG_WILL_QOS_MASK = 0x18,
    MQTT_CONNECT_FLAG_WILL_RETAIN = 0x20,
    MQTT_CONNECT_FLAG_PASSWORD = 0x40,
    MQTT_CONNECT_FLAG_USERNAME = 0x80
};

/* Connect Protocol */
/* Constant values for the protocol name and level */
#define MQTT_CONNECT_PROTOCOL_NAME_LEN  4
#define MQTT_CONNECT_PROTOCOL_NAME      "MQTT"
#define MQTT_CONNECT_PROTOCOL_LEVEL_4   4 /* v3.1.1 */
#define MQTT_CONNECT_PROTOCOL_LEVEL_5   5 /* v5.0 */
#ifdef WOLFMQTT_V5
#define MQTT_CONNECT_PROTOCOL_LEVEL     MQTT_CONNECT_PROTOCOL_LEVEL_5
#else
#define MQTT_CONNECT_PROTOCOL_LEVEL     MQTT_CONNECT_PROTOCOL_LEVEL_4
#endif
/* Initializer */
#define MQTT_CONNECT_INIT               \
    {{0, MQTT_CONNECT_PROTOCOL_NAME_LEN}, {'M', 'Q', 'T', 'T'}, \
        MQTT_CONNECT_PROTOCOL_LEVEL, 0, 0}

/* Connect packet structure */
typedef struct _MqttConnectPacket {
    byte        protocol_len[MQTT_DATA_LEN_SIZE];
    char        protocol_name[MQTT_CONNECT_PROTOCOL_NAME_LEN];
    byte        protocol_level;
    byte        flags;           /* MqttConnectFlags */
    word16      keep_alive;      /* Seconds */
} WOLFMQTT_PACK MqttConnectPacket;


/* CONNECT ACKNOWLEDGE */
/* Connect Ack flags */
enum MqttConnectAckFlags {
    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT = 0x01
};

/* Connect Ack return codes */
enum MqttConnectAckReturnCodes {
    /* Connection accepted */
    MQTT_CONNECT_ACK_CODE_ACCEPTED = 0,

    /* The Server does not support the level of the MQTT protocol requested
       by the Client */
    MQTT_CONNECT_ACK_CODE_REFUSED_PROTO = 1,

    /* The Client identifier is correct UTF-8 but not allowed by the Server */
    MQTT_CONNECT_ACK_CODE_REFUSED_ID = 2,

    /* The Network Connection has been made but the MQTT service is
       unavailable */
    MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL = 3,

    /* The data in the user name or password is malformed */
    MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD = 4,

    /* The Client is not authorized to connect */
    MQTT_CONNECT_ACK_CODE_REFUSED_NOT_AUTH = 5
};

/* Connect Ack packet structure */
typedef struct _MqttConnectAck {
    MqttMsgStat stat; /* must be first member at top */

    byte       flags;       /* MqttConnectAckFlags */
    byte       return_code; /* MqttConnectAckCodes */

#ifdef WOLFMQTT_V5
    MqttProp* props;
    byte protocol_level;
#endif
} MqttConnectAck;
/* Connect Ack has no payload */

/* CONNECT */
/* Connect structure */
struct _MqttMessage;
typedef struct _MqttConnect {
    /* stat and pendResp must be first members at top */
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    word16      keep_alive_sec;
    byte        clean_session;
    const char *client_id;

    /* Protocol version: 4=v3.1.1 (default), 5=v5.0 */
    byte protocol_level;

    /* Optional Last will and testament */
    byte                 enable_lwt;
    struct _MqttMessage *lwt_msg;

    /* Optional login */
    const char *username;
    const char *password;

    /* Ack data */
    MqttConnectAck ack;

#ifdef WOLFMQTT_V5
    MqttProp* props;
#endif
} MqttConnect;


/* PUBLISH RESPONSE */
/* This is the response struct for PUBLISH_ACK, PUBLISH_REC and PUBLISH_COMP */
/* If QoS = 0: No response */
/* If QoS = 1: Expect response packet with type =
    MQTT_PACKET_TYPE_PUBLISH_ACK */
/* If QoS = 2: Expect response packet with type =
    MQTT_PACKET_TYPE_PUBLISH_REC */
/* Packet Id required if QoS is 1 or 2 */
/* If Qos = 2: Send MQTT_PACKET_TYPE_PUBLISH_REL with PacketId to complete
    QoS2 protocol exchange */
/* Expect response packet with type = MQTT_PACKET_TYPE_PUBLISH_COMP */
typedef struct _MqttPublishResp {
    /* stat and pendResp must be first members at top */
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif
    word16      packet_id;
    byte        packet_type; /* type to send */

#ifdef WOLFMQTT_V5
    byte reason_code;
    MqttProp* props;
    byte protocol_level;
#endif
} MqttPublishResp;

/* PUBLISH */
/* PacketId sent only if QoS > 0 */
typedef struct _MqttMessage {
    /* stat and pendResp must be first members at top */
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif
    word16      packet_id;
    byte        type;
    MqttQoS     qos;
    byte        retain;
    byte        duplicate;
#ifdef WOLFMQTT_SN
    byte        topic_type;
    byte        return_code;
#endif

    const char *topic_name;   /* Pointer is valid only when
                                 msg_new set in callback */
    word16      topic_name_len;
    word32      total_len;    /* Payload total length */
    byte       *buffer;       /* Payload buffer */
    word32      buffer_len;   /* Payload buffer length */
    word32      buffer_pos;   /* Payload buffer position */

    /* Used internally for TX/RX buffers */
    byte        buffer_new;   /* flag to indicate new message */
    word32      intBuf_len;   /* Buffer length */
    word32      intBuf_pos;   /* Buffer position */

    void*       ctx;          /* user supplied context for publish callbacks */

    MqttPublishResp resp;

#ifdef WOLFMQTT_V5
    MqttProp* props;
    byte protocol_level;
#endif
} MqttMessage;
typedef MqttMessage MqttPublish; /* Publish is message */


/* SUBSCRIBE ACK */
/* Packet Id followed by list of return codes corresponding to subscription
    topic list sent. */
enum MqttSubscribeAckReturnCodes {
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0 = 0,
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS1 = 1,
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS2 = 2,
    MQTT_SUBSCRIBE_ACK_CODE_FAILURE = 0x80
};
typedef struct _MqttSubscribeAck {
    MqttMsgStat stat; /* must be first member at top */

    word16      packet_id;
    byte        return_codes[MAX_MQTT_TOPICS];
    word16      return_code_count; /* number of return codes the broker sent */
#ifdef WOLFMQTT_V5
    MqttProp* props;
    byte protocol_level;
#endif
} MqttSubscribeAck;

/* SUBSCRIBE */
/* Packet Id followed by contiguous list of topics w/Qos to subscribe to. */
typedef struct _MqttSubscribe {
    /* stat and pendResp must be first members at top */
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    word16      packet_id;
    int         topic_count;
    MqttTopic  *topics;

    MqttSubscribeAck ack;

#ifdef WOLFMQTT_V5
    MqttProp* props;
    byte protocol_level;
#endif
} MqttSubscribe;


/* UNSUBSCRIBE RESPONSE ACK */
/* No response payload (besides packet Id) */
typedef struct _MqttUnsubscribeAck {
    MqttMsgStat stat; /* must be first member at top */

    word16      packet_id;
#ifdef WOLFMQTT_V5
    MqttProp* props;
    byte*     reason_codes;
    word16    reason_code_count;
    byte protocol_level;
#endif
} MqttUnsubscribeAck;

/* UNSUBSCRIBE */
/* Packet Id followed by contiguous list of topics to unsubscribe from. */
typedef struct _MqttUnsubscribe {
    /* stat and pendResp must be first members at top */
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    word16      packet_id;
    int         topic_count;
    MqttTopic  *topics;

    MqttUnsubscribeAck ack;

#ifdef WOLFMQTT_V5
    MqttProp* props;
    byte protocol_level;
#endif
} MqttUnsubscribe;


/* PING / PING RESPONSE */
/* Fixed header "MqttPacket" only. No variable header or payload */
typedef struct _MqttPing {
    /* stat and pendResp must be first members at top */
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif
} MqttPing;


/* DISCONNECT */
typedef struct _MqttDisconnect {
    MqttMsgStat stat; /* must be first member at top */

#ifdef WOLFMQTT_V5
    byte reason_code;
    MqttProp* props;
    byte protocol_level;
#endif
} MqttDisconnect;


#ifdef WOLFMQTT_V5
/* AUTH */
typedef struct _MqttAuth {
    /* stat and pendResp must be first members at top */
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    byte        reason_code;
    MqttProp*   props;
} MqttAuth;
#endif

/* Generic MQTT struct for packet types */
typedef union _MqttObject {
    MqttMsgStat        stat; /* all objects types have this at top of struct */
    MqttConnect        connect;
    MqttConnectAck     connect_ack;
    MqttPublish        publish;
    MqttPublishResp    publish_resp;
    MqttSubscribe      subscribe;
    MqttSubscribeAck   subscribe_ack;
    MqttUnsubscribe    unsubscribe;
    MqttUnsubscribeAck unsubscribe_ack;
    MqttPing           ping;
    MqttDisconnect     disconnect;
#ifdef WOLFMQTT_V5
    MqttAuth           auth;
#endif
} MqttObject;



/* MQTT PACKET APPLICATION INTERFACE */
struct _MqttClient;
/* Packet Read/Write */
WOLFMQTT_API int MqttPacket_Write(struct _MqttClient *client, byte* tx_buf,
    int tx_buf_len);
WOLFMQTT_API int MqttPacket_Read(struct _MqttClient *client, byte* rx_buf,
    int rx_buf_len, int timeout_ms);

/* [MQTT-2.2.2-2] Validate the fixed-header reserved-flag bits for the given
 * first packet byte (type+flags). Returns 1 if the flags are valid for the
 * packet type, 0 if malformed. PUBLISH (type 3) carries DUP/QoS/RETAIN; QoS
 * value 3 ([MQTT-3.3.1-4]) and DUP=1 with QoS=0 ([MQTT-3.3.1-2]) are
 * rejected. The receiver MUST close the network connection on a malformed
 * packet. */
WOLFMQTT_API int MqttPacket_FixedHeaderFlagsValid(byte type_flags);

/*! \brief      [MQTT-4.7.1-2] / [MQTT-4.7.1-3] / [MQTT-4.7.3-1] Validate
 *              an MQTT Topic Filter. Rejects empty filters, '#' that is
 *              not solo or a final character after '/', and '+' that
 *              does not occupy an entire topic level. The filter need
 *              not be NUL-terminated.
 *  \param      filter      Pointer to the topic filter bytes.
 *  \param      len         Length of the filter in bytes.
 *  \return     1 if the filter is well-formed, 0 if it is malformed.
 */
WOLFMQTT_API int MqttPacket_TopicFilterValid(const char* filter, word16 len);

/*! \brief      Return non-zero if the Topic Filter contains a wildcard
 *              ('#' or '+'). Use only on a filter that has already
 *              passed MqttPacket_TopicFilterValid - wildcard placement
 *              is not re-validated here.
 *  \param      filter      Pointer to the topic filter bytes.
 *  \param      len         Length of the filter in bytes.
 *  \return     1 if a wildcard byte is present, 0 otherwise.
 */
WOLFMQTT_API int MqttPacket_TopicFilterIsWildcard(const char* filter,
    word16 len);

/*! \brief      [MQTT-4.7.3-1] / [MQTT-3.3.2-2] Validate a PUBLISH Topic
 *              Name. Always rejects topics containing the wildcard
 *              characters '#' or '+'. Empty Topic Names are rejected
 *              under v3.1.1 (protocol_level < 5) per [MQTT-4.7.3-1] but
 *              allowed under v5 (section 3.3.2.3.4) because v5 permits a
 *              zero-length Topic Name when paired with a Topic Alias
 *              property; the caller is responsible for the alias-empty
 *              pairing check. NULL topic_name is rejected regardless of
 *              len or protocol_level - callers representing the v5
 *              Topic Alias placeholder must pass an empty string ("")
 *              with len==0, not NULL, so the contract matches
 *              MqttEncode_Publish (which treats NULL as BAD_ARG).
 *  \param      topic_name      Pointer to the topic name bytes (must be
 *                              non-NULL; "" is permitted for v5 alias).
 *  \param      len             Length of the topic name in bytes.
 *  \param      protocol_level  MQTT protocol level (4 = v3.1.1, 5 = v5).
 *  \return     1 if well-formed, 0 if malformed (including NULL input).
 */
WOLFMQTT_API int MqttPacket_TopicNameValid(const char* topic_name,
    word16 len, byte protocol_level);

/*! \brief [MQTT-3.9.3-2] Validate a SUBACK return code / Reason Code.
 *  \param code            The byte to validate.
 *  \param protocol_level  MQTT protocol level (4 = v3.1.1, 5 = v5). v3.1.1
 *                         restricts SUBACK to {0x00, 0x01, 0x02, 0x80};
 *                         v5 broadens the set with additional Reason
 *                         Codes (e.g., 0x83, 0x87, 0x8F, 0x91, 0x97,
 *                         0x9E, 0xA1, 0xA2).
 *  \return     1 if the code is allowed, 0 if reserved.
 */
WOLFMQTT_API int MqttPacket_SubAckReturnCodeValid(byte code,
    byte protocol_level);

/* Packet Element Encoders/Decoders */
WOLFMQTT_API int MqttDecode_Num(byte* buf, word16 *len, word32 buf_len);
WOLFMQTT_API int MqttEncode_Num(byte *buf, word16 len);

WOLFMQTT_LOCAL int MqttDecode_Int(byte* buf, word32* len, word32 buf_len);
WOLFMQTT_LOCAL int MqttEncode_Int(byte* buf, word32 len);

WOLFMQTT_LOCAL int MqttDecode_String(byte *buf, const char **pstr,
    word16 *pstr_len, word32 buf_len);
WOLFMQTT_LOCAL int MqttEncode_String(byte *buf, const char *str);

WOLFMQTT_LOCAL int MqttEncode_Data(byte *buf, const byte *data,
    word16 data_len);

WOLFMQTT_API int MqttDecode_Vbi(byte *buf, word32 *value, word32 buf_len);
WOLFMQTT_API int MqttEncode_Vbi(byte *buf, word32 x);

/* Packet Encoders/Decoders */
WOLFMQTT_API int MqttEncode_Connect(byte *tx_buf, int tx_buf_len,
    MqttConnect *connect);
WOLFMQTT_API int MqttDecode_ConnectAck(byte *rx_buf, int rx_buf_len,
    MqttConnectAck *connect_ack);
WOLFMQTT_API int MqttEncode_Publish(byte *tx_buf, int tx_buf_len,
    MqttPublish *publish, byte use_cb);
WOLFMQTT_API int MqttDecode_Publish(byte *rx_buf, int rx_buf_len,
    MqttPublish *publish);
WOLFMQTT_API int MqttEncode_PublishResp(byte* tx_buf, int tx_buf_len,
    byte type, MqttPublishResp *publish_resp);
/*! \brief Decode a PUBACK / PUBREC / PUBREL / PUBCOMP packet.
 *
 *  \note Per MQTT 3.1.1 sections 3.4-3.7 the variable header is exactly the
 *  two-byte Packet Identifier with no payload; Remaining Length must be
 *  2. The decoder rejects any extra trailing bytes with
 *  MQTT_CODE_ERROR_MALFORMED_DATA. MQTT v5 sections 3.4-3.7 allows an optional
 *  Reason Code and Properties block - the longer form is accepted only
 *  when publish_resp is non-NULL and publish_resp->protocol_level is
 *  MQTT_CONNECT_PROTOCOL_LEVEL_5 or higher. Callers integrating against
 *  non-spec brokers that emit extra bytes for v3.x acks must either fix
 *  the peer or set protocol_level to 5 before calling.
 */
WOLFMQTT_API int MqttDecode_PublishResp(byte* rx_buf, int rx_buf_len,
    byte type, MqttPublishResp *publish_resp);
WOLFMQTT_API int MqttEncode_Subscribe(byte *tx_buf, int tx_buf_len,
    MqttSubscribe *subscribe);
WOLFMQTT_API int MqttDecode_SubscribeAck(byte* rx_buf, int rx_buf_len,
    MqttSubscribeAck *subscribe_ack);
WOLFMQTT_API int MqttEncode_Unsubscribe(byte *tx_buf, int tx_buf_len,
    MqttUnsubscribe *unsubscribe);
WOLFMQTT_API int MqttDecode_UnsubscribeAck(byte *rx_buf, int rx_buf_len,
    MqttUnsubscribeAck *unsubscribe_ack);
WOLFMQTT_API int MqttEncode_Ping(byte *tx_buf, int tx_buf_len, MqttPing* ping);
WOLFMQTT_API int MqttDecode_Ping(byte *rx_buf, int rx_buf_len, MqttPing* ping);
WOLFMQTT_API int MqttEncode_Disconnect(byte *tx_buf, int tx_buf_len,
    MqttDisconnect* disc);

#ifdef WOLFMQTT_V5
WOLFMQTT_API int MqttDecode_Disconnect(byte *rx_buf, int rx_buf_len,
    MqttDisconnect *disc);
WOLFMQTT_API int MqttDecode_Auth(byte *rx_buf, int rx_buf_len,
    MqttAuth *auth);
WOLFMQTT_API int MqttEncode_Auth(byte *tx_buf, int tx_buf_len,
    MqttAuth *auth);
WOLFMQTT_API int MqttEncode_Props(MqttPacketType packet, MqttProp* props,
    byte* buf);
WOLFMQTT_API int MqttDecode_Props(MqttPacketType packet, MqttProp** props,
    byte* buf, word32 buf_len, word32 prop_len);
/* Must be called once from a single thread before any concurrent access
 * to MQTTv5 property functions. Not thread-safe if called concurrently. */
WOLFMQTT_API int MqttProps_Init(void);
/* Must be called once from a single thread after all concurrent access
 * to MQTTv5 property functions has ceased. Not thread-safe if called
 * concurrently. */
WOLFMQTT_API int MqttProps_ShutDown(void);
WOLFMQTT_API MqttProp* MqttProps_Add(MqttProp **head);
WOLFMQTT_API int MqttProps_Free(MqttProp *head);
WOLFMQTT_API MqttProp* MqttProps_FindType(MqttProp *head,
    MqttPropertyType type);
#endif

#ifndef WOLFMQTT_NO_ERROR_STRINGS
    WOLFMQTT_LOCAL const char* MqttPacket_TypeDesc(MqttPacketType packet_type);
#else
    #define MqttPacket_TypeDesc(x) "not compiled in"
#endif

#ifdef WOLFMQTT_BROKER
WOLFMQTT_API int MqttDecode_Connect(byte *rx_buf, int rx_buf_len,
    MqttConnect *mc_connect);
WOLFMQTT_API int MqttEncode_ConnectAck(byte *tx_buf, int tx_buf_len,
    MqttConnectAck *connect_ack);
WOLFMQTT_API int MqttDecode_Subscribe(byte *rx_buf, int rx_buf_len,
    MqttSubscribe *subscribe);
WOLFMQTT_API int MqttDecode_Unsubscribe(byte *rx_buf, int rx_buf_len,
    MqttUnsubscribe *unsubscribe);
WOLFMQTT_API int MqttEncode_UnsubscribeAck(byte *tx_buf, int tx_buf_len,
    MqttUnsubscribeAck *unsubscribe_ack);
#ifndef WOLFMQTT_V5
WOLFMQTT_API int MqttDecode_Disconnect(byte *rx_buf, int rx_buf_len,
    MqttDisconnect* disc);
#endif
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_PACKET_H */
