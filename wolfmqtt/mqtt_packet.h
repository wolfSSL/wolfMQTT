/* mqtt_packet.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
    MQTT_DATA_TYPE_STRING_PAIR,
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
    MQTT_REASON_WILDCARD_SUB_NOT_SUP = 0xA2,
};
#endif /* WOLFMQTT_V5 */



/* QoS */
typedef enum _MqttQoS {
    MQTT_QOS_0 = 0, /* At most once delivery */
    MQTT_QOS_1 = 1, /* At least once delivery */
    MQTT_QOS_2 = 2, /* Exactly once delivery */
    MQTT_QOS_3 = 3, /* MQTT - Reserved - must not be used
                       MQTT-SN - QoS -1 allows publish without connection */
} MqttQoS;


/* Topic */
typedef struct _MqttTopic {
    const char* topic_filter;

    /* These are only on subscribe */
    MqttQoS     qos; /* Bits 0-1 = MqttQoS */
    byte        return_code; /* MqttSubscribeAckReturnCodes */
#ifdef WOLFMQTT_V5
    byte        sub_id;
    word16      alias;
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
    MQTT_PACKET_TYPE_ANY = 16,
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
    MQTT_PACKET_FLAG_DUPLICATE = 0x8,
};

/* Packet Header: Size is variable 2 - 5 bytes */
#define MQTT_PACKET_MAX_LEN_BYTES   4
#define MQTT_PACKET_LEN_ENCODE_MASK 0x80
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
typedef enum _MqttMsgStat {
    MQTT_MSG_BEGIN = 0, /* must be zero, so memset will setup state */
#ifdef WOLFMQTT_V5
    MQTT_MSG_AUTH,
#endif
    MQTT_MSG_WAIT,
    MQTT_MSG_WRITE,
    MQTT_MSG_WRITE_PAYLOAD,
    MQTT_MSG_READ,
    MQTT_MSG_READ_PAYLOAD,
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
    (((flags) MQTT_CONNECT_FLAG_WILL_QOS_MASK) >> \
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
    MQTT_CONNECT_FLAG_USERNAME = 0x80,
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
    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT = 0x01,
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
    MQTT_CONNECT_ACK_CODE_REFUSED_NOT_AUTH = 5,
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
    MQTT_SUBSCRIBE_ACK_CODE_FAILURE = 0x80,
};
typedef struct _MqttSubscribeAck {
    MqttMsgStat stat; /* must be first member at top */

    word16      packet_id;
    byte        return_codes[MAX_MQTT_TOPICS];
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
WOLFMQTT_LOCAL int MqttPacket_Write(struct _MqttClient *client, byte* tx_buf,
    int tx_buf_len);
WOLFMQTT_LOCAL int MqttPacket_Read(struct _MqttClient *client, byte* rx_buf,
    int rx_buf_len, int timeout_ms);

/* Packet Element Encoders/Decoders */
WOLFMQTT_LOCAL int MqttDecode_Num(byte* buf, word16 *len);
WOLFMQTT_LOCAL int MqttEncode_Num(byte *buf, word16 len);

WOLFMQTT_LOCAL int MqttDecode_Int(byte* buf, word32* len);
WOLFMQTT_LOCAL int MqttEncode_Int(byte* buf, word32 len);

WOLFMQTT_LOCAL int MqttDecode_String(byte *buf, const char **pstr,
    word16 *pstr_len);
WOLFMQTT_LOCAL int MqttEncode_String(byte *buf, const char *str);

WOLFMQTT_LOCAL int MqttEncode_Data(byte *buf, const byte *data,
    word16 data_len);

WOLFMQTT_LOCAL int MqttDecode_Vbi(byte *buf, word32 *value, word32 buf_len);
WOLFMQTT_LOCAL int MqttEncode_Vbi(byte *buf, word32 x);

/* Packet Encoders/Decoders */
WOLFMQTT_LOCAL int MqttEncode_Connect(byte *tx_buf, int tx_buf_len,
    MqttConnect *connect);
WOLFMQTT_LOCAL int MqttDecode_ConnectAck(byte *rx_buf, int rx_buf_len,
    MqttConnectAck *connect_ack);
WOLFMQTT_LOCAL int MqttEncode_Publish(byte *tx_buf, int tx_buf_len,
    MqttPublish *publish, byte use_cb);
WOLFMQTT_LOCAL int MqttDecode_Publish(byte *rx_buf, int rx_buf_len,
    MqttPublish *publish);
WOLFMQTT_LOCAL int MqttEncode_PublishResp(byte* tx_buf, int tx_buf_len,
    byte type, MqttPublishResp *publish_resp);
WOLFMQTT_LOCAL int MqttDecode_PublishResp(byte* rx_buf, int rx_buf_len,
    byte type, MqttPublishResp *publish_resp);
WOLFMQTT_LOCAL int MqttEncode_Subscribe(byte *tx_buf, int tx_buf_len,
    MqttSubscribe *subscribe);
WOLFMQTT_LOCAL int MqttDecode_SubscribeAck(byte* rx_buf, int rx_buf_len,
    MqttSubscribeAck *subscribe_ack);
WOLFMQTT_LOCAL int MqttEncode_Unsubscribe(byte *tx_buf, int tx_buf_len,
    MqttUnsubscribe *unsubscribe);
WOLFMQTT_LOCAL int MqttDecode_UnsubscribeAck(byte *rx_buf, int rx_buf_len,
    MqttUnsubscribeAck *unsubscribe_ack);
WOLFMQTT_LOCAL int MqttEncode_Ping(byte *tx_buf, int tx_buf_len, MqttPing* ping);
WOLFMQTT_LOCAL int MqttDecode_Ping(byte *rx_buf, int rx_buf_len, MqttPing* ping);
WOLFMQTT_LOCAL int MqttEncode_Disconnect(byte *tx_buf, int tx_buf_len,
    MqttDisconnect* disc);

#ifdef WOLFMQTT_V5
WOLFMQTT_LOCAL int MqttDecode_Disconnect(byte *rx_buf, int rx_buf_len,
    MqttDisconnect *disc);
WOLFMQTT_LOCAL int MqttDecode_Auth(byte *rx_buf, int rx_buf_len,
    MqttAuth *auth);
WOLFMQTT_LOCAL int MqttEncode_Auth(byte *tx_buf, int tx_buf_len,
    MqttAuth *auth);
WOLFMQTT_LOCAL int MqttEncode_Props(MqttPacketType packet, MqttProp* props,
    byte* buf);
WOLFMQTT_LOCAL int MqttDecode_Props(MqttPacketType packet, MqttProp** props,
    byte* buf, word32 buf_len, word32 prop_len);
WOLFMQTT_LOCAL int MqttProps_Init(void);
WOLFMQTT_LOCAL int MqttProps_ShutDown(void);
WOLFMQTT_LOCAL MqttProp* MqttProps_Add(MqttProp **head);
WOLFMQTT_LOCAL int MqttProps_Free(MqttProp *head);
WOLFMQTT_LOCAL MqttProp* MqttProps_FindType(MqttProp *head,
    MqttPropertyType type);
#endif

#ifndef WOLFMQTT_NO_ERROR_STRINGS
    WOLFMQTT_LOCAL const char* MqttPacket_TypeDesc(MqttPacketType packet_type);
#else
    #define MqttPacket_TypeDesc(x) "not compiled in"
#endif


#ifdef WOLFMQTT_SN

/* Note that because MQTT-SN does not support message fragmentation and
   reassembly, the maximum message length that could be used in a network is
   governed by the maximum packet size that is supported by that network,
   and not by the maximum length that could be encoded by MQTT-SN. */
#ifndef WOLFMQTT_SN_MAXPACKET_SIZE
#define WOLFMQTT_SN_MAXPACKET_SIZE 1024
#endif

/* The SN_GwAddr field has a variable length and contains the address of a GW.
   Its depends on the network over which MQTT-SN operates and is indicated in
   the first octet of this field. For example, in a ZigBee network the network
   address is 2-octet long. */
typedef word16 SN_GwAddr ;

/* RETURN CODE values */
enum SN_ReturnCodes {
    SN_RC_ACCEPTED      = 0x00,
    SN_RC_CONGESTION    = 0x01,
    SN_RC_INVTOPICNAME  = 0x02,
    SN_RC_NOTSUPPORTED  = 0x03
    /* 0x04 - 0xFF reserved */
};

/* MESSAGE HEADER */
/* Message types: Located in last byte of header */
typedef enum _SN_MsgType {
    SN_MSG_TYPE_ADVERTISE       = 0x00,
    SN_MSG_TYPE_SEARCHGW        = 0x01,
    SN_MSG_TYPE_GWINFO          = 0x02,
    /* 0x03 reserved */
    SN_MSG_TYPE_CONNECT         = 0x04,
    SN_MSG_TYPE_CONNACK         = 0x05,
    SN_MSG_TYPE_WILLTOPICREQ    = 0x06,
    SN_MSG_TYPE_WILLTOPIC       = 0x07,
    SN_MSG_TYPE_WILLMSGREQ      = 0x08,
    SN_MSG_TYPE_WILLMSG         = 0x09,
    SN_MSG_TYPE_REGISTER        = 0x0A,
    SN_MSG_TYPE_REGACK          = 0x0B,
    SN_MSG_TYPE_PUBLISH         = 0x0C,
    SN_MSG_TYPE_PUBACK          = 0x0D,
    SN_MSG_TYPE_PUBCOMP         = 0x0E,
    SN_MSG_TYPE_PUBREC          = 0x0F,
    SN_MSG_TYPE_PUBREL          = 0x10,
    /* 0x11 reserved */
    SN_MSG_TYPE_SUBSCRIBE       = 0x12,
    SN_MSG_TYPE_SUBACK          = 0x13,
    SN_MSG_TYPE_UNSUBSCRIBE     = 0x14,
    SN_MSG_TYPE_UNSUBACK        = 0x15,
    SN_MSG_TYPE_PING_REQ        = 0x16,
    SN_MSG_TYPE_PING_RESP       = 0x17,
    SN_MSG_TYPE_DISCONNECT      = 0x18,
    /* 0x19 reserved */
    SN_MSG_TYPE_WILLTOPICUPD    = 0x1A,
    SN_MSG_TYPE_WILLTOPICRESP   = 0x1B,
    SN_MSG_TYPE_WILLMSGUPD      = 0x1C,
    SN_MSG_TYPE_WILLMSGRESP     = 0x1D,
    /* 0x1E - 0xFD reserved */
    SN_MSG_TYPE_ENCAPMSG        = 0xFE,    /* Encapsulated message */
    /* 0xFF reserved */
    SN_MSG_TYPE_RESERVED        = 0xFF,
    SN_MSG_TYPE_ANY     = 0xFF
} SN_MsgType;

/* Topic ID types */
enum SN_TopicId_Types {
    SN_TOPIC_ID_TYPE_NORMAL = 0x0,
    SN_TOPIC_ID_TYPE_PREDEF = 0x1,
    SN_TOPIC_ID_TYPE_SHORT  = 0x2
};

enum SN_PacketFlags {
    SN_PACKET_FLAG_TOPICIDTYPE_MASK = 0x3,
    SN_PACKET_FLAG_CLEANSESSION     = 0x4,
    SN_PACKET_FLAG_WILL             = 0x8,
    SN_PACKET_FLAG_RETAIN           = 0x10,
    SN_PACKET_FLAG_QOS_MASK         = 0x60,
    SN_PACKET_FLAG_QOS_SHIFT        = 0x5,
    SN_PACKET_FLAG_DUPLICATE        = 0x80
};

/* Message Header: Size is variable 2 - 4 bytes */

/* If the first byte of the packet len is 0x01, then the packet size is
   greater than 0xFF and is stored in the next two bytes */
#define SN_PACKET_LEN_IND        0x01

#define SN_PACKET_MAX_SMALL_SIZE 0xFF

/* Gateway (GW) messages */
/* Advertise message */
typedef struct _SN_AdvertiseMsg {
    MqttMsgStat stat;

    byte gwId; /* ID of the gateway that sent this message */
    word16 duration; /* Seconds until next Advertise
                        is broadcast by this gateway */
} SN_Advertise;

typedef struct _SN_GwInfo {
    MqttMsgStat stat;

    byte gwId; /* ID of the gateway that sent this message */
    SN_GwAddr* gwAddr; /* Address of the indicated gateway */
} SN_GwInfo;

typedef struct _SN_SearchGw {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    byte radius; /* Broadcast radius (in hops) */
    SN_GwInfo gwInfo;
} SN_SearchGw;

/* Connect Protocol */
#define SN_PROTOCOL_ID_1 0x01
#define SN_PROTOCOL_ID SN_PROTOCOL_ID_1

#define SN_CLIENTID_MAX_LEN 23

/* Connect Ack message structure */
typedef struct _SN_ConnectAck {
    MqttMsgStat stat;

    byte       return_code;
} SN_ConnectAck;

/* WILL TOPIC */
typedef struct _SN_WillTopicUpd {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    byte flags;
    char* willTopic; /* contains the Will topic name */
} SN_WillTopicUpd;

typedef struct _SN_WillMsgUpd {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    char* willMsg;
} SN_WillMsgUpd;

typedef struct _SN_WillTopicResp {
    MqttMsgStat stat;

    byte return_code;
} SN_WillTopicResp;

typedef SN_WillTopicResp SN_WillMsgResp;

typedef union _SN_WillResp {
    SN_WillMsgResp   msgResp;
    SN_WillMsgUpd    msgUpd;
    SN_WillTopicResp topicResp;
    SN_WillTopicUpd  topicUpd;
} SN_WillResp;

typedef struct _SN_Will {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    byte qos;
    byte retain;
    const char* willTopic;
    byte* willMsg;
    word16 willMsgLen;

    SN_WillResp resp;
} SN_Will;

/* Connect */
typedef struct _SN_Connect {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    word16 keep_alive_sec;
    byte clean_session;
    const char *client_id;

    /* Protocol version: 1=v1.2 (default) */
    byte protocol_level;

    /* Optional Last will and testament */
    byte  enable_lwt;
    SN_Will will;

    /* Ack data */
    SN_ConnectAck ack;
} SN_Connect;

/* REGISTER protocol */
typedef struct _SN_RegAck {
    MqttMsgStat stat;

    word16 topicId;
    word16 packet_id;
    byte return_code;
} SN_RegAck;

typedef struct _SN_Register {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    word16 topicId;
    word16 packet_id;
    const char* topicName;
    SN_RegAck regack;
} SN_Register;

/* PUBLISH RESPONSE */
/* This is the response struct for PUBREC, PUBREL, and PUBCOMP */
/* If QoS = 0: No response */
/* If QoS = 1: Expect response packet with type = SN_MSG_TYPE_PUBACK */
/* If QoS = 2: Expect response packet with type = SN_MSG_TYPE_PUBREC */
/* Message ID required if QoS is 1 or 2 */
/* If QoS = 2: Send SN_MSG_TYPE_PUBREL with msgId to complete
    QoS2 protocol exchange */
/* Expect response packet with type = SN_MSG_TYPE_PUBCOMP */
typedef struct _SN_PublishResp {
    MqttMsgStat stat;

    word16 packet_id;
    word16 topicId; /* PUBACK Only */
    byte return_code; /* PUBACK Only */
} SN_PublishResp;

/* PUBLISH protocol */
typedef struct _SN_Publish {
    MqttMsgStat stat; /* must be first member at top */
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    /* BEGIN: THIS SECTION NEEDS TO MATCH MqttMessage */
    word16      packet_id;
    byte        type;
    MqttQoS     qos;
    byte        retain;
    byte        duplicate;
    byte        topic_type;
    byte        return_code;

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
    /* END: THIS SECTION NEEDS TO MATCH MqttMessage */

    SN_PublishResp resp;
} SN_Publish;

/* SUBSCRIBE ACK */
typedef struct _SN_SubAck {
    MqttMsgStat stat;

    byte flags;
    word16 topicId;
    word16 packet_id;
    byte return_code;
} SN_SubAck;

/* SUBSCRIBE */
typedef struct _SN_Subscribe {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    byte duplicate;
    byte qos;
    word16 packet_id;
    byte topic_type;
    /* 5.3.12 TopicName
       The TopicName field has a variable length and contains an UTF8-encoded
       string that specifies the topic name.*/
    const char* topicNameId; /* Contains topic name, ID,
                                or short name as indicated in topic type */
    SN_SubAck subAck;
} SN_Subscribe;

/* UNSUBSCRIBE RESPONSE ACK */
typedef struct _SN_UnsubscribeAck {
    MqttMsgStat stat; /* must be first member at top */

    word16      packet_id;
} SN_UnsubscribeAck;

/* UNSUBSCRIBE */
typedef struct _SN_Unsubscribe {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    byte duplicate;
    byte qos;
    word16 packet_id;
    byte topic_type;
    /* 5.3.12 TopicName
       The TopicName field has a variable length and contains an UTF8-encoded
       string that specifies the topic name.*/
    const char* topicNameId; /* Contains topic name, ID,
                                or short name as indicated in topic type */
    SN_UnsubscribeAck ack;
} SN_Unsubscribe;

/* PING REQUEST / PING RESPONSE */
typedef struct _SN_PingReq {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    /* clientId is optional and is included by a “sleeping” client when it
       goes to the “awake” state and is waiting for messages sent by the
       server/gateway. */
    char *clientId;
} SN_PingReq;

/* DISCONNECT */
typedef struct _SN_Disconnect {
    MqttMsgStat stat;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp pendResp;
#endif

    /* sleepTmr is optional and is included by a “sleeping” client
       that wants to go the “asleep” state. The receipt of this message
       is also acknowledged by the gateway by means of a DISCONNECT message
       (without a duration field).*/
    word16 sleepTmr;
} SN_Disconnect;

typedef union _SN_Object {
    SN_Advertise      advertise;
    SN_GwInfo         gwInfo;
    SN_SearchGw       searchGw;

    SN_Will           will;
    SN_Connect        connect;
    SN_ConnectAck     connectAck;

    SN_Register       reg;
    SN_RegAck         regAck;

    SN_Publish        publish;
    SN_PublishResp    publishResp;

    SN_Subscribe      sub;
    SN_SubAck         subAck;
    SN_Unsubscribe    unSub;
    SN_UnsubscribeAck unSubAck;

    SN_PingReq        pingReq;
    SN_Disconnect     disconnect;

    SN_WillMsgUpd     willMsgUpd;
    SN_WillMsgResp    willMsgResp;

    SN_WillTopicUpd   willTopicUpd;
    SN_WillTopicResp  willTopicResp;
} SN_Object;


/* Forward Encapsulation */
// TODO

WOLFMQTT_LOCAL int SN_Decode_Header(byte *rx_buf, int rx_buf_len,
    SN_MsgType* p_packet_type, word16* p_packet_id);
WOLFMQTT_LOCAL int SN_Decode_Advertise(byte *rx_buf, int rx_buf_len,
        SN_Advertise *gw_info);
WOLFMQTT_LOCAL int SN_Encode_SearchGW(byte *tx_buf, int tx_buf_len, byte hops);
WOLFMQTT_LOCAL int SN_Decode_GWInfo(byte *rx_buf, int rx_buf_len,
        SN_GwInfo *gw_info);
WOLFMQTT_LOCAL int SN_Encode_Connect(byte *tx_buf, int tx_buf_len,
        SN_Connect *connect);
WOLFMQTT_LOCAL int SN_Decode_ConnectAck(byte *rx_buf, int rx_buf_len,
        SN_ConnectAck *connect_ack);
WOLFMQTT_LOCAL int SN_Decode_WillTopicReq(byte *rx_buf, int rx_buf_len);
WOLFMQTT_LOCAL int SN_Encode_WillTopic(byte *tx_buf, int tx_buf_len,
        SN_Will *willTopic);
WOLFMQTT_LOCAL int SN_Decode_WillMsgReq(byte *rx_buf, int rx_buf_len);
WOLFMQTT_LOCAL int SN_Encode_WillMsg(byte *tx_buf, int tx_buf_len,
        SN_Will *willMsg);
WOLFMQTT_LOCAL int SN_Encode_WillTopicUpdate(byte *tx_buf, int tx_buf_len,
        SN_Will *willTopic);
WOLFMQTT_LOCAL int SN_Decode_WillTopicResponse(byte *rx_buf, int rx_buf_len,
        byte *ret_code);
WOLFMQTT_LOCAL int SN_Encode_WillMsgUpdate(byte *tx_buf, int tx_buf_len,
        SN_Will *willMsg);
WOLFMQTT_LOCAL int SN_Decode_WillMsgResponse(byte *rx_buf, int rx_buf_len,
        byte *ret_code);
WOLFMQTT_LOCAL int SN_Encode_Register(byte *tx_buf, int tx_buf_len,
        SN_Register *regist);
WOLFMQTT_LOCAL int SN_Decode_Register(byte *rx_buf, int rx_buf_len,
        SN_Register *regist);
WOLFMQTT_LOCAL int SN_Encode_RegAck(byte *tx_buf, int tx_buf_len,
        SN_RegAck *regack);
WOLFMQTT_LOCAL int SN_Decode_RegAck(byte *rx_buf, int rx_buf_len,
        SN_RegAck *regack);
WOLFMQTT_LOCAL int SN_Encode_Subscribe(byte *tx_buf, int tx_buf_len,
        SN_Subscribe *subscribe);
WOLFMQTT_LOCAL int SN_Decode_SubscribeAck(byte* rx_buf, int rx_buf_len,
        SN_SubAck *subscribe_ack);
WOLFMQTT_LOCAL int SN_Encode_Publish(byte *tx_buf, int tx_buf_len,
        SN_Publish *publish);
WOLFMQTT_LOCAL int SN_Decode_Publish(byte *rx_buf, int rx_buf_len,
        SN_Publish *publish);
WOLFMQTT_LOCAL int SN_Encode_PublishResp(byte* tx_buf, int tx_buf_len,
        byte type, SN_PublishResp *publish_resp);
WOLFMQTT_LOCAL int SN_Decode_PublishResp(byte* rx_buf, int rx_buf_len,
        byte type, SN_PublishResp *publish_resp);
WOLFMQTT_LOCAL int SN_Encode_Unsubscribe(byte *tx_buf, int tx_buf_len,
        SN_Unsubscribe *unsubscribe);
WOLFMQTT_LOCAL int SN_Decode_UnsubscribeAck(byte *rx_buf, int rx_buf_len,
        SN_UnsubscribeAck *unsubscribe_ack);
WOLFMQTT_LOCAL int SN_Encode_Disconnect(byte *tx_buf, int tx_buf_len,
        SN_Disconnect* disconnect);
WOLFMQTT_LOCAL int SN_Decode_Disconnect(byte *rx_buf, int rx_buf_len);
WOLFMQTT_LOCAL int SN_Encode_Ping(byte *tx_buf, int tx_buf_len,
        SN_PingReq *ping, byte type);
WOLFMQTT_LOCAL int SN_Decode_Ping(byte *rx_buf, int rx_buf_len);
WOLFMQTT_LOCAL int SN_Packet_Read(struct _MqttClient *client, byte* rx_buf,
        int rx_buf_len, int timeout_ms);

#ifndef WOLFMQTT_NO_ERROR_STRINGS
    WOLFMQTT_LOCAL const char* SN_Packet_TypeDesc(SN_MsgType packet_type);
#else
    #define SN_Packet_TypeDesc(x) "not compiled in"
#endif
#endif /* WOLFMQTT_SN */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_PACKET_H */
