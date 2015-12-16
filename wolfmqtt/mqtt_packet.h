/* mqtt_packet.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Implementation by: David Garske
 * Based on specification for MQTT v3.1.1
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


/* QoS */
typedef enum _MqttQoS {
    MQTT_QOS_0 = 0, /* At most once delivery */
    MQTT_QOS_1 = 1, /* At least once delivery */
    MQTT_QOS_2 = 2, /* Exactly once delivery */
    MQTT_QOS_3 = 3, /* Reserved - must not be used */
} MqttQoS;


/* Generic Message */
typedef struct _MqttMessage {
    word16      packet_id;
    MqttQoS     qos;
    byte        retain;
    byte        duplicate;
    const char *topic_name;   /* Pointer is valid only when msg_new set in callback */
    word16      topic_name_len;
    word32      total_len;    /* Payload total length */
    byte       *buffer;       /* Payload buffer */

    /* Used internally for TX/RX */
    word32      buffer_len;   /* Buffer length */
    word32      buffer_pos;   /* Buffer position */
} MqttMessage;


/* Topic */
typedef struct _MqttTopic {
    const char* topic_filter;

    /* These are only on subscribe */
    MqttQoS     qos; /* Bits 0-1 = MqttQoS */
    byte        return_code; /* MqttSubscribeAckReturnCodes */
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
    MQTT_PACKET_TYPE_MAX = 15,
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
#define MQTT_PACKET_MAX_SIZE        (int)sizeof(MqttPacket)

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
    MQTT_CONNECT_FLAG_CLEAN_SESSION = 0x02,
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
#define MQTT_CONNECT_PROTOCOL_LEVEL     4

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

/* CONNECT ACKNOWLEDGE PACKET */
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
    byte       flags;       /* MqttConnectAckFlags */
    byte       return_code; /* MqttConnectAckCodes */
} MqttConnectAck;
/* Connect Ack has no payload */

/* Connect */
typedef struct _MqttConnect {
    word16      keep_alive_sec;
    byte        clean_session;
    const char *client_id;

    /* Optional Last will and testament */
    byte        enable_lwt;
    MqttMessage *lwt_msg;

    /* Optional login */
    const char *username;
    const char *password;

    /* Ack data */
    MqttConnectAck ack;
} MqttConnect;


/* PUBLISH PACKET */
/* PacketId sent only if QoS > 0 */
typedef MqttMessage MqttPublish; /* Publish is message */


/* PUBLISH RESPONSE PACKET */
/* This is the response struct for PUBLISH_ACK, PUBLISH_REC and PUBLISH_COMP */
/* If QoS = 0: No response */
/* If QoS = 1: Expect response packet with type =
    MQTT_PACKET_TYPE_PUBLISH_ACK */
/* If QoS = 2: Expect response packet with type =
    MQTT_PACKET_TYPE_PUBLISH_REC */
/* Packet Id required if QoS is 1 or 2 */
/* If Qos = 2: Send MQTT_PACKET_TYPE_PUBLISH_REL with PacketId to complete
    QoS2 protcol exchange */
/* Expect response packet with type = MQTT_PACKET_TYPE_PUBLISH_COMP */
typedef struct _MqttPublishResp {
    word16      packet_id;
} MqttPublishResp;

/* SUBSCRIBE PACKET */
/* Packet Id followed by contiguous list of topics w/Qos to subscribe to. */
typedef struct _MqttSubscribe {
    word16      packet_id;
    int         topic_count;
    MqttTopic  *topics;
} MqttSubscribe;

/* SUBSCRIBE ACK PACKET */
/* Packet Id followed by list of return codes coorisponding to subscription
    topic list sent. */
enum MqttSubscribeAckReturnCodes {
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0 = 0,
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS1 = 1,
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS2 = 2,
    MQTT_SUBSCRIBE_ACK_CODE_FAILURE = 0x80,
};
typedef struct _MqttSubscribeAck {
    word16      packet_id;
    byte       *return_codes; /* MqttSubscribeAckReturnCodes */
} MqttSubscribeAck;


/* UNSUBSCRIBE PACKET */
/* Packet Id followed by contiguous list of topics to unsubscribe from. */
typedef MqttSubscribe MqttUnsubscribe;


/* UNSUBSCRIBE RESPONSE ACK */
/* No response payload (besides packet Id) */
typedef struct _MqttUnsubscribeAck {
    word16      packet_id;
} MqttUnsubscribeAck;


/* PING / PING RESPONSE PACKETS */
/* Fixed header "MqttPacket" only. No variable header or payload */


/* MQTT PACKET APPLICATION INTERFACE */
struct _MqttClient;
/* Packet Read/Write */
int MqttPacket_Write(struct _MqttClient *client, byte* tx_buf, int tx_buf_len);
int MqttPacket_Read(struct _MqttClient *client, byte* rx_buf, int rx_buf_len,
    int timeout_ms);

/* Packet Element Encoders/Decoders */
int MqttDecode_RemainLen(MqttPacket *header, int buf_len, int *remain_len);
int MqttEncode_RemainLen(MqttPacket *header, int buf_len, int remain_len);

int MqttDecode_Num(byte* buf, word16 *len);
int MqttEncode_Num(byte *buf, word16 len);

int MqttDecode_String(byte *buf, const char **pstr, word16 *pstr_len);
int MqttEncode_String(byte *buf, const char *str);

int MqttEncode_Data(byte *buf, const byte *data, word16 data_len);

/* Packet Encoders/Decoders */
int MqttEncode_Connect(byte *tx_buf, int tx_buf_len,
    MqttConnect *connect);
int MqttDecode_ConenctAck(byte *rx_buf, int rx_buf_len,
    MqttConnectAck *connect_ack);
int MqttEncode_Publish(byte *tx_buf, int tx_buf_len,
    MqttPublish *publish);
int MqttDecode_Publish(byte *rx_buf, int rx_buf_len,
    MqttPublish *publish);
int MqttEncode_PublishResp(byte* tx_buf, int tx_buf_len, byte type,
    MqttPublishResp *publish_resp);
int MqttDecode_PublishResp(byte* rx_buf, int rx_buf_len, byte type,
    MqttPublishResp *publish_resp);
int MqttEncode_Subscribe(byte *tx_buf, int tx_buf_len, MqttSubscribe *subscribe);
int MqttDecode_SubscribeAck(byte* rx_buf, int rx_buf_len,
    MqttSubscribeAck *subscribe_ack);
int MqttEncode_Unsubscribe(byte *tx_buf, int tx_buf_len,
    MqttUnsubscribe *unsubscribe);
int MqttDecode_UnsubscribeAck(byte *rx_buf, int rx_buf_len,
    MqttUnsubscribeAck *unsubscribe_ack);
int MqttEncode_Ping(byte *tx_buf, int tx_buf_len);
int MqttDecode_Ping(byte *rx_buf, int rx_buf_len);
int MqttEncode_Disconnect(byte *tx_buf, int tx_buf_len);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_PACKET_H */
