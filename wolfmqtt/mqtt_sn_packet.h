/* mqtt_sn_packet.h
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

/* Implementation by: David Garske
 * Based on specification for MQTT-SN v1.2
 * See http://mqtt.org/documentation for additional MQTT documentation.
 */

#ifndef WOLFMQTT_SN_PACKET_H
#define WOLFMQTT_SN_PACKET_H

#ifdef __cplusplus
    extern "C" {
#endif

#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_socket.h"

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
    SN_MSG_TYPE_ANY             = 0xFF
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

#endif /* WOLFMQTT_SN_PACKET_H */
