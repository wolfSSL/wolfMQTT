/* mqtt_client.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * Based on specification for MQTT v3.1.1
 * See http://mqtt.org/documentation for additional MQTT documentation.
 */

#ifndef WOLFMQTT_CLIENT_H
#define WOLFMQTT_CLIENT_H

#ifdef __cplusplus
    extern "C" {
#endif

/* Windows uses the vs_settings.h file included vis mqtt_types.h */
#if !defined(WOLFMQTT_USER_SETTINGS) && \
    !defined(_WIN32) && !defined(USE_WINDOWS_API)
    /* If options.h is missing use the "./configure" script. Otherwise, copy
     * the template "wolfmqtt/options.h.in" into "wolfmqtt/options.h" */
    #include <wolfmqtt/options.h>
#endif
#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_packet.h"
#include "wolfmqtt/mqtt_socket.h"

#if defined(WOLFMQTT_PROPERTY_CB) && !defined(WOLFMQTT_V5)
    #error "WOLFMQTT_V5 must be defined to use WOLFMQTT_PROPERTY_CB"
#endif

struct _MqttClient;

/*! \brief      Mqtt Message Callback.
 *  If the message payload is larger than the maximum RX buffer
    then this callback is called multiple times.
    If msg_new = 1 its a new message.
    The topic_name and topic_name length are only valid when msg_new = 1.
    If msg_new = 0 then we are receiving additional payload.
    Each callback populates the payload in MqttMessage.buffer.
    The MqttMessage.buffer_len is the size of the buffer payload.
    The MqttMessage.buffer_pos is the location in the total payload.
    The MqttMessage.total_len is the length of the complete payload message.
    If msg_done = 1 the entire publish payload has been received.
 *  \param      client      Pointer to MqttClient structure
 *  \param      message     Pointer to MqttMessage structure that has been
                            initialized with the payload properties
 *  \param      msg_new     If non-zero value then message is new and topic
                            name / len is provided and valid.
 *  \param      msg_done    If non-zero value then we have received the entire
                            message and payload.
 *  \return     MQTT_CODE_SUCCESS to remain connected (other values will cause
                net disconnect - see enum MqttPacketResponseCodes)
 */
typedef int (*MqttMsgCb)(struct _MqttClient *client, MqttMessage *message,
    byte msg_new, byte msg_done);

/*! \brief      Mqtt Publish Callback.
 *  If the publish payload is larger than the maximum TX buffer
    then this callback is called multiple times. This callback is executed from
    within a call to MqttPublish. It is expected to provide a buffer and it's
    size and return >=0 for success.
    Each callback populates the payload in MqttPublish.buffer.
    The MqttPublish.buffer_len is the size of the buffer payload.
    The MqttPublish.total_len is the length of the complete payload message.
 *  \param      publish     Pointer to MqttPublish structure
 *  \return     >= 0        Indicates success
 */
typedef int (*MqttPublishCb)(MqttPublish* publish);

/* Client flags */
enum MqttClientFlags {
    MQTT_CLIENT_FLAG_IS_CONNECTED = 0x01,
    MQTT_CLIENT_FLAG_IS_TLS = 0x02,
};

typedef enum _MqttPkStat {
    MQTT_PK_BEGIN,
    MQTT_PK_READ_HEAD,
    MQTT_PK_READ,
} MqttPkStat;

typedef struct _MqttPkRead {
    MqttPkStat stat;
    int header_len;
    int remain_len;
    int buf_len;
} MqttPkRead;

typedef struct _MqttSk {
    int pos;
    int len;
} MqttSk;

#ifdef WOLFMQTT_DISCONNECT_CB
    typedef int (*MqttDisconnectCb)(struct _MqttClient* client, int error_code, void* ctx);
#endif
#ifdef WOLFMQTT_PROPERTY_CB
    typedef int (*MqttPropertyCb)(struct _MqttClient* client, MqttProp* head, void* ctx);
#endif
#ifdef WOLFMQTT_SN
    /*! \brief      Mqtt-SN Register Callback.
     *  A GW sends a REGISTER message to a client if it wants to
        inform that client about the topic name and the assigned topic id that
        it will use later on when sending PUBLISH messages of the corresponding
        topic name. This callback allows the client to accept and save the new
        ID, or reject it if the ID is unknown. If the callback is not defined,
        then the regack will contain the "unsupported" return code.
     *  \param      topicId     New topic ID value
     *  \param      topicName   Pointer to topic name
     *  \param      reg_ctx     Pointer to user context
     *  \return     >= 0        Indicates acceptance
     */
    typedef int (*SN_ClientRegisterCb)(word16 topicId, const char* topicName, void *reg_ctx);
#endif

/* Client structure */
typedef struct _MqttClient {
    word32       flags; /* MqttClientFlags */
    int          cmd_timeout_ms;

    byte        *tx_buf;
    int          tx_buf_len;
    byte        *rx_buf;
    int          rx_buf_len;

    MqttNet     *net;   /* Pointer to network callbacks and context */
#ifdef ENABLE_MQTT_TLS
    MqttTls      tls;   /* WolfSSL context for TLS */
#endif

    MqttPkRead   packet; /* publish packet state - protected by read lock */
    MqttPublishResp packetAck; /* publish ACK - protected by write lock */
    MqttSk       read;   /* read socket state - protected by read lock */
    MqttSk       write;  /* write socket state - protected by write lock */

    MqttMsgCb    msg_cb;
    MqttObject   msg;   /* generic incoming message used by MqttClient_WaitType */
#ifdef WOLFMQTT_SN
    SN_Object    msgSN;
    SN_ClientRegisterCb reg_cb;
    void               *reg_ctx;
#endif
    void*        ctx;   /* user supplied context for publish callbacks */

#ifdef WOLFMQTT_V5
    word32 packet_sz_max; /* Server property */
    byte   max_qos;       /* Server property */
    byte   retain_avail;  /* Server property */
    byte   enable_eauth;  /* Enhanced authentication */
    byte   protocol_level;
#endif

#ifdef WOLFMQTT_DISCONNECT_CB
    MqttDisconnectCb disconnect_cb;
    void            *disconnect_ctx;
#endif
#ifdef WOLFMQTT_PROPERTY_CB
    MqttPropertyCb property_cb;
    void          *property_ctx;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    wm_Sem lockSend;
    wm_Sem lockRecv;
    wm_Sem lockClient;
    struct _MqttPendResp* firstPendResp; /* protected with client lock */
    struct _MqttPendResp* lastPendResp;  /* protected with client lock */
#endif
#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_DEBUG_CLIENT)
    int lastRc;
#endif
} MqttClient;


/* Application Interfaces */

/*! \brief      Initializes the MqttClient structure
 *  \param      client      Pointer to MqttClient structure
                            (uninitialized is okay)
 *  \param      net         Pointer to MqttNet structure that has been
                            initialized with callback pointers and context
 *  \param      msg_cb       Pointer to message callback function
 *  \param      tx_buf      Pointer to transmit buffer used during encoding
 *  \param      tx_buf_len  Maximum length of the transmit buffer
 *  \param      rx_buf      Pointer to receive buffer used during decoding
 *  \param      rx_buf_len  Maximum length of the receive buffer
 *  \param      cmd_timeout_ms
                            Maximum command wait timeout in milliseconds
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_BAD_ARG
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Init(
    MqttClient *client,
    MqttNet *net,
    MqttMsgCb msg_cb,
    byte *tx_buf, int tx_buf_len,
    byte *rx_buf, int rx_buf_len,
    int cmd_timeout_ms);

/*! \brief      Cleans up resources allocated to the MqttClient structure
 *  \param      client      Pointer to MqttClient structure
 *  \return     none
 */
WOLFMQTT_API void MqttClient_DeInit(MqttClient *client);

#ifdef WOLFMQTT_DISCONNECT_CB
/*! \brief      Sets a disconnect callback with custom context
 *  \param      client      Pointer to MqttClient structure
                            (uninitialized is okay)
 *  \param      discb       Pointer to disconnect callback function
 *  \param      ctx         Pointer to your own context
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_BAD_ARG
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_SetDisconnectCallback(
    MqttClient *client,
    MqttDisconnectCb discb,
    void* ctx);
#endif

#ifdef WOLFMQTT_PROPERTY_CB
/*! \brief      Sets a property callback with custom context
 *  \param      client      Pointer to MqttClient structure
                            (uninitialized is okay)
 *  \param      propCb      Pointer to property callback function
 *  \param      ctx         Pointer to your own context
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_BAD_ARG
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_SetPropertyCallback(
    MqttClient *client,
    MqttPropertyCb propCb,
    void* ctx);
#endif

/*! \brief      Encodes and sends the MQTT Connect packet and waits for the
                Connect Acknowledgment packet
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      connect     Pointer to MqttConnect structure initialized
                            with connect parameters
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Connect(
    MqttClient *client,
    MqttConnect *connect);

/*! \brief      Encodes and sends the MQTT Publish packet and waits for the
                Publish response (if QoS > 0). If the total size of the
                payload is larger than the buffer size, it can be called
                successively to transmit the full payload.
                (if QoS > 0)
 *  \note This is a blocking function that will wait for MqttNet.read
 *              If QoS level = 1 then will wait for PUBLISH_ACK.
 *              If QoS level = 2 then will wait for PUBLISH_REC then send
                    PUBLISH_REL and wait for PUBLISH_COMP.
 *  \param      client      Pointer to MqttClient structure
 *  \param      publish     Pointer to MqttPublish structure initialized
                            with message data
 *                          Note: MqttPublish and MqttMessage are same
                            structure.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Publish(
    MqttClient *client,
    MqttPublish *publish);

/*! \brief      Encodes and sends the MQTT Publish packet and waits for the
                Publish response (if QoS > 0). The callback function is used to
                copy the payload data, allowing the use of transmit buffers
                smaller than the total size of the payload.
 *  \note This is a blocking function that will wait for MqttNet.read
 *              If QoS level = 1 then will wait for PUBLISH_ACK.
 *              If QoS level = 2 then will wait for PUBLISH_REC then send
                    PUBLISH_REL and wait for PUBLISH_COMP.
 *  \param      client      Pointer to MqttClient structure
 *  \param      publish     Pointer to MqttPublish structure initialized
                            with message data
 *                          Note: MqttPublish and MqttMessage are same
                            structure.
*   \param      pubCb       Function pointer to callback routine
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Publish_ex(
    MqttClient *client,
    MqttPublish *publish,
    MqttPublishCb pubCb);

/*! \brief      Encodes and sends the MQTT Subscribe packet and waits for the
                Subscribe Acknowledgment packet
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      subscribe   Pointer to MqttSubscribe structure initialized with
                            subscription topic list and desired QoS.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Subscribe(
    MqttClient *client,
    MqttSubscribe *subscribe);

/*! \brief      Encodes and sends the MQTT Unsubscribe packet and waits for the
                Unsubscribe Acknowledgment packet
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      unsubscribe Pointer to MqttUnsubscribe structure initialized
                            with topic list.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Unsubscribe(
    MqttClient *client,
    MqttUnsubscribe *unsubscribe);

/*! \brief      Encodes and sends the MQTT Ping Request packet and waits for the
                Ping Response packet
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Ping(
    MqttClient *client);

/*! \brief      Encodes and sends the MQTT Ping Request packet and waits for the
                Ping Response packet. This version takes a MqttPing structure
                and can be used with non-blocking applications.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      ping        Pointer to MqttPing structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Ping_ex(MqttClient *client, MqttPing* ping);

#ifdef WOLFMQTT_V5
/*! \brief      Encodes and sends the MQTT Authentication Request packet and
                waits for the Ping Response packet
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      auth        Pointer to MqttAuth structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Auth(
    MqttClient *client,
    MqttAuth *auth);


/*! \brief      Add a new property.
 *  Allocate a property structure and add it to the head of the list
    pointed to by head. To be used prior to calling packet command.
 *  \param      head        Pointer-pointer to a property structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_BAD_ARG
 */
WOLFMQTT_API MqttProp* MqttClient_PropsAdd(
    MqttProp **head);

/*! \brief      Free property list.
 *  Deallocate the list pointed to by head. Must be used after the
                packet command that used MqttClient_Prop_Add.
 *  \param      head        Pointer-pointer to a property structure
 *  \return     MQTT_CODE_SUCCESS or -1 on error (and sets errno)
 */
WOLFMQTT_API int MqttClient_PropsFree(
    MqttProp *head);
#endif


/*! \brief      Encodes and sends the MQTT Disconnect packet (no response)
 *  \note This is a non-blocking function that will try and send using
                MqttNet.write
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Disconnect(
    MqttClient *client);


/*! \brief      Encodes and sends the MQTT Disconnect packet (no response)
 *  \note This is a non-blocking function that will try and send using
                MqttNet.write
 *  \param      client      Pointer to MqttClient structure
 *  \param      disconnect  Pointer to MqttDisconnect structure. NULL is valid.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Disconnect_ex(
    MqttClient *client,
    MqttDisconnect *disconnect);


/*! \brief      Waits for packets to arrive. Incoming publish messages
                will arrive via callback provided in MqttClient_Init.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      timeout_ms  Milliseconds until read timeout
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_WaitMessage(
    MqttClient *client,
    int timeout_ms);

/*! \brief      Waits for packets to arrive. Incoming publish messages
                will arrive via callback provided in MqttClient_Init.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      msg         Pointer to MqttObject structure
 *  \param      timeout_ms  Milliseconds until read timeout
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_WaitMessage_ex(
    MqttClient *client,
    MqttObject* msg,
    int timeout_ms);

/*! \brief      In a multi-threaded and non-blocking mode this allows you to
                cancel an MQTT object that was previously submitted.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      msg         Pointer to MqttObject structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_CancelMessage(
    MqttClient *client,
    MqttObject* msg);

/*! \brief      Performs network connect with TLS (if use_tls is non-zero value)
 *  Will perform the MqttTlsCb callback if use_tls is non-zero value
 *  \param      client      Pointer to MqttClient structure
 *  \param      host        Address of the broker server
 *  \param      port        Optional custom port. If zero will use defaults
 *  \param      use_tls     If non-zero value will connect with and use TLS for
                            encryption of data
 *  \param      cb          A function callback for configuration of the SSL
                            context certificate checking
 *  \param      timeout_ms  Milliseconds until read timeout
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_NetConnect(
    MqttClient *client,
    const char *host,
    word16 port,
    int timeout_ms,
    int use_tls,
    MqttTlsCb cb);

/*! \brief      Performs a network disconnect
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_NetDisconnect(
    MqttClient *client);

/*! \brief      Gets number version of connected protocol version
 *  \param      client      Pointer to MqttClient structure
 *  \return     4 (v3.1.1) or 5 (v5)
 */
WOLFMQTT_API int MqttClient_GetProtocolVersion(MqttClient *client);

/*! \brief      Gets string version of connected protocol version
 *  \param      client      Pointer to MqttClient structure
 *  \return     String v3.1.1 or v5
 */
WOLFMQTT_API const char* MqttClient_GetProtocolVersionString(MqttClient *client);

#ifndef WOLFMQTT_NO_ERROR_STRINGS
/*! \brief      Performs lookup of the WOLFMQTT_API return values
 *  \param      return_code The return value from a WOLFMQTT_API function
 *  \return     String representation of the return code
 */
WOLFMQTT_API const char* MqttClient_ReturnCodeToString(
    int return_code);
#else
    #define MqttClient_ReturnCodeToString(x) \
                                        "not compiled in"
#endif /* WOLFMQTT_NO_ERROR_STRINGS */

#ifdef WOLFMQTT_SN
/*! \brief      Encodes and sends the a message to search for a gateway and
                waits for the gateway info response message.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      search      Pointer to SN_SearchGW structure initialized
                            with hop radius.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_SearchGW(
        MqttClient *client,
        SN_SearchGw *search);

/*! \brief      Encodes and sends the Connect packet and waits for the
                Connect Acknowledgment packet. If Will is enabled, the gateway
                prompts for LWT Topic and Message. Sending an empty will topic
                indicates that the client wishes to delete the Will topic and
                the Will message stored in the server.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      connect     Pointer to SN_Connect structure initialized
                            with connect parameters
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Connect(
    MqttClient *client,
    SN_Connect *connect);

/*! \brief      Encodes and sends the MQTT-SN Will Topic Update packet. Sending
                a NULL 'will' indicates that the client wishes to delete the
                Will topic and the Will message stored in the server.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      will        Pointer to SN_Will structure initialized
                            with topic and message parameters. NULL is valid.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_WillTopicUpdate(MqttClient *client, SN_Will *will);

/*! \brief      Encodes and sends the MQTT-SN Will Message Update packet.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      will        Pointer to SN_Will structure initialized
                            with topic and message parameters. NULL is valid.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_WillMsgUpdate(MqttClient *client, SN_Will *will);

/*! \brief      Encodes and sends the MQTT-SN Register packet and waits for the
                Register Acknowledge packet. The Register packet is sent by a
                client to a GW for requesting a topic id value for the included
                topic name. It is also sent by a GW to inform a client about
                the topic id value it has assigned to the included topic name.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      regist      Pointer to SN_Register structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Register(
    MqttClient *client,
    SN_Register *regist);


/*! \brief      Sets a register callback with custom context
 *  \param      client      Pointer to MqttClient structure
                            (uninitialized is okay)
 *  \param      regCb       Pointer to register callback function
 *  \param      ctx         Pointer to your own context
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_BAD_ARG
 */
WOLFMQTT_API int SN_Client_SetRegisterCallback(
    MqttClient *client,
    SN_ClientRegisterCb regCb,
    void* ctx);


/*! \brief      Encodes and sends the MQTT-SN Publish packet and waits for the
                Publish response (if QoS > 0).
 *  \note This is a blocking function that will wait for MqttNet.read
 *              If QoS level = 1 then will wait for PUBLISH_ACK.
 *              If QoS level = 2 then will wait for PUBLISH_REC then send
                    PUBLISH_REL and wait for PUBLISH_COMP.
 *  \param      client      Pointer to MqttClient structure
 *  \param      publish     Pointer to SN_Publish structure initialized
                            with message data
 *                          Note: SN_Publish and MqttMessage are same
                            structure.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Publish(
    MqttClient *client,
    SN_Publish *publish);

/*! \brief      Encodes and sends the MQTT-SN Subscribe packet and waits for the
                Subscribe Acknowledgment packet containing the assigned
                topic ID.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      subscribe   Pointer to SN_Subscribe structure initialized with
                            subscription topic list and desired QoS.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Subscribe(
    MqttClient *client,
    SN_Subscribe *subscribe);

/*! \brief      Encodes and sends the MQTT-SN Unsubscribe packet and waits for
                the Unsubscribe Acknowledgment packet
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      unsubscribe Pointer to SN_Unsubscribe structure initialized
                            with topic ID.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Unsubscribe(
    MqttClient *client,
    SN_Unsubscribe *unsubscribe);

/*! \brief      Encodes and sends the MQTT-SN Disconnect packet. Client may
                send the disconnect with a duration to indicate the client is
                entering the "asleep" state.
 *  \note This is a non-blocking function that will try and send using
                MqttNet.write
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Disconnect(
    MqttClient *client);

/*! \brief      Encodes and sends the MQTT-SN Disconnect packet. Client may
                send the disconnect with a duration to indicate the client is
                entering the "asleep" state.
 *  \note This is a non-blocking function that will try and send using
                MqttNet.write
 *  \param      client      Pointer to MqttClient structure
 *  \param      disconnect  Pointer to SN_Disconnect structure. NULL is valid.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Disconnect_ex(
    MqttClient *client,
    SN_Disconnect *disconnect);


/*! \brief      Encodes and sends the MQTT-SN Ping Request packet and waits
                for the Ping Response packet. If client is in the "asleep"
                state and wants to notify the gateway that it is entering the
                "awake" state, it should add it's client ID to the ping
                request.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      ping        Pointer to SN_PingReq structure. NULL is valid.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Ping(
    MqttClient *client,
    SN_PingReq *ping);

/*! \brief      Waits for packets to arrive. Incoming publish messages
                will arrive via callback provided in MqttClient_Init.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      timeout_ms  Milliseconds until read timeout
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_WaitMessage(
    MqttClient *client,
    int timeout_ms);

WOLFMQTT_API int SN_Client_WaitMessage_ex(MqttClient *client, SN_Object* packet_obj,
    int timeout_ms);

#endif /* WOLFMQTT_SN */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_CLIENT_H */
