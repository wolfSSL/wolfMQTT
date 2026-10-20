/* mqtt_sn_client.h
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
 * Based on specification for MQTT-SN v1.2
 * See http://mqtt.org/documentation for additional MQTT-SN documentation.
 */

#ifndef WOLFMQTT_SN_CLIENT_H
#define WOLFMQTT_SN_CLIENT_H

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
#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_packet.h"
#include "wolfmqtt/mqtt_socket.h"

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
                prompts for LWT Topic and Message. The Will is always sent
                with its flags, so an empty Will topic here does not use the
                delete form (MQTT-SN 1.2 section 5.4.7).
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      connect     Pointer to SN_Connect structure initialized
                            with connect parameters
 *  \return     MQTT_CODE_SUCCESS if the gateway accepted the connection,
                MQTT_CODE_ERROR_CONNECT_REFUSED if the gateway returned a
                non-zero CONNACK return_code (check
                connect->ack.return_code for the specific SN_ReturnCodes
                value), or another MQTT_CODE_ERROR_* for transport/protocol
                failures (see enum MqttPacketResponseCodes). Callers must not
                proceed to SN_Client_Subscribe, SN_Client_Publish, or other
                session operations when this function does not return
                MQTT_CODE_SUCCESS.
 */
WOLFMQTT_API int SN_Client_Connect(
    MqttClient *client,
    SN_Connect *connect);

/*! \brief      Encodes and sends the MQTT-SN Will Topic Update packet. Setting
                will->willTopic to NULL sends an empty Will Topic Update,
                which asks the server to delete the stored Will topic and
                Will message.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      will        Pointer to SN_Will structure initialized
                            with topic and message parameters. Must not be
                            NULL; it also holds the request state.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_WillTopicUpdate(MqttClient *client, SN_Will *will);

/*! \brief      Encodes and sends the MQTT-SN Will Message Update packet.
 *  \note This is a blocking function that will wait for MqttNet.read
 *  \param      client      Pointer to MqttClient structure
 *  \param      will        Pointer to SN_Will structure initialized
                            with topic and message parameters. Must not be
                            NULL.
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
 *  \return     MQTT_CODE_SUCCESS if the gateway accepted the subscription,
                MQTT_CODE_ERROR_SUBSCRIBE_REJECTED if the gateway returned a
                non-zero SUBACK return_code (check subscribe->subAck.return_code
                for the specific SN_ReturnCodes value), or another
                MQTT_CODE_ERROR_* for transport/protocol failures (see enum
                MqttPacketResponseCodes). Callers must not assume messages will
                be delivered for this topic when this function does not return
                MQTT_CODE_SUCCESS.
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
 *  \note This function does not wait for a response. It sends using
                MqttNet.write and, unless WOLFMQTT_NONBLOCK is defined,
                blocks until the packet is written or the write fails.
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int SN_Client_Disconnect(
    MqttClient *client);

/*! \brief      Encodes and sends the MQTT-SN Disconnect packet. Client may
                send the disconnect with a duration to indicate the client is
                entering the "asleep" state.
 *  \note With a NULL disconnect or a zero sleepTmr this only sends the
                packet using MqttNet.write. With a nonzero sleepTmr it then
                waits up to cmd_timeout_ms for the gateway's DISCONNECT
                acknowledgement (MQTT-SN 1.2 section 6.14): blocking builds
                wait for it, while WOLFMQTT_NONBLOCK builds may return
                MQTT_CODE_CONTINUE and must be called again to complete.
 *  \param      client      Pointer to MqttClient structure
 *  \param      disconnect  Pointer to SN_Disconnect structure. NULL is valid.
 *  \return     MQTT_CODE_SUCCESS, MQTT_CODE_CONTINUE when the call must be
                repeated (another write is in progress, or a nonblocking wait
                for the acknowledgement), or MQTT_CODE_ERROR_*
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
 *  \param      ping        Pointer to SN_PingReq structure. NULL uses
                            client-owned state. Concurrent NULL-ping callers
                            receive MQTT_CODE_CONTINUE while that state is in
                            use and may retry.
 *                          A NULL ping uses client-owned storage so the request
 *                          can resume after MQTT_CODE_CONTINUE.
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

#endif /* WOLFMQTT_SN_CLIENT_H */
