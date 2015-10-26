/* mqtt_client.h
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

#ifndef WOLFMQTT_CLIENT_H
#define WOLFMQTT_CLIENT_H

#ifdef __cplusplus
    extern "C" {
#endif

#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_packet.h"
#include "wolfmqtt/mqtt_socket.h"

/* Client flags */
enum MqttClientFlags {
    MQTT_CLIENT_FLAG_IS_CONNECTED = 0x01,
    MQTT_CLIENT_FLAG_IS_TLS = 0x02,
};

/* Client structure */
typedef struct _MqttClient {
    word32       flags; /* MqttClientFlags */
    int          cmd_timeout_ms;

    byte        *tx_buf;
    int          tx_buf_len;
    byte        *rx_buf;
    int          rx_buf_len;

    MqttNet     *net;   /* Pointer to network callbacks and context */
    MqttTls      tls;   /* WolfSSL context for TLS */
} MqttClient;


/* Application Interfaces */
/*! \brief      Initializes the MqttClient structure
 *  \param      client      Pointer to MqttClient structure
 *  \param      net         Pointer to MqttNet structure that has been initialized with callback pointers and context
 *  \param      tx_buf      Pointer to transmit buffer used during encoding
 *  \param      tx_buf_len  Maximum length of the transmit buffer
 *  \param      rx_buf      Pointer to receive buffer used during decoding
 *  \param      rx_buf_len  Maximum length of the receive buffer
 *  \param      connect_timeout_ms  Maximum command wait timeout in milliseconds
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_BAD_ARG (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Init(MqttClient *client, MqttNet *net,
    byte *tx_buf, int tx_buf_len,
    byte *rx_buf, int rx_buf_len,
    int cmd_timeout_ms);


/*! \brief      Encodes and sends the MQTT Connect packet and waits for the Connect Acknowledgement packet
 *  \discussion This is a blocking function that will wait for MqttNet.read data
 *  \param      client      Pointer to MqttClient structure
 *  \param      connect     Pointer to MqttConnect structure initialized with connect parameters
 *  \return     Length of encoded packet or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Connect(MqttClient *client, MqttConnect *connect);

/*! \brief      Encodes and sends the MQTT Publish packet and waits for the Publish response (if QoS > 0)
 *  \discussion This is a blocking function that will wait for MqttNet.read data.
 *              If QoS level = 1 then will wait for PUBLISH_ACK.
 *              If QoS level = 2 then will wait for PUBLISH_REC then send PUBLISH_REL and wait for PUBLISH_COMP.
 *  \param      client      Pointer to MqttClient structure
 *  \param      publish     Pointer to MqttPublish structure initialized message data
 *                          Note: MqttPublish and MqttMessage are same structure.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Publish(MqttClient *client, MqttPublish *publish);

/*! \brief      Encodes and sends the MQTT Subscribe packet and waits for the Subscribe Acknowledgement packet
 *  \discussion This is a blocking function that will wait for MqttNet.read data
 *  \param      client      Pointer to MqttClient structure
 *  \param      subscribe   Pointer to MqttSubscribe structure initialized with subscription topic list and desired QoS.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Subscribe(MqttClient *client, MqttSubscribe *subscribe);

/*! \brief      Encodes and sends the MQTT Unsubscribe packet and waits for the Unsubscribe Acknowledgement packet
 *  \discussion This is a blocking function that will wait for MqttNet.read data
 *  \param      client      Pointer to MqttClient structure
 *  \param      connect     Pointer to MqttUnsubscribe structure initialized with topic list.
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Unsubscribe(MqttClient *client, MqttUnsubscribe *unsubscribe);

/*! \brief      Encodes and sends the MQTT Ping Request packet and waits for the Ping Response packet
 *  \discussion This is a blocking function that will wait for MqttNet.read data
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Ping(MqttClient *client);

/*! \brief      Encodes and sends the MQTT Disconnect packet (no response)
 *  \discussion This is a non-blocking function that will try and send using MqttNet.write
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_Disconnect(MqttClient *client);


/*! \brief      Waits for Publish packets to arrive
 *  \discussion This is a blocking function that will wait for MqttNet.read data
 *  \param      client      Pointer to MqttClient structure
 *  \param      message     Pointer to MqttMessage structure (un-initialized is okay)
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_WaitMessage(MqttClient *client, MqttMessage *message,
    int timeout_ms);


/*! \brief      Performs network connect with TLS (if use_tls is non-zero value)
 *  \discussion Will perform the MqttTlsCb callback if use_tls is non-zero value.
 *  \param      client      Pointer to MqttClient structure
 *  \param      host        Address of the broker sever
 *  \param      port        Optional custom port. If zero will use defaults
 *  \param      use_tls     If non-zero value will connect with and use TLS for encryption of data
 *  \param      cb          A function callback for configuration of the SSL context certificate checking
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_NetConnect(MqttClient *client, const char *host,
    word16 port, int timeout_ms, int use_tls, MqttTlsCb cb);

/*! \brief      Performs a network disconnect
 *  \param      client      Pointer to MqttClient structure
 *  \return     MQTT_CODE_SUCCESS or MQTT_CODE_ERROR_* (see enum MqttPacketResponseCodes)
 */
WOLFMQTT_API int MqttClient_NetDisconnect(MqttClient *client);

/*! \brief      Performs lookup of the WOLFMQTT_API return values
 *  \param      return_code The return value from a WOLFMQTT_API function
 *  \return     Srting representation of the return code
 */
WOLFMQTT_API const char* MqttClient_ReturnCodeToString(int return_code);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_CLIENT_H */
