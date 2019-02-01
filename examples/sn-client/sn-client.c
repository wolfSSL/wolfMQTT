/* sn-client.c
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

#include "wolfmqtt/mqtt_client.h"

#ifdef WOLFMQTT_SN

#include "sn-client.h"
#include "examples/mqttnet.h"

/* Locals */
static int mStopRead = 0;

/* Configuration */
/* Maximum size for network read/write callbacks. */
#define MAX_BUFFER_SIZE 1024
#define TEST_MESSAGE    "test"


static int sn_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

    (void)mqttCtx;

    if (msg_new) {
        /* Determine min size to dump */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure its null terminated */

        /* Print incoming message */
        PRINTF("MQTT-SN Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);

        /* for test mode: check if TEST_MESSAGE was received */
        if (mqttCtx->test_mode) {
            if (XSTRLEN(TEST_MESSAGE) == msg->buffer_len &&
                XSTRNCMP(TEST_MESSAGE, (char*)msg->buffer,
                         msg->buffer_len) == 0)
            {
                mStopRead = 1;
            }
        }
    }

    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure its null terminated */
    PRINTF("........Payload (%d - %d): %s",
        msg->buffer_pos, msg->buffer_pos + len, buf);

    if (msg_done) {
        PRINTF("....MQTT-SN Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

int sn_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS;
    word16 topicID;

    PRINTF("MQTT-SN Client: QoS %d", mqttCtx->qos);

    /* Initialize Network */
    rc = SN_ClientNet_Init(&mqttCtx->net, mqttCtx);
    PRINTF("MQTT-SN Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* setup tx/rx buffers */
    mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);

    /* Initialize MqttClient structure */
    rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net,
        sn_message_cb,
        mqttCtx->tx_buf, MAX_BUFFER_SIZE,
        mqttCtx->rx_buf, MAX_BUFFER_SIZE,
        mqttCtx->cmd_timeout_ms);

    PRINTF("MQTT-SN Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* The client.ctx will be stored in the cert callback ctx during
       MqttSocket_Connect for use by mqtt_tls_verify_cb */
    mqttCtx->client.ctx = mqttCtx;

    /* Setup socket direct to gateway */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
           mqttCtx->port,DEFAULT_CON_TIMEOUT_MS,
           mqttCtx->use_tls, mqtt_tls_cb);

    PRINTF("MQTT-SN Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    {
        SN_Connect connect_s, *connect = &connect_s;
        /* Build connect packet */
        XMEMSET(connect, 0, sizeof(SN_Connect));
        connect_s.keep_alive_sec = mqttCtx->keep_alive_sec;
        connect_s.clean_session = mqttCtx->clean_session;
        connect_s.client_id = mqttCtx->client_id;
        connect->protocol_level = SN_PROTOCOL_ID;

        /* Last will and testament sent by broker to subscribers
            of topic when broker connection is lost */
        connect_s.enable_lwt = mqttCtx->enable_lwt;
        if (connect_s.enable_lwt) {
            /* Send client id in LWT payload */
            connect_s.will.qos = mqttCtx->qos;
            connect_s.will.retain = 0;
            connect_s.will.willTopic = WOLFMQTT_TOPIC_NAME"lwttopic";
            connect_s.will.willMsg = (byte*)mqttCtx->client_id;
            connect_s.will.willMsgLen =
              (word16)XSTRLEN(mqttCtx->client_id);
        }

        PRINTF("MQTT-SN Broker Connect: broker = %s : %d",
                mqttCtx->host, mqttCtx->port);
        /* Send Connect and wait for Connect Ack */
        rc = SN_Client_Connect(&mqttCtx->client, connect);

        /* Validate Connect Ack info */
        PRINTF("....MQTT-SN Connect Ack: Return Code %u",
                mqttCtx->connect.ack.return_code);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
    }

    /* Either the register or the subscribe block could be used to get the
       topic ID. Both are done here as an example of using the API. */
    {
        /* Register topic name to get the assigned topic ID */
        SN_Register regist_s, *regist = &regist_s;

        XMEMSET(regist, 0, sizeof(SN_Register));
        regist->packet_id = mqtt_get_packetid();
        regist->topicName = DEFAULT_TOPIC_NAME;

        PRINTF("MQTT-SN Register: topic = %s", regist->topicName);
        rc = SN_Client_Register(&mqttCtx->client, regist);

        if ((rc == 0) && (regist->regack.return_code == SN_RC_ACCEPTED)) {
            /* Topic ID is returned in RegAck */
            topicID = regist->regack.topicId;
        }
        PRINTF("....MQTT-SN Register Ack: rc = %d, topic id = %d",
                regist->regack.return_code, regist->regack.topicId);
    }

    {
        /* Subscribe Topic */
        SN_Subscribe subscribe;

        XMEMSET(&subscribe, 0, sizeof(SN_Subscribe));

        subscribe.duplicate = 0;
        subscribe.qos = MQTT_QOS_0;
        subscribe.topic_type = SN_TOPIC_ID_TYPE_NORMAL;
        subscribe.topicNameId = DEFAULT_TOPIC_NAME;
        subscribe.packet_id = mqtt_get_packetid();

        PRINTF("MQTT-SN Subscribe: topic name = %s", subscribe.topicNameId);
        rc = SN_Client_Subscribe(&mqttCtx->client, &subscribe);

        PRINTF("....MQTT-SN Subscribe Ack: topic id = %d, rc = %d",
                subscribe.subAck.topicId, subscribe.subAck.return_code);

        if ((rc == 0) && (subscribe.subAck.return_code == SN_RC_ACCEPTED)) {
            /* Topic ID is returned in SubAck */
            topicID = subscribe.subAck.topicId;
        }
    }

    {
        /* Publish Topic */
        XMEMSET(&mqttCtx->publish, 0, sizeof(SN_Publish));
        mqttCtx->publish.retain = 0;
        mqttCtx->publish.qos = MQTT_QOS_1;//mqttCtx->qos;
        mqttCtx->publish.duplicate = 0;
        mqttCtx->publish.topic_type = SN_TOPIC_ID_TYPE_NORMAL;
        mqttCtx->publish.topic_name = (char*)&topicID;
        if (mqttCtx->publish.qos > MQTT_QOS_0) {
            mqttCtx->publish.packet_id = mqtt_get_packetid();
        }
        else {
            mqttCtx->publish.packet_id = 0x00;
        }

        mqttCtx->publish.buffer = (byte*)TEST_MESSAGE;
        mqttCtx->publish.total_len = (word16)XSTRLEN(TEST_MESSAGE);

        rc = SN_Client_Publish(&mqttCtx->client, &mqttCtx->publish);

        PRINTF("MQTT-SN Publish: topic id = %d, msg = \"%s\", rc = %d",
            (word16)*mqttCtx->publish.topic_name, mqttCtx->publish.buffer,
            mqttCtx->publish.return_code);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
    }

    /* Read Loop */
    PRINTF("MQTT Waiting for message...");

    do {
        /* Try and read packet */
        rc = SN_Client_WaitMessage(&mqttCtx->client,
                                   mqttCtx->cmd_timeout_ms);

        /* check for test mode */
        if (mStopRead) {
            rc = MQTT_CODE_SUCCESS;
            PRINTF("MQTT Exiting...");
            break;
        }

        /* check return code */
    #ifdef WOLFMQTT_ENABLE_STDIN_CAP
        else if (rc == MQTT_CODE_STDIN_WAKE) {
            XMEMSET(mqttCtx->rx_buf, 0, MAX_BUFFER_SIZE);
            if (XFGETS((char*)mqttCtx->rx_buf, MAX_BUFFER_SIZE - 1,
                    stdin) != NULL)
            {
                rc = (int)XSTRLEN((char*)mqttCtx->rx_buf);

                /* Publish Topic */
                mqttCtx->stat = WMQ_PUB;
                XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
                mqttCtx->publish.retain = 0;
                mqttCtx->publish.qos = mqttCtx->qos;
                mqttCtx->publish.duplicate = 0;
                mqttCtx->publish.topic_type = SN_TOPIC_ID_TYPE_NORMAL;
                mqttCtx->publish.topic_name = (char*)&topicID;
                mqttCtx->publish.packet_id = mqtt_get_packetid();
                mqttCtx->publish.buffer = mqttCtx->rx_buf;
                mqttCtx->publish.total_len = (word16)rc;
                rc = SN_Client_Publish(&mqttCtx->client,
                       &mqttCtx->publish);
                PRINTF("MQTT-SN Publish: topic id = %d, msg = \"%s\", rc = %d",
                    (word16)*mqttCtx->publish.topic_name, mqttCtx->publish.buffer,
                    mqttCtx->publish.return_code);
                if (rc != MQTT_CODE_SUCCESS) {
                    break;
                }
            }
        }
    #endif
        else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            /* Keep Alive */
            PRINTF("Keep-alive timeout, sending ping");

            rc = SN_Client_Ping(&mqttCtx->client, NULL);
            if (rc != MQTT_CODE_SUCCESS) {
                PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                    MqttClient_ReturnCodeToString(rc), rc);
                break;
            }
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            /* There was an error */
            PRINTF("MQTT-SN Message Wait Error: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while (1);

    /* Check for error */
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    {
        /* Unsubscribe Topics */
        SN_Unsubscribe unsubscribe;

        /* Build list of topics */
        XMEMSET(&unsubscribe, 0, sizeof(SN_Subscribe));

        unsubscribe.topicNameId = mqttCtx->topic_name;

        /* Subscribe Topic */
        unsubscribe.packet_id = mqtt_get_packetid();

        /* Unsubscribe Topics */
        rc = SN_Client_Unsubscribe(&mqttCtx->client, &unsubscribe);

        PRINTF("MQTT Unsubscribe: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
        mqttCtx->return_code = rc;
    }

disconn:
    /* Disconnect */
    rc = SN_Client_Disconnect(&mqttCtx->client);

    PRINTF("MQTT Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    rc = MqttClient_NetDisconnect(&mqttCtx->client);

    PRINTF("MQTT Socket Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

exit:

    /* Free resources */
    if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
    if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&mqttCtx->net);

    return rc;
}

#endif /* WOLFMQTT_SN */

/* so overall tests can pull in test function */
#if !defined(NO_MAIN_DRIVER) && !defined(MICROCHIP_MPLAB_HARMONY)
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
                mStopRead = 1;
                PRINTF("Received Ctrl+c");
                return TRUE;
            }
            return FALSE;
        }
    #elif HAVE_SIGNAL
        #include <signal.h>
        static void sig_handler(int signo)
        {
            if (signo == SIGINT) {
                mStopRead = 1;
                PRINTF("Received SIGINT");
            }
        }
    #endif

int main(int argc, char** argv)
{
    int rc;
#ifdef WOLFMQTT_SN
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.app_name = "sn-client";

    /* Settings for MQTT-SN gateway */
    mqttCtx.host = "localhost";
    mqttCtx.port = 10000;

    /* parse arguments */
    rc = mqtt_parse_args(&mqttCtx, argc, argv);
    if (rc != 0) {
        return rc;
    }
#endif
#ifdef USE_WINDOWS_API
    if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler,
          TRUE) == FALSE)
    {
        PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
    }
#elif HAVE_SIGNAL
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        PRINTF("Can't catch SIGINT");
    }
#endif

#ifdef WOLFMQTT_SN
    rc = sn_test(&mqttCtx);
#else
    (void)argc;
    (void)argv;

    /* This example requires MQTT-SN mode to be enabled
       ./configure --enable-sn */
    PRINTF("Example not compiled in!");
    rc = EXIT_FAILURE;
#endif


    return (rc == 0) ? 0 : EXIT_FAILURE;
}

#endif /* NO_MAIN_DRIVER */
