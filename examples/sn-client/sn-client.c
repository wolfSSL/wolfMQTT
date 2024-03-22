/* sn-client.c
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"

#include "sn-client.h"
#include "examples/mqttnet.h"

/* Locals */
static int mStopRead = 0;

#ifdef WOLFMQTT_SN

/* Configuration */
/* Maximum size for network read/write callbacks. */
#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE 1024
#endif
#define TEST_MESSAGE    "test"
#define SHORT_TOPIC_NAME "s1"

static int sn_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;
    word16 topicId;
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

    if (msg_new) {
        if (!(msg->topic_type & SN_TOPIC_ID_TYPE_SHORT)) {
            /* Topic ID name */
            topicId = (word16)((byte)msg->topic_name[0] << 8 |
                               (byte)msg->topic_name[1]);

            /* Print incoming message */
            PRINTF("MQTT-SN Message: Topic ID %hu, Qos %d, Id %d, Len %u",
                    topicId, msg->qos, msg->packet_id, msg->total_len);
        }
        else {
            /* Topic short name */
            /* Print incoming message */
            PRINTF("MQTT-SN Message: Topic ID %c%c, Qos %d, Id %d, Len %u",
                    msg->topic_name[0], msg->topic_name[1],
                    msg->qos, msg->packet_id, msg->total_len);
        }
        /* for test mode: check if TEST_MESSAGE was received */
        if (mqttCtx != NULL && mqttCtx->test_mode) {
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

/* The Register callback is used when the gateway
   assigns a new topic ID to a topic name. */
static int sn_reg_callback(word16 topicId, const char* topicName, void *ctx)
{
    PRINTF("MQTT-SN Register CB: New topic ID: %hu : \"%s\"", topicId, topicName);
    (void)ctx;

    return(MQTT_CODE_SUCCESS);
}

#ifdef WOLFMQTT_DISCONNECT_CB
/* callback indicates a network error or broker disconnect occurred */
static int mqtt_disconnect_cb(MqttClient* client, int error_code, void* ctx)
{
    (void)client;
    (void)ctx;
    PRINTF("Disconnect Callback: %s (error %d)",
        MqttClient_ReturnCodeToString(error_code), error_code);
    return 0;
}
#endif

int sn_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS;
    word16 topicID;

    PRINTF("MQTT-SN Client: Client ID %s, QoS %d",
            mqttCtx->client_id,
            mqttCtx->qos);

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

#if defined(ENABLE_MQTT_TLS) && defined(WOLFSSL_DTLS)
    if (mqttCtx->use_tls) {
        /* Set the DTLS flag in the client structure to indicate DTLS usage */
        MqttClient_Flags(&mqttCtx->client, 0, MQTT_CLIENT_FLAG_IS_DTLS);
    }
#endif

    /* Setup socket direct to gateway */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
           mqttCtx->port, DEFAULT_CON_TIMEOUT_MS,
           mqttCtx->use_tls, NULL /*mqtt_dtls_cb*/);

    PRINTF("MQTT-SN Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* Set the Register callback used when the gateway
       assigns a new topic ID to a topic name. */
    rc = SN_Client_SetRegisterCallback(&mqttCtx->client, sn_reg_callback, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

#ifdef WOLFMQTT_DISCONNECT_CB
    /* setup disconnect callback */
    rc = MqttClient_SetDisconnectCallback(&mqttCtx->client,
        mqtt_disconnect_cb, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
#endif

    {
        SN_Connect connect_s, *connect = &connect_s;
        /* Build connect packet */
        XMEMSET(connect, 0, sizeof(SN_Connect));
        connect->keep_alive_sec = mqttCtx->keep_alive_sec;
        connect->clean_session = mqttCtx->clean_session;
        connect->client_id = mqttCtx->client_id;
        connect->protocol_level = SN_PROTOCOL_ID;

        /* Last will and testament sent by broker to subscribers
            of topic when broker connection is lost */
        connect->enable_lwt = mqttCtx->enable_lwt;
        if (connect->enable_lwt) {
            /* Send client id in LWT payload */
            connect->will.qos = mqttCtx->qos;
            connect->will.retain = 0;
            connect->will.willTopic = WOLFMQTT_TOPIC_NAME"lwttopic";
            connect->will.willMsg = (byte*)mqttCtx->client_id;
            connect->will.willMsgLen =
              (word16)XSTRLEN(mqttCtx->client_id);
        }

        PRINTF("MQTT-SN Connect: gateway = %s : %d",
                mqttCtx->host, mqttCtx->port);
        /* Send Connect and wait for Connect Ack */
        rc = SN_Client_Connect(&mqttCtx->client, connect);

        if (rc != MQTT_CODE_SUCCESS) {
            PRINTF("MQTT-SN Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            goto disconn;
        }

        /* Validate Connect Ack info */
        PRINTF("....MQTT-SN Connect Ack: Return Code %u",
                connect->ack.return_code);
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
        PRINTF("....MQTT-SN Register Ack: rc = %d, topic id = %hu",
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

        PRINTF("....MQTT-SN Subscribe Ack: topic id = %hu, rc = %d",
                subscribe.subAck.topicId, subscribe.subAck.return_code);

        if ((rc == 0) && (subscribe.subAck.return_code == SN_RC_ACCEPTED)) {
            /* Topic ID is returned in SubAck */
            topicID = subscribe.subAck.topicId;
        }
    }

    {
        /* Subscribe Wildcard Topic - This allows the gateway to send a
           REGISTER command when another client publishes to a topic that
           matches this topic wildcard. This will trigger the register
           callback. */
        SN_Subscribe subscribe;

        XMEMSET(&subscribe, 0, sizeof(SN_Subscribe));

        subscribe.duplicate = 0;
        subscribe.qos = MQTT_QOS_0;
        subscribe.topic_type = SN_TOPIC_ID_TYPE_NORMAL;
        subscribe.topicNameId = WOLFMQTT_TOPIC_NAME"#";
        subscribe.packet_id = mqtt_get_packetid();

        PRINTF("MQTT-SN Subscribe: topic name = %s", subscribe.topicNameId);
        rc = SN_Client_Subscribe(&mqttCtx->client, &subscribe);

        PRINTF("....MQTT-SN Subscribe Ack: topic id = %hu, rc = %d",
                subscribe.subAck.topicId,
                (rc == 0) ? subscribe.subAck.return_code : rc);
    }

    {
        /* Publish Topic */
        XMEMSET(&mqttCtx->publishSN, 0, sizeof(SN_Publish));
        mqttCtx->publishSN.retain = 0;
        mqttCtx->publishSN.qos = mqttCtx->qos;
        mqttCtx->publishSN.duplicate = 0;
        mqttCtx->publishSN.topic_type = SN_TOPIC_ID_TYPE_NORMAL;

        /* Use the topic ID saved from the subscribe */
        mqttCtx->publishSN.topic_name = (char*)&topicID;
        if (mqttCtx->publishSN.qos > MQTT_QOS_0) {
            mqttCtx->publishSN.packet_id = mqtt_get_packetid();
        }
        else {
            mqttCtx->publishSN.packet_id = 0x00;
        }

        mqttCtx->publishSN.buffer = (byte*)TEST_MESSAGE;
        mqttCtx->publishSN.total_len = (word16)XSTRLEN(TEST_MESSAGE);

        rc = SN_Client_Publish(&mqttCtx->client, &mqttCtx->publishSN);

        PRINTF("MQTT-SN Publish: topic id = %hu, rc = %d\r\nPayload = %s",
                *(word16*)mqttCtx->publishSN.topic_name,
                mqttCtx->publishSN.return_code,
                mqttCtx->publishSN.buffer);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
    }

    /* The predefined topic examples require modification of the gateway
       configuration. To add a predefined topic to a Paho MQTTSN-Embedded-C
       Gateway, open the gateway config file and enable the following:

           PredefinedTopic=YES
           PredefinedTopicList=./predefinedTopic.conf

       Then in the "predefinedTopic.conf" file, add a topic:

           *, wolfMQTT/example/predefTopic7, 7

       Then restart the gateway.
     */
#if 0
    {
        SN_Publish publish;
        SN_Subscribe subscribe;
        SN_Unsubscribe unsub;
        char pd_topic_id[] = {0,7}; /* Same ID as set above */

        /* Subscribe Predefined Topic */
        XMEMSET(&subscribe, 0, sizeof(SN_Subscribe));

        subscribe.duplicate = 0;
        subscribe.qos = MQTT_QOS_0;
        subscribe.topic_type = SN_TOPIC_ID_TYPE_PREDEF;
        subscribe.topicNameId = pd_topic_id;
        subscribe.packet_id = mqtt_get_packetid();

        PRINTF("MQTT-SN Predefined Subscribe: topic id = %hu",
                subscribe.topicNameId[1]);
        rc = SN_Client_Subscribe(&mqttCtx->client, &subscribe);

        if (rc == MQTT_CODE_SUCCESS) {
            PRINTF("....MQTT-SN Predefined Subscribe Ack: topic id = %hu, rc = %d",
                    subscribe.subAck.topicId, subscribe.subAck.return_code);
        }
        if ((rc == MQTT_CODE_SUCCESS) && (subscribe.subAck.return_code != 0)) {
            /* Error in subscribe ack */
            PRINTF("MQTT-SN Predefined Topic (%d) is invalid in Gateway",
                    subscribe.subAck.topicId);
        }

        /* Publish Predefined Topic */
        XMEMSET(&publish, 0, sizeof(SN_Publish));
        publish.retain = 0;
        publish.qos = MQTT_QOS_0;
        publish.duplicate = 0;
        publish.topic_type = SN_TOPIC_ID_TYPE_PREDEF;

        /* Use the predefined topic ID */
        publish.topic_name = pd_topic_id;

        if (publish.qos > MQTT_QOS_0) {
            publish.packet_id = mqtt_get_packetid();
        }

        publish.buffer = (byte*)TEST_MESSAGE" predefined";
        publish.total_len = (word16)XSTRLEN(TEST_MESSAGE" predefined");

        rc = SN_Client_Publish(&mqttCtx->client, &publish);

        PRINTF("MQTT-SN Predefined Publish: topic id = %hu, rc = %d\r\nPayload = %s",
                publish.topic_name[1],
                publish.return_code,
                publish.buffer);

        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }

        /* Unsubscribe from Predefined Topic */
        XMEMSET(&unsub, 0, sizeof(SN_Unsubscribe));

        unsub.topic_type = SN_TOPIC_ID_TYPE_PREDEF;
        unsub.topicNameId = pd_topic_id;
        unsub.packet_id = mqtt_get_packetid();

        PRINTF("MQTT-SN Unsubscribe Predefined Topic: topic id = %hu",
                unsub.topicNameId[1]);
        rc = SN_Client_Unsubscribe(&mqttCtx->client, &unsub);
        PRINTF("....MQTT-SN Unsubscribe Predefined Topic Ack: rc = %d", rc);
    }
#endif

    {
        /* Short topic name subscribe */
        SN_Subscribe subscribe;
        SN_Publish publish;
        SN_Unsubscribe unsub;

        XMEMSET(&subscribe, 0, sizeof(SN_Subscribe));

        subscribe.duplicate = 0;
        subscribe.qos = MQTT_QOS_0;
        subscribe.topic_type = SN_TOPIC_ID_TYPE_SHORT;
        subscribe.topicNameId = SHORT_TOPIC_NAME;
        subscribe.packet_id = mqtt_get_packetid();

        PRINTF("MQTT-SN Subscribe Short Topic: topic ID = %s",
                subscribe.topicNameId);
        rc = SN_Client_Subscribe(&mqttCtx->client, &subscribe);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
        PRINTF("....MQTT-SN Subscribe Short Topic Ack: topic id = %c%c, rc = %d",
                ((byte*)&subscribe.subAck.topicId)[1],
                ((byte*)&subscribe.subAck.topicId)[0],
                subscribe.subAck.return_code);

        /* Short topic name publish */
        XMEMSET(&publish, 0, sizeof(SN_Publish));
        publish.retain = 0;
        publish.qos = mqttCtx->qos;
        publish.duplicate = 0;
        publish.topic_type = SN_TOPIC_ID_TYPE_SHORT;
        publish.topic_name = SHORT_TOPIC_NAME;
        if (publish.qos > MQTT_QOS_0) {
            publish.packet_id = mqtt_get_packetid();
        }
        else {
            publish.packet_id = 0x00;
        }

        publish.buffer = (byte*)TEST_MESSAGE" short";
        publish.total_len = (word16)XSTRLEN(TEST_MESSAGE" short");

        rc = SN_Client_Publish(&mqttCtx->client, &publish);

        PRINTF("MQTT-SN Publish Short Topic: topic id = %s, rc = %d\r\nPayload = %s",
            publish.topic_name,
            publish.return_code,
            publish.buffer);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }

        /* Unsubscribe short topic name */
        XMEMSET(&unsub, 0, sizeof(SN_Unsubscribe));

        unsub.topic_type = SN_TOPIC_ID_TYPE_SHORT;
        unsub.topicNameId = SHORT_TOPIC_NAME;
        unsub.packet_id = mqtt_get_packetid();

        PRINTF("MQTT-SN Unsubscribe Short Topic: topic ID = %s",
                unsub.topicNameId);
        rc = SN_Client_Unsubscribe(&mqttCtx->client, &unsub);
        PRINTF("....MQTT-SN Unsubscribe Short Topic Ack: rc = %d", rc);
    }

#if 0
    /* Disabled because will topic and message update are not currently
       supported by Paho MQTT-SN Gateway */
    {
        /* Will Topic and Message update */
        SN_Will willUpdate;
        char willTopicName[] = WOLFMQTT_TOPIC_NAME"lastWishes";
        char willTopicMsg[] = "I'LL BE BACK";

        XMEMSET(&willUpdate, 0, sizeof(SN_Will));

        /* Set new topic */
        willUpdate.willTopic = willTopicName;
        PRINTF("MQTT-SN Will Topic Update: topic name = %s", willUpdate.willTopic);
        rc = SN_Client_WillTopicUpdate(&mqttCtx->client, &willUpdate);
        PRINTF("....MQTT-SN Will Topic Update: response = %d, rc = %d",
                willUpdate.resp.topicResp.return_code, rc);

        /* Set new message*/
        willUpdate.willMsg = (byte*)willTopicMsg;
        willUpdate.willMsgLen = XSTRLEN(willTopicMsg);
        PRINTF("MQTT-SN Will Message Update: message = %s", willUpdate.willMsg);
        rc = SN_Client_WillMsgUpdate(&mqttCtx->client, &willUpdate);
        PRINTF("....MQTT-SN Will Message Update: response = %d, rc = %d",
                willUpdate.resp.msgResp.return_code, rc);
    }
#endif

    /* Read Loop */
    PRINTF("MQTT Waiting for message...");

    do {
        /* check for test mode */
        if (mStopRead) {
            rc = MQTT_CODE_SUCCESS;
            PRINTF("MQTT Exiting...");
            break;
        }

        /* Try and read packet */
        rc = SN_Client_WaitMessage(&mqttCtx->client,
                                   mqttCtx->cmd_timeout_ms);

        /* check return code */
    #ifdef WOLFMQTT_ENABLE_STDIN_CAP
        if (rc == MQTT_CODE_STDIN_WAKE) {
            XMEMSET(mqttCtx->rx_buf, 0, MAX_BUFFER_SIZE);
            if (XFGETS((char*)mqttCtx->rx_buf, MAX_BUFFER_SIZE - 1,
                    stdin) != NULL)
            {
                rc = (int)XSTRLEN((char*)mqttCtx->rx_buf);

                /* Publish Topic */
                mqttCtx->stat = WMQ_PUB;
                XMEMSET(&mqttCtx->publishSN, 0, sizeof(SN_Publish));
                mqttCtx->publishSN.retain = 0;
                mqttCtx->publishSN.qos = mqttCtx->qos;
                mqttCtx->publishSN.duplicate = 0;
                mqttCtx->publishSN.topic_type = SN_TOPIC_ID_TYPE_NORMAL;
                mqttCtx->publishSN.topic_name = (char*)&topicID;
                if (mqttCtx->publishSN.qos > MQTT_QOS_0) {
                    mqttCtx->publishSN.packet_id = mqtt_get_packetid();
                }
                else {
                    mqttCtx->publishSN.packet_id = 0x00;
                }
                mqttCtx->publishSN.buffer = mqttCtx->rx_buf;
                mqttCtx->publishSN.total_len = (word16)rc;
                rc = SN_Client_Publish(&mqttCtx->client,
                       &mqttCtx->publishSN);
                PRINTF("MQTT-SN Publish: topic id = %hu, rc = %d\r\nPayload = %s",
                    (word16)*mqttCtx->publishSN.topic_name,
                        mqttCtx->publishSN.return_code,
                        mqttCtx->publishSN.buffer);
                if (rc != MQTT_CODE_SUCCESS) {
                    break;
                }
            }
        }
        else
    #endif
        if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            /* Keep Alive */
            PRINTF("Keep-alive timeout, sending ping");

            rc = SN_Client_Ping(&mqttCtx->client, NULL);
            if (rc != MQTT_CODE_SUCCESS) {
                PRINTF("MQTT-SN Ping Keep Alive Error: %s (rc = %d)",
                    MqttClient_ReturnCodeToString(rc), rc);
                break;
            }
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            /* There was an error */
            PRINTF("MQTT-SN Message Wait Error: %s (rc = %d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while (1);

    /* Check for error */
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    {
        /* Unsubscribe Topic */
        SN_Unsubscribe unsubscribe;

        XMEMSET(&unsubscribe, 0, sizeof(SN_Unsubscribe));
        unsubscribe.topicNameId = DEFAULT_TOPIC_NAME;
        unsubscribe.packet_id = mqtt_get_packetid();

        rc = SN_Client_Unsubscribe(&mqttCtx->client, &unsubscribe);

        PRINTF("MQTT Unsubscribe: %s (rc = %d)",
            MqttClient_ReturnCodeToString(rc), rc);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
        mqttCtx->return_code = rc;
    }

    {
        /* Demonstrate client sleep cycle using disconnect with a sleep timer */
        SN_Disconnect disconnect;

        XMEMSET(&disconnect, 0, sizeof(SN_Disconnect));

        /* Set disconnect sleep timer */
        disconnect.sleepTmr = 30;

        /* Disconnect */
        rc = SN_Client_Disconnect_ex(&mqttCtx->client, &disconnect);

        PRINTF("MQTT Disconnect with sleep: %s (rc = %d)",
            MqttClient_ReturnCodeToString(rc), rc);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }

        /* Do low power state. Published messages from the broker will be
           queued in the gateway.*/

        /* Awake state: Send a ping req with client ID to retrieve buffered
           messages. */
        {
            SN_PingReq ping;
            XMEMSET(&ping, 0, sizeof(SN_PingReq));

            ping.clientId = (char*)mqttCtx->client_id;

            rc = SN_Client_Ping(&mqttCtx->client, &ping);
            if (rc != MQTT_CODE_SUCCESS) {
                PRINTF("MQTT Ping Keep Alive Error: %s (rc = %d)",
                    MqttClient_ReturnCodeToString(rc), rc);
                goto disconn;
            }
        }
    }


disconn:
    /* Disconnect */
    rc = SN_Client_Disconnect(&mqttCtx->client);

    PRINTF("MQTT Disconnect: %s (rc = %d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    rc = MqttClient_NetDisconnect(&mqttCtx->client);

    PRINTF("MQTT Socket Disconnect: %s (rc = %d)",
        MqttClient_ReturnCodeToString(rc), rc);

exit:

    /* Free resources */
    if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
    if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&mqttCtx->net);

    MqttClient_DeInit(&mqttCtx->client);

    return rc;
}

#endif /* WOLFMQTT_SN */

/* so overall tests can pull in test function */
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

#if defined(NO_MAIN_DRIVER)
int sn_main(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
    int rc;
#ifdef WOLFMQTT_SN
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.app_name = "sn-client";
    mqttCtx.client_id = DEFAULT_CLIENT_ID"-SN";

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


    return (rc == MQTT_CODE_SUCCESS) ? 0 : EXIT_FAILURE;
}

