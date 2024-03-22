/* sn-client_qos-1.c
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

/* This example requires a gateway that supports and is configured
   for Quality of Service level -1. The Paho gateway must be configured
   as described in the wolfMQTT README.md */

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
#define TEST_MESSAGE    "QoS-1 test message"
char    SHORT_TOPIC_NAME[] = {1};


int sn_testQoSn1(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS;

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
        NULL,
        mqttCtx->tx_buf, MAX_BUFFER_SIZE,
        mqttCtx->rx_buf, MAX_BUFFER_SIZE,
        mqttCtx->cmd_timeout_ms);

    PRINTF("MQTT-SN Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* Setup socket direct to gateway */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
           mqttCtx->port, DEFAULT_CON_TIMEOUT_MS,
           0, NULL);

    PRINTF("MQTT-SN Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    {
        SN_Publish publish;

        /* Predefined Topic Name Publish */
        XMEMSET(&publish, 0, sizeof(SN_Publish));
        publish.qos = MQTT_QOS_3; /* Set QoS level -1 */
        publish.topic_type = SN_TOPIC_ID_TYPE_PREDEF;
        publish.topic_name = (char*)SHORT_TOPIC_NAME;
        publish.buffer = (byte*)TEST_MESSAGE;
        publish.total_len = (word16)XSTRLEN(TEST_MESSAGE);

        rc = SN_Client_Publish(&mqttCtx->client, &publish);

        PRINTF("MQTT-SN Publish: topic id = %d, rc = %d\r\nPayload = %s",
            (word16)*publish.topic_name,
            publish.return_code,
            publish.buffer);
        if (rc != MQTT_CODE_SUCCESS) {
            goto disconn;
        }
    }

disconn:

    rc = MqttClient_NetDisconnect(&mqttCtx->client);

    PRINTF("MQTT Socket Disconnect: %s (%d)",
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
int sn_QoSn1_main(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
    int rc;
#ifdef WOLFMQTT_SN
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.app_name = "sn-client_qos-1";

    /* Settings for MQTT-SN gateway */
    mqttCtx.host = "localhost";
    mqttCtx.port = 1883;

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
    rc = sn_testQoSn1(&mqttCtx);
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

