/* websocket_client.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
#include "examples/mqttnet.h"
#include "examples/mqttexample.h"
#include "examples/net_libwebsockets.h"
#include <signal.h>

#ifdef ENABLE_MQTT_WEBSOCKET
/* Globals */
static int mStopRead = 0;

/* Define packet size */
#define MAX_BUFFER_SIZE 1024

static void sig_handler(int signo)
{
    if (signo == SIGINT) {
        mStopRead = 1;
    }
}

int main(int argc, char *argv[])
{
    MqttClient client;
    MqttNet mqttNet;
    MqttConnect connect;
    MQTTCtx mqttCtx;
    int rc;
    const char *host = "localhost";
    word16 port = 9001;
    const char* client_id = "wolfMQTT_Websocket_Client";
    byte *tx_buf, *rx_buf;
    
    /* Parse arguments */
    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = (word16)atoi(argv[2]);
    }
    
    /* Initialize MQTTCtx */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.host = host;
    mqttCtx.port = port;
    mqttCtx.client_id = client_id;
    
    /* Initialize Network */
    rc = MqttClientNet_Init(&mqttNet, &mqttCtx);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClientNet_Init failed: %d\n", rc);
        return rc;
    }
    
    /* Override with websocket callbacks */
    mqttNet.connect = NetWebsocket_Connect;
    mqttNet.read = NetWebsocket_Read;
    mqttNet.write = NetWebsocket_Write;
    mqttNet.disconnect = NetWebsocket_Disconnect;
    
    /* Setup buffers */
    tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    if (tx_buf == NULL || rx_buf == NULL) {
        printf("Memory allocation failed\n");
        rc = MQTT_CODE_ERROR_MEMORY;
        goto exit;
    }
    
    /* Initialize MqttClient */
    rc = MqttClient_Init(&client, &mqttNet, NULL, 
        tx_buf, MAX_BUFFER_SIZE, 
        rx_buf, MAX_BUFFER_SIZE, 
        5000);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Init failed: %d\n", rc);
        goto exit;
    }
    
    /* Connect to broker */
    printf("Connecting to %s:%d\n", host, port);
    rc = MqttClient_NetConnect(&client, host, port, 5000, 0, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_NetConnect failed: %d\n", rc);
        goto exit;
    }
    
    /* Perform MQTT Connect */
    XMEMSET(&connect, 0, sizeof(connect));
    connect.keep_alive_sec = 60;
    connect.clean_session = 1;
    connect.client_id = client_id;
    
    printf("MQTT Connect: ClientID=%s\n", connect.client_id);
    rc = MqttClient_Connect(&client, &connect);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Connect failed: %d\n", rc);
        goto exit;
    }
    
    printf("MQTT Connected\n");
    
    /* Subscribe to a topic */
    MqttSubscribe subscribe;
    MqttTopic topics[1];
    XMEMSET(&subscribe, 0, sizeof(subscribe));
    topics[0].topic_filter = "test/topic";
    topics[0].qos = MQTT_QOS_0;
    subscribe.packet_id = mqtt_get_packetid();
    subscribe.topic_count = 1;
    subscribe.topics = topics;
    
    printf("MQTT Subscribe: %s (QoS %d)\n", 
        topics[0].topic_filter, topics[0].qos);
    rc = MqttClient_Subscribe(&client, &subscribe);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Subscribe failed: %d\n", rc);
        goto exit;
    }
    
    /* Wait for messages */
    printf("Waiting for messages...\n");
    signal(SIGINT, sig_handler);
    
    while (!mStopRead) {
        /* Try receiving */
        rc = MqttClient_WaitMessage(&client, 1000);
        
        if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            /* Keep waiting */
            continue;
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            printf("MqttClient_WaitMessage failed: %d\n", rc);
            break;
        }
    }
    
    /* Unsubscribe */
    MqttUnsubscribe unsubscribe;
    XMEMSET(&unsubscribe, 0, sizeof(unsubscribe));
    unsubscribe.packet_id = mqtt_get_packetid();
    unsubscribe.topic_count = 1;
    unsubscribe.topics = topics;
    
    rc = MqttClient_Unsubscribe(&client, &unsubscribe);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Unsubscribe failed: %d\n", rc);
    }
    
exit:
    /* Disconnect */
    rc = MqttClient_Disconnect(&client);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Disconnect failed: %d\n", rc);
    }
    
    MqttClient_DeInit(&client);
    
    /* Free resources */
    if (tx_buf) {
        WOLFMQTT_FREE(tx_buf);
    }
    if (rx_buf) {
        WOLFMQTT_FREE(rx_buf);
    }
    MqttClientNet_DeInit(&mqttNet);
    
    return rc;
} 
#else

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    printf("WebSocket support is not enabled\n");
    return 0;
}

#endif /* ENABLE_MQTT_WEBSOCKET */

