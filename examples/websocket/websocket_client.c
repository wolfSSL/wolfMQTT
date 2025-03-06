/* websocket_client.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include <time.h>

#ifdef ENABLE_MQTT_WEBSOCKET
/* Globals */
static int mStopRead = 0;

/* Define packet size */
#define MAX_BUFFER_SIZE 1024

/* Define ping timeout in seconds */
#define PING_TIMEOUT_SEC 30

/* TLS callback */
static int mqtt_tls_cb(MqttClient* client)
{
    (void)client;
    return 0;
}

/* Message callback */
static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;
    
    (void)client;

    if (msg_new) {
        /* Topic */
        len = msg->topic_name_len;
        if (len > PRINT_BUFFER_SIZE) {
            len = PRINT_BUFFER_SIZE;
        }
        XMEMCPY(buf, msg->topic_name, len);
        buf[len] = '\0'; /* Make sure it's null terminated */
        
        /* Print topic */
        printf("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);
    }
    
    /* Print message payload */
    len = msg->buffer_len;
    if (len > PRINT_BUFFER_SIZE) {
        len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->buffer, len);
    buf[len] = '\0'; /* Make sure it's null terminated */
    
    printf("Payload (%d - %d): %s\n",
        msg->buffer_pos, msg->buffer_pos + msg->buffer_len, buf);

    if (msg_done) {
        printf("MQTT Message: Done\n");
    }
    
    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

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
    time_t ping_time;
    
    /* Initialize MQTTCtx */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.app_name = "websocket_client";
    mqttCtx.host = host;
    mqttCtx.port = port;
    mqttCtx.client_id = client_id;
    
    /* Parse arguments */
    rc = mqtt_parse_args(&mqttCtx, argc, argv);
    if (rc != 0) {
        return rc;
    }
    
    /* Update host and port if provided as arguments */
    if (mqttCtx.host) {
        host = mqttCtx.host;
    }
    if (mqttCtx.port) {
        port = mqttCtx.port;
    }
    
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
    rc = MqttClient_Init(&client, &mqttNet, mqtt_message_cb, 
        tx_buf, MAX_BUFFER_SIZE, 
        rx_buf, MAX_BUFFER_SIZE, 
        5000);
    if (rc != MQTT_CODE_SUCCESS) {
        printf("MqttClient_Init failed: %d\n", rc);
        goto exit;
    }
    
    /* Connect to broker */
    printf("Connecting to %s:%d%s\n", host, port, mqttCtx.use_tls ? " (TLS)" : "");
    rc = MqttClient_NetConnect(&client, host, port, 5000, mqttCtx.use_tls, mqtt_tls_cb);
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
    printf("Press Ctrl+C to quit\n");
    signal(SIGINT, sig_handler);
    
    /* Initialize ping timer */
    ping_time = time(NULL);
    
    while (!mStopRead) {
        /* Check if it's time to send a ping */
        time_t current_time = time(NULL);
        if (current_time - ping_time >= PING_TIMEOUT_SEC) {
            printf("Sending ping to broker\n");
            rc = MqttClient_Ping(&client);
            if (rc != MQTT_CODE_SUCCESS) {
                printf("MqttClient_Ping failed: %d\n", rc);
                break;
            }
            ping_time = current_time; /* Reset ping timer */
        }
        
        /* Try receiving with a shorter timeout to allow for ping checks */
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

