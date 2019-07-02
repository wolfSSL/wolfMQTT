/* multithread.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

#include "multithread.h"
#include "examples/mqttnet.h"
#ifdef WOLFMQTT_MULTITHREAD
    #include <pthread.h>
#endif

/* Locals */
static int mStopRead = 0;

#ifdef WOLFMQTT_MULTITHREAD
static wolfSSL_Mutex demoLock; /* Protect access to mqtt_get_packetid() */
#endif

/* Configuration */

/* Maximum size for network read/write callbacks. There is also a v5 define that
   describes the max MQTT control packet size, DEFAULT_MAX_PKT_SZ. */
#define MAX_BUFFER_SIZE 1024
#define TEST_MESSAGE    "test00"
/* Number of publish tasks. Each will send a unique message to the broker. */
#define NUM_PUB_TASKS   10

#ifdef WOLFMQTT_DISCONNECT_CB
/* callback indicates a network error occurred */
static int mqtt_disconnect_cb(MqttClient* client, int error_code, void* ctx)
{
    (void)client;
    (void)ctx;
    PRINTF("Network Error Callback: %s (error %d)",
        MqttClient_ReturnCodeToString(error_code), error_code);
    return 0;
}
#endif

#ifdef WOLFMQTT_MULTITHREAD
static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;
    static int num_msgs_recvd;
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
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
            buf, msg->qos, msg->total_len);

        /* for test mode: count the number of TEST_MESSAGE matches received */
        if (mqttCtx->test_mode) {
            if (XSTRLEN(TEST_MESSAGE) == msg->buffer_len &&
                /* Only compare the "test" part */
                XSTRNCMP(TEST_MESSAGE, (char*)msg->buffer,
                         msg->buffer_len-3) == 0)
            {
                num_msgs_recvd++;
                if (num_msgs_recvd == NUM_PUB_TASKS) {
                    mStopRead = 1;
                }
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
    PRINTF("Payload (%d - %d): %s",
        msg->buffer_pos, msg->buffer_pos + len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

static void client_exit(MQTTCtx *mqttCtx)
{
    /* Free resources */
    if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
    if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&mqttCtx->net);

    MqttClient_DeInit(&mqttCtx->client);
}

static void client_disconnect(MQTTCtx *mqttCtx)
{
    int rc;

    do {
        /* Disconnect */
        rc = MqttClient_Disconnect_ex(&mqttCtx->client,
               &mqttCtx->disconnect);

        PRINTF("MQTT Disconnect: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);
    } while (rc != MQTT_CODE_SUCCESS);

    rc = MqttClient_NetDisconnect(&mqttCtx->client);

    PRINTF("MQTT Socket Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    client_exit(mqttCtx);
}

static int multithread_test_init(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS;

    /* Create a demo mutex for making packet id values */
    rc = wc_InitMutex(&demoLock);
    if (rc != 0) {
        client_exit(mqttCtx);
    }

    PRINTF("MQTT Client: QoS %d, Use TLS %d", mqttCtx->qos,
            mqttCtx->use_tls);

    PRINTF("Use \"Ctrl+c\" to exit.");

    /* Initialize Network */
    rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
    PRINTF("MQTT Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        client_exit(mqttCtx);
    }

    /* setup tx/rx buffers */
    mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);

    /* Initialize MqttClient structure */
    rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net,
        mqtt_message_cb,
        mqttCtx->tx_buf, MAX_BUFFER_SIZE,
        mqttCtx->rx_buf, MAX_BUFFER_SIZE,
        mqttCtx->cmd_timeout_ms);

    PRINTF("MQTT Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        client_exit(mqttCtx);
    }
    /* The client.ctx will be stored in the cert callback ctx during
       MqttSocket_Connect for use by mqtt_tls_verify_cb */
    mqttCtx->client.ctx = mqttCtx;

#ifdef WOLFMQTT_DISCONNECT_CB
    /* setup disconnect callback */
    rc = MqttClient_SetDisconnectCallback(&mqttCtx->client,
        mqtt_disconnect_cb, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        client_exit(mqttCtx);
    }
#endif

    /* Connect to broker */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
           mqttCtx->port,
        DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqtt_tls_cb);

    PRINTF("MQTT Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        client_exit(mqttCtx);
    }

    /* Build connect packet */
    XMEMSET(&mqttCtx->connect, 0, sizeof(MqttConnect));
    mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
    mqttCtx->connect.clean_session = mqttCtx->clean_session;
    mqttCtx->connect.client_id = mqttCtx->client_id;

    /* Last will and testament sent by broker to subscribers
        of topic when broker connection is lost */
    XMEMSET(&mqttCtx->lwt_msg, 0, sizeof(mqttCtx->lwt_msg));
    mqttCtx->connect.lwt_msg = &mqttCtx->lwt_msg;
    mqttCtx->connect.enable_lwt = mqttCtx->enable_lwt;
    if (mqttCtx->enable_lwt) {
        /* Send client id in LWT payload */
        mqttCtx->lwt_msg.qos = mqttCtx->qos;
        mqttCtx->lwt_msg.retain = 0;
        mqttCtx->lwt_msg.topic_name = WOLFMQTT_TOPIC_NAME"lwttopic";
        mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
        mqttCtx->lwt_msg.total_len =
          (word16)XSTRLEN(mqttCtx->client_id);
    }
    /* Optional authentication */
    mqttCtx->connect.username = mqttCtx->username;
    mqttCtx->connect.password = mqttCtx->password;

    /* Send Connect and wait for Connect Ack */
    rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);

    PRINTF("MQTT Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        client_disconnect(mqttCtx);
    }

    /* Validate Connect Ack info */
    PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
        mqttCtx->connect.ack.return_code,
        (mqttCtx->connect.ack.flags &
            MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
            1 : 0
    );

    return rc;
}

static int multithread_test_finish(MQTTCtx *mqttCtx)
{
    client_disconnect(mqttCtx);
    wc_FreeMutex(&demoLock);

    return mqttCtx->return_code;
}

/* This task subscribes to a topic and waits for messages */
static void *waitMessage_task(void *param)
{
    int rc, i;
    MQTTCtx *mqttCtx = param;

    /* Build list of topics */
    XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));

    i = 0;
    mqttCtx->topics[i].topic_filter = mqttCtx->topic_name;
    mqttCtx->topics[i].qos = mqttCtx->qos;

    /* Subscribe Topic */
    mqttCtx->subscribe.stat = MQTT_MSG_BEGIN;

    /* Get the demo lock */
    wc_LockMutex(&demoLock);
    mqttCtx->subscribe.packet_id = mqtt_get_packetid();
    wc_UnLockMutex(&demoLock);

    mqttCtx->subscribe.topic_count =
            sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->subscribe.topics = mqttCtx->topics;

    rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);

    PRINTF("MQTT Subscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        client_disconnect(mqttCtx);
    }

    /* show subscribe results */
    for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
        mqttCtx->topic = &mqttCtx->subscribe.topics[i];
        PRINTF("  Topic %s, Qos %u, Return Code %u",
            mqttCtx->topic->topic_filter,
            mqttCtx->topic->qos, mqttCtx->topic->return_code);
    }

    /* Read Loop */
    PRINTF("MQTT Waiting for message...");

    do {
        /* Try and read packet */
        rc = MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);

        /* check for test mode */
        if (mStopRead) {
            PRINTF("MQTT Exiting...");
            break;
        }
        else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            /* Keep Alive */
            PRINTF("Keep-alive timeout, sending ping");

            rc = MqttClient_Ping(&mqttCtx->client);
            if (rc != MQTT_CODE_SUCCESS) {
                PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                    MqttClient_ReturnCodeToString(rc), rc);
                break;
            }
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            /* There was an error */
            PRINTF("MQTT Message Wait: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while(!mStopRead);


    /* Unsubscribe Topics */
    XMEMSET(&mqttCtx->unsubscribe, 0, sizeof(MqttUnsubscribe));

    /* Get the demo lock */
    wc_LockMutex(&demoLock);
    mqttCtx->unsubscribe.packet_id = mqtt_get_packetid();
    wc_UnLockMutex(&demoLock);

    mqttCtx->unsubscribe.topic_count =
        sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->unsubscribe.topics = mqttCtx->topics;

    /* Unsubscribe Topics */
    rc = MqttClient_Unsubscribe(&mqttCtx->client,
           &mqttCtx->unsubscribe);

    PRINTF("MQTT Unsubscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    mqttCtx->return_code = rc;

    pthread_exit(NULL);
}

/* This task publishes a message to the broker. The task will be created
   NUM_PUB_TASKS times, sending a unique message each time. */
static void *publish_task(void *param)
{
    int rc;
    char buf[7];
    MQTTCtx *mqttCtx = param;
    MqttPublish publish;

    /* Publish Topic */
    XMEMSET(&publish, 0, sizeof(MqttPublish));
    publish.retain = 0;
    publish.qos = mqttCtx->qos;
    publish.duplicate = 0;
    publish.topic_name = mqttCtx->topic_name;

    /* Get the demo lock */
    wc_LockMutex(&demoLock);
    publish.packet_id = mqtt_get_packetid();
    wc_UnLockMutex(&demoLock);

    XSTRNCPY(buf, TEST_MESSAGE, sizeof(buf));
    buf[4] = '0' + ((publish.packet_id / 10) % 10);
    buf[5] = '0' + (publish.packet_id % 10);
    publish.buffer = (byte*)buf;
    publish.total_len = (word16)XSTRLEN(buf);

    rc = MqttClient_Publish(&mqttCtx->client, &publish);

    PRINTF("MQTT Publish: Topic %s, %s (%d)",
        publish.topic_name,
        MqttClient_ReturnCodeToString(rc), rc);

    pthread_exit(NULL);
}

int multithread_test(MQTTCtx *mqttCtx)
{
    int rc = 0;
    int i;
    pthread_t waitMessage_thread;
    pthread_t publish_thread[NUM_PUB_TASKS];

    rc = multithread_test_init(mqttCtx);

    if (rc == 0) {
        /* Create the thread that waits for messages */
        pthread_create(&waitMessage_thread, NULL, waitMessage_task, mqttCtx);

        for (i = 0; i < NUM_PUB_TASKS; i++) {
            /* Create threads that publish unique messages */
            pthread_create(&publish_thread[i], NULL, publish_task, mqttCtx);
        }

        pthread_join(waitMessage_thread, NULL);

        for (i = 0; i < NUM_PUB_TASKS; i++) {
            pthread_join(publish_thread[i], NULL);
        }

        rc = multithread_test_finish(mqttCtx);
    }
    return rc;
}
#endif

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
#if defined(WOLFMQTT_MULTITHREAD) && !defined(WOLFMQTT_NONBLOCK)
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.app_name = "wolfMQTT multithread client";

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
#if defined(WOLFMQTT_MULTITHREAD) && !defined(WOLFMQTT_NONBLOCK)
    rc = multithread_test(&mqttCtx);

    return (rc == 0) ? 0 : EXIT_FAILURE;
#else
    (void)argc;
    (void)argv;

    /* This example requires multithread mode to be enabled
       ./configure --enable-mt */
    PRINTF("Example not compiled in!");
    rc = EXIT_FAILURE;
    (void) rc;
#endif
}

#endif /* NO_MAIN_DRIVER */
