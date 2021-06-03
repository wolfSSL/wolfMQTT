/* multithread.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
#include "examples/mqttexample.h"

#include <stdint.h>


/* Configuration */

/* Maximum size for network read/write callbacks. There is also a v5 define that
   describes the max MQTT control packet size, DEFAULT_MAX_PKT_SZ. */
#define MAX_BUFFER_SIZE 1024
#define TEST_MESSAGE    "test00"
/* Number of publish tasks. Each will send a unique message to the broker. */
#define NUM_PUB_TASKS   10


/* Locals */
static int mStopRead = 0;
static int mNumMsgsRecvd;

#ifdef WOLFMQTT_MULTITHREAD

#ifdef USE_WINDOWS_API
    /* Windows Threading */
	#include <windows.h>
    #include <process.h>
    typedef HANDLE THREAD_T;
    #define THREAD_CREATE(h, f, c) ((*h = CreateThread(NULL, 0, f, c, 0, NULL)) == NULL)
    #define THREAD_JOIN(h, c)      WaitForMultipleObjects(c, h, TRUE, INFINITE)
    #define THREAD_EXIT(e)         ExitThread(e)
#else
    /* Posix (Linux/Mac) */
	#include <pthread.h>
	#include <sched.h>
    typedef pthread_t THREAD_T;
    #define THREAD_CREATE(h, f, c) ({ int ret = pthread_create(h, NULL, f, c); if (ret) { errno = ret; } ret; })
    #define THREAD_JOIN(h, c)      ({ int ret, x; for(x=0;x<c;x++) { ret = pthread_join(h[x], NULL); if (ret) { errno = ret; break; }} ret; })
    #define THREAD_EXIT(e)         pthread_exit((void*)e)
#endif

static wm_Sem mtLock; /* Protect "packetId" and "stop" */
static wm_Sem pingSignal;

static MQTTCtx gMqttCtx;

static word16 mqtt_get_packetid_threadsafe(void)
{
    word16 packet_id;
    wm_SemLock(&mtLock);
    packet_id = mqtt_get_packetid();
    wm_SemUnlock(&mtLock);
    return packet_id;
}

static void mqtt_stop_set(void)
{
    wm_SemLock(&mtLock);
    mStopRead = 1;
    wm_SemUnlock(&mtLock);
}

static int mqtt_stop_get(void)
{
    int rc;
    wm_SemLock(&mtLock);
    rc = mStopRead;
    wm_SemUnlock(&mtLock);
    return rc;
}

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

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
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
        PRINTF("MQTT Message: Topic %s, Qos %d, Id %d, Len %u",
            buf, msg->qos, msg->packet_id, msg->total_len);

        /* for test mode: count the number of TEST_MESSAGE matches received */
        if (mqttCtx->test_mode) {
            if (XSTRLEN(TEST_MESSAGE) == msg->buffer_len &&
                /* Only compare the "test" part */
                XSTRNCMP(TEST_MESSAGE, (char*)msg->buffer,
                         msg->buffer_len-2) == 0)
            {
                mNumMsgsRecvd++;
                if (mNumMsgsRecvd == NUM_PUB_TASKS) {
                    mqtt_stop_set();
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

static void client_cleanup(MQTTCtx *mqttCtx)
{
    /* Free resources */
    if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
    if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&mqttCtx->net);

    MqttClient_DeInit(&mqttCtx->client);
}

WOLFMQTT_NORETURN static void client_exit(MQTTCtx *mqttCtx)
{
    client_cleanup(mqttCtx);
    exit(1);
}

static void client_disconnect(MQTTCtx *mqttCtx)
{
    int rc;

    do {
        /* Disconnect */
        rc = MqttClient_Disconnect_ex(&mqttCtx->client,
               &mqttCtx->disconnect);
    } while (rc == MQTT_CODE_CONTINUE);

    PRINTF("MQTT Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    rc = MqttClient_NetDisconnect(&mqttCtx->client);

    PRINTF("MQTT Socket Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    client_cleanup(mqttCtx);
}

static int multithread_test_init(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS;

    mNumMsgsRecvd = 0;

    /* Create a demo mutex for making packet id values */
    rc = wm_SemInit(&mtLock);
    if (rc != 0) {
        client_exit(mqttCtx);
    }
    rc = wm_SemInit(&pingSignal);
    if (rc != 0) {
        wm_SemFree(&mtLock);
        client_exit(mqttCtx);
    }
    wm_SemLock(&pingSignal); /* default to locked */

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
    do {
        rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
    } while (rc == MQTT_CODE_CONTINUE || rc == MQTT_CODE_STDIN_WAKE);

    PRINTF("MQTT Connect: Proto (%s), %s (%d)",
        MqttClient_GetProtocolVersionString(&mqttCtx->client),
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

    wm_SemFree(&pingSignal);
    wm_SemFree(&mtLock);

    return mqttCtx->return_code;
}

/* this task subscribes to topic */
#ifdef USE_WINDOWS_API
static DWORD WINAPI subscribe_task( LPVOID param ) 
#else
static void *subscribe_task(void *param)
#endif
{
    int rc = MQTT_CODE_SUCCESS;
    uint16_t i;
    MQTTCtx *mqttCtx = (MQTTCtx*)param;

    /* Build list of topics */
    XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
    i = 0;
    mqttCtx->topics[i].topic_filter = mqttCtx->topic_name;
    mqttCtx->topics[i].qos = mqttCtx->qos;

#ifdef WOLFMQTT_V5
    if (mqttCtx->subId_not_avail != 1) {
        /* Subscription Identifier */
        MqttProp* prop;
        mqttCtx->topics[i].sub_id = i + 1; /* Sub ID starts at 1 */
        prop = MqttClient_PropsAdd(&mqttCtx->subscribe.props);
        prop->type = MQTT_PROP_SUBSCRIPTION_ID;
        prop->data_int = mqttCtx->topics[i].sub_id;
    }
#endif

    /* Subscribe Topic */
    mqttCtx->subscribe.packet_id = mqtt_get_packetid_threadsafe();
    mqttCtx->subscribe.topic_count =
            sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->subscribe.topics = mqttCtx->topics;

    rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);

    PRINTF("MQTT Subscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    if (rc == MQTT_CODE_SUCCESS) {
        /* show subscribe results */
        for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
            MqttTopic *topic = &mqttCtx->subscribe.topics[i];
            PRINTF("  Topic %s, Qos %u, Return Code %u",
                topic->topic_filter,
                topic->qos, topic->return_code);
        }
    }

#ifdef WOLFMQTT_V5
    if (mqttCtx->subscribe.props != NULL) {
        MqttClient_PropsFree(mqttCtx->subscribe.props);
    }
#endif

    THREAD_EXIT(0);
}

/* This task waits for messages */
#ifdef USE_WINDOWS_API
static DWORD WINAPI waitMessage_task( LPVOID param ) 
#else
static void *waitMessage_task(void *param)
#endif
{
    int rc;
    MQTTCtx *mqttCtx = (MQTTCtx*)param;

    /* Read Loop */
    PRINTF("MQTT Waiting for message...");

    do {
        /* Try and read packet */
        rc = MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);

        /* check for test mode */
        if (mqtt_stop_get()) {
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
                mqttCtx->publish.topic_name = mqttCtx->topic_name;
                mqttCtx->publish.packet_id = mqtt_get_packetid_threadsafe();
                mqttCtx->publish.buffer = mqttCtx->rx_buf;
                mqttCtx->publish.total_len = (word16)rc;
                rc = MqttClient_Publish(&mqttCtx->client,
                       &mqttCtx->publish);
                PRINTF("MQTT Publish: Topic %s, %s (%d)",
                    mqttCtx->publish.topic_name,
                    MqttClient_ReturnCodeToString(rc), rc);
            }
        }
    #endif
        else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            if (mqttCtx->test_mode) {
                /* timeout in test mode should exit */
                PRINTF("MQTT Exiting timeout...");
                break;
            }

            /* Keep Alive handled in ping thread */
            /* Signal keep alive thread */
            wm_SemUnlock(&pingSignal);
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            /* There was an error */
            PRINTF("MQTT Message Wait Error: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while (!mqtt_stop_get());

    mqttCtx->return_code = rc;
    wm_SemUnlock(&pingSignal); /* wake ping thread */

    THREAD_EXIT(0);
}

/* This task publishes a message to the broker. The task will be created
   NUM_PUB_TASKS times, sending a unique message each time. */
#ifdef USE_WINDOWS_API
static DWORD WINAPI publish_task( LPVOID param ) 
#else
static void *publish_task(void *param)
#endif
{
    int rc;
    char buf[7];
    MQTTCtx *mqttCtx = (MQTTCtx*)param;
    MqttPublish publish;

    /* Publish Topic */
    XMEMSET(&publish, 0, sizeof(MqttPublish));
    publish.retain = 0;
    publish.qos = mqttCtx->qos;
    publish.duplicate = 0;
    publish.topic_name = mqttCtx->topic_name;
    publish.packet_id = mqtt_get_packetid_threadsafe();
    XSTRNCPY(buf, TEST_MESSAGE, sizeof(buf));
    buf[4] = '0' + ((publish.packet_id / 10) % 10);
    buf[5] = '0' + (publish.packet_id % 10);
    publish.buffer = (byte*)buf;
    publish.total_len = (word16)XSTRLEN(buf);

    rc = MqttClient_Publish(&mqttCtx->client, &publish);

    PRINTF("MQTT Publish: Topic %s, %s (%d)",
        publish.topic_name,
        MqttClient_ReturnCodeToString(rc), rc);

    THREAD_EXIT(0);
}

#ifdef USE_WINDOWS_API
static DWORD WINAPI ping_task( LPVOID param ) 
#else
static void *ping_task(void *param)
#endif
{
    int rc;
    MQTTCtx *mqttCtx = (MQTTCtx*)param;
    MqttPing ping;

    XMEMSET(&ping, 0, sizeof(ping));

    do {
        wm_SemLock(&pingSignal);
        if (mqtt_stop_get())
            break;

        /* Keep Alive Ping */
        PRINTF("Sending ping keep-alive");

        rc = MqttClient_Ping_ex(&mqttCtx->client, &ping);
        if (rc != MQTT_CODE_SUCCESS) {
            PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while (!mqtt_stop_get());

    THREAD_EXIT(0);
}

static int unsubscribe_do(MQTTCtx *mqttCtx)
{
    int rc;

    /* Unsubscribe Topics */
    XMEMSET(&mqttCtx->unsubscribe, 0, sizeof(MqttUnsubscribe));
    mqttCtx->unsubscribe.packet_id = mqtt_get_packetid_threadsafe();
    mqttCtx->unsubscribe.topic_count =
        sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->unsubscribe.topics = mqttCtx->topics;

    /* Unsubscribe Topics */
    rc = MqttClient_Unsubscribe(&mqttCtx->client,
           &mqttCtx->unsubscribe);

    PRINTF("MQTT Unsubscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    return rc;
}

int multithread_test(MQTTCtx *mqttCtx)
{
    int rc = 0;
    int i;
    THREAD_T threadList[NUM_PUB_TASKS+3];
    int threadCount = 0;

    rc = multithread_test_init(mqttCtx);
    if (rc == 0) {
        if (THREAD_CREATE(&threadList[threadCount++], subscribe_task, mqttCtx)) {
            PRINTF("THREAD_CREATE failed: %d\n", errno);
            return -1;
        }
        /* for test mode, we must complete subscribe to track number of pubs received */
        if (mqttCtx->test_mode) {
            if (THREAD_JOIN(threadList, threadCount)) {
                PRINTF("THREAD_JOIN failed: %d\n", errno);
                return -1;
            }
            threadCount = 0;
        }
        /* Create the thread that waits for messages */
        if (THREAD_CREATE(&threadList[threadCount++], waitMessage_task, mqttCtx)) {
            PRINTF("THREAD_CREATE failed: %d\n", errno);
            return -1;
        }
        /* Ping */
        if (THREAD_CREATE(&threadList[threadCount++], ping_task, mqttCtx)) {
            PRINTF("THREAD_CREATE failed: %d\n", errno);
            return -1;
        }
        /* Create threads that publish unique messages */
        for (i = 0; i < NUM_PUB_TASKS; i++) {
            if (THREAD_CREATE(&threadList[threadCount++], publish_task, mqttCtx)) {
                PRINTF("THREAD_CREATE failed: %d\n", errno);
                return -1;
            }
        }
        
        /* Join threads - wait for completion */
        if (THREAD_JOIN(threadList, threadCount)) {
#ifdef __GLIBC__
            PRINTF("THREAD_JOIN failed: %m\n"); /* %m is specific to glibc/uclibc/musl, and recently (2018) added to FreeBSD */
#else
            PRINTF("THREAD_JOIN failed: %d\n",errno);
#endif
        }

        (void)unsubscribe_do(mqttCtx);

        rc = multithread_test_finish(mqttCtx);
    }
    return rc;
}
#endif /* WOLFMQTT_MULTITHREAD */

/* so overall tests can pull in test function */
#if !defined(NO_MAIN_DRIVER) && !defined(MICROCHIP_MPLAB_HARMONY)
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
                mqtt_stop_set();
                PRINTF("Received Ctrl+c");
            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
                MqttClientNet_Wake(&gMqttCtx.net);
            #endif
                return TRUE;
            }
            return FALSE;
        }
    #elif HAVE_SIGNAL
        #include <signal.h>
        static void sig_handler(int signo)
        {
            if (signo == SIGINT) {
                mqtt_stop_set();
                PRINTF("Received SIGINT");
            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
                MqttClientNet_Wake(&gMqttCtx.net);
            #endif
            }
        }
    #endif

int main(int argc, char** argv)
{
    int rc;
#ifdef WOLFMQTT_MULTITHREAD
    /* init defaults */
    mqtt_init_ctx(&gMqttCtx);
    gMqttCtx.app_name = "wolfMQTT multithread client";

    /* parse arguments */
    rc = mqtt_parse_args(&gMqttCtx, argc, argv);
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
#ifdef WOLFMQTT_MULTITHREAD
    rc = multithread_test(&gMqttCtx);

    mqtt_free_ctx(&gMqttCtx);
#else
    (void)argc;
    (void)argv;

    /* This example requires multithread mode to be enabled
       ./configure --enable-mt */
    PRINTF("Example not compiled in!");
    rc = 0; /* return success, so make check passes with TLS disabled */
#endif /* WOLFMQTT_MULTITHREAD */

    return (rc == 0) ? 0 : EXIT_FAILURE;
}

#endif /* NO_MAIN_DRIVER */
