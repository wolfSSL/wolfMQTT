/* sn-multithread.c
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
#include "examples/mqttexample.h"

#include <stdint.h>


/* Configuration */

/* Maximum size for network read/write callbacks. */
#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE 1024
#endif
#define TEST_MESSAGE    "test00"
/* Number of publish tasks. Each will send a unique message to the broker. */
#define NUM_PUB_TASKS   10

/* Locals */
static int mStopRead = 0;


#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_SN)

/* Locals */
static int mNumMsgsRecvd;
static word16 topicID;


#ifdef USE_WINDOWS_API
    /* Windows Threading */
    #include <windows.h>
    #include <process.h>
    typedef HANDLE THREAD_T;
    #define THREAD_CREATE(h, f, c) *h = CreateThread(NULL, 0, f, c, 0, NULL)
    #define THREAD_JOIN(h, c)      WaitForMultipleObjects(c, h, TRUE, INFINITE)
    #define THREAD_EXIT(e)         return e;
#else
    /* Posix (Linux/Mac) */
    #include <pthread.h>
    #include <sched.h>
    typedef pthread_t THREAD_T;
    #define THREAD_CREATE(h, f, c) ({ int ret = pthread_create(h, NULL, f, c); if (ret) { errno = ret; } ret; })
    #define THREAD_JOIN(h, c)      ({ int ret, x; for(x=0;x<c;x++) { ret = pthread_join(h[x], NULL); if (ret) { errno = ret; break; }} ret; })
    #define THREAD_EXIT(e)         pthread_exit((void*)e)
#endif

static wm_Sem packetIdLock; /* Protect access to mqtt_get_packetid() */
static wm_Sem pingSignal;

static MQTTCtx gMqttCtx;

static word16 mqtt_get_packetid_threadsafe(void)
{
    word16 packet_id = 0;
    if (wm_SemLock(&packetIdLock) == 0) {
        packet_id = mqtt_get_packetid();
        wm_SemUnlock(&packetIdLock);
    }
    return packet_id;
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

static int sn_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;
    word16 topicId;
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

    if (msg_new) {
        /* Topic ID or short topic name */
        topicId = (word16)(msg->topic_name[0] << 8 | msg->topic_name[1]);

        /* Print incoming message */
        PRINTF("MQTT-SN Message: Topic ID %d, Qos %d, Id %d, Len %u",
                topicId, msg->qos, msg->packet_id, msg->total_len);

        /* for test mode: count the number of TEST_MESSAGE matches received */
        if (mqttCtx != NULL && mqttCtx->test_mode) {
            if (XSTRLEN(TEST_MESSAGE) == msg->buffer_len &&
                /* Only compare the "test" part */
                XSTRNCMP(TEST_MESSAGE, (char*)msg->buffer,
                         msg->buffer_len-2) == 0)
            {
                mNumMsgsRecvd++;
                if (mNumMsgsRecvd == NUM_PUB_TASKS) {
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
    PRINTF("........Payload (%d - %d): %s",
        msg->buffer_pos, msg->buffer_pos + len, buf);

    if (msg_done) {
        PRINTF("....MQTT-SN Message: Done");
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
    SN_Disconnect disconnect;

    XMEMSET(&disconnect, 0, sizeof(SN_Disconnect));
    do {
        /* Disconnect */
        rc = SN_Client_Disconnect_ex(&mqttCtx->client, &disconnect);
    } while (rc == MQTT_CODE_CONTINUE);

    PRINTF("MQTT Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    rc = MqttClient_NetDisconnect(&mqttCtx->client);

    PRINTF("MQTT Socket Disconnect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);

    client_cleanup(mqttCtx);
}

/* The Register callback is used when the gateway
   assigns a new topic ID to a topic name. */
static int sn_reg_callback(word16 topicId, const char* topicName, void *ctx)
{
    PRINTF("MQTT-SN Register CB: New topic ID: %d : \"%s\"", topicId, topicName);
    (void)ctx;

    return(MQTT_CODE_SUCCESS);
}

static int client_register(MQTTCtx *mqttCtx)
{
    int rc;
    SN_Register regist;

    /* Set the Register callback used when the gateway
       assigns a new topic ID to a topic name. */
    rc = SN_Client_SetRegisterCallback(&mqttCtx->client, sn_reg_callback, NULL);
    PRINTF("MQTT-SN Set Register Callback: rc = %d", rc);
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(&regist, 0, sizeof(SN_Register));
        regist.packet_id = mqtt_get_packetid_threadsafe();
        regist.topicName = DEFAULT_TOPIC_NAME;

        PRINTF("MQTT-SN Register: topic = %s", regist.topicName);

        /* Register topic name to get the assigned topic ID */
        rc = SN_Client_Register(&mqttCtx->client, &regist);

        if ((rc == 0) && (regist.regack.return_code == SN_RC_ACCEPTED)) {
            /* Topic ID is returned in RegAck */
            topicID = regist.regack.topicId;
        }
        PRINTF("....MQTT-SN Register Ack: rc = %d, topic id = %d",
                regist.regack.return_code, regist.regack.topicId);
    }
    return rc;
}

static int multithread_test_init(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS;
    SN_Connect connect;

    mNumMsgsRecvd = 0;

    /* Create a demo mutex for making packet id values */
    rc = wm_SemInit(&packetIdLock);
    if (rc != 0) {
        client_exit(mqttCtx);
    }
    rc = wm_SemInit(&pingSignal);
    if (rc != 0) {
        wm_SemFree(&packetIdLock);
        client_exit(mqttCtx);
    }
    if (wm_SemLock(&pingSignal) != 0) { /* default to locked */
        client_exit(mqttCtx);
    }

    PRINTF("MQTT-SN Client: QoS %d, Use TLS %d", mqttCtx->qos,
            mqttCtx->use_tls);

    PRINTF("Use \"Ctrl+c\" to exit.");

    /* Initialize Network */
    rc = SN_ClientNet_Init(&mqttCtx->net, mqttCtx);
    PRINTF("MQTT-SN Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        client_exit(mqttCtx);
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
    XMEMSET(&connect, 0, sizeof(SN_Connect));
    connect.keep_alive_sec = mqttCtx->keep_alive_sec;
    connect.clean_session = mqttCtx->clean_session;
    connect.client_id = mqttCtx->client_id;
    connect.protocol_level = SN_PROTOCOL_ID;

    /* Last will and testament sent by broker to subscribers
        of topic when broker connection is lost */
    connect.enable_lwt = mqttCtx->enable_lwt;
    if (connect.enable_lwt) {
        /* Send client id in LWT payload */
        connect.will.qos = mqttCtx->qos;
        connect.will.retain = 0;
        connect.will.willTopic = WOLFMQTT_TOPIC_NAME"lwttopic";
        connect.will.willMsg = (byte*)mqttCtx->client_id;
        connect.will.willMsgLen =
          (word16)XSTRLEN(mqttCtx->client_id);
    }

    /* Send Connect and wait for Connect Ack */
    do {
        rc = SN_Client_Connect(&mqttCtx->client, &connect);
    } while (rc == MQTT_CODE_CONTINUE || rc == MQTT_CODE_STDIN_WAKE);

    PRINTF("MQTT-SN Connect return code: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        client_disconnect(mqttCtx);
    }

    /* Validate Connect Ack info */
    PRINTF("....MQTT-SN Connect Ack: %u",
            connect.ack.return_code);

    return rc;
}

static int multithread_test_finish(MQTTCtx *mqttCtx)
{
    client_disconnect(mqttCtx);

    wm_SemFree(&pingSignal);
    wm_SemFree(&packetIdLock);

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
    MQTTCtx *mqttCtx = (MQTTCtx*)param;
    SN_Subscribe subscribe;

    XMEMSET(&subscribe, 0, sizeof(SN_Subscribe));

    /* Subscribe to wildcard topic so register callback can be used */
    subscribe.duplicate = 0;
    subscribe.qos = MQTT_QOS_0;
    subscribe.topic_type = SN_TOPIC_ID_TYPE_NORMAL;
    subscribe.topicNameId = WOLFMQTT_TOPIC_NAME"#";
    subscribe.packet_id = mqtt_get_packetid_threadsafe();

    PRINTF("MQTT-SN Subscribe: topic name = %s", subscribe.topicNameId);
    rc = SN_Client_Subscribe(&mqttCtx->client, &subscribe);

    PRINTF("....MQTT-SN Subscribe Ack: topic id = %d, rc = %d",
            subscribe.subAck.topicId, (rc != 0) ? rc : subscribe.subAck.return_code);

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
    PRINTF("MQTT-SN Waiting for message...");

    do {
        /* Try and read packet */
        rc = SN_Client_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);

        /* check for test mode */
        if (mStopRead) {
            rc = MQTT_CODE_SUCCESS;
            PRINTF("MQTT-SN Exiting...");
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
                PRINTF("MQTT-SN Publish: topic id = %d, rc = %d\r\nPayload = %s",
                    (word16)*mqttCtx->publishSN.topic_name,
                        mqttCtx->publishSN.return_code,
                        mqttCtx->publishSN.buffer);
            }
        }
    #endif
        else if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            if (mqttCtx->test_mode) {
                /* timeout in test mode should exit */
                PRINTF("MQTT-SN Exiting timeout...");
                break;
            }

            /* Keep Alive handled in ping thread */
            /* Signal keep alive thread */
            wm_SemUnlock(&pingSignal);
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            /* There was an error */
            PRINTF("MQTT-SN Message Wait: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while (!mStopRead);

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
    SN_Publish publish;

    /* Publish Topic */
    XMEMSET(&publish, 0, sizeof(SN_Publish));
    publish.retain = 0;
    publish.qos = mqttCtx->qos;
    publish.duplicate = 0;
    publish.topic_type = SN_TOPIC_ID_TYPE_NORMAL;

    /* Use the topic ID saved from the subscribe */
    publish.topic_name = (char*)&topicID;
    if ((publish.qos == MQTT_QOS_1) ||
        (publish.qos == MQTT_QOS_2)) {
        publish.packet_id = mqtt_get_packetid_threadsafe();
    }
    else {
        publish.packet_id = 0x00;
    }

    XSTRNCPY(buf, TEST_MESSAGE, sizeof(buf));
    buf[4] = '0' + ((publish.packet_id / 10) % 10);
    buf[5] = '0' + (publish.packet_id % 10);
    publish.buffer = (byte*)buf;
    publish.total_len = (word16)XSTRLEN(buf);

    rc = SN_Client_Publish(&mqttCtx->client, &publish);

    PRINTF("MQTT-SN Publish: topic id = %d, rc = %d\r\nPayload = %s",
        (word16)*publish.topic_name,
            rc,
            publish.buffer);

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
    SN_PingReq ping;

    XMEMSET(&ping, 0, sizeof(ping));

    do {
        if (wm_SemLock(&pingSignal) != 0)
            break;

        if (mStopRead)
            break;

        /* Keep Alive Ping */
        PRINTF("Sending ping keep-alive");

        rc = SN_Client_Ping(&mqttCtx->client, &ping);
        if (rc != MQTT_CODE_SUCCESS) {
            PRINTF("MQTT-SN Ping Error: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    } while (!mStopRead);

    THREAD_EXIT(0);
}

static int unsubscribe_do(MQTTCtx *mqttCtx)
{
    int rc;

    SN_Unsubscribe unsubscribe;

    /* Unsubscribe Topic */
    XMEMSET(&unsubscribe, 0, sizeof(SN_Unsubscribe));
    unsubscribe.topicNameId = mqttCtx->topic_name;
    unsubscribe.packet_id = mqtt_get_packetid_threadsafe();

    rc = SN_Client_Unsubscribe(&mqttCtx->client, &unsubscribe);

    PRINTF("MQTT Unsubscribe: %s (rc = %d)",
        MqttClient_ReturnCodeToString(rc), rc);

    return rc;
}

int sn_multithread_test(MQTTCtx *mqttCtx)
{
    int rc = 0;
    int i;
    THREAD_T threadList[NUM_PUB_TASKS+3];
    int threadCount = 0;

    rc = multithread_test_init(mqttCtx);
    if (rc == 0) {
        rc = client_register(mqttCtx);
    }

    if (rc == 0) {
        if (THREAD_CREATE(&threadList[threadCount++], subscribe_task, mqttCtx))
            return -1;
        /* for test mode, we must complete subscribe to track number of pubs received */
        if (mqttCtx->test_mode) {
            if (THREAD_JOIN(threadList, threadCount))
                return -1;
            threadCount = 0;
        }
        /* Create the thread that waits for messages */
        if (THREAD_CREATE(&threadList[threadCount++], waitMessage_task, mqttCtx))
            return -1;
        /* Ping */
        if (THREAD_CREATE(&threadList[threadCount++], ping_task, mqttCtx))
            return -1;
        /* Create threads that publish unique messages */
        for (i = 0; i < NUM_PUB_TASKS; i++) {
            if (THREAD_CREATE(&threadList[threadCount++], publish_task, mqttCtx))
                return -1;
        }

        /* Join threads - wait for completion */
        if (THREAD_JOIN(threadList, threadCount)) {
#ifdef __GLIBC__
            PRINTF("THREAD_JOIN failed: %m"); /* %m is specific to glibc/uclibc/musl, and recently (2018) added to FreeBSD */
#else
            PRINTF("THREAD_JOIN failed: %d",errno);
#endif
        }

        (void)unsubscribe_do(mqttCtx);

        rc = multithread_test_finish(mqttCtx);
    }
    return rc;
}
#endif /* WOLFMQTT_MULTITHREAD && WOLFMQTT_SN */

/* so overall tests can pull in test function */
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
                mStopRead = 1;
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
                mStopRead = 1;
                PRINTF("Received SIGINT");
            #if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_SN) && \
                defined(WOLFMQTT_ENABLE_STDIN_CAP)
                MqttClientNet_Wake(&gMqttCtx.net);
            #endif
            }
        }
    #endif

#if defined(NO_MAIN_DRIVER)
int sn_multithread_main(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
    int rc;
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_SN)
    /* init defaults */
    mqtt_init_ctx(&gMqttCtx);
    gMqttCtx.app_name = "wolfMQTT-SN multithread client";
    gMqttCtx.client_id = DEFAULT_CLIENT_ID"-SN-MT";

    /* Settings for MQTT-SN gateway */
    gMqttCtx.host = "localhost";
    gMqttCtx.port = 10000;

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
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_SN)
    rc = sn_multithread_test(&gMqttCtx);

    mqtt_free_ctx(&gMqttCtx);
#else
    (void)argc;
    (void)argv;

    /* This example requires multithread mode to be enabled
       ./configure --enable-mt */
    PRINTF("Example not compiled in!");
    rc = 0; /* return success, so make check passes with TLS disabled */
#endif /* WOLFMQTT_MULTITHREAD && WOLFMQTT_SN
 */

    return (rc == 0) ? 0 : EXIT_FAILURE;
}

