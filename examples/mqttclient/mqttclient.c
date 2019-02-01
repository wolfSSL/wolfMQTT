/* mqttclient.c
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

#include "mqttclient.h"
#include "examples/mqttnet.h"

/* Locals */
static int mStopRead = 0;

/* Configuration */

/* Maximum size for network read/write callbacks. There is also a v5 define that
   describes the max MQTT control packet size, DEFAULT_MAX_PKT_SZ. */
#define MAX_BUFFER_SIZE 1024
#define TEST_MESSAGE    "test"

#ifdef WOLFMQTT_PROPERTY_CB
#define MAX_CLIENT_ID_LEN 64
char gClientId[MAX_CLIENT_ID_LEN] = {0};
#endif

#ifdef WOLFMQTT_DISCONNECT_CB
static int mqtt_disconnect_cb(MqttClient* client, int error_code, void* ctx)
{
    (void)client;
    (void)ctx;
    PRINTF("Disconnect (error %d)", error_code);
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
        PRINTF("MQTT Message: Topic %s, Qos %d, Len %u",
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
    PRINTF("Payload (%d - %d): %s",
        msg->buffer_pos, msg->buffer_pos + len, buf);

    if (msg_done) {
        PRINTF("MQTT Message: Done");
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_PROPERTY_CB
/* The property callback is called after decoding a packet that contains at
   least one property. The property list is deallocated after returning from
   the callback. */
static int mqtt_property_cb(MqttClient *client, MqttProp *head, void *ctx)
{
    MqttProp *prop = head;
    int rc = 0;
    MQTTCtx* mqttCtx;

    if ((client == NULL) || (client->ctx == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    mqttCtx = (MQTTCtx*)client->ctx;

    while (prop != NULL)
    {
        switch (prop->type)
        {
            case MQTT_PROP_ASSIGNED_CLIENT_ID:
                /* Store client ID in global */
                mqttCtx->client_id = &gClientId[0];

                /* Store assigned client ID from CONNACK*/
                XSTRNCPY((char*)mqttCtx->client_id,
                        prop->data_str.str,
                        MAX_CLIENT_ID_LEN);
                break;

            case MQTT_PROP_SUBSCRIPTION_ID_AVAIL:
                mqttCtx->subId_not_avail =
                        prop->data_byte == 0;
                break;

            case MQTT_PROP_TOPIC_ALIAS_MAX:
                mqttCtx->topic_alias_max =
                 (mqttCtx->topic_alias_max < prop->data_short) ?
                 mqttCtx->topic_alias_max : prop->data_short;
                break;

            case MQTT_PROP_MAX_PACKET_SZ:
                if ((prop->data_int > 0) &&
                    (prop->data_int <= MQTT_PACKET_SZ_MAX))
                {
                    client->packet_sz_max =
                        (client->packet_sz_max < prop->data_int) ?
                         client->packet_sz_max : prop->data_int;
                }
                else {
                    /* Protocol error */
                    rc = MQTT_CODE_ERROR_PROPERTY;
                }
                break;

            case MQTT_PROP_SERVER_KEEP_ALIVE:
                mqttCtx->keep_alive_sec = prop->data_short;
                break;

            case MQTT_PROP_MAX_QOS:
                client->max_qos = prop->data_byte;
                break;

            case MQTT_PROP_RETAIN_AVAIL:
                client->retain_avail = prop->data_byte;
                break;

            case MQTT_PROP_REASON_STR:
                PRINTF("Reason String: %s", prop->data_str.str);
                break;

            case MQTT_PROP_PLAYLOAD_FORMAT_IND:
            case MQTT_PROP_MSG_EXPIRY_INTERVAL:
            case MQTT_PROP_CONTENT_TYPE:
            case MQTT_PROP_RESP_TOPIC:
            case MQTT_PROP_CORRELATION_DATA:
            case MQTT_PROP_SUBSCRIPTION_ID:
            case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
            case MQTT_PROP_TOPIC_ALIAS:
            case MQTT_PROP_TYPE_MAX:
            case MQTT_PROP_RECEIVE_MAX:
            case MQTT_PROP_USER_PROP:
            case MQTT_PROP_WILDCARD_SUB_AVAIL:
            case MQTT_PROP_SHARED_SUBSCRIPTION_AVAIL:
            case MQTT_PROP_RESP_INFO:
            case MQTT_PROP_SERVER_REF:
            case MQTT_PROP_AUTH_METHOD:
            case MQTT_PROP_AUTH_DATA:
                break;
            case MQTT_PROP_REQ_PROB_INFO:
            case MQTT_PROP_WILL_DELAY_INTERVAL:
            case MQTT_PROP_REQ_RESP_INFO:
            case MQTT_PROP_NONE:
            default:
                /* Invalid */
                rc = MQTT_CODE_ERROR_PROPERTY;
                break;
        }
        prop = prop->next;
    }

    (void)ctx;

    return rc;
}
#endif

int mqttclient_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;

    PRINTF("MQTT Client: QoS %d, Use TLS %d", mqttCtx->qos,
            mqttCtx->use_tls);

    /* Initialize Network */
    rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
    PRINTF("MQTT Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
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
        goto exit;
    }
    /* The client.ctx will be stored in the cert callback ctx during
       MqttSocket_Connect for use by mqtt_tls_verify_cb */
    mqttCtx->client.ctx = mqttCtx;

#ifdef WOLFMQTT_DISCONNECT_CB
    /* setup disconnect callback */
    rc = MqttClient_SetDisconnectCallback(&mqttCtx->client,
        mqtt_disconnect_cb, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
#endif
#ifdef WOLFMQTT_PROPERTY_CB
    rc = MqttClient_SetPropertyCallback(&mqttCtx->client,
            mqtt_property_cb, NULL);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }
#endif

    /* Connect to broker */
    rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
           mqttCtx->port,
        DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqtt_tls_cb);

    PRINTF("MQTT Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
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
#ifdef WOLFMQTT_V5
    mqttCtx->client.packet_sz_max = mqttCtx->max_packet_size;
    mqttCtx->client.enable_eauth = mqttCtx->enable_eauth;

    if (mqttCtx->client.enable_eauth == 1)
    {
        /* Enhanced authentication */
        /* Add property: Authentication Method */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_AUTH_METHOD;
        prop->data_str.str = (char*)DEFAULT_AUTH_METHOD;
        prop->data_str.len = (word16)XSTRLEN(prop->data_str.str);
    }
    {
        /* Request Response Information */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_REQ_RESP_INFO;
        prop->data_byte = 1;
    }
    {
        /* Request Problem Information */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_REQ_PROB_INFO;
        prop->data_byte = 1;
    }
    {
        /* Maximum Packet Size */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_MAX_PACKET_SZ;
        prop->data_int = (word32)mqttCtx->max_packet_size;
    }
    {
        /* Topic Alias Maximum */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->connect.props);
        prop->type = MQTT_PROP_TOPIC_ALIAS_MAX;
        prop->data_short = mqttCtx->topic_alias_max;
    }
#endif

    /* Send Connect and wait for Connect Ack */
    rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);

    PRINTF("MQTT Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

#ifdef WOLFMQTT_V5
    if (mqttCtx->connect.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(mqttCtx->connect.props);
    }
#endif

    /* Validate Connect Ack info */
    PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
        mqttCtx->connect.ack.return_code,
        (mqttCtx->connect.ack.flags &
            MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
            1 : 0
    );

#ifdef WOLFMQTT_PROPERTY_CB
        /* Print the acquired client ID */
        PRINTF("MQTT Connect Ack: Assigned Client ID: %s",
                mqttCtx->client_id);
#endif

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
    mqttCtx->subscribe.stat = MQTT_MSG_BEGIN;
    mqttCtx->subscribe.packet_id = mqtt_get_packetid();
    mqttCtx->subscribe.topic_count =
            sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->subscribe.topics = mqttCtx->topics;

    rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);

#ifdef WOLFMQTT_V5
    if (mqttCtx->subscribe.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(mqttCtx->subscribe.props);
    }
#endif

    PRINTF("MQTT Subscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    /* show subscribe results */
    for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
        mqttCtx->topic = &mqttCtx->subscribe.topics[i];
        PRINTF("  Topic %s, Qos %u, Return Code %u",
            mqttCtx->topic->topic_filter,
            mqttCtx->topic->qos, mqttCtx->topic->return_code);
    }

    /* Publish Topic */
    XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
    mqttCtx->publish.retain = 0;
    mqttCtx->publish.qos = mqttCtx->qos;
    mqttCtx->publish.duplicate = 0;
    mqttCtx->publish.topic_name = mqttCtx->topic_name;
    mqttCtx->publish.packet_id = mqtt_get_packetid();
    mqttCtx->publish.buffer = (byte*)TEST_MESSAGE;
    mqttCtx->publish.total_len = (word16)XSTRLEN(TEST_MESSAGE);
#ifdef WOLFMQTT_V5
    {
        /* Payload Format Indicator */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->publish.props);
        prop->type = MQTT_PROP_PLAYLOAD_FORMAT_IND;
        prop->data_int = 1;
    }
    {
        /* Content Type */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->publish.props);
        prop->type = MQTT_PROP_CONTENT_TYPE;
        prop->data_str.str = (char*)"wolf_type";
        prop->data_str.len = (word16)XSTRLEN(prop->data_str.str);
    }
    if ((mqttCtx->topic_alias_max > 0) &&
        (mqttCtx->topic_alias > 0) &&
        (mqttCtx->topic_alias < mqttCtx->topic_alias_max)) {
        /* Topic Alias */
        MqttProp* prop = MqttClient_PropsAdd(&mqttCtx->publish.props);
        prop->type = MQTT_PROP_TOPIC_ALIAS;
        prop->data_short = mqttCtx->topic_alias;
    }
#endif

    rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);

    PRINTF("MQTT Publish: Topic %s, %s (%d)",
        mqttCtx->publish.topic_name,
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }
#ifdef WOLFMQTT_V5
    if (mqttCtx->connect.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(mqttCtx->publish.props);
    }
#endif

    /* Read Loop */
    PRINTF("MQTT Waiting for message...");

    do {
        /* Try and read packet */
        rc = MqttClient_WaitMessage(&mqttCtx->client,
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
                mqttCtx->publish.topic_name = mqttCtx->topic_name;
                mqttCtx->publish.packet_id = mqtt_get_packetid();
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
    } while (1);

    /* Check for error */
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }

    /* Unsubscribe Topics */
    XMEMSET(&mqttCtx->unsubscribe, 0, sizeof(MqttUnsubscribe));
    mqttCtx->unsubscribe.packet_id = mqtt_get_packetid();
    mqttCtx->unsubscribe.topic_count =
        sizeof(mqttCtx->topics) / sizeof(MqttTopic);
    mqttCtx->unsubscribe.topics = mqttCtx->topics;

    /* Unsubscribe Topics */
    rc = MqttClient_Unsubscribe(&mqttCtx->client,
           &mqttCtx->unsubscribe);

    PRINTF("MQTT Unsubscribe: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto disconn;
    }
    mqttCtx->return_code = rc;

disconn:
    /* Disconnect */
    rc = MqttClient_Disconnect_ex(&mqttCtx->client,
           &mqttCtx->disconnect);

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
#ifndef WOLFMQTT_NONBLOCK
    MQTTCtx mqttCtx;

    /* init defaults */
    mqtt_init_ctx(&mqttCtx);
    mqttCtx.app_name = "mqttclient";

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

#ifndef WOLFMQTT_NONBLOCK
    rc = mqttclient_test(&mqttCtx);
#else
    (void)argc;
    (void)argv;

    /* This example requires non-blocking mode to be disabled
       ./configure --disable-nonblock */
    PRINTF("Example not compiled in!");
    rc = EXIT_FAILURE;
#endif


    return (rc == 0) ? 0 : EXIT_FAILURE;
}

#endif /* NO_MAIN_DRIVER */
