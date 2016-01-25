/* mqttclient.c
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfmqtt/mqtt_client.h>
#include <wolfssl/ssl.h>
#include "mqttclient.h"
#include "mqttnet.h"
#include "mqttexample.h"

/* Globals */
int myoptind = 0;
char* myoptarg = NULL;

/* Locals */
static int mStopRead = 0;
static const char* mTlsFile = NULL;
static int mPacketIdLast;

/* Configuration */
#define DEFAULT_CLIENT_ID       "WolfMQTTClient"
#define MAX_BUFFER_SIZE         1024
#define TEST_MESSAGE            "test"

/* Usage */
static void Usage(void)
{
    PRINTF("mqttclient:");
    PRINTF("-?          Help, print this usage");
    PRINTF("-h <host>   Host to connect to, default %s",
        DEFAULT_MQTT_HOST);
    PRINTF("-p <num>    Port to connect on, default: Normal %d, TLS %d",
        MQTT_DEFAULT_PORT, MQTT_SECURE_PORT);
    PRINTF("-t          Enable TLS");
    PRINTF("-c <file>   Use provided certificate file");
    PRINTF("-q <num>    Qos Level 0-2, default %d",
        DEFAULT_MQTT_QOS);
    PRINTF("-s          Disable clean session connect flag");
    PRINTF("-k <num>    Keep alive seconds, default %d",
        DEFAULT_KEEP_ALIVE_SEC);
    PRINTF("-i <id>     Client Id, default %s",
        DEFAULT_CLIENT_ID);
    PRINTF("-l          Enable LWT (Last Will and Testament)");
    PRINTF("-u <str>    Username");
    PRINTF("-w <str>    Password");
    PRINTF("-n <str>    Topic name, default %s", DEFAULT_TOPIC_NAME);
    PRINTF("-C <num>    Command Timeout, default %dms", DEFAULT_CMD_TIMEOUT_MS);
    PRINTF("-T          Test mode");
}

static word16 mqttclient_get_packetid(void)
{
    mPacketIdLast = (mPacketIdLast >= MAX_PACKET_ID) ?
        1 : mPacketIdLast + 1;
    return (word16)mPacketIdLast;
}

static int mqttclient_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    PRINTF("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)", preverify,
        store->error, wolfSSL_ERR_error_string(store->error, buffer));
    PRINTF("  Subject's domain name is %s", store->domain);

    /* Allowing to continue */
    /* Should check certificate and return 0 if not okay */
    PRINTF("  Allowing cert anyways");

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
static int mqttclient_tls_cb(MqttClient* client)
{
    int rc = SSL_FAILURE;
    (void)client; /* Supress un-used argument */

    client->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, SSL_VERIFY_PEER, mqttclient_tls_verify_cb);

        if (mTlsFile) {
    #if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx, mTlsFile, 0);
    #else
            rc = SSL_SUCCESS;
    #endif
        }
        else {
            rc = SSL_SUCCESS;
        }
    }

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}

static int mqttclient_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

    (void)client; /* Supress un-used argument */

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

int mqttclient_test(void* args)
{
    int rc;
    MqttClient client;
    MqttNet net;
    word16 port = 0;
    const char* host = DEFAULT_MQTT_HOST;
    int use_tls = 0;
    MqttQoS qos = DEFAULT_MQTT_QOS;
    byte clean_session = 1;
    word16 keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    const char* client_id = DEFAULT_CLIENT_ID;
    int enable_lwt = 0;
    const char* username = NULL;
    const char* password = NULL;
    byte *tx_buf = NULL, *rx_buf = NULL;
    const char* topicName = DEFAULT_TOPIC_NAME;
    word32 cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
    byte test_mode = 0;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?h:p:tc:q:sk:i:lu:w:n:C:T")) != -1) {
        switch ((char)rc) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);

            case 'h' :
                host = myoptarg;
                break;

            case 'p' :
                port = (word16)XATOI(myoptarg);
                if (port == 0) {
                    return err_sys("Invalid Port Number!");
                }
                break;

            case 't':
                use_tls = 1;
                break;

            case 'c':
                mTlsFile = myoptarg;
                break;

            case 'q' :
                qos = (MqttQoS)((byte)XATOI(myoptarg));
                if (qos > MQTT_QOS_2) {
                    return err_sys("Invalid QoS value!");
                }
                break;

            case 's':
                clean_session = 0;
                break;

            case 'k':
                keep_alive_sec = XATOI(myoptarg);
                break;

            case 'i':
                client_id = myoptarg;
                break;

            case 'l':
                enable_lwt = 1;
                break;

            case 'u':
                username = myoptarg;
                break;

            case 'w':
                password = myoptarg;
                break;

            case 'n':
                topicName = myoptarg;
                break;

            case 'C':
                cmd_timeout_ms = XATOI(myoptarg);
                break;

            case 'T':
                test_mode = 1;
                break;

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0; /* reset for test cases */

    /* Start example MQTT Client */
    PRINTF("MQTT Client: QoS %d", qos);

    /* Initialize Network */
    rc = MqttClientNet_Init(&net);
    PRINTF("MQTT Net Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* Initialize MqttClient structure */
    tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rc = MqttClient_Init(&client, &net, mqttclient_message_cb,
        tx_buf, MAX_BUFFER_SIZE, rx_buf, MAX_BUFFER_SIZE,
        cmd_timeout_ms);
    PRINTF("MQTT Init: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc != MQTT_CODE_SUCCESS) {
        goto exit;
    }

    /* Connect to broker */
    rc = MqttClient_NetConnect(&client, host, port,
        DEFAULT_CON_TIMEOUT_MS, use_tls, mqttclient_tls_cb);
    PRINTF("MQTT Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc == MQTT_CODE_SUCCESS) {
        /* Define connect parameters */
        MqttConnect connect;
        MqttMessage lwt_msg;
        XMEMSET(&connect, 0, sizeof(MqttConnect));
        connect.keep_alive_sec = keep_alive_sec;
        connect.clean_session = clean_session;
        connect.client_id = client_id;
        /* Last will and testament sent by broker to subscribers
            of topic when broker connection is lost */
        XMEMSET(&lwt_msg, 0, sizeof(lwt_msg));
        connect.lwt_msg = &lwt_msg;
        connect.enable_lwt = enable_lwt;
        if (enable_lwt) {
            /* Send client id in LWT payload */
            lwt_msg.qos = qos;
            lwt_msg.retain = 0;
            lwt_msg.topic_name = WOLFMQTT_TOPIC_NAME"lwttopic";
            lwt_msg.buffer = (byte*)client_id;
            lwt_msg.total_len = (word16)XSTRLEN(client_id);
        }
        /* Optional authentication */
        connect.username = username;
        connect.password = password;

        /* Send Connect and wait for Connect Ack */
        rc = MqttClient_Connect(&client, &connect);
        PRINTF("MQTT Connect: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);
        if (rc == MQTT_CODE_SUCCESS) {
            MqttSubscribe subscribe;
            MqttUnsubscribe unsubscribe;
            MqttTopic topics[1], *topic;
            MqttPublish publish;
            int i;

            /* Build list of topics */
            topics[0].topic_filter = topicName;
            topics[0].qos = qos;

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                connect.ack.return_code,
                (connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Subscribe Topic */
            XMEMSET(&subscribe, 0, sizeof(MqttSubscribe));
            subscribe.packet_id = mqttclient_get_packetid();
            subscribe.topic_count = sizeof(topics)/sizeof(MqttTopic);
            subscribe.topics = topics;
            rc = MqttClient_Subscribe(&client, &subscribe);
            PRINTF("MQTT Subscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            for (i = 0; i < subscribe.topic_count; i++) {
                topic = &subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    topic->topic_filter, topic->qos, topic->return_code);
            }

            /* Publish Topic */
            XMEMSET(&publish, 0, sizeof(MqttPublish));
            publish.retain = 0;
            publish.qos = qos;
            publish.duplicate = 0;
            publish.topic_name = topicName;
            publish.packet_id = mqttclient_get_packetid();
            publish.buffer = (byte*)TEST_MESSAGE;
            publish.total_len = (word16)XSTRLEN(TEST_MESSAGE);
            rc = MqttClient_Publish(&client, &publish);
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
            while (mStopRead == 0) {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&client, cmd_timeout_ms);
                if (rc == MQTT_CODE_ERROR_TIMEOUT) {
                    /* Check to see if command data (stdin) is available */
                    rc = MqttClientNet_CheckForCommand(&net, rx_buf, MAX_BUFFER_SIZE);
                    if (rc > 0) {
                        /* Publish Topic */
                        XMEMSET(&publish, 0, sizeof(MqttPublish));
                        publish.retain = 0;
                        publish.qos = qos;
                        publish.duplicate = 0;
                        publish.topic_name = topicName;
                        publish.packet_id = mqttclient_get_packetid();
                        publish.buffer = rx_buf;
                        publish.total_len = (word16)rc;
                        rc = MqttClient_Publish(&client, &publish);
                        PRINTF("MQTT Publish: Topic %s, %s (%d)",
                            publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
                    }
                    /* Keep Alive */
                    else {
                        rc = MqttClient_Ping(&client);
                        if (rc != MQTT_CODE_SUCCESS) {
                            PRINTF("MQTT Ping Keep Alive Error: %s (%d)",
                                MqttClient_ReturnCodeToString(rc), rc);
                            break;
                        }
                    }
                }
                else if (rc != MQTT_CODE_SUCCESS) {
                    /* There was an error */
                    PRINTF("MQTT Message Wait: %s (%d)",
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }

                /* Exit if test mode */
                if (test_mode) {
                    break;
                }
            }
            /* Check for error */
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Unsubscribe Topics */
            XMEMSET(&unsubscribe, 0, sizeof(MqttUnsubscribe));
            unsubscribe.packet_id = mqttclient_get_packetid();
            unsubscribe.topic_count = sizeof(topics)/sizeof(MqttTopic);
            unsubscribe.topics = topics;
            rc = MqttClient_Unsubscribe(&client, &unsubscribe);
            PRINTF("MQTT Unsubscribe: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Disconnect */
            rc = MqttClient_Disconnect(&client);
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }

        rc = MqttClient_NetDisconnect(&client);
        PRINTF("MQTT Socket Disconnect: %s (%d)",
             MqttClient_ReturnCodeToString(rc), rc);
    }

exit:
    /* Free resources */
    if (tx_buf) WOLFMQTT_FREE(tx_buf);
    if (rx_buf) WOLFMQTT_FREE(rx_buf);

    /* Cleanup network */
    MqttClientNet_DeInit(&net);

    /* Set return code */
    ((func_args*)args)->return_code = (rc == 0) ? 0 : EXIT_FAILURE;

    return 0;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #ifdef USE_WINDOWS_API
        BOOL CtrlHandler(DWORD fdwCtrlType)
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
        func_args args;

        args.argc = argc;
        args.argv = argv;

#ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", GetLastError());
        }
#elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
#endif

        mqttclient_test(&args);

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
