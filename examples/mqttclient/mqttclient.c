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
#include "examples/mqttclient/mqttclient.h"
#include "examples/mqttclient/mqttnet_linux.h"

/* Configuration */
#define DEFAULT_MQTT_HOST       "iot.eclipse.org"
#define DEFAULT_CMD_TIMEOUT_MS  1000
#define DEFAULT_CON_TIMEOUT_MS  5000
#define DEFAULT_MQTT_QOS        MQTT_QOS_0
#define DEFAULT_KEEP_ALIVE_SEC  60
#define DEFAULT_CLIENT_ID       "WolfMQTTClient"

#define MAX_BUFFER_SIZE         1024
#define TEST_MESSAGE            "test" /* NULL */
#define TEST_TOPIC_COUNT        2

/* Globals */
static int mStopRead = 0;
const char* mTlsFile = NULL;

/* Usage */
static void Usage(void)
{
    printf("mqttclient:\n");
    printf("-?          Help, print this usage\n");
    printf("-h <host>   Host to connect to, default %s\n", DEFAULT_MQTT_HOST);
    printf("-p <num>    Port to connect on, default: Normal %d, TLS %d\n", MQTT_DEFAULT_PORT, MQTT_SECURE_PORT);
    printf("-t          Enable TLS\n");
    printf("-c <file>   Use provided certificate file\n");
    printf("-q <num>    Qos Level 0-2, default %d\n", DEFAULT_MQTT_QOS);
    printf("-s          Disable clean session connect flag\n");
    printf("-k <num>    Keep alive seconds, default %d\n", DEFAULT_KEEP_ALIVE_SEC);
    printf("-i <id>     Client Id, default %s\n", DEFAULT_CLIENT_ID);
    printf("-l          Enable LWT (Last Will and Testament)\n");
    printf("-u <str>    Username\n");
    printf("-w <str>    Password\n");
}


/* Argument Parsing */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

#define MY_EX_USAGE 2 /* Exit reason code */

static int myoptind = 0;
static char* myoptarg = NULL;

static int mygetopt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind][0] != '-' ||
                                argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }

    return c;
}

static void err_sys(const char* msg)
{
    printf("wolfMQTT error: %s\n", msg);
    if (msg)
        exit(EXIT_FAILURE);
}

static int mqttclient_tls_cb(MqttClient* client)
{
    int rc = SSL_SUCCESS;
    printf("MQTT TLS Setup\n");
    if (mTlsFile) {
        rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx, mTlsFile, 0);
    }
    return rc;
}

void* mqttclient_test(void* args)
{
    int rc;
    char ch;
    word16 port = 0;
    const char* host = DEFAULT_MQTT_HOST;
    MqttClient client;
    int use_tls = 0;
    byte qos = DEFAULT_MQTT_QOS;
    byte clean_session = 1;
    word16 packet_id = 0;
    word16 keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    const char* client_id = DEFAULT_CLIENT_ID;
    int enable_lwt = 0;
    const char* username = NULL;
    const char* password = NULL;
    MqttNet net;
    byte *tx_buf = NULL, *rx_buf = NULL;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((ch = mygetopt(argc, argv, "?h:p:tc:q:sk:i:lu:w:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);

            case 'h' :
                host   = myoptarg;
                break;

            case 'p' :
                port = (word16)atoi(myoptarg);
                if (port == 0) {
                    err_sys("Invalid Port Number!");
                }
                break;

            case 't':
                use_tls = 1;
                break;

            case 'c':
                mTlsFile = myoptarg;
                break;

            case 'q' :
                qos = atoi(myoptarg);
                if (qos < 0 || qos > 2) {
                    err_sys("Invalid QoS value!");
                }
                break;

            case 's':
                clean_session = 0;
                break;

            case 'k':
                keep_alive_sec = atoi(myoptarg);
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

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0; /* reset for test cases */

    /* Start example MQTT Client */
    printf("MQTT Client\n");

    /* Initialize Network */
    rc = MqttClientNet_Init(&net);
    printf("MQTT Net Init: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);

    /* Initialize MqttClient structure */
    tx_buf = malloc(MAX_BUFFER_SIZE);
    rx_buf = malloc(MAX_BUFFER_SIZE);
    rc = MqttClient_Init(&client, &net,
        tx_buf, MAX_BUFFER_SIZE, rx_buf, MAX_BUFFER_SIZE,
        DEFAULT_CMD_TIMEOUT_MS);
    printf("MQTT Init: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);

    /* Connect to broker */
    rc = MqttClient_NetConnect(&client, host, port, DEFAULT_CON_TIMEOUT_MS, use_tls, mqttclient_tls_cb);
    printf("MQTT Socket Connect: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);

    if (rc == 0) {
        /* Define connect parameters */
        MqttConnect connect;
        MqttMessage lwt_msg;
        connect.keep_alive_sec = keep_alive_sec;
        connect.clean_session = clean_session;
        connect.client_id = client_id;
        /* Last will and testement sent by broker to subscribers of topic when broker connection is lost */
        memset(&lwt_msg, 0, sizeof(lwt_msg));
        connect.lwt_msg = &lwt_msg;
        connect.enable_lwt = enable_lwt;
        if (enable_lwt) {
            lwt_msg.qos = qos;
            lwt_msg.retain = 0;
            lwt_msg.topic_name = "lwttopic";
            lwt_msg.message = (byte*)DEFAULT_CLIENT_ID;
            lwt_msg.message_len = strlen(DEFAULT_CLIENT_ID);
        }
        /* Optional authentication */
        connect.username = username;
        connect.password = password;

        /* Send Connect and wait for Connect Ack */
        rc = MqttClient_Connect(&client, &connect);
        printf("MQTT Connect: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);
        if (rc == MQTT_CODE_SUCCESS) {
            MqttSubscribe subscribe;
            MqttUnsubscribe unsubscribe;
            MqttTopic topics[TEST_TOPIC_COUNT], *topic;
            MqttPublish publish;
            MqttMessage msg;
            int i;

            /* Build list of topics */
            topics[0].topic_filter = "subtopic1";
            topics[0].qos = qos;
            topics[1].topic_filter = "subtopic2";
            topics[1].qos = qos;

            /* Validate Connect Ack info */
            rc = connect.ack.return_code;
            printf("MQTT Connect Ack: Return Code %u, Session Present %d\n",
                connect.ack.return_code,
                connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT ? 1 : 0
            );

            /* Send Ping */
            rc = MqttClient_Ping(&client);
            printf("MQTT Ping: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);

            /* Subscribe Topic */
            subscribe.packet_id = ++packet_id;
            subscribe.topic_count = TEST_TOPIC_COUNT;
            subscribe.topics = topics;
            rc = MqttClient_Subscribe(&client, &subscribe);
            printf("MQTT Subscribe: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);
            for (i = 0; i < subscribe.topic_count; i++) {
                topic = &subscribe.topics[i];
                printf("  Topic %s, Qos %u, Return Code %u\n",
                    topic->topic_filter, topic->qos, topic->return_code);
            }

            /* Publish Topic */
            publish.retain = 0;
            publish.qos = qos;
            publish.duplicate = 0;
            publish.topic_name = "pubtopic";
            publish.packet_id = ++packet_id;
            publish.message = (byte*)TEST_MESSAGE;
            publish.message_len = strlen(TEST_MESSAGE);
            rc = MqttClient_Publish(&client, &publish);
            printf("MQTT Publish: Topic %s, %s (%d)\n", publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);

            /* Read Loop */
            printf("MQTT Waiting for message...\n");
            while (mStopRead == 0) {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&client, &msg, DEFAULT_CMD_TIMEOUT_MS);

                if (rc >= 0) {
                    /* Print incomming message */
                    printf("MQTT Message: Topic %s, Len %u\n", msg.topic_name, msg.message_len);
                }
                else if (rc != MQTT_CODE_ERROR_TIMEOUT) {
                    /* There was an error */
                    printf("MQTT Message Wait: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }
            }

            /* Unsubscribe Topics */
            unsubscribe.packet_id = ++packet_id;
            unsubscribe.topic_count = TEST_TOPIC_COUNT;
            unsubscribe.topics = topics;
            rc = MqttClient_Unsubscribe(&client, &unsubscribe);
            printf("MQTT Unsubscribe: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);

            rc = MqttClient_Disconnect(&client);
            printf("MQTT Disconnect: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);
        }

        rc = MqttClient_NetDisconnect(&client);
        printf("MQTT Socket Disconnect: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);
    }

    /* Free resources */
    if (tx_buf) free(tx_buf);
    if (rx_buf) free(rx_buf);

    /* Cleanup network */
    rc = MqttClientNet_DeInit(&net);
    printf("MQTT Net DeInit: %s (%d)\n", MqttClient_ReturnCodeToString(rc), rc);

    ((func_args*)args)->return_code = 0;

    return 0;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #if HAVE_SIGNAL
        #include <signal.h>
        static void sig_handler(int signo)
        {
            if (signo == SIGINT) {
                mStopRead = 1;
                printf("Received SIGINT\n");
            }
        }
    #endif

    int main(int argc, char** argv)
    {
        func_args args;

        args.argc = argc;
        args.argv = argv;

#if HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            printf("Can't catch SIGINT\n");
        }
#endif

        mqttclient_test(&args);

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
