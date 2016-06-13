/* azureiothub.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
#include <wolfssl/options.h>
#include <wolfssl/version.h>

#include "mqttexample.h"

/* This example only works with ENABLE_MQTT_TLS (wolfSSL library) */
/* Notes:
 *  The wolfSSL library must be built with
 *  #define WOLFSSL_BASE64_ENCODE
 *  or
 *  ./configure --enable-base64encode"
 *
 *  The "wc_GetTime" API was added in 3.9.1 and if not present you'll need to implement
 *  your own version of this to get current UTC seconds or update your wolfSSL library
*/

/* This example requires features in wolfSSL 3.9.1 or later */
#if defined(ENABLE_MQTT_TLS) && defined(LIBWOLFSSL_VERSION_HEX) && \
    LIBWOLFSSL_VERSION_HEX >= 0x03009001 && defined(WOLFSSL_BASE64_ENCODE)
    #undef ENABLE_AZUREIOTHUB_EXAMPLE
    #define ENABLE_AZUREIOTHUB_EXAMPLE
#endif


#ifdef ENABLE_AZUREIOTHUB_EXAMPLE

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "azureiothub.h"
#include "mqttnet.h"

/* Globals */
int myoptind = 0;
char* myoptarg = NULL;

/* Locals */
static int mStopRead = 0;
static const char* mTlsFile = NULL;
static int mPacketIdLast;

/* Configuration */
/* Reference:
 * https://azure.microsoft.com/en-us/documentation/articles/iot-hub-mqtt-support
 * https://azure.microsoft.com/en-us/documentation/articles/iot-hub-devguide/#mqtt-support
 * https://azure.microsoft.com/en-us/documentation/articles/iot-hub-sas-tokens/#using-sas-tokens-as-a-device
 */
#define MAX_BUFFER_SIZE         1024    /* Maximum size for network read/write callbacks */
#define AZURE_HOST              "wolfMQTT.azure-devices.net"
#define AZURE_DEVICE_ID         "demoDevice"
#define AZURE_KEY               "Vd8RHMAFPyRnAozkNCNFIPhVSffyZkB13r/YqiTWq5s=" /* Base64 Encoded */
#define AZURE_QOS               MQTT_QOS_1 /* Azure IoT Hub does not yet support QoS level 2 */
#define AZURE_KEEP_ALIVE_SEC    DEFAULT_KEEP_ALIVE_SEC
#define AZURE_CMD_TIMEOUT_MS    DEFAULT_CMD_TIMEOUT_MS
#define AZURE_TOKEN_EXPIRY_SEC  (60 * 60 * 1) /* 1 hour */

#define AZURE_DEVICE_NAME       AZURE_HOST"/devices/"AZURE_DEVICE_ID
#define AZURE_USERNAME          AZURE_HOST"/"AZURE_DEVICE_ID 
#define AZURE_SIG_FMT           "%s\n%ld"
    /* [device name (URL Encoded)]\n[Expiration sec UTC] */
#define AZURE_PASSWORD_FMT      "SharedAccessSignature sr=%s&sig=%s&se=%ld"
    /* sr=[device name (URL Encoded)]
       sig=[HMAC-SHA256 of AZURE_SIG_FMT using AZURE_KEY (URL Encoded)]
       se=[Expiration sec UTC] */

#define AZURE_MSGS_TOPIC_NAME   "devices/"AZURE_DEVICE_ID"/messages/devicebound/#" /* subscribe */
#define AZURE_EVENT_TOPIC       "devices/"AZURE_DEVICE_ID"/messages/events/" /* publish */


/* Usage */
static void Usage(void)
{
    PRINTF("azureiothub:");
    PRINTF("-?          Help, print this usage");
    PRINTF("-h <host>   Host to connect to, default %s",
        AZURE_HOST);
    PRINTF("-p <num>    Port to connect on, default: Normal %d, TLS %d",
        MQTT_DEFAULT_PORT, MQTT_SECURE_PORT);
    PRINTF("-t          Enable TLS, default: on");
    PRINTF("-c <file>   Use provided certificate file");
    PRINTF("-q <num>    Qos Level 0-2, default %d",
        AZURE_QOS);
    PRINTF("-s          Disable clean session connect flag");
    PRINTF("-k <num>    Keep alive seconds, default %d",
        AZURE_KEEP_ALIVE_SEC);
    PRINTF("-i <id>     Client Id, default %s",
        AZURE_DEVICE_ID);
    PRINTF("-l          Enable LWT (Last Will and Testament)");
    PRINTF("-C <num>    Command Timeout, default %dms", AZURE_CMD_TIMEOUT_MS);
    PRINTF("-T          Test mode");
}


/* Encoding Support */
static char mRfc3986[256] = {0};
//static char mHtml5[256] = {0};
static void url_encoder_init(void)
{
    int i;
    for (i = 0; i < 256; i++){
        mRfc3986[i] = XISALNUM( i) || i == '~' || i == '-' || i == '.' || i == '_' ? i : 0;
        //mHtml5[i] = XISALNUM( i) || i == '*' || i == '-' || i == '.' || i == '_' ? i : (i == ' ') ? '+' : 0;
    }
}

static char* url_encode(char* table, unsigned char *s, char *enc)
{
    for (; *s; s++){
        if (table[*s]) {
            XSNPRINTF(enc, 2, "%c", table[*s]);
        }
        else {
            XSNPRINTF(enc, 4, "%%%02x", *s);
        }
        while (*++enc); /* locate end */
    }
    return enc;
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

        rc = SSL_SUCCESS;
        if (mTlsFile) {
    #if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx, mTlsFile, NULL);
    #endif
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

static int SasTokenCreate(char* sasToken, int sasTokenLen)
{
    int rc;
    const char* encodedKey = AZURE_KEY;
    byte decodedKey[SHA256_DIGEST_SIZE+1];
    word32 decodedKeyLen = (word32)sizeof(decodedKey);
    char deviceName[150]; /* uri */
    char sigData[200]; /* max uri + expiration */
    byte sig[SHA256_DIGEST_SIZE];
    byte base64Sig[SHA256_DIGEST_SIZE*2];
    word32 base64SigLen = (word32)sizeof(base64Sig);
    byte encodedSig[SHA256_DIGEST_SIZE*4];
    long lTime;
    Hmac hmac;

    if (sasToken == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Decode Key */
    rc = Base64_Decode((const byte*)encodedKey, (word32)XSTRLEN(encodedKey), decodedKey, &decodedKeyLen);
    if (rc != 0) {
        PRINTF("SasTokenCreate: Decode shared access key failed! %d", rc);
        return rc;
    }

    /* Get time */
    rc = wc_GetTime(&lTime, (word32)sizeof(lTime));
    if (rc != 0) {
        PRINTF("SasTokenCreate: Unable to get time! %d", rc);
        return rc;
    }
    lTime += AZURE_TOKEN_EXPIRY_SEC;

    /* URL encode uri (device name) */
    url_encode(mRfc3986, (byte*)AZURE_DEVICE_NAME, deviceName);

    /* Build signature sting "uri \n expiration" */
    XSNPRINTF(sigData, sizeof(sigData), AZURE_SIG_FMT, deviceName, lTime);

    /* HMAC-SHA256 Hash sigData using decoded key */
    rc = wc_HmacSetKey(&hmac, SHA256, decodedKey, decodedKeyLen);
    if (rc < 0) {
        PRINTF("SasTokenCreate: Hmac setkey failed! %d", rc);
        return rc;
    }
    rc = wc_HmacUpdate(&hmac, (byte*)sigData, (word32)XSTRLEN(sigData));
    if (rc < 0) {
        PRINTF("SasTokenCreate: Hmac update failed! %d", rc);
        return rc;
    }
    rc = wc_HmacFinal(&hmac, sig);
    if (rc < 0) {
        PRINTF("SasTokenCreate: Hmac final failed! %d", rc);
        return rc;
    }

    /* Base64 encode signature */
    rc = Base64_Encode_NoNl(sig, sizeof(sig), base64Sig, &base64SigLen);
    if (rc < 0) {
        PRINTF("SasTokenCreate: Encoding sig failed! %d", rc);
        return rc;
    }

    /* URL encode signature */
    url_encode(mRfc3986, base64Sig, (char*)encodedSig);

    /* Build sasToken */
    XSNPRINTF(sasToken, sasTokenLen, AZURE_PASSWORD_FMT, deviceName, encodedSig, lTime);
    PRINTF("%s", sasToken);

    return 0;
}

int azureiothub_test(void* args)
{
    int rc;
    MqttClient client;
    MqttNet net;
    word16 port = 0;
    const char* host = AZURE_HOST;
    int use_tls = 1;
    MqttQoS qos = AZURE_QOS;
    byte clean_session = 1;
    word16 keep_alive_sec = AZURE_KEEP_ALIVE_SEC;
    const char* client_id = AZURE_DEVICE_ID;
    int enable_lwt = 0;
    byte *tx_buf = NULL, *rx_buf = NULL;
    word32 cmd_timeout_ms = AZURE_CMD_TIMEOUT_MS;
    byte test_mode = 0;
    char sasToken[400];

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?h:p:tc:q:sk:i:lC:T")) != -1) {
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
    url_encoder_init();

    /* Start example MQTT Client */
    PRINTF("AzureIoTHub Client: QoS %d, Use TLS %d", qos, use_tls);

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
            lwt_msg.topic_name = AZURE_EVENT_TOPIC;
            lwt_msg.buffer = (byte*)client_id;
            lwt_msg.total_len = (word16)XSTRLEN(client_id);
        }
        /* Authentication */
        /* build sas token for password */
        rc = SasTokenCreate(sasToken, (int)sizeof(sasToken));
        if (rc < 0) {
            goto exit;
        }
        connect.username = AZURE_USERNAME;
        connect.password = sasToken;

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
            topics[0].topic_filter = AZURE_MSGS_TOPIC_NAME;
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
            publish.topic_name = AZURE_EVENT_TOPIC;
            publish.packet_id = mqttclient_get_packetid();
            publish.buffer = NULL;
            publish.total_len = 0;
            rc = MqttClient_Publish(&client, &publish);
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");
            MqttClientNet_CheckForCommand_Enable(&net);
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
                        publish.topic_name = AZURE_EVENT_TOPIC;
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
#endif /* ENABLE_AZUREIOTHUB_EXAMPLE */


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #ifdef USE_WINDOWS_API
        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
            #ifdef ENABLE_AZUREIOTHUB_EXAMPLE
                mStopRead = 1;
            #endif
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
            #ifdef ENABLE_AZUREIOTHUB_EXAMPLE
                mStopRead = 1;
            #endif
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
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
#elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
#endif

    #ifdef ENABLE_AZUREIOTHUB_EXAMPLE
        azureiothub_test(&args);
    #else
        /* This example requires wolfSSL 3.9.1 or later with base64encode enabled */
        PRINTF("Example not compiled in!");
        args.return_code = EXIT_FAILURE;
    #endif

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
