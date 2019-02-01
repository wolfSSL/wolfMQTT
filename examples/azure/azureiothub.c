/* azureiothub.c
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
#if defined(ENABLE_MQTT_TLS)
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/version.h>

    #if defined(LIBWOLFSSL_VERSION_HEX) && \
        LIBWOLFSSL_VERSION_HEX >= 0x03009001 && defined(WOLFSSL_BASE64_ENCODE)
        #undef ENABLE_AZUREIOTHUB_EXAMPLE
        #define ENABLE_AZUREIOTHUB_EXAMPLE
    #endif
#endif


#ifdef ENABLE_AZUREIOTHUB_EXAMPLE

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "azureiothub.h"
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"

/* Locals */
static int mStopRead = 0;

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
#define AZURE_TOKEN_SIZE        400

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

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;
    byte buf[PRINT_BUFFER_SIZE+1];
    word32 len;

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
    byte decodedKey[WC_SHA256_DIGEST_SIZE+1];
    word32 decodedKeyLen = (word32)sizeof(decodedKey);
    char deviceName[150]; /* uri */
    char sigData[200]; /* max uri + expiration */
    byte sig[WC_SHA256_DIGEST_SIZE];
    byte base64Sig[WC_SHA256_DIGEST_SIZE*2];
    word32 base64SigLen = (word32)sizeof(base64Sig);
    byte encodedSig[WC_SHA256_DIGEST_SIZE*4];
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
    rc = wc_HmacSetKey(&hmac, WC_SHA256, decodedKey, decodedKeyLen);
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
    XMEMSET(base64Sig, 0, base64SigLen);
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

int azureiothub_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;

    switch (mqttCtx->stat)
    {
        case WMQ_BEGIN:
        {
            PRINTF("AzureIoTHub Client: QoS %d, Use TLS %d", mqttCtx->qos, mqttCtx->use_tls);

            /* Azure IoT Hub requires TLS */
            if (!mqttCtx->use_tls) {
                return MQTT_CODE_ERROR_BAD_ARG;
            }

            FALL_THROUGH;
        }

        case WMQ_NET_INIT:
        {
            mqttCtx->stat = WMQ_NET_INIT;

            /* Initialize Network */
            rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Net Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }

            /* setup tx/rx buffers */
            mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);

            /* init URL encode */
            url_encoder_init();

            /* build sas token for password */
            rc = SasTokenCreate((char*)mqttCtx->app_ctx, AZURE_TOKEN_SIZE);
            if (rc < 0) {
                goto exit;
            }

            FALL_THROUGH;
        }

        case WMQ_INIT:
        {
            mqttCtx->stat = WMQ_INIT;

            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net, mqtt_message_cb,
                mqttCtx->tx_buf, MAX_BUFFER_SIZE, mqttCtx->rx_buf, MAX_BUFFER_SIZE,
                mqttCtx->cmd_timeout_ms);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Init: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            mqttCtx->client.ctx = mqttCtx;

            FALL_THROUGH;
        }

        case WMQ_TCP_CONN:
        {
            mqttCtx->stat = WMQ_TCP_CONN;

            /* Connect to broker */
            rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host, mqttCtx->port,
                DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls, mqtt_tls_cb);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
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
                mqttCtx->lwt_msg.topic_name = AZURE_EVENT_TOPIC"lwttopic";
                mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
                mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);
            }

            /* Authentication */
            mqttCtx->connect.username = AZURE_USERNAME;
            mqttCtx->connect.password = (const char *)mqttCtx->app_ctx;

            FALL_THROUGH;
        }

        case WMQ_MQTT_CONN:
        {
            mqttCtx->stat = WMQ_MQTT_CONN;

            /* Send Connect and wait for Connect Ack */
            rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Connect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags &
                    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topic_name;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Subscribe Topic */
            XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx->subscribe.stat = MQTT_MSG_BEGIN;
            mqttCtx->subscribe.packet_id = mqtt_get_packetid();
            mqttCtx->subscribe.topic_count = sizeof(mqttCtx->topics)/sizeof(MqttTopic);
            mqttCtx->subscribe.topics = mqttCtx->topics;

            FALL_THROUGH;
        }

        case WMQ_SUB:
        {
            mqttCtx->stat = WMQ_SUB;

            rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
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
            mqttCtx->publish.topic_name = AZURE_EVENT_TOPIC;
            mqttCtx->publish.packet_id = mqtt_get_packetid();
            mqttCtx->publish.buffer = NULL;
            mqttCtx->publish.total_len = 0;

            FALL_THROUGH;
        }

        case WMQ_PUB:
        {
            mqttCtx->stat = WMQ_PUB;

            rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                mqttCtx->publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Read Loop */
            PRINTF("MQTT Waiting for message...");

            FALL_THROUGH;
        }

        case WMQ_WAIT_MSG:
        {
            mqttCtx->stat = WMQ_WAIT_MSG;

            do {
                /* check for test mode or stop */
                if (mStopRead || mqttCtx->test_mode) {
                    rc = MQTT_CODE_SUCCESS;
                    PRINTF("MQTT Exiting...");
                    break;
                }

                /* Try and read packet */
                rc = MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms);

            #ifdef WOLFMQTT_NONBLOCK
                /* Track elapsed time with no activity and trigger timeout */
                rc = mqtt_check_timeout(rc, &mqttCtx->start_sec,
                    mqttCtx->cmd_timeout_ms/1000);
            #endif

                /* check return code */
                if (rc == MQTT_CODE_CONTINUE) {
                    return rc;
                }
            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
                else if (rc == MQTT_CODE_STDIN_WAKE) {
                    /* Get data from STDIO */
                    XMEMSET(mqttCtx->rx_buf, 0, MAX_BUFFER_SIZE);
                    if (XFGETS((char*)mqttCtx->rx_buf, MAX_BUFFER_SIZE - 1, stdin) != NULL) {
                        rc = (int)XSTRLEN((char*)mqttCtx->rx_buf);

                        /* Publish Topic */
                        mqttCtx->stat = WMQ_PUB;
                        XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
                        mqttCtx->publish.retain = 0;
                        mqttCtx->publish.qos = mqttCtx->qos;
                        mqttCtx->publish.duplicate = 0;
                        mqttCtx->publish.topic_name = AZURE_EVENT_TOPIC;
                        mqttCtx->publish.packet_id = mqtt_get_packetid();
                        mqttCtx->publish.buffer = mqttCtx->rx_buf;
                        mqttCtx->publish.total_len = (word16)rc;
                        rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
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
                    if (rc == MQTT_CODE_CONTINUE) {
                        return rc;
                    }
                    else if (rc != MQTT_CODE_SUCCESS) {
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

            FALL_THROUGH;
        }

        case WMQ_DISCONNECT:
        {
            /* Disconnect */
            rc = MqttClient_Disconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            FALL_THROUGH;
        }

        case WMQ_NET_DISCONNECT:
        {
            mqttCtx->stat = WMQ_NET_DISCONNECT;

            rc = MqttClient_NetDisconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);

            FALL_THROUGH;
        }

        case WMQ_DONE:
        {
            mqttCtx->stat = WMQ_DONE;
            rc = mqttCtx->return_code;
            goto exit;
        }

        case WMQ_UNSUB: /* not used */
        default:
            rc = MQTT_CODE_ERROR_STAT;
            goto exit;
    } /* switch */

disconn:
    mqttCtx->stat = WMQ_NET_DISCONNECT;
    mqttCtx->return_code = rc;
    rc = MQTT_CODE_CONTINUE;

exit:

    if (rc != MQTT_CODE_CONTINUE) {
        /* Free resources */
        if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
        if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

        /* Cleanup network */
        MqttClientNet_DeInit(&mqttCtx->net);
    }

    return rc;
}
#endif /* ENABLE_AZUREIOTHUB_EXAMPLE */


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

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
        int rc;
    #ifdef ENABLE_AZUREIOTHUB_EXAMPLE
        MQTTCtx mqttCtx;
        char sasToken[AZURE_TOKEN_SIZE] = {0};

        /* init defaults */
        mqtt_init_ctx(&mqttCtx);
        mqttCtx.app_name = "azureiothub";
        mqttCtx.host = AZURE_HOST;
        mqttCtx.qos = AZURE_QOS;
        mqttCtx.keep_alive_sec = AZURE_KEEP_ALIVE_SEC;
        mqttCtx.client_id = AZURE_DEVICE_ID;
        mqttCtx.topic_name = AZURE_MSGS_TOPIC_NAME;
        mqttCtx.cmd_timeout_ms = AZURE_CMD_TIMEOUT_MS;
        mqttCtx.use_tls = 1;
        mqttCtx.app_ctx = (void*)sasToken;

        /* parse arguments */
        rc = mqtt_parse_args(&mqttCtx, argc, argv);
        if (rc != 0) {
            return rc;
        }
    #endif

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
        do {
            rc = azureiothub_test(&mqttCtx);
        } while (rc == MQTT_CODE_CONTINUE);
    #else
        (void)argc;
        (void)argv;

        /* This example requires wolfSSL 3.9.1 or later with base64encode enabled */
        PRINTF("Example not compiled in!");
        rc = EXIT_FAILURE;
    #endif

        return (rc == 0) ? 0 : EXIT_FAILURE;
    }

#endif /* NO_MAIN_DRIVER */
