/* fwclient.c
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

#if defined(ENABLE_MQTT_TLS)
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/version.h>

    /* The signature wrapper for this example was added in wolfSSL after 3.7.1 */
    #if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX > 0x03007001 \
    	    && defined(HAVE_ECC)
        #undef ENABLE_FIRMWARE_EXAMPLE
        #define ENABLE_FIRMWARE_EXAMPLE
    #endif
#endif


#if defined(ENABLE_FIRMWARE_EXAMPLE)

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "fwclient.h"
#include "firmware.h"
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"

/* Configuration */
#define MAX_BUFFER_SIZE         FIRMWARE_MAX_PACKET

/* Locals */
static int mStopRead = 0;
static byte* mFwBuf;


static int fwfile_save(const char* filePath, byte* fileBuf, int fileLen)
{
#if !defined(NO_FILESYSTEM)
    int ret = 0;
    FILE* file = NULL;

    /* Check arguments */
    if (filePath == NULL || XSTRLEN(filePath) == 0 || fileLen == 0 ||
        fileBuf == NULL) {
        return EXIT_FAILURE;
    }

    /* Open file */
    file = fopen(filePath, "wb");
    if (file == NULL) {
        PRINTF("File %s write error!", filePath);
        ret = EXIT_FAILURE;
        goto exit;
    }

    /* Save file */
    ret = (int)fwrite(fileBuf, 1, fileLen, file);
    if (ret != fileLen) {
        PRINTF("Error reading file! %d", ret);
        ret = EXIT_FAILURE;
        goto exit;
    }

    PRINTF("Saved %d bytes to %s", fileLen, filePath);

exit:
    if (file) {
        fclose(file);
    }
    return ret;

#else
    (void)filePath;
    (void)fileBuf;
    PRINTF("Firmware File Save: Len=%d (No Filesystem)", fileLen);
    return fileLen;
#endif
}

static int fw_message_process(MQTTCtx *mqttCtx, byte* buffer, word32 len)
{
    int rc;
    FirmwareHeader* header = (FirmwareHeader*)buffer;
    byte *sigBuf, *pubKeyBuf, *fwBuf;
    ecc_key eccKey;
    word32 check_len = sizeof(FirmwareHeader) + header->sigLen +
        header->pubKeyLen + header->fwLen;

    /* Verify entire message was received */
    if (len != check_len) {
        PRINTF("Message header vs. actual size mismatch! %d != %d",
            len, check_len);
        return EXIT_FAILURE;
    }

    /* Get pointers to structure elements */
    sigBuf = (buffer + sizeof(FirmwareHeader));
    pubKeyBuf = (buffer + sizeof(FirmwareHeader) + header->sigLen);
    fwBuf = (buffer + sizeof(FirmwareHeader) + header->sigLen +
        header->pubKeyLen);

    /* Import the public key */
    wc_ecc_init(&eccKey);
    rc = wc_ecc_import_x963(pubKeyBuf, header->pubKeyLen, &eccKey);
    if (rc == 0) {
        /* Perform signature verification using public key */
        rc = wc_SignatureVerify(
            FIRMWARE_HASH_TYPE, FIRMWARE_SIG_TYPE,
            fwBuf, header->fwLen,
            sigBuf, header->sigLen,
            &eccKey, sizeof(eccKey));
        PRINTF("Firmware Signature Verification: %s (%d)",
            (rc == 0) ? "Pass" : "Fail", rc);

        if (rc == 0) {
            /* TODO: Process firmware image */
            /* For example, save to disk using topic name */
            fwfile_save(mqttCtx->pub_file, fwBuf, header->fwLen);
        }
    }
    else {
        PRINTF("ECC public key import failed! %d", rc);
    }
    wc_ecc_free(&eccKey);

    return rc;
}

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

    /* Verify this message is for the firmware topic */
    if (msg_new &&
        XMEMCMP(msg->topic_name, FIRMWARE_TOPIC_NAME,
            msg->topic_name_len) == 0 &&
        !mFwBuf)
    {
        /* Allocate buffer for entire message */
        /* Note: On an embedded system this could just be a write to flash.
                 If writting to flash change FIRMWARE_MAX_BUFFER to match
                 block size */
        mFwBuf = (byte*)WOLFMQTT_MALLOC(msg->total_len);
        if (mFwBuf == NULL) {
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }

        /* Print incoming message */
        PRINTF("MQTT Firmware Message: Qos %d, Len %u",
            msg->qos, msg->total_len);
    }

    if (mFwBuf) {
        XMEMCPY(&mFwBuf[msg->buffer_pos], msg->buffer, msg->buffer_len);

        /* Process message if done */
        if (msg_done) {
            fw_message_process(mqttCtx, mFwBuf, msg->total_len);

            /* Free */
            WOLFMQTT_FREE(mFwBuf);
            mFwBuf = NULL;

            /* for test mode stop client */
            if (mqttCtx->test_mode) {
                mStopRead = 1;
            }
        }
    }

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

int fwclient_test(MQTTCtx *mqttCtx)
{
    int rc = MQTT_CODE_SUCCESS, i;

    switch(mqttCtx->stat) {
        case WMQ_BEGIN:
        {
            PRINTF("MQTT Firmware Client: QoS %d, Use TLS %d", mqttCtx->qos, mqttCtx->use_tls);

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

            FALL_THROUGH;
        }

        case WMQ_INIT:
        {
            mqttCtx->stat = WMQ_INIT;

            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net,
                mqtt_message_cb,
                mqttCtx->tx_buf, MAX_BUFFER_SIZE,
                mqttCtx->rx_buf, MAX_BUFFER_SIZE,
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
            rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
                mqttCtx->port, DEFAULT_CON_TIMEOUT_MS,
                mqttCtx->use_tls, mqtt_tls_cb);
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
            if (mqttCtx->enable_lwt) {
                /* Send client id in LWT payload */
                mqttCtx->lwt_msg.qos = mqttCtx->qos;
                mqttCtx->lwt_msg.retain = 0;
                mqttCtx->lwt_msg.topic_name = FIRMWARE_TOPIC_NAME"lwttopic";
                mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
                mqttCtx->lwt_msg.total_len = (word16)XSTRLEN(mqttCtx->client_id);
            }

            /* Optional authentication */
            mqttCtx->connect.username = mqttCtx->username;
            mqttCtx->connect.password = mqttCtx->password;

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

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* Build list of topics */
            mqttCtx->topics[0].topic_filter = mqttCtx->topic_name;
            mqttCtx->topics[0].qos = mqttCtx->qos;

            /* Subscribe Topic */
            XMEMSET(&mqttCtx->subscribe, 0, sizeof(MqttSubscribe));
            mqttCtx->subscribe.stat = MQTT_MSG_BEGIN;
            mqttCtx->subscribe.packet_id = mqtt_get_packetid();
            mqttCtx->subscribe.topic_count = 1;
            mqttCtx->subscribe.topics = mqttCtx->topics;
            mqttCtx->topics[0].topic_filter = FIRMWARE_TOPIC_NAME;
            mqttCtx->topics[0].qos = mqttCtx->qos;

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
            for (i = 0; i < mqttCtx->subscribe.topic_count; i++) {
                mqttCtx->topic = &mqttCtx->subscribe.topics[i];
                PRINTF("  Topic %s, Qos %u, Return Code %u",
                    mqttCtx->topic->topic_filter,
                    mqttCtx->topic->qos,
                    mqttCtx->topic->return_code);
            }
            /* Read Loop */
            PRINTF("MQTT Waiting for message...");

            FALL_THROUGH;
        }

        case WMQ_WAIT_MSG:
        {
            mqttCtx->stat = WMQ_WAIT_MSG;

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

            #ifdef WOLFMQTT_NONBLOCK
                /* Track elapsed time with no activity and trigger timeout */
                rc = mqtt_check_timeout(rc, &mqttCtx->start_sec,
                    mqttCtx->cmd_timeout_ms/1000);
            #endif

                /* check return code */
                if (rc == MQTT_CODE_CONTINUE) {
                    return rc;
                }
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

                /* Exit if test mode */
                if (mqttCtx->test_mode) {
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

        case WMQ_PUB:
        case WMQ_UNSUB:
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
#endif /* ENABLE_FIRMWARE_EXAMPLE */


/* so overall tests can pull in test function */
#if !defined(NO_MAIN_DRIVER) && !defined(MICROCHIP_MPLAB_HARMONY)
    #ifdef USE_WINDOWS_API
        #include <windows.h> /* for ctrl handler */

        static BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
            #if defined(ENABLE_FIRMWARE_EXAMPLE)
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
            #if defined(ENABLE_FIRMWARE_EXAMPLE)
                mStopRead = 1;
            #endif
                PRINTF("Received SIGINT");
            }
        }
    #endif

    int main(int argc, char** argv)
    {
        int rc;
    #ifdef ENABLE_FIRMWARE_EXAMPLE
        MQTTCtx mqttCtx;

        /* init defaults */
        mqtt_init_ctx(&mqttCtx);
        mqttCtx.app_name = "fwclient";
        mqttCtx.client_id = FIRMWARE_CLIIENT_ID;
        mqttCtx.topic_name = FIRMWARE_TOPIC_NAME;
        mqttCtx.qos = FIRMWARE_MQTT_QOS;
        mqttCtx.pub_file = FIRMWARE_DEF_SAVE_AS;

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

    #ifdef ENABLE_FIRMWARE_EXAMPLE
        do {
            rc = fwclient_test(&mqttCtx);
        } while (rc == MQTT_CODE_CONTINUE);
    #else
        (void)argc;
        (void)argv;

        /* This example requires wolfSSL after 3.7.1 for signature wrapper */
        PRINTF("Example not compiled in!");
        rc = EXIT_FAILURE;
    #endif

        return (rc == 0) ? 0 : EXIT_FAILURE;
    }

#endif /* NO_MAIN_DRIVER */
