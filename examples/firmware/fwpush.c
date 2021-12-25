/* fwpush.c
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

#if defined(ENABLE_MQTT_TLS)
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/version.h>

    /* The signature wrapper for this example was added in wolfSSL after 3.7.1 */
    #if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX > 0x03007001 \
            && defined(HAVE_ECC) && !defined(NO_SIG_WRAPPER)
        #undef ENABLE_FIRMWARE_EXAMPLE
        #define ENABLE_FIRMWARE_EXAMPLE
    #endif
#endif


#if defined(ENABLE_FIRMWARE_EXAMPLE)

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "fwpush.h"
#include "firmware.h"
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"

/* Configuration */
#define MAX_BUFFER_SIZE         FIRMWARE_MAX_PACKET

/* Locals */
static int mStopRead = 0;


static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    MQTTCtx* mqttCtx = (MQTTCtx*)client->ctx;

    (void)mqttCtx;
    (void)msg;
    (void)msg_new;
    (void)msg_done;

    /* Return negative to terminate publish processing */
    return MQTT_CODE_SUCCESS;
}

/* This callback is executed from within a call to MqttPublish. It is expected
   to provide a buffer and it's size and return >=0 for success. In this example
   a firmware header is stored in the publish->ctx. */
static int mqtt_publish_cb(MqttPublish *publish) {
    int ret = -1;
#if !defined(NO_FILESYSTEM)
    size_t bytes_read;
    FwpushCBdata *cbData;
    FirmwareHeader *header;
    word32 headerSize;

    /* Structure was stored in ctx pointer */
    if (publish != NULL) {
        cbData = (FwpushCBdata*)publish->ctx;
        if (cbData != NULL) {
            header = (FirmwareHeader*)cbData->data;

            /* Check for first iteration of callback */
            if (cbData->fp == NULL) {
                /* Get FW size from FW header struct */
                headerSize = sizeof(FirmwareHeader) + header->sigLen +
                        header->pubKeyLen;
                if (headerSize > publish->buffer_len) {
                    PRINTF("Error: Firmware Header %d larger than max buffer %d",
                        headerSize, publish->buffer_len);
                    return -1;
                }

                /* Copy header to buffer */
                XMEMCPY(publish->buffer, header, headerSize);

                /* Open file */
                cbData->fp = fopen(cbData->filename, "rb");
                if (cbData->fp != NULL) {
                    /* read a buffer of data from the file */
                    bytes_read = fread(&publish->buffer[headerSize],
                            1, publish->buffer_len - headerSize, cbData->fp);
                    if (bytes_read != 0) {
                        ret = (int)bytes_read + headerSize;
                    }
                }
            }
            else {
                /* read a buffer of data from the file */
                bytes_read = fread(publish->buffer, 1, publish->buffer_len,
                        cbData->fp);
                if (bytes_read != 0) {
                    ret = (int)bytes_read;
                }
            }
            if (cbData->fp && feof(cbData->fp)) {
                fclose(cbData->fp);
            }
        }
    }
#else
    (void)publish;
#endif
    return ret;
}

static int fw_message_build(MQTTCtx *mqttCtx, const char* fwFile,
    byte **p_msgBuf, int *p_msgLen)
{
    int rc;
    byte *msgBuf = NULL, *sigBuf = NULL, *keyBuf = NULL, *fwBuf = NULL;
    int msgLen = 0, fwLen = 0;
    word32 keyLen = 0, sigLen = 0;
    FirmwareHeader *header;
    ecc_key eccKey;
    WC_RNG rng;

    wc_InitRng(&rng);

    /* Verify file can be loaded */
    rc = mqtt_file_load(fwFile, &fwBuf, &fwLen);
    if (rc < 0 || fwLen == 0 || fwBuf == NULL) {
        PRINTF("Firmware File %s Load Error!", fwFile);
        mqtt_show_usage(mqttCtx);
        goto exit;
    }
    PRINTF("Firmware File %s is %d bytes", fwFile, fwLen);

    /* Generate Key */
    /* Note: Real implementation would use previously exchanged/signed key */
    wc_ecc_init(&eccKey);
    rc = wc_ecc_make_key(&rng, 32, &eccKey);
    if (rc != 0) {
        PRINTF("Make ECC Key Failed! %d", rc);
        goto exit;
    }
    keyLen = ECC_BUFSIZE;
    keyBuf = (byte*)WOLFMQTT_MALLOC(keyLen);
    if (!keyBuf) {
        PRINTF("Key malloc failed! %d", keyLen);
        rc = EXIT_FAILURE;
        goto exit;
    }
    rc = wc_ecc_export_x963(&eccKey, keyBuf, &keyLen);
    if (rc != 0) {
        PRINTF("ECC public key x963 export failed! %d", rc);
        goto exit;
    }

    /* Sign Firmware */
    rc = wc_SignatureGetSize(FIRMWARE_SIG_TYPE, &eccKey, sizeof(eccKey));
    if (rc <= 0) {
        PRINTF("Signature type %d not supported!", FIRMWARE_SIG_TYPE);
        rc = EXIT_FAILURE;
        goto exit;
    }
    sigLen = rc;
    sigBuf = (byte*)WOLFMQTT_MALLOC(sigLen);
    if (!sigBuf) {
        PRINTF("Signature malloc failed!");
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Display lengths */
    PRINTF("Firmware Message: Sig %d bytes, Key %d bytes, File %d bytes",
        sigLen, keyLen, fwLen);

    /* Generate Signature */
    rc = wc_SignatureGenerate(
        FIRMWARE_HASH_TYPE, FIRMWARE_SIG_TYPE,
        fwBuf, fwLen,
        sigBuf, &sigLen,
        &eccKey, sizeof(eccKey),
        &rng);
    if (rc != 0) {
        PRINTF("Signature Generate Failed! %d", rc);
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Assemble message */
    msgLen = sizeof(FirmwareHeader) + sigLen + keyLen + fwLen;

    /* The firmware will be copied by the callback */
    msgBuf = (byte*)WOLFMQTT_MALLOC(msgLen - fwLen);

    if (!msgBuf) {
        PRINTF("Message malloc failed! %d", msgLen);
        rc = EXIT_FAILURE;
        goto exit;
    }
    header = (FirmwareHeader*)msgBuf;
    header->sigLen = sigLen;
    header->pubKeyLen = keyLen;
    header->fwLen = fwLen;
    XMEMCPY(&msgBuf[sizeof(FirmwareHeader)], sigBuf, sigLen);
    XMEMCPY(&msgBuf[sizeof(FirmwareHeader) + sigLen], keyBuf, keyLen);

    rc = 0;

exit:

    if (rc == 0) {
        /* Return values */
        if (p_msgBuf) *p_msgBuf = msgBuf;
        if (p_msgLen) *p_msgLen = msgLen;
    }
    else {
        if (msgBuf) WOLFMQTT_FREE(msgBuf);
    }

    /* Free resources */
    if (keyBuf) WOLFMQTT_FREE(keyBuf);
    if (sigBuf) WOLFMQTT_FREE(sigBuf);
    if (fwBuf) WOLFMQTT_FREE(fwBuf);

    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);

    return rc;
}

int fwpush_test(MQTTCtx *mqttCtx)
{
    int rc;
    FwpushCBdata* cbData = NULL;

    if (mqttCtx == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* restore callback data */
    cbData = (FwpushCBdata*)mqttCtx->publish.ctx;

    /* check for stop */
    if (mStopRead) {
        rc = MQTT_CODE_SUCCESS;
        PRINTF("MQTT Exiting...");
        mStopRead = 0;
        goto disconn;
    }

    switch(mqttCtx->stat)
    {
        case WMQ_BEGIN:
        {
            PRINTF("MQTT Firmware Push Client: QoS %d, Use TLS %d",
                    mqttCtx->qos, mqttCtx->use_tls);
        }
        FALL_THROUGH;

        case WMQ_NET_INIT:
        {
            mqttCtx->stat = WMQ_NET_INIT;

            /* setup tx/rx buffers */
            mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
            mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
        }
        FALL_THROUGH;

        case WMQ_INIT:
        {
            mqttCtx->stat = WMQ_INIT;

            /* Initialize MqttClient structure */
            rc = MqttClient_Init(&mqttCtx->client, mqttCtx, mqtt_init_client_cb, mqtt_message_cb,
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
        }
        FALL_THROUGH;

        case WMQ_TCP_CONN:
        {
            mqttCtx->stat = WMQ_TCP_CONN;

            /* Connect to broker */
            rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
                    mqttCtx->port, DEFAULT_CON_TIMEOUT_MS, mqttCtx->use_tls,
                    mqtt_tls_cb);
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
                mqttCtx->lwt_msg.header.packet.qos = mqttCtx->qos;
                mqttCtx->lwt_msg.retain = 0;
                mqttCtx->lwt_msg.topic_name = FIRMWARE_TOPIC_NAME"lwttopic";
                mqttCtx->lwt_msg.buffer = (byte*)mqttCtx->client_id;
                mqttCtx->lwt_msg.total_len =
                        (word16)XSTRLEN(mqttCtx->client_id);
            }

            /* Optional authentication */
            mqttCtx->connect.username = mqttCtx->username;
            mqttCtx->connect.password = mqttCtx->password;
        }
        FALL_THROUGH;

        case WMQ_MQTT_CONN:
        {
            mqttCtx->stat = WMQ_MQTT_CONN;

            /* Send Connect and wait for Connect Ack */
            rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }

            PRINTF("MQTT Connect: Proto (%s), %s (%d)",
                MqttClient_GetProtocolVersionString(&mqttCtx->client),
                MqttClient_ReturnCodeToString(rc), rc);

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                mqttCtx->connect.ack.return_code,
                (mqttCtx->connect.ack.flags &
                        MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }

            /* setup publish message */
            XMEMSET(&mqttCtx->publish, 0, sizeof(MqttPublish));
            mqttCtx->publish.retain = mqttCtx->retain;
            mqttCtx->publish.header.packet.qos = mqttCtx->qos;
            mqttCtx->publish.duplicate = 0;
            mqttCtx->publish.topic_name = mqttCtx->topic_name;
            mqttCtx->publish.header.packet.id = mqtt_get_packetid();
            mqttCtx->publish.buffer_len = FIRMWARE_MAX_BUFFER;
            mqttCtx->publish.buffer = (byte*)WOLFMQTT_MALLOC(FIRMWARE_MAX_BUFFER);
            if (mqttCtx->publish.buffer == NULL) {
                rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
                goto disconn;
            }

            /* Calculate the total payload length and store the FirmwareHeader,
               signature, and key in fwpushCBdata structure to be used by the
               callback. */
            cbData = (FwpushCBdata*)WOLFMQTT_MALLOC(sizeof(FwpushCBdata));
            if (cbData == NULL) {
                rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
                goto disconn;
            }
            XMEMSET(cbData, 0, sizeof(FwpushCBdata));
            cbData->filename = mqttCtx->pub_file;

            rc = fw_message_build(mqttCtx, cbData->filename, &cbData->data,
                    (int*)&mqttCtx->publish.total_len);

            /* The publish->ctx is available for use by the application to pass
               data to the callback routine. */
            mqttCtx->publish.ctx = cbData;

            if (rc != 0) {
                PRINTF("Firmware message build failed! %d", rc);
                exit(rc);
            }
        }
        FALL_THROUGH;

        case WMQ_PUB:
        {
            mqttCtx->stat = WMQ_PUB;

            /* Publish using the callback version of the publish API. This
               allows the callback to write the payload data, in this case the
               FirmwareHeader stored in the publish->ctx and the firmware file.
               The callback will be executed multiple times until the entire
               payload in sent. */
            rc = MqttClient_Publish_ex(&mqttCtx->client, &mqttCtx->publish,
                                       mqtt_publish_cb);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }

            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                mqttCtx->publish.topic_name,
                MqttClient_ReturnCodeToString(rc), rc);
            if (rc != MQTT_CODE_SUCCESS) {
                goto disconn;
            }
        }
        FALL_THROUGH;

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
        }
        FALL_THROUGH;

        case WMQ_NET_DISCONNECT:
        {
            mqttCtx->stat = WMQ_NET_DISCONNECT;

            rc = MqttClient_NetDisconnect(&mqttCtx->client);
            if (rc == MQTT_CODE_CONTINUE) {
                return rc;
            }
            PRINTF("MQTT Socket Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }
        FALL_THROUGH;

        case WMQ_DONE:
        {
            mqttCtx->stat = WMQ_DONE;
            rc = mqttCtx->return_code;
            goto exit;
        }

        case WMQ_SUB:
        case WMQ_WAIT_MSG:
        case WMQ_UNSUB:
        case WMQ_PING:
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
        if (cbData) {
            if (cbData->data) WOLFMQTT_FREE(cbData->data);
            WOLFMQTT_FREE(cbData);
        }
        if (mqttCtx->publish.buffer) WOLFMQTT_FREE(mqttCtx->publish.buffer);
        if (mqttCtx->tx_buf) WOLFMQTT_FREE(mqttCtx->tx_buf);
        if (mqttCtx->rx_buf) WOLFMQTT_FREE(mqttCtx->rx_buf);

        MqttClient_DeInit(&mqttCtx->client);
    }

    return rc;
}
#endif /* ENABLE_FIRMWARE_EXAMPLE */


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
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
        mqttCtx.app_name = "fwpush";
        mqttCtx.client_id = FIRMWARE_PUSH_CLIENT_ID;
        mqttCtx.topic_name = FIRMWARE_TOPIC_NAME;
        mqttCtx.qos = FIRMWARE_MQTT_QOS;
        mqttCtx.pub_file = FIRMWARE_PUSH_DEF_FILE;

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
            rc = fwpush_test(&mqttCtx);
        } while (rc == MQTT_CODE_CONTINUE);

        mqtt_free_ctx(&mqttCtx);
    #else
        (void)argc;
        (void)argv;

        /* This example requires wolfSSL after 3.7.1 for signature wrapper */
        PRINTF("Example not compiled in!");
        rc = 0; /* return success, so make check passes with TLS disabled */
    #endif

        return (rc == 0) ? 0 : EXIT_FAILURE;
    }

#endif /* NO_MAIN_DRIVER */
