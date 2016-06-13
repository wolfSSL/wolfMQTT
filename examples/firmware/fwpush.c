/* fwpush.c
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

/* The signature wrapper for this example was added in wolfSSL after 3.7.1 */
#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX > 0x03007001 \
	    && defined(HAVE_ECC)
    #undef ENABLE_FIRMWARE_EXAMPLE
    #define ENABLE_FIRMWARE_EXAMPLE
#endif

#if defined(ENABLE_FIRMWARE_EXAMPLE)

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "mqttnet.h"
#include "fwpush.h"
#include "firmware.h"

/* Configuration */
#undef DEFAULT_MQTT_QOS
#define DEFAULT_MQTT_QOS        MQTT_QOS_2
#define DEFAULT_CLIENT_ID       "WolfMQTTFwPush"
#define MAX_BUFFER_SIZE         FIRMWARE_MAX_PACKET

/* Globals */
int myoptind = 0;
char* myoptarg = NULL;

/* Locals */
static int mStopRead = 0;
static const char* mTlsFile = NULL;
static int mPacketIdLast;

/* Usage */
static void Usage(void)
{
    PRINTF("fwpush:");
    PRINTF("-?          Help, print this usage");
    PRINTF("-f <file>   Firmware file to send");
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
    PRINTF("-u <str>    Username");
    PRINTF("-w <str>    Password");
    PRINTF("-r          Set Retain flag on firmware publish message");
    PRINTF("-C <num>    Command Timeout, default %dms", DEFAULT_CMD_TIMEOUT_MS);
    PRINTF("-T          Test mode");
}

static word16 mqttclient_get_packetid(void)
{
    mPacketIdLast = (mPacketIdLast >= MAX_PACKET_ID) ? 1 : mPacketIdLast + 1;
    return (word16)mPacketIdLast;
}

#ifdef ENABLE_MQTT_TLS
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
#else
static int mqttclient_tls_cb(MqttClient* client)
{
    (void)client;
    return 0;
}
#endif /* ENABLE_MQTT_TLS */

static int mqttclient_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    (void)client; /* Supress un-used argument */
    (void)msg;
    (void)msg_new;
    (void)msg_done;

    /* Return negative to termine publish processing */
    return MQTT_CODE_SUCCESS;
}

static int fwfile_load(const char* filePath, byte** fileBuf, int *fileLen)
{
    int rc = 0;
    FILE* file = NULL;

    /* Check arguments */
    if (filePath == NULL || XSTRLEN(filePath) == 0 || fileLen == NULL ||
        fileBuf == NULL) {
        return EXIT_FAILURE;
    }

    /* Open file */
    file = fopen(filePath, "rb");
    if (file == NULL) {
        PRINTF("File %s does not exist!", filePath);
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Determine length of file */
    fseek(file, 0, SEEK_END);
    *fileLen = (int) ftell(file);
    fseek(file, 0, SEEK_SET);
    //PRINTF("File %s is %d bytes", filePath, *fileLen);

    /* Allocate buffer for image */
    *fileBuf = (byte*)WOLFMQTT_MALLOC(*fileLen);
    if (*fileBuf == NULL) {
        PRINTF("File buffer malloc failed!");
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Load file into buffer */
    rc = (int)fread(*fileBuf, 1, *fileLen, file);
    if (rc != *fileLen) {
        PRINTF("Error reading file! %d", rc);
        rc = EXIT_FAILURE;
        goto exit;
    }
    rc = 0; /* Success */

exit:
    if (file) {
        fclose(file);
    }
    if (rc != 0) {
        if (*fileBuf) {
            WOLFMQTT_FREE(*fileBuf);
            *fileBuf = NULL;
        }
    }
    return rc;
}

static int fw_message_build(const char* fwFile, byte **p_msgBuf, int *p_msgLen)
{
    int rc;
    byte *msgBuf = NULL, *sigBuf = NULL, *keyBuf = NULL, *fwBuf = NULL;
    int msgLen = 0, fwLen = 0;
    word32 keyLen = 0, sigLen = 0;
    FirmwareHeader *header;
    ecc_key eccKey;
    RNG rng;

    wc_InitRng(&rng);

    /* Verify file can be loaded */
    rc = fwfile_load(fwFile, &fwBuf, &fwLen);
    if (rc < 0 || fwLen == 0 || fwBuf == NULL) {
        PRINTF("Firmware File %s Load Error!", fwFile);
        Usage();
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
    msgBuf = (byte*)WOLFMQTT_MALLOC(msgLen);
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
    XMEMCPY(&msgBuf[sizeof(FirmwareHeader) + sigLen + keyLen], fwBuf, fwLen);

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

int fwpush_test(void* args)
{
    int rc;
    MqttClient client;
    MqttNet net;
    word16 port = 0;
    const char* host = DEFAULT_MQTT_HOST;
    int use_tls = 0;
    MqttQoS qos = DEFAULT_MQTT_QOS;
    byte clean_session = 1;
    byte retain = 0;
    word16 keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    const char* client_id = DEFAULT_CLIENT_ID;
    const char* username = NULL;
    const char* password = NULL;
    byte *tx_buf = NULL, *rx_buf = NULL;
    byte *msgBuf = NULL;
    int msgLen = 0;
    const char* fwFile = NULL;
    word32 cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
    byte test_mode = 0;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?f:h:p:tc:q:sk:i:u:w:rC:T")) != -1) {
        switch ((char)rc) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);

            case 'f':
                fwFile = myoptarg;
                break;

            case 'h' :
                host   = myoptarg;
                break;

            case 'p' :
                port = (word16)XATOI(myoptarg);
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
                qos = (MqttQoS)((byte)XATOI(myoptarg));
                if (qos > MQTT_QOS_2) {
                    err_sys("Invalid QoS value!");
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

            case 'u':
                username = myoptarg;
                break;

            case 'w':
                password = myoptarg;
                break;

            case 'r':
                retain = 1;
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
    
    /* Suppress since nothing defined todo for test mode yet */
    (void)test_mode;

    /* Start example MQTT Client */
    PRINTF("MQTT Firmware Push Client: QoS %d, Use TLS %d", qos, use_tls);

    /* Load firmware, sign firmware and create message */
    rc = fw_message_build(fwFile, &msgBuf, &msgLen);
    if (rc != 0) {
        PRINTF("Firmware message build failed! %d", rc);
        exit(rc);
    }

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
    rc = MqttClient_NetConnect(&client, host, port, DEFAULT_CON_TIMEOUT_MS,
        use_tls, mqttclient_tls_cb);
    PRINTF("MQTT Socket Connect: %s (%d)",
        MqttClient_ReturnCodeToString(rc), rc);
    if (rc == MQTT_CODE_SUCCESS) {
        /* Define connect parameters */
        MqttConnect connect;
        XMEMSET(&connect, 0, sizeof(MqttConnect));
        connect.keep_alive_sec = keep_alive_sec;
        connect.clean_session = clean_session;
        connect.client_id = client_id;

        /* Optional authentication */
        connect.username = username;
        connect.password = password;

        /* Send Connect and wait for Connect Ack */
        rc = MqttClient_Connect(&client, &connect);
        PRINTF("MQTT Connect: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);
        if (rc == MQTT_CODE_SUCCESS) {
            MqttPublish publish;

            /* Validate Connect Ack info */
            PRINTF("MQTT Connect Ack: Return Code %u, Session Present %d",
                connect.ack.return_code,
                (connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Publish Topic */
            XMEMSET(&publish, 0, sizeof(MqttPublish));
            publish.retain = retain;
            publish.qos = qos;
            publish.duplicate = 0;
            publish.topic_name = FIRMWARE_TOPIC_NAME;
            publish.packet_id = mqttclient_get_packetid();
            publish.buffer = msgBuf;
            publish.total_len = msgLen;
            rc = MqttClient_Publish(&client, &publish);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            PRINTF("MQTT Publish: Topic %s, %s (%d)",
                publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);

            /* Disconnect */
            rc = MqttClient_Disconnect(&client);
            if (rc != MQTT_CODE_SUCCESS) {
                goto exit;
            }
            PRINTF("MQTT Disconnect: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }

        rc = MqttClient_NetDisconnect(&client);
        if (rc != MQTT_CODE_SUCCESS) {
            goto exit;
        }
        PRINTF("MQTT Socket Disconnect: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);
    }

exit:
    /* Free resources */
    if (tx_buf) WOLFMQTT_FREE(tx_buf);
    if (rx_buf) WOLFMQTT_FREE(rx_buf);
    if (msgBuf) WOLFMQTT_FREE(msgBuf);

    /* Cleanup network */
    MqttClientNet_DeInit(&net);

    ((func_args*)args)->return_code = (rc == 0) ? 0 : EXIT_FAILURE;

    return 0;
}
#endif /* ENABLE_FIRMWARE_EXAMPLE */


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #ifdef USE_WINDOWS_API
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
        func_args args;

        args.argc = argc;
        args.argv = argv;
        args.return_code = 0;

#ifdef USE_WINDOWS_API
        if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE) {
            PRINTF("Error setting Ctrl Handler! Error %d", (int)GetLastError());
        }
#elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            PRINTF("Can't catch SIGINT");
        }
#endif

    #if defined(ENABLE_FIRMWARE_EXAMPLE)
        fwpush_test(&args);
    #else
        /* This example requires wolfSSL after 3.7.1 for signature wrapper */
        PRINTF("Example not compiled in!");
        args.return_code = EXIT_FAILURE;
    #endif

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
