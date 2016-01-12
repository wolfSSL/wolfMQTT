/* fwpush.c
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

#include <wolfssl/options.h>
#include <wolfssl/version.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;


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
#include <wolfmqtt/mqtt_client.h>

#include "examples/mqttnet.h"
#include "examples/firmware/fwpush.h"
#include "examples/firmware/firmware.h"


/* Configuration */
#define DEFAULT_CMD_TIMEOUT_MS  30000
#define DEFAULT_CON_TIMEOUT_MS  5000
#define DEFAULT_MQTT_QOS        MQTT_QOS_2
#define DEFAULT_KEEP_ALIVE_SEC  60
#define DEFAULT_CLIENT_ID       "WolfMQTTFwPush"

#define MAX_BUFFER_SIZE         FIRMWARE_MAX_PACKET

/* Globals */
static int mStopRead = 0;
const char* mTlsFile = NULL;

/* Usage */
static void Usage(void)
{
    printf("fwpush:\n");
    printf("-?          Help, print this usage\n");
    printf("-f <file>   Firmware file to send\n");
    printf("-h <host>   Host to connect to, default %s\n",
        DEFAULT_MQTT_HOST);
    printf("-p <num>    Port to connect on, default: Normal %d, TLS %d\n",
        MQTT_DEFAULT_PORT, MQTT_SECURE_PORT);
    printf("-t          Enable TLS\n");
    printf("-c <file>   Use provided certificate file\n");
    printf("-q <num>    Qos Level 0-2, default %d\n",
        DEFAULT_MQTT_QOS);
    printf("-s          Disable clean session connect flag\n");
    printf("-k <num>    Keep alive seconds, default %d\n",
        DEFAULT_KEEP_ALIVE_SEC);
    printf("-i <id>     Client Id, default %s\n",
        DEFAULT_CLIENT_ID);
    printf("-u <str>    Username\n");
    printf("-w <str>    Password\n");
    printf("-r          Set Retain flag on firmware publish message\n");
}


/* Argument Parsing */
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

        if (XSTRCMP(argv[myoptind], "--") == 0) {
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
    cp = (char*)XSTRCHR(optstring, c);

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
    if (msg) {
        exit(EXIT_FAILURE);
    }
}

#define MAX_PACKET_ID   ((1 << 16) - 1)
static int mPacketIdLast;
static word16 mqttclient_get_packetid(void)
{
    mPacketIdLast = (mPacketIdLast >= MAX_PACKET_ID) ? 1 : mPacketIdLast + 1;
    return (word16)mPacketIdLast;
}

static int mqttclient_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];

    printf("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)\n", preverify, 
        store->error, wolfSSL_ERR_error_string(store->error, buffer));
    printf("  Subject's domain name is %s\n", store->domain);

    /* Allowing to continue */
    /* Should check certificate and return 0 if not okay */
    printf("  Allowing cert anyways\n");

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

    printf("MQTT TLS Setup (%d)\n", rc);

    return rc;
}

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
        printf("File %s does not exist!\n", filePath);
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Determine length of file */
    fseek(file, 0, SEEK_END);
    *fileLen = (int) ftell(file);
    fseek(file, 0, SEEK_SET);
    //printf("File %s is %d bytes\n", filePath, *fileLen);

    /* Allocate buffer for image */
    *fileBuf = (byte*)WOLFMQTT_MALLOC(*fileLen);
    if (*fileBuf == NULL) {
        printf("File buffer malloc failed!\n");
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Load file into buffer */
    rc = (int)fread(*fileBuf, 1, *fileLen, file);
    if (rc != *fileLen) {
        printf("Error reading file! %d", rc);
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
    if (rc < 0 || fwLen == 0) {
        printf("Firmware File %s Load Error!\n", fwFile);
        Usage();
        goto exit;
    }

    /* Generate Key */
    /* Note: Real implementation would use previously exchanged/signed key */
    wc_ecc_init(&eccKey);
    rc = wc_ecc_make_key(&rng, 32, &eccKey);
    if (rc != 0) {
        printf("Make ECC Key Failed! %d\n", rc);
        goto exit;
    }
    keyLen = ECC_BUFSIZE;
    keyBuf = (byte*)WOLFMQTT_MALLOC(keyLen);
    if (!keyBuf) {
        printf("Key malloc failed! %d\n", keyLen);
        rc = EXIT_FAILURE;
        goto exit;
    }
    rc = wc_ecc_export_x963(&eccKey, keyBuf, &keyLen);
    if (rc != 0) {
        printf("ECC public key x963 export failed! %d\n", rc);
        goto exit;
    }

    /* Sign Firmware */
    sigLen = wc_SignatureGetSize(FIRMWARE_SIG_TYPE, &eccKey, sizeof(eccKey));
    if (sigLen <= 0) {
        printf("Signature type %d not supported!\n", FIRMWARE_SIG_TYPE);
        rc = EXIT_FAILURE;
        goto exit;
    }
    sigBuf = (byte*)WOLFMQTT_MALLOC(sigLen);
    if (!sigBuf) {
        printf("Signature malloc failed!\n");
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Display lengths */
    printf("Firmware Message: Sig %d bytes, Key %d bytes, File %d bytes\n",
        sigLen, keyLen, fwLen);

    /* Generate Signature */
    rc = wc_SignatureGenerate(
        FIRMWARE_HASH_TYPE, FIRMWARE_SIG_TYPE,
        fwBuf, fwLen,
        sigBuf, &sigLen,
        &eccKey, sizeof(eccKey),
        &rng);
    if (rc != 0) {
        printf("Signature Generate Failed! %d\n", rc);
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Assemble message */
    msgLen = sizeof(FirmwareHeader) + sigLen + keyLen + fwLen;
    msgBuf = (byte*)WOLFMQTT_MALLOC(msgLen);
    if (!msgBuf) {
        printf("Message malloc failed! %d\n", msgLen);
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

void* fwpush_test(void* args)
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

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?f:h:p:tc:q:sk:i:u:w:r")) != -1) {
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

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0; /* reset for test cases */

    /* Start example MQTT Client */
    printf("MQTT Firmware Push Client: QoS %d\n", qos);

    /* Load firmware, sign firmware and create message */
    rc = fw_message_build(fwFile, &msgBuf, &msgLen);
    if (rc != 0) {
        printf("Firmware message build failed! %d\n", rc);
        exit(rc);
    }

    /* Initialize Network */
    rc = MqttClientNet_Init(&net);
    printf("MQTT Net Init: %s (%d)\n",
        MqttClient_ReturnCodeToString(rc), rc);

    /* Initialize MqttClient structure */
    tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    rc = MqttClient_Init(&client, &net, mqttclient_message_cb,
        tx_buf, MAX_BUFFER_SIZE, rx_buf, MAX_BUFFER_SIZE,
        DEFAULT_CMD_TIMEOUT_MS);
    printf("MQTT Init: %s (%d)\n",
        MqttClient_ReturnCodeToString(rc), rc);

    /* Connect to broker */
    rc = MqttClient_NetConnect(&client, host, port, DEFAULT_CON_TIMEOUT_MS,
        use_tls, mqttclient_tls_cb);
    printf("MQTT Socket Connect: %s (%d)\n",
        MqttClient_ReturnCodeToString(rc), rc);

    if (rc == 0) {
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
        printf("MQTT Connect: %s (%d)\n",
            MqttClient_ReturnCodeToString(rc), rc);
        if (rc == MQTT_CODE_SUCCESS) {
            MqttPublish publish;

            /* Validate Connect Ack info */
            printf("MQTT Connect Ack: Return Code %u, Session Present %d\n",
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
            printf("MQTT Publish: Topic %s, %s (%d)\n",
                publish.topic_name, MqttClient_ReturnCodeToString(rc), rc);

            /* Disconnect */
            rc = MqttClient_Disconnect(&client);
            printf("MQTT Disconnect: %s (%d)\n",
                MqttClient_ReturnCodeToString(rc), rc);
        }

        rc = MqttClient_NetDisconnect(&client);
        printf("MQTT Socket Disconnect: %s (%d)\n",
            MqttClient_ReturnCodeToString(rc), rc);
    }

    /* Free resources */
    if (tx_buf) WOLFMQTT_FREE(tx_buf);
    if (rx_buf) WOLFMQTT_FREE(rx_buf);
    if (msgBuf) WOLFMQTT_FREE(msgBuf);

    /* Cleanup network */
    rc = MqttClientNet_DeInit(&net);
    printf("MQTT Net DeInit: %s (%d)\n",
        MqttClient_ReturnCodeToString(rc), rc);

    ((func_args*)args)->return_code = rc;

    return 0;
}

#endif /* ENABLE_FIRMWARE_EXAMPLE */


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER
    #ifdef USE_WINDOWS_API
        BOOL CtrlHandler(DWORD fdwCtrlType)
        {
            if (fdwCtrlType == CTRL_C_EVENT) {
                mStopRead = 1;
                printf("Received Ctrl+c\n");
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
                printf("Received SIGINT\n");
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
            printf("Error setting Ctrl Handler! Error %d\n", GetLastError());
        }
#elif HAVE_SIGNAL
        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            printf("Can't catch SIGINT\n");
        }
#endif

#if defined(ENABLE_FIRMWARE_EXAMPLE)
        fwpush_test(&args);
#endif

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
