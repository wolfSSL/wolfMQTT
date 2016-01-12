/* fwclient.c
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
#include "examples/firmware/fwclient.h"
#include "examples/firmware/firmware.h"

/* Configuration */
#define DEFAULT_CMD_TIMEOUT_MS  30000
#define DEFAULT_CON_TIMEOUT_MS  5000
#define DEFAULT_MQTT_QOS        MQTT_QOS_2
#define DEFAULT_KEEP_ALIVE_SEC  240
#define DEFAULT_CLIENT_ID       "WolfMQTTFwClient"
#define DEFAULT_SAVE_AS         "firmware.bin"

#define MAX_BUFFER_SIZE         FIRMWARE_MAX_PACKET

/* Globals */
static int mStopRead = 0;
const char* mTlsFile = NULL;
static byte* mFwBuf;
static const char* mFwFile = DEFAULT_SAVE_AS;

/* Usage */
static void Usage(void)
{
    printf("fwclient:\n");
    printf("-?          Help, print this usage\n");
    printf("-f <file>   Save firmware file as, default %s\n",
        DEFAULT_SAVE_AS);
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

static int fwfile_save(const char* filePath, byte* fileBuf, int fileLen)
{
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
        printf("File %s write error!\n", filePath);
        ret = EXIT_FAILURE;
        goto exit;
    }

    /* Save file */
    ret = (int)fwrite(fileBuf, 1, fileLen, file);
    if (ret != fileLen) {
        printf("Error reading file! %d", ret);
        ret = EXIT_FAILURE;
        goto exit;
    }

    printf("Saved %d bytes to %s\n", fileLen, filePath);

exit:
    if (file) {
        fclose(file);
    }
    return ret;
}

static int fw_message_process(byte* buffer, word32 len)
{
    int rc;
    FirmwareHeader* header = (FirmwareHeader*)buffer;
    byte *sigBuf, *pubKeyBuf, *fwBuf;
    ecc_key eccKey;
    word32 check_len = sizeof(FirmwareHeader) + header->sigLen +
        header->pubKeyLen + header->fwLen;

    /* Verify entire message was received */
    if (len != check_len) {
        printf("Message header vs. actual size mismatch! %d != %d\n",
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
        printf("Firmware Signature Verification: %s (%d)\n",
            (rc == 0) ? "Pass" : "Fail", rc);

        if (rc == 0) {
            /* TODO: Process firmware image */
            /* For example, save to disk using topic name */
            fwfile_save(mFwFile, fwBuf, header->fwLen);
        }
    }
    else {
        printf("ECC public key import failed! %d\n", rc);
    }
    wc_ecc_free(&eccKey);

    return rc;
}

static int mqttclient_message_cb(MqttClient *client, MqttMessage *msg,
    byte msg_new, byte msg_done)
{
    (void)client; /* Supress un-used argument */

    /* Verify this message is for the firmware topic */
    if (msg_new &&
        memcmp(msg->topic_name, FIRMWARE_TOPIC_NAME,
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
        printf("MQTT Firmware Message: Qos %d, Len %u\n",
            msg->qos, msg->total_len);
    }

    if (mFwBuf) {
        XMEMCPY(&mFwBuf[msg->buffer_pos], msg->buffer, msg->buffer_len);

        /* Process message if done */
        if (msg_done) {
            fw_message_process(mFwBuf, msg->total_len);

            /* Free */
            WOLFMQTT_FREE(mFwBuf);
            mFwBuf = NULL;
        }
    }

    /* Return negative to termine publish processing */
    return MQTT_CODE_SUCCESS;
}

void* fwclient_test(void* args)
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
    const char* username = NULL;
    const char* password = NULL;
    byte *tx_buf = NULL, *rx_buf = NULL;

    int     argc = ((func_args*)args)->argc;
    char**  argv = ((func_args*)args)->argv;

    ((func_args*)args)->return_code = -1; /* error state */

    while ((rc = mygetopt(argc, argv, "?f:h:p:tc:q:sk:i:u:w:")) != -1) {
        switch ((char)rc) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);

            case 'f':
                mFwFile = myoptarg;
                break;

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

            default:
                Usage();
                exit(MY_EX_USAGE);
        }
    }

    myoptind = 0; /* reset for test cases */

    /* Start example MQTT Client */
    printf("MQTT Firmware Client: QoS %d\n", qos);

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
            MqttSubscribe subscribe;
            MqttTopic topics[1], *topic;
            int i;

            /* Validate Connect Ack info */
            printf("MQTT Connect Ack: Return Code %u, Session Present %d\n",
                connect.ack.return_code,
                (connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ?
                    1 : 0
            );

            /* Subscribe Topic */
            XMEMSET(&subscribe, 0, sizeof(MqttSubscribe));
            subscribe.packet_id = mqttclient_get_packetid();
            subscribe.topic_count = 1;
            subscribe.topics = topics;
            topics[0].topic_filter = FIRMWARE_TOPIC_NAME;
            topics[0].qos = qos;
            rc = MqttClient_Subscribe(&client, &subscribe);
            printf("MQTT Subscribe: %s (%d)\n",
                MqttClient_ReturnCodeToString(rc), rc);
            for (i = 0; i < subscribe.topic_count; i++) {
                topic = &subscribe.topics[i];
                printf("  Topic %s, Qos %u, Return Code %u\n",
                    topic->topic_filter, topic->qos, topic->return_code);
            }

            /* Read Loop */
            printf("MQTT Waiting for message...\n");
            while (mStopRead == 0) {
                /* Try and read packet */
                rc = MqttClient_WaitMessage(&client, DEFAULT_CMD_TIMEOUT_MS);
                if (rc != MQTT_CODE_SUCCESS && rc != MQTT_CODE_ERROR_TIMEOUT) {
                    /* There was an error */
                    printf("MQTT Message Wait: %s (%d)\n",
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }

                /* Keep Alive */
                rc = MqttClient_Ping(&client);
                if (rc != MQTT_CODE_SUCCESS) {
                    printf("MQTT Ping Keep Alive Error: %s (%d)\n",
                        MqttClient_ReturnCodeToString(rc), rc);
                    break;
                }
            }

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

    /* Cleanup network */
    rc = MqttClientNet_DeInit(&net);
    printf("MQTT Net DeInit: %s (%d)\n",
        MqttClient_ReturnCodeToString(rc), rc);

    ((func_args*)args)->return_code = 0;

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
        fwclient_test(&args);
#endif

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */
