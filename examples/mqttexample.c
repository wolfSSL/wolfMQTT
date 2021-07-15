/* mqttexample.c
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
#include "examples/mqttexample.h"
#include "examples/mqttnet.h"


/* locals */
static volatile word16 mPacketIdLast;
static const char* kDefTopicName = DEFAULT_TOPIC_NAME;
static const char* kDefClientId =  DEFAULT_CLIENT_ID;

/* argument parsing */
static int myoptind = 0;
static char* myoptarg = NULL;

#ifdef ENABLE_MQTT_TLS
static const char* mTlsCaFile;
static const char* mTlsCertFile;
static const char* mTlsKeyFile;
#ifdef HAVE_SNI
static int useSNI = 0;
static const char* mTlsSniHostName;
#endif
#endif

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

        if (XSTRNCMP(argv[myoptind], "--", 2) == 0) {
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
    else if (*cp == ';') {
        myoptarg = (char*)"";
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            /* Check if next argument is not a parameter argument */
            if (argv[myoptind] && argv[myoptind][0] != '-') {
                myoptarg = argv[myoptind];
                myoptind++;
            }
        }
    }

    return c;
}


/* used for testing only, requires wolfSSL RNG */
#ifdef ENABLE_MQTT_TLS
#include <wolfssl/wolfcrypt/random.h>
#endif

static int mqtt_get_rand(byte* data, word32 len)
{
    int ret = -1;
#ifdef ENABLE_MQTT_TLS
    WC_RNG rng;
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(&rng, data, len);
        wc_FreeRng(&rng);
    }
#elif defined(HAVE_RAND)
    word32 i;
    for (i = 0; i<len; i++) {
        data[i] = (byte)rand();
    }
#endif
    return ret;
}

#ifndef TEST_RAND_SZ
#define TEST_RAND_SZ 4
#endif
static char* mqtt_append_random(const char* inStr, word32 inLen)
{
    int rc;
    const char kHexChar[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    byte rndBytes[TEST_RAND_SZ], rndHexStr[TEST_RAND_SZ*2];
    char *tmp = NULL;

    rc = mqtt_get_rand(rndBytes, (word32)sizeof(rndBytes));
    if (rc == 0) {
        /* Convert random to hex string */
        int i;
        for (i=0; i<(int)sizeof(rndBytes); i++) {
            byte in = rndBytes[i];
            rndHexStr[(i*2)] =   kHexChar[in >> 4];
            rndHexStr[(i*2)+1] = kHexChar[in & 0xf];
        }
    }
    if (rc == 0) {
        /* Allocate topic name and client id */
        tmp = (char*)WOLFMQTT_MALLOC(inLen + 1 + sizeof(rndHexStr) + 1);
        if (tmp == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }
    if (rc == 0) {
        /* Format: inStr + `_` randhex + null term */
        XMEMCPY(tmp, inStr, inLen);
        tmp[inLen] = '_';
        XMEMCPY(tmp + inLen + 1, rndHexStr, sizeof(rndHexStr));
        tmp[inLen + 1 + sizeof(rndHexStr)] = '\0';
    }
    return tmp;
}

void mqtt_show_usage(MQTTCtx* mqttCtx)
{
    PRINTF("%s:", mqttCtx->app_name);
    PRINTF("-?          Help, print this usage");
    PRINTF("-h <host>   Host to connect to, default: %s",
            mqttCtx->host);
#ifdef ENABLE_MQTT_TLS
    PRINTF("-p <num>    Port to connect on, default: Normal %d, TLS %d",
            MQTT_DEFAULT_PORT, MQTT_SECURE_PORT);
    PRINTF("-t          Enable TLS");
    PRINTF("-A <file>   Load CA (validate peer)");
    PRINTF("-K <key>    Use private key (for TLS mutual auth)");
    PRINTF("-c <cert>   Use certificate (for TLS mutual auth)");
#ifdef HAVE_SNI
    PRINTF("-S <str>    Use Host Name Indication, blank defaults to host");
#endif
#else
    PRINTF("-p <num>    Port to connect on, default: %d",
            MQTT_DEFAULT_PORT);
#endif
    PRINTF("-q <num>    Qos Level 0-2, default: %d",
            mqttCtx->qos);
    PRINTF("-s          Disable clean session connect flag");
    PRINTF("-k <num>    Keep alive seconds, default: %d",
            mqttCtx->keep_alive_sec);
    PRINTF("-i <id>     Client Id, default: %s",
            mqttCtx->client_id);
    PRINTF("-l          Enable LWT (Last Will and Testament)");
    PRINTF("-u <str>    Username");
    PRINTF("-w <str>    Password");
    if (mqttCtx->message) {
        /* Only mqttclient example can set message from CLI */
        PRINTF("-m <str>    Message, default: %s", mqttCtx->message);
    }
    PRINTF("-n <str>    Topic name, default: %s", mqttCtx->topic_name);
    PRINTF("-r          Set Retain flag on publish message");
    PRINTF("-C <num>    Command Timeout, default: %dms",
            mqttCtx->cmd_timeout_ms);
#ifdef WOLFMQTT_V5
    PRINTF("-P <num>    Max packet size the client will accept, default: %d",
            DEFAULT_MAX_PKT_SZ);
#endif
    PRINTF("-T          Test mode");
    PRINTF("-f <file>   Use file contents for publish");
}

void mqtt_init_ctx(MQTTCtx* mqttCtx)
{
    XMEMSET(mqttCtx, 0, sizeof(MQTTCtx));
    mqttCtx->host = DEFAULT_MQTT_HOST;
    mqttCtx->qos = DEFAULT_MQTT_QOS;
    mqttCtx->clean_session = 1;
    mqttCtx->keep_alive_sec = DEFAULT_KEEP_ALIVE_SEC;
    mqttCtx->client_id = kDefClientId;
    mqttCtx->topic_name = kDefTopicName;
    mqttCtx->cmd_timeout_ms = DEFAULT_CMD_TIMEOUT_MS;
#ifdef WOLFMQTT_V5
    mqttCtx->max_packet_size = DEFAULT_MAX_PKT_SZ;
    mqttCtx->topic_alias = 1;
    mqttCtx->topic_alias_max = 1;
#endif
}

int mqtt_parse_args(MQTTCtx* mqttCtx, int argc, char** argv)
{
    int rc;

    #ifdef ENABLE_MQTT_TLS
        #define MQTT_TLS_ARGS "c:A:K:S;"
    #else
        #define MQTT_TLS_ARGS ""
    #endif
    #ifdef WOLFMQTT_V5
        #define MQTT_V5_ARGS "P:"
    #else
        #define MQTT_V5_ARGS ""
    #endif

    while ((rc = mygetopt(argc, argv, "?h:p:q:sk:i:lu:w:m:n:C:Tf:rt" \
            MQTT_TLS_ARGS MQTT_V5_ARGS)) != -1) {
        switch ((char)rc) {
        case '?' :
            mqtt_show_usage(mqttCtx);
            return MY_EX_USAGE;

        case 'h' :
            mqttCtx->host = myoptarg;
            break;

        case 'p' :
            mqttCtx->port = (word16)XATOI(myoptarg);
            if (mqttCtx->port == 0) {
                return err_sys("Invalid Port Number!");
            }
            break;

        case 'q' :
            mqttCtx->qos = (MqttQoS)((byte)XATOI(myoptarg));
            if (mqttCtx->qos > MQTT_QOS_2) {
                return err_sys("Invalid QoS value!");
            }
            break;

        case 's':
            mqttCtx->clean_session = 0;
            break;

        case 'k':
            mqttCtx->keep_alive_sec = XATOI(myoptarg);
            break;

        case 'i':
            mqttCtx->client_id = myoptarg;
            break;

        case 'l':
            mqttCtx->enable_lwt = 1;
            break;

        case 'u':
            mqttCtx->username = myoptarg;
            break;

        case 'w':
            mqttCtx->password = myoptarg;
            break;

        case 'm':
            mqttCtx->message = myoptarg;
            break;

        case 'n':
            mqttCtx->topic_name = myoptarg;
            break;

        case 'C':
            mqttCtx->cmd_timeout_ms = XATOI(myoptarg);
            break;

        case 'T':

            mqttCtx->test_mode = 1;
            break;

        case 'f':
            mqttCtx->pub_file = myoptarg;
            break;

        case 'r':
            mqttCtx->retain = 1;
            break;

        case 't':
            mqttCtx->use_tls = 1;
            break;

    #ifdef ENABLE_MQTT_TLS
        case 'A':
            mTlsCaFile = myoptarg;
            break;
        case 'c':
            mTlsCertFile = myoptarg;
            break;
        case 'K':
            mTlsKeyFile = myoptarg;
            break;
        case 'S':
        #ifdef HAVE_SNI
            useSNI = 1;
            mTlsSniHostName = myoptarg;
        #else
            PRINTF("To use '-S', enable SNI in wolfSSL");
        #endif
            break;
    #endif

    #ifdef WOLFMQTT_V5
        case 'P':
            mqttCtx->max_packet_size = XATOI(myoptarg);
            break;
    #endif

        default:
            mqtt_show_usage(mqttCtx);
            return MY_EX_USAGE;
        }
    }

    rc = 0;
    myoptind = 0; /* reset for test cases */

    /* if TLS not enable, check args */
#ifndef ENABLE_MQTT_TLS
    if (mqttCtx->use_tls) {
        PRINTF("Use TLS option not allowed (TLS not compiled in)");
        mqttCtx->use_tls = 0;
        if (mqttCtx->test_mode) {
            return MY_EX_USAGE;
        }
    }
#endif

#ifdef HAVE_SNI
    if ((useSNI == 1) && (XSTRLEN(mTlsSniHostName) == 0)) {
        /* Set SNI host name to host if -S was blank */
        mTlsSniHostName = mqttCtx->host;
    }
#endif

    /* for test mode only */
    /* add random data to end of client_id and topic_name */
    if (mqttCtx->test_mode && mqttCtx->topic_name == kDefTopicName) {
        char* topic_name = mqtt_append_random(kDefTopicName,
                (word32)XSTRLEN(kDefTopicName));
        if (topic_name) {
            mqttCtx->topic_name = (const char*)topic_name;
            mqttCtx->dynamicTopic = 1;
        }
    }
    if (mqttCtx->test_mode && mqttCtx->client_id == kDefClientId) {
        char* client_id = mqtt_append_random(kDefClientId,
                (word32)XSTRLEN(kDefClientId));
        if (client_id) {
            mqttCtx->client_id = (const char*)client_id;
            mqttCtx->dynamicClientId = 1;
        }
    }

    return rc;
}

void mqtt_free_ctx(MQTTCtx* mqttCtx)
{
    if (mqttCtx == NULL) {
        return;
    }

    if (mqttCtx->dynamicTopic && mqttCtx->topic_name) {
        WOLFMQTT_FREE((char*)mqttCtx->topic_name);
        mqttCtx->topic_name = NULL;
    }
    if (mqttCtx->dynamicClientId && mqttCtx->client_id) {
        WOLFMQTT_FREE((char*)mqttCtx->client_id);
        mqttCtx->client_id = NULL;
    }
}

#if defined(__GNUC__) && !defined(NO_EXIT)
    __attribute__ ((noreturn))
#endif
int err_sys(const char* msg)
{
    if (msg) {
        PRINTF("wolfMQTT error: %s", msg);
    }
    exit(EXIT_FAILURE);
}


word16 mqtt_get_packetid(void)
{
    /* Check rollover */
    if (mPacketIdLast >= MAX_PACKET_ID) {
        mPacketIdLast = 0;
    }

    return ++mPacketIdLast;
}

#ifdef WOLFMQTT_NONBLOCK
    #if defined(MICROCHIP_MPLAB_HARMONY)
        #include <system/tmr/sys_tmr.h>
    #else
        #include <time.h>
#endif

static word32 mqtt_get_timer_seconds(void)
{
    word32 timer_sec = 0;

#if defined(MICROCHIP_MPLAB_HARMONY)
    timer_sec = (word32)(SYS_TMR_TickCountGet() /
            SYS_TMR_TickCounterFrequencyGet());
#else
    /* Posix style time */
    timer_sec = (word32)time(0);
#endif

    return timer_sec;
}

int mqtt_check_timeout(int rc, word32* start_sec, word32 timeout_sec)
{
    word32 elapsed_sec;

    /* if start seconds not set or is not continue */
    if (*start_sec == 0 || rc != MQTT_CODE_CONTINUE) {
        *start_sec = mqtt_get_timer_seconds();
        return rc;
    }

    elapsed_sec = mqtt_get_timer_seconds();
    if (*start_sec < elapsed_sec) {
        elapsed_sec -= *start_sec;
        if (elapsed_sec >= timeout_sec) {
            *start_sec = mqtt_get_timer_seconds();
            PRINTF("Timeout timer %d seconds", timeout_sec);
            return MQTT_CODE_ERROR_TIMEOUT;
        }
    }

    return rc;
}
#endif /* WOLFMQTT_NONBLOCK */


#ifdef ENABLE_MQTT_TLS
static int mqtt_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    MQTTCtx *mqttCtx = NULL;
    char appName[PRINT_BUFFER_SIZE] = {0};

    if (store->userCtx != NULL) {
        /* The client.ctx was stored during MqttSocket_Connect. */
        mqttCtx = (MQTTCtx *)store->userCtx;
        XSTRNCPY(appName, " for ", PRINT_BUFFER_SIZE-1);
        XSTRNCAT(appName, mqttCtx->app_name,
                PRINT_BUFFER_SIZE-XSTRLEN(appName)-1);
    }

    PRINTF("MQTT TLS Verify Callback%s: PreVerify %d, Error %d (%s)",
            appName, preverify,
            store->error, store->error != 0 ?
                    wolfSSL_ERR_error_string(store->error, buffer) : "none");
    PRINTF("  Subject's domain name is %s", store->domain);

    if (store->error != 0) {
        /* Allowing to continue */
        /* Should check certificate and return 0 if not okay */
        PRINTF("  Allowing cert anyways");
    }

    return 1;
}

/* Use this callback to setup TLS certificates and verify callbacks */
int mqtt_tls_cb(MqttClient* client)
{
    int rc = WOLFSSL_FAILURE;

    client->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER,
                mqtt_tls_verify_cb);

        /* default to success */
        rc = WOLFSSL_SUCCESS;

#if !defined(NO_CERT)
    #if !defined(NO_FILESYSTEM)
        if (mTlsCaFile) {
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx,
                mTlsCaFile, NULL);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading CA %s: %d (%s)", mTlsCaFile, 
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }
        }
        if (mTlsCertFile && mTlsKeyFile) {
            /* Load If using a mutual authentication */
            rc = wolfSSL_CTX_use_certificate_file(client->tls.ctx,
                mTlsCertFile, WOLFSSL_FILETYPE_PEM);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading certificate %s: %d (%s)", mTlsCertFile, 
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }
            rc = wolfSSL_CTX_use_PrivateKey_file(client->tls.ctx,
                mTlsKeyFile, WOLFSSL_FILETYPE_PEM);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading key %s: %d (%s)", mTlsKeyFile, 
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }
        }
    #else
    #if 0
        /* Examples for loading buffer directly */
        /* Load CA certificate buffer */
        rc = wolfSSL_CTX_load_verify_buffer(client->tls.ctx,
            (const byte*)root_ca, (long)XSTRLEN(root_ca), WOLFSSL_FILETYPE_PEM);

        /* Load Client Cert */
        if (rc == WOLFSSL_SUCCESS)
            rc = wolfSSL_CTX_use_certificate_buffer(client->tls.ctx,
                (const byte*)device_cert, (long)XSTRLEN(device_cert),
                WOLFSSL_FILETYPE_PEM);

        /* Load Private Key */
        if (rc == WOLFSSL_SUCCESS)
            rc = wolfSSL_CTX_use_PrivateKey_buffer(client->tls.ctx,
                (const byte*)device_priv_key, (long)XSTRLEN(device_priv_key),
                WOLFSSL_FILETYPE_PEM);
    #endif
    #endif /* !NO_FILESYSTEM */
#endif /* !NO_CERT */
    }
#ifdef HAVE_SNI
    if ((rc == WOLFSSL_SUCCESS) && (mTlsSniHostName != NULL)) {
        rc = wolfSSL_CTX_UseSNI(client->tls.ctx, WOLFSSL_SNI_HOST_NAME,
                mTlsSniHostName, (word16) XSTRLEN(mTlsSniHostName));
        if (rc != WOLFSSL_SUCCESS) {
            PRINTF("UseSNI failed");
        }
    }
#endif /* HAVE_SNI */

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}
#else
int mqtt_tls_cb(MqttClient* client)
{
    (void)client;
    return 0;
}
#endif /* ENABLE_MQTT_TLS */

int mqtt_file_load(const char* filePath, byte** fileBuf, int *fileLen)
{
#if !defined(NO_FILESYSTEM)
    int rc = 0;
    FILE* file = NULL;
    long int pos = -1L;

    /* Check arguments */
    if (filePath == NULL || XSTRLEN(filePath) == 0 || fileLen == NULL ||
        fileBuf == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Open file */
    file = fopen(filePath, "rb");
    if (file == NULL) {
        PRINTF("File '%s' does not exist!", filePath);
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Determine length of file */
    if (fseek(file, 0, SEEK_END) != 0) {
        PRINTF("fseek() failed");
        rc = EXIT_FAILURE;
        goto exit;
     }

    pos = (int) ftell(file);
    if (pos == -1L) {
       PRINTF("ftell() failed");
       rc = EXIT_FAILURE;
       goto exit;
    }

    *fileLen = (int)pos;
    if (fseek(file, 0, SEEK_SET) != 0) {
        PRINTF("fseek() failed");
        rc = EXIT_FAILURE;
        goto exit;
     }
#ifdef DEBUG_WOLFMQTT
    PRINTF("File %s is %d bytes", filePath, *fileLen);
#endif

    /* Allocate buffer for image */
    *fileBuf = (byte*)WOLFMQTT_MALLOC(*fileLen);
    if (*fileBuf == NULL) {
        PRINTF("File buffer malloc failed!");
        rc = MQTT_CODE_ERROR_MEMORY;
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

#else
    (void)filePath;
    (void)fileBuf;
    (void)fileLen;
    PRINTF("File system support is not configured.");
    return EXIT_FAILURE;
#endif
}
