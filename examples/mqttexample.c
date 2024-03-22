/* mqttexample.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
#include "examples/mqttport.h"


/* locals */
static volatile word16 mPacketIdLast;
static const char* kDefTopicName = DEFAULT_TOPIC_NAME;
static const char* kDefClientId =  DEFAULT_CLIENT_ID;

/* argument parsing */
static int myoptind = 0;
static char* myoptarg = NULL;

#ifdef ENABLE_MQTT_TLS
#ifdef HAVE_SNI
static int useSNI;
static const char* mTlsSniHostName = NULL;
#endif
#ifdef HAVE_PQC
static const char* mTlsPQAlg = NULL;
#endif
#endif /* ENABLE_MQTT_TLS */

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
    ret = 0; /* success */
#endif
    return ret;
}

int mqtt_fill_random_hexstr(char* buf, word32 bufLen)
{
    int rc = 0;
    word32 pos = 0, sz, i;
    const char kHexChar[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    byte rndBytes[32]; /* fill up to x bytes at a time */

    while (rc == 0 && pos < bufLen) {
        sz = bufLen - pos;
        if (sz > (int)sizeof(rndBytes))
            sz = (int)sizeof(rndBytes);
        sz /= 2; /* 1 byte expands to 2 bytes */

        rc = mqtt_get_rand(rndBytes, sz);
        if (rc == 0) {
            /* Convert random to hex string */
            for (i=0; i<sz; i++) {
                byte in = rndBytes[i];
                buf[pos + (i*2)] =   kHexChar[in >> 4];
                buf[pos + (i*2)+1] = kHexChar[in & 0xf];
            }
            pos += sz*2;
        }
        else {
            PRINTF("MQTT Fill Random Failed! %d", rc);
        }
    }
    return rc;
}

#ifndef TEST_RAND_SZ
#define TEST_RAND_SZ 4
#endif
char* mqtt_append_random(const char* inStr, word32 inLen)
{
    int rc = 0;
    char *tmp;

    tmp = (char*)WOLFMQTT_MALLOC(inLen + 1 + (TEST_RAND_SZ*2) + 1);
    if (tmp == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == 0) {
        /* Format: inStr + `_` randhex + null term */
        XMEMCPY(tmp, inStr, inLen);
        tmp[inLen] = '_';
        rc = mqtt_fill_random_hexstr(tmp + inLen + 1, (TEST_RAND_SZ*2));
        tmp[inLen + 1 + (TEST_RAND_SZ*2)] = '\0'; /* null term */
    }
    if (rc != 0) {
        WOLFMQTT_FREE(tmp);
        tmp = NULL;
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
        PRINTF("-t          Enable TLS"); /* Note: this string is used in test
                                           * scripts to detect TLS feature */
        PRINTF("-A <file>   Load CA (validate peer)");
        PRINTF("-K <key>    Use private key (for TLS mutual auth)");
        PRINTF("-c <cert>   Use certificate (for TLS mutual auth)");
    #ifndef ENABLE_MQTT_CURL
        #ifdef HAVE_SNI
        /* Remove SNI args for sn-client */
        if(XSTRNCMP(mqttCtx->app_name, "sn-client", 10)){
            PRINTF("-S <str>    Use Host Name Indication, blank defaults to host");
        }
        #endif /* HAVE_SNI */
        #ifdef HAVE_PQC
        PRINTF("-Q <str>    Use Key Share with post-quantum algorithm");
        #endif /* HAVE_PQC */
    #endif /* !ENABLE_MQTT_CURL */
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
    if (!mqttCtx->debug_on) {
        PRINTF("-d          Enable example debug messages");
    }
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
    mqttCtx->debug_on = 1;
#ifdef WOLFMQTT_V5
    mqttCtx->max_packet_size = DEFAULT_MAX_PKT_SZ;
    mqttCtx->topic_alias = 1;
    mqttCtx->topic_alias_max = 1;
#endif
#ifdef WOLFMQTT_DEFAULT_TLS
    mqttCtx->use_tls = WOLFMQTT_DEFAULT_TLS;
#endif
#ifdef ENABLE_MQTT_TLS
    mqttCtx->ca_file = NULL;
    mqttCtx->mtls_keyfile = NULL;
    mqttCtx->mtls_certfile = NULL;
#endif
    mqttCtx->app_name = "mqttclient";
    mqttCtx->message = DEFAULT_MESSAGE;
}

int mqtt_parse_args(MQTTCtx* mqttCtx, int argc, char** argv)
{
    int rc;

    #ifdef ENABLE_MQTT_TLS
        #ifdef ENABLE_MQTT_CURL
            #define MQTT_TLS_ARGS "c:A:K:"
        #else
            #define MQTT_TLS_ARGS "c:A:K:S;Q:"
        #endif
    #else
        #define MQTT_TLS_ARGS ""
    #endif
    #ifdef WOLFMQTT_V5
        #define MQTT_V5_ARGS "P:"
    #else
        #define MQTT_V5_ARGS ""
    #endif

    while ((rc = mygetopt(argc, argv, "?h:p:q:sk:i:lu:w:m:n:C:Tf:rtd" \
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

        case 'd':
            mqttCtx->debug_on = 1;
            break;

    #ifdef ENABLE_MQTT_TLS
        case 'A':
            mqttCtx->ca_file = myoptarg;
            break;
        case 'c':
            mqttCtx->mtls_certfile = myoptarg;
            break;
        case 'K':
            mqttCtx->mtls_keyfile = myoptarg;
            break;
    #ifndef ENABLE_MQTT_CURL
        case 'S':
        #ifdef HAVE_SNI
            useSNI = 1;
            mTlsSniHostName = myoptarg;
        #else
            PRINTF("To use '-S', enable SNI in wolfSSL");
        #endif
            break;
        case 'Q':
        #ifdef HAVE_PQC
            mTlsPQAlg = myoptarg;
        #else
            PRINTF("To use '-Q', build wolfSSL with --with-liboqs");
        #endif
            break;
    #endif /* !ENABLE_MQTT_CURL */
    #endif /* ENABLE_MQTT_TLS */

    #ifdef WOLFMQTT_V5
        case 'P':
            mqttCtx->max_packet_size = XATOI(myoptarg);
            break;
    #endif

        default:
            mqtt_show_usage(mqttCtx);
            return MY_EX_USAGE;
        }

        /* Remove SNI functionality for sn-client */
        if(!XSTRNCMP(mqttCtx->app_name, "sn-client", 10)){
        #ifdef HAVE_SNI
            useSNI=0;
        #endif
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

#if defined(__GNUC__) && !defined(NO_EXIT) && !defined(WOLFMQTT_ZEPHYR)
    __attribute__ ((noreturn))
#endif
int err_sys(const char* msg)
{
    if (msg) {
        PRINTF("wolfMQTT error: %s", msg);
    }
    exit(EXIT_FAILURE);
#ifdef WOLFMQTT_ZEPHYR
    /* Zephyr compiler produces below warning. Let's silence it.
     * warning: 'noreturn' function does return
     * 477 | }
     *     | ^
     */
    return 0;
#endif
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

    /* Default to 2s timeout. This function sometimes incorrectly
     * triggers if 1s is used because of rounding. */
    if (timeout_sec == 0) {
        timeout_sec = DEFAULT_CHK_TIMEOUT_S;
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

#ifdef WOLFSSL_ENCRYPTED_KEYS
int mqtt_password_cb(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;
    (void)userdata;
    if (userdata != NULL) {
        XSTRNCPY(passwd, (char*)userdata, sz);
        return (int)XSTRLEN((char*)userdata);
    }
    else {
        XSTRNCPY(passwd, "yassl123", sz);
        return (int)XSTRLEN(passwd);
    }
}
#endif

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
    SocketContext * sock = (SocketContext *)client->net->context;

    /* Use highest available and allow downgrade. If wolfSSL is built with
     * old TLS support, it is possible for a server to force a downgrade to
     * an insecure version. */
    client->tls.ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER,
                mqtt_tls_verify_cb);

        /* default to success */
        rc = WOLFSSL_SUCCESS;

#if !defined(NO_CERT)
    #if !defined(NO_FILESYSTEM)
        if (sock->mqttCtx->ca_file) {
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx,
                sock->mqttCtx->ca_file, NULL);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading CA %s: %d (%s)", sock->mqttCtx->ca_file,
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }
        }
        if (sock->mqttCtx->mtls_certfile && sock->mqttCtx->mtls_keyfile) {
            /* Load If using a mutual authentication */
            rc = wolfSSL_CTX_use_certificate_file(client->tls.ctx,
                sock->mqttCtx->mtls_certfile, WOLFSSL_FILETYPE_PEM);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading certificate %s: %d (%s)",
                    sock->mqttCtx->mtls_certfile,
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }

        #ifdef WOLFSSL_ENCRYPTED_KEYS
            /* Setup password callback for pkcs8 key */
            wolfSSL_CTX_set_default_passwd_cb(client->tls.ctx,
                    mqtt_password_cb);
        #endif

            rc = wolfSSL_CTX_use_PrivateKey_file(client->tls.ctx,
                sock->mqttCtx->mtls_keyfile, WOLFSSL_FILETYPE_PEM);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading key %s: %d (%s)",
                    sock->mqttCtx->mtls_keyfile,
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }
        }
    #else
        /* Note: Zephyr example uses NO_FILESYSTEM */
    #ifdef WOLFSSL_ENCRYPTED_KEYS
        /* Setup password callback for pkcs8 key */
        wolfSSL_CTX_set_default_passwd_cb(client->tls.ctx,
                mqtt_password_cb);
    #endif
        /* Examples for loading buffer directly */
        /* Load CA certificate buffer */
        rc = wolfSSL_CTX_load_verify_buffer_ex(client->tls.ctx,
                (const byte*)root_ca, (long)sizeof(root_ca),
                WOLFSSL_FILETYPE_ASN1, 0, WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY);

        /* Load Client Cert */
        if (rc == WOLFSSL_SUCCESS) {
            rc = wolfSSL_CTX_use_certificate_buffer(client->tls.ctx,
                (const byte*)device_cert, (long)sizeof(device_cert),
                WOLFSSL_FILETYPE_ASN1);
        }

        /* Load Private Key */
        if (rc == WOLFSSL_SUCCESS) {
            rc = wolfSSL_CTX_use_PrivateKey_buffer(client->tls.ctx,
                (const byte*)device_priv_key, (long)sizeof(device_priv_key),
                WOLFSSL_FILETYPE_ASN1);
        }
    #endif /* !NO_FILESYSTEM */
#endif /* !NO_CERT */
#ifdef HAVE_SNI
        if ((rc == WOLFSSL_SUCCESS) && (mTlsSniHostName != NULL)) {
            rc = wolfSSL_CTX_UseSNI(client->tls.ctx, WOLFSSL_SNI_HOST_NAME,
                    mTlsSniHostName, (word16) XSTRLEN(mTlsSniHostName));
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("UseSNI failed");
            }
        }
#endif /* HAVE_SNI */
#ifdef HAVE_PQC
        if ((rc == WOLFSSL_SUCCESS) && (mTlsPQAlg != NULL)) {
            int group = 0;
            if (XSTRCMP(mTlsPQAlg, "KYBER_LEVEL1") == 0) {
                group = WOLFSSL_KYBER_LEVEL1;
            } else if (XSTRCMP(mTlsPQAlg, "P256_KYBER_LEVEL1") == 0) {
                group = WOLFSSL_P256_KYBER_LEVEL1;
            } else {
                PRINTF("Invalid post-quantum KEM specified");
            }

            if (group != 0) {
                client->tls.ssl = wolfSSL_new(client->tls.ctx);
                if (client->tls.ssl == NULL) {
                    rc = WOLFSSL_FAILURE;
                }

                if (rc == WOLFSSL_SUCCESS) {
                    rc = wolfSSL_UseKeyShare(client->tls.ssl, group);
                    if (rc != WOLFSSL_SUCCESS) {
                        PRINTF("Use key share failed");
                    }
                }
            }
        }
#endif /* HAVE_PQC */
    }

#if defined(NO_CERT) || defined(NO_FILESYSTEM)
    (void)sock;
#endif

    PRINTF("MQTT TLS Setup (%d)", rc);

    return rc;
}

#ifdef WOLFMQTT_SN
int mqtt_dtls_cb(MqttClient* client) {
#ifdef WOLFSSL_DTLS
    int rc = WOLFSSL_FAILURE;
    SocketContext * sock = (SocketContext *)client->net->context;

    client->tls.ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    if (client->tls.ctx) {
        wolfSSL_CTX_set_verify(client->tls.ctx, WOLFSSL_VERIFY_PEER,
                mqtt_tls_verify_cb);

        /* default to success */
        rc = WOLFSSL_SUCCESS;

#if !defined(NO_CERT) && !defined(NO_FILESYSTEM)
        if (sock->mqttCtx->ca_file) {
            /* Load CA certificate file */
            rc = wolfSSL_CTX_load_verify_locations(client->tls.ctx,
                sock->mqttCtx->ca_file, NULL);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading CA %s: %d (%s)", sock->mqttCtx->ca_file,
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }
        }
        if (sock->mqttCtx->mtls_certfile && sock->mqttCtx->mtls_keyfile) {
            /* Load If using a mutual authentication */
            rc = wolfSSL_CTX_use_certificate_file(client->tls.ctx,
                sock->mqttCtx->mtls_certfile, WOLFSSL_FILETYPE_PEM);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading certificate %s: %d (%s)",
                    sock->mqttCtx->mtls_certfile,
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }

            rc = wolfSSL_CTX_use_PrivateKey_file(client->tls.ctx,
                sock->mqttCtx->mtls_keyfile, WOLFSSL_FILETYPE_PEM);
            if (rc != WOLFSSL_SUCCESS) {
                PRINTF("Error loading key %s: %d (%s)",
                    sock->mqttCtx->mtls_keyfile,
                    rc, wolfSSL_ERR_reason_error_string(rc));
                return rc;
            }
        }
#else
    (void)sock;
#endif

        client->tls.ssl = wolfSSL_new(client->tls.ctx);
        if (client->tls.ssl == NULL) {
            rc = WOLFSSL_FAILURE;
            return rc;
        }
    }

    PRINTF("MQTT DTLS Setup (%d)", rc);
#else /* WOLFSSL_DTLS */
    (void)client;
    int rc = 0;
    PRINTF("MQTT DTLS Setup - Must enable DTLS in wolfSSL!");
#endif
    return rc;
}
#endif /* WOLFMQTT_SN */
#else
int mqtt_tls_cb(MqttClient* client)
{
    (void)client;
    return 0;
}
#ifdef WOLFMQTT_SN
int mqtt_dtls_cb(MqttClient* client)
{
    (void)client;
    return 0;
}
#endif
#endif /* ENABLE_MQTT_TLS */

int mqtt_file_load(const char* filePath, byte** fileBuf, int *fileLen)
{
#if !defined(NO_FILESYSTEM)
    int rc = 0;
    XFILE file = NULL;
    long int pos = -1L;

    /* Check arguments */
    if (filePath == NULL || XSTRLEN(filePath) == 0 || fileLen == NULL ||
        fileBuf == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Open file */
    file = XFOPEN(filePath, "rb");
    if (file == NULL) {
        PRINTF("File '%s' does not exist!", filePath);
        rc = EXIT_FAILURE;
        goto exit;
    }

    /* Determine length of file */
    if (XFSEEK(file, 0, XSEEK_END) != 0) {
        PRINTF("fseek() failed");
        rc = EXIT_FAILURE;
        goto exit;
     }

    pos = (int)XFTELL(file);
    if (pos == -1L) {
       PRINTF("ftell() failed");
       rc = EXIT_FAILURE;
       goto exit;
    }

    *fileLen = (int)pos;
    if (XFSEEK(file, 0, XSEEK_SET) != 0) {
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
    rc = (int)XFREAD(*fileBuf, 1, *fileLen, file);
    if (rc != *fileLen) {
        PRINTF("Error reading file! %d", rc);
        rc = EXIT_FAILURE;
        goto exit;
    }
    rc = 0; /* Success */

exit:
    if (file) {
        XFCLOSE(file);
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
