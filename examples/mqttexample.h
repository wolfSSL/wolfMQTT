/* mqttexample.h
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

#ifndef WOLFMQTT_EXAMPLE_H
#define WOLFMQTT_EXAMPLE_H

#include "wolfmqtt/mqtt_client.h"

#ifdef __cplusplus
    extern "C" {
#endif

/* Compatibility Options */
#ifdef NO_EXIT
    #undef exit
    #define exit(rc) return rc
#endif

#ifndef MY_EX_USAGE
#define MY_EX_USAGE 2 /* Exit reason code */
#endif

/* STDIN / FGETS for examples */
#ifndef WOLFMQTT_NO_STDIO
    /* For Linux/Mac */
    #if !defined(FREERTOS) && !defined(USE_WINDOWS_API) && \
        !defined(FREESCALE_MQX) && !defined(FREESCALE_KSDK_MQX) && \
        !defined(MICROCHIP_MPLAB_HARMONY) && !defined(WOLFMQTT_ZEPHYR)
        /* Make sure its not explicitly disabled and not already defined */
        #if !defined(WOLFMQTT_NO_STDIN_CAP) && \
            !defined(WOLFMQTT_ENABLE_STDIN_CAP)
            /* Wake on stdin activity */
            #define WOLFMQTT_ENABLE_STDIN_CAP
        #endif
    #endif

    #ifdef WOLFMQTT_ENABLE_STDIN_CAP
        #ifndef XFGETS
            #define XFGETS     fgets
        #endif
        #ifndef STDIN
            #define STDIN 0
        #endif
    #endif
#endif /* !WOLFMQTT_NO_STDIO */


/* Default Configurations */

#ifndef DEFAULT_MQTT_HOST
    /* Default MQTT host broker to use,
     * when none is specified in the examples */
    #define DEFAULT_MQTT_HOST   "test.mosquitto.org"
    /* "iot.eclipse.org" */
    /* "broker.emqx.io" */
    /* "broker.hivemq.com" */
#endif

#define DEFAULT_CMD_TIMEOUT_MS  30000
#define DEFAULT_CON_TIMEOUT_MS  5000
#define DEFAULT_CHK_TIMEOUT_S   2
#define DEFAULT_MQTT_QOS        MQTT_QOS_0
#define DEFAULT_KEEP_ALIVE_SEC  60
#define DEFAULT_CLIENT_ID       "WolfMQTTClient"
#ifndef WOLFMQTT_TOPIC_NAME
    #define WOLFMQTT_TOPIC_NAME     "wolfMQTT/example/"
    #define DEFAULT_TOPIC_NAME      WOLFMQTT_TOPIC_NAME"testTopic"
#else
    #define DEFAULT_TOPIC_NAME      WOLFMQTT_TOPIC_NAME
#endif
#define DEFAULT_AUTH_METHOD    "EXTERNAL"
#define PRINT_BUFFER_SIZE       80
#define DEFAULT_MESSAGE         "test"

#ifdef WOLFMQTT_V5
#define DEFAULT_MAX_PKT_SZ      1024*1024 /* The max MQTT control packet size
                                             the client is willing to accept. */
#define DEFAULT_SUB_ID          1 /* Sub ID starts at 1 */
#define DEFAULT_SESS_EXP_INT    0xFFFFFFFF
#endif

/* certs are either static or extern, depending on the specific example */
#ifdef WOLFMQTT_EXTERN_CERT
    #undef  WOLFMQTT_EXAMPLE_CERT
    #define WOLFMQTT_EXAMPLE_CERT /* init extern from mqttexample.h */
    extern const char* root_ca;
    extern const char* device_cert;
    extern const char* device_priv_key;
#else
    #undef  WOLFMQTT_EXAMPLE_CERT
    #define WOLFMQTT_EXAMPLE_CERT static
#endif

/* MQTT Client state */
typedef enum _MQTTCtxState {
    WMQ_BEGIN = 0,
    WMQ_NET_INIT,
    WMQ_INIT,
    WMQ_TCP_CONN,
    WMQ_MQTT_CONN,
    WMQ_SUB,
    WMQ_PUB,
    WMQ_WAIT_MSG,
    WMQ_PING,
    WMQ_UNSUB,
    WMQ_DISCONNECT,
    WMQ_NET_DISCONNECT,
    WMQ_DONE
} MQTTCtxState;

/* MQTT Client context */
/* This is used for the examples as reference */
/* Use of this structure allow non-blocking context */
typedef struct _MQTTCtx {
    MQTTCtxState stat;

    void* app_ctx; /* For storing application specific data */

    /* client and net containers */
    MqttClient client;
    MqttNet net;

    /* temp mqtt containers */
    MqttConnect connect;
    MqttMessage lwt_msg;
    MqttSubscribe subscribe;
    MqttUnsubscribe unsubscribe;
    MqttTopic topics[1];
    MqttPublish publish;
    MqttDisconnect disconnect;
    MqttPing ping;
#ifdef WOLFMQTT_SN
    SN_Publish publishSN;
#endif

    /* configuration */
    MqttQoS qos;
    const char* app_name;
    const char* host;
    const char* username;
    const char* password;
    const char* topic_name;
    const char* message;
    const char* pub_file;
    const char* client_id;
#if defined (ENABLE_MQTT_TLS)
    const char* ca_file;
    const char* mtls_keyfile;
    const char* mtls_certfile;
#endif
    byte *tx_buf, *rx_buf;
    int return_code;
    int use_tls;
    int retain;
    int enable_lwt;
#ifdef WOLFMQTT_V5
    int      max_packet_size;
#endif
    word32 cmd_timeout_ms;
#ifdef WOLFMQTT_NONBLOCK
    word32 start_sec; /* used for timeout and keep-alive */
#endif
    word16 keep_alive_sec;
    word16 port;
#ifdef WOLFMQTT_V5
    word16  topic_alias;
    word16  topic_alias_max; /* Server property */
#endif
    byte    clean_session;
    byte    test_mode;
    byte    debug_on:1; /* enable debug messages in example */
#ifdef WOLFMQTT_V5
    byte    subId_not_avail; /* Server property */
    byte    enable_eauth; /* Enhanced authentication */
#endif
    unsigned int dynamicTopic:1;
    unsigned int dynamicClientId:1;
#ifdef WOLFMQTT_NONBLOCK
    unsigned int useNonBlockMode:1; /* set to use non-blocking mode.
        network callbacks can return MQTT_CODE_CONTINUE to indicate "would block" */
#endif
} MQTTCtx;


void mqtt_show_usage(MQTTCtx* mqttCtx);
void mqtt_init_ctx(MQTTCtx* mqttCtx);
void mqtt_free_ctx(MQTTCtx* mqttCtx);
int mqtt_parse_args(MQTTCtx* mqttCtx, int argc, char** argv);
int err_sys(const char* msg);

int mqtt_tls_cb(MqttClient* client);

#ifdef WOLFMQTT_SN
int mqtt_dtls_cb(MqttClient* client);
#endif

word16 mqtt_get_packetid(void);

#ifdef WOLFMQTT_NONBLOCK
int mqtt_check_timeout(int rc, word32* start_sec, word32 timeout_sec);
#endif

int mqtt_fill_random_hexstr(char* buf, word32 bufLen);
char* mqtt_append_random(const char* inStr, word32 inLen);

int mqtt_file_load(const char* filePath, byte** fileBuf, int *fileLen);

#ifdef WOLFSSL_ENCRYPTED_KEYS
int mqtt_password_cb(char* passwd, int sz, int rw, void* userdata);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_EXAMPLE_H */
