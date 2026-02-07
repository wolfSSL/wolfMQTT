/* mqtt_broker.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLFMQTT_BROKER_H
#define WOLFMQTT_BROKER_H

#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_socket.h"
#include "wolfmqtt/mqtt_client.h"

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFMQTT_BROKER

/* -------------------------------------------------------------------------- */
/* Socket type abstraction - override for non-POSIX platforms                  */
/* -------------------------------------------------------------------------- */
#ifndef BROKER_SOCKET_T
    #define BROKER_SOCKET_T        int
#endif
#ifndef BROKER_SOCKET_INVALID
    #define BROKER_SOCKET_INVALID  (-1)
#endif

/* -------------------------------------------------------------------------- */
/* Time abstraction - override for platforms without time.h                    */
/* -------------------------------------------------------------------------- */
#ifndef WOLFMQTT_BROKER_TIME_T
    #define WOLFMQTT_BROKER_TIME_T  unsigned long
#endif
/* Note: WOLFMQTT_BROKER_GET_TIME_S() default is defined in mqtt_broker.c
 * because it depends on <time.h> which is only included for POSIX builds.
 * Override this macro for custom platforms. */

/* -------------------------------------------------------------------------- */
/* Buffer and limit defaults                                                   */
/* -------------------------------------------------------------------------- */
#ifndef BROKER_RX_BUF_SZ
    #define BROKER_RX_BUF_SZ       4096
#endif
#ifndef BROKER_TX_BUF_SZ
    #define BROKER_TX_BUF_SZ       4096
#endif
#ifndef BROKER_TIMEOUT_MS
    #define BROKER_TIMEOUT_MS      1000
#endif
#ifndef BROKER_LISTEN_BACKLOG
    #define BROKER_LISTEN_BACKLOG  128
#endif

/* Static allocation limits */
#ifndef BROKER_MAX_CLIENTS
    #define BROKER_MAX_CLIENTS       16
#endif
#ifndef BROKER_MAX_SUBS
    #define BROKER_MAX_SUBS          64
#endif
#ifndef BROKER_MAX_CLIENT_ID_LEN
    #define BROKER_MAX_CLIENT_ID_LEN 64
#endif
#ifndef BROKER_MAX_USERNAME_LEN
    #define BROKER_MAX_USERNAME_LEN  64
#endif
#ifndef BROKER_MAX_PASSWORD_LEN
    #define BROKER_MAX_PASSWORD_LEN  64
#endif
#ifndef BROKER_MAX_FILTER_LEN
    #define BROKER_MAX_FILTER_LEN    128
#endif
#ifndef BROKER_MAX_RETAINED
    #define BROKER_MAX_RETAINED      16
#endif
#ifndef BROKER_MAX_TOPIC_LEN
    #define BROKER_MAX_TOPIC_LEN     128
#endif
#ifndef BROKER_MAX_PAYLOAD_LEN
    #define BROKER_MAX_PAYLOAD_LEN   4096
#endif
#ifndef BROKER_MAX_PENDING_WILLS
    #define BROKER_MAX_PENDING_WILLS 4
#endif

/* -------------------------------------------------------------------------- */
/* Forward declarations                                                        */
/* -------------------------------------------------------------------------- */
struct MqttBroker;

/* -------------------------------------------------------------------------- */
/* Broker network callback types                                               */
/* -------------------------------------------------------------------------- */
typedef int (*MqttBrokerNet_ListenCb)(void* ctx, BROKER_SOCKET_T* sock,
    word16 port, int backlog);
typedef int (*MqttBrokerNet_AcceptCb)(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock);
typedef int (*MqttBrokerNet_ReadCb)(void* ctx, BROKER_SOCKET_T sock,
    byte* buf, int buf_len, int timeout_ms);
typedef int (*MqttBrokerNet_WriteCb)(void* ctx, BROKER_SOCKET_T sock,
    const byte* buf, int buf_len, int timeout_ms);
typedef int (*MqttBrokerNet_CloseCb)(void* ctx, BROKER_SOCKET_T sock);

typedef struct MqttBrokerNet {
    MqttBrokerNet_ListenCb  listen;
    MqttBrokerNet_AcceptCb  accept;
    MqttBrokerNet_ReadCb    read;
    MqttBrokerNet_WriteCb   write;
    MqttBrokerNet_CloseCb   close;
    void*                   ctx;
} MqttBrokerNet;

/* -------------------------------------------------------------------------- */
/* Broker client tracking                                                      */
/* -------------------------------------------------------------------------- */
typedef struct BrokerClient {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    client_id[BROKER_MAX_CLIENT_ID_LEN];
    char    username[BROKER_MAX_USERNAME_LEN];
    char    password[BROKER_MAX_PASSWORD_LEN];
    byte    tx_buf[BROKER_TX_BUF_SZ];
    byte    rx_buf[BROKER_RX_BUF_SZ];
    char    will_topic[BROKER_MAX_TOPIC_LEN];
    byte    will_payload[BROKER_MAX_PAYLOAD_LEN];
#else
    char*   client_id;
    char*   username;
    char*   password;
    byte*   tx_buf;
    byte*   rx_buf;
    int     tx_buf_len;
    int     rx_buf_len;
    char*   will_topic;
    byte*   will_payload;
    struct BrokerClient* next;
#endif
    BROKER_SOCKET_T sock;
    byte    protocol_level;
    word16  keep_alive_sec;
    WOLFMQTT_BROKER_TIME_T last_rx;
    byte    clean_session;
    byte    has_will;
    word16  will_payload_len;
    MqttQoS will_qos;
    byte    will_retain;
    word32  will_delay_sec;     /* v5 Will Delay Interval (seconds) */
    MqttNet net;
    MqttClient client;
    struct MqttBroker* broker;  /* back-pointer to parent broker context */
#ifdef ENABLE_MQTT_TLS
    byte    tls_handshake_done;
#endif
} BrokerClient;

/* -------------------------------------------------------------------------- */
/* Broker subscription tracking                                                */
/* -------------------------------------------------------------------------- */
typedef struct BrokerSub {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    filter[BROKER_MAX_FILTER_LEN];
#else
    char*   filter;
    struct BrokerSub* next;
#endif
    struct BrokerClient* client;
    MqttQoS qos;
} BrokerSub;

/* -------------------------------------------------------------------------- */
/* Retained message store                                                      */
/* -------------------------------------------------------------------------- */
typedef struct BrokerRetainedMsg {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    topic[BROKER_MAX_TOPIC_LEN];
    byte    payload[BROKER_MAX_PAYLOAD_LEN];
#else
    char*   topic;
    byte*   payload;
    struct BrokerRetainedMsg* next;
#endif
    word16  payload_len;
    WOLFMQTT_BROKER_TIME_T store_time;  /* when stored (seconds) */
    word32  expiry_sec;                 /* v5 message expiry (0=none) */
} BrokerRetainedMsg;

/* -------------------------------------------------------------------------- */
/* Pending will messages (v5 Will Delay Interval)                              */
/* -------------------------------------------------------------------------- */
typedef struct BrokerPendingWill {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    client_id[BROKER_MAX_CLIENT_ID_LEN];
    char    topic[BROKER_MAX_TOPIC_LEN];
    byte    payload[BROKER_MAX_PAYLOAD_LEN];
#else
    char*   client_id;
    char*   topic;
    byte*   payload;
    struct BrokerPendingWill* next;
#endif
    word16  payload_len;
    MqttQoS qos;
    byte    retain;
    WOLFMQTT_BROKER_TIME_T publish_time; /* absolute time to publish */
} BrokerPendingWill;

/* -------------------------------------------------------------------------- */
/* Broker context                                                              */
/* -------------------------------------------------------------------------- */
typedef struct MqttBroker {
    BROKER_SOCKET_T listen_sock;
    word16  port;
    int     running;
    const char* auth_user;
    const char* auth_pass;
    MqttBrokerNet net;
    word16  next_packet_id;
#ifdef ENABLE_MQTT_TLS
    WOLFSSL_CTX* tls_ctx;
    const char*  tls_cert;     /* Server certificate file path */
    const char*  tls_key;      /* Server private key file path */
    const char*  tls_ca;       /* CA cert for mutual auth (optional) */
    byte         use_tls;
    byte         tls_version;  /* 0=auto (v23), 12=TLS 1.2, 13=TLS 1.3 */
#endif
#ifdef WOLFMQTT_STATIC_MEMORY
    BrokerClient clients[BROKER_MAX_CLIENTS];
    BrokerSub    subs[BROKER_MAX_SUBS];
    BrokerRetainedMsg retained[BROKER_MAX_RETAINED];
    BrokerPendingWill pending_wills[BROKER_MAX_PENDING_WILLS];
#else
    BrokerClient* clients;
    BrokerSub*    subs;
    BrokerRetainedMsg* retained;
    BrokerPendingWill* pending_wills;
#endif
} MqttBroker;

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/* Initialize the broker context with network callbacks */
WOLFMQTT_API int MqttBroker_Init(MqttBroker* broker, MqttBrokerNet* net);

/* Run the broker main loop (blocking) */
WOLFMQTT_API int MqttBroker_Run(MqttBroker* broker);

/* Execute a single iteration of the broker loop (for embedded main loops) */
WOLFMQTT_API int MqttBroker_Step(MqttBroker* broker);

/* Signal the broker loop to stop */
WOLFMQTT_API int MqttBroker_Stop(MqttBroker* broker);

/* Clean up broker resources */
WOLFMQTT_API int MqttBroker_Free(MqttBroker* broker);

/* Default POSIX backend initializer.
 * Only available when WOLFMQTT_BROKER_CUSTOM_NET is NOT defined. */
#ifndef WOLFMQTT_BROKER_CUSTOM_NET
WOLFMQTT_API int MqttBrokerNet_Init(MqttBrokerNet* net);
#endif

/* CLI wrapper - retained for backward compatibility */
WOLFMQTT_API int wolfmqtt_broker(int argc, char** argv);

#endif /* WOLFMQTT_BROKER */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_BROKER_H */
