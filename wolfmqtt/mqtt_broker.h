/* mqtt_broker.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
/* Log levels                                                                  */
/* -------------------------------------------------------------------------- */
#define BROKER_LOG_ERROR  1
#define BROKER_LOG_INFO   2
#define BROKER_LOG_DEBUG  3

#ifndef BROKER_LOG_LEVEL_DEFAULT
    #define BROKER_LOG_LEVEL_DEFAULT  BROKER_LOG_INFO
#endif

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
    #define BROKER_MAX_CLIENTS       8
#endif
#ifndef BROKER_MAX_SUBS
    #define BROKER_MAX_SUBS          32
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
#ifndef BROKER_MAX_WILL_PAYLOAD_LEN
    #define BROKER_MAX_WILL_PAYLOAD_LEN 256
#endif
#ifndef BROKER_MAX_PENDING_WILLS
    #define BROKER_MAX_PENDING_WILLS 4
#endif

/* -------------------------------------------------------------------------- */
/* Feature toggles (opt-out: define WOLFMQTT_BROKER_NO_xxx to disable)        */
/* -------------------------------------------------------------------------- */
#ifndef WOLFMQTT_BROKER_NO_RETAINED
    #define WOLFMQTT_BROKER_RETAINED
#endif
#ifndef WOLFMQTT_BROKER_NO_WILL
    #define WOLFMQTT_BROKER_WILL
#endif
#ifndef WOLFMQTT_BROKER_NO_WILDCARDS
    #define WOLFMQTT_BROKER_WILDCARDS
#endif
#ifndef WOLFMQTT_BROKER_NO_AUTH
    #define WOLFMQTT_BROKER_AUTH
#endif
#ifndef WOLFMQTT_BROKER_NO_INSECURE
    #define WOLFMQTT_BROKER_INSECURE
#endif
#if defined(WOLFMQTT_BROKER_NO_INSECURE) && !defined(ENABLE_MQTT_TLS)
    #error "WOLFMQTT_BROKER_NO_INSECURE requires ENABLE_MQTT_TLS"
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
/* WebSocket per-client context                                                */
/* -------------------------------------------------------------------------- */
#ifdef ENABLE_MQTT_WEBSOCKET
#ifdef WOLFMQTT_STATIC_MEMORY
    #error "WebSocket support (ENABLE_MQTT_WEBSOCKET) is incompatible with " \
           "static memory mode (WOLFMQTT_STATIC_MEMORY). libwebsockets " \
           "requires dynamic allocation internally."
#endif
#ifndef BROKER_WS_RX_BUF_SZ
    #define BROKER_WS_RX_BUF_SZ  BROKER_RX_BUF_SZ
#endif
typedef struct BrokerWsCtx {
    void  *wsi;                 /* struct lws* (opaque to avoid lws header) */
    byte   rx_buffer[BROKER_WS_RX_BUF_SZ];
    size_t rx_len;
    byte  *tx_pending;          /* allocated with LWS_PRE prefix room */
    size_t tx_len;
    int    status;              /* 1=established, 0=closed, -1=error */
    int    pending_close;       /* 1 when broker-initiated close is in progress */
    int    processing;          /* 1 while BrokerClient_Process is dispatching a packet */
    int    pending_remove;      /* 1 when peer closed during processing; deferred free */
} BrokerWsCtx;
#endif /* ENABLE_MQTT_WEBSOCKET */

/* -------------------------------------------------------------------------- */
/* Broker client tracking                                                      */
/* -------------------------------------------------------------------------- */
typedef struct BrokerClient {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    client_id[BROKER_MAX_CLIENT_ID_LEN];
#ifdef WOLFMQTT_BROKER_AUTH
    char    username[BROKER_MAX_USERNAME_LEN];
    char    password[BROKER_MAX_PASSWORD_LEN];
#endif
    byte    tx_buf[BROKER_TX_BUF_SZ];
    byte    rx_buf[BROKER_RX_BUF_SZ];
#ifdef WOLFMQTT_BROKER_WILL
    char    will_topic[BROKER_MAX_TOPIC_LEN];
    byte    will_payload[BROKER_MAX_WILL_PAYLOAD_LEN];
#endif
#else
    char*   client_id;
#ifdef WOLFMQTT_BROKER_AUTH
    char*   username;
    char*   password;
#endif
    byte*   tx_buf;
    byte*   rx_buf;
    int     tx_buf_len;
    int     rx_buf_len;
#ifdef WOLFMQTT_BROKER_WILL
    char*   will_topic;
    byte*   will_payload;
#endif
    struct BrokerClient* next;
#endif
    BROKER_SOCKET_T sock;
    byte    protocol_level;
    word16  keep_alive_sec;
    WOLFMQTT_BROKER_TIME_T last_rx;
    byte    clean_session;
#ifdef WOLFMQTT_BROKER_WILL
    byte    has_will;
    word16  will_payload_len;
    MqttQoS will_qos;
    byte    will_retain;
    word32  will_delay_sec;     /* v5 Will Delay Interval (seconds) */
#endif
    MqttNet net;
    MqttClient client;
    struct MqttBroker* broker;  /* back-pointer to parent broker context */
#ifdef ENABLE_MQTT_TLS
    byte    tls_handshake_done;
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
    void   *ws_ctx;             /* BrokerWsCtx* (NULL for TCP clients) */
#endif
} BrokerClient;

/* -------------------------------------------------------------------------- */
/* Broker subscription tracking                                                */
/* -------------------------------------------------------------------------- */
typedef struct BrokerSub {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    filter[BROKER_MAX_FILTER_LEN];
    char    client_id[BROKER_MAX_CLIENT_ID_LEN]; /* For session persistence */
#else
    char*   filter;
    char*   client_id; /* For session persistence */
    struct BrokerSub* next;
#endif
    struct BrokerClient* client; /* NULL if client disconnected (session persisted) */
    MqttQoS qos;
} BrokerSub;

/* -------------------------------------------------------------------------- */
/* Retained message store                                                      */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_RETAINED
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
#endif /* WOLFMQTT_BROKER_RETAINED */

/* -------------------------------------------------------------------------- */
/* Pending will messages (v5 Will Delay Interval)                              */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_WILL
typedef struct BrokerPendingWill {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    client_id[BROKER_MAX_CLIENT_ID_LEN];
    char    topic[BROKER_MAX_TOPIC_LEN];
    byte    payload[BROKER_MAX_WILL_PAYLOAD_LEN];
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
#endif /* WOLFMQTT_BROKER_WILL */

/* -------------------------------------------------------------------------- */
/* Broker context                                                              */
/* -------------------------------------------------------------------------- */
typedef struct MqttBroker {
    BROKER_SOCKET_T listen_sock;
    word16  port;
    int     running;
    byte    log_level;
#ifdef WOLFMQTT_BROKER_AUTH
    const char* auth_user;
    const char* auth_pass;
#endif
    MqttBrokerNet net;
    word16  next_packet_id;
#ifdef ENABLE_MQTT_TLS
    BROKER_SOCKET_T listen_sock_tls; /* TLS listener socket */
    word16       port_tls;           /* TLS port (default 8883) */
    WOLFSSL_CTX* tls_ctx;
    const char*  tls_cert;     /* Server certificate file path */
    const char*  tls_key;      /* Server private key file path */
    const char*  tls_ca;       /* CA cert for mutual auth (optional) */
    byte         use_tls;
    byte         tls_version;  /* 0=auto (v23), 12=TLS 1.2, 13=TLS 1.3 */
    byte         tls_ctx_owned; /* 1 if BrokerTls_Init created tls_ctx */
#endif
#ifdef WOLFMQTT_STATIC_MEMORY
    BrokerClient clients[BROKER_MAX_CLIENTS];
    BrokerSub    subs[BROKER_MAX_SUBS];
#ifdef WOLFMQTT_BROKER_RETAINED
    BrokerRetainedMsg retained[BROKER_MAX_RETAINED];
#endif
#ifdef WOLFMQTT_BROKER_WILL
    BrokerPendingWill pending_wills[BROKER_MAX_PENDING_WILLS];
#endif
#else
    BrokerClient* clients;
    BrokerSub*    subs;
#ifdef WOLFMQTT_BROKER_RETAINED
    BrokerRetainedMsg* retained;
#endif
#ifdef WOLFMQTT_BROKER_WILL
    BrokerPendingWill* pending_wills;
#endif
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
    void   *ws_ctx;             /* struct lws_context* (opaque) */
    word16  ws_port;
    byte    use_websocket;
    const char *ws_tls_cert;
    const char *ws_tls_key;
    const char *ws_tls_ca;
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

/* Start the broker (listen + TLS init). Call once before MqttBroker_Step().
 * For embedded systems that use a cooperative main loop with Step(). */
WOLFMQTT_API int MqttBroker_Start(MqttBroker* broker);

/* wolfIP backend initializer.
 * wolfIP_stack is a (struct wolfIP*) pointer to the wolfIP stack instance. */
#ifdef WOLFMQTT_WOLFIP
WOLFMQTT_API int MqttBrokerNet_wolfIP_Init(MqttBrokerNet* net,
    void* wolfIP_stack);
#endif

/* Default POSIX backend initializer.
 * Only available when WOLFMQTT_BROKER_CUSTOM_NET is NOT defined. */
#if !defined(WOLFMQTT_WOLFIP) && !defined(WOLFMQTT_BROKER_CUSTOM_NET)
WOLFMQTT_API int MqttBrokerNet_Init(MqttBrokerNet* net);
#endif

/* CLI wrapper interface */
WOLFMQTT_API int wolfmqtt_broker(int argc, char** argv);

#endif /* WOLFMQTT_BROKER */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_BROKER_H */
