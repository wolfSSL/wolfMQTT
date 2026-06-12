/* mqtt_broker.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Windows uses the vs_settings.h file included via mqtt_types.h */
#if !defined(WOLFMQTT_USER_SETTINGS) && \
    !defined(_WIN32) && !defined(USE_WINDOWS_API)
    /* If options.h is missing use the "./configure" script. Otherwise, copy
     * the template "wolfmqtt/options.h.in" into "wolfmqtt/options.h" */
    #include <wolfmqtt/options.h>
#endif
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
/* Per-client subscription cap so one client cannot occupy the whole shared
 * subscription table and deny other clients (CWE-770). */
#ifndef BROKER_MAX_SUBS_PER_CLIENT
    #define BROKER_MAX_SUBS_PER_CLIENT (BROKER_MAX_SUBS / BROKER_MAX_CLIENTS)
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
/* Upper bound (seconds) the broker accepts for a v5 Will Delay Interval.
 * Caps how long a deferred-will slot can be monopolized so a few clients
 * advertising near-UINT32_MAX delays cannot permanently exhaust the pool. */
#ifndef BROKER_MAX_WILL_DELAY_SEC
    #define BROKER_MAX_WILL_DELAY_SEC 3600
#endif
/* Maximum concurrent inbound QoS 2 packet IDs awaiting PUBREL per client.
 * Used to dedup duplicate PUBLISHes per [MQTT-4.3.3] (Method B). 16 covers
 * any reasonable client; a misbehaving client that exceeds this gets a
 * malformed-packet rejection. */
#ifndef BROKER_MAX_INBOUND_QOS2
    #define BROKER_MAX_INBOUND_QOS2 16
#endif

/* Per-subscriber outbound delivery shaping.
 *
 * BROKER_MAX_INFLIGHT_PER_SUB bounds the number of outbound QoS 1/2 PUBLISHes
 * the broker may have in flight to a single subscriber at once. This gives
 * users a Mosquitto "max_inflight_messages" equivalent that works on both
 * v3.1.1 and v5; for v5 clients it is further clamped by the client's
 * Receive Maximum property (MQTT v5 sec 3.1.2.11.3).
 *
 * The default is derived from BROKER_TX_BUF_SZ so that the per-subscriber
 * outbound queue is "roughly the size that the tx buffer could plausibly
 * pipeline" without picking an arbitrary number. Override with
 *   -DBROKER_MAX_INFLIGHT_PER_SUB=N   to set a hard cap (1 = strict serial),
 *   -DBROKER_DEFAULT_AVG_MSG_SZ=N     to retune the derivation.
 *
 * Only used in dynamic-memory mode; STATIC_MEMORY mode keeps the legacy
 * synchronous fan-out path. */
#ifndef BROKER_DEFAULT_AVG_MSG_SZ
    #define BROKER_DEFAULT_AVG_MSG_SZ 256
#endif
#ifndef BROKER_MIN_INFLIGHT_PER_SUB
    #define BROKER_MIN_INFLIGHT_PER_SUB 8
#endif
#ifndef BROKER_MAX_INFLIGHT_PER_SUB
    #define BROKER_MAX_INFLIGHT_PER_SUB \
        (((BROKER_TX_BUF_SZ / BROKER_DEFAULT_AVG_MSG_SZ) < \
            BROKER_MIN_INFLIGHT_PER_SUB) ? \
         BROKER_MIN_INFLIGHT_PER_SUB : \
         (BROKER_TX_BUF_SZ / BROKER_DEFAULT_AVG_MSG_SZ))
#endif

/* Persistent storage caps (only meaningful with WOLFMQTT_BROKER_PERSIST).
 *
 * BROKER_MAX_PERSIST_SESSIONS bounds the number of disconnected
 * persistent sessions kept across broker restart.
 * BROKER_MAX_OFFLINE_MSGS_PER_SUB bounds the per-session offline queue
 * depth; overflow drops the oldest message (FIFO eviction). */
#ifndef BROKER_MAX_PERSIST_SESSIONS
    #define BROKER_MAX_PERSIST_SESSIONS  64
#endif
#ifndef BROKER_MAX_OFFLINE_MSGS_PER_SUB
    #define BROKER_MAX_OFFLINE_MSGS_PER_SUB 32
#endif

/* Schema version stamped on every persisted record. Bump when the
 * encoding of any namespace changes incompatibly; a startup with stored
 * records carrying a different version logs a warning, wipes all
 * persisted state, and starts clean (per plan: wipe-and-restart). */
#ifndef WOLFMQTT_BROKER_PERSIST_SCHEMA_VER
    /* Bumped from 1 -> 2 when the header layout split a dedicated
     * wrap_mode byte out of the schema-version field. Bumped 2 -> 3 when
     * the NS_SESSION record gained an orphan_since timestamp so the v5
     * Session Expiry timer survives a broker restart. Any existing dev
     * directory written by an older build mismatches and is wiped via the
     * schema-mismatch path on first restart. */
    #define WOLFMQTT_BROKER_PERSIST_SCHEMA_VER 3
#endif

/* Header wrap_mode byte values (record body framing on disk). */
#define WOLFMQTT_BROKER_PERSIST_WRAP_PLAIN    0
#define WOLFMQTT_BROKER_PERSIST_WRAP_AES_GCM  1

/* Magic bytes prefixing every persisted record so a stray file in the
 * backend directory cannot be misinterpreted as broker state. */
#define WOLFMQTT_BROKER_PERSIST_MAGIC0  'W'
#define WOLFMQTT_BROKER_PERSIST_MAGIC1  'M'
#define WOLFMQTT_BROKER_PERSIST_MAGIC2  'Q'
#define WOLFMQTT_BROKER_PERSIST_MAGIC3  'B'

/* Default storage directory for the POSIX backend. Application can pass
 * a different path at MqttBrokerNet_PersistPosix_Init time. */
#ifndef BROKER_PERSIST_DIR_DEFAULT
    #define BROKER_PERSIST_DIR_DEFAULT  "/var/lib/wolfmqtt"
#endif

/* Persistence namespaces. One per logical record type. The backend
 * is free to map each namespace to a separate directory, table,
 * keyspace, or sub-region; the broker just passes the namespace byte
 * verbatim. Values are stable across schema versions. */
#define BROKER_PERSIST_NS_META      1   /* schema version, broker meta */
#define BROKER_PERSIST_NS_SESSION   2   /* per-client_id session record */
#define BROKER_PERSIST_NS_SUBS      3   /* per-client_id subscription list */
#define BROKER_PERSIST_NS_RETAINED  4   /* per-topic retained message */
#define BROKER_PERSIST_NS_OUTQ      5   /* per-client_id outbound queue + inflight */

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
/* Persistent storage hooks                                                    */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_PERSIST
/* The persistence layer is intentionally hook-based so the broker can run
 * on top of POSIX files, embedded flash, an external KV store, or an
 * in-RAM stub used by tests. Each hook returns 0 on success or a negative
 * error code (broker logs and skips persist for that record - the
 * in-memory state is still authoritative).
 *
 * Both a key/value API and a streaming API are provided. The broker will
 * use whichever family the registered hook implements; any individual
 * hook pointer may be NULL when not supported. At minimum kv_put / kv_get
 * / kv_iter must be installed for sessions / subs / retained / outq to
 * round-trip; the streaming API is offered for backends that prefer an
 * append-only log (e.g., raw NOR flash). */

/* Iterator callback supplied by the broker to kv_iter. Return 0 to
 * continue, non-zero to stop iteration early. */
typedef int (*MqttBrokerPersist_IterCb)(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx);

/* Stream open mode. */
#define BROKER_PERSIST_STREAM_READ    1
#define BROKER_PERSIST_STREAM_WRITE   2
#define BROKER_PERSIST_STREAM_APPEND  3

typedef struct MqttBrokerPersistHooks {
    /* Key/value blob API. key bytes are opaque to the backend; len is
     * always <= 256 in current use (a client_id or topic). */
    int (*kv_put)(void* ctx, byte ns, const byte* key, word16 key_len,
                  const byte* blob, word32 blob_len);
    int (*kv_get)(void* ctx, byte ns, const byte* key, word16 key_len,
                  byte* out, word32* inout_len);
    int (*kv_del)(void* ctx, byte ns, const byte* key, word16 key_len);
    int (*kv_iter)(void* ctx, byte ns, MqttBrokerPersist_IterCb cb,
                   void* cb_ctx);

    /* Streaming API. handle is opaque; broker passes through. */
    int (*stream_open)(void* ctx, byte ns, const byte* key, word16 key_len,
                       int mode, void** handle);
    int (*stream_read)(void* ctx, void* handle, byte* buf, word32 len,
                       word32* out_len);
    int (*stream_write)(void* ctx, void* handle, const byte* buf,
                        word32 len);
    int (*stream_close)(void* ctx, void* handle);

    /* Force all pending writes to durable storage. Called after every
     * shadow-write commit per plan's "fsync after each commit" choice. */
    int (*sync)(void* ctx);

    /* Encryption-at-rest key derivation. Called once at broker init when
     * WOLFMQTT_BROKER_PERSIST_ENCRYPT is enabled. Must fill 32 bytes
     * (AES-256) into out_key. */
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    int (*derive_key)(void* ctx, byte* out_key, word32 key_len);
#endif

    /* Backend context pointer passed back into every callback. */
    void* ctx;
} MqttBrokerPersistHooks;
#endif /* WOLFMQTT_BROKER_PERSIST */

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
/* Inbound QoS 2 dedup state                                                   */
/* -------------------------------------------------------------------------- */
/* Per-client set of QoS 2 packet IDs that have been received and PUBREC'd
 * but not yet PUBREL'd. Used to skip the fan-out for duplicate PUBLISHes
 * per [MQTT-4.3.3] / Method B. Gated by WOLFMQTT_MAX_QOS so capped-QoS
 * broker builds drop the dedup state and PUBREC/PUBREL/PUBCOMP handlers. */
#if WOLFMQTT_MAX_QOS >= 2
#ifndef WOLFMQTT_STATIC_MEMORY
typedef struct BrokerInboundQos2 {
    word16  packet_id;
    struct BrokerInboundQos2* next;
} BrokerInboundQos2;
#endif
#endif /* WOLFMQTT_MAX_QOS >= 2 */

/* -------------------------------------------------------------------------- */
/* Per-subscriber outbound publish queue (dynamic memory mode only).
 *
 * Each entry owns the topic and payload bytes via heap copy so the queue is
 * independent of the publisher's rx_buf lifetime. The state field tracks
 * the QoS handshake position for that one delivery to that one subscriber:
 *
 *   BROKER_OUTQ_QUEUED        Not yet sent on the wire.
 *   BROKER_OUTQ_PUBLISH_SENT  QoS 1: awaiting PUBACK. QoS 2: awaiting PUBREC.
 *   BROKER_OUTQ_PUBREL_SENT   QoS 2 only: PUBREC received, PUBREL sent,
 *                             awaiting PUBCOMP.
 *
 * QoS 0 entries are deleted as soon as the PUBLISH is written; they never
 * leave the QUEUED state and never increment the inflight counter. */
#ifndef WOLFMQTT_STATIC_MEMORY
enum BrokerOutPubState {
    BROKER_OUTQ_QUEUED       = 0,
    BROKER_OUTQ_PUBLISH_SENT = 1,
    BROKER_OUTQ_PUBREL_SENT  = 2
};

typedef struct BrokerOutPub {
    char*   topic;          /* heap-owned, NUL-terminated */
    byte*   payload;        /* heap-owned, may be NULL when payload_len == 0 */
    word32  payload_len;
    MqttQoS qos;
    word16  packet_id;      /* 0 for QoS 0 */
    byte    retain;
    byte    state;          /* BROKER_OUTQ_* */
    /* On session resumption, BrokerOrphan_Reclaim resets any entry
     * that was previously PUBLISH_SENT back to QUEUED and sets
     * retransmit_dup=1. The drain encodes the PUBLISH with
     * MqttPublish.duplicate=1 on first re-send, as required by
     * MQTT-4.4.0-1, then clears the flag. */
    byte    retransmit_dup; /* 0 or 1 */
    WOLFMQTT_BROKER_TIME_T enq_time;
    word32  expiry_sec;     /* v5 Message Expiry Interval, 0 = no expiry */
    byte    protocol_level; /* echoed back to subscriber on send */
    struct BrokerOutPub* next;
} BrokerOutPub;

/* -------------------------------------------------------------------------- */
/* Orphan session (dynamic memory only).                                       */
/*                                                                            */
/* Holds the persistent-session state of a disconnected client (Clean         */
/* Start=0): its outbound message queue, in-flight QoS 1/2 receipts, and      */
/* enough identity to be reclaimed on reconnect. Smaller than a full          */
/* BrokerClient because no socket / tx_buf / rx_buf / TLS state is needed     */
/* while disconnected. Subs that belonged to the original BrokerClient        */
/* keep sub->client=NULL while orphaned; reconnect rebinds them.              */
/* -------------------------------------------------------------------------- */
typedef struct BrokerOrphanSession {
    char*       client_id;       /* heap-owned, NUL-terminated */
    byte        protocol_level;
    word32      session_expiry_sec;  /* v5 Session Expiry; 0xFFFFFFFF=never */
    WOLFMQTT_BROKER_TIME_T orphan_since;
    BrokerOutPub* out_q_head;
    BrokerOutPub* out_q_tail;
    int           out_q_count;
    int           out_q_inflight;
    struct BrokerOrphanSession* next;
} BrokerOrphanSession;
#endif

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
    byte    connected;       /* set after successful CONNECT handshake */
    int     sub_count;       /* active subscriptions owned by this client */
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
#ifdef WOLFMQTT_BROKER_AUTH
    /* Actual stored length of password bytes. Tracked separately because
     * [MQTT-3.1.3.5] defines Password as Binary Data, which may legally
     * contain 0x00 - XSTRLEN would truncate at the first embedded NUL. */
    word16  password_len;
#endif
    /* [MQTT-4.3.3] Inbound QoS 2 packet IDs that have been PUBREC'd but
     * not yet PUBREL'd. A duplicate PUBLISH carrying one of these IDs is
     * acked again (PUBREC) but NOT re-fanned-out to subscribers. The
     * BROKER_MAX_INBOUND_QOS2 cap is enforced in both memory modes; a
     * client that exceeds it is disconnected with malformed-packet error.
     * Compiled out for capped-QoS builds (WOLFMQTT_MAX_QOS < 2). */
#if WOLFMQTT_MAX_QOS >= 2
#ifdef WOLFMQTT_STATIC_MEMORY
    word16  qos2_pending[BROKER_MAX_INBOUND_QOS2]; /* 0 = empty slot */
#else
    BrokerInboundQos2* qos2_pending;
    int                qos2_pending_count;
#endif
#endif /* WOLFMQTT_MAX_QOS >= 2 */
#ifndef WOLFMQTT_STATIC_MEMORY
    /* Per-subscriber outbound publish queue. FIFO from head to tail;
     * drain pulls from head. out_q_inflight is the number of entries in
     * state PUBLISH_SENT or PUBREL_SENT (QoS 1/2 awaiting an ack);
     * BROKER_MAX_INFLIGHT_PER_SUB and client_receive_max together bound
     * how many of those may exist at once. out_q_count is total entries
     * including not-yet-sent QUEUED ones. Used for fan-out at every
     * QoS level (QoS 0 forwards transit the queue too). */
    BrokerOutPub* out_q_head;
    BrokerOutPub* out_q_tail;
    int           out_q_count;
    int           out_q_inflight;
    /* v5 Receive Maximum advertised by this client in CONNECT, or 65535
     * (per MQTT v5 sec 3.1.2.11.3) when the client did not include the
     * property. For v3.1.1 clients this is left at 65535 - the cap
     * comes from BROKER_MAX_INFLIGHT_PER_SUB alone. */
    word16        client_receive_max;
    /* v5 Session Expiry Interval (seconds). Captured from CONNECT
     * properties for clean_session=0 sessions so the disconnect path
     * can stamp it into the orphan slot. 0xFFFFFFFF means "never
     * expire"; the v3.1.1 persistent-session default. */
    word32        session_expiry_sec;
#endif /* !WOLFMQTT_STATIC_MEMORY */
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
    word32  payload_len;
    WOLFMQTT_BROKER_TIME_T store_time;  /* when stored (seconds) */
    word32  expiry_sec;                 /* v5 message expiry (0=none) */
    MqttQoS qos;                        /* [MQTT-3.3.1-5] stored QoS */
    byte    pending_delete;             /* deferred free during delivery */
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
    word32  next_auto_id; /* monotonically increasing counter for
                           * server-assigned ClientIds (empty-ID accepts) */
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
    int                retained_count;
    int                retained_delivering; /* re-entrancy guard for delete */
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
    /* Optional exact Origin allowlist for browser WebSocket connections. When
     * non-NULL, a request whose HTTP Origin header is present and does not
     * match is rejected (CSWSH defense). NULL = no Origin enforcement. */
    const char *ws_allowed_origin;
#endif
#ifdef WOLFMQTT_BROKER_PERSIST
    /* Pointer (not embedded struct) so the broker stays small when no
     * application installs hooks. NULL means "in-memory only", which is
     * the same behavior as a build without WOLFMQTT_BROKER_PERSIST. */
    const MqttBrokerPersistHooks* persist;
    #ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    /* AES-256 key cache for at-rest encryption. Populated by the first
     * encrypt/decrypt call via derive_key(); zeroed (ForceZero) on
     * MqttBroker_Free. Per-broker so multiple broker instances in one
     * process don't share key material. */
    byte persist_key_cache[32];
    byte persist_key_loaded; /* 0 or 1 */
    #endif
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    /* Linked list of disconnected persistent sessions. Each entry holds
     * its own outbound queue + identity so messages published while the
     * owning client is offline are retained until reconnect (or
     * BROKER_MAX_PERSIST_SESSIONS forces drop-oldest eviction). Subs
     * pointing at orphaned sessions keep sub->client=NULL; fan-out
     * branches on that to look up the orphan by client_id. */
    BrokerOrphanSession* orphan_sessions;
    int                  orphan_session_count;
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

#ifdef WOLFMQTT_BROKER_PERSIST
/* Install persistence hooks on the broker. Must be called before
 * MqttBroker_Start. Passing NULL clears any previously installed hooks
 * (reverts to in-memory-only behavior). The MqttBrokerPersistHooks
 * struct must outlive the broker. */
WOLFMQTT_API int MqttBroker_SetPersistHooks(MqttBroker* broker,
    const MqttBrokerPersistHooks* hooks);

/* Initialize the default POSIX file-based persistence backend. Stores
 * each record as a file under dir (defaults to BROKER_PERSIST_DIR_DEFAULT
 * when dir is NULL). fsync's every commit. Caller is responsible for
 * keeping the hooks struct alive while the broker runs. */
WOLFMQTT_API int MqttBrokerNet_PersistPosix_Init(
    MqttBrokerPersistHooks* hooks, const char* dir);

/* Tear down the POSIX backend - releases the directory descriptor and
 * any per-handle state. Does not delete persisted files. */
WOLFMQTT_API void MqttBrokerNet_PersistPosix_Free(
    MqttBrokerPersistHooks* hooks);

/* -------------------------------------------------------------------------- */
/* Internal shadow-write helpers (linked from mqtt_broker.c into the
 * mqtt_broker binary). All are no-ops when broker->persist is NULL so
 * call sites do not need to guard. WOLFMQTT_LOCAL keeps them out of
 * the public shared-library ABI. The encoders use a heap-allocated
 * scratch buffer sized to the record - too large to live on the
 * select-loop stack and bursty enough that a per-call alloc is the
 * least surprising approach. Backends can themselves choose how to
 * persist or fsync. Forward-compat is via WOLFMQTT_BROKER_PERSIST_SCHEMA_VER. */
struct BrokerClient;
struct BrokerSub;
struct BrokerRetainedMsg;
struct BrokerOutPub;

WOLFMQTT_LOCAL int BrokerPersist_PutSession(MqttBroker* broker,
    const struct BrokerClient* bc);
#ifndef WOLFMQTT_STATIC_MEMORY
WOLFMQTT_LOCAL int BrokerPersist_PutOrphanSession(MqttBroker* broker,
    const char* client_id, byte protocol_level, word32 session_expiry_sec,
    word64 orphan_since);
#endif
WOLFMQTT_LOCAL int BrokerPersist_DelSession(MqttBroker* broker,
    const char* client_id);

WOLFMQTT_LOCAL int BrokerPersist_PutSubs(MqttBroker* broker,
    const char* client_id);
WOLFMQTT_LOCAL int BrokerPersist_DelSubs(MqttBroker* broker,
    const char* client_id);

WOLFMQTT_LOCAL int BrokerPersist_PutRetained(MqttBroker* broker,
    const struct BrokerRetainedMsg* rm);
WOLFMQTT_LOCAL int BrokerPersist_DelRetained(MqttBroker* broker,
    const char* topic);

WOLFMQTT_LOCAL int BrokerPersist_PutOutPub(MqttBroker* broker,
    const char* client_id, const struct BrokerOutPub* e);
WOLFMQTT_LOCAL int BrokerPersist_DelOutPub(MqttBroker* broker,
    const char* client_id, word16 packet_id);
WOLFMQTT_LOCAL int BrokerPersist_DelOutQueue(MqttBroker* broker,
    const char* client_id);

/* Startup-time restore: iterate persisted records and rebuild the
 * in-memory tables. Called from MqttBroker_Init when hooks are
 * installed. Wipes everything and re-stamps the META namespace if
 * the persisted schema version doesn't match. */
WOLFMQTT_LOCAL int BrokerPersist_Restore(MqttBroker* broker);
#endif /* WOLFMQTT_BROKER_PERSIST */

#ifndef WOLFMQTT_STATIC_MEMORY
/* Full orphan teardown: delete persisted records (no-op without
 * WOLFMQTT_BROKER_PERSIST), drop any orphan-bound subs
 * (sub->client == NULL with matching client_id) from broker->subs,
 * unlink and free the orphan slot. Used by both eviction (cap reached)
 * and restore-time expiry sweep so the two paths can't drift. */
WOLFMQTT_LOCAL void BrokerOrphan_DropFull(MqttBroker* broker,
    BrokerOrphanSession* o);
#endif

/* CLI wrapper interface */
WOLFMQTT_API int wolfmqtt_broker(int argc, char** argv);

/* -------------------------------------------------------------------------- */
/* Local declarations */
/* -------------------------------------------------------------------------- */
WOLFMQTT_LOCAL int BrokerSend_SubAck(BrokerClient* bc, word16 packet_id,
    const byte* return_codes, int return_code_count);


#endif /* WOLFMQTT_BROKER */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_BROKER_H */
