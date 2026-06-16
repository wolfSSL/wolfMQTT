/* mqtt_broker.c
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_broker.h"
#include "wolfmqtt/mqtt_types.h"
#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_packet.h"
#include "wolfmqtt/mqtt_socket.h"

#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_MQTT_TLS
    #include <wolfssl/wolfcrypt/random.h>
#endif

#ifdef WOLFMQTT_BROKER

/* Secure memory zeroing - uses volatile pointer to prevent the compiler
 * from optimizing away the stores (dead-store elimination). */
static void MqttBroker_ForceZero(void* mem, word32 len)
{
    volatile byte* p = (volatile byte*)mem;
    word32 i;
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

#define BROKER_FORCE_ZERO(mem, len) \
    MqttBroker_ForceZero(mem, (word32)(len))

/* -------------------------------------------------------------------------- */
/* Platform includes                                                           */
/* -------------------------------------------------------------------------- */
#if defined(WOLFMQTT_WOLFIP)
    #include "wolfip.h"
#elif !defined(WOLFMQTT_BROKER_CUSTOM_NET)
    #include <errno.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <signal.h>
    #include <sys/select.h>
    #include <sys/socket.h>
    #include <time.h>
    #include <unistd.h>
#endif

/* -------------------------------------------------------------------------- */
/* Default time abstraction                                                    */
/* -------------------------------------------------------------------------- */
#ifndef WOLFMQTT_BROKER_GET_TIME_S
    #if defined(WOLFMQTT_WOLFIP)
        /* wolfIP has no default time source. Define
         * WOLFMQTT_BROKER_GET_TIME_S in user_settings.h to provide one.
         * Example: #define WOLFMQTT_BROKER_GET_TIME_S() myGetTimeSec() */
        #error "WOLFMQTT_WOLFIP requires WOLFMQTT_BROKER_GET_TIME_S to be defined"
    #else
        #define WOLFMQTT_BROKER_GET_TIME_S() \
            ((WOLFMQTT_BROKER_TIME_T)time(NULL))
    #endif
#endif

/* -------------------------------------------------------------------------- */
/* Default sleep abstraction                                                   */
/* -------------------------------------------------------------------------- */
#ifndef BROKER_SLEEP_MS
    #if defined(WOLFMQTT_WOLFIP)
        /* No-op: wolfIP uses cooperative scheduling via MqttBroker_Step().
         * Do not use MqttBroker_Run() on wolfIP - it will busy-spin.
         * Override BROKER_SLEEP_MS in user_settings.h if a yield/delay
         * primitive is available on your platform. */
        #define BROKER_SLEEP_MS(ms) do {} while(0)
    #elif defined(USE_WINDOWS_API)
        #define BROKER_SLEEP_MS(ms) Sleep(ms)
    #else
        #define BROKER_SLEEP_MS(ms) usleep((unsigned)(ms) * 1000)
    #endif
#endif

/* Logging macros with level filtering.
 * Define WOLFMQTT_BROKER_NO_LOG to strip all broker log calls at compile time. */
#ifdef WOLFMQTT_BROKER_NO_LOG
    #define WBLOG_ERR(b, ...)   do { (void)(b); } while(0)
    #define WBLOG_INFO(b, ...)  do { (void)(b); } while(0)
    #define WBLOG_DBG(b, ...)   do { (void)(b); } while(0)
#else
    #define WBLOG(b, level, ...) \
        do { if ((b)->log_level >= (level)) PRINTF(__VA_ARGS__); } while(0)
    #define WBLOG_ERR(b, ...)   WBLOG(b, BROKER_LOG_ERROR, __VA_ARGS__)
    #define WBLOG_INFO(b, ...)  WBLOG(b, BROKER_LOG_INFO, __VA_ARGS__)
    #define WBLOG_DBG(b, ...)   WBLOG(b, BROKER_LOG_DEBUG, __VA_ARGS__)
#endif

#ifndef WOLFMQTT_BROKER_NO_LOG
#define BROKER_LOG_SAN_SZ   128 /* per-string scratch size */
#define BROKER_LOG_SAN_POOL 4   /* distinct buffers per log statement */

/* Sanitize a peer-controlled string (topic, filter, client_id, cert CN, ...)
 * before it reaches a PRINTF log sink. Control bytes (< 0x20 and
 * DEL 0x7f) become printable escapes so a remote peer cannot inject forged log
 * lines (CR/LF) or hijack the operator terminal (ANSI ESC). The result is
 * returned from a small rotating pool of static buffers so several sanitized
 * arguments can appear in one log statement; the broker log path is single
 * threaded (as is PRINTF itself). Output is NUL-terminated and truncated to
 * fit. NULL src yields "(null)". */
static const char* BrokerLog_Sanitize(const char* src)
{
    static const char hex_digits[] = "0123456789abcdef";
    static char pool[BROKER_LOG_SAN_POOL][BROKER_LOG_SAN_SZ];
    static int pool_idx = 0;
    char* dst = pool[pool_idx];
    word32 di = 0;

    pool_idx = (pool_idx + 1) % BROKER_LOG_SAN_POOL;

    if (src == NULL) {
        src = "(null)";
    }

    while (*src != '\0') {
        byte c = (byte)*src++;
        char rep[4];
        word32 repLen = 0;
        word32 j;

        switch (c) {
            case '\r': rep[0] = '\\'; rep[1] = 'r'; repLen = 2; break;
            case '\n': rep[0] = '\\'; rep[1] = 'n'; repLen = 2; break;
            case '\t': rep[0] = '\\'; rep[1] = 't'; repLen = 2; break;
            case '\v': rep[0] = '\\'; rep[1] = 'v'; repLen = 2; break;
            case 0x1b: rep[0] = '\\'; rep[1] = 'e'; repLen = 2; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    rep[0] = '\\';
                    rep[1] = 'x';
                    rep[2] = hex_digits[(c >> 4) & 0x0f];
                    rep[3] = hex_digits[c & 0x0f];
                    repLen = 4;
                }
                else {
                    rep[0] = (char)c;
                    repLen = 1;
                }
                break;
        }

        if (di + repLen + 1 > BROKER_LOG_SAN_SZ) {
            break;
        }
        for (j = 0; j < repLen; j++) {
            dst[di++] = rep[j];
        }
    }

    dst[di] = '\0';
    return dst;
}
#endif /* !WOLFMQTT_BROKER_NO_LOG */

/* Buffer size accessors - unify static/dynamic code paths */
#ifdef WOLFMQTT_STATIC_MEMORY
    #define BROKER_CLIENT_TX_SZ(bc) BROKER_TX_BUF_SZ
    #define BROKER_CLIENT_RX_SZ(bc) BROKER_RX_BUF_SZ
#else
    #define BROKER_CLIENT_TX_SZ(bc) ((bc)->tx_buf_len)
    #define BROKER_CLIENT_RX_SZ(bc) ((bc)->rx_buf_len)
#endif

/* String validity check - static arrays vs dynamic pointers */
#ifdef WOLFMQTT_STATIC_MEMORY
    #define BROKER_STR_VALID(s) ((s)[0] != '\0')
#else
    #define BROKER_STR_VALID(s) ((s) != NULL)
#endif

/* No-op stubs when features are compiled out */
#ifndef WOLFMQTT_BROKER_RETAINED
    #define BrokerRetained_Store(b, t, p, l, q, e)      (0)
    #define BrokerRetained_Delete(b, t)                 do {} while(0)
    #define BrokerRetained_FreeAll(b)                   do {} while(0)
    #define BrokerRetained_DeliverToClient(b, c, f, q)  do {} while(0)
#endif
#ifndef WOLFMQTT_BROKER_WILL
    #define BrokerClient_ClearWill(bc)                  do {} while(0)
    #define BrokerClient_PublishWill(b, bc)             do {} while(0)
    #define BrokerPendingWill_Cancel(b, id)             do {} while(0)
    #define BrokerPendingWill_Process(b)                (0)
    #define BrokerPendingWill_FreeAll(b)                do {} while(0)
#endif

#ifdef WOLFMQTT_BROKER_AUTH
/* Constant-time buffer comparison for authentication.
 * Iterates exactly cmp_len times so loop duration is independent of
 * either input's length; cmp_len is a caller-supplied fixed bound
 * (the credential buffer size). Length mismatch is folded in via the
 * final XOR. Inputs with length >= cmp_len force a mismatch to prevent
 * bypass when both inputs match in the first cmp_len bytes but differ
 * beyond. Caller supplies explicit lengths so binary inputs containing
 * embedded NULs (e.g. [MQTT-3.1.3.5] Password) are compared correctly.
 * Returns 0 if equal, non-zero if different. */
static int BrokerBufCompare(const byte* a, int len_a,
    const byte* b, int len_b, int cmp_len)
{
    int result = 0;
    int i;
    for (i = 0; i < cmp_len; i++) {
        /* Branchless index clamp: when i >= len, reads position 0.
         * Length mismatch is caught by the final XOR below. */
        unsigned int maskA = 0u - (unsigned int)(i < len_a);
        unsigned int maskB = 0u - (unsigned int)(i < len_b);
        int ia = (int)((unsigned int)i & maskA);
        int ib = (int)((unsigned int)i & maskB);
        result |= ((int)a[ia] ^ (int)b[ib]);
    }
    result |= (len_a ^ len_b);
    /* Force mismatch if either input meets or exceeds cmp_len, since the
     * loop cannot observe bytes beyond that bound. */
    result |= (len_a >= cmp_len);
    result |= (len_b >= cmp_len);
    return result;
}

/* Constant-time C-string comparison wrapper. Both inputs are assumed to
 * be NUL-terminated UTF-8 (e.g. configured username, decoded username
 * field which is rejected if it contains U+0000). */
static int BrokerStrCompare(const char* a, const char* b, int cmp_len)
{
    return BrokerBufCompare((const byte*)a, (int)XSTRLEN(a),
                            (const byte*)b, (int)XSTRLEN(b), cmp_len);
}
#endif /* WOLFMQTT_BROKER_AUTH */

/* Store a string of known length into a BrokerClient field.
 * Static mode: copies into fixed-size buffer with truncation.
 * Dynamic mode: frees old value, allocates new buffer, copies.
 *
 * The "sensitive" flavor in dynamic mode wipes the previous value via
 * XSTRLEN-derived length. That is correct for NUL-terminated UTF-8
 * fields (e.g., username, where [MQTT-1.5.3-2] forbids embedded U+0000)
 * but unsafe for binary data. Use BrokerStore_BinarySensitive for fields
 * that may contain embedded 0x00 (e.g., [MQTT-3.1.3.5] Password). */
#ifdef WOLFMQTT_STATIC_MEMORY
static void BrokerStore_String(char* dst, int max_len,
    const char* src, word16 src_len)
{
    if (src_len >= (word16)max_len) {
        src_len = (word16)(max_len - 1);
    }
    XMEMCPY(dst, src, src_len);
    dst[src_len] = '\0';
}
#ifdef WOLFMQTT_BROKER_AUTH
static void BrokerStore_StringSensitive(char* dst, int max_len,
    const char* src, word16 src_len)
{
    /* Wipe old value before overwriting */
    BROKER_FORCE_ZERO(dst, max_len);
    if (src_len >= (word16)max_len) {
        src_len = (word16)(max_len - 1);
    }
    XMEMCPY(dst, src, src_len);
    dst[src_len] = '\0';
}
/* Binary-data sensitive store. Wipes the destination (full buffer) and
 * records the actual stored length so callers don't need XSTRLEN-based
 * length recovery. */
static void BrokerStore_BinarySensitive(char* dst, int max_len,
    word16* dst_len_out, const char* src, word16 src_len)
{
    BROKER_FORCE_ZERO(dst, max_len);
    if (src_len >= (word16)max_len) {
        src_len = (word16)(max_len - 1);
    }
    XMEMCPY(dst, src, src_len);
    dst[src_len] = '\0';
    *dst_len_out = src_len;
}
#endif /* WOLFMQTT_BROKER_AUTH */
#else
static void BrokerStore_String(char** dst_ptr,
    const char* src, word16 src_len, int sensitive)
{
    if (*dst_ptr != NULL) {
        if (sensitive) {
            BROKER_FORCE_ZERO(*dst_ptr, XSTRLEN(*dst_ptr) + 1);
        }
        WOLFMQTT_FREE(*dst_ptr);
        *dst_ptr = NULL;
    }
    *dst_ptr = (char*)WOLFMQTT_MALLOC(src_len + 1);
    if (*dst_ptr != NULL) {
        XMEMCPY(*dst_ptr, src, src_len);
        (*dst_ptr)[src_len] = '\0';
    }
}
#ifdef WOLFMQTT_BROKER_AUTH
/* Binary-data sensitive store. Wipes the previous value using its
 * tracked length (binary-safe - [MQTT-3.1.3.5] Password may contain
 * 0x00) before free, then records the new stored length. */
static void BrokerStore_BinarySensitive(char** dst_ptr,
    word16* dst_len_out, const char* src, word16 src_len)
{
    if (*dst_ptr != NULL) {
        BROKER_FORCE_ZERO(*dst_ptr, (size_t)(*dst_len_out) + 1);
        WOLFMQTT_FREE(*dst_ptr);
        *dst_ptr = NULL;
    }
    *dst_len_out = 0;
    *dst_ptr = (char*)WOLFMQTT_MALLOC(src_len + 1);
    if (*dst_ptr != NULL) {
        XMEMCPY(*dst_ptr, src, src_len);
        (*dst_ptr)[src_len] = '\0';
        *dst_len_out = src_len;
    }
}
#endif /* WOLFMQTT_BROKER_AUTH */
#endif

/* Wrapper macros to unify static/dynamic calling convention */
#ifdef WOLFMQTT_STATIC_MEMORY
    #define BROKER_STORE_STR(dst, src, len, maxlen) \
        BrokerStore_String(dst, maxlen, src, len)
#ifdef WOLFMQTT_BROKER_AUTH
    #define BROKER_STORE_STR_SENSITIVE(dst, src, len, maxlen) \
        BrokerStore_StringSensitive(dst, maxlen, src, len)
    #define BROKER_STORE_BIN_SENSITIVE(dst, dst_len, src, len, maxlen) \
        BrokerStore_BinarySensitive(dst, maxlen, &(dst_len), src, len)
#endif
#else
    #define BROKER_STORE_STR(dst, src, len, maxlen) \
        BrokerStore_String(&(dst), src, len, 0)
#ifdef WOLFMQTT_BROKER_AUTH
    #define BROKER_STORE_STR_SENSITIVE(dst, src, len, maxlen) \
        BrokerStore_String(&(dst), src, len, 1)
    #define BROKER_STORE_BIN_SENSITIVE(dst, dst_len, src, len, maxlen) \
        BrokerStore_BinarySensitive(&(dst), &(dst_len), src, len)
#endif
#endif

#if defined(ENABLE_MQTT_TLS) && !defined(WOLFMQTT_BROKER_CUSTOM_NET)
static int BrokerTls_Init(MqttBroker* broker)
{
    WOLFSSL_CTX* ctx = NULL;
    int wolf_rc; /* wolfSSL return codes (compared against WOLFSSL_SUCCESS) */
    int mqtt_rc = MQTT_CODE_SUCCESS; /* normalized MQTT return code */

    wolf_rc = wolfSSL_Init();
    if (wolf_rc != WOLFSSL_SUCCESS) {
        WBLOG_ERR(broker, "broker: wolfSSL_Init failed %d", wolf_rc);
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Select TLS method based on version preference */
    if (broker->tls_version == 12) {
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    }
    else if (broker->tls_version == 13) {
        ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    }
    else {
        ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
        if (ctx != NULL) {
            wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
        }
    }
    if (ctx == NULL) {
        WBLOG_ERR(broker, "broker: wolfSSL_CTX_new failed");
        mqtt_rc = MQTT_CODE_ERROR_MEMORY;
    }

    /* Load server certificate */
    if (mqtt_rc == MQTT_CODE_SUCCESS) {
        if (broker->tls_cert == NULL) {
            WBLOG_ERR(broker, "broker: TLS cert not set (-c)");
            mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
        }
    }
    if (mqtt_rc == MQTT_CODE_SUCCESS) {
#ifndef NO_FILESYSTEM
        wolf_rc = wolfSSL_CTX_use_certificate_file(ctx, broker->tls_cert,
            WOLFSSL_FILETYPE_PEM);
        if (wolf_rc != WOLFSSL_SUCCESS) {
            WBLOG_ERR(broker, "broker: load cert failed %d (%s)",
                wolf_rc, broker->tls_cert);
            mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
        }
#else
        /* File operations not available in NO_FILESYSTEM builds */
        mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
#endif
    }

    /* Load server private key */
    if (mqtt_rc == MQTT_CODE_SUCCESS) {
        if (broker->tls_key == NULL) {
            WBLOG_ERR(broker, "broker: TLS key not set (-K)");
            mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
        }
    }
    if (mqtt_rc == MQTT_CODE_SUCCESS) {
#ifndef NO_FILESYSTEM
        wolf_rc = wolfSSL_CTX_use_PrivateKey_file(ctx, broker->tls_key,
            WOLFSSL_FILETYPE_PEM);
        if (wolf_rc != WOLFSSL_SUCCESS) {
            WBLOG_ERR(broker, "broker: load key failed %d (%s)",
                wolf_rc, broker->tls_key);
            mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
        }
#else
        mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
#endif
    }

    /* Set wolfSSL IO callbacks */
    if (mqtt_rc == MQTT_CODE_SUCCESS) {
        wolfSSL_CTX_SetIORecv(ctx, MqttSocket_TlsSocketReceive);
        wolfSSL_CTX_SetIOSend(ctx, MqttSocket_TlsSocketSend);
    }

    /* Mutual TLS: load CA and require client certificate */
    if (mqtt_rc == MQTT_CODE_SUCCESS && broker->tls_ca != NULL) {
#ifndef NO_FILESYSTEM
        wolf_rc = wolfSSL_CTX_load_verify_locations(ctx, broker->tls_ca,
            NULL);
        if (wolf_rc != WOLFSSL_SUCCESS) {
            WBLOG_ERR(broker, "broker: load CA failed %d (%s)",
                wolf_rc, broker->tls_ca);
            mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
        }
#else
        mqtt_rc = MQTT_CODE_ERROR_BAD_ARG;
#endif
        if (mqtt_rc == MQTT_CODE_SUCCESS) {
            wolfSSL_CTX_set_verify(ctx,
                WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                NULL);
            WBLOG_INFO(broker, "broker: mutual TLS enabled (CA=%s)",
                broker->tls_ca);
        }
    }

    if (mqtt_rc == MQTT_CODE_SUCCESS) {
        broker->tls_ctx = ctx;
        broker->tls_ctx_owned = 1;
    }
    else {
        if (ctx != NULL) {
            wolfSSL_CTX_free(ctx);
        }
        wolfSSL_Cleanup();
    }
    return mqtt_rc;
}

static void BrokerTls_Free(MqttBroker* broker)
{
    if (broker->tls_ctx != NULL) {
        wolfSSL_CTX_free(broker->tls_ctx);
        broker->tls_ctx = NULL;
    }
    wolfSSL_Cleanup();
}
#endif /* ENABLE_MQTT_TLS && !WOLFMQTT_BROKER_CUSTOM_NET */

/* -------------------------------------------------------------------------- */
/* wolfIP network backend                                                      */
/* -------------------------------------------------------------------------- */
#if defined(WOLFMQTT_WOLFIP)

/* Context passed through MqttBrokerNet.ctx */
#ifndef WOLFMQTT_WOLFIP_CTX_DEFINED
#define WOLFMQTT_WOLFIP_CTX_DEFINED
typedef struct BrokerWolfIP_Ctx {
    struct wolfIP *stack;
} BrokerWolfIP_Ctx;
#endif

/* Single-instance context: wolfIP targets are typically embedded systems
 * with one broker instance. For multiple instances, use
 * WOLFMQTT_BROKER_CUSTOM_NET and provide per-instance context. */
static BrokerWolfIP_Ctx broker_wolfip_ctx;

static int BrokerWolfIP_Listen(void* ctx, BROKER_SOCKET_T* sock,
    word16 port, int backlog)
{
    BrokerWolfIP_Ctx* wctx = (BrokerWolfIP_Ctx*)ctx;
    struct wolfIP_sockaddr_in addr;
    BROKER_SOCKET_T fd;

    if (wctx == NULL || wctx->stack == NULL || sock == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    fd = wolfIP_sock_socket(wctx->stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (fd < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = 0; /* INADDR_ANY */

    if (wolfIP_sock_bind(wctx->stack, fd,
            (struct wolfIP_sockaddr*)&addr, sizeof(addr)) < 0) {
        wolfIP_sock_close(wctx->stack, fd);
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (wolfIP_sock_listen(wctx->stack, fd, backlog) < 0) {
        wolfIP_sock_close(wctx->stack, fd);
        return MQTT_CODE_ERROR_NETWORK;
    }

    *sock = fd;
    return MQTT_CODE_SUCCESS;
}

static int BrokerWolfIP_Accept(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock)
{
    BrokerWolfIP_Ctx* wctx = (BrokerWolfIP_Ctx*)ctx;
    BROKER_SOCKET_T fd;

    if (wctx == NULL || wctx->stack == NULL || client_sock == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    fd = wolfIP_sock_accept(wctx->stack, listen_sock, NULL, NULL);
    if (fd == -WOLFIP_EAGAIN) {
        /* No pending connection */
        return MQTT_CODE_CONTINUE;
    }
    if (fd < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    *client_sock = fd;
    return MQTT_CODE_SUCCESS;
}

static int BrokerWolfIP_Read(void* ctx, BROKER_SOCKET_T sock,
    byte* buf, int buf_len, int timeout_ms)
{
    BrokerWolfIP_Ctx* wctx = (BrokerWolfIP_Ctx*)ctx;
    int rc;
    (void)timeout_ms;

    if (wctx == NULL || wctx->stack == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    rc = wolfIP_sock_recv(wctx->stack, sock, buf, (size_t)buf_len, 0);
    /* -WOLFIP_EAGAIN: no data yet; -1: socket not yet in ESTABLISHED state */
    if (rc == -WOLFIP_EAGAIN || rc == -1) {
        return MQTT_CODE_CONTINUE;
    }
    if (rc <= 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    return rc;
}

static int BrokerWolfIP_Write(void* ctx, BROKER_SOCKET_T sock,
    const byte* buf, int buf_len, int timeout_ms)
{
    BrokerWolfIP_Ctx* wctx = (BrokerWolfIP_Ctx*)ctx;
    int rc;
    (void)timeout_ms;

    if (wctx == NULL || wctx->stack == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    rc = wolfIP_sock_send(wctx->stack, sock, buf, (size_t)buf_len, 0);
    /* -WOLFIP_EAGAIN: send buffer full; -1: socket not yet in ESTABLISHED state */
    if (rc == -WOLFIP_EAGAIN || rc == -1) {
        return MQTT_CODE_CONTINUE;
    }
    if (rc <= 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }
    return rc;
}

static int BrokerWolfIP_Close(void* ctx, BROKER_SOCKET_T sock)
{
    BrokerWolfIP_Ctx* wctx = (BrokerWolfIP_Ctx*)ctx;

    if (wctx != NULL && wctx->stack != NULL &&
        sock != BROKER_SOCKET_INVALID) {
        wolfIP_sock_close(wctx->stack, sock);
    }
    return MQTT_CODE_SUCCESS;
}

int MqttBrokerNet_wolfIP_Init(MqttBrokerNet* net, void* wolfIP_stack)
{
    if (net == NULL || wolfIP_stack == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    XMEMSET(net, 0, sizeof(*net));
    XMEMSET(&broker_wolfip_ctx, 0, sizeof(broker_wolfip_ctx));
    broker_wolfip_ctx.stack = (struct wolfIP*)wolfIP_stack;

    net->listen = BrokerWolfIP_Listen;
    net->accept = BrokerWolfIP_Accept;
    net->read   = BrokerWolfIP_Read;
    net->write  = BrokerWolfIP_Write;
    net->close  = BrokerWolfIP_Close;
    net->ctx    = &broker_wolfip_ctx;
    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Default POSIX network backend                                               */
/* -------------------------------------------------------------------------- */
#elif !defined(WOLFMQTT_BROKER_CUSTOM_NET)

static int BrokerPosix_SetNonBlocking(BROKER_SOCKET_T fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    return MQTT_CODE_SUCCESS;
}

static int BrokerPosix_Listen(void* ctx, BROKER_SOCKET_T* sock,
    word16 port, int backlog)
{
    struct sockaddr_in addr;
    int opt = 1;
    BROKER_SOCKET_T fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: socket failed (%d)", errno);
        return MQTT_CODE_ERROR_NETWORK;
    }

    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (BrokerPosix_SetNonBlocking(fd) != MQTT_CODE_SUCCESS) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: set nonblocking failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }

    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: bind failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (listen(fd, backlog) < 0) {
        WBLOG_ERR((MqttBroker*)ctx, "broker: listen failed (%d)", errno);
        close(fd);
        return MQTT_CODE_ERROR_NETWORK;
    }

    *sock = fd;
    return MQTT_CODE_SUCCESS;
}

static int BrokerPosix_Accept(void* ctx, BROKER_SOCKET_T listen_sock,
    BROKER_SOCKET_T* client_sock)
{
    BROKER_SOCKET_T fd;
#ifdef SO_NOSIGPIPE
    int on = 1;
#endif
    (void)ctx;

    fd = accept(listen_sock, NULL, NULL);
    if (fd < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return MQTT_CODE_CONTINUE;
        }
        return MQTT_CODE_ERROR_NETWORK;
    }
    if (BrokerPosix_SetNonBlocking(fd) != MQTT_CODE_SUCCESS) {
        close(fd);
        return MQTT_CODE_ERROR_SYSTEM;
    }
#ifdef SO_NOSIGPIPE
    /* macOS / BSDs: suppress SIGPIPE on writes to a peer-closed socket.
     * Without this (and without MSG_NOSIGNAL in send()), a client that
     * publishes QoS>0 and immediately closes its socket would cause the
     * broker's PUBACK/PUBREC write to deliver SIGPIPE, terminating the
     * broker. Linux uses MSG_NOSIGNAL in BrokerPosix_Write instead. */
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    *client_sock = fd;
    return MQTT_CODE_SUCCESS;
}

static int BrokerPosix_Read(void* ctx, BROKER_SOCKET_T sock,
    byte* buf, int buf_len, int timeout_ms)
{
    fd_set rfds;
    struct timeval tv;
    int rc;

    if (buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (sock < 0 || sock >= FD_SETSIZE) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(sock + 1, &rfds, NULL, NULL, &tv);
    if (rc == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (rc < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    rc = (int)recv(sock, buf, (size_t)buf_len, 0);
    if (rc <= 0) {
        if (rc < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return MQTT_CODE_CONTINUE;
        }
        WBLOG_ERR((MqttBroker*)ctx, "broker: recv error sock=%d rc=%d errno=%d",
            (int)sock, rc, errno);
        return MQTT_CODE_ERROR_NETWORK;
    }
    return rc;
}

static int BrokerPosix_Write(void* ctx, BROKER_SOCKET_T sock,
    const byte* buf, int buf_len, int timeout_ms)
{
    fd_set wfds;
    struct timeval tv;
    int rc;

    if (buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (sock < 0 || sock >= FD_SETSIZE) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    rc = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (rc == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }
    if (rc < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    /* MSG_NOSIGNAL (Linux/BSDs that define it) prevents SIGPIPE delivery when
     * the peer has already closed the connection - the syscall just returns
     * EPIPE and we treat it as a normal network error. Platforms without
     * MSG_NOSIGNAL (e.g. macOS) rely on the SO_NOSIGPIPE socket option set
     * in BrokerPosix_Accept. */
#ifdef MSG_NOSIGNAL
    rc = (int)send(sock, buf, (size_t)buf_len, MSG_NOSIGNAL);
#else
    rc = (int)send(sock, buf, (size_t)buf_len, 0);
#endif
    if (rc <= 0) {
        if (rc < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return MQTT_CODE_CONTINUE;
        }
        WBLOG_ERR((MqttBroker*)ctx, "broker: send error sock=%d rc=%d errno=%d",
            (int)sock, rc, errno);
        return MQTT_CODE_ERROR_NETWORK;
    }
    return rc;
}

static int BrokerPosix_Close(void* ctx, BROKER_SOCKET_T sock)
{
    (void)ctx;
    if (sock != BROKER_SOCKET_INVALID) {
        close(sock);
    }
    return MQTT_CODE_SUCCESS;
}

int MqttBrokerNet_Init(MqttBrokerNet* net)
{
#ifdef SIGPIPE
    struct sigaction sa;
#endif
    if (net == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
#ifdef SIGPIPE
    /* Backstop the per-send (MSG_NOSIGNAL) and per-socket (SO_NOSIGPIPE)
     * suppression so a write to a peer-closed socket cannot terminate the
     * process on platforms that define neither, or if the SO_NOSIGPIPE
     * setsockopt in BrokerPosix_Accept fails. Only install the ignore when
     * SIGPIPE is still at its default disposition, so we never clobber a
     * SIGPIPE handler the embedding application has already chosen. The
     * targeted mechanisms remain primary so send() still returns EPIPE for
     * clean client teardown. */
    if (sigaction(SIGPIPE, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL) {
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        (void)sigaction(SIGPIPE, &sa, NULL);
    }
#endif
    XMEMSET(net, 0, sizeof(*net));
    net->listen = BrokerPosix_Listen;
    net->accept = BrokerPosix_Accept;
    net->read   = BrokerPosix_Read;
    net->write  = BrokerPosix_Write;
    net->close  = BrokerPosix_Close;
    net->ctx    = NULL;
    return MQTT_CODE_SUCCESS;
}



#endif /* WOLFMQTT_WOLFIP / !WOLFMQTT_BROKER_CUSTOM_NET */

/* -------------------------------------------------------------------------- */
/* WebSocket server support (libwebsockets)                                    */
/* -------------------------------------------------------------------------- */
#ifdef ENABLE_MQTT_WEBSOCKET

#include <libwebsockets.h>

/* Compatibility for older libwebsockets versions (pre-4.1) */
#ifndef LWS_PROTOCOL_LIST_TERM
    #define LWS_PROTOCOL_LIST_TERM { NULL, NULL, 0, 0, 0, NULL, 0 }
#endif

/* Forward declaration for the no-op connect callback (defined after WS section) */
static int BrokerNetConnect(void* context, const char* host, word16 port,
    int timeout_ms);

/* Forward declarations for WS-specific MqttNet callbacks */
static int BrokerWsNetRead(void* context, byte* buf, int buf_len,
    int timeout_ms);
static int BrokerWsNetWrite(void* context, const byte* buf, int buf_len,
    int timeout_ms);
static int BrokerWsNetDisconnect(void* context);

/* Forward declarations for client management used by lws callback */
static void BrokerSubs_RemoveClient(MqttBroker* broker, BrokerClient* bc);
static void BrokerClient_Remove(MqttBroker* broker, BrokerClient* bc);
#ifdef WOLFMQTT_BROKER_WILL
static void BrokerClient_PublishWill(MqttBroker* broker, BrokerClient* bc);
#endif

static BrokerClient* BrokerClient_AddWs(MqttBroker* broker, struct lws *wsi)
{
    BrokerClient* bc = NULL;
    int rc = MQTT_CODE_SUCCESS;
    BrokerWsCtx* ws;

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
            if (!broker->clients[i].in_use) {
                bc = &broker->clients[i];
                break;
            }
        }
        if (bc == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(bc, 0, sizeof(*bc));
            bc->in_use = 1;
        }
    }
#else
    bc = (BrokerClient*)WOLFMQTT_MALLOC(sizeof(BrokerClient));
    if (bc == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(bc, 0, sizeof(*bc));
        bc->tx_buf_len = BROKER_TX_BUF_SZ;
        bc->rx_buf_len = BROKER_RX_BUF_SZ;
        bc->tx_buf = (byte*)WOLFMQTT_MALLOC(bc->tx_buf_len);
        bc->rx_buf = (byte*)WOLFMQTT_MALLOC(bc->rx_buf_len);
        if (bc->tx_buf == NULL || bc->rx_buf == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }
#endif

    /* Allocate WebSocket context */
    if (rc == MQTT_CODE_SUCCESS) {
        ws = (BrokerWsCtx*)WOLFMQTT_MALLOC(sizeof(BrokerWsCtx));
        if (ws == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        else {
            XMEMSET(ws, 0, sizeof(*ws));
            ws->wsi = wsi;
            ws->status = 1; /* established */
            bc->ws_ctx = ws;
        }
    }

    if (rc == MQTT_CODE_SUCCESS) {
        bc->sock = BROKER_SOCKET_INVALID;
        bc->broker = broker;
        bc->protocol_level = 0;
        bc->keep_alive_sec = 0;
        bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();

        /* Use WS-specific MqttNet callbacks instead of broker->net */
        bc->net.context = bc;
        bc->net.connect = BrokerNetConnect; /* no-op, but must be non-NULL */
        bc->net.read = BrokerWsNetRead;
        bc->net.write = BrokerWsNetWrite;
        bc->net.disconnect = BrokerWsNetDisconnect;

#ifdef ENABLE_MQTT_TLS
        /* lws handles TLS internally for WSS - skip wolfSSL setup */
        bc->tls_handshake_done = 1;
#endif

        rc = MqttClient_Init(&bc->client, &bc->net, NULL,
                bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
                bc->rx_buf, BROKER_CLIENT_RX_SZ(bc), BROKER_TIMEOUT_MS);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: ws client init failed rc=%d", rc);
        }
    }

    if (rc == MQTT_CODE_SUCCESS) {
#ifndef WOLFMQTT_STATIC_MEMORY
        bc->next = broker->clients;
        broker->clients = bc;
#endif
        WBLOG_INFO(broker, "broker: ws client added (wsi=%p)", (void*)wsi);
    }
    else if (bc != NULL) {
        if (bc->ws_ctx) {
            WOLFMQTT_FREE(bc->ws_ctx);
            bc->ws_ctx = NULL;
        }
#ifdef WOLFMQTT_STATIC_MEMORY
        XMEMSET(bc, 0, sizeof(*bc));
#else
        if (bc->tx_buf) WOLFMQTT_FREE(bc->tx_buf);
        if (bc->rx_buf) WOLFMQTT_FREE(bc->rx_buf);
        WOLFMQTT_FREE(bc);
#endif
        bc = NULL;
    }

    return bc;
}

/* lws server protocol callback */
static int callback_broker_mqtt(struct lws *wsi,
    enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    struct lws_context *ctx = lws_get_context(wsi);
    MqttBroker *broker = (MqttBroker*)lws_context_user(ctx);
    BrokerWsCtx *ws;
    BrokerClient *bc;

    (void)user;

    if (reason == LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION) {
        /* CSWSH defense: when an Origin allowlist is configured, reject a
         * browser-supplied Origin that does not match exactly. Requests with
         * no Origin header (native clients) are not browser-originated and are
         * allowed through. */
        if (broker != NULL && broker->ws_allowed_origin != NULL) {
            char origin[256];
            int olen = lws_hdr_copy(wsi, origin, (int)sizeof(origin),
                WSI_TOKEN_ORIGIN);
            if (olen > 0 &&
                    XSTRCMP(origin, broker->ws_allowed_origin) != 0) {
                WBLOG_ERR(broker, "broker: ws origin rejected: %s",
                    BrokerLog_Sanitize(origin));
                return -1;
            }
        }
    }
    else if (reason == LWS_CALLBACK_ESTABLISHED) {
        bc = BrokerClient_AddWs(broker, wsi);
        if (bc == NULL) {
            WBLOG_ERR(broker, "broker: ws accept rejected (alloc)");
            return -1; /* reject connection */
        }
        /* Store BrokerClient pointer in lws user data for later lookup */
        *((BrokerClient**)lws_wsi_user(wsi)) = bc;
    }
    else if (reason == LWS_CALLBACK_RECEIVE) {
        BrokerClient **bc_ptr = (BrokerClient**)lws_wsi_user(wsi);
        if (bc_ptr == NULL || *bc_ptr == NULL) return 0;
        bc = *bc_ptr;
        ws = (BrokerWsCtx*)bc->ws_ctx;
        if (ws == NULL || in == NULL || len == 0) return 0;

        /* Append data to rx_buffer */
        if (ws->rx_len + len <= sizeof(ws->rx_buffer)) {
            XMEMCPY(ws->rx_buffer + ws->rx_len, in, len);
            ws->rx_len += len;
        }
        else {
            /* Dropping bytes would desynchronize MQTT packet framing,
             * so treat overflow as a fatal protocol error. */
            WBLOG_ERR(broker, "broker: ws rx buffer overflow "
                "(wsi=%p, have=%d, need=%d, max=%d)",
                (void*)wsi, (int)ws->rx_len, (int)len,
                (int)sizeof(ws->rx_buffer));
            return -1; /* close connection */
        }
    }
    else if (reason == LWS_CALLBACK_SERVER_WRITEABLE) {
        BrokerClient **bc_ptr = (BrokerClient**)lws_wsi_user(wsi);
        if (bc_ptr == NULL || *bc_ptr == NULL) return 0;
        bc = *bc_ptr;
        ws = (BrokerWsCtx*)bc->ws_ctx;
        if (ws == NULL) return 0;

        if (ws->pending_close) {
            /* Broker-initiated close: stage the close code here (inside a
             * callback) where lws_close_reason() is actually effective, then
             * return -1 to trigger the WebSocket close handshake. */
            lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
            return -1;
        }

        if (ws->tx_pending != NULL && ws->tx_len > 0) {
            int n = lws_write(wsi, ws->tx_pending + LWS_PRE,
                ws->tx_len, LWS_WRITE_BINARY);
            if (n < (int)ws->tx_len) {
                WBLOG_ERR(broker, "broker: ws write failed (wsi=%p, "
                    "n=%d, len=%d)", (void*)wsi, n, (int)ws->tx_len);
                WOLFMQTT_FREE(ws->tx_pending);
                ws->tx_pending = NULL;
                ws->tx_len = 0;
                ws->status = -1;
                return -1;
            }
            WOLFMQTT_FREE(ws->tx_pending);
            ws->tx_pending = NULL;
            ws->tx_len = 0;
        }
    }
    else if (reason == LWS_CALLBACK_CLOSED) {
        BrokerClient **bc_ptr = (BrokerClient**)lws_wsi_user(wsi);
        if (bc_ptr == NULL || *bc_ptr == NULL) return 0;
        bc = *bc_ptr;
        ws = (BrokerWsCtx*)bc->ws_ctx;

        WBLOG_INFO(broker, "broker: ws closed (wsi=%p)", (void*)wsi);

        /* Mark WS context as closed so disconnect callback won't
         * try to close the wsi again */
        if (ws != NULL) {
            ws->status = 0;
            ws->wsi = NULL;

            if (ws->pending_close) {
                /* Broker-initiated close: BrokerClient_Remove is already on
                 * the call stack (BrokerWsNetDisconnect's spin loop drove us
                 * here). Signal completion and return - do NOT call
                 * BrokerClient_Remove again. */
                *bc_ptr = NULL;
                return 0;
            }
        }

        /* Peer-initiated close: publish will and remove client. */
        BrokerClient_PublishWill(broker, bc);
        BrokerSubs_RemoveClient(broker, bc);
        *bc_ptr = NULL;
        if (ws != NULL && ws->processing) {
            /* bc is on the call stack inside BrokerClient_Process (a packet
             * handler triggered a lws_service spin that delivered this CLOSED
             * callback).  Freeing bc now would leave dangling pointers in the
             * packet handler - e.g. the fan-out payload pointing into rx_buf,
             * or the post-fan-out PUBACK write into tx_buf.  Defer the free;
             * BrokerClient_Process will call BrokerClient_Remove on return. */
            ws->pending_remove = 1;
        }
        else {
            BrokerClient_Remove(broker, bc);
        }
    }

    return 0;
}

static const struct lws_protocols broker_ws_protocols[] = {
    {
        "mqtt",
        callback_broker_mqtt,
        sizeof(BrokerClient*),      /* per-session user data = pointer */
        BROKER_WS_RX_BUF_SZ,       /* rx buffer size */
        0,                          /* id */
        NULL,                       /* user */
        0                           /* tx_packet_size */
    },
    LWS_PROTOCOL_LIST_TERM
};

/* WS-specific MqttNet callbacks */
static int BrokerWsNetRead(void* context, byte* buf, int buf_len,
    int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    BrokerWsCtx* ws;
    int ret;

    (void)timeout_ms;

    if (bc == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    ws = (BrokerWsCtx*)bc->ws_ctx;
    if (ws == NULL || ws->status <= 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    if (ws->rx_len == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }

    ret = (ws->rx_len <= (size_t)buf_len) ? (int)ws->rx_len : buf_len;
    XMEMCPY(buf, ws->rx_buffer, ret);

    if (ret < (int)ws->rx_len) {
        XMEMMOVE(ws->rx_buffer, ws->rx_buffer + ret, ws->rx_len - ret);
        ws->rx_len -= ret;
        /* Scrub the vacated tail so consumed CONNECT credentials do not
         * linger in the WS staging buffer. */
        BROKER_FORCE_ZERO(ws->rx_buffer + ws->rx_len, (word32)ret);
    }
    else {
        /* Scrub the whole consumed buffer (may hold username/password). */
        BROKER_FORCE_ZERO(ws->rx_buffer, (word32)ws->rx_len);
        ws->rx_len = 0;
    }

    return ret;
}

static int BrokerWsNetWrite(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    BrokerWsCtx* ws;
    int attempts = 0;
    int prev_processing;

    (void)timeout_ms;

    if (bc == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    ws = (BrokerWsCtx*)bc->ws_ctx;
    if (ws == NULL || ws->status <= 0 || ws->wsi == NULL) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    /* Free any prior unsent data */
    if (ws->tx_pending != NULL) {
        WOLFMQTT_FREE(ws->tx_pending);
        ws->tx_pending = NULL;
        ws->tx_len = 0;
    }

    /* Allocate buffer with LWS_PRE prefix space */
    ws->tx_pending = (byte*)WOLFMQTT_MALLOC(LWS_PRE + buf_len);
    if (ws->tx_pending == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMCPY(ws->tx_pending + LWS_PRE, buf, buf_len);
    ws->tx_len = (size_t)buf_len;

    /* Request writable callback and service until data is flushed. Mark this
     * context busy across the spin so a peer-initiated LWS_CALLBACK_CLOSED for
     * this wsi (e.g. a subscriber whose peer closes during publish fan-out)
     * takes the deferred-remove path instead of freeing ws and bc out from
     * under this function. Mirrors the publisher guard in BrokerClient_Process. */
    lws_callback_on_writable((struct lws*)ws->wsi);
    prev_processing = ws->processing;
    ws->processing = 1;
    while (ws->tx_pending != NULL && ws->status > 0 && attempts < 100) {
        lws_service(lws_get_context((struct lws*)ws->wsi), 0);
        attempts++;
    }
    ws->processing = prev_processing;

    if (ws->tx_pending != NULL) {
        /* Data was not flushed - connection may be in bad state */
        WOLFMQTT_FREE(ws->tx_pending);
        ws->tx_pending = NULL;
        ws->tx_len = 0;
        return MQTT_CODE_ERROR_NETWORK;
    }

    /* Check if the write callback reported an error (it frees tx_pending
     * and sets status to -1 before returning -1 to lws) */
    if (ws->status < 0) {
        return MQTT_CODE_ERROR_NETWORK;
    }

    return buf_len;
}

static int BrokerWsNetDisconnect(void* context)
{
    BrokerClient* bc = (BrokerClient*)context;
    BrokerWsCtx* ws;

    if (bc == NULL) {
        return MQTT_CODE_SUCCESS;
    }

    ws = (BrokerWsCtx*)bc->ws_ctx;
    if (ws == NULL) {
        return MQTT_CODE_SUCCESS;
    }

    if (ws->wsi != NULL && ws->status > 0) {
        struct lws *wsi_local = (struct lws*)ws->wsi;
        struct lws_context *lws_ctx = lws_get_context(wsi_local);
        int attempts = 0;

        WBLOG_INFO(bc->broker, "broker: ws disconnect (wsi=%p)", (void*)ws->wsi);

        /* Signal the WRITEABLE callback to send a close frame and return -1.
         * lws_close_reason() is only effective from inside a callback, so the
         * flag + writable-callback + return(-1) pattern is used here to
         * properly initiate the WebSocket close handshake. */
        ws->pending_close = 1;
        lws_callback_on_writable(wsi_local);

        /* Spin until LWS_CALLBACK_CLOSED fires and clears ws->wsi. */
        while (ws->wsi != NULL && attempts < 100) {
            lws_service(lws_ctx, 0);
            attempts++;
        }

        /* Fallback: if the close handshake did not complete in time, null out
         * the per-session user data so any future callback cannot dereference
         * the about-to-be-freed bc. The wsi is left for lws to reclaim via
         * its own keep-alive machinery. */
        if (ws->wsi != NULL) {
            BrokerClient **bc_ptr = (BrokerClient**)lws_wsi_user(wsi_local);
            if (bc_ptr != NULL) {
                *bc_ptr = NULL;
            }
            ws->wsi = NULL;
        }
    }

    if (ws->tx_pending != NULL) {
        WOLFMQTT_FREE(ws->tx_pending);
        ws->tx_pending = NULL;
    }
    ws->tx_len = 0;
    /* Scrub any unconsumed staged bytes (may hold credentials) before free. */
    BROKER_FORCE_ZERO(ws->rx_buffer, (word32)sizeof(ws->rx_buffer));
    ws->rx_len = 0;
    ws->status = 0;

    WOLFMQTT_FREE(ws);
    bc->ws_ctx = NULL;

    return MQTT_CODE_SUCCESS;
}

static int BrokerWs_Init(MqttBroker* broker)
{
    struct lws_context_creation_info info;

    XMEMSET(&info, 0, sizeof(info));
    info.port = broker->ws_port;
    info.protocols = broker_ws_protocols;
    info.gid = -1;
    info.uid = -1;
    info.user = broker;

    /* WSS (TLS over WebSocket) configuration */
    if (broker->ws_tls_cert != NULL) {
        info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        info.ssl_cert_filepath = broker->ws_tls_cert;
        info.ssl_private_key_filepath = broker->ws_tls_key;
        if (broker->ws_tls_ca != NULL) {
            info.ssl_ca_filepath = broker->ws_tls_ca;
        }
    }

    broker->ws_ctx = lws_create_context(&info);
    if (broker->ws_ctx == NULL) {
        WBLOG_ERR(broker, "broker: lws_create_context failed");
        return MQTT_CODE_ERROR_NETWORK;
    }

    WBLOG_INFO(broker, "broker: WebSocket listening on port %d%s",
        broker->ws_port, broker->ws_tls_cert ? " (WSS)" : "");
    return MQTT_CODE_SUCCESS;
}

static void BrokerWs_Free(MqttBroker* broker)
{
    if (broker->ws_ctx != NULL) {
        lws_context_destroy(broker->ws_ctx);
        broker->ws_ctx = NULL;
    }
}

#endif /* ENABLE_MQTT_WEBSOCKET */

/* BrokerNextPacketId forward declaration. The body lives in the broker
 * core section below. Used by both the WebSocket branch and the orphan
 * enqueue helpers earlier in the file, so the forward decl is hoisted
 * out of the ENABLE_MQTT_WEBSOCKET guard. */
static word16 BrokerNextPacketId(MqttBroker* broker);

/* -------------------------------------------------------------------------- */
/* Per-client MqttNet callbacks (route through MqttBrokerNet)                  */
/* -------------------------------------------------------------------------- */
static int BrokerNetConnect(void* context, const char* host, word16 port,
    int timeout_ms)
{
    /* Server side: connection already established via accept() */
    (void)context;
    (void)host;
    (void)port;
    (void)timeout_ms;
    return MQTT_CODE_SUCCESS;
}

static int BrokerNetRead(void* context, byte* buf, int buf_len,
    int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    if (bc == NULL || bc->broker == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    return bc->broker->net.read(bc->broker->net.ctx, bc->sock,
        buf, buf_len, timeout_ms);
}

static int BrokerNetWrite(void* context, const byte* buf, int buf_len,
    int timeout_ms)
{
    BrokerClient* bc = (BrokerClient*)context;
    if (bc == NULL || bc->broker == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    return bc->broker->net.write(bc->broker->net.ctx, bc->sock,
        buf, buf_len, timeout_ms);
}

static int BrokerNetDisconnect(void* context)
{
    BrokerClient* bc = (BrokerClient*)context;
    if (bc != NULL && bc->broker != NULL &&
        bc->sock != BROKER_SOCKET_INVALID) {
        WBLOG_INFO(bc->broker, "broker: disconnect sock=%d", (int)bc->sock);
        bc->broker->net.close(bc->broker->net.ctx, bc->sock);
        bc->sock = BROKER_SOCKET_INVALID;
    }
    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Client management                                                           */
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* Inbound QoS 2 dedup state (per [MQTT-4.3.3])                                */
/*                                                                             */
/* Track packet IDs for which we've sent PUBREC and are waiting for PUBREL.    */
/* A duplicate PUBLISH carrying the same packet ID gets PUBREC'd again but     */
/* must NOT be re-delivered to subscribers. The state is per-client and is    */
/* cleared on disconnect; surviving across reconnect would require the         */
/* broader session-state work (see #485/#489/#494).                            */
/*                                                                             */
/* The entire QoS 2 inbound state and PUBREL/PUBREC/PUBCOMP handling is        */
/* compiled out when WOLFMQTT_MAX_QOS < 2. Subscribe-grant capping and         */
/* inbound-publish QoS rejection cover the corresponding wire paths.           */
/* -------------------------------------------------------------------------- */

#if WOLFMQTT_MAX_QOS >= 2
/* Returns 1 if packet_id is currently awaiting PUBREL, 0 otherwise. */
static int BrokerInboundQos2_Contains(BrokerClient* bc, word16 packet_id)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerInboundQos2* cur;
#endif

    if (bc == NULL || packet_id == 0) {
        return 0;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_INBOUND_QOS2; i++) {
        if (bc->qos2_pending[i] == packet_id) {
            return 1;
        }
    }
#else
    cur = bc->qos2_pending;
    while (cur != NULL) {
        if (cur->packet_id == packet_id) {
            return 1;
        }
        cur = cur->next;
    }
#endif
    return 0;
}

/* Add packet_id to the awaiting-PUBREL set. Returns MQTT_CODE_SUCCESS on
 * success, MQTT_CODE_ERROR_OUT_OF_BUFFER if the per-client cap is reached,
 * or MQTT_CODE_ERROR_MEMORY if the underlying allocator fails. Idempotent:
 * a second add of an already-present packet_id is a no-op success. */
static int BrokerInboundQos2_Add(BrokerClient* bc, word16 packet_id)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerInboundQos2 *node;
#endif

    if (bc == NULL || packet_id == 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (BrokerInboundQos2_Contains(bc, packet_id)) {
        return MQTT_CODE_SUCCESS;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_INBOUND_QOS2; i++) {
        if (bc->qos2_pending[i] == 0) {
            bc->qos2_pending[i] = packet_id;
            return MQTT_CODE_SUCCESS;
        }
    }
    return MQTT_CODE_ERROR_OUT_OF_BUFFER;
#else
    /* Enforce the same per-client cap in dynamic-memory builds so a
     * misbehaving client cannot grow the list to ~65 535 entries. */
    if (bc->qos2_pending_count >= BROKER_MAX_INBOUND_QOS2) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    node = (BrokerInboundQos2*)WOLFMQTT_MALLOC(sizeof(*node));
    if (node == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    node->packet_id = packet_id;
    node->next = bc->qos2_pending;
    bc->qos2_pending = node;
    bc->qos2_pending_count++;
    return MQTT_CODE_SUCCESS;
#endif
}

/* Remove packet_id from the awaiting-PUBREL set. No-op if not present. */
static void BrokerInboundQos2_Remove(BrokerClient* bc, word16 packet_id)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerInboundQos2* prev = NULL;
    BrokerInboundQos2* cur;
#endif

    if (bc == NULL || packet_id == 0) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_INBOUND_QOS2; i++) {
        if (bc->qos2_pending[i] == packet_id) {
            bc->qos2_pending[i] = 0;
            return;
        }
    }
#else
    cur = bc->qos2_pending;
    while (cur != NULL) {
        if (cur->packet_id == packet_id) {
            if (prev == NULL) {
                bc->qos2_pending = cur->next;
            }
            else {
                prev->next = cur->next;
            }
            WOLFMQTT_FREE(cur);
            if (bc->qos2_pending_count > 0) {
                bc->qos2_pending_count--;
            }
            else {
                /* This should never happen.
                 * Count should never be negative. */
                WBLOG_ERR(bc->broker,
                    "broker: qos2_pending_count underflow");
            }
            return;
        }
        prev = cur;
        cur = cur->next;
    }
#endif
}

/* Clear all entries (called on client free / disconnect). */
static void BrokerInboundQos2_Clear(BrokerClient* bc)
{
#ifndef WOLFMQTT_STATIC_MEMORY
    BrokerInboundQos2* cur;
#endif

    if (bc == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    XMEMSET(bc->qos2_pending, 0, sizeof(bc->qos2_pending));
#else
    cur = bc->qos2_pending;
    while (cur != NULL) {
        BrokerInboundQos2* next = cur->next;
        WOLFMQTT_FREE(cur);
        cur = next;
    }
    bc->qos2_pending = NULL;
    bc->qos2_pending_count = 0;
#endif
}
#endif /* WOLFMQTT_MAX_QOS >= 2 */

#ifndef WOLFMQTT_STATIC_MEMORY
/* -------------------------------------------------------------------------- */
/* Per-subscriber outbound publish queue (dynamic memory only).
 *
 * Adds the message-shaping layer asked for in customer report #7 (ordered
 * delivery) and consumed later by report-#5 follow-up work and PR2's
 * offline queue. Fan-out enqueues; drain dispatches up to the inflight
 * cap. Drain is also called from PUBACK / PUBREC / PUBCOMP handlers and
 * once per select() tick so a slow subscriber that just opened a window
 * gets unblocked promptly.                                                  */
/* -------------------------------------------------------------------------- */

/* Free a single queue entry (topic, payload, the entry itself). */
static void BrokerOutPub_Free(BrokerOutPub* e)
{
    if (e == NULL) {
        return;
    }
    if (e->topic != NULL) {
        WOLFMQTT_FREE(e->topic);
        e->topic = NULL;
    }
    if (e->payload != NULL) {
        WOLFMQTT_FREE(e->payload);
        e->payload = NULL;
    }
    WOLFMQTT_FREE(e);
}

/* Allocate a new entry holding a deep copy of topic + payload. Returns
 * NULL on allocation failure (caller decides whether that means drop or
 * close). All fields are zero-initialized; caller fills qos / packet_id /
 * etc. and links into out_q via BrokerClient_EnqueueOutPub. */
static BrokerOutPub* BrokerOutPub_Alloc(const char* topic,
    const byte* payload, word32 payload_len)
{
    BrokerOutPub* e;
    size_t topic_len;

    if (topic == NULL) {
        return NULL;
    }
    topic_len = XSTRLEN(topic);

    e = (BrokerOutPub*)WOLFMQTT_MALLOC(sizeof(BrokerOutPub));
    if (e == NULL) {
        return NULL;
    }
    XMEMSET(e, 0, sizeof(*e));

    e->topic = (char*)WOLFMQTT_MALLOC(topic_len + 1);
    if (e->topic == NULL) {
        BrokerOutPub_Free(e);
        return NULL;
    }
    XMEMCPY(e->topic, topic, topic_len);
    e->topic[topic_len] = '\0';

    if (payload_len > 0 && payload != NULL) {
        e->payload = (byte*)WOLFMQTT_MALLOC(payload_len);
        if (e->payload == NULL) {
            BrokerOutPub_Free(e);
            return NULL;
        }
        XMEMCPY(e->payload, payload, payload_len);
        e->payload_len = payload_len;
    }
    return e;
}

/* Append e to the subscriber's out_q tail. Caller is responsible for
 * counting against any caps before allocation. */
static void BrokerClient_EnqueueOutPub(BrokerClient* bc, BrokerOutPub* e)
{
    if (bc == NULL || e == NULL) {
        return;
    }
    e->next = NULL;
    if (bc->out_q_tail == NULL) {
        bc->out_q_head = e;
        bc->out_q_tail = e;
    }
    else {
        bc->out_q_tail->next = e;
        bc->out_q_tail = e;
    }
    bc->out_q_count++;
}

/* Walk out_q and free every entry. Called from BrokerClient_Free. */
static void BrokerClient_FreeOutQueue(BrokerClient* bc)
{
    BrokerOutPub* cur;

    if (bc == NULL) {
        return;
    }
    cur = bc->out_q_head;
    while (cur != NULL) {
        BrokerOutPub* next = cur->next;
        BrokerOutPub_Free(cur);
        cur = next;
    }
    bc->out_q_head = NULL;
    bc->out_q_tail = NULL;
    bc->out_q_count = 0;
    bc->out_q_inflight = 0;
}

/* Send as many QUEUED entries from out_q as the inflight cap allows.
 *
 * Ordering: walks from out_q_head, never reorders. Already-sent entries
 * (state != QUEUED) are stepped over - their PUBLISH already hit the
 * wire in publish order. The cap stops the drain at the first QUEUED
 * QoS>0 entry that would exceed BROKER_MAX_INFLIGHT_PER_SUB (or the v5
 * client's Receive Maximum, whichever is smaller). [MQTT-4.6.0-3] is
 * preserved: even a QUEUED QoS 0 behind a capped QoS>0 stays put. */
static void BrokerClient_DrainOutQueue(BrokerClient* bc)
{
    BrokerOutPub* cur;
    BrokerOutPub* prev;
    int effective_cap;

    if (bc == NULL || bc->out_q_head == NULL) {
        return;
    }

    effective_cap = BROKER_MAX_INFLIGHT_PER_SUB;
    if (bc->client_receive_max != 0 &&
        (int)bc->client_receive_max < effective_cap) {
        effective_cap = (int)bc->client_receive_max;
    }

    prev = NULL;
    cur = bc->out_q_head;
    while (cur != NULL) {
        MqttPublish out_pub;
        int enc_rc;

        if (cur->state != BROKER_OUTQ_QUEUED) {
#if WOLFMQTT_MAX_QOS >= 2
            /* A QoS 2 entry restored to PUBREL_SENT by BrokerOrphan_Reclaim
             * (retransmit_dup set) must have its PUBREL re-sent on session
             * resume per MQTT-4.4.0-1: the subscriber will not re-send
             * PUBREC, so without this the entry and its inflight slot stay
             * stuck forever. Re-send once, then keep awaiting PUBCOMP. */
            if (cur->state == BROKER_OUTQ_PUBREL_SENT && cur->retransmit_dup) {
                MqttPublishResp rel;
                int rel_rc;
                XMEMSET(&rel, 0, sizeof(rel));
                rel.packet_id = cur->packet_id;
            #ifdef WOLFMQTT_V5
                rel.protocol_level = cur->protocol_level;
                rel.reason_code = MQTT_REASON_SUCCESS;
            #endif
                rel_rc = MqttEncode_PublishResp(bc->tx_buf,
                            BROKER_CLIENT_TX_SZ(bc),
                            MQTT_PACKET_TYPE_PUBLISH_REL, &rel);
                if (rel_rc > 0) {
                    if (MqttPacket_Write(&bc->client, bc->tx_buf,
                            rel_rc) < 0) {
                        return; /* socket dropped; retry on next reclaim */
                    }
                    cur->retransmit_dup = 0;
                    WBLOG_DBG(bc->broker,
                        "broker: drain re-send PUBREL sock=%d packet_id=%u",
                        (int)bc->sock, (unsigned)cur->packet_id);
                }
            }
#endif
            prev = cur;
            cur = cur->next;
            continue;
        }
        if (cur->qos > MQTT_QOS_0 && bc->out_q_inflight >= effective_cap) {
            /* Cap reached. Stop here - cannot send anything behind it
             * either, because [MQTT-4.6.0-3] requires ordered delivery. */
            break;
        }

        XMEMSET(&out_pub, 0, sizeof(out_pub));
        out_pub.topic_name = cur->topic;
        out_pub.qos        = cur->qos;
        out_pub.packet_id  = cur->packet_id;
        out_pub.retain     = cur->retain;
        /* MQTT-4.4.0-1: DUP=1 on re-send of an unacked PUBLISH after
         * session resumption. Set by BrokerOrphan_Reclaim when an
         * entry was previously in PUBLISH_SENT and got reset to
         * QUEUED here for retransmit. */
        out_pub.duplicate  = cur->retransmit_dup;
        out_pub.buffer     = cur->payload;
        out_pub.total_len  = cur->payload_len;
    #ifdef WOLFMQTT_V5
        out_pub.protocol_level = cur->protocol_level;
    #endif

        enc_rc = MqttEncode_Publish(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
                    &out_pub, 0);
        if (enc_rc <= 0) {
            WBLOG_ERR(bc->broker,
                "broker: drain encode failed sock=%d topic=%s rc=%d",
                (int)bc->sock, BrokerLog_Sanitize(cur->topic), enc_rc);
            /* Drop just this entry and continue. Encoding failure for
             * a single message is not fatal to the connection. */
            if (prev == NULL) {
                bc->out_q_head = cur->next;
            }
            else {
                prev->next = cur->next;
            }
            if (bc->out_q_tail == cur) {
                bc->out_q_tail = prev;
            }
            bc->out_q_count--;
            {
                BrokerOutPub* free_me = cur;
                cur = cur->next;
            #ifdef WOLFMQTT_BROKER_PERSIST
                /* If this entry was previously shadow-written (orphan
                 * path), drop the disk record now so a future restart
                 * cannot replay an undeliverable message. Idempotent
                 * for entries that were never persisted (QoS 0, or
                 * not-yet-orphaned). */
                if (free_me->qos > MQTT_QOS_0 &&
                        BROKER_STR_VALID(bc->client_id)) {
                    (void)BrokerPersist_DelOutPub(bc->broker,
                        bc->client_id, free_me->packet_id);
                }
            #endif
                BrokerOutPub_Free(free_me);
            }
            continue;
        }
        {
            int wr_rc;
            wr_rc = MqttPacket_Write(&bc->client, bc->tx_buf, enc_rc);
            if (wr_rc < 0) {
                /* Socket dropped (EPIPE/ECONNRESET/etc). Leave this
                 * entry in QUEUED state, do not advance, do not bump
                 * inflight. The broker's read path will detect the
                 * close on the next step and re-orphan the client;
                 * still-QUEUED entries follow the orphan and replay
                 * on the next reconnect. Subsequent writes on the
                 * same dead socket would just stack more errors, so
                 * stop the drain here. */
                WBLOG_ERR(bc->broker,
                    "broker: drain write failed sock=%d topic=%s rc=%d",
                    (int)bc->sock, BrokerLog_Sanitize(cur->topic), wr_rc);
                return;
            }
        }
        WBLOG_DBG(bc->broker,
            "broker: drain send sock=%d topic=%s qos=%d packet_id=%u dup=%d",
            (int)bc->sock, BrokerLog_Sanitize(cur->topic), (int)cur->qos,
            (unsigned)cur->packet_id, (int)cur->retransmit_dup);
        cur->retransmit_dup = 0;

        if (cur->qos == MQTT_QOS_0) {
            BrokerOutPub* free_me = cur;
            if (prev == NULL) {
                bc->out_q_head = cur->next;
            }
            else {
                prev->next = cur->next;
            }
            if (bc->out_q_tail == cur) {
                bc->out_q_tail = prev;
            }
            bc->out_q_count--;
            cur = cur->next;
            BrokerOutPub_Free(free_me);
            /* prev unchanged */
        }
        else {
            cur->state = BROKER_OUTQ_PUBLISH_SENT;
            bc->out_q_inflight++;
            prev = cur;
            cur = cur->next;
        }
    }
}

/* Locate the queue entry that matches packet_id and is awaiting an ack
 * in the given expected_state. Returns NULL if no match (e.g., spurious
 * ack, or our state has already moved on). On match returns the entry
 * (still linked) and sets *out_prev to the predecessor (or NULL when
 * the match is at head) so the caller can unlink in O(1). */
static BrokerOutPub* BrokerClient_FindOutPub(BrokerClient* bc,
    word16 packet_id, byte expected_state, BrokerOutPub** out_prev)
{
    BrokerOutPub* prev = NULL;
    BrokerOutPub* cur;

    if (bc == NULL || packet_id == 0) {
        return NULL;
    }
    cur = bc->out_q_head;
    while (cur != NULL) {
        if (cur->packet_id == packet_id && cur->state == expected_state) {
            if (out_prev != NULL) {
                *out_prev = prev;
            }
            return cur;
        }
        prev = cur;
        cur = cur->next;
    }
    return NULL;
}

/* Unlink and free the entry; decrement inflight if it was counted. */
static void BrokerClient_UnlinkOutPub(BrokerClient* bc, BrokerOutPub* prev,
    BrokerOutPub* e)
{
    if (bc == NULL || e == NULL) {
        return;
    }
    if (prev == NULL) {
        bc->out_q_head = e->next;
    }
    else {
        prev->next = e->next;
    }
    if (bc->out_q_tail == e) {
        bc->out_q_tail = prev;
    }
    bc->out_q_count--;
    if (e->state == BROKER_OUTQ_PUBLISH_SENT ||
        e->state == BROKER_OUTQ_PUBREL_SENT) {
        if (bc->out_q_inflight > 0) {
            bc->out_q_inflight--;
        }
    }
    BrokerOutPub_Free(e);
}

/* PUBACK from subscriber - completes a QoS 1 delivery. */
static void BrokerClient_OnPubAck(BrokerClient* bc, word16 packet_id)
{
    BrokerOutPub* prev = NULL;
    BrokerOutPub* e;

    if (bc == NULL) {
        return;
    }
    e = BrokerClient_FindOutPub(bc, packet_id, BROKER_OUTQ_PUBLISH_SENT,
            &prev);
    if (e == NULL) {
        WBLOG_DBG(bc->broker,
            "broker: spurious PUBACK sock=%d packet_id=%u",
            (int)bc->sock, (unsigned)packet_id);
        return;
    }
    BrokerClient_UnlinkOutPub(bc, prev, e);
#ifdef WOLFMQTT_BROKER_PERSIST
    /* Defense in depth: in normal flow the orphan-reclaim path already
     * wiped this client's disk records, but if the entry was ever
     * shadow-written (e.g., a previous orphan cycle) make sure the
     * on-disk record is gone so a crash before the next reclaim cannot
     * cause duplicate redelivery. Idempotent on a missing key. */
    if (BROKER_STR_VALID(bc->client_id)) {
        (void)BrokerPersist_DelOutPub(bc->broker, bc->client_id, packet_id);
    }
#endif
    BrokerClient_DrainOutQueue(bc);
}

#if WOLFMQTT_MAX_QOS >= 2
/* PUBREC from subscriber - advance the QoS 2 entry to PUBREL_SENT.
 * Returns 1 if a matching entry was found (so the caller knows whether
 * the PUBREL we send is correlated to a real outbound message), 0
 * otherwise. The wire response is still sent in both cases to remain
 * idempotent for buggy peers. */
static int BrokerClient_OnPubRec(BrokerClient* bc, word16 packet_id)
{
    BrokerOutPub* prev = NULL;
    BrokerOutPub* e;

    if (bc == NULL) {
        return 0;
    }
    e = BrokerClient_FindOutPub(bc, packet_id, BROKER_OUTQ_PUBLISH_SENT,
            &prev);
    if (e == NULL) {
        WBLOG_DBG(bc->broker,
            "broker: spurious PUBREC sock=%d packet_id=%u",
            (int)bc->sock, (unsigned)packet_id);
        return 0;
    }
    e->state = BROKER_OUTQ_PUBREL_SENT;
    /* Inflight stays counted - the delivery is still outstanding until
     * PUBCOMP returns. */
    return 1;
}

/* PUBCOMP from subscriber - completes a QoS 2 delivery. */
static void BrokerClient_OnPubComp(BrokerClient* bc, word16 packet_id)
{
    BrokerOutPub* prev = NULL;
    BrokerOutPub* e;

    if (bc == NULL) {
        return;
    }
    e = BrokerClient_FindOutPub(bc, packet_id, BROKER_OUTQ_PUBREL_SENT,
            &prev);
    if (e == NULL) {
        WBLOG_DBG(bc->broker,
            "broker: spurious PUBCOMP sock=%d packet_id=%u",
            (int)bc->sock, (unsigned)packet_id);
        return;
    }
    BrokerClient_UnlinkOutPub(bc, prev, e);
#ifdef WOLFMQTT_BROKER_PERSIST
    /* See BrokerClient_OnPubAck: defense-in-depth disk record purge. */
    if (BROKER_STR_VALID(bc->client_id)) {
        (void)BrokerPersist_DelOutPub(bc->broker, bc->client_id, packet_id);
    }
#endif
    BrokerClient_DrainOutQueue(bc);
}
#endif /* WOLFMQTT_MAX_QOS >= 2 */
#endif /* !WOLFMQTT_STATIC_MEMORY */

static void BrokerClient_Free(BrokerClient* bc)
{
    if (bc == NULL) {
        return;
    }
#if WOLFMQTT_MAX_QOS >= 2
    BrokerInboundQos2_Clear(bc);
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    BrokerClient_FreeOutQueue(bc);
#endif

#ifdef ENABLE_MQTT_WEBSOCKET
    if (bc->ws_ctx != NULL) {
        (void)BrokerWsNetDisconnect(bc);
    }
    else
#endif

#ifdef ENABLE_MQTT_TLS
    if (bc->client.tls.ssl) {
        /* Send close_notify before closing the socket, because
         * wolfSSL_shutdown uses I/O callbacks that need a valid fd */
        if (bc->tls_handshake_done) {
            wolfSSL_shutdown(bc->client.tls.ssl);
        }
        wolfSSL_free(bc->client.tls.ssl);
        bc->client.tls.ssl = NULL;
    }
#endif
    (void)BrokerNetDisconnect(bc);
    MqttClient_DeInit(&bc->client);
#ifdef WOLFMQTT_STATIC_MEMORY
    XMEMSET(bc, 0, sizeof(*bc));
    /* in_use is now 0 after memset */
#else
    if (bc->client_id) {
        WOLFMQTT_FREE(bc->client_id);
    }
#ifdef WOLFMQTT_BROKER_AUTH
    if (bc->username) {
        BROKER_FORCE_ZERO(bc->username, XSTRLEN(bc->username) + 1);
        WOLFMQTT_FREE(bc->username);
    }
    if (bc->password) {
        /* Wipe the full stored binary length plus the trailing NUL byte
         * appended by BrokerStore_String. password_len reflects the actual
         * decoded length, since [MQTT-3.1.3.5] Password may contain 0x00. */
        BROKER_FORCE_ZERO(bc->password, (size_t)bc->password_len + 1);
        WOLFMQTT_FREE(bc->password);
    }
#endif
#ifdef WOLFMQTT_BROKER_WILL
    if (bc->will_topic) {
        BROKER_FORCE_ZERO(bc->will_topic, XSTRLEN(bc->will_topic) + 1);
        WOLFMQTT_FREE(bc->will_topic);
    }
    if (bc->will_payload) {
        BROKER_FORCE_ZERO(bc->will_payload, bc->will_payload_len);
        WOLFMQTT_FREE(bc->will_payload);
    }
#endif
    if (bc->tx_buf) {
        BROKER_FORCE_ZERO(bc->tx_buf, bc->tx_buf_len);
        WOLFMQTT_FREE(bc->tx_buf);
    }
    if (bc->rx_buf) {
        BROKER_FORCE_ZERO(bc->rx_buf, bc->rx_buf_len);
        WOLFMQTT_FREE(bc->rx_buf);
    }
    WOLFMQTT_FREE(bc);
#endif
}

static BrokerClient* BrokerClient_Add(MqttBroker* broker,
    BROKER_SOCKET_T sock, int is_tls)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#endif
    BrokerClient* bc = NULL;
    int rc = MQTT_CODE_SUCCESS;

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
        if (!broker->clients[i].in_use) {
            bc = &broker->clients[i];
            break;
        }
    }
    if (bc == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(bc, 0, sizeof(*bc));
        bc->in_use = 1;
    }
#else
    bc = (BrokerClient*)WOLFMQTT_MALLOC(sizeof(BrokerClient));
    if (bc == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(bc, 0, sizeof(*bc));
        bc->tx_buf_len = BROKER_TX_BUF_SZ;
        bc->rx_buf_len = BROKER_RX_BUF_SZ;
        bc->tx_buf = (byte*)WOLFMQTT_MALLOC(bc->tx_buf_len);
        bc->rx_buf = (byte*)WOLFMQTT_MALLOC(bc->rx_buf_len);
        if (bc->tx_buf == NULL || bc->rx_buf == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        bc->sock = sock;
        bc->broker = broker;
        bc->protocol_level = 0;
        bc->keep_alive_sec = 0;
        bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();

        bc->net.context = bc;
        bc->net.connect = BrokerNetConnect;
        bc->net.read = BrokerNetRead;
        bc->net.write = BrokerNetWrite;
        bc->net.disconnect = BrokerNetDisconnect;

        rc = MqttClient_Init(&bc->client, &bc->net, NULL,
                bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
                bc->rx_buf, BROKER_CLIENT_RX_SZ(bc), BROKER_TIMEOUT_MS);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: client init failed rc=%d", rc);
        }
    }

#ifdef ENABLE_MQTT_TLS
    if (rc == MQTT_CODE_SUCCESS) {
        if (is_tls && broker->tls_ctx) {
            bc->client.tls.ssl = wolfSSL_new(broker->tls_ctx);
            if (bc->client.tls.ssl == NULL) {
                WBLOG_ERR(broker, "broker: wolfSSL_new failed sock=%d", (int)sock);
                rc = MQTT_CODE_ERROR_MEMORY;
            }
            else {
                wolfSSL_SetIOReadCtx(bc->client.tls.ssl, &bc->client);
                wolfSSL_SetIOWriteCtx(bc->client.tls.ssl, &bc->client);
                MqttClient_Flags(&bc->client, 0, MQTT_CLIENT_FLAG_IS_TLS);
                bc->tls_handshake_done = 0;
            }
        }
        else if (is_tls) {
            WBLOG_ERR(broker, "broker: TLS ctx not set, rejecting sock=%d",
                (int)sock);
            rc = MQTT_CODE_ERROR_BAD_ARG;
        }
        else {
            bc->tls_handshake_done = 1;
        }
    }
#else
    (void)is_tls;
#endif

    if (rc == MQTT_CODE_SUCCESS) {
#ifndef WOLFMQTT_STATIC_MEMORY
        /* Prepend to linked list */
        bc->next = broker->clients;
        broker->clients = bc;
#endif
    }
    else if (bc != NULL) {
        BrokerClient_Free(bc);
        bc = NULL;
    }

    return bc;
}

static void BrokerClient_Remove(MqttBroker* broker, BrokerClient* bc)
{
#ifndef WOLFMQTT_STATIC_MEMORY
    BrokerClient* cur;
    BrokerClient* prev = NULL;
    int found = 0;
#endif

    if (broker == NULL || bc == NULL) {
        return;
    }

#ifndef WOLFMQTT_STATIC_MEMORY
    cur = broker->clients;
    while (cur) {
        if (cur == bc) {
            if (prev) {
                prev->next = cur->next;
            }
            else {
                broker->clients = cur->next;
            }
            found = 1;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    /* Only free when bc was actually unlinked. A re-entrant close callback
     * (e.g. WebSocket LWS_CALLBACK_CLOSED during a takeover fan-out) can have
     * already removed and freed bc; freeing again here would double-free. */
    if (found) {
        BrokerClient_Free(bc);
    }
#else
    BrokerClient_Free(bc);
#endif
}

/* -------------------------------------------------------------------------- */
/* Subscription management                                                     */
/* -------------------------------------------------------------------------- */

/* Orphan subscriptions for session persistence (clean_session=0).
 * Sets client pointer to NULL but keeps the subscription for reconnect. */
#ifndef WOLFMQTT_STATIC_MEMORY
/* -------------------------------------------------------------------------- */
/* Orphan session pool (dynamic memory only).                                  */
/* -------------------------------------------------------------------------- */

/* Find the orphan slot whose client_id matches. NULL if none. */
static BrokerOrphanSession* BrokerOrphan_Find(MqttBroker* broker,
    const char* client_id)
{
    BrokerOrphanSession* cur;
    if (broker == NULL || client_id == NULL) {
        return NULL;
    }
    for (cur = broker->orphan_sessions; cur != NULL; cur = cur->next) {
        if (cur->client_id != NULL &&
                XSTRCMP(cur->client_id, client_id) == 0) {
            return cur;
        }
    }
    return NULL;
}

/* Free everything an orphan owns (queue entries + client_id) but do
 * NOT unlink from broker->orphan_sessions; the caller does that. */
static void BrokerOrphan_FreeContents(BrokerOrphanSession* o)
{
    BrokerOutPub* cur;
    if (o == NULL) {
        return;
    }
    cur = o->out_q_head;
    while (cur != NULL) {
        BrokerOutPub* next = cur->next;
        if (cur->topic != NULL) {
            WOLFMQTT_FREE(cur->topic);
        }
        if (cur->payload != NULL) {
            WOLFMQTT_FREE(cur->payload);
        }
        WOLFMQTT_FREE(cur);
        cur = next;
    }
    o->out_q_head = NULL;
    o->out_q_tail = NULL;
    o->out_q_count = 0;
    o->out_q_inflight = 0;
    if (o->client_id != NULL) {
        WOLFMQTT_FREE(o->client_id);
        o->client_id = NULL;
    }
}

/* Unlink + free a single orphan from broker->orphan_sessions. */
static void BrokerOrphan_Remove(MqttBroker* broker, BrokerOrphanSession* o)
{
    BrokerOrphanSession** pp;
    if (broker == NULL || o == NULL) {
        return;
    }
    pp = &broker->orphan_sessions;
    while (*pp != NULL && *pp != o) {
        pp = &(*pp)->next;
    }
    if (*pp == o) {
        *pp = o->next;
        if (broker->orphan_session_count > 0) {
            broker->orphan_session_count--;
        }
    }
    BrokerOrphan_FreeContents(o);
    WOLFMQTT_FREE(o);
}

/* Drop the oldest orphan (smallest orphan_since) and its subs+persist.
 * Returns 1 if one was dropped, 0 if pool was empty.
 *
 * Complexity is O(N) over the orphan pool because the list is singly
 * linked and we scan for the minimum orphan_since timestamp. With the
 * default BROKER_MAX_PERSIST_SESSIONS = 64 this is in the noise.
 * Operators raising the cap into the thousands should swap this for a
 * doubly-linked LRU (next/prev pointers and an oldest-tail pointer on
 * MqttBroker) so eviction stays O(1). */
static int BrokerOrphan_EvictOldest(MqttBroker* broker)
{
    BrokerOrphanSession* cur;
    BrokerOrphanSession* oldest = NULL;
    if (broker == NULL) {
        return 0;
    }
    for (cur = broker->orphan_sessions; cur != NULL; cur = cur->next) {
        if (oldest == NULL || cur->orphan_since < oldest->orphan_since) {
            oldest = cur;
        }
    }
    if (oldest == NULL) {
        return 0;
    }
    WBLOG_INFO(broker,
        "broker: evicting oldest orphan client_id=%s (cap reached)",
        BrokerLog_Sanitize(BROKER_STR_VALID(oldest->client_id)
            ? oldest->client_id : "(null)"));
    BrokerOrphan_DropFull(broker, oldest);
    return 1;
}

/* Shared orphan teardown (callable from broker_persist.c too, hence
 * WOLFMQTT_LOCAL linkage). Deletes persisted records, drops the
 * orphan's still-NULL-bound subs from broker->subs, and unlinks +
 * frees the orphan slot itself. Caller already validated that o is
 * actually linked into broker->orphan_sessions. */
WOLFMQTT_LOCAL void BrokerOrphan_DropFull(MqttBroker* broker,
    BrokerOrphanSession* o)
{
    if (broker == NULL || o == NULL) {
        return;
    }
#ifdef WOLFMQTT_BROKER_PERSIST
    if (o->client_id != NULL) {
        (void)BrokerPersist_DelSubs(broker, o->client_id);
        (void)BrokerPersist_DelSession(broker, o->client_id);
        (void)BrokerPersist_DelOutQueue(broker, o->client_id);
    }
#endif
    /* Drop the orphan's subs entirely (their session is gone). */
    {
        BrokerSub* sp = broker->subs;
        BrokerSub* prev = NULL;
        while (sp != NULL) {
            BrokerSub* next = sp->next;
            if (sp->client == NULL && sp->client_id != NULL &&
                o->client_id != NULL &&
                XSTRCMP(sp->client_id, o->client_id) == 0) {
                if (prev != NULL) {
                    prev->next = next;
                }
                else {
                    broker->subs = next;
                }
                if (sp->filter) {
                    WOLFMQTT_FREE(sp->filter);
                }
                if (sp->client_id) {
                    WOLFMQTT_FREE(sp->client_id);
                }
                WOLFMQTT_FREE(sp);
            }
            else {
                prev = sp;
            }
            sp = next;
        }
    }
    BrokerOrphan_Remove(broker, o);
}

/* Allocate or recycle an orphan slot, then transfer the persistent
 * state of bc into it. Subs already point at NULL (caller handled);
 * the out_q on bc is unlinked from bc before this returns so
 * BrokerClient_Free does not free it. */
static BrokerOrphanSession* BrokerOrphan_Take(MqttBroker* broker,
    BrokerClient* bc)
{
    BrokerOrphanSession* o;
    BrokerOrphanSession* existing;
    size_t cid_len;

    if (broker == NULL || bc == NULL || !BROKER_STR_VALID(bc->client_id)) {
        return NULL;
    }

    /* If an orphan already exists for this client_id (e.g., the same
     * client took over its own session via duplicate CONNECT), drop it
     * before staging the new orphan. */
    existing = BrokerOrphan_Find(broker, bc->client_id);
    if (existing != NULL) {
        BrokerOrphan_Remove(broker, existing);
    #ifdef WOLFMQTT_BROKER_PERSIST
        /* Purge the previous orphan's persisted outbound queue so its
         * (different packet_id) records cannot be restored and replayed
         * after a restart once the new orphan shadow-writes its own. */
        (void)BrokerPersist_DelOutQueue(broker, bc->client_id);
    #endif
    }

    /* Cap check; evict oldest if at limit. */
    while (broker->orphan_session_count >= BROKER_MAX_PERSIST_SESSIONS) {
        if (!BrokerOrphan_EvictOldest(broker)) {
            break;
        }
    }

    o = (BrokerOrphanSession*)WOLFMQTT_MALLOC(sizeof(*o));
    if (o == NULL) {
        return NULL;
    }
    XMEMSET(o, 0, sizeof(*o));
    cid_len = XSTRLEN(bc->client_id);
    o->client_id = (char*)WOLFMQTT_MALLOC(cid_len + 1);
    if (o->client_id == NULL) {
        WOLFMQTT_FREE(o);
        return NULL;
    }
    XMEMCPY(o->client_id, bc->client_id, cid_len);
    o->client_id[cid_len] = '\0';

    o->protocol_level = bc->protocol_level;
    o->session_expiry_sec = bc->session_expiry_sec;
    o->orphan_since = WOLFMQTT_BROKER_GET_TIME_S();

    /* Move out_q ownership. bc->out_q_* must be cleared so
     * BrokerClient_FreeOutQueue (called from BrokerClient_Free)
     * doesn't double-free. */
    o->out_q_head     = bc->out_q_head;
    o->out_q_tail     = bc->out_q_tail;
    o->out_q_count    = bc->out_q_count;
    o->out_q_inflight = bc->out_q_inflight;
    bc->out_q_head    = NULL;
    bc->out_q_tail    = NULL;
    bc->out_q_count   = 0;
    bc->out_q_inflight = 0;

    /* Link at head; orphan_session_count tracks size. */
    o->next = broker->orphan_sessions;
    broker->orphan_sessions = o;
    broker->orphan_session_count++;
    WBLOG_INFO(broker,
        "broker: orphan session created client_id=%s queued=%d",
        BrokerLog_Sanitize(o->client_id), o->out_q_count);

#ifdef WOLFMQTT_BROKER_PERSIST
    /* Re-persist the session record stamped with the orphan time so the v5
     * Session Expiry timer is measured from disconnect, not from the next
     * broker restart. */
    (void)BrokerPersist_PutOrphanSession(broker, o->client_id,
        o->protocol_level, o->session_expiry_sec, o->orphan_since);
    /* Shadow-write every transferred QoS 1/2 entry so the queue
     * survives a broker restart. QoS 0 entries (if any leaked into
     * the queue) are skipped by PutOutPub. */
    {
        BrokerOutPub* cur;
        for (cur = o->out_q_head; cur != NULL; cur = cur->next) {
            if (cur->qos > MQTT_QOS_0) {
                (void)BrokerPersist_PutOutPub(broker, o->client_id, cur);
            }
        }
    }
#endif
    return o;
}

/* On reconnect with same client_id: transfer the orphan's queue back
 * to the new live BrokerClient and remove the orphan. Returns 1 if an
 * orphan was consumed, 0 otherwise. */
static int BrokerOrphan_Reclaim(MqttBroker* broker, BrokerClient* new_bc)
{
    BrokerOrphanSession* o;
    if (broker == NULL || new_bc == NULL ||
            !BROKER_STR_VALID(new_bc->client_id)) {
        return 0;
    }
    o = BrokerOrphan_Find(broker, new_bc->client_id);
    if (o == NULL) {
        return 0;
    }
    /* Move queue ownership back. The new bc's own out_q is expected
     * to be empty at this point (fresh BrokerClient post-CONNECT). */
    new_bc->out_q_head     = o->out_q_head;
    new_bc->out_q_tail     = o->out_q_tail;
    new_bc->out_q_count    = o->out_q_count;
    new_bc->out_q_inflight = 0;
    o->out_q_head = NULL;
    o->out_q_tail = NULL;
    o->out_q_count = 0;
    o->out_q_inflight = 0;
    if (new_bc->session_expiry_sec == 0xFFFFFFFFu) {
        new_bc->session_expiry_sec = o->session_expiry_sec;
    }
    /* MQTT-4.4.0-1: any message that was previously in-flight on the old
     * session is re-sent on resume. PUBLISH_SENT -> QUEUED with
     * retransmit_dup so the drain re-sends the PUBLISH with DUP=1.
     * PUBREL_SENT stays PUBREL_SENT but is also flagged retransmit_dup so
     * the drain re-sends a fresh PUBREL (same packet_id; PUBREL carries no
     * DUP flag) - the subscriber will not re-send PUBREC, so the broker
     * must drive the PUBREL/PUBCOMP completion itself. */
    {
        BrokerOutPub* e = new_bc->out_q_head;
        int retx = 0;
        while (e != NULL) {
            if (e->state == BROKER_OUTQ_PUBLISH_SENT) {
                e->state = BROKER_OUTQ_QUEUED;
                e->retransmit_dup = 1;
                retx++;
            }
            else if (e->state == BROKER_OUTQ_PUBREL_SENT) {
                /* Still in flight by definition - the prior session was
                 * awaiting PUBCOMP. Restore the inflight count (zeroed
                 * above) so the Receive Maximum / BROKER_MAX_INFLIGHT_PER_SUB
                 * cap stays accurate, and flag it so the drain re-sends the
                 * PUBREL on resume. */
                e->retransmit_dup = 1;
                new_bc->out_q_inflight++;
            }
            e = e->next;
        }
        if (retx > 0) {
            WBLOG_INFO(broker,
                "broker: orphan reclaim queued retransmit=%d client_id=%s",
                retx, BrokerLog_Sanitize(new_bc->client_id));
        }
    }
    WBLOG_INFO(broker,
        "broker: orphan reclaimed client_id=%s queued=%d",
        BrokerLog_Sanitize(new_bc->client_id), new_bc->out_q_count);
#ifdef WOLFMQTT_BROKER_PERSIST
    /* The reclaimed queue is now in a LIVE BrokerClient. Persisted
     * records for this client_id are no longer authoritative - the
     * subscriber will receive these via the upcoming drain and ack
     * them. Wipe the on-disk copies so a subsequent crash doesn't
     * re-deliver them. */
    (void)BrokerPersist_DelOutQueue(broker, new_bc->client_id);
#endif
    BrokerOrphan_Remove(broker, o);
    return 1;
}

/* Enqueue a fan-out target onto an orphan session's queue. Called from
 * BrokerHandle_Publish when sub->client is NULL but an orphan with the
 * matching client_id exists. QoS 0 is dropped per spec; only persistent
 * messages live in the offline queue. */
static void BrokerOrphan_Enqueue(MqttBroker* broker, BrokerOrphanSession* o,
    const char* topic, const byte* payload, word32 payload_len,
    MqttQoS qos, byte retain)
{
    BrokerOutPub* e;
    if (broker == NULL || o == NULL || topic == NULL ||
            qos == MQTT_QOS_0) {
        return;
    }
    /* Drop-oldest eviction when the per-session offline queue is full. */
    while (o->out_q_count >= BROKER_MAX_OFFLINE_MSGS_PER_SUB) {
        BrokerOutPub* head = o->out_q_head;
        if (head == NULL) {
            break;
        }
        o->out_q_head = head->next;
        if (o->out_q_tail == head) {
            o->out_q_tail = NULL;
        }
        if (o->out_q_count > 0) {
            o->out_q_count--;
        }
        /* Keep inflight accounting consistent if the evicted head was an
         * in-flight QoS 1/2 message, else the cap drifts after reclaim. */
        if ((head->state == BROKER_OUTQ_PUBLISH_SENT ||
                head->state == BROKER_OUTQ_PUBREL_SENT) &&
                o->out_q_inflight > 0) {
            o->out_q_inflight--;
        }
    #ifdef WOLFMQTT_BROKER_PERSIST
        if (o->client_id != NULL && head->packet_id != 0) {
            (void)BrokerPersist_DelOutPub(broker, o->client_id,
                head->packet_id);
        }
    #endif
        if (head->topic) WOLFMQTT_FREE(head->topic);
        if (head->payload) WOLFMQTT_FREE(head->payload);
        WOLFMQTT_FREE(head);
    }

    e = BrokerOutPub_Alloc(topic, payload, payload_len);
    if (e == NULL) {
        WBLOG_ERR(broker,
            "broker: orphan enqueue alloc failed client_id=%s",
            BrokerLog_Sanitize(
                BROKER_STR_VALID(o->client_id) ? o->client_id : "(null)"));
        return;
    }
    e->qos = qos;
    e->packet_id = BrokerNextPacketId(broker);
    e->retain = retain;
    e->state = BROKER_OUTQ_QUEUED;
    e->enq_time = WOLFMQTT_BROKER_GET_TIME_S();
    e->protocol_level = o->protocol_level;
    e->next = NULL;
    if (o->out_q_tail != NULL) {
        o->out_q_tail->next = e;
    }
    else {
        o->out_q_head = e;
    }
    o->out_q_tail = e;
    o->out_q_count++;
#ifdef WOLFMQTT_BROKER_PERSIST
    (void)BrokerPersist_PutOutPub(broker, o->client_id, e);
#endif
    WBLOG_DBG(broker,
        "broker: orphan enqueue client_id=%s topic=%s qos=%d count=%d",
        BrokerLog_Sanitize(
            BROKER_STR_VALID(o->client_id) ? o->client_id : "(null)"),
        BrokerLog_Sanitize(topic), (int)qos, o->out_q_count);
}

/* Free every orphan (used by MqttBroker_Free and by wipe paths). */
static void BrokerOrphan_FreeAll(MqttBroker* broker)
{
    BrokerOrphanSession* cur;
    if (broker == NULL) {
        return;
    }
    cur = broker->orphan_sessions;
    while (cur != NULL) {
        BrokerOrphanSession* next = cur->next;
        BrokerOrphan_FreeContents(cur);
        WOLFMQTT_FREE(cur);
        cur = next;
    }
    broker->orphan_sessions = NULL;
    broker->orphan_session_count = 0;
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

/* Forward declaration; orphan-take-failure rollback in
 * BrokerSubs_OrphanClient falls back to the clean removal path.
 * Already declared above when ENABLE_MQTT_WEBSOCKET is set. */
#ifndef ENABLE_MQTT_WEBSOCKET
static void BrokerSubs_RemoveClient(MqttBroker* broker, BrokerClient* bc);
#endif

static void BrokerSubs_OrphanClient(MqttBroker* broker, BrokerClient* bc)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerSub *cur;
#endif
    int count = 0;

    /* First pass: count matching subs without yet detaching them. We
     * must not flip cur->client to NULL until we know the orphan
     * carrier was successfully created - otherwise an allocation
     * failure inside BrokerOrphan_Take would leave dangling subs in
     * broker->subs with no carrier and no way to be reclaimed. */
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        if (broker->subs[i].in_use && broker->subs[i].client == bc) {
            count++;
        }
    }
#else
    cur = broker->subs;
    while (cur) {
        if (cur->client == bc) {
            count++;
        }
        cur = cur->next;
    }
#endif
    if (count == 0) {
        return;
    }

#ifndef WOLFMQTT_STATIC_MEMORY
    /* Stage a persistent-session record in broker->orphan_sessions.
     * Carries the out_q ownership across the upcoming
     * BrokerClient_Free so messages published while disconnected
     * can still be queued for the eventual reconnect. If Take fails
     * (OOM), fall through to clean removal so subs are not left
     * dangling without a carrier. */
    if (BrokerOrphan_Take(broker, bc) == NULL) {
        WBLOG_ERR(broker,
            "broker: orphan take failed client_id=%s - removing %d subs",
            BrokerLog_Sanitize(
                BROKER_STR_VALID(bc->client_id) ? bc->client_id : "(null)"),
            count);
        BrokerSubs_RemoveClient(broker, bc);
        return;
    }
#endif

    /* Second pass: detach. Safe to mutate now - the carrier exists
     * (dynamic mode) or the broker decided not to persist (static
     * mode); either way, count > 0 reached this point. */
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        if (broker->subs[i].in_use && broker->subs[i].client == bc) {
            broker->subs[i].client = NULL;
        }
    }
#else
    cur = broker->subs;
    while (cur) {
        if (cur->client == bc) {
            cur->client = NULL;
        }
        cur = cur->next;
    }
#endif
    WBLOG_INFO(broker,
        "broker: orphaned %d subs for client_id=%s (session persist)",
        count, BrokerLog_Sanitize(
            BROKER_STR_VALID(bc->client_id) ? bc->client_id : "(null)"));
}

static void BrokerSubs_RemoveClient(MqttBroker* broker, BrokerClient* bc)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerSub* cur = broker->subs;
    BrokerSub* prev = NULL;
#endif

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        if (broker->subs[i].in_use && broker->subs[i].client == bc) {
            XMEMSET(&broker->subs[i], 0, sizeof(BrokerSub));
        }
    }
#else
    while (cur) {
        BrokerSub* next = cur->next;
        if (cur->client == bc) {
            if (prev) {
                prev->next = next;
            }
            else {
                broker->subs = next;
            }
            if (cur->filter) {
                WOLFMQTT_FREE(cur->filter);
            }
            if (cur->client_id) {
                WOLFMQTT_FREE(cur->client_id);
            }
            WOLFMQTT_FREE(cur);
        }
        else {
            prev = cur;
        }
        cur = next;
    }
#endif
    bc->sub_count = 0;

#ifdef WOLFMQTT_BROKER_PERSIST
    /* Clean-session disconnect drops the persistent record. For
     * non-clean disconnects the broker uses BrokerSubs_OrphanClient
     * instead (subs stay in memory, persist record stays intact).
     * Guard on bc->clean_session so paths that reach this function
     * for a clean_session=0 client (takeover, socket-error teardown,
     * shutdown sweep) do not silently wipe a persistent record that
     * the orphan path is meant to preserve. */
    if (bc != NULL && bc->clean_session &&
            BROKER_STR_VALID(bc->client_id)) {
        (void)BrokerPersist_DelSubs(broker, bc->client_id);
        (void)BrokerPersist_DelSession(broker, bc->client_id);
    }
#endif
}

static int BrokerSubs_Add(MqttBroker* broker, BrokerClient* bc,
    const char* filter, word16 filter_len, MqttQoS qos)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerSub* cur = broker->subs;
#endif
    BrokerSub* sub = NULL;
    int rc = MQTT_CODE_SUCCESS;

    /* Check for existing subscription to same filter by same client */
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        if (broker->subs[i].in_use && broker->subs[i].client == bc &&
            (word16)XSTRLEN(broker->subs[i].filter) == filter_len &&
            XMEMCMP(broker->subs[i].filter, filter, filter_len) == 0) {
            broker->subs[i].qos = qos;
            WBLOG_INFO(broker, "broker: sub update sock=%d filter=%s qos=%d",
                (int)bc->sock, BrokerLog_Sanitize(broker->subs[i].filter), qos);
            return MQTT_CODE_SUCCESS;
        }
    }
#else
    while (cur) {
        if (cur->client == bc && cur->filter != NULL &&
            (word16)XSTRLEN(cur->filter) == filter_len &&
            XMEMCMP(cur->filter, filter, filter_len) == 0) {
            cur->qos = qos;
            WBLOG_INFO(broker, "broker: sub update sock=%d filter=%s qos=%d",
                (int)bc->sock, BrokerLog_Sanitize(cur->filter), qos);
            return MQTT_CODE_SUCCESS;
        }
        cur = cur->next;
    }
#endif

    /* Per-client cap: prevent a single client from occupying the whole shared
     * subscription table and denying SUBSCRIBE to other clients. */
    if (bc->sub_count >= BROKER_MAX_SUBS_PER_CLIENT) {
        WBLOG_ERR(broker, "broker: sub cap reached sock=%d (max %d)",
            (int)bc->sock, BROKER_MAX_SUBS_PER_CLIENT);
        return MQTT_CODE_ERROR_MEMORY;
    }

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        if (!broker->subs[i].in_use) {
            sub = &broker->subs[i];
            break;
        }
    }
    if (sub == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        if (filter_len >= BROKER_MAX_FILTER_LEN) {
            rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(sub, 0, sizeof(*sub));
        sub->in_use = 1;
        XMEMCPY(sub->filter, filter, filter_len);
        sub->filter[filter_len] = '\0';
    }
#else
    sub = (BrokerSub*)WOLFMQTT_MALLOC(sizeof(BrokerSub));
    if (sub == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMSET(sub, 0, sizeof(*sub));
        sub->filter = (char*)WOLFMQTT_MALLOC(filter_len + 1);
        if (sub->filter == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
    }
    if (rc == MQTT_CODE_SUCCESS) {
        XMEMCPY(sub->filter, filter, filter_len);
        sub->filter[filter_len] = '\0';
        sub->next = broker->subs;
        broker->subs = sub;
    }
    else if (sub != NULL) {
        WOLFMQTT_FREE(sub);
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        sub->client = bc;
        sub->qos = qos;
        /* Store client_id for session persistence */
#ifdef WOLFMQTT_STATIC_MEMORY
        if (BROKER_STR_VALID(bc->client_id)) {
            int id_len = (int)XSTRLEN(bc->client_id);
            if (id_len >= BROKER_MAX_CLIENT_ID_LEN) {
                id_len = BROKER_MAX_CLIENT_ID_LEN - 1;
            }
            XMEMCPY(sub->client_id, bc->client_id, (size_t)id_len);
            sub->client_id[id_len] = '\0';
        }
#else
        if (BROKER_STR_VALID(bc->client_id)) {
            int id_len = (int)XSTRLEN(bc->client_id);
            sub->client_id = (char*)WOLFMQTT_MALLOC((size_t)id_len + 1);
            if (sub->client_id != NULL) {
                XMEMCPY(sub->client_id, bc->client_id, (size_t)id_len + 1);
            }
        }
#endif
        bc->sub_count++;
        WBLOG_INFO(broker, "broker: sub add sock=%d filter=%s qos=%d",
            (int)bc->sock, BrokerLog_Sanitize(sub->filter), qos);
    }
    return rc;
}

static void BrokerSubs_Remove(MqttBroker* broker, BrokerClient* bc,
    const char* filter, word16 filter_len)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerSub *cur;
    BrokerSub *prev = NULL;
#endif

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        BrokerSub* s = &broker->subs[i];
        if (s->in_use && s->client == bc &&
            s->filter[0] != '\0' &&
            (word16)XSTRLEN(s->filter) == filter_len &&
            XMEMCMP(s->filter, filter, filter_len) == 0) {
            WBLOG_INFO(broker, "broker: sub remove sock=%d filter=%s",
                (int)bc->sock, BrokerLog_Sanitize(s->filter));
            XMEMSET(s, 0, sizeof(BrokerSub));
            if (bc->sub_count > 0) {
                bc->sub_count--;
            }
            return;
        }
    }
#else
    cur = broker->subs;
    while (cur) {
        BrokerSub* next = cur->next;
        if (cur->client == bc &&
            cur->filter != NULL &&
            (word16)XSTRLEN(cur->filter) == filter_len &&
            XMEMCMP(cur->filter, filter, filter_len) == 0) {
            if (prev) {
                prev->next = next;
            }
            else {
                broker->subs = next;
            }
            WBLOG_INFO(broker, "broker: sub remove sock=%d filter=%s",
                (int)bc->sock, BrokerLog_Sanitize(cur->filter));
            WOLFMQTT_FREE(cur->filter);
            if (cur->client_id) {
                WOLFMQTT_FREE(cur->client_id);
            }
            WOLFMQTT_FREE(cur);
            if (bc->sub_count > 0) {
                bc->sub_count--;
            }
            return;
        }
        prev = cur;
        cur = next;
    }
#endif
}

/* -------------------------------------------------------------------------- */
/* Packet ID generation                                                        */
/* -------------------------------------------------------------------------- */
static word16 BrokerNextPacketId(MqttBroker* broker)
{
    word16 id = broker->next_packet_id;
    broker->next_packet_id++;
    if (broker->next_packet_id == 0) {
        broker->next_packet_id = 1; /* wrap: skip 0 */
    }
    return id;
}

/* -------------------------------------------------------------------------- */
/* Client lookup by ID                                                         */
/* -------------------------------------------------------------------------- */
static BrokerClient* BrokerClient_FindByClientId(MqttBroker* broker,
    const char* client_id, BrokerClient* exclude)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerClient* bc;
#endif

    if (broker == NULL || client_id == NULL || client_id[0] == '\0') {
        return NULL;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
        BrokerClient* bc = &broker->clients[i];
        if (!bc->in_use) continue;
        if (bc != exclude && BROKER_STR_VALID(bc->client_id) &&
            XSTRCMP(bc->client_id, client_id) == 0) {
            return bc;
        }
    }
#else
    bc = broker->clients;
    while (bc) {
        if (bc != exclude && BROKER_STR_VALID(bc->client_id) &&
            XSTRCMP(bc->client_id, client_id) == 0) {
            return bc;
        }
        bc = bc->next;
    }
#endif
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Subscription helpers for clean session                                      */
/* -------------------------------------------------------------------------- */
static void BrokerSubs_RemoveByClientId(MqttBroker* broker,
    const char* client_id)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerSub* cur;
    BrokerSub* prev = NULL;
#endif

    if (broker == NULL || client_id == NULL || client_id[0] == '\0') {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        BrokerSub* s = &broker->subs[i];
        if (!s->in_use) continue;
        /* Check active client subs */
        if (s->client != NULL &&
            s->client->client_id[0] != '\0' &&
            XSTRCMP(s->client->client_id, client_id) == 0) {
            XMEMSET(s, 0, sizeof(BrokerSub));
        }
        /* Check orphaned subs (stored client_id) */
        else if (s->client == NULL &&
            BROKER_STR_VALID(s->client_id) &&
            XSTRCMP(s->client_id, client_id) == 0) {
            XMEMSET(s, 0, sizeof(BrokerSub));
        }
    }
#else
    cur = broker->subs;
    while (cur) {
        BrokerSub* next = cur->next;
        int remove = 0;
        /* Check active client subs */
        if (cur->client != NULL && cur->client->client_id != NULL &&
            XSTRCMP(cur->client->client_id, client_id) == 0) {
            remove = 1;
        }
        /* Check orphaned subs (stored client_id) */
        else if (cur->client == NULL &&
            BROKER_STR_VALID(cur->client_id) &&
            XSTRCMP(cur->client_id, client_id) == 0) {
            remove = 1;
        }
        if (remove) {
            if (prev) {
                prev->next = next;
            }
            else {
                broker->subs = next;
            }
            if (cur->filter) {
                WOLFMQTT_FREE(cur->filter);
            }
            if (cur->client_id) {
                WOLFMQTT_FREE(cur->client_id);
            }
            WOLFMQTT_FREE(cur);
        }
        else {
            prev = cur;
        }
        cur = next;
    }
#endif
}

/* Reattach orphaned (or active-takeover) subscriptions for `client_id` to
 * `new_bc`. Returns the number of reassociated subscriptions; the caller
 * uses a non-zero return as the [MQTT-3.2.2-2] "stored session state was
 * resumed" signal for CONNACK Session Present. */
static int BrokerSubs_ReassociateClient(MqttBroker* broker,
    const char* client_id, BrokerClient* new_bc)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerSub* s;
#endif

    int count = 0;
    if (broker == NULL || client_id == NULL || client_id[0] == '\0' ||
        new_bc == NULL) {
        return 0;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        BrokerSub* s = &broker->subs[i];
        if (!s->in_use) continue;
        /* Check orphaned subs (client=NULL, client_id stored in sub) */
        if (s->client == NULL && BROKER_STR_VALID(s->client_id) &&
            XSTRCMP(s->client_id, client_id) == 0) {
            s->client = new_bc;
            count++;
        }
        /* Check subs with active client (takeover scenario) */
        else if (s->client != NULL && BROKER_STR_VALID(s->client->client_id) &&
            XSTRCMP(s->client->client_id, client_id) == 0) {
            s->client = new_bc;
            count++;
        }
    }
#else
    s = broker->subs;
    while (s) {
        /* Check orphaned subs (client=NULL, client_id stored in sub) */
        if (s->client == NULL && BROKER_STR_VALID(s->client_id) &&
            XSTRCMP(s->client_id, client_id) == 0) {
            s->client = new_bc;
            count++;
        }
        /* Check subs with active client (takeover scenario) */
        else if (s->client != NULL && BROKER_STR_VALID(s->client->client_id) &&
            XSTRCMP(s->client->client_id, client_id) == 0) {
            s->client = new_bc;
            count++;
        }
        s = s->next;
    }
#endif
    if (count > 0) {
        /* The new client now owns these subs; reflect them in its cap count
         * so a reconnect cannot be used to exceed BROKER_MAX_SUBS_PER_CLIENT. */
        new_bc->sub_count += count;
        WBLOG_INFO(broker, "broker: reassociated %d subs for client_id=%s",
            count, BrokerLog_Sanitize(client_id));
    }
    return count;
}

/* -------------------------------------------------------------------------- */
/* Retained message management                                                 */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_RETAINED
static int BrokerRetained_Store(MqttBroker* broker, const char* topic,
    const byte* payload, word32 payload_len, MqttQoS qos, word32 expiry_sec)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    byte is_new = 0;
    byte* new_payload = NULL;
    BrokerRetainedMsg* cur;
#endif
    BrokerRetainedMsg* msg = NULL;
    int rc = MQTT_CODE_SUCCESS;

    if (broker == NULL || topic == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
#ifndef WOLFMQTT_STATIC_MEMORY
    cur = broker->retained;
#endif

#ifdef WOLFMQTT_STATIC_MEMORY
    /* Look for existing retained msg on this topic */
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        if (broker->retained[i].in_use &&
            XSTRCMP(broker->retained[i].topic, topic) == 0) {
            msg = &broker->retained[i];
            break;
        }
    }
    /* If not found, find a free slot */
    if (msg == NULL) {
        for (i = 0; i < BROKER_MAX_RETAINED; i++) {
            if (!broker->retained[i].in_use) {
                msg = &broker->retained[i];
                break;
            }
        }
    }
    if (msg == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        int tlen = (int)XSTRLEN(topic);
        if (tlen >= BROKER_MAX_TOPIC_LEN) {
            rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        else if (payload_len > BROKER_MAX_PAYLOAD_LEN) {
            rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(msg, 0, sizeof(*msg));
            msg->in_use = 1;
            XMEMCPY(msg->topic, topic, (size_t)tlen);
            msg->topic[tlen] = '\0';
            if (payload_len > 0 && payload != NULL) {
                XMEMCPY(msg->payload, payload, payload_len);
            }
            msg->payload_len = payload_len;
        }
    }
#else
    while (cur) {
        if (cur->topic != NULL && XSTRCMP(cur->topic, topic) == 0) {
            msg = cur;
            /* Re-publishing this topic cancels a deferred delete, otherwise a
             * later delivery would reap the freshly stored message. */
            msg->pending_delete = 0;
            break;
        }
        cur = cur->next;
    }
    if (msg == NULL) {
        /* Allocate new node + topic */
        int tlen = (int)XSTRLEN(topic);
        /* Cap the dynamic retained list so a client publishing RETAIN=1 to
         * many distinct topics cannot grow it without bound and exhaust the
         * heap; the static path is already bounded by BROKER_MAX_RETAINED. */
        if (broker->retained_count >= BROKER_MAX_RETAINED) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            msg = (BrokerRetainedMsg*)WOLFMQTT_MALLOC(
                sizeof(BrokerRetainedMsg));
            if (msg == NULL) {
                rc = MQTT_CODE_ERROR_MEMORY;
            }
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(msg, 0, sizeof(*msg));
            msg->topic = (char*)WOLFMQTT_MALLOC((size_t)tlen + 1);
            if (msg->topic == NULL) {
                WOLFMQTT_FREE(msg);
                msg = NULL;
                rc = MQTT_CODE_ERROR_MEMORY;
            }
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMCPY(msg->topic, topic, (size_t)tlen);
            msg->topic[tlen] = '\0';
            is_new = 1;
        }
    }
    /* Stage new payload in a temp; only touch the stored message after
     * all allocations succeed, so an OOM cannot destroy the prior one. */
    if (rc == MQTT_CODE_SUCCESS && payload_len > 0 && payload != NULL) {
        new_payload = (byte*)WOLFMQTT_MALLOC(payload_len);
        if (new_payload == NULL) {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        else {
            XMEMCPY(new_payload, payload, payload_len);
        }
    }
    if (rc == MQTT_CODE_SUCCESS) {
        if (!is_new && msg->payload != NULL) {
            WOLFMQTT_FREE(msg->payload);
        }
        msg->payload = new_payload;
        msg->payload_len = payload_len;
        if (is_new) {
            msg->next = broker->retained;
            broker->retained = msg;
            broker->retained_count++;
        }
    }
    else if (is_new && msg != NULL) {
        if (msg->topic) {
            WOLFMQTT_FREE(msg->topic);
        }
        WOLFMQTT_FREE(msg);
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        msg->store_time = WOLFMQTT_BROKER_GET_TIME_S();
        msg->expiry_sec = expiry_sec;
        msg->qos = qos;
        WBLOG_DBG(broker, "broker: retained store topic=%s len=%u qos=%d "
            "expiry=%u",
            BrokerLog_Sanitize(topic), (unsigned)payload_len, (int)qos,
            (unsigned)expiry_sec);
#ifdef WOLFMQTT_BROKER_PERSIST
        (void)BrokerPersist_PutRetained(broker, msg);
#endif
    }
    return rc;
}

static void BrokerRetained_Delete(MqttBroker* broker, const char* topic)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerRetainedMsg* cur;
    BrokerRetainedMsg* prev = NULL;
#endif
    int found = 0;

    if (broker == NULL || topic == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        if (broker->retained[i].in_use &&
            XSTRCMP(broker->retained[i].topic, topic) == 0) {
            WBLOG_DBG(broker, "broker: retained delete topic=%s",
                BrokerLog_Sanitize(topic));
            XMEMSET(&broker->retained[i], 0, sizeof(BrokerRetainedMsg));
            found = 1;
            break;
        }
    }
#else
    cur = broker->retained;
    while (cur) {
        BrokerRetainedMsg* next = cur->next;
        if (cur->topic != NULL && XSTRCMP(cur->topic, topic) == 0) {
            WBLOG_DBG(broker, "broker: retained delete topic=%s",
                BrokerLog_Sanitize(topic));
            if (broker->retained_delivering > 0) {
                /* A delivery loop is iterating this list (possibly re-entered
                 * via a WebSocket fan-out). Freeing now would invalidate that
                 * loop's saved next pointer; flag for deferred reap
                 * by the delivery loop instead. */
                cur->pending_delete = 1;
                found = 1;
                break;
            }
            if (prev) {
                prev->next = next;
            }
            else {
                broker->retained = next;
            }
            WOLFMQTT_FREE(cur->topic);
            if (cur->payload) {
                WOLFMQTT_FREE(cur->payload);
            }
            WOLFMQTT_FREE(cur);
            if (broker->retained_count > 0) {
                broker->retained_count--;
            }
            found = 1;
            break;
        }
        prev = cur;
        cur = next;
    }
#endif

#ifdef WOLFMQTT_BROKER_PERSIST
    if (found) {
        (void)BrokerPersist_DelRetained(broker, topic);
    }
#else
    (void)found;
#endif
}

static void BrokerRetained_FreeAll(MqttBroker* broker)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerRetainedMsg *cur = broker->retained;
#endif

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        XMEMSET(&broker->retained[i], 0, sizeof(BrokerRetainedMsg));
    }
#else
    while (cur) {
        BrokerRetainedMsg* next = cur->next;
        if (cur->topic) {
            WOLFMQTT_FREE(cur->topic);
        }
        if (cur->payload) {
            WOLFMQTT_FREE(cur->payload);
        }
        WOLFMQTT_FREE(cur);
        cur = next;
    }
    broker->retained = NULL;
    broker->retained_count = 0;
#endif
}
#endif /* WOLFMQTT_BROKER_RETAINED */

/* Forward declaration - used by retained delivery, will publish, and PUBLISH handler */
static int BrokerTopicMatch(const char* filter, const char* topic);

/* -------------------------------------------------------------------------- */
/* LWT (Last Will and Testament) helpers                                       */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_WILL
static void BrokerClient_ClearWill(BrokerClient* bc)
{
    if (bc == NULL) {
        return;
    }
    bc->has_will = 0;
    bc->will_qos = MQTT_QOS_0;
    bc->will_retain = 0;
    bc->will_delay_sec = 0;
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->will_payload_len = 0;
    bc->will_topic[0] = '\0';
#else
    if (bc->will_topic) {
        BROKER_FORCE_ZERO(bc->will_topic, XSTRLEN(bc->will_topic) + 1);
        WOLFMQTT_FREE(bc->will_topic);
        bc->will_topic = NULL;
    }
    if (bc->will_payload) {
        BROKER_FORCE_ZERO(bc->will_payload, bc->will_payload_len);
        WOLFMQTT_FREE(bc->will_payload);
        bc->will_payload = NULL;
    }
    bc->will_payload_len = 0;
#endif
}

/* -------------------------------------------------------------------------- */
/* Pending will management (v5 Will Delay Interval)                            */
/* -------------------------------------------------------------------------- */

/* Add a pending will to be published after delay expires */
static int BrokerPendingWill_Add(MqttBroker* broker, BrokerClient* bc)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#endif

    BrokerPendingWill* pw = NULL;
    WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();
    int rc = MQTT_CODE_SUCCESS;

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_PENDING_WILLS; i++) {
        if (!broker->pending_wills[i].in_use) {
            pw = &broker->pending_wills[i];
            break;
        }
    }
    if (pw == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        int id_len = (int)XSTRLEN(bc->client_id);
        int t_len = (int)XSTRLEN(bc->will_topic);
        if (id_len >= BROKER_MAX_CLIENT_ID_LEN) {
            rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        else if (t_len >= BROKER_MAX_TOPIC_LEN) {
            rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        else if (bc->will_payload_len > BROKER_MAX_WILL_PAYLOAD_LEN) {
            rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            XMEMSET(pw, 0, sizeof(*pw));
            pw->in_use = 1;
            XMEMCPY(pw->client_id, bc->client_id, id_len);
            pw->client_id[id_len] = '\0';
            XMEMCPY(pw->topic, bc->will_topic, t_len);
            pw->topic[t_len] = '\0';
            if (bc->will_payload_len > 0) {
                XMEMCPY(pw->payload, bc->will_payload,
                    bc->will_payload_len);
                pw->payload_len = bc->will_payload_len;
            }
        }
    }
#else
    pw = (BrokerPendingWill*)WOLFMQTT_MALLOC(sizeof(BrokerPendingWill));
    if (pw == NULL) {
        rc = MQTT_CODE_ERROR_MEMORY;
    }
    if (rc == MQTT_CODE_SUCCESS) {
        int id_len = (int)XSTRLEN(bc->client_id);
        int t_len = (int)XSTRLEN(bc->will_topic);
        XMEMSET(pw, 0, sizeof(*pw));
        pw->client_id = (char*)WOLFMQTT_MALLOC((size_t)id_len + 1);
        if (pw->client_id != NULL) {
            XMEMCPY(pw->client_id, bc->client_id, (size_t)id_len + 1);
        }
        else {
            rc = MQTT_CODE_ERROR_MEMORY;
        }
        if (rc == MQTT_CODE_SUCCESS) {
            pw->topic = (char*)WOLFMQTT_MALLOC((size_t)t_len + 1);
            if (pw->topic != NULL) {
                XMEMCPY(pw->topic, bc->will_topic, (size_t)t_len + 1);
            }
            else {
                rc = MQTT_CODE_ERROR_MEMORY;
            }
        }
        if (rc == MQTT_CODE_SUCCESS && bc->will_payload_len > 0) {
            pw->payload = (byte*)WOLFMQTT_MALLOC(bc->will_payload_len);
            if (pw->payload != NULL) {
                XMEMCPY(pw->payload, bc->will_payload, bc->will_payload_len);
                pw->payload_len = bc->will_payload_len;
            }
            else {
                rc = MQTT_CODE_ERROR_MEMORY;
            }
        }
    }
    if (rc == MQTT_CODE_SUCCESS) {
        pw->next = broker->pending_wills;
        broker->pending_wills = pw;
    }
    else if (pw != NULL) {
        if (pw->topic) {
            BROKER_FORCE_ZERO(pw->topic, XSTRLEN(pw->topic) + 1);
            WOLFMQTT_FREE(pw->topic);
        }
        if (pw->client_id) {
            WOLFMQTT_FREE(pw->client_id);
        }
        if (pw->payload) {
            BROKER_FORCE_ZERO(pw->payload, pw->payload_len);
            WOLFMQTT_FREE(pw->payload);
        }
        WOLFMQTT_FREE(pw);
    }
#endif

    if (rc == MQTT_CODE_SUCCESS) {
        pw->qos = bc->will_qos;
        pw->retain = bc->will_retain;
        pw->publish_time = now + (WOLFMQTT_BROKER_TIME_T)bc->will_delay_sec;
        WBLOG_DBG(broker, "broker: will deferred sock=%d client_id=%s delay=%u",
            (int)bc->sock, BrokerLog_Sanitize(bc->client_id),
            (unsigned)bc->will_delay_sec);
    }
    return rc;
}

/* Cancel a pending will for the given client_id (client reconnected) */
static void BrokerPendingWill_Cancel(MqttBroker* broker,
    const char* client_id)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerPendingWill* pw;
    BrokerPendingWill* prev = NULL;
#endif

    if (broker == NULL || client_id == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_PENDING_WILLS; i++) {
        if (broker->pending_wills[i].in_use &&
            XSTRCMP(broker->pending_wills[i].client_id, client_id) == 0) {
            WBLOG_DBG(broker, "broker: will cancelled client_id=%s",
                BrokerLog_Sanitize(client_id));
            XMEMSET(&broker->pending_wills[i], 0,
                sizeof(BrokerPendingWill));
            return;
        }
    }
#else
    pw = broker->pending_wills;
    while (pw) {
        BrokerPendingWill* next = pw->next;
        if (pw->client_id != NULL &&
            XSTRCMP(pw->client_id, client_id) == 0) {
            WBLOG_DBG(broker, "broker: will cancelled client_id=%s",
                BrokerLog_Sanitize(client_id));
            if (prev) {
                prev->next = next;
            }
            else {
                broker->pending_wills = next;
            }
            WOLFMQTT_FREE(pw->client_id);
            if (pw->topic) {
                BROKER_FORCE_ZERO(pw->topic, XSTRLEN(pw->topic) + 1);
                WOLFMQTT_FREE(pw->topic);
            }
            if (pw->payload) {
                BROKER_FORCE_ZERO(pw->payload, pw->payload_len);
                WOLFMQTT_FREE(pw->payload);
            }
            WOLFMQTT_FREE(pw);
            return;
        }
        prev = pw;
        pw = next;
    }
#endif
}

static void BrokerPendingWill_FreeAll(MqttBroker* broker)
{
#ifndef WOLFMQTT_STATIC_MEMORY
    BrokerPendingWill* pw;
#endif

    if (broker == NULL) {
        return;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    XMEMSET(broker->pending_wills, 0, sizeof(broker->pending_wills));
#else
    pw = broker->pending_wills;
    while (pw) {
        BrokerPendingWill* next = pw->next;
        if (pw->client_id) WOLFMQTT_FREE(pw->client_id);
        if (pw->topic) {
            BROKER_FORCE_ZERO(pw->topic, XSTRLEN(pw->topic) + 1);
            WOLFMQTT_FREE(pw->topic);
        }
        if (pw->payload) {
            BROKER_FORCE_ZERO(pw->payload, pw->payload_len);
            WOLFMQTT_FREE(pw->payload);
        }
        WOLFMQTT_FREE(pw);
        pw = next;
    }
    broker->pending_wills = NULL;
#endif
}

static void BrokerClient_PublishWillImmediate(MqttBroker* broker,
    const char* topic, const byte* payload, word16 payload_len,
    MqttQoS qos, byte retain);

/* Process pending wills - publish any that have expired their delay */
static int BrokerPendingWill_Process(MqttBroker* broker)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerPendingWill* pw;
    BrokerPendingWill* prev = NULL;
#endif
    int activity = 0;
    WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();

    if (broker == NULL) {
        return 0;
    }

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_PENDING_WILLS; i++) {
        BrokerPendingWill* pw = &broker->pending_wills[i];
        if (!pw->in_use) {
            continue;
        }
        if (now >= pw->publish_time) {
            WBLOG_DBG(broker, "broker: LWT deferred publish client_id=%s topic=%s "
                "len=%u", BrokerLog_Sanitize(pw->client_id),
                BrokerLog_Sanitize(pw->topic),
                (unsigned)pw->payload_len);
            BrokerClient_PublishWillImmediate(broker, pw->topic,
                pw->payload, pw->payload_len, pw->qos, pw->retain);
            XMEMSET(pw, 0, sizeof(BrokerPendingWill));
            activity = 1;
        }
    }
#else
    pw = broker->pending_wills;
    while (pw) {
        BrokerPendingWill* next = pw->next;
        if (now >= pw->publish_time) {
            WBLOG_DBG(broker, "broker: LWT deferred publish client_id=%s topic=%s "
                "len=%u", BrokerLog_Sanitize(pw->client_id),
                BrokerLog_Sanitize(pw->topic),
                (unsigned)pw->payload_len);
            BrokerClient_PublishWillImmediate(broker, pw->topic,
                pw->payload, pw->payload_len, pw->qos, pw->retain);
            if (prev) {
                prev->next = next;
            }
            else if (broker->pending_wills == pw) {
                broker->pending_wills = next;
            }
            else {
                /* The fan-out above re-entered BrokerPendingWill_Add (a WS
                 * close), prepending a node, so pw is no longer the head.
                 * Unlink pw via its real predecessor instead of clobbering the
                 * new head with the stale saved next. */
                BrokerPendingWill* p = broker->pending_wills;
                while (p != NULL && p->next != pw) {
                    p = p->next;
                }
                if (p != NULL) {
                    p->next = next;
                }
            }
            if (pw->client_id) WOLFMQTT_FREE(pw->client_id);
            if (pw->topic) {
                BROKER_FORCE_ZERO(pw->topic, XSTRLEN(pw->topic) + 1);
                WOLFMQTT_FREE(pw->topic);
            }
            if (pw->payload) {
                BROKER_FORCE_ZERO(pw->payload, pw->payload_len);
                WOLFMQTT_FREE(pw->payload);
            }
            WOLFMQTT_FREE(pw);
            activity = 1;
        }
        else {
            prev = pw;
        }
        pw = next;
    }
#endif

    return activity;
}
#endif /* WOLFMQTT_BROKER_WILL */

#ifdef WOLFMQTT_BROKER_RETAINED
static void BrokerRetained_DeliverToClient(MqttBroker* broker,
    BrokerClient* bc, const char* filter, MqttQoS sub_qos)
{
    WOLFMQTT_BROKER_TIME_T now;
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerRetainedMsg* rm;
    BrokerRetainedMsg* rm_prev = NULL;
#endif

    if (broker == NULL || bc == NULL || filter == NULL) {
        return;
    }
    now = WOLFMQTT_BROKER_GET_TIME_S();

#ifndef WOLFMQTT_STATIC_MEMORY
    /* Mark a delivery in progress so a re-entrant BrokerRetained_Delete (via a
     * WebSocket fan-out close) defers its free instead of invalidating the
     * loop's saved next pointer. */
    broker->retained_delivering++;
#endif

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_RETAINED; i++) {
        BrokerRetainedMsg* rm = &broker->retained[i];
        if (!rm->in_use || rm->topic[0] == '\0') {
            continue;
        }
        /* Skip expired messages */
        if (rm->expiry_sec > 0 &&
            (now - rm->store_time) >= rm->expiry_sec) {
            WBLOG_DBG(broker, "broker: retained expired topic=%s",
                BrokerLog_Sanitize(rm->topic));
            XMEMSET(rm, 0, sizeof(BrokerRetainedMsg));
            continue;
        }
        if (BrokerTopicMatch(filter, rm->topic)) {
            MqttPublish out_pub;
            MqttQoS eff_qos = (rm->qos < sub_qos) ? rm->qos : sub_qos;
            int enc_rc;
            XMEMSET(&out_pub, 0, sizeof(out_pub));
            out_pub.topic_name = rm->topic;
            out_pub.qos = eff_qos;
            out_pub.retain = 1;
            out_pub.duplicate = 0;
            out_pub.buffer = (rm->payload_len > 0) ? rm->payload : NULL;
            out_pub.total_len = rm->payload_len;
            if (eff_qos >= MQTT_QOS_1) {
                out_pub.packet_id = BrokerNextPacketId(broker);
            }
#ifdef WOLFMQTT_V5
            out_pub.protocol_level = bc->protocol_level;
#endif
            enc_rc = MqttEncode_Publish(bc->tx_buf,
                BROKER_CLIENT_TX_SZ(bc), &out_pub, 0);
            if (enc_rc > 0) {
                WBLOG_DBG(broker, "broker: retained deliver sock=%d topic=%s "
                    "len=%u qos=%d", (int)bc->sock,
                    BrokerLog_Sanitize(rm->topic),
                    (unsigned)rm->payload_len, (int)eff_qos);
                (void)MqttPacket_Write(&bc->client, bc->tx_buf, enc_rc);
            }
        }
    }
#else
    rm = broker->retained;
    while (rm) {
        BrokerRetainedMsg* rm_next = rm->next;
        /* Reap deferred-delete and expired nodes. Freeing is only safe at the
         * outermost delivery depth; a nested re-entrant (WS fan-out) delivery
         * may hold rm in an enclosing loop's saved rm_next, so at deeper depths
         * mark the node and defer to the retained_delivering==0 post-loop reap. */
        if (rm->pending_delete ||
            (rm->expiry_sec > 0 &&
            (now - rm->store_time) >= rm->expiry_sec)) {
            if (broker->retained_delivering > 1) {
                rm->pending_delete = 1;
                rm_prev = rm;
                rm = rm_next;
                continue;
            }
            WBLOG_DBG(broker, "broker: retained expired topic=%s",
                BrokerLog_Sanitize(rm->topic));
            if (rm_prev) {
                rm_prev->next = rm_next;
            }
            else {
                broker->retained = rm_next;
            }
            if (rm->topic) WOLFMQTT_FREE(rm->topic);
            if (rm->payload) WOLFMQTT_FREE(rm->payload);
            WOLFMQTT_FREE(rm);
            if (broker->retained_count > 0) {
                broker->retained_count--;
            }
            rm = rm_next;
            continue;
        }
        if (rm->topic != NULL && BrokerTopicMatch(filter, rm->topic)) {
            MqttPublish out_pub;
            MqttQoS eff_qos = (rm->qos < sub_qos) ? rm->qos : sub_qos;
            int enc_rc;
            XMEMSET(&out_pub, 0, sizeof(out_pub));
            out_pub.topic_name = rm->topic;
            out_pub.qos = eff_qos;
            out_pub.retain = 1;
            out_pub.duplicate = 0;
            out_pub.buffer = (rm->payload_len > 0) ? rm->payload : NULL;
            out_pub.total_len = rm->payload_len;
            if (eff_qos >= MQTT_QOS_1) {
                out_pub.packet_id = BrokerNextPacketId(broker);
            }
#ifdef WOLFMQTT_V5
            out_pub.protocol_level = bc->protocol_level;
#endif
            enc_rc = MqttEncode_Publish(bc->tx_buf,
                BROKER_CLIENT_TX_SZ(bc), &out_pub, 0);
            if (enc_rc > 0) {
                WBLOG_DBG(broker, "broker: retained deliver sock=%d topic=%s "
                    "len=%u qos=%d", (int)bc->sock,
                    BrokerLog_Sanitize(rm->topic),
                    (unsigned)rm->payload_len, (int)eff_qos);
                (void)MqttPacket_Write(&bc->client, bc->tx_buf, enc_rc);
            }
        }
        rm_prev = rm;
        rm = rm_next;
    }
#endif

#ifndef WOLFMQTT_STATIC_MEMORY
    if (broker->retained_delivering > 0) {
        broker->retained_delivering--;
    }
    /* When the outermost delivery finishes, reap nodes a re-entrant delete
     * marked after this loop had already passed them, so they stop counting
     * against BROKER_MAX_RETAINED. Safe now: no delivery loop holds pointers. */
    if (broker->retained_delivering == 0) {
        BrokerRetainedMsg* p = broker->retained;
        BrokerRetainedMsg* pprev = NULL;
        while (p != NULL) {
            BrokerRetainedMsg* pnext = p->next;
            if (p->pending_delete) {
                if (pprev) {
                    pprev->next = pnext;
                }
                else {
                    broker->retained = pnext;
                }
                if (p->topic) WOLFMQTT_FREE(p->topic);
                if (p->payload) WOLFMQTT_FREE(p->payload);
                WOLFMQTT_FREE(p);
                if (broker->retained_count > 0) {
                    broker->retained_count--;
                }
            }
            else {
                pprev = p;
            }
            p = pnext;
        }
    }
#endif
}
#endif /* WOLFMQTT_BROKER_RETAINED */

#ifdef WOLFMQTT_BROKER_WILL
static void BrokerClient_PublishWill(MqttBroker* broker, BrokerClient* bc)
{
    if (broker == NULL || bc == NULL || !bc->has_will) {
        return;
    }
    if (!BROKER_STR_VALID(bc->will_topic)) {
        return;
    }

    /* v5 Will Delay Interval: defer publication */
    if (bc->will_delay_sec > 0) {
        if (BrokerPendingWill_Add(broker, bc) == MQTT_CODE_SUCCESS) {
            BrokerClient_ClearWill(bc);
            return; /* will deferred, not published now */
        }
        /* Out of pending-will slots: fall back to immediate publication, but
         * surface it - a silent fallback lets slot exhaustion erase the Will
         * Delay grace window invisibly to the operator. */
        WBLOG_ERR(broker,
            "broker: pending-will pool full, publishing LWT immediately "
            "(delay=%u lost) sock=%d", (unsigned)bc->will_delay_sec,
            (int)bc->sock);
    }

    WBLOG_DBG(broker, "broker: LWT publish sock=%d topic=%s len=%u",
        (int)bc->sock, BrokerLog_Sanitize(bc->will_topic),
        (unsigned)bc->will_payload_len);

    BrokerClient_PublishWillImmediate(broker, bc->will_topic,
        bc->will_payload, bc->will_payload_len, bc->will_qos,
        bc->will_retain);
    BrokerClient_ClearWill(bc);
}

/* Publish a will message immediately (shared by direct and deferred paths) */
static void BrokerClient_PublishWillImmediate(MqttBroker* broker,
    const char* topic, const byte* payload, word16 payload_len,
    MqttQoS qos, byte retain)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    BrokerSub* sub;
    BrokerSub* next_sub = NULL;
#endif

    if (broker == NULL || topic == NULL) {
        return;
    }

    /* Handle retain flag on will message */
    if (retain) {
        if (payload_len == 0) {
            BrokerRetained_Delete(broker, topic);
        }
        else {
            int ret_rc = BrokerRetained_Store(broker, topic, payload,
                payload_len, qos, 0);
            if (ret_rc != MQTT_CODE_SUCCESS) {
                WBLOG_ERR(broker, "Retained store failed: %s",
                    MqttClient_ReturnCodeToString(ret_rc));
            }
        }
    }

    /* Fan out to matching subscribers */
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        BrokerSub* sub = &broker->subs[i];
        if (!sub->in_use) continue;
#else
    sub = broker->subs;
    while (sub) {
        /* Snapshot the successor before any MqttPacket_Write: a WS fan-out
         * write can drive an lws_service spin whose re-entrant CLOSED frees
         * this client's BrokerSub nodes, so reading sub->next afterwards
         * would dereference a freed node. */
        next_sub = sub->next;
#endif
        if (sub->client != NULL && sub->client->protocol_level != 0 &&
            BROKER_STR_VALID(sub->filter) &&
            BrokerTopicMatch(sub->filter, topic)) {
            MqttPublish out_pub;
            MqttQoS eff_qos;
            int enc_rc;
            XMEMSET(&out_pub, 0, sizeof(out_pub));
            out_pub.topic_name = (char*)topic;
            eff_qos = (qos < sub->qos) ? qos : sub->qos;
            out_pub.qos = eff_qos;
            out_pub.retain = 0;
            out_pub.duplicate = 0;
            out_pub.buffer = (payload_len > 0) ? (byte*)payload : NULL;
            out_pub.total_len = payload_len;
            if (eff_qos >= MQTT_QOS_1) {
                out_pub.packet_id = BrokerNextPacketId(broker);
            }
#ifdef WOLFMQTT_V5
            out_pub.protocol_level = sub->client->protocol_level;
#endif
            enc_rc = MqttEncode_Publish(sub->client->tx_buf,
                BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
            if (enc_rc > 0) {
                (void)MqttPacket_Write(&sub->client->client,
                    sub->client->tx_buf, enc_rc);
            }
        }
#ifndef WOLFMQTT_STATIC_MEMORY
        sub = next_sub;
#endif
    }
}
#endif /* WOLFMQTT_BROKER_WILL */

/* -------------------------------------------------------------------------- */
/* Topic matching                                                              */
/* -------------------------------------------------------------------------- */
#ifdef WOLFMQTT_BROKER_WILDCARDS
static int BrokerTopicMatch(const char* filter, const char* topic)
{
    const char* f = filter;
    const char* t = topic;

    if (filter == NULL || topic == NULL) {
        return 0;
    }

    /* [MQTT-4.7.2] Wildcard filters must not match $-prefixed topics */
    if (*t == '$' && (*f == '+' || *f == '#')) {
        return 0;
    }

    while (*f && *t) {
        if (*f == '#') {
            return (f[1] == '\0');
        }
        if (*f == '+') {
            while (*t && *t != '/') {
                t++;
            }
            f++;
        }
        else {
            if (*f != *t) {
                return 0;
            }
            f++;
            t++;
        }
        if (*t == '/' && *f == '/') {
            t++;
            f++;
        }
        else if (*t == '/' || *f == '/') {
            /* [MQTT-4.7.1.2] 'topic/#' must also match 'topic' itself */
            if (*f == '/' && f[1] == '#' && f[2] == '\0' && *t == '\0') {
                return 1;
            }
            return 0;
        }
    }

    if (*f == '#') {
        return (f[1] == '\0');
    }
    if (*f == '+' && f[1] == '\0' && *t == '\0') {
        return 1;
    }
    return (*f == '\0' && *t == '\0');
}
#else
/* Exact match only when wildcards are disabled */
static int BrokerTopicMatch(const char* filter, const char* topic)
{
    if (filter == NULL || topic == NULL) {
        return 0;
    }
    return (XSTRCMP(filter, topic) == 0);
}
#endif /* WOLFMQTT_BROKER_WILDCARDS */

/* -------------------------------------------------------------------------- */
/* Packet send helpers                                                         */
/* -------------------------------------------------------------------------- */
static int BrokerSend_PingResp(BrokerClient* bc)
{
    if (bc == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    WBLOG_DBG(bc->broker, "broker: PINGREQ -> PINGRESP sock=%d", (int)bc->sock);
    bc->tx_buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PING_RESP);
    bc->tx_buf[1] = 0;
    return MqttPacket_Write(&bc->client, bc->tx_buf, 2);
}

int BrokerSend_SubAck(BrokerClient* bc, word16 packet_id,
    const byte* return_codes, int return_code_count)
{
    int remain_len;
    int pos = 0;
    int i;
    int i_chk;

    if (bc == NULL || return_codes == NULL || return_code_count <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* [MQTT-3.9.3-2] Refuse to serialize a reserved SUBACK return code.
     * The normal broker subscribe path produces only spec-allowed
     * values, but this helper is the final boundary - a future caller
     * passing a reserved value should fail loudly here rather than emit
     * a malformed SUBACK on the wire. */
    for (i_chk = 0; i_chk < return_code_count; i_chk++) {
        if (!MqttPacket_SubAckReturnCodeValid(return_codes[i_chk],
                                              bc->protocol_level)) {
            WBLOG_ERR(bc->broker,
                "broker: SUBACK reserved return code 0x%02X sock=%d "
                "[MQTT-3.9.3-2]",
                return_codes[i_chk], (int)bc->sock);
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
    }

    WBLOG_INFO(bc->broker, "broker: SUBACK sock=%d packet_id=%u topics=%d",
        (int)bc->sock, packet_id, return_code_count);
    remain_len = MQTT_DATA_LEN_SIZE + return_code_count;
#ifdef WOLFMQTT_V5
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        remain_len += 1; /* property length (0) */
    }
#endif

    /* 1 (type) + 4 (max VBI) + remain_len */
    if (1 + 4 + remain_len > (int)BROKER_CLIENT_TX_SZ(bc)) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }

    bc->tx_buf[pos++] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    pos += MqttEncode_Vbi(&bc->tx_buf[pos], remain_len);
    pos += MqttEncode_Num(&bc->tx_buf[pos], packet_id);
#ifdef WOLFMQTT_V5
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        bc->tx_buf[pos++] = 0; /* property length */
    }
#endif
    for (i = 0; i < return_code_count; i++) {
        bc->tx_buf[pos++] = return_codes[i];
    }

    return MqttPacket_Write(&bc->client, bc->tx_buf, pos);
}

#ifdef WOLFMQTT_V5
/* Find a property by type in a property list */
static MqttProp* BrokerProps_Find(MqttProp* head, MqttPropertyType type)
{
    MqttProp* prop = head;
    while (prop != NULL) {
        if (prop->type == type) {
            return prop;
        }
        prop = prop->next;
    }
    return NULL;
}

static int BrokerSend_Disconnect(BrokerClient* bc, byte reason_code)
{
    int rc;
    MqttDisconnect disc;

    if (bc == NULL ||
        bc->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        return 0;
    }

    XMEMSET(&disc, 0, sizeof(disc));
    disc.protocol_level = bc->protocol_level;
    disc.reason_code = reason_code;

    rc = MqttEncode_Disconnect(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &disc);
    if (rc > 0) {
        WBLOG_DBG(bc->broker, "broker: DISCONNECT send sock=%d reason=0x%02x",
            (int)bc->sock, reason_code);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }
    return rc;
}
#endif

/* -------------------------------------------------------------------------- */
/* Packet handlers                                                             */
/* -------------------------------------------------------------------------- */

/* Returns: > 0 success, 0 auth rejected (CONNACK sent with refused),
 *          < 0 error */
static int BrokerHandle_Connect(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    MqttConnect mc;
    MqttConnectAck ack;
    MqttMessage lwt;
    word16 id_len = 0;
    /* [MQTT-3.2.2-2] Session Present is set when an accepted
     * CleanSession=0 connection finds stored session state for the
     * client_id. The MQTT spec defines Session state as more than
     * subscriptions (in-flight QoS 1/2 PUBLISH, unacknowledged PUBREL,
     * outstanding packet identifiers); this broker only persists
     * subscriptions across disconnects today (BrokerSubs_OrphanClient
     * keeps them, but per-message QoS 2 state in bc->qos2_in_flight is
     * dropped). If broker session persistence ever widens to cover QoS
     * state, the source of session_present needs to widen too - a
     * BrokerSession_HasStoredState() helper is the natural extension
     * point. */
    int session_present = 0;
#ifdef WOLFMQTT_V5
    int auto_assigned = 0;
#endif

    XMEMSET(&mc, 0, sizeof(mc));
    XMEMSET(&ack, 0, sizeof(ack));
    XMEMSET(&lwt, 0, sizeof(lwt));
    mc.lwt_msg = &lwt;

    WBLOG_INFO(broker, "broker: CONNECT recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: CONNECT decode failed rc=%d", rc);
    #ifdef WOLFMQTT_V5
        if (mc.props) { (void)MqttProps_Free(mc.props); }
        if (lwt.props) { (void)MqttProps_Free(lwt.props); }
    #endif
        return rc;
    }

#ifdef WOLFMQTT_V5
    /* Initialize early so every `goto send_connack` below produces a CONNACK
     * matching the client's protocol level (v5 CONNACK has a Properties
     * length and uses v5 reason codes). */
    ack.protocol_level = mc.protocol_level;
#endif

    /* [MQTT-3.1.2-2] Reject unsupported Protocol Level. Per spec, the server
     * MUST respond with CONNACK 0x01 (unacceptable protocol level) and then
     * disconnect. v3.1.1 (level 4) is always supported; v5 (level 5) only
     * when WOLFMQTT_V5 is compiled in. Other values reach this branch and
     * are refused before any session/will/auth processing. */
    if (mc.protocol_level != MQTT_CONNECT_PROTOCOL_LEVEL_4
#ifdef WOLFMQTT_V5
        && mc.protocol_level != MQTT_CONNECT_PROTOCOL_LEVEL_5
#endif
        ) {
        WBLOG_ERR(broker,
            "broker: unsupported protocol level %u sock=%d [MQTT-3.1.2-2]",
            (unsigned)mc.protocol_level, (int)bc->sock);
        ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_PROTO;
#ifdef WOLFMQTT_V5
        /* The client claimed an unknown protocol; we don't know what wire
         * format they expect for the CONNACK. Fall back to the v3.1.1
         * shape (no properties), which is what [MQTT-3.1.2-2] specifies
         * verbatim and is the simplest format any reasonable client can
         * parse. */
        ack.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
#endif
        goto send_connack;
    }

    /* Store client ID */
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->client_id[0] = '\0';
#endif
    if (mc.client_id) {
        if (MqttDecode_Num((byte*)mc.client_id - MQTT_DATA_LEN_SIZE,
                &id_len, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        #ifdef WOLFMQTT_STATIC_MEMORY
            if (id_len >= BROKER_MAX_CLIENT_ID_LEN) {
                WBLOG_ERR(broker,
                    "broker: client_id too long (%u >= %d) sock=%d",
                    (unsigned)id_len, BROKER_MAX_CLIENT_ID_LEN,
                    (int)bc->sock);
            #ifdef WOLFMQTT_V5
                if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                    ack.return_code = MQTT_REASON_CLIENT_ID_NOT_VALID;
                }
                else
            #endif
                {
                    ack.return_code =
                        MQTT_CONNECT_ACK_CODE_REFUSED_ID;
                }
                goto send_connack;
            }
        #endif
            if (id_len > 0) {
                BROKER_STORE_STR(bc->client_id, mc.client_id, id_len,
                    BROKER_MAX_CLIENT_ID_LEN);
            }
        }
    }

    /* Reserve the "auto-" prefix for server-assigned IDs. Without this an
     * attacker could observe their own assigned auto-XXXXXXXX, then reconnect
     * with an explicit client_id matching a predicted future value and
     * hijack a victim's session via the duplicate-takeover path below. */
    if (id_len >= 5 && BROKER_STR_VALID(bc->client_id) &&
        XSTRNCMP(bc->client_id, "auto-", 5) == 0) {
        WBLOG_ERR(broker,
            "broker: client_id with reserved 'auto-' prefix sock=%d",
            (int)bc->sock);
    #ifdef WOLFMQTT_V5
        if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
            ack.return_code = MQTT_REASON_CLIENT_ID_NOT_VALID;
        }
        else
    #endif
        {
            ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_ID;
        }
        goto send_connack;
    }

    /* [MQTT-3.1.3-8] v3.1.1: zero-length ClientId requires CleanSession=1.
     * The server MUST respond with CONNACK 0x02 (Identifier rejected) and
     * close the connection. v5 dropped this restriction in favor of Clean
     * Start + Session Expiry Interval, so it is enforced for v3.1.1 only. */
    if (id_len == 0 && !mc.clean_session
#ifdef WOLFMQTT_V5
        && mc.protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5
#endif
        ) {
        WBLOG_ERR(broker,
            "broker: empty ClientId with clean_session=0 sock=%d "
            "[MQTT-3.1.3-8]", (int)bc->sock);
        ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_ID;
        goto send_connack;
    }

    bc->protocol_level = mc.protocol_level;
    bc->keep_alive_sec = mc.keep_alive_sec;
    bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();

#ifndef WOLFMQTT_STATIC_MEMORY
    /* Default Session Expiry. Set BEFORE the v5 property parse below
     * so that a v5 client carrying MQTT_PROP_SESSION_EXPIRY_INTERVAL
     * overrides this default rather than being silently clobbered:
     *  - v3.1.1 persistent (clean_session=0): 0xFFFFFFFF (server
     *    policy decides eviction; MQTT 3.1.1 sec 3.1.2.4).
     *  - clean_session=1 or v5 client without the property: 0
     *    (expire on disconnect, per MQTT v5 sec 3.1.2.11.2). */
    if (!mc.clean_session) {
        bc->session_expiry_sec = 0xFFFFFFFFu;
    }
    else {
        bc->session_expiry_sec = 0;
    }
#endif

#if defined(WOLFMQTT_V5) && !defined(WOLFMQTT_STATIC_MEMORY)
    /* [MQTT-3.1.2.11.3] v5 Receive Maximum. If present and non-zero, the
     * client is telling us not to exceed this many outbound QoS 1/2
     * PUBLISHes in flight to it. Absent property means 65535 (no
     * client-imposed cap). 0 is a protocol error, but tolerate it as
     * "unset" rather than disconnecting, to stay friendly to mildly
     * non-conforming clients - the actual cap then comes from
     * BROKER_MAX_INFLIGHT_PER_SUB alone. */
    if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
            mc.props != NULL) {
        MqttProp* rm_prop = BrokerProps_Find(mc.props,
                MQTT_PROP_RECEIVE_MAX);
        if (rm_prop != NULL && rm_prop->data_short > 0) {
            bc->client_receive_max = rm_prop->data_short;
            WBLOG_DBG(broker,
                "broker: client Receive Maximum sock=%d value=%u",
                (int)bc->sock, (unsigned)bc->client_receive_max);
        }
        /* [MQTT-3.1.2.11.2] v5 Session Expiry Interval. If present,
         * carry it onto bc->session_expiry_sec so the disconnect
         * path stamps it into the orphan record. Absent property
         * means the default set above stands (0 for clean_session=1,
         * 0xFFFFFFFF for clean_session=0 to honor v3.1.1 persistence
         * semantics when a v5 client opts in without the property). */
        {
            MqttProp* se_prop = BrokerProps_Find(mc.props,
                    MQTT_PROP_SESSION_EXPIRY_INTERVAL);
            if (se_prop != NULL) {
                bc->session_expiry_sec = se_prop->data_int;
                WBLOG_DBG(broker,
                    "broker: client Session Expiry sock=%d value=%u",
                    (int)bc->sock, (unsigned)bc->session_expiry_sec);
            }
        }
    }
#endif

    /* [MQTT-3.1.3-6] If we accepted a zero-length ClientId, assign a unique
     * server-generated one before the duplicate-check / session-resume block
     * below so the assigned ID flows through normal handling. v5 also echoes
     * it back to the client via the Assigned Client Identifier property
     * (emitted in the v5 CONNACK construction below); v3.1.1 has no such
     * field, so the assignment is server-internal. */
    if (id_len == 0 && !BROKER_STR_VALID(bc->client_id)) {
        /* "auto-" + 8 hex chars + NUL. The counter advances on every empty-ID
         * CONNECT that reaches this point - including connects that are later
         * refused (e.g., auth failure below) - so it is not a count of
         * accepted clients. */
        static const char hex_digits[] = "0123456789abcdef";
        char auto_id[14];
        const word16 auto_len = 13;
        word32 id_value = broker->next_auto_id++;
        int i;
        if (broker->next_auto_id == 0) {
            /* Skip 0 on wrap for stylistic consistency with next_packet_id;
             * unlike packet IDs, 0 has no protocol significance here. */
            broker->next_auto_id = 1;
        }
        XMEMCPY(auto_id, "auto-", 5);
        for (i = 7; i >= 0; i--) {
            auto_id[5 + i] = hex_digits[id_value & 0xF];
            id_value >>= 4;
        }
        auto_id[auto_len] = '\0';
        BROKER_STORE_STR(bc->client_id, auto_id, auto_len,
            BROKER_MAX_CLIENT_ID_LEN);
        if (!BROKER_STR_VALID(bc->client_id)) {
            /* Storage failed (e.g., WOLFMQTT_MALLOC returned NULL in the
             * dynamic-memory path). Refuse rather than proceeding with an
             * untracked client. */
            WBLOG_ERR(broker,
                "broker: auto-id store failed sock=%d", (int)bc->sock);
        #ifdef WOLFMQTT_V5
            if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                ack.return_code = MQTT_REASON_SERVER_UNAVAILABLE;
            }
            else
        #endif
            {
                ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL;
            }
            goto send_connack;
        }
    #ifdef WOLFMQTT_V5
        auto_assigned = 1;
    #endif
    }

    WBLOG_INFO(broker, "broker: CONNECT proto=%u clean=%d will=%d client_id=%s",
        mc.protocol_level, mc.clean_session, mc.enable_lwt,
        BrokerLog_Sanitize(
            BROKER_STR_VALID(bc->client_id) ? bc->client_id : "(null)"));

    /* Client ID uniqueness and clean session handling */
    bc->clean_session = mc.clean_session;

    /* Validate credentials BEFORE any session-state mutation. Storing the
     * username/password and running the credential gate here ensures an
     * unauthenticated peer that guesses a client_id cannot disconnect the
     * victim, fire its LWT, or hijack/destroy its persisted subscriptions:
     * the duplicate-takeover and orphan-reassociation logic below only runs
     * once auth has passed. */
#ifdef WOLFMQTT_BROKER_AUTH
#ifdef WOLFMQTT_STATIC_MEMORY
    bc->username[0] = '\0';
    bc->password[0] = '\0';
#endif
    bc->password_len = 0;
    if (mc.username) {
        word16 ulen = 0;
        if (MqttDecode_Num((byte*)mc.username - MQTT_DATA_LEN_SIZE,
                &ulen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        #ifdef WOLFMQTT_STATIC_MEMORY
            if (ulen >= BROKER_MAX_USERNAME_LEN) {
                WBLOG_ERR(broker,
                    "broker: username too long (%u >= %d) sock=%d",
                    (unsigned)ulen, BROKER_MAX_USERNAME_LEN,
                    (int)bc->sock);
            #ifdef WOLFMQTT_V5
                if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                    ack.return_code = MQTT_REASON_BAD_USER_OR_PASS;
                }
                else
            #endif
                {
                    ack.return_code =
                        MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD;
                }
                goto send_connack;
            }
        #endif
            BROKER_STORE_STR_SENSITIVE(bc->username, mc.username, ulen,
                BROKER_MAX_USERNAME_LEN);
        }
    }
    if (mc.password) {
        word16 plen = 0;
        if (MqttDecode_Num((byte*)mc.password - MQTT_DATA_LEN_SIZE,
                &plen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        #ifdef WOLFMQTT_STATIC_MEMORY
            if (plen >= BROKER_MAX_PASSWORD_LEN) {
                WBLOG_ERR(broker,
                    "broker: password too long (%u >= %d) sock=%d",
                    (unsigned)plen, BROKER_MAX_PASSWORD_LEN,
                    (int)bc->sock);
            #ifdef WOLFMQTT_V5
                if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                    ack.return_code = MQTT_REASON_BAD_USER_OR_PASS;
                }
                else
            #endif
                {
                    ack.return_code =
                        MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD;
                }
                goto send_connack;
            }
        #endif
            /* [MQTT-3.1.3.5] Password is Binary Data and may legally
             * contain 0x00. The binary-sensitive store records the
             * actual length in bc->password_len so wipe and compare
             * paths don't fall back to XSTRLEN truncation. */
            BROKER_STORE_BIN_SENSITIVE(bc->password, bc->password_len,
                mc.password, plen, BROKER_MAX_PASSWORD_LEN);
        }
    }
    if (broker->auth_user || broker->auth_pass) {
        int auth_ok = 1;
        if (broker->auth_user && (
        #ifndef WOLFMQTT_STATIC_MEMORY
            bc->username == NULL ||
        #endif
            bc->username[0] == '\0' ||
            BrokerStrCompare(broker->auth_user, bc->username,
                BROKER_MAX_USERNAME_LEN) != 0)) {
            auth_ok = 0;
        }
        if (broker->auth_pass && (
        #ifndef WOLFMQTT_STATIC_MEMORY
            bc->password == NULL ||
        #endif
            bc->password_len == 0 ||
            BrokerBufCompare((const byte*)broker->auth_pass,
                (int)XSTRLEN(broker->auth_pass),
                (const byte*)bc->password, (int)bc->password_len,
                BROKER_MAX_PASSWORD_LEN) != 0)) {
            auth_ok = 0;
        }
        if (!auth_ok) {
            WBLOG_ERR(broker, "broker: auth failed sock=%d user=%s",
                (int)bc->sock,
            #ifdef WOLFMQTT_STATIC_MEMORY
                BrokerLog_Sanitize(bc->username[0] ? bc->username : "(null)"));
            #else
                BrokerLog_Sanitize((bc->username && bc->username[0])
                    ? bc->username : "(null)"));
            #endif
        #ifdef WOLFMQTT_V5
            if (mc.protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                ack.return_code = MQTT_REASON_BAD_USER_OR_PASS;
            }
            else
        #endif
            {
                ack.return_code =
                    MQTT_CONNECT_ACK_CODE_REFUSED_BAD_USER_PWD;
            }
            goto send_connack;
        }
    }
#endif /* WOLFMQTT_BROKER_AUTH */

    if (BROKER_STR_VALID(bc->client_id)) {
        BrokerClient* old;

        /* Cancel any pending will for this client_id (reconnect) */
        BrokerPendingWill_Cancel(broker, bc->client_id);

        old = BrokerClient_FindByClientId(broker, bc->client_id, bc);
        if (old != NULL) {
            WBLOG_INFO(broker, "broker: duplicate client_id=%s, disconnecting "
                "old sock=%d", BrokerLog_Sanitize(bc->client_id),
                (int)old->sock);
#ifdef ENABLE_MQTT_WEBSOCKET
            /* Guard old across its takeover fan-out: a re-entrant
             * LWS_CALLBACK_CLOSED for old's dropped socket must take the
             * deferred-remove path instead of freeing old mid-takeover, which
             * would UAF (BrokerSubs_RemoveClient) and double-free below. */
            if (old->ws_ctx != NULL) {
                ((BrokerWsCtx*)old->ws_ctx)->processing = 1;
            }
#endif
            /* Publish old client's will on takeover */
#ifdef WOLFMQTT_V5
            if (old->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                BrokerClient_PublishWill(broker, old);
            }
            else {
                BrokerSend_Disconnect(old,
                    MQTT_REASON_SESSION_TAKEN_OVER);
                BrokerClient_ClearWill(old);
            }
#else
            BrokerClient_PublishWill(broker, old);
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
            if (old->ws_ctx != NULL) {
                ((BrokerWsCtx*)old->ws_ctx)->processing = 0;
            }
#endif
            if (!mc.clean_session) {
                /* Reassociate old client's subs to new client */
                if (BrokerSubs_ReassociateClient(broker, bc->client_id, bc)
                    > 0) {
                    session_present = 1;
                }
            }
            BrokerSubs_RemoveClient(broker, old);
            BrokerClient_Remove(broker, old);
        }
        else if (!mc.clean_session) {
            /* No existing client, but check for orphaned subs from
             * a previous session (clean_session=0 reconnect) */
            if (BrokerSubs_ReassociateClient(broker, bc->client_id, bc)
                > 0) {
                session_present = 1;
            }
        }
        if (mc.clean_session) {
            /* Remove any remaining subs for this client_id */
            BrokerSubs_RemoveByClientId(broker, bc->client_id);
        #ifndef WOLFMQTT_STATIC_MEMORY
            {
                BrokerOrphanSession* o =
                    BrokerOrphan_Find(broker, bc->client_id);
                if (o != NULL) {
                    BrokerOrphan_Remove(broker, o);
                }
            }
        #endif
        }
    #ifndef WOLFMQTT_STATIC_MEMORY
        else {
            /* Persistent session reconnect: pick up any queued messages
             * left by the prior incarnation. Inherits session_expiry
             * from the orphan when this CONNECT did not specify one.
             * Drain is invoked further down, after CONNACK is sent. */
            if (BrokerOrphan_Reclaim(broker, bc)) {
                session_present = 1;
            }
        }
    #endif
    }

    /* Store Last Will and Testament */
    BrokerClient_ClearWill(bc);
#ifdef WOLFMQTT_BROKER_WILL
    if (mc.enable_lwt && mc.lwt_msg != NULL) {
        if (mc.lwt_msg->topic_name != NULL &&
            mc.lwt_msg->topic_name_len > 0) {
        #ifdef WOLFMQTT_STATIC_MEMORY
            if (mc.lwt_msg->topic_name_len >= BROKER_MAX_TOPIC_LEN) {
                WBLOG_ERR(broker,
                    "broker: LWT topic too long (%u >= %d) sock=%d",
                    (unsigned)mc.lwt_msg->topic_name_len,
                    BROKER_MAX_TOPIC_LEN, (int)bc->sock);
                ack.return_code =
                    MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL;
                goto send_connack;
            }
        #endif
            BROKER_STORE_STR(bc->will_topic, mc.lwt_msg->topic_name,
                mc.lwt_msg->topic_name_len, BROKER_MAX_TOPIC_LEN);
        }
        if (mc.lwt_msg->total_len > 0 && mc.lwt_msg->buffer != NULL) {
            word16 wp_len;
            if (mc.lwt_msg->total_len > BROKER_MAX_WILL_PAYLOAD_LEN) {
                WBLOG_ERR(broker,
                    "broker: LWT payload too large (%u > %d) sock=%d",
                    (unsigned)mc.lwt_msg->total_len,
                    BROKER_MAX_WILL_PAYLOAD_LEN, (int)bc->sock);
                ack.return_code =
                    MQTT_CONNECT_ACK_CODE_REFUSED_UNAVAIL;
                goto send_connack;
            }
            else {
                wp_len = (word16)mc.lwt_msg->total_len;
            }
#ifdef WOLFMQTT_STATIC_MEMORY
            XMEMCPY(bc->will_payload, mc.lwt_msg->buffer, wp_len);
#else
            bc->will_payload = (byte*)WOLFMQTT_MALLOC(wp_len);
            if (bc->will_payload != NULL) {
                XMEMCPY(bc->will_payload, mc.lwt_msg->buffer, wp_len);
            }
            else {
                wp_len = 0;
            }
#endif
            bc->will_payload_len = wp_len;
        }
        /* Clamp will QoS to this build's Maximum QoS. A v5 client that
         * sent Will QoS > advertised Max QoS would already be in
         * Protocol Error territory, but for v3.1.1 (no advertisement)
         * we silently downgrade rather than rejecting CONNECT. */
        bc->will_qos = (mc.lwt_msg->qos > WOLFMQTT_MAX_QOS) ?
            (MqttQoS)WOLFMQTT_MAX_QOS : mc.lwt_msg->qos;
        bc->will_retain = mc.lwt_msg->retain;
        bc->will_delay_sec = 0;
#ifdef WOLFMQTT_V5
        if (mc.lwt_msg->props != NULL) {
            MqttProp* prop = BrokerProps_Find(mc.lwt_msg->props,
                MQTT_PROP_WILL_DELAY_INTERVAL);
            if (prop != NULL) {
                /* Clamp to a sane maximum so a client advertising a huge
                 * delay (e.g. UINT32_MAX) cannot monopolize a pending-will
                 * slot indefinitely. */
                if (prop->data_int > BROKER_MAX_WILL_DELAY_SEC) {
                    bc->will_delay_sec = BROKER_MAX_WILL_DELAY_SEC;
                }
                else {
                    bc->will_delay_sec = prop->data_int;
                }
            }
        }
#endif
        bc->has_will = 1;
        WBLOG_DBG(broker, "broker: LWT stored sock=%d topic=%s qos=%d retain=%d "
            "len=%u delay=%u", (int)bc->sock, BrokerLog_Sanitize(bc->will_topic),
            bc->will_qos, bc->will_retain,
            (unsigned)bc->will_payload_len,
            (unsigned)bc->will_delay_sec);
    }
#endif /* WOLFMQTT_BROKER_WILL */

    /* Credentials were already validated above, before any session-state
     * mutation. [MQTT-3.2.2-2]: when the accepted CleanSession=0 connection
     * finds stored session state, Session Present MUST be 1; otherwise it
     * MUST be 0. The flag is cleared again below for any path that overrides
     * return_code to a non-zero refusal - [MQTT-3.2.2-4] requires Session
     * Present=0 on a refused CONNACK. */
    ack.flags = session_present ? MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT : 0;
    ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
#ifdef WOLFMQTT_V5
    ack.props = NULL;
#endif

#ifdef WOLFMQTT_V5
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
        ack.return_code == MQTT_CONNECT_ACK_CODE_ACCEPTED) {
        MqttProp* prop;

        /* [MQTT-3.1.3-6] Echo any server-assigned ClientId to v5 clients.
         * Keyed off auto_assigned (set in the auto-id branch above) so this
         * stays true to its name even if a future code path populates
         * bc->client_id from another source (e.g., a TLS-cert identity). */
        if (auto_assigned) {
            prop = MqttProps_Add(&ack.props);
            if (prop != NULL) {
                prop->type = MQTT_PROP_ASSIGNED_CLIENT_ID;
                prop->data_str.str = bc->client_id;
                prop->data_str.len = (word16)XSTRLEN(bc->client_id);
            }
        }

        /* Advertise feature availability */
        prop = MqttProps_Add(&ack.props);
        if (prop != NULL) {
            prop->type = MQTT_PROP_RETAIN_AVAIL;
    #ifdef WOLFMQTT_BROKER_RETAINED
            prop->data_byte = 1;
    #else
            prop->data_byte = 0;
    #endif
        }
        prop = MqttProps_Add(&ack.props);
        if (prop != NULL) {
            prop->type = MQTT_PROP_WILDCARD_SUB_AVAIL;
    #ifdef WOLFMQTT_BROKER_WILDCARDS
            prop->data_byte = 1;
    #else
            prop->data_byte = 0;
    #endif
        }
        /* [MQTT-3.2.2.3.4] Maximum QoS property MUST be 0 or 1. Absence
         * of the property signals server supports Maximum QoS 2. Emitting
         * Maximum QoS = 2 is a Protocol Error and strict v5 clients (e.g.
         * mosquitto) will disconnect on receipt. Emit the property only
         * when this build caps below QoS 2 via WOLFMQTT_MAX_QOS. */
    #if WOLFMQTT_MAX_QOS < 2
        prop = MqttProps_Add(&ack.props);
        if (prop != NULL) {
            prop->type = MQTT_PROP_MAX_QOS;
            prop->data_byte = (byte)WOLFMQTT_MAX_QOS;
        }
    #endif

        /* [MQTT-3.2.2.3.3] Receive Maximum. Advertise the broker's
         * per-client inbound QoS 1/2 cap so well-behaved publishers can
         * pace themselves. We accept up to BROKER_MAX_INBOUND_QOS2
         * concurrent QoS 2 PUBLISHes awaiting PUBREL ([MQTT-4.3.3]); use
         * the same number as the wire value. The property MUST NOT be
         * 0 - we skip the emission entirely in that (unreachable) case
         * so a future tunable down to 0 cannot send an illegal value.
         * The cap applies in both dynamic and static memory modes. */
        if (BROKER_MAX_INBOUND_QOS2 > 0) {
            prop = MqttProps_Add(&ack.props);
            if (prop != NULL) {
                prop->type = MQTT_PROP_RECEIVE_MAX;
                prop->data_short =
                    (BROKER_MAX_INBOUND_QOS2 > 0xFFFF) ?
                    (word16)0xFFFF :
                    (word16)BROKER_MAX_INBOUND_QOS2;
            }
        }
    }
#endif

send_connack:
    /* [MQTT-3.2.2-4] A refused CONNACK MUST have Session Present = 0. The
     * accepted path above already set Session Present from session_present;
     * this clear covers any goto-send_connack jump that overrode
     * return_code to a refusal after that point. */
    if (ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
        ack.flags = 0;
    }
    rc = MqttEncode_ConnectAck(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &ack);
    if (rc > 0) {
        WBLOG_INFO(broker, "broker: CONNACK send sock=%d code=%d", (int)bc->sock,
            ack.return_code);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }

#ifdef WOLFMQTT_V5
    if (ack.props) {
        (void)MqttProps_Free(ack.props);
    }
    if (mc.props) {
        (void)MqttProps_Free(mc.props);
    }
    if (lwt.props) {
        (void)MqttProps_Free(lwt.props);
    }
#endif

    /* Return 0 if auth rejected so caller can disconnect */
    if (ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
        return 0;
    }

#ifdef WOLFMQTT_BROKER_PERSIST
    /* Successful CONNECT with clean_session=0 -> shadow-write the
     * session record. Already-persisted sessions get overwritten with
     * their current protocol_level / client_id, which is harmless. The
     * persist layer no-ops when no hooks are installed. */
    if (!bc->clean_session && BROKER_STR_VALID(bc->client_id)) {
        (void)BrokerPersist_PutSession(broker, bc);
    }
#endif

#ifndef WOLFMQTT_STATIC_MEMORY
    /* If the reconnect inherited a non-empty queue from an orphan
     * session, drain it now so the subscriber sees the queued
     * messages on the heels of CONNACK. (BrokerOrphan_Reclaim already
     * moved entries into bc->out_q above; drain dispatches up to the
     * inflight cap as usual.) */
    if (bc->out_q_count > 0) {
        BrokerClient_DrainOutQueue(bc);
    }
#endif

    return rc;
}

static int BrokerHandle_Subscribe(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    int i;
    MqttSubscribe sub;
    MqttTopic topic_buf[MAX_MQTT_TOPICS];
    byte return_codes[MAX_MQTT_TOPICS];

    XMEMSET(&sub, 0, sizeof(sub));
#ifdef WOLFMQTT_V5
    sub.protocol_level = bc->protocol_level;
#endif
    XMEMSET(topic_buf, 0, sizeof(topic_buf));
    sub.topics = topic_buf;

    WBLOG_INFO(broker, "broker: SUBSCRIBE recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Subscribe(bc->rx_buf, rx_len, &sub);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: SUBSCRIBE decode failed rc=%d", rc);
        return rc;
    }

    /* Register subscriptions and build return codes */
    for (i = 0; i < sub.topic_count && i < MAX_MQTT_TOPICS; i++) {
        const char* f = sub.topics[i].topic_filter;
        word16 flen = 0;
        MqttQoS topic_qos = sub.topics[i].qos;
        MqttQoS granted_qos;

        /* [MQTT-3.8.4-7] / [MQTT-3.9.3]: subscribe grant capped at the
         * build's Maximum QoS. Default is QoS 2. */
        if (topic_qos > WOLFMQTT_MAX_QOS) {
            topic_qos = (MqttQoS)WOLFMQTT_MAX_QOS;
        }
        granted_qos = topic_qos;

        if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
                &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            int sub_rc = MQTT_CODE_SUCCESS;
            byte fail_code = MQTT_SUBSCRIBE_ACK_CODE_FAILURE;
        #ifndef WOLFMQTT_BROKER_WILDCARDS
            /* [MQTT-3.8.3-2] (v3.1.1 section 3.8.3): when the server does not
             * support wildcard subscriptions it MUST reject any
             * Subscription request whose filter contains a wildcard.
             * v5 section 3.2.2.3.20 advertises this via the Wildcard
             * Subscription Available property and section 3.9.3 reserves
             * reason code 0xA2 (Wildcard Subscriptions not supported)
             * specifically for this case - use it on v5 connections so
             * the client gets the actionable diagnostic the spec
             * defines. The decoder already validated Topic Filter
             * syntax via MqttPacket_TopicFilterValid, so any '#' or
             * '+' byte here is necessarily a real wildcard. */
            if (MqttPacket_TopicFilterIsWildcard(f, flen)) {
                sub_rc = MQTT_CODE_ERROR_BAD_ARG;
            #ifdef WOLFMQTT_V5
                if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                    fail_code = MQTT_REASON_WILDCARD_SUB_NOT_SUP;
                }
            #endif
            }
            if (sub_rc == MQTT_CODE_SUCCESS)
        #endif
            {
                sub_rc = BrokerSubs_Add(broker, bc, f, flen, topic_qos);
            }
            if (sub_rc != MQTT_CODE_SUCCESS) {
                granted_qos = (MqttQoS)fail_code;
            #ifdef WOLFMQTT_V5
                /* A capacity rejection (per-client cap or full table) maps to
                 * the v5 Quota Exceeded reason so the client sees why. */
                if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                    sub_rc == MQTT_CODE_ERROR_MEMORY) {
                    granted_qos = (MqttQoS)MQTT_REASON_QUOTA_EXCEEDED;
                }
            #endif
            }
#ifdef WOLFMQTT_BROKER_RETAINED
            else {
                /* Deliver retained messages matching this filter */
                char filter_z[BROKER_MAX_FILTER_LEN];
                word16 copy_len = flen;
                if (copy_len >= BROKER_MAX_FILTER_LEN) {
                    copy_len = BROKER_MAX_FILTER_LEN - 1;
                }
                XMEMCPY(filter_z, f, copy_len);
                filter_z[copy_len] = '\0';
                BrokerRetained_DeliverToClient(broker, bc, filter_z,
                    topic_qos);
            }
#endif
        }
        return_codes[i] = (byte)granted_qos;
    }

    /* Use i (capped at MAX_MQTT_TOPICS) instead of sub.topic_count to
     * avoid reading past the end of the return_codes array */
    rc = BrokerSend_SubAck(bc, sub.packet_id, return_codes, i);

#ifdef WOLFMQTT_BROKER_PERSIST
    /* Shadow-write the full subscription list for this client. Only
     * meaningful for clean_session=0 sessions; the persist layer no-ops
     * when no hooks are installed. */
    if (rc > 0 && !bc->clean_session && BROKER_STR_VALID(bc->client_id)) {
        (void)BrokerPersist_PutSubs(broker, bc->client_id);
    }
#endif

#ifdef WOLFMQTT_V5
    if (sub.props) {
        (void)MqttProps_Free(sub.props);
    }
#endif
    return rc;
}

static int BrokerHandle_Unsubscribe(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    int i;
    MqttUnsubscribe unsub;
    MqttUnsubscribeAck ack;
    MqttTopic topic_buf[MAX_MQTT_TOPICS];
#ifdef WOLFMQTT_V5
    byte reasons[MAX_MQTT_TOPICS];
#endif

    XMEMSET(&unsub, 0, sizeof(unsub));
#ifdef WOLFMQTT_V5
    unsub.protocol_level = bc->protocol_level;
#endif
    XMEMSET(topic_buf, 0, sizeof(topic_buf));
    unsub.topics = topic_buf;

    WBLOG_INFO(broker, "broker: UNSUBSCRIBE recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Unsubscribe(bc->rx_buf, rx_len, &unsub);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: UNSUBSCRIBE decode failed rc=%d", rc);
        return rc;
    }

    /* Remove subscriptions and populate reason codes */
    for (i = 0; i < unsub.topic_count && i < MAX_MQTT_TOPICS; i++) {
        const char* f = unsub.topics[i].topic_filter;
        word16 flen = 0;
        if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
                &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
            BrokerSubs_Remove(broker, bc, f, flen);
        }
#ifdef WOLFMQTT_V5
        reasons[i] = MQTT_REASON_SUCCESS;
#endif
    }

    XMEMSET(&ack, 0, sizeof(ack));
    ack.packet_id = unsub.packet_id;
#ifdef WOLFMQTT_V5
    ack.protocol_level = bc->protocol_level;
    ack.props = NULL;
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        ack.reason_codes = reasons;
        ack.reason_code_count = (word16)unsub.topic_count;
    }
    else {
        ack.reason_codes = NULL;
        ack.reason_code_count = 0;
    }
#endif
    rc = MqttEncode_UnsubscribeAck(bc->tx_buf,
            BROKER_CLIENT_TX_SZ(bc), &ack);
    if (rc > 0) {
        WBLOG_INFO(broker, "broker: UNSUBACK send sock=%d packet_id=%u",
            (int)bc->sock, ack.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }

#ifdef WOLFMQTT_BROKER_PERSIST
    /* Re-snapshot subs (PutSubs converts count=0 into a DelSubs). */
    if (rc > 0 && !bc->clean_session && BROKER_STR_VALID(bc->client_id)) {
        (void)BrokerPersist_PutSubs(broker, bc->client_id);
    }
#endif

#ifdef WOLFMQTT_V5
    if (unsub.props) {
        (void)MqttProps_Free(unsub.props);
    }
#endif
    return rc;
}

static int BrokerHandle_Publish(BrokerClient* bc, int rx_len,
    MqttBroker* broker)
{
    int rc;
    MqttPublish pub;
    MqttPublishResp resp;
    byte* payload = NULL;
    char* topic = NULL;
#if WOLFMQTT_MAX_QOS >= 2
    int qos2_duplicate = 0;
#endif
#ifdef WOLFMQTT_STATIC_MEMORY
    char topic_buf[BROKER_MAX_TOPIC_LEN];
#endif

    XMEMSET(&pub, 0, sizeof(pub));
#ifdef WOLFMQTT_V5
    pub.protocol_level = bc->protocol_level;
#endif
    WBLOG_DBG(broker, "broker: PUBLISH recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_Publish(bc->rx_buf, rx_len, &pub);
    if (rc < 0) {
        WBLOG_ERR(broker, "broker: PUBLISH decode failed rc=%d", rc);
        return rc;
    }

#ifdef WOLFMQTT_V5
    /* [MQTT-3.3.4-6] A PUBLISH sent from a client to the server MUST NOT carry
     * a Subscription Identifier; reject as a Protocol Error instead of
     * forwarding the foreign id to subscribers. */
    if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
            pub.props != NULL &&
            BrokerProps_Find(pub.props, MQTT_PROP_SUBSCRIPTION_ID) != NULL) {
        WBLOG_ERR(broker, "broker: client PUBLISH carried SUBSCRIPTION_ID "
            "sock=%d", (int)bc->sock);
        (void)BrokerSend_Disconnect(bc, MQTT_REASON_PROTOCOL_ERR);
        rc = MQTT_CODE_ERROR_MALFORMED_DATA;
        goto publish_cleanup;
    }
#endif

    /* The decoder only captured pub.buffer_len bytes of the payload; if that is
     * short of the declared pub.total_len the message exceeded the broker
     * receive buffer. Reject it rather than fanning out a packet whose
     * Remaining Length overstates the bytes we actually hold. */
    if (pub.total_len > 0 && pub.buffer_len < pub.total_len) {
        WBLOG_ERR(broker,
            "broker: PUBLISH payload exceeds buffer (have %u of %u) sock=%d",
            (unsigned)pub.buffer_len, (unsigned)pub.total_len, (int)bc->sock);
        rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
        goto publish_cleanup;
    }

    /* [MQTT-3.3.2-2] PUBLISH topic name wildcard / [MQTT-4.7.3-1]
     * empty-topic checks now live in MqttDecode_Publish via
     * MqttPacket_TopicNameValid, which has already returned
     * MALFORMED_DATA before reaching this handler. The broker no longer
     * needs a per-handler scan. */

#if WOLFMQTT_MAX_QOS < 2
    /* [MQTT-3.2.2.3.4] / [MQTT-3.3.4]: this build advertised Maximum QoS
     * below 2. A client publishing at QoS > our cap is a Protocol Error;
     * v5 spec wants reason 0x9B QoS Not Supported. v3 has no reason code
     * field, so we just abnormally close. */
    if (pub.qos > WOLFMQTT_MAX_QOS) {
        WBLOG_ERR(broker,
            "broker: PUBLISH QoS %d exceeds WOLFMQTT_MAX_QOS=%d sock=%d",
            pub.qos, WOLFMQTT_MAX_QOS, (int)bc->sock);
    #ifdef WOLFMQTT_V5
        if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
            (void)BrokerSend_Disconnect(bc, MQTT_REASON_QOS_NOT_SUPPORTED);
        }
    #endif
        rc = MQTT_CODE_ERROR_MALFORMED_DATA;
        goto publish_cleanup;
    }
#endif /* WOLFMQTT_MAX_QOS < 2 */

#if WOLFMQTT_MAX_QOS >= 2
    /* [MQTT-4.3.3] QoS 2 duplicate detection. If we already PUBREC'd this
     * packet_id and are still waiting for PUBREL, treat the inbound PUBLISH
     * as a retransmission: send another PUBREC but DO NOT re-deliver the
     * application message to subscribers and DO NOT re-store the retained
     * payload. */
    if (pub.qos == MQTT_QOS_2) {
        if (BrokerInboundQos2_Contains(bc, pub.packet_id)) {
            WBLOG_DBG(broker,
                "broker: QoS2 duplicate PUBLISH sock=%d packet_id=%u "
                "[MQTT-4.3.3]", (int)bc->sock, pub.packet_id);
            qos2_duplicate = 1;
        }
        else {
            int add_rc = BrokerInboundQos2_Add(bc, pub.packet_id);
            if (add_rc != MQTT_CODE_SUCCESS) {
                /* Distinguish per-client cap reached (OUT_OF_BUFFER) from
                 * allocator failure (MEMORY) so v5 clients get an
                 * accurate DISCONNECT reason code, and propagate the
                 * underlying rc rather than masking it as MALFORMED_DATA
                 * - server-side resource exhaustion is not a wire-level
                 * protocol violation. The dispatch's BrokerRcIsFatal
                 * gate recognizes both codes and closes the connection. */
                WBLOG_ERR(broker,
                    "broker: QoS2 inbound add failed sock=%d packet_id=%u "
                    "rc=%d", (int)bc->sock, pub.packet_id, add_rc);
            #ifdef WOLFMQTT_V5
                if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                    byte reason = (add_rc == MQTT_CODE_ERROR_OUT_OF_BUFFER)
                        ? MQTT_REASON_QUOTA_EXCEEDED
                        : MQTT_REASON_SERVER_BUSY;
                    (void)BrokerSend_Disconnect(bc, reason);
                }
            #endif
                rc = add_rc;
                goto publish_cleanup;
            }
        }
    }
#endif /* WOLFMQTT_MAX_QOS >= 2 */

    /* Create null-terminated topic copy for matching/logging */
    if (pub.topic_name && pub.topic_name_len > 0) {
#ifdef WOLFMQTT_STATIC_MEMORY
        word16 tlen = pub.topic_name_len;
        if (tlen >= BROKER_MAX_TOPIC_LEN) {
            /* Reject rather than truncate: a truncated topic can match a
             * different subscriber filter than the wire topic (filter/auth
             * bypass) and collide retained-message keys. */
            WBLOG_ERR(broker,
                "broker: PUBLISH topic too long len=%u max=%d sock=%d",
                (unsigned)tlen, BROKER_MAX_TOPIC_LEN, (int)bc->sock);
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
            goto publish_cleanup;
        }
        XMEMCPY(topic_buf, pub.topic_name, tlen);
        topic_buf[tlen] = '\0';
        topic = topic_buf;
#else
        topic = (char*)WOLFMQTT_MALLOC(pub.topic_name_len + 1);
        if (topic == NULL) {
            /* Without the topic copy, retained-store and fan-out are skipped;
             * returning here prevents the QoS 1/2 ACK encoder below from
             * falsely reporting SUCCESS for a message that was never
             * delivered. */
            WBLOG_ERR(broker, "broker: PUBLISH topic alloc failed sock=%d",
                (int)bc->sock);
            rc = MQTT_CODE_ERROR_MEMORY;
            goto publish_cleanup;
        }
        XMEMCPY(topic, pub.topic_name, pub.topic_name_len);
        topic[pub.topic_name_len] = '\0';
#endif
    }
    /* Use payload pointer directly from decoded packet - rx_buf is not
     * modified during fan-out (each subscriber encodes into their own
     * tx_buf), so this pointer remains valid throughout. */
    payload = pub.buffer;

#ifdef WOLFMQTT_BROKER_RETAINED
    /* Handle retained messages - skipped for QoS 2 duplicates: the original
     * PUBLISH already updated the retained store. */
    if (
    #if WOLFMQTT_MAX_QOS >= 2
        !qos2_duplicate &&
    #endif
        topic != NULL && pub.retain) {
        if (pub.total_len == 0) {
            BrokerRetained_Delete(broker, topic);
        }
        else if (payload != NULL) {
            word32 expiry = 0;
#ifdef WOLFMQTT_V5
            if (pub.props != NULL) {
                MqttProp* prop = BrokerProps_Find(pub.props,
                    MQTT_PROP_MSG_EXPIRY_INTERVAL);
                if (prop != NULL) {
                    expiry = prop->data_int;
                }
            }
#endif
            {
                int ret_rc = BrokerRetained_Store(broker, topic, payload,
                    pub.total_len, pub.qos, expiry);
                if (ret_rc != MQTT_CODE_SUCCESS) {
                    WBLOG_ERR(broker, "Retained store failed: %s",
                        MqttClient_ReturnCodeToString(ret_rc));
                }
            }
        }
    }
#endif /* WOLFMQTT_BROKER_RETAINED */

    /* Fan-out is skipped for QoS 2 duplicates: subscribers already received
     * the application message from the original PUBLISH ([MQTT-4.3.3]). */
    if (
    #if WOLFMQTT_MAX_QOS >= 2
        !qos2_duplicate &&
    #endif
        topic != NULL && (payload != NULL || pub.total_len == 0)) {
#ifdef WOLFMQTT_STATIC_MEMORY
        int i;
#else
        BrokerSub* sub = broker->subs;
        BrokerSub* next_sub = NULL;
#endif
        /* Fan out to matching subscribers */
#ifdef WOLFMQTT_STATIC_MEMORY
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            BrokerSub* sub = &broker->subs[i];
            if (!sub->in_use) continue;
#else
        while (sub) {
            /* Snapshot the successor before any MqttPacket_Write: a fan-out
             * write can drive an lws_service spin that frees this client's
             * BrokerSub nodes re-entrantly (LWS_CALLBACK_CLOSED), so reading
             * sub->next afterwards would dereference a freed node. */
            next_sub = sub->next;
#endif
            if (sub->client != NULL &&
                sub->client->protocol_level != 0 &&
                sub->client->sock != BROKER_SOCKET_INVALID &&
                BROKER_STR_VALID(sub->filter) &&
                BrokerTopicMatch(sub->filter, topic)) {
                MqttQoS eff_qos;
                eff_qos = (pub.qos < sub->qos) ? pub.qos : sub->qos;
#ifdef WOLFMQTT_STATIC_MEMORY
                /* Static-memory mode keeps the legacy synchronous
                 * fan-out: no per-subscriber queue, no inflight cap.
                 * Sub-encoder failure is logged but not propagated. */
                {
                    int sub_rc;
                    int wr;
                    MqttPublish out_pub;
                    XMEMSET(&out_pub, 0, sizeof(out_pub));
                    out_pub.topic_name = topic;
                    out_pub.qos = eff_qos;
                    if (eff_qos >= MQTT_QOS_1) {
                        out_pub.packet_id = BrokerNextPacketId(broker);
                    }
                    out_pub.retain = 0;
                    out_pub.duplicate = 0;
                    out_pub.buffer = payload;
                    out_pub.total_len = pub.total_len;
                    out_pub.buffer_len = pub.buffer_len;
                #ifdef WOLFMQTT_V5
                    out_pub.protocol_level = sub->client->protocol_level;
                    if (sub->client->protocol_level >=
                        MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                        out_pub.props = pub.props;
                    }
                #endif
                    sub_rc = MqttEncode_Publish(sub->client->tx_buf,
                            BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
                    if (sub_rc > 0) {
                        WBLOG_DBG(broker,
                            "broker: PUBLISH fwd sock=%d -> sock=%d "
                            "topic=%s qos=%d len=%u",
                            (int)bc->sock, (int)sub->client->sock,
                            BrokerLog_Sanitize(topic), eff_qos,
                            (unsigned)pub.total_len);
                        wr = MqttPacket_Write(&sub->client->client,
                            sub->client->tx_buf, sub_rc);
                        /* Static fan-out has no per-subscriber resume queue, so
                         * a partial write leaves this subscriber's stream
                         * desynced and unrecoverable. Tear down its socket; the
                         * main loop reaps it on the next read error. The match
                         * guard above then skips this client's other matching
                         * subscriptions once its socket is invalidated. */
                        if (wr != sub_rc &&
                            sub->client->sock != BROKER_SOCKET_INVALID) {
                            broker->net.close(broker->net.ctx,
                                sub->client->sock);
                            sub->client->sock = BROKER_SOCKET_INVALID;
                            sub->client->connected = 0;
                        }
                    }
                    else {
                        WBLOG_ERR(broker,
                            "broker: PUBLISH fwd encode failed "
                            "sock=%d -> sock=%d rc=%d",
                            (int)bc->sock, (int)sub->client->sock, sub_rc);
                    }
                }
#else
                /* Dynamic mode: enqueue a heap-owned copy on the
                 * subscriber's out_q, then drain. The queue gives us
                 * the inflight cap (#7 ordered delivery) and is the
                 * substrate for the offline queue in PR2. Invariant:
                 * MqttDecode_Publish above has populated pub.buffer
                 * with at least pub.total_len contiguous bytes (full
                 * PUBLISH is fully received and decoded before we
                 * reach the fan-out); BrokerOutPub_Alloc deep-copies
                 * pub.total_len from that buffer. */
                {
                    BrokerOutPub* e = BrokerOutPub_Alloc(topic, payload,
                                          pub.total_len);
                    if (e == NULL) {
                        WBLOG_ERR(broker,
                            "broker: PUBLISH fwd alloc failed sock=%d "
                            "-> sock=%d", (int)bc->sock,
                            (int)sub->client->sock);
                    }
                    else {
                        e->qos = eff_qos;
                        if (eff_qos >= MQTT_QOS_1) {
                            e->packet_id = BrokerNextPacketId(broker);
                        }
                        e->retain = 0;
                        e->state = BROKER_OUTQ_QUEUED;
                    #ifdef WOLFMQTT_V5
                        e->protocol_level = sub->client->protocol_level;
                    #endif
                        BrokerClient_EnqueueOutPub(sub->client, e);
                        WBLOG_DBG(broker,
                            "broker: PUBLISH enq sock=%d -> sock=%d "
                            "topic=%s qos=%d len=%u",
                            (int)bc->sock, (int)sub->client->sock,
                            BrokerLog_Sanitize(topic), eff_qos,
                            (unsigned)pub.total_len);
                        BrokerClient_DrainOutQueue(sub->client);
                    }
                }
#endif
            }
#ifndef WOLFMQTT_STATIC_MEMORY
            /* Note on iteration model: static-mode walks the BrokerSub
             * array via for (i=0; i<BROKER_MAX_SUBS; i++) and gets its
             * advance from i++. Dynamic-mode walks the linked list and
             * needs an explicit sub = sub->next below. The orphan
             * branch (sub->client == NULL) only exists in dynamic mode -
             * static-mode orphan handling lives in the restore path. */
            else if (sub->client == NULL && sub->client_id != NULL &&
                     BROKER_STR_VALID(sub->filter) &&
                     BrokerTopicMatch(sub->filter, topic)) {
                /* Orphaned persistent session: subscriber is currently
                 * disconnected. Queue QoS 1/2 messages on the orphan
                 * slot for delivery on reconnect. */
                MqttQoS eff_qos =
                    (pub.qos < sub->qos) ? pub.qos : sub->qos;
                if (eff_qos > MQTT_QOS_0) {
                    BrokerOrphanSession* o =
                        BrokerOrphan_Find(broker, sub->client_id);
                    if (o != NULL) {
                        BrokerOrphan_Enqueue(broker, o, topic, payload,
                            pub.total_len, eff_qos, 0);
                    }
                }
            }
            sub = next_sub;
#endif
        }
    }

    if (pub.qos == MQTT_QOS_1 || pub.qos == MQTT_QOS_2) {
        XMEMSET(&resp, 0, sizeof(resp));
        resp.packet_id = pub.packet_id;
#ifdef WOLFMQTT_V5
        resp.protocol_level = bc->protocol_level;
        resp.reason_code = MQTT_REASON_SUCCESS;
        resp.props = NULL;
#endif
        rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
                (pub.qos == MQTT_QOS_1) ? MQTT_PACKET_TYPE_PUBLISH_ACK :
                MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
        if (rc > 0) {
            WBLOG_DBG(broker, "broker: PUBRESP send sock=%d qos=%d packet_id=%u",
                (int)bc->sock, pub.qos, pub.packet_id);
            rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
        }
    }

publish_cleanup:
#ifdef WOLFMQTT_V5
    if (pub.props) {
        (void)MqttProps_Free(pub.props);
    }
#endif
#ifndef WOLFMQTT_STATIC_MEMORY
    if (topic) {
        WOLFMQTT_FREE(topic);
    }
#endif

    return rc;
}

#if WOLFMQTT_MAX_QOS >= 2
static int BrokerHandle_PublishRel(BrokerClient* bc, int rx_len)
{
    int rc;
    MqttPublishResp resp;

    XMEMSET(&resp, 0, sizeof(resp));
#ifdef WOLFMQTT_V5
    resp.protocol_level = bc->protocol_level;
#endif
    WBLOG_DBG(bc->broker, "broker: PUBLISH_REL recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
            MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    if (rc < 0) {
        WBLOG_ERR(bc->broker, "broker: PUBLISH_REL decode failed rc=%d", rc);
        return rc;
    }

    /* [MQTT-4.3.3] QoS 2 step 3: discard the stored Packet Identifier so a
     * later PUBLISH with the same ID is treated as a fresh delivery. PUBREL
     * for an unknown ID is idempotent - we still PUBCOMP it. */
    BrokerInboundQos2_Remove(bc, resp.packet_id);

#ifdef WOLFMQTT_V5
    if (resp.props) {
        (void)MqttProps_Free(resp.props);
    }
    resp.reason_code = MQTT_REASON_SUCCESS;
    resp.props = NULL;
#endif
    rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
            MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
    if (rc > 0) {
        WBLOG_DBG(bc->broker, "broker: PUBCOMP send sock=%d packet_id=%u",
            (int)bc->sock, resp.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }
    return rc;
}

/* Handle PUBREC from subscriber: broker sent QoS 2 PUBLISH, subscriber
 * responds with PUBREC, broker sends PUBREL */
static int BrokerHandle_PublishRec(BrokerClient* bc, int rx_len)
{
    int rc;
    MqttPublishResp resp;

    XMEMSET(&resp, 0, sizeof(resp));
#ifdef WOLFMQTT_V5
    resp.protocol_level = bc->protocol_level;
#endif
    WBLOG_DBG(bc->broker, "broker: PUBLISH_REC recv sock=%d len=%d", (int)bc->sock, rx_len);
    rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
            MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
    if (rc < 0) {
        WBLOG_ERR(bc->broker, "broker: PUBLISH_REC decode failed rc=%d", rc);
        return rc;
    }

#ifndef WOLFMQTT_STATIC_MEMORY
    /* Advance the out_q entry from PUBLISH_SENT to PUBREL_SENT. The
     * PUBREL we send below is correlated to this entry; PUBCOMP from the
     * subscriber will then close it out. A spurious PUBREC (no matching
     * entry) still gets a PUBREL response for idempotency, just no
     * queue state change. */
    (void)BrokerClient_OnPubRec(bc, resp.packet_id);
#endif

#ifdef WOLFMQTT_V5
    if (resp.props) {
        (void)MqttProps_Free(resp.props);
    }
    resp.reason_code = MQTT_REASON_SUCCESS;
    resp.props = NULL;
#endif
    rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
            MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
    if (rc > 0) {
        WBLOG_DBG(bc->broker, "broker: PUBREL send sock=%d packet_id=%u",
            (int)bc->sock, resp.packet_id);
        rc = MqttPacket_Write(&bc->client, bc->tx_buf, rc);
    }
    return rc;
}
#endif /* WOLFMQTT_MAX_QOS >= 2 */

/* [MQTT-2.2.2-2] / [MQTT-3.8.1-1] etc.: a malformed packet MUST cause the
 * server to close the network connection. Mirrors the read-failure close
 * path: publish will, honor session persistence, then remove the client. */
static void BrokerClient_AbnormalClose(MqttBroker* broker, BrokerClient* bc)
{
    BrokerClient_PublishWill(broker, bc);
    if (bc->clean_session) {
        BrokerSubs_RemoveClient(broker, bc);
    }
    else {
        BrokerSubs_OrphanClient(broker, bc);
    }
    BrokerClient_Remove(broker, bc);
}

/* Returns non-zero for return codes that require the broker to close the
 * client connection. Includes:
 *   - Wire-level decode errors (malformed packet, wrong packet type).
 *   - Packet ID violations: [MQTT-2.3.1-1] requires a non-zero Packet
 *     Identifier on QoS>0 PUBLISH and on every SUBSCRIBE/UNSUBSCRIBE;
 *     decoders return MQTT_CODE_ERROR_PACKET_ID for packet_id == 0, and
 *     [MQTT-4.13]/[MQTT-4.8.0-1] mandate connection close on malformed
 *     packets.
 *   - Server-side resource exhaustion (allocator failure, per-client cap
 *     reached) - the connection must be torn down so resources release. */
static int BrokerRcIsFatal(int rc)
{
    return (rc == MQTT_CODE_ERROR_MALFORMED_DATA ||
            rc == MQTT_CODE_ERROR_PACKET_TYPE ||
            rc == MQTT_CODE_ERROR_PACKET_ID ||
            rc == MQTT_CODE_ERROR_MEMORY ||
            rc == MQTT_CODE_ERROR_OUT_OF_BUFFER);
}

/* -------------------------------------------------------------------------- */
/* Per-client processing (called from Step)                                    */
/* -------------------------------------------------------------------------- */
static int BrokerClient_Process(MqttBroker* broker, BrokerClient* bc)
{
    int rc;
    int activity = 0;

#ifdef ENABLE_MQTT_TLS
    /* Complete TLS handshake before processing MQTT packets */
    if (!bc->tls_handshake_done) {
        int ret;
        bc->client.tls.timeout_ms_read = BROKER_TIMEOUT_MS;
        bc->client.tls.timeout_ms_write = BROKER_TIMEOUT_MS;
        ret = wolfSSL_accept(bc->client.tls.ssl);
        if (ret == WOLFSSL_SUCCESS) {
            bc->tls_handshake_done = 1;
            WBLOG_INFO(broker, "broker: TLS handshake done sock=%d %s",
                (int)bc->sock, wolfSSL_get_version(bc->client.tls.ssl));
            /* Log client certificate CN if mutual TLS.
             * Requires wolfSSL built with KEEP_PEER_CERT or similar. */
        #if defined(KEEP_PEER_CERT) || defined(OPENSSL_EXTRA) || \
            defined(OPENSSL_EXTRA_X509_SMALL) || defined(SESSION_CERTS)
            if (broker->tls_ca != NULL) {
                WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(
                    bc->client.tls.ssl);
                if (peer != NULL) {
                    char* cn = wolfSSL_X509_get_subjectCN(peer);
                    (void)cn; /* may be unused if logging disabled */
                    WBLOG_INFO(broker, "broker: TLS client cert sock=%d CN=%s",
                        (int)bc->sock,
                        BrokerLog_Sanitize(cn ? cn : "(unknown)"));
                    wolfSSL_X509_free(peer);
                }
            }
        #endif
            return 1; /* activity */
        }
        else {
            int err = wolfSSL_get_error(bc->client.tls.ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE) {
                return 0; /* handshake in progress */
            }
            WBLOG_ERR(broker, "broker: TLS handshake failed sock=%d err=%d",
                (int)bc->sock, err);
            BrokerSubs_RemoveClient(broker, bc);
            BrokerClient_Remove(broker, bc);
            return 0;
        }
    }
#endif /* ENABLE_MQTT_TLS */

    /* Try non-blocking read (timeout=0) */
    rc = MqttPacket_Read(&bc->client, bc->rx_buf, BROKER_CLIENT_RX_SZ(bc), 0);

    if (rc == MQTT_CODE_ERROR_TIMEOUT || rc == MQTT_CODE_CONTINUE) {
        /* No data available - not an error */
        rc = 0;
    }
    else if (rc < 0) {
        WBLOG_ERR(broker, "broker: read failed sock=%d rc=%d", (int)bc->sock, rc);
        BrokerClient_AbnormalClose(broker, bc);
        return 0;
    }

    if (rc > 0) {
        byte type = MQTT_PACKET_TYPE_GET(bc->rx_buf[0]);
        bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();
        activity = 1;
        WBLOG_DBG(broker, "broker: packet sock=%d type=%u len=%d",
            (int)bc->sock, type, rc);
#ifdef ENABLE_MQTT_WEBSOCKET
        if (bc->ws_ctx != NULL) {
            ((BrokerWsCtx*)bc->ws_ctx)->processing = 1;
        }
#endif
        /* [MQTT-2.2.2-2] Reject malformed fixed-header reserved flags. The
         * per-type decoders also enforce this (see MqttDecode_FixedHeader),
         * but PUBACK / PUBCOMP / PINGREQ / DISCONNECT are not run through a
         * decoder here, so the broker enforces it directly before dispatch. */
        if (!MqttPacket_FixedHeaderFlagsValid(bc->rx_buf[0])) {
            WBLOG_ERR(broker,
                "broker: invalid fixed-header flags type=%u byte=0x%02X "
                "sock=%d [MQTT-2.2.2-2]",
                type, bc->rx_buf[0], (int)bc->sock);
            if (bc->connected) {
                BrokerClient_AbnormalClose(broker, bc);
            }
            else {
                BrokerSubs_RemoveClient(broker, bc);
                BrokerClient_Remove(broker, bc);
            }
            return 0;
        }
        /* [MQTT-3.1.0-1] First packet must be CONNECT */
        if (type != MQTT_PACKET_TYPE_CONNECT && !bc->connected) {
            WBLOG_ERR(broker,
                "broker: packet type %u before CONNECT sock=%d",
                type, (int)bc->sock);
            BrokerSubs_RemoveClient(broker, bc);
            BrokerClient_Remove(broker, bc);
            return 0;
        }
        /* [MQTT-3.1.0-2] Second CONNECT is a protocol violation */
        if (type == MQTT_PACKET_TYPE_CONNECT && bc->connected) {
            WBLOG_ERR(broker,
                "broker: second CONNECT on sock=%d [MQTT-3.1.0-2]",
                (int)bc->sock);
            BrokerSubs_RemoveClient(broker, bc);
            BrokerClient_Remove(broker, bc);
            return 0;
        }
        switch (type) {
            case MQTT_PACKET_TYPE_CONNECT:
            {
                int c_rc = BrokerHandle_Connect(bc, rc, broker);
                if (c_rc <= 0) {
                    /* Decode failed or auth rejected, disconnect */
                    BrokerSubs_RemoveClient(broker, bc);
                    BrokerClient_Remove(broker, bc);
                    return 0;
                }
                bc->connected = 1;
                break;
            }
            case MQTT_PACKET_TYPE_PUBLISH:
            {
                int p_rc = BrokerHandle_Publish(bc, rc, broker);
                if (BrokerRcIsFatal(p_rc)) {
                    BrokerClient_AbnormalClose(broker, bc);
                    return 0;
                }
                break;
            }
            case MQTT_PACKET_TYPE_PUBLISH_ACK:
                /* QoS 1 ack from subscriber - delivery complete. In
                 * dynamic-memory mode, locate the matching out_q entry,
                 * unlink/free it, decrement inflight, and drain. */
#ifndef WOLFMQTT_STATIC_MEMORY
            {
                MqttPublishResp ack_resp;
                XMEMSET(&ack_resp, 0, sizeof(ack_resp));
            #ifdef WOLFMQTT_V5
                ack_resp.protocol_level = bc->protocol_level;
            #endif
                if (MqttDecode_PublishResp(bc->rx_buf, rc,
                        MQTT_PACKET_TYPE_PUBLISH_ACK, &ack_resp) >= 0) {
                    BrokerClient_OnPubAck(bc, ack_resp.packet_id);
                }
            #ifdef WOLFMQTT_V5
                if (ack_resp.props) {
                    (void)MqttProps_Free(ack_resp.props);
                }
            #endif
            }
#endif
                break;
        #if WOLFMQTT_MAX_QOS >= 2
            case MQTT_PACKET_TYPE_PUBLISH_REC:
            {
                /* QoS 2 step 2: subscriber sends PUBREC, broker
                 * responds with PUBREL */
                int p_rc = BrokerHandle_PublishRec(bc, rc);
                if (BrokerRcIsFatal(p_rc)) {
                    BrokerClient_AbnormalClose(broker, bc);
                    return 0;
                }
                break;
            }
            case MQTT_PACKET_TYPE_PUBLISH_REL:
            {
                /* QoS 2 step 3: publisher sends PUBREL, broker
                 * responds with PUBCOMP */
                int p_rc = BrokerHandle_PublishRel(bc, rc);
                if (BrokerRcIsFatal(p_rc)) {
                    BrokerClient_AbnormalClose(broker, bc);
                    return 0;
                }
                break;
            }
            case MQTT_PACKET_TYPE_PUBLISH_COMP:
                /* QoS 2 step 4: subscriber sends PUBCOMP - delivery
                 * complete. Remove the matching out_q entry (state
                 * PUBREL_SENT), decrement inflight, drain. */
#ifndef WOLFMQTT_STATIC_MEMORY
            {
                MqttPublishResp comp_resp;
                XMEMSET(&comp_resp, 0, sizeof(comp_resp));
            #ifdef WOLFMQTT_V5
                comp_resp.protocol_level = bc->protocol_level;
            #endif
                if (MqttDecode_PublishResp(bc->rx_buf, rc,
                        MQTT_PACKET_TYPE_PUBLISH_COMP, &comp_resp) >= 0) {
                    BrokerClient_OnPubComp(bc, comp_resp.packet_id);
                }
            #ifdef WOLFMQTT_V5
                if (comp_resp.props) {
                    (void)MqttProps_Free(comp_resp.props);
                }
            #endif
            }
#endif
                break;
        #endif /* WOLFMQTT_MAX_QOS >= 2 */
            case MQTT_PACKET_TYPE_SUBSCRIBE:
            {
                int s_rc = BrokerHandle_Subscribe(bc, rc, broker);
                if (BrokerRcIsFatal(s_rc)) {
                    BrokerClient_AbnormalClose(broker, bc);
                    return 0;
                }
                break;
            }
            case MQTT_PACKET_TYPE_UNSUBSCRIBE:
            {
                int u_rc = BrokerHandle_Unsubscribe(bc, rc, broker);
                if (BrokerRcIsFatal(u_rc)) {
                    BrokerClient_AbnormalClose(broker, bc);
                    return 0;
                }
                break;
            }
            case MQTT_PACKET_TYPE_PING_REQ:
                /* MQTT 3.1.1 section 3.12 / v5 section 3.12: PINGREQ is fixed-header-
                 * only - Remaining Length MUST be 0. Reject malformed
                 * PINGREQ before sending PINGRESP. */
                if (bc->client.packet.remain_len != 0) {
                    BrokerClient_AbnormalClose(broker, bc);
                    return 0;
                }
                (void)BrokerSend_PingResp(bc);
                break;
            case MQTT_PACKET_TYPE_DISCONNECT:
                /* MQTT 3.1.1 section 3.14: DISCONNECT has no variable header and
                 * no payload - Remaining Length MUST be 0. v5 section 3.14
                 * relaxes this to allow an optional Reason Code and
                 * Properties, so the check is gated on protocol level. */
            #ifdef WOLFMQTT_V5
                if (bc->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                    bc->client.packet.remain_len != 0) {
            #else
                if (bc->client.packet.remain_len != 0) {
            #endif
                    BrokerClient_AbnormalClose(broker, bc);
                    return 0;
                }
            #if defined(WOLFMQTT_V5) && defined(WOLFMQTT_BROKER_WILL)
                /* [MQTT-3.14.4-3] A v5 DISCONNECT with Reason Code 0x04
                 * (Disconnect with Will Message) asks the broker to publish
                 * the Will rather than discard it. */
                if (bc->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                        bc->client.packet.remain_len > 0) {
                    MqttDisconnect disc;
                    XMEMSET(&disc, 0, sizeof(disc));
                    disc.protocol_level = bc->protocol_level;
                    if (MqttDecode_Disconnect(bc->rx_buf, rc, &disc) >= 0 &&
                            disc.reason_code ==
                                MQTT_REASON_DISCONNECT_W_WILL_MSG) {
                        BrokerClient_PublishWill(broker, bc);
                    }
                    else {
                        BrokerClient_ClearWill(bc);
                    }
                    /* Free any decoded v5 DISCONNECT properties. */
                    if (disc.props != NULL) {
                        (void)MqttProps_Free(disc.props);
                    }
                }
                else
            #endif
                BrokerClient_ClearWill(bc); /* normal disconnect */
                /* Session persistence: keep subs if clean_session=0 */
                if (bc->clean_session) {
                    BrokerSubs_RemoveClient(broker, bc);
                }
                else {
                    BrokerSubs_OrphanClient(broker, bc);
                }
                BrokerClient_Remove(broker, bc);
                return 0;
            default:
                /* Unhandled packet type for this broker. Catches v3.1.1
                 * clients sending AUTH (type 15, defined only in v5),
                 * v5 clients sending AUTH (this broker does not
                 * implement enhanced authentication), and any other
                 * type the dispatch above does not recognize. The
                 * pre-dispatch flag check rejects type 0 (RESERVED)
                 * already; this default closes the connection rather
                 * than silently no-op'ing the packet. */
                WBLOG_ERR(broker,
                    "broker: unhandled packet type %u sock=%d",
                    type, (int)bc->sock);
                BrokerClient_AbnormalClose(broker, bc);
                return 0;
        }
#ifdef ENABLE_MQTT_WEBSOCKET
        if (bc->ws_ctx != NULL) {
            BrokerWsCtx *wsc = (BrokerWsCtx*)bc->ws_ctx;
            wsc->processing = 0;
            if (wsc->pending_remove) {
                /* The peer closed bc's connection while we were dispatching a
                 * packet (LWS_CALLBACK_CLOSED deferred the free to here). */
                BrokerClient_Remove(broker, bc);
                return 0;
            }
        }
#endif
    }

    /* Check keepalive timeout (MQTT spec 3.1.2.10: 1.5x keep alive) */
    if (bc->keep_alive_sec > 0) {
        WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();
        if ((now - bc->last_rx) >
            (WOLFMQTT_BROKER_TIME_T)(bc->keep_alive_sec * 3 / 2)) {
            WBLOG_ERR(broker, "broker: keepalive timeout sock=%d", (int)bc->sock);
        #ifdef WOLFMQTT_V5
            BrokerSend_Disconnect(bc, MQTT_REASON_KEEP_ALIVE_TIMEOUT);
        #endif
            BrokerClient_PublishWill(broker, bc); /* abnormal disconnect */
            /* Session persistence: keep subs if clean_session=0 */
            if (bc->clean_session) {
                BrokerSubs_RemoveClient(broker, bc);
            }
            else {
                BrokerSubs_OrphanClient(broker, bc);
            }
            BrokerClient_Remove(broker, bc);
            return 0;
        }
    }
    else if (!bc->connected) {
        /* Pre-CONNECT idle timeout. A freshly accepted client has
         * keep_alive_sec == 0 until CONNECT completes, so it is not covered by
         * the keepalive check above; evict it once it has been idle past the
         * deadline (last_rx is the accept time until the first full packet)
         * so half-open sockets cannot squat the client table. */
        WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();
        if ((now - bc->last_rx) >
                (WOLFMQTT_BROKER_TIME_T)BROKER_CONNECT_TIMEOUT_SEC) {
            WBLOG_ERR(broker, "broker: pre-CONNECT idle timeout sock=%d",
                (int)bc->sock);
            BrokerSubs_RemoveClient(broker, bc);
            BrokerClient_Remove(broker, bc);
            return 0;
        }
    }

    return activity;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */
int MqttBroker_Init(MqttBroker* broker, MqttBrokerNet* net)
{
    if (broker == NULL || net == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    XMEMSET(broker, 0, sizeof(*broker));
    XMEMCPY(&broker->net, net, sizeof(MqttBrokerNet));
    broker->listen_sock = BROKER_SOCKET_INVALID;
    broker->port = MQTT_DEFAULT_PORT;
#ifdef ENABLE_MQTT_TLS
    broker->listen_sock_tls = BROKER_SOCKET_INVALID;
    broker->port_tls = MQTT_SECURE_PORT;
#endif
    broker->running = 0;
    broker->log_level = BROKER_LOG_LEVEL_DEFAULT;
    broker->next_packet_id = 1;
    /* Seed the auto-id counter from a CSPRNG so the initial value
     * doesn't reveal broker uptime or start time. The counter still
     * advances by +1 per empty-ID CONNECT, so observing one assigned
     * auto-id discloses subsequent ones; the "auto-" prefix reservation
     * is what actually blocks hijack-via-prediction. The CSPRNG seed is
     * defense-in-depth against the residual information leak in the
     * starting value only.
     *
     * Gated on ENABLE_MQTT_TLS to avoid pulling wolfCrypt into plaintext-
     * broker builds that don't otherwise depend on it. Non-TLS builds
     * therefore start at 1; this is acceptable because (a) the prefix
     * reservation is the actual security boundary, and (b) operators
     * deploying a plaintext broker have already accepted that the wire
     * is observable. */
    broker->next_auto_id = 1;
#ifdef ENABLE_MQTT_TLS
    {
        WC_RNG rng;
        if (wc_InitRng(&rng) == 0) {
            word32 seed = 0;
            if (wc_RNG_GenerateBlock(&rng, (byte*)&seed, sizeof(seed)) == 0
                    && seed != 0) {
                broker->next_auto_id = seed;
            }
            wc_FreeRng(&rng);
        }
    }
#endif

#if !defined(WOLFMQTT_WOLFIP) && !defined(WOLFMQTT_BROKER_CUSTOM_NET)
    /* For the default POSIX backend, the net callbacks expect ctx to be a
     * MqttBroker* for logging via WBLOG_*. If no context was provided,
     * default to using this broker instance to avoid NULL-dereference. */
    if (broker->net.ctx == NULL) {
        broker->net.ctx = broker;
    }
#endif

    return MQTT_CODE_SUCCESS;
}

int MqttBroker_Step(MqttBroker* broker)
{
    int activity = 0;
    int rc;

    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (!broker->running) {
        return MQTT_CODE_SUCCESS;
    }

    /* 1. Try to accept new connections (non-blocking) */

    /* Plain (non-TLS) listener */
    if (broker->listen_sock != BROKER_SOCKET_INVALID) {
        BROKER_SOCKET_T new_sock = BROKER_SOCKET_INVALID;
        rc = broker->net.accept(broker->net.ctx, broker->listen_sock,
            &new_sock);
        if (rc == MQTT_CODE_SUCCESS && new_sock != BROKER_SOCKET_INVALID) {
        #ifdef WOLFMQTT_POSIX_SOCKET
            /* Reject socket if >= FD_SETSIZE (would overflow fd_set) */
            if (new_sock >= FD_SETSIZE) {
                WBLOG_ERR(broker,
                    "broker: accept sock=%d rejected (>= FD_SETSIZE)",
                    (int)new_sock);
                broker->net.close(broker->net.ctx, new_sock);
            }
            else
        #endif
            {
                WBLOG_INFO(broker, "broker: accept sock=%d (plain)",
                    (int)new_sock);
                if (BrokerClient_Add(broker, new_sock, 0) == NULL) {
                    WBLOG_ERR(broker,
                        "broker: accept sock=%d rejected (alloc)",
                        (int)new_sock);
                    broker->net.close(broker->net.ctx, new_sock);
                }
                activity = 1;
            }
        }
    }

#ifdef ENABLE_MQTT_TLS
    /* TLS listener */
    if (broker->listen_sock_tls != BROKER_SOCKET_INVALID) {
        BROKER_SOCKET_T new_sock = BROKER_SOCKET_INVALID;
        rc = broker->net.accept(broker->net.ctx, broker->listen_sock_tls,
            &new_sock);
        if (rc == MQTT_CODE_SUCCESS && new_sock != BROKER_SOCKET_INVALID) {
        #ifdef WOLFMQTT_POSIX_SOCKET
            /* Reject socket if >= FD_SETSIZE (would overflow fd_set) */
            if (new_sock >= FD_SETSIZE) {
                WBLOG_ERR(broker,
                    "broker: accept sock=%d rejected (>= FD_SETSIZE)",
                    (int)new_sock);
                broker->net.close(broker->net.ctx, new_sock);
            }
            else
        #endif
            {
                WBLOG_INFO(broker, "broker: accept sock=%d (TLS)",
                    (int)new_sock);
                if (BrokerClient_Add(broker, new_sock, 1) == NULL) {
                    WBLOG_ERR(broker,
                        "broker: accept sock=%d rejected (alloc)",
                        (int)new_sock);
                    broker->net.close(broker->net.ctx, new_sock);
                }
                activity = 1;
            }
        }
    }
#endif /* ENABLE_MQTT_TLS */

#ifdef ENABLE_MQTT_WEBSOCKET
    /* 1b. Service WebSocket connections (non-blocking).
     * lws_service() uses poll/epoll internally and may block even with
     * timeout=0 when connections are active.  Cancel the service first
     * to force the internal poll to return immediately. */
    if (broker->ws_ctx != NULL) {
        lws_cancel_service(broker->ws_ctx);
        lws_service(broker->ws_ctx, 0);
    }
#endif

    /* 2. Process each client */
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
            BrokerClient* bc = &broker->clients[i];
            if (!bc->in_use) {
                continue;
            }
            rc = BrokerClient_Process(broker, bc);
            if (rc > 0) {
                activity = 1;
            }
        }
    }
#else
    {
        BrokerClient* bc = broker->clients;
        while (bc) {
            BrokerClient* next = bc->next;
            rc = BrokerClient_Process(broker, bc);
            if (rc > 0) {
                activity = 1;
            }
            /* BrokerClient_Process may remove another client (e.g. client ID
             * takeover), which could free the node that next points to.
             * Validate next is still in the linked list before dereferencing */
            if (next != NULL) {
                BrokerClient* v = broker->clients;
                while (v != NULL && v != next) {
                    v = v->next;
                }
                if (v == NULL) {
                    break; /* next was freed; remaining clients handled next step */
                }
            }
            bc = next;
        }
    }
#endif

    /* 3. Process pending wills (v5 Will Delay Interval) */
    if (BrokerPendingWill_Process(broker) > 0) {
        activity = 1;
    }

    return activity ? MQTT_CODE_SUCCESS : MQTT_CODE_CONTINUE;
}

int MqttBroker_Start(MqttBroker* broker)
{
    int rc;

    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_BROKER_PERSIST
    /* Restore persisted state (orphan subs, retained messages) before
     * opening the listen sockets so reconnecting clients see the
     * resumed session immediately. No-op when no hooks are installed. */
    (void)BrokerPersist_Restore(broker);
#endif

#ifdef ENABLE_MQTT_TLS
    /* Initialize TLS context if TLS is enabled */
    if (broker->use_tls) {
    #if !defined(WOLFMQTT_BROKER_CUSTOM_NET)
        rc = BrokerTls_Init(broker);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: TLS init failed rc=%d", rc);
            return rc;
        }
    #else
        if (broker->tls_ctx == NULL) {
            WBLOG_ERR(broker, "broker: TLS ctx must be set before start");
            return MQTT_CODE_ERROR_BAD_ARG;
        }
    #endif
    }

    /* Start plain (non-TLS) listener */
  #ifndef WOLFMQTT_BROKER_NO_INSECURE
    if (!broker->use_tls || broker->port != broker->port_tls) {
        rc = broker->net.listen(broker->net.ctx, &broker->listen_sock,
            broker->port, BROKER_LISTEN_BACKLOG);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: listen (plain) failed rc=%d", rc);
            return rc;
        }
        WBLOG_INFO(broker, "broker: listening on port %d (plain)",
            broker->port);
    }
    else if (broker->use_tls && broker->port == broker->port_tls) {
        WBLOG_INFO(broker,
            "broker: plain port == TLS port (%d), TLS-only mode",
            broker->port_tls);
    }
  #endif /* !WOLFMQTT_BROKER_NO_INSECURE */

    /* Start TLS listener */
    if (broker->use_tls) {
        rc = broker->net.listen(broker->net.ctx, &broker->listen_sock_tls,
            broker->port_tls, BROKER_LISTEN_BACKLOG);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: listen (TLS) failed rc=%d", rc);
            return rc;
        }
        WBLOG_INFO(broker, "broker: listening on port %d (TLS)",
            broker->port_tls);
    }
#else
    /* No TLS support compiled in: plain listener only */
    rc = broker->net.listen(broker->net.ctx, &broker->listen_sock,
        broker->port, BROKER_LISTEN_BACKLOG);
    if (rc != MQTT_CODE_SUCCESS) {
        WBLOG_ERR(broker, "broker: listen failed rc=%d", rc);
        return rc;
    }
    WBLOG_INFO(broker, "broker: listening on port %d (no TLS)", broker->port);
#endif

#ifdef WOLFMQTT_BROKER_AUTH
    if (broker->auth_user || broker->auth_pass) {
        /* Reject configured credentials that would be silently rejected
         * by BrokerStrCompare's cmp_len guard. Catching this at startup
         * avoids a confusing state where every client auth fails. */
        if (broker->auth_user &&
                XSTRLEN(broker->auth_user) >= BROKER_MAX_USERNAME_LEN) {
            WBLOG_ERR(broker,
                "broker: auth_user length %u >= BROKER_MAX_USERNAME_LEN (%d)",
                (unsigned)XSTRLEN(broker->auth_user),
                BROKER_MAX_USERNAME_LEN);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
        if (broker->auth_pass &&
                XSTRLEN(broker->auth_pass) >= BROKER_MAX_PASSWORD_LEN) {
            WBLOG_ERR(broker,
                "broker: auth_pass length %u >= BROKER_MAX_PASSWORD_LEN (%d)",
                (unsigned)XSTRLEN(broker->auth_pass),
                BROKER_MAX_PASSWORD_LEN);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
        WBLOG_INFO(broker, "broker: auth enabled user=%s",
            broker->auth_user ? broker->auth_user : "(null)");
    #ifdef ENABLE_MQTT_TLS
    #ifndef WOLFMQTT_BROKER_NO_INSECURE
        if (broker->use_tls &&
            broker->port != broker->port_tls) {
            WBLOG_ERR(broker,
                "broker: WARNING: auth credentials exposed on plaintext "
                "port %d. Rebuild with ./configure --disable-broker-insecure "
                "for TLS-only",
                broker->port);
        }
    #endif
    #endif
    }
#endif

    /* Ensure at least one listener is active */
    if (broker->listen_sock == BROKER_SOCKET_INVALID
#ifdef ENABLE_MQTT_TLS
        && broker->listen_sock_tls == BROKER_SOCKET_INVALID
#endif
    ) {
        WBLOG_ERR(broker, "broker: no listeners configured");
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef ENABLE_MQTT_WEBSOCKET
    if (broker->use_websocket) {
    #ifdef WOLFMQTT_BROKER_NO_INSECURE
        /* TLS-only build: a plaintext WebSocket listener would silently bypass
         * the policy the plain-TCP listener enforces. Require WSS. */
        if (broker->ws_tls_cert == NULL) {
            WBLOG_ERR(broker, "broker: plaintext WebSocket listener refused in "
                "TLS-only build (WOLFMQTT_BROKER_NO_INSECURE); set ws_tls_cert "
                "for WSS");
            return MQTT_CODE_ERROR_BAD_ARG;
        }
    #endif
        rc = BrokerWs_Init(broker);
        if (rc != MQTT_CODE_SUCCESS) {
            WBLOG_ERR(broker, "broker: WebSocket init failed rc=%d", rc);
            return rc;
        }
    }
#endif

    broker->running = 1;
    return MQTT_CODE_SUCCESS;
}

int MqttBroker_Run(MqttBroker* broker)
{
    int rc;

    rc = MqttBroker_Start(broker);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    while (broker->running) {
        rc = MqttBroker_Step(broker);
        if (rc == MQTT_CODE_CONTINUE) {
            /* Idle - sleep briefly to avoid busy-waiting */
            BROKER_SLEEP_MS(10);
        }
        else if (rc < 0 && rc != MQTT_CODE_CONTINUE) {
            break;
        }
    }

    return MQTT_CODE_SUCCESS;
}

int MqttBroker_Stop(MqttBroker* broker)
{
    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    broker->running = 0;
    return MQTT_CODE_SUCCESS;
}

int MqttBroker_Free(MqttBroker* broker)
{
    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Disconnect and free all clients and subscriptions */
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_CLIENTS; i++) {
            if (broker->clients[i].in_use) {
                BrokerSubs_RemoveClient(broker, &broker->clients[i]);
                BrokerClient_Free(&broker->clients[i]);
            }
        }
    }
#else
    while (broker->clients) {
        BrokerSubs_RemoveClient(broker, broker->clients);
        BrokerClient_Remove(broker, broker->clients);
    }
    /* Free any orphaned subs (e.g. from clean_session=0 clients) */
    while (broker->subs) {
        BrokerSub* next = broker->subs->next;
        if (broker->subs->filter) {
            WOLFMQTT_FREE(broker->subs->filter);
        }
        if (broker->subs->client_id) {
            WOLFMQTT_FREE(broker->subs->client_id);
        }
        WOLFMQTT_FREE(broker->subs);
        broker->subs = next;
    }
#endif

    /* Clean up pending wills and retained messages */
    BrokerPendingWill_FreeAll(broker);
    BrokerRetained_FreeAll(broker);
#ifndef WOLFMQTT_STATIC_MEMORY
    BrokerOrphan_FreeAll(broker);
#endif

#ifdef ENABLE_MQTT_TLS
    if (broker->tls_ctx != NULL) {
    #if !defined(WOLFMQTT_BROKER_CUSTOM_NET)
        if (broker->tls_ctx_owned) {
            /* Context was created by BrokerTls_Init: full cleanup */
            BrokerTls_Free(broker);
        }
        else
    #endif
        {
            /* Application-provided TLS context: free ctx but skip
             * wolfSSL_Cleanup() since wolfSSL may be shared */
            wolfSSL_CTX_free(broker->tls_ctx);
            broker->tls_ctx = NULL;
        }
    }
#endif

    /* Close listen sockets */
#ifdef ENABLE_MQTT_WEBSOCKET
    BrokerWs_Free(broker);
#endif

    if (broker->listen_sock != BROKER_SOCKET_INVALID) {
        broker->net.close(broker->net.ctx, broker->listen_sock);
        broker->listen_sock = BROKER_SOCKET_INVALID;
    }
#ifdef ENABLE_MQTT_TLS
    if (broker->listen_sock_tls != BROKER_SOCKET_INVALID) {
        broker->net.close(broker->net.ctx, broker->listen_sock_tls);
        broker->listen_sock_tls = BROKER_SOCKET_INVALID;
    }
#endif

#if defined(WOLFMQTT_BROKER_PERSIST) && \
    defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT)
    /* Zero the cached AES key on teardown. ForceZero so the compiler
     * cannot elide the wipe (plain XMEMSET on a value that becomes
     * dead-on-return is at the compiler's discretion). */
    if (broker->persist_key_loaded) {
        BROKER_FORCE_ZERO(broker->persist_key_cache,
            sizeof(broker->persist_key_cache));
        broker->persist_key_loaded = 0;
    }
#endif

    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* CLI wrapper                                                                 */
/* -------------------------------------------------------------------------- */
static void BrokerUsage(const char* prog)
{
    (void)prog; /* Suppress unused parameter warning */
    PRINTF("usage: %s [-p port] [-v level]"
#ifdef WOLFMQTT_BROKER_AUTH
           " [-u user] [-P pass]"
#endif
#ifdef ENABLE_MQTT_TLS
           " [-t] [-s port] [-V ver] [-c cert] [-K key] [-A ca]"
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
           " [-w port]"
#endif
           , prog);
    PRINTF("  -p <port>   Plain port (default: %d)", MQTT_DEFAULT_PORT);
    PRINTF("  -v <level>  Log level: 1=error, 2=info (default), 3=debug");
#ifdef ENABLE_MQTT_TLS
    PRINTF("  -t          Enable TLS support");
    PRINTF("  -s <port>   TLS port (default: %d)", MQTT_SECURE_PORT);
    PRINTF("  -V <ver>    TLS version: 12=TLS 1.2, 13=TLS 1.3 (default: auto)");
    PRINTF("  -c <file>   Server certificate file (PEM)");
    PRINTF("  -K <file>   Server private key file (PEM)");
    PRINTF("  -A <file>   CA certificate for mutual TLS (PEM)");
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
    PRINTF("  -w <port>   WebSocket listen port (enables WebSocket)");
#endif
#ifdef WOLFMQTT_BROKER_PERSIST
    PRINTF("  -D <dir>    Persistent storage directory (enables persistence)");
#endif
    PRINTF("Features:"
#ifdef WOLFMQTT_BROKER_RETAINED
           " retained"
#endif
#ifdef WOLFMQTT_BROKER_WILL
           " will"
#endif
#ifdef WOLFMQTT_BROKER_WILDCARDS
           " wildcards"
#endif
#ifdef WOLFMQTT_BROKER_AUTH
           " auth"
#endif
#ifdef WOLFMQTT_BROKER_INSECURE
           " insecure"
#endif
#ifdef ENABLE_MQTT_TLS
           " tls"
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
           " websocket"
#endif
#ifdef WOLFMQTT_BROKER_PERSIST
           " persist"
#endif
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
           " persist-encrypt"
#endif
#if defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT) && \
    defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY)
           " persist-encrypt-dev-key"
#endif
#ifdef WOLFMQTT_STATIC_MEMORY
           " static-memory"
#endif
           );
}

#if !defined(WOLFMQTT_WOLFIP) && !defined(WOLFMQTT_BROKER_CUSTOM_NET) && \
    !defined(NO_MAIN_DRIVER)
#include <signal.h>
static volatile sig_atomic_t g_broker_shutdown = 0;
static void broker_signal_handler(int signo)
{
    (void)signo;
    g_broker_shutdown = 1;
}
#endif

#if defined(WOLFMQTT_BROKER_PERSIST) && \
    defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT) && \
    defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY)
/* Development-only derive_key hook. Returns a fixed 32-byte key so the
 * CLI can exercise the AES-GCM persistence round-trip without external
 * key management. Real deployments override this via
 * MqttBroker_SetPersistHooks before MqttBroker_Start. Compile-time
 * gated so the fixed-pattern key generator is not linked into a
 * production binary (where flipping a runtime flag would otherwise
 * substitute trivially-recoverable keys for real ones). */
static int wolfmqtt_broker_dev_derive_key(void* ctx, byte* out_key,
    word32 key_len)
{
    word32 i;
    (void)ctx;
    if (out_key == NULL || key_len < 32) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    /* Fixed pattern. Operators must replace this with a real key
     * derivation before relying on confidentiality. */
    for (i = 0; i < key_len; i++) {
        out_key[i] = (byte)(0xA0 + (i & 0x0F));
    }
    return 0;
}
#endif

int wolfmqtt_broker(int argc, char** argv)
{
    int rc;
    MqttBroker broker;
    MqttBrokerNet net;
    int i;
#ifdef WOLFMQTT_BROKER_PERSIST
    MqttBrokerPersistHooks persist_hooks;
    const char* persist_dir = NULL;
    int persist_initialized = 0;
    #if defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT) && \
        defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY)
    /* Encrypt-key source. NULL = unset (broker refuses to start when
     * encrypt is enabled and persist_dir is given). "dev" = use the
     * hard-coded dev key for CI/smoke tests. Only declared when the
     * dev-key generator is compiled in - the -E option has no other
     * recognized value. */
    const char* encrypt_key_source = NULL;
    #endif
#endif

    /* Set stdout to unbuffered for immediate output */
#ifndef WOLFMQTT_NO_STDIO
    setvbuf(stdout, NULL, _IONBF, 0);
#endif

#if defined(WOLFMQTT_WOLFIP)
    XMEMSET(&net, 0, sizeof(net));
    PRINTF("broker: use MqttBrokerNet_wolfIP_Init() for wolfIP");
    return MQTT_CODE_ERROR_BAD_ARG;
#elif !defined(WOLFMQTT_BROKER_CUSTOM_NET)
    rc = MqttBrokerNet_Init(&net);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#else
    XMEMSET(&net, 0, sizeof(net));
    PRINTF("broker: custom net requires callbacks to be set");
    return MQTT_CODE_ERROR_BAD_ARG;
#endif

    rc = MqttBroker_Init(&broker, &net);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-p") == 0 && i + 1 < argc) {
            broker.port = (word16)XATOI(argv[++i]);
        }
        else if (XSTRCMP(argv[i], "-v") == 0 && i + 1 < argc) {
            broker.log_level = (byte)XATOI(argv[++i]);
        }
#ifdef WOLFMQTT_BROKER_AUTH
        else if (XSTRCMP(argv[i], "-u") == 0 && i + 1 < argc) {
            broker.auth_user = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-P") == 0 && i + 1 < argc) {
            broker.auth_pass = argv[++i];
        }
#endif
#ifdef ENABLE_MQTT_TLS
        else if (XSTRCMP(argv[i], "-t") == 0) {
            broker.use_tls = 1;
        }
        else if (XSTRCMP(argv[i], "-s") == 0 && i + 1 < argc) {
            broker.port_tls = (word16)XATOI(argv[++i]);
        }
        else if (XSTRCMP(argv[i], "-V") == 0 && i + 1 < argc) {
            broker.tls_version = (byte)XATOI(argv[++i]);
        }
        else if (XSTRCMP(argv[i], "-c") == 0 && i + 1 < argc) {
            broker.tls_cert = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-K") == 0 && i + 1 < argc) {
            broker.tls_key = argv[++i];
        }
        else if (XSTRCMP(argv[i], "-A") == 0 && i + 1 < argc) {
            broker.tls_ca = argv[++i];
        }
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
        else if (XSTRCMP(argv[i], "-w") == 0 && i + 1 < argc) {
            broker.ws_port = (word16)XATOI(argv[++i]);
            broker.use_websocket = 1;
        }
#endif
#ifdef WOLFMQTT_BROKER_PERSIST
        else if (XSTRCMP(argv[i], "-D") == 0 && i + 1 < argc) {
            persist_dir = argv[++i];
        }
    #if defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT) && \
        defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY)
        else if (XSTRCMP(argv[i], "-E") == 0 && i + 1 < argc) {
            /* Encrypt key source. Only "dev" is recognized: install the
             * hard-coded development key (NOT for production - the key
             * is a fixed pattern in the binary, trivially recoverable).
             * Production embedders should install their own derive_key
             * hook via MqttBroker_SetPersistHooks and skip this CLI.
             * The -E flag and the dev key generator are both compile-
             * gated by WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY. */
            encrypt_key_source = argv[++i];
        }
    #endif
#endif
        else if (XSTRCMP(argv[i], "-h") == 0) {
            BrokerUsage(argv[0]);
            return 0;
        }
        else {
            BrokerUsage(argv[0]);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
    }

#ifdef WOLFMQTT_BROKER_PERSIST
    /* If -D was passed, enable the default POSIX persistence backend
     * rooted at that directory. Absent the flag, persist hooks remain
     * uninstalled and the broker behaves like a build without
     * WOLFMQTT_BROKER_PERSIST. */
    if (persist_dir != NULL) {
    #ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
        #ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY
        /* This build enables AES-GCM at rest. Refuse to start unless
         * the operator explicitly opted in to a key source. The only
         * built-in option from this CLI is "-E dev" (development key).
         * Embedders providing real key management install derive_key
         * via MqttBroker_SetPersistHooks and don't reach this code. */
        if (encrypt_key_source == NULL) {
            PRINTF("broker: ERROR persist+encrypt build needs -E <source> "
                "(only \"dev\" is recognized; production deployments "
                "must install MqttBrokerPersistHooks.derive_key)");
            return MQTT_CODE_ERROR_BAD_ARG;
        }
        if (XSTRCMP(encrypt_key_source, "dev") != 0) {
            PRINTF("broker: ERROR unknown -E source \"%s\" "
                "(only \"dev\" is recognized)", encrypt_key_source);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
        #else
        /* Encrypt is built in but the development key generator is not.
         * The CLI cannot install a real derive_key on the operator's
         * behalf - refuse explicitly so the failure mode is obvious. */
        PRINTF("broker: ERROR persist+encrypt build has no built-in key "
            "source (rebuild with --enable-broker-persist-encrypt-dev-key "
            "for testing, or install MqttBrokerPersistHooks.derive_key)");
        return MQTT_CODE_ERROR_BAD_ARG;
        #endif
    #endif
        rc = MqttBrokerNet_PersistPosix_Init(&persist_hooks, persist_dir);
        if (rc != 0) {
            PRINTF("broker: persist init failed dir=%s rc=%d",
                persist_dir, rc);
            return rc;
        }
        persist_initialized = 1;
    #if defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT) && \
        defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY)
        /* Install the development-only derive_key hook. NOT for
         * production - the key is a fixed pattern in the binary and is
         * trivially recoverable by any adversary with read access. The
         * "DEV-KEY" log line below makes the choice obvious. */
        persist_hooks.derive_key = wolfmqtt_broker_dev_derive_key;
    #endif
        (void)MqttBroker_SetPersistHooks(&broker, &persist_hooks);
        PRINTF("broker: persist enabled dir=%s%s", persist_dir,
        #if defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT) && \
            defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY)
            " (encrypted, DEV-KEY: NOT FOR PRODUCTION)"
        #elif defined(WOLFMQTT_BROKER_PERSIST_ENCRYPT)
            " (encrypted)"
        #else
            ""
        #endif
            );
    }
#endif

#if !defined(WOLFMQTT_WOLFIP) && !defined(WOLFMQTT_BROKER_CUSTOM_NET) && \
    !defined(NO_MAIN_DRIVER)
    /* Reset shutdown flag so this wrapper is reusable across multiple
     * invocations in the same process (tests, embedding). */
    g_broker_shutdown = 0;
    signal(SIGINT, broker_signal_handler);
    signal(SIGTERM, broker_signal_handler);
    /* Belt-and-suspenders for the SIGPIPE-on-peer-close path. The socket
     * layer already uses MSG_NOSIGNAL / SO_NOSIGPIPE per platform, but
     * ignore SIGPIPE process-wide too so any reused or custom net callback
     * cannot kill the broker on a write to a closed peer. */
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    rc = MqttBroker_Start(&broker);
    if (rc == MQTT_CODE_SUCCESS) {
        while (broker.running && !g_broker_shutdown) {
            rc = MqttBroker_Step(&broker);
            if (rc == MQTT_CODE_CONTINUE) {
                BROKER_SLEEP_MS(10);
            }
            else if (rc < 0) {
                break;
            }
        }
        if (g_broker_shutdown) {
            PRINTF("broker: received shutdown signal, shutting down");
            MqttBroker_Stop(&broker);
            rc = MQTT_CODE_SUCCESS;
        }
    }
#else
    rc = MqttBroker_Run(&broker);
#endif

    MqttBroker_Free(&broker);

#ifdef WOLFMQTT_BROKER_PERSIST
    if (persist_initialized) {
        MqttBrokerNet_PersistPosix_Free(&persist_hooks);
    }
#endif

    return rc;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    return wolfmqtt_broker(argc, argv);
}
#endif

#else /* WOLFMQTT_BROKER */
#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    PRINTF("broker: not built (configure with --enable-broker)");
    return 0;
}
#endif
#endif /* WOLFMQTT_BROKER */
