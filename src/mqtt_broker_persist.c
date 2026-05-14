/* mqtt_broker_persist.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* Shadow-write helpers for the broker persistence layer. Every public
 * helper here is callable from src/mqtt_broker.c at the corresponding
 * state-change trigger point. Helpers no-op when broker->persist is
 * NULL, so the call sites do not need to guard.
 *
 * Record format on the wire (each kv_put/kv_get blob):
 *
 *   off  size   field
 *     0    4    magic       = "WMQB"
 *     4    2    schema_ver  = WOLFMQTT_BROKER_PERSIST_SCHEMA_VER (big endian)
 *     6    1    rec_kind    = namespace echo
 *     7    1    wrap_mode   = 0 plaintext, 1 AES-GCM
 *     8    4    body_len    (big endian)
 *    12   ...   body        (encoding depends on namespace and wrap_mode)
 *
 * The body encoding is intentionally simple: fixed-width header fields
 * first, variable-length strings/payloads last, lengths prefixed
 * big-endian. Forward compatibility is by schema-version bump + wipe.
 * wrap_mode is bound as AAD by the AES-GCM path so a tamper that
 * flips it (or flips rec_kind) fails the tag check.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_broker.h"

#ifdef WOLFMQTT_BROKER_PERSIST

/* The broker has private static structs we need to inspect (BrokerSub,
 * BrokerRetainedMsg, BrokerOutPub). Pull them in by including the public
 * header which exposes the typedefs. mqtt_broker.c defines static
 * helpers we cannot reach from here, but we don't need them: the
 * persist layer takes already-snapshot data via its function arguments. */

/* Local mirror of the WBLOG_* macros from mqtt_broker.c. Both files
 * are linked into the same broker binary; sharing a header for the
 * macros would force every embedder of wolfmqtt to inherit them, so
 * keep them file-local. */
#ifdef WOLFMQTT_BROKER_NO_LOG
    #define WMQB_LOG_ERR(b, ...)   do { (void)(b); } while(0)
    #define WMQB_LOG_INFO(b, ...)  do { (void)(b); } while(0)
#else
    #define WMQB_LOG(b, level, ...) \
        do { if ((b)->log_level >= (level)) PRINTF(__VA_ARGS__); } while(0)
    #define WMQB_LOG_ERR(b, ...)   WMQB_LOG(b, BROKER_LOG_ERROR, __VA_ARGS__)
    #define WMQB_LOG_INFO(b, ...)  WMQB_LOG(b, BROKER_LOG_INFO, __VA_ARGS__)
#endif

/* Time abstraction. Mirrors the fallback in src/mqtt_broker.c so this
 * translation unit doesn't depend on a private header. Override via
 * user_settings.h same as the broker core does. */
#ifndef WOLFMQTT_BROKER_GET_TIME_S
    #if defined(WOLFMQTT_WOLFIP)
        #error "WOLFMQTT_WOLFIP requires WOLFMQTT_BROKER_GET_TIME_S to be defined"
    #else
        #include <time.h>
        #define WOLFMQTT_BROKER_GET_TIME_S() \
            ((WOLFMQTT_BROKER_TIME_T)time(NULL))
    #endif
#endif

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    #include <wolfssl/wolfcrypt/aes.h>
    #include <wolfssl/wolfcrypt/random.h>
    #define WMQB_AES_KEY_LEN   32
    #define WMQB_GCM_NONCE_LEN 12
    #define WMQB_GCM_TAG_LEN   16
#endif

#define WMQB_HDR_LEN  12

/* Build's expected wrap_mode (byte 7 of every record header). Toggling
 * --enable-broker-persist-encrypt changes this value so a directory
 * written by the other build is rejected via the schema-mismatch wipe
 * path on next startup. */
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    #define WMQB_WRAP_MODE WOLFMQTT_BROKER_PERSIST_WRAP_AES_GCM
#else
    #define WMQB_WRAP_MODE WOLFMQTT_BROKER_PERSIST_WRAP_PLAIN
#endif

/* Big-endian numeric writers (no host-byte-order dependency in the
 * stored bytes, so a record written on x86 can be read on any platform). */
static WC_INLINE void wmqb_w_u16(byte* p, word16 v)
{
    p[0] = (byte)((v >> 8) & 0xFF);
    p[1] = (byte)(v & 0xFF);
}
static WC_INLINE void wmqb_w_u32(byte* p, word32 v)
{
    p[0] = (byte)((v >> 24) & 0xFF);
    p[1] = (byte)((v >> 16) & 0xFF);
    p[2] = (byte)((v >> 8) & 0xFF);
    p[3] = (byte)(v & 0xFF);
}
static WC_INLINE void wmqb_w_u64(byte* p, word64 v)
{
    p[0] = (byte)((v >> 56) & 0xFF);
    p[1] = (byte)((v >> 48) & 0xFF);
    p[2] = (byte)((v >> 40) & 0xFF);
    p[3] = (byte)((v >> 32) & 0xFF);
    p[4] = (byte)((v >> 24) & 0xFF);
    p[5] = (byte)((v >> 16) & 0xFF);
    p[6] = (byte)((v >> 8) & 0xFF);
    p[7] = (byte)(v & 0xFF);
}
static WC_INLINE word16 wmqb_r_u16(const byte* p)
{
    return (word16)(((word16)p[0] << 8) | (word16)p[1]);
}
static WC_INLINE word32 wmqb_r_u32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16) |
           ((word32)p[2] << 8) | (word32)p[3];
}
static WC_INLINE word64 wmqb_r_u64(const byte* p)
{
    return ((word64)p[0] << 56) | ((word64)p[1] << 48) |
           ((word64)p[2] << 40) | ((word64)p[3] << 32) |
           ((word64)p[4] << 24) | ((word64)p[5] << 16) |
           ((word64)p[6] << 8) | (word64)p[7];
}

/* Write the 12-byte record header. Caller guarantees buf has room.
 * rec_kind is one of BROKER_PERSIST_NS_* and fits in a single byte
 * (values are all < 0x80 by design). */
static void wmqb_write_header(byte* buf, word16 rec_kind, word32 body_len)
{
    buf[0] = WOLFMQTT_BROKER_PERSIST_MAGIC0;
    buf[1] = WOLFMQTT_BROKER_PERSIST_MAGIC1;
    buf[2] = WOLFMQTT_BROKER_PERSIST_MAGIC2;
    buf[3] = WOLFMQTT_BROKER_PERSIST_MAGIC3;
    wmqb_w_u16(&buf[4], (word16)WOLFMQTT_BROKER_PERSIST_SCHEMA_VER);
    buf[6] = (byte)(rec_kind & 0xFF);
    buf[7] = (byte)WMQB_WRAP_MODE;
    wmqb_w_u32(&buf[8], body_len);
}

/* Validate header against this build's schema. Returns 0 on match,
 * negative on magic or version mismatch. Body length is returned via
 * out_body_len. */
static WC_INLINE int wmqb_read_header(const byte* buf, word32 buf_len,
    word16 expect_kind, word32* out_body_len)
{
    word32 body_len;

    if (buf_len < WMQB_HDR_LEN) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (buf[0] != WOLFMQTT_BROKER_PERSIST_MAGIC0 ||
        buf[1] != WOLFMQTT_BROKER_PERSIST_MAGIC1 ||
        buf[2] != WOLFMQTT_BROKER_PERSIST_MAGIC2 ||
        buf[3] != WOLFMQTT_BROKER_PERSIST_MAGIC3) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (wmqb_r_u16(&buf[4]) !=
            (word16)WOLFMQTT_BROKER_PERSIST_SCHEMA_VER) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (buf[6] != (byte)(expect_kind & 0xFF)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (buf[7] != (byte)WMQB_WRAP_MODE) {
        /* Build expected plaintext but found encrypted record, or
         * vice versa. Treat as schema mismatch so the caller wipes. */
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    /* Read body length into a local so the bounds check works whether
     * out_body_len is NULL or not. Callers that only validate the
     * header (kind/version) without inspecting body length pass NULL. */
    body_len = wmqb_r_u32(&buf[8]);
    if (body_len > (buf_len - WMQB_HDR_LEN)) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (out_body_len != NULL) {
        *out_body_len = body_len;
    }
    return 0;
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
/* Lazy-init key cache. Single-threaded broker - no lock needed. The
 * application-provided derive_key hook fills 32 bytes on first request.
 * The cache lives on the MqttBroker (broker->persist_key_cache /
 * broker->persist_key_loaded) so multiple broker instances in one
 * process don't share key material, and MqttBroker_Free can ForceZero
 * the cached key on teardown. */
static int wmqb_get_key(MqttBroker* broker)
{
    const MqttBrokerPersistHooks* h;
    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (broker->persist_key_loaded) {
        return 0;
    }
    h = broker->persist;
    if (h == NULL || h->derive_key == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (h->derive_key(h->ctx, broker->persist_key_cache,
            (word32)sizeof(broker->persist_key_cache)) != 0) {
        return MQTT_CODE_ERROR_SYSTEM;
    }
    broker->persist_key_loaded = 1;
    return 0;
}

/* Wrap a plaintext record (header(12) + body) into an encrypted blob:
 *   header(12) || nonce(12) || ct(body_len) || tag(16)
 * Header is passed unencrypted but is bound as AAD so any tamper of
 * the namespace / body_len fields fails the tag check. Caller must
 * free the returned buffer. */
static int wmqb_encrypt_blob(MqttBroker* broker,
    const byte* plain, word32 plain_len, byte** ct_out, word32* ct_out_len)
{
    Aes aes;
    WC_RNG rng;
    byte* out;
    word32 body_len;
    int rc;

    if (broker == NULL || plain == NULL || plain_len < WMQB_HDR_LEN ||
            ct_out == NULL || ct_out_len == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_get_key(broker);
    if (rc != 0) {
        return rc;
    }
    body_len = plain_len - WMQB_HDR_LEN;
    *ct_out_len = WMQB_HDR_LEN + WMQB_GCM_NONCE_LEN + body_len +
                  WMQB_GCM_TAG_LEN;
    out = (byte*)WOLFMQTT_MALLOC(*ct_out_len);
    if (out == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMCPY(out, plain, WMQB_HDR_LEN);
    if (wc_InitRng(&rng) != 0) {
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (wc_RNG_GenerateBlock(&rng,
            out + WMQB_HDR_LEN, WMQB_GCM_NONCE_LEN) != 0) {
        wc_FreeRng(&rng);
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    wc_FreeRng(&rng);

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (wc_AesGcmSetKey(&aes, broker->persist_key_cache,
            (word32)sizeof(broker->persist_key_cache)) != 0) {
        wc_AesFree(&aes);
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (wc_AesGcmEncrypt(&aes,
            out + WMQB_HDR_LEN + WMQB_GCM_NONCE_LEN,        /* ct */
            plain + WMQB_HDR_LEN, body_len,                  /* plaintext */
            out + WMQB_HDR_LEN, WMQB_GCM_NONCE_LEN,          /* nonce */
            out + WMQB_HDR_LEN + WMQB_GCM_NONCE_LEN + body_len, /* tag */
            WMQB_GCM_TAG_LEN,
            plain, WMQB_HDR_LEN) != 0) {                     /* aad = header */
        wc_AesFree(&aes);
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    wc_AesFree(&aes);
    *ct_out = out;
    return 0;
}

/* Reverse of wmqb_encrypt_blob. Caller must free the returned plain. */
static int wmqb_decrypt_blob(MqttBroker* broker,
    const byte* ct, word32 ct_len, byte** plain_out, word32* plain_out_len)
{
    Aes aes;
    byte* out;
    word32 body_len;
    int rc;

    if (broker == NULL || ct == NULL ||
            ct_len < (word32)(WMQB_HDR_LEN + WMQB_GCM_NONCE_LEN +
                              WMQB_GCM_TAG_LEN) ||
            plain_out == NULL || plain_out_len == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = wmqb_get_key(broker);
    if (rc != 0) {
        return rc;
    }
    body_len = ct_len - WMQB_HDR_LEN - WMQB_GCM_NONCE_LEN -
               WMQB_GCM_TAG_LEN;
    *plain_out_len = WMQB_HDR_LEN + body_len;
    out = (byte*)WOLFMQTT_MALLOC(*plain_out_len);
    if (out == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMCPY(out, ct, WMQB_HDR_LEN);

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (wc_AesGcmSetKey(&aes, broker->persist_key_cache,
            (word32)sizeof(broker->persist_key_cache)) != 0) {
        wc_AesFree(&aes);
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_SYSTEM;
    }
    if (wc_AesGcmDecrypt(&aes,
            out + WMQB_HDR_LEN,
            ct + WMQB_HDR_LEN + WMQB_GCM_NONCE_LEN, body_len,
            ct + WMQB_HDR_LEN, WMQB_GCM_NONCE_LEN,
            ct + WMQB_HDR_LEN + WMQB_GCM_NONCE_LEN + body_len,
            WMQB_GCM_TAG_LEN,
            ct, WMQB_HDR_LEN) != 0) {
        wc_AesFree(&aes);
        WOLFMQTT_FREE(out);
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    wc_AesFree(&aes);
    *plain_out = out;
    return 0;
}
#endif /* WOLFMQTT_BROKER_PERSIST_ENCRYPT */

/* Commit a blob to the backend and sync if available. Returns the hook's
 * return code, or 0 if hooks are disabled (silent no-op). When persist
 * encryption is enabled, the blob is wrapped here so callers can keep
 * passing plaintext (header + body). */
static int wmqb_kv_put_commit(MqttBroker* broker, byte ns,
    const byte* key, word16 key_len, const byte* blob, word32 blob_len)
{
    int rc;
    const MqttBrokerPersistHooks* h;
    if (broker == NULL) {
        return 0;
    }
    h = broker->persist;
    if (h == NULL || h->kv_put == NULL) {
        return 0;
    }
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    {
        byte*  enc;
        word32 enc_len;
        rc = wmqb_encrypt_blob(broker, blob, blob_len, &enc, &enc_len);
        if (rc != 0) {
            return rc;
        }
        rc = h->kv_put(h->ctx, ns, key, key_len, enc, enc_len);
        WOLFMQTT_FREE(enc);
    }
#else
    rc = h->kv_put(h->ctx, ns, key, key_len, blob, blob_len);
#endif
    if (rc == 0 && h->sync != NULL) {
        (void)h->sync(h->ctx);
    }
    return rc;
}

static int wmqb_kv_del_commit(MqttBroker* broker, byte ns,
    const byte* key, word16 key_len)
{
    int rc;
    const MqttBrokerPersistHooks* h;
    if (broker == NULL) {
        return 0;
    }
    h = broker->persist;
    if (h == NULL || h->kv_del == NULL) {
        return 0;
    }
    rc = h->kv_del(h->ctx, ns, key, key_len);
    if (rc == 0 && h->sync != NULL) {
        (void)h->sync(h->ctx);
    }
    return rc;
}

#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
/* iter callback wrapper: decrypts each blob before delegating to the
 * "real" callback. Failures (bad tag) are logged via the iter cb's
 * skipped counter convention - we forward 0-len which the inner cb
 * treats as malformed. The persist context passed to the inner cb is
 * augmented to carry the original cb pointer and ctx. */
struct wmqb_iter_decrypt_ctx {
    MqttBroker*                    broker;
    MqttBrokerPersist_IterCb       inner_cb;
    void*                          inner_ctx;
};

static int wmqb_iter_decrypt_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx)
{
    struct wmqb_iter_decrypt_ctx* d =
        (struct wmqb_iter_decrypt_ctx*)cb_ctx;
    byte*  plain;
    word32 plain_len;
    int    rc;
    int    stop;

    rc = wmqb_decrypt_blob(d->broker, blob, blob_len, &plain, &plain_len);
    if (rc != 0) {
        /* Forward an empty blob; inner cb will read_header-fail and
         * bump its skipped counter. */
        return d->inner_cb(key, key_len, blob, 0, d->inner_ctx);
    }
    stop = d->inner_cb(key, key_len, plain, plain_len, d->inner_ctx);
    WOLFMQTT_FREE(plain);
    return stop;
}

/* Drop-in replacement for h->kv_iter that decrypts each blob. */
static int wmqb_iter_decrypt(MqttBroker* broker, byte ns,
    MqttBrokerPersist_IterCb cb, void* cb_ctx)
{
    struct wmqb_iter_decrypt_ctx wrap;
    const MqttBrokerPersistHooks* h;
    if (broker == NULL || cb == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    h = broker->persist;
    if (h == NULL || h->kv_iter == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    wrap.broker = broker;
    wrap.inner_cb = cb;
    wrap.inner_ctx = cb_ctx;
    return h->kv_iter(h->ctx, ns, wmqb_iter_decrypt_cb, &wrap);
}

/* Decrypt-on-get for META. The plaintext "header || body" is copied
 * into *out. Currently only META uses this (~44 bytes encrypted) so a
 * 256-byte stack buffer is plenty; any future caller with a larger
 * record must extend this assumption (assert is a runtime version of
 * a static check). */
static int wmqb_kv_get_decrypt(MqttBroker* broker, byte ns,
    const byte* key, word16 key_len, byte* out, word32* inout_len)
{
    /* Read encrypted into a temp, decrypt, then copy plaintext into
     * caller buffer. Caller's buffer should be at least
     * (encrypted_len - nonce - tag). */
    byte   enc[256];
    word32 cap = sizeof(enc);
    byte*  plain;
    word32 plain_len;
    int    rc;
    const MqttBrokerPersistHooks* h;

    if (broker == NULL || out == NULL || inout_len == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    h = broker->persist;
    if (h == NULL || h->kv_get == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    /* Compile-time sanity: WMQB_HDR_LEN(12) + nonce(12) + body + tag(16)
     * must fit in enc[256]. With ns==BROKER_PERSIST_NS_META the
     * plaintext body is 4 bytes -> 12+12+4+16 = 44 bytes. Plenty. If
     * a new caller routes through this with a larger record, this
     * limit needs revisiting. */
    rc = h->kv_get(h->ctx, ns, key, key_len, enc, &cap);
    if (rc != 0) {
        return rc;
    }
    rc = wmqb_decrypt_blob(broker, enc, cap, &plain, &plain_len);
    if (rc != 0) {
        return rc;
    }
    if (plain_len > *inout_len) {
        WOLFMQTT_FREE(plain);
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMCPY(out, plain, plain_len);
    *inout_len = plain_len;
    WOLFMQTT_FREE(plain);
    return 0;
}
#endif /* WOLFMQTT_BROKER_PERSIST_ENCRYPT */

/* Iter helper used by the restore code. When encryption is enabled,
 * wraps the callback to decrypt each blob; otherwise calls kv_iter
 * directly. */
static int wmqb_kv_iter(MqttBroker* broker, byte ns,
    MqttBrokerPersist_IterCb cb, void* cb_ctx)
{
    const MqttBrokerPersistHooks* h;
    if (broker == NULL || cb == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    h = broker->persist;
    if (h == NULL || h->kv_iter == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    return wmqb_iter_decrypt(broker, ns, cb, cb_ctx);
#else
    return h->kv_iter(h->ctx, ns, cb, cb_ctx);
#endif
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */
int MqttBroker_SetPersistHooks(MqttBroker* broker,
    const MqttBrokerPersistHooks* hooks)
{
    if (broker == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    broker->persist = hooks;
    return MQTT_CODE_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Shadow-write helpers (PutSession / PutSubs / PutRetained / PutOutPub /
 * Del* / Restore). Each helper:
 *   1) bails immediately if broker->persist is NULL,
 *   2) snapshots the relevant in-memory state into a heap buffer,
 *   3) commits via wmqb_kv_put_commit / wmqb_kv_del_commit.
 *
 * Restore is implemented in P6.                                               */
/* -------------------------------------------------------------------------- */

/* Snapshot a connected client into a persisted session record and commit.
 *
 * Body layout:
 *   off  size   field
 *     0    1    protocol_level
 *     1    1    _reserved   (0)
 *     2    4    session_expiry_sec  (big endian; 0xFFFFFFFF = never)
 *     6    2    client_id_len  (big endian)
 *     8    N    client_id   (no NUL terminator on the wire)
 *
 * Key is the client_id bytes. */
int BrokerPersist_PutSession(MqttBroker* broker,
    const struct BrokerClient* bc)
{
    const BrokerClient* c = (const BrokerClient*)bc;
    const char* cid;
    word16 cid_len;
    word32 body_len;
    word32 total_len;
    byte*  buf;
    int    rc;

    if (broker == NULL || broker->persist == NULL || c == NULL) {
        return 0;
    }
    /* Only persist sessions whose owner had a non-empty client_id and
     * connected with clean_session=0 (the spec's persistent-session
     * marker). Callers that want to evict use BrokerPersist_DelSession. */
    cid = c->client_id;
    if (cid == NULL || *cid == '\0') {
        return 0;
    }
    cid_len = (word16)XSTRLEN(cid);

    body_len = 1 + 1 + 4 + 2 + cid_len;
    total_len = WMQB_HDR_LEN + body_len;
    buf = (byte*)WOLFMQTT_MALLOC(total_len);
    if (buf == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    wmqb_write_header(buf, BROKER_PERSIST_NS_SESSION, body_len);
    buf[WMQB_HDR_LEN + 0] = c->protocol_level;
    buf[WMQB_HDR_LEN + 1] = 0;
    /* Session Expiry plumbed from CONNECT (v5 property) or defaulted to
     * 0xFFFFFFFF (never expire) for clean_session=0 v3.1.1 sessions. */
#ifndef WOLFMQTT_STATIC_MEMORY
    wmqb_w_u32(&buf[WMQB_HDR_LEN + 2], c->session_expiry_sec);
#else
    wmqb_w_u32(&buf[WMQB_HDR_LEN + 2], 0xFFFFFFFFu);
#endif
    wmqb_w_u16(&buf[WMQB_HDR_LEN + 6], cid_len);
    XMEMCPY(&buf[WMQB_HDR_LEN + 8], cid, cid_len);

    rc = wmqb_kv_put_commit(broker, BROKER_PERSIST_NS_SESSION,
        (const byte*)cid, cid_len, buf, total_len);
    WOLFMQTT_FREE(buf);
    return rc;
}

int BrokerPersist_DelSession(MqttBroker* broker, const char* client_id)
{
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
    return wmqb_kv_del_commit(broker, BROKER_PERSIST_NS_SESSION,
        (const byte*)client_id, (word16)XSTRLEN(client_id));
}

/* Snapshot every BrokerSub bound to client_id into a single per-client
 * subscription record.
 *
 * Body layout:
 *   off  size   field
 *     0    2    count   (big endian; 0 == "no subs", caller may DelSubs instead)
 *     2   ...   N entries, each:
 *                  1    qos
 *                  1    options (reserved for v5 NL/RAP/RH bits)
 *                  2    filter_len  (big endian)
 *                  N    filter      (no NUL)
 */
int BrokerPersist_PutSubs(MqttBroker* broker, const char* client_id)
{
    word16 cid_len;
    word32 body_len;
    word32 total_len;
    byte*  buf;
    byte*  p;
    word16 count = 0;
    int    rc;
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
#else
    const BrokerSub* sub;
#endif

    if (broker == NULL || broker->persist == NULL || client_id == NULL ||
        *client_id == '\0') {
        return 0;
    }
    {
        size_t raw = XSTRLEN(client_id);
        /* word16 downcast - reject lengths that wouldn't fit instead
         * of silently truncating. MQTT v3.1.1 caps client_id at 23
         * bytes; v5 caps at 65535 (i.e., fits in word16). Anything
         * longer is malformed input from a caller. */
        if (raw == 0 || raw > 0xFFFFu) {
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        cid_len = (word16)raw;
    }

    /* Pass 1: count + size */
    body_len = 2;
#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        const BrokerSub* s = &broker->subs[i];
        if (!s->in_use) {
            continue;
        }
        if (XSTRCMP(s->client_id, client_id) != 0) {
            continue;
        }
        count++;
        body_len += 1 + 1 + 2 + (word32)XSTRLEN(s->filter);
    }
#else
    for (sub = broker->subs; sub != NULL; sub = sub->next) {
        if (sub->client_id == NULL ||
            XSTRCMP(sub->client_id, client_id) != 0) {
            continue;
        }
        if (sub->filter == NULL) {
            continue;
        }
        count++;
        body_len += 1 + 1 + 2 + (word32)XSTRLEN(sub->filter);
    }
#endif

    if (count == 0) {
        /* Caller did all the unsubscribes; remove the record entirely. */
        return wmqb_kv_del_commit(broker, BROKER_PERSIST_NS_SUBS,
            (const byte*)client_id, cid_len);
    }

    total_len = WMQB_HDR_LEN + body_len;
    buf = (byte*)WOLFMQTT_MALLOC(total_len);
    if (buf == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    wmqb_write_header(buf, BROKER_PERSIST_NS_SUBS, body_len);
    p = &buf[WMQB_HDR_LEN];
    wmqb_w_u16(p, count); p += 2;

#ifdef WOLFMQTT_STATIC_MEMORY
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        const BrokerSub* s = &broker->subs[i];
        word16 flen;
        if (!s->in_use) {
            continue;
        }
        if (XSTRCMP(s->client_id, client_id) != 0) {
            continue;
        }
        flen = (word16)XSTRLEN(s->filter);
        *p++ = (byte)s->qos;
        *p++ = 0; /* reserved */
        wmqb_w_u16(p, flen); p += 2;
        XMEMCPY(p, s->filter, flen); p += flen;
    }
#else
    for (sub = broker->subs; sub != NULL; sub = sub->next) {
        word16 flen;
        if (sub->client_id == NULL ||
            XSTRCMP(sub->client_id, client_id) != 0 ||
            sub->filter == NULL) {
            continue;
        }
        flen = (word16)XSTRLEN(sub->filter);
        *p++ = (byte)sub->qos;
        *p++ = 0; /* reserved */
        wmqb_w_u16(p, flen); p += 2;
        XMEMCPY(p, sub->filter, flen); p += flen;
    }
#endif

    rc = wmqb_kv_put_commit(broker, BROKER_PERSIST_NS_SUBS,
        (const byte*)client_id, cid_len, buf, total_len);
    WOLFMQTT_FREE(buf);
    return rc;
}

int BrokerPersist_DelSubs(MqttBroker* broker, const char* client_id)
{
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
    return wmqb_kv_del_commit(broker, BROKER_PERSIST_NS_SUBS,
        (const byte*)client_id, (word16)XSTRLEN(client_id));
}

/* Snapshot a retained message into a persisted record.
 *
 * Body layout:
 *   off  size   field
 *     0    1    qos
 *     1    1    _reserved
 *     2    8    store_time   (big endian, seconds since epoch)
 *    10    4    expiry_sec   (big endian, 0 == no expiry)
 *    14    2    topic_len    (big endian)
 *    16    N    topic
 *    16+N 4     payload_len  (big endian)
 *    20+N M     payload
 *
 * Key is the topic bytes. */
int BrokerPersist_PutRetained(MqttBroker* broker,
    const struct BrokerRetainedMsg* rm)
{
    const BrokerRetainedMsg* m = (const BrokerRetainedMsg*)rm;
    const char* topic;
    word16 topic_len;
    word32 payload_len;
    const byte* payload;
    word32 body_len;
    word32 total_len;
    byte*  buf;
    byte*  p;
    int    rc;

    if (broker == NULL || broker->persist == NULL || m == NULL) {
        return 0;
    }
    topic = m->topic;
    if (topic == NULL || *topic == '\0') {
        return 0;
    }
    topic_len = (word16)XSTRLEN(topic);
    payload_len = m->payload_len;
    payload = m->payload;

    body_len = 1 + 1 + 8 + 4 + 2 + topic_len + 4 + payload_len;
    total_len = WMQB_HDR_LEN + body_len;
    buf = (byte*)WOLFMQTT_MALLOC(total_len);
    if (buf == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    wmqb_write_header(buf, BROKER_PERSIST_NS_RETAINED, body_len);
    p = &buf[WMQB_HDR_LEN];
    *p++ = (byte)m->qos;
    *p++ = 0;
    wmqb_w_u64(p, (word64)m->store_time); p += 8;
    wmqb_w_u32(p, m->expiry_sec); p += 4;
    wmqb_w_u16(p, topic_len); p += 2;
    XMEMCPY(p, topic, topic_len); p += topic_len;
    wmqb_w_u32(p, payload_len); p += 4;
    if (payload_len > 0 && payload != NULL) {
        XMEMCPY(p, payload, payload_len);
    }

    rc = wmqb_kv_put_commit(broker, BROKER_PERSIST_NS_RETAINED,
        (const byte*)topic, topic_len, buf, total_len);
    WOLFMQTT_FREE(buf);
    return rc;
}

int BrokerPersist_DelRetained(MqttBroker* broker, const char* topic)
{
    if (broker == NULL || broker->persist == NULL || topic == NULL) {
        return 0;
    }
    return wmqb_kv_del_commit(broker, BROKER_PERSIST_NS_RETAINED,
        (const byte*)topic, (word16)XSTRLEN(topic));
}

/* OUTQ key encoding:  client_id_bytes || 0x00 || packet_id_be(2 bytes).
 * The trailing 0x00 separator + fixed-width packet_id keep the key
 * deterministic for any client_id (which can itself contain arbitrary
 * UTF-8). 0x00 is illegal in MQTT-valid client_ids
 * ([MQTT-3.1.3-5] rejects null chars), so the separator is unambiguous. */
static int wmqb_outq_build_key(const char* client_id, word16 packet_id,
    byte* out_key, word16 out_cap, word16* out_len)
{
    size_t cid_len;
    if (client_id == NULL || out_key == NULL || out_len == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    cid_len = XSTRLEN(client_id);
    if (cid_len + 1 + 2 > out_cap) {
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    }
    XMEMCPY(out_key, client_id, cid_len);
    out_key[cid_len] = 0x00;
    wmqb_w_u16(&out_key[cid_len + 1], packet_id);
    *out_len = (word16)(cid_len + 3);
    return 0;
}

/* Snapshot a single outbound-queue entry into a persisted record.
 *
 * Body layout:
 *   off  size   field
 *     0    1    state          (BROKER_OUTQ_*)
 *     1    1    qos
 *     2    1    retain
 *     3    1    protocol_level
 *     4    2    _reserved
 *     6    2    packet_id      (redundant with key, simplifies decode)
 *     8    8    enq_time
 *    16    4    expiry_sec
 *    20    2    topic_len
 *    22    N    topic
 *  22+N    4    payload_len
 *  26+N    M    payload                                                       */
int BrokerPersist_PutOutPub(MqttBroker* broker, const char* client_id,
    const struct BrokerOutPub* e)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    /* BrokerOutPub is dynamic-memory only; static-memory builds keep
     * synchronous fan-out and therefore have no outbound queue to
     * persist. The function symbol still exists so static and dynamic
     * builds share the same ABI. */
    (void)broker; (void)client_id; (void)e;
    return 0;
#else
    const BrokerOutPub* p_e = (const BrokerOutPub*)e;
    word16 topic_len;
    word32 payload_len;
    word32 body_len;
    word32 total_len;
    byte*  buf;
    byte*  bp;
    byte   key[256 + 3];
    word16 key_len;
    int    rc;

    if (broker == NULL || broker->persist == NULL ||
            client_id == NULL || p_e == NULL) {
        return 0;
    }
    /* QoS 0 entries are not persisted per [MQTT-3.3.1-3]; if they
     * leak in here, no-op. */
    if (p_e->qos == MQTT_QOS_0) {
        return 0;
    }
    if (p_e->topic == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    topic_len = (word16)XSTRLEN(p_e->topic);
    payload_len = p_e->payload_len;

    rc = wmqb_outq_build_key(client_id, p_e->packet_id, key, sizeof(key),
            &key_len);
    if (rc != 0) {
        return rc;
    }
    body_len = 1 + 1 + 1 + 1 + 2 + 2 + 8 + 4 + 2 + topic_len + 4
                + payload_len;
    total_len = WMQB_HDR_LEN + body_len;
    buf = (byte*)WOLFMQTT_MALLOC(total_len);
    if (buf == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    wmqb_write_header(buf, BROKER_PERSIST_NS_OUTQ, body_len);
    bp = &buf[WMQB_HDR_LEN];
    *bp++ = p_e->state;
    *bp++ = (byte)p_e->qos;
    *bp++ = p_e->retain;
    *bp++ = p_e->protocol_level;
    *bp++ = 0; *bp++ = 0;  /* _reserved */
    wmqb_w_u16(bp, p_e->packet_id); bp += 2;
    wmqb_w_u64(bp, (word64)p_e->enq_time); bp += 8;
    wmqb_w_u32(bp, p_e->expiry_sec); bp += 4;
    wmqb_w_u16(bp, topic_len); bp += 2;
    XMEMCPY(bp, p_e->topic, topic_len); bp += topic_len;
    wmqb_w_u32(bp, payload_len); bp += 4;
    if (payload_len > 0 && p_e->payload != NULL) {
        XMEMCPY(bp, p_e->payload, payload_len);
    }

    rc = wmqb_kv_put_commit(broker, BROKER_PERSIST_NS_OUTQ,
        key, key_len, buf, total_len);
    WOLFMQTT_FREE(buf);
    return rc;
#endif /* WOLFMQTT_STATIC_MEMORY */
}

int BrokerPersist_DelOutPub(MqttBroker* broker, const char* client_id,
    word16 packet_id)
{
    byte key[256 + 3];
    word16 key_len;
    int rc;
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
    rc = wmqb_outq_build_key(client_id, packet_id, key, sizeof(key),
            &key_len);
    if (rc != 0) {
        return rc;
    }
    return wmqb_kv_del_commit(broker, BROKER_PERSIST_NS_OUTQ,
        key, key_len);
}

#ifndef WOLFMQTT_STATIC_MEMORY
/* Key-collection list used by DelOutQueue and the schema-wipe iter. A
 * single linked node of (key bytes, len) so iter callbacks can stash
 * keys and the caller can del them after iteration finishes. */
struct wmqb_wipe_key {
    word16 key_len;
    byte*  key;
    struct wmqb_wipe_key* next;
};

/* DelOutQueue iterator context: matches against client_id prefix and
 * collects keys to delete after iteration completes. */
struct wmqb_delq_ctx {
    const byte* cid;
    word16 cid_len;
    struct wmqb_wipe_key* head;
};

static int wmqb_delq_iter_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx)
{
    struct wmqb_delq_ctx* dq = (struct wmqb_delq_ctx*)cb_ctx;
    struct wmqb_wipe_key* node;
    (void)blob; (void)blob_len;
    /* Match key prefix: cid bytes followed by 0x00. */
    if (key_len < (word16)(dq->cid_len + 1)) {
        return 0;
    }
    if (XMEMCMP(key, dq->cid, dq->cid_len) != 0) {
        return 0;
    }
    if (key[dq->cid_len] != 0x00) {
        return 0;
    }
    node = (struct wmqb_wipe_key*)WOLFMQTT_MALLOC(sizeof(*node));
    if (node == NULL) {
        return 1;
    }
    node->key = (byte*)WOLFMQTT_MALLOC(key_len);
    if (node->key == NULL) {
        WOLFMQTT_FREE(node);
        return 1;
    }
    XMEMCPY(node->key, key, key_len);
    node->key_len = key_len;
    node->next = dq->head;
    dq->head = node;
    return 0;
}
#endif

int BrokerPersist_DelOutQueue(MqttBroker* broker, const char* client_id)
{
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
#ifdef WOLFMQTT_STATIC_MEMORY
    /* Static-memory backends typically lack a key-prefix iterator; the
     * orphan queue feature is dynamic-memory only in v1. */
    (void)client_id;
    return 0;
#else
    {
        const MqttBrokerPersistHooks* h = broker->persist;
        struct wmqb_delq_ctx ctx;
        struct wmqb_wipe_key* cur;
        int deleted = 0;
        if (h->kv_iter == NULL || h->kv_del == NULL) {
            return 0;
        }
        XMEMSET(&ctx, 0, sizeof(ctx));
        ctx.cid = (const byte*)client_id;
        ctx.cid_len = (word16)XSTRLEN(client_id);
        /* DelOutQueue only needs keys, not blob bodies - the wipe-key
         * iterator callback ignores blob bytes - so bypassing the
         * decrypt wrapper here is safe and avoids unnecessary AES
         * cycles. */
        (void)h->kv_iter(h->ctx, BROKER_PERSIST_NS_OUTQ,
            wmqb_delq_iter_cb, &ctx);
        cur = ctx.head;
        while (cur != NULL) {
            struct wmqb_wipe_key* next = cur->next;
            if (h->kv_del(h->ctx, BROKER_PERSIST_NS_OUTQ, cur->key,
                    cur->key_len) == 0) {
                deleted++;
            }
            WOLFMQTT_FREE(cur->key);
            WOLFMQTT_FREE(cur);
            cur = next;
        }
        if (h->sync != NULL) {
            (void)h->sync(h->ctx);
        }
        return deleted;
    }
#endif
}

/* META record. Body = 4-byte big-endian schema_ver (redundant with the
 * header check, but lets a stand-alone tool inspect the file without
 * knowing the broker's header format). Key is the single zero byte. */
static int wmqb_meta_check(MqttBroker* broker, int* out_present)
{
    const MqttBrokerPersistHooks* h = broker->persist;
    const byte meta_key = 0;
    byte buf[WMQB_HDR_LEN + 4];
    word32 cap = sizeof(buf);
    int rc;
    word32 body_len = 0;

    if (out_present != NULL) {
        *out_present = 0;
    }
    if (h->kv_get == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
#ifdef WOLFMQTT_BROKER_PERSIST_ENCRYPT
    rc = wmqb_kv_get_decrypt(broker, BROKER_PERSIST_NS_META, &meta_key, 1,
            buf, &cap);
#else
    rc = h->kv_get(h->ctx, BROKER_PERSIST_NS_META, &meta_key, 1, buf, &cap);
#endif
    if (rc != 0) {
        /* Treat any backend error as "no META yet". First run.
         * Schema-bit mismatch also lands here: an encrypted META read
         * by a plaintext build (or vice versa) fails decryption /
         * size check, schema_check returns 0 not-present, and the
         * caller does wipe-and-restart. */
        return 0;
    }
    if (cap < WMQB_HDR_LEN + 4) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (out_present != NULL) {
        *out_present = 1;
    }
    return wmqb_read_header(buf, cap, BROKER_PERSIST_NS_META, &body_len);
}

/* Write the current META record so subsequent runs detect schema match. */
static int wmqb_meta_write(MqttBroker* broker)
{
    const byte meta_key = 0;
    byte buf[WMQB_HDR_LEN + 4];
    wmqb_write_header(buf, BROKER_PERSIST_NS_META, 4);
    wmqb_w_u32(&buf[WMQB_HDR_LEN], WOLFMQTT_BROKER_PERSIST_SCHEMA_VER);
    return wmqb_kv_put_commit(broker, BROKER_PERSIST_NS_META,
        &meta_key, 1, buf, sizeof(buf));
}

/* Restore iterator context. Used for retained-msg, subs, session,
 * and OUTQ callbacks. */
struct wmqb_restore_ctx {
    MqttBroker* broker;
    int         loaded;
    int         skipped;
};

#ifndef WOLFMQTT_STATIC_MEMORY
/* Create an orphan slot from a NS_SESSION record. Does NOT call the
 * shadow-write Put hook (would be circular). Returns the new orphan
 * or NULL on failure. */
static BrokerOrphanSession* wmqb_restore_create_orphan(MqttBroker* broker,
    const byte* client_id, word16 cid_len, byte protocol_level,
    word32 session_expiry_sec)
{
    BrokerOrphanSession* o;
    if (broker == NULL || client_id == NULL || cid_len == 0) {
        return NULL;
    }
    if (broker->orphan_session_count >= BROKER_MAX_PERSIST_SESSIONS) {
        /* Cap is enforced when records are written, so the persisted
         * set should fit. If it does not (e.g., macro reduced between
         * runs), the oldest restored sessions get skipped. */
        return NULL;
    }
    o = (BrokerOrphanSession*)WOLFMQTT_MALLOC(sizeof(*o));
    if (o == NULL) {
        return NULL;
    }
    XMEMSET(o, 0, sizeof(*o));
    o->client_id = (char*)WOLFMQTT_MALLOC((size_t)cid_len + 1);
    if (o->client_id == NULL) {
        WOLFMQTT_FREE(o);
        return NULL;
    }
    XMEMCPY(o->client_id, client_id, cid_len);
    o->client_id[cid_len] = '\0';
    o->protocol_level = protocol_level;
    o->session_expiry_sec = session_expiry_sec;
    o->orphan_since = WOLFMQTT_BROKER_GET_TIME_S();
    o->next = broker->orphan_sessions;
    broker->orphan_sessions = o;
    broker->orphan_session_count++;
    return o;
}

/* Locate an existing orphan by client_id (linear scan; pool is small
 * by design). NULL if none. */
static BrokerOrphanSession* wmqb_restore_find_orphan(MqttBroker* broker,
    const byte* client_id, word16 cid_len)
{
    BrokerOrphanSession* cur;
    if (broker == NULL || client_id == NULL) {
        return NULL;
    }
    for (cur = broker->orphan_sessions; cur != NULL; cur = cur->next) {
        if (cur->client_id == NULL) {
            continue;
        }
        if (XSTRLEN(cur->client_id) == cid_len &&
                XMEMCMP(cur->client_id, client_id, cid_len) == 0) {
            return cur;
        }
    }
    return NULL;
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

/* Allocate and insert a retained-message node from a decoded NS_RETAINED
 * blob. Dynamic mode prepends a heap node onto broker->retained; static
 * mode copies into the first free slot of broker->retained[]. Mirrors
 * BrokerRetained_Store but without the already-exists merge logic
 * (every key is fresh at startup). */
static int wmqb_decode_and_insert_retained(MqttBroker* broker,
    const byte* blob, word32 blob_len)
{
    word32 body_len = 0;
    int rc;
    const byte* p;
    const byte* end;
    word16 topic_len;
    word32 payload_len;
    word64 store_time;
    word32 expiry;
    byte qos;

    rc = wmqb_read_header(blob, blob_len, BROKER_PERSIST_NS_RETAINED,
            &body_len);
    if (rc != 0) {
        return rc;
    }
    p = &blob[WMQB_HDR_LEN];
    end = p + body_len;
    if ((word32)(end - p) < 1 + 1 + 8 + 4 + 2) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    qos = *p++;
    p++; /* _reserved */
    store_time = wmqb_r_u64(p); p += 8;
    expiry = wmqb_r_u32(p); p += 4;
    topic_len = wmqb_r_u16(p); p += 2;
    if ((word32)(end - p) < (word32)topic_len + 4) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        BrokerRetainedMsg* slot = NULL;
        if (topic_len + 1 > BROKER_MAX_TOPIC_LEN) {
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        for (i = 0; i < BROKER_MAX_RETAINED; i++) {
            if (!broker->retained[i].in_use) {
                slot = &broker->retained[i];
                break;
            }
        }
        if (slot == NULL) {
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        XMEMSET(slot, 0, sizeof(*slot));
        slot->in_use = 1;
        XMEMCPY(slot->topic, p, topic_len);
        slot->topic[topic_len] = '\0';
        p += topic_len;
        payload_len = wmqb_r_u32(p); p += 4;
        if ((word32)(end - p) < payload_len ||
                payload_len > BROKER_MAX_PAYLOAD_LEN) {
            XMEMSET(slot, 0, sizeof(*slot));
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
        if (payload_len > 0) {
            XMEMCPY(slot->payload, p, payload_len);
        }
        slot->payload_len = payload_len;
        slot->qos = (MqttQoS)qos;
        slot->store_time = (WOLFMQTT_BROKER_TIME_T)store_time;
        slot->expiry_sec = expiry;
    }
#else
    {
        BrokerRetainedMsg* m;
        m = (BrokerRetainedMsg*)WOLFMQTT_MALLOC(sizeof(*m));
        if (m == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        XMEMSET(m, 0, sizeof(*m));
        m->topic = (char*)WOLFMQTT_MALLOC((size_t)topic_len + 1);
        if (m->topic == NULL) {
            WOLFMQTT_FREE(m);
            return MQTT_CODE_ERROR_MEMORY;
        }
        XMEMCPY(m->topic, p, topic_len);
        m->topic[topic_len] = '\0';
        p += topic_len;

        payload_len = wmqb_r_u32(p); p += 4;
        if ((word32)(end - p) < payload_len) {
            WOLFMQTT_FREE(m->topic);
            WOLFMQTT_FREE(m);
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
        if (payload_len > 0) {
            m->payload = (byte*)WOLFMQTT_MALLOC(payload_len);
            if (m->payload == NULL) {
                WOLFMQTT_FREE(m->topic);
                WOLFMQTT_FREE(m);
                return MQTT_CODE_ERROR_MEMORY;
            }
            XMEMCPY(m->payload, p, payload_len);
        }
        m->payload_len = payload_len;
        m->qos = (MqttQoS)qos;
        m->store_time = (WOLFMQTT_BROKER_TIME_T)store_time;
        m->expiry_sec = expiry;
        m->next = broker->retained;
        broker->retained = m;
    }
#endif
    return 0;
}

static int wmqb_iter_retained_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx)
{
    struct wmqb_restore_ctx* c = (struct wmqb_restore_ctx*)cb_ctx;
    int rc;
    (void)key; (void)key_len;
    rc = wmqb_decode_and_insert_retained(c->broker, blob, blob_len);
    if (rc == 0) {
        c->loaded++;
    }
    else {
        c->skipped++;
    }
    return 0; /* always continue */
}

/* Allocate orphan subs from a decoded NS_SUBS blob. The blob key carries
 * the client_id - subs created here have client=NULL, client_id set;
 * the existing BrokerSubs_ReassociateClient path on reconnect rebinds
 * them to the new BrokerClient.
 *
 * All-or-nothing: decode into a local working list (dynamic) or a
 * tracked slot-index array (static) first, then commit on success.
 * If any entry fails to decode or allocate, the partial work is rolled
 * back so broker->subs (and slot.in_use flags) end up exactly as they
 * were on entry. */
static int wmqb_decode_and_insert_subs(MqttBroker* broker,
    const byte* key, word16 key_len, const byte* blob, word32 blob_len)
{
    word32 body_len = 0;
    int rc;
    const byte* p;
    const byte* end;
    word16 count;
    word16 i;
#ifdef WOLFMQTT_STATIC_MEMORY
    /* Track slots we claimed in this call so we can release on failure.
     * BROKER_MAX_SUBS bounds the working set; allocating on the stack
     * keeps the failure path simple. */
    int claimed[BROKER_MAX_SUBS];
    int claimed_count = 0;
    int j;
#else
    BrokerSub* local_head = NULL;
    BrokerSub* local_tail = NULL;
#endif

    rc = wmqb_read_header(blob, blob_len, BROKER_PERSIST_NS_SUBS,
            &body_len);
    if (rc != 0) {
        return rc;
    }
    if (key == NULL || key_len == 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    p = &blob[WMQB_HDR_LEN];
    end = p + body_len;
    if ((word32)(end - p) < 2) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    count = wmqb_r_u16(p); p += 2;

    for (i = 0; i < count; i++) {
        byte qos;
        word16 flen;

        if ((word32)(end - p) < 4) {
            rc = MQTT_CODE_ERROR_MALFORMED_DATA;
            goto rollback;
        }
        qos = *p++;
        p++; /* options reserved */
        flen = wmqb_r_u16(p); p += 2;
        if ((word32)(end - p) < flen) {
            rc = MQTT_CODE_ERROR_MALFORMED_DATA;
            goto rollback;
        }

#ifdef WOLFMQTT_STATIC_MEMORY
        {
            BrokerSub* slot = NULL;
            int k;
            if (flen + 1 > BROKER_MAX_FILTER_LEN ||
                    key_len + 1 > BROKER_MAX_CLIENT_ID_LEN) {
                rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
                goto rollback;
            }
            for (k = 0; k < BROKER_MAX_SUBS; k++) {
                if (!broker->subs[k].in_use) {
                    slot = &broker->subs[k];
                    claimed[claimed_count++] = k;
                    break;
                }
            }
            if (slot == NULL) {
                rc = MQTT_CODE_ERROR_OUT_OF_BUFFER;
                goto rollback;
            }
            XMEMSET(slot, 0, sizeof(*slot));
            slot->in_use = 1;
            XMEMCPY(slot->filter, p, flen);
            slot->filter[flen] = '\0';
            XMEMCPY(slot->client_id, key, key_len);
            slot->client_id[key_len] = '\0';
            slot->client = NULL; /* orphan until reconnect */
            slot->qos = (MqttQoS)qos;
        }
        p += flen;
#else
        {
            BrokerSub* sub;
            char* cid;
            sub = (BrokerSub*)WOLFMQTT_MALLOC(sizeof(*sub));
            if (sub == NULL) {
                rc = MQTT_CODE_ERROR_MEMORY;
                goto rollback;
            }
            XMEMSET(sub, 0, sizeof(*sub));
            sub->filter = (char*)WOLFMQTT_MALLOC((size_t)flen + 1);
            if (sub->filter == NULL) {
                WOLFMQTT_FREE(sub);
                rc = MQTT_CODE_ERROR_MEMORY;
                goto rollback;
            }
            XMEMCPY(sub->filter, p, flen);
            sub->filter[flen] = '\0';
            p += flen;

            cid = (char*)WOLFMQTT_MALLOC((size_t)key_len + 1);
            if (cid == NULL) {
                WOLFMQTT_FREE(sub->filter);
                WOLFMQTT_FREE(sub);
                rc = MQTT_CODE_ERROR_MEMORY;
                goto rollback;
            }
            XMEMCPY(cid, key, key_len);
            cid[key_len] = '\0';
            sub->client_id = cid;
            sub->client = NULL; /* orphan until reconnect */
            sub->qos = (MqttQoS)qos;
            sub->next = NULL;

            /* Append to local list (preserve decode order so the
             * eventual broker->subs walk sees the same order as a
             * shadow-write would have produced). */
            if (local_tail == NULL) {
                local_head = sub;
            }
            else {
                local_tail->next = sub;
            }
            local_tail = sub;
        }
#endif
    }

    /* All entries decoded - splice into broker->subs. For dynamic mode,
     * prepend the local list head-first to match the existing
     * shadow-write order; tail->next is set to the prior head. */
#ifndef WOLFMQTT_STATIC_MEMORY
    if (local_head != NULL) {
        local_tail->next = broker->subs;
        broker->subs = local_head;
    }
#else
    (void)j;
#endif
    return 0;

rollback:
#ifdef WOLFMQTT_STATIC_MEMORY
    for (j = 0; j < claimed_count; j++) {
        XMEMSET(&broker->subs[claimed[j]], 0, sizeof(BrokerSub));
    }
#else
    while (local_head != NULL) {
        BrokerSub* nxt = local_head->next;
        if (local_head->filter != NULL) {
            WOLFMQTT_FREE(local_head->filter);
        }
        if (local_head->client_id != NULL) {
            WOLFMQTT_FREE(local_head->client_id);
        }
        WOLFMQTT_FREE(local_head);
        local_head = nxt;
    }
#endif
    return rc;
}

static int wmqb_iter_subs_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx)
{
    struct wmqb_restore_ctx* c = (struct wmqb_restore_ctx*)cb_ctx;
    int rc;
    rc = wmqb_decode_and_insert_subs(c->broker, key, key_len, blob,
            blob_len);
    if (rc == 0) {
        c->loaded++;
    }
    else {
        c->skipped++;
    }
    return 0;
}

#ifndef WOLFMQTT_STATIC_MEMORY
/* Decode NS_SESSION record and create a matching orphan slot. */
static int wmqb_decode_and_insert_session(MqttBroker* broker,
    const byte* blob, word32 blob_len)
{
    word32 body_len = 0;
    int rc;
    byte proto_level;
    word32 session_expiry;
    word16 cid_len;
    const byte* p;
    rc = wmqb_read_header(blob, blob_len, BROKER_PERSIST_NS_SESSION,
            &body_len);
    if (rc != 0) {
        return rc;
    }
    if (body_len < 1 + 1 + 4 + 2) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    p = &blob[WMQB_HDR_LEN];
    proto_level = p[0];
    /* p[1] reserved */
    session_expiry = wmqb_r_u32(&p[2]);
    cid_len = wmqb_r_u16(&p[6]);
    if (body_len < (word32)(8 + cid_len)) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (wmqb_restore_create_orphan(broker, &p[8], cid_len, proto_level,
            session_expiry) == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    return 0;
}

static int wmqb_iter_session_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx)
{
    struct wmqb_restore_ctx* c = (struct wmqb_restore_ctx*)cb_ctx;
    int rc;
    (void)key; (void)key_len;
    rc = wmqb_decode_and_insert_session(c->broker, blob, blob_len);
    if (rc == 0) {
        c->loaded++;
    }
    else {
        c->skipped++;
    }
    return 0;
}

/* Decode NS_OUTQ record and append to the matching orphan's queue.
 * Insertion is sorted by enq_time so replay preserves publish order. */
static int wmqb_decode_and_insert_outq(MqttBroker* broker,
    const byte* key, word16 key_len, const byte* blob, word32 blob_len)
{
    word32 body_len = 0;
    int rc;
    const byte* p;
    const byte* end;
    BrokerOrphanSession* o;
    BrokerOutPub* e;
    word16 cid_len;
    word16 topic_len;
    word32 payload_len;
    byte   state;
    byte   qos;
    byte   retain;
    byte   protocol_level;
    word16 packet_id;
    word64 enq_time;
    word32 expiry_sec;
    BrokerOutPub** prev_link;
    BrokerOutPub*  iter;

    if (key == NULL || key_len < 3) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    cid_len = key_len - 3; /* key = cid || 0x00 || pid_be(2) */
    if (key[cid_len] != 0x00) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    rc = wmqb_read_header(blob, blob_len, BROKER_PERSIST_NS_OUTQ,
            &body_len);
    if (rc != 0) {
        return rc;
    }
    if (body_len < 22) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    p = &blob[WMQB_HDR_LEN];
    end = p + body_len;
    state = *p++;
    qos = *p++;
    retain = *p++;
    protocol_level = *p++;
    p += 2; /* _reserved */
    packet_id = wmqb_r_u16(p); p += 2;
    enq_time = wmqb_r_u64(p); p += 8;
    expiry_sec = wmqb_r_u32(p); p += 4;
    topic_len = wmqb_r_u16(p); p += 2;
    if ((word32)(end - p) < (word32)topic_len + 4) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }

    o = wmqb_restore_find_orphan(broker, key, cid_len);
    if (o == NULL) {
        /* OUTQ record without a matching session - orphan record
         * leakage. Skip but keep the on-disk record intact; a wipe
         * pass would clean these up. */
        return MQTT_CODE_ERROR_NOT_FOUND;
    }

    e = (BrokerOutPub*)WOLFMQTT_MALLOC(sizeof(*e));
    if (e == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(e, 0, sizeof(*e));
    e->topic = (char*)WOLFMQTT_MALLOC((size_t)topic_len + 1);
    if (e->topic == NULL) {
        WOLFMQTT_FREE(e);
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMCPY(e->topic, p, topic_len);
    e->topic[topic_len] = '\0';
    p += topic_len;

    payload_len = wmqb_r_u32(p); p += 4;
    if ((word32)(end - p) < payload_len) {
        WOLFMQTT_FREE(e->topic);
        WOLFMQTT_FREE(e);
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (payload_len > 0) {
        e->payload = (byte*)WOLFMQTT_MALLOC(payload_len);
        if (e->payload == NULL) {
            WOLFMQTT_FREE(e->topic);
            WOLFMQTT_FREE(e);
            return MQTT_CODE_ERROR_MEMORY;
        }
        XMEMCPY(e->payload, p, payload_len);
    }
    e->payload_len = payload_len;
    e->qos = (MqttQoS)qos;
    e->packet_id = packet_id;
    e->retain = retain;
    e->state = state;
    e->enq_time = (WOLFMQTT_BROKER_TIME_T)enq_time;
    e->expiry_sec = expiry_sec;
    e->protocol_level = protocol_level;

    /* Insertion-sort by (enq_time, packet_id) so replay preserves
     * publish order. Two messages enqueued within the same second
     * (broker time granularity is 1s) tie-break on packet_id, which
     * the broker hands out monotonically for the lifetime of a
     * process. Across a restart packet_id resets but ordering is
     * still preserved within each window since the saved enq_time
     * advances between windows. */
    prev_link = &o->out_q_head;
    iter = o->out_q_head;
    while (iter != NULL) {
        if (iter->enq_time < e->enq_time) {
            prev_link = &iter->next;
            iter = iter->next;
            continue;
        }
        if (iter->enq_time == e->enq_time &&
                iter->packet_id < e->packet_id) {
            prev_link = &iter->next;
            iter = iter->next;
            continue;
        }
        break;
    }
    e->next = iter;
    *prev_link = e;
    if (iter == NULL) {
        o->out_q_tail = e;
    }
    o->out_q_count++;
    if (state == BROKER_OUTQ_PUBLISH_SENT ||
            state == BROKER_OUTQ_PUBREL_SENT) {
        o->out_q_inflight++;
    }
    return 0;
}

static int wmqb_iter_outq_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx)
{
    struct wmqb_restore_ctx* c = (struct wmqb_restore_ctx*)cb_ctx;
    int rc;
    rc = wmqb_decode_and_insert_outq(c->broker, key, key_len, blob,
            blob_len);
    if (rc == 0) {
        c->loaded++;
    }
    else {
        c->skipped++;
    }
    return 0;
}

/* Sweep orphans whose v5 Session Expiry has elapsed. Cascades to subs
 * and OUTQ records via the existing helpers. */
static void wmqb_restore_expiry_sweep(MqttBroker* broker)
{
    BrokerOrphanSession* cur = broker->orphan_sessions;
    WOLFMQTT_BROKER_TIME_T now = WOLFMQTT_BROKER_GET_TIME_S();
    while (cur != NULL) {
        BrokerOrphanSession* next = cur->next;
        /* Sign-safe elapsed-time check. The unsigned subtraction would
         * wrap to a huge positive value if the wall clock has stepped
         * backward since orphan_since was stamped (NTP step, RTC reset
         * on embedded targets); guard with the > test so a backward
         * jump never causes a spurious expiry. */
        if (cur->session_expiry_sec != 0xFFFFFFFFu &&
                cur->session_expiry_sec > 0 &&
                now >= cur->orphan_since &&
                (word64)(now - cur->orphan_since) >=
                    (word64)cur->session_expiry_sec) {
            WMQB_LOG_INFO(broker,
                "broker: persist expired session client_id=%s "
                "(expiry=%us)",
                cur->client_id == NULL ? "(null)" : cur->client_id,
                (unsigned)cur->session_expiry_sec);
            /* Shared teardown lives in mqtt_broker.c so the eviction
             * path and this expiry-sweep path can't drift. Drops
             * persisted records, the orphan's still-NULL-bound subs,
             * and unlinks + frees the orphan slot. */
            BrokerOrphan_DropFull(broker, cur);
        }
        cur = next;
    }
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

/* -------------------------------------------------------------------------- */
/* Schema-mismatch wipe                                                       */
/*                                                                            */
/* Walks each namespace, collects every key into a heap-grown list, then      */
/* deletes them one by one. Two-pass to avoid mutating the backend during     */
/* iteration. Only attempts the wipe when the backend implements both         */
/* kv_iter and kv_del; otherwise logs a warning and returns - new records    */
/* will overwrite by key as they arrive.                                      */
/* -------------------------------------------------------------------------- */
#ifndef WOLFMQTT_STATIC_MEMORY
/* wmqb_wipe_key struct defined above (shared with DelOutQueue). */

struct wmqb_wipe_ctx {
    struct wmqb_wipe_key* head;
    int collected;
    int alloc_failed;
};

static int wmqb_wipe_iter_cb(const byte* key, word16 key_len,
    const byte* blob, word32 blob_len, void* cb_ctx)
{
    struct wmqb_wipe_ctx* wc = (struct wmqb_wipe_ctx*)cb_ctx;
    struct wmqb_wipe_key* node;
    (void)blob; (void)blob_len;
    node = (struct wmqb_wipe_key*)WOLFMQTT_MALLOC(sizeof(*node));
    if (node == NULL) {
        wc->alloc_failed = 1;
        return 1; /* stop iteration; partial wipe is still useful */
    }
    node->key = (byte*)WOLFMQTT_MALLOC(key_len);
    if (node->key == NULL) {
        WOLFMQTT_FREE(node);
        wc->alloc_failed = 1;
        return 1;
    }
    XMEMCPY(node->key, key, key_len);
    node->key_len = key_len;
    node->next = wc->head;
    wc->head = node;
    wc->collected++;
    return 0;
}

static int wmqb_wipe_ns(MqttBroker* broker, byte ns)
{
    const MqttBrokerPersistHooks* h = broker->persist;
    struct wmqb_wipe_ctx wc;
    struct wmqb_wipe_key* cur;
    int deleted = 0;

    if (h->kv_iter == NULL || h->kv_del == NULL) {
        return 0;
    }
    XMEMSET(&wc, 0, sizeof(wc));
    (void)h->kv_iter(h->ctx, ns, wmqb_wipe_iter_cb, &wc);
    cur = wc.head;
    while (cur != NULL) {
        struct wmqb_wipe_key* next = cur->next;
        if (h->kv_del(h->ctx, ns, cur->key, cur->key_len) == 0) {
            deleted++;
        }
        WOLFMQTT_FREE(cur->key);
        WOLFMQTT_FREE(cur);
        cur = next;
    }
    if (h->sync != NULL) {
        (void)h->sync(h->ctx);
    }
    return deleted;
}
#endif /* !WOLFMQTT_STATIC_MEMORY */

static int wmqb_wipe_all(MqttBroker* broker)
{
#ifdef WOLFMQTT_STATIC_MEMORY
    /* Static-memory builds typically pair with backends that lack a
     * full kv_iter (e.g., raw flash). Skip the active wipe; new records
     * overwrite by key as they arrive, and orphan files linger
     * harmlessly. */
    WMQB_LOG_INFO(broker,
        "broker: persist wipe skipped (STATIC_MEMORY mode)");
    return 0;
#else
    int total = 0;
    if (broker == NULL || broker->persist == NULL) {
        return 0;
    }
    total += wmqb_wipe_ns(broker, BROKER_PERSIST_NS_META);
    total += wmqb_wipe_ns(broker, BROKER_PERSIST_NS_SESSION);
    total += wmqb_wipe_ns(broker, BROKER_PERSIST_NS_SUBS);
    total += wmqb_wipe_ns(broker, BROKER_PERSIST_NS_RETAINED);
    total += wmqb_wipe_ns(broker, BROKER_PERSIST_NS_OUTQ);
    WMQB_LOG_INFO(broker, "broker: persist wipe deleted=%d", total);
    return total;
#endif
}

int BrokerPersist_Restore(MqttBroker* broker)
{
    const MqttBrokerPersistHooks* h;
    int rc;
    int meta_present = 0;
    struct wmqb_restore_ctx ctx;

    if (broker == NULL || broker->persist == NULL) {
        return 0;
    }
    h = broker->persist;

    rc = wmqb_meta_check(broker, &meta_present);
    if (rc != 0) {
        /* Schema or magic mismatch. Wipe-and-restart per the chosen
         * policy: iterate every namespace, delete every record,
         * restamp META. New records get written fresh as activity
         * resumes. */
        WMQB_LOG_ERR(broker,
            "broker: persist schema mismatch - wiping all records");
        (void)wmqb_wipe_all(broker);
        return wmqb_meta_write(broker);
    }
    if (!meta_present) {
        /* First run - no state to restore. Just stamp META. */
        return wmqb_meta_write(broker);
    }

    XMEMSET(&ctx, 0, sizeof(ctx));
    ctx.broker = broker;
#ifndef WOLFMQTT_STATIC_MEMORY
    /* Sessions first so subs and OUTQ entries can find their owner. */
    if (h->kv_iter != NULL) {
        (void)wmqb_kv_iter(broker, BROKER_PERSIST_NS_SESSION,
            wmqb_iter_session_cb, &ctx);
        WMQB_LOG_INFO(broker,
            "broker: persist restore sessions loaded=%d skipped=%d",
            ctx.loaded, ctx.skipped);
        ctx.loaded = 0;
        ctx.skipped = 0;
    }
#endif
#ifdef WOLFMQTT_BROKER_RETAINED
    if (h->kv_iter != NULL) {
        (void)wmqb_kv_iter(broker, BROKER_PERSIST_NS_RETAINED,
            wmqb_iter_retained_cb, &ctx);
        WMQB_LOG_INFO(broker,
            "broker: persist restore retained loaded=%d skipped=%d",
            ctx.loaded, ctx.skipped);
        ctx.loaded = 0;
        ctx.skipped = 0;
    }
#endif
    if (h->kv_iter != NULL) {
        (void)wmqb_kv_iter(broker, BROKER_PERSIST_NS_SUBS,
            wmqb_iter_subs_cb, &ctx);
        WMQB_LOG_INFO(broker,
            "broker: persist restore subs loaded=%d skipped=%d",
            ctx.loaded, ctx.skipped);
        ctx.loaded = 0;
        ctx.skipped = 0;
    }
#ifndef WOLFMQTT_STATIC_MEMORY
    if (h->kv_iter != NULL) {
        (void)wmqb_kv_iter(broker, BROKER_PERSIST_NS_OUTQ,
            wmqb_iter_outq_cb, &ctx);
        WMQB_LOG_INFO(broker,
            "broker: persist restore outq loaded=%d skipped=%d",
            ctx.loaded, ctx.skipped);
    }
    /* v5 Session Expiry sweep: drop any orphan whose session_expiry has
     * elapsed since orphan_since was stamped. Cascades to its subs and
     * persisted OUTQ records via the existing helpers. */
    wmqb_restore_expiry_sweep(broker);
#endif
    return 0;
}

#endif /* WOLFMQTT_BROKER_PERSIST */
