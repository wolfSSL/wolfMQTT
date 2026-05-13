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
 *     6    2    rec_kind    = namespace echo (big endian)
 *     8    4    body_len    (big endian)
 *    12   ...   body        (encoding depends on namespace)
 *
 * The body encoding is intentionally simple: fixed-width header fields
 * first, variable-length strings/payloads last, lengths prefixed
 * big-endian. Forward compatibility is by schema-version bump + wipe.
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

#define WMQB_HDR_LEN  12

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

/* Write the 12-byte record header. Caller guarantees buf has room. */
static void wmqb_write_header(byte* buf, word16 rec_kind, word32 body_len)
{
    buf[0] = WOLFMQTT_BROKER_PERSIST_MAGIC0;
    buf[1] = WOLFMQTT_BROKER_PERSIST_MAGIC1;
    buf[2] = WOLFMQTT_BROKER_PERSIST_MAGIC2;
    buf[3] = WOLFMQTT_BROKER_PERSIST_MAGIC3;
    wmqb_w_u16(&buf[4], (word16)WOLFMQTT_BROKER_PERSIST_SCHEMA_VER);
    wmqb_w_u16(&buf[6], rec_kind);
    wmqb_w_u32(&buf[8], body_len);
}

/* Validate header against this build's schema. Returns 0 on match,
 * negative on magic or version mismatch. Body length is returned via
 * out_body_len. */
static WC_INLINE int wmqb_read_header(const byte* buf, word32 buf_len,
    word16 expect_kind, word32* out_body_len)
{
    if (buf_len < WMQB_HDR_LEN) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (buf[0] != WOLFMQTT_BROKER_PERSIST_MAGIC0 ||
        buf[1] != WOLFMQTT_BROKER_PERSIST_MAGIC1 ||
        buf[2] != WOLFMQTT_BROKER_PERSIST_MAGIC2 ||
        buf[3] != WOLFMQTT_BROKER_PERSIST_MAGIC3) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    if (wmqb_r_u16(&buf[4]) != WOLFMQTT_BROKER_PERSIST_SCHEMA_VER) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (wmqb_r_u16(&buf[6]) != expect_kind) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    if (out_body_len != NULL) {
        *out_body_len = wmqb_r_u32(&buf[8]);
    }
    if (*out_body_len > (buf_len - WMQB_HDR_LEN)) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    return 0;
}

/* Commit a blob to the backend and sync if available. Returns the hook's
 * return code, or 0 if hooks are disabled (silent no-op). */
static int wmqb_kv_put_commit(const MqttBrokerPersistHooks* h, byte ns,
    const byte* key, word16 key_len, const byte* blob, word32 blob_len)
{
    int rc;
    if (h == NULL || h->kv_put == NULL) {
        return 0;
    }
    rc = h->kv_put(h->ctx, ns, key, key_len, blob, blob_len);
    if (rc == 0 && h->sync != NULL) {
        (void)h->sync(h->ctx);
    }
    return rc;
}

static int wmqb_kv_del_commit(const MqttBrokerPersistHooks* h, byte ns,
    const byte* key, word16 key_len)
{
    int rc;
    if (h == NULL || h->kv_del == NULL) {
        return 0;
    }
    rc = h->kv_del(h->ctx, ns, key, key_len);
    if (rc == 0 && h->sync != NULL) {
        (void)h->sync(h->ctx);
    }
    return rc;
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
    /* Session Expiry plumbed in P3 once parsed from v5 CONNECT props;
     * for now mark "never expires" which is the v3.1.1 persistent-session
     * default and a safe v5 fallback. */
    wmqb_w_u32(&buf[WMQB_HDR_LEN + 2], 0xFFFFFFFFu);
    wmqb_w_u16(&buf[WMQB_HDR_LEN + 6], cid_len);
    XMEMCPY(&buf[WMQB_HDR_LEN + 8], cid, cid_len);

    rc = wmqb_kv_put_commit(broker->persist, BROKER_PERSIST_NS_SESSION,
        (const byte*)cid, cid_len, buf, total_len);
    WOLFMQTT_FREE(buf);
    return rc;
}

int BrokerPersist_DelSession(MqttBroker* broker, const char* client_id)
{
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
    return wmqb_kv_del_commit(broker->persist, BROKER_PERSIST_NS_SESSION,
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
    cid_len = (word16)XSTRLEN(client_id);

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
        return wmqb_kv_del_commit(broker->persist, BROKER_PERSIST_NS_SUBS,
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

    rc = wmqb_kv_put_commit(broker->persist, BROKER_PERSIST_NS_SUBS,
        (const byte*)client_id, cid_len, buf, total_len);
    WOLFMQTT_FREE(buf);
    return rc;
}

int BrokerPersist_DelSubs(MqttBroker* broker, const char* client_id)
{
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
    return wmqb_kv_del_commit(broker->persist, BROKER_PERSIST_NS_SUBS,
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

    rc = wmqb_kv_put_commit(broker->persist, BROKER_PERSIST_NS_RETAINED,
        (const byte*)topic, topic_len, buf, total_len);
    WOLFMQTT_FREE(buf);
    return rc;
}

int BrokerPersist_DelRetained(MqttBroker* broker, const char* topic)
{
    if (broker == NULL || broker->persist == NULL || topic == NULL) {
        return 0;
    }
    return wmqb_kv_del_commit(broker->persist, BROKER_PERSIST_NS_RETAINED,
        (const byte*)topic, (word16)XSTRLEN(topic));
}

int BrokerPersist_PutOutPub(MqttBroker* broker, const char* client_id,
    const struct BrokerOutPub* e)
{
    if (broker == NULL || broker->persist == NULL ||
        client_id == NULL || e == NULL) {
        return 0;
    }
    /* TODO P5: encode (client_id, packet_id) outq record and commit */
    return 0;
}

int BrokerPersist_DelOutPub(MqttBroker* broker, const char* client_id,
    word16 packet_id)
{
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
    /* TODO P5: del the (client_id, packet_id) record */
    (void)packet_id;
    return 0;
}

int BrokerPersist_DelOutQueue(MqttBroker* broker, const char* client_id)
{
    if (broker == NULL || broker->persist == NULL || client_id == NULL) {
        return 0;
    }
    /* TODO P5: iterate and remove all OUTQ entries for this client_id */
    return 0;
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
    rc = h->kv_get(h->ctx, BROKER_PERSIST_NS_META, &meta_key, 1, buf, &cap);
    if (rc != 0) {
        /* Treat any backend error as "no META yet". First run. */
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
    return wmqb_kv_put_commit(broker->persist, BROKER_PERSIST_NS_META,
        &meta_key, 1, buf, sizeof(buf));
}

/* Restore iterator context. Used for retained-msg and subs callbacks. */
struct wmqb_restore_ctx {
    MqttBroker* broker;
    int         loaded;
    int         skipped;
};

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
 * them to the new BrokerClient. */
static int wmqb_decode_and_insert_subs(MqttBroker* broker,
    const byte* key, word16 key_len, const byte* blob, word32 blob_len)
{
    word32 body_len = 0;
    int rc;
    const byte* p;
    const byte* end;
    word16 count;
    word16 i;

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
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
        qos = *p++;
        p++; /* options reserved */
        flen = wmqb_r_u16(p); p += 2;
        if ((word32)(end - p) < flen) {
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }

#ifdef WOLFMQTT_STATIC_MEMORY
        {
            int j;
            BrokerSub* slot = NULL;
            if (flen + 1 > BROKER_MAX_FILTER_LEN ||
                    key_len + 1 > BROKER_MAX_CLIENT_ID_LEN) {
                return MQTT_CODE_ERROR_OUT_OF_BUFFER;
            }
            for (j = 0; j < BROKER_MAX_SUBS; j++) {
                if (!broker->subs[j].in_use) {
                    slot = &broker->subs[j];
                    break;
                }
            }
            if (slot == NULL) {
                return MQTT_CODE_ERROR_OUT_OF_BUFFER;
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
                return MQTT_CODE_ERROR_MEMORY;
            }
            XMEMSET(sub, 0, sizeof(*sub));
            sub->filter = (char*)WOLFMQTT_MALLOC((size_t)flen + 1);
            if (sub->filter == NULL) {
                WOLFMQTT_FREE(sub);
                return MQTT_CODE_ERROR_MEMORY;
            }
            XMEMCPY(sub->filter, p, flen);
            sub->filter[flen] = '\0';
            p += flen;

            cid = (char*)WOLFMQTT_MALLOC((size_t)key_len + 1);
            if (cid == NULL) {
                WOLFMQTT_FREE(sub->filter);
                WOLFMQTT_FREE(sub);
                return MQTT_CODE_ERROR_MEMORY;
            }
            XMEMCPY(cid, key, key_len);
            cid[key_len] = '\0';
            sub->client_id = cid;
            sub->client = NULL; /* orphan until reconnect */
            sub->qos = (MqttQoS)qos;
            sub->next = broker->subs;
            broker->subs = sub;
        }
#endif
    }
    return 0;
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
struct wmqb_wipe_key {
    word16 key_len;
    byte*  key;
    struct wmqb_wipe_key* next;
};

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
#ifdef WOLFMQTT_BROKER_RETAINED
    if (h->kv_iter != NULL) {
        (void)h->kv_iter(h->ctx, BROKER_PERSIST_NS_RETAINED,
            wmqb_iter_retained_cb, &ctx);
        WMQB_LOG_INFO(broker,
            "broker: persist restore retained loaded=%d skipped=%d",
            ctx.loaded, ctx.skipped);
        ctx.loaded = 0;
        ctx.skipped = 0;
    }
#endif
    if (h->kv_iter != NULL) {
        (void)h->kv_iter(h->ctx, BROKER_PERSIST_NS_SUBS,
            wmqb_iter_subs_cb, &ctx);
        WMQB_LOG_INFO(broker,
            "broker: persist restore subs loaded=%d skipped=%d",
            ctx.loaded, ctx.skipped);
    }
    return 0;
}

#endif /* WOLFMQTT_BROKER_PERSIST */
