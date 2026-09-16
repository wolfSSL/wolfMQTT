/* mqtt_client.c
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

#include "wolfmqtt/mqtt_client.h"

/* Secure memory zeroing - uses volatile pointer to prevent the compiler
 * from optimizing away the stores (dead-store elimination).
 * Declared WOLFMQTT_LOCAL in mqtt_client.h so the MQTT-SN client can reuse it
 * (see SN_WillMessage) via the shared CLIENT_FORCE_ZERO macro. */
WOLFMQTT_LOCAL void MqttClient_ForceZero(void* mem, word32 len)
{
    volatile byte* p = (volatile byte*)mem;
    word32 i;
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

/* DOCUMENTED BUILD OPTIONS:
 *
 * WOLFMQTT_MULTITHREAD: Enables multi-thread support with mutex protection on
 *  client struct, write and read. When a pending response is needed its added
 *  to a linked list and if another thread reads the expected response it is
 *  flagged, so the other thread knows it completed.
 *
 * WOLFMQTT_NONBLOCK: Enabled transport support for returning WANT READ/WRITE,
 *  which becomes WOLFMQTT_CODE_CONTINUE. This prevents blocking if the
 *  transport (socket) has no data.
 *
 * WOLFMQTT_V5: Enables MQTT v5.0 support
 *
 * WOLFMQTT_ALLOW_NODATA_UNLOCK: Used with multi-threading and non-blocking to
 *   allow unlock if no data was sent/received. Note the TLS stack typically
 *   requires an attempt to write to continue with same write, not different.
 *   By default if we attempt a write we keep the mutex locked and return
 *   MQTT_CODE_CONTINUE
 *
 * WOLFMQTT_USER_THREADING: Allows custom mutex functions to be defined by the
 *  user. Example: wm_SemInit
 *
 * WOLFMQTT_DEBUG_CLIENT: Enables verbose PRINTF for the client code.
 */


/* Private functions */

#ifdef WOLFMQTT_MULTITHREAD
    #define MQTT_CLIENT_INIT_LOCK_SEND   0x01U
    #define MQTT_CLIENT_INIT_LOCK_RECV   0x02U
    #define MQTT_CLIENT_INIT_LOCK_CLIENT 0x04U
    #define MQTT_CLIENT_INIT_LOCK_CURL   0x08U
#endif

/* forward declarations */
static int MqttClient_Publish_ReadPayload(MqttClient* client,
    MqttPublish* publish, int timeout_ms);
#ifdef WOLFMQTT_V5
static int MqttClient_AuthEx(MqttClient *client, MqttAuth* auth,
    MqttMsgStat* stat,
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp* pend_resp,
#endif
    void* packet_obj);
#endif
#if !defined(WOLFMQTT_MULTITHREAD) && !defined(WOLFMQTT_NONBLOCK)
static int MqttClient_CancelMessage(MqttClient *client, MqttObject* msg);
#endif
#ifdef WOLFMQTT_MULTITHREAD

#ifdef WOLFMQTT_USER_THREADING

    /* User will supply their own semaphore functions.
     * int wm_SemInit(wm_Sem *s)
     * int wm_SemFree(wm_Sem *s)
     * int wm_SemLock(wm_Sem *s)
     * int wm_SemUnlock(wm_Sem *s)
     */

#elif defined(__MACH__)

    /* Apple style dispatch semaphore */
    int wm_SemInit(wm_Sem *s) {
        /* dispatch_release() fails hard, with Trace/BPT trap signal, if the
         * sem's internal count is less than the value passed in with
         * dispatch_semaphore_create().  work around this by initializing
         * with 0, then incrementing it afterwards.
         */
        s->sem = dispatch_semaphore_create(0);
        if (s->sem == NULL)
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MEMORY);
        if (dispatch_semaphore_signal(s->sem) < 0) {
            dispatch_release(s->sem);
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SYSTEM);
        }

        return 0;
    }
    int wm_SemFree(wm_Sem *s) {
        if ((s == NULL) ||
            (s->sem == NULL))
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        dispatch_release(s->sem);
        s->sem = NULL;
        return 0;
    }
    int wm_SemLock(wm_Sem *s) {
        dispatch_semaphore_wait(s->sem, DISPATCH_TIME_FOREVER);
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s){
        dispatch_semaphore_signal(s->sem);
        return 0;
    }
#elif defined(WOLFMQTT_POSIX_SEMAPHORES)
    /* Posix style semaphore */
    int wm_SemInit(wm_Sem *s) {
    #ifndef WOLFMQTT_NO_COND_SIGNAL
        s->lockCount = 0;
        pthread_cond_init(&s->cond, NULL);
    #endif
        pthread_mutex_init(&s->mutex, NULL);
        return 0;
    }
    int wm_SemFree(wm_Sem *s) {
        pthread_mutex_destroy(&s->mutex);
    #ifndef WOLFMQTT_NO_COND_SIGNAL
        pthread_cond_destroy(&s->cond);
    #endif
        return 0;
    }
    int wm_SemLock(wm_Sem *s) {
        pthread_mutex_lock(&s->mutex);
    #ifndef WOLFMQTT_NO_COND_SIGNAL
        while (s->lockCount > 0)
            pthread_cond_wait(&s->cond, &s->mutex);
        s->lockCount++;
        pthread_mutex_unlock(&s->mutex);
    #endif
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s) {
    #ifndef WOLFMQTT_NO_COND_SIGNAL
        pthread_mutex_lock(&s->mutex);
        if (s->lockCount > 0) {
            s->lockCount--;
            pthread_cond_signal(&s->cond);
        }
    #endif
        pthread_mutex_unlock(&s->mutex);
        return 0;
    }
#elif defined(FREERTOS)
    /* FreeRTOS binary semaphore */
    int wm_SemInit(wm_Sem *s) {
        *s = xSemaphoreCreateBinary();
        xSemaphoreGive(*s);
        return 0;
    }
    int wm_SemFree(wm_Sem *s) {
        vSemaphoreDelete(*s);
        *s = NULL;
        return 0;
    }
    int wm_SemLock(wm_Sem *s) {
        xSemaphoreTake(*s, portMAX_DELAY);
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s) {
        xSemaphoreGive(*s);
        return 0;
    }
#elif defined(USE_WINDOWS_API)
    /* Windows semaphore object */
    int wm_SemInit(wm_Sem *s) {
        *s = CreateSemaphoreW( NULL, 1, 1, NULL);
        return 0;
    }
    int wm_SemFree(wm_Sem *s) {
        CloseHandle(*s);
        *s = NULL;
        return 0;
    }
    int wm_SemLock(wm_Sem *s) {
        WaitForSingleObject(*s, INFINITE);
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s) {
        ReleaseSemaphore(*s, 1, NULL);
        return 0;
    }

#elif defined(THREADX)
    /* ThreadX semaphore */
    int wm_SemInit(wm_Sem *s) {
        if (tx_semaphore_create(s, NULL, 1) != TX_SUCCESS) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SYSTEM);
        }
        return 0;
    }
    int wm_SemFree(wm_Sem *s) {
        if (tx_semaphore_delete(s) != TX_SUCCESS) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SYSTEM);
        }
        return 0;
    }

    int wm_SemLock(wm_Sem *s) {
        UINT semstatus = tx_semaphore_get(s, TX_WAIT_FOREVER);
        if (semstatus != TX_SUCCESS) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SYSTEM);
        }
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s) {
        if (tx_semaphore_put(s) != TX_SUCCESS) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SYSTEM);
        }
        return 0;
    }
#endif /* MUTEX */
#endif /* WOLFMQTT_MULTITHREAD */

WOLFMQTT_LOCAL int MqttWriteStart(MqttClient* client, MqttMsgStat* stat)
{
    int rc = MQTT_CODE_SUCCESS;

#if defined(WOLFMQTT_DEBUG_CLIENT) || !defined(WOLFMQTT_ALLOW_NODATA_UNLOCK)
  #ifdef WOLFMQTT_DEBUG_CLIENT
    if (stat->isWriteActive) {
        MQTT_TRACE_MSG("Warning, send already locked!");
        rc = MQTT_CODE_ERROR_SYSTEM;
    }
  #endif
  #if !defined(WOLFMQTT_ALLOW_NODATA_UNLOCK) && \
      (!defined(WOLFMQTT_MULTITHREAD) || defined(WOLFMQTT_NONBLOCK) || \
       !defined(WOLFMQTT_THREAD_ID_T))
    /* Detect an in-progress write when the caller cannot wait for it. A
     * blocking build with thread identities instead distinguishes owner
     * reentry from another thread below. */
    #ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0)
    #endif
    {
        if (client->write.isActive) {
            MQTT_TRACE_MSG("Partial write in progress!");
            rc = MQTT_CODE_CONTINUE; /* can't write yet */
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }
  #endif
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#endif

#ifdef WOLFMQTT_MULTITHREAD
  #if !defined(WOLFMQTT_ALLOW_NODATA_UNLOCK) && \
      !defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_THREAD_ID_T)
    /* A blocking API may wait for another thread's write, but waiting on the
     * current thread's own non-recursive lockSend would deadlock. This occurs,
     * for example, when a streaming payload callback attempts another send or
     * an asynchronous transport leaves the writer active across reentry. */
    rc = wm_SemLock(&client->lockClient);
    if (rc == MQTT_CODE_SUCCESS) {
        if (client->write.isActive && client->write_owner_valid &&
                WOLFMQTT_THREAD_EQUAL(client->write_owner,
                    WOLFMQTT_THREAD_SELF())) {
            rc = MQTT_CODE_CONTINUE;
        }
        wm_SemUnlock(&client->lockClient);
    }
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
  #endif
    rc = wm_SemLock(&client->lockSend);
#endif
    if (rc == MQTT_CODE_SUCCESS) {
        stat->isWriteActive = 1;

    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0)
    #endif
        {
            client->write.isActive = 1;
        #if defined(WOLFMQTT_THREAD_ID_T)
            client->write_owner = WOLFMQTT_THREAD_SELF();
            client->write_owner_valid = 1;
        #endif
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockClient);
        #endif
        }

        MQTT_TRACE_MSG("lockSend");
    }

    return rc;
}
WOLFMQTT_LOCAL void MqttWriteStop(MqttClient* client, MqttMsgStat* stat)
{
#ifdef WOLFMQTT_DEBUG_CLIENT
    if (!stat->isWriteActive) {
        MQTT_TRACE_MSG("Warning, send not locked!");
        return;
    }
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0)
#endif
    {
        /* reset write */
        XMEMSET(&client->write, 0, sizeof(client->write));
    #if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_THREAD_ID_T)
        client->write_owner_valid = 0;
    #endif
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }

    if (stat->isWriteActive) {
        MQTT_TRACE_MSG("unlockSend");
        stat->isWriteActive = 0;
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
    }
}

WOLFMQTT_LOCAL int MqttReadStart(MqttClient* client, MqttMsgStat* stat)
{
    int rc = MQTT_CODE_SUCCESS;

#if defined(WOLFMQTT_DEBUG_CLIENT) || !defined(WOLFMQTT_ALLOW_NODATA_UNLOCK)
  #ifdef WOLFMQTT_DEBUG_CLIENT
    if (stat->isReadActive) {
        MQTT_TRACE_MSG("Warning, recv already locked!");
        rc = MQTT_CODE_ERROR_SYSTEM;
    }
  #endif /* WOLFMQTT_DEBUG_CLIENT */
  #ifndef WOLFMQTT_ALLOW_NODATA_UNLOCK
    /* detect if a read is already in progress */
    #ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0)
    #endif
    {
        if (client->read.isActive) {
            MQTT_TRACE_MSG("Partial read in progress!");
            rc = MQTT_CODE_CONTINUE; /* can't read yet */
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }
  #endif /* WOLFMQTT_ALLOW_NODATA_UNLOCK */
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#endif /* WOLFMQTT_DEBUG_CLIENT || !WOLFMQTT_ALLOW_NODATA_UNLOCK */

#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockRecv);
#endif
    if (rc == MQTT_CODE_SUCCESS) {
        stat->isReadActive = 1;

    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0)
    #endif
        {
            /* mark read active */
            client->read.isActive = 1;

            /* reset the packet state used by MqttPacket_Read */
            client->packet.stat = MQTT_PK_BEGIN;

        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockClient);
        #endif
        }

        MQTT_TRACE_MSG("lockRecv");
    }

    return rc;
}
WOLFMQTT_LOCAL void MqttReadStop(MqttClient* client, MqttMsgStat* stat)
{
#ifdef WOLFMQTT_DEBUG_CLIENT
    if (!stat->isReadActive) {
        MQTT_TRACE_MSG("Warning, recv not locked!");
        return;
    }
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0)
#endif
    {
        /* reset read */
        XMEMSET(&client->read, 0, sizeof(client->read));
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }

    if (stat->isReadActive) {
        MQTT_TRACE_MSG("unlockRecv");
        stat->isReadActive = 0;
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockRecv);
    #endif
    }
}

#ifdef WOLFMQTT_V5
/* Serialize the v5 Receive Maximum counter: the reserve runs on the send
 * path (lockSend) and the release on the read path (lockRecv), so the shared
 * word16 is guarded by lockClient to avoid a lost-update race. The per-message
 * recvQuotaHeld flag pairs each reserve with exactly one release so a stray,
 * duplicate, or unmatched ack cannot credit the quota twice. */
/* Atomically test-and-reserve one quota unit under lockClient (fixes the
 * unlocked exhaustion race). Returns 1 if a unit is held for this publish
 * (already held, or newly reserved), 0 if the quota is exhausted. */
static int MqttClient_RecvQuotaReserve(MqttClient* client,
    MqttPublish* publish)
{
    int reserved = 0;
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != 0) {
        return 1; /* lock failure: do not fail the publish on a quota race */
    }
#endif
    if (publish->stat.recvQuotaHeld) {
        reserved = 1;
    }
    else if (client->server_recv_max > 0) {
        client->server_recv_max--;
        publish->stat.recvQuotaHeld = 1;
        reserved = 1;
    }
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
    return reserved;
}

/* Credit one Receive Maximum unit back for this message. The caller must hold
 * lockClient (where applicable). Idempotent via recvQuotaHeld, so a second
 * release for the same message is a no-op. */
static void MqttClient_RecvQuotaRelease_Locked(MqttClient* client,
    MqttMsgStat* stat)
{
    if (stat->recvQuotaHeld) {
        if (client->server_recv_max < client->server_recv_max_negotiated) {
            client->server_recv_max++;
        }
        stat->recvQuotaHeld = 0;
    }
}

static void MqttClient_RecvQuotaRelease(MqttClient* client, MqttMsgStat* stat)
{
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != 0) {
        return;
    }
#endif
    MqttClient_RecvQuotaRelease_Locked(client, stat);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}
#endif /* WOLFMQTT_V5 */

#ifdef WOLFMQTT_SESSION_ID_TRACK
/* Does client_id name the Session whose state this client is holding? An
 * exact comparison: the ClientId identifies the Session [MQTT-3.1.3-2], and a
 * digest of it would let two different ClientIds that happen to share one
 * inherit each other's replay entries and QoS 2 pending ids. Returns 0 when no
 * Session is recorded, so a first connect never matches. */
static int MqttClient_SessionIdMatches(const MqttClient* client,
    const char* client_id)
{
    size_t len;

    if (client->session_client_id_len == 0 || client_id == NULL) {
        return 0;
    }
    len = XSTRLEN(client_id);
    if (len != (size_t)client->session_client_id_len) {
        return 0;
    }
    return (XMEMCMP(client->session_client_id, client_id, len) == 0) ? 1 : 0;
}

/* Record client_id as the Session this client now holds state for. A ClientId
 * too long for the buffer is not recorded, so the next Session Present is
 * treated as a different Session and the state is dropped rather than
 * inherited on a partial match. */
static void MqttClient_SessionIdRecord(MqttClient* client,
    const char* client_id)
{
    size_t len;

    client->session_client_id_len = 0;
    if (client_id == NULL) {
        return;
    }
    len = XSTRLEN(client_id);
    if (len == 0 || len > (size_t)MQTT_MAX_SESSION_CLIENT_ID) {
        return;
    }
    XMEMCPY(client->session_client_id, client_id, len);
    client->session_client_id_len = (word16)len;
}
#endif /* WOLFMQTT_SESSION_ID_TRACK */

#if WOLFMQTT_MAX_QOS >= 2
/* Inbound QoS 2 de-duplication. A subscribing client that has delivered a
 * QoS 2 PUBLISH to the application and answered with PUBREC records its packet
 * id until the matching PUBREL arrives, so a retransmitted PUBLISH is
 * acknowledged again without a second delivery [MQTT-4.3.3-10]. These run on
 * the receive path (under lockRecv), so no extra locking is required. */
static int MqttClient_RecvQos2_Contains(const MqttClient* client,
    word16 packet_id)
{
    int i;

    if (client == NULL || packet_id == 0) {
        return 0;
    }
    for (i = 0; i < MQTT_MAX_RECV_QOS2; i++) {
        if (client->recv_qos2_pending[i] == packet_id) {
            return 1;
        }
    }
    return 0;
}

static int MqttClient_RecvQos2_HasFreeSlot(const MqttClient* client)
{
    int i;

    if (client == NULL) {
        return 0;
    }
    for (i = 0; i < MQTT_MAX_RECV_QOS2; i++) {
        if (client->recv_qos2_pending[i] == 0) {
            return 1;
        }
    }
    return 0;
}

static void MqttClient_RecvQos2_Add(MqttClient* client, word16 packet_id)
{
    int i;

    if (client == NULL || packet_id == 0 ||
            MqttClient_RecvQos2_Contains(client, packet_id)) {
        return;
    }
    /* A new id is only delivered after MqttClient_Publish_ReadPayload confirmed
     * a free slot, so this loop always finds one. */
    for (i = 0; i < MQTT_MAX_RECV_QOS2; i++) {
        if (client->recv_qos2_pending[i] == 0) {
            client->recv_qos2_pending[i] = packet_id;
            return;
        }
    }
}

static void MqttClient_RecvQos2_Remove(MqttClient* client, word16 packet_id)
{
    int i;

    if (client == NULL || packet_id == 0) {
        return;
    }
    for (i = 0; i < MQTT_MAX_RECV_QOS2; i++) {
        if (client->recv_qos2_pending[i] == packet_id) {
            client->recv_qos2_pending[i] = 0;
            return;
        }
    }
}
#endif /* WOLFMQTT_MAX_QOS >= 2 */

#ifndef WOLFMQTT_NO_SESSION_REPLAY
/* Client-side outbound Session state. MQTT 3.1.1 section 4.1 keeps
 * unacknowledged QoS 1 and QoS 2 messages as Session state, and
 * [MQTT-4.4.0-1] requires them re-sent with their original Packet Identifiers
 * after a CleanSession 0 reconnect. The caller's MqttPublish is gone by then,
 * so the topic and payload are copied here.
 *
 * These run under client->lockClient in multithread builds, taken by the
 * MqttClient_SendId* callers they sit alongside. */
static MqttReplayMsg* MqttClient_Replay_Find(MqttClient* client,
    word16 packet_id)
{
    int i;

    for (i = 0; i < MQTT_MAX_REPLAY_MSGS; i++) {
        if (client->replay[i].packet_id == packet_id) {
            return &client->replay[i];
        }
    }
    return NULL;
}

/* The retained copies hold application data - a payload may carry credentials
 * or key material - so they are wiped before going back to the allocator, the
 * same way the client scrubs tx_buf and rx_buf. The static-memory build has no
 * separate buffers; the XMEMSET below covers its in-struct copies. */
static void MqttClient_Replay_FreeSlot(MqttReplayMsg* slot)
{
#ifndef WOLFMQTT_STATIC_MEMORY
    if (slot->topic != NULL) {
        CLIENT_FORCE_ZERO(slot->topic, XSTRLEN(slot->topic) + 1);
        WOLFMQTT_FREE(slot->topic);
    }
    if (slot->payload != NULL) {
        CLIENT_FORCE_ZERO(slot->payload, slot->payload_len);
        WOLFMQTT_FREE(slot->payload);
    }
#endif
    XMEMSET(slot, 0, sizeof(*slot));
}

/* Retain a copy of an outbound QoS > 0 PUBLISH. A message that does not fit
 * the pool is left unretained rather than refused: it still goes out, it just
 * cannot be replayed, which is the same position the client was in before the
 * store existed. */
static void MqttClient_Replay_Add(MqttClient* client, MqttPublish* publish)
{
    MqttReplayMsg* slot;
    size_t topic_len;

    if (publish->packet_id == 0 || publish->topic_name == NULL) {
        return;
    }
    /* A re-send reuses the entry the original PUBLISH created. */
    slot = MqttClient_Replay_Find(client, publish->packet_id);
    if (slot == NULL) {
        slot = MqttClient_Replay_Find(client, 0);
    }
    if (slot == NULL) {
        return; /* pool full: not retained */
    }
    MqttClient_Replay_FreeSlot(slot);

    slot->packet_id = publish->packet_id;
    slot->qos = (byte)publish->qos;
    slot->retain = publish->retain;

    /* A streamed publish delivers its payload through a callback, so there is
     * nothing here to copy; the entry still tracks the QoS 2 PUBREL stage.
     * A zero-byte payload is not that case - section 3.3.3 allows one, and
     * [MQTT-4.4.0-1] asks for it back like any other unacknowledged
     * message - so only a short buffer disqualifies the copy. */
    if (publish->total_len > 0 &&
            (publish->buffer == NULL ||
             publish->buffer_len < publish->total_len)) {
        return;
    }
#ifdef WOLFMQTT_V5
    /* The pool retains no properties, so a v5 PUBLISH that carries any could
     * only be replayed with Response Topic, Correlation Data and the rest
     * stripped - a different message from the one the server is waiting on.
     * Leave it unretained rather than re-send it altered. */
    if (publish->props != NULL) {
        return;
    }
#endif
    topic_len = XSTRLEN(publish->topic_name);

#ifdef WOLFMQTT_STATIC_MEMORY
    if (topic_len >= MQTT_MAX_REPLAY_TOPIC ||
            publish->total_len > MQTT_MAX_REPLAY_PAYLOAD) {
        return; /* too large for the fixed slot */
    }
    XMEMCPY(slot->topic, publish->topic_name, topic_len);
    slot->topic[topic_len] = '\0';
    if (publish->total_len > 0) {
        XMEMCPY(slot->payload, publish->buffer, publish->total_len);
    }
#else
    slot->topic = (char*)WOLFMQTT_MALLOC(topic_len + 1);
    if (slot->topic == NULL) {
        return;
    }
    XMEMCPY(slot->topic, publish->topic_name, topic_len);
    slot->topic[topic_len] = '\0';

    if (publish->total_len > 0) {
        slot->payload = (byte*)WOLFMQTT_MALLOC(publish->total_len);
        if (slot->payload == NULL) {
            CLIENT_FORCE_ZERO(slot->topic, topic_len + 1);
            WOLFMQTT_FREE(slot->topic);
            slot->topic = NULL;
            return;
        }
        XMEMCPY(slot->payload, publish->buffer, publish->total_len);
    }
#endif
    slot->payload_len = publish->total_len;
    slot->haveCopy = 1;
}

/* QoS 2 advanced past PUBREC, so [MQTT-4.4.0-1] replays the PUBREL rather
 * than the PUBLISH. Recorded even when no copy was retained: a PUBREL needs
 * only the Packet Identifier. */
static void MqttClient_Replay_PubRelSent(MqttClient* client, word16 packet_id)
{
    MqttReplayMsg* slot;

    if (packet_id == 0) {
        return;
    }
    slot = MqttClient_Replay_Find(client, packet_id);
    if (slot == NULL) {
        slot = MqttClient_Replay_Find(client, 0);
        if (slot == NULL) {
            return;
        }
        MqttClient_Replay_FreeSlot(slot);
        slot->packet_id = packet_id;
        slot->qos = MQTT_QOS_2;
    }
    slot->pubrelSent = 1;
}

static void MqttClient_Replay_Remove(MqttClient* client, word16 packet_id)
{
    MqttReplayMsg* slot;

    if (packet_id == 0) {
        return;
    }
    slot = MqttClient_Replay_Find(client, packet_id);
    if (slot != NULL) {
        MqttClient_Replay_FreeSlot(slot);
    }
}

static void MqttClient_Replay_Reset(MqttClient* client)
{
    int i;

    for (i = 0; i < MQTT_MAX_REPLAY_MSGS; i++) {
        MqttClient_Replay_FreeSlot(&client->replay[i]);
    }
    client->replayIdx = MQTT_MAX_REPLAY_MSGS;
}

/* Lock-taking wrappers for the callers that reach the store from outside the
 * client lock. Keeping the #ifdef inside a helper avoids leaving a bare scope
 * block behind at each call site in single-threaded builds. */
static void MqttClient_Replay_AddSafe(MqttClient* client, MqttPublish* publish)
{
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return;
    }
#endif
    MqttClient_Replay_Add(client, publish);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}

static void MqttClient_Replay_RemoveSafe(MqttClient* client, word16 packet_id)
{
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return;
    }
#endif
    MqttClient_Replay_Remove(client, packet_id);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}

static void MqttClient_Replay_PubRelSentSafe(MqttClient* client,
    word16 packet_id)
{
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return;
    }
#endif
    MqttClient_Replay_PubRelSent(client, packet_id);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}
#endif /* !WOLFMQTT_NO_SESSION_REPLAY */

/* Outbound Packet Identifier occupancy.
 *
 * [MQTT-2.3.1-2] "Each time a Client sends a new packet of one of these types
 * it MUST assign it a currently unused Packet Identifier", and [MQTT-2.3.1-3]
 * makes the identifier available for reuse only "after the Client has
 * processed the corresponding acknowledgement packet" - PUBACK for QoS 1,
 * PUBCOMP for QoS 2, SUBACK or UNSUBACK for the subscription packets.
 *
 * The WOLFMQTT_MULTITHREAD pending-response list already rejects a colliding
 * identifier, but it is not compiled in other builds and its entries are
 * dropped as soon as the waiting call returns - including on a timeout, where
 * no acknowledgement was processed at all. This table is the connection-level
 * record the rule actually asks for, so it is kept in every build. It is
 * cleared when a Network Connection starts or ends, because the client holds
 * no outbound session state across one.
 *
 * These are called from both the send and receive paths, so they take
 * client->lockClient themselves; no caller may already hold it. Every caller
 * has already rejected a NULL client, as MqttWriteStop and the other internal
 * helpers here assume. */
static int MqttClient_SendIds_Find(const MqttClient* client, word16 packet_id)
{
    int i;

    for (i = 0; i < MQTT_MAX_SEND_INFLIGHT; i++) {
        if (client->send_inflight[i].packet_id == packet_id) {
            return i;
        }
    }
    return -1;
}

/* Claim packet_id for a new outbound packet sent through owner. Returns
 * MQTT_CODE_SUCCESS when it was free (or when isRetransmit says this is a
 * re-send of the same Control Packet, which [MQTT-2.3.1-3] requires to keep
 * its original identifier), and MQTT_CODE_ERROR_PACKET_ID when it is still
 * awaiting its acknowledgement. */
static int MqttClient_SendIdReserve(MqttClient* client, word16 packet_id,
    void* owner, int isRetransmit, MqttPacketType ack_type)
{
    int rc = MQTT_CODE_SUCCESS;
    int i;

    if (packet_id == 0) {
        return MQTT_CODE_SUCCESS; /* nothing to track */
    }
#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#endif
    i = MqttClient_SendIds_Find(client, packet_id);
    if (i >= 0) {
        /* Only a re-send of the same Control Packet may keep an identifier
         * that is still awaiting its acknowledgement; it takes over the
         * existing slot. A new message is refused even when the caller reuses
         * the same message object, which says nothing about whether the
         * earlier exchange finished. Resuming a partially written packet does
         * not come through here: it re-enters past MQTT_MSG_BEGIN. */
        if (!isRetransmit) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
        }
        else {
            client->send_inflight[i].owner = owner;
            client->send_inflight[i].ack_type = (byte)ack_type;
        }
    }
    else {
        i = MqttClient_SendIds_Find(client, 0);
        if (i >= 0) {
            client->send_inflight[i].packet_id = packet_id;
            client->send_inflight[i].owner = owner;
            client->send_inflight[i].ack_type = (byte)ack_type;
        }
        /* Table full: this identifier goes untracked, so a later collision
         * with it is not caught. Refusing the send instead would break an
         * application legitimately keeping more than MQTT_MAX_SEND_INFLIGHT
         * packets in flight, so the check is best effort past that point -
         * raise MQTT_MAX_SEND_INFLIGHT to widen the window. */
    }
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
    return rc;
}

/* Release packet_id once its acknowledgement has been processed. ack_type is
 * the packet type that arrived; the reservation is only given back when it
 * matches the terminal acknowledgement the exchange was waiting for, so a
 * PUBACK naming a QoS 2 identifier cannot end that exchange early
 * [MQTT-2.3.1-3]. Pass MQTT_PACKET_TYPE_RESERVED to release regardless.
 *
 * Also drops the Session replay record for the same identifier, under the same
 * lock: releasing first and removing afterwards would let a publisher reuse
 * the identifier in between, and this ack would then delete the new
 * exchange's replay state. */
static void MqttClient_SendIdRelease(MqttClient* client, word16 packet_id,
    MqttPacketType ack_type)
{
    int i;

    if (packet_id == 0) {
        return;
    }
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return;
    }
#endif
    i = MqttClient_SendIds_Find(client, packet_id);
    if (i >= 0) {
        if (ack_type != MQTT_PACKET_TYPE_RESERVED &&
                client->send_inflight[i].ack_type !=
                    MQTT_PACKET_TYPE_RESERVED &&
                client->send_inflight[i].ack_type != (byte)ack_type) {
            /* Wrong acknowledgement for this exchange: leave it in flight. */
            i = -1;
        }
        else {
            client->send_inflight[i].packet_id = 0;
            client->send_inflight[i].owner = NULL;
            client->send_inflight[i].ack_type =
                (byte)MQTT_PACKET_TYPE_RESERVED;
        }
    }
#ifndef WOLFMQTT_NO_SESSION_REPLAY
    if (i >= 0) {
        /* Completely acknowledged, so it leaves Session state. */
        MqttClient_Replay_Remove(client, packet_id);
    }
#endif
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}

/* Release whatever identifier this message object reserved. Used when the
 * application abandons the exchange through MqttClient_CancelMessage, which
 * cannot tell which packet type the object holds. */
static void MqttClient_SendIdReleaseOwner(MqttClient* client, const void* owner)
{
    int i;

    if (owner == NULL) {
        return;
    }
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return;
    }
#endif
    for (i = 0; i < MQTT_MAX_SEND_INFLIGHT; i++) {
        if (client->send_inflight[i].packet_id != 0 &&
                client->send_inflight[i].owner == owner) {
            client->send_inflight[i].packet_id = 0;
            client->send_inflight[i].owner = NULL;
            client->send_inflight[i].ack_type =
                (byte)MQTT_PACKET_TYPE_RESERVED;
        }
    }
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}

/* Detach owner from its reservation without releasing the Packet Identifier.
 * Used when a message object is being reset for reuse but its packet is
 * already on the wire: the identifier stays claimed until the peer's
 * acknowledgement [MQTT-2.3.1-3], while the object must stop owning it so a
 * later cancel through the reused object cannot give the old one back. */
static void MqttClient_SendIdDisown(MqttClient* client, const void* owner)
{
    int i;

    if (owner == NULL) {
        return;
    }
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return;
    }
#endif
    for (i = 0; i < MQTT_MAX_SEND_INFLIGHT; i++) {
        if (client->send_inflight[i].packet_id != 0 &&
                client->send_inflight[i].owner == owner) {
            client->send_inflight[i].owner = NULL;
        }
    }
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}

/* Drop every reservation. The identifiers were only in use on the Network
 * Connection that is starting or ending, and the client keeps no outbound
 * session state across one. */
static void MqttClient_SendIdsReset(MqttClient* client)
{
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return;
    }
#endif
    XMEMSET(client->send_inflight, 0, sizeof(client->send_inflight));
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}

#ifdef WOLFMQTT_MULTITHREAD

/* These RespList functions assume caller has locked client->lockClient mutex */
int MqttClient_RespList_Add(MqttClient *client,
    MqttPacketType packet_type, word16 packet_id, MqttPendResp *newResp,
    void *packet_obj)
{
    MqttPendResp *tmpResp;

    if (client == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("PendResp Add: %p, Type %s (%d), ID %d",
        newResp, MqttPacket_TypeDesc(packet_type), packet_type, packet_id);
#endif

    /* Verify newResp is not already in the list, and enforce MQTT Packet
     * Identifier in-use uniqueness: the spec (3.1.1 section 2.3.1, 5.0 section 2.2.1)
     * requires a new QoS-related Control Packet to use a Packet Identifier
     * that is not currently in use. The identifier becomes reusable only
     * after the corresponding acknowledgement flow completes and the entry
     * is removed from this list. A packet_id of 0 is used for packet types
     * that do not carry a Packet Identifier (CONNECT_ACK, PING_RESP, AUTH)
     * and is excluded from the collision check. */
    for (tmpResp = client->firstPendResp;
         tmpResp != NULL;
         tmpResp = tmpResp->next)
    {
        if (tmpResp == newResp) {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Pending Response already in list!");
        #endif
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }
        if (packet_id != 0 && tmpResp->packet_id == packet_id) {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Pending Response packet_id %d already in use "
                   "(existing type %s (%d), new type %s (%d))",
                packet_id,
                MqttPacket_TypeDesc(tmpResp->packet_type),
                tmpResp->packet_type,
                MqttPacket_TypeDesc(packet_type), packet_type);
        #endif
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
        }
    }

    /* Initialize new response */
    XMEMSET(newResp, 0, sizeof(MqttPendResp));
    newResp->packet_id = packet_id;
    newResp->packet_type = packet_type;
    /* opaque pointer to struct based on type */
    newResp->packet_obj = packet_obj;

    if (client->lastPendResp == NULL) {
        /* This is the only list item */
        client->firstPendResp = newResp;
        client->lastPendResp = newResp;
    }
    else {
        /* Append to end of list */
        newResp->prev = client->lastPendResp;
        client->lastPendResp->next = newResp;
        client->lastPendResp = newResp;
    }
    return MQTT_CODE_SUCCESS;
}

void MqttClient_RespList_Remove(MqttClient *client, MqttPendResp *rmResp)
{
    MqttPendResp *tmpResp;

    if (client == NULL)
        return;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("PendResp Remove: %p", rmResp);
#endif

    /* Find the response entry */
    for (tmpResp = client->firstPendResp;
         tmpResp != NULL;
         tmpResp = tmpResp->next)
    {
        if (tmpResp == rmResp) {
            break;
        }
    }
    if (tmpResp) {
    #ifdef WOLFMQTT_V5
        /* Drop the reserved-quota back-reference so a recycled publish object
         * cannot carry a stale pointer into a future pending response. */
        tmpResp->recvQuotaStat = NULL;
    #endif
        /* Fix up the first and last pointers */
        if (client->firstPendResp == tmpResp) {
            client->firstPendResp = tmpResp->next;
        }
        if (client->lastPendResp == tmpResp) {
            client->lastPendResp = tmpResp->prev;
        }

        /* Remove the entry from the list */
        if (tmpResp->next != NULL) {
            tmpResp->next->prev = tmpResp->prev;
        }
        if (tmpResp->prev != NULL) {
            tmpResp->prev->next = tmpResp->next;
        }
    }
#ifdef WOLFMQTT_DEBUG_CLIENT
    else {
        PRINTF("\tPendResp not found");
    }
#endif
}

/* return codes: 0=not found, 1=found */
int MqttClient_RespList_Find(MqttClient *client,
    MqttPacketType packet_type, word16 packet_id, MqttPendResp **retResp)
{
    int rc = 0;
    MqttPendResp *tmpResp;

    if (client == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);

#ifdef WOLFMQTT_DEBUG_CLIENT
    #ifdef WOLFMQTT_NONBLOCK
    if (client->lastRc != MQTT_CODE_CONTINUE)
    #endif
    {
        PRINTF("PendResp Find: Type %s (%d), ID %d",
            MqttPacket_TypeDesc(packet_type), packet_type, packet_id);
    }
#endif

    if (retResp)
        *retResp = NULL; /* clear */

    /* Find pending response entry */
    for (tmpResp = client->firstPendResp;
         tmpResp != NULL;
         tmpResp = tmpResp->next)
    {
        if (packet_type == tmpResp->packet_type &&
           (packet_id == tmpResp->packet_id))
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            #if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_DEBUG_CLIENT)
            if (client->lastRc != MQTT_CODE_CONTINUE)
            #endif
            {
            PRINTF("PendResp Found: %p, Type %s (%d), ID %d, InProc %d, Done %d",
                tmpResp, MqttPacket_TypeDesc(tmpResp->packet_type),
                tmpResp->packet_type, tmpResp->packet_id,
                tmpResp->packetProcessing, tmpResp->packetDone);
            }
        #endif

            if (retResp)
                *retResp = tmpResp;
            rc = 1;
            break;
        }
    }
    return rc;
}
#endif /* WOLFMQTT_MULTITHREAD */

#ifdef WOLFMQTT_V5
/* Populate client fields from CONNACK server properties so that the
 * publish/packet-size guards are effective without requiring the
 * application to register a property callback. */
static int Handle_ConnectAck_Props(MqttClient* client, MqttProp* props)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttProp* prop;

    for (prop = props; prop != NULL; prop = prop->next) {
        /* MQTT 5.0 sections 3.2.2.3.4 and 3.2.2.3.5: these byte
         * properties can only contain 0 or 1. Reject the complete CONNACK
         * before applying any of its server limits. */
        if (((prop->type == MQTT_PROP_MAX_QOS) &&
                (prop->data_byte > MQTT_QOS_1)) ||
            ((prop->type == MQTT_PROP_RETAIN_AVAIL) &&
                (prop->data_byte > 1))) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
        }
    }

    for (prop = props; prop != NULL; prop = prop->next) {
        if (prop->type == MQTT_PROP_MAX_QOS) {
            byte adv = prop->data_byte;
            if (adv > WOLFMQTT_MAX_QOS) {
                adv = (byte)WOLFMQTT_MAX_QOS;
            }
            client->max_qos = adv;
        }
        else if (prop->type == MQTT_PROP_RETAIN_AVAIL) {
            client->retain_avail = prop->data_byte;
        }
        else if (prop->type == MQTT_PROP_MAX_PACKET_SZ) {
            if ((prop->data_int > 0) &&
                (prop->data_int <= MQTT_PACKET_SZ_MAX)) {
                /* Honor the smaller of the client's existing cap
                 * (0 means unset) and the server's limit. */
                if ((client->packet_sz_max == 0) ||
                    (prop->data_int < client->packet_sz_max)) {
                    client->packet_sz_max = prop->data_int;
                }
            }
        }
    #ifndef WOLFMQTT_NO_TIME
        else if (prop->type == MQTT_PROP_SERVER_KEEP_ALIVE) {
            /* MQTT v5 [3.1.2.11.2]: when the broker returns a Server Keep
             * Alive, the client MUST use it in place of the value it sent, and
             * a value of 0 disables keep-alive. The flag lets the arming logic
             * tell a server-provided 0 from an absent property. */
            client->keep_alive_sec = prop->data_short;
            client->keep_alive_from_server = 1;
        }
    #endif
        else if (prop->type == MQTT_PROP_RECEIVE_MAX) {
            /* [MQTT-3.1.2.11.3]: 0 is a Protocol Error, not clamped. */
            if (prop->data_short == 0) {
                rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
                break;
            }
            client->server_recv_max = prop->data_short;
            client->server_recv_max_negotiated = prop->data_short;
        }
        else if (prop->type == MQTT_PROP_TOPIC_ALIAS_MAX) {
            /* MQTT v5 [3.1.2.11.8] */
            client->topic_alias_max = prop->data_short;
        }
    }
    return rc;
}

static int Handle_Props(MqttClient* client, MqttProp* props, byte use_cb,
                        byte free_props)
{
    int rc = MQTT_CODE_SUCCESS;

    /* If no properties, just return */
    if (props != NULL) {
    #ifdef WOLFMQTT_PROPERTY_CB
        /* Check for properties set by the server */
        if ((use_cb == 1) && (client->property_cb != NULL)) {
            /* capture error if returned */
            int rc_err = client->property_cb(client, props,
                    client->property_ctx);
            if (rc_err < 0) {
                rc = rc_err;
            }
        }
    #else
        (void)client;
        (void)use_cb;
    #endif
        if (free_props) {
            /* Free the properties */
            MqttProps_Free(props);
        }
    }
    return rc;
}
#endif


/* Returns length decoded or error (as negative) */
/*! \brief      Take a received MQTT packet and try and decode it
 *  \param      client       MQTT client context
 *  \param      rx_buf       Incoming buffer data
 *  \param      rx_len       Incoming buffer length
 *  \param      p_decode     Opaque pointer to packet structure based on type
 *  \param      ppacket_type Decoded packet type
 *  \param      ppacket_qos  Decoded QoS level
 *  \param      ppacket_id   Decoded packet id
 *  \param      doProps      True: Call Handle_Props to free prop struct

 *  \return     Returns length decoded or error (as negative) MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
static int MqttClient_DecodePacket(MqttClient* client, byte* rx_buf,
    word32 rx_len, void *packet_obj, MqttPacketType* ppacket_type,
    MqttQoS* ppacket_qos, word16* ppacket_id, int doProps)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttPacket* header;
    MqttPacketType packet_type;
    MqttQoS packet_qos;
    word16 packet_id = 0;

    /* must have rx buffer with at least 2 byes for header */
    if (rx_buf == NULL || rx_len < MQTT_PACKET_HEADER_MIN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Decode header */
    header = (MqttPacket*)rx_buf;
    packet_type = (MqttPacketType)MQTT_PACKET_TYPE_GET(header->type_flags);
    if (ppacket_type) {
        *ppacket_type = packet_type;
    }
    packet_qos = (MqttQoS)MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);
    if (ppacket_qos) {
        *ppacket_qos = packet_qos;
    }

    /* Decode packet specific data (if requested) */
    if (ppacket_id || packet_obj) {
        switch (packet_type) {
        case MQTT_PACKET_TYPE_CONNECT_ACK:
        {
            MqttConnectAck connect_ack, *p_connect_ack = &connect_ack;
            if (packet_obj) {
                p_connect_ack = (MqttConnectAck*)packet_obj;
            }
            else {
                XMEMSET(p_connect_ack, 0, sizeof(MqttConnectAck));
            }
        #ifdef WOLFMQTT_V5
            p_connect_ack->protocol_level = client->protocol_level;
        #endif
            rc = MqttDecode_ConnectAck(rx_buf, rx_len, p_connect_ack);
        #ifdef WOLFMQTT_V5
            if (rc >= 0 && doProps) {
                int tmp;
                /* Only latch server-supplied session limits when the broker
                 * accepted the connection. A refused CONNACK must not
                 * mutate long-lived MqttClient state. */
                if (p_connect_ack->return_code ==
                        MQTT_CONNECT_ACK_CODE_ACCEPTED) {
                    tmp = Handle_ConnectAck_Props(client, p_connect_ack->props);
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
                tmp = Handle_Props(client, p_connect_ack->props,
                                   (packet_obj != NULL), 1);
                p_connect_ack->props = NULL;
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
        #endif
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH:
        {
            MqttPublish publish, *p_publish;
            if (packet_obj) {
                p_publish = (MqttPublish*)packet_obj;
            }
            else {
                p_publish = &publish;
                XMEMSET(p_publish, 0, sizeof(MqttPublish));
            }
        #ifdef WOLFMQTT_V5
            /* The preliminary decode must use the negotiated wire format. */
            p_publish->protocol_level = client->protocol_level;
        #endif
            rc = MqttDecode_Publish(rx_buf, rx_len, p_publish);
            if (rc >= 0) {
                packet_id = p_publish->packet_id;
            #ifdef WOLFMQTT_V5
                if (doProps) {
                    /* Retain returned properties until the message callback. */
                    int tmp = Handle_Props(client, p_publish->props,
                                           (packet_obj != NULL),
                                           (packet_obj == NULL));
                    if (packet_obj == NULL) {
                        p_publish->props = NULL;
                    }
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
            #endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
        {
            MqttPublishResp publish_resp, *p_publish_resp = &publish_resp;
            if (packet_obj) {
                p_publish_resp = (MqttPublishResp*)packet_obj;
            }
            else {
                XMEMSET(p_publish_resp, 0, sizeof(MqttPublishResp));
            }

        #ifdef WOLFMQTT_V5
            p_publish_resp->protocol_level = client->protocol_level;
        #endif
            rc = MqttDecode_PublishResp(rx_buf, rx_len, packet_type,
                p_publish_resp);
            if (rc >= 0) {
                packet_id = p_publish_resp->packet_id;
                /* [MQTT-2.3.1-3] The Packet Identifier becomes available for
                 * reuse once the corresponding acknowledgement is processed:
                 * PUBACK for QoS 1, PUBCOMP for QoS 2. PUBREC and PUBREL are
                 * intermediate steps of the QoS 2 flow and do not release it.
                 * An inbound PUBREL belongs to a PUBLISH this client received,
                 * whose identifier is tracked separately. */
                if (packet_type == MQTT_PACKET_TYPE_PUBLISH_ACK ||
                    packet_type == MQTT_PACKET_TYPE_PUBLISH_COMP) {
                    MqttClient_SendIdRelease(client, packet_id, packet_type);
                }
            #ifdef WOLFMQTT_V5
                if (doProps) {
                    int tmp = Handle_Props(client, p_publish_resp->props,
                                           (packet_obj != NULL), 1);
                    p_publish_resp->props = NULL;
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
            #endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
        {
            MqttSubscribeAck subscribe_ack, *p_subscribe_ack = &subscribe_ack;
            if (packet_obj) {
                p_subscribe_ack = (MqttSubscribeAck*)packet_obj;
            }
            else {
                XMEMSET(p_subscribe_ack, 0, sizeof(MqttSubscribeAck));
            }
        #ifdef WOLFMQTT_V5
            p_subscribe_ack->protocol_level = client->protocol_level;
        #endif
            rc = MqttDecode_SubscribeAck(rx_buf, rx_len, p_subscribe_ack);
            if (rc >= 0) {
                packet_id = p_subscribe_ack->packet_id;
                /* [MQTT-2.3.1-3] SUBACK releases the SUBSCRIBE identifier. */
                MqttClient_SendIdRelease(client, packet_id,
                    MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
            #ifdef WOLFMQTT_V5
                if (doProps) {
                    int tmp = Handle_Props(client, p_subscribe_ack->props,
                                           (packet_obj != NULL), 1);
                    p_subscribe_ack->props = NULL;
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
            #endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
        {
            MqttUnsubscribeAck unsubscribe_ack,
                               *p_unsubscribe_ack = &unsubscribe_ack;
            if (packet_obj) {
                p_unsubscribe_ack = (MqttUnsubscribeAck*)packet_obj;
            }
            else {
                XMEMSET(p_unsubscribe_ack, 0, sizeof(MqttUnsubscribeAck));
            }
        #ifdef WOLFMQTT_V5
            p_unsubscribe_ack->protocol_level = client->protocol_level;
        #endif
            rc = MqttDecode_UnsubscribeAck(rx_buf, rx_len, p_unsubscribe_ack);
            if (rc >= 0) {
                packet_id = p_unsubscribe_ack->packet_id;
                /* [MQTT-2.3.1-3] UNSUBACK releases the UNSUBSCRIBE
                 * identifier. */
                MqttClient_SendIdRelease(client, packet_id,
                    MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK);
            #ifdef WOLFMQTT_V5
                if (doProps) {
                    int tmp = Handle_Props(client, p_unsubscribe_ack->props,
                                           (packet_obj != NULL), 1);
                    p_unsubscribe_ack->props = NULL;
                    if (tmp != MQTT_CODE_SUCCESS) {
                        rc = tmp;
                    }
                }
            #endif
            }
            break;
        }
        case MQTT_PACKET_TYPE_PING_RESP:
        {
            MqttPing ping, *p_ping = &ping;
            if (packet_obj) {
                p_ping = (MqttPing*)packet_obj;
            }
            else {
                XMEMSET(p_ping, 0, sizeof(MqttPing));
            }
            rc = MqttDecode_Ping(rx_buf, rx_len, p_ping);
            break;
        }
        case MQTT_PACKET_TYPE_AUTH:
        {
        #ifdef WOLFMQTT_V5
            MqttAuth auth, *p_auth = &auth;
            /* Type 15 is reserved below v5 */
            if (client->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
                break;
            }
            if (packet_obj) {
                p_auth = (MqttAuth*)packet_obj;
            }
            else {
                XMEMSET(p_auth, 0, sizeof(MqttAuth));
            }
            rc = MqttDecode_Auth(rx_buf, rx_len, p_auth);
            if (rc >= 0 && doProps) {
                int tmp = Handle_Props(client, p_auth->props,
                                       (packet_obj != NULL), 1);
                p_auth->props = NULL;
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
        #else
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
        #endif /* WOLFMQTT_V5 */
            break;
        }
        case MQTT_PACKET_TYPE_DISCONNECT:
        {
        #ifdef WOLFMQTT_V5
            MqttDisconnect disc, *p_disc = &disc;
            /* DISCONNECT is client-to-server only below v5 */
            if (client->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
                break;
            }
            if (packet_obj) {
                p_disc = (MqttDisconnect*)packet_obj;
            }
            else {
                XMEMSET(p_disc, 0, sizeof(MqttDisconnect));
            }
            rc = MqttDecode_Disconnect(rx_buf, rx_len, p_disc);
            if (rc >= 0 && doProps) {
                int tmp = Handle_Props(client, p_disc->props,
                                       (packet_obj != NULL), 1);
                p_disc->props = NULL;
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
            #ifdef WOLFMQTT_DISCONNECT_CB
            /* Call disconnect callback with reason code */
            if ((packet_obj != NULL) && client->disconnect_cb) {
                client->disconnect_cb(client, p_disc->reason_code,
                    client->disconnect_ctx);
            }
            #endif
        #else
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
        #endif /* WOLFMQTT_V5 */
            break;
        }
        case MQTT_PACKET_TYPE_CONNECT:
        case MQTT_PACKET_TYPE_SUBSCRIBE:
        case MQTT_PACKET_TYPE_UNSUBSCRIBE:
        case MQTT_PACKET_TYPE_PING_REQ:
        case MQTT_PACKET_TYPE_ANY:
        case MQTT_PACKET_TYPE_RESERVED:
        default:
            /* these type are only encoded by client */
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
            break;
        } /* switch (packet_type) */
    }

    if (ppacket_id) {
        *ppacket_id = packet_id;
    }

    (void)client;
    (void)doProps;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_DecodePacket: Rc %d, Len %d, Type %s (%d), ID %d,"
            " QoS %d, doProps %d",
        rc, rx_len, MqttPacket_TypeDesc(packet_type), packet_type, packet_id,
        packet_qos, doProps);
#endif

    return rc;
}

static int MqttClient_HandlePacket(MqttClient* client,
    MqttPacketType packet_type, void *packet_obj, MqttPublishResp* resp,
    int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttQoS packet_qos = MQTT_QOS_0;
    word16 packet_id = 0;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* make sure the response defaults to no ACK */
    resp->packet_type = MQTT_PACKET_TYPE_RESERVED;

    switch (packet_type)
    {
        case MQTT_PACKET_TYPE_CONNECT_ACK:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id, 1);
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH:
        {
            MqttPublish* publish = (MqttPublish*)packet_obj;
            if (publish->stat.read != MQTT_MSG_PAYLOAD2) {
                rc = MqttClient_DecodePacket(client, client->rx_buf,
                    client->packet.buf_len, packet_obj, &packet_type,
                    &packet_qos, &packet_id, 1);
                if (rc <= 0) {
                    return rc;
                }
            }
            else {
                /* packet ID and QoS were already established */
                packet_id =  publish->packet_id;
                packet_qos = publish->qos;
            }

            rc = MqttClient_Publish_ReadPayload(client, publish, timeout_ms);

            /* MQTT_CODE_CONTINUE means the payload is not fully read yet. Return
             * to the caller and keep publish->props and the read state intact so
             * the non-blocking re-entry can resume. */
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }

            /* The publish read is terminal here, whether it succeeded or failed
             * to deliver (e.g. no msg_cb, or the callback returned an error).
             * Reset the read state and free the retained V5 property list for
             * every terminal result: the properties are intentionally kept
             * through decode/callback and were previously freed only on the
             * success path, so an error return would leak the property pool
             * (or heap, under WOLFMQTT_DYN_PROP). Also resetting the read state
             * keeps a caller that logs the error and retries from re-entering on
             * stale MQTT_MSG_PAYLOAD2 state. */
            publish->stat.read = MQTT_MSG_BEGIN; /* reset state */
        #ifdef WOLFMQTT_V5
            /* Free the properties */
            MqttProps_Free(publish->props);
            publish->props = NULL;
        #endif

            if (rc < 0) {
                break;
            }

            /* Handle QoS */
            if (packet_qos == MQTT_QOS_0) {
                /* we are done, no QoS response */
                break;
            }

        #ifdef WOLFMQTT_V5
            /* Copy response code in case changed by callback, then clear it on
             * the (possibly caller-owned) publish object so a later reuse does
             * not inherit this ack's reason, e.g. a quota rejection. */
            resp->reason_code = publish->resp.reason_code;
            publish->resp.reason_code = MQTT_REASON_SUCCESS;
        #endif
            /* Populate information needed for ack */
            resp->packet_type = (packet_qos == MQTT_QOS_1) ?
                MQTT_PACKET_TYPE_PUBLISH_ACK :
                MQTT_PACKET_TYPE_PUBLISH_REC;
            resp->packet_id = packet_id;
        #if WOLFMQTT_MAX_QOS >= 2
            /* Record this QoS 2 packet id as delivered and awaiting PUBREL so a
             * retransmit is acknowledged again without a second delivery
             * [MQTT-4.3.3-10]. A no-op for the retransmit, which is already
             * tracked. Skipped when the callback rejected the message and the
             * PUBREC carries a reason code >= 0x80: that ends the exchange
             * [MQTT-4.3.3], so no PUBREL will arrive to clear the entry and the
             * sender is free to reuse the packet id - a tracked id would both
             * hold a slot forever and suppress the next PUBLISH that reuses
             * it. */
            if (packet_qos == MQTT_QOS_2
            #ifdef WOLFMQTT_V5
                && (client->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5 ||
                    (resp->reason_code & 0x80) == 0)
            #endif
                ) {
                MqttClient_RecvQos2_Add(client, packet_id);
            }
        #endif
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
        {
        #if defined(WOLFMQTT_V5) && defined(WOLFMQTT_DEBUG_CLIENT)
            MqttPublishResp* publish_resp = (MqttPublishResp*)packet_obj;
        #endif
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type,
                &packet_qos, &packet_id, 1);
            if (rc <= 0) {
                return rc;
            }

        #if defined(WOLFMQTT_V5) && defined(WOLFMQTT_DEBUG_CLIENT)
            PRINTF("\tPublish response: reason code %d, Type %s (%d),"
                    " ID %d, QoS %d",
                    publish_resp->reason_code,
                    MqttPacket_TypeDesc(packet_type),
                    packet_type, packet_id, packet_qos);
        #endif

            /* Only ACK publish Received or Release QoS levels */
            if (packet_type != MQTT_PACKET_TYPE_PUBLISH_REC &&
                packet_type != MQTT_PACKET_TYPE_PUBLISH_REL) {
                break;
            }

        #ifdef WOLFMQTT_V5
            /* A v5 broker rejects a QoS 2 PUBLISH at the PUBREC stage with a
             * reason code >= 0x80 (e.g. not authorized, quota exceeded, topic
             * name invalid, payload format invalid). Per [MQTT-4.3.3] the
             * exchange is then complete and the sender MUST NOT send a PUBREL.
             * Surface the rejection instead of advancing the handshake, which
             * would emit an illegal PUBREL and then block waiting for a PUBCOMP
             * the broker will never send. The QoS 1 PUBACK and the QoS 2
             * PUBCOMP reason codes are checked by the caller after the wait.
             * Note (WOLFMQTT_MULTITHREAD): when a separate thread drives reads
             * and processes this PUBREC, that thread receives this error
             * directly, and the publishing thread's PUBCOMP pending response is
             * completed with it below, so its next poll returns
             * MQTT_CODE_ERROR_PUBLISH_REJECTED rather than spinning on
             * MQTT_CODE_CONTINUE until cmd_timeout_ms. This is the one
             * rejection MqttClient_Publish_WriteOnly does surface; see its
             * documentation in mqtt_client.h. */
            if (packet_type == MQTT_PACKET_TYPE_PUBLISH_REC &&
                client->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                (((MqttPublishResp*)packet_obj)->reason_code & 0x80)) {
            #ifdef WOLFMQTT_MULTITHREAD
                /* The QoS 2 exchange ends here with no PUBCOMP [MQTT-4.9].
                 * Complete the PUBCOMP pending response with the rejection so a
                 * write-only publisher polling for it observes the failure
                 * instead of spinning on CONTINUE, release the reserved unit,
                 * and clear the back-reference so a later cancel/disconnect
                 * cannot touch it. Idempotent for an ordinary waiting
                 * publisher, whose own wait also surfaces the rejection. */
                MqttPendResp* qpr = NULL;
                if (wm_SemLock(&client->lockClient) == 0) {
                    if (MqttClient_RespList_Find(client,
                            MQTT_PACKET_TYPE_PUBLISH_COMP, packet_id, &qpr) &&
                            qpr != NULL) {
                        if (qpr->recvQuotaStat != NULL) {
                            MqttClient_RecvQuotaRelease_Locked(client,
                                qpr->recvQuotaStat);
                            qpr->recvQuotaStat = NULL;
                        }
                        qpr->packet_ret = MQTT_CODE_ERROR_PUBLISH_REJECTED;
                        qpr->packetDone = 1;
                    }
                    wm_SemUnlock(&client->lockClient);
                }
            #endif
                /* [MQTT-2.3.1-3] The Packet Identifier is available for
                 * reuse once the exchange it belongs to is complete, and this
                 * one is: no PUBREL and no PUBCOMP follow a rejecting PUBREC.
                 * The message also leaves Session state - the server declined
                 * it, so [MQTT-4.4.0-1] does not ask for it back after a
                 * reconnect. */
                MqttClient_SendIdRelease(client, packet_id,
                    MQTT_PACKET_TYPE_RESERVED);
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PUBLISH_REJECTED);
            }
        #endif

        #if WOLFMQTT_MAX_QOS >= 2
            /* An incoming PUBREL completes the inbound QoS 2 handshake: drop the
             * awaiting-PUBREL record so a future PUBLISH may reuse the id. */
            if (packet_type == MQTT_PACKET_TYPE_PUBLISH_REL) {
                MqttClient_RecvQos2_Remove(client, packet_id);
            }
        #endif

            /* Populate information needed for ack */
            resp->packet_type = packet_type+1; /* next ack */
            resp->packet_id = packet_id;
            break;
        }
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id, 1);
            break;
        }
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id, 1);
            break;
        }
        case MQTT_PACKET_TYPE_PING_RESP:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id, 1);
            break;
        }
        case MQTT_PACKET_TYPE_AUTH:
        {
        #ifdef WOLFMQTT_V5
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id, 1);
            /* The decoded AUTH properties (including AUTH_DATA) were pointers
             * into rx_buf and have now been delivered to the callback and
             * freed. Scrub rx_buf so the enhanced-authentication material does
             * not linger until the next read, matching MqttClient_Auth and the
             * v5 CONNACK path. This runs under lockRecv (held by MqttReadStart
             * in MqttClient_WaitType), so no additional locking is needed. */
            CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
        #else
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
        #endif
            break;
        }

        case MQTT_PACKET_TYPE_DISCONNECT:
        {
        #ifdef WOLFMQTT_V5
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id, 1);
        #else
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
        #endif
            break;
        }
        case MQTT_PACKET_TYPE_CONNECT:
        case MQTT_PACKET_TYPE_SUBSCRIBE:
        case MQTT_PACKET_TYPE_UNSUBSCRIBE:
        case MQTT_PACKET_TYPE_PING_REQ:
        case MQTT_PACKET_TYPE_ANY:
        case MQTT_PACKET_TYPE_RESERVED:
        default:
            /* these types are only sent from client and should not be sent
             * by broker */
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
            break;
    } /* switch (packet_type) */

#ifdef WOLFMQTT_DEBUG_CLIENT
    if (rc < 0) {
        PRINTF("MqttClient_HandlePacket: Rc %d, Type %s (%d), QoS %d, ID %d",
            rc, MqttPacket_TypeDesc(packet_type), packet_type, packet_qos,
            packet_id);
    }
#endif

    return rc;
}

/* [MQTT-4.13.1] Malformed/protocol-invalid data requires disconnect. */
static int MqttClient_IsFatalProtoError(int rc)
{
    return (rc == MQTT_CODE_ERROR_MALFORMED_DATA ||
            rc == MQTT_CODE_ERROR_PACKET_TYPE ||
            rc == MQTT_CODE_ERROR_PACKET_ID ||
            rc == MQTT_CODE_ERROR_PROPERTY ||
            rc == MQTT_CODE_ERROR_PROPERTY_MISMATCH ||
            rc == MQTT_CODE_ERROR_SERVER_PROP);
}

static inline int MqttIsPubRespPacket(int packet_type)
{
    return (packet_type == MQTT_PACKET_TYPE_PUBLISH_ACK /* Acknowledgment */ ||
            packet_type == MQTT_PACKET_TYPE_PUBLISH_REC /* Received */ ||
            packet_type == MQTT_PACKET_TYPE_PUBLISH_REL /* Release */ ||
            packet_type == MQTT_PACKET_TYPE_PUBLISH_COMP /* Complete */);
}

#ifdef WOLFMQTT_MULTITHREAD
/* this function will return:
 * MQTT_CODE_CONTINUE indicating found, but not marked done
 * MQTT_CODE_ERROR_NOT_FOUND: Not found
 * Any other response is from the the packet_ret
 */
WOLFMQTT_LOCAL int MqttClient_CheckPendResp(MqttClient *client, byte wait_type,
    word16 wait_packet_id)
{
    int rc;
    MqttPendResp *pendResp = NULL;

    /* Check to see if packet type and id have already completed */
    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
        if (MqttClient_RespList_Find(client, (MqttPacketType)wait_type,
            wait_packet_id, &pendResp))
        {
            if ((pendResp != NULL) && (pendResp->packetDone)) {
                /* pending response is already done, so return */
                rc = pendResp->packet_ret;
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("PendResp Check Done %p: Rc %d", pendResp, rc);
            #endif
                MqttClient_RespList_Remove(client, pendResp);
            }
            else {
                /* item not done */
                rc = MQTT_CODE_CONTINUE;
            }
        }
        else {
            /* item not found */
            rc = MQTT_CODE_ERROR_NOT_FOUND;
        }
        wm_SemUnlock(&client->lockClient);
    }
    return rc;
}
#endif /* WOLFMQTT_MULTITHREAD */

/* Helper for clearing the contents of an object buffer based on packet type */
static void MqttClient_PacketReset(MqttPacketType packet_type, void* packet_obj)
{
    size_t objSz = 0;
    size_t offset = sizeof(MqttMsgStat);
    /* The MqttPendResp offset is added only for the types whose struct embeds
     * a pendResp member (right after MqttMsgStat). Ack-only types (CONNECT_ACK,
     * SUBSCRIBE_ACK, UNSUBSCRIBE_ACK, DISCONNECT) have no pendResp, so adding
     * it there would skip live fields - matching the per-type handling in
     * MqttSNClient_PacketReset. */
    switch (packet_type) {
        case MQTT_PACKET_TYPE_CONNECT:
            objSz = sizeof(MqttConnect);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case MQTT_PACKET_TYPE_CONNECT_ACK:
            objSz = sizeof(MqttConnectAck);
            break;
        case MQTT_PACKET_TYPE_PUBLISH:
            objSz = sizeof(MqttPublish);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
            objSz = sizeof(MqttPublishResp);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case MQTT_PACKET_TYPE_SUBSCRIBE:
            objSz = sizeof(MqttSubscribe);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
            objSz = sizeof(MqttSubscribeAck);
            break;
        case MQTT_PACKET_TYPE_UNSUBSCRIBE:
            objSz = sizeof(MqttUnsubscribe);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
            objSz = sizeof(MqttUnsubscribeAck);
            break;
        case MQTT_PACKET_TYPE_PING_REQ:
        case MQTT_PACKET_TYPE_PING_RESP:
            objSz = sizeof(MqttPing);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
            break;
        case MQTT_PACKET_TYPE_AUTH:
        #ifdef WOLFMQTT_V5
            objSz = sizeof(MqttAuth);
        #ifdef WOLFMQTT_MULTITHREAD
            offset += sizeof(MqttPendResp);
        #endif
        #endif
            break;
        case MQTT_PACKET_TYPE_DISCONNECT:
        #ifdef WOLFMQTT_V5
            objSz = sizeof(MqttDisconnect);
        #endif
            break;
        case MQTT_PACKET_TYPE_ANY:
        case MQTT_PACKET_TYPE_RESERVED:
        default:
            break;
    } /* switch (packet_type) */
    if (objSz > offset) {
        XMEMSET((byte*)packet_obj + offset, 0, objSz - offset);
    }
}

static int MqttClient_WaitType(MqttClient *client, void *packet_obj,
    byte wait_type, word16 wait_packet_id, int timeout_ms,
    MqttMsgStat* wait_stat)
{
    int rc = MQTT_CODE_SUCCESS;
    word16         packet_id;
    MqttPacketType packet_type;
    MqttQoS        packet_qos = MQTT_QOS_0;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp *pendResp;
#ifdef WOLFMQTT_V5
    int auto_auth_pending;
#endif
#endif
    MqttMsgStat* mms_stat;
    int waitMatchFound;
    int recvFatal = 0;
    void* use_packet_obj = NULL;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* all packet type structures must have MqttMsgStat at top */
    mms_stat = (wait_stat != NULL) ? wait_stat : (MqttMsgStat*)packet_obj;

wait_again:

    /* initialize variables */
    packet_id = 0;
    packet_type = MQTT_PACKET_TYPE_RESERVED;
#ifdef WOLFMQTT_MULTITHREAD
    pendResp = NULL;
#endif
    waitMatchFound = 0;

#ifdef WOLFMQTT_DEBUG_CLIENT
    #ifdef WOLFMQTT_NONBLOCK
    if (client->lastRc != MQTT_CODE_CONTINUE)
    #endif
    {
        PRINTF("MqttClient_WaitType: Type %s (%d), ID %d, State %d-%d",
            MqttPacket_TypeDesc((MqttPacketType)wait_type),
                wait_type, wait_packet_id, mms_stat->read, mms_stat->write);
    }
#endif

    switch (mms_stat->read)
    {
        case MQTT_MSG_BEGIN:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            /* Check to see if packet type and id have already completed */
            rc = MqttClient_CheckPendResp(client, wait_type, wait_packet_id);
            if (rc != MQTT_CODE_ERROR_NOT_FOUND && rc != MQTT_CODE_CONTINUE) {
                return rc;
            }
        #endif

            if ((rc = MqttReadStart(client, mms_stat)) != 0) {
                return rc;
            }

        #ifdef WOLFMQTT_MULTITHREAD
            /* Another reader can complete this response after the check above
             * but before this waiter acquires lockRecv. Recheck while holding
             * lockRecv; no reader can change the result after this point. */
            rc = MqttClient_CheckPendResp(client, wait_type, wait_packet_id);
            if (rc != MQTT_CODE_ERROR_NOT_FOUND &&
                    rc != MQTT_CODE_CONTINUE) {
                MqttReadStop(client, mms_stat);
                return rc;
            }
        #endif

            mms_stat->read = MQTT_MSG_WAIT;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        case MQTT_MSG_HEADER:
        {
            /* Wait for packet */
            rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len,
                    timeout_ms);
            /* handle failure */
            if (rc <= 0) {
            #ifdef WOLFMQTT_NONBLOCK
                if (rc == MQTT_CODE_CONTINUE &&
                    (client->packet.stat > MQTT_PK_BEGIN ||
                     client->read.total > 0)
                ) {
                    /* advance state, since we received some data */
                    mms_stat->read = MQTT_MSG_HEADER;
                }
            #endif
                break;
            }

            /* advance state, since we received some data */
            mms_stat->read = MQTT_MSG_HEADER;

            /* capture length read */
            client->packet.buf_len = rc;

            /* Decode Packet - get type, qos and id */
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, NULL, &packet_type, &packet_qos,
                &packet_id, 1);
            if (rc < 0) {
                break;
            }

            MqttClient_PacketReset(packet_type, &client->msg);

        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Read Packet: Len %d, Type %d, ID %d",
                client->packet.buf_len, packet_type, packet_id);
        #endif

            /* Ping response is special case, no payload */
            if (packet_type != MQTT_PACKET_TYPE_PING_RESP) {
                mms_stat->read = MQTT_MSG_PAYLOAD;
            }
            else {
                mms_stat->read = MQTT_MSG_WAIT;
            }
        }
        FALL_THROUGH;

        case MQTT_MSG_PAYLOAD:
        case MQTT_MSG_PAYLOAD2:
        {
            MqttPublishResp resp;
            MqttPacketType use_packet_type;
        #ifdef WOLFMQTT_V5
            int pubrec_tracked = 0;

            /* A synchronous QoS 2 publish waits for PUBCOMP while processing
             * the intermediate PUBREC for the same Packet Identifier. */
            if (packet_type == MQTT_PACKET_TYPE_PUBLISH_REC &&
                    client->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                    wait_type == MQTT_PACKET_TYPE_PUBLISH_COMP &&
                    wait_packet_id != 0 && wait_packet_id == packet_id) {
                pubrec_tracked = 1;
            }
        #endif

            /* Determine if we received data for this request */
            if ((wait_type == MQTT_PACKET_TYPE_ANY ||
                 wait_type == packet_type ||
                 (MqttIsPubRespPacket(packet_type) &&
                  MqttIsPubRespPacket(wait_type))) &&
                (wait_packet_id == 0 || wait_packet_id == packet_id))
            {
                use_packet_obj = packet_obj;
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("Using INCOMING packet_obj %p", use_packet_obj);
            #endif
                if (packet_type == wait_type ||
                        wait_type == MQTT_PACKET_TYPE_ANY) {
                    /* Only stop waiting when matched or waiting for "any" */
                    waitMatchFound = 1;
                }
            }
            else {
            #ifdef WOLFMQTT_MULTITHREAD
                rc = wm_SemLock(&client->lockClient);
                if (rc != 0) {
                    break; /* error */
                }
            #endif

                /* use generic packet object */
                use_packet_obj = &client->msg;
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("Using SHARED packet_obj %p", use_packet_obj);
            #endif

            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockClient);
            #endif
            }
            use_packet_type = packet_type;

        #ifdef WOLFMQTT_MULTITHREAD
            /* Check to see if we have a pending response for this packet */
            pendResp = NULL;
            rc = wm_SemLock(&client->lockClient);
            if (rc == 0) {
                if (MqttClient_RespList_Find(client, packet_type, packet_id,
                                                               &pendResp)) {
                    /* we found packet match this incoming read packet */
                    pendResp->packetProcessing = 1;
                    if (pendResp->packet_obj != packet_obj
                    #ifdef WOLFMQTT_V5
                            || (wait_type == MQTT_PACKET_TYPE_ANY &&
                                packet_type == MQTT_PACKET_TYPE_AUTH &&
                                pendResp == &client->packetAck.pendResp)
                    #endif
                    ) {
                        use_packet_obj = pendResp->packet_obj;
                        use_packet_type = pendResp->packet_type;
                        /* req from another thread... not a match */
                        waitMatchFound = 0;
                    }
                }
            #ifdef WOLFMQTT_V5
                /* A reader thread receives the intermediate PUBREC while the
                 * publisher's pending entry is keyed by the final PUBCOMP. */
                if (!pubrec_tracked &&
                        packet_type == MQTT_PACKET_TYPE_PUBLISH_REC &&
                        client->protocol_level >=
                            MQTT_CONNECT_PROTOCOL_LEVEL_5) {
                    MqttPendResp* qos2Resp;

                    for (qos2Resp = client->firstPendResp;
                         qos2Resp != NULL; qos2Resp = qos2Resp->next) {
                        if (qos2Resp->packet_type ==
                                MQTT_PACKET_TYPE_PUBLISH_COMP &&
                                qos2Resp->packet_id == packet_id &&
                                !qos2Resp->packetDone) {
                            pubrec_tracked = 1;
                            /* This belongs to the publisher's flow, not the
                             * generic WaitMessage caller. */
                            waitMatchFound = 0;
                            break;
                        }
                    }
                }
            #endif
                wm_SemUnlock(&client->lockClient);
            }
            else {
                break; /* error */
            }
        #endif /* WOLFMQTT_MULTITHREAD */

            /* for payload state packet type is always publish */
            if (use_packet_type == MQTT_PACKET_TYPE_RESERVED &&
                    (mms_stat->read == MQTT_MSG_PAYLOAD ||
                     mms_stat->read == MQTT_MSG_PAYLOAD2))
            {
                use_packet_type = MQTT_PACKET_TYPE_PUBLISH;
            }
            /* cache publish packet id and qos for MqttClient_HandlePacket payload */
            if (use_packet_type == MQTT_PACKET_TYPE_PUBLISH &&
                  mms_stat->read == MQTT_MSG_PAYLOAD && use_packet_obj != NULL)
            {
                MqttObject* obj = (MqttObject*)use_packet_obj;
                obj->publish.qos = packet_qos;
                obj->publish.packet_id = packet_id;
            }

            /* Perform packet handling for publish callback and QoS */
            XMEMSET(&resp, 0, sizeof(resp));
            rc = MqttClient_HandlePacket(client, use_packet_type,
                use_packet_obj, &resp, timeout_ms);

        #ifdef WOLFMQTT_V5
            /* [MQTT-3.6.2.1] An unsolicited PUBREC is answered with PUBREL
             * reason 0x92 instead of falsely advancing an unknown flow. */
            if (rc >= 0 &&
                    packet_type == MQTT_PACKET_TYPE_PUBLISH_REC &&
                    client->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                    resp.packet_type == MQTT_PACKET_TYPE_PUBLISH_REL &&
                    !pubrec_tracked) {
                resp.reason_code = MQTT_REASON_PACKET_ID_NOT_FOUND;
            }
        #endif

            /* if using the shared packet object, make sure the original
             * state is correct for publish payload 2 (continued) */
            if (use_packet_obj != NULL && use_packet_obj != mms_stat &&
                    ((MqttMsgStat*)use_packet_obj)->read == MQTT_MSG_PAYLOAD2) {
                mms_stat->read = MQTT_MSG_PAYLOAD2;
            }

        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
        #endif

            /* handle success case */
            if (rc >= 0) {
                rc = MQTT_CODE_SUCCESS;
            }
            else {
                /* error, break */
                break;
            }

        #ifdef WOLFMQTT_MULTITHREAD
            if (pendResp) {
                /* Mark pending response entry done */
                if (wm_SemLock(&client->lockClient) == 0) {
                    pendResp->packetDone = 1;
                    pendResp->packet_ret = rc;
                #ifdef WOLFMQTT_V5
                    /* A write-only QoS>0 publish reserves a Receive Maximum unit
                     * but does not wait for its own ack; release it here as this
                     * reading thread completes the terminal PUBACK / PUBCOMP,
                     * via the reserving stat recorded on the pending response.
                     * Only reached on a completed (non-error) response, so no
                     * result gate is needed. Idempotent, so an ordinary publish
                     * that also releases in its waiting thread is unaffected. */
                    if (pendResp->recvQuotaStat != NULL) {
                        MqttClient_RecvQuotaRelease_Locked(client,
                            pendResp->recvQuotaStat);
                    }
                #endif
                #ifdef WOLFMQTT_DEBUG_CLIENT
                    PRINTF("PendResp Done %p", pendResp);
                #endif
                    pendResp = NULL;
                    wm_SemUnlock(&client->lockClient);
                }
            }
        #endif /* WOLFMQTT_MULTITHREAD */

            /* Determine if we are sending ACK or done */
            if (MqttIsPubRespPacket(resp.packet_type)) {
            #if defined(WOLFMQTT_V5) && defined(WOLFMQTT_MULTITHREAD)
                /* Registration of automatic AUTH and reuse of packetAck must
                 * be atomic under lockClient. The earlier protocol guard is
                 * only an early rejection; this closes its check/use window. */
                auto_auth_pending = 0;
                rc = wm_SemLock(&client->lockClient);
                if (rc != MQTT_CODE_SUCCESS) {
                    break;
                }
                for (pendResp = client->firstPendResp;
                     pendResp != NULL; pendResp = pendResp->next) {
                    if (pendResp == &client->packetAck.pendResp) {
                        auto_auth_pending = 1;
                        break;
                    }
                }
                if (!auto_auth_pending) {
                    XMEMCPY(&client->packetAck, &resp,
                        sizeof(MqttPublishResp));
                    client->packetAck.protocol_level = client->protocol_level;
                }
                wm_SemUnlock(&client->lockClient);
                if (auto_auth_pending) {
                    rc = MQTT_CODE_ERROR_PACKET_TYPE;
                    break;
                }
            #else
                /* setup ACK in shared context */
                XMEMCPY(&client->packetAck, &resp,
                    sizeof(MqttPublishResp));
            #ifdef WOLFMQTT_V5
                client->packetAck.protocol_level = client->protocol_level;
            #endif
            #endif

                /* Stage the acknowledgement on this wait object as well.
                 * client->packetAck above is shared by every reader, so a
                 * thread finishing its own PUBLISH read can overwrite it in
                 * the window between this read lock being dropped and the
                 * send lock being taken below, sending the later ack twice
                 * and never the earlier one. [MQTT-4.6.0-2] requires PUBACKs
                 * to be sent in the order their PUBLISHes were received, so
                 * the encode reads these per-object fields instead. */
                mms_stat->ackPacketType = resp.packet_type;
                mms_stat->ackPacketId = resp.packet_id;
            #ifdef WOLFMQTT_V5
                mms_stat->ackReasonCode = resp.reason_code;
                mms_stat->ackProps = resp.props;
                mms_stat->ackProtocolLevel = client->protocol_level;
            #endif

                /* if we get here, then we are sending an ACK */
                mms_stat->read = MQTT_MSG_ACK;
                mms_stat->ack = MQTT_MSG_WAIT;
            }

            /* done reading */
            MqttReadStop(client, mms_stat);
            break;
        }

        case MQTT_MSG_ACK:
            /* go to write section below */
            break;

        case MQTT_MSG_AUTH:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_WaitType: Invalid read state %d!",
                mms_stat->read);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
        }
    } /* switch (mms_stat->read) */

    /* Record whether the failure came from decoding/handling received data;
     * a local ack-encode failure below must not tear down a healthy link. */
    recvFatal = (rc < 0);
    if (recvFatal && MqttClient_IsFatalProtoError(rc)) {
        if (mms_stat->isWriteActive) {
            CLIENT_FORCE_ZERO(client->tx_buf, client->tx_buf_len);
            MqttWriteStop(client, mms_stat);
        }
        /* The cleanup below releases lockRecv. Reset the wait state with it so
         * a later reuse cannot bypass MqttReadStart and read without the lock. */
        mms_stat->read = MQTT_MSG_BEGIN;
        mms_stat->ack = MQTT_MSG_BEGIN;
        goto read_cleanup;
    }

    switch (mms_stat->ack)
    {
        case MQTT_MSG_BEGIN:
            /* wait for read to set ack */
            break;

        case MQTT_MSG_WAIT:
        {
            /* Flag write active / lock mutex */
            if ((rc = MqttWriteStart(client, mms_stat)) != 0) {
                break;
            }
            mms_stat->ack = MQTT_MSG_ACK;
        }
        FALL_THROUGH;

        case MQTT_MSG_ACK:
        {
            /* Rebuild the response from this wait object's staged fields, not
             * from the shared client->packetAck another reader may have
             * replaced since [MQTT-4.6.0-2]. */
            MqttPublishResp ackResp;

            XMEMSET(&ackResp, 0, sizeof(ackResp));
            ackResp.packet_type = mms_stat->ackPacketType;
            ackResp.packet_id = mms_stat->ackPacketId;
        #ifdef WOLFMQTT_V5
            ackResp.reason_code = mms_stat->ackReasonCode;
            ackResp.props = mms_stat->ackProps;
            ackResp.protocol_level = mms_stat->ackProtocolLevel;
        #endif

            /* send ack */
            rc = MqttEncode_PublishResp(client->tx_buf, client->tx_buf_len,
                ackResp.packet_type, &ackResp);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttEncode_PublishResp: Len %d, Type %s (%d), ID %d",
                rc, MqttPacket_TypeDesc(ackResp.packet_type),
                    ackResp.packet_type, ackResp.packet_id);
        #endif
            if (rc < 0) {
                MqttWriteStop(client, mms_stat);
                break;
            }

            client->write.len = rc;
            /* Note: static analyzer complains about set, but not used here.
             * Keeping it to ensure no future issues with rc > 0 */
            rc = MQTT_CODE_SUCCESS;
            (void)rc; /* inhibit clang-analyzer-deadcode.DeadStores */

            mms_stat->ack = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        {
            int xfer = client->write.len;

            /* Send publish response packet */
            rc = MqttPacket_Write(client, client->tx_buf, xfer);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                /* keep send mutex locked and return to caller */
                /* must keep send locked */
                return rc;
            }
        #endif
            MqttWriteStop(client, mms_stat);
            if (rc == xfer) {
                rc = MQTT_CODE_SUCCESS; /* success */
            }

        #ifndef WOLFMQTT_NO_SESSION_REPLAY
            /* A PUBREL this client sent is replayed instead of its PUBLISH
             * after a CleanSession 0 reconnect [MQTT-4.4.0-1]. */
            if (rc == MQTT_CODE_SUCCESS &&
                    mms_stat->ackPacketType == MQTT_PACKET_TYPE_PUBLISH_REL) {
                MqttClient_Replay_PubRelSentSafe(client,
                    mms_stat->ackPacketId);
            }
        #endif

            /* The staged acknowledgement is spent. */
            mms_stat->ackPacketType = MQTT_PACKET_TYPE_RESERVED;
            mms_stat->ack = MQTT_MSG_BEGIN; /* reset write state */
            break;
        }

        case MQTT_MSG_AUTH:
        case MQTT_MSG_PAYLOAD:
        case MQTT_MSG_PAYLOAD2:
        default:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_WaitType: Invalid ack state %d!",
                mms_stat->ack);
        #endif
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
            break;
    } /* switch (mms_stat->ack) */

    /* no data read or ack done, then reset state */
    if (mms_stat->read == MQTT_MSG_WAIT) {
        mms_stat->read = MQTT_MSG_BEGIN;
    }

#ifdef WOLFMQTT_NONBLOCK
    /* if nonblocking and some data has been read, do not release read lock */
    if (rc == MQTT_CODE_CONTINUE && mms_stat->read > MQTT_MSG_WAIT) {
        return rc;
    }
#endif

read_cleanup:
    if (recvFatal && MqttClient_IsFatalProtoError(rc)) {
        /* Scrub decoded peer data before releasing lockRecv. */
        CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
    }
    MqttReadStop(client, mms_stat);

#ifdef WOLFMQTT_NONBLOCK
    #ifdef WOLFMQTT_DEBUG_CLIENT
    #ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0)
    #endif
    {
        client->lastRc = rc;
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }
    #endif /* WOLFMQTT_DEBUG_CLIENT */
    if (rc == MQTT_CODE_CONTINUE) {
        return rc;
    }
#endif

    if (rc < 0) {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        if (rc != MQTT_CODE_CONTINUE) {
            PRINTF("MqttClient_WaitType: Failure: %s (%d)",
                MqttClient_ReturnCodeToString(rc), rc);
        }
    #endif
        /* Keep IS_CONNECTED honest after a fatal error so the caller sees a
         * dead connection. Only clear the flag; the application tears the
         * transport down via MqttClient_NetDisconnect. Freeing it here would
         * disconnect twice (with curl, double curl_global_cleanup) and could
         * race a concurrent publisher inside wolfSSL_write in MT builds. Gated
         * on recvFatal so a local ack-encode failure (e.g. an out-of-table
         * Reason Code) does not disconnect an otherwise healthy peer. */
        if (recvFatal && MqttClient_IsFatalProtoError(rc) &&
            (client->flags & MQTT_CLIENT_FLAG_IS_CONNECTED) != 0) {
            (void)MqttClient_Flags(client, MQTT_CLIENT_FLAG_IS_CONNECTED, 0);
        }
        return rc;
    }

    if (!waitMatchFound) {
        /* if we get here, then the we are still waiting for a packet */
        mms_stat->read = MQTT_MSG_BEGIN;
    #ifdef WOLFMQTT_NONBLOCK
        /* for non-blocking return with code continue instead of waiting again
         * if called with packet type and id of 'any' */
        if (wait_type == MQTT_PACKET_TYPE_ANY && wait_packet_id == 0) {
            return MQTT_CODE_CONTINUE;
        }
    #endif
        MQTT_TRACE_MSG("Wait Again");
        goto wait_again;
    }
#ifdef WOLFMQTT_DEBUG_CLIENT
    if (rc != MQTT_CODE_CONTINUE) {
        PRINTF("MqttClient_WaitType: rc %d, state %d-%d-%d",
            rc, mms_stat->read, mms_stat->write, mms_stat->ack);
    }
#endif


    return rc;
}


/* Public Functions */
int MqttClient_Init(MqttClient *client, MqttNet* net,
    MqttMsgCb msg_cb,
    byte* tx_buf, int tx_buf_len,
    byte* rx_buf, int rx_buf_len,
    int cmd_timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;

    /* Check arguments */
    if (client == NULL ||
        tx_buf == NULL || tx_buf_len <= 0 ||
        rx_buf == NULL || rx_buf_len <= 0 ||
        cmd_timeout_ms < 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Initialize the client structure to zero */
    XMEMSET(client, 0, sizeof(MqttClient));

    /* Setup client structure */
    client->msg_cb = msg_cb;
    client->tx_buf = tx_buf;
    client->tx_buf_len = tx_buf_len;
    client->rx_buf = rx_buf;
    client->rx_buf_len = rx_buf_len;
    client->cmd_timeout_ms = cmd_timeout_ms;
#ifdef WOLFMQTT_V5
    /* Initialize to this build's Maximum QoS. Handle_Props will narrow
     * this if the server advertises a lower MQTT_PROP_MAX_QOS. */
    client->max_qos = (MqttQoS)WOLFMQTT_MAX_QOS;
    client->retain_avail = 1;
    client->protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL;
    /* [MQTT-3.1.2.11.3]: absent Receive Maximum means 65535. */
    client->server_recv_max = 65535;
    client->server_recv_max_negotiated = 65535;
    /* [MQTT-3.1.2.11.8]: absent Topic Alias Maximum means none accepted. */
    client->topic_alias_max = 0;
    rc = MqttProps_Init();
    if (rc == MQTT_CODE_SUCCESS) {
        client->props_initialized = 1;
    }
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (rc == 0) {
        rc = wm_SemInit(&client->lockSend);
        if (rc == 0) {
            client->init_flags |= MQTT_CLIENT_INIT_LOCK_SEND;
        }
    }
    if (rc == 0) {
        rc = wm_SemInit(&client->lockRecv);
        if (rc == 0) {
            client->init_flags |= MQTT_CLIENT_INIT_LOCK_RECV;
        }
    }
    if (rc == 0) {
        rc = wm_SemInit(&client->lockClient);
        if (rc == 0) {
            client->init_flags |= MQTT_CLIENT_INIT_LOCK_CLIENT;
        }
    }
    #ifdef ENABLE_MQTT_CURL
    if (rc == 0) {
        rc = wm_SemInit(&client->lockCURL);
        if (rc == 0) {
            client->init_flags |= MQTT_CLIENT_INIT_LOCK_CURL;
        }
    }
    #endif
#endif

    if (rc == 0) {
        /* Init socket */
        rc = MqttSocket_Init(client, net);
    }

    if (rc != 0) {
        /* Cleanup if init failed */
        MqttClient_DeInit(client);
    }

    return rc;
}

void MqttClient_DeInit(MqttClient *client)
{
    if (client != NULL) {
#ifndef WOLFMQTT_NO_SESSION_REPLAY
        /* Release the retained outbound Session copies. */
        MqttClient_Replay_Reset(client);
#endif
#ifdef WOLFMQTT_MULTITHREAD
    #ifdef ENABLE_MQTT_CURL
        if ((client->init_flags & MQTT_CLIENT_INIT_LOCK_CURL) != 0U) {
            if (wm_SemFree(&client->lockCURL) == MQTT_CODE_SUCCESS) {
                client->init_flags &= (byte)~MQTT_CLIENT_INIT_LOCK_CURL;
            }
        }
    #endif
        if ((client->init_flags & MQTT_CLIENT_INIT_LOCK_CLIENT) != 0U) {
            if (wm_SemFree(&client->lockClient) == MQTT_CODE_SUCCESS) {
                client->init_flags &= (byte)~MQTT_CLIENT_INIT_LOCK_CLIENT;
            }
        }
        if ((client->init_flags & MQTT_CLIENT_INIT_LOCK_RECV) != 0U) {
            if (wm_SemFree(&client->lockRecv) == MQTT_CODE_SUCCESS) {
                client->init_flags &= (byte)~MQTT_CLIENT_INIT_LOCK_RECV;
            }
        }
        if ((client->init_flags & MQTT_CLIENT_INIT_LOCK_SEND) != 0U) {
            if (wm_SemFree(&client->lockSend) == MQTT_CODE_SUCCESS) {
                client->init_flags &= (byte)~MQTT_CLIENT_INIT_LOCK_SEND;
            }
        }
#endif
#ifdef WOLFMQTT_V5
        if (client->props_initialized != 0U) {
            if (MqttProps_ShutDown() == MQTT_CODE_SUCCESS) {
                client->props_initialized = 0;
            }
        }
#endif
    }
}

#ifdef WOLFMQTT_DISCONNECT_CB
int MqttClient_SetDisconnectCallback(MqttClient *client,
        MqttDisconnectCb discCb, void* ctx)
{
    if (client == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);

    client->disconnect_cb = discCb;
    client->disconnect_ctx = ctx;

    return MQTT_CODE_SUCCESS;
}
#endif

#ifdef WOLFMQTT_PROPERTY_CB
int MqttClient_SetPropertyCallback(MqttClient *client, MqttPropertyCb propCb,
    void* ctx)
{
    if (client == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);

    client->property_cb = propCb;
    client->property_ctx = ctx;

    return MQTT_CODE_SUCCESS;
}
#endif

#ifdef WOLFMQTT_V5
/* Return 1 if the CONNECT carries an Authentication Method property, i.e. the
 * connection is negotiating enhanced authentication [MQTT-4.12]. */
/* Record the CONNECT Authentication Method (presence and value) so a later AUTH
 * must reuse it [MQTT-4.12.0-1]. A value longer than MQTT_AUTH_METHOD_MAX sets
 * auth_method_len but is not stored, so MqttClient_Auth refuses re-auth. */
static void MqttClient_StoreAuthMethod(MqttClient* client,
    const MqttConnect* mc_connect)
{
    const MqttProp* prop;

    client->auth_method_set = 0;
    client->auth_method_len = 0;
    for (prop = (mc_connect != NULL) ? mc_connect->props : NULL;
         prop != NULL; prop = prop->next) {
        if (prop->type == MQTT_PROP_AUTH_METHOD) {
            client->auth_method_set = 1;
            client->auth_method_len = prop->data_str.len;
            if (prop->data_str.len <= MQTT_AUTH_METHOD_MAX &&
                    prop->data_str.str != NULL) {
                XMEMCPY(client->auth_method, prop->data_str.str,
                    prop->data_str.len);
            }
            return;
        }
    }
}

#if WOLFMQTT_MAX_QOS >= 2
/* Return 1 if the CONNECT already carries a Receive Maximum property, i.e. the
 * application picked its own inbound flow-control window. */
static int MqttConnect_HasRecvMax(const MqttConnect* mc_connect)
{
    const MqttProp* prop;

    if (mc_connect == NULL) {
        return 0;
    }
    for (prop = mc_connect->props; prop != NULL; prop = prop->next) {
        if (prop->type == MQTT_PROP_RECEIVE_MAX) {
            return 1;
        }
    }
    return 0;
}
#endif /* WOLFMQTT_MAX_QOS >= 2 */
#endif

#ifndef WOLFMQTT_NO_SESSION_REPLAY
/* Encode the replay packet for client->replay[client->replayIdx] into
 * client->tx_buf. Returns the encoded length, 0 when the slot has nothing to
 * send, or a negative error when the client lock could not be taken.
 *
 * When the entry cannot be rebuilt it is dropped here and its Packet
 * Identifier is reported through dropped_id so the caller can release the
 * reservation the reconnect took for it. That release cannot happen inside
 * this function: MqttClient_SendIdRelease takes client->lockClient, which is
 * held below and is not recursive.
 *
 * Takes client->lockClient because the receive path frees a slot as soon as
 * its acknowledgement arrives: the slot fields, and the topic and payload
 * buffers the encoder copies out of it, must not be read without it. The
 * caller already holds lockSend, which is the lockSend -> lockClient order
 * used everywhere else. */
static int MqttClient_Replay_EncodeNext(MqttClient* client, word16* dropped_id)
{
    MqttReplayMsg* slot;
    int rc = 0;
    int keep = 0;

    *dropped_id = 0;
#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#endif
    slot = &client->replay[client->replayIdx];

    /* Empty slots, and PUBLISHes whose payload could not be retained, have
     * nothing to send. The entry is kept rather than dropped: the server may
     * still acknowledge the message it stands for, and that acknowledgement
     * is what releases both the slot and its Packet Identifier
     * [MQTT-2.3.1-3]. */
    if (slot->packet_id == 0 || (!slot->pubrelSent && !slot->haveCopy)) {
        rc = 0;
        keep = 1;
    }
    else if (slot->pubrelSent) {
        MqttPublishResp rel;

        XMEMSET(&rel, 0, sizeof(rel));
        rel.packet_id = slot->packet_id;
        rel.packet_type = MQTT_PACKET_TYPE_PUBLISH_REL;
    #ifdef WOLFMQTT_V5
        rel.protocol_level = client->protocol_level;
    #endif
        rc = MqttEncode_PublishResp(client->tx_buf, client->tx_buf_len,
            MQTT_PACKET_TYPE_PUBLISH_REL, &rel);
    }
    else {
        MqttPublish pub;

        XMEMSET(&pub, 0, sizeof(pub));
        pub.packet_id = slot->packet_id;
        pub.qos = (MqttQoS)slot->qos;
        pub.retain = slot->retain;
        pub.duplicate = 1; /* [MQTT-3.3.1-1] */
        pub.topic_name = slot->topic;
        pub.buffer = slot->payload;
        pub.buffer_len = slot->payload_len;
        pub.total_len = slot->payload_len;
    #ifdef WOLFMQTT_V5
        pub.protocol_level = client->protocol_level;
    #endif
        rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len, &pub, 0);
        /* MqttEncode_Publish declares the full Remaining Length in the fixed
         * header but clamps the payload it copies to what tx_buf holds,
         * leaving the remainder to MqttClient_Publish_WritePayload. The replay
         * sends a single buffer and has no such second stage, so a clamped
         * payload would put a short packet on the wire behind a longer
         * declared length and desynchronize the stream. Drop it instead. */
        if (rc > 0 && pub.buffer_pos != slot->payload_len) {
            rc = 0;
        }
    }

    if (rc <= 0 && !keep) {
        /* Cannot rebuild this one (e.g. it no longer fits tx_buf). Drop it
         * rather than stalling the rest of the replay, and report the
         * identifier so the caller can give it back - nothing will ever
         * acknowledge a message the client has abandoned. */
        CLIENT_FORCE_ZERO(client->tx_buf, client->tx_buf_len);
        *dropped_id = slot->packet_id;
        MqttClient_Replay_FreeSlot(slot);
        rc = 0;
    }
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
    return rc;
}

/* Re-send the retained Session messages after a CleanSession 0 reconnect the
 * server answered with Session Present = 1. [MQTT-4.4.0-1] requires every
 * unacknowledged QoS > 0 PUBLISH and PUBREL to go out again with its original
 * Packet Identifier, and [MQTT-3.3.1-1] requires DUP on the re-delivered
 * PUBLISH. Resumable: client->replayIdx records how far it got, so a
 * nonblocking caller re-enters and continues rather than restarting. */
static int MqttClient_ReplaySession(MqttClient* client,
    MqttConnect* mc_connect)
{
    int rc = MQTT_CODE_SUCCESS;

    while (client->replayIdx < MQTT_MAX_REPLAY_MSGS) {
        int xfer;
        word16 dropped_id;

        if (!mc_connect->stat.isWriteActive) {
            rc = MqttWriteStart(client, &mc_connect->stat);
            if (rc != MQTT_CODE_SUCCESS) {
                return rc; /* MQTT_CODE_CONTINUE while another write runs */
            }

            rc = MqttClient_Replay_EncodeNext(client, &dropped_id);
            if (rc <= 0) {
                MqttWriteStop(client, &mc_connect->stat);
                if (rc < 0) {
                    return rc; /* client lock failed */
                }
                /* Outside the client lock, which SendIdRelease takes. */
                if (dropped_id != 0) {
                    MqttClient_SendIdRelease(client, dropped_id,
                        MQTT_PACKET_TYPE_RESERVED);
                }
                client->replayIdx++; /* nothing to send from this slot */
                continue;
            }
            client->write.len = rc;
        }

        xfer = client->write.len;
        rc = MqttPacket_Write(client, client->tx_buf, xfer);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE) {
            return rc; /* keep send locked and resume here */
        }
    #endif
        MqttWriteStop(client, &mc_connect->stat);
        if (rc != xfer) {
            return rc; /* transport failed; the entry stays retained */
        }
        client->replayIdx++;
    }

    return MQTT_CODE_SUCCESS;
}
#endif /* !WOLFMQTT_NO_SESSION_REPLAY */

/* [MQTT-3.1.0-1] After a Network Connection is established by a Client to a
 * Server, the first Packet sent from the Client to the Server MUST be a
 * CONNECT Packet. MQTT_CLIENT_FLAG_IS_CONNECTED tracks only the transport, so
 * the send APIs consult MQTT_CLIENT_FLAG_CONNECT_SENT to refuse a PUBLISH,
 * SUBSCRIBE, UNSUBSCRIBE, PINGREQ or DISCONNECT that would otherwise become
 * the first MQTT packet on the wire. A Client need not wait for CONNACK
 * (section 3.1.4), so this checks only that CONNECT has been sent. Callers
 * have already rejected a NULL client. Reads client->flags directly rather
 * than through MqttClient_Flags so a lock failure is propagated instead of
 * being reported as "no flags set", and so the NULL branch inside that helper
 * does not leave GCC a path where client is NULL after the caller checked it
 * (which produced a false -Warray-bounds under partial inlining). */
static int MqttClient_ReadFlags(MqttClient *client, word32 *flags)
{
#ifdef WOLFMQTT_MULTITHREAD
    int rc = wm_SemLock(&client->lockClient);
    if (rc != 0) {
        return rc;
    }
#endif
    *flags = client->flags;
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
    return MQTT_CODE_SUCCESS;
}

static int MqttClient_CheckConnectSent(MqttClient *client)
{
    word32 flags = 0;
    int rc;

    rc = MqttClient_ReadFlags(client, &flags);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    if ((flags & MQTT_CLIENT_FLAG_CONNECT_SENT) == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
    }
    /* [MQTT-3.14.4-1] Nothing may follow a DISCONNECT on this connection. */
    if ((flags & MQTT_CLIENT_FLAG_DISCONNECT_SENT) != 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
    }
    return MQTT_CODE_SUCCESS;
}

#ifndef WOLFMQTT_NO_TIME
/* Apply the auto keep-alive decision once a connect attempt has reached a
 * final result. Shared by the normal handshake tail and by the
 * [MQTT-4.4.0-1] replay resume path, which returns to the caller before
 * reaching that tail; must not be called for MQTT_CODE_CONTINUE, which would
 * discard a v5 Server Keep Alive before the attempt has finished. */
static void MqttClient_ConnectKeepAlive(MqttClient* client,
    const MqttConnect* mc_connect, int rc)
{
    if (rc == MQTT_CODE_SUCCESS) {
        /* Connection accepted: arm auto keep-alive. A v5 Server Keep Alive
         * (applied while processing CONNACK) takes precedence, including a
         * value of 0 which disables keep-alive per [MQTT-3.1.2.11.2];
         * otherwise use the client-requested value. */
        if (!client->keep_alive_from_server) {
            client->keep_alive_sec = mc_connect->keep_alive_sec;
        }
        /* Baseline the idle timer from the completed handshake so the first
         * ping is scheduled a full interval out, not immediately. */
        client->last_tx_time = WOLFMQTT_GET_TIME_S();
    }
    else {
        /* Connect failed or was refused: leave the scheduler disarmed. */
        client->keep_alive_sec = 0;
    }
    client->keep_alive_from_server = 0;
}
#endif

int MqttClient_Connect(MqttClient *client, MqttConnect *mc_connect)
{
    int rc;
    word32 connect_flags = 0;
#ifdef WOLFMQTT_SESSION_ID_TRACK
    int session_id_matched = 0;
#endif
#if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 2
    MqttProp recv_max_prop;
    MqttProp* app_props = NULL;
    int recv_max_added = 0;
#endif

    /* Validate required arguments */
    if (client == NULL || mc_connect == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

#ifndef WOLFMQTT_NO_SESSION_REPLAY
    if (mc_connect->stat.write == MQTT_MSG_PAYLOAD) {
        /* MQTT_MSG_PAYLOAD is not part of the CONNECT write sequence
         * (MQTT_MSG_BEGIN -> MQTT_MSG_HEADER -> MQTT_MSG_AUTH/MQTT_MSG_WAIT);
         * it marks an [MQTT-4.4.0-1] replay this call started earlier and did
         * not finish. The CONNECT_SENT check pairs the sentinel with the
         * Network Connection it was set on, so one left behind by a failed
         * replay cannot make the replay the first packet of a new connection
         * [MQTT-3.1.0-1]. */
        if (MqttClient_CheckConnectSent(client) == MQTT_CODE_SUCCESS) {
            rc = MqttClient_ReplaySession(client, mc_connect);
            if (rc != MQTT_CODE_CONTINUE) {
                /* Finished, either way: clear the sentinel so a failed replay
                 * cannot bypass the handshake on the next call, and settle
                 * the keep-alive scheduler the tail of this function never
                 * reached. */
                mc_connect->stat.write = MQTT_MSG_BEGIN;
            #ifndef WOLFMQTT_NO_TIME
                MqttClient_ConnectKeepAlive(client, mc_connect, rc);
            #endif
            }
            return rc;
        }
        /* Stale sentinel on a fresh Network Connection: start over. */
        mc_connect->stat.write = MQTT_MSG_BEGIN;
    }
#endif

    if (mc_connect->stat.write == MQTT_MSG_BEGIN) {
        /* [MQTT-3.1.0-2] A Client can only send the CONNECT Packet once over a
         * Network Connection; a Server must treat a second one as a protocol
         * violation and disconnect. A partially written CONNECT re-enters with
         * stat.write past MQTT_MSG_BEGIN, so resuming one is unaffected -
         * only a new handshake attempt on the same transport is refused. The
         * application must close the Network Connection with
         * MqttClient_NetDisconnect before connecting again. */
        /* Read the flag under lockClient rather than through
         * MqttClient_Flags, which reports "no flags set" when the lock cannot
         * be taken - that would let a second CONNECT through the guard
         * instead of failing closed. */
        rc = MqttClient_ReadFlags(client, &connect_flags);
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }
        if ((connect_flags & MQTT_CLIENT_FLAG_CONNECT_SENT) != 0) {
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
        }

        /* Past the guard, so this really is a new handshake: start a fresh
         * outbound Packet Identifier space. The client keeps no
         * unacknowledged outbound PUBLISH/PUBREL across a Network Connection,
         * so nothing from a previous one is still in flight [MQTT-2.3.1-3].
         * Must run after the guard above - a refused duplicate CONNECT would
         * otherwise wipe identifiers still in flight on the live connection -
         * and outside the WOLFMQTT_V5 block below, since the table exists in
         * every build. */
        MqttClient_SendIdsReset(client);

    #ifdef WOLFMQTT_V5
        #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == MQTT_CODE_SUCCESS) {
            MqttClient_RespList_Remove(client,
                &client->packetAck.pendResp);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }
        #endif
        rc = MqttClient_CancelMessage(client,
            (MqttObject*)&mc_connect->ack);
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }
        XMEMSET(&mc_connect->ack, 0, sizeof(mc_connect->ack));

        /* Record whether this connection negotiates enhanced authentication and
         * retain the Authentication Method value so a later MqttClient_Auth can
         * be refused when no method was sent and required to reuse the same
         * method [MQTT-4.12.0-1]. Recomputed each connect, so it also resets
         * across a reconnect on the same client. */
        MqttClient_StoreAuthMethod(client, mc_connect);
    #endif
        /* Warn if credentials are being sent without TLS */
    #ifdef WOLFMQTT_DEBUG_CLIENT
        if ((mc_connect->username != NULL || mc_connect->password != NULL) &&
            !(MqttClient_Flags(client, 0, 0) & MQTT_CLIENT_FLAG_IS_TLS)) {
            PRINTF("Warning: MQTT credentials are being sent without TLS");
        }
    #endif

    #ifndef WOLFMQTT_NO_TIME
        /* Disarm auto keep-alive for the handshake; it is armed only after
         * CONNACK is accepted at the end of this function. Fully cancel any
         * ping left mid-exchange by a prior connection so its held locks and
         * pending response are released before the new write starts, rather
         * than leaving the ping state machine to stall a later wait. Must run
         * before MqttWriteStart so the send lock is free when it is taken.
         * Propagate a cancel failure - only reachable if wm_SemLock itself
         * errors (e.g. on ThreadX), since it otherwise blocks until acquired -
         * rather than starting the write with locks the abandoned ping may
         * still hold. */
        client->keep_alive_sec = 0;
        client->keep_alive_from_server = 0;
        rc = MqttClient_CancelMessage(client,
            (MqttObject*)&client->keep_alive_ping);
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }
    #endif

        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, &mc_connect->stat)) != 0) {
            return rc;
        }

    #ifdef WOLFMQTT_V5
        /* Use specified protocol version if set */
        mc_connect->protocol_level = client->protocol_level;

        /* Reset server-supplied session limits so stale values from a
         * prior broker do not leak across reconnects. An accepted CONNACK
         * will repopulate these in Handle_ConnectAck_Props. Initialize to
         * this build's Maximum QoS so the runtime guard in MqttPublishMsg
         * caps publishes even before CONNACK is processed. */
        client->max_qos = (MqttQoS)WOLFMQTT_MAX_QOS;
        client->retain_avail = 1;
        client->packet_sz_max = 0;
        client->server_recv_max = 65535;
        client->server_recv_max_negotiated = 65535;
        client->topic_alias_max = 0;
    #endif

    #if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 2
        /* [MQTT-3.3.4] Receive Maximum bounds the QoS 1 and QoS 2 PUBLISH
         * packets the server may have in flight toward this client. The inbound
         * QoS 2 de-duplication table tracks MQTT_MAX_RECV_QOS2 packet ids
         * awaiting PUBREL; with no advertised limit a server may exceed it, and
         * an id that no longer fits goes untracked, so a retransmit of it would
         * reach the application a second time [MQTT-4.3.3-10]. Advertising the
         * table size keeps a conforming server inside it. An application that
         * supplied its own Receive Maximum keeps it - that is an explicit
         * choice, and above MQTT_MAX_RECV_QOS2 the dedup is best effort again.
         * The property lives on this stack frame and is linked only across the
         * encode below, so the caller's list is unchanged on return. */
        if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                !MqttConnect_HasRecvMax(mc_connect)) {
            XMEMSET(&recv_max_prop, 0, sizeof(recv_max_prop));
            recv_max_prop.type = MQTT_PROP_RECEIVE_MAX;
            recv_max_prop.data_short = (word16)MQTT_MAX_RECV_QOS2;
            recv_max_prop.next = mc_connect->props;
            app_props = mc_connect->props;
            mc_connect->props = &recv_max_prop;
            recv_max_added = 1;
        }
    #endif

        /* Encode the connect packet */
        rc = MqttEncode_Connect(client->tx_buf, client->tx_buf_len, mc_connect);
    #if defined(WOLFMQTT_V5) && WOLFMQTT_MAX_QOS >= 2
        /* Unlink the stack-local property before anything else walks or frees
         * the caller's list. */
        if (recv_max_added) {
            mc_connect->props = app_props;
        }
    #endif
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_CONNECT),
            MQTT_PACKET_TYPE_CONNECT, 0, 0);
    #endif
        if (rc <= 0) {
            /* Encode failed: tx_buf may hold partial plaintext credentials.
             * Zero the full buffer before MqttWriteStop releases lockSend
             * so no other thread can see residual data. */
            CLIENT_FORCE_ZERO(client->tx_buf, client->tx_buf_len);
            MqttWriteStop(client, &mc_connect->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_CONNECT_ACK,
                    0, &mc_connect->pendResp, &mc_connect->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            /* Save write.len before MqttWriteStop zeroes client->write */
            int xfer = client->write.len;
            /* Clear tx_buf to remove plaintext credentials BEFORE
             * MqttWriteStop releases lockSend, so another thread cannot
             * race in and repopulate tx_buf before it is scrubbed. */
            CLIENT_FORCE_ZERO(client->tx_buf, xfer);
            MqttWriteStop(client, &mc_connect->stat);
            return rc; /* Error locking client */
        }
    #endif

        mc_connect->stat.write = MQTT_MSG_HEADER;
    }
    if (mc_connect->stat.write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;
        int wrote;

        /* Send connect packet */
        rc = MqttPacket_Write(client, client->tx_buf, xfer);

        /* Bytes this call put on the transport. MqttSocket_Write leaves
         * write.pos at the partial count and clears it only on a complete
         * write, so read it before MqttWriteStop resets the state. */
        wrote = (rc == xfer) ? xfer : client->write.pos;
        if (wrote > 0) {
            /* CONNECT bytes are on the wire, so this Network Connection has
             * had its one CONNECT [MQTT-3.1.0-2] and the other send APIs are
             * no longer blocked by [MQTT-3.1.0-1]. A Client need not wait for
             * CONNACK before sending more packets (section 3.1.4). Keyed on
             * bytes rather than the return code: a nonblocking write reports
             * MQTT_CODE_CONTINUE even when it accepted nothing, and a
             * blocking one reports an error after getting part of the packet
             * out. Resuming this same write re-enters past MQTT_MSG_BEGIN, so
             * the once-per-connection guard does not see it. */
            (void)MqttClient_Flags(client, 0, MQTT_CLIENT_FLAG_CONNECT_SENT);
        }
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE
        #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
            && client->write.total > 0
        #endif
        ) {
            /* keep send locked and return early.
             * Note: tx_buf still contains credentials until write completes */
            return rc;
        }
    #endif
        /* Clear tx_buf to remove any plaintext credentials from memory
         * BEFORE MqttWriteStop releases lockSend, so another thread cannot
         * race in and populate tx_buf before it is scrubbed.
         * Use xfer (saved before MqttWriteStop zeroes client->write). */
        CLIENT_FORCE_ZERO(client->tx_buf, xfer);
        MqttWriteStop(client, &mc_connect->stat);

        if (rc != xfer) {
            /* The handshake state set above stands or not on whether bytes
             * reached the peer, so a retry is refused only when some of this
             * CONNECT is already out there. */
            MqttClient_CancelMessage(client, (MqttObject*)mc_connect);
            return rc;
        }

    #ifdef WOLFMQTT_V5
        /* Enhanced authentication */
        if (client->enable_eauth == 1) {
            mc_connect->stat.write = MQTT_MSG_AUTH;
        }
        else
    #endif
        {
            mc_connect->stat.write = MQTT_MSG_WAIT;
        }
    }

#ifdef WOLFMQTT_V5
    /* Enhanced authentication */
    if (mc_connect->protocol_level > MQTT_CONNECT_PROTOCOL_LEVEL_4 &&
            mc_connect->stat.write == MQTT_MSG_AUTH)
    {
        MqttAuth auth;
        MqttProp auth_prop;
        MqttMsgStat* auth_stat = &mc_connect->ack.stat;
        int auth_rc;

        XMEMSET(&auth, 0, sizeof(auth));
        if (auth_stat->write == MQTT_MSG_BEGIN) {
            MqttProp* conn_prop;

            /* Find the AUTH property in the connect structure. It is only
             * needed for the initial encode; retries resume buffered state. */
            for (conn_prop = mc_connect->props;
                 (conn_prop != NULL) &&
                     (conn_prop->type != MQTT_PROP_AUTH_METHOD);
                 conn_prop = conn_prop->next) {
            }
            if (conn_prop == NULL) {
            #ifdef WOLFMQTT_MULTITHREAD
                if (wm_SemLock(&client->lockClient) == 0) {
                    MqttClient_RespList_Remove(client,
                        &mc_connect->pendResp);
                    wm_SemUnlock(&client->lockClient);
                }
            #endif
                /* AUTH property was not set in connect structure */
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
            }

            /* Set the authentication reason */
            auth.reason_code = MQTT_REASON_CONT_AUTH;
            auth_prop = *conn_prop;
            auth_prop.next = NULL;
            auth.props = &auth_prop;
        }

        /* Keep the state in the CONNECT ACK and the pending-response node in
         * the persistent publish-ack object. Its reuse is serialized under
         * lockClient while another thread dispatches the AUTH response. */
        rc = MqttClient_AuthEx(client, &auth, auth_stat,
        #ifdef WOLFMQTT_MULTITHREAD
            &client->packetAck.pendResp,
        #endif
            &client->msg);
    #if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
        if (rc == MQTT_CODE_CONTINUE) {
            return rc;
        }
    #endif
    #ifdef WOLFMQTT_MULTITHREAD
        if (rc < 0) {
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &mc_connect->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        }
    #endif
        auth_rc = rc;
        XMEMSET(auth_stat, 0, sizeof(*auth_stat));
        rc = auth_rc;
        if (rc < 0) {
            return rc;
        }
        mc_connect->stat.write = MQTT_MSG_WAIT;
    }
#endif /* WOLFMQTT_V5 */

    /* Wait for connect ack packet */
    rc = MqttClient_WaitType(client, &mc_connect->ack,
        MQTT_PACKET_TYPE_CONNECT_ACK, 0, client->cmd_timeout_ms, NULL);
#if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &mc_connect->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

#ifdef WOLFMQTT_V5
    /* Scrub the decoded v5 CONNACK from rx_buf. Its properties (e.g. the
     * MQTT_PROP_AUTH_DATA SASL server-final blob used by enhanced
     * authentication) decode as pointers into rx_buf and would otherwise
     * linger until the next read overwrites them - for an idle or QoS-0-only
     * client, potentially the process lifetime. MqttClient_WaitType already
     * delivered and freed the property list above, so the bytes are consumed
     * and no live pointer into rx_buf remains. Same hardening as
     * MqttClient_Auth; v3.1.1 CONNACK carries no properties so gate on v5. */
    if (mc_connect->protocol_level > MQTT_CONNECT_PROTOCOL_LEVEL_4) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Hold lockRecv so the scrub cannot race a concurrent rx_buf read. If
         * the lock cannot be taken, still scrub: leaving the AUTH_DATA
         * plaintext behind is worse than an unsynchronized wipe. */
        if (wm_SemLock(&client->lockRecv) == 0) {
            CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
            wm_SemUnlock(&client->lockRecv);
        }
        else {
            CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
        }
    #else
        CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
    #endif
    }
#endif

    /* reset state */
    mc_connect->stat.write = MQTT_MSG_BEGIN;

    /* The CONNACK exchange is finished, so its wait state must not carry into
     * a later handshake on the same object - the bundled examples reuse one
     * MqttConnect across reconnects. MqttClient_WaitType dispatches on the
     * stat of the object it was given, here mc_connect->ack: left at
     * MQTT_MSG_PAYLOAD it would skip the read on the next call and hand
     * whatever is still in rx_buf to the PUBLISH payload handler instead of
     * waiting for the new CONNACK. */
    mc_connect->ack.stat.read = MQTT_MSG_BEGIN;
    mc_connect->ack.stat.ack = MQTT_MSG_BEGIN;

    /* CONNACK was received and decoded, but the broker refused the
     * connection. The specific reason is in mc_connect->ack.return_code
     * (MqttConnectAckReturnCodes for v3.1.1, MqttReasonCodes for v5). */
    if (rc == MQTT_CODE_SUCCESS &&
            mc_connect->ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
        rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_CONNECT_REFUSED);
    }

    /* [MQTT-3.2.2-1] / [MQTT-3.2.2-4] A Server MUST report Session Present = 0
     * when the Client requested Clean Session / Clean Start. A successful
     * CONNACK that reports Session Present = 1 is then a protocol violation:
     * refuse it rather than proceed on session state the client never had.
     * Returning an error also leaves keep-alive disarmed below, and the caller
     * tears the transport down as it does for a refused CONNACK. */
    if (rc == MQTT_CODE_SUCCESS && mc_connect->clean_session &&
            (mc_connect->ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT)) {
        rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
    }

#ifdef WOLFMQTT_SESSION_ID_TRACK
    /* [MQTT-3.1.3-2] The ClientId identifies the Client and its Session, so
     * session state carries over only when the ClientId is the same one that
     * created it. Compared here, before the per-table decisions below, because
     * the recorded ClientId is updated as part of them. */
    if (rc == MQTT_CODE_SUCCESS) {
        session_id_matched =
            MqttClient_SessionIdMatches(client, mc_connect->client_id);
        MqttClient_SessionIdRecord(client, mc_connect->client_id);
    }
#endif

#if WOLFMQTT_MAX_QOS >= 2
    /* The server's Session Present flag, not the client's request, decides
     * whether inbound QoS 2 dedup state carries over. Keep it only when the
     * server resumed the session (Session Present = 1); on any fresh session -
     * a requested Clean Start or a resume the server declined - drop stale
     * pending packet ids so they cannot suppress a new inbound QoS 2 PUBLISH
     * that reuses one [MQTT-4.3.3-10]. Packet ids also restart per connection,
     * so a fresh session must start with an empty table. */
    if (rc == MQTT_CODE_SUCCESS) {
        if (!(mc_connect->ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ||
                !session_id_matched) {
            XMEMSET(client->recv_qos2_pending, 0,
                sizeof(client->recv_qos2_pending));
        }
    }
#endif

#ifndef WOLFMQTT_NO_SESSION_REPLAY
    if (rc == MQTT_CODE_SUCCESS) {
        /* [MQTT-3.1.3-2] The ClientId identifies the Session, so outbound
         * state belongs to the ClientId that created it. A Session Present
         * answer for a different ClientId is a different Session: replaying
         * into it would inject one Session's messages into another. */
        if (!(mc_connect->ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ||
                !session_id_matched) {
            /* A fresh Session starts with no outbound state to re-send. */
            MqttClient_Replay_Reset(client);
        }
        else {
            int i;

            /* The server resumed the Session, so these messages are still in
             * flight as far as it is concerned: keep their Packet Identifiers
             * reserved (MqttClient_Connect cleared the table above) and
             * re-send them [MQTT-4.4.0-1]. */
            for (i = 0; i < MQTT_MAX_REPLAY_MSGS; i++) {
                if (client->replay[i].packet_id == 0) {
                    continue;
                }
                if (!client->replay[i].pubrelSent &&
                        !client->replay[i].haveCopy) {
                    /* Nothing to re-send: the payload was never retained, so
                     * [MQTT-4.4.0-1] cannot be honoured for this one. Drop it
                     * instead of reserving an identifier that no
                     * acknowledgement will ever release [MQTT-2.3.1-3]. */
                    MqttClient_Replay_FreeSlot(&client->replay[i]);
                    continue;
                }
                (void)MqttClient_SendIdReserve(client,
                    client->replay[i].packet_id, &client->replay[i], 1,
                    client->replay[i].pubrelSent ?
                        MQTT_PACKET_TYPE_PUBLISH_COMP :
                        ((client->replay[i].qos == MQTT_QOS_2) ?
                            MQTT_PACKET_TYPE_PUBLISH_COMP :
                            MQTT_PACKET_TYPE_PUBLISH_ACK));
            }
            client->replayIdx = 0;
            mc_connect->stat.write = MQTT_MSG_PAYLOAD;
            rc = MqttClient_ReplaySession(client, mc_connect);
            if (rc == MQTT_CODE_CONTINUE) {
                /* The application re-enters through the resume block at the
                 * top of this function, which arms keep-alive when the replay
                 * finally completes. */
                return rc;
            }
            /* Clear the resume sentinel on success and on failure alike: a
             * failed replay must not leave an MqttConnect that a later call
             * would mistake for a resume and use to skip the handshake. */
            mc_connect->stat.write = MQTT_MSG_BEGIN;
        }
    }
#endif

#ifndef WOLFMQTT_NO_TIME
    MqttClient_ConnectKeepAlive(client, mc_connect, rc);
#endif

    return rc;
}

static int MqttClient_Publish_ReadPayload(MqttClient* client,
    MqttPublish* publish, int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    byte msg_done;
#if WOLFMQTT_MAX_QOS >= 2
    /* A retransmitted QoS 2 PUBLISH still awaiting its PUBREL must be drained to
     * keep the stream in sync, but not delivered to the application again
     * [MQTT-4.3.3-10]. Re-derived from the packet id so it survives non-blocking
     * re-entry into this function. */
    int is_dup = (publish->qos == MQTT_QOS_2 &&
        MqttClient_RecvQos2_Contains(client, publish->packet_id));
    /* A new QoS 2 id that will not fit the dedup table must not be delivered:
     * untracked, its retransmit would reach the application a second time
     * [MQTT-4.3.3-10]. Drained to stay in sync, then the exchange is refused. */
    int untrackable = (publish->qos == MQTT_QOS_2 && !is_dup &&
        !MqttClient_RecvQos2_HasFreeSlot(client));
    int suppress_cb = (is_dup || untrackable);
#endif

    /* Handle packet callback and read remaining payload */
    do {
        /* Determine if message is done */
        msg_done = ((publish->buffer_pos + publish->buffer_len) >=
                    publish->total_len) ? 1 : 0;

        if (publish->buffer_new) {
            /* Issue callback for new message (first time only) */
            if (client->msg_cb
            #if WOLFMQTT_MAX_QOS >= 2
                && !suppress_cb
            #endif
            ) {
                /* if using the temp publish message buffer,
                   then populate message context with client context */
                if (publish->ctx == NULL && &client->msg.publish == publish) {
                    publish->ctx = client->ctx;
                }
                rc = client->msg_cb(client, publish, publish->buffer_new,
                                    msg_done);
                if (rc != MQTT_CODE_SUCCESS) {
                    return rc;
                };
            }

            /* Reset topic name since valid on new message only */
            publish->topic_name = NULL;
            publish->topic_name_len = 0;

            publish->buffer_new = 0;
        }

        /* Read payload */
        if (!msg_done) {
            int msg_len;

            /* add last length to position and reset len */
            publish->buffer_pos += publish->buffer_len;
            publish->buffer_len = 0;

            /* set state to reading payload */
            publish->stat.read = MQTT_MSG_PAYLOAD2;

            msg_len = (publish->total_len - publish->buffer_pos);
            if (msg_len > client->rx_buf_len) {
                msg_len = client->rx_buf_len;
            }

            /* make sure there is something to read */
            if (msg_len > 0) {
                rc = MqttSocket_Read(client, client->rx_buf, msg_len,
                        timeout_ms);
                if (rc < 0) {
                    break;
                }

                /* Update message */
                publish->buffer = client->rx_buf;
                publish->buffer_len = rc;
                rc = MQTT_CODE_SUCCESS; /* mark success */

                msg_done = ((publish->buffer_pos + publish->buffer_len) >=
                    publish->total_len) ? 1 : 0;

                /* Issue callback for additional publish payload */
                if (client->msg_cb
                #if WOLFMQTT_MAX_QOS >= 2
                    && !suppress_cb
                #endif
                ) {
                    rc = client->msg_cb(client, publish, publish->buffer_new,
                                        msg_done);
                    if (rc != MQTT_CODE_SUCCESS) {
                        return rc;
                    };
                }
            }
        }
    } while (!msg_done);

#if WOLFMQTT_MAX_QOS >= 2
    /* The new QoS 2 id could not be tracked (dedup table full) and the drained
     * payload was not delivered. MQTT 3.1.1 cannot reject the PUBLISH in-band,
     * so fail without sending a successful PUBREC. */
    if (rc == MQTT_CODE_SUCCESS && untrackable) {
    #ifdef WOLFMQTT_V5
        if (client->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
            /* Reject on the PUBREC with Quota Exceeded so the peer ends the
             * exchange without a PUBREL and may retry once a slot frees. */
            publish->resp.reason_code = MQTT_REASON_QUOTA_EXCEEDED;
        }
        else
    #endif
        {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
        }
    }
#endif

    /* No message callback registered to deliver this incoming PUBLISH. The
     * payload was drained above to keep the stream in sync, but the application
     * never saw it. Return a distinct error instead of success so the caller is
     * notified and, for QoS 1/2, MqttClient_HandlePacket does not falsely ACK
     * the message as delivered. */
    if (rc == MQTT_CODE_SUCCESS && client->msg_cb == NULL) {
        rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_CALLBACK);
    }

    return rc;
}

static int MqttClient_Publish_WritePayload(MqttClient *client,
    MqttPublish *publish, MqttPublishCb pubCb)
{
    int rc = MQTT_CODE_SUCCESS;

    if (client == NULL || publish == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);

    if (pubCb) { /* use publish callback to get data */
        word32 tmp_len;
        word32 remaining;

        do {
            /* use the client->write.len to handle non-blocking re-entry when
             * new publish callback data is needed */
            if (client->write.len == 0) {
                /* Use the callback to get payload */
                if ((client->write.len = pubCb(publish)) < 0) {
                #ifdef WOLFMQTT_DEBUG_CLIENT
                    PRINTF("Publish callback error %d", client->write.len);
                #endif
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_CALLBACK);
                }

                /* Record how many valid bytes this callback produced (a short
                 * return marks the last read). Persisting it means a
                 * non-blocking resume does not mistake the in-progress chunk
                 * length for the fill length and drop the tail. */
                publish->intBuf_cb_len = (word32)client->write.len;
                if (publish->intBuf_cb_len > publish->buffer_len) {
                    publish->intBuf_cb_len = publish->buffer_len;
                }
                remaining = publish->total_len - publish->buffer_pos;
                if (publish->intBuf_cb_len > remaining) {
                    publish->intBuf_cb_len = remaining;
                }
            }

            tmp_len = publish->intBuf_cb_len;

            /* Send payload */
            do {
                /* Recompute the bytes remaining each pass so the final partial
                 * chunk copies only valid data and never reads past the end of
                 * the caller's payload buffer. */
                client->write.len = (int)(tmp_len - publish->intBuf_pos);
                if (client->write.len > client->tx_buf_len) {
                    client->write.len = client->tx_buf_len;
                }
                publish->intBuf_len = client->write.len;
                XMEMCPY(client->tx_buf, &publish->buffer[publish->intBuf_pos],
                    client->write.len);

                rc = MqttPacket_Write(client, client->tx_buf,
                        client->write.len);
                if (rc < 0) {
                    return rc;
                }

                publish->intBuf_pos += publish->intBuf_len;
                publish->intBuf_len = 0;

            } while (publish->intBuf_pos < tmp_len);

            publish->buffer_pos += publish->intBuf_pos;
            publish->intBuf_pos = 0;
            client->write.len = 0; /* reset current write len */

        } while (publish->buffer_pos < publish->total_len);
    }
    else if (publish->buffer_pos < publish->total_len) {
        if (publish->buffer_pos > 0) {
            client->write.len = (publish->total_len - publish->buffer_pos);
            if (client->write.len > client->tx_buf_len) {
                client->write.len = client->tx_buf_len;
            }

            XMEMCPY(client->tx_buf, &publish->buffer[publish->buffer_pos],
                client->write.len);

        #ifndef WOLFMQTT_NONBLOCK
            publish->intBuf_pos += client->write.len;
        #endif
        }

        /* Send packet and payload */
    #ifdef WOLFMQTT_NONBLOCK
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            if (rc < 0) {
                return rc;
            }

            /* ONLY if send was successful, update buffer position.
             * Otherwise, MqttPacket_Write() will resume where it left off. */
            publish->buffer_pos += client->write.len;

            /* Check if we are done sending publish message */
            if (publish->buffer_pos < publish->buffer_len) {
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("Publish Write: not done (%d remain)",
                    publish->buffer_len - publish->buffer_pos);
            #endif
                return MQTT_CODE_PUB_CONTINUE;
            }
        #ifdef WOLFMQTT_DEBUG_CLIENT
            else {
                PRINTF("Publish Write: done");
            }
        #endif
    #else
        do {
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            if (rc < 0) {
                return rc;
            }

            publish->intBuf_pos += publish->intBuf_len;
            publish->intBuf_len = 0;

            /* Check if we are done sending publish message */
            if (publish->intBuf_pos >= publish->buffer_len) {
                rc = MQTT_CODE_SUCCESS;
                break;
            }

            /* Build packet payload to send */
            client->write.len = (publish->buffer_len - publish->intBuf_pos);
            if (client->write.len > client->tx_buf_len) {
                client->write.len = client->tx_buf_len;
            }
            publish->intBuf_len = client->write.len;
            XMEMCPY(client->tx_buf, &publish->buffer[publish->intBuf_pos],
                client->write.len);
        } while (publish->intBuf_pos < publish->buffer_len);
    #endif

        if (rc >= 0) {
            /* If transferring more chunks */
            publish->buffer_pos += publish->intBuf_pos;
            if (publish->buffer_pos < publish->total_len) {
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("Publish Write: chunk (%d remain)",
                    publish->total_len - publish->buffer_pos);
            #endif

                /* Build next payload to send */
                client->write.len = (publish->total_len - publish->buffer_pos);
                if (client->write.len > client->tx_buf_len) {
                    client->write.len = client->tx_buf_len;
                }
                rc = MQTT_CODE_PUB_CONTINUE;
            }
        #ifdef WOLFMQTT_DEBUG_CLIENT
            else {
                PRINTF("Publish Write: chunked done");
            }
        #endif
        }
    }
    return rc;
}

#ifdef WOLFMQTT_V5
/* Give back the Receive Maximum unit reserved for a QoS>0 v5 PUBLISH when it
 * terminates without a matching PUBACK/PUBCOMP (write failure, cancel,
 * ack-wait timeout, PUBREC rejection). Clamped to the negotiated ceiling so a
 * later stray ack for the same id cannot inflate the quota past it. */
static void MqttClient_RestoreRecvQuota(MqttClient* client,
    MqttPublish* publish)
{
    MqttClient_RecvQuotaRelease(client, &publish->stat);
}
#endif

static int MqttPublishMsg(MqttClient *client, MqttPublish *publish,
                          MqttPublishCb pubCb, int writeOnly)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttPacketType resp_type;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* [MQTT-3.1.0-1] CONNECT must be the first packet on the connection. */
    rc = MqttClient_CheckConnectSent(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

#ifdef WOLFMQTT_V5
    /* Use specified protocol version if set */
    publish->protocol_level = client->protocol_level;

    /* Validate publish request against server properties */
    if ((publish->qos > client->max_qos) ||
        ((publish->retain != 0) && (client->retain_avail == 0)))
    {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
    }

    /* [MQTT-3.3.2.3.4]: reject a Topic Alias over CONNACK's maximum.
     * [MQTT-3.3.4-6]: a Client-to-Server PUBLISH MUST NOT carry a
     * Subscription Identifier. */
    if (client->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        MqttProp* prop;
        for (prop = publish->props; prop != NULL; prop = prop->next) {
            if (prop->type == MQTT_PROP_TOPIC_ALIAS) {
                if ((prop->data_short == 0) ||
                    (prop->data_short > client->topic_alias_max)) {
                    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
                }
            }
            /* The Subscription Identifier is only valid on a Server-to-Client
             * PUBLISH the broker generates; reject a caller-supplied one. */
            else if (prop->type == MQTT_PROP_SUBSCRIPTION_ID) {
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
            }
        }
    }

#endif

    switch (publish->stat.write)
    {
        case MQTT_MSG_BEGIN:
        {
            /* Flag write active / lock mutex */
            if ((rc = MqttWriteStart(client, &publish->stat)) != 0) {
                return rc;
            }

        #ifdef WOLFMQTT_V5
            /* [MQTT-3.1.2.11.3]: atomically reserve one flow-control unit,
             * refusing once the quota is exhausted. Only reached in
             * MQTT_MSG_BEGIN, so once per logical publish. The unit is released
             * only on the acknowledgement, so a publish is reserved only when
             * that ack can be tracked to completion. A write-only publish in a
             * WOLFMQTT_MULTITHREAD build without WOLFMQTT_NONBLOCK returns
             * success immediately, abandoning ack tracking (and the caller may
             * free the object), so it is left unreserved there - the alternative
             * would either over-credit an on-wire PUBLISH [MQTT-4.9] or dangle.
             * A blocking (non-multithread) write-only still waits, and a
             * non-blocking one keeps its pending response for the reader, so
             * both reserve. */
            if (client->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                publish->qos > MQTT_QOS_0 &&
            #if defined(WOLFMQTT_MULTITHREAD) && !defined(WOLFMQTT_NONBLOCK)
                !writeOnly &&
            #endif
                !MqttClient_RecvQuotaReserve(client, publish))
            {
                MqttWriteStop(client, &publish->stat);
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
            }
        #endif

            /* Encode the publish packet */
            rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len,
                    publish, pubCb ? 1 : 0);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d,"
                    " QoS %d",
                rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_PUBLISH),
                MQTT_PACKET_TYPE_PUBLISH, publish->packet_id,
                publish->qos);
        #endif
            if (rc <= 0) {
                MqttWriteStop(client, &publish->stat);
            #ifdef WOLFMQTT_V5
                MqttClient_RestoreRecvQuota(client, publish);
            #endif
                return rc;
            }
        #ifdef WOLFMQTT_V5
            /* [MQTT-3.1.2-24] The whole PUBLISH must fit the Server's Maximum
             * Packet Size. MqttPacket_Write only sees each tx_buf-sized
             * fragment, so a streamed or oversized payload can slip past it;
             * check the full packet once here before any byte is written.
             * rc is fixed header + variable header + the in-buffer payload
             * chunk (publish->intBuf_len), so (rc - intBuf_len) is the fixed
             * plus variable header and the full size adds total_len. The
             * comparison is ordered to avoid unsigned overflow. */
            if (client->packet_sz_max > 0 &&
                ((publish->total_len > client->packet_sz_max) ||
                 (((word32)rc - publish->intBuf_len) >
                     (client->packet_sz_max - publish->total_len)))) {
                MqttWriteStop(client, &publish->stat);
                MqttClient_RestoreRecvQuota(client, publish);
                return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
            }
        #endif
            client->write.len = rc;

            if (publish->qos > MQTT_QOS_0) {
                /* [MQTT-2.3.1-2] A new QoS>0 PUBLISH must carry a currently
                 * unused Packet Identifier. A re-send of this same PUBLISH is
                 * required to keep its original identifier [MQTT-2.3.1-3] and
                 * carries DUP=1 [MQTT-3.3.1-1], so it is allowed through. */
                rc = MqttClient_SendIdReserve(client, publish->packet_id,
                        publish, publish->duplicate,
                        (publish->qos == MQTT_QOS_2) ?
                            MQTT_PACKET_TYPE_PUBLISH_COMP :
                            MQTT_PACKET_TYPE_PUBLISH_ACK);
                if (rc != MQTT_CODE_SUCCESS) {
                    MqttWriteStop(client, &publish->stat);
                #ifdef WOLFMQTT_V5
                    MqttClient_RestoreRecvQuota(client, publish);
                #endif
                    return rc;
                }
            }

        #ifdef WOLFMQTT_MULTITHREAD
            if (publish->qos > MQTT_QOS_0) {
                resp_type = (publish->qos == MQTT_QOS_1) ?
                        MQTT_PACKET_TYPE_PUBLISH_ACK :
                        MQTT_PACKET_TYPE_PUBLISH_COMP;

                rc = wm_SemLock(&client->lockClient);
                if (rc == 0) {
                    /* inform other threads of expected response */
                    rc = MqttClient_RespList_Add(client, resp_type,
                        publish->packet_id, &publish->pendResp, &publish->resp);
                #ifdef WOLFMQTT_V5
                    /* Let the thread that completes this ack release any
                     * reserved Receive Maximum unit, needed for a write-only
                     * publish that does not wait for its own ack. */
                    if (rc == 0 && publish->stat.recvQuotaHeld) {
                        publish->pendResp.recvQuotaStat = &publish->stat;
                    }
                #endif
                    wm_SemUnlock(&client->lockClient);
                }
                if (rc != 0) {
                    MqttWriteStop(client, &publish->stat);
                    MqttClient_SendIdReleaseOwner(client, publish);
                #ifdef WOLFMQTT_V5
                    MqttClient_RestoreRecvQuota(client, publish);
                #endif
                    return rc; /* Error locking client */
                }
            }
        #endif

        #ifndef WOLFMQTT_NO_SESSION_REPLAY
            /* Record the Session state before the packet reaches the wire.
             * Once it is out, a reader thread can process the acknowledgement
             * at any moment; adding the entry afterwards would let that
             * removal run first and leave an acknowledged message retained,
             * to be replayed after the next reconnect [MQTT-4.4.0-1]. */
            if (publish->qos > MQTT_QOS_0) {
                MqttClient_Replay_AddSafe(client, publish);
            }
        #endif

            publish->stat.write = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        {
            int xfer = client->write.len;
            int wrote;

            /* Send publish packet */
            rc = MqttPacket_Write(client, client->tx_buf, xfer);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE
            #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
                && client->write.total > 0
            #endif
            ) {
                /* keep send locked and return early */
                return rc;
            }
        #endif
            /* Bytes this call put on the transport, read before MqttWriteStop
             * resets the write state. A blocking write can get part of the
             * packet out and then fail. */
            wrote = (rc == xfer) ? xfer : client->write.pos;
            client->write.len = 0; /* reset len, so publish chunk resets */

            /* if failure or no data was written yet */
            if (rc != xfer) {
                MqttWriteStop(client, &publish->stat);
            #ifdef WOLFMQTT_V5
                /* Credit the unit before the cancel: nothing reached the wire,
                 * so it is genuinely reclaimable, and the cancel drops this
                 * message's ownership of it either way. */
                MqttClient_RestoreRecvQuota(client, publish);
            #endif
                MqttClient_CancelMessage(client, (MqttObject*)publish);
                if (wrote > 0) {
                    /* Part of the PUBLISH reached the server, so it may have
                     * seen the Packet Identifier. Reclaim the reservation the
                     * cancel just dropped so a new message cannot take it
                     * [MQTT-2.3.1-3]. The replay entry recorded above stays:
                     * the message is in flight as far as the server may be
                     * concerned. */
                    (void)MqttClient_SendIdReserve(client, publish->packet_id,
                            publish, 1, (publish->qos == MQTT_QOS_2) ?
                                MQTT_PACKET_TYPE_PUBLISH_COMP :
                                MQTT_PACKET_TYPE_PUBLISH_ACK);
                }
            #ifndef WOLFMQTT_NO_SESSION_REPLAY
                else {
                    /* Nothing reached the wire, so this never became Session
                     * state. Drop the entry recorded before the write. */
                    MqttClient_Replay_RemoveSafe(client, publish->packet_id);
                }
            #endif
                return rc;
            }

            /* advance state */
            publish->stat.write = MQTT_MSG_PAYLOAD;
        }
        FALL_THROUGH;

        case MQTT_MSG_PAYLOAD:
        {
            rc = MqttClient_Publish_WritePayload(client, publish, pubCb);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE || rc == MQTT_CODE_PUB_CONTINUE)
                return rc;
        #else
            /* Chunked publish requests the next payload chunk; not terminal,
             * so return without releasing the reserved quota. */
            if (rc == MQTT_CODE_PUB_CONTINUE)
                return rc;
        #endif
            MqttWriteStop(client, &publish->stat);
            if (rc < 0) {
            #ifdef WOLFMQTT_V5
                /* Credit before the cancel; see the header-write failure path
                 * above. */
                MqttClient_RestoreRecvQuota(client, publish);
            #endif
                MqttClient_CancelMessage(client, (MqttObject*)publish);
                /* Reaching the payload means the fixed header - and with it
                 * the Packet Identifier - is already on the wire, so keep the
                 * reservation the cancel dropped [MQTT-2.3.1-3]. */
                (void)MqttClient_SendIdReserve(client, publish->packet_id,
                        publish, 1, (publish->qos == MQTT_QOS_2) ?
                            MQTT_PACKET_TYPE_PUBLISH_COMP :
                            MQTT_PACKET_TYPE_PUBLISH_ACK);
                break;
            }

            /* if not expecting a reply then we are done */
            if (publish->qos == MQTT_QOS_0) {
                break;
            }

            publish->stat.write = MQTT_MSG_WAIT;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        {
            /* Handle QoS */
            if (publish->qos > MQTT_QOS_0) {
                /* Determine packet type to wait for */
                resp_type = (publish->qos == MQTT_QOS_1) ?
                    MQTT_PACKET_TYPE_PUBLISH_ACK :
                    MQTT_PACKET_TYPE_PUBLISH_COMP;

            #ifdef WOLFMQTT_MULTITHREAD
                if (writeOnly) {
                    /* another thread will handle response */
                    /* check if response already received from other thread */
                    rc = MqttClient_CheckPendResp(client, resp_type,
                        publish->packet_id);
                #ifndef WOLFMQTT_NONBLOCK
                    if (rc == MQTT_CODE_CONTINUE) {
                        /* No non-blocking re-entry will complete this ack, so
                         * report success. This build does not reserve quota for
                         * a write-only publish (see the reserve gate above), and
                         * the pending response is unlinked below, so nothing is
                         * leaked and no reference to the caller's object
                         * remains. */
                        rc = MQTT_CODE_SUCCESS;
                    }
                #endif
                }
                else
            #endif
                {
                    (void)writeOnly; /* not used */

                    /* Wait for publish response packet */
                    rc = MqttClient_WaitType(client, &publish->resp, resp_type,
                        publish->packet_id, client->cmd_timeout_ms, NULL);

                #ifdef WOLFMQTT_V5
                    /* Replenish the reserved quota unit on any real end to the
                     * exchange, all of which free the server's unit [MQTT-4.9]:
                     * a clean PUBACK/PUBCOMP (rc SUCCESS), a rejecting
                     * PUBACK/PUBCOMP reason code (still SUCCESS here,
                     * reclassified below), and a PUBREC rejection (surfaced
                     * directly as PUBLISH_REJECTED, which without this credit
                     * would leak a unit in a non-multithread build). A timeout
                     * leaves the PUBLISH unacknowledged on a still-open
                     * connection - the server keeps counting it - so it is
                     * excluded. */
                    if (rc == MQTT_CODE_SUCCESS ||
                            rc == MQTT_CODE_ERROR_PUBLISH_REJECTED) {
                        MqttClient_RestoreRecvQuota(client, publish);
                    }

                    /* A v5 broker can acknowledge a QoS>0 PUBLISH at the
                     * protocol layer yet still reject the message via a
                     * PUBACK/PUBCOMP reason code >= 0x80 (e.g. not authorized,
                     * quota exceeded, topic name invalid, payload format
                     * invalid). Surface that as an error so the caller does not
                     * treat a rejected message as delivered. Mirrors the
                     * CONNECT/SUBSCRIBE/UNSUBSCRIBE rejection handling. The
                     * protocol_level guard avoids misreading a stale byte for
                     * v3.1.1 ACKs, which carry no reason code (same guard the
                     * PUBREC check in MqttClient_HandlePacket uses). */
                    if (rc == MQTT_CODE_SUCCESS &&
                        client->protocol_level >=
                            MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
                        (publish->resp.reason_code & 0x80)) {
                        rc = MQTT_TRACE_ERROR(
                            MQTT_CODE_ERROR_PUBLISH_REJECTED);
                    }
                #endif
                }

            #if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
                if (rc == MQTT_CODE_CONTINUE)
                    break;
            #endif
            #ifdef WOLFMQTT_MULTITHREAD
                /* Remove the pending response before returning: a caller told
                 * SUCCESS may free its publish object, so no reference to it may
                 * remain in the list. A write-only publish under
                 * WOLFMQTT_NONBLOCK returned CONTINUE above and broke out before
                 * here, leaving its entry for the reading thread to complete and
                 * remove. */
                if (wm_SemLock(&client->lockClient) == 0) {
                    MqttClient_RespList_Remove(client, &publish->pendResp);
                    wm_SemUnlock(&client->lockClient);
                }
            #endif
            }
            break;
        }

        case MQTT_MSG_ACK:
        case MQTT_MSG_AUTH:
        case MQTT_MSG_PAYLOAD2:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_Publish: Invalid state %d!",
                publish->stat.write);
        #endif
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_STAT);
            break;
    } /* switch (publish->stat) */

    /* reset state */
    if ((rc != MQTT_CODE_PUB_CONTINUE)
#ifdef WOLFMQTT_NONBLOCK
         && (rc != MQTT_CODE_CONTINUE)
#endif
        )
    {
        publish->stat.write = MQTT_MSG_BEGIN;
    }
    if (rc > 0) {
        rc = MQTT_CODE_SUCCESS;
    }

    return rc;
}

int MqttClient_Publish(MqttClient *client, MqttPublish *publish)
{
    return MqttPublishMsg(client, publish, NULL, 0);
}

int MqttClient_Publish_ex(MqttClient *client, MqttPublish *publish,
    MqttPublishCb pubCb)
{
    return MqttPublishMsg(client, publish, pubCb, 0);
}

#ifdef WOLFMQTT_MULTITHREAD
int MqttClient_Publish_WriteOnly(MqttClient *client, MqttPublish *publish,
    MqttPublishCb pubCb)
{
    return MqttPublishMsg(client, publish, pubCb, 1);
}
#endif


int MqttClient_Subscribe(MqttClient *client, MqttSubscribe *subscribe)
{
    int rc, i;
    MqttTopic* topic;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* [MQTT-3.1.0-1] CONNECT must be the first packet on the connection. */
    rc = MqttClient_CheckConnectSent(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

#ifdef WOLFMQTT_V5
    /* Use specified protocol version if set */
    subscribe->protocol_level = client->protocol_level;
#endif

    if (subscribe->stat.write == MQTT_MSG_BEGIN) {
        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, &subscribe->stat)) != 0) {
            return rc;
        }

        /* Encode the subscribe packet */
        rc = MqttEncode_Subscribe(client->tx_buf, client->tx_buf_len,
                subscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_SUBSCRIBE),
            MQTT_PACKET_TYPE_SUBSCRIBE, subscribe->packet_id);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &subscribe->stat);
            return rc;
        }
        client->write.len = rc;

        /* [MQTT-2.3.1-2] A new SUBSCRIBE must carry a currently unused Packet
         * Identifier; it is released by its SUBACK [MQTT-2.3.1-3]. SUBSCRIBE
         * has no DUP bit, so a repeat while one is unacknowledged cannot be
         * told apart from a new subscription and is refused. */
        rc = MqttClient_SendIdReserve(client, subscribe->packet_id,
                subscribe, 0, MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
        if (rc != MQTT_CODE_SUCCESS) {
            MqttWriteStop(client, &subscribe->stat);
            return rc;
        }

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_SUBSCRIBE_ACK,
                subscribe->packet_id, &subscribe->pendResp, &subscribe->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &subscribe->stat);
            MqttClient_SendIdReleaseOwner(client, subscribe);
            return rc; /* Error locking client */
        }
    #endif

        subscribe->stat.write = MQTT_MSG_HEADER;
    }
    if (subscribe->stat.write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;
        int wrote;

        /* Send subscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, xfer);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE
        #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
            && client->write.total > 0
        #endif
        ) {
            /* keep send locked and return early */
            return rc;
        }
    #endif
        /* Bytes this call put on the transport, read before MqttWriteStop
         * resets the write state. */
        wrote = (rc == xfer) ? xfer : client->write.pos;
        MqttWriteStop(client, &subscribe->stat);
        if (rc != xfer) {
            MqttClient_CancelMessage(client, (MqttObject*)subscribe);
            if (wrote > 0) {
                /* Part of the SUBSCRIBE reached the server, so it may have
                 * seen the Packet Identifier. Reclaim the reservation the
                 * cancel just dropped [MQTT-2.3.1-3]. */
                (void)MqttClient_SendIdReserve(client, subscribe->packet_id,
                        subscribe, 1, MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
            }
            return rc;
        }

        subscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for subscribe ack packet */
    rc = MqttClient_WaitType(client, &subscribe->ack,
        MQTT_PACKET_TYPE_SUBSCRIBE_ACK, subscribe->packet_id,
        client->cmd_timeout_ms, NULL);
#if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &subscribe->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* Populate return codes and detect broker rejection. A v3.1.1 SUBACK
     * uses MQTT_SUBSCRIBE_ACK_CODE_FAILURE (0x80) to indicate failure;
     * a v5 SUBACK uses any reason code >= 0x80. In either case, any
     * per-topic code with the high bit set means the broker rejected
     * that filter. */
    if (rc == MQTT_CODE_SUCCESS) {
        byte any_rejected = 0;
        /* [MQTT-3.9.3-1] a SUBACK carries exactly one reason code per
         * requested topic; too few would be read as granted QoS 0 (fail-open). */
        if (subscribe->ack.return_code_count != subscribe->topic_count) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
        }
        else {
            for (i = 0; i < subscribe->topic_count && i < MAX_MQTT_TOPICS; i++) {
                topic = &subscribe->topics[i];
                topic->return_code = subscribe->ack.return_codes[i];
                if (topic->return_code & MQTT_SUBSCRIBE_ACK_CODE_FAILURE) {
                    any_rejected = 1;
                }
            }
            if (any_rejected) {
                rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SUBSCRIBE_REJECTED);
            }
        }
    }

    /* reset state */
    subscribe->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int MqttClient_Unsubscribe(MqttClient *client, MqttUnsubscribe *unsubscribe)
{
    int rc;
#ifdef WOLFMQTT_V5
    int i;
#endif

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* [MQTT-3.1.0-1] CONNECT must be the first packet on the connection. */
    rc = MqttClient_CheckConnectSent(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

#ifdef WOLFMQTT_V5
    /* Use specified protocol version if set */
    unsubscribe->protocol_level = client->protocol_level;
#endif

    if (unsubscribe->stat.write == MQTT_MSG_BEGIN) {
        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, &unsubscribe->stat)) != 0) {
            return rc;
        }

        /* Encode the subscribe packet */
        rc = MqttEncode_Unsubscribe(client->tx_buf, client->tx_buf_len,
            unsubscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_UNSUBSCRIBE),
            MQTT_PACKET_TYPE_UNSUBSCRIBE, unsubscribe->packet_id, 0);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &unsubscribe->stat);
            return rc;
        }
        client->write.len = rc;

        /* [MQTT-2.3.1-2] A new UNSUBSCRIBE must carry a currently unused
         * Packet Identifier; it is released by its UNSUBACK [MQTT-2.3.1-3].
         * UNSUBSCRIBE has no DUP bit, so a repeat while one is unacknowledged
         * cannot be told apart from a new request and is refused. */
        rc = MqttClient_SendIdReserve(client, unsubscribe->packet_id,
                unsubscribe, 0, MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK);
        if (rc != MQTT_CODE_SUCCESS) {
            MqttWriteStop(client, &unsubscribe->stat);
            return rc;
        }

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK, unsubscribe->packet_id,
                &unsubscribe->pendResp, &unsubscribe->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &unsubscribe->stat);
            MqttClient_SendIdReleaseOwner(client, unsubscribe);
            return rc;
        }
    #endif

        unsubscribe->stat.write = MQTT_MSG_HEADER;
    }
    if (unsubscribe->stat.write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;
        int wrote;

        /* Send unsubscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, xfer);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE
        #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
            && client->write.total > 0
        #endif
        ) {
            /* keep send locked and return early */
            return rc;
        }
    #endif
        /* Bytes this call put on the transport, read before MqttWriteStop
         * resets the write state. */
        wrote = (rc == xfer) ? xfer : client->write.pos;
        MqttWriteStop(client, &unsubscribe->stat);
        if (rc != xfer) {
            MqttClient_CancelMessage(client, (MqttObject*)unsubscribe);
            if (wrote > 0) {
                /* Part of the UNSUBSCRIBE reached the server, so it may have
                 * seen the Packet Identifier. Reclaim the reservation the
                 * cancel just dropped [MQTT-2.3.1-3]. */
                (void)MqttClient_SendIdReserve(client, unsubscribe->packet_id,
                        unsubscribe, 1, MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK);
            }
            return rc;
        }

        unsubscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for unsubscribe ack packet */
    rc = MqttClient_WaitType(client, &unsubscribe->ack,
        MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK, unsubscribe->packet_id,
        client->cmd_timeout_ms, NULL);
#if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

#ifdef WOLFMQTT_V5
    /* [MQTT-3.11.3-1] A v5 UNSUBACK carries exactly one reason code per
     * topic filter. Any code with the high bit set (>= 0x80) means the
     * broker refused to remove that subscription. */
    if (rc == MQTT_CODE_SUCCESS &&
        unsubscribe->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
        if (unsubscribe->ack.reason_code_count != unsubscribe->topic_count ||
                (unsubscribe->ack.reason_code_count > 0 &&
                 unsubscribe->ack.reason_codes == NULL)) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
            (void)MqttClient_Flags(client,
                MQTT_CLIENT_FLAG_IS_CONNECTED, 0);
        }
        else {
            for (i = 0; i < unsubscribe->ack.reason_code_count; i++) {
                if (unsubscribe->ack.reason_codes[i] & 0x80) {
                    rc = MQTT_TRACE_ERROR(
                        MQTT_CODE_ERROR_UNSUBSCRIBE_REJECTED);
                    break;
                }
            }
        }
    }

    if (unsubscribe->ack.props != NULL) {
        /* Release the allocated properties and clear the caller-visible
         * pointer so a stale reference cannot be observed, reused, or freed
         * again after this API returns. */
        MqttClient_PropsFree(unsubscribe->ack.props);
        unsubscribe->ack.props = NULL;
    }
#endif

    /* reset state */
    unsubscribe->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

static int MqttClient_PingTimeoutDisconnect(MqttClient *client)
{
#ifdef WOLFMQTT_MULTITHREAD
    int rc;

    /* A message callback can hold lockRecv while starting a publish, so take
     * the I/O locks in that same direction. Once both are held, no read or
     * write callback can still reference socket, TLS, or curl state while the
     * transport is released. */
    rc = wm_SemLock(&client->lockRecv);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
    rc = wm_SemLock(&client->lockSend);
    if (rc != MQTT_CODE_SUCCESS) {
        (void)wm_SemUnlock(&client->lockRecv);
        return rc;
    }

    rc = MqttClient_NetDisconnect(client);
    (void)wm_SemUnlock(&client->lockSend);
    (void)wm_SemUnlock(&client->lockRecv);
    return rc;
#else
    return MqttClient_NetDisconnect(client);
#endif
}

int MqttClient_Ping_ex(MqttClient *client, MqttPing* ping)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || ping == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* [MQTT-3.1.0-1] CONNECT must be the first packet on the connection. */
    rc = MqttClient_CheckConnectSent(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    if (ping->stat.write == MQTT_MSG_BEGIN) {
        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, &ping->stat)) != 0) {
            return rc;
        }

        /* Encode the subscribe packet */
        rc = MqttEncode_Ping(client->tx_buf, client->tx_buf_len, ping);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_PING_REQ),
            MQTT_PACKET_TYPE_PING_REQ, 0, 0);
    #endif
        if (rc <= 0) {
            MqttWriteStop(client, &ping->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_PING_RESP, 0,
                &ping->pendResp, ping);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &ping->stat);
            return rc; /* Error locking client */
        }
    #endif

        ping->stat.write = MQTT_MSG_HEADER;
    }
    if (ping->stat.write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;

        /* Send ping req packet */
        rc = MqttPacket_Write(client, client->tx_buf, xfer);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE
        #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
            && client->write.total > 0
        #endif
        ) {
            /* keep send locked and return early */
            return rc;
        }
    #endif
        MqttWriteStop(client, &ping->stat);
        if (rc != xfer) {
            MqttClient_CancelMessage(client, (MqttObject*)ping);
            return rc;
        }

        ping->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for ping resp packet */
    rc = MqttClient_WaitType(client, ping, MQTT_PACKET_TYPE_PING_RESP, 0,
        client->cmd_timeout_ms, NULL);
#if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &ping->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    ping->stat.write = MQTT_MSG_BEGIN;

    /* MQTT 3.1.1 and 5.0 section 3.1.2.10: a client that does not receive
     * PINGRESP within a reasonable time should close the network connection.
     * MQTT_CODE_CONTINUE returned above keeps non-blocking exchanges alive;
     * only a terminal timeout reaches this teardown. Preserve the timeout for
     * direct Ping callers while the automatic keep-alive path maps it to a
     * network error. */
    if (rc == MQTT_CODE_ERROR_TIMEOUT) {
        (void)MqttClient_PingTimeoutDisconnect(client);
    }

    return rc;
}

int MqttClient_Ping(MqttClient *client)
{
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    return MqttClient_Ping_ex(client, &client->msg.ping);
}

int MqttClient_Disconnect(MqttClient *client)
{
    return MqttClient_Disconnect_ex(client, NULL);
}

int MqttClient_Disconnect_ex(MqttClient *client, MqttDisconnect *p_disconnect)
{
    int rc, xfer;
    MqttDisconnect *disconnect = p_disconnect, lcl_disconnect;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* [MQTT-3.1.0-1] CONNECT must be the first packet on the connection. */
    rc = MqttClient_CheckConnectSent(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    if (disconnect == NULL) {
        disconnect = &lcl_disconnect;
        XMEMSET(disconnect, 0, sizeof(*disconnect));
    }

    if (disconnect->stat.write == MQTT_MSG_BEGIN) {
    #ifndef WOLFMQTT_NO_TIME
        /* Stop auto keep-alive for a client being torn down, and fully cancel
         * any ping left mid-exchange so its held locks and pending response are
         * released before the disconnect write starts. A bare stat reset would
         * strand client->write.isActive and livelock MqttClient_Disconnect.
         * Propagate a cancel failure - only reachable if wm_SemLock itself
         * errors (e.g. on ThreadX), since it otherwise blocks until acquired -
         * rather than starting the write with locks the abandoned ping may
         * still hold. */
        client->keep_alive_sec = 0;
        rc = MqttClient_CancelMessage(client,
            (MqttObject*)&client->keep_alive_ping);
        if (rc != MQTT_CODE_SUCCESS) {
            return rc;
        }
    #endif
    #ifdef WOLFMQTT_V5
        /* Use specified protocol version if set */
        disconnect->protocol_level = client->protocol_level;
    #endif

        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, &disconnect->stat)) != 0) {
            return rc;
        }

        /* Encode the disconnect packet */
        rc = MqttEncode_Disconnect(client->tx_buf, client->tx_buf_len,
            disconnect);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_DISCONNECT),
            MQTT_PACKET_TYPE_DISCONNECT, 0, 0);
    #endif
        if (rc <= 0) {
            /* Encode failed: tx_buf may hold partial v5 DISCONNECT property
             * data. Zero the full buffer before MqttWriteStop releases
             * lockSend so no other thread can see residual data. */
            CLIENT_FORCE_ZERO(client->tx_buf, client->tx_buf_len);
            MqttWriteStop(client, &disconnect->stat);
            return rc;
        }
        client->write.len = rc;

        disconnect->stat.write = MQTT_MSG_HEADER;
    }

    /* Send disconnect packet */
    xfer = client->write.len;
    rc = MqttPacket_Write(client, client->tx_buf, xfer);
#ifdef WOLFMQTT_NONBLOCK
    /* if disconnect context avail allow partial write in non-blocking mode */
    if (p_disconnect != NULL && rc == MQTT_CODE_CONTINUE
    #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
        && client->write.total > 0
    #endif
    ) {
        /* keep send locked and return early (tx_buf still holds property
         * data until the write completes) */
        return rc;
    }
#endif
    /* Clear tx_buf to remove any v5 DISCONNECT property data BEFORE
     * MqttWriteStop releases lockSend, so another thread cannot race in and
     * populate tx_buf before it is scrubbed. */
    CLIENT_FORCE_ZERO(client->tx_buf, xfer);
    MqttWriteStop(client, &disconnect->stat);
    if (rc == xfer) {
        rc = MQTT_CODE_SUCCESS;
        /* [MQTT-3.14.4-1] "After sending a DISCONNECT Packet the Client MUST
         * NOT send any more Control Packets on that Network Connection."
         * Recorded separately from MQTT_CLIENT_FLAG_CONNECT_SENT: this call
         * does not close the transport, so clearing CONNECT_SENT would reopen
         * the [MQTT-3.1.0-2] duplicate-CONNECT guard and allow a second
         * CONNECT on the still-open Network Connection. */
        (void)MqttClient_Flags(client, 0, MQTT_CLIENT_FLAG_DISCONNECT_SENT);
    }

#if defined(WOLFMQTT_DISCONNECT_CB) && defined(WOLFMQTT_USE_CB_ON_DISCONNECT)
    /* Trigger disconnect callback - for intentional disconnect
     * This callback may occur on a network failure during an intentional
     * disconnect if the transport/socket is not setup yet. */
    if (client->disconnect_cb
    #ifdef WOLFMQTT_NONBLOCK
        && rc != MQTT_CODE_CONTINUE
    #endif
        ) {
        client->disconnect_cb(client, rc, client->disconnect_ctx);
    }
#endif

    /* No response for MQTT disconnect packet */

    /* reset state */
    disconnect->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

#ifdef WOLFMQTT_V5
static int MqttClient_AuthEx(MqttClient *client, MqttAuth* auth,
    MqttMsgStat* stat,
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp* pend_resp,
#endif
    void* packet_obj)
{
    int rc;
#ifdef WOLFMQTT_MULTITHREAD
    int lock_rc;
#endif

    /* Validate required arguments */
    if (client == NULL || auth == NULL || stat == NULL || packet_obj == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (stat->write == MQTT_MSG_BEGIN) {
        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, stat)) != 0) {
            return rc;
        }

        /* Encode the authentication packet */
        rc = MqttEncode_Auth(client->tx_buf, client->tx_buf_len, auth);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_AUTH),
            MQTT_PACKET_TYPE_AUTH, 0, 0);
    #endif
        if (rc <= 0) {
            /* Encode failed: tx_buf may hold partial SASL auth data.
             * Zero the full buffer before MqttWriteStop releases lockSend
             * so no other thread can see residual data. */
            CLIENT_FORCE_ZERO(client->tx_buf, client->tx_buf_len);
            MqttWriteStop(client, stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_AUTH, 0,
                pend_resp, packet_obj);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            /* Save write.len before MqttWriteStop zeroes client->write */
            int xfer = client->write.len;
            /* Clear tx_buf to remove SASL auth data BEFORE MqttWriteStop
             * releases lockSend, to prevent a racing thread from
             * repopulating tx_buf before it is scrubbed. */
            CLIENT_FORCE_ZERO(client->tx_buf, xfer);
            MqttWriteStop(client, stat);
            return rc; /* Error locking client */
        }
    #endif

        stat->write = MQTT_MSG_HEADER;
    }
    if (stat->write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;

        /* Send authentication packet */
        rc = MqttPacket_Write(client, client->tx_buf, xfer);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE
        #ifdef WOLFMQTT_ALLOW_NODATA_UNLOCK
            && client->write.total > 0
        #endif
        ) {
            /* keep send locked and return early */
            return rc;
        }
    #endif
        /* Clear tx_buf to remove any SASL auth data from memory BEFORE
         * MqttWriteStop releases lockSend, to prevent a racing thread
         * from populating tx_buf before it is scrubbed.
         * Use xfer (saved before MqttWriteStop zeroes client->write). */
        CLIENT_FORCE_ZERO(client->tx_buf, xfer);
        MqttWriteStop(client, stat);

        if (rc != xfer) {
            /* The scrubbed send buffer cannot be resumed. Reset before the
             * pending-list cleanup because a user lock implementation may
             * itself fail; retain the original transport result either way. */
            XMEMSET(stat, 0, sizeof(*stat));
        #ifdef WOLFMQTT_MULTITHREAD
            lock_rc = wm_SemLock(&client->lockClient);
            if (lock_rc == MQTT_CODE_SUCCESS) {
                MqttClient_RespList_Remove(client, pend_resp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        stat->write = MQTT_MSG_WAIT;
    }

    /* Wait for auth packet */
    rc = MqttClient_WaitType(client, packet_obj, MQTT_PACKET_TYPE_AUTH, 0,
        client->cmd_timeout_ms, stat);
#if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, pend_resp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* Scrub the decoded AUTH response from rx_buf. Its properties (e.g. the
     * MQTT_PROP_AUTH_DATA SASL blob) point into rx_buf and would otherwise
     * linger until the next read overwrites them. MqttClient_WaitType above
     * already delivered and freed auth->props, so the bytes are consumed
     * before this scrub and the caller has no live pointer into rx_buf. */
#ifdef WOLFMQTT_MULTITHREAD
    /* Hold lockRecv so the scrub cannot race a concurrent read into rx_buf. If
     * the lock cannot be taken, still scrub: leaving the AUTH_DATA plaintext
     * behind is worse than an unsynchronized wipe. */
    if (wm_SemLock(&client->lockRecv) == 0) {
        CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
        wm_SemUnlock(&client->lockRecv);
    }
    else {
        CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
    }
#else
    CLIENT_FORCE_ZERO(client->rx_buf, client->rx_buf_len);
#endif

    /* reset state */
    stat->write = MQTT_MSG_BEGIN;

    return rc;
}

/* Return 1 only if the AUTH packet carries the same Authentication Method value
 * that CONNECT negotiated [MQTT-4.12.0-1]. A missing method, a length or byte
 * mismatch, or a CONNECT method too long to have been stored all fail. */
static int MqttClient_AuthMethodMatches(const MqttClient* client,
    const MqttAuth* auth)
{
    const MqttProp* prop;

    if (client->auth_method_len > MQTT_AUTH_METHOD_MAX) {
        return 0;
    }
    for (prop = auth->props; prop != NULL; prop = prop->next) {
        if (prop->type == MQTT_PROP_AUTH_METHOD) {
            if (prop->data_str.len != client->auth_method_len) {
                return 0;
            }
            if (client->auth_method_len == 0) {
                return 1;
            }
            if (prop->data_str.str == NULL) {
                return 0;
            }
            return (XMEMCMP(prop->data_str.str, client->auth_method,
                        client->auth_method_len) == 0);
        }
    }
    return 0;
}

int MqttClient_Auth(MqttClient *client, MqttAuth* auth)
{
    if (client == NULL || auth == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    /* [MQTT-4.12.0-1] An AUTH may only be sent on a connection whose CONNECT
     * carried an Authentication Method. Refuse otherwise so a client cannot
     * emit an AUTH on a connection that never negotiated enhanced auth.
     * AUTH (type 15) does not exist below v5. */
    if (client->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5 ||
            client->auth_method_set == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    /* [MQTT-4.12.0-1] Re-authentication must reuse the negotiated method: refuse
     * an AUTH whose Authentication Method differs from or is missing relative to
     * the one CONNECT carried, so the mechanism cannot be switched mid-session. */
    if (!MqttClient_AuthMethodMatches(client, auth)) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
    return MqttClient_AuthEx(client, auth, &auth->stat,
#ifdef WOLFMQTT_MULTITHREAD
        &auth->pendResp,
#endif
        auth);
}

MqttProp* MqttClient_PropsAdd(MqttProp **head)
{
    return MqttProps_Add(head);
}

int MqttClient_PropsFree(MqttProp *head)
{
    return MqttProps_Free(head);
}

#endif /* WOLFMQTT_V5 */

#ifndef WOLFMQTT_NO_TIME
/* Send a keep-alive PINGREQ when the outbound link has been idle for about
 * three quarters of the negotiated keep-alive interval, so the application
 * does not have to schedule pings itself. Called from the wait path.
 * [MQTT-3.1.2-23] */
static int MqttClient_KeepAlive(MqttClient *client, MqttObject* msg)
{
    int rc = MQTT_CODE_SUCCESS;
    int mid_transfer;
    word32 now, elapsed, threshold;

    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* Disabled at runtime by the application (e.g. it schedules its own ping),
     * independent of the keep-alive negotiated with the broker. */
    if ((client->flags & MQTT_CLIENT_FLAG_NO_AUTO_KEEPALIVE) != 0) {
        return MQTT_CODE_SUCCESS;
    }

    /* Disabled until a non-zero keep-alive has been negotiated in CONNECT. */
    if (client->keep_alive_sec == 0) {
        return MQTT_CODE_SUCCESS;
    }

    /* Resume an in-progress ping exchange before evaluating the threshold. In
     * WOLFMQTT_NONBLOCK mode MqttClient_Ping_ex can return MQTT_CODE_CONTINUE
     * before the PINGRESP arrives, leaving the ping state machine mid-exchange.
     * Drive it to completion here so a later ping is not entered with stale
     * state, which would skip the PINGREQ and stretch the real ping interval. */
    if (client->keep_alive_ping.stat.write != MQTT_MSG_BEGIN) {
        rc = MqttClient_Ping_ex(client, &client->keep_alive_ping);
        if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK);
        }
        return rc;
    }

    /* Do not inject a ping while a message is mid-transfer: a partially read
     * fixed header (packet.stat), or a payload read still in progress on the
     * wait object (msg->read), which packet.stat alone does not catch once the
     * header has been consumed but the read is not finished. Under
     * WOLFMQTT_MULTITHREAD client->packet and client->read are protected by the
     * read lock, so evaluate this under lockClient (which MqttReadStart and
     * MqttReadStop also hold when they set read.isActive and reset
     * packet.stat). read.isActive - an in-progress read holding lockRecv - is
     * tested first, so packet.stat is only read when no read is active and thus
     * cannot be concurrently advanced. wm_SemLock blocks until lockClient is
     * available and returns an error only on a system fault (e.g. ThreadX), in
     * which case the ping is skipped this round. */
    mid_transfer = 0;
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        if (client->read.isActive ||
                client->packet.stat != MQTT_PK_BEGIN ||
                (msg != NULL && ((MqttMsgStat*)msg)->read != MQTT_MSG_BEGIN)) {
            mid_transfer = 1;
        }
        wm_SemUnlock(&client->lockClient);
    }
    else {
        mid_transfer = 1;
    }
#else
    if (client->packet.stat != MQTT_PK_BEGIN ||
            (msg != NULL && ((MqttMsgStat*)msg)->read != MQTT_MSG_BEGIN)) {
        mid_transfer = 1;
    }
#endif
    if (mid_transfer) {
        return MQTT_CODE_SUCCESS;
    }

    now = WOLFMQTT_GET_TIME_S();
    if (now < client->last_tx_time) {
        /* Clock stepped backward: re-baseline instead of pinging early. */
        client->last_tx_time = now;
        return MQTT_CODE_SUCCESS;
    }

    /* Ping at ~3/4 of the interval so the PINGREQ reaches the broker before
     * the hard deadline, leaving headroom for network latency and the
     * one-second clock granularity. Floor at one second so a small keep-alive
     * still schedules a single ping instead of firing on every poll. */
    threshold = (word32)client->keep_alive_sec * 3 / 4;
    if (threshold == 0) {
        threshold = 1;
    }

    elapsed = now - client->last_tx_time;
    if (elapsed >= threshold) {
        /* MqttPacket_Write refreshes last_tx_time as the PINGREQ is sent. */
        rc = MqttClient_Ping_ex(client, &client->keep_alive_ping);
        if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            /* No PINGRESP within cmd_timeout_ms: the link is unresponsive, not
             * merely idle. Surface a distinct error so a caller does not treat
             * a failed keep-alive as an ordinary read timeout and keep looping
             * on a dead connection. */
            rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_NETWORK);
        }
    }
    return rc;
}
#endif /* !WOLFMQTT_NO_TIME */

int MqttClient_WaitMessage_ex(MqttClient *client, MqttObject* msg,
        int timeout_ms)
{
#ifndef WOLFMQTT_NO_TIME
    int rc;
#endif

    if (client == NULL || msg == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

#ifndef WOLFMQTT_NO_TIME
    /* Send an automatic keep-alive PINGREQ if the outbound link has been idle
     * long enough. A deferred ping (another thread holds the write lock) comes
     * back as MQTT_CODE_CONTINUE, which is not an error, so in a blocking build
     * fall through to the normal wait rather than returning it to the caller. */
    rc = MqttClient_KeepAlive(client, msg);
    if (rc != MQTT_CODE_SUCCESS
    #ifndef WOLFMQTT_NONBLOCK
            && rc != MQTT_CODE_CONTINUE
    #endif
        ) {
        return rc;
    }
#endif
    return MqttClient_WaitType(client, msg, MQTT_PACKET_TYPE_ANY, 0,
        timeout_ms, NULL);
}
int MqttClient_WaitMessage(MqttClient *client, int timeout_ms)
{
    if (client == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    return MqttClient_WaitMessage_ex(client, &client->msg, timeout_ms);
}

#if !defined(WOLFMQTT_MULTITHREAD) && !defined(WOLFMQTT_NONBLOCK)
static
#endif
int MqttClient_CancelMessage(MqttClient *client, MqttObject* msg)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttMsgStat* mms_stat;
    int onWire;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp* tmpResp;
#endif

    if (client == NULL || msg == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* all packet type structures must have MqttMsgStat at top */
    mms_stat = (MqttMsgStat*)msg;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("Cancel Msg: %p", msg);
#endif

    /* Whether this message's packet finished going out. MQTT_MSG_WAIT is only
     * reached once the whole Control Packet has been written. */
    onWire = (mms_stat->write == MQTT_MSG_WAIT) ? 1 : 0;

    /* reset states */
    mms_stat->write = MQTT_MSG_BEGIN;
    mms_stat->read = MQTT_MSG_BEGIN;

    /* A packet that never fully reached the transport carries no identifier
     * the peer can act on, so cancelling it gives the identifier straight
     * back. One that did is a different matter: the peer may still process it
     * and answer, and that acknowledgement would complete whatever new
     * exchange had taken the identifier over. [MQTT-2.3.1-3] makes it reusable
     * only once the acknowledgement is processed, so the reservation outlives
     * the cancel - the same reasoning as the Receive Maximum unit below - and
     * only the object's ownership of it is dropped. The partial-write paths in
     * MqttPublishMsg re-reserve explicitly after cancelling. */
    if (onWire) {
        MqttClient_SendIdDisown(client, msg);
    }
    else {
        MqttClient_SendIdReleaseOwner(client, msg);
    }

    /* Do not credit the reserved Receive Maximum unit here. Cancelling an
     * abandoned QoS>0 publish that already reached the wire must retain the
     * unit while the connection stays open - the server still counts it against
     * Receive Maximum [MQTT-4.9], and crediting it would let the client exceed
     * the quota. The genuinely-unsent write-failure paths release explicitly via
     * MqttClient_RestoreRecvQuota, which they call before cancelling so the
     * credit is not swallowed by the ownership reset below. */
#ifdef WOLFMQTT_V5
    /* The unit stays charged to the connection, but ownership of it must not
     * stay on this message object: cancel resets the object for reuse, and a
     * leftover recvQuotaHeld would make MqttClient_RecvQuotaReserve treat the
     * next publish through it as already reserved and skip the decrement,
     * putting one more PUBLISH in flight than Receive Maximum allows
     * [MQTT-4.9]. Clear the flag without crediting server_recv_max; the unit is
     * recovered when the next connect resets the quota. */
    mms_stat->recvQuotaHeld = 0;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    /* Remove any pending responses expected */
    rc = wm_SemLock(&client->lockClient);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    for (tmpResp = client->firstPendResp;
         tmpResp != NULL;
         tmpResp = tmpResp->next)
    {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("\tMsg: %p (obj %p), Type %s (%d), ID %d, InProc %d, Done %d",
            tmpResp, tmpResp->packet_obj,
            MqttPacket_TypeDesc(tmpResp->packet_type),
            tmpResp->packet_type, tmpResp->packet_id,
            tmpResp->packetProcessing, tmpResp->packetDone);
    #endif
        if ((size_t)tmpResp->packet_obj == (size_t)msg ||
            (size_t)tmpResp - OFFSETOF(MqttMessage, pendResp) == (size_t)msg) {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Found Cancel Msg: %p (obj %p), Type %s (%d), ID %d, "
                   "InProc %d, Done %d",
                tmpResp, tmpResp->packet_obj,
                MqttPacket_TypeDesc(tmpResp->packet_type),
                tmpResp->packet_type, tmpResp->packet_id,
                tmpResp->packetProcessing, tmpResp->packetDone);
        #endif
            /* Do not credit any reserved Receive Maximum unit here: the PUBLISH
             * may already be on the wire, where the server keeps counting it
             * [MQTT-4.9], so crediting it on a local cancel could exceed the
             * negotiated quota. The unit is released on the acknowledgement, or
             * recovered when the connection resets server_recv_max. */
            MqttClient_RespList_Remove(client, tmpResp);
            break;
        }
    }
    wm_SemUnlock(&client->lockClient);
#endif /* WOLFMQTT_MULTITHREAD */

    /* cancel any active flags / locks */
    if (mms_stat->isReadActive) {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("Cancel Read Lock");
    #endif
        MqttReadStop(client, mms_stat);
    }
    if (mms_stat->isWriteActive) {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("Cancel Write Lock");
    #endif
        /* An abandoned write (e.g. a partial nonblocking CONNECT) leaves the
         * encoded packet - possibly plaintext credentials - in tx_buf. Scrub
         * it before MqttWriteStop releases lockSend. */
        CLIENT_FORCE_ZERO(client->tx_buf, client->tx_buf_len);
        MqttWriteStop(client, mms_stat);
    }

    return rc;
}

#ifdef WOLFMQTT_NONBLOCK
static inline int IsMessageActive(MqttObject *msg)
{
    return (msg->stat.read  != MQTT_MSG_BEGIN ||
            msg->stat.write != MQTT_MSG_BEGIN);
}

int MqttClient_IsMessageActive(
    MqttClient *client,
    MqttObject *msg)
{
    int rc;

    /* must supply either client or msg */
    if (client == NULL && msg == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* if msg is null then client->msg is used */
    if ((client != NULL && &client->msg == msg) || msg == NULL) {
    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0)
    #endif
        {
            rc = IsMessageActive(&client->msg);
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockClient);
        #endif
        }
    }
    else {
        rc = IsMessageActive(msg);
    }
    return rc;
}


#endif /* WOLFMQTT_NONBLOCK */


int MqttClient_NetConnect(MqttClient *client, const char* host,
    word16 port, int timeout_ms, int use_tls, MqttTlsCb cb)
{
    return MqttSocket_Connect(client, host, port, timeout_ms, use_tls, cb);
}

int MqttClient_NetDisconnect(MqttClient *client)
{
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp *tmpResp;
    MqttPendResp *nextResp;
    int rc;
#endif

    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_MULTITHREAD
    /* Get client lock on to ensure no other threads are active */
    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("Net Disconnect: Removing pending responses");
    #endif
        for (tmpResp = client->firstPendResp;
             tmpResp != NULL;
             tmpResp = nextResp) {
            nextResp = tmpResp->next;
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("\tPendResp: %p (obj %p), Type %s (%d), ID %d, InProc %d, Done %d",
                tmpResp, tmpResp->packet_obj,
                MqttPacket_TypeDesc(tmpResp->packet_type),
                tmpResp->packet_type, tmpResp->packet_id,
                tmpResp->packetProcessing, tmpResp->packetDone);
        #endif
            /* Reserved Receive Maximum units are not credited on disconnect
             * (the PUBLISH may be on the wire); the next connect resets
             * server_recv_max to the newly negotiated value. Ownership must
             * still be dropped from the message object, though: the quota
             * belonged to the connection being torn down, and a leftover
             * recvQuotaHeld would let a reused publish object skip the
             * decrement on the next connection [MQTT-4.9]. */
        #ifdef WOLFMQTT_V5
            if (tmpResp->recvQuotaStat != NULL) {
                tmpResp->recvQuotaStat->recvQuotaHeld = 0;
            }
        #endif
            MqttClient_RespList_Remove(client, tmpResp);
        }
        wm_SemUnlock(&client->lockClient);
    }
    else {
        return rc;
    }
#endif

    /* The Network Connection is going away and the client keeps no outbound
     * session state across one, so nothing stays in flight [MQTT-2.3.1-3]. */
    MqttClient_SendIdsReset(client);

    return MqttSocket_Disconnect(client);
}

int MqttClient_GetProtocolVersion(MqttClient *client)
{
#ifdef WOLFMQTT_V5
    if (client && client->protocol_level == MQTT_CONNECT_PROTOCOL_LEVEL_5)
        return MQTT_CONNECT_PROTOCOL_LEVEL_5;
#else
    (void)client;
#endif
    return MQTT_CONNECT_PROTOCOL_LEVEL_4;
}
const char* MqttClient_GetProtocolVersionString(MqttClient *client)
{
    const char* str = NULL;
    int ver = MqttClient_GetProtocolVersion(client);
    switch (ver) {
        case MQTT_CONNECT_PROTOCOL_LEVEL_4:
            return "v3.1.1";
    #ifdef WOLFMQTT_V5
        case MQTT_CONNECT_PROTOCOL_LEVEL_5:
            return "v5";
    #endif
        default:
            break;
    }
    return str;
}

#ifndef WOLFMQTT_NO_ERROR_STRINGS
const char* MqttClient_ReturnCodeToString(int return_code)
{
    switch(return_code) {
        case MQTT_CODE_SUCCESS:
            return "Success";
        case MQTT_CODE_CONTINUE:
            return "Continue"; /* would block */
        case MQTT_CODE_STDIN_WAKE:
            return "STDIN Wake";
        case MQTT_CODE_PUB_CONTINUE:
            return "Continue calling publish"; /* Chunked publish */
        case MQTT_CODE_ERROR_BAD_ARG:
            return "Error (Bad argument)";
        case MQTT_CODE_ERROR_OUT_OF_BUFFER:
            return "Error (Out of buffer)";
        case MQTT_CODE_ERROR_MALFORMED_DATA:
            return "Error (Malformed Remaining Length)";
        case MQTT_CODE_ERROR_PACKET_TYPE:
            return "Error (Packet Type Mismatch)";
        case MQTT_CODE_ERROR_PACKET_ID:
            return "Error (Packet Id Mismatch)";
        case MQTT_CODE_ERROR_TLS_CONNECT:
            return "Error (TLS Connect)";
        case MQTT_CODE_ERROR_TIMEOUT:
            return "Error (Timeout)";
        case MQTT_CODE_ERROR_NETWORK:
            return "Error (Network)";
        case MQTT_CODE_ERROR_MEMORY:
            return "Error (Memory)";
        case MQTT_CODE_ERROR_STAT:
            return "Error (State)";
        case MQTT_CODE_ERROR_PROPERTY:
            return "Error (Property)";
        case MQTT_CODE_ERROR_SERVER_PROP:
            return "Error (Server Property)";
        case MQTT_CODE_ERROR_CALLBACK:
            return "Error (Error in Callback)";
        case MQTT_CODE_ERROR_SYSTEM:
            return "Error (System resource failed)";
        case MQTT_CODE_ERROR_NOT_FOUND:
            return "Error (Not found)";
        case MQTT_CODE_ERROR_CONNECT_REFUSED:
            return "Error (Broker refused connection)";
        case MQTT_CODE_ERROR_SUBSCRIBE_REJECTED:
            return "Error (Broker rejected subscription)";
        case MQTT_CODE_ERROR_UNSUBSCRIBE_REJECTED:
            return "Error (Broker rejected unsubscribe)";
        case MQTT_CODE_ERROR_PUBLISH_REJECTED:
            return "Error (Broker rejected publish)";
#if defined(ENABLE_MQTT_CURL)
        case MQTT_CODE_ERROR_CURL:
            return "Error (libcurl)";
#endif

#ifdef WOLFMQTT_V5
        /* MQTT v5 Reason code strings */
        case MQTT_REASON_UNSPECIFIED_ERR:
            return "Unspecified error";
        case MQTT_REASON_MALFORMED_PACKET:
            return "Malformed Packet";
        case MQTT_REASON_PROTOCOL_ERR:
            return "Protocol Error";
        case MQTT_REASON_IMPL_SPECIFIC_ERR:
            return "Implementation specific error";
        case MQTT_REASON_UNSUP_PROTO_VER:
            return "Unsupported Protocol Version";
        case MQTT_REASON_CLIENT_ID_NOT_VALID:
            return "Client Identifier not valid";
        case MQTT_REASON_BAD_USER_OR_PASS:
            return "Bad User Name or Password";
        case MQTT_REASON_NOT_AUTHORIZED:
            return "Not authorized";
        case MQTT_REASON_SERVER_UNAVAILABLE:
            return "Server unavailable";
        case MQTT_REASON_SERVER_BUSY:
            return "Server busy";
        case MQTT_REASON_BANNED:
            return "Banned";
        case MQTT_REASON_SERVER_SHUTTING_DOWN:
            return "Server shutting down";
        case MQTT_REASON_BAD_AUTH_METHOD:
            return "Bad authentication method";
        case MQTT_REASON_KEEP_ALIVE_TIMEOUT:
            return "Keep Alive timeout";
        case MQTT_REASON_SESSION_TAKEN_OVER:
            return "Session taken over";
        case MQTT_REASON_TOPIC_FILTER_INVALID:
            return "Topic Filter invalid";
        case MQTT_REASON_TOPIC_NAME_INVALID:
            return "Topic Name invalid";
        case MQTT_REASON_PACKET_ID_IN_USE:
            return "Packet Identifier in use";
        case MQTT_REASON_PACKET_ID_NOT_FOUND:
            return "Packet Identifier not found";
        case MQTT_REASON_RX_MAX_EXCEEDED:
            return "Receive Maximum exceeded";
        case MQTT_REASON_TOPIC_ALIAS_INVALID:
            return "Topic Alias invalid";
        case MQTT_REASON_PACKET_TOO_LARGE:
            return "Packet too large";
        case MQTT_REASON_MSG_RATE_TOO_HIGH:
            return "Message rate too high";
        case MQTT_REASON_QUOTA_EXCEEDED:
            return "Quota exceeded";
        case MQTT_REASON_ADMIN_ACTION:
            return "Administrative action";
        case MQTT_REASON_PAYLOAD_FORMAT_INVALID:
            return "Payload format invalid";
        case MQTT_REASON_RETAIN_NOT_SUPPORTED:
            return "Retain not supported";
        case MQTT_REASON_QOS_NOT_SUPPORTED:
            return "QoS not supported";
        case MQTT_REASON_USE_ANOTHER_SERVER:
            return "Use another server";
        case MQTT_REASON_SERVER_MOVED:
            return "Server moved";
        case MQTT_REASON_SS_NOT_SUPPORTED:
            return "Shared Subscriptions not supported";
        case MQTT_REASON_CON_RATE_EXCEED:
            return "Connection rate exceeded";
        case MQTT_REASON_MAX_CON_TIME:
            return "Maximum connect time";
        case MQTT_REASON_SUB_ID_NOT_SUP:
            return "Subscription Identifiers not supported";
        case MQTT_REASON_WILDCARD_SUB_NOT_SUP:
            return "Wildcard Subscriptions not supported";
#endif
    }
    return "Unknown";
}
#endif /* !WOLFMQTT_NO_ERROR_STRINGS */

word32 MqttClient_Flags(MqttClient *client,  word32 mask, word32 flags)
{
    word32 ret = 0;
    if (client != NULL) {
#ifdef WOLFMQTT_MULTITHREAD
        /* Get client lock on to ensure no other threads are active */
        if (wm_SemLock(&client->lockClient) == 0)
#endif
        {
            client->flags &= ~mask;
            client->flags |= flags;
            ret = client->flags;
#ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockClient);
#endif
        }
    }
    return ret;
}
