/* mqtt_client.c
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

/* forward declarations */
static int MqttClient_Publish_ReadPayload(MqttClient* client,
    MqttPublish* publish, int timeout_ms);
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

#endif /* MUTEX */
#endif /* WOLFMQTT_MULTITHREAD */

static int MqttWriteStart(MqttClient* client, MqttMsgStat* stat)
{
    int rc = MQTT_CODE_SUCCESS;

#if defined(WOLFMQTT_DEBUG_CLIENT) || !defined(WOLFMQTT_ALLOW_NODATA_UNLOCK)
  #ifdef WOLFMQTT_DEBUG_CLIENT
    if (stat->isWriteActive) {
        MQTT_TRACE_MSG("Warning, send already locked!");
        rc = MQTT_CODE_ERROR_SYSTEM;
    }
  #endif
  #ifndef WOLFMQTT_ALLOW_NODATA_UNLOCK
    /* detect if a write is already in progress */
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
  #endif /* WOLFMQTT_ALLOW_NODATA_UNLOCK */
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
#endif

#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockSend);
#endif
    if (rc == MQTT_CODE_SUCCESS) {
        stat->isWriteActive = 1;

    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0)
    #endif
        {
            client->write.isActive = 1;
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockClient);
        #endif
        }

        MQTT_TRACE_MSG("lockSend");
    }

    return rc;
}
static void MqttWriteStop(MqttClient* client, MqttMsgStat* stat)
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

static int MqttReadStart(MqttClient* client, MqttMsgStat* stat)
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
static void MqttReadStop(MqttClient* client, MqttMsgStat* stat)
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

    /* verify newResp is not already in the list */
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
                int tmp = Handle_Props(client, p_connect_ack->props,
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
            #ifdef WOLFMQTT_V5
                /* setting the protocol level will enable parsing of the
                 * properties. The properties are allocated from a list,
                 * so only parse if we are using a return packet object */
                p_publish->protocol_level = client->protocol_level;
            #endif
            }
            else {
                p_publish = &publish;
                XMEMSET(p_publish, 0, sizeof(MqttPublish));
            }
            rc = MqttDecode_Publish(rx_buf, rx_len, p_publish);
            if (rc >= 0) {
                packet_id = p_publish->packet_id;
            #ifdef WOLFMQTT_V5
                if (doProps) {
                    /* Do not free property list here. It will be freed
                       after the message callback. */
                    int tmp = Handle_Props(client, p_publish->props,
                                           (packet_obj != NULL), 0);
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
            if (rc < 0) {
                break;
            }
            /* Note: Getting here means the Publish Read is done */
            publish->stat.read = MQTT_MSG_BEGIN; /* reset state */

        #ifdef WOLFMQTT_V5
            /* Free the properties */
            MqttProps_Free(publish->props);
            publish->props = NULL;
        #endif

            /* Handle QoS */
            if (packet_qos == MQTT_QOS_0) {
                /* we are done, no QoS response */
                break;
            }

        #ifdef WOLFMQTT_V5
            /* Copy response code in case changed by callback */
            resp->reason_code = publish->resp.reason_code;
        #endif
            /* Populate information needed for ack */
            resp->packet_type = (packet_qos == MQTT_QOS_1) ?
                MQTT_PACKET_TYPE_PUBLISH_ACK :
                MQTT_PACKET_TYPE_PUBLISH_REC;
            resp->packet_id = packet_id;
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
static int MqttClient_CheckPendResp(MqttClient *client, byte wait_type,
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
#ifdef WOLFMQTT_MULTITHREAD
    offset += sizeof(MqttPendResp);
#endif
    switch (packet_type) {
        case MQTT_PACKET_TYPE_CONNECT:
            objSz = sizeof(MqttConnect);
            break;
        case MQTT_PACKET_TYPE_CONNECT_ACK:
            objSz = sizeof(MqttConnectAck);
            break;
        case MQTT_PACKET_TYPE_PUBLISH:
            objSz = sizeof(MqttPublish);
            break;
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
            objSz = sizeof(MqttPublishResp);
            break;
        case MQTT_PACKET_TYPE_SUBSCRIBE:
            objSz = sizeof(MqttSubscribe);
            break;
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
            objSz = sizeof(MqttSubscribeAck);
            break;
        case MQTT_PACKET_TYPE_UNSUBSCRIBE:
            objSz = sizeof(MqttUnsubscribe);
            break;
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
            objSz = sizeof(MqttUnsubscribeAck);
            break;
        case MQTT_PACKET_TYPE_PING_REQ:
        case MQTT_PACKET_TYPE_PING_RESP:
            objSz = sizeof(MqttPing);
            break;
        case MQTT_PACKET_TYPE_AUTH:
        #ifdef WOLFMQTT_V5
            objSz = sizeof(MqttAuth);
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
    byte wait_type, word16 wait_packet_id, int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    word16         packet_id;
    MqttPacketType packet_type;
    MqttQoS        packet_qos = MQTT_QOS_0;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp *pendResp;
#endif
    MqttMsgStat* mms_stat;
    int waitMatchFound;
    void* use_packet_obj = NULL;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    /* all packet type structures must have MqttMsgStat at top */
    mms_stat = (MqttMsgStat*)packet_obj;

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

            mms_stat->read = MQTT_MSG_PAYLOAD;
        }
        FALL_THROUGH;

        case MQTT_MSG_PAYLOAD:
        case MQTT_MSG_PAYLOAD2:
        {
            MqttPublishResp resp;
            MqttPacketType use_packet_type;

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
                    if (pendResp->packet_obj != packet_obj) {
                        use_packet_obj = pendResp->packet_obj;
                        use_packet_type = pendResp->packet_type;
                        /* req from another thread... not a match */
                        waitMatchFound = 0;
                    }
                }
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
                /* if we get here, then we are sending an ACK */
                mms_stat->read = MQTT_MSG_ACK;
                mms_stat->ack = MQTT_MSG_WAIT;

                /* setup ACK in shared context */
                XMEMCPY(&client->packetAck, &resp, sizeof(MqttPublishResp));
            #ifdef WOLFMQTT_V5
                client->packetAck.protocol_level = client->protocol_level;
            #endif
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
            /* send ack */
            rc = MqttEncode_PublishResp(client->tx_buf, client->tx_buf_len,
                client->packetAck.packet_type, &client->packetAck);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttEncode_PublishResp: Len %d, Type %s (%d), ID %d",
                rc, MqttPacket_TypeDesc(client->packetAck.packet_type),
                    client->packetAck.packet_type, client->packetAck.packet_id);
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

#ifdef WOLFMQTT_DEBUG_CLIENT
    if (rc != MQTT_CODE_CONTINUE) {
        PRINTF("MqttClient_WaitType: rc %d, state %d-%d-%d",
            rc, mms_stat->read, mms_stat->write, mms_stat->ack);
    }
#endif

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
        rx_buf == NULL || rx_buf_len <= 0) {
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
    client->max_qos = MQTT_QOS_2;
    client->retain_avail = 1;
    client->protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL;
    rc = MqttProps_Init();
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (rc == 0) {
        rc = wm_SemInit(&client->lockSend);
    }
    if (rc == 0) {
        rc = wm_SemInit(&client->lockRecv);
    }
    if (rc == 0) {
        rc = wm_SemInit(&client->lockClient);
    }
    #ifdef ENABLE_MQTT_CURL
    if (rc == 0) {
        rc = wm_SemInit(&client->lockCURL);
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
#ifdef WOLFMQTT_MULTITHREAD
        (void)wm_SemFree(&client->lockSend);
        (void)wm_SemFree(&client->lockRecv);
        (void)wm_SemFree(&client->lockClient);
    #ifdef ENABLE_MQTT_CURL
        (void)wm_SemFree(&client->lockCURL);
    #endif
#endif
    }
#ifdef WOLFMQTT_V5
    (void)MqttProps_ShutDown();
#endif
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

int MqttClient_Connect(MqttClient *client, MqttConnect *mc_connect)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || mc_connect == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (mc_connect->stat.write == MQTT_MSG_BEGIN) {
        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, &mc_connect->stat)) != 0) {
            return rc;
        }

    #ifdef WOLFMQTT_V5
        /* Use specified protocol version if set */
        mc_connect->protocol_level = client->protocol_level;
    #endif

        /* Encode the connect packet */
        rc = MqttEncode_Connect(client->tx_buf, client->tx_buf_len, mc_connect);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_CONNECT),
            MQTT_PACKET_TYPE_CONNECT, 0, 0);
    #endif
        if (rc <= 0) {
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
            MqttWriteStop(client, &mc_connect->stat);
            return rc; /* Error locking client */
        }
    #endif

        mc_connect->stat.write = MQTT_MSG_HEADER;
    }
    if (mc_connect->stat.write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;

        /* Send connect packet */
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
        MqttWriteStop(client, &mc_connect->stat);
        if (rc != xfer) {
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
        MqttAuth auth, *p_auth = &auth;
        MqttProp* prop, *conn_prop;

        /* Find the AUTH property in the connect structure */
        for (conn_prop = mc_connect->props;
             (conn_prop != NULL) && (conn_prop->type != MQTT_PROP_AUTH_METHOD);
             conn_prop = conn_prop->next) {
        }
        if (conn_prop == NULL) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &mc_connect->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            /* AUTH property was not set in connect structure */
            return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
        }

        XMEMSET((void*)p_auth, 0, sizeof(MqttAuth));

        /* Set the authentication reason */
        p_auth->reason_code = MQTT_REASON_CONT_AUTH;

        /* Use the same authentication method property from connect */
        prop = MqttProps_Add(&p_auth->props);
        prop->type = MQTT_PROP_AUTH_METHOD;
        prop->data_str.str = conn_prop->data_str.str;
        prop->data_str.len = conn_prop->data_str.len;

        /* Send the AUTH packet */
        rc = MqttClient_Auth(client, p_auth);
        MqttClient_PropsFree(p_auth->props);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE)
            return rc;
    #endif
        if (rc < 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &mc_connect->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
        mc_connect->stat.write = MQTT_MSG_WAIT;
    }
#endif /* WOLFMQTT_V5 */

    /* Wait for connect ack packet */
    rc = MqttClient_WaitType(client, &mc_connect->ack,
        MQTT_PACKET_TYPE_CONNECT_ACK, 0, client->cmd_timeout_ms);
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

    /* reset state */
    mc_connect->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

static int MqttClient_Publish_ReadPayload(MqttClient* client,
    MqttPublish* publish, int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    byte msg_done;

    /* Handle packet callback and read remaining payload */
    do {
        /* Determine if message is done */
        msg_done = ((publish->buffer_pos + publish->buffer_len) >=
                    publish->total_len) ? 1 : 0;

        if (publish->buffer_new) {
            /* Issue callback for new message (first time only) */
            if (client->msg_cb) {
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
                if (client->msg_cb) {
                    rc = client->msg_cb(client, publish, publish->buffer_new,
                                        msg_done);
                    if (rc != MQTT_CODE_SUCCESS) {
                        return rc;
                    };
                }
            }
        }
    } while (!msg_done);

    return rc;
}

static int MqttClient_Publish_WritePayload(MqttClient *client,
    MqttPublish *publish, MqttPublishCb pubCb)
{
    int rc = MQTT_CODE_SUCCESS;

    if (client == NULL || publish == NULL)
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);

    if (pubCb) { /* use publish callback to get data */
        word32 tmp_len = publish->buffer_len;

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
            }

            if ((word32)client->write.len < publish->buffer_len) {
                /* Last read */
                tmp_len = (word32)client->write.len;
            }

            /* Send payload */
            do {
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

static int MqttPublishMsg(MqttClient *client, MqttPublish *publish,
                          MqttPublishCb pubCb, int writeOnly)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttPacketType resp_type;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

#ifdef WOLFMQTT_V5
    /* Use specified protocol version if set */
    publish->protocol_level = client->protocol_level;

    /* Validate publish request against server properties */
    if ((publish->qos > client->max_qos) ||
        ((publish->retain == 1) && (client->retain_avail == 0)))
    {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_SERVER_PROP);
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
                return rc;
            }
            client->write.len = rc;

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
                    wm_SemUnlock(&client->lockClient);
                }
                if (rc != 0) {
                    MqttWriteStop(client, &publish->stat);
                    return rc; /* Error locking client */
                }
            }
        #endif

            publish->stat.write = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        {
            int xfer = client->write.len;

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
            client->write.len = 0; /* reset len, so publish chunk resets */

            /* if failure or no data was written yet */
            if (rc != xfer) {
                MqttWriteStop(client, &publish->stat);
                MqttClient_CancelMessage(client, (MqttObject*)publish);
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
        #endif
            MqttWriteStop(client, &publish->stat);
            if (rc < 0) {
                MqttClient_CancelMessage(client, (MqttObject*)publish);
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
                        /* mark success, let other thread handle response */
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
                        publish->packet_id, client->cmd_timeout_ms);
                }

            #if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
                if (rc == MQTT_CODE_CONTINUE)
                    break;
            #endif
            #ifdef WOLFMQTT_MULTITHREAD
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
            return rc; /* Error locking client */
        }
    #endif

        subscribe->stat.write = MQTT_MSG_HEADER;
    }
    if (subscribe->stat.write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;

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
        MqttWriteStop(client, &subscribe->stat);
        if (rc != xfer) {
            MqttClient_CancelMessage(client, (MqttObject*)subscribe);
            return rc;
        }

        subscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for subscribe ack packet */
    rc = MqttClient_WaitType(client, &subscribe->ack,
        MQTT_PACKET_TYPE_SUBSCRIBE_ACK, subscribe->packet_id,
        client->cmd_timeout_ms);
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

    /* Populate return codes */
    if (rc == MQTT_CODE_SUCCESS) {
        for (i = 0; i < subscribe->topic_count && i < MAX_MQTT_TOPICS; i++) {
            topic = &subscribe->topics[i];
            topic->return_code = subscribe->ack.return_codes[i];
        }
    }

    /* reset state */
    subscribe->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int MqttClient_Unsubscribe(MqttClient *client, MqttUnsubscribe *unsubscribe)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
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
            return rc;
        }
    #endif

        unsubscribe->stat.write = MQTT_MSG_HEADER;
    }
    if (unsubscribe->stat.write == MQTT_MSG_HEADER) {
        int xfer = client->write.len;

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
        MqttWriteStop(client, &unsubscribe->stat);
        if (rc != xfer) {
            MqttClient_CancelMessage(client, (MqttObject*)unsubscribe);
            return rc;
        }

        unsubscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for unsubscribe ack packet */
    rc = MqttClient_WaitType(client, &unsubscribe->ack,
        MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK, unsubscribe->packet_id,
        client->cmd_timeout_ms);
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
    if (unsubscribe->ack.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(unsubscribe->ack.props);
    }
#endif

    /* reset state */
    unsubscribe->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int MqttClient_Ping_ex(MqttClient *client, MqttPing* ping)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || ping == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
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
        client->cmd_timeout_ms);
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

    return rc;
}

int MqttClient_Ping(MqttClient *client)
{
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
    if (disconnect == NULL) {
        disconnect = &lcl_disconnect;
        XMEMSET(disconnect, 0, sizeof(*disconnect));
    }

    if (disconnect->stat.write == MQTT_MSG_BEGIN) {
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
        /* keep send locked and return early */
        return rc;
    }
#endif
    MqttWriteStop(client, &disconnect->stat);
    if (rc == xfer) {
        rc = MQTT_CODE_SUCCESS;
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
int MqttClient_Auth(MqttClient *client, MqttAuth* auth)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    if (auth->stat.write == MQTT_MSG_BEGIN) {
        /* Flag write active / lock mutex */
        if ((rc = MqttWriteStart(client, &auth->stat)) != 0) {
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
            MqttWriteStop(client, &auth->stat);
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_AUTH, 0,
                &auth->pendResp, auth);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            MqttWriteStop(client, &auth->stat);
            return rc; /* Error locking client */
        }
    #endif

        auth->stat.write = MQTT_MSG_HEADER;
    }
    if (auth->stat.write == MQTT_MSG_BEGIN) {
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
        MqttWriteStop(client, &auth->stat);
        if (rc != xfer) {
            MqttClient_CancelMessage(client, (MqttObject*)auth);
            return rc;
        }

        auth->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for auth packet */
    rc = MqttClient_WaitType(client, auth, MQTT_PACKET_TYPE_AUTH, 0,
        client->cmd_timeout_ms);
#if defined(WOLFMQTT_NONBLOCK) || defined(WOLFMQTT_MULTITHREAD)
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &auth->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    auth->stat.write = MQTT_MSG_BEGIN;

    return rc;
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

int MqttClient_WaitMessage_ex(MqttClient *client, MqttObject* msg,
        int timeout_ms)
{
    return MqttClient_WaitType(client, msg, MQTT_PACKET_TYPE_ANY, 0,
        timeout_ms);
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

    /* reset states */
    mms_stat->write = MQTT_MSG_BEGIN;
    mms_stat->read = MQTT_MSG_BEGIN;

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
             tmpResp = tmpResp->next) {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("\tPendResp: %p (obj %p), Type %s (%d), ID %d, InProc %d, Done %d",
                tmpResp, tmpResp->packet_obj,
                MqttPacket_TypeDesc(tmpResp->packet_type),
                tmpResp->packet_type, tmpResp->packet_id,
                tmpResp->packetProcessing, tmpResp->packetDone);
        #endif
            MqttClient_RespList_Remove(client, tmpResp);
        }
        wm_SemUnlock(&client->lockClient);
    }
    else {
        return rc;
    }
#endif

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
