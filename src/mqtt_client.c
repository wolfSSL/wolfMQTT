/* mqtt_client.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

/* Options */
#ifdef WOLFMQTT_NO_STDIO
    #undef WOLFMQTT_DEBUG_CLIENT
#endif

/* Private functions */

/* forward declarations */
static int MqttClient_Publish_ReadPayload(MqttClient* client,
    MqttPublish* publish, int timeout_ms);

static int MqttClient_Publish_WritePayload(MqttClient *client,
    MqttPublish *publish);

#if !defined(WOLFMQTT_MULTITHREAD)
    void* wm_CurrentThreadId(void) {
        return NULL;
    }
#else /* defined(WOLFMQTT_MULTITHREAD) */

#ifdef WOLFMQTT_USER_THREADING

    /* User will supply their own semaphore functions.
     * int wm_SemInit(wm_Sem *s)
     * int wm_SemFree(wm_Sem *s)
     * int wm_SemLock(wm_Sem *s)
     * int wm_SemUnlock(wm_Sem *s)
     * void* wm_CurrentThreadId(void)
     */

#elif defined(__MACH__)

    /* Apple style dispatch semaphore */
    int wm_SemInit(wm_Sem *s){
        /* dispatch_release() fails hard, with Trace/BPT trap signal, if the
         * sem's internal count is less than the value passed in with
         * dispatch_semaphore_create().  work around this by initing
         * with 0, then incrementing it afterwards.
         */
        *s = dispatch_semaphore_create(0);
        if (*s == NULL)
            return MQTT_CODE_ERROR_MEMORY;
        if (dispatch_semaphore_signal(*s) < 0) {
            dispatch_release(*s);
            return MQTT_CODE_ERROR_SYSTEM;
        }

        return 0;
    }
    int wm_SemFree(wm_Sem *s){
        if ((s == NULL) ||
            (*s == NULL))
            return MQTT_CODE_ERROR_BAD_ARG;
        dispatch_release(*s);
        *s = NULL;
        return 0;
    }
    int wm_SemLock(wm_Sem *s){
        dispatch_semaphore_wait(*s, DISPATCH_TIME_FOREVER);
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s){
        dispatch_semaphore_signal(*s);
        return 0;
    }
    void* wm_CurrentThreadId(void) {
        return (void*)(intptr_t)pthread_self();
    }
#elif defined(WOLFMQTT_POSIX_SEMAPHORES)
    /* Posix style semaphore */
    int wm_SemInit(wm_Sem *s){
        s->lockCount = 0;
        pthread_mutex_init(&s->mutex, NULL);
        pthread_cond_init(&s->cond, NULL);
        return 0;
    }
    int wm_SemFree(wm_Sem *s){
        pthread_mutex_destroy(&s->mutex);
        pthread_cond_destroy(&s->cond);
        return 0;
    }
    int wm_SemLock(wm_Sem *s){
        pthread_mutex_lock(&s->mutex);
        while (s->lockCount > 0)
            pthread_cond_wait(&s->cond, &s->mutex);
        s->lockCount++;
        pthread_mutex_unlock(&s->mutex);
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s){
        pthread_mutex_lock(&s->mutex);
        s->lockCount--;
        pthread_cond_signal(&s->cond);
        pthread_mutex_unlock(&s->mutex);
        return 0;
    }
    void* wm_CurrentThreadId(void) {
        return (void*)(intptr_t)pthread_self();
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
    void* wm_CurrentThreadId(void) {
        return (void*)(intptr_t)xTaskGetCurrentTaskHandle();
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
    void* wm_CurrentThreadId(void) {
        return (void*)(intptr_t)GetCurrentThreadId();
    }
#endif
#endif /* WOLFMQTT_MULTITHREAD */

int MqttClient_SendLock(MqttClient *client, MqttMsgHeader *stat)
{
    int rc = MQTT_CODE_SUCCESS;
    if (stat->writeLocked) {
        return rc;
    }
#ifdef WOLFMQTT_MULTITHREAD
    /* Lock send socket mutex */
    rc = wm_SemLock(&client->lockSend);
    if (rc < 0) {
        return rc;
    }
#endif
    stat->writeLocked = 1;
    stat->start_time_ms = 0;
    client->write.len = 0;
    return rc;
}

void MqttClient_SendUnlock(MqttClient *client, MqttMsgHeader *stat)
{
    (void)client;
    if (stat->writeLocked) {
        stat->writeLocked = 0;
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
    }
}

static int MqttClient_RecvLock(MqttClient *client)
{
    int rc = MQTT_CODE_SUCCESS;
#ifdef WOLFMQTT_MULTITHREAD
    /* Lock recv socket mutex */
    rc = wm_SemLock(&client->lockRecv);
    if (rc < 0) {
        return rc;
    }
#endif
#if defined(WOLFMQTT_DEBUG_THREAD) && defined(WOLFMQTT_DEBUG_CLIENT)
    PRINTF("MqttClient_RecvLock done");
#endif
    client->readLocked = 1;
    return rc;
}

static void MqttClient_RecvUnlock(MqttClient *client)
{
    if (client->readLocked) {
    #if defined(WOLFMQTT_DEBUG_THREAD) && defined(WOLFMQTT_DEBUG_CLIENT)
        PRINTF("MqttClient_RecvUnlock done");
    #endif
        client->readLocked = 0;
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockRecv);
    #endif
    } else {
    #if defined(WOLFMQTT_DEBUG_THREAD)
        PRINTF("MqttClient_RecvUnlock twice");
    #endif
    }
}

int MqttClient_RespList_Reset(MqttClient *client)
{
    int rc = MQTT_CODE_SUCCESS;
#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
#endif
    if (rc == MQTT_CODE_SUCCESS) {
        client->firstPendResp = NULL;
        client->lastPendResp = NULL;
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }
    return rc;
}

static void MqttClient_RespListClear(MqttClient *client)
{
    MqttPendResp *tmpResp;
    int rc = MQTT_CODE_SUCCESS;
#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
#endif
    if (rc == MQTT_CODE_SUCCESS) {
        /* Find pending response entry */
        for (tmpResp = client->lastPendResp;
            tmpResp != NULL;
            tmpResp = tmpResp->prev)
        {
            tmpResp->packetDone = 1;
            tmpResp->packet_ret = MQTT_CODE_ERROR_NETWORK;
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    #endif
    }
}

static void MqttClient_Resp_Init(MqttPendResp *newResp,
    MqttPacketType packet_type, word16 packet_id, void *packet_obj)
{
    if (packet_obj != NULL) {
        newResp->packet.id = packet_id;
        newResp->packet.type = packet_type;
    }
    /* opaque pointer to struct based on type */
    newResp->packet_obj = packet_obj;
}

static int MqttClient_Resp_Compare(MqttMsgPacketHeader *a, MqttMsgPacketHeader *b)
{
    if (a->type != b->type) {
        return a->type - b->type;
    }
    if (a->id != b->id) {
        return a->id - b->id;
    }
    return 0;
}

/* These RespList functions assume caller has locked client->lockClient mutex */
static int MqttClient_RespList_Add(MqttClient *client, MqttPendResp *newResp)
{
    MqttPendResp *tmpResp;
    int rc = MQTT_CODE_ERROR_BAD_ARG;

    if (client == NULL || newResp == NULL)
        return rc;
#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
    if (rc != 0) {
        return rc;
    }
#endif
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("PendResp Add: %p packet_obj:%p, Type %s (%d), ID %d",
        newResp, newResp->packet_obj, MqttPacket_TypeDesc(newResp->packet.type),
        newResp->packet.type, newResp->packet.id);
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
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockClient);
        #endif
            return rc;
        }
    }

    /* Initialize new response */
    rc = MQTT_CODE_SUCCESS;
    newResp->inRespList = 1;
    newResp->prev = NULL;
    newResp->next = NULL;
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
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
    return rc;
}

void MqttClient_RespList_Remove(MqttClient *client, MqttPendResp *rmResp)
{
    MqttPendResp *tmpResp;

    if (client == NULL)
        return;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("PendResp Remove: %p packet_type:%d id:%d",
        rmResp, rmResp->packet.type, rmResp->packet.id);
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != 0)
    {
        return;
    }
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
        tmpResp->inRespList = 0;
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
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
}

static int MqttClient_RespList_Find(MqttClient *client,
    MqttMsgPacketHeader *expectPacketHeader,
    MqttPendResp **retResp)
{
    int rc = 0;
    MqttPendResp *tmpResp;

    if (client == NULL || expectPacketHeader == NULL)
        return rc;
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) != MQTT_CODE_SUCCESS) {
        return rc;
    }
#endif
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("PendResp Find: Type %s (%d), QoS %d, ID %d",
        MqttPacket_TypeDesc(expectPacketHeader->type),
            expectPacketHeader->type, expectPacketHeader->qos, expectPacketHeader->id);
#endif

    if (retResp)
        *retResp = NULL; /* clear */

    /* Find pending response entry */
    for (tmpResp = client->lastPendResp;
         tmpResp != NULL;
         tmpResp = tmpResp->prev)
    {
        if (MqttClient_Resp_Compare(expectPacketHeader, &tmpResp->packet) == 0)
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("PendResp Found: %p, Type %s (%d), ID %d, InProc %d",
                tmpResp, MqttPacket_TypeDesc(tmpResp->packet.type),
                tmpResp->packet.type, tmpResp->packet.id,
                tmpResp->packetProcessing);
        #endif

            if (retResp)
                *retResp = tmpResp;
            rc = 1;
            break;
        }
    }
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockClient);
#endif
    return rc;
}

static int MqttClient_WriteEncoded(
    MqttClient *client,
    MqttMsgHeader *packet_send,
    MqttPacketType packet_type,
    MqttPacketType packet_type_ack,
    word16 packet_id,
    void *packet_obj_recv,
    MqttMsgState next_stat) /* The next stat after writing header or payload finished */
{
    /* Lock send socket mutex */
    int rc = MQTT_CODE_SUCCESS;

    switch (packet_send->writeState) {
    case MQTT_MSG_BEGIN:
    {
        Mqtt_DecodeEncode_Function p_encode_function = NULL;
        int encoded_len;
        if (next_stat != MQTT_MSG_BEGIN) {
            rc = MqttClient_SendLock(client, packet_send);
            if (rc < 0) {
                return rc;
            }
        }
        if (packet_type >= 0 && packet_type < MQTT_PACKET_TYPE_ANY) {
            p_encode_function = MqttClient_EncodeFunctionList[packet_type];
        }
        if (p_encode_function == NULL) {
            rc = MQTT_CODE_ERROR_PACKET_TYPE;
            break;
        }
    #ifdef WOLFMQTT_V5
        /* Use specified protocol version if set */
        packet_send->protocol_level = client->protocol_level;
    #endif
        MqttClient_Resp_Init(packet_send, packet_type_ack, packet_id, packet_obj_recv);
        /* Encode the connect packet */
        encoded_len = p_encode_function(client->tx_buf, client->tx_buf_len, packet_send);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_WriteEncoded: Len %d, Type %s (%d), ID %d",
            encoded_len, MqttPacket_TypeDesc(packet_type),
            packet_type, packet_id);
    #endif
        if (encoded_len == 0) {
            rc = MQTT_CODE_ERROR_MALFORMED_DATA;
        } else if (encoded_len < 0) {
            rc = encoded_len;
        } else {
            /* The packet is just encoded and it's valid, so update write.len */
            client->write.len = encoded_len;
            if (packet_obj_recv != NULL) {
                /* Add to response list for waiting ack */
                rc = MqttClient_RespList_Add(client, packet_send);
            }
        }
        if (rc < 0) {
            break;
        }
        packet_send->writeState = MQTT_MSG_HEADER;
    }
    FALL_THROUGH;

    case MQTT_MSG_HEADER:
    {
        /* Send encoded packet header */
        int write_rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        if (write_rc != client->write.len) {
            if (write_rc < 0) {
                rc = write_rc;
            } else {
                /* Not the whole header are sent */
                rc = MQTT_CODE_ERROR_NETWORK;
            }
            break;
        }
        if (rc < 0) {
            break;
        }
        if (packet_type != MQTT_PACKET_TYPE_PUBLISH) {
            /* For non publish packet, it's already finished */
            packet_send->writeState = next_stat;
            break;
        }
        packet_send->writeState = MQTT_MSG_PAYLOAD;
    }
    FALL_THROUGH;

    case MQTT_MSG_PAYLOAD:
    {
        int write_rc = MqttClient_Publish_WritePayload(client, (MqttPublish *)packet_send);
        /* Send publish payload */
        if (write_rc >= 0) {
            rc = MQTT_CODE_SUCCESS;
        } else {
            rc = write_rc;
        }
        if (rc == MQTT_CODE_PUB_CONTINUE) {
            return rc;
        }
        if (rc < 0) {
            break;
        }
        packet_send->writeState = next_stat;
        break;
    }
    case MQTT_MSG_WAIT:
    case MQTT_MSG_AUTH:
    {
        return MQTT_CODE_SUCCESS;
    }
    case MQTT_MSG_ACK:
    default:
        return MQTT_CODE_ERROR_STAT;
    }
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
    if (next_stat != MQTT_MSG_BEGIN) {
         MqttClient_SendUnlock(client, packet_send);
    }
    return rc;
}

#ifdef WOLFMQTT_V5
static int Handle_Props(MqttClient* client, MqttProp* props)
{
    int rc = MQTT_CODE_SUCCESS;

    /* If no properties, just return */
    if (props != NULL) {
    #ifdef WOLFMQTT_PROPERTY_CB
        /* Check for properties set by the server */
        if (client->property_cb != NULL) {
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
        /* Free the properties */
        MqttProps_Free(props);
    }
    return rc;
}
#endif

int MqttClient_CheckTimeout(int rc, int timeout_rc, word32* start_ms, word32 timeout_ms, word32 now_ms)
{
    word32 elapsed_ms;

    if (now_ms == 0) {
        now_ms = 1;
    }
    /* if start seconds is not set */
    if (*start_ms == 0) {
        *start_ms = now_ms;
        return rc;
    }

    elapsed_ms = now_ms - *start_ms;
    /* For handling now_ms < start_ms when now_ms overflow (2^32 -1) */
    if (elapsed_ms < (1u << 30)) {
        if (elapsed_ms > timeout_ms) {
            *start_ms = 0;
            return timeout_rc;
        }
    }

    return rc;
}

/* Returns length decoded or error (as negative) */
/*! \brief      Take a received MQTT packet and try and decode it
 *  \param      client       MQTT client context
 *  \param      rx_buf       Incoming buffer data
 *  \param      rx_len       Incoming buffer length
 *  \param      packet_obj   Opaque pointer to packet structure based on type
 *  \param      packet_header The packet header for decoding

 *  \return     Returns length decoded or error (as negative) MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
static int MqttClient_DecodePacket(MqttClient* client, byte* rx_buf,
    word32 rx_len, MqttObject *packet_obj, MqttMsgPacketHeader *packet_header)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttObject packet, *p_packet = &packet;
    MqttPacket* header;
    Mqtt_DecodeEncode_Function p_decode_function = NULL;

    /* must have rx buffer with at least 2 byes for header */
    if (rx_buf == NULL || rx_len < MQTT_PACKET_HEADER_MIN_SIZE || (packet_header == NULL && packet_obj == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (packet_header == NULL) {
        packet_header = &packet_obj->header.packet;
    }

    /* Decode header */
    header = (MqttPacket*)rx_buf;
    packet_header->type = (MqttPacketType)MQTT_PACKET_TYPE_GET(header->type_flags);
    packet_header->qos = (MqttQoS)MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);

    (void)client;
    if (packet_obj) {
    #ifdef WOLFMQTT_V5
        packet_obj->header.protocol_level = client->protocol_level;
    #endif
        p_packet = packet_obj;
    } else {
        /* Only need decoding into the packet header, so memset the header only */
        XMEMSET(&packet.header, 0, sizeof(packet.header));
    #ifdef WOLFMQTT_V5
        /* Disable decoding of mqtt v5 props when decode the packet header only */
        packet.header.protocol_level = MQTT_CONNECT_PROTOCOL_LEVEL_4;
    #endif
    }
    if (packet_header->type < MQTT_PACKET_TYPE_ANY) {
        p_decode_function = MqttClient_DecodeFunctionList[packet_header->type];
    }
    if (p_decode_function != NULL) {
        /* The mqtt client need decoding for type: packet_header->type */
        rc = p_decode_function(rx_buf, rx_len, p_packet);
    #ifdef WOLFMQTT_V5
        if (rc >= 0){
            int tmp = Handle_Props(client, p_packet->header.props);
            if (tmp != MQTT_CODE_SUCCESS) {
                rc = tmp;
            }
            p_packet->header.props = NULL;
        }
    #endif
    } else {
        rc = MQTT_CODE_ERROR_PACKET_TYPE;
    }
    packet_header->id = p_packet->header.packet.id;
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_DecodePacket: Rc %d, Len %d, Type %s (%d), ID %d,"
            " QoS %d",
        rc, rx_len, MqttPacket_TypeDesc(packet_header->type), packet_header->type, packet_header->id,
        packet_header->qos);
#endif

    return rc;
}

/**
 * @brief MqttClient_WaitType will unlock the receive lock unless the receive lock
 * is just locked
 *
 * @param rc The previous lock result
 * @param client Mqtt Client instance
 * @param timeout_ms read timeout
 * @return The new rc code
 */
static int MqttClient_WaitType(MqttClient *client, int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttMsgHeader *msgHeader = &client->anyMsgHeader;

    if (client == NULL || msgHeader == NULL || msgHeader->packet_obj == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_WaitType: Type %s (%d), ID %d, State %d",
        MqttPacket_TypeDesc(msgHeader->packet.type),
            msgHeader->packet.type, msgHeader->packet.id, client->readState);
#endif
    switch (client->readState)
    {
        case MQTT_MSG_BEGIN:
        {
            client->readState = MQTT_MSG_WAIT;
            XMEMSET(&client->recvPacketHeader, 0, sizeof(client->recvPacketHeader));
            if (client->usedPendResp != NULL) {
                rc = MQTT_CODE_ERROR_STAT;
                break;
            }
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        {
            /* Wait for packet header */
            rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len,
                    timeout_ms);
            if (rc == 0) {
                /* Read return 0 byte is not possible */
                rc = MQTT_CODE_ERROR_NETWORK;
                break;
            } else if (rc < 0) {
                /* handle failure */
                break;
            }

            /* capture length read */
            client->packet.buf_len = rc;

            /* Decode Packet - get type, qos and id */
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, NULL, &client->recvPacketHeader);
            if (rc < 0) {
                break;
            }

        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Read Packet: Len %d, Type %d, ID %d",
                client->packet.buf_len, client->recvPacketHeader.type, client->recvPacketHeader.id);
        #endif
            rc = MQTT_CODE_SUCCESS;
            client->readState = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        {
            MqttObject *packet_obj_recv;
            /* Check if the new packet is waited in the response list */
            MqttClient_RespList_Find(client,
                &client->recvPacketHeader,
                &client->usedPendResp);
            if (client->usedPendResp == NULL) {
                /* Use anyMsgHeader to parse the new packet as the new message is not in response list */
                client->usedPendResp = &client->anyMsgHeader;
            }
            if (client->usedPendResp == &client->anyMsgHeader) {
                MqttObject *msg = (MqttObject *)client->usedPendResp->packet_obj;
                /* Use anyMsgHeader to receiving data */
                XMEMSET(msg, 0, sizeof(msg[0]));
            }
            client->usedPendResp->packetProcessing = 1;
            packet_obj_recv = (MqttObject *)client->usedPendResp->packet_obj;
            /* Decode Packet - decoding into packet_obj_recv */
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj_recv, NULL);
            if (rc == MQTT_CODE_CONTINUE) {
                /* rc won't be MQTT_CODE_CONTINUE as MqttClient_DecodePacket didn't access network */
                rc = MQTT_CODE_ERROR_STAT;
            }
            if (rc < 0) {
                break;
            }
            rc = MQTT_CODE_SUCCESS;
            if (client->recvPacketHeader.type != MQTT_PACKET_TYPE_PUBLISH &&
                client->recvPacketHeader.type != MQTT_PACKET_TYPE_PUBLISH_REC &&
                client->recvPacketHeader.type != MQTT_PACKET_TYPE_PUBLISH_REL) {
                /* For non publish and publish resp message, it's already finished */
                break;
            }
            /* set state to reading payload */
            client->readState = MQTT_MSG_PAYLOAD;
        }
        FALL_THROUGH;

        case MQTT_MSG_PAYLOAD:
        {
            if (client->recvPacketHeader.type == MQTT_PACKET_TYPE_PUBLISH) {
                MqttPublish* publish = &((MqttObject *)client->usedPendResp->packet_obj)->publish;
                rc = MqttClient_Publish_ReadPayload(client, publish, timeout_ms);
                if (rc != MQTT_CODE_SUCCESS) {
                    break;
                }
            }
            client->readState = MQTT_MSG_ACK;
        }
        FALL_THROUGH;

        case MQTT_MSG_ACK:
            if (client->recvPacketHeader.type == MQTT_PACKET_TYPE_PUBLISH) {
                /* Note: Getting here means the Publish Read is done */
                /* Handle QoS */
                if (client->recvPacketHeader.qos != MQTT_QOS_0) {
                    /* Populate information needed for ack */
                    rc = MqttMsgPacketHeaderQueue_Write(&client->ackQueue,
                    (client->recvPacketHeader.qos == MQTT_QOS_1) ?
                        MQTT_PACKET_TYPE_PUBLISH_ACK :
                        MQTT_PACKET_TYPE_PUBLISH_REC,
                    client->recvPacketHeader.qos,
                    client->recvPacketHeader.id);
                    break;
                }
            } else if (client->recvPacketHeader.type == MQTT_PACKET_TYPE_PUBLISH_REC ||
                client->recvPacketHeader.type == MQTT_PACKET_TYPE_PUBLISH_REL) {
                /* Populate information needed for ack */
                rc = MqttMsgPacketHeaderQueue_Write(&client->ackQueue,
                        client->recvPacketHeader.type + 1,  /* next ack */
                        client->recvPacketHeader.qos,
                        client->recvPacketHeader.id);
                rc = MQTT_CODE_SUCCESS;
            } else {
                rc = MQTT_CODE_ERROR_STAT;
            }
            break;

        case MQTT_MSG_AUTH:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_WaitType: Invalid read state %d!", client->readState);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
        }
    } /* switch (client->readState) */
    if (rc == MQTT_CODE_CONTINUE)
    {
        return rc;
    }
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_WaitType: rc: %s (%d) read state %d",
        MqttClient_ReturnCodeToString(rc), rc, client->readState);
#endif
    if (client->usedPendResp) {
        client->usedPendResp->packetProcessing = 0;
        /* for 'any' packet, never reach done state */
        if (client->usedPendResp != &client->anyMsgHeader) {
            client->usedPendResp->packetDone = 1;
            client->usedPendResp->packet_ret = rc;
            /* The rc code is transferred to response list */
            rc = MQTT_CODE_SUCCESS;
        }
        client->usedPendResp = NULL;
    }
    /* reset read state */
    client->readState = MQTT_MSG_BEGIN;
    return rc;
}

/* This function won't take read/write lock, they are always unlocked when returned from this function */
static int MqttClient_WaitAck(int rc, MqttClient *client,
    void *packet_obj_send, int timeout_ms)
{
    MqttMsgHeader *msgHeader = (MqttMsgHeader *)packet_obj_send;
    do {
        MqttPublishResp *resp = &client->currrent_ack;
        int wait_any = msgHeader == NULL;
        int no_ack = !wait_any && msgHeader->packet_obj == NULL;
        int wait_ack = !wait_any && msgHeader->packet_obj != NULL;
        if (rc != MQTT_CODE_SUCCESS) {
            /* It's already failed or MQTT_CODE_CONTINUE when sending the packet */
            break;
        }
        if (no_ack) {
            /* publish qos0 and disconnect packet dot not need wait ack
             * For sent packet that dot not need wait ack,
             * don't wait `any` or `ack` message in blocking mode
             */
            break;
        }
        /* First acquire the receive lock */
        rc = MqttClient_RecvLock(client);
        if (rc != MQTT_CODE_SUCCESS) {
            break;
        }
        /* The recv lock is acquired */
        for (;;) {
            if (wait_ack && msgHeader->packetDone) {
                /* If we are waiting an ack and the ack is received or failed with error
                 * by other thread, then break the loop with packet_ret
                 */
                rc = msgHeader->packet_ret;
                break;
            }
            if (client->net.get_time_ms)
            {
                word32 now_ms = client->net.get_time_ms();
                /* Checking the timeout properly */
                rc = MqttClient_CheckTimeout(rc, MQTT_CODE_ERROR_TIMEOUT,
                    &client->time_socket_write_ms, timeout_ms, now_ms);
            }
            if (rc != MQTT_CODE_SUCCESS && rc != MQTT_CODE_CONTINUE) {
                break;
            }
            /* Sending ack */
            if (resp->header.packet.type == MQTT_PACKET_TYPE_RESERVED) {
                MqttMsgPacketHeader *new_resp = MqttMsgPacketHeaderQueue_Read(&client->ackQueue);
                if (new_resp != NULL) {
                    resp->header.packet = *new_resp;
                }
            }
            if (resp->header.packet.type != MQTT_PACKET_TYPE_RESERVED) {
                int write_rc = MQTT_CODE_SUCCESS;
                if (!resp->header.writeLocked) {
                    write_rc = MqttClient_SendLock(client, &resp->header);
                    if (write_rc != MQTT_CODE_SUCCESS) {
                        /* lock write failed */
                        rc = write_rc;
                        continue;
                    }
                }
                /* The send lock is acquired */
                write_rc = MqttClient_WriteEncoded(client, &resp->header,
                    resp->header.packet.type, MQTT_PACKET_TYPE_RESERVED,
                    resp->header.packet.id, NULL, MQTT_MSG_BEGIN);
                if (write_rc == MQTT_CODE_CONTINUE) {
                    continue;
                }
                if (write_rc == MQTT_CODE_SUCCESS) {
                    /* The ack packet write finished, try continue write next one */
                    XMEMSET(&resp->header.packet, 0, sizeof(resp->header.packet));
                    continue;
                }
                /* faltal error, assign to rc for proper error handling */
                rc = write_rc;
                continue;
            }
            /** Make sure write lock unlocked before MqttClient_WaitType,
             *  as we may receiving a large chunk of data in MqttClient_WaitType that
             *  consumes a lot of time
             */
            if (resp->header.writeLocked) {
                XMEMSET(&resp->header.packet, 0, sizeof(resp->header.packet));
                MqttClient_SendUnlock(client, &resp->header);
            }
            rc = MqttClient_WaitType(client, timeout_ms);
            if (wait_any) {
                if (client->useNonBlockMode) {
                    /* Non blocking mode, break to continue the event loop */
                } else {
                    /* Only receive a single message for wait_any in blocking mode */
                    /* Ping should send by other thead that not `wait_any` */
                }
                break;
            } else if (wait_ack) {
                /* It's wait ack, need check if the ack is received again, so continue */
            } else {
                /* Impossible state */
                rc  = MQTT_CODE_ERROR_STAT;
            }
        }
        /* make sure unlock write before return from this function */
        if (resp->header.writeLocked) {
            XMEMSET(&resp->header.packet, 0, sizeof(resp->header.packet));
            MqttClient_SendUnlock(client, &resp->header);
        }
        /* unlock read */
        MqttClient_RecvUnlock(client);
    } while (0);

    if (rc == MQTT_CODE_CONTINUE) {
        return rc;
    }

    if (msgHeader != NULL) {
        /* reset write state for publish_qos0 or wait ack */
        msgHeader->writeState = MQTT_MSG_BEGIN;
        if (msgHeader->inRespList) {
            MqttClient_RespList_Remove(client, msgHeader);
        }
    }
    return rc;
}

/* Public Functions */
int MqttClient_Init(MqttClient *client,
    void *ctx,
    MqttClientCb ctx_init_cb,
    MqttMsgCb msg_cb,
    byte* tx_buf, int tx_buf_len,
    byte* rx_buf, int rx_buf_len,
    int cmd_timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;

    /* Check arguments */
    if (client == NULL || ctx_init_cb == NULL ||
        tx_buf == NULL || tx_buf_len <= 0 ||
        rx_buf == NULL || rx_buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
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

    client->ctx = ctx;
#ifdef WOLFMQTT_NONBLOCK
    client->useNonBlockMode = 1;
#else
    client->useNonBlockMode = 0;
#endif

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
#endif

    if (rc == 0) {
        /* Initialize client with ctx */
        rc = ctx_init_cb(client);
    }

    if (rc == 0) {
        /* Init socket */
        rc = MqttSocket_Init(client);
    }

    if(rc == 0) {
        MqttClient_Resp_Init(&client->anyMsgHeader, 0, 0, &client->msg_header);
    }
    client->ackQueue.size = 16;
    client->ackQueue.data = malloc(client->ackQueue.size * sizeof(client->ackQueue.data[0]));

    if (rc != 0) {
        /* Cleanup if init failed */
        MqttClient_DeInit(client);
    }

    return rc;
}

void MqttClient_DeInit(MqttClient *client)
{
    if (client != NULL) {
        /* Cleanup network */
        if (client->net.deinit != NULL) {
            client->net.deinit(client);
        }

#ifdef WOLFMQTT_MULTITHREAD
        (void)wm_SemFree(&client->lockSend);
        (void)wm_SemFree(&client->lockRecv);
        (void)wm_SemFree(&client->lockClient);
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
        return MQTT_CODE_ERROR_BAD_ARG;

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
        return MQTT_CODE_ERROR_BAD_ARG;

    client->property_cb = propCb;
    client->property_ctx = ctx;

    return MQTT_CODE_SUCCESS;
}
#endif

int MqttClient_Connect(MqttClient *client, MqttConnect *mc_connect)
{
    int rc;
    MqttMsgState next_stat = MQTT_MSG_WAIT;

    /* Validate required arguments */
    if (client == NULL || mc_connect == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
#ifdef WOLFMQTT_V5
    /* Enhanced authentication */
    if (client->enable_eauth == 1) {
        next_stat = MQTT_MSG_AUTH;
    }
#endif
    /* Send connect packet */
    rc = MqttClient_WriteEncoded(client, &mc_connect->header,
            MQTT_PACKET_TYPE_CONNECT, MQTT_PACKET_TYPE_CONNECT_ACK,
            0, &mc_connect->ack, next_stat);
#ifdef WOLFMQTT_V5
    /* Enhanced authentication */
    if (rc == MQTT_CODE_SUCCESS &&
        mc_connect->header.protocol_level > MQTT_CONNECT_PROTOCOL_LEVEL_4 &&
            mc_connect->header.writeState == MQTT_MSG_AUTH)
    {
        MqttAuth *p_auth = &mc_connect->auth;
        if (p_auth->header.writeState == MQTT_MSG_BEGIN) {
            MqttProp* prop, *conn_prop;
            /* Find the AUTH property in the connect structure */
            for (conn_prop = mc_connect->header.props;
                (conn_prop != NULL) && (conn_prop->type != MQTT_PROP_AUTH_METHOD);
                conn_prop = conn_prop->next) {
            }
            if (conn_prop == NULL) {
                rc = MQTT_CODE_ERROR_BAD_ARG;
            } else {
                /* Set the authentication reason */
                p_auth->reason_code = MQTT_REASON_CONT_AUTH;

                /* Use the same authentication method property from connect */
                prop = MqttProps_Add(&p_auth->header.props);
                prop->type = MQTT_PROP_AUTH_METHOD;
                prop->data_str.str = conn_prop->data_str.str;
                prop->data_str.len = conn_prop->data_str.len;
            }
        }

        /* Send the AUTH packet may result MQTT_CODE_CONTINUE in blocking mode because of waiting ack */
        rc = MqttClient_Auth(client, p_auth);
        if (rc == MQTT_CODE_CONTINUE)
            return rc;

        MqttClient_PropsFree(p_auth->header.props);
        mc_connect->header.writeState = MQTT_MSG_WAIT;
    }
#endif /* WOLFMQTT_V5 */
    /* Wait for connect ack packet */
    return MqttClient_WaitAck(rc, client, mc_connect, client->cmd_timeout_ms);
}

static int MqttClient_Publish_ReadPayload(MqttClient* client,
    MqttPublish* publish, int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    byte msg_done = 0;
    byte received_chunk = 0;

    /* Handle packet callback and read remaining payload */
    for (;;) {
        int msg_len;
        word32 received_len = publish->buffer_pos + publish->buffer_len;
        if (received_len > publish->total_len) {
            rc = MQTT_CODE_ERROR_MALFORMED_DATA;
            break;
        }

        /* Determine if message is done */
        if (received_len == publish->total_len) {
            msg_done = 1;
        }

        /* Issue callback for new message (first time only) */
        if (client->msg_cb) {
            /* if using the temp publish message buffer,
                then populate message context with client context */
            if (publish->ctx == NULL && &client->msg.publish == publish) {
                publish->ctx = client->ctx;
            }
            rc = client->msg_cb(client, publish, publish->buffer_new,
                                msg_done);
            /* May be MQTT_CODE_CONTINUE, so break it and try next time */
            if (rc != MQTT_CODE_SUCCESS) {
                break;
            }
        }
        /**The buffer is either consumed by msg_cb or dropped.
         * add last length to position and reset len
         */
        publish->buffer_pos += publish->buffer_len;
        publish->buffer_len = 0;
        if (publish->buffer_new) {
            publish->buffer_new = 0;
            /* Reset topic name since valid on new message only */
            publish->topic_name = NULL;
            publish->topic_name_len = 0;
        }
        if (msg_done) {
            break;
        }

        if (received_chunk && client->useNonBlockMode) {
            rc = MQTT_CODE_CONTINUE; /* mark continue for event loop */
            break;
        }

        if (rc == MQTT_CODE_SUCCESS) {
            /* Read payload */
            msg_len = publish->total_len - received_len;
            if (msg_len > client->rx_buf_len) {
                msg_len = client->rx_buf_len;
            }

            /* make sure there is something to read */
            rc = MqttSocket_Read(client, client->rx_buf, msg_len,
                    timeout_ms);
            if (rc >= 0) {
                /* Update message */
                publish->buffer = client->rx_buf;
                publish->buffer_len = rc;
                received_chunk = 1;
                rc = MQTT_CODE_SUCCESS; /* mark success */
            } else {
                break;
            }
        } else {
            break;
        }
    }

    return rc;
}

static int MqttClient_Publish_WritePayload(MqttClient *client,
    MqttPublish *publish)
{
    int rc = MQTT_CODE_SUCCESS;

    if (client == NULL || publish == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

    if (publish->pub_cb) {
        word32 tmp_len = publish->buffer_len;

        do {
            /* Use the callback to get payload */
            if ((client->write.len = publish->pub_cb(publish)) < 0) {
                return MQTT_CODE_ERROR_CALLBACK;
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

        } while (publish->buffer_pos < publish->total_len);
    }
    else if (publish->buffer_pos < publish->total_len) {
        for (;;) {
            publish->intBuf_pos += publish->intBuf_len;
            publish->intBuf_len = 0;

            /* Check if we are done sending publish message */
            if (publish->intBuf_pos == publish->buffer_len) {
                break;
            } else if (publish->intBuf_pos > publish->buffer_len) {
                return MQTT_CODE_ERROR_MALFORMED_DATA;
            }

            /* Build packet payload to send */
            client->write.len = (publish->buffer_len - publish->intBuf_pos);
            if (client->write.len > client->tx_buf_len) {
                client->write.len = client->tx_buf_len;
            }
            XMEMCPY(client->tx_buf, &publish->buffer[publish->intBuf_pos],
                client->write.len);
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            if (rc < 0) {
                return rc;
            }
            if (rc != client->write.len) {
                return MQTT_CODE_ERROR_NETWORK;
            }
            publish->intBuf_len = rc;
            publish->buffer_pos += rc;
        }
        /* If transferring more chunks */
        if (publish->buffer_pos < publish->total_len) {
            rc = MQTT_CODE_PUB_CONTINUE;
        }
    }
    return rc;
}

int MqttClient_Publish(MqttClient *client, MqttPublish *publish)
{
    return MqttClient_Publish_ex(client, publish, NULL);
}

int MqttClient_Publish_ex(MqttClient *client, MqttPublish *publish,
                            MqttPublishCb pubCb)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttPacketType resp_type;
    MqttPublishResp *resp;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_V5
    /* Validate publish request against server properties */
    if ((publish->header.packet.qos > client->max_qos) ||
        ((publish->retain == 1) && (client->retain_avail == 0)))
    {
        return MQTT_CODE_ERROR_SERVER_PROP;
    }
#endif
    if (publish->header.packet.qos > MQTT_QOS_0) {
        resp_type = (publish->header.packet.qos == MQTT_QOS_1) ?
            MQTT_PACKET_TYPE_PUBLISH_ACK :
            MQTT_PACKET_TYPE_PUBLISH_COMP;
        resp = &publish->resp;

    } else {
        resp_type = MQTT_PACKET_TYPE_RESERVED;
        resp = NULL;
    }
    publish->pub_cb = pubCb;
    /* Send the publish packet */
    rc = MqttClient_WriteEncoded(client, &publish->header,
            MQTT_PACKET_TYPE_PUBLISH, resp_type,
            publish->header.packet.id, resp, MQTT_MSG_WAIT);
    /* Wait for publish response packet */
    return MqttClient_WaitAck(rc, client, publish, client->cmd_timeout_ms);
}

int MqttClient_Subscribe(MqttClient *client, MqttSubscribe *subscribe)
{
    int rc, i;
    MqttTopic* topic;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    /* Send subscribe packet */
    rc = MqttClient_WriteEncoded(client, &subscribe->header,
        MQTT_PACKET_TYPE_SUBSCRIBE, MQTT_PACKET_TYPE_SUBSCRIBE_ACK,
        subscribe->header.packet.id, &subscribe->ack, MQTT_MSG_WAIT);
    /* Wait for subscribe ack packet */
    rc = MqttClient_WaitAck(rc, client, subscribe, client->cmd_timeout_ms);

    /* Populate return codes */
    if (rc == MQTT_CODE_SUCCESS) {
        for (i = 0; i < subscribe->topic_count && i < MAX_MQTT_TOPICS; i++) {
            topic = &subscribe->topics[i];
            topic->return_code = subscribe->ack.return_codes[i];
        }
    }

    return rc;
}

int MqttClient_Unsubscribe(MqttClient *client, MqttUnsubscribe *unsubscribe)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    /* Send unsubscribe packet */
    rc = MqttClient_WriteEncoded(client, &unsubscribe->header,
        MQTT_PACKET_TYPE_UNSUBSCRIBE, MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK,
        unsubscribe->header.packet.id, &unsubscribe->ack, MQTT_MSG_WAIT);
    /* Wait for unsubscribe ack packet */
    return MqttClient_WaitAck(rc, client, unsubscribe, client->cmd_timeout_ms);
}

int MqttClient_Ping_ex(MqttClient *client, MqttPing* ping)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || ping == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    rc = MqttClient_WriteEncoded(client, &ping->header,
        MQTT_PACKET_TYPE_PING_REQ, MQTT_PACKET_TYPE_PING_RESP, 0,
        ping, MQTT_MSG_WAIT);
    /* Wait for ping resp packet */
    return MqttClient_WaitAck(rc, client, ping, client->cmd_timeout_ms);
}

int MqttClient_Ping(MqttClient *client)
{
    return MqttClient_Ping_ex(client, &client->msg.ping);
}

int MqttClient_Disconnect(MqttClient *client)
{
    return MqttClient_Disconnect_ex(client, &client->msg.disconnect);
}

int MqttClient_Disconnect_ex(MqttClient *client, MqttDisconnect *disconnect)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || disconnect == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    /* Send disconnect packet */
    rc = MqttClient_WriteEncoded(client, &disconnect->header,
        MQTT_PACKET_TYPE_DISCONNECT, MQTT_PACKET_TYPE_RESERVED, 0, NULL, MQTT_MSG_WAIT);
    /* No response for MQTT disconnect packet */
    return MqttClient_WaitAck(rc, client, disconnect, client->cmd_timeout_ms);
}

#ifdef WOLFMQTT_V5
int MqttClient_Auth(MqttClient *client, MqttAuth* auth)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    /* Send authentication packet */
    rc = MqttClient_WriteEncoded(client, &auth->header,
        MQTT_PACKET_TYPE_AUTH, MQTT_PACKET_TYPE_AUTH,
        0, auth, MQTT_MSG_WAIT);
    /* Wait for auth packet */
    return MqttClient_WaitAck(rc, client, auth, client->cmd_timeout_ms);
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
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    (void)msg;
    return MqttClient_WaitAck(MQTT_CODE_SUCCESS, client, NULL, timeout_ms);
}
int MqttClient_WaitMessage(MqttClient *client, int timeout_ms)
{
    return MqttClient_WaitMessage_ex(client, NULL, timeout_ms);
}

int MqttClient_NetConnect(MqttClient *client, const char* host,
    word16 port, int timeout_ms, int use_tls, MqttTlsCb cb)
{
    return MqttSocket_Connect(client, host, port, timeout_ms, use_tls, cb);
}

int MqttClient_NetDisconnect(MqttClient *client)
{
    int rc = MQTT_CODE_SUCCESS;
    client->flags &= ~MQTT_CLIENT_FLAG_IS_CONNECTED;
    MqttClient_RespListClear(client);
#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockSend);
    if (rc < 0) {
        return rc;
    }
#endif
    rc = MqttSocket_Disconnect(client);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockSend);
#endif
    return rc;
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
        case MQTT_CODE_ERROR_DNS_RESOLVE:
            return "Error (DNS Resolve Failed)";
        case MQTT_CODE_ERROR_ROUTE_TO_HOST:
            return "Error (No route to host)";
    }
    return "Unknown";
}
#endif /* !WOLFMQTT_NO_ERROR_STRINGS */

#ifdef WOLFMQTT_SN

/* Private functions */
static int SN_Client_HandlePacket(MqttClient* client, SN_MsgType packet_type,
    void* packet_obj, int timeout)
{
    int rc = MQTT_CODE_SUCCESS;
    word16 packet_id = 0;

    (void)timeout;

    switch ((int)packet_type)
    {
        case SN_MSG_TYPE_GWINFO:
        {
            SN_GwInfo info, *p_info = &info;
            if (packet_obj) {
                p_info = (SN_GwInfo*)packet_obj;
            }
            else {
                XMEMSET(p_info, 0, sizeof(SN_GwInfo));
            }

            rc = SN_Decode_GWInfo(client->rx_buf, client->packet.buf_len,
                    p_info);
            if (rc <= 0) {
                return rc;
            }
            break;
        }
        case SN_MSG_TYPE_CONNACK:
        {
            /* Decode connect ack */
            SN_ConnectAck connect_ack, *p_connect_ack = &connect_ack;
            if (packet_obj) {
                p_connect_ack = (SN_ConnectAck*)packet_obj;
            }
            else {
                XMEMSET(p_connect_ack, 0, sizeof(SN_ConnectAck));
            }
            p_connect_ack->return_code =
                    client->rx_buf[client->packet.buf_len-1];

            break;
        }
        case SN_MSG_TYPE_WILLTOPICREQ:
        {
            rc = SN_Decode_WillTopicReq(client->rx_buf, client->packet.buf_len);
            break;
        }
        case SN_MSG_TYPE_WILLMSGREQ:
        {
            rc = SN_Decode_WillMsgReq(client->rx_buf, client->packet.buf_len);
            break;
        }
        case SN_MSG_TYPE_REGISTER:
        {
            /* Decode register */
            SN_Register reg_s;

            XMEMSET(&reg_s, 0, sizeof(SN_Register));

            rc = SN_Decode_Register(client->rx_buf, client->packet.buf_len,
                    &reg_s);

            if (rc > 0) {
                /* Initialize the regack */
                reg_s.regack.packet_id = reg_s.packet_id;
                reg_s.regack.topicId = reg_s.topicId;
                reg_s.regack.return_code = SN_RC_NOTSUPPORTED;

                /* Call the register callback to allow app to
                   handle new topic ID assignment. */
                if (client->reg_cb != NULL) {
                     rc = client->reg_cb(reg_s.topicId,
                            reg_s.topicName, client->reg_ctx);
                     /* Set the regack return code */
                     reg_s.regack.return_code = (rc >= 0) ? SN_RC_ACCEPTED :
                             SN_RC_INVTOPICNAME;
                }

            #ifdef WOLFMQTT_MULTITHREAD
                /* Lock send socket mutex */
                rc = wm_SemLock(&client->lockSend);
                if (rc != 0) {
                    return rc;
                }
            #endif

                /* Encode the register acknowledgment */
                rc = SN_Encode_RegAck(client->tx_buf, client->tx_buf_len,
                        &reg_s.regack);
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d",
                    rc, SN_Packet_TypeDesc(SN_MSG_TYPE_REGACK),
                    SN_MSG_TYPE_REGACK, reg_s.packet_id);
            #endif
                if (rc <= 0) {
                #ifdef WOLFMQTT_MULTITHREAD
                    wm_SemUnlock(&client->lockSend);
                #endif
                    return rc;
                }
                client->write.len = rc;

                /* Send regack packet */
                rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                if (rc != client->write.len) { return rc; }
            }

            break;
        }
        case SN_MSG_TYPE_REGACK:
        {
            /* Decode register ack */
            SN_RegAck regack_s, *p_regack = &regack_s;
            if (packet_obj) {
                p_regack = (SN_RegAck*)packet_obj;
            }
            else {
                XMEMSET(p_regack, 0, sizeof(SN_RegAck));
            }

            rc = SN_Decode_RegAck(client->rx_buf, client->packet.buf_len,
                    p_regack);
            if (rc > 0) {
                packet_id = p_regack->packet_id;
            }

            break;
        }
        case SN_MSG_TYPE_PUBLISH:
        {
            SN_Publish pub, *p_pub = &pub;
            if (packet_obj) {
                p_pub = (SN_Publish*)packet_obj;
            }
            else {
                XMEMSET(p_pub, 0, sizeof(SN_Publish));
            }

            /* Decode publish message */
            rc = SN_Decode_Publish(client->rx_buf, client->packet.buf_len,
                   p_pub);
            if (rc <= 0) {
                return rc;
            }

            /* Issue callback for new message */
            if (client->msg_cb) {
                /* if using the temp publish message buffer,
                   then populate message context with client context */
                if (&client->msgSN.publish == p_pub)
                    p_pub->ctx = client->ctx;
                rc = client->msg_cb(client, (MqttMessage*)p_pub, 1, 1);
                if (rc != MQTT_CODE_SUCCESS) {
                    return rc;
                };
            }

            /* Handle Qos */
            if (p_pub->qos > MQTT_QOS_0) {
                SN_MsgType type;

                packet_id = p_pub->packet_id;

                /* Determine packet type to write */
                type = (p_pub->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBREC;
                p_pub->resp.packet_id = packet_id;

            #ifdef WOLFMQTT_MULTITHREAD
                /* Lock send socket mutex */
                rc = wm_SemLock(&client->lockSend);
                if (rc != 0) {
                    return rc;
                }
            #endif

                /* Encode publish response */
                rc = SN_Encode_PublishResp(client->tx_buf,
                                    client->tx_buf_len, type, &p_pub->resp);
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d,"
                        " QoS %d",
                    rc, SN_Packet_TypeDesc(type), type, packet_id,
                    p_pub->qos);
            #endif
                if (rc <= 0) {
                #ifdef WOLFMQTT_MULTITHREAD
                    wm_SemUnlock(&client->lockSend);
                #endif
                    return rc;
                }
                client->write.len = rc;

                /* Send packet */
                rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
            }
            break;
        }
        case SN_MSG_TYPE_PUBACK:
        case SN_MSG_TYPE_PUBCOMP:
        case SN_MSG_TYPE_PUBREC:
        case SN_MSG_TYPE_PUBREL:
        {
            SN_PublishResp publish_resp;
            XMEMSET(&publish_resp, 0, sizeof(SN_PublishResp));

            /* Decode publish response message */
            rc = SN_Decode_PublishResp(client->rx_buf, client->packet.buf_len,
                packet_type, &publish_resp);
            if (rc <= 0) {
                return rc;
            }
            packet_id = publish_resp.packet_id;

            /* If Qos then send response */
            if (packet_type == SN_MSG_TYPE_PUBREC ||
                packet_type == SN_MSG_TYPE_PUBREL) {

                byte resp_type = (packet_type == SN_MSG_TYPE_PUBREC) ?
                        SN_MSG_TYPE_PUBREL : SN_MSG_TYPE_PUBCOMP;

            #ifdef WOLFMQTT_MULTITHREAD
                /* Lock send socket mutex */
                rc = wm_SemLock(&client->lockSend);
                if (rc != 0) {
                    return rc;
                }
            #endif

                /* Encode publish response */
                publish_resp.packet_id = packet_id;
                rc = SN_Encode_PublishResp(client->tx_buf,
                    client->tx_buf_len, resp_type, &publish_resp);
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d",
                    rc, MqttPacket_TypeDesc(resp_type), resp_type, packet_id);
            #endif
                if (rc <= 0) {
                #ifdef WOLFMQTT_MULTITHREAD
                    wm_SemUnlock(&client->lockSend);
                #endif
                    return rc;
                }
                client->write.len = rc;

                /* Send packet */
                rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
            }
            break;
        }
        case SN_MSG_TYPE_SUBACK:
        {
            /* Decode subscribe ack */
            SN_SubAck subscribe_ack, *p_subscribe_ack = &subscribe_ack;
            if (packet_obj) {
                p_subscribe_ack = (SN_SubAck*)packet_obj;
            }
            else {
                XMEMSET(p_subscribe_ack, 0, sizeof(SN_SubAck));
            }

            rc = SN_Decode_SubscribeAck(client->rx_buf, client->packet.buf_len,
                    p_subscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            packet_id = p_subscribe_ack->packet_id;

            break;
        }
        case SN_MSG_TYPE_UNSUBACK:
        {
            /* Decode unsubscribe ack */
            SN_UnsubscribeAck unsubscribe_ack,
                              *p_unsubscribe_ack = &unsubscribe_ack;
            if (packet_obj) {
                p_unsubscribe_ack = (SN_UnsubscribeAck*)packet_obj;
            }
            else {
                XMEMSET(p_unsubscribe_ack, 0, sizeof(SN_UnsubscribeAck));
            }
            rc = SN_Decode_UnsubscribeAck(client->rx_buf,
                    client->packet.buf_len, p_unsubscribe_ack);
            if (rc <= 0) {
                return rc;
            }
            packet_id = p_unsubscribe_ack->packet_id;

            break;
        }
        case SN_MSG_TYPE_PING_RESP:
        {
            /* Decode ping */
            rc = SN_Decode_Ping(client->rx_buf, client->packet.buf_len);
            break;
        }
        case SN_MSG_TYPE_PING_REQ:
        {
            /* Decode ping */
            rc = SN_Decode_Ping(client->rx_buf, client->packet.buf_len);
            if (rc <= 0) { return rc; }

        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif

            /* Encode the ping packet as a response */
            rc = SN_Encode_Ping(client->tx_buf, client->tx_buf_len, NULL,
                    SN_MSG_TYPE_PING_RESP);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PING_RESP),
                SN_MSG_TYPE_PING_RESP);
        #endif
            if (rc <= 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                return rc;
            }
            client->write.len = rc;

            /* Send ping resp packet */
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            if (rc != client->write.len) { return rc; }

            break;
        }
        case SN_MSG_TYPE_WILLTOPICRESP:
        {
            /* Decode Will Topic Response */
            SN_WillTopicResp resp_s, *resp = &resp_s;
            if (packet_obj) {
                resp = (SN_WillTopicResp*)packet_obj;
            }
            else {
                XMEMSET(resp, 0, sizeof(SN_WillTopicResp));
            }
            rc = SN_Decode_WillTopicResponse(client->rx_buf,
                    client->packet.buf_len, &resp->return_code);
            break;
        }
        case SN_MSG_TYPE_WILLMSGRESP:
        {
            /* Decode Will Message Response */
            SN_WillMsgResp resp_s, *resp = &resp_s;
            if (packet_obj) {
                resp = (SN_WillMsgResp*)packet_obj;
            }
            else {
                XMEMSET(resp, 0, sizeof(SN_WillMsgResp));
            }
            rc = SN_Decode_WillMsgResponse(client->rx_buf,
                    client->packet.buf_len, &resp->return_code);
            break;
        }
        case SN_MSG_TYPE_DISCONNECT:
        {
            /* Decode Disconnect */
            rc = SN_Decode_Disconnect(client->rx_buf, client->packet.buf_len);
            break;
        }

        default:
        {
            /* Other types are server side only, ignore */
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_HandlePacket: Invalid client packet type %u!",
                packet_type);
        #endif
            break;
        }
    } /* switch (packet_type) */

    (void)packet_id;

    return rc;
}

static int SN_Client_WaitType(MqttClient *client, void* packet_obj,
    byte wait_type, word16 wait_packet_id, int timeout_ms)
{
    int rc;
    word16 packet_id;
    SN_MsgType packet_type;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp *pendResp;
#endif
    MqttMsgStat* mms_stat;
    int waitMatchFound;
    void* use_packet_obj = NULL;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* all packet type structures must have MqttMsgStat at top */
    mms_stat = (MqttMsgStat*)packet_obj;

wait_again:

    /* initialize variables */
    packet_id = 0;
    packet_type = SN_MSG_TYPE_RESERVED;
#ifdef WOLFMQTT_MULTITHREAD
    pendResp = NULL;
#endif
    waitMatchFound = 0;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("SN_Client_WaitType: Type %s (%d), ID %d",
            SN_Packet_TypeDesc((SN_MsgType)wait_type),
                wait_type, wait_packet_id);
#endif

    switch (mms_stat->read)
    {
        case MQTT_MSG_BEGIN:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock recv socket mutex */
            rc = wm_SemLock(&client->lockRecv);
            if (rc != 0) {
                PRINTF("SN_Client_WaitType recv lock error");
                return rc;
            }
            mms_stat->isReadLocked = 1;
        #endif

            /* reset the packet state used by SN_Packet_Read */
            client->packet.stat = MQTT_PK_BEGIN;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            /* Check to see if packet type and id have already completed */
            pendResp = NULL;
            rc = wm_SemLock(&client->lockClient);
            if (rc == 0) {
                if (MqttClient_RespList_Find(client, (MqttPacketType)wait_type,
                        wait_packet_id, &pendResp)) {
                    if (pendResp->packetDone) {
                        /* pending response is already done, so return */
                        rc = pendResp->packet_ret;
                    #ifdef WOLFMQTT_DEBUG_CLIENT
                        PRINTF("PendResp already Done %p: Rc %d", pendResp, rc);
                    #endif
                        MqttClient_RespList_Remove(client, pendResp);
                        wm_SemUnlock(&client->lockClient);
                        wm_SemUnlock(&client->lockRecv);
                        return rc;
                    }
                }
                wm_SemUnlock(&client->lockClient);
            }
            else {
                break; /* error */
            }
        #endif /* WOLFMQTT_MULTITHREAD */

            mms_stat->read = MQTT_MSG_WAIT;

            /* Wait for packet */
            rc = SN_Packet_Read(client, client->rx_buf, client->rx_buf_len,
                    timeout_ms);
            if (rc <= 0) {
                break;
            }

            client->packet.buf_len = rc;

            /* Decode header */
            rc = SN_Decode_Header(client->rx_buf, client->packet.buf_len,
                    &packet_type, &packet_id);
            if (rc < 0) {
                break;
            }

        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Read Packet: Len %d, Type %d, ID %d",
                client->packet.buf_len, packet_type, packet_id);
        #endif

            mms_stat->read = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        case MQTT_MSG_PAYLOAD:
        {
            SN_MsgType use_packet_type;

            /* Determine if we received data for this request */
            if ((wait_type == SN_MSG_TYPE_ANY || wait_type == packet_type) &&
                (wait_packet_id == 0 || wait_packet_id == packet_id))
            {
                use_packet_obj = packet_obj;
                waitMatchFound = 1;
            }
            else {
                /* use generic packet object */
                use_packet_obj = &client->msgSN;
            }
            use_packet_type = packet_type;

        #ifdef WOLFMQTT_MULTITHREAD
            /* Check to see if we have a pending response for this packet */
            pendResp = NULL;
            rc = wm_SemLock(&client->lockClient);
            if (rc == 0) {
                if (MqttClient_RespList_Find(client,
                        (MqttPacketType)packet_type, packet_id, &pendResp)) {
                    /* we found packet match this incoming read packet */
                    pendResp->packetProcessing = 1;
                    if (pendResp->packet_obj != packet_obj) {
                        use_packet_obj = pendResp->packet_obj;
                        use_packet_type = (SN_MsgType)pendResp->packet_type;
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

            rc = SN_Client_HandlePacket(client, use_packet_type, use_packet_obj,
                    timeout_ms);

        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                break;
            }
        #endif

            /* handle success case */
            if (rc >= 0) {
                rc = MQTT_CODE_SUCCESS;
            }

        #ifdef WOLFMQTT_MULTITHREAD
            if (pendResp) {
                /* Mark pending response entry done */
                if (wm_SemLock(&client->lockClient) == 0) {
                    pendResp->packetDone = 1;
                    pendResp->packet_ret = rc;
                #ifdef WOLFMQTT_DEBUG_CLIENT
                    PRINTF("PendResp Marked Done %p", pendResp);
                #endif
                    pendResp = NULL;
                    wm_SemUnlock(&client->lockClient);
                }
            }
        #endif /* WOLFMQTT_MULTITHREAD */
            break;
        }

        case MQTT_MSG_ACK: /* ack handled in SN_Client_HandlePacket */
        case MQTT_MSG_AUTH:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_WaitType: Invalid state %d!", mms_stat->read);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
        }
    } /* switch (msg->stat) */

#ifdef WOLFMQTT_DEBUG_CLIENT
    if (rc != MQTT_CODE_CONTINUE) {
        PRINTF("SN_Client_WaitType: rc %d, state %d", rc, mms_stat->read);
    }
#endif

    if (mms_stat->read == MQTT_MSG_WAIT || rc != MQTT_CODE_CONTINUE) {
        /* reset state */
        mms_stat->read = MQTT_MSG_BEGIN;

    #ifdef WOLFMQTT_MULTITHREAD
        if (mms_stat->isReadLocked) {
            mms_stat->isReadLocked = 0;
            wm_SemUnlock(&client->lockRecv);
        }
    #endif
    }
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE) {
        return rc;
    }
#endif

    /* Clear shared union for next call */
    if ((MqttObject*)use_packet_obj == &client->msg) {
        /* reset the members, but not the stat */
        XMEMSET(((byte*)&client->msg.stat) + sizeof(client->msg.stat), 0,
            sizeof(client->msg)-sizeof(client->msg.stat));
    }

    if (rc < 0) {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("SN_Client_WaitType: Failure: %s (%d)",
            MqttClient_ReturnCodeToString(rc), rc);
    #endif
        return rc;
    }

    if (!waitMatchFound) {
        /* if we get here, then the we are still waiting for a packet */
        goto wait_again;
    }

    return rc;
}

/* Public Functions */

int SN_Client_SetRegisterCallback(MqttClient *client,
        SN_ClientRegisterCb regCb,
        void* ctx)
{
    int rc = MQTT_CODE_SUCCESS;

    if (client == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
#endif

        client->reg_cb = regCb;
        client->reg_ctx = ctx;

#ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockClient);
    }
#endif

    return rc;
}

int SN_Client_SearchGW(MqttClient *client, SN_SearchGw *search)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || search == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (search->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the search packet */
        rc = SN_Encode_SearchGW(client->tx_buf, client->tx_buf_len,
                search->radius);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_SEARCHGW),
            SN_MSG_TYPE_SEARCHGW);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_GWINFO, 0,
                    &search->pendResp, &search->gwInfo);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send search for gateway packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &search->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
        search->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for gateway info packet */
    rc = SN_Client_WaitType(client, &search->gwInfo, SN_MSG_TYPE_GWINFO, 0,
        client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &search->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    search->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

static int SN_WillTopic(MqttClient *client, SN_Will *will)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
        /* inform other threads of expected response */
        rc = MqttClient_RespList_Add(client,
                (MqttPacketType)SN_MSG_TYPE_WILLTOPICREQ, 0,
                &will->pendResp, &will->resp.topicResp);
        wm_SemUnlock(&client->lockClient);
    }
    if (rc != 0) {
        return rc; /* Error locking client */
    }
#endif

    /* Wait for Will Topic Request packet */
    rc = SN_Client_WaitType(client, will,
            SN_MSG_TYPE_WILLTOPICREQ, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &will->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif
    if (rc == 0) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode Will Topic */
        rc = SN_Encode_WillTopic(client->tx_buf, client->tx_buf_len,
                will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPIC),
            SN_MSG_TYPE_WILLTOPIC);
    #endif
        if (rc > 0) {
            /* Send Will Topic packet */
            client->write.len = rc;
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            if (rc == client->write.len) {
                rc = 0;
            }
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
    }

    return rc;
}

static int SN_WillMessage(MqttClient *client, SN_Will *will)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_MULTITHREAD
    rc = wm_SemLock(&client->lockClient);
    if (rc == 0) {
        /* inform other threads of expected response */
        rc = MqttClient_RespList_Add(client,
                (MqttPacketType)SN_MSG_TYPE_WILLMSGREQ, 0,
                &will->pendResp, &will->resp.msgResp);
        wm_SemUnlock(&client->lockClient);
    }
    if (rc != 0) {
        return rc; /* Error locking client */
    }
#endif

    /* Wait for Will Message Request */
    rc = SN_Client_WaitType(client, &will->resp.msgResp,
            SN_MSG_TYPE_WILLMSGREQ, 0, client->cmd_timeout_ms);

#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif

#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &will->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    if (rc == 0) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif
        /* Encode Will Message */
        rc = SN_Encode_WillMsg(client->tx_buf,
            client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLMSG),
            SN_MSG_TYPE_WILLMSG);
    #endif
        if (rc > 0) {
            /* Send Will Topic packet */
            client->write.len = rc;
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
            if (rc == client->write.len) {
                rc = 0;
            }
        }
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
    }

    return rc;
}

int SN_Client_Connect(MqttClient *client, SN_Connect *mc_connect)
{
    int rc = 0;
    static byte will_done;

    /* Validate required arguments */
    if ((client == NULL) || (mc_connect == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (mc_connect->stat.write == MQTT_MSG_BEGIN) {

        will_done = 0;

    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

    /* Encode the connect packet */
        rc = SN_Encode_Connect(client->tx_buf, client->tx_buf_len, mc_connect);
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
        rc, SN_Packet_TypeDesc(SN_MSG_TYPE_CONNECT),
        SN_MSG_TYPE_CONNECT, 0, 0);
#endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_CONNACK, 0,
                    &mc_connect->pendResp, &mc_connect->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send connect packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
            return rc;
        }

        mc_connect->stat.write = MQTT_MSG_WAIT;
    }

    if ((mc_connect->enable_lwt == 1) && (will_done != 1)) {
        /* If the will is enabled, then the gateway requests the topic and
           message in separate packets. */
        rc = SN_WillTopic(client, &mc_connect->will);
        if (rc != 0) {
            return rc;
        }

        rc = SN_WillMessage(client, &mc_connect->will);
        if (rc != 0) {
            return rc;
        }
        will_done = 1;
    }

    /* Wait for connect ack packet */
    rc = SN_Client_WaitType(client, &mc_connect->ack,
            SN_MSG_TYPE_CONNACK, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
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

int SN_Client_WillTopicUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (will->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode Will Topic Update */
        rc = SN_Encode_WillTopicUpdate(client->tx_buf,
                client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPICUPD),
            SN_MSG_TYPE_WILLTOPICUPD);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_WILLTOPICRESP,
                    0, &will->pendResp, &will->resp.topicResp);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send Will Topic Update packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
        }
        will->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for Will Topic Update Response packet */
    rc = SN_Client_WaitType(client, &will->resp.topicResp,
            SN_MSG_TYPE_WILLTOPICRESP, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &will->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    will->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_WillMsgUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0;

    /* Validate required arguments */
    if ((client == NULL) || (will == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (will->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif
        /* Encode Will Message Update */
        rc = SN_Encode_WillMsgUpdate(client->tx_buf,
                client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPICUPD),
            SN_MSG_TYPE_WILLTOPICUPD);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_WILLMSGRESP,
                    0, &will->pendResp, &will->resp.msgResp);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send Will Message Update packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
        }
        will->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for Will Message Update Response packet */
    rc = SN_Client_WaitType(client, &will->resp.msgResp,
            SN_MSG_TYPE_WILLMSGRESP, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &will->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    will->stat.write = MQTT_MSG_BEGIN;

    return rc;

}

int SN_Client_Subscribe(MqttClient *client, SN_Subscribe *subscribe)
{
    int rc = -1;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (subscribe->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the subscribe packet */
        rc = SN_Encode_Subscribe(client->tx_buf, client->tx_buf_len,
                subscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), QoS %d",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_SUBSCRIBE),
            SN_MSG_TYPE_SUBSCRIBE, subscribe->qos);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_SUBACK, subscribe->packet_id,
                    &subscribe->pendResp, &subscribe->subAck);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send subscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &subscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        subscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for subscribe ack packet */
    rc = SN_Client_WaitType(client, &subscribe->subAck,
            SN_MSG_TYPE_SUBACK, subscribe->packet_id, client->cmd_timeout_ms);

#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &subscribe->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    subscribe->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Publish(MqttClient *client, SN_Publish *publish)
{
    int rc = MQTT_CODE_SUCCESS;
    SN_MsgType resp_type;

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    switch (publish->stat.write)
    {
        case MQTT_MSG_BEGIN:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif

            /* Encode the publish packet */
            rc = SN_Encode_Publish(client->tx_buf, client->tx_buf_len,
                    publish);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d,"
                    " QoS %d",
                rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PUBLISH),
                SN_MSG_TYPE_PUBLISH, publish->packet_id,
                publish->qos);
        #endif
            if (rc <= 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                return rc;
            }

            client->write.len = rc;
            publish->buffer_pos = 0;

        #ifdef WOLFMQTT_MULTITHREAD
            if ((publish->qos == MQTT_QOS_1) ||
                (publish->qos == MQTT_QOS_2)) {
                resp_type = (publish->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBCOMP;

                rc = wm_SemLock(&client->lockClient);
                if (rc == 0) {
                    /* inform other threads of expected response */
                    rc = MqttClient_RespList_Add(client,
                            (MqttPacketType)resp_type, publish->packet_id,
                            &publish->pendResp, &publish->resp);
                    wm_SemUnlock(&client->lockClient);
                }
                if (rc != 0) {
                    wm_SemUnlock(&client->lockSend);
                    return rc; /* Error locking client */
                }
            }
        #endif

            publish->stat.write = MQTT_MSG_HEADER;
        }
        FALL_THROUGH;

        case MQTT_MSG_HEADER:
        case MQTT_MSG_PAYLOAD:
        {
            /* Send packet and payload */
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE)
                return rc;
        #endif
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif

            if (rc < 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                if (wm_SemLock(&client->lockClient) == 0) {
                    MqttClient_RespList_Remove(client, &publish->pendResp);
                    wm_SemUnlock(&client->lockClient);
                }
            #endif
                return rc;
            }

            if (rc == client->write.len) {
                rc = MQTT_CODE_SUCCESS;
            }
            else {
                rc = -1;
            }

            /* if not expecting a reply, the reset state and exit */
            if ((publish->qos == MQTT_QOS_0) ||
                (publish->qos == MQTT_QOS_3)) {
                break;
            }

            publish->stat.write = MQTT_MSG_WAIT;
        }
        FALL_THROUGH;

        case MQTT_MSG_WAIT:
        {
            /* Handle QoS */
            if ((publish->qos == MQTT_QOS_1) ||
                (publish->qos == MQTT_QOS_2)) {

                /* Determine packet type to wait for */
                resp_type = (publish->qos == MQTT_QOS_1) ?
                        SN_MSG_TYPE_PUBACK :
                        SN_MSG_TYPE_PUBCOMP;

                /* Wait for publish response packet */
                rc = SN_Client_WaitType(client, &publish->resp,
                    resp_type, publish->packet_id, client->cmd_timeout_ms);
            #ifdef WOLFMQTT_NONBLOCK
                if (rc == MQTT_CODE_CONTINUE)
                    break;
            #endif
            #ifdef WOLFMQTT_MULTITHREAD
                if (wm_SemLock(&client->lockClient) == 0) {
                    MqttClient_RespList_Remove(client, &publish->pendResp);
                    wm_SemUnlock(&client->lockClient);
                }
            #endif

                publish->return_code = publish->resp.return_code;
            }

            break;
        }

        case MQTT_MSG_ACK:
        case MQTT_MSG_AUTH:
        default:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_Publish: Invalid state %d!",
                publish->stat.write);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
    } /* switch (publish->stat) */

    /* reset state */
#ifdef WOLFMQTT_NONBLOCK
    if (rc != MQTT_CODE_CONTINUE)
#endif
    {
        publish->stat.write = MQTT_MSG_BEGIN;
    }
    if (rc > 0) {
        rc = MQTT_CODE_SUCCESS;
    }

    return rc;
}

int SN_Client_Unsubscribe(MqttClient *client, SN_Unsubscribe *unsubscribe)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (unsubscribe->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the subscribe packet */
        rc = SN_Encode_Unsubscribe(client->tx_buf, client->tx_buf_len,
            unsubscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_UNSUBSCRIBE),
            SN_MSG_TYPE_UNSUBSCRIBE);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_UNSUBACK,
                    0, &unsubscribe->pendResp, &unsubscribe->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send unsubscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
        }
        unsubscribe->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for unsubscribe ack packet */
    rc = SN_Client_WaitType(client, &unsubscribe->ack,
            SN_MSG_TYPE_UNSUBACK, unsubscribe->packet_id,
            client->cmd_timeout_ms);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE)
            return rc;
    #endif
    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0) {
            MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
            wm_SemUnlock(&client->lockClient);
        }
    #endif

    /* reset state */
    unsubscribe->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Register(MqttClient *client, SN_Register *regist)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL || regist == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (regist->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the register packet */
        rc = SN_Encode_Register(client->tx_buf, client->tx_buf_len, regist);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_REGISTER),
            SN_MSG_TYPE_REGISTER);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_REGACK,
                    regist->packet_id, &regist->pendResp, &regist->regack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send register packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &regist->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        regist->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for register acknowledge packet */
    rc = SN_Client_WaitType(client, &regist->regack,
            SN_MSG_TYPE_REGACK, regist->packet_id, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
    if (rc == MQTT_CODE_CONTINUE)
        return rc;
#endif
#ifdef WOLFMQTT_MULTITHREAD
    if (wm_SemLock(&client->lockClient) == 0) {
        MqttClient_RespList_Remove(client, &regist->pendResp);
        wm_SemUnlock(&client->lockClient);
    }
#endif

    /* reset state */
    regist->stat.write = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Ping(MqttClient *client, SN_PingReq *ping)
{
    int rc;
    SN_PingReq loc_ping;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (ping == NULL) {
        XMEMSET(&loc_ping, 0, sizeof(SN_PingReq));
        ping = &loc_ping;
    }

    if (ping->stat.write == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the ping packet as a request */
        rc = SN_Encode_Ping(client->tx_buf, client->tx_buf_len, ping,
                SN_MSG_TYPE_PING_REQ);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_PING_REQ),
            SN_MSG_TYPE_PING_REQ);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        client->write.len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_PING_RESP, 0,
                    &ping->pendResp, NULL);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send ping req packet */
        rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != client->write.len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &ping->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        ping->stat.write = MQTT_MSG_WAIT;
    }

    /* Wait for ping resp packet */
    rc = SN_Client_WaitType(client, ping,
            SN_MSG_TYPE_PING_RESP, 0, client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
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

int SN_Client_Disconnect(MqttClient *client)
{
    return SN_Client_Disconnect_ex(client, NULL);
}

int SN_Client_Disconnect_ex(MqttClient *client, SN_Disconnect *disconnect)
{
    int rc;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_MULTITHREAD
    /* Lock send socket mutex */
    rc = wm_SemLock(&client->lockSend);
    if (rc != 0) {
        return rc;
    }
#endif

    /* Encode the disconnect packet */
    rc = SN_Encode_Disconnect(client->tx_buf, client->tx_buf_len, disconnect);
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d)",
        rc, SN_Packet_TypeDesc(SN_MSG_TYPE_DISCONNECT),
        SN_MSG_TYPE_DISCONNECT);
#endif
    if (rc <= 0) {
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        return rc;
    }
    client->write.len = rc;

#ifdef WOLFMQTT_MULTITHREAD
    if ((disconnect != NULL) && (disconnect->sleepTmr != 0)) {
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client,
                    (MqttPacketType)SN_MSG_TYPE_DISCONNECT, 0,
                    &disconnect->pendResp, NULL);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    }
#endif

    /* Send disconnect packet */
    rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockSend);
#endif
    if (rc != client->write.len) {
    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0) {
            MqttClient_RespList_Remove(client, &disconnect->pendResp);
            wm_SemUnlock(&client->lockClient);
        }
    #endif
        return rc;
    }
    else {
        rc = MQTT_CODE_SUCCESS;
    }

    /* If sleep was set, wait for response disconnect packet */
    if ((disconnect != NULL) && (disconnect->sleepTmr != 0)) {
        rc = SN_Client_WaitType(client, disconnect,
                SN_MSG_TYPE_DISCONNECT, 0, client->cmd_timeout_ms);
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == MQTT_CODE_CONTINUE)
            return rc;
    #endif
    #ifdef WOLFMQTT_MULTITHREAD
        if (wm_SemLock(&client->lockClient) == 0) {
            MqttClient_RespList_Remove(client, &disconnect->pendResp);
            wm_SemUnlock(&client->lockClient);
        }
    #endif
    }

    return rc;
}

int SN_Client_WaitMessage_ex(MqttClient *client, SN_Object* packet_obj,
        int timeout_ms)
{
    return SN_Client_WaitType(client, packet_obj,
        SN_MSG_TYPE_ANY, 0, timeout_ms);
}

int SN_Client_WaitMessage(MqttClient *client, int timeout_ms)
{
    if (client == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;
    return SN_Client_WaitMessage_ex(client, &client->msgSN, timeout_ms);
}

#endif /* defined WOLFMQTT_SN */
