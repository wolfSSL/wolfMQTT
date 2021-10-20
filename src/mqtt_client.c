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

#ifdef WOLFMQTT_MULTITHREAD

#ifdef __MACH__
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
        *s = CreateSemaphore( NULL, 0, 1, NULL);
        return 0;
    }
    int wm_SemFree(wm_Sem *s) {
        CloseHandle(*s);
        *s = NULL;
        return 0;
    }
    int wm_SemLock(wm_Sem *s) {
        WaitForSingleObject(*s, 0);
        return 0;
    }
    int wm_SemUnlock(wm_Sem *s) {
        ReleaseSemaphore(*s, 1, NULL);
        return 0;
    }

#endif

/* These RespList functions assume caller has locked client->lockClient mutex */
static int MqttClient_RespList_Add(MqttClient *client,
    MqttPacketType packet_type, word16 packet_id, MqttPendResp *newResp,
    void *packet_obj)
{
    MqttPendResp *tmpResp;

    if (client == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

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
            return MQTT_CODE_ERROR_BAD_ARG;
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
    return 0;
}

static void MqttClient_RespList_Remove(MqttClient *client, MqttPendResp *rmResp)
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
        PRINTF("\tPendResp Remove Failed");
    }
#endif
}

static int MqttClient_RespList_Find(MqttClient *client,
    MqttPacketType packet_type, word16 packet_id, MqttPendResp **retResp)
{
    int rc = 0;
    MqttPendResp *tmpResp;

    if (client == NULL)
        return MQTT_CODE_ERROR_BAD_ARG;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("PendResp Find: Type %s (%d), ID %d",
        MqttPacket_TypeDesc(packet_type), packet_type, packet_id);
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
            PRINTF("PendResp Found: %p, Type %s (%d), ID %d",
                tmpResp, MqttPacket_TypeDesc(tmpResp->packet_type),
                tmpResp->packet_type, tmpResp->packet_id);
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
static int Handle_Props(MqttClient* client, MqttProp* props, byte use_cb)
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
        /* Free the properties */
        MqttProps_Free(props);
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

 *  \return     Returns length decoded or error (as negative) MQTT_CODE_ERROR_*
                (see enum MqttPacketResponseCodes)
 */
static int MqttClient_DecodePacket(MqttClient* client, byte* rx_buf,
    word32 rx_len, void *packet_obj, MqttPacketType* ppacket_type,
    MqttQoS* ppacket_qos, word16* ppacket_id)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttPacket* header;
    MqttPacketType packet_type;
    MqttQoS packet_qos;
    word16 packet_id = 0;

    /* must have rx buffer with at least 2 byes for header */
    if (rx_buf == NULL || rx_len < MQTT_PACKET_HEADER_MIN_SIZE) {
        return MQTT_CODE_ERROR_BAD_ARG;
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
            if (rc >= 0){
                int tmp = Handle_Props(client, p_connect_ack->props,
                                       (packet_obj != NULL));
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
        #endif
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH:
        {
            MqttPublish publish, *p_publish = &publish;
            if (packet_obj) {
                p_publish = (MqttPublish*)packet_obj;
            }
            else {
                XMEMSET(p_publish, 0, sizeof(MqttPublish));
            }
        #ifdef WOLFMQTT_V5
            p_publish->protocol_level = client->protocol_level;
        #endif
            rc = MqttDecode_Publish(rx_buf, rx_len, p_publish);
            if (rc >= 0) {
                packet_id = p_publish->packet_id;
            #ifdef WOLFMQTT_V5
                {
                    int tmp = Handle_Props(client, p_publish->props,
                                           (packet_obj != NULL));
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
                {
                    int tmp = Handle_Props(client, p_publish_resp->props,
                                           (packet_obj != NULL));
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
                {
                    int tmp = Handle_Props(client, p_subscribe_ack->props,
                                           (packet_obj != NULL));
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
                {
                    int tmp = Handle_Props(client, p_unsubscribe_ack->props,
                                           (packet_obj != NULL));
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
            if (rc >= 0) {
                int tmp = Handle_Props(client, p_auth->props,
                                       (packet_obj != NULL));
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
        #else
            rc = MQTT_CODE_ERROR_PACKET_TYPE;
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
            if (rc >= 0) {
                int tmp = Handle_Props(client, p_disc->props,
                                       (packet_obj != NULL));
                if (tmp != MQTT_CODE_SUCCESS) {
                    rc = tmp;
                }
            }
        #else
            rc = MQTT_CODE_ERROR_PACKET_TYPE;
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
            rc = MQTT_CODE_ERROR_PACKET_TYPE;
            break;
        } /* switch (packet_type) */
    }

    if (ppacket_id) {
        *ppacket_id = packet_id;
    }

    (void)client;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_DecodePacket: Rc %d, Len %d, Type %s (%d), ID %d,"
            " QoS %d",
        rc, rx_len, MqttPacket_TypeDesc(packet_type), packet_type, packet_id,
        packet_qos);
#endif

    return rc;
}

static int MqttClient_HandlePacket(MqttClient* client,
    MqttPacketType packet_type, void *packet_obj, int timeout_ms)
{
    int rc = MQTT_CODE_SUCCESS;
    MqttQoS packet_qos = MQTT_QOS_0;
    word16 packet_id = 0;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    switch (packet_type)
    {
        case MQTT_PACKET_TYPE_CONNECT_ACK:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id);
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH:
        {
            MqttPublish *publish = (MqttPublish*)packet_obj;
            MqttPacketType resp_type;

            if (publish->stat == MQTT_MSG_BEGIN ||
                publish->stat == MQTT_MSG_READ) {
                rc = MqttClient_DecodePacket(client, client->rx_buf,
                    client->packet.buf_len, packet_obj, &packet_type,
                    &packet_qos, &packet_id);
                if (rc <= 0) {
                    return rc;
                }
            }
            else {
                /* packet ID and QoS were already established */
                packet_id = client->msg.publish.packet_id;
                packet_qos = client->msg.publish.qos;
            }

            rc = MqttClient_Publish_ReadPayload(client, publish, timeout_ms);
            if (rc < 0) {
                break;
            }

            /* Handle QoS */
            if (packet_qos == MQTT_QOS_0) {
                /* we are done, no QoS response */
                break;
            }

            /* Determine packet type to write */
            resp_type = (packet_qos == MQTT_QOS_1) ?
                MQTT_PACKET_TYPE_PUBLISH_ACK :
                MQTT_PACKET_TYPE_PUBLISH_REC;
            publish->resp.packet_id = packet_id;

        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif

            /* Encode publish response */
            rc = MqttEncode_PublishResp(client->tx_buf, client->tx_buf_len,
                resp_type, &publish->resp);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d,"
                    " QoS %d",
                rc, MqttPacket_TypeDesc(resp_type), resp_type, packet_id,
                packet_qos);
        #endif
            if (rc <= 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                return rc;
            }
            client->packet.buf_len = rc;

            /* Send publish response packet */
            rc = MqttPacket_Write(client, client->tx_buf,
                client->packet.buf_len);

        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            break;
        }
        case MQTT_PACKET_TYPE_PUBLISH_ACK:
        case MQTT_PACKET_TYPE_PUBLISH_REC:
        case MQTT_PACKET_TYPE_PUBLISH_REL:
        case MQTT_PACKET_TYPE_PUBLISH_COMP:
        {
            MqttPublishResp pubRespObj, *publish_resp = &pubRespObj;
            XMEMSET(publish_resp, 0, sizeof(MqttPublishResp));

            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, publish_resp, &packet_type,
                &packet_qos, &packet_id);
            if (rc <= 0) {
                return rc;
            }

            /* If publish Received or Release QoS then proceed */
            if (packet_type != MQTT_PACKET_TYPE_PUBLISH_REC &&
                packet_type != MQTT_PACKET_TYPE_PUBLISH_REL) {
                break;
            }

        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock send socket mutex */
            rc = wm_SemLock(&client->lockSend);
            if (rc != 0) {
                return rc;
            }
        #endif

            /* Encode publish response */
            publish_resp->packet_id = packet_id;
            packet_type = (MqttPacketType)((int)packet_type+1); /* next ack */
        #ifdef WOLFMQTT_V5
            #ifdef WOLFMQTT_DEBUG_CLIENT
                PRINTF("\tPublish response: reason code %d, Type %s (%d),"
                        " ID %d, QoS %d",
                        publish_resp->reason_code,
                        MqttPacket_TypeDesc(packet_type),
                        packet_type, packet_id, packet_qos);
            #endif

            /* return reason code to caller */
            if (packet_obj != NULL) {
                MqttPublishResp* caller_rsp = (MqttPublishResp*)packet_obj;
                caller_rsp->reason_code = publish_resp->reason_code;
            }

            /* Publish QoS response needs success reason code,
             * otherwise will cause disconnect at broker */
            publish_resp->reason_code = MQTT_REASON_SUCCESS;
        #endif

            rc = MqttEncode_PublishResp(client->tx_buf, client->tx_buf_len,
                packet_type, publish_resp);
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d,"
                    " QoS %d",
                rc, MqttPacket_TypeDesc(packet_type), packet_type, packet_id,
                packet_qos);
        #endif
            if (rc <= 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                return rc;
            }
            client->packet.buf_len = rc;

            /* Send publish response packet */
            rc = MqttPacket_Write(client, client->tx_buf,
                client->packet.buf_len);

        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            break;
        }
        case MQTT_PACKET_TYPE_SUBSCRIBE_ACK:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id);
            break;
        }
        case MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id);
            break;
        }
        case MQTT_PACKET_TYPE_PING_RESP:
        {
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id);
            break;
        }
        case MQTT_PACKET_TYPE_AUTH:
        {
        #ifdef WOLFMQTT_V5
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id);
        #else
            rc = MQTT_CODE_ERROR_PACKET_TYPE;
        #endif
            break;
        }

        case MQTT_PACKET_TYPE_DISCONNECT:
        {
        #ifdef WOLFMQTT_V5
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, packet_obj, &packet_type, &packet_qos,
                &packet_id);
        #else
            rc = MQTT_CODE_ERROR_PACKET_TYPE;
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
            rc = MQTT_CODE_ERROR_PACKET_TYPE;
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

static int MqttClient_WaitType(MqttClient *client, void *packet_obj,
    byte wait_type, word16 wait_packet_id, int timeout_ms)
{
    int rc;
    word16 packet_id;
    MqttPacketType packet_type;
#ifdef WOLFMQTT_MULTITHREAD
    MqttPendResp *pendResp;
    int readLocked;
#endif
    MqttMsgStat* mms_stat;
    int waitMatchFound;

    if (client == NULL || packet_obj == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* all packet type structures must have MqttMsgStat at top */
    mms_stat = (MqttMsgStat*)packet_obj;

wait_again:

    /* initialize variables */
    packet_id = 0;
    packet_type = MQTT_PACKET_TYPE_RESERVED;
#ifdef WOLFMQTT_MULTITHREAD
    pendResp = NULL;
    readLocked = 0;
#endif
    waitMatchFound = 0;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_WaitType: Type %s (%d), ID %d",
        MqttPacket_TypeDesc((MqttPacketType)wait_type),
            wait_type, wait_packet_id);
#endif

    switch ((int)*mms_stat)
    {
        case MQTT_MSG_BEGIN:
        {
        #ifdef WOLFMQTT_MULTITHREAD
            /* Lock recv socket mutex */
            rc = wm_SemLock(&client->lockRecv);
            if (rc != 0) {
                PRINTF("MqttClient_WaitType: recv lock error!");
                return rc;
            }
            readLocked = 1;
        #endif

            /* reset the packet state */
            client->packet.stat = MQTT_PK_BEGIN;
        }
        FALL_THROUGH;

    #ifdef WOLFMQTT_V5
        case MQTT_MSG_AUTH:
    #endif
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

            *mms_stat = MQTT_MSG_WAIT;

            /* Wait for packet */
            rc = MqttPacket_Read(client, client->rx_buf, client->rx_buf_len,
                    timeout_ms);
            /* handle failure */
            if (rc <= 0) {
                break;
            }

            /* capture length read */
            client->packet.buf_len = rc;

            /* Decode Packet - get type and id */
            rc = MqttClient_DecodePacket(client, client->rx_buf,
                client->packet.buf_len, NULL, &packet_type, NULL, &packet_id);
            if (rc < 0) {
                break;
            }

        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("Read Packet: Len %d, Type %d, ID %d",
                client->packet.buf_len, packet_type, packet_id);
        #endif

            *mms_stat = MQTT_MSG_READ;
        }
        FALL_THROUGH;

        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        {
            MqttPacketType use_packet_type;
            void* use_packet_obj;

        #ifdef WOLFMQTT_MULTITHREAD
            readLocked = 1; /* if in this state read is locked */
        #endif

            /* read payload state only happens for publish messages */
            if (*mms_stat == MQTT_MSG_READ_PAYLOAD) {
                packet_type = MQTT_PACKET_TYPE_PUBLISH;
            }

            /* Determine if we received data for this request */
            if ((wait_type == MQTT_PACKET_TYPE_ANY ||
                 wait_type == packet_type ||
                 (MqttIsPubRespPacket(packet_type) &&
                  MqttIsPubRespPacket(wait_type))) &&
                (wait_packet_id == 0 || wait_packet_id == packet_id))
            {
                use_packet_obj = packet_obj;
                if (packet_type == wait_type) {
                    /* Only stop waiting when matched */
                    waitMatchFound = 1;
                }
            }
            else {
                /* use generic packet object */
                use_packet_obj = &client->msg;
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
                    use_packet_obj = pendResp->packet_obj;
                    use_packet_type = pendResp->packet_type;
                    /* req from another thread... not a match */
                    waitMatchFound = 0;
                }
                wm_SemUnlock(&client->lockClient);
            }
            else {
                break; /* error */
            }
        #endif /* WOLFMQTT_MULTITHREAD */

            /* Perform packet handling for publish callback and QoS */
            rc = MqttClient_HandlePacket(client, use_packet_type,
                use_packet_obj, timeout_ms);

        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE) {
                /* we have received some data, so keep the recv
                    mutex lock active and return */
                return rc;
            }
        #endif

            /* Clear shared union for next call */
            if ((MqttObject*)use_packet_obj == &client->msg) {
                XMEMSET(&client->msg, 0, sizeof(client->msg));
            }

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
                    PRINTF("PendResp Done %p", pendResp);
                #endif
                    pendResp = NULL;
                    wm_SemUnlock(&client->lockClient);
                }
            }
        #endif /* WOLFMQTT_MULTITHREAD */
            break;
        }

        case MQTT_MSG_WRITE:
        case MQTT_MSG_WRITE_PAYLOAD:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_WaitType: Invalid state %d!", *mms_stat);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
        }
    } /* switch (*mms_stat) */

#ifdef WOLFMQTT_NONBLOCK
    if (rc != MQTT_CODE_CONTINUE)
#endif
    {
        /* reset state */
        *mms_stat = MQTT_MSG_BEGIN;
    }

#ifdef WOLFMQTT_MULTITHREAD
    if (readLocked) {
        wm_SemUnlock(&client->lockRecv);
    }
#endif
    if (rc < 0) {
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_WaitType: Failure: %s (%d)",
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
    int rc, len = 0;

    /* Validate required arguments */
    if (client == NULL || mc_connect == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (mc_connect->stat == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

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
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
            return rc;
        }
        len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_CONNECT_ACK,
                    0, &mc_connect->pendResp, &mc_connect->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send connect packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
    #ifdef WOLFMQTT_MULTITHREAD
            if ((rc != MQTT_CODE_CONTINUE) &&
                (wm_SemLock(&client->lockClient)) == 0) {
                MqttClient_RespList_Remove(client, &mc_connect->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
    #endif
            return rc;
        }
    #ifdef WOLFMQTT_V5
        /* Enhanced authentication */
        if (client->enable_eauth == 1) {
            mc_connect->stat = MQTT_MSG_AUTH;
        }
        else
    #endif
        {
            mc_connect->stat = MQTT_MSG_WAIT;
        }
    }

#ifdef WOLFMQTT_V5
    /* Enhanced authentication */
    if (mc_connect->protocol_level > MQTT_CONNECT_PROTOCOL_LEVEL_4 && 
            mc_connect->stat == MQTT_MSG_AUTH)
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
            return MQTT_CODE_ERROR_BAD_ARG;
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
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &mc_connect->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
    }
#endif /* WOLFMQTT_V5 */

    /* Wait for connect ack packet */
    rc = MqttClient_WaitType(client, &mc_connect->ack,
        MQTT_PACKET_TYPE_CONNECT_ACK, 0, client->cmd_timeout_ms);
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
    mc_connect->stat = MQTT_MSG_BEGIN;

    return rc;
}

#ifdef WOLFMQTT_TEST_NONBLOCK
static int testNbAlt = 0;
#endif

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
            publish->stat = MQTT_MSG_READ_PAYLOAD;

            msg_len = (publish->total_len - publish->buffer_pos);
            if (msg_len > client->rx_buf_len) {
                msg_len = client->rx_buf_len;
            }

            /* make sure there is something to read */
            if (msg_len > 0) {
                #ifdef WOLFMQTT_TEST_NONBLOCK
                    if (!testNbAlt) {
                        testNbAlt = 1;
                        return MQTT_CODE_CONTINUE;
                    }
                    testNbAlt = 0;
                #endif

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
        return MQTT_CODE_ERROR_BAD_ARG;

    if (pubCb) {
        word32 tmp_len = publish->buffer_len;

        do {
            /* Use the callback to get payload */
            if ((client->write.len = pubCb(publish)) < 0) {
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
            rc = MqttPacket_Write(client, client->tx_buf,
                    client->write.len);
            if (rc < 0) {
                return rc;
            }

            /* ONLY if send was successful, update buffer position.
             * Otherwise, MqttPacket_Write() will resume where it left off. */
            publish->buffer_pos += client->write.len;

            /* Check if we are done sending publish message */
            if (publish->buffer_pos < publish->buffer_len) {
                return MQTT_CODE_PUB_CONTINUE;
            }
    #else
        do {
            rc = MqttPacket_Write(client, client->tx_buf,
                    client->write.len);
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
                /* Build next payload to send */
                client->write.len = (publish->total_len - publish->buffer_pos);
                if (client->write.len > client->tx_buf_len) {
                    client->write.len = client->tx_buf_len;
                }
                rc = MQTT_CODE_PUB_CONTINUE;
            }
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

    /* Validate required arguments */
    if (client == NULL || publish == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_V5
    /* Use specified protocol version if set */
    publish->protocol_level = client->protocol_level;

    /* Validate publish request against server properties */
    if ((publish->qos > client->max_qos) ||
        ((publish->retain == 1) && (client->retain_avail == 0)))
    {
        return MQTT_CODE_ERROR_SERVER_PROP;
    }
#endif

    switch (publish->stat)
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
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
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
                    wm_SemUnlock(&client->lockSend);
                    return rc; /* Error locking client */
                }
            }
        #endif

            publish->stat = MQTT_MSG_WRITE;
        }
        FALL_THROUGH;

        case MQTT_MSG_WRITE:
        {
            /* Send packet */
            rc = MqttPacket_Write(client, client->tx_buf, client->write.len);
        #ifdef WOLFMQTT_NONBLOCK
            if (rc == MQTT_CODE_CONTINUE)
                return rc;
        #endif
            if (rc < 0) {
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
            #ifdef WOLFMQTT_MULTITHREAD
                if (wm_SemLock(&client->lockClient) == 0) {
                    MqttClient_RespList_Remove(client, &publish->pendResp);
                    wm_SemUnlock(&client->lockClient);
                }
            #endif
                return rc;
            }

            /* advance state */
            publish->stat = MQTT_MSG_WRITE_PAYLOAD;
        }
        FALL_THROUGH;

        case MQTT_MSG_WRITE_PAYLOAD:
        {
            rc = MqttClient_Publish_WritePayload(client, publish, pubCb);
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
                break;
            }

            /* if not expecting a reply then we are done */
            if (publish->qos == MQTT_QOS_0) {
                break;
            }
            publish->stat = MQTT_MSG_WAIT;
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

                /* Wait for publish response packet */
                rc = MqttClient_WaitType(client, &publish->resp, resp_type,
                    publish->packet_id, client->cmd_timeout_ms);
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
            }
            break;
        }

    #ifdef WOLFMQTT_V5
        case MQTT_MSG_AUTH:
    #endif
        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("MqttClient_Publish: Invalid state %d!",
                publish->stat);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
    } /* switch (publish->stat) */

    /* reset state */
    if ((rc != MQTT_CODE_PUB_CONTINUE)
#ifdef WOLFMQTT_NONBLOCK
         && (rc != MQTT_CODE_CONTINUE)
#endif
        )
    {
        publish->stat = MQTT_MSG_BEGIN;
    }
    if (rc > 0) {
        rc = MQTT_CODE_SUCCESS;
    }

    return rc;
}

int MqttClient_Subscribe(MqttClient *client, MqttSubscribe *subscribe)
{
    int rc, len, i;
    MqttTopic* topic;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_V5
    /* Use specified protocol version if set */
    subscribe->protocol_level = client->protocol_level;
#endif

    if (subscribe->stat == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the subscribe packet */
        rc = MqttEncode_Subscribe(client->tx_buf, client->tx_buf_len,
                subscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_SUBSCRIBE),
            MQTT_PACKET_TYPE_SUBSCRIBE, subscribe->packet_id);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_SUBSCRIBE_ACK,
                subscribe->packet_id, &subscribe->pendResp, &subscribe->ack);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send subscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &subscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        subscribe->stat = MQTT_MSG_WAIT;
    }

    /* Wait for subscribe ack packet */
    rc = MqttClient_WaitType(client, &subscribe->ack,
        MQTT_PACKET_TYPE_SUBSCRIBE_ACK, subscribe->packet_id,
        client->cmd_timeout_ms);
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

    /* Populate return codes */
    if (rc == MQTT_CODE_SUCCESS) {
        for (i = 0; i < subscribe->topic_count && i < MAX_MQTT_TOPICS; i++) {
            topic = &subscribe->topics[i];
            topic->return_code = subscribe->ack.return_codes[i];
        }
    }

    /* reset state */
    subscribe->stat = MQTT_MSG_BEGIN;

    return rc;
}

int MqttClient_Unsubscribe(MqttClient *client, MqttUnsubscribe *unsubscribe)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_V5
    /* Use specified protocol version if set */
    unsubscribe->protocol_level = client->protocol_level;
#endif

    if (unsubscribe->stat == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the subscribe packet */
        rc = MqttEncode_Unsubscribe(client->tx_buf, client->tx_buf_len,
            unsubscribe);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_UNSUBSCRIBE),
            MQTT_PACKET_TYPE_UNSUBSCRIBE, unsubscribe->packet_id, 0);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        len = rc;

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
            wm_SemUnlock(&client->lockSend); /* Error locking client */
            return rc;
        }
    #endif

        /* Send unsubscribe packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        unsubscribe->stat = MQTT_MSG_WAIT;
    }

    /* Wait for unsubscribe ack packet */
    rc = MqttClient_WaitType(client, &unsubscribe->ack,
        MQTT_PACKET_TYPE_UNSUBSCRIBE_ACK, unsubscribe->packet_id,
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

#ifdef WOLFMQTT_V5
    if (unsubscribe->ack.props != NULL) {
        /* Release the allocated properties */
        MqttClient_PropsFree(unsubscribe->ack.props);
    }
#endif

    /* reset state */
    unsubscribe->stat = MQTT_MSG_BEGIN;

    return rc;
}

int MqttClient_Ping_ex(MqttClient *client, MqttPing* ping)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL || ping == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (ping->stat == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the subscribe packet */
        rc = MqttEncode_Ping(client->tx_buf, client->tx_buf_len, ping);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_PING_REQ),
            MQTT_PACKET_TYPE_PING_REQ, 0, 0);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_PING_RESP, 0,
                &ping->pendResp, ping);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send ping req packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &ping->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        ping->stat = MQTT_MSG_WAIT;
    }

    /* Wait for ping resp packet */
    rc = MqttClient_WaitType(client, ping, MQTT_PACKET_TYPE_PING_RESP, 0,
        client->cmd_timeout_ms);
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
    ping->stat = MQTT_MSG_BEGIN;

    return rc;
}

int MqttClient_Ping(MqttClient *client)
{
    MqttPing ping;
    XMEMSET(&ping, 0, sizeof(ping));
    return MqttClient_Ping_ex(client, &ping);
}

int MqttClient_Disconnect(MqttClient *client)
{
    return MqttClient_Disconnect_ex(client, NULL);
}

int MqttClient_Disconnect_ex(MqttClient *client, MqttDisconnect *disconnect)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef WOLFMQTT_V5
    if (disconnect != NULL) {
        /* Use specified protocol version if set */
        disconnect->protocol_level = client->protocol_level;
    }
#endif

#ifdef WOLFMQTT_MULTITHREAD
    /* Lock send socket mutex */
    rc = wm_SemLock(&client->lockSend);
    if (rc != 0) {
        return rc;
    }
#endif

    /* Encode the disconnect packet */
    rc = MqttEncode_Disconnect(client->tx_buf, client->tx_buf_len, disconnect);
#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
        rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_DISCONNECT),
        MQTT_PACKET_TYPE_DISCONNECT, 0, 0);
#endif
    if (rc <= 0) {
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        return rc;
    }
    len = rc;

    /* Send disconnect packet */
    rc = MqttPacket_Write(client, client->tx_buf, len);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockSend);
#endif
    if (rc != len) {
        return rc;
    }

    /* No response for MQTT disconnect packet */

    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_V5
int MqttClient_Auth(MqttClient *client, MqttAuth* auth)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (auth->stat == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode the authentication packet */
        rc = MqttEncode_Auth(client->tx_buf, client->tx_buf_len, auth);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("MqttClient_EncodePacket: Len %d, Type %s (%d), ID %d, QoS %d",
            rc, MqttPacket_TypeDesc(MQTT_PACKET_TYPE_AUTH),
            MQTT_PACKET_TYPE_AUTH, 0, 0);
    #endif
        if (rc <= 0) {
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            return rc;
        }
        len = rc;

    #ifdef WOLFMQTT_MULTITHREAD
        rc = wm_SemLock(&client->lockClient);
        if (rc == 0) {
            /* inform other threads of expected response */
            rc = MqttClient_RespList_Add(client, MQTT_PACKET_TYPE_AUTH, 0,
                &auth->pendResp, auth);
            wm_SemUnlock(&client->lockClient);
        }
        if (rc != 0) {
            wm_SemUnlock(&client->lockSend);
            return rc; /* Error locking client */
        }
    #endif

        /* Send authentication packet */
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &auth->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        auth->stat = MQTT_MSG_WAIT;
    }

    /* Wait for auth packet */
    rc = MqttClient_WaitType(client, auth, MQTT_PACKET_TYPE_AUTH, 0,
        client->cmd_timeout_ms);
#ifdef WOLFMQTT_NONBLOCK
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
    auth->stat = MQTT_MSG_BEGIN;

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
        return MQTT_CODE_ERROR_BAD_ARG;
    return MqttClient_WaitMessage_ex(client, &client->msg, timeout_ms);
}

int MqttClient_NetConnect(MqttClient *client, const char* host,
    word16 port, int timeout_ms, int use_tls, MqttTlsCb cb)
{
    return MqttSocket_Connect(client, host, port, timeout_ms, use_tls, cb);
}

int MqttClient_NetDisconnect(MqttClient *client)
{
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
            int len;

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
                len = rc;

                /* Send regack packet */
                rc = MqttPacket_Write(client, client->tx_buf, len);
            #ifdef WOLFMQTT_MULTITHREAD
                wm_SemUnlock(&client->lockSend);
            #endif
                if (rc != len) { return rc; }
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
                client->packet.buf_len = rc;

                /* Send packet */
                rc = MqttPacket_Write(client, client->tx_buf,
                                                    client->packet.buf_len);
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
                client->packet.buf_len = rc;

                /* Send packet */
                rc = MqttPacket_Write(client, client->tx_buf,
                        client->packet.buf_len);
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
            int len;

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
            len = rc;

            /* Send ping resp packet */
            rc = MqttPacket_Write(client, client->tx_buf, len);
        #ifdef WOLFMQTT_MULTITHREAD
            wm_SemUnlock(&client->lockSend);
        #endif
            if (rc != len) { return rc; }

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
    int readLocked;
#endif
    MqttMsgStat* mms_stat;
    int waitMatchFound;

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
    readLocked = 0;
#endif
    waitMatchFound = 0;

#ifdef WOLFMQTT_DEBUG_CLIENT
    PRINTF("SN_Client_WaitType: Type %s (%d), ID %d",
            SN_Packet_TypeDesc((SN_MsgType)wait_type),
                wait_type, wait_packet_id);
#endif

    switch ((int)*mms_stat)
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
            readLocked = 1;
        #endif

            /* reset the packet state */
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
                wm_SemUnlock(&client->lockRecv);
                return rc;
            }
        #endif /* WOLFMQTT_MULTITHREAD */

            *mms_stat = MQTT_MSG_WAIT;

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

            *mms_stat = MQTT_MSG_READ;
        }
        FALL_THROUGH;

        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        {
            SN_MsgType use_packet_type;
            void* use_packet_obj;

        #ifdef WOLFMQTT_MULTITHREAD
            readLocked = 1; /* if in this state read is locked */
        #endif

            if (*mms_stat == MQTT_MSG_READ_PAYLOAD) {
                packet_type = SN_MSG_TYPE_PUBLISH;
            }

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
                    use_packet_obj = pendResp->packet_obj;
                    use_packet_type = (SN_MsgType)pendResp->packet_type;
                    /* req from another thread... not a match */
                    waitMatchFound = 0;
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
                /* we have received some data, so keep the recv
                    mutex lock active and return */
                return rc;
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

        case MQTT_MSG_WRITE:
        default:
        {
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_WaitType: Invalid state %d!", *mms_stat);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
        }
    } /* switch (msg->stat) */

#ifdef WOLFMQTT_NONBLOCK
    if (rc != MQTT_CODE_CONTINUE)
#endif
    {
        /* reset state */
        *mms_stat = MQTT_MSG_BEGIN;
    }

#ifdef WOLFMQTT_MULTITHREAD
    if (readLocked) {
        wm_SemUnlock(&client->lockRecv);
    }
#endif

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
    int rc, len = 0;

    /* Validate required arguments */
    if (client == NULL || search == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (search->stat == MQTT_MSG_BEGIN) {
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
        len = rc;

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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &search->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }
        search->stat = MQTT_MSG_WAIT;
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
    search->stat = MQTT_MSG_BEGIN;

    return rc;
}

static int SN_WillTopic(MqttClient *client, SN_Will *will)
{
    int rc, len;

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
        len = rc = SN_Encode_WillTopic(client->tx_buf, client->tx_buf_len,
                will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLTOPIC),
            SN_MSG_TYPE_WILLTOPIC);
    #endif
        if (rc > 0) {
            /* Send Will Topic packet */
            rc = MqttPacket_Write(client, client->tx_buf, len);
            if (rc == len) {
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
    int rc, len;

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
        len = rc = SN_Encode_WillMsg(client->tx_buf,
            client->tx_buf_len, will);
    #ifdef WOLFMQTT_DEBUG_CLIENT
        PRINTF("EncodePacket: Len %d, Type %s (%d)",
            rc, SN_Packet_TypeDesc(SN_MSG_TYPE_WILLMSG),
            SN_MSG_TYPE_WILLMSG);
    #endif
        if (rc > 0) {
            /* Send Will Topic packet */
            rc = MqttPacket_Write(client, client->tx_buf, len);
            if (rc == len) {
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
    int rc = 0, len = 0;
    static byte will_done;

    /* Validate required arguments */
    if ((client == NULL) || (mc_connect == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (mc_connect->stat == MQTT_MSG_BEGIN) {

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
        len = rc;

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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
            return rc;
        }

        mc_connect->stat = MQTT_MSG_WAIT;
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
    mc_connect->stat = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_WillTopicUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0, len = 0;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (will->stat == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif

        /* Encode Will Topic Update */
        len = rc = SN_Encode_WillTopicUpdate(client->tx_buf,
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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
        }
        will->stat = MQTT_MSG_WAIT;
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
    will->stat = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_WillMsgUpdate(MqttClient *client, SN_Will *will)
{
    int rc = 0, len = 0;

    /* Validate required arguments */
    if ((client == NULL) || (will == NULL)) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (will->stat == MQTT_MSG_BEGIN) {
    #ifdef WOLFMQTT_MULTITHREAD
        /* Lock send socket mutex */
        rc = wm_SemLock(&client->lockSend);
        if (rc != 0) {
            return rc;
        }
    #endif
        /* Encode Will Message Update */
        len = rc = SN_Encode_WillMsgUpdate(client->tx_buf,
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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &will->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
        }
        will->stat = MQTT_MSG_WAIT;
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
    will->stat = MQTT_MSG_BEGIN;

    return rc;

}

int SN_Client_Subscribe(MqttClient *client, SN_Subscribe *subscribe)
{
    int rc = -1, len;

    /* Validate required arguments */
    if (client == NULL || subscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (subscribe->stat == MQTT_MSG_BEGIN) {
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
        len = rc;

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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &subscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        subscribe->stat = MQTT_MSG_WAIT;
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
    subscribe->stat = MQTT_MSG_BEGIN;

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

    switch ((int)publish->stat)
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

            publish->stat = MQTT_MSG_WRITE;
        }
        FALL_THROUGH;

        case MQTT_MSG_WRITE:
        {
            /* Send packet and payload */
            rc = MqttPacket_Write(client, client->tx_buf,
                    client->write.len);
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

            publish->stat = MQTT_MSG_WAIT;
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

        case MQTT_MSG_READ:
        case MQTT_MSG_READ_PAYLOAD:
        #ifdef WOLFMQTT_DEBUG_CLIENT
            PRINTF("SN_Client_Publish: Invalid state %d!",
                publish->stat);
        #endif
            rc = MQTT_CODE_ERROR_STAT;
            break;
    } /* switch (publish->stat) */

    /* reset state */
#ifdef WOLFMQTT_NONBLOCK
    if (rc != MQTT_CODE_CONTINUE)
#endif
    {
        publish->stat = MQTT_MSG_BEGIN;
    }
    if (rc > 0) {
        rc = MQTT_CODE_SUCCESS;
    }

    return rc;
}

int SN_Client_Unsubscribe(MqttClient *client, SN_Unsubscribe *unsubscribe)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL || unsubscribe == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (unsubscribe->stat == MQTT_MSG_BEGIN) {
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
        len = rc;

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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
        }
        unsubscribe->stat = MQTT_MSG_WAIT;
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
    unsubscribe->stat = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Register(MqttClient *client, SN_Register *regist)
{
    int rc, len;

    /* Validate required arguments */
    if (client == NULL || regist == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (regist->stat == MQTT_MSG_BEGIN) {
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
        len = rc;

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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &regist->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        regist->stat = MQTT_MSG_WAIT;
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
    regist->stat = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Ping(MqttClient *client, SN_PingReq *ping)
{
    int rc, len;
    SN_PingReq loc_ping;

    /* Validate required arguments */
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (ping == NULL) {
        XMEMSET(&loc_ping, 0, sizeof(SN_PingReq));
        ping = &loc_ping;
    }

    if (ping->stat == MQTT_MSG_BEGIN) {
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
        len = rc;

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
        rc = MqttPacket_Write(client, client->tx_buf, len);
    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&client->lockSend);
    #endif
        if (rc != len) {
        #ifdef WOLFMQTT_MULTITHREAD
            if (wm_SemLock(&client->lockClient) == 0) {
                MqttClient_RespList_Remove(client, &ping->pendResp);
                wm_SemUnlock(&client->lockClient);
            }
        #endif
            return rc;
        }

        ping->stat = MQTT_MSG_WAIT;
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
    ping->stat = MQTT_MSG_BEGIN;

    return rc;
}

int SN_Client_Disconnect(MqttClient *client)
{
    return SN_Client_Disconnect_ex(client, NULL);
}

int SN_Client_Disconnect_ex(MqttClient *client, SN_Disconnect *disconnect)
{
    int rc, len;

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
    len = rc;


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
    rc = MqttPacket_Write(client, client->tx_buf, len);
#ifdef WOLFMQTT_MULTITHREAD
    wm_SemUnlock(&client->lockSend);
#endif
    if (rc != len) {
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
