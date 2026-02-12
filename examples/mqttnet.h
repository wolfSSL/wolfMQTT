/* mqttnet.h
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

#ifndef WOLFMQTT_NET_H
#define WOLFMQTT_NET_H

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef ENABLE_MQTT_CURL
    #include <curl/curl.h>
#endif

#include "examples/mqttexample.h"
#include "examples/mqttport.h"

#if defined(HAVE_NETX) && !defined(WOLFMQTT_NO_NETX_DNS)
    /* include the NetX DNS addon header */
    #include "nxd_dns.h"
#endif


/* Local context for Net callbacks */
typedef enum {
    SOCK_BEGIN = 0,
    SOCK_CONN
} NB_Stat;

typedef struct _SocketContext {
    SOCKET_T fd;
    NB_Stat stat;
    SOCK_ADDR_IN addr;
#ifdef MICROCHIP_MPLAB_HARMONY
    word32 bytes;
#endif
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_ENABLE_STDIN_CAP)
    /* "self pipe" -> signal wake sleep() */
    SOCKET_T pfd[2];
#endif
#ifdef ENABLE_MQTT_CURL
    CURL  *  curl;
    int      bytes; /* track partial read/write */
#endif
#ifdef ENABLE_MQTT_WEBSOCKET
    void* websocket_ctx;
#endif
#ifdef HAVE_NETX
#ifndef WOLFMQTT_NO_NETX_DNS
    NX_DNS    *dnsPtr;
#endif
    NX_IP     *ipPtr;
    NX_PACKET *nxPacket;
    ULONG     nxOffset;
#endif
#ifdef WOLFMQTT_WOLFIP
    struct wolfIP *stack;
#endif
    MQTTCtx* mqttCtx;
} SocketContext;

/* Functions used to handle the MqttNet structure creation / destruction */
int MqttClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx);
int MqttClientNet_DeInit(MqttNet* net);
#ifdef WOLFMQTT_SN
int SN_ClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx);
#endif

int MqttClientNet_Wake(MqttNet* net);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_NET_H */
