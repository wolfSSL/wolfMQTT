/* net_libwebsockets.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#ifndef WOLFMQTT_NET_LIBWEBSOCKETS_H
#define WOLFMQTT_NET_LIBWEBSOCKETS_H

#ifdef __cplusplus
    extern "C" {
#endif

#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttnet.h"

#ifdef ENABLE_MQTT_WEBSOCKET

/* Function declarations */
int NetWebsocket_Connect(void *context, const char* host, word16 port, 
    int timeout_ms);
int NetWebsocket_Read(void *context, byte* buf, int buf_len, 
    int timeout_ms);
int NetWebsocket_Write(void *context, const byte* buf, int buf_len, 
    int timeout_ms);
int NetWebsocket_Disconnect(void *context);

#endif /* ENABLE_MQTT_WEBSOCKET */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_NET_LIBWEBSOCKETS_H */ 