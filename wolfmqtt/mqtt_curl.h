/* mqtt_curl.h
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

#ifndef WOLFMQTT_CURL_H
#define WOLFMQTT_CURL_H

#include <curl/curl.h>

#ifdef __cplusplus
    extern "C" {
#endif

#include "wolfmqtt/mqtt_types.h"

/* Default Port Numbers */
#define MQTT_DEFAULT_PORT   1883
#define MQTT_SECURE_PORT    8883


struct _MqttClient;

/* Function callbacks */
typedef int (*MqttTlsCb)(struct _MqttClient* client);

typedef int (*MqttNetConnectCb)(void *context,
    const char* host, word16 port, int timeout_ms);
typedef int (*MqttNetWriteCb)(void *context,
    const byte* buf, int buf_len, int timeout_ms);
typedef int (*MqttNetReadCb)(void *context,
    byte* buf, int buf_len, int timeout_ms);
#ifdef WOLFMQTT_SN
typedef int (*MqttNetPeekCb)(void *context,
    byte* buf, int buf_len, int timeout_ms);
#endif
typedef int (*MqttNetDisconnectCb)(void *context);

/* Structure for Network callbacks */
typedef struct _MqttNet {
    void                *context;
    MqttNetConnectCb    connect;
    MqttNetReadCb       read;
    MqttNetWriteCb      write;
    MqttNetDisconnectCb disconnect;
#ifdef WOLFMQTT_SN
    MqttNetPeekCb       peek;
    void                *multi_ctx;
#endif
} MqttNet;

/* MQTT SOCKET APPLICATION INTERFACE */
WOLFMQTT_LOCAL int MqttSocket_Init(struct _MqttClient *client, MqttNet* net);
WOLFMQTT_LOCAL int MqttSocket_Write(struct _MqttClient *client, const byte* buf,
        int buf_len, int timeout_ms);
WOLFMQTT_LOCAL int MqttSocket_Read(struct _MqttClient *client, byte* buf,
        int buf_len, int timeout_ms);
#ifdef WOLFMQTT_SN
WOLFMQTT_LOCAL int MqttSocket_Peek(struct _MqttClient *client, byte* buf,
        int buf_len, int timeout_ms);
#endif /* WOLFMQTT_SN */
WOLFMQTT_LOCAL int MqttSocket_Connect(struct _MqttClient *client,
        const char* host, word16 port, int timeout_ms, int use_tls,
        MqttTlsCb cb);
WOLFMQTT_LOCAL int MqttSocket_Disconnect(struct _MqttClient *client);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_CURL_H */
