/* mqttcurl.h
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

#ifndef WOLFMQTT_EXAMPLE_CURL_H
#define WOLFMQTT_EXAMPLE_CURL_H

#ifdef __cplusplus
    extern "C" {
#endif

#include "examples/mqttexample.h"
#include "examples/mqttport.h"

/* Local context for Net callbacks */
typedef enum {
    SOCK_BEGIN = 0,
    SOCK_CONN
} NB_Stat;

/* Structure for Network Security */
#ifdef ENABLE_MQTT_CURL
typedef struct _CurlContext {
    CURL  *  curl;
    SOCKET_T fd;
    NB_Stat  stat;
    int      sockRcRead;
    int      sockRcWrite;
    int      timeout_ms;
    MQTTCtx* mqttCtx;
} CurlContext;
#endif

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

#endif /* WOLFMQTT_EXAMPLE_CURL_H */
