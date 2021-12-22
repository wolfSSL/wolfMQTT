/* mqttuart.c
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
#include "examples/mqttnet.h"


/* TODO: Add includes for UART HW */

/* Include the example code */
#include "examples/mqttexample.h"


/* this code is a template for using UART for communication */
#if 1

/* Local context for callbacks */
typedef struct _UartContext {
    int uartPort;
    /* TODO: Add any other context info you want */
} UartContext;

/* Private functions */
static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    UartContext *uartCtx = (UartContext*)context;
    (void)uartCtx;

    return 0;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    UartContext *uartCtx = (UartContext*)context;
    (void)uartCtx;

    /* TODO: Implement write call to your UART HW */

    return 0;
}

static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    UartContext *uartCtx = (UartContext*)context;
    (void)uartCtx;

    /* TODO: Implement read call to your UART HW */

    return 0;
}

static int NetDisconnect(void *context)
{
    UartContext *uartCtx = (UartContext*)context;
    (void)uartCtx;

    return 0;
}

/* Public Functions */
int MqttClientUartNet_Init(MqttClient* client)
{
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    XMEMSET(&client->net, 0, sizeof(client->net));
    client->net.connect = NetConnect;
    client->net.read = NetRead;
    client->net.write = NetWrite;
    client->net.disconnect = NetDisconnect;
    client->net.context = WOLFMQTT_MALLOC(sizeof(UartContext));
    return 0;
}

int MqttClientUartNet_DeInit(MqttClient* client)
{
    if (client) {
        if (client->net.context) {
            WOLFMQTT_FREE(client->net.context);
        }
        XMEMSET(&client->net, 0, sizeof(client->net));
    }
    return 0;
}

#endif
