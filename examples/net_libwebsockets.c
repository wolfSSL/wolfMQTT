/* net_libwebsockets.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include "examples/mqttexample.h"
#include "examples/net_libwebsockets.h"

#ifdef ENABLE_MQTT_WEBSOCKET

#include <libwebsockets.h>

/* Network context for libwebsockets */
typedef struct _LibwebsockContext {
    struct lws_context *context;
    struct lws *wsi;
    char* host;
    int port;
    int status;
    void* heap;
    /* Buffer for received data */
    unsigned char rx_buffer[WOLFMQTT_LWS_RX_BUF_SIZE];
    size_t rx_len;
} LibwebsockContext;

/* Callback for libwebsockets events */
static int callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
    void *user, void *in, size_t len)
{
    LibwebsockContext *net;
    
    (void)user;

    net = (LibwebsockContext*)lws_context_user(lws_get_context(wsi));

    /* Only handle the events we care about */
    if (reason == LWS_CALLBACK_CLIENT_ESTABLISHED) {
        net->status = 1;
    }
    else if (reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR) {
        net->status = -1;
    }
    else if (reason == LWS_CALLBACK_CLOSED) {
        net->status = 0;
    }
    else if (reason == LWS_CALLBACK_CLIENT_RECEIVE) {
        if (in && len > 0) {
            /* Check if we have enough space in the buffer */
            if (net->rx_len + len <= sizeof(net->rx_buffer)) {
                /* Append new data to existing buffer */
                XMEMCPY(net->rx_buffer + net->rx_len, in, len);
                net->rx_len += len;
            } else {
                /* Buffer overflow - handle error */
                lwsl_err("WebSocket receive buffer overflow - dropping oldest data\n");
                
                /* Simple approach: If new data is larger than buffer, just keep newest data */
                if (len >= sizeof(net->rx_buffer)) {
                    /* New data is larger than entire buffer, keep only what fits */
                    /* Cast to byte pointer to allow pointer arithmetic */
                    const byte* in_bytes = (const byte*)in;
                    XMEMCPY(net->rx_buffer, 
                            &in_bytes[len - sizeof(net->rx_buffer)], 
                            sizeof(net->rx_buffer));
                    net->rx_len = sizeof(net->rx_buffer);
                } else {
                    /* Keep as much new data as possible */
                    size_t keep_bytes = sizeof(net->rx_buffer) - len;
                    
                    /* Move the portion of old data we want to keep to the beginning */
                    if (keep_bytes > 0 && net->rx_len > 0) {
                        XMEMMOVE(net->rx_buffer, 
                                net->rx_buffer + (net->rx_len - keep_bytes),
                                keep_bytes);
                    }
                    
                    /* Append all new data */
                    XMEMCPY(net->rx_buffer + keep_bytes, in, len);
                    net->rx_len = keep_bytes + len;
                }
            }
        }
    }
    
    return 0;
}

static const struct lws_protocols protocols[] = {
    {
        "mqtt",
        callback_mqtt,
        sizeof(LibwebsockContext),
        WOLFMQTT_LWS_RX_BUF_SIZE,
        0, /* id */
        NULL, /* user */
        0 /* tx_packet_size */
    },
    LWS_PROTOCOL_LIST_TERM
};

int NetWebsocket_Connect(void *ctx, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)ctx;
    LibwebsockContext *net;
    struct lws_client_connect_info conn_info;
    struct lws_context_creation_info info;
    int rc = 0;

    (void)timeout_ms;
    if (sock == NULL || host == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    
    /* Create libwebsocket context */
    net = (LibwebsockContext*)WOLFMQTT_MALLOC(sizeof(LibwebsockContext));
    if (net == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    XMEMSET(net, 0, sizeof(LibwebsockContext));

    /* Initialize info struct */
    XMEMSET(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.user = net;
    
    net->context = lws_create_context(&info);
    if (net->context == NULL) {
        sock->websocket_ctx = NULL;
        WOLFMQTT_FREE(net);
        net = NULL;
        return MQTT_CODE_ERROR_NETWORK;
    }
    
    /* Store in socket context */
    sock->websocket_ctx = net;
    
    XMEMSET(&conn_info, 0, sizeof(conn_info));
    conn_info.context = net->context;
    conn_info.address = host;
    conn_info.port = port;
    conn_info.path = "/mqtt";
    conn_info.host = host;
    conn_info.protocol = "mqtt";
    conn_info.pwsi = &net->wsi;
    
    net->wsi = lws_client_connect_via_info(&conn_info);
    if (net->wsi == NULL) {
        lws_context_destroy(net->context);
        sock->websocket_ctx = NULL;
        WOLFMQTT_FREE(net);
        net = NULL;
        return MQTT_CODE_ERROR_NETWORK;
    }
    
    /* Wait for connection */
    while (rc >= 0 && net->status == 0) {
        rc = lws_service(net->context, 0);
    }
    
    return (net->status > 0) ? MQTT_CODE_SUCCESS : MQTT_CODE_ERROR_NETWORK;
}

int NetWebsocket_Write(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    LibwebsockContext *net;
    unsigned char *ws_buf;
    int ret;
    time_t start_time, current_time;
    
    if (sock == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    
    net = (LibwebsockContext*)sock->websocket_ctx;
    if (net == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    
    /* Add LWS_PRE bytes for libwebsockets header */
    ws_buf = (unsigned char*)WOLFMQTT_MALLOC(LWS_PRE + buf_len);
    if (ws_buf == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    
    XMEMCPY(ws_buf + LWS_PRE, buf, buf_len);
    
    /* Record start time for timeout handling */
    start_time = time(NULL);
    
    /* Try to write with timeout */
    ret = 0;
    while (ret <= 0) {
        ret = lws_write(net->wsi, ws_buf + LWS_PRE, buf_len, LWS_WRITE_BINARY);
        
        if (ret <= 0) {
            /* Check if we've timed out */
            current_time = time(NULL);
            if ((current_time - start_time) * 1000 >= timeout_ms) {
                ret = MQTT_CODE_ERROR_TIMEOUT;
                break;
            }
            
            /* Service libwebsockets and try again */
            lws_service(net->context, 100);
            
            /* Small delay before retrying */
            #ifdef _WIN32
                Sleep(10);
            #else
                usleep(10000);
            #endif
        }
    }
    
    WOLFMQTT_FREE(ws_buf);
    
    return (ret > 0) ? ret : ret;
}

int NetWebsocket_Read(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    LibwebsockContext *net;
    int ret = 0;
    time_t start_time, current_time;
    
    if (sock == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    
    net = (LibwebsockContext*)sock->websocket_ctx;
    if (net == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    
    /* Record start time for timeout handling */
    start_time = time(NULL);
    
    /* Check if we already have data */
    if (net->rx_len > 0) {
        ret = (net->rx_len <= (size_t)buf_len) ? (int)net->rx_len : buf_len;
        XMEMCPY(buf, net->rx_buffer, ret);
        
        /* If we didn't consume all data, move remaining data to beginning of buffer */
        if (ret < (int)net->rx_len) {
            XMEMMOVE(net->rx_buffer, net->rx_buffer + ret, net->rx_len - ret);
            net->rx_len -= ret;
        } else {
            net->rx_len = 0;
        }
        
        return ret;
    }
    
    /* Wait for data with timeout */
    while (net->rx_len == 0) {
        /* Service libwebsockets to process callbacks */
        lws_service(net->context, 100);
        
        /* Check if we received data in the callback */
        if (net->rx_len > 0) {
            ret = (net->rx_len <= (size_t)buf_len) ? (int)net->rx_len : buf_len;
            XMEMCPY(buf, net->rx_buffer, ret);
            
            /* If we didn't consume all data, move remaining data to beginning of buffer */
            if (ret < (int)net->rx_len) {
                XMEMMOVE(net->rx_buffer, net->rx_buffer + ret, net->rx_len - ret);
                net->rx_len -= ret;
            } else {
                net->rx_len = 0;
            }
            
            return ret;
        }
        
        /* Check if we've timed out */
        current_time = time(NULL);
        if ((current_time - start_time) * 1000 >= timeout_ms) {
            return MQTT_CODE_ERROR_TIMEOUT;
        }
        
        /* Small delay to avoid tight loops */
        #ifdef _WIN32
            Sleep(10);
        #else
            usleep(10000);
        #endif
    }
    
    /* Should not reach here, but just in case */
    return MQTT_CODE_ERROR_NETWORK;
}

int NetWebsocket_Disconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    LibwebsockContext *net;
    
    if (sock == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    
    net = (LibwebsockContext*)sock->websocket_ctx;
    if (net == NULL) {
        return MQTT_CODE_SUCCESS; /* Already disconnected */
    }
    
    if (net->wsi) {
        lws_close_reason(net->wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
        net->wsi = NULL;
    }
    
    if (net->context) {
        lws_context_destroy(net->context);
        net->context = NULL;
    }
    
    WOLFMQTT_FREE(net);
    sock->websocket_ctx = NULL;
    
    return MQTT_CODE_SUCCESS;
}

#endif /* ENABLE_MQTT_WEBSOCKET */ 