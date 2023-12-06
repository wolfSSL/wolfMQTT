/* mqttcurl.c
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

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "examples/mqttcurl.h"

#if !defined(ENABLE_MQTT_CURL)
    #error "This example requires ENABLE_MQTT_CURL"
#endif

/* How many times to retry after a timeout. */
#define MQTT_CURL_NUM_RETRY (2)

/* Private functions */

/* -------------------------------------------------------------------------- */
/* CURL EASY SOCKET BACKEND EXAMPLE */
/* -------------------------------------------------------------------------- */

static int
wait_on_socket(curl_socket_t sockfd, int for_recv, int timeout_ms)
{
    struct timeval tv;
    fd_set         infd;
    fd_set         outfd;
    fd_set         errfd;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (int)(timeout_ms % 1000) * 1000;

    FD_ZERO(&infd);
    FD_ZERO(&outfd);
    FD_ZERO(&errfd);

    FD_SET(sockfd, &errfd);

    if(for_recv) {
        FD_SET(sockfd, &infd);
    }
    else {
        FD_SET(sockfd, &outfd);
    }

    return select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    CURLcode      res = 0;
    CurlContext * ctx = (CurlContext*)context;
    int           use_tls = 0;

    if (context == NULL || host == NULL || *host == '\0') {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (ctx->mqttCtx == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (port == MQTT_SECURE_PORT) { use_tls = 1; }

#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
    PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
           host, port, timeout_ms, 0);
#endif

    ctx->curl = curl_easy_init();

    if (ctx->curl == NULL) {
        PRINTF("error: curl_easy_init returned NULL");
        return MQTT_CODE_ERROR_MEMORY;
    }

    res = curl_easy_setopt(ctx->curl, CURLOPT_VERBOSE, 1L);
    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(VERBOSE, 1L) returned: %d, %s",
               res, curl_easy_strerror(res));
        return MQTT_CODE_ERROR_CURL;
    }

    if (timeout_ms != 0) {
        res = curl_easy_setopt(ctx->curl, CURLOPT_CONNECTTIMEOUT_MS,
                               timeout_ms);
        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(CONNECTTIMEOUT_MS, %d) "
                   "returned %d", timeout_ms, res);
            return MQTT_CODE_ERROR_CURL;
        }

        res = curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT_MS,
                               timeout_ms);
        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(TIMEOUT_MS, %d) "
                   "returned %d", timeout_ms, res);
            return MQTT_CODE_ERROR_CURL;
        }
    }

    res = curl_easy_setopt(ctx->curl, CURLOPT_URL, host);
    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(URL, %s) returned: %d",
               host, res);
        return MQTT_CODE_ERROR_CURL;
    }

    res = curl_easy_setopt(ctx->curl, CURLOPT_PORT, port);
    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(PORT, %d) returned: %d",
               port, res);
        return MQTT_CODE_ERROR_CURL;
    }

    if (use_tls) {
        res = curl_easy_setopt(ctx->curl, CURLOPT_SSLVERSION,
                               CURL_SSLVERSION_TLSv1_2);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(SSLVERSION) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }

        /* With CURLOPT_CONNECT_ONLY this means do TLS by default. */
        res = curl_easy_setopt(ctx->curl, CURLOPT_DEFAULT_PROTOCOL,
                               "https");

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(DEFAULT_PROTOCOL) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }

        /* Set path to Certificate Authority (CA) file bundle. */
        if (ctx->mqttCtx->ca_file != NULL) {
            res = curl_easy_setopt(ctx->curl, CURLOPT_CAINFO,
                                   ctx->mqttCtx->ca_file);

            if (res != CURLE_OK) {
                PRINTF("error: curl_easy_setopt(CAINFO) returned: %d",
                       res);
                return MQTT_CODE_ERROR_CURL;
            }
        }

        /* Set path to dir holding CA files.
         * Unused at the moment. */
        /*
        if (ctx->mqttCtx->ca_path != NULL) {
            res = curl_easy_setopt(ctx->curl, CURLOPT_CAPATH,
                                   ctx->mqttCtx->ca_path);

            if (res != CURLE_OK) {
                PRINTF("error: curl_easy_setopt(CAPATH) returned: %d",
                       res);
                return MQTT_CODE_ERROR_CURL;
            }
        }
        */

        /* Require peer and host verification. */
        res = curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 1);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(SSL_VERIFYPEER) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }

        res = curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, 2);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(SSL_VERIFYHOST) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }
    }

    res = curl_easy_setopt(ctx->curl, CURLOPT_CONNECT_ONLY, 1);
    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(CONNECT_ONLY, 1) returned: %d",
               res);
        return MQTT_CODE_ERROR_CURL;
    }

    res = curl_easy_perform(ctx->curl);
    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_perform returned: %d, %s", res,
               curl_easy_strerror(res));
        return MQTT_CODE_ERROR_CURL;
    }

    ctx->stat = SOCK_CONN;
    return MQTT_CODE_SUCCESS;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    CURLcode res = 0;
    CurlContext * ctx = (CurlContext*)context;
    size_t sent = 0;
    curl_socket_t sockfd = 0;

    if (context == NULL || buf == NULL || buf_len == 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* get the active socket from libcurl */
    res = curl_easy_getinfo(ctx->curl, CURLINFO_ACTIVESOCKET, &sockfd);
    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_getinfo(CURLINFO_ACTIVESOCKET) returned %d",
               res);
        return MQTT_CODE_ERROR_CURL;
    }

    /* check it makes sense */
    if (sockfd <= 0) {
        PRINTF("error: libcurl sockfd: %d", sockfd);
        return MQTT_CODE_ERROR_CURL;
    }

#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
    PRINTF("ctx->curl = %lld, sockfd = %d", (long long) ctx->curl, sockfd);
#endif

    /* A very simple retry with timeout example. This assumes the entire
     * payload will be transfered in a single shot without buffering. */
    for (size_t i = 0; i < MQTT_CURL_NUM_RETRY; ++i) {
        res = curl_easy_send(ctx->curl, buf, buf_len, &sent);

        if (res == CURLE_OK) {
#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
            PRINTF("info: curl_easy_send(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
#endif
            break;
        }

        if (res == CURLE_AGAIN) {
#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
            PRINTF("info: curl_easy_send(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
#endif

            if (wait_on_socket(sockfd, 0, timeout_ms) >= 0) {
                continue;
            }
        }

        PRINTF("error: curl_easy_send(%d) returned: %d, %s", buf_len, res,
               curl_easy_strerror(res));
        return MQTT_CODE_ERROR_CURL;
    }

    if ((int) sent != buf_len) {
        PRINTF("error: sent %d bytes, expected %d", (int)sent, buf_len);
        return MQTT_CODE_ERROR_CURL;
    }

    return buf_len;
}

static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    CURLcode      res = 0;
    CurlContext * ctx = (CurlContext*)context;
    size_t        recvd = 0;
    curl_socket_t sockfd = 0;

    if (context == NULL || buf == NULL || buf_len == 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* get the active socket from libcurl */
    res = curl_easy_getinfo(ctx->curl, CURLINFO_ACTIVESOCKET, &sockfd);
    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_getinfo(CURLINFO_ACTIVESOCKET) returned %d",
               res);
        return MQTT_CODE_ERROR_CURL;
    }

    /* check it makes sense */
    if (sockfd <= 0) {
        PRINTF("error: libcurl sockfd: %d", sockfd);
        return MQTT_CODE_ERROR_CURL;
    }

#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
    PRINTF("ctx->curl = %lld, sockfd = %d", (long long) ctx->curl, sockfd);
#endif

    /* A very simple retry with timeout example. This assumes the entire
     * payload will be transfered in a single shot without buffering. */
    for (size_t i = 0; i < MQTT_CURL_NUM_RETRY; ++i) {
        res = curl_easy_recv(ctx->curl, buf, buf_len, &recvd);

        if (res == CURLE_OK) {
#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
            PRINTF("info: curl_easy_recv(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
#endif
            break;
        }

        if (res == CURLE_AGAIN) {
#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
            PRINTF("info: curl_easy_recv(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
#endif

            if (wait_on_socket(sockfd, 1, timeout_ms) >= 0) {
                continue;
            }
        }

        PRINTF("error: curl_easy_recv(%d) returned: %d, %s", buf_len, res,
               curl_easy_strerror(res));
        return MQTT_CODE_ERROR_CURL;
    }

    if ((int) recvd != buf_len) {
        PRINTF("error: recvd %d bytes, expected %d", (int)recvd, buf_len);
        return MQTT_CODE_ERROR_CURL;
    }

    return buf_len;
}

static int NetDisconnect(void *context)
{
    CurlContext * ctx = (CurlContext*)context;

    if (ctx == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (ctx->curl != NULL) {
#if defined(WOLFMQTT_DEBUG_CURL_VERBOSE)
        PRINTF("info: curl_easy_cleanup");
#endif
        curl_easy_cleanup(ctx->curl);
        ctx->curl = NULL;
    }

    return 0;
}

/* Public Functions */
int MqttClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx)
{
    if (net) {
        CurlContext* curlCtx;

        XMEMSET(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;

        curlCtx = (CurlContext*)WOLFMQTT_MALLOC(sizeof(CurlContext));
        if (curlCtx == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        net->context = curlCtx;
        XMEMSET(curlCtx, 0, sizeof(CurlContext));
        curlCtx->curl = NULL;
        curlCtx->fd = SOCKET_INVALID;
        curlCtx->stat = SOCK_BEGIN;
        curlCtx->mqttCtx = mqttCtx;
    }

    return MQTT_CODE_SUCCESS;
}

int MqttClientNet_DeInit(MqttNet* net)
{
    if (net) {
        if (net->context) {
            WOLFMQTT_FREE(net->context);
        }
        XMEMSET(net, 0, sizeof(MqttNet));
    }
    return 0;
}

int MqttClientNet_Wake(MqttNet* net)
{
    (void)net;
    return 0;
}
