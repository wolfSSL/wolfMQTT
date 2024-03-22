/* mqttnet.c
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

#include "examples/mqttnet.h"

#if 0 /* TODO: add multicast support */
typedef struct MulticastCtx {

} MulticastCtx;
#endif

#ifndef WOLFMQTT_TEST_NONBLOCK_TIMES
    #define WOLFMQTT_TEST_NONBLOCK_TIMES 1
#endif

/* Private functions */

/* -------------------------------------------------------------------------- */
/* FREERTOS TCP NETWORK CALLBACK EXAMPLE */
/* -------------------------------------------------------------------------- */
#ifdef FREERTOS_TCP

#ifndef WOLFMQTT_NO_TIMEOUT
    static SocketSet_t gxFDSet = NULL;
#endif
static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    uint32_t hostIp = 0;
    int rc = -1;
    MQTTCtx* mqttCtx = sock->mqttCtx;

    switch (sock->stat) {
    case SOCK_BEGIN:
        if (mqttCtx->debug_on) {
            PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
                host, port, timeout_ms, mqttCtx->use_tls);
        }

        hostIp = FreeRTOS_gethostbyname_a(host, NULL, 0, 0);
        if (hostIp == 0)
            break;

        sock->addr.sin_family = FREERTOS_AF_INET;
        sock->addr.sin_port = FreeRTOS_htons(port);
        sock->addr.sin_addr = hostIp;

        /* Create socket */
        sock->fd = FreeRTOS_socket(sock->addr.sin_family, FREERTOS_SOCK_STREAM,
                                   FREERTOS_IPPROTO_TCP);

        if (sock->fd == FREERTOS_INVALID_SOCKET)
            break;

#ifndef WOLFMQTT_NO_TIMEOUT
        /* Set timeouts for socket */
        timeout_ms = pdMS_TO_TICKS(timeout_ms);
        FreeRTOS_setsockopt(sock->fd, 0, FREERTOS_SO_SNDTIMEO,
            (void*)&timeout_ms, sizeof(timeout_ms));
        FreeRTOS_setsockopt(sock->fd, 0, FREERTOS_SO_RCVTIMEO,
            (void*)&timeout_ms, sizeof(timeout_ms));
#else
        (void)timeout_ms;
#endif
        sock->stat = SOCK_CONN;

        FALL_THROUGH;
    case SOCK_CONN:
        /* Start connect */
        rc = FreeRTOS_connect(sock->fd, (SOCK_ADDR_IN*)&sock->addr,
                              sizeof(sock->addr));
        break;
    }

    return rc;
}

static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc = -1, timeout = 0;
    word32 bytes = 0;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifndef WOLFMQTT_NO_TIMEOUT
    /* Create the set of sockets that will be passed into FreeRTOS_select(). */
    if (gxFDSet == NULL)
        gxFDSet = FreeRTOS_CreateSocketSet();
    if (gxFDSet == NULL)
        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
    timeout_ms = pdMS_TO_TICKS(timeout_ms); /* convert ms to ticks */
#else
    (void)timeout_ms;
#endif

    /* Loop until buf_len has been read, error or timeout */
    while ((bytes < buf_len) && (timeout == 0)) {

#ifndef WOLFMQTT_NO_TIMEOUT
        /* set the socket to do used */
        FreeRTOS_FD_SET(sock->fd, gxFDSet, eSELECT_READ | eSELECT_EXCEPT);

        /* Wait for any event within the socket set. */
        rc = FreeRTOS_select(gxFDSet, timeout_ms);
        if (rc != 0) {
            if (FreeRTOS_FD_ISSET(sock->fd, gxFDSet))
#endif
            {
                /* Try and read number of buf_len provided,
                    minus what's already been read */
                rc = (int)FreeRTOS_recv(sock->fd, &buf[bytes],
                    buf_len - bytes, 0);

                if (rc <= 0) {
                    break; /* Error */
                }
                else {
                    bytes += rc; /* Data */
                }
            }
#ifndef WOLFMQTT_NO_TIMEOUT
        }
        else {
            timeout = 1;
        }
#endif
    }

    if (rc == 0 || timeout) {
        rc = MQTT_CODE_ERROR_TIMEOUT;
    }
    else if (rc < 0) {
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == -pdFREERTOS_ERRNO_EWOULDBLOCK) {
            return MQTT_CODE_CONTINUE;
        }
    #endif
        PRINTF("NetRead: Error %d", rc);
        rc = MQTT_CODE_ERROR_NETWORK;
    }
    else {
        rc = bytes;
    }

    return rc;
}

static int NetWrite(void *context, const byte* buf, int buf_len, int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc = -1;

    (void)timeout_ms;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    rc = (int)FreeRTOS_send(sock->fd, buf, buf_len, 0);

    if (rc < 0) {
    #ifdef WOLFMQTT_NONBLOCK
        if (rc == -pdFREERTOS_ERRNO_EWOULDBLOCK) {
            return MQTT_CODE_CONTINUE;
        }
    #endif
        PRINTF("NetWrite: Error %d", rc);
        rc = MQTT_CODE_ERROR_NETWORK;
    }

    return rc;
}

static int NetDisconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    if (sock) {
        FreeRTOS_closesocket(sock->fd);
        sock->stat = SOCK_BEGIN;
    }

#ifndef WOLFMQTT_NO_TIMEOUT
    if (gxFDSet != NULL) {
        FreeRTOS_DeleteSocketSet(gxFDSet);
        gxFDSet = NULL;
    }
#endif

    return 0;
}


/* -------------------------------------------------------------------------- */
/* MICROCHIP HARMONY TCP NETWORK CALLBACK EXAMPLE */
/* -------------------------------------------------------------------------- */
#elif defined(MICROCHIP_MPLAB_HARMONY)

static int NetDisconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    if (sock) {
        if (sock->fd != SOCKET_INVALID) {
            closesocket(sock->fd);
            sock->fd = SOCKET_INVALID;
        }

        sock->stat = SOCK_BEGIN;
    }
    return 0;
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int type = SOCK_STREAM;
    int rc = MQTT_CODE_ERROR_NETWORK;
    struct addrinfo hints;
    struct hostent *hostInfo;
    MQTTCtx* mqttCtx = sock->mqttCtx;

    /* Get address information for host and locate IPv4 */
    switch(sock->stat) {
        case SOCK_BEGIN:
        {
            if (mqttCtx->debug_on) {
                PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, "
                        "Use TLS %d", host, port, timeout_ms, mqttCtx->use_tls);
            }
            XMEMSET(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            XMEMSET(&sock->addr, 0, sizeof(sock->addr));
            sock->addr.sin_family = AF_INET;

            hostInfo = gethostbyname((char *)host);
            if (hostInfo != NULL) {
                sock->addr.sin_port = port; /* htons(port); */
                sock->addr.sin_family = AF_INET;
                XMEMCPY(&sock->addr.sin_addr.S_un,
                        *(hostInfo->h_addr_list), sizeof(IPV4_ADDR));
            }
            else {
                return MQTT_CODE_CONTINUE;
            }

            /* Create socket */
            sock->fd = SOCK_OPEN(sock->addr.sin_family, type, 0);
            if (sock->fd == SOCKET_INVALID)
                goto exit;

            sock->stat = SOCK_CONN;
        }
        FALL_THROUGH;

        case SOCK_CONN:
        {
            /* Start connect */
            rc = SOCK_CONNECT(sock->fd, (struct sockaddr*)&sock->addr,
                sizeof(sock->addr));
            break;
        }

        default:
            rc = MQTT_CODE_ERROR_BAD_ARG;
            break;
    } /* switch */

    (void)timeout_ms;

exit:

    /* check for error */
    if (rc != 0) {
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            return MQTT_CODE_CONTINUE;
        }
        NetDisconnect(context);

        /* Show error */
        PRINTF("NetConnect: Rc=%d, ErrNo=%d", rc, errno);
    }

    return rc;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    rc = (int)send(sock->fd, buf, (size_t)buf_len, 0);
    if (rc <= 0) {
        /* Check for in progress */
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            return MQTT_CODE_CONTINUE;
        }

        PRINTF("NetWrite Error: Rc %d, BufLen %d, ErrNo %d", rc, buf_len, errno);
        rc = MQTT_CODE_ERROR_NETWORK;
    }

    (void)timeout_ms;

    return rc;
}

static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc = MQTT_CODE_ERROR_NETWORK;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    rc = (int)recv(sock->fd,
                   &buf[sock->bytes],
                   (size_t)(buf_len - sock->bytes),
                   0);
    if (rc < 0) {
        if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
            return MQTT_CODE_CONTINUE;
        }

        PRINTF("NetRead Error: Rc %d, BufLen %d, ErrNo %d", rc, buf_len, errno);
        rc = MQTT_CODE_ERROR_NETWORK;
    }
    else {
        /* Try and build entire recv buffer before returning success */
        sock->bytes += rc;
        if (sock->bytes < buf_len) {
            return MQTT_CODE_CONTINUE;
        }
        rc = sock->bytes;
        sock->bytes = 0;
    }

    (void)timeout_ms;

    return rc;
}


/* -------------------------------------------------------------------------- */
/* CURL EASY SOCKET BACKEND EXAMPLE */
/* -------------------------------------------------------------------------- */
#elif defined(ENABLE_MQTT_CURL)

/* How many times to retry after a timeout. */
#define MQTT_CURL_NUM_RETRY (2)

#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_TEST_NONBLOCK)
/* Tells the calling function to either return early with
 * MQTT_CODE_CONTINUE, or proceed with a smaller buffer read/write.
 * Used for testing nonblocking. */
static int
mqttcurl_test_nonblock_read(int* buf_len)
{
    static int testNbReadAlt = 0;
    static int testSmallerRead = 0;

    if (testNbReadAlt < WOLFMQTT_TEST_NONBLOCK_TIMES) {
        testNbReadAlt++;
        #if defined(WOLFMQTT_DEBUG_SOCKET)
        PRINTF("mqttcurl_test_nonblock_read: returning early with CONTINUE");
        #endif
        return MQTT_CODE_CONTINUE;
    }

    testNbReadAlt = 0;

    if (!testSmallerRead) {
        if (*buf_len > 2) {
            *buf_len /= 2;
            testSmallerRead = 1;
        #if defined(WOLFMQTT_DEBUG_SOCKET)
            PRINTF("mqttcurl_test_nonblock_read: testing small buff: %d",
                   *buf_len);
        #endif
        }
    }
    else {
        testSmallerRead = 0;
    }

    return MQTT_CODE_SUCCESS;
}

static int
mqttcurl_test_nonblock_write(int* buf_len)
{
    static int testNbWriteAlt = 0;
    static int testSmallerWrite = 0;

    if (testNbWriteAlt < WOLFMQTT_TEST_NONBLOCK_TIMES) {
        testNbWriteAlt++;
        #if defined(WOLFMQTT_DEBUG_SOCKET)
        PRINTF("mqttcurl_test_nonblock_write: returning early with CONTINUE");
        #endif
        return MQTT_CODE_CONTINUE;
    }

    testNbWriteAlt = 0;

    if (!testSmallerWrite) {
        if (*buf_len > 2) {
            *buf_len /= 2;
            testSmallerWrite = 1;
        #if defined(WOLFMQTT_DEBUG_SOCKET)
            PRINTF("mqttcurl_test_nonblock_write: testing small buff: %d",
                   *buf_len);
        #endif
        }
    }
    else {
        testSmallerWrite = 0;
    }

    return MQTT_CODE_SUCCESS;
}

#endif /* WOLFMQTT_NONBLOCK && WOLFMQTT_TEST_NONBLOCK */

static int
mqttcurl_wait(curl_socket_t sockfd, int for_recv, int timeout_ms,
              int test_mode)
{
    struct timeval tv;
    fd_set         infd;
    fd_set         outfd;
    fd_set         errfd;
    int            rc = 0;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (int)(timeout_ms % 1000) * 1000;

    FD_ZERO(&infd);
    FD_ZERO(&outfd);
    FD_ZERO(&errfd);

    FD_SET(sockfd, &errfd);

    if (for_recv) {
        FD_SET(sockfd, &infd);
        #ifdef WOLFMQTT_ENABLE_STDIN_CAP
        if (!test_mode) {
            FD_SET(STDIN, &infd);
        }
        #endif /* WOLFMQTT_ENABLE_STDIN_CAP */
    }
    else {
        FD_SET(sockfd, &outfd);
    }

    rc = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);

    if (rc > 0) {
        if (for_recv && FD_ISSET(sockfd, &infd)) {
            return MQTT_CODE_CONTINUE;
        }
        else if (!for_recv && FD_ISSET(sockfd, &outfd)) {
            return MQTT_CODE_CONTINUE;
        }
        #ifdef WOLFMQTT_ENABLE_STDIN_CAP
        else if (for_recv && !test_mode && FD_ISSET(STDIN, &infd)) {
            return MQTT_CODE_STDIN_WAKE;
        }
        #endif /* WOLFMQTT_ENABLE_STDIN_CAP */
        else if (FD_ISSET(sockfd, &errfd)) {
            return MQTT_CODE_ERROR_NETWORK;
        }
    }
    else if (rc == 0) {
        return MQTT_CODE_ERROR_TIMEOUT;
    }

    #ifndef WOLFMQTT_ENABLE_STDIN_CAP
    (void)test_mode;
    #endif

    return MQTT_CODE_ERROR_NETWORK;
}

static int
mqttcurl_connect(SocketContext* sock, const char* host, word16 port,
    int timeout_ms)
{
    CURLcode res = CURLE_OK;

    if (sock == NULL || sock->curl == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifdef DEBUG_WOLFMQTT
    res = curl_easy_setopt(sock->curl, CURLOPT_VERBOSE, 1L);

    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(VERBOSE, 1L) returned: %d, %s",
               res, curl_easy_strerror(res));
        return MQTT_CODE_ERROR_CURL;
    }
#endif

    if (timeout_ms != 0) {
        res = curl_easy_setopt(sock->curl, CURLOPT_CONNECTTIMEOUT_MS,
                               timeout_ms);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(CONNECTTIMEOUT_MS, %d) "
                   "returned %d", timeout_ms, res);
            return MQTT_CODE_ERROR_CURL;
        }

        res = curl_easy_setopt(sock->curl, CURLOPT_TIMEOUT_MS,
                               timeout_ms);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(TIMEOUT_MS, %d) "
                   "returned %d", timeout_ms, res);
            return MQTT_CODE_ERROR_CURL;
        }
    }

    res = curl_easy_setopt(sock->curl, CURLOPT_URL, host);

    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(URL, %s) returned: %d",
               host, res);
        return MQTT_CODE_ERROR_CURL;
    }

    res = curl_easy_setopt(sock->curl, CURLOPT_PORT, port);

    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(PORT, %d) returned: %d",
               port, res);
        return MQTT_CODE_ERROR_CURL;
    }

    #ifdef ENABLE_MQTT_TLS
    if (sock->mqttCtx->use_tls) {
        /* Set TLS specific options. */
        res = curl_easy_setopt(sock->curl, CURLOPT_SSLVERSION,
                               CURL_SSLVERSION_TLSv1_2);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(SSLVERSION) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }

        /* With CURLOPT_CONNECT_ONLY this means do TLS by default. */
        res = curl_easy_setopt(sock->curl, CURLOPT_DEFAULT_PROTOCOL,
                               "https");

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(DEFAULT_PROTOCOL) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }

        /* Set path to Certificate Authority (CA) file bundle. */
        if (sock->mqttCtx->ca_file != NULL) {
            res = curl_easy_setopt(sock->curl, CURLOPT_CAINFO,
                                   sock->mqttCtx->ca_file);

            if (res != CURLE_OK) {
                PRINTF("error: curl_easy_setopt(CAINFO) returned: %d",
                       res);
                return MQTT_CODE_ERROR_CURL;
            }
        }

        /* Set path to mutual TLS keyfile. */
        if (sock->mqttCtx->mtls_keyfile != NULL) {
            res = curl_easy_setopt(sock->curl, CURLOPT_SSLKEY,
                                   sock->mqttCtx->mtls_keyfile);

            if (res != CURLE_OK) {
                PRINTF("error: curl_easy_setopt(CURLOPT_SSLKEY) returned: %d",
                       res);
                return MQTT_CODE_ERROR_CURL;
            }
        }

        /* Set path to mutual TLS certfile. */
        if (sock->mqttCtx->mtls_certfile != NULL) {
            res = curl_easy_setopt(sock->curl, CURLOPT_SSLCERT,
                                   sock->mqttCtx->mtls_certfile);

            if (res != CURLE_OK) {
                PRINTF("error: curl_easy_setopt(CURLOPT_SSLCERT) returned: %d",
                       res);
                return MQTT_CODE_ERROR_CURL;
            }
        }

        /* Set path to dir holding CA files.
         * Unused at the moment. */
        /*
        if (sock->mqttCtx->ca_path != NULL) {
            res = curl_easy_setopt(sock->curl, CURLOPT_CAPATH,
                                   sock->mqttCtx->ca_path);

            if (res != CURLE_OK) {
                PRINTF("error: curl_easy_setopt(CAPATH) returned: %d",
                       res);
                return MQTT_CODE_ERROR_CURL;
            }
        }
        */

        /* Set peer and host verification. */
        res = curl_easy_setopt(sock->curl, CURLOPT_SSL_VERIFYPEER, 1);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(SSL_VERIFYPEER) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }

        /* Only do server host verification when not running against
         * localhost broker. */
        if (XSTRCMP(host, "localhost") == 0) {
            res = curl_easy_setopt(sock->curl, CURLOPT_SSL_VERIFYHOST, 0);
        }
        else {
            res = curl_easy_setopt(sock->curl, CURLOPT_SSL_VERIFYHOST, 2);
        }

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(SSL_VERIFYHOST) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }
    }
    #endif /* ENABLE_MQTT_TLS */

    #if 0
    /* Set proxy options.
     * Unused at the moment. */
    if (sock->mqttCtx->use_proxy) {
        /* Set the proxy hostname or ip address string. Append
         * ":[port num]" to the string to specify a port. */
        res = curl_easy_setopt(sock->curl, CURLOPT_PROXY,
                               sock->mqttCtx->proxy_str);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(CURLOPT_PROXY, %s) returned: %d",
                   res, sock->mqttCtx->proxy_str);
            return MQTT_CODE_ERROR_CURL;
        }

        /* Set the proxy type. E.g. CURLPROXY_HTTP, CURLPROXY_HTTPS,
         * CURLPROXY_HTTPS2, etc. */
        res = curl_easy_setopt(sock->curl, CURLOPT_PROXYTYPE,
                               CURLPROXY_HTTP);

        if (res != CURLE_OK) {
            PRINTF("error: curl_easy_setopt(CURLOPT_PROXYTYPE) returned: %d",
                   res);
            return MQTT_CODE_ERROR_CURL;
        }
    }
    #endif

    res = curl_easy_setopt(sock->curl, CURLOPT_CONNECT_ONLY, 1);

    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_setopt(CONNECT_ONLY, 1) returned: %d",
               res);
        return MQTT_CODE_ERROR_CURL;
    }

    /* Finally do the connection. */
    res = curl_easy_perform(sock->curl);

    if (res != CURLE_OK) {
        PRINTF("error: curl_easy_perform returned: %d, %s", res,
               curl_easy_strerror(res));
        return MQTT_CODE_ERROR_CURL;
    }

    return MQTT_CODE_SUCCESS;
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext * sock = (SocketContext*)context;
    int             rc = 0;

    if (context == NULL || host == NULL || *host == '\0') {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (sock->mqttCtx == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#if defined(WOLFMQTT_DEBUG_SOCKET)
    PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
           host, port, timeout_ms, sock->mqttCtx->use_tls);
#endif

    sock->curl = curl_easy_init();

    if (sock->curl == NULL) {
        PRINTF("error: curl_easy_init returned NULL");
        return MQTT_CODE_ERROR_MEMORY;
    }

    rc = mqttcurl_connect(sock, host, port, timeout_ms);

    if (rc != MQTT_CODE_SUCCESS) {
        curl_easy_cleanup(sock->curl);
        sock->curl = NULL;
        return rc;
    }

    sock->stat = SOCK_CONN;
    return MQTT_CODE_SUCCESS;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    CURLcode        res = CURLE_OK;
    SocketContext * sock = (SocketContext*)context;
    size_t          sent = 0;
    curl_socket_t   sockfd = 0;
    int             wait_rc = 0;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_TEST_NONBLOCK)
    if (sock->mqttCtx->useNonBlockMode) {
        if (mqttcurl_test_nonblock_write(&buf_len)) {
            return MQTT_CODE_CONTINUE;
        }
    }
#endif /* WOLFMQTT_NONBLOCK && WOLFMQTT_TEST_NONBLOCK */

    /* get the active socket from libcurl */
    res = curl_easy_getinfo(sock->curl, CURLINFO_ACTIVESOCKET, &sockfd);
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

#if defined(WOLFMQTT_DEBUG_SOCKET)
    PRINTF("sock->curl = %p, sockfd = %d", (void *)sock->curl, sockfd);
#endif

    /* A very simple retry with timeout example. This assumes the entire
     * payload will be transferred in a single shot without buffering.
     * todo: add buffering? */
    for (size_t i = 0; i < MQTT_CURL_NUM_RETRY; ++i) {
    #ifdef WOLFMQTT_MULTITHREAD
        int rc = wm_SemLock(&sock->mqttCtx->client.lockCURL);
        if (rc != 0) {
            return rc;
        }
    #endif

        res = curl_easy_send(sock->curl, buf, buf_len, &sent);

    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&sock->mqttCtx->client.lockCURL);
    #endif

        if (res == CURLE_OK) {
            #if defined(WOLFMQTT_DEBUG_SOCKET)
            PRINTF("info: curl_easy_send(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
            #endif
            break;
        }

        if (res == CURLE_AGAIN) {
            #if defined(WOLFMQTT_DEBUG_SOCKET)
            PRINTF("info: curl_easy_send(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
            #endif

            wait_rc = mqttcurl_wait(sockfd, 0, timeout_ms,
                                    sock->mqttCtx->test_mode);

            if (wait_rc == MQTT_CODE_CONTINUE) {
                continue;
            }
            else {
                return wait_rc;
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
    CURLcode        res = CURLE_OK;
    SocketContext * sock = (SocketContext*)context;
    size_t          recvd = 0;
    curl_socket_t   sockfd = 0;
    int             wait_rc = 0;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_TEST_NONBLOCK)
    if (sock->mqttCtx->useNonBlockMode) {
        if (mqttcurl_test_nonblock_read(&buf_len)) {
            return MQTT_CODE_CONTINUE;
        }
    }
#endif /* WOLFMQTT_NONBLOCK && WOLFMQTT_TEST_NONBLOCK */

    /* get the active socket from libcurl */
    res = curl_easy_getinfo(sock->curl, CURLINFO_ACTIVESOCKET, &sockfd);
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

#if defined(WOLFMQTT_DEBUG_SOCKET)
    PRINTF("sock->curl = %p, sockfd = %d", (void *)sock->curl, sockfd);
#endif

    /* A very simple retry with timeout example. This assumes the entire
     * payload will be transferred in a single shot without buffering.
     * todo: add buffering? */
    for (size_t i = 0; i < MQTT_CURL_NUM_RETRY; ++i) {
    #ifdef WOLFMQTT_MULTITHREAD
        int rc = wm_SemLock(&sock->mqttCtx->client.lockCURL);
        if (rc != 0) {
            return rc;
        }
    #endif

        res = curl_easy_recv(sock->curl, buf, buf_len, &recvd);

    #ifdef WOLFMQTT_MULTITHREAD
        wm_SemUnlock(&sock->mqttCtx->client.lockCURL);
    #endif

        if (res == CURLE_OK) {
            #if defined(WOLFMQTT_DEBUG_SOCKET)
            PRINTF("info: curl_easy_recv(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
            #endif
            break;
        }

        if (res == CURLE_AGAIN) {
            #if defined(WOLFMQTT_DEBUG_SOCKET)
            PRINTF("info: curl_easy_recv(%d) returned: %d, %s", buf_len, res,
                   curl_easy_strerror(res));
            #endif

            wait_rc = mqttcurl_wait(sockfd, 1, timeout_ms,
                                    sock->mqttCtx->test_mode);

            if (wait_rc == MQTT_CODE_CONTINUE) {
                continue;
            }
            else {
                return wait_rc;
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
    SocketContext * sock = (SocketContext*)context;

    if (sock == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (sock->curl != NULL) {
#if defined(WOLFMQTT_DEBUG_SOCKET)
        PRINTF("info: curl_easy_cleanup");
#endif
        curl_easy_cleanup(sock->curl);
        sock->curl = NULL;
    }

    return 0;
}

/* -------------------------------------------------------------------------- */
/* GENERIC BSD SOCKET TCP NETWORK CALLBACK EXAMPLE */
/* -------------------------------------------------------------------------- */
#else

#ifndef WOLFMQTT_NO_TIMEOUT
static void tcp_setup_timeout(struct timeval* tv, int timeout_ms)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms % 1000) * 1000;

    /* Make sure there is a minimum value specified */
    if (tv->tv_sec < 0 || (tv->tv_sec == 0 && tv->tv_usec <= 0)) {
        tv->tv_sec = 0;
        tv->tv_usec = 100;
    }
}

static void tcp_set_fds(SocketContext* sock, fd_set* recvfds, fd_set* errfds)
{
    /* Setup select file descriptors to watch */
    FD_ZERO(errfds);
    FD_SET(sock->fd, errfds);
    FD_ZERO(recvfds);
    FD_SET(sock->fd, recvfds);
#ifdef WOLFMQTT_ENABLE_STDIN_CAP
    #ifdef WOLFMQTT_MULTITHREAD
        FD_SET(sock->pfd[0], recvfds);
    #endif
    if (!sock->mqttCtx->test_mode) {
        FD_SET(STDIN, recvfds);
    }
#endif /* WOLFMQTT_ENABLE_STDIN_CAP */
}

#ifdef WOLFMQTT_NONBLOCK
static void tcp_set_nonblocking(SOCKET_T* sockfd)
{
#ifdef USE_WINDOWS_API
    unsigned long blocking = 1;
    int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
    if (ret == SOCKET_ERROR)
        PRINTF("ioctlsocket failed!");
#else
    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags < 0)
        PRINTF("fcntl get failed!");
    flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0)
        PRINTF("fcntl set failed!");
#endif
}
#endif /* WOLFMQTT_NONBLOCK */
#endif /* !WOLFMQTT_NO_TIMEOUT */

static int NetDisconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    if (sock) {
        if (sock->fd != SOCKET_INVALID) {
            SOCK_CLOSE(sock->fd);
            sock->fd = SOCKET_INVALID;
        }

        sock->stat = SOCK_BEGIN;
    }
    return 0;
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int type = SOCK_STREAM;
    int rc = -1;
    SOERROR_T so_error = 0;
    struct addrinfo *result = NULL;
    struct addrinfo hints;
    MQTTCtx* mqttCtx = sock->mqttCtx;

    /* Get address information for host and locate IPv4 */
    switch(sock->stat) {
        case SOCK_BEGIN:
        {
            if (mqttCtx->debug_on) {
                PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, "
                        "Use TLS %d", host, port, timeout_ms, mqttCtx->use_tls);
            }

            XMEMSET(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            XMEMSET(&sock->addr, 0, sizeof(sock->addr));
            sock->addr.sin_family = AF_INET;

            rc = getaddrinfo(host, NULL, &hints, &result);
            if (rc == 0) {
                struct addrinfo* result_i = result;

                if (! result) {
                    rc = -1;
                    goto exit;
                }

                /* prefer ip4 addresses */
                while (result_i) {
                    if (result_i->ai_family == AF_INET)
                        break;
                    result_i = result_i->ai_next;
                }

                if (result_i) {
                    sock->addr.sin_port = htons(port);
                    sock->addr.sin_family = AF_INET;
                    sock->addr.sin_addr =
                        ((SOCK_ADDR_IN*)(result_i->ai_addr))->sin_addr;
                }
                else {
                    rc = -1;
                }

                freeaddrinfo(result);
            }
            if (rc != 0)
                goto exit;

            /* Default to error */
            rc = -1;

            /* Create socket */
            sock->fd = SOCK_OPEN(sock->addr.sin_family, type, 0);
            if (sock->fd == SOCKET_INVALID)
                goto exit;

            sock->stat = SOCK_CONN;
        }
        FALL_THROUGH;

        case SOCK_CONN:
        {
        #ifndef WOLFMQTT_NO_TIMEOUT
            fd_set fdset;
            struct timeval tv;

            /* Setup timeout and FD's */
            tcp_setup_timeout(&tv, timeout_ms);
            FD_ZERO(&fdset);
            FD_SET(sock->fd, &fdset);
        #endif /* !WOLFMQTT_NO_TIMEOUT */

        #if !defined(WOLFMQTT_NO_TIMEOUT) && defined(WOLFMQTT_NONBLOCK)
            if (mqttCtx->useNonBlockMode) {
                /* Set socket as non-blocking */
                tcp_set_nonblocking(&sock->fd);
            }
        #endif

            /* Start connect */
            rc = SOCK_CONNECT(sock->fd, (struct sockaddr*)&sock->addr,
                    sizeof(sock->addr));
            if (rc < 0) {
                /* set default error case */
                rc = MQTT_CODE_ERROR_NETWORK;
        #ifdef WOLFMQTT_NONBLOCK
                {
                    /* Check for error */
                    GET_SOCK_ERROR(sock->fd, SOL_SOCKET, SO_ERROR, so_error);
                }
                if (
            #ifndef _WIN32
                        (errno == EINPROGRESS) ||
            #endif
                        SOCK_EQ_ERROR(so_error))
                {
            #ifndef WOLFMQTT_NO_TIMEOUT
                    /* Wait for connect */
                    if (select((int)SELECT_FD(sock->fd), NULL, &fdset,
                                              NULL, &tv) > 0) {
                        rc = MQTT_CODE_SUCCESS;
                    }
            #else
                    rc = MQTT_CODE_CONTINUE;
            #endif
                }
        #endif
            }
            break;
        }

        default:
            rc = -1;
    } /* switch */

    (void)timeout_ms;

exit:
    if ((rc != 0) && (rc != MQTT_CODE_CONTINUE)) {
        NetDisconnect(context);
        PRINTF("NetConnect: Rc=%d, SoErr=%d", rc, so_error); /* Show error */
    }

    return rc;
}

#ifdef WOLFMQTT_SN
static int SN_NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int type = SOCK_DGRAM;
    int rc;
    SOERROR_T so_error = 0;
    struct addrinfo *result = NULL;
    struct addrinfo hints;
    MQTTCtx* mqttCtx = sock->mqttCtx;

    PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use DTLS %d",
        host, port, timeout_ms, mqttCtx->use_tls);

    /* Get address information for host and locate IPv4 */
    XMEMSET(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */

    XMEMSET(&sock->addr, 0, sizeof(sock->addr));
    sock->addr.sin_family = AF_INET;

    rc = getaddrinfo(host, NULL, &hints, &result);
    if (rc == 0) {
        struct addrinfo* result_i = result;

        if (! result) {
            rc = -1;
            goto exit;
        }

        /* prefer ip4 addresses */
        while (result_i) {
            if (result_i->ai_family == AF_INET)
                break;
            result_i = result_i->ai_next;
        }

        if (result_i) {
            sock->addr.sin_port = htons(port);
            sock->addr.sin_family = AF_INET;
            sock->addr.sin_addr =
                ((SOCK_ADDR_IN*)(result_i->ai_addr))->sin_addr;
        }
        else {
            rc = -1;
        }

        freeaddrinfo(result);
    }
    if (rc != 0)
        goto exit;

    if (rc == 0) {
        /* Create the socket */
        sock->fd = SOCK_OPEN(sock->addr.sin_family, type, 0);
        if (sock->fd == SOCKET_INVALID) {
            rc = -1;
        }
    }

    if (rc == 0)
    {
    #ifndef WOLFMQTT_NO_TIMEOUT
        fd_set fdset;
        struct timeval tv;

        /* Setup timeout and FD's */
        tcp_setup_timeout(&tv, timeout_ms);
        FD_ZERO(&fdset);
        FD_SET(sock->fd, &fdset);
    #else
        (void)timeout_ms;
    #endif /* !WOLFMQTT_NO_TIMEOUT */

        /* Start connect */
        rc = SOCK_CONNECT(sock->fd, (struct sockaddr*)&sock->addr,
                sizeof(sock->addr));
    }

  exit:
    /* Show error */
    if ((rc != 0) && (rc != MQTT_CODE_CONTINUE)) {
        NetDisconnect(context);
        PRINTF("NetConnect: Rc=%d, SoErr=%d", rc, so_error);
    }

    return rc;
}
#endif

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    MQTTCtx* mqttCtx;
    int rc;
    SOERROR_T so_error = 0;
#ifndef WOLFMQTT_NO_TIMEOUT
    struct timeval tv;
#endif
#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_TEST_NONBLOCK)
    static int testNbWriteAlt = 0;
    static int testSmallerWrite = 0;
#endif

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (sock->fd == SOCKET_INVALID)
        return MQTT_CODE_ERROR_BAD_ARG;

    mqttCtx = sock->mqttCtx;
    (void)mqttCtx;

#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_TEST_NONBLOCK)
    if (mqttCtx->useNonBlockMode) {
        if (testNbWriteAlt < WOLFMQTT_TEST_NONBLOCK_TIMES) {
            testNbWriteAlt++;
            return MQTT_CODE_CONTINUE;
        }
        testNbWriteAlt = 0;
        if (!testSmallerWrite) {
            if (buf_len > 2) {
                buf_len /= 2;
            }
            testSmallerWrite = 1;
        }
        else {
            testSmallerWrite = 0;
        }
    }
#endif

#ifndef WOLFMQTT_NO_TIMEOUT
    /* Setup timeout */
    tcp_setup_timeout(&tv, timeout_ms);
    (void)setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,
            sizeof(tv));
#endif

    rc = (int)SOCK_SEND(sock->fd, buf, buf_len, 0);
    #if defined(WOLFMQTT_DEBUG_SOCKET)
    PRINTF("info: SOCK_SEND(%d) returned %d, buf_len is %d",
           buf_len, rc, buf_len);
    #endif
    if (rc == -1) {
        {
            /* Get error */
            GET_SOCK_ERROR(sock->fd, SOL_SOCKET, SO_ERROR, so_error);
        }
        if (so_error == 0) {
    #if defined(USE_WINDOWS_API) && defined(WOLFMQTT_NONBLOCK)
            /* assume non-blocking case */
            rc = MQTT_CODE_CONTINUE;
    #else
            rc = 0; /* Handle signal */
    #endif
        }
        else {
    #ifdef WOLFMQTT_NONBLOCK
            if (SOCK_EQ_ERROR(so_error)) {
                return MQTT_CODE_CONTINUE;
            }
    #endif
            rc = MQTT_CODE_ERROR_NETWORK;
            PRINTF("NetWrite: Error %d", so_error);
        }
    }

    (void)timeout_ms;

    return rc;
}

static int NetRead_ex(void *context, byte* buf, int buf_len,
    int timeout_ms, byte peek)
{
    SocketContext *sock = (SocketContext*)context;
    MQTTCtx* mqttCtx;
    int rc = -1, timeout = 0;
    SOERROR_T so_error = 0;
    int bytes = 0;
    int flags = 0;
#ifndef WOLFMQTT_NO_TIMEOUT
    fd_set recvfds;
    fd_set errfds;
    struct timeval tv;
#else
    (void)timeout_ms;
#endif
#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_TEST_NONBLOCK)
    static int testNbReadAlt = 0;
    static int testSmallerRead = 0;
#endif

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (sock->fd == SOCKET_INVALID)
        return MQTT_CODE_ERROR_BAD_ARG;

    if (peek == 1) {
        flags |= MSG_PEEK;
    }

    mqttCtx = sock->mqttCtx;
    (void)mqttCtx;

#if defined(WOLFMQTT_NONBLOCK) && defined(WOLFMQTT_TEST_NONBLOCK)
    if (mqttCtx->useNonBlockMode) {
        if (testNbReadAlt < WOLFMQTT_TEST_NONBLOCK_TIMES) {
            testNbReadAlt++;
            return MQTT_CODE_CONTINUE;
        }
        testNbReadAlt = 0;
        if (!testSmallerRead) {
            if (buf_len > 2) {
                buf_len /= 2;
            }
            testSmallerRead = 1;
        }
        else {
            testSmallerRead = 0;
        }
    }
#endif

    /* Loop until buf_len has been read, error or timeout */
    while (bytes < buf_len) {
        int do_read = 0;

    #ifndef WOLFMQTT_NO_TIMEOUT
        #ifdef WOLFMQTT_NONBLOCK
        if (mqttCtx->useNonBlockMode) {
            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
            /* quick no timeout check if data is available on stdin */
            tcp_setup_timeout(&tv, 0);

            /* Setup select file descriptors to watch */
            tcp_set_fds(sock, &recvfds, &errfds);

            rc = select((int)SELECT_FD(sock->fd), &recvfds, NULL, &errfds, &tv);
            if (rc > 0) {
                if (FD_ISSET(sock->fd, &recvfds)) {
                    do_read = 1;
                }
                else if ((!mqttCtx->test_mode && FD_ISSET(STDIN, &recvfds))) {
                    return MQTT_CODE_STDIN_WAKE;
                }
            }
            #else
            do_read = 1;
            #endif
        }
        else
        #endif /* WOLFMQTT_NONBLOCK */
        {
            /* Wait for rx data to be available */
            tcp_setup_timeout(&tv, timeout_ms);

            /* Setup select file descriptors to watch */
            tcp_set_fds(sock, &recvfds, &errfds);

            rc = select((int)SELECT_FD(sock->fd), &recvfds, NULL, &errfds, &tv);
            if (rc > 0) {
                if (FD_ISSET(sock->fd, &recvfds)) {
                    do_read = 1;
                }
                /* Check if rx or error */
            #ifdef WOLFMQTT_ENABLE_STDIN_CAP
                else if ((!mqttCtx->test_mode && FD_ISSET(STDIN, &recvfds))
                #ifdef WOLFMQTT_MULTITHREAD
                    || FD_ISSET(sock->pfd[0], &recvfds)
                #endif
                ) {
                    return MQTT_CODE_STDIN_WAKE;
                }
            #endif
                if (FD_ISSET(sock->fd, &errfds)) {
                    rc = -1;
                    break;
                }
            }
            else {
                timeout = 1;
                break; /* timeout or signal */
            }
        }
    #else
        do_read = 1;
    #endif /* !WOLFMQTT_NO_TIMEOUT */

        if (do_read) {
            /* Try and read number of buf_len provided,
             * minus what's already been read */
            rc = (int)SOCK_RECV(sock->fd,
                           &buf[bytes],
                           buf_len - bytes,
                           flags);
            #if defined(WOLFMQTT_DEBUG_SOCKET)
            PRINTF("info: SOCK_RECV(%d) returned %d, buf_len - bytes is %d",
                   bytes, rc, buf_len - bytes);
            #endif
            if (rc <= 0) {
                rc = -1;
                goto exit; /* Error */
            }
            else {
                bytes += rc; /* Data */
    #ifdef ENABLE_MQTT_TLS
                if (MqttClient_Flags(&mqttCtx->client, 0, 0)
                    & MQTT_CLIENT_FLAG_IS_TLS) {
                    break;
                }
    #endif
            }
        }

        /* no timeout and non-block should always exit loop */
    #ifdef WOLFMQTT_NONBLOCK
        if (mqttCtx->useNonBlockMode) {
            break;
        }
    #endif
    #ifdef WOLFMQTT_NO_TIMEOUT
        break;
    #endif
    } /* while */

exit:

    if (rc == 0 && timeout) {
        rc = MQTT_CODE_ERROR_TIMEOUT;
    }
    else if (rc < 0) {
        {
            /* Get error */
            GET_SOCK_ERROR(sock->fd, SOL_SOCKET, SO_ERROR, so_error);
        }
        if (so_error == 0) {
            rc = 0; /* Handle signal */
        }
        else {
    #ifdef WOLFMQTT_NONBLOCK
            if (SOCK_EQ_ERROR(so_error)) {
                return MQTT_CODE_CONTINUE;
            }
    #endif
            rc = MQTT_CODE_ERROR_NETWORK;
            PRINTF("NetRead: Error %d", so_error);
        }
    }
    else {
        rc = bytes;
    }

    return rc;
}

static int NetRead(void *context, byte* buf, int buf_len, int timeout_ms)
{
    return NetRead_ex(context, buf, buf_len, timeout_ms, 0);
}

#ifdef WOLFMQTT_SN
static int NetPeek(void *context, byte* buf, int buf_len, int timeout_ms)
{
    return NetRead_ex(context, buf, buf_len, timeout_ms, 1);
}
#endif

#endif


/* Public Functions */
int MqttClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx)
{
#if defined(USE_WINDOWS_API) && !defined(FREERTOS_TCP)
    WSADATA wsd;
    WSAStartup(0x0002, &wsd);
#endif

#ifdef MICROCHIP_MPLAB_HARMONY
    static IPV4_ADDR    dwLastIP[2] = { {-1}, {-1} };
    IPV4_ADDR           ipAddr;
    int Dummy;
    int nNets;
    int i;
    SYS_STATUS          stat;
    TCPIP_NET_HANDLE    netH;

    stat = TCPIP_STACK_Status(sysObj.tcpip);
    if (stat < 0) {
        return MQTT_CODE_CONTINUE;
    }

    nNets = TCPIP_STACK_NumberOfNetworksGet();
    for (i = 0; i < nNets; i++) {
        netH = TCPIP_STACK_IndexToNet(i);
        ipAddr.Val = TCPIP_STACK_NetAddress(netH);
        if (ipAddr.v[0] == 0) {
            return MQTT_CODE_CONTINUE;
        }
        if (dwLastIP[i].Val != ipAddr.Val) {
            dwLastIP[i].Val = ipAddr.Val;
            PRINTF("%s", TCPIP_STACK_NetNameGet(netH));
            PRINTF(" IP Address: %d.%d.%d.%d",
                ipAddr.v[0], ipAddr.v[1], ipAddr.v[2], ipAddr.v[3]);
        }
    }
#endif /* MICROCHIP_MPLAB_HARMONY */

    if (net) {
        SocketContext* sockCtx;

        XMEMSET(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;

        sockCtx = (SocketContext*)WOLFMQTT_MALLOC(sizeof(SocketContext));
        if (sockCtx == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        net->context = sockCtx;
        XMEMSET(sockCtx, 0, sizeof(SocketContext));
#if defined(ENABLE_MQTT_CURL)
        sockCtx->curl = NULL;
#endif
        sockCtx->fd = SOCKET_INVALID;
        sockCtx->stat = SOCK_BEGIN;
        sockCtx->mqttCtx = mqttCtx;

    #if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_ENABLE_STDIN_CAP)
        /* setup the pipe for waking select() */
        if (pipe(sockCtx->pfd) != 0) {
            PRINTF("Failed to set up pipe for stdin");
            return -1;
        }
    #endif
    }

    return MQTT_CODE_SUCCESS;
}

#ifdef WOLFMQTT_SN
int SN_ClientNet_Init(MqttNet* net, MQTTCtx* mqttCtx)
{
    if (net) {
        SocketContext* sockCtx;

        XMEMSET(net, 0, sizeof(MqttNet));
        net->connect = SN_NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->peek = NetPeek;
        net->disconnect = NetDisconnect;

        sockCtx = (SocketContext*)WOLFMQTT_MALLOC(sizeof(SocketContext));
        if (sockCtx == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        net->context = sockCtx;
        XMEMSET(sockCtx, 0, sizeof(SocketContext));
        sockCtx->stat = SOCK_BEGIN;
        sockCtx->mqttCtx = mqttCtx;

    #if 0 /* TODO: add multicast support */
        MulticastCtx* multi_ctx;
        multi_ctx = (MulticastCtx*)WOLFMQTT_MALLOC(sizeof(MulticastCtx));
        if (multi_ctx == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        net->multi_ctx = multi_ctx;
        XMEMSET(multi_ctx, 0, sizeof(MulticastCtx));
        multi_ctx->stat = SOCK_BEGIN;
    #endif

    #if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_ENABLE_STDIN_CAP)
        /* setup the pipe for waking select() */
        if (pipe(sockCtx->pfd) != 0) {
            PRINTF("Failed to set up pipe for stdin");
            return -1;
        }
    #endif
    }

    return MQTT_CODE_SUCCESS;
}
#endif

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
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_ENABLE_STDIN_CAP)
    if (net) {
        SocketContext* sockCtx = (SocketContext*)net->context;
        if (sockCtx) {
            /* wake the select() */
            if (write(sockCtx->pfd[1], "\n", 1) < 0) {
                PRINTF("Failed to wake select");
                return -1;
            }
        }
    }
#else
    (void)net;
#endif
    return 0;
}
