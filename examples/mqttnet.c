/* mqttnet.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

/* FreeRTOS TCP */
#ifdef FREERTOS_TCP
    #include "FreeRTOS.h"
    #include "task.h"
    #include "FreeRTOS_IP.h"
    #include "FreeRTOS_DNS.h"
    #include "FreeRTOS_Sockets.h"

    #define SOCKET_T                     Socket_t
    #define SOCK_ADDR_IN                 struct freertos_sockaddr

/* FreeRTOS and LWIP */
#elif defined(FREERTOS) && defined(WOLFSSL_LWIP)
    /* Scheduler includes. */
    #include "FreeRTOS.h"
    #include "task.h"
    #include "semphr.h"

    /* lwIP includes. */
    #include "lwip/api.h"
    #include "lwip/tcpip.h"
    #include "lwip/memp.h"
    #include "lwip/stats.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"

/* Windows */
#elif defined(USE_WINDOWS_API)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <stdio.h>
    #define SOCKET_T        SOCKET
    #define SOERROR_T       char
    #define SELECT_FD(fd)   (fd)
    #define SOCKET_INVALID  ((SOCKET_T)INVALID_SOCKET)
    #define SOCK_CLOSE      closesocket
    #define SOCK_SEND(s,b,l,f) send((s), (const char*)(b), (size_t)(l), (f))
    #define SOCK_RECV(s,b,l,f) recv((s), (char*)(b), (size_t)(l), (f))

/* Freescale MQX / RTCS */
#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #if defined(FREESCALE_MQX)
        #include <posix.h>
    #endif
    #include <rtcs.h>
    /* Note: Use "RTCS_geterror(sock->fd);" to get error number */

/* Microchip MPLABX Harmony, TCP/IP */
#elif defined(MICROCHIP_MPLAB_HARMONY)
    #include "app.h"
    #include "system_config.h"
    #include "tcpip/tcpip.h"
    #include <sys/errno.h>
    #include <errno.h>

    #define SOCKET_INVALID (-1)
    #define SOCK_CLOSE      closesocket

    #ifndef WOLFMQTT_NONBLOCK
        #error wolfMQTT must be built with WOLFMQTT_NONBLOCK defined for Harmony
    #endif

/* Linux */
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/param.h>
    #include <sys/time.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <signal.h>
#endif

/* Setup defaults */
#ifndef SOCKET_T
    #define SOCKET_T        int
#endif
#ifndef SOERROR_T
    #define SOERROR_T       int
#endif
#ifndef SELECT_FD
    #define SELECT_FD(fd)   ((fd) + 1)
#endif
#ifndef SOCKET_INVALID
    #define SOCKET_INVALID  ((SOCKET_T)0)
#endif
#ifndef SOCK_CONNECT
    #define SOCK_CONNECT    connect
#endif
#ifndef SOCK_SEND
    #define SOCK_SEND(s,b,l,f) send((s), (b), (size_t)(l), (f))
#endif
#ifndef SOCK_RECV
    #define SOCK_RECV(s,b,l,f) recv((s), (b), (size_t)(l), (f))
#endif
#ifndef SOCK_CLOSE
    #define SOCK_CLOSE      close
#endif
#ifndef SOCK_ADDR_IN
    #define SOCK_ADDR_IN    struct sockaddr_in
#endif
#ifdef SOCK_ADDRINFO
    #define SOCK_ADDRINFO   struct addrinfo
#endif


/* Local context for Net callbacks */
typedef enum {
    SOCK_BEGIN = 0,
    SOCK_CONN,
} NB_Stat;


#if 0 /* TODO: add multicast support */
typedef struct MulticastContext {

} MulticastContext;
#endif


typedef struct _SocketContext {
    SOCKET_T fd;
    NB_Stat stat;
    SOCK_ADDR_IN addr;
#ifdef MICROCHIP_MPLAB_HARMONY
    word32 bytes;
#endif
    MQTTCtx* mqttCtx;
} SocketContext;

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
        PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
            host, port, timeout_ms, mqttCtx->use_tls);

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
            PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
                host, port, timeout_ms, mqttCtx->use_tls);

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
            sock->fd = socket(sock->addr.sin_family, type, 0);
            if (sock->fd == SOCKET_INVALID)
                goto exit;

            sock->stat = SOCK_CONN;

            FALL_THROUGH;
        }

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

/* -------------------------------------------------------------------------- */
/* GENERIC BSD SOCKET TCP NETWORK CALLBACK EXAMPLE */
/* -------------------------------------------------------------------------- */
#else

#ifndef WOLFMQTT_NO_TIMEOUT
static void setup_timeout(struct timeval* tv, int timeout_ms)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms % 1000) * 1000;

    /* Make sure there is a minimum value specified */
    if (tv->tv_sec < 0 || (tv->tv_sec == 0 && tv->tv_usec <= 0)) {
        tv->tv_sec = 0;
        tv->tv_usec = 100;
    }
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
            PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
                host, port, timeout_ms, mqttCtx->use_tls);

            XMEMSET(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            XMEMSET(&sock->addr, 0, sizeof(sock->addr));
            sock->addr.sin_family = AF_INET;

            rc = getaddrinfo(host, NULL, &hints, &result);
            if (rc >= 0 && result != NULL) {
                struct addrinfo* res = result;

                /* prefer ip4 addresses */
                while (res) {
                    if (res->ai_family == AF_INET) {
                        result = res;
                        break;
                    }
                    res = res->ai_next;
                }

                if (result->ai_family == AF_INET) {
                    sock->addr.sin_port = htons(port);
                    sock->addr.sin_family = AF_INET;
                    sock->addr.sin_addr =
                        ((SOCK_ADDR_IN*)(result->ai_addr))->sin_addr;
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
            sock->fd = socket(sock->addr.sin_family, type, 0);
            if (sock->fd == SOCKET_INVALID)
                goto exit;

            sock->stat = SOCK_CONN;

            FALL_THROUGH;
        }

        case SOCK_CONN:
        {
        #ifndef WOLFMQTT_NO_TIMEOUT
            fd_set fdset;
            struct timeval tv;

            /* Setup timeout and FD's */
            setup_timeout(&tv, timeout_ms);
            FD_ZERO(&fdset);
            FD_SET(sock->fd, &fdset);
        #endif /* !WOLFMQTT_NO_TIMEOUT */

        #if !defined(WOLFMQTT_NO_TIMEOUT) && defined(WOLFMQTT_NONBLOCK)
            /* Set socket as non-blocking */
            tcp_set_nonblocking(&sock->fd);
        #endif

            /* Start connect */
            rc = SOCK_CONNECT(sock->fd, (struct sockaddr*)&sock->addr, sizeof(sock->addr));
        #ifndef WOLFMQTT_NO_TIMEOUT
            /* Wait for connect */
            if (rc < 0 || select((int)SELECT_FD(sock->fd), NULL, &fdset, NULL, &tv) > 0)
        #else
            if (rc < 0)
        #endif /* !WOLFMQTT_NO_TIMEOUT */
            {
                /* Check for error */
                socklen_t len = sizeof(so_error);
                getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    rc = 0; /* Success */
                }
            #if !defined(WOLFMQTT_NO_TIMEOUT) && defined(WOLFMQTT_NONBLOCK)
                else if (so_error == EINPROGRESS) {
                    rc = MQTT_CODE_CONTINUE;
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
    /* Show error */
    if (rc != 0) {
        PRINTF("NetConnect: Rc=%d, SoErr=%d", rc, so_error);
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

    PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d\n",
        host, port, timeout_ms, mqttCtx->use_tls);

    /* Get address information for host and locate IPv4 */
    XMEMSET(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */

    XMEMSET(&sock->addr, 0, sizeof(sock->addr));
    sock->addr.sin_family = AF_INET;

    rc = getaddrinfo(host, NULL, &hints, &result);
    if (rc >= 0 && result != NULL) {
        struct addrinfo* res = result;

        /* prefer ip4 addresses */
        while (res) {
            if (res->ai_family == AF_INET) {
                result = res;
                break;
            }
            res = res->ai_next;
        }

        if (result->ai_family == AF_INET) {
            sock->addr.sin_port = htons(port);
            sock->addr.sin_family = AF_INET;
            sock->addr.sin_addr =
                ((SOCK_ADDR_IN*)(result->ai_addr))->sin_addr;
        }
        else {
            rc = -1;
        }

        freeaddrinfo(result);
    }

    if (rc == 0) {

    /* Create the socket */
        sock->fd = socket(sock->addr.sin_family, type, 0);
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
        setup_timeout(&tv, timeout_ms);
        FD_ZERO(&fdset);
        FD_SET(sock->fd, &fdset);
    #else
        (void)timeout_ms;
    #endif /* !WOLFMQTT_NO_TIMEOUT */

        /* Start connect */
        rc = SOCK_CONNECT(sock->fd, (struct sockaddr*)&sock->addr, sizeof(sock->addr));
    }

    /* Show error */
    if (rc != 0) {
        SOCK_CLOSE(sock->fd);
        PRINTF("NetConnect: Rc=%d, SoErr=%d", rc, so_error);
    }

    return rc;
}
#endif

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc;
    SOERROR_T so_error = 0;
#ifndef WOLFMQTT_NO_TIMEOUT
    struct timeval tv;
#endif

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

#ifndef WOLFMQTT_NO_TIMEOUT
    /* Setup timeout */
    setup_timeout(&tv, timeout_ms);
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
#endif

    rc = (int)SOCK_SEND(sock->fd, buf, buf_len, 0);
    if (rc == -1) {
        /* Get error */
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            rc = 0; /* Handle signal */
        }
        else {
        #ifdef WOLFMQTT_NONBLOCK
            if (so_error == EWOULDBLOCK || so_error == EAGAIN) {
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
    int rc = -1, timeout = 0;
    SOERROR_T so_error = 0;
    int bytes = 0;
    int flags = 0;
#if !defined(WOLFMQTT_NO_TIMEOUT) && !defined(WOLFMQTT_NONBLOCK)
    fd_set recvfds;
    fd_set errfds;
    struct timeval tv;
#endif

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (peek == 1) {
        flags |= MSG_PEEK;
    }

#if !defined(WOLFMQTT_NO_TIMEOUT) && !defined(WOLFMQTT_NONBLOCK)
    /* Setup timeout and FD's */
    setup_timeout(&tv, timeout_ms);
    FD_ZERO(&recvfds);
    FD_SET(sock->fd, &recvfds);
    FD_ZERO(&errfds);
    FD_SET(sock->fd, &errfds);

    #ifdef WOLFMQTT_ENABLE_STDIN_CAP
        FD_SET(STDIN, &recvfds);
    #endif

#else
    (void)timeout_ms;
#endif /* !WOLFMQTT_NO_TIMEOUT && !WOLFMQTT_NONBLOCK */

    /* Loop until buf_len has been read, error or timeout */
    while (bytes < buf_len) {

    #if !defined(WOLFMQTT_NO_TIMEOUT) && !defined(WOLFMQTT_NONBLOCK)
        /* Wait for rx data to be available */
        rc = select((int)SELECT_FD(sock->fd), &recvfds, NULL, &errfds, &tv);
        if (rc > 0)
        {
            /* Check if rx or error */
            if (FD_ISSET(sock->fd, &recvfds)) {
    #endif /* !WOLFMQTT_NO_TIMEOUT && !WOLFMQTT_NONBLOCK */

                /* Try and read number of buf_len provided,
                    minus what's already been read */
                rc = (int)SOCK_RECV(sock->fd,
                               &buf[bytes],
                               buf_len - bytes,
                               flags);
                if (rc <= 0) {
                    rc = -1;
                    goto exit; /* Error */
                }
                else {
                    bytes += rc; /* Data */
                }

    #if !defined(WOLFMQTT_NO_TIMEOUT) && !defined(WOLFMQTT_NONBLOCK)
            }
        #ifdef WOLFMQTT_ENABLE_STDIN_CAP
            else if (FD_ISSET(STDIN, &recvfds)) {
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
    #else
        /* non-blocking should always exit loop */
        break;
    #endif /* !WOLFMQTT_NO_TIMEOUT && !WOLFMQTT_NONBLOCK */
    } /* while */

exit:

    if (rc == 0 && timeout) {
        rc = MQTT_CODE_ERROR_TIMEOUT;
    }
    else if (rc < 0) {
        /* Get error */
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            rc = 0; /* Handle signal */
        }
        else {
        #ifdef WOLFMQTT_NONBLOCK
            if (so_error == EWOULDBLOCK || so_error == EAGAIN) {
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

static int NetDisconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    if (sock) {
        if (sock->fd != SOCKET_INVALID) {
            SOCK_CLOSE(sock->fd);
            sock->fd = -1;
        }

        sock->stat = SOCK_BEGIN;
    }
    return 0;
}

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
            PRINTF(" IP Address: ");
            PRINTF("%d.%d.%d.%d\n", ipAddr.v[0], ipAddr.v[1], ipAddr.v[2], ipAddr.v[3]);
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
        sockCtx->stat = SOCK_BEGIN;
        sockCtx->mqttCtx = mqttCtx;
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
        MulticastContext* multi_ctx;
        multi_ctx = (MulticastContext*)WOLFMQTT_MALLOC(sizeof(MulticastContext));
        if (multi_ctx == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        net->multi_ctx = multi_ctx;
        XMEMSET(multi_ctx, 0, sizeof(MulticastContext));
        multi_ctx->stat = SOCK_BEGIN;
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
