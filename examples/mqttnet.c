/* mqttnet.c
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

#if defined(MICROCHIP_MPLAB_HARMONY)
    #include <system/tmr/sys_tmr.h>
#else
    #include <time.h>
#endif

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
#elif defined(WOLFSSL_LWIP)
#if defined(FREERTOS)
    /* Scheduler includes. */
    #include "FreeRTOS.h"
    #include "task.h"
    #include "semphr.h"
#endif
    /* lwIP includes. */
    #include "lwip/api.h"
    #include "lwip/tcpip.h"
    #include "lwip/memp.h"
    #include "lwip/stats.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"

    #define SOCK_OPEN lwip_socket
    #define SOCK_CONNECT lwip_connect
    #define SOCK_SEND lwip_send
    #define SOCK_RECV lwip_recv
    #define SOCK_FCNTL lwip_fcntl
    #define SOCK_GETSOCKOPT lwip_getsockopt
    #define SOCK_CLOSE lwip_close
    #define SOCK_SETSOCKOPT lwip_setsockopt
    #define SOCK_GETADDRINFO lwip_getaddrinfo
    #define SOCK_FREEADDRINFO lwip_freeaddrinfo
    #define SOCK_SELECT lwip_select

/* Windows */
#elif defined(USE_WINDOWS_API)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <errno.h>
    #define SOCKET_T        SOCKET
    #define SOERROR_T int
    #define SELECT_FD(fd)   (fd)
    #ifndef SOCKET_INVALID /* Do not redefine from wolfssl */
        #define SOCKET_INVALID  ((SOCKET_T)INVALID_SOCKET)
    #endif
    #define SOCK_CLOSE      closesocket
    #define SOCK_SEND(s,b,l,f) send((s), (const char*)(b), (size_t)(l), (f))
    #define SOCK_RECV(s,b,l,f) recv((s), (char*)(b), (size_t)(l), (f))

    #ifndef ESOCKTNOSUPPORT
        #define ESOCKTNOSUPPORT 10000
    #endif
    #ifndef EPFNOSUPPORT
        #define EPFNOSUPPORT  10001
    #endif
    #ifndef ESHUTDOWN
        #define ESHUTDOWN  10002
    #endif
    #ifndef ETOOMANYREFS
        #define ETOOMANYREFS 10003
    #endif
    #ifndef EHOSTDOWN
        #define EHOSTDOWN 10004
    #endif
    #ifndef EPROCLIM
        #define EPROCLIM 10005
    #endif
    #ifndef EUSERS
        #define EUSERS 10006
    #endif
    #ifndef EDQUOT
        #define EDQUOT 10007
    #endif
    #ifndef ESTALE
        #define ESTALE 10008
    #endif
    #define EREMOTE 10009
    #define ESYSNOTREADY 10010
    #define ERNOTSUPPORTED 10011
    #define ENOTINITIALISED 10012
    #define EDISCON 10013
    #define ENOMORE 10014
    #define ECANCELLED 10015
    #define EINVALIDPROCTABLE 10016
    #define EINVALIDPROVIDER 10017
    #define EPROVIDERFAILEDINIT 10018
    #define ESYSCALLFAILURE 10019
    #define ESERVICE_NOT_FOUND 10020
    #define ETYPE_NOT_FOUND 10021
    #define E_NO_MORE 10022
    #define E_CANCELLED 10023
    #define EREFUSED 10024
    #define EHOSTNOTFOUND 10025
    #define ETRY_AGAIN 10029
    #define ENO_RECOVERY 10030

    #define GET_SOCK_ERROR GET_SOCK_ERROR

static SOERROR_T win32_wsa_error_to_errno(int e) {
    /* https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2 */
    switch (e) {
    case 0:
        return 0;
    case WSAEINTR:
        return EINTR;
    case WSAEBADF:
        return EBADF;
    case WSAEACCES:
        return EACCES;
    case WSAEFAULT:
        return EFAULT;
    case WSAEINVAL:
        return EINVAL;
    case WSAEMFILE:
        return EMFILE;
    case WSAEWOULDBLOCK:
        return EWOULDBLOCK;
    case WSAEINPROGRESS:
        return EINPROGRESS;
    case WSAEALREADY:
        return EALREADY;
    case WSAENOTSOCK:
        return ENOTSOCK;
    case WSAEDESTADDRREQ:
        return EDESTADDRREQ;
    case WSAEMSGSIZE:
        return EMSGSIZE;
    case WSAEPROTOTYPE:
        return EPROTOTYPE;
    case WSAENOPROTOOPT:
        return ENOPROTOOPT;
    case WSAEPROTONOSUPPORT:
        return EPROTONOSUPPORT;
    case WSAESOCKTNOSUPPORT:
        return ESOCKTNOSUPPORT;
    case WSAEOPNOTSUPP:
        return EOPNOTSUPP;
    case WSAEPFNOSUPPORT:
        return EPFNOSUPPORT;
    case WSAEAFNOSUPPORT:
        return EAFNOSUPPORT;
    case WSAEADDRINUSE:
        return EADDRINUSE;
    case WSAEADDRNOTAVAIL:
        return EADDRNOTAVAIL;
    case WSAENETDOWN:
        return ENETDOWN;
    case WSAENETUNREACH:
        return ENETUNREACH;
    case WSAENETRESET:
        return ENETRESET;
    case WSAECONNABORTED:
        return ECONNABORTED;
    case WSAECONNRESET:
        return ECONNRESET;
    case WSAENOBUFS:
        return ENOBUFS;
    case WSAEISCONN:
        return EISCONN;
    case WSAENOTCONN:
        return ENOTCONN;
    case WSAESHUTDOWN:
        return ESHUTDOWN;
    case WSAETOOMANYREFS:
        return ETOOMANYREFS;
    case WSAETIMEDOUT:
        return ETIMEDOUT;
    case WSAECONNREFUSED:
        return ECONNREFUSED;
    case WSAELOOP:
        return ELOOP;
    case WSAENAMETOOLONG:
        return ENAMETOOLONG;
    case WSAEHOSTDOWN:
        return EHOSTDOWN;
    case WSAEHOSTUNREACH:
        return EHOSTUNREACH;
    case WSAENOTEMPTY:
        return ENOTEMPTY;
    case WSAEPROCLIM:
        return EPROCLIM;
    case WSAEUSERS:
        return EUSERS;
    case WSAEDQUOT:
        return EDQUOT;
    case WSAESTALE:
        return ESTALE;
    case WSAEREMOTE:
        return EREMOTE;
    case WSASYSNOTREADY:
        return ESYSNOTREADY;
    case WSAVERNOTSUPPORTED:
        return ERNOTSUPPORTED;
    case WSANOTINITIALISED:
        return ENOTINITIALISED;
    case WSAEDISCON:
        return EDISCON;
    case WSAENOMORE:
        return ENOMORE;
    case WSAECANCELLED:
        return ECANCELLED;
    case WSAEINVALIDPROCTABLE:
        return EINVALIDPROCTABLE;
    case WSAEINVALIDPROVIDER:
        return EINVALIDPROVIDER;
    case WSAEPROVIDERFAILEDINIT:
        return EPROVIDERFAILEDINIT;
    case WSASYSCALLFAILURE:
        return ESYSCALLFAILURE;
    case WSASERVICE_NOT_FOUND:
        return ESERVICE_NOT_FOUND;
    case WSATYPE_NOT_FOUND:
        return ETYPE_NOT_FOUND;
    case WSA_E_NO_MORE:
        return E_NO_MORE;
    case WSA_E_CANCELLED:
        return E_CANCELLED;
    case WSAEREFUSED:
        return EREFUSED;
    case WSAHOST_NOT_FOUND:
        return EHOSTNOTFOUND;
    case WSATRY_AGAIN:
        return ETRY_AGAIN;
    case WSANO_RECOVERY:
        return ENO_RECOVERY;
    default:
        return ENOTSUP;
    }
}

static SOERROR_T GET_SOCK_ERROR(int fd)
{
    int wsa_err_saved = WSAGetLastError();
    int win_err = 0;
    socklen_t len = sizeof(win_err);
    if (fd != SOCKET_INVALID) {
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&(win_err), &len);
    }
    if (win_err == 0) {
        win_err = wsa_err_saved;
    }
    return win32_wsa_error_to_errno(win_err);
}

/* Freescale MQX / RTCS */
#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #if defined(FREESCALE_MQX)
        #include <posix.h>
    #endif
    #include <rtcs.h>
    /* Note: Use "RTCS_geterror(sock->fd);" to get error number */
    #define SOCKET_INVALID  RTCS_SOCKET_ERROR
    #define SOCKET_T        uint32_t
    #define SOCK_CLOSE      closesocket
    #define SOCK_OPEN       RTCS_socket

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

#ifndef EHOSTNOTFOUND
#define EHOSTNOTFOUND 10000
#endif

/* Setup defaults */
#ifndef SOCK_OPEN
    #define SOCK_OPEN       socket
#endif
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
#ifndef SOCK_FCNTL
#define SOCK_FCNTL fcntl
#endif
#ifndef SOCK_GETSOCKOPT
#define SOCK_GETSOCKOPT getsockopt
#endif
#ifndef SOCK_SETSOCKOPT
#define SOCK_SETSOCKOPT setsockopt
#endif
#ifndef SOCK_GETADDRINFO
#define SOCK_GETADDRINFO getaddrinfo
#endif
#ifndef SOCK_FREEADDRINFO
#define SOCK_FREEADDRINFO freeaddrinfo
#endif
#ifndef SOCK_SELECT
#define SOCK_SELECT select
#endif
#ifndef GET_SOCK_ERROR
static SOERROR_T GET_SOCK_ERROR(int fd)
{
    SOERROR_T __saved_errno = errno;
    SOERROR_T e = 0;
    socklen_t len = sizeof(e);
    if (fd != SOCKET_INVALID) {
        SOCK_GETSOCKOPT(fd, SOL_SOCKET, SO_ERROR, &e, &len);
    }
    if (e == 0) {
        e = __saved_errno;
    }
    return e;
}
#endif
#ifndef SOCK_EQ_ERROR
    #define SOCK_EQ_ERROR(e) \
        (((e) == EWOULDBLOCK) || ((e) == EAGAIN) || ((e) == EINPROGRESS) || ((e) == EALREADY))
#endif
/* Local context for Net callbacks */
typedef enum {
    SOCK_BEGIN = 0,
    SOCK_CONN,
} NB_Stat;


#if 0 /* TODO: add multicast support */
typedef struct MulticastCtx {

} MulticastCtx;
#endif


typedef struct _SocketContext {
    SOCKET_T fd;
    NB_Stat stat;
    SOCK_ADDR_IN addr;
    word32 start_time_ms;
#ifdef MICROCHIP_MPLAB_HARMONY
    word32 bytes;
#endif
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_ENABLE_STDIN_CAP)
    /* "self pipe" -> signal wake sleep() */
    SOCKET_T pfd[2];
#endif
    MqttClient* mqttCtx;
    int shown;
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
    MqttClient* mqttCtx = sock->mqttCtx;

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
    MqttClient* mqttCtx = sock->mqttCtx;

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
#endif /* !WOLFMQTT_NO_TIMEOUT */

static void tcp_set_nonblocking(SOCKET_T* sockfd)
{
#if defined(USE_WINDOWS_API) && !defined(WOLFSSL_LWIP)
    unsigned long blocking = 1;
    int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
    if (ret == SOCKET_ERROR)
        PRINTF("ioctlsocket failed!");
#else
    int flags = SOCK_FCNTL(*sockfd, F_GETFL, 0);
    if (flags < 0)
        PRINTF("fcntl get failed!");
    flags = SOCK_FCNTL(*sockfd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0)
        PRINTF("fcntl set failed!");
#endif
}

static int NetTranslateError(SOERROR_T so_error) {
    int rc = MQTT_CODE_ERROR_NETWORK;
    if (SOCK_EQ_ERROR(so_error)) {
        rc = MQTT_CODE_CONTINUE;
    } else if (so_error == EHOSTUNREACH) {
        rc = MQTT_CODE_ERROR_ROUTE_TO_HOST;
    } else if (so_error == EISCONN) {
        rc = MQTT_CODE_SUCCESS;
    } else if (so_error == ETIMEDOUT) {
        rc = MQTT_CODE_ERROR_TIMEOUT;
    } else if (so_error == EHOSTNOTFOUND) {
        rc = MQTT_CODE_ERROR_DNS_RESOLVE;
    } else if (so_error == 0) {
        rc = MQTT_CODE_SUCCESS;
    }
    return rc;
}

static int NetGetError(SocketContext *sock) {
    /* Get error */
    SOERROR_T so_error = GET_SOCK_ERROR(sock->fd);
    int rc = NetTranslateError(so_error);
    if (!sock->mqttCtx->useNonBlockMode && rc == MQTT_CODE_CONTINUE) {
        rc = MQTT_CODE_ERROR_NETWORK;
    }
    if (sock->fd == SOCKET_INVALID && rc == MQTT_CODE_SUCCESS) {
        rc = MQTT_CODE_ERROR_NETWORK;
    }
#ifdef WOLFMQTT_DEBUG_SOCKET
    if (rc != MQTT_CODE_CONTINUE && rc != MQTT_CODE_SUCCESS) {
        PRINTF("NetGetError: rc:%d so_error:%d", rc, so_error);
    }
#endif
    return rc;
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int type = SOCK_STREAM;
    int rc = -1;
    struct addrinfo *result = NULL;
    struct addrinfo hints;
    MqttClient* mqttCtx = sock->mqttCtx;

    /* Get address information for host and locate IPv4 */
    switch(sock->stat) {
        case SOCK_BEGIN:
        {
            if (!sock->shown) {
                sock->shown = 1;
                PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
                    host, port, timeout_ms, mqttCtx->use_tls);
            }
            XMEMSET(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            XMEMSET(&sock->addr, 0, sizeof(sock->addr));
            sock->addr.sin_family = AF_INET;
            sock->fd = SOCKET_INVALID;
            sock->start_time_ms = mqttCtx->net.get_time_ms();

            rc = SOCK_GETADDRINFO(host, NULL, &hints, &result);
            if (rc == 0) {
                struct addrinfo* result_i = result;

                if (!result) {
                    rc = NetGetError(sock);
                    break;
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

                SOCK_FREEADDRINFO(result);
            }
            if (rc != 0) {
                rc = NetGetError(sock);
                break;
            }

            /* Default to error */
            rc = -1;

            /* Create socket */
            sock->fd = SOCK_OPEN(sock->addr.sin_family, type, 0);
            if (sock->fd == SOCKET_INVALID)
            {
                rc = NetGetError(sock);
                break;
            }

            if (mqttCtx->useNonBlockMode) {
                /* Set socket as non-blocking */
                tcp_set_nonblocking(&sock->fd);
            }
            sock->stat = SOCK_CONN;
        }
        FALL_THROUGH;

        case SOCK_CONN:
        {
            /* Start connect */
            rc = SOCK_CONNECT(sock->fd, (struct sockaddr*)&sock->addr,
                    sizeof(sock->addr));
            if (rc >= 0) {
                rc = MqttClient_CheckTimeout(rc, MQTT_CODE_ERROR_TIMEOUT,
                    &sock->start_time_ms, timeout_ms, mqttCtx->net.get_time_ms());
                break;
            }
            /* set default error case */
            rc = MQTT_CODE_ERROR_NETWORK;
        #ifndef WOLFMQTT_NO_TIMEOUT
            {
                fd_set fdset;
                struct timeval tv;

                /* Setup timeout and FD's */
                setup_timeout(&tv, timeout_ms);
                FD_ZERO(&fdset);
                FD_SET(sock->fd, &fdset);
                /* Wait for connect */
                if (SOCK_SELECT((int)SELECT_FD(sock->fd), NULL, &fdset,
                                            NULL, &tv) > 0) {
                    rc = MQTT_CODE_SUCCESS;
                }
            }
        #endif /* !WOLFMQTT_NO_TIMEOUT */
            if (rc != MQTT_CODE_SUCCESS) {
                /* Check for error */
                rc = NetGetError(sock);
            }
            break;
        }

        default:
            rc = MQTT_CODE_ERROR_STAT;
            break;
    } /* switch */

    (void)timeout_ms;

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
    MqttClient* mqttCtx = sock->mqttCtx;

    PRINTF("NetConnect: Host %s, Port %u, Timeout %d ms, Use TLS %d",
        host, port, timeout_ms, mqttCtx->use_tls);

    /* Get address information for host and locate IPv4 */
    XMEMSET(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */

    XMEMSET(&sock->addr, 0, sizeof(sock->addr));
    sock->addr.sin_family = AF_INET;

    rc = SOCK_GETADDRINFO(host, NULL, &hints, &result);
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

        SOCK_FREEADDRINFO(result);
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
        setup_timeout(&tv, timeout_ms);
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
    if (rc != 0) {
        SOCK_CLOSE(sock->fd);
        PRINTF("NetConnect: Rc=%d, SoErr=%d", rc, so_error);
    }

    return rc;
}
#endif

/* Always return value other than 0ms, if 0ms appeared, use 1ms instead */
static word32 NetGetTimeMs(void)
{
    word32 now_time_ms = 0;
#if defined(WOLFSSL_LWIP)
    now_time_ms = sys_now();
#elif defined(MICROCHIP_MPLAB_HARMONY)
    now_time_ms = (word32)(SYS_TMR_TickCountGet() * 1000llu /
            SYS_TMR_TickCounterFrequencyGet());
#elif defined(_WIN32)
    FILETIME st;
    ULARGE_INTEGER ul;
    GetSystemTimeAsFileTime(&st);
    ul.LowPart = st.dwLowDateTime;
    ul.HighPart = st.dwHighDateTime;
    now_time_ms = ul.QuadPart / 10000.0 - 11644473600000LL;
#else
    /* TODO: precise Posix style time */
    now_time_ms = (word32)(time(0) * 1000llu);
#endif
    return now_time_ms;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc;
#ifndef WOLFMQTT_NO_TIMEOUT
    struct timeval tv;
#endif

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (sock->fd == SOCKET_INVALID)
        return MQTT_CODE_ERROR_BAD_ARG;

#ifndef WOLFMQTT_NO_TIMEOUT
    /* Setup timeout */
    setup_timeout(&tv, timeout_ms);
    SOCK_SETSOCKOPT(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
#endif

    rc = (int)SOCK_SEND(sock->fd, buf, buf_len, 0);
    if (rc < 0) {
        rc = NetGetError(sock);
    }

    (void)timeout_ms;

    return rc;
}

static int NetRead_ex(void *context, byte* buf, int buf_len,
    int timeout_ms, byte peek)
{
    SocketContext *sock = (SocketContext*)context;
    MqttClient* mqttCtx = sock->mqttCtx;
    int rc = -1, timeout = 0;
    int bytes = 0;
    int flags = 0;
#ifndef WOLFMQTT_NO_TIMEOUT
    fd_set recvfds;
    fd_set errfds;
    struct timeval tv;
#endif

    (void)mqttCtx;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    if (sock->fd == SOCKET_INVALID)
        return MQTT_CODE_ERROR_BAD_ARG;

    if (peek == 1) {
        flags |= MSG_PEEK;
    }

#ifndef WOLFMQTT_NO_TIMEOUT
    /* Setup timeout */
    setup_timeout(&tv, timeout_ms);

    /* Setup select file descriptors to watch */
    FD_ZERO(&errfds);
    FD_SET(sock->fd, &errfds);
    FD_ZERO(&recvfds);
    FD_SET(sock->fd, &recvfds);
    #ifdef WOLFMQTT_ENABLE_STDIN_CAP
    #ifdef WOLFMQTT_MULTITHREAD
        FD_SET(sock->pfd[0], &recvfds);
    #endif
    if (!mqttCtx->test_mode) {
        FD_SET(STDIN, &recvfds);
    }
    #endif /* WOLFMQTT_ENABLE_STDIN_CAP */
#else
    (void)timeout_ms;
#endif /* !WOLFMQTT_NO_TIMEOUT */

    /* Loop until buf_len has been read, error or timeout */
    while (bytes < buf_len) {
        int do_read = 0;

    #ifndef WOLFMQTT_NO_TIMEOUT
        if (mqttCtx->useNonBlockMode) {
            do_read = 1;
        }
        else
        {
            /* Wait for rx data to be available */
            rc = SOCK_SELECT((int)SELECT_FD(sock->fd), &recvfds, NULL, &errfds, &tv);
            if (rc > 0)
            {
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
                minus what's already been read */
            rc = (int)SOCK_RECV(sock->fd,
                           &buf[bytes],
                           buf_len - bytes,
                           flags);
            if (rc < 0) {
                rc = -1;
                goto exit; /* Error */
            } else if (rc == 0) {
                if (mqttCtx->useNonBlockMode) {
                    return MQTT_CODE_CONTINUE;
                } else {
                    continue;
                }
            } else {
                bytes += rc; /* Data */
            }
        }

        /* no timeout and non-block should always exit loop */
        if (mqttCtx->useNonBlockMode) {
            break;
        }
    #ifdef WOLFMQTT_NO_TIMEOUT
        break;
    #endif
    } /* while */

exit:

    if (rc == 0 && timeout) {
        rc = MQTT_CODE_ERROR_TIMEOUT;
    }
    else if (rc < 0) {
        rc = NetGetError(sock);
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


int MqttClientNet_DeInit(MqttClient* client);
int MqttClientNet_Wake(MqttClient* client);

static int MqttClientNet_InitShared(MqttClient* client)
{
    SocketContext* sockCtx;
    if (client == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    XMEMSET(&client->net, 0, sizeof(client->net));
    sockCtx = (SocketContext*)WOLFMQTT_MALLOC(sizeof(SocketContext));
    if (sockCtx == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }
    client->net.get_time_ms = NetGetTimeMs;
    client->net.read = NetRead;
    client->net.write = NetWrite;
    client->net.disconnect = NetDisconnect;
    client->net.deinit = MqttClientNet_DeInit;
    client->net.wake = MqttClientNet_Wake;
    client->net.context = sockCtx;
    XMEMSET(sockCtx, 0, sizeof(SocketContext));
    sockCtx->fd = SOCKET_INVALID;
    sockCtx->stat = SOCK_BEGIN;
    sockCtx->mqttCtx = client;
    return MQTT_CODE_SUCCESS;
}

/* Public Functions */
int MqttClientNet_Init(MqttClient* client)
{
    int rc;
#if defined(USE_WINDOWS_API) && !defined(FREERTOS_TCP) && !defined(WOLFSSL_LWIP)
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
    rc = MqttClientNet_InitShared(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
    {
        client->net.connect = NetConnect;

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
int SN_ClientNet_Init(MqttClient* client)
{
    int rc = MqttClientNet_InitShared(client);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }
    {
        client->net.connect = SN_NetConnect;
        client->net.peek = NetPeek;

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

int MqttClientNet_DeInit(MqttClient* client)
{
    if (client) {
        if (client->net.context) {
            WOLFMQTT_FREE(client->net.context);
        }
        XMEMSET(&client->net, 0, sizeof(client->net));
    }
    return 0;
}

int MqttClientNet_Wake(MqttClient* client)
{
#if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_ENABLE_STDIN_CAP)
    if (client) {
        SocketContext* sockCtx = (SocketContext*)client->net.context;
        if (sockCtx) {
            /* wake the select() */
            if (write(sockCtx->pfd[1], "\n", 1) < 0) {
                PRINTF("Failed to wake select");
                return -1;
            }
        }
    }
#else
    (void)client;
#endif
    return 0;
}
