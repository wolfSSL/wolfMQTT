/* mqttnet.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
#include "mqttnet.h"

/* FreeRTOS and LWIP */
#ifdef FREERTOS
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
    #include "wolfmqtt/mqtt_client.h"
    #include "mqttnet.h"

    #include "system_config.h"
    #include "tcpip/tcpip.h"
    #include <sys/errno.h>
    #include <errno.h>
    struct timeval {
        int tv_sec;
        int tv_usec;
    };

    #define SOCKET_INVALID (-1)
    #define SO_ERROR 0
    #define SOERROR_T uint8_t
    #undef  FD_ISSET
    #define FD_ISSET(f1, f2) (1==1)

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

    /* Wake on stdin activity */
    #define ENABLE_STDIN_CAPTURE
    #define STDIN   0
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


/* Include the example code */
#include "mqttexample.h"

/* Local context for Net callbacks */
typedef enum {
    SOCK_BEGIN = 0,
    SOCK_CONN,
} NB_Stat;

typedef struct _SocketContext {
    SOCKET_T fd;
    NB_Stat stat;
    int bytes;
    struct sockaddr_in addr;
#ifdef ENABLE_STDIN_CAPTURE
    byte stdin_cap_enable;
    byte stdin_has_data;
#endif
} SocketContext;

/* Private functions */
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

static void tcp_set_nonblocking(SOCKET_T* sockfd)
{
#ifdef USE_WINDOWS_API
    unsigned long blocking = 1;
    int ret = ioctlsocket(*sockfd, FIONBIO, &blocking);
    if (ret == SOCKET_ERROR)
        PRINTF("ioctlsocket failed!");
#elif defined(MICROCHIP_MPLAB_HARMONY)
    /* Do nothing */
#else
    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags < 0)
        PRINTF("fcntl get failed!");
    flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0)
        PRINTF("fcntl set failed!");
#endif
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
#if defined(MICROCHIP_MPLAB_HARMONY)
    struct hostent *hostInfo;
#endif

    /* Get address information for host and locate IPv4 */
    switch(sock->stat) {
        case SOCK_BEGIN:
        {
            XMEMSET(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            XMEMSET(&sock->addr, 0, sizeof(sock->addr));
            sock->addr.sin_family = AF_INET;


        #if defined(MICROCHIP_MPLAB_HARMONY)
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
        #else
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
                        ((struct sockaddr_in*)(result->ai_addr))->sin_addr;
                }
                else {
                    rc = -1;
                }

                freeaddrinfo(result);
            }
            if (rc != 0) goto exit;
        #endif /* MICROCHIP_MPLAB_HARMONY */

            /* Default to error */
            rc = -1;

            /* Create socket */
        #if defined(MICROCHIP_MPLAB_HARMONY)
            sock->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        #else
            sock->fd = socket(sock->addr.sin_family, type, 0);
        #endif
            if (sock->fd == SOCKET_INVALID)
                goto exit;

            sock->stat = SOCK_CONN;
            /* fall-through */
        }

        case SOCK_CONN:
        {
            fd_set fdset;
            struct timeval tv;

            /* Setup timeout and FD's */
            setup_timeout(&tv, timeout_ms);
            FD_ZERO(&fdset);
            FD_SET(sock->fd, &fdset);

            /* Set socket as non-blocking */
            tcp_set_nonblocking(&sock->fd);

            /* Start connect */
        #if defined(MICROCHIP_MPLAB_HARMONY)
            rc = connect(sock->fd, (struct sockaddr*)&sock->addr, sizeof(sock->addr));
            if (rc)
        #else
            connect(sock->fd, (struct sockaddr*)&sock->addr, sizeof(sock->addr));

            /* Wait for connect */
            if (select((int)SELECT_FD(sock->fd), NULL, &fdset, NULL, &tv) > 0)
        #endif
            {
                socklen_t len = sizeof(so_error);
            #if defined(MICROCHIP_MPLAB_HARMONY)
                if (errno == EINPROGRESS) {
                    return MQTT_CODE_CONTINUE;
                }
            #else
                /* Check for error */
                getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    rc = 0; /* Success */
                }
            #endif
            }
            break;
        }

        default:
            rc = -1;
    } /* switch */

exit:
    /* Show error */
    if (rc != 0) {
        PRINTF("NetConnect: Rc=%d, SoErr=%d", rc, so_error);
    }

    return rc;
}

static int NetWrite(void *context, const byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc;
    SOERROR_T so_error = 0;
    struct timeval tv;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Setup timeout */
    setup_timeout(&tv, timeout_ms);
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    rc = (int)SOCK_SEND(sock->fd, buf, buf_len, 0);
    if (rc == -1) {
        /* Get error */
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            rc = 0; /* Handle signal */
        }
        else {
            rc = MQTT_CODE_ERROR_NETWORK;
            PRINTF("NetWrite: Error %d", so_error);
        }
    }

    return rc;
}

static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc = -1, timeout = 0;
    SOERROR_T so_error = 0;
#ifndef WOLFMQTT_NONBLOCK
    fd_set recvfds;
    fd_set errfds;
    struct timeval tv;
#endif

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    sock->bytes = 0;

#ifndef WOLFMQTT_NONBLOCK
    /* Setup timeout and FD's */
    setup_timeout(&tv, timeout_ms);
    FD_ZERO(&recvfds);
    FD_SET(sock->fd, &recvfds);
    FD_ZERO(&errfds);
    FD_SET(sock->fd, &errfds);

#ifdef ENABLE_STDIN_CAPTURE
    if (sock->stdin_cap_enable) {
        FD_SET(STDIN, &recvfds);
    }
#endif
#else
    (void)timeout_ms;
#endif /* !WOLFMQTT_NONBLOCK */

    /* Loop until buf_len has been read, error or timeout */
    while (sock->bytes < buf_len) {

    #ifndef WOLFMQTT_NONBLOCK
        /* Wait for rx data to be available */
        rc = select((int)SELECT_FD(sock->fd), &recvfds, NULL, &errfds, &tv);
        if (rc > 0)
        {
            /* Check if rx or error */
            if (FD_ISSET(sock->fd, &recvfds)) {
    #endif /* !WOLFMQTT_NONBLOCK */

                /* Try and read number of buf_len provided,
                    minus what's already been read */
                rc = (int)SOCK_RECV(sock->fd,
                               &buf[sock->bytes],
                               buf_len - sock->bytes,
                               0);
                if (rc <= 0) {
                    rc = -1;
                    goto exit; /* Error */
                }
                else {
                    sock->bytes += rc; /* Data */
                }

    #ifndef WOLFMQTT_NONBLOCK
            }
        #ifdef ENABLE_STDIN_CAPTURE
            else if (FD_ISSET(STDIN, &recvfds)) {
                sock->stdin_has_data = 1;
                /* Don't exit read until cap enabled */
                if (sock->stdin_cap_enable) {
                    return MQTT_CODE_ERROR_TIMEOUT;
                }
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
    #endif /* !WOLFMQTT_NONBLOCK */
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
            if (so_error == EWOULDBLOCK) {
                return MQTT_CODE_CONTINUE;
            }
        #endif
            rc = MQTT_CODE_ERROR_NETWORK;
            PRINTF("NetRead: Error %d", so_error);
        }
    }
    else {
        rc = sock->bytes;
    }
    sock->bytes = 0;

    return rc;
}

static int NetDisconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    if (sock) {
        if (sock->fd != SOCKET_INVALID) {
        #ifdef USE_WINDOWS_API
            closesocket(sock->fd);
        #else
            close(sock->fd);
        #endif
            sock->fd = -1;
        }

        sock->stat = SOCK_BEGIN;
        sock->bytes = 0;
    }
    return 0;
}

/* Public Functions */
int MqttClientNet_Init(MqttNet* net)
{
#ifdef USE_WINDOWS_API
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
        XMEMSET(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;
        net->context = (SocketContext *)WOLFMQTT_MALLOC(sizeof(SocketContext));
        if (net->context == NULL) {
            return MQTT_CODE_ERROR_MEMORY;
        }
        XMEMSET(net->context, 0, sizeof(SocketContext));

        ((SocketContext*)(net->context))->stat = SOCK_BEGIN;
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

int MqttClientNet_CheckForCommand_Enable(MqttNet* net)
{
    if (net && net->context) {
    #ifdef ENABLE_STDIN_CAPTURE
        SocketContext *sock = (SocketContext*)net->context;
        sock->stdin_cap_enable = 1;
    #endif
    }
    return 0;
}

/* Return length of data */
int MqttClientNet_CheckForCommand(MqttNet* net, byte* buffer, word32 length)
{
    int ret = 0;

    if (net && net->context) {
    #ifdef ENABLE_STDIN_CAPTURE
        SocketContext *sock = (SocketContext*)net->context;
        if (sock->stdin_has_data) {
            if (fgets((char*)buffer, length, stdin) != NULL) {
                ret = (int)XSTRLEN((char*)buffer);
            }
            sock->stdin_has_data = 0;
        }
    #endif
    }

    (void)buffer;
    (void)length;

    return ret;
}
