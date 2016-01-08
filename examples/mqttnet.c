/* mqttnet.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Include the autoconf generated config.h */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfmqtt/mqtt_client.h>
#include "examples/mqttnet.h"

/* Standard includes. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

#ifndef SOCKET_T
    #define SOCKET_T        int
#endif
#ifndef SOERROR_T
    #define SOERROR_T       int
#endif
#ifndef SELECT_FD
    #define SELECT_FD(fd)   ((fd) + 1)
#endif

/* Local context for Net callbacks */
typedef struct _SocketContext {
    SOCKET_T fd;
#ifdef ENABLE_STDIN_CAPTURE
    int stdin_has_data;
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
        printf("ioctlsocket failed!\n");
#else
    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags < 0)
        printf("fcntl get failed!\n");
    flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
    if (flags < 0)
        printf("fcntl set failed!\n");
#endif
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int type = SOCK_STREAM;
    struct sockaddr_in address;
    int rc;
    SOERROR_T so_error = 0;
    struct addrinfo *result = NULL;
    struct addrinfo hints;

    XMEMSET(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    XMEMSET(&address, 0, sizeof(address));
    address.sin_family = AF_INET;

    /* Get address information for host and locate IPv4 */
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
            address.sin_port = htons(port);
            address.sin_family = AF_INET;
            address.sin_addr =
                ((struct sockaddr_in*)(result->ai_addr))->sin_addr;
        }
        else {
            rc = -1;
        }

        freeaddrinfo(result);
    }

    if (rc == 0) {
        /* Default to error */
        rc = -1;

        /* Create socket */
        sock->fd = socket(address.sin_family, type, 0);
        if (sock->fd != -1) {
            fd_set fdset;
            struct timeval tv;

            /* Setup timeout and FD's */
            setup_timeout(&tv, timeout_ms);
            FD_ZERO(&fdset);
            FD_SET(sock->fd, &fdset);

            /* Set socket as non-blocking */
            tcp_set_nonblocking(&sock->fd);

            /* Start connect */
            connect(sock->fd, (struct sockaddr*)&address, sizeof(address));

            /* Wait for connect */
            if (select((int)SELECT_FD(sock->fd), NULL, &fdset, NULL, &tv) > 0)
            {
                socklen_t len = sizeof(so_error);

                /* Check for error */
                getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    rc = 0; /* Success */
                }
            }
        }
    }

    /* Show error */
    if (rc != 0) {
        printf("MqttSocket_Connect: Rc=%d, SoErr=%d\n", rc, so_error);
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

    rc = (int)send(sock->fd, buf, (size_t)buf_len, 0);
    if (rc == -1) {
        /* Get error */
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            rc = 0; /* Handle signal */
        }
        else {
            printf("MqttSocket_NetWrite: Error %d\n", so_error);
        }
    }

    return rc;
}

static int NetRead(void *context, byte* buf, int buf_len,
    int timeout_ms)
{
    SocketContext *sock = (SocketContext*)context;
    int rc = -1, bytes = 0;
    SOERROR_T so_error = 0;
    fd_set recvfds, errfds;
    struct timeval tv;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Setup timeout and FD's */
    setup_timeout(&tv, timeout_ms);
    FD_ZERO(&recvfds);
    FD_SET(sock->fd, &recvfds);
    FD_ZERO(&errfds);
    FD_SET(sock->fd, &errfds);

#ifdef ENABLE_STDIN_CAPTURE
    FD_SET(STDIN, &recvfds); /* STDIN */
    sock->stdin_has_data = 0;
#endif

    /* Loop until buf_len has been read, error or timeout */
    while (bytes < buf_len)
    {
        /* Wait for rx data to be available */
        rc = select((int)SELECT_FD(sock->fd), &recvfds, NULL, &errfds, &tv);
        if (rc > 0) {
            /* Check if rx or error */
            if (FD_ISSET(sock->fd, &recvfds)) {
                /* Try and read number of buf_len provided,
                    minus what's already been read */
                rc = (int)recv(sock->fd,
                               &buf[bytes],
                               (size_t)(buf_len - bytes),
                               0);
                if (rc <= 0) {
                    rc = -1;
                    break; /* Error */
                }
                else {
                    bytes += rc; /* Data */
                }
            }
#ifdef ENABLE_STDIN_CAPTURE
            if (FD_ISSET(STDIN, &recvfds)) {
                sock->stdin_has_data = 1;
                rc = 0;
                break;
            }
#endif
            if (FD_ISSET(sock->fd, &errfds)) {
                rc = -1;
                break;
            }
        }
        else {
            break; /* timeout or signal */
        }
    }

    if (rc < 0) {
        /* Get error */
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0 && !FD_ISSET(sock->fd, &recvfds)) {
            rc = 0; /* Handle signal */
        }
        else {
            printf("MqttSocket_NetRead: Error %d\n", so_error);
        }
    }
    else {
        rc = bytes;
    }

    return rc;
}

static int NetDisconnect(void *context)
{
    SocketContext *sock = (SocketContext*)context;
    if (sock) {
        if (sock->fd != -1) {
#ifdef USE_WINDOWS_API
            closesocket(sock->fd);
#else
            close(sock->fd);
#endif
            sock->fd = -1;
        }
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

    if (net) {
        XMEMSET(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;
        net->context = WOLFMQTT_MALLOC(sizeof(SocketContext));
    }
    return 0;
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

/* Return length of data */
int MqttClientNet_CheckForCommand(MqttNet* net, byte* buffer, word32 length)
{
    int stdin_has_data = 0;
    if (net && net->context) {
        SocketContext *sock = (SocketContext*)net->context;
#ifdef ENABLE_STDIN_CAPTURE
        stdin_has_data = sock->stdin_has_data;
#endif
    }
    
    if (stdin_has_data) {
#ifdef ENABLE_STDIN_CAPTURE
        stdin_has_data = 0;
        if(fgets((char*)buffer, length, stdin) != NULL) {
            stdin_has_data = (int)XSTRLEN((char*)buffer);
        }
#endif
    }
    return stdin_has_data;
}
