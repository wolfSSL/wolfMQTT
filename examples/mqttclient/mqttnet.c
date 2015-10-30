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
#include "examples/mqttclient/mqttnet.h"

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


/* Local context for Net callbacks */
typedef struct _SocketContext {
    int fd;
} SocketContext;


static void _setupTimeout(struct timeval* tv, int timeout_ms)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms % 1000) * 1000;

    /* Make sure there is a minimum value specified */
    if (tv->tv_sec < 0 || (tv->tv_sec == 0 && tv->tv_usec <= 0)) {
        tv->tv_sec = 0;
        tv->tv_usec = 100;
    }
}

static int NetConnect(void *context, const char* host, word16 port,
    int timeout_ms)
{
    SocketContext *sock = context;
    int type = SOCK_STREAM;
    struct sockaddr_in address;
    int rc, so_error = 0;
    sa_family_t family = AF_INET;
    struct addrinfo *result = NULL;
    struct addrinfo hints = {0, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0, NULL, NULL, NULL};

    /* Get address information for host and locate IPv4 */
    if ((rc = getaddrinfo(host, NULL, &hints, &result)) == 0) {
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
            address.sin_family = family = AF_INET;
            address.sin_addr = ((struct sockaddr_in*)(result->ai_addr))->sin_addr;
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
        sock->fd = socket(family, type, 0);
        if (sock->fd != -1) {
            fd_set fdset;
            struct timeval tv;

            /* Setup timeout and FD's */
            _setupTimeout(&tv, timeout_ms);
            FD_ZERO(&fdset);
            FD_SET(sock->fd, &fdset);

            /* Set socket as non-blocking */
            fcntl(sock->fd, F_SETFL, O_NONBLOCK);

            /* Start connect */
            connect(sock->fd, (struct sockaddr*)&address, sizeof(address));

            /* Wait for connect */
            if (select(sock->fd + 1, NULL, &fdset, NULL, &tv) == 1)
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
    SocketContext *sock = context;
    int rc, so_error = 0;
    struct timeval tv;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Setup timeout */
    _setupTimeout(&tv, timeout_ms);
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    rc = (int)write(sock->fd, buf, (size_t)buf_len);
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
    SocketContext *sock = context;
    int rc = -1, so_error = 0, bytes = 0;
    fd_set recvfds, errfds;
    struct timeval tv;

    if (context == NULL || buf == NULL || buf_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Setup timeout and FD's */
    _setupTimeout(&tv, timeout_ms);
    FD_ZERO(&recvfds);
    FD_SET(sock->fd, &recvfds);
    FD_ZERO(&errfds);
    FD_SET(sock->fd, &errfds);

    /* Loop until buf_len has been read, error or timeout */
    while (bytes < buf_len)
    {
        /* Wait for rx data to be available */
        rc = select(sock->fd + 1, &recvfds, NULL, &errfds, &tv);
        if (rc > 0) {
            /* Check if rx or error */
            if (FD_ISSET(sock->fd, &recvfds)) {

                /* Try and read number of buf_len provided, minus what's already been read */
                rc = (int)recv(sock->fd, &buf[bytes], (size_t)(buf_len - bytes), 0);
                if (rc < 0) {
                    break; /* Error */
                }
                else if (rc > 0) {
                    bytes += rc; /* Data */
                }
            }
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
        if (so_error == 0) {
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
    SocketContext *sock = context;
    if (sock) {
        if (sock->fd != -1) {
            close(sock->fd);
            sock->fd = -1;
        }
    }

    return 0;
}

int MqttClientNet_Init(MqttNet* net)
{
    if (net) {
        memset(net, 0, sizeof(MqttNet));
        net->connect = NetConnect;
        net->read = NetRead;
        net->write = NetWrite;
        net->disconnect = NetDisconnect;
        net->context = malloc(sizeof(SocketContext));
    }
    return 0;
}

int MqttClientNet_DeInit(MqttNet* net)
{
    if (net) {
        if (net->context) {
            free(net->context);
        }
        memset(net, 0, sizeof(MqttNet));
    }
    return 0;
}
