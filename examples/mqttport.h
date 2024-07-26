/*
 * mqttport.h
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

#ifndef WOLFMQTT_PORT_H
#define WOLFMQTT_PORT_H

#ifdef __cplusplus
extern "C" {
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

/* ToppersOS and LWIP */
#elif defined(TOPPERS) && defined(WOLFSSL_LWIP)
    /* lwIP includes. */
    #include "lwip/api.h"
    #include "lwip/tcpip.h"
    #include "lwip/memp.h"
    #include "lwip/stats.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"

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

/* LWIP only */
#elif defined(WOLFSSL_LWIP)
    /* lwIP includes. */
    #include "lwip/api.h"
    #include "lwip/tcpip.h"
    #include "lwip/memp.h"
    #include "lwip/stats.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"

/* User defined IO */
#elif defined(WOLFMQTT_USER_IO)
    #include "userio_template.h"

/* Windows */
#elif defined(USE_WINDOWS_API)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <stdio.h>
    #define SOCKET_T        SOCKET
    #ifdef _WIN32
        #define SOERROR_T int
    #else
        #define SOERROR_T char
    #endif
    #define SELECT_FD(fd)   (fd)
    #ifndef SOCKET_INVALID /* Do not redefine from wolfssl */
        #define SOCKET_INVALID  ((SOCKET_T)INVALID_SOCKET)
    #endif
    #define SOCK_CLOSE      closesocket
    #define SOCK_SEND(s,b,l,f) send((s), (const char*)(b), (size_t)(l), (f))
    #define SOCK_RECV(s,b,l,f) recv((s), (char*)(b), (size_t)(l), (f))
    #define GET_SOCK_ERROR(f,s,o,e) (e) = WSAGetLastError()
    #define SOCK_EQ_ERROR(e) (((e) == WSAEWOULDBLOCK) || ((e) == WSAEINPROGRESS))

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

/* Zephyr RTOS */
#elif defined(WOLFMQTT_ZEPHYR)
    #include <zephyr/kernel.h>
    #include <zephyr/fs/fs.h>
    #ifndef CONFIG_POSIX_API
        #include <zephyr/net/socket.h>
    #endif
    #ifdef CONFIG_ARCH_POSIX
        #include <fcntl.h>
    #else
        #include <zephyr/posix/fcntl.h>
    #endif


    #define SOCKET_INVALID (-1)

    typedef zsock_fd_set fd_set;
    #define FD_ZERO ZSOCK_FD_ZERO
    #define FD_SET  ZSOCK_FD_SET
    #define FD_ISSET  ZSOCK_FD_ISSET
    #define select zsock_select

    #ifdef WOLFSSL_ZEPHYR
        /* wolfSSL takes care of most defines */
        #include <wolfssl/wolfcrypt/wc_port.h>
    #else
        #define addrinfo   zsock_addrinfo
        #define getaddrinfo   zsock_getaddrinfo
        #define freeaddrinfo   zsock_freeaddrinfo
        #define socket zsock_socket
        #define close zsock_close
        #define SOCK_CONNECT zsock_connect
        #define getsockopt zsock_getsockopt
        #define setsockopt zsock_setsockopt
        #define send zsock_send
        #define recv zsock_recv
        #define MSG_PEEK ZSOCK_MSG_PEEK
        #ifndef NO_FILESYSTEM
            #define XFOPEN              z_fs_open
            #define XFCLOSE             z_fs_close

            #define XFILE               struct fs_file_t*
            /* These are our wrappers for opening and closing files to
             * make the API more POSIX like. Copied from wolfSSL */
            XFILE z_fs_open(const char* filename, const char* mode);
            int z_fs_close(XFILE file);
        #endif
    #endif

    #ifndef NO_FILESYSTEM
        #ifndef XFILE
        #define XFILE               struct fs_file_t*
        #endif
        #ifndef XFFLUSH
        #define XFFLUSH             fs_sync
        #endif
        #ifndef XFSEEK
        #define XFSEEK              fs_seek
        #endif
        #ifndef XFTELL
        #define XFTELL              fs_tell
        #endif
        #ifndef XFREWIND
        #define XFREWIND            fs_rewind
        #endif
        #ifndef XFREAD
        #define XFREAD(P,S,N,F)     fs_read(F, P, S*N)
        #endif
        #ifndef XFWRITE
        #define XFWRITE(P,S,N,F)    fs_write(F, P, S*N)
        #endif
        #ifndef XSEEK_SET
        #define XSEEK_SET           FS_SEEK_SET
        #endif
        #ifndef XSEEK_END
        #define XSEEK_END           FS_SEEK_END
        #endif
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
#ifndef NO_FILESYSTEM
#ifndef XFILE
    #define XFILE           FILE*
#endif
#ifndef XFOPEN
    #define XFOPEN          fopen
#endif
#ifndef XFCLOSE
    #define XFCLOSE         fclose
#endif
#ifndef XFSEEK
    #define XFSEEK          fseek
#endif
#ifndef XFTELL
    #define XFTELL          ftell
#endif
#ifndef XFREAD
    #define XFREAD          fread
#endif
#ifndef XFWRITE
    #define XFWRITE         fwrite
#endif
#ifndef XSEEK_SET
    #define XSEEK_SET       SEEK_SET
#endif
#ifndef XSEEK_END
    #define XSEEK_END       SEEK_END
#endif
#endif /* NO_FILESYSTEM */
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
#ifndef GET_SOCK_ERROR
    #define GET_SOCK_ERROR(f,s,o,e) \
        socklen_t len = sizeof(so_error); \
        (void)getsockopt((f), (s), (o), &(e), &len)
#endif
#ifndef SOCK_EQ_ERROR
    #define SOCK_EQ_ERROR(e) (((e) == EWOULDBLOCK) || ((e) == EAGAIN))
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFMQTT_PORT_H */
