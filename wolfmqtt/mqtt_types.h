/* mqtt_types.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

/* Implementation by: David Garske
 * Based on specification for MQTT v3.1.1
 * See http://mqtt.org/documentation for additional MQTT documentation.
 */

#ifndef WOLFMQTT_TYPES_H
#define WOLFMQTT_TYPES_H

/* configuration for Arduino */
#ifdef ARDUINO
    #include "wolfmqtt/options.h"

    /* make sure arduino can see the wolfssl library directory */
    #ifdef ENABLE_MQTT_TLS
        #include <wolfssl.h>
    #endif
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#include "wolfmqtt/visibility.h"

#ifdef _WIN32
    #define USE_WINDOWS_API

    /* Make sure a level of Win compatibility is defined */
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0501
    #endif

    /* Allow "unsafe" strncpy */
    #ifndef _CRT_SECURE_NO_WARNINGS
    #define _CRT_SECURE_NO_WARNINGS
    #endif

    /* Visual Studio build settings from wolfmqtt/vs_settings.h */
    #include "wolfmqtt/vs_settings.h"
#endif

#ifdef WOLFMQTT_USER_SETTINGS
#include "user_settings.h"
#endif

#ifdef ENABLE_MQTT_TLS
    #if !defined(WOLFSSL_USER_SETTINGS) && !defined(USE_WINDOWS_API)
        #include <wolfssl/options.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/ssl.h>
    #include <wolfssl/wolfcrypt/types.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>

    #ifndef WOLF_TLS_DHKEY_BITS_MIN /* allow define to be overridden */
        #ifdef WOLFSSL_MAX_STRENGTH
            #define WOLF_TLS_DHKEY_BITS_MIN 2048
        #else
            #define WOLF_TLS_DHKEY_BITS_MIN 1024
        #endif
    #endif
#endif

#ifdef WOLFMQTT_MULTITHREAD
    /* Multi-threading uses binary semaphores */
    #if defined(WOLFMQTT_USER_THREADING)
        /* User provides API's and wm_Sem type.
         * Add your wc_Sem into user_settings.h */

    #elif defined(__MACH__)
        /* Apple Style Dispatch Semaphore */
        #include <dispatch/dispatch.h>
        typedef struct {
            dispatch_semaphore_t sem;
        } wm_Sem;

    #elif defined(__FreeBSD__) || defined(__linux__) || defined(__QNX__)
        /* Posix Style Pthread Mutex and Conditional */
        #define WOLFMQTT_POSIX_SEMAPHORES
        #include <pthread.h>
        typedef struct {
            volatile int lockCount;
            pthread_mutex_t mutex;
            pthread_cond_t cond;
        } wm_Sem;

    #elif defined(FREERTOS)
        /* FreeRTOS binary semaphore */
        #include <FreeRTOS.h>
        #include <semphr.h>
        typedef SemaphoreHandle_t wm_Sem;

    #elif defined(USE_WINDOWS_API)
        /* Windows semaphore object */
        #include <winsock2.h> /* winsock2.h needs included before windows.h */
        #include <ws2tcpip.h>
        #include <windows.h>
        typedef HANDLE wm_Sem;

    #else
        #error "Multithreading requires binary semaphore implementation!"
    #endif

    WOLFMQTT_API int wm_SemInit(wm_Sem* s);
    WOLFMQTT_API int wm_SemFree(wm_Sem* s);
    WOLFMQTT_API int wm_SemLock(wm_Sem* s);
    WOLFMQTT_API int wm_SemUnlock(wm_Sem* s);
#endif

/* configuration for Harmony */
#ifdef MICROCHIP_MPLAB_HARMONY
    #define NO_EXIT

    /* make sure we are using non-blocking for Harmony */
    #ifndef WOLFMQTT_NONBLOCK
        #define WOLFMQTT_NONBLOCK
    #endif

    #include "system_config.h"
    #ifdef SYS_CMD_ENABLE
        extern void SYS_CMD_PRINT(const char *format, ...);

        /* use SYS_PRINT for printf */
        #define WOLFMQTT_CUSTOM_PRINTF
        #define PRINTF(_f_, ...)  SYS_CMD_PRINT( (_f_ "\n"), ##__VA_ARGS__)
    #endif

#endif

#ifndef WOLFMQTT_NO_STDIO
    #include <stdio.h>
#endif

/* Allow custom override of data types */
#if !defined(WOLFMQTT_CUSTOM_TYPES) && !defined(WOLF_CRYPT_TYPES_H)
    /* Basic Types */
    #ifndef byte
        typedef unsigned char  byte;
    #endif
    #ifndef word16
        typedef unsigned short word16;
    #endif
    #ifndef word32
        typedef unsigned int   word32;
    #endif
    #define WOLFSSL_TYPES /* make sure wolfSSL knows we defined these types */
#endif

/* Response Codes */
enum MqttPacketResponseCodes {
    MQTT_CODE_SUCCESS = 0,
    MQTT_CODE_ERROR_BAD_ARG = -1,
    MQTT_CODE_ERROR_OUT_OF_BUFFER = -2,
    MQTT_CODE_ERROR_MALFORMED_DATA = -3, /* Error (Malformed Remaining Len) */
    MQTT_CODE_ERROR_PACKET_TYPE = -4,
    MQTT_CODE_ERROR_PACKET_ID = -5,
    MQTT_CODE_ERROR_TLS_CONNECT = -6,
    MQTT_CODE_ERROR_TIMEOUT = -7,
    MQTT_CODE_ERROR_NETWORK = -8,
    MQTT_CODE_ERROR_MEMORY = -9,
    MQTT_CODE_ERROR_STAT = -10,
    MQTT_CODE_ERROR_PROPERTY = -11,
    MQTT_CODE_ERROR_SERVER_PROP = -12,
    MQTT_CODE_ERROR_CALLBACK = -13,
    MQTT_CODE_ERROR_SYSTEM = -14,

    MQTT_CODE_CONTINUE = -101,
    MQTT_CODE_STDIN_WAKE = -102,
    MQTT_CODE_PUB_CONTINUE = -103,
};


/* Standard wrappers */
#ifndef WOLFMQTT_CUSTOM_STRING
    #include <string.h>

    #ifndef XSTRLEN
        #define XSTRLEN(s1)         strlen((s1))
    #endif
    #ifndef XSTRCHR
        #define XSTRCHR(s,c)        strchr((s),(c))
    #endif
    #ifndef XSTRNCMP
        #define XSTRNCMP(s1,s2,n)   strncmp((s1),(s2),(n))
    #endif
    #ifndef XSTRNCPY
        #define XSTRNCPY(s1,s2,n)   strncpy((s1),(s2),(n))
    #endif
    #ifndef XMEMCPY
        #define XMEMCPY(d,s,l)      memcpy((d),(s),(l))
    #endif
    #ifndef XMEMSET
        #define XMEMSET(b,c,l)      memset((b),(c),(l))
    #endif
    #ifndef XMEMCMP
        #define XMEMCMP(s1,s2,n)    memcmp((s1),(s2),(n))
    #endif
    #ifndef XATOI
        #define XATOI(s)            atoi((s))
    #endif
    #ifndef XISALNUM
        #define XISALNUM(c)         isalnum((c))
    #endif
    #ifndef XSNPRINTF
        #ifndef USE_WINDOWS_API
            #define XSNPRINTF        snprintf
        #else
            #define XSNPRINTF        _snprintf
        #endif
    #endif
#endif

#ifndef WOLFMQTT_CUSTOM_MALLOC
    #ifndef WOLFMQTT_MALLOC
        #define WOLFMQTT_MALLOC(s)  malloc((s))
    #endif
    #ifndef WOLFMQTT_FREE
        #define WOLFMQTT_FREE(p)    {void* xp = (p); if((xp)) free((xp));}
    #endif
#endif

#ifndef WOLFMQTT_PACK
    #if defined(__GNUC__)
        #define WOLFMQTT_PACK __attribute__ ((packed))
    #else
        #define WOLFMQTT_PACK
    #endif
#endif

/* use inlining if compiler allows */
#ifndef INLINE
#ifndef NO_INLINE
    #if defined(__GNUC__) || defined(__MINGW32__) || defined(__IAR_SYSTEMS_ICC__)
           #define INLINE inline
    #elif defined(_MSC_VER)
        #define INLINE __inline
    #elif defined(THREADX)
        #define INLINE _Inline
    #else
        #define INLINE
    #endif
#else
    #define INLINE
#endif /* !NO_INLINE */
#endif /* !INLINE */


/* printf */
#ifndef WOLFMQTT_CUSTOM_PRINTF
    #ifndef LINE_END
        #define LINE_END    "\n"
    #endif
    #ifndef PRINTF
        #if defined(WOLFMQTT_MULTITHREAD) && defined(WOLFMQTT_DEBUG_THREAD)
            #ifdef USE_WINDOWS_API
                #define PRINTF(_f_, ...)  printf( ("%lx: "_f_ LINE_END), GetCurrentThreadId(), ##__VA_ARGS__)
            #elif defined(__MACH__)
                #include <pthread.h>
                #define PRINTF(_f_, ...)  printf( ("%p: "_f_ LINE_END), (void*)pthread_self(), ##__VA_ARGS__)
            #else
                #include <pthread.h>
                #define PRINTF(_f_, ...)  printf( ("%lx: "_f_ LINE_END), pthread_self(), ##__VA_ARGS__)
            #endif
        #else
            #define PRINTF(_f_, ...)  printf( (_f_ LINE_END), ##__VA_ARGS__)
        #endif
    #endif

    #ifndef WOLFMQTT_NO_STDIO
        #include <stdlib.h>
        #include <string.h>
        #include <stdio.h>
    #else
        #undef PRINTF
        #define PRINTF
    #endif
#endif

#ifndef FALL_THROUGH
    /* GCC 7 has new switch() fall-through detection */
    #if defined(__GNUC__)
        #if ((__GNUC__ > 7) || ((__GNUC__ == 7) && (__GNUC_MINOR__ >= 1)))
            #undef  FALL_THROUGH
            #if defined(WOLFSSL_LINUXKM) && defined(fallthrough)
                #define FALL_THROUGH fallthrough
            #else
                #define FALL_THROUGH __attribute__ ((fallthrough));
            #endif
        #endif
    #endif
#endif /* FALL_THROUGH */
#if !defined(FALL_THROUGH) || defined(__XC32)
    /* use stub for fall through by default or for Microchip compiler */
    #undef  FALL_THROUGH
    #define FALL_THROUGH
#endif

/* No return macro */
#if defined(__IAR_SYSTEMS_ICC__) || defined(__GNUC__)
    #define WOLFMQTT_NORETURN __attribute__((noreturn))
#else
    #define WOLFMQTT_NORETURN
#endif

/* Logging / Tracing */
#ifdef WOLFMQTT_NO_STDIO
    #undef WOLFMQTT_DEBUG_CLIENT
    #undef WOLFMQTT_DEBUG_SOCKET
#endif

#ifdef WOLFMQTT_DEBUG_TRACE
#define MQTT_TRACE_ERROR(err) ({ PRINTF("ERROR: %d (%s:%d)", err, __FUNCTION__, __LINE__); err; })
#define MQTT_TRACE_MSG(msg)      PRINTF("%s: (%s:%d)", msg, __FUNCTION__, __LINE__);
#else
#define MQTT_TRACE_ERROR(err) err
#define MQTT_TRACE_MSG(msg)
#endif /* WOLFMQTT_DEBUG_TRACE */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_TYPES_H */
