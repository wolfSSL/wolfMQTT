/* mqtt_types.h
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

/* Implementation by: David Garske
 * Based on specification for MQTT v3.1.1
 * See http://mqtt.org/documentation for additional MQTT documentation.
 */

#ifndef WOLFMQTT_TYPES_H
#define WOLFMQTT_TYPES_H

#ifdef __cplusplus
    extern "C" {
#endif

#include "wolfmqtt/visibility.h"

/* Endianess check */
#if defined(__BIG_ENDIAN__) || defined(BIG_ENDIAN_ORDER)
    #error Big Endian is not yet supported. Please contact us if \
        you are interested in this feature.
#endif

#ifdef _WIN32
#define USE_WINDOWS_API
#endif

/* Allow custom override of data types */
#ifndef WOLFMQTT_CUSTOM_TYPES
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
    #ifndef XSTRCMP
        #define XSTRCMP(s1,s2)      strcmp((s1),(s2))
    #endif
    #ifndef XMEMCPY
        #define XMEMCPY(d,s,l)      memcpy((d),(s),(l))
    #endif
    #ifndef XMEMSET
        #define XMEMSET(b,c,l)      memset((b),(c),(l))
    #endif
    #ifndef XATOI
        #define XATOI(s)            atoi((s))
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

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_TYPES_H */
