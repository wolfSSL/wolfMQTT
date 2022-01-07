/* visibility.h
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

/* Visibility control macros */

#ifndef WOLFMQTT_VISIBILITY_H
#define WOLFMQTT_VISIBILITY_H

/* WOLFMQTT_API is used for the public API symbols.
        It either imports or exports (or does nothing for static builds)

   WOLFMQTT_LOCAL is used for non-API symbols (private).
*/

#if defined(BUILDING_WOLFMQTT)
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #ifdef _WINDLL
            #define WOLFMQTT_API __declspec(dllexport)
        #else
            #define WOLFMQTT_API
        #endif
        #define WOLFMQTT_LOCAL
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFMQTT_API   __attribute__ ((visibility("default")))
        #define WOLFMQTT_LOCAL __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFMQTT_API   __global
        #define WOLFMQTT_LOCAL __hidden
    #else
        #define WOLFMQTT_API
        #define WOLFMQTT_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* BUILDING_WOLFMQTT */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #ifdef _WINDLL
            #define WOLFMQTT_API __declspec(dllimport)
        #else
            #define WOLFMQTT_API
        #endif
        #define WOLFMQTT_LOCAL
    #else
        #define WOLFMQTT_API
        #define WOLFMQTT_LOCAL
    #endif
#endif /* BUILDING_WOLFMQTT */

#endif /* WOLFMQTT_VISIBILITY_H */
