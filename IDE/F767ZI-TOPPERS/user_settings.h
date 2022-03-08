/* user_settings.h
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

/* used by TOPPERS OS */
#ifndef _TOPPERS_USER_SETTINGS_H
#define _TOPPERS_USER_SETTINGS_H

#ifdef TOPPERS
    #define WOLFMQTT_USER_SETTINGS
    #define ENABLE_MQTT_TLS
    #define WOLFSSL_BASE64_ENCODE
    #define WOLFMQTT_NO_TIMEOUT
#endif

#endif /* _TOPPERS_USER_SETTINGS_H */
