/* firmware.h
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

#ifndef WOLFMQTT_FIRMWARE_H
#define WOLFMQTT_FIRMWARE_H

#ifdef __cplusplus
extern "C" {
#endif

#define FIRMWARE_TOPIC_NAME     "wolfMQTT/example/firmware"
#define FIRMWARE_MAX_BUFFER     2048
#define FIRMWARE_MAX_PACKET     (int)(FIRMWARE_MAX_BUFFER + sizeof(MqttPacket) + XSTRLEN(FIRMWARE_TOPIC_NAME) + MQTT_DATA_LEN_SIZE)
#define FIRMWARE_MQTT_QOS		MQTT_QOS_2

#define FIRMWARE_HASH_TYPE      WC_HASH_TYPE_SHA256
#define FIRMWARE_SIG_TYPE       WC_SIGNATURE_TYPE_ECC


/* Signature Len, Public Key Len, Firmware Len, Signature, Public Key, Data */
typedef struct _FirmwareHeader {
    word16 sigLen;
    word16 pubKeyLen;
    word32 fwLen;
} WOLFMQTT_PACK FirmwareHeader;

#ifdef __cplusplus
}
#endif

#endif /* WOLFMQTT_FIRMWARE_H */
