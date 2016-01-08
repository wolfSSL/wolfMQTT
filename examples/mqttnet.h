/* mqttnet.h
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

#ifndef WOLFMQTT_NET_H
#define WOLFMQTT_NET_H

#ifdef __cplusplus
    extern "C" {
#endif


/* Default MQTT host broker to use, when none is specified in the examples */
#define DEFAULT_MQTT_HOST       "iot.eclipse.org" /* broker.hivemq.com */


/* Functions used to handle the MqttNet structure creation / destruction */
int MqttClientNet_Init(MqttNet* net);
int MqttClientNet_DeInit(MqttNet* net);

/* Standard In / Command handling */
int MqttClientNet_CheckForCommand(MqttNet* net, byte* buffer, word32 length);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFMQTT_NET_H */
