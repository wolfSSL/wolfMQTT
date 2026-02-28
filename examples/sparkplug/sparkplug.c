/* sparkplug.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfMQTT.
 *
 * wolfMQTT is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* Sparkplug B Example
 *
 * This example demonstrates Sparkplug B industrial IoT protocol using wolfMQTT.
 * Two MQTT clients communicate:
 *   - Edge Node: Publishes sensor data, responds to commands
 *   - Host Application: Subscribes to data, sends commands
 *
 * To run:
 *   ./examples/sparkplug/sparkplug
 *
 * The example will:
 *   1. Connect both clients to the MQTT broker
 *   2. Edge Node publishes NBIRTH (Node Birth Certificate)
 *   3. Host subscribes to Sparkplug namespace
 *   4. Edge Node publishes DDATA (Device Data) with sensor values
 *   5. Host sends DCMD (Device Command) to toggle LED
 *   6. Edge Node receives command and updates state
 *   7. Both clients disconnect cleanly with NDEATH
 */

#include "wolfmqtt/mqtt_client.h"
#include "examples/mqttnet.h"
#include "examples/mqttexample.h"
#include "examples/sparkplug/sparkplug.h"

/* Enable for verbose debug output */
/* #define SPARKPLUG_DEBUG */

/* Configuration */
#define SPARKPLUG_QOS           MQTT_QOS_1
#define NUM_DATA_PUBLISHES      5
#define DATA_PUBLISH_INTERVAL   1  /* seconds */
#define MAX_BUFFER_SIZE         1024

/* Threading support */
#ifdef WOLFMQTT_MULTITHREAD
    #include "wolfmqtt/mqtt_types.h"

    #ifdef USE_WINDOWS_API
        typedef HANDLE THREAD_T;
        typedef DWORD  THREAD_RET_T;
        #define THREAD_RET_SUCCESS 0
        #define THREAD_CREATE(h, f, c) ((*h = CreateThread(NULL, 0, f, c, 0, NULL)) == NULL)
        #define THREAD_JOIN(h) WaitForSingleObject(h, INFINITE)
        #define THREAD_EXIT(c) ExitThread(c)
        #define SLEEP(ms) Sleep(ms)
    #else
        #include <pthread.h>
        #include <unistd.h>
        typedef pthread_t THREAD_T;
        typedef void*     THREAD_RET_T;
        #define THREAD_RET_SUCCESS NULL
        #define THREAD_CREATE(h, f, c) pthread_create(h, NULL, f, c)
        #define THREAD_JOIN(h) pthread_join(h, NULL)
        #define THREAD_EXIT(c) pthread_exit(c)
        #define SLEEP(ms) usleep((ms) * 1000)
    #endif

    static wm_Sem gSparkplugLock;
    static int    gStopFlag = 0;
    static int    gHostReady = 0;
    static int    gEdgeReady = 0;
    static int    gCmdReceived = 0;

    #define SPARKPLUG_LOCK()   wm_SemLock(&gSparkplugLock)
    #define SPARKPLUG_UNLOCK() wm_SemUnlock(&gSparkplugLock)
#else
    #define SPARKPLUG_LOCK()
    #define SPARKPLUG_UNLOCK()
#endif

/* Simulated sensor data */
static struct {
    float    temperature;    /* Temperature in Celsius */
    float    humidity;       /* Humidity in percent */
    int      led_state;      /* LED on/off */
    uint32_t counter;        /* Message counter */
} gSensorData = { 22.5f, 45.0f, 0, 0 };

/* Forward declarations */
static int edge_node_run(SparkplugCtx* spCtx);
#ifdef WOLFMQTT_MULTITHREAD
static int host_app_run(SparkplugCtx* spCtx);
#endif
static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
                          byte msg_new, byte msg_done);

/* Helper to print payload (used when SPARKPLUG_DEBUG is defined) */
#ifdef __GNUC__
__attribute__((unused))
#endif
static void print_payload(const char* prefix, const SparkplugPayload* payload)
{
    int i;
    PRINTF("%s: seq=%llu, timestamp=%llu, metrics=%d",
           prefix, (unsigned long long)payload->seq,
           (unsigned long long)payload->timestamp,
           payload->metric_count);
    for (i = 0; i < payload->metric_count; i++) {
        const SparkplugMetric* m = &payload->metrics[i];
        PRINTF("  [%d] %s (alias=%llu, type=%d):",
               i, m->name, (unsigned long long)m->alias, m->datatype);
        switch (m->datatype) {
            case SP_DTYPE_FLOAT:
                {
                    union { uint32_t u; float f; } conv;
                    conv.u = m->value.uint32_val;
                    PRINTF("      value = %.2f", conv.f);
                }
                break;
            case SP_DTYPE_BOOLEAN:
                PRINTF("      value = %s", m->value.uint8_val ? "true" : "false");
                break;
            case SP_DTYPE_UINT32:
                PRINTF("      value = %u", (unsigned int)m->value.uint32_val);
                break;
            case SP_DTYPE_STRING:
                PRINTF("      value = \"%s\"", m->value.str_val);
                break;
            case SP_DTYPE_INT8:
            case SP_DTYPE_INT16:
            case SP_DTYPE_INT32:
            case SP_DTYPE_INT64:
            case SP_DTYPE_UINT8:
            case SP_DTYPE_UINT16:
            case SP_DTYPE_UINT64:
            case SP_DTYPE_DOUBLE:
            case SP_DTYPE_BYTES:
                PRINTF("      value = (raw)");
                break;
        }
    }
}

/* Initialize Sparkplug context */
static int sparkplug_init(SparkplugCtx* spCtx, const char* client_id,
                          int is_host)
{
    MQTTCtx* mqttCtx = &spCtx->mqttCtx;

    XMEMSET(spCtx, 0, sizeof(*spCtx));

    /* Initialize base MQTT context */
    mqtt_init_ctx(mqttCtx);

    /* Set Sparkplug-specific fields */
    spCtx->group_id = SPARKPLUG_GROUP_ID;
    spCtx->edge_node_id = SPARKPLUG_EDGE_NODE_ID;
    spCtx->device_id = SPARKPLUG_DEVICE_ID;
    spCtx->is_host = is_host;
    spCtx->bdSeq = 0;
    spCtx->seq = 0;

    /* Override MQTT context settings */
    mqttCtx->client_id = client_id;
    mqttCtx->qos = SPARKPLUG_QOS;
    mqttCtx->retain = 0;
    mqttCtx->clean_session = 1;
    mqttCtx->keep_alive_sec = 60;
    mqttCtx->cmd_timeout_ms = 30000;

    return MQTT_CODE_SUCCESS;
}

/* Connect to MQTT broker */
static int sparkplug_connect(SparkplugCtx* spCtx)
{
    int rc;
    MQTTCtx* mqttCtx = &spCtx->mqttCtx;

    PRINTF("Sparkplug: Connecting %s to broker %s:%d...",
           mqttCtx->client_id, mqttCtx->host, mqttCtx->port);

    /* Initialize network */
    rc = MqttClientNet_Init(&mqttCtx->net, mqttCtx);
    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: Network init failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
        return rc;
    }

    /* Allocate buffers */
    mqttCtx->tx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    mqttCtx->rx_buf = (byte*)WOLFMQTT_MALLOC(MAX_BUFFER_SIZE);
    if (mqttCtx->tx_buf == NULL || mqttCtx->rx_buf == NULL) {
        return MQTT_CODE_ERROR_MEMORY;
    }

    /* Initialize MQTT client */
    rc = MqttClient_Init(&mqttCtx->client, &mqttCtx->net,
                         mqtt_message_cb,
                         mqttCtx->tx_buf, MAX_BUFFER_SIZE,
                         mqttCtx->rx_buf, MAX_BUFFER_SIZE,
                         mqttCtx->cmd_timeout_ms);
    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: MQTT init failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
        return rc;
    }

    /* Set context pointer for callbacks */
    mqttCtx->client.ctx = spCtx;

    /* Connect socket (loop for non-blocking) */
    do {
        rc = MqttClient_NetConnect(&mqttCtx->client, mqttCtx->host,
                                   mqttCtx->port, DEFAULT_CON_TIMEOUT_MS,
                                   mqttCtx->use_tls, mqtt_tls_cb);
    } while (rc == MQTT_CODE_CONTINUE);

    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: Socket connect failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
        return rc;
    }

    /* Build MQTT CONNECT packet */
    XMEMSET(&mqttCtx->connect, 0, sizeof(mqttCtx->connect));
    mqttCtx->connect.keep_alive_sec = mqttCtx->keep_alive_sec;
    mqttCtx->connect.clean_session = mqttCtx->clean_session;
    mqttCtx->connect.client_id = mqttCtx->client_id;

    /* Set Last Will and Testament (NDEATH) for Edge Node */
    if (!spCtx->is_host) {
        static byte lwt_payload[128];
        static MqttMessage lwt_msg;
        SparkplugPayload lwt_pl;
        int lwt_len;

        /* Build NDEATH payload */
        XMEMSET(&lwt_pl, 0, sizeof(lwt_pl));
        lwt_pl.timestamp = SparkplugTimestamp_Get();
        lwt_pl.seq = 0;
        lwt_pl.metric_count = 1;
        lwt_pl.metrics[0].name = "bdSeq";
        lwt_pl.metrics[0].datatype = SP_DTYPE_UINT64;
        lwt_pl.metrics[0].value.uint64_val = spCtx->bdSeq;
        lwt_pl.metrics[0].timestamp = lwt_pl.timestamp;

        lwt_len = SparkplugPayload_Encode(&lwt_pl, lwt_payload, sizeof(lwt_payload));
        if (lwt_len > 0) {
            /* Build NDEATH topic */
            SparkplugTopic_Build(spCtx->topic_buf, sizeof(spCtx->topic_buf),
                                spCtx->group_id, SP_MSG_NDEATH,
                                spCtx->edge_node_id, NULL);

            XMEMSET(&lwt_msg, 0, sizeof(lwt_msg));
            lwt_msg.qos = MQTT_QOS_1;
            lwt_msg.retain = 0;
            lwt_msg.topic_name = spCtx->topic_buf;
            lwt_msg.buffer = lwt_payload;
            lwt_msg.total_len = lwt_len;

            mqttCtx->connect.lwt_msg = &lwt_msg;
            mqttCtx->connect.enable_lwt = 1;

            PRINTF("Sparkplug: LWT configured on topic: %s", spCtx->topic_buf);
        }
    }

    /* Send CONNECT (loop for non-blocking and stdin wake) */
    do {
        rc = MqttClient_Connect(&mqttCtx->client, &mqttCtx->connect);
    } while (rc == MQTT_CODE_CONTINUE || rc == MQTT_CODE_STDIN_WAKE);

    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: MQTT connect failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
        return rc;
    }

    PRINTF("Sparkplug: Connected! (client_id=%s)", mqttCtx->client_id);
    return MQTT_CODE_SUCCESS;
}

/* Publish a Sparkplug message */
static int sparkplug_publish(SparkplugCtx* spCtx, SparkplugMsgType msg_type,
                             const char* device_id, SparkplugPayload* payload)
{
    int rc;
    MQTTCtx* mqttCtx = &spCtx->mqttCtx;
    byte payload_buf[MAX_BUFFER_SIZE];
    int payload_len;

    /* Build topic */
    SparkplugTopic_Build(spCtx->topic_buf, sizeof(spCtx->topic_buf),
                        spCtx->group_id, msg_type,
                        spCtx->edge_node_id, device_id);

    /* Set sequence number */
    payload->seq = spCtx->seq;
    if (msg_type != SP_MSG_NBIRTH && msg_type != SP_MSG_DBIRTH) {
        spCtx->seq = (spCtx->seq + 1) % 256;  /* 0-255 per spec */
    }

    /* Encode payload */
    payload_len = SparkplugPayload_Encode(payload, payload_buf, sizeof(payload_buf));
    if (payload_len <= 0) {
        PRINTF("Sparkplug: Payload encode failed");
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Setup publish */
    XMEMSET(&mqttCtx->publish, 0, sizeof(mqttCtx->publish));
    mqttCtx->publish.retain = 0;
    mqttCtx->publish.qos = mqttCtx->qos;
    mqttCtx->publish.duplicate = 0;
    mqttCtx->publish.topic_name = spCtx->topic_buf;
    mqttCtx->publish.packet_id = mqtt_get_packetid();
    mqttCtx->publish.buffer = payload_buf;
    mqttCtx->publish.total_len = payload_len;

#ifdef SPARKPLUG_DEBUG
    PRINTF("Sparkplug: Publishing to %s (%d bytes)", spCtx->topic_buf, payload_len);
    print_payload("  Payload", payload);
#else
    PRINTF("Sparkplug: Published %s to %s",
           SparkplugMsgType_ToString(msg_type), spCtx->topic_buf);
#endif

    /* Publish (loop for non-blocking) */
    do {
        rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
    } while (rc == MQTT_CODE_CONTINUE || rc == MQTT_CODE_PUB_CONTINUE);

    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: Publish failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
    }

    return rc;
}

/* Subscribe to Sparkplug topics */
static int sparkplug_subscribe(SparkplugCtx* spCtx, const char* topic_filter)
{
    int rc;
    MQTTCtx* mqttCtx = &spCtx->mqttCtx;
    static MqttTopic topics[1];

    XMEMSET(&mqttCtx->subscribe, 0, sizeof(mqttCtx->subscribe));
    mqttCtx->subscribe.packet_id = mqtt_get_packetid();
    mqttCtx->subscribe.topic_count = 1;
    topics[0].topic_filter = topic_filter;
    topics[0].qos = mqttCtx->qos;
    mqttCtx->subscribe.topics = topics;

    PRINTF("Sparkplug: Subscribing to %s", topic_filter);

    /* Subscribe (loop for non-blocking) */
    do {
        rc = MqttClient_Subscribe(&mqttCtx->client, &mqttCtx->subscribe);
    } while (rc == MQTT_CODE_CONTINUE);

    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: Subscribe failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
    }
    else {
        PRINTF("Sparkplug: Subscribed (granted QoS=%d)",
               topics[0].return_code);
    }

    return rc;
}

/* Disconnect from broker */
static int sparkplug_disconnect(SparkplugCtx* spCtx)
{
    int rc;
    MQTTCtx* mqttCtx = &spCtx->mqttCtx;

    PRINTF("Sparkplug: Disconnecting %s...", mqttCtx->client_id);

    /* MQTT Disconnect (loop for non-blocking) */
    do {
        rc = MqttClient_Disconnect(&mqttCtx->client);
    } while (rc == MQTT_CODE_CONTINUE);

    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: Disconnect failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
    }

    /* Network disconnect */
    MqttClient_NetDisconnect(&mqttCtx->client);

    /* Cleanup */
    MqttClientNet_DeInit(&mqttCtx->net);

    if (mqttCtx->tx_buf) {
        WOLFMQTT_FREE(mqttCtx->tx_buf);
        mqttCtx->tx_buf = NULL;
    }
    if (mqttCtx->rx_buf) {
        WOLFMQTT_FREE(mqttCtx->rx_buf);
        mqttCtx->rx_buf = NULL;
    }

    PRINTF("Sparkplug: Disconnected %s", mqttCtx->client_id);
    return rc;
}

/* Message callback */
static int mqtt_message_cb(MqttClient *client, MqttMessage *msg,
                          byte msg_new, byte msg_done)
{
    SparkplugCtx* spCtx = (SparkplugCtx*)client->ctx;
    SparkplugPayload payload;
    SparkplugMsgType msg_type;
    char group_id[64], node_id[64], device_id[64];
    int rc;

    if (msg_new) {
        /* Parse topic */
        char topic_str[SPARKPLUG_TOPIC_MAX_LEN];
        int topic_len = msg->topic_name_len;
        if (topic_len >= (int)sizeof(topic_str)) {
            topic_len = sizeof(topic_str) - 1;
        }
        XMEMCPY(topic_str, msg->topic_name, topic_len);
        topic_str[topic_len] = '\0';

        rc = SparkplugTopic_Parse(topic_str, group_id, sizeof(group_id),
                                  &msg_type, node_id, sizeof(node_id),
                                  device_id, sizeof(device_id));

        if (rc == MQTT_CODE_SUCCESS) {
            PRINTF("Sparkplug [%s]: Received %s from %s/%s%s%s",
                   spCtx->mqttCtx.client_id,
                   SparkplugMsgType_ToString(msg_type),
                   group_id, node_id,
                   device_id[0] ? "/" : "", device_id);

            /* Decode payload if complete */
            if (msg_done && msg->buffer_len > 0) {
                rc = SparkplugPayload_Decode(msg->buffer, msg->buffer_len, &payload);
                if (rc > 0) {
#ifdef SPARKPLUG_DEBUG
                    print_payload("  Received", &payload);
#endif

                    /* Handle message based on type and role */
                    if (spCtx->is_host) {
                        /* Host Application message handling */
                        switch (msg_type) {
                            case SP_MSG_NBIRTH:
                                PRINTF("  -> Edge Node came online (bdSeq=%llu)",
                                       (unsigned long long)payload.metrics[0].value.uint64_val);
                                break;
                            case SP_MSG_NDEATH:
                                PRINTF("  -> Edge Node went offline");
                                break;
                            case SP_MSG_DDATA:
                                {
                                    int i;
                                    PRINTF("  -> Device data received:");
                                    for (i = 0; i < payload.metric_count; i++) {
                                        const SparkplugMetric* m = &payload.metrics[i];
                                        if (m->datatype == SP_DTYPE_FLOAT) {
                                            union { uint32_t u; float f; } conv;
                                            conv.u = m->value.uint32_val;
                                            PRINTF("     %s = %.2f", m->name, conv.f);
                                        }
                                        else if (m->datatype == SP_DTYPE_BOOLEAN) {
                                            PRINTF("     %s = %s", m->name,
                                                   m->value.uint8_val ? "ON" : "OFF");
                                        }
                                        else if (m->datatype == SP_DTYPE_UINT32) {
                                            PRINTF("     %s = %u", m->name,
                                                   (unsigned int)m->value.uint32_val);
                                        }
                                    }
                                }
                                break;
                            case SP_MSG_DBIRTH:
                            case SP_MSG_DDEATH:
                            case SP_MSG_NDATA:
                            case SP_MSG_NCMD:
                            case SP_MSG_DCMD:
                            case SP_MSG_STATE:
                            case SP_MSG_COUNT:
                                /* Not handled by host in this example */
                                break;
                        }
                    }
                    else {
                        /* Edge Node message handling */
                        switch (msg_type) {
                            case SP_MSG_DCMD:
                                {
                                    int i;
                                    PRINTF("  -> Command received:");
                                    for (i = 0; i < payload.metric_count; i++) {
                                        const SparkplugMetric* m = &payload.metrics[i];
                                        if (XSTRCMP(m->name, "LED") == 0 &&
                                            m->datatype == SP_DTYPE_BOOLEAN) {
                                            gSensorData.led_state = m->value.uint8_val;
                                            PRINTF("     LED set to %s",
                                                   gSensorData.led_state ? "ON" : "OFF");
#ifdef WOLFMQTT_MULTITHREAD
                                            SPARKPLUG_LOCK();
                                            gCmdReceived = 1;
                                            SPARKPLUG_UNLOCK();
#endif
                                        }
                                    }
                                }
                                break;
                            case SP_MSG_NBIRTH:
                            case SP_MSG_NDEATH:
                            case SP_MSG_DBIRTH:
                            case SP_MSG_DDEATH:
                            case SP_MSG_NDATA:
                            case SP_MSG_DDATA:
                            case SP_MSG_NCMD:
                            case SP_MSG_STATE:
                            case SP_MSG_COUNT:
                                /* Not handled by edge node in this example */
                                break;
                        }
                    }
                }
            }
        }
        else {
            PRINTF("Sparkplug [%s]: Received non-Sparkplug message on topic: %s",
                   spCtx->mqttCtx.client_id, topic_str);
        }
    }

    (void)msg_done;
    return MQTT_CODE_SUCCESS;
}

/* Publish Node Birth Certificate */
static int edge_publish_nbirth(SparkplugCtx* spCtx)
{
    SparkplugPayload payload;
    union { float f; uint32_t u; } conv;

    XMEMSET(&payload, 0, sizeof(payload));
    payload.timestamp = SparkplugTimestamp_Get();
    payload.metric_count = 4;

    /* bdSeq metric (required) */
    payload.metrics[0].name = "bdSeq";
    payload.metrics[0].datatype = SP_DTYPE_UINT64;
    payload.metrics[0].value.uint64_val = spCtx->bdSeq;
    payload.metrics[0].timestamp = payload.timestamp;

    /* Define available metrics */
    payload.metrics[1].name = "Temperature";
    payload.metrics[1].alias = 1;
    payload.metrics[1].datatype = SP_DTYPE_FLOAT;
    conv.f = gSensorData.temperature;
    payload.metrics[1].value.uint32_val = conv.u;
    payload.metrics[1].timestamp = payload.timestamp;

    payload.metrics[2].name = "Humidity";
    payload.metrics[2].alias = 2;
    payload.metrics[2].datatype = SP_DTYPE_FLOAT;
    conv.f = gSensorData.humidity;
    payload.metrics[2].value.uint32_val = conv.u;
    payload.metrics[2].timestamp = payload.timestamp;

    payload.metrics[3].name = "LED";
    payload.metrics[3].alias = 3;
    payload.metrics[3].datatype = SP_DTYPE_BOOLEAN;
    payload.metrics[3].value.uint8_val = (uint8_t)gSensorData.led_state;
    payload.metrics[3].timestamp = payload.timestamp;

    spCtx->seq = 0;  /* Reset sequence on birth */
    return sparkplug_publish(spCtx, SP_MSG_NBIRTH, NULL, &payload);
}

/* Publish Device Data */
static int edge_publish_ddata(SparkplugCtx* spCtx)
{
    SparkplugPayload payload;
    union { float f; uint32_t u; } conv;

    /* Simulate sensor changes */
    gSensorData.temperature += ((float)(rand() % 100) - 50) / 100.0f;
    gSensorData.humidity += ((float)(rand() % 100) - 50) / 100.0f;
    gSensorData.counter++;

    if (gSensorData.humidity < 0) gSensorData.humidity = 0;
    if (gSensorData.humidity > 100) gSensorData.humidity = 100;

    XMEMSET(&payload, 0, sizeof(payload));
    payload.timestamp = SparkplugTimestamp_Get();
    payload.metric_count = 4;

    payload.metrics[0].name = "Temperature";
    payload.metrics[0].alias = 1;
    payload.metrics[0].datatype = SP_DTYPE_FLOAT;
    conv.f = gSensorData.temperature;
    payload.metrics[0].value.uint32_val = conv.u;
    payload.metrics[0].timestamp = payload.timestamp;

    payload.metrics[1].name = "Humidity";
    payload.metrics[1].alias = 2;
    payload.metrics[1].datatype = SP_DTYPE_FLOAT;
    conv.f = gSensorData.humidity;
    payload.metrics[1].value.uint32_val = conv.u;
    payload.metrics[1].timestamp = payload.timestamp;

    payload.metrics[2].name = "LED";
    payload.metrics[2].alias = 3;
    payload.metrics[2].datatype = SP_DTYPE_BOOLEAN;
    payload.metrics[2].value.uint8_val = (uint8_t)gSensorData.led_state;
    payload.metrics[2].timestamp = payload.timestamp;

    payload.metrics[3].name = "Counter";
    payload.metrics[3].alias = 4;
    payload.metrics[3].datatype = SP_DTYPE_UINT32;
    payload.metrics[3].value.uint32_val = gSensorData.counter;
    payload.metrics[3].timestamp = payload.timestamp;

    return sparkplug_publish(spCtx, SP_MSG_DDATA, spCtx->device_id, &payload);
}

#ifdef WOLFMQTT_MULTITHREAD
/* Host sends command to Edge Node */
static int host_send_command(SparkplugCtx* spCtx, int led_state)
{
    SparkplugPayload payload;
    int rc;
    MQTTCtx* mqttCtx = &spCtx->mqttCtx;
    byte payload_buf[MAX_BUFFER_SIZE];
    int payload_len;
    char topic[SPARKPLUG_TOPIC_MAX_LEN];

    XMEMSET(&payload, 0, sizeof(payload));
    payload.timestamp = SparkplugTimestamp_Get();
    payload.seq = 0;  /* Commands don't use sequence */
    payload.metric_count = 1;

    payload.metrics[0].name = "LED";
    payload.metrics[0].alias = 3;
    payload.metrics[0].datatype = SP_DTYPE_BOOLEAN;
    payload.metrics[0].value.uint8_val = (uint8_t)led_state;
    payload.metrics[0].timestamp = payload.timestamp;

    /* Build DCMD topic (target the edge node's device) */
    SparkplugTopic_Build(topic, sizeof(topic),
                        spCtx->group_id, SP_MSG_DCMD,
                        spCtx->edge_node_id, spCtx->device_id);

    /* Encode payload */
    payload_len = SparkplugPayload_Encode(&payload, payload_buf, sizeof(payload_buf));
    if (payload_len <= 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Setup publish */
    XMEMSET(&mqttCtx->publish, 0, sizeof(mqttCtx->publish));
    mqttCtx->publish.retain = 0;
    mqttCtx->publish.qos = mqttCtx->qos;
    mqttCtx->publish.topic_name = topic;
    mqttCtx->publish.packet_id = mqtt_get_packetid();
    mqttCtx->publish.buffer = payload_buf;
    mqttCtx->publish.total_len = payload_len;

    PRINTF("Sparkplug [Host]: Sending DCMD to %s (LED=%s)",
           topic, led_state ? "ON" : "OFF");

    /* Publish command (loop for non-blocking) */
    do {
        rc = MqttClient_Publish(&mqttCtx->client, &mqttCtx->publish);
    } while (rc == MQTT_CODE_CONTINUE || rc == MQTT_CODE_PUB_CONTINUE);

    if (rc != MQTT_CODE_SUCCESS) {
        PRINTF("Sparkplug: Command publish failed: %s (%d)",
               MqttClient_ReturnCodeToString(rc), rc);
    }

    return rc;
}
#endif /* WOLFMQTT_MULTITHREAD */

/* Edge Node main loop */
static int edge_node_run(SparkplugCtx* spCtx)
{
    int rc;
    int i;
#ifdef WOLFMQTT_MULTITHREAD
    int stop;
#endif

    /* Connect to broker */
    rc = sparkplug_connect(spCtx);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    /* Subscribe to commands */
    {
        char cmd_topic[SPARKPLUG_TOPIC_MAX_LEN];
        XSNPRINTF(cmd_topic, sizeof(cmd_topic), "%s/%s/DCMD/%s/#",
                  SPARKPLUG_NAMESPACE, spCtx->group_id, spCtx->edge_node_id);
        rc = sparkplug_subscribe(spCtx, cmd_topic);
        if (rc != MQTT_CODE_SUCCESS) {
            sparkplug_disconnect(spCtx);
            return rc;
        }
    }

    /* Publish NBIRTH */
    rc = edge_publish_nbirth(spCtx);
    if (rc != MQTT_CODE_SUCCESS) {
        sparkplug_disconnect(spCtx);
        return rc;
    }

#ifdef WOLFMQTT_MULTITHREAD
    /* Signal that edge node is ready */
    SPARKPLUG_LOCK();
    gEdgeReady = 1;
    SPARKPLUG_UNLOCK();

    /* Wait for host to be ready */
    do {
        SLEEP(100);
        SPARKPLUG_LOCK();
        stop = gHostReady;
        SPARKPLUG_UNLOCK();
    } while (!stop);
#endif

    /* Publish sensor data periodically */
    for (i = 0; i < NUM_DATA_PUBLISHES; i++) {
#ifdef WOLFMQTT_MULTITHREAD
        SPARKPLUG_LOCK();
        stop = gStopFlag;
        SPARKPLUG_UNLOCK();
        if (stop) break;
#endif

        /* Publish device data */
        rc = edge_publish_ddata(spCtx);
        if (rc != MQTT_CODE_SUCCESS) {
            break;
        }

        /* Wait and check for incoming commands */
        rc = MqttClient_WaitMessage(&spCtx->mqttCtx.client,
                                    DATA_PUBLISH_INTERVAL * 1000);
        if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            rc = MQTT_CODE_SUCCESS;  /* Timeout is OK */
        }
        else if (rc != MQTT_CODE_SUCCESS) {
            PRINTF("Sparkplug [Edge]: WaitMessage error: %s (%d)",
                   MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    }

    /* Disconnect */
    sparkplug_disconnect(spCtx);
    return rc;
}

#ifdef WOLFMQTT_MULTITHREAD
/* Host Application main loop */
static int host_app_run(SparkplugCtx* spCtx)
{
    int rc;
    int msg_count = 0;
    int cmd_sent = 0;
#ifdef WOLFMQTT_MULTITHREAD
    int stop;
#endif

    /* Connect to broker */
    rc = sparkplug_connect(spCtx);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    /* Subscribe to all Sparkplug messages in our group */
    {
        char sub_topic[SPARKPLUG_TOPIC_MAX_LEN];
        XSNPRINTF(sub_topic, sizeof(sub_topic), "%s/%s/#",
                  SPARKPLUG_NAMESPACE, spCtx->group_id);
        rc = sparkplug_subscribe(spCtx, sub_topic);
        if (rc != MQTT_CODE_SUCCESS) {
            sparkplug_disconnect(spCtx);
            return rc;
        }
    }

#ifdef WOLFMQTT_MULTITHREAD
    /* Signal that host is ready */
    SPARKPLUG_LOCK();
    gHostReady = 1;
    SPARKPLUG_UNLOCK();

    /* Wait for edge node to be ready */
    do {
        SLEEP(100);
        SPARKPLUG_LOCK();
        stop = gEdgeReady;
        SPARKPLUG_UNLOCK();
    } while (!stop);
#endif

    /* Wait for messages from Edge Node */
    while (msg_count < (NUM_DATA_PUBLISHES + 2)) {  /* +2 for NBIRTH and extra */
#ifdef WOLFMQTT_MULTITHREAD
        SPARKPLUG_LOCK();
        stop = gStopFlag;
        SPARKPLUG_UNLOCK();
        if (stop) break;
#endif

        rc = MqttClient_WaitMessage(&spCtx->mqttCtx.client, 2000);
        if (rc == MQTT_CODE_ERROR_TIMEOUT) {
            rc = MQTT_CODE_SUCCESS;
            msg_count++;  /* Count timeouts to eventually exit */
        }
        else if (rc == MQTT_CODE_SUCCESS) {
            msg_count++;

            /* Send command after receiving some data */
            if (!cmd_sent && msg_count >= 2) {
                PRINTF("Sparkplug [Host]: Sending command to toggle LED ON");
                host_send_command(spCtx, 1);  /* Turn LED ON */
                cmd_sent = 1;
            }
        }
        else {
            PRINTF("Sparkplug [Host]: WaitMessage error: %s (%d)",
                   MqttClient_ReturnCodeToString(rc), rc);
            break;
        }
    }

#ifdef WOLFMQTT_MULTITHREAD
    /* Signal stop */
    SPARKPLUG_LOCK();
    gStopFlag = 1;
    SPARKPLUG_UNLOCK();
#endif

    /* Disconnect */
    sparkplug_disconnect(spCtx);
    return rc;
}
#endif /* WOLFMQTT_MULTITHREAD */

#ifdef WOLFMQTT_MULTITHREAD
/* Thread functions */
static THREAD_RET_T edge_node_thread(void* arg)
{
    SparkplugCtx* spCtx = (SparkplugCtx*)arg;
    edge_node_run(spCtx);
    THREAD_EXIT(THREAD_RET_SUCCESS);
    return THREAD_RET_SUCCESS;
}

static THREAD_RET_T host_app_thread(void* arg)
{
    SparkplugCtx* spCtx = (SparkplugCtx*)arg;
    host_app_run(spCtx);
    THREAD_EXIT(THREAD_RET_SUCCESS);
    return THREAD_RET_SUCCESS;
}
#endif

/* Main test function */
int sparkplug_test(MQTTCtx *mqttCtx)
{
    int rc = 0;
    SparkplugCtx edgeCtx, hostCtx;

    PRINTF("Sparkplug B Example");
    PRINTF("===================");
    PRINTF("This example demonstrates two MQTT clients communicating");
    PRINTF("using the Sparkplug B industrial IoT protocol.\n");

#ifdef WOLFMQTT_MULTITHREAD
    {
        THREAD_T edge_thread, host_thread;

        /* Initialize synchronization */
        rc = wm_SemInit(&gSparkplugLock);
        if (rc != 0) {
            PRINTF("Failed to initialize semaphore");
            return rc;
        }

        gStopFlag = 0;
        gHostReady = 0;
        gEdgeReady = 0;
        gCmdReceived = 0;

        /* Initialize contexts */
        rc = sparkplug_init(&edgeCtx, "WolfMQTT_Sparkplug_Edge", 0);
        if (rc != MQTT_CODE_SUCCESS) {
            wm_SemFree(&gSparkplugLock);
            return rc;
        }

        rc = sparkplug_init(&hostCtx, "WolfMQTT_Sparkplug_Host", 1);
        if (rc != MQTT_CODE_SUCCESS) {
            wm_SemFree(&gSparkplugLock);
            return rc;
        }

        /* Copy host/port from provided context */
        if (mqttCtx != NULL) {
            edgeCtx.mqttCtx.host = mqttCtx->host;
            edgeCtx.mqttCtx.port = mqttCtx->port;
            edgeCtx.mqttCtx.use_tls = mqttCtx->use_tls;
            hostCtx.mqttCtx.host = mqttCtx->host;
            hostCtx.mqttCtx.port = mqttCtx->port;
            hostCtx.mqttCtx.use_tls = mqttCtx->use_tls;
        }

        PRINTF("Starting Edge Node and Host Application threads...\n");

        /* Start threads */
        if (THREAD_CREATE(&edge_thread, edge_node_thread, &edgeCtx) != 0) {
            PRINTF("Failed to create edge node thread");
            wm_SemFree(&gSparkplugLock);
            return -1;
        }

        if (THREAD_CREATE(&host_thread, host_app_thread, &hostCtx) != 0) {
            PRINTF("Failed to create host app thread");
            SPARKPLUG_LOCK();
            gStopFlag = 1;
            SPARKPLUG_UNLOCK();
            THREAD_JOIN(edge_thread);
            wm_SemFree(&gSparkplugLock);
            return -1;
        }

        /* Wait for threads to complete */
        THREAD_JOIN(edge_thread);
        THREAD_JOIN(host_thread);

        wm_SemFree(&gSparkplugLock);

        PRINTF("\nSparkplug example completed!");
    }
#else
    /* Single-threaded: run Edge Node first, then Host */
    PRINTF("Note: Running in single-threaded mode.");
    PRINTF("For full two-client demo, enable WOLFMQTT_MULTITHREAD.\n");

    rc = sparkplug_init(&edgeCtx, "WolfMQTT_Sparkplug_Edge", 0);
    if (rc != MQTT_CODE_SUCCESS) {
        return rc;
    }

    /* Copy host/port from provided context */
    if (mqttCtx != NULL) {
        edgeCtx.mqttCtx.host = mqttCtx->host;
        edgeCtx.mqttCtx.port = mqttCtx->port;
        edgeCtx.mqttCtx.use_tls = mqttCtx->use_tls;
    }

    PRINTF("Running Edge Node...\n");
    rc = edge_node_run(&edgeCtx);

    PRINTF("\nSparkplug example completed (single-threaded mode)!");
    (void)hostCtx;
#endif

    (void)mqttCtx;
    return rc;
}

#if defined(NO_MAIN_DRIVER)
int sparkplug_main(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
    int rc;
    MQTTCtx mqttCtx;

    /* Initialize context with defaults */
    mqtt_init_ctx(&mqttCtx);

    /* Parse command line arguments */
    mqttCtx.app_name = "sparkplug";
    rc = mqtt_parse_args(&mqttCtx, argc, argv);
    if (rc != 0) {
        return rc;
    }

    rc = sparkplug_test(&mqttCtx);

    mqtt_free_ctx(&mqttCtx);

    return (rc == 0) ? 0 : EXIT_FAILURE;
}
