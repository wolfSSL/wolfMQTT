/* sparkplug.h
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
 * This example demonstrates the Sparkplug B specification using wolfMQTT.
 * It creates two MQTT clients:
 *   1. Edge Node - Publishes sensor data and responds to commands
 *   2. Host Application - Subscribes to data and sends commands
 *
 * Sparkplug Topic Namespace:
 *   spBv1.0/{group_id}/{message_type}/{edge_node_id}[/{device_id}]
 *
 * Message Types:
 *   NBIRTH - Node Birth Certificate
 *   NDEATH - Node Death Certificate
 *   DBIRTH - Device Birth Certificate
 *   DDEATH - Device Death Certificate
 *   NDATA  - Node Data
 *   DDATA  - Device Data
 *   NCMD   - Node Command
 *   DCMD   - Device Command
 *   STATE  - SCADA Host Application State
 *
 * Note: This example uses a simplified payload format instead of full
 * Protocol Buffers to keep dependencies minimal. In production, use
 * the official Sparkplug B protobuf definitions.
 */

#ifndef WOLFMQTT_SPARKPLUG_H
#define WOLFMQTT_SPARKPLUG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "examples/mqttexample.h"

/* Standard integer types for Sparkplug protocol */
#include <stdint.h>
#include <stdlib.h>  /* for rand() */

/* Define word64 if not already defined (wolfMQTT only defines byte/word16/word32) */
#ifndef word64
    typedef uint64_t word64;
#endif

/* Time support for timestamps */
#ifdef USE_WINDOWS_API
    /* Windows defines FILETIME */
#else
    #include <sys/time.h>
#endif

/* XSTRCMP and XSSCANF may not be defined by mqtt_types.h */
#ifndef XSTRCMP
    #define XSTRCMP(s1, s2) strcmp((s1), (s2))
#endif
#ifndef XSSCANF
    #define XSSCANF sscanf
#endif

/* Sparkplug configuration */
#define SPARKPLUG_NAMESPACE     "spBv1.0"
#define SPARKPLUG_GROUP_ID      "WolfMQTT"
#define SPARKPLUG_EDGE_NODE_ID  "EdgeNode1"
#define SPARKPLUG_DEVICE_ID     "Device1"
#define SPARKPLUG_HOST_ID       "HostApp1"

/* Topic buffer size */
#define SPARKPLUG_TOPIC_MAX_LEN 256

/* Sparkplug message types */
typedef enum SparkplugMsgType {
    SP_MSG_NBIRTH = 0,  /* Node Birth Certificate */
    SP_MSG_NDEATH,      /* Node Death Certificate */
    SP_MSG_DBIRTH,      /* Device Birth Certificate */
    SP_MSG_DDEATH,      /* Device Death Certificate */
    SP_MSG_NDATA,       /* Node Data */
    SP_MSG_DDATA,       /* Device Data */
    SP_MSG_NCMD,        /* Node Command */
    SP_MSG_DCMD,        /* Device Command */
    SP_MSG_STATE,       /* SCADA Host State */
    SP_MSG_COUNT
} SparkplugMsgType;

/* Sparkplug metric data types */
typedef enum SparkplugDataType {
    SP_DTYPE_INT8 = 1,
    SP_DTYPE_INT16,
    SP_DTYPE_INT32,
    SP_DTYPE_INT64,
    SP_DTYPE_UINT8,
    SP_DTYPE_UINT16,
    SP_DTYPE_UINT32,
    SP_DTYPE_UINT64,
    SP_DTYPE_FLOAT,
    SP_DTYPE_DOUBLE,
    SP_DTYPE_BOOLEAN,
    SP_DTYPE_STRING,
    SP_DTYPE_BYTES
} SparkplugDataType;

/* Metric value union */
typedef union SparkplugValue {
    int8_t   int8_val;
    int16_t  int16_val;
    int32_t  int32_val;
    int64_t  int64_val;
    uint8_t  uint8_val;
    uint16_t uint16_val;
    uint32_t uint32_val;
    uint64_t uint64_val;
    float    float_val;
    double   double_val;
    int      bool_val;
    char*    str_val;
    struct {
        byte*  data;
        word32 len;
    } bytes_val;
} SparkplugValue;

/* Sparkplug metric */
typedef struct SparkplugMetric {
    const char*       name;       /* Metric name */
    word64            alias;      /* Metric alias (optional) */
    word64            timestamp;  /* Metric timestamp (ms since epoch) */
    SparkplugDataType datatype;   /* Data type */
    SparkplugValue    value;      /* Metric value */
    int               is_null;    /* True if value is null */
} SparkplugMetric;

/* Sparkplug payload (simplified) */
#define SPARKPLUG_MAX_METRICS 16
typedef struct SparkplugPayload {
    word64          timestamp;   /* Payload timestamp */
    word64          seq;         /* Sequence number (0-255) */
    SparkplugMetric metrics[SPARKPLUG_MAX_METRICS];
    int             metric_count;
} SparkplugPayload;

/* Sparkplug client context extension */
typedef struct SparkplugCtx {
    MQTTCtx     mqttCtx;         /* Base MQTT context */
    const char* group_id;        /* Group ID */
    const char* edge_node_id;    /* Edge Node ID */
    const char* device_id;       /* Device ID (NULL for node-level) */
    word64      bdSeq;           /* Birth/Death sequence number */
    word64      seq;             /* Message sequence number */
    int         is_host;         /* True if this is a host application */
    char        topic_buf[SPARKPLUG_TOPIC_MAX_LEN];
} SparkplugCtx;

/* Message type string names */
static const char* sparkplug_msg_type_str[] = {
    "NBIRTH", "NDEATH", "DBIRTH", "DDEATH",
    "NDATA", "DDATA", "NCMD", "DCMD", "STATE"
};

/* Get message type string */
static INLINE const char* SparkplugMsgType_ToString(SparkplugMsgType type) {
    if (type < SP_MSG_COUNT) {
        return sparkplug_msg_type_str[type];
    }
    return "UNKNOWN";
}

/* Build Sparkplug topic string */
static INLINE int SparkplugTopic_Build(char* buf, int buf_len,
    const char* group_id, SparkplugMsgType msg_type,
    const char* edge_node_id, const char* device_id)
{
    int len;
    const char* type_str = SparkplugMsgType_ToString(msg_type);

    if (device_id != NULL) {
        len = XSNPRINTF(buf, buf_len, "%s/%s/%s/%s/%s",
            SPARKPLUG_NAMESPACE, group_id, type_str, edge_node_id, device_id);
    }
    else {
        len = XSNPRINTF(buf, buf_len, "%s/%s/%s/%s",
            SPARKPLUG_NAMESPACE, group_id, type_str, edge_node_id);
    }

    return len;
}

/* Parse Sparkplug topic to extract components */
static INLINE int SparkplugTopic_Parse(const char* topic,
    char* group_id, int group_len,
    SparkplugMsgType* msg_type,
    char* edge_node_id, int node_len,
    char* device_id, int device_len)
{
    char namespace_buf[16];
    char type_buf[16];
    int i, matched;

    /* Initialize outputs */
    if (group_id) group_id[0] = '\0';
    if (edge_node_id) edge_node_id[0] = '\0';
    if (device_id) device_id[0] = '\0';

    /* Parse topic: spBv1.0/group/type/node[/device] */
    matched = XSSCANF(topic, "%15[^/]/%63[^/]/%15[^/]/%63[^/]/%63s",
        namespace_buf, group_id, type_buf, edge_node_id, device_id);

    if (matched < 4) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Verify namespace */
    if (XSTRCMP(namespace_buf, SPARKPLUG_NAMESPACE) != 0) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Parse message type */
    if (msg_type) {
        *msg_type = SP_MSG_COUNT; /* Invalid default */
        for (i = 0; i < SP_MSG_COUNT; i++) {
            if (XSTRCMP(type_buf, sparkplug_msg_type_str[i]) == 0) {
                *msg_type = (SparkplugMsgType)i;
                break;
            }
        }
    }

    (void)group_len;
    (void)node_len;
    (void)device_len;

    return MQTT_CODE_SUCCESS;
}

/* Encode a simple payload (simplified format, not protobuf) */
/* Format: [timestamp:8][seq:8][count:4][metrics...] */
/* Metric: [name_len:2][name][alias:8][ts:8][type:1][value] */
static INLINE int SparkplugPayload_Encode(const SparkplugPayload* payload,
    byte* buf, int buf_len)
{
    int i, pos = 0;
    word16 name_len;

    if (buf_len < 20) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    /* Timestamp (8 bytes, big-endian) */
    buf[pos++] = (byte)(payload->timestamp >> 56);
    buf[pos++] = (byte)(payload->timestamp >> 48);
    buf[pos++] = (byte)(payload->timestamp >> 40);
    buf[pos++] = (byte)(payload->timestamp >> 32);
    buf[pos++] = (byte)(payload->timestamp >> 24);
    buf[pos++] = (byte)(payload->timestamp >> 16);
    buf[pos++] = (byte)(payload->timestamp >> 8);
    buf[pos++] = (byte)(payload->timestamp);

    /* Sequence (8 bytes) */
    buf[pos++] = (byte)(payload->seq >> 56);
    buf[pos++] = (byte)(payload->seq >> 48);
    buf[pos++] = (byte)(payload->seq >> 40);
    buf[pos++] = (byte)(payload->seq >> 32);
    buf[pos++] = (byte)(payload->seq >> 24);
    buf[pos++] = (byte)(payload->seq >> 16);
    buf[pos++] = (byte)(payload->seq >> 8);
    buf[pos++] = (byte)(payload->seq);

    /* Metric count (4 bytes) */
    buf[pos++] = (byte)(payload->metric_count >> 24);
    buf[pos++] = (byte)(payload->metric_count >> 16);
    buf[pos++] = (byte)(payload->metric_count >> 8);
    buf[pos++] = (byte)(payload->metric_count);

    /* Encode each metric */
    for (i = 0; i < payload->metric_count; i++) {
        const SparkplugMetric* m = &payload->metrics[i];

        /* Name length and name */
        name_len = (word16)XSTRLEN(m->name);
        if (pos + 2 + name_len + 17 > buf_len) {
            return MQTT_CODE_ERROR_OUT_OF_BUFFER;
        }
        buf[pos++] = (byte)(name_len >> 8);
        buf[pos++] = (byte)(name_len);
        XMEMCPY(&buf[pos], m->name, name_len);
        pos += name_len;

        /* Alias (8 bytes) */
        buf[pos++] = (byte)(m->alias >> 56);
        buf[pos++] = (byte)(m->alias >> 48);
        buf[pos++] = (byte)(m->alias >> 40);
        buf[pos++] = (byte)(m->alias >> 32);
        buf[pos++] = (byte)(m->alias >> 24);
        buf[pos++] = (byte)(m->alias >> 16);
        buf[pos++] = (byte)(m->alias >> 8);
        buf[pos++] = (byte)(m->alias);

        /* Timestamp (8 bytes) */
        buf[pos++] = (byte)(m->timestamp >> 56);
        buf[pos++] = (byte)(m->timestamp >> 48);
        buf[pos++] = (byte)(m->timestamp >> 40);
        buf[pos++] = (byte)(m->timestamp >> 32);
        buf[pos++] = (byte)(m->timestamp >> 24);
        buf[pos++] = (byte)(m->timestamp >> 16);
        buf[pos++] = (byte)(m->timestamp >> 8);
        buf[pos++] = (byte)(m->timestamp);

        /* Data type (1 byte) */
        buf[pos++] = (byte)m->datatype;

        /* Value based on type */
        switch (m->datatype) {
            case SP_DTYPE_BOOLEAN:
            case SP_DTYPE_INT8:
            case SP_DTYPE_UINT8:
                if (pos + 1 > buf_len) return MQTT_CODE_ERROR_OUT_OF_BUFFER;
                buf[pos++] = (byte)m->value.uint8_val;
                break;
            case SP_DTYPE_INT16:
            case SP_DTYPE_UINT16:
                if (pos + 2 > buf_len) return MQTT_CODE_ERROR_OUT_OF_BUFFER;
                buf[pos++] = (byte)(m->value.uint16_val >> 8);
                buf[pos++] = (byte)(m->value.uint16_val);
                break;
            case SP_DTYPE_INT32:
            case SP_DTYPE_UINT32:
            case SP_DTYPE_FLOAT:
                if (pos + 4 > buf_len) return MQTT_CODE_ERROR_OUT_OF_BUFFER;
                buf[pos++] = (byte)(m->value.uint32_val >> 24);
                buf[pos++] = (byte)(m->value.uint32_val >> 16);
                buf[pos++] = (byte)(m->value.uint32_val >> 8);
                buf[pos++] = (byte)(m->value.uint32_val);
                break;
            case SP_DTYPE_INT64:
            case SP_DTYPE_UINT64:
            case SP_DTYPE_DOUBLE:
                if (pos + 8 > buf_len) return MQTT_CODE_ERROR_OUT_OF_BUFFER;
                buf[pos++] = (byte)(m->value.uint64_val >> 56);
                buf[pos++] = (byte)(m->value.uint64_val >> 48);
                buf[pos++] = (byte)(m->value.uint64_val >> 40);
                buf[pos++] = (byte)(m->value.uint64_val >> 32);
                buf[pos++] = (byte)(m->value.uint64_val >> 24);
                buf[pos++] = (byte)(m->value.uint64_val >> 16);
                buf[pos++] = (byte)(m->value.uint64_val >> 8);
                buf[pos++] = (byte)(m->value.uint64_val);
                break;
            case SP_DTYPE_STRING:
                {
                    word16 str_len = (word16)XSTRLEN(m->value.str_val);
                    if (pos + 2 + str_len > buf_len) {
                        return MQTT_CODE_ERROR_OUT_OF_BUFFER;
                    }
                    buf[pos++] = (byte)(str_len >> 8);
                    buf[pos++] = (byte)(str_len);
                    XMEMCPY(&buf[pos], m->value.str_val, str_len);
                    pos += str_len;
                }
                break;
            case SP_DTYPE_BYTES:
                /* Bytes encoding not implemented in this example */
                break;
        }
    }

    return pos;
}

/* Decode a simple payload */
static INLINE int SparkplugPayload_Decode(const byte* buf, int buf_len,
    SparkplugPayload* payload)
{
    int i, pos = 0;
    word16 name_len;
    static char name_bufs[SPARKPLUG_MAX_METRICS][64];
    static char str_bufs[SPARKPLUG_MAX_METRICS][128];

    if (buf_len < 20) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }

    XMEMSET(payload, 0, sizeof(*payload));

    /* Timestamp */
    payload->timestamp = ((word64)buf[pos] << 56) | ((word64)buf[pos+1] << 48) |
                         ((word64)buf[pos+2] << 40) | ((word64)buf[pos+3] << 32) |
                         ((word64)buf[pos+4] << 24) | ((word64)buf[pos+5] << 16) |
                         ((word64)buf[pos+6] << 8) | (word64)buf[pos+7];
    pos += 8;

    /* Sequence */
    payload->seq = ((word64)buf[pos] << 56) | ((word64)buf[pos+1] << 48) |
                   ((word64)buf[pos+2] << 40) | ((word64)buf[pos+3] << 32) |
                   ((word64)buf[pos+4] << 24) | ((word64)buf[pos+5] << 16) |
                   ((word64)buf[pos+6] << 8) | (word64)buf[pos+7];
    pos += 8;

    /* Metric count */
    payload->metric_count = ((int)buf[pos] << 24) | ((int)buf[pos+1] << 16) |
                            ((int)buf[pos+2] << 8) | (int)buf[pos+3];
    pos += 4;

    if (payload->metric_count > SPARKPLUG_MAX_METRICS) {
        payload->metric_count = SPARKPLUG_MAX_METRICS;
    }

    /* Decode each metric */
    for (i = 0; i < payload->metric_count && pos < buf_len; i++) {
        SparkplugMetric* m = &payload->metrics[i];

        /* Name length and name */
        if (pos + 2 > buf_len) break;
        name_len = ((word16)buf[pos] << 8) | buf[pos+1];
        pos += 2;
        if (pos + name_len > buf_len || name_len >= sizeof(name_bufs[0])) break;
        XMEMCPY(name_bufs[i], &buf[pos], name_len);
        name_bufs[i][name_len] = '\0';
        m->name = name_bufs[i];
        pos += name_len;

        /* Alias */
        if (pos + 8 > buf_len) break;
        m->alias = ((word64)buf[pos] << 56) | ((word64)buf[pos+1] << 48) |
                   ((word64)buf[pos+2] << 40) | ((word64)buf[pos+3] << 32) |
                   ((word64)buf[pos+4] << 24) | ((word64)buf[pos+5] << 16) |
                   ((word64)buf[pos+6] << 8) | (word64)buf[pos+7];
        pos += 8;

        /* Timestamp */
        if (pos + 8 > buf_len) break;
        m->timestamp = ((word64)buf[pos] << 56) | ((word64)buf[pos+1] << 48) |
                       ((word64)buf[pos+2] << 40) | ((word64)buf[pos+3] << 32) |
                       ((word64)buf[pos+4] << 24) | ((word64)buf[pos+5] << 16) |
                       ((word64)buf[pos+6] << 8) | (word64)buf[pos+7];
        pos += 8;

        /* Data type */
        if (pos + 1 > buf_len) break;
        m->datatype = (SparkplugDataType)buf[pos++];

        /* Value based on type */
        switch (m->datatype) {
            case SP_DTYPE_BOOLEAN:
            case SP_DTYPE_INT8:
            case SP_DTYPE_UINT8:
                if (pos + 1 > buf_len) break;
                m->value.uint8_val = buf[pos++];
                break;
            case SP_DTYPE_INT16:
            case SP_DTYPE_UINT16:
                if (pos + 2 > buf_len) break;
                m->value.uint16_val = ((word16)buf[pos] << 8) | buf[pos+1];
                pos += 2;
                break;
            case SP_DTYPE_INT32:
            case SP_DTYPE_UINT32:
            case SP_DTYPE_FLOAT:
                if (pos + 4 > buf_len) break;
                m->value.uint32_val = ((word32)buf[pos] << 24) | ((word32)buf[pos+1] << 16) |
                                      ((word32)buf[pos+2] << 8) | buf[pos+3];
                pos += 4;
                break;
            case SP_DTYPE_INT64:
            case SP_DTYPE_UINT64:
            case SP_DTYPE_DOUBLE:
                if (pos + 8 > buf_len) break;
                m->value.uint64_val = ((word64)buf[pos] << 56) | ((word64)buf[pos+1] << 48) |
                                      ((word64)buf[pos+2] << 40) | ((word64)buf[pos+3] << 32) |
                                      ((word64)buf[pos+4] << 24) | ((word64)buf[pos+5] << 16) |
                                      ((word64)buf[pos+6] << 8) | (word64)buf[pos+7];
                pos += 8;
                break;
            case SP_DTYPE_STRING:
                {
                    word16 str_len;
                    if (pos + 2 > buf_len) break;
                    str_len = ((word16)buf[pos] << 8) | buf[pos+1];
                    pos += 2;
                    if (pos + str_len > buf_len || str_len >= sizeof(str_bufs[0])) break;
                    XMEMCPY(str_bufs[i], &buf[pos], str_len);
                    str_bufs[i][str_len] = '\0';
                    m->value.str_val = str_bufs[i];
                    pos += str_len;
                }
                break;
            case SP_DTYPE_BYTES:
                /* Unsupported type */
                break;
        }
    }

    return pos;
}

/* Get current timestamp in milliseconds */
static INLINE word64 SparkplugTimestamp_Get(void)
{
#if defined(_WIN32)
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    /* Convert from 100-nanosecond intervals since 1601 to ms since 1970 */
    return (uli.QuadPart - 116444736000000000ULL) / 10000;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (word64)tv.tv_sec * 1000 + (word64)tv.tv_usec / 1000;
#endif
}

/* Exposed functions */
int sparkplug_test(MQTTCtx *mqttCtx);

#if defined(NO_MAIN_DRIVER)
int sparkplug_main(int argc, char** argv);
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFMQTT_SPARKPLUG_H */
