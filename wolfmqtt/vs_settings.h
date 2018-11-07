/* Template build settings for Visual Studio projects */
/* This is meant to be customized */

#ifndef _WOLFMQTT_VS_SETTINGS_
#define _WOLFMQTT_VS_SETTINGS_


/* TLS Support */
#undef  ENABLE_MQTT_TLS
#define ENABLE_MQTT_TLS

/* MQTT-SN Support */
#undef  WOLFMQTT_SN
#define WOLFMQTT_SN

/* MQTT v5.0 support */
#undef  WOLFMQTT_V5
#define WOLFMQTT_V5

/* Enable property callback support */
#ifdef WOLFMQTT_V5
    #undef  WOLFMQTT_PROPERTY_CB
    #define WOLFMQTT_PROPERTY_CB
#endif

/* Non-blocking support */
#undef  WOLFMQTT_NONBLOCK
#define WOLFMQTT_NONBLOCK

/* Disable socket timeout code */
#undef  WOLFMQTT_NO_TIMEOUT
//#define WOLFMQTT_NO_TIMEOUT

/* Disconnect callback support */
#undef  WOLFMQTT_DISCONNECT_CB
#define WOLFMQTT_DISCONNECT_CB

/* Debugging */
#undef  DEBUG_WOLFMQTT
#define DEBUG_WOLFMQTT

#undef  WOLFMQTT_DEBUG_CLIENT
#define WOLFMQTT_DEBUG_CLIENT

#undef  WOLFMQTT_DEBUG_SOCKET
#define WOLFMQTT_DEBUG_SOCKET

/* Disable error strings */
#undef  WOLFMQTT_NO_ERROR_STRINGS
//#define WOLFMQTT_NO_ERROR_STRINGS


#endif /* _WOLFMQTT_VS_SETTINGS_ */
