#ifndef WOLFMQTT_ZEPHYR_SAMPLE_SETTINGS_H
#define WOLFMQTT_ZEPHYR_SAMPLE_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#undef NO_FILESYSTEM
#define NO_FILESYSTEM

#define WOLFMQTT_TOPIC_NAME "sensors"
#define DEFAULT_MQTT_HOST "192.0.2.2"
#define NO_MAIN_DRIVER

#if defined(CONFIG_WOLFSSL_DEBUG)
#undef  DEBUG_WOLFSSL
#define DEBUG_WOLFSSL
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFMQTT_ZEPHYR_SAMPLE_SETTINGS_H */

