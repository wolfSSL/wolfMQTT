cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mqtt_client_tls)

FILE(GLOB app_sources ../../../examples/mqttclient/*.c ../../../examples/*.c ../*.c)
target_sources(app PRIVATE ${app_sources})
target_include_directories(app PRIVATE ${ZEPHYR_WOLFMQTT_MODULE_DIR}/zephyr/client_tls)
add_definitions(-DWOLFMQTT_ZEPHYR)
add_definitions(-DWOLFSSL_USER_SETTINGS)
add_definitions(-DWOLFMQTT_USER_SETTINGS)
