cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mqtt_client)

FILE(GLOB app_sources ../../../examples/mqttclient/*.c ../../../examples/*.c ../*.c)
target_sources(app PRIVATE ${app_sources})
target_include_directories(app PUBLIC ${ZEPHYR_WOLFMQTT_MODULE_DIR}/zephyr/client)
add_definitions(-DWOLFMQTT_ZEPHYR)
add_definitions(-DWOLFMQTT_USER_SETTINGS)
