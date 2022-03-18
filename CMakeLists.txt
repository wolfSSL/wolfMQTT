# CMakeList.txt
#
# Copyright (C) 2006-2022 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# Usage:
# $ mkdir build
# $ cd build
# $ cmake ..
# $ cmake --build .
#
# To build with debugging use:
# $ cmake .. -DCMAKE_BUILD_TYPE=Debug
#
# See "CMake" in README.md for more.

####################################################
# Project
####################################################

cmake_minimum_required(VERSION 3.16)

project(wolfMQTT VERSION 11.0.0 LANGUAGES C)

set(MQTT_SOURCES
    src/mqtt_client.c
    src/mqtt_packet.c
    src/mqtt_socket.c
    )

add_library(wolfmqtt ${MQTT_SOURCES})


if (WITH_WOLFSSL)
    target_link_libraries(wolfmqtt wolfssl)
    target_include_directories(wolfmqtt PUBLIC ${WITH_WOLFSSL}/include)
    target_link_directories(wolfmqtt PUBLIC ${WITH_WOLFSSL}/lib)
    target_compile_definitions(wolfmqtt PUBLIC
        "ENABLE_MQTT_TLS"
        )
elseif (WITH_WOLFSSL_TREE)
    add_subdirectory(${WITH_WOLFSSL_TREE} wolfssl)
    target_link_libraries(wolfmqtt wolfssl)
    target_compile_definitions(wolfmqtt PUBLIC
        "ENABLE_MQTT_TLS"
        )
else()
    find_package(PkgConfig)
    pkg_check_modules(WOLFSSL wolfssl)

    if (WOLFSSL_FOUND)
        target_compile_definitions(wolfmqtt PUBLIC
            "ENABLE_MQTT_TLS"
            )
        target_link_libraries(wolfmqtt ${WOLFSSL_LIBRARIES})
        target_include_directories(wolfmqtt PUBLIC ${WOLFSSL_INCLUDE_DIRS})
        target_link_directories(wolfmqtt PUBLIC ${WOLFSSL_LIBRARY_DIRS})
        target_compile_options(wolfmqtt PUBLIC ${WOLFSSL_CFLAGS_OTHER})
    endif()
endif()


# TODO: add options
# * tls
# * sn
# * nonblock
# * timeout
# * examples
# * errorstrings
# * stdincap
# * v5
# * discb
# * mt

target_compile_definitions(wolfmqtt PRIVATE
    "BUILDING_WOLFMQTT"
    )

configure_file(wolfmqtt/options.h.in wolfmqtt/options.h)


if(WIN32)
    target_compile_definitions(wolfmqtt PRIVATE
        "_WINDLL"
        )
endif(WIN32)

target_include_directories(wolfmqtt
    PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    $<INSTALL_INTERFACE:wolfmqtt>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    )

add_library(mqtt_test_lib STATIC
    examples/mqttexample.c
    examples/mqttnet.c
    )
target_link_libraries(mqtt_test_lib wolfmqtt)

function(add_mqtt_example name src)
    add_executable(${name}
        examples/${src}
        )
    target_link_libraries(${name} wolfmqtt mqtt_test_lib)
endfunction()

#TODO generate options file


add_mqtt_example(mqttclient mqttclient/mqttclient.c)
add_mqtt_example(mqttsimple mqttsimple/mqttsimple.c)
add_mqtt_example(nbclient nbclient/nbclient.c)
#add_mqtt_example(mqttuart mqttuart.c)
add_mqtt_example(multithread multithread/multithread.c)
add_mqtt_example(sn-client sn-client/sn-client.c)
add_mqtt_example(sn-client_qos-1 sn-client/sn-client_qos-1.c)
add_mqtt_example(sn-multithread sn-client/sn-multithread.c)
add_mqtt_example(awsiot aws/awsiot.c)
add_mqtt_example(wiot wiot/wiot.c)
add_mqtt_example(azureiothub azure/azureiothub.c)
add_mqtt_example(fwpush firmware/fwpush.c)
add_mqtt_example(fwclient firmware/fwclient.c)


install(TARGETS wolfmqtt
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY)
# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/wolfmqtt/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wolfmqtt
        FILES_MATCHING PATTERN "*.h")
