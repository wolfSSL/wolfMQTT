# CMakeList.txt
#
# Copyright (C) 2006-2023 wolfSSL Inc.
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

project(wolfMQTT VERSION 1.16.0 LANGUAGES C)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(MQTT_SOURCES
    src/mqtt_client.c
    src/mqtt_packet.c
    src/mqtt_socket.c
    )

# default to build shared library
option(BUILD_SHARED_LIBS "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" ON)
add_library(wolfmqtt ${MQTT_SOURCES})


if (WITH_WOLFSSL)
    target_link_libraries(wolfmqtt PUBLIC wolfssl)
    target_include_directories(wolfmqtt PUBLIC ${WITH_WOLFSSL}/include)
    target_link_directories(wolfmqtt PUBLIC ${WITH_WOLFSSL}/lib)
    target_compile_definitions(wolfmqtt PUBLIC
        "ENABLE_MQTT_TLS"
        )
elseif (WITH_WOLFSSL_TREE)
    set(WOLFSSL_EXAMPLES "no" CACHE STRING "")
    set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "")

    add_subdirectory(${WITH_WOLFSSL_TREE} wolfssl)
    target_link_libraries(wolfmqtt PUBLIC wolfssl)
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
        target_link_libraries(wolfmqtt PUBLIC ${WOLFSSL_LIBRARIES})
        target_include_directories(wolfmqtt PUBLIC ${WOLFSSL_INCLUDE_DIRS})
        target_link_directories(wolfmqtt PUBLIC ${WOLFSSL_LIBRARY_DIRS})
        target_compile_options(wolfmqtt PUBLIC ${WOLFSSL_CFLAGS_OTHER})
    else()
        # For support with vcpkg
        find_package(wolfssl CONFIG)
        if (wolfssl_FOUND)
            target_compile_definitions(wolfmqtt PUBLIC
                "ENABLE_MQTT_TLS"
                )
            target_link_libraries(wolfmqtt PUBLIC wolfssl)
        endif()
    endif()
endif()


# TODO: add options
# * tls
# * sn
# * nonblock
# * timeout
# * errorstrings
# * stdincap
# * v5
# * discb
# * mt

set(WOLFMQTT_EXAMPLES "yes" CACHE BOOL
    "Build examples")

target_compile_definitions(wolfmqtt PRIVATE
    "BUILDING_WOLFMQTT"
    )

    # Tell mqtt_types.h we are using a ./configure like output / options.h
target_compile_definitions(wolfmqtt PRIVATE
    "BUILDING_CMAKE"
    )

#TODO generate options file
configure_file(wolfmqtt/options.h.in wolfmqtt/options.h)

if(WIN32)
    target_compile_definitions(wolfmqtt PRIVATE
        "_WINDLL"
        )
endif(WIN32)

target_include_directories(wolfmqtt
    PUBLIC
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    )


if (WOLFMQTT_EXAMPLES)
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
endif()

####################################################
# Installation
####################################################

include(GNUInstallDirs)

install(TARGETS wolfmqtt
        EXPORT  wolfmqtt-targets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        )

# Install the export set
install(EXPORT wolfmqtt-targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wolfmqtt
        FILE wolfmqtt-config.cmake)

# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/wolfmqtt/
        DESTINATION include/wolfmqtt
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/wolfmqtt/
        DESTINATION include/wolfmqtt
        FILES_MATCHING PATTERN "*.h")
