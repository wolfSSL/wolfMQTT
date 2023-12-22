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

project(wolfMQTT VERSION 1.18.0 LANGUAGES C)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/functions.cmake)

find_package(Threads)

set(MQTT_SOURCES
    src/mqtt_client.c
    src/mqtt_packet.c
    src/mqtt_socket.c
    src/mqtt_sn_client.c
    src/mqtt_sn_packet.c
    )

# default to build shared library
option(BUILD_SHARED_LIBS "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" ON)
add_library(wolfmqtt ${MQTT_SOURCES})


if (WITH_WOLFSSL)
    target_link_libraries(wolfmqtt PUBLIC wolfssl)
    target_include_directories(wolfmqtt PUBLIC ${WITH_WOLFSSL}/include)
    target_link_directories(wolfmqtt PUBLIC ${WITH_WOLFSSL}/lib)
    list(APPEND WOLFMQTT_DEFINITIONS "-DENABLE_MQTT_TLS")
elseif (WITH_WOLFSSL_TREE)
    set(WOLFSSL_EXAMPLES "no" CACHE STRING "")
    set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "")

    add_subdirectory(${WITH_WOLFSSL_TREE} wolfssl)
    target_link_libraries(wolfmqtt PUBLIC wolfssl)
    list(APPEND WOLFMQTT_DEFINITIONS "-DENABLE_MQTT_TLS")
else()
    find_package(PkgConfig)
    pkg_check_modules(WOLFSSL wolfssl)

    if (WOLFSSL_FOUND)
        list(APPEND WOLFMQTT_DEFINITIONS "-DENABLE_MQTT_TLS")
        target_link_libraries(wolfmqtt PUBLIC ${WOLFSSL_LIBRARIES})
        target_include_directories(wolfmqtt PUBLIC ${WOLFSSL_INCLUDE_DIRS})
        target_link_directories(wolfmqtt PUBLIC ${WOLFSSL_LIBRARY_DIRS})
        target_compile_options(wolfmqtt PUBLIC ${WOLFSSL_CFLAGS_OTHER})
    else()
        # For support with vcpkg
        find_package(wolfssl CONFIG REQUIRED)
        if (wolfssl_FOUND)
            list(APPEND WOLFMQTT_DEFINITIONS "-DENABLE_MQTT_TLS")
            target_link_libraries(wolfmqtt PUBLIC wolfssl::wolfssl)
        endif()
    endif()
endif()


set(WOLFMQTT_EXAMPLES "yes" CACHE BOOL
    "Build examples")

target_compile_definitions(wolfmqtt PRIVATE
    "BUILDING_WOLFMQTT"
    )

    # Tell mqtt_types.h we are using a ./configure like output / options.h
target_compile_definitions(wolfmqtt PRIVATE
    "BUILDING_CMAKE"
    )

add_option(WOLFMQTT_TLS
           "Enable TLS support with wolfSSL"
           "yes" "yes;no")
if (WOLFMQTT_TLS)
    list(APPEND WOLFMQTT_DEFINITIONS "-DENABLE_MQTT_TLS")
endif()

add_option("WOLFMQTT_SN"
           "Enable MQTT-SN support"
           "no" "yes;no")
if (WOLFMQTT_SN)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_SN")
endif()

add_option("WOLFMQTT_NONBLOCK"
           "Enable non-blocking support"
           "no" "yes;no")
if (WOLFMQTT_NONBLOCK)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_NONBLOCK")
endif()

add_option(WOLFMQTT_TIMEOUT
           "Enable timeout support"
           "yes" "yes;no")
if (NOT WOLFMQTT_TIMEOUT)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_NO_TIMEOUT")
endif()
           
add_option(WOLFMQTT_ERRORSTRINGS
           "Enable error strings"
           "yes" "yes;no")
if (NOT WOLFMQTT_ERRORSTRINGS)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_NO_ERROR_STRINGS")
endif()

add_option(WOLFMQTT_STDINCAP
           "Enable examples STDIN capture"
           "yes" "yes;no")
if (NOT WOLFMQTT_STDINCAP)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_NO_STDIN_CAP")
endif()

add_option("WOLFMQTT_V5"
           "Enable MQTT v5.0 support"
           "no" "yes;no")
if (WOLFMQTT_V5)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_V5")
endif()

add_option(WOLFMQTT_DISCB
           "Enable disconnect callback"
           "yes" "yes;no")
if (WOLFMQTT_DISCB)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_DISCONNECT_CB")
endif()

add_option(WOLFMQTT_MT
           "Enable multiple thread support"
           "no" "yes;no")
if (WOLFMQTT_MT)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_MULTITHREAD")
endif()

add_option(WOLFMQTT_CURL
           "Enable curl easy socket backend"
           "no" "yes;no")
if (WOLFMQTT_CURL)
    list(APPEND WOLFMQTT_DEFINITIONS "-DENABLE_MQTT_CURL")
endif()


# generate options file
message("Generating user options header...")
if (${CMAKE_DISABLE_SOURCE_CHANGES})
    set(WOLFMQTT_BUILD_OUT_OF_TREE_DEFAULT "${CMAKE_DISABLE_SOURCE_CHANGES}")
else()
    set(WOLFMQTT_BUILD_OUT_OF_TREE_DEFAULT "no")
endif()

set(WOLFMQTT_BUILD_OUT_OF_TREE "${WOLFMQTT_BUILD_OUT_OF_TREE_DEFAULT}" CACHE STRING
    "Don't generate files in the source tree (default: ${WOLFMQTT_BUILD_OUT_OF_TREE_DEFAULT})")
set_property(CACHE WOLFMQTT_BUILD_OUT_OF_TREE
    PROPERTY STRINGS "yes;no")

if (${WOLFMQTT_BUILD_OUT_OF_TREE})
   set(WOLFMQTT_OUTPUT_BASE ${CMAKE_CURRENT_BINARY_DIR})
else()
   set(WOLFMQTT_OUTPUT_BASE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
set(OPTION_FILE "${WOLFMQTT_OUTPUT_BASE}/wolfmqtt/options.h")

file(REMOVE ${OPTION_FILE})

file(APPEND ${OPTION_FILE} "/* wolfmqtt options.h\n")
file(APPEND ${OPTION_FILE} " * generated from cmake configure options\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " * Copyright (C) 2006-2024 wolfSSL Inc.\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " * This file is part of wolfSSL.\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " */\n\n")
file(APPEND ${OPTION_FILE} "#ifndef WOLFMQTT_OPTIONS_H\n")
file(APPEND ${OPTION_FILE} "#define WOLFMQTT_OPTIONS_H\n\n\n")
file(APPEND ${OPTION_FILE} "#ifdef __cplusplus\n")
file(APPEND ${OPTION_FILE} "extern \"C\" {\n")
file(APPEND ${OPTION_FILE} "#endif\n\n")

add_to_options_file("${WOLFMQTT_DEFINITIONS}" "${OPTION_FILE}")
# CMAKE_C_FLAGS is just a string of space-separated flags to pass to the C
# compiler. We need to replace those spaces with semicolons in order to treat it
# as a CMake list.
string(REPLACE " " ";" CMAKE_C_FLAGS_LIST "${CMAKE_C_FLAGS}")
add_to_options_file("${CMAKE_C_FLAGS_LIST}" "${OPTION_FILE}")

file(APPEND ${OPTION_FILE} "\n#ifdef __cplusplus\n")
file(APPEND ${OPTION_FILE} "}\n")
file(APPEND ${OPTION_FILE} "#endif\n\n\n")
file(APPEND ${OPTION_FILE} "#endif /* WOLFMQTT_OPTIONS_H */\n\n")

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
    add_mqtt_example(mqtt-pub pub-sub/mqtt-pub.c)
    add_mqtt_example(mqtt-sub pub-sub/mqtt-sub.c)
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
