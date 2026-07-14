# CMakeLists.txt
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfMQTT
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

project(wolfMQTT VERSION 2.0.0 LANGUAGES C)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/functions.cmake)

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

# Maximum QoS supported (compile-time cap for both client and broker).
# Default 2 = full QoS support. 1 or 0 compiles out the broker's QoS 2
# state machine and the client's initial max_qos clamp, and causes the
# broker to advertise v5 MQTT_PROP_MAX_QOS in CONNACK.
set(WOLFMQTT_MAX_QOS "2" CACHE STRING
    "Maximum QoS supported by client and broker (0, 1, or 2)")
set_property(CACHE WOLFMQTT_MAX_QOS PROPERTY STRINGS "0;1;2")
if (NOT WOLFMQTT_MAX_QOS MATCHES "^[012]$")
    message(SEND_ERROR
        "WOLFMQTT_MAX_QOS must be 0, 1, or 2 (got: ${WOLFMQTT_MAX_QOS})")
endif()
list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_MAX_QOS=${WOLFMQTT_MAX_QOS}")
if (WOLFMQTT_DISCB)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_DISCONNECT_CB")
endif()

add_option(WOLFMQTT_MT
           "Enable multiple thread support"
           "no" "yes;no")
if (WOLFMQTT_MT)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_MULTITHREAD")
    find_package(Threads REQUIRED)
endif()

add_option(WOLFMQTT_CURL
           "Enable curl easy socket backend"
           "no" "yes;no")
if (WOLFMQTT_CURL)
    list(APPEND WOLFMQTT_DEFINITIONS "-DENABLE_MQTT_CURL")
endif()

# WebSocket
option(ENABLE_WEBSOCKET "Enable WebSocket support" OFF)
if(ENABLE_WEBSOCKET)
    # Add define
    add_definitions(-DENABLE_MQTT_WEBSOCKET)
    
    # Find libwebsockets
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(LIBWEBSOCKETS libwebsockets>=2.0.0)
    endif()
    
    if(LIBWEBSOCKETS_FOUND)
        include_directories(${LIBWEBSOCKETS_INCLUDE_DIRS})
        list(APPEND LIBS ${LIBWEBSOCKETS_LIBRARIES})
    else()
        # Try to find libwebsockets without pkg-config
        find_path(LIBWEBSOCKETS_INCLUDE_DIR libwebsockets.h)
        find_library(LIBWEBSOCKETS_LIBRARY websockets)
        
        if(LIBWEBSOCKETS_INCLUDE_DIR AND LIBWEBSOCKETS_LIBRARY)
            include_directories(${LIBWEBSOCKETS_INCLUDE_DIR})
            list(APPEND LIBS ${LIBWEBSOCKETS_LIBRARY})
        else()
            message(FATAL_ERROR "libwebsockets not found. Install libwebsockets or disable WebSocket support with -DENABLE_WEBSOCKET=OFF")
        endif()
    endif()
endif()

# Broker
add_option(WOLFMQTT_BROKER
           "Enable lightweight broker support"
           "no" "yes;no")
if (WOLFMQTT_BROKER)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER")

    add_option(WOLFMQTT_BROKER_RETAINED
               "Enable broker retained message support"
               "yes" "yes;no")
    if (NOT WOLFMQTT_BROKER_RETAINED)
        list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER_NO_RETAINED")
    endif()

    add_option(WOLFMQTT_BROKER_WILL
               "Enable broker Last Will and Testament support"
               "yes" "yes;no")
    if (NOT WOLFMQTT_BROKER_WILL)
        list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER_NO_WILL")
    endif()

    add_option(WOLFMQTT_BROKER_WILDCARDS
               "Enable broker wildcard topic matching"
               "yes" "yes;no")
    if (NOT WOLFMQTT_BROKER_WILDCARDS)
        list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER_NO_WILDCARDS")
    endif()

    add_option(WOLFMQTT_BROKER_AUTH
               "Enable broker username/password authentication"
               "yes" "yes;no")
    if (NOT WOLFMQTT_BROKER_AUTH)
        list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER_NO_AUTH")
    endif()

    add_option(WOLFMQTT_BROKER_LOG
               "Enable broker logging"
               "yes" "yes;no")
    if (NOT WOLFMQTT_BROKER_LOG)
        list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER_NO_LOG")
    endif()

    add_option(WOLFMQTT_BROKER_INSECURE
               "Enable broker plain-text (non-TLS) listener"
               "yes" "yes;no")
    if (NOT WOLFMQTT_BROKER_INSECURE)
        list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER_NO_INSECURE")
    endif()
endif()

# Note: not adding stress option to cmake build as of yet. stress is for
# testing only and requires the scripts/ dir to be useful.


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
    if (WOLFMQTT_MT)
        target_link_libraries(mqtt_test_lib wolfmqtt pthread)
    else()
        target_link_libraries(mqtt_test_lib wolfmqtt)
    endif()

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

if (WOLFMQTT_BROKER)
    add_executable(mqtt_broker src/mqtt_broker.c)
    target_link_libraries(mqtt_broker wolfmqtt)
    target_include_directories(mqtt_broker PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
endif()

add_option("WOLFMQTT_UNIT_TESTS"
           "Build unit tests (only when wolfMQTT is the top-level project)"
           "yes" "yes;no")
# Only build tests when wolfMQTT is the top-level project, to avoid adding
# a test target to parent projects that consume wolfMQTT via add_subdirectory.
if(WOLFMQTT_UNIT_TESTS AND CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    enable_testing()
    add_executable(wolfmqtt_unit_tests
        tests/unit_test.c
        tests/test_framework.c
        tests/test_mqtt_packet.c
        tests/test_mqtt_client.c
    )
    target_include_directories(wolfmqtt_unit_tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(wolfmqtt_unit_tests wolfmqtt)
    add_test(NAME wolfmqtt_unit_tests COMMAND wolfmqtt_unit_tests)
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

# Print configuration
message("-----------------------------------------------")
message("wolfMQTT Configuration:")
message("\tBuild Version:       ${VERSION}")
message("\tDebug Build:         ${DEBUG_WOLFMQTT}")
message("\tNon-Blocking:        ${ENABLE_NONBLOCK}")
message("\tMQTT-SN:             ${ENABLE_MQTT_SN}")
message("\tMQTT v5:             ${ENABLE_MQTT_V5}")
message("\tTLS:                 ${ENABLE_TLS}")
message("\tWebSocket:           ${ENABLE_WEBSOCKET}")
message("\tExamples:            ${ENABLE_EXAMPLES}")
message("\tFirmware Examples:   ${ENABLE_FIRMWARE_EXAMPLES}")
message("\tMultithread:         ${ENABLE_MULTITHREAD}")
message("\tCurl:                ${ENABLE_CURL}")
message("\tBroker:              ${WOLFMQTT_BROKER}")
message("-----------------------------------------------")

# ── SBOM generation target ────────────────────────────────────────────────────
#
# Usage:
#   cmake -B build -DWOLFSSL_DIR=/path/to/wolfssl/source .
#   cmake --build build
#   cmake --build build --target sbom
#
# WOLFSSL_DIR must point to a wolfssl source tree containing scripts/gen-sbom
# (feat/sbom-embedded branch). wolfSSL is NOT required to be installed for
# SBOM generation — only the source tree is needed to locate gen-sbom.
#
# Outputs in build directory:
#   wolfmqtt-<version>.cdx.json
#   wolfmqtt-<version>.spdx.json
#   wolfmqtt-<version>.spdx
#
# This mirrors the autotools `make sbom` target so both build systems emit
# byte-comparable SBOMs for the same source tree.

# Location of the wolfssl source tree that ships scripts/gen-sbom. A cache PATH
# (not a plain var) so it can be set on the command line with -DWOLFSSL_DIR=...
# and persists across reconfigures.
set(WOLFSSL_DIR "" CACHE PATH
    "Path to wolfssl source tree containing scripts/gen-sbom (for the sbom target)")

# Derive the SBOM version from wolfmqtt/version.h, NOT from PROJECT_VERSION.
# version.h is the single source of truth shared with the autotools build
# (PACKAGE_VERSION is generated from it); project(VERSION ...) is hand-maintained
# and can drift, which would make the cmake SBOM disagree with the autotools one.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/wolfmqtt/version.h" WOLFMQTT_VERSION_LINE
     REGEX "^#define[ \t]+LIBWOLFMQTT_VERSION_STRING[ \t]+\"")
string(REGEX REPLACE "^.*\"([^\"]+)\".*$" "\\1"
       WOLFMQTT_SBOM_VERSION "${WOLFMQTT_VERSION_LINE}")

set(SBOM_CDX     "wolfmqtt-${WOLFMQTT_SBOM_VERSION}.cdx.json")
set(SBOM_SPDX    "wolfmqtt-${WOLFMQTT_SBOM_VERSION}.spdx.json")
set(SBOM_SPDX_TV "wolfmqtt-${WOLFMQTT_SBOM_VERSION}.spdx")

# gen-sbom runs under python3; pyspdxtools validates the SPDX tag-value output.
# Both are required — fail at configure time so the user fixes their environment
# before building rather than hitting a confusing failure mid-`--target sbom`.
find_program(PYTHON3_EXECUTABLE python3)
find_program(PYSPDXTOOLS_EXECUTABLE pyspdxtools)

# WOLFSSL_DIR (a wolfssl source tree with scripts/gen-sbom) is required only to
# actually build the sbom target. CI and default builds never set it, so checking
# it at configure time would abort every build. Mirror the autotools `make sbom`
# recipe: configure always succeeds; if WOLFSSL_DIR is unset, define a stub sbom
# target that fails clearly at BUILD time. An empty WOLFSSL_DIR is the common
# first-run mistake.
if(WOLFSSL_DIR STREQUAL "")
    add_custom_target(sbom
        COMMAND ${CMAKE_COMMAND} -E echo
                "ERROR: WOLFSSL_DIR is not set. Cannot locate gen-sbom."
        COMMAND ${CMAKE_COMMAND} -E echo
                "       Reconfigure with: cmake -B build -DWOLFSSL_DIR=/path/to/wolfssl ."
        COMMAND ${CMAKE_COMMAND} -E false
        COMMENT "SBOM target requires -DWOLFSSL_DIR")
    return()
endif()

# WOLFSSL_DIR is set: the operator opted into SBOM generation. Validate the rest
# of the environment now so they get immediate, actionable feedback.
if(NOT EXISTS "${WOLFSSL_DIR}/scripts/gen-sbom")
    message(FATAL_ERROR
        "gen-sbom not found at ${WOLFSSL_DIR}/scripts/gen-sbom.\n"
        "  WOLFSSL_DIR must point to a wolfssl source tree (feat/sbom-embedded).")
endif()
if(NOT PYTHON3_EXECUTABLE)
    message(FATAL_ERROR "python3 not found in PATH. Cannot generate SBOM.")
endif()
if(NOT PYSPDXTOOLS_EXECUTABLE)
    message(FATAL_ERROR
        "pyspdxtools not found in PATH. Cannot validate SBOM.\n"
        "  Install with: pip install spdx-tools")
endif()

# Staging dir for `cmake --install` so gen-sbom hashes the as-installed
# library without polluting the system or requiring root.
set(SBOM_STAGING "${CMAKE_BINARY_DIR}/_sbom_staging")

add_custom_target(sbom
    # Install into the staging dir so the SBOM hashes the real installed
    # artifact rather than a build-tree intermediate.
    COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR}
            --prefix ${SBOM_STAGING}/usr/local

    # The generated options.h is passed to gen-sbom directly, the same input
    # the autotools `make sbom` feeds it, so both build systems record an
    # identical compile-time option fingerprint.  (No shell redirection here:
    # add_custom_target COMMANDs do not run through a shell under VERBATIM.)
    COMMAND ${PYTHON3_EXECUTABLE} ${WOLFSSL_DIR}/scripts/gen-sbom
            --name wolfmqtt
            --version ${WOLFMQTT_SBOM_VERSION}
            --supplier "wolfSSL Inc."
            --license-file ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
            # Match the autotools default (SBOM_LICENSE_OVERRIDE in
            # scripts/sbom.am): source headers say GPLv3 or later, which
            # LICENSE-file detection alone records as GPL-3.0-only.
            --license-override GPL-3.0-or-later
            --options-h ${WOLFMQTT_OUTPUT_BASE}/wolfmqtt/options.h
            --lib ${SBOM_STAGING}/usr/local/lib/$<TARGET_FILE_NAME:wolfmqtt>
            --cdx-out ${CMAKE_BINARY_DIR}/${SBOM_CDX}
            --spdx-out ${CMAKE_BINARY_DIR}/${SBOM_SPDX}

    # Validate the SPDX output and emit the tag-value (.spdx) rendering.
    COMMAND ${PYSPDXTOOLS_EXECUTABLE}
            --infile ${CMAKE_BINARY_DIR}/${SBOM_SPDX}
            --outfile ${CMAKE_BINARY_DIR}/${SBOM_SPDX_TV}

    # Remove the staging tree; keep only the three SBOM files.
    # (-E remove_directory, not -E rm: the latter needs CMake >= 3.17 and
    # this project's minimum is 3.16.)
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${SBOM_STAGING}

    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Generating SBOM for wolfMQTT ${WOLFMQTT_SBOM_VERSION}"
    VERBATIM)

# The library must exist before we install/hash it.
add_dependencies(sbom wolfmqtt)
