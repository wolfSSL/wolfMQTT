#
# Copyright (C) 2006-2023 wolfSSL Inc.  All rights reserved.
#
# This file is part of wolfMQTT.
#
# Contact licensing@wolfssl.com with any questions or comments.
#
# https://www.wolfssl.com
#/

#
# This is the CMakeLists.txt for the Espressif ESP-IDF wolfMQTT component
#
cmake_minimum_required(VERSION 3.5)

# Attention!
#
# When editing component CMake files, consider the following :
#
# NO Managed Componenets: Normal stand-alone app, "as cloned" from github.
#   There's no notion of staging names (e.g. mywolfmqtt) regardless of environment settings.
#   All of the component source is locall. See settings such s WOLFSSL_ROOT=[your path]
#
# Partially Managed Components. This one is tricky. When publishing a component with examples,
#    those examples will have a chicken-and-egg problem: the required component is not yet published.
#    Adding to the complexity is the notion of staging components, that are purposely prefixed with
#    "my" (e.g. mywolfmqtt) to distinguish from production, live components (e.g. wolfmqtt)
#
#    Partially Managed Component Examples are typically only encountered by the component publisher
#    and only at publish time, such as when performing the pre-publish build check.
#
#    A partially managed component may also be manually created, when adding a managed component to
#    and existing project. For example:
#
#       idf.py add-dependency "wolfssl/wolfssh^1.4.15-stable"
#
# Fully Managaged Componenets. This is the typical example as created from the Component Registry:
#    For example:
#
#       idf.py create-project-from-example "wolfssl/wolfssh^1.4.15-stable:wolfssh_server"
#
# In all cases, keep in mind that components other than wolfssl will depend on the wolfssl component.
#

# Component naming is only adjusted when using Managed Components, and only when using staging site.
if( "$ENV{IDF_COMPONENT_REGISTRY_URL}" STREQUAL "https://components-staging.espressif.com" )
    # TODO: Is checking these two variables really the best way to detect an active Component Manager?
    message(STATUS "component_manager_interface_version = ${component_manager_interface_version}")
    message(STATUS "managed_components = ${managed_components}")
    if( ("${managed_components}" STREQUAL "") AND ("${component_manager_interface_version}" STREQUAL "") )
        # We've found a staging component, but did not detect the component manager
        set(WOLFSSL_COMPONENT_NAME "wolfssl")
    else()
        set(WOLFSSL_COMPONENT_NAME "mywolfssl")
    endif()
else()
    set(WOLFSSL_COMPONENT_NAME "wolfssl")
endif()

# COMPONENT_NAME = wolfmqtt
# The component name is the directory name. "No feature to change this".
# See https://github.com/espressif/esp-idf/issues/8978#issuecomment-1129892685

# set the root of wolfMQTT in top-level project CMakelists.txt:
#   set(WOLFMQTT_ROOT  "C:/some path/with/spaces")
#   set(WOLFMQTT_ROOT  "c:/workspace/wolfmqtt-[username]")
#   set(WOLFMQTT_ROOT  "/mnt/c/some path/with/spaces")
#   or use this logic to assign value from Environment Variable WOLFMQTT_ROOT,
#   or assume this is an example 7 subdirectories below:

# We are typically in [root]/IDE/Espressif/ESP-IDF/examples/wolfssl_test/components/wolfssl
# The root of wolfSSL is 7 directories up from here:

# function: IS_WOLFMQTT_SOURCE
#  parameter: DIRECTORY_PARAMETER - the directory to test
#  output:    RESULT = contains contents of DIRECTORY_PARAMETER for wolfmqtt directory, otherwise blank.
function(IS_WOLFMQTT_SOURCE DIRECTORY_PARAMETER RESULT)
    if (EXISTS "${DIRECTORY_PARAMETER}/wolfmqtt/mqtt_client.h")
        if (EXISTS "${DIRECTORY_PARAMETER}/wolfmqtt")
            message(STATUS "1")
        endif()
        if (EXISTS "${DIRECTORY_PARAMETER}")
            message(STATUS "2")
        endif()
        if (EXISTS "${DIRECTORY_PARAMETER}/src")
            message(STATUS "3")
        endif()
        set(${RESULT} "${DIRECTORY_PARAMETER}" PARENT_SCOPE)
    else()
        set(${RESULT} "" PARENT_SCOPE)
    endif()
endfunction()

# function: FIND_WOLFMQTT_DIRECTORY
#  parameter: OUTPUT_FOUND_WOLFMQTT_DIRECTORY contains root of source code, otherwise blank
#
function(FIND_WOLFMQTT_DIRECTORY OUTPUT_FOUND_WOLFMQTT_DIRECTORY)
    message(STATUS "Starting FIND_WOLFMQTT_DIRECTORY")
    set(CURRENT_SEARCH_DIR "$ENV{WOLFMQTT_ROOT}")
    if( "${CURRENT_SEARCH_DIR}" STREQUAL "" )
        message(STATUS "The WOLFMQTT_ROOT environment variable is not set. Searching...")
    else()
        get_filename_component(CURRENT_SEARCH_DIR "$ENV{WOLFMQTT_ROOT}" ABSOLUTE)
        IS_WOLFMQTT_SOURCE("${CURRENT_SEARCH_DIR}" FOUND_WOLFMQTT)
        if("${FOUND_WOLFMQTT}")
            message(STATUS "Found WOLFMQTT_ROOT via Environment Variable:")
        else()
            message(FATAL_ERROR "WOLFMQTT_ROOT Environment Variable defined, but path not found:")
            message(STATUS "$ENV{WOLFMQTT_ROOT}")
        endif()
    endif()

    # we'll start in the CMAKE_CURRENT_SOURCE_DIR, typically [something]/projectname/components/wolfmqtt
    message(STATUS "CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")
    get_filename_component(CURRENT_SEARCH_DIR "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)
    message(STATUS "CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
    string(LENGTH ${CURRENT_SEARCH_DIR} CURRENT_SEARCH_DIR_LENGTH)

    # loop through all the parents, looking for wolfmqtt
    while(NOT CURRENT_SEARCH_DIR STREQUAL "/" AND NOT CURRENT_SEARCH_DIR STREQUAL "" )
        string(LENGTH ${CURRENT_SEARCH_DIR} CURRENT_SEARCH_DIR_LENGTH)
        # wolfmqtt may simply be in a parent directory, such as for local examples in wolfmqtt repo
        IS_WOLFMQTT_SOURCE("${CURRENT_SEARCH_DIR}" FOUND_WOLFMQTT)
        if( FOUND_WOLFMQTT )
            message(STATUS "Found wolfmqtt in CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
            set(${OUTPUT_FOUND_WOLFMQTT_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
            return()
        endif()

        if( THIS_USER )
            # Check for "wolfmqtt-[username]" subdirectory as we recurse up the directory tree
            set(CURRENT_SEARCH_DIR_ALT ${CURRENT_SEARCH_DIR}/wolfmqtt-${THIS_USER})
            message(STATUS "Looking in ${CURRENT_SEARCH_DIR}")

            #if(EXISTS ${CURRENT_SEARCH_DIR_ALT} AND IS_DIRECTORY ${CURRENT_SEARCH_DIR_ALT} AND EXISTS "${CURRENT_SEARCH_DIR_ALT}/wolfcrypt/src")
            IS_WOLFMQTT_SOURCE("${CURRENT_SEARCH_DIR_ALT}" FOUND_WOLFMQTT )
            if ( FOUND_WOLFMQTT )
               message(STATUS "Found wolfmqtt in user-suffix CURRENT_SEARCH_DIR_ALT = ${CURRENT_SEARCH_DIR_ALT}")
                set(${OUTPUT_FOUND_WOLFMQTT_DIRECTORY} ${CURRENT_SEARCH_DIR_ALT} PARENT_SCOPE)
                return()
            endif()
        endif()

        # Next check for no user suffix "wolfmqtt" subdirectory as we recurse up the directory tree
        set(CURRENT_SEARCH_DIR_ALT ${CURRENT_SEARCH_DIR}/wolfmqtt)
        # if(EXISTS ${CURRENT_SEARCH_DIR} AND IS_DIRECTORY ${CURRENT_SEARCH_DIR} AND EXISTS "${CURRENT_SEARCH_DIR}/wolfcrypt/src")
        IS_WOLFMQTT_SOURCE("${CURRENT_SEARCH_DIR_ALT}" FOUND_WOLFMQTT )
        if ( FOUND_WOLFMQTT )
            message(STATUS "Found wolfmqtt in CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
            set(${OUTPUT_FOUND_WOLFMQTT_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
            return()
        endif()

        # Move up one directory level
        set(PRIOR_SEARCH_DIR "${CURRENT_SEARCH_DIR}")
        get_filename_component(CURRENT_SEARCH_DIR "${CURRENT_SEARCH_DIR}" DIRECTORY)
        message(STATUS "Next CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
        if( "${PRIOR_SEARCH_DIR}" STREQUAL "${CURRENT_SEARCH_DIR}" )
            # when the search directory is empty, we'll give up
            set(CURRENT_SEARCH_DIR "")
        endif()
    endwhile()

    # If not found, set the output variable to empty before exiting
    set(${OUTPUT_FOUND_WOLFMQTT_DIRECTORY} "" PARENT_SCOPE)
endfunction()

# These flags apply only to compiling this component independently.
# be sure to include this like in the root CMakeFiles.txt
# for proper application-wide use of WOLFSSL_USER_SETTINGS:
#
#   add_compile_definitions("WOLFSSL_USER_SETTINGS")
#   add_compile_definitions("WOLFMQTT_USER_SETTINGS")
#
# if using ESP-IDF prior to 4.4, see:
# https://github.com/wolfSSL/wolfssl/issues/5727
if (CONFIG_DEBUG_WOLFMQTT)
    message(STATUS "Config DEBUG_WOLFMQTT is enabled for components/wolfmqtt")
endif()

if (WOLFSSL_USER_SETTINGS)
    message(STATUS "Component wolfmqtt: Found predefined WOLFSSL_USER_SETTINGS")
else()
    # wolfSSL settings should have occurred in project makefiles
    #message(WARNING "Component wolfmqtt: Setting WOLFSSL_USER_SETTINGS \
                     #(should have been a project-wide setting)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWOLFSSL_USER_SETTINGS")
endif()

if (WOLFMQTT_USER_SETTINGS)
    message(STATUS "Component wolfmqtt: Found predefined WOLFMQTT_USER_SETTINGS")
else()
    # wolfSSL settings should have occurred in project makefiles. See
    message(WARNING "Component wolfmqtt: Setting WOLFMQTT_USER_SETTINGS
                     (should have been a project-wide setting)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFMQTT_USER_SETTINGS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWOLFMQTT_USER_SETTINGS")
endif()

# Pick up the KConfig value and assign to cmake variable as appropriate
if(CONFIG_USE_WOLFMQTT_TLS)
    if (CONFIG_DEBUG_WOLFMQTT)
        message(STATUS "Config USE_WOLFMQTT_TLS is enabled for components/wolfmqtt")
    endif()
    set(MQTT_TLS_DEFINE "ENABLE_MQTT_TLS")
    add_compile_definitions("${MQTT_TLS_DEFINE}")
else()
    if (CONFIG_DEBUG_WOLFMQTT)
        message(STATUS "Config USE_WOLFMQTT_TLS is NOT enabled for components/wolfmqtt")
    endif()
    set(MQTT_TLS_DEFINE "")
endif()

message(STATUS "wolfmqtt CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")

set(CMAKE_CURRENT_SOURCE_DIR ".")
set(WOLFMQTT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(INCLUDE_PATH ${WOLFMQTT_ROOT})



set(COMPONENT_REQUIRES lwip ${WOLFSSL_COMPONENT_NAME})


# list(REMOVE_ITEM ASM_FILES  ".*\\.(asm|S)")

message(STATUS "WOLFSSL_ROOT = ${WOLFSSL_ROOT}")
message(STATUS "WOLFMQTT_ROOT = ${WOLFMQTT_ROOT}")
message(STATUS "ASM_FILES = ${ASM_FILES}")


if(CMAKE_BUILD_EARLY_EXPANSION)
    message(STATUS "wolfmqtt component CMAKE_BUILD_EARLY_EXPANSION:")
    idf_component_register(
                            REQUIRES "wolfssl" # "${COMPONENT_REQUIRES}"
                           )
else()
    FIND_WOLFMQTT_DIRECTORY(WOLFMQTT_ROOT)

    set(WOLFMQTT_ROOT "${WOLFMQTT_ROOT}" CACHE STRING "WOLFMQTT_ROOT")
    if(WOLFMQTT_ROOT)
        message(STATUS "Found wolfmqtt directory at: ${WOLFMQTT_ROOT}")
    else()
        message(STATUS "wolfmqtt directory not found.")
        # Abort. We need wolfmqtt _somewhere_.
        message(FATAL_ERROR "Could not find wolfmqtt in ${WOLFMQTT_ROOT}.\n"
                            "Try setting WOLFMQTT_ROOT environment variable or git clone.")
    endif()

    # Do not include example directories here.
    # CMake will otherwise not see the example code at all, or see it as a duplicate.
    set(COMPONENT_SRCDIRS "${WOLFMQTT_ROOT}/src"
    #                     "${WOLFMQTT_ROOT}/examples"
    #                     "${WOLFMQTT_ROOT}/examples/aws"
       )


    if(EXISTS "${WOLFMQTT_ROOT}")
        message(STATUS "Confirmed exists: WOLFMQTT_ROOT = ${WOLFMQTT_ROOT}")
    else()
        message(STATUS "ERROR: Result WOLFMQTT_ROOT does not exist: ${WOLFMQTT_ROOT}")
    endif()

    if(EXISTS "${WOLFMQTT_ROOT}/src")
        message(STATUS "Confirmed exists: WOLFMQTT_ROOT/src = ${WOLFMQTT_ROOT}/src")
    else()
        message(STATUS "ERROR: Result WOLFMQTT_ROOT does not exist: ${WOLFMQTT_ROOT}/src")
    endif()

    if(EXISTS "${COMPONENT_SRCDIRS}")
        message(STATUS "Confirmed exists: COMPONENT_SRCDIRS = ${COMPONENT_SRCDIRS}")
    else()
        message(STATUS "ERROR: Result COMPONENT_SRCDIRS does not exist: ${COMPONENT_SRCDIRS}")
    endif()

    message(STATUS "WOLFMQTT_ROOT = ${WOLFMQTT_ROOT}")
    set(COMPONENT_ADD_INCLUDEDIRS
        "."
        "./include"
        "${WOLFMQTT_ROOT}"
        "${WOLFMQTT_ROOT}/examples"
        "${WOLFMQTT_ROOT}/wolfmqtt"
        "${WOLFMQTT_ROOT}/examples/aws"
        )
    # list(REMOVE_ITEM ASM_FILES  ".*\\.(asm|S)")

    message(STATUS "WOLFSSL_ROOT = ${WOLFSSL_ROOT}")
    message(STATUS "ASM_FILES = ${ASM_FILES}")
    set(EXTRA_COMPONENT_DIRS "${COMPONENT_SRCDIRS}")
    set(COMPONENT_REQUIRES lwip ${WOLFSSL_COMPONENT_NAME})
    idf_component_register(
                            SRC_DIRS     "${COMPONENT_SRCDIRS}"
                            INCLUDE_DIRS "${COMPONENT_ADD_INCLUDEDIRS}"
                            REQUIRES     "${COMPONENT_REQUIRES}"
                            EXCLUDE_SRCS "${COMPONENT_SRCEXCLUDE}"
                            PRIV_REQUIRES "${WOLFSSL_COMPONENT_NAME}" # this will typically only be needed for wolfSSL benchmark
                           )
endif()

# check to see if there's both a local copy and EDP-IDF copy of the wolfmqtt components
if( EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfmqtt/" AND EXISTS "$ENV{IDF_PATH}/components/wolfmqtt/" )
    message(STATUS  "")
    message(WARNING "WARNING: Found components/wolfmqtt in both local project and IDF_PATH")
    message(STATUS  "")
endif()
# end multiple component check

