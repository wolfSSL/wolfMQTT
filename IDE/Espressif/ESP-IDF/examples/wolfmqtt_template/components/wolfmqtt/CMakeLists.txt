# [template]/components/wolfmqtt/CMakeLists.txt for Espressif targets
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfMQTT.
#
# wolfMQTT is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfMQTT is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#

#
# This is the CMakeLists.txt for the Espressif ESP-IDF wolfMQTT component
#

cmake_minimum_required(VERSION 3.16)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFMQTT_USER_SETTINGS")

set(VERBOSE_COMPONENT_MESSAGES 1)

# The scope of this CMAKE_C_FLAGS is just this component:
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

set(CMAKE_CURRENT_SOURCE_DIR ".")

message(STATUS "CMAKE_CURRENT_LIST_DIR = ${CMAKE_CURRENT_LIST_DIR}")

get_filename_component(THIS_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
message(STATUS "THIS_DIR = ${THIS_DIR}")

# The root of the project is two directories up from here. (we are typically in [project name]components/mywolfmqtt)
get_filename_component(PROJECT_ROOT "${THIS_DIR}" DIRECTORY)      # Up one directory from here is "components"
get_filename_component(PROJECT_ROOT "${PROJECT_ROOT}" DIRECTORY)  # up one more directory should be the root of our project
message(STATUS "PROJECT_ROOT = ${PROJECT_ROOT}")

# in case wolfssl user_settings.h is missing, we'll look for one in the ESP32/lib directory:
get_filename_component(LIB_USER_SETTINGS "${PROJECT_ROOT}/../lib/user_settings.h" ABSOLUTE)
message(STATUS "wolfssl user_settings.h lib  = ${LIB_USER_SETTINGS}")

get_filename_component(THIS_PROJECT_WOLFMQTT_USER_SETTINGS_PATH "${PROJECT_ROOT}/components/wolfssl/include" ABSOLUTE)
message(STATUS "wolfssl user_settings.h path = ${THIS_PROJECT_WOLFMQTT_USER_SETTINGS_PATH}")

# Optionally set your source to wolfSSL in your project CMakeLists.txt like this:
# set(WOLFMQTT_ROOT "c:/some/workspace/wolfmqtt" )

if ( "${WOLFMQTT_ROOT}" STREQUAL "")
    set(WOLFMQTT_ROOT "$ENV{WOLFMQTT_ROOT}" )
endif()

# Optional compiler definitions to help with system name detection (typically printed by app diagnostics)
if( VERBOSE_COMPONENT_MESSAGES )
    if(WIN32)
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS")
        message(STATUS "Detected Windows")
    endif()
    if(CMAKE_HOST_UNIX)
        message(STATUS "Detected UNIX")
    endif()
    if(APPLE)
        message(STATUS "Detected APPLE")
    endif()
    if(CMAKE_HOST_UNIX AND (NOT APPLE) AND EXISTS "/proc/sys/fs/binfmt_misc/WSLInterop")
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WSL")
        message(STATUS "Detected WSL")
    endif()
    if(CMAKE_HOST_UNIX AND (NOT APPLE) AND (NOT WIN32))
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_LINUX")
        message(STATUS "Detected Linux")
    endif()
    if(APPLE)
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_APPLE")
        message(STATUS "Detected Apple")
    endif()
endif() # End optional WOLFSSL_CMAKE_SYSTEM_NAME

message(STATUS "CONFIG_TARGET_PLATFORM = ${CONFIG_TARGET_PLATFORM}")

# find the user name to search for possible "wolfmqtt-username"
# Reminder that GitHub workflow actions will typically NOT have a user name available.
message(STATUS "USERNAME = $ENV{USERNAME}")
if(  "$ENV{USER}" STREQUAL "" ) # the bash user
    if(  "$ENV{USERNAME}" STREQUAL "" ) # the Windows user
        message(STATUS "could not find USER or USERNAME")
    else()
        # the Windows user is not blank, so we'll use it.
        set(THIS_USER "$ENV{USERNAME}")
    endif()
else()
    # the bash user is not blank, so we'll use it.
    set(THIS_USER "$ENV{USER}")
endif()
message(STATUS "THIS_USER = ${THIS_USER}")

# Attention!
#
# When editing component CMake files, consider the following :
#
# NO Managed Components: Normal stand-alone app, "as cloned" from github.
#   There's no notion of staging names (e.g. mywolfmqtt) regardless of environment settings.
#   All of the component source is local. See settings such s WOLFSSL_ROOT=[your path]
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
#       idf.py add-dependency "wolfssl/wolfmqtt^1.18.0"
#
# Fully Managed Components. This is the typical example as created from the Component Registry:
#    For example:
#
#       idf.py create-project-from-example "wolfssl/wolfmqtt=1.18.0:AWS_IoT_MQTT"
#
# In all cases, keep in mind that components other than wolfssl will depend on the wolfssl component.
#
message(STATUS "CMAKE_CURRENT_LIST_DIR = ${CMAKE_CURRENT_LIST_DIR}")

get_filename_component(THIS_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
message(STATUS "THIS_DIR = ${THIS_DIR}")

# The root of the project is two directories up from here. (we are typically in [project name]components/mywolfmqtt)
get_filename_component(PROJECT_ROOT "${THIS_DIR}" DIRECTORY)      # Up one directory from here is "components"
get_filename_component(PROJECT_ROOT "${PROJECT_ROOT}" DIRECTORY)  # up one more directory should be the root of our project
message(STATUS "PROJECT_ROOT = ${PROJECT_ROOT}")


# Component naming is only adjusted when using Managed Components, and only when using staging site.
if( "$ENV{IDF_COMPONENT_REGISTRY_URL}" STREQUAL "https://components-staging.espressif.com" )
    # TODO: Is checking these two variables really the best way to detect an active Component Manager?
    message(STATUS "component_manager_interface_version = ${component_manager_interface_version}")
    message(STATUS "managed_components = ${managed_components}")
    message(STATUS "Checking if wolfssl is in ${PROJECT_ROOT}/managed_components/${THIS_USER}__mywolfssl")

    if(EXISTS "${PROJECT_ROOT}/managed_components/${THIS_USER}__mywolfssl/CMakeLists.txt")
        message(STATUS "Found user-specific, managed, staging component. The wolfssl component will be named mywolfssl.")
        set(WOLFSSL_COMPONENT_NAME "mywolfssl")
    elseif( ("${managed_components}" STREQUAL "") AND ("${component_manager_interface_version}" STREQUAL "") )
        # We've found a staging component, but did not detect the component manager
        message(STATUS "No component manager interface component wolfssl ${CMAKE_HOME_DIRECTORY}")
        set(WOLFSSL_COMPONENT_NAME "wolfssl")
    else()
        message(STATUS "else mywolfssl")
        set(WOLFSSL_COMPONENT_NAME "mywolfssl")
    endif()
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/${THIS_USER}__mywolfssl/CMakeLists.txt")
    message(STATUS "Found managed_components mywolfssl")
    set(WOLFSSL_COMPONENT_NAME "mywolfssl")
else()
    message(STATUS "Not staging environment, no managed_components wolfssl")
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
    message(STATUS "IS_WOLFMQTT_SOURCE DIRECTORY_PARAMETER='${DIRECTORY_PARAMETER}'")
    if (EXISTS "${DIRECTORY_PARAMETER}/wolfmqtt/mqtt_client.h")
        if (EXISTS "${DIRECTORY_PARAMETER}/wolfmqtt")
            message(STATUS "Found ${DIRECTORY_PARAMETER}/wolfmqtt")
        endif()
        if (EXISTS "${DIRECTORY_PARAMETER}/src")
            message(STATUS "Found ${DIRECTORY_PARAMETER}/src")
        endif()
        message(STATUS "Found wolfmqtt!")
        set(${RESULT} "${DIRECTORY_PARAMETER}" PARENT_SCOPE)
    else()
        message(STATUS "NOT Found!")
        set(${RESULT} "" PARENT_SCOPE)
    endif()
endfunction()

# function: FIND_WOLFMQTT_DIRECTORY
#  parameter: OUTPUT_FOUND_WOLFMQTT_DIRECTORY contains root of source code, otherwise blank
#
function(FIND_WOLFMQTT_DIRECTORY OUTPUT_FOUND_WOLFMQTT_DIRECTORY)
    message(STATUS "Starting FIND_WOLFMQTT_DIRECTORY")

    message(STATUS "OUTPUT_FOUND_WOLFMQTT_DIRECTORY = ${${OUTPUT_FOUND_WOLFMQTT_DIRECTORY}}")
    IS_WOLFMQTT_SOURCE("${${OUTPUT_FOUND_WOLFMQTT_DIRECTORY}}" FOUND_WOLFMQTT)
    if( FOUND_WOLFMQTT )
        set(${OUTPUT_FOUND_WOLFMQTT_DIRECTORY} ${${OUTPUT_FOUND_WOLFMQTT_DIRECTORY}} PARENT_SCOPE)
        return()
    endif()
    message(STATUS "")

    if ( "${${OUTPUT_FOUND_WOLFMQTT_DIRECTORY}}" STREQUAL "" )
        set(CURRENT_SEARCH_DIR "$ENV{WOLFMQTT_ROOT}")
        if( "${CURRENT_SEARCH_DIR}" STREQUAL "" )
            message(STATUS "The WOLFMQTT_ROOT environment variable is not set. Searching...")
        else()
            get_filename_component(CURRENT_SEARCH_DIR "$ENV{WOLFMQTT_ROOT}" ABSOLUTE)
            IS_WOLFMQTT_SOURCE("${CURRENT_SEARCH_DIR}" FOUND_WOLFMQTT)
            if( FOUND_WOLFMQTT )
                message(STATUS "Found WOLFMQTT_ROOT via Environment Variable:")
            else()
                message(FATAL_ERROR "WOLFMQTT_ROOT Environment Variable defined, but path not found:")
                message(STATUS "$ENV{WOLFMQTT_ROOT}")
            endif()
        endif()
    else()
        # There's a non-blank OUTPUT_FOUND_WOLFMQTT_DIRECTORY. Is it a valid wolfmqtt directory?
        get_filename_component(CURRENT_SEARCH_DIR "{OUTPUT_FOUND_WOLFMQTT_DIRECTORY}" ABSOLUTE)
        IS_WOLFMQTT_SOURCE("${CURRENT_SEARCH_DIR}" FOUND_WOLFMQTT)
        if("${FOUND_WOLFMQTT}")
            message(STATUS "Found WOLFMQTT_ROOT: ${OUTPUT_FOUND_WOLFMQTT_DIRECTORY}")
        else()
            message(STATUS "OUTPUT_FOUND_WOLFMQTT_DIRECTORY does not appear to contain wolfMQTT source code:")
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
                            REQUIRES "${COMPONENT_REQUIRES}"
                            PRIV_REQUIRES
                                esp_timer
                                driver
                                "${WOLFSSL_COMPONENT_NAME}" # either wolfssl or mywolfssl as a staging component
                           )
else()
    # not CMAKE_BUILD_EARLY_EXPANSION
    message(STATUS "************************************************************************************************")
    message(STATUS "wolfmqtt component config:")
    message(STATUS "************************************************************************************************")
    FIND_WOLFMQTT_DIRECTORY(WOLFMQTT_ROOT)
    message(STATUS "Post find = ${WOLFMQTT_ROOT}")
    # Check to see if we're already in wolfmqtt, and only if WOLFMQTT_ROOT not specified
    if ("${WOLFMQTT_ROOT}" STREQUAL "")
        # wolfmqtt examples are 7 directories deep from wolfmqtt repo root
        #                        1  2  3  4  5  6  7
        set(THIS_RELATIVE_PATH "../../../../../../..")
        get_filename_component(THIS_SEARCH_PATH  "${THIS_RELATIVE_PATH}" ABSOLUTE)
        message(STATUS "Searching in path = ${THIS_SEARCH_PATH}")

        if (EXISTS "${THIS_SEARCH_PATH}/wolfmqtt/mqtt_client.h")
            # we're already in wolfmqtt examples!
            get_filename_component(WOLFMQTT_ROOT  "${THIS_SEARCH_PATH}" ABSOLUTE)
            message(STATUS "Using wolfmqtt example with root ${WOLFMQTT_ROOT}")
        else()
            # We're in some other repo such as wolfmqtt, so we'll search for an
            # adjacent-level directory for wolfmqtt. (8 directories up, then down one)
            #
            # For example wolfmqtt examples:
            #   C:\workspace\wolfmqtt-gojimmypi\IDE\Espressif\ESP-IDF\examples\wolfmqtt_template\components\wolfmqtt
            #
            # For example wolfMQTT examples:
            #   C:\workspace\wolfmqtt-gojimmypi\ide\Espressif\ESP-IDF\examples\wolfmqtt_template\components\wolfmqtt
            #
            #                        1  2  3  4  5  6  7  8
            set(THIS_RELATIVE_PATH "../../../../../../../..")
            get_filename_component(THIS_SEARCH_PATH  "${THIS_RELATIVE_PATH}" ABSOLUTE)
            message(STATUS "Searching next in path = ${THIS_SEARCH_PATH}")
        endif()
    endif()

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

    if(IS_DIRECTORY "${RTOS_IDF_PATH}")
        message(STATUS "Found current RTOS path: ${RTOS_IDF_PATH}")
    else()
        # ESP-IDF prior version 4.4x has a different RTOS directory structure
        string(REPLACE "\\" "/" RTOS_IDF_PATH "$ENV{IDF_PATH}/components/freertos/include/freertos")
        if(IS_DIRECTORY "${RTOS_IDF_PATH}")
            message(STATUS "Found legacy RTOS path: ${RTOS_IDF_PATH}")
        else()
            message(STATUS "Could not find RTOS path")
        endif()
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
        "${WOLFMQTT_ROOT}/wolfmqtt"
        )
    # list(REMOVE_ITEM ASM_FILES  ".*\\.(asm|S)")

    message(STATUS "WOLFSSL_ROOT = ${WOLFSSL_ROOT}")
    message(STATUS "ASM_FILES = ${ASM_FILES}")
    set(EXTRA_COMPONENT_DIRS "${COMPONENT_SRCDIRS}")
    set(COMPONENT_REQUIRES lwip ${WOLFSSL_COMPONENT_NAME})
    message(STATUS "idf_component_register PRIV_REQUIRES ${WOLFSSL_COMPONENT_NAME}")
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
    message(STATUS "")
    message(STATUS "")
    message(STATUS "**********************************************************************")
    message(STATUS "WARNING: Found components/wolfmqtt in both local project and IDF_PATH")
    message(STATUS "**********************************************************************")
    message(STATUS "")
endif()
# end multiple component check


#
# LIBWOLFMQTT_SAVE_INFO(VAR_OUPUT THIS_VAR VAR_RESULT)
#
# Save the THIS_VAR as a string in a macro called VAR_OUPUT
#
# VAR_OUPUT:  the name of the macro to define
# THIS_VAR:   the OUTPUT_VARIABLE result from a execute_process()
# VAR_RESULT: the RESULT_VARIABLE from a execute_process(); "0" if successful.
#
function ( LIBWOLFMQTT_SAVE_INFO VAR_OUPUT THIS_VAR VAR_RESULT )
    # is the RESULT_VARIABLE output value 0? If so, IS_VALID_VALUE is true.
    string(COMPARE EQUAL "${VAR_RESULT}" "0" IS_VALID_VALUE)

    # if we had a successful operation, save the THIS_VAR in VAR_OUPUT
    if(${IS_VALID_VALUE})
        # strip newline chars in THIS_VAR parameter and save in VAR_VALUE
        string(REPLACE "\n" ""  VAR_VALUE  ${THIS_VAR})

        # we'll could percolate the value to the parent for possible later use
        # set(${VAR_OUPUT} ${VAR_VALUE} PARENT_SCOPE)

        # but we're only using it here in this function
        set(${VAR_OUPUT} ${VAR_VALUE})

        # we'll print what we found to the console
        message(STATUS "Found ${VAR_OUPUT}=${VAR_VALUE}")

        # the interesting part is defining the VAR_OUPUT name a value to use in the app
        add_definitions(-D${VAR_OUPUT}=\"${VAR_VALUE}\")
    else()
        # if we get here, check the execute_process command and parameters.
        message(STATUS "LIBWOLFMQTT_SAVE_INFO encountered a non-zero VAR_RESULT")
        set(${VAR_OUPUT} "Unknown")
    endif()
endfunction() # LIBWOLFMQTT_SAVE_INFO

# create some programmatic #define values that will be used by ShowExtendedSystemInfo().
# see wolfcrypt\src\port\Espressif\esp32_utl.c
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    set (git_cmd "git")
    message(STATUS "Adding macro definitions:")

    # LIBWOLFMQTT_VERSION_GIT_ORIGIN: git config --get remote.origin.url
    execute_process(WORKING_DIRECTORY ${WOLFMQTT_ROOT} COMMAND ${git_cmd} "config" "--get" "remote.origin.url" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET  )
    LIBWOLFMQTT_SAVE_INFO(LIBWOLFMQTT_VERSION_GIT_ORIGIN "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFMQTT_VERSION_GIT_BRANCH: git rev-parse --abbrev-ref HEAD
    execute_process(WORKING_DIRECTORY ${WOLFMQTT_ROOT} COMMAND ${git_cmd} "rev-parse" "--abbrev-ref" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET  )
    LIBWOLFMQTT_SAVE_INFO(LIBWOLFMQTT_VERSION_GIT_BRANCH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFMQTT_VERSION_GIT_HASH: git rev-parse HEAD
    execute_process(WORKING_DIRECTORY ${WOLFMQTT_ROOT} COMMAND ${git_cmd} "rev-parse" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET  )
    LIBWOLFMQTT_SAVE_INFO(LIBWOLFMQTT_VERSION_GIT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFMQTT_VERSION_GIT_SHORT_HASH: git rev-parse --short HEAD
    execute_process(WORKING_DIRECTORY ${WOLFMQTT_ROOT} COMMAND ${git_cmd} "rev-parse" "--short" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFMQTT_SAVE_INFO(LIBWOLFMQTT_VERSION_GIT_SHORT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFMQTT_VERSION_GIT_HASH_DATE git show --no-patch --no-notes --pretty=\'\%cd\'
    execute_process(WORKING_DIRECTORY ${WOLFMQTT_ROOT} COMMAND ${git_cmd} "show" "--no-patch" "--no-notes" "--pretty=\'\%cd\'" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES  )
    LIBWOLFMQTT_SAVE_INFO(LIBWOLFMQTT_VERSION_GIT_HASH_DATE "${TMP_OUT}" "${TMP_RES}")

    message(STATUS "************************************************************************************************")
    message(STATUS "wolfmqtt component config complete!")
    message(STATUS "************************************************************************************************")
endif()
