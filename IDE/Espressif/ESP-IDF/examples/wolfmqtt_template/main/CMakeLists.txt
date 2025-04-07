# [example]/main/CMakeLists.txt for Espressif targets
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

#   v1.1
#
cmake_minimum_required(VERSION 3.16)

message(STATUS "main cmake found WOLFSSL_COMPONENT_NAME=${WOLFSSL_COMPONENT_NAME}")

# Check for the special case of ESP8266 SDK
if (idf_target STREQUAL "esp8266" OR IDF_TARGET STREQUAL "esp8266" OR IDF_VERSION_MAJOR VERSION_LESS "5.0")
    # `driver` component not available for ESP8266
    SET(THIS_PRIV_REQUIRES_DRIVER "")
else()
    SET(THIS_PRIV_REQUIRES_DRIVER "driver")
endif()

# find the user name to search for possible "wolfssl-username"
message(STATUS "USERNAME = $ENV{USERNAME}")
if(  "$ENV{USER}" STREQUAL "" ) # the bash user
    if(  "$ENV{USERNAME}" STREQUAL "" ) # the Windows user
        message(STATUS "could not find USER or USERNAME")
    else()
        # the bash user is not blank, so we'll use it.
        set(THIS_USER "$ENV{USERNAME}")
    endif()
else()
    # the bash user is not blank, so we'll use it.
    set(THIS_USER "$ENV{USER}")
endif()
message(STATUS "THIS_USER (main) = ${THIS_USER}")


# CHECK_DUPLICATE_LIBRARIES function
#   Parameters:
#      RESULT_VAR (output variable)
#      KEYWORD (e.g. "wolfssl", "wolfmqtt", etc).
#
# Constructs a list of possible directories based on the keyword.
# Counts the number of existing directories.
# If at least two directories exist, sets RESULT_VAR to TRUE, otherwise FALSE.
# Uses PARENT_SCOPE to return the result to the calling context.
function(CHECK_DUPLICATE_LIBRARIES RESULT_VAR KEYWORD)
    set(DIR_LIST
        "${CMAKE_HOME_DIRECTORY}/components/${KEYWORD}"
        "${CMAKE_HOME_DIRECTORY}/components/my${KEYWORD}"
        "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__${KEYWORD}"
        "${CMAKE_HOME_DIRECTORY}/managed_components/gojimmypi__my${KEYWORD}"
        "${CMAKE_HOME_DIRECTORY}/managed_components/${THIS_USER}__my${KEYWORD}"
        "$ENV{IDF_PATH}/components/${KEYWORD}/"
        "$ENV{IDF_PATH}/components/esp-${KEYWORD}/"
    )

    set(EXISTING_COUNT 0)

    foreach(DIR ${DIR_LIST})
        message(STATUS "Checking ${DIR}")
        file(TO_CMAKE_PATH "${DIR}" DIR)  # Normalize paths
        message(STATUS "Checking ${DIR}")
        if(EXISTS "${DIR}")
            math(EXPR EXISTING_COUNT "${EXISTING_COUNT} + 1")
            message(STATUS "Found: ${DIR}")
        endif()
    endforeach()

    if(EXISTING_COUNT GREATER_EQUAL 2)
        set(${RESULT_VAR} TRUE PARENT_SCOPE)
        message(STATUS "WARNING: At least two '${KEYWORD}' component directories exist.")

        # Append the warning flag to CMAKE_C_FLAGS and propagate it to the parent scope
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${KEYWORD}_MULTI_INSTALL_WARNING")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}" PARENT_SCOPE)
    else()
        set(${RESULT_VAR} FALSE PARENT_SCOPE)

        message(STATUS "Confirmed less than two '${KEYWORD}' component directories exist.")
    endif()
endfunction()


if(WIN32)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS")
    message(STATUS "Detected Windows")
endif()
if(CMAKE_HOST_UNIX)
    message(STATUS "Detected UNIX")
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
    # Apple-specific configuration here
    message(STATUS "Detected APPLE")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_APPLE")
    message(STATUS "Detected Apple")
endif()
set (git_cmd "git")

message(STATUS "Checking for duplicate components. CMAKE_HOME_DIRECTORY='${CMAKE_HOME_DIRECTORY}'")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolfssl")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolfmqtt")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolfssh")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolftpm")

if( EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl/" AND EXISTS "$ENV{IDF_PATH}/components/wolfssl/" )
    #
    # wolfSSL found in both ESP-IDF and local project - needs to be resolved by user
    #
    message(STATUS "")
    message(STATUS "WARNING: Found components/wolfssl in both local project and IDF_PATH")
    message(STATUS "")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_MULTI_INSTALL_WARNING")
endif()

if( "$ENV{IDF_COMPONENT_REGISTRY_URL}" STREQUAL "https://components-staging.espressif.com" )
    # Currently the only staging namespace is the gojimmypi developer, but allow for override.
    # See https://components-staging.espressif.com/components?q=namespace:gojimmypi
    #
    if(  "$ENV{WOLFSSL_STAGING_NAMESPACE}" STREQUAL "" )
        set(WOLFSSL_STAGING_NAMESPACE "gojimmypi")
    else()
        set(WOLFSSL_STAGING_NAMESPACE "$ENV{WOLFSSL_STAGING_NAMESPACE}")
    endif()
    message(STATUS "Using namespace: ${WOLFSSL_STAGING_NAMESPACE}")

    if( ("${managed_components}" STREQUAL "") AND ("${component_manager_interface_version}" STREQUAL "") )
        # We've found a staging component, but did not detect the component manager
        if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../components/mywolfmqtt/CMakeLists.txt)
            # This is typically during publish-time build test
            message(STATUS "Set name mywolfmqtt (1)")
            set(WOLFSSL_COMPONENT_NAME "mywolfssl")
            set(WOLFMQTT_COMPONENT_NAME "mywolfmqtt")
        else()
            if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../managed_components/${WOLFSSL_STAGING_NAMESPACE}__mywolfmqtt/CMakeLists.txt")
                # This is typically upon creating a project from managed component examples
                message(STATUS "Set name mywolfmqtt (2)")
                set(WOLFSSL_COMPONENT_NAME "mywolfssl")
                set(WOLFMQTT_COMPONENT_NAME "mywolfmqtt")
            else()
                message(STATUS "Set name wolfmqtt (1) CMAKE_CURRENT_LIST_DIR = ${CMAKE_CURRENT_LIST_DIR}")
                set(WOLFSSL_COMPONENT_NAME "wolfssl")
                set(WOLFMQTT_COMPONENT_NAME "wolfmqtt")
            endif()
        endif()
    else()
        message(STATUS "Set name mywolfmqtt (3)")
        set(WOLFSSL_COMPONENT_NAME "mywolfssl")
        set(WOLFMQTT_COMPONENT_NAME "mywolfmqtt")
    endif()
else()
    message(STATUS "Set name wolfmqtt (2)")
    set(WOLFSSL_COMPONENT_NAME "wolfssl")
    set(WOLFMQTT_COMPONENT_NAME "wolfmqtt")
endif()

# Example source code is not part of a published Managed Component library.
# Instead, it is copied to the specific example. This is important since the
# Managed Component source cannot be edited, as least not without converting
# to a regular local component, which defeats the value of a Managed Component.
#
# Is this CMakeLists in a GitHub Repo with supplementary example files in parent directory?
# [WOLFMQTT_ROOT]/examples/aws
#
# This CMakeLists file, when on GitHub, is in:
# [WOLFMQTT_ROOT]/IDE/Espressif/ESP-IDF/examples/AWS_IoT_MQTT/main
#
# Otherwise, when part of a published Managed Component or other stand-alone example,
# this CMakeLists file is in:
# [AWS_IoT_MQTT]/main
#
# Managed Components instead have the respective [examples] source copied here at publish time:
# [AWS_IoT_MQTT]/main/examples
#
# The respective specific example headers are copied here at publish time, in this case aws:
# [AWS_IoT_MQTT]/main/examples/aws
#
message(STATUS "__PROJECT_NAME=${__PROJECT_NAME}")
message(STATUS "CMAKE_PROJECT_NAME=${CMAKE_PROJECT_NAME}")

# __PROJECT_NAME and CMAKE_PROJECT_NAME not yet available, so we'll check if this is the template project
get_filename_component(THIS_PROJECT_DIR ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)
get_filename_component(THIS_PROJECT_PARENT_DIR ${THIS_PROJECT_DIR} NAME)
if("${THIS_PROJECT_PARENT_DIR}" STREQUAL "wolfmqtt_template")
    message(STATUS "For reference only in wolfmqtt_template project, no additional example code is added")
else()
    # All other examples are expected to have some example code available.

    # Set the specific example to look for in core examples:
    set(EXAMPLE_HEADER_FILE "mqttexample.h")

    # We'll first check if we are in the GitHub repo directory structure:
    set(PATH_TO_GITHUB_EXAMPLES "../../../../../../examples/")
    get_filename_component(PATH_TO_GITHUB_EXAMPLES "${PATH_TO_GITHUB_EXAMPLES}" ABSOLUTE)
    message(STATUS "Looking in PATH_TO_GITHUB_EXAMPLES: '${PATH_TO_GITHUB_EXAMPLES}'")

    # Otherwise we'll assume a stand-alone example, such as that from a Managed Component
    # Example: idf.py create-project-from-example "gojimmypi/mywolfmqtt=1.18.0-preview7:AWS_IoT_MQTT"
    get_filename_component(THIS_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
    message(STATUS "This CMakeLists.txt is located in: '${THIS_DIR}'")

    # Set a path to the example code.
    # Note that PATH_TO_EXAMPLES may be will be set to PATH_TO_GITHUB_EXAMPLES as appropriate.
    set(PATH_TO_EXAMPLES "${THIS_DIR}/examples")
    get_filename_component(PATH_TO_EXAMPLES "${PATH_TO_EXAMPLES}" ABSOLUTE)
    message(STATUS "Looking in PATH_TO_EXAMPLES: '${PATH_TO_EXAMPLES}'")

    # We cannot have source in both, so check that first:
    if (EXISTS "${PATH_TO_GITHUB_EXAMPLES}/${EXAMPLE_HEADER_FILE}" AND EXISTS "${PATH_TO_EXAMPLES}/${EXAMPLE_HEADER_FILE}")
        message(STATUS "ERROR: Found example source in multiple directories:")
        message(STATUS "Directory 1: '${THIS_DIR}'")
        get_filename_component(THIS_DIR "${PATH_TO_EXAMPLES}" ABSOLUTE)
        message(STATUS "Directory 1: '${THIS_DIR}'")
        message(FATAL_ERROR "Unable to resolve source. Please pick one.")
    elseif (EXISTS "${PATH_TO_GITHUB_EXAMPLES}/${EXAMPLE_HEADER_FILE}")
        # GitHub repository structure
        set(PATH_TO_EXAMPLES "${PATH_TO_GITHUB_EXAMPLES}" )
        message(STATUS "Using source from repository path: '${PATH_TO_EXAMPLES}'")
    elseif (EXISTS "${PATH_TO_EXAMPLES}/${EXAMPLE_HEADER_FILE}")
        # Standalone example
        message(STATUS "Using example source in '${PATH_TO_EXAMPLES}'")
    else()
        # Source not found
        set(PATH_TO_EXAMPLES "")
        message(STATUS "ERROR: Could not find example source code.")
    endif()
endif() # Example code check

message(STATUS "WOLFMQTT_ROOT for examples = ${WOLFMQTT_ROOT}")

idf_component_register(
    SRCS
        main.c
    INCLUDE_DIRS
        "."
        "include"
) # idf_component_register


#
# LIBWOLFSSL_SAVE_INFO(VAR_OUPUT THIS_VAR VAR_RESULT)
#
# Save the THIS_VAR as a string in a macro called VAR_OUPUT
#
# VAR_OUPUT:  the name of the macro to define
# THIS_VAR:   the OUTPUT_VARIABLE result from a execute_process()
# VAR_RESULT: the RESULT_VARIABLE from a execute_process(); "0" if successful.
#
function ( LIBWOLFSSL_SAVE_INFO VAR_OUPUT THIS_VAR VAR_RESULT )
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
        message(STATUS "LIBWOLFSSL_SAVE_INFO encountered a non-zero VAR_RESULT")
        set(${VAR_OUPUT} "Unknown")
    endif()
endfunction() # LIBWOLFSSL_SAVE_INFO

if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    # LIBWOLFSSL_VERSION_GIT_HASH
    execute_process(COMMAND ${git_cmd} "rev-parse" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_SHORT_HASH
    execute_process(COMMAND ${git_cmd} "rev-parse" "--short" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_SHORT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_HASH_DATE
    execute_process(COMMAND ${git_cmd} "show" "--no-patch" "--no-notes" "--pretty=\'\%cd\'" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES  )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH_DATE "${TMP_OUT}" "${TMP_RES}")
endif()

message(STATUS "${PROJECT_NAME}/main/CMakeLists.txt complete!")
message(STATUS "")
