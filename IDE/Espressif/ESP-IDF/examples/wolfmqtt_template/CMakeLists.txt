# [example]/CMakeLists.txt for Espressif targets
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
#   v1.0
#
# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# enable wolfssl user_settings.h project-wide
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")
set(WOLFSSL_USER_SETTINGS ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFMQTT_USER_SETTINGS")
set(WOLFMQTT_USER_SETTINGS ON)

# These should typically be set in user_settings.h
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_AWSIOT_EXAMPLE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_MQTT_TLS")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFMQTT_EXTERN_CERT")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_MAIN_DRIVER")

# Find the user name to search for possible "wolfssl-username"
# Reminder: Windows is  %USERNAME%, Linux is $USER
if("$ENV{USER}" STREQUAL "" ) # the bash user
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
message(STATUS "THIS_USER = ${THIS_USER}")


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
        "${CMAKE_CURRENT_LIST_DIR}/components/${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/components/my${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/managed_components/wolfssl__${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/managed_components/gojimmypi__my${KEYWORD}"
        "${CMAKE_CURRENT_LIST_DIR}/managed_components/${THIS_USER}__my${KEYWORD}"
        "$ENV{IDF_PATH}/components/${KEYWORD}/"
        "$ENV{IDF_PATH}/components/esp-${KEYWORD}/"
    )

    set(EXISTING_COUNT 0)
    set(MATCHING_DIRS "")  # List to store found directories

    foreach(DIR ${DIR_LIST})
        file(TO_CMAKE_PATH "${DIR}" DIR)  # Normalize paths
        message(STATUS "Checking for ${KEYWORD} in ${DIR}")
        if(EXISTS "${DIR}")
            math(EXPR EXISTING_COUNT "${EXISTING_COUNT} + 1")
            list(APPEND MATCHING_DIRS "${DIR}")
            message(STATUS "Found: ${DIR}")
        endif()
    endforeach()

    if(EXISTING_COUNT GREATER_EQUAL 2)
        set(${RESULT_VAR} TRUE PARENT_SCOPE)
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(STATUS  "WARNING: Found duplicate '${KEYWORD}' in")
        foreach(DUP_DIR ${MATCHING_DIRS})
            message(STATUS "  - ${DUP_DIR}")
        endforeach()
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(STATUS  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        message(WARNING "WARNING: More than 1 '${KEYWORD}' component directories exist.")

        # Append the warning flag to CMAKE_C_FLAGS and propagate it to the parent scope
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${KEYWORD}_MULTI_INSTALL_WARNING")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}" PARENT_SCOPE)
    else()
        set(${RESULT_VAR} FALSE PARENT_SCOPE)

        message(STATUS "Confirmed less than two '${KEYWORD}' component directories exist.")
    endif()
endfunction()

# The wolfSSL CMake file should be able to find the source code.
# Otherwise, assign an environment variable or set it here:
#
# set(WOLFSSL_ROOT "~/workspace/wolfssl-other-source")
# set(WOLFMQTT_ROOT "~/workspace/wolfmqtt-other-source")

# Optional WOLFSSL_CMAKE_SYSTEM_NAME detection to find
# USE_MY_PRIVATE_CONFIG path for my_private_config.h
#
# Expected path varies:
#
#     WSL:  /mnt/c/workspace
#   Linux:  ~/workspace
# Windows:  C:\workspace
#
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
# End optional WOLFSSL_CMAKE_SYSTEM_NAME

# This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
# set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
string(REPLACE "\\" "/" PROTOCOL_EXAMPLES_DIR "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common")

if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
    message(STATUS "Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
    set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
else()
    message(STATUS "NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
endif()

# Check that there are not conflicting wolfSSL components.
# The ESP Registry Component will be in ./managed_components/wolfssl__wolfssl
# The local component wolfSSL directory will be in ./components/wolfssl
message(STATUS "Checking for wolfSSL as Managed Component or not... ${CMAKE_HOME_DIRECTORY}")
message(STATUS "Checking for duplicate components. CMAKE_HOME_DIRECTORY='${CMAKE_HOME_DIRECTORY}'")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolfssl")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolfmqtt")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolfssh")
CHECK_DUPLICATE_LIBRARIES(DUPE_WOLFSSL_FOUND "wolftpm")

if( EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl" AND EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl" )
    # These exclude statements don't seem to be honored by the $ENV{IDF_PATH}/tools/cmake/project.cmake'
    # add_subdirectory("${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl" EXCLUDE_FROM_ALL)
    # add_subdirectory("${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl/include" EXCLUDE_FROM_ALL)
    # So we'll error out and let the user decide how to proceed:
    message(WARNING "\nFound wolfSSL components in\n"
                    "./managed_components/wolfssl__wolfssl\n"
                    "and\n"
                    "./components/wolfssl\n"
                    "in project directory: \n"
                    "${CMAKE_HOME_DIRECTORY}")
    message(FATAL_ERROR "\nPlease use either the ESP Registry Managed Component or the wolfSSL component directory but not both.\n"
                        "If removing the ./managed_components/wolfssl__wolfssl directory, remember to also remove "
                        "or rename the idf_component.yml file typically found in ./main/")
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl")
    # A standard project component (not a Managed Component)
    message(STATUS "No conflicting wolfSSL components found.")
    set(WOLFSSL_PATH "${CMAKE_HOME_DIRECTORY}/components/wolfssl")
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl")
    # The official Managed Component called wolfssl from the wolfssl user.
    message(STATUS "No conflicting wolfSSL components found as a Managed Component.")
    set(WOLFSSL_PATH "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl")
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/gojimmypi__mywolfssl")
    # There is a known gojimmypi staging component available for anyone:
    message(STATUS "No conflicting wolfSSL components found as a gojimmypi staging Managed Component.")
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/${THIS_USER}__mywolfssl")
    # Other users with permissions might publish their own mywolfssl staging Managed Component
    message(STATUS "No conflicting wolfSSL components found as a Managed Component.")
    set(WOLFSSL_PATH "${CMAKE_HOME_DIRECTORY}/managed_components/${THIS_USER}__mywolfssl")
else()
    message(STATUS "WARNING: wolfssl component directory not found.")
endif()


# This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)

if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
    message(STATUS "Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
    set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
else()
    message("NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

#set(COMPONENTS
  #main
  #wolfssl
  #wolfmqtt
#) # set components

project(wolfmqtt_template)
message(STATUS "end project")
