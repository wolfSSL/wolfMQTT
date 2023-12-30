# wolfSSL wolfMQTT Espressif Example Project/main/CMakeLists.txt
#   v1.0
#
message(STATUS "main cmake found WOLFSSL_COMPONENT_NAME = ${WOLFSSL_COMPONENT_NAME}")

if(WIN32)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS")
    message("Detected Windows")
endif()
if(CMAKE_HOST_UNIX)
    message("Detected UNIX")
endif()
if(APPLE)
    message("Detected APPLE")
endif()
if(CMAKE_HOST_UNIX AND (NOT APPLE) AND EXISTS "/proc/sys/fs/binfmt_misc/WSLInterop")
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WSL")
    message("Detected WSL")
endif()
if(CMAKE_HOST_UNIX AND (NOT APPLE) AND (NOT WIN32))
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_LINUX")
    message("Detected Linux")
endif()
if(APPLE)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_APPLE")
    message("Detected Apple")
endif()
set (git_cmd "git")

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
    if( ("${managed_components}" STREQUAL "") AND ("${component_manager_interface_version}" STREQUAL "") )
        # We've found a staging component, but did not detect the component manager
        if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../components/mywolfmqtt/CMakeLists.txt)
            # This is typically during publish-time build test
            message(STATUS "Set name mywolfmqtt (1)")
            set(WOLFSSL_COMPONENT_NAME "mywolfssl")
            set(WOLFMQTT_COMPONENT_NAME "mywolfmqtt")
        else()
            if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../managed_components/gojimmypi__mywolfmqtt/CMakeLists.txt)
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

if(CMAKE_BUILD_EARLY_EXPANSION)
    message(STATUS "wolfmqtt component CMAKE_BUILD_EARLY_EXPANSION:")
    string(REPLACE "\\" "/" PROTOCOL_EXAMPLES "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common")
    idf_component_register(
                        INCLUDE_DIRS
                            "include"
                            "${PROTOCOL_EXAMPLES}"
                        REQUIRES
                              "${WOLFMQTT_COMPONENT_NAME}"
                              nvs_flash
                              esp_event
                              esp_netif
                              esp_wifi
                            PRIV_REQUIRES
                              "${WOLFSSL_COMPONENT_NAME}"
                           )
    message(STATUS "Early Expansion WOLFMQTT_ROOT = ${WOLFMQTT_ROOT}")
else()
    ## register_component()
    message(STATUS "main WOLFMQTT_ROOT = ${WOLFMQTT_ROOT}")

    string(REPLACE "\\" "/" PROTOCOL_EXAMPLES "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common/include")
    idf_component_register(SRCS
                       	    main.c
                       	    wifi_connect.c
                       	    time_helper.c
                       	    ${WOLFMQTT_ROOT}/examples/mqttexample.c
                       	    ${WOLFMQTT_ROOT}/examples/mqttnet.c
                       	    ${WOLFMQTT_ROOT}/examples/mqttport.c
                       	    ${WOLFMQTT_ROOT}/examples/aws/awsiot.c
                        INCLUDE_DIRS
                            "."
                            "include"
                            "${WOLFMQTT_ROOT}/examples/aws/"
                            "${PROTOCOL_EXAMPLES}"
                        REQUIRES
                          "${WOLFMQTT_COMPONENT_NAME}"
                          "${WOLFSSL_COMPONENT_NAME}"
                          lwip
                          nvs_flash
                          esp_event
                        )
endif()
#

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

message(STATUS "")

