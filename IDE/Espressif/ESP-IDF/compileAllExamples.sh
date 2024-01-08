#!/bin/bash
#
# wolfMQTT testing script: compileAllExamples
#

echo "************************************************************************"
echo "************************************************************************"
echo "* Starting wolfMQTT compileAllExamples.sh"
echo "************************************************************************"
echo "************************************************************************"

if  [[ "$IDF_PATH" == "" ]]; then
    echo "Error: $IDF_PATH not found; run Espressif export.sh"
    exit 1
fi

# See https://components.espressif.com/components/wolfssl/wolfssl
WOLFSSL_COMPONENT=wolfssl/wolfssl^5.6.6-stable-update2-esp32

SCRIPT_DIR=$(builtin cd "${BASH_SOURCE%/*}" || exit 1; pwd)
RUN_SETUP=$1
THIS_ERR=0
BUILD_PUBLISHED_EXAMPLES=0


echo "Found IDF_PATH = $IDF_PATH"
echo "RUN_SETUP: $RUN_SETUP"
echo ""

# Optionally build published examples. (see above; set BUILD_PUBLISHED_EXAMPLES=1)
# The published examples don't change with GitHub, so no need to test every commit.
#
# See also [scripts]/espressif/wolfssl_component_publish.sh
#
if [ $BUILD_PUBLISHED_EXAMPLES -ne 0 ]; then
    echo "************************************************************************"
    echo "* template create-project-from-example"
    echo "************************************************************************"

    # See https://components.espressif.com/components/wolfssl/wolfmqtt
    idf.py create-project-from-example "wolfssl/wolfssl^5.6.6-stable-update2-esp32:template"

    THIS_ERROR_CODE=$?
    if [ $THIS_ERROR_CODE -ne 0 ]; then
        echo ""
        echo "ERROR: Failed idf.py create-project-from-example for template example"
        exit 1
    fi

    cd template || exit 1

    idf.py build

    THIS_ERROR_CODE=$?
    if [ $THIS_ERROR_CODE -ne 0 ]; then
        echo ""
        echo "ERROR: Failed to build template from the ESP Registry"
        exit 1
    else
        echo ""
        echo "Successfully built template example from the ESP Registry"
    fi


    echo "************************************************************************"
    echo "* AWS_IoT_MQTT create-project-from-example"
    echo "************************************************************************"

    # See https://components.espressif.com/components/wolfssl/wolfmqtt
    idf.py create-project-from-example "wolfssl/wolfmqtt^1.18.0-preview6:AWS_IoT_MQTT"

    THIS_ERROR_CODE=$?
    if [ $THIS_ERROR_CODE -ne 0 ]; then
        echo ""
        echo "ERROR: Failed idf.py create-project-from-example for AWS_IoT_MQTT example"
        exit 1
    fi

    cd AWS_IoT_MQTT || exit 1

    idf.py build

    THIS_ERROR_CODE=$?
    if [ $THIS_ERROR_CODE -ne 0 ]; then
        echo ""
        echo "ERROR: Failed to build AWS_IoT_MQTT from the ESP Registry"
        exit 1
    else
        echo ""
        echo "Successfully built AWS_IoT_MQTT from the ESP Registry"
    fi
fi

# NOTE: The wolfMQTT examples include a CMakeLists.txt that will look for wolfssl
# source code. Using managed components will cause a conflict.
# The manifested error will be something like:
#   CMake Error at /opt/esp/idf/tools/cmake/component.cmake:250 (message):
#     ERROR: Cannot process component requirements.  Multiple candidates to
#       satisfy project requirements:
#     requirement: "wolfssl" candidates: "wolfssl, wolfssl__wolfssl"
# See `components/wolfssl.bak` rename, below, to avoid this error.
# A future CMakeLists.txt may handle this more gracefully.
#
# Additionally, the wolfSSL.bak cmake file needs to be renamed (disabled), as it
# goes looking for wolfssl source code - which is not present in docker CI build.


# We could test on all possible ESP-IDF targets:
#
#   targets=$(idf.py --list-targets)
#   for target in $targets; do
#       if [[ $target == esp32* ]]; then
#           echo "Found target to process: $target"
#       else
#           echo "Will skip target $target"
#       fi
#   done
#
# But for now just testing the basic ESP32:
target=esp32
file=
for file in "wolfmqtt_template" "AWS_IoT_MQTT"; do
    echo "Building target = ${target} for ${file}"
    pushd "${SCRIPT_DIR}/examples/${file}/"                                            && \
          rm -rf ./build                                                               && \
          mv components/wolfssl/CMakeLists.txt components/wolfssl/CMakeLists.disabled  && \
          mv components/wolfssl components/wolfssl.bak                                 && \
          idf.py add-dependency "$WOLFSSL_COMPONENT"                                   && \
          idf.py set-target "${target}" fullclean build
          THIS_ERR=$?
    popd || exit 1
    if [ $THIS_ERR -ne 0 ]; then
        echo "Failed target ${target} in ${file}"
        all_build_success=false
    fi
done # for file...

echo "All builds successful: ${all_build_success}"
if [[ "${all_build_success}" == "false" ]]; then
  echo "One or more builds failed"
  exit 1
fi

echo "************************************************************************"
echo "* Completed wolfMQTT compileAllExamples.sh"
echo "************************************************************************"

