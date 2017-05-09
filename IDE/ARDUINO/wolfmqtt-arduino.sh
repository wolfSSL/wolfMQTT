#!/bin/sh

# this script will reformat the wolfSSL source code to be compatible with
# an Arduino project
# run as bash ./wolfssl-arduino.sh

DIR=${PWD##*/}

if [ "$DIR" == "ARDUINO" ]; then
    rm -rf wolfMQTT

    mkdir wolfMQTT
    cp ../../src/*.c ./wolfMQTT
    cp ../../examples/*.c ./wolfMQTT
    cp ../../examples/mqttclient/*.c ./wolfMQTT
    cp ../../examples/mqttclient/*.h ./wolfMQTT

    mkdir wolfMQTT/wolfmqtt
    cp ../../wolfmqtt/*.h ./wolfMQTT/wolfmqtt

    mkdir wolfMQTT/examples
    cp ../../examples/*.h ./wolfMQTT/examples

    echo "/* stub header file for Arduino compatibility */" >> ./wolfMQTT/wolfMQTT.h
else
    echo "ERROR: You must be in the IDE/ARDUINO directory to run this script"
fi
