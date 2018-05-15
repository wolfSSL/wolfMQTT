#!/bin/sh

# this script will reformat the wolfSSL source code to be compatible with
# an Arduino project
# run as bash ./wolfssl-arduino.sh

DIR=${PWD##*/}

if [ "$DIR" = "ARDUINO" ]; then
    rm -rf wolfMQTT

    mkdir wolfMQTT
    cp ../../src/*.c ./wolfMQTT

    mkdir wolfMQTT/wolfmqtt
    cp ../../wolfmqtt/*.h ./wolfMQTT/wolfmqtt

    echo "/* Generated wolfMQTT header file for Arduino */" >> ./wolfMQTT/wolfMQTT.h
    echo "#include <wolfmqtt/mqtt_client.h>" >> ./wolfMQTT/wolfMQTT.h
else
    echo "ERROR: You must be in the IDE/ARDUINO directory to run this script"
fi
