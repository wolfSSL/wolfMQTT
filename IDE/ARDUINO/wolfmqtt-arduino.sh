#!/bin/sh

# this script will reformat the wolfSSL source code to be compatible with
# an Arduino project
# run as bash ./wolfssl-arduino.sh

DIR=${PWD##*/}

if [ "$DIR" == "ARDUINO" ]; then
    mkdir wolfmqtt
    cp ../../src/*.c ./wolfmqtt
    cp ../../examples/*.c ./wolfmqtt
    cp ../../examples/mqttclient/*.c ./wolfmqtt
    cp ../../examples/mqttclient/*.h ./wolfmqtt
    cp ../../examples/*.h ./wolfmqtt
    echo "/* stub header file for Arduino compatibility */" >> ./wolfmqtt/wolfMQTT.h
else
    echo "ERROR: You must be in the IDE/ARDUINO directory to run this script"
fi
