#!/bin/sh

# this script will reformat the wolfSSL source code to be compatible with
# an Arduino project
# run as bash ./wolfssl-arduino.sh

DIR=${PWD##*/}

if [ "$DIR" == "ARDUINO" ]; then
    cp ../../src/*.c ../../
    cp ../../examples/*.c ../../
    cp ../../examples/mqttclient/*.c
    cp ../../examples/mqttclient/*.h
    cp ../../examples/*.h
    echo "/* stub header file for Arduino compatibility */" >> ../../wolfMQTT.h
else
    echo "ERROR: You must be in the IDE/ARDUINO directory to run this script"
fi
