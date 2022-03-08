#!/bin/sh

# This script is used in the F767ZI-TOPPERS project
# run as bash ./wolfmqtt-F767ZI-TOPPERS.sh

DIR=${PWD##*/}

if [ "$DIR" = "F767ZI-TOPPERS" ]; then
   rm -f wolfssl
   rm -rf src
   rm -rf examples
   rm -rf wolfmqtt
   
   if [ "$(expr substr $(uname -s) 1 5)" == MINGW ]; then
      export MSYS=winsymlinks:nativestrict
   fi
     ln -s ../../../wolfssl*  wolfssl
     mkdir src
     cp ../../src/*.c ./src

     mkdir examples
     cp ../../examples/mqttexample.* ./examples
     cp ../../examples/mqttnet.* ./examples

     mkdir examples/azure
     cp ../../examples/azure/*.c ./examples/azure
     cp ../../examples/azure/*.h ./examples/azure
   
     mkdir wolfmqtt
     cp ../../wolfmqtt/*.h ./wolfmqtt
     cp ./user_settings.h ./wolfmqtt
     cp ./options.h  ./wolfmq
else
    echo "ERROR: You must be in the IDE/F767ZI-TOPPERS directory to run this script"
fi
