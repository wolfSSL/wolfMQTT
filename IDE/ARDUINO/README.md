### wolfMQTT with Arduino

##### Reformatting wolfMQTT as a compatible Arduino Library
wolfmqtt-arduino.sh is a shell script that will re-organize the wolfMQTT
library to be compatible with Arduino projects. The Arduino IDE requires a
library's source files to be in the library's root directory with a header file
in the name of the library. This script copies all source files to the
`IDE/ARDUINO/wolfMQTT` directory and creates a stub header file called
`wolfMQTT.h`.

To configure wolfMQTT with Arduino, enter the following from within the
IDE/ARDUINO directory:

    ./wolfmqtt-arduino.sh

##### Including wolfMQTT in Arduino Libraries (for Arduino version 1.8.2)

1. In the Arduino IDE:
    - In `Sketch -> Include Library -> Add .ZIP Library...` and choose the
        `IDE/ARDUNIO/wolfMQTT` folder.
    - In `Sketch -> Include Library` choose wolfMQTT.

To enable TLS support, uncomment `#define ENABLE_MQTT_TLS` in
    `IDE/ARDUNIO/wolfMQTT/wolfmqtt/mqtt_types.h`.
Note: If using wolfSSL TLS then you'll need to do this for wolfSSL as well.
See `<wolfssl-root>/IDE/ARDUINO/README.md` for instructions.


An example wolfMQTT client INO sketch exists here:
`wolfmqtt_client/wolfmqtt_client.ino` to demonstrate using the wolfMQTT library.
