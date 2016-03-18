### wolfMQTT with Arduino

##### Reformatting wolfMQTT as a compatible Arduino Library
wolfmqtt-arduino.sh is a shell script that will re-organize the wolfMQTT 
library to be compatible with Arduino projects. The Arduino IDE requires a 
library's source files to be in the library's root directory with a header file
in the name of the library. This script moves all source files to the root
wolfMQTT directory and creates a stub header file called wolfMQTT.h.

To configure wolfMQTT with Arduino, enter the following from within the 
IDE/ARDUINO directory:

    ./wolfmqtt-arduino.sh
    
#####Including wolfMQTT in Arduino Libraries (for Arduino version 1.6.6)

1. In the Arduino IDE:
    - In `Sketch -> Import Library -> Add Library` and choose the wolfMQTT/IDE/ARDUNIO/wolfmqtt folder.
    - In `Sketch -> Import Library` choose wolfMQTT.

Note: If using wolfSSL TLS then you'll need to do this for wolfSSL as well.
