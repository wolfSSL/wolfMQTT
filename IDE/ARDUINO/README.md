### wolfMQTT with Arduino

##### Reformatting wolfMQTT as a compatible Arduino Library
wolfmqtt-arduino.sh is a shell script that will re-organize the wolfMQTT 
library to be compatible with Arduino projects. The Arduino IDE requires a 
library's source files to be in the library's root directory with a header file
in the name of the library. This script moves all source files to the root
wolfMQTT directory and creates a stub header file called wolfMQTT.h.

To configure wolfMQTT with Arduino, enter the following from within the 
wolfssl/IDE/ARDUINO directory:

    ./wolfmqtt-arduino.sh
    
#####Including wolfMQTT in Arduino Libraries (for Arduino version 1.6.6)
1. Copy the wolfMQTT directory into Arduino/libraries (or wherever Arduino 
searches for libraries).
2. In the Arduino IDE:
    - Go to ```Sketch > Include Libraries > Manage Libraries```. This refreshes
    your changes to the libraries.
    - Next go to ```Sketch > Include Libraries > wolfMQTT```. This includes
    wolfMQTT in your sketch.
