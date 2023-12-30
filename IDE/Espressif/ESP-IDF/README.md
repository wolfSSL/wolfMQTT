# Espressif ESP-IDF Examples

These are the core [examples](./examples/README.md) for wolfMQTT:

- [template](./examples/wolfmqtt_template/README.md)

- [AWS IoT MQTT](./examples/AWS_IoT_MQTT/README.md)

For details on wolfMQTT [see the wolfMQTT Manual](https://www.wolfssl.com/documentation/manuals/wolfmqtt/wolfMQTT-Manual.pdf).

## Installing wolfSSL for Espressif projects

[Core examples](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples) 
have a local `components/wolfssl` directory with a special CMakeFile.txt that does not require 
wolfSSL to be installed.

If you want to install wolfSSL, see the setup for [wolfSSL](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF#setup-for-linux) 
and [wolfSSH](https://github.com/wolfSSL/wolfssh/tree/master/ide/Espressif#setup-for-linux).

## VisualGDB

Users of VisualGDB can find project files in each respective example `.\VisualGDB` directory.
For convenience, there are separate project for various target chip sets and ESP-IDF version.

For devices without a built-in JTAG, the projects are configured with the open source [Tigard](https://www.crowdsupply.com/securinghw/tigard)
and using port `COM20`.

For devices _with_ a built-in JTAG, the projects are using `COM9`

Edit the COM port for your project:

- ESP-IDF Project; Bootloader COM Port.
- Raw Terminal; COM Port


## Troubleshooting

If unusual errors occur, exit Visual Studio and manually delete these directories to start over:

- `.\build`
- `.\VisualGDB\.visualgdb`
- `.\VisualGDB\.vs`


[RSA peripheral 50% slower on ESP32-S3/C3 than S2](https://www.esp32.com/viewtopic.php?t=23830)

[GPIO6,GPIO7,GPIO8,and GPIO9 changed for ESP32-WROOM-32E](https://esp32.com/viewtopic.php?t=29058)




