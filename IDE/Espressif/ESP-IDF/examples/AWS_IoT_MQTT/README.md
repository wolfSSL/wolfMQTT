# wolfSSL Example Project: wolfMQTT for AWS IoT

This is an example based on the [AWS IoT Example](https://github.com/wolfSSL/wolfMQTT/tree/master/examples/aws).

## Getting Started

The easiest way to get started is by using the Espressif Managed Component Registry
at https://components.espressif.com

The latest experimental development version can be found at the staging site: 
[gojimmypi/mywolfmqtt](https://components-staging.espressif.com/components/gojimmypi/mywolfmqtt/versions/1.0.14-test?language=en).

```bash
#!/bin/bash

. ~/esp/esp-idf/export.sh

# Needed for Staging site:
export IDF_COMPONENT_REGISTRY_URL=https://components-staging.espressif.com

idf.py create-project-from-example "gojimmypi/mywolfmqtt^1.0.14-test:AWS_IoT_MQTT"

cd AWS_IoT_MQTT

# Set your SSID and wifi Password in example configuration
idf.py menuconfig

idf.py -p /dev/ttyS9 -b 921600 flash monitor -b 115200

```

### Prerequisites

It is assumed the [ESP-IDF environment](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) has been installed.

### Files Included

- [main.c](./main/main.c) with a simple call to an Espressif library (`ESP_LOGI`) and a call to a wolfSSL library (`esp_ShowExtendedSystemInfo`) . 

- See [components/wolfssl/include](./components/wolfssl/include/user_settings.h) directory to edit the wolfSSL `user_settings.h`.

- Edit [main/CMakeLists.txt](./main/CMakeLists.txt) to add/remove source files.

- The [components/wolfssl/CMakeLists.txt](./components/wolfssl/CMakeLists.txt) typically does not need to be changed.

- Optional [VisualGDB Project](./VisualGDB/wolfssl_template_IDF_v5.1_ESP32.vgdbproj) for Visual Studio using ESP32 and ESP-IDF v5.1.

- Edit the project [CMakeLists.txt](./CMakeLists.txt) to optionally point this project's wolfSSL component source code at a different directory:

```
set(WOLFSSL_ROOT "~/workspace/wolfssl-other-source")
```


## Getting Started:

Here's an example using the command-line [idf.py](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-py.html).

Edit your `WRK_IDF_PATH`to point to your ESP-IDF install directory.

```
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.1

echo "Run export.sh from ${WRK_IDF_PATH}"
. ${WRK_IDF_PATH}/export.sh

# build the example:
idf.py build

# flash the code onto the serial device at /dev/ttyS19
idf.py flash -p /dev/ttyS19 -b 115200

# build, flash, and view UART output with one command:
idf.py flash -p /dev/ttyS19 -b 115200 monitor
```

Press `Ctrl+]` to exit `idf.py monitor`. See [additional monitor keyboard commands](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-monitor.html).

## Other Examples:

For examples, see:

- [TLS Client](../wolfssl_client/README.md)
- [TLS Server](../wolfssl_server/README.md)
- [Benchmark](../wolfssl_benchmark/README.md)
- [Test](../wolfssl_test/README.md)
- [wolfssl-examples](https://github.com/wolfSSL/wolfssl-examples/tree/master/ESP32)
- [wolfssh-examples](https://github.com/wolfSSL/wolfssh-examples/tree/main/Espressif)



