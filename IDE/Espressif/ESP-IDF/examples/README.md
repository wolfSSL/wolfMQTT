# IDE: Espressif ESP-IDF Examples

These are the core [examples](./README.md) for wolMQTT:

- [template](./wolfmqtt_template/README.md)

- [AWS IoT MQTT](./AWS_IoT_MQTT/README.md)

For details on wolfMQTT [see the wolfMQTT Manual](https://www.wolfssl.com/documentation/manuals/wolfmqtt/wolfMQTT-Manual.pdf).

## Getting Started:

Here's an example using the command-line [idf.py](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-py.html).

Edit your `WRK_IDF_PATH`to point to your ESP-IDF install directory.

```
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

echo "Run export.sh from ${WRK_IDF_PATH}"
. ${WRK_IDF_PATH}/export.sh

# build the example:
idf.py build

# optionally erase the flash
idf.py erase-flash -p /dev/ttyS19 -b 115200

# flash the code onto the serial device at /dev/ttyS19
idf.py flash -p /dev/ttyS19 -b 115200

# build, flash, and view UART output with one command:
idf.py flash -p /dev/ttyS19 -b 115200 monitor
```

Press `Ctrl+]` to exit `idf.py monitor`. See [additional monitor keyboard commands](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-monitor.html).
