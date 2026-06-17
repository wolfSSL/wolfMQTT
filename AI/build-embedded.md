# Building wolfMQTT for Embedded Platforms

wolfMQTT runs on a range of embedded platforms. The `IDE/` directory contains ready-made project files and README files for each supported target.

## General approach

Embedded builds add the wolfMQTT source files directly to your IDE project rather than using autotools. The key files to include are:

- `src/mqtt_client.c`
- `src/mqtt_packet.c`
- `src/mqtt_socket.c`
- `src/mqtt_sn_client.c` and `src/mqtt_sn_packet.c` (if using MQTT-SN)
- `src/mqtt_broker.c` (if using the embedded broker)

Define the features you need via compiler macros (see the Key Compile Macros section in AGENTS.md). For TLS, also include wolfSSL in your build.

## Supported IDE Platforms

| Directory | Platform |
|-----------|----------|
| `IDE/ARDUINO/` | Arduino |
| `IDE/Espressif/` | ESP32 / ESP-IDF |
| `IDE/STM32CUBE/` | STM32CubeIDE |
| `IDE/F767ZI-TOPPERS/` | STM32 F767ZI with TOPPERS RTOS |
| `IDE/Microchip-Harmony/` | Microchip Harmony (MPLAB X) |
| `IDE/QNX/` | QNX Neutrino |
| `zephyr/` | Zephyr RTOS |

Each subdirectory has its own README with platform-specific setup instructions.

## Arduino

The `IDE/ARDUINO/` directory contains an Arduino library package. Copy or symlink it into your Arduino `libraries/` folder. See `IDE/ARDUINO/README.md` for the steps to configure wolfSSL alongside wolfMQTT.

Key macro to define in your sketch or `user_settings.h`:

```c
#define ENABLE_MQTT_TLS    /* enable TLS via wolfSSL */
#define WOLFMQTT_NONBLOCK  /* use non-blocking I/O for Arduino event loop compatibility */
```

## Espressif (ESP32 / ESP-IDF)

The `IDE/Espressif/` directory contains ESP-IDF component integration. wolfMQTT is available as an ESP Registry component.

```bash
# Add to your ESP-IDF project's managed components
idf.py add-dependency "wolfssl/wolfmqtt"
idf.py build
```

Or use the project files in `IDE/Espressif/ESP-IDF/examples/` as a starting point. See the README in each example for wolfSSL dependency configuration.

Espressif-specific notes:
- `sdkconfig` files are gitignored; use `sdkconfig.defaults` to persist build options
- Managed component lock files are gitignored (tied to a specific IDF version)

## STM32 / STM32CubeIDE

The `IDE/STM32CUBE/` directory has a STM32CubeIDE project. Import it into your workspace via File > Import > Existing Projects. wolfSSL must be added to the project separately — see wolfSSL's `IDE/STM32Cube/` for the matching wolfSSL project.

## STM32 F767ZI with TOPPERS

`IDE/F767ZI-TOPPERS/` targets the STM32 Nucleo-144 board running the TOPPERS RTOS. See the README in that directory for toolchain and RTOS configuration steps.

## Microchip Harmony

`IDE/Microchip-Harmony/` contains a Harmony 3 wolfMQTT client component (`wolfmqtt_client/`). Add it to your Harmony project via MCC (MPLAB Code Configurator). The generated `mqtt_client.X` MPLAB X project is in `firmware/`.

## QNX

`IDE/QNX/` provides a QNX Neutrino build. Use the QNX Momentics IDE or the QNX command-line tools:

```bash
source /path/to/qnx/qnxsdp-env.sh
cd IDE/QNX
make
```

## Zephyr

wolfMQTT is available as a Zephyr module. The `zephyr/` directory contains the module manifest and Kconfig integration.

To add wolfMQTT to a Zephyr workspace, add it to your `west.yml`:

```yaml
- name: wolfmqtt
  url: https://github.com/wolfSSL/wolfMQTT
  revision: master
  path: modules/lib/wolfmqtt
```

Then enable it in your project's `prj.conf`:

```
CONFIG_WOLFMQTT=y
CONFIG_WOLFMQTT_TLS=y
```

## Minimizing Footprint

wolfMQTT is designed for constrained environments. To reduce code size:

- Only include the source files you need (omit `mqtt_broker.c`, `mqtt_sn_*.c` if unused)
- Define `WOLFMQTT_STATIC_MEMORY` to eliminate heap allocation
- Disable unused features: omit `WOLFMQTT_V5`, `WOLFMQTT_SN`, `ENABLE_MQTT_WEBSOCKET` if not needed
- Use `WOLFMQTT_NONBLOCK` to avoid blocking I/O when integrating with an event loop
