# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

wolfMQTT is an MQTT client library written in C for embedded systems. It supports MQTT v3.1.1 and v5.0 protocols, MQTT-SN for sensor networks, and integrates with wolfSSL for TLS support.

## Build Commands

### Standard Build (Linux/macOS)
```bash
./autogen.sh          # Required if cloned from GitHub
./configure           # See --help for options
make
sudo make install
```

### Run Tests
```bash
make check            # Runs all tests with local mosquitto broker
```

### Individual Test Scripts
```bash
./scripts/client.test       # Main MQTT client tests (QoS 0-2, TLS)
./scripts/nbclient.test     # Non-blocking client tests
./scripts/multithread.test  # Multi-threading tests
./scripts/stress.test       # Stress testing (requires --enable-stress)
```

### CMake Build
```bash
mkdir build && cd build
cmake .. -DWITH_WOLFSSL=/path/to/wolfssl/install/   # Use installed wolfSSL
# OR
cmake .. -DWITH_WOLFSSL_TREE=/path/to/wolfssl/      # Use source tree
cmake --build .
```

### Common Configure Options
```bash
--enable-tls        # TLS support (default: enabled)
--enable-v5         # MQTT v5.0 support
--enable-sn         # MQTT-SN (Sensor Network) support
--enable-nonblock   # Non-blocking I/O support
--enable-mt         # Multi-threading support
--enable-websocket  # WebSocket support (requires libwebsockets)
--enable-curl       # libcurl backend support
--enable-all        # Enable all features
--enable-debug      # Debug mode (--enable-debug=verbose for extra logging)
--enable-stress     # Stress testing (e.g., --enable-stress=t7,p8 for 7 threads, 8 pubs)
--disable-tls       # Disable TLS for testing without wolfSSL
```

### Running Examples
```bash
./examples/mqttclient/mqttclient -?    # Show help with available options
./examples/mqttclient/mqttclient -h localhost -p 1883   # Connect to local broker
./examples/mqttclient/mqttclient -h localhost -t -p 8883  # TLS connection
```

## Architecture

### Core Library Components (in /src/)

1. **mqtt_client.c** - Top-level client API
   - `MqttClient_Init()`, `MqttClient_Connect()`, `MqttClient_Publish()`
   - `MqttClient_Subscribe()`, `MqttClient_WaitMessage()`, `MqttClient_Disconnect()`

2. **mqtt_packet.c** - MQTT packet encoding/decoding
   - Structures: `MqttConnect`, `MqttPublish`/`MqttMessage`, `MqttSubscribe`

3. **mqtt_socket.c** - Transport layer with TLS integration
   - Network callbacks via `MqttNet` structure

4. **mqtt_sn_client.c / mqtt_sn_packet.c** - MQTT-SN protocol support

### Public Headers (in /wolfmqtt/)

- `mqtt_types.h` - Type definitions, error codes, platform abstractions
- `mqtt_client.h` - Client API declarations
- `mqtt_packet.h` - Packet structures
- `mqtt_socket.h` - Network interface
- `options.h` - Generated build configuration

### Examples (in /examples/)

- `mqttclient/` - Full-featured reference client (best starting template)
- `mqttsimple/` - Standalone BSD sockets client
- `nbclient/` - Non-blocking I/O example
- `multithread/` - Multi-threaded publish/subscribe
- `firmware/` - Firmware update (fwpush/fwclient)
- `aws/`, `azure/`, `wiot/` - Cloud platform integrations
- `sn-client/` - MQTT-SN client
- `websocket/` - WebSocket client
- `pub-sub/` - Simple mqtt-pub and mqtt-sub utilities

### Shared Example Code

- `examples/mqttnet.c` - Network callback reference implementation
- `examples/mqttport.c` - Platform abstraction layer
- `examples/mqttexample.c` - Common example utilities

## Key Compile Macros

```c
ENABLE_MQTT_TLS           // TLS support
WOLFMQTT_V5               // MQTT v5.0
WOLFMQTT_SN               // MQTT-SN protocol
WOLFMQTT_NONBLOCK         // Non-blocking I/O
WOLFMQTT_MULTITHREAD      // Multi-threading
WOLFMQTT_DYN_PROP         // Dynamic property allocation (v5.0)
DEBUG_WOLFMQTT            // Debug mode
```

## Testing

Tests require a local mosquitto broker. The CI uses `bubblewrap` for network isolation.

To skip external broker tests:
```bash
WOLFMQTT_NO_EXTERNAL_BROKER_TESTS=1 ./configure --enable-all
make check
```

Test certificates are in `/certs/` (RSA and ECC variants).
Broker test config: `/scripts/broker_test/mosquitto.conf`

## Code Style

Uses `.clang-format` with LLVM base style:
- Tab indentation (4-space tabs)
- K&R inspired style

## Dependencies

- **wolfSSL** - Required for TLS support
- **libwebsockets** - Optional, for WebSocket support
- **libcurl** - Optional, for curl backend
- **mosquitto** - For running tests
