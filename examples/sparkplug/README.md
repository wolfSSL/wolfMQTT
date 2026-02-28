# Sparkplug B Example

This example demonstrates the [Sparkplug B](https://sparkplug.eclipse.org/) industrial IoT protocol specification using wolfMQTT. It creates two MQTT clients that communicate using the Sparkplug topic namespace and message types.

## Overview

Sparkplug B is an open-source specification designed for industrial IoT and SCADA systems. It defines:

- **Topic Namespace**: `spBv1.0/{group_id}/{message_type}/{edge_node_id}[/{device_id}]`
- **Message Types**: Birth/Death certificates, Data, and Commands
- **Payload Format**: Google Protocol Buffers (this example uses a simplified encoding)

## Architecture

The example implements two clients:

### Edge Node (Publisher)
- Represents an industrial device or gateway
- Publishes **NBIRTH** (Node Birth Certificate) on startup
- Publishes **DDATA** (Device Data) with sensor metrics periodically
- Subscribes to **DCMD** (Device Command) topics to receive commands
- Configures **NDEATH** (Node Death Certificate) as Last Will and Testament

### Host Application (Subscriber)
- Represents a SCADA or supervisory system
- Subscribes to all Sparkplug messages in the group (`spBv1.0/{group}/#`)
- Receives and processes birth certificates and device data
- Sends **DCMD** (Device Command) messages to control devices

## Message Types

| Type | Description |
|------|-------------|
| NBIRTH | Node Birth Certificate - Edge node announces itself |
| NDEATH | Node Death Certificate - Edge node goes offline (LWT) |
| DBIRTH | Device Birth Certificate - Device announces itself |
| DDEATH | Device Death Certificate - Device goes offline |
| NDATA | Node Data - Metrics from the edge node |
| DDATA | Device Data - Metrics from a device |
| NCMD | Node Command - Command to the edge node |
| DCMD | Device Command - Command to a specific device |
| STATE | Host Application state |

## Simulated Metrics

The Edge Node simulates the following sensor data:

| Metric | Type | Description |
|--------|------|-------------|
| Temperature | Float | Simulated temperature in Celsius |
| Humidity | Float | Simulated humidity percentage |
| LED | Boolean | LED on/off state (controllable via command) |
| Counter | UInt32 | Message counter |

## Building

### Autotools

```bash
# Single-threaded (Edge Node only)
./configure --disable-tls
make

# Multi-threaded (both clients communicate)
./configure --enable-mt --disable-tls
make
```

### CMake

```bash
mkdir build && cd build

# Single-threaded
cmake -DWOLFMQTT_TLS=no ..
make sparkplug

# Multi-threaded
cmake -DWOLFMQTT_TLS=no -DWOLFMQTT_MT=yes ..
make sparkplug
```

## Running

```bash
# Using default broker (test.mosquitto.org)
./examples/sparkplug/sparkplug

# Specify broker
./examples/sparkplug/sparkplug -h <broker_host> -p <port>

# With TLS (if built with TLS support)
./examples/sparkplug/sparkplug -h <broker_host> -p 8883 -t
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h <host>` | MQTT broker hostname (default: test.mosquitto.org) |
| `-p <port>` | MQTT broker port (default: 1883) |
| `-t` | Enable TLS |
| `-c <file>` | TLS CA certificate file |
| `-q <qos>` | QoS level (0, 1, or 2) |
| `-C` | Clean session |

## Example Output

```
Sparkplug B Example
===================
This example demonstrates two MQTT clients communicating
using the Sparkplug B industrial IoT protocol.

Starting Edge Node and Host Application threads...

Sparkplug: Connecting WolfMQTT_Sparkplug_Edge to broker test.mosquitto.org:1883...
Sparkplug: Connected! (client_id=WolfMQTT_Sparkplug_Edge)
Sparkplug: Subscribing to spBv1.0/WolfMQTT/DCMD/EdgeNode1/#
Sparkplug: Subscribed (granted QoS=1)
Sparkplug: Published NBIRTH to spBv1.0/WolfMQTT/NBIRTH/EdgeNode1

Sparkplug: Connecting WolfMQTT_Sparkplug_Host to broker test.mosquitto.org:1883...
Sparkplug: Connected! (client_id=WolfMQTT_Sparkplug_Host)
Sparkplug: Subscribing to spBv1.0/WolfMQTT/#
Sparkplug: Subscribed (granted QoS=1)

Sparkplug [WolfMQTT_Sparkplug_Host]: Received NBIRTH from WolfMQTT/EdgeNode1
  -> Edge Node came online (bdSeq=0)

Sparkplug: Published DDATA to spBv1.0/WolfMQTT/DDATA/EdgeNode1/Device1
Sparkplug [WolfMQTT_Sparkplug_Host]: Received DDATA from WolfMQTT/EdgeNode1/Device1
  -> Device data received:
     Temperature = 22.83
     Humidity = 45.36
     LED = OFF
     Counter = 1

Sparkplug [Host]: Sending command to toggle LED ON
Sparkplug [Host]: Sending DCMD to spBv1.0/WolfMQTT/DCMD/EdgeNode1/Device1 (LED=ON)

Sparkplug [WolfMQTT_Sparkplug_Edge]: Received DCMD from WolfMQTT/EdgeNode1/Device1
  -> Command received:
     LED set to ON

Sparkplug: Published DDATA to spBv1.0/WolfMQTT/DDATA/EdgeNode1/Device1
Sparkplug [WolfMQTT_Sparkplug_Host]: Received DDATA from WolfMQTT/EdgeNode1/Device1
  -> Device data received:
     Temperature = 23.10
     Humidity = 45.01
     LED = ON
     Counter = 2

Sparkplug: Disconnecting WolfMQTT_Sparkplug_Host...
Sparkplug: Disconnected WolfMQTT_Sparkplug_Host
Sparkplug: Disconnecting WolfMQTT_Sparkplug_Edge...
Sparkplug: Disconnected WolfMQTT_Sparkplug_Edge

Sparkplug example completed!
```

## Configuration

The following constants can be modified in `sparkplug.h`:

```c
#define SPARKPLUG_NAMESPACE     "spBv1.0"
#define SPARKPLUG_GROUP_ID      "WolfMQTT"
#define SPARKPLUG_EDGE_NODE_ID  "EdgeNode1"
#define SPARKPLUG_DEVICE_ID     "Device1"
#define SPARKPLUG_HOST_ID       "HostApp1"
```

## Payload Format

This example uses a simplified binary payload format for demonstration purposes. Production Sparkplug implementations should use the official [Sparkplug B Protocol Buffer definitions](https://github.com/eclipse/tahu/tree/master/sparkplug_b).

The simplified format encodes:
- Timestamp (8 bytes)
- Sequence number (8 bytes)
- Metric count (4 bytes)
- For each metric: name, alias, timestamp, datatype, and value

## Notes

- **Multi-threading Required**: For full two-client communication, build with `--enable-mt` (Autotools) or `-DWOLFMQTT_MT=yes` (CMake). In single-threaded mode, only the Edge Node runs.
- **Birth/Death Sequence**: The `bdSeq` metric in NBIRTH and NDEATH allows hosts to correlate birth and death messages.
- **Sequence Numbers**: Data messages include a sequence number (0-255) for ordering and gap detection.
- **Last Will and Testament**: The Edge Node configures NDEATH as its LWT so the broker publishes it if the client disconnects unexpectedly.

## See Also

- [Sparkplug Specification](https://sparkplug.eclipse.org/specification/version/3.0/documents/sparkplug-specification-3.0.0.pdf)
- [Eclipse Tahu](https://github.com/eclipse/tahu) - Reference Sparkplug implementations
- [wolfMQTT Documentation](https://www.wolfssl.com/documentation/wolfMQTT-Manual.pdf)
