# wolfMQTT

This is an implementation of the MQTT Client written in C for embedded use, which supports SSL/TLS via the wolfSSL library. This library was built from the ground up to be multi-platform, space conscious and extensible. Integrates with wolfSSL to provide TLS support.

For details on wolfMQTT [see the wolfMQTT Manual](https://www.wolfssl.com/documentation/manuals/wolfmqtt/wolfMQTT-Manual.pdf).

## Building

### Mac/Linux/Unix

1. `./autogen.sh` (if cloned from GitHub)
2. `./configure` (to see a list of build options use `./configure --help`)
3. `make`
4. `sudo make install`

Notes:
* If `wolfssl` was recently installed, run `sudo ldconfig` to update the linker cache.
* Debug messages can be enabled using `--enable-debug` or `--enable-debug=verbose` (for extra logging).
* For a list of build options run `./configure --help`.
* The build options are generated in a file here: `wolfmqtt/options.h`.

### Windows Visual Studio

For building wolfMQTT with TLS support in Visual Studio:

1. Open the `<wolfssl-root>/wolfssl64.sln`.
2. Re-target for your Visual Studio version (right-click on solution and choose `Retarget solution`).
3. Make sure the `Debug DLL` or `Release DLL` configuration is selected. Make note if you are building 32-bit `x86` or 64-bit `x64`.
4. Build the wolfSSL solution.
5. Copy the `wolfssl.lib` and `wolfssl.dll` files into `<wolfmqtt-root>`.
   * For `DLL Debug` with `x86` the files are in: `DLL Debug`.
   * For `DLL Release` with `x86` the files are in: `DLL Release`.
   * For `DLL Debug` with `x64` the files are in: `x64/DLL Debug`.
   * For `DLL Release` with `x64` the files are in: `x64/DLL Release`.
6. Open the `<wolfmqtt-root>/wolfmqtt.sln` solution.
7. Make sure you have the same architecture (`x86` or `x64` selected) as used in wolfSSL above.
8. By default the include path for the wolfssl headers is `./../wolfssl/`. If your wolfssl root location is different you can go into the project settings and adjust this in `C/C++` -> `General` -> `Additional Include Directories`.
9. Configure your Visual Studio build settings using `wolfmqtt/vs_settings.h`.
10. Build the wolfMQTT solution.

### CMake
CMake supports compiling in many environments including Visual Studio
if CMake support is installed. The commands below can be run in
`Developer Command Prompt`.

```
mkdir build
cd build
# to use installed wolfSSL location (library and headers)
cmake .. -DWITH_WOLFSSL=/prefix/to/wolfssl/install/
# OR to use a wolfSSL source tree
cmake .. -DWITH_WOLFSSL_TREE=/path/to/wolfssl/
# build
cmake --build .
```

### vcpkg

 You can download and install wolfMQTT using the [vcpkg](https://github.com/Microsoft/vcpkg):

    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    ./bootstrap-vcpkg.sh
    OR for Windows
    bootstrap-vcpkg.bat

    ./vcpkg integrate install
    ./vcpkg install wolfmqtt

The wolfMQTT port in vcpkg is kept up to date by wolfSSL.

We also have vcpkg ports for wolftpm, wolfssl and curl.

### Arduino

See `README.md` at [IDE/ARDUINO.README.md](IDE/ARDUINO.README.md)

### MinGW

```sh
export PATH="/opt/mingw-w32-bin_i686-darwin/bin:$PATH"
export PREFIX=$PWD/build

# wolfSSL
cd wolfssl
./configure --host=i686 CC=i686-w64-mingw32-gcc LD=i686-w64-mingw32-ld CFLAGS="-DWIN32 -DMINGW -D_WIN32_WINNT=0x0600" LIBS="-lws2_32 -L$PREFIX/lib -lwolfssl" --prefix=$PREFIX
make
make install

# wolfMQTT
cd ../wolfmqtt
./configure --host=i686 CC=i686-w64-mingw32-gcc LD=i686-w64-mingw32-ld CFLAGS="-DWIN32 -DMINGW -D_WIN32_WINNT=0x0600 -DBUILDING_WOLFMQTT -I$PREFIX/include" LDFLAGS="-lws2_32 -L$PREFIX/lib -lwolfssl" --prefix=$PREFIX --disable-examples
make
```

### Zephyr RTOS

Support for Zephyr is available in the [zephyr](zephyr) directory. For instructions on how to build for Zephyr, see the [README.md](zephyr/README.md).

## Architecture

The library has three components.

### 1. mqtt_client

This is where the top level application interfaces for the MQTT client reside.

* `int MqttClient_Init(MqttClient *client, MqttNet *net, MqttMsgCb msg_cb, byte *tx_buf, int tx_buf_len, byte *rx_buf, int rx_buf_len, int cmd_timeout_ms);`

These API's are blocking on `MqttNet.read` until error/timeout (`cmd_timeout_ms`):

* `int MqttClient_Connect(MqttClient *client, MqttConnect *connect);`
* `int MqttClient_Publish(MqttClient *client, MqttPublish *publish);`
* `int MqttClient_Subscribe(MqttClient *client, MqttSubscribe *subscribe);`
* `int MqttClient_Unsubscribe(MqttClient *client, MqttUnsubscribe *unsubscribe);`
* `int MqttClient_Ping(MqttClient *client);`
* `int MqttClient_Disconnect(MqttClient *client);`

This function blocks waiting for a new publish message to arrive for a maximum duration of `timeout_ms`.

* `int MqttClient_WaitMessage(MqttClient *client, MqttMessage *message, int timeout_ms);`

These are the network connect / disconnect interfaces that wrap the MqttNet callbacks and handle WolfSSL TLS:

* `int MqttClient_NetConnect(MqttClient *client, const char* host, word16 port, int timeout_ms, int use_tls, MqttTlsCb cb);`
* `int MqttClient_NetDisconnect(MqttClient *client);`

Helper functions:

* `const char* MqttClient_ReturnCodeToString(int return_code);`

### 2. mqtt_packet

This is where all the packet encoding/decoding is handled.

The header contains the MQTT Packet structures for:

* Connect: `MqttConnect`
* Publish / Message: `MqttPublish` / `MqttMessage` (they are the same)
* Subscribe: `MqttSubscribe`
* Unsubscribe: `MqttUnsubscribe`


### 3. mqtt_socket

This is where the transport socket optionally wraps TLS and uses the `MqttNet` callbacks for the platform specific network handling.

The header contains the MQTT Network structure `MqttNet` for network callback and context.


## Implementation

Here are the steps for creating your own implementation.

1. Create network callback functions for Connect, Read, Write and Disconnect. See `examples/mqttnet.c` and `examples/mqttnet.h`.
2. Define the callback functions and context in a `MqttNet` structure.
3. Call `MqttClient_Init` passing in a `MqttClient` structure pointer, `MqttNet` structure pointer, `MqttMsgCb` function pointer, TX/RX buffers with maximum length and command timeout.
4. Call `MqttClient_NetConnect` to connect to broker over network. If `use_tls` is non-zero value then it will perform a TLS connection. The TLS callback `MqttTlsCb` should be defined for wolfSSL certificate configuration.
5. Call `MqttClient_Connect` passing pointer to `MqttConnect` structure to send MQTT connect command and wait for Connect Ack.
6. Call `MqttClient_Subscribe` passing pointer to `MqttSubscribe` structure to send MQTT Subscribe command and wait for Subscribe Ack (depending on QoS level).
7. Call `MqttClient_WaitMessage` passing pointer to `MqttMessage` to wait for incoming MQTT Publish message.


## Examples

### Client Example
The example MQTT client is located in `/examples/mqttclient/`. This example exercises many of the exposed API's and prints any incoming publish messages for subscription topic "wolfMQTT/example/testTopic". This client contains examples of many MQTTv5 features, including the property callback and server assignment of client ID. The mqqtclient example is a good starting template for your MQTT application.

### Simple Standalone Client Example
The example MQTT client is located in `/examples/mqttsimple/`. This example demonstrates a standalone client using standard BSD sockets. This requires `HAVE_SOCKET` to be defined, which comes from the ./configure generated `wolfmqtt/config.h` file. All parameters are build-time macros defined at the top of `/examples/mqttsimple/mqttsimple.c`.

### Non-Blocking Client Example
The example MQTT client is located in `/examples/nbclient/`. This example uses non-blocking I/O for message exchange. The wolfMQTT library must be configured with the `--enable-nonblock` option (or built with `WOLFMQTT_NONBLOCK`).

### Firmware Example
The MQTT firmware update is located in `/examples/firmware/`. This example has two parts. The first is called "fwpush", which signs and publishes a firmware image. The second is called "fwclient", which receives the firmware image and verifies the signature. This example publishes message on the topic "wolfMQTT/example/firmware". The "fwpush" application is an example of using a publish callback to send the payload data.

### Azure IoT Hub Example
We setup a wolfMQTT IoT Hub on the Azure server for testing. We added a device called `demoDevice`, which you can connect and publish to. The example demonstrates creation of a SasToken, which is used as the password for the MQTT connect packet. It also shows the topic names for publishing events and listening to `devicebound` messages. This example only works with `ENABLE_MQTT_TLS` set and the wolfSSL library present because it requires Base64 Encode/Decode and HMAC-SHA256. Note: The wolfSSL library must be built with `./configure --enable-base64encode` or `#define WOLFSSL_BASE64_ENCODE`. The `wc_GetTime` API was added in 3.9.1 and if not present you'll need to implement your own version of this to get current UTC seconds or update your wolfSSL library.
**NOTE** The Azure broker only supports MQTT v3.1.1

### AWS IoT Example
We setup an AWS IoT endpoint and testing device certificate for testing. The
 AWS server uses TLS client certificate for authentication. The example is located in `/examples/aws/`. The example subscribes to `$aws/things/"AWSIOT_DEVICE_ID"/shadow/update/delta` and publishes to `$aws/things/"AWSIOT_DEVICE_ID"/shadow/update`.
**NOTE** The AWS broker only supports MQTT v3.1.1

### Watson IoT Example
This example enables the wolfMQTT client to connect to the IBM Watson Internet of Things (WIOT) Platform. The WIOT Platform has a limited test broker called "Quickstart" that allows non-secure connections to exercise the component. The example is located in `/examples/wiot/`. Works with MQTT v5 support enabled.
**NOTE** The WIOT Platform will be disabled DEC2023. The demo may still be useful for users of IBM Watson IOT. 

### MQTT-SN Example
The Sensor Network client implements the MQTT-SN protocol for low-bandwidth networks. There are several differences from MQTT, including the ability to use a two byte Topic ID instead the full topic during subscribe and publish. The SN client requires an MQTT-SN gateway. The gateway acts as an intermediary between the SN clients and the broker. This client was tested with the Eclipse Paho MQTT-SN Gateway, which connects by default to the public Eclipse broker, much like our wolfMQTT Client example. The address of the gateway must be configured as the host. The example is located in `/examples/sn-client/`.

More about MQTT-SN examples in [examples/sn-client/README.md](examples/sn-client/README.md)

### Multithread Example
This example exercises the multithreading capabilities of the client library. The client implements two tasks: one that publishes to the broker; and another that waits for messages from the broker. The publish thread is created `NUM_PUB_TASKS` times (5 by default) and sends unique messages to the broker. This feature is enabled using the `--enable-mt` configuration option. The example is located in `/examples/multithread/`.

The multi-threading feature can also be used with the non-blocking socket (--enable-nonblock).

If you are having issues with thread synchronization on Linux consider using not the conditional signal (`WOLFMQTT_NO_COND_SIGNAL`).

### Atomic publish and subscribe examples
In the `examples/pub-sub` folder, there are two simple client examples:
* mqtt-pub - publishes to a topic
* mqtt-sub - subscribes to a topic and waits for messages

These examples are useful for quickly testing or scripting.

## Example Options
The command line examples can be executed with optional parameters. To see a list of the available parameters, add the `-?`

```
 ./examples/mqttclient/mqttclient -?
mqttclient:
-?          Help, print this usage
-h <host>   Host to connect to, default: test.mosquitto.org
-p <num>    Port to connect on, default: Normal 1883, TLS 8883
-t          Enable TLS
-A <file>   Load CA (validate peer)
-K <key>    Use private key (for TLS mutual auth)
-c <cert>   Use certificate (for TLS mutual auth)
-S <str>    Use Host Name Indication, blank defaults to host
-q <num>    Qos Level 0-2, default: 0
-s          Disable clean session connect flag
-k <num>    Keep alive seconds, default: 60
-i <id>     Client Id, default: WolfMQTTClient
-l          Enable LWT (Last Will and Testament)
-u <str>    Username
-w <str>    Password
-m <str>    Message, default: test
-n <str>    Topic name, default: wolfMQTT/example/testTopic
-r          Set Retain flag on publish message
-C <num>    Command Timeout, default: 30000ms
-P <num>    Max packet size the client will accept, default: 1048576
-T          Test mode
-f <file>   Use file contents for publish
```
The available options vary depending on the library configuration.


## Broker compatibility
wolfMQTT client library has been tested with the following brokers:
* Adafruit IO by Adafruit
* AWS by Amazon
* Azure by Microsoft
* flespi by Gurtam
* HiveMQ and HiveMQ Cloud by HiveMQ GmbH
* IBM WIoTP Message Gateway by IBM
* Mosquitto by Eclipse
* Paho MQTT-SN Gateway by Eclipse
* VerneMQ by VerneMQ/Erlio
* EMQX broker

## Specification Support

### MQTT v3.1.1 Specification Support

The initially supported version with full specification support for all features and packets type such as:
* QoS 0-2
* Last Will and Testament (LWT)
* Client examples for: AWS, Azure IoT, Firmware update, non-blocking and generic.

### MQTT v5.0 Specification Support

The wolfMQTT client supports connecting to v5 enabled brokers when configured with the `--enable-v5` option. 
The following v5.0 specification features are supported by the wolfMQTT client:
* AUTH packet
* User properties
* Server connect ACK properties
* Format and content type for publish
* Server disconnect
* Reason codes and strings
* Maximum packet size
* Server assigned client identifier
* Subscription ID
* Topic Alias

The v5 enabled wolfMQTT client was tested with the following MQTT v5 brokers:
* Mosquitto
** Runs locally.
** `./examples/mqttclient/mqttclient -h localhost`
* Flespi
** Requires an account tied token that is regenerated hourly.
** `./examples/mqttclient/mqttclient -h "mqtt.flespi.io" -u "<your-flespi-token>"`
* VerneMQ MQTTv5 preview
** Runs locally.
** `./examples/mqttclient/mqttclient -h localhost`
* HiveMQ 4.0.0 EAP
** Runs locally.
** `./examples/mqttclient/mqttclient -h localhost`
* HiveMQ Cloud
** `./examples/mqttclient/mqttclient -h 833f87e253304692bd2b911f0c18dba1.s1.eu.hivemq.cloud -t -S -u wolf1 -w NEZjcm7i8eRjFKF -p 8883`
* EMQX broker
** `./examples/mqttclient/mqttclient -h "broker.emqx.io"`

Properties are allocated from a local stack (size `MQTT_MAX_PROPS`) by default. Define `WOLFMQTT_DYN_PROP` to use malloc for property allocation.

### MQTT Sensor Network (MQTT-SN) Specification Support

The wolfMQTT SN Client implementation is based on the OASIS MQTT-SN v1.2 specification. The SN API is configured with the `--enable-sn` option. There is a separate API for the sensor network API, which all begin with the "SN_" prefix. The wolfMQTT SN Client operates over UDP, which is distinct from the wolfMQTT clients that use TCP. The following features are supported by the wolfMQTT SN Client:
* Register
* Will topic and message set up
* Will topic and message update
* All QoS levels
* Variable-sized packet length field

Unsupported features:
* Automatic gateway discovery is not implemented
* Multiple gateway handling

The SN client was tested using the Eclipse Paho MQTT-SN Gateway (https://github.com/eclipse/paho.mqtt-sn.embedded-c) running locally and on a separate network node. Instructions for building and running the gateway are in the project README.

## Post-Quantum MQTT Support

Recently the OpenQuantumSafe project has integrated their fork of OpenSSL with the mosquito MQTT broker. You can now build wolfMQTT with wolfSSL and use that to publish to the mosquito MQTT broker. Currently, wolfMQTT supports the `ML_KEM_768` and `P384_ML_KEM_768` groups and ML-DSA-65 for authentication in TLS 1.3. This works on Linux.

### Getting Started with Post-Quantum Mosquito MQTT Broker and Subscriber

To get started, you can use the oqs-demos repo at https://github.com/open-quantum-safe/oqs-demos/ .

Follow all the instructions in README.md and USAGE.md. This allows you to create a docker image and a docker network. Then you will run a broker, a subscriber and a publisher. At the end the publisher will exit and the broker and subscriber will remain active.

NOTE: Do not stop the broker and the subscriber instances.

You will need to get into a docker instance and get the following files onto your local machine:

- /test/cert/CA.crt
- /test/cert/publisher.crt
- /test/cert/publisher.key

Once the publisher exits, the following command can be executed:

sudo docker run --network mosquitto-test --ip 174.18.0.4 -it --rm --name oqs-mosquitto-publisher -e "BROKER_IP=174.18.0.2" -e "PUB_IP=174.18.0.4" oqs-mosquitto bash

This opens a bash shell "inside" the docker container. You'll see the shell script for executing the publisher. This includes commands for generating the keys and certificates. Execute them and then use cat to display them and then copy and paste them into the wolfMQTT root directory.

### Building and Running Post-Quantum wolfMQTT Publisher

Build and install wolfSSL like this:

```
./autogen.sh (if obtained from github)
./configure --enable-dilithium --enable-mlkem
make all
make check
```

No special flags are required for building wolfMQTT. Simply do the following:

```
./autogen.sh (if obtained from github)
./configure
make all
make check
```

NOTE: No need to install wolfmqtt.

Since the broker and subscriber are still running, you can use `mqttclient` to publish using post-quantum algorithms in TLS 1.3 by doing the following:

```
./examples/mqttclient/mqttclient -T -h 174.18.0.2 -p 8883 -t -A CA.crt -K publisher.key -c publisher.crt -m "Hello from post-quantum wolfMQTT" -n test/sensor1 -Q P384_ML_KEM_768
```

Congratulations! You have just published an MQTT message using TLS 1.3 with ML-KEM-768 hybridized with ECDHE on the P-384 curve and ML-DSA-65 signature scheme. To use only ML-KEM-768, replace `P384_ML_KEM_768` with `ML_KEM_768`. Moreover, you have also shown interoperability with liboqs, liboqs-provider, openssl3 and mosquitto.

Latest version combination tested:
    - wolfSSL: v5.8.2-stable
    - wolfMQTT: v1.20.0
    - oqs-demos: commit 29d4dccbd547a62e8ba77d3fef1af5d6f8625d60

## Curl Easy Socket Support

wolfMQTT now supports using libcurl's easy socket interface as a backend.
When enabled, wolfMQTT will use the libcurl API for the socket backend,
and libcurl will use wolfSSL to negotiate TLS.
This can be enabled with `--enable-curl`.

At this time wolfMQTT's libcurl option supports both TLS and mTLS, but not Post-Quantum TLS.

### How to use libcurl with wolfMQTT

To use wolfMQTT with libcurl and wolfSSL:
- build wolfssl with `--enable-curl` and install to `/usr/local`.
- build libcurl with `--with-wolfssl` and install to `/usr/local`.

Finally, build wolfMQTT with `--enable-curl`.

### Supported Build Options

The `--enable-curl` option works with these combinations:
- `--enable-mt`
- `--enable-nonblock`
- `--enable-tls` (default enabled)
- `--enable-timeout` (default enabled)

However `--enable-curl` is incompatible and not supported with these options:
- `--enable-all`
- `--enable-sn`

## Stress Build Option

To simplify testing a stress build option has been added, `--enable-stress=[args]`.
The Stress option enables multithreading and nonblocking, and adds defines for
`TEST_NONBLOCK`, `NUM_PUB_TASKS`, and `NUM_PUB_PER_TASK`.

Examples of usage:
- `--enable-stress`: stress with default options.
- `--enable-stress=t7,p8`: stress with 7 threads, and 8 publishes per thread.
- `--enable-stress=t7,p8 --enable-curl`: same as above, but with curl backend.

Note: When stress is enabled, the Multithread Example becomes localhost only
and will not connect to remote servers. Additionally the test `scripts/stress.test`
is added to `make check`, and all other tests are disabled.

## WebSocket Support

wolfMQTT supports MQTT over WebSockets, allowing clients to connect to MQTT brokers through WebSocket endpoints. This is useful for environments where traditional MQTT ports might be blocked or when integrating with web applications.

Both standard WebSockets and secure WebSockets (WSS) are supported.

### Building with WebSocket Support

To build wolfMQTT with WebSocket support:

1. Install the libwebsockets development library:

```
# On Debian/Ubuntu
sudo apt-get install libwebsockets-dev

# On macOS with Homebrew
brew install libwebsockets
```

2. Configure wolfMQTT with WebSocket support:

```
./configure --enable-websocket
```
   Note: You can also build wolfSSL with `--enable-opensslcoexist` (to support both OpenSSL and wolfSSL in the same build) if you encounter any conflicts.

3. Build as usual:

```
make
```

### WebSocket Example

The WebSocket client example is located in `/examples/websocket/`. This example demonstrates how to connect to an MQTT broker using WebSockets. The example subscribes to the topic "test/topic" and waits for incoming messages.

To run the example:

```
./examples/websocket/websocket_client [-h host] [-p port] [-t]
```

By default, it connects to `localhost` on port `8080`.

#### Secure WebSocket Support

wolfMQTT also supports secure WebSockets (WSS), which use TLS to encrypt the WebSocket connection.

To use secure WebSockets:

* Make sure you have built wolfMQTT with both WebSocket and TLS support:

```
./configure --enable-websocket --enable-tls
```
* Run the WebSocket example with TLS enabled:

```
./examples/websocket/websocket_client -t -p 8081
```
* You can also specify a CA certificate for TLS verification:

```
./examples/websocket/websocket_client -t -p 8081 -A /path/to/ca-cert.pem
```
* For mutual TLS authentication, you can specify client certificate and key:

```
./examples/websocket/websocket_client -t -p 8081 -A /path/to/ca-cert.pem --cert /path/to/client-cert.pem --key /path/to/client-key.pem
```

* You can also build the libwebsockets library from source with support for TLS from wolfSSL:

```
cmake .. -DLWS_WITH_WOLFSSL=1 -DLWS_WOLFSSL_INCLUDE_DIRS=/usr/local/include/wolfssl -DLWS_WOLFSSL_LIBRARIES=/usr/local/lib/libwolfssl.so -DLWS_WITH_EXTERNAL_POLL=1 -DCMAKE_BUILD_TYPE=DEBUG ..
```

   This option requires wolfSSL to be built with `./configure --enable-libwebsockets --enable-alpn` and installed to `/usr/local`.

### Broker Configuration

To use the WebSocket example, your MQTT broker must be configured to support WebSockets. For Mosquitto, add the following to your `mosquitto.conf`:

```
# WebSocket settings
listener 8080
protocol websockets
```

For Secure WebSocket Support, add:

```
# Secure WebSocket
listener 8081
protocol websockets
cafile <path-to>/ca-cert.pem
# Path to the PEM encoded server certificate.
certfile <path-to>/server-cert.pem
# Path to the PEM encoded keyfile.
keyfile <path-to>/server-key.pem
```

Then restart Mosquitto with this configuration:

```
mosquitto -c mosquitto.conf
```

There is an example mosquitto configuration file in the websocket folder:
`<wolfMQTT>$ mosquitto -c examples/websocket/mosq_ws.conf`

You can also build the mosquitto broker to use wolfSSL for the TLS connection:
https://github.com/wolfSSL/osp/tree/master/mosquitto

### Implementation Details

The WebSocket implementation uses libwebsockets as the backend and provides custom network callbacks for the MQTT client:

- `NetWebsocket_Connect`: Establishes a WebSocket connection to the broker
- `NetWebsocket_Read`: Reads data from the WebSocket connection
- `NetWebsocket_Write`: Writes data to the WebSocket connection
- `NetWebsocket_Disconnect`: Closes the WebSocket connection

The example also implements a ping mechanism to keep the WebSocket connection alive, sending a ping to the broker every 30 seconds.

### Testing with public brokers
You can test the wolfMQTT client against public brokers supporting websockets:
* Mosquitto unencrypted

    `./examples/websocket/websocket_client -h test.mosquitto.org -p8080`
 
* Mosquitto secure websocket

    `./examples/websocket/websocket_client -h test.mosquitto.org -p8081 -t`
 
* HiveMQ unencrypted

    `./examples/websocket/websocket_client -h broker.hivemq.com -p8000`

* HiveMQ secure websockets

    `./examples/websocket/websocket_client -h broker.hivemq.com -p8884 -t`
