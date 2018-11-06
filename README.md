# wolfMQTT

This is an implementation of the MQTT Client written in C for embedded use, which supports SSL/TLS via the wolfSSL library. This library was built from the ground up to be multi-platform, space conscience and extensible. Integrates with wolfSSL to provide TLS support.


## Building

### Mac/Linux/Unix/MinGW

1. `./autogen.sh` (if cloned from GitHub)
2. `./configure` (to see a list of build options use `./configure --help`)
3. `make`
4. `sudo make install`

If `wolfssl` was recently installed run `sudo ldconfig` to update the linker cache.
 
### Windows Visual Studio

For building wolfMQTT with TLS support in Visual Studio:

1. Open the `wolfssl-root>/wolfssl64.sln`.
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

### Arduino

See `README.md` at [IDE/ARDUINO.README.md](IDE/ARDUINO.README.md)


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
The example MQTT client is located in `/examples/mqttclient/`. This example exercises many of the exposed API’s and prints any incoming publish messages for subscription topic “wolfMQTT/example/testTopic”. This client contains examples of many MQTTv5 features, including the property callback and server assignment of client ID. The mqqtclient example is a good starting template for your MQTT application.

### Non-Blocking Client Example
The example MQTT client is located in `/examples/nbclient/`. This example uses non-blocking I/O for message exchange. The wolfMQTT library must be configured with the `--enable-nonblock` option (or built with `WOLFMQTT_NONBLOCK`).

### Firmware Example
The MQTT firmware update is located in `/examples/firmware/`. This example has two parts. The first is called “fwpush”, which signs and publishes a firmware image. The second is called “fwclient”, which receives the firmware image and verifies the signature. This example publishes message on the topic “wolfMQTT/example/firmware”. The "fwpush" application is an example of using a publish callback to send the payload data. 

### Azure IoT Hub Example
We setup a wolfMQTT IoT Hub on the Azure server for testing. We added a device called `demoDevice`, which you can connect and publish to. The example demonstrates creation of a SasToken, which is used as the password for the MQTT connect packet. It also shows the topic names for publishing events and listening to `devicebound` messages. This example only works with `ENABLE_MQTT_TLS` set and the wolfSSL library present because it requires Base64 Encode/Decode and HMAC-SHA256. Note: The wolfSSL library must be built with `./configure --enable-base64encode` or `#define WOLFSSL_BASE64_ENCODE`. The `wc_GetTime` API was added in 3.9.1 and if not present you'll need to implement your own version of this to get current UTC seconds or update your wolfSSL library.

### AWS IoT Example
We setup an AWS IoT endpoint and testing device certificate for testing. The AWS server uses TLS client certificate for authentication. The example is located in `/examples/aws/`. The example subscribes to `$aws/things/"AWSIOT_DEVICE_ID"/shadow/update/delta` and publishes to `$aws/things/"AWSIOT_DEVICE_ID"/shadow/update`.

### Watson IoT Example
This example enables the wolfMQTT client to connect to the IBM Watson Internet of Things (WIOT) Platform. The WIOT Platform has a limited test broker called "Quickstart" that allows non-secure connections to exercise the component. The example is located in `/examples/wiot/`. Works with MQTT v5 support enabled. 

### MQTT-SN Example
The Sensor Network client implements the MQTT-SN protocol for low-bandwidth networks. There are several differences from MQTT, including the ability to use a two byte Topic ID instead the full topic during subscribe and publish. The SN client requires an MQTT-SN gateway. The gateway acts as an intermediary between the SN clients and the broker. This client was tested with the Eclipse Paho MQTT-SN Gateway, which connects by default to the public Eclipse broker, much like our wolfMQTT Client example. The address of the gateway must be configured as the host. The example is located in `/examples/sn-client/`.


## Specification Support

### MQTT v3.1.1 Specification Support

The initially supported version with full specification support for all features and packets type such as:
* QoS 0-2
* Last Will and Testament (LWT)
* Client examples for: AWS, Azure IoT, IBM Watson, Firmware update, non-blocking and generic.

### MQTT v5.0 Specification Support

The wolfMQTT client supports connecting to v5 enabled brokers when configured with the `--enable-mqtt5` option. Handling properties received from the server is accomplished via a callback when the `--enable-propcb` option is set. The following v5.0 specification features are supported by the wolfMQTT client:
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
* Flespi
** Requires an account tied token that is regenerated hourly.
** `./examples/mqttclient/mqttclient -h "mqtt.flespi.io" -u "<your-flespi-token>"`
* VerneMQ MQTTv5 preview
** Runs locally.
** `./examples/mqttclient/mqttclient -h localhost`
* HiveMQ 4.0.0 EAP
** Runs locally.
** `./examples/mqttclient/mqttclient -h localhost`
* Watson IoT Quickserver
** `./examples/wiot/wiot`

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


## Release Notes

### v1.2 (11/07/18)

* Added MQTT Sensor Network (SN) client support (`--enable-sn` or `WOLFMQTT_SN`). (PR #96)
* Added MQTT v5.0 support with (`--enable-mqtt5` or `WOLFMQTT_V5`). (PR #87)
* Added property callback support (MQTT v5.0 only). Enabled with `--enable-propcb` or `WOLFMQTT_PROPERTY_CB`). (PR #87)
* Fix for Harmony NetConnect function incorrectly checking `EWOULDBLOCK`. Fixes issue #88. (PR #89)
* Fix to reset the TLS ctx and ssl pointers when they have been free'd. (PR #85)
* Add way to pass custom context to the wolfMQTT TLS verify callback example `mqtt_tls_verify_cb`. PR #94)
* Create nonblocking mqttclient example `./examples/nbclient/nbclient`. (PR #93)
* Add support for publishing in smaller chunks using new API `MqttClient_Publish_ex`. (PR #92)
* Added simplified Microchip Harmony wolfMQTT network callback example. (PR #83)

### v1.1 (06/21/18)
* Fixed case when `use_tls` was requested but TLS feature not compiled in. (PR #57)
* Fixed non-blocking issue that caused out of buffer error if not all of packet were received. (PR #65)
* Fixed non-blocking mode issue that was sending multiple connect requests for examples. (PR #65)
* Fixed non-blocking issue with ping keep alive in examples. (PR #68)
* Fixed the Arduino example with `ENABLE_MQTT_TLS` defined (PR #78)
* Added support for FreeRTOS TCP in wolfMQTT. (PR #58)
* Added `README.md` section for building wolfMQTT. (PR #63)
* Added new option to enable verbose logging `./configure --enable-debug=verbose`. (PR #65)
* Added support for disconnect callback using `WOLFMQTT_DISCONNECT_CB` or `./configure --enable-discb`. (PR #69)
* Added `WOLFMQTT_LOCAL` to internal API's for hidden visibility. (PR #73)
* Added include for `wolfmqtt/options.h`. (PR #79)
* Added IBM Watson IoT example (see `./examples/wiot/wiot`). (PR #80)
* Updated the autoconf M4 files and added generation of `./configure` options to `wolfmqtt/options.h`. (PR #71)
* Improved the message callback to support a custom context per message. (PR #62)
* Improved the non-blocking unsubscribe handling in mqttclient example for timeout. (PR #65)

### v1.0 (04/03/18)
* Fixed `MqttClient_WaitMessage` to use provided `timeout_ms` arg. With TLS enabled it was using the `MqttClient_Init` `cmd_timeout_ms` arg. Thanks PeterL for that report.
* Fixed cast warnings when building with Visual Studio.
* Cleanup socket code to use existing `SOCK_CLOSE` for `NetDisconnect`.
* Cleanup to move the `sockRc` into the `MqttTls` struct, since it only applies when TLS is enabled.
* Added configure option to disable error strings for reduced code size (`./configure disable-errorstrings` or `#define WOLFMQTT_NO_ERROR_STRINGS`).
* Added support for ChibiOS.

### v0.14 (11/22/17)
* Fixed non-blocking connect to check for `EINPROGRESS` for all platforms (not just Harmony).
* Fixed buffer overflow position check on read/write.
* Fixed typo on internal packet function `MqttDecode_ConnectAck`.
* Fixed the socket close for Harmony to use `closesocket`.
* Fixed non-blocking connect where `WOLFMQTT_NO_STDIO` is defined.
* Fixed GCC 7's new fall-through check.
* Added check for EAGAIN in non-blocking mode (was only EWOULDBLOCK).
* Added non-blocking support for write operations when `WOLFMQTT_NONBLOCK` is defined.
* Added support for DH and setting the default minimum key bits.
* Added support for keep-alive ping when using non-blocking mode.
* Improvements to example TLS callback handling of return code failures.
* Improvements and fixes to Visual Studio projects.
* Enhancement to adjust wolfSSL options.h include based on `WOLFSSL_USER_SETTINGS`.

### v0.13 (05/10/17)
* Fixed issue with `msg->stat` in non-blocking.
* Fixed Arduino library build.
* Fixed examples with non-blocking (--enable-nonblock).
* Enhancement to pass network callback return codes through context when using TLS.
* Added option to disable the blocking timeouts for `select()` using `--disable-timeout` (or `WOLFMQTT_NO_TIMEOUT`).
* Added option to disable STDIN/fgets capture for examples using `--disable-stdincap` (or `WOLFMQTT_NO_STDIN_CAP`)
* Refactor to use new `MQTT_CODE_STDIN_WAKE` return code for examples using STDIN to send publish messages (normal blocking mode only).

### v0.12 (12/20/16)
* Fixes issue with read timeout in non-blocking mode with TLS enabled being teated as socket error.
* Fixed issue with “msg->stat” not getting reset on failure or timeout.
* Fix to not link libwolfssl with ./configure --disable-tls.
* Added AWS IoT Example and test script.

### v0.11 (11/28/16)
* Fix for building MQTT client example without the wolfSSL headers present.
* Fix for Microchip Harmony IP check so it works with non 192 subnets.

### v0.10 (09/26/16)
* Enabled big endian support.
* Fixes for building with Visual Studio.

### v0.9 (08/22/16)
* Added Microchip Harmony support (see new readme in `IDE/Microchip-Harmony/README.md`).
* Added non-blocking mode `--enable-nonblock` or `WOLFMQTT_NONBLOCK`, which uses new `MQTT_CODE_CONTINUE` response code.
* Added `scripts/azureiothub.test`.
* Added `./commit-tests.sh` for testing all configurations.
* Added git pre-commit hook to run `commit-tests.sh`.
* Combined duplicate code in the examples into `examples/mqttexample.c`.
* Examples now use `MQTTCtx` structure as argument for tracking info/state.

### v0.8 (06/13/16)
* Fixed stdin capture bug and improved signal (ctrl+c) handling.
* Added Azure IoT hub MQTT client example.
* Added support for MQX / RTCS.
* Added "--disable-tls" and "--disable-examples" configure options.
* Added comment about max packet size.
* Added example for how to load a client certificate to mqttclient example.
* Added return code for firmware and azure examples that are not compiled in due to older / incompatible version of wolfSSL.
* Moved the support for custom printf/line endings into the mqtt_types.h for use throughout the project.
* Updated README.md with information about the examples.

### v0.6 (03/18/2016)
* Fixes to support MinGW compiler.
* Fixed bug with include of the wolfSSL include of options.h.
* Fix to properly handle negative return code from wc_SignatureGetSize.
* Added Arduino IDE example in `IDE/ARDUINO`. See `IDE/ARDUINOREADME.md` for details.
* Added example UART interface for wolfMQTT. See `examples/mqttuart.c`.
* Added the ability to pass additional arguments to the scripts. Example: `./scripts/client.test "-h localhost"`

### v0.5 (01/27/2016)
* Fixed build error when using older wolfSSL in firmware examples.
* Updated the get error string function in `mqtt_socket.c` from `wc_GetErrorString` to `wolfSSL_ERR_reason_error_string` so both wolfSSL and wolfCrypt error codes are resolved.
* Added `-n <str>` option so a custom topic name can be used.
* The mqttclient example now listens to stdin and will send a publish message with the data entered on the console when end-of-line (return) is detected (Linux only).
* Added keep-alive ping to the mqttclient and fwclient examples.
* Moved the TLS callback prior to the `client->tls.ctx` creation, allowing the callback function to implement its own client method cert verification.
* Enhanced `MqttClient_WaitMessage` so it will return if we get a message, not just on timeout
* Added make check/test scripts (scripts/client.test and scripts/firmware.test) to validate client TLS (with and without) plus QoS 0-2 levels and the firmware update example.
* Adjusted the example include paths for more flexibility.
* Added new `-T` option for using examples to test.
* Added new `-C` option to allow custom command timeout.
* Combined duplicate example code into new header `mqttexample.h`.
* Added a PRINTF helper macro to the examples for easier porting.
* Added better error trapping in examples so return code is populated for testing.
* Changed the example test functions to return int.

### v0.4 (12/30/2015)
* Fixed bug with subscribe not populating acknowledgment return code(s) properly.
* Fixed build error if using wolfSSL 3.7.1 or older due to missing signature.c/.h wrappers. This fix disables the firmware examples if the wolfSSL version isn't greater than 3.7.1.
* Fix to ensure `topic_name` pointer is reset when publish callback message is not new `msg_new = 0`.
* Fixes to suppress possible warning "Value stored to [] is never read".
* Fixed firmware example to trap case where file isn't found.
* Fixed possible ./autogen.sh error with missing "config.rpath".
* Fixed Windows issue with SetConsoleCtrlHandler incorrectly reporting error.
* Fixed issue with Visual Studio 2015 wolfssl.lib reference.
* Fixed build errors with G++ (./configure CC=g++).
* Fixed "FirmwareHeader" to use WOLFMQTT_PACK macro.
* Added helper macro's and comments for topic names/filters.
* Added TLS certification verification reference implementation to examples.
* Updated the topic names in examples to use "wolfMQTT/example/".
* Added QoS level to example console output.
* Added memset to initialize some of the example stack variables.
* Removed the LWT from the firmware examples.
* Added retain flag "-r" option on the "fwpush" example.
* Updated the examples to use macros for all memory and string functions, so they are more portable.
* Added Visual Studio projects for "fwpush" and "fwclient".

### v0.3 (11/18/2015)
* Fixes bug with first byte of payload being null'd if QoS level was 0.
* Fixed issue with stdint types (uint#_t) being used.
* Fixes for remaining length encoding/decoding for large packets.
* Added support for large payloads using new message callback flags `msg_done` and `msg_new` along with MqttMessage `buffer_pos` and `buffer_len`.
* Added example for secure firmware upgrade. Uses the MQTT client library to push a signed payload `fwpush` to a broker, then uses another client `fwclient` to receive the signed payload and verify its signature using a provided public key.

### v0.2 (11/06/2015)
* Fixes to handle receival of publish and QoS messages while performing packet writes/waits.
* Added support / tested with Windows.
* Added Visual Studio 2015 solution and projects.
* Added support / tested with FreeRTOS and Lwip.
* Fixes for compiler warnings.

### v0.1 (10/26/15)
* Initial release with support for MQTT v3.1.1, QoS 0-2, TLS and example client.
