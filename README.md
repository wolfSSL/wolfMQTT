# wolfMQTT

This is an implementation of the MQTT Client written in C for embedded use, which supports SSL/TLS via the wolfSSL library. This library was built from the ground up to be multi-platform, space conscience and extensible. Integrates with wolfSSL to provide TLS support.

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
The example MQTT client is located in /examples/mqttclient/. This example exercises all exposed API’s and prints any incoming publish messages for subscription topic “wolfMQTT/example/testTopic”.

### Firmware Example
The MQTT firmware update  is located in /examples/firmware/. This example has two parts. The first is called “fwpush”, which publishes a signed firmware image. The second is called “fwclient”, which receives the firmware image and verifies the signature. This example publishes message on the topic “wolfMQTT/example/firmware”.

### Azure IoT Hub Example
We setup a wolfMQTT IoT Hub on the Azure server for testing. We added a device called `demoDevice`, which you can connect and publish to. The example demonstrates creation of a SasToken, which is used as the password for the MQTT connect packet. It also shows the topic names for publishing events and listening to `devicebound` messages. This example only works with `ENABLE_MQTT_TLS` set and the wolfSSL library present because it requires Base64 Encode/Decode and HMAC-SHA256. Note: The wolfSSL library must be built with `./configure --enable-base64encode` or `#define WOLFSSL_BASE64_ENCODE`. The `wc_GetTime` API was added in 3.9.1 and if not present you'll need to implement your own version of this to get current UTC seconds or update your wolfSSL library.

## Release Notes

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
