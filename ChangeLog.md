
## Release Notes

### v1.8 (02/19/2021)
* Fixes for non-blocking in WIN32 and large payload (PR #202)
* Make TLS IO callback functions public (PR #201)
* Bug fixes (PR #186, 188, 189, 193, 196, 199, 200)
* Update default test broker (PR #194)
* MQTT-SN fixes for multithread and register topic name (PR #185, 190)
* Fix multi-thread to use pthread mutex with condition (PR #183)
* Fix for WIN thread create macro (PR #182)
* Use options.h with Arduino build (PR #181)
* Use MqttClient_Ping_ex instead of MqttClient_Ping in examples (PR #179)
* Fixes for building with MinGW (PR #178)
* MQTT-SN support for multithread (PR #176)
* TLS mutual auth in client examples (PR #175)
* MQTT-SN feature enhancements (PR #173)
* Add runtime message option to client (PR #171)

### v1.7 (08/21/2020)

* Fix for publish with short topic name and example. (PR #169)
Add MqttProps_ShutDown(). Fix MqttProp leaks(PR #167)
* Multithread fixes. (PR #166)
* Fix buffer overrun in strcpy(). Fix logic around getaddrinfo(). (PR #165)
* Fix MqttClient_WaitType for nonblock mode. (PR #164)
* Change anon union for ARMv6 error. (PR #163)
* Fix for publish large payload. (PR #162)
* Fixing LWT prop and allow null LWT. (PR #161)
* Fix for receive timeout in mqttsimple example. (PR #158)

### v1.6 (04/24/2020)

* Fixes to improve buffer size checking when using a small tx or rx buffer. (PR #137)
* Fix for MQTT v5 issue with using wrong property free. (PR #152)
* Refactor of the thread locking to use binary semaphore, which resolves issue with thread synchronization. (PR #146)
* Improved multi-thread example exit (ctrl+c). Use internal pipe to wake "select()" and use semaphore signal to "wake" ping thread. (PR #146)
* Adjust multi-threading use case to use separate thread for ping keep-alive. (PR #146)
* Added simple standalone MQTT client example. (PR #138)
* Added include for "user_settings.h" when `WOLFMQTT_USER_SETTINGS` is defined. (PR #138)
* Added broker compatibility list (PR #145)
* Added protocol version API's. (PR #152)
* Added multithread example for Windows and Visual Studio. (PR #146)
* Made protocol level a run time option (PR #147)
* Remove obsolete "sched_yield" call. (PR #146)
* Remove deprecated call to `wolfSSL_set_using_nonblock()` (PR #148)
* Sync automake fixes from wolfSSL to wolfMQTT. (PR #150)
* Moved `MAX_PACKET_ID` to library. (PR #138)

### v1.4 (12/27/19)

* Fixes for non-blocking and multi-threading edge cases. (PR #130)
    - Improved logic for processing objects from different threads.
    - Improved network connect/read to handle runtime option for block/non-block.
    - Improved examples to support adding random hex string to client_id and topic name when "-T" option is used.
    - Fix for test scripts to check non-zero return code.
    - Enabled the mqttclient, multithread and wiot examples when non-blocking is enabled.
    - Added encode debug log messages when `WOLFMQTT_DEBUG_CLIENT` is defined.
    - Added thread logging when `WOLFMQTT_DEBUG_THREAD` is defined with multi-threading support enabled.
* Fixes for Visual Studio project (PR #122)
    - Improvements to catch use of socket file descriptor before its been created/opened.
    - Improved handling for Windows socket want write.
    - Added library references to wolfSSL project.
    - Adjusted include to have IDE/WIN for user_settings.h.
* Fixes for Visual Studio conversion warning (PR #128)
* Fix visibility warnings in Cygwin (PR #127)
* Fix global declaration conflicts for CentOS (PR #133)
* Fix Microchip Harmony for `mqtt_socket.c` with non-blocking and `errno.h`  (PR #135)
* Fix to not return from `MqttClient_WaitMessage` if response from another thread (PR #129)
* Refactor of the multi-threading code to better handle edge case and state for non-blocking (PR #126)
    - Fixes for multi-thread handling of ack's when processing.
    - Refactor to use `stat` from own struct, not shared `msg->stat`.
    - Eliminated use of `client->msg` except for `MqttClient_WaitMessage`.
    - Fixes to restore "state" after performing MqttClient operation.
    - Refactor of publish read and write payload.
    - Improvements to multithread example.
    - Refactor of the SN code to support new object type and unique state for future multi-thread support.
    - Added build option `TEST_NONBLOCK` to force testing non-blocking edge cases.
    - Fix for fwpush getting stuck in stop loop on Ctrl+c exit.
* Update Azure login and default broker (PR #131)

### v1.3 (08/01/19)

* Fix `fwpush` example to use filename option `-f`. (PR #117)
* Added multiple thread support using `--enable-mt` or `WOLFMQTT_MULTITHREAD`. (PR #115)
* Fix for `MQTT_DATA_TYPE_BINARY` data length encoded twice. (PR #112)
* Fix to clear local structures for subscribe and unsubscribe ACK's. (PR #112)
* Fix for `SN_Encode_Unsubscribe` using wrong data type for topic name ID. (PR #110)
* Add `WOLFSSL_USER_SETTINGS` to VS project files. (PR #109)
* Fixes for using RTCS in `mqttnet.c` socket example code. (PR #108)
* Fix MQTT-SN decode publish parsing and QoS2 response. (PR #107)
* Make MqttSocket_TlsSocket callbacks public. (PR #104)
* Improved the disconnect network error callback example. (PR #102)
* Add MQTT context information to socket callback examples. (PR #101)
* Initialize subscribe state to `MQTT_MSG_BEGIN`. (PR #99)
* Fix for Harmony possible circular include issue. (PR #98)

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
