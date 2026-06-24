# Building wolfMQTT on Linux / macOS

## Autotools (primary build system)

From a git checkout (not a release tarball), generate the configure script first:

```bash
./autogen.sh    # requires autoconf, automake, libtool
```

Then build and test:

```bash
./configure
make
make check      # runs all tests — do this before submitting any PR
sudo make install
make sbom WOLFSSL_DIR=/path/to/wolfssl   # generate SBOM for EU CRA compliance
```

### Common configure flags

| Flag | Purpose |
|------|---------|
| `--enable-all` | Enable all features (use for broad testing; incompatible with `--enable-curl` and `--enable-stress`) |
| `--enable-tls` | TLS support via wolfSSL (default: enabled) |
| `--disable-tls` | Disable TLS for testing without wolfSSL |
| `--enable-v5` | MQTT v5.0 support |
| `--enable-sn` | MQTT-SN (Sensor Network) support |
| `--enable-nonblock` | Non-blocking I/O support |
| `--enable-mt` | Multi-threading support |
| `--enable-websocket` | WebSocket support (requires libwebsockets) |
| `--enable-curl` | libcurl backend support |
| `--enable-broker` | Lightweight embedded broker |
| `--enable-stress` | Stress testing (e.g. `--enable-stress=t7,p8` for 7 threads, 8 publishers) |
| `--enable-debug` | Debug mode (`--enable-debug=verbose` or `--enable-debug=trace`) |

The full list is in `./configure --help`.

### TLS configuration

By default, wolfMQTT looks for a system-installed wolfSSL. To point at a specific installation or source tree:

```bash
# Installed wolfSSL
./configure --with-wolfssl=/path/to/wolfssl/install

# wolfSSL source tree (for development)
./configure --with-wolfssl-tree=/path/to/wolfssl
```

Build wolfSSL first with at least `./configure --enable-all && make && sudo make install` or the feature set your application needs.

## CMake (secondary)

```bash
mkdir build && cd build

# Use installed wolfSSL
cmake .. -DWITH_WOLFSSL=/path/to/wolfssl/install

# Use wolfSSL source tree
cmake .. -DWITH_WOLFSSL_TREE=/path/to/wolfssl

cmake --build .
```

Primary development and CI use autotools. CMake support is available but autotools is the source of truth for feature configuration.

## Running Tests

```bash
make check    # full test suite
```

Most tests require a local mosquitto broker. The CI uses `bubblewrap` for network isolation. `broker.test` is self-contained (no external broker needed).

To skip external broker tests:

```bash
WOLFMQTT_NO_EXTERNAL_BROKER_TESTS=1 ./configure --enable-all
make check
```

### Individual test scripts

```bash
./scripts/client.test         # Main MQTT client tests (QoS 0-2, TLS)
./scripts/nbclient.test       # Non-blocking client tests
./scripts/multithread.test    # Multi-threading tests
./scripts/firmware.test       # Firmware update tests
./scripts/broker.test         # Broker tests (no external broker needed)
./scripts/stress.test         # Stress testing (requires --enable-stress)
```

Test certificates are in `certs/` (RSA and ECC variants). Broker test config: `scripts/broker_test/mosquitto.conf`.

## Running Examples

```bash
./examples/mqttclient/mqttclient -?                    # Show help with available options
./examples/mqttclient/mqttclient -h localhost -p 1883  # Connect to local broker
./examples/mqttclient/mqttclient -h localhost -t -p 8883  # TLS connection
```
