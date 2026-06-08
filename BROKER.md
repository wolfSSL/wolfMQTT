# wolfMQTT Broker

wolfMQTT includes a lightweight MQTT broker suitable for embedded and resource-constrained environments. It serves both MQTT v3.1.1 and v5.0 clients, with optional TLS via wolfSSL, optional WebSocket transport, and optional encrypted persistence. The broker uses non-blocking sockets driven by a single `select()` loop, so it runs without threads.

## Features

* QoS 0, QoS 1, and QoS 2 publish/subscribe (full QoS 2 flow with PUBREC/PUBREL/PUBCOMP)
* Retained messages
* Last Will and Testament (LWT), including v5 Will Delay Interval
* Wildcard subscriptions (`+` and `#`)
* Username/password authentication
* MQTT v5 ordering and Receive Maximum (per-subscriber inflight shaping)
* TLS support (requires wolfSSL with `--enable-tls`)
* WebSocket / secure WebSocket transport (requires libwebsockets; see the WebSocket section of the main [README.md](README.md))
* Clean session handling with subscription persistence
* Keep-alive monitoring with automatic client disconnect
* Unique client ID enforcement (existing session takeover)
* Optional on-disk persistence of sessions, subscriptions, retained messages, and offline queues, with optional AES-GCM encryption-at-rest
* Static memory mode (`WOLFMQTT_STATIC_MEMORY`) for zero-malloc operation

## Quick start

With autotools:

```sh
./configure --enable-broker
make
./src/mqtt_broker -p 1883
```

With CMake:

```sh
cmake .. -DWOLFMQTT_BROKER=yes
cmake --build .
```

For TLS:

```sh
./configure --enable-broker --enable-tls
make
./src/mqtt_broker -p 8883 -t -A ca-cert.pem -K server-key.pem -c server-cert.pem
```

Run `./src/mqtt_broker -h` to see the options compiled into your build.

## Command-line options

```
usage: mqtt_broker [-p port] [-v level] [-u user] [-P pass]
                   [-t] [-s port] [-V ver] [-c cert] [-K key] [-A ca]
                   [-w port] [-D dir] [-E source]
```

| Option | Available when | Description |
|---|---|---|
| `-p <port>` | always | Plain (non-TLS) port (default: 1883) |
| `-v <level>` | always | Log level: 1=error, 2=info (default), 3=debug |
| `-u <user>` | auth build | Username for authentication |
| `-P <pass>` | auth build | Password for authentication |
| `-t` | TLS build | Enable the TLS listener |
| `-s <port>` | TLS build | TLS port (default: 8883) |
| `-V <ver>` | TLS build | TLS version: 12=TLS 1.2, 13=TLS 1.3 (default: auto) |
| `-c <file>` | TLS build | Server certificate file (PEM) |
| `-K <file>` | TLS build | Server private key file (PEM) |
| `-A <file>` | TLS build | CA certificate for mutual TLS (PEM) |
| `-w <port>` | WebSocket build | WebSocket listen port (enables WebSocket) |
| `-D <dir>` | persist build | Persistent storage directory (enables persistence; default `/var/lib/wolfmqtt`) |
| `-E <source>` | encrypt + dev-key build | Encryption key source. Only `dev` is recognized, selecting the development hard-coded key. NOT FOR PRODUCTION. |

## Build options

All broker features are enabled by default and can be disabled at build time to reduce code and memory footprint on constrained platforms.

| Feature | Autotools | CMake | Define |
|---|---|---|---|
| Broker support | `--enable-broker` | `-DWOLFMQTT_BROKER=yes` | `WOLFMQTT_BROKER` |
| Retained messages | `--disable-broker-retained` | `-DWOLFMQTT_BROKER_RETAINED=no` | `WOLFMQTT_BROKER_NO_RETAINED` |
| Last Will and Testament | `--disable-broker-will` | `-DWOLFMQTT_BROKER_WILL=no` | `WOLFMQTT_BROKER_NO_WILL` |
| Wildcard subscriptions | `--disable-broker-wildcards` | `-DWOLFMQTT_BROKER_WILDCARDS=no` | `WOLFMQTT_BROKER_NO_WILDCARDS` |
| Authentication | `--disable-broker-auth` | `-DWOLFMQTT_BROKER_AUTH=no` | `WOLFMQTT_BROKER_NO_AUTH` |
| Logging | `--disable-broker-log` | `-DWOLFMQTT_BROKER_LOG=no` | `WOLFMQTT_BROKER_NO_LOG` |
| Plain-text listener | `--disable-broker-insecure` | `-DWOLFMQTT_BROKER_INSECURE=no` | `WOLFMQTT_BROKER_NO_INSECURE` |

The maximum QoS the broker negotiates is capped by `--enable-max-qos=<0,1,2>` (default 2). Setting it to 1 or 0 compiles out the QoS 2 state machine and shrinks the broker.

## Static memory tuning

When built with `WOLFMQTT_STATIC_MEMORY`, the broker uses fixed-size arrays instead of dynamic allocation. The limits below can be overridden via CFLAGS at build time.

| Macro | Default | Description |
|---|---|---|
| `BROKER_MAX_CLIENTS` | 8 | Maximum concurrent client connections |
| `BROKER_MAX_SUBS` | 32 | Maximum total subscriptions across all clients |
| `BROKER_MAX_RETAINED` | 16 | Maximum retained messages |
| `BROKER_MAX_CLIENT_ID_LEN` | 64 | Maximum client ID length |
| `BROKER_MAX_USERNAME_LEN` | 64 | Maximum username length |
| `BROKER_MAX_PASSWORD_LEN` | 64 | Maximum password length |
| `BROKER_MAX_FILTER_LEN` | 128 | Maximum subscription filter length |
| `BROKER_MAX_TOPIC_LEN` | 128 | Maximum topic name length |
| `BROKER_MAX_PAYLOAD_LEN` | 4096 | Maximum retained message payload |
| `BROKER_MAX_WILL_PAYLOAD_LEN` | 256 | Maximum LWT payload |
| `BROKER_MAX_PENDING_WILLS` | 4 | Maximum queued pending wills |
| `BROKER_MAX_INBOUND_QOS2` | 16 | Concurrent inbound QoS 2 packet IDs per client |
| `BROKER_RX_BUF_SZ` | 4096 | Per-client receive buffer size |
| `BROKER_TX_BUF_SZ` | 4096 | Per-client transmit buffer size |
| `BROKER_TIMEOUT_MS` | 1000 | `select()` timeout |
| `BROKER_LISTEN_BACKLOG` | 128 | Listen queue depth |

With dynamic memory the per-subscriber inflight window is derived at runtime, bounded by `BROKER_MIN_INFLIGHT_PER_SUB` (default 8) and `BROKER_MAX_INFLIGHT_PER_SUB`. Define `BROKER_MAX_INFLIGHT_PER_SUB=1` to force strict serial delivery (one inflight QoS 1/2 message per subscriber).

## Persistence

Build with `--enable-broker-persist` to persist sessions, subscriptions, retained messages, and offline queues across restarts. The persistence layer is hook-based: a default POSIX backend stores records as files under the directory given with `-D` (default `/var/lib/wolfmqtt`). Embedded targets can supply their own storage backend through `MqttBroker_SetPersistHooks()`.

| Macro | Default | Description |
|---|---|---|
| `BROKER_MAX_PERSIST_SESSIONS` | 64 | Persistent sessions retained across restarts |
| `BROKER_MAX_OFFLINE_MSGS_PER_SUB` | 32 | Offline queue depth per session |
| `WOLFMQTT_BROKER_PERSIST_SCHEMA_VER` | 3 | On-disk record schema version |

### Encryption at rest

Add `--enable-broker-persist-encrypt` (requires `--enable-broker-persist`) to wrap persisted records with wolfCrypt AES-GCM. The key is provided by a `derive_key` callback that real deployments install via `MqttBroker_SetPersistHooks()` before starting the broker.

For development and CI only, the CLI can link a fixed-pattern `derive_key` hook so the AES-GCM round-trip can be exercised without external key management. This is NOT a configure option -- define the macro through CFLAGS:

```sh
CFLAGS="-DWOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY" \
  ./configure --enable-broker --enable-broker-persist --enable-broker-persist-encrypt
make
./src/mqtt_broker -p 1883 -D ./state -E dev
```

The dev key is a trivially-recoverable hard-coded pattern. Never define `WOLFMQTT_BROKER_PERSIST_ENCRYPT_DEV_KEY` in a production build, and never pass `-E dev` in production -- doing so substitutes the fixed key for real key management. Production builds omit the macro entirely, so the `-E` option and the dev hook are not present in the binary.

## Testing

The repository ships an end-to-end broker test harness:

```sh
./scripts/broker.test
```

It builds the client examples (`examples/pub-sub/mqtt-pub`, `examples/pub-sub/mqtt-sub`) and `mosquitto`-based checks against the wolfMQTT broker, covering QoS flows, retained messages, wildcards, persistence round-trips, and AES-GCM encryption (when the dev-key hook is linked). Tests that depend on features not present in the current build are reported as `SKIP`.

The CONNECT-handler unit test (`tests/test_broker_connect`) is part of `make check` and exercises the broker packet path with a mock network layer.

## Limitations

The wolfMQTT broker targets embedded and edge use cases. It is intentionally smaller in scope than full-featured server brokers such as Mosquitto or EMQX: there is no clustering, no bridging, no plugin/ACL framework, and no dynamic configuration reload. For large-scale or feature-rich deployments use a dedicated server broker; for a small, auditable, optionally-TLS broker that runs without threads or a heap, wolfMQTT is a good fit.
