Zephyr Project Port
===================

## Overview

This port is for the Zephyr RTOS Project, available [here](https://www.zephyrproject.org/).


It provides the following zephyr code.

- modules/lib/wolfmqtt
    - wolfMQTT library code
- modules/lib/wolfmqtt/zephyr/
    - Configuration and CMake files for wolfMQTT as a Zephyr module
- modules/lib/wolfmqtt/zephyr/samples/client
    - wolfMQTT client test application
- modules/lib/wolfmqtt/zephyr/samples/client_tls
    - wolfMQTT client test application over TLS

## How to setup as a Zephyr Module

Follow the [instructions](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) to setup a zephyr project.

### Modify your project's west manifest

Add wolfMQTT as a project to your west.yml:

```
manifest:
  remotes:
    # <your other remotes>
    - name: wolfmqtt
      url-base: https://github.com/wolfssl

  projects:
    # <your other projects>
    - name: wolfmqtt
      path: modules/lib/wolfmqtt
      revision: master
      remote: wolfmqtt
```

Update west's modules:

```bash
west update
```

Now west recognizes 'wolfmqtt' as a module, and will include it's Kconfig and
CMakeFiles.txt in the build system.

## Build and Run Samples

Follow the [instructions](https://docs.zephyrproject.org/latest/connectivity/networking/qemu_setup.html) to setup the infratructure to enable networking in QEMU. Run the following commands in parallel in this order in the `net-tools` directory to allow comunication between the QEMU instance and the host. Make sure to disable any software that modifies the local network like VPN's.

```bash
./loop-socat.sh
sudo ./loop-slip-tap.sh
```

Run the following commands in parallel in this order in the `zephyrproject` directory to setup a MQTT broker and subscriber.

```bash
cd modules/lib/wolfmqtt && mosquitto -c scripts/broker_test/mosquitto.conf
mosquitto_sub -t sensors
```

### Build and Run client Test Application

build and execute `client`

```bash
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolfmqtt/zephyr/samples/client
west build -t run
```

### Build and Run client TLS Test Application

build and execute `client TLS`

```bash
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolfmqtt/zephyr/samples/client_tls
west build -t run
```

### Debugging using QEMU

To attach a debugger to the QEMU instance run:

```bash
west build -t debugserver_qemu
```

And attach gdb with:

```bash
$ gdb path/to/zephyr.elf
(gdb) target remote localhost:1234
```
