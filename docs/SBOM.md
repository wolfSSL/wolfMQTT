# wolfMQTT SBOM

wolfMQTT writes a CycloneDX 1.6 file and an SPDX 2.3 file. The generator is the wolfssl-compliance-tooling snapshot in `tools/sbom/`. The pin is `tools/sbom/.wolfssl-compliance-tooling-rev`. Do not edit those files. To update the pin, run `wolfssl-compliance-tooling-sync` from a checkout of that repository:

    tools/wolfssl-compliance-tooling-sync --dest /path/to/wolfMQTT --prune

The SBOM records the build options and hashes `libwolfmqtt` when the build produces that library. When TLS is enabled, the SBOM names wolfSSL as a dependency. The licence expression is `GPL-3.0-or-later`. That matches the per-file headers. A commercial Autotools build sets `SBOM_LICENSE_OVERRIDE` before `make sbom`. A commercial CMake build sets `-DWOLFMQTT_SBOM_LICENSE=LicenseRef-wolfSSL-Commercial` and `LICENSE_TEXT` is required for a `LicenseRef-*` expression. Pass `-DWOLFMQTT_SBOM_LICENSE_TEXT=/path/to/licence.txt` in that case.

You need `python3` and `pyspdxtools` (`pip install spdx-tools`).

## Library builds

These two builds hash the installed library. They read `wolfmqtt/options.h`.

Autotools, including a MinGW cross build. The macro capture uses the host compiler `cc`, so the cross compiler does not change the option list. The library hash still names the binary you built.

    ./configure
    make sbom

Pass `WOLFSSL_DIR=/path/to/wolfssl` when pkg-config cannot see the wolfSSL that this build linked.

CMake, including the Visual Studio and Ninja generators:

    cmake -B build
    cmake --build build --target sbom
    DESTDIR="$PWD/stage" cmake --build build --target install-sbom

Outputs:

- `wolfmqtt-<version>.cdx.json`
- `wolfmqtt-<version>.spdx.json`
- `wolfmqtt-<version>.spdx` (tag-value)

## Other builds

These builds do not install `libwolfmqtt` through Autotools or the top-level CMake target. `scripts/sbom-port.sh` calls the same generator.

| Build | Compiler | Command |
|---|---|---|
| Zephyr | Zephyr SDK gcc | `scripts/sbom-port.sh zephyr --compdb <west-build>/compile_commands.json` |
| ESP-IDF | ESP-IDF gcc (Xtensa or RISC-V) | `scripts/sbom-port.sh compdb <build>/compile_commands.json` |
| QNX | `qcc` | `scripts/sbom-port.sh compdb <build>/compile_commands.json` |
| Microchip Harmony | XC32 | `scripts/sbom-port.sh compdb <build>/compile_commands.json` |
| STM32Cube | the Cube toolchain | `scripts/sbom-port.sh compdb <build>/compile_commands.json` |
| Visual Studio `.sln` | MSVC | `scripts/sbom-port.sh visual-studio` |
| Arduino | the board compiler | `scripts/sbom-port.sh arduino --options-h <build>/wolfmqtt/options.h` |

Zephyr adds the wolfMQTT sources to the application (`target_sources(app ...)`). The script passes `--target app`. Enable `CMAKE_EXPORT_COMPILE_COMMANDS` in the west build. When the compile command names a wolfMQTT settings header (`-include`, `-imacros`, or `user_settings.h` on a `-I` path), the script passes `--user-settings` and `--hostcc cc`. The frontend records the macros that header and the `-D` flags add on top of `autoconf.h`. When the command has no settings header, the script copies the `-D` macros into a header and passes `--options-h`. Pass `--user-settings` yourself when the header is included only from a C file. `--dep-wolfssl` is `yes` when those macros define `ENABLE_MQTT_TLS`.

ESP-IDF, QNX, Harmony, and STM32Cube: produce `compile_commands.json` from the IDE build (CMake export, or `bear -- make`). The script keeps the wolfMQTT library sources. When a compile command names `user_settings.h` or `wolfSSL.I-CUBE-wolfMQTT_conf.h`, the script passes `--settings-h` and `--include-dir` so the host compiler expands that header. `--dep-wolfssl` follows `ENABLE_MQTT_TLS`.

The Visual Studio script preprocesses `wolfmqtt/vs_settings.h` with the host compiler and `-D_WIN32`. `HAVE_CONFIG_H` stays unset, so `WOLFMQTT_PROPERTY_CB` under `#ifdef WOLFMQTT_V5` is recorded. The script lists the five sources in `wolfmqtt.vcxproj` because that project file does not produce a library this host can hash. A CMake Visual Studio build uses `cmake --build build --target sbom` and hashes the library.

The Arduino script requires `--options-h`. Pass the `wolfmqtt/options.h` from the Arduino build. `wolfmqtt/options.h.in` is the empty Autotools template. The script records every `src/*.c` file that `IDE/ARDUINO/wolfmqtt-arduino.sh` copies. `--dep-wolfssl` follows `ENABLE_MQTT_TLS` in the header you pass. Wrap a real Arduino build with a compilation database and use the `compdb` mode when you need the board's macros.

Add `--cdx-out` and `--spdx-out` to choose the output paths. The default is the current directory.
