#!/bin/sh
# SBOM for a wolfMQTT build that is not the Autotools or top-level CMake
# library target. Those two builds use `make sbom` and
# `cmake --build <dir> --target sbom`.
#
# Usage:
#   scripts/sbom-port.sh zephyr --compdb <west-build>/compile_commands.json
#   scripts/sbom-port.sh compdb --compdb <build>/compile_commands.json
#   scripts/sbom-port.sh visual-studio
#   scripts/sbom-port.sh arduino
#
# compdb is the route for ESP-IDF, QNX, Microchip Harmony, and STM32Cube.
# Pass extra frontend flags after the mode. --cdx-out and --spdx-out
# override the default file names in the current directory.

set -e

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MODE=${1:-}
if [ -n "$MODE" ]; then
    shift
fi

DRIVER="$ROOT/tools/sbom/sbom-driver"
ZEPHYR="$ROOT/tools/sbom/frontends/zephyr_sbom.py"
COMPDB="$ROOT/tools/sbom/frontends/compdb_sbom.py"
VERSION_FILE="$ROOT/wolfmqtt/version.h"
LICENSE="$ROOT/LICENSE"

usage() {
    echo "Usage: $0 zephyr|compdb|visual-studio|arduino [frontend flags]" >&2
    exit 1
}

need_file() {
    if [ ! -f "$1" ]; then
        echo "ERROR: $1 is missing. Vendor tools/sbom from wolfssl-compliance-tooling." >&2
        exit 1
    fi
}

need_file "$DRIVER"

case "$MODE" in
zephyr)
    need_file "$ZEPHYR"
    # The Zephyr module compiles its sources into the application
    # (target_sources(app ...)). The frontend selects that target.
    # The caller passes --compdb <west-build>/compile_commands.json.
    #
    # zephyr_sbom.py records a source inventory unless the caller passes
    # --user-settings or --options-h. wolfMQTT's Zephyr config is the -D
    # set on those compile commands (WOLFMQTT_ZEPHYR, and the Kconfig
    # macros). Copy that set into a flat header so the SBOM records it.
    cfg=no
    for a in "$@"; do
        case "$a" in
            --options-h|--user-settings|--options-h=*|--user-settings=*)
                cfg=yes
                ;;
        esac
    done
    optfile=""
    if [ "$cfg" = no ]; then
        optfile=$(mktemp)
        set +e
        python3 - "$ZEPHYR" "$ROOT" "$optfile" "$@" <<'PY'
import importlib.util
import sys

zephyr_path, root, optfile, *args = sys.argv[1:]
compdb = None
it = iter(args)
for arg in it:
    if arg == "--compdb":
        compdb = next(it, None)
    elif arg.startswith("--compdb="):
        compdb = arg.split("=", 1)[1]
if not compdb:
    sys.exit(2)
spec = importlib.util.spec_from_file_location("zephyr_sbom", zephyr_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
entries, _outside = mod.compdb_entries(
    compdb, root, mod.module_name(root), "app")
lines = ["/* wolfMQTT Zephyr macros from the compile commands */", ""]
flags = mod._defines(entries)
i = 0
while i < len(flags):
    if flags[i] == "-D" and i + 1 < len(flags):
        token = flags[i + 1]
        name, sep, val = token.partition("=")
        if not sep:
            val = "1"
        lines.append("#undef %s" % name)
        lines.append("#define %s %s" % (name, val))
        lines.append("")
        i += 2
    else:
        i += 1
with open(optfile, "w", encoding="utf-8") as out:
    out.write("\n".join(lines) + "\n")
PY
        rc=$?
        set -e
        if [ "$rc" -eq 2 ]; then
            rm -f "$optfile"
            optfile=""
        elif [ "$rc" -ne 0 ]; then
            rm -f "$optfile"
            exit "$rc"
        fi
    fi
    if [ -n "$optfile" ]; then
        set -- --options-h "$optfile" "$@"
    fi
    python3 "$ZEPHYR" \
        --root "$ROOT" \
        --target app \
        --name wolfmqtt \
        --version-file "$VERSION_FILE" \
        --version-macro LIBWOLFMQTT_VERSION_STRING \
        --license-file "$LICENSE" \
        --license-override GPL-3.0-or-later \
        --supplier "wolfSSL Inc." \
        --dep-wolfssl yes \
        "$@"
    status=$?
    if [ -n "$optfile" ]; then
        rm -f "$optfile"
    fi
    exit "$status"
    ;;
compdb)
    need_file "$COMPDB"
    # Keep the wolfMQTT library sources. Drop examples and the application.
    python3 "$COMPDB" \
        --name wolfmqtt \
        --version-file "$VERSION_FILE" \
        --version-macro LIBWOLFMQTT_VERSION_STRING \
        --license-file "$LICENSE" \
        --license-override GPL-3.0-or-later \
        --supplier "wolfSSL Inc." \
        --root "$ROOT" \
        --include 'src/mqtt_(client|packet|socket|sn_client|sn_packet)\.c$' \
        --dep-wolfssl yes \
        "$@"
    ;;
visual-studio)
    need_file "$DRIVER"
    srcs=$(mktemp)
    trap 'rm -f "$srcs"' EXIT INT TERM HUP
    cat > "$srcs" <<EOF
$ROOT/src/mqtt_client.c
$ROOT/src/mqtt_packet.c
$ROOT/src/mqtt_socket.c
$ROOT/src/mqtt_sn_client.c
$ROOT/src/mqtt_sn_packet.c
EOF
    # The .sln build reads wolfmqtt/vs_settings.h. There is no installed
    # library on a host that does not run MSVC, so record the source set.
    "$DRIVER" \
        --name wolfmqtt \
        --version-file "$VERSION_FILE" \
        --version-macro LIBWOLFMQTT_VERSION_STRING \
        --license-file "$LICENSE" \
        --license-override GPL-3.0-or-later \
        --supplier "wolfSSL Inc." \
        --root "$ROOT" \
        --options-h "$ROOT/wolfmqtt/vs_settings.h" \
        --srcs-file "$srcs" \
        --dep-wolfssl yes \
        "$@"
    ;;
arduino)
    need_file "$DRIVER"
    srcs=$(mktemp)
    trap 'rm -f "$srcs"' EXIT INT TERM HUP
    # IDE/ARDUINO/wolfmqtt-arduino.sh copies every src/*.c and ships
    # wolfmqtt/options.h.in as the untouched option header.
    find "$ROOT/src" -name '*.c' | sort > "$srcs"
    "$DRIVER" \
        --name wolfmqtt \
        --version-file "$VERSION_FILE" \
        --version-macro LIBWOLFMQTT_VERSION_STRING \
        --license-file "$LICENSE" \
        --license-override GPL-3.0-or-later \
        --supplier "wolfSSL Inc." \
        --root "$ROOT" \
        --options-h "$ROOT/wolfmqtt/options.h.in" \
        --srcs-file "$srcs" \
        "$@"
    ;;
*)
    usage
    ;;
esac
