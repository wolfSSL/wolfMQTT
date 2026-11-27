#!/bin/sh
# SBOM for a wolfMQTT build that is not the Autotools or top-level CMake
# library target. Those two builds use `make sbom` and
# `cmake --build <dir> --target sbom`.
#
# Usage:
#   scripts/sbom-port.sh zephyr --compdb <west-build>/compile_commands.json
#   scripts/sbom-port.sh compdb <build>/compile_commands.json
#   scripts/sbom-port.sh visual-studio
#   scripts/sbom-port.sh arduino --options-h <build>/wolfmqtt/options.h
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

# Read ENABLE_MQTT_TLS from a flat header. A generated options.h is already
# expanded, so a literal #define is the configured value.
header_enables_tls() {
    grep -E -q '^[[:space:]]*#define[[:space:]]+ENABLE_MQTT_TLS([[:space:]]|$)' "$1"
}

case "$MODE" in
zephyr)
    need_file "$ZEPHYR"
    # The Zephyr module compiles its sources into the application
    # (target_sources(app ...)). The frontend selects that target.
    # The caller passes --compdb <west-build>/compile_commands.json.
    #
    # zephyr_sbom.py records a source inventory until it receives
    # --user-settings or --options-h. When the compile command names a
    # wolfMQTT settings header, pass --user-settings so the host compiler
    # expands that header together with the -D flags. Otherwise copy the
    # -D macros into a flat header.
    state=$(mktemp)
    optfile=""
    set +e
    python3 - "$ZEPHYR" "$ROOT" "$state" "$@" <<'PY'
import importlib.util
import os
import sys

zephyr_path, root, state, *args = sys.argv[1:]
compdb = None
caller_cfg = False
caller_header = ""
it = iter(args)
for arg in it:
    if arg in ("--options-h", "--user-settings"):
        caller_cfg = True
        caller_header = next(it, "") or ""
    elif arg.startswith("--options-h=") or arg.startswith("--user-settings="):
        caller_cfg = True
        caller_header = arg.split("=", 1)[1]
    elif arg == "--compdb":
        compdb = next(it, None)
    elif arg.startswith("--compdb="):
        compdb = arg.split("=", 1)[1]

def write(mode, path, dep):
    with open(state, "w", encoding="utf-8") as out:
        out.write("%s\n%s\n%s\n" % (mode, path, dep))

if not compdb:
    write("missing", "", "no")
    sys.exit(2)

spec = importlib.util.spec_from_file_location("zephyr_sbom", zephyr_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
entries, _outside = mod.compdb_entries(
    compdb, root, mod.module_name(root), "app")
flags = mod._defines(entries)

def tls_from_flags(tokens):
    on = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-D", "-U") and i + 1 < len(tokens):
            name = tokens[i + 1].split("=", 1)[0]
            if name == "ENABLE_MQTT_TLS":
                on = tok == "-D"
            i += 2
            continue
        if tok.startswith("-D") and tok[2:].split("=", 1)[0] == "ENABLE_MQTT_TLS":
            on = True
        elif tok == "-UENABLE_MQTT_TLS":
            on = False
        i += 1
    return on

def resolve(directory, path):
    if os.path.isabs(path):
        return path
    return os.path.join(directory or root, path)

def mqtt_settings(path):
    base = os.path.basename(path)
    if base == "wolfSSL.I-CUBE-wolfMQTT_conf.h":
        return True
    if base != "user_settings.h":
        return False
    if "mqtt" in path.lower():
        return True
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return False
    return "WOLFMQTT" in text or "ENABLE_MQTT" in text

settings = ""
if not caller_cfg:
    for _src, entry in entries:
        directory = entry.get("directory") or root
        for opt, arg in mod._options(entry):
            if opt in ("-include", "-imacros") and arg:
                path = resolve(directory, arg)
                if os.path.isfile(path) and mqtt_settings(path):
                    settings = os.path.abspath(path)
                    break
        if settings:
            break
    if not settings:
        seen = set()
        for _src, entry in entries:
            directory = entry.get("directory") or root
            for opt, arg in mod._options(entry):
                if opt != "-I" or not arg:
                    continue
                inc = resolve(directory, arg)
                if inc in seen or inc.startswith(("/usr", "/Library", "/Applications")):
                    continue
                seen.add(inc)
                for base in ("user_settings.h", "wolfSSL.I-CUBE-wolfMQTT_conf.h"):
                    path = os.path.join(inc, base)
                    if os.path.isfile(path) and mqtt_settings(path):
                        settings = os.path.abspath(path)
                        break
                if settings:
                    break
            if settings:
                break

dep = "yes" if tls_from_flags(flags) else "no"
tls_header = caller_header or settings
if tls_header and dep == "no":
    try:
        text = open(tls_header, encoding="utf-8", errors="replace").read()
    except OSError:
        text = ""
    for line in text.splitlines():
        parts = line.split("/*", 1)[0].strip().split()
        if len(parts) >= 2 and parts[0] == "#define" and parts[1] == "ENABLE_MQTT_TLS":
            dep = "yes"
            break

if caller_cfg:
    write("caller", "", dep)
elif settings:
    write("user", settings, dep)
else:
    lines = ["/* wolfMQTT Zephyr macros from the compile commands */", ""]
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
    optfile = state + ".h"
    with open(optfile, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
    write("options", optfile, dep)
PY
    rc=$?
    set -e
    if [ "$rc" -eq 2 ]; then
        rm -f "$state" "$state.h"
    elif [ "$rc" -ne 0 ]; then
        rm -f "$state" "$state.h"
        exit "$rc"
    else
        mode=$(sed -n '1p' "$state")
        path=$(sed -n '2p' "$state")
        dep=$(sed -n '3p' "$state")
        rm -f "$state"
        if [ "$mode" = options ]; then
            optfile=$path
            set -- --options-h "$optfile" "$@"
        elif [ "$mode" = user ]; then
            set -- --user-settings "$path" --hostcc cc "$@"
        fi
        set -- --dep-wolfssl "$dep" "$@"
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
    # When the compile command names a wolfMQTT settings header, pass
    # --settings-h so the host compiler expands the macros that header
    # derives. --dep-wolfssl follows ENABLE_MQTT_TLS.
    state=$(mktemp)
    python3 - "$state" "$ROOT" "$@" <<'PY'
import json
import os
import shlex
import sys

state, root, *args = sys.argv[1:]

def write(dep, settings):
    with open(state, "w", encoding="utf-8") as out:
        out.write("%s\n%s\n" % (dep, settings))

def has_flag(name):
    for arg in args:
        if arg == name or arg.startswith(name + "="):
            return True
    return False

compdb = None
i = 0
while i < len(args):
    arg = args[i]
    if arg == "--compdb" and i + 1 < len(args):
        compdb = args[i + 1]
        break
    if arg.startswith("--compdb="):
        compdb = arg.split("=", 1)[1]
        break
    if arg.startswith("--"):
        i += 2 if "=" not in arg else 1
        continue
    compdb = arg
    break

if has_flag("--dep-wolfssl"):
    dep = "keep"
else:
    dep = "no"
settings = ""
if not compdb or not os.path.isfile(compdb) or has_flag("--options-h") or has_flag("--settings-h"):
    write(dep, "")
    sys.exit(0)

def mqtt_settings(path):
    base = os.path.basename(path)
    if base == "wolfSSL.I-CUBE-wolfMQTT_conf.h":
        return True
    if base != "user_settings.h":
        return False
    if "mqtt" in path.lower():
        return True
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return False
    return "WOLFMQTT" in text or "ENABLE_MQTT" in text

db = json.load(open(compdb, encoding="utf-8"))
tls = False
seen = set()
for entry in db:
    directory = entry.get("directory") or root
    if entry.get("arguments"):
        tokens = entry["arguments"]
    else:
        tokens = shlex.split(entry.get("command") or "")
    i = 0
    includes = []
    while i < len(tokens):
        tok = tokens[i]
        arg = None
        if tok in ("-I", "-include", "-imacros", "-D", "-U") and i + 1 < len(tokens):
            arg = tokens[i + 1]
            i += 2
        else:
            if tok.startswith("-I") and tok != "-I":
                arg = tok[2:]
                tok = "-I"
            elif tok.startswith("-D"):
                arg = tok[2:]
                tok = "-D"
            elif tok == "-UENABLE_MQTT_TLS":
                tls = False
            i += 1
        if tok == "-D" and arg is not None and arg.split("=", 1)[0] == "ENABLE_MQTT_TLS":
            tls = True
        elif tok == "-U" and arg == "ENABLE_MQTT_TLS":
            tls = False
        elif tok == "-I" and arg:
            inc = arg if os.path.isabs(arg) else os.path.join(directory, arg)
            includes.append(inc)
        elif tok in ("-include", "-imacros") and arg and not settings:
            path = arg if os.path.isabs(arg) else os.path.join(directory, arg)
            if os.path.isfile(path) and mqtt_settings(path):
                settings = os.path.abspath(path)
    if settings:
        continue
    for inc in includes:
        if inc in seen or inc.startswith(("/usr", "/Library", "/Applications")):
            continue
        seen.add(inc)
        for base in ("user_settings.h", "wolfSSL.I-CUBE-wolfMQTT_conf.h"):
            path = os.path.join(inc, base)
            if os.path.isfile(path) and mqtt_settings(path):
                settings = os.path.abspath(path)
                break
        if settings:
            break

if dep != "keep":
    dep = "yes" if tls else "no"
    if settings and dep == "no":
        try:
            text = open(settings, encoding="utf-8", errors="replace").read()
        except OSError:
            text = ""
        for line in text.splitlines():
            parts = line.split("/*", 1)[0].strip().split()
            if len(parts) >= 2 and parts[0] == "#define" and parts[1] == "ENABLE_MQTT_TLS":
                dep = "yes"
                break
write(dep, settings)
PY
    dep=$(sed -n '1p' "$state")
    settings=$(sed -n '2p' "$state")
    rm -f "$state"
    if [ -n "$settings" ]; then
        set -- --settings-h "$settings" \
            --include-dir "$(dirname "$settings")" \
            --include-dir "$ROOT" \
            "$@"
    fi
    if [ "$dep" != keep ]; then
        set -- --dep-wolfssl "$dep" "$@"
    fi
    python3 "$COMPDB" \
        --name wolfmqtt \
        --version-file "$VERSION_FILE" \
        --version-macro LIBWOLFMQTT_VERSION_STRING \
        --license-file "$LICENSE" \
        --license-override GPL-3.0-or-later \
        --supplier "wolfSSL Inc." \
        --root "$ROOT" \
        --include 'src/mqtt_(client|packet|socket|sn_client|sn_packet)\.c$' \
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
    # Preprocess wolfmqtt/vs_settings.h with the host compiler. -D_WIN32
    # selects the template. HAVE_CONFIG_H stays unset, so the template body
    # is visible. WOLFMQTT_PROPERTY_CB sits inside #ifdef WOLFMQTT_V5 and
    # is recorded only after the preprocessor runs.
    dep=no
    if cc -D_WIN32 -dM -E -I"$ROOT" -include "$ROOT/wolfmqtt/vs_settings.h" \
            -x c /dev/null | grep -q '^#define ENABLE_MQTT_TLS'; then
        dep=yes
    fi
    "$DRIVER" \
        --name wolfmqtt \
        --version-file "$VERSION_FILE" \
        --version-macro LIBWOLFMQTT_VERSION_STRING \
        --license-file "$LICENSE" \
        --license-override GPL-3.0-or-later \
        --supplier "wolfSSL Inc." \
        --root "$ROOT" \
        --cflags="-D_WIN32" \
        --settings-h "$ROOT/wolfmqtt/vs_settings.h" \
        --include-dir "$ROOT" \
        --srcs-file "$srcs" \
        --dep-wolfssl "$dep" \
        "$@"
    ;;
arduino)
    need_file "$DRIVER"
    # The Arduino build writes wolfmqtt/options.h. options.h.in is the empty
    # Autotools template, so the caller passes the generated header.
    options_h=""
    prev=""
    for a in "$@"; do
        if [ "$prev" = "--options-h" ]; then
            options_h=$a
        fi
        case "$a" in
            --options-h=*)
                options_h=${a#--options-h=}
                ;;
        esac
        prev=$a
    done
    if [ -z "$options_h" ] || [ ! -f "$options_h" ]; then
        echo "ERROR: arduino mode requires --options-h PATH." >&2
        echo "PATH is the wolfmqtt/options.h produced by the Arduino build." >&2
        exit 2
    fi
    dep=no
    if header_enables_tls "$options_h"; then
        dep=yes
    fi
    srcs=$(mktemp)
    trap 'rm -f "$srcs"' EXIT INT TERM HUP
    find "$ROOT/src" -name '*.c' | sort > "$srcs"
    "$DRIVER" \
        --name wolfmqtt \
        --version-file "$VERSION_FILE" \
        --version-macro LIBWOLFMQTT_VERSION_STRING \
        --license-file "$LICENSE" \
        --license-override GPL-3.0-or-later \
        --supplier "wolfSSL Inc." \
        --root "$ROOT" \
        --srcs-file "$srcs" \
        --dep-wolfssl "$dep" \
        "$@"
    ;;
*)
    usage
    ;;
esac
