#!/bin/bash
# fuzz.sh - Build and run the wolfMQTT broker fuzzer
#
# Usage: ./scripts/fuzz.sh [seconds]
#   seconds: fuzz duration (default: 60)
#
# Requires: clang with libFuzzer support

set -e

FUZZ_TIME=${1:-60}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"

# Check for clang
if ! command -v clang >/dev/null 2>&1; then
    echo "Error: clang is required for fuzzing (libFuzzer)" >&2
    exit 1
fi

# Generate configure if needed
if [ ! -f ./configure ]; then
    ./autogen.sh
fi

# Configure with fuzzer and address sanitizer
CC=clang ./configure --enable-broker --enable-v5 --enable-fuzz \
    --disable-tls --disable-examples \
    CFLAGS="-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g -O1" \
    LDFLAGS="-fsanitize=address"

make -j$(nproc)

# Generate seed corpus
python3 tests/fuzz/gen_corpus.py

# Run fuzzer
echo "Fuzzing for ${FUZZ_TIME} seconds..."
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:symbolize=1"

timeout "$FUZZ_TIME" \
    ./tests/fuzz/broker_fuzz \
        tests/fuzz/corpus/ \
        -dict=tests/fuzz/mqtt.dict \
        -max_len=4096 \
        -timeout=10 \
        -rss_limit_mb=2048 \
        -print_final_stats=1 \
    || FUZZ_RC=$?

# timeout returns 124 on normal expiry, fuzzer returns 0 on no crash
if [ "${FUZZ_RC:-0}" -eq 124 ] || [ "${FUZZ_RC:-0}" -eq 0 ]; then
    echo "Fuzzer completed without crashes"
else
    echo "Fuzzer found crashes (exit code $FUZZ_RC)"
    ls -la crash-* 2>/dev/null || true
    exit 1
fi
