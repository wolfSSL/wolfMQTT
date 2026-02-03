#!/usr/bin/env bash
set -euo pipefail

HOST="localhost"
PORT="1883"
USER=""
PASS=""
NUM_CLIENTS="2"
READY_TIMEOUT="30"
RUN_SECS="5"
KEEP_LOGS="${KEEP_LOGS:-0}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUB_BIN="${ROOT_DIR}/examples/pub-sub/mqtt-pub"
SUB_BIN="${ROOT_DIR}/examples/pub-sub/mqtt-sub"

usage() {
  cat <<EOF
Usage: $(basename "$0") [-h host] [-p port] [-u user] [-w pass]
                        [-n num_clients] [-t ready_timeout] [-R run_secs]

Runs clients in pairs. Each pair (P0, P1, P2, ...) has two clients:
  pair P client A: subscribes to "pair/P/a", publishes to "pair/P/b"
  pair P client B: subscribes to "pair/P/b", publishes to "pair/P/a"

Each subscriber verifies it received the message from its partner.

Options:
  -h host            Broker host (default: localhost)
  -p port            Broker port (default: 1883)
  -u user            Username for auth
  -w pass            Password for auth
  -n num_clients     Total number of clients, must be even (default: 2)
  -t ready_timeout   Max seconds to wait for subscribers to be ready (default: 30)
  -R run_secs        Seconds to wait after publish for delivery (default: 5)

Environment:
  KEEP_LOGS=1        Preserve log directory after exit

Examples:
  $(basename "$0") -n 2          # 1 pair, 2 clients
  $(basename "$0") -n 100        # 50 pairs, 100 clients
  $(basename "$0") -n 200 -R 10  # 100 pairs, longer delivery wait
EOF
}

while getopts "h:p:u:w:n:t:R:?" opt; do
  case "${opt}" in
    h) HOST="${OPTARG}" ;;
    p) PORT="${OPTARG}" ;;
    u) USER="${OPTARG}" ;;
    w) PASS="${OPTARG}" ;;
    n) NUM_CLIENTS="${OPTARG}" ;;
    t) READY_TIMEOUT="${OPTARG}" ;;
    R) RUN_SECS="${OPTARG}" ;;
    ?) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

# Validate num_clients is even and >= 2
if (( NUM_CLIENTS < 2 || NUM_CLIENTS % 2 != 0 )); then
  echo "error: -n must be an even number >= 2 (got ${NUM_CLIENTS})"
  exit 1
fi

NUM_PAIRS=$(( NUM_CLIENTS / 2 ))

if [[ ! -x "${PUB_BIN}" || ! -x "${SUB_BIN}" ]]; then
  echo "error: mqtt-pub or mqtt-sub not found. Build examples first."
  exit 1
fi

TMP_DIR="$(mktemp -d)"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [[ "${KEEP_LOGS}" == "1" ]]; then
    echo "Logs preserved in ${TMP_DIR}"
  else
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

auth_args=()
if [[ -n "${USER}" ]]; then auth_args+=(-u "${USER}"); fi
if [[ -n "${PASS}" ]]; then auth_args+=(-w "${PASS}"); fi

# All subscriber log files (for readiness polling)
SUB_LOGS=()

start_sub() {
  local client_id="$1"
  local topic="$2"
  local log="$3"
  # -T = test mode (disables STDIN capture so background processes work)
  # -d = debug output (needed to detect readiness via log polling)
  # -i = unique client ID
  # stdbuf -oL = line-buffered stdout so grep can detect readiness in logs
  stdbuf -oL "${SUB_BIN}" -T -h "${HOST}" -p "${PORT}" -i "${client_id}" \
    -n "${topic}" -q 0 -d "${auth_args[@]}" >"${log}" 2>&1 &
  PIDS+=("$!")
  SUB_LOGS+=("${log}")
}

run_pub() {
  local client_id="$1"
  local topic="$2"
  local msg="$3"
  # -T = test mode (disables STDIN capture)
  # -i = unique client ID
  "${PUB_BIN}" -T -h "${HOST}" -p "${PORT}" -i "${client_id}" -n "${topic}" \
    -m "${msg}" -q 0 "${auth_args[@]}" >/dev/null 2>&1
}

# Wait until all subscriber logs contain the ready marker
wait_for_subscribers() {
  local total="${#SUB_LOGS[@]}"
  local elapsed=0
  while (( elapsed < READY_TIMEOUT )); do
    local ready_count=0
    for log in "${SUB_LOGS[@]}"; do
      if grep -q "MQTT Waiting for message" "${log}" 2>/dev/null; then
        (( ready_count++ )) || true
      fi
    done
    if (( ready_count == total )); then
      echo "All ${total} subscriber(s) ready after ${elapsed}s"
      return 0
    fi
    if (( elapsed > 0 && elapsed % 5 == 0 )); then
      echo "  ... ${ready_count}/${total} subscribers ready (${elapsed}s elapsed)"
    fi
    sleep 1
    (( elapsed++ )) || true
  done
  echo "WARNING: Not all subscribers ready after ${READY_TIMEOUT}s (continuing anyway)"
  return 0
}

echo "Starting ${NUM_CLIENTS} clients (${NUM_PAIRS} pairs)..."

# --- Start all subscribers ---
for p in $(seq 0 $(( NUM_PAIRS - 1 ))); do
  start_sub "sub_${p}_a" "pair/${p}/a" "${TMP_DIR}/sub_${p}_a.log"
  start_sub "sub_${p}_b" "pair/${p}/b" "${TMP_DIR}/sub_${p}_b.log"
done

echo "Waiting for subscribers to connect and subscribe..."
wait_for_subscribers

# --- Publish: each client publishes to its partner's topic ---
echo "Publishing ${NUM_CLIENTS} messages..."
for p in $(seq 0 $(( NUM_PAIRS - 1 ))); do
  # Client A publishes to pair/P/b (B's topic)
  run_pub "pub_${p}_a" "pair/${p}/b" "hello_from_${p}_a"
  # Client B publishes to pair/P/a (A's topic)
  run_pub "pub_${p}_b" "pair/${p}/a" "hello_from_${p}_b"
done

# --- Wait for message delivery ---
echo "Waiting ${RUN_SECS}s for message delivery..."
sleep "${RUN_SECS}"

# --- Check results ---
PASS_COUNT=0
FAIL_COUNT=0

check_result() {
  local description="$1"
  local pattern="$2"
  local log="$3"
  if grep -q "${pattern}" "${log}" 2>/dev/null; then
    (( PASS_COUNT++ )) || true
  else
    echo "FAIL: ${description}"
    (( FAIL_COUNT++ )) || true
  fi
}

echo ""
echo "== Results =="
for p in $(seq 0 $(( NUM_PAIRS - 1 ))); do
  # A subscribed to pair/P/a, should have received hello_from_P_b
  check_result "pair ${p} A (sub pair/${p}/a) did not receive hello_from_${p}_b" \
    "hello_from_${p}_b" "${TMP_DIR}/sub_${p}_a.log"
  # B subscribed to pair/P/b, should have received hello_from_P_a
  check_result "pair ${p} B (sub pair/${p}/b) did not receive hello_from_${p}_a" \
    "hello_from_${p}_a" "${TMP_DIR}/sub_${p}_b.log"
done

echo "${PASS_COUNT} passed, ${FAIL_COUNT} failed (${NUM_CLIENTS} clients, ${NUM_PAIRS} pairs)"

if (( FAIL_COUNT > 0 )); then
  # Preserve logs on failure regardless of KEEP_LOGS setting
  KEEP_LOGS=1
  exit 1
fi
exit 0
