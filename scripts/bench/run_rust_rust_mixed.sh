#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="${CERT_DIR:-"${ROOT_DIR}/fixtures/certs"}"
RUN_DIR="${ROOT_DIR}/.interop/bench-rust-rust-mixed-$(date +%Y%m%d_%H%M%S)"

DNS_LISTEN_PORT="${DNS_LISTEN_PORT:-8853}"
PROXY_RECURSIVE_PORT="${PROXY_RECURSIVE_PORT:-5300}"
PROXY_AUTHORITATIVE_PORT="${PROXY_AUTHORITATIVE_PORT:-5301}"
USE_PROXY="${USE_PROXY:-0}"
RECURSIVE_ADDR="${RECURSIVE_ADDR:-}"
AUTHORITATIVE_ADDR="${AUTHORITATIVE_ADDR:-}"
TCP_TARGET_PORT="${TCP_TARGET_PORT:-5201}"
CLIENT_TCP_PORT="${CLIENT_TCP_PORT:-7000}"
DOMAIN="${DOMAIN:-test.com}"
TRANSFER_BYTES="${TRANSFER_BYTES:-10485760}"
CHUNK_SIZE="${CHUNK_SIZE:-16384}"
PREFACE_BYTES="${PREFACE_BYTES:-1}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-10}"
DEBUG_WAIT_SECS="${DEBUG_WAIT_SECS:-2}"
DEBUG_LOG_WAIT_SECS="${DEBUG_LOG_WAIT_SECS:-5}"
CLIENT_ARGS="${CLIENT_ARGS:-}"
RUN_EXFIL="${RUN_EXFIL:-1}"
RUN_DOWNLOAD="${RUN_DOWNLOAD:-1}"
THROUGHPUT_COMPARE="${THROUGHPUT_COMPARE:-1}"
THROUGHPUT_MIN_RATIO="${THROUGHPUT_MIN_RATIO:-}" # Minimum mixed/best-single ratio.
MIN_AVG_MIB_S="${MIN_AVG_MIB_S:-}"
MIN_AVG_MIB_S_EXFIL="${MIN_AVG_MIB_S_EXFIL:-5}"
MIN_AVG_MIB_S_DOWNLOAD="${MIN_AVG_MIB_S_DOWNLOAD:-25}"

if [[ -n "${MIN_AVG_MIB_S}" ]]; then
  MIN_AVG_MIB_S_EXFIL="${MIN_AVG_MIB_S}"
  MIN_AVG_MIB_S_DOWNLOAD="${MIN_AVG_MIB_S}"
fi

if [[ ! -f "${CERT_DIR}/cert.pem" || ! -f "${CERT_DIR}/key.pem" ]]; then
  echo "Missing test certs in ${CERT_DIR}. Set CERT_DIR to override." >&2
  exit 1
fi

mkdir -p "${RUN_DIR}" "${ROOT_DIR}/.interop"

cleanup_pids() {
  for pid in "${CLIENT_PID:-}" "${TARGET_PID:-}" "${PROXY_RECURSIVE_PID:-}" "${PROXY_AUTHORITATIVE_PID:-}" "${SERVER_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}

cleanup() {
  cleanup_pids
}
trap cleanup EXIT INT TERM HUP

cargo build -p slipstream-server -p slipstream-client --release

client_extra_args=()
if [[ -n "${CLIENT_ARGS}" ]]; then
  read -r -a client_extra_args <<< "${CLIENT_ARGS}"
fi

if [[ "${USE_PROXY}" == "1" ]]; then
  RECURSIVE_ADDR="${RECURSIVE_ADDR:-127.0.0.1:${PROXY_RECURSIVE_PORT}}"
  AUTHORITATIVE_ADDR="${AUTHORITATIVE_ADDR:-127.0.0.1:${PROXY_AUTHORITATIVE_PORT}}"
else
  RECURSIVE_ADDR="${RECURSIVE_ADDR:-127.0.0.1:${DNS_LISTEN_PORT}}"
  AUTHORITATIVE_ADDR="${AUTHORITATIVE_ADDR:-[::1]:${DNS_LISTEN_PORT}}"
fi

if [[ "${RECURSIVE_ADDR}" == "${AUTHORITATIVE_ADDR}" ]]; then
  echo "Recursive and authoritative resolver addresses must differ; set RECURSIVE_ADDR/AUTHORITATIVE_ADDR or USE_PROXY=1." >&2
  exit 1
fi

"${ROOT_DIR}/target/release/slipstream-server" \
  --dns-listen-port "${DNS_LISTEN_PORT}" \
  --target-address "127.0.0.1:${TCP_TARGET_PORT}" \
  --domain "${DOMAIN}" \
  --cert "${CERT_DIR}/cert.pem" \
  --key "${CERT_DIR}/key.pem" \
  >"${RUN_DIR}/server.log" 2>&1 &
SERVER_PID=$!

if [[ "${USE_PROXY}" == "1" ]]; then
  python3 "${ROOT_DIR}/scripts/interop/udp_capture_proxy.py" \
    --listen "127.0.0.1:${PROXY_RECURSIVE_PORT}" \
    --upstream "127.0.0.1:${DNS_LISTEN_PORT}" \
    --log "${RUN_DIR}/dns_recursive.jsonl" \
    >"${RUN_DIR}/udp_proxy_recursive.log" 2>&1 &
  PROXY_RECURSIVE_PID=$!

  python3 "${ROOT_DIR}/scripts/interop/udp_capture_proxy.py" \
    --listen "127.0.0.1:${PROXY_AUTHORITATIVE_PORT}" \
    --upstream "127.0.0.1:${DNS_LISTEN_PORT}" \
    --log "${RUN_DIR}/dns_authoritative.jsonl" \
    >"${RUN_DIR}/udp_proxy_authoritative.log" 2>&1 &
  PROXY_AUTHORITATIVE_PID=$!
fi

wait_for_log() {
  local label="$1"
  local log_path="$2"
  local pattern="$3"
  local attempts="${4:-10}"
  for _ in $(seq 1 "${attempts}"); do
    if [[ -s "${log_path}" ]] && grep -Eq "${pattern}" "${log_path}"; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${label}; see ${log_path}." >&2
  return 1
}

client_has_arg() {
  local needle="$1"
  shift
  for arg in "$@"; do
    if [[ "${arg}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

client_debug_poll_enabled() {
  if client_has_arg "--debug-poll" "$@"; then
    return 0
  fi
  if client_has_arg "--debug-poll" "${client_extra_args[@]}"; then
    return 0
  fi
  return 1
}

wait_for_log_patterns() {
  local label="$1"
  local log_path="$2"
  local attempts="$3"
  shift 3
  local missing=()
  for _ in $(seq 1 "${attempts}"); do
    missing=()
    for pattern in "$@"; do
      if [[ ! -s "${log_path}" ]] || ! grep -Eq "${pattern}" "${log_path}"; then
        missing+=("${pattern}")
      fi
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${label} (${log_path}); missing patterns: ${missing[*]}." >&2
  return 1
}

start_client() {
  local log_path="$1"
  shift
  local rust_log="info"
  if client_debug_poll_enabled "$@"; then
    rust_log="debug"
  fi
  RUST_LOG="${rust_log}" "${ROOT_DIR}/target/release/slipstream-client" \
    --tcp-listen-port "${CLIENT_TCP_PORT}" \
    --domain "${DOMAIN}" \
    "$@" \
    "${client_extra_args[@]}" \
    >"${log_path}" 2>&1 &
  CLIENT_PID=$!
}

stop_client() {
  if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  CLIENT_PID=""
}

start_target() {
  local label="$1"
  local target_mode="$2"
  local preface_bytes="$3"
  local target_json="${RUN_DIR}/target_${label}.jsonl"
  local target_log="${RUN_DIR}/target_${label}.log"
  local target_args=(
    --listen "127.0.0.1:${TCP_TARGET_PORT}"
    --mode "${target_mode}"
    --bytes "${TRANSFER_BYTES}"
    --chunk-size "${CHUNK_SIZE}"
    --timeout "${SOCKET_TIMEOUT}"
    --log "${target_json}"
  )
  if [[ "${preface_bytes}" -gt 0 ]]; then
    target_args+=(--preface-bytes "${preface_bytes}")
  fi
  python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" server \
    "${target_args[@]}" \
    >"${target_log}" 2>&1 &
  TARGET_PID=$!
  if ! wait_for_log "bench target (${label})" "${target_json}" '"event": "listening"'; then
    return 1
  fi
}

stop_target() {
  if [[ -n "${TARGET_PID:-}" ]] && kill -0 "${TARGET_PID}" 2>/dev/null; then
    kill "${TARGET_PID}" 2>/dev/null || true
    wait "${TARGET_PID}" 2>/dev/null || true
  fi
  TARGET_PID=""
}

run_bench_client() {
  local label="$1"
  local client_mode="$2"
  local preface_bytes="$3"
  local bench_json="${RUN_DIR}/bench_${label}.jsonl"
  local bench_log="${RUN_DIR}/bench_${label}.log"
  local bench_args=(
    --connect "127.0.0.1:${CLIENT_TCP_PORT}"
    --mode "${client_mode}"
    --bytes "${TRANSFER_BYTES}"
    --chunk-size "${CHUNK_SIZE}"
    --timeout "${SOCKET_TIMEOUT}"
    --log "${bench_json}"
  )
  if [[ "${preface_bytes}" -gt 0 ]]; then
    bench_args+=(--preface-bytes "${preface_bytes}")
  fi
  if ! python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" client \
    "${bench_args[@]}" \
    >"${bench_log}" 2>&1; then
    echo "Bench transfer failed (${label}); see logs in ${RUN_DIR}." >&2
    return 1
  fi
}

extract_e2e_mib_s() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

start_path, end_path, bytes_s = sys.argv[1:4]

def load_done(path: str):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "done":
                    return event
    except OSError as exc:
        print(f"Failed to read {path}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Missing done event in {path}", file=sys.stderr)
    raise SystemExit(1)

start = load_done(start_path)
end = load_done(end_path)
start_ts = start.get("first_payload_ts")
end_ts = end.get("last_payload_ts")
if start_ts is None or end_ts is None:
    print("Missing payload timestamps", file=sys.stderr)
    raise SystemExit(1)
elapsed = end_ts - start_ts
if elapsed <= 0:
    print(f"Invalid timing window secs={elapsed:.6f}", file=sys.stderr)
    raise SystemExit(1)

bytes_val = int(bytes_s)
mib_s = (bytes_val / (1024 * 1024)) / elapsed
print(f"{mib_s:.2f}")
PY
}

report_throughput() {
  python3 - "$1" "$2" "$3" "$4" "${THROUGHPUT_MIN_RATIO}" <<'PY'
import sys

def parse(value: str):
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None

label = sys.argv[1]
mixed = parse(sys.argv[2])
authoritative = parse(sys.argv[3])
recursive = parse(sys.argv[4])
min_ratio_raw = sys.argv[5]

if mixed is not None:
    print(f"throughput {label} mixed MiB/s={mixed:.2f}")
if authoritative is not None:
    print(f"throughput {label} authoritative MiB/s={authoritative:.2f}")
if recursive is not None:
    print(f"throughput {label} recursive MiB/s={recursive:.2f}")

best_single = None
if authoritative is not None and recursive is not None:
    best_single = max(authoritative, recursive)
elif authoritative is not None:
    best_single = authoritative
elif recursive is not None:
    best_single = recursive

if mixed is not None and best_single is not None and best_single > 0:
    ratio = mixed / best_single
    print(f"throughput {label} ratio mixed/best_single={ratio:.2f}")
    if min_ratio_raw:
        try:
            min_ratio = float(min_ratio_raw)
        except ValueError:
            print(f"Invalid THROUGHPUT_MIN_RATIO={min_ratio_raw}", file=sys.stderr)
            raise SystemExit(1)
        if ratio < min_ratio:
            print(
                f"Mixed throughput ratio {ratio:.2f} < minimum {min_ratio:.2f}",
                file=sys.stderr,
            )
            raise SystemExit(1)

if authoritative is not None and recursive is not None and recursive > 0:
    ratio = authoritative / recursive
    print(f"throughput {label} ratio authoritative/recursive={ratio:.2f}")
PY
}

enforce_min_throughput() {
  local label="$1"
  local value="$2"
  local threshold="$3"
  if [[ -z "${threshold}" ]]; then
    return 0
  fi
  python3 - "$label" "$value" "$threshold" <<'PY'
import sys

label, value_s, threshold_s = sys.argv[1:4]
try:
    value = float(value_s)
    threshold = float(threshold_s)
except ValueError:
    print(f"Invalid threshold compare for {label}: {value_s} vs {threshold_s}", file=sys.stderr)
    raise SystemExit(1)

if value < threshold:
    print(f"{label} mixed throughput {value:.2f} < minimum {threshold:.2f}", file=sys.stderr)
    raise SystemExit(1)
print(f"{label} mixed throughput minimum ok ({value:.2f} >= {threshold:.2f})")
PY
}

run_client_bench() {
  local label="$1"
  local target_mode="$2"
  local client_mode="$3"
  shift 3
  local client_log="${RUN_DIR}/client_${label}.log"
  local target_json="${RUN_DIR}/target_${label}.jsonl"
  local bench_json="${RUN_DIR}/bench_${label}.jsonl"
  local preface_bytes=0
  local start_path="${bench_json}"
  local end_path="${target_json}"
  local debug_poll=0

  if [[ "${client_mode}" == "recv" ]]; then
    preface_bytes="${PREFACE_BYTES}"
    start_path="${target_json}"
    end_path="${bench_json}"
  fi
  if client_debug_poll_enabled "$@"; then
    debug_poll=1
  fi

  if ! start_target "${label}" "${target_mode}" "${preface_bytes}"; then
    stop_target
    return 1
  fi
  start_client "${client_log}" "$@"
  echo "Waiting for Rust client (${label}) to accept connections..." >&2
  if ! wait_for_log "Rust client (${label})" "${client_log}" "Listening on TCP port"; then
    stop_client
    stop_target
    return 1
  fi
  if ! run_bench_client "${label}" "${client_mode}" "${preface_bytes}"; then
    stop_client
    stop_target
    return 1
  fi
  if ! wait "${TARGET_PID}"; then
    echo "Target server failed (${label}); see logs in ${RUN_DIR}." >&2
    stop_client
    stop_target
    return 1
  fi
  if [[ "${label}" == mixed_* && "${debug_poll}" == "1" ]]; then
    if ! wait_for_log_patterns \
      "mixed debug output (${label})" \
      "${client_log}" \
      "${DEBUG_LOG_WAIT_SECS}" \
      "mode=Recursive" \
      "mode=Authoritative" \
      "mode=Authoritative.*pacing_rate="; then
      stop_client
      stop_target
      return 1
    fi
  fi
  sleep "${DEBUG_WAIT_SECS}"
  stop_client
  stop_target

  extract_e2e_mib_s "${start_path}" "${end_path}" "${TRANSFER_BYTES}"
}

verify_mixed_log() {
  local label="$1"
  local log_path="$2"
  if ! grep -Eq "Added path" "${log_path}"; then
    echo "Expected multipath to add a secondary path (${label}); see ${log_path}." >&2
    return 1
  fi
  if ! grep -Eq "mode=Recursive" "${log_path}"; then
    echo "Missing recursive debug output (${label}); see ${log_path}." >&2
    return 1
  fi
  if ! grep -Eq "mode=Authoritative" "${log_path}"; then
    echo "Missing authoritative debug output (${label}); see ${log_path}." >&2
    return 1
  fi
  if ! grep -Eq "mode=Authoritative.*pacing_rate=" "${log_path}"; then
    echo "Missing authoritative pacing output (${label}); see ${log_path}." >&2
    return 1
  fi
}

mixed_download_mib_s=""
mixed_exfil_mib_s=""

if [[ "${RUN_DOWNLOAD}" != "0" ]]; then
  if ! mixed_download_mib_s=$(run_client_bench \
    mixed_download \
    source \
    recv \
    --authoritative "${AUTHORITATIVE_ADDR}" \
    --resolver "${RECURSIVE_ADDR}" \
    --debug-poll); then
    exit 1
  fi
  if ! verify_mixed_log "download" "${RUN_DIR}/client_mixed_download.log"; then
    exit 1
  fi
  if ! enforce_min_throughput "download" "${mixed_download_mib_s}" "${MIN_AVG_MIB_S_DOWNLOAD}"; then
    exit 1
  fi
fi

if [[ "${RUN_EXFIL}" != "0" ]]; then
  if ! mixed_exfil_mib_s=$(run_client_bench \
    mixed_exfil \
    sink \
    send \
    --authoritative "${AUTHORITATIVE_ADDR}" \
    --resolver "${RECURSIVE_ADDR}" \
    --debug-poll); then
    exit 1
  fi
  if ! verify_mixed_log "exfil" "${RUN_DIR}/client_mixed_exfil.log"; then
    exit 1
  fi
  if ! enforce_min_throughput "exfil" "${mixed_exfil_mib_s}" "${MIN_AVG_MIB_S_EXFIL}"; then
    exit 1
  fi
fi

if [[ "${RUN_DOWNLOAD}" == "0" && "${RUN_EXFIL}" == "0" ]]; then
  echo "RUN_DOWNLOAD and RUN_EXFIL are both disabled; nothing to run." >&2
  exit 1
fi

if [[ "${USE_PROXY}" == "1" ]]; then
  python3 - "${RUN_DIR}/dns_recursive.jsonl" "${RUN_DIR}/dns_authoritative.jsonl" <<'PY'
import json
import sys

paths = [("recursive", sys.argv[1]), ("authoritative", sys.argv[2])]
failed = False

for label, path in paths:
    counts = {"client_to_server": 0, "server_to_client": 0}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                direction = entry.get("direction")
                if direction in counts:
                    counts[direction] += 1
    except OSError as exc:
        print(f"{label} capture missing ({path}): {exc}", file=sys.stderr)
        failed = True
        continue

    missing = [direction for direction, total in counts.items() if total == 0]
    if missing:
        print(f"{label} capture missing directions: {missing} ({counts})", file=sys.stderr)
        failed = True
    else:
        print(
            f"{label} capture: client_to_server={counts['client_to_server']} "
            f"server_to_client={counts['server_to_client']}"
        )

if failed:
    raise SystemExit(1)
PY
fi

if [[ "${THROUGHPUT_COMPARE}" == "1" ]]; then
  if [[ "${RUN_DOWNLOAD}" != "0" ]]; then
    if ! authoritative_download_mib_s=$(run_client_bench \
      authoritative_download \
      source \
      recv \
      --authoritative "${AUTHORITATIVE_ADDR}"); then
      exit 1
    fi
    if ! recursive_download_mib_s=$(run_client_bench \
      recursive_download \
      source \
      recv \
      --resolver "${RECURSIVE_ADDR}"); then
      exit 1
    fi
    report_throughput "download" "${mixed_download_mib_s}" "${authoritative_download_mib_s}" "${recursive_download_mib_s}"
  fi
  if [[ "${RUN_EXFIL}" != "0" ]]; then
    if ! authoritative_exfil_mib_s=$(run_client_bench \
      authoritative_exfil \
      sink \
      send \
      --authoritative "${AUTHORITATIVE_ADDR}"); then
      exit 1
    fi
    if ! recursive_exfil_mib_s=$(run_client_bench \
      recursive_exfil \
      sink \
      send \
      --resolver "${RECURSIVE_ADDR}"); then
      exit 1
    fi
    report_throughput "exfil" "${mixed_exfil_mib_s}" "${authoritative_exfil_mib_s}" "${recursive_exfil_mib_s}"
  fi
else
  if [[ "${RUN_DOWNLOAD}" != "0" ]]; then
    report_throughput "download" "${mixed_download_mib_s}" "" ""
  fi
  if [[ "${RUN_EXFIL}" != "0" ]]; then
    report_throughput "exfil" "${mixed_exfil_mib_s}" "" ""
  fi
fi

echo "Interop mixed OK; logs in ${RUN_DIR}."
