#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="${CERT_DIR:-"${ROOT_DIR}/.github/certs"}"
RUN_DIR="${ROOT_DIR}/.interop/bench-rust-rust-$(date +%Y%m%d_%H%M%S)"

DNS_LISTEN_PORT="${DNS_LISTEN_PORT:-8853}"
TCP_TARGET_PORT="${TCP_TARGET_PORT:-5201}"
CLIENT_TCP_PORT="${CLIENT_TCP_PORT:-7000}"
DOMAIN="${DOMAIN:-test.com}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-30}"
TRANSFER_BYTES="${TRANSFER_BYTES:-10485760}"
CHUNK_SIZE="${CHUNK_SIZE:-16384}"
RUNS="${RUNS:-1}"
RUN_EXFIL="${RUN_EXFIL:-1}"
RUN_DOWNLOAD="${RUN_DOWNLOAD:-1}"
MIN_AVG_MIB_S="${MIN_AVG_MIB_S:-}"
MIN_AVG_MIB_S_EXFIL="${MIN_AVG_MIB_S_EXFIL:-5}"
MIN_AVG_MIB_S_DOWNLOAD="${MIN_AVG_MIB_S_DOWNLOAD:-10}"
NETEM_IFACE="${NETEM_IFACE:-lo}"
NETEM_DELAY_MS="${NETEM_DELAY_MS:-}"
NETEM_JITTER_MS="${NETEM_JITTER_MS:-}"
NETEM_DIST="${NETEM_DIST:-normal}"
NETEM_SUDO="${NETEM_SUDO:-1}"
NETEM_ACTIVE=0
PROXY_DELAY_MS="${PROXY_DELAY_MS:-}"
PROXY_JITTER_MS="${PROXY_JITTER_MS:-}"
PROXY_DIST="${PROXY_DIST:-normal}"
PROXY_PORT="${PROXY_PORT:-}"
PROXY_REORDER_PROB="${PROXY_REORDER_PROB:-}"
PROXY_BURST_CORRELATION="${PROXY_BURST_CORRELATION:-}"
CLIENT_ARGS="${CLIENT_ARGS:-}"

client_extra_args=()
if [[ -n "${CLIENT_ARGS}" ]]; then
  read -r -a client_extra_args <<< "${CLIENT_ARGS}"
fi

if [[ ! -f "${CERT_DIR}/cert.pem" || ! -f "${CERT_DIR}/key.pem" ]]; then
  echo "Missing test certs in ${CERT_DIR}. Set CERT_DIR to override." >&2
  exit 1
fi

mkdir -p "${RUN_DIR}" "${ROOT_DIR}/.interop"

cleanup_pids() {
  for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}" "${TARGET_PID:-}" "${PROXY_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  CLIENT_PID=""
  SERVER_PID=""
  TARGET_PID=""
  PROXY_PID=""
}

setup_netem() {
  if [[ -z "${NETEM_DELAY_MS}" ]]; then
    return
  fi
  if ! command -v tc >/dev/null 2>&1; then
    echo "tc not found; install iproute2 or unset NETEM_DELAY_MS." >&2
    exit 1
  fi

  local args=(qdisc replace dev "${NETEM_IFACE}" root netem delay "${NETEM_DELAY_MS}ms")
  if [[ -n "${NETEM_JITTER_MS}" ]]; then
    args+=("${NETEM_JITTER_MS}ms" distribution "${NETEM_DIST}")
  fi

  echo "Applying netem on ${NETEM_IFACE}: delay ${NETEM_DELAY_MS}ms${NETEM_JITTER_MS:+ jitter ${NETEM_JITTER_MS}ms}." >&2
  if [[ "$(id -u)" -eq 0 ]]; then
    tc "${args[@]}"
  else
    if [[ "${NETEM_SUDO}" == "1" ]]; then
      sudo -n tc "${args[@]}" || {
        echo "Failed to apply netem; re-run with sudo or set NETEM_SUDO=0." >&2
        exit 1
      }
    else
      echo "NETEM requires root; re-run with sudo or set NETEM_SUDO=1." >&2
      exit 1
    fi
  fi
  NETEM_ACTIVE=1
}

cleanup_netem() {
  if [[ "${NETEM_ACTIVE}" != "1" ]]; then
    return
  fi
  local args=(qdisc del dev "${NETEM_IFACE}" root)
  if [[ "$(id -u)" -eq 0 ]]; then
    tc "${args[@]}" || true
  else
    if [[ "${NETEM_SUDO}" == "1" ]]; then
      sudo -n tc "${args[@]}" || true
    fi
  fi
}

cleanup() {
  cleanup_pids
  cleanup_netem
}
trap cleanup EXIT INT TERM HUP

e2e_report() {
  local label="$1"
  local start_log="$2"
  local end_log="$3"
  local bytes="$4"
  python3 - "$start_log" "$end_log" "$bytes" "$label" <<'PY'
import json
import sys

start_path, end_path, bytes_s, label = sys.argv[1:5]

def load_done(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "done":
                return event
    return None

start = load_done(start_path)
end = load_done(end_path)
if not start or not end:
    print(f"{label}: missing timing data")
    raise SystemExit(0)
start_ts = start.get("first_payload_ts")
end_ts = end.get("last_payload_ts")
if start_ts is None or end_ts is None:
    print(f"{label}: missing payload timestamps")
    raise SystemExit(0)
elapsed = end_ts - start_ts
if elapsed <= 0:
    print(f"{label}: invalid timing window secs={elapsed:.6f}")
    raise SystemExit(0)
bytes_val = int(bytes_s)
mib = bytes_val / (1024 * 1024)
mib_s = mib / elapsed
print(f"{label}: bytes={bytes_val} secs={elapsed:.3f} MiB/s={mib_s:.2f}")
PY
}

enforce_min_avg() {
  python3 - "$RUN_DIR" "$TRANSFER_BYTES" "$MIN_AVG_MIB_S" "$MIN_AVG_MIB_S_EXFIL" "$MIN_AVG_MIB_S_DOWNLOAD" "$RUN_EXFIL" "$RUN_DOWNLOAD" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
bytes_val = int(sys.argv[2])
min_avg = sys.argv[3]
min_exfil = float(sys.argv[4])
min_download = float(sys.argv[5])
run_exfil = int(sys.argv[6]) != 0
run_download = int(sys.argv[7]) != 0

def load_done(path: pathlib.Path):
    try:
        data = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in data:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "done":
            return event
    return None

def e2e_mib_s(start_log: pathlib.Path, end_log: pathlib.Path):
    start = load_done(start_log)
    end = load_done(end_log)
    if not start or not end:
        return None
    start_ts = start.get("first_payload_ts")
    end_ts = end.get("last_payload_ts")
    if start_ts is None or end_ts is None:
        return None
    elapsed = end_ts - start_ts
    if elapsed <= 0:
        return None
    mib = bytes_val / (1024 * 1024)
    return mib / elapsed

def collect(case: str):
    values = []
    for path in run_dir.glob(f"**/{case}"):
        if not path.is_dir():
            continue
        if case == "exfil":
            start_log = path / "bench.jsonl"
            end_log = path / "target.jsonl"
        else:
            start_log = path / "target.jsonl"
            end_log = path / "bench.jsonl"
        if start_log.exists() and end_log.exists():
            rate = e2e_mib_s(start_log, end_log)
            if rate is not None:
                values.append(rate)
    return values

failed = False
if run_exfil:
    threshold = min_exfil
    if min_avg:
        threshold = float(min_avg)
    exfil_rates = collect("exfil")
    if not exfil_rates:
        print("exfil avg: missing timing data")
        failed = True
    else:
        exfil_avg = sum(exfil_rates) / len(exfil_rates)
        print(f"exfil avg MiB/s: {exfil_avg:.2f} (min {threshold:.2f})")
        if exfil_avg < threshold:
            failed = True

if run_download:
    threshold = min_download
    if min_avg:
        threshold = float(min_avg)
    download_rates = collect("download")
    if not download_rates:
        print("download avg: missing timing data")
        failed = True
    else:
        download_avg = sum(download_rates) / len(download_rates)
        print(f"download avg MiB/s: {download_avg:.2f} (min {threshold:.2f})")
        if download_avg < threshold:
            failed = True

raise SystemExit(1 if failed else 0)
PY
}

cargo build -p slipstream-server -p slipstream-client --release

run_case() {
  local case_name="$1"
  local target_mode="$2"
  local client_mode="$3"
  local run_id="${4:-}"
  local case_base="${case_name##*/}"
  local case_dir="${RUN_DIR}/${case_name}"
  local preface_args=()
  local target_preface_args=()
  local resolver_port="${DNS_LISTEN_PORT}"
  mkdir -p "${case_dir}"

  if [[ "${client_mode}" == "recv" ]]; then
    preface_args=(--preface-bytes 1)
    target_preface_args=(--preface-bytes 1)
  fi

  if [[ -n "${PROXY_DELAY_MS}" ]]; then
    local proxy_port="${PROXY_PORT:-$((DNS_LISTEN_PORT + 1))}"
    if [[ "${proxy_port}" -eq "${DNS_LISTEN_PORT}" ]]; then
      echo "Proxy port ${proxy_port} conflicts with DNS_LISTEN_PORT." >&2
      return 1
    fi
    local proxy_args=(
      --listen "127.0.0.1:${proxy_port}"
      --upstream "127.0.0.1:${DNS_LISTEN_PORT}"
      --delay-ms "${PROXY_DELAY_MS}"
      --dist "${PROXY_DIST}"
      --log "${case_dir}/dns_proxy.jsonl"
    )
    if [[ -n "${PROXY_JITTER_MS}" ]]; then
      proxy_args+=(--jitter-ms "${PROXY_JITTER_MS}")
    fi
    if [[ -n "${PROXY_BURST_CORRELATION}" ]]; then
      proxy_args+=(--burst-correlation "${PROXY_BURST_CORRELATION}")
    fi
    if [[ -n "${PROXY_REORDER_PROB}" ]]; then
      proxy_args+=(--reorder-rate "${PROXY_REORDER_PROB}")
    fi
    python3 "${ROOT_DIR}/scripts/interop/udp_capture_proxy.py" \
      "${proxy_args[@]}" \
      >"${case_dir}/dns_proxy.log" 2>&1 &
    PROXY_PID=$!
    resolver_port="${proxy_port}"
  fi

  python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" server \
    --listen "127.0.0.1:${TCP_TARGET_PORT}" \
    --mode "${target_mode}" \
    --bytes "${TRANSFER_BYTES}" \
    --chunk-size "${CHUNK_SIZE}" \
    --timeout "${SOCKET_TIMEOUT}" \
    "${target_preface_args[@]}" \
    --log "${case_dir}/target.jsonl" \
    >"${case_dir}/target.log" 2>&1 &
  TARGET_PID=$!

  "${ROOT_DIR}/target/release/slipstream-server" \
    --dns-listen-port "${DNS_LISTEN_PORT}" \
    --target-address "127.0.0.1:${TCP_TARGET_PORT}" \
    --domain "${DOMAIN}" \
    --cert "${CERT_DIR}/cert.pem" \
    --key "${CERT_DIR}/key.pem" \
    >"${case_dir}/server.log" 2>&1 &
  SERVER_PID=$!

  "${ROOT_DIR}/target/release/slipstream-client" \
    --tcp-listen-port "${CLIENT_TCP_PORT}" \
    --resolver "127.0.0.1:${resolver_port}" \
    --domain "${DOMAIN}" \
    "${client_extra_args[@]}" \
    >"${case_dir}/client.log" 2>&1 &
  CLIENT_PID=$!

  if [[ -n "${run_id}" ]]; then
    echo "Running ${case_name} benchmark (run ${run_id})..."
  else
    echo "Running ${case_name} benchmark..."
  fi
  sleep 2

  python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" client \
    --connect "127.0.0.1:${CLIENT_TCP_PORT}" \
    --mode "${client_mode}" \
    --bytes "${TRANSFER_BYTES}" \
    --chunk-size "${CHUNK_SIZE}" \
    --timeout "${SOCKET_TIMEOUT}" \
    "${preface_args[@]}" \
    --log "${case_dir}/bench.jsonl" \
    | tee "${case_dir}/bench.log"

  wait "${TARGET_PID}" || {
    echo "Target ${case_name} server failed." >&2
    return 1
  }
  local label="end-to-end ${case_base}"
  if [[ -n "${run_id}" ]]; then
    label="${label} (run ${run_id})"
  fi
  if [[ "${case_base}" == "exfil" ]]; then
    e2e_report "${label}" "${case_dir}/bench.jsonl" "${case_dir}/target.jsonl" "${TRANSFER_BYTES}"
  else
    e2e_report "${label}" "${case_dir}/target.jsonl" "${case_dir}/bench.jsonl" "${TRANSFER_BYTES}"
  fi
  cleanup_pids
}

if [[ -z "${PROXY_DELAY_MS}" ]]; then
  setup_netem
fi

if [[ "${RUNS}" -le 1 ]]; then
  if [[ "${RUN_EXFIL}" -ne 0 ]]; then
    run_case "exfil" "sink" "send"
  fi
  if [[ "${RUN_DOWNLOAD}" -ne 0 ]]; then
    run_case "download" "source" "recv"
  fi
else
  for run_id in $(seq 1 "${RUNS}"); do
    if [[ "${RUN_EXFIL}" -ne 0 ]]; then
      run_case "run-${run_id}/exfil" "sink" "send" "${run_id}"
    fi
    if [[ "${RUN_DOWNLOAD}" -ne 0 ]]; then
      run_case "run-${run_id}/download" "source" "recv" "${run_id}"
    fi
  done
fi

enforce_min_avg
echo "Benchmarks OK; logs in ${RUN_DIR}."
