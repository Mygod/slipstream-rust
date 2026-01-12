#!/usr/bin/env python3
import argparse
import json
import heapq
import random
import socket
import sys
import time
from select import select
from typing import Optional, Tuple


def parse_hostport(value: str) -> Tuple[str, int]:
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("invalid IPv6 address, missing closing bracket")
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest.startswith(":"):
            raise ValueError("missing port for IPv6 address")
        port = int(rest[1:])
        return host, port
    if ":" not in value:
        raise ValueError("missing port (expected host:port)")
    host, port_str = value.rsplit(":", 1)
    return host, int(port_str)


def addr_to_string(addr: Tuple[str, int]) -> str:
    host, port = addr
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def main() -> int:
    parser = argparse.ArgumentParser(description="UDP proxy that logs packets as JSON lines")
    parser.add_argument("--listen", required=True, help="listen address, host:port")
    parser.add_argument("--upstream", required=True, help="upstream address, host:port")
    parser.add_argument("--log", default="-", help="log file path (default: stdout)")
    parser.add_argument("--max-packets", type=int, default=0, help="stop after N packets")
    parser.add_argument("--delay-ms", type=float, default=0.0, help="base delay per packet")
    parser.add_argument("--jitter-ms", type=float, default=0.0, help="jitter to apply to delay")
    parser.add_argument(
        "--dist",
        choices=("normal", "uniform"),
        default="normal",
        help="delay distribution (default: normal)",
    )
    parser.add_argument(
        "--reorder-prob",
        type=float,
        default=0.0,
        help="probability to allow out-of-order delivery (default: 0)",
    )
    args = parser.parse_args()

    listen = parse_hostport(args.listen)
    upstream = parse_hostport(args.upstream)

    family = socket.AF_INET6 if ":" in listen[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind(listen)

    log_fp = sys.stdout if args.log == "-" else open(args.log, "w", encoding="utf-8")

    last_client_addr: Optional[Tuple[str, int]] = None
    packet_count = 0
    rng = random.Random()
    pending = []
    last_send_at = {
        "client_to_server": 0.0,
        "server_to_client": 0.0,
    }
    push_seq = 0
    reorder_interval = int(1.0 / args.reorder_prob) if args.reorder_prob > 0 else 0
    reorder_counters = {
        "client_to_server": 0,
        "server_to_client": 0,
    }

    def sample_delay_ms() -> float:
        delay_ms = args.delay_ms
        jitter_ms = args.jitter_ms
        if delay_ms <= 0 and jitter_ms <= 0:
            return 0.0
        if jitter_ms <= 0:
            return max(0.0, delay_ms)
        if args.dist == "uniform":
            delay = rng.uniform(delay_ms - jitter_ms, delay_ms + jitter_ms)
        else:
            delay = rng.gauss(delay_ms, jitter_ms)
        return max(0.0, delay)

    try:
        while True:
            now_mono = time.monotonic()
            while pending and pending[0][0] <= now_mono:
                _, _, data, dst = heapq.heappop(pending)
                sock.sendto(data, dst)

            timeout = None
            if pending:
                timeout = max(0.0, pending[0][0] - now_mono)

            ready, _, _ = select([sock], [], [], timeout)
            if not ready:
                continue

            data, addr = sock.recvfrom(65535)
            direction = "client_to_server"
            dst = upstream
            if addr == upstream:
                direction = "server_to_client"
                if last_client_addr is None:
                    dst = None
                else:
                    dst = last_client_addr
            else:
                last_client_addr = addr

            entry = {
                "ts": time.time(),
                "direction": direction,
                "len": len(data),
                "src": addr_to_string(addr),
                "dst": addr_to_string(dst) if dst else None,
                "hex": data.hex().upper(),
            }

            delay_ms = sample_delay_ms() if dst is not None else 0.0
            if delay_ms:
                entry["delay_ms"] = delay_ms
            log_fp.write(json.dumps(entry) + "\n")
            log_fp.flush()

            if dst is not None:
                if delay_ms:
                    send_at = time.monotonic() + (delay_ms / 1000.0)
                    last_for_dir = last_send_at[direction]
                    if send_at <= last_for_dir:
                        send_at = last_for_dir + 1e-6
                    if reorder_interval > 0:
                        reorder_counters[direction] += 1
                        if reorder_counters[direction] % reorder_interval == 0 and last_for_dir > 0:
                            send_at = last_for_dir - 1e-6
                    last_send_at[direction] = max(last_for_dir, send_at)
                    push_seq += 1
                    heapq.heappush(pending, (send_at, push_seq, data, dst))
                else:
                    sock.sendto(data, dst)

            packet_count += 1
            if args.max_packets and packet_count >= args.max_packets:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if log_fp is not sys.stdout:
            log_fp.close()
        sock.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
