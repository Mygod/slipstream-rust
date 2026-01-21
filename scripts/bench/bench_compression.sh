#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ITERATIONS="${ITERATIONS:-100000}"
SIZES="${SIZES:-64,256,1024,4096}"

echo "Building release binary..."
cargo build -p slipstream-core --release 2>&1 | tail -1

# Create a temporary Rust program for benchmarking
BENCH_DIR="${ROOT_DIR}/.bench-compression"
mkdir -p "${BENCH_DIR}/src"

cat > "${BENCH_DIR}/Cargo.toml" << 'EOF'
[package]
name = "bench-compression"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
slipstream-core = { path = "../crates/slipstream-core" }
EOF

cat > "${BENCH_DIR}/src/main.rs" << 'EOF'
use slipstream_core::compression::{compress, decompress};
use std::env;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let iterations: usize = env::var("ITERATIONS")
        .unwrap_or_else(|_| "100000".to_string())
        .parse()
        .unwrap();
    let sizes: Vec<usize> = env::var("SIZES")
        .unwrap_or_else(|_| "64,256,1024,4096".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    println!("Compression benchmark ({} iterations per size)\n", iterations);

    // Passthrough mode (no compression)
    println!("=== NO COMPRESSION (passthrough) ===");
    println!("{:>6} {:>12} {:>12} {:>12} {:>12}",
        "Size", "Send", "Recv", "Send MiB/s", "Recv MiB/s");
    println!("{}", "-".repeat(60));

    for size in &sizes {
        let data: Vec<u8> = (0..*size).map(|i| (i % 64) as u8).collect();

        // Warm up
        let _ = black_box(data.clone());

        // Benchmark send (clone simulates memcpy to network buffer)
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = black_box(data.clone());
        }
        let send_elapsed = start.elapsed();
        let send_us = send_elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64;
        let send_mib = (*size as f64 * iterations as f64) / (1024.0 * 1024.0) / send_elapsed.as_secs_f64();

        // Benchmark recv (same as send for passthrough)
        let recv_us = send_us;
        let recv_mib = send_mib;

        println!("{:>5}B {:>10.2}us {:>10.2}us {:>10.0} {:>12.0}",
            size, send_us, recv_us, send_mib, recv_mib);
    }

    // Compression mode
    println!("\n=== WITH COMPRESSION (zstd level 3) ===");
    println!("{:>6} {:>12} {:>12} {:>12} {:>12} {:>8}",
        "Size", "Send", "Recv", "Send MiB/s", "Recv MiB/s", "Ratio");
    println!("{}", "-".repeat(70));

    for size in &sizes {
        let data: Vec<u8> = (0..*size).map(|i| (i % 64) as u8).collect();

        // Warm up
        let compressed = compress(&data).unwrap();
        let _ = decompress(&compressed).unwrap();

        let ratio = if compressed.len() < data.len() {
            data.len() as f64 / compressed.len() as f64
        } else {
            1.0
        };

        // Benchmark send (compress)
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = black_box(compress(&data).unwrap());
        }
        let send_elapsed = start.elapsed();
        let send_us = send_elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64;
        let send_mib = (*size as f64 * iterations as f64) / (1024.0 * 1024.0) / send_elapsed.as_secs_f64();

        // Benchmark recv (decompress)
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = black_box(decompress(&compressed).unwrap());
        }
        let recv_elapsed = start.elapsed();
        let recv_us = recv_elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64;
        let recv_mib = (*size as f64 * iterations as f64) / (1024.0 * 1024.0) / recv_elapsed.as_secs_f64();

        println!("{:>5}B {:>10.2}us {:>10.2}us {:>10.0} {:>12.0} {:>7.2}x",
            size, send_us, recv_us, send_mib, recv_mib, ratio);
    }

    println!("\nBenchmark complete.");
}
EOF

echo "Building compression benchmark..."
cargo build --manifest-path "${BENCH_DIR}/Cargo.toml" --release 2>&1 | grep -v "Compiling\|Downloading" || true

echo ""
ITERATIONS="${ITERATIONS}" SIZES="${SIZES}" "${BENCH_DIR}/target/release/bench-compression"
