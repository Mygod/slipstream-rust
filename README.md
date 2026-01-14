# Slipstream (Rust)

Slipstream is a high-performance DNS tunnel that carries QUIC packets over DNS queries and responses.
This repository hosts the Rust rewrite of the original C implementation.

## What is here

- slipstream-client and slipstream-server CLI binaries.
- A DNS codec crate with vector-based tests.
- picoquic FFI integration for multipath QUIC support.
- Fully async with tokio.

## Quick start (local dev)

Prereqs:

- Rust toolchain (stable)
- cmake, pkg-config
- OpenSSL headers and libs
- python3 (for interop and benchmark scripts)

Initialize the picoquic submodule:

```
git submodule update --init --recursive
```

Build the Rust binaries:

```
cargo build -p slipstream-client -p slipstream-server
```

Generate a test TLS cert (example):

```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=slipstream"
```

Run the server:

```
cargo run -p slipstream-server -- \
  --dns-listen-port 8853 \
  --target-address 127.0.0.1:5201 \
  --domain example.com \
  --cert ./cert.pem \
  --key ./key.pem
```

Run the client:

```
cargo run -p slipstream-client -- \
  --tcp-listen-port 7000 \
  --resolver 127.0.0.1:8853 \
  --domain example.com
```

Note: You can also run the client against a resolver that forwards to the server. For local testing, see the interop docs.

## Benchmarks (local snapshot)

All results below are end-to-end completion times in seconds (lower is better),
averaged over 5 runs on local loopback. Payload: 10 MiB in each direction.
Variants are dnstt, C-C slipstream, Rust-Rust (non-auth), and Rust-Rust (auth
via `--authoritative`).

See `scripts/bench` for scripts used for obtaining these results.

| Variant                              | Exfil avg (s) | Download avg (s) |
|--------------------------------------| ---: | ---: |
| dnstt                                | 16.207 | 2.492 |
| slipstream (C)                       | 5.332 | 1.096 |
| slipstream-rust                      | 3.249 | 0.978 |
| slipstream-rust (Authoritative mode) | 1.602 | 0.407 |

![Throughput bar chart](.github/throughput.png)

## Documentation

- docs/README.md for the doc index
- docs/build.md for build prerequisites and picoquic setup
- docs/usage.md for CLI usage
- docs/protocol.md for DNS encapsulation notes
- docs/dns-codec.md for codec behavior and vectors
- docs/interop.md for local harnesses and interop
- docs/benchmarks.md for benchmarking harnesses
- docs/benchmarks-results.md for benchmark results
- docs/profiling.md for profiling notes
- docs/design.md for architecture notes

## Repo layout

- crates/      Rust workspace crates
- docs/        Public docs and internal design notes
- fixtures/    Golden DNS vectors
- scripts/     Interop and benchmark harnesses
- tools/       Vector generator and helpers
- vendor/      picoquic submodule

## License

Apache-2.0. See LICENSE.
