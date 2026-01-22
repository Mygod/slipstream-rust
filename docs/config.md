# Configuration

This page documents runtime knobs and environment variables.

## Client and server environment variables

- SLIPSTREAM_STREAM_WRITE_BUFFER_BYTES
  Overrides the connection-level QUIC max_data limit used for backpressure.
  Default is 8 MiB. Values must be positive integers.

## TLS certificates

Sample certs live in `fixtures/certs/` for local testing only. The server
requires explicit `--cert` and `--key` paths; provide your own cert/key pair
for real deployments. The client can pass `--cert` to pin the server leaf
certificate (PEM); CA bundles are not supported and the PEM must contain a
single certificate. If omitted, server certificates are not verified.

## Logging and debug knobs

- Logging uses `tracing` with `RUST_LOG` (default `info`). Example:
  `RUST_LOG=debug cargo run -p slipstream-client -- --resolver=IP:PORT --domain=example.com`.
- `--debug-poll` (client) enables periodic poll/pacing metrics.
- `--debug-streams` (client/server) logs stream lifecycle details.
- `--debug-commands` (server) reports command counts once per second.

## Protocol defaults

- Client ALPN: `picoquic_sample` (must match server ALPN).
- Client SNI: `test.example.com`.
- Server ALPN: `picoquic_sample`.
- Server QUIC MTU: `900`.
  Update `crates/slipstream-client/src/client.rs` and `crates/slipstream-server/src/server.rs`
  together to keep client/server ALPN in sync.

## Server runtime knobs

- `--max-connections`
  Caps concurrent QUIC connections and sizes internal connection tables (default: 256).
- `--idle-timeout-seconds`
  Closes idle QUIC connections after the given number of seconds (default: 1200).
  Set to 0 to disable idle GC.

## picoquic build environment

These affect the build script in crates/slipstream-ffi:

- PICOQUIC_AUTO_BUILD
  Set to 0 to disable auto-building picoquic when headers/libs are missing.

- PICOQUIC_DIR
  picoquic source tree (default: vendor/picoquic).

- PICOQUIC_INCLUDE_DIR
  picoquic headers directory (default: vendor/picoquic/picoquic).

- PICOTLS_INCLUDE_DIR
  picotls headers directory (default: .picoquic-build/_deps/picotls-src/include).

- PICOQUIC_BUILD_DIR
  picoquic build output (default: .picoquic-build).

- PICOQUIC_LIB_DIR
  Directory containing picoquic and picotls libraries.

## Script environment variables

Interop and benchmark scripts accept environment variables for ports, domains,
and paths. See docs/interop.md and docs/benchmarks.md for details.
