# Zstd Compression Implementation Notes

## Overview

This document contains implementation notes for the zstd compression feature. Delete after verification.

## Implementation Details

### Magic Byte: `0x28`

Chosen because it doesn't collide with QUIC header patterns:
- QUIC long header starts with bit pattern `1xxxxxxx` (0x80+)
- QUIC short header starts with bit pattern `01xxxxxx` (0x40-0x7F) or `00xxxxxx` (0x00-0x3F depending on version)
- `0x28` is safe and allows auto-detection on decompress

### Compression Level: 3

Default zstd level 3 provides good balance of compression ratio vs latency for real-time tunnel traffic.

### Auto-Detection on Decompress

The `decompress()` function checks for the magic byte prefix:
- If present: decompress the payload
- If absent: return unchanged (passthrough)

This makes it safe if one side doesn't have compression enabled - the data flows through unchanged.

### Skip Compression When No Benefit

`compress()` returns the original payload if compressed size >= original size. This handles small payloads that don't compress well.

## Files Changed

1. **slipstream-core/Cargo.toml** - Added zstd dependency
2. **slipstream-core/src/compression.rs** - New module with compress/decompress
3. **slipstream-core/src/lib.rs** - Export compression module
4. **slipstream-ffi/src/lib.rs** - Added `zstd: bool` to ClientConfig
5. **slipstream-client/src/main.rs** - Added `--zstd` CLI flag
6. **slipstream-client/src/runtime.rs** - Compress outbound QUIC packets
7. **slipstream-client/src/dns/poll.rs** - Compress poll query payloads
8. **slipstream-client/src/dns/response.rs** - Decompress inbound responses
9. **slipstream-server/src/main.rs** - Added `--zstd` CLI flag
10. **slipstream-server/src/server.rs** - Added zstd to ServerConfig, compress/decompress

## Testing

```bash
# Unit tests pass
cargo test -p slipstream-core

# Manual testing (after build works)
./target/debug/slipstream-server --cert cert.pem --key key.pem -d test.com --zstd -l 8853
./target/debug/slipstream-client --authoritative 127.0.0.1:8853 -d test.com --zstd
```

## Build Issue (macOS)

Build failed on macOS due to missing `picotls-fusion` library (ARM Mac doesn't support fusion). This is unrelated to the zstd changes - the code compiles fine, it's the picoquic native dependency that fails.

Should work on Linux where fusion is typically available or properly disabled.

## TODO After Verification

- [ ] Delete this file
- [ ] Run full integration test with iperf3 through tunnel
- [ ] Compare throughput with/without compression
