# Build

## Prereqs

- Rust toolchain (stable)
- C toolchain (cc/clang)
- cmake
- pkg-config
- OpenSSL development headers and libs
- python3 (for interop and benchmark scripts)

## picoquic submodule

This repo uses a picoquic fork as a submodule under vendor/picoquic.
Initialize it before building:

```
git submodule update --init --recursive
```

## Default build (non-Windows hosts)

The build script in crates/slipstream-ffi will auto-build picoquic if the
headers and libs are missing. It uses vendor/picoquic and writes outputs to
.picoquic-build/ (ignored). Set PICOQUIC_FETCH_PTLS=OFF to skip the picotls
fetch.

```
cargo build -p slipstream-client -p slipstream-server
```

You can disable auto-build with:

```
PICOQUIC_AUTO_BUILD=0 cargo build -p slipstream-client -p slipstream-server
```

For Windows targets, Cargo does not auto-build picoquic; provide explicit
picoquic/picotls build directories or use the Windows helper below.

## Windows target build

Windows binary builds are supported in GitHub Actions for
`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`. The workflow runs
`scripts/build_picoquic_windows.ps1`, which builds picotls and picoquic with
CMake, stages static OpenSSL libraries, and exports the Cargo environment
through `GITHUB_ENV`.

For manual Windows builds, run the helper for the target platform before the
matching Cargo build:

```
pwsh -File ./scripts/build_picoquic_windows.ps1
cargo build -p slipstream-client -p slipstream-server --target x86_64-pc-windows-msvc

pwsh -File ./scripts/build_picoquic_windows.ps1 -Platform ARM64
cargo build -p slipstream-client -p slipstream-server --target aarch64-pc-windows-msvc
```

Other Windows build arrangements are not blocked when `PICOQUIC_INCLUDE_DIR`,
`PICOQUIC_LIB_DIR`, and `PICOTLS_INCLUDE_DIR` point at compatible prebuilt
artifacts, but CI only exercises the two Windows MSVC targets above.

The uploaded Windows artifact is expected to contain only the two Slipstream
executables plus checksums. CI rejects artifacts with non-platform DLL
dependencies; Windows system DLLs, API-set DLLs, and the VC/UCRT runtime are
allowed.

## Manual picoquic build (non-Windows hosts)

If you prefer to build picoquic yourself, run:

```
./scripts/build_picoquic.sh
```

Then point Cargo at the build output if needed:

- PICOQUIC_DIR: picoquic source tree (default: vendor/picoquic)
- PICOQUIC_INCLUDE_DIR: headers (default: vendor/picoquic/picoquic)
- PICOTLS_INCLUDE_DIR: picotls headers (default: .picoquic-build/_deps/picotls-src/include)
- PICOQUIC_BUILD_DIR: build output (default: .picoquic-build)
- PICOQUIC_LIB_DIR: directory containing picoquic and picotls libs

## Tests

Run the DNS vector tests:

```
cargo test -p slipstream-dns
```

Run the full workspace tests:

```
cargo test
```
