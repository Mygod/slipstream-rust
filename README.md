# slipstream-rust mipsel-musl fork

This fork provides a build of
[slipstream-rust](https://github.com/Mygod/slipstream-rust) for older
MIPS-based routers running old Linux kernels, down to Linux 2.6.22.

The upstream project contains the protocol description, usage documentation,
architecture notes, and general development information. Refer to
https://github.com/Mygod/slipstream-rust for everything outside the scope of
this mipsel-musl fork.

## Target

The supported binary target in this fork is:

```text
mipsel-unknown-linux-musl
```

The local and GitHub Actions builds produce statically linked musl binaries:

```text
build/slipstream-client-linux-mipsel-musl
build/slipstream-server-linux-mipsel-musl
```

The intended deployment target is little-endian MIPS routers where modern
glibc-based binaries are not usable and where the kernel may lack newer Linux
syscalls used by current Rust async runtimes.

## Old Kernel Compatibility

Linux 2.6.22 does not provide `epoll_create1` or flagged `eventfd` support.
The mipsel-musl build links compatibility wrappers that fall back to older
syscalls so Tokio can initialize on these routers.

The build also uses a no-64-bit-atomic fallback in the Rust code path required
by the MIPS target.

## Local Build

Requirements:

- Docker
- Git submodules initialized

Initialize submodules first:

```sh
git submodule update --init --recursive
```

Build the static mipsel-musl client and server:

```sh
./scripts/build-mipsel-musl.sh
```

For an unstripped debug build:

```sh
SLIPSTREAM_MIPSEL_PROFILE=debug ./scripts/build-mipsel-musl.sh
```

Debug outputs are written as:

```text
build/slipstream-client-linux-mipsel-musl-debug
build/slipstream-server-linux-mipsel-musl-debug
```

Set `SLIPSTREAM_MIPSEL_STRIP=0` to keep release binaries unstripped.

## Build Pins

The default reproducibility pins live in
`scripts/mipsel-musl/versions.env`:

- Docker image: `ghcr.io/cross-rs/mipsel-unknown-linux-musl` pinned by digest
- Rust toolchain: pinned nightly with `-Z build-std`
- OpenSSL: pinned source version and SHA-256
- Rust crates: `Cargo.lock` via `cargo build --locked`
- picoquic: checked-out `vendor/picoquic` submodule commit

The build script allows overrides through `SLIPSTREAM_MIPSEL_*` environment
variables, but release builds should use the pinned defaults.

## Build Helper Files

- `scripts/build-mipsel-musl.sh` - local Docker build entry point
- `scripts/mipsel-musl/versions.env` - pinned toolchain and OpenSSL versions
- `scripts/mipsel-musl/mipsel-rust-linker.sh` - Rust linker wrapper
- `scripts/mipsel-musl/picoquic-toolchain.cmake` - picoquic CMake toolchain
- `scripts/mipsel-musl/old-linux-syscall-compat.c` - old kernel syscall wrappers
- `scripts/mipsel-musl/unwind-stubs.c` - panic-abort unwind link stubs

## CI And Releases

GitHub Actions builds only the active mipsel-musl artifact:

```text
slipstream-linux-mipsel-musl.tar.gz
slipstream-linux-mipsel-musl.sha256
```

The workflow remains matrix-based so additional targets, such as big-endian
MIPS, can be added later without redesigning the release pipeline.

Before releasing, validate:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p slipstream-core -p slipstream-dns
./scripts/build-mipsel-musl.sh
```

## License

Apache-2.0. See `LICENSE`.
