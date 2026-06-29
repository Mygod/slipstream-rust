#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "${repo_root}/scripts/mipsel-musl/versions.env"

image="${SLIPSTREAM_MIPSEL_IMAGE:-${SLIPSTREAM_MIPSEL_DEFAULT_IMAGE}}"
platform="${SLIPSTREAM_MIPSEL_PLATFORM:-linux/amd64}"
target="${SLIPSTREAM_MIPSEL_TARGET:-mipsel-unknown-linux-musl}"
rust_toolchain="${SLIPSTREAM_MIPSEL_RUST_TOOLCHAIN:-${SLIPSTREAM_MIPSEL_DEFAULT_RUST_TOOLCHAIN}}"
profile="${SLIPSTREAM_MIPSEL_PROFILE:-release}"
case "${profile}" in
  release)
    default_artifact_suffix="linux-mipsel-musl"
    cargo_profile_args="--release"
    cargo_profile_dir="release"
    default_strip="1"
    ;;
  debug)
    default_artifact_suffix="linux-mipsel-musl-debug"
    cargo_profile_args=""
    cargo_profile_dir="debug"
    default_strip="0"
    ;;
  *)
    echo "error: SLIPSTREAM_MIPSEL_PROFILE must be release or debug" >&2
    exit 1
    ;;
esac
artifact_suffix="${SLIPSTREAM_MIPSEL_ARTIFACT_SUFFIX:-${default_artifact_suffix}}"
strip_binaries="${SLIPSTREAM_MIPSEL_STRIP:-${default_strip}}"
openssl_version="${SLIPSTREAM_MIPSEL_OPENSSL_VERSION:-${SLIPSTREAM_MIPSEL_DEFAULT_OPENSSL_VERSION}}"
openssl_url="${SLIPSTREAM_MIPSEL_OPENSSL_URL:-https://www.openssl.org/source/old/3.0/openssl-${openssl_version}.tar.gz}"
openssl_sha256="${SLIPSTREAM_MIPSEL_OPENSSL_SHA256:-${SLIPSTREAM_MIPSEL_DEFAULT_OPENSSL_SHA256}}"
openssl_prefix="${SLIPSTREAM_MIPSEL_OPENSSL_PREFIX:-.cache/mipsel-musl-openssl-${openssl_version}}"
openssl_source_dir="${SLIPSTREAM_MIPSEL_OPENSSL_SOURCE_DIR:-.cache/mipsel-musl-openssl-src}"
picoquic_build_dir="${SLIPSTREAM_MIPSEL_PICOQUIC_BUILD_DIR:-.picoquic-build/mipsel-musl}"
cargo_home="${SLIPSTREAM_MIPSEL_CARGO_HOME:-.cache/mipsel-musl-cargo}"
rustup_home="${SLIPSTREAM_MIPSEL_RUSTUP_HOME:-.cache/mipsel-musl-rustup}"
host_uid=$(id -u)
host_gid=$(id -g)

if ! command -v docker >/dev/null 2>&1; then
  echo "error: Docker is required to build the mipsel musl binaries" >&2
  exit 1
fi

docker run --rm \
  --platform "${platform}" \
  -v "${repo_root}:/work" \
  -w /work \
  -e ARTIFACT_SUFFIX="${artifact_suffix}" \
  -e CARGO_PROFILE_ARGS="${cargo_profile_args}" \
  -e CARGO_PROFILE_DIR="${cargo_profile_dir}" \
  -e STRIP_BINARIES="${strip_binaries}" \
  -e CARGO_HOME="/work/${cargo_home}" \
  -e RUSTUP_HOME="/work/${rustup_home}" \
  -e RUST_TOOLCHAIN="${rust_toolchain}" \
  -e OPENSSL_VERSION="${openssl_version}" \
  -e OPENSSL_URL="${openssl_url}" \
  -e OPENSSL_SHA256="${openssl_sha256}" \
  -e OPENSSL_PREFIX="${openssl_prefix}" \
  -e OPENSSL_SOURCE_DIR="${openssl_source_dir}" \
  -e PICOQUIC_BUILD_DIR="${picoquic_build_dir}" \
  -e RUST_TARGET="${target}" \
  -e HOST_UID="${host_uid}" \
  -e HOST_GID="${host_gid}" \
  "${image}" \
  sh -ceu '
    export DEBIAN_FRONTEND=noninteractive
    export PATH="$CARGO_HOME/bin:$PATH"

    restore_owner() {
      if [ "${HOST_UID:-0}" != "0" ] && [ "${HOST_GID:-0}" != "0" ]; then
        chown -R "$HOST_UID:$HOST_GID" \
          "$CARGO_HOME" "$RUSTUP_HOME" "$OPENSSL_PREFIX" "$OPENSSL_SOURCE_DIR" \
          "$PICOQUIC_BUILD_DIR" build target .cache 2>/dev/null || true
      fi
    }
    trap restore_owner EXIT

    for required_tool in curl make perl cmake git pkg-config bash sha256sum mipsel-linux-muslsf-gcc; do
      if ! command -v "$required_tool" >/dev/null 2>&1; then
        echo "error: $required_tool is not installed in the pinned Docker image" >&2
        exit 1
      fi
    done

    if ! command -v cargo >/dev/null 2>&1; then
      curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
    fi
    if ! rustup toolchain list 2>/dev/null | grep -Eq "^${RUST_TOOLCHAIN}(-| |$)"; then
      rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
    fi
    rustup component add rust-src --toolchain "$RUST_TOOLCHAIN"

    mkdir -p .cache/mipsel-rust-link-libs
    cp scripts/mipsel-musl/unwind-stubs.c .cache/mipsel-rust-link-libs/unwind-stubs.c
    mipsel-linux-muslsf-gcc -c -o .cache/mipsel-rust-link-libs/unwind-stubs.o \
      .cache/mipsel-rust-link-libs/unwind-stubs.c
    mipsel-linux-muslsf-ar crs .cache/mipsel-rust-link-libs/libunwind.a \
      .cache/mipsel-rust-link-libs/unwind-stubs.o
    cp scripts/mipsel-musl/old-linux-syscall-compat.c \
      .cache/mipsel-rust-link-libs/old-linux-syscall-compat.c
    mipsel-linux-muslsf-gcc -c -o .cache/mipsel-rust-link-libs/old-linux-syscall-compat.o \
      .cache/mipsel-rust-link-libs/old-linux-syscall-compat.c
    libgcc_file=$(mipsel-linux-muslsf-gcc -print-libgcc-file-name)
    rm -rf .cache/mipsel-rust-link-libs/libgcc-members
    mkdir -p .cache/mipsel-rust-link-libs/libgcc-members
    (
      cd .cache/mipsel-rust-link-libs/libgcc-members
      mipsel-linux-muslsf-ar x "$libgcc_file" _ucmpdi2.o
      mipsel-linux-muslsf-ar crs ../libgcc-helpers.a _ucmpdi2.o
    )

    cp scripts/mipsel-musl/mipsel-rust-linker.sh .cache/mipsel-rust-linker
    chmod +x .cache/mipsel-rust-linker

    cp scripts/mipsel-musl/picoquic-toolchain.cmake \
      .cache/mipsel-musl-picoquic-toolchain.cmake

    case "$OPENSSL_PREFIX" in
      /*) openssl_root="$OPENSSL_PREFIX" ;;
      *) openssl_root="/work/$OPENSSL_PREFIX" ;;
    esac

    if [ ! -f "$openssl_root/lib/libssl.a" ] && [ ! -f "$openssl_root/lib64/libssl.a" ]; then
      mkdir -p "$OPENSSL_SOURCE_DIR"
      cd "$OPENSSL_SOURCE_DIR"
      if [ ! -f "openssl-$OPENSSL_VERSION.tar.gz" ]; then
        curl -fsSL -o "openssl-$OPENSSL_VERSION.tar.gz" "$OPENSSL_URL"
      fi
      printf "%s  %s\n" "$OPENSSL_SHA256" "openssl-$OPENSSL_VERSION.tar.gz" | sha256sum -c -
      rm -rf "openssl-$OPENSSL_VERSION"
      tar -xzf "openssl-$OPENSSL_VERSION.tar.gz"
      cd "openssl-$OPENSSL_VERSION"
      ./Configure linux-mips32 \
        no-asm \
        no-shared \
        no-tests \
        no-module \
        --prefix="$openssl_root" \
        --openssldir="$openssl_root/ssl" \
        --cross-compile-prefix=mipsel-linux-muslsf-
      make -j"$(nproc 2>/dev/null || echo 2)"
      make install_sw
      cd /work
    fi

    export CC=mipsel-linux-muslsf-gcc
    export CXX=mipsel-linux-muslsf-g++
    export AR=mipsel-linux-muslsf-ar
    export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER=/work/.cache/mipsel-rust-linker
    linker_compat_id=$(
      cksum \
        .cache/mipsel-rust-linker \
        .cache/mipsel-rust-link-libs/old-linux-syscall-compat.o \
        .cache/mipsel-rust-link-libs/libunwind.a \
        .cache/mipsel-rust-link-libs/libgcc-helpers.a \
        | cksum \
        | awk "{print \$1}"
    )
    export RUSTFLAGS="-C panic=abort -C target-feature=+crt-static -C relocation-model=static -C link-arg=-static -C link-arg=-no-pie -C link-arg=-Wl,-Bstatic -C link-self-contained=yes -C link-arg=-Wl,--defsym=slipstream_linker_compat_${linker_compat_id}=0"
    export OPENSSL_DIR="$openssl_root"
    export OPENSSL_ROOT_DIR="$openssl_root"
    export OPENSSL_INCLUDE_DIR="$openssl_root/include"
    export OPENSSL_STATIC=1
    export OPENSSL_NO_VENDOR=1
    export OPENSSL_USE_STATIC_LIBS=TRUE
    export PKG_CONFIG_PATH="$openssl_root/lib/pkgconfig:$openssl_root/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
    export PICOQUIC_BUILD_DIR="/work/$PICOQUIC_BUILD_DIR"
    export PICOQUIC_CMAKE_TOOLCHAIN_FILE="/work/.cache/mipsel-musl-picoquic-toolchain.cmake"
    export PICOQUIC_FETCH_PTLS=ON
    export PICOQUIC_AUTO_BUILD=1

    # shellcheck disable=SC2086
    cargo "+$RUST_TOOLCHAIN" build \
      $CARGO_PROFILE_ARGS \
      --locked \
      -Z build-std=std,panic_abort \
      --target "$RUST_TARGET" \
      -p slipstream-client \
      -p slipstream-server \
      --features openssl-static,picoquic-minimal-build

    mkdir -p build
    cp "target/$RUST_TARGET/$CARGO_PROFILE_DIR/slipstream-client" "build/slipstream-client-$ARTIFACT_SUFFIX"
    cp "target/$RUST_TARGET/$CARGO_PROFILE_DIR/slipstream-server" "build/slipstream-server-$ARTIFACT_SUFFIX"

    if [ "$STRIP_BINARIES" = "1" ] && command -v mipsel-linux-muslsf-strip >/dev/null 2>&1; then
      mipsel-linux-muslsf-strip "build/slipstream-client-$ARTIFACT_SUFFIX"
      mipsel-linux-muslsf-strip "build/slipstream-server-$ARTIFACT_SUFFIX"
    fi

    for binary in "build/slipstream-client-$ARTIFACT_SUFFIX" "build/slipstream-server-$ARTIFACT_SUFFIX"; do
      if mipsel-linux-muslsf-readelf -d "$binary" 2>/dev/null | grep -q "Dynamic section"; then
        echo "error: $binary has a dynamic section" >&2
        exit 1
      fi
    done

    restore_owner
  '

echo "Built:"
echo "  build/slipstream-client-${artifact_suffix}"
echo "  build/slipstream-server-${artifact_suffix}"
