#!/usr/bin/env bash
set -euo pipefail

args=()
for arg in "$@"; do
  case "$arg" in
    -lunwind)
      args+=("/work/.cache/mipsel-rust-link-libs/libunwind.a")
      ;;
    crt1.o|crti.o|crtn.o|Scrt1.o|rcrt1.o|crtbegin.o|crtbeginS.o|crtbeginT.o|crtend.o|crtendS.o)
      args+=("$(mipsel-linux-muslsf-gcc -print-file-name="$arg")")
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

args+=(
  -static
  -Wl,-Bstatic
  -Wl,--wrap=epoll_create1
  -Wl,--wrap=eventfd
  /work/.cache/mipsel-rust-link-libs/old-linux-syscall-compat.o
  -latomic
  /work/.cache/mipsel-rust-link-libs/libgcc-helpers.a
)
exec mipsel-linux-muslsf-gcc "${args[@]}"
