#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
print_usage() {
  cat <<'USAGE'
Slipstream interactive installer

Usage:
  scripts/installer.sh [--mode client|server|both]

The script will:
  - detect your OS and install dependencies
  - ensure Rust is installed
  - build the selected binaries
  - ask for runtime configuration
  - optionally start the selected service immediately
USAGE
}

log() {
  printf "[installer] %s\n" "$1"
}

die() {
  printf "[installer] error: %s\n" "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1
}

maybe_sudo() {
  if [[ $EUID -eq 0 ]]; then
    "$@"
  elif require_command sudo; then
    sudo "$@"
  else
    die "sudo is required to install dependencies"
  fi
}

install_rust() {
  if require_command cargo; then
    return
  fi
  log "Rust toolchain not found; installing via rustup"
  if ! require_command curl; then
    die "curl is required to install rustup"
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
}

install_packages_linux() {
  if require_command apt-get; then
    log "Installing dependencies via apt"
    maybe_sudo apt-get update
    maybe_sudo apt-get install -y build-essential cmake pkg-config libssl-dev python3 git curl
    return
  fi
  if require_command dnf; then
    log "Installing dependencies via dnf"
    maybe_sudo dnf install -y gcc gcc-c++ make cmake pkgconfig openssl-devel python3 git curl
    return
  fi
  if require_command yum; then
    log "Installing dependencies via yum"
    maybe_sudo yum install -y gcc gcc-c++ make cmake pkgconfig openssl-devel python3 git curl
    return
  fi
  if require_command pacman; then
    log "Installing dependencies via pacman"
    maybe_sudo pacman -Sy --noconfirm base-devel cmake pkgconf openssl python git curl
    return
  fi
  if require_command apk; then
    log "Installing dependencies via apk"
    maybe_sudo apk add --no-cache build-base cmake pkgconf openssl-dev python3 git curl
    return
  fi
  if require_command zypper; then
    log "Installing dependencies via zypper"
    maybe_sudo zypper install -y gcc gcc-c++ make cmake pkg-config libopenssl-devel python3 git curl
    return
  fi
  die "Unsupported Linux package manager. Install Rust, cmake, pkg-config, OpenSSL, python3, git, curl manually."
}

install_packages_macos() {
  if ! require_command brew; then
    die "Homebrew is required on macOS. Install it from https://brew.sh/ and re-run."
  fi
  log "Installing dependencies via brew"
  brew update
  brew install cmake pkg-config openssl@3 python3 git
  log "Ensure your OpenSSL paths are configured for cargo builds if needed."
}

install_dependencies() {
  local os
  os=$(uname -s)
  case "$os" in
    Linux)
      install_packages_linux
      ;;
    Darwin)
      install_packages_macos
      ;;
    *)
      die "Unsupported OS: ${os}"
      ;;
  esac
}

prompt() {
  local label=$1
  local default=${2-}
  local value
  if [[ -n $default ]]; then
    read -r -p "${label} [${default}]: " value
    printf '%s' "${value:-$default}"
  else
    read -r -p "${label}: " value
    printf '%s' "$value"
  fi
}

prompt_required() {
  local label=$1
  local default=${2-}
  local value
  while true; do
    value=$(prompt "$label" "$default")
    if [[ -n $value ]]; then
      printf '%s' "$value"
      return
    fi
    printf "Please enter a value.\n" >&2
  done
}

build_targets() {
  local mode=$1
  log "Updating submodules"
  git -C "$REPO_ROOT" submodule update --init --recursive
  if [[ $mode == client ]]; then
    log "Building slipstream-client"
    cargo -C "$REPO_ROOT" build -p slipstream-client --release
  elif [[ $mode == server ]]; then
    log "Building slipstream-server"
    cargo -C "$REPO_ROOT" build -p slipstream-server --release
  else
    log "Building slipstream-client and slipstream-server"
    cargo -C "$REPO_ROOT" build -p slipstream-client -p slipstream-server --release
  fi
}

should_start_now() {
  local value
  read -r -p "Start the service now? [Y/n]: " value
  value=${value:-Y}
  case "$value" in
    y|Y) return 0 ;;
    n|N) return 1 ;;
    *)
      printf "Please answer y or n.\n" >&2
      should_start_now
      ;;
  esac
}

run_client() {
  log "Configuring client"
  local domain tcp_port resolver authoritative cert
  domain=$(prompt_required "Domain (example.com)" "example.com")
  tcp_port=$(prompt_required "TCP listen port" "5201")
  resolver=$(prompt "Resolver address (host:port), leave empty to use authoritative" "")
  if [[ -z $resolver ]]; then
    authoritative=$(prompt_required "Authoritative DNS address (host:port)" "127.0.0.1:8853")
  fi
  cert=$(prompt "Pinned cert path (optional)" "")

  local -a cmd=("${REPO_ROOT}/target/release/slipstream-client" "--tcp-listen-port" "$tcp_port" "--domain" "$domain")
  if [[ -n $resolver ]]; then
    cmd+=("--resolver" "$resolver")
  fi
  if [[ -n ${authoritative:-} ]]; then
    cmd+=("--authoritative" "$authoritative")
  fi
  if [[ -n $cert ]]; then
    cmd+=("--cert" "$cert")
  fi

  if should_start_now; then
    log "Starting client"
    exec "${cmd[@]}"
  else
    log "Client not started. Run manually:"
    printf '  %q ' "${cmd[@]}"
    printf '\n'
  fi
}

run_server() {
  log "Configuring server"
  local domain dns_port target_address cert key reset_seed fallback
  domain=$(prompt_required "Domain (example.com)" "example.com")
  dns_port=$(prompt_required "DNS listen port" "53")
  target_address=$(prompt_required "Target address (host:port)" "127.0.0.1:5201")
  cert=$(prompt_required "Certificate path" "${REPO_ROOT}/cert.pem")
  key=$(prompt_required "Key path" "${REPO_ROOT}/key.pem")
  reset_seed=$(prompt "Reset seed path (optional)" "")
  fallback=$(prompt "Fallback address (optional host:port)" "")

  local -a cmd=("${REPO_ROOT}/target/release/slipstream-server" "--dns-listen-port" "$dns_port" "--target-address" "$target_address" "--domain" "$domain" "--cert" "$cert" "--key" "$key")
  if [[ -n $reset_seed ]]; then
    cmd+=("--reset-seed" "$reset_seed")
  fi
  if [[ -n $fallback ]]; then
    cmd+=("--fallback" "$fallback")
  fi

  if should_start_now; then
    log "Starting server"
    exec "${cmd[@]}"
  else
    log "Server not started. Run manually:"
    printf '  %q ' "${cmd[@]}"
    printf '\n'
  fi
}

main() {
  local mode=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        mode=${2:-}
        shift 2
        ;;
      -h|--help)
        print_usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done

  if [[ -z $mode ]]; then
    printf "Choose install mode:\n"
    printf "  1) client\n"
    printf "  2) server\n"
    printf "  3) both\n"
    read -r -p "Selection [3]: " selection
    selection=${selection:-3}
    case "$selection" in
      1) mode=client ;;
      2) mode=server ;;
      3) mode=both ;;
      *) die "Invalid selection" ;;
    esac
  fi

  case "$mode" in
    client|server|both)
      ;;
    *)
      die "Mode must be client, server, or both"
      ;;
  esac

  log "Installing dependencies"
  install_dependencies
  install_rust

  log "Building Slipstream"
  build_targets "$mode"

  if [[ $mode == client ]]; then
    run_client
  elif [[ $mode == server ]]; then
    run_server
  else
    run_server
    run_client
  fi
}

main "$@"
