#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PICOQUIC_DIR="${PICOQUIC_DIR:-"${ROOT_DIR}/vendor/picoquic"}"
BUILD_DIR="${PICOQUIC_BUILD_DIR:-"${ROOT_DIR}/.picoquic-build"}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
FETCH_PTLS="${PICOQUIC_FETCH_PTLS:-ON}"

if [[ ! -d "${PICOQUIC_DIR}" ]]; then
  echo "picoquic not found at ${PICOQUIC_DIR}. Run: git submodule update --init --recursive" >&2
  exit 1
fi

cmake -S "${PICOQUIC_DIR}" -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DPICOQUIC_FETCH_PTLS="${FETCH_PTLS}" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cmake --build "${BUILD_DIR}"
