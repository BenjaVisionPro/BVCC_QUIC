#!/usr/bin/env bash
set -euo pipefail

# Build MsQuic into build/deps/install using cmake ExternalProject in deps/
# Optional overrides:
#   QUIC_IMPL      (default: msquic)
#   QUIC_VERSION   (default: v2.5.3)
#   DEPS_BUILD     (default: ./build/deps-build)
#   DEPS_INSTALL   (default: ./build/deps/install)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS_BUILD="${DEPS_BUILD:-$ROOT/build/deps-build}"
DEPS_INSTALL="${DEPS_INSTALL:-$ROOT/build/deps/install}"
QUIC_IMPL="${QUIC_IMPL:-msquic}"
QUIC_VERSION="${QUIC_VERSION:-v2.5.3}"

mkdir -p "$DEPS_BUILD"
cmake -S "$ROOT/deps" -B "$DEPS_BUILD"   -DQUIC_IMPL="$QUIC_IMPL"   -DQUIC_VERSION="$QUIC_VERSION"   -DDEPS_PREFIX="$DEPS_INSTALL"

cmake --build "$DEPS_BUILD" --target dep_quic --config Release
echo "==> Deps installed to: $DEPS_INSTALL"
