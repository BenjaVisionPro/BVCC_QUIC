#!/usr/bin/env bash
#
# build_dist.sh — produce a self-contained dist layout where our library
# and its runtime deps (msquic + quictls) live in the SAME directory.
#
# Final naming (no TLS suffix, no quictls tag):
#   macOS : dist/macos-<arch>/libbvcquic-<impl>-macos-<arch>.dylib
#   Linux : dist/linux-<arch>/libbvcquic-<impl>-linux-<arch>.so
#   Win   : dist/windows-<arch>/bvcquic-<impl>-windows-<arch>.dll
#
# Dependencies copied into SAME platform dir:
#   - libmsquic.{dylib,so,dll}
#   - libssl & libcrypto from QuicTLS (quictls)
#
# Loader hints:
#   - macOS: add @loader_path to RPATH of ALL copied dylibs
#   - Linux: set RUNPATH=$ORIGIN (if patchelf present) for ALL copied .so
#   - Windows: same-folder DLL load works by default
#
# Inputs (env overrides):
#   QUIC_IMPL       : msquic (default)
#   INSTALL_PREFIX  : deps install root (default: ./build/deps/install)
#   BVC_BUILD       : cmake build dir for libbvcquic (default: ./build/bvc-build)
#   BUILD_DIRS      : extra search roots (pipe-separated) for our compiled lib
#   ROOT            : project root (auto)
#
# Usage: ./tooling/build_dist.sh

set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }

norm_arch() {
  local m="${1:-}"
  case "$m" in
    arm64|aarch64) echo "arm64" ;;
    x86_64|amd64)  echo "x86_64" ;;
    *)             echo "$m" ;;
  esac
}

norm_os() {
  case "$(uname -s)" in
    Darwin)                               echo "macos"   ;;
    Linux)                                echo "linux"   ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)      echo "windows" ;;
    *)                                    echo "$(uname -s)" ;;
  esac
}

lib_ext_for() {
  case "$1" in
    macos)   echo "dylib" ;;
    linux)   echo "so"    ;;
    windows) echo "dll"   ;;
    *)       echo "so"    ;;
  esac
}

# ----- paths & inputs -----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"

QUIC_IMPL="${QUIC_IMPL:-msquic}"
OS="$(norm_os)"
ARCH="$(norm_arch "$(uname -m)")"
EXT="$(lib_ext_for "$OS")"

INSTALL_PREFIX="${INSTALL_PREFIX:-$ROOT/build/deps/install}"
BVC_BUILD="${BVC_BUILD:-$ROOT/build/bvc-build}"
BUILD_DIRS="${BUILD_DIRS:-$BVC_BUILD|$ROOT/build/artifacts|$ROOT}"

DIST_ROOT="$ROOT/dist"
DIST_PLAT="$DIST_ROOT/$OS-$ARCH"
DIST_INCLUDE="$DIST_ROOT/include"

mkdir -p "$DIST_PLAT" "$DIST_INCLUDE"

echo "==> dist target: $DIST_PLAT"

# ----- locate our lib (be generous about where CMake might have put it) -----
declare -a CANDIDATES=()
if [[ "$OS" == "windows" ]]; then
  CANDIDATES+=("$BVC_BUILD/Release/bvcquic.dll" "$BVC_BUILD/bvcquic.dll" "$ROOT/build/artifacts/bvcquic.dll")
else
  CANDIDATES+=("$BVC_BUILD/libbvcquic.$EXT" "$ROOT/build/artifacts/libbvcquic.$EXT")
fi

IFS='|' read -r -a EXTRA_DIRS <<< "$BUILD_DIRS"
for d in "${EXTRA_DIRS[@]}"; do
  if [[ "$OS" == "windows" ]]; then
    CANDIDATES+=("$d/bvcquic.dll" "$d/Release/bvcquic.dll")
  else
    CANDIDATES+=("$d/libbvcquic.$EXT")
  fi
done

OUR_LIB_SRC=""
for f in "${CANDIDATES[@]}"; do
  [[ -f "$f" ]] && { OUR_LIB_SRC="$f"; break; }
done
[[ -n "$OUR_LIB_SRC" ]] || fail "could not find built libbvcquic (searched: ${CANDIDATES[*]})"

# Final name for our lib (no TLS / provider suffix)
if [[ "$OS" == "windows" ]]; then
  OUR_LIB_DST="$DIST_PLAT/bvcquic-${QUIC_IMPL}-${OS}-${ARCH}.dll"
else
  OUR_LIB_DST="$DIST_PLAT/libbvcquic-${QUIC_IMPL}-${OS}-${ARCH}.${EXT}"
fi

cp -f "$OUR_LIB_SRC" "$OUR_LIB_DST"
echo "==> wrote $(basename "$OUR_LIB_DST")"

# ----- helper: rpath/runpath fixups for colocated libs -----
fixup_macos_rpath() {
  local lib="$1"
  command -v install_name_tool >/dev/null 2>&1 || return 0
  # Ensure the lib's id uses @rpath (helps consumers)
  install_name_tool -id "@rpath/$(basename "$lib")" "$lib" || true
  # Ensure @loader_path is an rpath entry
  if command -v otool >/dev/null 2>&1; then
    if ! otool -l "$lib" | grep -q '@loader_path'; then
      install_name_tool -add_rpath "@loader_path" "$lib" || true
    fi
  else
    install_name_tool -add_rpath "@loader_path" "$lib" || true
  fi
}

fixup_linux_runpath() {
  local lib="$1"
  command -v patchelf >/dev/null 2>&1 || return 0
  patchelf --set-rpath '$ORIGIN' "$lib" || true
}

fixup_lib_paths() {
  local lib="$1"
  case "$OS" in
    macos)  fixup_macos_rpath "$lib" ;;
    linux)  fixup_linux_runpath "$lib" ;;
    *)      ;;
  esac
}

# ----- copy msquic side-by-side (same directory) -----
case "$OS" in
  macos)
    MSQUIC_CAND=(
      "$INSTALL_PREFIX/lib/libmsquic.dylib"
      "$INSTALL_PREFIX/bin/libmsquic.dylib"
    )
    ;;
  linux)
    MSQUIC_CAND=(
      "$INSTALL_PREFIX/lib/libmsquic.so"
      "$INSTALL_PREFIX/lib64/libmsquic.so"
      "$INSTALL_PREFIX/bin/libmsquic.so"
    )
    ;;
  windows)
    MSQUIC_CAND=(
      "$INSTALL_PREFIX/bin/msquic.dll"
      "$INSTALL_PREFIX/lib/msquic.dll"
    )
    ;;
  *)
    MSQUIC_CAND=()
    ;;
esac

MSQUIC_SRC=""
for f in "${MSQUIC_CAND[@]}"; do
  [[ -f "$f" ]] && { MSQUIC_SRC="$f"; break; }
done

if [[ -n "$MSQUIC_SRC" ]]; then
  cp -f "$MSQUIC_SRC" "$DIST_PLAT/"
  MSQUIC_DST="$DIST_PLAT/$(basename "$MSQUIC_SRC")"
  echo "==> copied $(basename "$MSQUIC_SRC") next to our lib"
  fixup_lib_paths "$MSQUIC_DST"
else
  echo "warn: msquic not found under $INSTALL_PREFIX — did you run build_deps?" >&2
fi

# ----- copy QuicTLS (OpenSSL+QUIC) runtime sidecars: libssl + libcrypto -----
# Default prefix where quictls was installed by deps build
QUICTLS_PREFIX="${QUICTLS_PREFIX:-$INSTALL_PREFIX/quictls}"

declare -a QT_SSL_CAND=()
declare -a QT_CRYPTO_CAND=()

case "$OS" in
  macos)
    QT_SSL_CAND=(
      "$QUICTLS_PREFIX/lib/libssl.dylib"
      "$QUICTLS_PREFIX/lib/libssl.3.dylib"
    )
    QT_CRYPTO_CAND=(
      "$QUICTLS_PREFIX/lib/libcrypto.dylib"
      "$QUICTLS_PREFIX/lib/libcrypto.3.dylib"
    )
    ;;
  linux)
    QT_SSL_CAND=(
      "$QUICTLS_PREFIX/lib/libssl.so"
      "$QUICTLS_PREFIX/lib64/libssl.so"
      "$QUICTLS_PREFIX/lib/libssl.so.3"
      "$QUICTLS_PREFIX/lib64/libssl.so.3"
    )
    QT_CRYPTO_CAND=(
      "$QUICTLS_PREFIX/lib/libcrypto.so"
      "$QUICTLS_PREFIX/lib64/libcrypto.so"
      "$QUICTLS_PREFIX/lib/libcrypto.so.3"
      "$QUICTLS_PREFIX/lib64/libcrypto.so.3"
    )
    ;;
  windows)
    QT_SSL_CAND=(
      "$QUICTLS_PREFIX/bin/libssl-3*.dll"
      "$QUICTLS_PREFIX/bin/libssl*.dll"
    )
    QT_CRYPTO_CAND=(
      "$QUICTLS_PREFIX/bin/libcrypto-3*.dll"
      "$QUICTLS_PREFIX/bin/libcrypto*.dll"
    )
    ;;
esac

copy_first_match() {
  local outvar="$1"; shift
  local -a globs=("$@")
  local f
  for g in "${globs[@]}"; do
    for f in $g; do
      [[ -f "$f" ]] && { printf '%s' "$f"; return 0; }
    done
  done
  return 1
}

QT_SSL_SRC="$(copy_first_match QT_SSL_SRC "${QT_SSL_CAND[@]}" || true)"
QT_CRYPTO_SRC="$(copy_first_match QT_CRYPTO_SRC "${QT_CRYPTO_CAND[@]}" || true)"

if [[ -n "${QT_SSL_SRC:-}" && -n "${QT_CRYPTO_SRC:-}" ]]; then
  cp -f "$QT_SSL_SRC" "$DIST_PLAT/"
  cp -f "$QT_CRYPTO_SRC" "$DIST_PLAT/"
  echo "==> copied $(basename "$QT_SSL_SRC"), $(basename "$QT_CRYPTO_SRC")"
  fixup_lib_paths "$DIST_PLAT/$(basename "$QT_SSL_SRC")"
  fixup_lib_paths "$DIST_PLAT/$(basename "$QT_CRYPTO_SRC")"
else
  echo "warn: QuicTLS runtime (libssl/libcrypto) not found under $QUICTLS_PREFIX" >&2
  echo "      If you used system OpenSSL instead of QuicTLS, this may be expected." >&2
fi

# ----- headers (platform-agnostic) -----
if [[ -f "$ROOT/libbvcquic/include/bvc_quic.h" ]]; then
  cp -f "$ROOT/libbvcquic/include/bvc_quic.h" "$DIST_INCLUDE/"
  echo "==> copied public header to dist/include/"
fi

# ----- loader hints so sidecars are discovered in-place -----
fixup_lib_paths "$OUR_LIB_DST"

echo "==> dist complete at: $DIST_PLAT"
ls -la "$DIST_PLAT"