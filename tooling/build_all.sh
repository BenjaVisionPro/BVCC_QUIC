#!/usr/bin/env bash
# build_all.sh — one-button build: deps -> lib -> dist
#
# Usage:
#   tooling/build_all.sh [--clean] [--impl <msquic>] [--version <v2.5.3>] [--dist-root <path>] [--openssl-root <path>] [--keylog]
#
# Notes:
# - Delegates to:
#     tooling/build_deps.sh
#     tooling/build_lib.sh
#     tooling/build_dist.sh
# - Ensures consistent env across steps and makes OpenSSL discoverable for MsQuic.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---- Defaults (can be overridden by CLI or environment) ----------------------
QUIC_IMPL_DEFAULT="${QUIC_IMPL:-msquic}"
QUIC_VERSION_DEFAULT="${QUIC_VERSION:-v2.5.3}"

BUILD_DIR_DEFAULT="${BUILD_DIR:-$ROOT/build}"
DEPS_BUILD_DEFAULT="${DEPS_BUILD:-$BUILD_DIR_DEFAULT/deps-build}"
DEPS_INSTALL_DEFAULT="${DEPS_INSTALL:-$BUILD_DIR_DEFAULT/deps/install}"
BVC_BUILD_DEFAULT="${BVC_BUILD:-$BUILD_DIR_DEFAULT/bvc-build}"

# The dist root (top-level, sibling of build/)
DIST_ROOT_DEFAULT="${DIST_ROOT:-$ROOT/dist}"

CLEAN=0
QUIC_IMPL="$QUIC_IMPL_DEFAULT"
QUIC_VERSION="$QUIC_VERSION_DEFAULT"
DIST_ROOT="$DIST_ROOT_DEFAULT"

# Let caller predefine OPENSSL_ROOT_DIR; we may auto-detect if not set.
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-}"

# TLS keylog (default OFF). CLI --keylog or env BVCQ_ENABLE_KEYLOG=1 will enable.
ENABLE_KEYLOG="${BVCQ_ENABLE_KEYLOG:-0}"

# ---- CLI parsing -------------------------------------------------------------
print_help() {
  cat <<EOF
Usage: tooling/build_all.sh [options]

Options:
  --clean                 Remove ./build (but keep ./dist) before building
  --impl <name>           QUIC implementation (default: $QUIC_IMPL_DEFAULT)
  --version <tag>         QUIC version/tag (default: $QUIC_VERSION_DEFAULT)
  --dist-root <path>      Output distributables root (default: $DIST_ROOT_DEFAULT)
  --openssl-root <path>   Root prefix of OpenSSL 3 installation (passed to CMake as OPENSSL_ROOT_DIR)
  --keylog                Build lib with TLS key logging enabled (OFF by default)
  -h, --help              Show this help

Environment overrides (optional):
  BUILD_DIR, DEPS_BUILD, DEPS_INSTALL, BVC_BUILD, DIST_ROOT, QUIC_IMPL, QUIC_VERSION, OPENSSL_ROOT_DIR, BVCQ_ENABLE_KEYLOG
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean) CLEAN=1; shift ;;
    --impl) QUIC_IMPL="${2:?}"; shift 2 ;;
    --version) QUIC_VERSION="${2:?}"; shift 2 ;;
    --dist-root) DIST_ROOT="${2:?}"; shift 2 ;;
    --openssl-root) OPENSSL_ROOT_DIR="${2:?}"; shift 2 ;;
    --keylog) ENABLE_KEYLOG=1; shift ;;
    -h|--help) print_help; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; print_help; exit 1 ;;
  esac
done

# ---- Sanity checks -----------------------------------------------------------
req() { [[ -x "$1" ]] || { echo "missing or not executable: $1" >&2; exit 1; }; }

DEPS_SH="$ROOT/tooling/build_deps.sh"
LIB_SH="$ROOT/tooling/build_lib.sh"
DIST_SH="$ROOT/tooling/build_dist.sh"

req "$DEPS_SH"
req "$LIB_SH"
req "$DIST_SH"

# ---- Clean (optional) --------------------------------------------------------
if [[ "$CLEAN" -eq 1 ]]; then
  echo ">> clean: removing $BUILD_DIR_DEFAULT"
  rm -rf "$BUILD_DIR_DEFAULT"
fi

# Ensure standard dirs exist
mkdir -p "$DEPS_BUILD_DEFAULT" "$DEPS_INSTALL_DEFAULT" "$BVC_BUILD_DEFAULT" "$DIST_ROOT"

# ---- OpenSSL 3 auto-detect (macOS convenience) ------------------------------
# MsQuic with QUIC_TLS_LIB=openssl needs OpenSSL 3. We make it easy for devs/CI.
if [[ -z "$OPENSSL_ROOT_DIR" ]]; then
  case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
    darwin)
      if command -v brew >/dev/null 2>&1; then
        set +e
        _brew_ossl="$(brew --prefix openssl@3 2>/dev/null)"
        _brew_rc=$?
        set -e
        if [[ $_brew_rc -eq 0 && -n "$_brew_ossl" && -d "$_brew_ossl" ]]; then
          OPENSSL_ROOT_DIR="$(_python_arg=unused; echo "$_brew_ossl")"
        fi
      fi
      if [[ -z "$OPENSSL_ROOT_DIR" ]]; then
        for p in /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3; do
          if [[ -d "$p" ]]; then OPENSSL_ROOT_DIR="$p"; break; fi
        done
      fi
      ;;
    linux) : ;;
    msys*|mingw*|cygwin*|windowsnt) : ;;
    *) : ;;
  esac
fi

if [[ -n "$OPENSSL_ROOT_DIR" ]]; then
  echo ">> OpenSSL root: $OPENSSL_ROOT_DIR"
else
  echo ">> OpenSSL root: (not set) — relying on CMake discovery (Linux) or Schannel (Windows)"
fi

# ---- Step 1: deps (MsQuic) ---------------------------------------------------
echo ">> deps: QUIC_IMPL=$QUIC_IMPL QUIC_VERSION=$QUIC_VERSION"
QUIC_IMPL="$QUIC_IMPL" \
QUIC_VERSION="$QUIC_VERSION" \
BUILD_DIR="$DEPS_BUILD_DEFAULT" \
INSTALL_PREFIX="$DEPS_INSTALL_DEFAULT" \
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR}" \
bash "$DEPS_SH"

# ---- Step 2: lib (libbvcquic) -----------------------------------------------
# The lib build expects to find msquic in the deps install we just produced.
echo ">> lib: building libbvcquic against deps at $DEPS_INSTALL_DEFAULT"
DEPS_PREFIX="$DEPS_INSTALL_DEFAULT" \
BVC_BUILD="$BVC_BUILD_DEFAULT" \
BVCQ_ENABLE_KEYLOG="$ENABLE_KEYLOG" \
bash "$LIB_SH" $( [[ "$ENABLE_KEYLOG" = "1" ]] && echo "--keylog" )

# ---- Step 3: dist (package) --------------------------------------------------
# Collect and name artifacts deterministically; put them under $DIST_ROOT/<os-arch>/
echo ">> dist: packaging artifacts to $DIST_ROOT"
DEPS_INSTALL="$DEPS_INSTALL_DEFAULT" \
BVC_BUILD="$BVC_BUILD_DEFAULT" \
DIST_ROOT="$DIST_ROOT" \
bash "$DIST_SH"

# ---- Summary -----------------------------------------------------------------
echo ""
echo "============================================"
echo "Build complete"
echo "  QUIC_IMPL        : $QUIC_IMPL"
echo "  QUIC_VERSION     : $QUIC_VERSION"
echo "  OpenSSL root     : ${OPENSSL_ROOT_DIR:-<auto/none>}"
echo "  deps install     : $DEPS_INSTALL_DEFAULT"
echo "  lib build dir    : $BVC_BUILD_DEFAULT"
echo "  dist root        : $DIST_ROOT"
echo "  keylog enabled   : ${ENABLE_KEYLOG}"
echo "Artifacts have been placed under platform/arch folders in dist/."
echo "============================================"