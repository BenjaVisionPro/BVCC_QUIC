#!/usr/bin/env bash
#
# build_test.sh — configure, build, and run tests for libbvcquic
# - Builds/stages MsQuic deps (unless RUN_DEPS=0)
# - Configures the top-level CMake (so tests live under tests/)
# - Auto-generates short-lived self-signed certs for the test server
# - Cleans the ephemeral certs on exit
#
# Env overrides:
#   RUN_DEPS=1              # build deps first (default 1)
#   CLEAN=0                 # rm -rf build dir first (default 0)
#   BUILD_TYPE=RelWithDebInfo
#   GENERATOR="Unix Makefiles"
#   INSTALL_PREFIX=<path>   # deps install (default: ./build/deps/install)
#   BUILD_DIR_TEST=<path>   # test build dir (default: ./build/test-build)
#   PARALLEL=auto|<n>       # build/test parallelism (default auto)
#   FILTER_REGEX=<regex>    # ctest -R <regex>
#   CTEST_ARGS="..."        # extra args to ctest
#
set -euo pipefail

# ---------- helpers ----------
fail(){ echo "error: $*" >&2; exit 1; }
os_name(){ uname -s; }
norm_jobs(){
  if [[ "${PARALLEL:-auto}" == "auto" ]]; then
    if command -v sysctl >/dev/null 2>&1; then
      sysctl -n hw.ncpu 2>/dev/null || echo 4
    elif command -v nproc >/dev/null 2>&1; then
      nproc
    else
      echo 4
    fi
  else
    echo "${PARALLEL}"
  fi
}

# ---------- arg parsing ----------
ENABLE_DIAG=0
for arg in "$@"; do
  case "$arg" in
    --diag) ENABLE_DIAG=1 ;;   # <— new single switch for all diagnostics
    -h|--help)
      cat <<'USAGE'
Usage: $(basename "$0") [--diag]

Options:
  --diag   Enable unified diagnostics (sets BVCQ_DIAG=1)

Environment overrides (examples):
  RUN_DEPS=0 CLEAN=1 PARALLEL=8 FILTER_REGEX='test_smoke'
USAGE
      exit 0
      ;;
    *) ;; # ignore unknown flags
  esac
done

# Later, before running cmake/ctest (or anywhere early):
if [ "$ENABLE_DIAG" = "1" ]; then
  export BVCQ_DIAG=1
fi

# ---------- paths & defaults ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RUN_DEPS="${RUN_DEPS:-1}"
CLEAN="${CLEAN:-0}"
BUILD_TYPE="${BUILD_TYPE:-RelWithDebInfo}"
GENERATOR="${GENERATOR:-Unix Makefiles}"

INSTALL_PREFIX="${INSTALL_PREFIX:-$ROOT/build/deps/install}"
BUILD_DIR_TEST="${BUILD_DIR_TEST:-$ROOT/build/test-build}"

PARALLEL="${PARALLEL:-auto}"
JOBS="$(norm_jobs)"
FILTER_REGEX="${FILTER_REGEX:-}"
CTEST_ARGS="${CTEST_ARGS:-}"

# ---------- log settings ----------
cat <<EOF
==> Settings
ROOT            = $ROOT
SRC (root)      = $ROOT
BUILD_DIR_TEST  = $BUILD_DIR_TEST
INSTALL_PREFIX  = $INSTALL_PREFIX
BUILD_TYPE      = $BUILD_TYPE
GENERATOR       = $GENERATOR
RUN_DEPS        = $RUN_DEPS
CLEAN           = $CLEAN
PARALLEL        = $JOBS
FILTER_REGEX    = ${FILTER_REGEX:-<none>}
CTEST_ARGS      = ${CTEST_ARGS:-<none>}
BVCQ_DIAG_DGRAM = $([[ "$ENABLE_DIAG" == "1" ]] && echo "ENABLED" || echo "disabled")
EOF

# ---------- deps ----------
if [[ "$RUN_DEPS" == "1" ]]; then
  echo "==> Building deps (msquic)…"
  INSTALL_PREFIX="$INSTALL_PREFIX" "$ROOT/tooling/build_deps.sh"
  echo "==> Deps installed to: $INSTALL_PREFIX"
fi

# ---------- locate msquic ----------
MSQUIC_INCLUDE_DIR="$INSTALL_PREFIX/include"
OS="$(os_name)"
case "$OS" in
  Darwin)  MSQUIC_LIBRARY="$INSTALL_PREFIX/lib/libmsquic.dylib" ;;
  Linux)   MSQUIC_LIBRARY="$INSTALL_PREFIX/lib/libmsquic.so"    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
           if [[ -f "$INSTALL_PREFIX/lib/msquic.lib" ]]; then
             MSQUIC_LIBRARY="$INSTALL_PREFIX/lib/msquic.lib"
           else
             MSQUIC_LIBRARY="$INSTALL_PREFIX/bin/msquic.dll"
           fi ;;
  *)       MSQUIC_LIBRARY="$INSTALL_PREFIX/lib/libmsquic.so" ;;
esac

[[ -f "$MSQUIC_LIBRARY" || -L "$MSQUIC_LIBRARY" ]] || fail "MsQuic library not found: $MSQUIC_LIBRARY"
[[ -f "$MSQUIC_INCLUDE_DIR/msquic.h" ]] || fail "MsQuic headers not found under: $MSQUIC_INCLUDE_DIR"

# ---------- clean? ----------
if [[ "$CLEAN" == "1" ]]; then
  echo "==> Cleaning build dir: $BUILD_DIR_TEST"
  rm -rf "$BUILD_DIR_TEST"
fi
mkdir -p "$BUILD_DIR_TEST"

# ---------- configure (top level, with tests) ----------
echo "==> Configuring project (tests ON)…"
cmake -S "$ROOT" -B "$BUILD_DIR_TEST" \
  -G "$GENERATOR" \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  -DMSQUIC_INCLUDE_DIR="$MSQUIC_INCLUDE_DIR" \
  -DMSQUIC_LIBRARY="$MSQUIC_LIBRARY" \
  -DBVCQ_BUILD_TESTS=ON

# ---------- build ----------
echo "==> Building…"
if [[ "$GENERATOR" == "Unix Makefiles" ]]; then
  cmake --build "$BUILD_DIR_TEST" -- -j"$JOBS"
else
  cmake --build "$BUILD_DIR_TEST" --parallel "$JOBS"
fi

# ---------- ephemeral test certs ----------
TMP_CERT_DIR="$(mktemp -d "$ROOT/build/tmp-certs.XXXXXX")"
cleanup(){
  local ec="${1:-$?}"
  if [[ -n "${TMP_CERT_DIR:-}" && -d "$TMP_CERT_DIR" ]]; then
    rm -rf "$TMP_CERT_DIR"
  fi
  exit "$ec"
}
trap 'cleanup $?' EXIT INT TERM

# Find openssl
OPENSSL_BIN="${OPENSSL_BIN:-}"
if [[ -z "$OPENSSL_BIN" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    OPENSSL_BIN="$(command -v openssl)"
  elif [[ -x "/opt/homebrew/opt/openssl@3/bin/openssl" ]]; then
    OPENSSL_BIN="/opt/homebrew/opt/openssl@3/bin/openssl"
  fi
fi
[[ -n "$OPENSSL_BIN" ]] || fail "openssl not found. Install OpenSSL 3 (e.g., 'brew install openssl@3')"

echo "==> Generating ephemeral test certs…"
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes \
  -keyout "$TMP_CERT_DIR/server.key" \
  -out    "$TMP_CERT_DIR/server.crt" \
  -subj "/CN=localhost" -days 1 >/dev/null 2>&1

export BVCQ_TEST_CERT="$TMP_CERT_DIR/server.crt"
export BVCQ_TEST_KEY="$TMP_CERT_DIR/server.key"

# Provide INSTALL_PREFIX so tests can copy the msquic runtime next to the test exe
export INSTALL_PREFIX="$INSTALL_PREFIX"

# ---------- optional diagnostics (per-run switch) ----------
if [[ "$ENABLE_DIAG" == "1" ]]; then
  export BVCQ_DIAG_DGRAM=1
  echo "==> Datagram diagnostics ENABLED for this test run"
fi

# ---------- diagnostics (MsQuic logging) ----------
# Always enable verbose MsQuic logging for test runs and capture to files.
export QUIC_LOGGING=1
export QUIC_LOGGING_LEVEL=Verbose
# If your MsQuic build supports a file target, use a file near the build dir:
export QUIC_LOG_FILE="${BUILD_DIR_TEST}/msquic_verbose.log"

# bvcquic internal dgram diag (already recognized by the library)
export BVCQ_DIAG_DGRAM=1

# Enable core dumps to help when a crash happens
ulimit -c unlimited || true

# ---------- test ----------
echo "==> Running tests…"
pushd "$BUILD_DIR_TEST" >/dev/null

CTEST_OPTS=( -T Test )
if [[ -n "$FILTER_REGEX" ]]; then
  CTEST_OPTS+=( -R "$FILTER_REGEX" )
fi
CTEST_OPTS+=( -j "$JOBS" )
if [[ -n "$CTEST_ARGS" ]]; then
  # shellcheck disable=SC2206
  EXTRA_ARGS=( $CTEST_ARGS )
  CTEST_OPTS+=( "${EXTRA_ARGS[@]}" )
fi

ctest --output-on-failure "${CTEST_OPTS[@]}"
ec="$?"

popd >/dev/null
exit "$ec"