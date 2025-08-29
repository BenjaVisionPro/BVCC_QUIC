#!/usr/bin/env bash
set -euo pipefail

# Build libbvcquic against staged deps under build/deps/install
#
# Options:
#   --keylog               Enable TLS key logging (build-time opt-in)
#   -h | --help            Show usage
#
# Env overrides:
#   BVC_BUILD              (default: ./build/bvc-build)
#   DEPS_INSTALL           (default: ./build/deps/install)
#   BVCQ_ENABLE_KEYLOG     (default: 0; same effect as --keylog when set to 1)
#
# Notes:
#   - Requires MsQuic already staged at $DEPS_INSTALL (headers+lib)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BVC_BUILD="${BVC_BUILD:-$ROOT/build/bvc-build}"
DEPS_INSTALL="${DEPS_INSTALL:-$ROOT/build/deps/install}"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--keylog]

Options:
  --keylog            Build with TLS key logging support (OFF by default).
  -h, --help          Show this help.

Environment:
  BVC_BUILD           Build dir (default: $ROOT/build/bvc-build)
  DEPS_INSTALL        MsQuic install prefix (default: $ROOT/build/deps/install)
  BVCQ_ENABLE_KEYLOG  If "1", same as --keylog
USAGE
}

# ---------- arg parsing ----------
ENABLE_KEYLOG="${BVCQ_ENABLE_KEYLOG:-0}"
while (($#)); do
  case "$1" in
    --keylog) ENABLE_KEYLOG=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

# ---------- pick the right MsQuic lib name ----------
uname_s="$(uname || true)"
if [ "${uname_s:-}" = "Darwin" ]; then
  QUIC_LIB="libmsquic.dylib"
elif [[ "${uname_s:-}" == MINGW64_NT* || "${uname_s:-}" == MSYS_NT* || "${uname_s:-}" == CYGWIN_NT* ]]; then
  QUIC_LIB="msquic.lib"
else
  QUIC_LIB="libmsquic.so"
fi

# Windows layout quirk: import lib may be under lib/, runtime under bin/
if [ ! -f "$DEPS_INSTALL/lib/$QUIC_LIB" ] && [ -f "$DEPS_INSTALL/bin/msquic.dll" ]; then
  QUIC_LIB="msquic.lib"
fi

# ---------- CMake configure/build ----------
mkdir -p "$BVC_BUILD"

CMAKE_FLAGS=(
  -DCMAKE_BUILD_TYPE=Release
  -DMSQUIC_INCLUDE_DIR="$DEPS_INSTALL/include"
  -DMSQUIC_LIBRARY="$DEPS_INSTALL/lib/$QUIC_LIB"
)

if [ "$ENABLE_KEYLOG" = "1" ]; then
  CMAKE_FLAGS+=(-DBVCQ_ENABLE_KEYLOG=ON)
  echo ">> Keylog: ENABLED (BVCQ_ENABLE_KEYLOG=1)"
else
  CMAKE_FLAGS+=(-DBVCQ_ENABLE_KEYLOG=OFF)
  echo ">> Keylog: DISABLED (default)"
fi

cmake -S "$ROOT/libbvcquic" -B "$BVC_BUILD" "${CMAKE_FLAGS[@]}"
cmake --build "$BVC_BUILD" --config Release

echo "==> Built libbvcquic in: $BVC_BUILD"
echo "==> MsQuic include: $DEPS_INSTALL/include"
echo "==> MsQuic library: $DEPS_INSTALL/lib/$QUIC_LIB"