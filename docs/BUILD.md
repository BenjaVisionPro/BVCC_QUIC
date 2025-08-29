# Building libbvcquic

This repository intentionally separates **dependencies** (MsQuic) from **our wrapper** so builds are reproducible and easy to reason about.

## Quick start

```bash
# 1) Build dependencies (MsQuic v2.5.3 by default)
tooling/build_deps.sh

# 2) Copy your sources (if not already present)
#   libbvcquic/include/bvc_quic.h
#   libbvcquic/src/*.[ch]

# 3) Build libbvcquic against the staged deps
tooling/build_lib.sh

# 4) Collect artifacts (library + msquic runtime + headers)
tooling/build_all.sh
```

Artifacts will be placed under `build/artifacts/`:
- `libbvcquic.{dylib|so|dll}`
- `libmsquic.{dylib|so}` or `msquic.dll` (co-located)
- `include/bvc_quic.h` (only the public API)

## Overrides

- `QUIC_IMPL`: currently `"msquic"` only.
- `QUIC_VERSION`: tag/sha, default `v2.5.3`.
- Paths:
  - `DEPS_BUILD`: default `build/deps-build`
  - `DEPS_INSTALL`: default `build/deps/install`
  - `BVC_BUILD`: default `build/bvc-build`
  - `ARTIFACTS`: default `build/artifacts`

Example:
```bash
QUIC_VERSION=v2.5.3 DEPS_BUILD=/tmp/depb tooling/build_deps.sh
DEPS_INSTALL=/tmp/depinst BVC_BUILD=/tmp/bvclib tooling/build_lib.sh
```

## Platform notes

- **macOS / Linux:**  
  - MsQuic is built with `QUIC_TLS_LIB=quictls`.  
  - Auto-detects OpenSSL 3 from system or Homebrew (`/opt/homebrew/opt/openssl@3`).  
  - `bvc_quic_get_wakeup_handle()` returns `NULL` (use the wakeup pipe via `bvc_quic_drain_events`).

- **Windows:**  
  - MsQuic is built with `QUIC_TLS_LIB=schannel` (no OpenSSL required).  
  - Runtime ships as `msquic.dll` under `install/bin`, import lib under `install/lib`.  
  - `bvc_quic_get_wakeup_handle()` returns the internal event handle (cast to `void*`).

## Why two-file drop-in?

Shipping `libbvcquic` alongside the MsQuic runtime keeps deployments simple, avoids system-global dependencies, and makes versioning explicit.

## CI tips

Cache `build/deps-build/_src/msquic` and `build/deps/install` keyed by `QUIC_VERSION`. Then run `tooling/build_lib.sh` to compile the wrapper quickly.

## Public API surface

The installed header `bvc_quic.h` exposes only the stable FFI:  
- Types (`bvcq_lib`, `bvcq_conn`, `bvcq_stream`, etc.)  
- Enums / status codes  
- API functions (`bvc_quic_*`)  
- Required macros (`BVCQ_API`, `BVCQ_CALL`)  

No internal structs, logging macros, or MsQuic headers are exposed.
