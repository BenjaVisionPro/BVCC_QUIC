# QUIC sidecar for BenjaVision Catalyst Connect (libbvcquic)

This project provides a common surface (see bvc_quic.h) for using quic sockets in event driven applications. Targets include FFI in GemStone / Pharo and Unreal Engine c++. It is tested to interoperate with the SwiftNIO QUIC implementation as a minimum.

It's role is to insulate users from known quirks in various QUIC implementations with a goal of providing common instrumentation and benchmarking.

Maybe, in the future, QUIC sockets will become first class citizens across platforms and we can scrap this project, but until that day, this should do the trick.

# Building libbvcquic

This repository separates **dependencies** (MsQuic) from **our wrapper** so builds are reproducible, portable, and easy to reason about.

## Quick start

```bash
# Build everything and stage the distribution.
tooling/build_all.sh [--diag] [--keylog]
```

or you can do each bit individually to get the same result

```bash
# 1) Build dependencies (MsQuic v2.5.3 by default)
tooling/build_deps.sh

# 2) Build libbvcquic against the staged deps
tooling/build_lib.sh  [--diag] [--keylog]

# 3) Produce a platform-specific distribution layout
tooling/build_dist.sh

# 4) Run the full test suite (optional, but strongly recommended)
tooling/build_test.sh
```

## Outputs

- **Distributions:** under `dist/`
  - `dist/macos-arm64/…` (or `linux-x86_64/`, `windows-x86_64/`, etc.)
  - Includes:
    - `libbvcquic-<impl>-<os>-<arch>.<ext>`  
    - the matching `libmsquic` sidecar (`.dylib`/`.so`/`msquic.dll`)  
    - headers under `dist/include/`

- **Headers:** always copied to `dist/include/`

This layout ensures ops/dev teams can copy *a single directory* per platform into a target system.

## Overrides

- **QUIC_IMPL**: currently `"msquic"` only.
- **QUIC_VERSION**: tag/sha, default `v2.5.3`.
- **Paths**:
  - `BUILD_DIR`: default `build/bvc-build`
  - `INSTALL_PREFIX`: default `build/deps/install`
  - `DIST`: default `dist/`

Example:
```bash
QUIC_VERSION=v2.5.3 tooling/build_deps.sh
BVC_BUILD=/tmp/builddir tooling/build_lib.sh
DIST=/tmp/dist tooling/build_dist.sh
```

## Platform notes

- **macOS / Linux**  
  - MsQuic is built with `QUIC_TLS_LIB=quictls`.  
  - OpenSSL 3 is auto-detected; Homebrew installs are probed under `/opt/homebrew/opt/openssl@3`.  
  - Libraries named:  
    - `libbvcquic-msquic-macos-arm64.dylib`  
    - `libmsquic.dylib` (sidecar)

- **Windows**  
  - MsQuic is built with `QUIC_TLS_LIB=schannel` (no OpenSSL needed).  
  - Outputs include `bvcquic-msquic-windows-x86_64.dll` and `msquic.dll`.

## Tests

Run all tests with:

```bash
tooling/build_test.sh --clean
```

Options:
- `--filter <regex>` : run a subset of tests
- `--parallel <N>`   : parallel test jobs
- `--no-deps`        : skip rebuilding deps
- `--config Debug`   : override build type

## CI/CD tips

- Cache `build/deps-build/_src/msquic` and `build/deps/install` keyed by `QUIC_VERSION`.  
- Run `tooling/build_lib.sh` + `tooling/build_dist.sh` for fast incremental builds.  
- Run `tooling/build_test.sh` as a validation stage.

---

### Why this layout?

- **Deterministic**: one dist directory = one platform/arch build.  
- **Self-contained**: `libbvcquic` + `libmsquic` live side by side.  
- **Ops-friendly**: filenames include `impl-os-arch`, no ambiguity.  
- **Runtime-portable**: loader hints ensure local resolution (`@loader_path` on macOS, `$ORIGIN` on Linux, same-folder on Windows).
