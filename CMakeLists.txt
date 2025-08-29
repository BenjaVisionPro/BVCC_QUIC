# Top-level CMake for BVCC QUIC wrapper workspace.
# Primary build flows remain in tooling/*.sh. This file is intentionally small.
#
# - By default we only enable tests from here.
# - When tests are ON, we add the library subdir so tests can link the real target.
#
# Scripts should pass:
#   -DMSQUIC_INCLUDE_DIR=/path/to/build/deps/install/include
#   -DMSQUIC_LIBRARY=/path/to/build/deps/install/lib/libmsquic.{dylib,so} (or msquic.lib on Windows)

cmake_minimum_required(VERSION 3.16)

# We need C here because, when tests are ON, we build the library too.
project(bvcc_workspace LANGUAGES C)

# ---- Build options --------------------------------------------------------
option(BVCQ_BUILD_TESTS "Build bvcquic tests" ON)
option(BVCQ_ENABLE_KEYLOG "Enable TLS key logging support (disabled by default for security)" OFF)
option(BVCQ_ENABLE_DIAG   "Enable verbose diagnostics (may impact performance)" ON)

# These flags are picked up by libbvcquic/CMakeLists.txt
if (BVCQ_ENABLE_KEYLOG)
  add_compile_definitions(BVCQ_ENABLE_KEYLOG=1)
endif()

if (NOT BVCQ_ENABLE_DIAG)
  add_compile_definitions(BVCQ_NO_DIAG=1)
endif()

# ---- Tests ---------------------------------------------------------------
if (BVCQ_BUILD_TESTS)
  # Forward MsQuic locations (they may be provided by scripts or cache).
  set(MSQUIC_INCLUDE_DIR "${MSQUIC_INCLUDE_DIR}" CACHE PATH "Path to MsQuic headers (contains msquic.h)")
  set(MSQUIC_LIBRARY     "${MSQUIC_LIBRARY}"     CACHE FILEPATH "Path to MsQuic library (.so/.dylib/.lib)")

  # Build the library in-tree so tests can link the real 'bvcquic' target.
  add_subdirectory(libbvcquic)

  # Now add tests that link against the 'bvcquic' target.
  enable_testing()
  add_subdirectory(tests)
endif()