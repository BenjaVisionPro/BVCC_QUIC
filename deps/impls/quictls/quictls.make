# ---- QuicTLS (OpenSSL fork with QUIC) ExternalProject -----------------------

include(ExternalProject)

set(QUICTLS_PREFIX "${DEPS_PREFIX}/quictls")
set(QUICTLS_REPO "https://github.com/quictls/openssl.git")

if(NOT DEFINED QUICTLS_VERSION)
  set(QUICTLS_VERSION "openssl-3.1.5+quic")
endif()

# Choose Configure target
set(_qt_target "")
if(APPLE)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "[aA][rR][mM]64")
    set(_qt_target "darwin64-arm64-cc")
  else()
    set(_qt_target "darwin64-x86_64-cc")
  endif()
elseif(UNIX)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64")
    set(_qt_target "linux-aarch64")
  else()
    set(_qt_target "linux-x86_64")
  endif()
else()
  message(FATAL_ERROR "QuicTLS recipe is only intended for macOS/Linux.")
endif()

# Optional macOS sysroot
set(_osx_sysroot_arg "")
if(APPLE AND DEFINED CMAKE_OSX_SYSROOT AND NOT "${CMAKE_OSX_SYSROOT}" STREQUAL "")
  set(_osx_sysroot_arg "--with-sysroot=${CMAKE_OSX_SYSROOT}")
endif()

ExternalProject_Add(dep_quictls
  GIT_REPOSITORY        ${QUICTLS_REPO}
  GIT_TAG               ${QUICTLS_VERSION}
  UPDATE_DISCONNECTED   1

  # OpenSSL/QuicTLS wants in-source configure/build
  BUILD_IN_SOURCE       1

  # Run Configure from the QuicTLS source dir explicitly
  CONFIGURE_COMMAND
    ${CMAKE_COMMAND} -E chdir <SOURCE_DIR>
    ${CMAKE_COMMAND} -E env PERL5LIB=""
    /usr/bin/env perl ./Configure
      ${_qt_target}
      ${_osx_sysroot_arg}
      --prefix=${QUICTLS_PREFIX}
      --openssldir=${QUICTLS_PREFIX}/ssl
      shared
      no-tests

  BUILD_COMMAND         ${CMAKE_MAKE_PROGRAM} -j
  INSTALL_COMMAND       ${CMAKE_MAKE_PROGRAM} install_sw

  BUILD_BYPRODUCTS
    ${QUICTLS_PREFIX}/include/openssl/ssl.h
    ${QUICTLS_PREFIX}/lib/libssl.${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${QUICTLS_PREFIX}/lib/libcrypto.${CMAKE_SHARED_LIBRARY_SUFFIX}

  # Capture logs so failures aren’t silent
  LOG_CONFIGURE         1
  LOG_BUILD             1
  LOG_INSTALL           1
)

message(STATUS "QuicTLS -> ${QUICTLS_PREFIX} (target=${_qt_target}, tag=${QUICTLS_VERSION})")