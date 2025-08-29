# Dependency driver: fetch & build MsQuic and install into a controlled prefix.
# Output layout:
#   <install>/include/msquic*.h
#   <install>/lib/{libmsquic.so|libmsquic.dylib|msquic.lib}
#   <install>/{bin/msquic.dll on Windows}

cmake_minimum_required(VERSION 3.16)
project(bvcc_deps C)

include(ExternalProject)

# Public cache knobs (override via -D on configure)
set(QUIC_IMPL "msquic" CACHE STRING "QUIC implementation to build (currently: msquic)")
set(QUIC_VERSION "v2.5.3" CACHE STRING "Version/tag for QUIC implementation")
set(DEPS_PREFIX "${CMAKE_BINARY_DIR}/../deps/install" CACHE PATH "Install prefix for built deps")

# QuicTLS tag/version (override if you prefer)
set(QUICTLS_VERSION "openssl-3.1.5+quic" CACHE STRING "QuicTLS (OpenSSL+QUIC) version/tag")

message(STATUS "Deps: QUIC_IMPL=${QUIC_IMPL}")
message(STATUS "Deps: QUIC_VERSION=${QUIC_VERSION}")
message(STATUS "Deps: DEPS_PREFIX=${DEPS_PREFIX}")
if(NOT WIN32)
  message(STATUS "Deps: QUICTLS_VERSION=${QUICTLS_VERSION}")
endif()

# --- Build QuicTLS first on macOS/Linux --------------------------------------
if(NOT WIN32)
	include(${CMAKE_CURRENT_LIST_DIR}/impls/quictls/quictls.make)
	# Point MsQuic at our freshly built QuicTLS
	set(OPENSSL_ROOT_DIR "${DEPS_PREFIX}/quictls" CACHE PATH "OpenSSL root (via QuicTLS)" FORCE)
	message(STATUS "Deps: OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
endif()

# --- Build MsQuic -------------------------------------------------------------
if(QUIC_IMPL STREQUAL "msquic")
  include(${CMAKE_CURRENT_LIST_DIR}/impls/msquic/msquic.make)
else()
  message(FATAL_ERROR "Unsupported QUIC_IMPL: ${QUIC_IMPL}")
endif()