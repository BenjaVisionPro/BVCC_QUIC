# ---- MsQuic ExternalProject (QuicTLS provider) ------------------------------
include(ExternalProject)

set(_msquic_repo "https://github.com/microsoft/msquic.git")

if(NOT DEFINED QUIC_VERSION)
  set(QUIC_VERSION "v2.5.3")
endif()

# TLS provider for MsQuic
if(WIN32)
  set(_tls "schannel")
else()
  set(_tls "quictls")   # macOS/Linux: use QuicTLS we built
endif()

# Optional macOS SDK pass-through
set(_osx_sysroot "")
if(APPLE)
  if(DEFINED CMAKE_OSX_SYSROOT AND NOT "${CMAKE_OSX_SYSROOT}" STREQUAL "")
    set(_osx_sysroot "${CMAKE_OSX_SYSROOT}")
  else()
    find_program(_XCRUN_EXEC xcrun)
    if(_XCRUN_EXEC)
      execute_process(
        COMMAND "${_XCRUN_EXEC}" --show-sdk-path
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE _xcrun_sdk
        ERROR_QUIET
      )
      if(NOT "${_xcrun_sdk}" STREQUAL "")
        set(_osx_sysroot "${_xcrun_sdk}")
      endif()
    endif()
  endif()
endif()

# Configure args
set(_cfg
  -DCMAKE_BUILD_TYPE=Release
  -DQUIC_TLS_LIB=${_tls}
  -DQUIC_ENABLE_LOGGING=ON
  -DCMAKE_INSTALL_PREFIX=${DEPS_PREFIX}
)

# Point MsQuic at the QuicTLS we build in deps/
if(NOT WIN32)
  if(NOT DEFINED OPENSSL_ROOT_DIR OR "${OPENSSL_ROOT_DIR}" STREQUAL "")
    # deps/CMakeLists.txt sets this to ${DEPS_PREFIX}/quictls after including quictls.make
    set(OPENSSL_ROOT_DIR "${DEPS_PREFIX}/quictls")
  endif()
  list(APPEND _cfg -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR})
endif()

if(APPLE AND NOT "${_osx_sysroot}" STREQUAL "")
  list(APPEND _cfg -DCMAKE_OSX_SYSROOT=${_osx_sysroot})
endif()

ExternalProject_Add(dep_quic
  GIT_REPOSITORY       ${_msquic_repo}
  GIT_TAG              ${QUIC_VERSION}
  UPDATE_DISCONNECTED  1
  INSTALL_DIR          ${DEPS_PREFIX}
  CMAKE_ARGS           ${_cfg}
  BUILD_BYPRODUCTS     ${DEPS_PREFIX}/include/msquic.h
  DEPENDS              dep_quictls        # <-- ensure QuicTLS builds first
)

message(STATUS "MsQuic -> ${DEPS_PREFIX} (TLS=${_tls})")
if(NOT WIN32)
  message(STATUS "  Using OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
endif()