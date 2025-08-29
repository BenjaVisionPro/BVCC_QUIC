cmake_minimum_required(VERSION 3.16)

# Build and run unit tests for bvcquic.
# We link against the in-tree "bvcquic" target and copy its runtime
# sidecars (libbvcquic + libmsquic) next to each test exe so the
# dynamic loader can resolve everything without global installs.

enable_language(C)

# ---- Platform helpers ------------------------------------------------------
set(_OS "${CMAKE_SYSTEM_NAME}")
string(TOLOWER "${_OS}" _OSL)
if(_OSL STREQUAL "darwin")
  set(_EXT "dylib")
  set(_MSQUIC_NAME "libmsquic.dylib")
  set(_BVC_NAME "libbvcquic.dylib") # actual file name we copy (soname handled by linker)
elseif(_OSL STREQUAL "linux")
  set(_EXT "so")
  set(_MSQUIC_NAME "libmsquic.so")
  set(_BVC_NAME "libbvcquic.so")
else()
  set(_EXT "dll")
  set(_MSQUIC_NAME "msquic.dll")
  set(_BVC_NAME "bvcquic.dll")
endif()

# ---- Locate msquic runtime -------------------------------------------------
# Prefer the library path passed to the lib build, then fallback to env.
# MSQUIC_LIBRARY is a cache var defined by libbvcquic/CMakeLists.
set(_MSQUIC_CAND "")
if(DEFINED MSQUIC_LIBRARY AND EXISTS "${MSQUIC_LIBRARY}")
  if(WIN32)
    get_filename_component(_msquic_libdir "${MSQUIC_LIBRARY}" DIRECTORY)
    find_file(_msquic_dll "${_MSQUIC_NAME}"
      PATHS "${_msquic_libdir}" "${_msquic_libdir}/../bin" "${_msquic_libdir}/.."
      NO_CACHE NO_DEFAULT_PATH)
    if(_msquic_dll)
      set(_MSQUIC_CAND "${_msquic_dll}")
    endif()
  else()
    set(_MSQUIC_CAND "${MSQUIC_LIBRARY}") # This is the actual runtime on *nix
  endif()
endif()

if(NOT _MSQUIC_CAND AND DEFINED ENV{INSTALL_PREFIX})
  # Fallback to typical layout in our deps install prefix
  set(_MSQUIC_CAND "$ENV{INSTALL_PREFIX}/lib/${_MSQUIC_NAME}")
  if(WIN32 AND NOT EXISTS "${_MSQUIC_CAND}")
    set(_MSQUIC_CAND "$ENV{INSTALL_PREFIX}/bin/${_MSQUIC_NAME}")
  endif()
endif()

if(NOT _MSQUIC_CAND OR NOT EXISTS "${_MSQUIC_CAND}")
  message(WARNING "MsQuic runtime not found; tests may fail to load. Looked for: ${_MSQUIC_CAND}")
endif()

# ---- Locate msquic headers (so msquic probe tests can include <msquic.h>) ---
set(_MSQUIC_INCLUDE_DIR "")
if(DEFINED ENV{INSTALL_PREFIX})
  if(EXISTS "$ENV{INSTALL_PREFIX}/include/msquic.h")
    set(_MSQUIC_INCLUDE_DIR "$ENV{INSTALL_PREFIX}/include")
  endif()
endif()
if(NOT _MSQUIC_INCLUDE_DIR AND DEFINED MSQUIC_LIBRARY)
  get_filename_component(_msquic_libdir_hint "${MSQUIC_LIBRARY}" DIRECTORY)
  foreach(_cand "${_msquic_libdir_hint}/../include" "${_msquic_libdir_hint}/include" "${_msquic_libdir_hint}/../../include")
    if(EXISTS "${_cand}/msquic.h")
      set(_MSQUIC_INCLUDE_DIR "${_cand}")
      break()
    endif()
  endforeach()
endif()
if(_MSQUIC_INCLUDE_DIR)
  message(STATUS "MsQuic headers: ${_MSQUIC_INCLUDE_DIR}")
else()
  message(WARNING "MsQuic headers not found; tests that include <msquic.h> may fail to compile.")
endif()

# ---- Tiny util lib ---------------------------------------------------------
add_library(testutil STATIC test_util.c)
target_include_directories(testutil PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(testutil PUBLIC bvcquic)

# ---- RPATH for test executables --------------------------------------------
function(_bvcq_set_runtime_paths tgt)
  if(APPLE)
    set_target_properties(${tgt} PROPERTIES
      BUILD_RPATH "@loader_path"
      INSTALL_RPATH "@loader_path")
  elseif(UNIX)
    set_target_properties(${tgt} PROPERTIES
      BUILD_RPATH "\$ORIGIN"
      INSTALL_RPATH "\$ORIGIN")
  endif()
endfunction()

# ---- Copy sidecars next to each test exe -----------------------------------
function(_bvcq_co_locate_sidecars tgt)
  # Copy libbvcquic next to the test
  add_custom_command(TARGET ${tgt} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:bvcquic> $<TARGET_FILE_DIR:${tgt}>/${_BVC_NAME}
    VERBATIM)
  # Copy libmsquic if we found it
  if(EXISTS "${_MSQUIC_CAND}")
    add_custom_command(TARGET ${tgt} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "${_MSQUIC_CAND}" $<TARGET_FILE_DIR:${tgt}>/
      VERBATIM)
  endif()
endfunction()

# ---- Helper to declare a test ----------------------------------------------
# Adds _MSQUIC_INCLUDE_DIR to include path (harmless for tests that don't use it).
function(bvcq_add_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${_MSQUIC_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE bvcquic testutil)

  _bvcq_set_runtime_paths(${name})
  _bvcq_co_locate_sidecars(${name})

  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES TIMEOUT 30)
endfunction()

# ---- Individual tests -------------------------------------------------------
bvcq_add_test(test_smoke               test_smoke.c)
bvcq_add_test(test_stream_io           test_stream_io.c)
bvcq_add_test(test_datagrams           test_datagrams.c)
bvcq_add_test(test_events_api          test_events_api.c)
bvcq_add_test(test_errors              test_errors.c)
bvcq_add_test(test_stats               test_stats.c)
bvcq_add_test(test_msquic_roles        test_msquic_roles.c)
bvcq_add_test(test_msquic_credload     test_msquic_credload.c)

# ---- Extended coverage tests ------------------------------------------------
bvcq_add_test(test_cert_defer          test_cert_defer.c)
bvcq_add_test(test_alpn_mismatch       test_alpn_mismatch.c)
bvcq_add_test(test_datagram_echo       test_datagram_echo.c)
bvcq_add_test(test_stream_backpressure test_stream_backpressure.c)
bvcq_add_test(test_stream_read_enable  test_stream_read_enable.c)
bvcq_add_test(test_stream_many         test_stream_many.c)
bvcq_add_test(test_shutdown_order      test_shutdown_order.c)
bvcq_add_test(test_stats_activity      test_stats_activity.c)
bvcq_add_test(test_handshake_info      test_handshake_info.c)
bvcq_add_test(test_keylog_flag         test_keylog_flag.c)
bvcq_add_test(test_events_client_connect         test_events_client_connect.c)
