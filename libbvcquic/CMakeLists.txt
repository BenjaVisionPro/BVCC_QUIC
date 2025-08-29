# libbvcquic/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(bvcquic C)
set(CMAKE_C_STANDARD 11)

# ---------- Options ----------
option(BVCQ_ENABLE_KEYLOG "Build with TLS key logging support (OFF by default)" OFF)

# Inputs: where MsQuic is (set by your outer build script)
set(MSQUIC_INCLUDE_DIR "" CACHE PATH "Path to MsQuic headers directory (contains msquic.h)")
set(MSQUIC_LIBRARY     "" CACHE FILEPATH "Path to MsQuic library (.so/.dylib/.lib)")

if(NOT EXISTS "${MSQUIC_INCLUDE_DIR}/msquic.h")
  message(FATAL_ERROR "MSQUIC_INCLUDE_DIR must point to a directory containing msquic.h. Got: ${MSQUIC_INCLUDE_DIR}")
endif()
if(NOT EXISTS "${MSQUIC_LIBRARY}")
  message(FATAL_ERROR "MSQUIC_LIBRARY must point to MsQuic library file. Got: ${MSQUIC_LIBRARY}")
endif()

# Public header (for install & consumers)
set(BVCC_PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/bvc_quic.h)
if(NOT EXISTS "${BVCC_PUBLIC_HEADER}")
  message(FATAL_ERROR "Missing ${BVCC_PUBLIC_HEADER}.")
endif()

# Our split sources
file(GLOB BVCC_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
if(NOT BVCC_SOURCES)
  message(FATAL_ERROR "No .c files found under ${CMAKE_CURRENT_SOURCE_DIR}/src")
endif()

add_library(bvcquic SHARED ${BVCC_SOURCES})

target_include_directories(bvcquic
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${MSQUIC_INCLUDE_DIR}
)

# Prefer hidden visibility by default (exported via BVCQ_API)
if(NOT WIN32)
  set_target_properties(bvcquic PROPERTIES C_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
endif()

# Keylog build flag -> compile define
if(BVCQ_ENABLE_KEYLOG)
  target_compile_definitions(bvcquic PRIVATE BVCQ_ENABLE_KEYLOG=1)
endif()

target_link_libraries(bvcquic ${MSQUIC_LIBRARY})
if(WIN32)
  target_link_libraries(bvcquic ws2_32 ntdll)
endif()

set_target_properties(bvcquic PROPERTIES
  OUTPUT_NAME bvcquic
  VERSION 1.0.0
  SOVERSION 1
)

# RPATH so MsQuic can sit next to the shared lib at runtime
if(APPLE)
  set(CMAKE_MACOSX_RPATH ON)
  set_target_properties(bvcquic PROPERTIES
    MACOSX_RPATH ON
    INSTALL_NAME_DIR "@rpath"
    BUILD_WITH_INSTALL_RPATH ON
    INSTALL_RPATH "@loader_path;@loader_path/."
  )
elseif(UNIX)
  set_target_properties(bvcquic PROPERTIES
    BUILD_WITH_INSTALL_RPATH ON
    INSTALL_RPATH "$ORIGIN:$ORIGIN/."
  )
endif()

message(STATUS "Building bvcquic against:")
message(STATUS "  MsQuic include: ${MSQUIC_INCLUDE_DIR}")
message(STATUS "  MsQuic library: ${MSQUIC_LIBRARY}")
message(STATUS "  Keylog support: ${BVCQ_ENABLE_KEYLOG}")