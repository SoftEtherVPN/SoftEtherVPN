cmake_minimum_required(VERSION 3.22)

project(softether C)

# When built through AGP we do not use the vcpkg toolchain file; the Gradle
# script passes the per-triplet installed tree instead.
set(SE_VCPKG_INSTALL "" CACHE PATH "vcpkg installed directory for the target triplet")
if(SE_VCPKG_INSTALL)
  list(APPEND CMAKE_PREFIX_PATH "${SE_VCPKG_INSTALL}")
  if(EXISTS "${SE_VCPKG_INSTALL}/share/unofficial-sodium/unofficial-sodiumConfig.cmake")
    set(unofficial-sodium_DIR "${SE_VCPKG_INSTALL}/share/unofficial-sodium")
  endif()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsigned-char")

set(SE_SRC_DIR "" CACHE PATH "SoftEther source directory (src/)")
if(NOT SE_SRC_DIR)
  get_filename_component(SE_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src" ABSOLUTE)
endif()
set(SRC_DIR "${SE_SRC_DIR}")

file(GLOB MAYAQUA_SOURCES "${SRC_DIR}/Mayaqua/*.c" "${SRC_DIR}/Mayaqua/Crypto/*.c")
file(GLOB CEDAR_SOURCES "${SRC_DIR}/Cedar/*.c")
file(GLOB HAMCORE_SOURCES "${SRC_DIR}/libhamcore/*.c")

add_library(softether SHARED
  ${MAYAQUA_SOURCES}
  ${CEDAR_SOURCES}
  ${HAMCORE_SOURCES}
  ${CMAKE_CURRENT_SOURCE_DIR}/se_jni.c
)

target_include_directories(softether PRIVATE
  ${SRC_DIR}
  ${SRC_DIR}/Mayaqua
  ${SRC_DIR}/Cedar
  ${SRC_DIR}/libhamcore/include
)

target_compile_definitions(softether PRIVATE
  UNIX OS_UNIX UNIX_LINUX UNIX_ANDROID
  SKIP_CPU_FEATURES SKIP_OQS_PROVIDER
  _REENTRANT REENTRANT _THREAD_SAFE _THREADSAFE THREAD_SAFE THREADSAFE
  _FILE_OFFSET_BITS=64 NDEBUG VPN_SPEED
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_compile_definitions(softether PRIVATE CPU_64)
endif()

# NDK sysroot provides the zlib API (zlib.h + libz.so); vcpkg tree has no ZLIB config.
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

if(SE_VCPKG_INSTALL)
  # The NDK toolchain re-roots every find_package call to the sysroot, so
  # neither Module nor Config FindOpenSSL can see the vcpkg tree; use its
  # static libraries directly.
  set(OPENSSL_FOUND TRUE)
  set(OPENSSL_INCLUDE_DIR "${SE_VCPKG_INSTALL}/include")
  if(NOT EXISTS "${SE_VCPKG_INSTALL}/lib/libcrypto.a")
    message(FATAL_ERROR "libcrypto.a not found under ${SE_VCPKG_INSTALL} (run vcpkg install --triplet <triplet> in the vcpkg root)")
  endif()
  add_library(OpenSSL::Crypto STATIC IMPORTED)
  add_library(OpenSSL::SSL STATIC IMPORTED)
  set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION "${SE_VCPKG_INSTALL}/lib/libcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES "ZLIB::ZLIB;-ldl"
  )
  set_target_properties(OpenSSL::SSL PROPERTIES
    IMPORTED_LOCATION "${SE_VCPKG_INSTALL}/lib/libssl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES "OpenSSL::Crypto"
  )
else()
  find_package(OpenSSL CONFIG QUIET)
  if(NOT OpenSSL_FOUND)
    find_package(OpenSSL REQUIRED)
  endif()
endif()

target_include_directories(softether PRIVATE ${OPENSSL_INCLUDE_DIR})

include(CheckSymbolExists)
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL)
check_symbol_exists(SSL_CTX_set_num_tickets "openssl/ssl.h" HAVE_SSL_CTX_SET_NUM_TICKETS)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)
if(HAVE_SSL_CTX_SET_NUM_TICKETS)
  target_compile_definitions(softether PRIVATE HAVE_SSL_CTX_SET_NUM_TICKETS)
endif()

target_link_libraries(softether PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  Threads::Threads
)

# BLAKE2 (for Proto_WireGuard): pick the optimized variant for the target CPU,
# mirroring src/Cedar/CMakeLists.txt
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" SE_CPU_LOWER)
if(ANDROID_ABI STREQUAL "arm64-v8a" OR SE_CPU_LOWER MATCHES "^(arm64|aarch64)")
  set(BLAKE2_DIR "${SRC_DIR}/../3rdparty/BLAKE2/neon")
  set(BLAKE2_SRC_FILE "${BLAKE2_DIR}/blake2s-neon.c")
elseif(ANDROID_ABI STREQUAL "x86_64" OR SE_CPU_LOWER MATCHES "^(x86_64|amd64)")
  set(BLAKE2_DIR "${SRC_DIR}/../3rdparty/BLAKE2/sse")
  set(BLAKE2_SRC_FILE "${BLAKE2_DIR}/blake2s.c")
  target_compile_definitions(softether PRIVATE HAVE_SSE2)
else()
  set(BLAKE2_DIR "${SRC_DIR}/../3rdparty/BLAKE2/ref")
  set(BLAKE2_SRC_FILE "${BLAKE2_DIR}/blake2s-ref.c")
endif()
target_sources(softether PRIVATE ${BLAKE2_SRC_FILE})
target_include_directories(softether PRIVATE ${BLAKE2_DIR})

find_package(PkgConfig QUIET)
if(SE_VCPKG_INSTALL)
  # vcpkg's sodium config expects variables only its toolchain sets; import directly.
  if(NOT EXISTS "${SE_VCPKG_INSTALL}/lib/libsodium.a")
    message(FATAL_ERROR "libsodium.a not found under ${SE_VCPKG_INSTALL} (run vcpkg install --triplet <triplet> in the vcpkg root)")
  endif()
  add_library(unofficial-sodium::sodium STATIC IMPORTED)
  set_target_properties(unofficial-sodium::sodium PROPERTIES
    IMPORTED_LOCATION "${SE_VCPKG_INSTALL}/lib/libsodium.a"
    INTERFACE_INCLUDE_DIRECTORIES "${SE_VCPKG_INSTALL}/include"
  )
  target_link_libraries(softether PRIVATE unofficial-sodium::sodium)
elseif(DEFINED VCPKG_TARGET_TRIPLET)
  find_package(unofficial-sodium CONFIG REQUIRED)
  target_link_libraries(softether PRIVATE unofficial-sodium::sodium)
elseif(PKG_CONFIG_FOUND)
  pkg_search_module(SODIUM REQUIRED libsodium)
  target_include_directories(softether PRIVATE ${SODIUM_INCLUDE_DIRS})
  target_link_directories(softether PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_link_libraries(softether PRIVATE ${SODIUM_LINK_LIBRARIES} ${SODIUM_LINK_FLAGS})
else()
  message(FATAL_ERROR "libsodium not found. Install libsodium, or use vcpkg with the sodium port.")
endif()

if(ANDROID)
  target_link_libraries(softether PRIVATE log m)
elseif(UNIX)
  target_link_libraries(softether PRIVATE m)
endif()
