file(GLOB SOURCES_MAYAQUA "*.c" "Crypto/*.c")
file(GLOB HEADERS_MAYAQUA "*.h" "Crypto/*.h")

if(WIN32)
  add_library(mayaqua STATIC ${SOURCES_MAYAQUA} ${HEADERS_MAYAQUA})
else()
  add_library(mayaqua SHARED ${SOURCES_MAYAQUA} ${HEADERS_MAYAQUA})
endif()

target_include_directories(mayaqua PUBLIC .)

set_target_properties(mayaqua
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

find_package(OpenSSL REQUIRED)

if(OPENSSL_VERSION VERSION_LESS "3") # Disable oqsprovider when OpenSSL version < 3
  add_definitions(-DSKIP_OQS_PROVIDER)
else()
  set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Set liboqs to build only the library (no tests)")
  set(BUILD_TESTING OFF CACHE BOOL "By setting this to OFF, no tests or examples will be compiled.")
  set(OQS_PROVIDER_BUILD_STATIC ON CACHE BOOL "Build a static library instead of a shared library") # Build oqsprovider as a static library (defaults to shared)
  list(PREPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/src/Mayaqua/3rdparty/")

  add_subdirectory(3rdparty/liboqs)
  add_subdirectory(3rdparty/oqs-provider)

  target_include_directories(oqsprovider PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/liboqs/include)
  set_property(TARGET oqsprovider PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(mayaqua PRIVATE oqsprovider)
endif()

include(CheckSymbolExists)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto)
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL)

check_symbol_exists(EVP_PKEY_get_raw_public_key "openssl/evp.h" HAVE_EVP_PKEY_GET_RAW_PUBLIC_KEY)
check_symbol_exists(SSL_CTX_set_num_tickets "openssl/ssl.h" HAVE_SSL_CTX_SET_NUM_TICKETS)

unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)

if(NOT HAVE_EVP_PKEY_GET_RAW_PUBLIC_KEY)
  message(FATAL_ERROR "Required EVP_PKEY_get_raw_public_key() not found in OpenSSL library!")
endif()

if (HAVE_SSL_CTX_SET_NUM_TICKETS)
  add_compile_definitions(HAVE_SSL_CTX_SET_NUM_TICKETS)
endif()



find_package(ZLIB REQUIRED)

# Required because we include <openssl/opensslv.h> in Encrypt.h.
target_include_directories(mayaqua PUBLIC ${OPENSSL_INCLUDE_DIR})

target_link_libraries(mayaqua
  PRIVATE
    libhamcore
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

if(WIN32)
  set_target_properties(mayaqua
    PROPERTIES
    COMPILE_PDB_NAME "mayaqua"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  target_link_libraries(mayaqua
    PRIVATE
      "crypt32.lib"
      "DbgHelp.Lib"
      "dwmapi.lib"
      "iphlpapi.lib"
      "newdev.lib"
      "Psapi.Lib"
      "Secur32.Lib"
      "setupapi.lib"
      "winmm.lib"
      "ws2_32.lib"
      "WtsApi32.Lib"
    )
endif()

if(UNIX)
  find_package(Threads REQUIRED)

  # In some cases libiconv is not included in libc
  find_library(LIB_ICONV iconv)

  find_library(LIB_M m)
  find_library(LIB_RT rt)

  target_link_libraries(mayaqua
    PRIVATE
      Threads::Threads
      $<$<BOOL:${LIB_ICONV}>:${LIB_ICONV}>
      $<$<BOOL:${LIB_M}>:${LIB_M}>
      $<$<BOOL:${LIB_RT}>:${LIB_RT}>
  )

  if (NOT HAVE_SYS_AUXV OR SKIP_CPU_FEATURES)
    add_definitions(-DSKIP_CPU_FEATURES)
  elseif(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(amd64|i386)")
    message("cpu_features is not available on FreeBSD/${CMAKE_SYSTEM_PROCESSOR}")
    add_definitions(-DSKIP_CPU_FEATURES)
  elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" AND NOT CMAKE_SYSTEM_NAME MATCHES "^(arm64|x86_64)")
    # macOS runs only on Intel or ARM architecrues, should not reach here
    add_definitions(-DSKIP_CPU_FEATURES)
  elseif(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS" OR ${CMAKE_SYSTEM_NAME} STREQUAL "OpenBSD")
    message("cpu_features is not available on ${CMAKE_SYSTEM_NAME}")
    add_definitions(-DSKIP_CPU_FEATURES)
  elseif(USE_SYSTEM_CPU_FEATURES)
    CHECK_INCLUDE_FILE(cpu_features_macros.h HAVE_CPU_FEATURES)
    message("-- Using system's cpu_features")
    target_link_libraries(mayaqua PRIVATE cpu_features)
  else()
    message("-- Using bundled cpu_features")
    set(BUILD_SHARED_LIBS ON)
    add_subdirectory(3rdparty/cpu_features)
    target_link_libraries(mayaqua PRIVATE cpu_features)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
    target_link_libraries(mayaqua PRIVATE nsl socket)
  endif()

  install(TARGETS mayaqua
    COMPONENT "common"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )
endif()
