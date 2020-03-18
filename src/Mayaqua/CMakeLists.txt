file(GLOB SOURCES_MAYAQUA "*.c")
file(GLOB HEADERS_MAYAQUA "*.h")

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

if(WIN32)
  set_target_properties(mayaqua
    PROPERTIES
    COMPILE_PDB_NAME "mayaqua"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  add_subdirectory(3rdparty/zlib)

  target_include_directories(mayaqua PRIVATE win32_inc)
  target_include_directories(mayaqua PRIVATE 3rdparty/zlib)

  if(${COMPILER_ARCHITECTURE} STREQUAL "x64")
    find_library(LIB_SSL
      NAMES libssl ssleay32
      HINTS "${TOP_DIRECTORY}/src/BuildFiles/Library/vs2017/x64_${BUILD_TYPE}"
    )

    find_library(LIB_CRYPTO
      NAMES libcrypto libeay32
      HINTS "${TOP_DIRECTORY}/src/BuildFiles/Library/vs2017/x64_${BUILD_TYPE}"
    )
  else()
    find_library(LIB_SSL
      NAMES libssl ssleay32
      HINTS "${TOP_DIRECTORY}/src/BuildFiles/Library/vs2017/Win32_${BUILD_TYPE}"
    )

    find_library(LIB_CRYPTO
      NAMES libcrypto libeay32
      HINTS "${TOP_DIRECTORY}/src/BuildFiles/Library/vs2017/Win32_${BUILD_TYPE}"
    )
  endif()

  target_link_libraries(mayaqua PRIVATE zlibstatic ${LIB_SSL} ${LIB_CRYPTO})
endif()

if(UNIX)
  find_package(OpenSSL REQUIRED)
  find_package(Threads REQUIRED)
  find_package(ZLIB REQUIRED)

  # In some cases libiconv is not included in libc
  find_library(LIB_ICONV iconv)

  find_library(LIB_RT rt)

  target_link_libraries(mayaqua PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads ZLIB::ZLIB)

  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(armv7l|aarch64|s390x)$" OR NOT HAVE_SYS_AUXV OR SKIP_CPU_FEATURES)
    add_definitions(-DSKIP_CPU_FEATURES)
  else()
    add_subdirectory(3rdparty/cpu_features)
    set_property(TARGET cpu_features PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(mayaqua PRIVATE cpu_features)
  endif()

  if(LIB_RT)
    target_link_libraries(mayaqua PRIVATE rt)
  endif()

  if(LIB_ICONV)
    target_link_libraries(mayaqua PRIVATE ${LIB_ICONV})
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
