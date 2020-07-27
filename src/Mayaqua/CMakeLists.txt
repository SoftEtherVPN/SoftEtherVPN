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

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

target_link_libraries(mayaqua PRIVATE OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB)

if(WIN32)
  set_target_properties(mayaqua
    PROPERTIES
    COMPILE_PDB_NAME "mayaqua"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )
endif()

if(UNIX)
  find_package(Threads REQUIRED)

  # In some cases libiconv is not included in libc
  find_library(LIB_ICONV iconv)

  find_library(LIB_RT rt)

  target_link_libraries(mayaqua PRIVATE Threads::Threads)

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
