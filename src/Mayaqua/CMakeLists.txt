file(GLOB SOURCES_MAYAQUA "*.c")
file(GLOB HEADERS_MAYAQUA "*.h")

add_library(mayaqua STATIC ${SOURCES_MAYAQUA} ${HEADERS_MAYAQUA})

target_include_directories(mayaqua PUBLIC .)

set_target_properties(mayaqua
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Mayaqua"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Mayaqua"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Mayaqua"
)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)

# In some cases libiconv is not included in libc
find_library(LIB_ICONV iconv)

if(HAVE_SYS_AUXV)
  add_subdirectory(cpu_features)
endif()

target_include_directories(mayaqua PRIVATE cpu_features/include)

target_link_libraries(mayaqua OpenSSL::SSL OpenSSL::Crypto Threads::Threads ZLIB::ZLIB)

if(HAVE_SYS_AUXV)
  target_link_libraries(mayaqua cpu_features)
else()
  add_definitions(-DSKIP_CPU_FEATURES)
endif()

find_library(LIB_RT rt)
if(LIB_RT)
  target_link_libraries(mayaqua rt)
endif()

if(LIB_ICONV)
  target_link_libraries(mayaqua ${LIB_ICONV})
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
  target_link_libraries(mayaqua nsl socket)
endif()
