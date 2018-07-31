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

target_link_libraries(mayaqua OpenSSL::SSL OpenSSL::Crypto Threads::Threads ZLIB::ZLIB)

if(LIB_ICONV)
  target_link_libraries(mayaqua ${LIB_ICONV})
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
  target_link_libraries(mayaqua nsl socket)
endif()
