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

find_package(Threads)
find_library(LIB_READLINE readline)
find_library(LIB_NCURSES ncurses)
find_library(LIB_Z z)

# In some cases libiconv is not included in libc
find_library(LIB_ICONV iconv)

# This is required in order to link to the correct OpenSSL library
find_library(LIB_SSL
  NAMES ssl
  HINTS "/usr/local/opt/openssl/lib"
)

find_library(LIB_CRYPTO
  NAMES crypto
  HINTS "/usr/local/opt/openssl/lib"
)

target_link_libraries(mayaqua ${CMAKE_THREAD_LIBS_INIT} ${LIB_SSL} ${LIB_CRYPTO} ${LIB_READLINE} ${LIB_NCURSES} ${LIB_Z})

if(LIB_ICONV)
  target_link_libraries(mayaqua ${LIB_ICONV})
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
  target_link_libraries(mayaqua nsl socket)
endif()
