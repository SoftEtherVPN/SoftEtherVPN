file(GLOB SOURCES_MAYAQUA "*.c")
file(GLOB HEADERS_MAYAQUA "*.h")

add_library(mayaqua SHARED ${SOURCES_MAYAQUA} ${HEADERS_MAYAQUA})

target_include_directories(mayaqua PUBLIC .)

set_target_properties(mayaqua
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)

# In some cases libiconv is not included in libc
find_library(LIB_ICONV iconv)

if(HAVE_SYS_AUXV)
  add_subdirectory(cpu_features)
  set_property(TARGET cpu_features PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()

target_include_directories(mayaqua PRIVATE cpu_features/include)

target_link_libraries(mayaqua PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads ZLIB::ZLIB)

if(HAVE_SYS_AUXV)
  target_link_libraries(mayaqua PRIVATE cpu_features)
else()
  add_definitions(-DSKIP_CPU_FEATURES)
endif()

find_library(LIB_RT rt)
if(LIB_RT)
  target_link_libraries(mayaqua PRIVATE ${LIB_RT})
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
