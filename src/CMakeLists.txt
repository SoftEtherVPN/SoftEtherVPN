include(GNUInstallDirs)

macro(install_wrapper_script target destination)
  get_filename_component(filename ${target} NAME)

  file(WRITE ${CMAKE_SOURCE_DIR}/tmp/script/${filename} "#!/bin/sh\n")
  file(APPEND ${CMAKE_SOURCE_DIR}/tmp/script/${filename} "${target} \"$@\"\n")
  file(APPEND ${CMAKE_SOURCE_DIR}/tmp/script/${filename} "exit $?\n")

  install(FILES ${CMAKE_SOURCE_DIR}/tmp/script/${filename}
    DESTINATION ${destination}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )
endmacro(install_wrapper_script)

# Cedar communication module
file(GLOB SOURCES_CEDAR "Cedar/*.c")
file(GLOB HEADERS_CEDAR "Cedar/*.h")

add_library(cedar STATIC ${SOURCES_CEDAR} ${HEADERS_CEDAR})

set_target_properties(cedar
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Cedar"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Cedar"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Cedar"
)

# Mayaqua kernel
file(GLOB SOURCES_MAYAQUA "Mayaqua/*.c")
file(GLOB HEADERS_MAYAQUA "Mayaqua/*.h")

add_library(mayaqua STATIC ${SOURCES_MAYAQUA} ${HEADERS_MAYAQUA})

target_include_directories(mayaqua PUBLIC Mayaqua)

set_target_properties(mayaqua
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Mayaqua"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Mayaqua"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/Mayaqua"
)

# hamcorebuilder utility
add_executable(hamcorebuilder hamcorebuilder/hamcorebuilder.c)

set_target_properties(hamcorebuilder
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp"
)

# vpnserver
add_executable(vpnserver vpnserver/vpnserver.c)

set_target_properties(vpnserver
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/vpnserver"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnserver"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnserver"
)

get_target_property(VPNSERVER_RUNTIME_OUTPUT_DIRECTORY vpnserver RUNTIME_OUTPUT_DIRECTORY)

# vpnclient
add_executable(vpnclient vpnclient/vpncsvc.c)

set_target_properties(vpnclient
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/vpnclient"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnclient"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnclient"
)

get_target_property(VPNCLIENT_RUNTIME_OUTPUT_DIRECTORY vpnclient RUNTIME_OUTPUT_DIRECTORY)

# vpnbridge
add_executable(vpnbridge vpnbridge/vpnbridge.c)

set_target_properties(vpnbridge
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/vpnbridge"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnbridge"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpnbridge"
)

get_target_property(VPNBRIDGE_RUNTIME_OUTPUT_DIRECTORY vpnbridge RUNTIME_OUTPUT_DIRECTORY)

# vpncmd
add_executable(vpncmd vpncmd/vpncmd.c)

set_target_properties(vpncmd
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/tmp/vpncmd"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpncmd"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/vpncmd"
)

get_target_property(VPNCMD_RUNTIME_OUTPUT_DIRECTORY vpncmd RUNTIME_OUTPUT_DIRECTORY)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-D_DEBUG -DDEBUG)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_definitions(-DNDEBUG -DVPN_SPEED)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions(-DCPU_64)
endif()

add_definitions(-D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsigned-char")

# Add /src to the include paths
include_directories(.)

if(WIN32)
  message(FATAL_ERROR "Windows compilation via CMake is currently not supported.")
endif()

if(UNIX)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

  add_definitions(-DUNIX)

  find_library(LIB_PTHREAD pthread)
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

  if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    add_definitions(-DUNIX_LINUX)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    add_definitions(-DUNIX_BSD -DBRIDGE_BPF -DNO_VLAN)
    include_directories(SYSTEM /usr/local/include)
    link_directories(SYSTEM /usr/local/lib)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "OpenBSD")
    add_definitions(-DUNIX_BSD -DNO_VLAN)
    include_directories(SYSTEM /usr/local/include)
    link_directories(SYSTEM /usr/local/lib)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
    add_definitions(-DUNIX_SOLARIS -DNO_VLAN)
    target_link_libraries(mayaqua nsl socket)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    add_definitions(-DUNIX_MACOS -DBRIDGE_PCAP)
    include_directories(SYSTEM /usr/local/opt/openssl/include)
    link_directories(SYSTEM /usr/local/opt/openssl/lib)
    target_link_libraries(cedar pcap)
  endif()
endif()

target_link_libraries(mayaqua ${LIB_PTHREAD} ${LIB_SSL} ${LIB_CRYPTO} ${LIB_READLINE} ${LIB_NCURSES} ${LIB_Z})

if(LIB_ICONV)
  target_link_libraries(mayaqua ${LIB_ICONV})
endif()

target_link_libraries(hamcorebuilder cedar mayaqua)

target_link_libraries(vpnserver cedar mayaqua)
target_link_libraries(vpnclient cedar mayaqua)
target_link_libraries(vpnbridge cedar mayaqua)
target_link_libraries(vpncmd cedar mayaqua)

# hamcore.se2 archive file
add_custom_target(hamcore-archive-build
  ALL
  COMMAND hamcorebuilder ${CMAKE_SOURCE_DIR}/src/bin/hamcore/ ${CMAKE_SOURCE_DIR}/tmp/hamcore.se2
  DEPENDS hamcorebuilder
  COMMENT "Building hamcore.se2 archive file..."
  VERBATIM
)

# Copy hamcore.se2 to vpnserver's directory
add_custom_command(TARGET hamcore-archive-build
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/tmp/hamcore.se2 ${VPNSERVER_RUNTIME_OUTPUT_DIRECTORY}
)

# Copy hamcore.se2 to vpnclient's directory
add_custom_command(TARGET hamcore-archive-build
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/tmp/hamcore.se2 ${VPNCLIENT_RUNTIME_OUTPUT_DIRECTORY}
)

# Copy hamcore.se2 to vpnbridge's directory
add_custom_command(TARGET hamcore-archive-build
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/tmp/hamcore.se2 ${VPNBRIDGE_RUNTIME_OUTPUT_DIRECTORY}
)

# Copy hamcore.se2 to vpncmd's directory
add_custom_command(TARGET hamcore-archive-build
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/tmp/hamcore.se2 ${VPNCMD_RUNTIME_OUTPUT_DIRECTORY}
)

# Copy contents of "bin" directory to /usr/lib(exec)/softether/
install(DIRECTORY "${CMAKE_SOURCE_DIR}/bin/"
  DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether"
  PATTERN "*"
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# Create wrapper scripts in the user's binaries directory, which is usually "/usr/local/bin".
# This is required because symlinks use the folder they are in as working directory.
install_wrapper_script("${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnserver/vpnserver" ${CMAKE_INSTALL_FULL_BINDIR})
install_wrapper_script("${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnclient/vpnclient" ${CMAKE_INSTALL_FULL_BINDIR})
install_wrapper_script("${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnbridge/vpnbridge" ${CMAKE_INSTALL_FULL_BINDIR})
install_wrapper_script("${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpncmd/vpncmd" ${CMAKE_INSTALL_FULL_BINDIR})

# Print message after installing the targets
install(CODE "message(\"\n----------------------------------------------------------------------------------------------------------------------------\")")
install(CODE "message(\"Build completed successfully.\n\")")
install(CODE "message(\"Execute 'vpnserver start' to run the SoftEther VPN Server background service.\")")
install(CODE "message(\"Execute 'vpnbridge start' to run the SoftEther VPN Bridge background service.\")")
install(CODE "message(\"Execute 'vpnclient start' to run the SoftEther VPN Client background service.\")")
install(CODE "message(\"Execute 'vpncmd' to run the SoftEther VPN Command-Line Utility to configure VPN Server, VPN Bridge or VPN Client.\")")
install(CODE "message(\"----------------------------------------------------------------------------------------------------------------------------\n\")")
