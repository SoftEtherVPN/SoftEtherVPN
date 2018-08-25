include(GNUInstallDirs)

macro(install_wrapper_script component target destination)
  get_filename_component(filename ${target} NAME)

  file(WRITE ${CMAKE_SOURCE_DIR}/tmp/script/${filename} "#!/bin/sh\n")
  file(APPEND ${CMAKE_SOURCE_DIR}/tmp/script/${filename} "${target} \"$@\"\n")
  file(APPEND ${CMAKE_SOURCE_DIR}/tmp/script/${filename} "exit $?\n")

  install(FILES ${CMAKE_SOURCE_DIR}/tmp/script/${filename}
    COMPONENT ${component}
    DESTINATION ${destination}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  )
endmacro(install_wrapper_script)

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

# Add /src to the include paths
include_directories(.)

if(WIN32)
  message(FATAL_ERROR "Windows compilation via CMake is currently not supported.")
endif()

if(UNIX)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsigned-char")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

  add_definitions(-DUNIX)

  if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    add_definitions(-DUNIX_LINUX)
    if("$ENV{USE_MUSL}" STREQUAL "YES")
      add_definitions(-DUNIX_LINUX_MUSL)
    endif()
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    add_definitions(-DUNIX_BSD -DBRIDGE_BPF)
    include_directories(SYSTEM /usr/local/include)
    link_directories(SYSTEM /usr/local/lib)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "OpenBSD")
    add_definitions(-DUNIX_BSD -DUNIX_OPENBSD)
    include_directories(SYSTEM /usr/local/include)
    link_directories(SYSTEM /usr/local/lib)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
    add_definitions(-DUNIX_SOLARIS -DNO_VLAN)
  endif()

  if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    add_definitions(-DUNIX_BSD -DUNIX_MACOS -DBRIDGE_PCAP)
  endif()
endif()

# Cedar communication module
add_subdirectory(Cedar)

# Mayaqua kernel
add_subdirectory(Mayaqua)

# hamcorebuilder utility
add_subdirectory(hamcorebuilder)

# vpnserver
add_subdirectory(vpnserver)
get_target_property(VPNSERVER_RUNTIME_OUTPUT_DIRECTORY vpnserver RUNTIME_OUTPUT_DIRECTORY)

# vpnclient
add_subdirectory(vpnclient)
get_target_property(VPNCLIENT_RUNTIME_OUTPUT_DIRECTORY vpnclient RUNTIME_OUTPUT_DIRECTORY)

# vpnbridge
add_subdirectory(vpnbridge)
get_target_property(VPNBRIDGE_RUNTIME_OUTPUT_DIRECTORY vpnbridge RUNTIME_OUTPUT_DIRECTORY)

# vpncmd
add_subdirectory(vpncmd)
get_target_property(VPNCMD_RUNTIME_OUTPUT_DIRECTORY vpncmd RUNTIME_OUTPUT_DIRECTORY)

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

# Copy "vpnserver" directory to /usr/lib(exec)/softether/
install(DIRECTORY ${VPNSERVER_RUNTIME_OUTPUT_DIRECTORY}
  COMPONENT "vpnserver"
  DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether"
  PATTERN "*"
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# Copy "vpnclient" directory to /usr/lib(exec)/softether/
install(DIRECTORY ${VPNCLIENT_RUNTIME_OUTPUT_DIRECTORY}
  COMPONENT "vpnclient"
  DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether"
  PATTERN "*"
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# Copy "vpnbridge" directory to /usr/lib(exec)/softether/
install(DIRECTORY ${VPNBRIDGE_RUNTIME_OUTPUT_DIRECTORY}
  COMPONENT "vpnbridge"
  DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether"
  PATTERN "*"
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# Copy "vpncmd" directory to /usr/lib(exec)/softether/
install(DIRECTORY ${VPNCMD_RUNTIME_OUTPUT_DIRECTORY}
  COMPONENT "vpncmd"
  DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/softether"
  PATTERN "*"
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# Create wrapper scripts in the user's binaries directory, which is usually "/usr/local/bin".
# This is required because symlinks use the folder they are in as working directory.
install_wrapper_script("vpnserver" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnserver/vpnserver" ${CMAKE_INSTALL_FULL_BINDIR})
install_wrapper_script("vpnclient" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnclient/vpnclient" ${CMAKE_INSTALL_FULL_BINDIR})
install_wrapper_script("vpnbridge" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpnbridge/vpnbridge" ${CMAKE_INSTALL_FULL_BINDIR})
install_wrapper_script("vpncmd" "${CMAKE_INSTALL_FULL_LIBEXECDIR}/softether/vpncmd/vpncmd" ${CMAKE_INSTALL_FULL_BINDIR})

# Print message after installing the targets
install(CODE "message(\"\n----------------------------------------------------------------------------------------------------------------------------\")")
install(CODE "message(\"Build completed successfully.\n\")")
install(CODE "message(\"Execute 'vpnserver start' to run the SoftEther VPN Server background service.\")")
install(CODE "message(\"Execute 'vpnbridge start' to run the SoftEther VPN Bridge background service.\")")
install(CODE "message(\"Execute 'vpnclient start' to run the SoftEther VPN Client background service.\")")
install(CODE "message(\"Execute 'vpncmd' to run the SoftEther VPN Command-Line Utility to configure VPN Server, VPN Bridge or VPN Client.\")")
install(CODE "message(\"----------------------------------------------------------------------------------------------------------------------------\n\")")
