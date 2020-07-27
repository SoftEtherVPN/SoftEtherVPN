if(UNIX)
  # Creates wrapper scripts and installs them in the user's binaries directory, which is usually "/usr/local/bin".
  # This is required because symlinks use the folder they are in as working directory.
  #
  # The actual wrapper script needs to be generated at install time, not build time, because it depends on the
  # installation prefix. This is especially important when generating packages (rpm/deb) where the prefix is
  # changed from /usr to /usr/local for the install step.
  #
  # The placeholder is needed to satisfy the "install" dependency scanner which runs early.
  #
  macro(install_wrapper_script component)
    file(GENERATE OUTPUT ${BUILD_DIRECTORY}/${component}.sh
      CONTENT "# placeholder\n"
    )

    install(CODE "file(WRITE ${BUILD_DIRECTORY}/${component}.sh \"#!/bin/sh\nexec \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBEXECDIR}/softether/${component}/${component} \\\"$@\\\"\n\")"
     COMPONENT ${component}
    )

    install(PROGRAMS ${BUILD_DIRECTORY}/${component}.sh
      COMPONENT ${component}
      DESTINATION bin
      RENAME ${component}
    )
  endmacro(install_wrapper_script)

  # Same approach for systemd unit files
  #
  macro(install_unit_file component)
    file(GENERATE OUTPUT ${BUILD_DIRECTORY}/softether-${component}.service
      CONTENT "# placeholder\n"
    )

    install(CODE "set(DIR \"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBEXECDIR}\")\nconfigure_file(${TOP_DIRECTORY}/systemd/softether-${component}.service ${BUILD_DIRECTORY}/softether-${component}.service)"
      COMPONENT ${component}
    )

    install(FILES ${BUILD_DIRECTORY}/softether-${component}.service
      COMPONENT ${component}
      DESTINATION ${CMAKE_INSTALL_SYSTEMD_UNITDIR}
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
  endmacro(install_unit_file)
endif()

if(BUILD_TYPE STREQUAL "Debug")
  add_definitions(-D_DEBUG -DDEBUG)
else()
  add_definitions(-DNDEBUG -DVPN_SPEED)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(COMPILER_ARCHITECTURE "x64")
  add_definitions(-DCPU_64)
else()
  set(COMPILER_ARCHITECTURE "x86")
endif()

add_definitions(-D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64)

# Add /src to the include paths
include_directories(.)

if(WIN32)
  add_definitions(-DWIN32 -D_WINDOWS -D_CRT_SECURE_NO_WARNINGS)
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

  # custom db, log, pid directory for Unix
  set(SE_DBDIR "" CACHE STRING "Directory where config files are saved")
  set(SE_LOGDIR "" CACHE STRING "Directory where log files are written")
  set(SE_PIDDIR "" CACHE STRING "Directory where PID files are put")

  if(SE_DBDIR)
    add_definitions(-DSE_DBDIR="${SE_DBDIR}")
  endif()

  if(SE_LOGDIR)
    add_definitions(-DSE_LOGDIR="${SE_LOGDIR}")
  endif()

  if(SE_PIDDIR)
    add_definitions(-DSE_PIDDIR="${SE_PIDDIR}")
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

# vpnclient
add_subdirectory(vpnclient)

# vpnbridge
add_subdirectory(vpnbridge)

# vpncmd
add_subdirectory(vpncmd)

# vpntest
add_subdirectory(vpntest)

# hamcore.se2 archive file
add_custom_target(hamcore-archive-build
  ALL
  COMMAND hamcorebuilder "${TOP_DIRECTORY}/src/bin/hamcore/" "${BUILD_DIRECTORY}/hamcore.se2"
  DEPENDS hamcorebuilder
  COMMENT "Building hamcore.se2 archive file..."
  VERBATIM
)

if(WIN32)
  # PenCore
  add_subdirectory(PenCore)
  add_dependencies(hamcore-archive-build PenCore)

  # vpndrvinst
  add_subdirectory(vpndrvinst)
  add_dependencies(hamcore-archive-build vpndrvinst)

  # vpnsmgr
  add_subdirectory(vpnsmgr)

  # vpncmgr
  add_subdirectory(vpncmgr)

  # vpnsetup
  add_subdirectory(vpnsetup)
endif()

if(UNIX)
  # Print message after installing the targets
  install(CODE "message(\"\n----------------------------------------------------------------------------------------------------------------------------\")")
  install(CODE "message(\"Build completed successfully.\n\")")
  install(CODE "message(\"Execute 'vpnserver start' to run the SoftEther VPN Server background service.\")")
  install(CODE "message(\"Execute 'vpnbridge start' to run the SoftEther VPN Bridge background service.\")")
  install(CODE "message(\"Execute 'vpnclient start' to run the SoftEther VPN Client background service.\")")
  install(CODE "message(\"Execute 'vpncmd' to run the SoftEther VPN Command-Line Utility to configure VPN Server, VPN Bridge or VPN Client.\")")
  install(CODE "message(\"----------------------------------------------------------------------------------------------------------------------------\n\")")
endif()
