# Install script for directory: /home/runner/work/SoftEtherVPN/SoftEtherVPN/src/vpnbridge

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "vpnbridge" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge"
         RPATH "/usr/local/lib")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge" TYPE EXECUTABLE PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/vpnbridge")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge"
         OLD_RPATH "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "vpnbridge" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/vpnbridge/CMakeFiles/vpnbridge.dir/install-cxx-module-bmi-Release.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "vpnbridge" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/hamcore.se2")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "vpnbridge" OR NOT CMAKE_INSTALL_COMPONENT)
  file(WRITE /home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/vpnbridge.sh "#!/bin/sh
exec ${CMAKE_INSTALL_PREFIX}/libexec/softether/vpnbridge/vpnbridge \"$@\"
")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "vpnbridge" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE PROGRAM RENAME "vpnbridge" FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/vpnbridge.sh")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "vpnbridge" OR NOT CMAKE_INSTALL_COMPONENT)
  set(DIR "${CMAKE_INSTALL_PREFIX}/libexec")
configure_file(/home/runner/work/SoftEtherVPN/SoftEtherVPN/systemd/softether-vpnbridge.service /home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/softether-vpnbridge.service)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "vpnbridge" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/lib/systemd/system/softether-vpnbridge.service")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/lib/systemd/system" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/softether-vpnbridge.service")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/vpnbridge/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
