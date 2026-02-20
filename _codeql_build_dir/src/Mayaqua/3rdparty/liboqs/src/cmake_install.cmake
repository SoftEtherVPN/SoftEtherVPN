# Install script for directory: /home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src

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

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/common/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/kem/kyber/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/kem/ml_kem/cmake_install.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs" TYPE FILE FILES
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/liboqsConfig.cmake"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/liboqsConfigVersion.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/liboqs.pc")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/lib/liboqs.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsTargets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsTargets.cmake"
         "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/CMakeFiles/Export/c7e97583fbc7c9ca02085e7795e05761/liboqsTargets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsTargets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs/liboqsTargets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs" TYPE FILE FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/CMakeFiles/Export/c7e97583fbc7c9ca02085e7795e05761/liboqsTargets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/liboqs" TYPE FILE FILES "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/CMakeFiles/Export/c7e97583fbc7c9ca02085e7795e05761/liboqsTargets-release.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/oqs" TYPE FILE FILES
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/oqs.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/common/aes/aes_ops.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/common/common.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/common/rand/rand.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/common/sha2/sha2_ops.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/common/sha3/sha3_ops.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/common/sha3/sha3x4_ops.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/kem/kem.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/sig/sig.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/sig_stfl/sig_stfl.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/kem/kyber/kem_kyber.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/src/Mayaqua/3rdparty/liboqs/src/kem/ml_kem/kem_ml_kem.h"
    "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/include/oqs/oqsconfig.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/runner/work/SoftEtherVPN/SoftEtherVPN/_codeql_build_dir/src/Mayaqua/3rdparty/liboqs/src/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
