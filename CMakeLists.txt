cmake_minimum_required(VERSION 3.10)

set(BUILD_NUMBER CACHE STRING "The number of the current build.")

if ("${BUILD_NUMBER}" STREQUAL "")
	set(BUILD_NUMBER "5180")
endif()

if (BUILD_NUMBER LESS 5180)
	message(WARNING
		"Setting BUILD_NUMBER to a value less than 5180 will break compatibility with client binaries distributed by SoftEther Corporation. "
		"Set to a value greater than or equal to 5180 if you want such clients to work properly.\n"
		"For detailed info: https://github.com/SoftEtherVPN/SoftEtherVPN/issues/1392#issuecomment-867348281")
endif()

#
# Link MSVC runtime statically
# this should be revisited after installer migration to MSI
#
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project("SoftEther VPN"
  VERSION "5.02.${BUILD_NUMBER}"
  LANGUAGES C
)

set(CMAKE_C_STANDARD 99)

set(TOP_DIRECTORY ${CMAKE_SOURCE_DIR})
set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR})

# We define a dedicated variable because CMAKE_BUILD_TYPE can have different
# configurations than "Debug" and "Release", such as "RelWithDebInfo".
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(BUILD_TYPE "Debug")
else()
  set(BUILD_TYPE "Release")
endif()

# Check that submodules are present only if source was downloaded with git
if(EXISTS "${TOP_DIRECTORY}/.git" AND NOT EXISTS "${TOP_DIRECTORY}/src/libhamcore/CMakeLists.txt")
    message (FATAL_ERROR "Submodules are not initialized. Run\n\tgit submodule update --init --recursive")
endif()

if(WIN32 AND VCPKG_TARGET_TRIPLET AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message (FATAL_ERROR "vcpkg not installed or integrated with Visual Studio. Install it and run\n\tvcpkg integrate install")
endif()

if(UNIX)
  include(GNUInstallDirs)

  #
  # use rpath for locating installed libraries
  #
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

  include(CheckIncludeFile)
  Check_Include_File(sys/auxv.h HAVE_SYS_AUXV)
  if(EXISTS "/lib/systemd/system")
    set(CMAKE_INSTALL_SYSTEMD_UNITDIR "/lib/systemd/system" CACHE STRING "Where to install systemd unit files")
  endif()
endif()

configure_file("${TOP_DIRECTORY}/AUTHORS.TXT" "${TOP_DIRECTORY}/src/bin/hamcore/authors.txt" COPYONLY)

# Date and time
string(TIMESTAMP DATE_DAY "%d" UTC)
string(TIMESTAMP DATE_MONTH "%m" UTC)
string(TIMESTAMP DATE_YEAR "%Y" UTC)
string(TIMESTAMP TIME_HOUR "%H" UTC)
string(TIMESTAMP TIME_MINUTE "%M" UTC)
string(TIMESTAMP TIME_SECOND "%S" UTC)

message(STATUS "Build date: ${DATE_DAY}/${DATE_MONTH}/${DATE_YEAR}")
message(STATUS "Build time: ${TIME_HOUR}:${TIME_MINUTE}:${TIME_SECOND}")

add_subdirectory(src)

if(UNIX)
  # Packaging
  set(CPACK_COMPONENTS_ALL common vpnserver vpnclient vpnbridge vpncmd)
  set(CPACK_PACKAGE_DIRECTORY ${BUILD_DIRECTORY})
  set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
  set(CPACK_PACKAGE_VENDOR "SoftEther")
  set(CPACK_PACKAGE_NAME "softether")
  set(CPACK_PACKAGE_DESCRIPTION_FILE "${TOP_DIRECTORY}/description")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SoftEther VPN is an open-source cross-platform multi-protocol VPN program, created as an academic project in the University of Tsukuba.")

  # DEB
  if(BUILD_TYPE STREQUAL "Debug")
    set(CPACK_DEBIAN_PACKAGE_DEBUG ON)
  endif()

  set(CPACK_DEB_COMPONENT_INSTALL ON)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
  set(CPACK_DEBIAN_PACKAGE_SECTION "net")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Unknown")

  # RPM
  set(CPACK_RPM_COMPONENT_INSTALL ON)
  set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
  set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
  set(CPACK_RPM_PACKAGE_LICENSE "ASL 2.0")

  # Exclude system directories
  if(CPACK_GENERATOR STREQUAL "RPM")
    execute_process(
        COMMAND rpm -ql filesystem
        COMMAND tr \n \;
        OUTPUT_VARIABLE CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
        ERROR_QUIET)
  endif()

  include(CPack)
endif()
