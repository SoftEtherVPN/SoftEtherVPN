#
# macOS client build entry point.
#
# Builds the SoftEther core (repo root, pulled in as a subproject) with the L3
# TUN packet adapter enabled (SE_VLAN_L3_TUN, see src/Cedar/VLanAndroid.h) and
# the plain-C bridge the Swift packet tunnel provider links against:
#
#   libmayaqua / libcedar   the unmodified core libraries
#   libsebridge.a           Bridge/se_bridge.c + se_plan.c  (API: Bridge/*.h)
#   hamcore.se2             string tables, shipped in the app bundle
#   se_bridge_test          command-line end-to-end test of the bridge
#   se_plan_test            unit test of the routing / DNS plan (Bridge/se_plan.c)
#
# The main SoftEther project never defines SE_VLAN_L3_TUN, so the desktop
# builds (./configure at the repo root) are not affected by this folder.
#
#   cmake -S SoftEtherVPN-macOS -B build-macos -DCMAKE_BUILD_TYPE=Release \
#         -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
#         -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
#   cmake --build build-macos
#
# The bridge is portable POSIX, so the same entry point also configures on
# Linux; that is how Bridge/test/run-linux-test.sh exercises it.
#
cmake_minimum_required(VERSION 3.15)

project(SoftEtherVPNmacOS C)
set(CMAKE_C_STANDARD 99)

if(NOT UNIX)
  message(FATAL_ERROR "This folder builds the macOS client (or its bridge test on Linux).")
endif()

get_filename_component(SE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../" ABSOLUTE)

# The post-quantum provider is not needed by the client bridge and only adds
# another dylib to sign; OpenSSL >= 3.5 carries the algorithms itself.
set(OQS_ENABLE OFF CACHE BOOL "Open Quantum Safe provider" FORCE)

# Core opt-ins of this client. Directory-scope, so the core subproject below
# and the bridge both see them; no other build defines either macro.
#   SE_VLAN_L3_TUN         compile the L3 TUN packet adapter (VLanAndroid.c)
#   SE_CLIENT_CERT_PROMPT  hand an unverified server certificate to the
#                          client's CHECK_CERT_PROC instead of failing inside
#                          the TLS handshake (Session.c), so the UI can show
#                          it and offer to trust it
add_definitions(-DSE_VLAN_L3_TUN -DSE_CLIENT_CERT_PROMPT)

# Platform defines: the core's src/CMakeLists.txt contributes its own set at
# its directory scope; the bridge compiled here needs the same macros so its
# view of the core headers (struct layouts, bool type) matches the libraries.
add_definitions(-DUNIX -DOS_UNIX)
add_definitions(-D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DUNIX_BSD -DUNIX_MACOS -DBRIDGE_PCAP)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_definitions(-DUNIX_LINUX)
endif()
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_definitions(-DCPU_64)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-D_DEBUG -DDEBUG)
else()
  add_definitions(-DNDEBUG -DVPN_SPEED)
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsigned-char")

# SoftEther core as a subproject. EXCLUDE_FROM_ALL: only what the bridge
# depends on is built (no vpnserver / vpnbridge / vpncmd executables).
add_subdirectory("${SE_REPO_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/softether-core" EXCLUDE_FROM_ALL)

add_library(sebridge STATIC Bridge/se_bridge.c Bridge/se_plan.c)
target_include_directories(sebridge
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/Bridge"
  PRIVATE
    "${SE_REPO_ROOT}/src"
    "${SE_REPO_ROOT}/src/Cedar"
    "${SE_REPO_ROOT}/src/libhamcore/include")
target_link_libraries(sebridge PUBLIC cedar mayaqua)
add_dependencies(sebridge hamcore-archive-build)

# Includes only se_bridge.h, like the Swift side
add_executable(se_bridge_test Bridge/test/se_bridge_test.c)
target_link_libraries(se_bridge_test PRIVATE sebridge)

# Routing / DNS plan logic: no core dependency
add_executable(se_plan_test Bridge/test/se_plan_test.c Bridge/se_plan.c)
target_include_directories(se_plan_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/Bridge")

enable_testing()
add_test(NAME se_plan COMMAND se_plan_test)
