#
# Android build entry point — this CMakeLists (the Gradle module root) is THE
# main CMakeLists of the Android build.  The main SoftEther project never builds
# Android by default; the core (repo root, the parent of this directory) is
# pulled in here as a subproject and the default target "all" builds ONLY
# Android-relevant targets: libhamcore, hamcorebuilder, mayaqua, cedar and the
# JNI shared library "softether" defined below.  Desktop executables are not
# added when ANDROID (see src/CMakeLists.txt).
#
# Dependencies come from vcpkg on every platform (the repo's vcpkg.json
# manifest declares openssl/libsodium/zlib; the android triplets chainload the
# NDK toolchain and build everything against bionic).
#
# Standalone configure example:
#
#   cmake -B build -G Ninja ^
#     -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake ^
#     -DVCPKG_TARGET_TRIPLET=arm64-android ^
#     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29 ^
#     -DANDROID_STL=none -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build
#
# Gradle/AGP drives this same file through externalNativeBuild
# (path = "../../CMakeLists.txt", relative to the :app module; the Gradle script
# adds the vcpkg toolchain file + manifest directory arguments); after any
# configure the Gradle project itself is ready: this file rewrites
# local.properties (sdk.dir) so the folder opens in Android Studio or builds
# with ./gradlew directly.
#
cmake_minimum_required(VERSION 3.20)

project(SoftEtherVPNAndroid C)
set(CMAKE_C_STANDARD 99)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  message(FATAL_ERROR
    "This is the Android build folder: configure it with the Android toolchain. "
    "Recommended: -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake "
    "-DVCPKG_TARGET_TRIPLET=<triplet> plus -DANDROID_ABI=<abi> -DANDROID_PLATFORM=android-29.")
endif()

# Every Android dependency comes from vcpkg; without its toolchain there is
# nothing to find, so say so here instead of failing inside the core.
if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR
    "The Android build needs vcpkg (OpenSSL, libsodium, zlib). Pass it to Gradle "
    "with -Pvcpkg.root=<vcpkg> [-Pvcpkg.triplet=<triplet>] (or the VCPKG_ROOT "
    "environment variable), and set ANDROID_NDK_HOME so vcpkg can build its "
    "Android ports.")
endif()

get_filename_component(SE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../" ABSOLUTE)

# vcpkg-provided dependencies (CONFIG packages from the triplet's installed
# tree; the vcpkg toolchain puts it on CMAKE_PREFIX_PATH).
find_package(OpenSSL CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
# zlib: the vcpkg port when present, the NDK sysroot otherwise.
find_package(ZLIB REQUIRED)

# Third-party add-ons not fit for the NDK cross build (cache so the core sees them).
set(OQS_ENABLE OFF CACHE BOOL "Open Quantum Safe provider" FORCE)
set(SKIP_CPU_FEATURES ON CACHE BOOL "Skip cpu_features on Android" FORCE)

# Platform defines: the core's src/CMakeLists.txt contributes its own set at
# directory scope; the JNI shim compiled here needs the same macros so its
# view of the core headers (ABI, VLan backend) matches the libraries.
add_definitions(-DUNIX -DOS_UNIX -DUNIX_LINUX -DUNIX_ANDROID)
add_definitions(-D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64)
add_definitions(-DSKIP_CPU_FEATURES -DSKIP_OQS_PROVIDER)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_definitions(-DCPU_64)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-D_DEBUG -DDEBUG)
else()
  add_definitions(-DNDEBUG -DVPN_SPEED)
endif()

# SoftEther core (repo root) as a subproject.
add_subdirectory("${SE_REPO_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/softether-core")

# JNI shim — the single shared library the APK loads.
add_library(softether SHARED
  "${CMAKE_CURRENT_SOURCE_DIR}/app/src/main/cpp/se_jni.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/app/src/main/cpp/se_cfg.c")
target_include_directories(softether PRIVATE
  "${SE_REPO_ROOT}/src"
  "${SE_REPO_ROOT}/src/Cedar"
  "${SE_REPO_ROOT}/src/libhamcore/include")
target_link_libraries(softether PRIVATE cedar mayaqua log m)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(softether PRIVATE SE_DEBUG_LOG)
endif()

# Gradle glue: rewrite local.properties so the folder opens in Android Studio /
# plain Gradle, and record every machine-local input this configure needed (so a
# later sync without -P flags re-runs it identically).  Keys we own: sdk.dir,
# vcpkg.root, vcpkg.triplet, ndk.home — all other lines are kept as-is.
# Values are written the way java.util.Properties stores them: forward slashes
# with the drive-letter colon escaped ("I\:/dev/vcpkg"); a bare backslash inside
# a value is an escape character ("I:\dev" would read back as "I:dev").
function(se_props_value out value)
  string(REPLACE "\\" "/" _v "${value}")
  string(REPLACE ":" "\\:" _v "${_v}")
  set(${out} "${_v}" PARENT_SCOPE)
endfunction()

if(DEFINED CMAKE_ANDROID_NDK)
  set(_se_props "${CMAKE_CURRENT_LIST_DIR}/local.properties")

  set(_se_other "")
  if(EXISTS "${_se_props}")
    file(STRINGS "${_se_props}" _se_lines)
    string(REPLACE ";" "\\;" _se_lines "${_se_lines}")
    foreach(_se_line IN LISTS _se_lines)
      if(NOT _se_line MATCHES "^ *(sdk\\.dir|vcpkg\\.root|vcpkg\\.triplet|ndk\\.home) *=")
        string(APPEND _se_other "${_se_line}\n")
      endif()
    endforeach()
  endif()

  get_filename_component(_se_sdk_dir "${CMAKE_ANDROID_NDK}/../.." ABSOLUTE)
  se_props_value(_se_sdk_dir "${_se_sdk_dir}")
  se_props_value(_se_ndk_dir "${CMAKE_ANDROID_NDK}")

  set(_se_txt "sdk.dir=${_se_sdk_dir}\nndk.home=${_se_ndk_dir}\n")

  # Z_VCPKG_ROOT_DIR is the vcpkg toolchain's own root variable (cache internal);
  # the toolchain-file path is the fallback for a plain -D...TOOLCHAIN_FILE run.
  set(_se_vcpkg_root "${Z_VCPKG_ROOT_DIR}")
  if(_se_vcpkg_root STREQUAL "" AND
     CMAKE_TOOLCHAIN_FILE MATCHES "(.*)/scripts/buildsystems/vcpkg\\.cmake$")
    set(_se_vcpkg_root "${CMAKE_MATCH_1}")
  endif()
  if(NOT _se_vcpkg_root STREQUAL "")
    se_props_value(_se_vcpkg_root "${_se_vcpkg_root}")
    string(APPEND _se_txt "vcpkg.root=${_se_vcpkg_root}\n")
    if(DEFINED VCPKG_TARGET_TRIPLET AND NOT VCPKG_TARGET_TRIPLET STREQUAL "")
      string(APPEND _se_txt "vcpkg.triplet=${VCPKG_TARGET_TRIPLET}\n")
    endif()
  endif()

  file(WRITE "${_se_props}" "${_se_txt}${_se_other}")
endif()
