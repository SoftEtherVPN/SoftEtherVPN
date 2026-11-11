#
# Android build folder — this CMakeLists is THE entry point for Android builds.
# The main SoftEther project never builds Android by default; the core (repo
# root) is pulled in here as a subproject and the default target "all" builds
# ONLY Android-relevant targets: libhamcore, hamcorebuilder, mayaqua, cedar
# and the JNI shared library "softether" defined below.  Desktop executables
# are not added when ANDROID (see src/CMakeLists.txt).
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
# Gradle/AGP drives this same file through externalNativeBuild (the Gradle
# script adds the vcpkg toolchain file + manifest directory arguments); after
# any configure the Gradle project itself is ready: this file rewrites
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

get_filename_component(SE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../../" ABSOLUTE)

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
add_library(softether SHARED "${CMAKE_CURRENT_SOURCE_DIR}/se_jni.c")
target_include_directories(softether PRIVATE
  "${SE_REPO_ROOT}/src"
  "${SE_REPO_ROOT}/src/Cedar"
  "${SE_REPO_ROOT}/src/libhamcore/include")
target_link_libraries(softether PRIVATE cedar mayaqua log m)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(softether PRIVATE SE_DEBUG_LOG)
endif()

# Gradle glue: derive the SDK from the NDK path the toolchain reported and
# keep local.properties current (Android Studio / plain gradle need sdk.dir).
# Slashes are valid in .properties and Java's Properties parser eats
# backslashes ("I:\dev\..." -> "I:devAndroidSdk"), so do NOT convert.
if(DEFINED CMAKE_ANDROID_NDK)
  get_filename_component(_se_sdk_dir "${CMAKE_ANDROID_NDK}/../.." ABSOLUTE)
  file(WRITE "${SE_REPO_ROOT}/SoftEtherVPN-Android/local.properties" "sdk.dir=${_se_sdk_dir}\n")
endif()
