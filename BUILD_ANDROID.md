# SoftEther VPN for Android

Native Android client that drives the existing SoftEther C core (`src/Mayaqua`,
`src/Cedar`) through a small JNI shim and Android's `VpnService` (L3, IP-only).

## Architecture

```
MainActivity (Compose UI)
   |  mini-CFG string ("key=value" lines)
   v
VpnEngine : VpnService  --establish()--> tun fd (ParcelFileDescriptor)
   |
   v
SeNative (JNI) -> se_jni.c -> CEDAR + NewClientSessionEx
   |
   v
VLanAndroid (src/Cedar/VLanAndroid.c): user-space L2<->L3 bridge
  - PACKET_ADAPTER <-> in-process SOCK over a TUBE pair
  - IPC.c machinery: ARP + DHCPv4 + IPv6 ND/RA in user space
  - pump thread: IPCSendIPv4/IPCRecvIPv4 <-> read()/write() on tun fd
```

`src/Cedar/VLanAndroid.c` / `.h` are compiled only when `UNIX_ANDROID` is
defined (empty translation units on Windows/Linux/macOS, so the Visual Studio
and autoconf/CMake builds are unaffected).

## Project layout

- `SoftEtherVPN-Android/` — Gradle project (Android Studio).
  - `app/src/main/cpp/se_jni.c` — JNI shim (init/release/connect/status/IPv4 info/SetTunFd/disconnect).
  - `CMakeLists.txt` (the Gradle module root) — the Android build entry point:
    adds the repo root as a subproject (core libs), takes dependencies from
    vcpkg, builds the JNI shim (`app/src/main/cpp/se_jni.c`) into
    `libsoftether.so`, and rewrites `local.properties` (`sdk.dir`) so the folder
    is ready for Gradle / Android Studio.
  - `app/src/main/java/org/softether/android/` — `MainActivity.kt` (Compose),
    `VpnEngine.kt` (VpnService), `SeNative.kt` (JNI + config model).

## Prerequisites

1. Android SDK with platform 35/36, platform-tools, **NDK r30** (`30.0.16248370`)
   and the SDK **`cmake` 4.1.2** package. AGP 9.5.1 + Gradle 9.6.1 (wrapper
   included) run on modern JDKs (tested on Temurin 25). Point Gradle at the SDK
   via `local.properties` (`sdk.dir=...`) or `ANDROID_HOME`.
2. [vcpkg](https://github.com/microsoft/vcpkg) (clone + `bootstrap-vcpkg`
   anywhere) and `ANDROID_NDK_HOME` **exported** pointing at the NDK from (1) —
   vcpkg builds its Android ports through it. Dependencies always come from
   vcpkg: the repo-root `vcpkg.json` manifest declares openssl/libsodium/zlib
   and Gradle triggers the install (vcpkg **manifest mode**; the installed tree
   lands inside the CMake build dir). The Android triplets chainload the NDK
   toolchain, so every port is rebuilt against *bionic* — host `apt`/multiarch
   packages cannot be used (they link against glibc).
3. Tell Gradle where vcpkg lives — property `-Pvcpkg.root=<vcpkg>` (or env
   `VCPKG_ROOT`; required, the configure fails immediately with a message saying
   so) and `-Pvcpkg.triplet=<triplet>` (or env `VCPKG_TARGET_TRIPLET`, default
   `arm64-android`). Gradle then feeds the vcpkg toolchain file, the manifest
   directory (the repo root) and the chainloaded NDK toolchain (slash paths, so
   Windows backslashes don't leak into CMake caches) to the entry point.

## Building

The Android entry point is `SoftEtherVPN-Android/CMakeLists.txt` (the Gradle
module root): building `all` there yields exactly the Android-relevant targets
(libhamcore, hamcorebuilder, mayaqua, cedar, `libsoftether.so`) — the main
SoftEther project is never configured for Android on its own (the desktop
executables are not even added). Every successful configure rewrites
`SoftEtherVPN-Android/local.properties` (`sdk.dir`, written as `I\:/dev/...` —
Properties-escaped), so the Gradle folder is left ready for Android Studio or
plain `./gradlew` runs.

- Android Studio: open `SoftEtherVPN-Android/`, set `vcpkg.root`/`vcpkg.triplet`
  (e.g. in `gradle.properties`) plus `ANDROID_NDK_HOME`, sync, Run.
- CLI from `SoftEtherVPN-Android/` (Windows git-bash example):

  ```sh
  ANDROID_NDK_HOME=I:/dev/AndroidSdk/ndk/30.0.16248370 \
    ./gradlew assembleDebug -Pvcpkg.root=I:/dev/vcpkg -Pvcpkg.triplet=arm64-android
  ```

  APK lands in `app/build/outputs/apk/debug/app-debug.apk`.
- ABIs: one vcpkg triplet per build — `arm64-android`→`arm64-v8a`,
  `x64-android`→`x86_64`, `arm-neon-android`→`armeabi-v7a` (`abiFilters`
  follows the triplet).
- Gradle is the verified path; the same configure can be run standalone against
  `SoftEtherVPN-Android/` (see the header comment of its `CMakeLists.txt` for a
  ready-made command line).

## Building on Linux / WSL2

Same contract, no admin rights anywhere. Verified on Debian trixie under WSL2:

```sh
sudo apt-get install -y build-essential autoconf autoconf-archive automake \
  libtool libtool-bin pkg-config curl unzip zip openjdk-21-jdk
# Android SDK command-line tools, then:
sdkmanager "platform-tools" "platforms;android-36" "build-tools;36.0.0" \
  "ndk;30.0.16248370" "cmake;4.1.2"
# vcpkg
git clone https://github.com/microsoft/vcpkg --depth=1 ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh

export ANDROID_HOME=$HOME/android-sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/30.0.16248370
cd SoftEtherVPN-Android
./gradlew assembleDebug assembleRelease \
  -Pvcpkg.root=$HOME/vcpkg -Pvcpkg.triplet=arm64-android
```

The first build compiles the vcpkg ports (openssl/libsodium/zlib) for bionic —
roughly ten minutes; the result is cached and reused by later builds (per
build-type/ABI directory). `gradlew` needs `chmod +x` when the tree is copied
without preserving modes. The SDK `cmake;4.1.2` package also ships ninja, so
the SDK alone covers CMake/Ninja.

## Connection configuration (account CFG)

A profile is a standard SoftEther **account CFG text** — the exact format
`vpncmd`/vpnclient use for account import/export: the `# SoftEther VPN ...`
banner (with `hostname=`/`virtual_hub=` style lines) plus
`ClientOption`/`ClientAuth` blocks. `se_jni.c` reads and re-emits it with the
same `Cfg*` folder functions the desktop tools use (`nativeCfgDefault`
template, `nativeCfgParse`/`nativeCfgCompose` round-trip — unknown keys
survive untouched, so every Developer-Edition client setting round-trips),
plus `nativeHashPassword`/`nativeEncryptPassword`/`nativeDecryptPassword`.
Android's network options live in a **separate `declare AndroidOptions`
folder** (sibling of ClientOption/ClientAuth — the native folder is never
polluted with keys stock vpncmd wouldn't contain): `UseIPv4/UseIPv6`,
`IPv4Mode/IPv6Mode`, `StaticIp/StaticMask/StaticGw/Dns1/Dns2`, IPv6
equivalents, routes modes and manual/ignored route lists.

Auth rules: empty password → anonymous (`AuthType 0`); typed password →
SHA-1 hash auth (`AuthType 1` + `HashedPassword`); a stored
`EncryptedPassword` (`AuthType 2`) is kept as-is. `nativeConnect` takes the
CFG text directly (`declare` detection); the older line-based `key=value`
mini-CFG exists only as a legacy fallback.
