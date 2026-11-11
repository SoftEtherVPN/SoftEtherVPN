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
  - `app/src/main/cpp/CMakeLists.txt` — builds `libsoftether.so` from
    `src/Mayaqua/*.c`, `src/Mayaqua/Crypto/*.c`, `src/Cedar/*.c`,
    `src/libhamcore/*.c`, a per-CPU BLAKE2 object, and `se_jni.c`.
  - `app/src/main/java/org/softether/android/` — `MainActivity.kt` (Compose),
    `VpnEngine.kt` (VpnService), `SeNative.kt` (JNI + config model).
- `tmp_stub/jni.h`, `tmp_stub/smoke.sh` — desktop smoke test (see below).

## Prerequisites

1. Android SDK with platform 35/36, platform-tools, **NDK r30** (`30.0.16248370`)
   and the SDK **`cmake` 4.1.2** package. AGP 9.5.1 + Gradle 9.6.1 (wrapper
   included) run on modern JDKs (tested on Temurin 25). Point Gradle at the SDK
   via `local.properties` (`sdk.dir=...`) or `ANDROID_HOME`.
2. [vcpkg](https://github.com/microsoft/vcpkg) and `ANDROID_NDK_HOME` exported.
   The repo-root `vcpkg.json` manifest already declares openssl/zlib/libsodium,
   so `vcpkg install` takes **no package arguments** in manifest mode and
   installs into `vcpkg_installed/<triplet>` inside this repo:

   ```sh
   # ARM devices
   ANDROID_NDK_HOME=<sdk>/ndk/30.0.16248370 ./vcpkg install --triplet arm64-android
   # x86_64 emulator
   ANDROID_NDK_HOME=<sdk>/ndk/30.0.16248370 ./vcpkg install --triplet x64-android
   ```

3. Tell Gradle where vcpkg lives — `gradle.properties`, `~/.gradle/gradle.properties`,
   env vars (`VCPKG_ROOT`/`VCPKG_TARGET_TRIPLET`) or the `-Pvcpkg.*` CLI
   properties below. Note the vcpkg **toolchain file is deliberately not used**
   (its Android chain breaks on backslash NDK paths under AGP): AGP runs the
   NDK's own toolchain, and `app/src/main/cpp/CMakeLists.txt` imports OpenSSL
   and libsodium static libraries directly from
   `vcpkg_installed/<triplet>` (`-DSE_VCPKG_INSTALL=...`), while zlib comes
   from the NDK sysroot.

## Building

- Android Studio: open `SoftEtherVPN-Android/`, sync, Run.
- CLI from the repo root (git-bash):

  ```sh
  cmd //c "SoftEtherVPN-Android\gradlew.bat -p SoftEtherVPN-Android \
    -Pvcpkg.root=C:\dev\vcpkg -Pvcpkg.triplet=arm64-android :app:assembleDebug"
  ```

  APK lands in `app/build/outputs/apk/debug/app-debug.apk`.
- ABIs: one vcpkg triplet per build — `vcpkg.triplet=arm64-android` builds
  `arm64-v8a` only, `x64-android` builds `x86_64` only (a single vcpkg tree
  cannot serve both ABIs, so `abiFilters` follows the triplet).

## Desktop smoke test (no NDK required)

`tmp_stub/smoke.sh` compiles the exact same source set (Mayaqua + Cedar +
libhamcore + BLAKE2 + se_jni with the Android definitions) with plain gcc and
links it as a shared object. Run from a Linux/WSL shell:

```sh
wsl.exe -e bash -lc "bash tmp_stub/smoke.sh"   # from the repo root
```

It prints `LINK_OK` and any undefined symbols not provided by libc/libssl/
libcrypto; the only ones expected are zlib (`compress`, `uncompress`, ...) and
libsodium (`sodium_*`, `crypto_*`), which Android supplies via libz/vcpkg.

## Connection configuration (mini-CFG)

The UI serializes the profile to a small `key=value` format understood by
`se_jni.c` (`#` lines are comments):

```
host=vpn.example.com
port=5555
udp_port=0
hub=HTTPSVPN
user=myuser
pass=mypass
encrypt=true
compress=false
ipv4=dhcp            # or: static (+ static_ip/static_mask/static_gw/dns1/dns2)
proxy_host=          # SOCKS5 when set
proxy_port=0
```

Behavior defaults: `port=5555`, `hub=SERVERVPN`, `encrypt=true`,
`compress=false`, anonymous auth when `pass` is empty, SHA-1 password auth
otherwise, 3 retries at 10 s intervals, half-connection enabled.

## Current status and limitations

- Working: TLS connection + auth, in-process L2 bridge, ARP, DHCPv4 (server
  side emulated on the client per SoftEther's L2 model), IPv4 routing
  (`0.0.0.0/0`), DNS handoff, MTU 1500, static IPv4 profile (no DHCP),
  Connect/Disconnect lifecycle, profile persistence (SharedPreferences).
- Not yet done (planned M3/M4): IPv6 (ND/RA plumbing + UI), server
  certificate trust-on-first-use and hostname verification, automatic
  reconnect, MSS clamping, RTT/UDP-mode tuning, per-app VPN, hamcore-less
  cleanup, CI packaging.
- `readline` is not available on Bionic: `Cedar/Console.c` gets a small
  `AndroidReadline` fallback under `UNIX_ANDROID` (the console is unused in
  the app).
- No `hamcore.se2` archive is required at runtime on Android (only
  vpncmd-style tools touch hamcore data).
