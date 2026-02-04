# How to build SoftEther VPN for Windows ARM64

This guide explains how to build SoftEther VPN for Windows ARM64 architecture. Windows on ARM is becoming increasingly important, especially on modern laptops and virtualized environments. This allows SoftEther VPN to run **natively on Windows ARM64**, improving performance and compatibility compared to x86 emulation.

## Requirements

- **Windows x64 host machine** (ARM64 builds are cross-compiled from x64)
- Visual Studio 2019 or 2022 (Community Edition is fine)
  
  https://visualstudio.microsoft.com/downloads

- Git for Windows (or other git tool)

  https://gitforwindows.org/

- vcpkg

  https://github.com/microsoft/vcpkg

## Installation

### Visual Studio

Download from the official site and run the installer.

Make sure to check:
- **Desktop development with C++** under *Workloads*
- **Clang C++ Tools for Windows** in *Optional* components
- **MSVC v142 - VS 2019 C++ ARM64 build tools** (or equivalent for VS 2022) in *Optional* components

### Git

Nothing special. Just follow the installer.

### vcpkg

Let's say you will install it to `C:\vcpkg`.

Open your preferred terminal and go to `C:\`. Then run these commands:

```
C:\> git clone https://github.com/microsoft/vcpkg
C:\> cd vcpkg
C:\vcpkg> bootstrap-vcpkg.bat
C:\vcpkg> vcpkg integrate install
```

## Update

### vcpkg

You are recommended to update vcpkg from time to time, so that the latest libraries are used in the build.

Go to the installation path, pull the latest repo and the binary:

```
C:\vcpkg> git pull
C:\vcpkg> bootstrap-vcpkg.bat
```

## Building

### Step 1: Build x64-native first

**Important:** For ARM64 builds, an existing `x64-native` build is required to generate `hamcore.se2`.

1. Launch Visual Studio

   Choose either **Clone a repository** to clone from GitHub or **Open a local folder** if you already have a copy.

2. Open Terminal (*View -> Terminal*). Install the needed submodules to build the project:

   `git submodule update --init --recursive`

   **Note**: This step is not necessary if you have chosen **Clone a repository** as Visual Studio automatically takes care of it.

3. Switch to folder view in the solution explorer

4. Select **x64-native** configuration from the dropdown menu below the search box

5. Visual Studio will try generating CMake cache. If not, click **Project -> Configure Cache** or **Generate Cache**.

   If CMake is busy, you will find **Generate Cache** greyed out. Wait until it finishes or click **Cancel CMake Cache Generation** to stop it.

   The initial configuration will take a longer time since it needs to download and install dependencies.

6. When *CMake generation finished* is displayed, simply go to toolbar and click **Build -> Build All**.

7. Wait for the x64 build to complete. This creates the necessary `hamcorebuilder` executable that will be reused for the ARM64 build.

### Step 2: Build arm64-on-x64

1. Switch to the **arm64-on-x64** configuration from the dropdown menu

   This configuration cross-compiles ARM64 executables using the 64-bit compiler on your x64 Windows host.

2. Click **Project -> Configure Cache** or **Generate Cache** to configure the ARM64 build.

   The ARM64 build will reuse the `hamcorebuilder` executable from the x64-native build to generate `hamcore.se2`.

3. When *CMake generation finished* is displayed, click **Build -> Build All**.

4. Once building has finished, hopefully with no errors, look in the newly created `/build` directory in the project's folder.

## Installation on Windows ARM64 Devices

### Prerequisites

- Windows 10 or Windows 11 ARM64 device
- The compiled ARM64 binaries from the build process
- Administrator privileges

### Installing the VPN Client

1. Copy the ARM64 build output to your Windows ARM64 device

2. Run `vpnsetup.exe` from the ARM64 build output

3. Select the components you want to install (typically VPN Client)

4. Follow the installation wizard

### VPN Client Driver Installation

The ARM64 Neo6 VPN driver is included in the build and targets **Windows 10 ARM64** or later.

**Important Notes:**

- The ARM64 driver is **unsigned by default**
- To use the unsigned driver, you need to:
  1. Enable Windows Test Mode by running in an Administrator Command Prompt:
     ```
     bcdedit /set testsigning on
     ```
  2. Restart your computer
  3. Install the VPN Client as described above

- For production use, the driver should be properly signed with a valid code signing certificate

### Disabling Test Mode (Optional)

After you're done testing or if you have a signed driver, you can disable Test Mode:

```
bcdedit /set testsigning off
```

Then restart your computer.

## Build Configuration Details

The **arm64-on-x64** configuration includes:

- **Cross-compilation target**: Windows ARM64
- **Compiler**: clang-cl (LLVM)
- **Toolchain**: MSVC ARM64 toolchain
- **VCPKG triplet**: arm64-windows-static
- **CPU feature detection**: ARM64 crypto extensions (AES via `PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE`)
- **BLAKE2 optimization**: NEON implementation (instead of SSE2)

## Notes

### Build Number

You can change the build number in `CMakeSettings.json`. Use any integer no less than 5180.

Delete and regenerate CMake cache after the change.

### OpenSSL

The above instruction builds OpenSSL library statically in the SoftEther binaries. This means:

- When you distribute the installer, users will not need to install OpenSSL separately
- The OpenSSL library cannot be updated without a rebuild and reinstallation of SoftEther

It's also possible to build OpenSSL library dynamically, but this requires additional configuration and is beyond the scope of this ARM64-specific guide. Refer to `BUILD_WINDOWS.md` for details on dynamic OpenSSL linking.

### Driver Signing

For production deployments, you should sign the ARM64 driver with a valid code signing certificate:

1. Obtain a code signing certificate from a trusted Certificate Authority
2. Use the Windows Driver Kit (WDK) tools to sign the driver
3. Distribute the signed driver to users

Without driver signing, users will need to enable Test Mode which reduces system security.

### Tested Environments

This ARM64 build process has been tested on:

- Windows x64 host (cross-compiling ARM64)
- Windows 10 ARM64 (VPN Client driver load and basic functionality)
- Windows 11 ARM64 devices

## Troubleshooting

### Build Fails During hamcore.se2 Generation

Make sure you have completed the x64-native build first. The ARM64 build requires the x64 `hamcorebuilder` executable.

### Driver Installation Fails

Ensure you have:
- Enabled Test Mode (for unsigned drivers)
- Administrator privileges
- Windows 10 or later ARM64

### VPN Client Doesn't Start

Check that:
- All ARM64 binaries are in the correct installation directory
- The Neo6 ARM64 driver is properly installed
- Windows Event Viewer for any error messages

## References

- Main Windows build guide: `BUILD_WINDOWS.md`
- Pull Request #2209: Windows ARM64 support
- Issue #1331: Windows ARM64 support request
