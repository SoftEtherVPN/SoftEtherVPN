How to build SoftEther VPN for Windows
======================================

There are several methods for using CMake but the easiest by far is through Visual Studio by importing the CMake project directly
into it. So that is what will be described below.

## Requirements

- Visual Studio 2019 or 2022 (Community Edition is fine)

  https://visualstudio.microsoft.com/downloads

- Git for Windows (or other git tool)

  https://gitforwindows.org/

- vcpkg

  https://github.com/microsoft/vcpkg

## Installation

- Visual Studio

  Download from the official site and run the installer.

  Make sure to check **Desktop development with C++** under *Workloads* and **Clang C++ Tools for Windows** in *Optional* components.

- Git

  Nothing special. Just follow the installer.

- vcpkg

  Let's say you will install it to `C:\vcpkg`.

  Open your preferred terminal and go to `C:\`. Then run these commands.

  ```
  C:\> git clone https://github.com/microsoft/vcpkg
  C:\> cd vcpkg
  C:\vcpkg> bootstrap-vcpkg.bat
  C:\vcpkg> vcpkg integrate install
  ```

## Update

- vcpkg

  You are recommended to update vcpkg from time to time, so that the latest libraries are used in the build.

  Go to the installation path, pull the latest repo and the binary:

  ```
  C:\vcpkg> git pull
  C:\vcpkg> bootstrap-vcpkg.bat
  ```
  
## Building

1. Launch Visual Studio

   Choose either **Clone a repository** to clone from GitHub or **Open a local folder** if you already have a copy.

1. Open Terminal (*View -> Terminal*). Install the needed submodules to build the project, avoiding CMake telling you to do so with:

   `git submodule update --init --recursive`

   **Note**: This step is not necessary if you have chosen **Clone a repository** as Visual Studio automatically takes care of it.

1. Switch to folder view in the solution explorer

1. Select a configuration from the dropdown menu below the search box. The default configurations are:

   - x64-native

     Build x64 executables with 64-bit compiler (most common)

   - x64-on-x86

     Cross compile x64 executables with 32-bit compiler

   - x86-native

     Build x86 executables with 32-bit compiler

   - x86-on-x64

     Cross compile x86 executables with 64-bit compiler

   On 64-bit Windows, all four configurations can be used. 32-bit platforms can only use 32-bit compiler.

1. Visual Studio will try generating CMake cache. If not, click **Project -> Configure Cache** or **Generate Cache**.

   If CMake is busy, you will find **Generate Cache** greyed out. Wait until it finishes or click **Cancel CMake Cache Generation** to stop it.

   The initial configuration will take a longer time since it needs to download and install dependencies.

1. When *CMake generation finished* is displayed, simply go to toolbar and click **Build -> Build All**.

1. Once building has finished, hopefully with no errors, look in the newly created `/build` directory in the project's folder.

   Run `vpnsetup.exe` to install desired components.

1. Congrats, you now have a complete CMake development environment for SoftEtherVPN on Windows, enjoy and happy contributing!

## Notes

1. Build number

   You can change the build number in `CMakeSettings.json`. Use any integer no less than 5180.

   Delete and regenerate CMake cache after the change.

1. OpenSSL

   The above instruction builds OpenSSL library statically in the SoftEther binaries,
   so that when you distribute the installer to others they will not need to install OpenSSL separately.
   However, the downside is that the OpenSSL library cannot be updated without a rebuild and reinstallation of SoftEther.
   
   It's also possible to build OpenSSL library dynamically so that you can update OpenSSL without rebuilding SoftEther.
   To achieve that, you need to remove `openssl` from `vcpkg.json` and install OpenSSL directly.
   
   Installing from a package manager such as [Scoop](https://scoop.sh/) would make the subsequent updates easily.
   However, you should avoid using [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
   for the time being because due to a bug it cannot detect the correct version of OpenSSL, causing endless updates.
   
   If you install from Scoop, make sure to add the OpenSSL folder to the system's `PATH`.
   As Scoop already adds it to the user's `PATH`, just copy the same location into the system environment variable(s).
   SoftEther Client Service starts from the System account and will fail to start if OpenSSL is not in the global `PATH`.
   
   Building should be straightforward. You can verify that the binaries are now linked against the locally installed OpenSSL
   with tools like `ldd` (available from Git Bash):

   ```bash
   $ ldd /c/Program\ Files/SoftEther\ VPN\ Client\ Developer\ Edition/vpnclient.exe
        ...
        libcrypto-3-x64.dll => /c/Scoop/apps/openssl/current/bin/libcrypto-3-x64.dll (0x7ff8beb70000)
        libssl-3-x64.dll => /c/Scoop/apps/openssl/current/bin/libssl-3-x64.dll (0x7ff8beaa0000)
        ...
   ```

1. 32-bit Windows

   You don't need 32-bit Windows to build 32-bit executables. However, if 32-bit Windows is what you only have, things become a little complicated.

   Visual Studio 2019 is the last version that works on 32-bit Windows. It does the job but its bundled CMake and Ninja are 64-bit versions.

   After the installation of VS 2019, you need to download 32-bit CMake and Ninja and replace those that come with VS in:

   ```
   C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\CMake
   ```

   Currently CMake has an official x86 installer but Ninja does not. You may need to download from a 3rd party or build from source.
