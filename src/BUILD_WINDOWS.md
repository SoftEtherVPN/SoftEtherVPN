How to build SoftEther VPN for Windows
======================================

Full Build Instructions
-----------------------

There are several methods for using CMake but the easiest by far is through Visual Studio 2019 by importing the CMake project directly
into it. So that is what will be described below.

Requirements:

1. Download Visual Studio 2019 (Community Edition is fine).
2. During install, make sure to check "Desktop development with C++" under "Workloads".
3. Click on individual components and scroll until you see "Visual C++ tools for CMake" under the compilers section. Make sure this is checked.
4. Proceed with and finish Visual Studio 2019 installation.
5. Install the needed submodules to build the project, avoiding CMake telling you to do so with: `git submodule update --init --recursive`

Building:

Once both installs have finished, launch Visual Studio. Once its started go to the File menu click `Open --> CMake`. Then navigate to where you
cloned the project and open the `CMakeLists.txt` file in the projects root directory.

Visual Studio will proceed to start the CMake configuration process and once its finished, you can simply go to toolbar and click `CMake -> Build All`.

Once it has finished, hopefully with no errors, look in the newly created `/build` directory in the project's folder. Inside are the development versions
of all the SoftEtherVPN components.

Congrats, you now have a complete CMake development environment for SoftEtherVPN on Windows, enjoy and happy contributing!

Download Links:
- Visual Studio 2019 from Microsoft: https://visualstudio.microsoft.com/downloads
