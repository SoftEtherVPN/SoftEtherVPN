How to build SoftEther VPN for Windows
======================================


Requirements
------------

You need to install the following software to run a full release build of SoftEther VPN for Windows.

- Microsoft Windows XP, Vista, 7, 8 or later.
- Microsoft Visual Studio 2008 with the latest SP (SP1 9.0.30729.4462 QFE).
  Make sure that you installed the x64 compiler and build tools.
- Microsoft Windows Driver Kit 7.1.0.


Full Build Instructions
-----------------------

The following steps will build all SoftEther VPN program files, and also build
the installer packages of SoftEther VPN. It is very easy.

1. Run the "BuildAll.cmd" batch file in the "src" directory.
2. Wait until the building process will complete.
3. The built files are stored on the "output" directory.


Partly Build, Debug, or Development Instructions on Visual Studio 2008
---------------------------------------------------------------------

If you are a programmer, you can open the SoftEther VPN solution file
with Visual Studio 2008 to customize. Open "src\SEVPN.sln" and enjoy it.

Visual Studio 2008 is required as to maintain compatibility with Windows 9x, due to Visual C++ 2008 being the last version compatibile with Windows 9x and Windows NT 4.x binary linking.

- Visual Studio 2008's installer ISO can be found on Microsoft's site here: https://download.microsoft.com/download/E/8/E/E8EEB394-7F42-4963-A2D8-29559B738298/VS2008ExpressWithSP1ENUX1504728.iso

- The Microsoft Windows Driver Kit 7.1.0 can be found here: https://download.microsoft.com/download/4/A/2/4A25C7D5-EFBE-4182-B6A9-AE6850409A78/GRMWDK_EN_7600_1.ISO

If using anything else other than Visual Studio 2008 for development, your code **MUST** support Microsoft Visual C++ 2008 due to aforementioned reasons.

It is OK to add newer Visual Studio (2015, 2017) solution files to the project, but there then must be dual solution files for both Visual C++ 2008 and the latest Visual Studio.

Build and Development Instructions with Visual Studio 2017 & CMake
---------------------------------------------------------------------

An alternative method for development of the SoftEtherVPN project on Windows is through CMake.

There are several methods for using CMake but the easiest by far is through Visual Studio 2017 by importing the CMake project directly
into it. So that is what will be described below.

Requirements:

1. Download Visual Studio 2017 (Community Edition is fine).
2. During install, make sure to check "Desktop development with C++" under "Workloads".
3. Click on individual components and scroll until you see "Visual C++ tools for CMake" under the compilers section. Make sure this is checked.
4. Proceed with and finish Visual Studio 2017 install.
5. Install the needed submodules to build the project, avoiding CMake telling you to do so with: `git submodule update --init --recursive`

Building:

Once both installs have finished, launch Visual Studio. Once its started go to the File menu click `Open --> CMake`. Then navigate to where you
cloned the project and open the `CMakeLists.txt` file in the projects root directory.

Visual Studio will proceed to start the CMake configuration process and once its finished, you can simply go to toolbar and click `CMake -> Build All`.

Once it has finished, hopefully with no errors, look in the newly created `/build` directory in the project's folder. Inside are the development versions
of all the SoftEtherVPN components.

Congrats, you now have a complete CMake development environment for SoftEtherVPN on Windows, enjoy and happy contributing!

Download Links:
- Visual Studio 2017 from Microsoft: https://visualstudio.microsoft.com/downloads

************************************
Thank You Using SoftEther VPN !
By SoftEther VPN Open-Source Project
https://www.softether.org/
