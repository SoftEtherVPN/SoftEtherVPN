How to build SoftEther VPN for Windows
======================================


Requirements
------------

You need to install the following software to build SoftEther VPN for Windows.

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


Partly Build, Debug or Development Instructions on Visual Studio 2008
---------------------------------------------------------------------

If you are a programmer, you can open the SoftEther VPN solution file
with Visual Studio 2008 to customize. Open "src\SEVPN.sln" and enjoy it.

Visual Studio 2008 is required as to maintain compatibility with Windows 9x, due to Visual C++ 2008 being the last version compatibile with Windows 9x and Windows NT 4.x binary linking.

- Visual Studio 2008's installer ISO can be found on Microsoft's site here: https://download.microsoft.com/download/E/8/E/E8EEB394-7F42-4963-A2D8-29559B738298/VS2008ExpressWithSP1ENUX1504728.iso

- The Microsoft Windows Driver Kit 7.1.0 can be found here: https://download.microsoft.com/download/4/A/2/4A25C7D5-EFBE-4182-B6A9-AE6850409A78/GRMWDK_EN_7600_1.ISO

If using anything else other than Visual Studio 2008 for development, your code **MUST** support Microsoft Visual C++ 2008 due to aforementioned reasons.

It is OK to add newer Visual Studio (2015, 2017) solution files to the project, but there then must be dual solution files for both Visual C++ 2008 and the latest Visual Studio.

Note: There is an update to the CMake configuration that adds support for Windows in the works for future use.

************************************
Thank You Using SoftEther VPN !
By SoftEther VPN Open-Source Project
http://www.softether.org/
