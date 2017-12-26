How to build SoftEther VPN for Windows
======================================


Requirements
------------

You need to install the following software to build SoftEther VPN for Windows.

- Microsoft Windows XP, Vista, 7, 8 or later.
- Microsoft Visual Studio 2008 with the latest SP (SP1 9.0.30729.4462 QFE).
  Make sure that you installed the x64 compiler and build tools.

* Note:
  Visual Studio 2008 SP1 is required to build SoftEther VPN on Windows.
  Please make sure that VS2008 'SP1' is installed.
  Visual Studio 2010, 2012 or 2013 is currently not supported.
  Visual Studio 2008 Express Edition is not supported.
  Standard Edition, Professional Edition, Team System or Team Suite is
  required.


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


************************************
Thank You Using SoftEther VPN !
By SoftEther VPN Open-Source Project
http://www.softether.org/
