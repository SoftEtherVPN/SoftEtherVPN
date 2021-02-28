@echo off

echo ---------------------------------------------------------------------
echo SoftEther VPN for Windows
echo.
echo Copyright (c) all contributors on SoftEther VPN project in GitHub.
echo Copyright (c) Daiyuu Nobori, SoftEther Project at University of Tsukuba, and SoftEther Corporation.
echo.
echo Read and understand README, LICENSE and WARNING before use.
echo ---------------------------------------------------------------------
echo.

echo Welcome to the corner-cutting configure script !
echo.

if not exist "build" (
	mkdir build
)

cd build

cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -G "NMake Makefiles" ..

if %errorlevel% == 0 (
	echo.
	echo The Makefile is generated. Run 'nmake' to build SoftEther VPN.
) else (
	cd ..
	exit /b 1
)
