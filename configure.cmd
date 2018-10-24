@echo off

echo ---------------------------------------------------------------------
echo SoftEther VPN for Windows
echo.
echo Copyright (c) SoftEther VPN Project at University of Tsukuba, Japan.
echo Copyright (c) Daiyuu Nobori. All Rights Reserved.
echo.
echo This program is free software; you can redistribute it and/or
echo modify it under the terms of the GNU General Public License
echo version 2 as published by the Free Software Foundation.
echo.
echo Read and understand README.TXT, LICENSE.TXT and WARNING.TXT before use.
echo ---------------------------------------------------------------------
echo.

echo Welcome to the corner-cutting configure script !
echo.

if not exist "tmp" (
	mkdir tmp
)

cd tmp

cmake -DCMAKE_BUILD_TYPE=Release -G "NMake Makefiles" ..

if %errorlevel% == 0 (
	echo.
	echo The Makefile is generated. Run 'nmake' to build SoftEther VPN.
) else (
	cd ..
)
