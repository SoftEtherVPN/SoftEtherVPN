SETLOCAL
SET BATCH_FILE_NAME=%0
SET BATCH_DIR_PATH=%~dp0
SET NOW_TMP=%time:~0,2%
SET NOW=%date:~0,4%%date:~5,2%%date:~8,2%_%NOW_TMP: =0%%time:~3,2%%time:~6,2%

if exist "C:\Program Files\Microsoft Visual Studio 9.0" (
	call "C:\Program Files\Microsoft Visual Studio 9.0\VC\vcvarsall.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio 9.0" (
	call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat"
) else (
	echo "Visual Studio 2008 not found!"
	exit /b 1
)

if not exist "C:\windows\Microsoft.NET\Framework\v3.5" (
	echo ".NET Framework 3.5 not found!"
	exit /b 1
)

echo on

copy "%BATCH_DIR_PATH%..\AUTHORS.TXT" "%BATCH_DIR_PATH%bin\hamcore\authors.txt"

echo f | xcopy "%BATCH_DIR_PATH%BuildFiles\Library\vs2008\Win32_Release\ossl_static.pdb" "%BATCH_DIR_PATH%DebugFiles\pdb\Win32_Release\ossl_static.pdb"
echo f | xcopy "%BATCH_DIR_PATH%BuildFiles\Library\vs2008\x64_Release\ossl_static.pdb" "%BATCH_DIR_PATH%DebugFiles\pdb\x64_Release\ossl_static.pdb"

if exist "%BATCH_DIR_PATH%bin\BuildUtil.exe" (
	del "%BATCH_DIR_PATH%bin\BuildUtil.exe"
)

C:\windows\Microsoft.NET\Framework\v3.5\MSBuild.exe /toolsversion:3.5 /target:Clean;Rebuild /property:Configuration=Debug "%BATCH_DIR_PATH%BuildUtil\BuildUtil.csproj"

cd "%BATCH_DIR_PATH%bin"

BuildUtil.exe /CMD:All

if errorlevel 1 exit /b %errorlevel%
