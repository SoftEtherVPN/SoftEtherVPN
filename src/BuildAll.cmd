SETLOCAL
SET BATCH_FILE_NAME=%0
SET BATCH_DIR_NAME=%0\..
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

if exist "%BATCH_DIR_NAME%\bin\BuildUtil.exe" (
	del "%BATCH_DIR_NAME%\bin\BuildUtil.exe"
)

C:\windows\Microsoft.NET\Framework\v3.5\MSBuild.exe /toolsversion:3.5 /target:Clean;Rebuild /property:Configuration=Debug "%BATCH_DIR_NAME%\BuildUtil\BuildUtil.csproj"

cd %BATCH_DIR_NAME%\bin

BuildUtil.exe /CMD:All

if errorlevel 1 exit /b %errorlevel%
