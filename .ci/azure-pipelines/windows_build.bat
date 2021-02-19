@echo on

:: The method we use to store a command's output into a variable:
:: https://stackoverflow.com/a/6362922
for /f "tokens=* USEBACKQ" %%g in (`python "version.py"`) do (set "VERSION=%%g")

:: https://stackoverflow.com/a/8566001
echo %SE_BUILD_NUMBER_TOKEN%> "%tmp%\length.txt"
for %%? in ("%tmp%\length.txt") do ( set /A SE_BUILD_NUMBER_TOKEN_LENGTH=%%~z? - 2 )

if %SE_BUILD_NUMBER_TOKEN_LENGTH% equ 64 (
	for /f "tokens=* USEBACKQ" %%g in (`curl "https://softether.network/get-build-number?commit=%BUILD_SOURCEVERSION%&version=%VERSION%&token=%SE_BUILD_NUMBER_TOKEN%"`) do (set "BUILD_NUMBER=%%g")
) else (
	set BUILD_NUMBER=0
)

cd %BUILD_BINARIESDIRECTORY%

call "%VCVARS_PATH%"

cmake -G "Ninja" -DCMAKE_TOOLCHAIN_FILE="C:\vcpkg\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=%VCPKG_TRIPLET% -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER="%COMPILER_PATH%" -DCMAKE_CXX_COMPILER="%COMPILER_PATH%" -DBUILD_NUMBER=%BUILD_NUMBER% "%BUILD_SOURCESDIRECTORY%"
cmake --build .

mkdir "%BUILD_STAGINGDIRECTORY%\installers"
vpnsetup /SFXMODE:vpnclient /SFXOUT:"%BUILD_STAGINGDIRECTORY%\installers\softether-vpnclient-%VERSION%.%BUILD_NUMBER%.%ARCHITECTURE%.exe"
vpnsetup /SFXMODE:vpnserver_vpnbridge /SFXOUT:"%BUILD_STAGINGDIRECTORY%\installers\softether-vpnserver_vpnbridge-%VERSION%.%BUILD_NUMBER%.%ARCHITECTURE%.exe"
