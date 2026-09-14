@echo off
echo ============================================
echo  MSB Security Test Tool - Build Script
echo ============================================
echo.

:: Check for MSBuild
where msbuild >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] MSBuild not found in PATH.
    echo     Run this from "Developer Command Prompt for VS 2022"
    echo     or "x64 Native Tools Command Prompt for VS 2022"
    echo.
    echo     Find it in Start Menu under Visual Studio 2022.
    pause
    exit /b 1
)

echo [1/4] Building DLL (TaskManagerHack)...
msbuild TaskManagerHack.sln /p:Configuration=Debug /p:Platform=x64 /t:TaskManagerHack /v:minimal
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] DLL build failed!
    pause
    exit /b 1
)
echo       OK
echo.

echo [2/4] Copying DLL as payload for embedding...
copy /Y "x64\Debug\TaskManagerHack.dll" "MSBBypass\payload.dll" >nul
echo       OK
echo.

echo [3/4] Building MSBBypass (one-click tool)...
:: Build MSBBypass as a console app with the resource file
cl /EHsc /Fe:"x64\Debug\MSBBypass.exe" /Fo:"x64\Debug\\" MSBBypass\MSBBypass.cpp /link /MACHINE:X64 MSBBypass\Resource.res user32.lib advapi32.lib
if %ERRORLEVEL% NEQ 0 (
    :: Try with rc.exe first to compile the resource
    echo       Compiling resource file...
    rc /fo "MSBBypass\Resource.res" "MSBBypass\Resource.rc"
    cl /EHsc /Fe:"x64\Debug\MSBBypass.exe" /Fo:"x64\Debug\\" MSBBypass\MSBBypass.cpp /link /MACHINE:X64 MSBBypass\Resource.res user32.lib advapi32.lib
)
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MSBBypass build failed!
    echo         See "Manual Build" instructions in README.md
    pause
    exit /b 1
)
echo       OK
echo.

echo [4/4] Done!
echo.
echo ============================================
echo  Output: x64\Debug\MSBBypass.exe
echo ============================================
echo.
echo  Usage:
echo    1. Disable antivirus
echo    2. Right-click MSBBypass.exe ^> Run as administrator
echo    3. Start Mettl Secure Browser
echo    4. Enter the exam
echo.
pause
