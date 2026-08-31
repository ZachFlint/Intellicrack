@echo off
REM Adobe Injector Build Launcher for Intellicrack
REM This script launches the PowerShell build system with proper execution policy

setlocal EnableDelayedExpansion

echo ======================================================
echo   Adobe Injector Build System for Intellicrack
echo ======================================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator
    echo.
    echo Right-click build.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo [INFO] Running with administrative privileges
echo.

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "BUILD_SCRIPT=%SCRIPT_DIR%build.ps1"

REM Check if build.ps1 exists
if not exist "%BUILD_SCRIPT%" (
    echo [ERROR] build.ps1 not found in %SCRIPT_DIR%
    echo.
    pause
    exit /b 1
)

echo [INFO] Launching PowerShell build system...
echo.

REM Execute PowerShell build script with execution policy bypass
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%BUILD_SCRIPT%"

set BUILD_RESULT=%errorLevel%

echo.
if %BUILD_RESULT% equ 0 (
    echo ======================================================
    echo   BUILD SUCCESSFUL
    echo ======================================================
    echo.
    echo Next steps:
    echo   1. Check the Release\ directory for AdobeInjector.exe
    echo   2. Deploy files to D:\Intellicrack\tools\AdobeInjector\
    echo   3. Test integration with Intellicrack
    echo.
) else (
    echo ======================================================
    echo   BUILD FAILED
    echo ======================================================
    echo.
    echo Check the Logs\ directory for error details
    echo.
)

pause
exit /b %BUILD_RESULT%
