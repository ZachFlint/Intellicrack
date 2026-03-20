@echo off
REM Builds the CLI Launcher TUI (release, max optimization) and deploys
REM the executable to CLI Coding\CLI Launcher.exe
pushd "%~dp0\..\CLI Coding\launcher"
cargo build --release
if %ERRORLEVEL% EQU 0 (
    copy /Y "target\release\cli-launcher.exe" "..\CLI Launcher.exe" >nul
    echo Deployed to: CLI Coding\CLI Launcher.exe
) else (
    echo Build failed.
    popd
    exit /b 1
)
popd
