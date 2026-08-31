@echo off
for %%I in ("%~dp0\..") do set "ROOT=%%~fI"
pushd "%ROOT%\CLI Coding\launcher"
cargo build --release
if %ERRORLEVEL% EQU 0 (
    copy /Y "target\release\cli-launcher.exe" "%ROOT%\CLI Coding\CLI Launcher.exe" >nul
    if %ERRORLEVEL% NEQ 0 (
        echo Copy failed.
        popd
        exit /b 1
    )
    echo Deployed to: CLI Coding\CLI Launcher.exe
) else (
    echo Build failed.
    popd
    exit /b 1
)
popd
exit /b 0
