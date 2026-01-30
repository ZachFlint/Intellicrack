@echo off
set "PWSH="
where pwsh.exe >nul 2>&1 && set "PWSH=pwsh.exe"
if not defined PWSH (
    if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
)
if not defined PWSH (
    echo ERROR: pwsh.exe not found
    pause
    exit /b 1
)
"%PWSH%" -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0UpdateTools.ps1"
if errorlevel 1 pause
