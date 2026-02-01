@echo off
set "PWSH="
"%SystemRoot%\System32\where.exe" pwsh.exe >nul 2>&1 && set "PWSH=pwsh.exe"
if not defined PWSH (
    if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
)
if not defined PWSH (
    echo ERROR: pwsh.exe not found
    pause
    exit /b 1
)
"%PWSH%" -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0UpdateTools.ps1"
set "PS_RESULT=%ERRORLEVEL%"
if %PS_RESULT% neq 0 pause
exit /b %PS_RESULT%
