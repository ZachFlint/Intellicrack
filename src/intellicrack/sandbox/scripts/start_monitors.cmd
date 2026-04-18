@echo off
rem Intellicrack Windows Sandbox monitor launcher.
rem Spawns every *.ps1 monitor script in this directory with a shared -LogDir.
rem
rem First positional argument (optional) overrides the log directory.
rem Default: C:\Users\WDAGUtilityAccount\Desktop\Shared\logs

setlocal ENABLEEXTENSIONS

if "%~1"=="" (
    set "MON_LOGDIR=C:\Users\WDAGUtilityAccount\Desktop\Shared\logs"
) else (
    set "MON_LOGDIR=%~1"
)

if not exist "%MON_LOGDIR%" (
    mkdir "%MON_LOGDIR%" 2>nul
)

set "MON_DIR=%~dp0"

for %%F in ("%MON_DIR%*.ps1") do (
    start "" /B powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "%%~fF" -LogDir "%MON_LOGDIR%"
)

endlocal
exit /b 0
