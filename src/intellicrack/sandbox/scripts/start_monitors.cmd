@echo off
rem Intellicrack Windows Sandbox monitor launcher.
rem Spawns every *.ps1 monitor script in this directory with a shared -LogDir,
rem captures each child PID into "<LogDir>\monitors.pids", and propagates a
rem non-zero exit code if any monitor fails to start.
rem
rem First positional argument (optional) overrides the log directory.
rem Default: %ProgramData%\Intellicrack\Sandbox\logs

setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

set "DEFAULT_LOG_DIR=%ProgramData%\Intellicrack\Sandbox\logs"

if "%~1"=="" (
    set "MON_LOGDIR=%DEFAULT_LOG_DIR%"
) else (
    set "MON_LOGDIR=%~1"
)

if not exist "%MON_LOGDIR%" mkdir "%MON_LOGDIR%" 2>nul
if not exist "%MON_LOGDIR%" (
    >&2 echo [start_monitors] failed to create log directory: %MON_LOGDIR%
    endlocal
    exit /b 2
)

set "MON_DIR=%~dp0"
set "PID_FILE=%MON_LOGDIR%\monitors.pids"
set "ERR_FILE=%MON_LOGDIR%\start_monitors.errors.log"

rem Truncate previous PID file before tracking this session's children.
type nul > "%PID_FILE%"
if errorlevel 1 (
    >&2 echo [start_monitors] cannot write PID file: %PID_FILE%
    endlocal
    exit /b 3
)

set /a FAIL_COUNT=0
set /a LAUNCH_COUNT=0

for %%F in ("%MON_DIR%*.ps1") do call :launch_one "%%~fF" "%%~nxF"

if %LAUNCH_COUNT% EQU 0 (
    >&2 echo [start_monitors] no monitor scripts found in %MON_DIR%
    endlocal
    exit /b 4
)

if %FAIL_COUNT% GTR 0 (
    >&2 echo [start_monitors] %FAIL_COUNT% monitor failures; see %ERR_FILE%
    endlocal
    exit /b 1
)

endlocal
exit /b 0


:launch_one
set "SCRIPT_PATH=%~1"
set "SCRIPT_NAME=%~2"
rem Skip helper / underscore-prefixed scripts: they are utilities consumed
rem by start_monitors / stop_monitors themselves, not standalone monitors.
if "%SCRIPT_NAME:~0,1%"=="_" goto :eof
set "CHILD_PID="
set /a LAUNCH_COUNT+=1

rem Spawn the monitor as a hidden child process and emit its PID. The
rem child's stdout/stderr are redirected to per-monitor files under
rem MON_LOGDIR so launch failures surface in the matching .err.log.
for /f "usebackq tokens=*" %%P in (`powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $stem=[IO.Path]::GetFileNameWithoutExtension('%SCRIPT_NAME%'); $log=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.out.log'); $err=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.err.log'); try { $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','%SCRIPT_PATH%','-LogDir','%MON_LOGDIR%') -WindowStyle Hidden -PassThru -RedirectStandardOutput $log -RedirectStandardError $err; if ($null -eq $p) { exit 11 }; Write-Output $p.Id; exit 0 } catch { Write-Error $_.Exception.Message; exit 12 }"`) do set "CHILD_PID=%%P"

if not defined CHILD_PID goto :launch_failed

rem Validate that the launched PID is still alive a moment later;
rem PowerShell scripts that crash on argument validation exit instantly.
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Start-Sleep -Milliseconds 250; try { $p = Get-Process -Id %CHILD_PID% -ErrorAction Stop; if ($p.HasExited) { exit 21 }; exit 0 } catch { exit 22 }" >nul 2>&1
if errorlevel 1 goto :launch_died

>>"%PID_FILE%" echo %CHILD_PID% %SCRIPT_NAME%
goto :eof

:launch_died
>>"%ERR_FILE%" echo [%DATE% %TIME%] %SCRIPT_NAME% exited within 250 ms pid=%CHILD_PID%
>&2 echo [start_monitors] monitor exited immediately: %SCRIPT_NAME% pid=%CHILD_PID%
set /a FAIL_COUNT+=1
goto :eof

:launch_failed
>>"%ERR_FILE%" echo [%DATE% %TIME%] failed to launch %SCRIPT_NAME%
>&2 echo [start_monitors] failed to launch monitor: %SCRIPT_NAME%
set /a FAIL_COUNT+=1
goto :eof
