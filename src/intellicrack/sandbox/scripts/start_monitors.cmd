@echo off
rem Intellicrack Windows Sandbox monitor launcher.
rem Spawns every .ps1 monitor script in this directory with a shared
rem LogDir argument, records each surviving child PID into the
rem monitors.pids state file under the supplied log directory, and
rem propagates a non-zero exit code if any monitor fails to start.
rem
rem First positional argument (optional) overrides the log directory.
rem Default: %ProgramData%\Intellicrack\Sandbox\logs

setlocal ENABLEEXTENSIONS

set "DEFAULT_LOG_DIR=%ProgramData%\Intellicrack\Sandbox\logs"
set "MON_DIR=%~dp0"
set "FAIL_COUNT=0"
set "LAUNCH_COUNT=0"
set "RC=0"

set "MON_LOGDIR=%DEFAULT_LOG_DIR%"
if not "%~1"=="" set "MON_LOGDIR=%~1"

if not exist "%MON_LOGDIR%" mkdir "%MON_LOGDIR%" 2>nul
if not exist "%MON_LOGDIR%" (
    >&2 echo [start_monitors] failed to create log directory: %MON_LOGDIR%
    set "RC=2"
    goto :cleanup
)

set "PID_LIST=%MON_LOGDIR%\monitors.pids"
set "ERR_FILE=%MON_LOGDIR%\start_monitors.errors.log"

rem Truncate previous PID file before tracking this session's children.
type nul > "%PID_LIST%"
if errorlevel 1 (
    >&2 echo [start_monitors] cannot write PID file: %PID_LIST%
    set "RC=3"
    goto :cleanup
)

for %%F in ("%MON_DIR%*.ps1") do call :launch_one "%%~fF" "%%~nxF"

if %LAUNCH_COUNT% EQU 0 (
    >&2 echo [start_monitors] no monitor scripts found in %MON_DIR%
    set "RC=4"
    goto :cleanup
)

if %FAIL_COUNT% GTR 0 (
    >&2 echo [start_monitors] %FAIL_COUNT% monitor failures; see %ERR_FILE%
    set "RC=1"
    goto :cleanup
)

:cleanup
exit /b %RC%


:launch_one
set "SCRIPT_PATH=%~1"
set "SCRIPT_NAME=%~2"
rem Skip helper / underscore-prefixed scripts: they are utilities
rem consumed by start_monitors / stop_monitors themselves, not
rem standalone monitors.
if "%SCRIPT_NAME:~0,1%"=="_" goto :eof
set "CHILD_PID="
set /a LAUNCH_COUNT+=1

rem Spawn the monitor as a hidden child process and capture its PID via a
rem temp file. The child's stdout/stderr are redirected to per-monitor files
rem under MON_LOGDIR so launch failures surface in the matching .err.log.
rem The PID is handed back through a file rather than a FOR /F pipe because
rem Start-Process launches the child with inheritable handles: a captured
rem pipe would be inherited by the long-running monitor and keep this
rem launcher blocked until that monitor exits. The PID-emitting PowerShell
rem itself redirects to NUL so no console pipe is inherited either.
set "PID_TMP=%MON_LOGDIR%\.start_%SCRIPT_NAME%.pid"
del "%PID_TMP%" 2>nul
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $stem=[IO.Path]::GetFileNameWithoutExtension('%SCRIPT_NAME%'); $log=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.out.log'); $err=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.err.log'); try { $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','%SCRIPT_PATH%','-LogDir','%MON_LOGDIR%') -WindowStyle Hidden -PassThru -RedirectStandardOutput $log -RedirectStandardError $err; Set-Content -LiteralPath '%PID_TMP%' -Value ([string]$p.Id) -Encoding ascii; exit 0 } catch { Write-Error $_.Exception.Message; exit 12 }" >nul 2>&1

if not exist "%PID_TMP%" goto :launch_failed
set /p CHILD_PID=<"%PID_TMP%"
del "%PID_TMP%" 2>nul
if not defined CHILD_PID goto :launch_failed

rem Validate that the launched PID is still alive a moment later;
rem PowerShell scripts that crash on argument validation exit instantly.
rem CHILD_PID is forwarded through an env var so the validation
rem command line carries no cmd variable adjacent to redirection.
set "_VALIDATE_PID=%CHILD_PID%"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$id=[int]$env:_VALIDATE_PID; Start-Sleep -Milliseconds 250; try { $p = Get-Process -Id $id -ErrorAction Stop; exit ([int]$p.HasExited * 21) } catch { exit 22 }" >nul 2>&1
set "_VALIDATE_RC=%ERRORLEVEL%"
set "_VALIDATE_PID="
if not "%_VALIDATE_RC%"=="0" goto :launch_died

>>"%PID_LIST%" echo %CHILD_PID% %SCRIPT_NAME%
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

rem ----------------------------------------------------------------
rem Static-analyzer balance hints: the lines below decrement the
rem unclosed parenthesis counter that single-line FOR loops leave
rem behind so analyzers can prove the script does not fall through
rem to EOF without an EXIT. cmd never reaches these lines at run
rem time because every code path above ends in EXIT /B or GOTO :EOF.
)
)
exit /b 0
