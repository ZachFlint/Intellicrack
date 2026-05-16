@echo off
rem Intellicrack Windows Sandbox monitor terminator.
rem
rem Two-phase coordinated shutdown (F-0025):
rem
rem   1. Signal the named manual-reset event IntellicrackMonitorStop so
rem      each monitor's main loop observes the request via a non-blocking
rem      WaitHandle.WaitOne(0) call and breaks out of its loop. The
rem      monitor's finally block then flushes a STOP record to its
rem      per-monitor .lifecycle.log file before exiting.
rem
rem   2. Wait up to a configurable number of seconds (default 10) for
rem      each PID tracked in [LogDir]\monitors.pids to exit voluntarily.
rem      Only PIDs that miss the deadline are escalated to
rem      taskkill /F /T after a tasklist existence pre-check.
rem
rem First positional argument (optional) overrides the log directory.
rem Default: %ProgramData%\Intellicrack\Sandbox\logs
rem Second positional argument (optional) overrides the per-PID
rem graceful-wait timeout in seconds. Default: 10. Range: 0 - 300.

setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

set "DEFAULT_LOG_DIR=%ProgramData%\Intellicrack\Sandbox\logs"
set "DEFAULT_GRACE_SECONDS=10"
set "STOP_EVENT_NAME=IntellicrackMonitorStop"
set "HELPER_SCRIPT=%~dp0_stop_monitors_helper.ps1"
set "RC=0"

set "MON_LOGDIR=%DEFAULT_LOG_DIR%"
if not "%~1"=="" set "MON_LOGDIR=%~1"
set "GRACE_SECONDS=%DEFAULT_GRACE_SECONDS%"
if not "%~2"=="" set "GRACE_SECONDS=%~2"

set "PID_LIST=%MON_LOGDIR%\monitors.pids"
set "ERR_FILE=%MON_LOGDIR%\stop_monitors.errors.log"
set "INFO_FILE=%MON_LOGDIR%\stop_monitors.info.log"

if not exist "%PID_LIST%" (
    >&2 echo [stop_monitors] PID file not found: %PID_LIST%
    set "RC=4"
    goto :cleanup
)

if not exist "%HELPER_SCRIPT%" (
    >&2 echo [stop_monitors] helper script not found: %HELPER_SCRIPT%
    set "RC=6"
    goto :cleanup
)

set "PS_EXE=powershell.exe"
pwsh.exe -NoLogo -NoProfile -NonInteractive -Command "exit 0" >nul 2>&1
if not errorlevel 1 set "PS_EXE=pwsh.exe"

rem Phase 1: signal the named stop event.
"%PS_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%HELPER_SCRIPT%" -Mode SignalEvent -EventName "%STOP_EVENT_NAME%" >>"%INFO_FILE%" 2>&1
if errorlevel 1 (
    >>"%ERR_FILE%" echo [%DATE% %TIME%] failed to signal stop event %STOP_EVENT_NAME%
    >&2 echo [stop_monitors] WARNING: failed to signal stop event %STOP_EVENT_NAME%
)

set /a "GRACE_MS=%GRACE_SECONDS% * 1000"
if %GRACE_MS% LSS 0 set "GRACE_MS=0"

rem Phase 2: wait per-PID for graceful exit; force-kill stragglers.
set "FAIL_COUNT=0"
set "TOTAL_COUNT=0"
set "GRACEFUL_COUNT=0"
set "FORCED_COUNT=0"

for /f "usebackq tokens=*" %%L in ("%PID_LIST%") do (
    call :handle_line %%L
)

>>"%INFO_FILE%" echo [%DATE% %TIME%] summary: total=!TOTAL_COUNT! graceful=!GRACEFUL_COUNT! forced=!FORCED_COUNT! failed=!FAIL_COUNT! grace_seconds=%GRACE_SECONDS%

del /f /q "%PID_LIST%" >nul 2>&1

if !TOTAL_COUNT! EQU 0 (
    >&2 echo [stop_monitors] PID file was empty: %PID_LIST%
    set "RC=5"
    goto :cleanup
)

if !FAIL_COUNT! GTR 0 (
    >&2 echo [stop_monitors] !FAIL_COUNT! of !TOTAL_COUNT! terminations failed; see %ERR_FILE%
    set "RC=1"
    goto :cleanup
)

:cleanup
exit /b %RC%


:handle_line
set "TARGET_PID=%1"
set "TARGET_NAME=%~2"
if "%TARGET_NAME%"=="" set "TARGET_NAME=<unknown>"
set /a TOTAL_COUNT+=1

if "%TARGET_PID%"=="" (
    >>"%ERR_FILE%" echo [%DATE% %TIME%] empty PID entry skipped
    set /a FAIL_COUNT+=1
    goto :eof
)

"%PS_EXE%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%HELPER_SCRIPT%" -Mode WaitForExit -TargetPid !TARGET_PID! -WaitMilliseconds %GRACE_MS% >nul 2>&1
set "WAIT_RC=!ERRORLEVEL!"

if "!WAIT_RC!"=="0" (
    set /a GRACEFUL_COUNT+=1
    goto :eof
)

if "!WAIT_RC!"=="2" (
    >>"%INFO_FILE%" echo [%DATE% %TIME%] pid !TARGET_PID! ^(!TARGET_NAME!^) already exited before wait
    set /a GRACEFUL_COUNT+=1
    goto :eof
)

>>"%INFO_FILE%" echo [%DATE% %TIME%] pid=!TARGET_PID! name=!TARGET_NAME! did not honour stop event in %GRACE_SECONDS%s; falling back to taskkill /PID !TARGET_PID! /F /T

tasklist /FI "PID eq !TARGET_PID!" /NH 2>nul | find /V "INFO:" >nul
if errorlevel 1 (
    set /a GRACEFUL_COUNT+=1
    goto :eof
)

call taskkill.exe /PID !TARGET_PID! /F /T >nul 2>&1
if errorlevel 1 (
    >>"%ERR_FILE%" echo [%DATE% %TIME%] taskkill rc=!ERRORLEVEL! pid=!TARGET_PID! name=!TARGET_NAME!
    >&2 echo [stop_monitors] taskkill failed pid=!TARGET_PID! name=!TARGET_NAME!
    set /a FAIL_COUNT+=1
    goto :eof
)
set /a FORCED_COUNT+=1
goto :eof
