@echo off
rem Intellicrack Windows Sandbox monitor terminator.
rem Reads "<LogDir>\monitors.pids" produced by start_monitors.cmd and
rem terminates each tracked child PID via taskkill /F. Exits non-zero if
rem any termination call fails.
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

set "PID_FILE=%MON_LOGDIR%\monitors.pids"
set "ERR_FILE=%MON_LOGDIR%\stop_monitors.errors.log"

if not exist "%PID_FILE%" (
    >&2 echo [stop_monitors] PID file not found: %PID_FILE%
    endlocal
    exit /b 4
)

set "FAIL_COUNT=0"
set "TOTAL_COUNT=0"

for /f "usebackq tokens=1,*" %%P in ("%PID_FILE%") do (
    set "TARGET_PID=%%P"
    set "TARGET_NAME=%%Q"
    if "!TARGET_NAME!"=="" (
        set "TARGET_NAME=<unknown>"
    )
    set /a TOTAL_COUNT+=1

    if "!TARGET_PID!"=="" (
        >>"%ERR_FILE%" echo [%DATE% %TIME%] empty PID entry skipped
        set /a FAIL_COUNT+=1
    ) else (
        rem Verify PID is still alive before issuing taskkill so the
        rem "process not found" path does not pollute exit codes.
        powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { $null = Get-Process -Id !TARGET_PID! -ErrorAction Stop; exit 0 } catch { exit 1 }" >nul 2>&1
        if errorlevel 1 (
            >>"%ERR_FILE%" echo [%DATE% %TIME%] pid !TARGET_PID! ^(!TARGET_NAME!^) already exited
        ) else (
            taskkill /PID !TARGET_PID! /F /T >nul 2>&1
            if errorlevel 1 (
                >>"%ERR_FILE%" echo [%DATE% %TIME%] taskkill failed for pid !TARGET_PID! ^(!TARGET_NAME!^) errorlevel=!ERRORLEVEL!
                >&2 echo [stop_monitors] taskkill failed for pid !TARGET_PID! ^(!TARGET_NAME!^)
                set /a FAIL_COUNT+=1
            )
        )
    )
)

del /f /q "%PID_FILE%" >nul 2>&1

if !TOTAL_COUNT! EQU 0 (
    >&2 echo [stop_monitors] PID file was empty: %PID_FILE%
    endlocal
    exit /b 5
)

if !FAIL_COUNT! GTR 0 (
    >&2 echo [stop_monitors] !FAIL_COUNT! of !TOTAL_COUNT! terminations failed; see %ERR_FILE%
    endlocal
    exit /b 1
)

endlocal
exit /b 0
