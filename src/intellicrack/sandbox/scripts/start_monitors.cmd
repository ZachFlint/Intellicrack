@echo off
rem Intellicrack Windows Sandbox monitor launcher.
rem Spawns every .ps1 monitor script in this directory with a shared
rem LogDir argument, records each child PID into the monitors.pids state
rem file under the supplied log directory, waits until every monitor has
rem either reported that it is ready or exited, and propagates a non-zero
rem exit code if any monitor did not start.
rem
rem First positional argument (optional) overrides the log directory.
rem Default: %ProgramData%\Intellicrack\Sandbox\logs
rem Second positional argument (optional) sets how long, in seconds, the
rem launcher keeps waiting for a monitor that has neither reported ready
rem nor exited. Range: 1 - 300. Omit it (or pass 0) for the default in
rem DEFAULT_READY_WAIT_MS; see :readiness_gate.

setlocal ENABLEEXTENSIONS

set "DEFAULT_LOG_DIR=%ProgramData%\Intellicrack\Sandbox\logs"
set "DEFAULT_READY_WAIT_MS=120000"
set "MAX_READY_WAIT_MS=300000"
set "MON_DIR=%~dp0"
set "FAIL_COUNT=0"
set "LAUNCH_COUNT=0"
set "RC=0"

set "MON_LOGDIR=%DEFAULT_LOG_DIR%"
if not "%~1"=="" set "MON_LOGDIR=%~1"
set "READY_WAIT_MS=%DEFAULT_READY_WAIT_MS%"
if not "%~2"=="" call :parse_wait_seconds "%~2"

if not exist "%MON_LOGDIR%" mkdir "%MON_LOGDIR%" 2>nul
if not exist "%MON_LOGDIR%" (
    >&2 echo [start_monitors] failed to create log directory: %MON_LOGDIR%
    set "RC=2"
    goto :cleanup
)

set "PID_LIST=%MON_LOGDIR%\monitors.pids"
set "ERR_FILE=%MON_LOGDIR%\start_monitors.errors.log"
set "GATE_REPORT=%MON_LOGDIR%\.start_monitors.gate"

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

call :readiness_gate

if %FAIL_COUNT% GTR 0 (
    >&2 echo [start_monitors] %FAIL_COUNT% monitor failures; see %ERR_FILE%
    set "RC=1"
    goto :cleanup
)

:cleanup
endlocal & exit /b %RC%


rem :launch_one <full_script_path> <script_file_name>
rem Spawns one monitor and appends its PID to the PID file. Increments
rem LAUNCH_COUNT for every non-helper script and FAIL_COUNT when the spawn
rem itself fails. Returns via GOTO :EOF.
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
rem
rem The monitor inherits INTELLICRACK_MONITOR_READY, the path of the file
rem it creates once its own startup is over and it is collecting. That file
rem is the only thing :readiness_gate accepts as proof the monitor started.
set "PID_TMP=%MON_LOGDIR%\.start_%SCRIPT_NAME%.pid"
set "READY_FILE=%MON_LOGDIR%\.ready_%SCRIPT_NAME%"
del "%PID_TMP%" 2>nul
del "%READY_FILE%" 2>nul
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $stem=[IO.Path]::GetFileNameWithoutExtension('%SCRIPT_NAME%'); $log=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.out.log'); $err=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.err.log'); try { $env:INTELLICRACK_MONITOR_READY='%READY_FILE%'; $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','%SCRIPT_PATH%','-LogDir','%MON_LOGDIR%') -WindowStyle Hidden -PassThru -RedirectStandardOutput $log -RedirectStandardError $err; Set-Content -LiteralPath '%PID_TMP%' -Value ([string]$p.Id) -Encoding ascii; exit 0 } catch { Write-Error $_.Exception.Message; exit 12 }" >nul 2>&1

if not exist "%PID_TMP%" goto :launch_failed
set /p CHILD_PID=<"%PID_TMP%"
del "%PID_TMP%" 2>nul
if not defined CHILD_PID goto :launch_failed

>>"%PID_LIST%" echo %CHILD_PID% %SCRIPT_NAME%
goto :eof


rem :readiness_gate
rem Decides, for every PID recorded in the PID file, whether that monitor
rem started. The decision rests on what the monitor did, never on how long
rem it took:
rem
rem   ready  - the monitor created its ready file. It started.
rem   dead   - the monitor's process exited without creating it. It did not
rem            start, however long it took to die.
rem   silent - the monitor is still running and has still not created it
rem            when the wait limit runs out. It did not start either, and
rem            it stays in the PID file so stop_monitors can still reap it.
rem
rem A monitor creates its ready file before it can exit, so each pass reads
rem the process state first and looks for the file second: a process seen
rem to be gone had already written whatever it was ever going to write.
rem
rem The gate returns as soon as nothing is left undecided. The wait limit
rem only bounds a monitor that hangs before it reports; it is not a window
rem a slow failure can outlast, because a monitor still undecided when it
rem expires is reported as silent rather than assumed to be healthy.
rem
rem The PID file is rewritten to hold only the monitors still running, so
rem stop_monitors never targets a reaped PID. FAIL_COUNT is incremented
rem once per dead or silent monitor, and once more if the gate could not
rem evaluate the fleet at all.
:readiness_gate
del "%GATE_REPORT%" 2>nul
set "_MON_GATE_PIDFILE=%PID_LIST%"
set "_MON_GATE_REPORT=%GATE_REPORT%"
set "_MON_GATE_MARKERDIR=%MON_LOGDIR%"
set "_MON_GATE_LIMIT=%READY_WAIT_MS%"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $pidFile=$env:_MON_GATE_PIDFILE; $report=$env:_MON_GATE_REPORT; $markerDir=$env:_MON_GATE_MARKERDIR; $limit=[int]$env:_MON_GATE_LIMIT; $tracked=New-Object System.Collections.ArrayList; foreach ($line in [IO.File]::ReadAllLines($pidFile)) { $entry=$line.Trim(); if ($entry.Length -eq 0) { continue }; $parts=$entry.Split(@(' '),2,[StringSplitOptions]::RemoveEmptyEntries); $target=0; if (-not [int]::TryParse($parts[0],[ref]$target)) { continue }; $label='unknown'; if ($parts.Length -gt 1 -and $parts[1].Trim().Length -gt 0) { $label=$parts[1].Trim() }; $handle=$null; try { $handle=Get-Process -Id $target -ErrorAction Stop } catch { $handle=$null }; if ($null -ne $handle) { try { $null=$handle.Handle } catch { $null=$_ } }; $null=$tracked.Add([pscustomobject]@{Target=$target;Label=$label;Handle=$handle;Marker=(Join-Path -Path $markerDir -ChildPath ('.ready_' + $label));State='waiting'}) }; $deadline=(Get-Date).AddMilliseconds($limit); while ($true) { $waiting=0; foreach ($item in $tracked) { if ($item.State -ne 'waiting') { continue }; $gone=($null -eq $item.Handle -or $item.Handle.HasExited); if (Test-Path -LiteralPath $item.Marker) { $item.State='ready' } elseif ($gone) { $item.State='dead' } else { $waiting=$waiting+1 } }; if ($waiting -eq 0) { break }; if ((Get-Date) -ge $deadline) { break }; Start-Sleep -Milliseconds 100 }; $running=New-Object System.Collections.ArrayList; $unstarted=New-Object System.Collections.ArrayList; foreach ($item in $tracked) { if ($item.State -eq 'dead') { $code='unknown'; if ($null -ne $item.Handle) { try { $code=[string]$item.Handle.ExitCode } catch { $code='unknown' } }; if ([string]::IsNullOrEmpty($code)) { $code='unknown' }; $null=$unstarted.Add(('dead {0} {1} {2}' -f $item.Target,$code,$item.Label)) } else { if ($item.State -eq 'waiting') { $null=$unstarted.Add(('silent {0} none {1}' -f $item.Target,$item.Label)) }; if ($null -ne $item.Handle -and -not $item.Handle.HasExited) { $null=$running.Add(('{0} {1}' -f $item.Target,$item.Label)) } }; Remove-Item -LiteralPath $item.Marker -Force -ErrorAction SilentlyContinue }; [IO.File]::WriteAllLines($pidFile,[string[]]$running.ToArray()); [IO.File]::WriteAllLines($report,[string[]]$unstarted.ToArray()); if ($unstarted.Count -gt 0) { exit 1 }; exit 0 } catch { Write-Error $_.Exception.Message; exit 12 }" >nul 2>&1
set "_GATE_RC=%ERRORLEVEL%"
set "_MON_GATE_PIDFILE="
set "_MON_GATE_REPORT="
set "_MON_GATE_MARKERDIR="
set "_MON_GATE_LIMIT="
if "%_GATE_RC%"=="0" goto :eof
if not "%_GATE_RC%"=="1" goto :gate_broken
if not exist "%GATE_REPORT%" goto :gate_broken
for /f "usebackq tokens=1,2,3,* delims= " %%K in ("%GATE_REPORT%") do call :report_unstarted "%%K" "%%L" "%%M" "%%N"
if %FAIL_COUNT% EQU 0 goto :gate_broken
goto :eof


rem :parse_wait_seconds <caller_supplied_seconds>
rem Sets the wait limit to a caller-supplied number of seconds. Anything
rem that is not a 1-4 digit decimal, and zero, leaves READY_WAIT_MS at its
rem default.
:parse_wait_seconds
set "WAIT_INPUT=%~1"
for /f "delims=0123456789" %%N in ("%WAIT_INPUT%") do set "WAIT_INPUT="
if "%WAIT_INPUT%"=="" goto :eof
if not "%WAIT_INPUT:~4%"=="" goto :eof
set /a "WAIT_MS=%WAIT_INPUT%*1000"
if %WAIT_MS% EQU 0 goto :eof
if %WAIT_MS% GTR %MAX_READY_WAIT_MS% set "WAIT_MS=%MAX_READY_WAIT_MS%"
set "READY_WAIT_MS=%WAIT_MS%"
goto :eof


rem :report_unstarted <dead|silent> <pid> <exit_code> <script_file_name>
rem Records one monitor that did not start to the error log and to stderr,
rem then increments FAIL_COUNT.
:report_unstarted
set "LOST_KIND=%~1"
set "LOST_PID=%~2"
set "LOST_CODE=%~3"
set "LOST_NAME=%~4"
if /i "%LOST_KIND%"=="silent" goto :report_silent
>>"%ERR_FILE%" echo [%DATE% %TIME%] monitor %LOST_NAME% exited before reporting ready pid=%LOST_PID% exit=%LOST_CODE%
>&2 echo [start_monitors] monitor exited before reporting ready: %LOST_NAME% pid=%LOST_PID% exit=%LOST_CODE%
set /a FAIL_COUNT+=1
goto :eof


rem :report_silent
rem Records a monitor that was still running, and still had not reported
rem ready, when the wait limit ran out.
:report_silent
>>"%ERR_FILE%" echo [%DATE% %TIME%] monitor %LOST_NAME% did not report ready within %READY_WAIT_MS% ms pid=%LOST_PID%
>&2 echo [start_monitors] monitor did not report ready within %READY_WAIT_MS% ms: %LOST_NAME% pid=%LOST_PID%
set /a FAIL_COUNT+=1
goto :eof


rem :gate_broken
rem Handles a readiness gate that could not evaluate the fleet. Treated as
rem a failure so an unverifiable fleet never reports success.
:gate_broken
>>"%ERR_FILE%" echo [%DATE% %TIME%] monitor readiness gate failed rc=%_GATE_RC%
>&2 echo [start_monitors] monitor readiness gate could not confirm the monitors started rc=%_GATE_RC%
set /a FAIL_COUNT+=1
goto :eof


rem :launch_failed
rem Handles a monitor whose spawn never produced a PID. Increments
rem FAIL_COUNT after logging to the error log and to stderr.
:launch_failed
>>"%ERR_FILE%" echo [%DATE% %TIME%] failed to launch %SCRIPT_NAME%
>&2 echo [start_monitors] failed to launch monitor: %SCRIPT_NAME%
set /a FAIL_COUNT+=1
goto :eof
