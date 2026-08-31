@echo off
rem Intellicrack Windows Sandbox monitor launcher.
rem Spawns every .ps1 monitor script in this directory with a shared
rem LogDir argument, records each surviving child PID into the
rem monitors.pids state file under the supplied log directory, and
rem propagates a non-zero exit code if any monitor fails to start.
rem
rem First positional argument (optional) overrides the log directory.
rem Default: %ProgramData%\Intellicrack\Sandbox\logs
rem Second positional argument (optional) pins the readiness grace period
rem to a fixed number of seconds. Range: 1 - 300. Omit it (or pass 0) to
rem let the readiness gate calibrate the window against the PowerShell
rem cold-start cost it measures in the environment it is actually running
rem in; see :readiness_gate for the derivation.

setlocal ENABLEEXTENSIONS

set "DEFAULT_LOG_DIR=%ProgramData%\Intellicrack\Sandbox\logs"
set "AUTO_GRACE_FACTOR=3"
set "AUTO_GRACE_FLOOR_MS=2000"
set "AUTO_GRACE_CEILING_MS=45000"
set "MAX_GRACE_MS=300000"
set "MON_DIR=%~dp0"
set "FAIL_COUNT=0"
set "LAUNCH_COUNT=0"
set "RC=0"

set "MON_LOGDIR=%DEFAULT_LOG_DIR%"
if not "%~1"=="" set "MON_LOGDIR=%~1"
set "GRACE_MS=0"
if not "%~2"=="" call :parse_grace_seconds "%~2"

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
set "PID_TMP=%MON_LOGDIR%\.start_%SCRIPT_NAME%.pid"
del "%PID_TMP%" 2>nul
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $stem=[IO.Path]::GetFileNameWithoutExtension('%SCRIPT_NAME%'); $log=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.out.log'); $err=Join-Path -Path '%MON_LOGDIR%' -ChildPath ('start_' + $stem + '.err.log'); try { $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','%SCRIPT_PATH%','-LogDir','%MON_LOGDIR%') -WindowStyle Hidden -PassThru -RedirectStandardOutput $log -RedirectStandardError $err; Set-Content -LiteralPath '%PID_TMP%' -Value ([string]$p.Id) -Encoding ascii; exit 0 } catch { Write-Error $_.Exception.Message; exit 12 }" >nul 2>&1

if not exist "%PID_TMP%" goto :launch_failed
set /p CHILD_PID=<"%PID_TMP%"
del "%PID_TMP%" 2>nul
if not defined CHILD_PID goto :launch_failed

>>"%PID_LIST%" echo %CHILD_PID% %SCRIPT_NAME%
goto :eof


rem :readiness_gate
rem Confirms every PID recorded in the PID file survived startup. Each
rem tracked child is opened once and then polled on its own process handle
rem until either all of them have exited or the grace window expires. A monitor that dies at any point inside
rem the window is reported as a startup failure, so detection no longer
rem depends on sampling liveness at one fixed offset that a cold-starting
rem powershell.exe can still be alive at.
rem
rem The window is derived, not guessed. A monitor that fails argument
rem binding dies during its own PowerShell cold start, so its death time
rem tracks the cold-start cost of the environment. Measured against the
rem gate's own boot time (its OS start time versus its first statement),
rem a doomed monitor took 1.08x-1.21x that cost in a 2-CPU container
rem (death 7204-8470 ms, gate boot 6564-7007 ms) and 1.39x-2.01x on a
rem 22-CPU host (death 829-1129 ms, gate boot 549-624 ms), both with a
rem six-monitor fleet starting concurrently. The gate has therefore
rem already absorbed 1.0x of that cost by the time it runs, leaving at
rem most 1.01x still to wait, and it waits AUTO_GRACE_FACTOR (3x) to keep
rem roughly a 3x margin in whatever environment it lands in. The floor and
rem ceiling bound a pathological reading. Survivors are rewritten back to
rem the PID file so stop_monitors never targets a reaped PID. FAIL_COUNT is
rem incremented once per monitor that exited inside the grace window, and
rem once more if liveness could not be evaluated at all.
:readiness_gate
del "%GATE_REPORT%" 2>nul
set "_MON_GATE_PIDFILE=%PID_LIST%"
set "_MON_GATE_REPORT=%GATE_REPORT%"
set "_MON_GATE_GRACE=%GRACE_MS%"
set "_MON_GATE_FACTOR=%AUTO_GRACE_FACTOR%"
set "_MON_GATE_FLOOR=%AUTO_GRACE_FLOOR_MS%"
set "_MON_GATE_CEILING=%AUTO_GRACE_CEILING_MS%"
set "_MON_GATE_INFO=%GATE_REPORT%.info"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $selfMs=[int]((Get-Date) - (Get-Process -Id $PID).StartTime).TotalMilliseconds; $pidFile=$env:_MON_GATE_PIDFILE; $report=$env:_MON_GATE_REPORT; $grace=[int]$env:_MON_GATE_GRACE; if ($grace -le 0) { $floor=[int]$env:_MON_GATE_FLOOR; $ceiling=[int]$env:_MON_GATE_CEILING; $grace=$selfMs * [int]$env:_MON_GATE_FACTOR; if ($grace -lt $floor) { $grace=$floor }; if ($grace -gt $ceiling) { $grace=$ceiling } }; [IO.File]::WriteAllText($env:_MON_GATE_INFO,('powershell_cold_start_ms=' + $selfMs + ' readiness_grace_ms=' + $grace)); $tracked=New-Object System.Collections.ArrayList; foreach ($line in [IO.File]::ReadAllLines($pidFile)) { $entry=$line.Trim(); if ($entry.Length -eq 0) { continue }; $parts=$entry.Split(@(' '),2,[StringSplitOptions]::RemoveEmptyEntries); $target=0; if (-not [int]::TryParse($parts[0],[ref]$target)) { continue }; $label='unknown'; if ($parts.Length -gt 1 -and $parts[1].Trim().Length -gt 0) { $label=$parts[1].Trim() }; $handle=$null; try { $handle=Get-Process -Id $target -ErrorAction Stop } catch { $handle=$null }; $null=$tracked.Add([pscustomobject]@{Target=$target;Label=$label;Handle=$handle}) }; $deadline=(Get-Date).AddMilliseconds($grace); while ($true) { $pending=0; foreach ($item in $tracked) { if ($null -ne $item.Handle -and -not $item.Handle.HasExited) { $pending=$pending+1 } }; if ($pending -eq 0) { break }; if ((Get-Date) -ge $deadline) { break }; Start-Sleep -Milliseconds 100 }; $dead=New-Object System.Collections.ArrayList; $alive=New-Object System.Collections.ArrayList; foreach ($item in $tracked) { if ($null -eq $item.Handle -or $item.Handle.HasExited) { $code='unknown'; if ($null -ne $item.Handle) { try { $code=[string]$item.Handle.ExitCode } catch { $code='unknown' } }; $null=$dead.Add(('{0} {1} {2}' -f $item.Target,$item.Label,$code)) } else { $null=$alive.Add(('{0} {1}' -f $item.Target,$item.Label)) } }; [IO.File]::WriteAllLines($pidFile,[string[]]$alive.ToArray()); [IO.File]::WriteAllLines($report,[string[]]$dead.ToArray()); if ($dead.Count -gt 0) { exit 1 }; exit 0 } catch { Write-Error $_.Exception.Message; exit 12 }" >nul 2>&1
set "_GATE_RC=%ERRORLEVEL%"
set "_MON_GATE_PIDFILE="
set "_MON_GATE_REPORT="
set "_MON_GATE_GRACE="
set "_MON_GATE_FACTOR="
set "_MON_GATE_FLOOR="
set "_MON_GATE_CEILING="
set "_MON_GATE_INFO="
if "%_GATE_RC%"=="0" goto :eof
if not "%_GATE_RC%"=="1" goto :gate_broken
if not exist "%GATE_REPORT%" goto :gate_broken
for /f "usebackq tokens=1,2,* delims= " %%P in ("%GATE_REPORT%") do call :report_dead "%%P" "%%Q" "%%R"
if %FAIL_COUNT% EQU 0 goto :gate_broken
goto :eof


rem :parse_grace_seconds <caller_supplied_seconds>
rem Pins the readiness window to a fixed number of seconds. Anything that
rem is not a 1-4 digit decimal is ignored and leaves GRACE_MS at 0, which
rem selects the self-calibrating window.
:parse_grace_seconds
set "GRACE_INPUT=%~1"
for /f "delims=0123456789" %%N in ("%GRACE_INPUT%") do set "GRACE_INPUT="
if "%GRACE_INPUT%"=="" goto :eof
if not "%GRACE_INPUT:~4%"=="" goto :eof
set /a "GRACE_MS=%GRACE_INPUT%*1000"
if %GRACE_MS% GTR %MAX_GRACE_MS% set "GRACE_MS=%MAX_GRACE_MS%"
goto :eof


rem :report_dead <pid> <script_file_name> <exit_code>
rem Records one startup casualty to the error log and to stderr, then
rem increments FAIL_COUNT.
:report_dead
set "DEAD_PID=%~1"
set "DEAD_NAME=%~2"
set "DEAD_CODE=%~3"
>>"%ERR_FILE%" echo [%DATE% %TIME%] monitor %DEAD_NAME% exited during startup pid=%DEAD_PID% exit=%DEAD_CODE%
>&2 echo [start_monitors] monitor exited immediately: %DEAD_NAME% pid=%DEAD_PID% exit=%DEAD_CODE%
set /a FAIL_COUNT+=1
goto :eof


rem :gate_broken
rem Handles a readiness gate that could not evaluate liveness. Treated as a
rem failure so an unverifiable fleet never reports success.
:gate_broken
>>"%ERR_FILE%" echo [%DATE% %TIME%] monitor readiness gate failed rc=%_GATE_RC%
>&2 echo [start_monitors] monitor readiness gate could not confirm monitor liveness rc=%_GATE_RC%
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
