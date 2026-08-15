[CmdletBinding()]
param(
    [string]$LogDir = '.',
    [int]$TargetPid = 0,
    [int]$DurationSeconds = 0
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$logPath = Join-Path -Path $LogDir -ChildPath 'api_trace.log'

function Write-TraceLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Line
    )
    Add-Content -LiteralPath $logPath -Value $Line -Encoding utf8
}

function Format-TraceField {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)][object]$Value
    )
    if ($null -eq $Value) { return '' }
    return ([string]$Value) -replace '\|', '_' -replace '[\r\n]+', ' '
}

function Write-TraceError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $ts = Get-Date -Format 'o'
    $detail = Format-TraceField -Value $Message
    Write-TraceLine -Line "$ts|tracer|0|ERROR|$Stage|$detail|-1"
}

function Find-TraceEventAssembly {
    [CmdletBinding()]
    param()

    $candidates = [System.Collections.Generic.List[string]]::new()

    if ($env:TRACE_EVENT_DLL) {
        $candidates.Add($env:TRACE_EVENT_DLL)
    }

    $scriptDir = $PSScriptRoot
    if (-not $scriptDir -and $PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
    }
    if ($scriptDir -and (Test-Path -LiteralPath $scriptDir)) {
        $localDll = Join-Path -Path $scriptDir -ChildPath 'Microsoft.Diagnostics.Tracing.TraceEvent.dll'
        if (Test-Path -LiteralPath $localDll) { $candidates.Add($localDll) }
    }

    if ($env:USERPROFILE) {
        $nugetRoot = Join-Path -Path $env:USERPROFILE -ChildPath '.nuget\packages\microsoft.diagnostics.tracing.traceevent'
        if (Test-Path -LiteralPath $nugetRoot) {
            $versions = Get-ChildItem -LiteralPath $nugetRoot -Directory -ErrorAction SilentlyContinue |
                Sort-Object -Property Name -Descending
            foreach ($ver in $versions) {
                $libRoot = Join-Path -Path $ver.FullName -ChildPath 'lib'
                if (-not (Test-Path -LiteralPath $libRoot)) { continue }
                $dlls = Get-ChildItem -LiteralPath $libRoot -Recurse -Filter 'Microsoft.Diagnostics.Tracing.TraceEvent.dll' -ErrorAction SilentlyContinue
                foreach ($dll in $dlls) { $candidates.Add($dll.FullName) }
            }
        }
    }

    $programFiles = 'C:\Program Files\TraceEvent'
    if (Test-Path -LiteralPath $programFiles) {
        $dlls = Get-ChildItem -LiteralPath $programFiles -Recurse -Filter 'Microsoft.Diagnostics.Tracing.TraceEvent.dll' -ErrorAction SilentlyContinue
        foreach ($dll in $dlls) { $candidates.Add($dll.FullName) }
    }

    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

#region TraceEventDependencyResolver
function Register-TraceEventDependencyResolver {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AssemblyDir
    )

    Get-ChildItem -LiteralPath $AssemblyDir -Filter '*.dll' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'Microsoft.Diagnostics.Tracing.TraceEvent.dll' } |
        ForEach-Object {
            $dependencyFile = $_
            try {
                [System.Reflection.Assembly]::LoadFrom($dependencyFile.FullName) | Out-Null
            } catch {
                Write-TraceError -Stage 'dependency_load' -Message "$($dependencyFile.Name): $($_.Exception.Message)"
            }
        }

    $resolver = [System.ResolveEventHandler] {
        param($resolveSender, $resolveArgs)
        $requestedName = ([System.Reflection.AssemblyName]$resolveArgs.Name).Name
        foreach ($loaded in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
            if ($loaded.GetName().Name -eq $requestedName) { return $loaded }
        }
        return $null
    }
    [System.AppDomain]::CurrentDomain.add_AssemblyResolve($resolver)
}
#endregion TraceEventDependencyResolver

function Get-AuditApiName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][int]$EventId
    )
    # Microsoft-Windows-Kernel-Audit-API-Calls provider {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
    # Event-id -> kernel API mapping per the provider manifest.
    switch ($EventId) {
        1 { return 'PsSetLoadImageNotifyRoutine' }
        2 { return 'NtTerminateProcess' }
        3 { return 'NtCreateSymbolicLinkObject' }
        4 { return 'SePrivilegeCheck' }
        5 { return 'NtOpenProcess' }
        6 { return 'NtOpenThread' }
        7 { return 'IoRegisterLastChanceShutdownNotification' }
        8 { return 'IoRegisterShutdownNotification' }
        default { return "AuditApi_EventId_$EventId" }
    }
}

function Resolve-PayloadField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Event,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        return $Event.PayloadByName($Name)
    } catch {
        return $null
    }
}

$script:Session = $null
$script:Timer = $null
$script:StopWatchTimer = $null
$script:StopWatchSubscriberId = $null
$script:StopWatchJob = $null
$script:DurationStopSubscriberId = $null
$script:DurationStopJob = $null
$script:ExitCode = 0
$script:StopEventName = 'IntellicrackMonitorStop'
$script:StopEvent = $null
$script:StopPollIntervalMs = 250
$script:LifecyclePath = Join-Path -Path $LogDir -ChildPath 'api_trace.lifecycle.log'

function Open-MonitorStopEvent {
    [CmdletBinding()]
    [OutputType([System.Threading.EventWaitHandle])]
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    $createdNew = $false
    try {
        $handle = [System.Threading.EventWaitHandle]::new(
            $false,
            [System.Threading.EventResetMode]::ManualReset,
            $Name,
            [ref]$createdNew)
        return $handle
    } catch [System.UnauthorizedAccessException] {
        try {
            return [System.Threading.EventWaitHandle]::OpenExisting($Name)
        } catch {
            return $null
        }
    } catch {
        return $null
    }
}

function Test-MonitorStopRequested {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($null -eq $script:StopEvent) { return $false }
    try {
        return $script:StopEvent.WaitOne(0)
    } catch {
        return $false
    }
}

function Write-TraceLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $false)][string]$Detail = ''
    )

    $ts = (Get-Date).ToString('o')
    $safeDetail = (Format-TraceField -Value $Detail)
    $line = "$ts|api_trace|$State|$safeDetail"
    try {
        Add-Content -LiteralPath $script:LifecyclePath -Value $line -Encoding utf8
    } catch {
        $null = $_
    }
}

function Write-TraceFatal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$Code,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][AllowNull()][System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    # The catch-all around Invoke-ApiTrace reports every unguarded failure under
    # the single stage 'session', and $_.Exception.Message names neither the
    # statement nor the line. A null-receiver failure therefore surfaced as a
    # bare "You cannot call a method on a null-valued expression" with nothing
    # to locate it by, which is what left S18-D08 undiagnosable across runs.
    # InvocationInfo is not enough on its own: once an error crosses a function
    # boundary it describes the *call site*, so it named the Invoke-ApiTrace
    # call rather than the statement that failed. ScriptStackTrace's first
    # frame is the innermost one and carries the real function, file and line.
    $located = $Message
    if ($null -ne $ErrorRecord) {
        $frames = @()
        if ($ErrorRecord.ScriptStackTrace) {
            $frames = @($ErrorRecord.ScriptStackTrace -split "`r?`n" | Where-Object { $_.Trim() })
        }
        if ($frames.Count -gt 0) {
            $located = '{0} [{1}]' -f $Message, $frames[0].Trim()
        } elseif ($null -ne $ErrorRecord.InvocationInfo) {
            $info = $ErrorRecord.InvocationInfo
            $statement = ([string]$info.Line).Trim()
            $scriptLeaf = if ($info.ScriptName) { Split-Path -Leaf -Path $info.ScriptName } else { 'api_trace.ps1' }
            $located = '{0} [at {1}: line {2}: {3}]' -f $Message, $scriptLeaf, $info.ScriptLineNumber, $statement
        }
    }
    Write-TraceError -Stage $Stage -Message $located
    $script:ExitCode = $Code
}

function Invoke-ApiTrace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$FilterPid,
        [Parameter(Mandatory = $true)][int]$DurationSeconds
    )

    $sessionName = 'IntApiTrace'
    $auditApiProviderGuid = [Guid]'E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23'

    $traceEventDll = Find-TraceEventAssembly
    if (-not $traceEventDll) {
        Write-TraceFatal -Code 2 -Stage 'unavailable' -Message 'Microsoft.Diagnostics.Tracing.TraceEvent.dll not found in $env:TRACE_EVENT_DLL, $PSScriptRoot, $env:USERPROFILE\.nuget\packages\microsoft.diagnostics.tracing.traceevent, or C:\Program Files\TraceEvent'
        return
    }

    $traceEventDir = Split-Path -Parent $traceEventDll
    Register-TraceEventDependencyResolver -AssemblyDir $traceEventDir

    try {
        Add-Type -LiteralPath $traceEventDll -ErrorAction Stop
    } catch {
        Write-TraceFatal -Code 3 -Stage 'load_failed' -Message "TraceEvent assembly load failed: $($_.Exception.Message)" -ErrorRecord $_
        return
    }

    $sessionType = [System.Type]::GetType(
        'Microsoft.Diagnostics.Tracing.Session.TraceEventSession, Microsoft.Diagnostics.Tracing.TraceEvent',
        $false
    )
    if ($null -eq $sessionType) {
        Write-TraceFatal -Code 3 -Stage 'type_missing' -Message 'TraceEventSession type not exposed by loaded assembly'
        return
    }

    try {
        # Real-time only: the in-process callbacks consume each event, so no ETL
        # file is produced and no out-of-band harvest is required. The overload
        # has to be named explicitly to get that. TraceEvent 3.2.5 declares no
        # (name, fileName) constructor at all - only (name, options) and
        # (name, fileName, options) - so passing $null as a second argument
        # bound the options parameter to null and produced a *file* session with
        # no file. Construction still succeeded; the first EnableProvider then
        # failed with ERROR_BAD_PATHNAME (0x800700A1), one call away from the
        # cause, and the whole API Calls tab was empty (S17-D70).
        $script:Session = $sessionType::new($sessionName, [Microsoft.Diagnostics.Tracing.Session.TraceEventSessionOptions]::Create)
        $script:Session.StopOnDispose = $true
    } catch {
        Write-TraceFatal -Code 4 -Stage 'session_create' -Message "TraceEventSession constructor failed: $($_.Exception.Message)" -ErrorRecord $_
        return
    }

    try {
        $verbose = [Microsoft.Diagnostics.Tracing.TraceEventLevel]::Verbose
        $allKeywords = [uint64]::MaxValue
        $script:Session.EnableProvider($auditApiProviderGuid, $verbose, $allKeywords) | Out-Null
    } catch {
        Write-TraceFatal -Code 4 -Stage 'enable_provider' -Message "EnableProvider failed: $($_.Exception.Message)" -ErrorRecord $_
        return
    }

    $source = $script:Session.Source
    $script:FilterPid = $FilterPid

    $handler = {
        param($evt)
        try {
            $procIdRaw = 0
            try { $procIdRaw = [int]$evt.ProcessID } catch { $procIdRaw = 0 }

            $targetField = Resolve-PayloadField -Event $evt -Name 'TargetProcessId'
            $targetPidVal = 0
            if ($null -ne $targetField) {
                try { $targetPidVal = [int]$targetField } catch { $targetPidVal = 0 }
            }

            if ($script:FilterPid -ne 0) {
                if ($procIdRaw -ne $script:FilterPid -and $targetPidVal -ne $script:FilterPid) { return }
            }

            $ts = Get-Date -Format 'o'
            $procName = 'unknown'
            if ($procIdRaw -gt 0) {
                $p = Get-Process -Id $procIdRaw -ErrorAction SilentlyContinue
                if ($p) { $procName = $p.Name }
            }

            $eventId = 0
            try { $eventId = [int]$evt.ID } catch { $eventId = 0 }
            $apiName = Get-AuditApiName -EventId $eventId
            $module = 'ntoskrnl.exe'

            $argParts = [System.Collections.Generic.List[string]]::new()
            $payloadNames = $null
            try { $payloadNames = $evt.PayloadNames } catch { $payloadNames = $null }
            if ($payloadNames) {
                foreach ($name in $payloadNames) {
                    if ([string]::IsNullOrEmpty($name)) { continue }
                    if ($name -eq 'ReturnCode') { continue }
                    $val = Resolve-PayloadField -Event $evt -Name $name
                    $safeName = Format-TraceField -Value $name
                    $safeVal = Format-TraceField -Value $val
                    $argParts.Add("$safeName=$safeVal")
                }
            }
            $arguments = ($argParts -join ';')

            $returnValue = ''
            $rc = Resolve-PayloadField -Event $evt -Name 'ReturnCode'
            if ($null -ne $rc) {
                try {
                    $returnValue = '0x{0:X}' -f [uint32]$rc
                } catch {
                    $returnValue = Format-TraceField -Value $rc
                }
            }

            Write-TraceLine -Line "$ts|$procName|$procIdRaw|$apiName|$module|$arguments|$returnValue"
        } catch {
            Write-TraceError -Stage 'handler' -Message $_.Exception.Message
        }
    }

    $boundHandler = $handler.GetNewClosure()
    $source.Dynamic.add_All($boundHandler)
    # UnhandledEvents is a .NET *event* on TraceEventDispatcher, not a parser
    # property like Dynamic. PowerShell surfaces events only as add_/remove_
    # methods, so reading $source.UnhandledEvents always yielded $null and the
    # .add_All() on it threw before Process() was ever reached - every run of
    # this collector died here with the providers already enabled and the
    # handlers already wired, so the API Calls tab was empty on every run
    # (S18-D08). The event's own accessor takes the Action<TraceEvent> directly.
    $source.add_UnhandledEvents($boundHandler)

    $tsStart = Get-Date -Format 'o'
    Write-TraceLine -Line "$tsStart|tracer|0|START|$sessionName|provider=$auditApiProviderGuid;pid_filter=$FilterPid;duration=$DurationSeconds|0"

    if ($DurationSeconds -gt 0) {
        $script:Timer = New-Object System.Timers.Timer
        $script:Timer.Interval = [double]($DurationSeconds * 1000)
        $script:Timer.AutoReset = $false
        $stopAction = {
            try {
                if ($null -ne $script:Session -and $null -ne $script:Session.Source) {
                    $script:Session.Source.StopProcessing()
                }
            } catch {
                Write-TraceError -Stage 'timer_stop_processing' -Message $_.Exception.Message
            }
        }
        $script:DurationStopSubscriberId = 'IntApiTraceDurationTimer'
        try { Unregister-Event -SourceIdentifier $script:DurationStopSubscriberId -ErrorAction SilentlyContinue } catch { $null = $_ }
        $script:DurationStopJob = Register-ObjectEvent -InputObject $script:Timer -EventName Elapsed `
            -SourceIdentifier $script:DurationStopSubscriberId -Action $stopAction
        $script:Timer.Start()
    }

    $script:StopWatchTimer = New-Object System.Timers.Timer
    $script:StopWatchTimer.Interval = [double]$script:StopPollIntervalMs
    $script:StopWatchTimer.AutoReset = $true
    $stopWatchAction = {
        try {
            if ($null -eq $script:StopEvent) { return }
            if (-not $script:StopEvent.WaitOne(0)) { return }
            if ($null -ne $script:Session -and $null -ne $script:Session.Source) {
                try { $script:Session.Source.StopProcessing() } catch { $null = $_ }
            }
            if ($null -ne $script:StopWatchTimer) {
                try { $script:StopWatchTimer.Stop() } catch { $null = $_ }
            }
        } catch {
            $null = $_
        }
    }
    $script:StopWatchSubscriberId = 'IntApiTraceStopWatcher'
    try { Unregister-Event -SourceIdentifier $script:StopWatchSubscriberId -ErrorAction SilentlyContinue } catch { $null = $_ }
    $script:StopWatchJob = Register-ObjectEvent -InputObject $script:StopWatchTimer -EventName Elapsed `
        -SourceIdentifier $script:StopWatchSubscriberId -Action $stopWatchAction
    $script:StopWatchTimer.Start()

    try {
        # Pumped through psbase deliberately. PowerShell's adapted-member binder
        # refuses this one call - "the result type 'System.Boolean' of the
        # dynamic binding produced by binder 'PSInvokeMember: Process' is not
        # compatible with the result type 'System.Object' expected by the call
        # site" - on both Windows PowerShell and PowerShell 7, against both
        # ETWTraceEventSource and EventPipeEventSource, with or without any
        # handler registered. It is specific to the member name: the Boolean
        # EnableProvider above binds normally. psbase reaches the .NET object
        # directly and the same source then delivers its events (S18-D08).
        $source.psbase.Process() | Out-Null
    } catch {
        Write-TraceFatal -Code 5 -Stage 'process' -Message $_.Exception.Message -ErrorRecord $_
    }
}

$script:StopEvent = Open-MonitorStopEvent -Name $script:StopEventName
Write-TraceLifecycle -State 'started' -Detail "pid_filter=$TargetPid duration=$DurationSeconds stop_event=$script:StopEventName"

try {
    Invoke-ApiTrace -FilterPid $TargetPid -DurationSeconds $DurationSeconds
} catch {
    Write-TraceFatal -Code 5 -Stage 'session' -Message $_.Exception.Message -ErrorRecord $_
} finally {
    if ($null -ne $script:Timer) {
        try { $script:Timer.Stop() } catch { Write-TraceError -Stage 'timer_stop' -Message $_.Exception.Message }
        try { $script:Timer.Dispose() } catch { Write-TraceError -Stage 'timer_dispose' -Message $_.Exception.Message }
    }
    if ($null -ne $script:DurationStopSubscriberId) {
        try { Unregister-Event -SourceIdentifier $script:DurationStopSubscriberId -ErrorAction SilentlyContinue } catch { $null = $_ }
        $script:DurationStopSubscriberId = $null
    }
    if ($null -ne $script:DurationStopJob) {
        try { Remove-Job -Job $script:DurationStopJob -Force -ErrorAction SilentlyContinue } catch { $null = $_ }
        $script:DurationStopJob = $null
    }
    if ($null -ne $script:StopWatchTimer) {
        try { $script:StopWatchTimer.Stop() } catch { Write-TraceError -Stage 'stop_watch_timer_stop' -Message $_.Exception.Message }
        try { $script:StopWatchTimer.Dispose() } catch { Write-TraceError -Stage 'stop_watch_timer_dispose' -Message $_.Exception.Message }
        $script:StopWatchTimer = $null
    }
    if ($null -ne $script:StopWatchSubscriberId) {
        try { Unregister-Event -SourceIdentifier $script:StopWatchSubscriberId -ErrorAction SilentlyContinue } catch { $null = $_ }
        $script:StopWatchSubscriberId = $null
    }
    if ($null -ne $script:StopWatchJob) {
        try { Remove-Job -Job $script:StopWatchJob -Force -ErrorAction SilentlyContinue } catch { $null = $_ }
        $script:StopWatchJob = $null
    }
    if ($null -ne $script:Session) {
        try {
            $script:Session.Dispose()
        } catch {
            Write-TraceError -Stage 'dispose' -Message $_.Exception.Message
            if ($script:ExitCode -eq 0) { $script:ExitCode = 6 }
        }
    }
    $tsStop = Get-Date -Format 'o'
    Write-TraceLine -Line "$tsStop|tracer|0|STOP|IntApiTrace||$($script:ExitCode)"
    Write-TraceLifecycle -State 'stopped' -Detail "exit_code=$($script:ExitCode) stop_requested=$(Test-MonitorStopRequested)"
    if ($null -ne $script:StopEvent) {
        try { $script:StopEvent.Dispose() } catch { $null = $_ }
        $script:StopEvent = $null
    }
}

exit $script:ExitCode
