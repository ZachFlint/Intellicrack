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
$script:ExitCode = 0

function Write-TraceFatal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$Code,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Message
    )
    Write-TraceError -Stage $Stage -Message $Message
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

    try {
        Add-Type -LiteralPath $traceEventDll -ErrorAction Stop
    } catch {
        Write-TraceFatal -Code 3 -Stage 'load_failed' -Message "TraceEvent assembly load failed: $($_.Exception.Message)"
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
        # Real-time only: passing $null as the file path keeps everything in-memory
        # and lets the in-process callbacks consume each event. No ETL file is
        # produced, so no out-of-band harvest is required.
        $script:Session = $sessionType::new($sessionName, $null)
        $script:Session.StopOnDispose = $true
    } catch {
        Write-TraceFatal -Code 4 -Stage 'session_create' -Message "TraceEventSession constructor failed: $($_.Exception.Message)"
        return
    }

    try {
        $verbose = [Microsoft.Diagnostics.Tracing.TraceEventLevel]::Verbose
        $allKeywords = [uint64]::MaxValue
        $script:Session.EnableProvider($auditApiProviderGuid, $verbose, $allKeywords) | Out-Null
    } catch {
        Write-TraceFatal -Code 4 -Stage 'enable_provider' -Message "EnableProvider failed: $($_.Exception.Message)"
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
    $source.UnhandledEvents.add_All($boundHandler)

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
        Register-ObjectEvent -InputObject $script:Timer -EventName Elapsed -Action $stopAction | Out-Null
        $script:Timer.Start()
    }

    try {
        $source.Process() | Out-Null
    } catch {
        Write-TraceFatal -Code 5 -Stage 'process' -Message $_.Exception.Message
    }
}

try {
    Invoke-ApiTrace -FilterPid $TargetPid -DurationSeconds $DurationSeconds
} catch {
    Write-TraceFatal -Code 5 -Stage 'session' -Message $_.Exception.Message
} finally {
    if ($null -ne $script:Timer) {
        try { $script:Timer.Stop() } catch { Write-TraceError -Stage 'timer_stop' -Message $_.Exception.Message }
        try { $script:Timer.Dispose() } catch { Write-TraceError -Stage 'timer_dispose' -Message $_.Exception.Message }
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
}

exit $script:ExitCode
