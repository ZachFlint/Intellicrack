[CmdletBinding()]
param(
    [string]$LogDir = '.',
    [int]$TargetPid = 0
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$script:logPathRef = Join-Path -Path $LogDir -ChildPath 'injection_monitor.log'
$script:diagPathRef = Join-Path -Path $LogDir -ChildPath 'injection_monitor.diag.log'
$script:lifecyclePathRef = Join-Path -Path $LogDir -ChildPath 'injection_monitor.lifecycle.log'
$script:targetPidFilter = [int]$TargetPid
$script:StopEventName = 'IntellicrackMonitorStop'
$script:StopEvent = $null
$script:StopPollIntervalMs = 250
$script:StopWatchTimer = $null
$script:StopWatchSubscriberId = $null
$script:StopWatchJob = $null
$script:CurrentInjectionSource = $null

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

function Write-InjectionLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $false)][string]$Detail = ''
    )
    $ts = (Get-Date).ToString('o')
    $safeDetail = ($Detail -replace '\|', '_' -replace '[\r\n]+', ' ')
    $line = "$ts|injection_monitor|$State|$safeDetail"
    try {
        Add-Content -LiteralPath $script:lifecyclePathRef -Value $line -Encoding utf8
    } catch {
        $null = $_
    }
}

function Write-InjectionRecord {
    [CmdletBinding()]
    param(
        [string]$Timestamp,
        [int]$SourcePid,
        [string]$SourceName,
        [int]$InjectedPid,
        [string]$InjectedName,
        [string]$InjectionType,
        [string]$ApiCalls
    )
    $safeSource = ($SourceName -replace '\|', '_')
    $safeInjected = ($InjectedName -replace '\|', '_')
    $safeType = ($InjectionType -replace '\|', '_')
    $safeApis = ($ApiCalls -replace '\|', '_')
    $record = "$Timestamp|$SourcePid|$safeSource|$InjectedPid|$safeInjected|$safeType|$safeApis"
    Add-Content -LiteralPath $script:logPathRef -Value $record -Encoding utf8
}

function Write-InjectionDiagnostic {
    [CmdletBinding()]
    param(
        [string]$Timestamp,
        [string]$Category,
        [string]$Detail,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    # $_.Exception.Message alone named neither the statement nor the line, so a
    # null-receiver failure could not be located (S17-D79). The error record's
    # InvocationInfo carries the offending source line and its number; folding
    # them into the detail makes the diagnostic point at the exact statement.
    $located = $Detail
    if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.InvocationInfo) {
        $info = $ErrorRecord.InvocationInfo
        $statement = ([string]$info.Line).Trim()
        $scriptLeaf = if ($info.ScriptName) { Split-Path -Leaf -Path $info.ScriptName } else { 'injection_monitor.ps1' }
        $located = '{0} [at {1}:{2}: {3}]' -f $Detail, $scriptLeaf, $info.ScriptLineNumber, $statement
    }
    $safeDetail = ($located -replace '\|', '_' -replace '[\r\n]+', ' ')
    $line = "$Timestamp|$Category|$safeDetail"
    Add-Content -LiteralPath $script:diagPathRef -Value $line -Encoding utf8
}

function Assert-TraceObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Detail
    )
    # A null Source or Kernel is the shape S17-D79 saw live: reading a property
    # off $null never throws, so the null propagated silently to the first
    # method call on the parser and surfaced three lines on as an unlocated
    # "call a method on a null-valued expression". Failing at the read itself,
    # with a named category, states the real cause where it happens.
    if ($null -eq $Value) {
        $ts = Get-Date -Format 'o'
        Write-InjectionDiagnostic -Timestamp $ts -Category $Category -Detail $Detail
        throw $Detail
    }
    return $Value
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
                $ts = Get-Date -Format 'o'
                Write-InjectionDiagnostic -Timestamp $ts -Category 'traceevent_dependency_load_failed' `
                    -Detail "$($dependencyFile.Name): $($_.Exception.Message)"
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

$traceEventAssembly = $null
$searchRoots = @()
if ($PSScriptRoot) { $searchRoots += $PSScriptRoot }
if ($env:TRACE_EVENT_DLL_DIR) { $searchRoots += $env:TRACE_EVENT_DLL_DIR }
$searchRoots += (Join-Path -Path $env:USERPROFILE -ChildPath '.nuget\packages\microsoft.diagnostics.tracing.traceevent')
$searchRoots += 'C:\Program Files\dotnet\shared'
$searchRoots += (Join-Path -Path ${env:ProgramFiles} -ChildPath 'Microsoft Visual Studio')

foreach ($root in $searchRoots) {
    if (-not $root) { continue }
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $candidate = Get-ChildItem -Path $root -Filter 'Microsoft.Diagnostics.Tracing.TraceEvent.dll' -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($candidate) {
        $traceEventAssembly = $candidate.FullName
        break
    }
}

if (-not $traceEventAssembly) {
    $ts = Get-Date -Format 'o'
    Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
        -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
        -ApiCalls 'TraceEvent.dll not found'
    Write-InjectionDiagnostic -Timestamp $ts -Category 'traceevent_dll_missing' `
        -Detail "searched=$([string]::Join(';', $searchRoots))"
    throw 'Microsoft.Diagnostics.Tracing.TraceEvent.dll not found in any search root'
}

$traceEventDir = Split-Path -Parent $traceEventAssembly
Register-TraceEventDependencyResolver -AssemblyDir $traceEventDir

try {
    Add-Type -Path $traceEventAssembly
} catch {
    $ts = Get-Date -Format 'o'
    $msg = $_.Exception.Message
    Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
        -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
        -ApiCalls "TraceEvent.dll load failed: $($msg -replace '\|', '_')"
    Write-InjectionDiagnostic -Timestamp $ts -Category 'traceevent_dll_load_failed' `
        -Detail $msg
    throw "Failed to load Microsoft.Diagnostics.Tracing.TraceEvent assembly: $msg"
}

$sessionName = 'IntellicrackInjectionMonitor'
$kernelProcessGuid = [Guid]::Parse('22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716')
$threatIntelGuid = [Guid]::Parse('f4e1897c-bb5d-5668-f1d8-040f4d8dd344')
$threadStartKeyword = [uint64]0x20

$script:threatIntelEnabled = $false
$script:moduleCacheTtl = 5
$script:allocTtl = 30
$script:allocCap = 4096
$script:moduleCache = @{}
$script:moduleCacheStamp = @{}
$script:virtualAllocByThread = @{}

function Sync-ModuleCache {
    [CmdletBinding()]
    param([int]$ProcId)
    $now = [DateTime]::UtcNow
    $stamp = $script:moduleCacheStamp[$ProcId]
    if ($stamp -and ($now - $stamp).TotalSeconds -lt $script:moduleCacheTtl) { return }
    try {
        $proc = Get-Process -Id $ProcId -ErrorAction Stop
        $ranges = New-Object System.Collections.Generic.List[object]
        foreach ($mod in $proc.Modules) {
            $base = [int64]$mod.BaseAddress.ToInt64()
            $size = [int64]$mod.ModuleMemorySize
            $path = [string]$mod.FileName
            $ranges.Add([pscustomobject]@{
                Start = $base
                End   = $base + $size
                Path  = $path
            }) | Out-Null
        }
        $script:moduleCache[$ProcId] = $ranges
        $script:moduleCacheStamp[$ProcId] = $now
    } catch {
        $script:moduleCache[$ProcId] = New-Object System.Collections.Generic.List[object]
        $script:moduleCacheStamp[$ProcId] = $now
    }
}

function Resolve-StartAddress {
    [CmdletBinding()]
    param(
        [int]$ProcId,
        [int64]$Address
    )
    Sync-ModuleCache -ProcId $ProcId
    $ranges = $script:moduleCache[$ProcId]
    $outside = [pscustomobject]@{ InModule = $false; Suspicious = $true; Path = '' }
    if (-not $ranges) { return $outside }
    foreach ($r in $ranges) {
        if ($Address -ge $r.Start -and $Address -lt $r.End) {
            $suspicious = ($r.Path -match '\\Temp\\|\\AppData\\Local\\Temp\\')
            return [pscustomobject]@{ InModule = $true; Suspicious = [bool]$suspicious; Path = $r.Path }
        }
    }
    return $outside
}

function Get-ProcessNameSafe {
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$ProcId)
    try {
        $proc = Get-Process -Id $ProcId -ErrorAction Stop
        return $proc.ProcessName
    } catch {
        return 'unknown'
    }
}

function Resolve-PayloadValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$EtwEvent,
        [Parameter(Mandatory = $true)][string[]]$FieldNames
    )
    foreach ($f in $FieldNames) {
        try {
            $val = $EtwEvent.PayloadByName($f)
            if ($null -ne $val) { return $val }
        } catch {
            $null = $_
        }
    }
    return $null
}

function Get-OpcodeNameSafe {
    [CmdletBinding()]
    [OutputType([string])]
    param($EtwEvent)
    try { return [string]$EtwEvent.OpcodeName } catch { return '' }
}

function Get-TaskNameSafe {
    [CmdletBinding()]
    [OutputType([string])]
    param($EtwEvent)
    try { return [string]$EtwEvent.TaskName } catch { return '' }
}

function Get-ProviderEventApiName {
    [CmdletBinding()]
    [OutputType([string])]
    param($EtwEvent)

    $opcode = Get-OpcodeNameSafe -EtwEvent $EtwEvent
    $task = Get-TaskNameSafe -EtwEvent $EtwEvent
    if ($opcode -and $task) { return "$task/$opcode" }
    if ($opcode) { return $opcode }
    if ($task) { return $task }
    try {
        $name = [string]$EtwEvent.EventName
        if ($name) { return $name }
    } catch {
        $null = $_
    }
    return "EventId_$([int]$EtwEvent.ID)"
}

$script:StopEvent = Open-MonitorStopEvent -Name $script:StopEventName
Write-InjectionLifecycle -State 'started' -Detail "pid_filter=$script:targetPidFilter stop_event=$script:StopEventName"

$session = $null
try {
    $sessionType = [Type]::GetType('Microsoft.Diagnostics.Tracing.Session.TraceEventSession, Microsoft.Diagnostics.Tracing.TraceEvent')
    if (-not $sessionType) {
        $ts = Get-Date -Format 'o'
        Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
            -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
            -ApiCalls 'TraceEvent.dll not found'
        Write-InjectionDiagnostic -Timestamp $ts -Category 'traceevent_session_type_missing' `
            -Detail 'TraceEventSession type not loaded'
        throw 'TraceEventSession type unavailable after Add-Type'
    }

    try {
        $existingStop = [Microsoft.Diagnostics.Tracing.Session.TraceEventSession]::new($sessionName)
        $existingStop.Stop($true) | Out-Null
        $existingStop.Dispose()
    } catch {
        $null = $_
    }

    $session = [Microsoft.Diagnostics.Tracing.Session.TraceEventSession]::new($sessionName)
    $session.StopOnDispose = $true

    $kernelFlags = [Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser+Keywords]::Thread `
        -bor [Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser+Keywords]::VirtualAlloc `
        -bor [Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser+Keywords]::VAMap
    $session.EnableKernelProvider($kernelFlags, [Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser+Keywords]::None) | Out-Null

    try {
        $session.EnableProvider($kernelProcessGuid, [Microsoft.Diagnostics.Tracing.TraceEventLevel]::Informational, $threadStartKeyword) | Out-Null
    } catch {
        $ts = Get-Date -Format 'o'
        Write-InjectionDiagnostic -Timestamp $ts -Category 'kernel_process_provider_enable_failed' `
            -Detail $_.Exception.Message
    }

    try {
        $session.EnableProvider($threatIntelGuid, [Microsoft.Diagnostics.Tracing.TraceEventLevel]::Informational, [uint64]::MaxValue) | Out-Null
        $script:threatIntelEnabled = $true
    } catch {
        $script:threatIntelEnabled = $false
        $ts = Get-Date -Format 'o'
        Write-InjectionDiagnostic -Timestamp $ts -Category 'threat_intel_provider_unavailable' `
            -Detail "$($_.Exception.Message); falling back to narrowed Kernel-Process heuristic; events labelled remote_thread_start"
        Write-Warning "Microsoft-Windows-Threat-Intelligence provider unavailable: $($_.Exception.Message)"
    }

    $source = Assert-TraceObject -Value $session.Source -Category 'trace_source_null' `
        -Detail 'TraceEventSession.Source returned null; the real-time ETW source was not created, so no parser can be built'
    $kernelParser = Assert-TraceObject -Value $source.Kernel -Category 'trace_kernel_parser_null' `
        -Detail 'ETWTraceEventSource.Kernel returned null; the kernel event handlers cannot be registered'
    $dynamicParser = New-Object Microsoft.Diagnostics.Tracing.Parsers.DynamicTraceEventParser($source)

    $kernelParser.add_ThreadStart({
        param($evt)
        try {
            $evtPid = [int]$evt.ProcessID
            if ($script:targetPidFilter -ne 0 -and $evtPid -ne $script:targetPidFilter) { return }
            if ($evtPid -le 4) { return }

            $startVal = Resolve-PayloadValue -EtwEvent $evt -FieldNames @('Win32StartAddr', 'StartAddr')
            if ($null -eq $startVal) { return }
            $startAddr = [int64]$startVal
            if ($startAddr -eq 0) { return }

            $resolution = Resolve-StartAddress -ProcId $evtPid -Address $startAddr
            if (-not $resolution.Suspicious -and $resolution.InModule) { return }

            $threadId = [int]$evt.ThreadID
            $sourcePid = 0
            $parentVal = Resolve-PayloadValue -EtwEvent $evt -FieldNames @('ParentProcessID', 'ParentPid', 'CreatorProcessID')
            if ($null -ne $parentVal) { $sourcePid = [int]$parentVal }
            if ($sourcePid -eq 0) { $sourcePid = $evtPid }

            $sourceName = Get-ProcessNameSafe -ProcId $sourcePid
            $targetName = Get-ProcessNameSafe -ProcId $evtPid
            $apiName = Get-ProviderEventApiName -EtwEvent $evt

            $hasAlloc = $script:virtualAllocByThread.ContainsKey($threadId)
            if ($hasAlloc) {
                $script:virtualAllocByThread.Remove($threadId) | Out-Null
            }

            if ($script:threatIntelEnabled) {
                if ($resolution.InModule -and $resolution.Suspicious) {
                    $injType = 'remote_thread_in_temp_module'
                } elseif (-not $resolution.InModule) {
                    $injType = 'remote_thread_outside_modules'
                } else {
                    $injType = 'remote_thread_start'
                }
            } else {
                $injType = 'remote_thread_start'
            }

            $apiList = New-Object System.Collections.Generic.List[string]
            $apiList.Add($apiName) | Out-Null
            if ($hasAlloc) { $apiList.Add('KernelTrace/VirtualAlloc') | Out-Null }
            $unique = $apiList | Select-Object -Unique

            $ts = Get-Date -Format 'o'
            Write-InjectionRecord -Timestamp $ts -SourcePid $sourcePid -SourceName $sourceName `
                -InjectedPid $evtPid -InjectedName $targetName `
                -InjectionType $injType -ApiCalls ($unique -join ',')
        } catch {
            $ts = Get-Date -Format 'o'
            Write-InjectionDiagnostic -Timestamp $ts -Category 'thread_start_handler_error' `
                -Detail $_.Exception.Message
        }
    })

    # KernelTraceEventParser calls these VirtualMemAlloc/VirtualMemFree, both
    # carrying VirtualAllocTraceData. There is no VirtualMemVirtualAlloc, and
    # PowerShell resolves add_* late, so registering that name did not fail at
    # load: the monitor started, reported itself healthy, enabled its kernel
    # provider and then died on this line about a second in - taking the
    # narrowed Kernel-Process fallback with it and leaving the Injections tab
    # empty on every run (S17-D71).
    $kernelParser.add_VirtualMemAlloc({
        param($evt)
        try {
            $evtPid = [int]$evt.ProcessID
            if ($script:targetPidFilter -ne 0 -and $evtPid -ne $script:targetPidFilter) { return }
            $threadId = [int]$evt.ThreadID
            $script:virtualAllocByThread[$threadId] = [DateTime]::UtcNow
            if ($script:virtualAllocByThread.Count -gt $script:allocCap) {
                $cutoff = [DateTime]::UtcNow.AddSeconds(-$script:allocTtl)
                $stale = @($script:virtualAllocByThread.GetEnumerator() |
                    Where-Object { $_.Value -lt $cutoff } |
                    Select-Object -ExpandProperty Key)
                foreach ($k in $stale) { $script:virtualAllocByThread.Remove($k) | Out-Null }
            }
        } catch {
            $ts = Get-Date -Format 'o'
            Write-InjectionDiagnostic -Timestamp $ts -Category 'virtual_alloc_handler_error' `
                -Detail $_.Exception.Message
        }
    })

    $kernelParser.add_VirtualMemFree({
        param($evt)
        try {
            $threadId = [int]$evt.ThreadID
            if ($script:virtualAllocByThread.ContainsKey($threadId)) {
                $script:virtualAllocByThread.Remove($threadId) | Out-Null
            }
        } catch {
            $ts = Get-Date -Format 'o'
            Write-InjectionDiagnostic -Timestamp $ts -Category 'virtual_free_handler_error' `
                -Detail $_.Exception.Message
        }
    })

    $threatIntelHandler = {
        param($evt)
        try {
            $providerName = ''
            try { $providerName = [string]$evt.ProviderName } catch { $providerName = '' }
            if ($providerName -ne 'Microsoft-Windows-Threat-Intelligence') { return }

            $apiName = Get-ProviderEventApiName -EtwEvent $evt
            if ($apiName -notmatch 'CreateThread|CreateUserThread|CreateThreadEx|AllocVirtualMemory|WriteVirtualMemory|MapView|ProtectVirtualMemory') {
                return
            }

            $targetVal = Resolve-PayloadValue -EtwEvent $evt -FieldNames @('TargetProcessId', 'TargetProcessID', 'ProcessId', 'ProcessID')
            if ($null -eq $targetVal) { return }
            $targetPid = [int]$targetVal
            if ($script:targetPidFilter -ne 0 -and $targetPid -ne $script:targetPidFilter) { return }
            if ($targetPid -le 4) { return }

            $sourceVal = Resolve-PayloadValue -EtwEvent $evt -FieldNames @('CallingProcessId', 'CallingProcessID', 'SourceProcessId', 'SourceProcessID')
            $sourcePid = if ($null -ne $sourceVal) { [int]$sourceVal } else { [int]$evt.ProcessID }

            $sourceName = Get-ProcessNameSafe -ProcId $sourcePid
            $targetName = Get-ProcessNameSafe -ProcId $targetPid

            $injType = switch -Regex ($apiName) {
                'CreateUserThread|CreateThreadEx|CreateThread' { 'remote_thread_create' }
                'AllocVirtualMemory|ProtectVirtualMemory' { 'remote_memory_alloc' }
                'WriteVirtualMemory' { 'remote_memory_write' }
                'MapView' { 'remote_section_map' }
                Default { 'threat_intel_event' }
            }

            $ts = Get-Date -Format 'o'
            Write-InjectionRecord -Timestamp $ts -SourcePid $sourcePid -SourceName $sourceName `
                -InjectedPid $targetPid -InjectedName $targetName `
                -InjectionType $injType -ApiCalls "Microsoft-Windows-Threat-Intelligence/$apiName"
        } catch {
            $ts = Get-Date -Format 'o'
            Write-InjectionDiagnostic -Timestamp $ts -Category 'threat_intel_handler_error' `
                -Detail $_.Exception.Message
        }
    }

    $dynamicParser.add_All($threatIntelHandler)
    # UnhandledEvents is a .NET *event* on TraceEventDispatcher, not a parser
    # property. PowerShell surfaces events only as add_/remove_ methods, so
    # reading $source.UnhandledEvents always yielded $null and the .add_All()
    # on it threw with every provider enabled and every kernel handler already
    # registered, one statement short of Process() - the Injections tab was
    # empty on every run (S18-D08). The event accessor takes the delegate.
    $source.add_UnhandledEvents($threatIntelHandler)

    $script:CurrentInjectionSource = $source
    $script:StopWatchTimer = New-Object System.Timers.Timer
    $script:StopWatchTimer.Interval = [double]$script:StopPollIntervalMs
    $script:StopWatchTimer.AutoReset = $true
    $stopWatchAction = {
        try {
            if ($null -eq $script:StopEvent) { return }
            if (-not $script:StopEvent.WaitOne(0)) { return }
            if ($null -ne $script:CurrentInjectionSource) {
                try { $script:CurrentInjectionSource.StopProcessing() } catch { $null = $_ }
            }
            if ($null -ne $script:StopWatchTimer) {
                try { $script:StopWatchTimer.Stop() } catch { $null = $_ }
            }
        } catch {
            $null = $_
        }
    }
    $script:StopWatchSubscriberId = 'IntInjectionStopWatcher'
    try { Unregister-Event -SourceIdentifier $script:StopWatchSubscriberId -ErrorAction SilentlyContinue } catch { $null = $_ }
    $script:StopWatchJob = Register-ObjectEvent -InputObject $script:StopWatchTimer -EventName Elapsed `
        -SourceIdentifier $script:StopWatchSubscriberId -Action $stopWatchAction
    $script:StopWatchTimer.Start()

    # Pumped through psbase: PowerShell's adapted-member binder refuses this one
    # call ("result type 'System.Boolean' ... not compatible with ... 'System.Object'
    # expected by the call site") on both PowerShell editions and both source
    # types, while the Boolean EnableProvider above binds normally. psbase
    # reaches the .NET object directly and events are delivered (S18-D08).
    [void]$source.psbase.Process()
} catch {
    $ts = Get-Date -Format 'o'
    $msg = ($_.Exception.Message -replace '\|', '_')
    Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
        -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
        -ApiCalls "trace session failed: $msg"
    Write-InjectionDiagnostic -Timestamp $ts -Category 'trace_session_failed' -Detail $_.Exception.Message -ErrorRecord $_
    throw
} finally {
    if ($null -ne $script:StopWatchTimer) {
        try { $script:StopWatchTimer.Stop() } catch { $null = $_ }
        try { $script:StopWatchTimer.Dispose() } catch { $null = $_ }
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
    $script:CurrentInjectionSource = $null
    if ($session) {
        try { $session.Stop($true) | Out-Null } catch { $null = $_ }
        try { $session.Dispose() } catch { $null = $_ }
    }
    Write-InjectionLifecycle -State 'stopped' -Detail "stop_requested=$(Test-MonitorStopRequested)"
    if ($null -ne $script:StopEvent) {
        try { $script:StopEvent.Dispose() } catch { $null = $_ }
        $script:StopEvent = $null
    }
}
