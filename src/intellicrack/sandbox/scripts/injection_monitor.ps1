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
$script:targetPidFilter = [int]$TargetPid

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
        [string]$Detail
    )
    $safeDetail = ($Detail -replace '\|', '_' -replace '[\r\n]+', ' ')
    $line = "$Timestamp|$Category|$safeDetail"
    Add-Content -LiteralPath $script:diagPathRef -Value $line -Encoding utf8
}

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

    $source = $session.Source
    $kernelParser = $source.Kernel
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

    $kernelParser.add_VirtualMemVirtualAlloc({
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

    $kernelParser.add_VirtualMemVirtualFree({
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
    $source.UnhandledEvents.add_All($threatIntelHandler)

    [void]$source.Process()
} catch {
    $ts = Get-Date -Format 'o'
    $msg = ($_.Exception.Message -replace '\|', '_')
    Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
        -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
        -ApiCalls "trace session failed: $msg"
    Write-InjectionDiagnostic -Timestamp $ts -Category 'trace_session_failed' -Detail $_.Exception.Message
    throw
} finally {
    if ($session) {
        try { $session.Stop($true) | Out-Null } catch { $null = $_ }
        try { $session.Dispose() } catch { $null = $_ }
    }
}
