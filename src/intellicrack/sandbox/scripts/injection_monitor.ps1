param(
    [string]$LogDir = '.',
    [int]$TargetPid = 0
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$logPath = Join-Path -Path $LogDir -ChildPath 'injection_monitor.log'

function Write-InjectionRecord {
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
    $targetPath = if ($script:logPathRef) { $script:logPathRef } else { $logPath }
    Add-Content -LiteralPath $targetPath -Value $record -Encoding utf8
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
    return
}

try {
    Add-Type -Path $traceEventAssembly
} catch {
    $ts = Get-Date -Format 'o'
    Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
        -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
        -ApiCalls "TraceEvent.dll load failed: $($_.Exception.Message -replace '\|', '_')"
    return
}

$sessionName = 'IntellicrackInjectionMonitor'
$kernelProcessGuid = [Guid]::Parse('22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716')
$threadStartKeyword = [uint64]0x20

$logmanStarted = $false
$etlPath = Join-Path -Path $LogDir -ChildPath 'injection_monitor.etl'
$moduleCacheTtlSeconds = 5
$allocEntryTtlSeconds = 30
$allocEntryCap = 4096

$script:moduleCache = @{}
$script:moduleCacheStamp = @{}
$script:virtualProtectByThread = @{}
$script:targetPidFilter = $TargetPid
$script:moduleCacheTtl = $moduleCacheTtlSeconds
$script:allocTtl = $allocEntryTtlSeconds
$script:allocCap = $allocEntryCap
$script:logPathRef = $logPath

function Sync-ModuleCache {
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
    param([int]$ProcId)
    try {
        $proc = Get-Process -Id $ProcId -ErrorAction Stop
        return $proc.ProcessName
    } catch {
        return 'unknown'
    }
}

$session = $null
try {
    $sessionType = [Type]::GetType('Microsoft.Diagnostics.Tracing.Session.TraceEventSession, Microsoft.Diagnostics.Tracing.TraceEvent')
    if (-not $sessionType) {
        $ts = Get-Date -Format 'o'
        Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
            -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
            -ApiCalls 'TraceEvent.dll not found'
        return
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
        $null = $_
    }

    $source = $session.Source
    $kernelParser = $source.Kernel

    $kernelParser.add_ThreadStart({
        param($evt)
        try {
            $evtPid = [int]$evt.ProcessID
            if ($script:targetPidFilter -ne 0 -and $evtPid -ne $script:targetPidFilter) { return }
            if ($evtPid -le 4) { return }

            $startAddr = [int64]$evt.StartAddr
            if ($startAddr -eq 0) { return }

            $resolution = Resolve-StartAddress -ProcId $evtPid -Address $startAddr
            if (-not $resolution.Suspicious -and $resolution.InModule) { return }

            $threadId = [int]$evt.ThreadID
            $sourcePid = [int]$evt.ParentProcessID
            if ($sourcePid -eq 0) { $sourcePid = $evtPid }

            $sourceName = Get-ProcessNameSafe -ProcId $sourcePid
            $targetName = Get-ProcessNameSafe -ProcId $evtPid

            $apis = New-Object System.Collections.Generic.List[string]
            $apis.Add('CreateRemoteThread') | Out-Null
            if ($script:virtualProtectByThread.ContainsKey($threadId)) {
                $apis.Add('VirtualProtect') | Out-Null
                $script:virtualProtectByThread.Remove($threadId) | Out-Null
            }

            $injType = 'remote_thread'
            if ($resolution.InModule -and $resolution.Suspicious) {
                $injType = 'dll_injection'
                $apis.Add('LoadLibrary') | Out-Null
            } elseif (-not $resolution.InModule) {
                $injType = 'shellcode_injection'
                $apis.Add('VirtualAllocEx') | Out-Null
                $apis.Add('WriteProcessMemory') | Out-Null
            }

            $ts = Get-Date -Format 'o'
            Write-InjectionRecord -Timestamp $ts -SourcePid $sourcePid -SourceName $sourceName `
                -InjectedPid $evtPid -InjectedName $targetName `
                -InjectionType $injType -ApiCalls ($apis -join ',')
        } catch {
            $null = $_
        }
    })

    $kernelParser.add_VirtualMemVirtualAlloc({
        param($evt)
        try {
            $evtPid = [int]$evt.ProcessID
            if ($script:targetPidFilter -ne 0 -and $evtPid -ne $script:targetPidFilter) { return }
            $threadId = [int]$evt.ThreadID
            $script:virtualProtectByThread[$threadId] = [DateTime]::UtcNow
            if ($script:virtualProtectByThread.Count -gt $script:allocCap) {
                $cutoff = [DateTime]::UtcNow.AddSeconds(-$script:allocTtl)
                $stale = @($script:virtualProtectByThread.GetEnumerator() |
                    Where-Object { $_.Value -lt $cutoff } |
                    Select-Object -ExpandProperty Key)
                foreach ($k in $stale) { $script:virtualProtectByThread.Remove($k) | Out-Null }
            }
        } catch {
            $null = $_
        }
    })

    $kernelParser.add_VirtualMemVirtualFree({
        param($evt)
        try {
            $threadId = [int]$evt.ThreadID
            if ($script:virtualProtectByThread.ContainsKey($threadId)) {
                $script:virtualProtectByThread.Remove($threadId) | Out-Null
            }
        } catch {
            $null = $_
        }
    })

    $logmanStarted = $true
    [void]$source.Process()
} catch {
    $ts = Get-Date -Format 'o'
    $msg = ($_.Exception.Message -replace '\|', '_')
    Write-InjectionRecord -Timestamp $ts -SourcePid 0 -SourceName 'tracer' `
        -InjectedPid 0 -InjectedName '' -InjectionType 'ERROR' `
        -ApiCalls "trace session failed: $msg"
} finally {
    if ($session) {
        try { $session.Stop($true) | Out-Null } catch { $null = $_ }
        try { $session.Dispose() } catch { $null = $_ }
    }
    if ($logmanStarted) {
        try { & logman stop $sessionName -ets | Out-Null } catch { $null = $_ }
        try { & logman delete $sessionName -ets | Out-Null } catch { $null = $_ }
    }
    try { Remove-Item -LiteralPath $etlPath -Force -ErrorAction SilentlyContinue } catch { $null = $_ }
}
