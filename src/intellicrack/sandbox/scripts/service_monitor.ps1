param(
    [string]$LogDir = 'C:\Users\WDAGUtilityAccount\Desktop\Shared\logs',
    [int]$EventQueryWindowSeconds = 1
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$logPath = Join-Path -Path $LogDir -ChildPath 'service_monitor.log'
$jsonlPath = Join-Path -Path $LogDir -ChildPath 'service_monitor.jsonl'
$errorLogPath = Join-Path -Path $LogDir -ChildPath 'service_monitor.errors.jsonl'

function Format-Field {
    param(
        [Parameter(Mandatory = $false)][object]$Value
    )
    if ($null -eq $Value) { return '' }
    return ([string]$Value) -replace '\|', '_' -replace '[\r\n]+', ' '
}

function Write-ErrorRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][string]$ServiceName = ''
    )
    $payload = [ordered]@{
        timestamp    = (Get-Date -Format 'o')
        stage        = $Stage
        message      = $Message
        service_name = $ServiceName
    }
    $json = ($payload | ConvertTo-Json -Compress -Depth 3)
    Add-Content -LiteralPath $errorLogPath -Value $json -Encoding utf8
}

function Write-PipeRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $false)][string]$DisplayName = '',
        [Parameter(Mandatory = $false)][string]$BinaryPath = '',
        [Parameter(Mandatory = $false)][string]$StartType = ''
    )
    $ts = Get-Date -Format 'o'
    $line = ('{0}|{1}|{2}|{3}|{4}|{5}' -f `
        (Format-Field -Value $ts), `
        (Format-Field -Value $Operation), `
        (Format-Field -Value $ServiceName), `
        (Format-Field -Value $DisplayName), `
        (Format-Field -Value $BinaryPath), `
        (Format-Field -Value $StartType))
    try {
        Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
    } catch {
        Write-ErrorRecord -Stage 'write_pipe_record' -Message $_.Exception.Message -ServiceName $ServiceName
    }
}

function Write-JsonlRecord {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Record
    )
    $Record['timestamp'] = (Get-Date -Format 'o')
    try {
        $json = ($Record | ConvertTo-Json -Compress -Depth 4)
        Add-Content -LiteralPath $jsonlPath -Value $json -Encoding utf8
    } catch {
        Write-ErrorRecord -Stage 'write_jsonl_record' -Message $_.Exception.Message
    }
}

$startTypeMap = @{
    0 = 'Boot'
    1 = 'System'
    2 = 'Automatic'
    3 = 'Manual'
    4 = 'Disabled'
}
$stateMap = @{
    1 = 'Stopped'
    2 = 'StartPending'
    3 = 'StopPending'
    4 = 'Running'
    5 = 'ContinuePending'
    6 = 'PausePending'
    7 = 'Paused'
}

function ConvertTo-StartTypeName {
    param([Parameter(Mandatory = $false)][object]$Value)
    if ($null -eq $Value) { return '' }
    try {
        $intVal = [int]$Value
        if ($startTypeMap.ContainsKey($intVal)) { return $startTypeMap[$intVal] }
        return [string]$Value
    } catch {
        return [string]$Value
    }
}

function ConvertTo-StateName {
    param([Parameter(Mandatory = $false)][object]$Value)
    if ($null -eq $Value) { return '' }
    try {
        $intVal = [int]$Value
        if ($stateMap.ContainsKey($intVal)) { return $stateMap[$intVal] }
    } catch {
        $null = $_
    }
    return [string]$Value
}

$script:lastTransition = @{}
$script:duplicateWindowMs = 250

function Test-DuplicateTransition {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$State
    )
    $key = "$ServiceName::$State"
    $now = [DateTime]::UtcNow
    $prev = $script:lastTransition[$key]
    if ($prev -and ($now - $prev).TotalMilliseconds -lt $script:duplicateWindowMs) {
        return $true
    }
    $script:lastTransition[$key] = $now
    return $false
}

function Read-ServiceFromRegistry {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName
    )
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (-not (Test-Path -LiteralPath $svcKey)) { return $null }
    try {
        $props = Get-ItemProperty -LiteralPath $svcKey -ErrorAction Stop
        return @{
            DisplayName = [string]$props.DisplayName
            ImagePath   = [string]$props.ImagePath
            Start       = ConvertTo-StartTypeName -Value $props.Start
        }
    } catch {
        Write-ErrorRecord -Stage 'read_registry' -Message $_.Exception.Message -ServiceName $ServiceName
        return $null
    }
}

function Get-BaselineSnapshot {
    $baseline = @{}
    try {
        $services = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop
    } catch {
        Write-ErrorRecord -Stage 'enumerate_baseline' -Message $_.Exception.Message
        return $baseline
    }
    foreach ($svc in $services) {
        $svcName = $svc.PSChildName
        $info = Read-ServiceFromRegistry -ServiceName $svcName
        if ($null -ne $info) {
            $baseline[$svcName] = $info
        }
    }
    return $baseline
}

function Publish-LifecycleTransition {
    param(
        [Parameter(Mandatory = $true)][object]$Instance,
        [Parameter(Mandatory = $true)][string]$EventKind
    )
    $serviceName = ''
    try {
        $serviceName = [string]$Instance.Name
    } catch {
        Write-ErrorRecord -Stage 'read_instance_name' -Message $_.Exception.Message
        return
    }
    if (-not $serviceName) { return }

    $displayName = ''
    $binaryPath = ''
    $startMode = ''
    $stateRaw = ''
    try { $displayName = [string]$Instance.DisplayName } catch { Write-ErrorRecord -Stage 'read_display_name' -Message $_.Exception.Message -ServiceName $serviceName }
    try { $binaryPath = [string]$Instance.PathName } catch { Write-ErrorRecord -Stage 'read_binary_path' -Message $_.Exception.Message -ServiceName $serviceName }
    try { $startMode = [string]$Instance.StartMode } catch { Write-ErrorRecord -Stage 'read_start_mode' -Message $_.Exception.Message -ServiceName $serviceName }
    try { $stateRaw = [string]$Instance.State } catch { Write-ErrorRecord -Stage 'read_state' -Message $_.Exception.Message -ServiceName $serviceName }

    $stateName = ConvertTo-StateName -Value $stateRaw

    if (Test-DuplicateTransition -ServiceName $serviceName -State "$EventKind::$stateName") {
        return
    }

    $operation = switch ($EventKind) {
        'created'  { 'created' }
        'deleted'  { 'deleted' }
        default    { 'state_changed' }
    }

    Write-PipeRecord -Operation $operation -ServiceName $serviceName `
        -DisplayName $displayName -BinaryPath $binaryPath -StartType $stateName

    $record = @{
        event       = $EventKind
        service     = $serviceName
        display     = $displayName
        binary_path = $binaryPath
        start_mode  = $startMode
        state       = $stateName
    }
    Write-JsonlRecord -Record $record
}

$baseline = Get-BaselineSnapshot
$baselineLines = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $baseline.GetEnumerator()) {
    $info = $entry.Value
    $tsField = Format-Field -Value (Get-Date -Format 'o')
    $line = ('{0}|{1}|{2}|{3}|{4}|{5}' -f `
        $tsField, `
        'baseline', `
        (Format-Field -Value $entry.Key), `
        (Format-Field -Value $info.DisplayName), `
        (Format-Field -Value $info.ImagePath), `
        (Format-Field -Value $info.Start))
    $baselineLines.Add($line) | Out-Null
}
if ($baselineLines.Count -gt 0) {
    try {
        Add-Content -LiteralPath $logPath -Value $baselineLines -Encoding utf8
    } catch {
        Write-ErrorRecord -Stage 'write_baseline' -Message $_.Exception.Message
    }
}
Write-JsonlRecord -Record @{ event = 'baseline'; count = $baseline.Count }

$wmiSubs = [System.Collections.Generic.List[object]]::new()
$sourceIdentifierKindMap = @{}

function Register-ServiceWmiSubscription {
    param(
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][string]$EventKind,
        [Parameter(Mandatory = $true)][string]$SourceIdentifier
    )
    try {
        $sub = Register-CimIndicationEvent -Query $Query -SourceIdentifier $SourceIdentifier -ErrorAction Stop -MessageData $EventKind
        $wmiSubs.Add($sub) | Out-Null
        $sourceIdentifierKindMap[$SourceIdentifier] = $EventKind
        return $true
    } catch {
        Write-ErrorRecord -Stage 'register_event' -Message $_.Exception.Message -ServiceName $SourceIdentifier
        return $false
    }
}

$within = [int]$EventQueryWindowSeconds
if ($within -lt 1) { $within = 1 }

$modificationQuery = "SELECT * FROM __InstanceModificationEvent WITHIN $within WHERE TargetInstance ISA 'Win32_Service'"
$creationQuery = "SELECT * FROM __InstanceCreationEvent WITHIN $within WHERE TargetInstance ISA 'Win32_Service'"
$deletionQuery = "SELECT * FROM __InstanceDeletionEvent WITHIN $within WHERE TargetInstance ISA 'Win32_Service'"

$registered = $true
$registered = (Register-ServiceWmiSubscription -Query $modificationQuery -EventKind 'modified' -SourceIdentifier 'IntellicrackServiceModified') -and $registered
$registered = (Register-ServiceWmiSubscription -Query $creationQuery -EventKind 'created' -SourceIdentifier 'IntellicrackServiceCreated') -and $registered
$registered = (Register-ServiceWmiSubscription -Query $deletionQuery -EventKind 'deleted' -SourceIdentifier 'IntellicrackServiceDeleted') -and $registered

if (-not $registered) {
    Write-ErrorRecord -Stage 'register_summary' -Message 'one or more WMI event registrations failed; monitor will exit'
    foreach ($sub in $wmiSubs) {
        try { Unregister-Event -SubscriptionId $sub.Id -ErrorAction Stop } catch { Write-ErrorRecord -Stage 'unregister' -Message $_.Exception.Message }
    }
    return
}

Write-JsonlRecord -Record @{ event = 'monitor_started'; query_window_seconds = $within }

try {
    while ($true) {
        $evt = Wait-Event -Timeout 5
        if ($null -eq $evt) { continue }
        try {
            $sourceId = [string]$evt.SourceIdentifier
            $kind = $sourceIdentifierKindMap[$sourceId]
            if (-not $kind) { $kind = [string]$evt.MessageData }
            if (-not $kind) { $kind = 'modified' }
            $instance = $null
            try {
                $instance = $evt.SourceEventArgs.NewEvent.TargetInstance
            } catch {
                Write-ErrorRecord -Stage 'extract_target_instance' -Message $_.Exception.Message
            }
            if ($null -ne $instance) {
                Publish-LifecycleTransition -Instance $instance -EventKind $kind
            }
        } catch {
            Write-ErrorRecord -Stage 'event_dispatch' -Message $_.Exception.Message
        } finally {
            try { Remove-Event -EventIdentifier $evt.EventIdentifier -ErrorAction Stop } catch { Write-ErrorRecord -Stage 'remove_event' -Message $_.Exception.Message }
        }
    }
} finally {
    foreach ($sub in $wmiSubs) {
        try {
            Unregister-Event -SubscriptionId $sub.Id -ErrorAction Stop
        } catch {
            Write-ErrorRecord -Stage 'unregister' -Message $_.Exception.Message
        }
    }
    Write-JsonlRecord -Record @{ event = 'monitor_stopped' }
}
