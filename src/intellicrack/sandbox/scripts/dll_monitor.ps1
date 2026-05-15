[CmdletBinding()]
param(
    [string]$LogDir = '.',
    [int]$TargetPid = 0
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$script:LogPath = Join-Path -Path $LogDir -ChildPath 'dll_monitor.log'
$script:DiagPath = Join-Path -Path $LogDir -ChildPath 'dll_monitor.diag.log'
$script:LifecyclePath = Join-Path -Path $LogDir -ChildPath 'dll_monitor.lifecycle.log'
$script:SessionName = 'IntDllMon'
$script:KernelProcessProviderGuid = [Guid]::Parse('22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716')
$script:ImageLoadKeyword = [uint64]0x40
$script:FilterPid = [int]$TargetPid
$script:MonitorName = 'dll_monitor'
$script:StopEventName = 'IntellicrackMonitorStop'
$script:StopEvent = $null
$script:StopPollIntervalMs = 250
$script:StopMonitorTimer = $null
$script:StopMonitorJob = $null
$script:StopMonitorSubscriberId = $null
$script:CurrentTraceSource = $null

$script:ImagePathFieldNames = [System.Collections.Generic.List[string]]::new()
foreach ($name in @('ImageName', 'FileName', 'ImageFileName', 'ImagePath', 'OriginalFileName')) {
    $script:ImagePathFieldNames.Add($name) | Out-Null
}
$script:ImageBaseFieldNames = [System.Collections.Generic.List[string]]::new()
foreach ($name in @('ImageBase', 'BaseAddr', 'ImageAddress', 'BaseAddress')) {
    $script:ImageBaseFieldNames.Add($name) | Out-Null
}
$script:ImageSizeFieldNames = [System.Collections.Generic.List[string]]::new()
foreach ($name in @('ImageSize', 'Size', 'ImageLength')) {
    $script:ImageSizeFieldNames.Add($name) | Out-Null
}

$script:KnownPayloadSchemas = [System.Collections.Generic.HashSet[string]]::new()
$script:ObservedPayloadFieldNames = [System.Collections.Generic.HashSet[string]]::new()

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

function Write-DllRecord {
    [CmdletBinding()]
    param(
        [string]$Timestamp,
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$ImagePath,
        [string]$BaseAddress,
        [long]$ImageSize,
        [int]$EventId = 0,
        [string]$PayloadSchema = ''
    )

    if ($script:FilterPid -ne 0 -and $ProcessId -ne $script:FilterPid) {
        return
    }

    $safePath = ($ImagePath -replace '\|', '_')
    $safeName = ($ProcessName -replace '\|', '_')
    $safeSchema = ($PayloadSchema -replace '\|', '_' -replace '[\r\n]+', ' ')
    $line = "$Timestamp|$ProcessId|$safeName|$safePath|$BaseAddress|$ImageSize|$EventId|$safeSchema"
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding utf8
}

function Write-DllDiagnostic {
    [CmdletBinding()]
    param(
        [string]$Timestamp,
        [string]$Category,
        [string]$Detail
    )

    $safeDetail = ($Detail -replace '\|', '_' -replace '[\r\n]+', ' ')
    $line = "$Timestamp|$Category|$safeDetail"
    Add-Content -LiteralPath $script:DiagPath -Value $line -Encoding utf8
}

function Write-DllLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $false)][string]$Detail = ''
    )

    $ts = (Get-Date).ToString('o')
    $safeDetail = ($Detail -replace '\|', '_' -replace '[\r\n]+', ' ')
    $line = "$ts|$script:MonitorName|$State|$safeDetail"
    try {
        Add-Content -LiteralPath $script:LifecyclePath -Value $line -Encoding utf8
    } catch {
        $null = $_
    }
    try {
        Write-DllDiagnostic -Timestamp $ts -Category "lifecycle_$State" -Detail $safeDetail
    } catch {
        $null = $_
    }
}

function Test-TraceEventAvailable {
    try {
        $type = [System.Type]::GetType('Microsoft.Diagnostics.Tracing.Session.TraceEventSession, Microsoft.Diagnostics.Tracing.TraceEvent', $false)
        return ($null -ne $type)
    } catch {
        $ts = Get-Date -Format 'o'
        Write-DllDiagnostic -Timestamp $ts -Category 'traceevent_probe_failed' -Detail $_.Exception.Message
        return $false
    }
}

function Resolve-PayloadString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]$EtwEvent,
        [Parameter(Mandatory = $true)]$FieldNames
    )

    foreach ($fieldName in $FieldNames) {
        try {
            $val = $EtwEvent.PayloadByName($fieldName)
            if ($null -ne $val -and "$val".Length -gt 0) {
                return [string]$val
            }
        } catch {
            $null = $_
        }
    }
    return ''
}

function Resolve-PayloadInt64 {
    [CmdletBinding()]
    [OutputType([int64])]
    param(
        [Parameter(Mandatory = $true)]$EtwEvent,
        [Parameter(Mandatory = $true)]$FieldNames
    )

    foreach ($fieldName in $FieldNames) {
        try {
            $val = $EtwEvent.PayloadByName($fieldName)
            if ($null -ne $val) {
                return [int64]$val
            }
        } catch {
            $null = $_
        }
    }
    return 0L
}

function Get-PayloadFieldList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]$EtwEvent
    )

    try {
        $names = $EtwEvent.PayloadNames
        if ($names) { return ($names -join ',') }
    } catch {
        return ''
    }
    return ''
}

function Sync-PayloadFieldCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$EtwEvent
    )

    $names = $null
    try {
        $names = $EtwEvent.PayloadNames
    } catch {
        return
    }
    if (-not $names) { return }

    foreach ($name in $names) {
        if ([string]::IsNullOrEmpty($name)) { continue }
        if (-not $script:ObservedPayloadFieldNames.Add($name)) { continue }
        $upper = $name.ToUpperInvariant()
        if ($upper.Contains('IMAGE') -or $upper.Contains('FILE') -or $upper.Contains('PATH') -or $upper.Contains('MODULE')) {
            if (-not $script:ImagePathFieldNames.Contains($name)) {
                $script:ImagePathFieldNames.Add($name) | Out-Null
            }
        }
        if ($upper.Contains('BASE') -or $upper.Contains('ADDRESS') -or $upper.Contains('ADDR')) {
            if (-not $script:ImageBaseFieldNames.Contains($name)) {
                $script:ImageBaseFieldNames.Add($name) | Out-Null
            }
        }
        if ($upper.Contains('SIZE') -or $upper.Contains('LENGTH')) {
            if (-not $script:ImageSizeFieldNames.Contains($name)) {
                $script:ImageSizeFieldNames.Add($name) | Out-Null
            }
        }
    }
}

function Import-ProviderManifestField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][Guid]$ProviderGuid
    )

    try {
        $parserType = [System.Type]::GetType(
            'Microsoft.Diagnostics.Tracing.RegisteredTraceEventParser, Microsoft.Diagnostics.Tracing.TraceEvent',
            $false)
        if ($null -eq $parserType) { return }

        $getMethod = $parserType.GetMethod('GetManifestForRegisteredProvider', [type[]]@([Guid]))
        if ($null -eq $getMethod) { return }
        $manifestText = [string]$getMethod.Invoke($null, @($ProviderGuid))
        if ([string]::IsNullOrEmpty($manifestText)) { return }

        $manifestMatches = [System.Text.RegularExpressions.Regex]::Matches(
            $manifestText,
            'name="([^"]+)"\s+inType="win:UnicodeString"',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $manifestMatches) {
            $name = $m.Groups[1].Value
            if ([string]::IsNullOrEmpty($name)) { continue }
            $upper = $name.ToUpperInvariant()
            if ($upper.Contains('IMAGE') -or $upper.Contains('FILE') -or $upper.Contains('PATH') -or $upper.Contains('MODULE')) {
                if (-not $script:ImagePathFieldNames.Contains($name)) {
                    $script:ImagePathFieldNames.Add($name) | Out-Null
                }
            }
        }
    } catch {
        $null = $_
    }
}

function Invoke-RealtimeDllMonitor {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Session,
        [Guid]$ProviderGuid,
        [uint64]$Keyword
    )

    if (-not $PSCmdlet.ShouldProcess($Session, 'Start realtime ETW image-load trace')) {
        return
    }

    try {
        $existing = [Microsoft.Diagnostics.Tracing.Session.TraceEventSession]::new($Session)
        $existing.Stop($true) | Out-Null
        $existing.Dispose()
    } catch {
        $null = $_
    }

    $tesType = [Microsoft.Diagnostics.Tracing.Session.TraceEventSession]
    $realtime = $tesType::new($Session)
    $realtime.StopOnDispose = $true

    try {
        Import-ProviderManifestField -ProviderGuid $ProviderGuid

        $realtime.EnableProvider(
            $ProviderGuid,
            [Microsoft.Diagnostics.Tracing.TraceEventLevel]::Informational,
            $Keyword
        ) | Out-Null

        $source = $realtime.Source
        $dynamicParser = New-Object Microsoft.Diagnostics.Tracing.Parsers.DynamicTraceEventParser($source)

        $imageLoadHandler = {
            param($evt)
            try {
                $opcodeName = ''
                try { $opcodeName = [string]$evt.OpcodeName } catch { $opcodeName = '' }
                $taskName = ''
                try { $taskName = [string]$evt.TaskName } catch { $taskName = '' }

                $eventIdValue = 0
                try { $eventIdValue = [int]$evt.ID } catch { $eventIdValue = 0 }

                $isImageLoad = ($opcodeName -eq 'Load' -or $taskName -match 'Image' -or $eventIdValue -eq 5)
                if (-not $isImageLoad) { return }

                $ts = (Get-Date).ToString('o')
                $processId = [int]$evt.ProcessID

                Sync-PayloadFieldCandidate -EtwEvent $evt

                $imagePath = Resolve-PayloadString -EtwEvent $evt -FieldNames $script:ImagePathFieldNames

                if (-not $imagePath) {
                    $fields = Get-PayloadFieldList -EtwEvent $evt
                    Write-DllDiagnostic -Timestamp $ts -Category 'dll_event_unparsed' `
                        -Detail "pid=$processId provider=$($evt.ProviderName) task=$taskName opcode=$opcodeName event_id=$eventIdValue payload_fields=$fields"

                    $procName = 'unknown'
                    try {
                        $procName = (Get-Process -Id $processId -ErrorAction Stop).ProcessName
                    } catch {
                        $procName = 'unknown'
                    }
                    Write-DllRecord -Timestamp $ts -ProcessId $processId -ProcessName $procName `
                        -ImagePath '' -BaseAddress '0x0' -ImageSize 0 `
                        -EventId $eventIdValue -PayloadSchema $fields

                    $schemaKey = "$($evt.ProviderName)|$taskName|$opcodeName|$eventIdValue|$fields"
                    if ($script:KnownPayloadSchemas.Add($schemaKey)) {
                        Write-DllDiagnostic -Timestamp $ts -Category 'dll_event_schema_discovered' `
                            -Detail "schema_key=$schemaKey"
                    }
                    return
                }

                $imageBase = Resolve-PayloadInt64 -EtwEvent $evt -FieldNames $script:ImageBaseFieldNames
                $imageSize = Resolve-PayloadInt64 -EtwEvent $evt -FieldNames $script:ImageSizeFieldNames

                $procName = 'unknown'
                try {
                    $procName = (Get-Process -Id $processId -ErrorAction Stop).ProcessName
                } catch {
                    $procName = 'unknown'
                }
                $baseAddr = '0x{0:X}' -f $imageBase
                Write-DllRecord -Timestamp $ts -ProcessId $processId -ProcessName $procName `
                    -ImagePath $imagePath -BaseAddress $baseAddr -ImageSize $imageSize `
                    -EventId $eventIdValue -PayloadSchema ''
            } catch {
                $ts = (Get-Date).ToString('o')
                Write-DllDiagnostic -Timestamp $ts -Category 'dll_event_handler_error' `
                    -Detail $_.Exception.Message
            }
        }

        $dynamicParser.add_All($imageLoadHandler)

        $script:CurrentTraceSource = $source
        $stopMonitor = New-Object System.Timers.Timer
        $stopMonitor.Interval = [double]$script:StopPollIntervalMs
        $stopMonitor.AutoReset = $true
        $stopActionSubscriberId = 'IntDllMonStopWatcher'
        try {
            Unregister-Event -SourceIdentifier $stopActionSubscriberId -ErrorAction SilentlyContinue
        } catch {
            $null = $_
        }
        $stopMonitorJob = Register-ObjectEvent -InputObject $stopMonitor -EventName Elapsed `
            -SourceIdentifier $stopActionSubscriberId -Action {
                try {
                    if ($null -eq $script:StopEvent) { return }
                    if (-not $script:StopEvent.WaitOne(0)) { return }
                    if ($null -ne $script:CurrentTraceSource) {
                        try { $script:CurrentTraceSource.StopProcessing() } catch { $null = $_ }
                    }
                    if ($null -ne $script:StopMonitorTimer) {
                        try { $script:StopMonitorTimer.Stop() } catch { $null = $_ }
                    }
                } catch {
                    $null = $_
                }
            }
        $script:StopMonitorTimer = $stopMonitor
        $script:StopMonitorJob = $stopMonitorJob
        $script:StopMonitorSubscriberId = $stopActionSubscriberId
        $stopMonitor.Start()

        $source.Process() | Out-Null
    } finally {
        if ($null -ne $script:StopMonitorTimer) {
            try { $script:StopMonitorTimer.Stop() } catch { $null = $_ }
            try { $script:StopMonitorTimer.Dispose() } catch { $null = $_ }
            $script:StopMonitorTimer = $null
        }
        if ($null -ne $script:StopMonitorSubscriberId) {
            try {
                Unregister-Event -SourceIdentifier $script:StopMonitorSubscriberId -ErrorAction SilentlyContinue
            } catch {
                $null = $_
            }
            $script:StopMonitorSubscriberId = $null
        }
        if ($null -ne $script:StopMonitorJob) {
            try { Remove-Job -Job $script:StopMonitorJob -Force -ErrorAction SilentlyContinue } catch { $null = $_ }
            $script:StopMonitorJob = $null
        }
        $script:CurrentTraceSource = $null
        try { $realtime.Stop($true) | Out-Null } catch { $null = $_ }
        try { $realtime.Dispose() } catch { $null = $_ }
    }
}

function Invoke-WmiDllMonitor {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    if (-not $PSCmdlet.ShouldProcess('Win32_ModuleLoadTrace', 'Subscribe to CIM module-load events')) {
        return
    }

    $query = 'SELECT * FROM Win32_ModuleLoadTrace'
    $sourceId = 'IntDllMonCim'
    $subscription = Register-CimIndicationEvent -Query $query -SourceIdentifier $sourceId -Action {
        try {
            $ne = $Event.SourceEventArgs.NewEvent
            $ts = (Get-Date).ToString('o')
            $processId = [int]$ne.ProcessID
            $procName = try { (Get-Process -Id $processId -ErrorAction Stop).ProcessName } catch { 'unknown' }
            $imagePath = [string]$ne.FileName
            $baseAddr = '0x{0:X}' -f [int64]$ne.DefaultBase
            $imageSize = [long]$ne.ImageSize
            Write-DllRecord -Timestamp $ts -ProcessId $processId -ProcessName $procName `
                -ImagePath $imagePath -BaseAddress $baseAddr -ImageSize $imageSize
        } catch {
            $ts = (Get-Date).ToString('o')
            Write-DllDiagnostic -Timestamp $ts -Category 'wmi_event_handler_error' `
                -Detail $_.Exception.Message
        }
    }

    try {
        while ($true) {
            if ($null -ne $script:StopEvent) {
                if ($script:StopEvent.WaitOne(1000)) { break }
            } else {
                Start-Sleep -Seconds 1
            }
        }
    } finally {
        Unregister-Event -SourceIdentifier $sourceId -ErrorAction SilentlyContinue
        if ($null -ne $subscription) {
            Remove-Job -Job $subscription -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-WmiFallback {
    [CmdletBinding()]
    param(
        [string]$Reason
    )

    $ts = (Get-Date).ToString('o')
    $message = "etw_unavailable_falling_back_to_wmi reason=$Reason"
    Write-Warning $message
    Write-DllDiagnostic -Timestamp $ts -Category 'etw_unavailable_falling_back_to_wmi' -Detail $Reason
    Invoke-WmiDllMonitor -Confirm:$false
}

$script:StopEvent = Open-MonitorStopEvent -Name $script:StopEventName
Write-DllLifecycle -State 'started' -Detail "pid_filter=$script:FilterPid stop_event=$script:StopEventName"

try {
    if (-not (Test-TraceEventAvailable)) {
        Invoke-WmiFallback -Reason 'TraceEvent.dll not loaded'
    } else {
        try {
            Invoke-RealtimeDllMonitor -Session $script:SessionName `
                -ProviderGuid $script:KernelProcessProviderGuid `
                -Keyword $script:ImageLoadKeyword -Confirm:$false
        } catch {
            Invoke-WmiFallback -Reason $_.Exception.Message
        }
    }
} finally {
    Write-DllLifecycle -State 'stopped' -Detail "stop_requested=$(Test-MonitorStopRequested)"
    if ($null -ne $script:StopEvent) {
        try { $script:StopEvent.Dispose() } catch { $null = $_ }
        $script:StopEvent = $null
    }
}
