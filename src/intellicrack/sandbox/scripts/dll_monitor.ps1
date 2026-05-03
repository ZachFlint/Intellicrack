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
$script:SessionName = 'IntDllMon'
$script:KernelProcessProviderGuid = [Guid]::Parse('22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716')
$script:ImageLoadKeyword = [uint64]0x40
$script:FilterPid = [int]$TargetPid

$script:ImagePathFieldNames = @('ImageName', 'FileName', 'ImageFileName')
$script:ImageBaseFieldNames = @('ImageBase', 'BaseAddr', 'ImageAddress')
$script:ImageSizeFieldNames = @('ImageSize', 'Size')

function Write-DllRecord {
    [CmdletBinding()]
    param(
        [string]$Timestamp,
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$ImagePath,
        [string]$BaseAddress,
        [long]$ImageSize
    )

    if ($script:FilterPid -ne 0 -and $ProcessId -ne $script:FilterPid) {
        return
    }

    $safePath = ($ImagePath -replace '\|', '_')
    $safeName = ($ProcessName -replace '\|', '_')
    $line = "$Timestamp|$ProcessId|$safeName|$safePath|$BaseAddress|$ImageSize"
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
        [Parameter(Mandatory = $true)][string[]]$FieldNames
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
        [Parameter(Mandatory = $true)][string[]]$FieldNames
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

                $isImageLoad = ($opcodeName -eq 'Load' -or $taskName -match 'Image' -or [int]$evt.ID -eq 5)
                if (-not $isImageLoad) { return }

                $ts = (Get-Date).ToString('o')
                $processId = [int]$evt.ProcessID

                $imagePath = Resolve-PayloadString -EtwEvent $evt -FieldNames $script:ImagePathFieldNames

                if (-not $imagePath) {
                    $fields = Get-PayloadFieldList -EtwEvent $evt
                    Write-DllDiagnostic -Timestamp $ts -Category 'dll_event_unparsed' `
                        -Detail "pid=$processId provider=$($evt.ProviderName) task=$taskName opcode=$opcodeName payload_fields=$fields"
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
                    -ImagePath $imagePath -BaseAddress $baseAddr -ImageSize $imageSize
            } catch {
                $ts = (Get-Date).ToString('o')
                Write-DllDiagnostic -Timestamp $ts -Category 'dll_event_handler_error' `
                    -Detail $_.Exception.Message
            }
        }

        $dynamicParser.add_All($imageLoadHandler)
        $source.Process() | Out-Null
    } finally {
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
            Start-Sleep -Seconds 1
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

if (-not (Test-TraceEventAvailable)) {
    Invoke-WmiFallback -Reason 'TraceEvent.dll not loaded'
    return
}

try {
    Invoke-RealtimeDllMonitor -Session $script:SessionName `
        -ProviderGuid $script:KernelProcessProviderGuid `
        -Keyword $script:ImageLoadKeyword -Confirm:$false
} catch {
    Invoke-WmiFallback -Reason $_.Exception.Message
}
