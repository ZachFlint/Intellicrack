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
$script:EtlPath = Join-Path -Path $LogDir -ChildPath 'dll_monitor.etl'
$script:SessionName = 'IntDllMon'
$script:KernelProviderGuid = '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}'
$script:ImageLoadKeyword = '0x40'
$script:FilterPid = [int]$TargetPid

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

    $line = "$Timestamp|$ProcessId|$ProcessName|$ImagePath|$BaseAddress|$ImageSize"
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding utf8
}

function Invoke-LogmanCleanup {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param([string]$Name)

    if ($PSCmdlet.ShouldProcess($Name, 'Stop and delete ETW trace session')) {
        & logman stop $Name -ets 2>&1 | Out-Null
        & logman delete $Name -ets 2>&1 | Out-Null
    }
}

function Test-TraceEventAvailable {
    try {
        $type = [System.Type]::GetType('Microsoft.Diagnostics.Tracing.Session.TraceEventSession, Microsoft.Diagnostics.Tracing.TraceEvent', $false)
        return ($null -ne $type)
    } catch {
        return $false
    }
}

function Invoke-EtwDllMonitor {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$Session,
        [string]$EtlPath,
        [string]$ProviderGuid,
        [string]$Keyword
    )

    if (-not $PSCmdlet.ShouldProcess($Session, 'Start ETW kernel image-load trace')) {
        return
    }

    Invoke-LogmanCleanup -Name $Session -Confirm:$false

    $create = & logman create trace $Session -p $ProviderGuid $Keyword 5 -o $EtlPath -ets 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "logman create failed: $create"
    }

    $tesType = [Microsoft.Diagnostics.Tracing.Session.TraceEventSession]
    $realtime = $tesType::new($Session)

    $source = $realtime.Source
    $kernelParser = New-Object Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser($source)

    $handler = {
        param($evt)
        try {
            $ts = (Get-Date).ToString('o')
            $processId = [int]$evt.ProcessID
            $procName = try { (Get-Process -Id $processId -ErrorAction Stop).ProcessName } catch { 'unknown' }
            $imagePath = [string]$evt.FileName
            $baseAddr = '0x{0:X}' -f [int64]$evt.ImageBase
            $imageSize = [long]$evt.ImageSize
            Write-DllRecord -Timestamp $ts -ProcessId $processId -ProcessName $procName -ImagePath $imagePath -BaseAddress $baseAddr -ImageSize $imageSize
        } catch {
            return
        }
    }

    Register-ObjectEvent -InputObject $kernelParser -EventName 'ImageLoad' -Action $handler | Out-Null

    try {
        $source.Process() | Out-Null
    } finally {
        $realtime.Dispose()
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
            Write-DllRecord -Timestamp $ts -ProcessId $processId -ProcessName $procName -ImagePath $imagePath -BaseAddress $baseAddr -ImageSize $imageSize
        } catch {
            return
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

try {
    if (Test-TraceEventAvailable) {
        try {
            Invoke-EtwDllMonitor -Session $script:SessionName -EtlPath $script:EtlPath -ProviderGuid $script:KernelProviderGuid -Keyword $script:ImageLoadKeyword -Confirm:$false
        } finally {
            Invoke-LogmanCleanup -Name $script:SessionName -Confirm:$false
        }
    } else {
        Invoke-WmiDllMonitor -Confirm:$false
    }
} catch {
    Invoke-LogmanCleanup -Name $script:SessionName -Confirm:$false
    Invoke-WmiDllMonitor -Confirm:$false
}
