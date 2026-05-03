param(
    [string]$LogDir = 'C:\Users\WDAGUtilityAccount\Desktop\Shared\logs',
    [int]$SampleIntervalSeconds = 5,
    [string[]]$CounterPaths = @()
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$logPath = Join-Path -Path $LogDir -ChildPath 'resource_monitor.log'
$errorLogPath = Join-Path -Path $LogDir -ChildPath 'resource_monitor.errors.jsonl'

function Format-Field {
    param(
        [Parameter(Mandatory = $false)][object]$Value
    )
    if ($null -eq $Value) { return '' }
    return ([string]$Value) -replace '\|', '_' -replace '[\r\n]+', ' '
}

function Write-SampleLine {
    param(
        [Parameter(Mandatory = $true)][string]$Line
    )
    Add-Content -LiteralPath $logPath -Value $Line -Encoding utf8
}

function Write-ErrorRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][string]$CounterPath = ''
    )
    $payload = [ordered]@{
        timestamp    = (Get-Date -Format 'o')
        stage        = $Stage
        message      = $Message
        counter_path = $CounterPath
    }
    $json = ($payload | ConvertTo-Json -Compress -Depth 3)
    Add-Content -LiteralPath $errorLogPath -Value $json -Encoding utf8
}

if ($null -eq $CounterPaths -or $CounterPaths.Count -eq 0) {
    $counterPaths = @(
        '\Processor(_Total)\% Processor Time',
        '\Memory\Available MBytes',
        '\PhysicalDisk(_Total)\Disk Read Bytes/sec',
        '\PhysicalDisk(_Total)\Disk Write Bytes/sec',
        '\Network Interface(*)\Bytes Sent/sec',
        '\Network Interface(*)\Bytes Received/sec'
    )
} else {
    $counterPaths = $CounterPaths
}

try {
    $totalMemMB = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1MB
} catch {
    Write-ErrorRecord -Stage 'init_total_memory' -Message $_.Exception.Message
    $totalMemMB = 0.0
}

while ($true) {
    $ts = Get-Date -Format 'o'

    $samples = $null
    try {
        $samples = Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
    } catch {
        Write-ErrorRecord -Stage 'get_counter_batch' -Message $_.Exception.Message -CounterPath ($counterPaths -join ';')
        $samples = $null

        $perCounterSamples = [System.Collections.Generic.List[object]]::new()
        foreach ($cp in $counterPaths) {
            try {
                $single = Get-Counter -Counter $cp -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
                foreach ($cs in $single.CounterSamples) { $perCounterSamples.Add($cs) | Out-Null }
            } catch {
                Write-ErrorRecord -Stage 'get_counter_single' -Message $_.Exception.Message -CounterPath $cp
            }
        }

        if ($perCounterSamples.Count -eq 0) {
            Start-Sleep -Seconds $SampleIntervalSeconds
            continue
        }

        $samples = [pscustomobject]@{ CounterSamples = $perCounterSamples }
    }

    $cpuPercent = 0.0
    $availMemMB = 0.0
    $diskReadBytes = 0
    $diskWriteBytes = 0
    $netSentBytes = 0
    $netRecvBytes = 0

    foreach ($sample in $samples.CounterSamples) {
        try {
            $path = $sample.Path.ToLower()
            $val = $sample.CookedValue

            if ($path -match '% processor time') {
                $cpuPercent = [math]::Round($val, 2)
            } elseif ($path -match 'available mbytes') {
                $availMemMB = $val
            } elseif ($path -match 'disk read bytes') {
                $diskReadBytes = [int64]$val
            } elseif ($path -match 'disk write bytes') {
                $diskWriteBytes = [int64]$val
            } elseif ($path -match 'bytes sent') {
                $netSentBytes += [int64]$val
            } elseif ($path -match 'bytes received') {
                $netRecvBytes += [int64]$val
            }
        } catch {
            Write-ErrorRecord -Stage 'parse_sample' -Message $_.Exception.Message -CounterPath ([string]$sample.Path)
        }
    }

    $usedMemMB = [math]::Round($totalMemMB - $availMemMB, 2)

    $tsField = Format-Field -Value $ts
    $line = "$tsField|$cpuPercent|$usedMemMB|$diskReadBytes|$diskWriteBytes|$netSentBytes|$netRecvBytes"
    try {
        Write-SampleLine -Line $line
    } catch {
        Write-ErrorRecord -Stage 'write_sample' -Message $_.Exception.Message
    }

    Start-Sleep -Seconds $SampleIntervalSeconds
}
