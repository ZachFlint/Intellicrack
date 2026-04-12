$ErrorActionPreference = 'SilentlyContinue'

$logDir = 'C:\sandbox_shared\logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logPath = Join-Path $logDir 'resource_monitor.log'

$counterPaths = @(
    '\Processor(_Total)\% Processor Time',
    '\Memory\Available MBytes',
    '\PhysicalDisk(_Total)\Disk Read Bytes/sec',
    '\PhysicalDisk(_Total)\Disk Write Bytes/sec',
    '\Network Interface(*)\Bytes Sent/sec',
    '\Network Interface(*)\Bytes Received/sec'
)

$totalMemMB = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1MB

while ($true) {
    $ts = Get-Date -Format 'o'

    $samples = Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples 1

    $cpuPercent = 0.0
    $availMemMB = 0.0
    $diskReadBytes = 0
    $diskWriteBytes = 0
    $netSentBytes = 0
    $netRecvBytes = 0

    foreach ($sample in $samples.CounterSamples) {
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
    }

    $usedMemMB = [math]::Round($totalMemMB - $availMemMB, 2)

    "$ts|$cpuPercent|$usedMemMB|$diskReadBytes|$diskWriteBytes|$netSentBytes|$netRecvBytes" | Out-File -Append -FilePath $logPath -Encoding utf8

    Start-Sleep -Seconds 5
}
