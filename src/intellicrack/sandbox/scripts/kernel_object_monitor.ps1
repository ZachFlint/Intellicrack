$ErrorActionPreference = 'SilentlyContinue'

$logDir = 'C:\sandbox_shared\logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logPath = Join-Path $logDir 'kernel_object_monitor.log'

$knownObjects = @{}

while ($true) {
    $ts = Get-Date -Format 'o'

    $mutexes = Get-CimInstance -ClassName Win32_Mutex
    foreach ($obj in $mutexes) {
        $key = "Mutex:$($obj.Name)"
        if (-not $knownObjects.ContainsKey($key)) {
            $knownObjects[$key] = $true
            $ownerPid = 0
            $ownerName = ''
            if ($obj.Handle) {
                $proc = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.HandleCount -gt 0 } | Select-Object -First 1
                if ($proc) {
                    $ownerPid = $proc.ProcessId
                    $ownerName = $proc.Name
                }
            }
            "$ts|Mutex|$($obj.Name)|$ownerPid|$ownerName|created" | Out-File -Append -FilePath $logPath -Encoding utf8
        }
    }

    $events = Get-CimInstance -ClassName Win32_Event
    foreach ($obj in $events) {
        $key = "Event:$($obj.Name)"
        if (-not $knownObjects.ContainsKey($key)) {
            $knownObjects[$key] = $true
            "$ts|Event|$($obj.Name)|0||created" | Out-File -Append -FilePath $logPath -Encoding utf8
        }
    }

    $semaphores = Get-CimInstance -ClassName Win32_Semaphore
    foreach ($obj in $semaphores) {
        $key = "Semaphore:$($obj.Name)"
        if (-not $knownObjects.ContainsKey($key)) {
            $knownObjects[$key] = $true
            "$ts|Semaphore|$($obj.Name)|0||created" | Out-File -Append -FilePath $logPath -Encoding utf8
        }
    }

    Start-Sleep -Seconds 3
}
