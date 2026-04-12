$ErrorActionPreference = 'SilentlyContinue'

$logDir = 'C:\sandbox_shared\logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logPath = Join-Path $logDir 'service_monitor.log'

$baseline = @{}
$services = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services'
foreach ($svc in $services) {
    $svcName = $svc.PSChildName
    $props = Get-ItemProperty -Path $svc.PSPath
    $baseline[$svcName] = @{
        DisplayName = [string]$props.DisplayName
        ImagePath   = [string]$props.ImagePath
        Start       = [string]$props.Start
    }
}

while ($true) {
    Start-Sleep -Seconds 2
    $ts = Get-Date -Format 'o'
    $current = @{}
    $services = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services'

    foreach ($svc in $services) {
        $svcName = $svc.PSChildName
        $props = Get-ItemProperty -Path $svc.PSPath
        $displayName = [string]$props.DisplayName
        $imagePath = [string]$props.ImagePath
        $startType = [string]$props.Start

        $current[$svcName] = @{
            DisplayName = $displayName
            ImagePath   = $imagePath
            Start       = $startType
        }

        if (-not $baseline.ContainsKey($svcName)) {
            "$ts|created|$svcName|$displayName|$imagePath|$startType" | Out-File -Append -FilePath $logPath -Encoding utf8
        } else {
            $prev = $baseline[$svcName]
            if ($prev.ImagePath -ne $imagePath -or $prev.Start -ne $startType -or $prev.DisplayName -ne $displayName) {
                "$ts|modified|$svcName|$displayName|$imagePath|$startType" | Out-File -Append -FilePath $logPath -Encoding utf8
            }
        }
    }

    $removed = $baseline.Keys | Where-Object { -not $current.ContainsKey($_) }
    foreach ($svcName in $removed) {
        $prev = $baseline[$svcName]
        "$ts|deleted|$svcName|$($prev.DisplayName)|$($prev.ImagePath)|$($prev.Start)" | Out-File -Append -FilePath $logPath -Encoding utf8
    }

    $baseline = $current
}
