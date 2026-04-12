$ErrorActionPreference = 'SilentlyContinue'

$logDir = 'C:\sandbox_shared\logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logPath = Join-Path $logDir 'dll_monitor.log'

$sessionName = 'IntDllMon'

$existingSession = Get-EtwTraceSession -Name $sessionName
if ($existingSession) {
    Stop-EtwTraceSession -Name $sessionName
}

$traceProps = @{
    Name            = $sessionName
    LogFileMode     = 0x0200
    LocalFilePath   = Join-Path $env:TEMP 'dll_trace.etl'
}

try {
    $session = New-EtwTraceSession @traceProps
    $providerGuid = '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}'
    $imageLoadKeyword = [uint64]0x40
    Add-EtwTraceProvider -SessionName $sessionName -Guid $providerGuid -MatchAnyKeyword $imageLoadKeyword -Level 5
} catch {
    $session = $null
}

if (-not $session) {
    $knownModules = @{}
    while ($true) {
        $ts = Get-Date -Format 'o'
        $processes = Get-Process
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                foreach ($mod in $modules) {
                    $key = "$($proc.Id):$($mod.FileName)"
                    if (-not $knownModules.ContainsKey($key)) {
                        $knownModules[$key] = $true
                        $baseAddr = '0x{0:X}' -f [int64]$mod.BaseAddress
                        $size = $mod.ModuleMemorySize
                        "$ts|$($proc.Id)|$($proc.Name)|$($mod.FileName)|$baseAddr|$size" | Out-File -Append -FilePath $logPath -Encoding utf8
                    }
                }
            } catch {}
        }
        Start-Sleep -Seconds 2
    }
} else {
    $knownModules = @{}
    while ($true) {
        $ts = Get-Date -Format 'o'
        $processes = Get-Process
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                foreach ($mod in $modules) {
                    $key = "$($proc.Id):$($mod.FileName)"
                    if (-not $knownModules.ContainsKey($key)) {
                        $knownModules[$key] = $true
                        $baseAddr = '0x{0:X}' -f [int64]$mod.BaseAddress
                        $size = $mod.ModuleMemorySize
                        "$ts|$($proc.Id)|$($proc.Name)|$($mod.FileName)|$baseAddr|$size" | Out-File -Append -FilePath $logPath -Encoding utf8
                    }
                }
            } catch {}
        }
        Start-Sleep -Seconds 2
    }
}
