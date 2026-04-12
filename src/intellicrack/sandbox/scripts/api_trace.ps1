$ErrorActionPreference = 'SilentlyContinue'

$logDir = 'C:\sandbox_shared\logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logPath = Join-Path $logDir 'api_trace.log'

$sessionName = 'IntApiTrace'

$existingSession = Get-EtwTraceSession -Name $sessionName
if ($existingSession) {
    Stop-EtwTraceSession -Name $sessionName
}

$auditApiProvider = '{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}'

$etwAvailable = $false
try {
    $session = New-EtwTraceSession -Name $sessionName -LogFileMode 0x0200 -LocalFilePath (Join-Path $env:TEMP 'api_trace.etl')
    if ($session) {
        Add-EtwTraceProvider -SessionName $sessionName -Guid $auditApiProvider -Level 5 -MatchAnyKeyword ([uint64]::MaxValue)
        $etwAvailable = $true
    }
} catch {
    $etwAvailable = $false
}

$trackedApis = @(
    'CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile',
    'RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey',
    'CreateProcess', 'OpenProcess', 'TerminateProcess',
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
    'WriteProcessMemory', 'ReadProcessMemory',
    'CreateRemoteThread', 'NtCreateThreadEx',
    'LoadLibrary', 'GetProcAddress',
    'WSAStartup', 'connect', 'send', 'recv',
    'InternetOpen', 'InternetConnect', 'HttpSendRequest',
    'CryptEncrypt', 'CryptDecrypt',
    'SetWindowsHookEx', 'GetAsyncKeyState'
)

if ($etwAvailable) {
    while ($true) {
        $ts = Get-Date -Format 'o'

        $events = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-Audit-API-Calls/Operational' -MaxEvents 100

        foreach ($event in $events) {
            $procId = $event.ProcessId
            $procName = 'unknown'
            $proc = Get-Process -Id $procId
            if ($proc) { $procName = $proc.Name }

            $apiName = $event.Message
            if (-not $apiName) { $apiName = "EventId_$($event.Id)" }
            $apiName = $apiName -replace '\|', '_'

            $module = ''
            $arguments = ''
            $returnValue = ''

            if ($event.Properties) {
                $propValues = @()
                foreach ($prop in $event.Properties) {
                    $propValues += [string]$prop.Value
                }
                if ($propValues.Count -ge 1) { $module = $propValues[0] }
                if ($propValues.Count -ge 2) { $arguments = $propValues[1] -replace '\|', '_' }
                if ($propValues.Count -ge 3) { $returnValue = $propValues[2] }
            }

            "$ts|$procName|$procId|$apiName|$module|$arguments|$returnValue" | Out-File -Append -FilePath $logPath -Encoding utf8
        }

        Start-Sleep -Seconds 2
    }
} else {
    $knownModules = @{}

    while ($true) {
        $ts = Get-Date -Format 'o'
        $processes = Get-Process | Where-Object { $_.Id -gt 4 }

        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                foreach ($mod in $modules) {
                    $key = "$($proc.Id):$($mod.ModuleName)"
                    if (-not $knownModules.ContainsKey($key)) {
                        $knownModules[$key] = $true

                        foreach ($api in $trackedApis) {
                            if ($mod.ModuleName -match 'kernel32|ntdll|ws2_32|wininet|advapi32|user32|crypt32') {
                                $moduleName = $mod.ModuleName -replace '\|', '_'
                                "$ts|$($proc.Name)|$($proc.Id)|$api|$moduleName||" | Out-File -Append -FilePath $logPath -Encoding utf8
                            }
                        }
                    }
                }
            } catch {}
        }

        Start-Sleep -Seconds 3
    }
}
