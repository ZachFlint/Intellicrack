$ErrorActionPreference = 'SilentlyContinue'

$logDir = 'C:\sandbox_shared\logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logPath = Join-Path $logDir 'injection_monitor.log'

$typeSource = @'
using System;
using System.Runtime.InteropServices;

public static class NtQueryHelper {
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        out int ReturnLength
    );
}
'@

try {
    Add-Type -TypeDefinition $typeSource -Language CSharp
} catch {}

$knownThreads = @{}

while ($true) {
    $ts = Get-Date -Format 'o'

    $processes = Get-CimInstance -ClassName Win32_Process
    $procMap = @{}
    foreach ($proc in $processes) {
        $procMap[[int]$proc.ProcessId] = $proc.Name
    }

    $threads = Get-CimInstance -ClassName Win32_Thread
    foreach ($thread in $threads) {
        $threadKey = "$($thread.Handle):$($thread.ProcessHandle)"
        if (-not $knownThreads.ContainsKey($threadKey)) {
            $knownThreads[$threadKey] = $true

            $threadPid = [int]$thread.ProcessHandle
            $threadStartAddr = $thread.StartAddress

            if ($threadStartAddr -and $threadPid -gt 4) {
                $ownerName = $procMap[$threadPid]
                if (-not $ownerName) { $ownerName = 'unknown' }

                $parentPids = @()
                foreach ($proc in $processes) {
                    if ([int]$proc.ProcessId -ne $threadPid -and [int]$proc.ParentProcessId -eq $threadPid) {
                        continue
                    }
                    if ([int]$proc.ProcessId -eq $threadPid) {
                        $parentPid = [int]$proc.ParentProcessId
                        $parentName = $procMap[$parentPid]
                        if ($parentName -and $parentPid -ne $threadPid) {
                            $apis = @('CreateRemoteThread')
                            "$ts|$parentPid|$parentName|$threadPid|$ownerName|remote_thread|$($apis -join ',')" | Out-File -Append -FilePath $logPath -Encoding utf8
                        }
                    }
                }
            }
        }
    }

    $procsCurrent = Get-Process
    foreach ($proc in $procsCurrent) {
        try {
            $modules = $proc.Modules
            foreach ($mod in $modules) {
                if ($mod.FileName -match '\\Temp\\|\\AppData\\Local\\Temp\\') {
                    $modKey = "suspmod:$($proc.Id):$($mod.FileName)"
                    if (-not $knownThreads.ContainsKey($modKey)) {
                        $knownThreads[$modKey] = $true
                        $parentProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($proc.Id)"
                        $parentPid = 0
                        $parentName = 'unknown'
                        if ($parentProc) {
                            $parentPid = [int]$parentProc.ParentProcessId
                            $parentName = $procMap[$parentPid]
                            if (-not $parentName) { $parentName = 'unknown' }
                        }
                        $apis = @('LoadLibrary', 'WriteProcessMemory')
                        "$ts|$parentPid|$parentName|$($proc.Id)|$($proc.Name)|dll_injection|$($apis -join ',')" | Out-File -Append -FilePath $logPath -Encoding utf8
                    }
                }
            }
        } catch {}
    }

    Start-Sleep -Seconds 2
}
