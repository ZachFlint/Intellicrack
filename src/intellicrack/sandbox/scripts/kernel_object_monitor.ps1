param(
    [string]$LogDir = '.',
    [int]$PollIntervalMilliseconds = 250
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$logPath = Join-Path -Path $LogDir -ChildPath 'kernel_object_monitor.log'
$errorLogPath = Join-Path -Path $LogDir -ChildPath 'kernel_object_monitor.errors.log'

# Polling cadence trade-off:
#
#  * The Microsoft-Windows-Kernel-Object ETW provider can deliver per-handle
#    open/close events in real time, but enabling it requires either an
#    Autologger/system-trace session (admin + reboot for the AutoLogger key)
#    or an active TraceEventSession with SystemTraceFlags Object Manager
#    enabled. Inside Windows Sandbox the autologger path is unreliable and
#    the realtime kernel provider frequently fails with ERROR_ACCESS_DENIED
#    even from an elevated session.
#  * As a deterministic fallback we tighten the NtQuerySystemInformation
#    poll loop to 250 ms (configurable via -PollIntervalMilliseconds). At
#    250 ms the loop catches mutex/event/semaphore creations that close
#    again within ~250 ms which the previous 3 s cadence missed entirely.
#  * The trade-off is CPU: a 250 ms full-system handle enumeration costs
#    roughly 4x the previous load; this is acceptable because the monitor
#    runs only inside short-lived sandbox sessions.

if ($PollIntervalMilliseconds -lt 50) {
    $PollIntervalMilliseconds = 50
}
if ($PollIntervalMilliseconds -gt 5000) {
    $PollIntervalMilliseconds = 5000
}

function Write-MonitorError {
    param(
        [string]$Stage,
        [string]$Detail,
        [int]$ErrorCode = 0,
        [int]$TargetPid = 0
    )

    $ts = (Get-Date).ToString('o')
    $safeStage = ($Stage -replace '[\r\n|]', '_')
    $safeDetail = ($Detail -replace '[\r\n|]', ' ')
    $line = "$ts|$safeStage|pid=$TargetPid|err=$ErrorCode|$safeDetail"
    try {
        Add-Content -LiteralPath $errorLogPath -Value $line -Encoding utf8
    } catch {
        # Last-resort: emit to stderr if the error log itself is unwritable
        # so the sandbox bridge can still surface the failure rather than
        # silently dropping it.
        [Console]::Error.WriteLine($line)
    }
}

$typeDef = @'
using System;
using System.Runtime.InteropServices;

public static class NtKernelObjects
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    public const int SystemExtendedHandleInformation = 64;
    public const int ObjectNameInformation = 1;
    public const int ObjectTypeInformation = 2;

    public const uint STATUS_SUCCESS = 0x00000000;
    public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    public const uint PROCESS_DUP_HANDLE = 0x0040;
    public const uint DUPLICATE_SAME_ACCESS = 0x00000002;

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    public const int ERROR_NOT_ALL_ASSIGNED = 1300;

    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryObject(
        IntPtr Handle,
        int ObjectInformationClass,
        IntPtr ObjectInformation,
        uint ObjectInformationLength,
        out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle,
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwOptions);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValueW(
        string lpSystemName,
        string lpName,
        out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);
}
'@

if (-not ('NtKernelObjects' -as [type])) {
    Add-Type -TypeDefinition $typeDef -Language CSharp
}

function Enable-SeDebugPrivilege {
    [OutputType([bool])]
    param()

    $tokenHandle = [IntPtr]::Zero
    try {
        $current = [NtKernelObjects]::GetCurrentProcess()
        $access = [NtKernelObjects]::TOKEN_ADJUST_PRIVILEGES -bor [NtKernelObjects]::TOKEN_QUERY
        if (-not [NtKernelObjects]::OpenProcessToken($current, $access, [ref]$tokenHandle)) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-MonitorError -Stage 'OpenProcessToken' -Detail 'cannot open primary token' -ErrorCode $err
            return $false
        }

        $luid = New-Object NtKernelObjects+LUID
        if (-not [NtKernelObjects]::LookupPrivilegeValueW($null, 'SeDebugPrivilege', [ref]$luid)) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-MonitorError -Stage 'LookupPrivilegeValueW' -Detail 'SeDebugPrivilege lookup failed' -ErrorCode $err
            return $false
        }

        $tp = New-Object NtKernelObjects+TOKEN_PRIVILEGES
        $tp.PrivilegeCount = 1
        $laa = New-Object NtKernelObjects+LUID_AND_ATTRIBUTES
        $laa.Luid = $luid
        $laa.Attributes = [NtKernelObjects]::SE_PRIVILEGE_ENABLED
        $tp.Privileges = $laa

        if (-not [NtKernelObjects]::AdjustTokenPrivileges(
                $tokenHandle, $false, [ref]$tp,
                [uint32]([Runtime.InteropServices.Marshal]::SizeOf([type][NtKernelObjects+TOKEN_PRIVILEGES])),
                [IntPtr]::Zero, [IntPtr]::Zero)) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-MonitorError -Stage 'AdjustTokenPrivileges' -Detail 'AdjustTokenPrivileges call failed' -ErrorCode $err
            return $false
        }

        # AdjustTokenPrivileges returns TRUE even when not all privileges
        # were assigned; ERROR_NOT_ALL_ASSIGNED is the canonical signal that
        # the caller is non-admin and SeDebugPrivilege was not granted.
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq [NtKernelObjects]::ERROR_NOT_ALL_ASSIGNED) {
            Write-MonitorError -Stage 'AdjustTokenPrivileges' -Detail 'SeDebugPrivilege not held by caller (non-admin) - peer-process inspection will be partial' -ErrorCode $err
            return $false
        }
        return $true
    } finally {
        if ($tokenHandle -ne [IntPtr]::Zero) {
            [void][NtKernelObjects]::CloseHandle($tokenHandle)
        }
    }
}

$script:DebugPrivilegeEnabled = Enable-SeDebugPrivilege

$watchedTypes = @{
    'Mutant'    = $true
    'Event'     = $true
    'Semaphore' = $true
    'Section'   = $true
    'Job'       = $true
    'Directory' = $true
}

$knownObjects = @{}
$processNameCache = @{}
$openProcessFailures = @{}

function Get-ProcessNameById {
    [OutputType([string])]
    param([int]$ProcessId)

    if ($processNameCache.ContainsKey($ProcessId)) {
        return $processNameCache[$ProcessId]
    }

    $name = ''
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        $name = $proc.ProcessName
    } catch {
        $name = ''
    }

    $processNameCache[$ProcessId] = $name
    return $name
}

function Get-SystemHandleInformation {
    [OutputType([System.Collections.ArrayList])]
    param()

    $size = 0x10000
    $buffer = [IntPtr]::Zero
    $handles = New-Object System.Collections.ArrayList
    $attempts = 0

    try {
        while ($attempts -lt 12) {
            $attempts++
            if ($buffer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
                $buffer = [IntPtr]::Zero
            }
            $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
            $returned = 0
            $status = [NtKernelObjects]::NtQuerySystemInformation(
                [NtKernelObjects]::SystemExtendedHandleInformation,
                $buffer,
                [uint32]$size,
                [ref]$returned)

            if ($status -eq [NtKernelObjects]::STATUS_SUCCESS) {
                break
            }
            if ($status -eq [NtKernelObjects]::STATUS_INFO_LENGTH_MISMATCH) {
                if ($returned -gt 0) {
                    $size = [int]([Math]::Max([int]$returned + 0x10000, $size * 2))
                } else {
                    $size = $size * 2
                }
                continue
            }
            Write-MonitorError -Stage 'NtQuerySystemInformation' -Detail "non-success status 0x$($status.ToString('X8'))" -ErrorCode ([int]$status)
            return $handles
        }

        if ($buffer -eq [IntPtr]::Zero) {
            return $handles
        }

        $numHandles = [Runtime.InteropServices.Marshal]::ReadIntPtr($buffer).ToInt64()
        $ptrSize = [IntPtr]::Size
        $headerSize = $ptrSize * 2
        $entrySize = [Runtime.InteropServices.Marshal]::SizeOf([type][NtKernelObjects+SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX])
        $basePtr = [IntPtr]::Add($buffer, $headerSize)

        for ($i = 0L; $i -lt $numHandles; $i++) {
            $entryPtr = [IntPtr]::Add($basePtr, [int]($i * $entrySize))
            $entry = [Runtime.InteropServices.Marshal]::PtrToStructure(
                $entryPtr,
                [type][NtKernelObjects+SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX])
            [void]$handles.Add($entry)
        }
    } catch {
        Write-MonitorError -Stage 'Get-SystemHandleInformation' -Detail $_.Exception.Message
        return $handles
    } finally {
        if ($buffer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    }

    return $handles
}

function Get-ObjectInfoString {
    [OutputType([string])]
    param(
        [IntPtr]$Handle,
        [int]$InfoClass
    )

    $result = ''
    $bufSize = 0x1000
    $buf = [IntPtr]::Zero

    try {
        $returned = 0
        $null = [NtKernelObjects]::NtQueryObject($Handle, $InfoClass, [IntPtr]::Zero, 0, [ref]$returned)

        if ($returned -gt 0) {
            $bufSize = [int]$returned + 0x100
        }

        $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufSize)
        $status = [NtKernelObjects]::NtQueryObject($Handle, $InfoClass, $buf, [uint32]$bufSize, [ref]$returned)

        if ($status -ne [NtKernelObjects]::STATUS_SUCCESS) {
            return $result
        }

        $us = [Runtime.InteropServices.Marshal]::PtrToStructure($buf, [type][NtKernelObjects+UNICODE_STRING])
        if ($us.Length -gt 0 -and $us.Buffer -ne [IntPtr]::Zero) {
            $result = [Runtime.InteropServices.Marshal]::PtrToStringUni($us.Buffer, [int]($us.Length / 2))
        }
    } catch {
        return ''
    } finally {
        if ($buf -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        }
    }

    return $result
}

function Invoke-MonitorSweep {
    $ts = (Get-Date).ToString('o')
    $handles = Get-SystemHandleInformation
    if ($handles.Count -eq 0) {
        return
    }

    $currentProcess = [NtKernelObjects]::GetCurrentProcess()
    $openProcesses = @{}

    try {
        foreach ($h in $handles) {
            $ownerPid = [int]$h.UniqueProcessId.ToInt64()
            if ($ownerPid -le 0) {
                continue
            }

            $procHandle = [IntPtr]::Zero
            if ($openProcesses.ContainsKey($ownerPid)) {
                $procHandle = $openProcesses[$ownerPid]
            } else {
                $procHandle = [NtKernelObjects]::OpenProcess(
                    [NtKernelObjects]::PROCESS_DUP_HANDLE, $false, [uint32]$ownerPid)
                if ($procHandle -eq [IntPtr]::Zero) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    # De-duplicate per (pid, error) to avoid log floods on
                    # System (PID 4) and other protected processes that
                    # always fail with the same error code.
                    $key = "$ownerPid|$err"
                    if (-not $openProcessFailures.ContainsKey($key)) {
                        $openProcessFailures[$key] = $true
                        Write-MonitorError -Stage 'OpenProcess' -Detail 'PROCESS_DUP_HANDLE failed' -ErrorCode $err -TargetPid $ownerPid
                    }
                }
                $openProcesses[$ownerPid] = $procHandle
            }

            if ($procHandle -eq [IntPtr]::Zero) {
                continue
            }

            $dup = [IntPtr]::Zero
            $dupOk = $false
            try {
                $dupOk = [NtKernelObjects]::DuplicateHandle(
                    $procHandle,
                    $h.HandleValue,
                    $currentProcess,
                    [ref]$dup,
                    0,
                    $false,
                    [NtKernelObjects]::DUPLICATE_SAME_ACCESS)
            } catch {
                $dupOk = $false
            }

            if (-not $dupOk -or $dup -eq [IntPtr]::Zero) {
                continue
            }

            try {
                $typeName = Get-ObjectInfoString -Handle $dup -InfoClass ([NtKernelObjects]::ObjectTypeInformation)
                if ([string]::IsNullOrEmpty($typeName)) {
                    continue
                }
                if (-not $watchedTypes.ContainsKey($typeName)) {
                    continue
                }

                $objName = Get-ObjectInfoString -Handle $dup -InfoClass ([NtKernelObjects]::ObjectNameInformation)
                if ([string]::IsNullOrEmpty($objName)) {
                    continue
                }

                $dedupKey = "{0}|{1}|{2}" -f $typeName, $objName, $ownerPid
                if ($knownObjects.ContainsKey($dedupKey)) {
                    continue
                }
                $knownObjects[$dedupKey] = $true

                $procName = Get-ProcessNameById -ProcessId $ownerPid
                $safeType = ($typeName -replace '[\r\n|]', '_')
                $safeName = ($objName -replace '[\r\n|]', '_')
                $safeProc = ($procName -replace '[\r\n|]', '_')
                $record = "$ts|$safeType|$safeName|$ownerPid|$safeProc|created"

                try {
                    Add-Content -LiteralPath $logPath -Value $record -Encoding utf8
                } catch {
                    Write-MonitorError -Stage 'WriteLog' -Detail $_.Exception.Message -TargetPid $ownerPid
                    continue
                }
            } finally {
                [void][NtKernelObjects]::CloseHandle($dup)
            }
        }
    } finally {
        foreach ($kv in $openProcesses.GetEnumerator()) {
            if ($kv.Value -ne [IntPtr]::Zero) {
                [void][NtKernelObjects]::CloseHandle($kv.Value)
            }
        }
    }
}

while ($true) {
    try {
        Invoke-MonitorSweep
    } catch {
        Write-MonitorError -Stage 'Invoke-MonitorSweep' -Detail $_.Exception.Message
    }

    if ($processNameCache.Count -gt 4096) {
        $processNameCache.Clear()
    }
    if ($openProcessFailures.Count -gt 4096) {
        $openProcessFailures.Clear()
    }

    Start-Sleep -Milliseconds $PollIntervalMilliseconds
}
