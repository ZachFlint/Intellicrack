param(
    [string]$LogDir = '.'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$logPath = Join-Path -Path $LogDir -ChildPath 'kernel_object_monitor.log'

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

    public const int SystemExtendedHandleInformation = 64;
    public const int ObjectNameInformation = 1;
    public const int ObjectTypeInformation = 2;

    public const uint STATUS_SUCCESS = 0x00000000;
    public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    public const uint PROCESS_DUP_HANDLE = 0x0040;
    public const uint DUPLICATE_SAME_ACCESS = 0x00000002;

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
}
'@

if (-not ('NtKernelObjects' -as [type])) {
    Add-Type -TypeDefinition $typeDef -Language CSharp
}

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

function Get-ProcessNameById {
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
        return $handles
    } finally {
        if ($buffer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    }

    return $handles
}

function Get-ObjectInfoString {
    param(
        [IntPtr]$Handle,
        [int]$InfoClass
    )

    $result = ''
    $bufSize = 0x1000
    $buf = [IntPtr]::Zero

    try {
        $returned = 0
        $status = [NtKernelObjects]::NtQueryObject($Handle, $InfoClass, [IntPtr]::Zero, 0, [ref]$returned)

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
            if ($ownerPid -le 4) {
                continue
            }

            $procHandle = [IntPtr]::Zero
            if ($openProcesses.ContainsKey($ownerPid)) {
                $procHandle = $openProcesses[$ownerPid]
            } else {
                try {
                    $procHandle = [NtKernelObjects]::OpenProcess(
                        [NtKernelObjects]::PROCESS_DUP_HANDLE, $false, [uint32]$ownerPid)
                } catch {
                    $procHandle = [IntPtr]::Zero
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
                $record = "$ts|$typeName|$objName|$ownerPid|$procName|created"

                try {
                    Add-Content -LiteralPath $logPath -Value $record -Encoding utf8
                } catch {
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
        $errTs = (Get-Date).ToString('o')
        $errMsg = $_.Exception.Message -replace '[\r\n|]', ' '
        try {
            Add-Content -LiteralPath $logPath -Value "$errTs|ERROR||0||$errMsg" -Encoding utf8
        } catch {
            $null = $_
        }
    }

    if ($processNameCache.Count -gt 4096) {
        $processNameCache.Clear()
    }

    Start-Sleep -Seconds 3
}
