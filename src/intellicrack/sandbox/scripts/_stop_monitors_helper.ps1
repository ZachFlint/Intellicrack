[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('SignalEvent', 'WaitForExit')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$EventName = 'IntellicrackMonitorStop',

    [Parameter(Mandatory = $false)]
    [int]$TargetPid = 0,

    [Parameter(Mandatory = $false)]
    [int]$WaitMilliseconds = 0
)

$ErrorActionPreference = 'Stop'

function Invoke-SignalEvent {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    $createdNew = $false
    try {
        $handle = [System.Threading.EventWaitHandle]::new(
            $true,
            [System.Threading.EventResetMode]::ManualReset,
            $Name,
            [ref]$createdNew)
        try {
            $handle.Set() | Out-Null
        } finally {
            $handle.Dispose()
        }
        return 0
    } catch [System.UnauthorizedAccessException] {
        try {
            $existing = [System.Threading.EventWaitHandle]::OpenExisting($Name)
            try {
                $existing.Set() | Out-Null
            } finally {
                $existing.Dispose()
            }
            return 0
        } catch {
            [Console]::Error.WriteLine("OpenExisting failed: $($_.Exception.Message)")
            return 1
        }
    } catch {
        [Console]::Error.WriteLine("Signal failed: $($_.Exception.Message)")
        return 1
    }
}

function Invoke-WaitForExit {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][int]$WaitMs
    )

    if ($ProcessId -le 0) {
        return 2
    }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch {
        return 2
    }

    try {
        $clampMs = [Math]::Max(0, [Math]::Min(300000, $WaitMs))
        if ($proc.WaitForExit($clampMs)) {
            return 0
        }
        return 1
    } catch {
        [Console]::Error.WriteLine("WaitForExit failed pid=$ProcessId : $($_.Exception.Message)")
        return 1
    }
}

switch ($Mode) {
    'SignalEvent' {
        exit (Invoke-SignalEvent -Name $EventName)
    }
    'WaitForExit' {
        exit (Invoke-WaitForExit -ProcessId $TargetPid -WaitMs $WaitMilliseconds)
    }
}

exit 99
