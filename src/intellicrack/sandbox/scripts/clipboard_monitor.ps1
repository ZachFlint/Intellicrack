[CmdletBinding()]
param(
    [Parameter()][string]$LogDir = (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\Shared\logs')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$script:LogPath = Join-Path -Path $LogDir -ChildPath 'clipboard_monitor.log'
$script:FallbackPollSeconds = 2

function Write-LogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Line
    )
    Add-Content -LiteralPath $script:LogPath -Value $Line -Encoding utf8
}

function Write-StructuredError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Event,
        [Parameter(Mandatory = $true)][object]$ErrorRecord,
        [Parameter()][hashtable]$Extra
    )

    $payload = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        event     = $Event
        error     = ([string]$ErrorRecord)
    }
    if ($PSBoundParameters.ContainsKey('Extra') -and $null -ne $Extra) {
        foreach ($key in $Extra.Keys) {
            $payload[$key] = $Extra[$key]
        }
    }

    $json = $payload | ConvertTo-Json -Compress -Depth 4
    try {
        Add-Content -LiteralPath $script:LogPath -Value $json -Encoding utf8
    } catch {
        Write-Error -Message $json -ErrorAction Continue
    }
}

function Format-PreviewField {
    [CmdletBinding()]
    param(
        [Parameter()][string]$Value
    )
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    $trimmed = $Value.Substring(0, [Math]::Min(100, $Value.Length))
    return ($trimmed -replace '\|', '_' -replace '[\r\n]+', ' ')
}

$clipSource = @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

public class ClipboardListener : Form {
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardOwner();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    private const int WM_CLIPBOARDUPDATE = 0x031D;
    public event EventHandler<ClipboardChangedEventArgs> ClipboardChanged;

    public ClipboardListener() {
        this.ShowInTaskbar = false;
        this.FormBorderStyle = FormBorderStyle.None;
        this.Size = new System.Drawing.Size(1, 1);
        this.Location = new System.Drawing.Point(-2000, -2000);
    }

    protected override void OnHandleCreated(EventArgs e) {
        base.OnHandleCreated(e);
        AddClipboardFormatListener(this.Handle);
    }

    protected override void OnHandleDestroyed(EventArgs e) {
        RemoveClipboardFormatListener(this.Handle);
        base.OnHandleDestroyed(e);
    }

    protected override void WndProc(ref Message m) {
        if (m.Msg == WM_CLIPBOARDUPDATE) {
            uint pid = 0;
            IntPtr owner = GetClipboardOwner();
            if (owner != IntPtr.Zero) {
                GetWindowThreadProcessId(owner, out pid);
            }
            ClipboardChanged?.Invoke(this, new ClipboardChangedEventArgs(pid));
        }
        base.WndProc(ref m);
    }
}

public class ClipboardChangedEventArgs : EventArgs {
    public uint OwnerPid { get; }
    public ClipboardChangedEventArgs(uint ownerPid) {
        OwnerPid = ownerPid;
    }
}
'@

function Invoke-FallbackPolling {
    [CmdletBinding()]
    param()

    $lastSeen = $null
    while ($true) {
        $ts = (Get-Date).ToString('o')
        $clipText = $null
        try {
            $clipText = Get-Clipboard -Raw
        } catch {
            Write-StructuredError -Event 'fallback.read_failed' -ErrorRecord $_
        }

        if ($clipText -and $clipText -ne $lastSeen) {
            $preview = Format-PreviewField -Value $clipText
            $sizeBytes = [System.Text.Encoding]::UTF8.GetByteCount($clipText)
            $line = "$ts|changed|Text|$preview|$sizeBytes|0|unknown"
            try {
                Write-LogEntry -Line $line
                $lastSeen = $clipText
            } catch {
                Write-StructuredError -Event 'fallback.write_failed' -ErrorRecord $_ -Extra @{ size = $sizeBytes }
            }
        }

        Start-Sleep -Seconds $script:FallbackPollSeconds
    }
}

function Invoke-EventDrivenMonitor {
    [CmdletBinding()]
    param()

    $listener = New-Object ClipboardListener
    $eventHandler = {
        param($source, $clipboardArgs)
        $null = $source
        $ts = (Get-Date).ToString('o')
        $ownerPid = 0
        try {
            $ownerPid = [int]$clipboardArgs.OwnerPid
        } catch {
            Write-StructuredError -Event 'event.pid_cast_failed' -ErrorRecord $_
        }

        $procName = 'unknown'
        if ($ownerPid -gt 0) {
            try {
                $proc = Get-Process -Id $ownerPid -ErrorAction Stop
                if ($proc) { $procName = $proc.Name }
            } catch {
                Write-StructuredError -Event 'event.process_lookup_failed' -ErrorRecord $_ -Extra @{ owner_pid = $ownerPid }
            }
        }

        $format = 'unknown'
        $preview = ''
        $sizeBytes = 0

        try {
            $clipText = [System.Windows.Forms.Clipboard]::GetText()
            if ($clipText) {
                $format = 'Text'
                $preview = Format-PreviewField -Value $clipText
                $sizeBytes = [System.Text.Encoding]::UTF8.GetByteCount($clipText)
            } elseif ([System.Windows.Forms.Clipboard]::ContainsImage()) {
                $format = 'Image'
                $img = [System.Windows.Forms.Clipboard]::GetImage()
                if ($img) {
                    $preview = "Image $($img.Width)x$($img.Height)"
                    $sizeBytes = $img.Width * $img.Height * 4
                }
            } elseif ([System.Windows.Forms.Clipboard]::ContainsFileDropList()) {
                $format = 'FileDrop'
                $files = [System.Windows.Forms.Clipboard]::GetFileDropList()
                $preview = Format-PreviewField -Value (($files | Select-Object -First 3) -join '; ')
                $sizeBytes = $files.Count
            }
        } catch {
            Write-StructuredError -Event 'event.clipboard_read_failed' -ErrorRecord $_ -Extra @{ owner_pid = $ownerPid }
            return
        }

        if ($format -ne 'unknown') {
            $line = "$ts|changed|$format|$preview|$sizeBytes|$ownerPid|$procName"
            try {
                Write-LogEntry -Line $line
            } catch {
                Write-StructuredError -Event 'event.write_failed' -ErrorRecord $_ -Extra @{ owner_pid = $ownerPid; format = $format }
            }
        }
    }

    $listener.Add_ClipboardChanged($eventHandler)
    $listener.Show()
    $listener.Hide()
    [System.Windows.Forms.Application]::Run($listener)
}

$useEventDriven = $false
try {
    Add-Type -TypeDefinition $clipSource -ReferencedAssemblies System.Windows.Forms, System.Drawing -Language CSharp
    $useEventDriven = $true
} catch {
    Write-StructuredError -Event 'init.add_type_failed' -ErrorRecord $_ -Extra @{ fallback = 'polling' }
}

if ($useEventDriven) {
    try {
        Invoke-EventDrivenMonitor
    } catch {
        Write-StructuredError -Event 'event.monitor_failed' -ErrorRecord $_ -Extra @{ fallback = 'polling' }
        Invoke-FallbackPolling
    }
} else {
    Invoke-FallbackPolling
}
