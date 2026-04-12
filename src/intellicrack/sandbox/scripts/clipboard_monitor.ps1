$ErrorActionPreference = 'SilentlyContinue'

$logDir = 'C:\sandbox_shared\logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logPath = Join-Path $logDir 'clipboard_monitor.log'

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

try {
    Add-Type -TypeDefinition $clipSource -ReferencedAssemblies System.Windows.Forms, System.Drawing -Language CSharp
} catch {
    while ($true) {
        $ts = Get-Date -Format 'o'
        $clipText = Get-Clipboard -Raw
        if ($clipText) {
            $preview = $clipText.Substring(0, [Math]::Min(100, $clipText.Length)) -replace '\|', '_'
            $sizeBytes = [System.Text.Encoding]::UTF8.GetByteCount($clipText)
            "$ts|changed|Text|$preview|$sizeBytes|0|unknown" | Out-File -Append -FilePath $logPath -Encoding utf8
        }
        Start-Sleep -Seconds 2
    }
    exit
}

$lastContent = ''

$listener = New-Object ClipboardListener
$listener.Add_ClipboardChanged({
    param($sender, $eventArgs)
    $ts = Get-Date -Format 'o'
    $pid = [int]$eventArgs.OwnerPid
    $procName = 'unknown'
    if ($pid -gt 0) {
        $proc = Get-Process -Id $pid
        if ($proc) { $procName = $proc.Name }
    }

    $format = 'unknown'
    $preview = ''
    $sizeBytes = 0

    $clipText = [System.Windows.Forms.Clipboard]::GetText()
    if ($clipText) {
        $format = 'Text'
        $preview = $clipText.Substring(0, [Math]::Min(100, $clipText.Length)) -replace '\|', '_'
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
        $preview = ($files | Select-Object -First 3) -join '; '
        $preview = $preview -replace '\|', '_'
        $sizeBytes = $files.Count
    }

    if ($format -ne 'unknown') {
        "$ts|changed|$format|$preview|$sizeBytes|$pid|$procName" | Out-File -Append -FilePath $logPath -Encoding utf8
    }
})

$listener.Show()
$listener.Hide()
[System.Windows.Forms.Application]::Run($listener)
