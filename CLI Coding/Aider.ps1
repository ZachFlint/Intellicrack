try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32Show {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
}
"@
} catch {}
Start-Sleep -Milliseconds 100
[Win32Show]::ShowWindow([Win32Show]::GetForegroundWindow(), 3) | Out-Null

Set-Location D:\Intellicrack
& aider
