Set-Location "C:\Users\zachf"

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
Write-Host "Updating all CLI coding tools..." -ForegroundColor Magenta;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Aider..." -ForegroundColor Blue;
uv tool upgrade aider-chat;
Write-Host "Aider updated!" -ForegroundColor Green;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Claude Code..." -ForegroundColor DarkCyan;
claude update;
Write-Host "Claude Code updated!" -ForegroundColor Cyan;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Codex..." -ForegroundColor Green;
npm install -g @openai/codex;
Write-Host "Codex updated!" -ForegroundColor DarkGreen;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Gemini CLI..." -ForegroundColor Cyan;
npm update -g @google/gemini-cli;
Write-Host "Gemini CLI updated!" -ForegroundColor DarkCyan;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Grok..." -ForegroundColor Red;
npm install -g @vibe-kit/grok-cli --force;
Write-Host "Grok updated!" -ForegroundColor DarkRed;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating OpenCode..." -ForegroundColor Yellow;
winget upgrade SST.opencode;
Write-Host "OpenCode updated!" -ForegroundColor DarkYellow;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Qodo..." -ForegroundColor White;
npm install -g @qodo/command;
Write-Host "Qodo updated!" -ForegroundColor Gray;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Qwen..." -ForegroundColor DarkGray;
npm install -g @qwen-code/qwen-code;
Write-Host "Qwen updated!" -ForegroundColor DarkMagenta;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Kiro CLI..." -ForegroundColor Cyan;
wsl bash -c 'if command -v kiro-cli &> /dev/null; then kiro-cli update --non-interactive; else curl -fsSL https://cli.kiro.dev/install | bash; fi';
wsl --shutdown;
Write-Host "Kiro CLI updated!" -ForegroundColor Red;
Write-Host "`n"
Write-Host "`n"
Write-Host "Updating Kimi Cli..." -ForegroundColor Magenta;
uv tool upgrade kimi-cli --no-cache --link-mode=copy
Write-Host "Kimi CLI updated!" -ForegroundColor DarkMagenta;
Write-Host "`n"
Write-Host "`n"
Write-Host "`nAll CLI coding tools updated!" -ForegroundColor Magenta;
Write-Host "`n"
Write-Host "`n"
Write-Host "`nPress any key to continue..." -ForegroundColor Yellow;
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")