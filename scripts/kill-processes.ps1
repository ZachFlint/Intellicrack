$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$elevatedBody = @'
$procs = @("python", "pythonw", "uv", "pixi")
Write-Host ""
Write-Host "=== Killing Dev Processes (Elevated) ===" -ForegroundColor Cyan
Write-Host ""
$k = 0
foreach ($n in $procs) {
    $p = Get-Process -Name $n -ErrorAction SilentlyContinue
    if ($p) {
        $c = @($p).Count
        $p | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] $n ($c)" -ForegroundColor Green
        $k += $c
    } else {
        Write-Host "  [SKIP] $n" -ForegroundColor DarkGray
    }
}
Write-Host ""
Write-Host "=== Done: $k killed ===" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to close"
'@

if (-not $isAdmin) {
    Write-Host "Requesting administrator elevation..." -ForegroundColor Yellow

    $tempScript = Join-Path $env:TEMP "intellicrack-kill-processes-$PID.ps1"
    Set-Content -LiteralPath $tempScript -Value $elevatedBody -Encoding UTF8

    try {
        $proc = Start-Process pwsh -Verb RunAs -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$tempScript`""
        ) -PassThru -Wait -ErrorAction Stop

        if ($proc.ExitCode -ne 0) {
            Write-Host "Elevated kill process exited with code $($proc.ExitCode)" -ForegroundColor Red
            exit $proc.ExitCode
        }
    } catch {
        Write-Host "Elevation was cancelled or failed: $_" -ForegroundColor Red
        exit 1
    } finally {
        Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

$procs = @("python", "pythonw", "uv", "pixi")
Write-Host ""
Write-Host "=== Killing Dev Processes (Elevated) ===" -ForegroundColor Cyan
Write-Host ""
$k = 0
foreach ($n in $procs) {
    $p = Get-Process -Name $n -ErrorAction SilentlyContinue
    if ($p) {
        $c = @($p).Count
        $p | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] $n ($c)" -ForegroundColor Green
        $k += $c
    } else {
        Write-Host "  [SKIP] $n" -ForegroundColor DarkGray
    }
}
Write-Host ""
Write-Host "=== Done: $k killed ===" -ForegroundColor Green
Write-Host ""
