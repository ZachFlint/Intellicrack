$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Host "Requesting administrator elevation..." -ForegroundColor Yellow
    $script = @'
$procs = @("python","pythonw","uv","pixi")
Write-Host ""
Write-Host "=== Killing Dev Processes (Elevated) ===" -ForegroundColor Cyan
Write-Host ""
$k = 0
foreach ($n in $procs) {
    $p = Get-Process -Name $n -EA SilentlyContinue
    if ($p) {
        $c = @($p).Count
        $p | Stop-Process -Force -EA SilentlyContinue
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
    Start-Process pwsh -Verb RunAs -ArgumentList "-NoProfile", "-Command", $script
    exit 0
}

$procs = @("python", "pythonw", "uv", "pixi")
Write-Host ""
Write-Host "=== Killing Dev Processes (Elevated) ===" -ForegroundColor Cyan
Write-Host ""
$k = 0
foreach ($n in $procs) {
    $p = Get-Process -Name $n -EA SilentlyContinue
    if ($p) {
        $c = @($p).Count
        $p | Stop-Process -Force -EA SilentlyContinue
        Write-Host "  [OK] $n ($c)" -ForegroundColor Green
        $k += $c
    } else {
        Write-Host "  [SKIP] $n" -ForegroundColor DarkGray
    }
}
Write-Host ""
Write-Host "=== Done: $k killed ===" -ForegroundColor Green
Write-Host ""
