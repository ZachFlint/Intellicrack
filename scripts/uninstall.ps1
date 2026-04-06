$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

Write-Banner "Intellicrack Uninstall"

$startTime = Get-Date

Write-Step 'UNINSTALL' "Cleaning pixi environment..."
try {
    pixi clean
    if ($LASTEXITCODE -ne 0) { throw "pixi clean failed with exit code $LASTEXITCODE" }
    Write-Success "Pixi environment cleaned"
} catch {
    Write-Fail "Pixi clean failed: $_"
    exit 1
}

Write-Step 'UNINSTALL' "Removing pixi.lock..."
if (Test-Path "pixi.lock") {
    try {
        Remove-Item -Force "pixi.lock" -ErrorAction Stop
        Write-Success "pixi.lock removed"
    } catch {
        Write-Fail "Failed to remove pixi.lock: $_"
        exit 1
    }
} else {
    Write-Skip "pixi.lock not found"
}

Write-Footer "Uninstall Complete" $startTime
