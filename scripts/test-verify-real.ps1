param(
    [string]$Pixi = 'pixi run'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

Write-Step 'VERIFY' "Verifying no mocks or fake data..."
try {
    Invoke-Expression "$Pixi python scripts/verify_no_mocks.py 2>&1" | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "Verification failed with exit code $LASTEXITCODE" }
    Write-Success "All tests use REAL data"
} catch {
    Write-Fail "Verification failed: $_"
    exit 1
}
