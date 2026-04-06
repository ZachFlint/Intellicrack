param(
    [string]$Pixi = 'pixi run',
    [string]$Src = 'src/intellicrack',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Fixing Lint Issues"

Write-Step 'LINT-FIX' "Fixing code style issues..."
try {
    Invoke-Expression "$Pixi ruff check --fix $Flags $Src/ 2>&1" | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "ruff check --fix failed" }
} catch {
    Write-Fail "Style fix failed: $_"
    exit 1
}

Write-Step 'LINT-FIX' "Formatting code..."
try {
    Invoke-Expression "$Pixi ruff format $Flags $Src/ 2>&1" | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "ruff format failed" }
} catch {
    Write-Fail "Format failed: $_"
    exit 1
}

Write-Success "Lint issues fixed"
Write-Footer "Lint Fix Complete" $startTime
