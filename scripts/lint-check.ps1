param(
    [string]$Pixi = 'pixi run',
    [string]$Src = 'src/intellicrack',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Running Ruff Linter"

Write-Step 'LINT' "Checking code style..."
try {
    Invoke-Expression "$Pixi ruff check $Flags $Src/ 2>&1" | ForEach-Object { Write-Host "  $_" }
    $checkCode = $LASTEXITCODE
} catch {
    $checkCode = 1
}

Write-Step 'LINT' "Checking formatting..."
try {
    Invoke-Expression "$Pixi ruff format --check $Flags $Src/ 2>&1" | ForEach-Object { Write-Host "  $_" }
    $formatCode = $LASTEXITCODE
} catch {
    $formatCode = 1
}

if ($checkCode -ne 0 -or $formatCode -ne 0) {
    Write-Fail "Linting issues found"
    exit 1
}

Write-Success "All lint checks passed"
Write-Footer "Lint Complete" $startTime
