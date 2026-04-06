param(
    [string]$Pixi = 'pixi run',
    [string]$SrcAndTests = 'src/intellicrack/ tests/'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$removed = 0

Write-Banner "Cleaning Project Artifacts"

Write-Step 'CLEAN' "Cleaning Python bytecode (intellicrack, tests)..."
try {
    Invoke-Expression "$Pixi pyclean $SrcAndTests 2>&1" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Python bytecode cleaned"
        $removed++
    } else {
        Write-Fail "pyclean failed"
    }
} catch {
    Write-Skip "Python cleanup skipped: $_"
}

Write-Step 'CLEAN' "Checking for MagicMock artifact directory..."
$magicMockPath = Join-Path (Get-Location) "MagicMock"
if ((Test-Path $magicMockPath) -and (Get-Item $magicMockPath).PSIsContainer -and (Test-Path (Join-Path $magicMockPath "mock"))) {
    Remove-Item -Recurse -Force $magicMockPath -ErrorAction Stop
    Write-Success "MagicMock directory removed"
    $removed++
} else {
    Write-Skip "MagicMock not found or not matching expected structure"
}

Write-Step 'CLEAN' "Cleaning test artifacts..."
$artifacts = @('.pytest_cache', 'coverage_html_report', '.coverage', '.mypy_cache', '.ruff_cache')
foreach ($art in $artifacts) {
    if (Test-Path $art) {
        Remove-Item -Recurse -Force $art -ErrorAction SilentlyContinue
        $removed++
    }
}
Write-Success "Test artifacts cleaned"

$e = [char]27
Write-Host "`n${e}[1;32m=== Cleanup Complete ($removed items) ===${e}[0m`n"
