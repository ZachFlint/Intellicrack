param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Building PDF Documentation"

Write-Step 'DOCS' "Generating LaTeX files..."
try {
    Invoke-Expression "$Pixi sphinx-build $Flags -b latex docs/source docs/build/latex 2>&1" | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "sphinx-build latex failed" }
    Write-Success "LaTeX files generated in docs/build/latex/"
} catch {
    Write-Fail "Generation failed: $_"
    exit 1
}

Write-Footer "PDF Build Complete" $startTime
