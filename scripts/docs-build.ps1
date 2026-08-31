param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Building Documentation"

Write-Step 'DOCS' "Running Sphinx build..."
try {
    Invoke-Expression "$Pixi sphinx-build $Flags -b html docs/source docs/build/html 2>&1" | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "sphinx-build failed with exit code $LASTEXITCODE" }
    Write-Success "Documentation built"
} catch {
    Write-Fail "Build failed: $_"
    exit 1
}

Write-Step 'DOCS' "Validating output..."
if (-not (Test-Path "docs/build/html/index.html")) {
    Write-Fail "index.html not found"
    exit 1
}
Write-Success "Output validated: docs/build/html/index.html"

Write-Footer "Documentation Built" $startTime
