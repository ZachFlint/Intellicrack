param(
    [string]$Pixi = 'pixi run'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Generating Structure Files"

Write-Step 'STRUCT' "Running structure generator..." '34'
try {
    $output = Invoke-Expression "$Pixi python scripts/generate_tree.py 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "Generator script failed" }
    Write-Success "Generator completed"
} catch {
    Write-Fail "Generation failed: $_"
    exit 1
}

Write-Step 'STRUCT' "Validating outputs..." '34'
$htaPath = "IntellicrackStructure.hta"
$txtPath = "IntellicrackStructure.txt"

if (-not (Test-Path $htaPath)) { Write-Fail "HTA file not found: $htaPath"; exit 1 }
Write-Success "HTA: $htaPath"

if (-not (Test-Path $txtPath)) { Write-Fail "TXT file not found: $txtPath"; exit 1 }
Write-Success "TXT: $txtPath"

$e = [char]27
$elapsed = ((Get-Date) - $startTime).TotalSeconds
Write-Host "`n${e}[1;34m=== Structure Generation Complete ===${e}[0m ${e}[90m($("{0:N1}" -f $elapsed)s)${e}[0m`n"
