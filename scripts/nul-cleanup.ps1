param(
    [string]$Pixi = 'pixi run'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "NUL File Cleanup"

Write-Step 'NUL' "Scanning for NUL file artifacts..." '35'
try {
    $output = Invoke-Expression "$Pixi python scripts/clean_nul.py 2>&1"
    $outputStr = $output -join "`n"
    if ($outputStr -match '(\d+)\s+file\(s\)\s+deleted') {
        $deleted = $matches[1]
    } else {
        $deleted = 0
    }
    if ($LASTEXITCODE -ne 0) { throw "Clean script failed" }
    Write-Success "Cleanup complete ($deleted files removed)"
} catch {
    Write-Fail "Cleanup failed: $_"
    exit 1
}

$e = [char]27
$elapsed = ((Get-Date) - $startTime).TotalSeconds
Write-Host "`n${e}[1;35m=== NUL Cleanup Complete ===${e}[0m ${e}[90m($("{0:N1}" -f $elapsed)s)${e}[0m`n"
