param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date

Write-Step 'DOCS' "Checking documentation links..."
try {
    Invoke-Expression "$Pixi sphinx-build $Flags -b linkcheck docs/source docs/build/linkcheck 2>&1" | ForEach-Object { Write-Host "  $_" }
    Write-Success "Link check complete. Results in docs/build/linkcheck/output.txt"
} catch {
    Write-Fail "Link check failed: $_"
    exit 1
}

$e = [char]27
$elapsed = ((Get-Date) - $startTime).TotalSeconds
Write-Host "`n${e}[32mLink check complete${e}[0m ${e}[90m($("{0:N1}" -f $elapsed)s)${e}[0m"
