param(
    [string]$Pixi = 'pixi run'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Downloading CI Reports"

Write-Step 'CI' "Checking gh authentication..."
try {
    gh auth status 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gh not authenticated" }
} catch {
    Write-Fail "gh CLI not authenticated. Run 'gh auth login' first."
    exit 1
}

Write-Step 'CI' "Downloading job logs and artifacts..."
Invoke-Expression "$Pixi python scripts/download_ci_reports.py"
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Download failed"
    exit 1
}

Write-Footer "CI Reports Complete" $startTime
