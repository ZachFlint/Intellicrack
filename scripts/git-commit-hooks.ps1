param(
    [Parameter(Mandatory)][string]$Message
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date

Write-Step 'GIT' "Full commit with hooks..." '36'

Write-Step 'GIT' "Staging all changes..." '36'
try {
    git add -A 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git add failed" }
    Write-Success "Changes staged"
} catch {
    Write-Fail "Staging failed: $_"
    exit 1
}

Write-Step 'GIT' "Committing with hooks..." '36'
try {
    git commit -m $Message 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git commit failed (hooks may have failed)" }
    Write-Success "Committed"
} catch {
    Write-Fail "Commit failed: $_"
    exit 1
}

Write-Step 'GIT' "Pushing to origin..." '36'
try {
    git push origin HEAD 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git push failed" }
    Write-Success "Pushed to origin"
} catch {
    Write-Fail "Push failed: $_"
    exit 1
}

Write-Footer "Commit Complete" $startTime
