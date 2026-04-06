$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

Write-Step 'GIT' "Checking gh CLI..."
try {
    $ghVersion = gh --version 2>&1 | Select-Object -First 1
    if ($LASTEXITCODE -ne 0) { throw "gh CLI not found" }
} catch {
    Write-Fail "gh CLI not installed: $_"
    exit 1
}

Write-Step 'GIT' "Watching GitHub Actions..."
gh run watch
