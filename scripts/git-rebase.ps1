param(
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Git Rebase"

Write-Step 'REBASE' "Fetching origin..." '33'
git fetch origin 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) { Write-Fail "Fetch failed"; exit 1 }
Write-Success "Fetched origin"

$local = (git rev-parse HEAD 2>&1).Trim()
$remote = (git rev-parse origin/main 2>&1).Trim()

if ($local -eq $remote) {
    Write-Success "Already up to date"
    Write-Footer "Rebase Complete" $startTime
    exit 0
}

$behind = (git rev-list --count HEAD..origin/main 2>&1).Trim()
$ahead = (git rev-list --count origin/main..HEAD 2>&1).Trim()
Write-Step 'REBASE' "Local is $ahead ahead, $behind behind origin/main" '33'

$hasChanges = $false
$status = git status --porcelain 2>&1
if ($status) {
    $hasChanges = $true
    Write-Step 'REBASE' "Stashing uncommitted changes..." '33'
    git stash push -m "git-rebase: auto-stash before rebase" 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { Write-Fail "Stash failed"; exit 1 }
    Write-Success "Changes stashed"
} else {
    Write-Success "Working tree clean, no stash needed"
}

Write-Step 'REBASE' "Rebasing onto origin/main..." '33'
$rebaseCmd = "git pull --rebase origin main $Flags"
Invoke-Expression $rebaseCmd 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Rebase failed"
    if ($hasChanges) {
        Write-Step 'REBASE' "Aborting rebase and restoring stash..." '33'
        git rebase --abort 2>&1 | ForEach-Object { Write-Host "  $_" }
        git stash pop 2>&1 | ForEach-Object { Write-Host "  $_" }
    }
    exit 1
}
Write-Success "Rebased $ahead local commit(s) onto $behind new remote commit(s)"

if ($hasChanges) {
    Write-Step 'REBASE' "Restoring stashed changes..." '33'
    git stash pop 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Stash pop had conflicts - resolve manually with: git stash show -p | git apply"
        exit 1
    }
    Write-Success "Stash restored"
}

Write-Footer "Rebase Complete" $startTime
