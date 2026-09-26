param(
    [string]$Flags = '',
    [int]$MaxRebases = 2
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$outOfDatePattern = '^!\t[^\t]*\t\[rejected\] \((fetch first|non-fast-forward)\)'

function Invoke-GitPush {
    param([string]$PushFlags)
    $ErrorActionPreference = 'Continue'
    $extra = @($PushFlags -split '\s+' | Where-Object { $_ })
    $lines = @(git push --porcelain --no-verify origin HEAD @extra 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
    $lines | ForEach-Object { Write-Host "  $_" }
    $rejected = @($lines | Where-Object { $_ -match '^!\t' })
    $outOfDate = $rejected.Count -gt 0 -and @($rejected | Where-Object { $_ -notmatch $outOfDatePattern }).Count -eq 0
    return [pscustomobject]@{ ExitCode = $exitCode; OutOfDate = $outOfDate }
}

function Invoke-RebaseOntoRemote {
    param([string]$Branch)
    $ErrorActionPreference = 'Continue'

    $dirty = git status --porcelain 2>&1
    if ($dirty) {
        Write-Fail "Working tree has uncommitted changes; not rebasing automatically"
        return $false
    }
    if (Test-GitRebaseInProgress) {
        Write-Fail "A rebase is already in progress; not rebasing automatically"
        return $false
    }

    git fetch origin $Branch 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Fetch of origin/$Branch failed"
        return $false
    }

    $before = (git rev-parse HEAD).Trim()
    git rebase --no-autostash "origin/$Branch" 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -eq 0) { return $true }

    $conflicts = @(git diff --name-only --diff-filter=U 2>$null)
    $aborted = Stop-GitRebase
    $after = (git rev-parse HEAD).Trim()
    if ($conflicts.Count -gt 0) {
        Write-Fail "Rebase conflicts in: $($conflicts -join ', ')"
    } else {
        Write-Fail "Rebase onto origin/$Branch failed"
    }
    if ($aborted -and $after -eq $before) {
        Write-Step 'GIT' "Rebase aborted; your commit is unchanged. Resolve with: just git-rebase" '33'
    } else {
        Write-Fail "Could not restore the pre-rebase state; run 'git status' before doing anything else"
    }
    return $false
}

$branch = git symbolic-ref --quiet --short HEAD 2>$null
$rebases = 0
while ($true) {
    $result = Invoke-GitPush -PushFlags $Flags
    if ($result.ExitCode -eq 0) {
        Write-Success "Pushed to origin"
        exit 0
    }
    if (-not $result.OutOfDate -or -not $branch) {
        Write-Fail "Push failed"
        exit 1
    }
    if ($rebases -ge $MaxRebases) {
        Write-Fail "origin/$branch kept moving; still behind after $rebases rebase(s)"
        exit 1
    }
    $rebases++
    Write-Step 'GIT' "origin/$branch has new commits; rebasing onto it (attempt $rebases of $MaxRebases)..." '33'
    if (-not (Invoke-RebaseOntoRemote -Branch $branch)) { exit 1 }
    Write-Success "Rebased onto origin/$branch; retrying push"
}
