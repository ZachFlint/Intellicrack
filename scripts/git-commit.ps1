param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Commit"

Write-Step 'GIT' "Running NUL cleanup..." '32'
try {
    python scripts/clean_nul.py 2>&1 | Out-Null
    Write-Success "NUL cleanup complete"
} catch {
    Write-Success "NUL cleanup skipped"
}

Write-Step 'GIT' "Generating structure files..." '32'
try {
    Invoke-Expression "$Pixi python scripts/generate_tree.py 2>&1" | Out-Null
    Write-Success "Structure generated"
} catch {
    Write-Success "Structure generation skipped"
}

Write-Step 'GIT' "Generating knowledge map..." '32'
try {
    Invoke-Expression "$Pixi python scripts/knowledge-graph/visualize_architecture.py --layout hierarchical 2>&1" | Out-Null
    Write-Success "Knowledge map generated"
} catch {
    Write-Success "Knowledge map skipped"
}

Write-Step 'GIT' "Generating requirements.txt..." '32'
try {
    Invoke-Expression "$Pixi python scripts/generate_requirements.py 2>&1" | Out-Null
    Write-Success "Requirements generated"
} catch {
    Write-Success "Requirements generation skipped"
}

Write-Step 'GIT' "Staging changes..." '32'
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
try {
    git add -A 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git add failed" }
    Write-Success "Changes staged"
} catch {
    Write-Fail "Staging failed: $_"
    exit 1
}

$commitMsg = "WIP: $timestamp"
Write-Step 'GIT' "Generating commit message..." '32'
try {
    $stat = (git diff --cached --stat 2>&1) | Out-String
    $diffBody = (git diff --cached -- 'src/' 'tests/' 'scripts/' 'pyproject.toml' 'justfile' 2>&1) | Out-String
    $diffInput = "FILES CHANGED:`n$stat`nDIFF:`n$diffBody"
    $raw = Invoke-Expression "`$diffInput | $Pixi python scripts/generate_commit_message.py"
    $geminiExit = $LASTEXITCODE
    $genMsg = if ($raw) { ($raw | Out-String).Trim() } else { '' }
    if ($geminiExit -eq 0 -and $genMsg.Length -gt 5) {
        $commitMsg = $genMsg
        Write-Success "Message: $($commitMsg.Split("`n")[0])"
    } else {
        Write-Fail "Gemini failed (exit=$geminiExit, output=$($genMsg.Length) chars)"
        Write-Step 'GIT' "Using fallback: $commitMsg" '32'
    }
} catch {
    Write-Fail "Gemini exception: $($_.Exception.Message)"
    Write-Step 'GIT' "Using fallback: $commitMsg" '32'
}

Write-Step 'GIT' "Regenerating CHANGELOG.md (including pending commit)..." '32'
try {
    & "$PSScriptRoot/update-changelog.ps1" -Pixi "$Pixi" -Message "$commitMsg"
    if ($LASTEXITCODE -ne 0) { throw "update-changelog.ps1 failed (exit=$LASTEXITCODE)" }
    git add CHANGELOG.md 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git add CHANGELOG.md failed" }
    Write-Success "CHANGELOG.md staged"
} catch {
    Write-Fail "Changelog step failed: $_"
    Write-Step 'GIT' "Proceeding with commit without changelog update" '33'
}

Write-Step 'GIT' "Committing and pushing..." '32'
try {
    git commit --no-verify -m $commitMsg 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git commit failed" }
    Write-Success "Committed"
} catch {
    Write-Fail "Commit failed: $_"
    exit 1
}

try {
    $pushArgs = "git push --no-verify origin HEAD $Flags"
    Invoke-Expression $pushArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git push failed" }
    Write-Success "Pushed to origin"
} catch {
    Write-Fail "Push failed: $_"
    exit 1
}

Write-Footer "Commit Complete" $startTime
