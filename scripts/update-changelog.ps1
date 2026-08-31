param(
    [string]$Pixi = 'pixi run',
    [string]$Message = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Changelog"

$pixiParts = @($Pixi -split '\s+') | Where-Object { $_ }
if ($pixiParts.Count -eq 0) {
    Write-Fail "Pixi command is empty"
    exit 1
}
$pixiCmd = $pixiParts[0]
$pixiArgs = @()
if ($pixiParts.Count -gt 1) {
    $pixiArgs = $pixiParts[1..($pixiParts.Count - 1)]
}

Write-Step 'CL' "Regenerating CHANGELOG.md from git history..." '32'
try {
    $cliffArgs = $pixiArgs + @('git-cliff', '--output', 'CHANGELOG.md')
    if ($Message -and $Message.Trim().Length -gt 0) {
        $subject = ($Message -split "`n", 2)[0].Trim()
        Write-Step 'CL' "Including pending commit: $subject" '32'
        $cliffArgs += @('--with-commit', $Message)
    }
    $origRustLog = $env:RUST_LOG
    $env:RUST_LOG = 'error'
    try {
        & $pixiCmd @cliffArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
    } finally {
        $env:RUST_LOG = $origRustLog
    }
    if ($LASTEXITCODE -ne 0) { throw "git-cliff failed (exit=$LASTEXITCODE)" }
    Write-Success "CHANGELOG.md regenerated"
} catch {
    Write-Fail "Changelog generation failed: $_"
    exit 1
}

Write-Footer "Changelog Complete" $startTime
