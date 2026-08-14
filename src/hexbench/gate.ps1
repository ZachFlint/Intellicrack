#Requires -Version 7
<#
.SYNOPSIS
    Runs every quality gate hexbench must pass, scoped to hexbench alone.

.DESCRIPTION
    Locates the repository root relative to this script, then runs the
    formatter check, the linter, the type checker, both docstring checkers and
    the unit tests against src/hexbench only. Each gate is reported
    individually and the script exits non-zero if any of them failed.

    This is a PowerShell script rather than a Python one precisely so it can
    shell out to these tools without any Python module in the package needing
    to import subprocess.

.EXAMPLE
    pwsh -File src/hexbench/gate.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$target = 'src/hexbench'
$testRoot = Join-Path $PSScriptRoot 'tests'

$usePixi = $null -ne (Get-Command 'pixi' -ErrorAction SilentlyContinue)
$results = [System.Collections.Generic.List[psobject]]::new()

function Invoke-Gate {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string[]] $CommandLine
    )

    $full = if ($usePixi) { @('pixi', 'run') + $CommandLine } else { $CommandLine }
    $exe = $full[0]
    $rest = if ($full.Count -gt 1) { $full[1..($full.Count - 1)] } else { @() }

    Write-Host ''
    Write-Host "--- $Name ---" -ForegroundColor Cyan
    Write-Host "    $($full -join ' ')" -ForegroundColor DarkGray

    $code = 0
    try {
        & $exe @rest
        $code = $LASTEXITCODE
    }
    catch {
        Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
        $code = 1
    }

    $status = if ($code -eq 0) { 'PASS' } else { 'FAIL' }
    Write-Host "    $status ($Name, exit $code)" -ForegroundColor $(if ($code -eq 0) { 'Green' } else { 'Red' })
    $results.Add([pscustomobject]@{ Gate = $Name; Status = $status; ExitCode = $code })
}

Push-Location $repoRoot
try {
    Invoke-Gate -Name 'ruff format' -CommandLine @('ruff', 'format', '--check', $target)
    Invoke-Gate -Name 'ruff check' -CommandLine @('ruff', 'check', $target, '--output-format=concise')
    Invoke-Gate -Name 'basedpyright' -CommandLine @('basedpyright', $target)
    Invoke-Gate -Name 'pydoclint' -CommandLine @('pydoclint', $target)
    Invoke-Gate -Name 'pydocstyle' -CommandLine @('pydocstyle', $target)

    $mjsFiles = @()
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        $mjsFiles = @(Get-ChildItem -LiteralPath $testRoot -Filter '*.test.mjs' -File -ErrorAction SilentlyContinue | Sort-Object Name)
    }

    if ($mjsFiles.Count -eq 0) {
        Write-Host ''
        Write-Host '--- mjs tests ---' -ForegroundColor Cyan
        Write-Host "    FAIL (mjs tests, no *.test.mjs files in $testRoot)" -ForegroundColor Red
        Write-Host '    A gate cannot pass by having nothing to run.' -ForegroundColor Red
        $results.Add([pscustomobject]@{ Gate = 'mjs tests'; Status = 'FAIL'; ExitCode = 1 })
    }
    else {
        foreach ($mjsFile in $mjsFiles) {
            Invoke-Gate -Name "mjs: $($mjsFile.Name)" -CommandLine @(
                'node',
                '--disable-warning=MODULE_TYPELESS_PACKAGE_JSON',
                $mjsFile.FullName
            )
        }
    }

    $missingReason = $null
    if (-not (Test-Path -LiteralPath $testRoot -PathType Container)) {
        $missingReason = "no test directory at $testRoot"
    }
    else {
        $modules = @(Get-ChildItem -LiteralPath $testRoot -Filter 'test_*.py' -File -ErrorAction SilentlyContinue)
        if ($modules.Count -eq 0) {
            $missingReason = "no test_*.py modules in $testRoot"
        }
    }

    if ($null -eq $missingReason) {
        Invoke-Gate -Name 'unittest' -CommandLine @('python', '-m', 'unittest', 'discover', '-s', "$target/tests", '-t', 'src')
    }
    else {
        Write-Host ''
        Write-Host '--- unittest ---' -ForegroundColor Cyan
        Write-Host "    FAIL (unittest, $missingReason)" -ForegroundColor Red
        Write-Host '    A gate cannot pass by having nothing to run.' -ForegroundColor Red
        $results.Add([pscustomobject]@{ Gate = 'unittest'; Status = 'FAIL'; ExitCode = 1 })
    }
}
finally {
    Pop-Location
}

Write-Host ''
Write-Host '=== hexbench quality gates ===' -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host

$failed = @($results | Where-Object { $_.Status -eq 'FAIL' })
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) gate(s) failed: $($failed.Gate -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host 'all gates clean' -ForegroundColor Green
exit 0
