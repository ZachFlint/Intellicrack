#Requires -Version 7
<#
.SYNOPSIS
    Scans Hexbench for the dependencies it actually has, and upgrades them.

.DESCRIPTION
    Derives the dependency list by reading the package rather than by keeping
    one: hexbench.dependencies walks every module and the build description,
    resolves the imports to distributions, and reports which of them the
    environment manifest declares.

    Each declared distribution is then upgraded and its version reported
    before and after, so the recipe is useful on its own and not only as a
    step after a whole-environment upgrade.

    A distribution that is neither declared in the manifest nor built from
    this repository is a gap: the package imports something a fresh install
    would not get. That fails the script rather than being printed and
    forgotten.

    This is a PowerShell script rather than a Python one to match gate.ps1, so
    that no module inside the package needs to import subprocess.

.PARAMETER DryRun
    Report what would be upgraded without upgrading anything. The scan and the
    manifest-gap check still run in full, so this verifies the whole path
    without rewriting pyproject.toml or the lock file.

.EXAMPLE
    pwsh -File src/hexbench/update-deps.ps1

.EXAMPLE
    pwsh -File src/hexbench/update-deps.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$package = 'src/hexbench'
$manifest = 'pyproject.toml'

$usePixi = $null -ne (Get-Command 'pixi' -ErrorAction SilentlyContinue)

function Invoke-Tool {
    param([Parameter(Mandatory)][string[]] $CommandLine)

    $full = if ($usePixi) { @('pixi', 'run') + $CommandLine } else { $CommandLine }
    & $full[0] @($full[1..($full.Count - 1)])
}

Push-Location $repoRoot
try {
    Write-Host ''
    Write-Host '--- scanning hexbench for its dependencies ---' -ForegroundColor Cyan

    $raw = Invoke-Tool @('python', '-m', 'hexbench.dependencies', $package, $manifest) | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    the scan failed (exit $LASTEXITCODE)" -ForegroundColor Red
        Write-Host $raw
        exit 1
    }

    $report = $raw | ConvertFrom-Json
    $dependencies = @($report.dependencies)
    Write-Host "    imports outside the standard library: $($report.modules -join ', ')" -ForegroundColor DarkGray

    if ($dependencies.Count -eq 0) {
        Write-Host '    no third-party dependencies were found, which cannot be right' -ForegroundColor Red
        exit 1
    }

    $gaps = @($dependencies | Where-Object { -not $_.declared -and -not $_.built_here })
    $local = @($dependencies | Where-Object { -not $_.declared -and $_.built_here })
    $managed = @($dependencies | Where-Object { $_.declared })

    foreach ($entry in $local) {
        Write-Host "    $($entry.distribution) $($entry.installed) is built from this repository; run 'just build-hexcore' to update it" -ForegroundColor DarkGray
    }

    $results = [System.Collections.Generic.List[psobject]]::new()
    foreach ($entry in $managed) {
        Write-Host ''
        if ($DryRun) {
            Write-Host "--- would run: pixi upgrade $($entry.distribution) ---" -ForegroundColor Yellow
            $results.Add([pscustomobject]@{
                    Distribution = $entry.distribution
                    Before       = $entry.installed
                    After        = 'not attempted'
                    ExitCode     = 0
                })
            continue
        }

        Write-Host "--- pixi upgrade $($entry.distribution) ---" -ForegroundColor Cyan
        Invoke-Tool @('pixi', 'upgrade', $entry.distribution)
        $upgradeCode = $LASTEXITCODE

        $after = (Invoke-Tool @('python', '-c', "from importlib.metadata import version; print(version('$($entry.distribution)'))") | Out-String).Trim()
        $results.Add([pscustomobject]@{
                Distribution = $entry.distribution
                Before       = $entry.installed
                After        = if ($after) { $after } else { 'unknown' }
                ExitCode     = $upgradeCode
            })
    }

    Write-Host ''
    Write-Host '=== hexbench dependencies ===' -ForegroundColor Cyan
    $results | Format-Table -AutoSize | Out-String | Write-Host

    $failed = @($results | Where-Object { $_.ExitCode -ne 0 })
    if ($failed.Count -gt 0) {
        Write-Host "$($failed.Count) upgrade(s) failed: $($failed.Distribution -join ', ')" -ForegroundColor Red
        exit 1
    }

    if ($gaps.Count -gt 0) {
        Write-Host 'these are imported but neither declared in pyproject.toml nor built here:' -ForegroundColor Red
        foreach ($gap in $gaps) {
            Write-Host "    $($gap.distribution) (imported as $($gap.imported_as -join ', '))" -ForegroundColor Red
        }
        Write-Host 'a fresh install would not get them; declare them under [tool.pixi] pypi-dependencies' -ForegroundColor Red
        exit 1
    }

    Write-Host 'hexbench dependencies are declared and up to date' -ForegroundColor Green
}
finally {
    Pop-Location
}
