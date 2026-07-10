param(
    [string]$Pixi = 'pixi run'
)

<#
.SYNOPSIS
    Works around a packaging defect in the win-64 conda-forge cppcheck
    2.21.0 build: the binary is compiled with an absolute FILESDIR from the
    CI build machine (e.g. "D:/bld/bld/rattler-build_cppcheck_.../share/
    Cppcheck") baked in for locating cfg/std.cfg, which never exists on an
    end user's machine, so cppcheck refuses to run ("Failed to load library
    configuration file 'std.cfg'"). cppcheck also probes an executable-
    relative "<exe_dir>/cfg" directory before giving up, so this script
    copies the real cfg files (installed under
    "<env>/share/Cppcheck/cfg" by the conda package) next to cppcheck.exe
    once. Idempotent and safe to run before every cppcheck invocation; a
    fresh "pixi install" wipes and recreates the env, so this must be
    re-applied rather than assumed permanent.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$cppcheckPath = (Invoke-Expression "$Pixi python -c `"import shutil; print(shutil.which('cppcheck') or '')`"").Trim()
if (!$cppcheckPath -or !(Test-Path $cppcheckPath)) {
    Write-Fail "cppcheck executable not found via '$Pixi python -c ...shutil.which'"
    exit 1
}

$exeDir = Split-Path $cppcheckPath -Parent
$cfgDst = Join-Path $exeDir "cfg"
if ((Test-Path (Join-Path $cfgDst "std.cfg"))) {
    exit 0
}

$envRoot = Split-Path (Split-Path $exeDir -Parent) -Parent
$cfgSrc = Join-Path $envRoot "share/Cppcheck/cfg"
if (!(Test-Path (Join-Path $cfgSrc "std.cfg"))) {
    Write-Fail "cppcheck cfg source not found at $cfgSrc (conda package layout may have changed)"
    exit 1
}

New-Item -ItemType Directory -Path $cfgDst -Force | Out-Null
Copy-Item -Path (Join-Path $cfgSrc "*") -Destination $cfgDst -Recurse -Force
Write-Success "Installed cppcheck cfg files to $cfgDst"
