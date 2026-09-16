#Requires -Version 7
[CmdletBinding()]
param(
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
# docker/npx/DockerCli.exe exit codes are checked explicitly below (MegaLinter
# itself is expected to exit non-zero whenever it finds real findings) -- the
# PowerShell 7.4+ default would turn that into a terminating error before the
# check runs.
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest
. "$PSScriptRoot/common.ps1"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$DockerCli = 'C:\Program Files\Docker\Docker\DockerCli.exe'

function Split-CommandArgument {
    <#
    .SYNOPSIS
        Split a recipe-supplied argument string into an argument array.
    .DESCRIPTION
        just hands flags through as a single string; an empty or whitespace-only
        value must become an empty array rather than one empty argument, which
        npx would reject.
    #>
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @($Value -split '\s+' | Where-Object { $_ })
}

function Test-ProcessRunning {
    <#
    .SYNOPSIS
        Check whether any process matching one of the given name patterns is running.
    #>
    param([Parameter(Mandatory)][string[]]$NamePatterns)
    foreach ($pattern in $NamePatterns) {
        if (Get-Process -Name $pattern -ErrorAction SilentlyContinue) { return $true }
    }
    return $false
}

function Get-DockerEngine {
    <#
    .SYNOPSIS
        Return the running Docker Desktop engine's OSType ('linux' or 'windows'),
        or $null if the Docker daemon is unreachable.
    #>
    $result = & docker info --format '{{.OSType}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $result) { return $null }
    return $result.Trim()
}

function Wait-DockerEngine {
    <#
    .SYNOPSIS
        Poll until Docker Desktop reports the requested engine, or time out.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('linux', 'windows')][string]$Target,
        [int]$TimeoutSeconds = 120
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if ((Get-DockerEngine) -eq $Target) { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return $false
}

Write-Banner 'MegaLinter'
$started = Get-Date

if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
    Write-Fail 'npx is not on PATH; install Node.js'
    exit 1
}

Write-Step 'MEGALINT' 'Checking Docker Desktop is running...'
$originalEngine = Get-DockerEngine
if (-not $originalEngine) {
    Write-Fail 'Docker Desktop is not running (docker info failed). Start Docker Desktop and retry.'
    exit 1
}
Write-Success "Docker Desktop is running (engine: $originalEngine)"

# Interleaving a WHPX-backed VM (QEMU, Windows Sandbox) with a Docker Desktop
# engine switch has previously crashed this host outright -- both compete for
# the same Host Compute Service layer. Refuse to switch engines while one is up.
Write-Step 'MEGALINT' 'Checking for running QEMU / Windows Sandbox VMs...'
if (Test-ProcessRunning -NamePatterns @('qemu-system-*', 'WindowsSandbox*')) {
    Write-Fail 'A QEMU or Windows Sandbox VM is currently running. Switching the Docker engine while one is active has previously crashed this machine -- close it first, then retry.'
    exit 1
}
Write-Success 'No QEMU / Windows Sandbox VM detected'

if ($originalEngine -ne 'linux') {
    Write-Step 'MEGALINT' 'Switching Docker Desktop to Linux containers (MegaLinter images are Linux-only)...'
    & $DockerCli -SwitchLinuxEngine
    if (-not (Wait-DockerEngine -Target 'linux')) {
        Write-Fail 'Docker Desktop did not report the Linux engine within 120s; check its state manually'
        exit 1
    }
    Write-Success 'Docker Desktop is now running Linux containers'
} else {
    Write-Progress 'Docker Desktop is already running Linux containers'
}

$exitCode = 1
try {
    Write-Step 'MEGALINT' 'Running MegaLinter on src/ via mega-linter-runner (npx)...'
    $runnerArgv = @('--yes', 'mega-linter-runner@10', '--no-prompt', '--remove-container', '--path', '.') +
        (Split-CommandArgument -Value $Flags)
    & npx @runnerArgv
    $exitCode = $LASTEXITCODE
} finally {
    if ($originalEngine -eq 'windows') {
        Write-Step 'MEGALINT' 'Restoring Docker Desktop to Windows containers...'
        & $DockerCli -SwitchWindowsEngine
        if (Wait-DockerEngine -Target 'windows') {
            Write-Success 'Docker Desktop is back on Windows containers'
        } else {
            Write-Fail 'Docker Desktop did not report back to the Windows engine within 120s; check it manually'
        }
    }
}

Write-Footer 'MegaLinter' $started
if ($exitCode -eq 0) {
    Write-Success 'MegaLinter found no issues'
} else {
    Write-Progress "MegaLinter reported findings (exit $exitCode) -- see reports/megalinter/megalinter.log"
}
exit $exitCode
