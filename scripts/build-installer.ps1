#Requires -Version 7
[CmdletBinding()]
param(
    [string]$StageArgs = '',
    [string]$IsccArgs = ''
)

$ErrorActionPreference = 'Stop'
# Every native step below checks $LASTEXITCODE explicitly, and stage.ps1 forwards
# robocopy's bitmask exit codes (only >= 8 is a real failure). The PowerShell 7.4+
# default would turn a healthy non-zero exit into a terminating error before that
# check runs, so exit-code handling stays at each call site.
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest
. "$PSScriptRoot/common.ps1"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot 'logs\installer'
$LogPath = Join-Path $LogDir 'build.log'

# Matches the CSI escape sequences the Write-* helpers emit. The console keeps its
# colour (the sequences stay in the string handed to Write-Host); only the file copy
# is stripped, so the log stays readable in a plain text editor.
$AnsiPattern = "`e\[[0-9;]*[A-Za-z]"

function Write-LogLine {
    <#
    .SYNOPSIS
        Append one line to the build log with its ANSI colour codes removed.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)
    Add-Content -LiteralPath $script:LogPath -Value ($Line -replace $script:AnsiPattern, '') -Encoding utf8
}

function Write-Both {
    <#
    .SYNOPSIS
        Write a line to the console and to the build log.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)
    Write-Host $Line
    Write-LogLine -Line $Line
}

function Invoke-LoggedStep {
    <#
    .SYNOPSIS
        Run a native command, streaming its output to the console and the log.
    .DESCRIPTION
        stderr is merged into the output stream so a failing tool's diagnostics land
        in the log next to the step that produced them. A completion line carrying
        the exit code and wall-clock duration is written after the step so the log
        records each step's outcome uniformly -- greppable on both success and
        failure -- and the command's exit code is returned unchanged for the caller
        to check.
    #>
    param(
        [Parameter(Mandatory)][string]$What,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    Write-Both ''
    Write-Both "--- $What : $FilePath $($ArgumentList -join ' ') ---"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    & $FilePath @ArgumentList 2>&1 | ForEach-Object {
        $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.ToString() } else { [string]$_ }
        Write-Host $line
        Write-LogLine -Line $line
    }
    $code = $LASTEXITCODE
    $stopwatch.Stop()
    $seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
    Write-Both "--- $What : done in ${seconds}s (exit $code) ---"
    return $code
}

function Split-CommandArgument {
    <#
    .SYNOPSIS
        Split a recipe-supplied argument string into an argument array.
    .DESCRIPTION
        just hands flags through as a single string; an empty or whitespace-only
        value must become an empty array rather than one empty argument, which a
        native tool would reject.
    #>
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @($Value -split '\s+' | Where-Object { $_ })
}

if (-not (Test-Path -LiteralPath $LogDir)) {
    $null = New-Item -ItemType Directory -Path $LogDir -Force
}
# Single rolling log: each build replaces the previous one.
Set-Content -LiteralPath $LogPath -Value '' -Encoding utf8 -NoNewline

Write-Banner 'Build Installer'
$started = Get-Date
Write-Both "Intellicrack installer build"
Write-Both "started : $($started.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Both "repo    : $RepoRoot"
Write-Both "stage   : $(if ($StageArgs) { $StageArgs } else { '(full stage)' })"
Write-Both "iscc    : $(if ($IsccArgs) { $IsccArgs } else { '(no extra flags)' })"
Write-Both "log     : $LogPath"

$StageScript = Join-Path $RepoRoot 'packaging\stage.ps1'
if (-not (Test-Path -LiteralPath $StageScript)) {
    Write-Both 'packaging/stage.ps1 is missing, so the payload cannot be staged'
    exit 1
}
$Iss = Join-Path $RepoRoot 'packaging\intellicrack.iss'
if (-not (Test-Path -LiteralPath $Iss)) {
    Write-Both 'packaging/intellicrack.iss is missing, so Setup cannot be compiled'
    exit 1
}
$isccCommand = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $isccCommand) {
    Write-Both 'iscc is not on PATH; install Inno Setup 6.6.0 or newer'
    exit 1
}

$pwshPath = (Get-Process -Id $PID).Path
$stageArgv = @('-NoLogo', '-NonInteractive', '-File', $StageScript) + (Split-CommandArgument -Value $StageArgs)
$code = Invoke-LoggedStep -What 'Stage payload' -FilePath $pwshPath -ArgumentList $stageArgv
if ($code -ne 0) {
    Write-Both "stage.ps1 failed (exit $code); see $LogPath"
    exit $code
}

$isccArgv = @($Iss) + (Split-CommandArgument -Value $IsccArgs)
$code = Invoke-LoggedStep -What 'Compile Setup with Inno Setup' -FilePath $isccCommand.Source -ArgumentList $isccArgv
if ($code -ne 0) {
    Write-Both "iscc failed (exit $code); see $LogPath"
    exit $code
}

$SetupExe = Join-Path $RepoRoot 'packaging\Output\Intellicrack-Setup.exe'
if (-not (Test-Path -LiteralPath $SetupExe)) {
    Write-Both 'Inno Setup produced no Intellicrack-Setup.exe'
    exit 1
}

$elapsed = (Get-Date) - $started
$sizeMb = [math]::Round((Get-Item -LiteralPath $SetupExe).Length / 1MB, 1)
Write-Both ''
Write-Both "==> $SetupExe ($sizeMb MB)"
Write-Both "elapsed : $([math]::Round($elapsed.TotalSeconds, 1))s"
Write-Both "log     : $LogPath"
exit 0
