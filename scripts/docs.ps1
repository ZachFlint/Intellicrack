#Requires -Version 7.0
<#
.SYNOPSIS
    Unified Intellicrack documentation dispatcher.

.DESCRIPTION
    Single entry point for all documentation actions. Replaces the previous
    docs-build / docs-clean / docs-apidoc / docs-linkcheck / docs-pdf /
    docs-open / docs-rebuild recipes. Chooses behavior by the -Action
    parameter, forwards any remaining flags to the underlying tool.

.PARAMETER Action
    One of: build, clean, apidoc, linkcheck, pdf, open, rebuild. Defaults to
    'build' when omitted.

.PARAMETER Pixi
    Pixi invocation prefix (for example 'pixi run'). Used to call
    sphinx-build, sphinx-apidoc, etc. inside the project environment.

.PARAMETER Src
    Source directory for sphinx-apidoc (typically 'src/intellicrack').

.PARAMETER Flags
    Extra flags forwarded to the underlying tool. Passed as a single string
    because justfile variadic args arrive that way.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('build', 'clean', 'apidoc', 'linkcheck', 'pdf', 'open', 'rebuild')]
    [string]$Action = 'build',

    [string]$Pixi = 'pixi run',
    [string]$Src = 'src/intellicrack',
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
$esc = [char]27

$script:Pixi = $Pixi
$script:Src = $Src
$script:Flags = $Flags

function Write-Step {
    param([string]$Message)
    Write-Information -MessageData "$esc[36m[DOCS]$esc[0m $Message"
}

function Write-Success {
    param([string]$Message)
    Write-Information -MessageData "  $esc[32m[OK]$esc[0m $Message"
}

function Write-Fail {
    param([string]$Message)
    Write-Information -MessageData "  $esc[31m[FAIL]$esc[0m $Message"
}

function Invoke-PixiTool {
    param(
        [Parameter(Mandatory = $true)][string]$Tool,
        [string]$Arguments = ''
    )
    $cmdLine = "$script:Pixi $Tool $Arguments".Trim()
    Write-Step "Running: $cmdLine"
    $invocation = [scriptblock]::Create($cmdLine)
    & $invocation 2>&1 | ForEach-Object { Write-Information -MessageData "  $_" }
    return $LASTEXITCODE
}

function Invoke-Clean {
    Write-Step 'Cleaning documentation build...'
    if (Test-Path 'docs\build') {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue docs\build\*
        Write-Success 'Documentation build cleaned'
    }
    else {
        Write-Success 'Nothing to clean'
    }
}

function Invoke-Apidoc {
    Write-Step 'Generating API documentation...'
    $argLine = "$script:Flags -f -o docs/source $script:Src".Trim()
    $code = Invoke-PixiTool -Tool 'sphinx-apidoc' -Arguments $argLine
    if ($code -ne 0) {
        Write-Fail "sphinx-apidoc failed (exit $code)"
        exit $code
    }
    Write-Success 'API documentation generated'
}

function Invoke-Build {
    $scriptPath = Join-Path $PSScriptRoot 'docs-build.ps1'
    if (-not (Test-Path $scriptPath)) {
        Write-Fail "docs-build.ps1 not found at $scriptPath"
        exit 1
    }
    & $scriptPath -Pixi $script:Pixi -Flags $script:Flags
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Invoke-Linkcheck {
    $scriptPath = Join-Path $PSScriptRoot 'docs-linkcheck.ps1'
    if (-not (Test-Path $scriptPath)) {
        Write-Fail "docs-linkcheck.ps1 not found at $scriptPath"
        exit 1
    }
    & $scriptPath -Pixi $script:Pixi -Flags $script:Flags
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Invoke-Pdf {
    $scriptPath = Join-Path $PSScriptRoot 'docs-pdf.ps1'
    if (-not (Test-Path $scriptPath)) {
        Write-Fail "docs-pdf.ps1 not found at $scriptPath"
        exit 1
    }
    & $scriptPath -Pixi $script:Pixi -Flags $script:Flags
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Invoke-Open {
    $docPath = 'docs\build\html\index.html'
    if (-not (Test-Path $docPath)) {
        Write-Fail "Documentation not found. Run 'just docs build' first."
        exit 1
    }
    Write-Step 'Opening documentation in browser...'
    Start-Process $docPath
    Write-Success 'Opened in browser'
}

function Invoke-Rebuild {
    Invoke-Clean
    Invoke-Apidoc
    Invoke-Build
    Write-Information -MessageData "`n$esc[1;32m=== Documentation Rebuild Complete ===$esc[0m"
    Write-Information -MessageData "View at: docs/build/html/index.html`n"
}

switch ($Action) {
    'build'     { Invoke-Build }
    'clean'     { Invoke-Clean }
    'apidoc'    { Invoke-Apidoc }
    'linkcheck' { Invoke-Linkcheck }
    'pdf'       { Invoke-Pdf }
    'open'      { Invoke-Open }
    'rebuild'   { Invoke-Rebuild }
    default {
        Write-Fail "Unknown action: $Action"
        exit 2
    }
}
