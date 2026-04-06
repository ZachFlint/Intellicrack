$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$totalSteps = 7
$script:currentStep = 0

Write-Banner "Intellicrack Installation"

$startTime = Get-Date

$script:currentStep++
$e = [char]27
Write-Host "${e}[36m[$script:currentStep/$totalSteps]${e}[0m Preparing environment..."
if (Test-Path "pixi.lock") {
    Remove-Item -Force "pixi.lock" -ErrorAction Stop
    Write-Success "Removed existing pixi.lock"
} else {
    Write-Success "Environment clean"
}

$script:currentStep++
Write-Host "${e}[36m[$script:currentStep/$totalSteps]${e}[0m Installing dependencies with pixi..."
try {
    pixi install
    if ($LASTEXITCODE -ne 0) { throw "pixi install failed with exit code $LASTEXITCODE" }
    Write-Success "Pixi dependencies installed"
} catch {
    Write-Fail "Pixi installation failed: $_"
    exit 1
}

$subSteps = @(
    @{ Step = 3; Name = 'Ghidra';  Recipe = 'install-ghidra' },
    @{ Step = 4; Name = 'radare2'; Recipe = 'install-radare2' },
    @{ Step = 5; Name = 'QEMU';    Recipe = 'install-qemu' },
    @{ Step = 6; Name = 'x64dbg';  Recipe = 'install-x64dbg' },
    @{ Step = 7; Name = 'Cutter';  Recipe = 'install-cutter' }
)

foreach ($sub in $subSteps) {
    $script:currentStep++
    Write-Host "${e}[36m[$script:currentStep/$totalSteps]${e}[0m Installing $($sub.Name)..."
    try {
        & just $sub.Recipe
        if ($LASTEXITCODE -ne 0) { throw "$($sub.Recipe) failed with exit code $LASTEXITCODE" }
        Write-Success "$($sub.Name) ready"
    } catch {
        Write-Fail "$($sub.Name) installation failed: $_"
        exit 1
    }
}

Write-Footer "Installation Complete" $startTime
