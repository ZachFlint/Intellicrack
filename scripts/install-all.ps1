$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$totalSteps = 8
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

$script:currentStep++
Write-Host "${e}[36m[$script:currentStep/$totalSteps]${e}[0m Fixing pixi SSL cert directory..."
try {
    & just fix-pixi-ssl
    if ($LASTEXITCODE -ne 0) { throw "fix-pixi-ssl failed with exit code $LASTEXITCODE" }
    Write-Success "SSL cert directory populated"
} catch {
    Write-Fail "SSL cert fix failed: $_"
    exit 1
}

$subSteps = @(
    @{ Step = 4; Name = 'Ghidra';  Recipe = 'install-ghidra' },
    @{ Step = 5; Name = 'radare2'; Recipe = 'install-radare2' },
    @{ Step = 6; Name = 'QEMU';    Recipe = 'install-qemu' },
    @{ Step = 7; Name = 'x64dbg';  Recipe = 'install-x64dbg' },
    @{ Step = 8; Name = 'Cutter';  Recipe = 'install-cutter' }
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
