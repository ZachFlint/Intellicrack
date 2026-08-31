param(
    [string]$Pixi = 'pixi run'
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$tools = @(
    'cargo-deny',
    'cargo-nextest',
    'cargo-llvm-cov',
    'cargo-machete',
    'cargo-mutants',
    'rust-code-analysis-cli',
    'typos-cli'
)

$totalSteps = $tools.Count
$script:currentStep = 0

Write-Banner "Installing Rust Dev Tools"

$startTime = Get-Date

foreach ($tool in $tools) {
    $script:currentStep++
    $e = [char]27
    Write-Host "${e}[36m[$script:currentStep/$totalSteps]${e}[0m Installing $tool..."
    try {
        Invoke-Expression "$Pixi cargo install $tool 2>&1" | Out-Null
        Write-Success "$tool installed"
    } catch {
        Write-Fail "$tool installation failed: $_"
    }
}

Write-Footer "Rust Tools Install Complete" $startTime
