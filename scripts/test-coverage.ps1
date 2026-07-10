param(
    [string]$Pixi = 'pixi run',
    [switch]$DryRun
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$runRust = $false
$runPython = $false
$passthrough = [System.Collections.Generic.List[string]]::new()

foreach ($token in $args) {
    if ($token -eq '--rust') {
        $runRust = $true
    } elseif ($token -eq '--python') {
        $runPython = $true
    } else {
        $passthrough.Add([string]$token)
    }
}

$explicit = $runRust -or $runPython
if (-not $explicit) {
    $runRust = $true
    $runPython = $true
}

$extra = ($passthrough -join ' ').Trim()
$targetCount = ([int]$runRust) + ([int]$runPython)

if ($extra -and $targetCount -gt 1) {
    [Console]::Error.WriteLine(
        "test-coverage: extra flags ('$extra') require exactly one target; " +
        'pass them with --python or --rust.')
    exit 2
}

if ($extra) {
    $rustCommand = "$Pixi cargo llvm-cov $extra"
} else {
    $rustCommand = "$Pixi cargo llvm-cov nextest --no-fail-fast"
}
$pythonCommand = "$Pixi python -m scripts.sandbox.docker_sandbox coverage $extra".Trim()

$exitCode = 0

if ($runRust) {
    if ($DryRun) {
        Write-Host "DRYRUN RUST $rustCommand"
    } else {
        Write-Host '[test-coverage] Rust hexcore (cargo llvm-cov)...' -ForegroundColor Cyan
        & (Join-Path $scriptDir 'run-lint-tool.ps1') `
            -ToolName llvm-cov -DisplayName LlvmCov `
            -Command "$Pixi cargo llvm-cov nextest $extra --no-fail-fast" `
            -TextMode -Pixi $Pixi -WorkDir 'src/intellicrack-hexcore' `
            -ReportFormats 'txt', 'json', 'xml', 'csv', 'sarif', 'sql' `
            -Flags $extra -PassthruExe "$Pixi cargo llvm-cov"
        if ($LASTEXITCODE -ne 0) { $exitCode = $LASTEXITCODE }
    }
}

if ($runPython) {
    if ($DryRun) {
        Write-Host "DRYRUN PYTHON $pythonCommand"
    } else {
        Write-Host '[test-coverage] Python suite (docker sandbox, coverage gate)...' -ForegroundColor Cyan
        Invoke-Expression $pythonCommand
        if ($LASTEXITCODE -ne 0 -and $exitCode -eq 0) { $exitCode = $LASTEXITCODE }
    }
}

exit $exitCode
