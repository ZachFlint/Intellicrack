#Requires -Version 7.0
<#
.SYNOPSIS
    Intellicrack Docker sandbox entrypoint.

.DESCRIPTION
    Runs inside the Windows process-isolated container. Reads the serialized
    run specification produced by the host driver, invokes pytest through the
    pre-built pixi environment, then harvests JUnit XML and coverage XML into
    a structured summary.json alongside the existing artifacts.

.PARAMETER TestType
    One of: interactive, interactive-rw, unit, all, coverage, integration,
    e2e, smoke, parallel, failed, verbose, bench, module, module-cov,
    registry, custom. Defaults to the value of the TEST_TYPE environment
    variable, which is set by the host driver.

.PARAMETER Module
    Module argument for module / module-cov runs. Defaults to TEST_MODULE.

.PARAMETER ExtraArgs
    Extra pytest arguments forwarded to the container. Defaults to empty.
#>
[CmdletBinding()]
param(
    [string]$TestType = $env:TEST_TYPE,
    [string]$Module = $env:TEST_MODULE,
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$WorkspaceRoot = 'C:\app'
$ReportsRoot = Join-Path $WorkspaceRoot 'reports\tests'
$SpecPath = if ($env:SANDBOX_SPEC_PATH) { $env:SANDBOX_SPEC_PATH } else { Join-Path $ReportsRoot '_run_spec.json' }
$PixiPython = Join-Path $WorkspaceRoot '.pixi\envs\default\python.exe'
$PixiExe = 'pixi.exe'
$ContainerEventsLog = Join-Path $ReportsRoot '_container_events.jsonl'
$CacheRoot = 'C:\cache'

if (-not (Test-Path $CacheRoot)) {
    New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $CacheRoot 'pytest') -Force | Out-Null
}
if (-not (Test-Path $ReportsRoot)) {
    New-Item -ItemType Directory -Path $ReportsRoot -Force | Out-Null
}

function Write-SandboxLog {
    param(
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Event,
        [hashtable]$Context
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $payload = @{ timestamp = $timestamp; level = $Level; event = $Event; logger = 'sandbox.container' }
    if ($Context) {
        foreach ($key in $Context.Keys) {
            $payload[$key] = $Context[$key]
        }
    }
    $line = ($payload | ConvertTo-Json -Compress -Depth 6)
    [Console]::Error.WriteLine($line)
    if (Test-Path (Split-Path $ContainerEventsLog -Parent)) {
        Add-Content -Path $ContainerEventsLog -Value $line -Encoding utf8
    }
}

function Assert-PixiEnvironment {
    if (-not (Test-Path $PixiPython)) {
        Write-SandboxLog -Level 'error' -Event 'pixi_env_missing' -Context @{ path = $PixiPython }
        throw "pixi environment not found at $PixiPython; the container image is not fully built"
    }
}

function Get-Timestamp {
    if ($env:TEST_TIMESTAMP) { return $env:TEST_TIMESTAMP }
    return (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
}

function Initialize-ReportLayout {
    param([string]$Timestamp, [string]$Type)
    if (-not (Test-Path $ReportsRoot)) {
        New-Item -ItemType Directory -Path $ReportsRoot -Force | Out-Null
    }
    $suffix = "${Type}_${Timestamp}"
    return [pscustomobject]@{
        Suffix = $suffix
        Junit = Join-Path $ReportsRoot "junit_${suffix}.xml"
        CoverageXml = Join-Path $ReportsRoot "coverage_${suffix}.xml"
        CoverageHtml = Join-Path $ReportsRoot "coverage-html_${suffix}"
        HtmlReport = Join-Path $ReportsRoot "report_${suffix}.html"
        Log = Join-Path $ReportsRoot 'test-log.txt'
        Summary = Join-Path $ReportsRoot "summary_${suffix}.json"
        BenchJson = Join-Path $ReportsRoot "bench_${suffix}.json"
    }
}

function Get-ModuleTarget {
    param([string]$Name)
    $normalized = ($Name -replace '\\', '/').Trim('/')
    if ($normalized.StartsWith('tests/')) { return $normalized }
    if ($normalized.Contains('/')) { return "tests/$normalized" }
    return "tests/test_$normalized"
}

function Resolve-PytestArgList {
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [string]$ModuleName,
        [Parameter(Mandatory = $true)][pscustomobject]$Paths,
        [string[]]$Extra
    )
    $base = @(
        "--junitxml=$($Paths.Junit)",
        "--html=$($Paths.HtmlReport)",
        '--self-contained-html',
        '-ra',
        '--strict-markers'
    )
    switch ($Type) {
        'unit' {
            $pytestArgs = @('tests/', '-m', 'not slow and not integration', '--timeout=180', '--timeout-method=thread', '-p', 'no:randomly') + $base
        }
        'all' {
            $pytestArgs = @('tests/', '--timeout=300', '--timeout-method=thread', '-p', 'no:randomly') + $base
        }
        'coverage' {
            $pytestArgs = @(
                'tests/',
                '--cov=src/intellicrack',
                '--cov-branch',
                "--cov-report=xml:$($Paths.CoverageXml)",
                "--cov-report=html:$($Paths.CoverageHtml)",
                '--cov-report=term-missing',
                '--cov-fail-under=95'
            ) + $base
        }
        'integration' {
            $pytestArgs = @('tests/', '-m', 'integration', '--timeout=600', '--timeout-method=thread', '-p', 'no:randomly') + $base
        }
        'e2e' {
            $pytestArgs = @('tests/test_hexcore_e2e/') + $base
        }
        'smoke' {
            $pytestArgs = @('tests/', '-k', 'not slow', '-m', 'not slow and not integration', '--timeout=60') + $base
        }
        'parallel' {
            $pytestArgs = @('tests/', '-n', 'auto') + $base
        }
        'failed' {
            $pytestArgs = @('tests/', '--last-failed', '--last-failed-no-failures=all') + $base
        }
        'verbose' {
            $pytestArgs = @('tests/', '-vv', '--tb=long', '--showlocals') + $base
        }
        'bench' {
            $pytestArgs = @(
                'tests/',
                '-m', 'benchmark',
                '--benchmark-only',
                "--benchmark-json=$($Paths.BenchJson)"
            ) + $base
        }
        'module' {
            if (-not $ModuleName) { throw 'module mode requires -Module' }
            $pytestArgs = @((Get-ModuleTarget -Name $ModuleName)) + $base
        }
        'module-cov' {
            if (-not $ModuleName) { throw 'module-cov mode requires -Module' }
            $pytestArgs = @(
                (Get-ModuleTarget -Name $ModuleName),
                '--cov=src/intellicrack',
                '--cov-branch',
                "--cov-report=xml:$($Paths.CoverageXml)",
                "--cov-report=html:$($Paths.CoverageHtml)",
                '--cov-report=term-missing',
                '--cov-fail-under=80'
            ) + $base
        }
        'registry' {
            $pytestArgs = @('tests/', '-k', 'registry or hw_spoofer or hwid') + $base
        }
        'custom' {
            $pytestArgs = $base
        }
        default {
            throw "unsupported TestType: $Type"
        }
    }
    if ($Extra -and $Extra.Count -gt 0) {
        $pytestArgs += $Extra
    }
    return ,$pytestArgs
}

function Invoke-InteractiveShell {
    Write-SandboxLog -Level 'info' -Event 'sandbox_shell_started'
    if (Get-Command $PixiExe -ErrorAction SilentlyContinue) {
        & $PixiExe shell --no-install --frozen
    }
    else {
        & $PixiPython -i
    }
    return $LASTEXITCODE
}

function Read-SpecFile {
    if (-not (Test-Path $SpecPath)) { return $null }
    try {
        return Get-Content -Path $SpecPath -Raw -Encoding utf8 | ConvertFrom-Json
    }
    catch {
        Write-SandboxLog -Level 'warning' -Event 'spec_parse_failed' -Context @{ path = $SpecPath; error = $_.Exception.Message }
        return $null
    }
}

function Read-JunitCount {
    param([string]$JunitPath)
    $counts = [pscustomobject]@{
        tests = 0
        passed = 0
        failed = 0
        skipped = 0
        errors = 0
        duration_seconds = 0.0
    }
    if (-not (Test-Path $JunitPath)) { return $counts }
    try {
        [xml]$xml = Get-Content -Path $JunitPath -Raw -Encoding utf8
    }
    catch {
        return $counts
    }
    $nodes = @()
    if ($xml.testsuites) { $nodes = @($xml.testsuites.testsuite) }
    elseif ($xml.testsuite) { $nodes = @($xml.testsuite) }
    $totalTests = 0
    $failures = 0
    $errs = 0
    $skipped = 0
    $duration = 0.0
    foreach ($node in $nodes) {
        if ($null -eq $node) { continue }
        $totalTests += [int]($node.tests | ForEach-Object { if ($_) { $_ } else { 0 } })
        $failures += [int]($node.failures | ForEach-Object { if ($_) { $_ } else { 0 } })
        $errs += [int]($node.errors | ForEach-Object { if ($_) { $_ } else { 0 } })
        $skipped += [int]($node.skipped | ForEach-Object { if ($_) { $_ } else { 0 } })
        $timeValue = $node.time
        if ($timeValue) { $duration += [double]$timeValue }
    }
    $passed = $totalTests - $failures - $errs - $skipped
    if ($passed -lt 0) { $passed = 0 }
    $counts.tests = $totalTests
    $counts.passed = $passed
    $counts.failed = $failures
    $counts.skipped = $skipped
    $counts.errors = $errs
    $counts.duration_seconds = [math]::Round($duration, 3)
    return $counts
}

function Get-CoveragePercent {
    param([string]$CoverageXmlPath)
    if (-not (Test-Path $CoverageXmlPath)) { return $null }
    try {
        [xml]$xml = Get-Content -Path $CoverageXmlPath -Raw -Encoding utf8
    }
    catch {
        return $null
    }
    $lineRate = $xml.coverage.'line-rate'
    if (-not $lineRate) { return $null }
    try {
        return [math]::Round([double]$lineRate * 100.0, 2)
    }
    catch {
        return $null
    }
}

function Write-SummaryJson {
    param(
        [Parameter(Mandatory = $true)][string]$TestType,
        [Parameter(Mandatory = $true)][string]$Timestamp,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][pscustomobject]$Paths,
        [Parameter(Mandatory = $true)][pscustomobject]$Counts,
        [object]$CoveragePercent,
        [string]$ModuleName,
        [string[]]$Extra
    )
    $payload = [ordered]@{
        test_type = $TestType
        timestamp = $Timestamp
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        exit_code = $ExitCode
        counts = [ordered]@{
            tests = $Counts.tests
            passed = $Counts.passed
            failed = $Counts.failed
            skipped = $Counts.skipped
            errors = $Counts.errors
            duration_seconds = $Counts.duration_seconds
        }
        coverage_percent = $CoveragePercent
        module = $ModuleName
        extra_args = @($Extra)
        report_paths = [ordered]@{
            junit = if (Test-Path $Paths.Junit) { $Paths.Junit } else { $null }
            coverage_xml = if (Test-Path $Paths.CoverageXml) { $Paths.CoverageXml } else { $null }
            coverage_html = if (Test-Path $Paths.CoverageHtml) { $Paths.CoverageHtml } else { $null }
            html_report = if (Test-Path $Paths.HtmlReport) { $Paths.HtmlReport } else { $null }
            log = if (Test-Path $Paths.Log) { $Paths.Log } else { $null }
            summary = $Paths.Summary
        }
    }
    $json = $payload | ConvertTo-Json -Depth 8
    Set-Content -Path $Paths.Summary -Value $json -Encoding utf8 -Force
}

function Write-LastExitCode {
    param([Parameter(Mandatory = $true)][int]$Code)
    $target = Join-Path $ReportsRoot '_last_exitcode'
    Set-Content -Path $target -Value ([string]$Code) -Encoding ascii -Force
}

function Invoke-Pytest {
    param(
        [Parameter(Mandatory = $true)][string[]]$PytestArgs,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$TestType,
        [Parameter(Mandatory = $true)][string]$Timestamp
    )
    Assert-PixiEnvironment
    Write-SandboxLog -Level 'info' -Event 'pytest_started' -Context @{ argv = $PytestArgs; log = $LogPath }
    $start = Get-Date

    $banner = @(
        '',
        '================================================================================',
        "RUN: $TestType   TIMESTAMP: $Timestamp",
        "ARGS: $($PytestArgs -join ' ')",
        '================================================================================',
        ''
    ) -join [Environment]::NewLine
    Add-Content -Path $LogPath -Value $banner -Encoding utf8

    $exit = 0
    try {
        if (Get-Command $PixiExe -ErrorAction SilentlyContinue) {
            $cmdArgs = @('run', '--no-install', '--frozen', 'pytest') + $PytestArgs
            & $PixiExe @cmdArgs 2>&1 | Tee-Object -FilePath $LogPath -Append | Out-Host
        }
        else {
            $cmdArgs = @('-m', 'pytest') + $PytestArgs
            & $PixiPython @cmdArgs 2>&1 | Tee-Object -FilePath $LogPath -Append | Out-Host
        }
        $exit = $LASTEXITCODE
        if ($null -eq $exit) { $exit = 0 }
    }
    catch {
        Write-SandboxLog -Level 'error' -Event 'pytest_launch_failed' -Context @{ error = $_.Exception.Message }
        Add-Content -Path $LogPath -Value "ENTRYPOINT ERROR: $($_.Exception.Message)" -Encoding utf8
        $exit = 99
    }

    $duration = ((Get-Date) - $start).TotalSeconds
    $footer = @(
        '',
        "END: $TestType   exit=$exit   duration=$([math]::Round($duration, 2))s",
        '--------------------------------------------------------------------------------',
        ''
    ) -join [Environment]::NewLine
    Add-Content -Path $LogPath -Value $footer -Encoding utf8

    Write-SandboxLog -Level 'info' -Event 'pytest_finished' -Context @{
        exit_code = $exit
        duration_seconds = [math]::Round($duration, 2)
    }
    return $exit
}

# ----- Main ------------------------------------------------------------------

if (-not $TestType) {
    throw 'TestType is required (set -TestType or TEST_TYPE environment variable)'
}

$Timestamp = Get-Timestamp
Write-SandboxLog -Level 'info' -Event 'entrypoint_started' -Context @{
    test_type = $TestType
    timestamp = $Timestamp
    module = $Module
    spec_path = $SpecPath
}

$Spec = Read-SpecFile
$specExtraArgs = @()
if ($Spec -and $Spec.extra_args) {
    foreach ($item in $Spec.extra_args) { $specExtraArgs += [string]$item }
}
$mergedExtra = @($ExtraArgs) + $specExtraArgs

if ($TestType -in @('interactive', 'interactive-rw')) {
    exit (Invoke-InteractiveShell)
}

$Paths = Initialize-ReportLayout -Timestamp $Timestamp -Type $TestType

$finalArgs = $null
if ($Spec -and $Spec.pytest_args -and $Spec.pytest_args.Count -gt 0 -and ($TestType -eq $Spec.test_type)) {
    $finalArgs = @()
    foreach ($arg in $Spec.pytest_args) { $finalArgs += [string]$arg }
    if ($ExtraArgs -and $ExtraArgs.Count -gt 0) { $finalArgs += $ExtraArgs }
    Write-SandboxLog -Level 'info' -Event 'using_host_spec_argv' -Context @{ argc = $finalArgs.Count }
}
else {
    $finalArgs = Resolve-PytestArgList -Type $TestType -ModuleName $Module -Paths $Paths -Extra $mergedExtra
    Write-SandboxLog -Level 'info' -Event 'using_container_argv' -Context @{ argc = $finalArgs.Count }
}

$exitCode = Invoke-Pytest -PytestArgs $finalArgs -LogPath $Paths.Log -TestType $TestType -Timestamp $Timestamp
Write-LastExitCode -Code $exitCode

$counts = Read-JunitCount -JunitPath $Paths.Junit
$coverage = Get-CoveragePercent -CoverageXmlPath $Paths.CoverageXml
Write-SummaryJson -TestType $TestType -Timestamp $Timestamp -ExitCode $exitCode `
    -Paths $Paths -Counts $counts -CoveragePercent $coverage `
    -ModuleName $Module -Extra $mergedExtra

Write-SandboxLog -Level 'info' -Event 'sandbox_run_complete' -Context @{
    test_type = $TestType
    timestamp = $Timestamp
    exit_code = $exitCode
    tests = $counts.tests
    passed = $counts.passed
    failed = $counts.failed
    skipped = $counts.skipped
    errors = $counts.errors
    coverage_percent = $coverage
}

exit $exitCode
