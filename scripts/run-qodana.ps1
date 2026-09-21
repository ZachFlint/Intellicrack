param(
    [string]$ResultsDir = 'reports/qodana/results',
    [string]$ReportDir = 'reports/qodana/report',
    [string]$SarifCopy = 'reports/sarif/qodana_findings.sarif',
    [string]$PythonPath = '',
    [switch]$ShowReport,
    [string]$Flags = ''
)

$ErrorActionPreference = 'Stop'
Write-Host '[Qodana] Running...'

$qodana = Get-Command qodana -ErrorAction SilentlyContinue
if (-not $qodana) {
    Write-Host '[Qodana] FAIL: qodana CLI not found on PATH. Install it with: winget install -e --id JetBrains.QodanaCLI'
    exit 1
}

if (-not $PythonPath) {
    $PythonPath = Join-Path (Get-Location) '.pixi/envs/default/python.exe'
}
if (-not (Test-Path $PythonPath)) {
    Write-Host "[Qodana] FAIL: interpreter not found at $PythonPath. Run 'pixi install' first."
    exit 1
}
$env:QODANA_PYTHON_PATH = (Resolve-Path $PythonPath).Path

foreach ($dir in @($ResultsDir, $ReportDir, (Split-Path $SarifCopy -Parent))) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$scanArgs = @('scan', '--results-dir', $ResultsDir, '--report-dir', $ReportDir)
if ($ShowReport) { $scanArgs += '--show-report' }
if ($Flags.Trim()) { $scanArgs += ($Flags.Trim() -split '\s+') }

& qodana @scanArgs
$scanExit = $LASTEXITCODE

$sarif = Join-Path $ResultsDir 'qodana.sarif.json'
if (-not (Test-Path $sarif)) {
    Write-Host "[Qodana] FAIL: no SARIF produced at $sarif (qodana exit code $scanExit)"
    exit 1
}

Copy-Item $sarif $SarifCopy -Force

$results = (Get-Content $sarif -Raw | ConvertFrom-Json).runs.results
$total = @($results).Count
Write-Host "[Qodana] $total problems -> $SarifCopy"
if ($total -gt 0) {
    @($results) | Group-Object ruleId | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        Write-Host ('  {0,5}  {1}' -f $_.Count, $_.Name)
    }
}
Write-Host "[Qodana] HTML report: $ReportDir/index.html"
exit $scanExit
