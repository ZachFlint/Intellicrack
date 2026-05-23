param(
    [Parameter(Mandatory)][string]$ToolName,
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Command,
    [switch]$TextMode,
    [string]$Processor = 'lint_report',
    [string]$Pixi = 'pixi run',
    [string]$WorkDir,
    [string[]]$ReportFormats = @('txt', 'json', 'xml'),
    [string[]]$EnvVars,
    [switch]$JsonDirect,
    [switch]$SuppressStderr
)

Write-Host "[$DisplayName] Running..."

$ReportFormats | ForEach-Object {
    if (!(Test-Path "reports/$_")) {
        New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null
    }
}

if ($EnvVars) {
    foreach ($ev in $EnvVars) {
        $k, $v = $ev -split '=', 2
        Set-Item -Path "env:$k" -Value $v
    }
}

$tmpFile = [System.IO.Path]::GetTempFileName()
try {
    if ($WorkDir) { Push-Location $WorkDir }

    $toolStart = Get-Date
    if ($JsonDirect) {
        $actualCmd = $Command -replace '\{TMPFILE\}', $tmpFile
        Invoke-Expression $actualCmd 2>&1 | Out-Null
    } elseif ($SuppressStderr) {
        Invoke-Expression $Command 2>$null | Out-File -FilePath $tmpFile -Encoding utf8
    } else {
        $captured = Invoke-Expression "$Command 2>&1"
        $captured | Out-File -FilePath $tmpFile -Encoding utf8
    }
    $toolSeconds = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 2)
    $toolSecondsText = $toolSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    Write-Host "TOOL_ELAPSED_SECONDS=$toolSecondsText"

    if ($WorkDir) { Pop-Location }

    $textArg = if ($TextMode) { '--text ' } else { '' }
    Invoke-Expression "$Pixi python scripts/$Processor.py $ToolName $textArg$tmpFile"
} finally {
    if ($WorkDir) { Pop-Location -ErrorAction SilentlyContinue }
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}
