param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

if ($Flags.Trim()) {
    Invoke-Expression "node_modules/.bin/jsonlint $Flags"
    exit $LASTEXITCODE
}

Write-Host "[JSONLint] Running..."

@('txt', 'json', 'xml') | ForEach-Object {
    if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null }
}

$jsonFiles = @(fd -e json --type f --exclude 'package-lock.json' --exclude 'pixi.lock' --exclude 'reports' --exclude 'node_modules' --exclude .pixi --exclude .git --exclude .claude --exclude target --exclude vendor --exclude build --exclude dist 2>$null |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })

if ($jsonFiles.Count -eq 0) {
    Write-Host "[JSONLint] 0 findings (no JSON files found)"
    'No findings.' | Out-File -FilePath 'reports/txt/jsonlint_findings.txt' -Encoding utf8
    @{
        tool           = 'jsonlint'
        generated      = (Get-Date).ToString('o')
        total_findings = 0
        total_files    = 0
        files          = @()
    } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/jsonlint_findings.json' -Encoding utf8
    '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="jsonlint"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' |
        Out-File -FilePath 'reports/xml/jsonlint_findings.xml' -Encoding utf8
    exit 0
}

$tmpFile = [System.IO.Path]::GetTempFileName()
try {
    $jsonFiles | ForEach-Object {
        & node_modules/.bin/jsonlint -q -c $Flags $_ 2>&1
    } | Out-File -FilePath $tmpFile -Encoding utf8
    Invoke-Expression "$Pixi python scripts/lint_report.py jsonlint --text $tmpFile"
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}
