param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

if ($Flags -match '(?:^|\s)(-h|--help|-\?|/\?)(?:\s|$)') {
    Invoke-Expression "$Pixi shellcheck --help"
    exit $LASTEXITCODE
}

Write-Host "[ShellCheck] Running..."

@('txt', 'json', 'xml') | ForEach-Object {
    if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null }
}

$shFiles = @(fd -e sh -e bash --type f --exclude .pixi --exclude node_modules --exclude .git --exclude .claude --exclude target --exclude vendor --exclude build --exclude dist 2>$null |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })

if ($shFiles.Count -eq 0) {
    Write-Host "[ShellCheck] 0 findings (no shell scripts found)"
    'No findings.' | Out-File -FilePath 'reports/txt/shellcheck_findings.txt' -Encoding utf8
    @{
        tool           = 'shellcheck'
        generated      = (Get-Date).ToString('o')
        total_findings = 0
        total_files    = 0
        files          = @()
    } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/shellcheck_findings.json' -Encoding utf8
    '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="shellcheck"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' |
        Out-File -FilePath 'reports/xml/shellcheck_findings.xml' -Encoding utf8
    exit 0
}

$tmpFile = [System.IO.Path]::GetTempFileName()
try {
    $shFiles | ForEach-Object {
        Invoke-Expression "$Pixi shellcheck $Flags --format=gcc $_ 2>&1"
    } | Out-File -FilePath $tmpFile -Encoding utf8
    Invoke-Expression "$Pixi python scripts/lint_report.py shellcheck --text $tmpFile"
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}
