param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

Write-Host "[Blinter] Running..."

@('txt', 'json', 'xml') | ForEach-Object {
    if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null }
}

$batFiles = @(fd -e bat -e cmd --type f --exclude .pixi --exclude node_modules --exclude .git --exclude .claude --exclude target --exclude tools --exclude build --exclude dist --exclude vendor 2>$null |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })

if ($batFiles.Count -eq 0) {
    Write-Host "[Blinter] 0 findings (no batch files found)"
    'No findings.' | Out-File -FilePath 'reports/txt/blinter_findings.txt' -Encoding utf8
    @{
        tool           = 'blinter'
        generated      = (Get-Date).ToString('o')
        total_findings = 0
        total_files    = 0
        files          = @()
    } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/blinter_findings.json' -Encoding utf8
    '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="blinter"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' |
        Out-File -FilePath 'reports/xml/blinter_findings.xml' -Encoding utf8
    exit 0
}

$tmpFile = [System.IO.Path]::GetTempFileName()
try {
    $batFiles | ForEach-Object {
        Invoke-Expression "$Pixi python -m blinter $Flags $_ 2>&1"
    } | Out-File -FilePath $tmpFile -Encoding utf8
    Invoke-Expression "$Pixi python scripts/process_lint_json.py blinter --text $tmpFile"
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}
