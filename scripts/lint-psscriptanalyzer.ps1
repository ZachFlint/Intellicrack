param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = ''
)

if ($Flags -match '(?:^|\s)(-h|--help|-\?|/\?)(?:\s|$)') {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck
    }
    Import-Module PSScriptAnalyzer
    Get-Help Invoke-ScriptAnalyzer -Detailed
    exit 0
}

Write-Host "[PSScriptAnalyzer] Running..."

@('txt', 'json', 'xml') | ForEach-Object {
    if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null }
}

$psFiles = @(fd -e ps1 -e psm1 -e psd1 --type f --exclude .pixi --exclude node_modules --exclude .git --exclude .claude --exclude target --exclude vendor --exclude build --exclude dist 2>$null |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })

if ($psFiles.Count -eq 0) {
    Write-Host "[PSScriptAnalyzer] 0 findings (no PowerShell scripts found)"
    'No findings.' | Out-File -FilePath 'reports/txt/psscriptanalyzer_findings.txt' -Encoding utf8
    @{
        tool           = 'psscriptanalyzer'
        generated      = (Get-Date).ToString('o')
        total_findings = 0
        total_files    = 0
        files          = @()
    } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/psscriptanalyzer_findings.json' -Encoding utf8
    '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="psscriptanalyzer"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' |
        Out-File -FilePath 'reports/xml/psscriptanalyzer_findings.xml' -Encoding utf8
    exit 0
}

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck
}

$tmpFile = [System.IO.Path]::GetTempFileName()
try {
    $psFiles | ForEach-Object {
        Invoke-ScriptAnalyzer -Path $_ -Severity @('Error', 'Warning', 'Information')
    } | ForEach-Object {
        "$($_.ScriptPath):$($_.Line):$($_.Column): [$($_.Severity)] $($_.Message) ($($_.RuleName))"
    } | Out-File -FilePath $tmpFile -Encoding utf8
    Invoke-Expression "$Pixi python scripts/lint_report.py psscriptanalyzer --text $tmpFile"
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}
