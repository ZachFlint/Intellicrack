param(
    [string]$Flags = ''
)

$ErrorActionPreference = 'SilentlyContinue'

$skipList = @()
if ($Flags -match '--skip\s+(\S+)') { $skipList = $matches[1] -split ',' }

$groupAliases = @{
    python     = 'py'
    py         = 'py'
    rust       = 'rs'
    rs         = 'rs'
    toml       = 'toml'
    json       = 'json'
    yaml       = 'yaml'
    yml        = 'yaml'
    markdown   = 'md'
    md         = 'md'
    shell      = 'sh'
    sh         = 'sh'
    bash       = 'sh'
    batch      = 'bat'
    bat        = 'bat'
    powershell = 'ps'
    ps         = 'ps'
    ps1        = 'ps'
    text       = 'txt'
    txt        = 'txt'
    dashboard  = 'dash'
    dash       = 'dash'
}
$groupFilter = @()
foreach ($f in ($Flags -split '\s+')) {
    if ($f -ne '' -and $f -notmatch '^--' -and $groupAliases.ContainsKey($f.ToLower())) {
        $groupFilter += $groupAliases[$f.ToLower()]
    }
}

$h = [char]0x2500
$tl = [char]0x256D
$tr = [char]0x256E
$bl = [char]0x2570
$br = [char]0x256F
$v = [char]0x2502
$line = "$h" * 31
$e = [char]27

Write-Host "`n${e}[38;2;228;0;43m$tl$line$tr${e}[0m"
Write-Host "${e}[38;2;228;0;43m$v${e}[0m     ${e}[1;95mRunning All Dev Tools${e}[0m     ${e}[38;2;228;0;43m$v${e}[0m"
Write-Host "${e}[38;2;228;0;43m$bl$line$br${e}[0m`n"

$tools = @(
    @{N = 'Ruff Fmt';       R = 'ruff-fmt';           F = $true;  G = 'py' },
    @{N = 'Docformatter';   R = 'docformatter';       F = $true;  G = 'py' },
    @{N = 'TOMLfmt';        R = 'tomlfmt';            F = $true;  G = 'toml' },
    @{N = 'JSONfmt';        R = 'jsonfmt';            F = $true;  G = 'json' },
    @{N = 'YAMLfmt';        R = 'yamlfmt';            F = $true;  G = 'yaml' },
    @{N = 'MDfmt';          R = 'mdfmt';              F = $true;  G = 'md' },
    @{N = 'Ruff';           R = 'ruff';               F = $false; G = 'py' },
    @{N = 'Flake8';         R = 'flake8';             F = $false; G = 'py' },
    @{N = 'Wemake';         R = 'wemake';             F = $false; G = 'py' },
    @{N = 'BasedPyright';   R = 'basedpyright';       F = $false; G = 'py' },
    @{N = 'Mypy';           R = 'mypy';               F = $false; G = 'py' },
    @{N = 'Ty';             R = 'ty';                 F = $false; G = 'py' },
    @{N = 'Pydocstyle';     R = 'pydocstyle';         F = $false; G = 'py' },
    @{N = 'Pydoclint';      R = 'pydoclint';          F = $false; G = 'py' },
    @{N = 'Interrogate';    R = 'interrogate';        F = $false; G = 'py' },
    @{N = 'McCabe';         R = 'mccabe';             F = $false; G = 'py' },
    @{N = 'Radon';          R = 'radon';              F = $false; G = 'py' },
    @{N = 'Xenon';          R = 'xenon';              F = $false; G = 'py' },
    @{N = 'Complexipy';     R = 'complexipy';         F = $false; G = 'py' },
    @{N = 'Skylos';         R = 'skylos';             F = $false; G = 'py' },
    @{N = 'Vulture';        R = 'vulture';            F = $false; G = 'py' },
    @{N = 'Dead';           R = 'dead';               F = $false; G = 'py' },
    @{N = 'Deadcode';       R = 'deadcode';           F = $false; G = 'py' },
    @{N = 'Uncalled';       R = 'uncalled';           F = $false; G = 'py' },
    @{N = 'Bandit';         R = 'bandit';             F = $false; G = 'py' },
    @{N = 'Semgrep';        R = 'semgrep';            F = $false; G = 'py' },
    @{N = 'Deptry';         R = 'deptry';             F = $false; G = 'py' },
    @{N = 'Vermin';         R = 'vermin';             F = $false; G = 'py' },
    @{N = 'JSONLint';       R = 'jsonlint';           F = $false; G = 'json' },
    @{N = 'Tombi';          R = 'tombi';              F = $false; G = 'toml' },
    @{N = 'Markdown';       R = 'mdlint';             F = $false; G = 'md' },
    @{N = 'YAML';           R = 'yamllint';           F = $false; G = 'yaml' },
    @{N = 'ShellCheck';     R = 'shellcheck';         F = $false; G = 'sh' },
    @{N = 'Blinter';        R = 'blinter';            F = $false; G = 'bat' },
    @{N = 'PSScript';       R = 'psscriptanalyzer';   F = $false; G = 'ps' },
    @{N = 'Codespell';      R = 'codespell';          F = $false; G = 'txt' },
    @{N = 'PreCommitHooks'; R = 'precommit-hooks';    F = $false; G = 'txt' },
    @{N = 'Clippy';         R = 'clippy';             F = $false; G = 'rs' },
    @{N = 'RustFmt';        R = 'rustfmt';            F = $true;  G = 'rs' },
    @{N = 'CargoDeny';      R = 'cargo-deny';         F = $false; G = 'rs' },
    @{N = 'Nextest';        R = 'nextest';            F = $false; G = 'rs' },
    @{N = 'LlvmCov';        R = 'llvm-cov';           F = $false; G = 'rs' },
    @{N = 'Machete';        R = 'machete';            F = $false; G = 'rs' },
    @{N = 'RustAnalysis';   R = 'rust-code-analysis'; F = $false; G = 'rs' },
    @{N = 'Typos';          R = 'typos';              F = $false; G = 'txt' },
    @{N = 'Dashboard';      R = 'lint-dashboard';     F = $true;  G = 'dash' }
)

$gNames = @{
    py   = 'Python'
    rs   = 'Rust'
    toml = 'TOML'
    json = 'JSON'
    yaml = 'YAML'
    md   = 'Markdown'
    sh   = 'Shell'
    bat  = 'Batch'
    ps   = 'PowerShell'
    txt  = 'Text'
    dash = 'Dashboard'
}

if ($groupFilter.Count -gt 0) {
    $tools = $tools | Where-Object { $groupFilter -contains $_.G }
    $filterNames = ($groupFilter | ForEach-Object { $gNames[$_] }) -join ', '
    Write-Host "  Filtering: $filterNames only" -ForegroundColor DarkGray
    Write-Host ""
}

if ($skipList.Count -gt 0) {
    $validNames = $tools | ForEach-Object { $_.R }
    $invalid = $skipList | Where-Object { $validNames -notcontains $_ }
    if ($invalid) {
        Write-Host "  Unknown tool(s): $($invalid -join ', ')" -ForegroundColor Red
        Write-Host "  Valid names: $($validNames -join ', ')" -ForegroundColor DarkGray
        Write-Host ""
        exit 1
    }
    $tools = $tools | Where-Object { $skipList -notcontains $_.R }
    Write-Host "  Skipping: $($skipList -join ', ')" -ForegroundColor DarkGray
    Write-Host ""
}

$results = @{}
$globalStart = Get-Date
$lastGroup = ''

foreach ($tool in $tools) {
    switch ($tool.G) {
        'py'   { $gc = "${e}[38;2;55;118;171m" }
        'rs'   { $gc = "${e}[38;2;222;120;40m" }
        'toml' { $gc = "${e}[38;2;156;66;33m" }
        'json' { $gc = "${e}[38;2;218;165;32m" }
        'yaml' { $gc = "${e}[38;2;203;23;30m" }
        'md'   { $gc = "${e}[38;2;200;200;205m" }
        'sh'   { $gc = "${e}[38;2;137;224;81m" }
        'bat'  { $gc = "${e}[38;2;120;180;230m" }
        'ps'   { $gc = "${e}[38;2;30;110;200m" }
        'txt'  { $gc = "${e}[38;2;190;190;190m" }
        'dash' { $gc = "${e}[95m" }
    }

    if ($tool.G -ne $lastGroup) {
        $lastGroup = $tool.G
        Write-Host "`n  $gc-- $($gNames[$tool.G]) --${e}[0m`n"
    }

    try {
        $toolStart = Get-Date
        $tmpOut = [System.IO.Path]::GetTempFileName()
        cmd /c "just $($tool.R) > `"$tmpOut`" 2>&1"
        $duration = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 1)

        $findings = 0
        $outputStr = if (Test-Path $tmpOut) { Get-Content $tmpOut -Raw -ErrorAction SilentlyContinue } else { '' }
        Remove-Item $tmpOut -Force -ErrorAction SilentlyContinue
        if (-not $tool.F -and $outputStr -match '(\d+)\s+findings') {
            $findings = [int]$matches[1]
        }

        $results[$tool.R] = @{
            Name        = $tool.N
            Findings    = $findings
            Duration    = $duration
            Success     = $true
            IsFormatter = $tool.F
        }

        if ($tool.F) {
            Write-Host "  $gc$([char]0x2714) $($tool.N): Done in ${duration}s${e}[0m"
        } else {
            Write-Host "  $gc$([char]0x2714) $($tool.N): Completed in ${duration}s with $($findings) findings${e}[0m"
        }
    } catch {
        $duration = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 1)
        $results[$tool.R] = @{
            Name        = $tool.N
            Findings    = 0
            Duration    = $duration
            Success     = $false
            IsFormatter = $tool.F
        }
        Write-Host "  ${e}[31m$([char]0x2718) $($tool.N): Failed after ${duration}s - $_${e}[0m"
    }
}

Write-Host "`n${e}[90m$('-' * 60)${e}[0m"
$totalTime = [Math]::Round(((Get-Date) - $globalStart).TotalSeconds, 1)
$totalFindings = ($results.Values | ForEach-Object { $_.Findings } | Measure-Object -Sum).Sum
$passedCount = ($results.Values | Where-Object { $_.Success -and $_.Findings -eq 0 }).Count
Write-Host "Time: ${e}[36m${totalTime}s${e}[0m | Findings: ${e}[33m$totalFindings${e}[0m | Passed: ${e}[32m$passedCount/$($tools.Count)${e}[0m"
exit 0
