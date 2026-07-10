param(
    [string]$Pixi = 'pixi run',
    [string]$Flags = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$pluginDir = "src/x64dbg-plugin"
$buildLintDir = "$pluginDir/build_lint"

& "$PSScriptRoot/build-x64dbg-plugin-compiledb.ps1" -Pixi $Pixi -Force:$Force
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Compile database generation failed; cannot run clang-tidy"
    exit 1
}

Import-VcVarsEnvironment -Arch x64

$sourceFiles = @(
    "$pluginDir/intellicrack_bridge.cpp",
    "$pluginDir/pipe_server.cpp",
    "$pluginDir/command_handler.cpp"
)
$sourceFilesArg = ($sourceFiles | ForEach-Object { "`"$_`"" }) -join ' '

if ($Flags.Trim()) {
    Invoke-Expression "$Pixi clang-tidy -p `"$buildLintDir`" $Flags $sourceFilesArg"
    exit $LASTEXITCODE
}

Write-Host "[ClangTidy] Running..."

@('txt', 'json', 'xml', 'csv', 'sarif', 'sql') | ForEach-Object {
    if (!(Test-Path "reports/$_")) {
        New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null
    }
}

$tmpFile = [System.IO.Path]::GetTempFileName()
try {
    $toolStart = Get-Date
    $captured = Invoke-Expression "$Pixi clang-tidy -p `"$buildLintDir`" $sourceFilesArg 2>&1"
    $captured | Out-File -FilePath $tmpFile -Encoding utf8
    $toolSeconds = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 2)
    $toolSecondsText = $toolSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    Write-Host "TOOL_ELAPSED_SECONDS=$toolSecondsText"

    Invoke-Expression "$Pixi python scripts/lint_report.py clang-tidy --text $tmpFile"
} finally {
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}
