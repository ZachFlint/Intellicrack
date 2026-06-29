$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "x64dbg Bridge Plugin"

$pluginDir = "tools/x64dbg_plugin"
$buildDir = "$pluginDir/build"
$dest32 = "tools/x64dbg/release/x32/plugins"
$dest64 = "tools/x64dbg/release/x64/plugins"
$pluginSrc32 = "$buildDir/plugins/intellicrack_bridge_x32.dp32"
$pluginSrc64 = "$buildDir/plugins/intellicrack_bridge_x64.dp64"

if (!(Test-Path "$pluginDir/CMakeLists.txt")) {
    Write-Fail "Plugin source not found at $pluginDir/CMakeLists.txt"
    exit 1
}
if (!(Test-Path "tools/x64dbg/release")) {
    Write-Fail "x64dbg not installed. Run 'just install-x64dbg' first."
    exit 1
}

$cmakePath = $null
$cmakeCmd = Get-Command cmake -ErrorAction SilentlyContinue
if ($cmakeCmd) {
    $cmakePath = $cmakeCmd.Source
} else {
    $pf86 = ${env:ProgramFiles(x86)}
    if (!$pf86) { $pf86 = ${env:ProgramFiles} }
    if (!$pf86) { $pf86 = "C:\Program Files (x86)" }
    $vswhere = Join-Path $pf86 "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath
        if ($vsPath) {
            $candidate = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
            if (Test-Path $candidate) {
                $cmakePath = $candidate
            }
        }
    }
}

if (!$cmakePath) {
    Write-Fail "CMake not found. Install Visual Studio or CMake standalone."
    exit 1
}

Write-Step 'PLUGIN' "Building x64 plugin..."
try {
    if (!(Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir -Force | Out-Null }
    Push-Location $buildDir
    & $cmakePath .. -G "Visual Studio 17 2022" -A x64 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }
    & $cmakePath --build . --config Release 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }
    Pop-Location
    Write-Success "x64 plugin built"
} catch {
    Pop-Location
    Write-Fail "x64 build failed: $_"
    exit 1
}

Write-Step 'PLUGIN' "Building x32 plugin..."
$buildDir32 = "$pluginDir/build_x32"
try {
    if (!(Test-Path $buildDir32)) { New-Item -ItemType Directory -Path $buildDir32 -Force | Out-Null }
    Push-Location $buildDir32
    & $cmakePath .. -G "Visual Studio 17 2022" -A Win32 -DBUILD_X64=OFF 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }
    & $cmakePath --build . --config Release 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }
    Pop-Location
    Write-Success "x32 plugin built"
} catch {
    Pop-Location
    Write-Skip "x32 build failed (optional): $_"
}

Write-Step 'PLUGIN' "Deploying plugins..."
if (!(Test-Path $dest32)) { New-Item -ItemType Directory -Path $dest32 -Force | Out-Null }
if (!(Test-Path $dest64)) { New-Item -ItemType Directory -Path $dest64 -Force | Out-Null }

$installed = $false

$candidate64 = @(
    "$buildDir/plugins/intellicrack_bridge_x64.dp64",
    "$buildDir/plugins/Release/intellicrack_bridge_x64.dp64",
    "$buildDir/Release/intellicrack_bridge_x64.dp64"
)
$candidate32 = @(
    "$buildDir/plugins/intellicrack_bridge_x32.dp32",
    "$buildDir32/plugins/intellicrack_bridge_x32.dp32",
    "$buildDir/plugins/Release/intellicrack_bridge_x32.dp32",
    "$buildDir32/plugins/Release/intellicrack_bridge_x32.dp32",
    "$buildDir/Release/intellicrack_bridge_x32.dp32",
    "$buildDir32/Release/intellicrack_bridge_x32.dp32"
)

$src64 = $candidate64 | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
$src32 = $candidate32 | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if ($src64) {
    Copy-Item $src64 $dest64 -Force
    Write-Success "Deployed x64 plugin to $dest64"
    $installed = $true
} else {
    Write-Skip "x64 plugin binary not found"
}

if ($src32) {
    Copy-Item $src32 $dest32 -Force
    Write-Success "Deployed x32 plugin to $dest32"
    $installed = $true
} else {
    Write-Skip "x32 plugin binary not found"
}

if (!$installed) {
    Write-Fail "No plugin binaries produced by build"
    exit 1
}

$elapsed = ((Get-Date) - $startTime).TotalSeconds
$e = [char]27
Write-Host "`n${e}[1;32m=== Plugin Install Complete ===${e}[0m ${e}[90m($("{0:N1}" -f $elapsed)s)${e}[0m`n"
