param(
    [string]$Pixi = 'pixi run',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$pluginDir = "src/x64dbg-plugin"
$buildLintDir = "$pluginDir/build_lint"
$cmakeLists = "$pluginDir/CMakeLists.txt"
$compileDb = "$buildLintDir/compile_commands.json"

if (!(Test-Path $cmakeLists)) {
    Write-Fail "Plugin source not found at $cmakeLists"
    exit 1
}

if (!$Force -and (Test-Path $compileDb)) {
    $dbTime = (Get-Item $compileDb).LastWriteTimeUtc
    $listsTime = (Get-Item $cmakeLists).LastWriteTimeUtc
    if ($dbTime -ge $listsTime) {
        Write-Skip "Compile database is up to date at $compileDb"
        exit 0
    }
}

Write-Banner "x64dbg Plugin Compile Database"

Write-Step 'COMPILEDB' "Locating Visual Studio installation..."
$vsPath = Find-VsInstallationPath
if (!$vsPath) {
    Write-Fail "vswhere.exe not found or no Visual Studio installation with the C++ workload detected. Install the 'Desktop development with C++' workload."
    exit 1
}
Write-Success "Found Visual Studio at $vsPath"

$vcvarsall = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
if (!(Test-Path $vcvarsall)) {
    Write-Fail "vcvarsall.bat not found at $vcvarsall"
    exit 1
}

Write-Step 'COMPILEDB' "Importing MSVC x64 developer environment..."
Import-VcVarsEnvironment -Arch x64
if (!(Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Fail "cl.exe not found on PATH after importing the vcvarsall environment"
    exit 1
}
Write-Success "MSVC environment imported (cl.exe: $((Get-Command cl.exe).Source))"

$cmakeCmd = Get-Command cmake -ErrorAction SilentlyContinue
if (!$cmakeCmd) {
    Write-Step 'COMPILEDB' "Resolving pixi-provided cmake/ninja..."
    try {
        Invoke-Expression "$Pixi cmake --version" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "cmake not resolvable via '$Pixi cmake'" }
    } catch {
        Write-Fail "cmake not found. Install it via 'pixi install' (dependencies.cmake in pyproject.toml) or ensure it is on PATH: $_"
        exit 1
    }
}

try {
    Invoke-Expression "$Pixi ninja --version" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "ninja not resolvable via '$Pixi ninja'" }
} catch {
    Write-Fail "ninja not found. Install it via 'pixi install' (dependencies.ninja in pyproject.toml) or ensure it is on PATH: $_"
    exit 1
}

if (!(Test-Path $buildLintDir)) {
    New-Item -ItemType Directory -Path $buildLintDir -Force | Out-Null
}

Write-Step 'COMPILEDB' "Configuring with Ninja + cl.exe (CMAKE_EXPORT_COMPILE_COMMANDS=ON)..."
$cmakeArgs = @(
    '-S', $pluginDir,
    '-B', $buildLintDir,
    '-G', 'Ninja',
    '-DCMAKE_BUILD_TYPE=Release',
    '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
    '-DBUILD_X64=ON',
    '-DCMAKE_C_COMPILER=cl.exe',
    '-DCMAKE_CXX_COMPILER=cl.exe'
)
$quotedArgs = $cmakeArgs | ForEach-Object { "`"$_`"" }
Invoke-Expression "$Pixi cmake $($quotedArgs -join ' ')" 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Fail "CMake configure failed"
    exit 1
}

if (!(Test-Path $compileDb)) {
    Write-Fail "compile_commands.json was not generated at $compileDb"
    exit 1
}

Write-Success "Compile database generated at $compileDb"
