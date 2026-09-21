param(
    [string]$EnvPrefix = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Fix PyQt6 ICU DLL Resolution"

if (-not $EnvPrefix) {
    if ($env:CONDA_PREFIX) {
        $EnvPrefix = $env:CONDA_PREFIX
    } else {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $EnvPrefix = Join-Path $repoRoot '.pixi\envs\default'
    }
}

if (-not (Test-Path -LiteralPath $EnvPrefix -PathType Container)) {
    Write-Fail "Pixi env prefix not found: $EnvPrefix"
    Write-Fail "Run 'pixi install' first, or pass -EnvPrefix <path>."
    exit 1
}
Write-Step 'ICU' "Env prefix: $EnvPrefix"

$pythonExe = Join-Path $EnvPrefix 'python.exe'
if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    Write-Fail "python.exe not found in env prefix: $pythonExe"
    exit 1
}

$qt6Bin = Join-Path $EnvPrefix 'Lib\site-packages\PyQt6\Qt6\bin'
$qt6CoreDll = Join-Path $qt6Bin 'Qt6Core.dll'

if (-not (Test-Path -LiteralPath $qt6CoreDll -PathType Leaf)) {
    Write-Skip "PyQt6 not installed (Qt6Core.dll not found under $qt6Bin); nothing to fix"
    Write-Footer "Fix PyQt6 ICU DLL Resolution (no-op)" $startTime
    exit 0
}

Write-Step 'ICU' "Checking whether 'from PyQt6.QtCore import QT_VERSION_STR' already works..."
$importProbe = & $pythonExe -c "from PyQt6.QtCore import QT_VERSION_STR; print(QT_VERSION_STR)" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Skip "PyQt6.QtCore already imports cleanly (Qt $importProbe); nothing to fix"
    Write-Footer "Fix PyQt6 ICU DLL Resolution (no-op)" $startTime
    exit 0
}
Write-Progress "Import currently fails: $($importProbe | Select-Object -Last 1)"

# Qt 6.10+ Windows builds link Qt6Core.dll against the OS-provided, UNVERSIONED
# icuuc.dll/icu.dll pair instead of bundling their own ICU (see
# doc.qt.io/qt-6/qtwebengine-3rdparty-icu.html and the Qt Windows deployment
# notes). The PyQt6-Qt6 wheel does not bundle an icuuc.dll of its own -- confirmed
# against the wheel's RECORD, which lists no icu* file -- so Qt6Core.dll depends
# entirely on this machine's System32 copy.
#
# On this class of Windows build, System32\icuuc.dll ("ICU Common Forwarder DLL
# (deprecated)" per its own version info) exports every ucnv_*/UCNV_* symbol
# Qt6Core.dll needs as a PE export *forward* to System32\icu.dll -- but the
# forward fails to resolve at load time (GetProcAddress on the forwarded entry
# returns NULL, Win32 error 127) even though icu.dll's own direct, non-forwarded
# implementation of every one of those same symbols resolves fine via
# GetProcAddress called on icu.dll directly. That is a defect in this Windows
# build's forwarder chain, verified with a ctypes probe, not something a
# repo-side code change can fix.
#
# The fix: copy this machine's own System32\icu.dll -- which holds direct,
# non-forwarded implementations of every symbol Qt6Core.dll imports, under the
# exact unversioned names it imports them by -- to PyQt6\Qt6\bin\icuuc.dll,
# right next to Qt6Core.dll. Windows always searches the directory containing
# the importing DLL before System32, so this local copy resolves first and the
# broken System32 forwarder chain is never consulted. Nothing outside this pixi
# environment is touched, and .pixi/ is gitignored, so the copy never reaches
# source control -- it is a per-machine environment fix, reproduced here by
# re-running this script, not a repo change.
$systemIcu = Join-Path $env:SystemRoot 'System32\icu.dll'
if (-not (Test-Path -LiteralPath $systemIcu -PathType Leaf)) {
    Write-Fail "System ICU not found: $systemIcu"
    Write-Fail "This Windows build has no OS-provided ICU; Qt 6.10+ needs Windows 10 1903+ or Windows 11."
    exit 1
}
$icuSizeMB = [math]::Round((Get-Item -LiteralPath $systemIcu).Length / 1MB, 1)
Write-Success "Found system ICU: $systemIcu ($icuSizeMB MB)"

$destIcuUc = Join-Path $qt6Bin 'icuuc.dll'
Write-Step 'ICU' "Copying icu.dll -> Qt6\bin\icuuc.dll..."
try {
    Copy-Item -LiteralPath $systemIcu -Destination $destIcuUc -Force -ErrorAction Stop
    Write-Success "Copied ($icuSizeMB MB)"
} catch {
    Write-Fail "Copy failed: $($_.Exception.Message)"
    exit 1
}

Write-Step 'ICU' "Re-verifying 'from PyQt6.QtCore import QT_VERSION_STR'..."
$verify = & $pythonExe -c "from PyQt6.QtCore import QT_VERSION_STR; print(QT_VERSION_STR)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Import still fails after the fix:"
    Write-Fail ($verify -join "`n")
    Remove-Item -LiteralPath $destIcuUc -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Success "PyQt6.QtCore imports cleanly (Qt $verify)"

Write-Footer "Fix PyQt6 ICU DLL Resolution" $startTime
