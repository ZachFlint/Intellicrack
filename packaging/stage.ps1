#Requires -Version 7
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/../scripts/common.ps1"

# Intellicrack installer staging build script.
#
# Assembles the fixed <repo>/build/stage layout that packaging/intellicrack.iss
# consumes verbatim. Every expected source is asserted before use: a missing
# source is a hard failure (throw / nonzero exit), never a silent skip. The
# script is idempotent - it recreates build/stage from scratch on each run.

$StartTime = Get-Date

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Stage = Join-Path $RepoRoot 'build\stage'
$BuildRoot = Join-Path $RepoRoot 'build'

function Assert-Source {
    <#
    .SYNOPSIS
        Throws unless a required source path exists.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$What
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing required source ($What): $Path"
    }
}

function Assert-Produced {
    <#
    .SYNOPSIS
        Throws unless a path that the stage was supposed to produce exists.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$What
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Staging did not produce required output ($What): $Path"
    }
}

function Invoke-Robocopy {
    <#
    .SYNOPSIS
        Mirror a directory tree with robocopy, treating exit codes >= 8 as fatal.
    #>
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [string[]]$ExcludeDirs = @(),
        [string[]]$ExcludeFiles = @()
    )
    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }
    $roboArgs = @($Source, $Destination, '/E', '/COPY:DAT', '/DCOPY:DAT',
        '/R:2', '/W:2', '/NFL', '/NDL', '/NJH', '/NJS', '/NP')
    foreach ($d in $ExcludeDirs) { $roboArgs += @('/XD', $d) }
    foreach ($f in $ExcludeFiles) { $roboArgs += @('/XF', $f) }
    & robocopy @roboArgs | Out-Null
    $code = $LASTEXITCODE
    if ($code -ge 8) {
        throw "robocopy failed (exit $code): $Source -> $Destination"
    }
}

function Remove-MatchingItem {
    <#
    .SYNOPSIS
        Recursively remove every file or directory whose name matches a filter.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Filter,
        [switch]$Directories
    )
    if (-not (Test-Path -LiteralPath $Root)) { return }
    $items = Get-ChildItem -LiteralPath $Root -Recurse -Force -Filter $Filter -ErrorAction SilentlyContinue |
        Where-Object { $_.PSIsContainer -eq [bool]$Directories }
    foreach ($item in $items) {
        if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove')) {
            Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-OptionalSign {
    <#
    .SYNOPSIS
        Authenticode-sign a file when signing credentials are configured, else warn.
    .DESCRIPTION
        Signs $Path with signtool when INTELLICRACK_SIGN_PFX names a code-signing
        certificate. INTELLICRACK_SIGN_PASS supplies the .pfx password and
        INTELLICRACK_SIGN_TS an RFC-3161 timestamp URL when present. With no
        certificate configured the file is left unsigned and a warning is emitted;
        the build never hardcodes a certificate.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$What
    )
    $pfx = $env:INTELLICRACK_SIGN_PFX
    if (-not $pfx) {
        Write-Warning "$What is unsigned (set INTELLICRACK_SIGN_PFX to a code-signing .pfx to sign it)"
        return
    }
    if (-not (Test-Path -LiteralPath $pfx)) {
        throw "INTELLICRACK_SIGN_PFX points at a missing file: $pfx"
    }
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)?.Source
    if (-not $signtool) {
        throw 'INTELLICRACK_SIGN_PFX is set but signtool.exe is not on PATH (install the Windows SDK)'
    }
    $signArgs = @('sign', '/fd', 'SHA256', '/f', $pfx)
    if ($env:INTELLICRACK_SIGN_PASS) { $signArgs += @('/p', $env:INTELLICRACK_SIGN_PASS) }
    if ($env:INTELLICRACK_SIGN_TS) { $signArgs += @('/tr', $env:INTELLICRACK_SIGN_TS, '/td', 'SHA256') }
    $signArgs += $Path
    & $signtool @signArgs
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $What (exit $LASTEXITCODE)" }
    Write-Success "$What signed"
}

Write-Banner 'Intellicrack Stage Build'
Write-Step 'STAGE' "Repo root: $RepoRoot"
Write-Step 'STAGE' "Stage dir: $Stage"

# ---------------------------------------------------------------------------
# Step 1: recreate build/stage clean.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 1/14: recreating build/stage clean...'
if (Test-Path -LiteralPath $Stage) {
    Remove-Item -LiteralPath $Stage -Recurse -Force
}
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
Write-Success 'build/stage recreated'

# ---------------------------------------------------------------------------
# Step 2: runtime = trimmed copy of the pixi default env.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 2/14: staging runtime (trimmed pixi env)...'
$PixiEnv = Join-Path $RepoRoot '.pixi\envs\default'
Assert-Source -Path $PixiEnv -What 'pixi default env'
Assert-Source -Path (Join-Path $PixiEnv 'python.exe') -What 'runtime python.exe'
$RuntimeDir = Join-Path $Stage 'runtime'
Invoke-Robocopy -Source $PixiEnv -Destination $RuntimeDir
$RuntimeSitePackages = Join-Path $RuntimeDir 'Lib\site-packages'
Assert-Produced -Path (Join-Path $RuntimeDir 'python.exe') -What 'staged runtime python.exe'
Assert-Produced -Path $RuntimeSitePackages -What 'staged runtime site-packages'

Write-Progress 'Removing dev-only distributions from runtime...'
$DevPatterns = @('pytest*', '_pytest*', 'ruff*', 'basedpyright*', 'sphinx*', 'mypy*')
foreach ($pattern in $DevPatterns) {
    $siteMatches = Get-ChildItem -LiteralPath $RuntimeSitePackages -Force -Filter $pattern -ErrorAction SilentlyContinue
    foreach ($m in $siteMatches) {
        Remove-Item -LiteralPath $m.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    $binMatches = Get-ChildItem -LiteralPath (Join-Path $RuntimeDir 'Scripts') -Force -Filter $pattern -ErrorAction SilentlyContinue
    foreach ($m in $binMatches) {
        Remove-Item -LiteralPath $m.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Progress 'Removing node.exe, *.pdb, *.pyd.old_*, and __pycache__ from runtime...'
Remove-MatchingItem -Root $RuntimeDir -Filter 'node.exe'
Remove-MatchingItem -Root $RuntimeDir -Filter '*.pdb'
Remove-MatchingItem -Root $RuntimeDir -Filter '*.pyd.old_*'
Remove-MatchingItem -Root $RuntimeDir -Filter '__pycache__' -Directories

foreach ($pth in @('_editable_impl_intellicrack.pth', 'a1_coverage.pth')) {
    $pthPath = Join-Path $RuntimeSitePackages $pth
    if (Test-Path -LiteralPath $pthPath) {
        Remove-Item -LiteralPath $pthPath -Force
        Write-Progress "Removed $pth"
    }
}

# The pip/distlib console-script launchers under Scripts\ embed the absolute
# build-interpreter path (D:\...\.pixi\envs\default\python.exe). On a target
# that path does not exist, and worse, if it is user-writable anyone who plants
# a python.exe there gains code execution through any invoked shim. The
# application never runs these shims (it launches python via -m), so every shim
# that embeds the build interpreter is stripped here and Scripts\ is dropped
# from the launchers' child PATH.
Write-Progress 'Removing console-script shims that embed the build interpreter path...'
$ScriptsDir = Join-Path $RuntimeDir 'Scripts'
$ShimsRemoved = 0
if (Test-Path -LiteralPath $ScriptsDir) {
    foreach ($exe in Get-ChildItem -LiteralPath $ScriptsDir -Filter '*.exe' -File -ErrorAction SilentlyContinue) {
        $bytes = [System.IO.File]::ReadAllBytes($exe.FullName)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        if ($ascii.Contains($PixiEnv)) {
            Remove-Item -LiteralPath $exe.FullName -Force
            $ShimsRemoved++
        }
    }
}
Write-Progress "Removed $ShimsRemoved build-path console-script shim(s)"

# The editable install's dist-info carries a direct_url.json that records
# file:///D:/Intellicrack. The app source ships under app\src and is placed on
# PYTHONPATH by the launcher, so this dist-info is dead weight that only leaks
# the build tree path. Remove it.
Write-Progress 'Removing the editable-install dist-info that leaks the source path...'
$EditableDistInfo = @(Get-ChildItem -LiteralPath $RuntimeSitePackages -Directory -Filter 'intellicrack*.dist-info' -ErrorAction SilentlyContinue)
foreach ($di in $EditableDistInfo) {
    Remove-Item -LiteralPath $di.FullName -Recurse -Force -ErrorAction SilentlyContinue
    Write-Progress "Removed $($di.Name)"
}
Write-Success 'runtime staged and trimmed'

# ---------------------------------------------------------------------------
# Step 3: portable hexcore rebuild -> runtime site-packages.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 3/14: rebuilding portable hexcore wheel...'
$HexcoreDir = Join-Path $RepoRoot 'src\intellicrack-hexcore'
Assert-Source -Path (Join-Path $HexcoreDir 'Cargo.toml') -What 'hexcore crate'

# Empty the wheels directory before building so the wheel staged below is
# provably the one this build produced. maturin/cargo honour CARGO_TARGET_DIR
# redirection, and picking the newest-mtime wheel from a shared directory would
# silently stage a stale .pyd whenever the redirect leaves an older wheel behind.
$WheelsDir = Join-Path $HexcoreDir 'target\wheels'
if (Test-Path -LiteralPath $WheelsDir) {
    Get-ChildItem -LiteralPath $WheelsDir -Filter '*.whl' -File -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

$env:RUSTFLAGS = '-C target-cpu=x86-64-v2'
Push-Location $HexcoreDir
try {
    & pixi run maturin build --release
    if ($LASTEXITCODE -ne 0) {
        throw "maturin build failed (exit $LASTEXITCODE)"
    }
} finally {
    Pop-Location
}

Assert-Produced -Path $WheelsDir -What 'hexcore wheels dir'
$Wheels = @(Get-ChildItem -LiteralPath $WheelsDir -Filter '*.whl' -File)
if ($Wheels.Count -ne 1) {
    $names = ($Wheels | ForEach-Object { $_.Name }) -join ', '
    throw "Expected exactly one freshly-built hexcore wheel under $WheelsDir, found $($Wheels.Count): $names"
}
$Wheel = $Wheels[0]
Write-Progress "Using wheel: $($Wheel.Name)"

$WheelExtract = Join-Path $BuildRoot '_hexcore_wheel'
if (Test-Path -LiteralPath $WheelExtract) { Remove-Item -LiteralPath $WheelExtract -Recurse -Force }
New-Item -ItemType Directory -Path $WheelExtract -Force | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($Wheel.FullName, $WheelExtract)

$WheelPkg = Join-Path $WheelExtract 'intellicrack_hexcore'
Assert-Produced -Path $WheelPkg -What 'hexcore package inside wheel'
$HexcoreDest = Join-Path $RuntimeSitePackages 'intellicrack_hexcore'
if (Test-Path -LiteralPath $HexcoreDest) { Remove-Item -LiteralPath $HexcoreDest -Recurse -Force }
New-Item -ItemType Directory -Path $HexcoreDest -Force | Out-Null
foreach ($member in @('intellicrack_hexcore.cp313-win_amd64.pyd', '__init__.py', '__init__.pyi', 'py.typed')) {
    $src = Join-Path $WheelPkg $member
    Assert-Produced -Path $src -What "hexcore wheel member $member"
    Copy-Item -LiteralPath $src -Destination (Join-Path $HexcoreDest $member) -Force
}
Remove-Item -LiteralPath $WheelExtract -Recurse -Force -ErrorAction SilentlyContinue
Assert-Produced -Path (Join-Path $HexcoreDest 'intellicrack_hexcore.cp313-win_amd64.pyd') -What 'staged hexcore .pyd'
Write-Success 'portable hexcore staged'

# ---------------------------------------------------------------------------
# Step 4: app source materialized copy.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 4/14: staging app source...'
$SrcIntellicrack = Join-Path $RepoRoot 'src\intellicrack'
Assert-Source -Path (Join-Path $SrcIntellicrack '__init__.py') -What 'intellicrack source package'
$AppSrcDest = Join-Path $Stage 'app\src\intellicrack'
Invoke-Robocopy -Source $SrcIntellicrack -Destination $AppSrcDest -ExcludeDirs @('__pycache__') -ExcludeFiles @('*.pyc')
Assert-Produced -Path (Join-Path $AppSrcDest '__init__.py') -What 'staged intellicrack __init__.py'
Assert-Produced -Path (Join-Path $AppSrcDest 'assets\icon.ico') -What 'staged intellicrack icon'
Write-Success 'app source staged'

# ---------------------------------------------------------------------------
# Step 5: ML split - move ML-only distributions out of runtime into ml_overlay.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 5/14: splitting ML-only distributions into ml_overlay...'
$RuntimePython = Join-Path $RuntimeDir 'python.exe'
$Pyproject = Join-Path $RepoRoot 'pyproject.toml'
Assert-Source -Path $Pyproject -What 'pyproject.toml'
$MlSplitScript = Join-Path $RepoRoot 'packaging\ml_split.py'
Assert-Source -Path $MlSplitScript -What 'ml_split.py'

$MlEntries = & $RuntimePython $MlSplitScript $Pyproject
if ($LASTEXITCODE -ne 0) {
    throw "ML-split closure computation failed (exit $LASTEXITCODE)"
}
$MlEntries = @($MlEntries | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
if ($MlEntries.Count -eq 0) {
    throw 'ML split computed zero entries to move; refusing to produce a runtime that still contains torch/transformers'
}

$MlOverlaySite = Join-Path $Stage 'ml_overlay\Lib\site-packages'
New-Item -ItemType Directory -Path $MlOverlaySite -Force | Out-Null
foreach ($entry in $MlEntries) {
    $src = Join-Path $RuntimeSitePackages $entry
    if (-not (Test-Path -LiteralPath $src)) {
        Write-Progress "ML entry already absent from runtime: $entry"
        continue
    }
    $dest = Join-Path $MlOverlaySite $entry
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    Move-Item -LiteralPath $src -Destination $dest -Force
}

foreach ($required in @('torch', 'transformers')) {
    if (Test-Path -LiteralPath (Join-Path $RuntimeSitePackages $required)) {
        throw "ML split failed: '$required' is still present in runtime site-packages"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $MlOverlaySite $required))) {
        throw "ML split failed: '$required' was not moved into ml_overlay"
    }
}
Write-Success "ML split complete ($($MlEntries.Count) entries moved to ml_overlay)"

# ---------------------------------------------------------------------------
# Step 6: x64dbg tree + plugin verification.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 6/14: staging x64dbg...'
$X64dbgSrc = Join-Path $RepoRoot 'tools\x64dbg'
Assert-Source -Path $X64dbgSrc -What 'x64dbg tree'
$X64dbgDest = Join-Path $Stage 'app\tools\x64dbg'
Invoke-Robocopy -Source $X64dbgSrc -Destination $X64dbgDest
Assert-Produced -Path (Join-Path $X64dbgDest 'release\x64\x64dbg.exe') -What 'x64dbg.exe'
Assert-Produced -Path (Join-Path $X64dbgDest 'release\x32\x32dbg.exe') -What 'x32dbg.exe'
Assert-Produced -Path (Join-Path $X64dbgDest 'release\x64\plugins\intellicrack_bridge_x64.dp64') -What 'x64 bridge plugin'
Assert-Produced -Path (Join-Path $X64dbgDest 'release\x32\plugins\intellicrack_bridge_x32.dp32') -What 'x32 bridge plugin'
Write-Success 'x64dbg staged'

# ---------------------------------------------------------------------------
# Step 7: remaining tool subset.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 7/14: staging tool subset...'
$ToolSubset = @('radare2', 'cutter', 'NASM', 'pmd', 'google-java-format',
    'AdobeInjector', 'IDMActivator', 'WindowsPatch')
foreach ($tool in $ToolSubset) {
    $toolSrc = Join-Path $RepoRoot "tools\$tool"
    Assert-Source -Path $toolSrc -What "tool $tool"
    $toolDest = Join-Path $Stage "app\tools\$tool"
    Invoke-Robocopy -Source $toolSrc -Destination $toolDest
    Write-Progress "Staged tool: $tool"
}
Write-Warning 'tools/resource_hacker skipped (ResourceHacker.exe is absent from the repo)'
Write-Warning 'tools/pmd-bin-7.8.0 skipped (only the extracted pmd/ tree is shipped)'
Assert-Produced -Path (Join-Path $Stage 'app\tools\cutter\rizin.exe') -What 'cutter rizin.exe'
Assert-Produced -Path (Join-Path $Stage 'app\tools\radare2\bin\radare2.exe') -What 'radare2.exe'
Assert-Produced -Path (Join-Path $Stage 'app\tools\NASM\nasm.exe') -What 'nasm.exe'
Assert-Produced -Path (Join-Path $Stage 'app\tools\google-java-format\google-java-format.jar') -What 'google-java-format.jar'
Assert-Produced -Path (Join-Path $Stage 'app\tools\IDMActivator\IDMA.ps1') -What 'IDMA.ps1'
Assert-Produced -Path (Join-Path $Stage 'app\tools\WindowsPatch\WindowsActivator.cmd') -What 'WindowsActivator.cmd'
Assert-Produced -Path (Join-Path $Stage 'app\tools\AdobeInjector\AdobeInjector.exe') -What 'AdobeInjector.exe'
Write-Success 'tool subset staged'

# ---------------------------------------------------------------------------
# Step 8: Ghidra tree.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 8/14: staging Ghidra...'
$GhidraSrc = Join-Path $RepoRoot 'tools\ghidra'
Assert-Source -Path (Join-Path $GhidraSrc 'support\analyzeHeadless.bat') -What 'Ghidra tree'
$GhidraDest = Join-Path $Stage 'app\tools\ghidra'
Invoke-Robocopy -Source $GhidraSrc -Destination $GhidraDest
Assert-Produced -Path (Join-Path $GhidraDest 'support\analyzeHeadless.bat') -What 'staged analyzeHeadless.bat'
Write-Success 'Ghidra staged'

# ---------------------------------------------------------------------------
# Step 9: bundled Temurin JDK 21 under the Ghidra tree.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 9/14: staging pinned Temurin JDK 21...'
# Provenance is anchored in the repo, not the download host: packaging/jdk21.lock.json
# pins an immutable GitHub release asset and its SHA-256. We fetch that exact url
# (with bounded retry) and refuse to proceed unless the hash matches the pin.
$JdkLockPath = Join-Path $RepoRoot 'packaging\jdk21.lock.json'
Assert-Source -Path $JdkLockPath -What 'JDK pin lock file'
$JdkLock = Get-Content -LiteralPath $JdkLockPath -Raw | ConvertFrom-Json
foreach ($field in @('url', 'sha256', 'release')) {
    if (-not $JdkLock.$field) { throw "packaging/jdk21.lock.json is missing required field '$field'" }
}
Write-Progress "Pinned Temurin release: $($JdkLock.release)"
$ProgressPreference = 'SilentlyContinue'

$JdkZip = Join-Path $BuildRoot '_temurin21.zip'
if (Test-Path -LiteralPath $JdkZip) { Remove-Item -LiteralPath $JdkZip -Force }

$Downloaded = $false
for ($attempt = 1; $attempt -le 4; $attempt++) {
    try {
        Invoke-WebRequest -Uri $JdkLock.url -OutFile $JdkZip -TimeoutSec 600
        $Downloaded = $true
        break
    } catch {
        Write-Warning "Temurin download attempt $attempt failed: $($_.Exception.Message)"
        if (Test-Path -LiteralPath $JdkZip) { Remove-Item -LiteralPath $JdkZip -Force -ErrorAction SilentlyContinue }
        if ($attempt -lt 4) { Start-Sleep -Seconds ([int][math]::Pow(2, $attempt)) }
    }
}
if (-not $Downloaded) { throw "Temurin JDK download failed after 4 attempts: $($JdkLock.url)" }
Assert-Produced -Path $JdkZip -What 'downloaded Temurin JDK zip'

$ExpectedSha = $JdkLock.sha256.ToLowerInvariant()
$ActualSha = (Get-FileHash -LiteralPath $JdkZip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualSha -ne $ExpectedSha) {
    Remove-Item -LiteralPath $JdkZip -Force -ErrorAction SilentlyContinue
    throw "Temurin JDK SHA-256 mismatch (pinned in packaging/jdk21.lock.json): expected $ExpectedSha, got $ActualSha"
}
Write-Progress 'JDK checksum verified against the in-repo pin'

[System.IO.Compression.ZipFile]::ExtractToDirectory($JdkZip, $GhidraDest)
Remove-Item -LiteralPath $JdkZip -Force -ErrorAction SilentlyContinue
$JdkRoot = Get-ChildItem -LiteralPath $GhidraDest -Directory -Filter 'jdk-21*' | Select-Object -First 1
if (-not $JdkRoot) { throw 'Extracted Temurin archive produced no jdk-21* directory' }
Assert-Produced -Path (Join-Path $JdkRoot.FullName 'bin\java.exe') -What 'bundled JDK java.exe'
Write-Success "Temurin JDK staged: $($JdkRoot.Name)"

# ---------------------------------------------------------------------------
# Step 10: QEMU program tree, excluding images/.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 10/14: staging QEMU (excluding images/)...'
$QemuSrc = Join-Path $RepoRoot 'tools\qemu'
Assert-Source -Path (Join-Path $QemuSrc 'qemu-system-x86_64.exe') -What 'QEMU tree'
$QemuDest = Join-Path $Stage 'app\tools\qemu'
Invoke-Robocopy -Source $QemuSrc -Destination $QemuDest -ExcludeDirs @((Join-Path $QemuSrc 'images'))
Assert-Produced -Path (Join-Path $QemuDest 'qemu-system-x86_64.exe') -What 'staged qemu-system-x86_64.exe'
Assert-Produced -Path (Join-Path $QemuDest 'qemu-img.exe') -What 'staged qemu-img.exe'
if (Test-Path -LiteralPath (Join-Path $QemuDest 'images')) {
    throw 'QEMU images/ directory leaked into the stage'
}
Write-Success 'QEMU staged'

# ---------------------------------------------------------------------------
# Step 11: optional bundled Debian sandbox guest.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 11/14: staging Debian sandbox guest...'
$GuestSrc = Join-Path $RepoRoot 'tools\qemu\images\debian13-intellicrack.qcow2'
Assert-Source -Path $GuestSrc -What 'Debian sandbox guest image'
$GuestDestDir = Join-Path $Stage 'qemu-guest'
New-Item -ItemType Directory -Path $GuestDestDir -Force | Out-Null
Copy-Item -LiteralPath $GuestSrc -Destination (Join-Path $GuestDestDir 'debian13-intellicrack.qcow2') -Force
Assert-Produced -Path (Join-Path $GuestDestDir 'debian13-intellicrack.qcow2') -What 'staged Debian guest'
Write-Warning 'Debian guest must have qemu-guest-agent installed in-guest to be usable by the sandbox'
Write-Success 'Debian sandbox guest staged'

# ---------------------------------------------------------------------------
# Step 12: vendor pattern/data trees.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 12/14: staging vendor trees...'
$VendorSubset = @('community-patterns', 'ImHex-Patterns', 'PatternLanguage', 'traceevent')
foreach ($vendor in $VendorSubset) {
    $vendorSrc = Join-Path $RepoRoot "vendor\$vendor"
    Assert-Source -Path $vendorSrc -What "vendor $vendor"
    $vendorDest = Join-Path $Stage "app\vendor\$vendor"
    Invoke-Robocopy -Source $vendorSrc -Destination $vendorDest
    Write-Progress "Staged vendor: $vendor"
}
$CommunityPatternsDir = Join-Path $Stage 'app\vendor\community-patterns\patterns'
Assert-Produced -Path $CommunityPatternsDir -What 'community-patterns patterns/ dir'
$patternCount = @(Get-ChildItem -LiteralPath $CommunityPatternsDir -Recurse -File -ErrorAction SilentlyContinue).Count
if ($patternCount -eq 0) {
    throw 'community-patterns/patterns is empty in the stage'
}
Write-Success 'vendor trees staged'

# ---------------------------------------------------------------------------
# Step 13: hexbench standalone GUI.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 13/14: staging hexbench...'
$HexbenchSrc = Join-Path $RepoRoot 'src\hexbench'
Assert-Source -Path $HexbenchSrc -What 'hexbench source'
$HexbenchDest = Join-Path $Stage 'hexbench'
Invoke-Robocopy -Source $HexbenchSrc -Destination $HexbenchDest -ExcludeDirs @('__pycache__') -ExcludeFiles @('*.pyc')
Write-Success 'hexbench staged'

# ---------------------------------------------------------------------------
# Step 14: PyInstaller launchers.
#
# Both are small stdlib-only bootstrappers that resolve the runtime staged
# beside them. Hexbench is deliberately NOT built from src/hexbench/hexbench.spec
# here: that spec freezes the editor with an interpreter of its own for
# standalone distribution, which inside the installer would duplicate the
# runtime, webview and hexcore this stage already carries.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 14/14: building the launchers...'
$Launchers = @(
    @{ Spec = 'packaging/launcher/launcher.spec'; Exe = 'Intellicrack.exe'; What = 'launcher' }
    @{ Spec = 'packaging/launcher/hexbench_launcher.spec'; Exe = 'Hexbench.exe'; What = 'hexbench launcher' }
)
foreach ($Launcher in $Launchers) {
    $LauncherSpec = Join-Path $RepoRoot ($Launcher.Spec -replace '/', '\')
    Assert-Source -Path $LauncherSpec -What $Launcher.Spec
    Push-Location $RepoRoot
    try {
        & pixi run pyinstaller $Launcher.Spec
        if ($LASTEXITCODE -ne 0) {
            throw "pyinstaller failed for $($Launcher.Spec) (exit $LASTEXITCODE)"
        }
    } finally {
        Pop-Location
    }
    $LauncherExe = Join-Path $RepoRoot "dist\$($Launcher.Exe)"
    Assert-Produced -Path $LauncherExe -What "built $($Launcher.What) $($Launcher.Exe)"
    $StagedExe = Join-Path $Stage $Launcher.Exe
    Copy-Item -LiteralPath $LauncherExe -Destination $StagedExe -Force
    Assert-Produced -Path $StagedExe -What "staged $($Launcher.Exe)"
    Invoke-OptionalSign -Path $StagedExe -What $Launcher.Exe
    Write-Success "$($Launcher.What) staged"
}

# ---------------------------------------------------------------------------
# Finalize: single-source the installer version and stamp build provenance.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Finalizing: version stamp and build metadata...'

# Derive the installer version defines from the single source of truth so the
# .iss never carries a hand-typed version. intellicrack.iss #includes the file
# written here; tests/packaging/test_version_consistency.py gates that every
# copy of the version across the repo agrees.
$MetadataPath = Join-Path $RepoRoot 'src\intellicrack\_metadata.py'
Assert-Source -Path $MetadataPath -What '_metadata.py'
$VersionMatch = Select-String -LiteralPath $MetadataPath -Pattern '__version__:\s*str\s*=\s*"([^"]+)"' |
    Select-Object -First 1
if (-not $VersionMatch) { throw 'could not read __version__ from _metadata.py' }
$AppVersion = $VersionMatch.Matches[0].Groups[1].Value
$Release = ($AppVersion -replace '(?i)(a|b|rc|\.dev|\.post)\d+.*$', '')
$Parts = @($Release -split '\.')
while ($Parts.Count -lt 4) { $Parts += '0' }
$AppVerNumeric = ($Parts[0..3] -join '.')

$VersionIssPath = Join-Path $RepoRoot 'packaging\version.generated.iss'
$VersionIssLines = @(
    '; AUTO-GENERATED by packaging/stage.ps1 from src/intellicrack/_metadata.py.'
    '; Do not edit by hand: packaging/intellicrack.iss #includes this file, and'
    '; tests/packaging/test_version_consistency.py gates that every copy of the'
    '; version across the repository agrees with pyproject.toml.'
    "#define AppVersion `"$AppVersion`""
    "#define AppVerNumeric `"$AppVerNumeric`""
)
[System.IO.File]::WriteAllText(
    $VersionIssPath,
    (($VersionIssLines -join "`r`n") + "`r`n"),
    (New-Object System.Text.UTF8Encoding($false)))
Write-Success "version.generated.iss written ($AppVersion / $AppVerNumeric)"

# Stamp the staged app tree with the exact commit it was built from so every
# artifact is traceable. build-info.json lives under build/stage (never tracked).
$Commit = (& git -C $RepoRoot rev-parse HEAD 2>$null)
$Short = (& git -C $RepoRoot rev-parse --short HEAD 2>$null)
$Porcelain = (& git -C $RepoRoot status --porcelain 2>$null)
$Dirty = [bool]$Porcelain
if ($Dirty) { Write-Warning 'Working tree is dirty; build-info.json will record dirty=true' }
$BuildInfo = [ordered]@{
    commit    = "$Commit"
    short     = "$Short"
    dirty     = $Dirty
    version   = $AppVersion
    built_utc = (Get-Date).ToUniversalTime().ToString('o')
}
$BuildInfoPath = Join-Path $Stage 'app\build-info.json'
$BuildInfo | ConvertTo-Json | Set-Content -LiteralPath $BuildInfoPath -Encoding UTF8
Assert-Produced -Path $BuildInfoPath -What 'staged build-info.json'
Write-Success "build-info stamped: $Short (dirty=$Dirty)"

Write-Footer 'Stage build complete' $StartTime
