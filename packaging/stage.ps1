#Requires -Version 7
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipJdkDownload,
    [switch]$SkipGuestImage,
    [switch]$SkipSigning,
    [ValidateSet('release', 'debug')]
    [string]$HexcoreProfile = 'release',
    [ValidateRange(1, 10)]
    [int]$JdkDownloadRetries = 4
)

$ErrorActionPreference = 'Stop'
# PowerShell 7.4+ defaults $PSNativeCommandUseErrorActionPreference to $true, which
# turns any non-zero native exit into a terminating error before the caller can read
# $LASTEXITCODE. This script checks every native exit code explicitly, and robocopy
# reports success as a bitmask where only >= 8 is a failure (1 means "files copied"),
# so that default would abort a healthy staging run. Exit-code handling stays with
# the explicit checks at each call site.
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest
. "$PSScriptRoot/../scripts/common.ps1"

# Intellicrack installer staging build script.
#
# Assembles the fixed <repo>/build/stage layout that packaging/intellicrack.iss
# consumes verbatim. Every expected source is asserted before use: a missing
# source is a hard failure (throw / nonzero exit), never a silent skip. The
# script is idempotent - it recreates build/stage from scratch on each run.
#
# Every parameter is opt-in: with no arguments the script behaves exactly as it
# did before they existed. The -Skip* switches drop optional or network-bound
# steps for a CI job that only needs the rest, and each one warns that the
# resulting stage is incomplete rather than pretending it is shippable.

$StartTime = Get-Date

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Stage = Join-Path $RepoRoot 'build\stage'
$BuildRoot = Join-Path $RepoRoot 'build'
$GitPath = (Get-Command git -ErrorAction SilentlyContinue)?.Source

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

function Get-ContentStamp {
    <#
    .SYNOPSIS
        Return the moment a tracked file's content last changed, as a Unix time.
    .DESCRIPTION
        Ordering a committed input against a committed output cannot use raw
        mtimes: a fresh clone stamps every working-tree file with the checkout
        time, so the comparison would be decided by checkout order. Git history
        gives the same answer on every clone, so it is preferred. A path with
        uncommitted changes, or any path git cannot date (git absent, no history
        for the path, a source export with no repository), falls back to its
        filesystem write time, which is the only signal available there.
    .PARAMETER Path
        The existing file to date.
    .OUTPUTS
        System.Int64. Seconds since the Unix epoch.
    #>
    param(
        [Parameter(Mandatory)][string]$Path
    )
    if ($script:GitPath) {
        # A host that promotes a nonzero native exit code to a terminating error
        # would turn "this is not a repository" into a build failure instead of
        # the documented fallback, so the interrogation is contained here.
        try {
            $dirty = @(& $script:GitPath -C $script:RepoRoot status --porcelain -- $Path 2>$null)
            if ($dirty.Count -eq 0) {
                $committed = @(& $script:GitPath -C $script:RepoRoot log -1 --format=%ct -- $Path 2>$null)
                if ($committed.Count -gt 0 -and $committed[0]) {
                    return [long]$committed[0]
                }
            }
        } catch {
            Write-Progress "git could not date $Path ($($_.Exception.Message)); falling back to its write time"
        }
    }
    $written = (Get-Item -LiteralPath $Path).LastWriteTimeUtc
    return [long](($written - [datetime]::UnixEpoch).TotalSeconds)
}

function Get-CondaOwnedEntry {
    <#
    .SYNOPSIS
        Map every top-level site-packages entry to the conda package that owns it.
    .DESCRIPTION
        The runtime is a copy of a pixi (conda) environment, and conda-meta
        records exactly which files each conda package laid down. Those packages
        are the base of the runtime - the interpreter, setuptools, jinja2,
        pygments and friends - so nothing may relocate them out of it, whatever
        a pip-metadata closure computed over the same directory concludes.
    .PARAMETER EnvironmentRoot
        Root of the conda environment whose conda-meta records are read.
    .OUTPUTS
        System.Collections.Hashtable. Entry name -> owning conda package name.
    #>
    param(
        [Parameter(Mandatory)][string]$EnvironmentRoot
    )
    $metaDir = Join-Path $EnvironmentRoot 'conda-meta'
    if (-not (Test-Path -LiteralPath $metaDir)) {
        throw "Environment carries no conda-meta records: $metaDir"
    }
    $owners = @{}
    foreach ($record in Get-ChildItem -LiteralPath $metaDir -Filter '*.json' -File) {
        $data = Get-Content -LiteralPath $record.FullName -Raw | ConvertFrom-Json
        $properties = $data.PSObject.Properties.Name
        if ($properties -notcontains 'files' -or -not $data.files) { continue }
        $package = $record.BaseName
        if ($properties -contains 'name' -and $data.name) { $package = [string]$data.name }
        foreach ($file in $data.files) {
            $normalized = ([string]$file).Replace('\', '/')
            if ($normalized -notmatch '^lib/site-packages/([^/]+)') { continue }
            $entry = $Matches[1]
            if (-not $owners.ContainsKey($entry)) { $owners[$entry] = $package }
        }
    }
    return $owners
}

Write-Banner 'Intellicrack Stage Build'
Write-Step 'STAGE' "Repo root: $RepoRoot"
Write-Step 'STAGE' "Stage dir: $Stage"

# ---------------------------------------------------------------------------
# Preflight: the committed wizard images must not be stale.
#
# packaging/wizard/*.png are generated from the app icon by
# packaging/wizard/generate_banners.ps1 and committed; intellicrack.iss consumes
# those committed files directly. Regenerating them is a documented manual step,
# so changing the icon and forgetting it ships an installer whose branding is a
# release behind, with nothing to notice it. The generator is parsed rather than
# restated so the gate follows a change of icon path, background directory or
# selected background instead of silently guarding the wrong files.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Preflight: checking wizard image freshness...'
$WizardDir = Join-Path $RepoRoot 'packaging\wizard'
$WizardGenerator = Join-Path $WizardDir 'generate_banners.ps1'
Assert-Source -Path $WizardGenerator -What 'wizard image generator'
$GeneratorText = Get-Content -LiteralPath $WizardGenerator -Raw

if ($GeneratorText -notmatch "Join-Path\s+\`$Here\s+'([^']*icon\.ico)'") {
    throw ('packaging/wizard/generate_banners.ps1 no longer resolves its icon through Join-Path $Here; ' +
        'update the freshness gate in packaging/stage.ps1')
}
$WizardIcon = [System.IO.Path]::GetFullPath((Join-Path $WizardDir $Matches[1]))

if ($GeneratorText -notmatch "\`$BgDir\s*=\s*Join-Path\s+\`$Here\s+'([^']+)'") {
    throw 'packaging/wizard/generate_banners.ps1 no longer declares $BgDir; update the freshness gate in packaging/stage.ps1'
}
$WizardBackgroundDir = Join-Path $WizardDir $Matches[1]

if ($GeneratorText -notmatch "\`$SelectedKey\s*=\s*'([^']+)'") {
    throw 'packaging/wizard/generate_banners.ps1 no longer declares $SelectedKey; update the freshness gate in packaging/stage.ps1'
}
$WizardSelectedKey = $Matches[1]
if ($GeneratorText -notmatch "Key\s*=\s*'$([regex]::Escape($WizardSelectedKey))'[^}]*File\s*=\s*'([^']+)'") {
    throw "packaging/wizard/generate_banners.ps1 selects the background '$WizardSelectedKey' but declares no file for it"
}
$WizardBackground = Join-Path $WizardBackgroundDir $Matches[1]

$WizardImageNames = @([regex]::Matches($GeneratorText, "Join-Path\s+\`$Here\s+'([^']+\.png)'") |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
if ($WizardImageNames.Count -eq 0) {
    throw 'packaging/wizard/generate_banners.ps1 writes no wizard image beside itself; update the freshness gate in packaging/stage.ps1'
}

# The generator rewrites every image beside it in a single run, so the freshness
# question is whether that run happened after the last source change - not
# whether one particular image changed. Comparing the newest source against the
# newest image answers exactly that, and stays right when a re-run leaves one
# image byte-identical (git then reports its content as older than the icon's
# even though it was regenerated from it).
$WizardSources = @($WizardIcon, $WizardGenerator, $WizardBackground)
$WizardNewestSource = ''
$WizardNewestSourceStamp = [long]::MinValue
foreach ($wizardSource in $WizardSources) {
    Assert-Source -Path $wizardSource -What "wizard image source $(Split-Path -Leaf $wizardSource)"
    $stamp = Get-ContentStamp -Path $wizardSource
    if ($stamp -gt $WizardNewestSourceStamp) {
        $WizardNewestSourceStamp = $stamp
        $WizardNewestSource = $wizardSource
    }
}
$WizardNewestImageStamp = [long]::MinValue
foreach ($imageName in $WizardImageNames) {
    $imagePath = Join-Path $WizardDir $imageName
    Assert-Source -Path $imagePath -What "committed wizard image $imageName"
    $stamp = Get-ContentStamp -Path $imagePath
    if ($stamp -gt $WizardNewestImageStamp) { $WizardNewestImageStamp = $stamp }
}
if ($WizardNewestSourceStamp -gt $WizardNewestImageStamp) {
    $staleSource = $WizardNewestSource -replace [regex]::Escape($RepoRoot + '\'), ''
    throw ("Stale wizard images: $staleSource changed after packaging/wizard/$($WizardImageNames -join ', ') were last written. " +
        'The installer ships those committed images verbatim, so regenerate them with: pwsh packaging\wizard\generate_banners.ps1')
}
Write-Success "wizard images current ($($WizardImageNames.Count) checked against $($WizardSources.Count) sources)"

# ---------------------------------------------------------------------------
# Step 1: recreate build/stage clean.
# ---------------------------------------------------------------------------
Write-Step 'STAGE' 'Step 1/14: recreating build/stage clean...'
if (Test-Path -LiteralPath $Stage) {
    if ($PSCmdlet.ShouldProcess($Stage, 'Remove the previously staged tree')) {
        Remove-Item -LiteralPath $Stage -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
Write-Success 'build/stage recreated'

# ---------------------------------------------------------------------------
# Step 2: runtime = trimmed copy of the slim pixi runtime environment.
# ---------------------------------------------------------------------------
# The shipped runtime is staged from the dedicated `runtime` pixi environment,
# which composes only the default (runtime) feature. The build/dev/test/docs/
# profile/tooling features - the Rust and clang toolchains, cmake/ninja, the
# PyPI linters/formatters/test runners - live in the `default` environment used
# for development and the maturin/pyinstaller build steps, and are absent here,
# so ~2 GB of build-only payload never reaches the installer.
Write-Step 'STAGE' 'Step 2/14: staging runtime (trimmed pixi env)...'
$PixiEnv = Join-Path $RepoRoot '.pixi\envs\runtime'
if (-not (Test-Path -LiteralPath (Join-Path $PixiEnv 'python.exe'))) {
    Write-Progress 'Runtime pixi environment missing; provisioning it (pixi install --locked -e runtime)...'
    Push-Location $RepoRoot
    try {
        # --locked: a plain `pixi install` silently updates pixi.lock when the
        # manifest has drifted, which would mutate a tracked file mid-build and
        # ship a runtime that differs from the locked one. Fail loudly instead.
        & pixi install --locked -e runtime
        if ($LASTEXITCODE -ne 0) {
            throw "pixi install --locked -e runtime failed (exit $LASTEXITCODE); run 'pixi install -e runtime' and commit the updated pixi.lock"
        }
    } finally {
        Pop-Location
    }
}
Assert-Source -Path $PixiEnv -What 'pixi runtime env'
Assert-Source -Path (Join-Path $PixiEnv 'python.exe') -What 'runtime python.exe'
$RuntimeDir = Join-Path $Stage 'runtime'
# pixi quarantines superseded binaries it cannot delete in-place into a top-level
# .trash directory (old DLL/exe versions with a hash suffix). Those are dead
# weight that nothing loads, so excluding them keeps ~100 MB of duplicate
# binaries out of the shipped runtime and the installer.
Invoke-Robocopy -Source $PixiEnv -Destination $RuntimeDir -ExcludeDirs @('.trash')
$RuntimeSitePackages = Join-Path $RuntimeDir 'Lib\site-packages'
Assert-Produced -Path (Join-Path $RuntimeDir 'python.exe') -What 'staged runtime python.exe'
Assert-Produced -Path $RuntimeSitePackages -What 'staged runtime site-packages'

# The runtime is staged from the slim `runtime` pixi environment, which never
# carried the dev/test/docs/profile toolchains, so there is nothing to prune per
# distribution here - the former prune_dev closure step has been retired.
Write-Progress 'Removing node.exe, *.pdb, *.pyd.old_*, and __pycache__ from runtime...'
Remove-MatchingItem -Root $RuntimeDir -Filter 'node.exe'
Remove-MatchingItem -Root $RuntimeDir -Filter '*.pdb'
Remove-MatchingItem -Root $RuntimeDir -Filter '*.pyd.old_*'
Remove-MatchingItem -Root $RuntimeDir -Filter '__pycache__' -Directories

# Static import libraries (*.lib), C headers and bundled package test suites are
# link/compile/test-time artifacts that the frozen runtime never loads at
# runtime; share/doc and share/man are documentation. Stripping them removes
# ~75 MB of dead weight from the shipped runtime. Test-dir removal is scoped to
# site-packages so it can only touch third-party package test suites.
#
# Header removal is scoped to the interpreter's own include trees rather than a
# recursive name match: several shipped packages keep an `include` directory that
# their own code resolves at runtime (triton's Intel XPU backend builds a SYCL
# helper from torch\include, triton\backends\intel\include and
# opt\compiler\include), so a blind recursive delete would break them.
Write-Progress 'Removing static import libs, C headers, bundled test suites and docs from runtime...'
Remove-MatchingItem -Root $RuntimeDir -Filter '*.lib'
Remove-MatchingItem -Root $RuntimeSitePackages -Filter 'tests' -Directories
Remove-MatchingItem -Root $RuntimeSitePackages -Filter 'test' -Directories
foreach ($deadDir in @('include', 'Library\include', 'share\doc', 'share\man')) {
    $deadPath = Join-Path $RuntimeDir $deadDir
    if (Test-Path -LiteralPath $deadPath) {
        Remove-Item -LiteralPath $deadPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($pth in @('_editable_impl_intellicrack.pth', 'a1_coverage.pth')) {
    $pthPath = Join-Path $RuntimeSitePackages $pth
    if (Test-Path -LiteralPath $pthPath) {
        Remove-Item -LiteralPath $pthPath -Force
        Write-Progress "Removed $pth"
    }
}

# The pip/distlib console-script launchers under Scripts\ embed the absolute
# build-interpreter path (D:\...\.pixi\envs\runtime\python.exe). On a target
# that path does not exist, and worse, if it is user-writable anyone who plants
# a python.exe there gains code execution through any invoked shim. The
# application never runs these shims (it launches python via -m), so every shim
# that embeds the build interpreter is stripped here and Scripts\ is dropped
# from the launchers' child PATH.
#
# Every file is checked, not just *.exe: the entry-point scripts pip installs
# without a launcher (bottle.py, readelf.py, dul-receive-pack, dul-upload-pack)
# carry the same absolute path in a shebang line. Scripts\ is not on sys.path,
# so removing them cannot break an import.
Write-Progress 'Removing console-script shims that embed the build interpreter path...'
$ScriptsDir = Join-Path $RuntimeDir 'Scripts'
$ShimsRemoved = 0
if (Test-Path -LiteralPath $ScriptsDir) {
    foreach ($shim in Get-ChildItem -LiteralPath $ScriptsDir -File -Force -ErrorAction SilentlyContinue) {
        $bytes = [System.IO.File]::ReadAllBytes($shim.FullName)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        if ($ascii.Contains($PixiEnv)) {
            Remove-Item -LiteralPath $shim.FullName -Force
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
$MaturinArgs = @('build')
if ($HexcoreProfile -eq 'release') {
    $MaturinArgs += '--release'
} else {
    Write-Warning "hexcore is being built with the '$HexcoreProfile' profile; the resulting stage is for iteration only, never for release"
}
Push-Location $HexcoreDir
try {
    & pixi run maturin @MaturinArgs
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

# ml_split.py reasons over pip metadata alone, so it can hand back an entry that
# the conda half of the environment owns: torch declares an unconditional
# setuptools dependency while no core pip root declares one outside an extra, so
# setuptools - and jinja2, markupsafe and pygments through the same route - come
# back as "ML-only". They are not: conda installed them as part of the base
# runtime, and relocating them would carve pieces out of the interpreter's own
# environment. The conda-meta records staged with the runtime say who owns what,
# so they get the final word on what may move.
$CondaOwners = Get-CondaOwnedEntry -EnvironmentRoot $RuntimeDir
$VetoedEntries = @($MlEntries | Where-Object { $CondaOwners.ContainsKey($_) })
foreach ($vetoed in $VetoedEntries) {
    Write-Warning "Keeping '$vetoed' in runtime: the conda package '$($CondaOwners[$vetoed])' installs it as part of the base runtime"
}
$MlEntries = @($MlEntries | Where-Object { -not $CondaOwners.ContainsKey($_) })

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

foreach ($ownedEntry in $CondaOwners.Keys) {
    if (Test-Path -LiteralPath (Join-Path $MlOverlaySite $ownedEntry)) {
        throw ("ML split failed: '$ownedEntry' reached ml_overlay, but the conda package " +
            "'$($CondaOwners[$ownedEntry])' installs it as part of the base runtime")
    }
}

# The assertions above name only the packages this split exists to remove and the
# ones it must never touch. The failure that reaches a user is a third one: an entry the core
# runtime still needs went to ml_overlay, so an installation without the optional
# ML component cannot start. ml_split.py computes the core side of the closure
# from [project.dependencies], which does not describe this runtime - PyQt6,
# structlog and tiktoken are all imported by the application and named nowhere in
# it - so that closure cannot be trusted to have kept everything back. This gate
# asks the staged runtime itself instead: the application source is the source of
# truth for what it imports, and the runtime must satisfy every one of those
# imports with ml_overlay absent, exactly as a core-only installation will.
Write-Progress 'Verifying the core runtime still satisfies the application without ml_overlay...'
$CoreGateScript = Join-Path $BuildRoot '_core_runtime_gate.py'
$CoreGateSource = @'
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Verify the staged core runtime stands on its own without ``ml_overlay``.

Generated by ``packaging/stage.ps1`` after the ML split and run with the staged
runtime's own ``python.exe``; it is a build artifact and is never shipped.

Two checks, both derived from the staged application source rather than from a
hand-written list of packages:

1. Every unconditional module-level third-party import in the staged application
   source must resolve. An import that is a direct child of a module body is one
   the interpreter always executes when that module is loaded, so the core
   runtime alone has to satisfy it. Genuinely optional dependencies are guarded
   with ``try``/``except ImportError`` throughout the codebase and are therefore
   excluded here, which is what keeps ``torch`` and ``transformers`` from being
   demanded of a runtime that deliberately no longer carries them.
2. The production startup chain - the modules ``python -m intellicrack`` loads
   before any window exists - must import.

A failure means the split relocated something the core runtime still needs, so a
user who does not select the optional ML component gets an installation that
cannot start.
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path


APP_PACKAGE = "intellicrack"
STARTUP_MODULES = ("intellicrack.__main__", "intellicrack.main")


def module_level_imports(source: Path) -> set[str]:
    """Return the unconditionally executed module-level imports of one file.

    Args:
        source: The ``.py`` file to parse.

    Returns:
        set[str]: Dotted module names imported at the top level of the module
        body, excluding imports nested in ``try``, ``if`` or function scopes.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


def third_party_surface(app_src: Path) -> list[str]:
    """Collect the third-party import surface of the staged application source.

    Args:
        app_src: The staged ``app/src`` directory.

    Returns:
        list[str]: Sorted dotted module names that belong to neither the standard
        library nor the application package itself.
    """
    names: set[str] = set()
    for source in sorted((app_src / APP_PACKAGE).rglob("*.py")):
        names |= module_level_imports(source)
    return sorted(
        name
        for name in names
        if name.split(".")[0] not in sys.stdlib_module_names and name.split(".")[0] != APP_PACKAGE
    )


def import_all(names: list[str]) -> list[str]:
    """Import every named module, collecting one message per failure.

    Args:
        names: Dotted module names to import.

    Returns:
        list[str]: A message for each module that could not be imported.
    """
    failures: list[str] = []
    for name in names:
        try:
            importlib.import_module(name)
        except Exception as error:
            failures.append(f"{name}: {type(error).__name__}: {error}")
    return failures


def main(argv: list[str]) -> int:
    """Check the staged core runtime against the staged application source.

    Args:
        argv: ``argv[0]`` is the staged ``app/src`` directory.

    Returns:
        int: ``0`` when the core runtime is self-sufficient, ``1`` otherwise.
    """
    app_src = Path(argv[0])
    surface = third_party_surface(app_src)
    if not surface:
        sys.stderr.write(
            "ERROR: no third-party module-level imports found under "
            f"{app_src / APP_PACKAGE}; the gate would pass vacuously\n"
        )
        return 1
    failures = import_all(surface)
    sys.path.insert(0, str(app_src))
    failures += import_all(list(STARTUP_MODULES))
    for failure in failures:
        sys.stderr.write(f"ERROR: the core runtime cannot import {failure}\n")
    if failures:
        sys.stderr.write(
            f"ERROR: {len(failures)} import(s) failed with ml_overlay absent; the ML split "
            "relocated a package the core runtime still needs\n"
        )
        return 1
    sys.stdout.write(
        f"core runtime gate: {len(surface)} third-party module(s) and "
        f"{len(STARTUP_MODULES)} startup module(s) import cleanly\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'@
if ($PSCmdlet.ShouldProcess($CoreGateScript, 'Write the core-runtime gate script')) {
    [System.IO.File]::WriteAllText(
        $CoreGateScript,
        $CoreGateSource,
        (New-Object System.Text.UTF8Encoding($false)))
}
$AppSrcRoot = Join-Path $Stage 'app\src'
Push-Location (Join-Path $Stage 'app')
try {
    & $RuntimePython $CoreGateScript $AppSrcRoot
    $gateCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($gateCode -ne 0) {
    throw ("Core-runtime gate failed (exit $gateCode): the ML split moved something the core " +
        "runtime still needs. The gate script is kept at $CoreGateScript so it can be re-run " +
        'against the staged runtime.')
}
Remove-Item -LiteralPath $CoreGateScript -Force -ErrorAction SilentlyContinue

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
$ToolSubset = @('radare2', 'cutter', 'NASM')
foreach ($tool in $ToolSubset) {
    $toolSrc = Join-Path $RepoRoot "tools\$tool"
    Assert-Source -Path $toolSrc -What "tool $tool"
    $toolDest = Join-Path $Stage "app\tools\$tool"
    Invoke-Robocopy -Source $toolSrc -Destination $toolDest
    Write-Progress "Staged tool: $tool"
}
Write-Warning 'tools/resource_hacker skipped (ResourceHacker.exe is absent from the repo)'
Assert-Produced -Path (Join-Path $Stage 'app\tools\cutter\rizin.exe') -What 'cutter rizin.exe'
Assert-Produced -Path (Join-Path $Stage 'app\tools\radare2\bin\radare2.exe') -What 'radare2.exe'
Assert-Produced -Path (Join-Path $Stage 'app\tools\NASM\nasm.exe') -What 'nasm.exe'
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
if ($SkipJdkDownload) {
    Write-Skip 'Temurin JDK download skipped (-SkipJdkDownload)'
    Write-Warning 'The stage carries no bundled JDK; Ghidra will have no interpreter and the installer must not be built from it'
} else {
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
    for ($attempt = 1; $attempt -le $JdkDownloadRetries; $attempt++) {
        try {
            Invoke-WebRequest -Uri $JdkLock.url -OutFile $JdkZip -TimeoutSec 600
            $Downloaded = $true
            break
        } catch {
            Write-Warning "Temurin download attempt $attempt failed: $($_.Exception.Message)"
            if (Test-Path -LiteralPath $JdkZip) { Remove-Item -LiteralPath $JdkZip -Force -ErrorAction SilentlyContinue }
            if ($attempt -lt $JdkDownloadRetries) { Start-Sleep -Seconds ([int][math]::Pow(2, $attempt)) }
        }
    }
    if (-not $Downloaded) { throw "Temurin JDK download failed after $JdkDownloadRetries attempts: $($JdkLock.url)" }
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
}

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
if ($SkipGuestImage) {
    Write-Skip 'Debian sandbox guest image skipped (-SkipGuestImage)'
    Write-Warning 'The stage carries no guest image; the installer must not be built from it'
} else {
    $GuestSrc = Join-Path $RepoRoot 'tools\qemu\images\debian13-intellicrack.qcow2'
    Assert-Source -Path $GuestSrc -What 'Debian sandbox guest image'
    $GuestDestDir = Join-Path $Stage 'qemu-guest'
    New-Item -ItemType Directory -Path $GuestDestDir -Force | Out-Null
    Copy-Item -LiteralPath $GuestSrc -Destination (Join-Path $GuestDestDir 'debian13-intellicrack.qcow2') -Force
    Assert-Produced -Path (Join-Path $GuestDestDir 'debian13-intellicrack.qcow2') -What 'staged Debian guest'
    Write-Warning 'Debian guest must have qemu-guest-agent installed in-guest to be usable by the sandbox'
    Write-Success 'Debian sandbox guest staged'
}

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
# hexbench keeps its test suite and dev tooling inside its own package tree
# (src/hexbench/tests, gate.ps1, update-deps.ps1, .qodo) rather than under the
# repo-root tests/ dir, so a plain mirror would ship all of it. None of it is
# imported at runtime; hexbench.spec is deliberately unused here (Step 14 builds
# Hexbench.exe from packaging/launcher/hexbench_launcher.spec). Exclude them so
# only the runnable GUI reaches the installer.
Invoke-Robocopy -Source $HexbenchSrc -Destination $HexbenchDest `
    -ExcludeDirs @('__pycache__', 'tests', '.qodo') `
    -ExcludeFiles @('*.pyc', 'gate.ps1', 'update-deps.ps1', 'hexbench.spec')
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
        # --clean discards PyInstaller's cached analysis and its build directory
        # first, so a spec, launcher or runtime change can never be masked by an
        # artifact left over from an earlier build.
        & pixi run pyinstaller --clean $Launcher.Spec
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
    if ($SkipSigning) {
        Write-Skip "$($Launcher.Exe) signing skipped (-SkipSigning)"
    } else {
        Invoke-OptionalSign -Path $StagedExe -What $Launcher.Exe
    }
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
if ($PSCmdlet.ShouldProcess($VersionIssPath, 'Write the generated version defines')) {
    [System.IO.File]::WriteAllText(
        $VersionIssPath,
        (($VersionIssLines -join "`r`n") + "`r`n"),
        (New-Object System.Text.UTF8Encoding($false)))
}
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

# Checksum every staged file so an installer built from this tree can be verified
# offline, file by file, against what the stage actually produced. The manifest
# is written beside build/stage rather than inside it: a manifest that lived in
# the tree would have to list itself, and intellicrack.iss packages the tree
# verbatim, so it would also ship as if it were application content.
Write-Step 'STAGE' 'Finalizing: hashing the staged tree...'
$ManifestPath = Join-Path $BuildRoot 'stage-SHA256SUMS.txt'
$StagePrefix = $Stage.TrimEnd('\') + '\'
$StagedFiles = @(Get-ChildItem -LiteralPath $Stage -Recurse -File -Force)
if ($StagedFiles.Count -eq 0) {
    throw "Refusing to write an empty checksum manifest: no files under $Stage"
}
$StagedByRelative = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
foreach ($staged in $StagedFiles) {
    $relative = $staged.FullName.Substring($StagePrefix.Length).Replace('\', '/')
    if ($StagedByRelative.ContainsKey($relative)) {
        throw "Duplicate staged path while building the checksum manifest: $relative"
    }
    $StagedByRelative[$relative] = $staged.FullName
}
# Ordinal sorting, not the culture-aware default, so the manifest a French or
# Turkish build host produces is byte-for-byte the one an invariant host does.
$RelativePaths = [string[]]@($StagedByRelative.Keys)
[Array]::Sort($RelativePaths, [System.StringComparer]::Ordinal)
$ManifestLines = [System.Collections.Generic.List[string]]::new()
foreach ($relative in $RelativePaths) {
    $digest = (Get-FileHash -LiteralPath $StagedByRelative[$relative] -Algorithm SHA256).Hash.ToLowerInvariant()
    $ManifestLines.Add("$digest  $relative")
}
if ($PSCmdlet.ShouldProcess($ManifestPath, 'Write the staged-tree SHA-256 manifest')) {
    [System.IO.File]::WriteAllText(
        $ManifestPath,
        (($ManifestLines -join "`n") + "`n"),
        (New-Object System.Text.UTF8Encoding($false)))
    Assert-Produced -Path $ManifestPath -What 'staged-tree SHA-256 manifest'
}
Write-Success "SHA-256 manifest written ($($ManifestLines.Count) files): build\stage-SHA256SUMS.txt"

Write-Footer 'Stage build complete' $StartTime
