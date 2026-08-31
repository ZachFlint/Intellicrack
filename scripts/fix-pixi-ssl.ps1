param(
    [string]$EnvPrefix = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date
Write-Banner "Fix Pixi SSL_CERT_DIR"

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
Write-Step 'SSL' "Env prefix: $EnvPrefix"

$bundle = Join-Path $EnvPrefix 'Library\ssl\cacert.pem'
$certsDir = Join-Path $EnvPrefix 'Library\ssl\certs'

if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) {
    Write-Fail "CA bundle not found: $bundle"
    Write-Fail "The conda-forge 'ca-certificates' package may be missing from this env."
    exit 1
}
$bundleSizeKB = [math]::Round((Get-Item -LiteralPath $bundle).Length / 1KB, 1)
Write-Success "Found bundle: cacert.pem ($bundleSizeKB KB)"

if (-not (Test-Path -LiteralPath $certsDir -PathType Container)) {
    Write-Step 'SSL' "Creating certs directory..."
    New-Item -ItemType Directory -Path $certsDir -Force | Out-Null
    Write-Success "Created: $certsDir"
}

$existing = Get-ChildItem -LiteralPath $certsDir -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne '.keep' -and $_.Extension -in '.pem', '.crt', '.cer', '.der' }

if ($existing) {
    Write-Skip "certs\ already populated with $($existing.Count) cert file(s): $($existing.Name -join ', ')"
    Write-Footer "Fix Pixi SSL_CERT_DIR (no-op)" $startTime
    exit 0
}

$linkPath = Join-Path $certsDir 'cacert.pem'
$relativeTarget = '..\cacert.pem'
$linked = $false

Write-Step 'SSL' "Attempting symlink: certs\cacert.pem -> $relativeTarget"
try {
    $linkItem = New-Item -ItemType SymbolicLink -Path $linkPath -Target $relativeTarget -ErrorAction Stop
    if ($linkItem.LinkType -eq 'SymbolicLink') {
        Write-Success "Symlink created (tracks future ca-certificates updates)"
        $linked = $true
    } else {
        Write-Skip "Item created but not registered as SymbolicLink; falling back to copy"
        Remove-Item -LiteralPath $linkPath -Force -ErrorAction SilentlyContinue
    }
} catch {
    $errMsg = $_.Exception.Message
    if ($errMsg -match 'privilege|administrator|developer mode') {
        Write-Skip "Symlink requires admin or Developer Mode; falling back to copy"
    } else {
        Write-Skip "Symlink failed: $errMsg; falling back to copy"
    }
    if (Test-Path -LiteralPath $linkPath) {
        Remove-Item -LiteralPath $linkPath -Force -ErrorAction SilentlyContinue
    }
}

if (-not $linked) {
    Write-Step 'SSL' "Copying bundle: cacert.pem -> certs\cacert.pem"
    try {
        Copy-Item -LiteralPath $bundle -Destination $linkPath -Force -ErrorAction Stop
        $copySizeKB = [math]::Round((Get-Item -LiteralPath $linkPath).Length / 1KB, 1)
        Write-Success "Bundle copied ($copySizeKB KB)"
    } catch {
        Write-Fail "Copy failed: $($_.Exception.Message)"
        exit 1
    }
}

Write-Step 'SSL' "Verifying destination contains parseable certificates..."
try {
    $content = Get-Content -LiteralPath $linkPath -Raw -ErrorAction Stop
} catch {
    Write-Fail "Cannot read destination file: $($_.Exception.Message)"
    exit 1
}
$blocks = ([regex]::Matches($content, '-----BEGIN CERTIFICATE-----')).Count
if ($blocks -lt 1) {
    Write-Fail "Destination contains no '-----BEGIN CERTIFICATE-----' blocks"
    exit 1
}
Write-Success "Verified: $blocks certificate block(s) parseable by rustls_native_certs"

Write-Step 'SSL' "Open a fresh 'pixi shell' or 'pixi run' to confirm the WARN is gone."
Write-Footer "Fix Pixi SSL_CERT_DIR" $startTime
