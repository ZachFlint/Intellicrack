$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

function Select-InnoSetupAsset {
    <#
    .SYNOPSIS
        Choose the Inno Setup installer executable from a release's asset names.
    .DESCRIPTION
        A jrsoftware/issrc release publishes several assets: the Inno Setup 7 line
        ships per-architecture installers (innosetup-<ver>-x64.exe and -x86.exe),
        while the Inno Setup 6 line ships a single un-suffixed innosetup-<ver>.exe.
        Every installer is accompanied by a detached signature (.exe.asc), and the
        release also carries non-installer assets (source archives, checksums).
        This returns the real installer to fetch: only names of the form
        innosetup-<...>.exe qualify, so a signature or an archive can never win;
        the 32-bit build is dropped in favour of the 64-bit or un-suffixed
        installer, and is chosen only when it is the sole installer offered.
    .PARAMETER AssetNames
        The asset file names from the GitHub release (``$release.assets.name``).
    .OUTPUTS
        System.String. The chosen installer file name, or ``$null`` when the
        release exposes no Inno Setup installer.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$AssetNames
    )
    $installers = @($AssetNames | Where-Object { $_ -match '(?i)^innosetup-.*\.exe$' })
    $preferred = @($installers | Where-Object { $_ -notmatch '(?i)-x86\.exe$' })
    $candidates = if ($preferred.Count -gt 0) { $preferred } else { $installers }
    return ($candidates | Sort-Object -Descending | Select-Object -First 1)
}

$startTime = Get-Date
Write-Banner "Inno Setup"

$installDir = Join-Path (Get-Location).Path 'tools\innosetup'
$isccPath = Join-Path $installDir 'ISCC.exe'

Write-Step 'INNO' "Creating tools directory..."
try {
    if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }
    if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }
    Write-Success "Tools directory ready"
} catch {
    Write-Fail "Directory creation failed: $_"
    exit 1
}

Write-Step 'INNO' "Checking existing Inno Setup installation..."
if (Test-Path $isccPath) {
    Write-Success "Inno Setup already installed at $installDir"
    exit 0
}

Write-Step 'INNO' "Fetching latest release from GitHub..."
$headers = @{ 'Accept' = 'application/vnd.github+json'; 'User-Agent' = 'intellicrack-installer' }
$token = if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } elseif ($env:GH_TOKEN) { $env:GH_TOKEN } else { $null }
if ($token) { $headers['Authorization'] = "Bearer $token" }

$maxRetries = 3
$release = $null
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/jrsoftware/issrc/releases/latest" -Headers $headers -TimeoutSec 30
        break
    } catch {
        if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }
        Write-Progress "Retry $i/$maxRetries..."
        Start-Sleep -Seconds 2
    }
}

$assetName = Select-InnoSetupAsset -AssetNames @($release.assets.name)
if (!$assetName) { Write-Fail "No Inno Setup installer asset found in latest release '$($release.tag_name)'"; exit 1 }

$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
$downloadUrl = $asset.browser_download_url
$fileSize = [math]::Round($asset.size / 1MB, 1)
$installerPath = Join-Path "tools" $assetName
Write-Success "Found: $assetName ($fileSize MB, release $($release.tag_name))"

Write-Step 'INNO' "Downloading $assetName..."
$ProgressPreference = 'SilentlyContinue'
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -TimeoutSec 600
        if (-not (Test-Path $installerPath)) { throw "Download file not found" }
        $actualSize = (Get-Item $installerPath).Length
        if ($actualSize -lt 1000000) { throw "Downloaded file too small ($actualSize bytes)" }
        break
    } catch {
        if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }
        Write-Progress "Retry $i/$maxRetries..."
        if (Test-Path $installerPath) { Remove-Item $installerPath -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 5
    }
}
Write-Success "Download complete"

Write-Step 'INNO' "Installing Inno Setup (portable) to $installDir..."
try {
    if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/PORTABLE=1', "/DIR=$installDir")
    $process = Start-Process -FilePath (Resolve-Path $installerPath).Path -ArgumentList $arguments -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -ne 0) { throw "Installer exited with code $($process.ExitCode)" }
    if (-not (Test-Path $isccPath)) { throw "ISCC.exe not found after installation at $isccPath" }
    Write-Success "Installation complete"
} catch {
    Write-Fail "Installation failed: $_"
    exit 1
}

Write-Step 'INNO' "Verifying compiler..."
$versionOutput = & $isccPath /? 2>&1 | Select-Object -First 1
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
    Write-Fail "ISCC.exe did not run cleanly (exit $LASTEXITCODE)"
    exit 1
}
Write-Success "Compiler verified: $versionOutput"

Write-Step 'INNO' "Cleaning up..."
try {
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    Write-Success "Cleanup complete"
} catch {
    Write-Progress "Cleanup warning: $_"
}

Write-Footer "Inno Setup installed to tools\innosetup" $startTime
