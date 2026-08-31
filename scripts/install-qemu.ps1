$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/common.ps1"

$startTime = Get-Date

Write-Step 'QEMU' "Creating tools directory..."
try {
    if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }
    if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }
    Write-Success "Tools directory ready"
} catch {
    Write-Fail "Directory creation failed: $_"
    exit 1
}

Write-Step 'QEMU' "Checking existing QEMU installation..."
$existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (!$existingQemu) {
    $existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-img.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($existingQemu) {
    Write-Success "QEMU already installed at $($existingQemu.DirectoryName)"
    exit 0
}

Write-Step 'QEMU' "Fetching QEMU release page..."
$maxRetries = 3
$html = $null
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        $html = Invoke-WebRequest -Uri "https://qemu.weilnetz.de/w64/" -UseBasicParsing -TimeoutSec 30
        break
    } catch {
        if ($i -eq $maxRetries) { Write-Fail "Failed to fetch QEMU release page after $maxRetries attempts: $_"; exit 1 }
        Write-Progress "Retry $i/$maxRetries..."
        Start-Sleep -Seconds 2
    }
}

$links = $html.Links | Where-Object { $_.href -match 'qemu-w64-setup-.*\.exe$' } |
    Sort-Object { $_.href } -Descending | Select-Object -First 1
if (!$links) { Write-Fail "Could not find QEMU installer on release page"; exit 1 }

$installerName = $links.href
$installerUrl = "https://qemu.weilnetz.de/w64/$installerName"
Write-Success "Found: $installerName"

$installerPath = Join-Path "tools" $installerName

Write-Step 'QEMU' "Downloading $installerName..."
$ProgressPreference = 'SilentlyContinue'
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -TimeoutSec 600
        if (-not (Test-Path $installerPath)) { throw "Download file not found" }
        $actualSize = (Get-Item $installerPath).Length
        if ($actualSize -lt 10000000) { throw "Downloaded file too small ($actualSize bytes)" }
        break
    } catch {
        if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }
        Write-Progress "Retry $i/$maxRetries..."
        if (Test-Path $installerPath) { Remove-Item $installerPath -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 5
    }
}
Write-Success "Download complete"

Write-Step 'QEMU' "Installing QEMU (this may take a minute)..."
try {
    $installDir = Join-Path (Get-Location) "tools\qemu"
    if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
    $process = Start-Process -FilePath $installerPath -ArgumentList "/S", "/D=$installDir" -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -ne 0) { throw "Installer exited with code $($process.ExitCode)" }
    Start-Sleep -Seconds 2
    $qemuExe = Get-ChildItem -Path $installDir -Recurse -Filter "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$qemuExe) {
        $qemuExe = Get-ChildItem -Path $installDir -Recurse -Filter "qemu-img.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (!$qemuExe) { throw "QEMU executables not found after installation" }
    Write-Success "Installation complete"
} catch {
    Write-Fail "Installation failed: $_"
    exit 1
}

Write-Step 'QEMU' "Cleaning up..."
try {
    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    Write-Success "Cleanup complete"
} catch {
    Write-Progress "Cleanup warning: $_"
}

$e = [char]27
$elapsed = ((Get-Date) - $startTime).TotalSeconds
Write-Host "`n${e}[32mQEMU installed to tools\qemu${e}[0m ${e}[90m($("{0:N1}" -f $elapsed)s)${e}[0m"
