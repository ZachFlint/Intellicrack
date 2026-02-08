# Intellicrack Commands
# Configure shell for Windows

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

# ==================== INSTALLATION ====================

# Complete installation with all post-install tasks
install:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; $totalSteps = 8; $currentStep = 0; function Write-Step { param($msg) $script:currentStep++; Write-Host "$e[36m[$script:currentStep/$totalSteps]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" -ForegroundColor Red }; Write-Host "`n$e[1;36m=== Intellicrack Installation ===$e[0m`n"; $startTime = Get-Date; Write-Step "Preparing environment..."; if (Test-Path "pixi.lock") { Remove-Item -Force "pixi.lock" -ErrorAction Stop; Write-Success "Removed existing pixi.lock" } else { Write-Success "Environment clean" }; Write-Step "Installing dependencies with pixi..."; try { pixi install; if ($LASTEXITCODE -ne 0) { throw "pixi install failed with exit code $LASTEXITCODE" }; Write-Success "Pixi dependencies installed" } catch { Write-Fail "Pixi installation failed: $_"; exit 1 }; Write-Step "Installing Ghidra..."; try { & just install-ghidra; if ($LASTEXITCODE -ne 0) { throw "install-ghidra failed with exit code $LASTEXITCODE" }; Write-Success "Ghidra ready" } catch { Write-Fail "Ghidra installation failed: $_"; exit 1 }; Write-Step "Installing radare2..."; try { & just install-radare2; if ($LASTEXITCODE -ne 0) { throw "install-radare2 failed with exit code $LASTEXITCODE" }; Write-Success "radare2 ready" } catch { Write-Fail "radare2 installation failed: $_"; exit 1 }; Write-Step "Installing QEMU..."; try { & just install-qemu; if ($LASTEXITCODE -ne 0) { throw "install-qemu failed with exit code $LASTEXITCODE" }; Write-Success "QEMU ready" } catch { Write-Fail "QEMU installation failed: $_"; exit 1 }; Write-Step "Installing HxD..."; try { & just install-hxd; if ($LASTEXITCODE -ne 0) { throw "install-hxd failed with exit code $LASTEXITCODE" }; Write-Success "HxD ready" } catch { Write-Fail "HxD installation failed: $_"; exit 1 }; Write-Step "Installing x64dbg..."; try { & just install-x64dbg; if ($LASTEXITCODE -ne 0) { throw "install-x64dbg failed with exit code $LASTEXITCODE" }; Write-Success "x64dbg ready" } catch { Write-Fail "x64dbg installation failed: $_"; exit 1 }; Write-Step "Installing Cutter..."; try { & just install-cutter; if ($LASTEXITCODE -ne 0) { throw "install-cutter failed with exit code $LASTEXITCODE" }; Write-Success "Cutter ready" } catch { Write-Fail "Cutter installation failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Installation Complete ===$e[0m"; Write-Host "$e[90mTotal time: $("{0:N1}" -f $elapsed) seconds$e[0m`n"

# Remove pixi environment
uninstall:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[UNINSTALL]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Warn { param($msg) Write-Host "  $e[33m[SKIP]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Host "`n$e[1;36m=== Intellicrack Uninstall ===$e[0m`n"; $startTime = Get-Date; Write-Step "Cleaning pixi environment..."; try { pixi clean; if ($LASTEXITCODE -ne 0) { throw "pixi clean failed with exit code $LASTEXITCODE" }; Write-Success "Pixi environment cleaned" } catch { Write-Fail "Pixi clean failed: $_"; exit 1 }; Write-Step "Removing pixi.lock..."; if (Test-Path "pixi.lock") { try { Remove-Item -Force "pixi.lock" -ErrorAction Stop; Write-Success "pixi.lock removed" } catch { Write-Fail "Failed to remove pixi.lock: $_"; exit 1 } } else { Write-Warn "pixi.lock not found" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Uninstall Complete ===$e[0m"; Write-Host "$e[90mTotal time: $("{0:N1}" -f $elapsed) seconds$e[0m`n"

# Downloads and installs the latest Ghidra reverse engineering tool.
# Uses SSL validation and verifies downloaded file integrity.
install-ghidra:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[GHIDRA]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing Ghidra installation..."; $existingGhidra = Get-ChildItem -Path "tools" -Recurse -Filter "ghidraRun.bat" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($existingGhidra) { Write-Success "Ghidra already installed at $($existingGhidra.DirectoryName)"; exit 0 }; Write-Step "Fetching latest Ghidra release from GitHub..."; $maxRetries = 3; $release = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $release = Invoke-RestMethod -Uri "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest" -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $asset = $release.assets | Where-Object { $_.name -match '\.zip$' -and $_.name -notmatch 'DEV' } | Select-Object -First 1; if (!$asset) { Write-Fail "Could not find Ghidra release asset in GitHub response"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $fileSize = [math]::Round($asset.size / 1MB, 1); $zipPath = Join-Path "tools" $fileName; Write-Success "Found: $fileName ($fileSize MB)"; Write-Step "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 600; if (-not (Test-Path $zipPath)) { throw "Download file not found" }; $actualSize = (Get-Item $zipPath).Length; if ($actualSize -lt 1000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Extracting Ghidra..."; $tempExtract = Join-Path "tools" "ghidra_temp"; try { if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract -ErrorAction Stop; Write-Success "Extraction complete" } catch { Write-Fail "Extraction failed: $_"; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; exit 1 }; Write-Step "Installing Ghidra..."; try { $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1; if (!$extractedDir) { throw "No directory found in archive" }; $destPath = Join-Path "tools" "ghidra"; if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }; Move-Item -Path $extractedDir.FullName -Destination $destPath -ErrorAction Stop; if (-not (Test-Path (Join-Path $destPath "ghidraRun.bat"))) { throw "ghidraRun.bat not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mGhidra installed to tools\ghidra$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Downloads and installs the latest radare2 reverse engineering framework.
# Uses SSL validation and verifies downloaded file integrity.
install-radare2:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[RADARE2]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing radare2 installation..."; $existingRadare2 = Get-ChildItem -Path "tools" -Recurse -Filter "radare2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingRadare2) { $existingRadare2 = Get-ChildItem -Path "tools" -Recurse -Filter "r2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingRadare2) { Write-Success "radare2 already installed at $($existingRadare2.DirectoryName)"; exit 0 }; Write-Step "Fetching latest radare2 release from GitHub..."; $maxRetries = 3; $release = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $release = Invoke-RestMethod -Uri "https://api.github.com/repos/radareorg/radare2/releases/latest" -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $asset = $release.assets | Where-Object { $_.name -match 'w64\.zip$' -or $_.name -match 'windows.*\.zip$' } | Select-Object -First 1; if (!$asset) { Write-Fail "Could not find radare2 Windows release asset in GitHub response"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $fileSize = [math]::Round($asset.size / 1MB, 1); $zipPath = Join-Path "tools" $fileName; Write-Success "Found: $fileName ($fileSize MB)"; Write-Step "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 300; if (-not (Test-Path $zipPath)) { throw "Download file not found" }; $actualSize = (Get-Item $zipPath).Length; if ($actualSize -lt 1000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Extracting radare2..."; $tempExtract = Join-Path "tools" "radare2_temp"; try { if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract -ErrorAction Stop; Write-Success "Extraction complete" } catch { Write-Fail "Extraction failed: $_"; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; exit 1 }; Write-Step "Installing radare2..."; try { $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1; $destPath = Join-Path "tools" "radare2"; if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }; if ($extractedDir) { Move-Item -Path $extractedDir.FullName -Destination $destPath -ErrorAction Stop } else { Move-Item -Path $tempExtract -Destination $destPath -ErrorAction Stop }; $r2exe = Get-ChildItem -Path $destPath -Recurse -Filter "radare2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$r2exe) { $r2exe = Get-ChildItem -Path $destPath -Recurse -Filter "r2.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if (!$r2exe) { throw "radare2.exe or r2.exe not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mradare2 installed to tools\radare2$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Downloads and installs the latest HxD Hex Editor.
# Dynamically fetches version from developer website and downloads portable edition.
# Uses Inno Setup silent extraction for automated installation.
install-hxd:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[HXD]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing HxD installation..."; $existingHxD = Get-ChildItem -Path "tools\hxd" -Filter "HxD*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($existingHxD) { Write-Success "HxD already installed at $($existingHxD.DirectoryName)"; exit 0 }; Write-Step "Fetching latest HxD version from mh-nexus.de..."; $maxRetries = 3; $version = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $html = Invoke-WebRequest -Uri "https://mh-nexus.de/en/hxd/" -UseBasicParsing -TimeoutSec 30; $content = $html.Content; if ($content -match '(\d+\.\d+\.\d+\.\d+)') { $version = $matches[1] }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Failed to fetch HxD page after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; if (!$version) { $version = "latest" }; $downloadUrl = "https://mh-nexus.de/downloads/HxDPortableSetup.zip"; $fileName = "HxDPortableSetup.zip"; Write-Success "Found: HxD v$version"; $zipPath = Join-Path "tools" $fileName; Write-Step "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 300; if (-not (Test-Path $zipPath)) { throw "Download file not found" }; $actualSize = (Get-Item $zipPath).Length; if ($actualSize -lt 100000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; $fileSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2); Write-Success "Download complete ($fileSize MB)"; Write-Step "Extracting setup from archive..."; $tempExtract = Join-Path "tools" "hxd_temp"; try { if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract -ErrorAction Stop; Write-Success "Archive extracted" } catch { Write-Fail "Extraction failed: $_"; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; exit 1 }; Write-Step "Installing HxD (silent mode)..."; try { $destPath = Join-Path (Get-Location) "tools\hxd"; if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }; $setupExe = Get-ChildItem -Path $tempExtract -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$setupExe) { throw "Setup executable not found in archive" }; $proc = Start-Process -FilePath $setupExe.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=$destPath" -Wait -PassThru -NoNewWindow; if ($proc.ExitCode -ne 0) { throw "Installer exited with code $($proc.ExitCode)" }; Start-Sleep -Seconds 1; $hxdExe = Get-ChildItem -Path $destPath -Filter "HxD*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$hxdExe) { throw "HxD executable not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mHxD v$version installed to tools\hxd$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Downloads and installs the latest QEMU emulator.
# Uses SSL validation and verifies downloaded installer integrity.
install-qemu:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[QEMU]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing QEMU installation..."; $existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingQemu) { $existingQemu = Get-ChildItem -Path "tools" -Recurse -Filter "qemu-img.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingQemu) { Write-Success "QEMU already installed at $($existingQemu.DirectoryName)"; exit 0 }; Write-Step "Fetching QEMU release page..."; $maxRetries = 3; $html = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $html = Invoke-WebRequest -Uri "https://qemu.weilnetz.de/w64/" -UseBasicParsing -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "Failed to fetch QEMU release page after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $links = $html.Links | Where-Object { $_.href -match 'qemu-w64-setup-.*\.exe$' } | Sort-Object { $_.href } -Descending | Select-Object -First 1; if (!$links) { Write-Fail "Could not find QEMU installer on release page"; exit 1 }; $installerName = $links.href; $installerUrl = "https://qemu.weilnetz.de/w64/$installerName"; Write-Success "Found: $installerName"; $installerPath = Join-Path "tools" $installerName; Write-Step "Downloading $installerName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -TimeoutSec 600; if (-not (Test-Path $installerPath)) { throw "Download file not found" }; $actualSize = (Get-Item $installerPath).Length; if ($actualSize -lt 10000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $installerPath) { Remove-Item $installerPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Installing QEMU (this may take a minute)..."; try { $installDir = Join-Path (Get-Location) "tools\qemu"; if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }; $process = Start-Process -FilePath $installerPath -ArgumentList "/S", "/D=$installDir" -Wait -NoNewWindow -PassThru; if ($process.ExitCode -ne 0) { throw "Installer exited with code $($process.ExitCode)" }; Start-Sleep -Seconds 2; $qemuExe = Get-ChildItem -Path $installDir -Recurse -Filter "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$qemuExe) { $qemuExe = Get-ChildItem -Path $installDir -Recurse -Filter "qemu-img.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if (!$qemuExe) { throw "QEMU executables not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $installerPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mQEMU installed to tools\qemu$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Downloads and installs the latest x64dbg debugger.
# Fetches latest release from GitHub and extracts portable package.
install-x64dbg:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[X64DBG]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing x64dbg installation..."; $existingX64dbg = Get-ChildItem -Path "tools\x64dbg" -Recurse -Filter "x64dbg.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingX64dbg) { $existingX64dbg = Get-ChildItem -Path "tools\x64dbg" -Recurse -Filter "x96dbg.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingX64dbg) { Write-Success "x64dbg already installed at $($existingX64dbg.DirectoryName)"; exit 0 }; Write-Step "Fetching latest x64dbg release from GitHub..."; $maxRetries = 3; $release = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $release = Invoke-RestMethod -Uri "https://api.github.com/repos/x64dbg/x64dbg/releases/latest" -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $asset = $release.assets | Where-Object { $_.name -match 'snapshot.*\.zip$' -and $_.name -notmatch 'pdb' } | Select-Object -First 1; if (!$asset) { Write-Fail "Could not find x64dbg release asset in GitHub response"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $fileSize = [math]::Round($asset.size / 1MB, 1); $zipPath = Join-Path "tools" $fileName; Write-Success "Found: $fileName ($fileSize MB)"; Write-Step "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 600; if (-not (Test-Path $zipPath)) { throw "Download file not found" }; $actualSize = (Get-Item $zipPath).Length; if ($actualSize -lt 1000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Extracting x64dbg..."; $destPath = Join-Path "tools" "x64dbg"; try { if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }; New-Item -ItemType Directory -Path $destPath -Force | Out-Null; Expand-Archive -Path $zipPath -DestinationPath $destPath -ErrorAction Stop; Write-Success "Extraction complete" } catch { Write-Fail "Extraction failed: $_"; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; exit 1 }; Write-Step "Verifying installation..."; try { $x64exe = Get-ChildItem -Path $destPath -Recurse -Filter "x64dbg.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; $x32exe = Get-ChildItem -Path $destPath -Recurse -Filter "x32dbg.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$x64exe -and !$x32exe) { throw "x64dbg executables not found after extraction" }; Write-Success "Installation verified" } catch { Write-Fail "Verification failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mx64dbg installed to tools\x64dbg$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Downloads and installs the latest Cutter reverse engineering tool.
# Fetches latest release from GitHub (rizinorg/cutter) and extracts portable package.
install-cutter:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[CUTTER]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Progress { param($msg) Write-Host "  $e[90m...$e[0m $msg" }; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $startTime = Get-Date; Write-Step "Creating tools directory..."; try { if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }; if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }; Write-Success "Tools directory ready" } catch { Write-Fail "Directory creation failed: $_"; exit 1 }; Write-Step "Checking existing Cutter installation..."; $existingCutter = Get-ChildItem -Path "tools\cutter" -Recurse -Filter "Cutter.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$existingCutter) { $existingCutter = Get-ChildItem -Path "tools\cutter" -Recurse -Filter "cutter.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if ($existingCutter) { Write-Success "Cutter already installed at $($existingCutter.DirectoryName)"; exit 0 }; Write-Step "Fetching latest Cutter release from GitHub..."; $maxRetries = 3; $release = $null; for ($i = 1; $i -le $maxRetries; $i++) { try { $release = Invoke-RestMethod -Uri "https://api.github.com/repos/rizinorg/cutter/releases/latest" -TimeoutSec 30; break } catch { if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; Start-Sleep -Seconds 2 } }; $asset = $release.assets | Where-Object { $_.name -match 'Windows.*x64.*\.zip$' -or $_.name -match 'win64.*\.zip$' -or ($_.name -match 'Windows' -and $_.name -match '\.zip$') } | Select-Object -First 1; if (!$asset) { Write-Fail "Could not find Cutter Windows release asset in GitHub response"; exit 1 }; $downloadUrl = $asset.browser_download_url; $fileName = $asset.name; $fileSize = [math]::Round($asset.size / 1MB, 1); $zipPath = Join-Path "tools" $fileName; Write-Success "Found: $fileName ($fileSize MB)"; Write-Step "Downloading $fileName..."; $ProgressPreference = 'SilentlyContinue'; for ($i = 1; $i -le $maxRetries; $i++) { try { Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 600; if (-not (Test-Path $zipPath)) { throw "Download file not found" }; $actualSize = (Get-Item $zipPath).Length; if ($actualSize -lt 1000000) { throw "Downloaded file too small ($actualSize bytes)" }; break } catch { if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }; Write-Progress "Retry $i/$maxRetries..."; if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }; Start-Sleep -Seconds 5 } }; Write-Success "Download complete"; Write-Step "Extracting Cutter..."; $tempExtract = Join-Path "tools" "cutter_temp"; try { if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }; Expand-Archive -Path $zipPath -DestinationPath $tempExtract -ErrorAction Stop; Write-Success "Extraction complete" } catch { Write-Fail "Extraction failed: $_"; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; exit 1 }; Write-Step "Installing Cutter..."; try { $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1; $destPath = Join-Path "tools" "cutter"; if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }; if ($extractedDir) { Move-Item -Path $extractedDir.FullName -Destination $destPath -ErrorAction Stop } else { Move-Item -Path $tempExtract -Destination $destPath -ErrorAction Stop }; $cutterExe = Get-ChildItem -Path $destPath -Recurse -Filter "Cutter.exe" -ErrorAction SilentlyContinue | Select-Object -First 1; if (!$cutterExe) { $cutterExe = Get-ChildItem -Path $destPath -Recurse -Filter "cutter.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }; if (!$cutterExe) { throw "Cutter.exe not found after installation" }; Write-Success "Installation complete" } catch { Write-Fail "Installation failed: $_"; exit 1 }; Write-Step "Cleaning up..."; try { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item $zipPath -Force -ErrorAction SilentlyContinue; Write-Success "Cleanup complete" } catch { Write-Progress "Cleanup warning: $_" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mCutter installed to tools\cutter$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Copy Intellicrack bridge plugin to x64dbg plugins directory.
# Requires the plugin to be built first with CMake.
install-x64dbg-plugin:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[PLUGIN]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Skip { param($msg) Write-Host "  $e[33m[SKIP]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Step "Installing x64dbg bridge plugin..."; $pluginSrc32 = "tools/x64dbg_plugin/build/plugins/intellicrack_bridge_x32.dp32"; $pluginSrc64 = "tools/x64dbg_plugin/build/plugins/intellicrack_bridge_x64.dp64"; $dest32 = "tools/x64dbg/release/x32/plugins"; $dest64 = "tools/x64dbg/release/x64/plugins"; $installed = $false; if (!(Test-Path "tools/x64dbg/release")) { Write-Fail "x64dbg not installed. Run 'just install-x64dbg' first."; exit 1 }; if (!(Test-Path $dest32)) { New-Item -ItemType Directory -Path $dest32 -Force | Out-Null }; if (!(Test-Path $dest64)) { New-Item -ItemType Directory -Path $dest64 -Force | Out-Null }; if (Test-Path $pluginSrc32) { Copy-Item $pluginSrc32 $dest32 -Force; Write-Success "Copied x32 plugin to $dest32"; $installed = $true } else { Write-Skip "x32 plugin not found at $pluginSrc32" }; if (Test-Path $pluginSrc64) { Copy-Item $pluginSrc64 $dest64 -Force; Write-Success "Copied x64 plugin to $dest64"; $installed = $true } else { Write-Skip "x64 plugin not found at $pluginSrc64" }; if (!$installed) { Write-Fail "No plugin binaries found. Build the plugin first with CMake."; Write-Host "  Build instructions:"; Write-Host "    cd tools/x64dbg_plugin && mkdir build && cd build"; Write-Host "    For x64: cmake .. -G 'Visual Studio 17 2022' -A x64 && cmake --build . --config Release"; Write-Host "    For x32: cmake .. -G 'Visual Studio 17 2022' -A Win32 -DBUILD_X64=OFF && cmake --build . --config Release"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mPlugin installation complete$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# ==================== CLEANUP ====================

# Clean all build artifacts (Python, test caches)
clean:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; $removed = 0; function Write-Step { param($msg) Write-Host "$e[36m[CLEAN]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; function Write-Skip { param($msg) Write-Host "  $e[33m[SKIP]$e[0m $msg" }; Write-Host "`n$e[1;36m=== Cleaning Project Artifacts ===$e[0m`n"; Write-Step "Cleaning Python bytecode (intellicrack, tests)..."; try { pixi run pyclean src/intellicrack tests 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { Write-Success "Python bytecode cleaned"; $removed++ } else { Write-Fail "pyclean failed" } } catch { Write-Skip "Python cleanup skipped: $_" }; Write-Step "Checking for MagicMock artifact directory..."; $magicMockPath = Join-Path (Get-Location) "MagicMock"; if ((Test-Path $magicMockPath) -and (Get-Item $magicMockPath).PSIsContainer -and (Test-Path (Join-Path $magicMockPath "mock"))) { Remove-Item -Recurse -Force $magicMockPath -ErrorAction Stop; Write-Success "MagicMock directory removed"; $removed++ } else { Write-Skip "MagicMock not found or not matching expected structure" }; Write-Step "Cleaning test artifacts..."; if (Test-Path ".pytest_cache") { Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path "coverage_html_report") { Remove-Item -Recurse -Force coverage_html_report -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path ".coverage") { Remove-Item -Force .coverage -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path ".mypy_cache") { Remove-Item -Recurse -Force .mypy_cache -ErrorAction SilentlyContinue; $removed++ }; if (Test-Path ".ruff_cache") { Remove-Item -Recurse -Force .ruff_cache -ErrorAction SilentlyContinue; $removed++ }; Write-Success "Test artifacts cleaned"; Write-Host "`n$e[1;32m=== Cleanup Complete ($removed items) ===$e[0m`n"

# ==================== SANDBOX ====================

# Launch interactive Windows Sandbox for Intellicrack testing (READ-ONLY)
sandbox:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType interactive }

# Launch interactive Windows Sandbox with READ-WRITE access (changes persist to host)
sandbox-rw:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType interactive-rw }

# Launch sandbox and run unit tests
sandbox-test:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType unit }

# Launch sandbox and run all tests
sandbox-test-all:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType all }

# Launch sandbox and run tests with coverage
sandbox-test-coverage:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType coverage }

# Launch sandbox and run hardware spoofer registry tests
sandbox-test-registry:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType registry }

# ==================== TESTING ====================

# Quick unit tests - runs in Windows Sandbox for isolation
test:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType unit }

# Full test suite - runs in Windows Sandbox for isolation
test-all:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType all }

# Coverage report - runs in Windows Sandbox with 95%+ coverage requirement
test-coverage:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType coverage }

# Runs tests for a specific module in Windows Sandbox
test-module module:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType module -Module "{{ module }}" }

# Benchmarks - runs in Windows Sandbox
test-bench:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType bench }

# Integration tests - runs in Windows Sandbox
test-integration:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType integration }

# End-to-end tests - runs in Windows Sandbox
test-e2e:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType e2e }

# Quick smoke test - runs in Windows Sandbox
test-smoke:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType smoke }

# Module tests with coverage - runs in Windows Sandbox
test-module-cov module:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType module-cov -Module "{{ module }}" }

# HTML coverage report - runs in Windows Sandbox (uses coverage type)
test-cov-html:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType coverage }

# Parallel tests - runs in Windows Sandbox
test-parallel:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType parallel }

# Retest failed tests - runs in Windows Sandbox
test-failed:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType failed }

# Verbose tests - runs in Windows Sandbox
test-verbose:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType verbose }

# Install test dependencies
test-install:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[INSTALL]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Installing test dependencies..."; try { pip install pytest pytest-cov pytest-benchmark pytest-asyncio pytest-qt pytest-xdist pytest-mock 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "pip install failed with exit code $LASTEXITCODE" }; Write-Success "Test dependencies installed" } catch { Write-Fail "Installation failed: $_"; exit 1 }

# Verify no mocks or fake data
test-verify-real:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[VERIFY]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Verifying no mocks or fake data..."; try { pixi run python scripts/verify_no_mocks.py 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "Verification failed with exit code $LASTEXITCODE" }; Write-Success "All tests use REAL data" } catch { Write-Fail "Verification failed: $_"; exit 1 }

# ==================== PYTHON LINTING ====================

# Lint code with ruff
lint *FLAGS:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[LINT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Running Ruff Linter ===$e[0m`n"; Write-Step "Checking code style..."; try { pixi run ruff check {{FLAGS}} src/intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; $checkCode = $LASTEXITCODE } catch { $checkCode = 1 }; Write-Step "Checking formatting..."; try { pixi run ruff format --check {{FLAGS}} src/intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; $formatCode = $LASTEXITCODE } catch { $formatCode = 1 }; if ($checkCode -ne 0 -or $formatCode -ne 0) { Write-Fail "Linting issues found"; exit 1 }; Write-Success "All lint checks passed"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Lint Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Fix linting issues automatically
lint-fix *FLAGS:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[LINT-FIX]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Fixing Lint Issues ===$e[0m`n"; Write-Step "Fixing code style issues..."; try { pixi run ruff check --fix {{FLAGS}} src/intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "ruff check --fix failed" } } catch { Write-Fail "Style fix failed: $_"; exit 1 }; Write-Step "Formatting code..."; try { pixi run ruff format {{FLAGS}} src/intellicrack/ 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "ruff format failed" } } catch { Write-Fail "Format failed: $_"; exit 1 }; Write-Success "Lint issues fixed"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Lint Fix Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Detect dead code with vulture and output sorted findings
vulture *FLAGS:
    @echo "[Vulture] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run vulture {{FLAGS}} src/ --min-confidence 60 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py vulture --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Upgrade Python syntax to newer versions
pyupgrade *FLAGS:
    @Get-ChildItem -Path .\src\intellicrack\ -Recurse -Include "*.py" | ForEach-Object { pixi run pyupgrade --py312-plus {{FLAGS}} $_.FullName }
    @Get-ChildItem -Path .\tests\ -Recurse -Include "*.py" | ForEach-Object { pixi run pyupgrade --py312-plus {{FLAGS}} $_.FullName }

# Apply AI-powered code suggestions and save CSV findings to reports/csv/
sourcery *FLAGS:
    @if (!(Test-Path 'reports/csv')) { New-Item -ItemType Directory -Path 'reports/csv' -Force | Out-Null }
    @pixi run sourcery review --fix --csv --no-summary {{FLAGS}} src/intellicrack 2>&1 | Tee-Object -FilePath reports/csv/sourcery_src_findings.csv
    @pixi run sourcery review --fix --csv --no-summary {{FLAGS}} tests 2>&1 | Tee-Object -FilePath reports/csv/sourcery_tests_findings.csv

# Check docstring validity with darglint and output sorted findings
darglint *FLAGS:
    @echo "[Darglint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run darglint {{FLAGS}} src/intellicrack 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py darglint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Check code line statistics with pygount
pygount *FLAGS:
    @pixi run pygount {{FLAGS}} src/intellicrack --format=summary
    @pixi run pygount {{FLAGS}} tests --format=summary

# Check Python packaging best practices with pyroma
pyroma *FLAGS:
    @pixi run pyroma {{FLAGS}} .

# Detect dead code and output sorted findings
dead *FLAGS:
    @echo "[Dead Code] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run dead {{FLAGS}} src/ 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py dead --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run type checking with ty and output sorted findings
ty *FLAGS:
    @echo "[Ty Type] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run ty check {{FLAGS}} src/intellicrack tests --output-format concise 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py ty $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run type checking with basedpyright and output sorted findings
basedpyright *FLAGS:
    @echo "[BasedPyright] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:NODE_OPTIONS = '--max-old-space-size=8192'; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run basedpyright {{FLAGS}} src/ --outputjson 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py basedpyright $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run type checking with mypy and output sorted findings
mypy *FLAGS:
    @echo "[Mypy] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run mypy {{FLAGS}} src/intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py mypy --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Security linting with bandit and output sorted findings
bandit *FLAGS:
    @echo "[Bandit Security] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run bandit {{FLAGS}} -r src/intellicrack/ tests/ -c pyproject.toml 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py bandit --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Security scanning with Semgrep and output sorted findings
semgrep *FLAGS:
    @echo "[Semgrep] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $env:PYTHONUTF8 = '1'; $env:PYTHONIOENCODING = 'utf-8'; $tmpFile = [System.IO.Path]::GetTempFileName(); try { semgrep scan --config=auto --json --timeout 30 {{FLAGS}} src/ 2>$null | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py semgrep $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run flake8 style linting and output sorted findings
flake8 *FLAGS:
    @echo "[Flake8] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run flake8 {{FLAGS}} src/intellicrack tests --statistics 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py flake8 --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run wemake-python-styleguide (strictest linter) and output sorted findings
wemake *FLAGS:
    @echo "[Wemake Styleguide] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run flake8 {{FLAGS}} src/intellicrack tests --select=WPS,C9 --max-complexity 10 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py wemake --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run mccabe complexity checker and output sorted findings
mccabe *FLAGS:
    @echo "[McCabe Complexity] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run flake8 {{FLAGS}} src/intellicrack tests --select=C901 --max-complexity 10 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py mccabe --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run pydocstyle docstring checker and output sorted findings
pydocstyle *FLAGS:
    @echo "[Pydocstyle] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run pydocstyle {{FLAGS}} src/intellicrack tests 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py pydocstyle --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run radon cyclomatic complexity analysis and output sorted findings
radon *FLAGS:
    @echo "[Radon Complexity] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run radon cc {{FLAGS}} src/intellicrack tests -s -a 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py radon --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run xenon complexity threshold checker and output sorted findings
xenon *FLAGS:
    @echo "[Xenon Complexity] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run xenon {{FLAGS}} src/intellicrack tests -b B -m C -a C 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py xenon --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run complexipy cognitive complexity analysis and output sorted findings
complexipy *FLAGS:
    @echo "[Complexipy] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run complexipy {{FLAGS}} src --failed --color no 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py complexipy --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run ruff linter and output sorted findings (uses native JSON output for speed)
ruff *FLAGS:
    @echo "[Ruff Linter] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run ruff check {{FLAGS}} src/intellicrack/ tests/ --output-format=json -o $tmpFile 2>&1 | Out-Null; pixi run python scripts/process_lint_json.py ruff $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run ruff format to format Python code
ruff-fmt *FLAGS:
    @echo "[Ruff Format] Running..."
    @pixi run ruff format {{FLAGS}} src/intellicrack/ tests/ 2>&1 | Out-Null; Write-Host "[RUFF FMT] Done"

# Detect uncalled functions with uncalled and output sorted findings
uncalled *FLAGS:
    @echo "[Uncalled] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run uncalled {{FLAGS}} --how both src/ 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py uncalled --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Detect dead code with deadcode and output sorted findings
deadcode *FLAGS:
    @echo "[Deadcode] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run deadcode {{FLAGS}} src/ 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py deadcode --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# ==================== OTHER LINTING ====================

# Run markdownlint and output sorted findings
mdlint *FLAGS:
    @echo "[Markdown Lint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run markdownlint {{FLAGS}} "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py markdownlint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run yamllint and output sorted findings
yamllint *FLAGS:
    @echo "[YAML Lint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { pixi run yamllint {{FLAGS}} . 2>&1 | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py yamllint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run shellcheck on shell scripts and output sorted findings
shellcheck *FLAGS:
    @echo "[ShellCheck] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $shFiles = @(Get-ChildItem -Path . -Include "*.sh","*.bash" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.pixi|node_modules|\.git|target' }); if ($shFiles.Count -eq 0) { Write-Host "[ShellCheck] 0 findings (no shell scripts found)"; 'No findings.' | Out-File -FilePath 'reports/txt/shellcheck_findings.txt' -Encoding utf8; @{ tool = 'shellcheck'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/shellcheck_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="shellcheck"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/shellcheck_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $shFiles | ForEach-Object { pixi run shellcheck {{FLAGS}} --format=gcc $_.FullName 2>&1 } | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py shellcheck --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run blinter on batch files and output sorted findings
blinter *FLAGS:
    @echo "[Blinter] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $batFiles = @(Get-ChildItem -Path . -Include "*.bat","*.cmd" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.pixi|node_modules|\.git|target|\\tools\\|\\build\\|\\dist\\' }); if ($batFiles.Count -eq 0) { Write-Host "[Blinter] 0 findings (no batch files found)"; 'No findings.' | Out-File -FilePath 'reports/txt/blinter_findings.txt' -Encoding utf8; @{ tool = 'blinter'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/blinter_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="blinter"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/blinter_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $batFiles | ForEach-Object { pixi run python -m blinter {{FLAGS}} $_.FullName 2>&1 } | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py blinter --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Validates JSON files in the project using PowerShell JSON parsing.
# Reports any syntax errors found in the JSON files.
jsonlint:
    @echo "[JSONLint] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $jsonFiles = fd -e json --type f --exclude 'package-lock.json' --exclude 'pixi.lock' --exclude 'reports' 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }; if ($null -eq $jsonFiles -or @($jsonFiles).Count -eq 0) { Write-Host "[JSONLint] 0 findings (no JSON files found)"; 'No findings.' | Out-File -FilePath 'reports/txt/jsonlint_findings.txt' -Encoding utf8; @{ tool = 'jsonlint'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/jsonlint_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="jsonlint"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/jsonlint_findings.xml' -Encoding utf8; exit 0 }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $errors = @(); foreach ($file in $jsonFiles) { try { Get-Content $file -Raw | ConvertFrom-Json | Out-Null } catch { $errors += "$file`: $($_.Exception.Message)" } }; if ($errors.Count -gt 0) { $errors | Out-File -FilePath $tmpFile -Encoding utf8 } else { "No JSON syntax errors found" | Out-File -FilePath $tmpFile -Encoding utf8 }; pixi run python scripts/process_lint_json.py jsonlint --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Run PSScriptAnalyzer on PowerShell files and output sorted findings
psscriptanalyzer *FLAGS:
    @echo "[PSScriptAnalyzer] Running..."
    @('txt','json','xml') | ForEach-Object { if (!(Test-Path "reports/$_")) { New-Item -ItemType Directory -Path "reports/$_" -Force | Out-Null } }; $psFiles = Get-ChildItem -Path . -Include "*.ps1","*.psm1","*.psd1" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.pixi|node_modules|\.git|target' } | ForEach-Object { $_.FullName }; if ($null -eq $psFiles -or @($psFiles).Count -eq 0) { Write-Host "[PSScriptAnalyzer] 0 findings (no PowerShell scripts found)"; 'No findings.' | Out-File -FilePath 'reports/txt/psscriptanalyzer_findings.txt' -Encoding utf8; @{ tool = 'psscriptanalyzer'; generated = (Get-Date).ToString('o'); total_findings = 0; total_files = 0; files = @() } | ConvertTo-Json -Depth 4 | Out-File -FilePath 'reports/json/psscriptanalyzer_findings.json' -Encoding utf8; '<?xml version="1.0" encoding="UTF-8"?><LintReport tool="psscriptanalyzer"><Summary><TotalFindings>0</TotalFindings><TotalFiles>0</TotalFiles></Summary><Files/></LintReport>' | Out-File -FilePath 'reports/xml/psscriptanalyzer_findings.xml' -Encoding utf8; exit 0 }; if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) { Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck }; $tmpFile = [System.IO.Path]::GetTempFileName(); try { $psFiles | ForEach-Object { Invoke-ScriptAnalyzer {{FLAGS}} -Path $_ -Severity @('Error','Warning','Information') } | ForEach-Object { "$($_.ScriptPath):$($_.Line):$($_.Column): [$($_.Severity)] $($_.Message) ($($_.RuleName))" } | Out-File -FilePath $tmpFile -Encoding utf8; pixi run python scripts/process_lint_json.py psscriptanalyzer --text $tmpFile } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }

# Lint Markdown files with markdownlint
lint-md *FLAGS:
    @pixi run markdownlint {{FLAGS}} "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Fix Markdown linting issues automatically
lint-md-fix *FLAGS:
    @pixi run markdownlint --fix {{FLAGS}} "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools

# Lint all YAML files in the project with yamllint
lint-yaml *FLAGS:
    @pixi run yamllint {{FLAGS}} .

# ==================== FORMATTING ====================

# Format JSON files with PowerShell
jsonfmt:
    @echo "[JSON Format] Running..."
    @$jsonFiles = fd -e json --type f --exclude 'package-lock.json' --exclude 'pixi.lock' --exclude 'reports' 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }; foreach ($file in $jsonFiles) { try { $content = Get-Content $file -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 100; Set-Content -Path $file -Value $content -Encoding utf8 } catch { } }; Write-Host "[JSONFMT] Done"

# Format YAML files with yamlfmt (if available) or skip
yamlfmt:
    @echo "[YAML Format] Skipped (no formatter configured)"

# Format TOML files (no formatter configured)
tomlfmt:
    @echo "[TOML Format] Skipped (no formatter configured)"

# Format Markdown files with markdownlint --fix
mdfmt *FLAGS:
    @echo "[Markdown Format] Running..."
    @pixi run markdownlint --fix {{FLAGS}} "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore build --ignore dist --ignore tools 2>&1 | Out-Null; Write-Host "[MDFMT] Done"

# Lint all file types (Python, Markdown, YAML, JSON)
lint-all:
    -@just lint
    -@just lint-md
    -@just lint-yaml
    -@just jsonlint
    @echo "All linting complete"

# Fix all auto-fixable linting issues (Python, Markdown, JSON)
lint-all-fix:
    -@just lint-fix
    -@just lint-md-fix
    -@just jsonfmt
    @echo "All auto-fixable linting issues resolved"

# ==================== GIT ====================

# Watch GitHub Actions CI runs in real-time
watch:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[GIT]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Checking gh CLI..."; try { $ghVersion = gh --version 2>&1 | Select-Object -First 1; if ($LASTEXITCODE -ne 0) { throw "gh CLI not found" } } catch { Write-Fail "gh CLI not installed: $_"; exit 1 }; Write-Step "Watching GitHub Actions..."; gh run watch

# Cleans Windows NUL file artifacts from the repository.
nul-cleanup:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[35m[NUL]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;35m=== NUL File Cleanup ===$e[0m`n"; Write-Step "Scanning for NUL file artifacts..."; try { $output = pixi run python scripts/clean_nul.py 2>&1; $outputStr = $output -join "`n"; if ($outputStr -match '(\d+)\s+file\(s\)\s+deleted') { $deleted = $matches[1] } else { $deleted = 0 }; if ($LASTEXITCODE -ne 0) { throw "Clean script failed" }; Write-Success "Cleanup complete ($deleted files removed)" } catch { Write-Fail "Cleanup failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;35m=== NUL Cleanup Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Generates project structure files (HTA and TXT).
generate-structure:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[34m[STRUCT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;34m=== Generating Structure Files ===$e[0m`n"; Write-Step "Running structure generator..."; try { $output = pixi run python scripts/generate_tree.py 2>&1; if ($LASTEXITCODE -ne 0) { throw "Generator script failed" }; Write-Success "Generator completed" } catch { Write-Fail "Generation failed: $_"; exit 1 }; Write-Step "Validating outputs..."; $htaPath = "IntellicrackStructure.hta"; $txtPath = "IntellicrackStructure.txt"; if (-not (Test-Path $htaPath)) { Write-Fail "HTA file not found: $htaPath"; exit 1 }; Write-Success "HTA: $htaPath"; if (-not (Test-Path $txtPath)) { Write-Fail "TXT file not found: $txtPath"; exit 1 }; Write-Success "TXT: $txtPath"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;34m=== Structure Generation Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Creates a quick WIP commit with automatic timestamp and pushes to origin.
# Skips git hooks for faster commits during development work.
git-commit:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[32m[GIT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;32m=== WIP Commit ===$e[0m`n"; Write-Step "Running NUL cleanup..."; try { python scripts/clean_nul.py 2>&1 | Out-Null; Write-Success "NUL cleanup complete" } catch { Write-Success "NUL cleanup skipped" }; Write-Step "Generating structure files..."; try { pixi run python scripts/generate_tree.py 2>&1 | Out-Null; Write-Success "Structure generated" } catch { Write-Success "Structure generation skipped" }; Write-Step "Generating knowledge map..."; try { pixi run python scripts/knowledge-graph/visualize_architecture.py --layout hierarchical 2>&1 | Out-Null; Write-Success "Knowledge map generated" } catch { Write-Success "Knowledge map skipped" }; Write-Step "Committing and pushing..."; $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; try { git add -A 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git add failed" }; Write-Success "Changes staged" } catch { Write-Fail "Staging failed: $_"; exit 1 }; try { git commit --no-verify -m "WIP: $timestamp" 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git commit failed" }; Write-Success "Committed: WIP: $timestamp" } catch { Write-Fail "Commit failed: $_"; exit 1 }; try { git push origin HEAD 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git push failed" }; Write-Success "Pushed to origin" } catch { Write-Fail "Push failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Commit Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Full commit with hooks - prompts for message, runs pre-commit hooks, pushes to origin
git-commit-hooks message:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[GIT]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Step "Full commit with hooks..."; $commitMsg = '{{ message }}' -replace "'", "''"; Write-Step "Staging all changes..."; try { git add -A 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "git add failed" }; Write-Success "Changes staged" } catch { Write-Fail "Staging failed: $_"; exit 1 }; Write-Step "Committing with hooks..."; try { git commit -m $commitMsg 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "git commit failed (hooks may have failed)" }; Write-Success "Committed" } catch { Write-Fail "Commit failed: $_"; exit 1 }; Write-Step "Pushing to origin..."; try { git push origin HEAD 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "git push failed" }; Write-Success "Pushed to origin" } catch { Write-Fail "Push failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Commit Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# ==================== DOCUMENTATION ====================

# Generate Sphinx documentation
docs-build *FLAGS:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building Documentation ===$e[0m`n"; Write-Step "Running Sphinx build..."; try { pixi run sphinx-build {{FLAGS}} -b html docs/source docs/build/html 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "sphinx-build failed with exit code $LASTEXITCODE" }; Write-Success "Documentation built" } catch { Write-Fail "Build failed: $_"; exit 1 }; Write-Step "Validating output..."; if (-not (Test-Path "docs/build/html/index.html")) { Write-Fail "index.html not found"; exit 1 }; Write-Success "Output validated: docs/build/html/index.html"; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== Documentation Built ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Clean documentation build
docs-clean:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; Write-Step "Cleaning documentation build..."; if (Test-Path "docs\build") { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue docs\build\*; Write-Success "Documentation build cleaned" } else { Write-Success "Nothing to clean" }

# Regenerate API documentation from code
docs-apidoc *FLAGS:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Generating API documentation..."; try { pixi run sphinx-apidoc {{FLAGS}} -f -o docs/source src/intellicrack 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "sphinx-apidoc failed" }; Write-Success "API documentation generated" } catch { Write-Fail "Generation failed: $_"; exit 1 }

# Full documentation rebuild
docs-rebuild: docs-clean docs-apidoc docs-build
    @$e = [char]27; Write-Host "`n$e[1;32m=== Documentation Rebuild Complete ===$e[0m"; Write-Host "View at: docs/build/html/index.html`n"

# Open documentation in browser (Windows)
docs-open:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $docPath = "docs\build\html\index.html"; if (-not (Test-Path $docPath)) { Write-Fail "Documentation not found. Run 'just docs-build' first."; exit 1 }; Write-Step "Opening documentation in browser..."; Start-Process $docPath; Write-Success "Opened in browser"

# Build PDF documentation
docs-pdf *FLAGS:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Building PDF Documentation ===$e[0m`n"; Write-Step "Generating LaTeX files..."; try { pixi run sphinx-build {{FLAGS}} -b latex docs/source docs/build/latex 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "sphinx-build latex failed" }; Write-Success "LaTeX files generated in docs/build/latex/" } catch { Write-Fail "Generation failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;32m=== PDF Build Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Check documentation links
docs-linkcheck *FLAGS:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Step "Checking documentation links..."; try { pixi run sphinx-build {{FLAGS}} -b linkcheck docs/source docs/build/linkcheck 2>&1 | ForEach-Object { Write-Host "  $_" }; Write-Success "Link check complete. Results in docs/build/linkcheck/output.txt" } catch { Write-Fail "Link check failed: $_"; exit 1 }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[32mLink check complete$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m"

# Generate interactive knowledge graph visualization of codebase architecture.
# Creates an interactive HTML visualization (IntellicrackKnowledgeGraph.html) at project root.
generate-map:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[MAP]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $startTime = Get-Date; Write-Host "`n$e[1;36m=== Generating Knowledge Map ===$e[0m`n"; Write-Step "Running map generator..."; $scriptPath = "scripts\knowledge-graph\visualize_architecture.py"; try { $output = pixi run python $scriptPath --layout hierarchical 2>&1; if ($LASTEXITCODE -ne 0) { throw "Map generation failed" }; Write-Success "Map generated" } catch { Write-Fail "Generation failed: $_"; exit 1 }; Write-Step "Validating outputs..."; $htmlPath = "IntellicrackKnowledgeGraph.html"; $kgDir = "scripts\knowledge-graph"; $graphmlPath = "$kgDir\IntellicrackKnowledgeGraph.graphml"; $dotPath = "$kgDir\IntellicrackKnowledgeGraph.dot"; if (-not (Test-Path $htmlPath)) { Write-Fail "HTML not found: $htmlPath"; exit 1 }; Write-Success "HTML: $htmlPath"; if (Test-Path $graphmlPath) { Write-Success "GraphML: $graphmlPath" }; if (Test-Path $dotPath) { Write-Success "DOT: $dotPath" }; $elapsed = ((Get-Date) - $startTime).TotalSeconds; Write-Host "`n$e[1;36m=== Knowledge Map Complete ===$e[0m $e[90m($("{0:N1}" -f $elapsed)s)$e[0m`n"

# Open knowledge map in browser (Windows)
open-map:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[MAP]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $htmlPath = "IntellicrackKnowledgeGraph.html"; if (-not (Test-Path $htmlPath)) { Write-Fail "Knowledge map not found. Run 'just generate-map' first."; exit 1 }; Write-Step "Opening knowledge map in browser..."; Start-Process $htmlPath; Write-Success "Opened in browser"

# ==================== COMPREHENSIVE REPORTS ====================

# Runs all Python development tools for comprehensive analysis.
# Executes tools sequentially with progress tracking and results summary.
run-all-tools:
    @$ErrorActionPreference = 'SilentlyContinue'; $h = [char]0x2500; $tl = [char]0x256D; $tr = [char]0x256E; $bl = [char]0x2570; $br = [char]0x256F; $v = [char]0x2502; $line = "$h" * 31; Write-Host "`n$([char]27)[38;2;228;0;43m$tl$line$tr$([char]27)[0m"; Write-Host "$([char]27)[38;2;228;0;43m$v$([char]27)[0m     $([char]27)[1;95mRunning All Dev Tools$([char]27)[0m     $([char]27)[38;2;228;0;43m$v$([char]27)[0m"; Write-Host "$([char]27)[38;2;228;0;43m$bl$line$br$([char]27)[0m`n"; $tools = @(@{N='Ruff Fmt';R='ruff-fmt';F=$true}, @{N='MDfmt';R='mdfmt';F=$true}, @{N='JSONfmt';R='jsonfmt';F=$true}, @{N='Ruff';R='ruff';F=$false}, @{N='JSONLint';R='jsonlint';F=$false}, @{N='ShellCheck';R='shellcheck';F=$false}, @{N='Blinter';R='blinter';F=$false}, @{N='Vulture';R='vulture';F=$false}, @{N='Dead';R='dead';F=$false}, @{N='Ty';R='ty';F=$false}, @{N='Bandit';R='bandit';F=$false}, @{N='Semgrep';R='semgrep';F=$false}, @{N='Flake8';R='flake8';F=$false}, @{N='McCabe';R='mccabe';F=$false}, @{N='Radon';R='radon';F=$false}, @{N='Xenon';R='xenon';F=$false}, @{N='Complexipy';R='complexipy';F=$false}, @{N='Markdown';R='mdlint';F=$false}, @{N='YAML';R='yamllint';F=$false}, @{N='Uncalled';R='uncalled';F=$false}, @{N='Deadcode';R='deadcode';F=$false}, @{N='PSScript';R='psscriptanalyzer';F=$false}, @{N='Pydocstyle';R='pydocstyle';F=$false}, @{N='Wemake';R='wemake';F=$false}, @{N='BasedPyright';R='basedpyright';F=$false}, @{N='Darglint';R='darglint';F=$false}, @{N='Mypy';R='mypy';F=$false}); $results = @{}; $globalStart = Get-Date; foreach ($tool in $tools) { try { $toolStart = Get-Date; $output = & { just $tool.R 2>&1 }; $duration = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 1); $findings = 0; $outputStr = $output -join "`n"; if (-not $tool.F -and $outputStr -match '(\d+)\s+findings') { $findings = [int]$matches[1] }; $results[$tool.R] = @{ Name = $tool.N; Findings = $findings; Duration = $duration; Success = $true; IsFormatter = $tool.F }; if ($tool.F) { Write-Host "  $([char]0x2714) $($tool.N): Done in ${duration}s" -ForegroundColor Green } else { Write-Host "  $([char]0x2714) $($tool.N): Completed in ${duration}s with $($findings) findings" -ForegroundColor Green } } catch { $duration = [Math]::Round(((Get-Date) - $toolStart).TotalSeconds, 1); $results[$tool.R] = @{ Name = $tool.N; Findings = 0; Duration = $duration; Success = $false; IsFormatter = $tool.F }; Write-Host "  $([char]0x2718) $($tool.N): Failed after ${duration}s - $_" -ForegroundColor Red } }; Write-Host "`n$([char]27)[90m$('-' * 60)$([char]27)[0m"; $totalTime = [Math]::Round(((Get-Date) - $globalStart).TotalSeconds, 1); $totalFindings = ($results.Values | ForEach-Object { $_.Findings } | Measure-Object -Sum).Sum; $passedCount = ($results.Values | Where-Object { $_.Success -and $_.Findings -eq 0 }).Count; Write-Host "Time: $([char]27)[36m${totalTime}s$([char]27)[0m | Findings: $([char]27)[33m$totalFindings$([char]27)[0m | Passed: $([char]27)[32m$passedCount/$($tools.Count)$([char]27)[0m"; exit 0

# ==================== SYSTEM ====================

# Kill all development processes with automatic elevation
kill:
    @$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); if(-not $isAdmin){ Write-Host "Requesting administrator elevation..." -ForegroundColor Yellow; $script = '$procs = @(\"python\",\"pythonw\",\"uv\",\"pixi\"); Write-Host \"\"; Write-Host \"=== Killing Dev Processes (Elevated) ===\" -ForegroundColor Cyan; Write-Host \"\"; $k=0; foreach($n in $procs){ $p=Get-Process -Name $n -EA SilentlyContinue; if($p){ $c=@($p).Count; $p | Stop-Process -Force -EA SilentlyContinue; Write-Host \"  [OK] $n ($c)\" -ForegroundColor Green; $k+=$c } else { Write-Host \"  [SKIP] $n\" -ForegroundColor DarkGray } }; Write-Host \"\"; Write-Host \"=== Done: $k killed ===\" -ForegroundColor Green; Write-Host \"\"; Read-Host \"Press Enter to close\"'; Start-Process pwsh -Verb RunAs -ArgumentList "-NoProfile","-Command",$script; exit 0 }; $procs = @("python","pythonw","uv","pixi"); Write-Host ""; Write-Host "=== Killing Dev Processes (Elevated) ===" -ForegroundColor Cyan; Write-Host ""; $k=0; foreach($n in $procs){ $p=Get-Process -Name $n -EA SilentlyContinue; if($p){ $c=@($p).Count; $p | Stop-Process -Force -EA SilentlyContinue; Write-Host "  [OK] $n ($c)" -ForegroundColor Green; $k+=$c } else { Write-Host "  [SKIP] $n" -ForegroundColor DarkGray } }; Write-Host ""; Write-Host "=== Done: $k killed ===" -ForegroundColor Green; Write-Host ""
