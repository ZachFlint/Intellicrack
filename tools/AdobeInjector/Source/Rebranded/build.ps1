<#
Adobe Injector Build Script for Intellicrack
Full production build system - downloads dependencies, compiles, and packages
Requires administrative privileges
Run with: .\build.ps1 or via build.bat
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive build script uses Write-Host for colored console UI')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installBaseDir = Join-Path $env:SystemDrive "Intellicrack-BuildEnv"
$autoItInstallDir = Join-Path $installBaseDir "AutoIt"
$autoItCoreExe = Join-Path $autoItInstallDir "install\AutoIt3_x64.exe"
$sciteInstallDir = Join-Path $autoItInstallDir "install\SciTE"
$wrapperScript = Join-Path $sciteInstallDir "AutoIt3Wrapper\AutoIt3Wrapper.au3"
$scriptDir = $PSScriptRoot
$sourceDir = $scriptDir
$logsDir = Join-Path $scriptDir "Logs"
$releaseDir = Join-Path $scriptDir "Release"
$upxDir = Join-Path $scriptDir "UPX"
$winTrustDir = Join-Path $scriptDir "WinTrust"
$autoItZipPath = Join-Path $scriptDir "autoit-v3.zip"
$sciTEZipPath = Join-Path $scriptDir "SciTE4AutoIt3_Portable.zip"
$logPath = Join-Path $logsDir "build.log"
$upxExe = Join-Path $sourceDir "upx.exe"
$winTrustDll = Join-Path $sourceDir "wintrust.dll"

if (-not (Test-Path $logsDir)) {
    New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $releaseDir)) {
    New-Item -Path $releaseDir -ItemType Directory -Force | Out-Null
}

$autoItUrl = "https://www.autoitscript.com/files/autoit3/autoit-v3.zip"
$sciTEUrl = "https://www.autoitscript.com/autoit3/scite/download/SciTE4AutoIt3_Portable.zip"

$winTrustStockHash = "1B3BF770D4F59CA883391321A21923AE"
$winTrustPatchedHash = "B7A38368A52FF07D875E6465BD7EE26A"

Start-Transcript -Path $logPath -Append -NoClobber | Out-Null

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ExecutionPolicy {
}

function Get-MD5Hash {
    param ([string]$filePath)
    if (-not (Test-Path $filePath)) { return $null }
    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $hash = [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($filePath))).Replace("-", "").ToUpper()
    return $hash
}

function Get-UserConfirmation {
    param ([string]$Prompt)
    Write-Host $Prompt
    $response = Read-Host "Enter 'y' to proceed, 'n' to cancel"
    return $response -eq 'y' -or $response -eq 'Y'
}

function Save-FileFromUrl {
    param (
        [string]$Url,
        [string]$Destination
    )
    $success = $false
    $errorMessage = ""

    try {
        $curl = "curl.exe"
        if (Get-Command $curl -ErrorAction SilentlyContinue) {
            & $curl -L -o "$Destination" "$Url" --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" --silent --show-error --connect-timeout 30
            if ($LASTEXITCODE -eq 0 -and (Test-Path $Destination)) {
                $success = $true
            }
            else {
                $errorMessage = "curl failed with exit code $LASTEXITCODE"
            }
        }
    }
    catch {
        $errorMessage = "curl error: $_"
    }

    if (-not $success) {
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            $wc.DownloadFile($Url, $Destination)
            if (Test-Path $Destination) {
                $success = $true
            }
            else {
                $errorMessage = "WebClient completed but file not found"
            }
        }
        catch {
            $errorMessage = "WebClient error: $_"
        }
    }

    if (-not $success) {
        Write-Error "Failed to download $Url to $Destination - $errorMessage"
        Stop-Transcript | Out-Null
        exit 1
    }
}

Test-ExecutionPolicy

if (-not (Test-Admin)) {
    Write-Error "This script must be run as an Administrator. Right-click build.bat and select 'Run as administrator'."
    Stop-Transcript | Out-Null
    exit 1
}

if (-not (Test-Path $sourceDir)) {
    Write-Error "Source directory not found at $sourceDir."
    Stop-Transcript | Out-Null
    exit 1
}
if (-not (Test-Path $upxDir)) {
    Write-Error "UPX directory not found at $upxDir."
    Stop-Transcript | Out-Null
    exit 1
}
if (-not (Test-Path $winTrustDir)) {
    Write-Error "WinTrust directory not found at $winTrustDir."
    Stop-Transcript | Out-Null
    exit 1
}

$hasAutoIt = Test-Path $autoItCoreExe
$hasSciTE = Test-Path $wrapperScript
$hasUpx = Test-Path $upxExe
$hasWinTrust = Test-Path $winTrustDll
$winTrustStatus = if ($hasWinTrust) {
    $hash = Get-MD5Hash $winTrustDll
    if ($hash -eq $winTrustPatchedHash) { "patched" }
    elseif ($hash -eq $winTrustStockHash) { "stock" }
    else { "unknown" }
} else { "missing" }

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Adobe Injector Build System for Intellicrack" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

if ($hasUpx) {
    Write-Host " [OK] upx.exe found in build directory" -ForegroundColor Green
}
if ($hasWinTrust -and $winTrustStatus -eq "patched") {
    Write-Host " [OK] wintrust.dll found (patched)" -ForegroundColor Green
}
elseif ($hasWinTrust -and $winTrustStatus -eq "unknown") {
    Write-Warning " [WARN] wintrust.dll has unknown MD5 hash"
    if (-not (Get-UserConfirmation -Prompt "Proceed with current wintrust.dll? (y/n)")) {
        Write-Error "User chose not to proceed with unknown wintrust.dll."
        Stop-Transcript | Out-Null
        exit 1
    }
}
if ($hasAutoIt) {
    Write-Host " [OK] AutoIt3 found in $autoItInstallDir\" -ForegroundColor Green
}
if ($hasSciTE) {
    Write-Host " [OK] SciTE found in $sciteInstallDir\" -ForegroundColor Green
}

$downloadsNeeded = @()
if (!$hasAutoIt) { $downloadsNeeded += "AutoIt3 Portable (~17MB)" }
if (!$hasSciTE) { $downloadsNeeded += "SciTE Portable (~7MB)" }

if ($downloadsNeeded.Count -gt 0) {
    Write-Host ""
    Write-Host "The following components are missing and need to be downloaded:" -ForegroundColor Yellow
    $downloadsNeeded | ForEach-Object { Write-Host " - $_" }
    if (-not (Get-UserConfirmation -Prompt "Proceed with downloading these components? (y/n)")) {
        Write-Host "Operation cancelled by user."
        Stop-Transcript | Out-Null
        exit 0
    }
}

if (-not (Test-Path $installBaseDir)) {
    Write-Host ""
    Write-Host "[1/5] Creating build environment at $installBaseDir..." -ForegroundColor Cyan
    New-Item -Path $installBaseDir -ItemType Directory -Force | Out-Null
}

if (!$hasUpx) {
    Write-Host ""
    Write-Host "[2/5] Preparing UPX compression tool..." -ForegroundColor Cyan
    try {
        $upxExtractedDir = Get-ChildItem -Path $upxDir -Directory | Where-Object { $_.Name -match '^upx-.*-win64$' } | Select-Object -First 1
        if (-not $upxExtractedDir) {
            $upxZip = Get-ChildItem -Path $upxDir -File | Where-Object { $_.Name -match '^upx-.*-win64\.zip$' } | Select-Object -First 1
            if (-not $upxZip) {
                Write-Error "No UPX extracted directory or zip file found in $upxDir."
                Stop-Transcript | Out-Null
                exit 1
            }
            Write-Host "      Extracting: $($upxZip.Name)"

            $tarExe = "tar.exe"
            $extracted = $false
            if (Get-Command $tarExe -ErrorAction SilentlyContinue) {
                $tarOutLog = Join-Path $logsDir "tar_out.log"
                $tarErrLog = Join-Path $logsDir "tar_err.log"
                $process = Start-Process -FilePath $tarExe -ArgumentList "-xf `"$($upxZip.FullName)`" -C `"$upxDir`"" -Wait -PassThru -RedirectStandardOutput $tarOutLog -RedirectStandardError $tarErrLog
                if ($process.ExitCode -eq 0) {
                    $extracted = $true
                }
                else {
                    Write-Warning "      tar.exe failed, using Expand-Archive fallback"
                }
            }

            if (-not $extracted) {
                $unzipErrLog = Join-Path $logsDir "unzip_err.log"
                Expand-Archive -Path $upxZip.FullName -DestinationPath $upxDir -Force -ErrorAction Stop 2> $unzipErrLog
            }

            $upxExtractedDir = Get-ChildItem -Path $upxDir -Directory | Where-Object { $_.Name -match '^upx-.*-win64$' } | Select-Object -First 1
            if (-not $upxExtractedDir) {
                Write-Error "UPX extracted directory not found after extraction."
                Stop-Transcript | Out-Null
                exit 1
            }
        }
        $upxExtractedDir = $upxExtractedDir.FullName
        Write-Host "      Found: $upxExtractedDir"

        $upxExeSource = Join-Path $upxExtractedDir "upx.exe"
        if (-not (Test-Path $upxExeSource)) {
            Write-Error "UPX executable not found at $upxExeSource."
            Stop-Transcript | Out-Null
            exit 1
        }

        Copy-Item -Path $upxExeSource -Destination $sourceDir -Force
        Write-Host " [OK] UPX prepared successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to prepare UPX: $_"
        Stop-Transcript | Out-Null
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[2/5] UPX already available, skipping..." -ForegroundColor Green
}

if ($hasWinTrust -and $winTrustStatus -eq "patched") {
    Write-Host ""
    Write-Host "[3/5] wintrust.dll already patched, skipping..." -ForegroundColor Green
} elseif (!$hasWinTrust -or $winTrustStatus -eq "stock" -or $winTrustStatus -eq "unknown") {
    Write-Host ""
    Write-Host "[3/5] Patching wintrust.dll for signature bypass..." -ForegroundColor Cyan
    try {
        $patchScript = Join-Path $winTrustDir "patch_wintrust.ps1"
        $winTrustSource = Join-Path $winTrustDir "wintrust.dll"
        if (-not (Test-Path $patchScript)) {
            Write-Error "patch_wintrust.ps1 not found in $winTrustDir"
            Stop-Transcript | Out-Null
            exit 1
        }
        if (-not (Test-Path $winTrustSource)) {
            Write-Error "wintrust.dll not found in $winTrustDir"
            Stop-Transcript | Out-Null
            exit 1
        }
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$patchScript`"" -WorkingDirectory $winTrustDir -Wait -NoNewWindow
        $winTrustPatched = Join-Path $winTrustDir "wintrust.dll.patched"
        if (-not (Test-Path $winTrustPatched)) {
            Write-Error "wintrust.dll.patched not found after patching"
            Stop-Transcript | Out-Null
            exit 1
        }
        Move-Item -Path $winTrustPatched -Destination $winTrustDll -Force
        Write-Host " [OK] wintrust.dll patched successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to patch wintrust.dll: $_"
        Stop-Transcript | Out-Null
        exit 1
    }
}

if (!$hasAutoIt) {
    Write-Host ""
    Write-Host "[4/5] Downloading and installing AutoIt3..." -ForegroundColor Cyan
    try {
        Write-Host "      Downloading from: $autoItUrl"
        Save-FileFromUrl -Url $autoItUrl -Destination $autoItZipPath
        Write-Host "      Extracting to: $autoItInstallDir"

        New-Item -Path $autoItInstallDir -ItemType Directory -Force | Out-Null
        Remove-Item -Path "$autoItInstallDir\*" -Recurse -Force -ErrorAction SilentlyContinue

        $tarExe = "tar.exe"
        $extracted = $false
        if (Get-Command $tarExe -ErrorAction SilentlyContinue) {
            $tarOutLog = Join-Path $logsDir "tar_out.log"
            $tarErrLog = Join-Path $logsDir "tar_err.log"
            $process = Start-Process -FilePath $tarExe -ArgumentList "-xf `"$autoItZipPath`" -C `"$autoItInstallDir`"" -Wait -PassThru -RedirectStandardOutput $tarOutLog -RedirectStandardError $tarErrLog
            if ($process.ExitCode -eq 0) {
                $extracted = $true
            }
            else {
                Write-Warning "      tar.exe failed, using Expand-Archive fallback"
            }
        }

        if (-not $extracted) {
            $unzipErrLog = Join-Path $logsDir "unzip_err.log"
            Expand-Archive -Path $autoItZipPath -DestinationPath $autoItInstallDir -Force -ErrorAction Stop 2> $unzipErrLog
        }

        Remove-Item $autoItZipPath -Force -ErrorAction SilentlyContinue
        Write-Host " [OK] AutoIt3 installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download or extract AutoIt3: $_"
        Stop-Transcript | Out-Null
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[4/5] AutoIt3 already installed, skipping..." -ForegroundColor Green
}

if (!$hasSciTE) {
    Write-Host ""
    Write-Host "[4/5 continued] Downloading and installing SciTE..." -ForegroundColor Cyan
    try {
        Write-Host "      Downloading from: $sciTEUrl"
        Save-FileFromUrl -Url $sciTEUrl -Destination $sciTEZipPath
        $sciTEDestDir = Join-Path $autoItInstallDir "install\SciTE"
        Write-Host "      Extracting to: $sciTEDestDir"

        New-Item -Path $sciTEDestDir -ItemType Directory -Force | Out-Null
        Remove-Item -Path "$sciTEDestDir\*" -Recurse -Force -ErrorAction SilentlyContinue

        $tarExe = "tar.exe"
        $extracted = $false
        if (Get-Command $tarExe -ErrorAction SilentlyContinue) {
            $tarOutLog = Join-Path $logsDir "tar_out.log"
            $tarErrLog = Join-Path $logsDir "tar_err.log"
            $process = Start-Process -FilePath $tarExe -ArgumentList "-xf `"$sciTEZipPath`" -C `"$sciTEDestDir`"" -Wait -PassThru -RedirectStandardOutput $tarOutLog -RedirectStandardError $tarErrLog
            if ($process.ExitCode -eq 0) {
                $extracted = $true
            }
            else {
                Write-Warning "      tar.exe failed, using Expand-Archive fallback"
            }
        }

        if (-not $extracted) {
            $unzipErrLog = Join-Path $logsDir "unzip_err.log"
            Expand-Archive -Path $sciTEZipPath -DestinationPath $sciTEDestDir -Force -ErrorAction Stop 2> $unzipErrLog
        }

        Remove-Item $sciTEZipPath -Force -ErrorAction SilentlyContinue
        Write-Host " [OK] SciTE installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download or extract SciTE: $_"
        Stop-Transcript | Out-Null
        exit 1
    }
} else {
    if (!$hasAutoIt) {
        Write-Host ""
        Write-Host "[4/5 continued] SciTE already installed, skipping..." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "[5/5] Compiling AdobeInjector.exe..." -ForegroundColor Cyan
try {
    $au3Files = @(Get-ChildItem -Path $sourceDir -Filter "*.au3" -File -ErrorAction Stop)
    if ($au3Files.Count -eq 0) {
        Write-Error "No .au3 files found in $sourceDir."
        Stop-Transcript | Out-Null
        exit 1
    }
    if ($au3Files.Count -gt 1) {
        $strippedFiles = @($au3Files | Where-Object { $_.Name -like "*_stripped.au3" })
        if ($strippedFiles) {
            Write-Host "      Cleaning up stripped files: $($strippedFiles.Name -join ', ')" -ForegroundColor Yellow
            $strippedFiles | ForEach-Object { Remove-Item $_.FullName -Force }
            $au3Files = @(Get-ChildItem -Path $sourceDir -Filter "*.au3" -File -ErrorAction Stop)
        }
    }
    if ($au3Files.Count -ne 1) {
        Write-Error "Expected one .au3 file in $sourceDir, found $($au3Files.Count): $($au3Files.Name -join ', ')"
        Stop-Transcript | Out-Null
        exit 1
    }
    $au3File = $au3Files[0].FullName
    Write-Host "      Source file: $($au3Files[0].Name)"

    if (-not (Test-Path $autoItCoreExe)) {
        Write-Error "AutoIt3_x64.exe not found at $autoItCoreExe"
        Stop-Transcript | Out-Null
        exit 1
    }
    if (-not (Test-Path $wrapperScript)) {
        Write-Error "AutoIt3Wrapper.au3 not found at $wrapperScript"
        Stop-Transcript | Out-Null
        exit 1
    }

    $autoItOutLog = Join-Path $logsDir "AutoIt_out.log"
    $autoItErrLog = Join-Path $logsDir "AutoIt_err.log"
    Remove-Item -Path (Join-Path $sourceDir "AdobeInjector*.exe") -Force -ErrorAction SilentlyContinue
    $autoItArgs = "`"$wrapperScript`" /NoStatus /in `"$au3File`""
    Write-Host "      Invoking AutoIt3Wrapper..."
    Start-Process -FilePath $autoItCoreExe -ArgumentList $autoItArgs -WorkingDirectory $sourceDir -RedirectStandardOutput $autoItOutLog -RedirectStandardError $autoItErrLog -Wait -ErrorAction Stop

    $exeFiles = @(Get-ChildItem -Path $sourceDir -Filter "AdobeInjector*.exe" -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending)
    if ($exeFiles.Count -eq 0) {
        Write-Error "AutoIt3Wrapper failed to produce AdobeInjector.exe. Check $autoItErrLog for details."
        Stop-Transcript | Out-Null
        exit 1
    }
    if ($exeFiles.Count -gt 1) {
        $exeNames = $exeFiles.Name -join ', '
        Write-Host "      Warning: Multiple executables found: $exeNames" -ForegroundColor Yellow
        Write-Host "      Using most recent: $($exeFiles[0].Name)"
    }

    $builtExe = $exeFiles[0].FullName
    $releaseExe = Join-Path $releaseDir "AdobeInjector.exe"
    Copy-Item -Path $builtExe -Destination $releaseExe -Force -ErrorAction Stop
    Copy-Item -Path (Join-Path $sourceDir "config.ini") -Destination $releaseDir -Force -ErrorAction SilentlyContinue
    Copy-Item -Path $winTrustDll -Destination $releaseDir -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $releaseExe)) {
        Write-Error "Failed to copy executable to $releaseExe."
        Stop-Transcript | Out-Null
        exit 1
    }

    $fileSize = (Get-Item $releaseExe).Length
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
    Write-Host " [OK] Build completed successfully!" -ForegroundColor Green
    Write-Host "      Output: $releaseExe ($fileSizeMB MB)" -ForegroundColor Green

    Remove-Item -Path (Join-Path $sourceDir "AdobeInjector*_stripped.au3") -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Host " [ERROR] Failed to compile: $_" -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Build Process Completed Successfully!" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output files:" -ForegroundColor White
Write-Host "  - $releaseExe" -ForegroundColor White
Write-Host "  - $releaseDir\config.ini" -ForegroundColor White
Write-Host "  - $releaseDir\wintrust.dll" -ForegroundColor White
Write-Host ""
Stop-Transcript | Out-Null
