$script:e = [char]27

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Write-Step {
    param([string]$Tag, [string]$Msg, [string]$Color = '36')
    Write-Host "$script:e[${Color}m[$Tag]$script:e[0m $Msg"
}

function Write-Success {
    param([string]$Msg)
    Write-Host "  $script:e[32m[OK]$script:e[0m $Msg"
}

function Write-Fail {
    param([string]$Msg)
    Write-Host "  $script:e[31m[FAIL]$script:e[0m $Msg" -ForegroundColor Red
}

function Write-Progress {
    param([string]$Msg)
    Write-Host "  $script:e[90m...$script:e[0m $Msg"
}

function Write-Skip {
    param([string]$Msg)
    Write-Host "  $script:e[33m[SKIP]$script:e[0m $Msg"
}

function Write-Banner {
    param([string]$Title)
    Write-Host "`n$script:e[1;36m=== $Title ===$script:e[0m`n"
}

function Write-Footer {
    param([string]$Title, [datetime]$StartTime)
    $elapsed = ((Get-Date) - $StartTime).TotalSeconds
    Write-Host "`n$script:e[1;32m=== $Title ===$script:e[0m"
    Write-Host "$script:e[90mTotal time: $("{0:N1}" -f $elapsed) seconds$script:e[0m`n"
}

function Install-GitHubRelease {
    param(
        [Parameter(Mandatory)][string]$Tag,
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$AssetPattern,
        [string]$AssetExclude,
        [Parameter(Mandatory)][string]$DestName,
        [string]$VerifyFile,
        [string[]]$AlternateVerifyFiles,
        [string]$SearchPath = 'tools',
        [switch]$DirectExtract,
        [int]$MinSizeBytes = 1000000
    )

    $startTime = Get-Date

    Write-Step $Tag "Creating tools directory..."
    try {
        if (!(Test-Path "tools")) { New-Item -ItemType Directory -Path "tools" -Force | Out-Null }
        if (-not (Test-Path "tools")) { throw "Failed to create tools directory" }
        Write-Success "Tools directory ready"
    } catch {
        Write-Fail "Directory creation failed: $_"
        exit 1
    }

    Write-Step $Tag "Checking existing installation..."
    if ($VerifyFile) {
        $existing = Get-ChildItem -Path $SearchPath -Recurse -Filter $VerifyFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if (!$existing -and $AlternateVerifyFiles) {
            foreach ($alt in $AlternateVerifyFiles) {
                $existing = Get-ChildItem -Path $SearchPath -Recurse -Filter $alt -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($existing) { break }
            }
        }
        if ($existing) {
            Write-Success "$Tag already installed at $($existing.DirectoryName)"
            exit 0
        }
    }

    Write-Step $Tag "Fetching latest release from GitHub..."
    $maxRetries = 3
    $release = $null
    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -TimeoutSec 30
            break
        } catch {
            if ($i -eq $maxRetries) { Write-Fail "GitHub API request failed after $maxRetries attempts: $_"; exit 1 }
            Write-Progress "Retry $i/$maxRetries..."
            Start-Sleep -Seconds 2
        }
    }

    $assets = $release.assets | Where-Object { $_.name -match $AssetPattern }
    if ($AssetExclude) { $assets = $assets | Where-Object { $_.name -notmatch $AssetExclude } }
    $asset = $assets | Select-Object -First 1
    if (!$asset) { Write-Fail "Could not find release asset matching pattern"; exit 1 }

    $downloadUrl = $asset.browser_download_url
    $fileName = $asset.name
    $fileSize = [math]::Round($asset.size / 1MB, 1)
    $zipPath = Join-Path "tools" $fileName
    Write-Success "Found: $fileName ($fileSize MB)"

    Write-Step $Tag "Downloading $fileName..."
    $ProgressPreference = 'SilentlyContinue'
    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -TimeoutSec 600
            if (-not (Test-Path $zipPath)) { throw "Download file not found" }
            $actualSize = (Get-Item $zipPath).Length
            if ($actualSize -lt $MinSizeBytes) { throw "Downloaded file too small ($actualSize bytes)" }
            break
        } catch {
            if ($i -eq $maxRetries) { Write-Fail "Download failed after $maxRetries attempts: $_"; exit 1 }
            Write-Progress "Retry $i/$maxRetries..."
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Seconds 5
        }
    }
    Write-Success "Download complete"

    $destPath = Join-Path "tools" $DestName

    if ($DirectExtract) {
        Write-Step $Tag "Extracting..."
        try {
            if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }
            New-Item -ItemType Directory -Path $destPath -Force | Out-Null
            Expand-Archive -Path $zipPath -DestinationPath $destPath -ErrorAction Stop
            Write-Success "Extraction complete"
        } catch {
            Write-Fail "Extraction failed: $_"
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            exit 1
        }
    } else {
        Write-Step $Tag "Extracting..."
        $tempExtract = Join-Path "tools" "${DestName}_temp"
        try {
            if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }
            Expand-Archive -Path $zipPath -DestinationPath $tempExtract -ErrorAction Stop
            Write-Success "Extraction complete"
        } catch {
            Write-Fail "Extraction failed: $_"
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            exit 1
        }

        Write-Step $Tag "Installing..."
        try {
            $extractedDir = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1
            if (Test-Path $destPath) { Remove-Item $destPath -Recurse -Force }
            if ($extractedDir) {
                Move-Item -Path $extractedDir.FullName -Destination $destPath -ErrorAction Stop
            } else {
                Move-Item -Path $tempExtract -Destination $destPath -ErrorAction Stop
            }
            Write-Success "Installation complete"
        } catch {
            Write-Fail "Installation failed: $_"
            exit 1
        }
    }

    if ($VerifyFile) {
        Write-Step $Tag "Verifying installation..."
        $installed = Get-ChildItem -Path $destPath -Recurse -Filter $VerifyFile -ErrorAction SilentlyContinue | Select-Object -First 1
        if (!$installed -and $AlternateVerifyFiles) {
            foreach ($alt in $AlternateVerifyFiles) {
                $installed = Get-ChildItem -Path $destPath -Recurse -Filter $alt -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($installed) { break }
            }
        }
        if (!$installed) { Write-Fail "$VerifyFile not found after installation"; exit 1 }
        Write-Success "Installation verified"
    }

    Write-Step $Tag "Cleaning up..."
    try {
        if (Test-Path (Join-Path "tools" "${DestName}_temp")) {
            Remove-Item (Join-Path "tools" "${DestName}_temp") -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Write-Success "Cleanup complete"
    } catch {
        Write-Progress "Cleanup warning: $_"
    }

    $elapsed = ((Get-Date) - $startTime).TotalSeconds
    Write-Host "`n$script:e[32m$Tag installed to tools\$DestName$script:e[0m $script:e[90m($("{0:N1}" -f $elapsed)s)$script:e[0m"
}
