#Requires -Version 7
# Rebuilds src/intellicrack/assets/icon.ico with a complete frame set.
#
# The committed icon carried only 24/32/48/64/256 frames, so Windows had no
# 16px or 20px frame for title bars, small taskbar buttons, and 125% display
# scaling and fell back to downscaling a larger frame. This regenerates the
# icon with 16/20/24/32/40/48/64/128/256 frames from the crisp 256px source.
#
# The minimum supported OS is Windows 10, which reads PNG-compressed frames at
# every size, so all frames are stored as PNG. Re-run after changing the 256px
# artwork; generate_banners.ps1 then picks up the refreshed source.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Drawing

$Here = $PSScriptRoot
$IconPath = (Resolve-Path (Join-Path $Here '..\..\src\intellicrack\assets\icon.ico')).Path

$FrameSizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)

function Get-IconMaster {
    <#
    .SYNOPSIS
        Decode the icon's largest frame (the 256x256 PNG) into a crisp bitmap.
    .OUTPUTS
        System.Drawing.Bitmap. The decoded 256px master bitmap.
    #>
    $bytes = [System.IO.File]::ReadAllBytes($IconPath)
    $count = [BitConverter]::ToUInt16($bytes, 4)
    $bestW = -1; $bestOff = 0; $bestSz = 0
    for ($i = 0; $i -lt $count; $i++) {
        $o = 6 + $i * 16
        $w = $bytes[$o]; if ($w -eq 0) { $w = 256 }
        $sz = [BitConverter]::ToUInt32($bytes, $o + 8)
        $off = [BitConverter]::ToUInt32($bytes, $o + 12)
        if ($w -gt $bestW) { $bestW = $w; $bestOff = $off; $bestSz = $sz }
    }
    $isPng = ($bytes[$bestOff] -eq 0x89 -and $bytes[$bestOff + 1] -eq 0x50 `
        -and $bytes[$bestOff + 2] -eq 0x4E -and $bytes[$bestOff + 3] -eq 0x47)
    if (-not $isPng) {
        throw "Largest icon frame (${bestW}px) is not PNG-compressed; cannot extract a crisp source."
    }
    $frame = New-Object byte[] $bestSz
    [Array]::Copy($bytes, $bestOff, $frame, 0, $bestSz)
    $ms = New-Object System.IO.MemoryStream(, $frame)
    try {
        $img = [System.Drawing.Image]::FromStream($ms)
        try {
            return New-Object System.Drawing.Bitmap($img)
        } finally {
            $img.Dispose()
        }
    } finally {
        $ms.Dispose()
    }
}

function Get-FramePng {
    <#
    .SYNOPSIS
        Render the master bitmap to a size and return its PNG-encoded bytes.
    .PARAMETER Master
        The 256px master bitmap.
    .PARAMETER Size
        Target square edge length in pixels.
    .OUTPUTS
        System.Byte[]. PNG bytes for the rendered frame.
    #>
    param(
        [Parameter(Mandatory)][System.Drawing.Bitmap]$Master,
        [Parameter(Mandatory)][int]$Size
    )
    $bmp = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $g.DrawImage($Master, 0, 0, $Size, $Size)
    } finally {
        $g.Dispose()
    }
    $ms = New-Object System.IO.MemoryStream
    try {
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        return , $ms.ToArray()
    } finally {
        $ms.Dispose(); $bmp.Dispose()
    }
}

$master = Get-IconMaster
try {
    $frames = foreach ($s in $FrameSizes) {
        [pscustomobject]@{ Size = $s; Png = (Get-FramePng -Master $master -Size $s) }
    }
} finally {
    $master.Dispose()
}

$count = $frames.Count
$offset = 6 + 16 * $count
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)
try {
    $bw.Write([uint16]0)      # reserved
    $bw.Write([uint16]1)      # type: icon
    $bw.Write([uint16]$count)
    foreach ($f in $frames) {
        $dim = if ($f.Size -ge 256) { [byte]0 } else { [byte]$f.Size }
        $bw.Write([byte]$dim)                 # width
        $bw.Write([byte]$dim)                 # height
        $bw.Write([byte]0)                    # palette colour count
        $bw.Write([byte]0)                    # reserved
        $bw.Write([uint16]1)                  # colour planes
        $bw.Write([uint16]32)                 # bits per pixel
        $bw.Write([uint32]$f.Png.Length)      # bytes in resource
        $bw.Write([uint32]$offset)            # image offset
        $offset += $f.Png.Length
    }
    foreach ($f in $frames) { $bw.Write($f.Png) }
    $bw.Flush()
    [System.IO.File]::WriteAllBytes($IconPath, $out.ToArray())
} finally {
    $bw.Dispose(); $out.Dispose()
}

Write-Host "wrote $IconPath with frames: $($FrameSizes -join ', ')"
