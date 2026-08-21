#Requires -Version 7
# Generates the Inno Setup wizard images from the real Intellicrack app icon.
#
# The large welcome/finished banner (WizardImageFile / WizardImageFileDynamicDark)
# is built by compositing the app-icon tile onto one of the committed brand
# backgrounds under backgrounds\; the small page icon (WizardSmallImageFile) is
# the bare tile on transparency. Images render at 3x the classic Inno base sizes
# so they stay crisp up to 300% display scaling. Re-run to regenerate.
#
# The app icon's 256x256 frame is PNG-compressed, which System.Drawing.Icon
# cannot decode (it silently falls back to the 64x64 BMP frame). This script
# therefore extracts the largest frame's PNG bytes directly and never scales the
# 256px source up, so the artwork stays sharp. icon.ico is the single source of
# the wordmark: correct it there and every wizard image follows.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Drawing

$Here = $PSScriptRoot
$IconPath = (Resolve-Path (Join-Path $Here '..\..\src\intellicrack\assets\icon.ico')).Path
$BgDir = Join-Path $Here 'backgrounds'
$OptDir = Join-Path $Here 'options'

$Scale = 3
$BannerW = 164 * $Scale
$BannerH = 314 * $Scale
$SmallSz = 55 * $Scale
$Accent = [System.Drawing.Color]::FromArgb(7, 197, 255)

# All brand backgrounds, in presentation order. The active wizard banner uses
# $SelectedKey; every entry is also rendered to options\ for future reuse.
$Backgrounds = @(
    [pscustomobject]@{ Key = 'circuit'; Label = 'Circuit'; File = '1-circuit.png' }
    [pscustomobject]@{ Key = 'neuralring'; Label = 'Neural Ring'; File = '2-neuralring.png' }
    [pscustomobject]@{ Key = 'lowpoly'; Label = 'Low-Poly'; File = '3-lowpoly.png' }
    [pscustomobject]@{ Key = 'ribbons'; Label = 'Ribbons'; File = '4-ribbons.png' }
    [pscustomobject]@{ Key = 'hexgrid'; Label = 'Hex Grid'; File = '5-hexgrid.png' }
    [pscustomobject]@{ Key = 'particles'; Label = 'Particles'; File = '6-particles.png' }
)
$SelectedKey = 'neuralring'

function Get-IconSourceBitmap {
    <#
    .SYNOPSIS
        Load the app icon's largest frame (the 256x256 PNG) as a crisp bitmap.
    .DESCRIPTION
        Parses the ICONDIR, selects the widest frame, and decodes its embedded
        PNG bytes through System.Drawing.Image so the true 256px artwork is used
        instead of the 64px BMP fallback that Icon.ToBitmap() returns.
    .OUTPUTS
        System.Drawing.Bitmap. The decoded 256x256 icon tile.
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

function Set-Quality {
    <#
    .SYNOPSIS
        Apply the highest-quality rendering hints to a Graphics context.
    .PARAMETER G
        The Graphics context to configure.
    #>
    param([Parameter(Mandatory)][System.Drawing.Graphics]$G)
    $G.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $G.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $G.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $G.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $G.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
}

function New-RoundedRectPath {
    <#
    .SYNOPSIS
        Build a rounded-rectangle GraphicsPath.
    .PARAMETER X
        Left edge of the rectangle.
    .PARAMETER Y
        Top edge of the rectangle.
    .PARAMETER W
        Rectangle width.
    .PARAMETER H
        Rectangle height.
    .PARAMETER R
        Corner radius.
    .OUTPUTS
        System.Drawing.Drawing2D.GraphicsPath. The rounded-rectangle path.
    #>
    param(
        [Parameter(Mandatory)][single]$X,
        [Parameter(Mandatory)][single]$Y,
        [Parameter(Mandatory)][single]$W,
        [Parameter(Mandatory)][single]$H,
        [Parameter(Mandatory)][single]$R
    )
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $R * 2
    $path.AddArc($X, $Y, $d, $d, 180, 90)
    $path.AddArc($X + $W - $d, $Y, $d, $d, 270, 90)
    $path.AddArc($X + $W - $d, $Y + $H - $d, $d, $d, 0, 90)
    $path.AddArc($X, $Y + $H - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

function Add-Background {
    <#
    .SYNOPSIS
        Paint a background image scaled to cover the banner (centre-cropped).
    .PARAMETER G
        Target Graphics context.
    .PARAMETER Path
        Path to the source background image.
    #>
    param(
        [Parameter(Mandatory)][System.Drawing.Graphics]$G,
        [Parameter(Mandatory)][string]$Path
    )
    $bg = [System.Drawing.Image]::FromFile($Path)
    try {
        $scale = [double]$BannerH / $bg.Height
        $scaledW = [int]($bg.Width * $scale)
        if ($scaledW -lt $BannerW) {
            $scale = [double]$BannerW / $bg.Width
            $scaledW = $BannerW
        }
        $scaledH = [int]($bg.Height * $scale)
        $offX = [int](($scaledW - $BannerW) / 2)
        $offY = [int](($scaledH - $BannerH) / 2)
        $G.DrawImage($bg, (New-Object System.Drawing.Rectangle(-$offX, -$offY, $scaledW, $scaledH)))
    } finally {
        $bg.Dispose()
    }
}

function Add-IconTile {
    <#
    .SYNOPSIS
        Draw the app icon as a rounded tile with a soft shadow and hairline edge.
    .DESCRIPTION
        The app icon fills its 256px canvas edge to edge with a near-black
        background, which reads as a hard box on a photographic background.
        Clipping it to a rounded rectangle, laying a soft layered shadow beneath
        it, and stroking a subtle light edge on top makes it read as an
        intentional app tile floating on the artwork.
    .PARAMETER G
        Target Graphics context.
    .PARAMETER Icon
        The 256px icon bitmap.
    .PARAMETER X
        Tile left edge.
    .PARAMETER Y
        Tile top edge.
    .PARAMETER Size
        Tile edge length in pixels.
    #>
    param(
        [Parameter(Mandatory)][System.Drawing.Graphics]$G,
        [Parameter(Mandatory)][System.Drawing.Bitmap]$Icon,
        [Parameter(Mandatory)][int]$X,
        [Parameter(Mandatory)][int]$Y,
        [Parameter(Mandatory)][int]$Size
    )
    $radius = [single]($Size * 0.16)

    for ($s = 14; $s -ge 1; $s--) {
        $grow = [single]($s * 1.7)
        $sp = New-RoundedRectPath ([single]($X - $grow)) ([single]($Y - $grow + $Size * 0.03)) `
            ([single]($Size + 2 * $grow)) ([single]($Size + 2 * $grow)) ([single]($radius + $grow))
        $sb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(9, 0, 0, 0))
        $G.FillPath($sb, $sp)
        $sb.Dispose(); $sp.Dispose()
    }

    $clip = New-RoundedRectPath ([single]$X) ([single]$Y) ([single]$Size) ([single]$Size) $radius
    $G.SetClip($clip)
    $G.DrawImage($Icon, $X, $Y, $Size, $Size)
    $G.ResetClip()

    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(60, 255, 255, 255), [single]2.0)
    $G.DrawPath($pen, $clip)
    $pen.Dispose(); $clip.Dispose()
}

function Add-Subtitle {
    <#
    .SYNOPSIS
        Draw the subtitle on a dark scrim chip so it stays legible on any art.
    .DESCRIPTION
        A semi-transparent navy chip with a cyan hairline sits behind the text,
        and the text carries a soft drop shadow, so the label reads cleanly over
        both dark and bright regions of a photographic background. A cyan accent
        rule underlines the chip.
    .PARAMETER G
        Target Graphics context.
    #>
    param([Parameter(Mandatory)][System.Drawing.Graphics]$G)
    $subtitle = 'Binary Analysis Platform'
    $fmt = New-Object System.Drawing.StringFormat
    $fmt.Alignment = [System.Drawing.StringAlignment]::Center
    $fmt.LineAlignment = [System.Drawing.StringAlignment]::Center
    $font = New-Object System.Drawing.Font('Segoe UI', [single]($BannerH * 0.028), [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    try {
        $cx = [single]($BannerW / 2)
        $ty = [single]($BannerH * 0.62)

        $sz = $G.MeasureString($subtitle, $font)
        $padX = [single]22; $padY = [single]9
        $chipW = $sz.Width + 2 * $padX
        $chipH = $sz.Height + 2 * $padY
        $chipX = [single]($cx - $chipW / 2)
        $chipY = [single]($ty - $chipH / 2)
        $chip = New-RoundedRectPath $chipX $chipY $chipW $chipH ([single]($chipH / 2))
        try {
            $cb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(120, 4, 10, 20))
            $G.FillPath($cb, $chip); $cb.Dispose()
            $cp = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(45, 7, 197, 255), [single]1.0)
            $G.DrawPath($cp, $chip); $cp.Dispose()
        } finally {
            $chip.Dispose()
        }

        $shadow = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(150, 0, 0, 0))
        $G.DrawString($subtitle, $font, $shadow, [single]($cx + 1), [single]($ty + 1), $fmt)
        $shadow.Dispose()
        $text = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(240, 247, 253))
        $G.DrawString($subtitle, $font, $text, $cx, $ty, $fmt)
        $text.Dispose()

        $uy = [single]($chipY + $chipH + $BannerH * 0.018)
        $pen = New-Object System.Drawing.Pen($Accent, [single]2.6)
        $G.DrawLine($pen, [single]($BannerW * 0.34), $uy, [single]($BannerW * 0.66), $uy)
        $pen.Dispose()
    } finally {
        $font.Dispose(); $fmt.Dispose()
    }
}

function New-Banner {
    <#
    .SYNOPSIS
        Render one large welcome banner (background, icon tile, subtitle).
    .PARAMETER OutFile
        Destination PNG path.
    .PARAMETER BackgroundPath
        Source background image to composite under the tile.
    .PARAMETER Icon
        The 256px icon bitmap to place as the app tile.
    #>
    param(
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string]$BackgroundPath,
        [Parameter(Mandatory)][System.Drawing.Bitmap]$Icon
    )
    $bmp = New-Object System.Drawing.Bitmap($BannerW, $BannerH, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        Set-Quality -G $g
        Add-Background -G $g -Path $BackgroundPath

        $iconSize = 256
        $iconX = [int](($BannerW - $iconSize) / 2)
        $iconY = [int]($BannerH * 0.18)
        Add-IconTile -G $g -Icon $Icon -X $iconX -Y $iconY -Size $iconSize
        Add-Subtitle -G $g

        $bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Png)
        Write-Host "wrote $OutFile ($BannerW x $BannerH)"
    } finally {
        $g.Dispose(); $bmp.Dispose()
    }
}

function New-SmallIcon {
    <#
    .SYNOPSIS
        Render the transparent small page icon used on interior wizard pages.
    .PARAMETER OutFile
        Destination PNG path.
    .PARAMETER Icon
        The 256px icon bitmap, downscaled onto a transparent canvas.
    #>
    param(
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][System.Drawing.Bitmap]$Icon
    )
    $bmp = New-Object System.Drawing.Bitmap($SmallSz, $SmallSz, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        Set-Quality -G $g
        $g.Clear([System.Drawing.Color]::Transparent)
        $g.DrawImage($Icon, 0, 0, $SmallSz, $SmallSz)
        $bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Png)
        Write-Host "wrote $OutFile ($SmallSz x $SmallSz)"
    } finally {
        $g.Dispose(); $bmp.Dispose()
    }
}

if (-not (Test-Path $OptDir)) { New-Item -ItemType Directory -Path $OptDir | Out-Null }

$icon = Get-IconSourceBitmap
try {
    $selected = $Backgrounds | Where-Object { $_.Key -eq $SelectedKey } | Select-Object -First 1
    if ($null -eq $selected) { throw "selected background '$SelectedKey' not found in the background table" }

    # Render every option to options\ so any can be promoted later.
    foreach ($bg in $Backgrounds) {
        $bgPath = Join-Path $BgDir $bg.File
        if (-not (Test-Path $bgPath)) { throw "missing background: $bgPath" }
        New-Banner -OutFile (Join-Path $OptDir ("option-{0}.png" -f $bg.Key)) -BackgroundPath $bgPath -Icon $icon
    }

    # The active wizard banner. modern-dynamic swaps light/dark by system theme;
    # the chosen artwork is dark and works in both, so both slots use it.
    $selectedPath = Join-Path $BgDir $selected.File
    New-Banner -OutFile (Join-Path $Here 'banner-dark.png') -BackgroundPath $selectedPath -Icon $icon
    New-Banner -OutFile (Join-Path $Here 'banner-light.png') -BackgroundPath $selectedPath -Icon $icon
    New-SmallIcon -OutFile (Join-Path $Here 'small.png') -Icon $icon
} finally {
    $icon.Dispose()
}

Write-Host "wizard images generated (active background: $SelectedKey)"
