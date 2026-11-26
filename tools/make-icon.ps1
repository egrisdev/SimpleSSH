# Generates src/SimpleSSH/Assets/SimpleSSH.ico (PNG-compressed, multi-resolution).
# Usage: pwsh tools/make-icon.ps1
param([string]$Out = (Join-Path $PSScriptRoot '..\src\SimpleSSH\Assets\SimpleSSH.ico'))

Add-Type -AssemblyName System.Drawing
$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256

function New-RoundedRect([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

$pngs = foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)

    $m = [Math]::Max(0.5, $s * 0.04)
    $rect = New-RoundedRect $m $m ($s - 2 * $m) ($s - 2 * $m) ([Math]::Max(2, $s * 0.18))
    $bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush ([System.Drawing.PointF]::new(0, 0)), ([System.Drawing.PointF]::new(0, $s)), ([System.Drawing.Color]::FromArgb(255, 31, 41, 55)), ([System.Drawing.Color]::FromArgb(255, 17, 24, 39))
    $g.FillPath($bg, $rect)

    # Title bar accent
    if ($s -ge 24) {
        $bar = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 15, 108, 189))
        $g.SetClip($rect)
        $g.FillRectangle($bar, 0, 0, $s, [Math]::Round($s * 0.2))
        $g.ResetClip()
    }

    # ">" chevron and "_" cursor
    $w = [Math]::Max(1.6, $s * 0.09)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 74, 222, 128)), $w
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $top = if ($s -ge 24) { $s * 0.36 } else { $s * 0.28 }
    $mid = if ($s -ge 24) { $s * 0.55 } else { $s * 0.5 }
    $bot = if ($s -ge 24) { $s * 0.74 } else { $s * 0.72 }
    $g.DrawLines($pen, [System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new($s * 0.24, $top),
        [System.Drawing.PointF]::new($s * 0.44, $mid),
        [System.Drawing.PointF]::new($s * 0.24, $bot)))
    $pen2 = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 229, 231, 235)), $w
    $pen2.StartCap = 'Round'; $pen2.EndCap = 'Round'
    $g.DrawLine($pen2, $s * 0.52, $bot, $s * 0.76, $bot)

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    , $ms.ToArray()
}

New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
$fs = [System.IO.File]::Create($Out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s })))
    $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s })))
    $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]$pngs[$i].Length); $bw.Write([UInt32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $bw.Write($p) }
$bw.Dispose()
Write-Host "Wrote $Out"
