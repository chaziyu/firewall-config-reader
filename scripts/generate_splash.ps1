param(
    [string]$Version = "2.4.4",
    [string]$LogoPath = (Join-Path $PSScriptRoot "..\assets\app_logo.png"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "assets\splash.png")
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$cleanVersion = ($Version.Trim() -replace '^[vV]+', '')
if (-not $cleanVersion) {
    $cleanVersion = "0.0.0"
}

$width = 480
$height = 240

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$bmp = New-Object System.Drawing.Bitmap($width, $height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = $null
$bgBrush = $null
$accentBrush = $null
$titleBrush = $null
$subBrush = $null
$statusBrush = $null
$borderPen = $null
$titleFont = $null
$subFont = $null
$statusFont = $null
$logo = $null

try {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

    $bgColor = [System.Drawing.Color]::FromArgb(255, 255, 255, 255)
    $accentColor = [System.Drawing.Color]::FromArgb(255, 29, 111, 232)
    $borderColor = [System.Drawing.Color]::FromArgb(255, 203, 213, 225)
    $titleColor = [System.Drawing.Color]::FromArgb(255, 15, 23, 42)
    $statusColor = [System.Drawing.Color]::FromArgb(255, 100, 116, 139)

    $bgBrush = New-Object System.Drawing.SolidBrush($bgColor)
    $accentBrush = New-Object System.Drawing.SolidBrush($accentColor)
    $titleBrush = New-Object System.Drawing.SolidBrush($titleColor)
    $subBrush = New-Object System.Drawing.SolidBrush($accentColor)
    $statusBrush = New-Object System.Drawing.SolidBrush($statusColor)
    $borderPen = New-Object System.Drawing.Pen($borderColor, 1)

    $g.FillRectangle($bgBrush, 0, 0, $width, $height)
    $g.FillRectangle($accentBrush, 0, 0, $width, 6)
    $g.DrawRectangle($borderPen, 0, 0, $width - 1, $height - 1)

    if ($LogoPath -and (Test-Path $LogoPath)) {
        $logo = [System.Drawing.Image]::FromFile((Resolve-Path $LogoPath).Path)
        $g.DrawImage($logo, 36, 76, 88, 88)
    }

    $titleFont = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Point)
    $subFont = New-Object System.Drawing.Font("Segoe UI", 10.5, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Point)
    $statusFont = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Point)

    $g.DrawString("Firewall Config Reader", $titleFont, $titleBrush, 142, 76)
    $g.DrawString("Local Firewall Analysis Console  |  v$cleanVersion", $subFont, $subBrush, 142, 114)
    $g.DrawString("Starting local workspace...", $statusFont, $statusBrush, 142, 146)

    $bmp.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
}
finally {
    if ($logo) { $logo.Dispose() }
    if ($titleFont) { $titleFont.Dispose() }
    if ($subFont) { $subFont.Dispose() }
    if ($statusFont) { $statusFont.Dispose() }
    if ($borderPen) { $borderPen.Dispose() }
    if ($bgBrush) { $bgBrush.Dispose() }
    if ($accentBrush) { $accentBrush.Dispose() }
    if ($titleBrush) { $titleBrush.Dispose() }
    if ($subBrush) { $subBrush.Dispose() }
    if ($statusBrush) { $statusBrush.Dispose() }
    if ($g) { $g.Dispose() }
    if ($bmp) { $bmp.Dispose() }
}
