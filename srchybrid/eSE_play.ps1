# eSE Player v1.0
# Usage: .\eSE_play.ps1 [part_file_number]
# Example: .\eSE_play.ps1 001

param(
    [string]$PartNum = "001",
    [int]$CopyMB = 0  # 0 = copy all available
)

$ErrorActionPreference = "Stop"

# Paths
$emuleTemp = "C:\Users\iunan\Downloads\eMule\Temp"
$partFile = Join-Path $emuleTemp "$PartNum.part"
$ffmpegPath = (Get-ChildItem "C:\Users\iunan\AppData\Local\Microsoft\WinGet" -Recurse -Filter "ffmpeg.exe" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
$mpvPath = "C:\Program Files\MPV Player\mpv.exe"
$tempAvi = "$env:TEMP\eSE_temp.avi"
$tempTs = "$env:TEMP\eSE_stream.mp4"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   eSE Player v1.0" -ForegroundColor Cyan  
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Validate
if (!(Test-Path $partFile)) {
    Write-Host "ERROR: Part file not found: $partFile" -ForegroundColor Red
    Write-Host "Available .part files:"
    Get-ChildItem "$emuleTemp\*.part" | ForEach-Object { Write-Host "  $($_.Name) - $([Math]::Round($_.Length/1MB))MB" }
    exit 1
}

$fileSize = (Get-Item $partFile).Length
Write-Host "Part file: $partFile ($([Math]::Round($fileSize/1MB))MB)" -ForegroundColor Green

# Step 1: Copy data from .part (bypassing eMule's file lock)
Write-Host ""
Write-Host "[1/3] Copying data from .part file..." -ForegroundColor Yellow

$fs = [System.IO.File]::Open($partFile, 'Open', 'Read', 'ReadWrite')
$fw = [System.IO.File]::Create($tempAvi)
$buf = New-Object byte[] (4MB)
$totalRead = 0
$maxBytes = if ($CopyMB -gt 0) { $CopyMB * 1MB } else { $fs.Length }

while ($totalRead -lt $maxBytes) {
    $toRead = [Math]::Min($buf.Length, $maxBytes - $totalRead)
    $bytesRead = $fs.Read($buf, 0, $toRead)
    if ($bytesRead -eq 0) { break }
    $fw.Write($buf, 0, $bytesRead)
    $totalRead += $bytesRead
    $pct = [Math]::Round($totalRead * 100 / $maxBytes)
    Write-Host "`r  Copied: $([Math]::Round($totalRead/1MB))MB / $([Math]::Round($maxBytes/1MB))MB ($pct%)" -NoNewline
}
$fs.Close()
$fw.Close()
Write-Host ""
Write-Host "  Done! Temp file: $([Math]::Round($totalRead/1MB))MB" -ForegroundColor Green

# Step 2: Remux with ffmpeg (AVI -> MP4, no re-encoding)
Write-Host ""
Write-Host "[2/3] Remuxing with ffmpeg (instant, no re-encoding)..." -ForegroundColor Yellow

$ffArgs = "-i `"$tempAvi`" -c copy -err_detect ignore_err -y `"$tempTs`""
$proc = Start-Process -FilePath $ffmpegPath -ArgumentList $ffArgs -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Host "  Warning: ffmpeg returned $($proc.ExitCode), trying anyway..." -ForegroundColor Yellow
}
$remuxSize = if (Test-Path $tempTs) { [Math]::Round((Get-Item $tempTs).Length/1MB) } else { 0 }
Write-Host "  Done! Remuxed: ${remuxSize}MB" -ForegroundColor Green

# Step 3: Launch player
Write-Host ""
Write-Host "[3/3] Launching mpv player..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  ENJOY THE MOVIE!" -ForegroundColor Cyan
Write-Host ""

Start-Process $mpvPath -ArgumentList "`"$tempTs`""
