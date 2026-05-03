# eSE Copy Helper
# Copies data from eMule .part file bypassing file lock
param([string]$Source, [string]$Dest, [string]$MaxMB = "600")

$maxMBInt = [int]$MaxMB
$maxBytes = [long]$maxMBInt * 1048576

$fs = [System.IO.File]::Open($Source, 'Open', 'Read', 'ReadWrite')
$fw = [System.IO.File]::Create($Dest)
$buf = New-Object byte[] 4194304
$totalRead = [long]0
$limit = [Math]::Min($maxBytes, $fs.Length)


while ($totalRead -lt $limit) {
    $toRead = [Math]::Min($buf.Length, $limit - $totalRead)
    $bytesRead = $fs.Read($buf, 0, $toRead)
    if ($bytesRead -eq 0) { break }
    $fw.Write($buf, 0, $bytesRead)
    $totalRead += $bytesRead
}
$fs.Close()
$fw.Close()
Write-Host $totalRead
