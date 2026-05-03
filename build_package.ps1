$src = "c:\Users\iunan\OneDrive\Desktop\eMule0.70b-Sources"
$dst = "$src\eSE-Package"
$zip = "c:\Users\iunan\OneDrive\Desktop\eSE-Package-x64.zip"
if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
New-Item -ItemType Directory $dst | Out-Null
Write-Host "[1] emule.exe"
Copy-Item "$src\srchybrid\x64\Release\emule.exe" "$dst\emule.exe"
Write-Host "[2] eSE modules"
New-Item -ItemType Directory "$dst\eSE" | Out-Null
Get-ChildItem "$src\srchybrid\eSE\*.js" | Copy-Item -Destination "$dst\eSE"
foreach ($f in "package.json","package-lock.json","emule_mascot.svg","favicon.ico","cloudflared.exe") {
    $fp = "$src\srchybrid\eSE\$f"
    if (Test-Path $fp) { Copy-Item $fp "$dst\eSE" }
}
foreach ($sd in "pages","routes","shared","eSE-live") {
    $sp = "$src\srchybrid\eSE\$sd"
    if (Test-Path $sp) { Copy-Item $sp "$dst\eSE\$sd" -Recurse }
}
Write-Host "[3] node_modules"
if (Test-Path "$src\srchybrid\eSE\node_modules") {
    try {
        Copy-Item "$src\srchybrid\eSE\node_modules" "$dst\eSE\node_modules" -Recurse -ErrorAction Stop
        Write-Host "  node_modules OK"
    } catch {
        Write-Host "  node_modules partial copy (some files locked): $_" -ForegroundColor DarkYellow
    }
}
Write-Host "[4] node.exe"
New-Item -ItemType Directory "$dst\node" | Out-Null
if (Get-Command node -ErrorAction SilentlyContinue) {
    Copy-Item (Get-Command node).Source "$dst\node\node.exe"
    Write-Host "  node.exe from PATH"
} else {
    Write-Host "  SKIPPED: no node"
}
Write-Host "[5] preferences.ini"
New-Item -ItemType Directory "$dst\config" | Out-Null
$lines = "[eMule]","Nick=eSE-User","Port=4662","UDPPort=4672","Autoconnect=0","ToolbarSetting=009901020304050607990809101112","ToolbarLabels=0","ToolbarIconSize=32","ReBarToolbar=1","[WebServer]","Enabled=1","Port=4711","Password="
$lines | Out-File "$dst\config\preferences.ini" -Encoding ASCII
Write-Host "[6] README"
"eSE Mod v6.2 - $(Get-Date -Format 'yyyy-MM-dd')" | Out-File "$dst\README.md" -Encoding UTF8
Write-Host "[7] ZIP (excluye node_modules para evitar path-too-long)"
if (Test-Path $zip) { Remove-Item $zip }
$itemsToZip = Get-ChildItem $dst | Where-Object { $_.Name -ne "eSE" }
Compress-Archive -Path $itemsToZip.FullName -DestinationPath $zip -CompressionLevel Optimal
$eseItems = Get-ChildItem "$dst\eSE" | Where-Object { $_.Name -ne "node_modules" }
Compress-Archive -Path $eseItems.FullName -DestinationPath $zip -Update
$nm = "$dst\eSE\node_modules"
if (Test-Path $nm) {
    Write-Host "  Compressing node_modules (may take a while)..."
    try {
        Compress-Archive -Path $nm -DestinationPath $zip -Update -ErrorAction Stop
        Write-Host "  node_modules added OK"
    } catch {
        Write-Host "  node_modules skipped (path too long): $_" -ForegroundColor DarkYellow
        Write-Host "  Run 'npm install' in eSE folder on target PC"
    }
}
if (Test-Path $zip) {
    $mb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
    Write-Host "DONE: $zip ($mb MB)" -ForegroundColor Green
} else {
    Write-Host "ERROR: ZIP not created" -ForegroundColor Red
}
Get-ChildItem $dst | Select-Object Name,Length
