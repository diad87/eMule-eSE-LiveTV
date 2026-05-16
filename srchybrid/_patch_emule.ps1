$enc = [System.Text.Encoding]::GetEncoding(1252)
$f = Join-Path $PSScriptRoot "Emule.cpp"
$content = [System.IO.File]::ReadAllText($f, $enc)

$needle = "`tm_pPartFileWriteThread = new CPartFileWriteThread();"

$replacement = @"
`tm_pPartFileWriteThread = new CPartFileWriteThread();

`t// Cache Nodes: load cache.met and start cache download thread
`tm_pCacheNodeList = new CCacheNodeList();
`tm_pCacheNodeList->LoadCacheNodes(CCacheNodeList::GetDefaultCacheMetPath());
`tm_pCacheDownloadThread = new CCacheDownloadThread();
`tm_pCacheDownloadThread->SetCacheNodeList(m_pCacheNodeList);
"@

if ($content.Contains($needle) -and -not $content.Contains("m_pCacheNodeList")) {
    $content = $content.Replace($needle, $replacement)
    [System.IO.File]::WriteAllText($f, $content, $enc)
    Write-Host "OK: Emule.cpp patched - cache node init added"
} elseif ($content.Contains("m_pCacheNodeList")) {
    Write-Host "SKIP: Already patched"
} else {
    Write-Host "ERROR: needle not found"
}
