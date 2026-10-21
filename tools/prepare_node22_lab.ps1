param([Parameter(Mandatory=$true)][string]$RunDirectory)
$ErrorActionPreference='Stop'
$run=[IO.Path]::GetFullPath($RunDirectory)
if(!$run.StartsWith('D:\tmp\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $run)) {
    throw 'A new directory under D:/tmp is required.'
}
$null=New-Item -ItemType Directory -Path $run
$base='https://nodejs.org/dist/latest-v22.x/'
$checksums=Join-Path $run 'SHASUMS256.txt'
Invoke-WebRequest -Uri ($base+'SHASUMS256.txt') -OutFile $checksums
$releaseEntries=@(Get-Content -LiteralPath $checksums | ForEach-Object {
    if($_ -match '^([a-f0-9]{64})\s+(node-v22\.[0-9]+\.[0-9]+-win-x64\.zip)$') {
        [pscustomobject]@{hash=$Matches[1];file=$Matches[2]}
    }
})
if($releaseEntries.Count -ne 1) { throw 'Expected exactly one Node 22 Windows x64 ZIP.' }
$release=$releaseEntries[0]; $archive=Join-Path $run $release.file
Invoke-WebRequest -Uri ($base+$release.file) -OutFile $archive
if((Get-FileHash -LiteralPath $archive).Hash -ne $release.hash) { throw 'Node archive checksum mismatch.' }
Expand-Archive -LiteralPath $archive -DestinationPath $run
$node=Join-Path $run ($release.file.Replace('.zip','')+'\node.exe')
$version=(& $node --version | Out-String).Trim()
if($LASTEXITCODE -or $version -notmatch '^v22\.') { throw 'Node 22 executable check failed.' }
[ordered]@{schema='ese.node22.lab/1';source=$base;archive=$release.file;sha256=$release.hash;
    checksum_verified=$true;signature_verified=$false;node=$node;version=$version;
    global_path_changed=$false;release_provenance_approved=$false} | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $run 'manifest.json') -Encoding utf8
Write-Output "Isolated Node: $version, SHA256 matches official checksum; no global installation."
