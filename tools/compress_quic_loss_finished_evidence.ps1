param([Parameter(Mandatory=$true)][string]$CampaignRoot)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($CampaignRoot).TrimEnd('\')
if(!$root.StartsWith('C:\tmp\v93-c2-loss-night-',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected campaign root'}
$state=Get-Content -LiteralPath (Join-Path $root 'campaign-state.json') -Raw|ConvertFrom-Json
if($state.schema -ne 'ese.v93.udp-loss-campaign/1' -or $state.root -ne $root){throw 'Campaign identity mismatch'}
foreach($result in $state.results){
    $case=[IO.Path]::GetFullPath($result.root)
    if(!$case.StartsWith($root+'\case-',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected case root'}
    # Results are appended only after both clients terminate. Still verify live paths.
    $running=@(Get-CimInstance Win32_Process -Filter "Name='emule.exe'"|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($case+'\',[StringComparison]::OrdinalIgnoreCase)})
    if($running.Count -or ($state.current -and $state.current.root -eq $case)){continue}
    $evidence=Join-Path $case 'pair-evidence.json'
    if((Get-FileHash -LiteralPath $evidence).Hash -ne $result.evidence_sha256){throw 'Evidence JSON hash mismatch'}
    $e=Get-Content -LiteralPath $evidence -Raw|ConvertFrom-Json
    if($e.verdict -ne 'PASS' -or $e.bytes -ne 1073741824){throw 'Not a completed F1 PASS'}
    foreach($relative in @('upload/Temp/pair-f1.bin','download/Incoming/pair-f1.bin')){
        $file=Join-Path $case $relative
        $item=Get-Item -LiteralPath $file
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unexpected reparse file'}
        $marker=$file+'.lzx-verified'
        if(Test-Path -LiteralPath $marker){continue}
        if((Get-FileHash -LiteralPath $file).Hash -ne $e.expected_sha256){throw 'Pre-compression fixture hash mismatch'}
        & compact.exe /C /F /EXE:LZX $file
        if($LASTEXITCODE -ne 0){throw 'Reversible LZX compression failed'}
        if((Get-FileHash -LiteralPath $file).Hash -ne $e.expected_sha256){throw 'Post-compression fixture hash mismatch'}
        [IO.File]::WriteAllText($marker,"SHA256=$($e.expected_sha256)`nUTC=$([DateTimeOffset]::UtcNow.ToString('o'))`n",[Text.Encoding]::UTF8)
    }
    if((Get-FileHash -LiteralPath $evidence).Hash -ne $result.evidence_sha256){throw 'Evidence JSON changed'}
    Write-Output "LZX_VERIFIED $case"
}
