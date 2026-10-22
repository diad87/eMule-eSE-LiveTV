param(
    [Parameter(Mandatory=$true,ParameterSetName='Campaign')][string]$CampaignRoot,
    [Parameter(Mandatory=$true,ParameterSetName='Matrix')][string]$MatrixEvidence,
    [Parameter(Mandatory=$true,ParameterSetName='Pair')][string]$PairEvidence,
    [Parameter(Mandatory=$true)][string]$UntilUtc
)
$ErrorActionPreference='Stop'
$deadline=[DateTimeOffset]::Parse($UntilUtc).ToUniversalTime()
if($PSCmdlet.ParameterSetName -eq 'Pair'){
    $pairPath=[IO.Path]::GetFullPath($PairEvidence)
    if(!$pairPath.StartsWith('C:\tmp\v93-c2-',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($pairPath) -ne 'pair-evidence.json'){throw 'Unexpected pair evidence path'}
    $state=[pscustomobject]@{current=$null;results=@([pscustomobject]@{
        root=(Split-Path -Parent $pairPath);evidence_sha256=(Get-FileHash -LiteralPath $pairPath).Hash})}
} elseif($PSCmdlet.ParameterSetName -eq 'Matrix'){
    $matrixPath=[IO.Path]::GetFullPath($MatrixEvidence)
    if(!$matrixPath.StartsWith('C:\tmp\v93-c2-loss-matrix-',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected matrix evidence path'}
    $matrix=Get-Content -LiteralPath $matrixPath -Raw|ConvertFrom-Json
    if($matrix.schema -ne 'ese.v93.local-udp-loss-matrix/1' -or $matrix.verdict -ne 'PASS' -or @($matrix.cases).Count -ne 8){throw 'Not a verified eight-case matrix'}
    $state=[pscustomobject]@{current=$null;results=@($matrix.cases|ForEach-Object {[pscustomobject]@{root=(Split-Path -Parent $_.pair_evidence);evidence_sha256=$_.pair_sha256}})}
} else {
    $root=[IO.Path]::GetFullPath($CampaignRoot).TrimEnd('\')
    if(!$root.StartsWith('C:\tmp\v93-c2-loss-night-',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected campaign root'}
    $state=Get-Content -LiteralPath (Join-Path $root 'campaign-state.json') -Raw|ConvertFrom-Json
    if($state.schema -ne 'ese.v93.udp-loss-campaign/1' -or $state.root -ne $root){throw 'Campaign identity mismatch'}
}
foreach($result in $state.results){
    $case=[IO.Path]::GetFullPath($result.root)
    if(!$case.StartsWith('C:\tmp\v93-c2-',[StringComparison]::OrdinalIgnoreCase) -or
        ($PSCmdlet.ParameterSetName -eq 'Campaign' -and !$case.StartsWith($root+'\case-',[StringComparison]::OrdinalIgnoreCase))){throw 'Unexpected case root'}
    if($state.current -and $state.current.root -eq $case){continue}
    $running=@(Get-CimInstance Win32_Process -Filter "Name='emule.exe'"|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($case+'\',[StringComparison]::OrdinalIgnoreCase)})
    if($running.Count){continue}
    $ancestor=Get-Item -LiteralPath $case
    while($ancestor){if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse ancestor refused'};$ancestor=$ancestor.Parent}
    $evidence=Join-Path $case 'pair-evidence.json'
    if((Get-FileHash -LiteralPath $evidence).Hash -ne $result.evidence_sha256){throw 'Pair evidence hash mismatch'}
    $e=Get-Content -LiteralPath $evidence -Raw|ConvertFrom-Json
    if($e.schema -ne 'ese.v93.quic-product-pair/1' -or $e.verdict -ne 'PASS' -or !$e.terminal -or $e.bytes -ne 1073741824 -or @($e.runs).Count -ne 2 -or
        $e.expected_sha256 -ne '2C06ADE942EE3F17A048DD1064B2FAB046A4BB95386D8BB41B68DC6711AC2AF3' -or
        @($e.runs|Where-Object {!$_.terminal -or $_.exit_code -ne 0}).Count){throw 'Not a completed F1 PASS'}
    foreach($relative in @('upload/Temp/pair-f1.bin','download/Incoming/pair-f1.bin')){
        if([DateTimeOffset]::UtcNow -ge $deadline){Write-Output 'WINDOW_ENDED';return}
        $file=Join-Path $case $relative
        $item=Get-Item -LiteralPath $file
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unexpected data reparse point'}
        $marker=$file+'.xpress16k-verified'
        if(Test-Path -LiteralPath $marker){continue}
        # Do not force an optional conversion under host commit pressure.
        if((Get-CimInstance Win32_OperatingSystem).FreeVirtualMemory -lt 2*1024*1024){Write-Output 'DEFERRED_COMMIT_BELOW_2GIB';return}
        if($item.Length -ne 1073741824 -or (Get-FileHash -LiteralPath $file).Hash -ne $e.expected_sha256){throw 'Original fixture content mismatch'}
        & compact.exe /C /F /EXE:XPRESS16K $file
        if($LASTEXITCODE -ne 0){throw 'XPRESS conversion failed; original evidence retained'}
        if((Get-FileHash -LiteralPath $file).Hash -ne $e.expected_sha256){throw 'Post-compression content mismatch'}
        [IO.File]::WriteAllText($marker,(@{algorithm='XPRESS16K';sha256=$e.expected_sha256;pair_sha256=$result.evidence_sha256;verified_utc=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json),[Text.Encoding]::UTF8)
        Write-Output "XPRESS_HASH_VERIFIED $file"
    }
    if((Get-FileHash -LiteralPath $evidence).Hash -ne $result.evidence_sha256){throw 'Evidence JSON changed'}
}
