param(
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter(Mandatory=$true)][string]$UntilUtc,
    [Parameter(Mandatory=$true)][string]$Address,
    [Parameter(Mandatory=$true)][int]$InterfaceId,
    [switch]$HighresTimer,
    [string]$ExecutableDirectoryTemplate='D:/tmp/v93-native-mfc-{0}-out'
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($OutputRoot)
if(!$root.StartsWith('C:\tmp\v93-c2-loss-night-',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $root)) {
    throw 'A fresh, owned C:\tmp\v93-c2-loss-night-* root is required.'
}
$deadline=[DateTimeOffset]::Parse($UntilUtc).ToUniversalTime()
if($deadline -le [DateTimeOffset]::UtcNow -or $deadline -gt [DateTimeOffset]::UtcNow.AddHours(8)) { throw 'Deadline must be in the next eight hours.' }
$ancestor=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($root))
while($ancestor){if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'No reparse ancestors allowed.'};$ancestor=$ancestor.Parent}
$null=New-Item -ItemType Directory -Path $root
$state=[ordered]@{
    schema='ese.v93.udp-loss-campaign/1';root=$root;started_utc=[DateTimeOffset]::UtcNow.ToString('o');deadline_utc=$deadline.ToString('o');
    phase='PREPARING';pid=$PID;address=$Address;interface=$InterfaceId;profile_highres_timer_requested=$HighresTimer.IsPresent;current=$null;results=@();error=$null;
    scope='Repeated F1 real product pairs; exact endpoint lab UDP discard only, not physical network/router testing'
}
function SaveCampaign {
    $state.updated_utc=[DateTimeOffset]::UtcNow.ToString('o')
    $temporary=Join-Path $root ('state-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    [IO.File]::WriteAllText($temporary,($state|ConvertTo-Json -Depth 10),[Text.Encoding]::UTF8)
    [IO.File]::Move($temporary,(Join-Path $root 'campaign-state.json'),$true)
}
$pinned=@{}
foreach($arch in @('x64','Win32')){$pinned[$arch]=(Get-FileHash -LiteralPath (Join-Path ($ExecutableDirectoryTemplate -f $arch) 'emule.exe')).Hash}
$state.executable_directory_template=$ExecutableDirectoryTemplate
SaveCampaign
try {
    $index=0
    while([DateTimeOffset]::UtcNow -lt $deadline) {
        $arch=if(($index%2) -eq 0){'x64'}else{'Win32'}
        $loss=@(5000,15000,30000,45000)[[int][Math]::Floor($index/2)%4]
        $executable=Join-Path ($ExecutableDirectoryTemplate -f $arch) 'emule.exe'
        if((Get-FileHash -LiteralPath $executable).Hash -ne $pinned[$arch]){throw 'Executable changed during campaign; stop before starting another pair.'}
        $caseRoot=Join-Path $root ('case-{0:D3}-{1}-{2}ms' -f $index,$arch,$loss)
        $state.current=[ordered]@{index=$index;architecture=$arch;loss_ms=$loss;root=$caseRoot;started_utc=[DateTimeOffset]::UtcNow.ToString('o');exe_sha256=$pinned[$arch]}
        $state.phase='RUNNING_PAIR';SaveCampaign
        & (Join-Path $PSScriptRoot 'run_quic_product_pair.ps1') -Executable $executable -NativeDependencyRoot "D:/tmp/ese-quic-c1-pinned-$arch-20260930" -Architecture $arch -OutputRoot $caseRoot -Address $Address -InterfaceId $InterfaceId -FileBytes 1073741824 -NetworkLossMs $loss -HighresTimer:$HighresTimer *> (Join-Path $root "case-$index-run.log")
        $evidence=Join-Path $caseRoot 'pair-evidence.json'
        $result=Get-Content -LiteralPath $evidence -Raw|ConvertFrom-Json
        if($result.verdict -ne 'PASS' -or $result.silent_udp_loss_ms -ne $loss -or !$result.silent_udp_dropped_datagrams -or $result.profile_highres_timer_requested -ne $HighresTimer.IsPresent -or
            $result.received_sha256 -ne $result.expected_sha256 -or @($result.runs|Where-Object {$_.exit_code -ne 0 -or !$_.terminal}).Count){throw 'Pair evidence does not satisfy campaign oracle.'}
        $state.results+=@{index=$index;architecture=$arch;loss_ms=$loss;root=$caseRoot;verdict='PASS';evidence_sha256=(Get-FileHash -LiteralPath $evidence).Hash;finished_utc=[DateTimeOffset]::UtcNow.ToString('o')}
        $state.phase='COMPRESSING_FINISHED_EVIDENCE';SaveCampaign
        # Reversible NTFS compression of this completed, owned case only; never delete evidence.
        $stillRunning=@(Get-CimInstance Win32_Process -Filter "Name='emule.exe'" | Where-Object {$_.ExecutablePath -in @((Join-Path $caseRoot 'upload/emule.exe'),(Join-Path $caseRoot 'download/emule.exe'))})
        if($stillRunning.Count){throw 'Owned pair still running; do not compress or start another.'}
        & compact.exe /C "/S:$caseRoot" /I /Q *> (Join-Path $root "case-$index-compression.log")
        if($LASTEXITCODE -ne 0){$state.compression_warning="case-$index compression exit $LASTEXITCODE; files retained"}
        if((Get-FileHash -LiteralPath $evidence).Hash -ne $state.results[-1].evidence_sha256){throw 'Evidence content changed during compression.'}
        $state.phase='BETWEEN_PAIRS';$state.current=$null;SaveCampaign
        & (Join-Path $PSScriptRoot 'compress_quic_loss_xpress.ps1') -CampaignRoot $root -UntilUtc $UntilUtc *> (Join-Path $root "case-$index-xpress.log")
        Write-Output "CAMPAIGN case=$index arch=$arch loss_ms=$loss PASS"
        ++$index
    }
    $state.phase='WINDOW_FINISHED';$state.finished_utc=[DateTimeOffset]::UtcNow.ToString('o');SaveCampaign
} catch {
    $state.phase='FAILED_NEEDS_REVIEW';$state.error=$_.Exception.Message;SaveCampaign
    throw
}
