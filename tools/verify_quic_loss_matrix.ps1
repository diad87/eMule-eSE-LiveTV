param(
    [Parameter(Mandatory=$true)][string[]]$EvidencePaths,
    [Parameter(Mandatory=$true)][string]$ExpectedX64ExecutableSha256,
    [Parameter(Mandatory=$true)][string]$ExpectedWin32ExecutableSha256,
    [Parameter(Mandatory=$true)][string]$OutputEvidence
)
$ErrorActionPreference='Stop'
$output=[IO.Path]::GetFullPath($OutputEvidence)
if(!$output.StartsWith('C:\tmp\v93-c2-loss-matrix-',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $output)){throw 'A fresh owned matrix evidence path is required'}
if($EvidencePaths.Count -ne 8){throw 'Exactly eight complete pair evidences required'}
$expectedFile='2C06ADE942EE3F17A048DD1064B2FAB046A4BB95386D8BB41B68DC6711AC2AF3'
$rows=@(); $seen=@{}; $timerVariant=$null
foreach($path in $EvidencePaths){
    $resolved=(Resolve-Path -LiteralPath $path).Path
    $e=Get-Content -LiteralPath $resolved -Raw|ConvertFrom-Json
    $key="$($e.architecture)/$($e.silent_udp_loss_ms)"
    if($e.architecture -notin @('x64','Win32') -or $e.silent_udp_loss_ms -notin @(5000,15000,30000,45000) -or $seen.ContainsKey($key)){throw 'Invalid or duplicate matrix cell'}
    $seen[$key]=$true
    $variant=if($e.PSObject.Properties.Name -contains 'profile_highres_timer_requested'){
        if($e.profile_highres_timer_requested){'requested_highres'}else{'requested_default'}
    }else{'not_recorded'}
    if($rows.Count -eq 0){$timerVariant=$variant}elseif($timerVariant -ne $variant){throw 'Mixed timer profile variants cannot form one acceptance matrix'}
    if($e.schema -ne 'ese.v93.quic-product-pair/1' -or $e.verdict -ne 'PASS' -or !$e.terminal -or
        $e.bytes -ne 1073741824 -or $e.interruption_requested -or $e.silent_udp_dropped_datagrams -le 0 -or
        $e.expected_sha256 -ne $expectedFile -or $e.source_sha256 -ne $expectedFile -or $e.received_sha256 -ne $expectedFile){throw "Incomplete pair oracle: $key"}
    $root=Split-Path -Parent $resolved
    $exeExpected=if($e.architecture -eq 'x64'){$ExpectedX64ExecutableSha256}else{$ExpectedWin32ExecutableSha256}
    if($exeExpected -notmatch '^[0-9A-Fa-f]{64}$' -or @($e.runs).Count -ne 2 -or @($e.prepared).Count -ne 2){throw 'Invalid binary or role evidence'}
    $sum=[UInt64]0
    foreach($role in @('upload','download')){
        $run=@($e.runs|Where-Object {$_.role -eq $role})
        $prepared=@($e.prepared|Where-Object {$_.role -eq $role})
        if($run.Count -ne 1 -or $prepared.Count -ne 1 -or !$run[0].terminal -or $run[0].exit_code -ne 0 -or !$run[0].pass_marker -or
            $prepared[0].executable_sha256 -ne $exeExpected -or $null -eq $run[0].silent_udp_drops){throw "Invalid role: $key/$role"}
        $profile=Join-Path $root $role
        if((Get-FileHash -LiteralPath (Join-Path $profile 'emule.exe')).Hash -ne $exeExpected){throw 'Saved executable changed'}
        $log=Join-Path $profile 'logs/eMule.log'
        if((Get-FileHash -LiteralPath $log).Hash -ne $run[0].log_sha256){throw 'Saved log changed'}
        $text=Get-Content -LiteralPath $log -Raw
        $matches=[regex]::Matches($text,('QUIC_PAIR NETWORK_LOSS_{0} PASS milliseconds={1} [^\r\n]*\bdrops=(\d+)\b' -f $role.ToUpperInvariant(),$e.silent_udp_loss_ms))
        if($matches.Count -ne 1 -or [UInt64]::Parse($matches[0].Groups[1].Value) -ne $run[0].silent_udp_drops -or
            !$text.Contains('QUIC_PAIR NATIVE_TCP_TIMEOUT_DELEGATION PASS stale_tcp_timer=600000') -or
            !$text.Contains("QUIC_PAIR PASS role=$role bytes=1073741824 MD4=5582066AA63BF9A0D49397E4DDA34E6A")){throw 'Missing exact loss, timer or completion marker'}
        $sum+=[UInt64]$run[0].silent_udp_drops
        $data=Join-Path $profile $(if($role -eq 'upload'){'Temp/pair-f1.bin'}else{'Incoming/pair-f1.bin'})
        if((Get-Item -LiteralPath $data).Length -ne 1073741824 -or (Get-FileHash -LiteralPath $data).Hash -ne $expectedFile){throw 'Preserved file bytes/hash mismatch'}
    }
    if($sum -le 0 -or $sum -ne $e.silent_udp_dropped_datagrams){throw 'No verified actual loss'}
    $rows+=@{architecture=$e.architecture;loss_ms=$e.silent_udp_loss_ms;timer_profile=$variant;verdict='PASS';pair_evidence=$resolved;pair_sha256=(Get-FileHash -LiteralPath $resolved).Hash;executable_sha256=$exeExpected;dropped_datagrams=$sum;preserved_files_rehashed=$true}
    Write-Output "MATRIX $key PASS; original files and executable rehashed"
}
$result=[ordered]@{schema='ese.v93.local-udp-loss-matrix/1';verdict='PASS';checked_utc=[DateTimeOffset]::UtcNow.ToString('o');scope='Eight exact-endpoint injected UDP loss F1 product pairs, same-host enrolled LAN; not physical network, NC-Q05/Q06/Q10 or C2/release acceptance';timer_profile=$timerVariant;expected_file_sha256=$expectedFile;cases=$rows}
[IO.File]::WriteAllText($output,($result|ConvertTo-Json -Depth 8),[Text.Encoding]::UTF8)
Write-Output "Matrix evidence saved: $output"
