param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$NativeDependencyRoot,
    [ValidateSet('x64','Win32')][string]$Architecture='x64',
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter(Mandatory=$true)][string]$Address,
    [Parameter(Mandatory=$true)][int]$InterfaceId,
    [int]$TimeoutSeconds=120,
    [ValidateSet(65537,1048576,1073741824)][int]$FileBytes=65537,
    [switch]$Interrupt,
    [ValidateSet(0,1000,5000,15000,30000,45000)][int]$NetworkLossMs=0,
    [switch]$HighresTimer,
    [switch]$DiagnosticVerbose
)
$ErrorActionPreference='Stop'
if($Interrupt -and $FileBytes -ne 1073741824){throw 'Interruption requires the 1 GiB fixture.'}
if($NetworkLossMs -and ($Interrupt -or $FileBytes -ne 1073741824)){throw 'Silent network loss requires F1 and cannot request transport Close.'}
$fixtureName=if($FileBytes -eq 65537){'pair-small.bin'}elseif($FileBytes -eq 1048576){'pair-f2.bin'}else{'pair-f1.bin'}
if($FileBytes -eq 1073741824 -and !$PSBoundParameters.ContainsKey('TimeoutSeconds')) { $TimeoutSeconds=1100 }
$oracleBytes=New-Object byte[] ([Math]::Min($FileBytes,65536))
$patternModulus=if($FileBytes -eq 65537){251}else{256}
$oracleHasher=[Security.Cryptography.SHA256]::Create()
try {
    for($offset=0L;$offset -lt $FileBytes;) {
        $count=[int][Math]::Min($oracleBytes.Length,$FileBytes-$offset)
        if($offset -eq 0 -or $patternModulus -ne 256) {
            for($i=0;$i -lt $count;$i++){ $oracleBytes[$i]=[byte](($offset+$i) % $patternModulus) }
        }
        $null=$oracleHasher.TransformBlock($oracleBytes,0,$count,$oracleBytes,0)
        $offset+=$count
    }
    $null=$oracleHasher.TransformFinalBlock([byte[]]@(),0,0)
    $expectedSha=([BitConverter]::ToString($oracleHasher.Hash)).Replace('-','')
}
finally { $oracleHasher.Dispose() }
$root=[IO.Path]::GetFullPath($OutputRoot)
if((!$root.StartsWith('D:\tmp\',[StringComparison]::OrdinalIgnoreCase) -and !$root.StartsWith('C:\tmp\',[StringComparison]::OrdinalIgnoreCase)) -or (Test-Path -LiteralPath $root)) { throw 'A fresh C:\tmp or D:\tmp pair root is required.' }
$driveInfo=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))
if($driveInfo.AvailableFreeSpace -lt (2L*$FileBytes+2GB)) { throw 'Insufficient free space for source, destination and reserve.' }
$ip=[Net.IPAddress]::Parse($Address)
$bytes=$ip.GetAddressBytes()
if($bytes.Length -ne 4 -or !($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168))) { throw 'Only an assigned RFC1918 IPv4 address is allowed.' }
if(!(Get-NetIPAddress -InterfaceIndex $InterfaceId -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $Address -and $_.AddressState -eq 'Preferred' })) { throw 'The exact LAN interface/address must be assigned and preferred.' }
$tcpPorts=@(49501,49511); $udpPorts=@(49502,49512)
if(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in $tcpPorts }) { throw 'Pair TCP ports already occupied.' }
if(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in $udpPorts }) { throw 'Pair UDP ports already occupied.' }
$null=New-Item -ItemType Directory -Path $root
$profiles=@(); $prepared=@()
for($n=0;$n -lt 2;$n++) {
    $role=if($n -eq 0){'upload'}else{'download'}
    $profile=Join-Path $root $role
    & (Join-Path $PSScriptRoot 'prepare_reach_binding_selftest.ps1') -Executable $Executable -ProfileRoot $profile -NativeDependencyRoot $NativeDependencyRoot -NativeArchitecture $Architecture -TcpPort $tcpPorts[$n] -UdpPort $udpPorts[$n]
    $preferences=Join-Path $profile 'config/preferences.ini'
    $content=[IO.File]::ReadAllText($preferences).Replace('BindAddr=127.0.0.1',"BindAddr=$Address")
    # Explicit isolated LAN test rate; do not inherit the fresh-profile 80/90 KiB/s defaults.
    $content=$content.Replace('AutoStart=0',"AutoStart=0`r`nHighresTimer=$([int]$HighresTimer.IsPresent)`r`nUploadCapacityNew=16384`r`nDownloadCapacity=16384`r`nMaxUpload=16384`r`nMaxDownload=16384")
    if($DiagnosticVerbose) { $content=$content.Replace('AutoStart=0',"AutoStart=0`r`nSaveDebugToDisk=1") }
    [IO.File]::WriteAllText($preferences,$content,[Text.Encoding]::ASCII)
    $peer=1-$n
    $pairIni="[Pair]`r`nRoot=$root`r`nAddress=$Address`r`nInterface=$InterfaceId`r`nPeerTcp=$($tcpPorts[$peer])`r`nPeerUdp=$($udpPorts[$peer])`r`nFileBytes=$FileBytes`r`n"
    $pairPath=Join-Path $profile 'config/quic-pair.ini'
    $pairIni+="Interrupt=$([int]$Interrupt.IsPresent)`r`n"
    $pairIni+="NetworkLossMs=$NetworkLossMs`r`n"
    [IO.File]::WriteAllText($pairPath,$pairIni,[Text.Encoding]::ASCII)
    $profiles+=$profile
    $prepared+=@{role=$role;profile=$profile;executable_sha256=(Get-FileHash -LiteralPath (Join-Path $profile 'emule.exe')).Hash;preferences_sha256=(Get-FileHash -LiteralPath $preferences).Hash;pair_ini_sha256=(Get-FileHash -LiteralPath $pairPath).Hash}
}
if($prepared[0].executable_sha256 -ne $prepared[1].executable_sha256) { throw 'Pair executable mismatch.' }
$processes=@()
for($n=0;$n -lt 2;$n++) {
    $role=if($n -eq 0){'upload'}else{'download'}
    $processes+=Start-Process -FilePath (Join-Path $profiles[$n] 'emule.exe') -WorkingDirectory $profiles[$n] -ArgumentList @('--portable',"--quic-pair-selftest=$role",'--ignoreinstances') -WindowStyle Hidden -PassThru
}
$deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    foreach($process in $processes) { $process.Refresh() }
    if(@($processes | Where-Object { !$_.HasExited }).Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while([DateTime]::UtcNow -lt $deadline)
$terminal=@($processes | Where-Object { !$_.HasExited }).Count -eq 0
$runs=@(); $pass=$terminal; $lossDrops=[UInt64]0
for($n=0;$n -lt 2;$n++) {
    $log=Join-Path $profiles[$n] 'logs/eMule.log'
    $text=if(Test-Path -LiteralPath $log){[IO.File]::ReadAllText($log)}else{''}
    $role=if($n -eq 0){'upload'}else{'download'}
    $exitCode=if($processes[$n].HasExited){$processes[$n].ExitCode}else{$null}
    $marker=$text.Contains("QUIC_PAIR PASS role=$role bytes=$FileBytes MD4=")
    if($Interrupt) {
        $recoveryMarker=if($n -eq 0){'QUIC_PAIR RECOVERY_UPLOAD PASS epoch=2'}else{'QUIC_PAIR RECOVERY_DOWNLOAD PASS epoch=2'}
        $marker=$marker -and $text.Contains($recoveryMarker)
    }
    $roleDrops=$null
    if($NetworkLossMs) {
        $lossMarker=if($n -eq 0){"QUIC_PAIR NETWORK_LOSS_UPLOAD PASS milliseconds=$NetworkLossMs "}else{"QUIC_PAIR NETWORK_LOSS_DOWNLOAD PASS milliseconds=$NetworkLossMs "}
        $marker=$marker -and $text.Contains($lossMarker)
        $dropMatches=[regex]::Matches($text,('QUIC_PAIR NETWORK_LOSS_{0} PASS milliseconds={1} [^\r\n]*\bdrops=(\d+)\b' -f $role.ToUpperInvariant(),$NetworkLossMs))
        $marker=$marker -and $dropMatches.Count -eq 1
        if($dropMatches.Count -eq 1){$roleDrops=[UInt64]::Parse($dropMatches[0].Groups[1].Value);$lossDrops+=$roleDrops}
    }
    $pass=$pass -and ($exitCode -eq 0) -and $marker
    $runs+=@{pid=$processes[$n].Id;role=$role;terminal=$processes[$n].HasExited;exit_code=$exitCode;pass_marker=$marker;silent_udp_drops=$roleDrops;log_sha256=if(Test-Path -LiteralPath $log){(Get-FileHash -LiteralPath $log).Hash}else{$null}}
}
if($NetworkLossMs){$pass=$pass -and $lossDrops -gt 0} # Either endpoint may discard all ACKs before its peer sends; zero total never passes.
$incoming=Join-Path $profiles[1] "Incoming/$fixtureName"
$source=Join-Path $profiles[0] "Temp/$fixtureName"
$sourceSha=if(Test-Path -LiteralPath $source){(Get-FileHash -LiteralPath $source).Hash}else{$null}
$receivedSha=if(Test-Path -LiteralPath $incoming){(Get-FileHash -LiteralPath $incoming).Hash}else{$null}
$pass=$pass -and $sourceSha -and $receivedSha -and ($sourceSha -eq $expectedSha) -and ($receivedSha -eq $expectedSha) -and ((Get-Item -LiteralPath $incoming).Length -eq $FileBytes)
$result=[ordered]@{schema='ese.v93.quic-product-pair/1';scope='Two real product processes on an explicitly enrolled exact RFC1918 same-host /32; not WAN/NAT or zero-trust discovery acceptance';terminal=$terminal;verdict=if(!$terminal){'RUNNING'}elseif($pass){'PASS'}else{'FAIL'};architecture=$Architecture;address=$Address;interface=$InterfaceId;prepared=$prepared;runs=$runs;bytes=65537;source_sha256=$sourceSha;received_sha256=$receivedSha;md4=if(Test-Path -LiteralPath (Join-Path $root 'download.complete')){([BitConverter]::ToString([IO.File]::ReadAllBytes((Join-Path $root 'download.complete')))).Replace('-','')}else{$null}}
$result.bytes=$FileBytes
$result.fixture_name=$fixtureName
$result.pattern_modulus=$patternModulus
$result.expected_sha256=$expectedSha
$result.profile_rate_limit_kib_s=16384
$result.profile_highres_timer_requested=$HighresTimer.IsPresent
$result.profile_debug_to_disk_requested=$DiagnosticVerbose.IsPresent
$result.timer_scope='Existing application preference in a fresh portable lab profile; no clock scaling or transfer/recovery deadline changes'
$result.interruption_requested=$Interrupt.IsPresent
$result.silent_udp_loss_ms=$NetworkLossMs
$result.silent_udp_dropped_datagrams=$lossDrops
$result.silent_udp_loss_scope='Pair-only exact endpoint outbound/inbound datagram discard; real timers and QUIC, no Close injection; not physical adapter/router failure'
$result.interruption_scope='Explicit close of both actual QUIC transports after at least64MiB; not OS/network packet loss or process restart'
[IO.File]::WriteAllText((Join-Path $root 'pair-evidence.json'),($result|ConvertTo-Json -Depth 6),[Text.Encoding]::UTF8)
Write-Output ($result|ConvertTo-Json -Depth 6)
if(!$terminal) { throw 'Observation deadline; processes left alive. Observe before editing inputs or starting another pair.' }
if(!$pass) { throw 'Product pair failed; evidence retained.' }
