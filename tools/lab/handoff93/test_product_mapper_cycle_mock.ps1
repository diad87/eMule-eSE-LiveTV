[CmdletBinding()] param()
$ErrorActionPreference='Stop'; Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot '..\common.ps1')
function Assert-T($c,$m){if(-not $c){throw $m}}
function Import-F($ast,$name){$m=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));if($m.Count-ne 1){throw "missing $name"};$t=$m[0].Body.Extent.Text;Set-Item "Function:\script:$name" ([scriptblock]::Create($t.Substring(1,$t.Length-2)))}
$path=Join-Path $PSScriptRoot 'run_product_mapper_cycle.ps1';$tok=$null;$err=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tok,[ref]$err)
Assert-T ($err.Count-eq 0) 'parser errors'
foreach($n in @('Assert-R93NoReparseChain','Set-R93ProductIni',
        'Restore-R93IniBytes','Get-R93CandidateProjection',
        'Invoke-R93PartialCycle')){Import-F $ast $n}

# Intermediate reparse components are rejected, not merely the final leaf.
function Test-Path { param([string]$LiteralPath) return $true }
function Get-Item { param([string]$LiteralPath,[switch]$Force)
    [pscustomobject]@{Attributes=if($LiteralPath.EndsWith('\middle')){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory}} }
$reparseRejected=$false
try{$null=Assert-R93NoReparseChain -Root 'C:\package' -Path 'C:\package\middle\leaf' -Label test}catch{$reparseRejected=$true}
Assert-T $reparseRejected 'intermediate reparse accepted'
$casePath=Assert-R93NoReparseChain -Root 'C:\PACKAGE' -Path 'c:\package\leaf' -Label casing
Assert-T ($casePath -match '(?i)c:\\package\\leaf') 'canonical path casing rejected'
Remove-Item Function:\Test-Path;Remove-Item Function:\Get-Item

# Execute the production INI helpers against real bytes, then prove exact
# restoration rather than trusting a mock return value.
$iniPath=Join-Path ([IO.Path]::GetTempPath()) ('r93-ini-'+[Guid]::NewGuid().ToString('N')+'.ini')
$originalText="[eMule]`r`nPort=1`r`nUDPPort=2`r`n[UPnP]`r`nEnableUPnP=0`r`n[WebServer]`r`nEnabled=0`r`nPort=3`r`n"
$originalBytes=[Text.Encoding]::UTF8.GetBytes($originalText)
try{
    [IO.File]::WriteAllBytes($iniPath,$originalBytes)
    $originalSha=(Get-FileHash $iniPath -Algorithm SHA256).Hash
    Set-R93ProductIni $iniPath 41001 41002 41003
    $sections=@{};$currentSection=$null
    foreach($line in [IO.File]::ReadAllLines($iniPath)){
        if($line -match '^\[([^\]]+)\]$'){$currentSection=$Matches[1]
            if(-not $sections.ContainsKey($currentSection)){$sections[$currentSection]=@{}}
            continue}
        if($null-ne $currentSection -and $line -match '^([^=]+)=(.*)$'){
            $sections[$currentSection][$Matches[1]]=$Matches[2]}
    }
    Assert-T ($sections['UPnP']['EnableUPnP']-ceq '1') 'production helper did not enable UPnP'
    Assert-T ($sections['eMule']['Port']-ceq '41001' -and
        $sections['eMule']['UDPPort']-ceq '41002') 'production helper wrote wrong eMule ports'
    Assert-T ($sections['WebServer']['Enabled']-ceq '1' -and
        $sections['WebServer']['Port']-ceq '41003') 'production helper did not configure WebServer'
    $udpPortSections=@($sections.Keys|Where-Object{$sections[$_].ContainsKey('UDPPort')})
    $portSections=@($sections.Keys|Where-Object{$sections[$_].ContainsKey('Port')}|Sort-Object)
    Assert-T ($udpPortSections.Count-eq 1 -and $udpPortSections[0]-ceq 'eMule') 'UDPPort leaked outside eMule'
    Assert-T ($portSections.Count-eq 2 -and $portSections[0]-ceq 'eMule' -and
        $portSections[1]-ceq 'WebServer' -and
        -not $sections.ContainsKey('Connection')) 'Port appeared in an unauthorized section'
    Assert-T (Restore-R93IniBytes $iniPath $originalBytes $originalSha) 'production restore helper rejected exact roundtrip'
    $roundtrip=[IO.File]::ReadAllBytes($iniPath)
    Assert-T ([Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
            $roundtrip,$originalBytes)) 'production INI roundtrip was not byte-exact'
}finally{if([IO.File]::Exists($iniPath)){[IO.File]::Delete($iniPath)}}

function New-Adapters([scriptblock]$sample,[bool]$wait=$true,[bool]$absent=$true,[bool]$accredited=$true){
    $original=[byte[]](1,7,3,9,0,255)
    $state=[pscustomobject]@{configured=$false;started=$false;closed=$false
        restored=$false;alive=$false;upnp=$null
        bytes=[byte[]]$original.Clone();original=[byte[]]$original.Clone()
        order=[Collections.ArrayList]::new();start_saw_upnp=$false}
    $a=[pscustomobject]@{
        Configure={ $null=$state.order.Add('Configure');$state.configured=$true
            $state.upnp='1';$state.bytes=[byte[]](9,9,9) }
        Start={ $null=$state.order.Add('Start');$state.started=$true
            $state.start_saw_upnp=($state.upnp-ceq '1');$state.alive=$true;return 77 }
        Exists={param($t) $state.alive}; IsAccredited={param($t) $accredited}; Sample=$sample; Pause={}
        Close={param($t)$state.closed=$true}; WaitForExit={param($t)if($wait){$state.alive=$false};return $wait}
        MappingsAbsent={return $absent}; RestoreIni={
            $state.bytes=[byte[]]$state.original.Clone()
            $state.restored=[Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
                [byte[]]$state.bytes,[byte[]]$state.original)
            return $state.restored}
    }
    foreach($name in @('Configure','Start','Exists','IsAccredited','Sample','Pause','Close','WaitForExit','MappingsAbsent','RestoreIni')){$a.$name=$a.$name.GetNewClosure()}
    return [pscustomobject]@{adapters=$a;state=$state}
}
$ok=New-Adapters { [pscustomobject]@{tcp_candidate=$true;udp_candidate=$true;same_generation=$true;generation=9} }
$okResult=Invoke-R93PartialCycle $ok.adapters 1
Assert-T ($okResult.status-ceq 'MAPPING_OBSERVED_CLEAN_EXIT' -and -not $okResult.satisfies_h93_15 -and $ok.state.closed -and $ok.state.restored -and
    $ok.state.start_saw_upnp -and (($ok.state.order -join '>')-ceq 'Configure>Start')) 'honest partial success/config order failed'

$timeout=New-Adapters { $null }
$timeoutResult=Invoke-R93PartialCycle $timeout.adapters 1
Assert-T ($timeoutResult.status-ceq 'FAIL' -and $timeoutResult.failure_class-ceq 'CANDIDATE_PAIR_NOT_OBSERVED' -and $timeout.state.closed -and $timeout.state.restored -and
    [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
        $timeout.state.bytes,$timeout.state.original)) 'zero-transition timeout unsafe'

$alive=New-Adapters { throw 'injected sample failure' } $false $false
$aliveResult=Invoke-R93PartialCycle $alive.adapters 1
$aliveJson=$aliveResult|ConvertTo-Json -Compress
Assert-T ($aliveResult.status-ceq 'BLOCKED' -and $aliveResult.intervention_required -and $alive.state.closed -and $alive.state.restored -and
    [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
        $alive.state.bytes,$alive.state.original)) 'live PID exception path unsafe'
Assert-T ($aliveJson -notmatch '(?i)pid|process_id|[A-Z]:\\|/[A-Za-z]+/') 'safe result leaked identity/path'

$remaining=New-Adapters { [pscustomobject]@{tcp_candidate=$true;udp_candidate=$true;same_generation=$true;generation=4} } $true $false
$remainingResult=Invoke-R93PartialCycle $remaining.adapters 1
Assert-T ($remainingResult.status-ceq 'BLOCKED' -and $remainingResult.failure_class-ceq 'MAPPING_REMAINS_UNTOUCHED') 'remaining mapping not blocked'

$untrusted=New-Adapters { throw 'must not sample' } $true $true $false
$untrustedResult=Invoke-R93PartialCycle $untrusted.adapters 1
Assert-T ($untrustedResult.status-ceq 'BLOCKED' -and $untrustedResult.intervention_required -and -not $untrustedResult.graceful_exit -and -not $untrusted.state.closed -and $untrusted.state.restored) 'unaccredited live PID was closed or trusted'

function New-Plane($transport,$configuredPort,$grantedPort,$generation){[pscustomobject]@{
    gate_state='CANDIDATE';generation=$generation
    local=[pscustomobject]@{port=$configuredPort}
    mapped=[pscustomobject]@{port=$grantedPort}
    advertised=[pscustomobject]@{port=$grantedPort}
    lease=[pscustomobject]@{generation=$generation;transport=$transport
        requested_external_port=$configuredPort;granted_external_port=$grantedPort
        owned_by_us=$true;structurally_valid=$true}
    primary_evidence=[pscustomobject]@{current=$true}
}}
$payload=[pscustomobject]@{schema='ESE_REACH_STATUS_V1';topology_generation=[uint64]12;planes=[pscustomobject]@{
    ed2k_tcp_v4=(New-Plane Tcp 41001 42001 12)
    kad_udp_v4=(New-Plane Udp 41002 42002 12)}}
$projection=Get-R93CandidateProjection ([pscustomobject]@{available=$true;data=$payload}) 41001 41002
Assert-T ($projection.tcp_candidate -and $projection.udp_candidate -and $projection.same_generation) 'real projector rejected coherent sample'
$payload.planes.kad_udp_v4.lease.generation=13
$hostile=Get-R93CandidateProjection ([pscustomobject]@{available=$true;data=$payload}) 41001 41002
Assert-T (-not $hostile.same_generation) 'real projector accepted hostile lease generation'
$payload.planes.kad_udp_v4.lease.generation=12
$payload.planes.ed2k_tcp_v4.lease.requested_external_port=49999
$hostileRequested=Get-R93CandidateProjection ([pscustomobject]@{available=$true;data=$payload}) 41001 41002
Assert-T (-not $hostileRequested.same_generation) 'real projector accepted hostile requested port'
$payload.planes.ed2k_tcp_v4.lease.requested_external_port=41001
$payload.planes.ed2k_tcp_v4.lease.granted_external_port=0
$hostileGranted=Get-R93CandidateProjection ([pscustomobject]@{available=$true;data=$payload}) 41001 41002
Assert-T (-not $hostileGranted.same_generation) 'real projector accepted zero granted port'
$payload.planes.ed2k_tcp_v4.lease.granted_external_port=42001
$payload.planes.ed2k_tcp_v4.mapped.port=49999
$hostileMapped=Get-R93CandidateProjection ([pscustomobject]@{available=$true;data=$payload}) 41001 41002
Assert-T (-not $hostileMapped.same_generation) 'real projector accepted mapped/granted mismatch'

$source=Get-Content -Raw $path
Assert-T ($source -notmatch '(?i)ledger|Remove-R01Upnp|DeletePortMapping|Stop-Process|taskkill|TerminateProcess|\.Kill\(') 'forbidden mutation/termination present'
$upnpConfigIndex=$source.IndexOf('Set-R93ProductIni $ini $TcpPort $UdpPort $WebPort')
$startProcessIndex=$source.IndexOf('Start-Process -FilePath $exe')
Assert-T ($upnpConfigIndex-ge 0 -and $startProcessIndex-gt $upnpConfigIndex) 'real UPnP=1 configuration is not before Start'
foreach($needle in @('EnumWindows','PostMessage(h,0x0010',"-Path '/api/reach/status'",'[IO.File]::ReadAllBytes($ini)','Restore-R93IniBytes $ini $iniBytes $iniHash','satisfies_h93_15 = $false')){Assert-T $source.Contains($needle) "missing $needle"}

[pscustomobject]@{schema='ese.lab.product-mapper-cycle-mock/v2';status='PASS';physical_execution_performed=$false;outer_finally_close=$true;mapping_deletion_capability=$false;h93_15_satisfied=$false}|ConvertTo-Json -Compress
