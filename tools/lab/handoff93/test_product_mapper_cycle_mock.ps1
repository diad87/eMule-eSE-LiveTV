[CmdletBinding()] param()
$ErrorActionPreference='Stop'; Set-StrictMode -Version 2.0
function Assert-T($c,$m){if(-not $c){throw $m}}
function Import-F($ast,$name){$m=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));if($m.Count-ne 1){throw "missing $name"};$t=$m[0].Body.Extent.Text;Set-Item "Function:\script:$name" ([scriptblock]::Create($t.Substring(1,$t.Length-2)))}
$path=Join-Path $PSScriptRoot 'run_product_mapper_cycle.ps1';$tok=$null;$err=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tok,[ref]$err)
Assert-T ($err.Count-eq 0) 'parser errors'
foreach($n in @('Assert-R93NoReparseChain','Get-R93CandidateProjection','Invoke-R93PartialCycle')){Import-F $ast $n}

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

function New-Adapters([scriptblock]$sample,[bool]$wait=$true,[bool]$absent=$true,[bool]$accredited=$true){
    $state=[pscustomobject]@{configured=$false;started=$false;closed=$false;restored=$false;alive=$false}
    $a=[pscustomobject]@{
        Configure={ $state.configured=$true }; Start={ $state.started=$true;$state.alive=$true;return 77 }
        Exists={param($t) $state.alive}; IsAccredited={param($t) $accredited}; Sample=$sample; Pause={}
        Close={param($t)$state.closed=$true}; WaitForExit={param($t)if($wait){$state.alive=$false};return $wait}
        MappingsAbsent={return $absent}; RestoreIni={$state.restored=$true;return $true}
    }
    foreach($name in @('Configure','Start','Exists','IsAccredited','Sample','Pause','Close','WaitForExit','MappingsAbsent','RestoreIni')){$a.$name=$a.$name.GetNewClosure()}
    return [pscustomobject]@{adapters=$a;state=$state}
}
$ok=New-Adapters { [pscustomobject]@{tcp_candidate=$true;udp_candidate=$true;same_generation=$true;generation=9} }
$okResult=Invoke-R93PartialCycle $ok.adapters 1
Assert-T ($okResult.status-ceq 'MAPPING_OBSERVED_CLEAN_EXIT' -and -not $okResult.satisfies_h93_15 -and $ok.state.closed -and $ok.state.restored) 'honest partial success failed'

$timeout=New-Adapters { $null }
$timeoutResult=Invoke-R93PartialCycle $timeout.adapters 1
Assert-T ($timeoutResult.status-ceq 'FAIL' -and $timeoutResult.failure_class-ceq 'CANDIDATE_PAIR_NOT_OBSERVED' -and $timeout.state.closed -and $timeout.state.restored) 'zero-transition timeout unsafe'

$alive=New-Adapters { throw 'injected sample failure' } $false $false
$aliveResult=Invoke-R93PartialCycle $alive.adapters 1
$aliveJson=$aliveResult|ConvertTo-Json -Compress
Assert-T ($aliveResult.status-ceq 'BLOCKED' -and $aliveResult.intervention_required -and $alive.state.closed -and $alive.state.restored) 'live PID exception path unsafe'
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
foreach($needle in @('EnumWindows','PostMessage(h,0x0010',"-Path '/api/reach/status'",'[IO.File]::ReadAllBytes($ini)','[IO.File]::WriteAllBytes($ini, $iniBytes)','satisfies_h93_15 = $false')){Assert-T $source.Contains($needle) "missing $needle"}

[pscustomobject]@{schema='ese.lab.product-mapper-cycle-mock/v2';status='PASS';physical_execution_performed=$false;outer_finally_close=$true;mapping_deletion_capability=$false;h93_15_satisfied=$false}|ConvertTo-Json -Compress
