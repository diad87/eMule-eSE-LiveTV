$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$module=Join-Path $PSScriptRoot 'v92_o01_vm_session.psm1'
$sourceNames=@('v92_o01_formal_controller.js','v92_o01_formal_host.js','v92_o01_formal_rpc.js','v92_o01_product_stream.js','v92_o01_t8_child.js','v92_o01_t8_daemon.js','v92_o01_bridge_protocol.js','v92_o01_t8_network_adapter.js','v92_o01_t8_fault_controller.js')
$sources=$sourceNames|ForEach-Object{[IO.File]::ReadAllText((Join-Path $PSScriptRoot "nat_gateway\$_"))}
$excluded=@('O01_CONTROL_TOKEN_SHA256','O01_DAEMON_FAIL','O01_FORMAL_HOST_FAIL','O01_MODE','O01_T8_ALLOWED_SOURCE','O01_T8_BIND_ADDRESS','O01_T8_EXTERNAL_ADDRESS','O01_T8_HTTP_PORT','O01_T8_INTERFACE_SHA256','O01_T8_SWITCH_SHA256')
$sourceCodes=@([regex]::Matches(($sources-join[char]10),'O01_[A-Z0-9_]+')|ForEach-Object{$_.Value}|Where-Object{$_-notin$excluded}|Sort-Object -Unique)
$moduleText=[IO.File]::ReadAllText($module)
$timeoutContracts=@([regex]::Matches($moduleText,'\$waitMs=if\(\$handled-eq0\)\{(?<initial>[0-9]+)\}else\{(?<subsequent>[0-9]+)\}'))
if($timeoutContracts.Count-ne1-or[int]$timeoutContracts[0].Groups['initial'].Value-ne300000-or[int]$timeoutContracts[0].Groups['subsequent'].Value-ne140000){throw 'RPC host request timeout contract mismatch'}
$legacyHostCodes=@('O01_CONTROLLER_CLOCK_GAP')
$pumpCodes=@('O01_RPC_HOST_FAILED','O01_RPC_HOST_OUTPUT_CLOSED','O01_RPC_HOST_REQUEST_INVALID','O01_RPC_HOST_REQUEST_TIMEOUT','O01_RPC_HOST_WRITE_FAILED')
$evidenceCodes=@('O01_RPC_FAILURE_CHECKPOINT_INVALID','O01_RPC_FAILURE_EVIDENCE_EXISTS','O01_RPC_FAILURE_EVIDENCE_INVALID','O01_RPC_FAILURE_EVIDENCE_WRITE')
$localCodes=@('O01_PRODUCT_EXITED','O01_PRODUCT_LINE_TIMEOUT','O01_PRODUCT_READ_REMOTE','O01_PRODUCT_READ_REMOTE_INVOKE','O01_PRODUCT_READ_REMOTE_FAILED','O01_PRODUCT_READ_REMOTE_STOPPED','O01_PRODUCT_READ_REMOTE_DISCONNECTED','O01_PRODUCT_READ_REMOTE_RECEIVE','O01_PRODUCT_READ_REMOTE_TIMEOUT','O01_PRODUCT_READ_SHAPE','O01_PRODUCT_CYCLE_CANDIDATE_PAIR_NOT_OBSERVED','O01_PRODUCT_CYCLE_EXECUTION_FAILED','O01_PRODUCT_CYCLE_IDENTITY_NOT_ACCREDITED','O01_PRODUCT_CYCLE_INI_RESTORE_FAILED','O01_PRODUCT_CYCLE_PREEXISTING_PROCESS_CHANGED','O01_PRODUCT_CYCLE_PROCESS_STILL_ALIVE','O01_PRODUCT_CYCLE_RECORD_INVALID')
$closedControllerCodes=@('O01_CONTROLLER_CHILD_BEGIN_TIMEOUT','O01_CONTROLLER_CHILD_OBSERVE_TIMEOUT','O01_CONTROLLER_CLOCK_CHECKPOINT_GAP','O01_CONTROLLER_CLOCK_GAP','O01_CONTROLLER_CLOCK_INTERTICK_GAP','O01_CONTROLLER_CLOCK_INVALID','O01_CONTROLLER_CLOCK_NONMONOTONIC','O01_CONTROLLER_GATEWAY_PRODUCT')
$declarationPattern='\$script:(?:O01Rpc(?:Host|Pump|Dependency|ProductStream|Evidence|EmittedHost|Closed)|O01LocalProduct)FailureCodes=@\((?<body>[^)]*)\)'
$declarations=@([regex]::Matches($moduleText,$declarationPattern))
$declared=@($declarations|ForEach-Object{[regex]::Matches($_.Groups['body'].Value,"'(?<code>O01_[A-Z0-9_]+)'")}|ForEach-Object{$_.Groups['code'].Value}|Sort-Object -Unique)
$expectedDeclared=@($sourceCodes+$legacyHostCodes+$pumpCodes+$evidenceCodes+$localCodes|Sort-Object -Unique)
if($declarations.Count-ne9-or($expectedDeclared-join',')-cne($declared-join',')-or@($closedControllerCodes|Where-Object{$_-notin$declared}).Count-ne0){throw 'RPC host closed-code ratchet mismatch'}
if($moduleText.Contains('O01_FAULT_REPLAY_EMPTY')-or$moduleText.Contains('Get-FileHash -LiteralPath $latestPath')-or$moduleText.Contains('Get-FileHash -LiteralPath $path -Algorithm SHA256')){throw 'RPC failure stale or path-reopen ratchet'}
Import-Module $module -Force

$node=(Get-Command node -ErrorAction Stop).Source
$peer=Join-Path $PSScriptRoot 'nat_gateway\test\v92_o01_formal_rpc_peer_mock.js'
if($peer.Contains('"')){throw 'peer path invalid'}
function Start-Peer([string]$failure){
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$node
    $info.Arguments='"'+$peer+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    $oldPeer=[Environment]::GetEnvironmentVariable('O01_RPC_PEER_MOCK','Process')
    $oldFailure=[Environment]::GetEnvironmentVariable('O01_RPC_PEER_FAILURE','Process')
    try{[Environment]::SetEnvironmentVariable('O01_RPC_PEER_MOCK','1','Process');[Environment]::SetEnvironmentVariable('O01_RPC_PEER_FAILURE',$failure,'Process');$started=$process.Start()}
    finally{[Environment]::SetEnvironmentVariable('O01_RPC_PEER_MOCK',$oldPeer,'Process');[Environment]::SetEnvironmentVariable('O01_RPC_PEER_FAILURE',$oldFailure,'Process')}
    if(-not$started){throw 'peer start failed'}
    return $process
}
function Start-PowerShellPeer([string]$body){
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $info.Arguments='-NoProfile -ExecutionPolicy Bypass -EncodedCommand '+$encoded
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    if(-not$process.Start()){throw 'PowerShell peer start failed'}
    return $process
}
function Stop-TestProcess([Diagnostics.Process]$process){
    if($null-eq$process){return}
    try{if(-not$process.HasExited){$process.Kill();$process.WaitForExit()}}catch{}
    $process.Dispose()
}
function New-TestEvidence(){
    $root=Join-Path ([IO.Path]::GetTempPath()) ('o01-rpc-formal-'+[Guid]::NewGuid().ToString('N'))
    $controller=Join-Path $root 'controller'
    $null=New-Item -ItemType Directory -Path $controller
    return [pscustomobject]@{root=$root;controller=$controller}
}
function Remove-TestEvidence($fixture){
    if($null-ne$fixture-and(Test-Path -LiteralPath $fixture.root)){Remove-Item -LiteralPath $fixture.root -Recurse -Force}
}
function Read-RpcFailure($fixture){
    $path=Join-Path $fixture.controller 'rpc-failure.json'
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)-or(Test-Path -LiteralPath (Join-Path $fixture.controller 'rpc-failure.json.tmp'))){throw 'RPC failure publication invalid'}
    return [IO.File]::ReadAllText($path,[Text.Encoding]::UTF8)|ConvertFrom-Json -ErrorAction Stop
}
function Get-TestBytesSha256([byte[]]$bytes){$sha=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant())}finally{$sha.Dispose()}}
function Get-TestTextSha256([string]$value){Get-TestBytesSha256 ([Text.Encoding]::UTF8.GetBytes($value))}
function ConvertTo-TestCanonicalJson($value){
    if($null-eq$value){return 'null'}
    if($value-is[Collections.IDictionary]){$parts=@();foreach($key in @($value.Keys|ForEach-Object{[string]$_}|Sort-Object)){$parts+=(ConvertTo-Json -InputObject $key -Compress)+':'+(ConvertTo-TestCanonicalJson ($value[$key]))};return '{'+($parts-join',')+'}'}
    if($value.GetType().FullName-ceq'System.Management.Automation.PSCustomObject'){$parts=@();foreach($property in @($value.PSObject.Properties|Sort-Object Name)){$parts+=(ConvertTo-Json -InputObject ([string]$property.Name) -Compress)+':'+(ConvertTo-TestCanonicalJson $property.Value)};return '{'+($parts-join',')+'}'}
    if($value-is[Array]-or$value-is[Collections.IList]){$parts=@();foreach($entry in $value){$parts+=ConvertTo-TestCanonicalJson $entry};return '['+($parts-join',')+']'}
    return ConvertTo-Json -InputObject $value -Compress
}
function ConvertTo-TestPrettyJson($value,[int]$depth=0){
    if($null-eq$value){return 'null'}
    $indent=' '*($depth*2);$childIndent=' '*(($depth+1)*2)
    if($value-is[Collections.IDictionary]){$parts=@();foreach($key in $value.Keys){$parts+=$childIndent+(ConvertTo-Json -InputObject ([string]$key) -Compress)+': '+(ConvertTo-TestPrettyJson ($value[$key]) ($depth+1))};if($parts.Count-eq0){return '{}'};return "{`n"+($parts-join",`n")+"`n$indent}"}
    if($value.GetType().FullName-ceq'System.Management.Automation.PSCustomObject'){$parts=@();foreach($property in $value.PSObject.Properties){$parts+=$childIndent+(ConvertTo-Json -InputObject ([string]$property.Name) -Compress)+': '+(ConvertTo-TestPrettyJson $property.Value ($depth+1))};if($parts.Count-eq0){return '{}'};return "{`n"+($parts-join",`n")+"`n$indent}"}
    if($value-is[Array]-or$value-is[Collections.IList]){$parts=@();foreach($entry in $value){$parts+=$childIndent+(ConvertTo-TestPrettyJson $entry ($depth+1))};if($parts.Count-eq0){return '[]'};return "[`n"+($parts-join",`n")+"`n$indent]"}
    return ConvertTo-Json -InputObject $value -Compress
}
function New-TestCheckpoint([int]$ordinal,[string]$previous){
    $product=[ordered]@{schema='test-product';sequence=$ordinal;available=$true}
    $gateway=[ordered]@{schema='test-gateway';sequence=$ordinal;closed=$true}
    $body=[ordered]@{schema='ese.v92.o01-checkpoint/v2';ordinal=$ordinal;elapsed_ms=$ordinal*300000;fault_ordinal=$ordinal;executed=[ordered]@{};slots=[object[]]@([ordered]@{ordinal=$ordinal});product=$product;gateway=$gateway;product_sha256=Get-TestTextSha256 ("ese.v92.o01-product-sample/v1"+[char]0+(ConvertTo-TestCanonicalJson $product));gateway_sha256=Get-TestTextSha256 ("ese.v92.o01-gateway-observation/v1"+[char]0+(ConvertTo-TestCanonicalJson $gateway));previous_sha256=$previous}
    $record=[ordered]@{};foreach($key in $body.Keys){$record[$key]=$body[$key]}
    $record.record_sha256=Get-TestTextSha256 ("ese.v92.o01-checkpoint/v2"+[char]0+(ConvertTo-TestCanonicalJson $body))
    return $record
}
function Write-TestCheckpointChain([string]$controller,[int]$count){
    $previous='0'*64
    for($ordinal=1;$ordinal-le$count;$ordinal++){
        $record=New-TestCheckpoint $ordinal $previous
        $path=Join-Path $controller ('checkpoint-{0:D2}.json'-f$ordinal)
        [IO.File]::WriteAllText($path,((ConvertTo-TestPrettyJson $record)+[char]10),[Text.UTF8Encoding]::new($false))
        $previous=[string]$record.record_sha256
    }
}
$prettyInput=Join-Path ([IO.Path]::GetTempPath()) ('o01-rpc-pretty-in-'+[Guid]::NewGuid().ToString('N')+'.json')
$prettyOutput=Join-Path ([IO.Path]::GetTempPath()) ('o01-rpc-pretty-out-'+[Guid]::NewGuid().ToString('N')+'.json')
try{
    $prettyRecord=New-TestCheckpoint 1 ('0'*64)
    [IO.File]::WriteAllText($prettyInput,($prettyRecord|ConvertTo-Json -Compress -Depth 32),[Text.UTF8Encoding]::new($false))
    &$node -e "const fs=require('node:fs');const value=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));fs.writeFileSync(process.argv[2],JSON.stringify(value,null,2)+'\n','utf8')" $prettyInput $prettyOutput
    if($LASTEXITCODE-ne0-or[IO.File]::ReadAllText($prettyOutput,[Text.Encoding]::UTF8)-cne((ConvertTo-TestPrettyJson $prettyRecord)+[char]10)){throw 'checkpoint pretty JSON does not match productive Node writer'}
}finally{foreach($path in @($prettyInput,$prettyOutput)){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}}}

$process=Start-Peer $null
try{$count=Invoke-O01FormalRpcPump -Process $process -ReadProduct {param($sequence)"product-$sequence"};if($count-ne3){throw 'RPC count invalid'}}finally{$process.Dispose()}
foreach($case in @(@('1','O01_CHILD_SOCKET_ADDRESS_NOT_AVAILABLE'),@('2','O01_RPC_HOST_FAILED'),@('3','O01_CONTROLLER_MAPPER_PROTOCOL'))){
    $failed=Start-Peer $case[0]
    try{try{$null=Invoke-O01FormalRpcPump -Process $failed -ReadProduct {throw 'unreachable'};throw 'failed peer accepted'}catch{if($_.Exception.Message-cne$case[1]-or[int]$_.Exception.Data['stderr_tail_chars']-gt16384){throw}}}finally{$failed.Dispose()}
}
foreach($case in @(@('O01_PRODUCT_EXITED','O01_PRODUCT_EXITED'),@('O01_PRODUCT_LINE_TIMEOUT','O01_PRODUCT_LINE_TIMEOUT'),@('PRODUCT_PASSWORD_SECRET','O01_PRODUCT_READ_REMOTE'))){
    $failed=Start-Peer '4'
    try{$localCount=[pscustomobject]@{value=0};try{$null=Invoke-O01FormalRpcPump -Process $failed -ReadProduct {$localCount.value++;if($localCount.value-eq1-or$case[0]-ceq'PRODUCT_PASSWORD_SECRET'){throw $case[0]};throw 'O01_PRODUCT_LINE_TIMEOUT'}.GetNewClosure();throw 'local failure accepted'}catch{if($_.Exception.Message-cne$case[1]){throw}}}finally{$failed.Dispose()}
}
$pumpObservation=[pscustomobject][ordered]@{samples_total=180;samples_available=180;tcp_candidate_samples=0;udp_candidate_samples=0;same_generation_samples=0;last_tcp_gate_state='BLOCKED';last_udp_gate_state='BLOCKED';last_tcp_reason_code=10;last_udp_reason_code=10}
foreach($localCycleCode in @('O01_PRODUCT_CYCLE_CANDIDATE_PAIR_NOT_OBSERVED','O01_PRODUCT_CYCLE_EXECUTION_FAILED','O01_PRODUCT_CYCLE_IDENTITY_NOT_ACCREDITED','O01_PRODUCT_CYCLE_INI_RESTORE_FAILED','O01_PRODUCT_CYCLE_PREEXISTING_PROCESS_CHANGED','O01_PRODUCT_CYCLE_PROCESS_STILL_ALIVE','O01_PRODUCT_CYCLE_RECORD_INVALID')){
    $zero=Start-Peer '5'
    try{try{$null=Invoke-O01FormalRpcPump -Process $zero -ReadProduct {if($localCycleCode-ceq'O01_PRODUCT_CYCLE_RECORD_INVALID'){throw $localCycleCode};$cycleError=[InvalidOperationException]::new($localCycleCode);$cycleError.Data['product_cycle_observation']=$pumpObservation;throw $cycleError}.GetNewClosure();throw 'zero-exit local cycle failure accepted'}catch{if($_.Exception.Message-cne$localCycleCode-or($localCycleCode-cne'O01_PRODUCT_CYCLE_RECORD_INVALID'-and$_.Exception.Data['product_cycle_observation'].last_tcp_reason_code-ne10)){throw}}}finally{$zero.Dispose()}
}
$callbackPeer=Start-Peer $null
try{$callbackSequences=[Collections.Generic.List[int]]::new();$callbackCount=Invoke-O01FormalRpcPump -Process $callbackPeer -ReadProduct {param($sequence)"product-$sequence"} -AfterProductRead {param($sequence,$line)if($line-cne"product-$sequence"){throw 'callback line'};$callbackSequences.Add([int]$sequence)}.GetNewClosure();if($callbackCount-ne3-or($callbackSequences-join',')-cne'1,2,3'){throw 'RPC callback invalid'}}finally{$callbackPeer.Dispose()}
$callbackFailed=Start-Peer '5'
try{try{$null=Invoke-O01FormalRpcPump -Process $callbackFailed -ReadProduct {param($sequence)"product-$sequence"} -AfterProductRead {throw 'release injected failure'};throw 'callback failure accepted'}catch{if($_.Exception.Message-cne'O01_PRODUCT_READ_REMOTE'){throw}}}finally{$callbackFailed.Dispose()}

$hostFixture=New-TestEvidence
try{
    $evidencePeer=Start-Peer '3'
    try{try{$null=Invoke-O01FormalRpcPump -Process $evidencePeer -ReadProduct {throw 'unreachable'} -FailureEvidenceRoot $hostFixture.controller;throw 'evidence peer accepted'}catch{$evidenceError=$_.Exception;if($evidenceError.Message-cne'O01_CONTROLLER_MAPPER_PROTOCOL'){throw}}}finally{$evidencePeer.Dispose()}
    $rpcPath=Join-Path $hostFixture.controller 'rpc-failure.json';$rpcRaw=[IO.File]::ReadAllText($rpcPath,[Text.Encoding]::UTF8);$rpc=$rpcRaw|ConvertFrom-Json -ErrorAction Stop
    $rpcKeys=@($rpc.PSObject.Properties.Name|Sort-Object);$expectedRpcKeys=@('failure_code','host_exit_code','last_checkpoint_file_sha256','last_checkpoint_ordinal','last_checkpoint_record_sha256','maximum_requests','next_sequence','origin','release_gate','requests_handled','schema','stage','stderr_tail_chars','stderr_tail_sha256','stderr_tail_utf8_bytes','verdict')
    if(($rpcKeys-join',')-cne($expectedRpcKeys-join',')-or[string]$rpc.schema-cne'ese.v92.o01-rpc-failure/v1'-or[string]$rpc.verdict-cne'FAIL'-or[bool]$rpc.release_gate-ne$false-or[string]$rpc.origin-cne'FORMAL_HOST'-or[string]$rpc.stage-cne'HOST_EXIT'-or[string]$rpc.failure_code-cne'O01_CONTROLLER_MAPPER_PROTOCOL'-or[int]$rpc.requests_handled-ne0-or[int]$rpc.next_sequence-ne1-or[int]$rpc.maximum_requests-ne482-or[int]$rpc.host_exit_code-ne1-or[int]$rpc.last_checkpoint_ordinal-ne0-or$null-ne$rpc.last_checkpoint_record_sha256-or$null-ne$rpc.last_checkpoint_file_sha256-or[string]$rpc.stderr_tail_sha256-cnotmatch'^[a-f0-9]{64}$'-or[int]$rpc.stderr_tail_utf8_bytes-gt49152){throw 'RPC failure schema invalid'}
    $rpcHash=(Get-FileHash $rpcPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if([string]$evidenceError.Data['rpc_failure_sha256']-cne$rpcHash-or[string]$evidenceError.Data['stderr_tail_sha256']-cne[string]$rpc.stderr_tail_sha256){throw 'RPC failure binding invalid'}
    $v3=ConvertTo-O01FailureProjectionV3 $evidenceError -EvidenceRoot $hostFixture.root
    if([string]$v3.schema-cne'ese.v92.o01-formal-failure/v3'-or[string]$v3.primary_failure-cne'O01_CONTROLLER_MAPPER_PROTOCOL'-or[string]$v3.rpc_failure_sha256-cne$rpcHash-or(@($v3.Keys|Sort-Object)-join',')-cne'error_types,failure_codes,primary_failure,product_cycle_observation,records_examined,release_gate,rollback_failures,rpc_failure_sha256,schema,verdict'){throw 'RPC failure v3 projection invalid'}

    $aggregateValid=[AggregateException]::new('O01_FORMAL_RUN_AND_ROLLBACK_FAILED',@($evidenceError,[InvalidOperationException]::new('O01_SESSION_ROLLBACK_BASELINE')))
    $aggregateV3=ConvertTo-O01FailureProjectionV3 $aggregateValid -EvidenceRoot $hostFixture.root
    if([string]$aggregateV3.primary_failure-cne'O01_CONTROLLER_MAPPER_PROTOCOL'-or[string]$aggregateV3.rpc_failure_sha256-cne$rpcHash){throw 'RPC aggregate primary binding rejected'}
    $aggregateMismatch=[AggregateException]::new('O01_FORMAL_RUN_AND_ROLLBACK_FAILED',@([InvalidOperationException]::new('O01_PRODUCT_EXITED'),$evidenceError))
    try{ConvertTo-O01FailureProjectionV3 $aggregateMismatch -EvidenceRoot $hostFixture.root|Out-Null;throw 'RPC aggregate mismatched primary accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}

    [IO.File]::WriteAllText($rpcPath,$rpcRaw.Replace('"verdict":"FAIL"','"verdict":"FAIL "'),[Text.UTF8Encoding]::new($false))
    try{ConvertTo-O01FailureProjectionV3 $evidenceError -EvidenceRoot $hostFixture.root|Out-Null;throw 'mutated RPC evidence accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
    [IO.File]::WriteAllText($rpcPath,$rpcRaw,[Text.UTF8Encoding]::new($false))
    $extraRaw=$rpcRaw.TrimEnd([char]13,[char]10);$extraRaw=$extraRaw.Substring(0,$extraRaw.Length-1)+',"extra":1}'+[char]10
    [IO.File]::WriteAllText($rpcPath,$extraRaw,[Text.UTF8Encoding]::new($false));$evidenceError.Data['rpc_failure_sha256']=Get-TestTextSha256 $extraRaw
    try{ConvertTo-O01FailureProjectionV3 $evidenceError -EvidenceRoot $hostFixture.root|Out-Null;throw 'extra-key RPC evidence accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
    [IO.File]::WriteAllText($rpcPath,$rpcRaw,[Text.UTF8Encoding]::new($false));$evidenceError.Data['rpc_failure_sha256']=$rpcHash

    $noBinding=[InvalidOperationException]::new('O01_CONTROLLER_MAPPER_PROTOCOL')
    try{ConvertTo-O01FailureProjectionV3 $noBinding -EvidenceRoot $hostFixture.root|Out-Null;throw 'unbound sidecar accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
}finally{Remove-TestEvidence $hostFixture}

$hostileFixture=New-TestEvidence
try{
    $hostilePeer=Start-Peer '2'
    try{try{$null=Invoke-O01FormalRpcPump -Process $hostilePeer -ReadProduct {throw 'unreachable'} -FailureEvidenceRoot $hostileFixture.controller;throw 'hostile evidence peer accepted'}catch{$hostileError=$_.Exception;if($hostileError.Message-cne'O01_RPC_HOST_FAILED'){throw}}}finally{$hostilePeer.Dispose()}
    $hostileRaw=[IO.File]::ReadAllText((Join-Path $hostileFixture.controller 'rpc-failure.json'),[Text.Encoding]::UTF8);$hostileRpc=$hostileRaw|ConvertFrom-Json -ErrorAction Stop
    if([string]$hostileRpc.failure_code-cne'O01_RPC_HOST_FAILED'-or$hostileRaw.Contains('PRODUCT_PASSWORD_SECRET')-or$hostileRaw.Contains('C:\private')){throw 'hostile stderr escaped RPC evidence'}
    $null=ConvertTo-O01FailureProjectionV3 $hostileError -EvidenceRoot $hostileFixture.root
}finally{Remove-TestEvidence $hostileFixture}

foreach($localCase in @(@('5',0,1),@('4',1,2))){
    $localFixture=New-TestEvidence
    try{
        $localPeer=Start-Peer $localCase[0]
        try{try{$null=Invoke-O01FormalRpcPump -Process $localPeer -ReadProduct {throw 'O01_PRODUCT_EXITED'} -FailureEvidenceRoot $localFixture.controller;throw 'local evidence peer accepted'}catch{$localError=$_.Exception;if($localError.Message-cne'O01_PRODUCT_EXITED'){throw}}}finally{$localPeer.Dispose()}
        $localRpc=Read-RpcFailure $localFixture
        if([string]$localRpc.origin-cne'LOCAL_PRODUCT'-or[string]$localRpc.stage-cne'PRODUCT_READ'-or[string]$localRpc.failure_code-cne'O01_PRODUCT_EXITED'-or[int]$localRpc.requests_handled-ne[int]$localCase[2]-or[int]$localRpc.next_sequence-ne([int]$localCase[2]+1)-or$null-ne$localRpc.host_exit_code-or[int]$localRpc.last_checkpoint_ordinal-ne0){throw 'local RPC failure evidence invalid'}
        $null=ConvertTo-O01FailureProjectionV3 $localError -EvidenceRoot $localFixture.root
        if([string]$localCase[0]-ceq'5'){
            $localPath=Join-Path $localFixture.controller 'rpc-failure.json';$localOriginal=[IO.File]::ReadAllText($localPath,[Text.Encoding]::UTF8);$localOriginalHash=[string]$localError.Data['rpc_failure_sha256']
            foreach($mutation in @('HOST_EXIT','ZERO_BYTES','EMPTY_SHA','NONEMPTY_EMPTY_SHA')){
                $tampered=$localOriginal|ConvertFrom-Json
                if($mutation-ceq'HOST_EXIT'){$tampered.host_exit_code=1}elseif($mutation-ceq'ZERO_BYTES'){$tampered.stderr_tail_chars=0;$tampered.stderr_tail_utf8_bytes=1;$tampered.stderr_tail_sha256=Get-TestTextSha256 ''}elseif($mutation-ceq'EMPTY_SHA'){$tampered.stderr_tail_chars=0;$tampered.stderr_tail_utf8_bytes=0;$tampered.stderr_tail_sha256='a'*64}else{$tampered.stderr_tail_chars=1;$tampered.stderr_tail_utf8_bytes=1;$tampered.stderr_tail_sha256=Get-TestTextSha256 ''}
                $tamperedRaw=($tampered|ConvertTo-Json -Compress)+[char]10;[IO.File]::WriteAllText($localPath,$tamperedRaw,[Text.UTF8Encoding]::new($false));$localError.Data['rpc_failure_sha256']=Get-TestTextSha256 $tamperedRaw
                try{$null=ConvertTo-O01FailureProjectionV3 $localError -EvidenceRoot $localFixture.root;throw "hostile local sidecar accepted: $mutation"}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
            }
            [IO.File]::WriteAllText($localPath,$localOriginal,[Text.UTF8Encoding]::new($false));$localError.Data['rpc_failure_sha256']=$localOriginalHash
        }
    }finally{Remove-TestEvidence $localFixture}
}
$zeroLocalFixture=New-TestEvidence
try{
    $moduleInstance=Get-Module|Where-Object{[IO.Path]::GetFullPath([string]$_.Path)-ceq[IO.Path]::GetFullPath($module)}|Select-Object -First 1
    try{&$moduleInstance {param($root)Write-O01RpcFailureEvidence -EvidenceRoot $root -Origin 'LOCAL_PRODUCT' -Stage 'PRODUCT_READ' -FailureCode 'O01_PRODUCT_EXITED' -RequestsHandled 0 -NextSequence 1 -MaximumRequests 482 -HostExitCode $null -StderrTail ''} $zeroLocalFixture.controller|Out-Null;throw 'zero-handled local writer accepted'}catch{if($_.Exception.Message-cne'O01_RPC_FAILURE_EVIDENCE_INVALID'){throw}}
    try{&$moduleInstance {param($root)Get-O01RpcCheckpointBinding -EvidenceRoot $root -RequestsHandled 0 -Origin 'LOCAL_PRODUCT'} $zeroLocalFixture.controller|Out-Null;throw 'zero-handled local binding accepted'}catch{if($_.Exception.Message-cne'O01_RPC_FAILURE_CHECKPOINT_INVALID'){throw}}
    if(Test-Path -LiteralPath (Join-Path $zeroLocalFixture.controller 'rpc-failure.json')){throw 'zero-handled local sidecar published'}
}finally{Remove-TestEvidence $zeroLocalFixture}
$unknownFixture=New-TestEvidence
try{
    $unknownPeer=Start-Peer '5'
    try{try{$null=Invoke-O01FormalRpcPump -Process $unknownPeer -ReadProduct {throw 'PRODUCT_PASSWORD_SECRET'} -FailureEvidenceRoot $unknownFixture.controller;throw 'unknown local accepted'}catch{$unknownError=$_.Exception;if($unknownError.Message-cne'O01_PRODUCT_READ_REMOTE'){throw}}}finally{$unknownPeer.Dispose()}
    $unknownRaw=[IO.File]::ReadAllText((Join-Path $unknownFixture.controller 'rpc-failure.json'),[Text.Encoding]::UTF8)
    if($unknownRaw-match'PRODUCT_PASSWORD_SECRET'-or[string](($unknownRaw|ConvertFrom-Json).failure_code)-cne'O01_PRODUCT_READ_REMOTE'){throw 'unknown local was not closed privately'}
    $null=ConvertTo-O01FailureProjectionV3 $unknownError -EvidenceRoot $unknownFixture.root
}finally{Remove-TestEvidence $unknownFixture}

$countPeerPath=Join-Path ([IO.Path]::GetTempPath()) ('o01-rpc-count-'+[Guid]::NewGuid().ToString('N')+'.js')
$countPeerSource=@'
'use strict';
const readline=require('node:readline');
const limit=Number(process.argv[2]);
let expected=1;
const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
function request(){process.stdout.write(JSON.stringify({schema:'ese.v92.o01-formal-rpc-request/v1',sequence:expected,operation:'product_next'})+'\n');}
lines.on('line',(line)=>{const value=JSON.parse(line);if(!value||value.ok!==true||value.sequence!==expected)process.exit(2);if(expected===limit){process.stderr.write('V92_O01_FORMAL_HOST_FAIL O01_CONTROLLER_MAPPER_PROTOCOL\n');lines.close();process.exit(1);}expected++;request();});
request();
'@
[IO.File]::WriteAllText($countPeerPath,$countPeerSource,[Text.UTF8Encoding]::new($false))
function Start-CountPeer([int]$count){
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$node;$info.Arguments='"'+$countPeerPath+'" '+$count
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info;if(-not$process.Start()){throw 'count peer start failed'};return $process
}
try{
    foreach($boundary in @(@(6,1,$true),@(5,1,$false),@(31,6,$true),@(30,6,$false))){
        $fixture=New-TestEvidence
        try{
            Write-TestCheckpointChain $fixture.controller $boundary[1]
            $countPeer=Start-CountPeer $boundary[0]
            try{
                try{$null=Invoke-O01FormalRpcPump -Process $countPeer -ReadProduct {param($sequence)"product-$sequence"} -FailureEvidenceRoot $fixture.controller;throw 'checkpoint peer accepted'}
                catch{$checkpointError=$_.Exception}
            }finally{$countPeer.Dispose()}
            if([bool]$boundary[2]){
                if($checkpointError.Message-cne'O01_CONTROLLER_MAPPER_PROTOCOL'){throw 'valid checkpoint rejected'}
                $checkpointRpc=Read-RpcFailure $fixture
                $latestPath=Join-Path $fixture.controller ('checkpoint-{0:D2}.json'-f[int]$boundary[1]);$latestValue=[IO.File]::ReadAllText($latestPath)|ConvertFrom-Json
                if([int]$checkpointRpc.last_checkpoint_ordinal-ne[int]$boundary[1]-or[string]$checkpointRpc.last_checkpoint_record_sha256-cne[string]$latestValue.record_sha256-or[string]$checkpointRpc.last_checkpoint_file_sha256-cne(Get-FileHash $latestPath -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'checkpoint binding mismatch'}
                $null=ConvertTo-O01FailureProjectionV3 $checkpointError -EvidenceRoot $fixture.root
            }else{
                $inner=@($checkpointError.InnerExceptions|ForEach-Object{$_.Message})
                if($checkpointError.Message-cne'O01_RPC_FAILURE_EVIDENCE_WRITE'-or'O01_RPC_FAILURE_CHECKPOINT_INVALID'-cnotin$inner-or(Test-Path -LiteralPath (Join-Path $fixture.controller 'rpc-failure.json'))){throw 'future checkpoint accepted'}
                $projection=ConvertTo-O01FailureProjectionV3 $checkpointError -EvidenceRoot $fixture.root
                if([string]$projection.primary_failure-cne'O01_RPC_FAILURE_EVIDENCE_WRITE'){throw 'checkpoint publication failure not closed'}
            }
        }finally{Remove-TestEvidence $fixture}
    }

    foreach($localBoundary in @(@(6,$false),@(7,$true))){
        $localFixture=New-TestEvidence
        try{
            Write-TestCheckpointChain $localFixture.controller 1;$localPeer=Start-CountPeer $localBoundary[0]
            try{try{$null=Invoke-O01FormalRpcPump -Process $localPeer -ReadProduct {param($sequence)if($sequence-eq[int]$localBoundary[0]){throw 'O01_PRODUCT_EXITED'};"product-$sequence"}.GetNewClosure() -FailureEvidenceRoot $localFixture.controller;throw 'local checkpoint boundary accepted'}catch{$localCheckpointError=$_.Exception}}finally{$localPeer.Dispose()}
            $localSidecar=Join-Path $localFixture.controller 'rpc-failure.json'
            if([bool]$localBoundary[1]){
                if($localCheckpointError.Message-cne'O01_PRODUCT_EXITED'-or-not(Test-Path -LiteralPath $localSidecar -PathType Leaf)){throw 'causal local checkpoint rejected'}
                $localOriginalRaw=[IO.File]::ReadAllText($localSidecar);$localOriginalBinding=[string]$localCheckpointError.Data['rpc_failure_sha256'];$localDoc=$localOriginalRaw|ConvertFrom-Json
                if([int]$localDoc.requests_handled-ne7-or[int]$localDoc.last_checkpoint_ordinal-ne1-or[string]$localDoc.origin-cne'LOCAL_PRODUCT'){throw 'causal local checkpoint binding invalid'}
                $null=ConvertTo-O01FailureProjectionV3 $localCheckpointError -EvidenceRoot $localFixture.root
                $localDoc.requests_handled=6;$localDoc.next_sequence=7;[IO.File]::WriteAllText($localSidecar,(($localDoc|ConvertTo-Json -Compress)+[char]10),[Text.UTF8Encoding]::new($false));$localCheckpointError.Data['rpc_failure_sha256']=(Get-FileHash $localSidecar -Algorithm SHA256).Hash.ToLowerInvariant()
                try{$null=ConvertTo-O01FailureProjectionV3 $localCheckpointError -EvidenceRoot $localFixture.root;throw 'V3 accepted noncausal local checkpoint'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
                [IO.File]::WriteAllText($localSidecar,$localOriginalRaw,[Text.UTF8Encoding]::new($false));$localCheckpointError.Data['rpc_failure_sha256']=$localOriginalBinding;$localCheckpointPath=Join-Path $localFixture.controller 'checkpoint-01.json';$localCheckpointRaw=[IO.File]::ReadAllText($localCheckpointPath)
                [IO.File]::AppendAllText($localCheckpointPath," `n",[Text.UTF8Encoding]::new($false));try{$null=ConvertTo-O01FailureProjectionV3 $localCheckpointError -EvidenceRoot $localFixture.root;throw 'V3 accepted mutated bound checkpoint'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
                [IO.File]::WriteAllText($localCheckpointPath,$localCheckpointRaw,[Text.UTF8Encoding]::new($false));Remove-Item -LiteralPath $localCheckpointPath -Force;try{$null=ConvertTo-O01FailureProjectionV3 $localCheckpointError -EvidenceRoot $localFixture.root;throw 'V3 accepted deleted bound checkpoint'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
            }else{
                if($localCheckpointError.Message-cne'O01_RPC_FAILURE_EVIDENCE_WRITE'-or'O01_RPC_FAILURE_CHECKPOINT_INVALID'-cnotin@($localCheckpointError.InnerExceptions|ForEach-Object{$_.Message})-or(Test-Path -LiteralPath $localSidecar)){throw 'noncausal local checkpoint accepted'}
            }
        }finally{Remove-TestEvidence $localFixture}
    }

    $formatFixture=New-TestEvidence
    try{
        $compactRecord=New-TestCheckpoint 1 ('0'*64);[IO.File]::WriteAllText((Join-Path $formatFixture.controller 'checkpoint-01.json'),(($compactRecord|ConvertTo-Json -Compress -Depth 32)+[char]10),[Text.UTF8Encoding]::new($false))
        $formatPeer=Start-CountPeer 6
        try{try{$null=Invoke-O01FormalRpcPump -Process $formatPeer -ReadProduct {param($sequence)"product-$sequence"} -FailureEvidenceRoot $formatFixture.controller;throw 'compact checkpoint accepted'}catch{if('O01_RPC_FAILURE_CHECKPOINT_INVALID'-cnotin@($_.Exception.InnerExceptions|ForEach-Object{$_.Message})){throw}}}finally{$formatPeer.Dispose()}
    }finally{Remove-TestEvidence $formatFixture}

    $gapFixture=New-TestEvidence
    try{Write-TestCheckpointChain $gapFixture.controller 3;Remove-Item -LiteralPath (Join-Path $gapFixture.controller 'checkpoint-02.json') -Force;$gapPeer=Start-CountPeer 16;try{try{$null=Invoke-O01FormalRpcPump -Process $gapPeer -ReadProduct {param($sequence)"product-$sequence"} -FailureEvidenceRoot $gapFixture.controller;throw 'checkpoint gap accepted'}catch{if('O01_RPC_FAILURE_CHECKPOINT_INVALID'-cnotin@($_.Exception.InnerExceptions|ForEach-Object{$_.Message})){throw}}}finally{$gapPeer.Dispose()}}finally{Remove-TestEvidence $gapFixture}

    $hashFixture=New-TestEvidence
    try{
        Write-TestCheckpointChain $hashFixture.controller 1;$cpPath=Join-Path $hashFixture.controller 'checkpoint-01.json';$cp=[IO.File]::ReadAllText($cpPath)|ConvertFrom-Json;$cp.product_sha256='f'*64
        $body=[ordered]@{schema=$cp.schema;ordinal=$cp.ordinal;elapsed_ms=$cp.elapsed_ms;fault_ordinal=$cp.fault_ordinal;executed=$cp.executed;slots=$cp.slots;product=$cp.product;gateway=$cp.gateway;product_sha256=$cp.product_sha256;gateway_sha256=$cp.gateway_sha256;previous_sha256=$cp.previous_sha256}
        $cp.record_sha256=Get-TestTextSha256 ("ese.v92.o01-checkpoint/v2"+[char]0+(ConvertTo-TestCanonicalJson $body))
        [IO.File]::WriteAllText($cpPath,((ConvertTo-TestPrettyJson $cp)+[char]10),[Text.UTF8Encoding]::new($false))
        $hashPeer=Start-CountPeer 6;try{try{$null=Invoke-O01FormalRpcPump -Process $hashPeer -ReadProduct {param($sequence)"product-$sequence"} -FailureEvidenceRoot $hashFixture.controller;throw 'forged product hash accepted'}catch{if('O01_RPC_FAILURE_CHECKPOINT_INVALID'-cnotin@($_.Exception.InnerExceptions|ForEach-Object{$_.Message})){throw}}}finally{$hashPeer.Dispose()}
    }finally{Remove-TestEvidence $hashFixture}

    $chainFixture=New-TestEvidence
    try{
        Write-TestCheckpointChain $chainFixture.controller 2;$cpPath=Join-Path $chainFixture.controller 'checkpoint-02.json';$cp=[IO.File]::ReadAllText($cpPath)|ConvertFrom-Json;$cp.previous_sha256='f'*64
        $body=[ordered]@{schema=$cp.schema;ordinal=$cp.ordinal;elapsed_ms=$cp.elapsed_ms;fault_ordinal=$cp.fault_ordinal;executed=$cp.executed;slots=$cp.slots;product=$cp.product;gateway=$cp.gateway;product_sha256=$cp.product_sha256;gateway_sha256=$cp.gateway_sha256;previous_sha256=$cp.previous_sha256}
        $cp.record_sha256=Get-TestTextSha256 ("ese.v92.o01-checkpoint/v2"+[char]0+(ConvertTo-TestCanonicalJson $body))
        [IO.File]::WriteAllText($cpPath,((ConvertTo-TestPrettyJson $cp)+[char]10),[Text.UTF8Encoding]::new($false))
        $chainPeer=Start-CountPeer 11;try{try{$null=Invoke-O01FormalRpcPump -Process $chainPeer -ReadProduct {param($sequence)"product-$sequence"} -FailureEvidenceRoot $chainFixture.controller;throw 'forged previous chain accepted'}catch{if('O01_RPC_FAILURE_CHECKPOINT_INVALID'-cnotin@($_.Exception.InnerExceptions|ForEach-Object{$_.Message})){throw}}}finally{$chainPeer.Dispose()}
    }finally{Remove-TestEvidence $chainFixture}
}finally{if(Test-Path -LiteralPath $countPeerPath){Remove-Item -LiteralPath $countPeerPath -Force}}

$junctionParent=Join-Path ([IO.Path]::GetTempPath()) ('o01-rpc-junction-'+[Guid]::NewGuid().ToString('N'))
$junctionTarget=Join-Path $junctionParent 'target';$junctionAlias=Join-Path $junctionParent 'alias'
try{
    $null=New-Item -ItemType Directory -Path (Join-Path $junctionTarget 'controller')
    $null=New-Item -ItemType Junction -Path $junctionAlias -Target $junctionTarget
    $junctionPeer=Start-Peer '3'
    try{try{$null=Invoke-O01FormalRpcPump -Process $junctionPeer -ReadProduct {throw 'unreachable'} -FailureEvidenceRoot (Join-Path $junctionAlias 'controller');throw 'junction evidence accepted'}catch{$junctionError=$_.Exception}}finally{$junctionPeer.Dispose()}
    if($junctionError.Message-cne'O01_RPC_FAILURE_EVIDENCE_WRITE'-or'O01_RPC_FAILURE_EVIDENCE_INVALID'-cnotin@($junctionError.InnerExceptions|ForEach-Object{$_.Message})-or(Test-Path -LiteralPath (Join-Path $junctionTarget 'controller\rpc-failure.json'))){throw 'junction ancestor bypassed'}
}finally{if(Test-Path -LiteralPath $junctionAlias){[IO.Directory]::Delete($junctionAlias)};if(Test-Path -LiteralPath $junctionParent){Remove-Item -LiteralPath $junctionParent -Recurse -Force}}

$directCases=@(
    [pscustomobject]@{code='O01_RPC_HOST_REQUEST_INVALID';stage='REQUEST_PARSE';reader={param($process)[pscustomobject]@{IsCompleted=$true;Result='not-json'}};writer=$null},
    [pscustomobject]@{code='O01_RPC_HOST_OUTPUT_CLOSED';stage='REQUEST_WAIT';reader={param($process)[pscustomobject]@{IsCompleted=$true;Result=$null}};writer=$null},
    [pscustomobject]@{code='O01_RPC_HOST_WRITE_FAILED';stage='RESPONSE_WRITE';reader={param($process)[pscustomobject]@{IsCompleted=$true;Result='{"schema":"ese.v92.o01-formal-rpc-request/v1","sequence":1,"operation":"product_next"}'}};writer={param($process,$json)throw 'injected write failure'}}
)
foreach($case in $directCases){
    $fixture=New-TestEvidence;$scriptPeer=$null
    try{
        $scriptPeer=Start-PowerShellPeer 'Start-Sleep -Seconds 30'
        $pumpArguments=@{Process=$scriptPeer;ReadProduct={param($sequence)"product-$sequence"};FailureEvidenceRoot=$fixture.controller;ReadRequest=$case.reader}
        if($null-ne$case.writer){$pumpArguments.WriteResponse=$case.writer}
        try{$null=Invoke-O01FormalRpcPump @pumpArguments;throw "direct pump failure accepted $($case.code)"}catch{$directError=$_.Exception;if($directError.Message-cne$case.code){throw}}
        $doc=Read-RpcFailure $fixture
        if([string]$doc.origin-cne'RPC_PUMP'-or[string]$doc.stage-cne$case.stage-or[string]$doc.failure_code-cne$case.code-or$null-ne$doc.host_exit_code){throw 'direct pump sidecar invalid'}
        $null=ConvertTo-O01FailureProjectionV3 $directError -EvidenceRoot $fixture.root
    }finally{Stop-TestProcess $scriptPeer;Remove-TestEvidence $fixture}
}

$mutatedModule=Join-Path ([IO.Path]::GetTempPath()) ('o01-rpc-timeout-'+[Guid]::NewGuid().ToString('N')+'.psm1')
$timeoutFixture=New-TestEvidence;$timeoutPeer=$null
try{
    $mutated=$moduleText.Replace('if($handled-eq0){300000}else{140000}','if($handled-eq0){100}else{100}')
    if($mutated-ceq$moduleText){throw 'timeout mutation missed'}
    [IO.File]::WriteAllText($mutatedModule,$mutated,[Text.UTF8Encoding]::new($false));Import-Module $mutatedModule -Force
    $timeoutPeer=Start-PowerShellPeer 'Start-Sleep -Seconds 30'
    try{$null=Invoke-O01FormalRpcPump -Process $timeoutPeer -ReadProduct {throw 'unreachable'} -FailureEvidenceRoot $timeoutFixture.controller;throw 'timeout accepted'}catch{$timeoutError=$_.Exception;if($timeoutError.Message-cne'O01_RPC_HOST_REQUEST_TIMEOUT'){throw}}
    $timeoutDoc=Read-RpcFailure $timeoutFixture
    if([string]$timeoutDoc.origin-cne'RPC_PUMP'-or[string]$timeoutDoc.stage-cne'REQUEST_WAIT'-or$null-ne$timeoutDoc.host_exit_code){throw 'timeout sidecar invalid'}
    $null=ConvertTo-O01FailureProjectionV3 $timeoutError -EvidenceRoot $timeoutFixture.root
}finally{Stop-TestProcess $timeoutPeer;Import-Module $module -Force;if(Test-Path -LiteralPath $mutatedModule){Remove-Item -LiteralPath $mutatedModule -Force};Remove-TestEvidence $timeoutFixture}

$collisionFixture=New-TestEvidence
try{
    $collisionPath=Join-Path $collisionFixture.controller 'rpc-failure.json';$sentinel='{"schema":"sentinel"}';[IO.File]::WriteAllText($collisionPath,$sentinel,[Text.UTF8Encoding]::new($false))
    $collisionPeer=Start-Peer '3'
    try{try{$null=Invoke-O01FormalRpcPump -Process $collisionPeer -ReadProduct {throw 'unreachable'} -FailureEvidenceRoot $collisionFixture.controller;throw 'RPC evidence collision accepted'}catch{$collisionError=$_.Exception}}finally{$collisionPeer.Dispose()}
    $innerMessages=if($collisionError-is[AggregateException]){@($collisionError.InnerExceptions|ForEach-Object{$_.Message}|Sort-Object)}else{@()}
    if($collisionError.Message-cne'O01_RPC_FAILURE_EVIDENCE_WRITE'-or($innerMessages-join',')-cne'O01_CONTROLLER_MAPPER_PROTOCOL,O01_RPC_FAILURE_EVIDENCE_EXISTS'-or[IO.File]::ReadAllText($collisionPath)-cne$sentinel-or(Test-Path -LiteralPath (Join-Path $collisionFixture.controller 'rpc-failure.json.tmp'))){throw 'RPC evidence collision invalid'}
    try{ConvertTo-O01FailureProjectionV3 $collisionError -EvidenceRoot $collisionFixture.root|Out-Null;throw 'collision sidecar inconsistency accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
}finally{Remove-TestEvidence $collisionFixture}

$emptyFixture=New-TestEvidence
try{
    $forged=[InvalidOperationException]::new('O01_PRODUCT_EXITED');$forged.Data['rpc_failure_sha256']='a'*64
    try{ConvertTo-O01FailureProjectionV3 $forged -EvidenceRoot $emptyFixture.root|Out-Null;throw 'forged binding without sidecar accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
    $nullBinding=[InvalidOperationException]::new('O01_PRODUCT_EXITED');$nullBinding.Data['rpc_failure_sha256']=$null
    try{ConvertTo-O01FailureProjectionV3 $nullBinding -EvidenceRoot $emptyFixture.root|Out-Null;throw 'null binding accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
    $inner=[InvalidOperationException]::new('O01_PRODUCT_EXITED');$inner.Data['rpc_failure_sha256']='a'*64;$multiple=[InvalidOperationException]::new('O01_PRODUCT_EXITED',$inner);$multiple.Data['rpc_failure_sha256']='a'*64
    try{ConvertTo-O01FailureProjectionV3 $multiple -EvidenceRoot $emptyFixture.root|Out-Null;throw 'multiple binding accepted'}catch{if($_.Exception.Message-cne'O01_FAILURE_PROJECTION_RPC_BINDING'){throw}}
    $plain=ConvertTo-O01FailureProjectionV3 ([InvalidOperationException]::new('O01_PRODUCT_EXITED')) -EvidenceRoot $emptyFixture.root
    if($null-ne$plain.rpc_failure_sha256){throw 'non-RPC failure acquired binding'}
}finally{Remove-TestEvidence $emptyFixture}

[pscustomobject]@{schema='ese.v92.o01-formal-rpc-pump-mock/v3';verdict='PASS';requests=3;credential_serialized=$false;closed_host_failure=$true;hostile_stderr_bytes=1048576;stderr_tail_max=16384;rpc_failure_atomic=$true;rpc_failure_private=$true;failure_v3_bound=$true;checkpoint_chain_bound=$true;pump_failures_published=$true}|ConvertTo-Json -Compress
