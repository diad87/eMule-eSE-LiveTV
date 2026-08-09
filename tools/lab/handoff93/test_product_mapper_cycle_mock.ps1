[CmdletBinding()] param()
$ErrorActionPreference='Stop'; Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot '..\common.ps1')
function Assert-T($c,$m){if(-not $c){throw $m}}
function Import-F($ast,$name){$m=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));if($m.Count-ne 1){throw "missing $name"};$t=$m[0].Body.Extent.Text;Set-Item "Function:\script:$name" ([scriptblock]::Create($t.Substring(1,$t.Length-2)))}
$path=Join-Path $PSScriptRoot 'run_product_mapper_cycle.ps1';$tok=$null;$err=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tok,[ref]$err)
Assert-T ($err.Count-eq 0) 'parser errors'
foreach($n in @('Assert-R93NoReparseChain','Set-R93ProductIni',
        'Get-R93ProductProcessInventory','Get-R93LockedExecutableSha256',
        'Assert-R93LaunchedProcessHandleIdentity',
        'Read-R93PreexistingProcessAllowlist',
        'Assert-R93ExactProcessIdentitySet','Assert-R93OneNewCandidateProcess',
        'Restore-R93IniBytes','Invoke-R93AuthenticatedWebClose',
        'Invoke-R93AccreditedWebShutdown',
        'Get-R93CandidateProjection',
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
    $testAdminHash='0123456789abcdef0123456789abcdef'
    Set-R93ProductIni $iniPath 41001 41002 41003 $testAdminHash
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
        $sections['WebServer']['Port']-ceq '41003' -and
        $sections['WebServer']['Password']-ceq $testAdminHash) 'production helper did not configure authenticated WebServer'
    Assert-T ($sections['eMule']['AllowAdminHiLevelFunc']-ceq '1') 'high-level local admin action was not enabled'
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

$requests=[Collections.ArrayList]::new()
$storedHash='0123456789abcdef0123456789abcdef'
$challenge=('c'*64)
function Get-TestChallengeResponse($nonce,$hash){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return (($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes(
        $nonce+$hash))|ForEach-Object{$_.ToString('x2')})-join '')}
    finally{$sha.Dispose()}
}
$expectedResponse=Get-TestChallengeResponse $challenge $storedHash
$requestInvoker={param($uri,$session,$headers)
    $null=$requests.Add([pscustomobject]@{uri=$uri;session=$session;headers=$headers})
    if($uri.EndsWith('/')){
        return [pscustomobject]@{Content="<input type=`"hidden`" name=`"n`" value=`"$challenge`">";Headers=@{}}
    }
    if($uri -match 'w=password'){
        return [pscustomobject]@{Headers=@{'X-CSRF-Token'=('a'*64)}}
    }
    return [pscustomobject]@{Headers=@{}}
}.GetNewClosure()
Assert-T (Invoke-R93AuthenticatedWebClose 'http://127.0.0.1:41003' `
    $storedHash $requestInvoker) 'authenticated Web close protocol failed'
Assert-T ($requests.Count-eq 3 -and
    $requests[0].uri-ceq 'http://127.0.0.1:41003/' -and
    $requests[1].uri-ceq "http://127.0.0.1:41003/?w=password&n=$challenge&r=$expectedResponse" -and
    $requests[2].uri-ceq 'http://127.0.0.1:41003/?w=close' -and
    [object]::ReferenceEquals($requests[0].session,$requests[1].session) -and
    [object]::ReferenceEquals($requests[1].session,$requests[2].session) -and
    $requests[2].headers['X-CSRF-Token']-ceq ('a'*64) -and
    $requests[2].headers['Sec-Fetch-Site']-ceq 'same-origin') 'challenge/session/CSRF close exchange is not exact'
$requestText=($requests|ForEach-Object{$_.uri})-join ''
Assert-T (-not $requestText.Contains($storedHash)) 'stored credential hash leaked into request URI'

# A transport loss during challenge/login is retried with identity accreditation.
$retryNonces=@(('b'*64),('c'*64))
$retryState=[pscustomobject]@{alive=$true;challengeCalls=0;loginCalls=0
    accreditations=0;loginUris=[Collections.ArrayList]::new()}
$retryInvoker={param($uri,$session,$headers)
    if($uri.EndsWith('/')){
        $retryState.challengeCalls++
        $issued=$retryNonces[$retryState.challengeCalls-1]
        return [pscustomobject]@{Content="<input name=`"n`" value=`"$issued`">";Headers=@{}}
    }
    if($uri -match 'w=password'){
        $retryState.loginCalls++
        $null=$retryState.loginUris.Add($uri)
        if($retryState.loginCalls-eq 1){throw 'simulated transport loss during login'}
        return [pscustomobject]@{Headers=@{'X-CSRF-Token'=('d'*64)}}
    }
    return [pscustomobject]@{Headers=@{}}
}.GetNewClosure()
$retryClose={param($token)if(Invoke-R93AuthenticatedWebClose `
    'http://127.0.0.1:41003' $storedHash $retryInvoker){$retryState.alive=$false}}.GetNewClosure()
Assert-T (Invoke-R93AccreditedWebShutdown 77 2 `
    {param($t)$retryState.alive}.GetNewClosure() `
    {param($t)$retryState.accreditations++;$true}.GetNewClosure() $retryClose `
    {param($t,$ms)-not $retryState.alive}.GetNewClosure()) 'login transport retry did not recover'
Assert-T ($retryState.challengeCalls-eq 2 -and $retryState.loginCalls-eq 2 -and
    $retryState.accreditations-ge 2) 'login retry was not freshly challenged and re-accredited'
$loginProofs=@($retryState.loginUris|ForEach-Object{
    if($_ -cnotmatch '[?&]n=([0-9a-f]{64})&r=([0-9a-f]{64})$'){
        throw 'retry login URI is not canonical challenge-response'
    }
    [pscustomobject]@{nonce=$Matches[1];response=$Matches[2]}
})
Assert-T ($loginProofs.Count-eq 2 -and
    $loginProofs[0].nonce-cne $loginProofs[1].nonce) 'retry reused its consumed nonce'
foreach($proof in $loginProofs){
    Assert-T ($proof.response-ceq (Get-TestChallengeResponse $proof.nonce $storedHash)) `
        'retry response did not bind its own nonce to the stored hash'
}

# A lost response to the close request is ambiguous and also gets a fresh challenge.
$closeLossNonces=@(('d'*64),('e'*64))
$closeLoss=[pscustomobject]@{alive=$true;closeCalls=0;challengeCalls=0
    loginUris=[Collections.ArrayList]::new()}
$lossInvoker={param($uri,$session,$headers)
    if($uri.EndsWith('/')){
        $closeLoss.challengeCalls++
        $issued=$closeLossNonces[$closeLoss.challengeCalls-1]
        return [pscustomobject]@{Content="<input name=`"n`" value=`"$issued`">";Headers=@{}}
    }
    if($uri -match 'w=password'){
        $null=$closeLoss.loginUris.Add($uri)
        return [pscustomobject]@{Headers=@{'X-CSRF-Token'=('e'*64)}}
    }
    $closeLoss.closeCalls++;if($closeLoss.closeCalls-eq 1){throw 'simulated close response loss'}
    return [pscustomobject]@{Headers=@{}}
}.GetNewClosure()
$lossClose={param($token)if(Invoke-R93AuthenticatedWebClose `
    'http://127.0.0.1:41003' $storedHash $lossInvoker){$closeLoss.alive=$false}}.GetNewClosure()
Assert-T (Invoke-R93AccreditedWebShutdown 78 2 {param($t)$closeLoss.alive}.GetNewClosure() `
    {param($t)$true} $lossClose {param($t,$ms)-not $closeLoss.alive}.GetNewClosure()) 'close transport retry did not recover'
Assert-T ($closeLoss.closeCalls-eq 2 -and $closeLoss.challengeCalls-eq 2) 'close retry reused a consumed challenge'
$closeLossProofs=@($closeLoss.loginUris|ForEach-Object{
    if($_ -cnotmatch '[?&]n=([0-9a-f]{64})&r=([0-9a-f]{64})$'){
        throw 'close-loss login URI is not canonical challenge-response'
    }
    [pscustomobject]@{nonce=$Matches[1];response=$Matches[2]}
})
Assert-T ($closeLossProofs.Count-eq 2 -and
    $closeLossProofs[0].nonce-cne $closeLossProofs[1].nonce) `
    'close-loss retry did not replace its consumed nonce'
foreach($proof in $closeLossProofs){
    Assert-T ($proof.response-ceq (Get-TestChallengeResponse $proof.nonce $storedHash)) `
        'close-loss retry response did not bind its own nonce to the stored hash'
}

# Direct fail-closed contracts: exhausted timeout stays live; lost identity stops immediately.
$timeoutState=[pscustomobject]@{alive=$true;accreditations=0}
$timeoutShutdown=Invoke-R93AccreditedWebShutdown 79 1 `
    {param($t)$timeoutState.alive}.GetNewClosure() `
    {param($t)$timeoutState.accreditations++;$true}.GetNewClosure() `
    {param($t)throw 'transport unavailable'} `
    {param($t,$ms)Start-Sleep -Milliseconds $ms;$false}
Assert-T (-not $timeoutShutdown -and $timeoutState.accreditations-ge 1) 'live timeout was not fail-closed'
$identityState=[pscustomobject]@{attempts=0}
$identityLost=$false
try{
    $null=Invoke-R93AccreditedWebShutdown 80 1 {param($t)$true} `
        {param($t)$identityState.attempts++;$false}.GetNewClosure() `
        {param($t)throw 'must not close'} {param($t,$ms)throw 'must not wait'}
}catch{$identityLost=$_.Exception.Message -match 'identity changed'}
Assert-T ($identityLost -and $identityState.attempts-eq 1) 'lost identity did not stop before close/wait'

function New-Adapters([scriptblock]$sample,[bool]$wait=$true,[bool]$absent=$true,[bool]$accredited=$true){
    $original=[byte[]](1,7,3,9,0,255)
    $state=[pscustomobject]@{configured=$false;started=$false;closed=$false
        restored=$false;alive=$false;upnp=$null
        bytes=[byte[]]$original.Clone();original=[byte[]]$original.Clone()
        order=[Collections.ArrayList]::new();closed_tokens=[Collections.ArrayList]::new()
        start_saw_upnp=$false}
    $a=[pscustomobject]@{
        Configure={ $null=$state.order.Add('Configure');$state.configured=$true
            $state.upnp='1';$state.bytes=[byte[]](9,9,9) }
        Start={ $null=$state.order.Add('Start');$state.started=$true
            $state.start_saw_upnp=($state.upnp-ceq '1');$state.alive=$true;return 77 }
        Exists={param($t) $state.alive}; IsAccredited={param($t) $accredited}; Sample=$sample; Pause={}
        Close={param($t)$state.closed=$true;$null=$state.closed_tokens.Add([int]$t)}; WaitForExit={param($t)if($wait){$state.alive=$false};return $wait}
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
Assert-T ($aliveResult.status-ceq 'BLOCKED' -and $aliveResult.intervention_required -and $alive.state.closed -and -not $alive.state.restored -and
    -not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
        $alive.state.bytes,$alive.state.original)) 'live PID exception destroyed recovery configuration'
Assert-T ($aliveJson -notmatch '(?i)pid|process_id|[A-Z]:\\|/[A-Za-z]+/') 'safe result leaked identity/path'

$remaining=New-Adapters { [pscustomobject]@{tcp_candidate=$true;udp_candidate=$true;same_generation=$true;generation=4} } $true $false
$remainingResult=Invoke-R93PartialCycle $remaining.adapters 1
Assert-T ($remainingResult.status-ceq 'BLOCKED' -and $remainingResult.failure_class-ceq 'MAPPING_REMAINS_UNTOUCHED') 'remaining mapping not blocked'

$untrusted=New-Adapters { throw 'must not sample' } $true $true $false
$untrustedResult=Invoke-R93PartialCycle $untrusted.adapters 1
Assert-T ($untrustedResult.status-ceq 'BLOCKED' -and $untrustedResult.intervention_required -and -not $untrustedResult.graceful_exit -and -not $untrusted.state.closed -and -not $untrusted.state.restored) 'unaccredited live PID was closed or recovery configuration destroyed'

# Explicit preexisting identities are an exact immutable set. PID reuse,
# extras, missing entries and any identity-field drift fail closed.
function New-ProcessIdentity($processId,$path,$sha,$creation,$session){
    [pscustomobject]@{pid=$processId;canonical_path=$path;sha256=$sha
        creation_time_utc=$creation;session_id=$session}
}
$creation='2026-08-09T10:00:00.0000000Z'
$shaA='a'*64;$shaB='b'*64;$candidateSha='c'*64
$allowed=@(
    (New-ProcessIdentity 101 'C:\Product\emule.exe' $shaA $creation 1),
    (New-ProcessIdentity 202 'C:\Lab\emule.exe' $shaB $creation 2))

# The production reader accepts only its closed schema and canonical identity
# fields; hostile/duplicate entries cannot silently widen the allowlist.
$allowlistPath=Join-Path ([IO.Path]::GetTempPath()) `
    ('r93-process-allowlist-'+[Guid]::NewGuid().ToString('N')+'.json')
$allowlistStream=$null
function Read-TestAllowlist($path){
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try{return @(Read-R93PreexistingProcessAllowlist $stream)}
    finally{$stream.Dispose()}
}
try{
    [pscustomobject][ordered]@{schema='ese.lab.preexisting-process-allowlist/v1'
        processes=$allowed}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $allowlistPath -Encoding UTF8
    $readAllowed=@(Read-TestAllowlist $allowlistPath)
    Assert-T (Assert-R93ExactProcessIdentitySet $allowed $readAllowed) `
        'production allowlist reader changed an exact identity'
    [pscustomobject][ordered]@{schema='ese.lab.preexisting-process-allowlist/v1'
        processes=@($allowed[0],$allowed[0])}|ConvertTo-Json -Depth 4|
        Set-Content -LiteralPath $allowlistPath -Encoding UTF8
    $duplicateRejected=$false
    try{$null=Read-TestAllowlist $allowlistPath}catch{$duplicateRejected=$true}
    Assert-T $duplicateRejected 'duplicate allowlist PID was accepted'
    $hostileEntry=[pscustomobject]@{pid=101;canonical_path='C:\Product\emule.exe'
        sha256=$shaA;creation_time_utc=$creation;session_id=1;unexpected='x'}
    [pscustomobject][ordered]@{schema='ese.lab.preexisting-process-allowlist/v1'
        processes=@($hostileEntry)}|ConvertTo-Json -Depth 4|
        Set-Content -LiteralPath $allowlistPath -Encoding UTF8
    $fieldRejected=$false
    try{$null=Read-TestAllowlist $allowlistPath}catch{$fieldRejected=$true}
    Assert-T $fieldRejected 'allowlist identity with extra field was accepted'

    # Production-style retained handle blocks synchronized rename/replace and
    # keeps the hash/read bound to the same native file object.
    [pscustomobject][ordered]@{schema='ese.lab.preexisting-process-allowlist/v1'
        processes=$allowed}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $allowlistPath -Encoding UTF8
    $allowlistReplacement=$allowlistPath+'.replacement'
    [IO.File]::WriteAllText($allowlistReplacement,'{}',[Text.UTF8Encoding]::new($false))
    $allowlistStream=[IO.File]::Open($allowlistPath,[IO.FileMode]::Open,
        [IO.FileAccess]::Read,[IO.FileShare]::Read)
    $allowlistLockedHash=Get-R93LockedExecutableSha256 $allowlistStream
    $null=Read-R93PreexistingProcessAllowlist $allowlistStream
    $allowlistSwapRejected=$false
    try{[IO.File]::Replace($allowlistReplacement,$allowlistPath,$null)}
    catch{$allowlistSwapRejected=$true}
    Assert-T ($allowlistSwapRejected -and
        (Get-R93LockedExecutableSha256 $allowlistStream)-ceq $allowlistLockedHash) `
        'retained allowlist stream permitted synchronized swap or hash drift'
}finally{
    if($null-ne $allowlistStream){$allowlistStream.Dispose()}
    foreach($candidate in @($allowlistPath,$allowlistPath+'.replacement')){
        if(Test-Path -LiteralPath $candidate){Remove-Item -LiteralPath $candidate -Force}}
}
Assert-T (Assert-R93ExactProcessIdentitySet $allowed @($allowed[1],$allowed[0])) `
    'exact allowlist rejected ordering difference'
foreach($hostile in @(
    @($allowed[0]),
    @($allowed+(New-ProcessIdentity 70000 'C:\Extra\emule.exe' ('d'*64) $creation 3)),
    @($allowed[0],(New-ProcessIdentity 202 'C:\Lab\emule.exe' $shaB `
        '2026-08-09T10:00:01.0000000Z' 2)),
    @($allowed[0],(New-ProcessIdentity 202 'C:\Lab\emule.exe' $shaB $creation 9)),
    @($allowed[0],(New-ProcessIdentity 202 'C:\Other\emule.exe' $shaB $creation 2)),
    @($allowed[0],(New-ProcessIdentity 202 'C:\Lab\emule.exe' ('e'*64) $creation 2)))){
    $rejected=$false
    try{$null=Assert-R93ExactProcessIdentitySet $allowed $hostile}catch{$rejected=$true}
    Assert-T $rejected 'hostile preexisting set was accepted'
}
$after=@($allowed+(New-ProcessIdentity 70001 'c:\candidate\EMULE.EXE' `
    $candidateSha '2026-08-09T10:01:00.0000000Z' 4))
$newIdentity=Assert-R93OneNewCandidateProcess $allowed $after 70001 `
    'C:\Candidate\emule.exe' $candidateSha
Assert-T ($newIdentity.pid-eq 70001) 'one exact new candidate was not accredited'
foreach($badAfter in @(
    $allowed,
    @($after+(New-ProcessIdentity 70002 'C:\Candidate\emule.exe' $candidateSha `
        '2026-08-09T10:01:01.0000000Z' 4)),
    @($allowed+(New-ProcessIdentity 70001 'C:\Wrong\emule.exe' $candidateSha `
        '2026-08-09T10:01:00.0000000Z' 4)),
    @($allowed+(New-ProcessIdentity 70001 'C:\Candidate\emule.exe' ('f'*64) `
        '2026-08-09T10:01:00.0000000Z' 4)))){
    $rejected=$false
    try{$null=Assert-R93OneNewCandidateProcess $allowed $badAfter 70001 `
            'C:\Candidate\emule.exe' $candidateSha}catch{$rejected=$true}
    Assert-T $rejected 'invalid new-process delta was accepted'
}

# The protected set is verified around the complete cycle. Only the newly
# accredited token reaches Close.
$protected=New-Adapters { [pscustomobject]@{tcp_candidate=$true;udp_candidate=$true;same_generation=$true;generation=5} }
$protectedState=[pscustomobject]@{checks=0;accreditedPid=0}
$protected.adapters|Add-Member NoteProperty VerifyPreexisting ({
    $protectedState.checks++;return $true}.GetNewClosure())
$protected.adapters|Add-Member NoteProperty AccreditNewProcess ({param($token)
    $protectedState.accreditedPid=$token;return $true}.GetNewClosure())
$protectedResult=Invoke-R93PartialCycle $protected.adapters 1
Assert-T ($protectedResult.status-ceq 'MAPPING_OBSERVED_CLEAN_EXIT' -and
    $protectedState.checks-ge 4 -and $protectedState.accreditedPid-eq 77 -and
    $protected.state.closed_tokens.Count-eq 1 -and
    $protected.state.closed_tokens[0]-eq 77 -and
    $protected.state.closed_tokens -notcontains 101 -and
    $protected.state.closed_tokens -notcontains 202) `
    'preexisting process checks did not surround the full cycle'
$changed=New-Adapters { $null }
$changedState=[pscustomobject]@{checks=0}
$changed.adapters|Add-Member NoteProperty VerifyPreexisting ({
    $changedState.checks++;if($changedState.checks-ge 2){throw 'identity drift'}
    return $true}.GetNewClosure())
$changed.adapters|Add-Member NoteProperty AccreditNewProcess ({param($token)return $true})
$changedResult=Invoke-R93PartialCycle $changed.adapters 1
$changedJson=$changedResult|ConvertTo-Json -Compress
Assert-T ($changedResult.status-ceq 'BLOCKED' -and
    $changedResult.failure_class-ceq 'PREEXISTING_PROCESS_CHANGED' -and
    $changedResult.intervention_required -and $changed.state.closed) `
    'preexisting drift did not fail closed without closing only the launched PID'
Assert-T ($changedJson -notmatch '(?i)pid|process_id|canonical_path|sha256|creation_time|session_id|[A-Z]:\\') `
    'process allowlist identity leaked into result JSON'

# If creation succeeds and the very next identity capture throws, the published
# token is recovered by finally. The live unaccredited child is neither closed
# nor allowed to overwrite a restored INI.
$spawnThrowRoot=Join-Path 'C:\tmp' ('r93-spawn-throw-'+[Guid]::NewGuid().ToString('N'))
$spawnThrowState=[pscustomobject]@{process=$null;token=$null}
try{
    [IO.Directory]::CreateDirectory($spawnThrowRoot)|Out-Null
    $spawnThrowExe=Join-Path $spawnThrowRoot 'r93_spawn_throw.exe'
    [IO.File]::Copy((Join-Path $env:WINDIR 'System32\ping.exe'),$spawnThrowExe)
    $spawnThrow=New-Adapters {throw 'must not sample'}
    $spawnThrowToken=$null
    $spawnThrow.adapters.Start={
        $spawnThrowState.process=Start-Process -FilePath $spawnThrowExe `
            -ArgumentList @('-n','30','127.0.0.1') -WindowStyle Hidden -PassThru
        $spawnThrowState.token=[int]$spawnThrowState.process.Id
        throw 'injected capture failure after ownership publication'
    }.GetNewClosure()
    $spawnThrow.adapters|Add-Member NoteProperty GetSpawnedToken ({
        return $spawnThrowState.token}.GetNewClosure())
    $spawnThrow.adapters.Exists={param($token)
        return $null-ne $spawnThrowState.process -and
            [int]$spawnThrowState.process.Id-eq [int]$token -and
            -not $spawnThrowState.process.HasExited}.GetNewClosure()
    $spawnThrowResult=Invoke-R93PartialCycle $spawnThrow.adapters 1
    Assert-T ($spawnThrowResult.status-ceq 'BLOCKED' -and
        $spawnThrowResult.failure_class-ceq 'IDENTITY_NOT_ACCREDITED' -and
        $spawnThrowResult.intervention_required -and
        $spawnThrow.state.closed_tokens.Count-eq 0 -and
        -not $spawnThrow.state.restored -and
        $null-ne $spawnThrowState.process -and
        -not $spawnThrowState.process.HasExited) `
        'spawn-then-throw lost ownership or touched an unaccredited live child'
}finally{
    if($null-ne $spawnThrowState.process -and
        -not $spawnThrowState.process.HasExited){
        Stop-Process -Id $spawnThrowState.process.Id -Force -ErrorAction SilentlyContinue
        $spawnThrowState.process.WaitForExit(5000)|Out-Null}
    if($null-ne $spawnThrowState.process){$spawnThrowState.process.Dispose()}
    if(Test-Path -LiteralPath $spawnThrowRoot){
        Remove-Item -LiteralPath $spawnThrowRoot -Recurse -Force}
}

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
Assert-T ($source -notmatch '(?i)ledger|Remove-R01Upnp|DeletePortMapping|Stop-Process|taskkill|TerminateProcess|\.Kill\(|WM_QUIT|Send-R93WmClose') 'forbidden mutation/termination present'
$upnpConfigIndex=$source.IndexOf('Set-R93ProductIni $ini $TcpPort $UdpPort $WebPort $adminHash')
$startProcessIndex=$source.IndexOf('Start-Process -FilePath $exe')
Assert-T ($upnpConfigIndex-ge 0 -and $startProcessIndex-gt $upnpConfigIndex) 'real UPnP=1 configuration is not before Start'
foreach($needle in @("-Path '/api/reach/status'",'/?w=password&n=','&r=','/?w=close','X-CSRF-Token','Sec-Fetch-Site','[IO.File]::ReadAllBytes($ini)','Restore-R93IniBytes $ini $iniBytes $iniHash','satisfies_h93_15 = $false')){Assert-T $source.Contains($needle) "missing $needle"}
Assert-T ($source -notmatch '\?w=password&p=|AdminPassword|adminSecret') 'reversible credential login remains present'
Assert-T ($source -notmatch 'PreexistingProcessAllowlistPath' -and
    $source.Contains("Join-Path `$config 'preexisting-process-allowlist.json'") -and
    $source -match 'Assert-R93OneNewCandidateProcess') `
    'fixed-name preexisting-process allowlist is not wired into production'

# A real Windows process proves that the production handle identity accepts a
# live instance and rejects that same PID token after the retained handle dies.
$identityProcess=$null
$identityRoot=Join-Path 'C:\tmp' ('r93-process-identity-'+[Guid]::NewGuid().ToString('N'))
try{
    [IO.Directory]::CreateDirectory($identityRoot)|Out-Null
    $identityExe=Join-Path $identityRoot 'r93_identity_wait.exe'
    [IO.File]::Copy((Join-Path $env:WINDIR 'System32\ping.exe'),$identityExe)
    $identityProcess=Start-Process -FilePath $identityExe -ArgumentList @(
        '-n','30','127.0.0.1') -WindowStyle Hidden -PassThru
    $null=$identityProcess.Handle
    $identityInventory=@(Get-R93ProductProcessInventory 'r93_identity_wait.exe'|
        Where-Object{[int]$_.pid-eq [int]$identityProcess.Id})
    Assert-T ($identityInventory.Count-eq 1) 'real process identity was not observable'
    $identityPath=[string]$identityInventory[0].canonical_path
    $identitySha=[string]$identityInventory[0].sha256
    Assert-T (Assert-R93LaunchedProcessHandleIdentity $identityProcess `
        $identityInventory[0] $identityPath $identitySha) `
        'live retained process handle was not accredited'
    $commandLine=[string](Get-CimInstance Win32_Process `
        -Filter "ProcessId=$($identityProcess.Id)").CommandLine
    Assert-T ($commandLine -notmatch '(?i)preexisting-process-allowlist|[0-9a-f]{64}|C:\\Users\\') `
        'test launch command line exposed allowlist identity material'
    Stop-Process -Id $identityProcess.Id -Force
    $identityProcess.WaitForExit(5000)|Out-Null
    $deadRejected=$false
    try{$null=Assert-R93LaunchedProcessHandleIdentity $identityProcess `
            $identityInventory[0] $identityPath $identitySha}catch{$deadRejected=$true}
    Assert-T $deadRejected 'dead retained handle permitted PID-reuse accreditation'
}finally{
    if($null-ne $identityProcess -and -not $identityProcess.HasExited){
        Stop-Process -Id $identityProcess.Id -Force -ErrorAction SilentlyContinue}
    if($null-ne $identityProcess){$identityProcess.Dispose()}
    if(Test-Path -LiteralPath $identityRoot){
        Remove-Item -LiteralPath $identityRoot -Recurse -Force}
}

# Hashing and execution share one read handle that denies write/delete. A real
# rename/swap attempt against the locked image must fail until the handle closes.
$lockRoot=Join-Path ([IO.Path]::GetTempPath()) ('r93-exe-lock-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($lockRoot)|Out-Null
$lockImage=Join-Path $lockRoot 'candidate.exe';$replacement=Join-Path $lockRoot 'replacement.exe'
$lockStream=$null
try{
    [IO.File]::Copy((Join-Path $env:WINDIR 'System32\where.exe'),$lockImage)
    [IO.File]::Copy((Join-Path $env:WINDIR 'System32\where.exe'),$replacement)
    $lockStream=[IO.File]::Open($lockImage,[IO.FileMode]::Open,
        [IO.FileAccess]::Read,[IO.FileShare]::Read)
    $lockedHash=Get-R93LockedExecutableSha256 $lockStream
    Assert-T ($lockedHash -match '^[0-9a-f]{64}$') 'same-stream executable hash invalid'
    $loaderProbe=Start-Process -FilePath $lockImage -ArgumentList 'where.exe' `
        -WindowStyle Hidden -PassThru -Wait
    Assert-T $loaderProbe.HasExited 'read-locked verified image was not loader compatible'
    $loaderProbe.Dispose()
    $swapRejected=$false
    try{[IO.File]::Replace($replacement,$lockImage,$null)}catch{$swapRejected=$true}
    Assert-T $swapRejected 'locked executable permitted rename/replace TOCTOU'
}finally{
    if($null-ne $lockStream){$lockStream.Dispose()}
    if(Test-Path -LiteralPath $lockRoot){Remove-Item -LiteralPath $lockRoot -Recurse -Force}
}

[pscustomobject]@{schema='ese.lab.product-mapper-cycle-mock/v2';status='PASS';physical_execution_performed=$false;outer_finally_close=$true;mapping_deletion_capability=$false;h93_15_satisfied=$false}|ConvertTo-Json -Compress
