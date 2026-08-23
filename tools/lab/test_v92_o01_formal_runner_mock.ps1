$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0

$runner=Join-Path $PSScriptRoot 'run_v92_o01_formal.ps1'
$module=Join-Path $PSScriptRoot 'v92_o01_vm_session.psm1'
$runnerText=[IO.File]::ReadAllText($runner)
$moduleText=[IO.File]::ReadAllText($module)

foreach($surface in @($runner,$module)){
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($surface,[ref]$tokens,[ref]$errors)
    if(@($errors).Count-ne0){throw "runner parse: $surface"}
    foreach($command in $ast.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]},$true)){
        $name=$command.GetCommandName()
        if($name-and$name-match'^(?:throw|return|break|continue).+'){throw "PowerShell keyword merged: $name"}
        if($name-ceq'Join-Path'-and$command.CommandElements.Count-lt3){throw 'Join-Path missing explicit ChildPath argument'}
        foreach($element in $command.CommandElements){
            $elementText=$element.Extent.Text
            if(($element-is[Management.Automation.Language.CommandParameterAst]-and$element.ParameterName.Contains('$'))-or($elementText.StartsWith('-')-and($elementText.Contains([char]39)-or$elementText.Contains([char]34)))){throw 'PowerShell parameter merged with its argument'}
        }
    }
}

$tokens=$null;$errors=$null
$runnerAst=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
$functionNames=@('Assert-O01PhysicalLaunchBoundary','AssertNoReparse','AssertTreeNoReparse','Assert-O01IsolatedNodeRuntime','Set-O01IsolatedNodeEnvironment','Invoke-O01IsolatedNodeCapture','Set-O01ClosedGitProcessEnvironment','Get-O01NormalizedGitBlobSha1','Assert-O01ClosedGitCheckout','Assert-O01PackageManifest','Assert-O01InventoryBindings','Assert-O01DirectorySet','Get-O01RegularFileSha256','Read-O01RegularJsonSnapshot','Write-O01ExclusiveJson','Get-O01ValidatedInputHashes','Assert-O01InputHashesEqual','Open-O01ValidatedInputGuard','Get-O01InputGuardHashes','Read-O01InputGuardJson','Close-O01ValidatedInputGuard','Remove-O01HostConfig','Remove-O01PartialSeal','Get-O01FailureException')
$definitions=[ordered]@{}
foreach($name in $functionNames){
    $matches=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq$name},$true))
    if($matches.Count-ne1){throw "runner helper cardinality: $name"}
    $definitions[$name]=$matches[0].Extent.Text
}

foreach($required in @(
    'Start-O01VmSession','Invoke-O01FormalRpcPump','Invoke-O01FormalStage','Read-O01GuestSharedJsonlSnapshot','Read-O01ProductRecord',
    '-FormalSoakChild','New-VHD','Connect-VMNetworkAdapter','New-NetFirewallRule','New-PSSession','Copy-Item','Invoke-O01SessionRollback',
    'v92_o01_validate_formal.js','ExpectedNodeSha256','ExpectedBuildInfoSha256','ExpectedPackageManifestSha256','Assert-O01PackageManifest','Assert-O01DirectorySet','SHA256SUMS.txt','runtime_bindings','package_manifest_sha256','package_manifest_entry_count','package_file_count','node_version=$nodeVersion.TrimStart','EnvironmentVariables.Clear()','runtimePackageEntries','runtimePackageDirectories','guestProjection','GUEST_ROOT_EXISTS','GUEST_PACKAGE_REPARSE','ese.v92.o01-formal-run/v2','Assert-O01PhysicalLaunchBoundary','-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','AssertNoReparse','AssertTreeNoReparse','Assert-O01IsolatedNodeRuntime','Invoke-O01IsolatedNodeCapture','Set-O01IsolatedNodeEnvironment','Assert-O01ClosedGitCheckout','[IO.File]::Copy($nodeSource,$node,$false)',
    "'PREPARE_GUEST'","'COPY_PACKAGE_FILES'","'COPY_PACKAGE_DIRECTORIES'","'COPY_TOOL_FILES'","'BUILD_BINDINGS'","'VERIFY_GUEST_BINDINGS'","'START_PRODUCT'",
    'independent_validation=$true','release_gate=$true','duration_ms=28800000','product_records=482')){
    if(-not$runnerText.Contains($required)){throw "missing runner surface: $required"}
}
foreach($forbidden in @('[switch]$Resume','[switch]$SkipCleanup','DurationSec','mstsc','Enter-PSSession','Stop-Process','taskkill','[IO.File]::WriteAllText($failureTemp','Move-Item -LiteralPath $failureTemp')){
    if($runnerText.Contains($forbidden)){throw "forbidden runner surface: $forbidden"}
}

if(-not$runnerText.Contains('ConvertTo-O01FailureProjectionV3 $failure -EvidenceRoot $root')){throw 'failure V3 must receive the exact evidence root'}
if([regex]::Matches($runnerText,[regex]::Escape('ConvertTo-O01FailureProjectionV3 $failure -EvidenceRoot $root')).Count-ne1){throw 'formal failure branch must be unique'}
if(-not$runnerText.Contains("[IO.FileMode]::CreateNew")-or-not$runnerText.Contains('$stream.Flush($true)')-or-not$runnerText.Contains('[IO.File]::Move($temporary,$Path)')){throw 'exclusive durable JSON writer contract missing'}
if([regex]::Matches($runnerText,'Remove-O01HostConfig \$configPath').Count-ne2){throw 'host config must be removed on PASS and again in finally'}
if(-not$runnerText.Contains("foreach(`$name in @('formal-run-result.json','formal-run-result.json.tmp','formal-validation.json','formal-validation.json.tmp'))")){throw 'partial seal cleanup must be exact and closed'}

$guardOpenIndex=$runnerText.IndexOf('$inputGuard=Open-O01ValidatedInputGuard')
$packageInitialIndex=$runnerText.IndexOf('$packageBinding=Assert-O01PackageManifest')
$packageFinalIndex=$runnerText.IndexOf('$finalPackageBinding=Assert-O01PackageManifest')
$nodeHashIndex=$runnerText.IndexOf('$nodeHash=(Get-FileHash -LiteralPath $nodeSource -Algorithm SHA256)')
$nodeCopyIndex=$runnerText.IndexOf('[IO.File]::Copy($nodeSource,$node,$false)')
$nodePreflightIndex=$runnerText.IndexOf('Assert-O01IsolatedNodeRuntime $nodeIsolate $node $ExpectedNodeSha256 $nodeSourceBytes',$nodeCopyIndex)
$nodeVersionIndex=$runnerText.IndexOf('$versionProbe=Invoke-O01IsolatedNodeCapture')
if($nodeHashIndex-lt0-or$nodeCopyIndex-le$nodeHashIndex-or$nodePreflightIndex-le$nodeCopyIndex-or$nodeVersionIndex-le$nodePreflightIndex){throw 'runner must authenticate and isolate Node before executing it'}
$packageCopyIndex=$runnerText.IndexOf("'COPY_PACKAGE_FILES'")
$validatorLaunchIndex=$runnerText.IndexOf('$validationProbe=Invoke-O01IsolatedNodeCapture')
$validatorIndex=$runnerText.IndexOf('$validatedInputHashes=Get-O01InputGuardHashes')
$controllerSnapshotIndex=$runnerText.IndexOf('$controllerSnapshot=Read-O01InputGuardJson')
$postRollbackIndex=$runnerText.IndexOf('$postRollbackHashes=Get-O01InputGuardHashes')
$preSealIndex=$runnerText.IndexOf('$sealInputHashes=Get-O01InputGuardHashes')
$runWriteIndex=$runnerText.IndexOf('Write-O01ExclusiveJson -Path $runPath')
$runHashIndex=$runnerText.IndexOf('$runSealSha256=Get-O01RegularFileSha256 $runPath')
$validationWriteIndex=$runnerText.IndexOf('Write-O01ExclusiveJson -Path $validationPath')
$validationHashIndex=$runnerText.IndexOf('$validationSealSha256=Get-O01RegularFileSha256 $validationPath')
$finalGateIndex=$runnerText.IndexOf('$finalInputHashes=Get-O01ValidatedInputHashes')
$sealCompareIndex=$runnerText.IndexOf("`$finalInputHashes['formal-run-result.json']-cne`$runSealSha256")
$receiptIndex=$runnerText.IndexOf("`$launchReceipt=[ordered]@{schema='ese.v92.o01-formal-launch-receipt/v1'")
$closeGuardIndex=$runnerText.IndexOf('try{Close-O01ValidatedInputGuard $inputGuard}')
$receiptOutputIndex=$runnerText.IndexOf('$runOutput=[pscustomobject]$launchReceipt|ConvertTo-Json -Compress')
$partialCleanupIndex=$runnerText.LastIndexOf('Remove-O01PartialSeal $controllerRoot')
$projectionIndex=$runnerText.IndexOf('ConvertTo-O01FailureProjectionV3 $failure -EvidenceRoot $root')
if($packageInitialIndex-lt0-or$packageCopyIndex-le$packageInitialIndex-or$guardOpenIndex-lt0-or$validatorLaunchIndex-le$guardOpenIndex-or$validatorIndex-le$validatorLaunchIndex-or$controllerSnapshotIndex-le$validatorIndex-or$postRollbackIndex-le$controllerSnapshotIndex-or$packageFinalIndex-le$postRollbackIndex-or$preSealIndex-le$packageFinalIndex-or$runWriteIndex-le$preSealIndex-or$runHashIndex-le$runWriteIndex-or$validationWriteIndex-le$runHashIndex-or$validationHashIndex-le$validationWriteIndex-or$finalGateIndex-le$validationHashIndex-or$sealCompareIndex-le$finalGateIndex-or$receiptIndex-le$sealCompareIndex-or$closeGuardIndex-le$receiptIndex-or$receiptOutputIndex-le$closeGuardIndex-or$partialCleanupIndex-le$closeGuardIndex-or$projectionIndex-le$partialCleanupIndex){throw 'runner validation/seal/failure ordering invalid'}
if(-not$runnerText.Contains('[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read')-or-not$runnerText.Contains("try{Close-O01ValidatedInputGuard `$inputGuard}catch{if(`$null-eq`$failure){`$failure=`$_}else{")-or-not$runnerText.Contains('try{if($null-ne$hostProcess){$hostProcess.Dispose()}}catch{')-or-not$runnerText.Contains('$ownedTemporary=$true')-or-not$runnerText.Contains("`$controllerSnapshot.sha256-cne[string]`$validatedInputHashes['controller-result.json']")-or-not$runnerText.Contains('chain_tip_sha256=[string]$controllerResult.chain_tip_sha256')){throw 'persistent input guard/controller snapshot contract missing'}
if(-not$runnerText.Contains("`$artifactHashes['artifacts/v92-o01-formal/formal-run-result.json']=`$runSealSha256")){throw 'validation must bind the captured formal-run hash'}
foreach($receiptMarker in @('[Array]::Sort($evidenceNames,[StringComparer]::Ordinal)','artifacts=[object[]]$evidenceRows','evidence_set_sha256=$evidenceSetSha256','formal_run_sha256=$runSealSha256','formal_validation_sha256=$validationSealSha256','plan_sha256=$planSealSha256','state_sha256=$stateSealSha256','raw_streams_retained=$false')){if(-not$runnerText.Contains($receiptMarker)){throw "missing launch receipt marker: $receiptMarker"}}

$isolatedCalls=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]-and$node.GetCommandName()-ceq'Assert-O01IsolatedNodeRuntime'},$true))
$captureCalls=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]-and$node.GetCommandName()-ceq'Invoke-O01IsolatedNodeCapture'},$true))
$environmentCalls=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]-and$node.GetCommandName()-ceq'Set-O01IsolatedNodeEnvironment'},$true))
$checkoutCalls=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]-and$node.GetCommandName()-ceq'Assert-O01ClosedGitCheckout'},$true))
$launchBoundaryCalls=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]-and$node.GetCommandName()-ceq'Assert-O01PhysicalLaunchBoundary'},$true))
if($isolatedCalls.Count-ne3-or$captureCalls.Count-ne2-or$environmentCalls.Count-ne2-or$checkoutCalls.Count-ne2-or$launchBoundaryCalls.Count-ne1){throw 'isolated Node/source/launch-boundary call cardinality invalid'}
if($runnerText.Contains('&$nodeSource')-or$runnerText.Contains('FileName=$nodeSource')-or$runnerText.Contains('WorkingDirectory=$repo')-or$runnerText.Contains('$validation=@(&$node')){throw 'unisolated Node execution surface remains'}
$hostEnvironmentIndex=$runnerText.IndexOf('Set-O01IsolatedNodeEnvironment $pi $nodeIsolate $nodeScratch $repo')
$nodeCleanupIndex=$runnerText.IndexOf('[IO.File]::Delete($node)')
$sourceFinalIndex=$runnerText.LastIndexOf('Assert-O01ClosedGitCheckout $repo')
$finalDocumentIndex=$runnerText.IndexOf('$final=[ordered]@')
$launchBoundaryIndex=$runnerText.IndexOf('Assert-O01PhysicalLaunchBoundary $PSCommandPath $launchTail')
$firstOperationalIndex=$runnerText.IndexOf("`$ErrorActionPreference='Stop'")
if($hostEnvironmentIndex-lt0-or$nodeCleanupIndex-le$validatorLaunchIndex-or$sourceFinalIndex-le$nodeCleanupIndex-or$finalDocumentIndex-le$sourceFinalIndex-or$launchBoundaryIndex-lt0-or$firstOperationalIndex-le$launchBoundaryIndex-or-not$runnerText.Contains('[IO.Directory]::Delete($nodeIsolate,$false)')-or$runnerText.Contains('Remove-Item -LiteralPath $nodeIsolate -Recurse')){throw 'isolated Node cleanup/source recheck/launch-boundary ordering invalid'}

$helperSource="param([string]`$FixtureRoot,[string]`$RepoRoot)`n"+(@($definitions.Values)-join"`n")+@'

function Expect-SetFailure([scriptblock]$Action){
    try{&$Action;throw 'NEGATIVE_ACCEPTED'}catch{if([string]$_.Exception.Message-ceq'NEGATIVE_ACCEPTED'){throw};if([string]$_.Exception.Message-cne'O01_FORMAL_EVIDENCE_SET_INVALID'){throw}}
}
function Expect-PackageFailure([scriptblock]$Action){try{&$Action;throw 'PACKAGE_NEGATIVE_ACCEPTED'}catch{if([string]$_.Exception.Message-ceq'PACKAGE_NEGATIVE_ACCEPTED'){throw};if([string]$_.Exception.Message-cne'O01_FORMAL_PACKAGE_MANIFEST_INVALID'){throw}}}
function Expect-InventoryFailure([scriptblock]$Action){try{&$Action;throw 'INVENTORY_NEGATIVE_ACCEPTED'}catch{if([string]$_.Exception.Message-ceq'INVENTORY_NEGATIVE_ACCEPTED'){throw};if([string]$_.Exception.Message-cne'O01_GUEST_COPY_IDENTITY'){throw}}}
function Expect-LockFailure([scriptblock]$Action){try{&$Action;throw 'LOCK_BYPASS'}catch{if([string]$_.Exception.Message-ceq'LOCK_BYPASS'){throw}}}
function Expect-NodeIsolationFailure([scriptblock]$Action){try{&$Action;throw 'NODE_ISOLATION_NEGATIVE_ACCEPTED'}catch{if([string]$_.Exception.Message-ceq'NODE_ISOLATION_NEGATIVE_ACCEPTED'){throw};if([string]$_.Exception.Message-cne'O01_FORMAL_NODE_ISOLATION'){throw}}}
$runtime=Join-Path $FixtureRoot 'isolated-node';$scratch=Join-Path $FixtureRoot 'isolated-scratch';$null=New-Item -ItemType Directory -Path $runtime,$scratch;$isolatedNode=Join-Path $runtime 'node.exe';[IO.File]::WriteAllText($isolatedNode,'PINNED-NODE',[Text.UTF8Encoding]::new($false));$isolatedBytes=(Get-Item -LiteralPath $isolatedNode).Length;$isolatedHash=(Get-FileHash -LiteralPath $isolatedNode -Algorithm SHA256).Hash.ToLowerInvariant();Assert-O01IsolatedNodeRuntime $runtime $isolatedNode $isolatedHash $isolatedBytes
$environmentProbe=[Diagnostics.ProcessStartInfo]::new();$environmentProbe.FileName=$isolatedNode;$environmentProbe.UseShellExecute=$false;$null=$environmentProbe.EnvironmentVariables;$environmentProbe.EnvironmentVariables['NODE_OPTIONS']='--require hostile.js';$environmentProbe.EnvironmentVariables['NoDe_RePl_Hostile']='1';$environmentProbe.EnvironmentVariables['OPENSSL_CONF']='hostile.cnf';Set-O01IsolatedNodeEnvironment $environmentProbe $runtime $scratch $RepoRoot ([ordered]@{O01_TEST='PASS'});if($environmentProbe.EnvironmentVariables.ContainsKey('NODE_OPTIONS')-or$environmentProbe.EnvironmentVariables.ContainsKey('NoDe_RePl_Hostile')-or$environmentProbe.EnvironmentVariables.ContainsKey('OPENSSL_CONF')-or[string]$environmentProbe.EnvironmentVariables['O01_TEST']-cne'PASS'-or[string]$environmentProbe.EnvironmentVariables['TEMP']-cne$scratch){throw 'isolated Node child environment invalid'}
[IO.File]::WriteAllText((Join-Path $runtime 'extra.dll'),'EXTRA',[Text.UTF8Encoding]::new($false));Expect-NodeIsolationFailure {Assert-O01IsolatedNodeRuntime $runtime $isolatedNode $isolatedHash $isolatedBytes};[IO.File]::Delete((Join-Path $runtime 'extra.dll'))
$extraDirectory=Join-Path $runtime 'extra';$null=New-Item -ItemType Directory -Path $extraDirectory;Expect-NodeIsolationFailure {Assert-O01IsolatedNodeRuntime $runtime $isolatedNode $isolatedHash $isolatedBytes};[IO.Directory]::Delete($extraDirectory,$false)
Expect-NodeIsolationFailure {Assert-O01IsolatedNodeRuntime $runtime $isolatedNode ('0'*64) $isolatedBytes};Expect-NodeIsolationFailure {Assert-O01IsolatedNodeRuntime $runtime $isolatedNode $isolatedHash ($isolatedBytes+1)}
Set-Content -LiteralPath $isolatedNode -Stream hostile -Value 'ADS' -NoNewline -Encoding ASCII;Expect-NodeIsolationFailure {Assert-O01IsolatedNodeRuntime $runtime $isolatedNode $isolatedHash $isolatedBytes};Remove-Item -LiteralPath $isolatedNode -Stream hostile -Force
[IO.File]::Delete($isolatedNode);Expect-NodeIsolationFailure {Assert-O01IsolatedNodeRuntime $runtime $isolatedNode $isolatedHash $isolatedBytes};[IO.Directory]::Delete($runtime,$false);[IO.Directory]::Delete($scratch,$false)
$package=Join-Path $FixtureRoot 'package';$null=New-Item -ItemType Directory -Path (Join-Path $package 'config') -Force
[IO.File]::WriteAllText((Join-Path $package 'emule.exe'),'EXE',[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $package 'config\preferences.ini'),'PREFS',[Text.UTF8Encoding]::new($false))
$manifestLines=@();foreach($relative in @('config/preferences.ini','emule.exe')){$path=Join-Path $package ($relative.Replace('/',[IO.Path]::DirectorySeparatorChar));$manifestLines+=((Get-FileHash $path -Algorithm SHA256).Hash+'  '+$relative)};$manifestPath=Join-Path $package 'SHA256SUMS.txt';[IO.File]::WriteAllText($manifestPath,(($manifestLines-join"`n")+"`n"),[Text.UTF8Encoding]::new($false));$manifestHash=(Get-FileHash $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestText=[IO.File]::ReadAllText($manifestPath)
$packageRecord=Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $manifestHash;if([int]$packageRecord.manifest_entry_count-ne2-or[int]$packageRecord.package_file_count-ne3){throw 'package manifest counts invalid'}
$expectedInventory=@($packageRecord.entries);Assert-O01InventoryBindings -Expected $expectedInventory -Actual @($expectedInventory|ForEach-Object{[pscustomobject]@{path=$_.path;sha256=$_.sha256}})
Assert-O01DirectorySet -Expected @($packageRecord.directories) -Actual @('config')
Expect-InventoryFailure {Assert-O01DirectorySet -Expected @($packageRecord.directories) -Actual @()}
Expect-InventoryFailure {Assert-O01DirectorySet -Expected @($packageRecord.directories) -Actual @('config','extra')}
Expect-InventoryFailure {Assert-O01DirectorySet -Expected @($packageRecord.directories) -Actual @('../escape')}
Expect-InventoryFailure {Assert-O01InventoryBindings -Expected $expectedInventory -Actual @($expectedInventory|Select-Object -First 1)}
Expect-InventoryFailure {Assert-O01InventoryBindings -Expected $expectedInventory -Actual @($expectedInventory+([pscustomobject]@{path='extra.txt';sha256=('0'*64)}))}
$wrongInventory=@($expectedInventory|ForEach-Object{[pscustomobject]@{path=$_.path;sha256=$_.sha256}});$wrongInventory[0].sha256='0'*64;Expect-InventoryFailure {Assert-O01InventoryBindings -Expected $expectedInventory -Actual $wrongInventory}
Expect-InventoryFailure {Assert-O01InventoryBindings -Expected $expectedInventory -Actual @($expectedInventory+([pscustomobject]@{path=$expectedInventory[0].path;sha256=$expectedInventory[0].sha256}))}
Expect-InventoryFailure {Assert-O01InventoryBindings -Expected @([pscustomobject]@{path='../escape';sha256=('0'*64)}) -Actual @([pscustomobject]@{path='../escape';sha256=('0'*64)})}
Expect-PackageFailure {Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 ('0'*64)|Out-Null}
[IO.File]::AppendAllText((Join-Path $package 'emule.exe'),'MUTATED',[Text.UTF8Encoding]::new($false));Expect-PackageFailure {Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $manifestHash|Out-Null};[IO.File]::WriteAllText((Join-Path $package 'emule.exe'),'EXE',[Text.UTF8Encoding]::new($false))
[IO.File]::Delete((Join-Path $package 'config\preferences.ini'));Expect-PackageFailure {Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $manifestHash|Out-Null};[IO.File]::WriteAllText((Join-Path $package 'config\preferences.ini'),'PREFS',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $package 'extra.txt'),'EXTRA',[Text.UTF8Encoding]::new($false));Expect-PackageFailure {Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $manifestHash|Out-Null};Remove-Item -LiteralPath (Join-Path $package 'extra.txt') -Force
$emptyDirectory=Join-Path $package 'config\UNMANIFESTED_EMPTY';$null=New-Item -ItemType Directory -Path $emptyDirectory;Expect-PackageFailure {Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $manifestHash|Out-Null};Remove-Item -LiteralPath $emptyDirectory -Force
[IO.File]::WriteAllText($manifestPath,($manifestText+$manifestLines[0]+[Environment]::NewLine),[Text.UTF8Encoding]::new($false));$hostileManifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant();Expect-PackageFailure {Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $hostileManifestHash|Out-Null}
[IO.File]::WriteAllText($manifestPath,($manifestText+(('0'*64)+'  ../escape')+[Environment]::NewLine),[Text.UTF8Encoding]::new($false));$hostileManifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant();Expect-PackageFailure {Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $hostileManifestHash|Out-Null}
$bracketPath=Join-Path $package '[a].txt';$plainPath=Join-Path $package 'a.txt';[IO.File]::WriteAllText($bracketPath,'BRACKET',[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText($plainPath,'PLAIN',[Text.UTF8Encoding]::new($false));$wildManifest=$manifestText+((Get-FileHash -LiteralPath $bracketPath -Algorithm SHA256).Hash+'  [a].txt'+[Environment]::NewLine)+((Get-FileHash -LiteralPath $plainPath -Algorithm SHA256).Hash+'  a.txt'+[Environment]::NewLine);[IO.File]::WriteAllText($manifestPath,$wildManifest,[Text.UTF8Encoding]::new($false));$wildManifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant();$wildRecord=Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $wildManifestHash;if([int]$wildRecord.manifest_entry_count-ne4-or[int]$wildRecord.package_file_count-ne5){throw 'literal-path package manifest invalid'};Remove-Item -LiteralPath $bracketPath,$plainPath -Force
[IO.File]::WriteAllText($manifestPath,$manifestText,[Text.UTF8Encoding]::new($false))
$null=Assert-O01PackageManifest -PackageRoot $package -ExpectedManifestSha256 $manifestHash
$controller=Join-Path $FixtureRoot 'controller'
$null=New-Item -ItemType Directory -Path $controller
$configPath=Join-Path $controller 'host-config.json'
Write-O01ExclusiveJson -Path $configPath -Value ([ordered]@{schema='test-host-config'}) -Depth 2
Remove-O01HostConfig $configPath
if((Test-Path -LiteralPath $configPath)-or(Test-Path -LiteralPath ($configPath+'.tmp'))){throw 'owned host config survived cleanup'}
$foreignTemporary=$configPath+'.tmp';$foreignSentinel='FOREIGN_SENTINEL'
[IO.File]::WriteAllText($foreignTemporary,$foreignSentinel,[Text.UTF8Encoding]::new($false))
try{Write-O01ExclusiveJson -Path $configPath -Value ([ordered]@{schema='must-not-overwrite'}) -Depth 2;throw 'FOREIGN_TEMP_ACCEPTED'}catch{if([string]$_.Exception.Message-ceq'FOREIGN_TEMP_ACCEPTED'){throw};if([string]$_.Exception.Message-cne'O01_FAILURE_EVIDENCE_EXISTS'){throw}}
Expect-SetFailure {Remove-O01HostConfig $configPath}
if(-not(Test-Path -LiteralPath $foreignTemporary -PathType Leaf)-or[IO.File]::ReadAllText($foreignTemporary)-cne$foreignSentinel){throw 'foreign host config temporary was not preserved'}
Remove-Item -LiteralPath $foreignTemporary -Force
foreach($ordinal in 1..95){[IO.File]::WriteAllText((Join-Path $controller ('checkpoint-{0:D2}.json'-f$ordinal)),"checkpoint-$ordinal",[Text.UTF8Encoding]::new($false))}
$controllerResultPath=Join-Path $controller 'controller-result.json'
$controllerOriginal='{"chain_tip_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
[IO.File]::WriteAllText($controllerResultPath,$controllerOriginal,[Text.UTF8Encoding]::new($false))
$baseline=Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $false
if($baseline.Count-ne96){throw 'validated input capture count invalid'}
$controllerCapture=Read-O01RegularJsonSnapshot $controllerResultPath
if([string]$controllerCapture.sha256-cne[string]$baseline['controller-result.json']-or[string]$controllerCapture.value.chain_tip_sha256-cne'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'){throw 'controller-result snapshot binding invalid'}
[IO.File]::WriteAllText($controllerResultPath,'{"chain_tip_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}',[Text.UTF8Encoding]::new($false))
if((Get-O01RegularFileSha256 $controllerResultPath)-ceq[string]$controllerCapture.sha256){throw 'controller-result substitution undetected'}
[IO.File]::WriteAllText($controllerResultPath,$controllerOriginal,[Text.UTF8Encoding]::new($false))
$checkpoint=Join-Path $controller 'checkpoint-01.json'
[IO.File]::AppendAllText($checkpoint,'mutated',[Text.UTF8Encoding]::new($false))
$mutated=Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $false
Expect-SetFailure {Assert-O01InputHashesEqual $baseline $mutated}
[IO.File]::WriteAllText($checkpoint,'checkpoint-1',[Text.UTF8Encoding]::new($false))
$restored=Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $false
Assert-O01InputHashesEqual $baseline $restored

$guard=Open-O01ValidatedInputGuard -EvidenceRoot $FixtureRoot -ControllerRoot $controller
try{
    try{
        $guardHashes=Get-O01InputGuardHashes $guard
        Assert-O01InputHashesEqual $baseline $guardHashes
        $guardController=Read-O01InputGuardJson $guard 'controller-result.json'
        if([string]$guardController.sha256-cne[string]$baseline['controller-result.json']-or[string]$guardController.value.chain_tip_sha256-cne'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'){throw 'guard controller bytes invalid'}
        Expect-LockFailure {[IO.File]::WriteAllText($checkpoint,'writer-bypass',[Text.UTF8Encoding]::new($false))}
        Expect-LockFailure {[IO.File]::Move($checkpoint,($checkpoint+'.moved'))}
        Expect-LockFailure {Remove-Item -LiteralPath $checkpoint -Force -ErrorAction Stop}
        Expect-LockFailure {[IO.Directory]::Move($controller,($controller+'.replacement'))}
        $parallel=[IO.File]::Open($checkpoint,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try{$parallelSha=[Security.Cryptography.SHA256]::Create();try{$parallelHash=[BitConverter]::ToString($parallelSha.ComputeHash($parallel)).Replace('-','').ToLowerInvariant()}finally{$parallelSha.Dispose()}}finally{$parallel.Dispose()}
        if($parallelHash-cne[string]$baseline['checkpoint-01.json']){throw 'parallel validator did not see guarded bytes'}
        $nodeExe=(Get-Command node -ErrorAction Stop).Source;$nodeHash=@(&$nodeExe -e "const fs=require('node:fs');const crypto=require('node:crypto');process.stdout.write(crypto.createHash('sha256').update(fs.readFileSync(process.argv[1])).digest('hex'))" $checkpoint)
        if($LASTEXITCODE-ne0-or$nodeHash.Count-ne1-or[string]$nodeHash[0]-cne[string]$baseline['checkpoint-01.json']){throw 'Node validator could not read the guarded bytes'}
        throw 'SIMULATED_VALIDATOR_FAILURE'
    }finally{Close-O01ValidatedInputGuard $guard}
}catch{if([string]$_.Exception.Message-cne'SIMULATED_VALIDATOR_FAILURE'){throw}}
if(-not[bool]$guard.closed){throw 'input guard was not disposed on failure'}
[IO.File]::WriteAllText($checkpoint,'checkpoint-1',[Text.UTF8Encoding]::new($false))
if((Get-O01RegularFileSha256 $checkpoint)-cne[string]$baseline['checkpoint-01.json']){throw 'input guard did not release after failure'}

foreach($hostileName in @('rpc-failure.json','clock-failure.json','checkpoint-96.json','formal-run-result.json.tmp')){
    $hostilePath=Join-Path $controller $hostileName
    [IO.File]::WriteAllText($hostilePath,'hostile',[Text.UTF8Encoding]::new($false))
    Expect-SetFailure {Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $false|Out-Null}
    Remove-Item -LiteralPath $hostilePath -Force
}
[IO.File]::WriteAllText((Join-Path $FixtureRoot 'failure.json'),'hostile',[Text.UTF8Encoding]::new($false))
Expect-SetFailure {Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $false|Out-Null}
Remove-Item -LiteralPath (Join-Path $FixtureRoot 'failure.json') -Force

$runPath=Join-Path $controller 'formal-run-result.json'
$validationPath=Join-Path $controller 'formal-validation.json'
Write-O01ExclusiveJson -Path $runPath -Value ([ordered]@{schema='run';release_gate=$true}) -Depth 3
$runHash=Get-O01RegularFileSha256 $runPath
Write-O01ExclusiveJson -Path $validationPath -Value ([ordered]@{schema='validation';verdict='PASS'}) -Depth 3
$validationHash=Get-O01RegularFileSha256 $validationPath
$sealed=Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $true
Assert-O01InputHashesEqual $baseline $sealed
if($sealed.Count-ne98-or[string]$sealed['formal-run-result.json']-cne$runHash-or[string]$sealed['formal-validation.json']-cne$validationHash){throw 'sealed hash capture invalid'}

[IO.File]::AppendAllText($runPath,'substitution',[Text.UTF8Encoding]::new($false))
$substituted=Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $true
if([string]$substituted['formal-run-result.json']-ceq$runHash){throw 'formal-run substitution undetected'}
[IO.File]::WriteAllText($runPath,"{`"schema`":`"run`",`"release_gate`":true}`n",[Text.UTF8Encoding]::new($false))
[IO.File]::AppendAllText($validationPath,'substitution',[Text.UTF8Encoding]::new($false))
$substituted=Get-O01ValidatedInputHashes -EvidenceRoot $FixtureRoot -ControllerRoot $controller -Sealed $true
if([string]$substituted['formal-validation.json']-ceq$validationHash){throw 'formal-validation substitution undetected'}

[IO.File]::WriteAllText((Join-Path $controller 'formal-run-result.json.tmp'),'partial',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $controller 'formal-validation.json.tmp'),'partial',[Text.UTF8Encoding]::new($false))
Remove-O01PartialSeal $controller
foreach($name in @('formal-run-result.json','formal-run-result.json.tmp','formal-validation.json','formal-validation.json.tmp')){if(Test-Path -LiteralPath (Join-Path $controller $name)){throw 'partial seal survived cleanup'}}

Write-O01ExclusiveJson -Path $runPath -Value ([ordered]@{schema='run';release_gate=$true}) -Depth 3
Remove-O01PartialSeal $controller
if(Test-Path -LiteralPath $runPath){throw 'failure after run write left PASS carrier'}
Write-O01ExclusiveJson -Path $runPath -Value ([ordered]@{schema='run';release_gate=$true}) -Depth 3
Write-O01ExclusiveJson -Path $validationPath -Value ([ordered]@{schema='validation';verdict='PASS'}) -Depth 3
Remove-O01PartialSeal $controller
if((Test-Path -LiteralPath $runPath)-or(Test-Path -LiteralPath $validationPath)){throw 'failure after validation write left PASS carrier'}

foreach($finalizerKind in @('HOST_DISPOSE','INPUT_GUARD_CLOSE')){
    Write-O01ExclusiveJson -Path $runPath -Value ([ordered]@{schema='run';release_gate=$true}) -Depth 3
    Write-O01ExclusiveJson -Path $validationPath -Value ([ordered]@{schema='validation';verdict='PASS'}) -Depth 3
    $finalizerFailure=$null
    $throwing=[pscustomobject]@{};$throwing|Add-Member -MemberType ScriptMethod -Name Dispose -Value {throw 'INJECTED_FINALIZER_FAILURE'}
    if($finalizerKind-ceq'HOST_DISPOSE'){
        try{$throwing.Dispose()}catch{$finalizerFailure=$_}
    }else{
        $badGuard=[pscustomobject][ordered]@{entries=[object[]]@([pscustomobject]@{stream=$throwing});closed=$false}
        try{Close-O01ValidatedInputGuard $badGuard}catch{$finalizerFailure=$_}
        if(-not[bool]$badGuard.closed){throw 'throwing input guard was not marked closed'}
    }
    if($null-eq$finalizerFailure){throw "finalizer failure was not captured: $finalizerKind"}
    if((Get-O01FailureException $finalizerFailure)-isnot[Exception]){throw 'finalizer failure unwrap invalid'}
    Remove-O01PartialSeal $controller
    if((Test-Path -LiteralPath $runPath)-or(Test-Path -LiteralPath $validationPath)){throw "finalizer failure left PASS carriers: $finalizerKind"}
    $failurePath=Join-Path $FixtureRoot 'failure.json'
    Write-O01ExclusiveJson -Path $failurePath -Value ([ordered]@{schema='test-failure';finalizer=$finalizerKind}) -Depth 2
    if(@([IO.Directory]::EnumerateFiles($FixtureRoot,'failure.json')).Count-ne1){throw "finalizer failure publication cardinality invalid: $finalizerKind"}
    Remove-Item -LiteralPath $failurePath -Force
}
'@

$helperFixture=Join-Path ([IO.Path]::GetTempPath()) ('o01-runner-seal-'+[Guid]::NewGuid().ToString('N'))
try{
    $null=New-Item -ItemType Directory -Path $helperFixture
    & ([scriptblock]::Create($helperSource)) $helperFixture ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')))
}finally{if(Test-Path -LiteralPath $helperFixture){Remove-Item -LiteralPath $helperFixture -Recurse -Force}}

$boundaryRoot=Join-Path ([IO.Path]::GetTempPath()) ('o01-runner-boundary-'+[Guid]::NewGuid().ToString('N'))
$boundaryScript=$null;$boundaryLaunch=$null
try{
    $null=New-Item -ItemType Directory -Path $boundaryRoot
    $boundaryScript=Join-Path $boundaryRoot 'probe/tools/lab/boundary-probe.ps1';$null=New-Item -ItemType Directory -Path (Split-Path -Parent $boundaryScript)
    $boundaryText=@"
param([Parameter(Mandatory=`$true)][string]`$Token)
`$ErrorActionPreference='Stop'
$($definitions['Assert-O01PhysicalLaunchBoundary'])
`$tail=[string[]]@('-Token',`$Token)
Assert-O01PhysicalLaunchBoundary `$PSCommandPath `$tail
[Console]::WriteLine('BOUNDARY_PASS')
"@
    [IO.File]::WriteAllText($boundaryScript,$boundaryText,[Text.UTF8Encoding]::new($false))
    $pinnedPowerShell='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $boundaryLaunch=Join-Path $boundaryRoot 'launch';$null=New-Item -ItemType Directory -Path $boundaryLaunch
    function Invoke-BoundaryProbe([string]$Arguments){
        $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$pinnedPowerShell;$info.Arguments=$Arguments;$info.WorkingDirectory=$boundaryLaunch;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$null=$info.EnvironmentVariables;$info.EnvironmentVariables.Clear()
        $repoRoot=[IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $boundaryScript) '..\..'));$values=[ordered]@{SystemRoot='C:\Windows';WINDIR='C:\Windows';SystemDrive='C:';COMSPEC='C:\Windows\System32\cmd.exe';PATH='C:\Program Files\Git\cmd;C:\Program Files\Git\mingw64\bin;C:\Windows\System32;C:\Windows';PATHEXT='.COM;.EXE;.BAT;.CMD';PSModulePath='C:\Windows\System32\WindowsPowerShell\v1.0\Modules';TEMP=$boundaryLaunch;TMP=$boundaryLaunch;GIT_CONFIG_NOSYSTEM='1';GIT_CONFIG_GLOBAL='NUL';GIT_ATTR_NOSYSTEM='1';GIT_OPTIONAL_LOCKS='0';GIT_TERMINAL_PROMPT='0';GIT_NO_REPLACE_OBJECTS='1';GIT_CONFIG_COUNT='10';GIT_CONFIG_KEY_0='safe.directory';GIT_CONFIG_VALUE_0=$repoRoot;GIT_CONFIG_KEY_1='core.fsmonitor';GIT_CONFIG_VALUE_1='false';GIT_CONFIG_KEY_2='core.hooksPath';GIT_CONFIG_VALUE_2='NUL';GIT_CONFIG_KEY_3='core.excludesFile';GIT_CONFIG_VALUE_3='NUL';GIT_CONFIG_KEY_4='core.attributesFile';GIT_CONFIG_VALUE_4='NUL';GIT_CONFIG_KEY_5='core.worktree';GIT_CONFIG_VALUE_5=$repoRoot;GIT_CONFIG_KEY_6='core.bare';GIT_CONFIG_VALUE_6='false';GIT_CONFIG_KEY_7='core.ignoreStat';GIT_CONFIG_VALUE_7='false';GIT_CONFIG_KEY_8='extensions.worktreeConfig';GIT_CONFIG_VALUE_8='false';GIT_CONFIG_KEY_9='core.autocrlf';GIT_CONFIG_VALUE_9='true'};foreach($key in $values.Keys){$info.EnvironmentVariables[[string]$key]=[string]$values[$key]}
        $process=[Diagnostics.Process]::new();$process.StartInfo=$info;try{if(-not$process.Start()){throw 'boundary child start'};$stdout=$process.StandardOutput.ReadToEnd();$stderr=$process.StandardError.ReadToEnd();$process.WaitForExit();[pscustomobject]@{exit_code=[int]$process.ExitCode;stdout=$stdout;stderr=$stderr}}finally{$process.Dispose()}
    }
    $quotedBoundary='"'+$boundaryScript.Replace('"','\"')+'"'
    $boundaryProbe=Invoke-BoundaryProbe ("-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+$quotedBoundary+" -Token PASS")
    if($boundaryProbe.exit_code-ne0-or[string]$boundaryProbe.stdout-cne"BOUNDARY_PASS`r`n"-or[string]$boundaryProbe.stderr-cne''){throw 'physical launch boundary nominal failure'}
    $boundaryProbe=Invoke-BoundaryProbe ("-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File "+$quotedBoundary+" -Token PASS")
    if($boundaryProbe.exit_code-eq0){throw 'physical launch boundary accepted reordered flags'}
    $boundaryProbe=Invoke-BoundaryProbe ("-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+$quotedBoundary+" -Token PASS -Extra HOSTILE")
    if($boundaryProbe.exit_code-eq0){throw 'physical launch boundary accepted extra arguments'}
}finally{
    if($null-ne$boundaryScript-and(Test-Path -LiteralPath $boundaryScript)){Remove-Item -LiteralPath $boundaryScript -Force}
    if($null-ne$boundaryLaunch-and(Test-Path -LiteralPath $boundaryLaunch)){if(@([IO.Directory]::EnumerateFileSystemEntries($boundaryLaunch)).Count-ne0){throw 'boundary launch scratch not empty'};[IO.Directory]::Delete($boundaryLaunch,$false)}
    foreach($boundaryDirectory in @((Join-Path $boundaryRoot 'probe\tools\lab'),(Join-Path $boundaryRoot 'probe\tools'),(Join-Path $boundaryRoot 'probe'))){if(Test-Path -LiteralPath $boundaryDirectory){if(@([IO.Directory]::EnumerateFileSystemEntries($boundaryDirectory)).Count-ne0){throw 'boundary probe cleanup not empty'};[IO.Directory]::Delete($boundaryDirectory,$false)}}
    if(Test-Path -LiteralPath $boundaryRoot){[IO.Directory]::Delete($boundaryRoot,$false)}
}

$failureBranches=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.IfStatementAst]-and$node.Extent.Text.Contains('ConvertTo-O01FailureProjectionV3 $failure -EvidenceRoot $root')},$true))
if($failureBranches.Count-ne1){throw 'formal failure branch AST must be unique'}
$failureText=$failureBranches[0].Extent.Text
$cleanupInBranch=$failureText.IndexOf('Remove-O01PartialSeal $controllerRoot')
$projectionInBranch=$failureText.IndexOf('ConvertTo-O01FailureProjectionV3 $failure -EvidenceRoot $root')
$writeInBranch=$failureText.IndexOf('Write-O01ExclusiveJson -Path $failurePath')
$exitMarkInBranch=$failureText.IndexOf('$runExitCode=1')
$finalExitIndex=$runnerText.LastIndexOf('if($runExitCode-ne0){exit 1}')
if($cleanupInBranch-lt0-or$projectionInBranch-le$cleanupInBranch-or$writeInBranch-le$projectionInBranch-or$exitMarkInBranch-le$writeInBranch-or$finalExitIndex-le$projectionIndex){throw 'failure branch publication ordering invalid'}

$probeRoot=Join-Path ([IO.Path]::GetTempPath()) ('o01-runner-exit-'+[Guid]::NewGuid().ToString('N'))
$probeScript=$probeRoot+'.ps1'
try{
    $null=New-Item -ItemType Directory -Path $probeRoot
    $probeController=Join-Path $probeRoot 'controller';$null=New-Item -ItemType Directory -Path $probeController
    [IO.File]::WriteAllText((Join-Path $probeController 'formal-run-result.json'),'{"release_gate":true}',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $probeController 'formal-validation.json'),'{"verdict":"PASS"}',[Text.UTF8Encoding]::new($false))
    $quotedRoot="'"+$probeRoot.Replace("'","''")+"'"
    $quotedController="'"+$probeController.Replace("'","''")+"'"
    $probePrelude=@"
`$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
`$root=$quotedRoot
`$controllerRoot=$quotedController
`$failure=[Exception]::new('O01_FORMAL_EVIDENCE_SET_INVALID')
`$runExitCode=0
function ConvertTo-O01FailureProjectionV3{param(`$Value,[Parameter(Mandatory=`$true)][string]`$EvidenceRoot);if(`$EvidenceRoot-cne`$root){throw 'EVIDENCE_ROOT_MISMATCH'};[ordered]@{schema='ese.v92.o01-formal-failure/v3';verdict='FAIL';release_gate=`$false;primary_failure='O01_FORMAL_EVIDENCE_SET_INVALID';failure_codes=@('O01_FORMAL_EVIDENCE_SET_INVALID');rollback_failures=@();error_types=@('OTHER');rpc_failure_sha256=`$null;product_cycle_observation=`$null;records_examined=1}}
"@
    $probeFunctions=@($definitions['AssertNoReparse'],$definitions['Write-O01ExclusiveJson'],$definitions['Remove-O01PartialSeal'])-join"`n"
    [IO.File]::WriteAllText($probeScript,$probePrelude+$probeFunctions+"`n"+$failureText+"`nif(`$runExitCode-ne0){exit 1};exit 0",[Text.UTF8Encoding]::new($false))
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $probeScript 2>$null
    if($LASTEXITCODE-ne1-or-not(Test-Path -LiteralPath (Join-Path $probeRoot 'failure.json') -PathType Leaf)){throw 'failure process contract did not publish then exit 1'}
    foreach($name in @('formal-run-result.json','formal-validation.json')){if(Test-Path -LiteralPath (Join-Path $probeController $name)){throw 'failure process left a PASS carrier'}}
}finally{
    if(Test-Path -LiteralPath $probeScript){Remove-Item -LiteralPath $probeScript -Force}
    if(Test-Path -LiteralPath $probeRoot){Remove-Item -LiteralPath $probeRoot -Recurse -Force}
}

foreach($assignment in $runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.AssignmentStatementAst]},$true)){
    if($assignment.Left-is[Management.Automation.Language.VariableExpressionAst]-and$assignment.Left.VariablePath.UserPath-ieq'host'){throw 'runner assigns automatic Host'}
    if($assignment.Left-is[Management.Automation.Language.VariableExpressionAst]-and$assignment.Left.VariablePath.UserPath-ieq'pid'){throw 'runner assigns automatic PID'}
}
foreach($parameter in $runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.ParameterAst]},$true)){if($parameter.Name.VariablePath.UserPath-ieq'pid'){throw 'runner declares automatic PID'}}

$guestFunctions=@($runnerAst.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq'Read-O01GuestSharedJsonlSnapshot'},$true))
if($guestFunctions.Count-ne1-or-not$guestFunctions[0].Extent.Text.Contains('[IO.FileShare]::ReadWrite')-or-not$guestFunctions[0].Extent.Text.Contains('33554432')-or-not$guestFunctions[0].Extent.Text.Contains('$complete=$parts.Length-1')){throw 'bounded guest JSONL reader contract missing'}
$guestReader=[scriptblock]::Create($guestFunctions[0].Extent.Text+'; Read-O01GuestSharedJsonlSnapshot $args[0]')
$snapshotPath=Join-Path ([IO.Path]::GetTempPath()) ('o01-runner-shared-'+[Guid]::NewGuid().ToString('N')+'.tmp')
try{
    [IO.File]::WriteAllText($snapshotPath,"line1`r`nline2`npartial",[Text.UTF8Encoding]::new($false))
    $snapshot=@(&$guestReader $snapshotPath)
    if($snapshot.Count-ne2-or$snapshot[0]-cne'line1'-or$snapshot[1]-cne'line2'){throw 'guest reader partial handling invalid'}
    [IO.File]::AppendAllText($snapshotPath,"`r`n",[Text.UTF8Encoding]::new($false))
    $snapshot=@(&$guestReader $snapshotPath)
    if($snapshot.Count-ne3-or$snapshot[2]-cne'partial'){throw 'guest reader completion invalid'}
}finally{if(Test-Path -LiteralPath $snapshotPath){Remove-Item -LiteralPath $snapshotPath -Force}}

$failureDetect=$runnerText.IndexOf('Get-O01ProductCycleFailure -Line ([string]$row.line) -ExpectedSequence $seq')
$failureThrow=$runnerText.IndexOf("`$cycleError.Data['product_cycle_observation']=`$cycleFailure.observation",$failureDetect)
$cursorAdvance=$runnerText.IndexOf('$cursorState.value++',$failureDetect)
if($failureDetect-lt0-or$failureThrow-le$failureDetect-or$cursorAdvance-le$failureThrow){throw 'cycle failure must precede cursor advance'}
$hostReady=$runnerText.IndexOf('$hostProcess.Start()')
$productLaunch=$runnerText.IndexOf('$productState.pid=&$startProduct')
$controllerText=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'nat_gateway\v92_o01_formal_controller.js'))
if($hostReady-lt0-or$productLaunch-le$hostReady-or$controllerText.IndexOf('await child.start()')-gt$controllerText.IndexOf('bounded(readProduct()')){throw 'gateway READY must precede product launch'}
if([regex]::Matches($runnerText,'Credential').Count-lt4-or$runnerText-match'(?i)ConvertFrom-SecureString|NetworkCredential|password'){throw 'credential boundary weakened'}

foreach($marker in @('controller-tick-2880.release','[IO.FileMode]::CreateNew','$file.Flush($true)','-AfterProductRead $releaseProduct','$sequence-ne481')){if(-not$runnerText.Contains($marker)){throw "missing release marker: $marker"}}
if([regex]::Matches($runnerText,'Invoke-O01BoundedGuestCommand -Session').Count-ne3-or-not$runnerText.Contains('Wait-Job -Job $job -Timeout $TimeoutSeconds')-or-not$runnerText.Contains("throw 'O01_PRODUCT_READ_REMOTE_TIMEOUT'")){throw 'formal guest commands must remain bounded'}
foreach($remoteCode in @('O01_PRODUCT_READ_REMOTE_INVOKE','O01_PRODUCT_READ_REMOTE_FAILED','O01_PRODUCT_READ_REMOTE_STOPPED','O01_PRODUCT_READ_REMOTE_DISCONNECTED','O01_PRODUCT_READ_REMOTE_RECEIVE','O01_PRODUCT_READ_REMOTE_TIMEOUT')){if(-not$runnerText.Contains("throw '$remoteCode'")-or-not$moduleText.Contains("'$remoteCode'")){throw "missing closed remote state: $remoteCode"}}

& (Join-Path $PSScriptRoot 'test_v92_o01_vm_session_mock.ps1')|Out-Null
& (Join-Path $PSScriptRoot 'test_v92_o01_formal_rpc_pump_mock.ps1')|Out-Null

[pscustomobject]@{
    schema='ese.v92.o01-formal-runner-mock/v2'
    verdict='PASS'
    hyperv_executed=$false
    release_gate_emitted=$false
    rollback_mock=$true
    rpc_mock=$true
    validated_inputs=96
    sealed_artifacts=98
    partial_pass_carriers_removed=$true
}|ConvertTo-Json -Compress
