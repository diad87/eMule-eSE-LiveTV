[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [string]$NodePath = 'C:\tmp\node-v22.23.2-win-x64\node.exe',
    [string]$VMName = 'v92-o01-client',
    [string]$CredentialPath = 'C:\tmp\v92-o01-vm\guest-credential.clixml',
    [string]$PackageRoot = 'C:\tmp\eSE-w12-r-package-a2prime',
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedExeSha256 = '71616c54e3866e23b0b5c8b48e8e4ae3955ca4c5d3039a6b69fd78a3851d5dc1',
    [switch]$DiagnosticDirtyCandidate,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSourceSnapshotSha256,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedBuildInfoSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'O01 VM/T8 smoke requires an elevated PowerShell session'
}

$root = [IO.Path]::GetFullPath($EvidenceRoot)
if ((Split-Path -Leaf $root) -notmatch '^eSE-v9\.2-o01-vm-smoke-[0-9a-f]{12}$' -or
    (Test-Path -LiteralPath $root)) {
    throw 'EvidenceRoot must be a new eSE-v9.2-o01-vm-smoke-<12 hex> directory'
}
trap {
    if(Test-Path -LiteralPath $root -PathType Container){
        $causes=@();if($_.Exception -is [AggregateException]){$causes=@($_.Exception.InnerExceptions|ForEach-Object{[string]$_.Message})}elseif($null -ne $_.Exception.InnerException){$causes=@([string]$_.Exception.InnerException.Message)}
        $record=[ordered]@{schema='ese.v92.o01-vm-smoke-failure/v1';error_type=$_.Exception.GetType().FullName;message=[string]$_.Exception.Message;causes=$causes;line=[int]$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $root 'failure.json'),$record,[Text.UTF8Encoding]::new($false))
    }
    exit 1
}
$node = (Get-Command $NodePath -ErrorAction Stop).Source
$nodeVersion = (& $node --version).Trim()
if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v22\.') {
    throw 'O01 VM/T8 smoke requires Node 22.x'
}
$credentialFile = [IO.Path]::GetFullPath($CredentialPath)
if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) {
    throw 'O01 guest credential is unavailable'
}
$credential = Import-Clixml -LiteralPath $credentialFile
$vm = Get-VM -Name $VMName -ErrorAction Stop
if ([string]$vm.State -ne 'Off') { throw 'O01 client VM must be Off before smoke' }
$vmAdapters = @(Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop)
if ($vmAdapters.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$vmAdapters[0].SwitchName)) {
    throw 'O01 client VM must have exactly one attached NIC'
}
$originalSwitch = [string]$vmAdapters[0].SwitchName
$originalVmId = ([string]$vm.VMId).ToLowerInvariant()
$originalAdapterId = [string]$vmAdapters[0].Id
$originalAdapterMac = [string]$vmAdapters[0].MacAddress
$originalCheckpointType = [string]$vm.CheckpointType
if($originalCheckpointType -cne 'Disabled' -or @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop).Count -ne 0){throw 'O01 VM must start with checkpoints disabled and none present'}
$vmDisks=@(Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop)
if($vmDisks.Count -ne 1){throw 'O01 VM must have exactly one system disk'}
$originalVhd=[IO.Path]::GetFullPath([string]$vmDisks[0].Path)
if(-not (Test-Path -LiteralPath $originalVhd -PathType Leaf) -or (Get-Item -LiteralPath $originalVhd -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'O01 VM base VHD is unavailable or reparse-backed'}
$originalDiskControllerNumber=[int]$vmDisks[0].ControllerNumber;$originalDiskControllerLocation=[int]$vmDisks[0].ControllerLocation
$orchestrator = Join-Path $PSScriptRoot 't8_hyperv.ps1'
$holdScript = Join-Path $PSScriptRoot 'nat_gateway\v92_o01_t8_formal_hold.js'
if (-not (Test-Path -LiteralPath $holdScript -PathType Leaf)) { throw 'O01 formal hold script missing' }
$package=[IO.Path]::GetFullPath($PackageRoot)
$packageExe=Join-Path $package 'emule.exe';$buildInfo=Join-Path $package 'BUILD_INFO.txt'
if(-not (Test-Path -LiteralPath $packageExe -PathType Leaf) -or -not (Test-Path -LiteralPath $buildInfo -PathType Leaf) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $packageExe).Hash.ToLowerInvariant() -cne $ExpectedExeSha256){throw 'O01 product package identity invalid'}
$buildText=Get-Content -LiteralPath $buildInfo -Raw
if($DiagnosticDirtyCandidate){
    if([string]::IsNullOrEmpty($ExpectedSourceSnapshotSha256) -or [string]::IsNullOrEmpty($ExpectedBuildInfoSha256)){throw 'O01 diagnostic source and manifest bindings are required'}
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $buildInfo).Hash.ToLowerInvariant() -cne $ExpectedBuildInfoSha256 -or
       [regex]::Matches($buildText,'(?m)^base_commit: ').Count -ne 1 -or
       [regex]::Matches($buildText,'(?m)^dirty: ').Count -ne 1 -or
       [regex]::Matches($buildText,'(?m)^release_gate: ').Count -ne 1 -or
       [regex]::Matches($buildText,'(?m)^source_snapshot_sha256: ').Count -ne 1 -or
       [regex]::Matches($buildText,'(?m)^commit: ').Count -ne 0 -or
       $buildText -notmatch '(?m)^base_commit: 228190eac75454d083d6afef931a540ff3ff014a\s*$' -or
       $buildText -notmatch '(?m)^dirty: true\s*$' -or
       $buildText -notmatch ('(?m)^source_snapshot_sha256: '+[regex]::Escape($ExpectedSourceSnapshotSha256)+'\s*$') -or
       $buildText -notmatch '(?m)^release_gate: false\s*$'){
        throw 'O01 diagnostic BUILD_INFO binding invalid'
    }
} elseif([regex]::Matches($buildText,'(?m)^commit: ').Count -ne 1 -or
         [regex]::Matches($buildText,'(?m)^dirty: ').Count -ne 1 -or
         [regex]::Matches($buildText,'(?m)^base_commit: ').Count -ne 0 -or
         [regex]::Matches($buildText,'(?m)^source_snapshot_sha256: ').Count -ne 0 -or
         [regex]::Matches($buildText,'(?m)^release_gate: ').Count -ne 0 -or
         $buildText -notmatch '(?m)^commit: 6247075338787343872952896d25cf2e330be8ff\s*$' -or $buildText -notmatch '(?m)^dirty: false\s*$'){
    throw 'O01 product BUILD_INFO is not bound to A2-prime'
}

function Get-TextSha256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-', '').ToLowerInvariant()) }
    finally { $sha.Dispose() }
}
function Get-ProtectedEmuleInventory {
    $rows = @(Get-CimInstance Win32_Process -Filter "Name='emule.exe'" -ErrorAction Stop)
    $result = @()
    foreach($row in $rows){
        if([string]::IsNullOrWhiteSpace([string]$row.ExecutablePath) -or -not (Test-Path -LiteralPath $row.ExecutablePath -PathType Leaf)){throw 'Protected eMule identity is not inspectable'}
        $canonical=[IO.Path]::GetFullPath([string]$row.ExecutablePath)
        $created=([DateTime]$row.CreationDate).ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
        $result += [pscustomobject][ordered]@{pid=[int]$row.ProcessId;canonical_path=$canonical;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $canonical).Hash.ToLowerInvariant();creation_time_utc=$created;session_id=[int]$row.SessionId}
    }
    return @($result|Sort-Object pid)
}
function Compare-ProtectedEmuleInventory($Before,$After){
    [object[]]$beforeArray=@($Before);[object[]]$afterArray=@($After)
    if($beforeArray.Count -ne $afterArray.Count){return $false}
    for($i=0;$i -lt $beforeArray.Count;$i++){
        $a=$beforeArray[$i];$b=$afterArray[$i]
        if($a.pid -ne $b.pid -or $a.session_id -ne $b.session_id -or $a.sha256 -cne $b.sha256 -or $a.creation_time_utc -cne $b.creation_time_utc -or -not [string]::Equals($a.canonical_path,$b.canonical_path,[StringComparison]::OrdinalIgnoreCase)){return $false}
    }
    return $true
}
function Wait-File([string]$Path, [Diagnostics.Process]$Process, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
        if ($Process.HasExited) {
            $detail = if (Test-Path -LiteralPath (Join-Path $root 'daemon.stderr.txt')) { Get-Content -LiteralPath (Join-Path $root 'daemon.stderr.txt') -Raw } else { '' }
            throw "O01 formal daemon exited before readiness: $detail"
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'O01 formal daemon readiness timeout'
}
function Wait-PowerShellDirect([int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try {
            $value = Invoke-Command -VMName $VMName -Credential $credential -ScriptBlock { 'READY' } -ErrorAction Stop
            if (($value | Select-Object -First 1) -eq 'READY') { return }
        } catch { Start-Sleep -Seconds 2 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'O01 guest PowerShell Direct readiness timeout'
}
function Wait-HostPreferredAddress([int]$InterfaceIndex,[string]$Address,[int]$Seconds=30){
    $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    do{$items=@(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -IPAddress $Address -ErrorAction SilentlyContinue);if($items.Count -eq 1 -and [string]$items[0].AddressState -ceq 'Preferred'){return};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow -lt $deadline)
    throw 'O01 T8 gateway address did not become Preferred'
}
function Assert-ExactFields([object]$Value,[string[]]$Expected,[string]$Label){
    $actual=@($Value.PSObject.Properties.Name|Sort-Object)
    $wanted=@($Expected|Sort-Object)
    if(($actual -join ',') -cne ($wanted -join ',')){throw "$Label has an unexpected schema"}
}
function Assert-JsonTrue([object]$Value,[string]$Label){if($Value -isnot [bool] -or $Value -cne $true){throw "$Label is not JSON true"}}
function Assert-JsonUInt([object]$Value,[string]$Label){if(($Value -isnot [int] -and $Value -isnot [long]) -or [int64]$Value -lt 0){throw "$Label is not a JSON unsigned integer"}}
function Write-CompleteMarker([string]$SessionDigest){
    if($SessionDigest -notmatch '^[a-f0-9]{64}$'){throw 'O01 daemon session digest invalid'}
    $body=[ordered]@{schema='ese.v92.o01-t8-formal-complete/v1';session_id_digest=$SessionDigest}|ConvertTo-Json -Compress
    [IO.File]::WriteAllText($completePath,$body,[Text.UTF8Encoding]::new($false))
}
function Get-ExactFirewallRules([string]$Name){
    return @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name})
}
function Get-ExactPersistentFirewallRules([string]$Name){
    return @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object{[string]$_.Name -ceq $Name})
}
function Assert-OneFirewallValue([object]$Value,[string]$Expected,[string]$Label){
    $items=@($Value|ForEach-Object{[string]$_})
    if($items.Count -ne 1 -or -not [string]::Equals($items[0],$Expected,[StringComparison]::OrdinalIgnoreCase)){throw "$Label is not exact"}
}
function Assert-OwnedFirewallRule([object]$Spec,[string]$Program,[string]$LocalAddress,[string]$RemoteAddress,[string]$InterfaceAlias){
    $rules=@(Get-ExactFirewallRules $Spec.name)
    if($rules.Count -ne 1){throw 'O01 owned firewall rule cardinality is not one'}
    $rule=$rules[0]
    if([string]$rule.Name -cne [string]$Spec.name -or [string]$rule.DisplayName -cne [string]$Spec.name -or [string]$rule.Direction -cne 'Inbound' -or [string]$rule.Action -cne 'Allow' -or [string]$rule.Enabled -cne 'True' -or [string]$rule.Profile -cne 'Any'){throw 'O01 owned firewall rule policy is not exact'}
    $apps=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $addresses=@(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $ports=@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $interfaces=@(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    if($apps.Count -ne 1 -or $addresses.Count -ne 1 -or $ports.Count -ne 1 -or $interfaces.Count -ne 1){throw 'O01 owned firewall filter cardinality is not exact'}
    if(-not [string]::Equals([IO.Path]::GetFullPath([string]$apps[0].Program),[IO.Path]::GetFullPath($Program),[StringComparison]::OrdinalIgnoreCase)){throw 'O01 owned firewall program is not exact'}
    Assert-OneFirewallValue $addresses[0].LocalAddress $LocalAddress 'O01 firewall local address'
    Assert-OneFirewallValue $addresses[0].RemoteAddress $RemoteAddress 'O01 firewall remote address'
    Assert-OneFirewallValue $interfaces[0].InterfaceAlias $InterfaceAlias 'O01 firewall interface'
    Assert-OneFirewallValue $ports[0].LocalPort ([string]$Spec.port) 'O01 firewall local port'
    Assert-OneFirewallValue $ports[0].RemotePort 'Any' 'O01 firewall remote port'
    $actualProtocol=[string]$ports[0].Protocol
    $expectedNumber=if([string]$Spec.protocol -ceq 'UDP'){'17'}else{'6'}
    if($actualProtocol -cne [string]$Spec.protocol -and $actualProtocol -cne $expectedNumber){throw 'O01 firewall protocol is not exact'}
}

$null = New-Item -ItemType Directory -Path $root
$planPath = Join-Path $root 'plan.json'
$statePath = Join-Path $root 'state.json'
$readyPath = Join-Path $root 'daemon-ready.json'
$completePath = Join-Path $root 'daemon-complete.json'
$daemonResultPath = Join-Path $root 'daemon-result.json'
$guestResultPath = Join-Path $root 'guest-wire-result.json'
$resultPath = Join-Path $root 'smoke-result.json'
$protectedBefore = Get-ProtectedEmuleInventory
$plan = $null; $planHash = $null; $state = $null; $daemon = $null
$t8Applied = $false; $vmStarted = $false; $failure = $null
$forcedCleanup = $false;$differencingCreated=$false;$differencingAttached=$false
$ready=$null;$guestResult=$null;$daemonResult=$null
$guestSession=$null;$productResult=$null
$differencingVhd=Join-Path $root 'guest-run.vhdx'
$firewallRulePrefix=('ese-v92-o01-{0}' -f (Split-Path -Leaf $root))
$firewallRuleNames=@(
    "$firewallRulePrefix-udp5351",
    "$firewallRulePrefix-udp1900",
    "$firewallRulePrefix-tcp54321"
)
$firewallRulesCreated=$false
$firewallSpecs=@(
    [pscustomobject]@{name=$firewallRuleNames[0];protocol='UDP';port=5351;local_address='gateway'},
    [pscustomobject]@{name=$firewallRuleNames[1];protocol='UDP';port=1900;local_address='239.255.255.250'},
    [pscustomobject]@{name=$firewallRuleNames[2];protocol='TCP';port=54321;local_address='gateway'}
)
foreach($ruleName in $firewallRuleNames){
    if(@(Get-ExactFirewallRules $ruleName).Count -ne 0 -or @(Get-ExactPersistentFirewallRules $ruleName).Count -ne 0){throw 'O01 owned firewall rule name already exists'}
}

try {
    $null=New-VHD -Path $differencingVhd -ParentPath $originalVhd -Differencing -ErrorAction Stop
    $differencingCreated=$true
    Set-VMHardDiskDrive -VMHardDiskDrive $vmDisks[0] -Path $differencingVhd -ErrorAction Stop
    $attached=@(Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop)
    if($attached.Count -ne 1 -or [IO.Path]::GetFullPath([string]$attached[0].Path) -cne [IO.Path]::GetFullPath($differencingVhd)){throw 'O01 differencing VHD attachment failed'}
    $differencingAttached=$true
    $planText = @(& $orchestrator -RunLabel 'v92-o01-vm' -PlanPath $planPath) -join [Environment]::NewLine
    $planResult = $planText | ConvertFrom-Json
    if ([string]$planResult.verdict -ne 'PASS') { throw 'O01 T8 plan did not PASS' }
    $planHash = [string]$planResult.plan_hash
    $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
    $applyText = @(& $orchestrator -Apply -ExistingPlanPath $planPath -ExpectedPlanHash $planHash -StatePath $statePath) -join [Environment]::NewLine
    $applyResult = $applyText | ConvertFrom-Json
    if ([string]$applyResult.verdict -ne 'PASS') { throw 'O01 T8 apply did not PASS' }
    $t8Applied = $true
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $parts = ([string]$plan.resources.gateway_address).Split('.')
    $clientAddress = '{0}.{1}.{2}.2' -f $parts[0],$parts[1],$parts[2]
    $gatewayAddress = [string]$plan.resources.gateway_address
    $prefixLength = [int]$plan.resources.prefix_length
    $fixtureAdapter = Get-NetAdapter -InterfaceIndex ([int]$state.resources.interface_index) -ErrorAction Stop
    $fixtureSwitch = Get-VMSwitch -Name ([string]$plan.resources.switch_name) -ErrorAction Stop
    Wait-HostPreferredAddress -InterfaceIndex ([int]$state.resources.interface_index) -Address $gatewayAddress
    $interfaceDigest = Get-TextSha256 ('{0}|{1}|{2}' -f ([string]$fixtureAdapter.InterfaceGuid).ToLowerInvariant(),$fixtureAdapter.InterfaceIndex,$gatewayAddress)
    $switchDigest = Get-TextSha256 ('{0}|{1}|{2}' -f ([string]$fixtureSwitch.Id).ToLowerInvariant(),$fixtureSwitch.Name,$fixtureSwitch.SwitchType)

    Connect-VMNetworkAdapter -VMName $VMName -SwitchName ([string]$plan.resources.switch_name) -ErrorAction Stop

    foreach($spec in $firewallSpecs){
        $specLocalAddress=if([string]$spec.local_address -ceq 'gateway'){$gatewayAddress}else{[string]$spec.local_address}
        $created=New-NetFirewallRule -PolicyStore PersistentStore -Name $spec.name -DisplayName $spec.name -Direction Inbound -Action Allow -Enabled True -Profile Any `
            -Program $node -Protocol $spec.protocol -LocalPort $spec.port -RemotePort Any -LocalAddress $specLocalAddress -RemoteAddress $clientAddress `
            -InterfaceAlias ([string]$fixtureAdapter.Name) -ErrorAction Stop
        if($null -eq $created -or [string]$created.Name -cne [string]$spec.name){throw 'O01 owned firewall rule creation was not accredited'}
        Assert-OwnedFirewallRule $spec $node $specLocalAddress $clientAddress ([string]$fixtureAdapter.Name)
    }
    $firewallRulesCreated=$true

    $savedEnvironment = @{}
    $daemonEnvironment = [ordered]@{
        O01_T8_BIND_ADDRESS = $gatewayAddress
        O01_T8_ALLOWED_SOURCE = $clientAddress
        O01_T8_INTERFACE_SHA256 = $interfaceDigest
        O01_T8_SWITCH_SHA256 = $switchDigest
        O01_T8_HTTP_PORT = '54321'
        O01_T8_EXTERNAL_ADDRESS = '88.11.22.4'
        O01_READY_PATH = $readyPath
        O01_COMPLETE_PATH = $completePath
        O01_RESULT_PATH = $daemonResultPath
    }
    foreach ($entry in $daemonEnvironment.GetEnumerator()) {
        $savedEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
    }
    try {
        $daemon = Start-Process -FilePath $node -ArgumentList @($holdScript) -WorkingDirectory (Split-Path -Parent $PSScriptRoot) -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $root 'daemon.stdout.txt') -RedirectStandardError (Join-Path $root 'daemon.stderr.txt')
    } finally {
        foreach ($entry in $daemonEnvironment.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key, $savedEnvironment[$entry.Key], 'Process') }
    }
    Wait-File -Path $readyPath -Process $daemon -Seconds 60
    $ready=Get-Content -LiteralPath $readyPath -Raw|ConvertFrom-Json
    Assert-ExactFields $ready @('schema','state','session_id_digest','gateway_generation','foreign_fixture_present') 'O01 daemon ready'
    Assert-JsonUInt $ready.gateway_generation 'O01 ready generation';Assert-JsonTrue $ready.foreign_fixture_present 'O01 ready foreign fixture'
    if([string]$ready.schema -cne 'ese.v92.o01-t8-formal-ready/v1' -or [string]$ready.state -cne 'authenticated' -or [string]$ready.session_id_digest -cnotmatch '^[a-f0-9]{64}$'){throw 'O01 daemon ready evidence invalid'}

    Start-VM -Name $VMName -ErrorAction Stop | Out-Null
    $vmStarted = $true
    Wait-PowerShellDirect -Seconds 240
    $guestText = Invoke-Command -VMName $VMName -Credential $credential -ArgumentList $clientAddress,$gatewayAddress,$prefixLength -ScriptBlock {
        param($ClientAddress,$GatewayAddress,$PrefixLength)
        $ErrorActionPreference='Stop'
        $adapters=@(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
        if($adapters.Count -ne 1){throw 'GUEST_NIC_COUNT'}
        $nic=$adapters[0]
        Get-NetRoute -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
        Disable-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Out-Null
        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $ClientAddress -PrefixLength $PrefixLength -DefaultGateway $GatewayAddress -AddressFamily IPv4 -ErrorAction Stop | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses @('127.0.0.1') -ErrorAction Stop
        $addressDeadline=[DateTime]::UtcNow.AddSeconds(30)
        do{$guestAddresses=@(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -IPAddress $ClientAddress -ErrorAction SilentlyContinue);if($guestAddresses.Count -eq 1 -and [string]$guestAddresses[0].AddressState -ceq 'Preferred'){break};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow -lt $addressDeadline)
        if($guestAddresses.Count -ne 1 -or [string]$guestAddresses[0].AddressState -cne 'Preferred'){throw 'GUEST_ADDRESS_NOT_PREFERRED'}
        $defaults=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
        if($defaults.Count -ne 1 -or [string]$defaults[0].NextHop -cne $GatewayAddress -or [int]$defaults[0].InterfaceIndex -ne [int]$nic.ifIndex){throw 'GUEST_ROUTE_INVALID'}
        function Invoke-Udp([byte[]]$Bytes,[string]$Destination,[int]$Port,[string]$Label){
            $client=[Net.Sockets.UdpClient]::new((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($ClientAddress),0)))
            try{$client.Client.ReceiveTimeout=5000;$null=$client.Send($Bytes,$Bytes.Length,$Destination,$Port);$remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0);$reply=$client.Receive([ref]$remote);return [pscustomobject]@{bytes=$reply;remote_address=$remote.Address.ToString();remote_port=[int]$remote.Port}}catch{throw "WIRE_${Label}_FAILED: $($_.Exception.GetType().FullName)"}finally{$client.Dispose()}
        }
        $natResult=Invoke-Udp -Bytes ([byte[]](0,0)) -Destination $GatewayAddress -Port 5351 -Label 'NATPMP'
        if([string]$natResult.remote_address -cne $GatewayAddress -or [int]$natResult.remote_port -ne 5351){throw 'NATPMP_WIRE_SOURCE_INVALID'}
        $nat=[byte[]]$natResult.bytes
        if($nat.Length -lt 12 -or $nat[0] -ne 0 -or $nat[1] -ne 128){throw 'NATPMP_WIRE_INVALID'}
        $pcp=New-Object byte[] 24;$pcp[0]=2;$pcp[1]=0;$pcp[18]=255;$pcp[19]=255
        $octets=$ClientAddress.Split('.')|ForEach-Object{[byte][int]$_};for($i=0;$i -lt 4;$i++){$pcp[20+$i]=$octets[$i]}
        $pcpResult=Invoke-Udp -Bytes $pcp -Destination $GatewayAddress -Port 5351 -Label 'PCP'
        if([string]$pcpResult.remote_address -cne $GatewayAddress -or [int]$pcpResult.remote_port -ne 5351){throw 'PCP_WIRE_SOURCE_INVALID'}
        $pcpReply=[byte[]]$pcpResult.bytes
        if($pcpReply.Length -lt 24 -or $pcpReply[0] -ne 2 -or $pcpReply[1] -ne 128){throw 'PCP_WIRE_INVALID'}
        $ssdpText="M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 1`r`nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
        $ssdpResult=Invoke-Udp -Bytes ([Text.Encoding]::ASCII.GetBytes($ssdpText)) -Destination '239.255.255.250' -Port 1900 -Label 'SSDP'
        if([string]$ssdpResult.remote_address -cne $GatewayAddress -or [int]$ssdpResult.remote_port -ne 1900){throw 'SSDP_WIRE_SOURCE_INVALID'}
        $ssdp=[byte[]]$ssdpResult.bytes
        $ssdpBody=[Text.Encoding]::ASCII.GetString($ssdp)
        if($ssdpBody -notmatch 'HTTP/1.1 200 OK' -or $ssdpBody -notmatch [regex]::Escape("LOCATION: http://${GatewayAddress}:54321/rootDesc.xml")){throw 'SSDP_WIRE_INVALID'}
        $http=Invoke-WebRequest -UseBasicParsing -Uri "http://${GatewayAddress}:54321/rootDesc.xml" -TimeoutSec 5
        if([int]$http.StatusCode -ne 200 -or [string]$http.Content -notmatch 'InternetGatewayDevice'){throw 'UPNP_HTTP_INVALID'}
        [pscustomobject][ordered]@{schema='ese.v92.o01-vm-wire/v1';verdict='PASS';single_nic=$true;default_route_t8=$true;natpmp_wire=$true;pcp_wire=$true;ssdp_wire=$true;upnp_http=$true}|ConvertTo-Json -Compress
    }
    $guestResult=([string]($guestText|Select-Object -First 1))|ConvertFrom-Json
    Assert-ExactFields $guestResult @('schema','verdict','single_nic','default_route_t8','natpmp_wire','pcp_wire','ssdp_wire','upnp_http') 'O01 guest wire result'
    foreach($flag in @('single_nic','default_route_t8','natpmp_wire','pcp_wire','ssdp_wire','upnp_http')){Assert-JsonTrue $guestResult.$flag "O01 guest $flag"}
    if([string]$guestResult.schema -cne 'ese.v92.o01-vm-wire/v1' -or [string]$guestResult.verdict -cne 'PASS'){throw 'O01 guest wire result is not PASS'}
    [IO.File]::WriteAllText($guestResultPath,($guestResult|ConvertTo-Json -Depth 5)+"`n",[Text.UTF8Encoding]::new($false))

    $guestSession=New-PSSession -VMName $VMName -Credential $credential -ErrorAction Stop
    $guestBaseline=Invoke-Command -Session $guestSession -ScriptBlock {
        $existing=@(Get-CimInstance Win32_Process -Filter "Name='emule.exe'" -ErrorAction Stop)
        $physical=@(Get-NetAdapter -ErrorAction Stop|Where-Object{$_.Status -eq 'Up' -and $_.HardwareInterface -and -not $_.Virtual})
        [pscustomobject]@{emule_count=$existing.Count;physical_route_adapter_count=$physical.Count}
    }
    if([int]$guestBaseline.emule_count -ne 0 -or [int]$guestBaseline.physical_route_adapter_count -ne 1){throw 'O01 guest product baseline invalid'}
    $null=Invoke-Command -Session $guestSession -ScriptBlock {New-Item -ItemType Directory -Path C:\o01\package,C:\o01\tools\lab\handoff93 -Force|Out-Null}
    foreach($file in @('emule.exe','eMule.tmpl','BUILD_INFO.txt')){Copy-Item -LiteralPath (Join-Path $package $file) -Destination 'C:\o01\package' -ToSession $guestSession -ErrorAction Stop}
    foreach($folder in @('config','eSE','lang')){Copy-Item -LiteralPath (Join-Path $package $folder) -Destination 'C:\o01\package' -Recurse -ToSession $guestSession -ErrorAction Stop}
    $mapperSource=Join-Path $PSScriptRoot 'handoff93\run_product_mapper_cycle.ps1';$commonSource=Join-Path $PSScriptRoot 'common.ps1';$upnpSource=Join-Path $PSScriptRoot 'v91_r01_upnp.ps1'
    $mapperSha=(Get-FileHash -Algorithm SHA256 -LiteralPath $mapperSource).Hash.ToLowerInvariant();$commonSha=(Get-FileHash -Algorithm SHA256 -LiteralPath $commonSource).Hash.ToLowerInvariant();$upnpSha=(Get-FileHash -Algorithm SHA256 -LiteralPath $upnpSource).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $mapperSource -Destination 'C:\o01\tools\lab\handoff93' -ToSession $guestSession -ErrorAction Stop
    Copy-Item -LiteralPath $commonSource -Destination 'C:\o01\tools\lab' -ToSession $guestSession -ErrorAction Stop
    Copy-Item -LiteralPath $upnpSource -Destination 'C:\o01\tools\lab' -ToSession $guestSession -ErrorAction Stop
    $mapperExecutionText=Invoke-Command -Session $guestSession -ArgumentList $ExpectedExeSha256,$mapperSha,$commonSha,$upnpSha -ScriptBlock {
        param($ExpectedHash,$ExpectedMapperSha,$ExpectedCommonSha,$ExpectedUpnpSha)
        $bound=@(
            [pscustomobject]@{path='C:\o01\tools\lab\handoff93\run_product_mapper_cycle.ps1';sha=$ExpectedMapperSha},
            [pscustomobject]@{path='C:\o01\tools\lab\common.ps1';sha=$ExpectedCommonSha},
            [pscustomobject]@{path='C:\o01\tools\lab\v91_r01_upnp.ps1';sha=$ExpectedUpnpSha}
        )
        foreach($item in $bound){if(-not(Test-Path -LiteralPath $item.path -PathType Leaf) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $item.path).Hash.ToLowerInvariant() -cne [string]$item.sha){throw 'O01 guest harness identity mismatch'}}
        $command="& 'C:\o01\tools\lab\handoff93\run_product_mapper_cycle.ps1' -ExePath 'C:\o01\package\emule.exe' -PackageRoot 'C:\o01\package' -ConfigRoot 'C:\o01\package\config' -IniPath 'C:\o01\package\config\preferences.ini' -ExpectedExeSha256 '$ExpectedHash' -TcpPort 58662 -UdpPort 58672 -WebPort 58711 -ApiToken '' -ObservationTimeoutSec 180 -ShutdownTimeoutSec 45"
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $identityStagePath='C:\o01\package\config\r93-local-identity-stage.txt'
        if(Test-Path -LiteralPath $identityStagePath){throw 'O01 fixed identity stage path already exists'}
        $oldDiagnostic=[Environment]::GetEnvironmentVariable('R93_LOCAL_IDENTITY_DIAGNOSTIC','Process');[Environment]::SetEnvironmentVariable('R93_LOCAL_IDENTITY_DIAGNOSTIC','1','Process')
        try{$output=@(& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1);$childExit=[int]$LASTEXITCODE}
        finally{[Environment]::SetEnvironmentVariable('R93_LOCAL_IDENTITY_DIAGNOSTIC',$oldDiagnostic,'Process')}
        $identityStage=if(Test-Path -LiteralPath $identityStagePath -PathType Leaf){[IO.File]::ReadAllText($identityStagePath).Trim()}else{'NO_STAGE'}
        $fixedStages=@('HANDLE','INVENTORY','CANDIDATE','HANDLE_IDENTITY','MODULE','WINDOW_SET','GUARD_FALSE','GUARD_PRE','GUARD_ASSERT_BEGIN','GUARD_ASSERT_DONE','GUARD_TOKEN_COMPARE','INVENTORY_CALL','INVENTORY_SHAPE','GUARD_POST','CLASSIFY_VISIBLE','CLASSIFY_HIDDEN','CLASSIFY_UNEXPECTED','STABILITY','VISIBLE_MAIN','MULTIPLE_VISIBLE_MAIN','OTHER_VISIBLE','UNEXPECTED_WINDOW','NO_HIDDEN_MAIN_TIMEOUT','UNSTABLE_MAIN_TIMEOUT','WINDOW_ENUM_INCOMPLETE','WINDOW_MODAL','WINDOW_UNALLOWLISTED','WINDOW_TIMEOUT','WINDOW_IDENTITY_GUARD','WINDOW_INTERNAL_PROPERTY','WINDOW_INTERNAL_METHOD','WINDOW_INTERNAL_PARAMETER','WINDOW_INTERNAL_RUNTIME','WINDOW_INTERNAL_OTHER','ACCREDITED','NO_STAGE')
        if($identityStage -notin $fixedStages){throw 'O01 identity stage invalid'}
        $identity=[ordered]@{product_process_count=0;expected_binary_count=0;handle_access_count=0;handle_identity_match_count=0;window_enumeration_complete=$false;window_count=0;hidden_main_count=0;visible_main_count=0;other_visible_count=0;unexpected_window_count=0}
        $rows=@(Get-CimInstance Win32_Process -Filter "Name='emule.exe'" -ErrorAction Stop);$identity.product_process_count=$rows.Count
        $matching=@($rows|Where-Object{if([string]::IsNullOrWhiteSpace([string]$_.ExecutablePath)){return $false};$path=[IO.Path]::GetFullPath([string]$_.ExecutablePath);[string]::Equals($path,'C:\o01\package\emule.exe',[StringComparison]::OrdinalIgnoreCase) -and (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ceq $ExpectedHash});$identity.expected_binary_count=$matching.Count
        if($matching.Count -eq 1){
            $row=$matching[0];$process=Get-Process -Id ([int]$row.ProcessId) -ErrorAction Stop
            try{$null=$process.Handle;$identity.handle_access_count=1;$handleStart=$process.StartTime.ToUniversalTime();$cimStart=([DateTime]$row.CreationDate).ToUniversalTime();if([Math]::Abs($handleStart.Ticks-$cimStart.Ticks) -lt 10 -and [int]$process.SessionId -eq [int]$row.SessionId){$identity.handle_identity_match_count=1};$expectedClass='Afx:{0:X16}:0' -f $process.MainModule.BaseAddress.ToInt64()}catch{$expectedClass=''}
            if($null -eq ('O01WindowDiagNative' -as [type])){Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public static class O01WindowDiagNative { public sealed class Result { public bool complete; public Row[] rows; } public sealed class Row { public long owner; public bool visible; public string cls; public string title; } private delegate bool EnumProc(IntPtr h,IntPtr c); [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc p,IntPtr c); [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h,out uint p); [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h); [DllImport("user32.dll")] private static extern IntPtr GetWindow(IntPtr h,uint c); [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr h,StringBuilder v,int s); [DllImport("user32.dll",CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr h,StringBuilder v,int s); public static Result Get(uint wanted){var list=new List<Row>();bool ok=EnumWindows(delegate(IntPtr h,IntPtr c){uint p;GetWindowThreadProcessId(h,out p);if(p==wanted){var a=new StringBuilder(256);var b=new StringBuilder(256);GetClassName(h,a,a.Capacity);GetWindowText(h,b,b.Capacity);list.Add(new Row{owner=GetWindow(h,4).ToInt64(),visible=IsWindowVisible(h),cls=a.ToString(),title=b.ToString()});}return true;},IntPtr.Zero);return new Result{complete=ok,rows=list.ToArray()};} }
'@}
            $windows=[O01WindowDiagNative]::Get([uint32]$row.ProcessId);$identity.window_enumeration_complete=[bool]$windows.complete;$items=@($windows.rows);$identity.window_count=$items.Count
            $identity.hidden_main_count=@($items|Where-Object{-not $_.visible -and $_.owner -eq 0 -and $_.cls -ceq '#32770' -and $_.title.StartsWith('eMule ',[StringComparison]::Ordinal)}).Count
            $identity.visible_main_count=@($items|Where-Object{$_.visible -and $_.owner -eq 0 -and $_.cls -ceq '#32770' -and $_.title.StartsWith('eMule ',[StringComparison]::Ordinal)}).Count
            $identity.other_visible_count=@($items|Where-Object{$_.visible -and -not ($_.owner -eq 0 -and $_.cls -ceq '#32770' -and $_.title.StartsWith('eMule ',[StringComparison]::Ordinal))}).Count
            $identity.unexpected_window_count=@($items|Where-Object{$isMain=$_.cls -ceq '#32770' -and $_.owner -eq 0 -and $_.title.StartsWith('eMule ',[StringComparison]::Ordinal);$known=(($_.cls -in @('Auto-Suggest Dropdown','eMule_TaskbarNotifierWndClass','ComboLBox','tooltips_class32')) -and [string]::IsNullOrEmpty($_.title)) -or ($_.cls -ceq 'MSCTFIME UI' -and $_.title -ceq 'MSCTFIME UI') -or ($_.cls -ceq 'IME' -and $_.title -ceq 'Default IME') -or (-not [string]::IsNullOrEmpty($expectedClass) -and $_.cls -ceq $expectedClass -and $_.title -in @('eMule Async DNS Resolve Socket Wnd #2','Socket Notification Sink'));-not($isMain -or $known)}).Count
        }
        [pscustomobject][ordered]@{exit_code=$childExit;output=@($output|ForEach-Object{[string]$_});identity_stage=$identityStage;identity_diagnostic=$identity}|ConvertTo-Json -Depth 5 -Compress
    }
    $mapperExecution=([string]($mapperExecutionText|Select-Object -First 1))|ConvertFrom-Json
    Assert-ExactFields $mapperExecution @('exit_code','output','identity_stage','identity_diagnostic') 'O01 mapper execution'
    if($mapperExecution.exit_code -isnot [int] -and $mapperExecution.exit_code -isnot [long]){throw 'O01 mapper exit code type invalid'}
    $mapperDiagnostic=[ordered]@{schema='ese.v92.o01-product-mapper-diagnostic/v1';exit_code=[int]$mapperExecution.exit_code;output=@($mapperExecution.output);identity_stage=[string]$mapperExecution.identity_stage;identity_diagnostic=$mapperExecution.identity_diagnostic}
    [IO.File]::WriteAllText((Join-Path $root 'product-mapper-diagnostic.json'),($mapperDiagnostic|ConvertTo-Json -Depth 5)+"`n",[Text.UTF8Encoding]::new($false))
    if([int]$mapperExecution.exit_code -ne 0){throw "O01_PRODUCT_MAPPER_EXIT_$([int]$mapperExecution.exit_code)"}
    $mapperOutput=@($mapperExecution.output)
    $mapperJson=@($mapperOutput|ForEach-Object{[string]$_}|Where-Object{$_ -match '^\{.*\}$'}|Select-Object -Last 1)
    if($mapperJson.Count -ne 1){throw 'O01 product mapper did not emit one result'}
    $productResult=$mapperJson[0]|ConvertFrom-Json
    Assert-ExactFields $productResult @('schema','status','satisfies_h93_15','candidate_pair_same_generation','graceful_exit','mappings_absent','ini_restored_byte_exact','intervention_required','failure_class','cleanup_failure_class','sample_observation') 'O01 product result'
    Assert-ExactFields $productResult.sample_observation @('samples_total','samples_available','tcp_candidate_samples','udp_candidate_samples','same_generation_samples','last_tcp_gate_state','last_udp_gate_state','last_tcp_reason_code','last_udp_reason_code') 'O01 product sample observation'
    foreach($count in @('samples_total','samples_available','tcp_candidate_samples','udp_candidate_samples','same_generation_samples')){Assert-JsonUInt $productResult.sample_observation.$count "O01 product sample $count"}
    if([uint64]$productResult.sample_observation.samples_total -gt 180 -or
       [uint64]$productResult.sample_observation.samples_available -gt [uint64]$productResult.sample_observation.samples_total -or
       [uint64]$productResult.sample_observation.tcp_candidate_samples -gt [uint64]$productResult.sample_observation.samples_available -or
       [uint64]$productResult.sample_observation.udp_candidate_samples -gt [uint64]$productResult.sample_observation.samples_available -or
       [uint64]$productResult.sample_observation.same_generation_samples -gt [uint64]$productResult.sample_observation.samples_available){throw 'O01 product sample relationships invalid'}
    foreach($gate in @('last_tcp_gate_state','last_udp_gate_state')){if([string]$productResult.sample_observation.$gate -notin @('UNAVAILABLE','CANDIDATE','REACHABLE','BLOCKED','UNKNOWN','OTHER')){throw "O01 product sample $gate invalid"}}
    foreach($reason in @('last_tcp_reason_code','last_udp_reason_code')){Assert-JsonUInt $productResult.sample_observation.$reason "O01 product sample $reason";if([uint64]$productResult.sample_observation.$reason -gt 65535){throw "O01 product sample $reason out of range"}}
    $failureAllow=@('CANDIDATE_PAIR_NOT_OBSERVED','PROCESS_STILL_ALIVE','IDENTITY_NOT_ACCREDITED','MAPPING_REMAINS_UNTOUCHED','PREEXISTING_PROCESS_CHANGED','INI_RESTORE_FAILED','EXECUTION_FAILED')
    foreach($field in @('failure_class','cleanup_failure_class')){if($null-ne$productResult.$field -and ($productResult.$field-isnot[string] -or [string]$productResult.$field -notin $failureAllow)){throw "O01 product $field invalid"}}
    foreach($flag in @('candidate_pair_same_generation','graceful_exit','mappings_absent','ini_restored_byte_exact')){Assert-JsonTrue $productResult.$flag "O01 product $flag"}
    if($productResult.satisfies_h93_15 -isnot [bool] -or $productResult.satisfies_h93_15 -cne $false -or $productResult.intervention_required -isnot [bool] -or $productResult.intervention_required -cne $false -or [string]$productResult.schema -cne 'ese.lab.product-mapper-cycle-partial/v1' -or [string]$productResult.status -cne 'MAPPING_OBSERVED_CLEAN_EXIT' -or $null -ne $productResult.failure_class){throw 'O01 product mapper result invalid'}
    [IO.File]::WriteAllText((Join-Path $root 'product-cycle-result.json'),($productResult|ConvertTo-Json -Depth 6)+"`n",[Text.UTF8Encoding]::new($false))
    Write-CompleteMarker ([string]$ready.session_id_digest)
    if (-not $daemon.WaitForExit(30000)) { throw 'O01 formal daemon did not exit after completion' }
    if ($daemon.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $daemonResultPath -PathType Leaf)) { throw 'O01 formal daemon result failed' }
    $daemonResult=Get-Content -LiteralPath $daemonResultPath -Raw|ConvertFrom-Json
    Assert-ExactFields $daemonResult @('schema','verdict','session_id_digest','gateway_generation','mapping_count','pair_atomic','foreign_fixture_present','traffic') 'O01 daemon result'
    Assert-ExactFields $daemonResult.traffic @('pcp_requests','natpmp_requests','upnp_add_requests','upnp_get_requests','upnp_delete_requests','accepted_outcomes','rejected_outcomes','pcp_accepted','pcp_rejected','natpmp_accepted','natpmp_rejected','upnp_accepted','upnp_rejected','max_owned_mapping_count','final_owned_mapping_count','final_owned_pcp','final_owned_natpmp','final_owned_upnp') 'O01 daemon traffic'
    foreach($field in @($daemonResult.traffic.PSObject.Properties.Name)){Assert-JsonUInt $daemonResult.traffic.$field "O01 daemon traffic $field"}
    $trafficRequests=[uint64]$daemonResult.traffic.pcp_requests+[uint64]$daemonResult.traffic.natpmp_requests+[uint64]$daemonResult.traffic.upnp_add_requests+[uint64]$daemonResult.traffic.upnp_get_requests+[uint64]$daemonResult.traffic.upnp_delete_requests
    if($trafficRequests -ne ([uint64]$daemonResult.traffic.accepted_outcomes+[uint64]$daemonResult.traffic.rejected_outcomes) -or
       [uint64]$daemonResult.traffic.accepted_outcomes -ne ([uint64]$daemonResult.traffic.pcp_accepted+[uint64]$daemonResult.traffic.natpmp_accepted+[uint64]$daemonResult.traffic.upnp_accepted) -or
       [uint64]$daemonResult.traffic.rejected_outcomes -ne ([uint64]$daemonResult.traffic.pcp_rejected+[uint64]$daemonResult.traffic.natpmp_rejected+[uint64]$daemonResult.traffic.upnp_rejected) -or
       [uint64]$daemonResult.traffic.final_owned_mapping_count -ne ([uint64]$daemonResult.traffic.final_owned_pcp+[uint64]$daemonResult.traffic.final_owned_natpmp+[uint64]$daemonResult.traffic.final_owned_upnp) -or
       [uint64]$daemonResult.traffic.final_owned_mapping_count -gt [uint64]$daemonResult.traffic.max_owned_mapping_count){throw 'O01 daemon traffic relationships invalid'}
    Assert-JsonUInt $daemonResult.gateway_generation 'O01 result generation';Assert-JsonUInt $daemonResult.mapping_count 'O01 result mapping count';Assert-JsonTrue $daemonResult.pair_atomic 'O01 result pair atomic';Assert-JsonTrue $daemonResult.foreign_fixture_present 'O01 result foreign fixture'
    if([string]$daemonResult.schema -cne 'ese.v92.o01-t8-formal-smoke/v1' -or [string]$daemonResult.verdict -cne 'PASS' -or [string]$daemonResult.session_id_digest -cne [string]$ready.session_id_digest -or [int64]$daemonResult.mapping_count -ne 1){throw 'O01 daemon result evidence invalid'}
} catch { $failure = $_ }
finally {
    try{if($null -ne $guestSession){Remove-PSSession -Session $guestSession -ErrorAction Stop;$guestSession=$null}}catch{if($null -eq $failure){$failure=$_}}
    try {
        if ($null -ne $daemon -and -not $daemon.HasExited) {
            if (-not (Test-Path -LiteralPath $completePath) -and $null -ne $ready) { try{Write-CompleteMarker ([string]$ready.session_id_digest)}catch{} }
            if (-not $daemon.WaitForExit(15000)) {
                $row=Get-CimInstance Win32_Process -Filter "ProcessId=$($daemon.Id)" -ErrorAction Stop
                if([IO.Path]::GetFullPath([string]$row.ExecutablePath) -cne [IO.Path]::GetFullPath($node)){throw 'O01 daemon identity changed before forced cleanup'}
                $forcedCleanup=$true;& taskkill.exe /PID $daemon.Id /T /F | Out-Null
                if($LASTEXITCODE -ne 0){throw 'O01 daemon forced cleanup failed'}
                throw 'O01 daemon required forced cleanup'
            }
        }
    } catch { if($null -eq $failure){$failure=$_} }
    try {
        if ($vmStarted) {
            try { Invoke-Command -VMName $VMName -Credential $credential -ScriptBlock { Stop-Computer -Force } -ErrorAction Stop | Out-Null } catch {}
            $deadline=[DateTime]::UtcNow.AddSeconds(45);$current=$null
            do { Start-Sleep -Seconds 1; $current=Get-VM -Name $VMName -ErrorAction Stop } while([string]$current.State -ne 'Off' -and [DateTime]::UtcNow -lt $deadline)
            if([string]$current.State -ne 'Off'){$forcedCleanup=$true;Stop-VM -Name $VMName -TurnOff -Force -ErrorAction Stop;throw 'O01 VM required forced power off'}
        }
    } catch { if($null -eq $failure){$failure=$_} }
    $firewallCleanupFailure=$null
    foreach($ruleName in $firewallRuleNames){
        try{$owned=@(Get-ExactPersistentFirewallRules $ruleName);if($owned.Count -gt 1){throw 'O01 owned persistent firewall rule cardinality changed'};if($owned.Count -eq 1){Remove-NetFirewallRule -PolicyStore PersistentStore -Name $ruleName -ErrorAction Stop}}
        catch{if($null -eq $firewallCleanupFailure){$firewallCleanupFailure=$_}}
    }
    foreach($ruleName in $firewallRuleNames){
        try{if(@(Get-ExactPersistentFirewallRules $ruleName).Count -ne 0 -or @(Get-ExactFirewallRules $ruleName).Count -ne 0){throw 'O01 owned firewall rule cleanup verification failed'}}
        catch{if($null -eq $firewallCleanupFailure){$firewallCleanupFailure=$_}}
    }
    if($null -eq $firewallCleanupFailure){$firewallRulesCreated=$false}elseif($null -eq $failure){$failure=$firewallCleanupFailure}
    $baseDiskRestored=$false
    try{
        $currentDisks=@(Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop);if($currentDisks.Count -ne 1){throw 'O01 VM disk cardinality changed'}
        $currentPath=[IO.Path]::GetFullPath([string]$currentDisks[0].Path)
        if($currentPath -ceq [IO.Path]::GetFullPath($differencingVhd)){Set-VMHardDiskDrive -VMHardDiskDrive $currentDisks[0] -Path $originalVhd -ErrorAction Stop}
        elseif($currentPath -cne $originalVhd){throw 'O01 VM disk path changed outside owned differencing VHD'}
        $restoredDisks=@(Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop);if($restoredDisks.Count -ne 1 -or [IO.Path]::GetFullPath([string]$restoredDisks[0].Path) -cne $originalVhd -or [int]$restoredDisks[0].ControllerNumber -ne $originalDiskControllerNumber -or [int]$restoredDisks[0].ControllerLocation -ne $originalDiskControllerLocation){throw 'O01 base VHD restore verification failed'}
        $baseDiskRestored=$true;$differencingAttached=$false
    }catch{if($null -eq $failure){$failure=$_}}
    if($differencingCreated -and $baseDiskRestored){try{if(-not (Test-Path -LiteralPath $differencingVhd -PathType Leaf)){throw 'O01 differencing VHD missing before removal'};$vhd=Get-VHD -Path $differencingVhd -ErrorAction Stop;if([IO.Path]::GetFullPath([string]$vhd.ParentPath) -cne $originalVhd){throw 'O01 differencing VHD parent identity changed'};Remove-Item -LiteralPath $differencingVhd -Force -ErrorAction Stop;$differencingCreated=$false}catch{if($null -eq $failure){$failure=$_}}}
    try{$currentAdapters=@(Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop);if($currentAdapters.Count -ne 1){throw 'O01 VM NIC cardinality changed'};if([string]$currentAdapters[0].SwitchName -cne $originalSwitch){Connect-VMNetworkAdapter -VMName $VMName -SwitchName $originalSwitch -ErrorAction Stop}}catch{if($null -eq $failure){$failure=$_}}
    try{if ($null -ne $planHash -and (Test-Path -LiteralPath $statePath -PathType Leaf)) {$null=& $orchestrator -Teardown -ExistingPlanPath $planPath -ExpectedPlanHash $planHash -StatePath $statePath}}catch{if($null -eq $failure){$failure=$_}}
}

$protectedAfter = @(Get-ProtectedEmuleInventory)
$protectedUnchanged=Compare-ProtectedEmuleInventory -Before ([object[]]@($protectedBefore)) -After ([object[]]@($protectedAfter))
if (-not $protectedUnchanged) { throw 'Protected host eMule process inventory changed' }
$finalVm = Get-VM -Name $VMName -ErrorAction Stop
$finalAdapters = @(Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop)
$snapshotFinal=@(Get-VMSnapshot -VMName $VMName -ErrorAction Stop|ForEach-Object{([string]$_.Id).ToLowerInvariant()}|Sort-Object)
$finalDisks=@(Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop)
$firewallResidualCount=0;foreach($ruleName in $firewallRuleNames){$firewallResidualCount+=@(Get-ExactPersistentFirewallRules $ruleName).Count;$firewallResidualCount+=@(Get-ExactFirewallRules $ruleName).Count}
$baselineComparison=[ordered]@{schema='ese.v92.o01-vm-baseline-comparison/v1';vm_off=([string]$finalVm.State -ceq 'Off');vm_id_equal=(([string]$finalVm.VMId).ToLowerInvariant() -ceq $originalVmId);checkpoint_type_equal=([string]$finalVm.CheckpointType -ceq $originalCheckpointType);snapshot_set_equal=($snapshotFinal.Count -eq 0);disk_count_equal=($finalDisks.Count -eq 1);base_vhd_restored=($finalDisks.Count -eq 1 -and [IO.Path]::GetFullPath([string]$finalDisks[0].Path) -ceq $originalVhd);differencing_vhd_removed=(-not (Test-Path -LiteralPath $differencingVhd));adapter_count_equal=($finalAdapters.Count -eq 1);adapter_id_equal=($finalAdapters.Count -eq 1 -and [string]$finalAdapters[0].Id -ceq $originalAdapterId);adapter_mac_equal=($finalAdapters.Count -eq 1 -and [string]$finalAdapters[0].MacAddress -ceq $originalAdapterMac);adapter_switch_equal=($finalAdapters.Count -eq 1 -and [string]$finalAdapters[0].SwitchName -ceq $originalSwitch);firewall_rules_removed=($firewallResidualCount -eq 0)}
[IO.File]::WriteAllText((Join-Path $root 'baseline-comparison.json'),($baselineComparison|ConvertTo-Json -Depth 4)+"`n",[Text.UTF8Encoding]::new($false))
$baselineOk=@($baselineComparison.GetEnumerator()|Where-Object{$_.Key -notin @('schema') -and $_.Value -cne $true}).Count -eq 0
if(-not $baselineOk){$baselineError=[System.Management.Automation.RuntimeException]::new('O01 VM baseline was not restored');if($null -eq $failure){$failure=$baselineError}else{$failure=[AggregateException]::new('O01 run and baseline restoration both failed',@($failure.Exception,$baselineError))}}
if ($null -ne $failure) { throw $failure }
$stateFinal=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
$result=[pscustomobject][ordered]@{schema='ese.v92.o01-vm-t8-product-smoke/v1';verdict=if($guestResult.verdict -ceq 'PASS' -and $daemonResult.verdict -ceq 'PASS' -and $productResult.status -ceq 'MAPPING_OBSERVED_CLEAN_EXIT'){'PASS'}else{'FAIL'};release_gate=$false;product_exercised=$true;source_commit=if($DiagnosticDirtyCandidate){$null}else{'6247075338787343872952896d25cf2e330be8ff'};base_commit=if($DiagnosticDirtyCandidate){'228190eac75454d083d6afef931a540ff3ff014a'}else{$null};source_tree_clean=(-not [bool]$DiagnosticDirtyCandidate);diagnostic_dirty_candidate=[bool]$DiagnosticDirtyCandidate;source_snapshot_sha256=if($DiagnosticDirtyCandidate){$ExpectedSourceSnapshotSha256}else{$null};executable_sha256=$ExpectedExeSha256;node22=($nodeVersion -match '^v22\.');vm_identity_preserved=(([string]$finalVm.VMId).ToLowerInvariant() -ceq $originalVmId);single_t8_nic=$guestResult.single_nic;guest_default_route_t8=$guestResult.default_route_t8;natpmp_wire=$guestResult.natpmp_wire;pcp_wire=$guestResult.pcp_wire;upnp_ssdp_http=($guestResult.ssdp_wire -and $guestResult.upnp_http);product_pair_same_generation=$productResult.candidate_pair_same_generation;product_clean_exit=$productResult.graceful_exit;product_mappings_absent=$productResult.mappings_absent;daemon_natural_exit=(-not $forcedCleanup -and $daemon.ExitCode -eq 0);protected_processes_unchanged=$protectedUnchanged;t8_torn_down=([string]$stateFinal.phase -ceq 'TORN_DOWN');vm_restored_off=([string]$finalVm.State -ceq 'Off')}
if([string]$result.verdict -cne 'PASS' -or -not $result.daemon_natural_exit -or -not $result.t8_torn_down -or -not $result.vm_restored_off){throw 'O01 wire preflight derived result is not PASS'}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
$result | ConvertTo-Json -Depth 5
