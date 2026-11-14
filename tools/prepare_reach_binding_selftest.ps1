param([Parameter(Mandatory=$true)][string]$Executable,
      [Parameter(Mandatory=$true)][string]$ProfileRoot,
      [ValidateRange(1024,65535)][int]$TcpPort=49381,
      [ValidateRange(1024,65535)][int]$UdpPort=49382,
      [string]$NativeDependencyRoot='',
      [switch]$SignedQuic,
      [ValidateSet('x64','Win32')][string]$NativeArchitecture='x64',
      [ValidateRange(0,65535)][int]$DiagnosticWebPort=0)
$ErrorActionPreference='Stop'
$target=[IO.Path]::GetFullPath($ProfileRoot)
if(!$target.StartsWith('D:\tmp\',[StringComparison]::OrdinalIgnoreCase) -and !$target.StartsWith('C:\tmp\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Only a new C:\tmp or D:\tmp profile is permitted.' }
if(Test-Path -LiteralPath $target) { throw 'Profile must be new; no overwrite.' }
if($TcpPort -eq $UdpPort) { throw 'Use distinct ports.' }
if($SignedQuic -and !$NativeDependencyRoot) { throw 'Signed QUIC requires a dependency root.' }
if($DiagnosticWebPort -and ($DiagnosticWebPort -lt 1024 -or $DiagnosticWebPort -in @($TcpPort,$UdpPort))) { throw 'Use a distinct high diagnostic web port.' }
$source=(Resolve-Path -LiteralPath $Executable).Path
$null=New-Item -ItemType Directory -Path $target
$null=New-Item -ItemType Directory -Path (Join-Path $target 'config')
Copy-Item -LiteralPath $source -Destination (Join-Path $target 'emule.exe')
$nativeRuntimeInputs=@()
if($NativeDependencyRoot) {
    $manifestPath=Join-Path $NativeDependencyRoot "manifest-$NativeArchitecture.json"
    if($SignedQuic) {
        & (Join-Path $PSScriptRoot 'verify_quic_release_dependencies.ps1') -Root $NativeDependencyRoot -Architecture $NativeArchitecture
        $manifestHash=(Get-FileHash -LiteralPath $manifestPath).Hash
        if ((Get-Item -LiteralPath (Join-Path $target 'emule.exe')).VersionInfo.Comments -ne "eSE QUIC manifest SHA-256 $manifestHash") {
            throw 'The executable was not linked with this signed QUIC manifest.'
        }
    } else {
        & (Join-Path $PSScriptRoot 'verify_quic_host_dependencies.ps1') -Root $NativeDependencyRoot -Architecture $NativeArchitecture
    }
    $nativeManifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $runtimeFiles=if($SignedQuic){$nativeManifest.runtime}else{$nativeManifest.outputs | Where-Object { $_.name -like '*.dll' }}
    foreach($record in $runtimeFiles) {
        $name=if($SignedQuic){[IO.Path]::GetFileName($record.path)}else{[string]$record.name}
        if($name -ne [IO.Path]::GetFileName($name) -or !$name.EndsWith('.dll',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe native runtime name.' }
        $relative=if($SignedQuic){$record.path}else{"probe-$NativeArchitecture/Release/$name"}
        $destination=Join-Path $target $name
        Copy-Item -LiteralPath (Join-Path $NativeDependencyRoot $relative) -Destination $destination
        if((Get-FileHash -LiteralPath $destination).Hash -ne $record.sha256) { throw 'Copied native runtime hash mismatch.' }
        $nativeRuntimeInputs+=@{name=$name;sha256=$record.sha256}
    }
}
# Generated lab fixture, not an edit of an existing user profile.
$fixture=@"
[eMule]
AppVersion=eSE-v93-reach-binding-lab
UsePublicUserDirectories=2
AutoConnect=0
AutoStart=0
AutoTakeED2KLinks=0
OpenPortsOnStartUp=0
BindAddr=127.0.0.1
IncomingDir=$target\Incoming
TempDir=$target\Temp
Port=$TcpPort
UDPPort=$UdpPort
RunAsUnprivilegedUser=0
UpdateNotifyTestClient=0
SaveLogToDisk=1
Verbose=1

[Connection]
IPv6Mode=0

[UPnP]
EnableUPnP=0

[WebServer]
Enabled=0
Password=00000000000000000000000000000000

[eSE]
EseNetLabEnabled=0
EseNetLabConsent=0
EseNetLabAdvancedConsent=0
EseNetLabContributionConsent=0

[KRPRelay]
KrpRelayEnabled=0
KrpRelayKillSwitch=1
ExperimentalTcpDataPlane=0
"@
if($DiagnosticWebPort) {
    $template=Join-Path $PSScriptRoot '../srchybrid/eMule.tmpl'
    Copy-Item -LiteralPath $template -Destination (Join-Path $target 'eMule.tmpl')
    $fixture=$fixture.Replace("[WebServer]`nEnabled=0","[WebServer]`nEnabled=1`nPort=$DiagnosticWebPort`nWebUseUPnP=0")
    $fixture=$fixture.Replace("[WebServer]`r`nEnabled=0","[WebServer]`r`nEnabled=1`r`nPort=$DiagnosticWebPort`r`nWebUseUPnP=0")
    if(!$fixture.Contains("Enabled=1")) { throw 'Diagnostic web fixture substitution failed.' }
}
[IO.File]::WriteAllText((Join-Path $target 'config\preferences.ini'),$fixture,[Text.Encoding]::ASCII)
$manifest=[ordered]@{schema='ese.v93.reach-binding-lab/1';profile=$target;
    executable_sha256=(Get-FileHash -LiteralPath (Join-Path $target 'emule.exe')).Hash;
    preferences_sha256=(Get-FileHash -LiteralPath (Join-Path $target 'config\preferences.ini')).Hash;
    tcp=$TcpPort;udp=$UdpPort;launch_performed=$false;diagnostic_web_port=$DiagnosticWebPort;
    diagnostic_template_sha256=if($DiagnosticWebPort){(Get-FileHash -LiteralPath (Join-Path $target 'eMule.tmpl')).Hash}else{$null};
    native_runtime_inputs=$nativeRuntimeInputs;
    arguments=@('--portable','--reach-binding-selftest','--ignoreinstances')}
[IO.File]::WriteAllText((Join-Path $target 'prepared.json'),($manifest|ConvertTo-Json -Depth 4),[Text.Encoding]::UTF8)
Write-Output "Prepared only, not launched: $target"
