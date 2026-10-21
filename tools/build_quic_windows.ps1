param(
    [Parameter(Mandatory=$true)][string]$WorkRoot,
    [ValidateSet('x64','Win32')][string]$Architecture = 'x64',
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$lockPath = Join-Path $repoRoot 'third_party/quic/dependencies.lock.json'
$dependencyLock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$localInputPaths = @('tools/build_quic_windows.ps1','tools/quic/CMakeLists.txt',
    'tools/check_protocol_registry.py','tools/test_protocol_registry.py',
    'docs/protocol/ESE_WIRE.csv','docs/protocol/TAGS.csv','docs/protocol/OPCODES.csv',
    'docs/protocol/CAPABILITIES.csv','docs/protocol/TUNNEL_SERVICES.csv',
    'docs/protocol/KRP_MESSAGES.csv','docs/protocol/KAD6_MESSAGES.csv',
    'srchybrid/Opcodes.h','srchybrid/LiveTunnel.h',
    'librelaycore/include/relay/krp_control.h',
    'libkad6/include/kad6/kad6_search.h','libkad6/include/kad6/kad6_publish.h',
    'libkad6/include/kad6/kad6_lease.h','libkad6/include/kad6/kad6_gateway.h',
    'libkad6/include/kad6/kad6_quota.h',
    'tools/verify_quic_host_dependencies.ps1','srchybrid/EseNativeQuic.targets',
    'third_party/quic/dependencies.lock.json','srchybrid/EseChannelBinding.h','srchybrid/EseChannelBinding.cpp',
    'srchybrid/EseWireProtocol.h',
    'srchybrid/EseControlEnvelope.h',
    'srchybrid/EseQuicSharedSocketSelfTest.h',
    'srchybrid/DirectReachabilityManager.h','srchybrid/DirectReachabilityManager.cpp',
    'srchybrid/updownclient.h','srchybrid/BaseClient.cpp','srchybrid/DownloadClient.cpp',
    'srchybrid/ClientList.h','srchybrid/ClientList.cpp','srchybrid/ListenSocket.cpp',
    'srchybrid/EseQuicDownloadConsumer.cpp',
    'srchybrid/EmuleDlg.cpp',
    'srchybrid/DownloadQueue.h','srchybrid/DownloadQueue.cpp',
    'srchybrid/OtherFunctions.h',
    'srchybrid/Kad6CryptoHost.h','srchybrid/Kad6CryptoHost.cpp',
    'srchybrid/EseControlPendingRoutes.h',
    'srchybrid/EseControlPacketBudget.h',
    'srchybrid/EseControlBootstrap.h',
    'srchybrid/EseControlCookie.h',
    'srchybrid/EseControlChallengeLimit.h',
    'srchybrid/EseControlSessions.h',
    'srchybrid/EseControlInitiator.h',
    'srchybrid/EseControlInitiatorHost.h',
    'srchybrid/EseReachDescriptor.h',
    'srchybrid/EseDescriptorSerials.h',
    'srchybrid/EseWitnessDescriptors.h',
    'srchybrid/EseK6DirectSource.h',
    'srchybrid/EseKad6ServiceCapabilities.h','tools/test_kad6_service_capabilities.cpp',
    'srchybrid/EseKad6FindContacts.h',
    'srchybrid/EseKad6Lookup.h',
    'srchybrid/EseKad6Resolution.h',
    'srchybrid/EseKad6ResolutionHost.h',
    'srchybrid/EseResolutionCooldown.h',
    'srchybrid/EseKad6ContactRefresh.h',
    'srchybrid/EseKad6ContactCache.h',
    'srchybrid/EseKad6LookupCooldown.h',
    'srchybrid/EseKad6DiscoveryOutcome.h',
    'srchybrid/EseClassicCallbackProof.h',
    'srchybrid/EseClassicCallbackPolicy.h',
    'srchybrid/EseKad6PublicContactProof.h','tools/test_kad6_public_contact_proof.cpp',
    'srchybrid/kademlia/kademlia/UDPFirewallTester.cpp',
    'srchybrid/EseControlServiceRoutes.h','tools/test_control_service_routes.cpp',
    'srchybrid/EseKad6IndexService.h','tools/test_kad6_index_service.cpp',
    'tools/test_kad6_index_shutdown.cpp',
    'srchybrid/EseKad6IndexBootstrap.h',
    'srchybrid/EseKad6PublicationSerial.h','tools/test_kad6_publication_serial.cpp',
    'srchybrid/EseKad6PublicationAttempt.h',
    'srchybrid/EseKad6NearestContacts.h',
    'srchybrid/EseMappingReadback.h','tools/test_mapping_readback.cpp',
    'srchybrid/EseKad6PublicationDescriptor.h',
    'srchybrid/EseKad6IndexHostSelfTest.h',
    'srchybrid/EseKad6PublisherHostSelfTest.h',
    'tools/test_classic_callback_proof.cpp',
    'srchybrid/EseServerCallbackRetry.h',
    'srchybrid/EseServerCallbackHostSelfTest.h',
    'srchybrid/EseKad2IndexPersistenceSelfTest.h',
    'srchybrid/EseKad2SoakSelfTest.h','srchybrid/emuleDlg.cpp','srchybrid/UploadQueue.cpp',
    'srchybrid/ServerConnect.cpp','srchybrid/ServerConnect.h','srchybrid/ServerSocket.cpp',
    'srchybrid/Emule.cpp',
    'srchybrid/kademlia/net/KademliaUDPListener.cpp',
    'srchybrid/kademlia/net/KademliaUDPListener.h',
    'srchybrid/EseKad6ContactRefreshReplies.h',
    'srchybrid/EseKad6ContactCacheFile.h',
    'libkad6/include/kad6/kad6_records.h','libkad6/include/kad6/kad6_crypto.h',
    'libkad6/include/kad6/kad6_endpoint.h','libkad6/include/kad6/kad6_address.h',
    'libkad6/include/kad6/kad6_bytes.h','libkad6/include/kad6/kad6_types.h',
    'libkad6/src/kad6_records.cpp','libkad6/src/kad6_endpoint.cpp','libkad6/src/kad6_address.cpp',
    'srchybrid/EseControlCookieCrypto.h','srchybrid/EseControlCookieCrypto.cpp',
    'srchybrid/EseUdpDemux.h','srchybrid/EseUdpDemux.cpp','srchybrid/EseQuicHeaderProbe.h','srchybrid/EseQuicHeaderProbe.cpp',
    'srchybrid/LiveCrypto.h','srchybrid/LiveCrypto.cpp','libreach/src/direct_transport.cpp',
    'srchybrid/EseQuicTransport.h','srchybrid/EseQuicTransport.cpp','libreach/src/direct_event_queue.cpp',
    'srchybrid/EseNativeQuicRuntime.h','srchybrid/EseNativeQuicRuntime.cpp','srchybrid/NodeIdentity.h',
    'srchybrid/EseQuicUdpRouter.h','srchybrid/EseQuicUdpRouter.cpp','srchybrid/EseQuicUdpIngress.h',
    'srchybrid/EseQuicSocketOwner.h','srchybrid/EseQuicSocketOwner.cpp',
    'srchybrid/EseQuicHostLifecycle.h',
    'srchybrid/EseQuicHostFactory.h','srchybrid/EseQuicHostFactory.cpp',
    'srchybrid/EseQuicHostStart.h','libreach/include/reach/direct_coordinator.h',
    'srchybrid/EseQuicRouteOwners.h',
    'srchybrid/EseQuicAttemptRetirement.h',
    'srchybrid/EseDirectAttemptRetirement.h','libreach/include/reach/direct_route_dispatch.h',
    'tools/test_direct_route_dispatch.cpp',
    'srchybrid/EseUtpEndpoint.h','tools/test_utp_endpoint.cpp',
    'srchybrid/eMuleAI/UtpSocket.cpp','srchybrid/eMuleAI/UtpSocket.h',
    'srchybrid/ClientUDPSocket.cpp',
    'srchybrid/ClientUDPSocket.h','srchybrid/EseQuicPairSelfTest.h',
    'srchybrid/UploadQueue.h','srchybrid/UploadDiskIOThread.h','srchybrid/UploadDiskIOThread.cpp',
    'srchybrid/EmuleDlg.cpp','tools/run_reach_binding_selftest.ps1',
    'srchybrid/EseDirectBatchConsumer.h',
    'srchybrid/EsePeerTrust.h','srchybrid/EsePeerTrustStore.h',
    'srchybrid/EseQuicDownloadConsumer.h','srchybrid/EseQuicDownloadConsumer.cpp',
    'libreach/include/reach/native_direct_snapshot.h',
    'libreach/include/reach/native_direct_request.h',
    'libreach/include/reach/native_direct_reask.h',
    'libreach/include/reach/native_direct_routes.h',
    'libreach/include/reach/direct_subscribers.h',
    'libreach/include/reach/direct_client_lifetime.h',
    'libreach/include/reach/part_verification.h',
    'libreach/include/reach/part_contributions.h','libreach/include/reach/accepted_part_ranges.h','tools/test_part_contributions.cpp',
    'tools/test_native_direct_snapshot.cpp','tools/test_native_direct_routes.cpp',
    'tools/test_direct_subscribers.cpp','libreach/src/direct_attempt.cpp',
    'srchybrid/EseEd2kFramer.h',
    'srchybrid/EseQuicEd2kPump.h',
    'srchybrid/EseQuicEd2kWriter.h',
    'srchybrid/EseQuicDcoActions.h','libreach/src/direct_coordinator.cpp','libreach/src/direct_session.cpp',
    'libreach/include/reach/direct_event_queue.h',
    'libreach/include/reach/direct_transport.h','libreach/include/reach/direct_session.h',
    'libreach/include/reach/direct_attempt.h','libreach/include/reach/reach_types.h',
    "cryptopp/$Architecture/Output/Release/cryptlib.lib")
foreach ($inputFile in (Get-ChildItem -LiteralPath (Join-Path $repoRoot 'tools/quic') -File)) {
    if ($inputFile.Extension -in @('.c','.cpp','.h')) { $localInputPaths += 'tools/quic/' + $inputFile.Name }
}
foreach ($inputFile in (Get-ChildItem -LiteralPath (Join-Path $repoRoot 'cryptopp') -File -Filter '*.h')) {
    $localInputPaths += 'cryptopp/' + $inputFile.Name
}
$localInputs = @($localInputPaths | Sort-Object -Unique | ForEach-Object {
    @{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $repoRoot $_) -Algorithm SHA256).Hash}
})
$workDirectory = [IO.Path]::GetFullPath($WorkRoot)
if ($workDirectory -eq [IO.Path]::GetPathRoot($workDirectory) -or
    $workDirectory.TrimEnd('\') -eq $repoRoot.TrimEnd('\')) {
    throw 'Use a dedicated dependency build directory, not a drive or repository root.'
}
New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null

function Invoke-Checked([string]$Executable, [string[]]$Arguments, [string]$LogName) {
    & $Executable @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $workDirectory "$Architecture-$LogName")
    if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Executable" }
}
Invoke-Checked 'python' @((Join-Path $repoRoot 'tools/check_protocol_registry.py')) 'protocol-registry.log'
Invoke-Checked 'python' @((Join-Path $repoRoot 'tools/test_protocol_registry.py')) 'protocol-registry-negative.log'
function Get-PinnedArchive($Item) {
    $destination = Join-Path $workDirectory ([IO.Path]::GetFileName(([uri]$Item.url).AbsolutePath))
    if (-not (Test-Path -LiteralPath $destination)) {
        if ($Offline) { throw "Missing offline dependency: $destination" }
        Invoke-WebRequest -Uri $Item.url -OutFile $destination
    }
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $Item.sha256) {
        throw "Dependency SHA256 mismatch: $destination"
    }
    return $destination
}
function Assert-PinnedTree([string]$ExpectedRoot, [string]$ActualRoot) {
    $expectedFiles = @(Get-ChildItem -LiteralPath $ExpectedRoot -Recurse -File)
    $actualFiles = @(Get-ChildItem -LiteralPath $ActualRoot -Recurse -File)
    if ($expectedFiles.Count -ne $actualFiles.Count) { throw "Modified dependency tree: $ActualRoot" }
    foreach ($file in $expectedFiles) {
        $relative = $file.FullName.Substring($ExpectedRoot.TrimEnd('\').Length).TrimStart('\')
        $actual = Join-Path $ActualRoot $relative
        if (-not (Test-Path -LiteralPath $actual) -or
            (Get-FileHash -LiteralPath $actual).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash) {
            throw "Modified dependency file: $actual"
        }
    }
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsRoot) { throw 'Visual Studio 2022 C++ toolchain not found.' }
$cmake = Join-Path $vsRoot 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
$ctest = Join-Path (Split-Path $cmake) 'ctest.exe'
$machine = if ($Architecture -eq 'x64') { 'x64' } else { 'x86' }
$libTool = Join-Path $vsRoot "VC/Tools/MSVC/$($dependencyLock.toolchain.msvc_tools_version)/bin/Hostx64/$machine/lib.exe"
foreach ($tool in @($cmake,$ctest,$libTool)) {
    if (-not (Test-Path -LiteralPath $tool)) { throw "Missing pinned build tool: $tool" }
}
if ((& $cmake --version | Select-Object -First 1) -ne "cmake version $($dependencyLock.toolchain.cmake_version)") {
    throw 'CMake version differs from the dependency lock.'
}
$sourceArchive = Get-PinnedArchive $dependencyLock.ngtcp2
$tlsArchive = Get-PinnedArchive $dependencyLock.gnutls.$Architecture
$tasnArchive = Get-PinnedArchive $dependencyLock.libtasn1.$Architecture
$sourceDirectory = Join-Path $workDirectory "ngtcp2-$($dependencyLock.ngtcp2.version)"
if (-not (Test-Path -LiteralPath $sourceDirectory)) {
    Invoke-Checked 'tar.exe' @('-xf',$sourceArchive,'-C',$workDirectory) 'extract-ngtcp2.log'
}
$tlsDirectory = Join-Path $workDirectory "gnutls-$Architecture"
if (-not (Test-Path -LiteralPath $tlsDirectory)) {
    Expand-Archive -LiteralPath $tlsArchive -DestinationPath $tlsDirectory
}
$tlsRoot = Join-Path $tlsDirectory $dependencyLock.gnutls.$Architecture.archive_root
$tasnDirectory = Join-Path $workDirectory "tasn1-$Architecture"
if (-not (Test-Path -LiteralPath $tasnDirectory)) {
    New-Item -ItemType Directory -Path $tasnDirectory | Out-Null
    Invoke-Checked 'tar.exe' @('-xf',$tasnArchive,'-C',$tasnDirectory) 'extract-libtasn1.log'
}
# Re-extract trusted archive bytes into an evidence directory and compare every
# input, so a cached source/DLL modification cannot pass a pinned archive check.
$verificationDirectory = Join-Path $workDirectory "verify-$Architecture-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $verificationDirectory | Out-Null
Invoke-Checked 'tar.exe' @('-xf',$sourceArchive,'-C',$verificationDirectory) 'verify-source.log'
Expand-Archive -LiteralPath $tlsArchive -DestinationPath (Join-Path $verificationDirectory 'tls')
$tasnVerification = Join-Path $verificationDirectory 'tasn'
New-Item -ItemType Directory -Path $tasnVerification | Out-Null
Invoke-Checked 'tar.exe' @('-xf',$tasnArchive,'-C',$tasnVerification) 'verify-libtasn1.log'
Assert-PinnedTree (Join-Path $verificationDirectory "ngtcp2-$($dependencyLock.ngtcp2.version)") $sourceDirectory
Assert-PinnedTree (Join-Path $verificationDirectory "tls/$($dependencyLock.gnutls.$Architecture.archive_root)") $tlsRoot
Assert-PinnedTree $tasnVerification $tasnDirectory
$includeDirectory = Join-Path $workDirectory "include-$Architecture"
$headerDirectory = Join-Path $includeDirectory 'gnutls'
New-Item -ItemType Directory -Path $headerDirectory -Force | Out-Null
Copy-Item -Path (Join-Path $tlsRoot 'lib/includes/*.h') -Destination $headerDirectory
$importLibrary = Join-Path $workDirectory "gnutls-$Architecture.lib"
Invoke-Checked $libTool @('/nologo',"/def:$tlsRoot/lib/libgnutls-30.def","/machine:$machine","/out:$importLibrary") 'import-library.log'
$buildDirectory = Join-Path $workDirectory "build-$Architecture"
$cmakeFlags = @('-S',$sourceDirectory,'-B',$buildDirectory,'-G',$dependencyLock.toolchain.generator,
    '-A',$Architecture,'-T',"$($dependencyLock.toolchain.toolset),version=$($dependencyLock.toolchain.msvc_tools_version)",
    "-DCMAKE_SYSTEM_VERSION=$($dependencyLock.toolchain.windows_sdk)",
    "-DGNUTLS_INCLUDE_DIR=$includeDirectory","-DGNUTLS_LIBRARY=$importLibrary")
foreach ($property in $dependencyLock.flags.PSObject.Properties) {
    $cmakeFlags += "-D$($property.Name)=$($property.Value)"
}
Invoke-Checked $cmake $cmakeFlags 'configure.log'
Invoke-Checked $cmake @('--build',$buildDirectory,'--config','Release','--parallel','4') 'build.log'
Invoke-Checked $cmake @('--build',$buildDirectory,'--config','Release','--target','main','--parallel','4') 'build-tests.log'
Invoke-Checked $ctest @('--test-dir',$buildDirectory,'-C','Release','--output-on-failure') 'upstream-tests.log'
$probeDirectory = Join-Path $workDirectory "probe-$Architecture"
Invoke-Checked $cmake @('-S',(Join-Path $PSScriptRoot 'quic'),'-B',$probeDirectory,
    '-G',$dependencyLock.toolchain.generator,'-A',$Architecture,'-T',"$($dependencyLock.toolchain.toolset),version=$($dependencyLock.toolchain.msvc_tools_version)",
    "-DCMAKE_SYSTEM_VERSION=$($dependencyLock.toolchain.windows_sdk)",
    "-DNGTCP2_SOURCE=$sourceDirectory","-DNGTCP2_BUILD=$buildDirectory",
    "-DGNUTLS_INCLUDE=$includeDirectory","-DGNUTLS_IMPORT=$importLibrary") 'configure-probe.log'
Invoke-Checked $cmake @('--build',$probeDirectory,'--config','Release') 'build-probe.log'
$probeOutput = Join-Path $probeDirectory 'Release'
Copy-Item -Path (Join-Path $tlsRoot 'bin/*.dll') -Destination $probeOutput
Copy-Item -LiteralPath (Join-Path $tasnDirectory $dependencyLock.libtasn1.$Architecture.dll) -Destination $probeOutput
Copy-Item -LiteralPath (Join-Path $buildDirectory 'lib/Release/ngtcp2.dll'),
    (Join-Path $buildDirectory 'crypto/gnutls/Release/ngtcp2_crypto_gnutls.dll') -Destination $probeOutput
Invoke-Checked (Join-Path $probeOutput 'quic_dependency_smoke.exe') @() 'abi-probe.log'
Invoke-Checked (Join-Path $probeOutput 'test_channel_binding.exe') @() 'binding-state.log'
Invoke-Checked (Join-Path $probeOutput 'test_control_envelope.exe') @() 'control-envelope-state.log'
Invoke-Checked (Join-Path $probeOutput 'test_control_cookie_crypto.exe') @() 'control-cookie-crypto.log'
Invoke-Checked (Join-Path $probeOutput 'test_find_contacts.exe') @() 'find-contacts.log'
foreach ($controlScenario in @('clean','loss-challenge','loss-ack','bad-ack')) {
    Invoke-Checked (Join-Path $probeOutput 'control_udp_loopback.exe') @($controlScenario) "control-udp-$controlScenario.log"
}
Invoke-Checked (Join-Path $probeOutput 'test_udp_demux.exe') @() 'udp-demux.log'
Invoke-Checked (Join-Path $probeOutput 'test_quic_transport.exe') @() 'quic-transport-state.log'
Invoke-Checked (Join-Path $probeOutput 'test_quic_udp_router.exe') @() 'quic-udp-router-state.log'
Invoke-Checked (Join-Path $probeOutput 'test_quic_route_owners.exe') @() 'quic-route-owners-state.log'
Invoke-Checked (Join-Path $probeOutput 'test_native_direct_snapshot.exe') @() 'native-direct-snapshot.log'
Invoke-Checked (Join-Path $probeOutput 'test_native_direct_routes.exe') @() 'native-direct-routes.log'
Invoke-Checked (Join-Path $probeOutput 'test_direct_subscribers.exe') @() 'direct-subscribers.log'
Invoke-Checked (Join-Path $probeOutput 'test_part_contributions.exe') @() 'part-contributions.log'
Invoke-Checked (Join-Path $probeOutput 'test_utp_endpoint.exe') @() 'utp-endpoint.log'
Invoke-Checked $ctest @('--test-dir',$probeDirectory,'-C','Release','--output-on-failure') 'native-direct-contracts-ctest.log'
Invoke-Checked (Join-Path $probeOutput 'quic_loopback.exe') @() 'loopback.log'
Invoke-Checked (Join-Path $probeOutput 'quic_loopback.exe') @('--wrong-alpn') 'loopback-alpn.log'
Invoke-Checked (Join-Path $probeOutput 'quic_loopback.exe') @('--bad-auth') 'loopback-auth-rejection.log'
Invoke-Checked (Join-Path $probeOutput 'quic_loopback.exe') @('--loss') 'loopback-loss.log'
foreach ($nativeScenario in @('clean','dco','pause','block','loss','server-only','bad-auth','reset','send-fail','begin-fail','close')) {
    Invoke-Checked (Join-Path $probeOutput 'native_quic_loopback.exe') @($nativeScenario) "native-facade-$nativeScenario.log"
}
$outputs = @(Get-ChildItem -LiteralPath $probeOutput -File | ForEach-Object {
    @{name=$_.Name; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash; size=$_.Length}
})
$dependencyHeaders = @(foreach ($headerRoot in @(
    (Join-Path $sourceDirectory 'lib/includes'),(Join-Path $sourceDirectory 'crypto/includes'),
    (Join-Path $buildDirectory 'lib/includes'),$includeDirectory)) {
    Get-ChildItem -LiteralPath $headerRoot -File -Recurse -Filter '*.h' | ForEach-Object {
        @{path=$_.FullName.Substring($workDirectory.TrimEnd('\').Length+1).Replace('\','/');
          sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    }
})
foreach ($inputRecord in $localInputs) {
    if ((Get-FileHash -LiteralPath (Join-Path $repoRoot $inputRecord.path) -Algorithm SHA256).Hash -ne $inputRecord.sha256) {
        throw "Source changed during QUIC build/test: $($inputRecord.path)"
    }
}
@{
    schema='ese.quic.build/v1'; architecture=$Architecture; evidence_class='DEPENDENCY_AND_LOOPBACK';
    delivery_status=$dependencyLock.delivery_status; handshake_tested=$true; transfer_tested=$false;
    transport_fixture_tested=$true; peer_binding_tested=$false; ed2k_tested=$false;
    binding_state_tested=$true; tls_exporter_tested=$true;
    signed_binding_fixture_tested=$true; persistent_identity_tested=$false; trust_storage_tested=$false;
    udp_demux_fixture_tested=$true;
    quic_transport_state_tested=$true; native_runtime_adapter_tested=$true;
    native_runtime_evidence_scope='LAB_UDP_FACADE_EPHEMERAL_IDENTITIES';
    native_runtime_scenarios=@('clean','dco','pause','block','loss','server-only','bad-auth','reset','send-fail','begin-fail','close');
    native_direct_contract_scenarios=@('native_direct_snapshot','native_direct_routes','direct_subscribers','part_contributions','native_quic_dco');
    control_runtime_scenarios=@('clean','loss-challenge','loss-ack','bad-ack');
    native_socket_owner_begin_failure_tested=$true;
    native_socket_owner_tested=$true; native_socket_owner_hard_send_failure_tested=$true;
    native_runtime_router_owned_tested=$true; native_runtime_router_reset_tested=$true;
    native_runtime_bad_auth_rejection_tested=$true;
    quic_udp_router_state_tested=$true;
    native_runtime_payload_bytes=6291456; host_shared_socket_tested=$false;
    native_runtime_bidirectional_tested=$true; native_runtime_demux_tested=$true;
    local_inputs=$localInputs; local_inputs_changed=$false;
    crypto_dependency='PREBUILT_NOT_REBUILT';
    crypto_library_sha256=(Get-FileHash (Join-Path $PSScriptRoot "../cryptopp/$Architecture/Output/Release/cryptlib.lib")).Hash;
    generated_at_utc=[DateTime]::UtcNow.ToString('o'); lock_sha256=(Get-FileHash $lockPath).Hash;
    ngtcp2_commit=$dependencyLock.ngtcp2.commit; gnutls_version=$dependencyLock.gnutls.version;
    cmake=(Get-Item $cmake).VersionInfo.FileVersion; toolchain=$dependencyLock.toolchain;
    archives=@(@{path=$sourceArchive;sha256=$dependencyLock.ngtcp2.sha256},
               @{path=$tlsArchive;sha256=$dependencyLock.gnutls.$Architecture.sha256},
               @{path=$tasnArchive;sha256=$dependencyLock.libtasn1.$Architecture.sha256});
    outputs=$outputs
    dependency_headers=$dependencyHeaders
    link_inputs=@("gnutls-$Architecture.lib",
        "build-$Architecture/lib/Release/ngtcp2.lib",
        "build-$Architecture/crypto/gnutls/Release/ngtcp2_crypto_gnutls.lib") | ForEach-Object {
            @{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $workDirectory $_) -Algorithm SHA256).Hash}
        }
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $workDirectory "manifest-$Architecture.json") -Encoding utf8
Write-Host "QUIC build/ABI/UDP loopback PASS ($Architecture); peer binding and full C1 acceptance remain open."
