param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][ValidateSet('x64','Win32')][string]$Architecture
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function FileHash([string]$path) {
    $stream=[IO.File]::OpenRead($path)
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','') }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}
$repoRoot=Split-Path $PSScriptRoot -Parent
$dependencyRoot=[IO.Path]::GetFullPath($Root)
$manifest=Get-Content -LiteralPath (Join-Path $dependencyRoot "manifest-$Architecture.json") -Raw | ConvertFrom-Json
$lock=Join-Path $repoRoot 'third_party/quic/dependencies.lock.json'
if($manifest.architecture -ne $Architecture -or $manifest.local_inputs_changed -or
    $manifest.delivery_status -ne 'LAB_ONLY_PROVENANCE_PENDING' -or
    !$manifest.native_runtime_adapter_tested -or
    $manifest.lock_sha256 -ne (FileHash $lock)) {
    throw 'QUIC laboratory manifest/lock does not match the requested host build.'
}
$requiredHostInputs=@('srchybrid/DirectReachabilityManager.h','srchybrid/DirectReachabilityManager.cpp',
    'srchybrid/Kad6CryptoHost.h','srchybrid/Kad6CryptoHost.cpp',
    'srchybrid/EseQuicSharedSocketSelfTest.h','srchybrid/EmuleDlg.cpp',
    'tools/run_reach_binding_selftest.ps1')
foreach($requiredInput in $requiredHostInputs) {
    $records=@($manifest.local_inputs | Where-Object { $_.path -eq $requiredInput })
    if($records.Count -ne 1) {
        throw "Missing or duplicate host source evidence: $requiredInput. Re-run the dependency builder."
    }
}
foreach($inputRecord in $manifest.local_inputs) {
    $path=Join-Path $repoRoot $inputRecord.path
    if((FileHash $path) -ne $inputRecord.sha256) {
        throw "QUIC laboratory source changed: $($inputRecord.path). Re-run the dependency builder."
    }
}
$requiredLinks=@("gnutls-$Architecture.lib","build-$Architecture/lib/Release/ngtcp2.lib",
    "build-$Architecture/crypto/gnutls/Release/ngtcp2_crypto_gnutls.lib")
foreach($relative in $requiredLinks) {
    $records=@($manifest.link_inputs | Where-Object { $_.path -eq $relative })
    if($records.Count -ne 1 -or (FileHash (Join-Path $dependencyRoot $relative)) -ne $records[0].sha256) {
        throw "QUIC linker input is missing or changed: $relative"
    }
}
if(@($manifest.dependency_headers).Count -eq 0) { throw 'Missing dependency header evidence.' }
foreach($record in $manifest.dependency_headers) {
    $path=[IO.Path]::GetFullPath((Join-Path $dependencyRoot $record.path))
    if(!$path.StartsWith($dependencyRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or
        (FileHash $path) -ne $record.sha256) {
        throw "QUIC dependency header changed or is outside root: $($record.path)"
    }
}
$dlls=@($manifest.outputs | Where-Object { $_.name -like '*.dll' })
foreach($required in @('ngtcp2.dll','ngtcp2_crypto_gnutls.dll','libgnutls-30.dll')) {
    if(!($dlls | Where-Object { $_.name -eq $required })) { throw "Missing runtime manifest entry: $required" }
}
foreach($record in $dlls) {
    if($record.name -ne [IO.Path]::GetFileName($record.name)) { throw 'Unsafe runtime file name in manifest.' }
    $path=Join-Path $dependencyRoot "probe-$Architecture/Release/$($record.name)"
    if((FileHash $path) -ne $record.sha256) {
        throw "QUIC runtime binary changed: $($record.name)"
    }
}
Write-Host "Pinned QUIC inputs verified for $Architecture; LAB ONLY, not release provenance approval."
