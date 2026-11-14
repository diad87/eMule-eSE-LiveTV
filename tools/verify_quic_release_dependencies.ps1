[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [ValidateSet('x64')][string]$Architecture = 'x64',
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedManifestSha256,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
$dependencyRoot = (Get-Item -LiteralPath $Root).FullName
$manifestPath = Join-Path $dependencyRoot "manifest-$Architecture.json"
$lockPath = Join-Path $repoRoot 'third_party/quic/dependencies.lock.json'
$inventoryPath = Join-Path $repoRoot 'third_party/quic/msys2-gnutls-x64-candidate.json'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json

function Get-DependencyHash([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try { [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-','') }
        finally { $sha256.Dispose() }
    } finally { $stream.Dispose() }
}

function Read-PlainDependencyPath([string]$RelativePath) {
    if ($RelativePath -notmatch '^[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$' -or
        $RelativePath -match '(^|/)\.{1,2}(/|$)') {
        throw "Unsafe QUIC manifest path: $RelativePath"
    }
    $item = Get-Item -LiteralPath (Join-Path $dependencyRoot $RelativePath) -Force
    $cursor = $item
    while ($cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "QUIC dependency path has a reparse point: $($cursor.FullName)"
        }
        $cursor = if ($cursor -is [IO.FileInfo]) { $cursor.Directory } else { $cursor.Parent }
    }
    return $item
}

function Get-PlainTreeFiles([string]$RelativeDirectory) {
    $directory = Read-PlainDependencyPath $RelativeDirectory
    if (!$directory.PSIsContainer) { throw "Expected QUIC dependency directory: $RelativeDirectory" }
    foreach ($entry in $directory.EnumerateFileSystemInfos()) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "QUIC dependency tree has a reparse point: $($entry.FullName)"
        }
        $relative = $entry.FullName.Substring($dependencyRoot.TrimEnd('\','/').Length+1).Replace('\','/')
        if ($entry -is [IO.DirectoryInfo]) { Get-PlainTreeFiles $relative }
        else { $relative }
    }
}

function Assert-FileSet([string]$Label,[string[]]$Expected,[string[]]$Actual) {
    if ($Actual.Count -ne $Expected.Count -or (Compare-Object ($Expected | Sort-Object) ($Actual | Sort-Object))) {
        throw "QUIC $Label file set differs from the expected inventory."
    }
}

function Read-FileRecords([string]$Label,[object[]]$Records) {
    $byPath = @{}
    foreach ($record in $Records) {
        $path = [string]$record.path
        $file = Read-PlainDependencyPath $path
        if ($byPath.ContainsKey($path) -or $file.PSIsContainer -or $file.Length -le 0 -or
            $file.Length -ne [long]$record.size -or $record.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
            $record.sha256 -ne (Get-DependencyHash $file.FullName)) {
            throw "QUIC $Label record is duplicate, empty or changed: $path"
        }
        $byPath.Add($path, [string]$record.sha256)
    }
    return $byPath
}

$manifestFile = Read-PlainDependencyPath (Split-Path -Leaf $manifestPath)
if ($manifestFile.PSIsContainer) { throw 'The QUIC manifest must be a file.' }
$manifestHash = Get-DependencyHash $manifestPath
if ($ExpectedManifestSha256 -and $manifestHash -ne $ExpectedManifestSha256) { throw 'QUIC manifest SHA-256 mismatch.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 'ese.quic.release-dependencies/v1' -or $manifest.architecture -ne $Architecture -or
    $inventory.status -ne 'signed-release-inputs' -or
    $manifest.lock_sha256 -ne (Get-DependencyHash $lockPath) -or
    $manifest.msys2_candidate_sha256 -ne (Get-DependencyHash $inventoryPath) -or
    $manifest.workflow_sha256 -ne (Get-DependencyHash (Join-Path $PSScriptRoot 'build_quic_msys2_candidate.ps1'))) {
    throw 'QUIC release manifest does not match the pinned inputs and build workflow.'
}

$links = Read-FileRecords 'link input' @($manifest.link_inputs)
$headers = Read-FileRecords 'header' @($manifest.dependency_headers)
$runtime = Read-FileRecords 'runtime' @($manifest.runtime)
$notices = Read-FileRecords 'notice' @($manifest.notices)
$sources = Read-FileRecords 'source' @($manifest.sources)

Assert-FileSet 'link input' @('gnutls-x64.lib','build-x64/lib/Release/ngtcp2.lib',
    'build-x64/crypto/gnutls/Release/ngtcp2_crypto_gnutls.lib') @($links.Keys)
if ($links['gnutls-x64.lib'] -ne $inventory.gnutls_import_sha256) { throw 'The GnuTLS import library is not the signed MSYS2 input.' }
$ngtcp2Dir = "ngtcp2-$($lock.ngtcp2.version)"
$expectedHeaders = @(foreach ($headerRoot in @("$ngtcp2Dir/lib/includes","$ngtcp2Dir/crypto/includes",'build-x64/lib/includes','include-x64')) {
    Get-PlainTreeFiles $headerRoot | Where-Object { $_ -like '*.h' }
})
Assert-FileSet 'header' $expectedHeaders @($headers.Keys)
foreach ($requiredHeader in @("$ngtcp2Dir/lib/includes/ngtcp2/ngtcp2.h","$ngtcp2Dir/crypto/includes/ngtcp2/ngtcp2_crypto_gnutls.h",
    'build-x64/lib/includes/ngtcp2/version.h','include-x64/gnutls/gnutls.h','include-x64/gnutls/crypto.h')) {
    if (!$headers.ContainsKey($requiredHeader)) { throw "Missing QUIC dependency header: $requiredHeader" }
}

$expectedRuntime = @{'runtime-x64/ngtcp2.dll'=$null; 'runtime-x64/ngtcp2_crypto_gnutls.dll'=$null}
$expectedSources = @{ "sources-x64/$ngtcp2Dir.tar.gz"=$lock.ngtcp2.sha256;
    "sources-x64/$ngtcp2Dir.tar.gz.asc"=$inventory.ngtcp2.signature_sha256 }
$expectedNotices = @('notices-x64/ngtcp2/COPYING','notices-x64/DISTRIBUTION.md')
foreach ($package in $inventory.packages) {
    foreach ($dll in $package.dlls.PSObject.Properties) {
        $expectedRuntime.Add("runtime-x64/$($dll.Name)", $dll.Value.sha256)
    }
    $expectedSources.Add("sources-x64/$($package.source)", $package.source_sha256)
    $expectedSources.Add("sources-x64/$($package.source)$($inventory.signature_suffix)", $package.source_signature_sha256)
    foreach ($path in $package.binary_license_files) {
        $expectedNotices += 'notices-x64/' + $path.Substring('mingw64/share/licenses/'.Length)
    }
    if (!$package.binary_license_files.Count) {
        $expectedNotices += $package.source_license_files | ForEach-Object { "notices-x64/$_" }
    }
}
Assert-FileSet 'runtime' @($expectedRuntime.Keys) @($runtime.Keys)
Assert-FileSet 'source' @($expectedSources.Keys) @($sources.Keys)
Assert-FileSet 'notice' $expectedNotices @($notices.Keys)
Assert-FileSet 'runtime on disk' @($runtime.Keys) @(Get-PlainTreeFiles 'runtime-x64')
Assert-FileSet 'sources on disk' @($sources.Keys) @(Get-PlainTreeFiles 'sources-x64')
Assert-FileSet 'notices on disk' @($notices.Keys) @(Get-PlainTreeFiles 'notices-x64')

foreach ($path in $expectedRuntime.Keys) {
    if ($expectedRuntime[$path] -and $runtime[$path] -ne $expectedRuntime[$path]) { throw "QUIC DLL differs from the signed inventory: $path" }
}
foreach ($path in $expectedSources.Keys) {
    if ($sources[$path] -ne $expectedSources[$path]) { throw "QUIC source or signature differs from the signed inventory: $path" }
}
if ($notices['notices-x64/DISTRIBUTION.md'] -ne (Get-DependencyHash (Join-Path $repoRoot 'third_party/quic/DISTRIBUTION.md'))) {
    throw 'QUIC distribution notice differs from the repository copy.'
}

$runtimeNames = @($runtime.Keys | ForEach-Object { Split-Path -Leaf $_ })
$importRecords = $manifest.runtime_imports.PSObject.Properties
Assert-FileSet 'import' $runtimeNames @($importRecords.Name)
$windowsImports = @('advapi32.dll','bcrypt.dll','crypt32.dll','kernel32.dll','msvcrt.dll','ncrypt.dll','shell32.dll','ws2_32.dll')
foreach ($record in $importRecords) {
    if (!$record.Value.Count -or @($record.Value | Where-Object { $_ -notin $runtimeNames -and $_ -notin $windowsImports }).Count) {
        throw "QUIC import closure is incomplete for $($record.Name)."
    }
}
Assert-FileSet 'tests' @('abi','loopback-clean','loopback-wrong-alpn','loopback-bad-auth','loopback-loss',
    'native-clean','native-loss','native-bad-auth','native-dco') @($manifest.tests)
if ((Get-DependencyHash $manifestPath) -ne $manifestHash) { throw 'QUIC manifest changed during verification.' }

Write-Host "Verified signed QUIC release dependencies for $Architecture."
if ($PassThru) { $manifest }
