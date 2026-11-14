[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [ValidateSet('x64','Win32')][string]$Architecture = 'x64',
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedManifestSha256,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
$dependencyRoot = (Get-Item -LiteralPath $Root).FullName
$manifestPath = Join-Path $dependencyRoot "manifest-$Architecture.json"
$lockPath = Join-Path $repoRoot 'third_party/quic/dependencies.lock.json'
$inventoryPath = Join-Path $repoRoot "third_party/quic/msys2-gnutls-$($Architecture.ToLowerInvariant())-candidate.json"
$windows32 = $Architecture -eq 'Win32'
$workflow = if ($windows32) { 'build_quic_msys2_win32_release.ps1' } else { 'build_quic_msys2_candidate.ps1' }
$distribution = if ($windows32) { 'DISTRIBUTION-Win32.md' } else { 'DISTRIBUTION.md' }
$msysRoot = if ($windows32) { 'mingw32' } else { 'mingw64' }
$buildDirectory = "build-$Architecture"
$includeDirectory = "include-$Architecture"
$runtimeDirectory = "runtime-$Architecture"
$sourcesDirectory = "sources-$Architecture"
$noticesDirectory = "notices-$Architecture"
$gnutlsImport = "gnutls-$Architecture.lib"
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
    $manifest.workflow_sha256 -ne (Get-DependencyHash (Join-Path $PSScriptRoot $workflow))) {
    throw 'QUIC release manifest does not match the pinned inputs and build workflow.'
}

$links = Read-FileRecords 'link input' @($manifest.link_inputs)
$headers = Read-FileRecords 'header' @($manifest.dependency_headers)
$runtime = Read-FileRecords 'runtime' @($manifest.runtime)
$notices = Read-FileRecords 'notice' @($manifest.notices)
$sources = Read-FileRecords 'source' @($manifest.sources)

Assert-FileSet 'link input' @($gnutlsImport,"$buildDirectory/lib/Release/ngtcp2.lib",
    "$buildDirectory/crypto/gnutls/Release/ngtcp2_crypto_gnutls.lib") @($links.Keys)
if ($links[$gnutlsImport] -ne $inventory.gnutls_import_sha256) { throw 'The GnuTLS import library is not the signed MSYS2 input.' }
$ngtcp2Dir = "ngtcp2-$($lock.ngtcp2.version)"
$expectedHeaders = @(foreach ($headerRoot in @("$ngtcp2Dir/lib/includes","$ngtcp2Dir/crypto/includes","$buildDirectory/lib/includes",$includeDirectory)) {
    Get-PlainTreeFiles $headerRoot | Where-Object { $_ -like '*.h' }
})
Assert-FileSet 'header' $expectedHeaders @($headers.Keys)
foreach ($requiredHeader in @("$ngtcp2Dir/lib/includes/ngtcp2/ngtcp2.h","$ngtcp2Dir/crypto/includes/ngtcp2/ngtcp2_crypto_gnutls.h",
    "$buildDirectory/lib/includes/ngtcp2/version.h","$includeDirectory/gnutls/gnutls.h","$includeDirectory/gnutls/crypto.h")) {
    if (!$headers.ContainsKey($requiredHeader)) { throw "Missing QUIC dependency header: $requiredHeader" }
}

$expectedRuntime = @{ "$runtimeDirectory/ngtcp2.dll"=$null
    "$runtimeDirectory/ngtcp2_crypto_gnutls.dll"=$null }
$expectedSources = @{ "$sourcesDirectory/$ngtcp2Dir.tar.gz"=$lock.ngtcp2.sha256;
    "$sourcesDirectory/$ngtcp2Dir.tar.gz.asc"=$inventory.ngtcp2.signature_sha256 }
$expectedNotices = @("$noticesDirectory/ngtcp2/COPYING","$noticesDirectory/DISTRIBUTION.md")
foreach ($package in $inventory.packages) {
    foreach ($dll in $package.dlls.PSObject.Properties) {
        $expectedRuntime.Add("$runtimeDirectory/$($dll.Name)", $dll.Value.sha256)
    }
    $expectedSources.Add("$sourcesDirectory/$($package.source)", $package.source_sha256)
    $expectedSources.Add("$sourcesDirectory/$($package.source)$($inventory.signature_suffix)", $package.source_signature_sha256)
    foreach ($path in $package.binary_license_files) {
        $expectedNotices += "$noticesDirectory/" + $path.Substring("$msysRoot/share/licenses/".Length)
    }
    if (!$package.binary_license_files.Count) {
        $expectedNotices += $package.source_license_files | ForEach-Object { "$noticesDirectory/$_" }
    }
}
if ($windows32) {
    $rebuiltGnutls = "$runtimeDirectory/libgnutls-30.dll"
    if ($manifest.gnutls_rebuilt_sha256 -ne 'E964569804BBF514069D027BD99BBDA62CDE4C7029D3DEB6A1B3C809A32C883C' -or
        $manifest.gnutls_source_sha256 -ne 'FFED8EC1BF09C2426D4F14AAE377DE4753B53E537D685E604E99A8B16CA9C97E') {
        throw 'Win32 GnuTLS must be rebuilt from the pinned MSYS2 source.'
    }
    $expectedRuntime[$rebuiltGnutls] = $manifest.gnutls_rebuilt_sha256
    $recipeName = 'rebuild_gnutls_win32.sh'
    $lockName = 'gnutls-win32-toolchain.sha256'
    $recipeHash = Get-DependencyHash (Join-Path $repoRoot "third_party/quic/$recipeName")
    $toolchainHash = Get-DependencyHash (Join-Path $repoRoot "third_party/quic/$lockName")
    if ($manifest.gnutls_rebuild_recipe_sha256 -ne $recipeHash -or
        $manifest.gnutls_toolchain_lock_sha256 -ne $toolchainHash) {
        throw 'Win32 GnuTLS recipe or cross-toolchain lock changed.'
    }
    $expectedSources.Add("$sourcesDirectory/$recipeName", $recipeHash)
    $expectedSources.Add("$sourcesDirectory/$lockName", $toolchainHash)
}
Assert-FileSet 'runtime' @($expectedRuntime.Keys) @($runtime.Keys)
Assert-FileSet 'source' @($expectedSources.Keys) @($sources.Keys)
Assert-FileSet 'notice' $expectedNotices @($notices.Keys)
Assert-FileSet 'runtime on disk' @($runtime.Keys) @(Get-PlainTreeFiles $runtimeDirectory)
Assert-FileSet 'sources on disk' @($sources.Keys) @(Get-PlainTreeFiles $sourcesDirectory)
Assert-FileSet 'notices on disk' @($notices.Keys) @(Get-PlainTreeFiles $noticesDirectory)

foreach ($path in $expectedRuntime.Keys) {
    if ($expectedRuntime[$path] -and $runtime[$path] -ne $expectedRuntime[$path]) { throw "QUIC DLL differs from the signed inventory: $path" }
}
foreach ($path in $expectedSources.Keys) {
    if ($sources[$path] -ne $expectedSources[$path]) { throw "QUIC source or signature differs from the signed inventory: $path" }
}
if ($notices["$noticesDirectory/DISTRIBUTION.md"] -ne (Get-DependencyHash (Join-Path $repoRoot "third_party/quic/$distribution"))) {
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
$expectedTests = @('abi','loopback-clean','loopback-wrong-alpn','loopback-bad-auth','loopback-loss',
    'native-clean','native-loss','native-bad-auth','native-dco')
Assert-FileSet 'tests' $expectedTests @($manifest.tests)
if ($windows32) {
    $testLogs = Read-FileRecords 'test log' @($manifest.test_logs)
    Assert-FileSet 'test log' @($expectedTests | ForEach-Object { "$_.log" }) @($testLogs.Keys)
}
if ((Get-DependencyHash $manifestPath) -ne $manifestHash) { throw 'QUIC manifest changed during verification.' }

Write-Host "Verified signed QUIC release dependencies for $Architecture."
if ($PassThru) { $manifest }
