[CmdletBinding()]
param(
    [ValidateSet('Coordinator', 'Peer')][string]$Role = 'Coordinator',
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$PackageZipPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPackageZipSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedHarnessSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCommonSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPrepareNodeSha256,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedEmuleSha256,
    [string]$PeerHostname = '',
    [Parameter(Mandatory = $true)][string]$PeerIPv4,
    [string]$PeerLocalIPv4 = '',
    [Parameter(Mandatory = $true)][string]$PeerIPv6,
    [string]$CoordinatorIPv4 = '',
    [string]$CoordinatorIPv6 = '',
    [Parameter(Mandatory = $true)][string]$CoordinationRoot,
    [Parameter(Mandatory = $true)][switch]$ControlledPeerAcknowledged,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCoordinatorMachineIdSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPeerMachineIdSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCoordinatorUserSidSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPeerUserSidSha256,
    [Parameter(Mandatory = $true)]
    [switch]$DisposableLabAccountAcknowledged,
    [ValidateRange(1024, 65535)][int]$PeerTcpPort = 9462,
    [ValidateRange(1024, 65535)][int]$PeerUdpPort = 9472,
    [ValidateRange(1024, 65535)][int]$PeerWebPort = 9511,
    [ValidateRange(1024, 65535)][int]$ClientTcpPort = 9562,
    [ValidateRange(1024, 65535)][int]$ClientUdpPort = 9572,
    [ValidateRange(1024, 65535)][int]$ClientWebPort = 9611,
    [ValidateRange(67108864, 17179869184)]
    [Int64]$FileSizeBytes = 1073741824,
    [ValidateRange(30, 900)][int]$PeerReadyTimeoutSeconds = 300,
    [ValidateRange(30, 3600)][int]$ScenarioTimeoutSeconds = 2700,
    [ValidateRange(4, 10)][int]$FallbackLimitSeconds = 10,
    [ValidateSet('Manual', 'PowerShellRemoting')]
    [string]$PeerControlMode = 'Manual',
    [string]$PeerComputerName = '',
    [Management.Automation.PSCredential]$PeerCredential,
    [string]$RemoteScriptPath = '',
    [string]$RemotePackagePath = '',
    [string]$RemotePackageZipPath = '',
    [string]$RemoteOutputRoot = '',
    [string]$RemoteCoordinationRoot = '',
    [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunNonce = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Get-I04BootstrapSha256FromStream {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if ($Stream.CanSeek) { $Stream.Position = 0 }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Stream)
    } finally {
        $sha.Dispose()
        if ($Stream.CanSeek) { $Stream.Position = 0 }
    }
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

function Get-I04BootstrapStringSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $stream = [IO.MemoryStream]::new($bytes, $false)
    try { return Get-I04BootstrapSha256FromStream -Stream $stream }
    finally { $stream.Dispose() }
}

if ([string]::IsNullOrWhiteSpace([string]$PSCommandPath)) {
    throw 'I04 physical harness must be invoked as a script file'
}
$script:i04HarnessBundleLocks =
    [Collections.Generic.List[IDisposable]]::new()
$bootstrapFiles = [ordered]@{
    harness = [pscustomobject]@{
        path = [IO.Path]::GetFullPath($PSCommandPath)
        expected = $ExpectedHarnessSha256.ToLowerInvariant()
    }
    common = [pscustomobject]@{
        path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'common.ps1'))
        expected = $ExpectedCommonSha256.ToLowerInvariant()
    }
    prepare_node = [pscustomobject]@{
        path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'prepare_node.ps1'))
        expected = $ExpectedPrepareNodeSha256.ToLowerInvariant()
    }
}
$bootstrapObserved = [ordered]@{}
try {
    foreach ($entry in $bootstrapFiles.GetEnumerator()) {
        $stream = [IO.File]::Open(
            [string]$entry.Value.path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $script:i04HarnessBundleLocks.Add($stream)
        $observed = Get-I04BootstrapSha256FromStream -Stream $stream
        if ($observed -cne [string]$entry.Value.expected) {
            throw "I04 harness bundle hash mismatch: $($entry.Key)"
        }
        $bootstrapObserved[$entry.Key] = $observed
    }
} catch {
    foreach ($stream in @($script:i04HarnessBundleLocks.ToArray())) {
        try { $stream.Dispose() } catch {}
    }
    $script:i04HarnessBundleLocks.Clear()
    throw
}
$bundleCanonical = @(
    'harness=' + [string]$bootstrapObserved.harness
    'common=' + [string]$bootstrapObserved.common
    'prepare_node=' + [string]$bootstrapObserved.prepare_node
) -join "`n"
$script:i04HarnessBundle = [pscustomobject][ordered]@{
    schema = 'ese.v91.i04-harness-bundle/v1'
    harness_sha256 = [string]$bootstrapObserved.harness
    common_sha256 = [string]$bootstrapObserved.common
    prepare_node_sha256 = [string]$bootstrapObserved.prepare_node
    bundle_sha256 = Get-I04BootstrapStringSha256 -Value $bundleCanonical
    immutable_read_locks_held = $true
}
. (Join-Path $PSScriptRoot 'common.ps1')

function Assert-I04ManagedTypeContract {
    param(
        [Parameter(Mandatory = $true)][string]$TypeName,
        [Parameter(Mandatory = $true)][string]$ExpectedContractId
    )

    $type = $TypeName -as [type]
    if ($null -eq $type) {
        throw "Required managed helper type is unavailable: $TypeName"
    }
    $field = $type.GetField(
        'ContractId',
        [Reflection.BindingFlags]::Public -bor
            [Reflection.BindingFlags]::Static
    )
    if ($null -eq $field -or
        [string]$field.GetValue($null) -cne $ExpectedContractId) {
        throw "Managed helper contract mismatch; start a fresh PowerShell process: $TypeName"
    }
    return $true
}

function Open-I04ImmutableEvidenceSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $safePath = Assert-I04NoReparsePath -Path $Path -Kind File
    $stream = [IO.File]::Open(
        $safePath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($stream.Length -gt [int]::MaxValue) {
            throw 'Evidence snapshot exceeds the bounded in-memory parser limit'
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw 'Evidence snapshot ended before its length' }
            $offset += $read
        }
        $memory = [IO.MemoryStream]::new($bytes, $false)
        try { $sha256 = Get-I04Sha256FromStream -Stream $memory }
        finally { $memory.Dispose() }
        $script:i04EvidenceLocks.Add($stream)
        return [pscustomobject][ordered]@{
            bytes = $bytes
            byte_count = [Int64]$bytes.Length
            sha256 = $sha256
            immutable_read_lock_held = $true
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Get-I04Sha256FromStream {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if ($Stream.CanSeek) { $Stream.Position = 0 }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Stream)
    } finally {
        $sha.Dispose()
        if ($Stream.CanSeek) { $Stream.Position = 0 }
    }
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

function Get-I04StringSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $stream = [IO.MemoryStream]::new($bytes, $false)
    try { return Get-I04Sha256FromStream -Stream $stream } finally {
        $stream.Dispose()
    }
}

function Get-I04SafeErrorToken {
    param(
        [Parameter(Mandatory = $true)][string]$Context,
        [AllowEmptyString()][string]$Message = ''
    )
    return '{0} [error_sha256={1}]' -f $Context,
        (Get-I04StringSha256 -Value $Message)
}

function Convert-I04PrivateText {
    param([AllowEmptyString()][string]$Value = '')

    $result = $Value
    $privateRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($rootValue in @(
        $env:USERPROFILE, $PackagePath, $PackageZipPath, $OutputRoot,
        $CoordinationRoot, $RemotePackagePath, $RemotePackageZipPath,
        $RemoteOutputRoot, $RemoteCoordinationRoot
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$rootValue)) { continue }
        if ([IO.Path]::IsPathRooted([string]$rootValue)) {
            $privateRoots.Add([string]$rootValue)
        }
        try { $privateRoots.Add([IO.Path]::GetFullPath([string]$rootValue)) }
        catch {}
    }
    foreach ($rootValue in @($privateRoots.ToArray() |
        Sort-Object Length -Descending -Unique)) {
        if (-not $rootValue) { continue }
        $result = [regex]::Replace(
            $result, [regex]::Escape($rootValue), '<private-path>',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }
    if ($env:USERNAME) {
        $result = [regex]::Replace(
            $result, [regex]::Escape($env:USERNAME), '<private-user>',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }
    return $result
}

function Assert-I04NoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('File', 'Directory')][string]$Kind
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if ($Kind -eq 'File' -and
        -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Required file is not a regular file: $resolved"
    }
    if ($Kind -eq 'Directory' -and
        -not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "Required directory is not a directory: $resolved"
    }
    $cursor = $resolved
    if ($Kind -eq 'File') { $cursor = Split-Path -Parent $cursor }
    $volumeRoot = [IO.Path]::GetPathRoot($cursor).TrimEnd('\')
    while ($cursor -and $cursor.TrimEnd('\') -ne $volumeRoot) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Candidate path crosses a reparse point: $cursor"
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    $leaf = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Candidate leaf is a reparse point: $resolved"
    }
    return $resolved
}

function Assert-I04SafeCreationPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) {
            throw "No existing safe ancestor was found for: $full"
        }
        $cursor = $parent
    }
    $null = Assert-I04NoReparsePath -Path $cursor -Kind Directory
    return $full
}

function Convert-I04SafeRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowTrailingSlash
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or
        $Path.StartsWith('/') -or $Path.Contains(':') -or
        [IO.Path]::IsPathRooted($Path)) {
        throw "Unsafe archive path: '$Path'"
    }
    $normalized = $Path.Normalize([Text.NormalizationForm]::FormC)
    if (-not [StringComparer]::Ordinal.Equals($normalized, $Path)) {
        throw "Archive path is not canonical Unicode NFC: '$Path'"
    }
    $plain = if ($AllowTrailingSlash) { $Path.TrimEnd('/') } else { $Path }
    if (-not $plain -or (-not $AllowTrailingSlash -and $Path.EndsWith('/'))) {
        throw "Unsafe archive file path: '$Path'"
    }
    $segments = @($plain -split '/')
    foreach ($segment in $segments) {
        if (-not $segment -or $segment -in @('.', '..') -or
            $segment -match '[<>:"|?*]' -or
            $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
            throw "Unsafe archive path segment '$segment' in '$Path'"
        }
        $deviceStem = ($segment -split '\.')[0]
        if ($deviceStem -match
            '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw "Reserved Windows device segment '$segment' in '$Path'"
        }
    }
    return $plain
}

function Get-I04SafeTreeFiles {
    param([Parameter(Mandatory = $true)][string]$Root)

    $resolvedRoot = Assert-I04NoReparsePath -Path $Root -Kind Directory
    $rootPrefix = $resolvedRoot.TrimEnd('\') + '\'
    $queue = New-Object 'Collections.Generic.Queue[IO.DirectoryInfo]'
    $queue.Enqueue((Get-Item -LiteralPath $resolvedRoot -Force))
    $files = [Collections.Generic.List[object]]::new()
    $seen = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory.FullName `
            -Force -ErrorAction Stop)) {
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Candidate tree contains a reparse point: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                $queue.Enqueue([IO.DirectoryInfo]$item)
                continue
            }
            if (-not (Test-Path -LiteralPath $item.FullName -PathType Leaf)) {
                throw "Candidate tree contains a non-regular entry: $($item.FullName)"
            }
            $relative = $item.FullName.Substring($rootPrefix.Length).
                Replace('\', '/')
            $relative = Convert-I04SafeRelativePath -Path $relative
            if (-not $seen.Add($relative)) {
                throw "Candidate tree has a case/Unicode path collision: $relative"
            }
            $files.Add([pscustomobject][ordered]@{
                relative_path = $relative
                full_path = $item.FullName
                length = [Int64]$item.Length
            })
        }
    }
    return @($files.ToArray() | Sort-Object relative_path)
}

function Open-I04LockedFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Assert-I04NoReparsePath -Path $Path -Kind File
    # First demand an exclusive open. This fails closed if a pre-existing
    # writer/renamer already owns the candidate. Reopen read-shared so the
    # verified bytes can be copied/executed while writes and deletes stay denied.
    $exclusive = New-Object IO.FileStream(
        $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None
    )
    try {
        $exclusiveHash = Get-I04Sha256FromStream -Stream $exclusive
        $exclusiveLength = $exclusive.Length
    } finally {
        $exclusive.Dispose()
    }
    $locked = New-Object IO.FileStream(
        $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $lockedHash = Get-I04Sha256FromStream -Stream $locked
        if ($lockedHash -ne $exclusiveHash -or
            $locked.Length -ne $exclusiveLength) {
            throw "Candidate changed while its immutable lock was acquired: $resolved"
        }
        $script:i04CandidateLocks.Add($locked)
    } catch {
        $locked.Dispose()
        throw
    }
    return [pscustomobject]@{
        path = $resolved
        length = [Int64]$exclusiveLength
        sha256 = $lockedHash
        stream = $locked
    }
}

function Get-I04CandidateBinding {
    param(
        [Parameter(Mandatory = $true)][string]$DirectoryPath,
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$ExpectedZipSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedExeSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )

    $packageRoot = Assert-I04NoReparsePath -Path $DirectoryPath `
        -Kind Directory
    $zipLock = Open-I04LockedFile -Path $ZipPath
    if ($zipLock.sha256 -ne $ExpectedZipSha256.ToLowerInvariant()) {
        throw "Package ZIP hash mismatch: $($zipLock.sha256)"
    }
    $packageFiles = @(Get-I04SafeTreeFiles -Root $packageRoot)
    if ($packageFiles.Count -eq 0) { throw 'Candidate package is empty' }
    $packageMap = New-Object `
        'Collections.Generic.Dictionary[string,object]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $packageFiles) {
        $locked = Open-I04LockedFile -Path $file.full_path
        $packageMap.Add([string]$file.relative_path, [pscustomobject]@{
            length = [Int64]$locked.length
            sha256 = [string]$locked.sha256
        })
    }

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    $zipLock.stream.Position = 0
    $archive = [IO.Compression.ZipArchive]::new(
        $zipLock.stream, [IO.Compression.ZipArchiveMode]::Read, $true
    )
    try {
        $entryRecords = [Collections.Generic.List[object]]::new()
        $entryNames = New-Object 'Collections.Generic.HashSet[string]' `
            ([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            $isDirectory = $entry.FullName.EndsWith('/')
            $safeName = Convert-I04SafeRelativePath -Path $entry.FullName `
                -AllowTrailingSlash:$isDirectory
            $external = [UInt32]([Int64]$entry.ExternalAttributes -band
                [Int64]0xffffffffL)
            $unixType = (($external -shr 16) -band 0xF000)
            if ($unixType -eq 0xA000 -or ($external -band 0x400) -ne 0) {
                throw "Package ZIP contains a symlink/reparse entry: $safeName"
            }
            if ($isDirectory) { continue }
            if (-not $entryNames.Add($safeName)) {
                throw "Package ZIP has a case/Unicode path collision: $safeName"
            }
            $entryRecords.Add([pscustomobject]@{
                safe_name = $safeName
                entry = $entry
            })
        }
        $exeEntries = @($entryRecords.ToArray() | Where-Object {
            ([string]$_.safe_name).Split('/')[-1] -ieq 'emule.exe'
        })
        if ($exeEntries.Count -ne 1) {
            throw "Package ZIP must contain exactly one emule.exe; found $($exeEntries.Count)"
        }
        $exeEntryName = [string]$exeEntries[0].safe_name
        $zipRootPrefix = $exeEntryName.Substring(
            0, $exeEntryName.Length - 'emule.exe'.Length
        )
        $zipMap = New-Object `
            'Collections.Generic.Dictionary[string,object]' `
            ([StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $entryRecords.ToArray()) {
            $entryName = [string]$record.safe_name
            if (-not $entryName.StartsWith(
                $zipRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "ZIP file entry is outside the candidate root: $entryName"
            }
            $relative = $entryName.Substring($zipRootPrefix.Length)
            $relative = Convert-I04SafeRelativePath -Path $relative
            if ($zipMap.ContainsKey($relative)) {
                throw "ZIP logical-root collision: $relative"
            }
            $entryStream = $record.entry.Open()
            try {
                $entryHash = Get-I04Sha256FromStream -Stream $entryStream
            } finally {
                $entryStream.Dispose()
            }
            $zipMap.Add($relative, [pscustomobject]@{
                length = [Int64]$record.entry.Length
                sha256 = $entryHash
            })
        }
    } finally {
        $archive.Dispose()
        $zipLock.stream.Position = 0
    }

    if ($zipMap.Count -ne $packageMap.Count) {
        throw "ZIP/package file-count mismatch: zip=$($zipMap.Count) directory=$($packageMap.Count)"
    }
    foreach ($relative in @($packageMap.Keys)) {
        if (-not $zipMap.ContainsKey($relative)) {
            throw "Package file is absent from ZIP: $relative"
        }
        if ([Int64]$zipMap[$relative].length -ne
                [Int64]$packageMap[$relative].length -or
            [string]$zipMap[$relative].sha256 -ne
                [string]$packageMap[$relative].sha256) {
            throw "ZIP/package content mismatch: $relative"
        }
    }
    if (-not $packageMap.ContainsKey('emule.exe') -or
        [string]$packageMap['emule.exe'].sha256 -ne
            $ExpectedExeSha256.ToLowerInvariant()) {
        throw 'ZIP/package emule.exe does not match ExpectedEmuleSha256'
    }
    if ($packageMap.ContainsKey('LAB_NODE.json')) {
        throw 'Candidate package may not predefine the harness-owned LAB_NODE.json'
    }

    $candidateInfo = Get-LabCandidateInfo -PackagePath $packageRoot `
        -ExpectedCommit $ExpectedCommit
    if ($candidateInfo.emule_sha256 -ne
        $ExpectedExeSha256.ToLowerInvariant()) {
        throw 'Strict package binding disagrees with BUILD_INFO candidate hash'
    }
    $manifestLines = @($packageMap.Keys | Sort-Object | ForEach-Object {
        '{0}|{1}|{2}' -f $_, $packageMap[$_].length,
            $packageMap[$_].sha256
    })
    return [pscustomobject][ordered]@{
        package_path = $packageRoot
        package_zip_path = $zipLock.path
        package_zip_sha256 = $zipLock.sha256
        package_manifest_sha256 = Get-I04StringSha256 `
            -Value ($manifestLines -join "`n")
        package_file_count = $packageMap.Count
        package_file_hashes = $packageMap
        release = $candidateInfo.release
        version = $candidateInfo.version
        commit = $candidateInfo.commit
        dirty = $candidateInfo.dirty
        emule_sha256 = $candidateInfo.emule_sha256
        ese_server_sha256 = $candidateInfo.ese_server_sha256
        build_info_sha256 = $candidateInfo.build_info_sha256
        immutable_locks_held = $true
    }
}

function Assert-I04CandidateBindingUnchanged {
    param([Parameter(Mandatory = $true)][object]$Binding)

    if ((Get-LabSha256 -Path $Binding.package_zip_path) -ne
        [string]$Binding.package_zip_sha256) {
        throw 'Locked package ZIP changed after binding'
    }
    $files = @(Get-I04SafeTreeFiles -Root $Binding.package_path)
    if ($files.Count -ne [int]$Binding.package_file_count) {
        throw 'Candidate package file set changed after binding'
    }
    $lines = foreach ($file in $files) {
        if (-not $Binding.package_file_hashes.ContainsKey(
            [string]$file.relative_path)) {
            throw "New candidate package file appeared: $($file.relative_path)"
        }
        $hash = Get-LabSha256 -Path $file.full_path
        $expected = $Binding.package_file_hashes[$file.relative_path]
        if ($hash -ne [string]$expected.sha256 -or
            [Int64]$file.length -ne [Int64]$expected.length) {
            throw "Candidate package file changed: $($file.relative_path)"
        }
        '{0}|{1}|{2}' -f $file.relative_path, $file.length, $hash
    }
    $fingerprint = Get-I04StringSha256 -Value (
        @($lines | Sort-Object) -join "`n"
    )
    if ($fingerprint -ne [string]$Binding.package_manifest_sha256) {
        throw 'Candidate package manifest fingerprint changed'
    }
    return $true
}

function Get-I04CandidateEvidence {
    param([Parameter(Mandatory = $true)][object]$Binding)

    return [pscustomobject][ordered]@{
        release = $Binding.release
        version = $Binding.version
        commit = $Binding.commit
        dirty = $Binding.dirty
        emule_sha256 = $Binding.emule_sha256
        ese_server_sha256 = $Binding.ese_server_sha256
        build_info_sha256 = $Binding.build_info_sha256
        package_zip_sha256 = $Binding.package_zip_sha256
        package_manifest_sha256 = $Binding.package_manifest_sha256
        package_file_count = $Binding.package_file_count
        immutable_locks_held = [bool]$Binding.immutable_locks_held
    }
}

function Get-I04StrictAddressClass {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address.Split('%')[0], [ref]$parsed)) {
        return 'invalid'
    }
    $bytes = $parsed.GetAddressBytes()
    if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($bytes[0] -eq 0) { return 'unspecified-or-this-network-v4' }
        if ($bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and
                $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {
            return 'private-v4'
        }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and
            $bytes[1] -le 127) { return 'shared-cgnat-v4' }
        if ($bytes[0] -eq 127) { return 'loopback-v4' }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
            return 'linklocal-v4'
        }
        if (($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and
                ($bytes[2] -in @(0, 2))) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 31 -and
                $bytes[2] -eq 196) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 52 -and
                $bytes[2] -eq 193) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 88 -and
                $bytes[2] -eq 99) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 175 -and
                $bytes[2] -eq 48) -or
            ($bytes[0] -eq 198 -and $bytes[1] -in @(18, 19)) -or
            ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and
                $bytes[2] -eq 100) -or
            ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and
                $bytes[2] -eq 113)) {
            return 'special-purpose-v4'
        }
        if ($bytes[0] -ge 224) { return 'multicast-or-reserved-v4' }
        return 'public-unicast-v4'
    }
    if ($parsed.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6 -or
        $parsed.IsIPv4MappedToIPv6) { return 'non-native-v6' }
    if ([Net.IPAddress]::IsLoopback($parsed)) { return 'loopback-v6' }
    if ($parsed.IsIPv6LinkLocal) { return 'linklocal-v6' }
    if ($parsed.IsIPv6Multicast) { return 'multicast-v6' }
    if (($bytes[0] -band 0xfe) -eq 0xfc) { return 'ula-v6' }
    if (($bytes[0] -band 0xe0) -ne 0x20) {
        return 'non-global-unicast-v6'
    }
    # Reject transition/documentation/IETF-special blocks even though they sit
    # inside 2000::/3. I04 requires a native provider-routed IPv6 endpoint.
    if (($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and
            $bytes[2] -le 0x01) -or
        ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and
            $bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8) -or
        ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x02) -or
        ($bytes[0] -eq 0x3f -and $bytes[1] -eq 0xfe) -or
        ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and
            $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x04 -and
            $bytes[4] -eq 0x01 -and $bytes[5] -eq 0x12) -or
        ($bytes[0] -eq 0x26 -and $bytes[1] -eq 0x20 -and
            $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x4f -and
            $bytes[4] -eq 0x80 -and $bytes[5] -eq 0x00) -or
        ($bytes[0] -eq 0x3f -and $bytes[1] -eq 0xff -and
            ($bytes[2] -band 0xf0) -eq 0)) {
        return 'transition-or-documentation-v6'
    }
    return 'native-global-v6'
}

function Test-I04UsableLocalIPv4 {
    param([Parameter(Mandatory = $true)][string]$Address)
    return (Get-I04StrictAddressClass -Address $Address) -in @(
        'private-v4', 'shared-cgnat-v4', 'public-unicast-v4'
    )
}

function New-I04EphemeralSecret {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([Convert]::ToBase64String($bytes)).TrimEnd('=').
        Replace('+', '-').Replace('/', '_')
}

function Assert-I04PortsInitiallyFree {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()][int[]]$Ports,
        [Parameter(Mandatory = $true)][string]$HostRole
    )

    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop)
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop)
    } catch {
        throw (Get-I04SafeErrorToken `
            -Context "$HostRole port ownership could not be enumerated" `
            -Message $_.Exception.Message)
    }
    $collisions = [System.Collections.Generic.List[object]]::new()
    foreach ($port in @($Ports | Sort-Object -Unique)) {
        foreach ($endpoint in @($tcp | Where-Object {
            [int]$_.LocalPort -eq $port
        })) {
            $collisions.Add([pscustomobject][ordered]@{
                protocol = 'TCP'
                port = $port
                owning_process = [int]$endpoint.OwningProcess
                state = [string]$endpoint.State
            })
        }
        foreach ($endpoint in @($udp | Where-Object {
            [int]$_.LocalPort -eq $port
        })) {
            $collisions.Add([pscustomobject][ordered]@{
                protocol = 'UDP'
                port = $port
                owning_process = [int]$endpoint.OwningProcess
                state = 'Bound'
            })
        }
    }
    if ($collisions.Count -gt 0) {
        $description = @($collisions.ToArray() | ForEach-Object {
            "$($_.protocol)/$($_.port)/PID$($_.owning_process)/$($_.state)"
        }) -join ', '
        throw "$HostRole configured ports were already owned: $description"
    }
    return [pscustomobject][ordered]@{
        checked_at_utc = Get-LabUtcTimestamp
        role = $HostRole
        ports = @($Ports | Sort-Object -Unique)
        collisions = @()
        all_free = $true
    }
}

function Get-I04TerminalOwnershipCensus {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][int[]]$ProcessIds,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][object[]]$OwnedProcesses,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()][int[]]$Ports,
        [Parameter(Mandatory = $true)][string]$HostRole
    )

    $descendantAudits = [System.Collections.Generic.List[object]]::new()
    try {
        $allProcesses = @(Get-Process -ErrorAction Stop)
        $allTcp = @(Get-NetTCPConnection -ErrorAction Stop)
        $allUdp = @(Get-NetUDPEndpoint -ErrorAction Stop)
        $descendantCollectorOk = $true
        $descendantsClear = $true
        foreach ($ownedProcess in $OwnedProcesses) {
            $required = @(
                'i04_owner_pid', 'i04_owner_cim_creation_utc_ticks',
                'i04_descendant_collector_failed',
                'i04_descendant_root_identity_contradicted',
                'i04_descendant_observed',
                'i04_descendant_observed_process_ids',
                'i04_descendant_error_sha256',
                'i04_descendant_last_census',
                'i04_job_contract_id', 'i04_job_active_process_limit',
                'i04_job_assigned_before_resume',
                'i04_job_last_accounting'
            )
            $bindingPresent = @($required | Where-Object {
                $ownedProcess.PSObject.Properties.Name -notcontains $_
            }).Count -eq 0
            if (-not $bindingPresent) {
                $descendantsClear = $false
                $descendantAudits.Add([pscustomobject][ordered]@{
                    ownership_binding_present = $false
                    root_process_id = [int]$ownedProcess.Id
                    root_creation_utc_ticks = $null
                    collector_ok = $false
                    root_identity_exact = $false
                    descendant_observed = $false
                    descendant_process_ids = @()
                    restricted_job_accounting = $null
                    clear = $false
                })
                $descendantCollectorOk = $false
                continue
            }
            $auditClear = Test-I04OwnedProcessDescendants `
                -Process $ownedProcess -RootMayHaveExited
            $collectorOk =
                -not [bool]$ownedProcess.i04_descendant_collector_failed
            $rootExact = -not [bool]$ownedProcess.
                i04_descendant_root_identity_contradicted
            $observed = [bool]$ownedProcess.i04_descendant_observed
            $descendantAudits.Add([pscustomobject][ordered]@{
                ownership_binding_present = $true
                root_process_id = [int]$ownedProcess.i04_owner_pid
                root_creation_utc_ticks =
                    [Int64]$ownedProcess.i04_owner_cim_creation_utc_ticks
                collector_ok = $collectorOk
                collector_error_sha256 =
                    [string]$ownedProcess.i04_descendant_error_sha256
                root_identity_exact = $rootExact
                descendant_observed = $observed
                descendant_process_ids = @(
                    $ownedProcess.i04_descendant_observed_process_ids
                )
                last_census = $ownedProcess.i04_descendant_last_census
                restricted_job_accounting =
                    $ownedProcess.i04_job_last_accounting
                clear = [bool]$auditClear
            })
            if (-not $collectorOk) { $descendantCollectorOk = $false }
            if (-not $auditClear) { $descendantsClear = $false }
        }
        $remainingProcesses = @($allProcesses | Where-Object {
            [int]$_.Id -in $ProcessIds
        } | ForEach-Object {
            [pscustomobject][ordered]@{ process_id = [int]$_.Id }
        })
        $tcp = @($allTcp | Where-Object {
            [int]$_.OwningProcess -in $ProcessIds -or
            [int]$_.LocalPort -in $Ports
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                owning_process = [int]$_.OwningProcess
                local_port = [int]$_.LocalPort
                remote_port = [int]$_.RemotePort
                state = [string]$_.State
            }
        })
        $udp = @($allUdp | Where-Object {
            [int]$_.OwningProcess -in $ProcessIds -or
            [int]$_.LocalPort -in $Ports
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                owning_process = [int]$_.OwningProcess
                local_port = [int]$_.LocalPort
            }
        })
        return [pscustomobject][ordered]@{
            collected_at_utc = Get-LabUtcTimestamp
            role = $HostRole
            collector_ok = $descendantCollectorOk
            collector_error = $null
            process_ids = @($ProcessIds | Sort-Object -Unique)
            ports = @($Ports | Sort-Object -Unique)
            remaining_processes = $remainingProcesses
            remaining_tcp = $tcp
            remaining_udp = $udp
            descendant_census = $descendantAudits.ToArray()
            all_clear = $descendantCollectorOk -and $descendantsClear -and
                $remainingProcesses.Count -eq 0 -and $tcp.Count -eq 0 -and
                $udp.Count -eq 0
        }
    } catch {
        return [pscustomobject][ordered]@{
            collected_at_utc = Get-LabUtcTimestamp
            role = $HostRole
            collector_ok = $false
            collector_error = Get-I04SafeErrorToken `
                -Context "$HostRole terminal ownership census failed" `
                -Message $_.Exception.Message
            process_ids = @($ProcessIds | Sort-Object -Unique)
            ports = @($Ports | Sort-Object -Unique)
            remaining_processes = @()
            remaining_tcp = @()
            remaining_udp = @()
            descendant_census = $descendantAudits.ToArray()
            all_clear = $false
        }
    }
}

function Lock-I04PreparedNodeCode {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ExpectedExeSha256
    )

    $root = Assert-I04NoReparsePath -Path $NodePath -Kind Directory
    $codeFiles = @(Get-I04SafeTreeFiles -Root $root | Where-Object {
        [IO.Path]::GetExtension([string]$_.relative_path) -in @('.exe', '.dll')
    })
    $exeFiles = @($codeFiles | Where-Object {
        [string]$_.relative_path -ieq 'emule.exe'
    })
    if ($exeFiles.Count -ne 1) {
        throw "Prepared node must contain exactly one root emule.exe; found $($exeFiles.Count)"
    }
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $codeFiles) {
        $lock = Open-I04LockedFile -Path $file.full_path
        $records.Add([pscustomobject][ordered]@{
            relative_path_sha256 = Get-I04StringSha256 -Value (
                [string]$file.relative_path
            )
            length = [Int64]$lock.length
            sha256 = [string]$lock.sha256
        })
    }
    $exe = @($records.ToArray() | Where-Object {
        [string]$_.sha256 -eq $ExpectedExeSha256.ToLowerInvariant() -and
        [Int64]$_.length -eq [Int64]$exeFiles[0].length
    })
    $rootExeHash = Get-LabSha256 -Path (Join-Path $root 'emule.exe')
    if ($rootExeHash -ne $ExpectedExeSha256.ToLowerInvariant()) {
        throw 'Prepared node emule.exe does not match the mandatory candidate hash'
    }
    return [pscustomobject][ordered]@{
        executable_sha256 = $rootExeHash
        code_module_count = $records.Count
        code_modules = @($records.ToArray())
        immutable_code_locks_held = $true
    }
}

function Assert-I04PreparedNodeDerivedFromBinding {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][object]$Binding
    )

    $files = @(Get-I04SafeTreeFiles -Root $NodePath)
    if ($files.Count -ne ([int]$Binding.package_file_count + 1)) {
        throw 'Prepared node file set is not exactly package plus LAB_NODE.json'
    }
    $seen = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $files) {
        $relative = [string]$file.relative_path
        if ($relative -ieq 'LAB_NODE.json') { continue }
        if (-not $Binding.package_file_hashes.ContainsKey($relative)) {
            throw "Prepared node contains a file outside the bound package: $relative"
        }
        $null = $seen.Add($relative)
        if ($relative -ieq 'config/preferences.ini') { continue }
        $expected = $Binding.package_file_hashes[$relative]
        if ([Int64]$file.length -ne [Int64]$expected.length -or
            (Get-LabSha256 -Path $file.full_path) -ne
                [string]$expected.sha256) {
            throw "Prepared node file differs from the bound package: $relative"
        }
    }
    foreach ($relative in @($Binding.package_file_hashes.Keys)) {
        if (-not $seen.Contains([string]$relative)) {
            throw "Prepared node omitted a bound package file: $relative"
        }
    }
    return $true
}

function Get-I04CurrentHostIdentity {
    $machineGuidText = [string](Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
        -Name MachineGuid -ErrorAction Stop).MachineGuid
    $machineGuid = [Guid]::Empty
    if (-not [Guid]::TryParse($machineGuidText, [ref]$machineGuid) -or
        $machineGuid -eq [Guid]::Empty) {
        throw 'MachineGuid is absent or invalid; host identity is unprovable'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) {
        throw 'Current Windows account has no SID'
    }
    $sid = $identity.User.Value
    if ($sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -or
        $sid -match '-500$') {
        throw 'Built-in Administrator/service identities are forbidden; use the acknowledged disposable lab account'
    }
    $profile = Assert-I04NoReparsePath -Path $env:USERPROFILE -Kind Directory
    return [pscustomobject][ordered]@{
        machine_id_sha256 = Get-I04StringSha256 `
            -Value $machineGuid.ToString('D').ToLowerInvariant()
        user_sid = $sid
        user_sid_sha256 = Get-I04StringSha256 -Value $sid
        account_name_sha256 = Get-I04StringSha256 -Value $identity.Name
        profile_path_sha256 = Get-I04StringSha256 -Value (
            [IO.Path]::GetFullPath($profile).ToLowerInvariant()
        )
        builtin_or_service = $false
        disposable_account_operator_attested = $true
    }
}

function Get-I04HostIdentityEvidence {
    return [pscustomobject][ordered]@{
        machine_id_sha256 = $script:i04HostIdentity.machine_id_sha256
        user_sid_sha256 = $script:i04HostIdentity.user_sid_sha256
        account_name_sha256 = $script:i04HostIdentity.account_name_sha256
        profile_path_sha256 = $script:i04HostIdentity.profile_path_sha256
        builtin_or_service = $script:i04HostIdentity.builtin_or_service
        disposable_account_operator_attested =
            $script:i04HostIdentity.disposable_account_operator_attested
    }
}

function ConvertTo-I04RegistryValueCanonical {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [byte[]]) {
        return 'bytes:' + [Convert]::ToBase64String([byte[]]$Value)
    }
    if ($Value -is [string[]]) {
        return 'multi:' + (@([string[]]$Value | ForEach-Object {
                    ([string]$_).Length.ToString(
                        [Globalization.CultureInfo]::InvariantCulture) + ':' +
                        [string]$_
                }) -join '|')
    }
    if ($Value -is [string]) {
        return 'string:' + ([string]$Value).Length.ToString(
            [Globalization.CultureInfo]::InvariantCulture) + ':' +
            [string]$Value
    }
    if ($Value -is [int] -or $Value -is [Int64]) {
        return 'integer:' + ([IConvertible]$Value).ToString(
            [Globalization.CultureInfo]::InvariantCulture)
    }
    throw "Unsupported registry value type: $($Value.GetType().FullName)"
}

function Get-I04RegistrySubtreeSnapshotOnce {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [AllowEmptyString()][string]$TrackedRootValueName = ''
    )

    $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $RelativePath, $false)
    if ($null -eq $root) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-registry-subtree/v2'
            path_sha256 = Get-I04StringSha256 -Value $RelativePath
            exists = $false
            node_count = 0
            value_count = 0
            tracked_root_value_count = 0
            canonical_sha256 = Get-I04StringSha256 -Value 'absent'
        }
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $state = [pscustomobject]@{ node_count = 0; value_count = 0 }
    $visit = $null
    $visit = {
        param(
            [Parameter(Mandatory = $true)]
            [Microsoft.Win32.RegistryKey]$Key,
            [Parameter(Mandatory = $true)][string]$LogicalPath
        )

        $state.node_count++
        $lines.Add(('K|{0}' -f $LogicalPath.ToLowerInvariant()))
        $valueNames = @($Key.GetValueNames() | Sort-Object)
        $subkeyNames = @($Key.GetSubKeyNames() | Sort-Object)
        foreach ($valueName in $valueNames) {
            $kind = $Key.GetValueKind([string]$valueName)
            $value = $Key.GetValue(
                [string]$valueName, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $canonicalValue = ConvertTo-I04RegistryValueCanonical -Value $value
            $valueAgain = $Key.GetValue(
                [string]$valueName, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($kind -ne $Key.GetValueKind([string]$valueName) -or
                $canonicalValue -cne
                    (ConvertTo-I04RegistryValueCanonical -Value $valueAgain)) {
                throw 'Registry value changed during fail-closed capture'
            }
            $lines.Add(('V|{0}|{1}|{2}' -f
                    ([string]$valueName).ToLowerInvariant(), [string]$kind,
                    (Get-I04StringSha256 -Value $canonicalValue)))
            $state.value_count++
        }
        foreach ($subkeyName in $subkeyNames) {
            $child = $Key.OpenSubKey([string]$subkeyName, $false)
            if ($null -eq $child) {
                throw 'Registry subtree changed during fail-closed capture'
            }
            try {
                & $visit -Key $child `
                    -LogicalPath ($LogicalPath + '\' + [string]$subkeyName)
            } finally { $child.Dispose() }
        }
        if ((@($Key.GetValueNames() | Sort-Object) -join "`n") -cne
                ($valueNames -join "`n") -or
            (@($Key.GetSubKeyNames() | Sort-Object) -join "`n") -cne
                ($subkeyNames -join "`n")) {
            throw 'Registry subtree names changed during fail-closed capture'
        }
    }

    try {
        $trackedCount = if ([string]::IsNullOrEmpty($TrackedRootValueName)) {
            0
        } else {
            @($root.GetValueNames() | Where-Object {
                    [string]$_ -ieq $TrackedRootValueName
                }).Count
        }
        & $visit -Key $root -LogicalPath $RelativePath
    } finally { $root.Dispose() }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-registry-subtree/v2'
        path_sha256 = Get-I04StringSha256 -Value $RelativePath
        exists = $true
        node_count = [int]$state.node_count
        value_count = [int]$state.value_count
        tracked_root_value_count = [int]$trackedCount
        canonical_sha256 = Get-I04StringSha256 -Value ($lines -join "`n")
    }
}

function Test-I04RegistrySubtreeSnapshotEqual {
    param(
        [Parameter(Mandatory = $true)]$Left,
        [Parameter(Mandatory = $true)]$Right
    )

    return [string]$Left.schema -ceq [string]$Right.schema -and
        [string]$Left.path_sha256 -ceq [string]$Right.path_sha256 -and
        [bool]$Left.exists -eq [bool]$Right.exists -and
        [int]$Left.node_count -eq [int]$Right.node_count -and
        [int]$Left.value_count -eq [int]$Right.value_count -and
        [int]$Left.tracked_root_value_count -eq
            [int]$Right.tracked_root_value_count -and
        [string]$Left.canonical_sha256 -ceq [string]$Right.canonical_sha256
}

function Get-I04RegistrySubtreeSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [AllowEmptyString()][string]$TrackedRootValueName = ''
    )

    $first = Get-I04RegistrySubtreeSnapshotOnce `
        -RelativePath $RelativePath `
        -TrackedRootValueName $TrackedRootValueName
    $second = Get-I04RegistrySubtreeSnapshotOnce `
        -RelativePath $RelativePath `
        -TrackedRootValueName $TrackedRootValueName
    if (-not (Test-I04RegistrySubtreeSnapshotEqual `
            -Left $first -Right $second)) {
        throw 'Registry subtree was not stable across the baseline capture'
    }
    return $second
}

function ConvertTo-I04FirewallValueCanonical {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [Array]) {
        [string[]]$members = @($Value | ForEach-Object {
                ConvertTo-I04FirewallValueCanonical -Value $_
            })
        [Array]::Sort($members, [StringComparer]::Ordinal)
        return 'array:[' + ($members -join ',') + ']'
    }
    if ($Value -is [string]) {
        return 'string:' + ([string]$Value).Length.ToString(
            [Globalization.CultureInfo]::InvariantCulture) + ':' +
            [string]$Value
    }
    if ($Value -is [bool]) {
        return 'bool:' + ([bool]$Value).ToString().ToLowerInvariant()
    }
    if ($Value -is [DateTime]) {
        return 'datetime:' + ([DateTime]$Value).ToUniversalTime().ToString('o')
    }
    if ($Value -is [Guid]) {
        return 'guid:' + ([Guid]$Value).ToString('D').ToLowerInvariant()
    }
    if ($Value -is [IFormattable]) {
        return $Value.GetType().FullName + ':' +
            ([IFormattable]$Value).ToString(
                $null, [Globalization.CultureInfo]::InvariantCulture)
    }
    return $Value.GetType().FullName + ':' + [string]$Value
}

function Get-I04FirewallCimCanonical {
    param([Parameter(Mandatory = $true)]$Instance)

    $properties = @($Instance.CimInstanceProperties)
    if ($properties.Count -eq 0) {
        throw 'Firewall collector returned an object without CIM properties'
    }
    [string[]]$lines = @($properties | Sort-Object Name | ForEach-Object {
            '{0}|{1}|{2}' -f ([string]$_.Name).ToLowerInvariant(),
                [string]$_.CimType,
                (ConvertTo-I04FirewallValueCanonical -Value $_.Value)
        })
    return $lines -join "`n"
}

function Get-I04GlobalFirewallSnapshotOnce {
    $collectors = [ordered]@{
        rules = 'Get-NetFirewallRule'
        port_filters = 'Get-NetFirewallPortFilter'
        application_filters = 'Get-NetFirewallApplicationFilter'
        address_filters = 'Get-NetFirewallAddressFilter'
        interface_filters = 'Get-NetFirewallInterfaceFilter'
        interface_type_filters = 'Get-NetFirewallInterfaceTypeFilter'
        service_filters = 'Get-NetFirewallServiceFilter'
        security_filters = 'Get-NetFirewallSecurityFilter'
    }
    $categories = [ordered]@{}
    [string[]]$aggregateLines = @()
    foreach ($entry in $collectors.GetEnumerator()) {
        $command = Get-Command -Name $entry.Value -ErrorAction Stop
        $items = @(& $command -PolicyStore ActiveStore -ErrorAction Stop)
        if ($items.Count -eq 0) {
            throw "Global firewall collector returned no $($entry.Key)"
        }
        [string[]]$records = @($items | ForEach-Object {
                Get-I04FirewallCimCanonical -Instance $_
            })
        [Array]::Sort($records, [StringComparer]::Ordinal)
        $digest = Get-I04StringSha256 -Value ($records -join "`n--ITEM--`n")
        $categories[$entry.Key] = [pscustomobject][ordered]@{
            item_count = $items.Count
            canonical_sha256 = $digest
        }
        $aggregateLines += ('{0}|{1}|{2}' -f $entry.Key,
            $items.Count, $digest)
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-global-firewall-snapshot/v2'
        captured_at_utc = Get-LabUtcTimestamp
        policy_store = 'ActiveStore'
        privacy_safe = $true
        categories = [pscustomobject]$categories
        canonical_sha256 = Get-I04StringSha256 -Value (
            $aggregateLines -join "`n")
    }
}

function Get-I04GlobalFirewallSnapshot {
    $first = Get-I04GlobalFirewallSnapshotOnce
    $second = Get-I04GlobalFirewallSnapshotOnce
    if ([string]$first.schema -cne [string]$second.schema -or
        [string]$first.policy_store -cne [string]$second.policy_store -or
        [string]$first.canonical_sha256 -cne
            [string]$second.canonical_sha256) {
        throw 'Global firewall inventory was not stable across capture'
    }
    return $second
}

function Get-I04AccountRegistrySnapshot {
    param([Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'Current Windows account SID is unavailable for registry capture'
    }
    $sidHash = Get-I04StringSha256 -Value ([string]$identity.User.Value)
    if ($sidHash -cne $ExpectedUserSidSha256.ToLowerInvariant()) {
        throw 'Registry capture account SID differs from the bound lab account'
    }
    $run = Get-I04RegistrySubtreeSnapshot `
        -RelativePath 'Software\Microsoft\Windows\CurrentVersion\Run' `
        -TrackedRootValueName 'eMuleAutoStart'
    $ed2k = Get-I04RegistrySubtreeSnapshot `
        -RelativePath 'Software\Classes\ed2k'
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-account-registry-snapshot/v2'
        captured_at_utc = Get-LabUtcTimestamp
        user_sid_sha256 = $sidHash
        run_subtree = $run
        ed2k_subtree = $ed2k
        emule_autostart_absent =
            [int]$run.tracked_root_value_count -eq 0
        ed2k_subtree_absent = -not [bool]$ed2k.exists
    }
}

function Start-I04AccountRegistryTransaction {
    param([Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256)

    $baseline = Get-I04AccountRegistrySnapshot `
        -ExpectedUserSidSha256 $ExpectedUserSidSha256
    if (-not [bool]$baseline.run_subtree.exists -or
        -not [bool]$baseline.emule_autostart_absent -or
        -not [bool]$baseline.ed2k_subtree_absent) {
        throw 'I04 requires the HKCU Run key to exist and eMuleAutoStart/the HKCU ed2k subtree to be absent before mutation'
    }
    $firewallBaseline = Get-I04GlobalFirewallSnapshot
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-account-registry-transaction/v2'
        expected_user_sid_sha256 = $ExpectedUserSidSha256.ToLowerInvariant()
        disposable_lab_account_attested = $true
        baseline = $baseline
        global_firewall_baseline = $firewallBaseline
        initial_absence_proved = $true
        destructive_restore_permitted = $false
    }
}

function Get-I04AccountRegistryPostcheckEvidence {
    param([Parameter(Mandatory = $true)]$Transaction)

    try {
        $after = Get-I04AccountRegistrySnapshot `
            -ExpectedUserSidSha256 (
                [string]$Transaction.expected_user_sid_sha256)
        $runUnchanged = Test-I04RegistrySubtreeSnapshotEqual `
            -Left $Transaction.baseline.run_subtree `
            -Right $after.run_subtree
        $ed2kUnchanged = Test-I04RegistrySubtreeSnapshotEqual `
            -Left $Transaction.baseline.ed2k_subtree `
            -Right $after.ed2k_subtree
        $firewallAfter = Get-I04GlobalFirewallSnapshot
        $firewallUnchanged = [string]$firewallAfter.canonical_sha256 -ceq
            [string]$Transaction.global_firewall_baseline.canonical_sha256
        $safe = $runUnchanged -and $ed2kUnchanged -and $firewallUnchanged -and
            [string]$after.user_sid_sha256 -ceq
                [string]$Transaction.expected_user_sid_sha256 -and
            [bool]$Transaction.baseline.run_subtree.exists -and
            [bool]$after.run_subtree.exists -and
            [bool]$after.emule_autostart_absent -and
            [bool]$after.ed2k_subtree_absent
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-account-registry-postcheck/v2'
            collector_ok = $true
            baseline = $Transaction.baseline
            post_state = $after
            global_firewall_baseline = $Transaction.global_firewall_baseline
            global_firewall_post_state = $firewallAfter
            bound_sid_unchanged = [string]$after.user_sid_sha256 -ceq
                [string]$Transaction.expected_user_sid_sha256
            run_subtree_unchanged = $runUnchanged
            run_subtree_existed_before =
                [bool]$Transaction.baseline.run_subtree.exists
            run_subtree_exists_after = [bool]$after.run_subtree.exists
            ed2k_subtree_unchanged = $ed2kUnchanged
            global_firewall_unchanged = $firewallUnchanged
            emule_autostart_absent_after =
                [bool]$after.emule_autostart_absent
            ed2k_subtree_absent_after = [bool]$after.ed2k_subtree_absent
            destructive_restore_attempted = $false
            nonce_owned_firewall_cleanup_only = $true
            safe_to_pass = $safe
            error = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-account-registry-postcheck/v2'
            collector_ok = $false
            baseline = $Transaction.baseline
            post_state = $null
            global_firewall_baseline = $Transaction.global_firewall_baseline
            global_firewall_post_state = $null
            bound_sid_unchanged = $false
            run_subtree_unchanged = $false
            run_subtree_existed_before =
                [bool]$Transaction.baseline.run_subtree.exists
            run_subtree_exists_after = $false
            ed2k_subtree_unchanged = $false
            global_firewall_unchanged = $false
            emule_autostart_absent_after = $false
            ed2k_subtree_absent_after = $false
            destructive_restore_attempted = $false
            nonce_owned_firewall_cleanup_only = $true
            safe_to_pass = $false
            error = Get-I04SafeErrorToken `
                -Context 'account/registry postcheck collector failed' `
                -Message $_.Exception.Message
        }
    }
}

function Assert-I04DisjointOperationalPaths {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryDirectory,
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$PackageZip,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$CoordinationDirectory
    )

    $entries = @(
        [pscustomobject]@{ name = 'repository'; path = $RepositoryDirectory; directory = $true },
        [pscustomobject]@{ name = 'package'; path = $PackageDirectory; directory = $true },
        [pscustomobject]@{ name = 'package_zip'; path = $PackageZip; directory = $false },
        [pscustomobject]@{ name = 'output'; path = $OutputDirectory; directory = $true },
        [pscustomobject]@{ name = 'coordination'; path = $CoordinationDirectory; directory = $true }
    )
    foreach ($entry in $entries) {
        if ([string]::IsNullOrWhiteSpace([string]$entry.path)) {
            throw "I04 operational path is empty: $($entry.name)"
        }
        $entry.path = [IO.Path]::GetFullPath([string]$entry.path).TrimEnd('\')
    }
    for ($leftIndex = 0; $leftIndex -lt $entries.Count; $leftIndex++) {
        for ($rightIndex = $leftIndex + 1;
            $rightIndex -lt $entries.Count; $rightIndex++) {
            $left = $entries[$leftIndex]
            $right = $entries[$rightIndex]
            $equal = [string]::Equals(
                [string]$left.path, [string]$right.path,
                [StringComparison]::OrdinalIgnoreCase)
            $leftContainsRight = [bool]$left.directory -and
                ([string]$right.path).StartsWith(
                    ([string]$left.path) + '\',
                    [StringComparison]::OrdinalIgnoreCase)
            $rightContainsLeft = [bool]$right.directory -and
                ([string]$left.path).StartsWith(
                    ([string]$right.path) + '\',
                    [StringComparison]::OrdinalIgnoreCase)
            if ($equal -or $leftContainsRight -or $rightContainsLeft) {
                throw "I04 operational roots overlap: $($left.name)/$($right.name)"
            }
        }
    }
    return $true
}

$script:i04CandidateLocks = [Collections.Generic.List[IDisposable]]::new()
$script:i04EvidenceLocks = [Collections.Generic.List[IDisposable]]::new()
$script:i04RestrictedJobPids = New-Object 'Collections.Generic.HashSet[int]'
$script:i04RestrictedJobLeaseCleanup = $null
$script:i04PeerTerminalReceiptPath = $null
$script:i04PeerResultSha256 = ''
$script:i04CoordinatorPublication = $null
$script:i04RoleCompleted = $false
$script:i04PktmonMutex = $null
$script:i04PktmonMutexEvidence = $null
$script:i04PreferenceContracts = New-Object `
    'Collections.Generic.Dictionary[string,object]' `
    ([StringComparer]::OrdinalIgnoreCase)
$script:i04AccountRegistryTransaction = $null
$script:i04AccountRegistryPostcheck = $null
$script:i04AccountRegistryPostcheckComplete = $false
$i04TerminalRegistryFailure = $null
$i04TerminalJobFailure = $null
$i04TerminalPktmonFailure = $null
$i04TerminalLockFailure = $null
try {
$caseId = 'V91-I04'
$expectedHash = $ExpectedEmuleSha256.ToLowerInvariant()
$expectedZipHash = $ExpectedPackageZipSha256.ToLowerInvariant()
if ($ExpectedCoordinatorMachineIdSha256 -ieq $ExpectedPeerMachineIdSha256) {
    throw 'I04 requires two distinct bound physical machine identities'
}
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$null = Assert-I04DisjointOperationalPaths `
    -RepositoryDirectory $repositoryRoot `
    -PackageDirectory $PackagePath -PackageZip $PackageZipPath `
    -OutputDirectory $OutputRoot -CoordinationDirectory $CoordinationRoot
$preexistingEmuleProcesses = @(
    Get-Process -ErrorAction Stop | Where-Object {
        [string]$_.ProcessName -ieq 'emule'
    }
)
if ($preexistingEmuleProcesses.Count -ne 0) {
    throw 'I04 requires zero pre-existing eMule processes before either role starts'
}
$preexistingEmuleProcessCount = 0
$candidate = Get-I04CandidateBinding -DirectoryPath $PackagePath `
    -ZipPath $PackageZipPath -ExpectedZipSha256 $expectedZipHash `
    -ExpectedExeSha256 $expectedHash -ExpectedCommit $Commit
if ($candidate.emule_sha256 -ne $expectedHash) {
    throw "Candidate hash mismatch: package=$($candidate.emule_sha256) expected=$expectedHash"
}
if (-not $ControlledPeerAcknowledged) {
    throw 'I04 may only target a peer controlled by, or explicitly authorized for, the operator'
}
if (-not $DisposableLabAccountAcknowledged) {
    throw 'I04 requires an explicitly acknowledged disposable lab account on both hosts'
}
$expectedCoordinatorSidHash =
    $ExpectedCoordinatorUserSidSha256.ToLowerInvariant()
$expectedPeerSidHash = $ExpectedPeerUserSidSha256.ToLowerInvariant()
$script:i04HostIdentity = Get-I04CurrentHostIdentity
$expectedLocalMachine = if ($Role -eq 'Peer') {
    $ExpectedPeerMachineIdSha256.ToLowerInvariant()
} else { $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant() }
$expectedLocalSid = if ($Role -eq 'Peer') {
    $expectedPeerSidHash
} else { $expectedCoordinatorSidHash }
if ([string]$script:i04HostIdentity.machine_id_sha256 -ne
        $expectedLocalMachine -or
    [string]$script:i04HostIdentity.user_sid_sha256 -ne $expectedLocalSid) {
    throw 'Current host/account identity does not match the mandatory campaign binding'
}
$script:i04AccountRegistryTransaction =
    Start-I04AccountRegistryTransaction `
        -ExpectedUserSidSha256 $expectedLocalSid

$canonicalHostname = $PeerHostname.Trim().TrimEnd('.').ToLowerInvariant()
if ($canonicalHostname -and (
    [Uri]::CheckHostName($canonicalHostname) -ne [UriHostNameType]::Dns -or
    $canonicalHostname.IndexOfAny([char[]]'|,[]:') -ge 0
)) {
    throw "Optional PeerHostname is not a valid DNS name: '$PeerHostname'"
}

$peerV4Address = $null
if (-not [Net.IPAddress]::TryParse($PeerIPv4, [ref]$peerV4Address) -or
    $peerV4Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw "PeerIPv4 is not an IPv4 address: '$PeerIPv4'"
}
$peerLocalV4Value = if ([string]::IsNullOrWhiteSpace($PeerLocalIPv4)) {
    $PeerIPv4
} else { $PeerLocalIPv4 }
$peerLocalV4Address = $null
if (-not [Net.IPAddress]::TryParse(
    $peerLocalV4Value, [ref]$peerLocalV4Address) -or
    $peerLocalV4Address.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork) {
    throw "PeerLocalIPv4 is not an IPv4 address: '$peerLocalV4Value'"
}
$peerV6Address = $null
if (-not [Net.IPAddress]::TryParse($PeerIPv6.Split('%')[0],
    [ref]$peerV6Address) -or
    $peerV6Address.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6 -or
    $peerV6Address.IsIPv4MappedToIPv6) {
    throw "PeerIPv6 is not a native IPv6 address: '$PeerIPv6'"
}
$peerV4Text = $peerV4Address.ToString()
$peerLocalV4Text = $peerLocalV4Address.ToString()
$peerV6Text = $peerV6Address.ToString()
if ((Get-I04StrictAddressClass -Address $peerV4Text) -ne
    'public-unicast-v4') {
    throw 'PeerIPv4 must be the real globally routable HighID endpoint'
}
if (-not (Test-I04UsableLocalIPv4 -Address $peerLocalV4Text)) {
    throw 'PeerLocalIPv4 must be an assigned unicast address on the peer adapter'
}
if ($PeerIPv6.Contains('%') -or
    (Get-I04StrictAddressClass -Address $peerV6Text) -ne
        'native-global-v6') {
    throw 'PeerIPv6 must be an unscoped native provider-routed global IPv6 address'
}
$expectedFallbackDelayMs = 3000
$captureTimingToleranceMs = 250
$socketClockCoherenceToleranceMs = 50
$minimumSilentWindowMs = $expectedFallbackDelayMs - $captureTimingToleranceMs
$schedulerReconnectFloorSeconds = 1205
$fileBSizeBytes = 67108864
$overlayPattern =
    '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
    'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi|' +
    'teredo|6to4|isatap|ip-?https'

$uniquePorts = @(
    $PeerTcpPort, $PeerUdpPort, $PeerWebPort,
    $ClientTcpPort, $ClientUdpPort, $ClientWebPort
) | Sort-Object -Unique
if ($uniquePorts.Count -ne 6) {
    throw 'All peer/client TCP, UDP and Web ports must be unique'
}

function Get-I04MachineId {
    if ($null -eq $script:i04HostIdentity -or
        -not [string]$script:i04HostIdentity.machine_id_sha256) {
        throw 'Strict local host identity was not initialized'
    }
    return [string]$script:i04HostIdentity.machine_id_sha256
}

function Test-I04Administrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    } catch {
        return $false
    }
}

function Get-I04NormalizedIp {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address.Split('%')[0], [ref]$parsed)) {
        return $Address
    }
    if ($parsed.IsIPv4MappedToIPv6) {
        return $parsed.MapToIPv4().ToString()
    }
    return $parsed.ToString()
}

function Get-I04EpochMilliseconds {
    param(
        [Parameter(Mandatory = $true)][DateTimeOffset]$Timestamp
    )

    # ToUnixTimeMilliseconds truncates the sub-millisecond part. Packet
    # timestamps are fractional milliseconds, so truncation could classify a
    # packet emitted just before a barrier as post-barrier.
    $unixEpochTicks = ([DateTimeOffset]'1970-01-01T00:00:00Z').UtcTicks
    return [double]($Timestamp.UtcTicks - $unixEpochTicks) /
        [double][TimeSpan]::TicksPerMillisecond
}

function Add-I04JsonLine {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $line = $Value | ConvertTo-Json -Depth 24 -Compress
    Add-Content -LiteralPath $Path -Value $line -Encoding utf8
}

function Add-I04Journal {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Mutation,
        [Parameter(Mandatory = $true)][string]$State,
        [AllowEmptyString()][string]$Detail = ''
    )

    Add-I04JsonLine -Path $Path -Value ([ordered]@{
        schema = 'ese.v91.i04-mutation-journal/v1'
        captured_at_utc = Get-LabUtcTimestamp
        mutation = $Mutation
        state = $State
        detail = $Detail
    })
}

function Add-I04RollbackJournal {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Mutation,
        [Parameter(Mandatory = $true)][string]$State,
        [AllowEmptyString()][string]$Detail = '',
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    # Rollback must never depend on writing evidence. A full/detached evidence
    # volume is a cleanup failure, but it must not prevent the remaining
    # process/firewall/filter rollback from running.
    try {
        Add-I04Journal -Path $Path -Mutation $Mutation -State $State `
            -Detail $Detail
    } catch {
        $CleanupFailures.Add((Get-I04SafeErrorToken `
            -Context "rollback journal write failed for $Mutation" `
            -Message $_.Exception.Message))
    }
}

function Get-I04IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $inSection = $false
    $value = $null
    foreach ($lineValue in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $line = [string]$lineValue
        if ($line -match '^\s*\[(?<section>[^\]]+)\]\s*$') {
            $inSection = $Matches.section -ieq $Section
            continue
        }
        if ($inSection -and
            $line -match ('^\s*' + [regex]::Escape($Key) +
                '\s*=\s*(?<value>.*?)\s*$')) {
            $value = [string]$Matches.value
        }
    }
    return $value
}

function Assert-I04PreferenceContract {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()][object[]]$Contract
    )

    $targetSections = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $expected = New-Object `
        'Collections.Generic.Dictionary[string,object]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Contract) {
        $section = [string]$entry.section
        $key = [string]$entry.key
        if ([string]::IsNullOrWhiteSpace($section) -or
            [string]::IsNullOrWhiteSpace($key)) {
            throw 'Preference contract contains an empty section/key'
        }
        $id = $section + [char]0x1f + $key
        if ($expected.ContainsKey($id)) {
            throw "Preference contract itself duplicates [$section] $key"
        }
        $expected.Add($id, $entry)
        $null = $targetSections.Add($section)
    }

    $sectionCounts = New-Object `
        'Collections.Generic.Dictionary[string,int]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $observed = New-Object `
        'Collections.Generic.Dictionary[string,object]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $section = ''
    foreach ($lineValue in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $line = [string]$lineValue
        if ($line -match '^\s*\[(?<section>[^\]]+)\]\s*$') {
            $section = [string]$Matches.section
            if ($targetSections.Contains($section)) {
                if (-not $sectionCounts.ContainsKey($section)) {
                    $sectionCounts.Add($section, 0)
                }
                $sectionCounts[$section]++
            }
            continue
        }
        if (-not $targetSections.Contains($section) -or
            $line -notmatch '^\s*(?<key>[^;#][^=]*?)\s*=\s*(?<value>.*?)\s*$') {
            continue
        }
        $key = ([string]$Matches.key).Trim()
        $id = $section + [char]0x1f + $key
        if (-not $expected.ContainsKey($id)) { continue }
        if (-not $observed.ContainsKey($id)) {
            $observed.Add($id, [System.Collections.Generic.List[string]]::new())
        }
        $observed[$id].Add([string]$Matches.value)
    }

    foreach ($targetSection in @($targetSections)) {
        if (-not $sectionCounts.ContainsKey($targetSection) -or
            $sectionCounts[$targetSection] -ne 1) {
            throw "Preference section [$targetSection] must occur exactly once"
        }
    }
    $fingerprintLines = [System.Collections.Generic.List[string]]::new()
    foreach ($id in @($expected.Keys | Sort-Object)) {
        $entry = $expected[$id]
        if (-not $observed.ContainsKey($id) -or
            $observed[$id].Count -ne 1 -or
            -not [StringComparer]::Ordinal.Equals(
                [string]$observed[$id][0], [string]$entry.value
            )) {
            throw "Preference [$($entry.section)] $($entry.key) must occur once with its exact value"
        }
        $fingerprintLines.Add(('{0}|{1}|{2}' -f
                $entry.section, $entry.key,
                (Get-I04StringSha256 -Value ([string]$entry.value))))
    }
    return [pscustomobject][ordered]@{
        exact = $true
        target_section_count = $targetSections.Count
        target_key_count = $expected.Count
        contract_sha256 = Get-I04StringSha256 -Value (
            @($fingerprintLines.ToArray() | Sort-Object) -join "`n"
        )
        duplicate_sections_rejected = $true
        duplicate_keys_rejected = $true
    }
}

function Set-I04StoredPreferenceContract {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()][object[]]$Contract,
        [switch]$Merge
    )

    $canonicalNode = Assert-I04NoReparsePath `
        -Path $NodePath -Kind Directory
    $nodeKey = [IO.Path]::GetFullPath($canonicalNode)
    $entries = New-Object `
        'Collections.Generic.Dictionary[string,object]' `
        ([StringComparer]::OrdinalIgnoreCase)
    if ($Merge) {
        if (-not $script:i04PreferenceContracts.ContainsKey($nodeKey)) {
            throw 'Cannot merge a preference contract before its isolated baseline is stored'
        }
        foreach ($entry in [object[]]$script:i04PreferenceContracts[$nodeKey]) {
            $id = [string]$entry.section + [char]0x1f + [string]$entry.key
            $entries.Add($id, $entry)
        }
    }
    foreach ($entry in $Contract) {
        $section = [string]$entry.section
        $key = [string]$entry.key
        if ([string]::IsNullOrWhiteSpace($section) -or
            [string]::IsNullOrWhiteSpace($key)) {
            throw 'Stored preference contract contains an empty section/key'
        }
        $id = $section + [char]0x1f + $key
        $copy = [pscustomobject]@{
            section = $section
            key = $key
            value = [string]$entry.value
        }
        if ($entries.ContainsKey($id)) {
            $entries[$id] = $copy
        } else {
            $entries.Add($id, $copy)
        }
    }
    $stored = [System.Collections.Generic.List[object]]::new()
    foreach ($id in @($entries.Keys | Sort-Object)) {
        $stored.Add($entries[$id])
    }
    if ($stored.Count -eq 0) {
        throw 'Stored preference contract cannot be empty'
    }
    $contractArray = $stored.ToArray()
    $script:i04PreferenceContracts[$nodeKey] = $contractArray
    return Assert-I04PreferenceContract `
        -Path (Join-Path $canonicalNode 'config\preferences.ini') `
        -Contract $contractArray
}

function Assert-I04StoredPreferenceContract {
    param([Parameter(Mandatory = $true)][string]$NodePath)

    $canonicalNode = Assert-I04NoReparsePath `
        -Path $NodePath -Kind Directory
    $nodeKey = [IO.Path]::GetFullPath($canonicalNode)
    if (-not $script:i04PreferenceContracts.ContainsKey($nodeKey)) {
        throw 'No complete preference contract is stored for this node'
    }
    $contract = [object[]]$script:i04PreferenceContracts[$nodeKey]
    if ($contract.Count -eq 0) {
        throw 'The stored preference contract is empty'
    }
    return Assert-I04PreferenceContract `
        -Path (Join-Path $canonicalNode 'config\preferences.ini') `
        -Contract $contract
}

function Get-I04PersistedUserHash {
    param([Parameter(Mandatory = $true)][string]$NodePath)

    $path = Join-Path $NodePath 'config\preferences.dat'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Peer identity file does not exist: $path"
    }
    $bytes = [IO.File]::ReadAllBytes($path)
    # Preferences_Ext_Struct is packed: uint8 version followed immediately by
    # uchar userhash[16]. This is the exact identity loaded by non-headless
    # startup before the TCP listener is created.
    if ($bytes.Length -lt 17) {
        throw "Peer identity file is truncated: $path"
    }
    $hashBytes = New-Object byte[] 16
    [Array]::Copy($bytes, 1, $hashBytes, 0, 16)
    $hash = ([BitConverter]::ToString($hashBytes)).Replace('-', '')
    if ($hash -notmatch '^[0-9A-F]{32}$' -or
        $hash -eq ('0' * 32) -or $hashBytes[5] -ne 14 -or
        $hashBytes[14] -ne 111) {
        throw "Peer preferences.dat does not contain a valid eMule user hash"
    }
    return [pscustomobject][ordered]@{
        relative_path = 'config\preferences.dat'
        file_sha256 = Get-LabSha256 -Path $path
        format_version = [int]$bytes[0]
        user_hash = $hash
        user_hash_offset = 1
        source_mode = 'non-headless persisted preferences.dat identity'
    }
}

function Set-I04IsolatedPreferences {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][int]$IPv6Mode,
        [Parameter(Mandatory = $true)][string]$IPv6BindAddress,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$IncomingPath,
        [Parameter(Mandatory = $true)][string]$TempPath,
        [ValidateRange(0, 1024)][int]$MaxUploadKiBps = 0
    )

    $config = Join-Path $NodePath 'config'
    $preferences = Join-Path $config 'preferences.ini'
    $preferenceContract = [System.Collections.Generic.List[object]]::new()
    $removedIdentityFiles = [Collections.Generic.List[string]]::new()
    foreach ($identityName in @(
        'preferences.dat', 'cryptkey.dat', 'clients.met'
    )) {
        $identityPath = Join-Path $config $identityName
        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
            Remove-Item -LiteralPath $identityPath -Force -ErrorAction Stop
            $removedIdentityFiles.Add($identityName)
        }
    }
    foreach ($entry in ([ordered]@{
        Autoconnect = '0'
        OpenPortsOnStartUp = '0'
        AutoStart = '0'
        AutoTakeED2KLinks = '0'
        WatchClipboard4ED2kFilelinks = '0'
        NetworkKademlia = '0'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        VerboseOptions = '1'
        Verbose = '1'
        SaveLogToDisk = '1'
        SaveDebugToDisk = '1'
        DebugClientTCP = '1'
        LogA4AF = '1'
        A4AFSaveCpu = '0'
        ConfirmExit = '0'
        IncomingDir = ($IncomingPath + '\')
        TempDir = ($TempPath + '\')
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
        $preferenceContract.Add([pscustomobject]@{
            section = 'eMule'; key = $entry.Key; value = $entry.Value
        })
    }
    if ($MaxUploadKiBps -gt 0) {
        foreach ($entry in ([ordered]@{
            MaxUpload = [string]$MaxUploadKiBps
            UploadCapacityNew = [string]($MaxUploadKiBps * 2)
            MinUpload = '1'
            USSEnabled = '0'
        }).GetEnumerator()) {
            Set-LabIniValue -Path $preferences -Section 'eMule' `
                -Key $entry.Key -Value $entry.Value
            $preferenceContract.Add([pscustomobject]@{
                section = 'eMule'; key = $entry.Key; value = $entry.Value
            })
        }
    }
    foreach ($entry in ([ordered]@{
        IPv6Mode = [string]$IPv6Mode
        IPv6BindAddr = $IPv6BindAddress
        KadNetworkMask = '0'
        NetworkED2K = '0'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
        $preferenceContract.Add([pscustomobject]@{
            section = 'Connection'; key = $entry.Key; value = $entry.Value
        })
    }
    foreach ($entry in ([ordered]@{
        EseNetLabConsent = '0'
        EseNetLabAdvancedConsent = '0'
        EseNetLabContributionConsent = '0'
        EseNetLabEnabled = '0'
        EseV9Experimental = '0'
        EnableUtpHolePunch = '0'
        EseAutoKeepalive = '0'
        EseKad3Rendezvous = '0'
        EseReachSelector = '0'
        EseHolePunchPortPredict = '0'
        EseEd2kPunch3 = '0'
        EseRelayAccept = '0'
        EseRelayEgress = '0'
        Kad6BetaExitOptIn = '0'
        Kad6PublicExitOptIn = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eSE' `
            -Key $entry.Key -Value $entry.Value
        $preferenceContract.Add([pscustomobject]@{
            section = 'eSE'; key = $entry.Key; value = $entry.Value
        })
    }
    Set-LabIniValue -Path $preferences -Section 'Proxy' `
        -Key 'ProxyEnableProxy' -Value '0'
    $preferenceContract.Add([pscustomobject]@{
        section = 'Proxy'; key = 'ProxyEnableProxy'; value = '0'
    })
    Set-LabIniValue -Path $preferences -Section 'UPnP' `
        -Key 'EnableUPnP' -Value '0'
    $preferenceContract.Add([pscustomobject]@{
        section = 'UPnP'; key = 'EnableUPnP'; value = '0'
    })
    foreach ($entry in ([ordered]@{
        Enabled = '1'
        Port = [string]$WebPort
        Password = Get-I04Md5Text -Value $Password
        AllowedIPs = '127.0.0.1'
        WebUseUPnP = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'WebServer' `
            -Key $entry.Key -Value $entry.Value
        $preferenceContract.Add([pscustomobject]@{
            section = 'WebServer'; key = $entry.Key; value = $entry.Value
        })
    }
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayEnabled' -Value '0'
    $preferenceContract.Add([pscustomobject]@{
        section = 'KRPRelay'; key = 'KrpRelayEnabled'; value = '0'
    })
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayKillSwitch' -Value '1'
    $preferenceContract.Add([pscustomobject]@{
        section = 'KRPRelay'; key = 'KrpRelayKillSwitch'; value = '1'
    })

    $preferenceContractEvidence = Set-I04StoredPreferenceContract `
        -NodePath $NodePath -Contract $preferenceContract.ToArray()

    foreach ($serverFile in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak', 'staticservers.dat'
    )) {
        $serverPath = Join-Path $config $serverFile
        if (Test-Path -LiteralPath $serverPath -PathType Leaf) {
            Remove-Item -LiteralPath $serverPath -Force -ErrorAction Stop
        }
    }
    $shares = Join-Path $config 'shareddir.dat'
    [IO.File]::WriteAllText(
        $shares, '', (New-Object Text.UTF8Encoding($false))
    )
    foreach ($runtimeLog in @(
        Get-ChildItem -LiteralPath $NodePath -Recurse -File -Filter '*.log' `
            -ErrorAction Stop
    )) {
        Remove-Item -LiteralPath $runtimeLog.FullName -Force `
            -ErrorAction Stop
    }
    return [pscustomobject][ordered]@{
        preferences_ini_relative_path = 'config\preferences.ini'
        preference_contract = $preferenceContractEvidence
        identity_bootstrap = 'fresh isolated profile'
        inherited_identity_files_removed =
            @($removedIdentityFiles.ToArray())
        preferences_dat_absent_before_start =
            -not (Test-Path -LiteralPath (
                Join-Path $config 'preferences.dat'
            ))
        cryptkey_dat_absent_before_start =
            -not (Test-Path -LiteralPath (
                Join-Path $config 'cryptkey.dat'
            ))
        max_upload_kib_per_second = $MaxUploadKiBps
        dynamic_upload_disabled = $MaxUploadKiBps -gt 0
    }
}

function New-I04FixtureFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Int64]$Bytes,
        [Parameter(Mandatory = $true)][string]$Seed
    )

    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        # Seed the first MiB and extend sparsely.  The eD2K and SHA-256
        # identities are therefore unique without making fixture creation slow.
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $written = 0
            $counter = 0
            while ($written -lt [Math]::Min(1MB, $Bytes)) {
                $block = $sha.ComputeHash(
                    [Text.Encoding]::UTF8.GetBytes(
                        "$Seed|$counter"
                    )
                )
                $wanted = [Math]::Min(
                    $block.Length,
                    [Math]::Min(1MB, $Bytes) - $written
                )
                $stream.Write($block, 0, $wanted)
                $written += $wanted
                $counter++
            }
        } finally {
            $sha.Dispose()
        }
        $stream.SetLength($Bytes)
    } finally {
        $stream.Dispose()
    }
    return [pscustomobject][ordered]@{
        name = [IO.Path]::GetFileName($Path)
        bytes = $Bytes
        sha256 = Get-LabSha256 -Path $Path
        seed_sha256 = Get-LabStringSha256 -Value $Seed
    }
}

function Wait-I04File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return Get-Content -LiteralPath $Path -Raw |
                ConvertFrom-Json -ErrorAction Stop
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Wait-I04PeerControl {
    param(
        [Parameter(Mandatory = $true)][string]$ArmPath,
        [Parameter(Mandatory = $true)][string]$StopPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        # Stop wins if both files appear while the peer is polling. This lets
        # the coordinator abort a bad fixture without arming any firewall rule.
        if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'stop'
                data = Get-Content -LiteralPath $StopPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $ArmPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'arm'
                data = Get-Content -LiteralPath $ArmPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Wait-I04RestartControl {
    param(
        [Parameter(Mandatory = $true)][string]$RestartPath,
        [Parameter(Mandatory = $true)][string]$StopPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'stop'
                data = Get-Content -LiteralPath $StopPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $RestartPath -PathType Leaf) {
            return [pscustomobject]@{
                kind = 'restart'
                data = Get-Content -LiteralPath $RestartPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Wait-I04StopWhileProcessAlive {
    param(
        [Parameter(Mandatory = $true)][string]$StopPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
            return Get-Content -LiteralPath $StopPath -Raw |
                ConvertFrom-Json -ErrorAction Stop
        }
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Peer source PID $($Process.Id) exited before coordinator stop"
        }
        $actualPath = ''
        try { $actualPath = [IO.Path]::GetFullPath($Process.Path) } catch {}
        if ($actualPath -ne [IO.Path]::GetFullPath($ExpectedPath)) {
            throw "Peer source PID $($Process.Id) no longer has the owned path"
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Convert-I04RequiredAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$AddressFamily,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $address = $null
    if ([string]::IsNullOrWhiteSpace($Value) -or
        -not [Net.IPAddress]::TryParse($Value.Split('%')[0], [ref]$address) -or
        $address.AddressFamily -ne $AddressFamily -or
        ($AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            $address.IsIPv4MappedToIPv6)) {
        throw "$Name is not an address in the required family: '$Value'"
    }
    return $address
}

function Get-I04TupleKey {
    param(
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort
    )

    return '{0}|{1}|{2}|{3}|{4}' -f $Family,
        (Get-I04NormalizedIp -Address $LocalAddress), $LocalPort,
        (Get-I04NormalizedIp -Address $RemoteAddress), $RemotePort
}

function Get-I04TargetConnections {
    param(
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )

    return @(
        Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            [int]$_.RemotePort -eq $Port -and
            @($IPv4, $IPv6) -contains
                (Get-I04NormalizedIp -Address $_.RemoteAddress)
        } | ForEach-Object {
            $remote = Get-I04NormalizedIp -Address $_.RemoteAddress
            $local = Get-I04NormalizedIp -Address $_.LocalAddress
            $family = if ($remote.Contains(':')) { 'IPv6' } else { 'IPv4' }
            [pscustomobject][ordered]@{
                captured_at_utc = Get-LabUtcTimestamp
                owning_process = [int]$_.OwningProcess
                state = [string]$_.State
                family = $family
                local_address = $local
                local_port = [int]$_.LocalPort
                remote_address = $remote
                remote_port = [int]$_.RemotePort
                tuple_key = Get-I04TupleKey -Family $family `
                    -LocalAddress $local -LocalPort ([int]$_.LocalPort) `
                    -RemoteAddress $remote -RemotePort ([int]$_.RemotePort)
            }
        }
    )
}

function Get-I04RequiredJsonProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Boolean', 'Integer', 'String', 'Object')]
        [string]$ExpectedType
    )

    if ($null -eq $Object) {
        throw "JSON parent object is null for property '$Name'"
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "Required JSON property is absent: $Name"
    }
    $value = $property.Value
    $valid = switch ($ExpectedType) {
        'Boolean' { $value -is [bool]; break }
        'Integer' { $value -is [int] -or $value -is [Int64]; break }
        'String' { $value -is [string]; break }
        'Object' {
            $null -ne $value -and -not ($value -is [Array]) -and
                @($value.PSObject.Properties).Count -gt 0
            break
        }
    }
    if (-not $valid) {
        $actual = if ($null -eq $value) { 'null' } else {
            $value.GetType().FullName
        }
        throw "JSON property '$Name' is $actual, expected $ExpectedType"
    }
    return $value
}

function Assert-I04ApiStatusContract {
    param([Parameter(Mandatory = $true)]$Status)

    foreach ($name in @(
        'user_hash', 'netlab_consent', 'netlab_advanced_consent',
        'netlab_contribution_consent'
    )) {
        $null = Get-I04RequiredJsonProperty -Object $Status `
            -Name $name -ExpectedType String
    }
    foreach ($name in @(
        'ed2k_connected', 'kad2_running', 'kad6_running', 'netlab_enabled',
        'utp_hole_punch_enabled'
    )) {
        $null = Get-I04RequiredJsonProperty -Object $Status `
            -Name $name -ExpectedType Boolean
    }
    foreach ($name in @(
        'kad_running_mask', 'connecting_client_count',
        'connecting_client_adds', 'connecting_client_high_water',
        'connecting_client_duplicate_adds'
    )) {
        $null = Get-I04RequiredJsonProperty -Object $Status `
            -Name $name -ExpectedType Integer
    }
    return $true
}

function Assert-I04ApiV9Contract {
    param([Parameter(Mandatory = $true)]$Value)

    $null = Get-I04RequiredJsonProperty -Object $Value `
        -Name 'success' -ExpectedType Boolean
    $netlab = Get-I04RequiredJsonProperty -Object $Value `
        -Name 'netlab' -ExpectedType Object
    $v9 = Get-I04RequiredJsonProperty -Object $Value `
        -Name 'v9' -ExpectedType Object
    foreach ($name in @('enabled', 'capability_advertised',
            'keepalive_running')) {
        $null = Get-I04RequiredJsonProperty -Object $netlab `
            -Name $name -ExpectedType Boolean
    }
    $staged = Get-I04RequiredJsonProperty -Object $netlab `
        -Name 'staged' -ExpectedType Object
    foreach ($name in @('selector', 'port_predict', 'ed2k_punch3',
            'kad3_rendezvous')) {
        $null = Get-I04RequiredJsonProperty -Object $staged `
            -Name $name -ExpectedType Boolean
    }
    $independent = Get-I04RequiredJsonProperty -Object $netlab `
        -Name 'independent' -ExpectedType Object
    foreach ($name in @('relay_accept', 'relay_egress', 'krp',
            'kad6_beta_exit', 'kad6_stable_public_exit')) {
        $null = Get-I04RequiredJsonProperty -Object $independent `
            -Name $name -ExpectedType Boolean
    }
    foreach ($name in @('experimental', 'port_predict', 'ed2k_punch3',
            'kad3_rendezvous', 'keepalive_running', 'hole_punch_master')) {
        $null = Get-I04RequiredJsonProperty -Object $v9 `
            -Name $name -ExpectedType Boolean
    }
    return $true
}

function Wait-I04Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API readiness (exit $($Process.ExitCode))"
        }
        try {
            $status = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$Port/api/status" `
                -TimeoutSec 2
            $null = Assert-I04ApiStatusContract -Status $status
            return $status
        } catch {
            Start-Sleep -Milliseconds 400
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "API on port $Port did not become ready"
}

function Wait-I04Listener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RequireDualStack
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before listener $Port became ready"
        }
        $listeners = @(
            Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                [string]$_.State -eq 'Listen' -and
                [int]$_.LocalPort -eq $Port -and
                [int]$_.OwningProcess -eq $Process.Id
            }
        )
        if ($listeners.Count -gt 0) {
            if (-not $RequireDualStack -or @(
                $listeners | Where-Object {
                    (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
                }
            ).Count -gt 0) {
                return $listeners
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($RequireDualStack) {
        throw "A dual-stack [::]:$Port listener did not become ready"
    }
    throw "Listener $Port did not become ready"
}

function Initialize-I04RestrictedProcessLauncher {
    $contractId = 'ese.v91.i04-restricted-process-launcher/2026-08-01.v1'
    if ('V91I04RestrictedProcessLauncher' -as [type]) {
        $null = Assert-I04ManagedTypeContract `
            -TypeName 'V91I04RestrictedProcessLauncher' `
            -ExpectedContractId $contractId
        return
    }
    Add-Type @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class V91I04RestrictedProcessLauncher {
    public const string ContractId = "ese.v91.i04-restricted-process-launcher/2026-08-01.v1";
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_HIDE = 0;
    private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectBasicAccountingInformation = 1;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS {
        public UInt64 ReadOperationCount;
        public UInt64 WriteOperationCount;
        public UInt64 OtherOperationCount;
        public UInt64 ReadTransferCount;
        public UInt64 WriteTransferCount;
        public UInt64 OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public Int64 PerProcessUserTimeLimit;
        public Int64 PerJobUserTimeLimit;
        public UInt32 LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public UInt32 ActiveProcessLimit;
        public UIntPtr Affinity;
        public UInt32 PriorityClass;
        public UInt32 SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
        public Int64 TotalUserTime;
        public Int64 TotalKernelTime;
        public Int64 ThisPeriodTotalUserTime;
        public Int64 ThisPeriodTotalKernelTime;
        public UInt32 TotalPageFaultCount;
        public UInt32 TotalProcesses;
        public UInt32 ActiveProcesses;
        public UInt32 TotalTerminatedProcesses;
    }

    private sealed class Lease {
        public IntPtr Job;
        public IntPtr Process;
        public int ProcessId;
    }

    public sealed class LaunchResult {
        public int ProcessId;
        public string Contract;
        public uint ActiveProcessLimit;
        public bool StartedSuspended;
        public bool AssignedBeforeResume;
    }

    public sealed class AccountingResult {
        public string Contract;
        public int ProcessId;
        public uint ActiveProcessLimit;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
        public bool ChildProcessesStructurallyForbidden;
    }

    private static readonly object Gate = new object();
    private static readonly Dictionary<int, Lease> Leases =
        new Dictionary<int, Lease>();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint creationFlags, IntPtr environment,
        string currentDirectory, ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(
        IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job, int infoClass, IntPtr info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(
        IntPtr job, int infoClass,
        out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info,
        uint length, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(
        IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static string Quote(string value) {
        if (value == null) value = "";
        bool quote = value.Length == 0;
        for (int i = 0; i < value.Length && !quote; ++i) {
            char c = value[i];
            quote = Char.IsWhiteSpace(c) || c == '"';
        }
        if (!quote) return value;
        StringBuilder result = new StringBuilder();
        result.Append('"');
        int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') {
                ++slashes;
                continue;
            }
            if (c == '"') {
                result.Append('\\', slashes * 2 + 1);
                result.Append('"');
                slashes = 0;
                continue;
            }
            result.Append('\\', slashes);
            slashes = 0;
            result.Append(c);
        }
        result.Append('\\', slashes * 2);
        result.Append('"');
        return result.ToString();
    }

    private static string BuildCommandLine(string application, string[] args) {
        StringBuilder result = new StringBuilder(Quote(application));
        if (args != null) {
            foreach (string arg in args) {
                result.Append(' ');
                result.Append(Quote(arg));
            }
        }
        return result.ToString();
    }

    public static LaunchResult Start(
        string application, string[] args, string currentDirectory) {
        if (String.IsNullOrWhiteSpace(application))
            throw new ArgumentException("application");
        if (String.IsNullOrWhiteSpace(currentDirectory))
            throw new ArgumentException("currentDirectory");

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        IntPtr job = IntPtr.Zero;
        bool stored = false;
        try {
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = (int)STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            StringBuilder command = new StringBuilder(
                BuildCommandLine(application, args));
            if (!CreateProcessW(
                application, command, IntPtr.Zero, IntPtr.Zero, false,
                CREATE_SUSPENDED, IntPtr.Zero, currentDirectory, ref si,
                out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "CreateProcessW(CREATE_SUSPENDED) failed");

            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "CreateJobObject failed");

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            int size = Marshal.SizeOf(typeof(
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                Marshal.StructureToPtr(limits, buffer, false);
                if (!SetInformationJobObject(
                    job, JobObjectExtendedLimitInformation, buffer,
                    (uint)size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "SetInformationJobObject failed");
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
            if (!AssignProcessToJobObject(job, pi.hProcess))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "AssignProcessToJobObject before resume failed");
            if (ResumeThread(pi.hThread) == UInt32.MaxValue)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "ResumeThread failed");
            CloseHandle(pi.hThread);
            pi.hThread = IntPtr.Zero;
            lock (Gate) {
                if (Leases.ContainsKey(pi.dwProcessId))
                    throw new InvalidOperationException(
                        "Restricted process PID already leased");
                Leases.Add(pi.dwProcessId, new Lease {
                    Job = job, Process = pi.hProcess,
                    ProcessId = pi.dwProcessId
                });
                stored = true;
            }
            return new LaunchResult {
                ProcessId = pi.dwProcessId,
                Contract = ContractId,
                ActiveProcessLimit = 1,
                StartedSuspended = true,
                AssignedBeforeResume = true
            };
        } catch {
            if (!stored && pi.hProcess != IntPtr.Zero)
                TerminateProcess(pi.hProcess, 0xE5040001);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (!stored && pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (!stored && job != IntPtr.Zero) CloseHandle(job);
            throw;
        }
    }

    public static AccountingResult Query(int processId) {
        lock (Gate) {
            Lease lease;
            if (!Leases.TryGetValue(processId, out lease))
                throw new InvalidOperationException(
                    "Restricted process lease is unavailable");
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
            if (!QueryInformationJobObject(
                lease.Job, JobObjectBasicAccountingInformation, out info,
                (uint)Marshal.SizeOf(typeof(
                    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "QueryInformationJobObject failed");
            return new AccountingResult {
                Contract = ContractId,
                ProcessId = processId,
                ActiveProcessLimit = 1,
                TotalProcesses = info.TotalProcesses,
                ActiveProcesses = info.ActiveProcesses,
                TotalTerminatedProcesses = info.TotalTerminatedProcesses,
                ChildProcessesStructurallyForbidden = true
            };
        }
    }

    public static bool Release(int processId) {
        Lease lease;
        lock (Gate) {
            if (!Leases.TryGetValue(processId, out lease)) return false;
            Leases.Remove(processId);
        }
        bool processClosed = CloseHandle(lease.Process);
        bool jobClosed = CloseHandle(lease.Job);
        return processClosed && jobClosed;
    }
}
'@
    $null = Assert-I04ManagedTypeContract `
        -TypeName 'V91I04RestrictedProcessLauncher' `
        -ExpectedContractId $contractId
}

function Get-I04RestrictedJobAccounting {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    Initialize-I04RestrictedProcessLauncher
    $accounting = [V91I04RestrictedProcessLauncher]::Query($ProcessId)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-restricted-job-accounting/v1'
        contract_id = [string]$accounting.Contract
        process_id = [int]$accounting.ProcessId
        active_process_limit = [int]$accounting.ActiveProcessLimit
        total_processes = [int]$accounting.TotalProcesses
        active_processes = [int]$accounting.ActiveProcesses
        total_terminated_processes =
            [int]$accounting.TotalTerminatedProcesses
        child_processes_structurally_forbidden =
            [bool]$accounting.ChildProcessesStructurallyForbidden
    }
}

function Assert-I04RestrictedJobAccountingContract {
    param(
        [Parameter(Mandatory = $true)][object]$Accounting,
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId,
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)][int]$ExpectedActiveProcesses
    )

    $expectedProperties = @(
        'schema', 'contract_id', 'process_id', 'active_process_limit',
        'total_processes', 'active_processes',
        'total_terminated_processes',
        'child_processes_structurally_forbidden'
    )
    $actualProperties = @($Accounting.PSObject.Properties.Name)
    $actualPropertySet = @($actualProperties | Sort-Object) -join "`n"
    $expectedPropertySet = @($expectedProperties | Sort-Object) -join "`n"
    if ($actualPropertySet -cne $expectedPropertySet -or
        -not ($Accounting.schema -is [string]) -or
        [string]$Accounting.schema -cne
            'ese.v91.i04-restricted-job-accounting/v1' -or
        -not ($Accounting.contract_id -is [string]) -or
        [string]$Accounting.contract_id -cne
            'ese.v91.i04-restricted-process-launcher/2026-08-01.v1' -or
        -not ($Accounting.process_id -is [int]) -or
        [int]$Accounting.process_id -ne $ExpectedProcessId -or
        -not ($Accounting.active_process_limit -is [int]) -or
        [int]$Accounting.active_process_limit -ne 1 -or
        -not ($Accounting.total_processes -is [int]) -or
        [int]$Accounting.total_processes -ne 1 -or
        -not ($Accounting.active_processes -is [int]) -or
        [int]$Accounting.active_processes -ne $ExpectedActiveProcesses -or
        -not ($Accounting.total_terminated_processes -is [int]) -or
        [int]$Accounting.total_terminated_processes -ne 0 -or
        -not ($Accounting.child_processes_structurally_forbidden -is [bool]) -or
        -not [bool]$Accounting.child_processes_structurally_forbidden) {
        throw 'Restricted job accounting violated its exact typed contract'
    }
    return $true
}

function Start-I04RestrictedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    Initialize-I04RestrictedProcessLauncher
    $launch = [V91I04RestrictedProcessLauncher]::Start(
        $FilePath, $ArgumentList, $WorkingDirectory
    )
    if (-not ($launch.ProcessId -is [int]) -or
        [int]$launch.ProcessId -le 0) {
        throw 'Restricted process launcher returned no exact root PID'
    }
    # Track the managed lease before validating the rest of the returned
    # envelope. A corrupted envelope must still reach the outer release path.
    $script:i04RestrictedJobPids.Add([int]$launch.ProcessId) | Out-Null
    if (-not ($launch.Contract -is [string]) -or
        [string]$launch.Contract -cne
            'ese.v91.i04-restricted-process-launcher/2026-08-01.v1' -or
        -not ($launch.ActiveProcessLimit -is [UInt32]) -or
        [UInt32]$launch.ActiveProcessLimit -ne 1 -or
        -not ($launch.StartedSuspended -is [bool]) -or
        -not [bool]$launch.StartedSuspended -or
        -not ($launch.AssignedBeforeResume -is [bool]) -or
        -not [bool]$launch.AssignedBeforeResume) {
        throw 'Restricted process launcher did not prove assignment-before-resume'
    }
    $process = [Diagnostics.Process]::GetProcessById([int]$launch.ProcessId)
    $accounting = Get-I04RestrictedJobAccounting -ProcessId $process.Id
    $null = Assert-I04RestrictedJobAccountingContract `
        -Accounting $accounting -ExpectedProcessId $process.Id `
        -ExpectedActiveProcesses 1
    $process | Add-Member -NotePropertyName i04_job_contract_id `
        -NotePropertyValue ([string]$accounting.contract_id) -Force
    $process | Add-Member -NotePropertyName i04_job_active_process_limit `
        -NotePropertyValue 1 -Force
    $process | Add-Member -NotePropertyName i04_job_assigned_before_resume `
        -NotePropertyValue $true -Force
    $process | Add-Member -NotePropertyName i04_job_last_accounting `
        -NotePropertyValue $accounting -Force
    return $process
}

function Complete-I04RestrictedJobLeaseCleanup {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Peer', 'Coordinator', 'OuterFinally')]
        [string]$Context
    )

    if ($null -ne $script:i04RestrictedJobLeaseCleanup) {
        return $script:i04RestrictedJobLeaseCleanup
    }

    $processIds = @($script:i04RestrictedJobPids | Sort-Object)
    $terminalAccountingExactCount = 0
    $releasedCount = 0
    $leaseUnavailableCount = 0
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($processId in $processIds) {
        try {
            $accounting = Get-I04RestrictedJobAccounting `
                -ProcessId ([int]$processId)
            $null = Assert-I04RestrictedJobAccountingContract `
                -Accounting $accounting `
                -ExpectedProcessId ([int]$processId) `
                -ExpectedActiveProcesses 0
            $terminalAccountingExactCount++
        } catch {
            $failures.Add((Get-I04SafeErrorToken `
                -Context 'restricted job terminal accounting failed' `
                -Message $_.Exception.Message))
        }

        $released = $false
        try {
            $released = [V91I04RestrictedProcessLauncher]::Release(
                [int]$processId)
            if (-not $released) {
                throw 'Restricted job lease was unavailable before release'
            }
            $releasedCount++
        } catch {
            $failures.Add((Get-I04SafeErrorToken `
                -Context 'restricted job lease release failed' `
                -Message $_.Exception.Message))
        }

        if ($released) {
            try {
                $null = Get-I04RestrictedJobAccounting `
                    -ProcessId ([int]$processId)
                $failures.Add(
                    'restricted job lease remained queryable after release'
                )
            } catch {
                if ([string]$_.Exception.GetBaseException().Message -cne
                    'Restricted process lease is unavailable') {
                    $failures.Add((Get-I04SafeErrorToken `
                        -Context 'restricted job post-release proof failed' `
                        -Message $_.Exception.Message))
                } else {
                    $leaseUnavailableCount++
                    $null = $script:i04RestrictedJobPids.Remove(
                        [int]$processId)
                }
            }
        }
    }

    $requestedCount = $processIds.Count
    $complete = $terminalAccountingExactCount -eq $requestedCount -and
        $releasedCount -eq $requestedCount -and
        $leaseUnavailableCount -eq $requestedCount -and
        $script:i04RestrictedJobPids.Count -eq 0 -and
        $failures.Count -eq 0
    $script:i04RestrictedJobLeaseCleanup = [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-restricted-job-lease-cleanup/v1'
        context = $Context
        completed_at_utc = Get-LabUtcTimestamp
        requested_process_count = [int]$requestedCount
        terminal_accounting_exact_count =
            [int]$terminalAccountingExactCount
        released_count = [int]$releasedCount
        lease_unavailable_after_release_count =
            [int]$leaseUnavailableCount
        remaining_registered_process_count =
            [int]$script:i04RestrictedJobPids.Count
        failures = @($failures.ToArray())
        complete = [bool]$complete
    }
    return $script:i04RestrictedJobLeaseCleanup
}

function Test-I04PeerTerminalContract {
    param(
        [Parameter(Mandatory = $true)][object]$Terminal,
        [Parameter(Mandatory = $true)][string]$ExpectedCaseId,
        [Parameter(Mandatory = $true)][string]$ExpectedRunNonce,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$ExpectedPeerResultSha256
    )

    try {
        $expectedProperties = @(
            'schema', 'case_id', 'run_nonce', 'status',
            'peer_result_sha256', 'restricted_job_lease_cleanup',
            'candidate_locks_released', 'evidence_locks_released',
            'harness_bundle_locks_released',
            'account_registry_postcheck_complete',
            'account_registry_safe_to_pass', 'outer_cleanup_complete',
            'completed_at_utc'
        )
        $actualProperties = @($Terminal.PSObject.Properties.Name)
        if ((@($actualProperties | Sort-Object) -join "`n") -cne
            (@($expectedProperties | Sort-Object) -join "`n")) {
            return $false
        }
        $lease = $Terminal.restricted_job_lease_cleanup
        $expectedLeaseProperties = @(
            'schema', 'context', 'completed_at_utc',
            'requested_process_count', 'terminal_accounting_exact_count',
            'released_count', 'lease_unavailable_after_release_count',
            'remaining_registered_process_count', 'failures', 'complete'
        )
        if ($null -eq $lease -or
            (@($lease.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                (@($expectedLeaseProperties | Sort-Object) -join "`n") -or
            -not ($lease.requested_process_count -is [int]) -or
            -not ($lease.terminal_accounting_exact_count -is [int]) -or
            -not ($lease.released_count -is [int]) -or
            -not ($lease.lease_unavailable_after_release_count -is [int]) -or
            -not ($lease.remaining_registered_process_count -is [int]) -or
            -not ($lease.failures -is [object[]]) -or
            -not ($lease.complete -is [bool]) -or
            -not ($Terminal.candidate_locks_released -is [bool]) -or
            -not ($Terminal.evidence_locks_released -is [bool]) -or
            -not ($Terminal.harness_bundle_locks_released -is [bool]) -or
            -not ($Terminal.account_registry_postcheck_complete -is [bool]) -or
            -not ($Terminal.account_registry_safe_to_pass -is [bool]) -or
            -not ($Terminal.outer_cleanup_complete -is [bool])) {
            return $false
        }
        $requested = [int]$lease.requested_process_count
        return $requested -ge 0 -and
            [string]$Terminal.schema -ceq
                'ese.v91.i04-peer-terminal/v1' -and
            [string]$Terminal.case_id -ceq $ExpectedCaseId -and
            [string]$Terminal.run_nonce -ceq
                $ExpectedRunNonce.ToLowerInvariant() -and
            [string]$Terminal.status -ceq 'COMPLETE' -and
            [string]$Terminal.peer_result_sha256 -ceq
                $ExpectedPeerResultSha256.ToLowerInvariant() -and
            [string]$lease.schema -ceq
                'ese.v91.i04-restricted-job-lease-cleanup/v1' -and
            [string]$lease.context -ceq 'Peer' -and
            [bool]$lease.complete -and
            [int]$lease.terminal_accounting_exact_count -eq $requested -and
            [int]$lease.released_count -eq $requested -and
            [int]$lease.lease_unavailable_after_release_count -eq
                $requested -and
            [int]$lease.remaining_registered_process_count -eq 0 -and
            @($lease.failures).Count -eq 0 -and
            [bool]$Terminal.candidate_locks_released -and
            [bool]$Terminal.evidence_locks_released -and
            [bool]$Terminal.harness_bundle_locks_released -and
            [bool]$Terminal.account_registry_postcheck_complete -and
            [bool]$Terminal.account_registry_safe_to_pass -and
            [bool]$Terminal.outer_cleanup_complete
    } catch {
        return $false
    }
}

function Get-I04ProcessOwnerSidHash {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $rows = @(Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $ProcessId" -ErrorAction Stop)
    if ($rows.Count -ne 1) {
        throw "Process owner query returned $($rows.Count) rows for PID $ProcessId"
    }
    $owner = Invoke-CimMethod -InputObject $rows[0] `
        -MethodName GetOwnerSid -ErrorAction Stop
    if ([UInt32]$owner.ReturnValue -ne 0 -or
        [string]::IsNullOrWhiteSpace([string]$owner.Sid)) {
        throw "Process owner SID query failed for PID $ProcessId"
    }
    $sid = [Security.Principal.SecurityIdentifier]::new(
        [string]$owner.Sid
    ).Value
    return Get-I04StringSha256 -Value $sid
}

function Get-I04CimProcessCreationUtcTicks {
    param([Parameter(Mandatory = $true)][object]$ProcessRow)

    $value = $ProcessRow.CreationDate
    if ($value -is [DateTimeOffset]) {
        return [Int64]$value.UtcDateTime.Ticks
    }
    if ($value -is [DateTime]) {
        return [Int64]$value.ToUniversalTime().Ticks
    }
    if ([string]::IsNullOrWhiteSpace([string]$value)) {
        throw 'CIM process row has no CreationDate'
    }
    $parsed = [System.Management.ManagementDateTimeConverter]::ToDateTime(
        [string]$value
    )
    return [Int64]$parsed.ToUniversalTime().Ticks
}

function Get-I04DescendantCensus {
    param(
        [Parameter(Mandatory = $true)][int]$RootProcessId,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [Int64]::MaxValue)][Int64]$RootCreationUtcTicks,
        [switch]$RootMayHaveExited
    )

    $rows = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $rootRows = @($rows | Where-Object {
        [int]$_.ProcessId -eq $RootProcessId
    })
    if ($rootRows.Count -gt 1) {
        throw 'CIM returned duplicate rows for an owned root PID'
    }
    $rootPresent = $rootRows.Count -eq 1
    $rootIdentityExact = $false
    $observedRootCreationTicks = $null
    if ($rootPresent) {
        $observedRootCreationTicks =
            Get-I04CimProcessCreationUtcTicks -ProcessRow $rootRows[0]
        $rootIdentityExact = [Int64]$observedRootCreationTicks -eq
            $RootCreationUtcTicks
    } elseif ($RootMayHaveExited) {
        $rootIdentityExact = $true
    }

    $knownAncestors = New-Object 'Collections.Generic.HashSet[int]'
    $seen = New-Object 'Collections.Generic.HashSet[int]'
    $null = $knownAncestors.Add($RootProcessId)
    $descendants = [System.Collections.Generic.List[object]]::new()
    do {
        $added = $false
        foreach ($row in $rows) {
            $processId = [int]$row.ProcessId
            if ($processId -eq $RootProcessId -or $seen.Contains($processId) -or
                -not $knownAncestors.Contains([int]$row.ParentProcessId)) {
                continue
            }
            $creationTicks =
                Get-I04CimProcessCreationUtcTicks -ProcessRow $row
            if ($creationTicks -lt $RootCreationUtcTicks) {
                continue
            }
            $null = $seen.Add($processId)
            $null = $knownAncestors.Add($processId)
            $descendants.Add([pscustomobject][ordered]@{
                process_id = $processId
                parent_process_id = [int]$row.ParentProcessId
                creation_utc_ticks = [Int64]$creationTicks
            })
            $added = $true
        }
    } while ($added)

    return [pscustomobject][ordered]@{
        root_process_id = $RootProcessId
        root_creation_utc_ticks = $RootCreationUtcTicks
        root_present = $rootPresent
        root_identity_exact = $rootIdentityExact
        observed_root_creation_utc_ticks = $observedRootCreationTicks
        descendant_count = $descendants.Count
        descendants = $descendants.ToArray()
        clear = $rootIdentityExact -and $descendants.Count -eq 0
    }
}

function Test-I04OwnedProcessDescendants {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RootMayHaveExited
    )

    try {
        $jobAccounting = Get-I04RestrictedJobAccounting `
            -ProcessId ([int]$Process.i04_owner_pid)
        $Process.i04_job_last_accounting = $jobAccounting
        $expectedActive = if ($RootMayHaveExited -or $Process.HasExited) {
            0
        } else { 1 }
        $null = Assert-I04RestrictedJobAccountingContract `
            -Accounting $jobAccounting `
            -ExpectedProcessId ([int]$Process.i04_owner_pid) `
            -ExpectedActiveProcesses $expectedActive
        $audit = Get-I04DescendantCensus `
            -RootProcessId ([int]$Process.i04_owner_pid) `
            -RootCreationUtcTicks (
                [Int64]$Process.i04_owner_cim_creation_utc_ticks
            ) -RootMayHaveExited:$RootMayHaveExited
        $Process | Add-Member -NotePropertyName i04_descendant_last_census `
            -NotePropertyValue $audit -Force
        if (-not [bool]$audit.root_identity_exact) {
            $Process.i04_descendant_root_identity_contradicted = $true
        }
        if ([int]$audit.descendant_count -gt 0) {
            $Process.i04_descendant_observed = $true
            $ids = @(
                @($Process.i04_descendant_observed_process_ids) +
                @($audit.descendants | ForEach-Object { [int]$_.process_id }) |
                    Sort-Object -Unique
            )
            $Process.i04_descendant_observed_process_ids = $ids
        }
    } catch {
        $Process.i04_descendant_collector_failed = $true
        $Process.i04_descendant_error_sha256 =
            Get-I04StringSha256 -Value $_.Exception.Message
        return $false
    }
    return -not [bool]$Process.i04_descendant_collector_failed -and
        -not [bool]$Process.i04_descendant_root_identity_contradicted -and
        -not [bool]$Process.i04_descendant_observed -and
        [bool]$Process.i04_descendant_last_census.clear
}

function Register-I04OwnedProcess {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$OwnerRole,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$Nonce
    )

    $jobRequired = @(
        'i04_job_contract_id', 'i04_job_active_process_limit',
        'i04_job_assigned_before_resume', 'i04_job_last_accounting'
    )
    if (@($jobRequired | Where-Object {
        $Process.PSObject.Properties.Name -notcontains $_
    }).Count -ne 0 -or
        [string]$Process.i04_job_contract_id -cne
            'ese.v91.i04-restricted-process-launcher/2026-08-01.v1' -or
        [int]$Process.i04_job_active_process_limit -ne 1 -or
        -not [bool]$Process.i04_job_assigned_before_resume) {
        throw 'Started process lacks the mandatory assignment-before-resume job contract'
    }
    [void]$Process.Handle
    $Process.Refresh()
    if ($Process.HasExited) { throw 'Started process exited before ownership binding' }
    $path = Assert-I04NoReparsePath -Path $Process.Path -Kind File
    if ([IO.Path]::GetFullPath($path) -ne
        [IO.Path]::GetFullPath($ExpectedPath)) {
        throw 'Started process path differs from the intended owned executable'
    }
    $pathHash = Get-I04StringSha256 -Value $path.ToLowerInvariant()
    $exeHash = Get-LabSha256 -Path $path
    if ($exeHash -ne $expectedHash) {
        throw 'Started process executable differs from the bound candidate'
    }
    $creationTicks = $Process.StartTime.ToUniversalTime().Ticks
    $cimRows = @(Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop)
    if ($cimRows.Count -ne 1) {
        throw 'Started process CIM creation binding was not unique'
    }
    $cimCreationTicks =
        Get-I04CimProcessCreationUtcTicks -ProcessRow $cimRows[0]
    if ([Math]::Abs([double]($cimCreationTicks - $creationTicks)) -gt
        [TimeSpan]::TicksPerSecond) {
        throw 'Started process creation clocks do not identify the same process'
    }
    $ownerSidHash = Get-I04ProcessOwnerSidHash -ProcessId $Process.Id
    if ($ownerSidHash -ne [string]$script:i04HostIdentity.user_sid_sha256) {
        throw 'Started process is not owned by the bound disposable account'
    }
    $ownershipId = Get-I04StringSha256 -Value (
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f
        $Nonce.ToLowerInvariant(), $OwnerRole, $Process.Id, $creationTicks,
        $cimCreationTicks, $pathHash, $exeHash, $ownerSidHash
    )
    foreach ($entry in ([ordered]@{
        i04_owner_nonce = $Nonce.ToLowerInvariant()
        i04_owner_role = $OwnerRole
        i04_owner_pid = [int]$Process.Id
        i04_owner_creation_utc_ticks = [Int64]$creationTicks
        i04_owner_cim_creation_utc_ticks = [Int64]$cimCreationTicks
        i04_owner_path_sha256 = $pathHash
        i04_owner_executable_sha256 = $exeHash
        i04_owner_sid_sha256 = $ownerSidHash
        i04_ownership_id_sha256 = $ownershipId
        i04_descendant_collector_failed = $false
        i04_descendant_root_identity_contradicted = $false
        i04_descendant_observed = $false
        i04_descendant_observed_process_ids = @()
        i04_descendant_error_sha256 = ''
        i04_descendant_last_census = $null
    }).GetEnumerator()) {
        $Process | Add-Member -NotePropertyName $entry.Key `
            -NotePropertyValue $entry.Value -Force
    }
    return $Process
}

function Test-I04OwnedProcessBinding {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $required = @(
        'i04_owner_nonce', 'i04_owner_role', 'i04_owner_pid',
        'i04_owner_creation_utc_ticks',
        'i04_owner_cim_creation_utc_ticks', 'i04_owner_path_sha256',
        'i04_owner_executable_sha256', 'i04_owner_sid_sha256',
        'i04_ownership_id_sha256', 'i04_descendant_collector_failed',
        'i04_descendant_root_identity_contradicted',
        'i04_descendant_observed', 'i04_descendant_observed_process_ids',
        'i04_descendant_error_sha256', 'i04_descendant_last_census',
        'i04_job_contract_id', 'i04_job_active_process_limit',
        'i04_job_assigned_before_resume', 'i04_job_last_accounting'
    )
    if (@($required | Where-Object {
        $Process.PSObject.Properties.Name -notcontains $_
    }).Count -ne 0) { return $false }
    [void]$Process.Handle
    $Process.Refresh()
    if ($Process.HasExited -or
        [int]$Process.Id -ne [int]$Process.i04_owner_pid -or
        [string]$Process.i04_owner_nonce -ne
            $RunNonce.ToLowerInvariant()) { return $false }
    $actualPath = Assert-I04NoReparsePath -Path $Process.Path -Kind File
    $creationTicks = $Process.StartTime.ToUniversalTime().Ticks
    $pathHash = Get-I04StringSha256 -Value $actualPath.ToLowerInvariant()
    $exeHash = Get-LabSha256 -Path $actualPath
    $ownerSidHash = Get-I04ProcessOwnerSidHash -ProcessId $Process.Id
    $expectedOwnerRole = if ($Role -eq 'Peer') {
        'PeerSource'
    } else { 'CoordinatorClient' }
    $ownershipId = Get-I04StringSha256 -Value (
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f
            [string]$Process.i04_owner_nonce,
            [string]$Process.i04_owner_role,
            [int]$Process.i04_owner_pid,
            [Int64]$Process.i04_owner_creation_utc_ticks,
            [Int64]$Process.i04_owner_cim_creation_utc_ticks,
            [string]$Process.i04_owner_path_sha256,
            [string]$Process.i04_owner_executable_sha256,
            [string]$Process.i04_owner_sid_sha256
    )
    if ([IO.Path]::GetFullPath($actualPath) -ne
            [IO.Path]::GetFullPath($ExpectedPath) -or
        [string]$Process.i04_owner_role -ne $expectedOwnerRole -or
        [Int64]$creationTicks -ne
            [Int64]$Process.i04_owner_creation_utc_ticks -or
        $pathHash -ne [string]$Process.i04_owner_path_sha256 -or
        $exeHash -ne [string]$Process.i04_owner_executable_sha256 -or
        $ownerSidHash -ne [string]$Process.i04_owner_sid_sha256 -or
        $ownerSidHash -ne [string]$script:i04HostIdentity.user_sid_sha256 -or
        $ownershipId -ne [string]$Process.i04_ownership_id_sha256) {
        return $false
    }
    # I04 never claims descendants. A recursive CIM census is persisted on the
    # retained Process object; any observation, identity contradiction or
    # collector failure permanently forbids termination of the root.
    return Test-I04OwnedProcessDescendants -Process $Process
}

function Stop-I04OwnedProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [switch]$ForceImmediate,
        [switch]$RequireGraceful
    )

    if ($ForceImmediate -and $RequireGraceful) {
        throw 'ForceImmediate and RequireGraceful are mutually exclusive'
    }
    if ($null -eq $Process) { return $true }
    try {
        $Process.Refresh()
        if ($Process.HasExited) {
            return Test-I04OwnedProcessDescendants -Process $Process `
                -RootMayHaveExited
        }
        [void]$Process.Handle
        if (-not (Test-I04OwnedProcessBinding -Process $Process `
            -ExpectedPath $ExpectedPath)) { return $false }
        if (-not $ForceImmediate -and
            $Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $null = $Process.CloseMainWindow()
            if ($Process.WaitForExit(10000)) {
                return Test-I04OwnedProcessDescendants -Process $Process `
                    -RootMayHaveExited
            }
        }
        if ($RequireGraceful) { return $false }
        # Both forced branches converge here. Revalidate the complete immutable
        # binding and descendants immediately before killing the retained handle.
        $Process.Refresh()
        if ($Process.HasExited) {
            return Test-I04OwnedProcessDescendants -Process $Process `
                -RootMayHaveExited
        }
        if (-not (Test-I04OwnedProcessBinding -Process $Process `
            -ExpectedPath $ExpectedPath)) { return $false }
        $Process.Kill()
        if (-not $Process.WaitForExit(10000)) { return $false }
        return Test-I04OwnedProcessDescendants -Process $Process `
            -RootMayHaveExited
    } catch {
        return $false
    }
}

function Get-I04Md5Text {
    param([Parameter(Mandatory = $true)][string]$Value)

    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        return ([BitConverter]::ToString(
            $md5.ComputeHash([Text.Encoding]::Unicode.GetBytes($Value))
        )).Replace('-', '')
    } finally {
        $md5.Dispose()
    }
}

function Get-I04ClassicSession {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $encoded = [Uri]::EscapeDataString($Password)
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/?w=password&p=$encoded" `
                -UseBasicParsing -TimeoutSec 10
            $match = [regex]::Match($response.Content, 'ses=(\d+)')
            if ($match.Success) { return $match.Groups[1].Value }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Classic WebServer login failed on port $Port"
}

function Get-I04SharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][Int64]$FileBytes
    )

    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$Port/?ses=$Session&w=shared" `
            -UseBasicParsing -TimeoutSec 15
        $pattern = 'ed2k://\|file\|' + [regex]::Escape($FileName) +
            '\|' + $FileBytes +
            '\|([A-Fa-f0-9]{32})(?:\|h=[A-Z2-7]{32})?\|/'
        $match = [regex]::Match($response.Content, $pattern)
        if ($match.Success) {
            return [pscustomobject][ordered]@{
                link = $match.Value
                ed2k_hash = $match.Groups[1].Value.ToUpperInvariant()
            }
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for '$FileName' to enter the shared list"
}

function Get-I04TransferSnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{32}$')][string]$FileHash
    )

    $response = Invoke-WebRequest `
        -Uri "http://127.0.0.1:$Port/?ses=$Session&w=transfer" `
        -UseBasicParsing -TimeoutSec 15
    $content = [string]$response.Content
    $hash = $FileHash.ToUpperInvariant()
    $anchor = $content.IndexOf(
        $hash, [StringComparison]::OrdinalIgnoreCase
    )
    if ($anchor -lt 0) {
        return [pscustomobject][ordered]@{
            captured_at_utc = Get-LabUtcTimestamp
            found = $false
            file_hash = $hash
            state = ''
            size_text = ''
            transferred_text = ''
            transferred_nonzero = $false
            source_active = $null
            source_total = $null
            source_transferring = $null
            row_sha256 = ''
        }
    }

    $rowStart = $content.LastIndexOf(
        '<tr', $anchor, [StringComparison]::OrdinalIgnoreCase
    )
    if ($rowStart -lt 0) { $rowStart = [Math]::Max(0, $anchor - 2048) }
    $nextAnchor = $content.IndexOf(
        'downmenu(event', $anchor + $hash.Length,
        [StringComparison]::OrdinalIgnoreCase
    )
    $rowEnd = if ($nextAnchor -gt $rowStart) {
        $nextAnchor
    } else {
        [Math]::Min($content.Length, $anchor + 8192)
    }
    $row = $content.Substring($rowStart, $rowEnd - $rowStart)
    $stateMatch = [regex]::Match(
        $row,
        "(?is)downmenu\(event,'[^']*','[^']*','[^']*'," +
            "'(?<state>[^']*)'[^)]*" + [regex]::Escape($hash)
    )
    $progressMatch = [regex]::Match(
        $row,
        '(?is)' + [regex]::Escape($hash) +
            '.*?</td>\s*</tr>\s*</table>\s*</td>\s*' +
            '<td[^>]*>(?<size>.*?)</td>\s*' +
            '<td[^>]*>(?<transferred>.*?)</td>'
    )
    $sourceMatch = [regex]::Match(
        $row,
        '(?is)(?<active>\d+)\s*(?:&nbsp;|\s)*\/' +
            '\s*(?:&nbsp;|\s)*(?<total>\d+)\s*' +
            '(?:&nbsp;|\s)*\((?<transferring>\d+)\)'
    )
    $strip = {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        $plain = [regex]::Replace($Value, '<[^>]+>', '')
        return [Net.WebUtility]::HtmlDecode($plain).Trim()
    }
    $sizeText = if ($progressMatch.Success) {
        & $strip $progressMatch.Groups['size'].Value
    } else { '' }
    $transferredText = if ($progressMatch.Success) {
        & $strip $progressMatch.Groups['transferred'].Value
    } else { '' }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        found = $true
        file_hash = $hash
        state = if ($stateMatch.Success) {
            $stateMatch.Groups['state'].Value.ToLowerInvariant()
        } elseif ($row -match '(?i)down-line-(stopped|paused|downloading|waiting)') {
            $Matches[1].ToLowerInvariant()
        } else { '' }
        size_text = $sizeText
        transferred_text = $transferredText
        transferred_nonzero = $transferredText -notin @('', '-') -and
            $transferredText -match '[1-9]'
        source_active = if ($sourceMatch.Success) {
            [int]$sourceMatch.Groups['active'].Value
        } else { $null }
        source_total = if ($sourceMatch.Success) {
            [int]$sourceMatch.Groups['total'].Value
        } else { $null }
        source_transferring = if ($sourceMatch.Success) {
            [int]$sourceMatch.Groups['transferring'].Value
        } else { $null }
        row_sha256 = Get-LabStringSha256 -Value $row
    }
}

function Invoke-I04DownloadOperation {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)]
        [ValidateSet('stop', 'pause', 'resume')][string]$Operation,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{32}$')][string]$FileHash,
        [AllowNull()][object]$PreparedBoundary = $null
    )

    if ($null -eq $PreparedBoundary) {
        $before = [DateTimeOffset]::UtcNow
        $beforeEpochMs = Get-I04EpochMilliseconds -Timestamp $before
        $beforeQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    } else {
        if ([string]$PreparedBoundary.operation -ne $Operation -or
            [string]$PreparedBoundary.file_hash -ne
                $FileHash.ToUpperInvariant() -or
            [double]$PreparedBoundary.boundary_before_request_epoch_ms -le 0 -or
            [Int64]$PreparedBoundary.boundary_before_request_qpc -le 0 -or
            [Int64]$PreparedBoundary.qpc_frequency -ne
                [Diagnostics.Stopwatch]::Frequency) {
            throw 'Prepared Classic Web operation boundary is invalid'
        }
        $before = [DateTimeOffset]::Parse(
            [string]$PreparedBoundary.boundary_before_request_utc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $beforeEpochMs =
            [double]$PreparedBoundary.boundary_before_request_epoch_ms
        $beforeQpc =
            [Int64]$PreparedBoundary.boundary_before_request_qpc
    }
    $response = Invoke-WebRequest -Uri (
        "http://127.0.0.1:$Port/?ses=$Session&w=transfer" +
        "&op=$Operation&file=$($FileHash.ToUpperInvariant())"
    ) -UseBasicParsing -TimeoutSec 15
    $afterQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    $after = [DateTimeOffset]::UtcNow
    return [pscustomobject][ordered]@{
        operation = $Operation
        file_hash = $FileHash.ToUpperInvariant()
        boundary_before_request_utc = $before.ToString('o')
        boundary_before_request_epoch_ms = $beforeEpochMs
        boundary_before_request_qpc = $beforeQpc
        response_completed_utc = $after.ToString('o')
        response_completed_epoch_ms =
            Get-I04EpochMilliseconds -Timestamp $after
        response_completed_qpc = $afterQpc
        qpc_frequency = [Diagnostics.Stopwatch]::Frequency
        request_completed = $true
        request_error = $null
        http_status = [int]$response.StatusCode
        response_sha256 = Get-LabStringSha256 -Value (
            [string]$response.Content
        )
    }
}

function Initialize-I04CopyData {
    $contractId = 'ese.v91.i04-copydata/2026-08-01.v1'
    if ('V91I04CopyData' -as [type]) {
        $null = Assert-I04ManagedTypeContract `
            -TypeName 'V91I04CopyData' -ExpectedContractId $contractId
        return
    }

    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I04CopyData {
    public const string ContractId = "ese.v91.i04-copydata/2026-08-01.v1";
    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, IntPtr wParam, ref COPYDATASTRUCT lParam,
        uint flags, uint timeoutMilliseconds, out IntPtr result);
}
'@
    $null = Assert-I04ManagedTypeContract `
        -TypeName 'V91I04CopyData' -ExpectedContractId $contractId
}

function Send-I04Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Link
    )

    Initialize-I04CopyData

    $handle = [IntPtr]::Zero
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Downloader exited before link injection' }
        $handle = $Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handle -eq [IntPtr]::Zero) {
        throw 'Downloader main window handle was not available'
    }

    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91I04CopyData+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $messageResult = [IntPtr]::Zero
        $sent = [V91I04CopyData]::SendMessageTimeout(
            $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
            0x0003, 5000, [ref]$messageResult
        )
        if ($sent -eq [IntPtr]::Zero) {
            $win32 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Timed out or failed injecting the eD2K link (Win32=$win32)"
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function Test-I04TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [ValidateRange(100, 10000)][int]$TimeoutMilliseconds = 3000
    )

    $startedAt = [DateTimeOffset]::UtcNow
    $startedEpochMs = Get-I04EpochMilliseconds -Timestamp $startedAt
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $socket = New-Object Net.Sockets.TcpClient($Address.AddressFamily)
    $connected = $false
    $timedOut = $false
    $errorText = $null
    $localAddress = $null
    $localPort = $null
    try {
        $task = $socket.ConnectAsync($Address, $Port)
        $completed = [Threading.Tasks.Task]::WaitAny(
            [Threading.Tasks.Task[]]@($task), $TimeoutMilliseconds
        )
        if ($completed -lt 0) {
            $timedOut = $true
        } elseif ($task.IsFaulted) {
            $errorText = $task.Exception.GetBaseException().Message
        } elseif ($task.IsCanceled) {
            $errorText = 'connection task canceled'
        } else {
            $connected = $socket.Connected
            if ($connected -and $null -ne $socket.Client.LocalEndPoint) {
                $localAddress = Get-I04NormalizedIp -Address (
                    [string]$socket.Client.LocalEndPoint.Address
                )
                $localPort = [int]$socket.Client.LocalEndPoint.Port
            }
        }
    } catch {
        $errorText = $_.Exception.GetBaseException().Message
    } finally {
        $watch.Stop()
        $socket.Dispose()
    }
    $finishedAt = [DateTimeOffset]::UtcNow
    return [pscustomobject][ordered]@{
        started_at_utc = $startedAt.ToString('o')
        finished_at_utc = $finishedAt.ToString('o')
        started_epoch_ms = $startedEpochMs
        finished_epoch_ms = Get-I04EpochMilliseconds -Timestamp $finishedAt
        address = $Address.ToString()
        family = if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
        port = $Port
        connected = $connected
        timed_out = $timedOut
        duration_ms = $watch.ElapsedMilliseconds
        local_address = $localAddress
        local_port = $localPort
        error = $errorText
    }
}

function Initialize-I04UiProbe {
    $contractId = 'ese.v91.i04-ui-probe/2026-08-01.v1'
    if ('V91I04UiProbe' -as [type]) {
        $null = Assert-I04ManagedTypeContract -TypeName 'V91I04UiProbe' `
            -ExpectedContractId $contractId
        return
    }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91I04UiProbe {
    public const string ContractId = "ese.v91.i04-ui-probe/2026-08-01.v1";
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out IntPtr result);
}
'@
    $null = Assert-I04ManagedTypeContract -TypeName 'V91I04UiProbe' `
        -ExpectedContractId $contractId
}

function Get-I04UiProbe {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    Initialize-I04UiProbe
    $Process.Refresh()
    $handle = $Process.MainWindowHandle
    $present = $handle -ne [IntPtr]::Zero
    $responsive = $false
    $duration = 0L
    if ($present) {
        $result = [IntPtr]::Zero
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $sent = [V91I04UiProbe]::SendMessageTimeout(
            $handle, 0, [IntPtr]::Zero, [IntPtr]::Zero,
            2, 500, [ref]$result
        )
        $watch.Stop()
        $duration = $watch.ElapsedMilliseconds
        $responsive = $sent -ne [IntPtr]::Zero
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        process_id = $Process.Id
        main_window_present = $present
        message_pump_responsive = $responsive
        probe_duration_ms = $duration
    }
}

function Get-I04ApiProbe {
    param([Parameter(Mandatory = $true)][int]$Port)

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $available = $false
    $statusAvailable = $false
    $v9Available = $false
    $errorText = $null
    $status = $null
    $v9 = $null
    try {
        $status = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$Port/api/status" `
            -TimeoutSec 2
        $null = Assert-I04ApiStatusContract -Status $status
        $statusAvailable = $true
        $v9 = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$Port/api/ese/v9" `
            -TimeoutSec 2
        $null = Assert-I04ApiV9Contract -Value $v9
        $v9Available = $true
        $available = $statusAvailable -and $v9Available
    } catch {
        $errorText = Get-I04SafeErrorToken -Context 'API probe failed' `
            -Message $_.Exception.Message
    } finally {
        $watch.Stop()
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        available = $available
        status_available = $statusAvailable
        v9_available = $v9Available
        duration_ms = $watch.ElapsedMilliseconds
        error = $errorText
        user_hash = if ($null -eq $status) {
            ''
        } else { [string]$status.user_hash }
        ed2k_connected = $null -ne $status -and
            [bool]$status.ed2k_connected
        kad_running_mask = if ($null -eq $status) {
            $null
        } else { [Int64]$status.kad_running_mask }
        kad2_running = $null -ne $status -and [bool]$status.kad2_running
        kad6_running = $null -ne $status -and [bool]$status.kad6_running
        netlab_consent = if ($null -eq $status) {
            ''
        } else { [string]$status.netlab_consent }
        netlab_advanced_consent = if ($null -eq $status) {
            ''
        } else { [string]$status.netlab_advanced_consent }
        netlab_contribution_consent = if ($null -eq $status) {
            ''
        } else { [string]$status.netlab_contribution_consent }
        netlab_enabled = $null -ne $status -and
            [bool]$status.netlab_enabled
        utp_hole_punch_enabled = $null -ne $status -and
            [bool]$status.utp_hole_punch_enabled
        connecting_client_count = if ($null -eq $status -or
            $null -eq $status.connecting_client_count) {
            $null
        } else { [Int64]$status.connecting_client_count }
        connecting_client_adds = if ($null -eq $status -or
            $null -eq $status.connecting_client_adds) {
            $null
        } else { [Int64]$status.connecting_client_adds }
        connecting_client_high_water = if ($null -eq $status -or
            $null -eq $status.connecting_client_high_water) {
            $null
        } else { [Int64]$status.connecting_client_high_water }
        connecting_client_duplicate_adds = if ($null -eq $status -or
            $null -eq $status.connecting_client_duplicate_adds) {
            $null
        } else { [Int64]$status.connecting_client_duplicate_adds }
        v9 = $v9
    }
}

function Test-I04ApiIsolation {
    param(
        [Parameter(Mandatory = $true)][object]$Data,
        [Parameter(Mandatory = $true)][bool]$RequireEd2k
    )

    if (-not [bool]$Data.available -or
        [string]$Data.user_hash -notmatch '^[0-9A-Fa-f]{32}$' -or
        [bool]$Data.ed2k_connected -ne $RequireEd2k -or
        [Int64]$Data.kad_running_mask -ne 0 -or
        [bool]$Data.kad2_running -or [bool]$Data.kad6_running -or
        [string]$Data.netlab_consent -eq 'accepted' -or
        [string]$Data.netlab_advanced_consent -eq 'accepted' -or
        [string]$Data.netlab_contribution_consent -eq 'accepted' -or
        [bool]$Data.netlab_enabled -or
        [bool]$Data.utp_hole_punch_enabled) {
        return $false
    }
    $v9 = $Data.v9
    if ($null -eq $v9 -or -not [bool]$v9.success -or
        [bool]$v9.netlab.enabled -or
        [bool]$v9.netlab.capability_advertised -or
        [bool]$v9.netlab.staged.selector -or
        [bool]$v9.netlab.staged.port_predict -or
        [bool]$v9.netlab.staged.ed2k_punch3 -or
        [bool]$v9.netlab.staged.kad3_rendezvous -or
        [bool]$v9.netlab.independent.relay_accept -or
        [bool]$v9.netlab.independent.relay_egress -or
        [bool]$v9.netlab.independent.krp -or
        [bool]$v9.netlab.independent.kad6_beta_exit -or
        [bool]$v9.netlab.independent.kad6_stable_public_exit -or
        [bool]$v9.netlab.keepalive_running -or
        [bool]$v9.v9.experimental -or
        [bool]$v9.v9.port_predict -or
        [bool]$v9.v9.ed2k_punch3 -or
        [bool]$v9.v9.kad3_rendezvous -or
        [bool]$v9.v9.keepalive_running -or
        [bool]$v9.v9.hole_punch_master) {
        return $false
    }
    return $true
}

function Get-I04ProductLogCounts {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$PeerIPv4,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [Parameter(Mandatory = $true)][int]$PeerPort,
        [string]$FileAName = '',
        [string]$FileBName = ''
    )

    $fallback = 0
    $boundedFallback = 0
    $hello = 0
    $helloAnswer = 0
    $a4afSwap = 0
    $ambiguous = 0
    $files = @()
    $collectorErrors = [System.Collections.Generic.List[string]]::new()
    $v4 = [regex]::Escape($PeerIPv4)
    $v6 = [regex]::Escape($PeerIPv6)
    $port = [regex]::Escape([string]$PeerPort)
    # DebugSend(client) and IPv6Fallback deliberately render
    # DbgGetClientInfo(), whose native endpoint contains the authoritative
    # address but no TCP port.  The isolated profile, exact PID/socket
    # correlation and PCAP provide the port attribution; requiring a textual
    # ":port" here would reject every genuine product marker.
    $exactTarget = '(?i)(?:' + $v4 + '|\[?' + $v6 + '\]?)'
    $possiblyRelevant = '(?i)(?<!\d)' + $port + '(?!\d)'
    $logs = @()
    try {
        $logs = @(Get-ChildItem -LiteralPath $NodePath -Recurse -File `
            -Filter '*.log' -ErrorAction Stop)
    } catch {
        $collectorErrors.Add((Get-I04SafeErrorToken `
            -Context 'product log enumeration failed' `
            -Message $_.Exception.Message))
    }
    foreach ($log in $logs) {
        try {
            # Read each active log exactly once.  Counts, byte length and hash
            # must describe the same immutable in-memory snapshot even when
            # eMule appends to the underlying file concurrently.
            $stream = [IO.FileStream]::new(
                $log.FullName, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite
            )
            try {
                $memory = [IO.MemoryStream]::new()
                try {
                    $stream.CopyTo($memory)
                    $logBytes = $memory.ToArray()
                } finally {
                    $memory.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
            $shaObject = [Security.Cryptography.SHA256]::Create()
            try {
                $logSha256 = ([BitConverter]::ToString(
                    $shaObject.ComputeHash($logBytes)
                )).Replace('-', '').ToLowerInvariant()
            } finally {
                $shaObject.Dispose()
            }
            $offset = 0
            $encoding = [Text.Encoding]::UTF8
            if ($logBytes.Length -ge 2 -and
                $logBytes[0] -eq 0xFF -and $logBytes[1] -eq 0xFE) {
                $encoding = [Text.Encoding]::Unicode
                $offset = 2
            } elseif ($logBytes.Length -ge 2 -and
                $logBytes[0] -eq 0xFE -and $logBytes[1] -eq 0xFF) {
                $encoding = [Text.Encoding]::BigEndianUnicode
                $offset = 2
            } elseif ($logBytes.Length -ge 3 -and
                $logBytes[0] -eq 0xEF -and
                $logBytes[1] -eq 0xBB -and $logBytes[2] -eq 0xBF) {
                $offset = 3
            }
            $logContent = $encoding.GetString(
                $logBytes, $offset, $logBytes.Length - $offset
            )
            $lines = @([regex]::Split($logContent, '\r\n|\n|\r'))
        } catch {
            $collectorErrors.Add((Get-I04SafeErrorToken `
                -Context 'product log collection failed' `
                -Message $_.Exception.Message))
            continue
        }
        foreach ($lineValue in $lines) {
            $line = [string]$lineValue
            $isFallback = $line -match
                'IPv6 connect failed \([^\r\n]+retrying [^\r\n]+ over IPv4'
            $isBounded = $line -match
                'IPv6 connect failed \([^\r\n]*bounded blackhole timeout'
            $isHello = $line -match '>>>\s+OP_Hello\s+to\s+'
            $isHelloAnswer = $line -match
                '<<<\s+OP_HelloAnswer\s+from\s+'
            $isA4afSwap = $FileAName -and $FileBName -and
                $line -match '(?i)ooo Swapped source ' -and
                $line -match [regex]::Escape($FileAName) -and
                $line -match [regex]::Escape($FileBName)
            if (-not (
                $isFallback -or $isBounded -or $isHello -or
                $isHelloAnswer -or $isA4afSwap
            )) { continue }
            if ($line -match $exactTarget) {
                if ($isFallback) { $fallback++ }
                if ($isBounded) { $boundedFallback++ }
                if ($isHello) { $hello++ }
                if ($isHelloAnswer) { $helloAnswer++ }
                if ($isA4afSwap) { $a4afSwap++ }
            } elseif ($line -match $possiblyRelevant) {
                # A marker carrying only the target port cannot be attributed
                # to the peer address and is deliberately ambiguous.
                $ambiguous++
            }
        }
        $files += [pscustomobject][ordered]@{
            relative_path = $log.FullName.Substring(
                [IO.Path]::GetFullPath($NodePath).Length
            ).TrimStart('\')
            bytes = [Int64]$logBytes.Length
            sha256 = $logSha256
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-product-log-counts/v2'
        captured_at_utc = Get-LabUtcTimestamp
        collector_ok = ($collectorErrors.Count -eq 0)
        adjudicable = $collectorErrors.Count -eq 0 -and $files.Count -gt 0
        log_file_count = $files.Count
        collector_errors = @($collectorErrors.ToArray())
        fallback_count = $fallback
        bounded_fallback_count = $boundedFallback
        hello_send_count = $hello
        hello_answer_receive_count = $helloAnswer
        a4af_swap_a_to_b_count = $a4afSwap
        ambiguous_target_marker_count = $ambiguous
        target = [ordered]@{
            ipv4 = $PeerIPv4
            ipv6 = $PeerIPv6
            tcp_port = $PeerPort
            file_a_name = $FileAName
            file_b_name = $FileBName
        }
        files = $files
    }
}

function Enable-I04ControlledEd2kProfile {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1024, 65535)][int]$ServerPort,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$OwnerRole
    )

    $serverIp = [Net.IPAddress]::Parse($ServerAddress)
    if ($serverIp.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
        -not (Test-I04UsableLocalIPv4 -Address $serverIp.ToString())) {
        throw 'Controlled eD2K profile requires a non-loopback IPv4 server'
    }
    $preferences = Join-Path $NodePath 'config\preferences.ini'
    $contract = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in ([ordered]@{
        Autoconnect = '1'
        NetworkKademlia = '0'
        AutoConnectStaticOnly = '1'
        Reconnect = '1'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        FilterServersByIP = '0'
        ServerKeepAliveTimeout = '60000'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
        $contract.Add([pscustomobject]@{
            section = 'eMule'; key = $entry.Key; value = $entry.Value
        })
    }
    foreach ($entry in ([ordered]@{
        NetworkED2K = '1'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
        $contract.Add([pscustomobject]@{
            section = 'Connection'; key = $entry.Key; value = $entry.Value
        })
    }
    $preferenceContractEvidence = Set-I04StoredPreferenceContract `
        -NodePath $NodePath -Contract $contract.ToArray() -Merge

    $config = Join-Path $NodePath 'config'
    foreach ($name in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak', 'staticservers.dat'
    )) {
        $path = Join-Path $config $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    $staticPath = Join-Path $config 'staticservers.dat'
    $line = '{0}:{1},0,eSE-I04-{2}-{3}' -f
        $ServerAddress, $ServerPort, $RunNonce, $OwnerRole
    [IO.File]::WriteAllText(
        $staticPath, ($line + "`r`n"),
        (New-Object Text.UnicodeEncoding($false, $true))
    )
    return [pscustomobject][ordered]@{
        endpoint = "$ServerAddress`:$ServerPort"
        endpoint_scope = 'same-host assigned physical IPv4'
        staticservers_relative_path = 'config\staticservers.dat'
        staticservers_sha256 = Get-LabSha256 -Path $staticPath
        preferences_sha256 = Get-LabSha256 -Path $preferences
        network_ed2k = $true
        network_kad = $false
        auto_connect_static_only = $true
        filter_lan_ips = $false
        third_party_server_files_removed = $true
        preference_contract = $preferenceContractEvidence
    }
}

function Start-I04ControlledEd2kServer {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedClientAddress,
        [Parameter(Mandatory = $true)][string]$HighIdAddress,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$OwnerRole,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[object]]$OwnerInventory
    )

    $listenIp = [Net.IPAddress]::Parse($ListenAddress)
    $expectedClientIp = [Net.IPAddress]::Parse($ExpectedClientAddress)
    $highIdIp = [Net.IPAddress]::Parse($HighIdAddress)
    foreach ($validatedIp in @($listenIp, $expectedClientIp, $highIdIp)) {
        if ($validatedIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
            [Net.IPAddress]::IsLoopback($validatedIp)) {
            throw 'Controlled eD2K server addresses must be non-loopback IPv4'
        }
    }
    $highIdBytes = $highIdIp.GetAddressBytes()
    $highIdNumeric = [BitConverter]::ToUInt32($highIdBytes, 0)
    if ($highIdNumeric -lt 0x01000000) {
        throw "Controlled server ID derived from $HighIdAddress is LowID"
    }

    # Publish an ownership record before the first external mutation.  The
    # caller can therefore retry cleanup even when construction throws before
    # this function can return its normal server handle.
    $owner = [pscustomobject][ordered]@{
        owner_id = Get-I04StringSha256 -Value (
            '{0}|{1}|{2}' -f $RunNonce, $OwnerRole, $EvidencePath
        )
        owner_role = $OwnerRole
        evidence_path = $EvidencePath
        started_at_utc = Get-LabUtcTimestamp
        listener = $null
        port = $null
        state = $null
        powershell = $null
        async = $null
        construction_complete = $false
        construction_error = ''
        construction_rollback = $null
        cleanup_attempt_count = 0
        cleanup_complete = $false
        cleanup_result = $null
    }
    $OwnerInventory.Add($owner)

    try {
        $listener = New-Object Net.Sockets.TcpListener($listenIp, 0)
        $owner.listener = $listener
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start(4)
        $port = [int]([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $owner.port = $port
        $state = New-Object `
            'Collections.Concurrent.ConcurrentDictionary[string,object]'
        $owner.state = $state
        $logins = New-Object 'Collections.Concurrent.ConcurrentQueue[object]'
        $state['phase'] = 'listening'
        $state['stop_requested'] = $false
        $state['error'] = ''
        $state['listen_port'] = $port
        $state['listen_address'] = $ListenAddress
        $state['expected_client_address'] = $ExpectedClientAddress
        $state['high_id_address'] = $HighIdAddress
        $state['high_id_numeric'] = [uint32]$highIdNumeric
        $state['login_count'] = 0
        $state['logins'] = $logins

    $serverBody = {
        param(
            $Listener, $State, $ResultPath, $Nonce, $RoleName,
            $AllowedClientAddress, [byte[]]$AssignedIdBytes
        )

        function Read-ExactBytes {
            param(
                [Parameter(Mandatory = $true)]
                [Net.Sockets.NetworkStream]$Stream,
                [Parameter(Mandatory = $true)][int]$Count
            )
            $buffer = New-Object byte[] $Count
            $offset = 0
            while ($offset -lt $Count) {
                $read = $Stream.Read($buffer, $offset, $Count - $offset)
                if ($read -le 0) {
                    throw (
                        "Controlled server stream closed after " +
                        "$offset/$Count bytes"
                    )
                }
                $offset += $read
            }
            return $buffer
        }

        function Send-Ed2kFrame {
            param(
                [Parameter(Mandatory = $true)]
                [Net.Sockets.NetworkStream]$Stream,
                [Parameter(Mandatory = $true)][byte]$Opcode,
                [Parameter(Mandatory = $true)][byte[]]$Payload
            )
            $header = New-Object byte[] 6
            $header[0] = 0xE3
            [Array]::Copy(
                [BitConverter]::GetBytes([uint32]($Payload.Length + 1)),
                0, $header, 1, 4
            )
            $header[5] = $Opcode
            $Stream.Write($header, 0, $header.Length)
            if ($Payload.Length -gt 0) {
                $Stream.Write($Payload, 0, $Payload.Length)
            }
            $Stream.Flush()
        }

        $stoppedAt = ''
        try {
            while (-not [bool]$State['stop_requested']) {
                $client = $null
                $stream = $null
                try {
                    $State['phase'] = 'accepting'
                    $client = $Listener.AcceptTcpClient()
                    if ([bool]$State['stop_requested']) { break }
                    $State['client'] = $client
                    $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
                    if ($remote.Address.ToString() -ne
                        $AllowedClientAddress) {
                        throw (
                            "Controlled server accepted unexpected client " +
                            "$remote; expected $AllowedClientAddress"
                        )
                    }
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 30000
                    $header = Read-ExactBytes -Stream $stream -Count 6
                    $packetLength = [BitConverter]::ToUInt32($header, 1)
                    if ($header[0] -ne 0xE3 -or
                        $header[5] -ne 0x01 -or
                        $packetLength -lt 23 -or
                        $packetLength -gt 1048576) {
                        throw (
                            'Expected OP_EDONKEYPROT:OP_LOGINREQUEST; ' +
                            "protocol=0x$('{0:X2}' -f $header[0]) " +
                            "opcode=0x$('{0:X2}' -f $header[5]) " +
                            "length=$packetLength"
                        )
                    }
                    $payload = Read-ExactBytes -Stream $stream `
                        -Count ([int]$packetLength - 1)
                    $hashBytes = New-Object byte[] 16
                    [Array]::Copy($payload, 0, $hashBytes, 0, 16)
                    $userHash = ([BitConverter]::ToString(
                        $hashBytes
                    )).Replace('-', '')
                    if ($userHash -eq ('0' * 32) -or
                        $hashBytes[5] -ne 14 -or
                        $hashBytes[14] -ne 111) {
                        throw 'LOGINREQUEST contains an invalid eMule user hash'
                    }
                    $sha = [Security.Cryptography.SHA256]::Create()
                    try {
                        $payloadSha = ([BitConverter]::ToString(
                            $sha.ComputeHash($payload)
                        )).Replace('-', '').ToLowerInvariant()
                    } finally {
                        $sha.Dispose()
                    }
                    $advertisedPort =
                        [int][BitConverter]::ToUInt16($payload, 20)
                    Send-Ed2kFrame -Stream $stream -Opcode 0x40 `
                        -Payload $AssignedIdBytes
                    $loginIndex = [int]$State['login_count'] + 1
                    $loginAt = [DateTime]::UtcNow.ToString('o')
                    $login = [pscustomobject][ordered]@{
                        index = $loginIndex
                        login_at_utc = $loginAt
                        accepted_remote = $remote.ToString()
                        protocol = [int]$header[0]
                        opcode = [int]$header[5]
                        payload_bytes = $payload.Length
                        payload_sha256 = $payloadSha
                        user_hash = $userHash
                        advertised_tcp_port = $advertisedPort
                    }
                    $State['logins'].Enqueue($login)
                    $State['login_count'] = $loginIndex
                    $State['latest_user_hash'] = $userHash
                    $State['latest_advertised_tcp_port'] = $advertisedPort
                    $State['latest_client_remote'] = $remote.ToString()
                    $State['reply_sent'] = $true
                    $State['phase'] = 'connected'
                    $stream.ReadTimeout = 2000
                    $nextStatus = [DateTime]::UtcNow.AddSeconds(10)
                    while (-not [bool]$State['stop_requested']) {
                        if ($client.Client.Poll(
                            1000,
                            [Net.Sockets.SelectMode]::SelectRead
                        ) -and $client.Client.Available -eq 0) {
                            break
                        }
                        if ($stream.DataAvailable) {
                            $nextHeader =
                                Read-ExactBytes -Stream $stream -Count 6
                            $nextLength =
                                [BitConverter]::ToUInt32($nextHeader, 1)
                            if ($nextLength -lt 1 -or
                                $nextLength -gt 16777216) {
                                throw "Invalid client frame length $nextLength"
                            }
                            $remaining = [int]$nextLength - 1
                            if ($remaining -gt 0) {
                                $null = Read-ExactBytes -Stream $stream `
                                    -Count $remaining
                            }
                        } elseif ([DateTime]::UtcNow -ge $nextStatus) {
                            Send-Ed2kFrame -Stream $stream -Opcode 0x34 `
                                -Payload (New-Object byte[] 8)
                            $nextStatus =
                                [DateTime]::UtcNow.AddSeconds(10)
                        } else {
                            Start-Sleep -Milliseconds 25
                        }
                    }
                } finally {
                    if ($null -ne $stream) {
                        try { $stream.Dispose() } catch {}
                    }
                    if ($null -ne $client) {
                        try { $client.Dispose() } catch {}
                    }
                    $removedClient = $null
                    $null = $State.TryRemove(
                        'client', [ref]$removedClient
                    )
                }
            }
        } catch {
            if (-not [bool]$State['stop_requested']) {
                $sha = [Security.Cryptography.SHA256]::Create()
                try {
                    $digest = $sha.ComputeHash(
                        [Text.Encoding]::UTF8.GetBytes($_.Exception.Message)
                    )
                } finally { $sha.Dispose() }
                $State['error'] = 'controlled server runtime failed ' +
                    '[error_sha256=' +
                    ([BitConverter]::ToString($digest)).Replace('-', '').
                        ToLowerInvariant() + ']'
                $State['phase'] = 'error'
            }
        } finally {
            $stoppedAt = [DateTime]::UtcNow.ToString('o')
            try { $Listener.Stop() } catch {}
            if ([string]$State['phase'] -ne 'error') {
                $State['phase'] = 'stopped'
            }
            $State['stopped_at_utc'] = $stoppedAt
            $result = [ordered]@{
                schema = 'ese.v91.i04-controlled-ed2k-server/v1'
                run_nonce = $Nonce
                owner_role = $RoleName
                listen_address = [string]$State['listen_address']
                listen_port = [int]$State['listen_port']
                high_id_address = [string]$State['high_id_address']
                high_id_numeric = [uint32]$State['high_id_numeric']
                stopped_at_utc = $stoppedAt
                phase = [string]$State['phase']
                login_count = [int]$State['login_count']
                login_events = @($State['logins'].ToArray())
                error = [string]$State['error']
            }
            [IO.File]::WriteAllText(
                $ResultPath,
                ($result | ConvertTo-Json -Depth 24),
                (New-Object Text.UTF8Encoding($false))
            )
        }
    }

        $powershell = [PowerShell]::Create()
        $owner.powershell = $powershell
        $null = $powershell.AddScript($serverBody.ToString())
        $null = $powershell.AddArgument($listener)
        $null = $powershell.AddArgument($state)
        $null = $powershell.AddArgument($EvidencePath)
        $null = $powershell.AddArgument($RunNonce)
        $null = $powershell.AddArgument($OwnerRole)
        $null = $powershell.AddArgument($ExpectedClientAddress)
        $null = $powershell.AddArgument($highIdBytes)
        $async = $powershell.BeginInvoke()
        $owner.async = $async
        $owner.construction_complete = $true
        return $owner
    } catch {
        $constructionFailure = $_
        $owner.construction_error = Get-I04SafeErrorToken `
            -Context 'controlled server construction failed' `
            -Message $_.Exception.Message
        try {
            $owner.construction_rollback =
                Stop-I04ControlledEd2kServer -Server $owner
        } catch {
            $owner.construction_rollback = [pscustomobject][ordered]@{
                stopped = $false
                error = Get-I04SafeErrorToken `
                    -Context 'controlled server construction rollback failed' `
                    -Message $_.Exception.Message
                evidence = $null
            }
        }
        throw $constructionFailure
    }
}

function Wait-I04ControlledEd2kLogin {
    param(
        [Parameter(Mandatory = $true)][object]$Server,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$ExpectedTcpPort,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 16)][int]$MinimumLoginCount,
        [ValidateRange(5, 120)][int]$TimeoutSeconds = 60
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Candidate exited before controlled eD2K login'
        }
        if ([string]$Server.state['error']) {
            throw "Controlled eD2K server failed: $($Server.state['error'])"
        }
        $loginCount = [int]$Server.state['login_count']
        if ($loginCount -ge $MinimumLoginCount -and
            [bool]$Server.state['reply_sent']) {
            $connections = @(
                Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                    [string]$_.State -eq 'Established' -and
                    [int]$_.OwningProcess -eq $Process.Id -and
                    (Get-I04NormalizedIp -Address $_.RemoteAddress) -eq
                        [string]$Server.state['listen_address'] -and
                    [int]$_.RemotePort -eq [int]$Server.port
                }
            )
            if ($connections.Count -eq 1 -and
                [int]$Server.state['latest_advertised_tcp_port'] -eq
                    $ExpectedTcpPort) {
                return [pscustomobject][ordered]@{
                    connected = $true
                    login_count = $loginCount
                    server_address =
                        [string]$Server.state['listen_address']
                    server_port = $Server.port
                    client_process_id = $Process.Id
                    client_local_address =
                        Get-I04NormalizedIp -Address `
                            ([string]$connections[0].LocalAddress)
                    client_local_port = [int]$connections[0].LocalPort
                    runtime_user_hash =
                        [string]$Server.state['latest_user_hash']
                    advertised_tcp_port =
                        [int]$Server.state['latest_advertised_tcp_port']
                    assigned_high_id_address =
                        [string]$Server.state['high_id_address']
                    assigned_high_id_numeric =
                        [uint32]$Server.state['high_id_numeric']
                    endpoint_is_same_host_physical = $true
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw (
        'Timed out proving the same-host physical-IP controlled eD2K ' +
        "login #$MinimumLoginCount"
    )
}

function Stop-I04ControlledEd2kServer {
    param([AllowNull()][object]$Server)

    if ($null -eq $Server) {
        return [pscustomobject][ordered]@{
            stopped = $true
            error = $null
            evidence = $null
            owner_id = ''
            construction_complete = $false
            listener_stopped = $true
            powershell_stopped = $true
        }
    }

    $properties = @($Server.PSObject.Properties.Name)
    if ('cleanup_complete' -in $properties -and
        [bool]$Server.cleanup_complete -and
        'cleanup_result' -in $properties -and
        $null -ne $Server.cleanup_result) {
        return $Server.cleanup_result
    }
    if ('cleanup_attempt_count' -in $properties) {
        $Server.cleanup_attempt_count =
            [int]$Server.cleanup_attempt_count + 1
    }

    $errors = [Collections.Generic.List[string]]::new()
    $state = if ('state' -in $properties) { $Server.state } else { $null }
    $listener = if ('listener' -in $properties) {
        $Server.listener
    } else { $null }
    $powershell = if ('powershell' -in $properties) {
        $Server.powershell
    } else { $null }
    $async = if ('async' -in $properties) { $Server.async } else { $null }
    $listenerStopped = $null -eq $listener
    $powershellStopped = $null -eq $powershell

    if ($null -ne $state) {
        try {
            $state['stop_requested'] = $true
            if ($state.ContainsKey('client') -and
                $null -ne $state['client']) {
                try { $state['client'].Close() } catch {
                    $errors.Add((Get-I04SafeErrorToken `
                        -Context 'controlled server client close failed' `
                        -Message $_.Exception.Message))
                }
            }
        } catch {
            $errors.Add((Get-I04SafeErrorToken `
                -Context 'controlled server state stop failed' `
                -Message $_.Exception.Message))
        }
    }
    if ($null -ne $listener) {
        try {
            $listener.Stop()
            $listenerStopped = $true
        } catch {
            $errors.Add((Get-I04SafeErrorToken `
                -Context 'controlled server listener stop failed' `
                -Message $_.Exception.Message))
        }
    }
    if ($null -ne $powershell) {
        try {
            if ($null -ne $async) {
                $completed = $async.AsyncWaitHandle.WaitOne(
                    [TimeSpan]::FromSeconds(10)
                )
                if (-not $completed) {
                    $powershell.Stop()
                    $completed = $async.AsyncWaitHandle.WaitOne(
                        [TimeSpan]::FromSeconds(2)
                    )
                }
                try {
                    $null = $powershell.EndInvoke($async)
                } catch {
                    $stopRequested = $null -ne $state -and
                        [bool]$state['stop_requested']
                    if (-not $stopRequested) {
                        $errors.Add((Get-I04SafeErrorToken `
                            -Context 'controlled server EndInvoke failed' `
                            -Message $_.Exception.Message))
                    }
                }
                $powershellStopped = $completed -or $async.IsCompleted
                if (-not $powershellStopped) {
                    $errors.Add(
                        'controlled server runspace did not stop within 12 seconds'
                    )
                }
            } else {
                # Construction failed after PowerShell::Create but before
                # BeginInvoke.  Disposing this unstarted owner is sufficient.
                try { $powershell.Stop() } catch {}
                $powershellStopped = $true
            }
        } catch {
            $errors.Add((Get-I04SafeErrorToken `
                -Context 'controlled server runspace stop failed' `
                -Message $_.Exception.Message))
        } finally {
            try {
                $powershell.Dispose()
            } catch {
                $errors.Add((Get-I04SafeErrorToken `
                    -Context 'controlled server runspace dispose failed' `
                    -Message $_.Exception.Message))
            }
        }
    }

    $evidence = $null
    $evidencePath = if ('evidence_path' -in $properties) {
        [string]$Server.evidence_path
    } else { '' }
    if ($evidencePath -and
        (Test-Path -LiteralPath $evidencePath -PathType Leaf)) {
        try {
            $evidence = Get-Content -LiteralPath $evidencePath -Raw |
                ConvertFrom-Json -ErrorAction Stop
        } catch {
            $errors.Add((Get-I04SafeErrorToken `
                -Context 'controlled server evidence parse failed' `
                -Message $_.Exception.Message))
        }
    }

    $errorText = @($errors.ToArray() | Select-Object -Unique) -join '; '
    $result = [pscustomobject][ordered]@{
        stopped = $listenerStopped -and $powershellStopped -and
            -not $errorText
        error = if ($errorText) { $errorText } else { $null }
        evidence = $evidence
        owner_id = if ('owner_id' -in $properties) {
            [string]$Server.owner_id
        } else { '' }
        construction_complete =
            'construction_complete' -in $properties -and
            [bool]$Server.construction_complete
        listener_stopped = $listenerStopped
        powershell_stopped = $powershellStopped
    }
    if ('cleanup_complete' -in $properties) {
        $Server.cleanup_complete = [bool]$result.stopped
    }
    if ('cleanup_result' -in $properties) {
        $Server.cleanup_result = $result
    }
    return $result
}

function Stop-I04ControlledEd2kServerInventory {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[object]]$OwnerInventory,
        [AllowNull()][object]$PrimaryServer = $null
    )

    $owners = [System.Collections.Generic.List[object]]::new()
    $seen = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    foreach ($owner in $OwnerInventory.ToArray()) {
        if ($null -eq $owner) { continue }
        $key = if ($owner.PSObject.Properties.Name -contains 'owner_id') {
            [string]$owner.owner_id
        } else { [Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($owner) }
        if ($seen.Add($key)) { $owners.Add($owner) }
    }
    if ($null -ne $PrimaryServer) {
        $key = if ($PrimaryServer.PSObject.Properties.Name -contains
            'owner_id') {
            [string]$PrimaryServer.owner_id
        } else {
            [string][Runtime.CompilerServices.RuntimeHelpers]::GetHashCode(
                $PrimaryServer
            )
        }
        if ($seen.Add($key)) { $owners.Add($PrimaryServer) }
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($owner in $owners.ToArray()) {
        $results.Add((Stop-I04ControlledEd2kServer -Server $owner))
    }
    $failures = @($results.ToArray() | Where-Object {
        -not [bool]$_.stopped -or [string]$_.error
    })
    return [pscustomobject][ordered]@{
        stopped = $failures.Count -eq 0
        error = if ($failures.Count -eq 0) {
            $null
        } else {
            @($failures | ForEach-Object {
                if ([string]$_.error) {
                    '{0}: {1}' -f $_.owner_id, $_.error
                } else { '{0}: not stopped' -f $_.owner_id }
            }) -join '; '
        }
        evidence = if ($results.Count -eq 1) {
            $results[0].evidence
        } else {
            @($results.ToArray() | ForEach-Object { $_.evidence })
        }
        owner_count = $owners.Count
        owner_results = $results.ToArray()
    }
}

function Get-I04RouteEvidence {
    param([Parameter(Mandatory = $true)][string]$RemoteAddress)

    try {
        $route = Find-NetRoute -RemoteIPAddress $RemoteAddress `
            -ErrorAction Stop | Select-Object -First 1
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex `
            -ErrorAction Stop
        $onLink = $route.NextHop -eq '0.0.0.0' -or $route.NextHop -eq '::'
        $isVirtual = $true
        $overlayLike = $true
        $physicalNonvirtual = $false
        if ($adapter) {
            if ($adapter.PSObject.Properties.Name -contains 'Virtual' -and
                $adapter.Virtual -is [bool]) {
                $isVirtual = [bool]$adapter.Virtual
            }
            $overlayLike =
                ([string]$adapter.Name) -match $overlayPattern -or
                ([string]$adapter.InterfaceDescription) -match
                    $overlayPattern
            $physicalNonvirtual =
                [bool]$adapter.HardwareInterface -and
                -not $isVirtual -and -not $overlayLike -and
                [string]$adapter.Status -eq 'Up'
        }
        return [pscustomobject][ordered]@{
            available = $true
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I04NormalizedIp -Address $RemoteAddress
            interface_index = [int]$route.InterfaceIndex
            interface_id = if ($adapter) {
                Get-LabInterfaceId -Id ([string]$adapter.InterfaceGuid) `
                    -Name ([string]$adapter.Name) `
                    -Description ([string]$adapter.InterfaceDescription)
            } else { '' }
            interface_status = if ($adapter) {
                [string]$adapter.Status
            } else { 'Unknown' }
            hardware_interface = if ($adapter) {
                [bool]$adapter.HardwareInterface
            } else { $false }
            virtual = $isVirtual
            overlay_or_vpn_like = $overlayLike
            physical_nonvirtual = $physicalNonvirtual
            on_link = $onLink
            source_address = Get-I04NormalizedIp -Address ([string]$route.IPAddress)
            next_hop = Get-I04NormalizedIp -Address ([string]$route.NextHop)
            next_hop_class = if ($onLink) {
                'on-link'
            } else {
                Get-I04StrictAddressClass -Address ([string]$route.NextHop)
            }
            error = $null
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            family = if ($RemoteAddress.Contains(':')) { 'IPv6' } else { 'IPv4' }
            remote_address = Get-I04NormalizedIp -Address $RemoteAddress
            interface_index = $null
            interface_id = ''
            interface_status = 'Unknown'
            hardware_interface = $false
            virtual = $true
            overlay_or_vpn_like = $true
            physical_nonvirtual = $false
            on_link = $false
            source_address = ''
            next_hop = ''
            next_hop_class = 'unknown'
            error = Get-I04SafeErrorToken -Context 'route query failed' `
                -Message $_.Exception.Message
        }
    }
}

function Get-I04IsolationEvidence {
    $adapterQueryError = $null
    $adapters = @()
    try {
        # Hidden tunnel/virtual adapters are still part of the host network
        # state and must not escape the fail-closed isolation inventory.
        $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    } catch {
        $adapterQueryError = Get-I04SafeErrorToken `
            -Context 'adapter inventory failed' -Message $_.Exception.Message
    }
    $overlays = @(
        $adapters | Where-Object {
            $adapterVirtual = if (
                $_.PSObject.Properties.Name -contains 'Virtual' -and
                $_.Virtual -is [bool]
            ) { [bool]$_.Virtual } else { $true }
            [string]$_.Status -eq 'Up' -and (
                $adapterVirtual -or
                ([string]$_.Name) -match $overlayPattern -or
                ([string]$_.InterfaceDescription) -match $overlayPattern
            )
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                interface_index = [int]$_.InterfaceIndex
                interface_id = Get-LabInterfaceId `
                    -Id ([string]$_.InterfaceGuid) `
                    -Name ([string]$_.Name) `
                    -Description ([string]$_.InterfaceDescription)
            }
        }
    )
    $proxyEnvironmentNames = @(
        'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
        'http_proxy', 'https_proxy', 'all_proxy'
    )
    $setProxyEnvironmentNames = @(
        $proxyEnvironmentNames | Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [Environment]::GetEnvironmentVariable($_)
            )
        } | Sort-Object -Unique
    )
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        adapter_inventory_error = $adapterQueryError
        active_overlay_or_vpn_adapters = $overlays
        active_overlay_or_vpn_count = $overlays.Count
        proxy_environment_variable_names_set = $setProxyEnvironmentNames
        proxy_environment_variable_count = $setProxyEnvironmentNames.Count
        strict_isolation_valid =
            -not $adapterQueryError -and $overlays.Count -eq 0 -and
            $setProxyEnvironmentNames.Count -eq 0
    }
}

function Convert-I04ValueSet {
    param(
        [AllowNull()][object[]]$Values,
        [switch]$NormalizeIp,
        [switch]$NormalizePath
    )

    $result = @()
    foreach ($value in @($Values)) {
        foreach ($item in @(([string]$value) -split ',')) {
            $text = $item.Trim()
            if (-not $text) { continue }
            if ($NormalizeIp) {
                $text = Get-I04NormalizedIp -Address $text
            } elseif ($NormalizePath) {
                try { $text = [IO.Path]::GetFullPath($text) } catch {}
                $text = $text.ToLowerInvariant()
            } else {
                $text = $text.ToLowerInvariant()
            }
            $result += $text
        }
    }
    return @($result | Sort-Object -Unique)
}

function Test-I04ValueSetEqual {
    param(
        [AllowNull()][object[]]$Actual,
        [AllowNull()][object[]]$Expected,
        [switch]$NormalizeIp,
        [switch]$NormalizePath
    )

    $actualSet = @(Convert-I04ValueSet -Values $Actual `
        -NormalizeIp:$NormalizeIp -NormalizePath:$NormalizePath)
    $expectedSet = @(Convert-I04ValueSet -Values $Expected `
        -NormalizeIp:$NormalizeIp -NormalizePath:$NormalizePath)
    return ($actualSet.Count -eq $expectedSet.Count -and
        ($actualSet -join "`n") -ceq ($expectedSet -join "`n"))
}

function Get-I04FirewallRuleEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][ValidateSet('Allow', 'Block')]
        [string]$Action,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$LocalAddresses,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddresses,
        [Parameter(Mandatory = $true)][int]$LocalPort
    )

    $rules = @(Get-NetFirewallRule -DisplayName $DisplayName `
        -ErrorAction Stop)
    $application = @()
    $address = @()
    $port = @()
    if ($rules.Count -eq 1) {
        $application = @($rules[0] | Get-NetFirewallApplicationFilter `
            -ErrorAction Stop)
        $address = @($rules[0] | Get-NetFirewallAddressFilter `
            -ErrorAction Stop)
        $port = @($rules[0] | Get-NetFirewallPortFilter `
            -ErrorAction Stop)
    }
    $protocolExact = $port.Count -eq 1 -and
        @('6', 'tcp') -contains ([string]$port[0].Protocol).ToLowerInvariant()
    $exact = $rules.Count -eq 1 -and $application.Count -eq 1 -and
        $address.Count -eq 1 -and $port.Count -eq 1 -and
        ([string]$rules[0].Direction) -eq 'Inbound' -and
        ([string]$rules[0].Action) -eq $Action -and
        ([string]$rules[0].Enabled) -eq 'True' -and
        ([string]$rules[0].Profile) -eq 'Any' -and
        (Test-I04ValueSetEqual -Actual @($application[0].Program) `
            -Expected @($Program) -NormalizePath) -and
        (Test-I04ValueSetEqual -Actual @($address[0].LocalAddress) `
            -Expected $LocalAddresses -NormalizeIp) -and
        (Test-I04ValueSetEqual -Actual @($address[0].RemoteAddress) `
            -Expected $RemoteAddresses -NormalizeIp) -and
        $protocolExact -and
        ([string]$port[0].LocalPort) -eq ([string]$LocalPort) -and
        ([string]$port[0].RemotePort) -eq 'Any'
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        display_name = $DisplayName
        rule_count = $rules.Count
        direction = if ($rules.Count -eq 1) {
            [string]$rules[0].Direction
        } else { '' }
        action = if ($rules.Count -eq 1) {
            [string]$rules[0].Action
        } else { '' }
        enabled = $rules.Count -eq 1 -and
            ([string]$rules[0].Enabled) -eq 'True'
        profile = if ($rules.Count -eq 1) {
            [string]$rules[0].Profile
        } else { '' }
        program_relative_path = if ($application.Count -eq 1) {
            [IO.Path]::GetFileName([string]$application[0].Program)
        } else { '' }
        program_path_sha256 = if ($application.Count -eq 1) {
            Get-I04StringSha256 -Value (
                [IO.Path]::GetFullPath([string]$application[0].Program).
                    ToLowerInvariant()
            )
        } else { '' }
        program_file_sha256 = if ($application.Count -eq 1 -and
            (Test-Path -LiteralPath ([string]$application[0].Program) `
                -PathType Leaf)) {
            Get-LabSha256 -Path ([string]$application[0].Program)
        } else { '' }
        protocol = if ($port.Count -eq 1) {
            [string]$port[0].Protocol
        } else { '' }
        local_addresses = if ($address.Count -eq 1) {
            @(Convert-I04ValueSet -Values @($address[0].LocalAddress) -NormalizeIp)
        } else { @() }
        remote_addresses = if ($address.Count -eq 1) {
            @(Convert-I04ValueSet -Values @($address[0].RemoteAddress) -NormalizeIp)
        } else { @() }
        local_port = if ($port.Count -eq 1) {
            [string]$port[0].LocalPort
        } else { '' }
        remote_port = if ($port.Count -eq 1) {
            [string]$port[0].RemotePort
        } else { '' }
        exact = $exact
    }
}

function Invoke-I04BoundedNative {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )

    $process = $null
    $timedOut = $false
    $output = @()
    $errorOutput = @()
    $exitCode = 9009
    try {
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = (Get-Command $FileName -ErrorAction Stop).Source
        # Quote according to CommandLineToArgvW rules. All values are
        # harness-derived, but paths may contain whitespace or quotes.
        $quotedArguments = foreach ($argumentValue in $Arguments) {
            $argument = [string]$argumentValue
            if ($argument -notmatch '[\s"]') {
                $argument
                continue
            }
            $builder = New-Object Text.StringBuilder
            $null = $builder.Append('"')
            $backslashes = 0
            foreach ($character in $argument.ToCharArray()) {
                if ($character -eq '\') {
                    $backslashes++
                    continue
                }
                if ($character -eq '"') {
                    $null = $builder.Append(('\' * ($backslashes * 2 + 1)))
                    $null = $builder.Append('"')
                    $backslashes = 0
                    continue
                }
                if ($backslashes -gt 0) {
                    $null = $builder.Append(('\' * $backslashes))
                    $backslashes = 0
                }
                $null = $builder.Append($character)
            }
            if ($backslashes -gt 0) {
                $null = $builder.Append(('\' * ($backslashes * 2)))
            }
            $null = $builder.Append('"')
            $builder.ToString()
        }
        $startInfo.Arguments = $quotedArguments -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "$FileName process did not start"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $processExited = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $processExited) {
            $timedOut = $true
            try { $process.Kill() } catch {}
            $processExited = $process.WaitForExit(10000)
        }
        $stdout = if ($processExited) {
            $stdoutTask.GetAwaiter().GetResult()
        } else { '' }
        $stderr = if ($processExited) {
            $stderrTask.GetAwaiter().GetResult()
        } else { "$FileName did not exit after timeout and forced termination" }
        $output = if ($stdout) { @($stdout -split '\r?\n') } else { @() }
        $errorOutput = if ($stderr) { @($stderr -split '\r?\n') } else { @() }
        if ($timedOut) {
            $exitCode = 1460
        } elseif ($processExited -and $process.HasExited) {
            $exitCode = $process.ExitCode
        }
    } catch {
        $errorOutput += Get-I04SafeErrorToken `
            -Context 'native command invocation failed' `
            -Message $_.Exception.Message
        $exitCode = 9009
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
    $output = @($output | ForEach-Object {
        Convert-I04PrivateText -Value ([string]$_)
    })
    $errorOutput = @($errorOutput | ForEach-Object {
        Convert-I04PrivateText -Value ([string]$_)
    })
    $loggedArguments = @($Arguments | ForEach-Object {
        Convert-I04PrivateText -Value ([string]$_)
    })
    $logError = $null
    try {
        Add-Content -LiteralPath $LogPath -Encoding utf8 -Value @(
            ('[{0}] {1} {2}' -f (Get-LabUtcTimestamp), $FileName,
                ($loggedArguments -join ' ')),
            ($output | ForEach-Object { [string]$_ }),
            ($errorOutput | ForEach-Object { [string]$_ }),
            "timed_out=$timedOut",
            "exit_code=$exitCode"
        )
    } catch {
        $logError = Get-I04SafeErrorToken `
            -Context 'native command log write failed' `
            -Message $_.Exception.Message
    }
    return [pscustomobject][ordered]@{
        exit_code = $exitCode
        timed_out = $timedOut
        output = @($output + $errorOutput)
        log_error = $logError
    }
}

function Invoke-I04Pktmon {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )
    return Invoke-I04BoundedNative -FileName 'pktmon.exe' `
        -Arguments $Arguments -LogPath $LogPath `
        -TimeoutSeconds $TimeoutSeconds
}

function Invoke-I04Logman {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )
    return Invoke-I04BoundedNative -FileName 'logman.exe' `
        -Arguments $Arguments -LogPath $LogPath `
        -TimeoutSeconds $TimeoutSeconds
}

function Get-I04EtwLossEvidence {
    param([Parameter(Mandatory = $true)][string]$SessionName)

    $contractId = 'ese.v91.i04-etw-trace-control/2026-08-01.v1'
    if ('V91I04EtwTraceControlV2' -as [type]) {
        $null = Assert-I04ManagedTypeContract `
            -TypeName 'V91I04EtwTraceControlV2' `
            -ExpectedContractId $contractId
    } else {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class V91I04EtwTraceControlV2 {
    public const string ContractId = "ese.v91.i04-etw-trace-control/2026-08-01.v1";
    [StructLayout(LayoutKind.Sequential)]
    private struct WNODE_HEADER {
        public UInt32 BufferSize;
        public UInt32 ProviderId;
        public UInt64 HistoricalContext;
        public Int64 TimeStamp;
        public Guid Guid;
        public UInt32 ClientContext;
        public UInt32 Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_PROPERTIES {
        public WNODE_HEADER Wnode;
        public UInt32 BufferSize;
        public UInt32 MinimumBuffers;
        public UInt32 MaximumBuffers;
        public UInt32 MaximumFileSize;
        public UInt32 LogFileMode;
        public UInt32 FlushTimer;
        public UInt32 EnableFlags;
        public Int32 AgeLimit;
        public UInt32 NumberOfBuffers;
        public UInt32 FreeBuffers;
        public UInt32 EventsLost;
        public UInt32 BuffersWritten;
        public UInt32 LogBuffersLost;
        public UInt32 RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public UInt32 LogFileNameOffset;
        public UInt32 LoggerNameOffset;
    }

    public sealed class Result {
        public UInt32 ErrorCode;
        public UInt32 EventsLost;
        public UInt32 LogBuffersLost;
        public UInt32 RealTimeBuffersLost;
        public UInt32 BuffersWritten;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern UInt32 ControlTrace(
        UInt64 sessionHandle, string sessionName, IntPtr properties,
        UInt32 controlCode);

    private static Result Control(string sessionName, UInt32 controlCode) {
        int propertiesSize = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
        byte[] encodedName = Encoding.Unicode.GetBytes(sessionName + "\0");
        int totalSize = propertiesSize + encodedName.Length + 2;
        IntPtr buffer = Marshal.AllocHGlobal(totalSize);
        try {
            byte[] zero = new byte[totalSize];
            Marshal.Copy(zero, 0, buffer, zero.Length);
            EVENT_TRACE_PROPERTIES properties = new EVENT_TRACE_PROPERTIES();
            properties.Wnode.BufferSize = (UInt32)totalSize;
            properties.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
            properties.LoggerNameOffset = (UInt32)propertiesSize;
            Marshal.StructureToPtr(properties, buffer, false);
            Marshal.Copy(encodedName, 0, IntPtr.Add(buffer, propertiesSize),
                encodedName.Length);
            UInt32 error = ControlTrace(
                0, sessionName, buffer, controlCode);
            Result result = new Result();
            result.ErrorCode = error;
            if (error == 0) {
                properties = (EVENT_TRACE_PROPERTIES)
                    Marshal.PtrToStructure(
                        buffer, typeof(EVENT_TRACE_PROPERTIES));
                result.EventsLost = properties.EventsLost;
                result.LogBuffersLost = properties.LogBuffersLost;
                result.RealTimeBuffersLost = properties.RealTimeBuffersLost;
                result.BuffersWritten = properties.BuffersWritten;
            }
            return result;
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static Result Query(string sessionName) {
        return Control(sessionName, 0); // EVENT_TRACE_CONTROL_QUERY
    }

    public static Result Flush(string sessionName) {
        return Control(sessionName, 3); // EVENT_TRACE_CONTROL_FLUSH
    }
}
'@
        $null = Assert-I04ManagedTypeContract `
            -TypeName 'V91I04EtwTraceControlV2' `
            -ExpectedContractId $contractId
    }

    try {
        $query = [V91I04EtwTraceControlV2]::Query($SessionName)
        $buffersLost = [UInt64]$query.LogBuffersLost +
            [UInt64]$query.RealTimeBuffersLost
        return [pscustomobject][ordered]@{
            available = [UInt32]$query.ErrorCode -eq 0
            error_code = [UInt32]$query.ErrorCode
            events_lost = [UInt64]$query.EventsLost
            log_buffers_lost = [UInt64]$query.LogBuffersLost
            realtime_buffers_lost = [UInt64]$query.RealTimeBuffersLost
            buffers_lost = $buffersLost
            buffers_written = [UInt64]$query.BuffersWritten
            proved_zero = [UInt32]$query.ErrorCode -eq 0 -and
                [UInt64]$query.EventsLost -eq 0 -and $buffersLost -eq 0
            error = if ([UInt32]$query.ErrorCode -eq 0) {
                $null
            } else {
                "ControlTrace query returned Win32 $($query.ErrorCode)"
            }
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            error_code = $null
            events_lost = $null
            log_buffers_lost = $null
            realtime_buffers_lost = $null
            buffers_lost = $null
            buffers_written = $null
            proved_zero = $false
            error = Get-I04SafeErrorToken `
                -Context 'ControlTrace query failed' `
                -Message $_.Exception.Message
        }
    }
}

function Invoke-I04EtwFinalFlush {
    param([Parameter(Mandatory = $true)][string]$SessionName)

    # Get-I04EtwLossEvidence initializes the V2 controller type in a fresh
    # harness process. Calling it here also makes a missing/redefined helper a
    # fail-closed condition instead of relying on Add-Type replacement.
    $preFlushDiagnostic = Get-I04EtwLossEvidence -SessionName $SessionName
    try {
        if (-not ('V91I04EtwTraceControlV2' -as [type])) {
            throw 'ETW V2 trace-control helper is unavailable'
        }
        $flush = [V91I04EtwTraceControlV2]::Flush($SessionName)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-etw-final-flush/v1'
            sample_phase = 'final-flush-before-stop'
            attempted_at_utc = Get-LabUtcTimestamp
            succeeded = [UInt32]$flush.ErrorCode -eq 0
            error_code = [UInt32]$flush.ErrorCode
            pre_flush_diagnostic = $preFlushDiagnostic
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-etw-final-flush/v1'
            sample_phase = 'final-flush-before-stop'
            attempted_at_utc = Get-LabUtcTimestamp
            succeeded = $false
            error_code = $null
            pre_flush_diagnostic = $preFlushDiagnostic
            error = Get-I04SafeErrorToken `
                -Context 'ControlTrace final flush failed' `
                -Message $_.Exception.Message
        }
    }
}

function Test-I04PktmonInventoryMetadataLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()][string]$Line
    )

    $value = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($value) -or
        $value -match '^[\s\-=|+]+$' -or
        $value -match
            '(?i)^(?:packet\s+filters?|filtros?\s+de\s+paquete)\s*:?\s*$') {
        return $true
    }
    $residual = $value
    foreach ($label in @(
        'direcci\S+n\s+mac', 'mac\s+address',
        'puerto\s+vxlan', 'vxlan\s+port',
        'direcci\S+n\s+ip', 'ip\s+address',
        'id\.?\s+de\s+vlan', 'vlan\s+id',
        'encapsulaci\S+n', 'encapsulation',
        'protocolo', 'protocol', 'ethertype', 'dscp',
        'nombre', 'name', 'puerto', 'port', 'id\.?'
    )) {
        $residual = [regex]::Replace(
            $residual, '(?i)(?<![A-Z0-9])' + $label + '(?![A-Z0-9])', '')
    }
    $residual = [regex]::Replace($residual, '[\s\-=|:+#().\[\]]+', '')
    return [string]::IsNullOrEmpty($residual)
}

function Get-I04PktmonInventoryCensus {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()][string]$Text
    )

    $normalized = (($Text -replace "`r`n", "`n") -replace "`r", "`n").Trim()
    $canonicalSha256 = if ([string]::IsNullOrWhiteSpace($normalized)) {
        $null
    } else { Get-I04StringSha256 -Value $normalized }
    $invalid = {
        param([string]$Reason, [string]$Mode)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-pktmon-filter-census/v1'
            exact = $false
            empty = $false
            reason = $Reason
            inventory_mode = $Mode
            canonical_sha256 = $canonicalSha256
            line_count = 0
            entry_count = 0
            numeric_ids_unique = $false
            names_unique = $false
            entries = @()
        }
    }
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return & $invalid 'empty-output' 'none'
    }

    $lines = @($normalized -split "`n" | ForEach-Object {
        ([string]$_).Trim()
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $numberedPattern =
        '^\s*(?<id>\d+)\s+(?<name>\S+)(?<rest>(?:\s+.*)?)$'
    $namePattern =
        '(?i)^\s*(?:filter\s+name|name|nombre(?:\s+de(?:l)?\s+filtro)?)' +
        '\s*:\s*(?<name>\S+)\s*$'
    $fieldPattern =
        '(?i)^\s*(?<field>address|direcci\S+n|protocol|protocolo|port|puerto)' +
        '\s*:\s*(?<value>\S(?:.*\S)?)\s*$'
    $emptyPattern =
        '(?i)^\s*(?:none|no\s+packet\s+filters?\s+specified|' +
        'no\s+filters(?:\s+(?:are\s+)?(?:configured|present|specified))?|' +
        'ning\S+n[oa]?|ning\S+n\s+filtro|no\s+hay\s+filtros|' +
        'sin\s+filtros|no\s+se\s+especificaron\s+filtros\s+de\s+paquete)' +
        '\.?\s*$'
    $numberedMatches = @($lines | Where-Object {
        [regex]::IsMatch([string]$_, $numberedPattern)
    })
    $nameMatches = @($lines | Where-Object {
        [regex]::IsMatch([string]$_, $namePattern)
    })

    if ($numberedMatches.Count -gt 0) {
        if ($nameMatches.Count -gt 0) {
            return & $invalid 'mixed-inventory-representations' 'invalid'
        }
        $entries = [System.Collections.Generic.List[object]]::new()
        $ids = [Collections.Generic.HashSet[UInt64]]::new()
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($line in $lines) {
            $match = [regex]::Match([string]$line, $numberedPattern)
            if ($match.Success) {
                $id = [UInt64]0
                if (-not [UInt64]::TryParse(
                    [string]$match.Groups['id'].Value, [ref]$id) -or
                    -not $ids.Add($id)) {
                    return & $invalid 'filter-id-census' 'numbered-rows'
                }
                $name = [string]$match.Groups['name'].Value
                if (-not $names.Add($name)) {
                    return & $invalid 'filter-name-census' 'numbered-rows'
                }
                $entries.Add([pscustomobject][ordered]@{
                    id = [UInt64]$id
                    name = $name
                    text = [string]$line
                })
            } elseif (-not (Test-I04PktmonInventoryMetadataLine -Line $line)) {
                return & $invalid 'unrecognized-inventory-line' 'numbered-rows'
            }
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-pktmon-filter-census/v1'
            exact = $true
            empty = $false
            reason = ''
            inventory_mode = 'numbered-rows'
            canonical_sha256 = $canonicalSha256
            line_count = $lines.Count
            entry_count = $entries.Count
            numeric_ids_unique = $true
            names_unique = $true
            entries = $entries.ToArray()
        }
    }

    if ($nameMatches.Count -gt 0) {
        $entries = [System.Collections.Generic.List[object]]::new()
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $currentName = $null
        $currentLines = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $lines) {
            $nameMatch = [regex]::Match([string]$line, $namePattern)
            if ($nameMatch.Success) {
                if ($null -ne $currentName) {
                    $entries.Add([pscustomobject][ordered]@{
                        id = $null; name = [string]$currentName
                        text = $currentLines.ToArray() -join "`n"
                    })
                }
                $currentName = [string]$nameMatch.Groups['name'].Value
                if (-not $names.Add($currentName)) {
                    return & $invalid 'filter-name-census' 'named-fields'
                }
                $currentLines.Clear()
                $currentLines.Add([string]$line)
                continue
            }
            if ($null -eq $currentName) {
                if (Test-I04PktmonInventoryMetadataLine -Line $line) {
                    continue
                }
                return & $invalid 'unrecognized-inventory-line' 'named-fields'
            }
            if (-not [regex]::IsMatch([string]$line, $fieldPattern)) {
                return & $invalid 'unrecognized-inventory-line' 'named-fields'
            }
            $currentLines.Add([string]$line)
        }
        if ($null -ne $currentName) {
            $entries.Add([pscustomobject][ordered]@{
                id = $null; name = [string]$currentName
                text = $currentLines.ToArray() -join "`n"
            })
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-pktmon-filter-census/v1'
            exact = $true
            empty = $false
            reason = ''
            inventory_mode = 'named-fields'
            canonical_sha256 = $canonicalSha256
            line_count = $lines.Count
            entry_count = $entries.Count
            numeric_ids_unique = $true
            names_unique = $true
            entries = $entries.ToArray()
        }
    }

    $emptyMarkers = 0
    foreach ($line in $lines) {
        if ([regex]::IsMatch([string]$line, $emptyPattern)) {
            $emptyMarkers++
        } elseif (-not (Test-I04PktmonInventoryMetadataLine -Line $line)) {
            return & $invalid 'unrecognized-inventory-line' 'empty'
        }
    }
    if ($emptyMarkers -ne 1) {
        return & $invalid 'empty-inventory-census' 'empty'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-pktmon-filter-census/v1'
        exact = $true
        empty = $true
        reason = ''
        inventory_mode = 'empty'
        canonical_sha256 = $canonicalSha256
        line_count = $lines.Count
        entry_count = 0
        numeric_ids_unique = $true
        names_unique = $true
        entries = @()
    }
}

function Test-I04PktmonArmedFilterContracts {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$FilterV4,
        [Parameter(Mandatory = $true)][string]$FilterV6,
        [Parameter(Mandatory = $true)][string]$FilterIcmpV6,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $definitions = @(
        [pscustomobject]@{
            name = $FilterV4; address = $IPv4; other_address = $IPv6
            protocol = 'TCP'; requires_port = $true; family = 'ipv4'
        },
        [pscustomobject]@{
            name = $FilterV6; address = $IPv6; other_address = $IPv4
            protocol = 'TCP'; requires_port = $true; family = 'ipv6'
        },
        [pscustomobject]@{
            name = $FilterIcmpV6; address = ''; other_address = ''
            protocol = 'ICMPV6'; requires_port = $false; family = 'icmpv6'
        }
    )

    $census = Get-I04PktmonInventoryCensus -Text $Text
    if (-not [bool]$census.exact -or [bool]$census.empty) {
        return [pscustomobject][ordered]@{
            exact = $false; reason = [string]$census.reason
            inventory_mode = [string]$census.inventory_mode
            canonical_sha256 = $census.canonical_sha256
            contracts = @()
        }
    }
    $inventoryMode = [string]$census.inventory_mode
    $inventoryEntries = @($census.entries)
    $segments = [System.Collections.Generic.List[object]]::new()
    if ($inventoryEntries.Count -ne $definitions.Count) {
        return [pscustomobject][ordered]@{
            exact = $false
            reason = if ($inventoryMode -eq 'numbered-rows') {
                'filter-row-census'
            } else { 'filter-name-census' }
            inventory_mode = $inventoryMode
            canonical_sha256 = $census.canonical_sha256
            contracts = @()
        }
    }
    foreach ($definition in $definitions) {
        $matchingEntries = @($inventoryEntries | Where-Object {
            $_.name -is [string] -and
            [string]$_.name -ceq [string]$definition.name
        })
        if ($matchingEntries.Count -ne 1) {
            return [pscustomobject][ordered]@{
                exact = $false; reason = 'filter-name-census'
                inventory_mode = $inventoryMode
                canonical_sha256 = $census.canonical_sha256
                contracts = @()
            }
        }
        $segments.Add([pscustomobject]@{
            definition = $definition
            text = [string]$matchingEntries[0].text
        })
    }

    $contracts = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $segments.ToArray()) {
        $definition = $entry.definition
        $segment = [string]$entry.text
        $namePattern = '(?i)(?<![A-Z0-9])' +
            [regex]::Escape([string]$definition.name) + '(?![A-Z0-9])'
        $nameOccurrences = @([regex]::Matches($segment, $namePattern))
        $nameExact = $nameOccurrences.Count -eq 1
        $protocolMatches = @([regex]::Matches(
            $segment,
            '(?i)(?<![A-Z0-9])(TCP|UDP|ICMPV6|ICMP|ARP|ESP|AH)(?![A-Z0-9])'
        ))
        $protocolPresent = $protocolMatches.Count -eq 1 -and
            [string]$protocolMatches[0].Value -ieq
                [string]$definition.protocol
        $addressPattern = if ([string]$definition.address) {
            [regex]::Escape([string]$definition.address) +
                $(if ([string]$definition.family -eq 'ipv4') {
                    '(?:/32)?'
                } else { '(?:/128)?' })
        } else { '' }
        [Text.RegularExpressions.Match[]]$addressOccurrences = @()
        if ($addressPattern) {
            $addressOccurrences = @([regex]::Matches(
                $segment, $addressPattern,
                [Text.RegularExpressions.RegexOptions]::IgnoreCase
            ) | ForEach-Object { $_ })
        }
        $addressPresent = if ([string]$definition.address) {
            $addressOccurrences.Count -eq 1
        } else { $true }
        $otherAddressAbsent = if ([string]$definition.other_address) {
            $segment.IndexOf(
                [string]$definition.other_address,
                [StringComparison]::OrdinalIgnoreCase
            ) -lt 0
        } else { $true }
        $portOccurrences = @([regex]::Matches(
            $segment, '(?<!\d)' + [string]$Port + '(?!\d)'
        ))
        $portPresent = $portOccurrences.Count -eq 1
        $portExact = if ([bool]$definition.requires_port) {
            $portPresent
        } else { -not $portPresent }

        $fieldSetExact = $true
        if ($inventoryMode -eq 'named-fields') {
            $actualFields = @($segment -split "`n" | ForEach-Object {
                ([string]$_).Trim()
            } | Where-Object { $_ })
            $expectedFields = if ([bool]$definition.requires_port) {
                @(
                    ('Name: ' + [string]$definition.name),
                    ('Address: ' + [string]$definition.address),
                    ('Protocol: ' + [string]$definition.protocol),
                    ('Port: ' + [string]$Port)
                )
            } else {
                @(
                    ('Name: ' + [string]$definition.name),
                    ('Protocol: ' + [string]$definition.protocol)
                )
            }
            $actualCanonical = @($actualFields | ForEach-Object {
                ([regex]::Replace([string]$_, '\s+', ' ')).ToLowerInvariant()
            } | Sort-Object)
            $expectedCanonical = @($expectedFields | ForEach-Object {
                ([regex]::Replace([string]$_, '\s+', ' ')).ToLowerInvariant()
            } | Sort-Object)
            $fieldSetExact = ($actualCanonical -join "`n") -ceq
                ($expectedCanonical -join "`n")
        } else {
            # Strip the one allowed value for every constrained dimension and
            # reject any residual address, MAC, TCP flag, encapsulation token
            # or non-default numeric value. PktMon prints zeroes/dashes for
            # unconstrained dimensions; those are the only residual values
            # admitted. Host-prefix lengths and protocol numbers are harmless
            # canonical renderings of the exact command we issued.
            $residual = [regex]::Replace($segment, '^\s*\d+\s+', '')
            $residual = [regex]::Replace(
                $residual, $namePattern, '')
            if ([string]$definition.address) {
                $residual = [regex]::Replace(
                    $residual, $addressPattern, '',
                    [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            $protocolNumber = if ([string]$definition.protocol -eq 'TCP') {
                6
            } else { 58 }
            $residual = [regex]::Replace(
                $residual, '(?i)(?<![A-Z0-9])' +
                    [regex]::Escape([string]$definition.protocol) +
                    '(?![A-Z0-9])(?:\s*\(' +
                    [string]$protocolNumber + '\))?', '')
            $implicitFamily = if ([string]$definition.family -eq 'ipv4') {
                'IPv4'
            } else { 'IPv6' }
            $implicitFamilyPattern = '(?i)(?<![A-Z0-9])' +
                $implicitFamily + '(?![A-Z0-9])'
            $implicitFamilyOccurrences = @([regex]::Matches(
                $residual, $implicitFamilyPattern
            ))
            $implicitFamilyExact = $implicitFamilyOccurrences.Count -le 1
            $residual = [regex]::Replace(
                $residual, $implicitFamilyPattern, '')
            if ([bool]$definition.requires_port) {
                $residual = [regex]::Replace(
                    $residual, '(?<!\d)' + [string]$Port + '(?!\d)', '')
            }
            $residual = [regex]::Replace(
                $residual, '(?i)(?<![0-9a-f])(?:00[:-]){5}00(?![0-9a-f])', '')
            $residual = [regex]::Replace(
                $residual, '(?i)(?<![A-Z0-9])0x0+(?![A-Z0-9])', '')
            $residual = [regex]::Replace(
                $residual, '(?<!\d)0\.0\.0\.0(?:/0)?(?!\d)', '')
            $residual = [regex]::Replace(
                $residual,
                '(?i)(?<![0-9a-f:])0:0:0:0:0:0:0:0(?:/0)?(?![0-9a-f:])', '')
            $residual = $residual.Replace('::', '')
            $unexpectedIpv4 = [regex]::IsMatch(
                $residual,
                '(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)'
            )
            $unexpectedIpv6 = [regex]::IsMatch(
                $residual,
                '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])'
            )
            $unexpectedMac = [regex]::IsMatch(
                $residual,
                '(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])'
            )
            $unexpectedFlagOrEncapsulation = [regex]::IsMatch(
                $residual,
                '(?i)(?<![A-Z0-9])(?:FIN|SYN|RST|PSH|ACK|URG|ECE|CWR|VXLAN|GRE|NVGRE|IPIP|UDP|ICMP|ARP|ESP|AH)(?![A-Z0-9])'
            )
            $unexpectedNumbers = @([regex]::Matches(
                $residual, '(?<![A-Z0-9])\d+(?![A-Z0-9])'
            ) | Where-Object {
                [int64]$_.Value -ne 0
            })
            $alphabeticResidual = [regex]::Replace(
                $residual,
                '(?i)(?<![A-Z0-9])(?:ANY|ALL|NONE|N/?A|NOTSET|' +
                    'UNSPECIFIED|FALSE|DISABLED|CUALQUIERA|TODOS|' +
                    'NINGUN[OA]?|VAC[IÍ]O|SIN|FALSO|NO|DESHABILITADO)' +
                    '(?![A-Z0-9])', '')
            $unexpectedAlphabetic = [regex]::IsMatch(
                $alphabeticResidual, '(?i)[A-Z]')
            $fieldSetExact = -not $unexpectedIpv4 -and
                -not $unexpectedIpv6 -and -not $unexpectedMac -and
                -not $unexpectedFlagOrEncapsulation -and
                $unexpectedNumbers.Count -eq 0 -and
                -not $unexpectedAlphabetic -and $implicitFamilyExact
        }
        $exact = $nameExact -and $protocolPresent -and $addressPresent -and
            $otherAddressAbsent -and $portExact -and $fieldSetExact
        $contracts.Add([pscustomobject][ordered]@{
            name_sha256 = Get-I04StringSha256 -Value ([string]$definition.name)
            name_contract_exact = $nameExact
            protocol = [string]$definition.protocol
            address_present = $addressPresent
            other_target_address_absent = $otherAddressAbsent
            port_contract_exact = $portExact
            field_set_exact = $fieldSetExact
            exact = $exact
        })
    }
    return [pscustomobject][ordered]@{
        exact = @($contracts.ToArray() | Where-Object { -not $_.exact }).Count -eq 0
        reason = if (@($contracts.ToArray() | Where-Object {
            -not $_.exact
        }).Count -eq 0) { '' } else { 'filter-field-contract' }
        inventory_mode = $inventoryMode
        canonical_sha256 = $census.canonical_sha256
        contracts = $contracts.ToArray()
    }
}

function Enter-I04PktmonGlobalMutex {
    if ($null -ne $script:i04PktmonMutex) {
        throw 'PktMon global mutex is already held by this harness instance'
    }

    $mutexName = 'Global\eSE-V91-I04-PktMon-v1'
    $createdNew = $false
    $mutex = [Threading.Mutex]::new($false, $mutexName, [ref]$createdNew)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        } catch [Threading.AbandonedMutexException] {
            try { $mutex.ReleaseMutex() } catch {}
            throw 'PktMon global mutex was abandoned; global capture state is not trustworthy'
        }
        if (-not $acquired) {
            throw 'PktMon global mutex is owned by another harness/process'
        }
        $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
        try {
            $processStartUtcTicks =
                [Int64]$currentProcess.StartTime.ToUniversalTime().Ticks
        } finally {
            $currentProcess.Dispose()
        }
        $script:i04PktmonMutex = $mutex
        $script:i04PktmonMutexEvidence = [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-pktmon-global-mutex/v1'
            name_sha256 = Get-I04StringSha256 -Value $mutexName
            owner_process_id = [int]$PID
            owner_process_start_utc_ticks = $processStartUtcTicks
            owner_managed_thread_id =
                [int][Threading.Thread]::CurrentThread.ManagedThreadId
            created_new = [bool]$createdNew
            acquired = $true
            abandoned = $false
            acquired_at_utc = Get-LabUtcTimestamp
            released = $false
            release_exact = $false
            released_at_utc = $null
        }
        return $script:i04PktmonMutexEvidence
    } catch {
        if ($acquired) {
            try { $mutex.ReleaseMutex() } catch {}
        }
        try { $mutex.Dispose() } catch {}
        throw
    }
}

function Assert-I04PktmonGlobalMutexOwnership {
    if ($null -eq $script:i04PktmonMutex -or
        $null -eq $script:i04PktmonMutexEvidence) {
        throw 'PktMon global mutex is not held'
    }
    $evidence = $script:i04PktmonMutexEvidence
    $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
    try {
        $processStartUtcTicks =
            [Int64]$currentProcess.StartTime.ToUniversalTime().Ticks
    } finally {
        $currentProcess.Dispose()
    }
    $expectedNameSha256 = Get-I04StringSha256 `
        -Value 'Global\eSE-V91-I04-PktMon-v1'
    if ([string]$evidence.schema -cne
            'ese.v91.i04-pktmon-global-mutex/v1' -or
        [string]$evidence.name_sha256 -cne
            $expectedNameSha256 -or
        [int]$evidence.owner_process_id -ne [int]$PID -or
        [Int64]$evidence.owner_process_start_utc_ticks -ne
            $processStartUtcTicks -or
        [int]$evidence.owner_managed_thread_id -ne
            [int][Threading.Thread]::CurrentThread.ManagedThreadId -or
        -not [bool]$evidence.acquired -or [bool]$evidence.abandoned -or
        [bool]$evidence.released) {
        throw 'PktMon global mutex ownership identity is not exact'
    }
    return $true
}

function Exit-I04PktmonGlobalMutex {
    $null = Assert-I04PktmonGlobalMutexOwnership
    $mutex = $script:i04PktmonMutex
    $evidence = $script:i04PktmonMutexEvidence
    $releaseFailure = $null
    try {
        $mutex.ReleaseMutex()
        $evidence.released = $true
        $evidence.release_exact = $true
        $evidence.released_at_utc = Get-LabUtcTimestamp
    } catch {
        $releaseFailure = $_
        $evidence.release_exact = $false
    } finally {
        try {
            $mutex.Dispose()
        } catch {
            $evidence.release_exact = $false
            if ($null -eq $releaseFailure) { $releaseFailure = $_ }
        }
        $script:i04PktmonMutex = $null
    }
    if ($null -ne $releaseFailure) { throw $releaseFailure }
    return $evidence
}

function Start-I04PacketCapture {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$FilterPrefix,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$JournalPath
    )

    $null = Assert-I04PktmonGlobalMutexOwnership

    $state = [ordered]@{
        available = $false
        started = $false
        start_attempted = $false
        ever_started = $false
        capture_ended_epoch_ms = $null
        filters = @()
        etl_path = Join-Path $EvidencePath 'i04-packets.etl'
        pcapng_path = Join-Path $EvidencePath 'i04-packets.pcapng'
        command_log = Join-Path $EvidencePath 'pktmon.log'
        filters_before_path = Join-Path $EvidencePath 'pktmon-filters-before.txt'
        filters_armed_path = Join-Path $EvidencePath 'pktmon-filters-armed.txt'
        filters_pre_stop_path =
            Join-Path $EvidencePath 'pktmon-filters-pre-stop.txt'
        session_started_path =
            Join-Path $EvidencePath 'pktmon-etw-session-started.txt'
        status_after_path = Join-Path $EvidencePath 'pktmon-status-after.txt'
        filters_after_path = Join-Path $EvidencePath 'pktmon-filters-after.txt'
        etw_after_path = Join-Path $EvidencePath 'pktmon-etw-session-after.txt'
        etw_session_stopped_verified = $null
        etw_session_owned_by_start_attempt = $false
        owned_filters_absent_verified = $null
        filter_inventory_restored_verified = $null
        filters_applied_verified = $false
        filter_contracts = $null
        filter_inventory_armed_sha256 = $null
        filter_inventory_pre_stop_sha256 = $null
        filter_inventory_scenario_unchanged = $false
        expected_filter_v4 = $null
        expected_filter_v6 = $null
        expected_filter_icmpv6 = $null
        expected_ipv4 = $IPv4
        expected_ipv6 = $IPv6
        expected_port = $Port
        etw_loss_proved_zero = $false
        etw_loss_schema = 'ese.v91.i04-etw-loss/v2'
        etw_loss_sample_phase = 'not-sampled'
        etw_final_flush_succeeded = $false
        etw_final_flush_error_code = $null
        etw_post_flush_query_ok = $false
        etw_events_lost = $null
        etw_buffers_lost = $null
        etw_log_buffers_lost = $null
        etw_realtime_buffers_lost = $null
        etw_buffers_written = $null
        etw_query_error = $null
        etl_size_bytes = $null
        etl_below_circular_limit = $false
        error = $null
    }
    if ($null -eq (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
        $state.error = 'pktmon.exe is unavailable'
        return [pscustomobject]$state
    }

    $statusPath = Join-Path $EvidencePath 'pktmon-status-before.txt'
    $filterPath = $state.filters_before_path
    $statusBeforeResult = Invoke-I04Pktmon -LogPath $state.command_log `
        -Arguments @('status')
    @($statusBeforeResult.output) | Set-Content -LiteralPath $statusPath `
        -Encoding utf8
    $filtersBeforeResult = Invoke-I04Pktmon -LogPath $state.command_log `
        -Arguments @('filter', 'list')
    $filtersBefore = @($filtersBeforeResult.output)
    $filtersBeforeExit = $filtersBeforeResult.exit_code
    $filtersBefore |
        Set-Content -LiteralPath $filterPath -Encoding utf8
    $etwProbePath = Join-Path $EvidencePath 'pktmon-etw-session-before.txt'
    $etwProbeResult = Invoke-I04Logman -LogPath $state.command_log `
        -Arguments @('query', '-ets', 'PktMon')
    $etwProbe = @($etwProbeResult.output)
    $etwProbeExit = $etwProbeResult.exit_code
    $etwProbe | Set-Content -LiteralPath $etwProbePath -Encoding utf8
    $etwAbsence = Get-I04EtwLossEvidence -SessionName 'PktMon'
    Add-I04Journal -Path $JournalPath -Mutation 'pktmon-state' `
        -State 'backed_up' -Detail 'Status and filter list captured before mutation'
    if ($statusBeforeResult.exit_code -ne 0 -or
        $statusBeforeResult.timed_out -or $statusBeforeResult.log_error -or
        $filtersBeforeResult.timed_out -or $filtersBeforeResult.log_error -or
        $etwProbeResult.timed_out -or $etwProbeResult.log_error) {
        $state.error = 'PktMon/logman preflight could not be completed exactly within its native timeout'
        return [pscustomobject]$state
    }
    if ([bool]$etwAbsence.available -or $etwProbeExit -eq 0) {
        $state.error = 'An existing PktMon ETW capture owns the global session; refusing to alter its filters or stop it'
        return [pscustomobject]$state
    }
    if ([UInt32]$etwAbsence.error_code -ne 4201) {
        $state.error = "PktMon ETW absence was not proved (Win32 $($etwAbsence.error_code))"
        return [pscustomobject]$state
    }
    $filtersBeforeText = $filtersBefore -join "`n"
    $filtersBeforeCensus =
        Get-I04PktmonInventoryCensus -Text $filtersBeforeText
    $emptyFilterInventory = $filtersBeforeExit -eq 0 -and
        $filtersBeforeCensus.exact -is [bool] -and
        [bool]$filtersBeforeCensus.exact -and
        $filtersBeforeCensus.empty -is [bool] -and
        [bool]$filtersBeforeCensus.empty -and
        $filtersBeforeCensus.entry_count -is [int] -and
        [int]$filtersBeforeCensus.entry_count -eq 0
    if (-not $emptyFilterInventory) {
        $state.error = (
            'PktMon filter inventory was not provably empty before the run; ' +
            'refusing to capture with global third-party filters'
        )
        return [pscustomobject]$state
    }

    $filterV4 = "$FilterPrefix-v4"
    $filterV6 = "$FilterPrefix-v6"
    $filterIcmp = "$FilterPrefix-icmp6"
    $state.expected_filter_v4 = $filterV4
    $state.expected_filter_v6 = $filterV6
    $state.expected_filter_icmpv6 = $filterIcmp
    $preexistingFilterText = (
        Get-Content -LiteralPath $filterPath -Raw -ErrorAction Stop
    )
    $preexistingOwnedNames = @(
        @($filterV4, $filterV6, $filterIcmp) | Where-Object {
            $preexistingFilterText.IndexOf(
                [string]$_, [StringComparison]::OrdinalIgnoreCase
            ) -ge 0
        }
    )
    if ($preexistingOwnedNames.Count -ne 0) {
        $state.error = (
            'A run-owned PktMon filter name already exists before mutation: ' +
            ($preexistingOwnedNames -join ',')
        )
        return [pscustomobject]$state
    }
    # Register every intended mutation before the first controller call. A
    # timed-out pktmon invocation may have applied its filter even when no
    # success result reached this process, so rollback must know all names.
    $state.filters = @($filterV4, $filterV6, $filterIcmp)
    try {
        $filterV4Result = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'filter', 'add', $filterV4, '-i', $IPv4,
            '-p', ([string]$Port), '-t', 'TCP'
        )
        if ($filterV4Result.exit_code -ne 0 -or
            $filterV4Result.log_error) {
            throw 'pktmon rejected the IPv4 TCP filter'
        }
        $filterV6Result = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'filter', 'add', $filterV6, '-i', $IPv6,
            '-p', ([string]$Port), '-t', 'TCP'
        )
        if ($filterV6Result.exit_code -ne 0 -or
            $filterV6Result.log_error) {
            throw 'pktmon rejected the IPv6 TCP filter'
        }
        # Capture every ICMPv6 error, not only packets whose outer address is
        # the peer: a router can reject the route while quoting the peer only
        # inside the ICMP payload. Without this filter "silent" is unprovable.
        $filterIcmpResult = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'filter', 'add', $filterIcmp, '-t', 'ICMPV6'
        )
        if ($filterIcmpResult.exit_code -ne 0 -or
            $filterIcmpResult.log_error) {
            throw 'pktmon rejected the required all-ICMPv6 filter'
        }
        Add-I04Journal -Path $JournalPath -Mutation 'pktmon-filters' `
            -State 'applied' -Detail ($state.filters -join ',')

        $armedFilterResult = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @('filter', 'list')
        $armedFilters = @($armedFilterResult.output)
        $armedFilterExit = $armedFilterResult.exit_code
        $armedFilters | Set-Content -LiteralPath $state.filters_armed_path `
            -Encoding utf8
        $armedFilterText = $armedFilters -join "`n"
        $filterContracts = Test-I04PktmonArmedFilterContracts `
            -Text $armedFilterText -FilterV4 $filterV4 -FilterV6 $filterV6 `
            -FilterIcmpV6 $filterIcmp -IPv4 $IPv4 -IPv6 $IPv6 -Port $Port
        $state.filter_contracts = $filterContracts
        $state.filter_inventory_armed_sha256 =
            [string]$filterContracts.canonical_sha256
        $state.filters_applied_verified =
            -not $armedFilterResult.timed_out -and
            -not $armedFilterResult.log_error -and
            $armedFilterExit -eq 0 -and
            [bool]$filterContracts.exact
        if (-not $state.filters_applied_verified) {
            throw 'PktMon did not prove the exact IPv4/IPv6/ICMPv6 filter contracts before capture'
        }

        $state.start_attempted = $true
        $startResult = Invoke-I04Pktmon -LogPath $state.command_log `
            -Arguments @(
            'start', '--capture', '--comp', 'nics', '--pkt-size', '0',
            '--file-name', $state.etl_path, '--file-size', '256'
        )
        $sessionProbeResult = Invoke-I04Logman `
            -LogPath $state.command_log `
            -Arguments @('query', '-ets', 'PktMon')
        $sessionProbe = @($sessionProbeResult.output)
        $sessionProbeExit = $sessionProbeResult.exit_code
        $sessionEtw = Get-I04EtwLossEvidence -SessionName 'PktMon'
        $sessionProbe | Set-Content `
            -LiteralPath $state.session_started_path -Encoding utf8
        if (-not $sessionProbeResult.timed_out -and
            -not $sessionProbeResult.log_error -and
            $sessionProbeExit -eq 0 -and [bool]$sessionEtw.available) {
            # Preflight proved this global session absent immediately before
            # the unique start attempt. Even an ambiguous controller return
            # therefore creates an owned cleanup obligation.
            $state.etw_session_owned_by_start_attempt = $true
            $state.started = $true
            $state.ever_started = $true
        }
        if ($startResult.exit_code -ne 0 -or $startResult.log_error) {
            throw 'pktmon capture could not start; another capture may own the global session'
        }
        if ($sessionProbeResult.timed_out -or $sessionProbeResult.log_error -or
            $sessionProbeExit -ne 0 -or -not [bool]$sessionEtw.available) {
            throw 'pktmon start returned success but no PktMon ETW session exists'
        }
        $state.started = $true
        $state.ever_started = $true
        Add-I04Journal -Path $JournalPath -Mutation 'pktmon-capture' `
            -State 'applied' -Detail $state.etl_path
        $state.available = $true
    } catch {
        $state.available = $false
        $state.error = Get-I04SafeErrorToken `
            -Context 'packet capture setup failed' `
            -Message $_.Exception.Message
    }
    return [pscustomobject]$state
}

function Stop-I04PacketCapture {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$JournalPath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    $null = Assert-I04PktmonGlobalMutexOwnership

    $pktmonCommand = Get-Command pktmon.exe -ErrorAction SilentlyContinue
    $logmanCommand = Get-Command logman.exe -ErrorAction SilentlyContinue
    if ($null -eq $pktmonCommand -or $null -eq $logmanCommand) {
        $State.etw_session_stopped_verified = $null
        $State.owned_filters_absent_verified = $null
        $State.filter_inventory_restored_verified = $null
        $State.etw_loss_proved_zero = $false
        $CleanupFailures.Add(
            'pktmon/logman disappeared before cleanup; capture, filter and ' +
            'ETW-session restoration cannot be verified'
        )
        return
    }

    $sessionPresent = $false
    if ([bool]$State.start_attempted) {
        try {
            $sessionProbeResult = Invoke-I04Logman `
                -LogPath $State.command_log `
                -Arguments @('query', '-ets', 'PktMon')
            if ($sessionProbeResult.timed_out -or
                $sessionProbeResult.log_error) {
                throw 'Bounded PktMon ownership probe was inconclusive'
            }
            $sessionEtwProbe = Get-I04EtwLossEvidence -SessionName 'PktMon'
            if (-not [bool]$sessionEtwProbe.available -and
                [UInt32]$sessionEtwProbe.error_code -ne 4201) {
                throw 'ControlTrace PktMon ownership probe was inconclusive'
            }
            $sessionPresent = [bool]$sessionEtwProbe.available
            if (($sessionProbeResult.exit_code -eq 0) -ne $sessionPresent) {
                throw 'logman and ControlTrace disagreed about PktMon ownership'
            }
            if ($sessionPresent) {
                $State.etw_session_owned_by_start_attempt = $true
                $State.started = $true
                $State.ever_started = $true
            }
        } catch {
            $CleanupFailures.Add((Get-I04SafeErrorToken `
                -Context 'PktMon ownership probe failed' `
                -Message $_.Exception.Message))
        }
    }
    $captureStopped = -not $sessionPresent -and -not [bool]$State.started
    if ($sessionPresent -or [bool]$State.started) {
        try {
            # This is the conservative upper boundary of admissible packet
            # observation. Immediately after fixing it, query the complete
            # filter inventory while the owned session is still alive. Thus a
            # removed, narrowed, replaced or additional filter at the boundary
            # invalidates packet-absence evidence before flush/stop can hide it.
            $captureEnd = [DateTimeOffset]::UtcNow
            $State.capture_ended_epoch_ms =
                Get-I04EpochMilliseconds -Timestamp $captureEnd
            try {
                $preStopFilterResult = Invoke-I04Pktmon `
                    -LogPath $State.command_log `
                    -Arguments @('filter', 'list')
                $preStopFilters = @($preStopFilterResult.output)
                $preStopFilters | Set-Content `
                    -LiteralPath $State.filters_pre_stop_path -Encoding utf8
                if ($preStopFilterResult.timed_out -or
                    $preStopFilterResult.log_error -or
                    $preStopFilterResult.exit_code -ne 0) {
                    throw 'Bounded pre-stop filter inventory was inconclusive'
                }
                $preStopContracts = Test-I04PktmonArmedFilterContracts `
                    -Text ($preStopFilters -join "`n") `
                    -FilterV4 ([string]$State.expected_filter_v4) `
                    -FilterV6 ([string]$State.expected_filter_v6) `
                    -FilterIcmpV6 ([string]$State.expected_filter_icmpv6) `
                    -IPv4 ([string]$State.expected_ipv4) `
                    -IPv6 ([string]$State.expected_ipv6) `
                    -Port ([int]$State.expected_port)
                $State.filter_inventory_pre_stop_sha256 =
                    [string]$preStopContracts.canonical_sha256
                $State.filter_inventory_scenario_unchanged =
                    [bool]$preStopContracts.exact -and
                    [string]$State.filter_inventory_armed_sha256 -match
                        '^[0-9a-f]{64}$' -and
                    [string]$State.filter_inventory_pre_stop_sha256 -ceq
                        [string]$State.filter_inventory_armed_sha256
                if (-not [bool]$State.filter_inventory_scenario_unchanged) {
                    throw 'PktMon filter inventory changed during the adjudicated capture window'
                }
            } catch {
                $State.filter_inventory_scenario_unchanged = $false
                $CleanupFailures.Add((Get-I04SafeErrorToken `
                    -Context 'PktMon scenario filter census failed' `
                    -Message $_.Exception.Message))
            }

            # Frames arriving during final flush/stop are outside the
            # adjudicated interval, but the flush must still account for every
            # buffer carrying a frame at or before the boundary above.
            $flush = Invoke-I04EtwFinalFlush -SessionName 'PktMon'
            $State.etw_final_flush_succeeded = [bool]$flush.succeeded
            $State.etw_final_flush_error_code = $flush.error_code
            $loss = Get-I04EtwLossEvidence -SessionName 'PktMon'
            $State.etw_loss_sample_phase = 'post-final-flush-pre-stop'
            $State.etw_post_flush_query_ok =
                [bool]$flush.succeeded -and [bool]$loss.available -and
                [UInt32]$loss.error_code -eq 0
            $State.etw_events_lost = $loss.events_lost
            $State.etw_buffers_lost = $loss.buffers_lost
            $State.etw_log_buffers_lost = $loss.log_buffers_lost
            $State.etw_realtime_buffers_lost = $loss.realtime_buffers_lost
            $State.etw_buffers_written = $loss.buffers_written
            $State.etw_loss_proved_zero =
                [bool]$State.etw_final_flush_succeeded -and
                [bool]$State.etw_post_flush_query_ok -and
                [bool]$loss.proved_zero
            $State.etw_query_error = $loss.error
            $stopResult = Invoke-I04Pktmon -LogPath $State.command_log `
                -Arguments @('stop')
            if ($stopResult.exit_code -ne 0 -or $stopResult.log_error) {
                throw 'pktmon stop returned a failure'
            }
            $State.started = $false
            $captureStopped = $true
            if (-not [bool]$State.etw_loss_proved_zero) {
                $CleanupFailures.Add(
                    'PktMon loss counters were not proved zero after the final ETW flush'
                )
            }
            if (Test-Path -LiteralPath $State.etl_path -PathType Leaf) {
                $State.etl_size_bytes =
                    (Get-Item -LiteralPath $State.etl_path `
                        -ErrorAction Stop).Length
                $State.etl_below_circular_limit =
                    [Int64]$State.etl_size_bytes -lt 256MB
                if (-not $State.etl_below_circular_limit) {
                    throw (
                        'PktMon ETL reached its 256 MiB circular limit; ' +
                        'capture-start retention is not provable'
                    )
                }
            }
            Add-I04RollbackJournal -Path $JournalPath `
                -Mutation 'pktmon-capture' -State 'rolled_back' `
                -Detail 'capture stopped' -CleanupFailures $CleanupFailures
        } catch {
            $CleanupFailures.Add((Get-I04SafeErrorToken `
                -Context 'PktMon capture stop failed' `
                -Message $_.Exception.Message))
        }
    }
    if ($captureStopped -and
        (Test-Path -LiteralPath $State.etl_path -PathType Leaf)) {
        try {
            $conversionResult = Invoke-I04Pktmon `
                -LogPath $State.command_log -Arguments @(
                'etl2pcap', $State.etl_path, '--out', $State.pcapng_path
            )
            if ($conversionResult.exit_code -ne 0 -or
                $conversionResult.log_error) {
                throw 'pktmon ETL to PCAPNG conversion failed'
            }
        } catch {
            $CleanupFailures.Add((Get-I04SafeErrorToken `
                -Context 'PktMon ETL conversion failed' `
                -Message $_.Exception.Message))
        }
    }

    $ownedFilterNames = @($State.filters)
    $remainingFilters = [Collections.Generic.List[string]]::new()
    foreach ($ownedName in $ownedFilterNames) {
        $remainingFilters.Add([string]$ownedName)
    }
    try {
        $filterInventoryResult = Invoke-I04Pktmon `
            -LogPath $State.command_log -Arguments @('filter', 'list')
        if ($filterInventoryResult.timed_out -or
            $filterInventoryResult.log_error) {
            throw 'Bounded pktmon filter inventory query was inconclusive'
        }
        $filterInventory = @($filterInventoryResult.output)
        $filterInventoryExit = $filterInventoryResult.exit_code
        $filterInventoryText = $filterInventory -join "`n"
    } catch {
        $filterInventory = @()
        $filterInventoryExit = -1
        $filterInventoryText = ''
        $CleanupFailures.Add((Get-I04SafeErrorToken `
            -Context 'pktmon filter inventory query failed' `
            -Message $_.Exception.Message))
    }
    if ($filterInventoryExit -eq 0) {
        try {
            # One full-inventory census is the mandatory gate for cleanup.
            # The ownership projection below may only consume entries after
            # this parser has rejected mixed modes, duplicate IDs and every
            # unrecognized line; global removal is otherwise forbidden.
            $filterInventoryCensus =
                Get-I04PktmonInventoryCensus -Text $filterInventoryText
            if (-not ($filterInventoryCensus.exact -is [bool]) -or
                -not [bool]$filterInventoryCensus.exact) {
                throw (
                    'PktMon filter inventory was not exact: ' +
                    [string]$filterInventoryCensus.reason
                )
            }
            $listedOwned = [Collections.Generic.List[string]]::new()
            $foreignFilterCount = 0
            foreach ($entry in @($filterInventoryCensus.entries)) {
                $ownedMatch = @($ownedFilterNames | Where-Object {
                    [string]$_ -ceq [string]$entry.name
                })
                if ($ownedMatch.Count -eq 1) {
                    $listedOwned.Add([string]$ownedMatch[0])
                } else { $foreignFilterCount++ }
            }
            $remainingFilters.Clear()
            foreach ($listedName in @($listedOwned.ToArray() |
                Sort-Object -Unique)) {
                $remainingFilters.Add([string]$listedName)
            }
            if ($foreignFilterCount -ne 0) {
                throw 'A foreign PktMon filter appeared; refusing global filter removal'
            }
            if ($listedOwned.Count -gt 0) {
                # `pktmon filter remove` is a global operation; current Windows
                # versions do not accept a filter name. It is safe here only
                # because preflight was empty and the exact current census above
                # proved that every listed row belongs to this run.
                $removeResult = Invoke-I04Pktmon `
                    -LogPath $State.command_log `
                    -Arguments @('filter', 'remove')
                if ($removeResult.timed_out -or $removeResult.log_error -or
                    $removeResult.exit_code -ne 0) {
                    throw 'pktmon global owned-filter removal failed'
                }
                $remainingFilters.Clear()
            }
        } catch {
            $CleanupFailures.Add((Get-I04SafeErrorToken `
                -Context 'pktmon owned filter removal failed' `
                -Message $_.Exception.Message))
        }
    }
    if ($ownedFilterNames.Count -gt 0 -and $remainingFilters.Count -eq 0) {
        Add-I04RollbackJournal -Path $JournalPath `
            -Mutation 'pktmon-filters' -State 'rolled_back' `
            -Detail ($ownedFilterNames -join ',') `
            -CleanupFailures $CleanupFailures
    }
    $State.filters = @($remainingFilters.ToArray())

    try {
        $statusAfterResult = Invoke-I04Pktmon `
            -LogPath $State.command_log -Arguments @('status')
        $filtersAfterResult = Invoke-I04Pktmon `
            -LogPath $State.command_log -Arguments @('filter', 'list')
        if ($statusAfterResult.timed_out -or
            $statusAfterResult.log_error -or
            $statusAfterResult.exit_code -ne 0 -or
            $filtersAfterResult.timed_out -or
            $filtersAfterResult.log_error -or
            $filtersAfterResult.exit_code -ne 0) {
            throw 'Bounded pktmon post-cleanup inventory was inconclusive'
        }
        $statusAfter = @($statusAfterResult.output)
        $statusAfter | Set-Content -LiteralPath $State.status_after_path `
            -Encoding utf8
        $filtersAfter = @($filtersAfterResult.output)
        $filtersAfter | Set-Content -LiteralPath $State.filters_after_path `
            -Encoding utf8
        $filterText = $filtersAfter -join "`n"
        $ownedStillListed = @($ownedFilterNames | Where-Object {
            $filterText.IndexOf([string]$_,
                [StringComparison]::OrdinalIgnoreCase) -ge 0
        })
        $State.owned_filters_absent_verified =
            $ownedStillListed.Count -eq 0 -and $State.filters.Count -eq 0
        if (-not $State.owned_filters_absent_verified) {
            $CleanupFailures.Add(
                'pktmon post-cleanup filter list still contains an owned filter'
            )
        }
        $filtersBeforeText = if (Test-Path `
            -LiteralPath $State.filters_before_path -PathType Leaf) {
            Get-Content -LiteralPath $State.filters_before_path -Raw
        } else { $null }
        $filtersBeforeNormalized = if ($null -eq $filtersBeforeText) {
            $null
        } else { $filtersBeforeText.Trim() -replace "`r`n", "`n" }
        $filtersAfterNormalized =
            (($filtersAfter -join "`n").Trim() -replace "`r`n", "`n")
        $State.filter_inventory_restored_verified =
            $null -ne $filtersBeforeNormalized -and
            $filtersBeforeNormalized -ceq $filtersAfterNormalized
        if (-not $State.filter_inventory_restored_verified) {
            $CleanupFailures.Add(
                'pktmon full filter inventory differs from its pre-mutation snapshot'
            )
        }

        $etwAfterResult = Invoke-I04Logman `
            -LogPath $State.command_log `
            -Arguments @('query', '-ets', 'PktMon')
        if ($etwAfterResult.timed_out -or $etwAfterResult.log_error) {
            throw 'Bounded logman post-cleanup session query was inconclusive'
        }
        $etwAfter = @($etwAfterResult.output)
        $etwAfterExit = $etwAfterResult.exit_code
        $etwAfter | Set-Content -LiteralPath $State.etw_after_path -Encoding utf8
        $etwAfterControl = Get-I04EtwLossEvidence -SessionName 'PktMon'
        $State.etw_session_stopped_verified =
            $etwAfterExit -ne 0 -and
            -not [bool]$etwAfterControl.available -and
            [UInt32]$etwAfterControl.error_code -eq 4201
        if ($State.ever_started -and
            -not $State.etw_session_stopped_verified) {
            $State.started = $true
            $CleanupFailures.Add(
                'PktMon ETW session is still active after owned-capture cleanup'
            )
        }
    } catch {
        $CleanupFailures.Add((Get-I04SafeErrorToken `
            -Context 'pktmon post-cleanup state could not be verified' `
            -Message $_.Exception.Message))
    }
}

function Initialize-I04SocketSampler {
    $contractId = 'ese.v91.i04-socket-sampler/2026-08-01.v1'
    if ('V91I04SocketSampler' -as [type]) {
        $null = Assert-I04ManagedTypeContract `
            -TypeName 'V91I04SocketSampler' `
            -ExpectedContractId $contractId
        return
    }
    Add-Type @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class V91I04SocketSampler {
    public const string ContractId = "ese.v91.i04-socket-sampler/2026-08-01.v1";
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    public sealed class Row {
        public string Family;
        public string State;
        public string LocalAddress;
        public int LocalPort;
        public string RemoteAddress;
        public int RemotePort;
        public int OwningProcess;
    }

    public sealed class Handle {
        internal CancellationTokenSource Cancellation;
        internal Task Worker;
        public string Path;
        public string Error;
        public long Samples;
        public long Rows;
        public bool Stopped;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table, ref int size, bool order, int family,
        int tableClass, uint reserved);

    private static int Port(uint raw) {
        return (int)(((raw & 0xFFu) << 8) | ((raw & 0xFF00u) >> 8));
    }

    private static string StateName(uint state) {
        switch (state) {
        case 2: return "Listen";
        case 3: return "SynSent";
        case 4: return "SynReceived";
        case 5: return "Established";
        case 6: return "FinWait1";
        case 7: return "FinWait2";
        case 8: return "CloseWait";
        case 9: return "Closing";
        case 10: return "LastAck";
        case 11: return "TimeWait";
        case 12: return "DeleteTcb";
        default: return "Closed";
        }
    }

    private static string V4(uint raw) {
        return new IPAddress(BitConverter.GetBytes(raw)).ToString();
    }

    private static string V6(byte[] bytes, uint scope) {
        IPAddress ip = new IPAddress(bytes, scope);
        if (ip.IsIPv4MappedToIPv6)
            return ip.MapToIPv4().ToString();
        return ip.ToString().Split('%')[0];
    }

    private static void AppendFamily(List<Row> rows, int family) {
        int size = 0;
        uint first = GetExtendedTcpTable(
            IntPtr.Zero, ref size, false, family,
            TCP_TABLE_OWNER_PID_ALL, 0);
        if (first != 0 && first != 122)
            throw new InvalidOperationException(
                "GetExtendedTcpTable size failed: " + first);
        if (size < 4) size = 4;
        IntPtr buffer = IntPtr.Zero;
        try {
            uint result = 122;
            for (int attempt = 0; attempt < 8 && result == 122; ++attempt) {
                if (buffer != IntPtr.Zero) {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                }
                buffer = Marshal.AllocHGlobal(size);
                int returnedSize = size;
                result = GetExtendedTcpTable(
                    buffer, ref returnedSize, false, family,
                    TCP_TABLE_OWNER_PID_ALL, 0);
                if (result == 122) {
                    size = Math.Max(returnedSize, checked(size * 2));
                } else {
                    size = returnedSize;
                }
            }
            if (result != 0)
                throw new InvalidOperationException(
                    "GetExtendedTcpTable failed after bounded resize: " +
                    result);
            int count = Marshal.ReadInt32(buffer);
            IntPtr cursor = IntPtr.Add(buffer, 4);
            if (family == AF_INET) {
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                for (int i = 0; i < count; ++i) {
                    MIB_TCPROW_OWNER_PID raw =
                        (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(
                            cursor, typeof(MIB_TCPROW_OWNER_PID));
                    rows.Add(new Row {
                        Family = "IPv4",
                        State = StateName(raw.state),
                        LocalAddress = V4(raw.localAddr),
                        LocalPort = Port(raw.localPort),
                        RemoteAddress = V4(raw.remoteAddr),
                        RemotePort = Port(raw.remotePort),
                        OwningProcess = unchecked((int)raw.owningPid)
                    });
                    cursor = IntPtr.Add(cursor, rowSize);
                }
            } else {
                int rowSize = Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID));
                for (int i = 0; i < count; ++i) {
                    MIB_TCP6ROW_OWNER_PID raw =
                        (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(
                            cursor, typeof(MIB_TCP6ROW_OWNER_PID));
                    rows.Add(new Row {
                        Family = "IPv6",
                        State = StateName(raw.state),
                        LocalAddress = V6(raw.localAddr, raw.localScopeId),
                        LocalPort = Port(raw.localPort),
                        RemoteAddress = V6(
                            raw.remoteAddr, raw.remoteScopeId),
                        RemotePort = Port(raw.remotePort),
                        OwningProcess = unchecked((int)raw.owningPid)
                    });
                    cursor = IntPtr.Add(cursor, rowSize);
                }
            }
        } finally {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }
    }

    private static Row[] TargetRows(
        string target4, string target6, int targetPort) {
        List<Row> all = new List<Row>();
        AppendFamily(all, AF_INET);
        AppendFamily(all, AF_INET6);
        List<Row> target = new List<Row>();
        foreach (Row row in all) {
            if (row.RemotePort == targetPort &&
                (String.Equals(row.RemoteAddress, target4,
                    StringComparison.OrdinalIgnoreCase) ||
                 String.Equals(row.RemoteAddress, target6,
                    StringComparison.OrdinalIgnoreCase)))
                target.Add(row);
        }
        return target.ToArray();
    }

    private static string Escape(string value) {
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    private static void WriteSample(
        StreamWriter writer, double epochMs, long qpc, Row[] rows) {
        StringBuilder line = new StringBuilder();
        line.Append("{\"epoch_ms\":");
        line.Append(epochMs.ToString("R", CultureInfo.InvariantCulture));
        line.Append(",\"qpc\":");
        line.Append(qpc.ToString(CultureInfo.InvariantCulture));
        line.Append(",\"rows\":[");
        for (int i = 0; i < rows.Length; ++i) {
            if (i != 0) line.Append(',');
            Row r = rows[i];
            line.Append("{\"family\":\"");
            line.Append(Escape(r.Family));
            line.Append("\",\"state\":\"");
            line.Append(Escape(r.State));
            line.Append("\",\"local_address\":\"");
            line.Append(Escape(r.LocalAddress));
            line.Append("\",\"local_port\":");
            line.Append(r.LocalPort.ToString(CultureInfo.InvariantCulture));
            line.Append(",\"remote_address\":\"");
            line.Append(Escape(r.RemoteAddress));
            line.Append("\",\"remote_port\":");
            line.Append(r.RemotePort.ToString(CultureInfo.InvariantCulture));
            line.Append(",\"owning_process\":");
            line.Append(
                r.OwningProcess.ToString(CultureInfo.InvariantCulture));
            line.Append('}');
        }
        line.Append("]}");
        writer.WriteLine(line.ToString());
        writer.Flush();
    }

    public static Handle Start(
        string path, string target4, string target6,
        int targetPort, int intervalMs) {
        Handle handle = new Handle();
        handle.Path = path;
        handle.Error = "";
        handle.Cancellation = new CancellationTokenSource();
        CancellationToken token = handle.Cancellation.Token;
        handle.Worker = Task.Run(delegate {
            try {
                using (StreamWriter writer = new StreamWriter(
                    new FileStream(path, FileMode.Create, FileAccess.Write,
                        FileShare.Read),
                    new UTF8Encoding(false))) {
                    while (!token.IsCancellationRequested) {
                        Row[] rows = TargetRows(
                            target4, target6, targetPort);
                        // Timestamp the completed snapshot.  epoch_ms and qpc
                        // must describe the same edge of the table query.
                        DateTimeOffset now = DateTimeOffset.UtcNow;
                        long qpc = Stopwatch.GetTimestamp();
                        double epochMs = (now.UtcTicks -
                            new DateTimeOffset(1970, 1, 1, 0, 0, 0,
                                TimeSpan.Zero).UtcTicks) /
                            (double)TimeSpan.TicksPerMillisecond;
                        WriteSample(writer, epochMs, qpc, rows);
                        Interlocked.Increment(ref handle.Samples);
                        Interlocked.Add(ref handle.Rows, rows.Length);
                        if (token.WaitHandle.WaitOne(intervalMs))
                            break;
                    }
                }
            } catch (Exception ex) {
                handle.Error = ex.ToString();
            } finally {
                handle.Stopped = true;
            }
        });
        return handle;
    }

    public static bool Stop(Handle handle, int timeoutMs) {
        if (handle == null) return true;
        handle.Cancellation.Cancel();
        bool stopped = handle.Worker.Wait(timeoutMs);
        handle.Stopped = stopped;
        return stopped;
    }
}
'@
    $null = Assert-I04ManagedTypeContract `
        -TypeName 'V91I04SocketSampler' `
        -ExpectedContractId $contractId
}

function Start-I04SocketSampler {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )

    Initialize-I04SocketSampler
    return [V91I04SocketSampler]::Start(
        $Path, $IPv4, $IPv6, $Port, 25
    )
}

function Stop-I04SocketSampler {
    param(
        [AllowNull()][object]$Sampler,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    if ($null -eq $Sampler) { return $true }
    $stopped = $false
    try {
        $stopped = [V91I04SocketSampler]::Stop($Sampler, 10000)
        if (-not $stopped) {
            $CleanupFailures.Add(
                'PID socket sampler did not stop within 10 seconds'
            )
        }
        if ([string]$Sampler.Error) {
            $CleanupFailures.Add((Get-I04SafeErrorToken `
                -Context 'PID socket sampler failed' `
                -Message ([string]$Sampler.Error)))
        }
    } catch {
        $CleanupFailures.Add((Get-I04SafeErrorToken `
            -Context 'PID socket sampler cleanup failed' `
            -Message $_.Exception.Message))
    }
    return $stopped
}

function Get-I04SamplerClockValidation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$Samples,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [Int64]::MaxValue)][Int64]$QpcFrequency,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0.001, 1000)][double]$CoherenceToleranceMs,
        [Parameter(Mandatory = $true)][double]$BoundaryEpochMs,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [Int64]::MaxValue)][Int64]$BoundaryQpc
    )

    $violations = [System.Collections.Generic.List[object]]::new()
    $previousEpoch = $null
    $previousQpc = $null
    $firstEpoch = $null
    $lastEpoch = $null
    $firstQpc = $null
    $lastQpc = $null
    $maximumEpochGapMs = 0.0
    $maximumQpcGapMs = 0.0
    $maximumIntervalErrorMs = 0.0
    $maximumBoundaryProjectionErrorMs = 0.0
    $epochMonotonic = $true
    $qpcStrictlyIncreasing = $true
    $intervalsCoherent = $true
    $boundaryProjectionCoherent = $true
    $index = 0

    foreach ($sample in $Samples) {
        $index++
        $epoch = [double]$sample.epoch_ms
        $qpc = [Int64]$sample.qpc
        if ([double]::IsNaN($epoch) -or
            [double]::IsInfinity($epoch) -or $epoch -le 0 -or $qpc -le 0) {
            $violations.Add([pscustomobject][ordered]@{
                sample_index = $index
                code = 'invalid-clock-value'
                epoch_ms = $epoch
                qpc = $qpc
                error_ms = $null
            })
            continue
        }
        if ($null -eq $firstEpoch) {
            $firstEpoch = $epoch
            $firstQpc = $qpc
        }
        $lastEpoch = $epoch
        $lastQpc = $qpc

        $boundaryQpcDeltaMs =
            (([double]$qpc - [double]$BoundaryQpc) * 1000.0) /
                [double]$QpcFrequency
        $boundaryEpochDeltaMs = $epoch - $BoundaryEpochMs
        $boundaryProjectionErrorMs = [Math]::Abs(
            $boundaryEpochDeltaMs - $boundaryQpcDeltaMs
        )
        $maximumBoundaryProjectionErrorMs = [Math]::Max(
            $maximumBoundaryProjectionErrorMs,
            $boundaryProjectionErrorMs
        )
        if ($boundaryProjectionErrorMs -gt $CoherenceToleranceMs) {
            $boundaryProjectionCoherent = $false
            $violations.Add([pscustomobject][ordered]@{
                sample_index = $index
                code = 'boundary-clock-incoherent'
                epoch_ms = $epoch
                qpc = $qpc
                error_ms = [Math]::Round(
                    $boundaryProjectionErrorMs, 6
                )
            })
        }

        if ($null -ne $previousEpoch) {
            $epochDeltaMs = $epoch - [double]$previousEpoch
            $qpcIncreasing = $qpc -gt [Int64]$previousQpc
            if ($epochDeltaMs -lt 0) {
                $epochMonotonic = $false
                $violations.Add([pscustomobject][ordered]@{
                    sample_index = $index
                    code = 'epoch-regressed'
                    epoch_ms = $epoch
                    qpc = $qpc
                    error_ms = [Math]::Round($epochDeltaMs, 6)
                })
            } else {
                $maximumEpochGapMs = [Math]::Max(
                    $maximumEpochGapMs, $epochDeltaMs
                )
            }
            if (-not $qpcIncreasing) {
                $qpcStrictlyIncreasing = $false
                $violations.Add([pscustomobject][ordered]@{
                    sample_index = $index
                    code = 'qpc-not-strictly-increasing'
                    epoch_ms = $epoch
                    qpc = $qpc
                    error_ms = $null
                })
            } else {
                $qpcDeltaMs =
                    (([double]$qpc - [double]$previousQpc) * 1000.0) /
                        [double]$QpcFrequency
                $maximumQpcGapMs = [Math]::Max(
                    $maximumQpcGapMs, $qpcDeltaMs
                )
                if ($epochDeltaMs -ge 0) {
                    $intervalErrorMs =
                        [Math]::Abs($epochDeltaMs - $qpcDeltaMs)
                    $maximumIntervalErrorMs = [Math]::Max(
                        $maximumIntervalErrorMs, $intervalErrorMs
                    )
                    if ($intervalErrorMs -gt $CoherenceToleranceMs) {
                        $intervalsCoherent = $false
                        $violations.Add([pscustomobject][ordered]@{
                            sample_index = $index
                            code = 'interval-clock-incoherent'
                            epoch_ms = $epoch
                            qpc = $qpc
                            error_ms = [Math]::Round(
                                $intervalErrorMs, 6
                            )
                        })
                    }
                }
            }
        }
        $previousEpoch = $epoch
        $previousQpc = $qpc
    }

    return [pscustomobject][ordered]@{
        valid = $violations.Count -eq 0
        sample_count = $Samples.Count
        qpc_frequency = $QpcFrequency
        coherence_tolerance_ms = $CoherenceToleranceMs
        boundary_epoch_ms = $BoundaryEpochMs
        boundary_qpc = $BoundaryQpc
        epoch_monotonic_non_decreasing = $epochMonotonic
        qpc_strictly_increasing = $qpcStrictlyIncreasing
        interval_deltas_coherent = $intervalsCoherent
        boundary_projection_coherent = $boundaryProjectionCoherent
        first_epoch_ms = $firstEpoch
        last_epoch_ms = $lastEpoch
        first_qpc = $firstQpc
        last_qpc = $lastQpc
        maximum_epoch_gap_ms = [Math]::Round($maximumEpochGapMs, 6)
        maximum_qpc_gap_ms = [Math]::Round($maximumQpcGapMs, 6)
        maximum_interval_error_ms =
            [Math]::Round($maximumIntervalErrorMs, 6)
        maximum_boundary_projection_error_ms =
            [Math]::Round($maximumBoundaryProjectionErrorMs, 6)
        violation_count = $violations.Count
        violations = $violations.ToArray()
    }
}

function Get-I04SocketSamplerEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][double]$BoundaryEpochMs,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [Int64]::MaxValue)][Int64]$BoundaryQpc,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0.001, 1000)][double]$ClockCoherenceToleranceMs
    )

    $v4Ports = New-Object 'Collections.Generic.HashSet[int]'
    $v6Ports = New-Object 'Collections.Generic.HashSet[int]'
    $allTargetRows = [System.Collections.Generic.List[object]]::new()
    $candidateTargetRows = [System.Collections.Generic.List[object]]::new()
    $otherPidRows = [System.Collections.Generic.List[object]]::new()
    $preBoundaryRows = [System.Collections.Generic.List[object]]::new()
    $sampleTimings = [System.Collections.Generic.List[object]]::new()
    $sampleCount = 0
    $parseErrors = 0
    $v4Established = $false
    $v6Attempt = $false
    $snapshot = Open-I04ImmutableEvidenceSnapshot -Path $Path
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $snapshotText = $strictUtf8.GetString([byte[]]$snapshot.bytes)
    foreach ($lineValue in @($snapshotText -split "\r?\n")) {
        if ([string]::IsNullOrWhiteSpace([string]$lineValue)) { continue }
        try {
            $sample = [string]$lineValue | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $parseErrors++
            continue
        }
        try {
            $epoch = [double]$sample.epoch_ms
            $qpc = [Int64]$sample.qpc
        } catch {
            $parseErrors++
            continue
        }
        $sampleCount++
        $sampleTimings.Add([pscustomobject][ordered]@{
            sample_index = $sampleCount
            epoch_ms = $epoch
            qpc = $qpc
        })
        foreach ($row in @($sample.rows)) {
            $localAddress =
                Get-I04NormalizedIp -Address ([string]$row.local_address)
            $remoteAddress =
                Get-I04NormalizedIp -Address ([string]$row.remote_address)
            $record = [pscustomobject][ordered]@{
                epoch_ms = $epoch
                qpc = $qpc
                family = [string]$row.family
                state = [string]$row.state
                local_address = $localAddress
                local_port = [int]$row.local_port
                remote_address = $remoteAddress
                remote_port = [int]$row.remote_port
                owning_process = [int]$row.owning_process
                tuple_key = Get-I04TupleKey `
                    -Family ([string]$row.family) `
                    -LocalAddress $localAddress `
                    -LocalPort ([int]$row.local_port) `
                    -RemoteAddress $remoteAddress `
                    -RemotePort ([int]$row.remote_port)
            }
            $allTargetRows.Add($record)
            # QPC is the authoritative side of the formal boundary. Wall-clock
            # epoch remains necessary only for PCAP correlation and is admitted
            # after dual-clock coherence validation below.
            if ($qpc -lt $BoundaryQpc) {
                $preBoundaryRows.Add($record)
                continue
            }
            if ([int]$row.owning_process -ne $CandidateProcessId) {
                $otherPidRows.Add($record)
                continue
            }
            $candidateTargetRows.Add($record)
            if ([string]$row.family -eq 'IPv6' -and
                [string]$row.state -in @('SynSent', 'Established')) {
                $null = $v6Ports.Add([int]$row.local_port)
                $v6Attempt = $true
            }
            if ([string]$row.family -eq 'IPv4' -and
                [string]$row.state -in @('SynSent', 'Established')) {
                $null = $v4Ports.Add([int]$row.local_port)
                if ([string]$row.state -eq 'Established') {
                    $v4Established = $true
                }
            }
        }
    }
    $clockValidation = Get-I04SamplerClockValidation `
        -Samples $sampleTimings.ToArray() `
        -QpcFrequency ([Diagnostics.Stopwatch]::Frequency) `
        -CoherenceToleranceMs $ClockCoherenceToleranceMs `
        -BoundaryEpochMs $BoundaryEpochMs -BoundaryQpc $BoundaryQpc
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-pid-socket-sampler/v1'
        path = 'evidence\socket-samples.ndjson'
        source_byte_count = [Int64]$snapshot.byte_count
        source_sha256 = [string]$snapshot.sha256
        source_immutable_read_lock_held =
            [bool]$snapshot.immutable_read_lock_held
        candidate_process_id = $CandidateProcessId
        boundary_epoch_ms = $BoundaryEpochMs
        boundary_qpc = $BoundaryQpc
        qpc_frequency = [Diagnostics.Stopwatch]::Frequency
        clock_coherence_tolerance_ms = $ClockCoherenceToleranceMs
        clock_coherence_valid = [bool]$clockValidation.valid
        clock_validation = $clockValidation
        sample_count = $sampleCount
        parse_error_count = $parseErrors
        first_sample_epoch_ms = $clockValidation.first_epoch_ms
        last_sample_epoch_ms = $clockValidation.last_epoch_ms
        first_sample_qpc = $clockValidation.first_qpc
        last_sample_qpc = $clockValidation.last_qpc
        maximum_sample_gap_ms = $clockValidation.maximum_qpc_gap_ms
        maximum_epoch_gap_ms = $clockValidation.maximum_epoch_gap_ms
        target_row_count = $allTargetRows.Count
        target_rows = $allTargetRows.ToArray()
        candidate_target_row_count = $candidateTargetRows.Count
        candidate_target_rows = $candidateTargetRows.ToArray()
        candidate_ipv4_local_ports = @($v4Ports | Sort-Object)
        candidate_ipv6_local_ports = @($v6Ports | Sort-Object)
        candidate_ipv6_attempt_observed = $v6Attempt
        candidate_ipv4_established_observed = $v4Established
        pre_boundary_target_row_count = $preBoundaryRows.Count
        pre_boundary_target_rows = $preBoundaryRows.ToArray()
        other_pid_target_row_count = $otherPidRows.Count
        other_pid_target_rows = $otherPidRows.ToArray()
        sampler_coverage_valid = $sampleCount -ge 2 -and
            $parseErrors -eq 0 -and [bool]$clockValidation.valid -and
            [double]$clockValidation.maximum_qpc_gap_ms -lt 250
    }
}

function Read-I04UInt16LE {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Read-I04UInt32LE {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Read-I04UInt16BE {
    param([byte[]]$Bytes, [int]$Offset)
    return ([int]$Bytes[$Offset] -shl 8) -bor [int]$Bytes[$Offset + 1]
}

function Read-I04UInt32BE {
    param([byte[]]$Bytes, [int]$Offset)
    return [uint32](
        ([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor
        [uint32]$Bytes[$Offset + 3]
    )
}

function Convert-I04Packet {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Packet,
        [Parameter(Mandatory = $true)][int]$LinkType,
        [Parameter(Mandatory = $true)][double]$TimestampMs
    )

    $offset = 0
    $etherType = 0
    if ($LinkType -eq 1) {
        if ($Packet.Length -lt 14) { return $null }
        $etherType = Read-I04UInt16BE -Bytes $Packet -Offset 12
        $offset = 14
        while ($etherType -eq 0x8100 -or $etherType -eq 0x88a8) {
            if ($Packet.Length -lt $offset + 4) { return $null }
            $etherType = Read-I04UInt16BE -Bytes $Packet -Offset ($offset + 2)
            $offset += 4
        }
    } elseif ($LinkType -eq 101) {
        if ($Packet.Length -lt 1) { return $null }
        $version = $Packet[0] -shr 4
        $etherType = if ($version -eq 4) { 0x0800 } elseif ($version -eq 6) {
            0x86dd
        } else { 0 }
    } elseif ($LinkType -eq 228) {
        $etherType = 0x0800
    } elseif ($LinkType -eq 229) {
        $etherType = 0x86dd
    } else {
        return $null
    }

    if ($etherType -eq 0x0800) {
        if ($Packet.Length -lt $offset + 20 -or
            ($Packet[$offset] -shr 4) -ne 4) { return $null }
        $ihl = ($Packet[$offset] -band 0x0f) * 4
        if ($ihl -lt 20 -or $Packet.Length -lt $offset + $ihl) { return $null }
        $totalLength = Read-I04UInt16BE -Bytes $Packet -Offset ($offset + 2)
        $ipEnd = $offset + $totalLength
        $fragmentField = Read-I04UInt16BE -Bytes $Packet `
            -Offset ($offset + 6)
        if ($totalLength -lt $ihl + 20 -or $ipEnd -gt $Packet.Length -or
            ($fragmentField -band 0x3fff) -ne 0) { return $null }
        $protocol = [int]$Packet[$offset + 9]
        $sourceBytes = New-Object byte[] 4
        $destinationBytes = New-Object byte[] 4
        [Array]::Copy($Packet, $offset + 12, $sourceBytes, 0, 4)
        [Array]::Copy($Packet, $offset + 16, $destinationBytes, 0, 4)
        $source = ([Net.IPAddress]::new($sourceBytes)).ToString()
        $destination = ([Net.IPAddress]::new($destinationBytes)).ToString()
        $transportOffset = $offset + $ihl
        if ($protocol -ne 6 -or $ipEnd -lt $transportOffset + 20) {
            return $null
        }
        $tcpHeaderLength = ($Packet[$transportOffset + 12] -shr 4) * 4
        if ($tcpHeaderLength -lt 20 -or
            $transportOffset + $tcpHeaderLength -gt $ipEnd) { return $null }
        $sourcePort = Read-I04UInt16BE -Bytes $Packet -Offset $transportOffset
        $destinationPort = Read-I04UInt16BE -Bytes $Packet `
            -Offset ($transportOffset + 2)
        $flags = [int]$Packet[$transportOffset + 13]
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv4'
            protocol = 'TCP'
            source = $source
            destination = $destination
            source_port = $sourcePort
            destination_port = $destinationPort
            sequence_number = Read-I04UInt32BE -Bytes $Packet `
                -Offset ($transportOffset + 4)
            acknowledgement_number = Read-I04UInt32BE -Bytes $Packet `
                -Offset ($transportOffset + 8)
            syn = ($flags -band 0x02) -ne 0
            ack = ($flags -band 0x10) -ne 0
            rst = ($flags -band 0x04) -ne 0
            fin = ($flags -band 0x01) -ne 0
            icmp_type = $null
            quoted_family = $null
            quoted_protocol = $null
            quoted_source = $null
            quoted_destination = $null
            quoted_source_port = $null
            quoted_destination_port = $null
            quoted_sequence_number = $null
            quoted_parse_complete = $null
        }
    }

    if ($etherType -ne 0x86dd -or $Packet.Length -lt $offset + 40 -or
        ($Packet[$offset] -shr 4) -ne 6) {
        return $null
    }
    $ipv6PayloadLength = Read-I04UInt16BE -Bytes $Packet `
        -Offset ($offset + 4)
    if ($ipv6PayloadLength -eq 0 -or
        $offset + 40 + $ipv6PayloadLength -gt $Packet.Length) {
        return $null
    }
    $ipv6End = $offset + 40 + $ipv6PayloadLength
    $nextHeader = [int]$Packet[$offset + 6]
    $sourceV6Bytes = New-Object byte[] 16
    $destinationV6Bytes = New-Object byte[] 16
    [Array]::Copy($Packet, $offset + 8, $sourceV6Bytes, 0, 16)
    [Array]::Copy($Packet, $offset + 24, $destinationV6Bytes, 0, 16)
    $sourceV6 = ([Net.IPAddress]::new($sourceV6Bytes)).ToString()
    $destinationV6 = ([Net.IPAddress]::new($destinationV6Bytes)).ToString()
    $transport = $offset + 40
    while ($nextHeader -in @(0, 43, 44, 51, 60)) {
        if ($nextHeader -eq 44 -or $ipv6End -lt $transport + 8) {
            return $null
        }
        $following = [int]$Packet[$transport]
        $extensionBytes = if ($nextHeader -eq 44) {
            8
        } elseif ($nextHeader -eq 51) {
            ([int]$Packet[$transport + 1] + 2) * 4
        } else {
            ([int]$Packet[$transport + 1] + 1) * 8
        }
        $transport += $extensionBytes
        $nextHeader = $following
        if ($ipv6End -lt $transport) { return $null }
    }
    if ($nextHeader -eq 58 -and $ipv6End -ge $transport + 8) {
        $quotedFamily = $null
        $quotedProtocol = $null
        $quotedSource = $null
        $quotedDestination = $null
        $quotedSourcePort = $null
        $quotedDestinationPort = $null
        $quotedSequence = $null
        $quotedParseComplete = $false
        $quotedOffset = $transport + 8
        if ($ipv6End -ge $quotedOffset + 40 -and
            ($Packet[$quotedOffset] -shr 4) -eq 6) {
            $quotedFamily = 'IPv6'
            $quotedNext = [int]$Packet[$quotedOffset + 6]
            $quotedSourceBytes = New-Object byte[] 16
            $quotedDestinationBytes = New-Object byte[] 16
            [Array]::Copy(
                $Packet, $quotedOffset + 8, $quotedSourceBytes, 0, 16
            )
            [Array]::Copy(
                $Packet, $quotedOffset + 24, $quotedDestinationBytes, 0, 16
            )
            $quotedSource = ([Net.IPAddress]::new(
                $quotedSourceBytes
            )).ToString()
            $quotedDestination = ([Net.IPAddress]::new(
                $quotedDestinationBytes
            )).ToString()
            $quotedTransport = $quotedOffset + 40
            while ($quotedNext -in @(0, 43, 44, 51, 60)) {
                if ($ipv6End -lt $quotedTransport + 8) { break }
                $quotedFollowing = [int]$Packet[$quotedTransport]
                $quotedExtensionBytes = if ($quotedNext -eq 44) {
                    8
                } elseif ($quotedNext -eq 51) {
                    ([int]$Packet[$quotedTransport + 1] + 2) * 4
                } else {
                    ([int]$Packet[$quotedTransport + 1] + 1) * 8
                }
                $quotedTransport += $quotedExtensionBytes
                $quotedNext = $quotedFollowing
            }
            if ($quotedNext -eq 6 -and
                $ipv6End -ge $quotedTransport + 8) {
                $quotedProtocol = 'TCP'
                $quotedSourcePort = Read-I04UInt16BE -Bytes $Packet `
                    -Offset $quotedTransport
                $quotedDestinationPort = Read-I04UInt16BE -Bytes $Packet `
                    -Offset ($quotedTransport + 2)
                $quotedSequence = Read-I04UInt32BE -Bytes $Packet `
                    -Offset ($quotedTransport + 4)
                $quotedParseComplete = $true
            } elseif ($quotedNext -notin @(0, 43, 44, 51, 60)) {
                $quotedProtocol = 'IPPROTO-' + [string]$quotedNext
                $quotedParseComplete = $true
            }
        }
        $icmpType = [int]$Packet[$transport]
        if ($icmpType -in @(1, 2, 3, 4) -and
            -not $quotedParseComplete) {
            # A truncated ICMPv6 error quote could be the only evidence that
            # the target SYN was rejected. Treat it as non-adjudicable rather
            # than silently converting it into a proved blackhole.
            return $null
        }
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv6'
            protocol = 'ICMPv6'
            source = $sourceV6
            destination = $destinationV6
            source_port = $null
            destination_port = $null
            sequence_number = $null
            acknowledgement_number = $null
            syn = $false
            ack = $false
            rst = $false
            fin = $false
            icmp_type = $icmpType
            quoted_family = $quotedFamily
            quoted_protocol = $quotedProtocol
            quoted_source = $quotedSource
            quoted_destination = $quotedDestination
            quoted_source_port = $quotedSourcePort
            quoted_destination_port = $quotedDestinationPort
            quoted_sequence_number = $quotedSequence
            quoted_parse_complete = $quotedParseComplete
        }
    }
    if ($nextHeader -ne 6 -or $ipv6End -lt $transport + 20) {
        return $null
    }
    $v6TcpHeaderLength = ($Packet[$transport + 12] -shr 4) * 4
    if ($v6TcpHeaderLength -lt 20 -or
        $transport + $v6TcpHeaderLength -gt $ipv6End) { return $null }
    $sourceV6Port = Read-I04UInt16BE -Bytes $Packet -Offset $transport
    $destinationV6Port = Read-I04UInt16BE -Bytes $Packet -Offset ($transport + 2)
    $v6Flags = [int]$Packet[$transport + 13]
    return [pscustomobject][ordered]@{
        timestamp_ms = $TimestampMs
        family = 'IPv6'
        protocol = 'TCP'
        source = $sourceV6
        destination = $destinationV6
        source_port = $sourceV6Port
        destination_port = $destinationV6Port
        sequence_number = Read-I04UInt32BE -Bytes $Packet `
            -Offset ($transport + 4)
        acknowledgement_number = Read-I04UInt32BE -Bytes $Packet `
            -Offset ($transport + 8)
        syn = ($v6Flags -band 0x02) -ne 0
        ack = ($v6Flags -band 0x10) -ne 0
        rst = ($v6Flags -band 0x04) -ne 0
        fin = ($v6Flags -band 0x01) -ne 0
        icmp_type = $null
        quoted_family = $null
        quoted_protocol = $null
        quoted_source = $null
        quoted_destination = $null
        quoted_source_port = $null
        quoted_destination_port = $null
        quoted_sequence_number = $null
        quoted_parse_complete = $null
    }
}

function Read-I04PcapNg {
    param([Parameter(Mandatory = $true)][string]$Path)

    $snapshot = Open-I04ImmutableEvidenceSnapshot -Path $Path
    $bytes = [byte[]]$snapshot.bytes
    if ($bytes.Length -lt 28 -or
        (Read-I04UInt32LE -Bytes $bytes -Offset 0) -ne 0x0a0d0d0a -or
        (Read-I04UInt32LE -Bytes $bytes -Offset 8) -ne 0x1a2b3c4d) {
        throw 'Only little-endian PCAPNG produced by pktmon is supported'
    }
    $interfaces = @{}
    $interfaceRecords = [System.Collections.Generic.List[object]]::new()
    $packets = [System.Collections.Generic.List[object]]::new()
    $parserComplete = $true
    $blockErrorCount = 0
    $idbOptionErrorCount = 0
    $unknownInterfaceFrameCount = 0
    $unsupportedLinkTypeFrameCount = 0
    $unsupportedPacketBlockCount = 0
    $truncatedFrameCount = 0
    $nonAdjudicableFrameCount = 0
    $parseNullFrameCount = 0
    $enhancedPacketCount = 0
    $sectionIndex = -1
    $interfaceNumber = 0
    $offset = 0
    while ($offset + 12 -le $bytes.Length) {
        $type = Read-I04UInt32LE -Bytes $bytes -Offset $offset
        $length = [int](Read-I04UInt32LE -Bytes $bytes -Offset ($offset + 4))
        if ($length -lt 12 -or ($length % 4) -ne 0 -or
            $offset + $length -gt $bytes.Length -or
            (Read-I04UInt32LE -Bytes $bytes -Offset ($offset + $length - 4)) -ne
                [uint32]$length) {
            $parserComplete = $false
            $blockErrorCount++
            break
        }
        if ($type -eq 0x0a0d0d0a) {
            if ($length -lt 28 -or
                (Read-I04UInt32LE -Bytes $bytes -Offset ($offset + 8)) -ne
                    0x1a2b3c4d) {
                $parserComplete = $false
                $blockErrorCount++
            } else {
                $sectionIndex++
                $interfaceNumber = 0
                $interfaces = @{}
            }
        } elseif ($type -eq 1) {
            if ($sectionIndex -lt 0 -or $length -lt 20) {
                $parserComplete = $false
                $blockErrorCount++
                $offset += $length
                continue
            }
            $linkType = Read-I04UInt16LE -Bytes $bytes -Offset ($offset + 8)
            $resolution = 0.000001
            $timestampOffsetSeconds = 0L
            $interfaceName = ''
            $interfaceDescription = ''
            $optionsValid = $true
            $option = $offset + 16
            $optionEnd = $offset + $length - 4
            while ($option -lt $optionEnd) {
                if ($option + 4 -gt $optionEnd) {
                    $optionsValid = $false
                    break
                }
                $code = Read-I04UInt16LE -Bytes $bytes -Offset $option
                $optionLength = Read-I04UInt16LE -Bytes $bytes `
                    -Offset ($option + 2)
                $paddedOptionLength = ($optionLength + 3) -band (-bnot 3)
                if ($code -eq 0) {
                    if ($optionLength -ne 0) { $optionsValid = $false }
                    break
                }
                if ($option + 4 + $paddedOptionLength -gt $optionEnd) {
                    $optionsValid = $false
                    break
                }
                if ($code -in @(2, 3)) {
                    try {
                        $optionText = [Text.Encoding]::UTF8.GetString(
                            $bytes, $option + 4, $optionLength
                        ).Trim([char]0)
                        if ($code -eq 2) {
                            $interfaceName = $optionText
                        } else {
                            $interfaceDescription = $optionText
                        }
                    } catch {
                        $optionsValid = $false
                        break
                    }
                }
                if ($code -eq 9 -and $optionLength -ne 1) {
                    $optionsValid = $false
                    break
                }
                if ($code -eq 9) {
                    $value = [int]$bytes[$option + 4]
                    if (($value -band 0x80) -ne 0) {
                        $resolution = [Math]::Pow(2, -($value -band 0x7f))
                    } else {
                        $resolution = [Math]::Pow(10, -$value)
                    }
                }
                if ($code -eq 10) {
                    # Deprecated if_tzone would make epoch normalization
                    # ambiguous across tool versions.
                    $optionsValid = $false
                    break
                }
                if ($code -eq 14) {
                    if ($optionLength -ne 8) {
                        $optionsValid = $false
                        break
                    }
                    $timestampOffsetSeconds = [BitConverter]::ToInt64(
                        $bytes, $option + 4)
                }
                $option += 4 + $paddedOptionLength
            }
            if (-not $optionsValid) {
                $parserComplete = $false
                $idbOptionErrorCount++
            }
            $interfaceRecord = [pscustomobject][ordered]@{
                section_index = $sectionIndex
                interface_id = $interfaceNumber
                link_type = [int]$linkType
                timestamp_resolution = [double]$resolution
                timestamp_offset_seconds = [Int64]$timestampOffsetSeconds
                supported_link_type = [int]$linkType -in @(1, 101, 228, 229)
                interface_name_sha256 = if ($interfaceName) {
                    Get-I04StringSha256 -Value $interfaceName
                } else { '' }
                interface_description_sha256 = if ($interfaceDescription) {
                    Get-I04StringSha256 -Value $interfaceDescription
                } else { '' }
                options_valid = $optionsValid
                _interface_name = $interfaceName
                _interface_description = $interfaceDescription
            }
            $interfaces[$interfaceNumber] = $interfaceRecord
            $interfaceRecords.Add($interfaceRecord)
            $interfaceNumber++
        } elseif ($type -in @(2, 3)) {
            # Obsolete Packet Blocks and Simple Packet Blocks also carry frame
            # bytes. This parser cannot preserve their interface/timestamp
            # binding, so their presence makes absence evidence inadmissible.
            $unsupportedPacketBlockCount++
            $nonAdjudicableFrameCount++
            $parserComplete = $false
        } elseif ($type -eq 6) {
            $enhancedPacketCount++
            if ($sectionIndex -lt 0 -or $length -lt 32) {
                $parserComplete = $false
                $blockErrorCount++
                $nonAdjudicableFrameCount++
                $offset += $length
                continue
            }
            $interfaceId = [int](Read-I04UInt32LE -Bytes $bytes `
                -Offset ($offset + 8))
            $capturedLength = [int](Read-I04UInt32LE -Bytes $bytes `
                -Offset ($offset + 20))
            $originalLength = [int](Read-I04UInt32LE -Bytes $bytes `
                -Offset ($offset + 24))
            $paddedCapturedLength = ($capturedLength + 3) -band (-bnot 3)
            if (-not $interfaces.ContainsKey($interfaceId)) {
                $unknownInterfaceFrameCount++
                $nonAdjudicableFrameCount++
                $parserComplete = $false
            } elseif ($capturedLength -lt 0 -or $originalLength -lt 0 -or
                $capturedLength -ne $originalLength -or
                $offset + 28 + $paddedCapturedLength -gt
                    $offset + $length - 4) {
                $truncatedFrameCount++
                $nonAdjudicableFrameCount++
                $parserComplete = $false
            } elseif (-not [bool]$interfaces[$interfaceId].supported_link_type) {
                $unsupportedLinkTypeFrameCount++
                $nonAdjudicableFrameCount++
                $parserComplete = $false
            } else {
                $high = [UInt64](Read-I04UInt32LE -Bytes $bytes `
                    -Offset ($offset + 12))
                $low = [UInt64](Read-I04UInt32LE -Bytes $bytes `
                    -Offset ($offset + 16))
                $ticks = ($high -shl 32) -bor $low
                $timeMs = [double]$ticks *
                    [double]$interfaces[$interfaceId].timestamp_resolution *
                    1000.0 +
                    ([double]$interfaces[$interfaceId].
                        timestamp_offset_seconds * 1000.0)
                $packetBytes = New-Object byte[] $capturedLength
                [Array]::Copy($bytes, $offset + 28, $packetBytes, 0,
                    $capturedLength)
                $parsed = Convert-I04Packet -Packet $packetBytes `
                    -LinkType $interfaces[$interfaceId].link_type `
                    -TimestampMs $timeMs
                if ($null -eq $parsed) {
                    $parseNullFrameCount++
                    $nonAdjudicableFrameCount++
                    $parserComplete = $false
                } else {
                    $parsed | Add-Member -NotePropertyName section_index `
                        -NotePropertyValue $sectionIndex
                    $parsed | Add-Member -NotePropertyName capture_interface_id `
                        -NotePropertyValue $interfaceId
                    $parsed | Add-Member -NotePropertyName capture_link_type `
                        -NotePropertyValue ([int]$interfaces[$interfaceId].link_type)
                    $parsed | Add-Member -NotePropertyName captured_length `
                        -NotePropertyValue $capturedLength
                    $parsed | Add-Member -NotePropertyName original_length `
                        -NotePropertyValue $originalLength
                    $parsed | Add-Member -NotePropertyName frame_complete `
                        -NotePropertyValue $true
                    $packets.Add($parsed)
                }
            }
        }
        $offset += $length
    }
    $trailingByteCount = $bytes.Length - $offset
    if ($trailingByteCount -ne 0) { $parserComplete = $false }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-pcapng-parse/v2'
        source_byte_count = [Int64]$snapshot.byte_count
        source_sha256 = [string]$snapshot.sha256
        source_immutable_read_lock_held =
            [bool]$snapshot.immutable_read_lock_held
        parser_complete = $parserComplete -and
            $blockErrorCount -eq 0 -and $idbOptionErrorCount -eq 0 -and
            $unknownInterfaceFrameCount -eq 0 -and
            $unsupportedLinkTypeFrameCount -eq 0 -and
            $unsupportedPacketBlockCount -eq 0 -and
            $truncatedFrameCount -eq 0 -and
            $parseNullFrameCount -eq 0 -and
            $nonAdjudicableFrameCount -eq 0 -and
            $trailingByteCount -eq 0 -and $sectionIndex -eq 0
        section_count = $sectionIndex + 1
        interface_count = $interfaceRecords.Count
        enhanced_packet_count = $enhancedPacketCount
        parsed_packet_count = $packets.Count
        trailing_byte_count = $trailingByteCount
        block_error_count = $blockErrorCount
        idb_option_error_count = $idbOptionErrorCount
        truncated_frame_count = $truncatedFrameCount
        unknown_interface_frame_count = $unknownInterfaceFrameCount
        unsupported_linktype_frame_count = $unsupportedLinkTypeFrameCount
        unsupported_packet_block_count = $unsupportedPacketBlockCount
        parse_null_frame_count = $parseNullFrameCount
        non_adjudicable_frame_count = $nonAdjudicableFrameCount
        interfaces = @($interfaceRecords.ToArray())
        packets = @($packets.ToArray())
    }
}

function Get-I04SynPidCorrelation {
    param(
        [Parameter(Mandatory = $true)][object]$Packet,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$SamplerRows,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)][double]$ToleranceMs
    )

    $tuple = Get-I04TupleKey -Family ([string]$Packet.family) `
        -LocalAddress ([string]$Packet.source) `
        -LocalPort ([int]$Packet.source_port) `
        -RemoteAddress ([string]$Packet.destination) `
        -RemotePort ([int]$Packet.destination_port)
    $packetEpochMs = [double]$Packet.timestamp_ms
    $matching = @($SamplerRows | Where-Object {
        [string]$_.tuple_key -eq $tuple -and
        [string]$_.state -in @('SynSent', 'Established') -and
        [Math]::Abs([double]$_.epoch_ms - $packetEpochMs) -le $ToleranceMs
    })
    $candidateMatches = @($matching | Where-Object {
        [int]$_.owning_process -eq $CandidateProcessId
    })
    $otherMatches = @($matching | Where-Object {
        [int]$_.owning_process -ne $CandidateProcessId
    })
    $nearestCandidate = if ($candidateMatches.Count -eq 0) {
        $null
    } else {
        @($candidateMatches | ForEach-Object {
            [Math]::Abs([double]$_.epoch_ms - $packetEpochMs)
        } | Measure-Object -Minimum).Minimum
    }
    $nearestOther = if ($otherMatches.Count -eq 0) {
        $null
    } else {
        @($otherMatches | ForEach-Object {
            [Math]::Abs([double]$_.epoch_ms - $packetEpochMs)
        } | Measure-Object -Minimum).Minimum
    }
    $candidateObserved = $candidateMatches.Count -gt 0
    $otherObserved = $otherMatches.Count -gt 0
    $status = if ($candidateObserved -and -not $otherObserved) {
        'candidate'
    } elseif ($candidateObserved -and $otherObserved) {
        'ambiguous-owner'
    } elseif ($otherObserved) {
        'foreign-owner'
    } else {
        'unobserved'
    }

    return [pscustomobject][ordered]@{
        packet_timestamp_ms = $packetEpochMs
        family = [string]$Packet.family
        tuple_key = $tuple
        tolerance_ms = $ToleranceMs
        status = $status
        candidate_process_id = $CandidateProcessId
        candidate_sample_count = $candidateMatches.Count
        other_pid_sample_count = $otherMatches.Count
        candidate_correlated = $status -eq 'candidate'
        correlation_ambiguous = $status -eq 'ambiguous-owner'
        nearest_candidate_sample_delta_ms = if ($null -eq
            $nearestCandidate) {
            $null
        } else { [Math]::Round([double]$nearestCandidate, 3) }
        nearest_other_pid_sample_delta_ms = if ($null -eq $nearestOther) {
            $null
        } else { [Math]::Round([double]$nearestOther, 3) }
        matching_process_ids = @(
            $matching | ForEach-Object { [int]$_.owning_process } |
                Sort-Object -Unique
        )
        candidate_matching_sample_epoch_ms = @(
            $candidateMatches | ForEach-Object { [double]$_.epoch_ms }
        )
        other_matching_samples = @($otherMatches | ForEach-Object {
            [pscustomobject][ordered]@{
                epoch_ms = [double]$_.epoch_ms
                owning_process = [int]$_.owning_process
                state = [string]$_.state
            }
        })
    }
}

function Get-I04CandidateBindingContract {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $required = @(
        'i04_owner_nonce', 'i04_owner_role', 'i04_owner_pid',
        'i04_owner_creation_utc_ticks',
        'i04_owner_cim_creation_utc_ticks', 'i04_owner_path_sha256',
        'i04_owner_executable_sha256', 'i04_owner_sid_sha256',
        'i04_ownership_id_sha256', 'i04_job_contract_id',
        'i04_job_active_process_limit', 'i04_job_assigned_before_resume',
        'i04_job_last_accounting'
    )
    $metadataPresent = @($required | Where-Object {
        $Process.PSObject.Properties.Name -notcontains $_
    }).Count -eq 0
    $metadataExact = $false
    $expectedPathSha256 = ''
    $expectedExeSha256 = ''
    if ($metadataPresent) {
        try {
            $expectedFullPath = Assert-I04NoReparsePath `
                -Path $ExpectedPath -Kind File
            $expectedPathSha256 = Get-I04StringSha256 `
                -Value $expectedFullPath.ToLowerInvariant()
            $expectedExeSha256 = Get-LabSha256 -Path $expectedFullPath
            $recomputedOwnershipId = Get-I04StringSha256 -Value (
                '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f
                    [string]$Process.i04_owner_nonce,
                    [string]$Process.i04_owner_role,
                    [int]$Process.i04_owner_pid,
                    [Int64]$Process.i04_owner_creation_utc_ticks,
                    [Int64]$Process.i04_owner_cim_creation_utc_ticks,
                    [string]$Process.i04_owner_path_sha256,
                    [string]$Process.i04_owner_executable_sha256,
                    [string]$Process.i04_owner_sid_sha256
            )
            $metadataExact =
                [string]$Process.i04_owner_nonce -ceq
                    $RunNonce.ToLowerInvariant() -and
                [string]$Process.i04_owner_role -ceq
                    'CoordinatorClient' -and
                [int]$Process.i04_owner_pid -eq [int]$Process.Id -and
                [Int64]$Process.i04_owner_creation_utc_ticks -gt 0 -and
                [Int64]$Process.i04_owner_cim_creation_utc_ticks -gt 0 -and
                [string]$Process.i04_owner_path_sha256 -ceq
                    $expectedPathSha256 -and
                [string]$Process.i04_owner_executable_sha256 -ceq
                    $expectedExeSha256 -and
                [string]$Process.i04_owner_sid_sha256 -ceq
                    [string]$script:i04HostIdentity.user_sid_sha256 -and
                [string]$Process.i04_ownership_id_sha256 -ceq
                    $recomputedOwnershipId -and
                [string]$Process.i04_job_contract_id -ceq
                    'ese.v91.i04-restricted-process-launcher/2026-08-01.v1' -and
                [int]$Process.i04_job_active_process_limit -eq 1 -and
                [bool]$Process.i04_job_assigned_before_resume
        } catch { $metadataExact = $false }
    }
    $exitStateCollectorOk = $false
    $hasExited = $null
    $liveBindingExact = $false
    $jobAccounting = $null
    $jobAccountingExact = $false
    try {
        $Process.Refresh()
        $hasExited = [bool]$Process.HasExited
        $exitStateCollectorOk = $true
        if (-not $hasExited -and $metadataExact) {
            $liveBindingExact = Test-I04OwnedProcessBinding `
                -Process $Process -ExpectedPath $ExpectedPath
        }
        if ($metadataExact) {
            $jobAccounting = Get-I04RestrictedJobAccounting `
                -ProcessId ([int]$Process.Id)
            $Process.i04_job_last_accounting = $jobAccounting
            $jobAccountingExact =
                Assert-I04RestrictedJobAccountingContract `
                    -Accounting $jobAccounting `
                    -ExpectedProcessId ([int]$Process.Id) `
                    -ExpectedActiveProcesses $(if ($hasExited) { 0 } else { 1 })
        }
    } catch {
        $exitStateCollectorOk = $false
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-candidate-binding/v1'
        pid = [int]$Process.Id
        creation_utc_ticks = if ($metadataPresent) {
            [Int64]$Process.i04_owner_creation_utc_ticks
        } else { 0L }
        cim_creation_utc_ticks = if ($metadataPresent) {
            [Int64]$Process.i04_owner_cim_creation_utc_ticks
        } else { 0L }
        ownership_id_sha256 = if ($metadataPresent) {
            [string]$Process.i04_ownership_id_sha256
        } else { '' }
        executable_sha256 = if ($metadataPresent) {
            [string]$Process.i04_owner_executable_sha256
        } else { '' }
        expected_executable_sha256 = $expectedExeSha256
        user_sid_sha256 = if ($metadataPresent) {
            [string]$Process.i04_owner_sid_sha256
        } else { '' }
        metadata_present = $metadataPresent
        exact = $metadataExact -and $jobAccountingExact
        exit_state_collector_ok = $exitStateCollectorOk
        has_exited = $hasExited
        current_live_binding_exact = $liveBindingExact
        restricted_job_contract_id = if ($metadataPresent) {
            [string]$Process.i04_job_contract_id
        } else { '' }
        restricted_job_active_process_limit = if ($metadataPresent) {
            [int]$Process.i04_job_active_process_limit
        } else { 0 }
        restricted_job_assigned_before_resume = $metadataPresent -and
            [bool]$Process.i04_job_assigned_before_resume
        restricted_job_accounting = $jobAccounting
        restricted_job_accounting_exact = $jobAccountingExact
    }
}

function Get-I04WebEndpointOwnershipEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId
    )

    try {
        $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen `
            -ErrorAction Stop | Where-Object {
                [string]$_.LocalAddress -in @(
                    '127.0.0.1', '::1', '0.0.0.0', '::'
                )
            })
        $ownerPids = @($listeners | ForEach-Object {
            [int]$_.OwningProcess
        } | Sort-Object -Unique)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-web-endpoint-ownership/v1'
            collector_ok = $true
            endpoint = "loopback-or-wildcard:$Port"
            listener_count = $listeners.Count
            owner_process_ids = $ownerPids
            endpoint_owner_pid = if ($ownerPids.Count -eq 1) {
                [int]$ownerPids[0]
            } else { $null }
            endpoint_bound_to_candidate = $listeners.Count -gt 0 -and
                $ownerPids.Count -eq 1 -and
                [int]$ownerPids[0] -eq $CandidateProcessId
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-web-endpoint-ownership/v1'
            collector_ok = $false
            endpoint = "loopback-or-wildcard:$Port"
            listener_count = 0
            owner_process_ids = @()
            endpoint_owner_pid = $null
            endpoint_bound_to_candidate = $false
            error_sha256 = Get-I04StringSha256 -Value $_.Exception.Message
        }
    }
}

function Test-I04PacketFailureSourceContract {
    param(
        [AllowNull()][object]$Evidence,
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId,
        [Parameter(Mandatory = $true)][double]$ExpectedBoundaryEpochMs
    )

    try {
        return ($null -ne $Evidence -and
            $Evidence.schema -is [string] -and
            [string]$Evidence.schema -ceq
                'ese.v91.i04-packet-verdict/v2' -and
            $Evidence.candidate_process_id -is [int] -and
            [int]$Evidence.candidate_process_id -eq $ExpectedProcessId -and
            $Evidence.pcapng_source_byte_count -is [Int64] -and
            [Int64]$Evidence.pcapng_source_byte_count -gt 0 -and
            $Evidence.pcapng_source_sha256 -is [string] -and
            [string]$Evidence.pcapng_source_sha256 -cmatch
                '^[0-9a-f]{64}$' -and
            $Evidence.pcapng_source_immutable_read_lock_held -is [bool] -and
            [bool]$Evidence.pcapng_source_immutable_read_lock_held -and
            $Evidence.pcapng_parser_complete -is [bool] -and
            [bool]$Evidence.pcapng_parser_complete -and
            $Evidence.capture_interface_binding_exact -is [bool] -and
            [bool]$Evidence.capture_interface_binding_exact -and
            $Evidence.target_frames_on_expected_physical_nic -is [bool] -and
            [bool]$Evidence.target_frames_on_expected_physical_nic -and
            $Evidence.coordinator_stop_a_boundary_epoch_ms -is [double] -and
            [double]$Evidence.coordinator_stop_a_boundary_epoch_ms -eq
                $ExpectedBoundaryEpochMs)
    } catch { return $false }
}

function Test-I04SocketFailureSourceContract {
    param(
        [AllowNull()][object]$Evidence,
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId,
        [Parameter(Mandatory = $true)][double]$ExpectedBoundaryEpochMs
    )

    try {
        $clock = $Evidence.clock_validation
        return ($null -ne $Evidence -and
            $Evidence.schema -is [string] -and
            [string]$Evidence.schema -ceq
                'ese.v91.i04-pid-socket-sampler/v1' -and
            $Evidence.candidate_process_id -is [int] -and
            [int]$Evidence.candidate_process_id -eq $ExpectedProcessId -and
            $Evidence.source_byte_count -is [Int64] -and
            [Int64]$Evidence.source_byte_count -gt 0 -and
            $Evidence.source_sha256 -is [string] -and
            [string]$Evidence.source_sha256 -cmatch '^[0-9a-f]{64}$' -and
            $Evidence.source_immutable_read_lock_held -is [bool] -and
            [bool]$Evidence.source_immutable_read_lock_held -and
            $Evidence.boundary_epoch_ms -is [double] -and
            [double]$Evidence.boundary_epoch_ms -eq
                $ExpectedBoundaryEpochMs -and
            $Evidence.boundary_qpc -is [Int64] -and
            [Int64]$Evidence.boundary_qpc -gt 0 -and
            $Evidence.qpc_frequency -is [Int64] -and
            [Int64]$Evidence.qpc_frequency -eq
                [Int64][Diagnostics.Stopwatch]::Frequency -and
            $Evidence.clock_coherence_valid -is [bool] -and
            [bool]$Evidence.clock_coherence_valid -and
            $Evidence.sample_count -is [int] -and
            [int]$Evidence.sample_count -ge 2 -and
            $Evidence.parse_error_count -is [int] -and
            [int]$Evidence.parse_error_count -eq 0 -and
            $Evidence.sampler_coverage_valid -is [bool] -and
            [bool]$Evidence.sampler_coverage_valid -and
            $null -ne $clock -and
            $clock.valid -is [bool] -and [bool]$clock.valid -and
            $clock.sample_count -is [int] -and
            [int]$clock.sample_count -eq [int]$Evidence.sample_count -and
            $clock.boundary_epoch_ms -is [double] -and
            [double]$clock.boundary_epoch_ms -eq
                [double]$Evidence.boundary_epoch_ms -and
            $clock.boundary_qpc -is [Int64] -and
            [Int64]$clock.boundary_qpc -eq [Int64]$Evidence.boundary_qpc -and
            $clock.qpc_frequency -is [Int64] -and
            [Int64]$clock.qpc_frequency -eq [Int64]$Evidence.qpc_frequency)
    } catch { return $false }
}

function New-I04ProductFailure {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'process_exit', 'classic_web_timeout', 'api_unavailable',
            'api_contract_invalid', 'ipv6_syn_missing',
            'fallback_window', 'ipv4_connectivity',
            'transport_attempt_count', 'product_log_contract',
            'transfer_contract', 'observation_window', 'socket_contract',
            'telemetry_contract', 'api_liveness', 'ui_liveness'
        )][string]$FailureType,
        [Parameter(Mandatory = $true)][string]$DisplayMessage,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][double]$BoundaryEpochMs,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'process_handle', 'classic_web_request', 'api_probe',
            'packet_verdict', 'product_log_counts', 'transfer_snapshot',
            'socket_sampler', 'telemetry_snapshot', 'ui_probe'
        )][string]$SourceKind,
        [AllowNull()][object]$SourceEvidence = $null,
        [bool]$SourceCollectorOk = $true,
        [switch]$RequireWebEndpoint,
        [switch]$RequireExitedProcess,
        [switch]$RequireLiveProcess
    )

    $observedEpochMs = Get-I04EpochMilliseconds `
        -Timestamp ([DateTimeOffset]::UtcNow)
    $binding = Get-I04CandidateBindingContract -Process $Process `
        -ExpectedPath $ExpectedPath
    $endpoint = if ($RequireWebEndpoint) {
        Get-I04WebEndpointOwnershipEvidence -Port $ClientWebPort `
            -CandidateProcessId ([int]$Process.Id)
    } else { $null }
    $sourceJson = if ($null -eq $SourceEvidence) {
        ''
    } else {
        $SourceEvidence | ConvertTo-Json -Compress -Depth 32
    }
    $sourceError = if ($null -eq $SourceEvidence) {
        ''
    } elseif ($SourceEvidence.PSObject.Properties.Name -contains 'error' -and
        $SourceEvidence.error) {
        [string]$SourceEvidence.error
    } elseif ($SourceEvidence.PSObject.Properties.Name -contains
        'request_error' -and $SourceEvidence.request_error) {
        [string]$SourceEvidence.request_error
    } else { '' }
    $sourceProperties = if ($null -eq $SourceEvidence) { @() } else {
        @($SourceEvidence.PSObject.Properties.Name)
    }
    $sourceEvidenceContractValid = switch ($SourceKind) {
        'process_handle' {
            [bool]$RequireExitedProcess
            break
        }
        'classic_web_request' {
            $null -ne $SourceEvidence -and
                'operation' -in $sourceProperties -and
                [string]$SourceEvidence.operation -ceq 'stop' -and
                'request_completed' -in $sourceProperties -and
                $SourceEvidence.request_completed -is [bool] -and
                -not [bool]$SourceEvidence.request_completed
            break
        }
        'api_probe' {
            $null -ne $SourceEvidence -and
                'available' -in $sourceProperties -and
                $SourceEvidence.available -is [bool]
            break
        }
        'packet_verdict' {
            Test-I04PacketFailureSourceContract `
                -Evidence $SourceEvidence `
                -ExpectedProcessId ([int]$Process.Id) `
                -ExpectedBoundaryEpochMs $BoundaryEpochMs
            break
        }
        'product_log_counts' {
            $null -ne $SourceEvidence -and
                [string]$SourceEvidence.schema -ceq
                    'ese.v91.i04-product-log-delta-evidence/v1' -and
                [string]$SourceEvidence.candidate_ownership_id_sha256 -ceq
                    [string]$Process.i04_ownership_id_sha256 -and
                $SourceEvidence.collector_ok -is [bool] -and
                [bool]$SourceEvidence.collector_ok -and
                $SourceEvidence.adjudicable -is [bool] -and
                [bool]$SourceEvidence.adjudicable -and
                $null -ne $SourceEvidence.before -and
                $null -ne $SourceEvidence.after -and
                [string]$SourceEvidence.before.schema -ceq
                    'ese.v91.i04-product-log-counts/v2' -and
                [string]$SourceEvidence.after.schema -ceq
                    'ese.v91.i04-product-log-counts/v2' -and
                [bool]$SourceEvidence.before.collector_ok -and
                [bool]$SourceEvidence.after.collector_ok -and
                [bool]$SourceEvidence.before.adjudicable -and
                [bool]$SourceEvidence.after.adjudicable -and
                $SourceEvidence.fallback_delta -is [ValueType] -and
                -not ($SourceEvidence.fallback_delta -is [bool]) -and
                $SourceEvidence.bounded_fallback_delta -is [ValueType] -and
                -not ($SourceEvidence.bounded_fallback_delta -is [bool]) -and
                $SourceEvidence.hello_send_delta -is [ValueType] -and
                -not ($SourceEvidence.hello_send_delta -is [bool]) -and
                $SourceEvidence.hello_answer_receive_delta -is
                    [ValueType] -and
                -not ($SourceEvidence.hello_answer_receive_delta -is
                    [bool]) -and
                $SourceEvidence.a4af_swap_a_to_b_delta -is [ValueType] -and
                -not ($SourceEvidence.a4af_swap_a_to_b_delta -is [bool]) -and
                [int]$SourceEvidence.fallback_delta -eq (
                    [int]$SourceEvidence.after.fallback_count -
                    [int]$SourceEvidence.before.fallback_count) -and
                [int]$SourceEvidence.bounded_fallback_delta -eq (
                    [int]$SourceEvidence.after.bounded_fallback_count -
                    [int]$SourceEvidence.before.bounded_fallback_count) -and
                [int]$SourceEvidence.hello_send_delta -eq (
                    [int]$SourceEvidence.after.hello_send_count -
                    [int]$SourceEvidence.before.hello_send_count) -and
                [int]$SourceEvidence.hello_answer_receive_delta -eq (
                    [int]$SourceEvidence.after.hello_answer_receive_count -
                    [int]$SourceEvidence.before.hello_answer_receive_count) -and
                [int]$SourceEvidence.a4af_swap_a_to_b_delta -eq (
                    [int]$SourceEvidence.after.a4af_swap_a_to_b_count -
                    [int]$SourceEvidence.before.a4af_swap_a_to_b_count)
            break
        }
        'transfer_snapshot' {
            $null -ne $SourceEvidence -and
                'found' -in $sourceProperties -and
                $SourceEvidence.found -is [bool] -and
                'file_hash' -in $sourceProperties -and
                [string]$SourceEvidence.file_hash -match
                    '^[0-9A-F]{32}$'
            break
        }
        'socket_sampler' {
            Test-I04SocketFailureSourceContract `
                -Evidence $SourceEvidence `
                -ExpectedProcessId ([int]$Process.Id) `
                -ExpectedBoundaryEpochMs $BoundaryEpochMs
            break
        }
        'telemetry_snapshot' {
            $null -ne $SourceEvidence -and
                [string]$SourceEvidence.schema -ceq
                    'ese.v91.i04-telemetry-delta-evidence/v1' -and
                [string]$SourceEvidence.candidate_ownership_id_sha256 -ceq
                    [string]$Process.i04_ownership_id_sha256 -and
                $SourceEvidence.collector_ok -is [bool] -and
                [bool]$SourceEvidence.collector_ok -and
                $SourceEvidence.adjudicable -is [bool] -and
                [bool]$SourceEvidence.adjudicable -and
                $null -ne $SourceEvidence.baseline -and
                $null -ne $SourceEvidence.final -and
                $SourceEvidence.baseline.available -is [bool] -and
                [bool]$SourceEvidence.baseline.available -and
                $SourceEvidence.final.available -is [bool] -and
                [bool]$SourceEvidence.final.available -and
                $SourceEvidence.adds_delta -is [ValueType] -and
                -not ($SourceEvidence.adds_delta -is [bool]) -and
                $SourceEvidence.duplicate_adds_delta -is [ValueType] -and
                -not ($SourceEvidence.duplicate_adds_delta -is [bool]) -and
                $SourceEvidence.observed_current_max -is [ValueType] -and
                -not ($SourceEvidence.observed_current_max -is [bool]) -and
                $SourceEvidence.observed_adds_max -is [ValueType] -and
                -not ($SourceEvidence.observed_adds_max -is [bool]) -and
                $SourceEvidence.observed_duplicate_adds_max -is
                    [ValueType] -and
                -not ($SourceEvidence.observed_duplicate_adds_max -is
                    [bool]) -and
                $SourceEvidence.observed_high_water_max -is [ValueType] -and
                -not ($SourceEvidence.observed_high_water_max -is [bool]) -and
                [Int64]$SourceEvidence.adds_delta -eq (
                    [Int64]$SourceEvidence.final.connecting_client_adds -
                    [Int64]$SourceEvidence.baseline.connecting_client_adds) -and
                [Int64]$SourceEvidence.duplicate_adds_delta -eq (
                    [Int64]$SourceEvidence.final.
                        connecting_client_duplicate_adds -
                    [Int64]$SourceEvidence.baseline.
                        connecting_client_duplicate_adds)
            break
        }
        'ui_probe' {
            $null -ne $SourceEvidence -and
                'process_id' -in $sourceProperties -and
                [int]$SourceEvidence.process_id -eq [int]$Process.Id -and
                'main_window_present' -in $sourceProperties -and
                $SourceEvidence.main_window_present -is [bool] -and
                'message_pump_responsive' -in $sourceProperties -and
                $SourceEvidence.message_pump_responsive -is [bool]
            break
        }
    }
    $sourceBound = [bool]$binding.exact -and
        [bool]$sourceEvidenceContractValid
    if ($RequireExitedProcess) {
        $sourceBound = $sourceBound -and
            [bool]$binding.exit_state_collector_ok -and
            $binding.has_exited -is [bool] -and [bool]$binding.has_exited
    }
    if ($RequireLiveProcess) {
        $sourceBound = $sourceBound -and
            [bool]$binding.exit_state_collector_ok -and
            $binding.has_exited -is [bool] -and
            -not [bool]$binding.has_exited -and
            [bool]$binding.current_live_binding_exact
    }
    if ($RequireWebEndpoint) {
        $sourceBound = $sourceBound -and
            [bool]$binding.exit_state_collector_ok -and
            $binding.has_exited -is [bool] -and
            -not [bool]$binding.has_exited -and
            [bool]$binding.current_live_binding_exact -and
            [bool]$endpoint.collector_ok -and
            [bool]$endpoint.endpoint_bound_to_candidate
    }
    $postBoundary = $BoundaryEpochMs -gt 0 -and
        $observedEpochMs -ge $BoundaryEpochMs
    $collectorOk = $SourceCollectorOk -and
        [bool]$sourceEvidenceContractValid -and (
        -not $RequireWebEndpoint -or [bool]$endpoint.collector_ok
    )
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-product-failure/v1'
        failure_type = $FailureType
        display_message = $DisplayMessage
        observed_at_epoch_ms = [double]$observedEpochMs
        boundary_epoch_ms = [double]$BoundaryEpochMs
        post_boundary = $postBoundary
        case_id = $caseId
        run_nonce = $RunNonce.ToLowerInvariant()
        candidate_binding = $binding
        source = [pscustomobject][ordered]@{
            kind = $SourceKind
            collector_ok = [bool]$collectorOk
            evidence_contract_valid =
                [bool]$sourceEvidenceContractValid
            endpoint = if ($null -eq $endpoint) { '' } else {
                [string]$endpoint.endpoint
            }
            endpoint_owner_pid = if ($null -eq $endpoint) {
                $null
            } else { $endpoint.endpoint_owner_pid }
            endpoint_bound_to_candidate = $null -ne $endpoint -and
                [bool]$endpoint.endpoint_bound_to_candidate
            evidence_sha256 = if ($sourceJson) {
                Get-I04StringSha256 -Value $sourceJson
            } else { '' }
            # Retain the exact private evidence whose digest is published.
            # The public projection deliberately omits this field.
            evidence = $SourceEvidence
            error_fingerprint_sha256 = if ($sourceError) {
                Get-I04StringSha256 -Value $sourceError
            } else { '' }
        }
        source_bound = [bool]$sourceBound
        adjudicable = [bool]$collectorOk -and [bool]$sourceBound -and
            $postBoundary
    }
}

function Assert-I04ProductFailureContract {
    param([Parameter(Mandatory = $true)][object]$Failure)

    $failureTypes = @(
        'process_exit', 'classic_web_timeout', 'api_unavailable',
        'api_contract_invalid', 'ipv6_syn_missing', 'fallback_window',
        'ipv4_connectivity', 'transport_attempt_count',
        'product_log_contract', 'transfer_contract', 'observation_window',
        'socket_contract', 'telemetry_contract', 'api_liveness',
        'ui_liveness'
    )
    $sourceKinds = @(
        'process_handle', 'classic_web_request', 'api_probe',
        'packet_verdict', 'product_log_counts', 'transfer_snapshot',
        'socket_sampler', 'telemetry_snapshot', 'ui_probe'
    )
    $observedValue = $Failure.observed_at_epoch_ms
    $boundaryValue = $Failure.boundary_epoch_ms
    $observedFinite = $observedValue -is [ValueType] -and
        -not ($observedValue -is [bool]) -and
        -not [double]::IsNaN([double]$observedValue) -and
        -not [double]::IsInfinity([double]$observedValue)
    $boundaryFinite = $boundaryValue -is [ValueType] -and
        -not ($boundaryValue -is [bool]) -and
        -not [double]::IsNaN([double]$boundaryValue) -and
        -not [double]::IsInfinity([double]$boundaryValue)
    $expectedPostBoundary = $observedFinite -and $boundaryFinite -and
        [double]$boundaryValue -gt 0 -and
        [double]$observedValue -ge [double]$boundaryValue
    $sourceEvidenceJson = if ($null -eq $Failure.source.evidence) {
        ''
    } else {
        $Failure.source.evidence | ConvertTo-Json -Compress -Depth 32
    }
    $sourceEvidenceHashExact = if ($sourceEvidenceJson) {
        [string]$Failure.source.evidence_sha256 -match '^[0-9a-f]{64}$' -and
            [string]$Failure.source.evidence_sha256 -ceq
                (Get-I04StringSha256 -Value $sourceEvidenceJson)
    } else {
        [string]$Failure.source.kind -ceq 'process_handle' -and
            [string]$Failure.source.evidence_sha256 -ceq ''
    }
    $expectedSourceKinds = @(switch ([string]$Failure.failure_type) {
        'process_exit' { 'process_handle' }
        'classic_web_timeout' { 'classic_web_request' }
        { $_ -in @('api_unavailable', 'api_contract_invalid',
                'api_liveness') } { 'api_probe' }
        { $_ -in @('ipv6_syn_missing', 'fallback_window',
                'ipv4_connectivity', 'transport_attempt_count',
                'observation_window') } { 'packet_verdict' }
        'product_log_contract' { 'product_log_counts' }
        'transfer_contract' { 'transfer_snapshot' }
        'socket_contract' { 'socket_sampler' }
        'telemetry_contract' { 'telemetry_snapshot' }
        'ui_liveness' { 'ui_probe' }
    })
    $failureSourceKindExact = $expectedSourceKinds.Count -eq 1 -and
        [string]$Failure.source.kind -ceq [string]$expectedSourceKinds[0]
    $evidence = $Failure.source.evidence
    $evidenceProperties = if ($null -eq $evidence) { @() } else {
        @($evidence.PSObject.Properties.Name)
    }
    $sourceEvidenceRevalidated = switch ([string]$Failure.source.kind) {
        'process_handle' {
            $Failure.candidate_binding.exit_state_collector_ok -is [bool] -and
                [bool]$Failure.candidate_binding.exit_state_collector_ok -and
                $Failure.candidate_binding.has_exited -is [bool] -and
                [bool]$Failure.candidate_binding.has_exited
            break
        }
        'classic_web_request' {
            $null -ne $evidence -and 'operation' -in $evidenceProperties -and
                [string]$evidence.operation -ceq 'stop' -and
                'request_completed' -in $evidenceProperties -and
                $evidence.request_completed -is [bool] -and
                -not [bool]$evidence.request_completed
            break
        }
        'api_probe' {
            $null -ne $evidence -and 'available' -in $evidenceProperties -and
                $evidence.available -is [bool]
            break
        }
        'packet_verdict' {
            Test-I04PacketFailureSourceContract `
                -Evidence $evidence `
                -ExpectedProcessId ([int]$Failure.candidate_binding.pid) `
                -ExpectedBoundaryEpochMs $boundaryValue
            break
        }
        'product_log_counts' {
            $null -ne $evidence -and [string]$evidence.schema -ceq
                'ese.v91.i04-product-log-delta-evidence/v1' -and
                [string]$evidence.candidate_ownership_id_sha256 -ceq
                    [string]$Failure.candidate_binding.ownership_id_sha256 -and
                $evidence.collector_ok -is [bool] -and
                [bool]$evidence.collector_ok -and
                $evidence.adjudicable -is [bool] -and
                [bool]$evidence.adjudicable -and
                $null -ne $evidence.before -and $null -ne $evidence.after -and
                [string]$evidence.before.schema -ceq
                    'ese.v91.i04-product-log-counts/v2' -and
                [string]$evidence.after.schema -ceq
                    'ese.v91.i04-product-log-counts/v2' -and
                [int]$evidence.fallback_delta -eq
                    ([int]$evidence.after.fallback_count -
                     [int]$evidence.before.fallback_count) -and
                [int]$evidence.bounded_fallback_delta -eq
                    ([int]$evidence.after.bounded_fallback_count -
                     [int]$evidence.before.bounded_fallback_count) -and
                [int]$evidence.hello_send_delta -eq
                    ([int]$evidence.after.hello_send_count -
                     [int]$evidence.before.hello_send_count) -and
                [int]$evidence.hello_answer_receive_delta -eq
                    ([int]$evidence.after.hello_answer_receive_count -
                     [int]$evidence.before.hello_answer_receive_count) -and
                [int]$evidence.a4af_swap_a_to_b_delta -eq
                    ([int]$evidence.after.a4af_swap_a_to_b_count -
                     [int]$evidence.before.a4af_swap_a_to_b_count)
            break
        }
        'transfer_snapshot' {
            $null -ne $evidence -and 'found' -in $evidenceProperties -and
                $evidence.found -is [bool] -and
                'file_hash' -in $evidenceProperties -and
                [string]$evidence.file_hash -match '^[0-9A-F]{32}$'
            break
        }
        'socket_sampler' {
            Test-I04SocketFailureSourceContract `
                -Evidence $evidence `
                -ExpectedProcessId ([int]$Failure.candidate_binding.pid) `
                -ExpectedBoundaryEpochMs $boundaryValue
            break
        }
        'telemetry_snapshot' {
            $null -ne $evidence -and [string]$evidence.schema -ceq
                'ese.v91.i04-telemetry-delta-evidence/v1' -and
                [string]$evidence.candidate_ownership_id_sha256 -ceq
                    [string]$Failure.candidate_binding.ownership_id_sha256 -and
                $evidence.collector_ok -is [bool] -and
                [bool]$evidence.collector_ok -and
                $evidence.adjudicable -is [bool] -and
                [bool]$evidence.adjudicable -and
                $null -ne $evidence.baseline -and $null -ne $evidence.final -and
                [Int64]$evidence.adds_delta -eq
                    ([Int64]$evidence.final.connecting_client_adds -
                     [Int64]$evidence.baseline.connecting_client_adds) -and
                [Int64]$evidence.duplicate_adds_delta -eq
                    ([Int64]$evidence.final.connecting_client_duplicate_adds -
                     [Int64]$evidence.baseline.connecting_client_duplicate_adds)
            break
        }
        'ui_probe' {
            $null -ne $evidence -and 'process_id' -in $evidenceProperties -and
                $evidence.process_id -is [ValueType] -and
                -not ($evidence.process_id -is [bool]) -and
                [int]$evidence.process_id -eq
                    [int]$Failure.candidate_binding.pid -and
                'main_window_present' -in $evidenceProperties -and
                $evidence.main_window_present -is [bool] -and
                'message_pump_responsive' -in $evidenceProperties -and
                $evidence.message_pump_responsive -is [bool]
            break
        }
        default { $false }
    }
    $candidateExitedExact =
        $Failure.candidate_binding.exit_state_collector_ok -is [bool] -and
        [bool]$Failure.candidate_binding.exit_state_collector_ok -and
        $Failure.candidate_binding.has_exited -is [bool]
    $expectedJobActiveProcesses = if ($candidateExitedExact -and
        [bool]$Failure.candidate_binding.has_exited) { 0 } else { 1 }
    $jobAccountingRevalidated = $false
    try {
        $jobAccountingRevalidated =
            Assert-I04RestrictedJobAccountingContract `
                -Accounting (
                    $Failure.candidate_binding.restricted_job_accounting) `
                -ExpectedProcessId ([int]$Failure.candidate_binding.pid) `
                -ExpectedActiveProcesses $expectedJobActiveProcesses
    } catch { $jobAccountingRevalidated = $false }
    if ([string]$Failure.schema -cne
            'ese.v91.i04-product-failure/v1' -or
        [string]$Failure.failure_type -notin $failureTypes -or
        -not ($Failure.display_message -is [string]) -or
        -not $observedFinite -or -not $boundaryFinite -or
        -not ($Failure.post_boundary -is [bool]) -or
        [bool]$Failure.post_boundary -ne $expectedPostBoundary -or
        [string]$Failure.case_id -cne $caseId -or
        [string]$Failure.run_nonce -cne $RunNonce.ToLowerInvariant() -or
        [string]$Failure.candidate_binding.schema -cne
            'ese.v91.i04-candidate-binding/v1' -or
        -not ($Failure.candidate_binding.pid -is [int]) -or
        -not ($Failure.candidate_binding.exact -is [bool]) -or
        -not [bool]$Failure.candidate_binding.exact -or
        [string]$Failure.candidate_binding.ownership_id_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$Failure.candidate_binding.executable_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$Failure.candidate_binding.user_sid_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$Failure.candidate_binding.restricted_job_contract_id -cne
            'ese.v91.i04-restricted-process-launcher/2026-08-01.v1' -or
        -not ($Failure.candidate_binding.restricted_job_active_process_limit `
            -is [int]) -or
        [int]$Failure.candidate_binding.
            restricted_job_active_process_limit -ne 1 -or
        -not ($Failure.candidate_binding.restricted_job_assigned_before_resume `
            -is [bool]) -or
        -not [bool]$Failure.candidate_binding.
            restricted_job_assigned_before_resume -or
        -not ($Failure.candidate_binding.restricted_job_accounting_exact `
            -is [bool]) -or
        -not [bool]$Failure.candidate_binding.
            restricted_job_accounting_exact -or
        -not $candidateExitedExact -or
        ([bool]$Failure.candidate_binding.has_exited -and
            [string]$Failure.failure_type -cne 'process_exit') -or
        (-not [bool]$Failure.candidate_binding.has_exited -and
            (-not ($Failure.candidate_binding.current_live_binding_exact `
                -is [bool]) -or
             -not [bool]$Failure.candidate_binding.current_live_binding_exact)) `
            -or
        -not [bool]$jobAccountingRevalidated -or
        [string]$Failure.source.kind -notin $sourceKinds -or
        -not $failureSourceKindExact -or
        -not [bool]$sourceEvidenceRevalidated -or
        -not ($Failure.source.collector_ok -is [bool]) -or
        -not ($Failure.source.evidence_contract_valid -is [bool]) -or
        -not [bool]$Failure.source.evidence_contract_valid -or
        -not $sourceEvidenceHashExact -or
        -not ($Failure.source.endpoint_bound_to_candidate -is [bool]) -or
        -not ($Failure.source_bound -is [bool]) -or
        -not [bool]$Failure.source_bound -or
        ([string]$Failure.source.kind -in @(
            'classic_web_request', 'api_probe'
        ) -and -not [bool]$Failure.source.endpoint_bound_to_candidate) -or
        -not ($Failure.adjudicable -is [bool]) -or
        [bool]$Failure.adjudicable -ne (
            [bool]$Failure.post_boundary -and
            [bool]$Failure.source_bound -and
            [bool]$Failure.source.collector_ok
        )) {
        throw 'Product failure does not satisfy the exact typed v1 contract'
    }
    return $true
}

function Add-I04TypedProductFailure {
    param(
        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[object]]$Failures,
        [Parameter(Mandatory = $true)][string]$FailureType,
        [Parameter(Mandatory = $true)][string]$DisplayMessage,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][double]$BoundaryEpochMs,
        [Parameter(Mandatory = $true)][string]$SourceKind,
        [AllowNull()][object]$SourceEvidence = $null
    )

    $failure = New-I04ProductFailure -FailureType $FailureType `
        -DisplayMessage $DisplayMessage -Process $Process `
        -ExpectedPath $ExpectedPath -BoundaryEpochMs $BoundaryEpochMs `
        -SourceKind $SourceKind -SourceEvidence $SourceEvidence
    $null = Assert-I04ProductFailureContract -Failure $failure
    if (-not [bool]$failure.source_bound -or
        -not [bool]$failure.adjudicable) {
        throw 'Typed product failure was not source-bound/adjudicable'
    }
    $Failures.Add($failure)
}

function Assert-I04ProjectionPropertySet {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Allowed,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $actual = @($Object.PSObject.Properties.Name)
    $missing = @($Allowed | Where-Object { $_ -notin $actual })
    $extra = @($actual | Where-Object { $_ -notin $Allowed })
    if ($missing.Count -ne 0 -or $extra.Count -ne 0) {
        throw "$Context public projection property set is not exact"
    }
    return $true
}

function Get-I04PublicSummaryProjection {
    param(
        [Parameter(Mandatory = $true)][object]$Summary,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$SourceSummarySha256
    )

    # This projection is constructed exclusively from this explicit list.
    # It intentionally omits host/user IDs, PIDs, ownership IDs, IPs, ports,
    # adapter names/IDs, routes, paths, log names, raw errors and evidence.
    $projection = [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-public-summary/v1'
        projection_policy = 'explicit-allowlist-v1'
        source_summary_sha256 = $SourceSummarySha256.ToLowerInvariant()
        case_id = [string]$Summary.case_id
        formal_status = [string]$Summary.formal_status
        partial_verdict = [string]$Summary.partial_verdict
        formal_v91_i04_eligible =
            [bool]$Summary.formal_v91_i04_eligible
        candidate = [pscustomobject][ordered]@{
            commit = [string]$Summary.candidate.commit
            version = [string]$Summary.candidate.version
            executable_sha256 =
                [string]$Summary.candidate.expected_emule_sha256
            package_zip_sha256 =
                [string]$Summary.candidate.package_zip_sha256
            package_manifest_sha256 =
                [string]$Summary.candidate.package_manifest_sha256
            unchanged = [bool]$Summary.candidate.unchanged
        }
        adjudication = [pscustomobject][ordered]@{
            fixture_proof_complete =
                [bool]$Summary.adjudication.fixture_proof_complete
            product_failure_proved =
                [bool]$Summary.adjudication.product_failure_proved
            product_failures_typed_and_source_bound =
                [bool]$Summary.adjudication.
                    product_failures_typed_and_source_bound
            proof_contradicted =
                [bool]$Summary.adjudication.proof_contradicted
            cleanup_complete =
                [bool]$Summary.adjudication.cleanup_complete
        }
        topology = [pscustomobject][ordered]@{
            required = [string]$Summary.topology.required
            observed = [string]$Summary.topology.observed_topology
            proved = [bool]$Summary.topology.proved
            distinct_physical_hosts =
                [bool]$Summary.topology.distinct_physical_hosts
            native_global_ipv6 =
                [bool]$Summary.topology.native_global_ipv6
            physical_adapters_and_sockets =
                [bool]$Summary.topology.physical_adapters_and_sockets
            overlay_vpn_proxy_absent =
                [bool]$Summary.topology.overlay_vpn_proxy_absent
        }
        proof = [pscustomobject][ordered]@{
            logs_adjudicable =
                [bool]$Summary.fixture.trigger_runtime_valid -and
                $null -ne $Summary.single_retry.fallback_log_delta
            pcapng_parser_complete = $null -ne
                $Summary.timing.packet_verdict -and
                [bool]$Summary.timing.packet_verdict.
                    pcapng_parser_complete
            capture_interface_binding_exact = $null -ne
                $Summary.timing.packet_verdict -and
                [bool]$Summary.timing.packet_verdict.
                    capture_interface_binding_exact
            target_frames_on_expected_physical_nic = $null -ne
                $Summary.timing.packet_verdict -and
                [bool]$Summary.timing.packet_verdict.
                    target_frames_on_expected_physical_nic
            packet_capture_zero_loss =
                [bool]$Summary.fixture.packet_capture_zero_loss
            packet_capture_below_circular_limit =
                [bool]$Summary.fixture.packet_capture_below_circular_limit
            socket_sampler_coverage_valid = $null -ne
                $Summary.fixture.socket_sampler -and
                [bool]$Summary.fixture.socket_sampler.
                    sampler_coverage_valid
        }
        measurements = [pscustomobject][ordered]@{
            fallback_log_delta = $Summary.single_retry.fallback_log_delta
            bounded_fallback_log_delta =
                $Summary.single_retry.bounded_fallback_log_delta
            hello_send_delta = $Summary.single_retry.hello_send_delta
            hello_answer_receive_delta =
                $Summary.single_retry.hello_answer_receive_delta
            a4af_swap_a_to_b_delta =
                $Summary.single_retry.a4af_swap_a_to_b_delta
            ipv6_syn_count = if ($null -eq
                $Summary.timing.packet_verdict) { $null } else {
                [int]$Summary.timing.packet_verdict.ipv6_syn_count
            }
            ipv4_syn_count = if ($null -eq
                $Summary.timing.packet_verdict) { $null } else {
                [int]$Summary.timing.packet_verdict.ipv4_syn_count
            }
            syn6_to_syn4_ms = if ($null -eq
                $Summary.timing.packet_verdict) { $null } else {
                $Summary.timing.packet_verdict.syn6_to_syn4_ms
            }
            syn6_to_ipv4_connected_ms = if ($null -eq
                $Summary.timing.packet_verdict) { $null } else {
                $Summary.timing.packet_verdict.syn6_to_ipv4_connected_ms
            }
            api_probe_count = [int]$Summary.liveness.api_probe_count
            api_failure_count = [int]$Summary.liveness.api_failure_count
            ui_probe_count = [int]$Summary.liveness.ui_probe_count
            ui_failure_count = [int]$Summary.liveness.ui_unresponsive_count
        }
        product_failures = @($Summary.product_failures | ForEach-Object {
            [pscustomobject][ordered]@{
                schema = [string]$_.schema
                failure_type = [string]$_.failure_type
                post_boundary = [bool]$_.post_boundary
                source_kind = [string]$_.source.kind
                source_bound = [bool]$_.source_bound
                adjudicable = [bool]$_.adjudicable
            }
        })
        counts = [pscustomobject][ordered]@{
            product_failure_count = @($Summary.product_failures).Count
            blocked_reason_count = @($Summary.blocked_reasons).Count
            cleanup_failure_count = @(
                $Summary.cleanup.failures
            ).Count
        }
        privacy = [pscustomobject][ordered]@{
            direct_identifiers_included = $false
            raw_paths_included = $false
            raw_network_endpoints_included = $false
            raw_logs_or_errors_included = $false
            stable_host_or_user_ids_included = $false
        }
    }
    $null = Assert-I04ProjectionPropertySet -Object $projection `
        -Allowed @(
            'schema', 'projection_policy', 'source_summary_sha256',
            'case_id', 'formal_status', 'partial_verdict',
            'formal_v91_i04_eligible', 'candidate', 'adjudication',
            'topology', 'proof', 'measurements', 'product_failures',
            'counts', 'privacy'
        ) -Context 'root'
    $null = Assert-I04ProjectionPropertySet -Object $projection.candidate `
        -Allowed @(
            'commit', 'version', 'executable_sha256',
            'package_zip_sha256', 'package_manifest_sha256', 'unchanged'
        ) -Context 'candidate'
    $null = Assert-I04ProjectionPropertySet -Object $projection.adjudication `
        -Allowed @(
            'fixture_proof_complete', 'product_failure_proved',
            'product_failures_typed_and_source_bound',
            'proof_contradicted', 'cleanup_complete'
        ) -Context 'adjudication'
    $null = Assert-I04ProjectionPropertySet -Object $projection.topology `
        -Allowed @(
            'required', 'observed', 'proved', 'distinct_physical_hosts',
            'native_global_ipv6', 'physical_adapters_and_sockets',
            'overlay_vpn_proxy_absent'
        ) -Context 'topology'
    $null = Assert-I04ProjectionPropertySet -Object $projection.proof `
        -Allowed @(
            'logs_adjudicable', 'pcapng_parser_complete',
            'capture_interface_binding_exact',
            'target_frames_on_expected_physical_nic',
            'packet_capture_zero_loss',
            'packet_capture_below_circular_limit',
            'socket_sampler_coverage_valid'
        ) -Context 'proof'
    $null = Assert-I04ProjectionPropertySet -Object $projection.measurements `
        -Allowed @(
            'fallback_log_delta', 'bounded_fallback_log_delta',
            'hello_send_delta', 'hello_answer_receive_delta',
            'a4af_swap_a_to_b_delta', 'ipv6_syn_count', 'ipv4_syn_count',
            'syn6_to_syn4_ms', 'syn6_to_ipv4_connected_ms',
            'api_probe_count', 'api_failure_count', 'ui_probe_count',
            'ui_failure_count'
        ) -Context 'measurements'
    $null = Assert-I04ProjectionPropertySet -Object $projection.counts `
        -Allowed @(
            'product_failure_count', 'blocked_reason_count',
            'cleanup_failure_count'
        ) -Context 'counts'
    $null = Assert-I04ProjectionPropertySet -Object $projection.privacy `
        -Allowed @(
            'direct_identifiers_included', 'raw_paths_included',
            'raw_network_endpoints_included',
            'raw_logs_or_errors_included',
            'stable_host_or_user_ids_included'
        ) -Context 'privacy'
    foreach ($failure in @($projection.product_failures)) {
        $null = Assert-I04ProjectionPropertySet -Object $failure `
            -Allowed @(
                'schema', 'failure_type', 'post_boundary', 'source_kind',
                'source_bound', 'adjudicable'
            ) -Context 'product_failure'
    }
    return $projection
}

function Get-I04FailureDisposition {
    param(
        [Parameter(Mandatory = $true)][bool]$CaseArmed,
        [Parameter(Mandatory = $true)][bool]$FormalBoundaryPublished,
        [AllowNull()][object]$CandidateFailure,
        [Parameter(Mandatory = $true)][bool]$ProofContradicted,
        [AllowEmptyString()][string]$ExceptionMessage = ''
    )

    $contractValid = $false
    if ($null -ne $CandidateFailure) {
        try {
            $null = Assert-I04ProductFailureContract `
                -Failure $CandidateFailure
            $contractValid = $true
        } catch { $contractValid = $false }
    }
    $candidatePostBoundary = $CaseArmed -and $FormalBoundaryPublished -and
        $contractValid -and [bool]$CandidateFailure.post_boundary -and
        [bool]$CandidateFailure.candidate_binding.exact -and
        [bool]$CandidateFailure.source_bound -and
        [bool]$CandidateFailure.source.collector_ok -and
        [bool]$CandidateFailure.adjudicable -and -not $ProofContradicted
    return [pscustomobject][ordered]@{
        classification = if ($candidatePostBoundary) {
            'FAIL'
        } else { 'BLOCKED' }
        candidate_post_boundary = $candidatePostBoundary
        case_armed = $CaseArmed
        formal_boundary_published = $FormalBoundaryPublished
        candidate_failure_contract_valid = $contractValid
        candidate_failure_proved = $candidatePostBoundary
        proof_contradicted = $ProofContradicted
        exception_present = -not [string]::IsNullOrWhiteSpace($ExceptionMessage)
        exception_fingerprint_sha256 = if (
            [string]::IsNullOrWhiteSpace($ExceptionMessage)
        ) { '' } else { Get-I04StringSha256 -Value $ExceptionMessage }
    }
}

function Get-I04PartialVerdict {
    param(
        [Parameter(Mandatory = $true)][bool]$FixtureProofComplete,
        [Parameter(Mandatory = $true)][bool]$ProductFailureProved,
        [Parameter(Mandatory = $true)][bool]$ProofContradicted,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)][int]$ProductFailureCount
    )

    # A product invariant proved on an exact fixture is historical evidence:
    # later cleanup/lab incidents are reported but cannot turn it into BLOCKED.
    # Only a contradiction in the binding/attribution proof can invalidate it.
    if ($ProductFailureProved -and $ProductFailureCount -gt 0 -and
        -not $ProofContradicted) {
        return 'FAIL'
    }
    if ($ProductFailureProved -and $ProductFailureCount -eq 0) {
        return 'BLOCKED'
    }
    if ($ProofContradicted -or -not $FixtureProofComplete -or
        $ProductFailureCount -gt 0) { return 'BLOCKED' }
    return 'PASS'
}

function Get-I04PacketVerdict {
    param(
        [Parameter(Mandatory = $true)][string]$PcapNgPath,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][string]$CoordinatorIPv4,
        [Parameter(Mandatory = $true)][string]$CoordinatorIPv6,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][double]$NotBeforeEpochMs,
        [Parameter(Mandatory = $true)][double]$ScenarioBoundaryEpochMs,
        [Parameter(Mandatory = $true)][double]$ObservationEndEpochMs,
        [Parameter(Mandatory = $true)][int]$LimitSeconds,
        [Parameter(Mandatory = $true)][int]$MinimumSilentWindowMs,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][object]$SocketSamplerEvidence,
        [Parameter(Mandatory = $true)][object]$ExpectedAdapterEvidence,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)][int]$SynCorrelationToleranceMs,
        [string[]]$ExcludedTupleKeys = @()
    )

    if ($NotBeforeEpochMs -gt $ScenarioBoundaryEpochMs -or
        $ObservationEndEpochMs -le $ScenarioBoundaryEpochMs) {
        throw 'Coordinator PCAP timestamps are not a valid capture/trigger/stop interval'
    }
    if ([string]$SocketSamplerEvidence.schema -ne
            'ese.v91.i04-pid-socket-sampler/v1' -or
        [int]$SocketSamplerEvidence.candidate_process_id -ne
            $CandidateProcessId -or
        [Math]::Abs(
            [double]$SocketSamplerEvidence.boundary_epoch_ms -
            $ScenarioBoundaryEpochMs
        ) -gt 1 -or
        -not [bool]$SocketSamplerEvidence.clock_coherence_valid -or
        [Int64]$SocketSamplerEvidence.qpc_frequency -ne
            [Diagnostics.Stopwatch]::Frequency -or
        -not [bool]$SocketSamplerEvidence.sampler_coverage_valid) {
        throw 'PID socket-sampler evidence does not identify this exact scenario'
    }
    $samplerRows = @($SocketSamplerEvidence.target_rows)
    $samplerMaximumGapMs =
        [double]$SocketSamplerEvidence.maximum_sample_gap_ms
    $samplerTemporalCoverage =
        [double]$SocketSamplerEvidence.first_sample_epoch_ms -le
            ($NotBeforeEpochMs + $SynCorrelationToleranceMs) -and
        [double]$SocketSamplerEvidence.last_sample_epoch_ms -ge
            ($ObservationEndEpochMs - $SynCorrelationToleranceMs) -and
        $samplerMaximumGapMs -lt $SynCorrelationToleranceMs
    $excluded = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($tuple in @($ExcludedTupleKeys)) {
        $null = $excluded.Add([string]$tuple)
    }
    $pcap = Read-I04PcapNg -Path $PcapNgPath
    if ([string]$pcap.schema -ne 'ese.v91.i04-pcapng-parse/v2') {
        throw 'PCAPNG parser did not return the required v2 contract'
    }
    $expectedAdapterId = [string]$ExpectedAdapterEvidence.interface_id
    $expectedAdapterName = [string]$ExpectedAdapterEvidence.name
    $expectedAdapterDescription =
        [string]$ExpectedAdapterEvidence.description
    $adapterInventory = try {
        @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    } catch { @() }
    $expectedInventoryAdapters = @($adapterInventory | Where-Object {
        $virtualTyped = $_.PSObject.Properties.Name -contains 'Virtual' -and
            $_.Virtual -is [bool]
        $inventoryId = if ($virtualTyped) {
            Get-LabInterfaceId -Id ([string]$_.InterfaceGuid) `
                -Name ([string]$_.Name) `
                -Description ([string]$_.InterfaceDescription)
        } else { '' }
        $virtualTyped -and -not [bool]$_.Virtual -and
            [int]$_.InterfaceIndex -eq
                [int]$ExpectedAdapterEvidence.interface_index -and
            [string]$inventoryId -ceq $expectedAdapterId -and
            [string]$_.Name -ceq $expectedAdapterName -and
            [string]$_.InterfaceDescription -ceq
                $expectedAdapterDescription -and
            [bool]$_.HardwareInterface -and
            [string]$_.Status -ceq 'Up'
    })
    $expectedNameInventoryCount = @($adapterInventory | Where-Object {
        [string]$_.Name -ceq $expectedAdapterName
    }).Count
    $expectedDescriptionInventoryCount = @($adapterInventory | Where-Object {
        [string]$_.InterfaceDescription -ceq $expectedAdapterDescription
    }).Count
    $expectedAdapterPhysical =
        [bool]$ExpectedAdapterEvidence.hardware_interface -and
        -not [bool]$ExpectedAdapterEvidence.virtual -and
        -not [bool]$ExpectedAdapterEvidence.overlay_or_vpn_like -and
        [string]$ExpectedAdapterEvidence.status -ceq 'Up' -and
        [int]$ExpectedAdapterEvidence.interface_index -gt 0 -and
        -not [string]::IsNullOrWhiteSpace($expectedAdapterId) -and
        $expectedInventoryAdapters.Count -eq 1
    $matchingCaptureInterfaces = @($pcap.interfaces | Where-Object {
        $name = [string]$_._interface_name
        $description = [string]$_._interface_description
        $namePresent = -not [string]::IsNullOrWhiteSpace($name)
        $descriptionPresent =
            -not [string]::IsNullOrWhiteSpace($description)
        $homologousFieldsExact = ($namePresent -or $descriptionPresent) -and
            (-not $namePresent -or $name -ceq $expectedAdapterName) -and
            (-not $descriptionPresent -or
                $description -ceq $expectedAdapterDescription)
        $identityUnique = if ($namePresent -and $descriptionPresent) {
            $expectedInventoryAdapters.Count -eq 1
        } elseif ($namePresent) {
            $expectedNameInventoryCount -eq 1
        } else {
            $expectedDescriptionInventoryCount -eq 1
        }
        [bool]$_.options_valid -and [bool]$_.supported_link_type -and
            $homologousFieldsExact -and $identityUnique
    })
    $captureInterfaceBindingExact = [bool]$pcap.parser_complete -and
        $expectedAdapterPhysical -and $matchingCaptureInterfaces.Count -eq 1
    $expectedCaptureInterface = if ($matchingCaptureInterfaces.Count -eq 1) {
        $matchingCaptureInterfaces[0]
    } else { $null }
    $expectedCaptureInterfaceKey = if ($null -eq $expectedCaptureInterface) {
        ''
    } else {
        '{0}|{1}' -f $expectedCaptureInterface.section_index,
            $expectedCaptureInterface.interface_id
    }
    $packets = @($pcap.packets | Where-Object {
        $_.timestamp_ms -ge $NotBeforeEpochMs -and
        $_.timestamp_ms -le $ObservationEndEpochMs
    } | Sort-Object timestamp_ms)
    $targetFrames = @($packets | Where-Object {
        if ($_.protocol -eq 'TCP') {
            return (
                $_.family -eq 'IPv4' -and (
                    ($_.source -eq $CoordinatorIPv4 -and
                        $_.destination -eq $IPv4 -and
                        $_.destination_port -eq $Port) -or
                    ($_.source -eq $IPv4 -and
                        $_.destination -eq $CoordinatorIPv4 -and
                        $_.source_port -eq $Port)
                )
            ) -or (
                $_.family -eq 'IPv6' -and (
                    ($_.source -eq $CoordinatorIPv6 -and
                        $_.destination -eq $IPv6 -and
                        $_.destination_port -eq $Port) -or
                    ($_.source -eq $IPv6 -and
                        $_.destination -eq $CoordinatorIPv6 -and
                        $_.source_port -eq $Port)
                )
            )
        }
        return $_.protocol -eq 'ICMPv6' -and
            $_.quoted_family -eq 'IPv6' -and
            $_.quoted_protocol -eq 'TCP' -and
            $_.quoted_source -eq $CoordinatorIPv6 -and
            $_.quoted_destination -eq $IPv6 -and
            $_.quoted_destination_port -eq $Port
    })
    $foreignInterfaceTargetFrames = @($targetFrames | Where-Object {
        $frameInterfaceKey = '{0}|{1}' -f $_.section_index,
            $_.capture_interface_id
        -not $captureInterfaceBindingExact -or
            $frameInterfaceKey -cne $expectedCaptureInterfaceKey
    })
    $targetFramesOnExpectedPhysicalNic =
        $captureInterfaceBindingExact -and
        $foreignInterfaceTargetFrames.Count -eq 0

    $outboundTargetSyn = @($packets | Where-Object {
        $_.protocol -eq 'TCP' -and $_.syn -and -not $_.ack -and
        $_.destination_port -eq $Port -and
        (($_.family -eq 'IPv4' -and $_.source -eq $CoordinatorIPv4 -and
            $_.destination -eq $IPv4) -or
         ($_.family -eq 'IPv6' -and $_.source -eq $CoordinatorIPv6 -and
            $_.destination -eq $IPv6))
    } | ForEach-Object {
        $family = [string]$_.family
        $tuple = Get-I04TupleKey -Family $family `
            -LocalAddress ([string]$_.source) -LocalPort ([int]$_.source_port) `
            -RemoteAddress ([string]$_.destination) `
            -RemotePort ([int]$_.destination_port)
        $correlation = Get-I04SynPidCorrelation -Packet $_ `
            -CandidateProcessId $CandidateProcessId `
            -SamplerRows $samplerRows `
            -ToleranceMs $SynCorrelationToleranceMs
        [pscustomobject][ordered]@{
            packet = $_
            tuple_key = $tuple
            # Never suppress by a historical 5-tuple: Windows may reuse the
            # ephemeral port after the old prewarm disappears.  Capture starts
            # with the old connection already established, so every captured
            # target SYN is a new attempt and must remain adjudicable.
            excluded_prewarm = $false
            matches_historical_prewarm_tuple = $excluded.Contains($tuple)
            correlation = $correlation
            candidate_correlated = [bool]$correlation.candidate_correlated
            correlation_ambiguous = [bool]$correlation.correlation_ambiguous
        }
    })
    $uncorrelated = @($outboundTargetSyn | Where-Object {
        [string]$_.correlation.status -in @('foreign-owner', 'unobserved')
    })
    $ambiguous = @($outboundTargetSyn | Where-Object {
        [bool]$_.correlation_ambiguous
    })
    $preBoundaryTargetSyn = @($outboundTargetSyn | Where-Object {
        $_.packet.timestamp_ms -lt $ScenarioBoundaryEpochMs -and
        $true
    })
    $excludedPrewarmPackets = @($outboundTargetSyn | Where-Object {
        $_.matches_historical_prewarm_tuple
    })
    $candidateSynPackets = @($outboundTargetSyn | Where-Object {
        $_.packet.timestamp_ms -ge $ScenarioBoundaryEpochMs -and
        $_.candidate_correlated
    } | ForEach-Object { $_.packet })

    $syn6 = @($candidateSynPackets | Where-Object {
        $_.family -eq 'IPv6' -and $_.destination -eq $IPv6
    })
    $syn4 = @($candidateSynPackets | Where-Object {
        $_.family -eq 'IPv4' -and $_.destination -eq $IPv4
    })
    $candidateV6Tuples = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($packet in $syn6) {
        $null = $candidateV6Tuples.Add((
            Get-I04TupleKey -Family 'IPv6' `
                -LocalAddress ([string]$packet.source) `
                -LocalPort ([int]$packet.source_port) `
                -RemoteAddress ([string]$packet.destination) `
                -RemotePort ([int]$packet.destination_port)
        ))
    }
    $candidateV4Tuples = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($packet in $syn4) {
        $null = $candidateV4Tuples.Add((
            Get-I04TupleKey -Family 'IPv4' `
                -LocalAddress ([string]$packet.source) `
                -LocalPort ([int]$packet.source_port) `
                -RemoteAddress ([string]$packet.destination) `
                -RemotePort ([int]$packet.destination_port)
        ))
    }
    $v6Responses = @($packets | Where-Object {
        if ($_.protocol -ne 'TCP' -or $_.family -ne 'IPv6' -or
            $_.source -ne $IPv6 -or $_.source_port -ne $Port -or
            $_.destination -ne $CoordinatorIPv6) {
            return $false
        }
        $reverseTuple = Get-I04TupleKey -Family 'IPv6' `
            -LocalAddress ([string]$_.destination) `
            -LocalPort ([int]$_.destination_port) `
            -RemoteAddress ([string]$_.source) `
            -RemotePort ([int]$_.source_port)
        return $candidateV6Tuples.Contains($reverseTuple)
    })
    $synAck4 = @($packets | Where-Object {
        if ($_.protocol -ne 'TCP' -or $_.family -ne 'IPv4' -or
            $_.source -ne $IPv4 -or $_.source_port -ne $Port -or
            $_.destination -ne $CoordinatorIPv4 -or
            -not $_.syn -or -not $_.ack) {
            return $false
        }
        $reverseTuple = Get-I04TupleKey -Family 'IPv4' `
            -LocalAddress ([string]$_.destination) `
            -LocalPort ([int]$_.destination_port) `
            -RemoteAddress ([string]$_.source) `
            -RemotePort ([int]$_.source_port)
        return $candidateV4Tuples.Contains($reverseTuple)
    })

    $firstSyn6 = $syn6 | Select-Object -First 1
    $firstSyn4 = if ($null -ne $firstSyn6) {
        $syn4 | Where-Object timestamp_ms -gt $firstSyn6.timestamp_ms |
            Select-Object -First 1
    } else { $null }
    $firstSynAck4 = if ($null -ne $firstSyn4) {
        $expectedAck = [uint32](
            ([uint64]$firstSyn4.sequence_number + 1) % 4294967296
        )
        $synAck4 | Where-Object {
            $_.timestamp_ms -ge $firstSyn4.timestamp_ms -and
            $_.destination_port -eq $firstSyn4.source_port -and
            $_.acknowledgement_number -eq $expectedAck
        } | Select-Object -First 1
    } else { $null }
    $firstAck4 = if ($null -ne $firstSynAck4) {
        $expectedClientSequence = [uint32](
            ([uint64]$firstSyn4.sequence_number + 1) % 4294967296
        )
        $expectedServerAck = [uint32](
            ([uint64]$firstSynAck4.sequence_number + 1) % 4294967296
        )
        $packets | Where-Object {
            $_.protocol -eq 'TCP' -and $_.family -eq 'IPv4' -and
            $_.destination -eq $IPv4 -and $_.destination_port -eq $Port -and
            $_.source -eq $CoordinatorIPv4 -and
            $_.source_port -eq $firstSyn4.source_port -and
            $_.ack -and -not $_.syn -and
            $_.sequence_number -eq $expectedClientSequence -and
            $_.acknowledgement_number -eq $expectedServerAck -and
            $_.timestamp_ms -ge $firstSynAck4.timestamp_ms
        } | Select-Object -First 1
    } else { $null }
    $fallbackMs = if ($null -ne $firstSyn6 -and $null -ne $firstSyn4) {
        [Math]::Round($firstSyn4.timestamp_ms - $firstSyn6.timestamp_ms, 3)
    } else { $null }
    $connectedMs = if ($null -ne $firstSyn6 -and $null -ne $firstAck4) {
        [Math]::Round($firstAck4.timestamp_ms - $firstSyn6.timestamp_ms, 3)
    } else { $null }
    $postConnectionObservationMs = if ($null -ne $firstAck4) {
        [Math]::Round(
            $ObservationEndEpochMs - $firstAck4.timestamp_ms, 3
        )
    } else { $null }
    $limitMs = $LimitSeconds * 1000
    $distinctV6Attempts = @($syn6 | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}' -f $_.source, $_.source_port,
            $_.destination, $_.destination_port, $_.sequence_number
    } | Sort-Object -Unique)
    $distinctV4Attempts = @($syn4 | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}' -f $_.source, $_.source_port,
            $_.destination, $_.destination_port, $_.sequence_number
    } | Sort-Object -Unique)
    $syn6AttemptKeys = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::Ordinal)
    foreach ($packet in $syn6) {
        $null = $syn6AttemptKeys.Add((
            '{0}|{1}|{2}|{3}|{4}' -f $packet.source,
                $packet.source_port, $packet.destination,
                $packet.destination_port, $packet.sequence_number
        ))
    }
    $correlatedIcmp = @($packets | Where-Object {
        if ($_.protocol -ne 'ICMPv6' -or $_.icmp_type -lt 1 -or
            $_.icmp_type -gt 4 -or $_.quoted_family -ne 'IPv6' -or
            $_.quoted_protocol -ne 'TCP') {
            return $false
        }
        $quotedKey = '{0}|{1}|{2}|{3}|{4}' -f $_.quoted_source,
            $_.quoted_source_port, $_.quoted_destination,
            $_.quoted_destination_port, $_.quoted_sequence_number
        return $syn6AttemptKeys.Contains($quotedKey)
    })
    # Environment validation is a fixed window after SYN6.  Do not shorten it
    # at SYN4: an overly eager product fallback must remain a product FAIL,
    # while any TCP/RST/application/ICMP response within this fixed interval
    # means the environment was not a silent blackhole.
    $silentWindowEndMs = if ($null -ne $firstSyn6) {
        [double]$firstSyn6.timestamp_ms + $MinimumSilentWindowMs
    } else { [double]$ObservationEndEpochMs }
    $captureCoverageAfterSyn6Ms = if ($null -ne $firstSyn6) {
        [Math]::Round(
            $ObservationEndEpochMs - $firstSyn6.timestamp_ms, 3
        )
    } else { $null }
    $silentWindowObservedMs = if ($null -ne $firstSyn6) {
        [Math]::Round(
            $silentWindowEndMs - $firstSyn6.timestamp_ms, 3
        )
    } else { $null }
    $silentWindowResponses = if ($null -ne $firstSyn6) {
        @($v6Responses | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -le $silentWindowEndMs
        }).Count
    } else { $v6Responses.Count }
    $silentWindowIcmp = if ($null -ne $firstSyn6) {
        @($correlatedIcmp | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -le $silentWindowEndMs
        }).Count
    } else { $correlatedIcmp.Count }
    $environmentResponseWindowEnd = if ($null -ne $firstSyn6) {
        [double]$firstSyn6.timestamp_ms + $MinimumSilentWindowMs
    } else { $null }
    $earlyV6Responses = if ($null -ne $firstSyn6) {
        @($v6Responses | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -lt $environmentResponseWindowEnd
        }).Count
    } else { 0 }
    $earlyIcmp = if ($null -ne $firstSyn6) {
        @($correlatedIcmp | Where-Object {
            $_.timestamp_ms -ge $firstSyn6.timestamp_ms -and
            $_.timestamp_ms -lt $environmentResponseWindowEnd
        }).Count
    } else { 0 }
    $correlationComplete = $samplerTemporalCoverage -and
        $uncorrelated.Count -eq 0 -and $ambiguous.Count -eq 0
    $planningUpperBoundMs = [Math]::Min($limitMs, 8000)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-packet-verdict/v2'
        candidate_process_id = $CandidateProcessId
        pcapng_source_byte_count = [Int64]$pcap.source_byte_count
        pcapng_source_sha256 = [string]$pcap.source_sha256
        pcapng_source_immutable_read_lock_held =
            [bool]$pcap.source_immutable_read_lock_held
        pcapng_parser_complete = [bool]$pcap.parser_complete
        pcapng_section_count = [int]$pcap.section_count
        pcapng_interface_count = [int]$pcap.interface_count
        pcapng_enhanced_packet_count = [int]$pcap.enhanced_packet_count
        pcapng_trailing_byte_count = [int]$pcap.trailing_byte_count
        pcapng_block_error_count = [int]$pcap.block_error_count
        pcapng_idb_option_error_count = [int]$pcap.idb_option_error_count
        pcapng_truncated_frame_count = [int]$pcap.truncated_frame_count
        pcapng_unknown_interface_frame_count =
            [int]$pcap.unknown_interface_frame_count
        pcapng_unsupported_linktype_frame_count =
            [int]$pcap.unsupported_linktype_frame_count
        pcapng_unsupported_packet_block_count =
            [int]$pcap.unsupported_packet_block_count
        pcapng_parse_null_frame_count =
            [int]$pcap.parse_null_frame_count
        pcapng_non_adjudicable_frame_count =
            [int]$pcap.non_adjudicable_frame_count
        capture_interface_binding = [ordered]@{
            schema = 'ese.v91.i04-capture-interface-binding/v1'
            adapter_interface_index =
                [int]$ExpectedAdapterEvidence.interface_index
            adapter_interface_id = $expectedAdapterId
            adapter_name_sha256 = if ($expectedAdapterName) {
                Get-I04StringSha256 -Value $expectedAdapterName
            } else { '' }
            adapter_description_sha256 = if ($expectedAdapterDescription) {
                Get-I04StringSha256 -Value $expectedAdapterDescription
            } else { '' }
            hardware_interface =
                [bool]$ExpectedAdapterEvidence.hardware_interface
            virtual = [bool]$ExpectedAdapterEvidence.virtual
            overlay_or_vpn_like =
                [bool]$ExpectedAdapterEvidence.overlay_or_vpn_like
            status = [string]$ExpectedAdapterEvidence.status
            adapter_inventory_match_count =
                $expectedInventoryAdapters.Count
            adapter_name_inventory_match_count =
                $expectedNameInventoryCount
            adapter_description_inventory_match_count =
                $expectedDescriptionInventoryCount
            pcapng_section_index = if ($null -eq
                $expectedCaptureInterface) { $null } else {
                [int]$expectedCaptureInterface.section_index
            }
            pcapng_interface_id = if ($null -eq
                $expectedCaptureInterface) { $null } else {
                [int]$expectedCaptureInterface.interface_id
            }
            pcapng_link_type = if ($null -eq
                $expectedCaptureInterface) { $null } else {
                [int]$expectedCaptureInterface.link_type
            }
            pcapng_interface_name_sha256 = if ($null -eq
                $expectedCaptureInterface) { '' } else {
                [string]$expectedCaptureInterface.interface_name_sha256
            }
            pcapng_interface_description_sha256 = if ($null -eq
                $expectedCaptureInterface) { '' } else {
                [string]$expectedCaptureInterface.
                    interface_description_sha256
            }
            matching_pcapng_interface_count =
                $matchingCaptureInterfaces.Count
            exact = $captureInterfaceBindingExact
        }
        capture_interface_binding_exact = $captureInterfaceBindingExact
        target_frame_count = $targetFrames.Count
        foreign_interface_target_frame_count =
            $foreignInterfaceTargetFrames.Count
        target_frames_on_expected_physical_nic =
            $targetFramesOnExpectedPhysicalNic
        not_before_epoch_ms = $NotBeforeEpochMs
        coordinator_stop_a_boundary_epoch_ms = $ScenarioBoundaryEpochMs
        coordinator_observation_end_epoch_ms = $ObservationEndEpochMs
        packet_count = $packets.Count
        ipv6_syn_count = $syn6.Count
        distinct_ipv6_connection_attempts = $distinctV6Attempts.Count
        ipv6_tcp_response_count_before_fallback = $silentWindowResponses
        correlated_icmpv6_error_count_before_fallback = $silentWindowIcmp
        ipv6_tcp_response_count_in_fixed_silent_window =
            $earlyV6Responses
        correlated_icmpv6_error_count_in_fixed_silent_window =
            $earlyIcmp
        environment_rejected_blackhole_in_fixed_window =
            $earlyV6Responses -gt 0 -or $earlyIcmp -gt 0
        ipv4_syn_count = $syn4.Count
        distinct_ipv4_connection_attempts = $distinctV4Attempts.Count
        ipv4_synack_observed = $null -ne $firstSynAck4
        ipv4_final_ack_observed = $null -ne $firstAck4
        syn6_to_syn4_ms = $fallbackMs
        syn6_to_ipv4_connected_ms = $connectedMs
        post_ipv4_connected_observation_ms = $postConnectionObservationMs
        minimum_silent_window_ms = $MinimumSilentWindowMs
        silent_window_observed_ms = $silentWindowObservedMs
        capture_coverage_after_syn6_ms = $captureCoverageAfterSyn6Ms
        pid_observed_ipv4_local_ports = @(
            $SocketSamplerEvidence.candidate_target_rows |
                Where-Object family -eq 'IPv4' |
                ForEach-Object { [int]$_.local_port } |
                Sort-Object -Unique
        )
        pid_observed_ipv6_local_ports = @(
            $SocketSamplerEvidence.candidate_target_rows |
                Where-Object family -eq 'IPv6' |
                ForEach-Object { [int]$_.local_port } |
                Sort-Object -Unique
        )
        pid_correlation_tolerance_ms = $SynCorrelationToleranceMs
        pid_sampler_temporal_coverage_valid = $samplerTemporalCoverage
        pid_sampler_maximum_gap_ms = $samplerMaximumGapMs
        target_syn_count = $outboundTargetSyn.Count
        pid_correlated_target_syn_count = @(
            $outboundTargetSyn | Where-Object candidate_correlated
        ).Count
        excluded_prewarm_tuple_count = $excluded.Count
        excluded_prewarm_syn_packet_count = $excludedPrewarmPackets.Count
        pre_boundary_target_syn_count = $preBoundaryTargetSyn.Count
        uncorrelated_target_syn_count = $uncorrelated.Count
        ambiguous_owner_target_syn_count = $ambiguous.Count
        target_syn_pid_correlations = @(
            $outboundTargetSyn | ForEach-Object { $_.correlation }
        )
        pid_packet_correlation_complete = $correlationComplete
        silent_drop_proved = $null -ne $firstSyn6 -and
            $silentWindowObservedMs -ge $MinimumSilentWindowMs -and
            $captureCoverageAfterSyn6Ms -ge $MinimumSilentWindowMs -and
            $silentWindowResponses -eq 0 -and $silentWindowIcmp -eq 0
        ipv4_attempt_absent_proved = $null -ne $firstSyn6 -and
            $syn4.Count -eq 0 -and
            $captureCoverageAfterSyn6Ms -ge $limitMs
        fallback_under_limit = $null -ne $fallbackMs -and
            $fallbackMs -ge 0 -and $fallbackMs -lt $limitMs
        fallback_in_planning_window = $null -ne $fallbackMs -and
            $fallbackMs -ge $MinimumSilentWindowMs -and
            $fallbackMs -lt $planningUpperBoundMs
        fallback_planning_upper_bound_ms = $planningUpperBoundMs
        connection_under_limit = $null -ne $connectedMs -and
            $connectedMs -ge 0 -and $connectedMs -lt $limitMs
    }
}

function Invoke-I04PeerRole {
    if (-not (Test-I04Administrator)) {
        throw 'Peer role requires an elevated Administrator PowerShell for scoped firewall setup/rollback'
    }
    foreach ($firewallCommand in @(
        'Get-NetFirewallRule', 'New-NetFirewallRule',
        'Remove-NetFirewallRule', 'Get-NetFirewallAddressFilter',
        'Get-NetFirewallApplicationFilter', 'Get-NetFirewallPortFilter',
        'Get-NetFirewallInterfaceFilter',
        'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallServiceFilter', 'Get-NetFirewallSecurityFilter',
        'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Get-NetIPAddress',
        'Get-NetAdapter', 'Find-NetRoute'
    )) {
        if ($null -eq (Get-Command $firewallCommand `
            -ErrorAction SilentlyContinue)) {
            throw "Peer firewall prerequisite is missing: $firewallCommand"
        }
    }
    if (-not $RunNonce) {
        throw 'Peer role requires -RunNonce from the coordinator'
    }
    $peerPortPreflight = Assert-I04PortsInitiallyFree `
        -Ports @($PeerTcpPort, $PeerUdpPort, $PeerWebPort) -HostRole 'Peer'
    $outputPath = Assert-I04SafeCreationPath -Path $OutputRoot
    if (Test-Path -LiteralPath $outputPath) {
        $null = Assert-I04NoReparsePath -Path $outputPath -Kind Directory
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Peer OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $null = Assert-I04NoReparsePath -Path $output -Kind Directory
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $journal = Join-Path $evidence 'mutation-journal.jsonl'
    $cleanupPath = Join-Path $evidence 'cleanup.json'
    $formalTriggerBoundaryPath =
        Join-Path $evidence 'formal-trigger-boundary.json'
    $coordinationRootSafe = Assert-I04NoReparsePath `
        -Path $CoordinationRoot -Kind Directory
    $coordination = Get-LabFullPath -Path (Join-Path `
        -Path $coordinationRootSafe `
        -ChildPath "v91-i04-$($RunNonce.ToLowerInvariant())")
    if (-not (Test-Path -LiteralPath $coordination -PathType Container)) {
        throw "Peer requires the coordinator-created run directory: $coordination"
    }
    $null = Assert-I04NoReparsePath -Path $coordination -Kind Directory
    $initialCoordinationEntries = @(
        Get-ChildItem -LiteralPath $coordination -Force -ErrorAction Stop
    )
    if ($initialCoordinationEntries.Count -ne 1 -or
        $initialCoordinationEntries[0].Name -ne 'run.json') {
        throw 'Peer coordination run directory is stale or was not pristine (expected only run.json)'
    }
    $runPath = Join-Path $coordination 'run.json'
    $null = Open-I04LockedFile -Path $runPath
    $runManifest = Get-Content -LiteralPath $runPath -Raw |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$runManifest.schema -ne 'ese.v91.i04-run/v1' -or
        [string]$runManifest.case_id -ne $caseId -or
        [string]$runManifest.run_nonce -ne $RunNonce.ToLowerInvariant() -or
        [string]$runManifest.expected_candidate_commit -ne $candidate.commit -or
        [string]$runManifest.expected_emule_sha256 -ne $expectedHash -or
        [string]$runManifest.expected_package_zip_sha256 -ne
            $expectedZipHash -or
        [string]$runManifest.expected_package_manifest_sha256 -ne
            [string]$candidate.package_manifest_sha256 -or
        [string]$runManifest.harness_bundle.schema -ne
            'ese.v91.i04-harness-bundle/v1' -or
        [string]$runManifest.harness_bundle.bundle_sha256 -ne
            [string]$script:i04HarnessBundle.bundle_sha256 -or
        [string]$runManifest.harness_bundle.harness_sha256 -ne
            [string]$script:i04HarnessBundle.harness_sha256 -or
        [string]$runManifest.harness_bundle.common_sha256 -ne
            [string]$script:i04HarnessBundle.common_sha256 -or
        [string]$runManifest.harness_bundle.prepare_node_sha256 -ne
            [string]$script:i04HarnessBundle.prepare_node_sha256 -or
        -not [bool]$runManifest.harness_bundle.immutable_read_locks_held -or
        [string]$runManifest.identity.coordinator_machine_id_sha256 -ne
            $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant() -or
        [string]$runManifest.identity.peer_machine_id_sha256 -ne
            $ExpectedPeerMachineIdSha256.ToLowerInvariant() -or
        [string]$runManifest.identity.coordinator_user_sid_sha256 -ne
            $expectedCoordinatorSidHash -or
        [string]$runManifest.identity.peer_user_sid_sha256 -ne
            $expectedPeerSidHash -or
        -not [bool]$runManifest.identity.
            disposable_accounts_operator_attested -or
        [string]$runManifest.identity.manifest_creator.
            machine_id_sha256 -ne
                $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant() -or
        [string]$runManifest.identity.manifest_creator.user_sid_sha256 -ne
            $expectedCoordinatorSidHash -or
        [string]$runManifest.identity.account_registry_transaction.schema -ne
            'ese.v91.i04-account-registry-transaction/v2' -or
        [string]$runManifest.identity.account_registry_transaction.
            expected_user_sid_sha256 -ne $expectedCoordinatorSidHash -or
        -not [bool]$runManifest.identity.account_registry_transaction.
            initial_absence_proved -or
        -not [bool]$runManifest.identity.account_registry_transaction.
            baseline.run_subtree.exists -or
        [string]$runManifest.peer.hostname -ne $canonicalHostname -or
        [string]$runManifest.peer.ipv4 -ne $peerV4Text -or
        [string]$runManifest.peer.local_ipv4 -ne $peerLocalV4Text -or
        [string]$runManifest.peer.ipv6 -ne $peerV6Text -or
        [int]$runManifest.peer.tcp_port -ne $PeerTcpPort -or
        [int]$runManifest.peer.udp_port -ne $PeerUdpPort -or
        [int]$runManifest.peer.web_port -ne $PeerWebPort -or
        [int]$runManifest.client.tcp_port -ne $ClientTcpPort -or
        [int]$runManifest.client.udp_port -ne $ClientUdpPort -or
        [int]$runManifest.client.web_port -ne $ClientWebPort -or
        [Int64]$runManifest.file_size_bytes -ne $FileSizeBytes -or
        [Int64]$runManifest.file_b_size_bytes -ne $fileBSizeBytes -or
        [int]$runManifest.scheduler_reconnect_floor_seconds -ne
            $schedulerReconnectFloorSeconds -or
        [int]$runManifest.fallback_limit_seconds -ne
            $FallbackLimitSeconds -or
        [int]$runManifest.expected_fallback_delay_ms -ne
            $expectedFallbackDelayMs -or
        [int]$runManifest.capture_tolerance_ms -ne
            $captureTimingToleranceMs -or
        [int]$runManifest.socket_clock_coherence_tolerance_ms -ne
            $socketClockCoherenceToleranceMs) {
        throw 'Peer run manifest does not exactly match the requested candidate/endpoints'
    }
    $coordinatorV4Address = Convert-I04RequiredAddress `
        -Value $CoordinatorIPv4 `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorIPv4'
    $coordinatorV6Address = Convert-I04RequiredAddress `
        -Value $CoordinatorIPv6 `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'CoordinatorIPv6'
    $coordinatorV4Text = $coordinatorV4Address.ToString()
    $coordinatorV6Text = $coordinatorV6Address.ToString()
    if ([string]$runManifest.coordinator.ipv4 -ne $coordinatorV4Text -or
        [string]$runManifest.coordinator.ipv6 -ne $coordinatorV6Text) {
        throw 'Peer coordinator addresses do not match the signed run manifest'
    }
    $readyPath = Join-Path $coordination 'peer-ready.json'
    $armPath = Join-Path $coordination 'arm-drop.json'
    $armedPath = Join-Path $coordination 'peer-drop-armed.json'
    $quiescePath = Join-Path $coordination 'quiesce.json'
    $quiescedPath = Join-Path $coordination 'peer-quiesced.json'
    $restartPath = Join-Path $coordination 'restart.json'
    $resumedPath = Join-Path $coordination 'peer-resumed.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $resultPath = Join-Path $coordination 'peer-result.json'
    $script:i04PeerTerminalReceiptPath =
        Join-Path $coordination 'peer-terminal.json'

    $password = New-I04EphemeralSecret
    $source = $null
    $peerOwnedProcesses = [System.Collections.Generic.List[object]]::new()
    $sourceExe = ''
    $sourceNode = ''
    $controlledServer = $null
    $controlledServersOwned =
        [System.Collections.Generic.List[object]]::new()
    $controlledServerStop = $null
    $allow4Rule = "eSE V91 I04 allow4 $RunNonce"
    $allow6Rule = "eSE V91 I04 allow6 $RunNonce"
    $dropRule = "eSE V91 I04 DROP6 $RunNonce"
    $allow4RuleName =
        "ese-v91-i04-allow4-$($RunNonce.ToLowerInvariant())"
    $allow6RuleName =
        "ese-v91-i04-allow6-$($RunNonce.ToLowerInvariant())"
    $dropRuleName = "ese-v91-i04-drop6-$($RunNonce.ToLowerInvariant())"
    $peerFirewallArmedSnapshot = $null
    $peerFirewallPreRemovalSnapshot = $null
    $peerFirewallScenarioUnchanged = $false
    $firewallNamesOwned = $false
    $runtimeFailure = $null
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    $armedAt = $null
    $oldPid = $null
    $newPid = $null
    $restartElapsedMs = $null
    $allow4Evidence = $null
    $allow6Evidence = $null
    $dropEvidence = $null
    $observedCoordinatorV4 = ''
    $observedCoordinatorPort = $null
    $fixtureA = $null
    $fixtureB = $null
    $sharedA = $null
    $sharedB = $null
    $peerEvidence = $null
    $sourceIdentityInitial = $null
    $sourceRuntimeInitial = $null
    $sourceRuntimeResumed = $null
    $serverLoginInitial = $null
    $serverLoginResumed = $null
    $peerIsolationInitial = $null
    $peerIsolationFinal = $null
    $peerRouteV6 = $null
    $peerRouteV4Observed = $null

    try {
        $peerIsolationInitial = Get-I04IsolationEvidence
        Write-LabJson -Value $peerIsolationInitial -Path (
            Join-Path $evidence 'peer-isolation-initial.json'
        ) | Out-Null
        if (-not [bool]$peerIsolationInitial.strict_isolation_valid) {
            throw 'Peer has an active overlay/VPN adapter or proxy environment'
        }
        $assignedV4 = Get-NetIPAddress -AddressFamily IPv4 `
            -ErrorAction Stop | Where-Object {
                (Get-I04NormalizedIp -Address $_.IPAddress) -eq
                    $peerLocalV4Text -and
                $_.AddressState -eq 'Preferred'
            } | Select-Object -First 1
        $assignedV6 = Get-NetIPAddress -AddressFamily IPv6 `
            -ErrorAction Stop | Where-Object {
                (Get-I04NormalizedIp -Address $_.IPAddress) -eq $peerV6Text -and
                $_.AddressState -eq 'Preferred'
            } | Select-Object -First 1
        if ($null -eq $assignedV4 -or $null -eq $assignedV6) {
            throw 'PeerLocalIPv4 and PeerIPv6 must both be Preferred addresses assigned to this peer'
        }
        if ([int]$assignedV4.InterfaceIndex -ne
            [int]$assignedV6.InterfaceIndex) {
            throw 'Peer IPv4 and IPv6 must be assigned to the same adapter'
        }
        if ((Get-I04StrictAddressClass -Address $peerV6Text) -ne
            'native-global-v6') {
            throw 'The real peer must advertise a native global IPv6 address; ULA/overlay-only is not a direct T1/T2 I04 fixture'
        }
        $adapter = Get-NetAdapter -InterfaceIndex $assignedV6.InterfaceIndex `
            -ErrorAction Stop
        $adapterVirtual = $true
        if ($adapter.PSObject.Properties.Name -contains 'Virtual' -and
            $adapter.Virtual -is [bool]) {
            $adapterVirtual = [bool]$adapter.Virtual
        }
        $adapterOverlayLike =
            ([string]$adapter.Name) -match $overlayPattern -or
            ([string]$adapter.InterfaceDescription) -match $overlayPattern
        $physical = [bool]$adapter.HardwareInterface -and
            -not $adapterVirtual -and -not $adapterOverlayLike
        if (-not $physical -or ([string]$adapter.Status) -ne 'Up') {
            throw 'Peer dual-stack adapter must be an Up physical, non-virtual interface'
        }
        $peerRouteV6 = Get-I04RouteEvidence `
            -RemoteAddress $coordinatorV6Text
        if (-not [bool]$peerRouteV6.available -or
            -not [bool]$peerRouteV6.physical_nonvirtual -or
            [int]$peerRouteV6.interface_index -ne
                [int]$assignedV6.InterfaceIndex -or
            [string]$peerRouteV6.source_address -ne $peerV6Text) {
            throw 'Peer does not have a native physical IPv6 route to coordinator'
        }
        $peerEvidence = [ordered]@{
            machine_id_sha256 = Get-I04MachineId
            operator_identity = Get-I04HostIdentityEvidence
            account_registry_transaction =
                $script:i04AccountRegistryTransaction
            computer_name_sha256 = Get-LabStringSha256 -Value $env:COMPUTERNAME
            interface_id = Get-LabInterfaceId `
                -Id ([string]$adapter.InterfaceGuid) `
                -Name ([string]$adapter.Name) `
                -Description ([string]$adapter.InterfaceDescription)
            interface_status = [string]$adapter.Status
            hardware_interface = [bool]$adapter.HardwareInterface
            virtual = $adapterVirtual
            overlay_or_vpn_like = $adapterOverlayLike
            physical = $physical
            ipv4_assigned = $true
            ipv6_assigned = $true
            public_ipv4_endpoint = $peerV4Text
            local_ipv4 = $peerLocalV4Text
            ipv4_interface_index = [int]$assignedV4.InterfaceIndex
            ipv6_interface_index = [int]$assignedV6.InterfaceIndex
            same_interface = [int]$assignedV4.InterfaceIndex -eq
                [int]$assignedV6.InterfaceIndex
            route_to_coordinator_ipv6 = $peerRouteV6
            isolation = $peerIsolationInitial
        }

        $offset = $PeerTcpPort - 4662
        if (($PeerUdpPort - 4672) -ne $offset -or
            ($PeerWebPort - 4711) -ne $offset) {
            throw 'Peer TCP/UDP/Web ports must share the standard 4662/4672/4711 offset'
        }
        $null = Assert-I04CandidateBindingUnchanged -Binding $candidate
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
            -SourcePackage $candidate.package_path -OutputRoot $nodes `
            -RunId 'v91-i04-peer' -PortOffset $offset
        $sourceNode = Join-Path $nodes 'v91-i04-peer-a'
        $sourceExe = Join-Path $sourceNode 'emule.exe'
        $null = Assert-I04CandidateBindingUnchanged -Binding $candidate
        $null = Assert-I04PreparedNodeDerivedFromBinding `
            -NodePath $sourceNode -Binding $candidate
        $sourceCodeBinding = Lock-I04PreparedNodeCode `
            -NodePath $sourceNode -ExpectedExeSha256 $expectedHash
        $incoming = New-LabDirectory -Path (Join-Path $sourceNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $sourceNode 'Temp')
        $isolation = Set-I04IsolatedPreferences -NodePath $sourceNode `
            -IPv6Mode 2 -IPv6BindAddress $peerV6Text `
            -WebPort $PeerWebPort -Password $password `
            -IncomingPath $incoming -TempPath $temp -MaxUploadKiBps 64
        if (-not $isolation.preferences_dat_absent_before_start -or
            -not $isolation.cryptkey_dat_absent_before_start) {
            throw 'Peer profile inherited identity state'
        }

        $fileAName = "v91-i04-$RunNonce-a.bin"
        $fileBName = "v91-i04-$RunNonce-b.bin"
        $fixtureA = New-I04FixtureFile `
            -Path (Join-Path $incoming $fileAName) `
            -Bytes $FileSizeBytes `
            -Seed (
                "V91-I04|peer|A|$($RunNonce.ToLowerInvariant())|" +
                "$($candidate.commit)|$FileSizeBytes"
            )
        $fixtureB = New-I04FixtureFile `
            -Path (Join-Path $incoming $fileBName) `
            -Bytes $fileBSizeBytes `
            -Seed (
                "V91-I04|peer|B|$($RunNonce.ToLowerInvariant())|" +
                "$($candidate.commit)|$fileBSizeBytes"
            )
        if ($fixtureA.sha256 -eq $fixtureB.sha256) {
            throw 'Peer files A and B are not unique'
        }

        $firewallPrecheck = @(
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
        )
        foreach ($ruleIdentity in @(
            [pscustomobject]@{
                name = $allow4RuleName; display = $allow4Rule
            },
            [pscustomobject]@{
                name = $allow6RuleName; display = $allow6Rule
            },
            [pscustomobject]@{ name = $dropRuleName; display = $dropRule }
        )) {
            if (@($firewallPrecheck | Where-Object {
                [string]$_.Name -eq $ruleIdentity.name
            }).Count -ne 0) {
                throw "Refusing to reuse firewall Name '$($ruleIdentity.name)'"
            }
            if (@($firewallPrecheck | Where-Object {
                [string]$_.DisplayName -eq $ruleIdentity.display
            }).Count -ne 0) {
                throw "Refusing to reuse firewall DisplayName '$($ruleIdentity.display)'"
            }
        }
        $firewallNamesOwned = $true
        New-NetFirewallRule `
            -Name $allow4RuleName -DisplayName $allow4Rule `
            -Direction Inbound -Action Allow -Program $sourceExe `
            -Protocol TCP -LocalAddress $peerLocalV4Text `
            -LocalPort $PeerTcpPort -RemoteAddress Any `
            -Profile Any -Enabled True | Out-Null
        Add-I04Journal -Path $journal -Mutation 'peer-firewall-allow4' `
            -State 'applied' -Detail "$allow4Rule remote=Any provisional"
        New-NetFirewallRule `
            -Name $allow6RuleName -DisplayName $allow6Rule `
            -Direction Inbound `
            -Action Allow -Program $sourceExe -Protocol TCP `
            -LocalAddress $peerV6Text -LocalPort $PeerTcpPort `
            -RemoteAddress $coordinatorV6Text `
            -Profile Any -Enabled True | Out-Null
        Add-I04Journal -Path $journal -Mutation 'peer-firewall-allow6' `
            -State 'applied' -Detail $allow6Rule
        $allow4Evidence = Get-I04FirewallRuleEvidence `
            -DisplayName $allow4Rule -Action Allow -Program $sourceExe `
            -LocalAddresses @($peerLocalV4Text) `
            -RemoteAddresses @('Any') `
            -LocalPort $PeerTcpPort
        $allow6Evidence = Get-I04FirewallRuleEvidence `
            -DisplayName $allow6Rule -Action Allow -Program $sourceExe `
            -LocalAddresses @($peerV6Text) `
            -RemoteAddresses @($coordinatorV6Text) `
            -LocalPort $PeerTcpPort
        if (-not $allow4Evidence.exact -or
            -not $allow6Evidence.exact) {
            throw 'Peer provisional allow rules did not round-trip exactly'
        }

        function Start-PeerSource {
            param(
                [AllowNull()][Diagnostics.Stopwatch]$RestartWatch = $null,
                [switch]$RequireEd2k,
                [ValidateRange(0, 16)][int]$MinimumServerLogin = 0
            )

            $process = $null
            try {
                $preferenceProof = Assert-I04StoredPreferenceContract `
                    -NodePath $sourceNode
                $process = Start-I04RestrictedProcess -FilePath $sourceExe `
                    -ArgumentList @(
                        '--portable', '--ignoreinstances',
                        "--metrics-port=$PeerWebPort",
                        "--tcp-port=$PeerTcpPort",
                        "--udp-port=$PeerUdpPort"
                    ) -WorkingDirectory $sourceNode
                $peerOwnedProcesses.Add($process)
                $process = Register-I04OwnedProcess -Process $process `
                    -ExpectedPath $sourceExe -OwnerRole 'PeerSource' `
                    -Nonce $RunNonce
                $listeners = Wait-I04Listener -Port $PeerTcpPort `
                    -Process $process -RequireDualStack
                $listenerReadyMs = if ($null -eq $RestartWatch) {
                    $null
                } else { [Int64]$RestartWatch.ElapsedMilliseconds }
                Wait-I04Api -Port $PeerWebPort -Process $process | Out-Null
                if ((Get-LabSha256 -Path $process.Path) -ne $expectedHash) {
                    throw 'Started peer process is not the exact candidate binary'
                }
                $serverLogin = $null
                if ($MinimumServerLogin -gt 0) {
                    if ($null -eq $controlledServer) {
                        throw 'Peer controlled eD2K server was not started'
                    }
                    $serverLogin = Wait-I04ControlledEd2kLogin `
                        -Server $controlledServer -Process $process `
                        -ExpectedTcpPort $PeerTcpPort `
                        -MinimumLoginCount $MinimumServerLogin `
                        -TimeoutSeconds 90
                }
                $apiDeadline = [DateTime]::UtcNow.AddSeconds(90)
                do {
                    $api = Get-I04ApiProbe -Port $PeerWebPort
                    if (Test-I04ApiIsolation -Data $api `
                        -RequireEd2k ([bool]$RequireEd2k)) {
                        break
                    }
                    Start-Sleep -Milliseconds 200
                } while ([DateTime]::UtcNow -lt $apiDeadline)
                if (-not (Test-I04ApiIsolation -Data $api `
                    -RequireEd2k ([bool]$RequireEd2k))) {
                    throw 'Peer runtime violated eD2K/Kad/NetLab isolation gates'
                }
                return [pscustomobject]@{
                    process = $process
                    listeners = $listeners
                    listener_ready_elapsed_ms = $listenerReadyMs
                    api = $api
                    controlled_server_login = $serverLogin
                    preference_contract = $preferenceProof
                }
            } catch {
                if ($null -ne $process -and -not (
                    Stop-I04OwnedProcess -Process $process `
                        -ExpectedPath $sourceExe
                )) {
                    $cleanupFailures.Add(
                        "partially started peer process $($process.Id) could not be stopped safely"
                    )
                }
                throw
            }
        }

        # A clean normal-mode start/stop materializes preferences.dat.  The
        # campaign source then reloads that exact persisted user hash on every
        # controlled restart; a first-run in-memory identity is not sufficient
        # evidence for the "same peer" requirement.
        $initialized = Start-PeerSource
        $source = $initialized.process
        Add-I04Journal -Path $journal -Mutation 'peer-identity-init-process' `
            -State 'applied' -Detail "pid=$($source.Id)"
        if (-not (Stop-I04OwnedProcess -Process $source `
            -ExpectedPath $sourceExe -RequireGraceful)) {
            throw 'Peer identity initialization did not stop gracefully'
        }
        Add-I04Journal -Path $journal -Mutation 'peer-identity-init-process' `
            -State 'rolled_back' -Detail "pid=$($source.Id)"
        $source = $null
        $sourceIdentitySeed = Get-I04PersistedUserHash -NodePath $sourceNode

        $controlledServer = Start-I04ControlledEd2kServer `
            -EvidencePath (
                Join-Path $evidence 'peer-controlled-ed2k-server.json'
            ) -ListenAddress $peerLocalV4Text `
            -ExpectedClientAddress $peerLocalV4Text `
            -HighIdAddress $peerV4Text `
            -RunNonce $RunNonce.ToLowerInvariant() -OwnerRole 'peer' `
            -OwnerInventory $controlledServersOwned
        $controlledProfile = Enable-I04ControlledEd2kProfile `
            -NodePath $sourceNode -ServerAddress $peerLocalV4Text `
            -ServerPort $controlledServer.port `
            -RunNonce $RunNonce.ToLowerInvariant() -OwnerRole 'peer'

        $started = Start-PeerSource -RequireEd2k -MinimumServerLogin 1
        $source = $started.process
        $sourceRuntimeInitial = $started.api
        $serverLoginInitial = $started.controlled_server_login
        $sourceIdentityInitial = Get-I04PersistedUserHash `
            -NodePath $sourceNode
        if ([string]$sourceIdentityInitial.user_hash -ne
                [string]$sourceIdentitySeed.user_hash -or
            [string]$sourceRuntimeInitial.user_hash -ne
                [string]$sourceIdentitySeed.user_hash -or
            [string]$serverLoginInitial.runtime_user_hash -ne
                [string]$sourceIdentitySeed.user_hash) {
            throw 'Peer persisted/runtime/server-login identity mismatch'
        }
        Add-I04Journal -Path $journal -Mutation 'peer-process' `
            -State 'applied' -Detail "pid=$($source.Id)"
        $session = Get-I04ClassicSession -Port $PeerWebPort -Password $password
        $sharedA = Get-I04SharedLink -Port $PeerWebPort -Session $session `
            -FileName $fileAName -FileBytes $FileSizeBytes
        $sharedB = Get-I04SharedLink -Port $PeerWebPort -Session $session `
            -FileName $fileBName -FileBytes $fileBSizeBytes
        if ([string]$sharedA.ed2k_hash -eq
            [string]$sharedB.ed2k_hash) {
            throw 'Peer files A and B have the same eD2K hash'
        }
        $ready = [ordered]@{
            schema = 'ese.v91.i04-peer-ready/v1'
            case_id = $caseId
            run_nonce = $RunNonce.ToLowerInvariant()
            ready_at_utc = Get-LabUtcTimestamp
            harness_bundle = $script:i04HarnessBundle
            candidate = [ordered]@{
                commit = $candidate.commit
                version = $candidate.version
                emule_sha256 = $candidate.emule_sha256
                process_emule_sha256 = Get-LabSha256 -Path $sourceExe
                package_zip_sha256 = $candidate.package_zip_sha256
                package_manifest_sha256 =
                    $candidate.package_manifest_sha256
                prepared_code_binding = $sourceCodeBinding
            }
            peer = $peerEvidence
            endpoint = [ordered]@{
                hostname = $canonicalHostname
                ipv4 = $peerV4Text
                local_ipv4 = $peerLocalV4Text
                ipv6 = $peerV6Text
                tcp_port = $PeerTcpPort
                dual_stack_listener = $true
                ipv6_bind_preference = $peerV6Text
                hello_ipv6_advertisement_configured = $true
            }
            coordinator = [ordered]@{
                ipv4 = $coordinatorV4Text
                ipv6 = $coordinatorV6Text
            }
            process = [ordered]@{
                id = $source.Id
                executable_sha256 = Get-LabSha256 -Path $sourceExe
                source_mode = 'non-headless'
                persisted_identity = $sourceIdentityInitial
                runtime_identity = [string]$sourceRuntimeInitial.user_hash
                controlled_server_login = $serverLoginInitial
            }
            fixtures = [ordered]@{
                a = $fixtureA
                b = $fixtureB
                unique_sha256 =
                    [string]$fixtureA.sha256 -ne [string]$fixtureB.sha256
            }
            ed2k = [ordered]@{
                a = [ordered]@{
                    base_link = $sharedA.link
                    hash = $sharedA.ed2k_hash
                }
                b = [ordered]@{
                    base_link = $sharedB.link
                    hash = $sharedB.ed2k_hash
                }
                unique_hash =
                    [string]$sharedA.ed2k_hash -ne
                        [string]$sharedB.ed2k_hash
                controlled_server = [ordered]@{
                    profile = $controlledProfile
                    login = $serverLoginInitial
                    minimum_logins_required_across_restart = 2
                }
            }
            controls = [ordered]@{
                inbound_ipv6_drop_is_remote = $true
                drop_action = 'Block'
                rejection_rule_created = $false
                allow4_rule_provisional = $allow4Evidence
                allow6_rule = $allow6Evidence
            }
            port_preflight = $peerPortPreflight
            runtime_isolation = $sourceRuntimeInitial
        }
        Write-LabJson -Value $ready -Path $readyPath | Out-Null

        $control = Wait-I04PeerControl -ArmPath $armPath `
            -StopPath $stopPath -TimeoutSeconds $ScenarioTimeoutSeconds
        if ($null -eq $control) {
            throw 'Coordinator sent neither arm nor stop within the bounded wait'
        }
        if ([string]$control.data.run_nonce -ne
            $RunNonce.ToLowerInvariant()) {
            throw 'Peer received a control command for a different run'
        }
        if ($control.kind -eq 'stop' -and (
            [string]$control.data.schema -ne
                'ese.v91.i04-stop-command/v1' -or
            [string]$control.data.case_id -ne $caseId -or
            [string]$control.data.action -ne 'stop-and-restore' -or
            [string]$control.data.candidate_commit -ne $candidate.commit -or
            [string]$control.data.candidate_emule_sha256 -ne $expectedHash
        )) {
            throw 'Peer received an invalid stop command'
        }

        if ($control.kind -eq 'arm') {
            $arm = $control.data
            if ([string]$arm.schema -ne 'ese.v91.i04-arm-command/v1' -or
                [string]$arm.case_id -ne $caseId -or
                [string]$arm.action -ne 'arm-remote-silent-drop' -or
                [string]$arm.run_nonce -ne $RunNonce.ToLowerInvariant() -or
                [string]$arm.candidate_commit -ne $candidate.commit -or
                [string]$arm.candidate_emule_sha256 -ne $expectedHash -or
                [int]$arm.expected_source_process_id -ne $source.Id -or
                [string]$arm.expected_peer_ipv4 -ne $peerV4Text -or
                [string]$arm.expected_peer_ipv6 -ne $peerV6Text -or
                [int]$arm.expected_peer_tcp_port -ne $PeerTcpPort) {
                throw 'Peer received an invalid arm command'
            }
            $armPrewarmTuples = @($arm.prewarm_tuples)
            $armPrewarmExact = $armPrewarmTuples.Count -gt 0 -and
                @($armPrewarmTuples | Where-Object {
                    [string]$_.state -ne 'Established' -or
                    (Get-I04NormalizedIp -Address ([string]$_.remote_address)) -ne
                        $peerV4Text -or
                    [int]$_.remote_port -ne $PeerTcpPort
                }).Count -eq 0
            if (-not $armPrewarmExact) {
                throw 'Peer received invalid prewarm tuple evidence'
            }

            $oldPid = $source.Id
            $source.Refresh()
            $oldListeners = @(
                Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                    [string]$_.State -eq 'Listen' -and
                    [int]$_.LocalPort -eq $PeerTcpPort -and
                    [int]$_.OwningProcess -eq $oldPid
                }
            )
            $prewarmInbound = @(
                Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                        [string]$_.State -eq 'Established' -and
                        [int]$_.LocalPort -eq $PeerTcpPort -and
                        [int]$_.OwningProcess -eq $oldPid -and
                        (Get-I04NormalizedIp -Address $_.LocalAddress) -eq
                            $peerLocalV4Text -and
                        -not (
                            Get-I04NormalizedIp -Address $_.RemoteAddress
                        ).Contains(':')
                    }
            )
            $oldDualListener = @($oldListeners | Where-Object {
                (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
            }).Count -gt 0
            if ($source.HasExited -or
                (Get-LabSha256 -Path $source.Path) -ne $expectedHash -or
                -not $oldDualListener -or $prewarmInbound.Count -ne 1) {
                throw 'Old peer source/prewarm was not alive at the DROP barrier'
            }
            $observedCoordinatorV4 = Get-I04NormalizedIp -Address (
                [string]$prewarmInbound[0].RemoteAddress
            )
            $observedCoordinatorPort = [int]$prewarmInbound[0].RemotePort
            if (-not (Test-I04UsableLocalIPv4 `
                -Address $observedCoordinatorV4)) {
                throw 'Peer observed an inadmissible post-NAT IPv4 source'
            }
            $peerRouteV4Observed = Get-I04RouteEvidence `
                -RemoteAddress $observedCoordinatorV4
            if (-not [bool]$peerRouteV4Observed.available -or
                -not [bool]$peerRouteV4Observed.physical_nonvirtual -or
                [int]$peerRouteV4Observed.interface_index -ne
                    [int]$assignedV4.InterfaceIndex -or
                [string]$peerRouteV4Observed.source_address -ne
                    $peerLocalV4Text) {
                throw 'Peer observed IPv4 client is not reached over the native physical data-plane adapter'
            }

            # The peer can only know the post-NAT remote endpoint.  First allow
            # any remote IPv4 long enough to observe the unique established
            # prewarm, then atomically replace it with that observed IP.  The
            # remote port deliberately remains Any because NAT may rewrite it.
            $provisionalRule = @(
                Get-NetFirewallRule -PolicyStore ActiveStore `
                    -ErrorAction Stop | Where-Object {
                    [string]$_.Name -eq $allow4RuleName
                }
            )
            $provisionalEvidence = Get-I04FirewallRuleEvidence `
                -DisplayName $allow4Rule -Action Allow -Program $sourceExe `
                -LocalAddresses @($peerLocalV4Text) `
                -RemoteAddresses @('Any') -LocalPort $PeerTcpPort
            if ($provisionalRule.Count -ne 1 -or
                [string]$provisionalRule[0].Name -ne $allow4RuleName -or
                [string]$provisionalRule[0].DisplayName -ne $allow4Rule -or
                -not [bool]$provisionalEvidence.exact) {
                throw 'Provisional IPv4 allow rule lost exact nonce-scoped ownership before replacement'
            }
            Remove-NetFirewallRule -Name $allow4RuleName -ErrorAction Stop
            New-NetFirewallRule `
                -Name $allow4RuleName -DisplayName $allow4Rule `
                -Direction Inbound -Action Allow -Program $sourceExe `
                -Protocol TCP -LocalAddress $peerLocalV4Text `
                -LocalPort $PeerTcpPort `
                -RemoteAddress $observedCoordinatorV4 `
                -Profile Any -Enabled True | Out-Null
            Add-I04Journal -Path $journal -Mutation 'peer-firewall-allow4' `
                -State 'narrowed' `
                -Detail (
                    "observed_post_nat_remote=$observedCoordinatorV4;" +
                    " remote_port_any; prewarm_remote_port=" +
                    "$observedCoordinatorPort"
                )

            New-NetFirewallRule -Name $dropRuleName -DisplayName $dropRule `
                -Direction Inbound `
                -Action Block -Program $sourceExe -Protocol TCP `
                -LocalAddress $peerV6Text -LocalPort $PeerTcpPort `
                -RemoteAddress $coordinatorV6Text `
                -Profile Any -Enabled True | Out-Null
            $dropEvidence = Get-I04FirewallRuleEvidence `
                -DisplayName $dropRule -Action Block -Program $sourceExe `
                -LocalAddresses @($peerV6Text) `
                -RemoteAddresses @($coordinatorV6Text) `
                -LocalPort $PeerTcpPort
            $allow4Evidence = Get-I04FirewallRuleEvidence `
                -DisplayName $allow4Rule -Action Allow -Program $sourceExe `
                -LocalAddresses @($peerLocalV4Text) `
                -RemoteAddresses @($observedCoordinatorV4) `
                -LocalPort $PeerTcpPort
            $allow6Evidence = Get-I04FirewallRuleEvidence `
                -DisplayName $allow6Rule -Action Allow -Program $sourceExe `
                -LocalAddresses @($peerV6Text) `
                -RemoteAddresses @($coordinatorV6Text) `
                -LocalPort $PeerTcpPort
            $source.Refresh()
            $listenersAfterDrop = @(
                Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                    [string]$_.State -eq 'Listen' -and
                    [int]$_.LocalPort -eq $PeerTcpPort -and
                    [int]$_.OwningProcess -eq $oldPid
                }
            )
            $dualStackStillAlive = @($listenersAfterDrop | Where-Object {
                (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
            }).Count -gt 0
            $prewarmStillAlive = @(
                Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                        [string]$_.State -eq 'Established' -and
                        [int]$_.LocalPort -eq $PeerTcpPort -and
                        [int]$_.OwningProcess -eq $oldPid -and
                        (Get-I04NormalizedIp -Address $_.RemoteAddress) -eq
                            $observedCoordinatorV4 -and
                        [int]$_.RemotePort -eq $observedCoordinatorPort
                    }
            ).Count -gt 0
            if (-not $dropEvidence.exact -or
                -not $allow4Evidence.exact -or
                -not $allow6Evidence.exact -or
                $source.HasExited -or -not $dualStackStillAlive -or
                -not $prewarmStillAlive -or
                (Get-LabSha256 -Path $source.Path) -ne $expectedHash) {
                throw 'DROP/allow rules or old source/prewarm failed exact armed verification'
            }
            $peerFirewallArmedSnapshot = Get-I04GlobalFirewallSnapshot
            $armedAt = [DateTime]::UtcNow
            Add-I04Journal -Path $journal -Mutation 'peer-ipv6-silent-drop' `
                -State 'applied' -Detail $dropRule
            Write-LabJson -Value ([ordered]@{
                schema = 'ese.v91.i04-peer-drop-armed/v1'
                case_id = $caseId
                run_nonce = $RunNonce.ToLowerInvariant()
                candidate_commit = $candidate.commit
                candidate_emule_sha256 = $candidate.emule_sha256
                armed_at_utc = $armedAt.ToString('o')
                source_process_id = $oldPid
                source_process_alive = $true
                source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
                dual_stack_listener_alive = $dualStackStillAlive
                prewarm_connection_alive = $prewarmStillAlive
                observed_ipv4_client = [ordered]@{
                    address = $observedCoordinatorV4
                    port = $observedCoordinatorPort
                    comparison_to_manifest_coordinator_ipv4 =
                        'intentionally_not_required_due_to_nat'
                    firewall_remote_port = 'Any'
                }
                route_to_observed_ipv4_client = $peerRouteV4Observed
                allow4_rule = $allow4Evidence
                allow6_rule = $allow6Evidence
                drop_rule = $dropEvidence
                global_firewall_armed = $peerFirewallArmedSnapshot
                semantic = 'remote inbound WFP DROP; no local reject/reset rule'
            }) -Path $armedPath | Out-Null

            $quiesceControl = Wait-I04RestartControl `
                -RestartPath $quiescePath -StopPath $stopPath `
                -TimeoutSeconds $ScenarioTimeoutSeconds
            if ($null -eq $quiesceControl) {
                throw 'Coordinator sent neither quiesce nor stop after DROP was armed'
            }
            if ([string]$quiesceControl.data.run_nonce -ne
                $RunNonce.ToLowerInvariant()) {
                throw 'Peer received post-arm control for a different run'
            }
            if ($quiesceControl.kind -eq 'stop' -and (
                [string]$quiesceControl.data.schema -ne
                    'ese.v91.i04-stop-command/v1' -or
                [string]$quiesceControl.data.case_id -ne $caseId -or
                [string]$quiesceControl.data.action -ne 'stop-and-restore' -or
                [string]$quiesceControl.data.candidate_commit -ne
                    $candidate.commit -or
                [string]$quiesceControl.data.candidate_emule_sha256 -ne
                    $expectedHash
            )) {
                throw 'Peer received an invalid post-arm stop command'
            }
            if ($quiesceControl.kind -eq 'restart') {
                $quiesce = $quiesceControl.data
                if ([string]$quiesce.schema -ne
                        'ese.v91.i04-quiesce-command/v1' -or
                    [string]$quiesce.case_id -ne $caseId -or
                    [string]$quiesce.action -ne
                        'stop-source-under-drop' -or
                    [string]$quiesce.candidate_commit -ne
                        $candidate.commit -or
                    [string]$quiesce.candidate_emule_sha256 -ne
                        $expectedHash -or
                    [int]$quiesce.expected_old_process_id -ne $oldPid) {
                    throw 'Peer received an invalid quiesce barrier command'
                }
                $source.Refresh()
                $prewarmAtQuiesce = @(
                    Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                            [string]$_.State -eq 'Established' -and
                            [int]$_.LocalPort -eq $PeerTcpPort -and
                            [int]$_.OwningProcess -eq $oldPid -and
                            (Get-I04NormalizedIp -Address $_.RemoteAddress) -eq
                                $observedCoordinatorV4 -and
                            [int]$_.RemotePort -eq $observedCoordinatorPort
                        }
                ).Count -gt 0
                if ($source.HasExited -or -not $prewarmAtQuiesce -or
                    (Get-LabSha256 -Path $source.Path) -ne $expectedHash) {
                    throw 'Old source/prewarm did not survive to quiesce release'
                }
                $sourceIdentityBeforeRestart = Get-I04PersistedUserHash `
                    -NodePath $sourceNode
                if ([string]$sourceIdentityBeforeRestart.user_hash -ne
                    [string]$sourceIdentityInitial.user_hash) {
                    throw 'Peer persisted identity changed before the controlled restart'
                }
                if (-not (Stop-I04OwnedProcess -Process $source `
                    -ExpectedPath $sourceExe -ForceImmediate)) {
                    throw 'Peer source could not be stopped safely at quiesce barrier'
                }
                Add-I04RollbackJournal -Path $journal `
                    -Mutation 'peer-process' -State 'rolled_back' `
                    -Detail "old_pid=$oldPid quiesced under DROP" `
                    -CleanupFailures $cleanupFailures
                $source = $null

                $oldTupleGoneDeadline =
                    [DateTime]::UtcNow.AddSeconds(30)
                do {
                    $oldSockets = @(
                        Get-NetTCPConnection -ErrorAction Stop |
                            Where-Object { [int]$_.OwningProcess -eq $oldPid }
                    )
                    if ($oldSockets.Count -eq 0) { break }
                    Start-Sleep -Milliseconds 100
                } while ([DateTime]::UtcNow -lt $oldTupleGoneDeadline)
                $oldOwnedProcess = @($peerOwnedProcesses.ToArray() |
                    Where-Object {
                    $_.PSObject.Properties.Name -contains 'i04_owner_pid' -and
                    [int]$_.i04_owner_pid -eq $oldPid
                } | Select-Object -Last 1)
                $oldProcessStillAlive = $oldOwnedProcess.Count -ne 1
                if ($oldOwnedProcess.Count -eq 1) {
                    $oldOwnedProcess[0].Refresh()
                    $oldProcessStillAlive = -not $oldOwnedProcess[0].HasExited
                }
                if ($oldSockets.Count -ne 0 -or $oldProcessStillAlive) {
                    throw 'Old peer PID/tuple remained after quiesce'
                }
                $quiescedAt = [DateTimeOffset]::UtcNow
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i04-peer-quiesced/v1'
                    case_id = $caseId
                    run_nonce = $RunNonce.ToLowerInvariant()
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $candidate.emule_sha256
                    quiesced_at_utc = $quiescedAt.ToString('o')
                    quiesced_epoch_ms =
                        Get-I04EpochMilliseconds -Timestamp $quiescedAt
                    old_process_id = $oldPid
                    old_process_absent = $true
                    old_listener_and_tuple_absent = $true
                    drop_rule = $dropEvidence
                    allow4_rule = $allow4Evidence
                    allow6_rule = $allow6Evidence
                }) -Path $quiescedPath | Out-Null

                $restartControl = Wait-I04RestartControl `
                    -RestartPath $restartPath -StopPath $stopPath `
                    -TimeoutSeconds $ScenarioTimeoutSeconds
                if ($null -eq $restartControl) {
                    throw 'Coordinator sent neither restart nor stop after quiesce'
                }
                if ([string]$restartControl.data.run_nonce -ne
                    $RunNonce.ToLowerInvariant()) {
                    throw 'Peer received post-quiesce control for another run'
                }
                if ($restartControl.kind -eq 'stop') {
                    if ([string]$restartControl.data.schema -ne
                            'ese.v91.i04-stop-command/v1' -or
                        [string]$restartControl.data.case_id -ne $caseId -or
                        [string]$restartControl.data.action -ne
                            'stop-and-restore') {
                        throw 'Peer received invalid stop after quiesce'
                    }
                    throw 'I04 coordinator stopped after peer quiesce'
                }
                $restart = $restartControl.data
                if ([string]$restart.schema -ne
                        'ese.v91.i04-restart-command/v1' -or
                    [string]$restart.case_id -ne $caseId -or
                    [string]$restart.action -ne
                        'restart-source-under-drop' -or
                    [string]$restart.candidate_commit -ne
                        $candidate.commit -or
                    [string]$restart.candidate_emule_sha256 -ne
                        $expectedHash -or
                    [int]$restart.expected_old_process_id -ne $oldPid -or
                    -not [bool]$restart.scheduler_floor_satisfied) {
                    throw 'Peer received an invalid restart barrier command'
                }
                $restartWatch = [Diagnostics.Stopwatch]::StartNew()
                $restarted = Start-PeerSource -RestartWatch $restartWatch `
                    -RequireEd2k -MinimumServerLogin 2
                $restartElapsedMs = [Int64]$restarted.listener_ready_elapsed_ms
                $restartWatch.Stop()
                $source = $restarted.process
                $newPid = $source.Id
                $sourceRuntimeResumed = $restarted.api
                $serverLoginResumed =
                    $restarted.controlled_server_login
                $sourceIdentityAfterRestart = Get-I04PersistedUserHash `
                    -NodePath $sourceNode
                $dualStackListenerReady = @($restarted.listeners |
                    Where-Object {
                        (Get-I04NormalizedIp -Address $_.LocalAddress) -eq '::'
                    }).Count -gt 0
                $dropEvidence = Get-I04FirewallRuleEvidence `
                    -DisplayName $dropRule -Action Block -Program $sourceExe `
                    -LocalAddresses @($peerV6Text) `
                    -RemoteAddresses @($coordinatorV6Text) `
                    -LocalPort $PeerTcpPort
                $allow4Evidence = Get-I04FirewallRuleEvidence `
                    -DisplayName $allow4Rule -Action Allow `
                    -Program $sourceExe `
                    -LocalAddresses @($peerLocalV4Text) `
                    -RemoteAddresses @($observedCoordinatorV4) `
                    -LocalPort $PeerTcpPort
                $allow6Evidence = Get-I04FirewallRuleEvidence `
                    -DisplayName $allow6Rule -Action Allow `
                    -Program $sourceExe `
                    -LocalAddresses @($peerV6Text) `
                    -RemoteAddresses @($coordinatorV6Text) `
                    -LocalPort $PeerTcpPort
                if ($newPid -eq $oldPid -or
                    (Get-LabSha256 -Path $source.Path) -ne $expectedHash -or
                    [string]$sourceIdentityAfterRestart.user_hash -ne
                        [string]$sourceIdentityInitial.user_hash -or
                    [string]$sourceRuntimeResumed.user_hash -ne
                        [string]$sourceIdentityInitial.user_hash -or
                    [string]$serverLoginResumed.runtime_user_hash -ne
                        [string]$sourceIdentityInitial.user_hash -or
                    [int]$serverLoginResumed.login_count -lt 2 -or
                    -not $dualStackListenerReady -or
                    -not $dropEvidence.exact -or
                    -not $allow4Evidence.exact -or
                    -not $allow6Evidence.exact) {
                    throw 'Restarted source failed PID/hash/identity/eD2K/listener/firewall verification'
                }
                Add-I04Journal -Path $journal -Mutation 'peer-process' `
                    -State 'applied' -Detail "new_pid=$newPid after DROP"
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i04-peer-resumed/v1'
                    case_id = $caseId
                    run_nonce = $RunNonce.ToLowerInvariant()
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $candidate.emule_sha256
                    resumed_at_utc = Get-LabUtcTimestamp
                    old_process_id = $oldPid
                    process_id = $newPid
                    process_emule_sha256 = Get-LabSha256 -Path $source.Path
                    stop_to_listener_ready_ms = $restartElapsedMs
                    restart_readiness_limit_ms = 90000
                    restart_within_readiness_limit =
                        $restartElapsedMs -le 90000
                    dual_stack_listener = $true
                    ipv4_capable_dual_stack_listener = $dualStackListenerReady
                    persisted_identity = $sourceIdentityAfterRestart
                    runtime_identity =
                        [string]$sourceRuntimeResumed.user_hash
                    runtime_isolation = $sourceRuntimeResumed
                    controlled_server_login = $serverLoginResumed
                    same_persisted_user_hash =
                        [string]$sourceIdentityAfterRestart.user_hash -eq
                            [string]$sourceIdentityInitial.user_hash
                    allow4_rule = $allow4Evidence
                    allow6_rule = $allow6Evidence
                    drop_rule = $dropEvidence
                }) -Path $resumedPath | Out-Null
                if ($restartElapsedMs -gt 90000) {
                    throw "Restart readiness exceeded 90 seconds: $restartElapsedMs ms"
                }

                $stop = Wait-I04StopWhileProcessAlive -StopPath $stopPath `
                    -TimeoutSeconds $ScenarioTimeoutSeconds -Process $source `
                    -ExpectedPath $sourceExe
                if ($null -eq $stop) {
                    throw 'Coordinator did not send the stop command within the bounded wait'
                }
                if ([string]$stop.run_nonce -ne $RunNonce.ToLowerInvariant()) {
                    throw 'Peer received a stop command for a different run'
                }
                if ([string]$stop.schema -ne
                        'ese.v91.i04-stop-command/v1' -or
                    [string]$stop.case_id -ne $caseId -or
                    [string]$stop.action -ne 'stop-and-restore' -or
                    [string]$stop.candidate_commit -ne $candidate.commit -or
                    [string]$stop.candidate_emule_sha256 -ne $expectedHash) {
                    throw 'Peer received an invalid final stop command'
                }
            }
        }
    } catch {
        $runtimeFailure = $_
    } finally {
        if ($null -ne $peerFirewallArmedSnapshot) {
            try {
                $peerFirewallPreRemovalSnapshot =
                    Get-I04GlobalFirewallSnapshot
                $peerFirewallScenarioUnchanged =
                    [string]$peerFirewallPreRemovalSnapshot.canonical_sha256 -ceq
                        [string]$peerFirewallArmedSnapshot.canonical_sha256
                if (-not $peerFirewallScenarioUnchanged) {
                    $cleanupFailures.Add(
                        'global firewall inventory drifted while the peer scenario was armed'
                    )
                }
            } catch {
                $cleanupFailures.Add((Get-I04SafeErrorToken `
                    -Context 'peer pre-removal firewall snapshot failed' `
                    -Message $_.Exception.Message))
            }
        }
        foreach ($ownedPeerProcess in @(
            $peerOwnedProcesses | Sort-Object Id -Unique
        )) {
            if (-not (Stop-I04OwnedProcess -Process $ownedPeerProcess `
                -ExpectedPath $sourceExe)) {
                $cleanupFailures.Add(
                    "peer owned process $($ownedPeerProcess.Id) could not be stopped safely"
                )
            } else {
                Add-I04RollbackJournal -Path $journal `
                    -Mutation 'peer-process' -State 'rolled_back' `
                    -Detail "pid=$($ownedPeerProcess.Id)" `
                    -CleanupFailures $cleanupFailures
            }
        }
        $controlledServerStop =
            Stop-I04ControlledEd2kServerInventory `
                -OwnerInventory $controlledServersOwned `
                -PrimaryServer $controlledServer
        if (-not [bool]$controlledServerStop.stopped -or
            [string]$controlledServerStop.error) {
            $cleanupFailures.Add(
                "peer controlled eD2K server cleanup failed: " +
                [string]$controlledServerStop.error
            )
        }
        if ($firewallNamesOwned) {
            foreach ($ownedRule in @(
                [pscustomobject]@{
                    name = $dropRuleName
                    display = $dropRule
                    mutation = 'peer-ipv6-silent-drop'
                    action = 'Block'
                    local_addresses = @($peerV6Text)
                    remote_addresses = @($coordinatorV6Text)
                },
                [pscustomobject]@{
                    name = $allow6RuleName
                    display = $allow6Rule
                    mutation = 'peer-firewall-allow6'
                    action = 'Allow'
                    local_addresses = @($peerV6Text)
                    remote_addresses = @($coordinatorV6Text)
                },
                [pscustomobject]@{
                    name = $allow4RuleName
                    display = $allow4Rule
                    mutation = 'peer-firewall-allow4'
                    action = 'Allow'
                    local_addresses = @($peerLocalV4Text)
                    remote_addresses = if ($observedCoordinatorV4) {
                        @($observedCoordinatorV4)
                    } else { @('Any') }
                }
            )) {
                try {
                    $existing = @(
                        Get-NetFirewallRule -PolicyStore ActiveStore `
                            -ErrorAction Stop | Where-Object {
                                [string]$_.Name -eq $ownedRule.name
                            }
                    )
                    if ($existing.Count -gt 1) {
                        throw 'firewall ownership query returned multiple rules'
                    }
                    if ($existing.Count -eq 1) {
                        if ([string]$existing[0].Name -ne $ownedRule.name -or
                            [string]$existing[0].DisplayName -ne
                                $ownedRule.display) {
                            throw 'firewall rule name/display ownership changed'
                        }
                        $ownedEvidence = Get-I04FirewallRuleEvidence `
                            -DisplayName $ownedRule.display `
                            -Action $ownedRule.action -Program $sourceExe `
                            -LocalAddresses $ownedRule.local_addresses `
                            -RemoteAddresses $ownedRule.remote_addresses `
                            -LocalPort $PeerTcpPort
                        if (-not [bool]$ownedEvidence.exact) {
                            throw 'firewall rule content no longer matches its owned nonce-scoped definition'
                        }
                        Remove-NetFirewallRule -Name $ownedRule.name `
                            -ErrorAction Stop
                    }
                    $remaining = @(
                        Get-NetFirewallRule -PolicyStore ActiveStore `
                            -ErrorAction Stop | Where-Object {
                                [string]$_.Name -eq $ownedRule.name
                            }
                    )
                    if ($remaining.Count -ne 0) {
                        throw "firewall Name '$($ownedRule.name)' remains after removal"
                    }
                    Add-I04RollbackJournal -Path $journal `
                        -Mutation $ownedRule.mutation -State 'rolled_back' `
                        -Detail $ownedRule.display `
                        -CleanupFailures $cleanupFailures
                } catch {
                    $cleanupFailures.Add((Get-I04SafeErrorToken `
                        -Context "firewall cleanup failed for $($ownedRule.name)" `
                        -Message $_.Exception.Message))
                }
            }
        }
    }

    try {
        $firewallAfter = @(
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
        )
        $dropStillPresent = @($firewallAfter | Where-Object {
            [string]$_.Name -eq $dropRuleName
        }).Count -ne 0
        $allow4StillPresent = @($firewallAfter | Where-Object {
            [string]$_.Name -eq $allow4RuleName
        }).Count -ne 0
        $allow6StillPresent = @($firewallAfter | Where-Object {
            [string]$_.Name -eq $allow6RuleName
        }).Count -ne 0
    } catch {
        $dropStillPresent = $true
        $allow4StillPresent = $true
        $allow6StillPresent = $true
        $cleanupFailures.Add((Get-I04SafeErrorToken `
            -Context 'firewall absence could not be verified' `
            -Message $_.Exception.Message))
    }
    if ($dropStillPresent) { $cleanupFailures.Add('DROP rule is still present') }
    if ($allow4StillPresent) {
        $cleanupFailures.Add('allow4 rule is still present')
    }
    if ($allow6StillPresent) {
        $cleanupFailures.Add('allow6 rule is still present')
    }
    try {
        $null = Assert-I04CandidateBindingUnchanged -Binding $candidate
    } catch {
        $cleanupFailures.Add((Get-I04SafeErrorToken `
            -Context 'peer candidate binding changed during execution' `
            -Message $_.Exception.Message))
    }
    $peerIsolationFinal = Get-I04IsolationEvidence
    Write-LabJson -Value $peerIsolationFinal -Path (
        Join-Path $evidence 'peer-isolation-final.json'
    ) | Out-Null
    if (-not [bool]$peerIsolationFinal.strict_isolation_valid) {
        $cleanupFailures.Add(
            'peer overlay/VPN/proxy isolation was not intact at final audit'
        )
    }
    $peerOwnedProcessIds = @(
        $peerOwnedProcesses | ForEach-Object { [int]$_.Id } |
            Sort-Object -Unique
    )
    $peerTerminalCensus = Get-I04TerminalOwnershipCensus `
        -ProcessIds $peerOwnedProcessIds `
        -OwnedProcesses ([object[]]$peerOwnedProcesses.ToArray()) `
        -Ports @($PeerTcpPort, $PeerUdpPort, $PeerWebPort) `
        -HostRole 'Peer'
    if (-not [bool]$peerTerminalCensus.collector_ok -or
        -not [bool]$peerTerminalCensus.all_clear) {
        $cleanupFailures.Add(
            'peer terminal process/TCP/UDP ownership census was not clear'
        )
    }
    $peerAccountRegistryPostcheck =
        Get-I04AccountRegistryPostcheckEvidence `
            -Transaction $script:i04AccountRegistryTransaction
    $script:i04AccountRegistryPostcheck = $peerAccountRegistryPostcheck
    $script:i04AccountRegistryPostcheckComplete = $true
    if (-not [bool]$peerAccountRegistryPostcheck.safe_to_pass) {
        $cleanupFailures.Add(
            'peer account/registry/global-firewall postcheck was not exact'
        )
    }
    $restrictedJobLeaseCleanup =
        Complete-I04RestrictedJobLeaseCleanup -Context Peer
    if (-not [bool]$restrictedJobLeaseCleanup.complete) {
        $cleanupFailures.Add(
            'peer restricted Job Object leases were not terminally released'
        )
    }
    $cleanup = [ordered]@{
        schema = 'ese.v91.i04-peer-cleanup/v1'
        captured_at_utc = Get-LabUtcTimestamp
        source_process_stopped = [bool]$peerTerminalCensus.collector_ok -and
            @($peerTerminalCensus.remaining_processes).Count -eq 0
        source_process_ids = $peerOwnedProcessIds
        terminal_ownership_census = $peerTerminalCensus
        drop_rule_present = $dropStillPresent
        allow4_rule_present = $allow4StillPresent
        allow6_rule_present = $allow6StillPresent
        controlled_ed2k_server_stopped =
            $null -ne $controlledServerStop -and
            [bool]$controlledServerStop.stopped -and
            -not [string]$controlledServerStop.error
        hosts_file_modified = $false
        dns_cache_modified = $false
        routes_modified = $false
        adapters_modified = $false
        isolation_initial = $peerIsolationInitial
        isolation_final = $peerIsolationFinal
        account_registry_transaction = $peerAccountRegistryPostcheck
        restricted_job_lease_cleanup = $restrictedJobLeaseCleanup
        global_firewall_armed = $peerFirewallArmedSnapshot
        global_firewall_pre_removal = $peerFirewallPreRemovalSnapshot
        global_firewall_scenario_unchanged = $peerFirewallScenarioUnchanged
        retained_by_design = @('peer OutputRoot profile', 'fixture', 'evidence')
        failures = @($cleanupFailures.ToArray())
    }
    Write-LabJson -Value $cleanup -Path $cleanupPath | Out-Null
    $peerResult = [ordered]@{
        schema = 'ese.v91.i04-peer-result/v1'
        case_id = $caseId
        run_nonce = $RunNonce.ToLowerInvariant()
        finished_at_utc = Get-LabUtcTimestamp
        harness_bundle = $script:i04HarnessBundle
        status = if ($null -eq $runtimeFailure -and
            $cleanupFailures.Count -eq 0 -and -not $dropStillPresent -and
            -not $allow4StillPresent -and
            -not $allow6StillPresent -and
            [bool]$restrictedJobLeaseCleanup.complete) {
                'COMPLETE'
            } else { 'BLOCKED' }
        candidate_commit = $candidate.commit
        candidate_emule_sha256 = $candidate.emule_sha256
        old_process_id = $oldPid
        restarted_process_id = $newPid
        restart_stop_to_listener_ready_ms = $restartElapsedMs
        barrier_completed = $null -ne $newPid -and
            $null -ne $restartElapsedMs -and
            $restartElapsedMs -le 90000 -and
            $null -ne $serverLoginResumed -and
            [int]$serverLoginResumed.login_count -ge 2
        controlled_ed2k_server = $controlledServerStop
        remote_ipv6_drop_was_armed = $null -ne $armedAt
        drop_armed_at_utc = if ($null -eq $armedAt) {
            $null
        } else { $armedAt.ToString('o') }
        cleanup = $cleanup
        runtime_error = if ($null -eq $runtimeFailure) {
            $null
        } else {
            Get-I04SafeErrorToken -Context 'peer runtime failed' `
                -Message $runtimeFailure.Exception.Message
        }
        evidence_retained_locally = $true
    }
    Write-LabJson -Value $peerResult -Path $resultPath | Out-Null
    $script:i04PeerResultSha256 = Get-LabSha256 -Path $resultPath
    Write-LabJson -Value $peerResult `
        -Path (Join-Path $evidence 'peer-result.json') | Out-Null
    $password = $null

    if ($peerResult.status -ne 'COMPLETE') {
        throw "I04 peer phase is BLOCKED: $($peerResult.runtime_error)"
    }
    Write-Host "I04 peer phase complete and restored: $output" `
        -ForegroundColor Green
}

function Invoke-I04CoordinatorRole {
    if (-not (Test-I04Administrator)) {
        throw 'Coordinator role requires an elevated Administrator PowerShell for pktmon capture'
    }
    foreach ($captureCommand in @(
        'pktmon.exe', 'logman.exe', 'Get-NetTCPConnection',
        'Get-NetUDPEndpoint', 'Get-NetIPAddress', 'Get-NetAdapter',
        'Find-NetRoute', 'Get-NetFirewallRule', 'New-NetFirewallRule',
        'Remove-NetFirewallRule', 'Get-NetFirewallPortFilter',
        'Get-NetFirewallApplicationFilter',
        'Get-NetFirewallAddressFilter', 'Get-NetFirewallInterfaceFilter',
        'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallServiceFilter', 'Get-NetFirewallSecurityFilter'
    )) {
        if ($null -eq (Get-Command $captureCommand -ErrorAction SilentlyContinue)) {
            throw "Coordinator capture prerequisite is missing: $captureCommand"
        }
    }
    $null = Enter-I04PktmonGlobalMutex
    $existingPktmonSession = Get-I04EtwLossEvidence -SessionName 'PktMon'
    if ([bool]$existingPktmonSession.available) {
        throw 'Coordinator found an existing PktMon ETW session; stop its owner before V91-I04'
    }
    if ([UInt32]$existingPktmonSession.error_code -ne 4201) {
        throw "Coordinator could not prove the PktMon ETW session absent (Win32 $($existingPktmonSession.error_code))"
    }
    if (-not $RunNonce) {
        $script:RunNonce = [Guid]::NewGuid().ToString('N')
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $clientPortPreflight = Assert-I04PortsInitiallyFree `
        -Ports @($ClientTcpPort, $ClientUdpPort, $ClientWebPort) `
        -HostRole 'Coordinator'
    $outputPath = Assert-I04SafeCreationPath -Path $OutputRoot
    if (Test-Path -LiteralPath $outputPath) {
        $null = Assert-I04NoReparsePath -Path $outputPath -Kind Directory
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Coordinator OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $null = Assert-I04NoReparsePath -Path $output -Kind Directory
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $captureEvidence = New-LabDirectory -Path (Join-Path $evidence 'capture')
    $journal = Join-Path $evidence 'mutation-journal.jsonl'
    $samplesPath = Join-Path $evidence 'runtime-samples.jsonl'
    $socketSamplesPath = Join-Path $evidence 'socket-samples.ndjson'
    $summaryPath = Join-Path $evidence 'summary.json'
    $publicSummaryPath = Join-Path $evidence 'public-summary.json'
    $cleanupPath = Join-Path $evidence 'cleanup.json'
    $coordinationRootSafe = Assert-I04NoReparsePath `
        -Path $CoordinationRoot -Kind Directory
    $coordination = Get-LabFullPath -Path (Join-Path `
        -Path $coordinationRootSafe `
        -ChildPath "v91-i04-$nonce")
    if (Test-Path -LiteralPath $coordination) {
        throw "Coordinator run directory must be fresh/absent: $coordination"
    }
    $null = New-Item -ItemType Directory -Path $coordination -ErrorAction Stop
    $null = Assert-I04NoReparsePath -Path $coordination -Kind Directory
    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'peer-ready.json'
    $armPath = Join-Path $coordination 'arm-drop.json'
    $armedPath = Join-Path $coordination 'peer-drop-armed.json'
    $quiescePath = Join-Path $coordination 'quiesce.json'
    $quiescedPath = Join-Path $coordination 'peer-quiesced.json'
    $restartPath = Join-Path $coordination 'restart.json'
    $resumedPath = Join-Path $coordination 'peer-resumed.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $peerResultPath = Join-Path $coordination 'peer-result.json'
    $peerTerminalPath = Join-Path $coordination 'peer-terminal.json'
    $manualPath = Join-Path $evidence 'MANUAL-PEER-COMMAND.txt'

    $client = $null
    $clientOwnedProcesses =
        [System.Collections.Generic.List[object]]::new()
    $clientProcessesStopped = $false
    $clientPassword = New-I04EphemeralSecret
    $clientNode = ''
    $clientExe = ''
    $clientCodeBinding = $null
    $clientControlledServer = $null
    $clientControlledServersOwned =
        [System.Collections.Generic.List[object]]::new()
    $clientControlledServerStop = $null
    $clientIdentity = $null
    $clientRuntime = $null
    $clientServerLogin = $null
    $clientSession = ''
    $capture = $null
    $socketSampler = $null
    $socketSamplerEvidence = $null
    $remoteJob = $null
    $remoteJobTerminalExact = $PeerControlMode -ne 'PowerShellRemoting'
    $peerTerminal = $null
    $peerTerminalExact = $false
    $runtimeFailure = $null
    $candidatePostTriggerFailure = $null
    $failureDisposition = $null
    $caseArmed = $false
    $formalBoundaryPublished = $false
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    $blockedReasons = [Collections.Generic.List[string]]::new()
    $productFailures = [Collections.Generic.List[object]]::new()
    $peerReady = $null
    $peerArmed = $null
    $peerResumed = $null
    $peerResult = $null
    $peerReadyExact = $false
    $peerArmedExact = $false
    $peerResumedExact = $false
    $peerResultExact = $false
    $peerRestorationExact = $false
    $peerScenarioExact = $false
    $peerExact = $false
    $baselineV4 = $null
    $baselineV6 = $null
    $routeV4 = $null
    $routeV6 = $null
    $packetVerdict = $null
    $logBefore = $null
    $logAfter = $null
    $armCommandWritten = $false
    $stopCommandWritten = $false
    $prewarmEstablished = $false
    $prewarmProgress = $false
    $prewarmFirstEstablishedAt = $null
    $prewarmFirstEstablishedEpochMs = $null
    $schedulerFloorSatisfied = $false
    $fileAPreProgress = $null
    $fileAProgress = $null
    $fileBReady = $null
    $fileAPaused = $null
    $fileAStopped = $null
    $fileBAfterTrigger = $null
    $pauseOperation = $null
    $stopAOperation = $null
    $prewarmTuples = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $scenarioV4LocalPorts = New-Object 'Collections.Generic.HashSet[int]'
    $scenarioV6LocalPorts = New-Object 'Collections.Generic.HashSet[int]'
    $otherPidObserved = $false
    $otherPidConnections = [System.Collections.Generic.List[object]]::new()
    $scenarioV6SocketObserved = $false
    $scenarioV4SocketObserved = $false
    $scenarioV4Established = $false
    $apiProbeCount = 0
    $apiFailureCount = 0
    $apiMaxMs = 0L
    $uiProbeCount = 0
    $uiMissingCount = 0
    $uiFailureCount = 0
    $uiMaxMs = 0L
    $scenarioStarted = $null
    $scenarioFinished = $null
    $successObservedAt = $null
    $armRequestedEpochMs = $null
    $armRequestedQpc = $null
    $pauseBoundaryEpochMs = $null
    $pauseBoundaryQpc = $null
    $restartPreparationAt = $null
    $restartPreparationEpochMs = $null
    $restartPreparationQpc = $null
    $restartBoundaryEpochMs = $null
    $restartBoundaryQpc = $null
    $captureStoppedEpochMs = $null
    $apiTelemetryBaseline = $null
    $apiTelemetryTrigger = $null
    $apiTelemetryPeak = $null
    $apiTelemetryFinal = $null
    $telemetryObservedCurrentMax = 0L
    $telemetryObservedAddsMax = $null
    $telemetryObservedDuplicateMax = $null
    $telemetryObservedHighWaterMax = $null
    $clientIsolationExact = $false
    $coordinatorIsolationInitial = $null
    $coordinatorIsolationFinal = $null
    $coordinatorFirewallBeforeBoundary = $null
    $coordinatorFirewallAfterObservation = $null
    $coordinatorFirewallScenarioUnchanged = $false

    $localMachineId = Get-I04MachineId
    $coordinatorIsolationInitial = Get-I04IsolationEvidence
    Write-LabJson -Value $coordinatorIsolationInitial -Path (
        Join-Path $evidence 'coordinator-isolation-initial.json'
    ) | Out-Null
    if (-not [bool]$coordinatorIsolationInitial.strict_isolation_valid) {
        throw 'Coordinator has an active overlay/VPN adapter or proxy environment'
    }
    $routeV4 = Get-I04RouteEvidence -RemoteAddress $peerV4Text
    $routeV6 = Get-I04RouteEvidence -RemoteAddress $peerV6Text
    if (-not $routeV4.available -or -not $routeV6.available -or
        -not [bool]$routeV4.physical_nonvirtual -or
        -not [bool]$routeV6.physical_nonvirtual) {
        throw 'Coordinator cannot derive native physical IPv4 and IPv6 routes to the peer'
    }
    $coordinatorV4Value = if ([string]::IsNullOrWhiteSpace($CoordinatorIPv4)) {
        [string]$routeV4.source_address
    } else { $CoordinatorIPv4 }
    $coordinatorV6Value = if ([string]::IsNullOrWhiteSpace($CoordinatorIPv6)) {
        [string]$routeV6.source_address
    } else { $CoordinatorIPv6 }
    $coordinatorV4Address = Convert-I04RequiredAddress `
        -Value $coordinatorV4Value `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorIPv4'
    $coordinatorV6Address = Convert-I04RequiredAddress `
        -Value $coordinatorV6Value `
        -AddressFamily ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'CoordinatorIPv6'
    $coordinatorV4Text = $coordinatorV4Address.ToString()
    $coordinatorV6Text = $coordinatorV6Address.ToString()
    if ($coordinatorV4Address.Equals([Net.IPAddress]::Any) -or
        [Net.IPAddress]::IsLoopback($coordinatorV4Address) -or
        ($coordinatorV4Address.GetAddressBytes()[0] -ge 224 -and
            $coordinatorV4Address.GetAddressBytes()[0] -le 239) -or
        $coordinatorV6Address.Equals([Net.IPAddress]::IPv6Any) -or
        [Net.IPAddress]::IsLoopback($coordinatorV6Address) -or
        $coordinatorV6Address.IsIPv6Multicast -or
        $CoordinatorIPv6.Contains('%') -or
        (Get-I04StrictAddressClass -Address $coordinatorV6Text) -ne
            'native-global-v6' -or
        $coordinatorV4Text -eq $peerV4Text -or
        $coordinatorV6Text -eq $peerV6Text -or
        (Get-I04NormalizedIp -Address $routeV4.source_address) -ne
            $coordinatorV4Text -or
        (Get-I04NormalizedIp -Address $routeV6.source_address) -ne
            $coordinatorV6Text) {
        throw 'Coordinator source addresses must be exact non-loopback route sources distinct from the peer'
    }
    $coordinatorAssignedV4 = Get-NetIPAddress -AddressFamily IPv4 `
        -ErrorAction Stop | Where-Object {
            (Get-I04NormalizedIp -Address $_.IPAddress) -eq
                $coordinatorV4Text -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1
    $coordinatorAssignedV6 = Get-NetIPAddress -AddressFamily IPv6 `
        -ErrorAction Stop | Where-Object {
            (Get-I04NormalizedIp -Address $_.IPAddress) -eq
                $coordinatorV6Text -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1
    if ($null -eq $coordinatorAssignedV4 -or
        $null -eq $coordinatorAssignedV6 -or
        [int]$coordinatorAssignedV4.InterfaceIndex -ne
            [int]$coordinatorAssignedV6.InterfaceIndex) {
        throw 'Coordinator route sources must be Preferred addresses on one adapter'
    }
    $coordinatorAdapter = Get-NetAdapter `
        -InterfaceIndex $coordinatorAssignedV4.InterfaceIndex -ErrorAction Stop
    $coordinatorAdapterVirtual = $true
    if ($coordinatorAdapter.PSObject.Properties.Name -contains 'Virtual' -and
        $coordinatorAdapter.Virtual -is [bool]) {
        $coordinatorAdapterVirtual = [bool]$coordinatorAdapter.Virtual
    }
    $coordinatorAdapterOverlayLike =
        ([string]$coordinatorAdapter.Name) -match $overlayPattern -or
        ([string]$coordinatorAdapter.InterfaceDescription) -match
            $overlayPattern
    $coordinatorPhysical = [bool]$coordinatorAdapter.HardwareInterface -and
        -not $coordinatorAdapterVirtual -and
        -not $coordinatorAdapterOverlayLike -and
        ([string]$coordinatorAdapter.Status) -eq 'Up'
    if (-not $coordinatorPhysical) {
        throw 'Coordinator dual-stack data plane is not one Up physical, non-overlay adapter'
    }

    Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i04-run/v1'
        case_id = $caseId
        run_nonce = $nonce
        created_at_utc = Get-LabUtcTimestamp
        expected_candidate_commit = $candidate.commit
        expected_emule_sha256 = $expectedHash
        expected_package_zip_sha256 = $expectedZipHash
        expected_package_manifest_sha256 =
            $candidate.package_manifest_sha256
        harness_bundle = $script:i04HarnessBundle
        identity = [ordered]@{
            coordinator_machine_id_sha256 =
                $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant()
            peer_machine_id_sha256 =
                $ExpectedPeerMachineIdSha256.ToLowerInvariant()
            coordinator_user_sid_sha256 = $expectedCoordinatorSidHash
            peer_user_sid_sha256 = $expectedPeerSidHash
            disposable_accounts_operator_attested = $true
            manifest_creator = Get-I04HostIdentityEvidence
            account_registry_transaction =
                $script:i04AccountRegistryTransaction
        }
        peer = [ordered]@{
            hostname = $canonicalHostname
            ipv4 = $peerV4Text
            local_ipv4 = $peerLocalV4Text
            ipv6 = $peerV6Text
            tcp_port = $PeerTcpPort
            udp_port = $PeerUdpPort
            web_port = $PeerWebPort
        }
        client = [ordered]@{
            tcp_port = $ClientTcpPort
            udp_port = $ClientUdpPort
            web_port = $ClientWebPort
        }
        coordinator = [ordered]@{
            ipv4 = $coordinatorV4Text
            ipv6 = $coordinatorV6Text
            interface_index = [int]$coordinatorAssignedV4.InterfaceIndex
            physical = $coordinatorPhysical
            isolation = $coordinatorIsolationInitial
        }
        file_size_bytes = $FileSizeBytes
        file_b_size_bytes = $fileBSizeBytes
        scheduler_reconnect_floor_seconds =
            $schedulerReconnectFloorSeconds
        fallback_limit_seconds = $FallbackLimitSeconds
        expected_fallback_delay_ms = $expectedFallbackDelayMs
        capture_tolerance_ms = $captureTimingToleranceMs
        socket_clock_coherence_tolerance_ms =
            $socketClockCoherenceToleranceMs
        control_mode = $PeerControlMode
    }) -Path $runPath | Out-Null

    Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i04-pre-mutation/v1'
        captured_at_utc = Get-LabUtcTimestamp
        candidate = Get-I04CandidateEvidence -Binding $candidate
        local_machine_id_sha256 = $localMachineId
        operator_identity = Get-I04HostIdentityEvidence
        account_registry_transaction = $script:i04AccountRegistryTransaction
        port_preflight = $clientPortPreflight
        routes = @($routeV4, $routeV6)
        coordinator = [ordered]@{
            ipv4 = $coordinatorV4Text
            ipv6 = $coordinatorV6Text
            same_interface = [int]$coordinatorAssignedV4.InterfaceIndex -eq
                [int]$coordinatorAssignedV6.InterfaceIndex
            interface_status = [string]$coordinatorAdapter.Status
            hardware_interface = [bool]$coordinatorAdapter.HardwareInterface
            virtual = $coordinatorAdapterVirtual
            overlay_or_vpn_like = $coordinatorAdapterOverlayLike
            physical = $coordinatorPhysical
            isolation = $coordinatorIsolationInitial
        }
        preexisting_emule_process_count = $preexistingEmuleProcessCount
        preexisting_emule_process_absence_proved =
            $preexistingEmuleProcessCount -eq 0
        planned_mutations = @(
            'isolated client profile/process',
            'unique pktmon filters/global capture',
            'remote unique allow and IPv6 inbound Block rules',
            'remote controlled source restart'
        )
        forbidden_and_not_planned = @(
            'hosts file', 'DNS cache', 'routes', 'adapters',
            'test-only product endpoint', 'local IPv6 reject rule'
        )
    }) -Path (Join-Path $evidence 'pre-mutation.json') | Out-Null

    try {
        if ($PeerControlMode -eq 'PowerShellRemoting') {
            foreach ($required in @(
                $PeerComputerName, $RemoteScriptPath, $RemotePackagePath,
                $RemotePackageZipPath, $RemoteOutputRoot,
                $RemoteCoordinationRoot
            )) {
                if ([string]::IsNullOrWhiteSpace($required)) {
                    throw 'PowerShellRemoting requires PeerComputerName, RemoteScriptPath, RemotePackagePath, RemotePackageZipPath, RemoteOutputRoot and RemoteCoordinationRoot'
                }
            }
            $remoteArguments = @{
                Role = 'Peer'
                PackagePath = $RemotePackagePath
                PackageZipPath = $RemotePackageZipPath
                ExpectedPackageZipSha256 = $expectedZipHash
                ExpectedHarnessSha256 =
                    [string]$script:i04HarnessBundle.harness_sha256
                ExpectedCommonSha256 =
                    [string]$script:i04HarnessBundle.common_sha256
                ExpectedPrepareNodeSha256 =
                    [string]$script:i04HarnessBundle.prepare_node_sha256
                OutputRoot = $RemoteOutputRoot
                Commit = $candidate.commit
                ExpectedEmuleSha256 = $expectedHash
                PeerHostname = $canonicalHostname
                PeerIPv4 = $peerV4Text
                PeerLocalIPv4 = $peerLocalV4Text
                PeerIPv6 = $peerV6Text
                CoordinatorIPv4 = $coordinatorV4Text
                CoordinatorIPv6 = $coordinatorV6Text
                CoordinationRoot = $RemoteCoordinationRoot
                ControlledPeerAcknowledged = $true
                ExpectedCoordinatorMachineIdSha256 =
                    $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant()
                ExpectedPeerMachineIdSha256 =
                    $ExpectedPeerMachineIdSha256.ToLowerInvariant()
                ExpectedCoordinatorUserSidSha256 =
                    $expectedCoordinatorSidHash
                ExpectedPeerUserSidSha256 = $expectedPeerSidHash
                DisposableLabAccountAcknowledged = $true
                PeerTcpPort = $PeerTcpPort
                PeerUdpPort = $PeerUdpPort
                PeerWebPort = $PeerWebPort
                ClientTcpPort = $ClientTcpPort
                ClientUdpPort = $ClientUdpPort
                ClientWebPort = $ClientWebPort
                FileSizeBytes = $FileSizeBytes
                PeerReadyTimeoutSeconds = $PeerReadyTimeoutSeconds
                ScenarioTimeoutSeconds = $ScenarioTimeoutSeconds
                FallbackLimitSeconds = $FallbackLimitSeconds
                RunNonce = $nonce
            }
            $invoke = @{
                ComputerName = $PeerComputerName
                AsJob = $true
                ScriptBlock = {
                    param($ScriptPath, $ArgumentMap)
                    & $ScriptPath @ArgumentMap
                }
                ArgumentList = @($RemoteScriptPath, $remoteArguments)
            }
            if ($null -ne $PeerCredential) {
                $invoke.Credential = $PeerCredential
            }
            $remoteJob = Invoke-Command @invoke
        } else {
            $manualCommand = @"
Run this on the controlled physical peer while this coordinator waits:

& '<path-to-test_v91_i04_fallback.ps1>' ``
  -Role Peer ``
  -PackagePath '<exact-package-on-peer>' ``
  -PackageZipPath '<exact-package-zip-on-peer>' ``
  -ExpectedPackageZipSha256 '$expectedZipHash' ``
  -ExpectedHarnessSha256 '$([string]$script:i04HarnessBundle.harness_sha256)' ``
  -ExpectedCommonSha256 '$([string]$script:i04HarnessBundle.common_sha256)' ``
  -ExpectedPrepareNodeSha256 '$([string]$script:i04HarnessBundle.prepare_node_sha256)' ``
  -OutputRoot '<new-empty-peer-output-root>' ``
  -Commit '$($candidate.commit)' ``
  -ExpectedEmuleSha256 '$expectedHash' ``
  -PeerHostname '$canonicalHostname' ``
  -PeerIPv4 '$peerV4Text' ``
  -PeerLocalIPv4 '$peerLocalV4Text' ``
  -PeerIPv6 '$peerV6Text' ``
  -CoordinatorIPv4 '$coordinatorV4Text' ``
  -CoordinatorIPv6 '$coordinatorV6Text' ``
  -CoordinationRoot '<same-shared-coordination-root-on-peer>' ``
  -ControlledPeerAcknowledged ``
  -ExpectedCoordinatorMachineIdSha256 '$($ExpectedCoordinatorMachineIdSha256.ToLowerInvariant())' ``
  -ExpectedPeerMachineIdSha256 '$($ExpectedPeerMachineIdSha256.ToLowerInvariant())' ``
  -ExpectedCoordinatorUserSidSha256 '$expectedCoordinatorSidHash' ``
  -ExpectedPeerUserSidSha256 '$expectedPeerSidHash' ``
  -DisposableLabAccountAcknowledged ``
  -PeerTcpPort $PeerTcpPort -PeerUdpPort $PeerUdpPort -PeerWebPort $PeerWebPort ``
  -ClientTcpPort $ClientTcpPort -ClientUdpPort $ClientUdpPort -ClientWebPort $ClientWebPort ``
  -FileSizeBytes $FileSizeBytes ``
  -FallbackLimitSeconds $FallbackLimitSeconds ``
  -ScenarioTimeoutSeconds $ScenarioTimeoutSeconds ``
  -RunNonce '$nonce'

The coordination root must identify the same shared directory from both hosts.
Do not create a local REJECT/RST rule: Peer role creates an inbound IPv6 Block
on the remote peer and restores it transactionally.
"@
            Write-LabText -Value $manualCommand -Path $manualPath | Out-Null
            Write-Host $manualCommand -ForegroundColor Yellow
        }

        $peerReady = Wait-I04File -Path $readyPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $peerReady) {
            $blockedReasons.Add(
                "Peer phase did not publish peer-ready.json within $PeerReadyTimeoutSeconds seconds"
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerReady `
            -Path (Join-Path $evidence 'peer-ready.json') | Out-Null
        $peerReadyExact =
            [string]$peerReady.schema -eq 'ese.v91.i04-peer-ready/v1' -and
            [string]$peerReady.case_id -eq $caseId -and
            [string]$peerReady.run_nonce -eq $nonce -and
            [string]$peerReady.candidate.commit -eq $candidate.commit -and
            [string]$peerReady.candidate.emule_sha256 -eq $expectedHash -and
            [string]$peerReady.candidate.process_emule_sha256 -eq
                $expectedHash -and
            [string]$peerReady.candidate.package_zip_sha256 -eq
                $expectedZipHash -and
            [string]$peerReady.candidate.package_manifest_sha256 -eq
                [string]$candidate.package_manifest_sha256 -and
            [string]$peerReady.harness_bundle.schema -eq
                'ese.v91.i04-harness-bundle/v1' -and
            [string]$peerReady.harness_bundle.bundle_sha256 -eq
                [string]$script:i04HarnessBundle.bundle_sha256 -and
            [string]$peerReady.harness_bundle.harness_sha256 -eq
                [string]$script:i04HarnessBundle.harness_sha256 -and
            [string]$peerReady.harness_bundle.common_sha256 -eq
                [string]$script:i04HarnessBundle.common_sha256 -and
            [string]$peerReady.harness_bundle.prepare_node_sha256 -eq
                [string]$script:i04HarnessBundle.prepare_node_sha256 -and
            [bool]$peerReady.harness_bundle.immutable_read_locks_held -and
            [bool]$peerReady.candidate.prepared_code_binding.
                immutable_code_locks_held -and
            [string]$peerReady.candidate.prepared_code_binding.
                executable_sha256 -eq $expectedHash -and
            [string]$peerReady.peer.operator_identity.machine_id_sha256 -eq
                $ExpectedPeerMachineIdSha256.ToLowerInvariant() -and
            [string]$peerReady.peer.operator_identity.user_sid_sha256 -eq
                $expectedPeerSidHash -and
            [bool]$peerReady.peer.operator_identity.
                disposable_account_operator_attested -and
            [string]$peerReady.peer.account_registry_transaction.schema -eq
                'ese.v91.i04-account-registry-transaction/v2' -and
            [string]$peerReady.peer.account_registry_transaction.
                expected_user_sid_sha256 -eq $expectedPeerSidHash -and
            [bool]$peerReady.peer.account_registry_transaction.
                initial_absence_proved -and
            [bool]$peerReady.peer.account_registry_transaction.
                baseline.run_subtree.exists -and
            [bool]$peerReady.port_preflight.all_free -and
            (Test-I04ValueSetEqual `
                -Actual @($peerReady.port_preflight.ports) `
                -Expected @($PeerTcpPort, $PeerUdpPort, $PeerWebPort)) -and
            [bool]$peerReady.peer.physical -and
            [bool]$peerReady.peer.same_interface -and
            -not [bool]$peerReady.peer.overlay_or_vpn_like -and
            [bool]$peerReady.peer.isolation.strict_isolation_valid -and
            [bool]$peerReady.peer.route_to_coordinator_ipv6.available -and
            [bool]$peerReady.peer.route_to_coordinator_ipv6.
                physical_nonvirtual -and
            [int]$peerReady.peer.route_to_coordinator_ipv6.interface_index -eq
                [int]$peerReady.peer.ipv6_interface_index -and
            [string]$peerReady.peer.route_to_coordinator_ipv6.source_address -eq
                $peerV6Text -and
            [string]$peerReady.endpoint.ipv4 -eq $peerV4Text -and
            [string]$peerReady.endpoint.local_ipv4 -eq $peerLocalV4Text -and
            [string]$peerReady.endpoint.ipv6 -eq $peerV6Text -and
            [int]$peerReady.endpoint.tcp_port -eq $PeerTcpPort -and
            [string]$peerReady.coordinator.ipv4 -eq $coordinatorV4Text -and
            [string]$peerReady.coordinator.ipv6 -eq $coordinatorV6Text -and
            [bool]$peerReady.endpoint.dual_stack_listener -and
            [bool]$peerReady.endpoint.hello_ipv6_advertisement_configured -and
            [int]$peerReady.process.id -gt 0 -and
            [string]$peerReady.process.executable_sha256 -eq $expectedHash -and
            [string]$peerReady.process.source_mode -eq 'non-headless' -and
            [string]$peerReady.process.persisted_identity.user_hash -match
                '^[0-9A-F]{32}$' -and
            [string]$peerReady.process.persisted_identity.source_mode -eq
                'non-headless persisted preferences.dat identity' -and
            [string]$peerReady.process.runtime_identity -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [string]$peerReady.process.controlled_server_login.runtime_user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [int]$peerReady.process.controlled_server_login.login_count -eq 1 -and
            [string]$peerReady.fixtures.a.name -eq
                "v91-i04-$nonce-a.bin" -and
            [Int64]$peerReady.fixtures.a.bytes -eq $FileSizeBytes -and
            [string]$peerReady.fixtures.a.sha256 -match
                '^[0-9a-fA-F]{64}$' -and
            [string]$peerReady.fixtures.b.name -eq
                "v91-i04-$nonce-b.bin" -and
            [Int64]$peerReady.fixtures.b.bytes -eq $fileBSizeBytes -and
            [string]$peerReady.fixtures.b.sha256 -match
                '^[0-9a-fA-F]{64}$' -and
            [bool]$peerReady.fixtures.unique_sha256 -and
            [string]$peerReady.ed2k.a.hash -match
                '^[0-9a-fA-F]{32}$' -and
            [string]$peerReady.ed2k.b.hash -match
                '^[0-9a-fA-F]{32}$' -and
            [bool]$peerReady.ed2k.unique_hash -and
            [string]$peerReady.ed2k.a.base_link -match
                ('^ed2k://\|file\|' +
                    [regex]::Escape("v91-i04-$nonce-a.bin") + '\|' +
                    $FileSizeBytes + '\|') -and
            [string]$peerReady.ed2k.b.base_link -match
                ('^ed2k://\|file\|' +
                    [regex]::Escape("v91-i04-$nonce-b.bin") + '\|' +
                    $fileBSizeBytes + '\|') -and
            [bool]$peerReady.controls.allow4_rule_provisional.exact -and
            [bool]$peerReady.controls.allow6_rule.exact -and
            (Test-I04ApiIsolation -Data $peerReady.runtime_isolation `
                -RequireEd2k $true)
        if (-not $peerReadyExact) {
            $blockedReasons.Add('Peer identity is not the exact candidate/run')
            throw 'I04_FIXTURE_BLOCKED'
        }
        if ([string]$peerReady.peer.machine_id_sha256 -eq $localMachineId) {
            $blockedReasons.Add(
                'Peer and coordinator are the same Windows host; direct T1/T2 requires two physical hosts'
            )
        }
        if (-not [bool]$peerReady.peer.physical -or
            -not [bool]$peerReady.peer.same_interface) {
            $blockedReasons.Add('Peer endpoint is not backed by a physical interface')
        }
        if (-not [bool]$peerReady.endpoint.dual_stack_listener -or
            -not [bool]$peerReady.endpoint.hello_ipv6_advertisement_configured) {
            $blockedReasons.Add('Peer did not prove a real dual-stack listener/HELLO configuration')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-dns-scope/v1'
            captured_at_utc = Get-LabUtcTimestamp
            status = 'NOT_IN_SCOPE_V91_D01'
            hostname = $canonicalHostname
            note = 'I04 uses literal controlled peer addresses; DNS retention/order is adjudicated by V91-D01'
        }) -Path (Join-Path $evidence 'dns-scope.json') | Out-Null

        $baselineV4 = Test-I04TcpEndpoint -Address $peerV4Address `
            -Port $PeerTcpPort
        $baselineV6 = Test-I04TcpEndpoint -Address $peerV6Address `
            -Port $PeerTcpPort
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-baseline-reachability/v1'
            IPv4 = $baselineV4
            IPv6 = $baselineV6
        }) -Path (Join-Path $evidence 'baseline-reachability.json') | Out-Null
        if (-not $baselineV4.connected -or -not $baselineV6.connected) {
            $blockedReasons.Add(
                'Literal IPv4 and IPv6 must both reach the real peer before DROP'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        Start-Sleep -Seconds 1

        $offset = $ClientTcpPort - 4662
        if (($ClientUdpPort - 4672) -ne $offset -or
            ($ClientWebPort - 4711) -ne $offset) {
            throw 'Client TCP/UDP/Web ports must share the standard 4662/4672/4711 offset'
        }
        $null = Assert-I04CandidateBindingUnchanged -Binding $candidate
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
            -SourcePackage $candidate.package_path -OutputRoot $nodes `
            -RunId 'v91-i04-client' -PortOffset $offset
        $clientNode = Join-Path $nodes 'v91-i04-client-b'
        $clientExe = Join-Path $clientNode 'emule.exe'
        $null = Assert-I04CandidateBindingUnchanged -Binding $candidate
        $null = Assert-I04PreparedNodeDerivedFromBinding `
            -NodePath $clientNode -Binding $candidate
        $clientCodeBinding = Lock-I04PreparedNodeCode `
            -NodePath $clientNode -ExpectedExeSha256 $expectedHash
        $incoming = New-LabDirectory -Path (Join-Path $clientNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $clientNode 'Temp')
        $clientIsolation = Set-I04IsolatedPreferences `
            -NodePath $clientNode -IPv6Mode 2 `
            -IPv6BindAddress $coordinatorV6Text `
            -WebPort $ClientWebPort -Password $clientPassword `
            -IncomingPath $incoming -TempPath $temp
        if (-not $clientIsolation.preferences_dat_absent_before_start -or
            -not $clientIsolation.cryptkey_dat_absent_before_start) {
            throw 'Client profile inherited identity state'
        }

        function Start-ClientSource {
            $process = $null
            try {
                $preferenceProof = Assert-I04StoredPreferenceContract `
                    -NodePath $clientNode
                $process = Start-I04RestrictedProcess -FilePath $clientExe `
                    -ArgumentList @(
                        '--portable', '--ignoreinstances',
                        "--metrics-port=$ClientWebPort",
                        "--tcp-port=$ClientTcpPort",
                        "--udp-port=$ClientUdpPort"
                    ) -WorkingDirectory $clientNode
                $clientOwnedProcesses.Add($process)
                $process = Register-I04OwnedProcess -Process $process `
                    -ExpectedPath $clientExe `
                    -OwnerRole 'CoordinatorClient' -Nonce $nonce
                Wait-I04Api -Port $ClientWebPort -Process $process |
                    Out-Null
                Wait-I04Listener -Port $ClientTcpPort -Process $process |
                    Out-Null
                $process | Add-Member `
                    -NotePropertyName i04_preference_contract_sha256 `
                    -NotePropertyValue $preferenceProof.contract_sha256 -Force
                return $process
            } catch {
                # The caller cannot receive $process when startup validation
                # throws. Keep it in clientOwnedProcesses and make a best
                # effort here; the outer finally retries and certifies every
                # PID before cleanup can be reported complete.
                if ($null -ne $process) {
                    $null = Stop-I04OwnedProcess -Process $process `
                        -ExpectedPath $clientExe
                }
                throw
            }
        }

        # Create a genuinely fresh, persisted identity with both discovery
        # networks disabled, then stop normally before enabling the private
        # controlled eD2K server.
        $client = Start-ClientSource
        Add-I04Journal -Path $journal `
            -Mutation 'client-identity-init-process' `
            -State 'applied' -Detail "pid=$($client.Id)"
        $bootstrapApi = Get-I04ApiProbe -Port $ClientWebPort
        if (-not (Test-I04ApiIsolation -Data $bootstrapApi `
            -RequireEd2k $false)) {
            throw 'Client identity bootstrap violated isolation gates'
        }
        if (-not (Stop-I04OwnedProcess -Process $client `
            -ExpectedPath $clientExe -RequireGraceful)) {
            throw 'Client identity initialization did not stop gracefully'
        }
        Add-I04Journal -Path $journal `
            -Mutation 'client-identity-init-process' `
            -State 'rolled_back' -Detail "pid=$($client.Id)"
        $client = $null
        $clientIdentity = Get-I04PersistedUserHash -NodePath $clientNode

        $clientControlledServer = Start-I04ControlledEd2kServer `
            -EvidencePath (
                Join-Path $evidence 'client-controlled-ed2k-server.json'
            ) -ListenAddress $coordinatorV4Text `
            -ExpectedClientAddress $coordinatorV4Text `
            -HighIdAddress $coordinatorV4Text `
            -RunNonce $nonce -OwnerRole 'coordinator' `
            -OwnerInventory $clientControlledServersOwned
        $clientControlledProfile = Enable-I04ControlledEd2kProfile `
            -NodePath $clientNode -ServerAddress $coordinatorV4Text `
            -ServerPort $clientControlledServer.port `
            -RunNonce $nonce -OwnerRole 'coordinator'

        $client = Start-ClientSource
        Add-I04Journal -Path $journal -Mutation 'client-process' `
            -State 'applied' -Detail "pid=$($client.Id)"
        $clientServerLogin = Wait-I04ControlledEd2kLogin `
            -Server $clientControlledServer -Process $client `
            -ExpectedTcpPort $ClientTcpPort -MinimumLoginCount 1 `
            -TimeoutSeconds 90
        $apiDeadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            $clientRuntime = Get-I04ApiProbe -Port $ClientWebPort
            if (Test-I04ApiIsolation -Data $clientRuntime `
                -RequireEd2k $true) {
                break
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $apiDeadline)
        $clientIsolationExact = Test-I04ApiIsolation `
            -Data $clientRuntime -RequireEd2k $true
        if (-not $clientIsolationExact -or
            [string]$clientIdentity.user_hash -ne
                [string]$clientRuntime.user_hash -or
            [string]$clientIdentity.user_hash -ne
                [string]$clientServerLogin.runtime_user_hash -or
            [string]$clientIdentity.user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash) {
            throw 'Client runtime/server identity is invalid or not independent from peer'
        }
        $clientSession = Get-I04ClassicSession `
            -Port $ClientWebPort -Password $clientPassword

        # A starts from a literal public IPv4 source.  Its genuine HELLOANSWER
        # teaches this same CUpDownClient the peer IPv6/DUALSTACK identity.
        # B is then injected with that same source while A owns it, producing
        # the ordinary A4AF relationship used by StopFile/RemoveAllSources.
        $directLinkA = [string]$peerReady.ed2k.a.base_link +
            "|sources,$peerV4Text`:$PeerTcpPort|/"
        Send-I04Ed2kLink -Process $client `
            -Link ([string]$peerReady.ed2k.a.base_link)
        $aRowDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $fileAPreProgress = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.a.hash)
            if ([bool]$fileAPreProgress.found) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $aRowDeadline)
        if (-not [bool]$fileAPreProgress.found -or
            [bool]$fileAPreProgress.transferred_nonzero) {
            throw 'File A did not begin as an untransferred Classic Web row'
        }
        Send-I04Ed2kLink -Process $client -Link $directLinkA
        $prewarmDeadline = [DateTime]::UtcNow.AddMinutes(5)
        do {
            $client.Refresh()
            if ($client.HasExited) { throw 'Client exited during peer prewarm' }
            $connections = @(
                Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                        [int]$_.OwningProcess -eq $client.Id -and
                        $_.RemotePort -eq $PeerTcpPort -and
                        (Get-I04NormalizedIp -Address $_.RemoteAddress) -eq
                            $peerV4Text
                    }
            )
            if (@($connections |
                Where-Object State -eq 'Established').Count -gt 0) {
                if (-not $prewarmEstablished) {
                    $prewarmFirstEstablishedAt = [DateTimeOffset]::UtcNow
                    $prewarmFirstEstablishedEpochMs =
                        Get-I04EpochMilliseconds `
                            -Timestamp $prewarmFirstEstablishedAt
                }
                $prewarmEstablished = $true
            }
            $fileAProgress = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.a.hash)
            $prewarmProgress = [bool]$fileAProgress.found -and
                [bool]$fileAProgress.transferred_nonzero
            if ($prewarmEstablished -and $prewarmProgress) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $prewarmDeadline)
        if (-not $prewarmEstablished -or -not $prewarmProgress) {
            $blockedReasons.Add('Real IPv4 prewarm did not establish and advance data')
            throw 'I04_FIXTURE_BLOCKED'
        }
        $prewarmConnectionEvidence = @(
            $connections | Where-Object State -eq 'Established' |
                ForEach-Object {
                    $local = Get-I04NormalizedIp -Address $_.LocalAddress
                    $remote = Get-I04NormalizedIp -Address $_.RemoteAddress
                    $tupleKey = Get-I04TupleKey -Family 'IPv4' `
                        -LocalAddress $local -LocalPort ([int]$_.LocalPort) `
                        -RemoteAddress $remote -RemotePort ([int]$_.RemotePort)
                    $null = $prewarmTuples.Add($tupleKey)
                    [pscustomobject][ordered]@{
                        owning_process = [int]$_.OwningProcess
                        state = [string]$_.State
                        local_address = $local
                        local_port = [int]$_.LocalPort
                        remote_address = $remote
                        remote_port = [int]$_.RemotePort
                        tuple_key = $tupleKey
                    }
                }
        )
        if ($prewarmTuples.Count -eq 0) {
            $blockedReasons.Add('Established prewarm tuple could not be frozen')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-prewarm-tuples/v1'
            captured_at_utc = Get-LabUtcTimestamp
            client_process_id = $client.Id
            first_established_at_utc =
                $prewarmFirstEstablishedAt.ToString('o')
            first_established_epoch_ms =
                $prewarmFirstEstablishedEpochMs
            classic_web_before = $fileAPreProgress
            classic_web_progress = $fileAProgress
            tuples = $prewarmConnectionEvidence
        }) -Path (Join-Path $evidence 'prewarm-tuples.json') | Out-Null

        $directLinkB = [string]$peerReady.ed2k.b.base_link +
            "|sources,$peerV4Text`:$PeerTcpPort|/"
        Send-I04Ed2kLink -Process $client -Link $directLinkB
        $bDeadline = [DateTime]::UtcNow.AddSeconds(60)
        do {
            $fileBReady = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.b.hash)
            if ([bool]$fileBReady.found -and
                $null -ne $fileBReady.source_total -and
                [int]$fileBReady.source_total -ge 1 -and
                ([int]$fileBReady.source_transferring -eq 0)) {
                break
            }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $bDeadline)
        if (-not [bool]$fileBReady.found -or
            $null -eq $fileBReady.source_total -or
            [int]$fileBReady.source_total -lt 1 -or
            [int]$fileBReady.source_transferring -ne 0) {
            $blockedReasons.Add(
                'File B did not retain the same peer as an inactive A4AF source'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        # Capture and the PID-independent 25 ms socket sampler begin while the
        # old prewarm is already Established.  Consequently every captured SYN
        # is a new attempt; no historical 5-tuple is ever excluded.
        $scenarioV6SocketObserved = $false
        $scenarioV4SocketObserved = $false
        $scenarioV4Established = $false

        $capture = Start-I04PacketCapture -EvidencePath $captureEvidence `
            -FilterPrefix ("i04-" + $nonce) `
            -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort `
            -JournalPath $journal
        if (-not $capture.available) {
            $blockedReasons.Add(
                "Packet capture unavailable; silent DROP cannot be proved: $($capture.error)"
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        $socketSampler = Start-I04SocketSampler `
            -Path $socketSamplesPath `
            -IPv4 $peerV4Text -IPv6 $peerV6Text `
            -Port $PeerTcpPort

        $armRequestedAt = [DateTimeOffset]::UtcNow
        $armRequestedEpochMs =
            Get-I04EpochMilliseconds -Timestamp $armRequestedAt
        $armRequestedQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-arm-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'arm-remote-silent-drop'
            requested_at_utc = $armRequestedAt.ToString('o')
            coordinator_epoch_ms = $armRequestedEpochMs
            coordinator_qpc = $armRequestedQpc
            coordinator_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_source_process_id = [int]$peerReady.process.id
            expected_peer_ipv6 = $peerV6Text
            expected_peer_ipv4 = $peerV4Text
            expected_peer_tcp_port = $PeerTcpPort
            prewarm_tuples = $prewarmConnectionEvidence
        }) -Path $armPath | Out-Null
        $armCommandWritten = $true
        $scenarioStarted = [DateTime]::UtcNow

        # First barrier: the peer installs and verifies DROP while the original
        # source process and the real IPv4 prewarm connection are still alive.
        # Only the coordinator may release that barrier.
        $peerStageDeadline = [DateTime]::UtcNow.AddSeconds(90)
        $nextStageHealth = [DateTime]::UtcNow
        $sample = 0
        do {
            $now = [DateTime]::UtcNow
            if ($null -eq $peerArmed -and
                (Test-Path -LiteralPath $armedPath -PathType Leaf)) {
                $peerArmed = Get-Content -LiteralPath $armedPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $resumedPath -PathType Leaf) {
                $blockedReasons.Add(
                    'Peer published resumed before coordinator restart barrier'
                )
                throw 'I04_FIXTURE_BLOCKED'
            }
            $client.Refresh()
            if ($client.HasExited) {
                throw 'Client exited while the remote DROP was being armed'
            }
            $stageConnections = @(Get-I04TargetConnections `
                -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort)
            foreach ($connection in $stageConnections) {
                $isPrewarm = $prewarmTuples.Contains(
                    [string]$connection.tuple_key
                )
                if ($isPrewarm) { continue }
                if ($connection.state -notin @('SynSent', 'Established')) {
                    continue
                }
                if ([int]$connection.owning_process -ne $client.Id) {
                    $otherPidObserved = $true
                    $otherPidConnections.Add($connection)
                    continue
                }
                if ($connection.remote_address -eq $peerV6Text) {
                    $null = $scenarioV6LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV6SocketObserved = $true
                } elseif ($connection.remote_address -eq $peerV4Text) {
                    $null = $scenarioV4LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV4SocketObserved = $true
                    if ($connection.state -eq 'Established') {
                        $scenarioV4Established = $true
                    }
                }
            }
            if ($now -ge $nextStageHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not $api.available) { $apiFailureCount++ }
                $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max(
                    $uiMaxMs, [Int64]$ui.probe_duration_ms
                )
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'peer-arm-and-blackhole'
                    captured_at_utc = Get-LabUtcTimestamp
                    elapsed_seconds = [Math]::Round(
                        ($now - $scenarioStarted).TotalSeconds, 3
                    )
                    connections = $stageConnections
                    api = $api
                    ui = $ui
                })
                $nextStageHealth = $now.AddSeconds(1)
            }
            if ($null -ne $peerArmed) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $peerStageDeadline)
        if ($null -eq $peerArmed) {
            $blockedReasons.Add('Peer did not prove DROP while old source was alive')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerArmed `
            -Path (Join-Path $evidence 'peer-drop-armed.json') | Out-Null
        $peerArmedExact =
            [string]$peerArmed.schema -eq
                'ese.v91.i04-peer-drop-armed/v1' -and
            [string]$peerArmed.case_id -eq $caseId -and
            [string]$peerArmed.run_nonce -eq $nonce -and
            [string]$peerArmed.candidate_commit -eq $candidate.commit -and
            [string]$peerArmed.candidate_emule_sha256 -eq $expectedHash -and
            [int]$peerArmed.source_process_id -eq
                [int]$peerReady.process.id -and
            [bool]$peerArmed.source_process_alive -and
            [bool]$peerArmed.dual_stack_listener_alive -and
            [bool]$peerArmed.prewarm_connection_alive -and
            [string]$peerArmed.source_process_emule_sha256 -eq
                $expectedHash -and
            [bool]$peerArmed.allow4_rule.exact -and
            [bool]$peerArmed.allow6_rule.exact -and
            [bool]$peerArmed.drop_rule.exact -and
            [string]$peerArmed.global_firewall_armed.schema -eq
                'ese.v91.i04-global-firewall-snapshot/v2' -and
            [bool]$peerArmed.global_firewall_armed.privacy_safe -and
            [string]$peerArmed.global_firewall_armed.canonical_sha256 -match
                '^[0-9a-f]{64}$' -and
            [string]$peerArmed.allow4_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerArmed.allow6_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerArmed.drop_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerArmed.drop_rule.action -eq 'Block' -and
            [string]$peerArmed.drop_rule.direction -eq 'Inbound' -and
            [string]$peerArmed.drop_rule.profile -eq 'Any' -and
            @('6', 'tcp') -contains
                ([string]$peerArmed.drop_rule.protocol).ToLowerInvariant() -and
            [string]$peerArmed.drop_rule.local_port -eq
                ([string]$PeerTcpPort) -and
            [string]$peerArmed.drop_rule.remote_port -eq 'Any' -and
            [string]$peerArmed.allow4_rule.action -eq 'Allow' -and
            [string]$peerArmed.allow4_rule.direction -eq 'Inbound' -and
            [string]$peerArmed.allow4_rule.profile -eq 'Any' -and
            @('6', 'tcp') -contains
                ([string]$peerArmed.allow4_rule.protocol).ToLowerInvariant() -and
            [string]$peerArmed.allow4_rule.local_port -eq
                ([string]$PeerTcpPort) -and
            [string]$peerArmed.allow4_rule.remote_port -eq 'Any' -and
            [string]$peerArmed.allow6_rule.remote_port -eq 'Any' -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.drop_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.drop_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow4_rule.local_addresses) `
                -Expected @($peerLocalV4Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow4_rule.remote_addresses) `
                -Expected @(
                    [string]$peerArmed.observed_ipv4_client.address
                ) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow6_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerArmed.allow6_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp) -and
            [string]$peerArmed.observed_ipv4_client.firewall_remote_port -eq
                'Any' -and
            [bool]$peerArmed.route_to_observed_ipv4_client.available -and
            [bool]$peerArmed.route_to_observed_ipv4_client.
                physical_nonvirtual -and
            [int]$peerArmed.route_to_observed_ipv4_client.interface_index -eq
                [int]$peerReady.peer.ipv4_interface_index -and
            [string]$peerArmed.route_to_observed_ipv4_client.source_address -eq
                $peerLocalV4Text -and
            [string]$peerArmed.route_to_observed_ipv4_client.remote_address -eq
                [string]$peerArmed.observed_ipv4_client.address -and
            -not ([string]$peerArmed.observed_ipv4_client.address).Contains(
                ':'
            ) -and
            (Test-I04UsableLocalIPv4 -Address (
                [string]$peerArmed.observed_ipv4_client.address
            )) -and
            [int]$peerArmed.observed_ipv4_client.port -gt 0
        $coordinatorPrewarmAlive = @(
            Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                if ([int]$_.OwningProcess -ne $client.Id -or
                    [string]$_.State -ne 'Established') {
                    return $false
                }
                $tuple = Get-I04TupleKey -Family 'IPv4' `
                    -LocalAddress $_.LocalAddress `
                    -LocalPort ([int]$_.LocalPort) `
                    -RemoteAddress $_.RemoteAddress `
                    -RemotePort ([int]$_.RemotePort)
                return $prewarmTuples.Contains($tuple)
            }
        ).Count -gt 0
        if (-not $peerArmedExact -or -not $coordinatorPrewarmAlive) {
            $blockedReasons.Add(
                'Remote armed evidence is not exact or prewarm died before restart release'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $pauseOperation = Invoke-I04DownloadOperation `
            -Port $ClientWebPort -Session $clientSession `
            -Operation pause `
            -FileHash ([string]$peerReady.ed2k.a.hash)
        $pauseBoundaryEpochMs =
            [double]$pauseOperation.boundary_before_request_epoch_ms
        $pauseBoundaryQpc =
            [Int64]$pauseOperation.boundary_before_request_qpc
        $pauseDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $fileAPaused = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.a.hash)
            $fileBReady = Get-I04TransferSnapshot `
                -Port $ClientWebPort -Session $clientSession `
                -FileHash ([string]$peerReady.ed2k.b.hash)
            if ([bool]$fileAPaused.found -and
                [string]$fileAPaused.state -eq 'paused' -and
                [bool]$fileBReady.found -and
                [int]$fileBReady.source_total -ge 1) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $pauseDeadline)
        if ([string]$fileAPaused.state -ne 'paused' -or
            -not [bool]$fileBReady.found -or
            [int]$fileBReady.source_total -lt 1) {
            $blockedReasons.Add(
                'Pause A did not preserve the ordinary A/B A4AF fixture'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $quiesceRequestedAt = [DateTimeOffset]::UtcNow
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-quiesce-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'stop-source-under-drop'
            requested_at_utc = $quiesceRequestedAt.ToString('o')
            coordinator_epoch_ms =
                Get-I04EpochMilliseconds -Timestamp $quiesceRequestedAt
            coordinator_qpc = [Diagnostics.Stopwatch]::GetTimestamp()
            coordinator_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_old_process_id = [int]$peerArmed.source_process_id
            pause_a_operation = $pauseOperation
        }) -Path $quiescePath | Out-Null

        $peerQuiesced = Wait-I04File -Path $quiescedPath `
            -TimeoutSeconds 90
        if ($null -eq $peerQuiesced -or
            [string]$peerQuiesced.schema -ne
                'ese.v91.i04-peer-quiesced/v1' -or
            [string]$peerQuiesced.case_id -ne $caseId -or
            [string]$peerQuiesced.run_nonce -ne $nonce -or
            [int]$peerQuiesced.old_process_id -ne
                [int]$peerArmed.source_process_id -or
            -not [bool]$peerQuiesced.old_process_absent -or
            -not [bool]$peerQuiesced.old_listener_and_tuple_absent -or
            -not [bool]$peerQuiesced.drop_rule.exact) {
            $blockedReasons.Add(
                'Peer did not prove the old PID/listener/tuple absent under DROP'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerQuiesced `
            -Path (Join-Path $evidence 'peer-quiesced.json') | Out-Null

        $oldTupleDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $oldClientTuple = @(
                Get-I04TargetConnections -IPv4 $peerV4Text `
                    -IPv6 $peerV6Text -Port $PeerTcpPort |
                    Where-Object {
                        [int]$_.owning_process -eq $client.Id -and
                        $prewarmTuples.Contains([string]$_.tuple_key) -and
                        [string]$_.state -in @(
                            'Established', 'SynSent', 'CloseWait'
                        )
                    }
            )
            if ($oldClientTuple.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $oldTupleDeadline)
        if ($oldClientTuple.Count -ne 0) {
            $blockedReasons.Add(
                'Coordinator prewarm tuple remained after peer quiesce'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $schedulerDeadlineUtc =
            $prewarmFirstEstablishedAt.UtcDateTime.AddSeconds(
                $schedulerReconnectFloorSeconds
            )
        $nextFloorHealth = [DateTime]::UtcNow
        do {
            $now = [DateTime]::UtcNow
            $client.Refresh()
            if ($client.HasExited) {
                throw 'Client exited while waiting for scheduler floor'
            }
            if ($now -ge $nextFloorHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not [bool]$api.available) {
                    $candidatePostTriggerFailure = New-I04ProductFailure `
                        -FailureType 'api_unavailable' `
                        -DisplayMessage (
                            'candidate API became unavailable during the ' +
                            'scheduler-floor observation'
                        ) -Process $client -ExpectedPath $clientExe `
                        -BoundaryEpochMs $(if ($null -eq
                            $restartBoundaryEpochMs) { 0.0 } else {
                            [double]$restartBoundaryEpochMs
                        }) -SourceKind 'api_probe' -SourceEvidence $api `
                        -RequireWebEndpoint
                    throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
                }
                if (-not (Test-I04ApiIsolation -Data $api `
                        -RequireEd2k $true)) {
                    $apiFailureCount++
                    $blockedReasons.Add(
                        'Candidate API isolation changed before the formal Stop A boundary'
                    )
                    throw 'I04_FIXTURE_BLOCKED'
                }
                $apiMaxMs =
                    [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                if ([Int64]$api.duration_ms -ge 1000) {
                    $blockedReasons.Add(
                        'Candidate API exceeded the liveness limit before the formal Stop A boundary'
                    )
                    throw 'I04_FIXTURE_BLOCKED'
                }
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max(
                    $uiMaxMs, [Int64]$ui.probe_duration_ms
                )
                if (-not [bool]$ui.main_window_present -or
                    -not [bool]$ui.message_pump_responsive -or
                    [Int64]$ui.probe_duration_ms -ge 500) {
                    $blockedReasons.Add(
                        'Candidate UI liveness failed before the formal Stop A boundary'
                    )
                    throw 'I04_FIXTURE_BLOCKED'
                }
                $pausedCheck = Get-I04TransferSnapshot `
                    -Port $ClientWebPort -Session $clientSession `
                    -FileHash ([string]$peerReady.ed2k.a.hash)
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'paused-a-scheduler-floor'
                    captured_at_utc = Get-LabUtcTimestamp
                    connections = @(
                        Get-I04TargetConnections -IPv4 $peerV4Text `
                            -IPv6 $peerV6Text -Port $PeerTcpPort
                    )
                    api = $api
                    ui = $ui
                    file_a = $pausedCheck
                })
                if ([string]$pausedCheck.state -ne 'paused') {
                    throw 'File A left Paused state before formal Stop A'
                }
                $nextFloorHealth = $now.AddSeconds(5)
            }
            if ($now -ge $schedulerDeadlineUtc) { break }
            Start-Sleep -Milliseconds 100
        } while ($true)
        $schedulerFloorSatisfied =
            [DateTime]::UtcNow -ge $schedulerDeadlineUtc
        if (-not $schedulerFloorSatisfied) {
            throw 'Scheduler reconnect floor was not satisfied'
        }

        $restartPreparationAt = [DateTimeOffset]::UtcNow
        $restartPreparationEpochMs =
            Get-I04EpochMilliseconds -Timestamp $restartPreparationAt
        $restartPreparationQpc =
            [Diagnostics.Stopwatch]::GetTimestamp()
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-restart-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            action = 'restart-source-under-drop'
            requested_at_utc = $restartPreparationAt.ToString('o')
            coordinator_epoch_ms = $restartPreparationEpochMs
            coordinator_qpc = $restartPreparationQpc
            coordinator_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            expected_old_process_id = [int]$peerArmed.source_process_id
            prewarm_first_established_at_utc =
                $prewarmFirstEstablishedAt.ToString('o')
            scheduler_floor_seconds =
                $schedulerReconnectFloorSeconds
            scheduler_floor_satisfied = $schedulerFloorSatisfied
        }) -Path $restartPath | Out-Null

        $resumeDeadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            $now = [DateTime]::UtcNow
            if ($null -eq $peerResumed -and
                (Test-Path -LiteralPath $resumedPath -PathType Leaf)) {
                $peerResumed = Get-Content -LiteralPath $resumedPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            }
            $client.Refresh()
            if ($client.HasExited) {
                throw 'Client exited while peer source was restarting'
            }
            $stageConnections = @(Get-I04TargetConnections `
                -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort)
            foreach ($connection in $stageConnections) {
                if ($prewarmTuples.Contains([string]$connection.tuple_key)) {
                    continue
                }
                if ($connection.state -notin @('SynSent', 'Established')) {
                    continue
                }
                if ([int]$connection.owning_process -ne $client.Id) {
                    $otherPidObserved = $true
                    $otherPidConnections.Add($connection)
                    continue
                }
                if ($connection.remote_address -eq $peerV6Text) {
                    $null = $scenarioV6LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV6SocketObserved = $true
                } elseif ($connection.remote_address -eq $peerV4Text) {
                    $null = $scenarioV4LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV4SocketObserved = $true
                    if ($connection.state -eq 'Established') {
                        $scenarioV4Established = $true
                    }
                }
            }
            if ($now -ge $nextStageHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not $api.available) { $apiFailureCount++ }
                $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max(
                    $uiMaxMs, [Int64]$ui.probe_duration_ms
                )
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'coordinator-restart-barrier'
                    captured_at_utc = Get-LabUtcTimestamp
                    elapsed_seconds = [Math]::Round(
                        ($now - $scenarioStarted).TotalSeconds, 3
                    )
                    connections = $stageConnections
                    api = $api
                    ui = $ui
                })
                $nextStageHealth = $now.AddSeconds(1)
            }
            if ($null -ne $peerResumed) { break }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $resumeDeadline)
        if ($null -eq $peerResumed) {
            $blockedReasons.Add('Peer did not publish resumed after restart release')
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value $peerResumed `
            -Path (Join-Path $evidence 'peer-resumed.json') | Out-Null
        $peerResumedExact =
            [string]$peerResumed.schema -eq 'ese.v91.i04-peer-resumed/v1' -and
            [string]$peerResumed.case_id -eq $caseId -and
            [string]$peerResumed.run_nonce -eq $nonce -and
            [string]$peerResumed.candidate_commit -eq $candidate.commit -and
            [string]$peerResumed.candidate_emule_sha256 -eq $expectedHash -and
            [int]$peerResumed.old_process_id -eq
                [int]$peerArmed.source_process_id -and
            [int]$peerResumed.process_id -gt 0 -and
            [int]$peerResumed.process_id -ne
                [int]$peerArmed.source_process_id -and
            [string]$peerResumed.process_emule_sha256 -eq $expectedHash -and
            [Int64]$peerResumed.stop_to_listener_ready_ms -ge 0 -and
            [Int64]$peerResumed.stop_to_listener_ready_ms -le 90000 -and
            [bool]$peerResumed.restart_within_readiness_limit -and
            [bool]$peerResumed.dual_stack_listener -and
            [bool]$peerResumed.ipv4_capable_dual_stack_listener -and
            [bool]$peerResumed.same_persisted_user_hash -and
            [string]$peerResumed.persisted_identity.user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [string]$peerResumed.persisted_identity.source_mode -eq
                'non-headless persisted preferences.dat identity' -and
            [string]$peerResumed.runtime_identity -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [string]$peerResumed.controlled_server_login.runtime_user_hash -eq
                [string]$peerReady.process.persisted_identity.user_hash -and
            [int]$peerResumed.controlled_server_login.login_count -ge 2 -and
            (Test-I04ApiIsolation -Data $peerResumed.runtime_isolation `
                -RequireEd2k $true) -and
            [bool]$peerResumed.allow4_rule.exact -and
            [bool]$peerResumed.allow6_rule.exact -and
            [bool]$peerResumed.drop_rule.exact -and
            [string]$peerResumed.drop_rule.program_file_sha256 -eq
                $expectedHash -and
            [string]$peerResumed.drop_rule.action -eq 'Block' -and
            [string]$peerResumed.drop_rule.local_port -eq
                ([string]$PeerTcpPort) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.drop_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.drop_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow4_rule.local_addresses) `
                -Expected @($peerLocalV4Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow4_rule.remote_addresses) `
                -Expected @(
                    [string]$peerArmed.observed_ipv4_client.address
                ) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow6_rule.local_addresses) `
                -Expected @($peerV6Text) -NormalizeIp) -and
            (Test-I04ValueSetEqual `
                -Actual @($peerResumed.allow6_rule.remote_addresses) `
                -Expected @($coordinatorV6Text) -NormalizeIp)
        if (-not $peerResumedExact) {
            $blockedReasons.Add(
                'Peer restart failed PID/hash/identity/eD2K/listener/firewall/readiness validation'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }

        $baselineDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            $apiTelemetryBaseline =
                Get-I04ApiProbe -Port $ClientWebPort
            $baselineFieldsPresent =
                $null -ne $apiTelemetryBaseline.connecting_client_count -and
                $null -ne $apiTelemetryBaseline.connecting_client_adds -and
                $null -ne
                    $apiTelemetryBaseline.connecting_client_high_water -and
                $null -ne
                    $apiTelemetryBaseline.connecting_client_duplicate_adds
            if ($baselineFieldsPresent -and
                [Int64]$apiTelemetryBaseline.connecting_client_count -eq 0) {
                break
            }
            Start-Sleep -Milliseconds 50
        } while ([DateTime]::UtcNow -lt $baselineDeadline)
        if (-not $baselineFieldsPresent -or
            [Int64]$apiTelemetryBaseline.connecting_client_count -ne 0 -or
            [Int64]$apiTelemetryBaseline.connecting_client_high_water -ne 1 -or
            -not (Test-I04ApiIsolation -Data $apiTelemetryBaseline `
                -RequireEd2k $true)) {
            $blockedReasons.Add(
                'Pre-Stop-A connecting-client/API baseline is absent or invalid'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        $telemetryObservedCurrentMax =
            [Int64]$apiTelemetryBaseline.connecting_client_count
        $telemetryObservedAddsMax =
            [Int64]$apiTelemetryBaseline.connecting_client_adds
        $telemetryObservedDuplicateMax =
            [Int64]$apiTelemetryBaseline.connecting_client_duplicate_adds
        $telemetryObservedHighWaterMax =
            [Int64]$apiTelemetryBaseline.connecting_client_high_water

        $preStopA = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.a.hash)
        $preStopB = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.b.hash)
        if ([string]$preStopA.state -ne 'paused' -or
            -not [bool]$preStopB.found -or
            [int]$preStopB.source_total -lt 1) {
            $blockedReasons.Add(
                'A/B ordinary fixture was not intact immediately before Stop A'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        $logBefore = Get-I04ProductLogCounts -NodePath $clientNode `
            -PeerIPv4 $peerV4Text -PeerIPv6 $peerV6Text `
            -PeerPort $PeerTcpPort -FileAName (
                [string]$peerReady.fixtures.a.name
            ) -FileBName ([string]$peerReady.fixtures.b.name)
        if (-not [bool]$logBefore.collector_ok -or
            -not [bool]$logBefore.adjudicable -or
            [int]$logBefore.log_file_count -lt 1) {
            $blockedReasons.Add(
                'Product log baseline collector did not complete exactly'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        $coordinatorFirewallBeforeBoundary =
            Get-I04GlobalFirewallSnapshot
        if ([string]$coordinatorFirewallBeforeBoundary.canonical_sha256 -cne
            [string]$script:i04AccountRegistryTransaction.
                global_firewall_baseline.canonical_sha256) {
            $blockedReasons.Add(
                'Coordinator global firewall changed before the formal boundary'
            )
            throw 'I04_FIXTURE_BLOCKED'
        }
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-formal-trigger-baseline/v1'
            captured_at_utc = Get-LabUtcTimestamp
            logs = $logBefore
            api = $apiTelemetryBaseline
            file_a = $preStopA
            file_b = $preStopB
            global_firewall = $coordinatorFirewallBeforeBoundary
        }) -Path (Join-Path $evidence 'formal-trigger-baseline.json') |
            Out-Null

        # From here onward the complete external fixture has been proved and
        # the only remaining trigger is the candidate's formal Stop A path.
        # Once the boundary artifact is published, candidate/API/telemetry
        # failures take FAIL precedence; pre-boundary setup failures remain
        # BLOCKED.
        $apiProbeCount = 0
        $apiFailureCount = 0
        $apiMaxMs = 0L
        $uiProbeCount = 0
        $uiMissingCount = 0
        $uiFailureCount = 0
        $uiMaxMs = 0L
        $caseArmed = $true
        # The only formal trigger boundary is immediately before this Classic
        # Web Stop A request. Publish and assign it before entering the
        # potentially blocking request so a candidate crash/hang cannot erase
        # the boundary and be mislabeled as harness uncertainty. Restart was
        # preparation; StopFile invokes RemoveAllSources(true), swaps the same
        # CUpDownClient A->B with reask=0, and the expired 20-minute floor
        # permits AskForDownload immediately.
        $stopABefore = [DateTimeOffset]::UtcNow
        $stopABoundary = [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-formal-trigger-boundary/v1'
            case_id = $caseId
            run_nonce = $nonce
            candidate_commit = $candidate.commit
            candidate_emule_sha256 = $expectedHash
            operation = 'stop'
            file_hash =
                ([string]$peerReady.ed2k.a.hash).ToUpperInvariant()
            boundary_before_request_utc = $stopABefore.ToString('o')
            boundary_before_request_epoch_ms =
                Get-I04EpochMilliseconds -Timestamp $stopABefore
            boundary_before_request_qpc =
                [Diagnostics.Stopwatch]::GetTimestamp()
            qpc_frequency = [Diagnostics.Stopwatch]::Frequency
        }
        Write-LabJson -Value $stopABoundary `
            -Path $formalTriggerBoundaryPath | Out-Null
        $formalBoundaryPublished = $true
        $restartBoundaryEpochMs =
            [double]$stopABoundary.boundary_before_request_epoch_ms
        $restartBoundaryQpc =
            [Int64]$stopABoundary.boundary_before_request_qpc
        $restartBoundaryAt = [DateTimeOffset]::FromUnixTimeMilliseconds(
            [Int64][Math]::Floor($restartBoundaryEpochMs)
        )
        $scenarioStarted = $restartBoundaryAt.UtcDateTime
        try {
            $stopAOperation = Invoke-I04DownloadOperation `
                -Port $ClientWebPort -Session $clientSession `
                -Operation stop `
                -FileHash ([string]$peerReady.ed2k.a.hash) `
                -PreparedBoundary $stopABoundary
        } catch {
            $requestFailure = Get-I04SafeErrorToken `
                -Context 'formal Stop A request failed' `
                -Message $_.Exception.Message
            $requestAfter = [DateTimeOffset]::UtcNow
            $stopAOperation = [pscustomobject][ordered]@{
                operation = 'stop'
                file_hash =
                    ([string]$peerReady.ed2k.a.hash).ToUpperInvariant()
                boundary_before_request_utc =
                    $stopABoundary.boundary_before_request_utc
                boundary_before_request_epoch_ms =
                    $stopABoundary.boundary_before_request_epoch_ms
                boundary_before_request_qpc =
                    $stopABoundary.boundary_before_request_qpc
                response_completed_utc = $requestAfter.ToString('o')
                response_completed_epoch_ms =
                    Get-I04EpochMilliseconds -Timestamp $requestAfter
                response_completed_qpc =
                    [Diagnostics.Stopwatch]::GetTimestamp()
                qpc_frequency = [Diagnostics.Stopwatch]::Frequency
                request_completed = $false
                request_error = $requestFailure
                http_status = $null
                response_sha256 = ''
            }
            $client.Refresh()
            $candidatePostTriggerFailure = if ([bool]$client.HasExited) {
                $message = "candidate exited while processing formal Stop A (exit $($client.ExitCode))"
                New-I04ProductFailure -FailureType 'process_exit' `
                    -DisplayMessage $message -Process $client `
                    -ExpectedPath $clientExe `
                    -BoundaryEpochMs $restartBoundaryEpochMs `
                    -SourceKind 'process_handle' `
                    -SourceEvidence $stopAOperation `
                    -RequireExitedProcess
            } else {
                $message = 'candidate Classic Web Stop A request failed or ' +
                    "timed out after the formal boundary: $requestFailure"
                New-I04ProductFailure -FailureType 'classic_web_timeout' `
                    -DisplayMessage $message -Process $client `
                    -ExpectedPath $clientExe `
                    -BoundaryEpochMs $restartBoundaryEpochMs `
                    -SourceKind 'classic_web_request' `
                    -SourceEvidence $stopAOperation -RequireWebEndpoint
            }
            throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
        }
        $apiTelemetryTrigger = Get-I04ApiProbe -Port $ClientWebPort
        if (-not [bool]$apiTelemetryTrigger.available -or
            $null -eq $apiTelemetryTrigger.connecting_client_count -or
            $null -eq $apiTelemetryTrigger.connecting_client_adds -or
            $null -eq $apiTelemetryTrigger.connecting_client_high_water -or
            $null -eq
                $apiTelemetryTrigger.connecting_client_duplicate_adds) {
            $failureType = if ([bool]$apiTelemetryTrigger.available) {
                'api_contract_invalid'
            } else { 'api_unavailable' }
            $candidatePostTriggerFailure = New-I04ProductFailure `
                -FailureType $failureType -DisplayMessage (
                    'candidate API/connecting telemetry was unavailable ' +
                    'immediately after formal Stop A'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'api_probe' `
                -SourceEvidence $apiTelemetryTrigger -RequireWebEndpoint
            throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
        }
        $telemetryObservedCurrentMax = [Math]::Max(
            $telemetryObservedCurrentMax,
            [Int64]$apiTelemetryTrigger.connecting_client_count
        )
        $telemetryObservedAddsMax = [Math]::Max(
            [Int64]$telemetryObservedAddsMax,
            [Int64]$apiTelemetryTrigger.connecting_client_adds
        )
        $telemetryObservedDuplicateMax = [Math]::Max(
            [Int64]$telemetryObservedDuplicateMax,
            [Int64]$apiTelemetryTrigger.connecting_client_duplicate_adds
        )
        $telemetryObservedHighWaterMax = [Math]::Max(
            [Int64]$telemetryObservedHighWaterMax,
            [Int64]$apiTelemetryTrigger.connecting_client_high_water
        )

        $deadline = [DateTime]::UtcNow.AddSeconds($ScenarioTimeoutSeconds)
        $nextHealth = [DateTime]::UtcNow
        $nextTelemetry = [DateTime]::UtcNow
        $nextLogCheck = [DateTime]::UtcNow
        $fallbackDeltaObserved = 0
        do {
            $now = [DateTime]::UtcNow
            $client.Refresh()
            if ($client.HasExited) {
                $message = "candidate exited during formal scenario (exit $($client.ExitCode))"
                $candidatePostTriggerFailure = New-I04ProductFailure `
                    -FailureType 'process_exit' -DisplayMessage $message `
                    -Process $client -ExpectedPath $clientExe `
                    -BoundaryEpochMs $restartBoundaryEpochMs `
                    -SourceKind 'process_handle' -RequireExitedProcess
                throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
            }
            $matching = @(Get-I04TargetConnections `
                -IPv4 $peerV4Text -IPv6 $peerV6Text -Port $PeerTcpPort)
            foreach ($connection in $matching) {
                if ($connection.state -notin @('SynSent', 'Established')) {
                    continue
                }
                if ([int]$connection.owning_process -ne $client.Id) {
                    $otherPidObserved = $true
                    $otherPidConnections.Add($connection)
                    continue
                }
                if ($connection.remote_address -eq $peerV6Text) {
                    $null = $scenarioV6LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV6SocketObserved = $true
                }
                if ($connection.remote_address -eq $peerV4Text) {
                    $null = $scenarioV4LocalPorts.Add(
                        [int]$connection.local_port
                    )
                    $scenarioV4SocketObserved = $true
                    if ($connection.state -eq 'Established') {
                        $scenarioV4Established = $true
                    }
                }
            }
            if ($now -ge $nextTelemetry) {
                $telemetry = Get-I04ApiProbe -Port $ClientWebPort
                if (-not [bool]$telemetry.available -or
                    $null -eq $telemetry.connecting_client_count -or
                    $null -eq $telemetry.connecting_client_adds -or
                    $null -eq $telemetry.connecting_client_high_water -or
                    $null -eq
                        $telemetry.connecting_client_duplicate_adds) {
                    $failureType = if ([bool]$telemetry.available) {
                        'api_contract_invalid'
                    } else { 'api_unavailable' }
                    $candidatePostTriggerFailure = New-I04ProductFailure `
                        -FailureType $failureType -DisplayMessage (
                            'candidate API/connecting telemetry became unavailable'
                        ) -Process $client -ExpectedPath $clientExe `
                        -BoundaryEpochMs $restartBoundaryEpochMs `
                        -SourceKind 'api_probe' -SourceEvidence $telemetry `
                        -RequireWebEndpoint
                    throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
                }
                $telemetryObservedCurrentMax = [Math]::Max(
                    $telemetryObservedCurrentMax,
                    [Int64]$telemetry.connecting_client_count
                )
                $telemetryObservedAddsMax = [Math]::Max(
                    [Int64]$telemetryObservedAddsMax,
                    [Int64]$telemetry.connecting_client_adds
                )
                $telemetryObservedDuplicateMax = [Math]::Max(
                    [Int64]$telemetryObservedDuplicateMax,
                    [Int64]$telemetry.connecting_client_duplicate_adds
                )
                $telemetryObservedHighWaterMax = [Math]::Max(
                    [Int64]$telemetryObservedHighWaterMax,
                    [Int64]$telemetry.connecting_client_high_water
                )
                if ($null -eq $apiTelemetryPeak -or
                    [Int64]$telemetry.connecting_client_count -gt
                        [Int64]$apiTelemetryPeak.connecting_client_count -or
                    [Int64]$telemetry.connecting_client_adds -gt
                        [Int64]$apiTelemetryPeak.connecting_client_adds) {
                    $apiTelemetryPeak = $telemetry
                }
                $nextTelemetry = $now.AddMilliseconds(100)
            }
            if ($now -ge $nextHealth) {
                $api = Get-I04ApiProbe -Port $ClientWebPort
                $ui = Get-I04UiProbe -Process $client
                $apiProbeCount++
                if (-not $api.available -or
                    -not (Test-I04ApiIsolation -Data $api `
                        -RequireEd2k $true)) {
                    $apiFailureCount++
                    $failureType = if ([bool]$api.available) {
                        'api_contract_invalid'
                    } else { 'api_unavailable' }
                    $candidatePostTriggerFailure = New-I04ProductFailure `
                        -FailureType $failureType -DisplayMessage (
                            'Candidate API liveness/isolation failed after ' +
                            'formal Stop A'
                        ) -Process $client -ExpectedPath $clientExe `
                        -BoundaryEpochMs $restartBoundaryEpochMs `
                        -SourceKind 'api_probe' -SourceEvidence $api `
                        -RequireWebEndpoint
                    throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
                }
                $apiMaxMs = [Math]::Max($apiMaxMs, [Int64]$api.duration_ms)
                if ([Int64]$api.duration_ms -ge 1000) {
                    $candidatePostTriggerFailure = New-I04ProductFailure `
                        -FailureType 'api_liveness' -DisplayMessage (
                            'Candidate API exceeded the post-boundary ' +
                            'one-second liveness limit'
                        ) -Process $client -ExpectedPath $clientExe `
                        -BoundaryEpochMs $restartBoundaryEpochMs `
                        -SourceKind 'api_probe' -SourceEvidence $api `
                        -RequireWebEndpoint
                    throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
                }
                $uiProbeCount++
                if (-not $ui.main_window_present) { $uiMissingCount++ }
                if ($ui.main_window_present -and
                    -not $ui.message_pump_responsive) {
                    $uiFailureCount++
                }
                $uiMaxMs = [Math]::Max($uiMaxMs, [Int64]$ui.probe_duration_ms)
                if (-not [bool]$ui.main_window_present -or
                    -not [bool]$ui.message_pump_responsive -or
                    [Int64]$ui.probe_duration_ms -ge 500) {
                    $candidatePostTriggerFailure = New-I04ProductFailure `
                        -FailureType 'ui_liveness' -DisplayMessage (
                            'Candidate UI failed the post-boundary liveness contract'
                        ) -Process $client -ExpectedPath $clientExe `
                        -BoundaryEpochMs $restartBoundaryEpochMs `
                        -SourceKind 'ui_probe' -SourceEvidence $ui `
                        -RequireLiveProcess
                    throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
                }
                Add-I04JsonLine -Path $samplesPath -Value ([ordered]@{
                    schema = 'ese.v91.i04-runtime-sample/v1'
                    sample_number = ++$sample
                    stage = 'fallback-observation'
                    captured_at_utc = Get-LabUtcTimestamp
                    elapsed_seconds = [Math]::Round(
                        ($now - $scenarioStarted).TotalSeconds, 3
                    )
                    connections = $matching
                    api = $api
                    ui = $ui
                })
                $nextHealth = $now.AddSeconds(1)
            }
            if ($now -ge $nextLogCheck) {
                $liveLog = Get-I04ProductLogCounts -NodePath $clientNode `
                    -PeerIPv4 $peerV4Text -PeerIPv6 $peerV6Text `
                    -PeerPort $PeerTcpPort -FileAName (
                        [string]$peerReady.fixtures.a.name
                    ) -FileBName (
                        [string]$peerReady.fixtures.b.name
                    )
                if (-not [bool]$liveLog.collector_ok -or
                    -not [bool]$liveLog.adjudicable -or
                    [int]$liveLog.log_file_count -lt 1) {
                    $blockedReasons.Add(
                        'Product log live collector did not complete exactly'
                    )
                    throw 'I04_LOG_COLLECTOR_BLOCKED'
                }
                $fallbackDeltaObserved = $liveLog.fallback_count -
                    $logBefore.fallback_count
                $nextLogCheck = $now.AddSeconds(1)
            }
            if ($fallbackDeltaObserved -ge 1 -and
                $scenarioV4Established) {
                if ($null -eq $successObservedAt) {
                    $successObservedAt = $now
                } elseif (($now - $successObservedAt).TotalSeconds -ge 10) {
                    break
                }
            }
            if ($null -eq $successObservedAt -and
                ($now - $restartBoundaryAt.UtcDateTime).TotalSeconds -ge
                    ($FallbackLimitSeconds + 10)) {
                # The formal fallback deadline plus the late-retry window has
                # elapsed under capture. Continuing to the broad scenario
                # timeout cannot turn this product failure into a PASS.
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        $scenarioFinished = [DateTime]::UtcNow
        $finalTelemetryDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $apiTelemetryFinal =
                Get-I04ApiProbe -Port $ClientWebPort
            if ([bool]$apiTelemetryFinal.available -and
                $null -ne $apiTelemetryFinal.connecting_client_count -and
                [Int64]$apiTelemetryFinal.connecting_client_count -eq 0) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $finalTelemetryDeadline)
        if (-not [bool]$apiTelemetryFinal.available -or
            $null -eq $apiTelemetryFinal.connecting_client_count -or
            $null -eq $apiTelemetryFinal.connecting_client_adds -or
            $null -eq $apiTelemetryFinal.connecting_client_high_water -or
            $null -eq
                $apiTelemetryFinal.connecting_client_duplicate_adds) {
            $failureType = if ([bool]$apiTelemetryFinal.available) {
                'api_contract_invalid'
            } else { 'api_unavailable' }
            $candidatePostTriggerFailure = New-I04ProductFailure `
                -FailureType $failureType -DisplayMessage (
                    'candidate final API/connecting telemetry remained unavailable'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'api_probe' `
                -SourceEvidence $apiTelemetryFinal -RequireWebEndpoint
            throw 'I04_CANDIDATE_FAILED_AFTER_TRIGGER'
        }
        $telemetryObservedCurrentMax = [Math]::Max(
            $telemetryObservedCurrentMax,
            [Int64]$apiTelemetryFinal.connecting_client_count
        )
        $telemetryObservedAddsMax = [Math]::Max(
            [Int64]$telemetryObservedAddsMax,
            [Int64]$apiTelemetryFinal.connecting_client_adds
        )
        $telemetryObservedDuplicateMax = [Math]::Max(
            [Int64]$telemetryObservedDuplicateMax,
            [Int64]$apiTelemetryFinal.connecting_client_duplicate_adds
        )
        $telemetryObservedHighWaterMax = [Math]::Max(
            [Int64]$telemetryObservedHighWaterMax,
            [Int64]$apiTelemetryFinal.connecting_client_high_water
        )
        $fileAStopped = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.a.hash)
        $fileBAfterTrigger = Get-I04TransferSnapshot `
            -Port $ClientWebPort -Session $clientSession `
            -FileHash ([string]$peerReady.ed2k.b.hash)
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-pid-port-correlation/v1'
            captured_at_utc = Get-LabUtcTimestamp
            candidate_process_id = $client.Id
            ipv4_local_ports = @($scenarioV4LocalPorts | Sort-Object)
            ipv6_local_ports = @($scenarioV6LocalPorts | Sort-Object)
            prewarm_tuple_keys = @($prewarmTuples | Sort-Object)
            other_pid_observed = $otherPidObserved
            other_pid_connections = @($otherPidConnections.ToArray())
            telemetry = [ordered]@{
                baseline = $apiTelemetryBaseline
                immediate_after_stop_a = $apiTelemetryTrigger
                peak_sample = $apiTelemetryPeak
                final = $apiTelemetryFinal
                observed_current_max = $telemetryObservedCurrentMax
                observed_adds_max = $telemetryObservedAddsMax
                observed_duplicate_adds_max =
                    $telemetryObservedDuplicateMax
                observed_high_water_max =
                    $telemetryObservedHighWaterMax
            }
            classic_web = [ordered]@{
                pause_a = $pauseOperation
                stop_a = $stopAOperation
                a_after_stop = $fileAStopped
                b_after_stop = $fileBAfterTrigger
            }
            post_success_observation_seconds = if ($null -eq $successObservedAt) {
                0
            } else {
                [Math]::Round(
                    ($scenarioFinished - $successObservedAt).TotalSeconds, 3
                )
            }
        }) -Path (Join-Path $evidence 'pid-port-correlation.json') | Out-Null
    } catch {
        $failureDisposition = Get-I04FailureDisposition `
            -CaseArmed $caseArmed `
            -FormalBoundaryPublished $formalBoundaryPublished `
            -CandidateFailure $candidatePostTriggerFailure `
            -ProofContradicted $false `
            -ExceptionMessage $_.Exception.Message
        if ([string]$failureDisposition.classification -eq 'FAIL') {
            # The product symptom was set explicitly at its observation site;
            # timing alone never promotes an arbitrary harness exception.
            $null = $candidatePostTriggerFailure
        } elseif ($null -ne $candidatePostTriggerFailure) {
            $blockedReasons.Add(
                'A candidate symptom occurred without a complete formal ' +
                'post-boundary proof and is therefore not adjudicable'
            )
        } elseif ($_.Exception.Message -ne 'I04_FIXTURE_BLOCKED') {
            $runtimeFailure = $_
        }
    } finally {
        if ($caseArmed -and $null -ne $coordinatorFirewallBeforeBoundary) {
            try {
                $coordinatorFirewallAfterObservation =
                    Get-I04GlobalFirewallSnapshot
                $coordinatorFirewallScenarioUnchanged =
                    [string]$coordinatorFirewallAfterObservation.
                        canonical_sha256 -ceq
                    [string]$coordinatorFirewallBeforeBoundary.canonical_sha256
                if (-not $coordinatorFirewallScenarioUnchanged) {
                    $blockedReasons.Add(
                        'Coordinator global firewall drifted during the formal scenario'
                    )
                }
            } catch {
                $blockedReasons.Add((Get-I04SafeErrorToken `
                    -Context 'Coordinator post-observation firewall snapshot failed' `
                    -Message $_.Exception.Message))
            }
        }
        if ($null -ne $socketSampler) {
            $null = Stop-I04SocketSampler -Sampler $socketSampler `
                -CleanupFailures $cleanupFailures
            if ($null -ne $restartBoundaryEpochMs -and
                $null -ne $restartBoundaryQpc -and
                (Test-Path -LiteralPath $socketSamplesPath `
                    -PathType Leaf)) {
                try {
                    $socketSamplerEvidence =
                        Get-I04SocketSamplerEvidence `
                            -Path $socketSamplesPath `
                            -CandidateProcessId $client.Id `
                            -BoundaryEpochMs $restartBoundaryEpochMs `
                            -BoundaryQpc $restartBoundaryQpc `
                            -ClockCoherenceToleranceMs `
                                $socketClockCoherenceToleranceMs
                    foreach ($portValue in @(
                        $socketSamplerEvidence.candidate_ipv4_local_ports
                    )) {
                        $null = $scenarioV4LocalPorts.Add(
                            [int]$portValue
                        )
                    }
                    foreach ($portValue in @(
                        $socketSamplerEvidence.candidate_ipv6_local_ports
                    )) {
                        $null = $scenarioV6LocalPorts.Add(
                            [int]$portValue
                        )
                    }
                    $scenarioV6SocketObserved =
                        [bool]$socketSamplerEvidence.candidate_ipv6_attempt_observed
                    $scenarioV4Established =
                        [bool]$socketSamplerEvidence.candidate_ipv4_established_observed
                    $scenarioV4SocketObserved =
                        @(
                            $socketSamplerEvidence.candidate_ipv4_local_ports
                        ).Count -gt 0
                    if (@(
                        $socketSamplerEvidence.other_pid_target_rows
                    ).Count -gt 0) {
                        $otherPidObserved = $true
                        foreach ($row in @(
                            $socketSamplerEvidence.other_pid_target_rows
                        )) {
                            $otherPidConnections.Add($row)
                        }
                    }
                    Write-LabJson -Value $socketSamplerEvidence `
                        -Path (
                            Join-Path $evidence 'socket-sampler.json'
                        ) | Out-Null
                } catch {
                    $cleanupFailures.Add((Get-I04SafeErrorToken `
                        -Context 'socket sampler evidence failed' `
                        -Message $_.Exception.Message))
                }
            }
        }
        try {
            if ($null -ne $capture) {
                Stop-I04PacketCapture -State $capture -JournalPath $journal `
                    -CleanupFailures $cleanupFailures
                $captureStoppedEpochMs = $capture.capture_ended_epoch_ms
            }
        } catch {
            $cleanupFailures.Add((Get-I04SafeErrorToken `
                -Context 'PktMon terminal cleanup failed' `
                -Message $_.Exception.Message))
        } finally {
            if ($null -ne $script:i04PktmonMutex) {
                try {
                    $pktmonMutexRelease = Exit-I04PktmonGlobalMutex
                    if (-not [bool]$pktmonMutexRelease.release_exact) {
                        throw 'PktMon global mutex release was not exact'
                    }
                } catch {
                    $cleanupFailures.Add((Get-I04SafeErrorToken `
                        -Context 'PktMon global mutex release failed' `
                        -Message $_.Exception.Message))
                }
            }
        }
        # Publish stop even when peer-ready timed out. A manually launched or
        # delayed remote peer will then see stop before arm and restore/exit
        # instead of leaving a source process or allow rule behind.
        if (-not $stopCommandWritten) {
            try {
                Write-LabJson -Value ([ordered]@{
                    schema = 'ese.v91.i04-stop-command/v1'
                    case_id = $caseId
                    run_nonce = $nonce
                    action = 'stop-and-restore'
                    requested_at_utc = Get-LabUtcTimestamp
                    candidate_commit = $candidate.commit
                    candidate_emule_sha256 = $expectedHash
                }) -Path $stopPath | Out-Null
                $stopCommandWritten = $true
            } catch {
                    $cleanupFailures.Add((Get-I04SafeErrorToken `
                        -Context 'peer stop command could not be written' `
                        -Message $_.Exception.Message))
            }
        }
        if ($stopCommandWritten -and $null -ne $peerReady) {
            $peerResult = Wait-I04File -Path $peerResultPath -TimeoutSeconds 90
            if ($null -eq $peerResult) {
                $cleanupFailures.Add('peer did not publish restoration evidence')
            } else {
                $peerTerminal = Wait-I04File -Path $peerTerminalPath `
                    -TimeoutSeconds 90
                if ($null -eq $peerTerminal) {
                    $cleanupFailures.Add(
                        'peer did not publish terminal outer-cleanup evidence'
                    )
                } else {
                    Write-LabJson -Value $peerTerminal -Path (
                        Join-Path $evidence 'peer-terminal.json'
                    ) | Out-Null
                    try {
                        $peerTerminalExact = Test-I04PeerTerminalContract `
                            -Terminal $peerTerminal `
                            -ExpectedCaseId $caseId `
                            -ExpectedRunNonce $nonce `
                            -ExpectedPeerResultSha256 (
                                Get-LabSha256 -Path $peerResultPath
                            )
                    } catch {
                        $peerTerminalExact = $false
                        $cleanupFailures.Add((Get-I04SafeErrorToken `
                            -Context 'peer terminal receipt validation failed' `
                            -Message $_.Exception.Message))
                    }
                    if (-not $peerTerminalExact) {
                        $cleanupFailures.Add(
                            'peer terminal outer-cleanup receipt was not exact'
                        )
                    }
                }
                Write-LabJson -Value $peerResult `
                    -Path (Join-Path $evidence 'peer-result.json') | Out-Null
                try {
                    $peerRestorationExact = $peerTerminalExact -and
                        [string]$peerResult.schema -eq
                            'ese.v91.i04-peer-result/v1' -and
                        [string]$peerResult.case_id -eq $caseId -and
                        [string]$peerResult.run_nonce -eq $nonce -and
                        [string]$peerResult.candidate_commit -eq
                            $candidate.commit -and
                        [string]$peerResult.candidate_emule_sha256 -eq
                            $expectedHash -and
                        [string]$peerResult.harness_bundle.schema -eq
                            'ese.v91.i04-harness-bundle/v1' -and
                        [string]$peerResult.harness_bundle.bundle_sha256 -eq
                            [string]$script:i04HarnessBundle.bundle_sha256 -and
                        [string]$peerResult.harness_bundle.harness_sha256 -eq
                            [string]$script:i04HarnessBundle.harness_sha256 -and
                        [string]$peerResult.harness_bundle.common_sha256 -eq
                            [string]$script:i04HarnessBundle.common_sha256 -and
                        [string]$peerResult.harness_bundle.prepare_node_sha256 -eq
                            [string]$script:i04HarnessBundle.prepare_node_sha256 -and
                        [bool]$peerResult.harness_bundle.
                            immutable_read_locks_held -and
                        [string]$peerResult.status -eq 'COMPLETE' -and
                        $null -eq $peerResult.runtime_error -and
                        [bool]$peerResult.cleanup.source_process_stopped -and
                        [bool]$peerResult.cleanup.terminal_ownership_census.
                            collector_ok -and
                        [bool]$peerResult.cleanup.terminal_ownership_census.
                            all_clear -and
                        @($peerResult.cleanup.terminal_ownership_census.
                            remaining_processes).Count -eq 0 -and
                        @($peerResult.cleanup.terminal_ownership_census.
                            remaining_tcp).Count -eq 0 -and
                        @($peerResult.cleanup.terminal_ownership_census.
                            remaining_udp).Count -eq 0 -and
                        [bool]$peerResult.cleanup.controlled_ed2k_server_stopped -and
                        -not [bool]$peerResult.cleanup.drop_rule_present -and
                        -not [bool]$peerResult.cleanup.allow4_rule_present -and
                        -not [bool]$peerResult.cleanup.allow6_rule_present -and
                        [bool]$peerResult.cleanup.isolation_initial.
                            strict_isolation_valid -and
                        [bool]$peerResult.cleanup.isolation_final.
                            strict_isolation_valid -and
                        [bool]$peerResult.cleanup.account_registry_transaction.
                            collector_ok -and
                        [bool]$peerResult.cleanup.account_registry_transaction.
                            safe_to_pass -and
                        [bool]$peerResult.cleanup.account_registry_transaction.
                            global_firewall_unchanged -and
                        [bool]$peerResult.cleanup.account_registry_transaction.
                            run_subtree_existed_before -and
                        [bool]$peerResult.cleanup.account_registry_transaction.
                            run_subtree_exists_after -and
                        [bool]$peerResult.cleanup.
                            global_firewall_scenario_unchanged -and
                        [string]$peerResult.cleanup.global_firewall_armed.
                            canonical_sha256 -eq
                            [string]$peerArmed.global_firewall_armed.
                                canonical_sha256 -and
                        [string]$peerResult.cleanup.global_firewall_pre_removal.
                            canonical_sha256 -eq
                            [string]$peerArmed.global_firewall_armed.
                                canonical_sha256 -and
                        -not [bool]$peerResult.cleanup.
                            account_registry_transaction.
                            destructive_restore_attempted -and
                        [bool]$peerResult.cleanup.
                            restricted_job_lease_cleanup.complete -and
                        [int]$peerResult.cleanup.
                            restricted_job_lease_cleanup.
                            remaining_registered_process_count -eq 0 -and
                        @($peerResult.cleanup.
                            restricted_job_lease_cleanup.failures).Count -eq 0 -and
                        @($peerResult.cleanup.failures).Count -eq 0
                    $peerResultExact = $peerRestorationExact -and
                        [bool]$peerResult.barrier_completed -and
                        $null -ne $peerArmed -and $null -ne $peerResumed -and
                        [int]$peerResult.old_process_id -eq
                            [int]$peerArmed.source_process_id -and
                        [int]$peerResult.restarted_process_id -eq
                            [int]$peerResumed.process_id
                } catch {
                    $peerRestorationExact = $false
                    $peerResultExact = $false
                    $cleanupFailures.Add((Get-I04SafeErrorToken `
                        -Context 'peer result schema could not be validated' `
                        -Message $_.Exception.Message))
                }
                if (-not $peerRestorationExact) {
                    $cleanupFailures.Add('peer restoration did not complete')
                }
            }
        }
        foreach ($ownedClientProcess in @(
            $clientOwnedProcesses | Sort-Object Id -Unique
        )) {
            $ownedClientProcess.Refresh()
            $ownedWasRunning = -not $ownedClientProcess.HasExited
            if (-not (Stop-I04OwnedProcess `
                -Process $ownedClientProcess -ExpectedPath $clientExe)) {
                $cleanupFailures.Add(
                    "client process $($ownedClientProcess.Id) could not be stopped safely"
                )
            } elseif ($ownedWasRunning) {
                Add-I04RollbackJournal -Path $journal `
                    -Mutation 'client-process' -State 'rolled_back' `
                    -Detail "pid=$($ownedClientProcess.Id)" `
                    -CleanupFailures $cleanupFailures
            }
        }
        $clientControlledServerStop =
            Stop-I04ControlledEd2kServerInventory `
                -OwnerInventory $clientControlledServersOwned `
                -PrimaryServer $clientControlledServer
        if (-not [bool]$clientControlledServerStop.stopped -or
            [string]$clientControlledServerStop.error) {
            $cleanupFailures.Add(
                'coordinator controlled eD2K server cleanup failed: ' +
                [string]$clientControlledServerStop.error
            )
        }
        if ($null -ne $remoteJob) {
            try {
                $completedRemoteJob = Wait-Job -Job $remoteJob `
                    -Timeout 90 -ErrorAction Stop
                if ($null -eq $completedRemoteJob -or
                    [string]$remoteJob.State -cne 'Completed') {
                    throw 'remote peer job did not reach Completed state'
                }
                $null = Receive-Job -Job $remoteJob -Wait -ErrorAction Stop
                $remoteChildren = @($remoteJob.ChildJobs)
                if ($remoteChildren.Count -eq 0 -or
                    @($remoteChildren | Where-Object {
                        [string]$_.State -cne 'Completed' -or
                        @($_.Error).Count -ne 0
                    }).Count -ne 0 -or @($remoteJob.Error).Count -ne 0) {
                    throw 'remote peer job or child job contained terminal errors'
                }
                $remoteJobTerminalExact = $true
                Remove-Job -Job $remoteJob -Force -ErrorAction Stop
            } catch {
                $remoteJobTerminalExact = $false
                $cleanupFailures.Add((Get-I04SafeErrorToken `
                    -Context 'remote peer job cleanup failed' `
                    -Message $_.Exception.Message))
                try {
                    Stop-Job -Job $remoteJob -ErrorAction Stop
                } catch {}
                try {
                    Remove-Job -Job $remoteJob -Force -ErrorAction Stop
                } catch {}
            }
        }
        $peerRestorationExact = $peerRestorationExact -and
            $peerTerminalExact -and $remoteJobTerminalExact
        $peerResultExact = $peerResultExact -and
            $peerTerminalExact -and $remoteJobTerminalExact
        if ($PeerControlMode -eq 'PowerShellRemoting' -and
            -not $remoteJobTerminalExact) {
            $cleanupFailures.Add(
                'remote peer process did not terminate Completed/error-free'
            )
        }
        if ($null -eq $scenarioFinished -and $null -ne $scenarioStarted) {
            $scenarioFinished = [DateTime]::UtcNow
        }
    }

    if ($clientNode -and (Test-Path -LiteralPath $clientNode) -and
        $null -ne $peerReady) {
        $logAfter = Get-I04ProductLogCounts -NodePath $clientNode `
            -PeerIPv4 $peerV4Text -PeerIPv6 $peerV6Text `
            -PeerPort $PeerTcpPort -FileAName (
                [string]$peerReady.fixtures.a.name
            ) -FileBName ([string]$peerReady.fixtures.b.name)
        if (-not [bool]$logAfter.collector_ok -or
            -not [bool]$logAfter.adjudicable -or
            [int]$logAfter.log_file_count -lt 1) {
            $blockedReasons.Add(
                'Product log final collector did not complete exactly'
            )
        }
        Write-LabJson -Value $logAfter `
            -Path (Join-Path $evidence 'logs-after-drop.json') | Out-Null
    } else {
        $blockedReasons.Add(
            'Product log final collector source directory was unavailable'
        )
    }
    if ($null -ne $capture) {
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-etw-loss/v2'
            captured_at_utc = Get-LabUtcTimestamp
            sample_phase = [string]$capture.etw_loss_sample_phase
            final_flush_succeeded =
                [bool]$capture.etw_final_flush_succeeded
            final_flush_error_code = $capture.etw_final_flush_error_code
            post_flush_query_ok = [bool]$capture.etw_post_flush_query_ok
            query_error = $capture.etw_query_error
            events_lost = $capture.etw_events_lost
            log_buffers_lost = $capture.etw_log_buffers_lost
            realtime_buffers_lost = $capture.etw_realtime_buffers_lost
            buffers_lost = $capture.etw_buffers_lost
            buffers_written = $capture.etw_buffers_written
            loss_proved_zero = [bool]$capture.etw_loss_proved_zero
        }) -Path (Join-Path $evidence 'capture\etw-loss.json') | Out-Null
    }
    if ($null -ne $capture -and
        (Test-Path -LiteralPath $capture.pcapng_path -PathType Leaf) -and
        $null -ne $socketSamplerEvidence -and $null -ne $client -and
        $null -ne $armRequestedEpochMs -and
        $null -ne $restartBoundaryEpochMs -and
        $null -ne $captureStoppedEpochMs) {
        try {
            $packetVerdict = Get-I04PacketVerdict `
                -PcapNgPath $capture.pcapng_path `
                -IPv4 $peerV4Text -IPv6 $peerV6Text `
                -CoordinatorIPv4 $coordinatorV4Text `
                -CoordinatorIPv6 $coordinatorV6Text -Port $PeerTcpPort `
                -NotBeforeEpochMs $armRequestedEpochMs `
                -ScenarioBoundaryEpochMs $restartBoundaryEpochMs `
                -ObservationEndEpochMs $captureStoppedEpochMs `
                -LimitSeconds $FallbackLimitSeconds `
                -MinimumSilentWindowMs $minimumSilentWindowMs `
                -CandidateProcessId $client.Id `
                -SocketSamplerEvidence $socketSamplerEvidence `
                -ExpectedAdapterEvidence ([pscustomobject][ordered]@{
                    interface_index =
                        [int]$coordinatorAssignedV4.InterfaceIndex
                    interface_id = [string]$routeV4.interface_id
                    name = [string]$coordinatorAdapter.Name
                    description =
                        [string]$coordinatorAdapter.InterfaceDescription
                    hardware_interface =
                        [bool]$coordinatorAdapter.HardwareInterface
                    virtual = $coordinatorAdapterVirtual
                    overlay_or_vpn_like = $coordinatorAdapterOverlayLike
                    status = [string]$coordinatorAdapter.Status
                }) `
                -SynCorrelationToleranceMs $captureTimingToleranceMs `
                -ExcludedTupleKeys @($prewarmTuples)
            Write-LabJson -Value $packetVerdict `
                -Path (Join-Path $evidence 'packet-verdict.json') | Out-Null
        } catch {
            $blockedReasons.Add((Get-I04SafeErrorToken `
                -Context 'Packet capture could not be adjudicated' `
                -Message $_.Exception.Message))
        }
    }

    $logsAdjudicable = $null -ne $logBefore -and
        $null -ne $logAfter -and
        [bool]$logBefore.collector_ok -and [bool]$logAfter.collector_ok -and
        [bool]$logBefore.adjudicable -and [bool]$logAfter.adjudicable -and
        [int]$logBefore.log_file_count -gt 0 -and
        [int]$logAfter.log_file_count -gt 0
    if (-not $logsAdjudicable) {
        $blockedReasons.Add(
            'Product log snapshots are absent, empty or non-adjudicable'
        )
    }
    $fallbackDelta = if ($logsAdjudicable) {
        [int]$logAfter.fallback_count - [int]$logBefore.fallback_count
    } else { $null }
    $boundedFallbackDelta = if ($logsAdjudicable) {
        [int]$logAfter.bounded_fallback_count -
            [int]$logBefore.bounded_fallback_count
    } else { $null }
    $helloDelta = if ($logsAdjudicable) {
        [int]$logAfter.hello_send_count - [int]$logBefore.hello_send_count
    } else { $null }
    $helloAnswerDelta = if ($logsAdjudicable) {
        [int]$logAfter.hello_answer_receive_count -
            [int]$logBefore.hello_answer_receive_count
    } else { $null }
    $a4afSwapDelta = if ($logsAdjudicable) {
        [int]$logAfter.a4af_swap_a_to_b_count -
            [int]$logBefore.a4af_swap_a_to_b_count
    } else { $null }
    $ambiguousMarkerDelta = if ($logsAdjudicable) {
        [int]$logAfter.ambiguous_target_marker_count -
            [int]$logBefore.ambiguous_target_marker_count
    } else { $null }

    $telemetryFieldsComplete =
        $null -ne $apiTelemetryBaseline -and
        $null -ne $apiTelemetryFinal -and
        $null -ne $apiTelemetryBaseline.connecting_client_count -and
        $null -ne $apiTelemetryBaseline.connecting_client_adds -and
        $null -ne $apiTelemetryBaseline.connecting_client_high_water -and
        $null -ne
            $apiTelemetryBaseline.connecting_client_duplicate_adds -and
        $null -ne $apiTelemetryFinal.connecting_client_count -and
        $null -ne $apiTelemetryFinal.connecting_client_adds -and
        $null -ne $apiTelemetryFinal.connecting_client_high_water -and
        $null -ne
            $apiTelemetryFinal.connecting_client_duplicate_adds
    $telemetryAddsDelta = if ($telemetryFieldsComplete) {
        [Int64]$apiTelemetryFinal.connecting_client_adds -
            [Int64]$apiTelemetryBaseline.connecting_client_adds
    } else { $null }
    $telemetryDuplicateDelta = if ($telemetryFieldsComplete) {
        [Int64]$apiTelemetryFinal.connecting_client_duplicate_adds -
        [Int64]$apiTelemetryBaseline.connecting_client_duplicate_adds
    } else { $null }
    $productLogFailureEvidence = if ($logsAdjudicable) {
        [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-product-log-delta-evidence/v1'
            candidate_ownership_id_sha256 =
                [string]$client.i04_ownership_id_sha256
            collector_ok = $true
            adjudicable = $true
            before = $logBefore
            after = $logAfter
            fallback_delta = [int]$fallbackDelta
            bounded_fallback_delta = [int]$boundedFallbackDelta
            hello_send_delta = [int]$helloDelta
            hello_answer_receive_delta = [int]$helloAnswerDelta
            a4af_swap_a_to_b_delta = [int]$a4afSwapDelta
        }
    } else { $null }
    $telemetryFailureEvidence = if ($telemetryFieldsComplete) {
        [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-telemetry-delta-evidence/v1'
            candidate_ownership_id_sha256 =
                [string]$client.i04_ownership_id_sha256
            collector_ok = [bool]$apiTelemetryBaseline.available -and
                [bool]$apiTelemetryFinal.available
            adjudicable = [bool]$apiTelemetryBaseline.available -and
                [bool]$apiTelemetryFinal.available
            baseline = $apiTelemetryBaseline
            final = $apiTelemetryFinal
            adds_delta = [Int64]$telemetryAddsDelta
            duplicate_adds_delta = [Int64]$telemetryDuplicateDelta
            observed_current_max = [Int64]$telemetryObservedCurrentMax
            observed_adds_max = [Int64]$telemetryObservedAddsMax
            observed_duplicate_adds_max =
                [Int64]$telemetryObservedDuplicateMax
            observed_high_water_max =
                [Int64]$telemetryObservedHighWaterMax
        }
    } else { $null }
    $candidateFailureAdjudicable = $null -ne
        $candidatePostTriggerFailure -and
        $null -ne $failureDisposition -and
        [string]$failureDisposition.classification -ceq 'FAIL' -and
        [bool]$failureDisposition.candidate_failure_contract_valid -and
        [bool]$candidatePostTriggerFailure.source_bound -and
        [bool]$candidatePostTriggerFailure.adjudicable
    $apiFinalIsolationExact = $candidateFailureAdjudicable -or (
        $telemetryFieldsComplete -and
        (Test-I04ApiIsolation -Data $apiTelemetryFinal `
            -RequireEd2k $true)
    )

    $peerScenarioExact = $peerReadyExact -and $peerArmedExact -and
        $peerResumedExact
    $peerFirewallScenarioEvidenceExact =
        $null -ne $peerResult -and $null -ne $peerArmed -and
        [bool]$peerResult.cleanup.global_firewall_scenario_unchanged -and
        [string]$peerArmed.global_firewall_armed.canonical_sha256 -match
            '^[0-9a-f]{64}$' -and
        [string]$peerResult.cleanup.global_firewall_armed.canonical_sha256 `
            -ceq [string]$peerArmed.global_firewall_armed.canonical_sha256 -and
        [string]$peerResult.cleanup.global_firewall_pre_removal.
            canonical_sha256 -ceq
            [string]$peerArmed.global_firewall_armed.canonical_sha256
    $peerFirewallScenarioContradicted = $caseArmed -and
        -not $peerFirewallScenarioEvidenceExact
    $peerExact = $peerScenarioExact -and $peerResultExact
    if ($peerFirewallScenarioContradicted) {
        $blockedReasons.Add(
            'Peer global firewall drifted or lacked exact armed-to-pre-removal scenario evidence'
        )
    }
    if ($otherPidObserved) {
        $blockedReasons.Add(
            'A non-candidate PID owned a post-boundary target connection'
        )
    }
    if ($logsAdjudicable -and $ambiguousMarkerDelta -ne 0) {
        $blockedReasons.Add(
            "Target log attribution is ambiguous ($ambiguousMarkerDelta marker(s))"
        )
    }
    if ($null -ne $packetVerdict -and
        -not [bool]$packetVerdict.pid_packet_correlation_complete) {
        $blockedReasons.Add(
            'PCAP target SYNs were ambiguous or lacked a nearby exact 5-tuple sample owned only by the candidate PID'
        )
    }
    if ($null -ne $packetVerdict -and (
        -not [bool]$packetVerdict.pcapng_parser_complete -or
        [int]$packetVerdict.pcapng_trailing_byte_count -ne 0 -or
        [int]$packetVerdict.pcapng_block_error_count -ne 0 -or
        [int]$packetVerdict.pcapng_idb_option_error_count -ne 0 -or
        [int]$packetVerdict.pcapng_truncated_frame_count -ne 0 -or
        [int]$packetVerdict.pcapng_unknown_interface_frame_count -ne 0 -or
        [int]$packetVerdict.pcapng_unsupported_linktype_frame_count -ne 0 -or
        [int]$packetVerdict.pcapng_unsupported_packet_block_count -ne 0 -or
        [int]$packetVerdict.pcapng_parse_null_frame_count -ne 0 -or
        [int]$packetVerdict.pcapng_non_adjudicable_frame_count -ne 0)) {
        $blockedReasons.Add(
            'PCAPNG contained truncated, unsupported, unparseable or structurally incomplete frame evidence'
        )
    }
    if ($null -ne $packetVerdict -and (
        -not [bool]$packetVerdict.capture_interface_binding_exact -or
        -not [bool]$packetVerdict.target_frames_on_expected_physical_nic -or
        [int]$packetVerdict.foreign_interface_target_frame_count -ne 0)) {
        $blockedReasons.Add(
            'PCAPNG target frames were not bound uniquely to the proved physical coordinator NIC'
        )
    }
    if ($null -eq $capture -or
        [string]$capture.etw_loss_schema -cne
            'ese.v91.i04-etw-loss/v2' -or
        [string]$capture.etw_loss_sample_phase -cne
            'post-final-flush-pre-stop' -or
        -not [bool]$capture.etw_final_flush_succeeded -or
        -not [bool]$capture.etw_post_flush_query_ok -or
        -not [bool]$capture.etw_loss_proved_zero) {
        $blockedReasons.Add(
            'PktMon ETW zero-loss capture was not proved; packet absence is inadmissible'
        )
    }
    if ($null -eq $capture -or
        -not [bool]$capture.filter_inventory_scenario_unchanged -or
        [string]$capture.filter_inventory_armed_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$capture.filter_inventory_pre_stop_sha256 -cne
            [string]$capture.filter_inventory_armed_sha256) {
        $blockedReasons.Add(
            'PktMon exact filter inventory was not stable through the capture boundary'
        )
    }
    if ($null -ne $capture -and
        -not [bool]$capture.etl_below_circular_limit) {
        $blockedReasons.Add(
            'PktMon ETL may have wrapped at its 256 MiB circular limit'
        )
    }
    if ($null -ne $socketSamplerEvidence -and
        -not [bool]$socketSamplerEvidence.clock_coherence_valid) {
        $blockedReasons.Add(
            'PID socket-sampler epoch/QPC clock coherence was not proved'
        )
    }
    if ($null -eq $socketSamplerEvidence -or
        -not [bool]$socketSamplerEvidence.sampler_coverage_valid) {
        $blockedReasons.Add(
            'Independent 25 ms PID socket-sampler coverage was not proved'
        )
    }
    if ($null -ne $packetVerdict -and
        [int]$packetVerdict.pre_boundary_target_syn_count -ne 0) {
        $blockedReasons.Add(
            'A target SYN occurred between capture/pause and formal Stop A; scheduler trigger was consumed early'
        )
    }
    if ($null -ne $packetVerdict -and
        [bool]$packetVerdict.environment_rejected_blackhole_in_fixed_window) {
        $blockedReasons.Add(
            'IPv6 returned TCP/RST/application or correlated ICMPv6 in the fixed 2.75-second environment window'
        )
    }
    if ($null -ne $packetVerdict -and
        [int]$packetVerdict.ipv6_syn_count -gt 0 -and
        [double]$packetVerdict.capture_coverage_after_syn6_ms -lt
            $minimumSilentWindowMs -and
        -not $candidateFailureAdjudicable) {
        $blockedReasons.Add(
            'Capture did not cover the full fixed 2.75-second environment window after SYN6'
        )
    }
    if (-not $telemetryFieldsComplete -and
        -not $candidateFailureAdjudicable) {
        $blockedReasons.Add(
            'Final connecting-client telemetry is absent; product deltas are not adjudicable'
        )
    }
    if (-not $apiFinalIsolationExact) {
        $blockedReasons.Add(
            'Final client eD2K/Kad/NetLab isolation gates were not proved'
        )
    }
    $livenessEvidenceComplete = $apiProbeCount -gt 0 -and
        $apiFailureCount -eq 0 -and $apiMaxMs -lt 1000 -and
        $uiProbeCount -gt 0 -and $uiMissingCount -eq 0 -and
        $uiFailureCount -eq 0 -and $uiMaxMs -lt 500
    if (-not $candidateFailureAdjudicable -and
        -not $livenessEvidenceComplete) {
        $blockedReasons.Add(
            'Post-boundary API/UI liveness evidence was incomplete or non-adjudicable'
        )
    }
    $triggerFixtureRuntimeValid = $peerScenarioExact -and
        $peerFirewallScenarioEvidenceExact -and
        $null -eq $runtimeFailure -and
        $logsAdjudicable -and
        ($candidateFailureAdjudicable -or $livenessEvidenceComplete) -and
        $null -ne $baselineV4 -and $baselineV4.connected -and
        $null -ne $baselineV6 -and $baselineV6.connected -and
        $prewarmEstablished -and $prewarmProgress -and
        $schedulerFloorSatisfied -and
        $null -ne $pauseOperation -and
        $null -ne $stopAOperation -and
        [string]$pauseOperation.operation -eq 'pause' -and
        [string]$stopAOperation.operation -eq 'stop' -and
        [string]$fileAPaused.state -eq 'paused' -and
        $clientIsolationExact -and
        $apiFinalIsolationExact -and
        $null -ne $clientIdentity -and
        [string]$clientIdentity.user_hash -ne
            [string]$peerReady.process.persisted_identity.user_hash -and
        $null -ne $packetVerdict -and
        $null -ne $capture -and
        [string]$capture.etw_loss_schema -ceq
            'ese.v91.i04-etw-loss/v2' -and
        [string]$capture.etw_loss_sample_phase -ceq
            'post-final-flush-pre-stop' -and
        [bool]$capture.etw_final_flush_succeeded -and
        [bool]$capture.etw_post_flush_query_ok -and
        [bool]$capture.etw_loss_proved_zero -and
        [bool]$capture.filter_inventory_scenario_unchanged -and
        [string]$capture.filter_inventory_armed_sha256 -match
            '^[0-9a-f]{64}$' -and
        [string]$capture.filter_inventory_pre_stop_sha256 -ceq
            [string]$capture.filter_inventory_armed_sha256 -and
        [bool]$capture.etl_below_circular_limit -and
        $null -ne $socketSamplerEvidence -and
        [bool]$socketSamplerEvidence.sampler_coverage_valid -and
        [int]$packetVerdict.pre_boundary_target_syn_count -eq 0 -and
        [bool]$packetVerdict.pcapng_parser_complete -and
        [int]$packetVerdict.pcapng_trailing_byte_count -eq 0 -and
        [int]$packetVerdict.pcapng_block_error_count -eq 0 -and
        [int]$packetVerdict.pcapng_idb_option_error_count -eq 0 -and
        [int]$packetVerdict.pcapng_truncated_frame_count -eq 0 -and
        [int]$packetVerdict.pcapng_unknown_interface_frame_count -eq 0 -and
        [int]$packetVerdict.pcapng_unsupported_linktype_frame_count -eq 0 -and
        [int]$packetVerdict.pcapng_unsupported_packet_block_count -eq 0 -and
        [int]$packetVerdict.pcapng_parse_null_frame_count -eq 0 -and
        [int]$packetVerdict.pcapng_non_adjudicable_frame_count -eq 0 -and
        [bool]$packetVerdict.capture_interface_binding_exact -and
        [bool]$packetVerdict.target_frames_on_expected_physical_nic -and
        [int]$packetVerdict.foreign_interface_target_frame_count -eq 0 -and
        [bool]$packetVerdict.pid_packet_correlation_complete -and
        ($candidateFailureAdjudicable -or
            [int]$packetVerdict.ipv6_syn_count -eq 0 -or
            [bool]$packetVerdict.silent_drop_proved) -and
        -not [bool]$packetVerdict.environment_rejected_blackhole_in_fixed_window -and
        -not $otherPidObserved -and $ambiguousMarkerDelta -eq 0
    if ($triggerFixtureRuntimeValid) {
        if ($candidateFailureAdjudicable) {
            $null = Assert-I04ProductFailureContract `
                -Failure $candidatePostTriggerFailure
            $productFailures.Add($candidatePostTriggerFailure)
        } elseif ([int]$packetVerdict.ipv6_syn_count -eq 0) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'ipv6_syn_missing' -DisplayMessage (
                    'Candidate emitted no IPv6 SYN after formal Stop A'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'packet_verdict' `
                -SourceEvidence $packetVerdict
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and
            -not $packetVerdict.fallback_in_planning_window) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'fallback_window' -DisplayMessage (
                    'First IPv4 SYN was not in the required ' +
                    '2.75-to-<8 second planning window'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'packet_verdict' `
                -SourceEvidence $packetVerdict
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and (
            -not $packetVerdict.connection_under_limit -or
            -not $packetVerdict.ipv4_final_ack_observed)) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'ipv4_connectivity' -DisplayMessage (
                    "IPv4 did not complete below $FallbackLimitSeconds seconds"
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'packet_verdict' `
                -SourceEvidence $packetVerdict
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and
            [int]$packetVerdict.distinct_ipv4_connection_attempts -ne 1) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'transport_attempt_count' -DisplayMessage (
                    'Expected one IPv4 fallback transport, observed ' +
                    [string]$packetVerdict.distinct_ipv4_connection_attempts
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'packet_verdict' `
                -SourceEvidence $packetVerdict
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and
            [int]$packetVerdict.distinct_ipv6_connection_attempts -ne 1) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'transport_attempt_count' -DisplayMessage (
                    'Expected one IPv6 transport attempt (retransmissions ' +
                    'share ISN), observed ' +
                    [string]$packetVerdict.distinct_ipv6_connection_attempts
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'packet_verdict' `
                -SourceEvidence $packetVerdict
        }
        if (-not $candidateFailureAdjudicable -and (
            $fallbackDelta -ne 1 -or $boundedFallbackDelta -ne 1)) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'product_log_contract' -DisplayMessage (
                    "Expected one bounded fallback log, observed fallback=$fallbackDelta bounded=$boundedFallbackDelta"
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'product_log_counts' `
                -SourceEvidence $productLogFailureEvidence
        }
        if (-not $candidateFailureAdjudicable -and
            $helloDelta -ne 1) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'product_log_contract' -DisplayMessage (
                    "Expected one queued HELLO after fallback, observed $helloDelta"
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'product_log_counts' `
                -SourceEvidence $productLogFailureEvidence
        }
        if (-not $candidateFailureAdjudicable -and
            $helloAnswerDelta -ne 1) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'product_log_contract' -DisplayMessage (
                    "Expected one HELLOANSWER after fallback, observed $helloAnswerDelta"
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'product_log_counts' `
                -SourceEvidence $productLogFailureEvidence
        }
        if (-not $candidateFailureAdjudicable -and
            $a4afSwapDelta -ne 1) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'product_log_contract' -DisplayMessage (
                    "Expected one A-to-B A4AF swap log, observed $a4afSwapDelta"
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'product_log_counts' `
                -SourceEvidence $productLogFailureEvidence
        }
        if (-not $candidateFailureAdjudicable -and (
            $null -eq $fileAStopped -or
            [string]$fileAStopped.state -ne 'stopped')) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'transfer_contract' -DisplayMessage (
                    'Classic Web did not prove file A stopped after the formal request'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'transfer_snapshot' -SourceEvidence $fileAStopped
        }
        if (-not $candidateFailureAdjudicable -and (
            $null -eq $fileBAfterTrigger -or
            -not [bool]$fileBAfterTrigger.found -or
            $null -eq $fileBAfterTrigger.source_total -or
            [int]$fileBAfterTrigger.source_total -lt 1 -or
            -not [bool]$fileBAfterTrigger.transferred_nonzero)) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'transfer_contract' -DisplayMessage (
                    'Classic Web did not prove file B retained the source ' +
                    'and advanced data after A-to-B swap'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'transfer_snapshot' `
                -SourceEvidence $fileBAfterTrigger
        }
        if ([bool]$packetVerdict.ipv4_final_ack_observed -and
            [double]$packetVerdict.post_ipv4_connected_observation_ms -lt
                10000) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'observation_window' -DisplayMessage (
                    'The required 10-second late-retry observation window did not complete'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'packet_verdict' `
                -SourceEvidence $packetVerdict
        }
        if ([int]$packetVerdict.ipv6_syn_count -gt 0 -and (
            -not $scenarioV4SocketObserved -or
            -not $scenarioV4Established)) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'socket_contract' -DisplayMessage (
                    'No working candidate IPv4 fallback socket was observed'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'socket_sampler' `
                -SourceEvidence $socketSamplerEvidence
        }
        if (-not $candidateFailureAdjudicable -and
            $telemetryFieldsComplete -and (
                [Int64]$apiTelemetryBaseline.connecting_client_count -ne 0 -or
                [Int64]$apiTelemetryBaseline.connecting_client_high_water -ne 1 -or
                [Int64]$telemetryObservedCurrentMax -ne 1 -or
                [Int64]$telemetryAddsDelta -ne 1 -or
                [Int64]$telemetryObservedAddsMax -ne
                    ([Int64]$apiTelemetryBaseline.connecting_client_adds + 1) -or
                [Int64]$telemetryDuplicateDelta -ne 0 -or
                [Int64]$telemetryObservedDuplicateMax -ne
                    [Int64]$apiTelemetryBaseline.connecting_client_duplicate_adds -or
                [Int64]$telemetryObservedHighWaterMax -ne 1 -or
                [Int64]$apiTelemetryFinal.connecting_client_high_water -ne 1 -or
                [Int64]$apiTelemetryFinal.connecting_client_count -ne 0
            )) {
            Add-I04TypedProductFailure -Failures $productFailures `
                -FailureType 'telemetry_contract' -DisplayMessage (
                    'connecting_client_* telemetry did not prove exactly ' +
                    'one logical A-to-B dial with no duplicate/re-add'
                ) -Process $client -ExpectedPath $clientExe `
                -BoundaryEpochMs $restartBoundaryEpochMs `
                -SourceKind 'telemetry_snapshot' `
                -SourceEvidence $telemetryFailureEvidence
        }
    } elseif ($blockedReasons.Count -eq 0) {
        $blockedReasons.Add(
            'The complete identities/A4AF/scheduler/DROP/capture trigger fixture was not proved'
        )
    }

    $candidateAfter = Get-I04CandidateEvidence -Binding $candidate
    $candidateUnchanged = $false
    try {
        $null = Assert-I04CandidateBindingUnchanged -Binding $candidate
        $candidateUnchanged = $true
    } catch {
        $cleanupFailures.Add((Get-I04SafeErrorToken `
            -Context 'candidate binding changed during execution' `
            -Message $_.Exception.Message))
    }
    $clientHashAfter = ''
    if ($clientExe) {
        try {
            $clientExeSafe = Assert-I04NoReparsePath `
                -Path $clientExe -Kind File
            $clientHashAfter = Get-LabSha256 -Path $clientExeSafe
        } catch {
            $cleanupFailures.Add((Get-I04SafeErrorToken `
                -Context 'isolated client binary could not be rebound' `
                -Message $_.Exception.Message))
        }
    }
    if (-not $candidateUnchanged) {
        $cleanupFailures.Add('candidate package changed during execution')
    }
    if ($clientExe -and $clientHashAfter -ne $expectedHash) {
        $cleanupFailures.Add('isolated client binary changed during execution')
    }
    $coordinatorIsolationFinal = Get-I04IsolationEvidence
    Write-LabJson -Value $coordinatorIsolationFinal -Path (
        Join-Path $evidence 'coordinator-isolation-final.json'
    ) | Out-Null
    if (-not [bool]$coordinatorIsolationFinal.strict_isolation_valid) {
        $cleanupFailures.Add(
            'coordinator overlay/VPN/proxy isolation was not intact at final audit'
        )
    }
    $clientOwnedProcessIds = @(
        $clientOwnedProcesses | ForEach-Object { [int]$_.Id } |
            Sort-Object -Unique
    )
    $clientTerminalCensus = Get-I04TerminalOwnershipCensus `
        -ProcessIds $clientOwnedProcessIds `
        -OwnedProcesses ([object[]]$clientOwnedProcesses.ToArray()) `
        -Ports @($ClientTcpPort, $ClientUdpPort, $ClientWebPort) `
        -HostRole 'Coordinator'
    $clientProcessesStopped = [bool]$clientTerminalCensus.collector_ok -and
        @($clientTerminalCensus.remaining_processes).Count -eq 0
    if (-not [bool]$clientTerminalCensus.collector_ok -or
        -not [bool]$clientTerminalCensus.all_clear) {
        $cleanupFailures.Add(
            'coordinator terminal process/TCP/UDP ownership census was not clear'
        )
    }
    $coordinatorAccountRegistryPostcheck =
        Get-I04AccountRegistryPostcheckEvidence `
            -Transaction $script:i04AccountRegistryTransaction
    $script:i04AccountRegistryPostcheck = $coordinatorAccountRegistryPostcheck
    $script:i04AccountRegistryPostcheckComplete = $true
    if (-not [bool]$coordinatorAccountRegistryPostcheck.safe_to_pass) {
        $cleanupFailures.Add(
            'coordinator account/registry/global-firewall postcheck was not exact'
        )
    }
    $restrictedJobLeaseCleanup =
        Complete-I04RestrictedJobLeaseCleanup -Context Coordinator
    if (-not [bool]$restrictedJobLeaseCleanup.complete) {
        $cleanupFailures.Add(
            'coordinator restricted Job Object leases were not terminally released'
        )
    }
    if ($null -eq $script:i04PktmonMutexEvidence -or
        -not [bool]$script:i04PktmonMutexEvidence.acquired -or
        -not [bool]$script:i04PktmonMutexEvidence.released -or
        -not [bool]$script:i04PktmonMutexEvidence.release_exact) {
        $cleanupFailures.Add(
            'PktMon global mutex ownership/release was not proved exactly'
        )
    }
    $cleanup = [ordered]@{
        schema = 'ese.v91.i04-coordinator-cleanup/v1'
        captured_at_utc = Get-LabUtcTimestamp
        client_process_stopped = $clientProcessesStopped
        client_process_ids = $clientOwnedProcessIds
        terminal_ownership_census = $clientTerminalCensus
        controlled_ed2k_server_stopped =
            $null -ne $clientControlledServerStop -and
            [bool]$clientControlledServerStop.stopped -and
            -not [string]$clientControlledServerStop.error
        controlled_ed2k_server_owner_count =
            if ($null -eq $clientControlledServerStop) {
                0
            } else { [int]$clientControlledServerStop.owner_count }
        controlled_ed2k_server_owner_results =
            if ($null -eq $clientControlledServerStop) {
                @()
            } else { @($clientControlledServerStop.owner_results) }
        socket_sampler_stopped = if ($null -eq $socketSampler) {
            $true
        } else { [bool]$socketSampler.Stopped }
        pktmon_capture_stopped = if ($null -eq $capture) {
            $true
        } else {
            -not [bool]$capture.started -and
            (-not [bool]$capture.ever_started -or
                [bool]$capture.etw_session_stopped_verified)
        }
        pktmon_owned_filters_remaining = if ($null -eq $capture) {
            0
        } else { @($capture.filters).Count }
        pktmon_owned_filters_absent_verified = if ($null -eq $capture) {
            $true
        } else { [bool]$capture.owned_filters_absent_verified }
        pktmon_filter_inventory_restored = if ($null -eq $capture) {
            $true
        } else { [bool]$capture.filter_inventory_restored_verified }
        pktmon_etl_below_circular_limit = if ($null -eq $capture) {
            $false
        } else { [bool]$capture.etl_below_circular_limit }
        pktmon_global_mutex = $script:i04PktmonMutexEvidence
        peer_restoration_confirmed = $peerRestorationExact
        peer_terminal_receipt_exact = $peerTerminalExact
        remote_job_terminal_exact = $remoteJobTerminalExact
        hosts_file_modified = $false
        dns_cache_modified = $false
        routes_modified = $false
        adapters_modified = $false
        local_firewall_modified = $false
        isolation_initial = $coordinatorIsolationInitial
        isolation_final = $coordinatorIsolationFinal
        account_registry_transaction = $coordinatorAccountRegistryPostcheck
        restricted_job_lease_cleanup = $restrictedJobLeaseCleanup
        retained_by_design = @(
            'coordinator OutputRoot profile', 'partial fixture', 'evidence',
            'nonce-scoped coordination records'
        )
        failures = @($cleanupFailures.ToArray())
    }
    Write-LabJson -Value $cleanup -Path $cleanupPath | Out-Null

    $distinctPhysicalHosts = $peerReadyExact -and
        [string]$peerReady.peer.machine_id_sha256 -ne $localMachineId
    $nativeGlobalIpv6 =
        (Get-I04StrictAddressClass -Address $peerV6Text) -eq
            'native-global-v6' -and
        (Get-I04StrictAddressClass -Address $coordinatorV6Text) -eq
            'native-global-v6'
    $coordinatorNativeRoutes = $routeV4.available -and
        $routeV6.available -and
        [bool]$routeV4.physical_nonvirtual -and
        [bool]$routeV6.physical_nonvirtual -and
        [int]$routeV4.interface_index -eq [int]$routeV6.interface_index -and
        [int]$routeV4.interface_index -eq
            [int]$coordinatorAssignedV4.InterfaceIndex -and
        [string]$routeV4.source_address -eq $coordinatorV4Text -and
        [string]$routeV6.source_address -eq $coordinatorV6Text
    $peerNativeRoutes = $peerReadyExact -and $peerArmedExact -and
        [bool]$peerReady.peer.route_to_coordinator_ipv6.available -and
        [bool]$peerReady.peer.route_to_coordinator_ipv6.
            physical_nonvirtual -and
        [bool]$peerArmed.route_to_observed_ipv4_client.available -and
        [bool]$peerArmed.route_to_observed_ipv4_client.
            physical_nonvirtual -and
        [int]$peerReady.peer.route_to_coordinator_ipv6.interface_index -eq
            [int]$peerReady.peer.ipv6_interface_index -and
        [int]$peerArmed.route_to_observed_ipv4_client.interface_index -eq
            [int]$peerReady.peer.ipv4_interface_index -and
        [string]$peerReady.peer.route_to_coordinator_ipv6.source_address -eq
            $peerV6Text -and
        [string]$peerArmed.route_to_observed_ipv4_client.source_address -eq
            $peerLocalV4Text
    $physicalAdaptersAndSockets = $peerReadyExact -and
        [bool]$peerReady.peer.physical -and
        [bool]$peerReady.peer.same_interface -and
        -not [bool]$peerReady.peer.overlay_or_vpn_like -and
        $coordinatorPhysical -and
        -not $coordinatorAdapterOverlayLike -and
        $null -ne $baselineV4 -and [bool]$baselineV4.connected -and
        $null -ne $baselineV6 -and [bool]$baselineV6.connected -and
        [bool]$peerReady.endpoint.dual_stack_listener -and
        $prewarmEstablished
    $overlayVpnProxyAbsent = $peerReadyExact -and
        [bool]$peerReady.peer.isolation.strict_isolation_valid -and
        [bool]$coordinatorIsolationInitial.strict_isolation_valid
    $relayAbsentBeforeTrigger = $peerReadyExact -and $peerResumedExact -and
        $clientIsolationExact -and $null -ne $apiTelemetryBaseline -and
        (Test-I04ApiIsolation -Data $peerReady.runtime_isolation `
            -RequireEd2k $true) -and
        (Test-I04ApiIsolation -Data $peerResumed.runtime_isolation `
            -RequireEd2k $true) -and
        (Test-I04ApiIsolation -Data $apiTelemetryBaseline `
            -RequireEd2k $true)
    $topologyDirectBase = $distinctPhysicalHosts -and
        $nativeGlobalIpv6 -and $coordinatorNativeRoutes -and
        $peerNativeRoutes -and $physicalAdaptersAndSockets -and
        $overlayVpnProxyAbsent -and $relayAbsentBeforeTrigger
    $topologyT1 = $topologyDirectBase -and
        $peerV4Text -eq $peerLocalV4Text -and
        [string]$peerArmed.observed_ipv4_client.address -eq
            $coordinatorV4Text -and
        [bool]$routeV4.on_link -and [bool]$routeV6.on_link -and
        [bool]$peerArmed.route_to_observed_ipv4_client.on_link -and
        [bool]$peerReady.peer.route_to_coordinator_ipv6.on_link
    $topologyT2Discriminator = $topologyDirectBase -and
        -not $topologyT1 -and (
            $peerV4Text -ne $peerLocalV4Text -or
            [string]$peerArmed.observed_ipv4_client.address -ne
                $coordinatorV4Text -or
            -not [bool]$routeV4.on_link -or
            -not [bool]$routeV6.on_link -or
            -not [bool]$peerArmed.route_to_observed_ipv4_client.on_link -or
            -not [bool]$peerReady.peer.route_to_coordinator_ipv6.on_link
        )
    $admissibleT2Ipv6NextHopClasses = @(
        'linklocal-v6', 'ula-v6', 'native-global-v6'
    )
    $topologyT2BilateralNativeNextHops =
        $topologyT2Discriminator -and
        [string]$routeV6.next_hop_class -in
            $admissibleT2Ipv6NextHopClasses -and
        [string]$peerReady.peer.route_to_coordinator_ipv6.next_hop_class -in
            $admissibleT2Ipv6NextHopClasses
    $topologyT2 = $topologyT2Discriminator -and
        $topologyT2BilateralNativeNextHops
    $topologyDirectStrict = $topologyT1 -or $topologyT2
    $observedTopology = if ($topologyT1) {
        'T1'
    } elseif ($topologyT2) {
        'T2'
    } else {
        'UNPROVED'
    }
    if (-not $topologyDirectStrict) {
        $blockedReasons.Add(
            'Neither strict direct T1 nor T2 was proved: two physical hosts, native global IPv6, physical data-plane routes/sockets and zero overlay/VPN/proxy/relay are required'
        )
    }
    $cleanupComplete = [bool]$cleanup.client_process_stopped -and
        [bool]$cleanup.terminal_ownership_census.collector_ok -and
        [bool]$cleanup.terminal_ownership_census.all_clear -and
        [bool]$cleanup.controlled_ed2k_server_stopped -and
        [bool]$cleanup.socket_sampler_stopped -and
        [bool]$cleanup.pktmon_capture_stopped -and
        [int]$cleanup.pktmon_owned_filters_remaining -eq 0 -and
        [bool]$cleanup.pktmon_owned_filters_absent_verified -and
        [bool]$cleanup.pktmon_filter_inventory_restored -and
        [bool]$cleanup.pktmon_global_mutex.acquired -and
        [bool]$cleanup.pktmon_global_mutex.released -and
        [bool]$cleanup.pktmon_global_mutex.release_exact -and
        [bool]$cleanup.peer_restoration_confirmed -and
        [bool]$cleanup.peer_terminal_receipt_exact -and
        [bool]$cleanup.remote_job_terminal_exact -and
        [bool]$cleanup.restricted_job_lease_cleanup.complete -and
        [int]$cleanup.restricted_job_lease_cleanup.
            remaining_registered_process_count -eq 0 -and
        [bool]$cleanup.account_registry_transaction.collector_ok -and
        [bool]$cleanup.account_registry_transaction.safe_to_pass -and
        [bool]$cleanup.account_registry_transaction.global_firewall_unchanged -and
        -not [bool]$cleanup.account_registry_transaction.
            destructive_restore_attempted -and
        [bool]$cleanup.isolation_initial.strict_isolation_valid -and
        [bool]$cleanup.isolation_final.strict_isolation_valid
    if ($cleanupFailures.Count -gt 0) {
        $blockedReasons.Add('Transactional cleanup did not complete')
    }
    if (-not $cleanupComplete) {
        $blockedReasons.Add('Cleanup postconditions were not all proved')
    }
    if ($null -ne $runtimeFailure) {
        $blockedReasons.Add((Get-I04SafeErrorToken `
            -Context 'Harness/runtime error' `
            -Message $runtimeFailure.Exception.Message))
    }

    $packetSamplerContradiction = $caseArmed -and
        $null -ne $packetVerdict -and
        $null -ne $socketSamplerEvidence -and
        [bool]$socketSamplerEvidence.sampler_coverage_valid -and (
            ($scenarioV6SocketObserved -and
                [int]$packetVerdict.ipv6_syn_count -eq 0) -or
            ($scenarioV4SocketObserved -and
                [int]$packetVerdict.ipv4_syn_count -eq 0) -or
            ($scenarioV4Established -and
                (-not [bool]$packetVerdict.ipv4_synack_observed -or
                 -not [bool]$packetVerdict.ipv4_final_ack_observed))
        )
    if ($packetSamplerContradiction) {
        $blockedReasons.Add(
            'PCAPNG and PID socket sampler contradicted each other'
        )
    }
    $pktmonFilterScenarioContradiction = $caseArmed -and (
        $null -eq $capture -or
        -not [bool]$capture.filter_inventory_scenario_unchanged -or
        [string]$capture.filter_inventory_armed_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$capture.filter_inventory_pre_stop_sha256 -cne
            [string]$capture.filter_inventory_armed_sha256
    )
    $proofContradicted = $caseArmed -and (
        -not $candidateUnchanged -or
        ($clientExe -and $clientHashAfter -ne $expectedHash) -or
        -not $coordinatorFirewallScenarioUnchanged -or
        $peerFirewallScenarioContradicted -or
        $pktmonFilterScenarioContradiction -or
        $packetSamplerContradiction
    )
    $fixtureProofComplete = $triggerFixtureRuntimeValid -and
        $topologyDirectStrict -and -not $proofContradicted
    $typedSourceBoundFailures = @($productFailures.ToArray() | Where-Object {
        try {
            $null = Assert-I04ProductFailureContract -Failure $_
            [bool]$_.source_bound -and [bool]$_.source.collector_ok -and
                [bool]$_.post_boundary -and [bool]$_.adjudicable
        } catch { $false }
    })
    $productFailuresTypedAndSourceBound =
        $typedSourceBoundFailures.Count -eq $productFailures.Count
    if (-not $productFailuresTypedAndSourceBound) {
        $blockedReasons.Add(
            'A product failure entry was not typed, source-bound and adjudicable'
        )
    }
    $productFailureProved = $fixtureProofComplete -and
        $productFailures.Count -gt 0 -and
        $productFailuresTypedAndSourceBound
    $triggerFixtureValid = $fixtureProofComplete -and $cleanupComplete -and
        $cleanupFailures.Count -eq 0 -and
        $null -eq $runtimeFailure -and
        $blockedReasons.Count -eq 0
    $adjudicationClean = $triggerFixtureValid -and $peerExact -and
        $null -eq $runtimeFailure -and $blockedReasons.Count -eq 0 -and
        $cleanupFailures.Count -eq 0 -and $cleanupComplete
    $adjudicablePostBoundaryCandidateFailure =
        $productFailureProved -and $caseArmed -and
        $formalBoundaryPublished -and $candidateFailureAdjudicable
    $partialVerdict = Get-I04PartialVerdict `
        -FixtureProofComplete $fixtureProofComplete `
        -ProductFailureProved $productFailureProved `
        -ProofContradicted $proofContradicted `
        -ProductFailureCount $productFailures.Count
    $formalStatus = if ($partialVerdict -eq 'FAIL') {
        'FAIL'
    } elseif ($partialVerdict -eq 'PASS' -and $adjudicationClean) {
        'PASS'
    } else {
        'BLOCKED'
    }

    $summary = [ordered]@{
        schema = 'ese.v91.i04-fallback/v1'
        case_id = $caseId
        formal_status = $formalStatus
        partial_verdict = $partialVerdict
        formal_v91_i04_eligible = $formalStatus -in @('PASS', 'FAIL')
        candidate = [ordered]@{
            commit = $candidate.commit
            version = $candidate.version
            expected_emule_sha256 = $expectedHash
            package_sha256_before = $candidate.emule_sha256
            package_sha256_after = if ($candidateUnchanged) {
                $expectedHash
            } else { '' }
            package_zip_sha256 = $candidate.package_zip_sha256
            package_manifest_sha256 = $candidate.package_manifest_sha256
            prepared_client_code_binding = $clientCodeBinding
            client_sha256_after = $clientHashAfter
            unchanged = $candidateUnchanged
            post_trigger_failure = $candidatePostTriggerFailure
            failure_disposition = $failureDisposition
            case_armed = $caseArmed
            formal_boundary_published = $formalBoundaryPublished
            post_boundary_failure_fail_precedence =
                $productFailureProved
        }
        harness_bundle = $script:i04HarnessBundle
        adjudication = [ordered]@{
            fixture_proof_complete = $fixtureProofComplete
            product_failure_proved = $productFailureProved
            product_failures_typed_and_source_bound =
                $productFailuresTypedAndSourceBound
            proof_contradicted = $proofContradicted
            packet_socket_sampler_contradiction =
                $packetSamplerContradiction
            pktmon_filter_scenario_contradiction =
                $pktmonFilterScenarioContradiction
            pktmon_filter_inventory_armed_sha256 = if ($null -ne $capture) {
                [string]$capture.filter_inventory_armed_sha256
            } else { $null }
            pktmon_filter_inventory_pre_stop_sha256 = if ($null -ne $capture) {
                [string]$capture.filter_inventory_pre_stop_sha256
            } else { $null }
            coordinator_global_firewall_scenario_unchanged =
                $coordinatorFirewallScenarioUnchanged
            peer_global_firewall_scenario_unchanged =
                $peerFirewallScenarioEvidenceExact
            peer_global_firewall_scenario_contradicted =
                $peerFirewallScenarioContradicted
            cleanup_complete = $cleanupComplete
            post_boundary_candidate_failure_adjudicable =
                $adjudicablePostBoundaryCandidateFailure
            proven_product_failure_survives_later_cleanup_incident = $true
        }
        topology = [ordered]@{
            required = 'T1_OR_T2_DIRECT_STRICT'
            accepted_topologies = @('T1', 'T2')
            observed_topology = $observedTopology
            proved = $topologyDirectStrict
            t1_direct_on_link = $topologyT1
            t2_direct_native_discriminator = $topologyT2Discriminator
            t2_bilateral_native_next_hops =
                $topologyT2BilateralNativeNextHops
            t2_proved = $topologyT2
            t2_admissible_ipv6_next_hop_classes =
                $admissibleT2Ipv6NextHopClasses
            distinct_physical_hosts = $distinctPhysicalHosts
            native_global_ipv6 = $nativeGlobalIpv6
            physical_adapters_and_sockets = $physicalAdaptersAndSockets
            overlay_vpn_proxy_absent = $overlayVpnProxyAbsent
            relay_absent_before_trigger = $relayAbsentBeforeTrigger
            local_machine_id_sha256 = $localMachineId
            peer_machine_id_sha256 = if (-not $peerReadyExact) {
                ''
            } else { [string]$peerReady.peer.machine_id_sha256 }
            peer_public_ipv4_endpoint = $peerV4Text
            peer_local_ipv4 = $peerLocalV4Text
            coordinator_route_to_peer_ipv4 = $routeV4
            coordinator_route_to_peer_ipv6 = $routeV6
            peer_route_to_observed_coordinator_ipv4 =
                if (-not $peerArmedExact) {
                    $null
                } else {
                    $peerArmed.route_to_observed_ipv4_client
                }
            peer_route_to_coordinator_ipv6 = if (-not $peerReadyExact) {
                $null
            } else {
                $peerReady.peer.route_to_coordinator_ipv6
            }
            coordinator_isolation_initial = $coordinatorIsolationInitial
            coordinator_isolation_final = $coordinatorIsolationFinal
            peer_isolation_initial = if (-not $peerReadyExact) {
                $null
            } else { $peerReady.peer.isolation }
            peer_isolation_final = if (-not $peerResultExact) {
                $null
            } else { $peerResult.cleanup.isolation_final }
        }
        fixture = [ordered]@{
            trigger_runtime_valid = $triggerFixtureRuntimeValid
            trigger_and_cleanup_valid = $triggerFixtureValid
            controlled_peer_acknowledged = $true
            dns_dependency = 'NOT_IN_SCOPE_V91_D01'
            exact_peer_scenario_artifacts = $peerScenarioExact
            exact_peer_artifacts_including_cleanup = $peerExact
            peer_ready_exact = $peerReadyExact
            peer_armed_exact = $peerArmedExact
            peer_resumed_exact = $peerResumedExact
            peer_result_exact = $peerResultExact
            peer_restoration_exact = $peerRestorationExact
            persisted_peer_identity = [ordered]@{
                initial_user_hash = if (-not $peerReadyExact) {
                    ''
                } else {
                    [string]$peerReady.process.persisted_identity.user_hash
                }
                resumed_user_hash = if (-not $peerResumedExact) {
                    ''
                } else {
                    [string]$peerResumed.persisted_identity.user_hash
                }
                same_across_restart = $peerReadyExact -and
                    $peerResumedExact -and
                    [string]$peerReady.process.persisted_identity.user_hash -eq
                        [string]$peerResumed.persisted_identity.user_hash
            }
            independent_client_identity = [ordered]@{
                user_hash = if ($null -eq $clientIdentity) {
                    ''
                } else { [string]$clientIdentity.user_hash }
                runtime_user_hash = if ($null -eq $clientRuntime) {
                    ''
                } else { [string]$clientRuntime.user_hash }
                controlled_server_user_hash =
                    if ($null -eq $clientServerLogin) {
                        ''
                    } else {
                        [string]$clientServerLogin.runtime_user_hash
                    }
                distinct_from_peer = $null -ne $clientIdentity -and
                    $peerReadyExact -and
                    [string]$clientIdentity.user_hash -ne
                        [string]$peerReady.process.persisted_identity.user_hash
            }
            IPv4_reached_real_listener_before_drop = if ($null -eq $baselineV4) {
                $false
            } else { [bool]$baselineV4.connected }
            IPv6_reached_real_listener_before_drop = if ($null -eq $baselineV6) {
                $false
            } else { [bool]$baselineV6.connected }
            real_ipv4_prewarm_established = $prewarmEstablished
            real_ipv4_prewarm_advanced_data = $prewarmProgress
            prewarm_first_established_at_utc =
                if ($null -eq $prewarmFirstEstablishedAt) {
                    $null
                } else { $prewarmFirstEstablishedAt.ToString('o') }
            scheduler_floor_seconds = $schedulerReconnectFloorSeconds
            scheduler_floor_satisfied = $schedulerFloorSatisfied
            pause_a_preparation = $pauseOperation
            stop_a_formal_trigger = $stopAOperation
            file_a_paused_before_trigger = $fileAPaused
            file_a_after_trigger = $fileAStopped
            file_b_before_trigger = $fileBReady
            file_b_after_trigger = $fileBAfterTrigger
            same_peer_dual_route_model = 'Initial connection to the real public HighID IPv4 endpoint (which may NAT-map to PeerLocalIPv4) receives the peer HELLO with configured global IPv6/DUALSTACK; the same persisted peer is then restarted behind a remote inbound IPv6 DROP. No DNS dependency, proxy, synthetic endpoint or test-only API is used.'
            remote_ipv6_drop_proved = if ($null -eq $packetVerdict) {
                $false
            } else { [bool]$packetVerdict.silent_drop_proved }
            packet_capture_zero_loss = $null -ne $capture -and
                [bool]$capture.etw_loss_proved_zero
            packet_capture_below_circular_limit =
                $null -ne $capture -and
                [bool]$capture.etl_below_circular_limit
            socket_sampler = $socketSamplerEvidence
            pre_boundary_target_syn_count =
                if ($null -eq $packetVerdict) {
                    $null
                } else {
                    [int]$packetVerdict.pre_boundary_target_syn_count
                }
            IPv4_operational_after_drop = $scenarioV4Established
            non_candidate_pid_observed = $otherPidObserved
            candidate_ipv4_local_ports = @(
                $scenarioV4LocalPorts | Sort-Object
            )
            candidate_ipv6_local_ports = @(
                $scenarioV6LocalPorts | Sort-Object
            )
        }
        timing = [ordered]@{
            limit_seconds = $FallbackLimitSeconds
            expected_fallback_delay_ms = $expectedFallbackDelayMs
            capture_tolerance_ms = $captureTimingToleranceMs
            socket_clock_coherence_tolerance_ms =
                $socketClockCoherenceToleranceMs
            minimum_silent_window_ms = $minimumSilentWindowMs
            arm_not_before_local_epoch_ms = $armRequestedEpochMs
            arm_not_before_local_qpc = $armRequestedQpc
            pause_a_boundary_local_epoch_ms = $pauseBoundaryEpochMs
            pause_a_boundary_local_qpc = $pauseBoundaryQpc
            restart_preparation_local_epoch_ms =
                $restartPreparationEpochMs
            restart_preparation_local_qpc = $restartPreparationQpc
            stop_a_formal_boundary_local_epoch_ms =
                $restartBoundaryEpochMs
            stop_a_formal_boundary_local_qpc = $restartBoundaryQpc
            local_qpc_frequency = [Diagnostics.Stopwatch]::Frequency
            capture_ended_local_epoch_ms = $captureStoppedEpochMs
            peer_stop_to_listener_ready_ms = if (-not $peerResumedExact) {
                $null
            } else { [Int64]$peerResumed.stop_to_listener_ready_ms }
            scenario_started_at_utc = if ($null -eq $scenarioStarted) {
                $null
            } else { $scenarioStarted.ToString('o') }
            scenario_finished_at_utc = if ($null -eq $scenarioFinished) {
                $null
            } else { $scenarioFinished.ToString('o') }
            packet_verdict = $packetVerdict
        }
        single_retry = [ordered]@{
            fallback_log_delta = $fallbackDelta
            bounded_fallback_log_delta = $boundedFallbackDelta
            hello_send_delta = $helloDelta
            hello_answer_receive_delta = $helloAnswerDelta
            a4af_swap_a_to_b_delta = $a4afSwapDelta
            ambiguous_target_marker_delta = $ambiguousMarkerDelta
            exactly_one_fallback = $fallbackDelta -eq 1 -and
                $boundedFallbackDelta -eq 1
            exactly_one_hello = $helloDelta -eq 1
            exactly_one_hello_answer = $helloAnswerDelta -eq 1
            exactly_one_a4af_swap = $a4afSwapDelta -eq 1
            connecting_client_telemetry = [ordered]@{
                complete = $telemetryFieldsComplete
                baseline = $apiTelemetryBaseline
                immediate_after_stop_a = $apiTelemetryTrigger
                peak = $apiTelemetryPeak
                final = $apiTelemetryFinal
                adds_delta = $telemetryAddsDelta
                duplicate_adds_delta = $telemetryDuplicateDelta
                observed_current_max = $telemetryObservedCurrentMax
                observed_adds_max = $telemetryObservedAddsMax
                observed_duplicate_adds_max =
                    $telemetryObservedDuplicateMax
                observed_high_water_max =
                    $telemetryObservedHighWaterMax
            }
        }
        liveness = [ordered]@{
            api_probe_count = $apiProbeCount
            api_failure_count = $apiFailureCount
            api_max_duration_ms = $apiMaxMs
            ui_probe_count = $uiProbeCount
            ui_missing_window_count = $uiMissingCount
            ui_unresponsive_count = $uiFailureCount
            ui_max_duration_ms = $uiMaxMs
        }
        product_failures = @($productFailures.ToArray())
        blocked_reasons = @(
            $blockedReasons.ToArray() | Select-Object -Unique
        )
        cleanup = $cleanup
        evidence = [ordered]@{
            dns_scope = 'evidence\dns-scope.json'
            baseline = 'evidence\baseline-reachability.json'
            prewarm_tuples = 'evidence\prewarm-tuples.json'
            pid_port_correlation = 'evidence\pid-port-correlation.json'
            peer_ready = 'evidence\peer-ready.json'
            peer_drop = 'evidence\peer-drop-armed.json'
            peer_quiesced = 'evidence\peer-quiesced.json'
            peer_resumed = 'evidence\peer-resumed.json'
            peer_result = 'evidence\peer-result.json'
            peer_terminal = 'evidence\peer-terminal.json'
            runtime_samples = 'evidence\runtime-samples.jsonl'
            socket_samples = 'evidence\socket-samples.ndjson'
            socket_sampler = 'evidence\socket-sampler.json'
            packet_capture = 'evidence\capture\i04-packets.pcapng'
            etw_loss = 'evidence\capture\etw-loss.json'
            packet_verdict = 'evidence\packet-verdict.json'
            formal_trigger_baseline =
                'evidence\formal-trigger-baseline.json'
            formal_trigger_boundary =
                'evidence\formal-trigger-boundary.json'
            log_counts_after = 'evidence\logs-after-drop.json'
            client_controlled_ed2k_server =
                'evidence\client-controlled-ed2k-server.json'
            mutation_journal = 'evidence\mutation-journal.jsonl'
            cleanup = 'evidence\cleanup.json'
            public_summary = 'evidence\public-summary.json'
            coordinator_terminal = 'evidence\coordinator-terminal.json'
            manual_peer_command = if ($PeerControlMode -eq 'Manual') {
                'evidence\MANUAL-PEER-COMMAND.txt'
            } else { $null }
        }
    }
    $script:i04CoordinatorPublication = [pscustomobject][ordered]@{
        summary = $summary
        summary_path = $summaryPath
        public_summary_path = $publicSummaryPath
        terminal_receipt_path = Join-Path $evidence 'coordinator-terminal.json'
        formal_status = $formalStatus
        observed_topology = $observedTopology
        output_path = $output
        failure_messages = @($productFailures.ToArray() | ForEach-Object {
            [string]$_.display_message
        })
    }
}

if ($Role -eq 'Peer') {
    Invoke-I04PeerRole
} else {
    Invoke-I04CoordinatorRole
}
$script:i04RoleCompleted = $true
} finally {
    if ($null -ne $script:i04AccountRegistryTransaction -and
        -not $script:i04AccountRegistryPostcheckComplete) {
        try {
            $script:i04AccountRegistryPostcheck =
                Get-I04AccountRegistryPostcheckEvidence `
                    -Transaction $script:i04AccountRegistryTransaction
            $script:i04AccountRegistryPostcheckComplete = $true
            if (-not [bool]$script:i04AccountRegistryPostcheck.safe_to_pass) {
                throw 'Terminal account/registry/global-firewall postcheck was not exact'
            }
        } catch { $i04TerminalRegistryFailure = $_ }
    }
    foreach ($lockedResource in @($script:i04CandidateLocks.ToArray())) {
        try { $lockedResource.Dispose() } catch {
            if ($null -eq $i04TerminalLockFailure) {
                $i04TerminalLockFailure = $_
            }
        }
    }
    $script:i04CandidateLocks.Clear()
    foreach ($lockedResource in @($script:i04EvidenceLocks.ToArray())) {
        try { $lockedResource.Dispose() } catch {
            if ($null -eq $i04TerminalLockFailure) {
                $i04TerminalLockFailure = $_
            }
        }
    }
    $script:i04EvidenceLocks.Clear()
    try {
        $terminalJobCleanup =
            Complete-I04RestrictedJobLeaseCleanup -Context OuterFinally
        if (-not [bool]$terminalJobCleanup.complete) {
            throw 'Restricted Job Object terminal release was not exact'
        }
    } catch {
        $i04TerminalJobFailure = $_
    }
    if ($null -ne $script:i04PktmonMutex) {
        try {
            $terminalPktmonCleanup = Exit-I04PktmonGlobalMutex
            if (-not [bool]$terminalPktmonCleanup.release_exact) {
                throw 'PktMon global mutex terminal release was not exact'
            }
        } catch {
            $i04TerminalPktmonFailure = $_
        }
    } elseif ($null -ne $script:i04PktmonMutexEvidence -and
        [bool]$script:i04PktmonMutexEvidence.acquired -and
        -not [bool]$script:i04PktmonMutexEvidence.release_exact) {
        $i04TerminalPktmonFailure =
            [InvalidOperationException]::new(
                'PktMon global mutex release evidence was not exact')
    }
    foreach ($lockedResource in @($script:i04HarnessBundleLocks.ToArray())) {
        try { $lockedResource.Dispose() } catch {
            if ($null -eq $i04TerminalLockFailure) {
                $i04TerminalLockFailure = $_
            }
        }
    }
    $script:i04HarnessBundleLocks.Clear()
    if ($null -ne $i04TerminalRegistryFailure) {
        throw $i04TerminalRegistryFailure
    }
    if ($null -ne $i04TerminalJobFailure) {
        throw $i04TerminalJobFailure
    }
    if ($null -ne $i04TerminalPktmonFailure) {
        throw $i04TerminalPktmonFailure
    }
    if ($null -ne $i04TerminalLockFailure) {
        throw $i04TerminalLockFailure
    }
    if ($Role -eq 'Peer' -and $script:i04RoleCompleted) {
        if ($null -eq $script:i04PeerTerminalReceiptPath -or
            [string]$script:i04PeerResultSha256 -notmatch
                '^[0-9a-f]{64}$' -or
            $null -eq $script:i04RestrictedJobLeaseCleanup -or
            -not [bool]$script:i04RestrictedJobLeaseCleanup.complete) {
            throw 'Peer terminal receipt prerequisites were not exact'
        }
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.i04-peer-terminal/v1'
            case_id = $caseId
            run_nonce = $RunNonce.ToLowerInvariant()
            status = 'COMPLETE'
            peer_result_sha256 = $script:i04PeerResultSha256
            restricted_job_lease_cleanup =
                $script:i04RestrictedJobLeaseCleanup
            candidate_locks_released =
                $script:i04CandidateLocks.Count -eq 0
            evidence_locks_released =
                $script:i04EvidenceLocks.Count -eq 0
            harness_bundle_locks_released =
                $script:i04HarnessBundleLocks.Count -eq 0
            account_registry_postcheck_complete =
                [bool]$script:i04AccountRegistryPostcheckComplete
            account_registry_safe_to_pass =
                [bool]$script:i04AccountRegistryPostcheck.safe_to_pass
            outer_cleanup_complete = $true
            completed_at_utc = Get-LabUtcTimestamp
        }) -Path $script:i04PeerTerminalReceiptPath | Out-Null
    }
}

if ($Role -eq 'Coordinator' -and $script:i04RoleCompleted) {
    $publication = $script:i04CoordinatorPublication
    $expectedPublicationProperties = @(
        'summary', 'summary_path', 'public_summary_path',
        'terminal_receipt_path', 'formal_status', 'observed_topology',
        'output_path', 'failure_messages'
    )
    if ($null -eq $publication -or
        (@($publication.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            (@($expectedPublicationProperties | Sort-Object) -join "`n") -or
        $null -eq $publication.summary -or
        [string]$publication.formal_status -notin @('PASS', 'FAIL', 'BLOCKED') -or
        [string]$publication.summary.formal_status -cne
            [string]$publication.formal_status -or
        $script:i04CandidateLocks.Count -ne 0 -or
        $script:i04EvidenceLocks.Count -ne 0 -or
        $script:i04HarnessBundleLocks.Count -ne 0 -or
        $null -eq $script:i04RestrictedJobLeaseCleanup -or
        -not [bool]$script:i04RestrictedJobLeaseCleanup.complete -or
        -not [bool]$script:i04AccountRegistryPostcheckComplete -or
        -not [bool]$script:i04AccountRegistryPostcheck.safe_to_pass -or
        ($null -ne $script:i04PktmonMutexEvidence -and
            [bool]$script:i04PktmonMutexEvidence.acquired -and
            -not [bool]$script:i04PktmonMutexEvidence.release_exact)) {
        throw 'Coordinator terminal publication prerequisites were not exact'
    }

    $publication.summary.outer_terminal_cleanup = [pscustomobject][ordered]@{
        restricted_job_lease_cleanup = $script:i04RestrictedJobLeaseCleanup
        candidate_locks_released = $true
        evidence_locks_released = $true
        harness_bundle_locks_released = $true
        pktmon_global_mutex_released = if (
            $null -eq $script:i04PktmonMutexEvidence
        ) { $true } else {
            [bool]$script:i04PktmonMutexEvidence.release_exact
        }
        account_registry_postcheck_complete = $true
        account_registry_safe_to_pass = $true
        outer_cleanup_complete = $true
    }
    Write-LabJson -Value $publication.summary `
        -Path ([string]$publication.summary_path) | Out-Null
    $summarySha256 = Get-LabSha256 `
        -Path ([string]$publication.summary_path)
    $publicProjection = Get-I04PublicSummaryProjection `
        -Summary $publication.summary -SourceSummarySha256 $summarySha256
    Write-LabJson -Value $publicProjection `
        -Path ([string]$publication.public_summary_path) | Out-Null
    $publicSummarySha256 = Get-LabSha256 `
        -Path ([string]$publication.public_summary_path)
    Write-LabJson -Value ([ordered]@{
        schema = 'ese.v91.i04-coordinator-terminal/v1'
        case_id = $caseId
        run_nonce = $RunNonce.ToLowerInvariant()
        formal_status = [string]$publication.formal_status
        summary_sha256 = $summarySha256
        public_summary_sha256 = $publicSummarySha256
        restricted_job_lease_cleanup = $script:i04RestrictedJobLeaseCleanup
        candidate_locks_released = $true
        evidence_locks_released = $true
        harness_bundle_locks_released = $true
        pktmon_global_mutex_released = [bool](
            $publication.summary.outer_terminal_cleanup.
                pktmon_global_mutex_released)
        account_registry_postcheck_complete = $true
        account_registry_safe_to_pass = $true
        outer_cleanup_complete = $true
        completed_at_utc = Get-LabUtcTimestamp
    }) -Path ([string]$publication.terminal_receipt_path) | Out-Null

    if ([string]$publication.formal_status -ceq 'FAIL') {
        throw "V91-I04 FAIL: $(@($publication.failure_messages) -join '; '). Evidence: $($publication.summary_path)"
    }
    if ([string]$publication.formal_status -ceq 'BLOCKED') {
        throw (
            'V91-I04 BLOCKED: ' +
            (@($publication.summary.blocked_reasons) -join '; ') +
            ". Evidence: $($publication.summary_path)"
        )
    }
    Write-Host (
        "V91-I04 PASS on exact candidate/$($publication.observed_topology): " +
        [string]$publication.output_path
    ) -ForegroundColor Green
}
