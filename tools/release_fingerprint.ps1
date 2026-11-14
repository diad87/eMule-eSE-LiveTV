function Test-ReleaseRequiresQuic {
    param([Parameter(Mandatory = $true)][string]$ReleaseTag)

    if ($ReleaseTag -notmatch '^v0\.70b-eSE(?<version>\d+\.\d+\.\d+)(?:-(?:alpha|beta|rc)\.\d+)?$') {
        throw "Invalid release tag: $ReleaseTag"
    }
    return [version]$Matches.version -ge [version]'9.3.0'
}

function Get-ReleaseLayout {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseTag,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )
    $win32 = $Architecture -eq 'Win32'
    $platform = if ($win32) { 'Win32' } else { 'x64' }
    $stampSuffix = if ($win32) { '-Win32' } else { '' }
    $releaseRoot = Join-Path $RepoRoot "dist\$ReleaseTag"
    $stampRoot = Join-Path $RepoRoot 'tools\build_logs'
    return [pscustomobject]@{
        Architecture = $platform
        Dashboard = -not $win32
        Runtime = Join-Path $RepoRoot "srchybrid\$platform\Release"
        ReleaseRoot = $releaseRoot
        Package = Join-Path $releaseRoot $(if ($win32) { 'package-x86' } else { 'package' })
        Archive = Join-Path $releaseRoot $(if ($win32) { "eMule-eSE-$ReleaseTag-x86.zip" } else { "eSE-LiveTV-$ReleaseTag-x64.zip" })
        EmuleStamp = Join-Path $stampRoot "emule-release-build$stampSuffix.json.log"
        LanguageStamp = Join-Path $stampRoot "languages-release-build$stampSuffix.json.log"
        DashboardStamp = Join-Path $stampRoot 'ese-release-build.json.log'
    }
}

function Assert-ReleasePEArchitecture {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($BinaryPath))
    try {
        $stream = $reader.BaseStream
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw "Invalid PE image: $BinaryPath" }
        $stream.Position = 0x3c
        $offset = $reader.ReadUInt32()
        if ($offset -lt 64 -or $offset -gt $stream.Length - 26) { throw "Invalid PE header: $BinaryPath" }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $BinaryPath" }
        $machine = $reader.ReadUInt16()
        $stream.Position = [long]$offset + 20
        $optionalSize = $reader.ReadUInt16()
        $stream.Position = [long]$offset + 24
        $magic = $reader.ReadUInt16()
        $expectedMachine = if ($Architecture -eq 'Win32') { 0x014c } else { 0x8664 }
        $expectedMagic = if ($Architecture -eq 'Win32') { 0x010b } else { 0x020b }
        if ($optionalSize -lt 2 -or $machine -ne $expectedMachine -or $magic -ne $expectedMagic) {
            throw "Expected $Architecture PE image: $BinaryPath"
        }
    } finally { $reader.Dispose() }
}

function Get-ReleaseQuicManifestHash {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$QuicReleaseRoot,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    $manifest = Join-Path $QuicReleaseRoot "manifest-$Architecture.json"
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifest).Hash
    & (Join-Path $RepoRoot 'tools\verify_quic_release_dependencies.ps1') `
        -Root $QuicReleaseRoot -Architecture $Architecture -ExpectedManifestSha256 $hash | Out-Null
    return $hash
}

function Assert-ReleaseQuicBinary {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$QuicManifestSha256,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    if ($QuicManifestSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw 'Signed QUIC build requires a manifest SHA-256'
    }
    Assert-ReleasePEArchitecture -BinaryPath $BinaryPath -Architecture $Architecture
    $versionInfo = (Get-Item -LiteralPath $BinaryPath).VersionInfo
    if ($versionInfo.Comments -ne "eSE QUIC manifest SHA-256 $QuicManifestSha256") {
        throw 'emule.exe was not linked with the verified signed QUIC manifest'
    }
}

function Get-ReleaseSourceFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [ValidateSet('emule', 'ese')][string]$Component,
        [switch]$IncludeQuic,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    $roots = if ($Component -eq 'ese') {
        @('srchybrid/eSE')
    } else {
        @(
            'srchybrid',
            'libkad6',
            'libnatmap',
            'libreach',
            'librelayclient',
            'librelaycore',
            'relayedge',
            'cryptopp',
            'CxImage',
            'id3lib',
            'libpng',
            'mbedtls',
            'miniupnpc',
            'ResizableLib',
            'zlib'
        )
    }
    $tracked = @(
        & git -C $RepoRoot -c core.quotepath=false ls-files -- $roots
    )
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) {
        throw "Could not enumerate tracked sources for $Component"
    }

    $include = if ($Component -eq 'ese') {
        '^srchybrid/eSE/(?!test/|_deprecated/|eSE_Remote\.html$).+'
    } else {
        '^(?:srchybrid/(?!eSE/|tests/)|libkad6/|libnatmap/|libreach/|' +
        'librelayclient/|librelaycore/|relayedge/|cryptopp/|CxImage/|' +
        'id3lib/|libpng/|mbedtls/|miniupnpc/|ResizableLib/|zlib/).+'
    }
    if ($IncludeQuic) {
        $quicInputs = @(
            'third_party/quic',
            'tools/quic',
            'tools/build_quic_msys2_candidate.ps1',
            'tools/verify_quic_release_dependencies.ps1'
        )
        if ($Architecture -eq 'Win32') {
            $quicInputs += @('tools/build_quic_msys2_win32_release.ps1', 'tools/libutp_win32.props')
            $include += '|^tools/(?:build_quic_msys2_win32_release\.ps1|libutp_win32\.props)$'
        }
        $tracked += @(& git -C $RepoRoot -c core.quotepath=false ls-files -- $quicInputs)
        if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate tracked QUIC release inputs' }
        $include += '|^(?:third_party/quic/|tools/quic/|tools/(?:build_quic_msys2_candidate|verify_quic_release_dependencies)\.ps1$)'
    }

    $manifest = [Text.StringBuilder]::new()
    $selected = @($tracked |
        Where-Object { ([string]$_).Replace('\', '/') -match $include } |
        Sort-Object -Unique)
    if ($selected.Count -eq 0) {
        throw "No tracked source inputs selected for $Component"
    }

    foreach ($relative in $selected) {
        $normalized = ([string]$relative).Replace('\', '/')
        $source = Join-Path $RepoRoot $normalized
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Tracked source input is missing: $normalized"
        }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
        [void]$manifest.Append($hash.ToUpperInvariant())
        [void]$manifest.Append('  ')
        [void]$manifest.Append($normalized)
        [void]$manifest.Append("`n")
    }

    if ($Component -eq 'emule') {
        $submoduleRoot = Join-Path $RepoRoot 'libutp'
        $submoduleFiles = @(
            & git -C $submoduleRoot -c core.quotepath=false ls-files
        )
        if ($LASTEXITCODE -ne 0 -or $submoduleFiles.Count -eq 0) {
            throw 'Could not enumerate the pinned libutp build inputs'
        }
        $submoduleCommit = (& git -C $submoduleRoot rev-parse HEAD).Trim()
        [void]$manifest.Append("SUBMODULE  libutp@$submoduleCommit`n")
        foreach ($relative in ($submoduleFiles | Sort-Object -Unique)) {
            $normalized = ([string]$relative).Replace('\', '/')
            $source = Join-Path $submoduleRoot $normalized
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "Tracked libutp input is missing: $normalized"
            }
            $hash = (
                Get-FileHash -Algorithm SHA256 -LiteralPath $source
            ).Hash.ToUpperInvariant()
            [void]$manifest.Append($hash)
            [void]$manifest.Append('  libutp/')
            [void]$manifest.Append($normalized)
            [void]$manifest.Append("`n")
        }
    }

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($manifest.ToString())
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
    } finally {
        $sha.Dispose()
    }
}

function Write-ReleaseBinaryStamp {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseTag,
        [Parameter(Mandatory = $true)]
        [ValidateSet('emule', 'ese')][string]$Component,
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$StampPath,
        [string]$QuicManifestSha256,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        throw "Release binary is missing: $BinaryPath"
    }
    $requiresQuic = $Component -eq 'emule' -and (Test-ReleaseRequiresQuic $ReleaseTag)
    if ($requiresQuic) {
        Assert-ReleaseQuicBinary -BinaryPath $BinaryPath -QuicManifestSha256 $QuicManifestSha256 -Architecture $Architecture
    }
    $stampParent = Split-Path -Parent $StampPath
    New-Item -ItemType Directory -Path $stampParent -Force | Out-Null
    $binary = Get-Item -LiteralPath $BinaryPath
    $stamp = [ordered]@{
        schema = 1
        component = $Component
        releaseTag = $ReleaseTag
        commit = (& git -C $RepoRoot rev-parse HEAD).Trim()
        sourceFingerprint = Get-ReleaseSourceFingerprint `
            -RepoRoot $RepoRoot -Component $Component -IncludeQuic:$requiresQuic -Architecture $Architecture
        binarySha256 = (
            Get-FileHash -Algorithm SHA256 -LiteralPath $BinaryPath
        ).Hash.ToUpperInvariant()
        binaryLength = [long]$binary.Length
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    if ($requiresQuic) {
        $stamp.architecture = $Architecture
        $stamp.quicManifestSha256 = $QuicManifestSha256.ToUpperInvariant()
    }
    $stamp | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath $StampPath -Encoding UTF8
}

function Assert-ReleaseBinaryStamp {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseTag,
        [Parameter(Mandatory = $true)]
        [ValidateSet('emule', 'ese')][string]$Component,
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$StampPath,
        [string]$QuicManifestSha256,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        throw "Release binary is missing: $BinaryPath"
    }
    if (-not (Test-Path -LiteralPath $StampPath -PathType Leaf)) {
        throw "Release binary provenance is missing: $StampPath"
    }
    try {
        $stamp = Get-Content -LiteralPath $StampPath -Raw | ConvertFrom-Json
    } catch {
        throw "Release binary provenance is malformed: $StampPath"
    }
    if ([int]$stamp.schema -ne 1 -or
        [string]$stamp.component -ne $Component -or
        [string]$stamp.releaseTag -ne $ReleaseTag) {
        throw "Release binary provenance identity mismatch for $Component"
    }
    $requiresQuic = $Component -eq 'emule' -and (Test-ReleaseRequiresQuic $ReleaseTag)
    if ($requiresQuic) {
        Assert-ReleaseQuicBinary -BinaryPath $BinaryPath -QuicManifestSha256 $QuicManifestSha256 -Architecture $Architecture
        if (($stamp.architecture -or $Architecture -eq 'Win32') -and $stamp.architecture -ne $Architecture) {
            throw 'emule.exe build stamp was recorded for another architecture'
        }
        if ($stamp.quicManifestSha256 -ne $QuicManifestSha256) {
            throw 'emule.exe build stamp was recorded for different QUIC dependencies'
        }
    }
    $head = (& git -C $RepoRoot rev-parse HEAD).Trim()
    if ([string]$stamp.commit -ne $head) {
        throw "Release binary was built from another commit: $Component"
    }
    $sourceFingerprint = Get-ReleaseSourceFingerprint `
        -RepoRoot $RepoRoot -Component $Component -IncludeQuic:$requiresQuic -Architecture $Architecture
    if ([string]$stamp.sourceFingerprint -ne $sourceFingerprint) {
        throw "Release binary is older than its source inputs: $Component"
    }
    $binary = Get-Item -LiteralPath $BinaryPath
    $binaryHash = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $BinaryPath
    ).Hash.ToUpperInvariant()
    if ([long]$stamp.binaryLength -ne [long]$binary.Length -or
        [string]$stamp.binarySha256 -ne $binaryHash) {
        throw "Release binary no longer matches its build provenance: $Component"
    }
}

function Get-ReleaseLanguageManifest {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeDir,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    $languageDir = Join-Path $RuntimeDir 'lang'
    if (-not (Test-Path -LiteralPath $languageDir -PathType Container)) {
        throw "Release language directory is missing: $languageDir"
    }
    $dlls = @(Get-ChildItem -LiteralPath $languageDir -Filter '*.dll' -File -Force |
        Sort-Object Name)
    if ($dlls.Count -eq 0) {
        throw "Release language directory has no DLLs: $languageDir"
    }
    $reparseDlls = @($dlls | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    })
    if ($reparseDlls.Count -gt 0) {
        throw "Release language manifest contains a reparse-point DLL: $($reparseDlls[0].FullName)"
    }
    return @($dlls | ForEach-Object {
        Assert-ReleasePEArchitecture -BinaryPath $_.FullName -Architecture $Architecture
        [pscustomobject][ordered]@{
            name = $_.Name
            sha256 = (
                Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
            ).Hash.ToUpperInvariant()
            length = [long]$_.Length
        }
    })
}

function Write-ReleaseLanguageStamp {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseTag,
        [Parameter(Mandatory = $true)][string]$RuntimeDir,
        [Parameter(Mandatory = $true)][string]$StampPath,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    $stampParent = Split-Path -Parent $StampPath
    New-Item -ItemType Directory -Path $stampParent -Force | Out-Null
    $stamp = [ordered]@{
        schema = 1
        component = 'languages'
        architecture = $Architecture
        releaseTag = $ReleaseTag
        commit = (& git -C $RepoRoot rev-parse HEAD).Trim()
        sourceFingerprint = Get-ReleaseSourceFingerprint `
            -RepoRoot $RepoRoot -Component emule
        languageDlls = @(Get-ReleaseLanguageManifest -RuntimeDir $RuntimeDir -Architecture $Architecture)
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    $stamp | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $StampPath -Encoding UTF8
}

function Assert-ReleaseLanguageStamp {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseTag,
        [Parameter(Mandatory = $true)][string]$RuntimeDir,
        [Parameter(Mandatory = $true)][string]$StampPath,
        [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64'
    )

    if (-not (Test-Path -LiteralPath $StampPath -PathType Leaf)) {
        throw "Release language provenance is missing: $StampPath"
    }
    try {
        $stamp = Get-Content -LiteralPath $StampPath -Raw | ConvertFrom-Json
    } catch {
        throw "Release language provenance is malformed: $StampPath"
    }
    if ([int]$stamp.schema -ne 1 -or
        [string]$stamp.component -ne 'languages' -or
        [string]$stamp.releaseTag -ne $ReleaseTag) {
        throw 'Release language provenance identity mismatch'
    }
    if (($stamp.architecture -or $Architecture -eq 'Win32') -and $stamp.architecture -ne $Architecture) {
        throw 'Release languages were built for another architecture'
    }
    $head = (& git -C $RepoRoot rev-parse HEAD).Trim()
    if ([string]$stamp.commit -ne $head) {
        throw 'Release languages were built from another commit'
    }
    $sourceFingerprint = Get-ReleaseSourceFingerprint `
        -RepoRoot $RepoRoot -Component emule
    if ([string]$stamp.sourceFingerprint -ne $sourceFingerprint) {
        throw 'Release languages are older than their source inputs'
    }

    $expected = @($stamp.languageDlls)
    $actual = @(Get-ReleaseLanguageManifest -RuntimeDir $RuntimeDir -Architecture $Architecture)
    if ($expected.Count -ne $actual.Count) {
        throw 'Release language DLL count no longer matches its build provenance'
    }
    for ($index = 0; $index -lt $actual.Count; $index++) {
        if ([string]$expected[$index].name -cne [string]$actual[$index].name -or
            [string]$expected[$index].sha256 -cne [string]$actual[$index].sha256 -or
            [long]$expected[$index].length -ne [long]$actual[$index].length) {
            throw (
                'Release language DLL no longer matches its build provenance: ' +
                [string]$actual[$index].name
            )
        }
    }
}
