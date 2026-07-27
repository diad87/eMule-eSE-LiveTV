function Get-ReleaseSourceFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [ValidateSet('emule', 'ese')][string]$Component
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
        [Parameter(Mandatory = $true)][string]$StampPath
    )

    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        throw "Release binary is missing: $BinaryPath"
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
            -RepoRoot $RepoRoot -Component $Component
        binarySha256 = (
            Get-FileHash -Algorithm SHA256 -LiteralPath $BinaryPath
        ).Hash.ToUpperInvariant()
        binaryLength = [long]$binary.Length
        builtAtUtc = [DateTime]::UtcNow.ToString('o')
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
        [Parameter(Mandatory = $true)][string]$StampPath
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
    $head = (& git -C $RepoRoot rev-parse HEAD).Trim()
    if ([string]$stamp.commit -ne $head) {
        throw "Release binary was built from another commit: $Component"
    }
    $sourceFingerprint = Get-ReleaseSourceFingerprint `
        -RepoRoot $RepoRoot -Component $Component
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
        [Parameter(Mandatory = $true)][string]$RuntimeDir
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
        [Parameter(Mandatory = $true)][string]$StampPath
    )

    $stampParent = Split-Path -Parent $StampPath
    New-Item -ItemType Directory -Path $stampParent -Force | Out-Null
    $stamp = [ordered]@{
        schema = 1
        component = 'languages'
        releaseTag = $ReleaseTag
        commit = (& git -C $RepoRoot rev-parse HEAD).Trim()
        sourceFingerprint = Get-ReleaseSourceFingerprint `
            -RepoRoot $RepoRoot -Component emule
        languageDlls = @(Get-ReleaseLanguageManifest -RuntimeDir $RuntimeDir)
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
        [Parameter(Mandatory = $true)][string]$StampPath
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
    $actual = @(Get-ReleaseLanguageManifest -RuntimeDir $RuntimeDir)
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
