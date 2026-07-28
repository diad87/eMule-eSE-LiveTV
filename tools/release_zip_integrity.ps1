function Get-ReleaseZipHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-ReleaseZipHashMap {
    param([Parameter(Mandatory = $true)][string]$Root)

    $resolvedRoot = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
    $map = @{}
    foreach ($file in Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Force |
        Sort-Object FullName) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Archive tree contains a reparse-point file: $($file.FullName)"
        }
        $relative = $file.FullName.Substring(
            $resolvedRoot.Length + 1
        ).Replace('\', '/')
        if ($map.ContainsKey($relative)) {
            throw "Archive tree contains a duplicate path: $relative"
        }
        $map[$relative] = Get-ReleaseZipHash -Path $file.FullName
    }
    return $map
}

function Assert-ReleaseZipNoReparseTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "ZIP verification root is not a plain directory: $($rootItem.FullName)"
    }
    foreach ($entry in Get-ChildItem -LiteralPath $rootItem.FullName -Recurse -Force) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "ZIP verification tree contains a reparse point: $($entry.FullName)"
        }
    }
}

function Test-ReleaseZipIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$VerificationRoot
    )

    $source = (Resolve-Path -LiteralPath $SourceDirectory).Path
    $archivePath = (Resolve-Path -LiteralPath $Archive).Path
    $root = (Resolve-Path -LiteralPath $VerificationRoot).Path.TrimEnd('\')
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "ZIP source is not a directory: $source"
    }
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw "ZIP archive is not a file: $archivePath"
    }
    Assert-ReleaseZipNoReparseTree -Root $source
    Assert-ReleaseZipNoReparseTree -Root $root

    $verifyRoot = Join-Path $root (
        '.zip-verify-' + [Guid]::NewGuid().ToString('N')
    )
    $resolvedRootPrefix = $root + '\'
    $resolvedVerify = [IO.Path]::GetFullPath($verifyRoot).TrimEnd('\')
    if (-not $resolvedVerify.StartsWith(
            $resolvedRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "ZIP verification path escaped its root: $resolvedVerify"
    }

    try {
        New-Item -ItemType Directory -Path $resolvedVerify | Out-Null
        Expand-Archive -LiteralPath $archivePath -DestinationPath $resolvedVerify
        Assert-ReleaseZipNoReparseTree -Root $resolvedVerify

        $expected = Get-ReleaseZipHashMap -Root $source
        $actual = Get-ReleaseZipHashMap -Root $resolvedVerify
        if ($expected.Count -ne $actual.Count) {
            throw (
                "ZIP file count mismatch: package=$($expected.Count), " +
                "archive=$($actual.Count)"
            )
        }
        foreach ($relative in $expected.Keys) {
            if (-not $actual.ContainsKey($relative)) {
                throw "ZIP is missing package file: $relative"
            }
            if ($actual[$relative] -ne $expected[$relative]) {
                throw "ZIP content differs from package file: $relative"
            }
        }

        $manifest = Join-Path $resolvedVerify 'SHA256SUMS.txt'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
            throw 'ZIP verification is missing SHA256SUMS.txt'
        }
        $manifestEntries = @{}
        foreach ($line in Get-Content -LiteralPath $manifest) {
            if ($line -notmatch '^([0-9A-Fa-f]{64})  ([^:]+)$') {
                throw "Malformed ZIP manifest entry: $line"
            }
            $relative = $Matches[2].Replace('\', '/')
            if ([IO.Path]::IsPathRooted($relative) -or
                $relative -match '(^|/)\.\.?(/|$)') {
                throw "Unsafe ZIP manifest path: $relative"
            }
            if ($manifestEntries.ContainsKey($relative)) {
                throw "Duplicate ZIP manifest path: $relative"
            }
            $manifestEntries[$relative] = $Matches[1].ToUpperInvariant()
        }
        $payloadKeys = @($actual.Keys | Where-Object {
                $_ -ne 'SHA256SUMS.txt'
            })
        if ($manifestEntries.Count -ne $payloadKeys.Count) {
            throw 'ZIP manifest does not cover the exact archive payload'
        }
        foreach ($relative in $payloadKeys) {
            if (-not $manifestEntries.ContainsKey($relative) -or
                $manifestEntries[$relative] -ne $actual[$relative]) {
                throw "ZIP manifest mismatch: $relative"
            }
        }
        return $true
    } finally {
        if (Test-Path -LiteralPath $resolvedVerify) {
            Assert-ReleaseZipNoReparseTree -Root $resolvedVerify
            Remove-Item -LiteralPath $resolvedVerify -Recurse -Force
        }
    }
}
