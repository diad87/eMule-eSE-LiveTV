# Deterministic-input portable package for eSE v9 prereleases.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseTag,
    [string]$RepoRoot = '',
    [string]$FfmpegPath = '',
    [switch]$AllowDirty
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }
$RepoRoot = (Resolve-Path $RepoRoot).Path

$preflightArgs = @{
    ReleaseTag = $ReleaseTag
    RepoRoot = $RepoRoot
    RequireFreshBinaries = $true
}
if ($AllowDirty) { $preflightArgs.AllowDirty = $true }
& (Join-Path $RepoRoot 'tools\release_preflight.ps1') @preflightArgs

# release_preflight has already validated this exact tag grammar. Derive the
# matching notes filename here so alpha, beta and RC packages cannot silently
# copy the notes from a different prerelease.
$ReleaseTag -match '^v0\.70b-eSE(?<version>.+)$' | Out-Null
$releaseVersion = $Matches.version
$releaseNotesRelativePath = "docs\RELEASE_NOTES_v$releaseVersion.md"
$releaseExecutionRelativePath = ''
if ($releaseVersion -match
    '^(?<major>\d+)\.(?<minor>\d+)\.\d+-rc\.(?<iteration>\d+)$') {
    $releaseExecutionRelativePath = (
        'docs\V{0}{1}_RC{2}_EXECUTION.md' -f
        $Matches.major, $Matches.minor, $Matches.iteration
    )
}
$testerNick = switch -Regex ($releaseVersion) {
    '-alpha\.' { 'eSE-Alpha-Tester'; break }
    '-beta\.'  { 'eSE-Beta-Tester'; break }
    '-rc\.'    { 'eSE-RC-Tester'; break }
    default    { 'eSE-Tester' }
}

$distRoot = Join-Path $RepoRoot 'dist'
$releaseRoot = Join-Path $distRoot $ReleaseTag
$packageDir = Join-Path $releaseRoot 'package'
$zipPath = Join-Path $releaseRoot "eSE-LiveTV-$ReleaseTag-x64.zip"
$resolvedDist = [IO.Path]::GetFullPath($distRoot).TrimEnd('\') + '\'
$resolvedRelease = [IO.Path]::GetFullPath($releaseRoot).TrimEnd('\') + '\'
if (-not $resolvedRelease.StartsWith($resolvedDist, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to prepare an output outside dist: $resolvedRelease"
}

function Assert-NoReparseAncestors([string]$Path, [string]$Anchor) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $anchorFull = [IO.Path]::GetFullPath($Anchor).TrimEnd('\')
    if ($full -ne $anchorFull -and -not $full.StartsWith(
            $anchorFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Output path escaped its trusted anchor: $full"
    }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Output path traverses a reparse point: $($item.FullName)"
            }
        }
        if ($cursor.Equals(
                $anchorFull, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) {
            throw "Output path has no trusted repository parent: $full"
        }
        $cursor = $parent.TrimEnd('\')
    }
}

function Assert-NoReparseTree([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (($rootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release output root is a reparse point: $($rootItem.FullName)"
    }
    if (-not $rootItem.PSIsContainer) {
        throw "Release output root is not a directory: $($rootItem.FullName)"
    }
    $pending = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
    $pending.Push([IO.DirectoryInfo]$rootItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            if (($entry.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Release output contains a reparse point: $($entry.FullName)"
            }
            if (($entry.Attributes -band
                    [IO.FileAttributes]::Directory) -ne 0) {
                $pending.Push([IO.DirectoryInfo]$entry)
            }
        }
    }
}

Assert-NoReparseAncestors -Path $releaseRoot -Anchor $RepoRoot
if (Test-Path -LiteralPath $releaseRoot) {
    Assert-NoReparseTree -Root $releaseRoot
    Remove-Item -LiteralPath $releaseRoot -Recurse -Force
}
New-Item -ItemType Directory $packageDir -Force | Out-Null

function Require-Copy([string]$Source, [string]$Destination) {
    if (-not (Test-Path $Source -PathType Leaf)) { throw "Required release input missing: $Source" }
    $parent = Split-Path -Parent $Destination
    if ($parent) { New-Item -ItemType Directory $parent -Force | Out-Null }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}
function Assert-GitTrackedSource([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\')
    if ($full -ne $root -and -not $full.StartsWith(
            $root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Tracked release input escaped the repository: $full"
    }
    $cursor = Get-Item -LiteralPath $full -Force
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Tracked release input traverses a reparse point: $full"
        }
        if ($cursor.FullName.Equals(
                $root, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $parent = Split-Path -Parent $cursor.FullName
        if (-not $parent) {
            throw "Tracked release input has no repository parent: $full"
        }
        $cursor = Get-Item -LiteralPath $parent -Force
    }
}
function Copy-GitTrackedTree([string]$RelativeSource, [string]$Destination) {
    $normalizedRoot = $RelativeSource.Trim([char[]]@('/', '\'))
    $prefix = $normalizedRoot.Replace('\', '/') + '/'
    $tracked = @(& git -C $RepoRoot ls-files -- "$prefix*")
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) {
        throw "No tracked release inputs found under: $RelativeSource"
    }
    foreach ($relative in $tracked) {
        $normalized = ([string]$relative).Replace('\', '/')
        if (-not $normalized.StartsWith(
                $prefix, [StringComparison]::Ordinal)) {
            throw "Tracked release input escaped its tree: $relative"
        }
        $childPosix = $normalized.Substring($prefix.Length)
        if ([IO.Path]::IsPathRooted($childPosix) -or
            $childPosix.Contains(':') -or
            $childPosix -match '(^|/)\.\.?(/|$)') {
            throw "Unsafe tracked release path: $relative"
        }
        $source = Join-Path $RepoRoot $normalized
        Assert-GitTrackedSource -Path $source
        $child = $childPosix.Replace('/', '\')
        Require-Copy $source `
            (Join-Path $Destination $child)
    }
}
function Copy-GitTrackedTopLevelFiles(
    [string]$RelativeSource,
    [string]$Destination,
    [string[]]$FileNames
) {
    $normalizedRoot = $RelativeSource.Trim([char[]]@('/', '\'))
    $prefix = $normalizedRoot.Replace('\', '/') + '/'
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($fileName in $FileNames) {
        if (-not $fileName -or $fileName.Contains('/') -or
            $fileName.Contains('\') -or $fileName.Contains(':') -or
            $fileName -in @('.', '..')) {
            throw "Unsafe top-level release input: $fileName"
        }
        if (-not $seen.Add($fileName)) {
            throw "Duplicate top-level release input: $fileName"
        }
        $relative = $prefix + $fileName
        $tracked = @(& git -C $RepoRoot ls-files --error-unmatch -- $relative)
        if ($LASTEXITCODE -ne 0 -or $tracked.Count -ne 1 -or
            [string]$tracked[0] -cne $relative) {
            throw "Top-level release input is not uniquely tracked: $relative"
        }
        $source = Join-Path $RepoRoot $relative
        Assert-GitTrackedSource -Path $source
        Require-Copy $source (Join-Path $Destination $fileName)
    }
}
function Hash([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant() }

function Get-FileHashMap([string]$Root) {
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $map = @{}
    foreach ($file in Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Force |
        Sort-Object FullName) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Archive input contains a reparse-point file: $($file.FullName)"
        }
        $relative = $file.FullName.Substring(
            $resolvedRoot.Length + 1
        ).Replace('\', '/')
        if ($map.ContainsKey($relative)) {
            throw "Archive input contains a duplicate path: $relative"
        }
        $map[$relative] = Hash $file.FullName
    }
    return $map
}

function Assert-NoHiddenOrSystemEntries([string]$Root) {
    foreach ($entry in Get-ChildItem -LiteralPath $Root -Recurse -Force) {
        if (($entry.Attributes -band [IO.FileAttributes]::Hidden) -ne 0 -or
            ($entry.Attributes -band [IO.FileAttributes]::System) -ne 0) {
            throw "Archive input contains a hidden/system entry: $($entry.FullName)"
        }
    }
}

function Assert-ZipMatchesPackage([string]$SourceDirectory, [string]$Archive) {
    $verifyRoot = Join-Path $releaseRoot (
        '.zip-verify-' + [Guid]::NewGuid().ToString('N')
    )
    $resolvedVerify = [IO.Path]::GetFullPath($verifyRoot).TrimEnd('\') + '\'
    if (-not $resolvedVerify.StartsWith(
            $resolvedRelease, [StringComparison]::OrdinalIgnoreCase)) {
        throw "ZIP verification path escaped release root: $resolvedVerify"
    }
    try {
        New-Item -ItemType Directory -Path $verifyRoot -Force | Out-Null
        Expand-Archive -LiteralPath $Archive -DestinationPath $verifyRoot
        $reparseDirectories = @(
            Get-ChildItem -LiteralPath $verifyRoot -Recurse -Directory -Force |
                Where-Object {
                    ($_.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0
                }
        )
        if ($reparseDirectories.Count -ne 0) {
            throw 'ZIP verification found a reparse-point directory'
        }

        $expected = Get-FileHashMap -Root $SourceDirectory
        $actual = Get-FileHashMap -Root $verifyRoot
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

        $manifest = Join-Path $verifyRoot 'SHA256SUMS.txt'
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
    } finally {
        if (Test-Path -LiteralPath $verifyRoot) {
            Assert-NoReparseTree -Root $verifyRoot
            $deleteTarget = [IO.Path]::GetFullPath(
                $verifyRoot
            ).TrimEnd('\') + '\'
            if (-not $deleteTarget.StartsWith(
                    $resolvedRelease,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to remove unsafe ZIP verification path"
            }
            Remove-Item -LiteralPath $verifyRoot -Recurse -Force
        }
    }
}

Write-Host '[1/7] Fresh binaries'
Require-Copy (Join-Path $RepoRoot 'srchybrid\x64\Release\emule.exe') (Join-Path $packageDir 'emule.exe')
Require-Copy (Join-Path $RepoRoot 'srchybrid\eSE\ese-server.exe') (Join-Path $packageDir 'ese-server.exe')

$langSource = Join-Path $RepoRoot 'srchybrid\x64\Release\lang'
Assert-NoReparseAncestors -Path $langSource -Anchor $RepoRoot
& (Join-Path $RepoRoot 'tools\check_languages.ps1') -RepoRoot $RepoRoot `
    -RuntimeDir (Join-Path $RepoRoot 'srchybrid\x64\Release')
$langDlls = @(Get-ChildItem -LiteralPath $langSource -Filter '*.dll' -File -Force `
    -ErrorAction SilentlyContinue | Sort-Object Name)
if ($langDlls.Count -eq 0) { throw 'No freshly built language DLLs found.' }
$langDir = Join-Path $packageDir 'lang'
New-Item -ItemType Directory $langDir -Force | Out-Null
foreach ($dll in $langDlls) { Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $langDir $dll.Name) -Force }
& (Join-Path $RepoRoot 'tools\check_languages.ps1') -RepoRoot $RepoRoot -RuntimeDir (Split-Path -Parent $langDir)

Write-Host '[2/7] Pinned media toolchain'
$inputs = Get-Content (Join-Path $RepoRoot 'tools\release_inputs.json') -Raw | ConvertFrom-Json
if (-not $FfmpegPath) {
    $ffmpegCommand = Get-Command ffmpeg.exe -ErrorAction SilentlyContinue
    if ($ffmpegCommand) { $FfmpegPath = $ffmpegCommand.Source }
}
if (-not $FfmpegPath -or -not (Test-Path $FfmpegPath -PathType Leaf)) {
    throw 'Pinned ffmpeg.exe not found. Pass -FfmpegPath explicitly.'
}
$FfmpegPath = (Resolve-Path $FfmpegPath).Path
$ffprobePath = Join-Path (Split-Path -Parent $FfmpegPath) 'ffprobe.exe'
if (-not (Test-Path $ffprobePath -PathType Leaf)) { throw "ffprobe.exe missing next to $FfmpegPath" }
if ((Hash $FfmpegPath) -ne $inputs.ffmpeg.sha256.ToUpperInvariant()) { throw 'ffmpeg.exe SHA-256 does not match tools/release_inputs.json' }
if ((Hash $ffprobePath) -ne $inputs.ffprobe.sha256.ToUpperInvariant()) { throw 'ffprobe.exe SHA-256 does not match tools/release_inputs.json' }
$ffmpegVersionLine = (& $FfmpegPath -version 2>&1 | Select-Object -First 1)
if ($ffmpegVersionLine -notmatch [regex]::Escape($inputs.ffmpeg.version)) { throw "Unexpected FFmpeg version: $ffmpegVersionLine" }
Require-Copy $FfmpegPath (Join-Path $packageDir 'ffmpeg.exe')
Require-Copy $ffprobePath (Join-Path $packageDir 'ffprobe.exe')

Write-Host '[3/7] Dashboard source assets'
$eseDest = Join-Path $packageDir 'eSE'
New-Item -ItemType Directory $eseDest -Force | Out-Null
Copy-GitTrackedTopLevelFiles -RelativeSource 'srchybrid\eSE' `
    -Destination $eseDest -FileNames @(
        '_player_bundle.js',
        'ai_assistant.js',
        'ai_oauth.js',
        'api_keys.js',
        'cinema_player.js',
        'clean_syntax.js',
        'cleanup.js',
        'debug_log.js',
        'debug_logo.js',
        'debug_search.js',
        'emule_api.js',
        'emule_mascot.svg',
        'favicon.ico',
        'hw_encoder.js',
        'init.js',
        'live_player_html.js',
        'live_player_server.js',
        'media_resolver.js',
        'mse_engine.js',
        'package-lock.json',
        'package.json',
        'player.js',
        'player_core.js',
        'poster_hero.js',
        'runtime_dir.js',
        'search_ui.js',
        'security.js',
        'server.js',
        'smart_play.js',
        'tmdb_api.js',
        'tunnel.js',
        'tunnel_settings.js',
        'utils.js'
    )
foreach ($directory in @('pages','routes','shared','eSE-live')) {
    Copy-GitTrackedTree "srchybrid\eSE\$directory" `
        (Join-Path $eseDest $directory)
}

Write-Host '[4/7] Canonical configuration'
$configDir = Join-Path $packageDir 'config'
New-Item -ItemType Directory $configDir -Force | Out-Null
Require-Copy (Join-Path $RepoRoot 'srchybrid\eMule.tmpl') (Join-Path $packageDir 'eMule.tmpl')
Require-Copy (Join-Path $RepoRoot 'srchybrid\eMule.tmpl') (Join-Path $configDir 'eMule.tmpl')

$nodesBytes = [Convert]::FromBase64String((Get-Content (Join-Path $RepoRoot 'srchybrid\config\nodes.dat.b64') -Raw).Trim())
$nodesExpected = (Get-Content (Join-Path $RepoRoot 'srchybrid\config\nodes.dat.sha256') -Raw).Trim().ToUpperInvariant()
$sha = [Security.Cryptography.SHA256]::Create()
try { $nodesActual = ([BitConverter]::ToString($sha.ComputeHash($nodesBytes))).Replace('-', '') }
finally { $sha.Dispose() }
if ($nodesExpected -notmatch '^[0-9A-F]{64}$' -or $nodesActual -ne $nodesExpected) { throw 'Pinned nodes.dat SHA-256 validation failed.' }
if ($nodesBytes.Length -lt 100 -or $nodesBytes.Length -gt 5MB) { throw 'Pinned nodes.dat has an invalid size.' }
[IO.File]::WriteAllBytes((Join-Path $configDir 'nodes.dat'), $nodesBytes)

@(
    '[eMule]',
    "Nick=$testerNick",
    'Port=4662',
    'UDPPort=4672',
    'MaxUpload=-1',
    'MaxDownload=-1',
    'Autoconnect=1',
    'AutoStart=1',
    'Networks=eD2K|Kad',
    'NetworkKademlia=1',
    '[Connection]',
    'KadNetworkMask=3',
    "[UPnP]",
    "EnableUPnP=1",
    "[WebServer]",
    'Enabled=1',
    'Port=4711',
    'Password=',
    "WebUseUPnP=0",
    "[eSE]",
    'EseNetLabConsent=0',
    'EseNetLabAdvancedConsent=0',
    'EseNetLabContributionConsent=0',
    'EseNetLabEnabled=0',
    "EseV9Experimental=0",
    'EseKad3Rendezvous=0',
    'EseAutoKeepalive=0',
    'EseRelayAccept=0',
    'EseRelayEgress=0',
    'EseReachSelector=0',
    'EseHolePunchPortPredict=0',
    'EseEd2kPunch3=0',
    'Kad6PublicExitOptIn=0',
    'Kad6BetaExitOptIn=0',
    '[KRPRelay]',
    'KrpRelayEnabled=0',
    'KrpRelayKillSwitch=1',
    'ExperimentalTcpDataPlane=0'
) | Out-File (Join-Path $configDir 'preferences.ini') -Encoding ASCII

Write-Host '[5/7] License, help and release notes'
foreach ($mapping in @(
    @('README.md','README.md'),
    @('GUIA-RAPIDA.md','GUIA-RAPIDA.md'),
    @('ARCHITECTURE.md','ARCHITECTURE.md'),
    @('CHANGES_FROM_EMULE_0.70b.md','CHANGES_FROM_EMULE_0.70b.md'),
    @('license.txt','license.txt'),
    @('THIRD_PARTY_LICENSES.md','THIRD_PARTY_LICENSES.md'),
    @($releaseNotesRelativePath,'RELEASE_NOTES.md')
)) {
    Require-Copy (Join-Path $RepoRoot $mapping[0]) (Join-Path $packageDir $mapping[1])
}
$packageDocs = Join-Path $packageDir 'docs'
Copy-GitTrackedTree 'docs' $packageDocs
# These two exact, version-bound files are required even for an explicitly
# dirty developer package; clean release builds already obtain them above from
# the tracked tree.
Require-Copy (Join-Path $RepoRoot 'docs\USER_GUIDE.md') `
    (Join-Path $packageDocs 'USER_GUIDE.md')
Require-Copy (Join-Path $RepoRoot $releaseNotesRelativePath) `
    (Join-Path $packageDocs (Split-Path -Leaf $releaseNotesRelativePath))
if ($releaseExecutionRelativePath) {
    Require-Copy (Join-Path $RepoRoot $releaseExecutionRelativePath) `
        (Join-Path $packageDocs (
                Split-Path -Leaf $releaseExecutionRelativePath
            ))
}

Write-Host '[6/7] Build provenance and file manifest'
$gitSha = (& git -C $RepoRoot rev-parse HEAD).Trim()
$dirty = @(& git -C $RepoRoot status --porcelain=v1 --untracked-files=all --ignore-submodules=none)
$dirtyText = if ($dirty.Count -eq 0) { 'false' } else { 'true (development override)' }
$nodeVersion = (& node --version 2>$null)
$npmVersion = (& npm.cmd --version 2>$null)
@(
    "release: $ReleaseTag",
    "commit: $gitSha",
    "dirty: $dirtyText",
    "built_utc: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
    "node: $nodeVersion",
    "npm: $npmVersion",
    "ffmpeg: $ffmpegVersionLine",
    "ffmpeg_sha256: $(Hash (Join-Path $packageDir 'ffmpeg.exe'))",
    "ffprobe_sha256: $(Hash (Join-Path $packageDir 'ffprobe.exe'))",
    "nodes_dat_sha256: $nodesActual"
) | Out-File (Join-Path $packageDir 'BUILD_INFO.txt') -Encoding ASCII

$manifestPath = Join-Path $packageDir 'SHA256SUMS.txt'
$manifestLines = @(Get-ChildItem -LiteralPath $packageDir -Recurse -File -Force | Where-Object { $_.FullName -ne $manifestPath } | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($packageDir.Length + 1).Replace('\','/')
    "$(Hash $_.FullName)  $relative"
})
$manifestLines | Out-File $manifestPath -Encoding ASCII

Write-Host '[7/7] ZIP and external checksum'
Assert-NoHiddenOrSystemEntries -Root $packageDir
Compress-Archive -Path (Join-Path $packageDir '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
Assert-ZipMatchesPackage -SourceDirectory $packageDir -Archive $zipPath
Write-Host 'ZIP content verification PASS'
$zipHash = Hash $zipPath
"$zipHash  $([IO.Path]::GetFileName($zipPath))" | Out-File "$zipPath.sha256" -Encoding ASCII
$forumDraftSource = Join-Path $RepoRoot "docs\FORUM_POST_v$releaseVersion.md"
if (Test-Path -LiteralPath $forumDraftSource -PathType Leaf) {
    $forumDraft = (Get-Content -LiteralPath $forumDraftSource -Raw).Replace('<ZIP_SHA256>', $zipHash)
    [IO.File]::WriteAllText(
        (Join-Path $releaseRoot 'FORUM_POST.md'),
        $forumDraft,
        (New-Object Text.UTF8Encoding($false)))
}
Write-Host "Package: $packageDir" -ForegroundColor Green
Write-Host "ZIP:     $zipPath" -ForegroundColor Green
Write-Host "SHA256:  $zipHash" -ForegroundColor Green
