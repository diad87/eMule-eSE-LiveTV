# Read-only release check for eMule eSE LiveTV.
#
# Only -CheckOnly is supported. v9.1 packages never ship or invoke this script;
# installation is manual so users can verify the published SHA-256, preserve
# the previous directory and roll back without an in-place overwrite.

[CmdletBinding()]
param(
    [string]$RepoOwner = 'diad87',
    [string]$RepoName = 'eMule-eSE-LiveTV',
    [string]$ReleaseUrl = '',
    [string]$InstallDir = '',
    [switch]$CheckOnly,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

if (-not $CheckOnly) {
    [Console]::Error.WriteLine(
        'Automatic installation is disabled. Download the release manually, ' +
        'verify its published SHA-256 and extract it to a new directory.'
    )
    exit 2
}

function Convert-ReleaseTag([string]$Tag) {
    if ($Tag -notmatch (
        '^v0\.70b-eSE(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)' +
        '(?:-(?<channel>alpha|beta|rc)\.(?<sequence>\d+))?$'
    )) {
        return $null
    }
    $channelRank = switch ([string]$Matches.channel) {
        'alpha' { 0 }
        'beta' { 1 }
        'rc' { 2 }
        default { 3 }
    }
    return [pscustomobject]@{
        major = [int]$Matches.major
        minor = [int]$Matches.minor
        patch = [int]$Matches.patch
        channel_rank = $channelRank
        sequence = if ($Matches.sequence) {
            [int]$Matches.sequence
        } else { 0 }
    }
}

function Compare-ReleaseTag([string]$Left, [string]$Right) {
    $leftVersion = Convert-ReleaseTag -Tag $Left
    $rightVersion = Convert-ReleaseTag -Tag $Right
    if ($null -eq $leftVersion -or $null -eq $rightVersion) {
        return $null
    }
    foreach ($property in @(
        'major', 'minor', 'patch', 'channel_rank', 'sequence'
    )) {
        if ([int]$leftVersion.$property -lt [int]$rightVersion.$property) {
            return -1
        }
        if ([int]$leftVersion.$property -gt [int]$rightVersion.$property) {
            return 1
        }
    }
    return 0
}

if (-not $InstallDir) {
    $candidates = @(
        (Split-Path -Parent $PSCommandPath),
        (Split-Path -Parent (Split-Path -Parent $PSCommandPath)),
        "$env:USERPROFILE\Desktop\eSE-Package",
        "$env:USERPROFILE\Downloads\eSE-LiveTV-x64",
        "$env:LOCALAPPDATA\eSE"
    ) | Where-Object {
        Test-Path (Join-Path $_ 'emule.exe') -PathType Leaf
    } | Select-Object -First 1
    if ($candidates) {
        $InstallDir = [string]$candidates
    }
}

$currentTag = ''
$currentSha = ''
$currentDateUtc = ''
$buildInfoPath = if ($InstallDir) {
    Join-Path $InstallDir 'BUILD_INFO.txt'
} else { '' }
if ($buildInfoPath -and
    (Test-Path -LiteralPath $buildInfoPath -PathType Leaf)) {
    $buildInfo = Get-Content -LiteralPath $buildInfoPath -Raw
    if ($buildInfo -match '(?m)^release:\s*(\S+)\s*$') {
        $currentTag = $Matches[1]
    }
    if ($buildInfo -match '(?m)^commit:\s*([0-9a-fA-F]{40})\s*$') {
        $currentSha = $Matches[1]
    }
    if ($buildInfo -match '(?m)^built_utc:\s*([^\r\n]+)\s*$') {
        $currentDateUtc = $Matches[1].Trim()
    }
}

if (-not $ReleaseUrl) {
    $ReleaseUrl =
        "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
}
$releaseUri = $null
if (-not [Uri]::TryCreate(
        $ReleaseUrl, [UriKind]::Absolute, [ref]$releaseUri
    ) -or $releaseUri.Scheme -ne 'https') {
    [Console]::Error.WriteLine(
        'ReleaseUrl must be an absolute HTTPS URL'
    )
    exit 2
}

try {
    $headers = @{
        Accept = 'application/vnd.github+json'
        'User-Agent' = 'eMule-eSE-ReadOnly-Release-Check'
    }
    $release = Invoke-RestMethod -Uri $releaseUri -Headers $headers `
        -TimeoutSec 15
} catch {
    @{
        has_update = $false
        error = 'release_feed_unavailable'
    } | ConvertTo-Json -Compress
    exit 0
}

$latestTag = [string]$release.tag_name
$latestDate = [string]$release.published_at
$latestSha = [string]$release.target_commitish
$asset = @($release.assets | Where-Object {
        [string]$_.name -like 'eSE-LiveTV-*.zip'
    } | Select-Object -First 1)
$downloadUrl = if ($asset.Count -eq 1) {
    [string]$asset[0].browser_download_url
} else { '' }

$hasUpdate = $false
$comparisonError = ''
if ($currentTag -and $latestTag) {
    $comparison = Compare-ReleaseTag -Left $latestTag -Right $currentTag
    if ($null -eq $comparison) {
        $comparisonError = 'noncanonical_release_tag'
    } else {
        $hasUpdate = [int]$comparison -gt 0
    }
} else {
    $comparisonError = 'current_or_latest_tag_missing'
}

@{
    has_update = $hasUpdate
    current_tag = $currentTag
    current_sha = $currentSha
    current_built = $currentDateUtc
    latest_tag = $latestTag
    latest_sha = $latestSha
    latest_built = $latestDate
    download_url = $downloadUrl
    release_url = [string]$release.html_url
    error = if ($comparisonError) { $comparisonError } else { $null }
} | ConvertTo-Json -Compress
exit 0
