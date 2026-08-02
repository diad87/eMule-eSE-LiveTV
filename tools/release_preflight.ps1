[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseTag,
    [string]$RepoRoot = '',
    [switch]$AllowDirty,
    [switch]$RequireFreshBinaries
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = (Resolve-Path $RepoRoot).Path
. (Join-Path $RepoRoot 'tools\release_fingerprint.ps1')

function Fail([string]$Message) { throw "Release preflight: $Message" }
function Require-File([string]$RelativePath) {
    if (-not (Test-Path (Join-Path $RepoRoot $RelativePath) -PathType Leaf)) {
        Fail "required file is missing: $RelativePath"
    }
}

if ($ReleaseTag -notmatch '^v0\.70b-eSE(?<version>\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?)$') {
    Fail "invalid tag '$ReleaseTag' (expected v0.70b-eSEX.Y.Z[-alpha.N|-beta.N|-rc.N])"
}
$tagVersion = $Matches.version

Require-File 'srchybrid\Version.h'
Require-File 'srchybrid\eSE\package.json'
Require-File 'srchybrid\eSE\package-lock.json'
Require-File 'srchybrid\eSE\server.js'
Require-File 'srchybrid\eSE\tunnel.js'
Require-File 'srchybrid\eSE\live_player_server.js'
Require-File 'srchybrid\eSE\pages\misc_pages.js'
Require-File 'srchybrid\eSE\pages\connect_page.js'
Require-File 'srchybrid\eSE\pages\app_page.js'
Require-File 'srchybrid\eSE\pages\main_page.js'
Require-File 'srchybrid\eSE\routes\system_routes.js'
Require-File 'srchybrid\eSE\security.js'
Require-File 'srchybrid\eSE\shared\navbar.js'
Require-File 'srchybrid\eSE\_player_bundle.js'
Require-File 'srchybrid\eSE\eSE-live\channel_api.js'
Require-File 'srchybrid\eSE\eSE-live\live_tv_page.js'
Require-File 'srchybrid\eSE\eSE-live\update_notifier.js'
Require-File 'srchybrid\eSE\eSE-live\ws_tunnel.js'
Require-File 'srchybrid\config\nodes.dat.b64'
Require-File 'srchybrid\config\nodes.dat.sha256'
Require-File 'srchybrid\eMule.tmpl'
Require-File 'tools\release_inputs.json'
Require-File 'tools\build_all.ps1'
Require-File 'tools\release_fingerprint.ps1'
$releaseNotesPath = "docs\RELEASE_NOTES_v$tagVersion.md"
Require-File $releaseNotesPath
$releaseExecutionPath = ''
if ($tagVersion -match
    '^(?<major>\d+)\.(?<minor>\d+)\.\d+-rc\.(?<iteration>\d+)$') {
    $releaseExecutionPath = (
        'docs\V{0}{1}_RC{2}_EXECUTION.md' -f
        $Matches.major, $Matches.minor, $Matches.iteration
    )
    Require-File $releaseExecutionPath
}

$versionHeader = Get-Content (Join-Path $RepoRoot 'srchybrid\Version.h') -Raw
if ($versionHeader -notmatch '#define\s+ESE_RELEASE_VERSION\s+_T\("(?<version>[^"]+)"\)') {
    Fail 'ESE_RELEASE_VERSION is missing from srchybrid/Version.h'
}
if ($Matches.version -ne $tagVersion) {
    Fail "Version.h says '$($Matches.version)' but tag says '$tagVersion'"
}
$productVersionMatch = [regex]::Match(
    $versionHeader,
    '#define\s+SZ_ESE_PRODUCT_VERSION\s+SZ_VERSION_NAME\s+_T\(" - eSE (?<version>[^"]+)"\)'
)
if (-not $productVersionMatch.Success -or
    $productVersionMatch.Groups['version'].Value -ne $tagVersion) {
    Fail 'SZ_ESE_PRODUCT_VERSION does not match the release tag'
}
$prereleaseMatch = [regex]::Match(
    $versionHeader,
    '#define\s+ESE_PRERELEASE\s+(?<value>[01])'
)
$expectedPrerelease = if ($tagVersion -match '-(?:alpha|beta|rc)\.\d+$') {
    '1'
} else {
    '0'
}
if (-not $prereleaseMatch.Success -or
    $prereleaseMatch.Groups['value'].Value -ne $expectedPrerelease) {
    Fail "ESE_PRERELEASE must be $expectedPrerelease for '$tagVersion'"
}
$packageMetadata = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\package.json'
) -Raw | ConvertFrom-Json
if ([string]$packageMetadata.version -ne $tagVersion) {
    Fail (
        "package.json says '$($packageMetadata.version)' but tag says " +
        "'$tagVersion'"
    )
}
if ([string]$packageMetadata.license -ne 'GPL-2.0-only') {
    Fail "package.json must declare GPL-2.0-only"
}
if (@($packageMetadata.pkg.assets) -contains 'eSE_Remote.html') {
    Fail 'package.json still embeds the postponed remote launcher'
}
$lockPath = Join-Path $RepoRoot 'srchybrid\eSE\package-lock.json'
$lockSummaryJson = & node -e @'
const fs = require('fs');
const value = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const root = value.packages && value.packages[''];
if (!root) process.exit(3);
process.stdout.write(JSON.stringify({
  version: value.version,
  root_version: root.version,
  root_license: root.license
}));
'@ $lockPath
if ($LASTEXITCODE -ne 0 -or -not $lockSummaryJson) {
    Fail 'package-lock.json has no readable root package metadata'
}
$lockSummary = $lockSummaryJson | ConvertFrom-Json
if ([string]$lockSummary.version -ne $tagVersion -or
    [string]$lockSummary.root_version -ne $tagVersion) {
    Fail 'package-lock.json version does not match the release tag'
}
if ([string]$lockSummary.root_license -ne 'GPL-2.0-only') {
    Fail 'package-lock.json must declare GPL-2.0-only'
}

$serverSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\server.js'
) -Raw
$miscPagesSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\pages\misc_pages.js'
) -Raw
$tunnelSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\tunnel.js'
) -Raw
$connectPageSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\pages\connect_page.js'
) -Raw
$appPageSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\pages\app_page.js'
) -Raw
$mainPageSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\pages\main_page.js'
) -Raw
$systemRoutesSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\routes\system_routes.js'
) -Raw
$securitySource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\security.js'
) -Raw
$navbarSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\shared\navbar.js'
) -Raw
$playerBundleSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\_player_bundle.js'
) -Raw
$legacyPlayerSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\live_player_server.js'
) -Raw
$webSocketTunnelSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\eSE-live\ws_tunnel.js'
) -Raw
if ($serverSource -notmatch
    [regex]::Escape("require('./package.json').version") -or
    $miscPagesSource -notmatch
    [regex]::Escape("require('../package.json').version")) {
    Fail 'dashboard runtime version is not derived from package.json'
}
if ($serverSource -notmatch
    "server\.listen\(PORT,\s*'127\.0\.0\.1'") {
    Fail 'dashboard server must bind explicitly to 127.0.0.1'
}
if ($legacyPlayerSource -notmatch
        "server\.listen\(PORT,\s*'127\.0\.0\.1'" -or
    $webSocketTunnelSource -notmatch
        "tunnelServer\.listen\(port,\s*'127\.0\.0\.1'") {
    Fail 'packaged auxiliary HTTP/WebSocket listeners must be loopback-only'
}
if ($serverSource -match 'updateNotifier\.start\s*\(') {
    Fail 'dashboard must not start the legacy update notifier'
}
if ($tunnelSource -notmatch 'REMOTE_ACCESS_DISABLED\s*=\s*true' -or
    $tunnelSource -notmatch
        'function\s+publishUrl\(\)\s*\{\s*return\s+false' -or
    $tunnelSource -match
        "require\(['""]https['""]\)|setInterval\s*\(|ntfy\.sh|api\.telegram\.org") {
    Fail 'dashboard remote publisher is not inert'
}
foreach ($failClosedSource in @(
    $miscPagesSource, $connectPageSource, $appPageSource, $systemRoutesSource
)) {
    if ($failClosedSource -notmatch 'remote_access_postponed' -or
        $failClosedSource -notmatch '410') {
        Fail 'a postponed dashboard remote route does not fail closed'
    }
}
$packagedRemoteSurface = @(
    $tunnelSource,
    $miscPagesSource,
    $connectPageSource,
    $appPageSource,
    $systemRoutesSource,
    $navbarSource,
    $playerBundleSource
) -join "`n"
if ($packagedRemoteSurface -match
    'ntfy\.sh|api\.telegram\.org|api\.qrserver\.com|eSE_Remote\.html') {
    Fail 'packaged dashboard runtime still contains a remote lookup surface'
}
if ($mainPageSource -match 'href=["'']/connect' -or
    $navbarSource -match 'href=["'']/connect|ICONS\.connect|connect\s*:' -or
    $playerBundleSource -match
        'Acceso Remoto|fetch\s*\(\s*[''"]/(?:api/connect-seed|api/tunnel/status)') {
    Fail 'dashboard UI still exposes postponed remote access'
}
if ($miscPagesSource -match 'Access-Control-Allow-Origin' -or
    $miscPagesSource -match
        'CONFIG\.(?:accessToken|encKey)|networkInterfaces\s*\(') {
    Fail 'local diagnostics can still expose pairing state or wildcard CORS'
}
foreach ($protectedRemotePath in @(
    "pathname === '/app'",
    "pathname === '/connect'",
    "pathname.startsWith('/pair/')",
    "pathname === '/manifest.json'",
    "pathname === '/remote'",
    "pathname === '/qr'"
)) {
    if ($securitySource -notmatch [regex]::Escape($protectedRemotePath)) {
        Fail "security boundary is missing postponed route: $protectedRemotePath"
    }
}

$updateNotifierSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\eSE-live\update_notifier.js'
) -Raw
$channelApiSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\eSE-live\channel_api.js'
) -Raw
$livePageSource = Get-Content (
    Join-Path $RepoRoot 'srchybrid\eSE\eSE-live\live_tv_page.js'
) -Raw
if ($updateNotifierSource -notmatch 'UPDATES_DISABLED\s*=\s*true' -or
    $updateNotifierSource -match
        "child_process|powershell(?:\.exe)?|Invoke-WebRequest") {
    Fail 'legacy updater module is not fail-closed'
}
if ($channelApiSource -match 'api\.github\.com|https\.get\s*\(' -or
    $channelApiSource -notmatch 'manual_updates_only') {
    Fail 'dashboard update routes can still perform an automatic update check'
}
if ($livePageSource -match
    '/api/(?:eSE/update/check|live/update_(?:status|check|run))') {
    Fail 'LiveTV page still invokes a legacy updater route'
}

$packageScript = Get-Content (Join-Path $RepoRoot 'build_package.ps1') -Raw
$buildAllSource = Get-Content (
    Join-Path $RepoRoot 'tools\build_all.ps1'
) -Raw
if ($packageScript -notmatch [regex]::Escape('"Nick=$testerNick"') -or
    $packageScript -notmatch [regex]::Escape("'eSE-Beta-Tester'")) {
    Fail 'package tester nickname is not derived from the release channel'
}
foreach ($requiredDefault in @(
    'NetworkKademlia=1',
    'KadNetworkMask=3',
    'EseNetLabConsent=0',
    'EseNetLabAdvancedConsent=0',
    'EseNetLabContributionConsent=0',
    'EseNetLabEnabled=0',
    'EseV9Experimental=0',
    'EseKad3Rendezvous=0',
    'EseAutoKeepalive=0',
    'EseRelayAccept=0',
    'EseRelayEgress=0',
    'EseReachSelector=0',
    'EseHolePunchPortPredict=0',
    'EseEd2kPunch3=0',
    'Kad6PublicExitOptIn=0',
    'Kad6BetaExitOptIn=0',
    'KrpRelayEnabled=0',
    'KrpRelayKillSwitch=1',
    'ExperimentalTcpDataPlane=0',
    'WebUseUPnP=0'
)) {
    if ($packageScript -notmatch [regex]::Escape($requiredDefault)) {
        Fail "safe package default missing: $requiredDefault"
    }
}
if ($packageScript -match 'WebServerUseUPnP=1' -or $packageScript -match 'http://www\.gruk\.org') {
    Fail 'package script contains a legacy unsafe or mutable input'
}
if ($packageScript -match 'update_check\.ps1') {
    Fail 'legacy updater must not be included in the release package'
}
if ($packageScript -match "['""]eSE_Remote\.html['""]") {
    Fail 'postponed remote launcher must not be included in the release package'
}
if ($packageScript -match "['""]hero_ui\.js['""]") {
    Fail 'syntactically invalid legacy hero fragment must not be packaged'
}
if ($buildAllSource -notmatch
        '\$Skip\.Count\s+-gt\s+0\s+-and\s+-not\s+\$AllowDirty' -or
    $buildAllSource -notmatch
        '\$DryRun\s+-and\s+-not\s+\$AllowDirty' -or
    $buildAllSource -notmatch
        'Development pipeline complete \(NOT RELEASABLE\)' -or
    $buildAllSource -notmatch
        'Get-NetTCPConnection[\s\S]{0,900}127\.0\.0\.1') {
    Fail 'official pipeline can bypass or mislabel a required runtime gate'
}
foreach ($requiredPackagingGuard in @(
    'Copy-GitTrackedTopLevelFiles',
    'Copy-GitTrackedTree',
    'Assert-GitTrackedSource',
    'Assert-ZipMatchesPackage'
)) {
    if ($packageScript -notmatch [regex]::Escape($requiredPackagingGuard)) {
        Fail "package script is missing guard: $requiredPackagingGuard"
    }
}
if ($packageScript -match 'function\s+Copy-Tree' -or
    $packageScript -match
        'Get-ChildItem\s+\(Join-Path\s+\$eseSource\s+\$pattern') {
    Fail 'package script still copies untracked dashboard files'
}

& git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'repository is not a Git worktree' }
if ($RequireFreshBinaries) {
    $emuleBinary = Join-Path $RepoRoot 'srchybrid\x64\Release\emule.exe'
    $eseBinary = Join-Path $RepoRoot 'srchybrid\eSE\ese-server.exe'
    $stampRoot = Join-Path $RepoRoot 'tools\build_logs'
    try {
        Assert-ReleaseBinaryStamp -RepoRoot $RepoRoot `
            -ReleaseTag $ReleaseTag -Component emule `
            -BinaryPath $emuleBinary `
            -StampPath (Join-Path $stampRoot 'emule-release-build.json.log')
        Assert-ReleaseBinaryStamp -RepoRoot $RepoRoot `
            -ReleaseTag $ReleaseTag -Component ese `
            -BinaryPath $eseBinary `
            -StampPath (Join-Path $stampRoot 'ese-release-build.json.log')
        Assert-ReleaseLanguageStamp -RepoRoot $RepoRoot `
            -ReleaseTag $ReleaseTag `
            -RuntimeDir (Join-Path $RepoRoot 'srchybrid\x64\Release') `
            -StampPath (Join-Path $stampRoot 'languages-release-build.json.log')
    } catch {
        Fail $_.Exception.Message
    }
    $emuleVersionInfo = (Get-Item -LiteralPath $emuleBinary).VersionInfo
    $emuleFileVersion = $emuleVersionInfo.FileVersion
    if ([string]$emuleFileVersion -notlike "*eSE $tagVersion*") {
        Fail (
            "emule.exe FileVersion '$emuleFileVersion' does not identify " +
            "'$tagVersion'"
        )
    }
    $binaryShouldBePrerelease = $tagVersion -match
        '-(?:alpha|beta|rc)\.\d+$'
    if ([bool]$emuleVersionInfo.IsPreRelease -ne
        [bool]$binaryShouldBePrerelease) {
        Fail (
            "emule.exe prerelease flag '$($emuleVersionInfo.IsPreRelease)' " +
            "does not match '$tagVersion'"
        )
    }
    if (-not $binaryShouldBePrerelease -and
        [bool]$emuleVersionInfo.IsPrivateBuild) {
        Fail 'stable emule.exe is marked as a private build'
    }
}
if (-not $AllowDirty) {
    $dirty = @(& git -C $RepoRoot status --porcelain=v1 --untracked-files=all --ignore-submodules=none)
    if ($LASTEXITCODE -ne 0) { Fail 'git status failed' }
    if ($dirty.Count -gt 0) { Fail "worktree or submodule is dirty ($($dirty.Count) entries)" }
}

$existingTag = ((@(& git -C $RepoRoot tag --list $ReleaseTag)) -join '').Trim()
if ($existingTag) {
    $tagCommit = (& git -C $RepoRoot rev-list -n 1 $ReleaseTag).Trim()
    $headCommit = (& git -C $RepoRoot rev-parse HEAD).Trim()
    if ($tagCommit -ne $headCommit) { Fail "tag already exists on another commit ($tagCommit)" }
}

Write-Host "Release preflight PASS: $ReleaseTag" -ForegroundColor Green
