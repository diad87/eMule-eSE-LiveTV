[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseTag,
    [string]$RepoRoot = '',
    [switch]$AllowDirty
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = (Resolve-Path $RepoRoot).Path

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
Require-File 'srchybrid\config\nodes.dat.b64'
Require-File 'srchybrid\config\nodes.dat.sha256'
Require-File 'srchybrid\eMule.tmpl'
Require-File 'tools\release_inputs.json'
$releaseNotesPath = "docs\RELEASE_NOTES_v$tagVersion.md"
Require-File $releaseNotesPath

$versionHeader = Get-Content (Join-Path $RepoRoot 'srchybrid\Version.h') -Raw
if ($versionHeader -notmatch '#define\s+ESE_RELEASE_VERSION\s+_T\("(?<version>[^"]+)"\)') {
    Fail 'ESE_RELEASE_VERSION is missing from srchybrid/Version.h'
}
if ($Matches.version -ne $tagVersion) {
    Fail "Version.h says '$($Matches.version)' but tag says '$tagVersion'"
}
$packageVersion = (Get-Content (Join-Path $RepoRoot 'srchybrid\eSE\package.json') -Raw | ConvertFrom-Json).version
if ($packageVersion -ne $tagVersion) {
    Fail "package.json says '$packageVersion' but tag says '$tagVersion'"
}

$packageScript = Get-Content (Join-Path $RepoRoot 'build_package.ps1') -Raw
foreach ($requiredDefault in @(
    'EseV9Experimental=0',
    'EseKad3Rendezvous=0',
    'EseAutoKeepalive=0',
    'EseRelayAccept=0',
    'EseRelayEgress=0',
    'EseReachSelector=0',
    'EseHolePunchPortPredict=0',
    'EseEd2kPunch3=0',
    'Kad6PublicExitOptIn=0',
    'KrpRelayEnabled=0',
    'KrpRelayKillSwitch=0',
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

& git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'repository is not a Git worktree' }
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
