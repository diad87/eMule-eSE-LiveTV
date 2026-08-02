[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'v91_i07_common.ps1')

function Test-I07ExpectedRejection {
    param([Parameter(Mandatory = $true)][scriptblock]$Operation)

    try {
        & $Operation
        return $false
    } catch { return $true }
}

function Add-I07ZipTextEntry {
    param(
        [Parameter(Mandatory = $true)]$Archive,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [AllowNull()]$ExternalAttributes = $null
    )

    $entry = $Archive.CreateEntry($Name)
    if ($null -ne $ExternalAttributes) {
        $entry.ExternalAttributes = [int]$ExternalAttributes
    }
    $stream = $entry.Open()
    $writer = [IO.StreamWriter]::new(
        $stream, [Text.UTF8Encoding]::new($false))
    try { $writer.Write($Text) }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
    return $entry
}

function Test-I07MutatedZipRejected {
    param(
        [Parameter(Mandatory = $true)][string]$SourceZip,
        [Parameter(Mandatory = $true)][string]$DestinationZip,
        [Parameter(Mandatory = $true)][object[]]$ExpectedFiles,
        [Parameter(Mandatory = $true)][scriptblock]$Mutator
    )

    Copy-Item -LiteralPath $SourceZip -Destination $DestinationZip -Force
    $stream = [IO.FileStream]::new(
        $DestinationZip, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $archive = [IO.Compression.ZipArchive]::new(
        $stream, [IO.Compression.ZipArchiveMode]::Update, $true)
    try { & $Mutator $archive }
    finally {
        $archive.Dispose()
        $stream.Dispose()
    }
    $sha256 = (Get-FileHash -LiteralPath $DestinationZip `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $bytes = [Int64](Get-Item -LiteralPath $DestinationZip).Length
    return Test-I07ExpectedRejection -Operation {
        $null = Get-I07CriticalZipEvidence -ZipPath $DestinationZip `
            -ExpectedFiles $ExpectedFiles -ExpectedZipSha256 $sha256 `
            -ExpectedZipBytes $bytes
    }
}

$toolFiles = @(
    'v91_i07_common.ps1',
    'inspect_v91_i07_baseline_remote.ps1',
    'inspect_v91_i07_remote.ps1',
    'run_v91_i07_node.ps1',
    'restore_v91_i07_wifi_watchdog.ps1',
    'set_v91_i07_wifi_profile.ps1',
    'invoke_v91_i07_campaign.ps1',
    'run_ese_lab_smallframe_agent.ps1',
    'control_ese_lab_smallframe_agent.ps1'
)
foreach ($leaf in $toolFiles) {
    $path = Join-Path $PSScriptRoot $leaf
    $errors = @()
    [Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$null, [ref]$errors) | Out-Null
    if ($errors.Count -ne 0) {
        throw "$leaf has $($errors.Count) PowerShell parser error(s)."
    }
}

$root = Join-Path $env:TEMP ("ese-v91-i07-offline-" +
    [Guid]::NewGuid().ToString('N'))
$hlsPath = ''
try {
    $null = Invoke-I07SelfTest
    $package = Join-Path $root 'package'
    $node = Join-Path $root 'node'
    New-Item -ItemType Directory -Path $package -Force | Out-Null
    $contents = [ordered]@{
        'BUILD_INFO.txt' = "release: v0.70b-eSE9.1.0-rc.2`ncommit: " +
            ('a' * 40) + "`ndirty: false`n" +
            "built_utc: 2026-07-31T10:00:00Z`n" +
            "node: v24.5.0`nnpm: 11.5.2`n" +
            "ffmpeg: ffmpeg version 8.1-full_build-www.gyan.dev " +
            "Copyright (c) 2000-2026 the FFmpeg developers`n" +
            "ffmpeg_sha256: " + ('b' * 64) + "`n" +
            "ffprobe_sha256: " + ('c' * 64) + "`n" +
            "nodes_dat_sha256: " + ('d' * 64) + "`n"
        'emule.exe' = 'offline-emule-fixture'
        'eMule.tmpl' = 'offline-template-fixture'
        'ese-server.exe' = 'offline-server-fixture'
        'ffmpeg.exe' = 'offline-ffmpeg-fixture'
        'ffprobe.exe' = 'offline-ffprobe-fixture'
        'SHA256SUMS.txt' = 'offline-sums-fixture'
    }
    foreach ($entry in $contents.GetEnumerator()) {
        [IO.File]::WriteAllText(
            (Join-Path $package $entry.Key), [string]$entry.Value,
            (New-Object Text.UTF8Encoding($false)))
    }
    $contractedEse = Join-Path $package 'eSE'
    New-Item -ItemType Directory -Path $contractedEse -Force |
        Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $contractedEse 'nested-runtime-fixture.txt'),
        'this nested package asset must be bound by I07',
        (New-Object Text.UTF8Encoding($false)))
    $packageIdentity = Get-I07PackageIdentity -PackagePath $package
    $contracts = @($packageIdentity.files)
    $exeContract = @($contracts | Where-Object path -ceq 'emule.exe')[0]
    $caseCollision = [pscustomobject][ordered]@{
        path = 'EMULE.EXE'
        bytes = [Int64]$exeContract.bytes
        sha256 = [string]$exeContract.sha256
    }
    if (-not (Test-I07ExpectedRejection -Operation {
                $null = Assert-I07CriticalPackageContract `
                    -Files @($contracts + $caseCollision)
            })) {
        throw 'Package contract accepted a case-folded path collision.'
    }
    $traversalContract = [pscustomobject][ordered]@{
        path = '../escape.bin'; bytes = 1L; sha256 = '1' * 64
    }
    if (-not (Test-I07ExpectedRejection -Operation {
                $null = Assert-I07CriticalPackageContract `
                    -Files @($contracts + $traversalContract)
            })) {
        throw 'Package contract accepted a traversal path.'
    }
    $unicodeContract = [pscustomobject][ordered]@{
        path = 'eSE/cafe' + [char]0x0301 + '.txt'
        bytes = 1L
        sha256 = '2' * 64
    }
    if (-not (Test-I07ExpectedRejection -Operation {
                $null = Assert-I07CriticalPackageContract `
                    -Files @($contracts + $unicodeContract)
            })) {
        throw 'Package contract accepted a non-NFC path.'
    }
    $mutablePreferencesContract = [pscustomobject][ordered]@{
        path = 'config/preferences.ini'; bytes = 1L; sha256 = '3' * 64
    }
    if (-not (Test-I07ExpectedRejection -Operation {
                $null = Assert-I07CriticalPackageContract `
                    -Files @($contracts + $mutablePreferencesContract)
            })) {
        throw 'Package contract accepted harness-owned mutable preferences.'
    }
    $prepared = New-I07CandidateNode -PackagePath $package `
        -ExpectedSha256 ([string]$exeContract.sha256) `
        -ExpectedPackageFiles $contracts -NodePath $node `
        -Role source `
        -BindIPv6 '2a02:26f7:abcd::10' -TcpPort 48067 `
        -UdpPort 48077 -WebPort 48117 -Password 'offline-password'
    if ([string]$prepared.sha256 -cne [string]$exeContract.sha256 -or
        @($prepared.package_files).Count -ne $contracts.Count) {
        throw 'Prepared-node identity did not preserve the package contract.'
    }
    foreach ($required in @('ffmpeg.exe', 'ffprobe.exe', 'eMule.tmpl')) {
        if (-not (Test-Path -LiteralPath (Join-Path $node $required) `
                -PathType Leaf)) {
            throw "Prepared node omitted $required."
        }
    }
    if (-not (Test-Path -LiteralPath (
                Join-Path $node 'eSE\nested-runtime-fixture.txt') `
            -PathType Leaf)) {
        throw 'Prepared node omitted a contracted nested package asset.'
    }
    $launchBinding = Get-I07PreparedNodeLaunchBinding `
        -CandidateNode $prepared -ExpectedPackageFiles $contracts
    if (-not [bool]$launchBinding.verified -or
        [int]$launchBinding.static_file_count -ne $contracts.Count -or
        [string]$launchBinding.candidate_sha256 -cne
            [string]$exeContract.sha256) {
        throw 'Prepared-node prelaunch binding lost the complete manifest.'
    }

    $lateExtra = Join-Path $package 'late-extra.bin'
    [IO.File]::WriteAllText($lateExtra, 'late package mutation',
        [Text.UTF8Encoding]::new($false))
    $lateExtraRejected = Test-I07ExpectedRejection -Operation {
        $null = New-I07CandidateNode -PackagePath $package `
            -ExpectedSha256 ([string]$exeContract.sha256) `
            -ExpectedPackageFiles $contracts `
            -NodePath (Join-Path $root 'late-extra-node') -Role source `
            -BindIPv6 '2a02:26f7:abcd::10' -TcpPort 48367 `
            -UdpPort 48377 -WebPort 48317 -Password 'offline-password'
    }
    Remove-Item -LiteralPath $lateExtra -Force
    if (-not $lateExtraRejected) {
        throw 'Prepared-node validation accepted a late package file.'
    }

    $lateEmptyDirectory = Join-Path $package 'late-empty-directory'
    New-Item -ItemType Directory -Path $lateEmptyDirectory | Out-Null
    $emptyDirectoryRejected = Test-I07ExpectedRejection -Operation {
        $null = Get-I07PackageIdentity -PackagePath $package
    }
    [IO.Directory]::Delete($lateEmptyDirectory)
    if (-not $emptyDirectoryRejected) {
        throw 'Package identity accepted an unbound empty directory.'
    }

    $nestedAsset = Join-Path $package 'eSE\nested-runtime-fixture.txt'
    $nestedOriginal = [IO.File]::ReadAllBytes($nestedAsset)
    [IO.File]::WriteAllText($nestedAsset, 'tampered nested asset',
        [Text.UTF8Encoding]::new($false))
    $packageTamperRejected = Test-I07ExpectedRejection -Operation {
        $null = New-I07CandidateNode -PackagePath $package `
            -ExpectedSha256 ([string]$exeContract.sha256) `
            -ExpectedPackageFiles $contracts `
            -NodePath (Join-Path $root 'tampered-package-node') `
            -Role source -BindIPv6 '2a02:26f7:abcd::10' `
            -TcpPort 48467 -UdpPort 48477 -WebPort 48417 `
            -Password 'offline-password'
    }
    [IO.File]::WriteAllBytes($nestedAsset, $nestedOriginal)
    if (-not $packageTamperRejected) {
        throw 'Prepared-node validation accepted a modified package file.'
    }

    $packageExternal = Join-Path $root 'package-external'
    New-Item -ItemType Directory -Path $packageExternal -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $packageExternal 'outside.txt'),
        'outside', [Text.UTF8Encoding]::new($false))
    $packageJunction = Join-Path $package 'linked-runtime'
    New-Item -ItemType Junction -Path $packageJunction `
        -Target $packageExternal -ErrorAction Stop | Out-Null
    $packageJunctionRejected = Test-I07ExpectedRejection -Operation {
        $null = Get-I07PackageIdentity -PackagePath $package
    }
    [IO.Directory]::Delete($packageJunction)
    if (-not $packageJunctionRejected) {
        throw 'Package identity followed a nested reparse point.'
    }
    $packageRootLink = Join-Path $root 'package-root-link'
    New-Item -ItemType Junction -Path $packageRootLink `
        -Target $package -ErrorAction Stop | Out-Null
    $packageRootLinkRejected = Test-I07ExpectedRejection -Operation {
        $null = Get-I07PackageIdentity -PackagePath $packageRootLink
    }
    [IO.Directory]::Delete($packageRootLink)
    if (-not $packageRootLinkRejected) {
        throw 'Package identity accepted a reparse-point root.'
    }

    $unexpectedNodeFile = Join-Path $node 'unexpected-runtime.bin'
    [IO.File]::WriteAllText($unexpectedNodeFile, 'unexpected',
        [Text.UTF8Encoding]::new($false))
    $prelaunchExtraRejected = Test-I07ExpectedRejection -Operation {
        $null = Get-I07PreparedNodeLaunchBinding `
            -CandidateNode $prepared -ExpectedPackageFiles $contracts
    }
    Remove-Item -LiteralPath $unexpectedNodeFile -Force
    if (-not $prelaunchExtraRejected) {
        throw 'Prelaunch binding accepted an unexpected node file.'
    }
    $nodeExe = Join-Path $node 'emule.exe'
    $nodeExeOriginal = [IO.File]::ReadAllBytes($nodeExe)
    [IO.File]::WriteAllText($nodeExe, 'tampered before launch',
        [Text.UTF8Encoding]::new($false))
    $prelaunchTamperRejected = Test-I07ExpectedRejection -Operation {
        $null = Get-I07PreparedNodeLaunchBinding `
            -CandidateNode $prepared -ExpectedPackageFiles $contracts
    }
    [IO.File]::WriteAllBytes($nodeExe, $nodeExeOriginal)
    if (-not $prelaunchTamperRejected) {
        throw 'Prelaunch binding accepted a modified candidate executable.'
    }
    $safeDeleteParent = Join-Path $root 'safe-delete-parent'
    $safeDeleteExternal = Join-Path $root 'safe-delete-external'
    New-Item -ItemType Directory -Path $safeDeleteParent -Force | Out-Null
    New-Item -ItemType Directory -Path $safeDeleteExternal -Force | Out-Null
    $externalSentinel = Join-Path $safeDeleteExternal 'must-survive.txt'
    [IO.File]::WriteAllText($externalSentinel, 'external-target',
        [Text.UTF8Encoding]::new($false))
    $ownedTree = Join-Path $safeDeleteParent 'owned-tree'
    New-Item -ItemType Directory -Path $ownedTree -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $ownedTree 'owned.txt'), 'owned',
        [Text.UTF8Encoding]::new($false))
    $nestedLink = Join-Path $ownedTree 'external-junction'
    New-Item -ItemType Junction -Path $nestedLink `
        -Target $safeDeleteExternal -ErrorAction Stop | Out-Null
    if (-not (Remove-I07TreeNoReparse -Path $ownedTree `
            -ExpectedParent $safeDeleteParent) -or
        -not (Test-Path -LiteralPath $externalSentinel -PathType Leaf)) {
        throw 'Safe cleanup followed a nested reparse point.'
    }
    $rootLink = Join-Path $safeDeleteParent 'owned-root-link'
    New-Item -ItemType Junction -Path $rootLink `
        -Target $safeDeleteExternal -ErrorAction Stop | Out-Null
    if (-not (Remove-I07TreeNoReparse -Path $rootLink `
            -ExpectedParent $safeDeleteParent) -or
        -not (Test-Path -LiteralPath $externalSentinel -PathType Leaf)) {
        throw 'Safe cleanup followed a root reparse point.'
    }
    $ini = Get-Content -LiteralPath $prepared.preferences_path -Raw
    foreach ($line in @(
        'AllowedIPs=127.0.0.1', 'ProxyEnableProxy=0',
        'ProxyEnablePassword=0', 'IPv6Mode=2',
        'EseNetLabEnabled=0', 'OpenPortsOnStartUp=0', 'AutoStart=0',
        'AutoTakeED2KLinks=0', 'WatchClipboard4ED2kFilelinks=0')) {
        if ($ini -cnotmatch ('(?m)^' + [regex]::Escape($line) + '\r?$')) {
            throw "Prepared preferences omitted '$line'."
        }
    }
    if ($ini -cmatch '(?m)^ProxyEnable=') {
        throw 'Prepared preferences used the obsolete ProxyEnable key.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipPath = Join-Path $root 'candidate.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($package, $zipPath)
    $zipSha = (Get-FileHash -LiteralPath $zipPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $zipBytes = [Int64](Get-Item -LiteralPath $zipPath).Length
    $zipEvidence = Get-I07CriticalZipEvidence -ZipPath $zipPath `
        -ExpectedFiles $contracts -ExpectedZipSha256 $zipSha `
        -ExpectedZipBytes $zipBytes
    if (-not [bool]$zipEvidence.verified -or
        [int]$zipEvidence.critical_file_count -ne $contracts.Count -or
        [string]$zipEvidence.schema -cne
            'ese.v91.i07-node-zip-binding/v2') {
        throw 'Node ZIP binding did not verify the complete file set.'
    }
    $zipNegative = $false
    try {
        $null = Get-I07CriticalZipEvidence -ZipPath $zipPath `
            -ExpectedFiles $contracts -ExpectedZipSha256 ('0' * 64) `
            -ExpectedZipBytes $zipBytes
    } catch { $zipNegative = $true }
    if (-not $zipNegative) {
        throw 'Node ZIP binding accepted a stale ZIP hash.'
    }

    $wrappedZipPath = Join-Path $root 'candidate-wrapped.zip'
    $wrappedStream = [IO.FileStream]::new(
        $wrappedZipPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $wrappedArchive = [IO.Compression.ZipArchive]::new(
        $wrappedStream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($contract in $contracts) {
            $entry = $wrappedArchive.CreateEntry(
                'candidate/' + [string]$contract.path)
            $input = [IO.File]::OpenRead((Join-Path $package (
                        ([string]$contract.path).Replace('/', '\'))))
            $output = $entry.Open()
            try { $input.CopyTo($output) }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    } finally {
        $wrappedArchive.Dispose()
        $wrappedStream.Dispose()
    }
    $wrappedSha = (Get-FileHash -LiteralPath $wrappedZipPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $wrappedBytes = [Int64](Get-Item -LiteralPath $wrappedZipPath).Length
    $wrappedEvidence = Get-I07CriticalZipEvidence `
        -ZipPath $wrappedZipPath -ExpectedFiles $contracts `
        -ExpectedZipSha256 $wrappedSha -ExpectedZipBytes $wrappedBytes
    if (-not [bool]$wrappedEvidence.verified -or
        [int]$wrappedEvidence.critical_file_count -ne $contracts.Count) {
        throw 'Node ZIP binding rejected one safe wrapper root.'
    }

    $zipMutationCases = [ordered]@{
        extra_entry = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'extra.bin' -Text 'unexpected'
        }
        missing_entry = {
            param($archive)
            $entry = @($archive.Entries | Where-Object {
                    ([string]$_.FullName).Replace('\', '/') -ceq
                        'ffprobe.exe'
                })[0]
            $entry.Delete()
        }
        tampered_executable = {
            param($archive)
            $entry = @($archive.Entries | Where-Object {
                    ([string]$_.FullName).Replace('\', '/') -ceq 'emule.exe'
                })[0]
            $entry.Delete()
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'emule.exe' -Text 'tampered executable'
        }
        traversal_entry = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name '../escape.txt' -Text 'escape'
        }
        traversal_directory = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name '../escape-dir/' -Text ''
        }
        unbound_empty_directory = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'empty-dir/' -Text ''
        }
        directory_case_collision = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'ESE/' -Text ''
        }
        case_collision = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'EMULE.EXE' -Text 'case collision'
        }
        noncanonical_unicode = {
            param($archive)
            $name = 'eSE/cafe' + [char]0x0301 + '.txt'
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name $name -Text 'non-nfc'
        }
        second_root = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'other-root/outside.bin' -Text 'second root'
        }
        unix_symlink = {
            param($archive)
            $attributes = [BitConverter]::ToInt32(
                [byte[]](0, 0, 0, 160), 0)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'unix-link' -Text 'target' `
                -ExternalAttributes $attributes
        }
        dos_reparse = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'dos-reparse' -Text 'target' -ExternalAttributes 1024
        }
        mixed_separators = {
            param($archive)
            $null = Add-I07ZipTextEntry -Archive $archive `
                -Name 'eSE/mixed\entry.bin' -Text 'mixed separators'
        }
    }
    $zipMutationRejectCount = 0
    foreach ($case in $zipMutationCases.GetEnumerator()) {
        $negativePath = Join-Path $root (
            'negative-' + [string]$case.Key + '.zip')
        if (-not (Test-I07MutatedZipRejected -SourceZip $zipPath `
                -DestinationZip $negativePath -ExpectedFiles $contracts `
                -Mutator $case.Value)) {
            throw "Node ZIP binding accepted '$($case.Key)'."
        }
        $zipMutationRejectCount++
    }

    $logDirectory = Join-Path $node 'logs'
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    $fixtureNonce = '0123456789abcdef0123456789abcdef'
    $fixtureSecret = 'token=super-secret-value'
    [IO.File]::WriteAllText((Join-Path $logDirectory 'emule.log'),
        "2026-07-31 12:34:56 peer 192.0.2.4 2a02:26f7:abcd::10 " +
        "$fixtureNonce $fixtureSecret`r`n",
        [Text.UTF8Encoding]::new($false))
    $buildContract = @($contracts | Where-Object {
            [string]$_.path -ceq 'BUILD_INFO.txt'
        })[0]
    $evidenceRoot = Join-Path $root 'retained-evidence'
    $apiIdentitySecret = 'persistent-user-hash-fixture'
    $apiTokenSecret = 'api-token-fixture-secret'
    $apiAddressSecret = '2001:db8:feed::1234'
    $controlledPeerAddress = '2a02:26f7:abcd::20'
    $decoyPeerAddress = '2a02:26f7:abcd::99'
    $peerResponse = [pscustomobject]@{
        peers = @(
            [pscustomobject]@{
                address = $controlledPeerAddress; port = 48267
                isFork = $true; dataplaneCap = $true
                user_hash = 'controlled-peer-private-fixture'
            },
            [pscustomobject]@{
                address = $decoyPeerAddress; port = 49999
                isFork = $true; dataplaneCap = $true
                token = 'decoy-peer-private-fixture'
            }
        )
    }
    $controlledPeerEvidence = Get-I07ControlledApiPeerEvidence `
        -PeersResponse $peerResponse -PeerIPv6 $controlledPeerAddress `
        -PeerTcpPort 48267
    $controlledPeerJson = $controlledPeerEvidence |
        ConvertTo-Json -Depth 8 -Compress
    if (-not [bool]$controlledPeerEvidence.matched -or
        $controlledPeerJson -notmatch [regex]::Escape($controlledPeerAddress) -or
        $controlledPeerJson -match [regex]::Escape($decoyPeerAddress) -or
        $controlledPeerJson -match 'private-fixture') {
        throw 'Controlled API-peer evidence retained raw or decoy peer data.'
    }
    $apiPre = [pscustomobject]@{
        ed2k_connected = $false; kad_connected = $false
        kad_configured_mask = 0; kad_running_mask = 0
        kad2_running = $false; kad2_connected = $false
        kad6_running = $false; kad6_connected = $false
        netlab_enabled = $false
        user_hash = $apiIdentitySecret; token = $apiTokenSecret
        public_ip = $apiAddressSecret
    }
    $apiPost = [pscustomobject]@{
        ed2k_connected = $false; kad_connected = $false
        kad_configured_mask = 0; kad_running_mask = 0
        kad2_running = $false; kad2_connected = $false
        kad6_running = $false; kad6_connected = $false
        netlab_enabled = $false
    }
    $captured = [DateTimeOffset]::UtcNow
    $apiSummary = Get-I07ApiEvidenceSummary -Value $apiPre `
        -CapturedAt $captured
    $apiSummaryJson = $apiSummary | ConvertTo-Json -Depth 8 -Compress
    foreach ($secret in @(
        $apiIdentitySecret, $apiTokenSecret, $apiAddressSecret)) {
        if ($apiSummaryJson.Contains($secret)) {
        throw 'Sanitized API status evidence retained a private value.'
        }
    }
    $apiPrivateVariant = [pscustomobject]@{
        ed2k_connected = $false; kad_connected = $false
        kad_configured_mask = 0; kad_running_mask = 0
        kad2_running = $false; kad2_connected = $false
        kad6_running = $false; kad6_connected = $false
        netlab_enabled = $false
        user_hash = 'different-persistent-user-hash'
        token = 'different-api-token'; public_ip = '2001:db8:cafe::5678'
    }
    $apiVariantSummary = Get-I07ApiEvidenceSummary `
        -Value $apiPrivateVariant -CapturedAt $captured
    $apiVariantJson = $apiVariantSummary | ConvertTo-Json -Depth 8 -Compress
    if ($apiVariantJson -cne $apiSummaryJson) {
        throw 'Private API fields changed the allowlisted status summary/hash.'
    }
    if ([string]$apiSummary.schema -cne
            'ese.v91.i07-api-status-evidence/v2' -or
        -not [bool]$apiSummary.available -or
        -not [bool]$apiSummary.contract_valid -or
        -not [bool]$apiSummary.isolation_invariant_satisfied -or
        [bool]$apiSummary.safe_scalars.ed2k_connected -or
        [string]$apiSummary.safe_response_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Sanitized API status evidence lost its safe contract.'
    }
    $malformedApi = [pscustomobject]@{
        ed2k_connected = 'false'; token = 'malformed-api-secret'
    }
    $malformedSummary = Get-I07ApiEvidenceSummary -Value $malformedApi `
        -CapturedAt $captured
    if ([bool]$malformedSummary.available -or
        @($malformedSummary.safe_scalars.Keys).Count -ne 0 -or
        ($malformedSummary | ConvertTo-Json -Compress) -match
            'malformed-api-secret') {
        throw 'Malformed API status was persisted or accepted.'
    }
    $contradictoryApi = $apiPre.PSObject.Copy()
    $contradictoryApi.ed2k_connected = $true
    $contradictorySummary = Get-I07ApiEvidenceSummary `
        -Value $contradictoryApi -CapturedAt $captured
    if (-not [bool]$contradictorySummary.available -or
        -not [bool]$contradictorySummary.contract_valid -or
        [bool]$contradictorySummary.isolation_invariant_satisfied) {
        throw 'Contradictory API isolation state was accepted.'
    }
    $topologyFixture = [pscustomobject]@{
        local_ipv6 = '2a02:26f7:abcd::10'
        peer_ipv6 = '2a02:26f7:abcd::20'
        interface_index = 7
        interface_guid = '11111111-1111-1111-1111-111111111111'
        ports = [pscustomobject]@{
            tcp = 48067; udp = 48077; web = 48117
            peer_tcp = 48267; control = 48907
        }
    }
    $retained = Write-I07RetainedNodeEvidence `
        -EvidencePath $evidenceRoot -NodePath $node `
        -ExpectedBuildInfoSha256 ([string]$buildContract.sha256) `
        -ApiStatusInitial $apiPre -ApiStatusFinal $apiPost `
        -ApiInitialAtUtc $captured.AddSeconds(-1) `
        -ApiFinalAtUtc $captured -Role source -CandidatePid 1234 `
        -TopologyPorts $topologyFixture `
        -Secrets @($fixtureNonce, 'super-secret-value')
    if (-not [bool]$retained.complete -or
        @($retained.files).Count -ne 7 -or
        [int]$retained.requirements.timestamped_log_line_count -lt 1) {
        throw 'Retained evidence self-test did not close its complete gate.'
    }
    $effectiveConfig = Get-Content -LiteralPath (
        Join-Path $evidenceRoot 'effective-config.json') -Raw
    $structuredLog = Get-Content -LiteralPath (
        Join-Path $evidenceRoot 'log-evidence.json') -Raw
    $buildEvidence = Get-Content -LiteralPath (
        Join-Path $evidenceRoot 'build-info-evidence.json') -Raw |
            ConvertFrom-Json
    $configSecretLeak = $effectiveConfig -match
        '(?i)"key"\s*:\s*"(?:Password|IPv6BindAddr)"'
    if ($configSecretLeak -or
        $effectiveConfig -notmatch '"value"\s*:\s*"eSE-A"' -or
        $structuredLog -match [regex]::Escape($fixtureNonce) -or
        $structuredLog -match '192\.0\.2\.4' -or
        $structuredLog -match '2a02:26f7:abcd::10' -or
        $structuredLog -match 'super-secret-value' -or
        $structuredLog -notmatch '2026-07-31 12:34:56' -or
        -not [bool]$buildEvidence.exact -or
        -not [bool]$buildEvidence.fields_valid) {
        throw 'Structured retained evidence leaked data or lost its contract.'
    }
    [IO.File]::WriteAllText((Join-Path $logDirectory 'emule.log'),
        'real line without a timestamp', [Text.UTF8Encoding]::new($false))
    $negativeEvidence = Write-I07RetainedNodeEvidence `
        -EvidencePath (Join-Path $root 'retained-negative') `
        -NodePath $node `
        -ExpectedBuildInfoSha256 ([string]$buildContract.sha256) `
        -ApiStatusInitial $apiPre -ApiStatusFinal $null `
        -ApiInitialAtUtc $captured -ApiFinalAtUtc $null `
        -Role source -CandidatePid 1234 -TopologyPorts $topologyFixture
    if ([bool]$negativeEvidence.complete -or
        [bool]$negativeEvidence.requirements.api_post_retained -or
        [int]$negativeEvidence.requirements.timestamped_log_line_count -ne 0) {
        throw 'Retained evidence accepted missing API/timestamp proof.'
    }
    Set-I07IniValue -Path $prepared.preferences_path -Section WebServer `
        -Key AllowedIPs -Value 'private-config-secret'
    $configNegative = Write-I07RetainedNodeEvidence `
        -EvidencePath (Join-Path $root 'retained-config-negative') `
        -NodePath $node `
        -ExpectedBuildInfoSha256 ([string]$buildContract.sha256) `
        -ApiStatusInitial $apiPre -ApiStatusFinal $apiPost `
        -ApiInitialAtUtc $captured.AddSeconds(-1) `
        -ApiFinalAtUtc $captured -Role source -CandidatePid 1234 `
        -TopologyPorts $topologyFixture
    $configNegativeJson = Get-Content -LiteralPath (
        Join-Path $root 'retained-config-negative\effective-config.json') -Raw
    if ([bool]$configNegative.complete -or
        $configNegativeJson -match 'private-config-secret') {
        throw 'Invalid allowlisted config content was persisted or accepted.'
    }
    Set-I07IniValue -Path $prepared.preferences_path -Section WebServer `
        -Key AllowedIPs -Value '127.0.0.1'
    $roleNegative = Write-I07RetainedNodeEvidence `
        -EvidencePath (Join-Path $root 'retained-role-negative') `
        -NodePath $node `
        -ExpectedBuildInfoSha256 ([string]$buildContract.sha256) `
        -ApiStatusInitial $apiPre -ApiStatusFinal $apiPost `
        -ApiInitialAtUtc $captured.AddSeconds(-1) `
        -ApiFinalAtUtc $captured -Role viewer -CandidatePid 1234 `
        -TopologyPorts $topologyFixture
    if ([bool]$roleNegative.complete) {
        throw 'Source alias evidence was accepted for the Viewer role.'
    }
    Add-Content -LiteralPath (Join-Path $node 'BUILD_INFO.txt') `
        -Value 'builder: private-build-secret'
    $buildNegativeRejected = $false
    $buildNegativeRoot = Join-Path $root 'retained-build-negative'
    try {
        $null = Write-I07RetainedNodeEvidence `
            -EvidencePath $buildNegativeRoot -NodePath $node `
            -ExpectedBuildInfoSha256 ([string]$buildContract.sha256) `
            -ApiStatusInitial $apiPre -ApiStatusFinal $apiPost `
            -ApiInitialAtUtc $captured.AddSeconds(-1) `
            -ApiFinalAtUtc $captured -Role source -CandidatePid 1234 `
            -TopologyPorts $topologyFixture
    } catch { $buildNegativeRejected = $true }
    $buildNegativeJson = Get-Content -LiteralPath (
        Join-Path $buildNegativeRoot 'build-info-evidence.json') -Raw
    if (-not $buildNegativeRejected -or
        (Test-Path -LiteralPath (Join-Path $buildNegativeRoot 'BUILD_INFO.txt')) -or
        $buildNegativeJson -match 'private-build-secret') {
        throw 'Non-schema BUILD_INFO content was copied or accepted.'
    }

    $key = [Guid]::NewGuid().ToString('N')
    $hlsPath = Join-Path $env:TEMP "eMule_RTMP\$key"
    New-Item -ItemType Directory -Path $hlsPath -Force | Out-Null
    $segmentPath = Join-Path $hlsPath 'seg-1.ts'
    [IO.File]::WriteAllBytes($segmentPath, [byte[]](1, 2, 3, 4))
    [IO.File]::WriteAllText((Join-Path $hlsPath 'stream.m3u8'),
        "#EXTM3U`nseg-1.ts`n", (New-Object Text.UTF8Encoding($false)))
    $now = [DateTimeOffset]::UtcNow
    $fresh = Get-I07HlsEvidence -StreamKey $key `
        -MinimumWriteTimeUtc $now.AddSeconds(-2)
    $stale = Get-I07HlsEvidence -StreamKey $key `
        -MinimumWriteTimeUtc $now.AddSeconds(2)
    if (-not [bool]$fresh.playlist_seen -or
        -not [bool]$fresh.segment_seen -or
        -not [bool]$fresh.segment_path_contained -or
        [bool]$stale.playlist_seen -or [bool]$stale.segment_seen) {
        throw 'HLS freshness adjudication self-test failed.'
    }
    $hlsJson = $fresh | ConvertTo-Json -Depth 8 -Compress
    if ($null -ne $fresh.PSObject.Properties['playlist_path']) {
        throw 'HLS evidence still publishes an absolute playlist path.'
    }
    foreach ($privateText in @(
        $key, [string]$env:TEMP, [string]$env:USERPROFILE,
        [string]$env:USERNAME) | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and $_.Length -ge 3
        }) {
        if ($hlsJson.IndexOf(
                $privateText, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'HLS evidence retained a stream key or user-specific path.'
        }
    }
    $outsideSegment = Join-Path (Split-Path -Parent $hlsPath) `
        "outside-$key.ts"
    try {
        [IO.File]::WriteAllBytes($outsideSegment, [byte[]](9, 8, 7, 6))
        [IO.File]::WriteAllText((Join-Path $hlsPath 'stream.m3u8'),
            "#EXTM3U`n..\outside-$key.ts`n",
            (New-Object Text.UTF8Encoding($false)))
        $hlsTraversalRejected = $false
        try {
            $null = Get-I07HlsEvidence -StreamKey $key `
                -MinimumWriteTimeUtc $now.AddSeconds(-2)
        } catch { $hlsTraversalRejected = $true }
        if (-not $hlsTraversalRejected) {
            throw 'HLS evidence accepted a traversal segment outside its stream root.'
        }
    } finally {
        Remove-Item -LiteralPath $outsideSegment -Force `
            -ErrorAction SilentlyContinue
    }
    $invalidKeyRejected = $false
    try {
        $null = Get-I07HlsEvidence -StreamKey '..\escape'
    } catch { $invalidKeyRejected = $true }
    if (-not $invalidKeyRejected) {
        throw 'HLS evidence accepted a non-nonce stream key.'
    }

    $wifiText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'set_v91_i07_wifi_profile.ps1') -Raw
    $watchdogText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'restore_v91_i07_wifi_watchdog.ps1') -Raw
    $controllerText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'invoke_v91_i07_campaign.ps1') -Raw
    $agentText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'run_ese_lab_smallframe_agent.ps1') -Raw
    $nodeText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'run_v91_i07_node.ps1') -Raw
    $commonText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'v91_i07_common.ps1') -Raw
    $baselineText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'inspect_v91_i07_baseline_remote.ps1') -Raw
    $preflightText = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'inspect_v91_i07_remote.ps1') -Raw

    $receiveStart = $controllerText.IndexOf(
        'function Receive-I07StagedJson')
    $receiveEnd = $controllerText.IndexOf(
        'function Get-I07AgentReadiness', $receiveStart)
    $trapStart = $controllerText.IndexOf("trap {")
    $trapEnd = $controllerText.IndexOf(
        '$requiredArguments = [ordered]@{', $trapStart)
    if ($receiveStart -lt 0 -or $receiveEnd -le $receiveStart -or
        $trapStart -lt 0 -or $trapEnd -le $trapStart) {
        throw 'Controller retention boundaries could not be isolated.'
    }
    $receiveText = $controllerText.Substring(
        $receiveStart, $receiveEnd - $receiveStart)
    $trapText = $controllerText.Substring($trapStart, $trapEnd - $trapStart)
    $homeRestoreIndex = $controllerText.LastIndexOf(
        '$homeRestore = Invoke-I07WifiTransition -Action home')
    $terminalIndex = $controllerText.LastIndexOf(
        'if (-not $script:i07PublicChecks.cleanup_terminal)')
    $sourcePassCommitIndex = $controllerText.LastIndexOf(
        'Write-I07HeldSnapshot -Snapshot $sourcePassProofSnapshot')
    $viewerPassCommitIndex = $controllerText.LastIndexOf(
        'Write-I07HeldSnapshot -Snapshot $viewerPassProofSnapshot')
    $sourceRawCommitIndex = $controllerText.LastIndexOf(
        'Write-I07HeldSnapshot -Snapshot $sourceResultSnapshot')
    $viewerRawCommitIndex = $controllerText.LastIndexOf(
        'Write-I07HeldSnapshot -Snapshot $viewerResultSnapshot')
    if ($receiveText -cnotmatch
            '\[scriptblock\]\$ContextValidator' -or
        $receiveText -cnotmatch 'Test-I07ExternalJsonBoundary' -or
        $receiveText -cnotmatch '& \$ContextValidator \$snapshot\.value' -or
        $receiveText -cmatch 'Write-I07HeldSnapshot|DestinationPath' -or
        $controllerText -cnotmatch
            'New-I07R01PrerequisiteSnapshot' -or
        $controllerText -cmatch
            'Write-I07HeldSnapshot\s+-Snapshot\s+\$r01Snapshot\b' -or
        $controllerText -cnotmatch
            '\$sourcePreflight\s*=\s*\$preflightSnapshots\.source\.snapshot\.value' -or
        $homeRestoreIndex -lt 0 -or $terminalIndex -le $homeRestoreIndex -or
        $sourcePassCommitIndex -le $terminalIndex -or
        $viewerPassCommitIndex -le $terminalIndex -or
        $sourceRawCommitIndex -ge 0 -or $viewerRawCommitIndex -ge 0 -or
        $trapText -cmatch
            'Write-I07HeldSnapshot\s+-Snapshot\s+\$held\.snapshot' -or
        $trapText -cnotmatch 'Clear-I07ProductEvidenceForTerminal' -or
        $receiveText -cnotmatch 'Remove-I07OwnedStagingFile' -or
        $controllerText -cnotmatch 'Assert-I07StagingCleanupProven' -or
        $controllerText -cnotmatch 'STAGING_CLEANUP_NOT_PROVEN' -or
        $controllerText -cnotmatch 'Test-I07TerminalProofBundle' -or
        $controllerText -cnotmatch
            'Test-I07FailureProofProvenanceContract' -or
        $controllerText -cnotmatch
            'Test-I07R01PrerequisiteProvenanceContract' -or
        $controllerText -cnotmatch
            'source-pass-proof\.json.*viewer-pass-proof\.json' -or
        $controllerText -cnotmatch
            'ese\.v91\.i07-failure-proof/v1') {
        throw 'Validate-before-retain or terminal product retention regressed.'
    }
    if ($nodeText -cnotmatch
            'Test-I07ExactPropertySet -Value \$request' -or
        $nodeText -cnotmatch
            'Test-I07StrictInteger -Value \$request\.candidate_zip_bytes' -or
        $nodeText -cnotmatch
            'local_port\s*=\s*\[int\]\$portFilter\.LocalPort' -or
        $nodeText -cmatch '\$samples\.Count\s+-ge\s+10' -or
        $nodeText -cnotmatch
            '\$sessionStartedAt\s*=\s*\$sampleAt' -or
        $nodeText -cnotmatch '\$sampleAt\s+-ge\s+\$deadline' -or
        $commonText -cnotmatch 'segment_bytes\s*=' -or
        $commonText -cnotmatch 'minimum_write_utc\s*=') {
        throw 'Strict node request or producer evidence shapes regressed.'
    }

    if (-not (Test-I07ExpectedRejection -Operation {
                $null = Start-I07SystemMutationTransaction `
                    -DisposableAccountAcknowledged $false `
                    -ExpectedUserSidSha256 ('0' * 64)
            })) {
        throw 'The disposable-account gate accepted a false attestation.'
    }
    foreach ($requiredText in @(
        'disposable_lab_account_acknowledged',
        'expected_lab_user_sid_sha256',
        'Start-I07SystemMutationTransaction',
        'Complete-I07SystemMutationTransaction',
        'system_state_restored')) {
        if ($nodeText -cnotmatch [regex]::Escape($requiredText)) {
            throw "Node account/system contract omitted '$requiredText'."
        }
    }
    foreach ($requiredText in @(
        'SourceDisposableLabAccountAcknowledged',
        'ViewerDisposableLabAccountAcknowledged',
        'ExpectedSourceLabUserSidSha256',
        'ExpectedViewerLabUserSidSha256')) {
        if ($controllerText -cnotmatch [regex]::Escape($requiredText)) {
            throw "Controller account binding omitted '$requiredText'."
        }
    }
    foreach ($requiredText in @(
        'Software\Microsoft\Windows\CurrentVersion\Run',
        "TrackedRootValueName 'eMuleAutoStart'",
        'Software\Classes\ed2k',
        'INITIAL_REGISTRY_ABSENCE_NOT_PROVEN',
        'destructive_registry_restore_permitted = $false')) {
        if ($commonText -cnotmatch [regex]::Escape($requiredText)) {
            throw "Registry transaction contract omitted '$requiredText'."
        }
    }
    $firewallCollectors = @(
        'Get-NetFirewallRule', 'Get-NetFirewallPortFilter',
        'Get-NetFirewallApplicationFilter', 'Get-NetFirewallAddressFilter',
        'Get-NetFirewallInterfaceFilter',
        'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallServiceFilter', 'Get-NetFirewallSecurityFilter'
    )
    foreach ($collector in $firewallCollectors) {
        if ($commonText -cnotmatch [regex]::Escape($collector)) {
            throw "Global firewall snapshot omitted '$collector'."
        }
    }
    foreach ($requiredText in @(
        'Get-I07GlobalFirewallSnapshotOnce',
        'I07_FIREWALL::UNSTABLE_GLOBAL_SNAPSHOT',
        'Get-I07BoundFirewallRuleSnapshot',
        'IDENTITY_CHANGED_BEFORE_REMOVE',
        'Remove-I07BoundFirewallRule')) {
        if (($commonText + $nodeText) -cnotmatch
                [regex]::Escape($requiredText)) {
            throw "Firewall transaction contract omitted '$requiredText'."
        }
    }
    foreach ($preference in @(
        "@('eMule', 'OpenPortsOnStartUp', '0')",
        "@('eMule', 'AutoStart', '0')",
        "@('eMule', 'AutoTakeED2KLinks', '0')",
        "@('eMule', 'WatchClipboard4ED2kFilelinks', '0')")) {
        if ($commonText -cnotmatch [regex]::Escape($preference)) {
            throw "Prepared preferences omitted the guard '$preference'."
        }
    }
    $launchSequencePattern =
        'Get-I07PreparedNodeLaunchBinding[\s\S]{0,600}' +
        'Start-I07CandidateProcess[\s\S]{0,600}' +
        'Get-I07ProcessIdentity'
    if (@([regex]::Matches($nodeText, $launchSequencePattern)).Count -ne 2 -or
        $commonText -cnotmatch '\[IO\.FileShare\]::Read' -or
        @([regex]::Matches($commonText,
                '\[IO\.FileShare\]::Read')).Count -lt 2 -or
        $commonText -cnotmatch 'I07_PROCESS_CLEANUP::UNEXPECTED_DESCENDANT' -or
        $commonText -cnotmatch 'DESCENDANT_PREDATES_ROOT' -or
        $commonText -cnotmatch 'user_sid_sha256' -or
        $nodeText -cmatch '(?m)^\s*Stop-Process\b') {
        throw 'Prelaunch, held-file or process identity binding regressed.'
    }
    foreach ($collectorPattern in @(
        'Get-NetRoute[\s\S]{0,180}-ErrorAction Stop',
        'Get-NetTCPConnection[\s\S]{0,180}-ErrorAction Stop',
        'Get-NetIPAddress[\s\S]{0,180}-ErrorAction Stop',
        'Get-NetAdapter[\s\S]{0,180}-ErrorAction Stop')) {
        if (($commonText + $nodeText) -cnotmatch $collectorPattern) {
            throw "Fail-closed collector pattern missing: $collectorPattern"
        }
    }
    if (($commonText + $nodeText + $baselineText + $preflightText +
            $wifiText + $watchdogText) -cmatch
            '(?i)-ErrorAction\s+SilentlyContinue') {
        throw 'A critical I07 collector still suppresses collection errors.'
    }

    $rawDiagnosticSecret =
        'C:\Users\fixture\dpapi-token.txt?key=' + ('f' * 32)
    $rawDiagnosticRoot = Join-Path $root 'raw-diagnostic-negative'
    New-Item -ItemType Directory -Path $rawDiagnosticRoot -Force |
        Out-Null
    $rawDiagnosticRequest = Join-Path $rawDiagnosticRoot 'request.json'
    [ordered]@{
        schema = 'invalid-contract'
        role = 'source'
        nonce = '0' * 32
        private_diagnostic = $rawDiagnosticSecret
    } | ConvertTo-Json | Set-Content -LiteralPath $rawDiagnosticRequest `
        -Encoding UTF8
    $rawDiagnosticOutput = @(& powershell.exe -NoProfile -NonInteractive `
        -File (Join-Path $PSScriptRoot `
            'inspect_v91_i07_baseline_remote.ps1') `
        -JobRequestPath $rawDiagnosticRequest 2>&1)
    $rawDiagnosticExit = $LASTEXITCODE
    $rawDiagnosticResult = Get-Content -LiteralPath (
        Join-Path $rawDiagnosticRoot 'result.json') -Raw
    if ($rawDiagnosticExit -ne 2 -or
        (($rawDiagnosticOutput -join "`n") + $rawDiagnosticResult) -match
            [regex]::Escape($rawDiagnosticSecret) -or
        $rawDiagnosticResult -notmatch
            '"error_code"\s*:\s*"BASELINE_NOT_CLEAN_OR_UNAVAILABLE"') {
        throw 'Typed remote errors leaked their raw diagnostic fixture.'
    }

    $hotspotIndex = $wifiText.IndexOf("if (`$action -ceq 'hotspot')")
    $armedIndex = $wifiText.IndexOf(
        'ese.v91.i07-home-watchdog-armed/v1', $hotspotIndex)
    $connectIndex = $wifiText.IndexOf(
        '& netsh.exe wlan connect', $hotspotIndex)
    if ($hotspotIndex -lt 0 -or $armedIndex -le $hotspotIndex -or
        $connectIndex -le $armedIndex) {
        throw 'The Home watchdog is not validated before hotspot connect.'
    }
    foreach ($requiredText in @(
        'deadline_utc', 'lease_deadline', 'restore-now.json',
        'home_wlan_profile_sha256', 'home_connection_profile_sha256',
        'interface_guid', 'ese.v91.i07-home-watchdog-result/v1',
        'ese.v91.i07-home-restore-signal/v1',
        'invalid_restore_signal', 'restore_signal_valid')) {
        if ($watchdogText -cnotmatch [regex]::Escape($requiredText)) {
            throw "Watchdog contract omitted '$requiredText'."
        }
    }
    foreach ($requiredText in @(
        'ese.v91.i07-home-watchdog-disarmed/v1',
        "trigger -cne 'controller_restore'",
        'ExpectedWlanSha256', 'process_exited = $true')) {
        if ($wifiText -cnotmatch [regex]::Escape($requiredText)) {
            throw "Wi-Fi disarm contract omitted '$requiredText'."
        }
    }
    if (@([regex]::Matches($nodeText,
            "apiWaitMessage\.StartsWith\('I07_LAB::'" )).Count -ne 2 -or
        @([regex]::Matches($nodeText,
            'Candidate launch failed:')).Count -ne 2 -or
        $nodeText -cnotmatch 'Get-I07ExactNodeFfmpegProcesses' -or
        $nodeText -cnotmatch "Name='ffmpeg\.exe'" -or
        $nodeText -cnotmatch 'cleanup\.ffmpeg_children_gone = ' -or
        $nodeText -cnotmatch 'Write-I07RetainedNodeEvidence' -or
        $nodeText -cnotmatch 'cleanup\.evidence_retained' -or
        @([regex]::Matches($nodeText,
            'api_status_(?:initial|final)\s*=\s*Get-I07ApiEvidenceSummary')).
                Count -ne 2 -or
        $nodeText -cmatch
            '(?m)^\s*api_status_(?:initial|final)\s*=\s*\$apiStatus') {
        throw 'Node cancellation, FFmpeg or retained-evidence guards regressed.'
    }
    if ($controllerText -cmatch '(?m)^\s*-ProfileSha256\s' -or
        $controllerText -cnotmatch
            'Viewer Home watchdog did not restore and disarm normally' -or
        @([regex]::Matches($controllerText,
            '\[string\]\$homeRestore\.status -cne ''PASS''')).Count -lt 2) {
        throw 'Controller does not gate every normal Home result as PASS.'
    }
    foreach ($requiredText in @(
        "protocol = 2", "utc_now =", "@('cooperative_cancel')")) {
        if ($agentText -cnotmatch [regex]::Escape($requiredText)) {
            throw "Small-frame readiness omitted '$requiredText'."
        }
    }
    foreach ($requiredText in @(
        'absolute_pair_offset_bound_ms',
        'inspect_v91_i07_baseline_remote.ps1',
        'agent_readiness_before_wifi_mutation',
        "kind = 'baseline'")) {
        if ($controllerText -cnotmatch [regex]::Escape($requiredText)) {
            throw "Pre-mutation controller guard omitted '$requiredText'."
        }
    }
    if ($controllerText -cnotmatch 'ese\.v91\.i07-public-aggregate/v1' -or
        $controllerText -cnotmatch 'Join-Path \$runRoot ''private''' -or
        @([regex]::Matches($controllerText,
            '(?m)^\s*controller_error\s*=')).Count -ne 1 -or
        $controllerText -cmatch 'recovered_results\s*=' -or
        $controllerText -cmatch
            '\[string\]\$SourceAgentIPv4\s*=\s*''100\.' -or
        $controllerText -cmatch
            '\[string\]\$ViewerAgentIPv4\s*=\s*''100\.' -or
        $nodeText -cmatch '(?m)^\s*detail\s*=\s*\$Detail' -or
        $nodeText -cmatch '(?m)^\s*message\s*=\s*\$failure' -or
        $nodeText -cmatch '(?m)^\s*(?:rule_bindings|firewall_bindings)\s*=' -or
        $commonText -cmatch '\$base\[''error''\]' -or
        $baselineText -cmatch '(?m)^\s*error\s*=' -or
        $wifiText -cmatch '(?m)^\s*error\s*=' -or
        $watchdogText -cmatch '(?m)^\s*error\s*=' -or
        $preflightText -cmatch
            'computer_name_sha256|native_global_candidates|ipv6_inventory\s*=' -or
        ($commonText + $baselineText + $wifiText + $watchdogText +
            $nodeText) -cmatch '\[Console\]::Error\.WriteLine' -or
        ($commonText + $baselineText + $wifiText + $watchdogText +
            $nodeText) -cmatch
                '(?i)Write-Error\s+(?:\$|\(|[^\r\n]*Exception\.Message)') {
        throw 'I07 public/private or fixed-error privacy guards regressed.'
    }

    [pscustomobject]@{
        schema = 'ese.v91.i07-offline-selftest/v3'
        case_id = 'V91-I07'
        status = 'PASS'
        formal_case_status = 'BLOCKED'
        physical_execution_performed = $false
        address_cases = 19
        package_files = $contracts.Count
        package_contract_negative_cases = 4
        package_mutation_negative_cases = 7
        zip_safe_wrapper_root = $true
        zip_negative_cases = 1 + $zipMutationRejectCount
        prelaunch_binding = $true
        held_file_share_read_only = $true
        ini_guards = 9
        hls_freshness = $true
        hls_traversal_negative_cases = 2
        hls_privacy_negative_cases = 4
        api_privacy_negative_cases = 5
        api_peer_privacy_negative_cases = 3
        remote_zip_binding = $true
        retained_evidence = $true
        retained_negative_cases = 4
        parser_files = $toolFiles.Count
        watchdog_static_guards = 4
        pre_mutation_static_guards = 4
        cancellation_static_guards = 2
        ffmpeg_cleanup_static_guard = $true
        safe_delete_reparse_cases = 2
        account_transaction_guards = 10
        registry_absence_guards = 5
        firewall_collector_guards = $firewallCollectors.Count
        firewall_identity_guards = 5
        process_identity_guards = 6
        fail_closed_collector_guards = 10
        privacy_static_guards = 12
        retention_boundary_static_guards = 13
        producer_contract_static_guards = 5
        raw_error_negative_cases = 1
    }
} finally {
    if (-not [string]::IsNullOrWhiteSpace($hlsPath)) {
        try {
            $hlsParent = [IO.Path]::GetDirectoryName(
                [IO.Path]::GetFullPath($hlsPath))
            $null = Remove-I07TreeNoReparse -Path $hlsPath `
                -ExpectedParent $hlsParent
        } catch {}
    }
    try {
        $rootParent = [IO.Path]::GetDirectoryName(
            [IO.Path]::GetFullPath($root))
        $null = Remove-I07TreeNoReparse -Path $root `
            -ExpectedParent $rootParent
    } catch {}
}
