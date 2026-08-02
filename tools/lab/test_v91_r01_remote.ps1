[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

function Get-IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $active = ''
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*\[(.+)\]\s*$') {
            $active = $Matches[1]
            continue
        }
        if ($active -ceq $Section -and
            $line -match ('^\s*' + [regex]::Escape($Key) +
                '\s*=(.*)$')) {
            return $Matches[1]
        }
    }
    throw "Missing [$Section] $Key in $Path."
}

$runner = Join-Path $PSScriptRoot 'run_v91_r01_remote.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $runner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "R01 runner has $($parseErrors.Count) parser error(s)."
}
foreach ($name in @(
        'Get-Hash', 'Test-R01SafeRelativePath', 'Assert-R01NoReparsePath',
        'Get-R01PackageManifestCanonical',
        'Assert-R01PackageManifestContract',
        'Test-R01AccountRegistrySnapshotEqual',
        'Remove-R01TreeNoReparse', 'Set-IniValue',
        'Set-R01CandidateProfile')) {
    $definition = @(
        $ast.FindAll({
                param($node)
                $node -is
                    [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
            }, $true)
    )
    if ($definition.Count -ne 1) {
        throw "Expected one $name definition, found $($definition.Count)."
    }
    Invoke-Expression $definition[0].Extent.Text
}

$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $tempRoot (
    'ese-v91-r01-profile-test-' + [guid]::NewGuid().ToString('N'))
if (-not ([IO.Path]::GetFullPath($testRoot)).StartsWith(
        $tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to create R01 test outside the system temp directory.'
}

try {
    $config = Join-Path $testRoot 'config'
    $null = New-Item -ItemType Directory -Path $config -Force
    $preferences = Join-Path $config 'preferences.ini'
    [IO.File]::WriteAllText(
        $preferences,
        @'
[eMule]
Autoconnect=0
NetworkED2K=0
FilterBadIPs=1
[Connection]
KadNetworkMask=3
NetworkED2K=0
CryptLayerRequested=1
CryptLayerRequired=1
CryptLayerSupported=1
[UPnP]
EnableUPnP=1
[WebServer]
Enabled=0
Port=4711
'@,
        [Text.UTF8Encoding]::new($false))
    foreach ($name in @('server.met', 'server_met.old')) {
        [IO.File]::WriteAllBytes(
            (Join-Path $config $name), [byte[]](0xE0, 0, 0, 0, 0))
    }
    $request = [pscustomobject]@{
        nonce = 'profiletest'
        initial_server_address = '192.0.2.10'
        mobile_server_address = '198.51.100.20'
        server_port = 18080
        tcp_port = 49662
        udp_port = 49672
        web_port = 49711
    }

    Set-R01CandidateProfile -NodePath $testRoot -Request $request

    Assert-Equal (Get-IniValue $preferences eMule FilterBadIPs) '0' `
        'LAN filtering was not disabled.'
    Assert-Equal (Get-IniValue $preferences Connection NetworkED2K) '1' `
        'NetworkED2K was not enabled in its effective section.'
    foreach ($key in @(
        'CryptLayerRequested', 'CryptLayerRequired',
        'CryptLayerSupported'
    )) {
        Assert-Equal (Get-IniValue $preferences Connection $key) '0' `
            "$key was not disabled in its effective section."
    }
    Assert-Equal (Get-IniValue $preferences eMule Port) '49662' `
        'TCP port was not pinned.'
    foreach ($key in @(
        'AutoStart', 'AutoTakeED2KLinks',
        'WatchClipboard4ED2kFilelinks', 'OpenPortsOnStartUp')) {
        Assert-Equal (Get-IniValue $preferences eMule $key) '0' `
            "$key was not forced to its non-persistent value."
    }
    Assert-Equal (Get-IniValue $preferences WebServer Port) '49711' `
        'Web API port was not pinned.'
    Assert-Equal (Get-IniValue $preferences UPnP EnableUPnP) '0' `
        'Candidate UPnP was not disabled.'
    Assert-Equal (Get-IniValue $preferences Proxy ProxyEnableProxy) '0' `
        'Inherited proxy data path was not disabled.'
    Assert-Equal (Get-IniValue $preferences Proxy ProxyType) '0' `
        'Inherited proxy type was not cleared.'

    foreach ($name in @('server.met', 'server_met.old')) {
        if (Test-Path -LiteralPath (Join-Path $config $name)) {
            throw "$name was not removed before the controlled run."
        }
    }
    $staticPath = Join-Path $config 'staticservers.dat'
    $staticBytes = [IO.File]::ReadAllBytes($staticPath)
    if ($staticBytes.Length -lt 4 -or $staticBytes[0] -ne 0xFF -or
        $staticBytes[1] -ne 0xFE) {
        throw 'staticservers.dat is not UTF-16 LE with BOM.'
    }
    $staticText = [Text.Encoding]::Unicode.GetString(
        $staticBytes, 2, $staticBytes.Length - 2)
    foreach ($expected in @(
        '192.0.2.10:18080,0,eSE-R01-LAN-profiletest',
        '198.51.100.20:18080,0,eSE-R01-MOBILE-profiletest'
    )) {
        if ($staticText -notmatch [regex]::Escape($expected)) {
            throw "Missing controlled server line: $expected"
        }
    }

    foreach ($unsafe in @(
        '../emule.exe', 'dir/../emule.exe', 'dir//emule.exe',
        '/absolute/emule.exe', 'C:\absolute\emule.exe', './emule.exe')) {
        if (Test-R01SafeRelativePath -Path $unsafe) {
            throw "Unsafe relative path was accepted: $unsafe"
        }
    }
    if (-not (Test-R01SafeRelativePath -Path 'config/preferences.ini')) {
        throw 'A normal nested relative path was rejected.'
    }

    $manifestFiles = @(
        [pscustomobject]@{ relative_path = 'BUILD_INFO.txt'; bytes = [Int64]3; sha256 = 'a' * 64 },
        [pscustomobject]@{ relative_path = 'emule.exe'; bytes = [Int64]4; sha256 = 'b' * 64 },
        [pscustomobject]@{ relative_path = 'ese-server.exe'; bytes = [Int64]5; sha256 = 'c' * 64 })
    $manifestSha = Get-Hash -Text (
        Get-R01PackageManifestCanonical -Files $manifestFiles)
    $manifest = [pscustomobject][ordered]@{
        schema = 'ese.v91.package-zip-binding/v3'
        zip_root_prefix = 'candidate/'
        zip_sha256 = 'd' * 64; zip_bytes = [Int64]99
        file_count = 3; manifest_sha256 = $manifestSha
        exact_file_set = $true; exact_bytes_and_sha256 = $true
        locked_snapshot = $true; reparse_free = $true
        files = $manifestFiles
    }
    $null = Assert-R01PackageManifestContract -Manifest $manifest `
        -ExpectedSha256 $manifestSha -ExpectedFileCount 3
    $savedFiles = $manifest.files
    $manifest.files = @(
        $manifestFiles[0], $manifestFiles[1],
        [pscustomobject]@{ relative_path = 'EMULE.EXE'; bytes = [Int64]5; sha256 = 'c' * 64 })
    $collisionRejected = $false
    try {
        $null = Assert-R01PackageManifestContract -Manifest $manifest `
            -ExpectedSha256 $manifestSha -ExpectedFileCount 3
    } catch { $collisionRejected = $true }
    if (-not $collisionRejected) { throw 'Manifest case collision was accepted.' }
    $manifest.files = $savedFiles
    $manifest.locked_snapshot = 'true'
    $typeRejected = $false
    try {
        $null = Assert-R01PackageManifestContract -Manifest $manifest `
            -ExpectedSha256 $manifestSha -ExpectedFileCount 3
    } catch { $typeRejected = $true }
    if (-not $typeRejected) { throw 'String boolean manifest flag was accepted.' }
    $manifest.locked_snapshot = $true

    $snapshotA = [pscustomobject]@{
        schema = 'ese.v91.r01-account-registry/v1'; sid_sha256 = '1' * 64
        snapshot_sha256 = '2' * 64
        run_subtree = [pscustomobject]@{ canonical_sha256 = '3' * 64 }
        ed2k_subtree = [pscustomobject]@{ canonical_sha256 = '4' * 64 }
    }
    $snapshotB = $snapshotA | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    if (-not (Test-R01AccountRegistrySnapshotEqual `
            -Before $snapshotA -After $snapshotB)) {
        throw 'Equal registry snapshots were rejected.'
    }
    $snapshotB.ed2k_subtree.canonical_sha256 = '5' * 64
    if (Test-R01AccountRegistrySnapshotEqual `
            -Before $snapshotA -After $snapshotB) {
        throw 'Changed ed2k registry state was accepted.'
    }

    $safeParent = Join-Path $testRoot 'cleanup-parent'
    $safeChild = Join-Path $safeParent 'node'
    [IO.Directory]::CreateDirectory($safeChild) | Out-Null
    [IO.File]::WriteAllText((Join-Path $safeChild 'owned.txt'), 'owned')
    if (-not (Remove-R01TreeNoReparse -Path $safeChild `
            -ExpectedParent $safeParent)) {
        throw 'Normal nonce-owned tree was not removed.'
    }
    $junctionTarget = Join-Path $safeParent 'target'
    $junction = Join-Path $safeParent 'node'
    [IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    [IO.File]::WriteAllText((Join-Path $junctionTarget 'sentinel.txt'), 'keep')
    $null = New-Item -ItemType Junction -Path $junction `
        -Target $junctionTarget -ErrorAction Stop
    $junctionRejected = $false
    try {
        $null = Remove-R01TreeNoReparse -Path $junction `
            -ExpectedParent $safeParent
    } catch { $junctionRejected = $true }
    if (-not $junctionRejected -or
        -not (Test-Path -LiteralPath (Join-Path $junctionTarget 'sentinel.txt'))) {
        throw 'Reparse cleanup was not rejected without touching its target.'
    }
    [IO.Directory]::Delete($junction)

    $runnerText = Get-Content -LiteralPath $runner -Raw
    foreach ($requiredText in @(
        'expected_account_sid_sha256', 'Get-R01AccountRegistrySnapshot',
        'AutoStart = ''0''', 'AutoTakeED2KLinks = ''0''',
        'WatchClipboard4ED2kFilelinks = ''0''',
        'OpenPortsOnStartUp = ''0''', 'FileShare]::Read',
        'Assert-R01PackageManifestContract',
        'Start-R01IdentityBoundCandidate',
        'Stop-R01IdentityBoundCandidate', 'Remove-R01TreeNoReparse',
        'Get-R01SelectedRouteEvidence', 'Test-R01OverlayAdapter',
        'Get-R01PortBaseline', 'Get-R01FirewallRulesByNameFailClosed',
        '$LASTEXITCODE -ne 0')) {
        if (-not $runnerText.Contains($requiredText)) {
            throw "Remote hardening invariant is missing: $requiredText"
        }
    }
    if ($runnerText -match
        'Get-Process\s+-Name\s+emule[\s\S]{0,80}SilentlyContinue') {
        throw 'Remote process collector still fails open.'
    }

    [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-remote-profile-selftest/v2'
        case_id = 'V91-R01'
        status = 'PASS'
        formal_case_status = 'BLOCKED'
        physical_execution_performed = $false
        runner = 'tools/lab/run_v91_r01_remote.ps1'
        runner_sha256 = (Get-FileHash -LiteralPath $runner `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        effective_network_section = 'Connection'
        staticservers_encoding = 'UTF-16LE-BOM'
        safe_preference_keys = 4
        manifest_negative_cases = 2
        path_negative_cases = 6
        registry_snapshot_negative_cases = 1
        reparse_cleanup_negative_cases = 1
        fail_closed_collectors = $true
        identity_bound_cleanup = $true
    } | ConvertTo-Json -Depth 4
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith(
                $tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean unexpected path: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
