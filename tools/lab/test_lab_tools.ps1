[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$labTools = Join-Path $RepoRoot 'tools\lab'
. (Join-Path $labTools 'common.ps1')

function Assert-LabTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw "WP0 smoke assertion failed: $Message" }
}

function Write-TestFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -Force
    }
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Value, $encoding)
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('eSE-lab-tool-tests-' + [Guid]::NewGuid().ToString('N'))
$testRoot = [IO.Path]::GetFullPath($testRoot)
$sourcePackage = Join-Path $testRoot 'source-package'
$nodesRoot = Join-Path $testRoot 'nodes'
$runDirectory = Join-Path $testRoot 'run'
$listener = $null
$client = $null
$acceptedClient = $null

try {
    $null = New-Item -ItemType Directory -Path $sourcePackage
    $null = New-Item -ItemType Directory -Path $runDirectory
    Write-TestFile -Path (Join-Path $sourcePackage 'emule.exe') -Value 'WP0 dummy executable'
    Write-TestFile -Path (Join-Path $sourcePackage 'ese-server.exe') -Value 'WP0 dummy API executable'
    Write-TestFile -Path (Join-Path $sourcePackage 'BUILD_INFO.txt') -Value @'
Version: 9.0.0-test
Commit: 0123456789abcdef0123456789abcdef01234567
'@
    Write-TestFile -Path (Join-Path $sourcePackage 'config\preferences.ini') -Value @'
[eMule]
Nick=original
Port=4662
UDPPort=4672
[WebServer]
Enabled=1
Port=4711
WebUseUPnP=1
[eSE]
EseNetLabEnabled=1
[KRPRelay]
KrpRelayEnabled=1
'@

    $secretFixture = [ordered]@{
        token = 'must-not-survive'
        timestamp = '2026-07-24T07:57:55.123Z'
        ipv4 = '192.168.1.20'
        ipv6 = '2001:db8::20'
    }
    $sanitized = ConvertTo-LabSanitizedValue -InputObject $secretFixture -RedactAddresses
    Assert-LabTest -Condition ($sanitized.token -eq '<redacted>') -Message 'token redaction'
    Assert-LabTest -Condition ($sanitized.ipv4 -eq '<redacted-ipv4>') -Message 'IPv4 redaction'
    Assert-LabTest -Condition ($sanitized.ipv6 -eq '<redacted-ipv6>') -Message 'IPv6 redaction'
    Assert-LabTest -Condition ($sanitized.timestamp -eq $secretFixture.timestamp) `
        -Message 'timestamp must not be mistaken for IPv6'

    & (Join-Path $labTools 'inventory.ps1') -NodeRole controller `
        -PackagePath $sourcePackage `
        -OutFile (Join-Path $runDirectory 'inventory.json')
    $inventoryText = Get-Content -LiteralPath (Join-Path $runDirectory 'inventory.json') -Raw
    Assert-LabTest -Condition (-not $inventoryText.Contains($env:COMPUTERNAME)) `
        -Message 'default inventory leaked the machine name'
    Assert-LabTest -Condition ($inventoryText -notmatch '"address"\s*:') `
        -Message 'default inventory contained a full network address'
    $inventory = $inventoryText | ConvertFrom-Json
    Assert-LabTest -Condition ($inventory.PSObject.Properties.Name -contains 'routes') `
        -Message 'inventory did not include the sanitized route table'
    $knownInterfaceIds = @($inventory.network_interfaces | ForEach-Object {
        [string]$_.interface_id
    })
    foreach ($routeInterfaceId in @($inventory.routes | Where-Object {
        $null -ne $_.interface_id
    } | ForEach-Object { [string]$_.interface_id })) {
        Assert-LabTest -Condition ($knownInterfaceIds -contains $routeInterfaceId) `
            -Message "route interface '$routeInterfaceId' is absent from network inventory"
    }
    Assert-LabTest -Condition ($inventory.candidate_build.version -eq '9.0.0-test') `
        -Message 'inventory did not identify the candidate version'
    Assert-LabTest -Condition ([string]$inventory.candidate_build.files.'emule.exe'.sha256 -match '^[0-9a-f]{64}$') `
        -Message 'inventory did not hash the candidate executable'

    & (Join-Path $labTools 'prepare_node.ps1') -NodeRole B -SourcePackage $sourcePackage `
        -OutputRoot $nodesRoot -RunId 'wp0-smoke' -PortOffset 100
    $preparedNode = Join-Path $nodesRoot 'wp0-smoke-b'
    $preferences = Get-Content -LiteralPath (Join-Path $preparedNode 'config\preferences.ini') -Raw
    foreach ($requiredSetting in @(
        'Nick=eSE-v9-lab-wp0-smoke-B',
        'Port=4762',
        'UDPPort=4772',
        'WebUseUPnP=0',
        'EseNetLabConsent=0',
        'EseNetLabEnabled=0',
        'EseV9Experimental=0',
        'KrpRelayEnabled=0',
        'KrpRelayKillSwitch=0',
        'ExperimentalTcpDataPlane=0'
    )) {
        Assert-LabTest -Condition $preferences.Contains($requiredSetting) `
            -Message "prepared profile is missing '$requiredSetting'"
    }
    $nodeManifest = Get-Content -LiteralPath (Join-Path $preparedNode 'LAB_NODE.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition ($nodeManifest.node_role -eq 'B') -Message 'node manifest role'
    Assert-LabTest -Condition (-not $nodeManifest.experimental_features_enabled) `
        -Message 'prepared node unexpectedly enabled experiments'
    Copy-Item -LiteralPath (Join-Path $preparedNode 'LAB_NODE.json') `
        -Destination (Join-Path $runDirectory 'node-b.json')
    $overwriteRefused = $false
    try {
        & (Join-Path $labTools 'prepare_node.ps1') -NodeRole B -SourcePackage $sourcePackage `
            -OutputRoot $nodesRoot -RunId 'wp0-smoke' -PortOffset 100
    } catch {
        $overwriteRefused = $true
    }
    Assert-LabTest -Condition $overwriteRefused `
        -Message 'node preparation did not refuse an existing target'

    & (Join-Path $labTools 'capture_status.ps1') -NodeRole controller `
        -BaseUrl 'http://127.0.0.1:1' -AllowUnavailable -TargetProcessIds @($PID) `
        -OutFile (Join-Path $runDirectory 'status.json')
    $status = Get-Content -LiteralPath (Join-Path $runDirectory 'status.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition (-not $status.status.available) `
        -Message 'unavailable API was not recorded as unavailable'
    Assert-LabTest -Condition (@($status.processes).Count -ge 1) `
        -Message 'status did not capture the requested process'
    $statusText = Get-Content -LiteralPath (Join-Path $runDirectory 'status.json') -Raw
    Assert-LabTest -Condition (-not $statusText.Contains('127.0.0.1')) `
        -Message 'default status artifact leaked a complete API address'

    $remoteApiRefused = $false
    try {
        & (Join-Path $labTools 'capture_status.ps1') -NodeRole controller `
            -BaseUrl 'http://192.0.2.1:4711' -AllowUnavailable `
            -OutFile (Join-Path $testRoot 'remote-api-must-not-exist.json')
    } catch {
        $remoteApiRefused = $true
    }
    Assert-LabTest -Condition $remoteApiRefused `
        -Message 'remote API was accepted without -AllowRemoteApi'

    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $routePort = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $client = New-Object Net.Sockets.TcpClient
    $connectTask = $client.ConnectAsync([Net.IPAddress]::Loopback, $routePort)
    $acceptedClient = $listener.AcceptTcpClient()
    $connectTask.Wait()
    & (Join-Path $labTools 'assert_data_route.ps1') -TargetProcessId $PID `
        -ExpectedRemoteAddress '127.0.0.1' -ExpectedRemotePort $routePort `
        -RequiredFamily IPv4 -OutFile (Join-Path $runDirectory 'route.json')
    $route = Get-Content -LiteralPath (Join-Path $runDirectory 'route.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition ($route.verdict -eq 'PASS') -Message 'loopback route assertion'
    $forbiddenRouteRefused = $false
    try {
        & (Join-Path $labTools 'assert_data_route.ps1') -TargetProcessId $PID `
            -ExpectedRemoteAddress '127.0.0.1' -ExpectedRemotePort $routePort `
            -RequiredFamily IPv4 -ForbiddenInterfacePattern '.' `
            -OutFile (Join-Path $testRoot 'forbidden-route.json')
    } catch {
        $forbiddenRouteRefused = $true
    }
    Assert-LabTest -Condition $forbiddenRouteRefused `
        -Message 'route assertion accepted a forbidden interface'

    & (Join-Path $labTools 'soak_monitor.ps1') -NodeRole controller `
        -BaseUrl 'http://127.0.0.1:1' -AllowUnavailable -TargetProcessId $PID `
        -RequireProcess -DurationSeconds 1 -IntervalSeconds 1 `
        -OutFile (Join-Path $runDirectory 'soak.json') `
        -SamplesFile (Join-Path $runDirectory 'soak.jsonl')
    $soak = Get-Content -LiteralPath (Join-Path $runDirectory 'soak.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition ($soak.verdict -eq 'PASS') -Message 'short soak verdict'
    Assert-LabTest -Condition ($soak.sample_count -ge 1) -Message 'short soak sample count'

    & (Join-Path $labTools 'collect_report.ps1') -RunDirectory $runDirectory `
        -CaseId 'WP0-SMOKE' -Outcome PASS -Version 'development' `
        -Notes 'redaction fixture 192.168.1.20' `
        -OutFile (Join-Path $runDirectory 'REPORT-WP0-SMOKE.json') `
        -MarkdownOut (Join-Path $runDirectory 'REPORT-WP0-SMOKE.md')
    $reportText = Get-Content -LiteralPath (Join-Path $runDirectory 'REPORT-WP0-SMOKE.json') -Raw
    $report = $reportText | ConvertFrom-Json
    Assert-LabTest -Condition ($report.outcome -eq 'PASS') -Message 'canonical report outcome'
    Assert-LabTest -Condition ($report.evidence_count -ge 6) -Message 'canonical evidence index'
    Assert-LabTest -Condition ([string]$report.notes -eq 'redaction fixture <redacted-ipv4>') `
        -Message 'canonical report did not redact note address'
    Assert-LabTest -Condition ([string]$report.generated_at_utc -match '^\d{4}-\d{2}-\d{2}T.+Z$') `
        -Message 'canonical report mistook timestamps for IPv6'

    $contradictoryRun = Join-Path $testRoot 'contradictory-run'
    Write-TestFile -Path (Join-Path $contradictoryRun 'failed.json') `
        -Value '{"schema":"ese.lab.test/v1","verdict":"FAIL"}'
    $contradictoryPassRefused = $false
    try {
        & (Join-Path $labTools 'collect_report.ps1') -RunDirectory $contradictoryRun `
            -CaseId 'WP0-CONTRADICTION' -Outcome PASS
    } catch {
        $contradictoryPassRefused = $true
    }
    Assert-LabTest -Condition $contradictoryPassRefused `
        -Message 'collector published PASS despite failed evidence'

    Write-Host "WP0 lab tools smoke PASS: $testRoot" -ForegroundColor Green
} finally {
    if ($null -ne $acceptedClient) { $acceptedClient.Dispose() }
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $listener) { $listener.Stop() }

    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $testRoot)) {
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@('\', '/'))
        $testParent = [IO.Path]::GetFullPath((Split-Path -Parent $testRoot)).TrimEnd([char[]]@('\', '/'))
        $testLeaf = Split-Path -Leaf $testRoot
        if ($testParent -ne $tempRoot -or -not $testLeaf.StartsWith('eSE-lab-tool-tests-')) {
            throw "Refusing unsafe smoke-test cleanup: $testRoot"
        }
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
