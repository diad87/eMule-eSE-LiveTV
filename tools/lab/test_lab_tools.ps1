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
$evidenceJunction = $null

try {
    $null = New-Item -ItemType Directory -Path $sourcePackage
    $null = New-Item -ItemType Directory -Path $runDirectory
    Write-TestFile -Path (Join-Path $sourcePackage 'emule.exe') -Value 'WP0 dummy executable'
    Write-TestFile -Path (Join-Path $sourcePackage 'ese-server.exe') -Value 'WP0 dummy API executable'
    Write-TestFile -Path (Join-Path $sourcePackage 'BUILD_INFO.txt') -Value @'
Version: 9.0.0-test
Commit: 0123456789abcdef0123456789abcdef01234567
Dirty: false
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
        'AppVersion=eSE v9 lab prepared profile',
        'MaxUpload=-1',
        'MaxDownload=-1',
        'WebUseUPnP=0',
        'EseNetLabConsent=0',
        'EseNetLabAdvancedConsent=0',
        'EseNetLabContributionConsent=0',
        'EseNetLabEnabled=0',
        'EseV9Experimental=0',
        'KrpRelayEnabled=0',
        'KrpRelayKillSwitch=1',
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

    & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
        -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory
    $ledgerPath = Join-Path $runDirectory 'V91-RC-LEDGER.json'
    $ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
    Assert-LabTest -Condition ($ledger.schema -eq 'ese.v91.rc-ledger/v2') `
        -Message 'V91 ledger schema'
    Assert-LabTest -Condition ($ledger.counts.total -eq 27) `
        -Message 'V91 ledger normative case count'
    foreach ($caseId in 'V91-I03', 'V91-I04', 'V91-D01') {
        $case = @($ledger.cases | Where-Object id -eq $caseId)
        Assert-LabTest -Condition ($case.Count -eq 1 -and
            $case[0].required_topology -eq 'T1/T2') `
            -Message "$caseId ledger topology"
    }

    & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
        -EvidenceRoot $runDirectory
    $campaignFinal = Get-Content -LiteralPath `
        (Join-Path $runDirectory 'V91-CAMPAIGN-FINAL.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition (
        $campaignFinal.schema -eq 'ese.v91.campaign-final/v2') `
        -Message 'V91 final report schema'
    Assert-LabTest -Condition (
        $campaignFinal.formal_counts.total -eq 27 -and
        $campaignFinal.cases.Count -eq 27) `
        -Message 'V91 final report case count'
    Assert-LabTest -Condition (
        $campaignFinal.candidate.commit -eq
            '0123456789abcdef0123456789abcdef01234567' -and
        $campaignFinal.candidate_binary_sha256 -match '^[0-9a-f]{64}$') `
        -Message 'V91 final report candidate identity'
    $evidenceManifest = Get-Content -LiteralPath `
        (Join-Path $runDirectory 'V91-EVIDENCE-MANIFEST.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition (
        $evidenceManifest.evidence_file_count -eq 0 -and
        $evidenceManifest.candidate.commit -eq
            '0123456789abcdef0123456789abcdef01234567') `
        -Message 'V91 evidence manifest identity'

    $candidateForLedger = Get-LabCandidateInfo -PackagePath $sourcePackage
    $exactEvidenceRelative = 'exact-candidate-evidence.json'
    Write-TestFile -Path (Join-Path $runDirectory $exactEvidenceRelative) `
        -Value (([ordered]@{
            schema = 'ese.lab.exact-candidate-evidence/v1'
            candidate = [ordered]@{
                commit = $candidateForLedger.commit
                expected_emule_sha256 = $candidateForLedger.emule_sha256
            }
            verdict = 'PASS'
        } | ConvertTo-Json -Depth 5))

    $unsafePassPath = Join-Path $runDirectory 'unsafe-pass-results.json'
    Write-TestFile -Path $unsafePassPath -Value (([ordered]@{
        candidate = [ordered]@{
            commit = $candidateForLedger.commit
            emule_sha256 = $candidateForLedger.emule_sha256
        }
        cases = @([ordered]@{
            id = 'V91-A01'
            status = 'PASS'
            executed = $false
            execution_state = 'COMPLETE'
            reason = 'must be rejected'
            evidence = @()
        })
    } | ConvertTo-Json -Depth 6))
    $unsafePassRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
            -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory `
            -ResultsPath $unsafePassPath `
            -OutputPath (Join-Path $runDirectory 'unsafe-pass-ledger.json')
    } catch {
        $unsafePassRefused = $true
    }
    Assert-LabTest -Condition $unsafePassRefused `
        -Message 'V91 ledger accepted an unexecuted evidence-free PASS'

    $foreignResultsPath = Join-Path $runDirectory 'foreign-results.json'
    Write-TestFile -Path $foreignResultsPath -Value (([ordered]@{
        candidate_commit = ('f' * 40)
        candidate_binary_sha256 = $candidateForLedger.emule_sha256
        cases = @([ordered]@{
            id = 'V91-A01'
            status = 'BLOCKED'
            executed = $false
            execution_state = 'NOT_RUN'
            reason = 'foreign bundle'
            evidence = @()
        })
    } | ConvertTo-Json -Depth 6))
    $foreignResultsRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
            -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory `
            -ResultsPath $foreignResultsPath `
            -OutputPath (Join-Path $runDirectory 'foreign-ledger.json')
    } catch {
        $foreignResultsRefused = $true
    }
    Assert-LabTest -Condition $foreignResultsRefused `
        -Message 'V91 ledger accepted a foreign results bundle'

    $foreignEvidenceRelative = 'foreign-candidate-evidence.json'
    Write-TestFile -Path (Join-Path $runDirectory $foreignEvidenceRelative) `
        -Value (([ordered]@{
            candidate_commit = $candidateForLedger.commit
            candidate_binary_sha256 = ('e' * 64)
            verdict = 'PASS'
        } | ConvertTo-Json -Depth 4))
    $foreignEvidenceResultsPath =
        Join-Path $runDirectory 'foreign-evidence-results.json'
    Write-TestFile -Path $foreignEvidenceResultsPath -Value (([ordered]@{
        candidate_commit = $candidateForLedger.commit
        candidate_binary_sha256 = $candidateForLedger.emule_sha256
        cases = @([ordered]@{
            id = 'V91-A01'
            status = 'PASS'
            executed = $true
            execution_state = 'COMPLETE'
            reason = 'foreign evidence must be rejected'
            evidence = @($foreignEvidenceRelative)
        })
    } | ConvertTo-Json -Depth 6))
    $foreignEvidenceRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
            -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory `
            -ResultsPath $foreignEvidenceResultsPath `
            -OutputPath (Join-Path $runDirectory 'foreign-evidence-ledger.json')
    } catch {
        $foreignEvidenceRefused = $true
    }
    Assert-LabTest -Condition $foreignEvidenceRefused `
        -Message 'V91 ledger accepted evidence from another binary'

    $k03EvidenceRelative = 'k03-candidate-evidence.json'
    Write-TestFile -Path (Join-Path $runDirectory $k03EvidenceRelative) `
        -Value (([ordered]@{
            candidate_commit = $candidateForLedger.commit
            candidate = [ordered]@{
                emule_sha256_before = $candidateForLedger.emule_sha256
                emule_sha256_after = $candidateForLedger.emule_sha256
            }
            verdict = 'PASS'
        } | ConvertTo-Json -Depth 5))
    $k03ResultsPath = Join-Path $runDirectory 'k03-results.json'
    Write-TestFile -Path $k03ResultsPath -Value (([ordered]@{
        candidate = [ordered]@{
            commit = $candidateForLedger.commit
            emule_sha256 = $candidateForLedger.emule_sha256
        }
        cases = @([ordered]@{
            id = 'V91-K03'
            status = 'PASS'
            executed = $true
            execution_state = 'COMPLETE'
            reason = 'K03 before/after identity aliases'
            evidence = @($k03EvidenceRelative)
        })
    } | ConvertTo-Json -Depth 6))
    $k03LedgerPath = Join-Path $runDirectory 'k03-ledger.json'
    & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
        -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory `
        -ResultsPath $k03ResultsPath -OutputPath $k03LedgerPath
    $k03Ledger = Get-Content -LiteralPath $k03LedgerPath -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition (
        $k03Ledger.counts.pass -eq 1 -and
        @($k03Ledger.cases | Where-Object {
            $_.id -eq 'V91-K03' -and $_.identity_evidence_count -eq 1
        }).Count -eq 1) `
        -Message 'V91 ledger rejected K03 before/after identity aliases'

    $k03ConflictEvidenceRelative = 'k03-conflict-evidence.json'
    Write-TestFile -Path `
        (Join-Path $runDirectory $k03ConflictEvidenceRelative) `
        -Value (([ordered]@{
            candidate_commit = $candidateForLedger.commit
            candidate = [ordered]@{
                emule_sha256_before = $candidateForLedger.emule_sha256
                emule_sha256_after = ('d' * 64)
            }
        } | ConvertTo-Json -Depth 5))
    $k03ConflictResults = Get-Content -LiteralPath $k03ResultsPath -Raw |
        ConvertFrom-Json
    $k03ConflictResults.cases[0].evidence =
        @($k03ConflictEvidenceRelative)
    $k03ConflictResultsPath =
        Join-Path $runDirectory 'k03-conflict-results.json'
    Write-TestFile -Path $k03ConflictResultsPath `
        -Value ($k03ConflictResults | ConvertTo-Json -Depth 8)
    $k03ConflictRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
            -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory `
            -ResultsPath $k03ConflictResultsPath `
            -OutputPath (Join-Path $runDirectory 'k03-conflict-ledger.json')
    } catch {
        $k03ConflictRefused = $true
    }
    Assert-LabTest -Condition $k03ConflictRefused `
        -Message 'V91 ledger accepted conflicting K03 before/after hashes'

    $normativeIds = @(
        'V91-A01', 'V91-A02',
        'V91-I01', 'V91-I02', 'V91-I03', 'V91-I04', 'V91-I05',
        'V91-I06', 'V91-I07', 'V91-I08', 'V91-D01',
        'V91-P01', 'V91-P02', 'V91-P03',
        'V91-K01', 'V91-K02', 'V91-K03', 'V91-K04',
        'V91-C01', 'V91-C02', 'V91-C03', 'V91-C04',
        'V91-S01', 'V91-S02', 'V91-S03', 'V91-R01', 'V91-O01'
    )
    $exactCases = @($normativeIds | ForEach-Object {
        [ordered]@{
            id = $_
            status = 'PASS'
            executed = $true
            execution_state = 'COMPLETE'
            reason = 'exact-candidate smoke evidence'
            evidence = @($exactEvidenceRelative)
        }
    })
    $exactResultsPath = Join-Path $runDirectory 'exact-results.json'
    Write-TestFile -Path $exactResultsPath -Value (([ordered]@{
        schema = 'ese.v91.rc-results/v2'
        candidate = [ordered]@{
            commit = $candidateForLedger.commit
            expected_emule_sha256 = $candidateForLedger.emule_sha256
        }
        cases = $exactCases
    } | ConvertTo-Json -Depth 8))
    $goLedgerPath = Join-Path $runDirectory 'V91-RC-LEDGER-GO.json'
    & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
        -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory `
        -ResultsPath $exactResultsPath -OutputPath $goLedgerPath
    $goLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition (
        $goLedger.gate_decision -eq 'GO' -and
        $goLedger.counts.pass -eq 27 -and
        @($goLedger.cases | Where-Object {
            $_.identity_evidence_count -ne 1
        }).Count -eq 0) `
        -Message 'V91 ledger rejected exact complete PASS evidence'

    foreach ($reservedEvidence in @(
        'V91-CAMPAIGN-FINAL.json',
        'V91-EVIDENCE-MANIFEST.json',
        'V91-CAMPAIGN-FINAL.md'
    )) {
        $reservedLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
            ConvertFrom-Json
        $reservedLedger.cases[0].evidence =
            @($reservedEvidence, $exactEvidenceRelative)
        $reservedLedger.cases[0].identity_evidence_count =
            if ([IO.Path]::GetExtension($reservedEvidence) -eq '.json') {
                2
            } else { 1 }
        $reservedLedgerPath = Join-Path $runDirectory `
            ("reserved-" + $reservedEvidence.Replace('.', '-') + '.json')
        Write-TestFile -Path $reservedLedgerPath `
            -Value ($reservedLedger | ConvertTo-Json -Depth 10)
        $reservedEvidenceRefused = $false
        try {
            & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
                -EvidenceRoot $runDirectory -LedgerPath $reservedLedgerPath
        } catch {
            $reservedEvidenceRefused = $true
        }
        Assert-LabTest -Condition $reservedEvidenceRefused `
            -Message "V91 report accepted reserved output as evidence: $reservedEvidence"
    }

    $outsideEvidence = Join-Path $testRoot 'outside-evidence-root'
    $null = New-Item -ItemType Directory -Path $outsideEvidence -Force
    Copy-Item -LiteralPath (Join-Path $runDirectory $exactEvidenceRelative) `
        -Destination (Join-Path $outsideEvidence 'exact.json')
    $evidenceJunction = Join-Path $runDirectory 'junction-evidence'
    $null = New-Item -ItemType Junction -Path $evidenceJunction `
        -Target $outsideEvidence
    $junctionEvidenceRelative = 'junction-evidence\exact.json'
    $junctionCases = @($normativeIds | ForEach-Object {
        [ordered]@{
            id = $_
            status = 'PASS'
            executed = $true
            execution_state = 'COMPLETE'
            reason = 'junction escape must be rejected'
            evidence = @($junctionEvidenceRelative)
        }
    })
    $junctionResultsPath = Join-Path $runDirectory 'junction-results.json'
    Write-TestFile -Path $junctionResultsPath -Value (([ordered]@{
        candidate = [ordered]@{
            commit = $candidateForLedger.commit
            emule_sha256 = $candidateForLedger.emule_sha256
        }
        cases = $junctionCases
    } | ConvertTo-Json -Depth 8))
    $junctionLedgerRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_ledger.ps1') `
            -CandidatePackage $sourcePackage -EvidenceRoot $runDirectory `
            -ResultsPath $junctionResultsPath `
            -OutputPath (Join-Path $runDirectory 'junction-ledger.json')
    } catch {
        $junctionLedgerRefused = $true
    }
    Assert-LabTest -Condition $junctionLedgerRefused `
        -Message 'V91 ledger followed a junction outside EvidenceRoot'

    $junctionReportLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    $junctionReportLedger.cases[0].evidence =
        @($junctionEvidenceRelative)
    $junctionReportLedger.cases[0].identity_evidence_count = 1
    $junctionReportLedgerPath =
        Join-Path $runDirectory 'junction-report-ledger.json'
    Write-TestFile -Path $junctionReportLedgerPath `
        -Value ($junctionReportLedger | ConvertTo-Json -Depth 10)
    $junctionReportRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
            -EvidenceRoot $runDirectory `
            -LedgerPath $junctionReportLedgerPath
    } catch {
        $junctionReportRefused = $true
    }
    Assert-LabTest -Condition $junctionReportRefused `
        -Message 'V91 report followed a junction outside EvidenceRoot'

    $k03GoLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    $k03GoCase = @($k03GoLedger.cases | Where-Object id -eq 'V91-K03')[0]
    $k03GoCase.evidence = @($k03EvidenceRelative)
    $k03GoCase.identity_evidence_count = 1
    $k03GoLedgerPath = Join-Path $runDirectory 'k03-go-ledger.json'
    Write-TestFile -Path $k03GoLedgerPath `
        -Value ($k03GoLedger | ConvertTo-Json -Depth 10)
    & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
        -EvidenceRoot $runDirectory -LedgerPath $k03GoLedgerPath
    $k03GoFinal = Get-Content -LiteralPath `
        (Join-Path $runDirectory 'V91-CAMPAIGN-FINAL.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition ($k03GoFinal.gate_decision -eq 'GO') `
        -Message 'V91 report rejected exact K03 before/after evidence'

    $tamperedCount = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    $tamperedCount.counts.pass = 26
    $tamperedCountPath = Join-Path $runDirectory 'tampered-count-ledger.json'
    Write-TestFile -Path $tamperedCountPath `
        -Value ($tamperedCount | ConvertTo-Json -Depth 10)
    $tamperedCountRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
            -EvidenceRoot $runDirectory -LedgerPath $tamperedCountPath
    } catch {
        $tamperedCountRefused = $true
    }
    Assert-LabTest -Condition $tamperedCountRefused `
        -Message 'V91 report accepted tampered formal counts'

    $tamperedGate = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    $tamperedGate.gate_decision = 'NO_GO'
    $tamperedGatePath = Join-Path $runDirectory 'tampered-gate-ledger.json'
    Write-TestFile -Path $tamperedGatePath `
        -Value ($tamperedGate | ConvertTo-Json -Depth 10)
    $tamperedGateRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
            -EvidenceRoot $runDirectory -LedgerPath $tamperedGatePath
    } catch {
        $tamperedGateRefused = $true
    }
    Assert-LabTest -Condition $tamperedGateRefused `
        -Message 'V91 report accepted a tampered gate decision'

    $duplicateCaseLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    $duplicateCaseLedger.cases[-1].id = $duplicateCaseLedger.cases[0].id
    $duplicateCasePath = Join-Path $runDirectory 'duplicate-case-ledger.json'
    Write-TestFile -Path $duplicateCasePath `
        -Value ($duplicateCaseLedger | ConvertTo-Json -Depth 10)
    $duplicateCaseRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
            -EvidenceRoot $runDirectory -LedgerPath $duplicateCasePath
    } catch {
        $duplicateCaseRefused = $true
    }
    Assert-LabTest -Condition $duplicateCaseRefused `
        -Message 'V91 report accepted duplicate/missing normative IDs'

    $lowercaseLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    foreach ($case in $lowercaseLedger.cases) {
        $case.id = ([string]$case.id).ToLowerInvariant()
    }
    $lowercaseLedgerPath = Join-Path $runDirectory 'lowercase-ledger.json'
    Write-TestFile -Path $lowercaseLedgerPath `
        -Value ($lowercaseLedger | ConvertTo-Json -Depth 10)
    $lowercaseIdsRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
            -EvidenceRoot $runDirectory -LedgerPath $lowercaseLedgerPath
    } catch {
        $lowercaseIdsRefused = $true
    }
    Assert-LabTest -Condition $lowercaseIdsRefused `
        -Message 'V91 report accepted non-canonical lowercase case IDs'

    $missingCaseLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    $missingCaseLedger.cases = @($missingCaseLedger.cases |
        Select-Object -First 26)
    $missingCasePath = Join-Path $runDirectory 'missing-case-ledger.json'
    Write-TestFile -Path $missingCasePath `
        -Value ($missingCaseLedger | ConvertTo-Json -Depth 10)
    $missingCaseRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
            -EvidenceRoot $runDirectory -LedgerPath $missingCasePath
    } catch {
        $missingCaseRefused = $true
    }
    Assert-LabTest -Condition $missingCaseRefused `
        -Message 'V91 report accepted a missing normative case'

    $foreignEvidenceLedger = Get-Content -LiteralPath $goLedgerPath -Raw |
        ConvertFrom-Json
    $foreignEvidenceLedger.cases[0].evidence =
        @($foreignEvidenceRelative)
    $foreignEvidenceLedger.cases[0].identity_evidence_count = 1
    $foreignEvidenceLedgerPath =
        Join-Path $runDirectory 'foreign-evidence-report-ledger.json'
    Write-TestFile -Path $foreignEvidenceLedgerPath `
        -Value ($foreignEvidenceLedger | ConvertTo-Json -Depth 10)
    $foreignReportEvidenceRefused = $false
    try {
        & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
            -EvidenceRoot $runDirectory `
            -LedgerPath $foreignEvidenceLedgerPath
    } catch {
        $foreignReportEvidenceRefused = $true
    }
    Assert-LabTest -Condition $foreignReportEvidenceRefused `
        -Message 'V91 report accepted foreign candidate evidence'

    & (Join-Path $labTools 'write_v91_campaign_report.ps1') `
        -EvidenceRoot $runDirectory -LedgerPath $goLedgerPath
    $goFinal = Get-Content -LiteralPath `
        (Join-Path $runDirectory 'V91-CAMPAIGN-FINAL.json') -Raw |
        ConvertFrom-Json
    Assert-LabTest -Condition (
        $goFinal.gate_decision -eq 'GO' -and
        $goFinal.formal_counts.pass -eq 27) `
        -Message 'V91 final report rejected a coherent exact GO ledger'

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
    if ($evidenceJunction -and
        (Test-Path -LiteralPath $evidenceJunction)) {
        $junctionFull = [IO.Path]::GetFullPath($evidenceJunction)
        $testPrefix = [IO.Path]::GetFullPath($testRoot).TrimEnd(
            [char[]]@('\', '/')) + '\'
        $junctionItem = Get-Item -LiteralPath $junctionFull -Force
        if (-not $junctionFull.StartsWith(
                $testPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            ($junctionItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -eq 0) {
            throw "Refusing unsafe junction cleanup: $junctionFull"
        }
        [IO.Directory]::Delete($junctionFull, $false)
    }

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
